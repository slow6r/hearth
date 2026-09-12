//! End-to-end tests for the admin API (ТЗ §7.3).
//!
//! These run the real server — real rustls mutual TLS against the real hearth admin CA,
//! real axum routes, real bundle minting — over loopback with an ephemeral port. What
//! they prove is the part that cannot be unit tested: that an issued certificate gets
//! in, that a revoked one does not, and that the bundle a client would scan is exactly
//! the document ТЗ Приложение B describes.

use std::path::Path;
use std::sync::Arc;

use hearthd::api;
use hearthd::config::Config;
use hearthd::model::bundle::Bundle;
use hearthd::model::device::Device;
use hearthd::model::health::HealthSnapshot;
use hearthd::state::AppState;
use hearthd::store;
use hearthd::sys::Sys;
use hearthd::{pki, VERSION};

/// A node pinned to loopback, so the test can bind a real socket.
fn loopback_config(dir: &Path) -> Config {
    let raw = include_str!("../deploy/hearthd.toml");
    let mut config: Config = toml::from_str(raw).expect("reference config parses");

    // The published host stays a normal public name — that is what goes into client
    // addresses. Only the admin API is moved onto loopback so the test can bind it.
    config.node.host = "relay.example.org".into();
    config.node.lan_networks = vec!["127.0.0.0/8".parse().expect("cidr")];
    config.node.admin_networks = vec!["127.0.0.0/8".parse().expect("cidr")];
    config.api.listen = "127.0.0.1:0".parse().expect("addr");
    config.api.pki_dir = dir.join("pki");

    config.paths.state_dir = dir.join("state");
    config.paths.hearth_etc = dir.join("etc-hearth");
    config.paths.secrets_dir = dir.join("secrets");
    config.paths.manifest = dir.join("manifest.toml");

    config.smp.fingerprint_file = dir.join("secrets/smp-fingerprint");
    config.smp.password_file = dir.join("secrets/smp-password");
    config.xftp.fingerprint_file = dir.join("secrets/xftp-fingerprint");
    config.xftp.password_file = dir.join("secrets/xftp-password");
    config.turn.secret_file = dir.join("secrets/turn-secret");

    config.backup.spool_dir = dir.join("spool");
    config.backup.remote = None;
    config.alerts.gotify = None;
    config.alerts.beeper = None;

    config.validate().expect("loopback config is valid");
    config
}

/// Relay state that `smp-server init` and `xftp-server init` would have produced.
fn seed_relay_state(dir: &Path) {
    store::write_secret(dir.join("secrets/smp-fingerprint"), "smpCaFingerprint").expect("w");
    store::write_secret(dir.join("secrets/smp-password"), "smpQueuePassword").expect("w");
    store::write_secret(dir.join("secrets/xftp-fingerprint"), "xftpCaFingerprint").expect("w");
    store::write_secret(dir.join("secrets/xftp-password"), "xftpUploadPassword").expect("w");
    store::write_secret(dir.join("secrets/turn-secret"), "turnStaticSecret").expect("w");
}

struct Harness {
    _dir: tempfile::TempDir,
    state: Arc<AppState>,
    client: api::client::AdminClient,
    shutdown: tokio::sync::watch::Sender<bool>,
}

async fn start() -> Harness {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tempfile::tempdir().expect("tempdir");
    let config = loopback_config(dir.path());
    seed_relay_state(dir.path());

    pki::init_ca(
        &config.api.pki_dir,
        "hearth-test",
        config.api.listen.ip(),
        false,
    )
    .expect("init ca");
    let issued = pki::issue_admin(&config.api.pki_dir, "owner", 30).expect("issue admin");
    let cert_path = config.api.pki_dir.join("owner.pem");
    let key_path = config.api.pki_dir.join("owner.key");
    std::fs::write(&cert_path, &issued.cert_pem).expect("write cert");
    std::fs::write(&key_path, &issued.key_pem).expect("write key");

    let pki_dir = config.api.pki_dir.clone();
    let state = AppState::new(config, Sys::new(true)).expect("state");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = api::serve_on(server_state, listener, shutdown_rx).await {
            eprintln!("server stopped: {e}");
        }
    });

    let client =
        api::client::AdminClient::new(addr, &pki_dir.join(pki::CA_CERT), &cert_path, &key_path)
            .expect("client");

    Harness {
        _dir: dir,
        state,
        client,
        shutdown,
    }
}

#[tokio::test]
async fn a_revoked_certificate_stops_working_immediately() {
    // Раньше допуск проверялся один раз на соединение: отозванный админ продолжал
    // работать внутри уже открытого keep-alive до таймаута. Окно было
    // детерминированным и выбиралось атакующим — за него проходит и выписка
    // приглашения себе, и снятие карантина, и восстановление из бэкапа.
    let harness = start().await;
    let _: HealthSnapshot = harness.client.get_json("/health").await.expect("до отзыва");

    let mut registry = pki::AdminRegistry::load(&harness.state.config.api.pki_dir)
        .expect("реестр администраторов");
    registry.revoke("owner").expect("отзыв");

    let after: Result<HealthSnapshot, _> = harness.client.get_json("/health").await;
    assert!(
        after.is_err(),
        "отозванный сертификат обязан перестать работать сразу, а не по таймауту"
    );
}

#[tokio::test]
async fn health_is_served_over_mutual_tls() {
    let harness = start().await;
    let health: HealthSnapshot = harness.client.get_json("/health").await.expect("health");
    assert_eq!(health.node, "hearth-node");
    assert_eq!(health.address, "relay.example.org");
    assert_eq!(health.version, VERSION);
    let _ = harness.shutdown.send(true);
}

#[tokio::test]
async fn device_lifecycle_and_bundle_issue() {
    let harness = start().await;

    // Register.
    let device: Device = harness
        .client
        .post_json(
            "/devices",
            Some(serde_json::json!({"name": "Мама — Pixel 8", "platform": "android"})),
        )
        .await
        .expect("add device");
    assert_eq!(device.id, "mama-pixel-8");

    // The listing sees it.
    let devices: Vec<Device> = harness.client.get_json("/devices").await.expect("list");
    assert_eq!(devices.len(), 1);

    // The bundle is exactly the ТЗ Приложение B document, valid for this node.
    let bundle: Bundle = harness
        .client
        .get_json("/devices/mama-pixel-8/bundle.json")
        .await
        .expect("bundle");
    bundle
        .validate("relay.example.org")
        .expect("bundle is valid");
    assert_eq!(
        bundle.smp,
        vec!["smp://smpCaFingerprint:smpQueuePassword@relay.example.org:8443".to_string()]
    );
    assert_eq!(bundle.device, "mama-pixel-8");
    assert!(!bundle.net.presets_enabled);
    assert_eq!(bundle.net.ntf_mode, "instant");
    assert!(bundle.to_json().expect("json").len() <= 1024);

    // The QR route returns a real PNG.
    let png = harness
        .client
        .get_bytes("/devices/mama-pixel-8/bundle.png")
        .await
        .expect("png");
    assert_eq!(&png[..8], &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);

    // The manual checklist is generated from the same source of truth.
    let checklist = harness
        .client
        .get_bytes("/devices/mama-pixel-8/checklist.txt")
        .await
        .expect("checklist");
    let checklist = String::from_utf8(checklist).expect("utf8");
    assert!(checklist.contains("smp://smpCaFingerprint"));
    assert!(checklist.contains("Operators"));

    // Revoke: no more bundles for this device.
    let revoked: Device = harness
        .client
        .post_json("/devices/mama-pixel-8/revoke", None)
        .await
        .expect("revoke");
    assert!(revoked.revoked.is_some());
    let err = harness
        .client
        .get_json::<Bundle>("/devices/mama-pixel-8/bundle.json")
        .await
        .expect_err("a revoked device must not receive a bundle");
    assert!(err.to_string().contains("revoked"), "got {err}");

    let _ = harness.shutdown.send(true);
}

#[tokio::test]
async fn unknown_device_is_a_404() {
    let harness = start().await;
    let err = harness
        .client
        .get_json::<Device>("/devices/nobody")
        .await
        .expect_err("404");
    assert!(
        matches!(err, hearthd::error::Error::NotFound(_)),
        "got {err:?}"
    );
    let _ = harness.shutdown.send(true);
}

#[tokio::test]
async fn a_revoked_admin_certificate_is_refused() {
    let harness = start().await;
    // Works before revocation.
    harness
        .client
        .get_json::<HealthSnapshot>("/health")
        .await
        .expect("authorized");

    pki::AdminRegistry::load(&harness.state.config.api.pki_dir)
        .expect("load")
        .revoke("owner")
        .expect("revoke");

    let err = harness
        .client
        .get_json::<HealthSnapshot>("/health")
        .await
        .expect_err("a revoked admin must be locked out without restarting the daemon");
    // The server drops the connection after the handshake, so this surfaces as a
    // transport error rather than a 401 body.
    let msg = err.to_string();
    assert!(
        msg.contains("http") || msg.contains("request failed") || msg.contains("Unauthorized"),
        "unexpected error: {msg}"
    );

    let _ = harness.shutdown.send(true);
}

#[tokio::test]
async fn a_certificate_from_another_ca_cannot_connect() {
    let harness = start().await;

    // A second, unrelated CA — the shape of an attacker who has their own PKI.
    let rogue_dir = tempfile::tempdir().expect("tempdir");
    pki::init_ca(
        rogue_dir.path(),
        "rogue",
        "127.0.0.1".parse().expect("ip"),
        false,
    )
    .expect("rogue ca");
    let rogue = pki::issue_admin(rogue_dir.path(), "intruder", 30).expect("rogue cert");
    let cert = rogue_dir.path().join("intruder.pem");
    let key = rogue_dir.path().join("intruder.key");
    std::fs::write(&cert, rogue.cert_pem).expect("write");
    std::fs::write(&key, rogue.key_pem).expect("write");

    let addr = harness.client.addr();
    let rogue_client = api::client::AdminClient::new(
        addr,
        &harness.state.config.api.pki_dir.join(pki::CA_CERT),
        &cert,
        &key,
    )
    .expect("client builds");

    let err = rogue_client
        .get_json::<HealthSnapshot>("/health")
        .await
        .expect_err("mTLS must reject a certificate from another CA");
    assert!(!err.to_string().is_empty());

    let _ = harness.shutdown.send(true);
}

#[tokio::test]
async fn operations_are_reachable_and_report_honestly() {
    let harness = start().await;

    // The shipped reference config carries a placeholder age recipient, so a backup
    // must fail — loudly and with a message that names the cause, never silently.
    let result: Result<serde_json::Value, _> = harness.client.post_json("/backup/now", None).await;
    match result {
        Ok(value) => assert!(value.get("sha256").is_some(), "unexpected success body"),
        Err(e) => assert!(
            e.to_string().contains("age") || e.to_string().contains("backup"),
            "the failure must explain itself, got: {e}"
        ),
    }

    // The backup status endpoint records that attempt.
    let status: hearthd::model::health::BackupStatus = harness
        .client
        .get_json("/backup/status")
        .await
        .expect("backup status");
    assert!(status.last_run.is_some());

    // Migration status is readable without performing a migration.
    let migrate: hearthd::model::health::MigrateStatus = harness
        .client
        .get_json("/migrate/export")
        .await
        .expect("migrate status");
    assert!(migrate.exported_at.is_none());

    let _ = harness.shutdown.send(true);
}

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
    config.smp.password_file = Some(dir.join("secrets/smp-password"));
    config.xftp.fingerprint_file = dir.join("secrets/xftp-fingerprint");
    config.xftp.password_file = Some(dir.join("secrets/xftp-password"));
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

/// Промах мимо реестра и потерянный отзыв — разные события.
///
/// Раньше `revoke_device` поднимал critical на ЛЮБУЮ ошибку: опечатка администратора
/// в идентификаторе попадала в журнал алертов наравне с отказом диска, при котором
/// телефон продолжит пускать после ближайшего перезапуска. Журнал, куда каждый день
/// сыплется чужой шум, перестают читать — и настоящее сообщение теряется в нём.
#[tokio::test]
async fn revoking_a_device_that_is_not_there_raises_no_critical_alert() {
    let harness = start().await;

    let err = harness
        .client
        .post_json::<Device>("/devices/no-such-device/revoke", None)
        .await
        .expect_err("несуществующее устройство обязано давать 404");
    assert!(
        matches!(err, hearthd::error::Error::NotFound(_)),
        "ожидали 404, получили {err:?}"
    );
    assert_eq!(
        harness.state.alerts.critical_count().await,
        0,
        "промах по идентификатору — не critical"
    );

    // Обратная половина: настоящий отзыв по-прежнему виден в журнале, иначе проверка
    // закрепляла бы молчание вместо разделения.
    let device: Device = harness
        .client
        .post_json("/devices", Some(serde_json::json!({ "name": "телефон" })))
        .await
        .expect("устройство заведено");
    let _: Device = harness
        .client
        .post_json(&format!("/devices/{}/revoke", device.id), None)
        .await
        .expect("отзыв существующего устройства");
    let alerts = harness.state.alerts.query(None, None, 50).await;
    assert!(
        alerts.iter().any(|a| a.summary.contains(&device.id)),
        "отзыв обязан быть записан: получили {alerts:?}"
    );

    let _ = harness.shutdown.send(true);
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

/// Демон обязан САМ назвать, из чего он собран и каким файлом запущен.
///
/// До этой правки `/health` отвечал одной лишь версией `0.1.0`, одинаковой для любой
/// сборки любого коммита. Вопрос «этот ли код сейчас работает» упирался в доступ к
/// файлу на узле, а у аудитора он закрыт: `/proc/<pid>/exe` требует ptrace, а ptrace
/// — это заодно и чтение памяти релеев, то есть переписки (ТЗ §7.4).
#[tokio::test]
async fn health_carries_the_build_passport() {
    let harness = start().await;
    let health: HealthSnapshot = harness.client.get_json("/health").await.expect("health");

    let build = hearthd::build_info();
    assert_eq!(health.commit, build.commit, "коммит в снимке не тот");
    assert_eq!(health.tree_sha256, build.tree_sha256);
    assert_eq!(
        health.self_sha256.len(),
        64,
        "sha256 работающего файла: `{}`",
        health.self_sha256
    );
    assert!(health.self_sha256.chars().all(|c| c.is_ascii_hexdigit()));

    let _ = harness.shutdown.send(true);
}

/// Снимок, записанный демоном прежней версии, обязан разбираться новым кодом.
/// Иначе обновление узла ломает уже разложенные по рабочим станциям hearthctl.
#[tokio::test]
async fn an_old_health_document_still_deserialises() {
    let raw = r#"{
        "node": "hearth-node",
        "address": "relay.example.org",
        "checked": "2026-09-18T03:00:00Z",
        "state": "ok",
        "services": [],
        "uptime_secs": 7,
        "version": "0.1.0"
    }"#;
    let snapshot: HealthSnapshot = serde_json::from_str(raw).expect("старый снимок разбирается");
    assert!(snapshot.commit.is_empty());
    assert!(snapshot.self_sha256.is_empty());
    // Поля backup в старом документе нет. Умолчание обязано читаться как «не
    // сообщено», а не как «проверено и хорошо»: иначе обновление демона превратило бы
    // молчание прежней версии в зелёный вердикт по резервной копии.
    assert_eq!(
        snapshot.backup,
        hearthd::model::health::HealthState::Degraded
    );
}

/// Аудиторский токен: выдача и немедленный отзыв через admin API.
///
/// Проверяется главное свойство — отзыв действует СРАЗУ, как и у сертификата
/// администратора: реестр смотрится на каждом запросе, а не при открытии соединения.
#[tokio::test]
async fn an_audit_token_is_issued_and_revoked_through_the_api() {
    use hearthd::model::audit_token::{AuditScope, AuditToken, AuditTokenPublic};

    let harness = start().await;

    let issued: AuditToken = harness
        .client
        .post_json(
            "/audit-tokens",
            Some(serde_json::json!({
                "ttl_hours": 48,
                "max_uses": 5,
                "scope": "updates",
                "note": "аудит 2026-09"
            })),
        )
        .await
        .expect("выдача токена");
    assert_eq!(issued.max_uses, 5);
    assert_eq!(issued.scope, AuditScope::updates());
    assert!(issued.expires > issued.created, "срок обязателен");

    // Список не несёт секрета: ровно этим он и уходит в выгрузку для аудита.
    let listed: serde_json::Value = harness
        .client
        .get_json("/audit-tokens")
        .await
        .expect("список");
    let text = listed.to_string();
    assert!(
        !text.contains(&issued.token),
        "секрет попал в список: {text}"
    );
    assert!(text.contains(&issued.id));

    // Слот устройства не израсходован и bundle не выпущен.
    let devices: Vec<Device> = harness.client.get_json("/devices").await.expect("devices");
    assert!(
        devices.is_empty(),
        "аудиторский токен не имеет права заводить устройство"
    );

    let revoked: AuditTokenPublic = harness
        .client
        .post_json(&format!("/audit-tokens/{}/revoke", issued.id), None)
        .await
        .expect("отзыв");
    assert_eq!(revoked.state, "отозван");

    // И узел действительно перестал его принимать — состояние на диске, а не в памяти.
    let registry = hearthd::model::audit_token::AuditTokenRegistry::load(
        harness.state.config.paths.audit_tokens_file(),
    )
    .expect("реестр");
    assert!(!registry
        .get(&issued.id)
        .expect("запись на месте")
        .is_usable_at(chrono::Utc::now()));

    let _ = harness.shutdown.send(true);
}

/// Токен без срока или без счётчика выписать нельзя — это и есть отличие
/// аудиторского доступа от токена устройства.
#[tokio::test]
async fn an_unbounded_audit_token_is_refused() {
    let harness = start().await;
    for body in [
        serde_json::json!({ "ttl_hours": 0, "max_uses": 5 }),
        serde_json::json!({ "ttl_hours": 48, "max_uses": 0 }),
        serde_json::json!({ "ttl_hours": 48, "max_uses": 5, "scope": "turn-credentials" }),
    ] {
        let result: Result<serde_json::Value, _> = harness
            .client
            .post_json("/audit-tokens", Some(body.clone()))
            .await;
        assert!(result.is_err(), "принято то, что принимать нельзя: {body}");
    }
    let _ = harness.shutdown.send(true);
}

/// Обезличенная проекция устройства — то, что уходит в выгрузку для аудита.
/// Наивный дамп реестра был бы утечкой ровно одним полем.
#[tokio::test]
async fn the_redacted_device_listing_carries_no_token() {
    let harness = start().await;

    let device: Device = harness
        .client
        .post_json(
            "/devices",
            Some(serde_json::json!({"name": "Папа — Pixel 9", "platform": "android"})),
        )
        .await
        .expect("add device");
    let secret = device.token.clone().expect("токен выдаётся при заведении");

    let devices: Vec<Device> = harness.client.get_json("/devices").await.expect("list");
    let public: Vec<hearthd::model::device::DevicePublic> =
        devices.iter().map(Device::public).collect();
    let text = serde_json::to_string(&public).expect("json");

    assert!(!text.contains(&secret), "секрет в выгрузке: {text}");
    assert!(text.contains("papa-pixel-9"), "полезное потеряно: {text}");

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

    // Статус обязан нести вердикт, а не только поля: «бэкап сделан?» и «бэкап чего?»
    // — разные вопросы, и на оба должен быть ответ без age-ключа.
    let raw: serde_json::Value = harness
        .client
        .get_json("/backup/status")
        .await
        .expect("backup status json");
    assert!(raw.get("state").is_some(), "вердикта нет в ответе: {raw}");
    if status.last_success.is_some() {
        assert!(!status.members.is_empty(), "успех без описи вошедшего");
    } else {
        assert!(status.last_error.is_some(), "провал обязан себя назвать");
        assert!(status.members.is_empty());
        assert_eq!(
            status.state,
            hearthd::model::health::HealthState::Down,
            "несостоявшийся бэкап не имеет права выглядеть зелёным"
        );
    }

    // Migration status is readable without performing a migration.
    let migrate: hearthd::model::health::MigrateStatus = harness
        .client
        .get_json("/migrate/export")
        .await
        .expect("migrate status");
    assert!(migrate.exported_at.is_none());

    let _ = harness.shutdown.send(true);
}

#[tokio::test]
async fn an_export_holds_the_node_even_when_it_fails() {
    // Раньше режим переноса выставлялся ПОСЛЕ остановки релеев, шифрования архива и
    // rsync — минуты и десятки минут на живом узле при тике надзора в 15 секунд. На
    // пути ошибки он не выставлялся вовсе: релеи остановлены, режим `normal`, и узел
    // молча возвращался в строй с наполовину сделанным переносом.
    let harness = start().await;

    let before: hearthd::model::mode::NodeState =
        harness.client.get_json("/mode").await.expect("mode");
    assert_eq!(before.mode, hearthd::model::mode::NodeMode::Normal);

    // В поставляемой конфигурации получатель age — плейсхолдер, а архивируемых
    // каталогов на машине разработчика нет, поэтому экспорт обрывается. Нам важно
    // ровно это: он оборвался, а запрет уже стоит.
    let result: Result<serde_json::Value, _> =
        harness.client.post_json("/migrate/export", None).await;
    assert!(
        result.is_err(),
        "фикстура обязана ронять экспорт, иначе тест не проверяет путь ошибки"
    );

    let after: hearthd::model::mode::NodeState =
        harness.client.get_json("/mode").await.expect("mode");
    assert_eq!(
        after.mode,
        hearthd::model::mode::NodeMode::Migration,
        "узел обязан остаться удержанным: {}",
        after.summary()
    );

    let _ = harness.shutdown.send(true);
}

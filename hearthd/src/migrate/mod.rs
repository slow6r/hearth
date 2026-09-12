//! Node migration (ТЗ §10.2): move the node from the ПК to the mini-PC without the
//! relay address changing, so no client has to do anything.
//!
//! What actually migrates is the *identity* of the node: the relay CA and its private
//! key, the queue-creation passwords, the store log, and the hearth state. The address
//! `smp://<fp>:<pass>@10.66.10.10:5223` is built from exactly those, which is why
//! moving them (and the port forwarding) is enough — ТЗ §2.5.
//!
//! Export refuses to leave the relays running: two nodes answering on one CA with one
//! address would be a split brain that clients cannot detect. The old node stays down
//! (ТЗ §10.2 п.5).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::backup::archive::{self, ArchiveInfo};
use crate::error::{Error, Result};
use crate::model::alert::Alert;
use crate::state::AppState;
use crate::store;
use crate::sys::systemd;

/// Result of `hearthctl migrate export`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportReport {
    pub archive: PathBuf,
    pub sha256: String,
    pub size_bytes: u64,
    pub members: Vec<String>,
    pub relays_stopped: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub copied_to: Option<String>,
    /// Reminders the operator must not skip.
    pub next_steps: Vec<String>,
}

/// Result of `hearthctl migrate import`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportReport {
    pub restored: Vec<PathBuf>,
    pub destination: PathBuf,
    pub integrity_ok: bool,
    pub integrity_notes: Vec<String>,
    pub next_steps: Vec<String>,
}

/// Stop the relays and produce the final encrypted archive (ТЗ §10.2 п.3).
pub async fn export(state: &Arc<AppState>) -> Result<ExportReport> {
    let config = state.config.clone();
    let started = Utc::now();

    // 1. Stop the relays first: the store log must not change while it is being copied.
    let mut stopped = Vec::new();
    for relay in config.relays() {
        if !relay.enabled {
            continue;
        }
        systemd::stop(&state.sys, &relay.unit).await?;
        stopped.push(relay.unit.clone());
    }
    if config.turn.enabled {
        systemd::stop(&state.sys, &config.turn.unit).await?;
        stopped.push(config.turn.unit.clone());
    }

    // 2. Archive the three ТЗ §10.1 directories plus hearth state.
    store::ensure_dir(&config.backup.spool_dir)?;
    let name = format!(
        "hearth-migrate-{}-{}.tar.gz.age",
        config.node.name,
        started.format("%Y%m%dT%H%M%SZ")
    );
    let output = config.backup.spool_dir.join(name);
    let info: ArchiveInfo =
        archive::create_encrypted(&config.backup.paths, &output, &config.backup.recipients)?;

    // 3. Push it to hearth-backup (ТЗ §10.2 п.3). The archive must not live only on a
    //    machine that is about to be wiped — but a failed copy does not invalidate a
    //    good archive, so this is a warning, not an error.
    let copied_to = match crate::backup::BackupJob::new(state.clone())
        .sync_remote()
        .await
    {
        Ok(destination) => destination,
        Err(e) => {
            state
                .alerts
                .emit(Alert::warning(
                    "migrate",
                    format!("export archive was not copied to hearth-backup: {e}"),
                ))
                .await;
            None
        }
    };

    {
        let mut status = state.migrate.write().await;
        status.exported_at = Some(started);
        status.archive = Some(info.path.clone());
        status.sha256 = Some(info.sha256.clone());
        status.size_bytes = info.size_bytes;
        status.relays_stopped = true;
        status.copied_to = copied_to.clone();
    }
    state.save_migrate_status().await?;

    // Иначе supervisor поднимет релеи обратно на ближайшем тике, и после импорта на
    // новом узле в сети окажутся два релея с одним CA и одним адресом — ровно то
    // расщепление, которое этот модуль объявляет недопустимым.
    state
        .set_mode(
            crate::model::mode::NodeMode::Migration,
            "перенос узла: выполнен `hearthctl migrate export`",
            Vec::new(),
        )
        .await?;

    state
        .alerts
        .emit(
            Alert::warning(
                "migrate",
                "migration export complete; the relays are stopped and must stay stopped",
            )
            .with_details(serde_json::json!({
                "archive": info.path.display().to_string(),
                "sha256": info.sha256,
            }))
            .sticky(true),
        )
        .await;

    Ok(ExportReport {
        archive: info.path,
        sha256: info.sha256,
        size_bytes: info.size_bytes,
        members: info.members,
        relays_stopped: stopped,
        copied_to,
        next_steps: next_steps_after_export(&config.node.host),
    })
}

/// Steps the operator still owns after an export — printed by `hearthctl`, so they
/// cannot be forgotten halfway through an evening's move.
fn next_steps_after_export(address: &str) -> Vec<String> {
    vec![
        format!(
            "Point the router's port forwarding for {address} (5223, 443, 5443, 3478, \
             49160-49200/udp) at the mini-PC — while the old node is still running."
        ),
        "Copy the archive to the mini-PC (hearth-backup or a USB stick).".into(),
        "On the mini-PC: hearthctl migrate import <archive> --identity <age key>.".into(),
        "Verify the sha256 printed above on the destination before importing.".into(),
        "Do NOT start the relays on this machine again: two nodes with one CA and one \
         address is a split brain (ТЗ §10.2 п.5)."
            .into(),
        "After the new node is verified: cryptsetup luksErase (or destroy) this disk \
         (ТЗ §10.2 п.7)."
            .into(),
    ]
}

/// Restore an exported archive onto this machine (ТЗ §10.2 п.4).
///
/// `destination` is `/` on a real migration; tests and rehearsals (A13) pass a
/// scratch directory.
pub async fn import(
    state: &Arc<AppState>,
    archive_path: &Path,
    identity_file: &Path,
    destination: &Path,
    expected_sha256: Option<&str>,
) -> Result<ImportReport> {
    if let Some(expected) = expected_sha256 {
        let actual = crate::model::manifest::sha256_file(archive_path)?;
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(Error::Integrity(format!(
                "archive sha256 mismatch: expected {expected}, got {actual}"
            )));
        }
    }

    // Relays must not be running while their state directory is replaced.
    for relay in state.config.relays() {
        if relay.enabled {
            systemd::stop(&state.sys, &relay.unit).await?;
        }
    }

    let restored = archive::decrypt_and_extract(archive_path, identity_file, destination)?;

    // Verify the binaries on THIS machine against the manifest that just arrived
    // (ТЗ §10.2 п.4: "проверка sha256 бинарей").
    let manifest_path = if destination == Path::new("/") {
        state.config.paths.manifest.clone()
    } else {
        destination.join(relative(&state.config.paths.manifest))
    };
    let (integrity_ok, integrity_notes) = verify_binaries(&manifest_path);

    {
        let mut status = state.migrate.write().await;
        status.imported_at = Some(Utc::now());
        status.archive = Some(archive_path.to_path_buf());
    }
    state.save_migrate_status().await?;

    Ok(ImportReport {
        restored,
        destination: destination.to_path_buf(),
        integrity_ok,
        integrity_notes,
        next_steps: vec![
            "Load the nftables ruleset: nft -f /etc/hearth/nftables/hearth.nft".into(),
            "systemctl enable --now smp-server xftp-server coturn hearthd".into(),
            "hearthctl health — every service must be ok".into(),
            "Send one message from a phone; the client must not notice anything \
             (ТЗ §10.2 п.6)."
                .into(),
            "Confirm the old node is powered off and will not come back with these keys.".into(),
        ],
    })
}

/// Hash the manifest's binaries on this machine.
fn verify_binaries(manifest_path: &Path) -> (bool, Vec<String>) {
    match crate::model::manifest::Manifest::load(manifest_path) {
        Ok(manifest) => {
            let findings = manifest.verify_all();
            let notes: Vec<String> = findings
                .iter()
                .map(|f| format!("{}: {:?}", f.name, f.status))
                .collect();
            let ok = findings
                .iter()
                .all(|f| f.status == crate::model::manifest::IntegrityStatus::Ok);
            (ok, notes)
        }
        Err(e) => (
            false,
            vec![format!(
                "cannot read the imported manifest {}: {e}",
                manifest_path.display()
            )],
        ),
    }
}

/// `/etc/hearth/manifest.toml` -> `etc/hearth/manifest.toml`, for rehearsals that
/// extract into a scratch directory rather than onto `/`.
fn relative(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        if let std::path::Component::Normal(part) = component {
            out.push(part);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::Sys;
    use age::secrecy::ExposeSecret as _;

    fn seed_node(dir: &Path) -> crate::config::Config {
        let mut config = crate::state::tests::test_config(dir);
        let etc_simplex = dir.join("etc/opt/simplex");
        std::fs::create_dir_all(&etc_simplex).expect("mkdir");
        std::fs::write(etc_simplex.join("ca.key"), b"RELAY-CA").expect("write");
        std::fs::write(etc_simplex.join("fingerprint"), b"FINGERPRINT").expect("write");

        let etc_hearth = dir.join("etc-hearth");
        std::fs::create_dir_all(&etc_hearth).expect("mkdir");
        std::fs::write(etc_hearth.join("devices.json"), b"{\"devices\":[]}").expect("write");

        config.backup.paths = vec![etc_simplex, etc_hearth];
        config
    }

    fn keyfile(dir: &Path) -> (String, PathBuf) {
        let identity = age::x25519::Identity::generate();
        let path = dir.join("age-key.txt");
        std::fs::write(&path, identity.to_string().expose_secret()).expect("write");
        (identity.to_public().to_string(), path)
    }

    #[tokio::test]
    async fn export_stops_relays_and_produces_a_verifiable_archive() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = seed_node(dir.path());
        let (recipient, _key) = keyfile(dir.path());
        config.backup.recipients = vec![recipient];

        let state = AppState::new(config, Sys::new(true)).expect("state");
        let report = export(&state).await.expect("export");

        assert!(report.archive.exists());
        assert_eq!(report.sha256.len(), 64);
        assert_eq!(
            report.relays_stopped,
            vec![
                "smp-server.service".to_string(),
                "xftp-server.service".to_string(),
                "coturn.service".to_string()
            ]
        );
        assert!(report
            .next_steps
            .iter()
            .any(|s| s.contains("port forwarding")));
        assert!(report.next_steps.iter().any(|s| s.contains("split brain")));

        let status = state.migrate.read().await;
        assert!(status.relays_stopped);
        assert_eq!(status.sha256.as_deref(), Some(report.sha256.as_str()));
    }

    #[tokio::test]
    async fn export_copies_the_archive_to_hearth_backup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = seed_node(dir.path());
        let (recipient, _key) = keyfile(dir.path());
        config.backup.recipients = vec![recipient];
        config.backup.remote = Some(crate::config::BackupRemote {
            host: "192.168.1.20".parse().expect("ip"),
            port: 22,
            user: "hearth-backup".into(),
            path: "/srv/hearth-backup".into(),
            ssh_key: dir.path().join("id_ed25519"),
        });

        // dry-run Sys: rsync is recorded, not executed.
        let state = AppState::new(config, Sys::new(true)).expect("state");
        let report = export(&state).await.expect("export");

        assert_eq!(
            report.copied_to.as_deref(),
            Some("hearth-backup@192.168.1.20:/srv/hearth-backup"),
            "ТЗ §10.2 п.3: the archive must not stay only on the machine being retired"
        );
        assert_eq!(
            state.migrate.read().await.copied_to.as_deref(),
            report.copied_to.as_deref()
        );
    }

    #[tokio::test]
    async fn import_restores_the_identity_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = seed_node(dir.path());
        let (recipient, key) = keyfile(dir.path());
        config.backup.recipients = vec![recipient];

        let state = AppState::new(config, Sys::new(true)).expect("state");
        let report = export(&state).await.expect("export");

        let dest = dir.path().join("new-node");
        let imported = import(&state, &report.archive, &key, &dest, Some(&report.sha256))
            .await
            .expect("import");

        // Archive members keep the source path minus its root, so in this fixture they
        // sit under the temp directory's path. On a real node the source is
        // /etc/opt/simplex and the member is etc/opt/simplex.
        let ca_member = imported
            .restored
            .iter()
            .find(|p| p.ends_with("ca.key"))
            .expect("the relay CA must survive the move");
        assert!(ca_member.to_string_lossy().contains("etc/opt/simplex"));
        let restored_ca = dest.join(ca_member);
        assert_eq!(std::fs::read(restored_ca).expect("read"), b"RELAY-CA");
        assert!(imported.next_steps.iter().any(|s| s.contains("nftables")));
        // The manifest is not part of this fixture, so integrity cannot be confirmed.
        assert!(!imported.integrity_ok);
    }

    #[tokio::test]
    async fn import_refuses_a_tampered_archive() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = seed_node(dir.path());
        let (recipient, key) = keyfile(dir.path());
        config.backup.recipients = vec![recipient];

        let state = AppState::new(config, Sys::new(true)).expect("state");
        let report = export(&state).await.expect("export");

        let err = import(
            &state,
            &report.archive,
            &key,
            &dir.path().join("out"),
            Some(&"f".repeat(64)),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::Integrity(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn import_refuses_the_wrong_age_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = seed_node(dir.path());
        let (recipient, _key) = keyfile(dir.path());
        config.backup.recipients = vec![recipient];

        let state = AppState::new(config, Sys::new(true)).expect("state");
        let report = export(&state).await.expect("export");

        let other = age::x25519::Identity::generate();
        let wrong = dir.path().join("wrong-key.txt");
        std::fs::write(&wrong, other.to_string().expose_secret()).expect("write");

        let err = import(
            &state,
            &report.archive,
            &wrong,
            &dir.path().join("out2"),
            None,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("decrypt"), "got {err}");
    }

    #[test]
    fn relative_strips_the_root() {
        assert_eq!(
            relative(Path::new("/etc/hearth/manifest.toml")),
            PathBuf::from("etc/hearth/manifest.toml")
        );
    }
}

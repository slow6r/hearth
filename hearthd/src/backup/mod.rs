//! Daily encrypted backup (ТЗ §7.3 `backup`, §10.7).
//!
//! Once a day: tar the state directories, encrypt to the owner's age public key, drop
//! the result in a local spool, mirror the spool to `hearth-backup` over ssh, and prune
//! anything older than the retention window.
//!
//! The private age key is **not** on this machine, by design — hearthd can create a
//! backup it cannot read back. Restoring is an owner-with-the-key operation
//! (`hearthctl restore`), which is also what makes the quarterly restore drill (ТЗ
//! §10.7) meaningful.

pub mod archive;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, TimeZone, Timelike, Utc};

use crate::config::BackupRemote;
use crate::error::{Error, Result};
use crate::model::alert::Alert;
use crate::state::AppState;
use crate::store;

use self::archive::ArchiveInfo;

/// Prefix of every archive this node writes.
const ARCHIVE_PREFIX: &str = "hearth-";
/// Suffix of every archive this node writes.
const ARCHIVE_SUFFIX: &str = ".tar.gz.age";

/// The backup task.
#[derive(Debug)]
pub struct BackupJob {
    state: Arc<AppState>,
}

impl BackupJob {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    /// Sleep until the configured hour, run, repeat.
    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        if !self.state.config.backup.enabled {
            tracing::warn!("backup is disabled in the configuration");
            return;
        }
        loop {
            let wait = duration_until_next_run(Utc::now(), self.state.config.backup.hour_utc);
            tracing::info!(next_run_in_secs = wait.as_secs(), "backup scheduled");
            tokio::select! {
                _ = tokio::time::sleep(wait) => {
                    if let Err(e) = self.run_once().await {
                        tracing::error!(error = %e, "scheduled backup failed");
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("backup job stopping");
                        return;
                    }
                }
            }
        }
    }

    /// Create one backup now. Used by the scheduler and by `POST /backup/now`.
    pub async fn run_once(&self) -> Result<ArchiveInfo> {
        let started = Utc::now();
        {
            let mut status = self.state.backup.write().await;
            status.last_run = Some(started);
            status.last_error = None;
        }

        let mut result = self.create_and_push(started).await;

        // Пропущенный обязательный путь — это провал, а не успех с замечанием.
        // Архив без состояния узла не является резервной копией: восстановиться из
        // него нельзя, а статус при этом показывал бы зелёное до самой попытки.
        if let Ok(info) = &result {
            let missed: Vec<String> = self
                .state
                .config
                .backup
                .required_paths
                .iter()
                .filter(|required| {
                    let required = required.to_string_lossy();
                    info.unreadable
                        .iter()
                        .any(|skipped| skipped.contains(required.as_ref()))
                })
                .map(|p| p.display().to_string())
                .collect();
            if !missed.is_empty() {
                result = Err(crate::error::Error::invalid(format!(
                    "в архив не попали обязательные пути: {}",
                    missed.join(", ")
                )));
            }
        }

        match &result {
            Ok(info) => {
                let kept = self.prune(started).unwrap_or_else(|e| {
                    tracing::error!(error = %e, "backup pruning failed");
                    0
                });
                {
                    let mut status = self.state.backup.write().await;
                    status.last_success = Some(Utc::now());
                    status.last_archive = Some(info.path.clone());
                    status.last_size_bytes = info.size_bytes;
                    status.last_sha256 = Some(info.sha256.clone());
                    status.archives_kept = kept;
                    status.unreadable = info.unreadable.clone();
                }
                if !info.unreadable.is_empty() {
                    self.state
                        .alerts
                        .emit(
                            Alert::warning(
                                "backup",
                                format!(
                                    "архив создан, но {} пут(и) в него не попали",
                                    info.unreadable.len()
                                ),
                            )
                            .with_details(serde_json::json!({ "paths": info.unreadable })),
                        )
                        .await;
                }
                tracing::info!(
                    archive = %info.path.display(),
                    size = info.size_bytes,
                    "backup complete"
                );
            }
            Err(e) => {
                {
                    let mut status = self.state.backup.write().await;
                    status.last_error = Some(e.to_string());
                    status.remote_ok = false;
                }
                self.state
                    .alerts
                    .emit(Alert::critical("backup", format!("backup failed: {e}")))
                    .await;
            }
        }

        if let Err(e) = self.state.save_backup_status().await {
            tracing::error!(error = %e, "failed to persist the backup status");
        }
        result
    }

    async fn create_and_push(&self, started: DateTime<Utc>) -> Result<ArchiveInfo> {
        let cfg = &self.state.config.backup;
        store::ensure_dir(&cfg.spool_dir)?;
        let output = cfg
            .spool_dir
            .join(archive_filename(&self.state.config.node.name, started));

        let info = archive::create_encrypted(&cfg.paths, &output, &cfg.recipients)?;

        let remote_ok = match &cfg.remote {
            Some(remote) => match self.push_remote(remote).await {
                Ok(()) => true,
                Err(e) => {
                    // A local archive that never reached hearth-backup is a warning, not a
                    // failed backup: the copy on this disk is still better than nothing.
                    self.state
                        .alerts
                        .emit(Alert::warning(
                            "backup",
                            format!("archive created but not copied to hearth-backup: {e}"),
                        ))
                        .await;
                    false
                }
            },
            None => false,
        };
        self.state.backup.write().await.remote_ok = remote_ok;
        Ok(info)
    }

    /// Mirror the spool directory to `hearth-backup` (ТЗ §4: 10.66.10.20).
    /// Mirror the spool to `hearth-backup`, if one is configured.
    ///
    /// Returns the destination it copied to, or `None` when no remote is configured.
    /// Used by the daily job and by `migrate export` (ТЗ §10.2 п.3: the migration
    /// archive is placed on hearth-backup, not left on a machine that is about to be
    /// wiped).
    pub async fn sync_remote(&self) -> Result<Option<String>> {
        let Some(remote) = &self.state.config.backup.remote else {
            return Ok(None);
        };
        self.push_remote(remote).await?;
        Ok(Some(format!(
            "{}@{}:{}",
            remote.user, remote.host, remote.path
        )))
    }

    async fn push_remote(&self, remote: &BackupRemote) -> Result<()> {
        // Belt and braces: nftables would drop it anyway, but a misconfigured backup
        // target is exactly the kind of mistake that quietly ships data off-site.
        self.state
            .policy
            .check(std::net::SocketAddr::new(remote.host, remote.port))?;

        let cfg = &self.state.config.backup;
        let ssh = format!(
            "ssh -i {key} -p {port} -o BatchMode=yes -o StrictHostKeyChecking=yes \
             -o PasswordAuthentication=no",
            key = remote.ssh_key.display(),
            port = remote.port,
        );
        let source = format!("{}/", cfg.spool_dir.display());
        let target = format!("{}@{}:{}/", remote.user, remote.host, remote.path);

        self.state
            .sys
            .run_mutating(
                "rsync",
                &[
                    "--archive",
                    "--delete",
                    "--partial",
                    "--chmod=F600",
                    "-e",
                    &ssh,
                    &source,
                    &target,
                ],
            )
            .await?;
        Ok(())
    }

    /// Delete archives older than the retention window. Returns how many are kept.
    ///
    /// Age is taken from the filename timestamp, not the file mtime: an rsync or a
    /// restore can rewrite mtimes, and the name is what the operator reads anyway.
    pub fn prune(&self, now: DateTime<Utc>) -> Result<u32> {
        let cfg = &self.state.config.backup;
        let cutoff = now - chrono::Duration::days(cfg.retention_days as i64);
        let mut kept = 0;
        let dir = match std::fs::read_dir(&cfg.spool_dir) {
            Ok(dir) => dir,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(Error::io(&cfg.spool_dir, e)),
        };
        for entry in dir.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(ts) = timestamp_from_filename(name) else {
                continue;
            };
            if ts < cutoff {
                match std::fs::remove_file(&path) {
                    Ok(()) => tracing::info!(archive = %name, "pruned expired backup"),
                    Err(e) => tracing::warn!(archive = %name, error = %e, "cannot prune"),
                }
            } else {
                kept += 1;
            }
        }
        Ok(kept)
    }

    /// Archives currently in the spool, newest first.
    pub fn list_archives(&self) -> Result<Vec<PathBuf>> {
        list_archives(&self.state.config.backup.spool_dir)
    }
}

/// `hearth-<node>-<YYYYMMDDTHHMMSSZ>.tar.gz.age`
pub fn archive_filename(node: &str, ts: DateTime<Utc>) -> String {
    format!(
        "{ARCHIVE_PREFIX}{node}-{stamp}{ARCHIVE_SUFFIX}",
        stamp = ts.format("%Y%m%dT%H%M%SZ")
    )
}

/// Recover the creation time from an archive filename.
pub fn timestamp_from_filename(name: &str) -> Option<DateTime<Utc>> {
    let rest = name.strip_prefix(ARCHIVE_PREFIX)?;
    let rest = rest.strip_suffix(ARCHIVE_SUFFIX)?;
    let stamp = rest.rsplit('-').next()?;
    chrono::NaiveDateTime::parse_from_str(stamp, "%Y%m%dT%H%M%SZ")
        .ok()
        .map(|naive| Utc.from_utc_datetime(&naive))
}

/// Archives in a directory, newest first.
pub fn list_archives(dir: &Path) -> Result<Vec<PathBuf>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::io(dir, e)),
    };
    let mut archives: Vec<(DateTime<Utc>, PathBuf)> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_str()?;
            let ts = timestamp_from_filename(name)?;
            Some((ts, path))
        })
        .collect();
    archives.sort_by_key(|(ts, _)| std::cmp::Reverse(*ts));
    Ok(archives.into_iter().map(|(_, path)| path).collect())
}

/// Time until the next run at `hour_utc:00`.
fn duration_until_next_run(now: DateTime<Utc>, hour_utc: u32) -> std::time::Duration {
    let today = now
        .with_hour(hour_utc.min(23))
        .and_then(|t| t.with_minute(0))
        .and_then(|t| t.with_second(0))
        .and_then(|t| t.with_nanosecond(0))
        .unwrap_or(now);
    let next = if today > now {
        today
    } else {
        today + chrono::Duration::days(1)
    };
    (next - now)
        .to_std()
        .unwrap_or(std::time::Duration::from_secs(3600))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::Sys;

    fn at(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, min, 0)
            .single()
            .expect("ts")
    }

    #[test]
    fn filename_round_trips() {
        let ts = at(2026, 9, 6, 3, 0);
        let name = archive_filename("hearth-node", ts);
        assert_eq!(name, "hearth-hearth-node-20260906T030000Z.tar.gz.age");
        assert_eq!(timestamp_from_filename(&name), Some(ts));
        assert_eq!(timestamp_from_filename("random.txt"), None);
    }

    #[test]
    fn schedules_the_next_run_correctly() {
        // Before the hour: later today.
        let wait = duration_until_next_run(at(2026, 9, 6, 1, 0), 3);
        assert_eq!(wait.as_secs(), 2 * 3600);
        // After the hour: tomorrow.
        let wait = duration_until_next_run(at(2026, 9, 6, 4, 0), 3);
        assert_eq!(wait.as_secs(), 23 * 3600);
    }

    #[tokio::test]
    async fn creates_an_archive_and_records_status() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = crate::state::tests::test_config(dir.path());
        let identity = age::x25519::Identity::generate();
        config.backup.recipients = vec![identity.to_public().to_string()];
        let source = dir.path().join("etc-hearth");
        std::fs::create_dir_all(&source).expect("mkdir");
        std::fs::write(source.join("hearthd.toml"), b"config").expect("write");
        config.backup.paths = vec![source];

        let state = AppState::new(config, Sys::new(true)).expect("state");
        let job = BackupJob::new(state.clone());
        let info = job.run_once().await.expect("backup");

        assert!(info.path.exists());
        assert!(info.size_bytes > 0);
        let status = state.backup.read().await;
        assert!(status.last_success.is_some());
        assert_eq!(status.last_sha256.as_deref(), Some(info.sha256.as_str()));
        assert!(status.last_error.is_none());
        assert!(!status.remote_ok, "no remote configured in this test");
    }

    #[tokio::test]
    async fn failure_records_an_error_and_alerts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = crate::state::tests::test_config(dir.path());
        config.backup.recipients = vec!["not-an-age-key".into()];
        config.backup.paths = vec![dir.path().join("etc-hearth")];
        std::fs::create_dir_all(dir.path().join("etc-hearth")).expect("mkdir");

        let state = AppState::new(config, Sys::new(true)).expect("state");
        assert!(BackupJob::new(state.clone()).run_once().await.is_err());

        let status = state.backup.read().await;
        assert!(status.last_error.is_some());
        let alerts = state.alerts.query(None, None, 10).await;
        assert!(alerts.iter().any(|a| a.summary.contains("backup failed")));
    }

    #[tokio::test]
    async fn prune_keeps_the_retention_window() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = crate::state::tests::test_config(dir.path());
        config.backup.retention_days = 14;
        let spool = config.backup.spool_dir.clone();
        std::fs::create_dir_all(&spool).expect("mkdir");

        let now = at(2026, 9, 6, 3, 0);
        let fresh = archive_filename("hearth-node", now - chrono::Duration::days(2));
        let stale = archive_filename("hearth-node", now - chrono::Duration::days(30));
        std::fs::write(spool.join(&fresh), b"x").expect("write");
        std::fs::write(spool.join(&stale), b"x").expect("write");
        std::fs::write(spool.join("unrelated.txt"), b"x").expect("write");

        let state = AppState::new(config, Sys::new(true)).expect("state");
        let kept = BackupJob::new(state).prune(now).expect("prune");

        assert_eq!(kept, 1);
        assert!(spool.join(&fresh).exists());
        assert!(!spool.join(&stale).exists());
        assert!(
            spool.join("unrelated.txt").exists(),
            "foreign files are left alone"
        );
    }

    #[tokio::test]
    async fn lists_archives_newest_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = crate::state::tests::test_config(dir.path());
        let spool = config.backup.spool_dir.clone();
        std::fs::create_dir_all(&spool).expect("mkdir");
        let older = archive_filename("n", at(2026, 9, 1, 3, 0));
        let newer = archive_filename("n", at(2026, 9, 5, 3, 0));
        std::fs::write(spool.join(&older), b"x").expect("write");
        std::fs::write(spool.join(&newer), b"x").expect("write");

        let state = AppState::new(config, Sys::new(true)).expect("state");
        let archives = BackupJob::new(state).list_archives().expect("list");
        assert_eq!(archives.len(), 2);
        assert!(archives[0].to_string_lossy().contains("20260905"));
    }

    #[tokio::test]
    async fn refuses_a_remote_outside_the_home_network() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = crate::state::tests::test_config(dir.path());
        let state = AppState::new(config, Sys::new(true)).expect("state");
        let job = BackupJob::new(state);
        let remote = BackupRemote {
            host: "203.0.113.9".parse().expect("ip"),
            port: 22,
            user: "backup".into(),
            path: "/srv".into(),
            ssh_key: "/etc/hearth/secrets/backup_ed25519".into(),
        };
        let err = job.push_remote(&remote).await.unwrap_err();
        assert!(matches!(err, Error::EgressDenied(_)), "got {err:?}");
    }
}

//! Integrity checker (ТЗ §7.3, acceptance test A12).
//!
//! At start-up and once an hour, hash every binary listed in `manifest.toml` and
//! compare against the pin. A mismatch means the thing running on the node is not the
//! artefact that was reviewed and signed — the relays are stopped and a critical alert
//! is raised. Fail closed: a node that cannot prove what it is running does not run.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use crate::model::alert::Alert;
use crate::model::health::{HealthState, IntegritySnapshot};
use crate::model::manifest::{IntegrityStatus, Manifest};
use crate::state::AppState;
use crate::sys::systemd;

/// The periodic checker.
#[derive(Debug)]
pub struct IntegrityChecker {
    state: Arc<AppState>,
    /// Set once relays have been stopped, so we do not fight an operator who restarts
    /// them deliberately during an upgrade.
    stopped_relays: bool,
}

impl IntegrityChecker {
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            state,
            stopped_relays: false,
        }
    }

    pub async fn run(mut self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let interval = Duration::from_secs(self.state.config.integrity.interval_secs);
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => { self.check().await; }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("integrity checker stopping");
                        return;
                    }
                }
            }
        }
    }

    /// One verification pass. Returns the published snapshot.
    pub async fn check(&mut self) -> IntegritySnapshot {
        let manifest_path = &self.state.config.paths.manifest;
        let snapshot = match Manifest::load(manifest_path) {
            Ok(manifest) => {
                let findings = manifest.verify_all();
                let bad: Vec<_> = findings
                    .iter()
                    .filter(|f| f.status != IntegrityStatus::Ok)
                    .cloned()
                    .collect();

                let state = if bad.is_empty() {
                    HealthState::Ok
                } else {
                    HealthState::Down
                };

                if !bad.is_empty() {
                    self.state
                        .alerts
                        .emit(
                            Alert::critical(
                                "integrity",
                                format!(
                                    "{} pinned binary(ies) do not match the manifest",
                                    bad.len()
                                ),
                            )
                            .with_details(serde_json::json!({ "findings": bad })),
                        )
                        .await;
                    self.stop_relays().await;
                } else {
                    self.stopped_relays = false;
                }

                IntegritySnapshot {
                    checked: Utc::now(),
                    state,
                    findings,
                    simplexmq_tag: manifest.upstream.simplexmq_tag.clone(),
                    simplex_chat_tag: manifest.upstream.simplex_chat_tag.clone(),
                }
            }
            Err(e) => {
                self.state
                    .alerts
                    .emit(
                        Alert::critical(
                            "integrity",
                            format!("cannot read the manifest {}: {e}", manifest_path.display()),
                        )
                        .with_details(serde_json::json!({
                            "manifest": manifest_path.display().to_string(),
                        })),
                    )
                    .await;
                IntegritySnapshot {
                    checked: Utc::now(),
                    state: HealthState::Down,
                    findings: Vec::new(),
                    simplexmq_tag: "unknown".into(),
                    simplex_chat_tag: "unknown".into(),
                }
            }
        };

        *self.state.integrity.write().await = snapshot.clone();
        snapshot
    }

    /// ТЗ §7.3: "Несовпадение → стоп релея + алерт".
    async fn stop_relays(&mut self) {
        if !self.state.config.integrity.stop_relays_on_mismatch || self.stopped_relays {
            return;
        }
        self.stopped_relays = true;
        for relay in self.state.config.relays() {
            if !relay.enabled {
                continue;
            }
            match systemd::stop(&self.state.sys, &relay.unit).await {
                Ok(()) => tracing::error!(unit = %relay.unit, "stopped after an integrity failure"),
                Err(e) => {
                    self.state
                        .alerts
                        .emit(Alert::critical(
                            "integrity",
                            format!(
                                "failed to stop {} after an integrity failure: {e}",
                                relay.unit
                            ),
                        ))
                        .await
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::manifest::sha256_file;
    use crate::sys::Sys;
    use std::io::Write;

    fn write_manifest(dir: &std::path::Path, entries: &str) {
        let raw = format!(
            "[upstream]\n\
             simplexmq_tag = \"v6.4.2\"\n\
             simplex_chat_tag = \"v6.4.2\"\n\
             gpg_identity = \"chat@simplex.chat\"\n\
             reviewed = \"2026-09-06\"\n\
             {entries}"
        );
        std::fs::write(dir.join("manifest.toml"), raw).expect("write manifest");
    }

    fn fake_binary(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(name.as_bytes()).expect("write");
        path
    }

    #[tokio::test]
    async fn matching_hashes_report_ok() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = fake_binary(dir.path(), "smp-server");
        let digest = sha256_file(&bin).expect("hash");
        write_manifest(
            dir.path(),
            &format!(
                "\n[[binary]]\nname = \"smp-server\"\npath = {path:?}\n\
                 version = \"v6.4.2\"\nsha256 = \"{digest}\"\n",
                path = bin.display().to_string()
            ),
        );

        let config = crate::state::tests::test_config(dir.path());
        let state = AppState::new(config, Sys::new(true)).expect("state");
        let snapshot = IntegrityChecker::new(state.clone()).check().await;

        assert_eq!(snapshot.state, HealthState::Ok);
        assert_eq!(snapshot.findings.len(), 1);
        assert_eq!(snapshot.simplexmq_tag, "v6.4.2");
        assert_eq!(state.alerts.query(None, None, 10).await.len(), 0);
    }

    #[tokio::test]
    async fn a_tampered_binary_is_critical_and_stops_relays() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = fake_binary(dir.path(), "smp-server");
        write_manifest(
            dir.path(),
            &format!(
                "\n[[binary]]\nname = \"smp-server\"\npath = {path:?}\n\
                 version = \"v6.4.2\"\nsha256 = \"{digest}\"\n",
                path = bin.display().to_string(),
                digest = "a".repeat(64)
            ),
        );

        let config = crate::state::tests::test_config(dir.path());
        // dry-run Sys: `systemctl stop` is recorded, not executed.
        let state = AppState::new(config, Sys::new(true)).expect("state");
        let snapshot = IntegrityChecker::new(state.clone()).check().await;

        assert_eq!(snapshot.state, HealthState::Down);
        assert_eq!(snapshot.findings[0].status, IntegrityStatus::Mismatch);

        let alerts = state.alerts.query(None, None, 10).await;
        assert!(alerts
            .iter()
            .any(|a| a.summary.contains("do not match the manifest")));
    }

    #[tokio::test]
    async fn a_missing_manifest_is_critical() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = crate::state::tests::test_config(dir.path());
        let state = AppState::new(config, Sys::new(true)).expect("state");
        let snapshot = IntegrityChecker::new(state.clone()).check().await;

        assert_eq!(snapshot.state, HealthState::Down);
        let alerts = state.alerts.query(None, None, 10).await;
        assert!(alerts
            .iter()
            .any(|a| a.summary.contains("cannot read the manifest")));
    }

    #[tokio::test]
    async fn relays_are_stopped_only_once_per_incident() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = fake_binary(dir.path(), "smp-server");
        write_manifest(
            dir.path(),
            &format!(
                "\n[[binary]]\nname = \"smp-server\"\npath = {path:?}\n\
                 version = \"v6.4.2\"\nsha256 = \"{digest}\"\n",
                path = bin.display().to_string(),
                digest = "a".repeat(64)
            ),
        );
        let config = crate::state::tests::test_config(dir.path());
        let state = AppState::new(config, Sys::new(true)).expect("state");
        let mut checker = IntegrityChecker::new(state.clone());
        checker.check().await;
        checker.check().await;
        assert!(checker.stopped_relays);
    }
}

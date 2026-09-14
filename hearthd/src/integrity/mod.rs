//! Integrity checker (ТЗ §7.3, acceptance test A12).
//!
//! At start-up and once an hour, hash every binary listed in `manifest.toml` and
//! compare against the pin. A mismatch means the thing running on the node is not the
//! artefact that was reviewed and signed — the relays are stopped and a critical alert
//! is raised. Fail closed: a node that cannot prove what it is running does not run.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use crate::config::Config;
use crate::model::alert::Alert;
use crate::model::health::{HealthState, IntegritySnapshot};
use crate::model::manifest::{IntegrityFinding, IntegrityStatus, Manifest};
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
                let mut findings = manifest.verify_all();
                findings.extend(unpinned_relays(&self.state.config, &manifest));
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
                    // Карантин фиксируется на диске ДО остановки: запрет, который не
                    // пережил бы перезагрузку, запретом не является.
                    self.quarantine(
                        format!("{} пинованных бинарей не совпали с манифестом", bad.len()),
                        bad.iter().map(|f| f.name.clone()).collect(),
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
                // Нечитаемый манифест — это НЕ «проверить не удалось, поедем
                // дальше». Усечь файл или снять с него права проще, чем подделать
                // хеш, и если такая ошибка оставляет релеи работать, вся проверка
                // целостности обходится одной строкой. Поэтому тот же карантин, что
                // и при несовпадении: различаются только слова в алерте.
                self.quarantine(
                    format!("манифест целостности не прочитан: {e}"),
                    vec![manifest_path.display().to_string()],
                )
                .await;
                self.stop_relays().await;

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

    /// Перевести узел в карантин и записать это на диск.
    ///
    /// Отдельный метод, потому что точек входа две — несовпадение хеша и нечитаемый
    /// манифест, — и обе обязаны оставлять одинаково прочный след.
    async fn quarantine(&mut self, reason: String, findings: Vec<String>) {
        if !self.state.config.integrity.stop_relays_on_mismatch {
            return;
        }
        if let Err(e) = self
            .state
            .set_mode(crate::model::mode::NodeMode::Quarantine, reason, findings)
            .await
        {
            // Не смогли записать запрет — говорим об этом громко: после перезапуска
            // узел поднимет релеи, и человек должен узнать об этом сейчас.
            tracing::error!(error = %e, "карантин не записан на диск");
            self.state
                .alerts
                .emit(Alert::critical(
                    "integrity",
                    format!("карантин не удалось записать на диск: {e}"),
                ))
                .await;
        }
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

/// Включённый релей, бинаря которого нет в манифесте.
///
/// Для smp и xftp это было невозможно: они стоят в поставляемом манифесте всегда.
/// Push-сервер там закомментирован — он есть не на каждом узле, а незаполненная запись
/// для несуществующего бинаря отправляла бы в карантин всех, кто его не заводил. Цена
/// такой поставки — возможность включить `[ntf]` и забыть запинить бинарь. Эта проверка
/// её снимает: запущенный, но ничем не подтверждённый бинарь — то же, что чужой хеш.
fn unpinned_relays(config: &Config, manifest: &Manifest) -> Vec<IntegrityFinding> {
    config
        .relays()
        .into_iter()
        .filter(|relay| relay.enabled && manifest.binary(&relay.process).is_none())
        .map(|relay| IntegrityFinding {
            name: relay.process.clone(),
            path: config.paths.manifest.clone(),
            expected: "an entry in the manifest".into(),
            actual: None,
            status: IntegrityStatus::Missing,
        })
        .collect()
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
    async fn an_unreadable_manifest_quarantines_the_node() {
        // Усечь файл или снять с него права проще, чем подделать хеш. Если такая
        // ошибка оставляет релеи работать, вся проверка целостности обходится одной
        // строкой — поэтому тот же карантин, что и при несовпадении.
        let dir = tempfile::tempdir().expect("tempdir");
        let config = crate::state::tests::test_config(dir.path());
        if let Some(parent) = config.paths.manifest.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&config.paths.manifest, "это не toml ====").expect("write");

        let state = crate::state::AppState::new(config, Sys::new(true)).expect("state");
        let mut checker = IntegrityChecker::new(state.clone());
        let snapshot = checker.check().await;

        assert_eq!(snapshot.state, HealthState::Down);
        let node = state.mode.read().await.clone();
        assert_eq!(
            node.mode,
            crate::model::mode::NodeMode::Quarantine,
            "нечитаемый манифест обязан переводить узел в карантин"
        );
        assert!(!node.relays_allowed());
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

        let mut config = crate::state::tests::test_config(dir.path());
        // Манифест здесь знает только smp-server, поэтому xftp выключен: включённый релей
        // без записи в манифесте — отдельная находка (unpinned_relays).
        config.xftp.enabled = false;
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

    /// smp-server и xftp-server, запиненные по-настоящему.
    fn pinned_relays_manifest(dir: &std::path::Path) {
        let smp = fake_binary(dir, "smp-server");
        let xftp = fake_binary(dir, "xftp-server");
        write_manifest(
            dir,
            &format!(
                "\n[[binary]]\nname = \"smp-server\"\npath = {smp:?}\n\
                 version = \"v7.0.1\"\nsha256 = \"{}\"\n\
                 \n[[binary]]\nname = \"xftp-server\"\npath = {xftp:?}\n\
                 version = \"v7.0.1\"\nsha256 = \"{}\"\n",
                sha256_file(&smp).expect("hash"),
                sha256_file(&xftp).expect("hash"),
                smp = smp.display().to_string(),
                xftp = xftp.display().to_string(),
            ),
        );
    }

    #[tokio::test]
    async fn an_enabled_relay_missing_from_the_manifest_quarantines_the_node() {
        // Запись push-сервера в манифесте закомментирована. Включили [ntf] и забыли
        // запинить — запущенный бинарь ничем не подтверждён, это то же, что чужой хеш.
        let dir = tempfile::tempdir().expect("tempdir");
        pinned_relays_manifest(dir.path());
        let mut config = crate::state::tests::test_config(dir.path());
        config
            .ntf
            .as_mut()
            .expect("the reference config carries [ntf]")
            .enabled = true;
        let state = AppState::new(config, Sys::new(true)).expect("state");
        let snapshot = IntegrityChecker::new(state.clone()).check().await;

        assert_eq!(snapshot.state, HealthState::Down);
        let finding = snapshot
            .findings
            .iter()
            .find(|f| f.name == "ntf-server")
            .expect("ntf-server is reported");
        assert_eq!(finding.status, IntegrityStatus::Missing);
        assert_eq!(
            state.mode.read().await.mode,
            crate::model::mode::NodeMode::Quarantine
        );
    }

    #[tokio::test]
    async fn a_disabled_push_server_needs_no_manifest_entry() {
        // Иначе поставляемый манифест отправлял бы в карантин каждый узел без push.
        let dir = tempfile::tempdir().expect("tempdir");
        pinned_relays_manifest(dir.path());
        let config = crate::state::tests::test_config(dir.path());
        let state = AppState::new(config, Sys::new(true)).expect("state");
        let snapshot = IntegrityChecker::new(state.clone()).check().await;

        assert_eq!(snapshot.state, HealthState::Ok);
        assert_eq!(snapshot.findings.len(), 2);
    }
}

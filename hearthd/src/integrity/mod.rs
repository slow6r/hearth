//! Integrity checker (ТЗ §7.3, acceptance test A12).
//!
//! At start-up and once an hour, hash every binary listed in `manifest.toml` and
//! compare against the pin. A mismatch means the thing running on the node is not the
//! artefact that was reviewed and signed — the relays are stopped and a critical alert
//! is raised. Fail closed: a node that cannot prove what it is running does not run.

use std::collections::HashSet;
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
    /// Юниты, о неудачной остановке которых уже сказано в этом инциденте.
    ///
    /// Раньше на этом месте стоял признак «релеи уже останавливали», и он подавлял
    /// саму остановку. Но это память о СВОЁМ действии, а не наблюдение за системой:
    /// релей, поднявшийся обратно во время карантина, второй раз не останавливался
    /// никогда. Теперь решение принимается по состоянию юнита (см. `stop_relays`), а
    /// этот список влияет только на частоту алертов.
    alerted_units: HashSet<String>,
    /// Карантин не удалось записать на диск — повторять запись на каждой проверке.
    mode_unpersisted: bool,
    /// Про незапинённые бинари уже сказано алертом в этом инциденте.
    ///
    /// Проверка идёт раз в час, а незапинённым бинарь остаётся до визита оператора:
    /// без этого признака журнал алертов состоял бы из одной и той же строки.
    unpinned_alerted: bool,
}

impl IntegrityChecker {
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            state,
            alerted_units: HashSet::new(),
            mode_unpersisted: false,
            unpinned_alerted: false,
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
                // Два разных события, и смешивать их нельзя. `bad` — настоящая
                // подмена или пропавший файл: карантин. `unpinned` — невыполненный
                // шаг установки: узел не поднимает релеи сам и громко просит запинить,
                // но запрет на диск не пишет и работающее не гасит.
                let bad: Vec<_> = findings
                    .iter()
                    .filter(|f| {
                        f.status != IntegrityStatus::Ok && f.status != IntegrityStatus::Unpinned
                    })
                    .cloned()
                    .collect();
                let unpinned: Vec<_> = findings
                    .iter()
                    .filter(|f| f.status == IntegrityStatus::Unpinned)
                    .cloned()
                    .collect();

                let state = if bad.is_empty() && unpinned.is_empty() {
                    HealthState::Ok
                } else {
                    HealthState::Down
                };

                if bad.is_empty() && !unpinned.is_empty() {
                    self.report_unpinned(&unpinned).await;
                }

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
                    self.alerted_units.clear();
                    if unpinned.is_empty() {
                        self.unpinned_alerted = false;
                    }
                    // Проверка сошлась, но режим мог не записаться на прошлом круге:
                    // в памяти запрет есть, на диске — нет. Снимать его нельзя (ADR
                    // 0013: карантин снимает человек), значит надо дописать.
                    self.persist_pending_mode().await;
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

    /// Сказать оператору про бинари, которые ещё никто не запинил.
    ///
    /// НЕ карантин и НЕ остановка: нулевой плейсхолдер не является уликой подмены, а
    /// поставочный манифест приходит с нулями во всех записях. Карантин здесь означал
    /// бы, что свежий узел через час сам себя выключает и требует локального снятия
    /// режима — из-за строки инструкции, которую оператор не выполнил. Вместо этого
    /// узел работает, надзор не поднимает релеи сам (см. `supervisor::may_restart`), а
    /// алерт называет точные команды.
    async fn report_unpinned(&mut self, unpinned: &[IntegrityFinding]) {
        let names: Vec<&str> = unpinned.iter().map(|f| f.name.as_str()).collect();
        tracing::error!(
            binaries = %names.join(", "),
            "в манифесте нулевые плейсхолдеры: узел не знает, что на нём работает"
        );
        if self.unpinned_alerted {
            return;
        }
        self.unpinned_alerted = true;
        let how = names
            .iter()
            .map(|name| format!("hearthctl manifest pin --name {name}"))
            .collect::<Vec<_>>()
            .join("; ");
        self.state
            .alerts
            .emit(
                Alert::critical(
                    "integrity",
                    format!(
                        "не запинено бинарей: {} ({}). Узел не может подтвердить, что \
                         на нём работает, и не поднимает релеи сам. Запинить: {how}",
                        names.len(),
                        names.join(", ")
                    ),
                )
                .with_details(serde_json::json!({ "findings": unpinned }))
                .sticky(true),
            )
            .await;
    }

    /// Перевести узел в карантин и записать это на диск.
    ///
    /// Отдельный метод, потому что точек входа две — несовпадение хеша и нечитаемый
    /// манифест, — и обе обязаны оставлять одинаково прочный след.
    async fn quarantine(&mut self, reason: String, findings: Vec<String>) {
        if !self.state.config.integrity.stop_relays_on_mismatch {
            return;
        }
        match self
            .state
            .set_mode(crate::model::mode::NodeMode::Quarantine, reason, findings)
            .await
        {
            Ok(()) => self.mode_unpersisted = false,
            Err(e) => {
                // Запрет уже действует в этом процессе (AppState::set_mode применяет
                // ужесточение до записи), но перезагрузку он не переживёт. Говорим
                // громко и пробуем записать снова на каждой следующей проверке.
                self.mode_unpersisted = true;
                tracing::error!(error = %e, "карантин не записан на диск");
                self.state
                    .alerts
                    .emit(Alert::critical(
                        "integrity",
                        format!(
                            "карантин не удалось записать на диск: {e}; он действует \
                             только до перезапуска hearthd"
                        ),
                    ))
                    .await;
            }
        }
    }

    /// Дописать на диск режим, который уже действует в памяти.
    async fn persist_pending_mode(&mut self) {
        if !self.mode_unpersisted {
            return;
        }
        match self.state.persist_mode().await {
            Ok(()) => {
                self.mode_unpersisted = false;
                tracing::warn!("режим узла наконец записан на диск");
            }
            Err(e) => tracing::error!(error = %e, "режим узла всё ещё не записан на диск"),
        }
    }

    /// ТЗ §7.3: "Несовпадение → стоп релея + алерт".
    ///
    /// Решение принимается по НАБЛЮДАЕМОМУ состоянию юнита, а не по памяти о прошлой
    /// остановке. Пока узел в карантине, работающий релей — это не воля оператора
    /// (ADR 0013), а обход карантина, и остановить его надо снова. Уже остановленному
    /// команда не выдаётся вовсе — иначе журнал тонул бы в `systemctl stop`.
    async fn stop_relays(&mut self) {
        if !self.state.config.integrity.stop_relays_on_mismatch {
            return;
        }
        for relay in self.state.config.relays() {
            if !relay.enabled {
                continue;
            }
            if !systemd::running(&self.state.sys, &relay.unit).await {
                continue;
            }
            match systemd::stop(&self.state.sys, &relay.unit).await {
                Ok(()) => {
                    self.alerted_units.remove(&relay.unit);
                    tracing::error!(unit = %relay.unit, "stopped after an integrity failure");
                }
                Err(e) => {
                    // Об одном и том же юните — один алерт на инцидент: проверка идёт
                    // раз в час, и повторы только прячут остальные события.
                    if self.alerted_units.insert(relay.unit.clone()) {
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

    /// Ответ `systemctl show` для всех юнитов сразу.
    fn all_units_are(sys: &Sys, active_state: &str) {
        sys.stub_capture(
            "systemctl show",
            crate::sys::Output::success(format!(
                "ActiveState={active_state}\nSubState={active_state}\nUnitFileState=enabled\n"
            )),
        );
    }

    /// Выданные команды остановки, по порядку.
    fn stops(sys: &Sys) -> Vec<String> {
        sys.recorded()
            .into_iter()
            .filter(|cmd| cmd.starts_with("systemctl stop "))
            .collect()
    }

    /// Манифест с заведомо неверным хешем smp-server.
    fn tampered_manifest(dir: &std::path::Path) {
        let bin = fake_binary(dir, "smp-server");
        write_manifest(
            dir,
            &format!(
                "\n[[binary]]\nname = \"smp-server\"\npath = {path:?}\n\
                 version = \"v6.4.2\"\nsha256 = \"{digest}\"\n",
                path = bin.display().to_string(),
                digest = "a".repeat(64)
            ),
        );
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

    /// Провенанс — запись о происхождении, а не предмет проверки. Попади он в
    /// вердикт — любой перепин версии ронял бы узел в карантин из-за расхождения
    /// строки, которую никто не измеряет.
    #[tokio::test]
    async fn a_provenance_field_does_not_change_the_verdict() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = fake_binary(dir.path(), "smp-server");
        let digest = sha256_file(&bin).expect("hash");
        write_manifest(
            dir.path(),
            &format!(
                "\n[[binary]]\nname = \"smp-server\"\npath = {path:?}\n\
                 version = \"v6.4.2\"\nsha256 = \"{digest}\"\n\
                 commit = \"{commit}\"\ntree_sha256 = \"{tree}\"\n",
                path = bin.display().to_string(),
                commit = "a".repeat(40),
                tree = "c".repeat(64),
            ),
        );

        let mut config = crate::state::tests::test_config(dir.path());
        config.xftp.enabled = false;
        let state = AppState::new(config, Sys::new(true)).expect("state");
        let snapshot = IntegrityChecker::new(state.clone()).check().await;

        assert_eq!(snapshot.state, HealthState::Ok);
        assert_eq!(snapshot.findings.len(), 1);
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
        // dry-run Sys: `systemctl stop` пишется в журнал вызовов, а не выполняется.
        let sys = Sys::new(true);
        all_units_are(&sys, "active");
        let state = AppState::new(config, sys).expect("state");
        let snapshot = IntegrityChecker::new(state.clone()).check().await;

        assert_eq!(snapshot.state, HealthState::Down);
        assert_eq!(snapshot.findings[0].status, IntegrityStatus::Mismatch);

        let alerts = state.alerts.query(None, None, 10).await;
        assert!(alerts
            .iter()
            .any(|a| a.summary.contains("do not match the manifest")));
        assert!(
            stops(&state.sys).contains(&"systemctl stop smp-server.service".to_string()),
            "получили {:?}",
            stops(&state.sys)
        );
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
    async fn a_relay_that_came_back_during_quarantine_is_stopped_again() {
        // Раньше вторую попытку подавлял признак «мы уже останавливали»: подменённый
        // бинарь, поднятый обратно (руками, перезагрузкой или тем, кто его подменил),
        // обслуживал трафик семьи бессрочно, а `hearthctl status` показывал карантин.
        let dir = tempfile::tempdir().expect("tempdir");
        tampered_manifest(dir.path());
        let sys = Sys::new(true);
        all_units_are(&sys, "inactive");
        let state =
            AppState::new(crate::state::tests::test_config(dir.path()), sys).expect("state");
        let mut checker = IntegrityChecker::new(state.clone());

        checker.check().await;
        assert!(
            stops(&state.sys).is_empty(),
            "остановленный релей останавливать незачем"
        );

        // Юнит поднялся обратно вопреки карантину.
        all_units_are(&state.sys, "active");
        checker.check().await;
        assert!(
            stops(&state.sys).contains(&"systemctl stop smp-server.service".to_string()),
            "получили {:?}",
            stops(&state.sys)
        );
    }

    #[tokio::test]
    async fn an_already_stopped_relay_is_not_stopped_twice() {
        let dir = tempfile::tempdir().expect("tempdir");
        tampered_manifest(dir.path());
        let sys = Sys::new(true);
        all_units_are(&sys, "inactive");
        let state =
            AppState::new(crate::state::tests::test_config(dir.path()), sys).expect("state");
        let mut checker = IntegrityChecker::new(state.clone());

        checker.check().await;
        checker.check().await;
        assert!(
            stops(&state.sys).is_empty(),
            "получили {:?}",
            stops(&state.sys)
        );
    }

    #[tokio::test]
    async fn an_unknown_unit_state_is_stopped_anyway() {
        // Недоступный systemd — не подтверждение того, что служба остановлена.
        let dir = tempfile::tempdir().expect("tempdir");
        tampered_manifest(dir.path());
        let sys = Sys::new(true);
        // Пустой вывод `systemctl show` разбирается в active_state = "unknown".
        sys.stub_capture("systemctl show", crate::sys::Output::success(""));
        let state =
            AppState::new(crate::state::tests::test_config(dir.path()), sys).expect("state");
        IntegrityChecker::new(state.clone()).check().await;

        assert!(
            stops(&state.sys).contains(&"systemctl stop smp-server.service".to_string()),
            "получили {:?}",
            stops(&state.sys)
        );
    }

    #[tokio::test]
    async fn a_quarantine_that_cannot_be_written_still_holds_this_process() {
        // Отказ диска не должен оставлять узел в противоречии: релеи остановлены, а
        // запрет нигде не действует — и надзор поднимает их через один тик.
        let dir = tempfile::tempdir().expect("tempdir");
        tampered_manifest(dir.path());
        let sys = Sys::new(true);
        all_units_are(&sys, "active");
        let state =
            AppState::new(crate::state::tests::test_config(dir.path()), sys).expect("state");
        let mode_file = state.config.paths.node_mode_file();
        std::fs::create_dir_all(&mode_file).expect("каталог на месте файла режима");

        IntegrityChecker::new(state.clone()).check().await;

        let node = state.mode.read().await.clone();
        assert_eq!(node.mode, crate::model::mode::NodeMode::Quarantine);
        assert!(!node.relays_allowed());
        let alerts = state.alerts.query(None, None, 20).await;
        assert!(
            alerts
                .iter()
                .any(|a| a.summary.contains("карантин не удалось записать на диск")),
            "человек обязан узнать, что запрет не переживёт перезапуск"
        );
        assert!(
            stops(&state.sys).contains(&"systemctl stop smp-server.service".to_string()),
            "релеи всё равно останавливаются"
        );
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

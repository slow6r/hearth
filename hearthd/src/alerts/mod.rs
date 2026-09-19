//! Alert sink: journal first, notification channels second (ТЗ §7.3).
//!
//! * every alert is appended to `/var/lib/hearth/alerts.jsonl`;
//! * `sticky` alerts (all criticals, every egress finding) are additionally appended
//!   to `egress-incidents.jsonl` / kept in the permanent history — ТЗ §7.3 requires an
//!   egress incident to stay "в истории навсегда";
//! * the last N alerts are held in memory for `GET /alerts`.
//!
//! Emitting an alert never fails the caller: a watchdog that cannot write its journal
//! must still keep watching.

pub mod notify;

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

use crate::config::Config;
use crate::error::Result;
use crate::model::alert::{Alert, Severity};
use crate::net::EgressPolicy;
use crate::store;
use crate::sys::Sys;

use self::notify::Notifier;

/// How many alerts are kept in memory for the API.
const RECENT_CAPACITY: usize = 512;

/// The alert sink.
pub struct AlertSink {
    journal: PathBuf,
    incidents: PathBuf,
    recent: RwLock<VecDeque<Alert>>,
    next_id: AtomicU64,
    notifier: Notifier,
    /// Беды, найденные при открытии журнала. Демон обязан подняться и НАЗВАТЬ их, а
    /// не исчезнуть с узла; печатает и рассылает их `hearthd` сразу после старта.
    complaints: Vec<String>,
}

impl std::fmt::Debug for AlertSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlertSink")
            .field("journal", &self.journal)
            .field("incidents", &self.incidents)
            .finish_non_exhaustive()
    }
}

impl AlertSink {
    /// Open the sink, restoring the id sequence and recent history from disk.
    pub fn open(config: &Config, policy: EgressPolicy, sys: Sys) -> Result<Self> {
        let journal = config.paths.alerts_file();
        let incidents = config.paths.egress_incidents_file();
        store::ensure_dir(&config.paths.state_dir)?;

        // Нечитаемый журнал НЕ повод не подняться. Раньше здесь стоял оператор
        // вопроса, и узел, у которого alerts.jsonl достался root или потерял права,
        // не стартовал вовсе: дом оставался без надзора, целостности, бэкапа и admin
        // API из-за прав на один файл. Хуже того, причина не попадала никуда, кроме
        // строки в systemd. Теперь — старт, громкая жалоба и работа дальше; уже
        // записанное при этом не теряется, дозапись идёт в конец того же файла.
        let mut complaints = Vec::new();
        if let Some(complaint) = store::root_owned_dir_complaint(&config.paths.state_dir) {
            tracing::error!("{complaint}");
            complaints.push(complaint);
        }
        let (tail, complaint) = store::tail_lines_best_effort(&journal, RECENT_CAPACITY);
        if let Some(complaint) = complaint {
            tracing::error!("{complaint}");
            complaints.push(complaint);
        }
        let mut recent: VecDeque<Alert> = VecDeque::with_capacity(RECENT_CAPACITY);
        let mut max_id = 0;
        for line in tail {
            if let Ok(alert) = serde_json::from_str::<Alert>(&line) {
                max_id = max_id.max(alert.id);
                recent.push_back(alert);
            }
        }

        let notifier = Notifier::new(
            policy,
            sys,
            config.alerts.gotify.as_ref(),
            config.alerts.beeper.as_ref(),
        );

        Ok(Self {
            journal,
            incidents,
            recent: RwLock::new(recent),
            next_id: AtomicU64::new(max_id + 1),
            notifier,
            complaints,
        })
    }

    /// Беды, найденные при открытии журнала, — для того, кто умеет их показать.
    ///
    /// Отдельный метод, а не алерт прямо из [`AlertSink::open`]: сток в этот момент
    /// ещё не построен, а жалоба обязана уйти и в journal, и в сам журнал алертов,
    /// и в каналы доставки. Этим занимается `hearthd` сразу после старта.
    pub fn complaints(&self) -> &[String] {
        &self.complaints
    }

    /// Record and deliver an alert. Best effort by design.
    pub async fn emit(&self, mut alert: Alert) {
        alert.id = self.next_id.fetch_add(1, Ordering::SeqCst);
        alert.ts = Utc::now();

        match alert.severity {
            Severity::Critical => {
                tracing::error!(module = %alert.module, id = alert.id, "{}", alert.summary)
            }
            Severity::Warning => {
                tracing::warn!(module = %alert.module, id = alert.id, "{}", alert.summary)
            }
            Severity::Info => {
                tracing::info!(module = %alert.module, id = alert.id, "{}", alert.summary)
            }
        }

        match serde_json::to_string(&alert) {
            Ok(line) => {
                if let Err(e) = store::append_line(&self.journal, &line) {
                    tracing::error!(error = %e, "failed to append to the alert journal");
                }
                if alert.sticky {
                    if let Err(e) = store::append_line(&self.incidents, &line) {
                        tracing::error!(error = %e, "failed to append to the incident history");
                    }
                }
            }
            Err(e) => tracing::error!(error = %e, "failed to serialize an alert"),
        }

        {
            let mut recent = self.recent.write().await;
            if recent.len() == RECENT_CAPACITY {
                recent.pop_front();
            }
            recent.push_back(alert.clone());
        }

        self.notifier.deliver(&alert).await;
    }

    /// Alerts for `GET /alerts`, newest last.
    pub async fn query(
        &self,
        min_severity: Option<Severity>,
        since: Option<DateTime<Utc>>,
        limit: usize,
    ) -> Vec<Alert> {
        let recent = self.recent.read().await;
        let mut out: Vec<Alert> = recent
            .iter()
            .filter(|a| min_severity.is_none_or(|min| a.severity.at_least(min)))
            .filter(|a| since.is_none_or(|since| a.ts >= since))
            .cloned()
            .collect();
        if out.len() > limit {
            out.drain(..out.len() - limit);
        }
        out
    }

    /// Number of critical alerts in the retained window — surfaced in `/status`.
    pub async fn critical_count(&self) -> usize {
        self.recent
            .read()
            .await
            .iter()
            .filter(|a| a.severity == Severity::Critical)
            .count()
    }

    /// Permanent incident history (`egress-incidents.jsonl`), newest last.
    pub fn incident_history(&self, limit: usize) -> Result<Vec<Alert>> {
        Ok(store::tail_lines(&self.incidents, limit)?
            .into_iter()
            .filter_map(|line| serde_json::from_str(&line).ok())
            .collect())
    }
}

/// Что получилось у [`record_offline`].
///
/// Жалобы возвращаются, а не пишутся в лог: функцию вызывает `hearthctl`, у которого
/// нет ни tracing-подписчика, ни journald, — а человек, стоящий у узла в этот момент,
/// обязан увидеть беду на своём экране.
#[derive(Debug)]
pub struct OfflineRecord {
    /// Записанный алерт — уже с номером и временем.
    pub alert: Alert,
    /// Беды, которые не помешали записи, но помешают дальше.
    pub complaints: Vec<String>,
}

/// Записать алерт БЕЗ работающего демона.
///
/// Нужна ровно одному сценарию — локальным командам на узле, когда hearthd не
/// запущен (`hearthctl mode clear --local`). Событие «человек снял запрет руками»
/// обязано остаться в журнале узла: иначе в разборе через неделю карантин выглядит
/// как исчезнувший сам собой, а это единственное, чего от режима нельзя допустить.
///
/// Каналы доставки (Gotify, beeper) здесь намеренно не трогаются: их настройки лежат
/// в конфигурации, которая в этот момент может быть как раз сломана, а отправка по
/// сети с узла без демона — лишний способ не записать главное. Журнал первичен.
///
/// `state_dir` — тот же каталог, в котором лежит файл режима; путь до журнала
/// собирается из него так же, как это делает [`crate::config::Paths`].
pub fn record_offline(state_dir: &std::path::Path, mut alert: Alert) -> Result<OfflineRecord> {
    let journal = state_dir.join("alerts.jsonl");
    let incidents = state_dir.join("egress-incidents.jsonl");
    let mut complaints = Vec::new();
    if let Some(complaint) = store::root_owned_dir_complaint(state_dir) {
        complaints.push(complaint);
    }
    // ПОРЯДОК ЗДЕСЬ — И ЕСТЬ СМЫСЛ ФУНКЦИИ. Владелец журналов чинится ПЕРВЫМ делом,
    // до чтения. Раньше функция начиналась с чтения хвоста оператором вопроса, и на
    // журнале, доставшемся не тому владельцу (или просто побитом), выходила с ошибкой
    // ДО `append_line_keep_owner` — то есть починка, ради которой всё и написано, не
    // случалась никогда.
    store::adopt_dir_owner(&journal);
    store::adopt_dir_owner(&incidents);
    // Идентификатор продолжает нумерацию журнала: демон при следующем старте
    // восстанавливает next_id из него же (`AlertSink::open`), и дубликат номера
    // сделал бы историю нечитаемой. Но прочитать — это попытка, а не условие: алерт
    // «карантин снят руками» обязан лечь на диск и тогда, когда прежнее содержимое
    // прочитать не удалось. Иначе разбор через неделю увидит режим, исчезнувший сам.
    let (tail, complaint) = store::tail_lines_best_effort(&journal, RECENT_CAPACITY);
    if let Some(complaint) = complaint {
        complaints.push(complaint);
    }
    let max_id = tail
        .iter()
        .filter_map(|line| serde_json::from_str::<Alert>(line).ok())
        .map(|a| a.id)
        .max()
        .unwrap_or(0);
    alert.id = max_id + 1;
    alert.ts = Utc::now();

    let line = serde_json::to_string(&alert)?;
    // ТОЛЬКО с наследованием владельца. Эта функция работает из-под `sudo`, а обычная
    // `append_line` при создании нового файла ставит лишь права: на узле, где журналов
    // ещё нет, они появлялись как `root:root`, и демон под `hearth` терял запись в них
    // навсегда. Заметить это можно было только по отсутствию алертов — то есть никак.
    store::append_line_keep_owner(&journal, &line)?;
    if alert.sticky {
        store::append_line_keep_owner(&incidents, &line)?;
    }
    Ok(OfflineRecord { alert, complaints })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Исходник этого модуля — для теста о выборе функции записи.
    const THIS_FILE: &str = include_str!("mod.rs");

    #[test]
    fn the_offline_journal_is_written_with_the_owning_writer() {
        // Тот же дефект владельца, что и у файла режима, только в журналах алертов:
        // `record_offline` работает из-под `sudo`, и созданные ею root-овые
        // alerts.jsonl / egress-incidents.jsonl закрывают демону запись навсегда.
        // Проверяем ВЫБОР функции: поведенчески различить наследование владельца можно
        // только на unix и только под двумя пользователями.
        let body = THIS_FILE
            .split_once("pub fn record_offline(")
            .expect("record_offline на месте")
            .1;
        let body = body.split_once("\n}").expect("тело функции").0;
        assert!(
            body.matches("append_line_keep_owner(&").count() == 2,
            "оба журнала обязаны писаться с наследованием владельца: {body}"
        );
        assert!(
            !body.contains("store::append_line(") && !body.contains(" append_line(&"),
            "запись без наследования владельца оставит журнал root:root: {body}"
        );
    }

    #[test]
    fn an_offline_alert_creates_both_journals() {
        let dir = tempfile::tempdir().expect("tempdir");
        let alert = Alert::warning("mode", "режим снят локально").sticky(true);
        let written = record_offline(dir.path(), alert).expect("запись без демона");
        assert_eq!(written.alert.id, 1);
        assert_eq!(
            store::tail_lines(dir.path().join("alerts.jsonl"), 10)
                .expect("tail")
                .len(),
            1
        );
        assert_eq!(
            store::tail_lines(dir.path().join("egress-incidents.jsonl"), 10)
                .expect("tail")
                .len(),
            1,
            "sticky-алерт обязан попасть в постоянную историю"
        );
    }

    #[test]
    fn an_offline_record_survives_an_unreadable_journal() {
        // Дефект: функция начиналась с чтения журнала оператором вопроса и выходила с
        // ошибкой ДО `append_line_keep_owner` — то есть ровно та починка, ради которой
        // она написана, не случалась. Нечитаемый журнал воспроизводится переносимо:
        // каталог на месте файла даёт ту же ошибку чтения, что и чужой владелец.
        let dir = tempfile::tempdir().expect("tempdir");
        let journal = dir.path().join("alerts.jsonl");
        // Оборванная запись: байты в файле не складываются в UTF-8. Чтение отказывает
        // так же, как на чужом владельце, но дозапись возможна — и обязана случиться.
        std::fs::write(&journal, [0xff, 0xfe, 0x0a]).expect("оборванная запись");

        let written = record_offline(
            dir.path(),
            Alert::warning("mode", "режим снят локально").sticky(true),
        )
        .expect("нечитаемый журнал не должен мешать записи");
        assert_eq!(written.alert.id, 1, "нумерация начинается заново");
        // Уже записанное не потеряно: старые байты на месте, строка дописана в конец.
        let raw = std::fs::read(&journal).expect("read");
        assert!(
            raw.starts_with(&[0xff, 0xfe, 0x0a]),
            "прежний файл не тронут"
        );
        assert!(raw.len() > 3, "алерт обязан быть дописан");
        assert!(
            written
                .complaints
                .iter()
                .any(|c| c.contains("fix-permissions.sh")),
            "человек обязан узнать о беде и о выходе из неё: {:?}",
            written.complaints
        );
        // Постоянная история — ЗАПИСАНА, несмотря на нечитаемый alerts.jsonl.
        assert_eq!(
            store::tail_lines(dir.path().join("egress-incidents.jsonl"), 10)
                .expect("tail")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn an_unreadable_journal_does_not_keep_the_daemon_down() {
        // Дефект: AppState::new -> AlertSink::open -> tail_lines с оператором вопроса.
        // Узел, у которого alerts.jsonl стал root-овым, не стартовал ВООБЩЕ — дом
        // оставался без надзора, целостности, бэкапа и admin API из-за прав на один
        // файл. Демон обязан подняться, громко сказать и работать дальше.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = crate::state::tests::test_config(dir.path());
        config.paths.state_dir = dir.path().join("state");
        std::fs::create_dir_all(&config.paths.state_dir).expect("state_dir");
        std::fs::write(config.paths.alerts_file(), [0xff, 0xfe, 0x0a]).expect("оборванная запись");

        let sink = AlertSink::open(
            &config,
            EgressPolicy::new(vec!["10.66.0.0/16".parse().expect("cidr")]),
            Sys::new(true),
        )
        .expect("демон обязан подняться на нечитаемом журнале");
        assert!(
            sink.complaints()
                .iter()
                .any(|c| c.contains("fix-permissions.sh")),
            "беда обязана быть названа вместе с выходом: {:?}",
            sink.complaints()
        );
        // И сток остаётся рабочим: алерты идут в память, в каналы доставки и в тот же
        // файл — уже записанное при этом не теряется.
        sink.emit(Alert::critical("integrity", "hash mismatch"))
            .await;
        assert_eq!(sink.query(None, None, 10).await.len(), 1);
        let raw = std::fs::read(config.paths.alerts_file()).expect("read");
        assert!(
            raw.starts_with(&[0xff, 0xfe, 0x0a]),
            "прежний файл не тронут"
        );
        assert!(raw.len() > 3, "алерт обязан быть дописан");
    }

    fn sink(dir: &std::path::Path) -> AlertSink {
        AlertSink {
            journal: dir.join("alerts.jsonl"),
            incidents: dir.join("egress-incidents.jsonl"),
            recent: RwLock::new(VecDeque::new()),
            next_id: AtomicU64::new(1),
            notifier: Notifier::new(
                EgressPolicy::new(vec!["10.66.0.0/16".parse().expect("cidr")]),
                Sys::new(true),
                None,
                None,
            ),
            complaints: Vec::new(),
        }
    }

    #[tokio::test]
    async fn assigns_increasing_ids_and_journals() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sink = sink(dir.path());
        sink.emit(Alert::info("supervisor", "one")).await;
        sink.emit(Alert::warning("supervisor", "two")).await;

        let alerts = sink.query(None, None, 10).await;
        assert_eq!(alerts.len(), 2);
        assert!(alerts[1].id > alerts[0].id);

        let lines = store::tail_lines(dir.path().join("alerts.jsonl"), 10).expect("tail");
        assert_eq!(lines.len(), 2);
    }

    #[tokio::test]
    async fn criticals_land_in_the_permanent_history() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sink = sink(dir.path());
        sink.emit(Alert::info("egress", "routine")).await;
        sink.emit(Alert::critical("egress", "drop counter moved"))
            .await;

        let history = sink.incident_history(10).expect("history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].summary, "drop counter moved");
        assert_eq!(sink.critical_count().await, 1);
    }

    #[tokio::test]
    async fn filters_by_severity_and_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sink = sink(dir.path());
        for i in 0..5 {
            sink.emit(Alert::info("supervisor", format!("info {i}")))
                .await;
        }
        sink.emit(Alert::critical("integrity", "hash mismatch"))
            .await;

        let criticals = sink.query(Some(Severity::Critical), None, 10).await;
        assert_eq!(criticals.len(), 1);

        let last_two = sink.query(None, None, 2).await;
        assert_eq!(last_two.len(), 2);
        assert_eq!(last_two[1].summary, "hash mismatch");
    }

    #[tokio::test]
    async fn restores_the_id_sequence_after_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let sink = sink(dir.path());
            sink.emit(Alert::info("supervisor", "before restart")).await;
        }
        let tail = store::tail_lines(dir.path().join("alerts.jsonl"), 10).expect("tail");
        let last: Alert = serde_json::from_str(&tail[0]).expect("parse");
        assert_eq!(last.id, 1);
    }

    #[tokio::test]
    async fn an_offline_record_continues_the_journal() {
        // Локальные команды на узле (снятие режима без демона) обязаны оставлять след
        // в том же журнале и продолжать нумерацию: иначе история узла врёт про то,
        // как именно был снят карантин.
        let dir = tempfile::tempdir().expect("tempdir");
        let sink = sink(dir.path());
        sink.emit(Alert::critical("integrity", "hash mismatch"))
            .await;
        drop(sink);

        let written = record_offline(
            dir.path(),
            Alert::critical("mode", "режим снят локально").sticky(true),
        )
        .expect("запись без демона");
        assert_eq!(written.alert.id, 2, "нумерация продолжает журнал");

        let journal = store::tail_lines(dir.path().join("alerts.jsonl"), 10).expect("tail");
        assert_eq!(journal.len(), 2);
        let incidents =
            store::tail_lines(dir.path().join("egress-incidents.jsonl"), 10).expect("tail");
        assert_eq!(incidents.len(), 2, "sticky остаётся в постоянной истории");
    }
}

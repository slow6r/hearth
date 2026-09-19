//! Status snapshots served by the admin API (`/health`, `/egress`, `/status`).
//!
//! These are plain data. Producing them is the job of the supervisor, egress,
//! integrity and backup modules; the API only serializes what they published.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::model::manifest::IntegrityFinding;

/// Aggregate state of one component or of the whole node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthState {
    Ok,
    Degraded,
    Down,
}

impl HealthState {
    /// Worst of two states — how a node-level verdict is folded together.
    pub fn worst(self, other: HealthState) -> HealthState {
        self.max(other)
    }
}

impl Default for HealthState {
    /// Состояние, о котором ещё ничего не известно, — не `Ok`.
    ///
    /// Умолчание попадает в статус, прочитанный из файла, записанного старой версией
    /// демона. Подставить туда «всё хорошо» значило бы утверждать результат проверки,
    /// которой не было.
    fn default() -> Self {
        HealthState::Degraded
    }
}

/// One supervised service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceHealth {
    pub name: String,
    pub unit: String,
    /// systemd `ActiveState` (`active`, `failed`, ...). `unknown` when systemd is absent.
    pub active_state: String,
    /// systemd `SubState` (`running`, `dead`, ...).
    pub sub_state: String,
    pub listen: SocketAddr,
    /// TCP probe on the service port inside the home network.
    pub listening: bool,
    /// TCP probe on the loopback control port, when the service has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_ok: Option<bool>,
    pub restarts_in_window: u32,
    #[serde(default, with = "crate::model::rfc3339::option")]
    pub last_restart: Option<DateTime<Utc>>,
    pub state: HealthState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// `GET /health`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthSnapshot {
    pub node: String,
    pub address: String,
    #[serde(with = "crate::model::rfc3339")]
    pub checked: DateTime<Utc>,
    pub state: HealthState,
    /// Вердикт по резервной копии — то же число, что и в `/backup/status`.
    ///
    /// Он входит слагаемым в `state` (складывает надзор), но публикуется и отдельно:
    /// увидев `state` хуже, чем у любой из служб, внешний контроль обязан понимать,
    /// откуда это взялось, иначе единственный вывод — «мониторинг врёт».
    ///
    /// `#[serde(default)]` обязателен: снимок, записанный демоном прежней версии,
    /// обязан разбираться новым кодом. Умолчание `Degraded` читается как «не
    /// сообщено», а не как «проверено и хорошо».
    #[serde(default)]
    pub backup: HealthState,
    /// Вердикт по свежести манифеста обновлений — то же число, что в `/status`.
    ///
    /// Здесь он публикуется КАК ЕСТЬ (истёкший срок — `Down`), а в общий `state`
    /// входит слагаемым не выше `Degraded`: узел с просроченным манифестом продолжает
    /// носить сообщения семьи, и ставить его в отчёте на одну строку с «связи нет»
    /// значит приучить смотреть на красное как на фон. Внешнему контролю нужна
    /// правда, а не смягчение, поэтому отдельное поле говорит её без оговорок.
    ///
    /// `#[serde(default)]` обязателен: снимок, записанный демоном прежней версии,
    /// обязан разбираться новым кодом. Умолчание `Degraded` читается как «не
    /// сообщено», а не как «проверено и хорошо».
    #[serde(default)]
    pub updates: HealthState,
    pub services: Vec<ServiceHealth>,
    /// hearthd uptime.
    pub uptime_secs: u64,
    pub version: String,
    /// Коммит, из которого собран работающий демон (`crate::build_info`).
    ///
    /// Всё, что ниже, — ответ на вопрос «этот ли код сейчас работает». Без него узнать
    /// о бинарнике можно было либо имея доступ к файлу (у аудитора его нет), либо
    /// имея сертификат администратора — и получить в ответ `0.1.0`, одинаковое у всех
    /// сборок за всю историю ветки.
    ///
    /// `#[serde(default)]` обязателен: на узле и на рабочих станциях живёт hearthctl
    /// прежней версии, и он обязан разобрать ответ нового демона, а не упасть на
    /// неизвестном поле. Пустая строка при этом честно читается как «не сообщено».
    #[serde(default)]
    pub commit: String,
    /// Хеш дерева исходников этой сборки (`crate::build_info`).
    #[serde(default)]
    pub tree_sha256: String,
    /// sha256 файла, которым запущен процесс (`crate::self_sha256`).
    ///
    /// Именно это замыкает цепочку «работающий процесс → файл на диске»: снаружи её
    /// не построить, `/proc/<pid>/exe` посторонним пользователем не читается.
    #[serde(default)]
    pub self_sha256: String,
}

impl HealthSnapshot {
    /// Placeholder used before the first supervisor pass completes.
    pub fn pending(node: &str, address: &str) -> Self {
        let build = crate::build_info();
        Self {
            node: node.to_string(),
            address: address.to_string(),
            checked: Utc::now(),
            state: HealthState::Degraded,
            backup: HealthState::Degraded,
            updates: HealthState::Degraded,
            services: Vec::new(),
            uptime_secs: 0,
            version: build.version,
            commit: build.commit,
            tree_sha256: build.tree_sha256,
            self_sha256: crate::self_sha256().to_string(),
        }
    }
}

/// A TCP socket owned by a relay whose peer is outside the home networks.
/// Its existence is by itself a critical finding (ТЗ §7.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignSocket {
    pub process: String,
    pub local: String,
    pub peer: String,
    pub state: String,
}

/// One aggregated destination seen in the `hearth-egress-drop` journal entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DropDestination {
    /// `daddr:dport` (ТЗ §7.3: aggregation key).
    pub dst: String,
    pub proto: String,
    pub packets: u64,
}

/// A permanent record of an egress anomaly. Appended to `egress-incidents.jsonl`
/// and never rotated away.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressIncident {
    #[serde(with = "crate::model::rfc3339")]
    pub ts: DateTime<Utc>,
    /// `counter` (nft drop counter moved) or `socket` (established foreign socket).
    pub kind: String,
    #[serde(default)]
    pub packets: u64,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destinations: Vec<DropDestination>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sockets: Vec<ForeignSocket>,
    /// Удалось ли прочитать журнал ядра, где лежат адреса назначения.
    ///
    /// Пустой список адресатов при недоступном journalctl и пустой при доступном —
    /// разные вещи. В первом случае улик нет и восстановить их уже нельзя: журнал
    /// ротируется, а запрос делается один раз узким окном. Во втором улик не было.
    /// Единственное событие, ради которого существует сторож, не должно фиксироваться
    /// так, чтобы эти случаи было не различить.
    #[serde(default = "yes")]
    pub destinations_known: bool,
}

/// serde-умолчание для записей, сделанных до появления поля.
fn yes() -> bool {
    true
}

/// `GET /egress`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressSnapshot {
    #[serde(with = "crate::model::rfc3339")]
    pub checked: DateTime<Utc>,
    pub state: HealthState,
    /// Whether nft counters could be read at all. `false` means the watchdog is blind.
    pub counters_readable: bool,
    /// Absolute counter values as reported by nftables.
    pub egress_drop_packets: u64,
    pub egress_drop_bytes: u64,
    pub input_drop_packets: u64,
    pub input_drop_bytes: u64,
    /// Growth of `egress_drop` since hearthd started watching. Expected: 0 (ТЗ §5.4).
    pub egress_drop_delta: u64,
    /// Counters for egress that is permitted on purpose — call media, and any other
    /// service on a multi-purpose host. Reported so the operator can see that it is
    /// *these* growing and not `egress_drop`; never an incident.
    #[serde(default)]
    pub informational: std::collections::BTreeMap<String, u64>,
    /// Счётчики, перечисленные в конфигурации, которых в загруженном ruleset нет.
    ///
    /// Раньше такое имя просто исчезало из `informational`, а основной `egress_drop`
    /// подменялся нулём — то есть ровно тем значением, которое означает «всё чисто».
    /// Отсутствие показаний обязано отличаться от показаний, равных нулю.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_counters: Vec<String>,
    /// Whether `ss` could attribute sockets to processes. When false the socket scan
    /// proves nothing, and saying so beats reporting a clean result.
    #[serde(default)]
    pub scanner_ok: bool,
    /// Relay sockets *initiating* connections outside the home networks. Expected: empty.
    pub foreign_sockets: Vec<ForeignSocket>,
    /// Total incidents ever recorded on this node.
    pub incidents_total: u64,
    #[serde(default, with = "crate::model::rfc3339::option")]
    pub last_incident: Option<DateTime<Utc>>,
    /// Most recent incidents, newest last.
    #[serde(default)]
    pub recent_incidents: Vec<EgressIncident>,
}

/// `GET /status` integrity section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegritySnapshot {
    #[serde(with = "crate::model::rfc3339")]
    pub checked: DateTime<Utc>,
    pub state: HealthState,
    pub findings: Vec<IntegrityFinding>,
    /// Upstream tags this node is pinned to.
    pub simplexmq_tag: String,
    pub simplex_chat_tag: String,
}

impl IntegritySnapshot {
    /// Имена бинарей, которые ещё никто не запинил (нулевой плейсхолдер в манифесте).
    ///
    /// Не карантин, но и не «всё в порядке»: пока список не пуст, узел не может
    /// сказать, что именно у него работает, и надзор не поднимает релеи сам.
    pub fn unpinned(&self) -> Vec<&str> {
        self.findings
            .iter()
            .filter(|f| f.status == crate::model::manifest::IntegrityStatus::Unpinned)
            .map(|f| f.name.as_str())
            .collect()
    }
}

/// Persisted backup status (`/var/lib/hearth/backup-status.json`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupStatus {
    /// Пути, которые демон не смог прочитать и которые поэтому НЕ попали в архив.
    ///
    /// Раньше этот список выбрасывался: каждый ночной архив по построению неполон
    /// (ключ admin CA намеренно недоступен демону), а экран статуса показывал
    /// безоговорочный успех. Оператор узнавал о дыре при восстановлении.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreadable: Vec<String>,
    /// Что вошло в архив, именами внутри tar (`etc/opt/simplex`, ...).
    ///
    /// Статус отвечал на вопрос «бэкап сделан?» и не отвечал на вопрос «бэкап чего?».
    /// Узнать состав можно было только расшифровав архив age-ключом, то есть раз в
    /// квартал на учениях; между ними расхождение `backup.paths` с реальностью было
    /// ненаблюдаемо.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
    /// Сконфигурированные источники, которых на диске не оказалось.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<String>,
    /// Те из `missing`, что перечислены в `backup.required_paths`.
    ///
    /// Вычисляемое поле, а не второй источник правды: его заполняет
    /// [`apply_backup_verdict`] в тот же момент, когда считает вердикт. Нужно оно
    /// тому, у кого нет конфигурации узла, — `hearthctl` и внешнему контролю: без
    /// него по ответу API не отличить «нет каталога push-сервера, которого здесь и не
    /// должно быть» от «нет переписки».
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_required: Vec<String>,
    /// Вердикт по бэкапу: см. [`backup_verdict`].
    ///
    /// Раньше состояние бэкапа было набором полей, а не вердиктом: `GET /health`
    /// отвечал `ok` при живых юнитах и недельной давности архиве.
    #[serde(default)]
    pub state: HealthState,
    #[serde(default, with = "crate::model::rfc3339::option")]
    pub last_run: Option<DateTime<Utc>>,
    #[serde(default, with = "crate::model::rfc3339::option")]
    pub last_success: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_archive: Option<PathBuf>,
    #[serde(default)]
    pub last_size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Внешняя копия на hearth-backup подтверждена сверкой sha256 с принимающей
    /// стороной, а не кодом возврата rsync.
    ///
    /// Имя читается как «архив есть снаружи», и теперь оно это и означает: после
    /// копирования демон спрашивает у hearth-backup хеш файла и сравнивает с
    /// собственным. Код возврата rsync такого утверждения не обосновывал.
    #[serde(default)]
    pub remote_ok: bool,
    /// Чем подтверждена внешняя копия — или почему не подтверждена.
    ///
    /// `remote_ok = false` без причины — это отчёт, по которому ночью нечего делать:
    /// «не доехало», «доехало испорченным» и «доехало, но приёмнику нельзя задать
    /// вопрос» требуют разных действий, а выглядели одинаково. Здесь лежит текст,
    /// называющий действие, и он же уходит в алерт.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_note: Option<String>,
    /// Настроен ли вообще внешний приёмник (`[backup.remote]`).
    ///
    /// Без этого поля `remote_ok = false` у узла без hearth-backup выглядел как
    /// неудачная отправка, и вердикт держал бы вечный Degraded на совершенно
    /// исправном узле.
    #[serde(default)]
    pub remote_configured: bool,
    #[serde(default)]
    pub archives_kept: u32,
}

/// Через сколько часов без успешного запуска бэкап считается несостоявшимся.
///
/// Двойной запас к суточному циклу: одна пропущенная ночь бывает от перезагрузки в
/// окно запуска, две подряд — это уже отказ.
pub const BACKUP_STALE_AFTER_HOURS: i64 = 48;

/// Вердикт по состоянию бэкапа.
///
/// Чистая функция и отдельная величина именно потому, что публикация полей вердиктом
/// не является: никто не сравнивал `last_success` с текущим временем, и устаревший
/// бэкап был виден только тому, кто сам посмотрит на дату. Считается при каждом
/// чтении статуса, а не только при запуске задачи, — иначе между ночными прогонами
/// значение «зависало» бы на том, что было в 03:00.
///
/// `enabled` приходит из конфигурации, а не из статуса: выключенный бэкап — это
/// осознанное решение оператора, и держать из-за него вечный `Down` значило бы
/// приучить всех не смотреть на красное. Но и `Ok` он не даёт: узел без резервной
/// копии исправен только до первой потери диска.
///
/// `required` — тоже из конфигурации (`backup.required_paths`), и без него вердикт
/// приходилось бы выносить по одному лишь `status.missing`. Так и было: ЛЮБОЙ
/// отсутствующий источник давал `Down`. Поставляемый `backup.paths` намеренно шире
/// обязательного списка — каталоги push-сервера (ADR 0016) на узле без push законно
/// отсутствуют, — поэтому такой узел показывал бы красный бэкап каждую ночь при
/// полностью исправной копии. Это ровно то «красное, на которое приучаются не
/// смотреть», от чего предостерегает абзац выше: отсутствие НЕобязательного источника
/// видно в `status.missing`, но вердикта не меняет.
pub fn backup_verdict(
    now: DateTime<Utc>,
    status: &BackupStatus,
    enabled: bool,
    required: &[PathBuf],
) -> HealthState {
    if !enabled {
        return HealthState::Degraded;
    }
    if status.last_error.is_some() || !missing_required(status, required).is_empty() {
        return HealthState::Down;
    }
    let Some(last_success) = status.last_success else {
        return HealthState::Down;
    };
    if now - last_success > chrono::Duration::hours(BACKUP_STALE_AFTER_HOURS) {
        return HealthState::Down;
    }
    if status.remote_configured && !status.remote_ok {
        // Копия на самом узле лучше, чем ничего, но узел, который она должна пережить,
        // — это тот же узел.
        return HealthState::Degraded;
    }
    HealthState::Ok
}

/// Отсутствующие источники, без которых восстановление не является восстановлением.
///
/// Сравнение по нормализованным путям, а не по подстроке: в `missing` попадают ровно
/// элементы `backup.paths`, так что равенства достаточно.
///
/// Обязательный путь, которого нет в `backup.paths` вовсе, сюда не доходит и дойти не
/// может — но и не теряется: `Config::warnings` называет его при старте, а ночной
/// прогон проваливается на нём в `required_paths_report` («не вошло в архив»), откуда
/// `last_error` и `Down` в вердикте.
pub fn missing_required(status: &BackupStatus, required: &[PathBuf]) -> Vec<String> {
    status
        .missing
        .iter()
        .filter(|m| {
            required
                .iter()
                .any(|r| Path::new(m.as_str()) == r.as_path())
        })
        .cloned()
        .collect()
}

/// Пересчитать вердикт и состав отсутствующего обязательного разом.
///
/// Одна функция на все точки чтения статуса (ночной прогон, `/backup/status`,
/// `/status`, надзор) именно потому, что эти два поля обязаны быть согласованы: пустой
/// `missing_required` при `Down` из-за отсутствующего пути — это отчёт, по которому
/// ночью принимают неверное решение.
pub fn apply_backup_verdict(
    now: DateTime<Utc>,
    status: &mut BackupStatus,
    enabled: bool,
    required: &[PathBuf],
) {
    status.missing_required = missing_required(status, required);
    status.state = backup_verdict(now, status, enabled, required);
}

/// Persisted migration status (`/var/lib/hearth/migrate-status.json`, ТЗ §10.2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrateStatus {
    #[serde(default, with = "crate::model::rfc3339::option")]
    pub exported_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default)]
    pub size_bytes: u64,
    /// After an export the relays stay stopped: two nodes must never share one CA.
    #[serde(default)]
    pub relays_stopped: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copied_to: Option<String>,
    #[serde(default, with = "crate::model::rfc3339::option")]
    pub imported_at: Option<DateTime<Utc>>,
}

/// `GET /status` — everything at once, for `hearthctl status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeStatus {
    /// Режим узла: норма, карантин, обслуживание, перенос.
    pub mode: crate::model::mode::NodeState,
    pub health: HealthSnapshot,
    pub egress: EgressSnapshot,
    pub integrity: IntegritySnapshot,
    pub backup: BackupStatus,
    /// Свежесть манифеста обновлений: срок назначает оператор, узел его только видит.
    ///
    /// `#[serde(default)]` — ради hearthctl прежней версии и ответа прежнего демона:
    /// умолчание честно читается как «не сообщено».
    #[serde(default)]
    pub updates: crate::model::update::UpdatesStatus,
    pub migrate: MigrateStatus,
    pub devices_active: usize,
    pub devices_total: usize,
    pub alerts_critical_open: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worst_state_wins() {
        assert_eq!(
            HealthState::Ok.worst(HealthState::Degraded),
            HealthState::Degraded
        );
        assert_eq!(HealthState::Down.worst(HealthState::Ok), HealthState::Down);
        assert_eq!(HealthState::Ok.worst(HealthState::Ok), HealthState::Ok);
    }

    /// Обязательные источники поставляемой конфигурации, как в deploy/hearthd.toml.
    fn required() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/opt/simplex"),
            PathBuf::from("/var/opt/simplex"),
            PathBuf::from("/etc/hearth"),
            PathBuf::from("/var/lib/hearth"),
        ]
    }

    /// Таблица случаев вместо живого узла: вердикт — чистая функция.
    #[test]
    fn backup_verdict_covers_staleness() {
        let now = Utc::now();
        let required = required();
        let fresh = BackupStatus {
            last_success: Some(now - chrono::Duration::hours(3)),
            remote_configured: true,
            remote_ok: true,
            ..Default::default()
        };
        assert_eq!(
            backup_verdict(now, &fresh, true, &required),
            HealthState::Ok
        );
        assert_eq!(
            backup_verdict(now, &fresh, false, &required),
            HealthState::Degraded,
            "выключенный бэкап не бывает зелёным"
        );

        let no_remote = BackupStatus {
            remote_configured: false,
            remote_ok: false,
            ..fresh.clone()
        };
        assert_eq!(
            backup_verdict(now, &no_remote, true, &required),
            HealthState::Ok,
            "узел без hearth-backup исправен, а не деградировал"
        );

        let remote_failed = BackupStatus {
            remote_ok: false,
            ..fresh.clone()
        };
        assert_eq!(
            backup_verdict(now, &remote_failed, true, &required),
            HealthState::Degraded
        );

        let stale = BackupStatus {
            last_success: Some(now - chrono::Duration::days(3)),
            ..fresh.clone()
        };
        assert_eq!(
            backup_verdict(now, &stale, true, &required),
            HealthState::Down,
            "бэкап трёхдневной давности — это отсутствующий бэкап"
        );

        let never = BackupStatus::default();
        assert_eq!(
            backup_verdict(now, &never, true, &required),
            HealthState::Down
        );

        let failed = BackupStatus {
            last_error: Some("age recipients".into()),
            ..fresh.clone()
        };
        assert_eq!(
            backup_verdict(now, &failed, true, &required),
            HealthState::Down
        );

        let incomplete = BackupStatus {
            missing: vec!["/var/opt/simplex".into()],
            ..fresh.clone()
        };
        assert_eq!(
            backup_verdict(now, &incomplete, true, &required),
            HealthState::Down,
            "архив без переписки не является резервной копией"
        );
    }

    /// Узел без push-сервера: каталоги ADR 0016 перечислены в `backup.paths`, но в
    /// `required_paths` их нет намеренно. До разделения обязательного и
    /// необязательного такой узел показывал `Down` каждую ночь при исправном бэкапе.
    #[test]
    fn a_missing_optional_source_is_visible_but_not_a_failure() {
        let now = Utc::now();
        let status = BackupStatus {
            last_success: Some(now - chrono::Duration::hours(3)),
            remote_configured: false,
            missing: vec!["/etc/opt/simplex-ntf".into(), "/var/opt/simplex-ntf".into()],
            ..Default::default()
        };
        assert_eq!(
            backup_verdict(now, &status, true, &required()),
            HealthState::Ok,
            "отсутствие каталога push-сервера не делает копию непригодной"
        );
        assert!(
            !status.missing.is_empty(),
            "и при этом факт остаётся виден в статусе, а не заметается"
        );
    }

    /// Обратная половина того же разделения: обязательный источник пропал — провал.
    #[test]
    fn a_missing_required_source_is_still_down() {
        let now = Utc::now();
        let mut status = BackupStatus {
            last_success: Some(now - chrono::Duration::hours(3)),
            missing: vec!["/etc/opt/simplex-ntf".into(), "/var/opt/simplex".into()],
            ..Default::default()
        };
        apply_backup_verdict(now, &mut status, true, &required());
        assert_eq!(status.state, HealthState::Down);
        assert_eq!(
            status.missing_required,
            vec!["/var/opt/simplex".to_string()],
            "отчёт обязан называть ровно тот путь, из-за которого горит красное"
        );
    }

    /// На узле уже лежит backup-status.json, записанный старой версией: он обязан
    /// читаться без миграции, и «неизвестно» не должно превратиться в «ok».
    #[test]
    fn an_old_backup_status_file_still_parses() {
        let raw = r#"{
            "unreadable": ["/etc/hearth/pki/ca.key"],
            "last_run": "2026-09-18T03:00:00Z",
            "last_success": "2026-09-18T03:00:00Z",
            "last_size_bytes": 123,
            "remote_ok": false,
            "archives_kept": 14
        }"#;
        let status: BackupStatus = serde_json::from_str(raw).expect("parse");
        assert!(status.members.is_empty());
        assert!(status.missing.is_empty());
        assert!(!status.remote_configured);
        assert_eq!(status.state, HealthState::Degraded);
    }

    /// То же для снимка egress: поля `missing_counters` в старом состоянии нет.
    #[test]
    fn an_old_egress_snapshot_still_parses() {
        let raw = r#"{
            "checked": "2026-09-18T03:00:00Z",
            "state": "ok",
            "counters_readable": true,
            "egress_drop_packets": 0,
            "egress_drop_bytes": 0,
            "input_drop_packets": 41,
            "input_drop_bytes": 2460,
            "egress_drop_delta": 0,
            "foreign_sockets": [],
            "incidents_total": 0
        }"#;
        let snap: EgressSnapshot = serde_json::from_str(raw).expect("parse");
        assert!(snap.missing_counters.is_empty());
    }

    /// hearthctl прежней версии писал `/health` без полей паспорта, и его ответ
    /// обязан разбираться новым кодом: иначе обновление узла ломает связь с уже
    /// разложенными по рабочим станциям клиентами.
    #[test]
    fn an_old_health_snapshot_without_the_passport_still_parses() {
        let raw = r#"{
            "node": "hearth-node",
            "address": "relay.example.org",
            "checked": "2026-09-18T03:00:00Z",
            "state": "ok",
            "services": [],
            "uptime_secs": 41,
            "version": "0.1.0"
        }"#;
        let snap: HealthSnapshot = serde_json::from_str(raw).expect("parse");
        assert!(snap.commit.is_empty(), "«не сообщено» — это пустая строка");
        assert!(snap.tree_sha256.is_empty());
        assert!(snap.self_sha256.is_empty());
    }

    /// Снимок обязан нести паспорт сборки: ради этого он и заведён.
    #[test]
    fn a_fresh_snapshot_carries_the_build_passport() {
        let snap = HealthSnapshot::pending("hearth-node", "relay.example.org");
        let build = crate::build_info();
        assert_eq!(snap.commit, build.commit);
        assert_eq!(snap.tree_sha256, build.tree_sha256);
        assert_eq!(
            snap.self_sha256.len(),
            64,
            "sha256 собственного файла: {}",
            snap.self_sha256
        );
    }

    #[test]
    fn snapshots_round_trip() {
        let snap = HealthSnapshot::pending("hearth-node", "10.66.10.10");
        let json = serde_json::to_string(&snap).expect("json");
        let back: HealthSnapshot = serde_json::from_str(&json).expect("parse");
        assert_eq!(snap.node, back.node);
        assert_eq!(back.state, HealthState::Degraded);
    }
}

//! Shared daemon state.
//!
//! Every background module owns one snapshot slot and publishes into it; the admin API
//! only ever reads. That keeps the API handlers free of side effects and means a slow
//! `nft` call can never stall an HTTP request.

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::RwLock;

use crate::alerts::AlertSink;
use crate::config::Config;
use crate::error::Result;
use crate::model::device::DeviceRegistry;
use crate::model::health::{
    BackupStatus, EgressSnapshot, HealthSnapshot, HealthState, IntegritySnapshot, MigrateStatus,
    NodeStatus,
};
use crate::net::EgressPolicy;
use crate::store;
use crate::sys::Sys;

/// Everything the daemon and the API share.
#[derive(Debug)]
pub struct AppState {
    pub config: Arc<Config>,
    pub sys: Sys,
    pub policy: EgressPolicy,
    pub alerts: Arc<AlertSink>,
    pub devices: RwLock<DeviceRegistry>,
    pub invites: RwLock<crate::model::invite::InviteRegistry>,
    /// Аудиторские токены. Отдельный реестр, а не поле у устройства: см.
    /// `crate::model::audit_token`. Берётся ПОСЛЕ `devices` и никогда вместе с
    /// `invites` — порядок захвата в device API от этого не меняется.
    pub audit_tokens: RwLock<crate::model::audit_token::AuditTokenRegistry>,
    /// Неудачные попытки предъявить код доступа, по адресам. Не `RwLock`: внутри
    /// обычный `Mutex`, и держать его дольше одной вставки в таблицу негде.
    pub claim_throttle: crate::deviceapi::throttle::ClaimThrottle,
    /// Режим узла — единственное место, где решается, можно ли держать релеи.
    /// Переживает перезапуск: запрет, живущий в памяти процесса, не запрет.
    pub mode: RwLock<crate::model::mode::NodeState>,
    pub health: RwLock<HealthSnapshot>,
    pub egress: RwLock<EgressSnapshot>,
    pub integrity: RwLock<IntegritySnapshot>,
    pub backup: RwLock<BackupStatus>,
    pub migrate: RwLock<MigrateStatus>,
    started: Instant,
}

impl AppState {
    /// Build the state, loading whatever persisted between restarts.
    pub fn new(config: Config, sys: Sys) -> Result<Arc<Self>> {
        let policy = config.egress_policy();
        store::ensure_dir(&config.paths.state_dir)?;

        let alerts = Arc::new(AlertSink::open(&config, policy.clone(), sys.clone())?);
        let devices = DeviceRegistry::load(config.paths.devices_file())?;
        let invites = crate::model::invite::InviteRegistry::load(config.paths.invites_file())?;
        let audit_tokens =
            crate::model::audit_token::AuditTokenRegistry::load(config.paths.audit_tokens_file())?;
        let backup: BackupStatus =
            store::read_json(config.paths.backup_status_file())?.unwrap_or_default();
        let migrate: MigrateStatus =
            store::read_json(config.paths.migrate_status_file())?.unwrap_or_default();
        // Режим читается до запуска надзора: иначе после перезагрузки supervisor
        // успеет поднять то, что было запрещено.
        //
        // Ошибка чтения НЕ роняет демон. Раньше здесь стоял `?`, и повреждённый (или
        // доставшийся root) node-mode.json означал «hearthd не стартует вовсе»: узел
        // одновременно без релеев и без управляющего контура, то есть без единственного
        // пути всё починить — admin API. Теперь демон поднимается в самом ограничивающем
        // режиме и говорит об этом словами; файл на диске не трогается, чтобы не стереть
        // ни улику, ни настоящую причину запрета.
        let mode = load_mode_or_restrict(&config.paths.node_mode_file());

        let node = config.node.name.clone();
        let address = config.node.host.clone();

        Ok(Arc::new(Self {
            config: Arc::new(config),
            sys,
            policy,
            alerts,
            devices: RwLock::new(devices),
            invites: RwLock::new(invites),
            audit_tokens: RwLock::new(audit_tokens),
            claim_throttle: Default::default(),
            mode: RwLock::new(mode),
            health: RwLock::new(HealthSnapshot::pending(&node, &address)),
            egress: RwLock::new(pending_egress()),
            integrity: RwLock::new(pending_integrity()),
            backup: RwLock::new(backup),
            migrate: RwLock::new(migrate),
            started: Instant::now(),
        }))
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    /// Перечитать файл режима с диска и, если он изменился, применить.
    ///
    /// # Зачем
    ///
    /// Файл режима читался ровно один раз — при старте. Аварийное снятие
    /// (`sudo hearthctl mode clear --local`) писало на диск `normal`, гейт после этого
    /// пропускал релей, а надзор через 15 секунд гасил его снова: в памяти демона
    /// по-прежнему стоял карантин. Человек видел релеи, которые «поднимаются и
    /// умирают», и снять это можно было только перезапуском демона — о чём нигде не
    /// было сказано. Теперь диск — источник истины, и надзор сверяется с ним на каждом
    /// тике.
    ///
    /// Замок берётся ПЕРВЫМ и держится на время чтения: иначе одновременный
    /// [`Self::set_mode`] успел бы записать более новый режим, а этот метод вернул бы
    /// память к прочитанному до него.
    ///
    /// Повреждённый или нечитаемый файл НЕ меняет память: снимать запрет по файлу,
    /// который не разобран, нельзя, а ужесточать по нему — значит дать любому сбою
    /// диска гасить релеи. Вызывающий получает `Err` и говорит об этом человеку.
    pub async fn reload_mode_from_disk(&self) -> Result<Option<crate::model::mode::NodeState>> {
        let path = self.config.paths.node_mode_file();
        let mut slot = self.mode.write().await;
        let raw = match tokio::fs::read_to_string(&path).await {
            Ok(raw) => Some(raw),
            // Файла нет — узел обычный. Запрет обязан быть записан ЯВНО: то же
            // правило, что и у гейта (`model::mode::gate_verdict`).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(crate::error::Error::io(&path, e)),
        };
        let next = match raw {
            None => crate::model::mode::NodeState::normal(),
            Some(raw) => serde_json::from_str::<crate::model::mode::NodeState>(&raw)
                .map_err(|e| crate::error::Error::Parse(format!("{}: {e}", path.display())))?,
        };
        // Сравниваем по смыслу, а не по структуре: `since` у только что созданной
        // «нормы» каждый раз новое, и равенство целиком давало бы изменение на каждом
        // тике.
        let same = next.mode == slot.mode && next.reason == slot.reason;
        if same {
            return Ok(None);
        }
        *slot = next.clone();
        Ok(Some(next))
    }

    /// Aggregate everything for `GET /status`.
    pub async fn status(&self) -> NodeStatus {
        let devices = self.devices.read().await;
        NodeStatus {
            mode: self.mode.read().await.clone(),
            health: self.health.read().await.clone(),
            egress: self.egress.read().await.clone(),
            integrity: self.integrity.read().await.clone(),
            backup: {
                // Та же причина, что и в обработчике `/backup/status`: давность
                // успеха — величина, которая меняется сама по себе, без событий.
                let mut backup = self.backup.read().await.clone();
                crate::model::health::apply_backup_verdict(
                    chrono::Utc::now(),
                    &mut backup,
                    self.config.backup.enabled,
                    &self.config.backup.required_paths,
                );
                backup
            },
            // Та же причина: срок годности манифеста кончается сам по себе, без
            // события, которое кто-нибудь записал бы в статус.
            updates: self.updates_status(chrono::Utc::now()).await,
            migrate: self.migrate.read().await.clone(),
            devices_active: devices.active().count(),
            devices_total: devices.devices.len(),
            alerts_critical_open: self.alerts.critical_count().await,
        }
    }

    /// Файл манифеста обновлений, который узел раздаёт устройствам.
    pub fn update_manifest_path(&self) -> std::path::PathBuf {
        self.config.device_api.updates_dir.join("manifest.json")
    }

    /// Свежесть манифеста обновлений: читается с диска в момент вопроса.
    ///
    /// Не кэшируется в `AppState` намеренно. Срок годности истекает от хода времени, а
    /// не от события: значение, посчитанное один раз при старте, «зависло» бы на том,
    /// что было в момент запуска демона, и оператор узнал бы об истечении от семьи.
    ///
    /// Ошибка чтения — не паника и не `Err`: вердикт обязан получиться при любом
    /// состоянии диска, иначе `/status` перестанет отвечать целиком из-за одного
    /// файла. Нечитаемый файл считается отсутствующим (`published = false`), а
    /// неразобранный — отказом; и то и другое видно в статусе.
    pub async fn updates_status(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::model::update::UpdatesStatus {
        let path = self.update_manifest_path();
        // Размер проверяется до чтения: файл в updates_dir кладёт человек, и опечатка
        // в имени могла положить туда APK.
        let too_big = match tokio::fs::metadata(&path).await {
            Ok(meta) => meta.len() > crate::model::update::MANIFEST_SIZE_LIMIT,
            Err(_) => false,
        };
        if too_big {
            tracing::error!(path = %path.display(), "манифест обновлений неправдоподобно велик");
            return crate::model::update::UpdatesStatus::unreadable(
                "манифест обновлений неправдоподобно велик и не читается; положите в \
                 updates_dir подписанный manifest.json",
            );
        }
        let raw = tokio::fs::read(&path).await.ok();
        crate::model::update::updates_status(now, raw.as_deref())
    }

    /// Текущий режим узла.
    pub async fn node_mode(&self) -> crate::model::mode::NodeMode {
        self.mode.read().await.mode
    }

    /// Перевести узел в режим и зафиксировать это на диске.
    ///
    /// Порядок памяти и диска здесь и в [`Self::clear_mode`] намеренно РАЗНЫЙ, и это
    /// асимметрия по смыслу, а не недосмотр. Замок при этом берётся ПЕРВЫМ в обеих
    /// операциях и держится до конца записи: асимметрия допустима только в том, что
    /// происходит под замком, иначе две одновременные команды разложатся в порядок, при
    /// котором на диске карантин, а в памяти норма (см. [`Self::clear_mode`]).
    ///
    /// Ужесточение применяется сразу в памяти, и только потом пишется на диск. Раньше
    /// было наоборот — из посылки «запрет, не переживший перезапуск, хуже запрета, не
    /// действующего сейчас». Посылка неверна: при неудачной записи (кончилось место
    /// на /var, снесён state_dir) прежний порядок не давал НИ ТОГО, НИ ДРУГОГО —
    /// память оставалась `normal`, а релеи вызывающий останавливал всё равно, и
    /// надзор поднимал их обратно через один тик. Теперь при отказе диска запрет по
    /// крайней мере действует в этом процессе, а ошибка уходит вызывающему, чтобы он
    /// мог сказать о ней человеку и повторить запись.
    ///
    /// Ослабление (`clear_mode`) остаётся «сначала диск»: снять запрет, который
    /// вернётся после перезагрузки, — это обмануть человека, решившего, что он его снял.
    pub async fn set_mode(
        &self,
        mode: crate::model::mode::NodeMode,
        reason: impl Into<String>,
        findings: Vec<String>,
    ) -> Result<()> {
        let next = crate::model::mode::NodeState::enter(mode, reason, findings);
        // Замок держится на всё время записи: иначе два одновременных перехода
        // оставили бы на диске не тот режим, что в памяти.
        let mut slot = self.mode.write().await;
        *slot = next.clone();
        store::write_json_atomic(self.config.paths.node_mode_file(), &next, store::MODE_STATE)
    }

    /// Повторить запись текущего режима на диск.
    ///
    /// Нужна тем, кто уже получил ошибку от [`Self::set_mode`]: режим в памяти
    /// действует, но перезагрузку не переживёт, и попытку надо повторять, пока диск
    /// не починят.
    pub async fn persist_mode(&self) -> Result<()> {
        // Замок держится на время записи: иначе одновременный `set_mode` успел бы
        // записать более новый режим, а эта запись затёрла бы его старым.
        let current = self.mode.read().await;
        store::write_json_atomic(
            self.config.paths.node_mode_file(),
            &*current,
            store::MODE_STATE,
        )
    }

    /// Снять режим. Только по явной команде человека: причина, по которой службы
    /// остановлены, не исчезает оттого, что проверка снова прошла.
    ///
    /// Замок берётся ДО записи — так же, как в [`Self::set_mode`], и это не
    /// формальность. Раньше запись на диск шла до захвата, и одновременные «карантин»
    /// и «снятие» могли разложиться так: снятие пишет `normal` на диск → карантин
    /// ставит память и диск в `quarantine` → снятие забирает замок и ставит память в
    /// `normal`. На диске карантин, в памяти норма, релеи разрешены до перезагрузки —
    /// тот же дефект, что и до появления режима, только через другую дверь.
    ///
    /// Внутри замка порядок обратный к `set_mode`: сначала подтверждённая запись,
    /// потом память. Снятие, которое вернётся после перезагрузки, — обман человека,
    /// решившего, что он его снял.
    pub async fn clear_mode(&self) -> Result<crate::model::mode::NodeState> {
        let mut slot = self.mode.write().await;
        let next = crate::model::mode::write_normal(&self.config.paths.node_mode_file())?;
        *slot = next.clone();
        Ok(next)
    }

    /// Persist the backup status slot.
    pub async fn save_backup_status(&self) -> Result<()> {
        let status = self.backup.read().await.clone();
        store::write_json_atomic(
            self.config.paths.backup_status_file(),
            &status,
            store::MODE_STATE,
        )
    }

    /// Persist the migration status slot.
    pub async fn save_migrate_status(&self) -> Result<()> {
        let status = self.migrate.read().await.clone();
        store::write_json_atomic(
            self.config.paths.migrate_status_file(),
            &status,
            store::MODE_STATE,
        )
    }
}

/// Прочитать режим при старте, а при любой неудаче — запретить работу релеев.
///
/// Самый ограничивающий режим здесь — карантин: он запрещает релеи (как и любой
/// не-`normal`) и прямо называет причину, по которой запрещает. Файл на диске не
/// переписывается: гейт увидит тот же повреждённый файл и тоже запретит старт, а
/// `hearthctl mode clear --local` чинит оба разом.
fn load_mode_or_restrict(path: &std::path::Path) -> crate::model::mode::NodeState {
    match store::read_json::<crate::model::mode::NodeState>(path) {
        Ok(Some(state)) => state,
        // Файла нет — обычный узел: запрет должен быть записан явно.
        Ok(None) => crate::model::mode::NodeState::normal(),
        Err(e) => {
            let reason = format!(
                "файл режима {} не прочитан ({e}); до починки узел считается \
                 запрещённым к обслуживанию. Снять: sudo hearthctl mode clear --local \
                 (docs/runbook-node-mode.md)",
                path.display()
            );
            tracing::error!(path = %path.display(), error = %e, "{reason}");
            crate::model::mode::NodeState::enter(
                crate::model::mode::NodeMode::Quarantine,
                reason,
                vec![path.display().to_string()],
            )
        }
    }
}

fn pending_egress() -> EgressSnapshot {
    EgressSnapshot {
        checked: chrono::Utc::now(),
        state: HealthState::Degraded,
        counters_readable: false,
        egress_drop_packets: 0,
        egress_drop_bytes: 0,
        input_drop_packets: 0,
        input_drop_bytes: 0,
        egress_drop_delta: 0,
        informational: Default::default(),
        missing_counters: Vec::new(),
        scanner_ok: false,
        foreign_sockets: Vec::new(),
        incidents_total: 0,
        last_incident: None,
        recent_incidents: Vec::new(),
    }
}

fn pending_integrity() -> IntegritySnapshot {
    IntegritySnapshot {
        checked: chrono::Utc::now(),
        state: HealthState::Degraded,
        findings: Vec::new(),
        simplexmq_tag: "unknown".into(),
        simplex_chat_tag: "unknown".into(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::path::Path;

    pub(crate) fn test_config(dir: &Path) -> Config {
        let raw = include_str!("../deploy/hearthd.toml");
        let mut config: Config = toml::from_str(raw).expect("reference config");
        config.paths.state_dir = dir.join("state");
        config.paths.hearth_etc = dir.join("etc-hearth");
        config.paths.secrets_dir = dir.join("etc-hearth/secrets");
        config.paths.manifest = dir.join("manifest.toml");
        config.backup.spool_dir = dir.join("spool");
        config.backup.remote = None;
        config.alerts.gotify = None;
        config.alerts.beeper = None;
        config.api.pki_dir = dir.join("etc-hearth/pki");
        config
    }

    #[tokio::test]
    async fn builds_and_aggregates_status() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = AppState::new(test_config(dir.path()), Sys::new(true)).expect("state");
        let status = state.status().await;
        assert_eq!(status.devices_total, 0);
        assert_eq!(status.health.state, HealthState::Degraded);
        assert!(!status.egress.counters_readable);
    }

    #[tokio::test]
    async fn a_quarantine_survives_a_restart() {
        // Запрет, живущий в памяти процесса, запретом не является: после
        // перезагрузки узла supervisor поднимал бы остановленные релеи.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = AppState::new(test_config(dir.path()), Sys::new(true)).expect("state");
        state
            .set_mode(
                crate::model::mode::NodeMode::Quarantine,
                "хеш smp-server не совпал",
                vec!["smp-server".into()],
            )
            .await
            .expect("set mode");
        drop(state);

        let state = AppState::new(test_config(dir.path()), Sys::new(true)).expect("restart");
        let node = state.mode.read().await.clone();
        assert_eq!(node.mode, crate::model::mode::NodeMode::Quarantine);
        assert!(!node.relays_allowed());
        assert_eq!(node.reason, "хеш smp-server не совпал");
        assert_eq!(node.findings, vec!["smp-server".to_string()]);
    }

    #[tokio::test]
    async fn a_corrupt_mode_file_does_not_stop_the_daemon() {
        // Дефект: `AppState::new` возвращала Err на нечитаемом node-mode.json, и
        // hearthd не стартовал вовсе. Итог — одновременно нет релеев (гейт на том же
        // файле отвечает запретом) и нет управляющего контура, то есть нет и пути
        // всё починить. Теперь демон поднимается в самом ограничивающем режиме.
        let dir = tempfile::tempdir().expect("tempdir");
        let config = test_config(dir.path());
        std::fs::create_dir_all(&config.paths.state_dir).expect("state_dir");
        std::fs::write(config.paths.node_mode_file(), "{это не json".as_bytes())
            .expect("битый файл");

        let state = AppState::new(config, Sys::new(true)).expect("демон обязан стартовать");
        let node = state.mode.read().await.clone();
        assert!(
            !node.relays_allowed(),
            "повреждённый файл не разрешает релеи"
        );
        assert!(node.reason.contains("не прочитан"), "{}", node.reason);
        // Причина обязана называть выход: её печатает `hearthctl status`.
        assert!(
            node.reason.contains("mode clear --local"),
            "{}",
            node.reason
        );
        // Файл на диске не тронут: улика и настоящая причина запрета не стираются.
        let raw = std::fs::read(state.config.paths.node_mode_file()).expect("файл на месте");
        assert_eq!(raw, "{это не json".as_bytes());
    }

    #[tokio::test]
    async fn a_local_clear_reaches_the_live_daemon() {
        // Дефект 18: файл режима читался ровно один раз, при старте. Оператор делал
        // `hearthctl mode clear --local`, гейт пропускал релей — и через 15 секунд
        // надзор гасил его снова, потому что в памяти демона всё ещё стоял карантин.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = AppState::new(test_config(dir.path()), Sys::new(true)).expect("state");
        state
            .set_mode(
                crate::model::mode::NodeMode::Quarantine,
                "хеш smp-server не совпал",
                vec!["smp-server".into()],
            )
            .await
            .expect("set mode");
        assert!(!state.node_mode().await.relays_allowed());

        // Ничего не перечитывалось — изменений нет.
        assert_eq!(
            state.reload_mode_from_disk().await.expect("перечитывание"),
            None
        );

        // Снятие «снаружи», ровно как это делает hearthctl на узле.
        crate::model::mode::write_normal(&state.config.paths.node_mode_file())
            .expect("локальное снятие");
        let changed = state
            .reload_mode_from_disk()
            .await
            .expect("перечитывание")
            .expect("изменение обязано быть замечено");
        assert!(changed.relays_allowed());
        assert!(
            state.node_mode().await.relays_allowed(),
            "память демона обязана принять снятие с диска"
        );
    }

    #[tokio::test]
    async fn a_broken_mode_file_does_not_lift_a_ban_at_runtime() {
        // Обратная сторона перечитывания: нечитаемый файл НЕ снимает запрет и НЕ
        // ужесточает его. Иначе любой сбой диска гасил бы релеи, а усечённая запись
        // снимала бы карантин.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = AppState::new(test_config(dir.path()), Sys::new(true)).expect("state");
        state
            .set_mode(crate::model::mode::NodeMode::Quarantine, "инцидент", vec![])
            .await
            .expect("set mode");
        std::fs::write(state.config.paths.node_mode_file(), "{обрыв".as_bytes())
            .expect("битый файл");

        assert!(state.reload_mode_from_disk().await.is_err());
        assert!(
            !state.node_mode().await.relays_allowed(),
            "запрет из памяти обязан устоять"
        );
    }

    #[tokio::test]
    async fn a_removed_mode_file_lifts_the_ban_at_runtime() {
        // Снять запрет можно и удалением файла — это тот же «нет файла, значит узел
        // обычный», что у гейта. Правило обязано быть одно на оба места.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = AppState::new(test_config(dir.path()), Sys::new(true)).expect("state");
        state
            .set_mode(crate::model::mode::NodeMode::Migration, "перенос", vec![])
            .await
            .expect("set mode");
        std::fs::remove_file(state.config.paths.node_mode_file()).expect("удаление");

        let changed = state
            .reload_mode_from_disk()
            .await
            .expect("перечитывание")
            .expect("изменение");
        assert!(changed.relays_allowed());
    }

    #[tokio::test]
    async fn a_fresh_node_starts_in_normal_mode() {
        // Отсутствие файла — это обычная работа, а не «неизвестно, поэтому запретим»:
        // иначе первый же запуск встал бы колом.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = AppState::new(test_config(dir.path()), Sys::new(true)).expect("state");
        assert!(state.node_mode().await.relays_allowed());
    }

    /// Сделать запись файла режима заведомо невозможной, не трогая права.
    ///
    /// Каталог на месте файла — переносимый способ: `rename` не заменит каталог ни на
    /// unix, ни на Windows, где идут эти тесты.
    fn break_the_mode_file(config: &Config) {
        let path = config.paths.node_mode_file();
        let _ = std::fs::remove_file(&path);
        std::fs::create_dir_all(&path).expect("каталог на месте файла режима");
    }

    #[tokio::test]
    async fn a_failed_mode_write_still_bans_the_relays() {
        // Отказ диска не должен давать худшее из двух: раньше при неудачной записи
        // память оставалась `normal`, а релеи вызывающий останавливал всё равно —
        // и надзор поднимал их обратно через один тик.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = AppState::new(test_config(dir.path()), Sys::new(true)).expect("state");
        break_the_mode_file(&state.config);

        let err = state
            .set_mode(
                crate::model::mode::NodeMode::Quarantine,
                "хеш smp-server не совпал",
                vec!["smp-server".into()],
            )
            .await
            .expect_err("запись обязана провалиться");
        assert!(!err.to_string().is_empty());
        assert!(
            !state.node_mode().await.relays_allowed(),
            "запрет обязан действовать в этом процессе даже без диска"
        );
    }

    #[tokio::test]
    async fn clearing_the_mode_needs_a_successful_write() {
        // Асимметрия: ужесточение применяется и без диска, ослабление — нет. Иначе
        // человек решит, что снял карантин, а после перезагрузки узел снова замолчит.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = AppState::new(test_config(dir.path()), Sys::new(true)).expect("state");
        state
            .set_mode(crate::model::mode::NodeMode::Quarantine, "инцидент", vec![])
            .await
            .expect("set");
        break_the_mode_file(&state.config);

        state
            .clear_mode()
            .await
            .expect_err("снятие без записи на диск недопустимо");
        assert!(!state.node_mode().await.relays_allowed());
    }

    #[tokio::test]
    async fn a_mode_can_be_persisted_again_after_the_disk_recovers() {
        // Повторная запись — единственный способ довести запрет до диска, если первая
        // попытка пришлась на заполненный /var.
        let dir = tempfile::tempdir().expect("tempdir");
        let config = test_config(dir.path());
        let state = AppState::new(config.clone(), Sys::new(true)).expect("state");
        break_the_mode_file(&state.config);
        state
            .set_mode(crate::model::mode::NodeMode::Quarantine, "инцидент", vec![])
            .await
            .expect_err("диск сломан");

        std::fs::remove_dir(state.config.paths.node_mode_file()).expect("починили диск");
        state.persist_mode().await.expect("повторная запись");
        drop(state);

        let state = AppState::new(config, Sys::new(true)).expect("restart");
        assert_eq!(
            state.node_mode().await,
            crate::model::mode::NodeMode::Quarantine
        );
    }

    #[tokio::test]
    async fn clearing_the_mode_is_persistent_too() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = AppState::new(test_config(dir.path()), Sys::new(true)).expect("state");
        state
            .set_mode(crate::model::mode::NodeMode::Migration, "перенос", vec![])
            .await
            .expect("set");
        state.clear_mode().await.expect("clear");
        drop(state);

        let state = AppState::new(test_config(dir.path()), Sys::new(true)).expect("restart");
        assert!(state.node_mode().await.relays_allowed());
    }

    #[tokio::test]
    async fn clearing_the_mode_never_touches_the_disk_before_it_owns_the_lock() {
        // Гонка от асимметрии замков. Раньше `clear_mode` писала `normal` на диск ДО
        // захвата замка, и одновременный карантин мог вклиниться между записью и
        // присвоением памяти: на диске карантин, в памяти норма, релеи разрешены до
        // перезагрузки.
        //
        // Проверяем наблюдаемое следствие правила «сначала замок, потом диск»: пока
        // замком владеет кто-то другой, файл режима не меняется.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = AppState::new(test_config(dir.path()), Sys::new(true)).expect("state");
        state
            .set_mode(crate::model::mode::NodeMode::Quarantine, "инцидент", vec![])
            .await
            .expect("set");

        let held = state.mode.read().await;
        let clearing = tokio::spawn({
            let state = state.clone();
            async move { state.clear_mode().await }
        });
        // Даём снятию все шансы выполниться: прежний порядок записал бы диск здесь же.
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        let on_disk: crate::model::mode::NodeState =
            store::read_json(state.config.paths.node_mode_file())
                .expect("чтение файла режима")
                .expect("файл режима существует");
        assert_eq!(
            on_disk.mode,
            crate::model::mode::NodeMode::Quarantine,
            "снятие записало диск в обход замка"
        );

        drop(held);
        clearing.await.expect("join").expect("clear");
        assert!(state.node_mode().await.relays_allowed());
        let on_disk: crate::model::mode::NodeState =
            store::read_json(state.config.paths.node_mode_file())
                .expect("чтение файла режима")
                .expect("файл режима существует");
        assert!(on_disk.relays_allowed(), "диск и память обязаны сойтись");
    }

    #[tokio::test]
    async fn persists_backup_status_across_restarts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = test_config(dir.path());
        {
            let state = AppState::new(config.clone(), Sys::new(true)).expect("state");
            state.backup.write().await.remote_ok = true;
            state.save_backup_status().await.expect("save");
        }
        let state = AppState::new(config, Sys::new(true)).expect("state");
        assert!(state.backup.read().await.remote_ok);
    }
}

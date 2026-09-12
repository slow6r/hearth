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
        let backup: BackupStatus =
            store::read_json(config.paths.backup_status_file())?.unwrap_or_default();
        let migrate: MigrateStatus =
            store::read_json(config.paths.migrate_status_file())?.unwrap_or_default();
        // Режим читается до запуска надзора: иначе после перезагрузки supervisor
        // успеет поднять то, что было запрещено.
        let mode: crate::model::mode::NodeState =
            store::read_json(config.paths.node_mode_file())?.unwrap_or_default();

        let node = config.node.name.clone();
        let address = config.node.host.clone();

        Ok(Arc::new(Self {
            config: Arc::new(config),
            sys,
            policy,
            alerts,
            devices: RwLock::new(devices),
            invites: RwLock::new(invites),
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

    /// Aggregate everything for `GET /status`.
    pub async fn status(&self) -> NodeStatus {
        let devices = self.devices.read().await;
        NodeStatus {
            mode: self.mode.read().await.clone(),
            health: self.health.read().await.clone(),
            egress: self.egress.read().await.clone(),
            integrity: self.integrity.read().await.clone(),
            backup: self.backup.read().await.clone(),
            migrate: self.migrate.read().await.clone(),
            devices_active: devices.active().count(),
            devices_total: devices.devices.len(),
            alerts_critical_open: self.alerts.critical_count().await,
        }
    }

    /// Текущий режим узла.
    pub async fn node_mode(&self) -> crate::model::mode::NodeMode {
        self.mode.read().await.mode
    }

    /// Перевести узел в режим и зафиксировать это на диске.
    ///
    /// Пишем файл ДО обновления памяти: если запись не удалась, узел не имеет права
    /// считать запрет установленным — иначе он исчезнет при следующем перезапуске, и
    /// ровно в тот момент, когда был нужен.
    pub async fn set_mode(
        &self,
        mode: crate::model::mode::NodeMode,
        reason: impl Into<String>,
        findings: Vec<String>,
    ) -> Result<()> {
        let next = crate::model::mode::NodeState::enter(mode, reason, findings);
        store::write_json_atomic(self.config.paths.node_mode_file(), &next, store::MODE_STATE)?;
        *self.mode.write().await = next;
        Ok(())
    }

    /// Снять режим. Только по явной команде человека: причина, по которой службы
    /// остановлены, не исчезает оттого, что проверка снова прошла.
    pub async fn clear_mode(&self) -> Result<crate::model::mode::NodeState> {
        let next = crate::model::mode::NodeState::normal();
        store::write_json_atomic(self.config.paths.node_mode_file(), &next, store::MODE_STATE)?;
        *self.mode.write().await = next.clone();
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
    async fn a_fresh_node_starts_in_normal_mode() {
        // Отсутствие файла — это обычная работа, а не «неизвестно, поэтому запретим»:
        // иначе первый же запуск встал бы колом.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = AppState::new(test_config(dir.path()), Sys::new(true)).expect("state");
        assert!(state.node_mode().await.relays_allowed());
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

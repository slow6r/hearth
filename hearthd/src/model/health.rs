//! Status snapshots served by the admin API (`/health`, `/egress`, `/status`).
//!
//! These are plain data. Producing them is the job of the supervisor, egress,
//! integrity and backup modules; the API only serializes what they published.

use std::net::SocketAddr;
use std::path::PathBuf;

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
    pub services: Vec<ServiceHealth>,
    /// hearthd uptime.
    pub uptime_secs: u64,
    pub version: String,
}

impl HealthSnapshot {
    /// Placeholder used before the first supervisor pass completes.
    pub fn pending(node: &str, address: &str) -> Self {
        Self {
            node: node.to_string(),
            address: address.to_string(),
            checked: Utc::now(),
            state: HealthState::Degraded,
            services: Vec::new(),
            uptime_secs: 0,
            version: crate::VERSION.to_string(),
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

/// Persisted backup status (`/var/lib/hearth/backup-status.json`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupStatus {
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
    /// Whether the last rsync to hearth-backup succeeded.
    #[serde(default)]
    pub remote_ok: bool,
    #[serde(default)]
    pub archives_kept: u32,
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
    pub health: HealthSnapshot,
    pub egress: EgressSnapshot,
    pub integrity: IntegritySnapshot,
    pub backup: BackupStatus,
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

    #[test]
    fn snapshots_round_trip() {
        let snap = HealthSnapshot::pending("hearth-node", "10.66.10.10");
        let json = serde_json::to_string(&snap).expect("json");
        let back: HealthSnapshot = serde_json::from_str(&json).expect("parse");
        assert_eq!(snap.node, back.node);
        assert_eq!(back.state, HealthState::Degraded);
    }
}

//! `hearthd` configuration (`/etc/hearth/hearthd.toml`).
//!
//! The file is the single source of truth for the node. Every struct uses
//! `deny_unknown_fields`: a typo in a security-relevant key must fail the daemon at
//! start-up, not silently fall back to a default.
//!
//! [`Config::validate`] encodes the invariants of ТЗ §4–§7 that can be checked
//! statically: no wildcard binds (A1), admin subnet inside the WG subnet, control
//! ports on loopback only, backup/alert targets inside the home networks.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::net::{is_wildcard, EgressPolicy};

/// Root configuration document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub node: Node,
    pub api: Api,
    pub paths: Paths,
    pub smp: Relay,
    pub xftp: Relay,
    pub turn: Turn,
    #[serde(default)]
    pub supervisor: Supervisor,
    #[serde(default)]
    pub egress: Egress,
    #[serde(default)]
    pub integrity: Integrity,
    pub backup: Backup,
    #[serde(default)]
    pub alerts: Alerts,
    #[serde(default)]
    pub devices: Devices,
}

/// Node identity and the networks it is allowed to exist in.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    /// Human name for logs and alerts, e.g. `hearth-node`.
    pub name: String,
    /// The address the relays bind to. Constant across hardware changes (ТЗ §2.5).
    pub address: IpAddr,
    /// Home + WireGuard networks. Everything outside is denied (ТЗ §5.1).
    pub home_networks: Vec<IpNet>,
    /// Subnet allowed to reach the admin API and ssh (ТЗ §5.3).
    pub admin_networks: Vec<IpNet>,
}

/// Admin API listener (mTLS, ТЗ §7.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Api {
    pub listen: SocketAddr,
    /// Directory with `ca.pem`, `ca.key`, `server.pem`, `server.key`, `admins.json`.
    pub pki_dir: PathBuf,
    /// When non-empty, only these client-certificate SHA-256 fingerprints may connect,
    /// on top of the mTLS chain check. Empty means "any non-revoked cert in admins.json".
    #[serde(default)]
    pub allowed_admin_fingerprints: Vec<String>,
    #[serde(default = "d_api_body_limit")]
    pub max_body_bytes: usize,
}

/// The three directories that hold all node state (ТЗ §10.1) plus runtime state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Paths {
    /// `/etc/opt/simplex` — relay CA, keys, ini files. Migrates with the node.
    pub simplex_etc: PathBuf,
    /// `/var/opt/simplex` — store log, xftp files. Migrates with the node.
    pub simplex_var: PathBuf,
    /// `/etc/hearth` — hearthd config, secrets, PKI, device registry. Migrates with the node.
    pub hearth_etc: PathBuf,
    /// `/var/lib/hearth` — alerts journal, egress incident history, statuses.
    pub state_dir: PathBuf,
    /// `/etc/hearth/secrets`.
    pub secrets_dir: PathBuf,
    /// Pinned upstream binaries + hashes (ТЗ §6.1).
    pub manifest: PathBuf,
}

impl Paths {
    /// Device registry. Lives in `/etc/hearth` so it survives the ПК → mini-PC move.
    pub fn devices_file(&self) -> PathBuf {
        self.hearth_etc.join("devices.json")
    }
    /// Append-only alert journal.
    pub fn alerts_file(&self) -> PathBuf {
        self.state_dir.join("alerts.jsonl")
    }
    /// Egress incidents. Kept forever (ТЗ §7.3, egress-watchdog).
    pub fn egress_incidents_file(&self) -> PathBuf {
        self.state_dir.join("egress-incidents.jsonl")
    }
    /// Last observed nft counter values, so a restart does not re-report old drops.
    pub fn egress_state_file(&self) -> PathBuf {
        self.state_dir.join("egress-counters.json")
    }
    pub fn backup_status_file(&self) -> PathBuf {
        self.state_dir.join("backup-status.json")
    }
    pub fn migrate_status_file(&self) -> PathBuf {
        self.state_dir.join("migrate-status.json")
    }
    /// Issued admin client certificates (fingerprint allowlist for the API).
    pub fn admins_file(&self) -> PathBuf {
        self.hearth_etc.join("pki").join("admins.json")
    }
}

/// A stock upstream relay supervised by hearthd. hearthd never touches its data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relay {
    #[serde(default = "d_true")]
    pub enabled: bool,
    /// systemd unit name, e.g. `smp-server.service`.
    pub unit: String,
    /// URI scheme used in client addresses: `smp` or `xftp`.
    pub scheme: String,
    /// Public listener inside the home network, e.g. `10.66.10.10:5223`.
    pub listen: SocketAddr,
    /// Control port, loopback only (ТЗ §6.2).
    #[serde(default)]
    pub control: Option<SocketAddr>,
    /// Upstream ini file (owned by the relay; hearthd only reads it).
    pub config_file: PathBuf,
    /// File written by `smp-server init` holding the CA fingerprint.
    pub fingerprint_file: PathBuf,
    /// File holding the queue/upload creation password (ТЗ §6.2, §6.3).
    pub password_file: PathBuf,
    /// Process name as reported by `ss -tnp`, for the socket scanner.
    pub process: String,
}

/// coturn (ТЗ §6.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Turn {
    #[serde(default = "d_true")]
    pub enabled: bool,
    pub unit: String,
    /// STUN/TURN listener, e.g. `10.66.10.10:3478`.
    pub listen: SocketAddr,
    pub realm: String,
    /// Static part of the REST username: `<expiry-ts>:<username>`.
    #[serde(default = "d_turn_user")]
    pub username: String,
    pub secret_file: PathBuf,
    /// Template rendered by hearthd on secret rotation.
    pub config_template: PathBuf,
    pub config_file: PathBuf,
    /// Lifetime of a generated TURN credential.
    #[serde(default = "d_turn_cred_ttl")]
    pub credential_ttl_secs: u64,
    /// Static secret rotation period (ТЗ §6.4: once a month).
    #[serde(default = "d_turn_rotate_days")]
    pub rotate_days: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Supervisor {
    #[serde(default = "d_sup_interval")]
    pub check_interval_secs: u64,
    #[serde(default = "d_sup_timeout")]
    pub probe_timeout_secs: u64,
    /// Restart backoff ladder in seconds.
    #[serde(default = "d_sup_backoff")]
    pub restart_backoff_secs: Vec<u64>,
    /// Alert when this many restarts happen inside `restart_window_secs` (ТЗ §7.3).
    #[serde(default = "d_sup_threshold")]
    pub restart_alert_threshold: u32,
    #[serde(default = "d_sup_window")]
    pub restart_window_secs: u64,
    /// Set to false on a workstation where systemd is not available.
    #[serde(default = "d_true")]
    pub restart_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Egress {
    #[serde(default = "d_egress_poll")]
    pub poll_interval_secs: u64,
    #[serde(default = "d_egress_scan")]
    pub socket_scan_interval_secs: u64,
    #[serde(default = "d_nft_table")]
    pub nft_table: String,
    #[serde(default = "d_nft_family")]
    pub nft_family: String,
    #[serde(default = "d_ctr_egress")]
    pub egress_counter: String,
    #[serde(default = "d_ctr_input")]
    pub input_counter: String,
    #[serde(default = "d_journal_prefix")]
    pub journal_prefix: String,
    /// Process names whose sockets must never leave the home networks.
    #[serde(default = "d_watch_processes")]
    pub watch_processes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Integrity {
    #[serde(default = "d_integrity_interval")]
    pub interval_secs: u64,
    /// Stop the relays when a binary hash does not match the manifest (ТЗ §7.3, A12).
    #[serde(default = "d_true")]
    pub stop_relays_on_mismatch: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backup {
    #[serde(default = "d_true")]
    pub enabled: bool,
    /// UTC hour of the daily run.
    #[serde(default = "d_backup_hour")]
    pub hour_utc: u32,
    /// Directories included in the archive: the three ТЗ §10.1 dirs plus the
    /// hearthd state dir (alert + egress history must survive a rebuild).
    pub paths: Vec<PathBuf>,
    pub spool_dir: PathBuf,
    /// age recipients (public keys, `age1...`). The private key lives OFF the node.
    pub recipients: Vec<String>,
    #[serde(default = "d_retention")]
    pub retention_days: u64,
    #[serde(default)]
    pub remote: Option<BackupRemote>,
}

/// `hearth-backup` target (ТЗ §4: 10.66.10.20). Must be inside the home networks.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRemote {
    pub host: IpAddr,
    #[serde(default = "d_ssh_port")]
    pub port: u16,
    pub user: String,
    pub path: String,
    pub ssh_key: PathBuf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alerts {
    #[serde(default)]
    pub gotify: Option<Gotify>,
    #[serde(default)]
    pub beeper: Option<Beeper>,
}

/// Gotify on the UDM Pro. WG-only; external channels are forbidden (ТЗ §7.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gotify {
    pub addr: SocketAddr,
    pub token_file: PathBuf,
    #[serde(default = "d_gotify_priority")]
    pub priority: u8,
    /// Minimum severity that is pushed: `info` | `warning` | `critical`.
    #[serde(default = "d_gotify_min")]
    pub min_severity: String,
}

/// GPIO beeper / any local command. Runs on the node itself, no network involved.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Beeper {
    pub command: Vec<String>,
    #[serde(default = "d_beeper_min")]
    pub min_severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Devices {
    /// ТЗ §1.1: a closed circle of at most 20 devices.
    #[serde(default = "d_max_devices")]
    pub max_devices: usize,
}

impl Default for Devices {
    fn default() -> Self {
        Self {
            max_devices: d_max_devices(),
        }
    }
}

impl Default for Supervisor {
    fn default() -> Self {
        Self {
            check_interval_secs: d_sup_interval(),
            probe_timeout_secs: d_sup_timeout(),
            restart_backoff_secs: d_sup_backoff(),
            restart_alert_threshold: d_sup_threshold(),
            restart_window_secs: d_sup_window(),
            restart_enabled: true,
        }
    }
}

impl Default for Egress {
    fn default() -> Self {
        Self {
            poll_interval_secs: d_egress_poll(),
            socket_scan_interval_secs: d_egress_scan(),
            nft_table: d_nft_table(),
            nft_family: d_nft_family(),
            egress_counter: d_ctr_egress(),
            input_counter: d_ctr_input(),
            journal_prefix: d_journal_prefix(),
            watch_processes: d_watch_processes(),
        }
    }
}

impl Default for Integrity {
    fn default() -> Self {
        Self {
            interval_secs: d_integrity_interval(),
            stop_relays_on_mismatch: true,
        }
    }
}

impl Config {
    /// Read and validate the configuration file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
        let cfg: Config = toml::from_str(&raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Egress policy derived from `node.home_networks`.
    pub fn egress_policy(&self) -> EgressPolicy {
        EgressPolicy::new(self.node.home_networks.clone())
    }

    /// Relays in a stable order, for iteration.
    pub fn relays(&self) -> Vec<&Relay> {
        vec![&self.smp, &self.xftp]
    }

    /// Enforce the structural invariants of ТЗ §4–§7.
    pub fn validate(&self) -> Result<()> {
        if self.node.home_networks.is_empty() {
            return Err(Error::config("node.home_networks must not be empty"));
        }
        let policy = self.egress_policy();

        if !policy.permits_ip(self.node.address) {
            return Err(Error::config(format!(
                "node.address {} is outside node.home_networks",
                self.node.address
            )));
        }

        for net in &self.node.admin_networks {
            let inside =
                self.node.home_networks.iter().any(|home| {
                    home.contains(&net.network()) && home.prefix_len() <= net.prefix_len()
                });
            if !inside {
                return Err(Error::config(format!(
                    "node.admin_networks entry {net} is not contained in node.home_networks"
                )));
            }
        }

        // A1: nothing may listen on a wildcard address.
        check_listener("api.listen", self.api.listen, self.node.address)?;
        for relay in self.relays() {
            if !relay.enabled {
                continue;
            }
            check_listener(
                &format!("{}.listen", relay.scheme),
                relay.listen,
                self.node.address,
            )?;
            if let Some(control) = relay.control {
                if !control.ip().is_loopback() {
                    return Err(Error::config(format!(
                        "{}.control must be on loopback, got {control}",
                        relay.scheme
                    )));
                }
            }
            if relay.scheme != "smp" && relay.scheme != "xftp" {
                return Err(Error::config(format!(
                    "unsupported relay scheme `{}` (expected smp or xftp)",
                    relay.scheme
                )));
            }
        }
        if self.turn.enabled {
            check_listener("turn.listen", self.turn.listen, self.node.address)?;
        }

        if let Some(remote) = &self.backup.remote {
            if !policy.permits_ip(remote.host) {
                return Err(Error::config(format!(
                    "backup.remote.host {} is outside the home networks",
                    remote.host
                )));
            }
        }
        if self.backup.enabled {
            if self.backup.recipients.is_empty() {
                return Err(Error::config(
                    "backup.recipients must list at least one age public key",
                ));
            }
            if self.backup.paths.is_empty() {
                return Err(Error::config("backup.paths must not be empty"));
            }
            if self.backup.hour_utc > 23 {
                return Err(Error::config("backup.hour_utc must be 0..=23"));
            }
        }

        if let Some(gotify) = &self.alerts.gotify {
            if !policy.permits_ip(gotify.addr.ip()) {
                return Err(Error::config(format!(
                    "alerts.gotify.addr {} is outside the home networks \
                     (external alerting is forbidden by ТЗ §7.3)",
                    gotify.addr
                )));
            }
        }

        if self.devices.max_devices == 0 {
            return Err(Error::config("devices.max_devices must be >= 1"));
        }
        if self.supervisor.restart_backoff_secs.is_empty() {
            return Err(Error::config(
                "supervisor.restart_backoff_secs must not be empty",
            ));
        }
        Ok(())
    }
}

fn check_listener(what: &str, addr: SocketAddr, node: IpAddr) -> Result<()> {
    if is_wildcard(&addr) {
        return Err(Error::config(format!(
            "{what} binds the wildcard address {addr}; ТЗ §5.1 requires an explicit bind to {node}"
        )));
    }
    if addr.ip() != node && !addr.ip().is_loopback() {
        return Err(Error::config(format!(
            "{what} binds {addr}, expected node.address {node} or loopback"
        )));
    }
    Ok(())
}

fn d_true() -> bool {
    true
}
fn d_api_body_limit() -> usize {
    64 * 1024
}
fn d_turn_user() -> String {
    "hearth".into()
}
fn d_turn_cred_ttl() -> u64 {
    24 * 3600
}
fn d_turn_rotate_days() -> u64 {
    30
}
fn d_sup_interval() -> u64 {
    15
}
fn d_sup_timeout() -> u64 {
    3
}
fn d_sup_backoff() -> Vec<u64> {
    vec![5, 15, 60, 300]
}
fn d_sup_threshold() -> u32 {
    3
}
fn d_sup_window() -> u64 {
    600
}
fn d_egress_poll() -> u64 {
    30
}
fn d_egress_scan() -> u64 {
    300
}
fn d_nft_table() -> String {
    "hearth".into()
}
fn d_nft_family() -> String {
    "inet".into()
}
fn d_ctr_egress() -> String {
    "egress_drop".into()
}
fn d_ctr_input() -> String {
    "input_drop".into()
}
fn d_journal_prefix() -> String {
    "hearth-egress-drop".into()
}
fn d_watch_processes() -> Vec<String> {
    vec![
        "smp-server".into(),
        "xftp-server".into(),
        "turnserver".into(),
    ]
}
fn d_integrity_interval() -> u64 {
    3600
}
fn d_backup_hour() -> u32 {
    3
}
fn d_retention() -> u64 {
    14
}
fn d_ssh_port() -> u16 {
    22
}
fn d_gotify_priority() -> u8 {
    8
}
fn d_gotify_min() -> String {
    "warning".into()
}
fn d_beeper_min() -> String {
    "critical".into()
}
fn d_max_devices() -> usize {
    20
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped reference configuration must always parse and validate.
    fn reference() -> Config {
        let raw = include_str!("../deploy/hearthd.toml");
        toml::from_str(raw).expect("reference config parses")
    }

    #[test]
    fn reference_config_is_valid() {
        reference().validate().expect("reference config is valid");
    }

    #[test]
    fn rejects_wildcard_bind() {
        let mut cfg = reference();
        cfg.smp.listen = "0.0.0.0:5223".parse().expect("addr");
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("wildcard"), "got {err}");
    }

    #[test]
    fn rejects_non_loopback_control_port() {
        let mut cfg = reference();
        cfg.smp.control = Some("10.66.10.10:5224".parse().expect("addr"));
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_backup_target_outside_home() {
        let mut cfg = reference();
        if let Some(remote) = cfg.backup.remote.as_mut() {
            remote.host = "203.0.113.7".parse().expect("ip");
        }
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("outside the home networks"),
            "got {err}"
        );
    }

    #[test]
    fn rejects_external_alert_target() {
        let mut cfg = reference();
        cfg.alerts.gotify = Some(Gotify {
            addr: "198.51.100.10:80".parse().expect("addr"),
            token_file: PathBuf::from("/etc/hearth/secrets/gotify-token"),
            priority: 8,
            min_severity: "warning".into(),
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_admin_network_outside_home() {
        let mut cfg = reference();
        cfg.node.admin_networks = vec!["192.168.1.0/24".parse().expect("cidr")];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_unknown_keys() {
        let err = toml::from_str::<Config>("[node]\nname='x'\nbogus=1\n").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("bogus") || msg.contains("unknown"),
            "got {msg}"
        );
    }
}

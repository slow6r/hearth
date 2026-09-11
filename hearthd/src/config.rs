//! `hearthd` configuration (`/etc/hearth/hearthd.toml`).
//!
//! The file is the single source of truth for the node. Every struct uses
//! `deny_unknown_fields`: a typo in a security-relevant key must fail the daemon at
//! start-up, not silently fall back to a default.
//!
//! [`Config::validate`] encodes the invariants of ТЗ §4–§7 that can be checked
//! statically: the admin API is never exposed, the admin subnet is inside the LAN,
//! control ports are on loopback, and backup/alert targets stay on the LAN.

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
    /// API для самих устройств семьи: обновления и свежие TURN-креды.
    #[serde(default)]
    pub device_api: DeviceApi,
}

/// Device API — единственный сервис узла, доступный ТЕЛЕФОНАМ, а не только LAN.
///
/// # Чем он отличается от admin API и почему это отдельная сущность
///
/// Admin API (`[api]`) — mTLS, только из `admin_networks`, права администратора.
/// Этот — токен на устройство, из интернета, и умеет ровно две вещи: отдать
/// обновление и выписать свежие TURN-креды. Смешивать их в одном слушателе нельзя:
/// у них разные модели доверия, и ошибка в маршрутизации стоила бы прав админа.
///
/// # Чего он стоит
///
/// [ADR 0007](../../docs/adr/0007-public-relay-no-vpn.md) сводил публичную поверхность
/// узла к релеям и TURN — то есть к стоковому коду upstream. Этот сервис добавляет к
/// ней НАШ код. Взамен снимаются две вещи: обновление за ≤ 7 дней (ТЗ §1.4) для того,
/// кто в отъезде, и поломка звонков у всех при каждой ротации TURN-секрета.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceApi {
    /// Выключен по умолчанию: включение расширяет публичную поверхность узла, и это
    /// должно быть осознанным действием, а не следствием обновления конфига.
    #[serde(default)]
    pub enabled: bool,
    /// Где слушать. В отличие от admin API здесь wildcard допустим и нормален:
    /// подключаются телефоны из интернета.
    #[serde(default = "DeviceApi::default_listen")]
    pub listen: std::net::SocketAddr,
    /// Порт, который попадает в bundle. Отличается от `listen`, когда роутер
    /// пробрасывает снаружи другой порт.
    #[serde(default = "DeviceApi::default_public_port")]
    pub public_port: u16,
    /// Каталог с APK и manifest.json.
    #[serde(default = "DeviceApi::default_updates_dir")]
    pub updates_dir: PathBuf,
}

impl Default for DeviceApi {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: Self::default_listen(),
            public_port: Self::default_public_port(),
            updates_dir: Self::default_updates_dir(),
        }
    }
}

impl DeviceApi {
    fn default_listen() -> std::net::SocketAddr {
        // Собираем из частей, а не парсим строку: у парсинга есть ветка ошибки,
        // которой здесь взяться неоткуда, и clippy справедливо не любит expect().
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 7444)
    }
    fn default_public_port() -> u16 {
        7444
    }
    fn default_updates_dir() -> PathBuf {
        PathBuf::from("/srv/hearth/updates")
    }
}

/// Node identity: how clients reach it, and which networks hearthd itself may talk to.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    /// Human name for logs and alerts, e.g. `hearth-node`.
    pub name: String,
    /// Public hostname or IP that appears in every client address — the constant that
    /// outlives the hardware (ТЗ §2.5). Clients reach the relays here over the internet.
    pub host: String,
    /// Networks **hearthd itself** is allowed to connect to: the LAN holding the backup
    /// target and the alert channel. The relays serve the internet; the control plane
    /// still never leaves home (ТЗ §7.4).
    pub lan_networks: Vec<IpNet>,
    /// Networks allowed to reach the admin API and ssh. A subset of `lan_networks`:
    /// the relays are public, administration is not.
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
    /// Device registry.
    ///
    /// In `state_dir`, not `/etc/hearth`. The daemon writes this file, and every write
    /// here is atomic (temp file + rename), which needs write permission on the
    /// *directory* — not just on the file. Keeping it in `/etc/hearth` therefore meant
    /// giving the `hearth` user write access to the directory that also holds
    /// `hearthd.toml` and `manifest.toml`: a compromised daemon could then repoint
    /// `backup.recipients` at someone else's age key, or rewrite the very manifest its
    /// own integrity check reads.
    ///
    /// The migration property is unaffected: `state_dir` is one of `backup.paths`
    /// ([ADR 0006](../../docs/adr/0006-state-dir-in-backup.md)), and `migrate::export`
    /// archives exactly those, so the registry still travels with the node.
    pub fn devices_file(&self) -> PathBuf {
        self.state_dir.join("devices.json")
    }
    /// Приглашения: одноразовые токены, которыми новое устройство заводит себя само.
    /// Рядом с devices.json и по тем же причинам — это состояние, а не конфигурация.
    pub fn invites_file(&self) -> PathBuf {
        self.state_dir.join("invites.json")
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
///
/// Note on binding: upstream's `[TRANSPORT] host` is documented as "only used to print
/// server address on start" — the server listens on every interface. So hearthd tracks
/// *ports*, probes them on loopback, and leaves address filtering to nftables.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relay {
    #[serde(default = "d_true")]
    pub enabled: bool,
    /// systemd unit name, e.g. `smp-server.service`.
    pub unit: String,
    /// URI scheme used in client addresses: `smp` or `xftp`.
    pub scheme: String,
    /// Port advertised in client addresses, e.g. 5223.
    pub port: u16,
    /// Additional ports the relay also listens on. Upstream defaults to `5223,443`;
    /// 443 is what gets through restrictive networks (hotel wifi, mobile operators).
    #[serde(default)]
    pub extra_ports: Vec<u16>,
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
///
/// Unlike the relays, TURN must be publicly reachable for a reason that is not about
/// convenience: when both callers are behind NAT — two phones on mobile networks, which
/// is the normal case — a relay is the only way the media path exists at all.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Turn {
    #[serde(default = "d_true")]
    pub enabled: bool,
    pub unit: String,
    /// Plain STUN/TURN port (UDP and TCP), conventionally 3478.
    pub port: u16,
    /// TLS port for `turns:`, conventionally 5349 or 443. Without TLS, calls fail on
    /// networks that permit only 443/tcp.
    ///
    /// Setting this alone is not enough: coturn will not open a TLS listener without a
    /// certificate, so `tls_cert`/`tls_key` are required alongside it and
    /// [`Config::validate`] refuses a half-configured TLS setup rather than letting the
    /// listener silently fail to appear.
    #[serde(default)]
    pub tls_port: Option<u16>,
    /// Certificate for `turns:` — e.g. a Let's Encrypt fullchain for `node.host`.
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    /// Private key matching `tls_cert`. Must be readable by the coturn user.
    #[serde(default)]
    pub tls_key: Option<PathBuf>,
    /// Range coturn allocates relay ports from. Must match `min-port`/`max-port` in
    /// turnserver.conf and be open in the firewall, or media stops after signalling.
    #[serde(default = "d_turn_min_port")]
    pub relay_min_port: u16,
    #[serde(default = "d_turn_max_port")]
    pub relay_max_port: u16,
    pub realm: String,
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
    /// The relay stack: processes that must never *initiate* a connection outward.
    ///
    /// Deliberately excludes `turnserver`, which relays call media to the internet by
    /// design, and everything else on the host — on a multi-purpose machine a browser
    /// or a package manager talking to the internet is not a finding.
    #[serde(default = "d_relay_processes")]
    pub relay_processes: Vec<String>,
    /// Counters that are read and reported but never raise an incident: the permitted
    /// egress of other services. Their growth is expected; it is shown so the operator
    /// can see it is *them* growing and not `egress_drop`.
    #[serde(default = "d_informational_counters")]
    pub informational_counters: Vec<String>,
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
    /// Size of the closed circle, counted in **devices**, not people.
    ///
    /// ТЗ §1.1 says "≤ 20 устройств", written when one device per person was assumed.
    /// A household of 20 people runs 40–60 devices, so the shipped configuration sets
    /// this higher; the default here stays at the ТЗ figure so that a config which does
    /// not mention it keeps the original promise.
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
            relay_processes: d_relay_processes(),
            informational_counters: d_informational_counters(),
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

    /// Egress policy for hearthd's own outbound connections (`node.lan_networks`).
    ///
    /// The relays face the internet; the control plane does not. Keeping this in place
    /// costs nothing and preserves the property that any outbound attempt by the node
    /// itself is both blocked and observed (ТЗ §5.4).
    pub fn egress_policy(&self) -> EgressPolicy {
        EgressPolicy::new(self.node.lan_networks.clone())
    }

    /// Relays in a stable order, for iteration.
    pub fn relays(&self) -> Vec<&Relay> {
        vec![&self.smp, &self.xftp]
    }

    /// Enforce the invariants that can be checked statically.
    pub fn validate(&self) -> Result<()> {
        if self.node.host.trim().is_empty() {
            return Err(Error::config(
                "node.host must be the public hostname or IP clients connect to",
            ));
        }
        if self.node.host.contains([':', '/', '@']) {
            return Err(Error::config(format!(
                "node.host `{}` must be a bare host, without scheme, port or credentials",
                self.node.host
            )));
        }
        if self.node.lan_networks.is_empty() {
            return Err(Error::config("node.lan_networks must not be empty"));
        }
        let policy = self.egress_policy();

        for net in &self.node.admin_networks {
            let inside =
                self.node.lan_networks.iter().any(|lan| {
                    lan.contains(&net.network()) && lan.prefix_len() <= net.prefix_len()
                });
            if !inside {
                return Err(Error::config(format!(
                    "node.admin_networks entry {net} is not contained in node.lan_networks; \
                     the relays are public but administration must stay on the LAN"
                )));
            }
        }

        // The relays bind every interface by design (upstream: `host` is cosmetic), so
        // there is nothing to check there. The admin API is ours, and it must never be
        // exposed: no wildcard bind.
        if is_wildcard(&self.api.listen) {
            return Err(Error::config(format!(
                "api.listen binds the wildcard address {}; the admin API must be bound \
                 to a LAN address, never to the internet",
                self.api.listen
            )));
        }
        if !policy.permits_ip(self.api.listen.ip()) {
            return Err(Error::config(format!(
                "api.listen {} is outside node.lan_networks",
                self.api.listen
            )));
        }

        for relay in self.relays() {
            if !relay.enabled {
                continue;
            }
            if relay.port == 0 {
                return Err(Error::config(format!("{}.port must be set", relay.scheme)));
            }
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
        if self.smp.enabled && self.xftp.enabled {
            let smp_ports = self.smp.all_ports();
            if let Some(clash) = self.xftp.all_ports().iter().find(|p| smp_ports.contains(p)) {
                return Err(Error::config(format!("smp and xftp both use port {clash}")));
            }
        }
        if self.turn.enabled {
            if self.turn.relay_min_port >= self.turn.relay_max_port {
                return Err(Error::config(
                    "turn.relay_min_port must be below turn.relay_max_port",
                ));
            }
            // A TLS port without a certificate means coturn starts, opens no TLS
            // listener, and calls from TLS-only networks fail with nothing in the log
            // pointing at the cause. Refuse the half-configuration instead.
            match (self.turn.tls_port, &self.turn.tls_cert, &self.turn.tls_key) {
                (None, None, None) => {}
                (Some(_), Some(_), Some(_)) => {}
                (Some(port), _, _) => {
                    return Err(Error::config(format!(
                        "turn.tls_port {port} is set but turn.tls_cert/turn.tls_key are \
                         not; coturn would open no TLS listener at all"
                    )))
                }
                _ => {
                    return Err(Error::config(
                        "turn.tls_cert/turn.tls_key are set without turn.tls_port",
                    ))
                }
            }
            let relay_range = self.turn.relay_min_port..=self.turn.relay_max_port;
            for relay in self.relays() {
                if relay.enabled {
                    if let Some(clash) = relay
                        .all_ports()
                        .into_iter()
                        .find(|p| relay_range.contains(p))
                    {
                        return Err(Error::config(format!(
                            "{} port {clash} falls inside the TURN relay range \
                             {}-{}; coturn would fight the relay for it",
                            relay.scheme, self.turn.relay_min_port, self.turn.relay_max_port
                        )));
                    }
                }
            }
        }

        if let Some(remote) = &self.backup.remote {
            if !policy.permits_ip(remote.host) {
                return Err(Error::config(format!(
                    "backup.remote.host {} is outside node.lan_networks",
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
                    "alerts.gotify.addr {} is outside node.lan_networks \
                     (external alerting is forbidden by ТЗ §7.3)",
                    gotify.addr
                )));
            }
        }

        if self.device_api.enabled {
            // Порт device API не должен совпадать ни с релейным, ни с admin API:
            // иначе один из слушателей не поднимется, и какой именно — зависит от
            // порядка старта, то есть отладка будет случайной.
            let port = self.device_api.listen.port();
            let mut taken: Vec<u16> = self.smp.all_ports();
            taken.extend(self.xftp.all_ports());
            taken.push(self.api.listen.port());
            taken.push(self.turn.port);
            if taken.contains(&port) {
                return Err(Error::config(format!(
                    "device_api.listen port {port} is already used by another service"
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

impl Relay {
    /// Every port this relay listens on.
    pub fn all_ports(&self) -> Vec<u16> {
        let mut ports = vec![self.port];
        ports.extend(self.extra_ports.iter().copied());
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// Health probe target. The relay binds every interface, so loopback is the
    /// cheapest honest way to ask "is it accepting connections?".
    pub fn probe_addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }
}

impl Turn {
    /// Ports coturn listens on for signalling (not the relay range).
    pub fn all_ports(&self) -> Vec<u16> {
        let mut ports = vec![self.port];
        ports.extend(self.tls_port);
        ports
    }
}

fn d_true() -> bool {
    true
}
fn d_turn_min_port() -> u16 {
    49160
}
fn d_turn_max_port() -> u16 {
    49200
}
fn d_api_body_limit() -> usize {
    64 * 1024
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
fn d_relay_processes() -> Vec<String> {
    vec!["smp-server".into(), "xftp-server".into()]
}
fn d_informational_counters() -> Vec<String> {
    vec!["app_egress".into(), "turn_egress".into()]
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
    fn admin_api_may_not_be_exposed() {
        // The relays are public; the admin API must not be.
        let mut cfg = reference();
        cfg.api.listen = "0.0.0.0:7443".parse().expect("addr");
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("wildcard"), "got {err}");

        let mut cfg = reference();
        cfg.api.listen = "203.0.113.10:7443".parse().expect("addr");
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("lan_networks"), "got {err}");
    }

    #[test]
    fn rejects_non_loopback_control_port() {
        let mut cfg = reference();
        cfg.smp.control = Some("192.168.1.10:5224".parse().expect("addr"));
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_backup_target_outside_the_lan() {
        let mut cfg = reference();
        if let Some(remote) = cfg.backup.remote.as_mut() {
            remote.host = "203.0.113.7".parse().expect("ip");
        }
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("lan_networks"), "got {err}");
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
    fn rejects_admin_network_outside_the_lan() {
        let mut cfg = reference();
        cfg.node.admin_networks = vec!["10.99.0.0/16".parse().expect("cidr")];
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("admin_networks"), "got {err}");
    }

    #[test]
    fn rejects_a_host_that_is_not_a_bare_hostname() {
        for bad in ["smp://relay.example.org", "relay.example.org:5223", ""] {
            let mut cfg = reference();
            cfg.node.host = bad.into();
            assert!(cfg.validate().is_err(), "`{bad}` should be rejected");
        }
    }

    #[test]
    fn catches_port_collisions_between_services() {
        let mut cfg = reference();
        cfg.xftp.port = 443; // already in smp.extra_ports
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("both use port 443"), "got {err}");

        // A relay port inside the TURN relay range would be taken by coturn.
        let mut cfg = reference();
        cfg.smp.port = 49170;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("TURN relay range"), "got {err}");
    }

    #[test]
    fn refuses_half_configured_turn_tls() {
        // coturn without a certificate starts fine and opens no TLS listener. Calls
        // from TLS-only networks then fail with nothing in the log explaining why —
        // so the configuration is refused instead.
        let mut cfg = reference();
        cfg.turn.tls_port = Some(5349);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("tls_cert"), "got {err}");

        let mut cfg = reference();
        cfg.turn.tls_cert = Some("/etc/ssl/relay.pem".into());
        cfg.turn.tls_key = Some("/etc/ssl/relay.key".into());
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("tls_port"), "got {err}");

        let mut cfg = reference();
        cfg.turn.tls_port = Some(5349);
        cfg.turn.tls_cert = Some("/etc/ssl/relay.pem".into());
        cfg.turn.tls_key = Some("/etc/ssl/relay.key".into());
        cfg.validate().expect("all three together are valid");
    }

    #[test]
    fn relay_ports_include_the_extras() {
        let cfg = reference();
        assert_eq!(cfg.smp.all_ports(), vec![443, 5223, 8443]);
        // Проверка здоровья идёт на порт из адресов клиентов — теперь это 443.
        assert_eq!(cfg.smp.probe_addr().port(), 8443);
        assert!(cfg.smp.probe_addr().ip().is_loopback());
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

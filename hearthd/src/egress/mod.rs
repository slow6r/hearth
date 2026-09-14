//! Egress watchdog (ТЗ §5.4, §7.3).
//!
//! The relays are stock binaries nobody in this project audits line by line. Instead of
//! trusting them, the node is built so the relay stack cannot reach the internet, and
//! any attempt lands in a counter hearthd reads. Expected value of `egress_drop` over
//! 24 hours: **0**. Anything else is an incident, recorded forever.
//!
//! On a multi-purpose host other services DO go out on purpose (ADR 0008). They are
//! permitted by name in nftables and counted separately, so `egress_drop` keeps meaning
//! exactly one thing: the relay stack tried to leave.
//!
//! Two independent signals:
//!
//! 1. **nft named counters** every 30 s — cheap, catches blocked attempts;
//! 2. **`ss` socket scan** every 5 min — catches a connection that was *not* blocked,
//!    which would mean the ruleset is missing or bypassed.
//!
//! The counter baseline is persisted so that a hearthd restart does not re-report drops
//! that were already turned into incidents.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::model::alert::Alert;
use crate::model::health::{EgressIncident, ForeignSocket, HealthState};
use crate::state::AppState;
use crate::store;
use crate::sys::{journal, nft, ss};

/// Persisted baseline (`/var/lib/hearth/egress-counters.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Baseline {
    egress: nft::Counter,
    input: nft::Counter,
    incidents_total: u64,
    /// Когда случился инцидент, который человек ещё не подтвердил.
    ///
    /// Раньше красный статус жил только в памяти: в 02:00 релей пытался выйти
    /// наружу, в 03:00 hearthd перезапускался — по таймеру systemd, при обновлении
    /// или потому, что оператор сам перезапустил, увидев красное, — и утром
    /// `/egress` показывал `ok`. Единственным следом оставалась строчка «incidents
    /// ever», которую никто не читает.
    #[serde(default, with = "crate::model::rfc3339::option")]
    unresolved_since: Option<chrono::DateTime<chrono::Utc>>,
}

/// How many incidents `GET /egress` returns inline.
const RECENT_INCIDENTS: usize = 20;

/// The watchdog task.
#[derive(Debug)]
pub struct EgressWatchdog {
    state: Arc<AppState>,
    baseline: Baseline,
    /// Whether we already alerted that the counters cannot be read.
    blind_alerted: bool,
    /// То же для сканера сокетов: шумим один раз, пока он не заработает.
    scan_alerted: bool,
    /// Set when the persisted baseline existed but could not be parsed; reported on
    /// the first poll, once.
    baseline_lost: Option<String>,
}

impl EgressWatchdog {
    pub fn new(state: Arc<AppState>) -> Self {
        // A missing baseline is the normal first start. A baseline that exists but does
        // not parse is different: starting from zero would re-report every drop already
        // turned into an incident, so it is worth saying out loud.
        let path = state.config.paths.egress_state_file();
        let (baseline, baseline_lost) = match store::read_json::<Baseline>(&path) {
            Ok(Some(baseline)) => (baseline, None),
            Ok(None) => (Baseline::default(), None),
            Err(e) => (
                Baseline::default(),
                Some(format!("{}: {e}", path.display())),
            ),
        };
        Self {
            state,
            baseline,
            blind_alerted: false,
            scan_alerted: false,
            baseline_lost,
        }
    }

    /// Run both loops until shutdown.
    pub async fn run(mut self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let cfg = self.state.config.egress.clone();
        let mut counters = tokio::time::interval(Duration::from_secs(cfg.poll_interval_secs));
        let mut sockets = tokio::time::interval(Duration::from_secs(cfg.socket_scan_interval_secs));
        counters.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        sockets.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = counters.tick() => self.poll_counters().await,
                _ = sockets.tick() => self.scan_sockets().await,
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("egress watchdog stopping");
                        return;
                    }
                }
            }
        }
    }

    /// Read the nft counters and turn any growth into an incident.
    pub async fn poll_counters(&mut self) {
        self.refresh_unresolved();
        let cfg = self.state.config.egress.clone();
        let counters =
            match nft::list_counters(&self.state.sys, &cfg.nft_family, &cfg.nft_table).await {
                Ok(counters) => counters,
                Err(e) => {
                    self.mark_blind(&e.to_string()).await;
                    return;
                }
            };
        self.blind_alerted = false;

        if let Some(reason) = self.baseline_lost.take() {
            self.state
                .alerts
                .emit(
                    Alert::warning(
                        "egress",
                        "the persisted counter baseline was unreadable and has been reset; \
                         drops recorded before this restart may be reported again",
                    )
                    .with_details(serde_json::json!({ "reason": reason })),
                )
                .await;
        }

        let egress = counters
            .get(&cfg.egress_counter)
            .copied()
            .unwrap_or_default();
        let input = counters
            .get(&cfg.input_counter)
            .copied()
            .unwrap_or_default();
        let delta = nft::delta(self.baseline.egress, egress);

        let mut incidents = Vec::new();
        if delta.packets > 0 {
            // Something tried to leave the home network. Find out where to.
            let since = format!("-{}s", cfg.poll_interval_secs.saturating_mul(3).max(60));
            let read = journal::read_drops(&self.state.sys, &since, &cfg.journal_prefix).await;
            let destinations_known = read.is_ok();
            if let Err(e) = &read {
                tracing::warn!(error = %e, "журнал ядра недоступен: инцидент останется без адресатов");
            }
            let destinations = journal::aggregate(&read.unwrap_or_default());

            let incident = EgressIncident {
                ts: Utc::now(),
                kind: "counter".into(),
                packets: delta.packets,
                bytes: delta.bytes,
                destinations: destinations.clone(),
                sockets: Vec::new(),
                destinations_known,
            };
            self.record_incident(&incident).await;
            incidents.push(incident);

            self.state
                .alerts
                .emit(
                    // The counter is not attributed to a process — nftables counts
                    // whatever fell through every allow rule. Say that, rather than
                    // naming the relay stack: the journal destinations below are what
                    // actually identify the source.
                    Alert::critical(
                        "egress",
                        format!(
                            "{} outbound packets were dropped: something not on the \
                             allow-list tried to leave (expected 0)",
                            delta.packets
                        ),
                    )
                    .with_details(serde_json::json!({
                        "packets": delta.packets,
                        "bytes": delta.bytes,
                        "destinations": destinations,
                    })),
                )
                .await;
        }

        self.baseline.egress = egress;
        self.baseline.input = input;
        self.persist_baseline();

        let mut snapshot = self.state.egress.write().await;
        snapshot.checked = Utc::now();
        snapshot.counters_readable = true;
        snapshot.egress_drop_packets = egress.packets;
        snapshot.egress_drop_bytes = egress.bytes;
        snapshot.input_drop_packets = input.packets;
        snapshot.input_drop_bytes = input.bytes;
        snapshot.egress_drop_delta = snapshot.egress_drop_delta.saturating_add(delta.packets);
        snapshot.informational = cfg
            .informational_counters
            .iter()
            .filter_map(|name| counters.get(name).map(|c| (name.clone(), c.packets)))
            .collect();
        snapshot.incidents_total = self.baseline.incidents_total;
        if !incidents.is_empty() {
            snapshot.last_incident = incidents.last().map(|i| i.ts);
            snapshot.recent_incidents.extend(incidents);
            let overflow = snapshot
                .recent_incidents
                .len()
                .saturating_sub(RECENT_INCIDENTS);
            snapshot.recent_incidents.drain(..overflow);
        }
        snapshot.state = verdict(
            snapshot.egress_drop_delta,
            snapshot.foreign_sockets.len(),
            snapshot.counters_readable,
            snapshot.scanner_ok,
            self.baseline.unresolved_since.is_some(),
        );
    }

    /// List sockets and flag any relay connection leaving the home networks.
    pub async fn scan_sockets(&mut self) {
        let cfg = &self.state.config.egress;
        let sockets = match ss::list_tcp(&self.state.sys).await {
            Ok(sockets) => sockets,
            Err(e) => {
                // Ранний выход оставлял в снимке протухшие scanner_ok=true и пустой
                // список сокетов со временем последнего УДАЧНОГО скана: экран
                // утверждал, что проверка прошла и чиста, хотя её не было.
                tracing::warn!(error = %e, "ss unavailable, socket scan skipped");
                {
                    let mut snapshot = self.state.egress.write().await;
                    snapshot.checked = Utc::now();
                    snapshot.scanner_ok = false;
                    snapshot.foreign_sockets.clear();
                    snapshot.state = verdict(
                        snapshot.egress_drop_delta,
                        0,
                        snapshot.counters_readable,
                        false,
                        self.baseline.unresolved_since.is_some(),
                    );
                }
                if !self.scan_alerted {
                    self.scan_alerted = true;
                    self.state
                        .alerts
                        .emit(Alert::warning(
                            "egress",
                            format!("сокеты не перечисляются ({e}); второй сигнал утечки мёртв"),
                        ))
                        .await;
                }
                return;
            }
        };
        self.scan_alerted = false;
        // Ports we publish. A relay socket on one of them is an accepted connection —
        // a family member connecting in — not a leak.
        let mut listening_ports: Vec<u16> = Vec::new();
        for relay in self.state.config.relays() {
            if relay.enabled {
                listening_ports.extend(relay.all_ports());
            }
        }

        let can_see = scanner_can_see_relays(&sockets, &listening_ports);
        if !can_see {
            tracing::warn!(
                "ss does not reveal the owners of the relay sockets, so the socket scan \
                 proves nothing; the nft counters remain the primary signal"
            );
        }
        let foreign = find_foreign(
            &sockets,
            &cfg.relay_processes,
            &listening_ports,
            &self.state.policy,
            &cfg.process_allow,
        );

        if !foreign.is_empty() {
            let incident = EgressIncident {
                ts: Utc::now(),
                kind: "socket".into(),
                packets: 0,
                bytes: 0,
                destinations: Vec::new(),
                sockets: foreign.clone(),
                destinations_known: true,
            };
            self.record_incident(&incident).await;
            self.state
                .alerts
                .emit(
                    Alert::critical(
                        "egress",
                        format!(
                            "{} relay socket(s) are connected outside the home network",
                            foreign.len()
                        ),
                    )
                    .with_details(serde_json::json!({ "sockets": foreign })),
                )
                .await;

            let mut snapshot = self.state.egress.write().await;
            snapshot.last_incident = Some(incident.ts);
            snapshot.recent_incidents.push(incident);
            let overflow = snapshot
                .recent_incidents
                .len()
                .saturating_sub(RECENT_INCIDENTS);
            snapshot.recent_incidents.drain(..overflow);
        }

        let mut snapshot = self.state.egress.write().await;
        snapshot.checked = Utc::now();
        snapshot.foreign_sockets = foreign;
        snapshot.scanner_ok = can_see;
        snapshot.incidents_total = self.baseline.incidents_total;
        snapshot.state = verdict(
            snapshot.egress_drop_delta,
            snapshot.foreign_sockets.len(),
            snapshot.counters_readable,
            snapshot.scanner_ok,
            self.baseline.unresolved_since.is_some(),
        );
    }

    async fn record_incident(&mut self, incident: &EgressIncident) {
        self.baseline.incidents_total = self.baseline.incidents_total.saturating_add(1);
        if self.baseline.unresolved_since.is_none() {
            self.baseline.unresolved_since = Some(Utc::now());
        }
        self.persist_baseline();
        if let Ok(line) = serde_json::to_string(incident) {
            if let Err(e) =
                store::append_line(self.state.config.paths.egress_incidents_file(), &line)
            {
                tracing::error!(error = %e, "failed to append to the egress incident history");
            }
        }
    }

    /// The watchdog cannot read its counters: that is itself a problem worth alerting on,
    /// because a silent watchdog looks exactly like a clean node.
    async fn mark_blind(&mut self, reason: &str) {
        tracing::warn!(reason, "egress counters unreadable");
        {
            let mut snapshot = self.state.egress.write().await;
            snapshot.checked = Utc::now();
            snapshot.counters_readable = false;
            snapshot.state = HealthState::Degraded;
        }
        if !self.blind_alerted {
            self.blind_alerted = true;
            self.state
                .alerts
                .emit(
                    Alert::warning(
                        "egress",
                        "cannot read nftables counters; the leak detector is blind",
                    )
                    .with_details(serde_json::json!({ "reason": reason })),
                )
                .await;
        }
    }

    /// Перечитать с диска отметку о неподтверждённом инциденте.
    ///
    /// Подтверждает его человек — через admin API, то есть из другого процесса
    /// относительно этой задачи. Читать раз в опрос дешевле и честнее, чем городить
    /// канал: файл маленький, интервал секунды.
    fn refresh_unresolved(&mut self) {
        if let Ok(Some(persisted)) =
            store::read_json::<Baseline>(self.state.config.paths.egress_state_file())
        {
            self.baseline.unresolved_since = persisted.unresolved_since;
        }
    }

    fn persist_baseline(&self) {
        if let Err(e) = store::write_json_atomic(
            self.state.config.paths.egress_state_file(),
            &self.baseline,
            store::MODE_STATE,
        ) {
            tracing::error!(error = %e, "failed to persist the egress baseline");
        }
    }
}

/// Relay sockets that represent an **outbound** connection to the internet.
///
/// # Why the direction matters now
///
/// Before the relays were published, any relay socket with a non-home peer was a
/// finding. Since [ADR 0007](../../docs/adr/0007-public-relay-no-vpn.md) that is the
/// normal case: those are family members connecting in from the internet.
///
/// The leak is the opposite direction — the relay *initiating* a connection. The two
/// are told apart by the local port: an accepted connection keeps the listening port
/// locally, while an outbound one gets an ephemeral port and the service port on the
/// remote side. So a relay socket whose local port is not one of ours, pointing at a
/// non-home peer, is the thing worth alerting on.
///
/// # Named exceptions
///
/// One relay process dials out by design: ntf-server delivering pushes to Apple
/// (ADR 0016). `allow` lists such destinations per process, and a socket is excused only
/// when its owner, peer network AND peer port all match — the width of the `ntf_egress`
/// rule in hearth.nft, not wider.
fn find_foreign(
    sockets: &[ss::SocketEntry],
    relay_processes: &[String],
    listening_ports: &[u16],
    policy: &crate::net::EgressPolicy,
    allow: &[crate::config::ProcessAllow],
) -> Vec<ForeignSocket> {
    sockets
        .iter()
        .filter(|s| s.is_established())
        // Only the relay stack. Everything else on a multi-purpose host — a browser,
        // a package manager, coturn relaying a call — talks to the internet by design.
        .filter(|s| relay_processes.iter().any(|p| s.owned_by(p)))
        .filter(|s| {
            // Inbound: the local side is one of our published ports.
            let local_port = ss::split_host_port(&s.local).map(|(_, port)| port);
            !local_port.is_some_and(|port| listening_ports.contains(&port))
        })
        .filter(|s| match s.peer_ip() {
            Some(ip) => !policy.permits_ip(ip),
            None => false,
        })
        .filter(|s| {
            let peer = ss::split_host_port(&s.peer)
                .and_then(|(_, port)| s.peer_ip().map(|ip| SocketAddr::new(ip, port)));
            !peer.is_some_and(|peer| {
                allow
                    .iter()
                    .any(|entry| s.owned_by(&entry.process) && entry.covers(peer))
            })
        })
        .map(|s| ForeignSocket {
            process: s.processes.first().cloned().unwrap_or_else(|| "?".into()),
            local: s.local.clone(),
            peer: s.peer.clone(),
            state: s.state.clone(),
        })
        .collect()
}

/// Can the scan actually see the relays?
///
/// `ss -p` names the owning process only for sockets the caller is allowed to inspect;
/// for another user's socket that needs root or `CAP_SYS_PTRACE`. hearthd runs as an
/// unprivileged user, so in a properly sandboxed deployment it sees its **own** socket
/// names and not the relays'.
///
/// Asking "did any socket name a process?" therefore answers yes on hearthd's own
/// sockets and reports a clean scan that examined nothing. The honest question is
/// narrower: on the ports we publish — where the relays' sockets live — is any owner
/// visible at all?
///
/// hearthd deliberately does **not** take `CAP_SYS_PTRACE` to fix this: that capability
/// would let it read the relay's memory, and the one thing this daemon must never be
/// able to do is look at message content (ТЗ §7.4). A degraded second signal is the
/// right trade; the nft counters remain the primary one.
fn scanner_can_see_relays(sockets: &[ss::SocketEntry], listening_ports: &[u16]) -> bool {
    let mut relay_sockets = sockets.iter().filter(|s| {
        ss::split_host_port(&s.local).is_some_and(|(_, port)| listening_ports.contains(&port))
    });
    // No sockets on the published ports at all means the relays are down — that is the
    // supervisor's problem, not evidence that the scan is blind.
    match relay_sockets.next() {
        None => true,
        Some(first) => {
            !first.processes.is_empty() || relay_sockets.any(|s| !s.processes.is_empty())
        }
    }
}

/// Подтвердить инцидент: человек его увидел и разобрался.
///
/// Снимается только так. Молчаливое «следующий опрос чистый — значит всё хорошо» и
/// было причиной того, что красный статус исчезал сам при перезапуске демона.
pub fn acknowledge_incident(
    config: &crate::config::Config,
) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    let path = config.paths.egress_state_file();
    let mut baseline: Baseline = store::read_json(&path)?.unwrap_or_default();
    let was = baseline.unresolved_since.take();
    store::write_json_atomic(&path, &baseline, store::MODE_STATE)?;
    Ok(was)
}

/// Any drop or any foreign socket is critical; ТЗ §5.4 allows no grey zone.
///
/// Отдельно — случай «проверить не удалось». Раньше он давал `Ok`: недоступный nft
/// или отсутствующий `ss` означали, что сторож ослеп, а `GET /egress` при этом
/// отдавал state:"ok" и `hearthctl egress` завершался нулём. Внешний контроль видел
/// зелёное там, где не было никакой проверки. Неизвестность — это Degraded, и она
/// обязана отличаться и от «всё чисто», и от «есть утечка».
fn verdict(
    egress_delta: u64,
    foreign: usize,
    counters_readable: bool,
    scanner_ok: bool,
    unresolved_incident: bool,
) -> HealthState {
    if egress_delta > 0 || foreign > 0 || unresolved_incident {
        HealthState::Down
    } else if !counters_readable || !scanner_ok {
        HealthState::Degraded
    } else {
        HealthState::Ok
    }
}

/// Aggregate the permanent incident history for reporting.
pub fn summarize_history(incidents: &[EgressIncident]) -> BTreeMap<String, u64> {
    let mut by_dst = BTreeMap::new();
    for incident in incidents {
        for dst in &incident.destinations {
            *by_dst.entry(dst.dst.clone()).or_insert(0) += dst.packets;
        }
        for socket in &incident.sockets {
            *by_dst.entry(socket.peer.clone()).or_insert(0) += 1;
        }
    }
    by_dst
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::EgressPolicy;
    use crate::sys::Sys;

    fn policy() -> EgressPolicy {
        EgressPolicy::new(vec!["192.168.1.0/24".parse().expect("cidr")])
    }

    fn relays() -> Vec<String> {
        vec!["smp-server".to_string(), "xftp-server".to_string()]
    }

    /// Ports we publish. Sockets whose LOCAL side is one of these are inbound.
    const PORTS: &[u16] = &[443, 5223, 5443];

    /// A realistic multi-purpose host: family members connected from the internet,
    /// a browser and a package manager doing their job, coturn relaying a call —
    /// and one relay socket that should not exist.
    const SS_OUTPUT: &str = "\
LISTEN 0 1024 0.0.0.0:5223 0.0.0.0:* users:((\"smp-server\",pid=812,fd=9))
ESTAB  0 0 203.0.113.10:5223 84.17.52.9:44321 users:((\"smp-server\",pid=812,fd=27))
ESTAB  0 0 203.0.113.10:443  91.108.4.7:51200 users:((\"smp-server\",pid=812,fd=28))
ESTAB  0 0 203.0.113.10:5443 84.17.52.9:44980 users:((\"xftp-server\",pid=830,fd=14))
ESTAB  0 0 192.168.1.10:47120 142.250.185.78:443 users:((\"firefox\",pid=2201,fd=51))
ESTAB  0 0 192.168.1.10:47250 151.101.0.204:443 users:((\"apt-get\",pid=2299,fd=7))
ESTAB  0 0 203.0.113.10:49170 88.12.3.4:60000 users:((\"turnserver\",pid=900,fd=33))
ESTAB  0 0 203.0.113.10:38000 142.250.185.78:443 users:((\"smp-server\",pid=812,fd=31))
";

    #[test]
    fn flags_a_relay_that_dials_out() {
        let sockets = ss::parse(SS_OUTPUT);
        let foreign = find_foreign(&sockets, &relays(), PORTS, &policy(), &[]);
        assert_eq!(foreign.len(), 1, "exactly one socket is a real finding");
        assert_eq!(foreign[0].peer, "142.250.185.78:443");
        assert_eq!(foreign[0].process, "smp-server");
        assert_eq!(
            foreign[0].local, "203.0.113.10:38000",
            "an ephemeral local port is what makes it outbound"
        );
    }

    #[test]
    fn inbound_clients_are_not_findings() {
        // The whole point of ADR 0007: strangers' addresses connecting to 5223/443/5443
        // are family members, not leaks.
        let sockets = ss::parse(SS_OUTPUT);
        let foreign = find_foreign(&sockets, &relays(), PORTS, &policy(), &[]);
        assert!(
            !foreign
                .iter()
                .any(|f| f.peer.starts_with("84.17") || f.peer.starts_with("91.108")),
            "connections accepted on published ports must be ignored"
        );
    }

    #[test]
    fn other_services_are_none_of_our_business() {
        let sockets = ss::parse(SS_OUTPUT);
        let foreign = find_foreign(&sockets, &relays(), PORTS, &policy(), &[]);
        for process in ["firefox", "apt-get", "turnserver"] {
            assert!(
                !foreign.iter().any(|f| f.process == process),
                "{process} talking to the internet is expected on this host"
            );
        }
    }

    #[test]
    fn the_push_server_may_reach_apple_and_nothing_else() {
        // ntf-server звонит в APNs по назначению (ADR 0016). Исключение ровно такой ширины,
        // как правило ntf_egress в hearth.nft: процесс, сеть и порт — вместе.
        let allow = vec![crate::config::ProcessAllow {
            process: "ntf-server".into(),
            networks: vec!["17.0.0.0/8".parse().expect("cidr")],
            ports: vec![443],
        }];
        let processes = vec![
            "smp-server".to_string(),
            "xftp-server".to_string(),
            "ntf-server".to_string(),
        ];
        let sockets = ss::parse(
            "ESTAB 0 0 203.0.113.10:41000 17.188.143.34:443 users:((\"ntf-server\",pid=950,fd=20))\n\
             ESTAB 0 0 203.0.113.10:41001 17.188.143.34:80 users:((\"ntf-server\",pid=950,fd=21))\n\
             ESTAB 0 0 203.0.113.10:41002 142.250.185.78:443 users:((\"ntf-server\",pid=950,fd=22))\n\
             ESTAB 0 0 203.0.113.10:41003 17.188.143.34:443 users:((\"smp-server\",pid=812,fd=40))\n\
             ESTAB 0 0 192.168.1.72:41004 192.168.1.72:8443 users:((\"ntf-server\",pid=950,fd=23))\n",
        );
        let ports = [443, 5223, 5443, 8443, 2053];
        let foreign = find_foreign(&sockets, &processes, &ports, &policy(), &allow);
        let peers: Vec<(&str, &str)> = foreign
            .iter()
            .map(|f| (f.process.as_str(), f.peer.as_str()))
            .collect();
        assert_eq!(
            peers,
            vec![
                ("ntf-server", "17.188.143.34:80"),
                ("ntf-server", "142.250.185.78:443"),
                ("smp-server", "17.188.143.34:443"),
            ],
            "only ntf-server itself, to Apple, on 443 is excused; its own relay over the LAN \
             was never a finding"
        );
    }

    #[test]
    fn a_scan_that_cannot_see_the_relays_says_so() {
        let named = ss::parse(SS_OUTPUT);
        assert!(scanner_can_see_relays(&named, PORTS));

        // The realistic failure: hearthd runs unprivileged, so `ss` names hearthd's own
        // socket but not the relays'. Asking "did ANY socket name a process?" would
        // answer yes here and report a scan that examined nothing.
        let partial = ss::parse(
            "ESTAB 0 0 203.0.113.10:5223 84.17.52.9:44321\n\
             ESTAB 0 0 192.168.1.10:7443 192.168.1.5:51000 users:((\"hearthd\",pid=901,fd=12))\n",
        );
        assert!(
            !scanner_can_see_relays(&partial, PORTS),
            "hearthd seeing its own socket is not the same as seeing the relays"
        );

        // Relays stopped: no sockets on the published ports. That is the supervisor's
        // problem, not evidence that the scan is blind.
        let no_relays = ss::parse(
            "ESTAB 0 0 192.168.1.10:7443 192.168.1.5:51000 users:((\"hearthd\",pid=901,fd=12))\n",
        );
        assert!(scanner_can_see_relays(&no_relays, PORTS));
        assert!(scanner_can_see_relays(&[], PORTS));
    }

    #[tokio::test]
    async fn an_unacknowledged_incident_survives_a_restart() {
        // Сценарий: ночью релей пытался выйти наружу, утром демон перезапустился по
        // таймеру. Раньше красный статус исчезал вместе с памятью процесса.
        let dir = tempfile::tempdir().expect("tempdir");
        let config = crate::state::tests::test_config(dir.path());
        let path = config.paths.egress_state_file();
        crate::store::ensure_dir(path.parent().expect("parent")).expect("dir");

        let baseline = Baseline {
            egress: Default::default(),
            input: Default::default(),
            incidents_total: 1,
            unresolved_since: Some(Utc::now()),
        };
        crate::store::write_json_atomic(&path, &baseline, crate::store::MODE_STATE).expect("write");

        let restored: Baseline = crate::store::read_json(&path).expect("read").expect("some");
        assert!(
            restored.unresolved_since.is_some(),
            "неподтверждённый инцидент обязан пережить перезапуск"
        );
        assert_eq!(
            verdict(0, 0, true, true, restored.unresolved_since.is_some()),
            HealthState::Down,
            "пока инцидент не подтверждён, статус остаётся красным"
        );

        let was = acknowledge_incident(&config).expect("acknowledge");
        assert!(was.is_some());
        let after: Baseline = crate::store::read_json(&path).expect("read").expect("some");
        assert!(after.unresolved_since.is_none());
        assert_eq!(after.incidents_total, 1, "история инцидентов не стирается");
    }

    #[tokio::test]
    async fn a_corrupt_baseline_is_reported_not_silently_reset() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = crate::state::tests::test_config(dir.path());
        std::fs::create_dir_all(&config.paths.state_dir).expect("mkdir");
        std::fs::write(config.paths.egress_state_file(), b"{ this is not json").expect("write");

        let state = AppState::new(config, Sys::new(true)).expect("state");
        let watchdog = EgressWatchdog::new(state.clone());
        assert!(
            watchdog.baseline_lost.is_some(),
            "a baseline that exists but does not parse must be noticed"
        );

        // A missing file, by contrast, is the normal first start.
        let dir2 = tempfile::tempdir().expect("tempdir");
        let config2 = crate::state::tests::test_config(dir2.path());
        let state2 = AppState::new(config2, Sys::new(true)).expect("state");
        assert!(EgressWatchdog::new(state2).baseline_lost.is_none());
    }

    #[test]
    fn verdict_is_binary() {
        assert_eq!(verdict(0, 0, true, true, false), HealthState::Ok);
        assert_eq!(verdict(1, 0, true, true, false), HealthState::Down);
        assert_eq!(verdict(0, 1, true, true, false), HealthState::Down);
        // Ослепший сторож не имеет права отвечать «всё хорошо».
        assert_eq!(verdict(0, 0, false, true, false), HealthState::Degraded);
        assert_eq!(verdict(0, 0, true, false, false), HealthState::Degraded);
        // Но настоящая утечка важнее неизвестности.
        assert_eq!(verdict(1, 0, false, false, false), HealthState::Down);
        // Неподтверждённый инцидент держит красное, даже когда сейчас всё чисто:
        // иначе перезапуск демона стирал бы след утечки.
        assert_eq!(verdict(0, 0, true, true, true), HealthState::Down);
    }

    #[tokio::test]
    async fn unreadable_counters_degrade_and_alert_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = crate::state::tests::test_config(dir.path());
        let state = AppState::new(config, Sys::new(false)).expect("state");
        let mut watchdog = EgressWatchdog::new(state.clone());

        // `nft` does not exist on the test machine -> the watchdog must notice it is blind.
        watchdog.poll_counters().await;
        watchdog.poll_counters().await;

        let snapshot = state.egress.read().await;
        assert!(!snapshot.counters_readable);
        assert_eq!(snapshot.state, HealthState::Degraded);

        let alerts = state.alerts.query(None, None, 10).await;
        let blind: Vec<_> = alerts
            .iter()
            .filter(|a| a.summary.contains("leak detector is blind"))
            .collect();
        assert_eq!(blind.len(), 1, "the blind-watchdog alert must not spam");
    }

    #[test]
    fn history_summary_counts_destinations() {
        let incidents = vec![
            EgressIncident {
                ts: Utc::now(),
                kind: "counter".into(),
                packets: 3,
                bytes: 180,
                destinations: vec![crate::model::health::DropDestination {
                    dst: "142.250.185.78:443".into(),
                    proto: "TCP".into(),
                    packets: 3,
                }],
                sockets: Vec::new(),
                destinations_known: true,
            },
            EgressIncident {
                ts: Utc::now(),
                kind: "socket".into(),
                packets: 0,
                bytes: 0,
                destinations: Vec::new(),
                sockets: vec![ForeignSocket {
                    process: "smp-server".into(),
                    local: "10.66.10.10:47120".into(),
                    peer: "142.250.185.78:443".into(),
                    state: "ESTAB".into(),
                }],
                destinations_known: true,
            },
        ];
        let summary = summarize_history(&incidents);
        assert_eq!(summary["142.250.185.78:443"], 4);
    }
}

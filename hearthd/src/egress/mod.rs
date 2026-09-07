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
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};

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
}

impl EgressWatchdog {
    pub fn new(state: Arc<AppState>) -> Self {
        let baseline: Baseline = store::read_json(state.config.paths.egress_state_file())
            .ok()
            .flatten()
            .unwrap_or_default();
        Self {
            state,
            baseline,
            blind_alerted: false,
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
            let events = journal::read_drops(&self.state.sys, &since, &cfg.journal_prefix)
                .await
                .unwrap_or_default();
            let destinations = journal::aggregate(&events);

            let incident = EgressIncident {
                ts: Utc::now(),
                kind: "counter".into(),
                packets: delta.packets,
                bytes: delta.bytes,
                destinations: destinations.clone(),
                sockets: Vec::new(),
            };
            self.record_incident(&incident).await;
            incidents.push(incident);

            self.state
                .alerts
                .emit(
                    Alert::critical(
                        "egress",
                        format!(
                            "{} packets from the relay stack were dropped on the way out \
                             (expected 0)",
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
        snapshot.state = verdict(snapshot.egress_drop_delta, snapshot.foreign_sockets.len());
    }

    /// List sockets and flag any relay connection leaving the home networks.
    pub async fn scan_sockets(&mut self) {
        let cfg = &self.state.config.egress;
        let sockets = match ss::list_tcp(&self.state.sys).await {
            Ok(sockets) => sockets,
            Err(e) => {
                tracing::warn!(error = %e, "ss unavailable, socket scan skipped");
                return;
            }
        };
        // Ports we publish. A relay socket on one of them is an accepted connection —
        // a family member connecting in — not a leak.
        let mut listening_ports: Vec<u16> = Vec::new();
        for relay in self.state.config.relays() {
            if relay.enabled {
                listening_ports.extend(relay.all_ports());
            }
        }

        let blind = scanner_is_blind(&sockets);
        if blind {
            tracing::warn!(
                "ss reported no process names; the socket scan cannot attribute sockets \
                 (hearthd needs privileges to inspect other users' sockets)"
            );
        }
        let foreign = find_foreign(
            &sockets,
            &cfg.relay_processes,
            &listening_ports,
            &self.state.policy,
        );

        if !foreign.is_empty() {
            let incident = EgressIncident {
                ts: Utc::now(),
                kind: "socket".into(),
                packets: 0,
                bytes: 0,
                destinations: Vec::new(),
                sockets: foreign.clone(),
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
        snapshot.scanner_ok = !blind;
        snapshot.incidents_total = self.baseline.incidents_total;
        snapshot.state = verdict(snapshot.egress_drop_delta, snapshot.foreign_sockets.len());
    }

    async fn record_incident(&mut self, incident: &EgressIncident) {
        self.baseline.incidents_total = self.baseline.incidents_total.saturating_add(1);
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
fn find_foreign(
    sockets: &[ss::SocketEntry],
    relay_processes: &[String],
    listening_ports: &[u16],
    policy: &crate::net::EgressPolicy,
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
        .map(|s| ForeignSocket {
            process: s.processes.first().cloned().unwrap_or_else(|| "?".into()),
            local: s.local.clone(),
            peer: s.peer.clone(),
            state: s.state.clone(),
        })
        .collect()
}

/// `ss` only reveals process names for sockets the caller may inspect. If none of the
/// listed sockets name a process, the scan cannot attribute anything and must say so
/// rather than report a clean result — a blind scanner looks exactly like a clean host.
fn scanner_is_blind(sockets: &[ss::SocketEntry]) -> bool {
    !sockets.is_empty() && sockets.iter().all(|s| s.processes.is_empty())
}

/// Any drop or any foreign socket is critical; ТЗ §5.4 allows no grey zone.
fn verdict(egress_delta: u64, foreign: usize) -> HealthState {
    if egress_delta > 0 || foreign > 0 {
        HealthState::Down
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
        let foreign = find_foreign(&sockets, &relays(), PORTS, &policy());
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
        let foreign = find_foreign(&sockets, &relays(), PORTS, &policy());
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
        let foreign = find_foreign(&sockets, &relays(), PORTS, &policy());
        for process in ["firefox", "apt-get", "turnserver"] {
            assert!(
                !foreign.iter().any(|f| f.process == process),
                "{process} talking to the internet is expected on this host"
            );
        }
    }

    #[test]
    fn a_scan_that_cannot_name_processes_says_so() {
        let named = ss::parse(SS_OUTPUT);
        assert!(!scanner_is_blind(&named));

        // `ss` without privileges: sockets listed, owners hidden.
        let anonymous = ss::parse("ESTAB 0 0 203.0.113.10:38000 1.2.3.4:443\n");
        assert!(
            scanner_is_blind(&anonymous),
            "reporting `clean` here would be a lie"
        );
        assert!(!scanner_is_blind(&[]), "no sockets at all is not blindness");
    }

    #[test]
    fn verdict_is_binary() {
        assert_eq!(verdict(0, 0), HealthState::Ok);
        assert_eq!(verdict(1, 0), HealthState::Down);
        assert_eq!(verdict(0, 1), HealthState::Down);
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
            },
        ];
        let summary = summarize_history(&incidents);
        assert_eq!(summary["142.250.185.78:443"], 4);
    }
}

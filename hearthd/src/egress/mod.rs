//! Egress watchdog (ТЗ §5.4, §7.3) — the module the whole trust model rests on.
//!
//! The relays are stock binaries nobody in this project audits line by line. Instead of
//! trusting them, the node is built so that *any* attempt to talk to the outside world
//! is dropped by nftables and lands in a counter hearthd reads. Expected value of
//! `egress_drop` over 24 hours: **0**. Anything else is an incident, recorded forever.
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
        let cfg = &self.state.config.egress;
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
                            "{} packets were dropped leaving the home network (expected 0)",
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
        let foreign = find_foreign(&sockets, &cfg.watch_processes, &self.state.policy);

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

/// Sockets owned by a watched process whose peer is outside the home networks.
fn find_foreign(
    sockets: &[ss::SocketEntry],
    watch_processes: &[String],
    policy: &crate::net::EgressPolicy,
) -> Vec<ForeignSocket> {
    sockets
        .iter()
        .filter(|s| s.is_established())
        .filter(|s| {
            watch_processes.is_empty()
                || watch_processes.iter().any(|p| s.owned_by(p))
                // A socket with no visible owner still matters: `ss` may not have had
                // permission to read /proc for it.
                || s.processes.is_empty()
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
        EgressPolicy::new(vec!["10.66.0.0/16".parse().expect("cidr")])
    }

    const SS_OUTPUT: &str = "\
ESTAB 0 0 10.66.10.10:5223 10.66.100.5:44321 users:((\"smp-server\",pid=812,fd=27))
ESTAB 0 0 10.66.10.10:47120 142.250.185.78:443 users:((\"smp-server\",pid=812,fd=31))
LISTEN 0 1024 10.66.10.10:5223 0.0.0.0:* users:((\"smp-server\",pid=812,fd=9))
ESTAB 0 0 10.66.10.10:38000 8.8.8.8:53 users:((\"unrelated\",pid=99,fd=3))
";

    #[test]
    fn flags_only_foreign_relay_sockets() {
        let sockets = ss::parse(SS_OUTPUT);
        let watched = vec!["smp-server".to_string()];
        let foreign = find_foreign(&sockets, &watched, &policy());
        assert_eq!(foreign.len(), 1);
        assert_eq!(foreign[0].peer, "142.250.185.78:443");
        assert_eq!(foreign[0].process, "smp-server");
    }

    #[test]
    fn ignores_home_peers_and_listeners() {
        let sockets = ss::parse(SS_OUTPUT);
        let foreign = find_foreign(&sockets, &["smp-server".to_string()], &policy());
        assert!(foreign.iter().all(|f| f.state == "ESTAB"));
        assert!(!foreign.iter().any(|f| f.peer.starts_with("10.66.")));
    }

    #[test]
    fn empty_watch_list_watches_everything() {
        let sockets = ss::parse(SS_OUTPUT);
        let foreign = find_foreign(&sockets, &[], &policy());
        assert_eq!(foreign.len(), 2, "both foreign peers are reported");
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

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

        let tail = store::tail_lines(&journal, RECENT_CAPACITY)?;
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
        })
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

#[cfg(test)]
mod tests {
    use super::*;

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
}

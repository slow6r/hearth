//! Alert model (ТЗ §7.3 `alerts`).
//!
//! Alerts go to the journal first and to a WG-only channel second. There is no
//! external notification path by design — Telegram/e-mail would be an egress hole.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Alert severity, ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn at_least(self, min: Severity) -> bool {
        self >= min
    }

    /// Gotify priority mapping (1 = quiet, 8 = pop-up + sound).
    pub fn gotify_priority(self, configured: u8) -> u8 {
        match self {
            Severity::Info => 1,
            Severity::Warning => configured.min(5),
            Severity::Critical => configured.max(8),
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for Severity {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "warn" | "warning" => Ok(Severity::Warning),
            "crit" | "critical" => Ok(Severity::Critical),
            other => Err(Error::invalid(format!(
                "unknown severity `{other}` (info|warning|critical)"
            ))),
        }
    }
}

/// A single alert record, as stored in `alerts.jsonl` and returned by `GET /alerts`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Alert {
    /// Monotonic per-node id (sequence number in the journal).
    pub id: u64,
    #[serde(with = "crate::model::rfc3339")]
    pub ts: DateTime<Utc>,
    pub severity: Severity,
    /// Emitting module: `supervisor`, `egress`, `integrity`, `backup`, `api`, `migrate`.
    pub module: String,
    /// One-line human summary.
    pub summary: String,
    /// Structured payload. Must never contain client addresses (ТЗ §7.4).
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub details: serde_json::Value,
    /// Kept in the permanent incident history (egress drops, integrity mismatches).
    #[serde(default)]
    pub sticky: bool,
}

impl Alert {
    pub fn new(severity: Severity, module: &str, summary: impl Into<String>) -> Self {
        Self {
            id: 0,
            ts: Utc::now(),
            severity,
            module: module.to_string(),
            summary: summary.into(),
            details: serde_json::Value::Null,
            sticky: false,
        }
    }

    pub fn info(module: &str, summary: impl Into<String>) -> Self {
        Self::new(Severity::Info, module, summary)
    }

    pub fn warning(module: &str, summary: impl Into<String>) -> Self {
        Self::new(Severity::Warning, module, summary)
    }

    /// A critical alert is always sticky: it stays in the permanent history.
    pub fn critical(module: &str, summary: impl Into<String>) -> Self {
        let mut alert = Self::new(Severity::Critical, module, summary);
        alert.sticky = true;
        alert
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }

    pub fn sticky(mut self, sticky: bool) -> Self {
        self.sticky = sticky;
        self
    }

    /// One-line rendering for the journal and the beeper/Gotify title.
    pub fn title(&self) -> String {
        format!("[{}] {}: {}", self.severity, self.module, self.summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_is_ordered() {
        assert!(Severity::Critical > Severity::Warning);
        assert!(Severity::Warning > Severity::Info);
        assert!(Severity::Critical.at_least(Severity::Warning));
        assert!(!Severity::Info.at_least(Severity::Warning));
    }

    #[test]
    fn severity_round_trips() {
        for s in [Severity::Info, Severity::Warning, Severity::Critical] {
            let parsed: Severity = s.to_string().parse().expect("parse");
            assert_eq!(parsed, s);
        }
        assert!("nonsense".parse::<Severity>().is_err());
    }

    #[test]
    fn criticals_are_sticky_by_default() {
        let alert = Alert::critical("egress", "unexpected egress drop");
        assert!(alert.sticky);
        assert_eq!(alert.title(), "[critical] egress: unexpected egress drop");
    }

    #[test]
    fn critical_forces_loud_gotify_priority() {
        assert_eq!(Severity::Critical.gotify_priority(3), 8);
        assert_eq!(Severity::Info.gotify_priority(8), 1);
    }

    #[test]
    fn serializes_without_null_details() {
        let alert = Alert::info("supervisor", "started");
        let json = serde_json::to_string(&alert).expect("json");
        assert!(!json.contains("details"), "got {json}");
    }
}

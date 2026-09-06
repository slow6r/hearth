//! systemd unit control.
//!
//! ТЗ §7.2 suggests `zbus`. This implementation shells out to `systemctl` instead —
//! see docs/adr/0002-systemctl-instead-of-zbus.md. The behaviour is identical, the
//! dependency surface is ~30 crates smaller, and the daemon needs no access to the
//! D-Bus system socket, which keeps its sandbox tighter.

use std::collections::BTreeMap;

use crate::error::Result;
use crate::sys::Sys;

/// Properties hearthd reads for every supervised unit.
const PROPERTIES: &str = "ActiveState,SubState,UnitFileState,NRestarts,ExecMainStartTimestamp";

/// Snapshot of a unit's systemd state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnitState {
    pub active_state: String,
    pub sub_state: String,
    pub unit_file_state: String,
    pub n_restarts: u32,
    pub start_timestamp: String,
}

impl UnitState {
    pub fn is_active(&self) -> bool {
        self.active_state == "active"
    }

    pub fn is_failed(&self) -> bool {
        self.active_state == "failed"
    }

    /// `unknown` state used when systemd is not available (dev machine, container).
    pub fn unknown() -> Self {
        Self {
            active_state: "unknown".into(),
            sub_state: "unknown".into(),
            unit_file_state: "unknown".into(),
            n_restarts: 0,
            start_timestamp: String::new(),
        }
    }
}

/// `systemctl show <unit> --property=...`
pub async fn show(sys: &Sys, unit: &str) -> Result<UnitState> {
    let out = sys
        .capture(
            "systemctl",
            &["show", unit, &format!("--property={PROPERTIES}")],
        )
        .await?;
    if !out.ok() {
        return Ok(UnitState::unknown());
    }
    Ok(parse_show(&out.stdout))
}

/// Parse `Key=Value` lines from `systemctl show`.
pub fn parse_show(text: &str) -> UnitState {
    let mut props: BTreeMap<&str, &str> = BTreeMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            props.insert(k.trim(), v.trim());
        }
    }
    UnitState {
        active_state: props.get("ActiveState").unwrap_or(&"unknown").to_string(),
        sub_state: props.get("SubState").unwrap_or(&"unknown").to_string(),
        unit_file_state: props.get("UnitFileState").unwrap_or(&"unknown").to_string(),
        n_restarts: props
            .get("NRestarts")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        start_timestamp: props
            .get("ExecMainStartTimestamp")
            .unwrap_or(&"")
            .to_string(),
    }
}

pub async fn restart(sys: &Sys, unit: &str) -> Result<()> {
    sys.run_mutating("systemctl", &["restart", unit]).await?;
    Ok(())
}

pub async fn start(sys: &Sys, unit: &str) -> Result<()> {
    sys.run_mutating("systemctl", &["start", unit]).await?;
    Ok(())
}

pub async fn stop(sys: &Sys, unit: &str) -> Result<()> {
    sys.run_mutating("systemctl", &["stop", unit]).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_systemctl_show() {
        let text = "ActiveState=active\nSubState=running\nUnitFileState=enabled\n\
                    NRestarts=2\nExecMainStartTimestamp=Sat 2026-09-06 12:00:00 UTC\n";
        let state = parse_show(text);
        assert!(state.is_active());
        assert!(!state.is_failed());
        assert_eq!(state.sub_state, "running");
        assert_eq!(state.n_restarts, 2);
    }

    #[test]
    fn missing_properties_fall_back_to_unknown() {
        let state = parse_show("");
        assert_eq!(state.active_state, "unknown");
        assert_eq!(state.n_restarts, 0);
        assert!(!state.is_active());
    }

    #[test]
    fn detects_failed_units() {
        let state = parse_show("ActiveState=failed\nSubState=failed\n");
        assert!(state.is_failed());
    }
}

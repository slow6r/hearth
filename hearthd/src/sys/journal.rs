//! journald reading for the egress watchdog (ТЗ §7.3).
//!
//! nftables logs every dropped packet with the prefix `hearth-egress-drop `. The
//! counter says *how many*; the log says *where to*. hearthd aggregates the log lines
//! by `daddr:dport` so an incident report names the destination that was attempted.
//!
//! Only kernel messages are read (`journalctl -k`) and only the `LOG=` fields are
//! parsed — hearthd never reads relay logs, which could contain client addresses.

use std::collections::BTreeMap;

use crate::error::Result;
use crate::model::health::DropDestination;
use crate::sys::Sys;

/// One netfilter LOG record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropEvent {
    pub prefix: String,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub proto: String,
    pub spt: Option<u16>,
    pub dpt: Option<u16>,
    pub out_iface: Option<String>,
}

impl DropEvent {
    /// Aggregation key: `daddr:dport` (ТЗ §7.3).
    pub fn key(&self) -> String {
        match (&self.dst, self.dpt) {
            (Some(dst), Some(port)) => format!("{dst}:{port}"),
            (Some(dst), None) => dst.clone(),
            (None, _) => "unknown".to_string(),
        }
    }
}

/// Read kernel log entries since `since` (a journalctl time spec such as `-30min`)
/// and return those carrying `prefix`.
pub async fn read_drops(sys: &Sys, since: &str, prefix: &str) -> Result<Vec<DropEvent>> {
    let out = sys
        .capture(
            "journalctl",
            &["-k", "--no-pager", "-o", "json", "--since", since],
        )
        .await?;
    if !out.ok() {
        // journalctl missing or not permitted: the counters remain the primary signal.
        tracing::warn!(stderr = %out.stderr.trim(), "journalctl unavailable, egress detail degraded");
        return Ok(Vec::new());
    }
    Ok(parse_journal_json(&out.stdout, prefix))
}

/// Parse `journalctl -o json` output (one JSON object per line) into drop events.
pub fn parse_journal_json(text: &str, prefix: &str) -> Vec<DropEvent> {
    let mut events = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(message) = value.get("MESSAGE").and_then(|m| m.as_str()) else {
            continue;
        };
        if !message.contains(prefix) {
            continue;
        }
        if let Some(event) = parse_log_line(message) {
            events.push(event);
        }
    }
    events
}

/// Parse a single netfilter LOG message.
///
/// `hearth-egress-drop IN= OUT=eth0 SRC=10.66.10.10 DST=142.250.185.78 LEN=60 ...
///  PROTO=TCP SPT=54321 DPT=443 ...`
pub fn parse_log_line(message: &str) -> Option<DropEvent> {
    let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
    let mut prefix_parts: Vec<&str> = Vec::new();
    for token in message.split_whitespace() {
        match token.split_once('=') {
            Some((k, v)) => {
                fields.insert(k, v);
            }
            None => {
                if fields.is_empty() {
                    prefix_parts.push(token);
                }
            }
        }
    }
    if fields.is_empty() {
        return None;
    }
    let prefix = prefix_parts.join(" ");
    Some(DropEvent {
        prefix,
        src: fields.get("SRC").map(|s| s.to_string()),
        dst: fields.get("DST").map(|s| s.to_string()),
        proto: fields
            .get("PROTO")
            .map(|s| s.to_string())
            .unwrap_or_else(|| "UNKNOWN".to_string()),
        spt: fields.get("SPT").and_then(|s| s.parse().ok()),
        dpt: fields.get("DPT").and_then(|s| s.parse().ok()),
        out_iface: fields
            .get("OUT")
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string()),
    })
}

/// Aggregate events by destination, most packets first.
pub fn aggregate(events: &[DropEvent]) -> Vec<DropDestination> {
    let mut by_key: BTreeMap<(String, String), u64> = BTreeMap::new();
    for event in events {
        *by_key
            .entry((event.key(), event.proto.clone()))
            .or_insert(0) += 1;
    }
    let mut out: Vec<DropDestination> = by_key
        .into_iter()
        .map(|((dst, proto), packets)| DropDestination {
            dst,
            proto,
            packets,
        })
        .collect();
    out.sort_by(|a, b| b.packets.cmp(&a.packets).then_with(|| a.dst.cmp(&b.dst)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: &str = "hearth-egress-drop IN= OUT=eth0 SRC=10.66.10.10 DST=142.250.185.78 \
                        LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=4242 DF PROTO=TCP SPT=54321 \
                        DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0";

    #[test]
    fn parses_a_netfilter_log_line() {
        let event = parse_log_line(LINE).expect("parses");
        assert_eq!(event.prefix, "hearth-egress-drop");
        assert_eq!(event.dst.as_deref(), Some("142.250.185.78"));
        assert_eq!(event.dpt, Some(443));
        assert_eq!(event.proto, "TCP");
        assert_eq!(event.out_iface.as_deref(), Some("eth0"));
        assert_eq!(event.key(), "142.250.185.78:443");
    }

    #[test]
    fn filters_journal_by_prefix() {
        let text = format!(
            "{}\n{}\n{}\n",
            serde_json::json!({ "MESSAGE": LINE }),
            serde_json::json!({ "MESSAGE": "hearth-in-drop IN=eth0 SRC=10.0.0.1 DST=10.66.10.10 PROTO=TCP DPT=22" }),
            "not json at all",
        );
        let events = parse_journal_json(&text, "hearth-egress-drop");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].dpt, Some(443));

        let inbound = parse_journal_json(&text, "hearth-in-drop");
        assert_eq!(inbound.len(), 1);
        assert_eq!(inbound[0].dpt, Some(22));
    }

    #[test]
    fn aggregates_by_destination_and_sorts_by_volume() {
        let mut events = vec![parse_log_line(LINE).expect("parse"); 3];
        let mut other = parse_log_line(LINE).expect("parse");
        other.dst = Some("1.1.1.1".into());
        other.dpt = Some(53);
        other.proto = "UDP".into();
        events.push(other);

        let agg = aggregate(&events);
        assert_eq!(agg.len(), 2);
        assert_eq!(agg[0].dst, "142.250.185.78:443");
        assert_eq!(agg[0].packets, 3);
        assert_eq!(agg[1].dst, "1.1.1.1:53");
        assert_eq!(agg[1].proto, "UDP");
    }

    #[test]
    fn ignores_lines_without_fields() {
        assert!(parse_log_line("just a message").is_none());
    }
}

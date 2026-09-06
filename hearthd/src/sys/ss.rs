//! `ss` output parsing — the second half of the egress watchdog (ТЗ §7.3).
//!
//! Counters tell us that something was *blocked*. Established sockets tell us whether
//! anything got through before the rules were loaded, or through a path the rules do
//! not cover. Every five minutes we list TCP sockets and flag any relay socket whose
//! peer sits outside the home networks.

use std::net::IpAddr;

use crate::error::Result;
use crate::sys::Sys;

/// One socket line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketEntry {
    pub state: String,
    pub local: String,
    pub peer: String,
    /// Process names owning the socket (usually exactly one).
    pub processes: Vec<String>,
}

impl SocketEntry {
    /// Peer IP, when it is a real address (not `*` or a wildcard listener).
    pub fn peer_ip(&self) -> Option<IpAddr> {
        split_host_port(&self.peer).and_then(|(host, _)| host.parse().ok())
    }

    pub fn local_ip(&self) -> Option<IpAddr> {
        split_host_port(&self.local).and_then(|(host, _)| host.parse().ok())
    }

    pub fn is_established(&self) -> bool {
        self.state.eq_ignore_ascii_case("ESTAB") || self.state.eq_ignore_ascii_case("ESTABLISHED")
    }

    pub fn owned_by(&self, process: &str) -> bool {
        self.processes.iter().any(|p| p == process)
    }
}

/// List TCP sockets with owning processes: `ss -H -t -n -p -a`.
pub async fn list_tcp(sys: &Sys) -> Result<Vec<SocketEntry>> {
    let out = sys.run("ss", &["-H", "-t", "-n", "-p", "-a"]).await?;
    Ok(parse(&out.stdout))
}

/// Parse `ss -Htnpa` output. Tolerates a header line and missing process columns.
pub fn parse(text: &str) -> Vec<SocketEntry> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("State") || line.starts_with("Netid") {
            continue;
        }
        if let Some(entry) = parse_line(line) {
            entries.push(entry);
        }
    }
    entries
}

fn parse_line(line: &str) -> Option<SocketEntry> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 4 {
        return None;
    }
    // Layout: State Recv-Q Send-Q Local Peer [Process]
    // Recv-Q/Send-Q are numbers, so the two address columns are the first two fields
    // that look like host:port. Finding them positionally survives ss layout changes.
    let mut addr_idx = Vec::new();
    for (i, f) in fields.iter().enumerate() {
        if i == 0 {
            continue; // state
        }
        if split_host_port(f).is_some() {
            addr_idx.push(i);
        }
        if addr_idx.len() == 2 {
            break;
        }
    }
    if addr_idx.len() < 2 {
        return None;
    }
    let local = fields[addr_idx[0]].to_string();
    let peer = fields[addr_idx[1]].to_string();
    let processes = fields
        .iter()
        .skip(addr_idx[1] + 1)
        .filter(|f| f.starts_with("users:"))
        .flat_map(|f| parse_processes(f))
        .collect();
    Some(SocketEntry {
        state: fields[0].to_string(),
        local,
        peer,
        processes,
    })
}

/// Extract process names from `users:(("smp-server",pid=1234,fd=9),("x",pid=1,fd=2))`.
fn parse_processes(field: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = field;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        match after.find('"') {
            Some(end) => {
                let name = &after[..end];
                if !name.is_empty() {
                    names.push(name.to_string());
                }
                rest = &after[end + 1..];
            }
            None => break,
        }
    }
    names
}

/// Split `host:port`, handling `[::1]:5223` and the `*` wildcards `ss` prints for
/// listening sockets (`0.0.0.0:*`, `*:*`). A wildcard port is reported as `0`.
pub fn split_host_port(field: &str) -> Option<(String, u16)> {
    if let Some(rest) = field.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        let port = parse_port(rest.strip_prefix(':')?)?;
        return Some((host.to_string(), port));
    }
    let (host, port) = field.rsplit_once(':')?;
    if host.is_empty() || host.contains(':') {
        return None;
    }
    let port = parse_port(port)?;
    if host == "*" {
        return Some(("0.0.0.0".to_string(), port));
    }
    host.parse::<IpAddr>().ok()?;
    Some((host.to_string(), port))
}

fn parse_port(raw: &str) -> Option<u16> {
    if raw == "*" {
        return Some(0);
    }
    raw.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
LISTEN 0      1024   10.66.10.10:5223       0.0.0.0:*     users:((\"smp-server\",pid=812,fd=9))
LISTEN 0      1024   127.0.0.1:5224         0.0.0.0:*     users:((\"smp-server\",pid=812,fd=10))
ESTAB  0      0      10.66.10.10:5223       10.66.100.5:44321 users:((\"smp-server\",pid=812,fd=27))
ESTAB  0      0      10.66.10.10:47120      142.250.185.78:443 users:((\"smp-server\",pid=812,fd=31))
ESTAB  0      0      [::1]:7443             [::1]:51234   users:((\"hearthd\",pid=901,fd=12))
";

    #[test]
    fn parses_listeners_and_connections() {
        let entries = parse(SAMPLE);
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].state, "LISTEN");
        assert_eq!(entries[0].local, "10.66.10.10:5223");
        assert!(entries[0].owned_by("smp-server"));
        assert!(entries[2].is_established());
    }

    #[test]
    fn identifies_a_peer_outside_the_home_network() {
        let entries = parse(SAMPLE);
        let leak = entries
            .iter()
            .find(|e| e.is_established() && e.peer.starts_with("142.250"))
            .expect("sample has one foreign socket");
        assert_eq!(leak.peer_ip(), Some("142.250.185.78".parse().expect("ip")));
        assert!(leak.owned_by("smp-server"));
    }

    #[test]
    fn handles_ipv6_and_headers() {
        let entries = parse(&format!("State Recv-Q Send-Q Local Peer\n{SAMPLE}"));
        let v6 = entries.last().expect("entry");
        assert_eq!(v6.local_ip(), Some("::1".parse().expect("ip")));
        assert!(v6.owned_by("hearthd"));
    }

    #[test]
    fn skips_junk_lines() {
        assert!(parse("garbage\n\n").is_empty());
    }

    #[test]
    fn splits_host_port_forms() {
        assert_eq!(
            split_host_port("10.66.10.10:5223"),
            Some(("10.66.10.10".into(), 5223))
        );
        assert_eq!(
            split_host_port("[fe80::1]:443"),
            Some(("fe80::1".into(), 443))
        );
        assert_eq!(split_host_port("*:443"), Some(("0.0.0.0".into(), 443)));
        assert_eq!(split_host_port("0.0.0.0:*"), Some(("0.0.0.0".into(), 0)));
        assert_eq!(split_host_port("nonsense"), None);
        assert_eq!(split_host_port("example.com:443"), None);
    }

    #[test]
    fn parses_multiple_owning_processes() {
        let names = parse_processes("users:((\"smp-server\",pid=1,fd=2),(\"child\",pid=3,fd=4))");
        assert_eq!(names, vec!["smp-server".to_string(), "child".to_string()]);
    }
}

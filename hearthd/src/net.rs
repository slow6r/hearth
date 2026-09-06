//! Egress policy — the code-level twin of the nftables `output` chain (ТЗ §5.3, §7.4).
//!
//! `hearthd` must never open a connection to anything outside the home networks.
//! nftables enforces that in the kernel; this module enforces it *before* the
//! syscall, so a misconfiguration shows up as a loud application error instead of
//! a silent packet drop. Both layers exist on purpose: `Verify, don't trust` (ТЗ §2.1).
//!
//! Host **names** are rejected outright: the node has no resolver (ТЗ §5.2), so any
//! name that reached this code would be a bug or an injection attempt.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use ipnet::IpNet;
use tokio::net::TcpStream;

use crate::error::{Error, Result};

/// Networks `hearthd` is allowed to talk to. Everything else is denied.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    allowed: Vec<IpNet>,
}

impl EgressPolicy {
    pub fn new(allowed: Vec<IpNet>) -> Self {
        Self { allowed }
    }

    /// Allowed networks, for diagnostics.
    pub fn networks(&self) -> &[IpNet] {
        &self.allowed
    }

    /// Loopback is always permitted (control ports bind to 127.0.0.1, ТЗ §6.2).
    pub fn permits_ip(&self, ip: IpAddr) -> bool {
        ip.is_loopback() || self.allowed.iter().any(|net| net.contains(&ip))
    }

    /// Returns `Err(EgressDenied)` for any address outside the home networks.
    pub fn check(&self, addr: SocketAddr) -> Result<()> {
        if self.permits_ip(addr.ip()) {
            Ok(())
        } else {
            Err(Error::EgressDenied(addr.to_string()))
        }
    }

    /// Parse `host:port` where `host` MUST be an IP literal, then check the policy.
    pub fn check_target(&self, target: &str) -> Result<SocketAddr> {
        let addr: SocketAddr = target.parse().map_err(|_| {
            Error::EgressDenied(format!(
                "{target}: not an ip:port literal (the node has no DNS resolver)"
            ))
        })?;
        self.check(addr)?;
        Ok(addr)
    }

    /// Guarded TCP connect: policy check, then connect with a timeout.
    pub async fn connect(&self, addr: SocketAddr, timeout: Duration) -> Result<TcpStream> {
        self.check(addr)?;
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(Error::io(addr.to_string(), e)),
            Err(_) => Err(Error::Timeout(timeout)),
        }
    }

    /// TCP reachability probe used by the supervisor health checks.
    pub async fn probe(&self, addr: SocketAddr, timeout: Duration) -> bool {
        self.connect(addr, timeout).await.is_ok()
    }
}

/// `true` when the socket address is a wildcard bind (`0.0.0.0` / `[::]`).
///
/// Acceptance test A1 forbids wildcard binds on the node.
pub fn is_wildcard(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_unspecified(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> EgressPolicy {
        EgressPolicy::new(vec!["10.66.0.0/16".parse().expect("valid cidr")])
    }

    #[test]
    fn allows_home_networks_and_loopback() {
        let p = policy();
        assert!(p.permits_ip("10.66.10.10".parse().expect("ip")));
        assert!(p.permits_ip("10.66.100.5".parse().expect("ip")));
        assert!(p.permits_ip("127.0.0.1".parse().expect("ip")));
    }

    #[test]
    fn denies_everything_else() {
        let p = policy();
        assert!(!p.permits_ip("1.1.1.1".parse().expect("ip")));
        assert!(!p.permits_ip("192.168.1.10".parse().expect("ip")));
        assert!(!p.permits_ip("10.67.0.1".parse().expect("ip")));
        assert!(p.check("8.8.8.8:53".parse().expect("addr")).is_err());
    }

    #[test]
    fn rejects_hostnames_outright() {
        let p = policy();
        let err = p.check_target("gotify.example.com:80").unwrap_err();
        assert!(matches!(err, Error::EgressDenied(_)), "got {err:?}");
    }

    #[test]
    fn accepts_ip_literal_targets() {
        let p = policy();
        let addr = p.check_target("10.66.0.1:8080").expect("allowed");
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn wildcard_detection() {
        assert!(is_wildcard(&"0.0.0.0:5223".parse().expect("addr")));
        assert!(is_wildcard(&"[::]:5223".parse().expect("addr")));
        assert!(!is_wildcard(&"10.66.10.10:5223".parse().expect("addr")));
    }
}

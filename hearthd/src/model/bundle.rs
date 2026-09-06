//! Client bundle — ТЗ Приложение B.
//!
//! One JSON document that fully configures a client: relay addresses (with the CA
//! fingerprint and the queue-creation password baked in, exactly as upstream SimpleX
//! encodes them), ICE servers, and the network defaults the fork must not deviate
//! from. It is rendered as a QR code, shown only over the admin API inside WG, and
//! never written to disk by hearthd.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Максимальный размер JSON внутри QR (ТЗ Приложение B: ≤ 1 КБ).
pub const MAX_BUNDLE_BYTES: usize = 1024;

/// Bundle version. Bumping it is a breaking change for the Android importer.
pub const BUNDLE_VERSION: u32 = 1;

/// The full client configuration payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    /// Format version (`1`).
    pub v: u32,
    /// SMP relay addresses, `smp://<fp>:<pass>@host:port`.
    pub smp: Vec<String>,
    /// XFTP relay addresses, `xftp://<fp>:<pass>@host:port`.
    pub xftp: Vec<String>,
    /// ICE servers: our coturn only, никаких публичных STUN (ТЗ §6.4).
    pub ice: Vec<IceServer>,
    /// Network defaults the client must apply.
    pub net: NetPrefs,
    /// Issue time, RFC 3339 with second precision.
    #[serde(with = "super::rfc3339")]
    pub issued: DateTime<Utc>,
    /// Device id this bundle was minted for.
    pub device: String,
}

/// One ICE server entry, shaped like the WebRTC `RTCIceServer` dictionary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceServer {
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

/// Network preferences forced onto the client (ТЗ §8.2 п.3–5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetPrefs {
    /// SimpleX private message routing: `always`.
    #[serde(rename = "privateRouting")]
    pub private_routing: String,
    /// Upstream operator presets: disabled, forever.
    #[serde(rename = "presetsEnabled")]
    pub presets_enabled: bool,
    /// Notification mode: `instant` (foreground service, no push infrastructure).
    #[serde(rename = "ntfMode")]
    pub ntf_mode: String,
}

impl Default for NetPrefs {
    fn default() -> Self {
        Self {
            private_routing: "always".into(),
            presets_enabled: false,
            ntf_mode: "instant".into(),
        }
    }
}

impl Bundle {
    /// Serialize to compact JSON (what goes into the QR code).
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    /// Serialize to pretty JSON (what a human reads over the API).
    pub fn to_json_pretty(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn from_json(raw: &str) -> Result<Self> {
        Ok(serde_json::from_str(raw)?)
    }

    /// Full self-check. Everything a client would reject, hearthd rejects first.
    ///
    /// `node` is the address the whole контур is pinned to (ТЗ §2.5).
    pub fn validate(&self, node: IpAddr) -> Result<()> {
        if self.v != BUNDLE_VERSION {
            return Err(Error::invalid(format!(
                "bundle version {} is not supported (expected {BUNDLE_VERSION})",
                self.v
            )));
        }
        if self.smp.is_empty() {
            return Err(Error::invalid("bundle has no smp servers"));
        }
        for uri in &self.smp {
            ServerUri::parse(uri)?.check_scheme_and_host("smp", node)?;
        }
        for uri in &self.xftp {
            ServerUri::parse(uri)?.check_scheme_and_host("xftp", node)?;
        }
        if self.ice.is_empty() {
            return Err(Error::invalid("bundle has no ICE servers"));
        }
        for server in &self.ice {
            for url in &server.urls {
                check_ice_url(url, node)?;
            }
        }
        if self.net.private_routing != "always" {
            return Err(Error::invalid(
                "net.privateRouting must be `always` (ТЗ §8.2 п.5)",
            ));
        }
        if self.net.presets_enabled {
            return Err(Error::invalid(
                "net.presetsEnabled must be false (ТЗ §1.2: no federation with the public network)",
            ));
        }
        if self.net.ntf_mode != "instant" {
            return Err(Error::invalid(
                "net.ntfMode must be `instant` (ТЗ §8.2 п.4: no push infrastructure)",
            ));
        }
        if self.device.trim().is_empty() {
            return Err(Error::invalid("bundle has no device id"));
        }
        let size = self.to_json()?.len();
        if size > MAX_BUNDLE_BYTES {
            return Err(Error::invalid(format!(
                "bundle is {size} bytes, over the {MAX_BUNDLE_BYTES} byte QR budget"
            )));
        }
        Ok(())
    }
}

/// A parsed SimpleX server address: `<scheme>://<fingerprint>[:<password>]@<host>:<port>`.
///
/// hearthd only *composes* and *checks* these; the format itself belongs to upstream
/// and must never be modified (ТЗ §8.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerUri {
    pub scheme: String,
    pub fingerprint: String,
    pub password: Option<String>,
    pub host: String,
    pub port: u16,
}

impl ServerUri {
    /// Build an address out of its parts.
    pub fn new(
        scheme: &str,
        fingerprint: &str,
        password: Option<&str>,
        host: IpAddr,
        port: u16,
    ) -> Result<Self> {
        if fingerprint.trim().is_empty() {
            return Err(Error::invalid("server fingerprint is empty"));
        }
        if fingerprint.contains([':', '@', '/']) {
            return Err(Error::invalid(format!(
                "server fingerprint contains a separator: {fingerprint}"
            )));
        }
        if let Some(pass) = password {
            if pass.contains([':', '@', '/']) {
                return Err(Error::invalid(
                    "server password contains a separator (:, @ or /)",
                ));
            }
        }
        Ok(Self {
            scheme: scheme.to_string(),
            fingerprint: fingerprint.to_string(),
            password: password.map(str::to_string),
            host: host.to_string(),
            port,
        })
    }

    pub fn parse(raw: &str) -> Result<Self> {
        let (scheme, rest) = raw
            .split_once("://")
            .ok_or_else(|| Error::invalid(format!("server address without scheme: {raw}")))?;
        let (auth, hostport) = rest
            .rsplit_once('@')
            .ok_or_else(|| Error::invalid(format!("server address without fingerprint: {raw}")))?;
        let (fingerprint, password) = match auth.split_once(':') {
            Some((fp, pass)) => (fp, Some(pass.to_string())),
            None => (auth, None),
        };
        let (host, port) = hostport
            .rsplit_once(':')
            .ok_or_else(|| Error::invalid(format!("server address without port: {raw}")))?;
        let port: u16 = port
            .parse()
            .map_err(|_| Error::invalid(format!("bad port in server address: {raw}")))?;
        if fingerprint.is_empty() {
            return Err(Error::invalid(format!("empty fingerprint in {raw}")));
        }
        Ok(Self {
            scheme: scheme.to_string(),
            fingerprint: fingerprint.to_string(),
            password,
            host: host.to_string(),
            port,
        })
    }

    /// The address must use the expected scheme and point at our node by IP literal.
    ///
    /// A hostname here would mean the client needs DNS — which the контур does not
    /// have (ТЗ §5.2) and which would reintroduce a MITM surface.
    pub fn check_scheme_and_host(&self, scheme: &str, node: IpAddr) -> Result<()> {
        if self.scheme != scheme {
            return Err(Error::invalid(format!(
                "expected scheme {scheme}, got {}",
                self.scheme
            )));
        }
        let host: IpAddr = self.host.parse().map_err(|_| {
            Error::invalid(format!(
                "server host `{}` is not an IP literal (ТЗ §5.2: the контур has no DNS)",
                self.host
            ))
        })?;
        if host != node {
            return Err(Error::invalid(format!(
                "server host {host} is not the node address {node}"
            )));
        }
        if self.password.is_none() {
            return Err(Error::invalid(format!(
                "{scheme} address has no creation password (ТЗ §6.2: password is mandatory)"
            )));
        }
        Ok(())
    }
}

impl std::fmt::Display for ServerUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.password {
            Some(pass) => write!(
                f,
                "{}://{}:{}@{}:{}",
                self.scheme, self.fingerprint, pass, self.host, self.port
            ),
            None => write!(
                f,
                "{}://{}@{}:{}",
                self.scheme, self.fingerprint, self.host, self.port
            ),
        }
    }
}

/// ICE URLs must be `stun:`/`turn:` on our own node — a public STUN would leak the
/// client's real address to a third party (ТЗ §6.4).
fn check_ice_url(url: &str, node: IpAddr) -> Result<()> {
    let rest = url
        .strip_prefix("stun:")
        .or_else(|| url.strip_prefix("turn:"))
        .or_else(|| url.strip_prefix("turns:"))
        .ok_or_else(|| Error::invalid(format!("unsupported ICE url: {url}")))?;
    let host = rest.split(['?', ':']).next().unwrap_or(rest);
    let host: IpAddr = host
        .parse()
        .map_err(|_| Error::invalid(format!("ICE url host is not an IP literal: {url}")))?;
    if host != node {
        return Err(Error::invalid(format!(
            "ICE url {url} does not point at the node address {node}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn node() -> IpAddr {
        "10.66.10.10".parse().expect("ip")
    }

    fn sample() -> Bundle {
        Bundle {
            v: 1,
            smp: vec!["smp://fp1:pass1@10.66.10.10:5223".into()],
            xftp: vec!["xftp://fp2:pass2@10.66.10.10:5443".into()],
            ice: vec![
                IceServer {
                    urls: vec!["stun:10.66.10.10:3478".into()],
                    username: None,
                    credential: None,
                },
                IceServer {
                    urls: vec!["turn:10.66.10.10:3478".into()],
                    username: Some("1757160000:hearth".into()),
                    credential: Some("aGVhcnRo".into()),
                },
            ],
            net: NetPrefs::default(),
            issued: Utc
                .with_ymd_and_hms(2026, 9, 6, 12, 0, 0)
                .single()
                .expect("ts"),
            device: "mama-pixel8".into(),
        }
    }

    #[test]
    fn matches_appendix_b_shape() {
        let json = sample().to_json().expect("json");
        // Key names and order follow ТЗ Приложение B literally.
        assert!(json.starts_with(r#"{"v":1,"smp":["smp://fp1:pass1@10.66.10.10:5223"]"#));
        assert!(json.contains(r#""privateRouting":"always""#));
        assert!(json.contains(r#""presetsEnabled":false"#));
        assert!(json.contains(r#""ntfMode":"instant""#));
        assert!(json.contains(r#""issued":"2026-09-06T12:00:00Z""#));
        assert!(json.contains(r#""device":"mama-pixel8""#));
    }

    #[test]
    fn round_trips() {
        let bundle = sample();
        let parsed = Bundle::from_json(&bundle.to_json().expect("json")).expect("parse");
        assert_eq!(bundle, parsed);
    }

    #[test]
    fn valid_bundle_passes() {
        sample().validate(node()).expect("valid");
    }

    #[test]
    fn rejects_public_stun() {
        let mut b = sample();
        b.ice[0].urls = vec!["stun:stun.l.google.com:19302".into()];
        assert!(b.validate(node()).is_err());
    }

    #[test]
    fn rejects_foreign_relay() {
        let mut b = sample();
        b.smp = vec!["smp://fp:pass@smp8.simplex.im:5223".into()];
        let err = b.validate(node()).unwrap_err();
        assert!(err.to_string().contains("not an IP literal"), "got {err}");
    }

    #[test]
    fn rejects_missing_relay_password() {
        let mut b = sample();
        b.smp = vec!["smp://fp1@10.66.10.10:5223".into()];
        let err = b.validate(node()).unwrap_err();
        assert!(err.to_string().contains("creation password"), "got {err}");
    }

    #[test]
    fn rejects_presets_enabled() {
        let mut b = sample();
        b.net.presets_enabled = true;
        assert!(b.validate(node()).is_err());
    }

    #[test]
    fn rejects_non_instant_notifications() {
        let mut b = sample();
        b.net.ntf_mode = "periodic".into();
        assert!(b.validate(node()).is_err());
    }

    #[test]
    fn enforces_qr_size_budget() {
        let mut b = sample();
        b.smp = (0..40)
            .map(|i| format!("smp://fingerprint{i}:password{i}@10.66.10.10:5223"))
            .collect();
        let err = b.validate(node()).unwrap_err();
        assert!(err.to_string().contains("QR budget"), "got {err}");
    }

    #[test]
    fn server_uri_round_trip() {
        let uri = ServerUri::new("smp", "abc", Some("secret"), node(), 5223).expect("uri");
        assert_eq!(uri.to_string(), "smp://abc:secret@10.66.10.10:5223");
        let parsed = ServerUri::parse("smp://abc:secret@10.66.10.10:5223").expect("parse");
        assert_eq!(parsed, uri);
    }

    #[test]
    fn server_uri_rejects_injected_separators() {
        assert!(ServerUri::new("smp", "abc", Some("pa@ss"), node(), 5223).is_err());
        assert!(ServerUri::new("smp", "a:b", Some("pass"), node(), 5223).is_err());
    }
}

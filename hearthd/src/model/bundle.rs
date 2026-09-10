//! Client bundle — one QR that configures a client (ТЗ Приложение B).
//!
//! Relay addresses, ICE servers and the network defaults the fork must not deviate
//! from. Minted on demand, never written to disk by hearthd: it carries relay passwords.
//!
//! # Formats come from upstream, not from us
//!
//! Both string formats in here are upstream's, verified against simplexmq/simplex-chat
//! v7.0.1 — this project never invents an address format (ТЗ §8.3):
//!
//! * relays: `smp://<fingerprint>:<password>@host:port`
//!   (`Server/Main/Init.hs`: "smp://fingerprint:password@host1,host2")
//! * ICE: `scheme:[user:credential@]host:port[?query]`
//!   (`views/call/WebRTC.kt` `parseRTCIceServer`, e.g.
//!   `turns:private2:Hxuq...@turn.simplex.im:443?transport=tcp`)
//!
//! The ICE entry is a **string**, not a `{urls, username, credential}` object: that
//! object is the WebRTC dictionary the client builds internally, but what it parses
//! from configuration is the string form.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Maximum JSON size inside a QR code (ТЗ Приложение B: ≤ 1 KB).
pub const MAX_BUNDLE_BYTES: usize = 1024;

/// Bundle version. Bumping it is a breaking change for the client importer.
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
    /// ICE servers in upstream's string form. Our own STUN/TURN only — a public STUN
    /// would hand the participant's address to a third party (ТЗ §6.4).
    pub ice: Vec<String>,
    /// Network defaults the client must apply.
    pub net: NetPrefs,
    /// Issue time, RFC 3339 with second precision.
    #[serde(with = "super::rfc3339")]
    pub issued: DateTime<Utc>,
    /// Device id this bundle was minted for.
    pub device: String,
    /// Device API узла: откуда брать обновления и свежие TURN-креды.
    ///
    /// `None` — узел без device API; клиент тогда живёт как раньше, но звонки у него
    /// сломаются при следующей ротации TURN-секрета, и bundle придётся выдать заново.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<NodeApi>,
}

/// Адрес device API и токен этого устройства.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeApi {
    /// Тот же хост, что и в адресе релея. Клиент обязан брать адрес отсюда, а не из
    /// документов, которые этот же API потом отдаёт: иначе подменённый ответ увёл бы
    /// устройство на чужой сервер.
    pub host: String,
    pub port: u16,
    /// Секрет этого устройства. Уходит заголовком, не в URL: URL оседает в логах.
    pub token: String,
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
    /// `host` is the public name or address the node is published under — the one
    /// constant every client depends on (ТЗ §2.5).
    pub fn validate(&self, host: &str) -> Result<()> {
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
            ServerUri::parse(uri)?.check(host, "smp")?;
        }
        for uri in &self.xftp {
            ServerUri::parse(uri)?.check(host, "xftp")?;
        }
        if self.ice.is_empty() {
            return Err(Error::invalid(
                "bundle has no ICE servers; calls would silently fall back to nothing",
            ));
        }
        for entry in &self.ice {
            IceUri::parse(entry)?.check(host)?;
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
/// hearthd only *composes* and *checks* these; the format belongs to upstream and must
/// never be modified (ТЗ §8.3).
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
        host: &str,
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
            // Upstream: "any printable ASCII characters without whitespace, '@', ':' and '/'"
            if pass.is_empty() {
                return Err(Error::invalid("server password is empty"));
            }
            if pass.contains([':', '@', '/']) || pass.chars().any(char::is_whitespace) {
                return Err(Error::invalid(
                    "server password must not contain whitespace, ':', '@' or '/'",
                ));
            }
        }
        if host.trim().is_empty() {
            return Err(Error::invalid("server host is empty"));
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
            password: password.filter(|p| !p.is_empty()),
            host: host.to_string(),
            port,
        })
    }

    /// The address must use the expected scheme, point at our node, and carry the
    /// queue-creation password (ТЗ §6.2 — without it the relay is open to anyone).
    pub fn check(&self, host: &str, scheme: &str) -> Result<()> {
        if self.scheme != scheme {
            return Err(Error::invalid(format!(
                "expected scheme {scheme}, got {}",
                self.scheme
            )));
        }
        if !self.host.eq_ignore_ascii_case(host) {
            return Err(Error::invalid(format!(
                "server host `{}` is not this node's published host `{host}`",
                self.host
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

/// An ICE server entry in the form the client parses:
/// `scheme:[user:credential@]host:port[?query]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceUri {
    pub scheme: String,
    pub username: Option<String>,
    pub credential: Option<String>,
    pub host: String,
    pub port: u16,
    pub query: Option<String>,
}

impl IceUri {
    /// Build a STUN entry (no credentials).
    pub fn stun(host: &str, port: u16, tls: bool) -> Self {
        Self {
            scheme: if tls { "stuns".into() } else { "stun".into() },
            username: None,
            credential: None,
            host: host.to_string(),
            port,
            query: None,
        }
    }

    /// Build a TURN entry with REST credentials.
    pub fn turn(
        host: &str,
        port: u16,
        tls: bool,
        username: &str,
        credential: &str,
        transport: Option<&str>,
    ) -> Result<Self> {
        // The credential is base64 and may contain '+', '/' and '='. A '/' would end
        // the authority section, and '@' or ':' would shift the field boundaries.
        if username.contains(['@', '/']) || credential.contains(['@', '/']) {
            return Err(Error::invalid(
                "TURN credentials must not contain '@' or '/'",
            ));
        }
        Ok(Self {
            scheme: if tls { "turns".into() } else { "turn".into() },
            username: Some(username.to_string()),
            credential: Some(credential.to_string()),
            host: host.to_string(),
            port,
            query: transport.map(|t| format!("transport={t}")),
        })
    }

    pub fn parse(raw: &str) -> Result<Self> {
        let (scheme, rest) = raw
            .split_once(':')
            .ok_or_else(|| Error::invalid(format!("ICE entry without scheme: {raw}")))?;
        if !matches!(scheme, "stun" | "stuns" | "turn" | "turns") {
            return Err(Error::invalid(format!("unsupported ICE scheme: {raw}")));
        }
        let (rest, query) = match rest.split_once('?') {
            Some((head, q)) => (head, Some(q.to_string())),
            None => (rest, None),
        };
        let (userinfo, hostport) = match rest.rsplit_once('@') {
            Some((info, hp)) => (Some(info), hp),
            None => (None, rest),
        };
        let (username, credential) = match userinfo {
            Some(info) => match info.split_once(':') {
                Some((u, c)) => (Some(u.to_string()), Some(c.to_string())),
                None => (Some(info.to_string()), None),
            },
            None => (None, None),
        };
        let (host, port) = hostport
            .rsplit_once(':')
            .ok_or_else(|| Error::invalid(format!("ICE entry without port: {raw}")))?;
        let port: u16 = port
            .parse()
            .map_err(|_| Error::invalid(format!("bad port in ICE entry: {raw}")))?;
        if host.is_empty() {
            return Err(Error::invalid(format!("ICE entry without host: {raw}")));
        }
        Ok(Self {
            scheme: scheme.to_string(),
            username,
            credential,
            host: host.to_string(),
            port,
            query,
        })
    }

    /// ICE must point at our own node. A public STUN would tell a third party who is
    /// calling whom and from where (ТЗ §6.4).
    pub fn check(&self, host: &str) -> Result<()> {
        if !self.host.eq_ignore_ascii_case(host) {
            return Err(Error::invalid(format!(
                "ICE host `{}` is not this node's published host `{host}` \
                 (a public STUN/TURN would leak the caller's address)",
                self.host
            )));
        }
        if self.scheme.starts_with("turn") && self.credential.is_none() {
            return Err(Error::invalid(format!(
                "TURN entry without credentials: {self}"
            )));
        }
        Ok(())
    }
}

impl std::fmt::Display for IceUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:", self.scheme)?;
        if let Some(user) = &self.username {
            match &self.credential {
                Some(cred) => write!(f, "{user}:{cred}@")?,
                None => write!(f, "{user}@")?,
            }
        }
        write!(f, "{}:{}", self.host, self.port)?;
        if let Some(query) = &self.query {
            write!(f, "?{query}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    const HOST: &str = "relay.example.org";

    fn sample() -> Bundle {
        Bundle {
            v: 1,
            smp: vec![format!("smp://fp1:pass1@{HOST}:5223")],
            xftp: vec![format!("xftp://fp2:pass2@{HOST}:5443")],
            ice: vec![
                format!("stun:{HOST}:3478"),
                format!("turn:1757160000%3Ahearth:aGVhcnRo@{HOST}:3478?transport=udp"),
            ],
            net: NetPrefs::default(),
            issued: Utc
                .with_ymd_and_hms(2026, 9, 6, 12, 0, 0)
                .single()
                .expect("ts"),
            device: "mama-pixel8".into(),
            node: None,
        }
    }

    #[test]
    fn valid_bundle_passes() {
        sample().validate(HOST).expect("valid");
    }

    #[test]
    fn round_trips() {
        let bundle = sample();
        let parsed = Bundle::from_json(&bundle.to_json().expect("json")).expect("parse");
        assert_eq!(bundle, parsed);
    }

    #[test]
    fn ice_entries_use_the_form_the_client_parses() {
        // Verified against simplex-chat v7.0.1 WebRTC.kt parseRTCIceServer:
        //   turns:private2:Hxuq2QxUjnhj96Zq2r4HjqHRj@turn.simplex.im:443?transport=tcp
        let entry =
            IceUri::turn(HOST, 443, true, "user1", "Y3JlZA==", Some("tcp")).expect("turn entry");
        assert_eq!(
            entry.to_string(),
            format!("turns:user1:Y3JlZA==@{HOST}:443?transport=tcp")
        );
        let parsed = IceUri::parse(&entry.to_string()).expect("parse");
        assert_eq!(parsed, entry);

        let stun = IceUri::stun(HOST, 3478, false);
        assert_eq!(stun.to_string(), format!("stun:{HOST}:3478"));
        assert_eq!(IceUri::parse(&stun.to_string()).expect("parse"), stun);
    }

    #[test]
    fn rejects_public_stun() {
        let mut b = sample();
        b.ice[0] = "stun:stun.simplex.im:443".into();
        let err = b.validate(HOST).unwrap_err();
        assert!(err.to_string().contains("leak the caller"), "got {err}");
    }

    #[test]
    fn rejects_foreign_relay() {
        let mut b = sample();
        b.smp = vec!["smp://fp:pass@smp8.simplex.im:5223".into()];
        let err = b.validate(HOST).unwrap_err();
        assert!(err.to_string().contains("published host"), "got {err}");
    }

    #[test]
    fn rejects_missing_relay_password() {
        let mut b = sample();
        b.smp = vec![format!("smp://fp1@{HOST}:5223")];
        let err = b.validate(HOST).unwrap_err();
        assert!(err.to_string().contains("creation password"), "got {err}");
    }

    #[test]
    fn rejects_turn_without_credentials() {
        let mut b = sample();
        b.ice[1] = format!("turn:{HOST}:3478");
        assert!(b.validate(HOST).is_err());
    }

    #[test]
    fn rejects_no_ice_at_all() {
        let mut b = sample();
        b.ice.clear();
        let err = b.validate(HOST).unwrap_err();
        assert!(err.to_string().contains("no ICE servers"), "got {err}");
    }

    #[test]
    fn rejects_presets_enabled() {
        let mut b = sample();
        b.net.presets_enabled = true;
        assert!(b.validate(HOST).is_err());
    }

    #[test]
    fn rejects_non_instant_notifications() {
        let mut b = sample();
        b.net.ntf_mode = "periodic".into();
        assert!(b.validate(HOST).is_err());
    }

    #[test]
    fn enforces_qr_size_budget() {
        let mut b = sample();
        b.smp = (0..40)
            .map(|i| format!("smp://fingerprint{i}:password{i}@{HOST}:5223"))
            .collect();
        let err = b.validate(HOST).unwrap_err();
        assert!(err.to_string().contains("QR budget"), "got {err}");
    }

    #[test]
    fn server_uri_round_trip() {
        let uri = ServerUri::new("smp", "abc", Some("secret"), HOST, 5223).expect("uri");
        assert_eq!(uri.to_string(), format!("smp://abc:secret@{HOST}:5223"));
        assert_eq!(ServerUri::parse(&uri.to_string()).expect("parse"), uri);
    }

    #[test]
    fn server_uri_rejects_characters_upstream_forbids() {
        // Upstream: "any printable ASCII characters without whitespace, '@', ':' and '/'"
        assert!(ServerUri::new("smp", "abc", Some("pa@ss"), HOST, 5223).is_err());
        assert!(ServerUri::new("smp", "abc", Some("pa ss"), HOST, 5223).is_err());
        assert!(ServerUri::new("smp", "a:b", Some("pass"), HOST, 5223).is_err());
    }

    #[test]
    fn accepts_a_bare_ip_host_too() {
        let mut b = sample();
        b.smp = vec!["smp://fp1:pass1@203.0.113.10:5223".into()];
        b.xftp = vec!["xftp://fp2:pass2@203.0.113.10:5443".into()];
        b.ice = vec!["stun:203.0.113.10:3478".into()];
        b.validate("203.0.113.10").expect("an IP host is fine too");
    }
}

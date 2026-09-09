//! coturn REST credentials and static-secret rotation (ТЗ §6.4).
//!
//! coturn's `use-auth-secret` scheme ("TURN REST API"):
//!
//! ```text
//! username   = <unix-expiry>[:<userid>]
//! credential = base64( HMAC-SHA1( static-secret, username ) )
//! ```
//!
//! # Why the credential is not simply whatever the HMAC produced
//!
//! The client stores ICE servers as one string and parses it like this
//! (simplex-chat v7.0.1, `views/call/WebRTC.kt`):
//!
//! ```text
//! turn:USER:CRED@host:port  ->  URI(...)  ->  userInfo.split(":")
//!                                              [0] = username, [1] = credential
//!   ... and the entry is accepted only if u.path == ""
//! ```
//!
//! Three consequences, all of which this module has to respect:
//!
//! * the **username must not contain `:`** — so the bare expiry timestamp is used as
//!   the username, never coturn's optional `<expiry>:<userid>` form;
//! * the **credential must not contain `/`** — standard base64 emits it, and a `/`
//!   would start the URI path, making `u.path == ""` false;
//! * a rejected entry makes `parseRTCIceServers` return `null` for the **whole list**,
//!   and the client then falls back to its built-in **public** STUN/TURN. A malformed
//!   credential would therefore not break calls loudly — it would quietly route them
//!   through a third party, which is precisely what this contour exists to avoid.
//!
//! So [`credential`] searches forward from the requested expiry for the first second
//! whose HMAC is URI-safe. coturn recomputes the HMAC from the username the client
//! sends, so any such timestamp validates normally.

use base64::Engine as _;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::config::Turn;
use crate::error::{Error, Result};
use crate::model::bundle::IceUri;
use crate::store;
use crate::sys::{systemd, Sys};

type HmacSha1 = Hmac<Sha1>;

/// How many one-second steps to try before giving up on a URI-safe credential.
/// About 65% of candidates are safe, so this is astronomically generous.
const MAX_EXPIRY_SHIFT: i64 = 64;

/// A time-limited TURN credential, guaranteed safe to embed in an ICE URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnCredential {
    pub username: String,
    pub credential: String,
    pub expires: DateTime<Utc>,
}

/// Derive a credential valid until roughly `now + ttl_secs`.
pub fn credential(secret: &str, ttl_secs: u64, now: DateTime<Utc>) -> Result<TurnCredential> {
    if secret.is_empty() {
        return Err(Error::Config("turn secret is empty".into()));
    }
    let base = now.timestamp().saturating_add(ttl_secs as i64);

    for shift in 0..MAX_EXPIRY_SHIFT {
        let expiry = base.saturating_add(shift);
        let username = expiry.to_string();
        let credential = sign(secret, &username)?;
        if is_uri_safe(&credential) {
            return Ok(TurnCredential {
                username,
                credential,
                expires: DateTime::from_timestamp(expiry, 0).unwrap_or(now),
            });
        }
    }
    Err(Error::Crypto(
        "could not derive a URI-safe TURN credential; rotate the static secret".into(),
    ))
}

fn sign(secret: &str, username: &str) -> Result<String> {
    let mut mac = HmacSha1::new_from_slice(secret.as_bytes())
        .map_err(|e| Error::Crypto(format!("hmac key: {e}")))?;
    mac.update(username.as_bytes());
    Ok(base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes()))
}

/// `/` would start a URI path and make the client discard the entry.
/// `+` and `=` are sub-delims and are accepted in userinfo, so they may stay.
fn is_uri_safe(credential: &str) -> bool {
    !credential.contains(['/', ':', '@', '?', '#'])
}

/// The ICE entries a client gets: our STUN and our TURN, nothing else.
///
/// A public STUN would hand the caller's real address to a third party (ТЗ §6.4), and
/// there is deliberately no fallback: if this list is wrong, calls must fail visibly.
pub fn ice_servers(cfg: &Turn, host: &str, cred: &TurnCredential) -> Result<Vec<String>> {
    let mut entries = vec![
        IceUri::stun(host, cfg.port, false).to_string(),
        IceUri::turn(
            host,
            cfg.port,
            false,
            &cred.username,
            &cred.credential,
            None,
        )?
        .to_string(),
    ];
    // TLS on its own port, when a certificate is configured. `transport=tcp` is what
    // gets a call out of a network that only permits TCP/443.
    if let Some(tls_port) = cfg.tls_port {
        entries.push(IceUri::stun(host, tls_port, true).to_string());
        entries.push(
            IceUri::turn(
                host,
                tls_port,
                true,
                &cred.username,
                &cred.credential,
                Some("tcp"),
            )?
            .to_string(),
        );
    }
    Ok(entries)
}

/// Render `turnserver.conf` from the template.
///
/// Placeholders: `{{TURN_SECRET}}`, `{{REALM}}`, `{{PORT}}`, `{{TLS_PORT_LINE}}`,
/// `{{MIN_PORT}}`, `{{MAX_PORT}}`.
pub fn render_config(template: &str, secret: &str, cfg: &Turn) -> Result<String> {
    if !template.contains("{{TURN_SECRET}}") {
        return Err(Error::Config(
            "turnserver template has no {{TURN_SECRET}} placeholder".into(),
        ));
    }
    // coturn refuses to open a TLS listener without a certificate, and does so quietly.
    // Config::validate already rejects a port without cert/key, so by the time we get
    // here the three either all exist or none do.
    let tls_line = match (cfg.tls_port, &cfg.tls_cert, &cfg.tls_key) {
        (Some(port), Some(cert), Some(key)) => format!(
            "tls-listening-port={port}\ncert={}\npkey={}",
            cert.display(),
            key.display()
        ),
        _ => "no-tls\nno-dtls".to_string(),
    };
    let rendered = template
        .replace("{{TURN_SECRET}}", secret)
        .replace("{{REALM}}", &cfg.realm)
        .replace("{{PORT}}", &cfg.port.to_string())
        .replace("{{TLS_PORT_LINE}}", &tls_line)
        .replace("{{MIN_PORT}}", &cfg.relay_min_port.to_string())
        .replace("{{MAX_PORT}}", &cfg.relay_max_port.to_string());
    if rendered.contains("{{") {
        return Err(Error::Config(
            "turnserver template still contains unresolved placeholders".into(),
        ));
    }
    Ok(rendered)
}

/// Rotate the static secret: new secret, re-render the config, restart coturn.
///
/// Every credential minted from the old secret stops validating at once, so bundles
/// must be re-issued afterwards. That is why this is monthly, not hourly.
pub async fn rotate_secret(sys: &Sys, cfg: &Turn) -> Result<()> {
    let template = std::fs::read_to_string(&cfg.config_template)
        .map_err(|e| Error::io(&cfg.config_template, e))?;
    let secret = store::random_hex(32);
    let rendered = render_config(&template, &secret, cfg)?;

    store::write_secret(&cfg.secret_file, &secret)?;
    // MODE_SHARED_SECRET, not MODE_SECRET: coturn reads this file as `turnserver`, and
    // 0600 owned by `hearth` locks out the one process that needs it. See the constant.
    store::write_atomic(
        &cfg.config_file,
        rendered.as_bytes(),
        store::MODE_SHARED_SECRET,
    )?;
    systemd::restart(sys, &cfg.unit).await?;
    tracing::info!(unit = %cfg.unit, "turn static secret rotated");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    const HOST: &str = "relay.example.org";

    fn turn_cfg() -> Turn {
        Turn {
            enabled: true,
            unit: "coturn.service".into(),
            port: 3478,
            tls_port: None,
            tls_cert: None,
            tls_key: None,
            relay_min_port: 49160,
            relay_max_port: 49200,
            realm: "hearth".into(),
            secret_file: "/etc/hearth/secrets/turn-secret".into(),
            config_template: "/etc/hearth/templates/turnserver.conf.tmpl".into(),
            config_file: "/etc/turnserver.conf".into(),
            credential_ttl_secs: 2_592_000,
            rotate_days: 30,
        }
    }

    fn at(ts: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(ts, 0).single().expect("ts")
    }

    #[test]
    fn credential_matches_the_coturn_rest_scheme() {
        let cred = credential("hearth-secret", 3600, at(1_757_160_000)).expect("cred");
        // Username is the bare expiry: coturn accepts it, and it carries no ':' that
        // would confuse the client's userInfo.split(":").
        assert!(cred.username.chars().all(|c| c.is_ascii_digit()));
        assert!(cred.expires.timestamp() >= 1_757_163_600);

        // Exactly what coturn will recompute from the username it receives.
        let expected = sign("hearth-secret", &cred.username).expect("sign");
        assert_eq!(cred.credential, expected);
    }

    #[test]
    fn credentials_are_always_uri_safe() {
        // Across many secrets the search must always find a usable timestamp.
        for i in 0..500 {
            let secret = format!("secret-{i}");
            let cred = credential(&secret, 60, at(1_000_000 + i)).expect("cred");
            assert!(
                is_uri_safe(&cred.credential),
                "credential {} is not URI-safe",
                cred.credential
            );
            // And it must survive a round trip through the client's parser shape.
            let uri = IceUri::turn(HOST, 3478, false, &cred.username, &cred.credential, None)
                .expect("uri");
            let parsed = IceUri::parse(&uri.to_string()).expect("parse");
            assert_eq!(parsed.username.as_deref(), Some(cred.username.as_str()));
            assert_eq!(parsed.credential.as_deref(), Some(cred.credential.as_str()));
        }
    }

    #[test]
    fn rejects_credentials_a_client_would_discard() {
        assert!(!is_uri_safe("abc/def"));
        assert!(!is_uri_safe("abc:def"));
        assert!(is_uri_safe("abc+def=="));
    }

    #[test]
    fn credentials_change_with_time_and_secret() {
        let a = credential("s1", 60, at(1_000_000)).expect("cred");
        let b = credential("s1", 60, at(1_000_600)).expect("cred");
        let c = credential("s2", 60, at(1_000_000)).expect("cred");
        assert_ne!(a.credential, b.credential);
        assert_ne!(a.credential, c.credential);
    }

    #[test]
    fn empty_secret_is_refused() {
        assert!(credential("", 60, Utc::now()).is_err());
    }

    #[test]
    fn ice_servers_point_only_at_our_node() {
        let cred = credential("secret", 60, at(1_000_000)).expect("cred");
        let servers = ice_servers(&turn_cfg(), HOST, &cred).expect("ice");
        assert_eq!(servers.len(), 2, "stun + turn on the plain port");
        assert_eq!(servers[0], format!("stun:{HOST}:3478"));
        assert!(servers[1].starts_with("turn:"));
        assert!(servers.iter().all(|s| s.contains(HOST)));
    }

    #[test]
    fn tls_port_adds_the_turns_entries() {
        let mut cfg = turn_cfg();
        cfg.tls_port = Some(5349);
        cfg.tls_cert = Some("/etc/ssl/relay.pem".into());
        cfg.tls_key = Some("/etc/ssl/relay.key".into());
        let cred = credential("secret", 60, at(1_000_000)).expect("cred");
        let servers = ice_servers(&cfg, HOST, &cred).expect("ice");
        assert_eq!(servers.len(), 4);
        assert!(servers.iter().any(|s| s == &format!("stuns:{HOST}:5349")));
        assert!(servers
            .iter()
            .any(|s| s.starts_with("turns:") && s.ends_with("?transport=tcp")));
    }

    #[test]
    fn renders_the_template() {
        let template = "listening-port={{PORT}}\n{{TLS_PORT_LINE}}\nrealm={{REALM}}\n\
                        static-auth-secret={{TURN_SECRET}}\nmin-port={{MIN_PORT}}\n\
                        max-port={{MAX_PORT}}\n";
        let out = render_config(template, "deadbeef", &turn_cfg()).expect("render");
        assert!(out.contains("listening-port=3478"));
        assert!(out.contains("static-auth-secret=deadbeef"));
        assert!(out.contains("min-port=49160"));
        // Without a certificate, TLS is switched off rather than left half-configured.
        assert!(out.contains("no-tls"));
        assert!(!out.contains("{{"));

        // With a certificate: a real TLS listener, cert and key included. Without them
        // coturn would start and quietly open no TLS listener at all, which is why
        // Config::validate refuses that combination in the first place.
        let mut cfg = turn_cfg();
        cfg.tls_port = Some(5349);
        cfg.tls_cert = Some("/etc/letsencrypt/live/relay/fullchain.pem".into());
        cfg.tls_key = Some("/etc/letsencrypt/live/relay/privkey.pem".into());
        let out = render_config(template, "deadbeef", &cfg).expect("render");
        assert!(out.contains("tls-listening-port=5349"));
        assert!(out.contains("cert=/etc/letsencrypt/live/relay/fullchain.pem"));
        assert!(out.contains("pkey=/etc/letsencrypt/live/relay/privkey.pem"));
        assert!(!out.contains("no-tls"));
    }

    #[test]
    fn refuses_a_template_without_the_secret_placeholder() {
        assert!(render_config("listening-port={{PORT}}\n", "s", &turn_cfg()).is_err());
    }

    #[test]
    fn refuses_a_template_with_unknown_placeholders() {
        let template = "static-auth-secret={{TURN_SECRET}}\nmystery={{WHAT}}\n";
        assert!(render_config(template, "s", &turn_cfg()).is_err());
    }

    #[test]
    fn shipped_template_renders() {
        let template = include_str!("../../deploy/coturn/turnserver.conf.tmpl");
        let out = render_config(template, "deadbeef", &turn_cfg()).expect("render");
        assert!(out.contains("static-auth-secret=deadbeef"));
        assert!(out.contains("use-auth-secret"));
        // A public TURN must not be usable to reach anything private (SSRF into the
        // home LAN, or as an amplifier).
        assert!(out.contains("denied-peer-ip=10.0.0.0-10.255.255.255"));
        assert!(out.contains("no-multicast-peers"));
        assert!(!out.contains("{{"));
    }
}

//! coturn REST credentials and static-secret rotation (ТЗ §6.4, §7.3).
//!
//! coturn's `use-auth-secret` scheme (the "TURN REST API", RFC 7635 style):
//!
//! ```text
//! username   = <unix-expiry>:<user>
//! credential = base64( HMAC-SHA1( static-secret, username ) )
//! ```
//!
//! The static secret never leaves the node; clients only ever see a short-lived
//! derived credential, which is what goes into the bundle (ТЗ Приложение B).

use base64::Engine as _;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::config::Turn;
use crate::error::{Error, Result};
use crate::model::bundle::IceServer;
use crate::store;
use crate::sys::{systemd, Sys};

type HmacSha1 = Hmac<Sha1>;

/// A time-limited TURN credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnCredential {
    pub username: String,
    pub credential: String,
    pub expires: DateTime<Utc>,
}

/// Derive a credential valid for `ttl_secs` from `now`.
pub fn credential(
    secret: &str,
    user: &str,
    ttl_secs: u64,
    now: DateTime<Utc>,
) -> Result<TurnCredential> {
    if secret.is_empty() {
        return Err(Error::Config("turn secret is empty".into()));
    }
    let expiry = now.timestamp().saturating_add(ttl_secs as i64);
    let username = format!("{expiry}:{user}");
    let mut mac = HmacSha1::new_from_slice(secret.as_bytes())
        .map_err(|e| Error::Crypto(format!("hmac key: {e}")))?;
    mac.update(username.as_bytes());
    let credential = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    Ok(TurnCredential {
        username,
        credential,
        expires: DateTime::from_timestamp(expiry, 0).unwrap_or(now),
    })
}

/// The two ICE entries a client gets: our STUN and our TURN. Nothing else — a public
/// STUN server would learn the client's real address (ТЗ §6.4).
pub fn ice_servers(cfg: &Turn, cred: &TurnCredential) -> Vec<IceServer> {
    let host = cfg.listen.ip();
    let port = cfg.listen.port();
    vec![
        IceServer {
            urls: vec![format!("stun:{host}:{port}")],
            username: None,
            credential: None,
        },
        IceServer {
            urls: vec![format!("turn:{host}:{port}")],
            username: Some(cred.username.clone()),
            credential: Some(cred.credential.clone()),
        },
    ]
}

/// Render `turnserver.conf` from the template.
///
/// Placeholders: `{{TURN_SECRET}}`, `{{LISTEN_IP}}`, `{{LISTEN_PORT}}`, `{{REALM}}`.
pub fn render_config(template: &str, secret: &str, cfg: &Turn) -> Result<String> {
    if !template.contains("{{TURN_SECRET}}") {
        return Err(Error::Config(
            "turnserver template has no {{TURN_SECRET}} placeholder".into(),
        ));
    }
    let rendered = template
        .replace("{{TURN_SECRET}}", secret)
        .replace("{{LISTEN_IP}}", &cfg.listen.ip().to_string())
        .replace("{{LISTEN_PORT}}", &cfg.listen.port().to_string())
        .replace("{{REALM}}", &cfg.realm);
    if rendered.contains("{{") {
        return Err(Error::Config(
            "turnserver template still contains unresolved placeholders".into(),
        ));
    }
    Ok(rendered)
}

/// Rotate the static secret: new random secret, re-render the config, restart coturn.
///
/// Existing credentials stop validating immediately — acceptable for a family контур
/// and the reason the ТЗ schedules this monthly rather than hourly.
pub async fn rotate_secret(sys: &Sys, cfg: &Turn) -> Result<()> {
    let template = std::fs::read_to_string(&cfg.config_template)
        .map_err(|e| Error::io(&cfg.config_template, e))?;
    let secret = store::random_hex(32);
    let rendered = render_config(&template, &secret, cfg)?;

    store::write_secret(&cfg.secret_file, &secret)?;
    store::write_atomic(&cfg.config_file, rendered.as_bytes(), store::MODE_SECRET)?;
    systemd::restart(sys, &cfg.unit).await?;
    tracing::info!(unit = %cfg.unit, "turn static secret rotated");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn turn_cfg() -> Turn {
        Turn {
            enabled: true,
            unit: "coturn.service".into(),
            listen: "10.66.10.10:3478".parse().expect("addr"),
            realm: "hearth".into(),
            username: "hearth".into(),
            secret_file: "/etc/hearth/secrets/turn-secret".into(),
            config_template: "/etc/hearth/templates/turnserver.conf.tmpl".into(),
            config_file: "/etc/turnserver.conf".into(),
            credential_ttl_secs: 86400,
            rotate_days: 30,
        }
    }

    fn at(ts: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(ts, 0).single().expect("ts")
    }

    #[test]
    fn credential_matches_the_coturn_rest_scheme() {
        // Vector computed from the documented scheme: base64(HMAC-SHA1(secret, username)).
        let cred = credential("hearth-secret", "hearth", 3600, at(1_757_160_000)).expect("cred");
        assert_eq!(cred.username, "1757163600:hearth");

        let mut mac = HmacSha1::new_from_slice(b"hearth-secret").expect("key");
        mac.update(cred.username.as_bytes());
        let expected =
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        assert_eq!(cred.credential, expected);
        assert_eq!(cred.expires.timestamp(), 1_757_163_600);
    }

    #[test]
    fn credentials_change_with_time_and_secret() {
        let a = credential("s1", "hearth", 60, at(1_000_000)).expect("cred");
        let b = credential("s1", "hearth", 60, at(1_000_060)).expect("cred");
        let c = credential("s2", "hearth", 60, at(1_000_000)).expect("cred");
        assert_ne!(a.credential, b.credential);
        assert_ne!(a.credential, c.credential);
    }

    #[test]
    fn empty_secret_is_refused() {
        assert!(credential("", "hearth", 60, Utc::now()).is_err());
    }

    #[test]
    fn ice_servers_point_only_at_our_node() {
        let cred = credential("secret", "hearth", 60, at(1_000_000)).expect("cred");
        let servers = ice_servers(&turn_cfg(), &cred);
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].urls, vec!["stun:10.66.10.10:3478".to_string()]);
        assert_eq!(servers[1].urls, vec!["turn:10.66.10.10:3478".to_string()]);
        assert_eq!(servers[1].username.as_deref(), Some("1000060:hearth"));
        assert!(servers[0].username.is_none());
    }

    #[test]
    fn renders_the_template() {
        let template = "listening-ip={{LISTEN_IP}}\nlistening-port={{LISTEN_PORT}}\n\
                        realm={{REALM}}\nstatic-auth-secret={{TURN_SECRET}}\n";
        let out = render_config(template, "deadbeef", &turn_cfg()).expect("render");
        assert!(out.contains("listening-ip=10.66.10.10"));
        assert!(out.contains("listening-port=3478"));
        assert!(out.contains("realm=hearth"));
        assert!(out.contains("static-auth-secret=deadbeef"));
        assert!(!out.contains("{{"));
    }

    #[test]
    fn refuses_a_template_without_the_secret_placeholder() {
        assert!(render_config("listening-ip={{LISTEN_IP}}\n", "s", &turn_cfg()).is_err());
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
        assert!(out.contains("listening-ip=10.66.10.10"));
        // ТЗ §6.4: no TCP relaying, credentials required.
        assert!(out.contains("no-tcp"));
        assert!(out.contains("use-auth-secret"));
    }
}

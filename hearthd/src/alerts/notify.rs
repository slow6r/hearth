//! Alert delivery channels (ТЗ §7.3).
//!
//! Two channels, both local to the home network:
//!
//! * **Gotify on the UDM Pro** — reached with a hand-written HTTP/1.1 request over a
//!   [`EgressPolicy`]-guarded socket. There is deliberately no HTTP *client crate* in
//!   the dependency tree: a general-purpose client would follow redirects, resolve
//!   names and speak TLS to anywhere. This one can only ever POST to one IP literal.
//! * **A local beeper command** — no network at all.
//!
//! Delivery is best effort: the journal is the source of truth, a failed push is
//! logged and never propagated into the caller's control flow.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::{Beeper, Gotify};
use crate::error::{Error, Result};
use crate::model::alert::{Alert, Severity};
use crate::net::EgressPolicy;
use crate::store;
use crate::sys::Sys;

/// Configured delivery channels.
#[derive(Debug)]
pub struct Notifier {
    policy: EgressPolicy,
    sys: Sys,
    gotify: Option<GotifyChannel>,
    beeper: Option<BeeperChannel>,
}

#[derive(Debug)]
struct GotifyChannel {
    addr: SocketAddr,
    token: String,
    priority: u8,
    min_severity: Severity,
}

#[derive(Debug)]
struct BeeperChannel {
    command: Vec<String>,
    min_severity: Severity,
}

impl Notifier {
    /// Build the notifier. Missing token files disable the channel with a warning
    /// rather than failing the daemon: alerting must never be the reason the node
    /// refuses to run.
    pub fn new(
        policy: EgressPolicy,
        sys: Sys,
        gotify: Option<&Gotify>,
        beeper: Option<&Beeper>,
    ) -> Self {
        let gotify = gotify.and_then(|cfg| match Self::build_gotify(&policy, cfg) {
            Ok(channel) => Some(channel),
            Err(e) => {
                tracing::warn!(error = %e, "gotify alerting disabled");
                None
            }
        });
        let beeper = beeper.and_then(|cfg| {
            if cfg.command.is_empty() {
                tracing::warn!("beeper command is empty, channel disabled");
                return None;
            }
            match cfg.min_severity.parse::<Severity>() {
                Ok(min_severity) => Some(BeeperChannel {
                    command: cfg.command.clone(),
                    min_severity,
                }),
                Err(e) => {
                    tracing::warn!(error = %e, "beeper alerting disabled");
                    None
                }
            }
        });
        Self {
            policy,
            sys,
            gotify,
            beeper,
        }
    }

    fn build_gotify(policy: &EgressPolicy, cfg: &Gotify) -> Result<GotifyChannel> {
        policy.check(cfg.addr)?;
        let token = store::read_secret(&cfg.token_file)?;
        if !token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
        {
            return Err(Error::Config(
                "gotify token contains characters that cannot appear in a header".into(),
            ));
        }
        Ok(GotifyChannel {
            addr: cfg.addr,
            token,
            priority: cfg.priority,
            min_severity: cfg.min_severity.parse()?,
        })
    }

    /// Push an alert to every channel that wants this severity. Never fails.
    pub async fn deliver(&self, alert: &Alert) {
        if let Some(gotify) = &self.gotify {
            if alert.severity.at_least(gotify.min_severity) {
                if let Err(e) = self.push_gotify(gotify, alert).await {
                    tracing::warn!(error = %e, "gotify delivery failed");
                }
            }
        }
        if let Some(beeper) = &self.beeper {
            if alert.severity.at_least(beeper.min_severity) {
                if let Err(e) = self.run_beeper(beeper, alert).await {
                    tracing::warn!(error = %e, "beeper delivery failed");
                }
            }
        }
    }

    async fn push_gotify(&self, channel: &GotifyChannel, alert: &Alert) -> Result<()> {
        let body = serde_json::json!({
            "title": alert.title(),
            "message": render_message(alert),
            "priority": alert.severity.gotify_priority(channel.priority),
        })
        .to_string();
        let request = build_gotify_request(channel.addr, &channel.token, &body);

        let mut stream = self
            .policy
            .connect(channel.addr, std::time::Duration::from_secs(5))
            .await?;
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(Error::RawIo)?;
        stream
            .write_all(body.as_bytes())
            .await
            .map_err(Error::RawIo)?;
        stream.flush().await.map_err(Error::RawIo)?;

        let mut response = vec![0u8; 256];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read(&mut response),
        )
        .await
        .map_err(|_| Error::Timeout(std::time::Duration::from_secs(5)))?
        .map_err(Error::RawIo)?;
        check_status_line(&String::from_utf8_lossy(&response[..read]))
    }

    async fn run_beeper(&self, channel: &BeeperChannel, alert: &Alert) -> Result<()> {
        let (program, rest) = channel
            .command
            .split_first()
            .ok_or_else(|| Error::Config("beeper command is empty".into()))?;
        let mut args: Vec<String> = rest.to_vec();
        args.push(alert.severity.to_string());
        args.push(alert.summary.clone());
        self.sys.run_mutating(program, &args).await?;
        Ok(())
    }
}

/// Build the request head. The token travels in `X-Gotify-Key`, never in the URL,
/// so it cannot end up in an access log or a proxy history.
fn build_gotify_request(addr: SocketAddr, token: &str, body: &str) -> String {
    format!(
        "POST /message HTTP/1.1\r\n\
         Host: {addr}\r\n\
         X-Gotify-Key: {token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n",
        len = body.len()
    )
}

fn render_message(alert: &Alert) -> String {
    if alert.details.is_null() {
        alert.summary.clone()
    } else {
        format!(
            "{}\n{}",
            alert.summary,
            serde_json::to_string_pretty(&alert.details).unwrap_or_default()
        )
    }
}

/// Accept only 2xx.
fn check_status_line(response: &str) -> Result<()> {
    let first = response.lines().next().unwrap_or_default();
    let code = first.split_whitespace().nth(1).unwrap_or_default();
    match code.parse::<u16>() {
        Ok(code) if (200..300).contains(&code) => Ok(()),
        Ok(code) => Err(Error::Command {
            cmd: "gotify".into(),
            status: code.to_string(),
            stderr: first.to_string(),
        }),
        Err(_) => Err(Error::Parse(format!("unexpected gotify response: {first}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_keeps_the_token_out_of_the_url() {
        let req = build_gotify_request(
            "10.66.0.1:8088".parse().expect("addr"),
            "AbC-123",
            "{\"a\":1}",
        );
        assert!(req.starts_with("POST /message HTTP/1.1\r\n"));
        assert!(req.contains("X-Gotify-Key: AbC-123\r\n"));
        assert!(!req.contains("token="));
        assert!(req.contains("Content-Length: 7\r\n"));
        assert!(req.ends_with("\r\n\r\n"));
    }

    #[test]
    fn status_line_checking() {
        assert!(check_status_line("HTTP/1.1 200 OK\r\n").is_ok());
        assert!(check_status_line("HTTP/1.1 401 Unauthorized\r\n").is_err());
        assert!(check_status_line("garbage").is_err());
    }

    #[test]
    fn gotify_target_outside_home_network_is_refused() {
        let policy = EgressPolicy::new(vec!["10.66.0.0/16".parse().expect("cidr")]);
        let cfg = Gotify {
            addr: "1.2.3.4:80".parse().expect("addr"),
            token_file: "/nonexistent".into(),
            priority: 8,
            min_severity: "warning".into(),
        };
        let err = Notifier::build_gotify(&policy, &cfg).unwrap_err();
        assert!(matches!(err, Error::EgressDenied(_)), "got {err:?}");
    }

    #[test]
    fn message_includes_details_when_present() {
        let alert = Alert::critical("egress", "drop counter moved")
            .with_details(serde_json::json!({"packets": 3}));
        assert!(render_message(&alert).contains("\"packets\": 3"));
    }
}

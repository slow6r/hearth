//! Admin API server (ТЗ §7.3): `:7443`, mTLS, admin subnet only.
//!
//! Three independent gates before any handler runs:
//!
//! 1. **Source address** — the peer must be inside `node.admin_networks`. nftables says
//!    the same thing; this is the application-level echo of it, and it is what makes a
//!    misapplied ruleset visible in the log instead of silently permissive.
//! 2. **mTLS chain** — rustls requires a client certificate issued by the hearth admin CA.
//! 3. **Fingerprint allowlist** — the certificate's sha256 must be an active entry in
//!    `admins.json`, re-read on every connection so a revocation takes effect at once.

pub mod client;
pub mod routes;
pub mod tls;

use std::sync::Arc;

use chrono::Utc;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;

use crate::error::{Error, Result};
use crate::pki::AdminRegistry;
use crate::state::AppState;

pub use routes::Admin;

/// How long a peer may take to complete the TLS handshake.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// Upper bound on one admin connection. Long enough for `backup now` on a large
/// archive, short enough that a wedged connection does not live forever.
const CONNECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// Bind `api.listen` and serve until `shutdown` flips.
pub async fn serve(
    state: Arc<AppState>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let listen = state.config.api.listen;
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|e| Error::io(listen.to_string(), e))?;
    serve_on(state, listener, shutdown).await
}

/// Serve on an already-bound listener. Split out so tests can use an ephemeral port.
pub async fn serve_on(
    state: Arc<AppState>,
    listener: TcpListener,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let config = state.config.clone();
    let tls_config = tls::server_config(&config.api.pki_dir)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
    tracing::info!(listen = ?listener.local_addr().ok(), "admin api listening (mTLS)");

    let app = routes::router(state.clone());

    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("admin api stopping");
                    return Ok(());
                }
                continue;
            }
        };

        let (tcp, peer) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };

        // Gate 1: source address.
        if !config
            .node
            .admin_networks
            .iter()
            .any(|net| net.contains(&peer.ip()))
        {
            tracing::warn!(%peer, "rejected: outside the admin networks");
            continue;
        }

        let acceptor = acceptor.clone();
        let app = app.clone();
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(acceptor, tcp, peer, app, state).await {
                tracing::debug!(%peer, error = %e, "connection closed");
            }
        });
    }
}

async fn handle_connection(
    acceptor: tokio_rustls::TlsAcceptor,
    tcp: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    app: axum::Router,
    state: Arc<AppState>,
) -> Result<()> {
    // Gate 2: mTLS. rustls rejects anything not chaining to the hearth admin CA.
    //
    // Bounded: a peer that opens a socket and then says nothing would otherwise hold
    // the task forever. The API is LAN-only so this is housekeeping rather than
    // defence, but an unbounded wait is never the right default.
    let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp))
        .await
        .map_err(|_| Error::Tls(format!("handshake with {peer} timed out")))?
        .map_err(|e| Error::Tls(format!("handshake with {peer} failed: {e}")))?;

    let fingerprint = {
        let (_, connection) = stream.get_ref();
        connection
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(|cert| crate::pki::fingerprint_der(cert.as_ref()))
            .ok_or_else(|| Error::Unauthorized("no client certificate".into()))?
    };

    // Gate 3: fingerprint allowlist, re-read per connection so revocation is instant.
    let admin = authorize(&state, &fingerprint, peer)?;
    tracing::info!(%peer, admin = %admin.name, "admin session");

    let service = TowerToHyperService::new(app.layer(axum::Extension(admin)));
    // `backup now` and `migrate export` can legitimately take minutes (a large archive,
    // then an rsync), so the cap is generous — it exists to reap stuck connections,
    // not to bound honest work.
    tokio::time::timeout(
        CONNECTION_TIMEOUT,
        ConnBuilder::new(TokioExecutor::new()).serve_connection(TokioIo::new(stream), service),
    )
    .await
    .map_err(|_| Error::Timeout(CONNECTION_TIMEOUT))?
    .map_err(|e| Error::Tls(format!("http: {e}")))?;
    Ok(())
}

/// Check the presented certificate against `admins.json` and the optional pin list.
fn authorize(
    state: &Arc<AppState>,
    fingerprint: &str,
    peer: std::net::SocketAddr,
) -> Result<Admin> {
    let config = &state.config;
    if !config.api.allowed_admin_fingerprints.is_empty()
        && !config
            .api
            .allowed_admin_fingerprints
            .iter()
            .any(|pin| pin.eq_ignore_ascii_case(fingerprint))
    {
        tracing::warn!(%peer, fingerprint, "rejected: not in allowed_admin_fingerprints");
        return Err(Error::Unauthorized("certificate is not pinned".into()));
    }

    let registry = AdminRegistry::load(&config.api.pki_dir)?;
    match registry.authorize(fingerprint, Utc::now()) {
        Some(admin) => Ok(Admin {
            name: admin.name.clone(),
            fingerprint: fingerprint.to_string(),
            peer,
        }),
        None => {
            tracing::warn!(%peer, fingerprint, "rejected: revoked, expired or unknown certificate");
            Err(Error::Unauthorized(
                "certificate is revoked, expired or unknown".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki;
    use crate::sys::Sys;

    fn state_with_pki(dir: &std::path::Path) -> (Arc<AppState>, pki::IssuedAdmin) {
        let config = crate::state::tests::test_config(dir);
        let pki_dir = config.api.pki_dir.clone();
        pki::init_ca(&pki_dir, "hearth-node", config.api.listen.ip(), false).expect("ca");
        let issued = pki::issue_admin(&pki_dir, "owner", 30).expect("issue");
        let state = AppState::new(config, Sys::new(true)).expect("state");
        (state, issued)
    }

    #[test]
    fn authorizes_an_issued_certificate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, issued) = state_with_pki(dir.path());
        let peer = "192.168.1.5:40000".parse().expect("addr");
        let admin = authorize(&state, &issued.fingerprint, peer).expect("authorized");
        assert_eq!(admin.name, "owner");
    }

    #[test]
    fn rejects_an_unknown_certificate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, _issued) = state_with_pki(dir.path());
        let peer = "192.168.1.5:40000".parse().expect("addr");
        let err = authorize(&state, &"0".repeat(64), peer).unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)), "got {err:?}");
    }

    #[test]
    fn rejects_a_revoked_certificate_immediately() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, issued) = state_with_pki(dir.path());
        let peer = "192.168.1.5:40000".parse().expect("addr");
        assert!(authorize(&state, &issued.fingerprint, peer).is_ok());

        AdminRegistry::load(&state.config.api.pki_dir)
            .expect("load")
            .revoke("owner")
            .expect("revoke");

        assert!(
            authorize(&state, &issued.fingerprint, peer).is_err(),
            "revocation must not need a daemon restart"
        );
    }

    #[test]
    fn honours_the_fingerprint_pin_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = crate::state::tests::test_config(dir.path());
        let pki_dir = config.api.pki_dir.clone();
        pki::init_ca(&pki_dir, "hearth-node", config.api.listen.ip(), false).expect("ca");
        let issued = pki::issue_admin(&pki_dir, "owner", 30).expect("issue");

        let mut config = config;
        config.api.allowed_admin_fingerprints = vec!["a".repeat(64)];
        let state = AppState::new(config, Sys::new(true)).expect("state");
        let peer = "192.168.1.5:40000".parse().expect("addr");
        let err = authorize(&state, &issued.fingerprint, peer).unwrap_err();
        assert!(err.to_string().contains("not pinned"), "got {err}");
    }
}

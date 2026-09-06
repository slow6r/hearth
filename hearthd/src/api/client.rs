//! mTLS client for the admin API — the transport half of `hearthctl`.
//!
//! Uses the same hyper that serves the API, over a tokio-rustls stream pinned to the
//! hearth admin CA. There is no general-purpose HTTP client crate in the tree: this one
//! speaks to exactly one IP literal and trusts exactly one CA (ТЗ §7.2).

use std::net::SocketAddr;
use std::path::Path;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use serde::de::DeserializeOwned;

use crate::error::{Error, Result};

/// Connected-on-demand admin client.
#[derive(Clone)]
pub struct AdminClient {
    addr: SocketAddr,
    connector: tokio_rustls::TlsConnector,
    server_name: ServerName<'static>,
    timeout: std::time::Duration,
}

impl std::fmt::Debug for AdminClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminClient")
            .field("addr", &self.addr)
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl AdminClient {
    /// Build a client from the PEM material `hearthctl` was given.
    pub fn new(addr: SocketAddr, ca: &Path, cert: &Path, key: &Path) -> Result<Self> {
        let config = super::tls::client_config(ca, cert, key)?;
        Ok(Self {
            addr,
            connector: tokio_rustls::TlsConnector::from(config),
            // The API is reached by IP; the server certificate carries an IP SAN.
            server_name: ServerName::IpAddress(addr.ip().into()),
            timeout: std::time::Duration::from_secs(60),
        })
    }

    /// Address this client talks to.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// GET a JSON document.
    pub async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let (status, body) = self.send(Method::GET, path, None).await?;
        decode(status, &body, path)
    }

    /// POST (optionally with a JSON body) and decode a JSON reply.
    pub async fn post_json<T: DeserializeOwned>(
        &self,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T> {
        let payload = match body {
            Some(value) => Some(serde_json::to_vec(&value)?),
            None => None,
        };
        let (status, body) = self.send(Method::POST, path, payload).await?;
        decode(status, &body, path)
    }

    /// GET raw bytes (the QR PNG, the manual checklist).
    pub async fn get_bytes(&self, path: &str) -> Result<Vec<u8>> {
        let (status, body) = self.send(Method::GET, path, None).await?;
        if status.is_success() {
            Ok(body)
        } else {
            Err(api_error(status, &body, path))
        }
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(StatusCode, Vec<u8>)> {
        let tcp = tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(self.addr))
            .await
            .map_err(|_| Error::Timeout(self.timeout))?
            .map_err(|e| Error::io(self.addr.to_string(), e))?;
        let tls = self
            .connector
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(|e| Error::Tls(format!("handshake with {}: {e}", self.addr)))?;

        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|e| Error::Tls(format!("http handshake: {e}")))?;
        let driver = tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::debug!(error = %e, "admin connection closed");
            }
        });

        let has_body = body.is_some();
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(hyper::header::HOST, self.addr.to_string())
            .header(hyper::header::ACCEPT, "application/json")
            .header(
                hyper::header::CONTENT_TYPE,
                if has_body {
                    "application/json"
                } else {
                    "text/plain"
                },
            )
            .body(Full::new(Bytes::from(body.unwrap_or_default())))
            .map_err(|e| Error::invalid(format!("bad request: {e}")))?;

        let response = tokio::time::timeout(self.timeout, sender.send_request(request))
            .await
            .map_err(|_| Error::Timeout(self.timeout))?
            .map_err(|e| Error::Tls(format!("request failed: {e}")))?;

        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| Error::Tls(format!("reading response: {e}")))?
            .to_bytes()
            .to_vec();
        driver.abort();
        Ok((status, bytes))
    }
}

fn decode<T: DeserializeOwned>(status: StatusCode, body: &[u8], path: &str) -> Result<T> {
    if !status.is_success() {
        return Err(api_error(status, body, path));
    }
    serde_json::from_slice(body).map_err(|e| {
        Error::Parse(format!(
            "{path}: unexpected response: {e} ({})",
            String::from_utf8_lossy(&body[..body.len().min(200)])
        ))
    })
}

/// Turn an error response into a readable `hearthctl` error.
fn api_error(status: StatusCode, body: &[u8], path: &str) -> Error {
    #[derive(serde::Deserialize)]
    struct Body {
        error: String,
    }
    let detail = serde_json::from_slice::<Body>(body)
        .map(|b| b.error)
        .unwrap_or_else(|_| String::from_utf8_lossy(body).trim().to_string());
    let message = if detail.is_empty() {
        format!("{path}: {status}")
    } else {
        format!("{path}: {status}: {detail}")
    };
    match status {
        StatusCode::NOT_FOUND => Error::NotFound(message),
        StatusCode::CONFLICT => Error::Conflict(message),
        StatusCode::BAD_REQUEST => Error::Invalid(message),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Error::Unauthorized(message),
        _ => Error::Command {
            cmd: format!("admin api {path}"),
            status: status.as_u16().to_string(),
            stderr: detail,
        },
    }
}

/// Where `hearthctl` looks for its client material by default.
pub fn default_material(pki_dir: &Path, name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    (
        pki_dir.join(format!("{name}.pem")),
        pki_dir.join(format!("{name}.key")),
    )
}

/// Convenience wrapper used by `hearthctl`.
pub fn connect(
    addr: SocketAddr,
    pki_dir: &Path,
    admin: &str,
    ca_override: Option<&Path>,
    cert_override: Option<&Path>,
    key_override: Option<&Path>,
) -> Result<AdminClient> {
    let ca = ca_override
        .map(Path::to_path_buf)
        .unwrap_or_else(|| pki_dir.join(crate::pki::CA_CERT));
    let (default_cert, default_key) = default_material(pki_dir, admin);
    let cert = cert_override.map(Path::to_path_buf).unwrap_or(default_cert);
    let key = key_override.map(Path::to_path_buf).unwrap_or(default_key);

    for (what, path) in [("ca", &ca), ("certificate", &cert), ("key", &key)] {
        if !path.exists() {
            return Err(Error::NotFound(format!(
                "admin {what} {} not found — issue one with `hearthd ca issue <name>`",
                path.display()
            )));
        }
    }
    AdminClient::new(addr, &ca, &cert, &key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_status_codes_to_errors() {
        let body = br#"{"error":"device `x` not found","kind":"not_found"}"#;
        let err = api_error(StatusCode::NOT_FOUND, body, "/devices/x");
        assert!(matches!(err, Error::NotFound(_)));
        assert!(err.to_string().contains("device `x` not found"));

        let err = api_error(StatusCode::UNAUTHORIZED, b"", "/health");
        assert!(matches!(err, Error::Unauthorized(_)));
    }

    #[test]
    fn decode_rejects_non_json_success_bodies() {
        let err = decode::<serde_json::Value>(StatusCode::OK, b"<html>", "/health").unwrap_err();
        assert!(err.to_string().contains("unexpected response"));
    }

    #[test]
    fn connect_reports_missing_material_clearly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = connect(
            "127.0.0.1:7443".parse().expect("addr"),
            dir.path(),
            "owner",
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("ca.pem"), "got {err}");
    }
}

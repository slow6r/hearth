//! TLS material for the admin API (ТЗ §7.3).
//!
//! Mutual TLS against the hearth admin CA, with the `ring` provider — no aws-lc, so the
//! static musl build needs no C toolchain. Both sides pin the same private CA: there is
//! no public trust store anywhere in this contour.

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::error::{Error, Result};

/// The crypto provider used everywhere in hearthd.
pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Read a PEM certificate chain.
pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let data = std::fs::read(path).map_err(|e| Error::io(path, e))?;
    let certs: std::result::Result<Vec<_>, _> =
        rustls_pemfile::certs(&mut data.as_slice()).collect();
    let certs = certs.map_err(|e| Error::Tls(format!("{}: {e}", path.display())))?;
    if certs.is_empty() {
        return Err(Error::Tls(format!(
            "{} contains no certificate",
            path.display()
        )));
    }
    Ok(certs)
}

/// Read a PEM private key (PKCS#8, SEC1 or PKCS#1).
pub fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let data = std::fs::read(path).map_err(|e| Error::io(path, e))?;
    rustls_pemfile::private_key(&mut data.as_slice())
        .map_err(|e| Error::Tls(format!("{}: {e}", path.display())))?
        .ok_or_else(|| Error::Tls(format!("{} contains no private key", path.display())))
}

/// Trust store containing only our own CA.
pub fn root_store(ca_pem: &Path) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in load_certs(ca_pem)? {
        roots
            .add(cert)
            .map_err(|e| Error::Tls(format!("cannot trust {}: {e}", ca_pem.display())))?;
    }
    Ok(roots)
}

/// Server side: require a client certificate signed by the hearth admin CA.
pub fn server_config(pki_dir: &Path) -> Result<Arc<ServerConfig>> {
    let roots = Arc::new(root_store(&pki_dir.join(super::super::pki::CA_CERT))?);
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(roots, provider())
        .build()
        .map_err(|e| Error::Tls(format!("client verifier: {e}")))?;

    let certs = load_certs(&pki_dir.join(super::super::pki::SERVER_CERT))?;
    let key = load_key(&pki_dir.join(super::super::pki::SERVER_KEY))?;

    let config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Tls(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| Error::Tls(format!("server certificate: {e}")))?;
    Ok(Arc::new(config))
}

/// Client side (`hearthctl`): trust only our CA, always present the admin certificate.
pub fn client_config(ca_pem: &Path, cert: &Path, key: &Path) -> Result<Arc<ClientConfig>> {
    let roots = root_store(ca_pem)?;
    let certs = load_certs(cert)?;
    let key = load_key(key)?;

    let config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Tls(e.to_string()))?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .map_err(|e| Error::Tls(format!("client certificate: {e}")))?;
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki;

    #[test]
    fn builds_server_and_client_configs_from_a_fresh_ca() {
        let dir = tempfile::tempdir().expect("tempdir");
        pki::init_ca(
            dir.path(),
            "hearth-node",
            "10.66.10.10".parse().expect("ip"),
            false,
        )
        .expect("init ca");
        let issued = pki::issue_admin(dir.path(), "owner", 30).expect("issue");

        server_config(dir.path()).expect("server config");

        let cert_path = dir.path().join("owner.pem");
        let key_path = dir.path().join("owner.key");
        std::fs::write(&cert_path, issued.cert_pem).expect("write");
        std::fs::write(&key_path, issued.key_pem).expect("write");
        client_config(&dir.path().join(pki::CA_CERT), &cert_path, &key_path)
            .expect("client config");
    }

    #[test]
    fn rejects_missing_material() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(server_config(dir.path()).is_err());
        assert!(load_certs(&dir.path().join("nope.pem")).is_err());
    }
}

//! The admin PKI (ТЗ §7.3: "mTLS, клиентские сертификаты от собственного CA hearthd").
//!
//! A tiny, self-contained CA that exists for exactly one purpose: deciding who may talk
//! to the admin API. It is unrelated to the relay CA — that one belongs to
//! `smp-server init`, lives in `/etc/opt/simplex`, and hearthd never touches it.
//!
//! Authorisation is by **certificate fingerprint**, not by Common Name. rustls has
//! already proven the chain by the time a request arrives; matching the sha256 of the
//! presented certificate against `admins.json` means a stolen-but-revoked certificate
//! stops working the moment the registry is edited, and it needs no X.509 name parser.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::store;

/// Filenames inside `pki_dir`.
pub const CA_CERT: &str = "ca.pem";
pub const CA_KEY: &str = "ca.key";
pub const SERVER_CERT: &str = "server.pem";
pub const SERVER_KEY: &str = "server.key";
pub const ADMINS: &str = "admins.json";

/// CA validity. Long, because rotating it means re-issuing every admin certificate by
/// hand — and it only guards a LAN-only API.
const CA_DAYS: i64 = 3650;
/// Server certificate validity.
const SERVER_DAYS: i64 = 825;
/// Default admin certificate validity.
pub const DEFAULT_ADMIN_DAYS: i64 = 730;

/// One issued admin certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminCert {
    pub name: String,
    /// Lowercase hex sha256 of the DER certificate. This is the identity.
    pub fingerprint: String,
    #[serde(with = "crate::model::rfc3339")]
    pub issued: DateTime<Utc>,
    #[serde(with = "crate::model::rfc3339")]
    pub expires: DateTime<Utc>,
    #[serde(default, with = "crate::model::rfc3339::option")]
    pub revoked: Option<DateTime<Utc>>,
}

impl AdminCert {
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked.is_none() && now < self.expires
    }
}

/// `admins.json` — the allowlist the API checks on every connection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdminRegistry {
    #[serde(default)]
    pub admins: Vec<AdminCert>,
    #[serde(skip)]
    path: PathBuf,
}

impl AdminRegistry {
    pub fn load(pki_dir: &Path) -> Result<Self> {
        let path = pki_dir.join(ADMINS);
        let mut registry: AdminRegistry = store::read_json(&path)?.unwrap_or_default();
        registry.path = path;
        Ok(registry)
    }

    pub fn save(&self) -> Result<()> {
        store::write_json_atomic(&self.path, self, store::MODE_STATE)
    }

    /// Is this certificate allowed to use the admin API right now?
    pub fn authorize(&self, fingerprint: &str, now: DateTime<Utc>) -> Option<&AdminCert> {
        self.admins
            .iter()
            .find(|a| a.fingerprint.eq_ignore_ascii_case(fingerprint) && a.is_valid_at(now))
    }

    pub fn revoke(&mut self, name: &str) -> Result<AdminCert> {
        let admin = self
            .admins
            .iter_mut()
            .find(|a| a.name == name)
            .ok_or_else(|| Error::NotFound(format!("admin certificate `{name}`")))?;
        if admin.revoked.is_none() {
            admin.revoked = Some(Utc::now());
        }
        let admin = admin.clone();
        self.save()?;
        Ok(admin)
    }
}

/// What `hearthd ca init` produced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaInfo {
    pub ca_cert: PathBuf,
    pub server_cert: PathBuf,
    pub ca_fingerprint: String,
    pub server_fingerprint: String,
}

/// A freshly issued admin certificate. The key material is returned, never stored:
/// hearthd keeps only the fingerprint.
#[derive(Debug, Clone)]
pub struct IssuedAdmin {
    pub name: String,
    pub fingerprint: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub expires: DateTime<Utc>,
}

/// Create the admin CA and the API server certificate. Idempotent guard: refuses to
/// overwrite an existing CA, because that would lock out every issued admin at once.
pub fn init_ca(pki_dir: &Path, node_name: &str, address: IpAddr, force: bool) -> Result<CaInfo> {
    store::ensure_dir(pki_dir)?;
    let ca_cert_path = pki_dir.join(CA_CERT);
    if ca_cert_path.exists() && !force {
        return Err(Error::Conflict(format!(
            "{} already exists; re-initialising the CA invalidates every issued admin \
             certificate. Pass --force if that is really what you want.",
            ca_cert_path.display()
        )));
    }

    let ca_key = rcgen::KeyPair::generate().map_err(Error::from)?;
    let ca_params = ca_params()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);

    // Server certificate: the API is reached by IP literal, so the SAN is an IP.
    let server_key = rcgen::KeyPair::generate()?;
    let mut server_params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    server_params.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!("hearthd api ({node_name})"),
    );
    server_params.subject_alt_names = vec![rcgen::SanType::IpAddress(address)];
    server_params.use_authority_key_identifier_extension = true;
    server_params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    set_validity(&mut server_params, SERVER_DAYS);
    let server_cert = server_params.signed_by(&server_key, &issuer)?;

    store::write_atomic(&ca_cert_path, ca_cert.pem().as_bytes(), store::MODE_STATE)?;
    store::write_secret(pki_dir.join(CA_KEY), ca_key.serialize_pem().trim())?;
    store::write_atomic(
        pki_dir.join(SERVER_CERT),
        server_cert.pem().as_bytes(),
        store::MODE_STATE,
    )?;
    store::write_secret(pki_dir.join(SERVER_KEY), server_key.serialize_pem().trim())?;

    // Create an empty registry so the API has something to read.
    let registry = AdminRegistry::load(pki_dir)?;
    registry.save()?;

    Ok(CaInfo {
        ca_cert: ca_cert_path,
        server_cert: pki_dir.join(SERVER_CERT),
        ca_fingerprint: fingerprint_der(ca_cert.der()),
        server_fingerprint: fingerprint_der(server_cert.der()),
    })
}

/// Issue an admin client certificate and record its fingerprint.
pub fn issue_admin(pki_dir: &Path, name: &str, days: i64) -> Result<IssuedAdmin> {
    let name = name.trim();
    if name.is_empty() {
        return Err(Error::invalid("admin name must not be empty"));
    }
    if !pki_dir.join(CA_CERT).exists() {
        return Err(Error::NotFound(format!(
            "{} — run `hearthd ca init` first",
            pki_dir.join(CA_CERT).display()
        )));
    }
    let ca_key_pem = store::read_secret(pki_dir.join(CA_KEY))?;
    let ca_key = rcgen::KeyPair::from_pem(&ca_key_pem)?;
    let ca_params = ca_params()?;
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);

    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "hearth admins");
    params.use_authority_key_identifier_extension = true;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    set_validity(&mut params, days);
    let cert = params.signed_by(&key, &issuer)?;

    let fingerprint = fingerprint_der(cert.der());
    let now = Utc::now();
    let expires = now + chrono::Duration::days(days);

    let mut registry = AdminRegistry::load(pki_dir)?;
    if registry
        .admins
        .iter()
        .any(|a| a.name == name && a.revoked.is_none())
    {
        return Err(Error::Conflict(format!(
            "an active admin certificate named `{name}` already exists; revoke it first"
        )));
    }
    registry.admins.push(AdminCert {
        name: name.to_string(),
        fingerprint: fingerprint.clone(),
        issued: now,
        expires,
        revoked: None,
    });
    registry.save()?;

    Ok(IssuedAdmin {
        name: name.to_string(),
        fingerprint,
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        expires,
    })
}

/// sha256 of a DER certificate, lowercase hex — the admin identity.
pub fn fingerprint_der(der: &[u8]) -> String {
    crate::model::manifest::sha256_bytes(der)
}

/// Parameters of the admin CA.
///
/// Deliberately deterministic: the issuer's subject DN must match the CA certificate's
/// subject byte for byte, and `issue_admin` rebuilds it months later from nothing but
/// this function. Nothing node-specific goes in here for exactly that reason.
fn ca_params() -> Result<rcgen::CertificateParams> {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "hearth admin CA");
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "hearth");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    set_validity(&mut params, CA_DAYS);
    Ok(params)
}

fn set_validity(params: &mut rcgen::CertificateParams, days: i64) {
    let now = Utc::now();
    let not_before = now - chrono::Duration::hours(1);
    let not_after = now + chrono::Duration::days(days);
    params.not_before = rcgen::date_time_ymd(
        not_before.date_naive().year(),
        not_before.date_naive().month() as u8,
        not_before.date_naive().day() as u8,
    );
    params.not_after = rcgen::date_time_ymd(
        not_after.date_naive().year(),
        not_after.date_naive().month() as u8,
        not_after.date_naive().day() as u8,
    );
}

use chrono::Datelike as _;

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> IpAddr {
        "10.66.10.10".parse().expect("ip")
    }

    #[test]
    fn init_creates_ca_and_server_material() {
        let dir = tempfile::tempdir().expect("tempdir");
        let info = init_ca(dir.path(), "hearth-node", node(), false).expect("init");

        for name in [CA_CERT, CA_KEY, SERVER_CERT, SERVER_KEY, ADMINS] {
            assert!(dir.path().join(name).exists(), "{name} must exist");
        }
        assert_eq!(info.ca_fingerprint.len(), 64);
        assert_ne!(info.ca_fingerprint, info.server_fingerprint);

        let ca_pem = std::fs::read_to_string(dir.path().join(CA_CERT)).expect("read");
        assert!(ca_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn init_refuses_to_clobber_an_existing_ca() {
        let dir = tempfile::tempdir().expect("tempdir");
        init_ca(dir.path(), "hearth-node", node(), false).expect("init");
        let err = init_ca(dir.path(), "hearth-node", node(), false).unwrap_err();
        assert!(matches!(err, Error::Conflict(_)), "got {err:?}");
        init_ca(dir.path(), "hearth-node", node(), true).expect("forced re-init");
    }

    #[test]
    fn issues_and_authorizes_admin_certificates() {
        let dir = tempfile::tempdir().expect("tempdir");
        init_ca(dir.path(), "hearth-node", node(), false).expect("init");
        let issued = issue_admin(dir.path(), "owner", 30).expect("issue");

        assert!(issued.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(issued.key_pem.contains("PRIVATE KEY"));
        assert_eq!(issued.fingerprint.len(), 64);

        let registry = AdminRegistry::load(dir.path()).expect("load");
        assert_eq!(registry.admins.len(), 1);
        assert!(registry
            .authorize(&issued.fingerprint, Utc::now())
            .is_some());
        assert!(registry.authorize("deadbeef", Utc::now()).is_none());
    }

    #[test]
    fn private_keys_are_never_stored_for_admins() {
        let dir = tempfile::tempdir().expect("tempdir");
        init_ca(dir.path(), "hearth-node", node(), false).expect("init");
        let issued = issue_admin(dir.path(), "owner", 30).expect("issue");
        let registry_raw = std::fs::read_to_string(dir.path().join(ADMINS)).expect("read");
        assert!(!registry_raw.contains("PRIVATE KEY"));
        assert!(registry_raw.contains(&issued.fingerprint));
    }

    #[test]
    fn revoked_and_expired_certificates_are_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        init_ca(dir.path(), "hearth-node", node(), false).expect("init");
        let issued = issue_admin(dir.path(), "owner", 30).expect("issue");

        let mut registry = AdminRegistry::load(dir.path()).expect("load");
        // Expired.
        let future = Utc::now() + chrono::Duration::days(60);
        assert!(registry.authorize(&issued.fingerprint, future).is_none());
        // Revoked.
        registry.revoke("owner").expect("revoke");
        assert!(registry
            .authorize(&issued.fingerprint, Utc::now())
            .is_none());
        assert!(registry.revoke("nobody").is_err());
    }

    #[test]
    fn duplicate_active_names_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        init_ca(dir.path(), "hearth-node", node(), false).expect("init");
        issue_admin(dir.path(), "owner", 30).expect("issue");
        assert!(issue_admin(dir.path(), "owner", 30).is_err());

        AdminRegistry::load(dir.path())
            .expect("load")
            .revoke("owner")
            .expect("revoke");
        issue_admin(dir.path(), "owner", 30).expect("re-issue after revocation");
    }

    #[test]
    fn fingerprints_are_stable_sha256() {
        assert_eq!(
            fingerprint_der(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

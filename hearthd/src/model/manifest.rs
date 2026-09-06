//! Pinned upstream versions and hashes — `/etc/hearth/manifest.toml` (ТЗ §6.1, §7.3).
//!
//! One source of truth for what is allowed to run on the node. `latest` does not
//! exist here: every artefact is a tag plus a sha256. The integrity module compares
//! the running binaries against this file at start-up and hourly (A12).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The manifest document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub upstream: Upstream,
    /// Every binary that must match a known hash.
    #[serde(default, rename = "binary")]
    pub binaries: Vec<BinaryEntry>,
}

/// Provenance of the pinned upstream release.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// simplexmq release tag, e.g. `v6.4.2`.
    pub simplexmq_tag: String,
    /// simplex-chat release tag the Android fork rebases onto.
    pub simplex_chat_tag: String,
    /// GPG identity whose signature was verified for the release artefacts.
    pub gpg_identity: String,
    /// When the pin was last reviewed (ISO date).
    pub reviewed: String,
}

/// One pinned binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryEntry {
    /// Logical name, e.g. `smp-server`.
    pub name: String,
    /// Absolute path on the node.
    pub path: PathBuf,
    /// Upstream version/tag this binary came from.
    pub version: String,
    /// Lowercase hex sha256 of the file.
    pub sha256: String,
    /// Where it was obtained from (release URL or `built-from-source`).
    #[serde(default)]
    pub source: Option<String>,
}

/// Result of checking one binary against the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityFinding {
    pub name: String,
    pub path: PathBuf,
    pub expected: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
    pub status: IntegrityStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityStatus {
    /// Hash matches the manifest.
    Ok,
    /// Hash differs — the binary was replaced. Critical (ТЗ §7.3).
    Mismatch,
    /// File is missing or unreadable.
    Missing,
}

impl Manifest {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
        let manifest: Manifest = toml::from_str(&raw)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        if self.binaries.is_empty() {
            return Err(Error::config("manifest lists no binaries"));
        }
        for entry in &self.binaries {
            if entry.sha256.len() != 64 || !entry.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(Error::config(format!(
                    "manifest entry `{}` has an invalid sha256: {}",
                    entry.name, entry.sha256
                )));
            }
            if entry.sha256.chars().any(|c| c.is_ascii_uppercase()) {
                return Err(Error::config(format!(
                    "manifest entry `{}` sha256 must be lowercase hex",
                    entry.name
                )));
            }
            if entry.version.eq_ignore_ascii_case("latest") {
                return Err(Error::config(format!(
                    "manifest entry `{}` uses `latest`, which ТЗ §2.6 forbids",
                    entry.name
                )));
            }
        }
        Ok(())
    }

    pub fn binary(&self, name: &str) -> Option<&BinaryEntry> {
        self.binaries.iter().find(|b| b.name == name)
    }

    /// Hash every listed binary and compare against the pin.
    pub fn verify_all(&self) -> Vec<IntegrityFinding> {
        self.binaries.iter().map(verify_one).collect()
    }
}

fn verify_one(entry: &BinaryEntry) -> IntegrityFinding {
    match sha256_file(&entry.path) {
        Ok(actual) => {
            let status = if actual == entry.sha256 {
                IntegrityStatus::Ok
            } else {
                IntegrityStatus::Mismatch
            };
            IntegrityFinding {
                name: entry.name.clone(),
                path: entry.path.clone(),
                expected: entry.sha256.clone(),
                actual: Some(actual),
                status,
            }
        }
        Err(_) => IntegrityFinding {
            name: entry.name.clone(),
            path: entry.path.clone(),
            expected: entry.sha256.clone(),
            actual: None,
            status: IntegrityStatus::Missing,
        },
    }
}

/// Rewrite one binary's `sha256` (and optionally `version`) in the raw manifest text.
///
/// Line based on purpose: re-serializing through `toml` would drop every comment, and
/// this file's comments are the operating instructions for verifying a release.
pub fn pin(raw: &str, name: &str, sha256: &str, version: Option<&str>) -> Result<String> {
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::invalid(format!("`{sha256}` is not a sha256 digest")));
    }
    let sha256 = sha256.to_ascii_lowercase();

    let mut out = Vec::new();
    let mut in_target = false;
    let mut seen_target = false;
    let mut replaced_sha = false;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            // Any new table ends the block we might have been in.
            in_target = false;
        }
        if is_name_line(trimmed, name) {
            in_target = true;
            seen_target = true;
        }
        if in_target && trimmed.starts_with("sha256") {
            out.push(format!("sha256 = \"{sha256}\""));
            replaced_sha = true;
            continue;
        }
        if in_target && trimmed.starts_with("version") {
            if let Some(version) = version {
                out.push(format!("version = \"{version}\""));
                continue;
            }
        }
        out.push(line.to_string());
    }

    if !seen_target {
        return Err(Error::NotFound(format!("manifest entry `{name}`")));
    }
    if !replaced_sha {
        return Err(Error::invalid(format!(
            "manifest entry `{name}` has no sha256 line to update"
        )));
    }
    let mut text = out.join("\n");
    if raw.ends_with('\n') {
        text.push('\n');
    }
    Ok(text)
}

fn is_name_line(trimmed: &str, name: &str) -> bool {
    let Some(value) = trimmed.strip_prefix("name") else {
        return false;
    };
    let Some(value) = value.trim_start().strip_prefix('=') else {
        return false;
    };
    value.trim().trim_matches('"') == name
}

/// Streaming sha256 of a file (binaries are ~100 MB; never read them whole).
pub fn sha256_file(path: impl AsRef<Path>) -> Result<String> {
    use sha2::{Digest, Sha256};
    let path = path.as_ref();
    let mut file = std::fs::File::open(path).map_err(|e| Error::io(path, e))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(|e| Error::io(path, e))?;
    Ok(hex::encode(hasher.finalize()))
}

/// sha256 of a byte slice.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn reference_manifest_parses() {
        let raw = include_str!("../../manifest.toml");
        let manifest: Manifest = toml::from_str(raw).expect("manifest parses");
        manifest.validate().expect("manifest is valid");
        assert!(manifest.binary("smp-server").is_some());
        assert!(manifest.binary("xftp-server").is_some());
    }

    #[test]
    fn rejects_latest_pin() {
        let raw = r#"
            [upstream]
            simplexmq_tag = "v6.4.2"
            simplex_chat_tag = "v6.4.2"
            gpg_identity = "chat@simplex.chat"
            reviewed = "2026-09-06"

            [[binary]]
            name = "smp-server"
            path = "/usr/local/bin/smp-server"
            version = "latest"
            sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
        "#;
        let manifest: Manifest = toml::from_str(raw).expect("parses");
        let err = manifest.validate().unwrap_err();
        assert!(err.to_string().contains("latest"), "got {err}");
    }

    #[test]
    fn rejects_malformed_hash() {
        let raw = r#"
            [upstream]
            simplexmq_tag = "v6.4.2"
            simplex_chat_tag = "v6.4.2"
            gpg_identity = "chat@simplex.chat"
            reviewed = "2026-09-06"

            [[binary]]
            name = "smp-server"
            path = "/usr/local/bin/smp-server"
            version = "v6.4.2"
            sha256 = "deadbeef"
        "#;
        let manifest: Manifest = toml::from_str(raw).expect("parses");
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn detects_ok_mismatch_and_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let good = dir.path().join("good");
        let mut f = std::fs::File::create(&good).expect("create");
        f.write_all(b"hearth").expect("write");
        drop(f);
        let digest = sha256_file(&good).expect("hash");

        let manifest = Manifest {
            upstream: Upstream {
                simplexmq_tag: "v6.4.2".into(),
                simplex_chat_tag: "v6.4.2".into(),
                gpg_identity: "chat@simplex.chat".into(),
                reviewed: "2026-09-06".into(),
            },
            binaries: vec![
                BinaryEntry {
                    name: "good".into(),
                    path: good.clone(),
                    version: "v1".into(),
                    sha256: digest.clone(),
                    source: None,
                },
                BinaryEntry {
                    name: "tampered".into(),
                    path: good,
                    version: "v1".into(),
                    sha256: "a".repeat(64),
                    source: None,
                },
                BinaryEntry {
                    name: "absent".into(),
                    path: dir.path().join("nope"),
                    version: "v1".into(),
                    sha256: "b".repeat(64),
                    source: None,
                },
            ],
        };

        let findings = manifest.verify_all();
        assert_eq!(findings[0].status, IntegrityStatus::Ok);
        assert_eq!(findings[1].status, IntegrityStatus::Mismatch);
        assert_eq!(findings[2].status, IntegrityStatus::Missing);
    }

    #[test]
    fn pins_a_hash_without_losing_comments() {
        let raw = include_str!("../../manifest.toml");
        let digest = "b".repeat(64);
        let updated = pin(raw, "xftp-server", &digest, Some("v6.4.2")).expect("pin");

        assert!(
            updated.contains("# hearth — pinned upstream artefacts"),
            "comments kept"
        );
        let manifest: Manifest = toml::from_str(&updated).expect("still parses");
        let entry = manifest.binary("xftp-server").expect("entry");
        assert_eq!(entry.sha256, digest);
        assert_eq!(entry.version, "v6.4.2");
        // Other entries are untouched.
        assert_eq!(
            manifest.binary("smp-server").expect("entry").sha256,
            "0".repeat(64)
        );
    }

    #[test]
    fn pin_rejects_bad_input() {
        let raw = include_str!("../../manifest.toml");
        assert!(pin(raw, "smp-server", "not-a-hash", None).is_err());
        assert!(pin(raw, "does-not-exist", &"a".repeat(64), None).is_err());
    }

    #[test]
    fn known_sha256_vector() {
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

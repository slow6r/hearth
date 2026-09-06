//! Archive creation and age encryption, shared by [`crate::backup`] and
//! [`crate::migrate`] (ТЗ §7.3, §10.2).
//!
//! The pipeline is a single stream — `tar` → `gzip` → `age` → file — so a plaintext
//! copy of the relay CA and the store log never exists on disk, not even briefly.
//!
//! Decryption is deliberately *not* implemented as a daemon capability: the age
//! identity lives off the node (YubiKey / offline copy, ТЗ §7.3), so restoring is a
//! `hearthctl` operation the owner runs with the key in hand.

use std::io::Write as _;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr as _;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::model::manifest::sha256_file;

/// What went into an archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveInfo {
    pub path: PathBuf,
    pub size_bytes: u64,
    /// sha256 of the encrypted artefact, so a transfer can be verified.
    pub sha256: String,
    /// Directories included, as stored inside the tar.
    pub members: Vec<String>,
}

/// Build `tar.gz.age` from a list of directories.
///
/// Paths are stored without their leading `/`, so `/etc/opt/simplex` becomes
/// `etc/opt/simplex` and the archive extracts cleanly onto `/` on the new node.
/// Missing directories are skipped with a warning rather than failing the run: a node
/// without xftp still deserves a backup of everything else.
pub fn create_encrypted(
    sources: &[PathBuf],
    output: &Path,
    recipients: &[String],
) -> Result<ArchiveInfo> {
    if recipients.is_empty() {
        return Err(Error::Config("no age recipients configured".into()));
    }
    if let Some(parent) = output.parent() {
        crate::store::ensure_dir(parent)?;
    }

    let recipients = parse_recipients(recipients)?;
    let refs: Vec<&dyn age::Recipient> = recipients
        .iter()
        .map(|r| r as &dyn age::Recipient)
        .collect();
    let encryptor = age::Encryptor::with_recipients(refs.into_iter())
        .map_err(|e| Error::Crypto(format!("age recipients: {e}")))?;

    let file = std::fs::File::create(output).map_err(|e| Error::io(output, e))?;
    let age_writer = encryptor
        .wrap_output(file)
        .map_err(|e| Error::Crypto(format!("age: {e}")))?;
    let gz = flate2::write::GzEncoder::new(age_writer, flate2::Compression::default());

    let mut members = Vec::new();
    let mut builder = tar::Builder::new(gz);
    builder.follow_symlinks(false);
    for source in sources {
        if !source.exists() {
            tracing::warn!(path = %source.display(), "backup source is missing, skipped");
            continue;
        }
        let name = archive_name(source);
        builder
            .append_dir_all(&name, source)
            .map_err(|e| Error::io(source, e))?;
        members.push(name);
    }
    if members.is_empty() {
        return Err(Error::Config(
            "none of the configured backup paths exist".into(),
        ));
    }

    let gz = builder.into_inner().map_err(Error::RawIo)?;
    let age_writer = gz.finish().map_err(Error::RawIo)?;
    age_writer
        .finish()
        .map_err(|e| Error::Crypto(format!("age finish: {e}")))?
        .flush()
        .map_err(Error::RawIo)?;

    crate::store::set_mode(output, crate::store::MODE_SECRET)?;
    let size_bytes = std::fs::metadata(output)
        .map_err(|e| Error::io(output, e))?
        .len();
    Ok(ArchiveInfo {
        path: output.to_path_buf(),
        size_bytes,
        sha256: sha256_file(output)?,
        members,
    })
}

/// Decrypt and extract an archive into `dest` (`/` on a real restore).
///
/// `identity_file` holds the age secret key — supplied by the owner at restore time.
pub fn decrypt_and_extract(
    archive: &Path,
    identity_file: &Path,
    dest: &Path,
) -> Result<Vec<PathBuf>> {
    let identities = parse_identities(identity_file)?;
    let file = std::fs::File::open(archive).map_err(|e| Error::io(archive, e))?;
    let decryptor = age::Decryptor::new_buffered(std::io::BufReader::new(file))
        .map_err(|e| Error::Crypto(format!("age: {e}")))?;
    let reader = decryptor
        .decrypt(identities.iter().map(|i| i as &dyn age::Identity))
        .map_err(|e| Error::Crypto(format!("age decrypt (wrong key?): {e}")))?;

    let gz = flate2::read::GzDecoder::new(reader);
    let mut tar = tar::Archive::new(gz);
    tar.set_preserve_permissions(true);
    tar.set_overwrite(true);
    #[cfg(unix)]
    tar.set_preserve_ownerships(true);

    crate::store::ensure_dir(dest)?;
    let mut restored = Vec::new();
    for entry in tar.entries().map_err(Error::RawIo)? {
        let mut entry = entry.map_err(Error::RawIo)?;
        let path = entry.path().map_err(Error::RawIo)?.to_path_buf();
        reject_traversal(&path)?;
        entry.unpack_in(dest).map_err(|e| Error::io(&path, e))?;
        restored.push(path);
    }
    Ok(restored)
}

/// List the members of an encrypted archive without writing anything to disk.
pub fn list_members(archive: &Path, identity_file: &Path) -> Result<Vec<PathBuf>> {
    let identities = parse_identities(identity_file)?;
    let file = std::fs::File::open(archive).map_err(|e| Error::io(archive, e))?;
    let decryptor = age::Decryptor::new_buffered(std::io::BufReader::new(file))
        .map_err(|e| Error::Crypto(format!("age: {e}")))?;
    let reader = decryptor
        .decrypt(identities.iter().map(|i| i as &dyn age::Identity))
        .map_err(|e| Error::Crypto(format!("age decrypt (wrong key?): {e}")))?;
    let gz = flate2::read::GzDecoder::new(reader);
    let mut tar = tar::Archive::new(gz);
    let mut out = Vec::new();
    for entry in tar.entries().map_err(Error::RawIo)? {
        let entry = entry.map_err(Error::RawIo)?;
        out.push(entry.path().map_err(Error::RawIo)?.to_path_buf());
    }
    Ok(out)
}

fn parse_recipients(recipients: &[String]) -> Result<Vec<age::x25519::Recipient>> {
    recipients
        .iter()
        .map(|raw| {
            age::x25519::Recipient::from_str(raw.trim())
                .map_err(|e| Error::Crypto(format!("bad age recipient `{raw}`: {e}")))
        })
        .collect()
}

fn parse_identities(path: &Path) -> Result<Vec<age::x25519::Identity>> {
    let raw = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
    let identities: Vec<age::x25519::Identity> = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            age::x25519::Identity::from_str(line)
                .map_err(|e| Error::Crypto(format!("bad age identity: {e}")))
        })
        .collect::<Result<_>>()?;
    if identities.is_empty() {
        return Err(Error::Crypto(format!(
            "{} contains no age identity",
            path.display()
        )));
    }
    Ok(identities)
}

/// `/etc/opt/simplex` -> `etc/opt/simplex`; relative paths are kept as they are.
fn archive_name(path: &Path) -> String {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => parts.push("..".to_string()),
        }
    }
    parts.join("/")
}

/// Refuse any entry that would escape the destination when unpacked.
fn reject_traversal(path: &Path) -> Result<()> {
    // Checked on components rather than with `is_absolute`, which is platform-dependent:
    // `/etc/passwd` is not "absolute" on Windows, and this must be refused everywhere.
    let escapes = path.components().any(|c| {
        matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    });
    if escapes {
        return Err(Error::invalid(format!(
            "archive entry `{}` tries to escape the destination",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret as _;

    fn seed_tree(root: &Path) -> Vec<PathBuf> {
        let etc = root.join("etc/opt/simplex");
        let var = root.join("var/opt/simplex");
        std::fs::create_dir_all(&etc).expect("mkdir");
        std::fs::create_dir_all(&var).expect("mkdir");
        std::fs::write(etc.join("ca.key"), b"RELAY-CA-PRIVATE-KEY").expect("write");
        std::fs::write(etc.join("fingerprint"), b"abcdef").expect("write");
        std::fs::write(var.join("store.log"), b"encrypted-queues").expect("write");
        vec![etc, var]
    }

    fn keypair() -> (String, age::x25519::Identity) {
        let identity = age::x25519::Identity::generate();
        (identity.to_public().to_string(), identity)
    }

    #[test]
    fn round_trips_through_age() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sources = seed_tree(dir.path());
        let (recipient, identity) = keypair();
        let archive = dir.path().join("backup.tar.gz.age");

        let info = create_encrypted(&sources, &archive, &[recipient]).expect("create");
        assert!(info.size_bytes > 0);
        assert_eq!(info.sha256.len(), 64);
        assert_eq!(info.members.len(), 2);

        // The artefact must not contain the plaintext anywhere.
        let bytes = std::fs::read(&archive).expect("read");
        assert!(!contains(&bytes, b"RELAY-CA-PRIVATE-KEY"));
        assert!(bytes.starts_with(b"age-encryption.org/"));

        let identity_file = dir.path().join("key.txt");
        std::fs::write(&identity_file, identity.to_string().expose_secret()).expect("write key");

        let dest = dir.path().join("restored");
        let restored = decrypt_and_extract(&archive, &identity_file, &dest).expect("restore");
        assert!(!restored.is_empty());

        let restored_key = dest.join(archive_name(&sources[0])).join("ca.key");
        assert_eq!(
            std::fs::read(restored_key).expect("read restored"),
            b"RELAY-CA-PRIVATE-KEY"
        );
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sources = seed_tree(dir.path());
        let (recipient, _owner) = keypair();
        let (_other_pub, attacker) = keypair();
        let archive = dir.path().join("backup.tar.gz.age");
        create_encrypted(&sources, &archive, &[recipient]).expect("create");

        let wrong = dir.path().join("wrong.txt");
        std::fs::write(&wrong, attacker.to_string().expose_secret()).expect("write");
        let err = decrypt_and_extract(&archive, &wrong, &dir.path().join("out")).unwrap_err();
        assert!(err.to_string().contains("decrypt"), "got {err}");
    }

    #[test]
    fn lists_members_without_extracting() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sources = seed_tree(dir.path());
        let (recipient, identity) = keypair();
        let archive = dir.path().join("backup.tar.gz.age");
        create_encrypted(&sources, &archive, &[recipient]).expect("create");

        let key = dir.path().join("key.txt");
        std::fs::write(&key, identity.to_string().expose_secret()).expect("write");
        let members = list_members(&archive, &key).expect("list");
        assert!(members
            .iter()
            .any(|m| m.to_string_lossy().ends_with("ca.key")));
    }

    #[test]
    fn absolute_paths_become_relative_members() {
        assert_eq!(
            archive_name(Path::new("/etc/opt/simplex")),
            "etc/opt/simplex"
        );
        assert_eq!(archive_name(Path::new("/var/lib/hearth")), "var/lib/hearth");
    }

    #[test]
    fn traversal_entries_are_refused() {
        assert!(reject_traversal(Path::new("etc/../../root/.ssh")).is_err());
        assert!(reject_traversal(Path::new("/etc/passwd")).is_err());
        assert!(reject_traversal(Path::new("etc/opt/simplex/ca.key")).is_ok());
    }

    #[test]
    fn refuses_to_run_without_recipients() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sources = seed_tree(dir.path());
        let err = create_encrypted(&sources, &dir.path().join("x.age"), &[]).unwrap_err();
        assert!(err.to_string().contains("no age recipients"), "got {err}");
    }

    #[test]
    fn missing_sources_are_skipped_but_all_missing_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sources = seed_tree(dir.path());
        let (recipient, _id) = keypair();
        let mut with_missing = sources.clone();
        with_missing.push(dir.path().join("does-not-exist"));
        let info = create_encrypted(
            &with_missing,
            &dir.path().join("a.age"),
            std::slice::from_ref(&recipient),
        )
        .expect("create");
        assert_eq!(info.members.len(), 2);

        let err = create_encrypted(
            &[dir.path().join("nope")],
            &dir.path().join("b.age"),
            &[recipient],
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("none of the configured backup paths exist"));
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
}

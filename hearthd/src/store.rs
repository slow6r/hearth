//! Small persistence helpers: atomic JSON documents, append-only journals, secrets.
//!
//! Everything hearthd writes lands under one of the ТЗ §10.1 directories, is written
//! through a temp file + rename (so a power cut never leaves a half-written registry),
//! and gets restrictive permissions on unix.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{Error, Result};

/// `0600` — owner read/write. Used for secrets and anything holding relay passwords.
pub const MODE_SECRET: u32 = 0o600;
/// `0640` — owner write, group read. Used for state the admin group may inspect.
pub const MODE_STATE: u32 = 0o640;
/// `0640` — a secret that a DIFFERENT service has to read.
///
/// The rendered coturn config holds `static-auth-secret`, and on Debian coturn runs as
/// `User=turnserver` — not as `hearth`, and not as root. Written `0600` by `hearth`, the
/// file is unreadable by the only process that needs it, and coturn fails to start with
/// nothing but a permissions error to go on.
///
/// The mode alone would expose the secret to whatever group the file lands in, so it is
/// only half the mechanism: the containing directory is setgid `turnserver`, which is
/// what narrows "group" to exactly the service that must read it.
pub const MODE_SHARED_SECRET: u32 = 0o640;
/// `0750` — directories.
pub const MODE_DIR: u32 = 0o750;

/// Create a directory (and parents) with restrictive permissions.
pub fn ensure_dir(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    if path.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(path).map_err(|e| Error::io(path, e))?;
    set_mode(path, MODE_DIR)?;
    Ok(())
}

/// Apply a unix mode. No-op on other platforms (dev machines only).
pub fn set_mode(path: impl AsRef<Path>, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = path.as_ref();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| Error::io(path, e))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

/// Read a JSON document. Returns `Ok(None)` when the file does not exist yet.
pub fn read_json<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<Option<T>> {
    let path = path.as_ref();
    match std::fs::read_to_string(path) {
        Ok(raw) => {
            let value = serde_json::from_str(&raw)
                .map_err(|e| Error::Parse(format!("{}: {e}", path.display())))?;
            Ok(Some(value))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::io(path, e)),
    }
}

/// Write a JSON document atomically: temp file in the same directory, fsync, rename.
pub fn write_json_atomic<T: Serialize>(path: impl AsRef<Path>, value: &T, mode: u32) -> Result<()> {
    let path = path.as_ref();
    let body = serde_json::to_vec_pretty(value)?;
    write_atomic(path, &body, mode)
}

/// Atomic byte write with the given mode.
pub fn write_atomic(path: impl AsRef<Path>, body: &[u8], mode: u32) -> Result<()> {
    write_atomic_owned(path.as_ref(), body, mode, None)
}

/// Как [`write_atomic`], но новый файл получает владельца и группу прежнего.
///
/// Атомарная запись создаёт НОВЫЙ файл и переименовывает его поверх старого, поэтому
/// владельцем становится тот, кто пишет. Для файлов, которые правят через `sudo`, а
/// читает служба по группе, это ломает доступ: так 2026-09-11 `hearthctl manifest pin`
/// оставил `/etc/hearth/manifest.toml` с `root:root` вместо `root:hearth`, служба при
/// следующем старте не смогла его прочитать, сочла целостность нарушенной и
/// остановила релеи.
///
/// Владелец выставляется временному файлу ДО переименования: иначе на мгновение на
/// месте старого файла лежал бы файл, который служба прочитать не может. Если сменить
/// владельца нельзя, запись отменяется и старый файл остаётся как был.
pub fn write_atomic_keep_owner(path: impl AsRef<Path>, body: &[u8], mode: u32) -> Result<()> {
    let path = path.as_ref();
    #[cfg(unix)]
    let owner = {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata(path).ok().map(|m| (m.uid(), m.gid()))
    };
    #[cfg(not(unix))]
    let owner = None;
    write_atomic_owned(path, body, mode, owner)
}

fn write_atomic_owned(
    path: &Path,
    body: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_dir(parent)?;
        }
    }
    let tmp = tmp_path(path);
    {
        // The mode is applied at creation, not after writing. Creating with the default
        // umask and chmod-ing afterwards leaves a window — short, but real — where a
        // relay password or a private key is world-readable. `create_new` also refuses
        // to follow an existing file, so a predictable temp name cannot be used to
        // point the write somewhere else.
        let mut file = open_tmp(&tmp, mode)?;
        file.write_all(body).map_err(|e| Error::io(&tmp, e))?;
        file.sync_all().map_err(|e| Error::io(&tmp, e))?;
    }
    set_mode(&tmp, mode)?;
    if let Some((uid, gid)) = owner {
        if let Err(e) = set_owner(&tmp, uid, gid) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    }
    std::fs::rename(&tmp, path).map_err(|e| Error::io(path, e))?;
    Ok(())
}

fn set_owner(path: &Path, uid: u32, gid: u32) -> Result<()> {
    #[cfg(unix)]
    std::os::unix::fs::chown(path, Some(uid), Some(gid)).map_err(|e| Error::io(path, e))?;
    #[cfg(not(unix))]
    let _ = (path, uid, gid);
    Ok(())
}

/// Create the temp file with its final permissions already in place.
fn open_tmp(tmp: &Path, mode: u32) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;

    match options.open(tmp) {
        Ok(file) => Ok(file),
        // A leftover temp file from a killed process must not block writes forever.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(tmp).map_err(|e| Error::io(tmp, e))?;
            options.open(tmp).map_err(|e| Error::io(tmp, e))
        }
        Err(e) => Err(Error::io(tmp, e)),
    }
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{}", std::process::id()));
    path.with_file_name(name)
}

/// Append one line to a journal file (JSONL), creating it if needed.
pub fn append_line(path: impl AsRef<Path>, line: &str) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_dir(parent)?;
        }
    }
    let existed = path.exists();
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| Error::io(path, e))?;
    writeln!(file, "{line}").map_err(|e| Error::io(path, e))?;
    file.sync_data().map_err(|e| Error::io(path, e))?;
    if !existed {
        set_mode(path, MODE_STATE)?;
    }
    Ok(())
}

/// Read the last `limit` lines of a JSONL journal, oldest first.
pub fn tail_lines(path: impl AsRef<Path>, limit: usize) -> Result<Vec<String>> {
    let path = path.as_ref();
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::io(path, e)),
    };
    let lines: Vec<String> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect();
    let start = lines.len().saturating_sub(limit);
    Ok(lines[start..].to_vec())
}

/// Read a secret (relay password, TURN secret, Gotify token).
///
/// Trailing whitespace is stripped — an accidental newline in a password file would
/// otherwise change the queue-creation password and lock every client out.
pub fn read_secret(path: impl AsRef<Path>) -> Result<String> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
    let secret = raw.trim().to_string();
    if secret.is_empty() {
        return Err(Error::Config(format!(
            "secret file {} is empty",
            path.display()
        )));
    }
    warn_if_world_readable(path);
    Ok(secret)
}

/// Write a secret with `0600`.
pub fn write_secret(path: impl AsRef<Path>, secret: &str) -> Result<()> {
    write_atomic(path, format!("{secret}\n").as_bytes(), MODE_SECRET)
}

#[cfg(unix)]
fn warn_if_world_readable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o077;
        if mode != 0 {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{:o}", meta.permissions().mode() & 0o777),
                "secret file is readable beyond its owner"
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_world_readable(_path: &Path) {}

/// Generate `n` bytes of cryptographic randomness, hex-encoded.
///
/// Used for relay passwords and the TURN static secret.
pub fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

#[cfg(test)]
mod tests {

    #[test]
    fn write_keeping_owner_replaces_content_and_keeps_the_owner() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.toml");
        write_atomic(&path, b"old", MODE_STATE).unwrap();
        #[cfg(unix)]
        let before = {
            use std::os::unix::fs::MetadataExt as _;
            let m = std::fs::metadata(&path).unwrap();
            (m.uid(), m.gid())
        };
        write_atomic_keep_owner(&path, b"new", MODE_STATE).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let m = std::fs::metadata(&path).unwrap();
            assert_eq!((m.uid(), m.gid()), before);
        }
    }

    #[test]
    fn write_keeping_owner_creates_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fresh.toml");
        write_atomic_keep_owner(&path, b"x", MODE_STATE).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
    }
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Doc {
        a: u32,
    }

    #[test]
    fn json_round_trip_is_atomic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("doc.json");
        assert_eq!(read_json::<Doc>(&path).expect("missing ok"), None);
        write_json_atomic(&path, &Doc { a: 7 }, MODE_STATE).expect("write");
        assert_eq!(read_json::<Doc>(&path).expect("read"), Some(Doc { a: 7 }));
        // No temp files left behind.
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().expect("parent"))
            .expect("readdir")
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn journal_appends_and_tails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("alerts.jsonl");
        for i in 0..5 {
            append_line(&path, &format!("line{i}")).expect("append");
        }
        let tail = tail_lines(&path, 2).expect("tail");
        assert_eq!(tail, vec!["line3".to_string(), "line4".to_string()]);
        assert_eq!(
            tail_lines(dir.path().join("nope"), 10).expect("missing"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn secrets_are_trimmed_and_non_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pass");
        write_secret(&path, "s3cret").expect("write");
        assert_eq!(read_secret(&path).expect("read"), "s3cret");
        write_atomic(&path, b"   \n", MODE_SECRET).expect("write empty");
        assert!(read_secret(&path).is_err());
    }

    #[test]
    fn random_hex_has_expected_length_and_varies() {
        let a = random_hex(24);
        let b = random_hex(24);
        assert_eq!(a.len(), 48);
        assert_ne!(a, b);
    }
}

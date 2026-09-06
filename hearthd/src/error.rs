//! Error type shared by every `hearthd` module.
//!
//! Rule of the house (ТЗ §7.2): no panics in production paths. Everything that can
//! fail returns [`Result`]. `unwrap`/`expect` are denied by lint in `lib.rs`.

use std::path::Path;

/// All failures `hearthd` can produce.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("config: {0}")]
    Config(String),

    #[error("io: {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("io: {0}")]
    RawIo(#[from] std::io::Error),

    #[error("command `{cmd}` failed ({status}): {stderr}")]
    Command {
        cmd: String,
        status: String,
        stderr: String,
    },

    #[error("parse: {0}")]
    Parse(String),

    /// Raised by [`crate::net::EgressPolicy`] before any socket is opened.
    #[error("egress denied: {0} is outside the allowed home networks")]
    EgressDenied(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("invalid: {0}")]
    Invalid(String),

    #[error("integrity: {0}")]
    Integrity(String),

    #[error("crypto: {0}")]
    Crypto(String),

    #[error("tls: {0}")]
    Tls(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("timeout after {0:?}")]
    Timeout(std::time::Duration),
}

impl Error {
    /// Attach a path to an [`std::io::Error`] so operators get an actionable message.
    pub fn io(path: impl AsRef<Path>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.as_ref().display().to_string(),
            source,
        }
    }

    pub fn config(msg: impl Into<String>) -> Self {
        Error::Config(msg.into())
    }

    pub fn parse(msg: impl Into<String>) -> Self {
        Error::Parse(msg.into())
    }

    pub fn invalid(msg: impl Into<String>) -> Self {
        Error::Invalid(msg.into())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Parse(format!("json: {e}"))
    }
}

impl From<toml::de::Error> for Error {
    fn from(e: toml::de::Error) -> Self {
        Error::Parse(format!("toml: {e}"))
    }
}

impl From<rustls::Error> for Error {
    fn from(e: rustls::Error) -> Self {
        Error::Tls(e.to_string())
    }
}

impl From<rcgen::Error> for Error {
    fn from(e: rcgen::Error) -> Self {
        Error::Crypto(format!("rcgen: {e}"))
    }
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

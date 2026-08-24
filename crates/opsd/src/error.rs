//! Crate-wide error type. `thiserror` is intentionally not pulled in — the
//! workspace dependency policy keeps the new-dep list short, and the handful
//! of variants here is cheap to write out by hand.

use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum OpsdError {
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
    Http(reqwest::Error),
    Ssh(crate::ssh::SshError),
    /// No `env/mlc-utah-1` directory found walking up from the cwd — the
    /// binary was launched outside the nemo checkout.
    NemoRootNotFound,
    /// `<state_dir>/api-key` exists but is not 64 lowercase/uppercase hex.
    BadApiKeyFile(PathBuf),
    /// A canonical secret file needed for unlock is missing or malformed.
    CanonSecret(String),
    /// Remote command ran but reported failure.
    Remote(String),
}

impl fmt::Display for OpsdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpsdError::Io(e) => write!(f, "io: {e}"),
            OpsdError::Sqlite(e) => write!(f, "sqlite: {e}"),
            OpsdError::Http(e) => write!(f, "http: {e}"),
            OpsdError::Ssh(e) => write!(f, "ssh: {e}"),
            OpsdError::NemoRootNotFound => {
                write!(f, "nemo root not found (no env/mlc-utah-1 above cwd)")
            }
            OpsdError::BadApiKeyFile(p) => {
                write!(f, "api key file {} is malformed (want 64 hex chars)", p.display())
            }
            OpsdError::CanonSecret(m) => write!(f, "canonical secret: {m}"),
            OpsdError::Remote(m) => write!(f, "remote: {m}"),
        }
    }
}

impl std::error::Error for OpsdError {}

impl From<std::io::Error> for OpsdError {
    fn from(e: std::io::Error) -> Self {
        OpsdError::Io(e)
    }
}

impl From<rusqlite::Error> for OpsdError {
    fn from(e: rusqlite::Error) -> Self {
        OpsdError::Sqlite(e)
    }
}

impl From<reqwest::Error> for OpsdError {
    fn from(e: reqwest::Error) -> Self {
        OpsdError::Http(e)
    }
}

impl From<crate::ssh::SshError> for OpsdError {
    fn from(e: crate::ssh::SshError) -> Self {
        OpsdError::Ssh(e)
    }
}

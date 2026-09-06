//! [`DaemonConfig`] — everything [`crate::run`] needs for the evaluation
//! loop itself. Does NOT carry the standalone binary's own health-server
//! bind address/port (`BIND_ADDR`/`MLC_ALERT_DAEMON_PORT`) — those only
//! matter to a process running this crate as its own binary and are read
//! directly by `main.rs` instead, since the embedded-in-`mylittlechart-
//! server` mode this crate's module doc describes has no independent
//! health port at all (its counters ride on the host server's own
//! `/health`).

use std::fmt;
use std::time::Duration;

const DEFAULT_POLL_SECS: u64 = 30;
const DEFAULT_DATA_DIR: &str = "./data";

/// Configuration for [`crate::run`].
///
/// Construct via [`DaemonConfig::from_env`] for a standalone process
/// (`main.rs`), or build one directly when embedding this crate in another
/// process — `mylittlechart-server` does this, handing over the SQLCipher
/// key material it already read at boot instead of asking this crate to
/// read a second copy from `MLC_DB_KEY_HEX` (see this crate's module doc).
pub struct DaemonConfig {
    /// `mylittlechart.db` path — opened read-only, never written to (see
    /// `identity_db.rs`'s module doc).
    pub identity_db_path: String,
    /// This crate's own bookkeeping file (`alert_daemon.db`) — the ONE
    /// database it writes.
    pub store_db_path: String,
    /// SQLCipher key for `identity_db_path`, as a hex string. [`crate::run`]
    /// zeroizes this immediately after the read-only connection opens —
    /// never logged, never `Debug`-printed (see the manual [`fmt::Debug`]
    /// impl below).
    pub db_key_hex: String,
    /// Same bot token `tg-login-bot` uses (`TELEGRAM_BOT_TOKEN`) — one bot,
    /// one delivery channel.
    pub telegram_bot_token: String,
    pub poll_interval: Duration,
}

// Manual `Debug`: the derived version would print `db_key_hex` and
// `telegram_bot_token` in full — both are secrets this crate promises
// never to log.
impl fmt::Debug for DaemonConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DaemonConfig")
            .field("identity_db_path", &self.identity_db_path)
            .field("store_db_path", &self.store_db_path)
            .field("db_key_hex", &"<redacted>")
            .field("telegram_bot_token", &"<redacted>")
            .field("poll_interval", &self.poll_interval)
            .finish()
    }
}

#[derive(Debug)]
pub enum ConfigError {
    MissingEnv(&'static str),
    InvalidKeyHex,
    InvalidPollSecs(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::MissingEnv(name) => write!(f, "missing required env var {name}"),
            ConfigError::InvalidKeyHex => write!(f, "MLC_DB_KEY_HEX is empty after trimming"),
            ConfigError::InvalidPollSecs(v) => {
                write!(f, "MLC_ALERT_POLL_SECS {v:?} is not a valid positive integer")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl DaemonConfig {
    /// Standalone-process construction from environment variables — see
    /// this crate's `main.rs` module doc for the full env-var list.
    pub fn from_env() -> Result<Self, ConfigError> {
        let data_dir = std::env::var("MLC_DATA_DIR").unwrap_or_else(|_| DEFAULT_DATA_DIR.to_string());

        let db_key_hex_raw = std::env::var("MLC_DB_KEY_HEX").map_err(|_| ConfigError::MissingEnv("MLC_DB_KEY_HEX"))?;
        let db_key_hex = normalize_key_hex(&db_key_hex_raw).ok_or(ConfigError::InvalidKeyHex)?;

        let telegram_bot_token =
            std::env::var("TELEGRAM_BOT_TOKEN").map_err(|_| ConfigError::MissingEnv("TELEGRAM_BOT_TOKEN"))?;

        let poll_secs = match std::env::var("MLC_ALERT_POLL_SECS") {
            Ok(v) => {
                let parsed = v.parse::<u64>().map_err(|_| ConfigError::InvalidPollSecs(v.clone()))?;
                if parsed == 0 {
                    return Err(ConfigError::InvalidPollSecs(v));
                }
                parsed
            }
            Err(_) => DEFAULT_POLL_SECS,
        };

        Ok(DaemonConfig {
            identity_db_path: format!("{data_dir}/mylittlechart.db"),
            store_db_path: format!("{data_dir}/alert_daemon.db"),
            db_key_hex,
            telegram_bot_token,
            poll_interval: Duration::from_secs(poll_secs),
        })
    }
}

/// Same normalization idiom as `mylittlechart-server`'s private
/// `db::db_key_hex` (accept 64 hex chars, or raw key bytes to be hex
/// encoded) — reimplemented here because that function is private to
/// `db.rs` and this crate has no library surface of that binary crate to
/// depend on (see `identity_db.rs`'s module doc).
fn normalize_key_hex(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some(trimmed.to_lowercase());
    }
    Some(hex::encode(trimmed.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_key_hex_accepts_64_char_hex_and_lowercases_it() {
        let hex64 = "AB".repeat(32);
        assert_eq!(normalize_key_hex(&hex64), Some(hex64.to_lowercase()));
    }

    #[test]
    fn normalize_key_hex_hex_encodes_raw_bytes() {
        assert_eq!(normalize_key_hex("not-hex"), Some(hex::encode("not-hex")));
    }

    #[test]
    fn normalize_key_hex_trims_whitespace_and_rejects_empty() {
        assert_eq!(normalize_key_hex("   \n"), None);
        assert_eq!(normalize_key_hex(""), None);
    }

    #[test]
    fn debug_impl_redacts_secrets() {
        let cfg = DaemonConfig {
            identity_db_path: "./data/mylittlechart.db".to_string(),
            store_db_path: "./data/alert_daemon.db".to_string(),
            db_key_hex: "deadbeef".repeat(8),
            telegram_bot_token: "123:supersecret".to_string(),
            poll_interval: Duration::from_secs(30),
        };
        let printed = format!("{cfg:?}");
        assert!(!printed.contains("deadbeef"));
        assert!(!printed.contains("supersecret"));
        assert!(printed.contains("<redacted>"));
    }
}

//! Environment configuration — see the crate's `main.rs` doc comment for
//! the full env-var list and rationale.

use std::fmt;
use std::time::Duration;

const DEFAULT_PORT: u16 = 19210;
const DEFAULT_POLL_SECS: u64 = 30;
const DEFAULT_BIND_ADDR: &str = "127.0.0.1";
const DEFAULT_DATA_DIR: &str = "./data";

#[derive(Debug)]
pub struct Config {
    /// `{data_dir}/mylittlechart.db` — read-only.
    pub identity_db_path: String,
    /// `{data_dir}/alert_daemon.db` — this daemon's own bookkeeping file.
    pub store_db_path: String,
    pub db_key_hex: String,
    pub telegram_bot_token: String,
    pub bind_addr: String,
    pub port: u16,
    pub poll_interval: Duration,
}

#[derive(Debug)]
pub enum ConfigError {
    MissingEnv(&'static str),
    InvalidKeyHex,
    InvalidPort(String),
    InvalidPollSecs(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::MissingEnv(name) => write!(f, "missing required env var {name}"),
            ConfigError::InvalidKeyHex => write!(f, "MLC_DB_KEY_HEX is empty after trimming"),
            ConfigError::InvalidPort(v) => write!(f, "MLC_ALERT_DAEMON_PORT {v:?} is not a valid u16"),
            ConfigError::InvalidPollSecs(v) => {
                write!(f, "MLC_ALERT_POLL_SECS {v:?} is not a valid positive integer")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let data_dir = std::env::var("MLC_DATA_DIR").unwrap_or_else(|_| DEFAULT_DATA_DIR.to_string());

        let db_key_hex_raw = std::env::var("MLC_DB_KEY_HEX").map_err(|_| ConfigError::MissingEnv("MLC_DB_KEY_HEX"))?;
        let db_key_hex = normalize_key_hex(&db_key_hex_raw).ok_or(ConfigError::InvalidKeyHex)?;

        let telegram_bot_token =
            std::env::var("TELEGRAM_BOT_TOKEN").map_err(|_| ConfigError::MissingEnv("TELEGRAM_BOT_TOKEN"))?;

        let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());

        let port = match std::env::var("MLC_ALERT_DAEMON_PORT") {
            Ok(v) => v.parse::<u16>().map_err(|_| ConfigError::InvalidPort(v))?,
            Err(_) => DEFAULT_PORT,
        };

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

        Ok(Config {
            identity_db_path: format!("{data_dir}/mylittlechart.db"),
            store_db_path: format!("{data_dir}/alert_daemon.db"),
            db_key_hex,
            telegram_bot_token,
            bind_addr,
            port,
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
}

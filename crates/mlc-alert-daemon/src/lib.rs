//! `mlc-alert-daemon` — server-side evaluation loop for account-wide Price
//! alerts (plan `docs/mlc/plans/alerts-account-wide-and-telegram-delivery-
//! 2026-09-06.md` §3 "Server evaluation — Price-source only", §6 step 4).
//!
//! Reads `alerts`-category sync items read-only from the identity database
//! `mylittlechart-server` owns (`identity_db.rs`), runs a stateless
//! price-crossing check (`crossing.rs`) against a per-alert in-memory
//! cache (`eval.rs`), and delivers a Telegram DM (`telegram.rs`) via the
//! same `mylittlechart_login_bot` identity `routes/tg_login.rs` already
//! resolves `tg_user_id` for — paid accounts with a linked Telegram
//! identity only (`gate.rs`). This process never writes to the identity
//! database; it keeps its own bookkeeping (`alert_daemon.db`, `store.rs`)
//! as the single writer for that one small file.
//!
//! # Two run modes
//!
//! 1. **Standalone binary** (`main.rs`) — a sibling process to
//!    `mylittlechart-server`, reading its own copy of the SQLCipher key
//!    from `MLC_DB_KEY_HEX`. This was the original shape, and still works
//!    for local runs, but it cannot be deployed as-is: the box that runs
//!    `mylittlechart-server` deliberately keeps NO copy of the SQLCipher
//!    key on disk after boot (`db::read_sqlcipher_key` deletes the tmpfs
//!    handoff file after its one read), so nothing can hand a second copy
//!    to a separate process without inventing a new key-distribution
//!    channel.
//! 2. **Embedded in `mylittlechart-server`** — the deployed shape.
//!    `mylittlechart-server`'s `main.rs` spawns [`run`] as a background
//!    task on its own tokio runtime, passing the SAME `key_hex` it already
//!    read for its own databases. [`run`] opens its OWN
//!    `SQLITE_OPEN_READ_ONLY` connection from that key — it never shares
//!    the server's writer connection (see `identity_db.rs`'s module doc) —
//!    and zeroizes its copy of the key material immediately afterward.
//!    Gated by `MLC_ALERT_DAEMON=1` (default off), with counters exposed
//!    on the server's own `/health` endpoint instead of a second listener.

mod alert_item;
mod config;
mod crossing;
mod eval;
mod gate;
mod health;
mod identity_db;
mod price_source;
mod store;
pub mod telegram;

pub use config::{ConfigError, DaemonConfig};
pub use health::{DaemonStats, HealthBody};

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{watch, Mutex};

use eval::EvalState;
use price_source::PriceCache;

/// Errors [`run`] can return before entering its loop — opening either
/// database, or building the HTTP client. Once inside the loop, per-cycle
/// errors are logged and the loop continues instead (see `eval::run_once`'s
/// doc comment) — a transient database or network hiccup must not end a
/// process a whole server is embedding.
#[derive(Debug)]
pub enum RunError {
    Identity(rusqlite::Error),
    Store(rusqlite::Error),
    Http(reqwest::Error),
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunError::Identity(e) => write!(f, "failed to open the identity database read-only: {e}"),
            RunError::Store(e) => write!(f, "failed to open the alert-daemon store database: {e}"),
            RunError::Http(e) => write!(f, "failed to build the HTTP client: {e}"),
        }
    }
}

impl std::error::Error for RunError {}

/// Runs the evaluation loop until `shutdown` reports `true`, or forever if
/// it never does.
///
/// Opens its own read-only connection to `cfg.identity_db_path` keyed by
/// `cfg.db_key_hex` — this function never accepts, nor shares, a caller's
/// existing connection (see this crate's module doc for why a second,
/// independent connection is the deliberate shape here). `cfg.db_key_hex`
/// is zeroized in place immediately after that connection opens
/// successfully, whether `cfg` was built from `MLC_DB_KEY_HEX`
/// ([`DaemonConfig::from_env`]) or handed over directly by an embedding
/// process.
pub async fn run(mut cfg: DaemonConfig, mut shutdown: watch::Receiver<bool>, stats: Arc<DaemonStats>) -> Result<(), RunError> {
    let identity_conn =
        identity_db::open_identity_db_readonly(&cfg.identity_db_path, &cfg.db_key_hex).map_err(RunError::Identity)?;
    zeroize_string(&mut cfg.db_key_hex);

    let store_conn = store::open_store(&cfg.store_db_path).map_err(RunError::Store)?;

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(RunError::Http)?;

    let state = Arc::new(EvalState {
        identity_conn: Mutex::new(identity_conn),
        store_conn: Mutex::new(store_conn),
        http,
        // A refetch floor shorter than the evaluation cycle would only add
        // network calls the cycle can never observe; this simply mirrors
        // the poll interval.
        price_cache: Mutex::new(PriceCache::new(cfg.poll_interval)),
        prev_price: Mutex::new(HashMap::new()),
        telegram_bot_token: cfg.telegram_bot_token.clone(),
        counters: stats.clone(),
    });

    let mut ticker = tokio::time::interval(cfg.poll_interval);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Err(e) = eval::run_once(&state).await {
                    tracing::error!("alert evaluation cycle failed: {e}");
                }
                stats.last_cycle_at.store(chrono::Utc::now().timestamp_millis(), Ordering::Relaxed);
            }
            changed = shutdown.changed() => {
                // An `Err` here means the sender was dropped without ever
                // sending `true` — treat that the same as a clean shutdown
                // request rather than looping on a channel nothing can
                // signal through anymore.
                if changed.is_err() || *shutdown.borrow() {
                    tracing::info!("mlc-alert-daemon: shutdown requested, stopping evaluation loop");
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Overwrites every byte of `s` with `0` in place, then clears it — used to
/// scrub SQLCipher key material out of process memory as soon as it is no
/// longer needed, rather than leaving it for the allocator to reuse
/// unzeroed whenever the `String` eventually drops.
fn zeroize_string(s: &mut String) {
    // SAFETY: `as_bytes_mut` requires the caller to keep the buffer valid
    // UTF-8. `0` (NUL) is itself a valid single-byte UTF-8 code point, so
    // overwriting every byte with it cannot produce invalid UTF-8.
    unsafe {
        for b in s.as_bytes_mut() {
            *b = 0;
        }
    }
    s.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_string_clears_contents() {
        let mut s = "supersecretkeyhex".to_string();
        zeroize_string(&mut s);
        assert_eq!(s, "");
    }
}

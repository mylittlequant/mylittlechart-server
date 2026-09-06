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
//! Sibling binary to `mylittlechart-server` (`dig2pay-server` precedent) —
//! NOT embedded in the server process, so closing that process (or this
//! one) never silently drops the other's duties.
//!
//! Configuration via environment variables:
//!   MLC_DATA_DIR           — directory holding `mylittlechart.db` (opened
//!                            read-only) and this daemon's own
//!                            `alert_daemon.db` (default: `./data`). MUST
//!                            be the same directory `mylittlechart-server`'s
//!                            own `DATA_DIR` points at — this process never
//!                            creates the identity database, only opens it.
//!   MLC_DB_KEY_HEX         — the SQLCipher key for `mylittlechart.db` (64
//!                            hex chars, or raw key bytes). NOTE: this is
//!                            NOT the tmpfs handoff `db::read_sqlcipher_key`
//!                            uses on the main server — that file is
//!                            deleted after its one read at server boot, so
//!                            a second process cannot race it for the same
//!                            key. Whatever starts this daemon must inject
//!                            its own copy of the same key material through
//!                            this env var instead — see `identity_db.rs`'s
//!                            module doc for the exposure trade-off that
//!                            implies.
//!   TELEGRAM_BOT_TOKEN     — same bot token `mylittlechart-server` uses
//!                            for `tg-login-bot` (`mylittlechart_login_bot`)
//!                            — one bot, one identity plane, one delivery
//!                            channel.
//!   BIND_ADDR              — health endpoint bind address (default: 127.0.0.1)
//!   MLC_ALERT_DAEMON_PORT  — health endpoint port (default: 19210)
//!   MLC_ALERT_POLL_SECS    — evaluation cycle interval in seconds (default: 30)

mod alert_item;
mod config;
mod crossing;
mod eval;
mod gate;
mod health;
mod identity_db;
mod price_source;
mod store;
mod telegram;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use tokio::sync::Mutex;

use config::Config;
use eval::EvalState;
use health::Counters;
use price_source::PriceCache;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let config = Config::from_env()?;
    tracing::info!(
        "mlc-alert-daemon starting: identity_db={} store_db={} poll_secs={} bind={}:{}",
        config.identity_db_path,
        config.store_db_path,
        config.poll_interval.as_secs(),
        config.bind_addr,
        config.port
    );

    let identity_conn = identity_db::open_identity_db_readonly(&config.identity_db_path, &config.db_key_hex)?;
    let store_conn = store::open_store(&config.store_db_path)?;

    let counters = Arc::new(Counters::default());

    let state = Arc::new(EvalState {
        identity_conn: Mutex::new(identity_conn),
        store_conn: Mutex::new(store_conn),
        http: reqwest::Client::builder().timeout(Duration::from_secs(15)).build()?,
        // A refetch floor shorter than the evaluation cycle would only add
        // network calls the cycle can never observe; this simply mirrors
        // the poll interval.
        price_cache: Mutex::new(PriceCache::new(config.poll_interval)),
        prev_price: Mutex::new(HashMap::new()),
        telegram_bot_token: config.telegram_bot_token.clone(),
        counters: counters.clone(),
    });

    let eval_task = tokio::spawn(eval::run_forever(state, config.poll_interval));

    let app = Router::new().route("/health", get(health::health_handler)).with_state(counters);

    let addr = format!("{}:{}", config.bind_addr, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("mlc-alert-daemon health endpoint listening on {addr}");

    tokio::select! {
        res = axum::serve(listener, app) => {
            if let Err(e) = res {
                tracing::error!("health server exited: {e}");
            }
        }
        _ = eval_task => {
            tracing::error!("evaluation loop exited unexpectedly");
        }
    }

    Ok(())
}

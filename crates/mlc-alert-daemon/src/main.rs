//! `mlc-alert-daemon` — standalone-binary entry point for the evaluation
//! loop this crate's library half (`lib.rs`) implements.
//!
//! This binary is the ORIGINAL, standalone-process shape: a sibling to
//! `mylittlechart-server`, reading its own copy of the SQLCipher key from
//! `MLC_DB_KEY_HEX`. It still works for local runs and manual testing, but
//! it is NOT how this crate is deployed — see `lib.rs`'s module doc for why
//! (the deploy box keeps no SQLCipher key on disk after boot) and for the
//! embedded-in-`mylittlechart-server` mode that replaces it in production.
//!
//! Configuration via environment variables:
//!   MLC_DATA_DIR           — directory holding `mylittlechart.db` (opened
//!                            read-only) and this daemon's own
//!                            `alert_daemon.db` (default: `./data`). MUST
//!                            be the same directory `mylittlechart-server`'s
//!                            own `DATA_DIR` points at.
//!   MLC_DB_KEY_HEX         — the SQLCipher key for `mylittlechart.db` (64
//!                            hex chars, or raw key bytes). See `lib.rs`'s
//!                            module doc for why this process needs its own
//!                            copy rather than racing the server's one-time
//!                            tmpfs read.
//!   TELEGRAM_BOT_TOKEN     — same bot token `mylittlechart-server` uses
//!                            for `tg-login-bot` (`mylittlechart_login_bot`)
//!                            — one bot, one identity plane, one delivery
//!                            channel.
//!   MLC_ALERT_POLL_SECS    — evaluation cycle interval in seconds (default: 30)
//!   BIND_ADDR              — health endpoint bind address (default: 127.0.0.1)
//!   MLC_ALERT_DAEMON_PORT  — health endpoint port (default: 19210)

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};

use mlc_alert_daemon::{DaemonConfig, DaemonStats, HealthBody};

const DEFAULT_PORT: u16 = 19210;
const DEFAULT_BIND_ADDR: &str = "127.0.0.1";

async fn health_handler(State(stats): State<Arc<DaemonStats>>) -> Json<HealthBody> {
    Json(stats.snapshot())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let config = DaemonConfig::from_env()?;
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());
    let port: u16 = std::env::var("MLC_ALERT_DAEMON_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    tracing::info!(
        "mlc-alert-daemon starting: identity_db={} store_db={} poll_secs={} bind={}:{}",
        config.identity_db_path,
        config.store_db_path,
        config.poll_interval.as_secs(),
        bind_addr,
        port
    );

    let stats = Arc::new(DaemonStats::default());

    // A local shutdown channel, tripped by Ctrl-C — this standalone binary
    // has no shared shutdown broadcast to bridge into, unlike the embedded
    // mode inside `mylittlechart-server`.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::info!("mlc-alert-daemon: shutdown signal received");
            let _ = shutdown_tx.send(true);
        }
    });

    let eval_task = tokio::spawn(mlc_alert_daemon::run(config, shutdown_rx, stats.clone()));

    let app = Router::new().route("/health", get(health_handler)).with_state(stats);

    let addr = format!("{bind_addr}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("mlc-alert-daemon health endpoint listening on {addr}");

    tokio::select! {
        res = axum::serve(listener, app) => {
            if let Err(e) = res {
                tracing::error!("health server exited: {e}");
            }
        }
        res = eval_task => {
            match res {
                Ok(Ok(())) => tracing::info!("evaluation loop stopped"),
                Ok(Err(e)) => tracing::error!("evaluation loop failed: {e}"),
                Err(e) => tracing::error!("evaluation loop task panicked: {e}"),
            }
        }
    }

    Ok(())
}

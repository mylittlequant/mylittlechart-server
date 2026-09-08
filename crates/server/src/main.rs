//! mylittlechart-server — production server for mylittlechart.org
//!
//! Serves:
//! - Static landing page from `../landing-pure/web/`
//! - OTA update manifest and binary downloads
//! - Telemetry collection
//! - OAuth authentication (GitHub, Discord, Telegram)
//! - Device heartbeat registration
//!
//! Configuration via environment variables:
//!   PORT                   — listen port (default: 19200)
//!   BIND_ADDR              — listen address (default: 127.0.0.1; set to the
//!                            WireGuard address on a control box so edges can
//!                            reach it, never to a public interface)
//!   ADMIN_SECRET           — bearer token for admin upload endpoint
//!   GITHUB_CLIENT_ID       — GitHub OAuth app client ID
//!   GITHUB_CLIENT_SECRET   — GitHub OAuth app client secret
//!   DISCORD_CLIENT_ID      — Discord OAuth app client ID
//!   DISCORD_CLIENT_SECRET  — Discord OAuth app client secret
//!   TELEGRAM_BOT_TOKEN     — Telegram bot token for login widget verification
//!   DATA_DIR               — directory for the databases, the hot sync store
//!                            and screenshot-share blobs (`share/`, see
//!                            routes/share.rs; default: ./data). No release
//!                            artifacts live here — those are on the public
//!                            edges, see routes/admin.rs and routes/updates.rs.
//!   BUILD_ATTEST_PUBKEY    — hex-encoded Ed25519 public key(s), comma-separated (optional)
//!   BUILD_ATTEST_ENFORCE   — "true"/"1" to reject unsigned clients (default: false)
//!   BUILD_ATTEST_MAX_AGE_DAYS — max build age in days (default: 365)
//!   MLC_DBKEY_PATH         — SQLCipher key file in tmpfs (default: /run/mlc/dbkey)
//!   MLC_TELEMETRY_RETENTION_DAYS — days of `device_metrics` rows (the
//!                            telemetry time series) to keep in the
//!                            operational database before the periodic
//!                            cleanup task deletes them (default: 30).
//!   MLC_TELEMETRY_DAILY_CAP — max `device_metrics` rows accepted per device
//!                            per UTC calendar day; over-cap posts are
//!                            dropped silently (default: 48).
//!   MLC_DEVICE_PROFILE_RETENTION_DAYS — days a `device_profile` row may go
//!                            untouched before the periodic cleanup task
//!                            deletes it (default: 180).
//!   MLC_FREE_FEATURES      — comma-separated feature names granted to every
//!                            caller with no paid claim (see entitlements.rs).
//!                            Unset (default): every feature is free — this is
//!                            what makes the paywall inert until deliberately
//!                            flipped. Valid names: multi_profile,
//!                            archive_proxy. Replaces the old MLC_PROXY_GATE.
//!   MLC_ROLE               — "control" (default) or "edge". Control runs the
//!                            database and every identity/sync/admin route.
//!                            Edge never opens a database — it boots with no
//!                            control plane and mounts only the stateless
//!                            subset (see routes::edge_api_router).
//!   MLC_ALERT_DAEMON       — "1" to run the `mlc-alert-daemon` account-wide
//!                            price-alert evaluation loop as a background
//!                            task on this process's own tokio runtime
//!                            (control role only). Default off, so this
//!                            deploy stays inert until the toggle is set.
//!                            The loop opens its OWN read-only SQLCipher
//!                            connection to `mylittlechart.db`, keyed from
//!                            the SAME `key_hex` this process already read
//!                            for its own databases — see
//!                            `mlc_alert_daemon`'s crate-level doc for why a
//!                            separate process cannot get that key at all
//!                            (the box keeps no copy of it on disk after
//!                            boot).
//!   MLC_ALERT_POLL_SECS    — alert-evaluation cycle interval in seconds
//!                            for the above (default: 30). Ignored when
//!                            `MLC_ALERT_DAEMON` is off.

use std::sync::{Arc, Mutex};

use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;

mod account_merge;
mod auth;
mod build_attest;
mod db;
mod dm_db;
mod entitlements;
mod models;
mod opswriter;
mod pathutil;
mod routes;
mod social_db;
mod state;
mod syncstore;

use state::AppState;

/// `GET /` → 301 to the app root on the public domain.
///
/// The edges proxy the legacy `/home` path to this backend's `/`, which used
/// to render a marketing landing page (deleted per the 2026-09-05
/// web-surface-cleanup plan). Redirecting `/` here kills `/home` without
/// touching the edges' nginx config — nginx is provisioned by hand over ssh
/// and there is no delivery script for it (see the static-file fallback
/// further down, which still serves everything else).
async fn redirect_to_app_root() -> axum::response::Response {
    axum::response::Response::builder()
        .status(301)
        .header("location", "https://mylittlechart.org/")
        .body(axum::body::Body::empty())
        .unwrap()
}

/// `GET /health` body — the liveness probe d-watchdog polls, extended
/// (2026-09-06) with the embedded alert daemon's counters (see this file's
/// module doc for `MLC_ALERT_DAEMON`). d-watchdog itself only checks the
/// status code, never the body, so widening this from the old plain-text
/// `"ok"` response cannot break its healthcheck.
#[derive(serde::Serialize)]
struct HealthResponse {
    status: &'static str,
    alert_daemon: state::AlertDaemonHealth,
}

async fn health_handler(
    axum::extract::State(app_state): axum::extract::State<Arc<AppState>>,
) -> axum::Json<HealthResponse> {
    axum::Json(HealthResponse {
        status: "ok",
        alert_daemon: app_state.alert_daemon_health(),
    })
}

/// Middleware that injects security headers into every response on the main router.
async fn security_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(
        "strict-transport-security",
        "max-age=63072000; includeSubDomains; preload"
            .parse()
            .unwrap(),
    );
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert(
        "referrer-policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    response
}

#[tokio::main]
async fn main() {
    // Load .env file (if present) into process environment.
    let _ = dotenvy::dotenv();

    // Initialize structured logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mylittlechart_server=info,tower_http=info".into()),
        )
        .init();

    // Which role this process plays (2026-08-30 control/edge split, see
    // state.rs). Read once, before anything role-dependent below.
    let role = state::ServerRole::from_env();
    tracing::info!("Server role: {}", role);

    // Read configuration from environment.
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(19200);

    let admin_secret = std::env::var("ADMIN_SECRET").unwrap_or_else(|_| {
        tracing::warn!("ADMIN_SECRET not set — admin upload will be inaccessible");
        String::new()
    });

    let github_client_id = std::env::var("GITHUB_CLIENT_ID").unwrap_or_default();
    let github_client_secret = std::env::var("GITHUB_CLIENT_SECRET").unwrap_or_default();
    let discord_client_id = std::env::var("DISCORD_CLIENT_ID").unwrap_or_default();
    let discord_client_secret = std::env::var("DISCORD_CLIENT_SECRET").unwrap_or_default();
    let telegram_bot_token = std::env::var("TELEGRAM_BOT_TOKEN").unwrap_or_default();
    let google_client_id = std::env::var("GOOGLE_CLIENT_ID").unwrap_or_default();
    let google_client_secret = std::env::var("GOOGLE_CLIENT_SECRET").unwrap_or_default();
    let twitter_client_id = std::env::var("TWITTER_CLIENT_ID").unwrap_or_default();
    let twitter_client_secret = std::env::var("TWITTER_CLIENT_SECRET").unwrap_or_default();
    let data_dir = std::env::var("DATA_DIR").unwrap_or_else(|_| "./data".to_string());

    // ---- Build attestation config ----
    let build_attest_pubkeys = build_attest::parse_pubkeys_from_env();
    if build_attest_pubkeys.is_empty() {
        tracing::info!(
            "Build attestation: no public keys configured — all clients allowed (grace mode)"
        );
    } else {
        tracing::info!(
            "Build attestation: {} public key(s) loaded",
            build_attest_pubkeys.len()
        );
    }

    let build_attest_enforce = std::env::var("BUILD_ATTEST_ENFORCE")
        .ok()
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);

    let build_attest_max_age_secs = std::env::var("BUILD_ATTEST_MAX_AGE_DAYS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(365)
        .saturating_mul(86400);

    // Retention for the operational database's `device_metrics` table (the
    // telemetry time series) — read once here, used by the periodic cleanup
    // task below.
    let telemetry_retention_days: i64 = std::env::var("MLC_TELEMETRY_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);

    // Retention for `device_profile` — much longer than `device_metrics`
    // gets, since it is one row per device rather than a time series.
    let device_profile_retention_days: i64 = std::env::var("MLC_DEVICE_PROFILE_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(180);

    // Per-device daily cap on `device_metrics` inserts — read once at boot
    // (not per request) and handed to every telemetry post via AppState. See
    // routes/telemetry.rs for why this, and not the client cadence, is the
    // control that actually holds under a misbehaving client.
    let telemetry_daily_cap: i64 = std::env::var("MLC_TELEMETRY_DAILY_CAP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(48);

    tracing::info!(
        "Build attestation: enforce={}, max_age={}d",
        build_attest_enforce,
        build_attest_max_age_secs / 86400
    );

    // Shared shutdown channel: one signal fans out to both servers, admin
    // restart, AND (below) the embedded alert daemon. Created here, ahead of
    // the control-plane match, so the daemon's shutdown bridge can subscribe
    // to it while still inside that match arm.
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    // Control plane (database + hot sync store) — control role only. An edge
    // process must never open a database: no wait on the SQLCipher key at
    // `MLC_DBKEY_PATH`, no data directory, no migrations (`db::init_db`'s
    // `wait_for_db_key` loop would otherwise block edge boot forever, since
    // an edge box has no key to give it).
    let mut alert_daemon_stats: Option<Arc<mlc_alert_daemon::DaemonStats>> = None;
    let control_plane = match role {
        state::ServerRole::Control => {
            // No `data/binaries` directory here — the control box stores no
            // release artifacts at all since the 2026-08-30 publish redesign;
            // they live only on the public edges (see routes/admin.rs and
            // routes/updates.rs). `data_dir` is still the root for the
            // database files initialized below.

            // Read the SQLCipher key once — both the identity and social
            // databases use it (see `db::read_sqlcipher_key`'s doc comment;
            // the tmpfs key file is deleted after this call).
            let key_hex = db::read_sqlcipher_key();

            // Initialize the identity database (SQLCipher).
            let db_path = format!("{}/mylittlechart.db", data_dir);
            let db_conn = match db::init_db(&db_path, &key_hex) {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::error!("Failed to initialize database at {}: {}", db_path, e);
                    std::process::exit(1);
                }
            };
            tracing::info!("Database initialized at {}", db_path);

            // Initialize the social database (SQLCipher, same key, separate
            // file — 2026-09-06 storage split, see social_db.rs's module
            // doc). Forum-v2 boards/threads/replies/roles live here; the
            // identity database above keeps only users and their vaults.
            let social_db_path = format!("{}/social.db", data_dir);
            let social_conn = match social_db::init_social_db(&social_db_path, &key_hex) {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::error!("Failed to initialize social database at {}: {}", social_db_path, e);
                    std::process::exit(1);
                }
            };
            tracing::info!("Social database initialized at {}", social_db_path);

            // Initialize the operational database (plain SQLite, no key wait —
            // see state::ControlPlane::ops_db). Then run the one-time move of
            // `devices`/`releases` out of identity, if their identity copies
            // still exist (2026-08-30 store split). `telemetry` was a third
            // leg of that same move; see `db::migrate_legacy_ops_tables`'s
            // doc comment for why it is gone from this list.
            let ops_db_path = format!("{}/operational.db", data_dir);
            let ops_conn = match db::init_ops_db(&ops_db_path) {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::error!("Failed to initialize operational database at {}: {}", ops_db_path, e);
                    std::process::exit(1);
                }
            };
            tracing::info!("Operational database initialized at {}", ops_db_path);

            if let Err(e) = db::migrate_legacy_ops_tables(&db_conn, &ops_conn) {
                tracing::error!("Operational store migration failed: {}", e);
                std::process::exit(1);
            }

            // Second connection to the same operational database file,
            // owned exclusively by the dedicated writer thread (see
            // opswriter.rs) — `ops_conn` above stays the read-mostly
            // connection every other route still locks directly; telemetry
            // is the one write that now goes through this thread instead,
            // so it never queues behind a dashboard read or another
            // device's post on the same mutex.
            let ops_writer_conn = match rusqlite::Connection::open(&ops_db_path) {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::error!("Failed to open the ops-writer connection at {}: {}", ops_db_path, e);
                    std::process::exit(1);
                }
            };
            // `journal_mode=WAL` is a file-level setting already applied by
            // `init_ops_db` above, but set again here explicitly rather
            // than assumed — this is the connection two-connection
            // contention actually depends on getting right, along with the
            // busy timeout (see `db::init_ops_db`'s doc comment for why
            // both connections need one).
            if let Err(e) = ops_writer_conn
                .execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
            {
                tracing::error!("Failed to configure the ops-writer connection at {}: {}", ops_db_path, e);
                std::process::exit(1);
            }
            let ops_writer =
                opswriter::OpsWriter::spawn(ops_writer_conn, opswriter::OPS_WRITER_QUEUE_CAPACITY);
            tracing::info!("Operational database writer thread started");

            // Embedded alert-evaluation daemon (see this file's module doc
            // for `MLC_ALERT_DAEMON`, and `mlc_alert_daemon`'s crate doc for
            // why this runs inside the server process rather than as a
            // sibling binary). `key_hex` is moved into `daemon_cfg` here —
            // its last use on this process was the two `init_*_db` calls
            // above — and `mlc_alert_daemon::run` zeroizes its copy right
            // after opening its own read-only connection with it.
            let alert_daemon_enabled =
                std::env::var("MLC_ALERT_DAEMON").map(|v| v == "1").unwrap_or(false);
            if alert_daemon_enabled {
                let poll_secs: u64 = std::env::var("MLC_ALERT_POLL_SECS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(30);
                let daemon_cfg = mlc_alert_daemon::DaemonConfig {
                    identity_db_path: db_path.clone(),
                    store_db_path: format!("{}/alert_daemon.db", data_dir),
                    db_key_hex: key_hex,
                    telegram_bot_token: telegram_bot_token.clone(),
                    poll_interval: std::time::Duration::from_secs(poll_secs),
                };

                // Bridges the shared broadcast shutdown signal into the
                // `watch`-based one `mlc_alert_daemon::run` expects — a
                // dedicated channel rather than reusing `shutdown_tx`
                // directly, since that is a `broadcast::Sender<()>` and
                // `run` wants a `watch::Receiver<bool>`.
                let (daemon_shutdown_tx, daemon_shutdown_rx) = tokio::sync::watch::channel(false);
                let mut bridge_rx = shutdown_tx.subscribe();
                tokio::spawn(async move {
                    let _ = bridge_rx.recv().await;
                    let _ = daemon_shutdown_tx.send(true);
                });

                let stats = Arc::new(mlc_alert_daemon::DaemonStats::default());
                let run_stats = stats.clone();
                tokio::spawn(async move {
                    if let Err(e) = mlc_alert_daemon::run(daemon_cfg, daemon_shutdown_rx, run_stats).await {
                        tracing::error!("alert daemon exited: {}", e);
                    }
                });
                alert_daemon_stats = Some(stats);
                tracing::info!("Alert daemon enabled (poll_secs={})", poll_secs);
            } else {
                tracing::info!("Alert daemon disabled (MLC_ALERT_DAEMON not set)");
            }

            Some(state::ControlPlane {
                db: Mutex::new(db_conn),
                social: Mutex::new(social_conn),
                ops_db: Mutex::new(ops_conn),
                ops_writer,
                sync_store: crate::syncstore::SyncStore::new(
                    std::path::Path::new(&data_dir).join("sync"),
                ),
                share_root: std::path::Path::new(&data_dir).join("share"),
                data_dir: std::path::PathBuf::from(&data_dir),
            })
        }
        state::ServerRole::Edge => {
            tracing::info!("Edge role: no database, no hot sync store, no data directory");
            None
        }
    };

    // Build shared application state.
    let app_state = Arc::new(AppState::new(
        control_plane,
        admin_secret,
        github_client_id,
        github_client_secret,
        discord_client_id,
        discord_client_secret,
        telegram_bot_token,
        google_client_id,
        google_client_secret,
        twitter_client_id,
        twitter_client_secret,
        shutdown_tx.clone(),
        build_attest_pubkeys,
        build_attest_enforce,
        build_attest_max_age_secs,
        telemetry_daily_cap,
        alert_daemon_stats,
    ));

    // Start the Telegram login bot (background task) — control role only.
    // The bot calls db::confirm_tg_login_token synchronously via the closure,
    // which needs the control plane; an edge process has none.
    if role == state::ServerRole::Control {
        let bot_token = app_state.telegram_bot_token.clone();
        let confirm_fn: tg_login_bot::ConfirmFn = {
            let state = app_state.clone();
            Arc::new(move |token, tg_user_id, display_name| {
                let conn = state
                    .control_plane()
                    .db
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                db::confirm_tg_login_token(&conn, token, tg_user_id, display_name)
                    .unwrap_or(false)
            })
        };
        let bot_shutdown = shutdown_tx.subscribe();
        tg_login_bot::start(bot_token, confirm_fn, bot_shutdown);
    }

    // Spawn background cleanup task — runs every 12 hours, control role only
    // (everything it cleans lives in the control plane).
    // Handles expired sessions, tokens, stale devices, and inactive sync data
    // — both the cold plane (SQL `sync_items`) and the hot plane (files under
    // `<data_dir>/sync/`, see `syncstore::cleanup_inactive`; added 2026-08-30
    // — the SQL sweep alone never touched hot-only users' files).
    if role == state::ServerRole::Control {
        let state = app_state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(12 * 60 * 60));
            // Skip the first immediate tick so cleanup doesn't fire on startup.
            interval.tick().await;
            loop {
                interval.tick().await;
                let state = state.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let cp = state.control_plane();

                    let conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
                    let sessions = crate::db::cleanup_expired_sessions(&conn)
                        .map(|_| 0usize)
                        .unwrap_or(0);
                    let tokens = crate::db::cleanup_expired_auth_tokens(&conn).unwrap_or(0);
                    let sync = crate::db::cleanup_inactive_sync_data(&conn, 365).unwrap_or(0);

                    // `devices`/`device_metrics`/`device_profile` live in the
                    // operational database (2026-08-30 store split);
                    // `device_users` stays in identity, so reconciling it
                    // against `devices` needs both connections held at once —
                    // see `cleanup_orphan_device_users`.
                    let ops_conn = cp.ops_db.lock().unwrap_or_else(|e| e.into_inner());
                    let devices = crate::db::cleanup_stale_devices(&ops_conn, 365).unwrap_or(0);
                    let telemetry_purged =
                        crate::db::cleanup_old_telemetry(&ops_conn, telemetry_retention_days)
                            .unwrap_or(0);
                    let profiles_purged = crate::db::cleanup_stale_device_profiles(
                        &ops_conn,
                        device_profile_retention_days,
                    )
                    .unwrap_or(0);
                    let orphan_links =
                        crate::db::cleanup_orphan_device_users(&conn, &ops_conn).unwrap_or(0);
                    // Expired share links: rows go away here, their PNG blobs
                    // (if any) are unlinked below once the lock is dropped.
                    let share_blobs =
                        crate::db::cleanup_expired_share_links(&conn).unwrap_or_default();
                    drop(ops_conn);
                    drop(conn);

                    let mut shares_purged = 0usize;
                    for (_token, blob_path) in &share_blobs {
                        shares_purged += 1;
                        if blob_path.is_empty() {
                            continue;
                        }
                        // blob_path is a string crossing into the filesystem —
                        // same relative-path guard as the static handler.
                        if !crate::pathutil::is_safe_relative_path(blob_path) {
                            continue;
                        }
                        if let Err(e) = std::fs::remove_file(cp.share_root.join(blob_path)) {
                            tracing::warn!("could not unlink share blob {}: {}", blob_path, e);
                        }
                    }

                    let sync_files =
                        crate::syncstore::cleanup_inactive(&cp.sync_store, 365).unwrap_or(0);
                    (sessions, tokens, devices, orphan_links, telemetry_purged, profiles_purged, sync, sync_files, shares_purged)
                })
                .await;
                match result {
                    Ok((_sessions, tokens, devices, orphan_links, telemetry_purged, profiles_purged, sync, sync_files, shares_purged)) => {
                        if tokens + devices + orphan_links + telemetry_purged + profiles_purged + sync + sync_files + shares_purged > 0 {
                            tracing::info!(
                                "Periodic cleanup: {} expired tokens, {} stale devices, {} orphaned device links, \
                                 {} old telemetry rows, {} stale device profiles, {} inactive sync items, \
                                 {} inactive sync user dirs, {} expired share links",
                                tokens, devices, orphan_links, telemetry_purged, profiles_purged, sync, sync_files, shares_purged
                            );
                        }
                    }
                    Err(e) => tracing::error!("Background cleanup task panicked: {}", e),
                }
            }
        });
    }

    // CORS allowlist. The site and API are same-origin, so first-party
    // browser flows never need CORS (OAuth callbacks are top-level
    // navigations, not fetch; the desktop client is not a browser and sends
    // no Origin header). Only the two public origins plus localhost dev are
    // allowed; a foreign Origin gets no Access-Control-Allow-Origin and is
    // blocked by the browser. Credentials are NOT enabled — the absolute-url
    // fetch in the landing (index.html → /api/updates/latest) is anonymous.
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::predicate(|origin, _| {
            let o = origin.as_bytes();
            o == b"https://mylittlechart.org"
                || o == b"https://www.mylittlechart.org"
                || o.starts_with(b"http://localhost")
                || o.starts_with(b"http://127.0.0.1")
        }))
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::PATCH,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            // wasm cloud client (mlc-cloud FetchTransport) headers — needed
            // for cross-origin dev (localhost); prod is same-origin.
            axum::http::HeaderName::from_static("x-profile-id"),
            axum::http::HeaderName::from_static("x-device-id"),
            axum::http::HeaderName::from_static("x-build-attestation"),
            axum::http::HeaderName::from_static("x-build-version"),
            axum::http::HeaderName::from_static("x-build-timestamp"),
            axum::http::HeaderName::from_static("x-build-platform"),
            axum::http::HeaderName::from_static("x-confirm-delete"),
        ]);

    // Landing page static file service.
    // STATIC_DIR env var or fallback to ../landing-pure/web/ (dev) or ./static (deploy).
    let static_dir = std::env::var("STATIC_DIR").unwrap_or_else(|_| {
        if std::path::Path::new("../mylittlechart-landing/web").exists() {
            "../mylittlechart-landing/web".to_string()
        } else {
            "./static".to_string()
        }
    });
    tracing::info!("Serving static files from: {}", static_dir);
    let static_files = ServeDir::new(&static_dir)
        .append_index_html_on_directories(true);

    // Serve a file from the static directory, guessing content-type from extension.
    let serve_file = {
        let dir = static_dir.clone();
        move |path: String| {
            let dir = dir.clone();
            async move {
                let base = std::path::Path::new(&dir);

                // Path traversal guard (2026-07-27 incident): reject `\`,
                // `.`/`..` and anything outside the component allowlist,
                // then verify canonicalized containment inside `base`.
                // Rejection surfaces as a bare 404 — no detail is leaked.
                if !pathutil::is_safe_relative_path(&path) {
                    return None;
                }

                // 1) Try {path}.html (clean URL: /privacy → privacy.html)
                if !path.contains('.') {
                    if let Some(html_path) =
                        pathutil::resolve_under(base, &format!("{}.html", path))
                    {
                        if let Ok(body) = tokio::fs::read(&html_path).await {
                            return Some(
                                axum::response::Response::builder()
                                    .status(200)
                                    .header("content-type", "text/html; charset=utf-8")
                                    .body(axum::body::Body::from(body))
                                    .unwrap(),
                            );
                        }
                    }
                }

                // 2) Try exact path (for robots.txt, sitemap.xml, llms.txt, etc.)
                if let Some(exact_path) = pathutil::resolve_under(base, &path) {
                    if let Ok(body) = tokio::fs::read(&exact_path).await {
                        let ct = match exact_path.extension().and_then(|e| e.to_str()) {
                            Some("xml") => "application/xml; charset=utf-8",
                            Some("txt") => "text/plain; charset=utf-8",
                            Some("json") => "application/json; charset=utf-8",
                            Some("html") => "text/html; charset=utf-8",
                            Some("js") => "application/javascript; charset=utf-8",
                            Some("wasm") => "application/wasm",
                            Some("css") => "text/css; charset=utf-8",
                            Some("png") => "image/png",
                            Some("jpg") | Some("jpeg") => "image/jpeg",
                            Some("svg") => "image/svg+xml",
                            Some("webp") => "image/webp",
                            Some("ico") => "image/x-icon",
                            _ => "application/octet-stream",
                        };
                        return Some(
                            axum::response::Response::builder()
                                .status(200)
                                .header("content-type", ct)
                                .body(axum::body::Body::from(body))
                                .unwrap(),
                        );
                    }
                }

                None
            }
        }
    };

    // Clean URL routes: /privacy → privacy.html, /docs/agent-api → docs/agent-api.html
    // Also serves files with extensions that would otherwise miss ServeDir due to route priority.
    let handler_single = {
        let f = serve_file.clone();
        move |axum::extract::Path(page): axum::extract::Path<String>| {
            let f = f.clone();
            async move {
                match f(page).await {
                    Some(resp) => resp,
                    None => axum::response::Response::builder()
                        .status(404)
                        .header("content-type", "text/plain")
                        .body(axum::body::Body::from("Not Found"))
                        .unwrap(),
                }
            }
        }
    };
    let handler_nested = {
        let f = serve_file;
        move |axum::extract::Path((dir, page)): axum::extract::Path<(String, String)>| {
            let f = f.clone();
            async move {
                match f(format!("{}/{}", dir, page)).await {
                    Some(resp) => resp,
                    None => axum::response::Response::builder()
                        .status(404)
                        .header("content-type", "text/plain")
                        .body(axum::body::Body::from("Not Found"))
                        .unwrap(),
                }
            }
        }
    };

    // The one dot-prefixed path this server ever serves:
    // `.well-known/security.txt` (RFC 9116). The static handler's
    // `pathutil::is_safe_path_component` refuses every dot-prefixed segment
    // on principle (see pathutil.rs) — this is a fixed route matched by its
    // own literal string, not a loosened general rule.
    let well_known_security_txt = {
        let dir = static_dir.clone();
        move || {
            let dir = dir.clone();
            async move {
                const REL: &str = ".well-known/security.txt";
                // `REL` is a compile-time literal — this check can only ever
                // pass — kept so the route shares the exact allowlist
                // spelling the pathutil test exercises, not a second copy of
                // the string.
                if !pathutil::is_well_known_security_txt(REL) {
                    return axum::response::Response::builder()
                        .status(404)
                        .header("content-type", "text/plain")
                        .body(axum::body::Body::from("Not Found"))
                        .unwrap();
                }
                match tokio::fs::read(std::path::Path::new(&dir).join(REL)).await {
                    Ok(body) => axum::response::Response::builder()
                        .status(200)
                        .header("content-type", "text/plain; charset=utf-8")
                        .body(axum::body::Body::from(body))
                        .unwrap(),
                    Err(_) => axum::response::Response::builder()
                        .status(404)
                        .header("content-type", "text/plain")
                        .body(axum::body::Body::from("Not Found"))
                        .unwrap(),
                }
            }
        }
    };

    // Dashboard router — localhost only, no auth, control role only: it reads
    // the database directly (routes/dashboard.rs) and an edge process has
    // none. Not binding the listener at all (further down) beats a runtime
    // check on every request — an admin surface that isn't listening cannot
    // be reached by a bug, and "is it up" is externally verifiable the same
    // way `/health`'s absence would be: connection refused.
    let dash_app = (role == state::ServerRole::Control).then(|| {
        axum::Router::new()
            .route("/", axum::routing::get(routes::dashboard::render))
            .with_state(app_state.clone())
    });

    // In-app blog: patch notes and posts (see routes/posts.rs) — the
    // compatibility JSON, the Atom feed, and the server-rendered HTML
    // mirror. Control role only, same reasoning as `dash_app` above: every
    // one of these reads `state.control_plane()` directly, which an edge
    // process does not have.
    let blog_app = (role == state::ServerRole::Control).then(|| {
        axum::Router::new()
            .route("/blog/posts.json", axum::routing::get(routes::posts::compat_posts_json))
            .route("/blog/feed.xml", axum::routing::get(routes::posts::feed_xml))
            .route("/blog/", axum::routing::get(routes::posts::blog_index))
            .route("/blog/{id}", axum::routing::get(routes::posts::blog_single))
            .with_state(app_state.clone())
    });

    // `/health` as its own tiny state-carrying router (see `health_handler`)
    // — built ahead of the `/api` router below, which otherwise consumes
    // `app_state` by value.
    let health_app = axum::Router::new()
        .route("/health", axum::routing::get(health_handler))
        .with_state(app_state.clone());

    // Assemble the full router. `/api` mounts the role-appropriate route
    // table — see `routes::control_api_router` / `routes::edge_api_router`.
    let api_router = match role {
        state::ServerRole::Control => routes::control_api_router(app_state),
        state::ServerRole::Edge => routes::edge_api_router(app_state),
    };
    let app = axum::Router::new()
        // Root redirect (see redirect_to_app_root's doc comment) — ahead of
        // the static fallback so the deleted landing page's index.html, if
        // it is ever restored on disk by mistake, still cannot answer here.
        .route("/", axum::routing::get(redirect_to_app_root))
        .route(
            "/.well-known/security.txt",
            axum::routing::get(well_known_security_txt),
        )
        .nest("/api", api_router)
        // Clean URLs + file serving for subpages (before static fallback)
        .route("/{page}", axum::routing::get(handler_single))
        .route("/{dir}/{page}", axum::routing::get(handler_nested))
        // Static files at root (fallback for index.html, assets, etc.).
        .fallback_service(static_files);
    // Literal routes (`/blog/posts.json`, `/blog/feed.xml`, `/blog/`, and
    // `/health` below) always win over the `/{dir}/{page}` parameter route
    // and the static fallback above regardless of merge order — matchit
    // prioritises a static path segment over a dynamic one — so these
    // merges can happen anywhere ahead of `.layer(...)` below.
    let app = match blog_app {
        Some(blog_app) => app.merge(blog_app),
        None => app,
    };
    let app = app.merge(health_app);
    let app = app
        .layer(cors)
        .layer(axum::middleware::from_fn(security_headers));

    // Bind the main listener.
    //
    // The main listener defaults to loopback, which is right when nginx sits
    // on the same box. `BIND_ADDR` overrides it for the split topology, where
    // this process runs on the control box and the edges reach it across the
    // WireGuard link — there is no local nginx to talk to. It is still never
    // bound to a public interface: on the control box the address given is the
    // tunnel's, and the firewall accepts :19200 only with `iifname wg0`.
    //
    // (The previous comment here said public traffic arrives via a local
    // cloudflared tunnel. That stopped being true at the 2026-08-24 cutover,
    // which moved the site to direct DNS.)
    let bind_host = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
    let main_addr = format!("{}:{}", bind_host, port);
    tracing::info!("mylittlechart-server listening on {}", main_addr);
    let main_listener = tokio::net::TcpListener::bind(&main_addr)
        .await
        .unwrap_or_else(|e| panic!("Failed to bind to {}: {}", main_addr, e));

    // Subscribe to the shutdown channel before spawning the signal task, for
    // both listeners that will exist — otherwise a shutdown broadcast that
    // fires between spawn and subscribe would be missed.
    let mut main_shutdown_rx = shutdown_tx.subscribe();
    let dash_listen = if let Some(dash_app) = dash_app {
        // Read dashboard port from environment (default 19237).
        let dash_port: u16 = std::env::var("DASHBOARD_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(19237);
        let dash_addr = format!("127.0.0.1:{}", dash_port);
        tracing::info!("Admin dashboard listening on http://{}", dash_addr);
        let dash_listener = tokio::net::TcpListener::bind(&dash_addr)
            .await
            .unwrap_or_else(|e| panic!("Failed to bind dashboard to {}: {}", dash_addr, e));
        Some((dash_listener, dash_app, shutdown_tx.subscribe()))
    } else {
        tracing::info!("Edge role: admin dashboard listener not started");
        None
    };

    // Spawn a task that waits for Ctrl-C (SIGINT) or SIGTERM, then broadcasts shutdown.
    // NOTE: /api/admin/restart can also trigger shutdown via app_state.shutdown_tx.
    tokio::spawn(async move {
        // Wait for either signal.
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate())
                .expect("Failed to register SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = sigterm.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await.ok();
        }

        tracing::info!("Shutdown signal received — draining in-flight requests (max 30 s)…");
        // Broadcast to all subscribers; ignore errors (receivers may have already dropped).
        let _ = shutdown_tx.send(());
    });

    // Graceful-shutdown future for the main server.
    let main_shutdown = async move {
        let _ = main_shutdown_rx.recv().await;
    };
    // A 30-second hard timeout prevents a stuck connection from blocking deploys.
    //
    // `into_make_service_with_connect_info` (rather than passing `app`
    // directly) is what makes `ConnectInfo<SocketAddr>` extractable in
    // handlers — `routes::admin::verify_admin_secret` logs the peer address
    // on every refusal (see its doc comment), and that address has to come
    // from somewhere: this is the one place it is threaded onto every
    // connection this listener accepts.
    let main_serve = axum::serve(
        main_listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(main_shutdown);

    // Run the main server, plus the dashboard when this is a control process.
    // Both drain when the shutdown signal fires.
    match dash_listen {
        Some((dash_listener, dash_app, mut dash_shutdown_rx)) => {
            let dash_shutdown = async move {
                let _ = dash_shutdown_rx.recv().await;
            };
            let dash_serve =
                axum::serve(dash_listener, dash_app).with_graceful_shutdown(dash_shutdown);
            tokio::select! {
                r = main_serve => r.expect("Main server error"),
                r = dash_serve => r.expect("Dashboard server error"),
            };
        }
        None => main_serve.await.expect("Main server error"),
    }

    tracing::info!("Server shut down gracefully");
}

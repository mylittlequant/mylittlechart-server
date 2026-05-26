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
//!   ADMIN_SECRET           — bearer token for admin upload endpoint
//!   GITHUB_CLIENT_ID       — GitHub OAuth app client ID
//!   GITHUB_CLIENT_SECRET   — GitHub OAuth app client secret
//!   DISCORD_CLIENT_ID      — Discord OAuth app client ID
//!   DISCORD_CLIENT_SECRET  — Discord OAuth app client secret
//!   TELEGRAM_BOT_TOKEN     — Telegram bot token for login widget verification
//!   DATA_DIR               — directory for DB and binaries (default: ./data)
//!   BUILD_ATTEST_PUBKEY    — hex-encoded Ed25519 public key(s), comma-separated (optional)
//!   BUILD_ATTEST_ENFORCE   — "true"/"1" to reject unsigned clients (default: false)
//!   BUILD_ATTEST_MAX_AGE_DAYS — max build age in days (default: 365)

use std::sync::{Arc, Mutex};

use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

mod auth;
mod build_attest;
mod db;
mod models;
mod routes;
mod state;

use state::AppState;

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

    tracing::info!(
        "Build attestation: enforce={}, max_age={}d",
        build_attest_enforce,
        build_attest_max_age_secs / 86400
    );

    // Ensure data directories exist.
    let binaries_dir = format!("{}/binaries", data_dir);
    std::fs::create_dir_all(&binaries_dir).expect("Failed to create data/binaries directory");

    // Initialize SQLite database.
    let db_path = format!("{}/mylittlechart.db", data_dir);
    let db_conn = db::init_db(&db_path).expect("Failed to initialize SQLite database");
    tracing::info!("Database initialized at {}", db_path);

    // Shared shutdown channel: one signal fans out to both servers + admin restart.
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    // Build shared application state.
    let app_state = Arc::new(AppState {
        db: Mutex::new(db_conn),
        data_dir,
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
        shutdown_tx: shutdown_tx.clone(),
        build_attest_pubkeys,
        build_attest_enforce,
        build_attest_max_age_secs,
    });

    // Start the Telegram login bot (background task).
    // The bot calls db::confirm_tg_login_token synchronously via the closure.
    {
        let bot_token = app_state.telegram_bot_token.clone();
        let confirm_fn: tg_login_bot::ConfirmFn = {
            let state = app_state.clone();
            Arc::new(move |token, tg_user_id, display_name| {
                let conn = state.db.lock().unwrap_or_else(|e| e.into_inner());
                db::confirm_tg_login_token(&conn, token, tg_user_id, display_name)
                    .unwrap_or(false)
            })
        };
        let bot_shutdown = shutdown_tx.subscribe();
        tg_login_bot::start(bot_token, confirm_fn, bot_shutdown);
    }

    // Spawn background cleanup task — runs every 12 hours.
    // Handles expired sessions, tokens, stale devices, and inactive sync data.
    {
        let state = app_state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(12 * 60 * 60));
            // Skip the first immediate tick so cleanup doesn't fire on startup.
            interval.tick().await;
            loop {
                interval.tick().await;
                let state = state.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let conn = state.db.lock().unwrap_or_else(|e| e.into_inner());
                    let sessions = crate::db::cleanup_expired_sessions(&conn)
                        .map(|_| 0usize)
                        .unwrap_or(0);
                    let tokens = crate::db::cleanup_expired_auth_tokens(&conn).unwrap_or(0);
                    let devices = crate::db::cleanup_stale_devices(&conn, 365).unwrap_or(0);
                    let sync = crate::db::cleanup_inactive_sync_data(&conn, 365).unwrap_or(0);
                    (sessions, tokens, devices, sync)
                })
                .await;
                match result {
                    Ok((_sessions, tokens, devices, sync)) => {
                        if tokens + devices + sync > 0 {
                            tracing::info!(
                                "Periodic cleanup: {} expired tokens, {} stale devices, {} inactive sync items",
                                tokens, devices, sync
                            );
                        }
                    }
                    Err(e) => tracing::error!("Background cleanup task panicked: {}", e),
                }
            }
        });
    }

    // CORS layer — allow all origins (public API).
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

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

                // 1) Try {path}.html (clean URL: /privacy → privacy.html)
                if !path.contains('.') {
                    let html_path = base.join(format!("{}.html", path));
                    if html_path.exists() {
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
                let exact_path = base.join(&path);
                if exact_path.is_file() {
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

    // Read dashboard port from environment (default 19237).
    let dash_port: u16 = std::env::var("DASHBOARD_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(19237);

    // Clone state for the dashboard router before moving it into the main router.
    let dash_state = app_state.clone();

    // Assemble the full router.
    let app = axum::Router::new()
        // Liveness probe for d-watchdog (root-level, before /{page} catch-all).
        .route("/health", axum::routing::get(|| async { "ok" }))
        .nest("/api", routes::api_router(app_state))
        // Clean URLs + file serving for subpages (before static fallback)
        .route("/{page}", axum::routing::get(handler_single))
        .route("/{dir}/{page}", axum::routing::get(handler_nested))
        // Static files at root (fallback for index.html, assets, etc.).
        .fallback_service(static_files)
        .layer(cors)
        .layer(axum::middleware::from_fn(security_headers));

    // Dashboard router — localhost only, no auth.
    let dash_app = axum::Router::new()
        .route("/", axum::routing::get(routes::dashboard::render))
        .with_state(dash_state);

    // Bind both listeners.
    let main_addr = format!("0.0.0.0:{}", port);
    tracing::info!("mylittlechart-server listening on {}", main_addr);
    let main_listener = tokio::net::TcpListener::bind(&main_addr)
        .await
        .unwrap_or_else(|e| panic!("Failed to bind to {}: {}", main_addr, e));

    let dash_addr = format!("127.0.0.1:{}", dash_port);
    tracing::info!("Admin dashboard listening on http://{}", dash_addr);
    let dash_listener = tokio::net::TcpListener::bind(&dash_addr)
        .await
        .unwrap_or_else(|e| panic!("Failed to bind dashboard to {}: {}", dash_addr, e));

    // Subscribe both servers to the shutdown channel before spawning the signal task.
    let mut main_shutdown_rx = shutdown_tx.subscribe();
    let mut dash_shutdown_rx = shutdown_tx.subscribe();

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

    // Graceful-shutdown futures for each server.
    let main_shutdown = async move {
        let _ = main_shutdown_rx.recv().await;
    };
    let dash_shutdown = async move {
        let _ = dash_shutdown_rx.recv().await;
    };

    // Run both servers concurrently. Both drain when the shutdown signal fires.
    // A 30-second hard timeout prevents a stuck connection from blocking deploys.
    let main_serve = axum::serve(main_listener, app)
        .with_graceful_shutdown(main_shutdown);
    let dash_serve = axum::serve(dash_listener, dash_app)
        .with_graceful_shutdown(dash_shutdown);

    tokio::select! {
        r = main_serve => r.expect("Main server error"),
        r = dash_serve => r.expect("Dashboard server error"),
    };

    tracing::info!("Server shut down gracefully");
}

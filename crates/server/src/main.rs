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
//!   DIG2PAY_BASE_URL       — dig2pay merchant API base (control role only),
//!                            e.g. `http://10.83.1.1:37300` over the `wg-mlc`
//!                            tunnel. Empty (default): checkout and plan
//!                            changes answer 503. See `billing::config`.
//!   DIG2PAY_API_KEY_FILE   — file holding the merchant bearer key
//!   DIG2PAY_WEBHOOK_SECRET_FILES — comma-separated files, one HMAC secret
//!                            each (several live at once during a rotation)
//!   DIG2PAY_TIMEOUT_SECS   — timeout of one merchant API call (default: 15)
//!   MLC_BILLING_ONION_HOSTS — comma-separated `Host` names of the onion
//!                            vhost; the Tor plan variants are offered only
//!                            to requests carrying one of them
//!   MLC_BILLING_PLAN_PAID / _ANON / _PAID_TOR / _ANON_TOR — ids of the four
//!                            one-time account plans (defaults:
//!                            mlc-paid-account-v1, mlc-anon-account-v1,
//!                            mlc-paid-account-tor-v1, mlc-anon-account-tor-v1)
//!   MLC_BILLING_QUANT_QUOTAS — `plan_id=quota` pairs, comma-separated: the
//!                            quant quota of each monthly tier (no quota
//!                            number lives in code)
//!   MLC_BILLING_ANON_PER_IP_PER_HOUR / MLC_BILLING_ANON_GLOBAL_PER_HOUR /
//!   MLC_BILLING_KEY_FAILS_PER_IP_PER_HOUR — hourly abuse budgets of the
//!                            unauthenticated anonymous-account routes:
//!                            checkouts per client IP (default 5), checkouts
//!                            across all IPs (200), failed account-key
//!                            attempts per client IP (20)
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
//!   ADMIN_BIND / ADMIN_PORT — admin API listener (`routes::admin_api_router`,
//!                            every `/admin/*` route, mounted as
//!                            `/api/admin/...`), default `127.0.0.1:19238`.
//!                            Control role only — an edge process never
//!                            starts this listener. This is the ONLY place
//!                            `/api/admin/*` answers (2026-09-22
//!                            admin-listener split — see
//!                            `docs/mlc/audits/api-surface-hardening-2026-09-10.md`
//!                            §3/§6): the main listener (`BIND_ADDR:PORT`
//!                            above) mounts `control_api_router`, which does
//!                            not register `/admin/*` at all. An operator
//!                            reaches this listener only through an SSH
//!                            tunnel to the loopback bind (see
//!                            `ops/README.md`) — `ADMIN_SECRET` is still
//!                            checked on every route here; the tunnel is a
//!                            first lock, not a replacement for it.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tower_http::timeout::TimeoutLayer;

mod account_merge;
mod auth;
mod billing;
mod build_attest;
mod db;
mod dm_db;
mod entitlements;
// `live` and `share_hub` live in the library target (`lib.rs`), not here —
// see that file's doc comment for why. `share_live` below is the glue that
// binds the hub to this crate's accounts and share rights.
mod models;
mod nick_policy;
mod notify;
mod opswriter;
mod pathutil;
mod ratelimit;
mod rooms_codec;
mod routes;
mod share_live;
mod social_db;
mod staff;
mod state;
mod syncstore;
mod text_policy;

use state::AppState;

/// `GET /` → 301 to the app root on the public domain.
///
/// The edges proxy the legacy `/home` path to this backend's `/`, which used
/// to render a marketing landing page (deleted per the 2026-09-05
/// web-surface-cleanup plan). Redirecting `/` here kills `/home` without
/// touching the edges' nginx config — nginx is provisioned by hand over ssh
/// and there is no delivery script for it (see the static-file fallback
/// further down, which still serves everything else).
///
/// This is also the fallback [`root_or_share_og`] uses for every request
/// that is NOT a link-preview crawler's `?share=` fetch — unchanged
/// behaviour for the overwhelming majority of hits on this path (nginx
/// itself never even reaches this backend for a plain `/`: it serves its own
/// copy of `index.html` directly, `ops/nginx-mlc-site.conf`'s `location /`
/// block — this handler only matters for a direct hit on this backend, or a
/// share-tagged one nginx detours here on purpose, §9).
async fn redirect_to_app_root() -> axum::response::Response {
    axum::response::Response::builder()
        .status(301)
        .header("location", "https://mylittlechart.org/")
        .body(axum::body::Body::empty())
        .unwrap()
}

/// State for [`root_or_share_og`] — `Arc<AppState>` plus the same
/// `static_dir` string `outside_api_app` was built with (main() computes it
/// once, see `STATIC_DIR`'s doc in this file's module comment). Not folded
/// into `AppState` itself: nothing else needs `static_dir` at runtime, and
/// `AppState::new`'s constructor is already an established long positional
/// list several tests build by hand — this stays a small, route-local
/// bundle instead of growing that list for one handler.
#[derive(Clone)]
struct RootAppState {
    app_state: Arc<AppState>,
    static_dir: String,
}

/// Query params `GET /` accepts. `share` mirrors the client's own `?share=`
/// convention (`mlc-app/src/share_viewer.rs`'s `request_open_share`) — the
/// same token a recipient's browser fetches `/api/share/{token}` with.
#[derive(serde::Deserialize)]
struct ShareQueryParam {
    #[serde(default)]
    share: Option<String>,
}

/// `GET /` — per-link preview card / OG injection
/// (docs/mlc/plans/share-policy-2026-09-25.md §9). Edge nginx detours every
/// `?share=` request here (`ops/nginx-mlc-site.conf`, `$mlc_share_preview`
/// → `@mlc_share_preview`) and this handler returns `STATIC_DIR/index.html`
/// — the edge app index, copied by `deploy-app.sh` — with that link's
/// og tags substituted. Every other request — no `share` param at all —
/// gets the unchanged [`redirect_to_app_root`] 301.
///
/// For a `share`-tagged request: reads `static_dir/index.html` (the SAME
/// file `outside_api_app`'s `ServeDir` would have served — never a
/// baked-in copy, so a landing-page edit never has to be mirrored into this
/// crate) and, when the token resolves to a real, live share, substitutes
/// its `og:title`/`og:image`/`twitter:title`/`twitter:image` tags
/// (`routes::share::og_tags_for_share` + `inject_og_tags`) before answering.
/// An unknown/expired/revoked token gets the file back byte-identical — the
/// same opacity `routes::share`'s own bare-404 doctrine holds for those
/// three cases, extended here to "no distinguishable behaviour either" —
/// and a private share whose caller (there is none; this route has no
/// notion of a caller at all) holds no tier gets the neutral card via
/// `og_tags_for_share`'s own `visibility == "private"` branch, not a lock
/// screen (§8.5's lock screen is the OPEN-in-app case; a crawler is never
/// signed in, so §8.5 is not reachable from here).
fn share_preview_agent(ua: &str) -> bool {
    if ua.is_empty() {
        return true;
    }
    let ua = ua.to_ascii_lowercase();
    [
        "telegrambot",
        "facebookexternalhit",
        "facebot",
        "twitterbot",
        "slackbot",
        "discordbot",
        "whatsapp",
        "vkshare",
        "linkedinbot",
        "googlebot",
        "bingbot",
        "yandex",
        "baiduspider",
        "embedly",
        "pinterest",
        "redditbot",
        "applebot",
    ]
    .iter()
    .any(|name| ua.contains(name))
        || ua.contains("bot")
        || ua.contains("crawler")
        || ua.contains("spider")
}

/// Browser pasted `/?share=`. The token moves into a one-shot cookie and
/// the address bar becomes `/`. The app turns that cookie into a tab.
fn redirect_share_into_tab(token: &str) -> axum::response::Response {
    let cookie = format!("mlc_share={token}; Max-Age=120; Path=/; Secure; SameSite=Lax");
    axum::response::Response::builder()
        .status(302)
        .header("location", "/")
        .header("set-cookie", cookie)
        .header("cache-control", "no-store")
        .body(axum::body::Body::empty())
        .unwrap()
}

async fn root_or_share_og(
    axum::extract::State(state): axum::extract::State<Arc<RootAppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(q): axum::extract::Query<ShareQueryParam>,
) -> axum::response::Response {
    let Some(token) = q.share.filter(|t| !t.is_empty()) else {
        return redirect_to_app_root().await;
    };
    let ua = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !share_preview_agent(ua) && token.len() == 32 && token.chars().all(|c| c.is_ascii_hexdigit()) {
        return redirect_share_into_tab(&token);
    }

    let index_path = std::path::Path::new(&state.static_dir).join("index.html");
    let html = match tokio::fs::read_to_string(&index_path).await {
        Ok(html) => html,
        Err(_) => return redirect_to_app_root().await,
    };

    let app_state = state.app_state.clone();
    let tags = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<routes::share::OgTags>> {
        let conn = app_state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let Some(row) = crate::db::get_share_link(&conn, &token)? else {
            return Ok(None);
        };
        let label = crate::db::effective_label_for_user(&conn, row.user_id).unwrap_or_default();
        Ok(Some(routes::share::og_tags_for_share(&row, &label)))
    })
    .await;

    let html = match tags {
        Ok(Ok(Some(tags))) => routes::share::inject_og_tags(&html, &tags),
        Ok(Ok(None)) => html,
        Ok(Err(e)) => {
            tracing::error!("DB error resolving share for OG injection: {}", e);
            html
        }
        Err(_) => html,
    };

    axum::response::Response::builder()
        .status(200)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(axum::body::Body::from(html))
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

/// Middleware layered on the `/api` sub-router only (never on the static
/// files, blog, or health routes, which want caching) — owner ruling: an API
/// answer must never be served from a cache, by this process or by anything
/// in front of it (nginx/Cloudflare/a browser). `pragma: no-cache` is the
/// HTTP/1.0-era companion header some older intermediaries still honor
/// instead of `cache-control`; harmless, and cheap insurance alongside it.
async fn no_store_api_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert("cache-control", "no-store".parse().unwrap());
    headers.insert("pragma", "no-cache".parse().unwrap());
    response
}

/// The one 404 every path OUTSIDE `/api` falls back to — byte-identical
/// (empty body, no extra headers) to `routes::admin::admin_not_found()`'s
/// answer for the `/api` half of this invariant. Before this existed, a
/// top-level unknown path (`handler_single`/`handler_nested`'s miss arm)
/// answered `text/plain "Not Found"` instead — a different shape a prober
/// could use to tell "under /api" apart from "not under /api" by body
/// content. That distinction carries no information about admin secrets
/// (the property `admin_not_found` actually claims), but there is no reason
/// to leave two different 404 shapes lying around outside `/api` either.
fn bare_not_found() -> axum::response::Response {
    use axum::response::IntoResponse;
    axum::http::StatusCode::NOT_FOUND.into_response()
}

/// Build the static/clean-URL sub-app: the fixed `.well-known/security.txt`
/// route, the `/{page}` and `/{dir}/{page}` clean-URL handlers, and the
/// `ServeDir` fallback for everything else (assets, `index.html`, 3+segment
/// paths). Standalone (rather than inlined in `main()`) so this module's own
/// tests can build the exact same router `main()` serves — see
/// `tests::outside_api_paths_get_the_same_bare_404_everywhere` below.
fn outside_api_app(static_dir: &str) -> axum::Router {
    // Serve a file from the static directory, guessing content-type from extension.
    let serve_file = {
        let dir = static_dir.to_string();
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
                    None => bare_not_found(),
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
                    None => bare_not_found(),
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
        let dir = static_dir.to_string();
        move || {
            let dir = dir.clone();
            async move {
                const REL: &str = ".well-known/security.txt";
                // `REL` is a compile-time literal — this check can only ever
                // pass — kept so the route shares the exact allowlist
                // spelling the pathutil test exercises, not a second copy of
                // the string.
                if !pathutil::is_well_known_security_txt(REL) {
                    return bare_not_found();
                }
                match tokio::fs::read(std::path::Path::new(&dir).join(REL)).await {
                    Ok(body) => axum::response::Response::builder()
                        .status(200)
                        .header("content-type", "text/plain; charset=utf-8")
                        .body(axum::body::Body::from(body))
                        .unwrap(),
                    Err(_) => bare_not_found(),
                }
            }
        }
    };

    // Landing page static file service. Wrapped with `.not_found_service`
    // so a 3+-segment miss (the one case neither `/{page}` nor
    // `/{dir}/{page}` can match) answers the SAME bare 404 as everything
    // else here, instead of `tower_http`'s own default not-found shape.
    let empty_not_found = tower::service_fn(|_req: axum::extract::Request| async move {
        Ok::<_, std::convert::Infallible>(bare_not_found())
    });
    let static_files = ServeDir::new(static_dir)
        .append_index_html_on_directories(true)
        .not_found_service(empty_not_found);

    axum::Router::new()
        .route(
            "/.well-known/security.txt",
            axum::routing::get(well_known_security_txt),
        )
        // Clean URLs + file serving for subpages (before static fallback)
        .route("/{page}", axum::routing::get(handler_single))
        .route("/{dir}/{page}", axum::routing::get(handler_nested))
        // Static files at root (fallback for index.html, assets, etc.).
        .fallback_service(static_files)
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

            // Reserved-nick cache (owner order 2026-09-09) — loaded once
            // here, right after `db::init_db`'s own seeding, so
            // `db::set_nick`'s impersonation check never scans
            // `reserved_nicks` on a self-service request. See
            // `ControlPlane::reserved_nick_cache_snapshot`.
            let reserved_nick_cache_entries = match db::reserved_nick_entries(&db_conn) {
                Ok(entries) => entries,
                Err(e) => {
                    tracing::error!("Failed to load the reserved-nick cache: {}", e);
                    Vec::new()
                }
            };

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

            let control_plane = state::ControlPlane {
                db: Mutex::new(db_conn),
                social: Mutex::new(social_conn),
                ops_db: Mutex::new(ops_conn),
                ops_writer,
                sync_store: crate::syncstore::SyncStore::new(
                    std::path::Path::new(&data_dir).join("sync"),
                ),
                share_root: std::path::Path::new(&data_dir).join("share"),
                data_dir: std::path::PathBuf::from(&data_dir),
                reserved_nick_cache: std::sync::RwLock::new(reserved_nick_cache_entries),
                live: mylittlechart_server::live::LiveRegistry::new(),
            };
            tracing::info!(
                "Live event registry ready ({} topic(s))",
                control_plane.live.topic_count()
            );
            Some(control_plane)
        }
        state::ServerRole::Edge => {
            tracing::info!("Edge role: no database, no hot sync store, no data directory");
            None
        }
    };

    // The dig2pay billing adapter (control role only — every billing route
    // reads the identity database). Reads its key/secret files here and never
    // fails: whatever is not configured leaves that half disabled.
    let billing = (role == state::ServerRole::Control).then(billing::BillingRuntime::from_env);

    // Build shared application state.
    let app_state = AppState::new(
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
    );
    let app_state = Arc::new(match billing {
        Some(billing) => app_state.with_billing(billing),
        None => app_state,
    });

    // Live share hub background work (shutdown close, periodic rights
    // re-check) — control role only: the hub's rights live in the database.
    if role == state::ServerRole::Control {
        share_live::spawn_hub_tasks(app_state.clone(), shutdown_tx.subscribe());
    }

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
                    // Anonymous accounts bought but never paid for: deleted
                    // once their invoice has been expired for a day (one
                    // with money attached is kept for a human).
                    match crate::billing::anon::gc_pending(&conn, chrono::Utc::now()) {
                        Ok(report) if report.deleted > 0 || report.kept_with_payment > 0 => tracing::info!(
                            "Anonymous account GC: {} unpaid deleted, {} kept because a payment is attached",
                            report.deleted,
                            report.kept_with_payment
                        ),
                        Ok(_) => {}
                        Err(e) => tracing::warn!("Anonymous account GC failed: {e}"),
                    }
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
    // `.well-known/security.txt`, the `/{page}`/`/{dir}/{page}` clean-URL
    // handlers, and the `ServeDir` fallback — see `outside_api_app`'s own
    // doc comment for why this is a standalone function rather than inlined
    // here.
    let outside_api = outside_api_app(&static_dir);

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

    // Admin API router — its own loopback listener, control role only, same
    // reasoning as `dash_app` above: `routes::admin_api_router` needs
    // `state.control_plane()`, which an edge process has none of. Mounted
    // the same way the main `/api` router is further down
    // (`.nest("/api", …)`), so every admin path keeps its
    // `/api/admin/...` shape — only the listener a caller has to reach
    // changes (see `routes/mod.rs`'s `//!` doc for the 2026-09-22 split).
    // `no_store_api_headers` is layered the same way it is on the main
    // `/api` router further down (`cache-control: no-store` on every admin
    // response); the concurrency/timeout backstops mirror the main app's
    // own (`ConcurrencyLimitLayer`/`TimeoutLayer` further down). No per-IP
    // rate limit here — the admin listener has exactly one loopback peer.
    let admin_app = (role == state::ServerRole::Control).then(|| {
        axum::Router::new()
            .nest("/api", routes::admin_api_router(app_state.clone()))
            .layer(axum::middleware::from_fn(no_store_api_headers))
            .layer(ConcurrencyLimitLayer::new(512))
            .layer(TimeoutLayer::with_status_code(
                axum::http::StatusCode::REQUEST_TIMEOUT,
                Duration::from_secs(60),
            ))
    });

    // `/health` as its own tiny state-carrying router (see `health_handler`)
    // — built ahead of the `/api` router below, which otherwise consumes
    // `app_state` by value.
    let health_app = axum::Router::new()
        .route("/health", axum::routing::get(health_handler))
        .with_state(app_state.clone());

    // `/` as its own tiny state-carrying router (see `root_or_share_og`) —
    // built ahead of the `/api` router below for the same reason
    // `health_app` is: that router consumes `app_state` by value. Registered
    // unconditionally (unlike `dash_app`/`blog_app`/`admin_app`, which are
    // control-role only) because the plain redirect — the ONLY behaviour a
    // `share`-less request ever gets — must keep working on an edge process
    // exactly like it did before this route existed. A `share`-tagged
    // request on an EDGE process (not a real production path — nginx's own
    // `mlc_backend` upstream always points at the control box, never an
    // edge) would hit `AppState::control_plane()`'s panic inside
    // `spawn_blocking`; tokio contains that to a `JoinError` on the awaited
    // handle, which `root_or_share_og` already treats as "serve the file
    // unmodified" — a graceful degrade, not a process crash.
    let root_app = axum::Router::new()
        .route("/", axum::routing::get(root_or_share_og))
        .with_state(Arc::new(RootAppState {
            app_state: app_state.clone(),
            static_dir: static_dir.clone(),
        }));

    // Assemble the full router. `/api` mounts the role-appropriate route
    // table — see `routes::control_api_router` / `routes::edge_api_router`.
    let api_router = match role {
        state::ServerRole::Control => routes::control_api_router(app_state),
        state::ServerRole::Edge => routes::edge_api_router(app_state),
    };
    // Per-IP token-bucket rate limiting (see ratelimit.rs) — one process-wide
    // limiter, swept for idle entries every 5 minutes.
    let rate_limiter = Arc::new(ratelimit::RateLimiter::new());
    ratelimit::spawn_sweeper(rate_limiter.clone());
    // Layering order here matters: `rate_limit_middleware` is added FIRST
    // (innermost) and `no_store_api_headers` SECOND (outermost) — each
    // subsequent `.layer()` call wraps the previous one, so the outermost
    // layer's post-response step ALWAYS runs, even when an inner layer
    // short-circuits with an early response. That is exactly what a 429
    // does: without this ordering, a rate-limited response would skip
    // `no_store_api_headers` entirely and reach the caller without
    // `cache-control: no-store` — the one thing this ordering exists to
    // prevent.
    let api_router = api_router
        .layer(axum::middleware::from_fn_with_state(
            rate_limiter,
            ratelimit::rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn(no_store_api_headers));
    // `/` (see `root_or_share_og`'s doc comment) merges in alongside
    // `blog_app`/`health_app`/`outside_api` below — ahead of the static
    // fallback so the deleted landing page's index.html, if it is ever
    // restored on disk by mistake, still cannot answer here.
    let app = axum::Router::new().merge(root_app).nest("/api", api_router);
    // Literal routes (`/blog/posts.json`, `/blog/feed.xml`, `/blog/`, and
    // `/health` below) always win over `outside_api`'s `/{dir}/{page}`
    // parameter route and its `ServeDir` fallback regardless of merge order
    // — matchit prioritises a static path segment over a dynamic one — so
    // these merges can happen anywhere ahead of `.layer(...)` below. Exactly
    // one of the routers being merged here (`outside_api`) sets a
    // `fallback_service`; axum panics at merge time if two did.
    let app = match blog_app {
        Some(blog_app) => app.merge(blog_app),
        None => app,
    };
    let app = app.merge(health_app).merge(outside_api);
    let app = app
        .layer(cors)
        .layer(axum::middleware::from_fn(security_headers))
        // App-wide concurrency backstop — behind nginx this is not meant to
        // throttle legitimate traffic (512 is far above anything nginx lets
        // through today), only to bound how many requests this process ever
        // has in flight at once.
        .layer(ConcurrencyLimitLayer::new(512))
        // App-wide request deadline. `TimeoutLayer::with_status_code` (NOT
        // the deprecated `TimeoutLayer::new`, which this crate's
        // `-D warnings` gate would refuse to build) answers a timed-out
        // request with an empty body and the given status directly — it
        // does not change the wrapped service's error type, so no
        // `HandleErrorLayer` is needed to keep the stack infallible.
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(60),
        ));

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
    // every listener that will exist — otherwise a shutdown broadcast that
    // fires between spawn and subscribe would be missed. Three listeners
    // now, not two: main, dashboard, admin.
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
    // Admin API listener — same role gate and subscribe-before-spawn
    // reasoning as the dashboard listener above. `ADMIN_BIND` defaults to
    // loopback (never a public interface, see this file's module doc);
    // `ADMIN_PORT` defaults to 19238.
    let admin_listen = if let Some(admin_app) = admin_app {
        let admin_host = std::env::var("ADMIN_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
        let admin_port: u16 = std::env::var("ADMIN_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(19238);
        let admin_addr = format!("{}:{}", admin_host, admin_port);
        tracing::info!("Admin API listening on http://{}", admin_addr);
        let admin_listener = tokio::net::TcpListener::bind(&admin_addr)
            .await
            .unwrap_or_else(|e| panic!("Failed to bind admin listener to {}: {}", admin_addr, e));
        Some((admin_listener, admin_app, shutdown_tx.subscribe()))
    } else {
        tracing::info!("Edge role: admin listener not started");
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
    // A 30-second hard timeout prevents a stuck connection from blocking
    // deploys.
    //
    // `into_make_service_with_connect_info` (rather than passing `app`
    // directly) is what makes `ConnectInfo<SocketAddr>` extractable in
    // handlers — `routes::admin::verify_admin_secret` logs the peer address
    // on every refusal (see its doc comment), and that address has to come
    // from somewhere: this is where it is threaded onto every connection
    // this listener accepts. The admin listener further down does the same
    // for its own connections, for the same reason.
    //
    // Each of the three `_serve` futures below resolves to `Result<(), String>`
    // (mapped from `io::Result<()>`, tagged with which listener it came
    // from) so `tokio::try_join!` further down can report which one failed.
    let main_serve = async move {
        axum::serve(
            main_listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(main_shutdown)
        .await
        .map_err(|e| format!("main listener: {e}"))
    };

    // Run the main server, plus the dashboard/admin listeners when this is a
    // control process. All three must drain fully before the process exits
    // — `tokio::try_join!`, not `select!`: `select!` resolves on whichever
    // listener finishes FIRST, and a quiet dashboard/admin listener
    // routinely finishes before the main listener's in-flight requests
    // drain, which used to cut the main listener's 30-second drain short on
    // every SIGTERM (all three receive the same shutdown broadcast at once,
    // so the dashboard/admin futures reliably raced ahead and won).
    // `try_join!` polls all three concurrently and only returns once every
    // one of them has resolved `Ok` — it still short-circuits immediately on
    // the first `Err`, cancelling the rest, so a genuine listener failure
    // (not a graceful shutdown — those always resolve `Ok`) still kills the
    // process right away, the same property `select!` had. A `None`
    // listener (edge role: no dashboard/admin) resolves to `Ok(())`
    // immediately rather than `std::future::pending()` — `pending()` would
    // make `try_join!` wait forever for an arm that can never finish.
    let dash_serve = async move {
        match dash_listen {
            Some((dash_listener, dash_app, mut dash_shutdown_rx)) => {
                let dash_shutdown = async move {
                    let _ = dash_shutdown_rx.recv().await;
                };
                axum::serve(dash_listener, dash_app)
                    .with_graceful_shutdown(dash_shutdown)
                    .await
                    .map_err(|e| format!("dashboard listener: {e}"))
            }
            None => Ok(()),
        }
    };
    // `into_make_service_with_connect_info` here too — `routes::admin`
    // logs the peer address on every refusal (see the main listener's own
    // comment above), and a loopback-only listener with a single expected
    // peer is exactly where that address is most worth keeping.
    let admin_serve = async move {
        match admin_listen {
            Some((admin_listener, admin_app, mut admin_shutdown_rx)) => {
                let admin_shutdown = async move {
                    let _ = admin_shutdown_rx.recv().await;
                };
                axum::serve(
                    admin_listener,
                    admin_app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
                )
                .with_graceful_shutdown(admin_shutdown)
                .await
                .map_err(|e| format!("admin listener: {e}"))
            }
            None => Ok(()),
        }
    };
    if let Err(e) = tokio::try_join!(main_serve, dash_serve, admin_serve) {
        panic!("server error: {e}");
    }

    tracing::info!("Server shut down gracefully");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// Extends `routes::mod`'s own indistinguishability proof (admin refusal
    /// ≡ unknown `/api/*` path) to every path OUTSIDE `/api`: a 1-segment
    /// miss (`handler_single`), a 2-segment miss (`handler_nested`), and a
    /// 3+-segment miss (the `ServeDir` fallback) must all answer the exact
    /// same bare 404 `bare_not_found()` gives — empty body, no extra
    /// headers — the same shape `routes::admin::admin_not_found()` answers
    /// for the `/api` half of this invariant. The static dir here is
    /// deliberately nonexistent: every one of these paths must miss on
    /// disk for the test to exercise the actual "nothing answers" case.
    #[tokio::test]
    async fn outside_api_paths_get_the_same_bare_404_everywhere() {
        for path in ["/whatever", "/a/b", "/a/b/c"] {
            let router = outside_api_app("this-directory-does-not-exist-2026-09-10");
            let resp = router
                .oneshot(
                    Request::get(path)
                        .body(Body::empty())
                        .expect("build request"),
                )
                .await
                .expect("Router::call is infallible");

            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "path {path}");
            let body = to_bytes(resp.into_body(), usize::MAX)
                .await
                .expect("read body");
            assert!(body.is_empty(), "path {path} body must be empty, got {body:?}");
        }
    }

    /// The bare 404 helper itself: empty body, no content-type — the exact
    /// shape `routes::admin::admin_not_found()` gives, so the two are
    /// provably the same construction, not just coincidentally equal today.
    #[tokio::test]
    async fn bare_not_found_has_no_body_and_no_content_type_header() {
        let resp = bare_not_found();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(resp.headers().get(axum::http::header::CONTENT_TYPE).is_none());
        let body = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        assert!(body.is_empty());
    }

    /// `main()`'s three listeners (main/dashboard/admin) share one shutdown
    /// broadcast and are joined with `tokio::try_join!`, not `select!` — the
    /// 2026-09-22 admin-listener-split review caught that `select!` resolves
    /// on whichever listener finishes FIRST, and a quiet dashboard/admin
    /// listener (nothing in flight) routinely finishes before the main
    /// listener's real traffic drains, cutting the 30-second drain window
    /// short on every SIGTERM. `main()` itself isn't callable from a test
    /// (real sockets on fixed ports, needs a database), so this reproduces
    /// the identical shape — two `axum::serve(...).with_graceful_shutdown`
    /// futures sharing one `broadcast` channel — with a real TCP connection
    /// held open past the shutdown signal, and proves `try_join!` does NOT
    /// resolve until that connection's request finishes.
    #[tokio::test]
    async fn try_join_waits_for_the_slower_listener_to_finish_draining() {
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::io::AsyncWriteExt;
        use tokio::net::{TcpListener, TcpStream};
        use tokio::sync::{broadcast, Notify};

        // "Busy" listener: its one handler blocks on `hold` until released,
        // standing in for a request still in flight when shutdown fires.
        let hold = Arc::new(Notify::new());
        let hold_for_handler = hold.clone();
        let busy_router = axum::Router::new().route(
            "/hold",
            axum::routing::get(move || {
                let hold = hold_for_handler.clone();
                async move {
                    hold.notified().await;
                    "released"
                }
            }),
        );
        let busy_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind busy listener");
        let busy_addr = busy_listener.local_addr().expect("busy listener addr");

        // "Idle" listener: nothing ever connects to it, so its graceful
        // shutdown resolves the instant the signal fires — the role the
        // dashboard/admin listeners play against a quiet operator.
        let idle_router = axum::Router::new().route("/", axum::routing::get(|| async { "ok" }));
        let idle_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind idle listener");

        let (shutdown_tx, _) = broadcast::channel::<()>(1);
        let mut busy_shutdown_rx = shutdown_tx.subscribe();
        let mut idle_shutdown_rx = shutdown_tx.subscribe();

        let busy_serve = async move {
            axum::serve(busy_listener, busy_router)
                .with_graceful_shutdown(async move {
                    let _ = busy_shutdown_rx.recv().await;
                })
                .await
        };
        let idle_serve = async move {
            axum::serve(idle_listener, idle_router)
                .with_graceful_shutdown(async move {
                    let _ = idle_shutdown_rx.recv().await;
                })
                .await
        };

        // Open a real in-flight request against the busy listener — a raw
        // HTTP/1.1 GET, written by hand (no new client dependency): the
        // handler above blocks on `hold` the moment it starts running, so
        // the connection stays open until this test releases it.
        let mut client = TcpStream::connect(busy_addr)
            .await
            .expect("connect to busy listener");
        client
            .write_all(b"GET /hold HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("write request");

        // Same shape as `main()`: spawn the joined pair as its own task so
        // this test can observe it from the outside via `JoinHandle`
        // rather than pinning/polling a macro-generated future by hand.
        let join_handle = tokio::spawn(async move { tokio::try_join!(busy_serve, idle_serve) });

        // Give the server a moment to accept the connection and reach the
        // handler's `hold.notified().await`, then fire shutdown — the same
        // sequence a real SIGTERM produces against `main()`'s listeners.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = shutdown_tx.send(());

        // Well past the point an idle listener alone would have resolved
        // (`select!`'s old, buggy exit point), the joined future must still
        // be pending — proving `try_join!` is correctly waiting on the busy
        // listener's held connection, not racing ahead on the idle one.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !join_handle.is_finished(),
            "try_join! resolved before the busy listener's in-flight request finished draining"
        );

        // Release the held request; the joined future must now finish
        // promptly, and both toy listeners must report a clean shutdown.
        hold.notify_one();
        tokio::time::timeout(Duration::from_secs(2), join_handle)
            .await
            .expect("try_join! did not finish within 2s of releasing the held request")
            .expect("join task panicked")
            .expect("both toy listeners should shut down cleanly");
    }
}

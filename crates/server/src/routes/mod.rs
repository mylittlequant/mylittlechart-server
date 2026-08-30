//! Route assembly for the `/api` sub-router.
//!
//! Note: rate limiting for public endpoints (telemetry, heartbeat) is handled at the
//! Cloudflare level. `tower_governor 0.4` is incompatible with `axum 0.8` (axum-core
//! version mismatch), so application-level rate limiting is deferred until a compatible
//! version is available.

use axum::{
    extract::DefaultBodyLimit,
    routing::{delete, get, patch, post},
    Router,
};
use std::sync::Arc;

use crate::state::AppState;

pub mod admin;
pub mod agent_keys;
pub mod dashboard;
pub mod device_auth;
pub mod heartbeat;
pub mod link;
pub mod oauth;
pub mod proxy;
pub mod sessions;
pub mod sync;
pub mod telemetry;
pub mod tg_login;
pub mod updates;

/// Build the `/api` sub-router for a control-role process: every endpoint,
/// unchanged from before the 2026-08-30 control/edge split.
/// The state is `Arc<AppState>` and is attached via `.with_state()` on the outer router.
pub fn control_api_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Admin endpoints — protected by ADMIN_SECRET.
        .route(
            "/admin/upload",
            post(admin::upload_binary).layer(DefaultBodyLimit::max(200 * 1024 * 1024)),
        )
        .route("/admin/restart", post(admin::restart))
        .route("/admin/promote", post(admin::promote))
        // Standard routes (axum default 2MB is fine).
        .route("/proxy/entitlement", get(proxy::entitlement))
        .route("/heartbeat", post(heartbeat::handle_heartbeat))
        .route("/telemetry", post(telemetry::submit_telemetry))
        .route("/updates/latest", get(updates::get_latest))
        .route(
            "/updates/download/{platform}/{version}",
            get(updates::download_binary),
        )
        .route("/oauth/{provider}/authorize", get(oauth::authorize))
        .route("/oauth/{provider}/callback", post(oauth::callback))
        .route("/oauth/telegram/callback", post(oauth::telegram_callback))
        // Telegram redirect-flow web callback — client JS POSTs decoded tgAuthResult here.
        .route("/oauth/telegram/web-callback", post(oauth::telegram_web_callback))
        // Web OAuth callback — provider redirects browser here (GET).
        .route("/oauth/{provider}/web-callback", get(oauth::web_callback))
        // Device authorization flow.
        .route("/auth/device-code", post(device_auth::create_code))
        .route("/auth/poll", get(device_auth::poll_code))
        .route("/auth/confirm", post(device_auth::confirm_code))
        .route("/auth/me", get(device_auth::me))
        .route("/auth/logout", post(device_auth::logout))
        // Telegram bot login flow.
        .route("/auth/tg-login", post(tg_login::create_tg_login))
        .route("/auth/tg-login/poll", get(tg_login::poll_tg_login))
        // Device linking flow (OAuth account linking).
        .route("/auth/link/init", post(link::init_link))
        .route("/auth/link/poll", get(link::poll_link))
        .route("/auth/link/confirm", post(link::confirm_link))
        // Agent API key management.
        .route("/auth/keys/generate", post(agent_keys::generate_key))
        .route("/auth/agent-key/request", post(agent_keys::request_agent_key))
        .route("/auth/agent-key/poll", get(agent_keys::poll_agent_key))
        .route("/auth/agent-key/confirm", post(agent_keys::confirm_agent_key))
        .route("/auth/agent-key/deny", post(agent_keys::deny_agent_key))
        .route("/auth/agent-key/info", get(agent_keys::get_agent_key_info))
        .route("/auth/keys", get(agent_keys::list_keys))
        .route("/auth/keys/usage", patch(agent_keys::update_key_usage))
        .route("/auth/keys/{hash_prefix}", delete(agent_keys::revoke_key))
        // Session management (cookie-session auth only).
        .route("/auth/sessions", get(sessions::list_sessions))
        .route("/auth/sessions/{hash_prefix}", delete(sessions::revoke_session))
        // Account self-service (cookie-session auth only).
        .route("/auth/account/export", get(sessions::export_account))
        .route("/auth/account/delete", post(sessions::delete_account))
        // Cloud sync endpoints.
        .route("/sync/status", get(sync::sync_status_handler))
        .route("/sync/changes", get(sync::sync_changes))
        .route("/sync/push", post(sync::sync_push))
        .route("/sync/pull", get(sync::sync_pull))
        .route("/sync/item/{sync_id}", delete(sync::sync_delete_item_handler))
        .route("/sync/all", delete(sync::sync_delete_all_handler))
        .route("/sync/e2e-params", get(sync::sync_get_e2e))
        .route("/sync/e2e-setup", post(sync::sync_setup_e2e))
        .route("/sync/profiles", get(sync::sync_list_profiles))
        .route("/sync/pull-profile", get(sync::sync_pull_profile))
        .with_state(state)
}

/// Build the `/api` sub-router for an edge-role process.
///
/// An edge process holds no `ControlPlane` (see `state.rs`) — every route
/// here must be answerable without touching `AppState::control_plane()`.
/// Deliberately NOT mounted: identity (device-auth, oauth, tg-login, link,
/// agent-key, sessions/account), sync, admin, and updates — all of them read
/// or write the database. Not mounting beats a runtime check: a route that
/// does not exist cannot be reached by a bug, and its absence is verifiable
/// from outside with a plain 404, the same way `/health`'s presence is
/// verifiable with a 200.
///
/// Kept: `/proxy/entitlement`, the one endpoint in the full router that
/// takes no `State` at all — it reads only `MLC_PROXY_GATE` from the
/// environment. `heartbeat` and `telemetry` are intentionally NOT kept here
/// even though they are public/unauthenticated: both write to the database
/// (see routes/heartbeat.rs, routes/telemetry.rs), so mounting them on edge
/// would 500 on every call. Stage 2 (rate-limit lease) is the reason this
/// router exists at all, but it lands as its own follow-up, not a
/// db-shaped hole opened today.
pub fn edge_api_router(_state: Arc<AppState>) -> Router {
    Router::new().route("/proxy/entitlement", get(proxy::entitlement))
}

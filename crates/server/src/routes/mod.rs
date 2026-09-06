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

pub mod account;
pub mod admin;
pub mod agent_keys;
pub mod dashboard;
pub mod device_auth;
pub mod dm;
pub mod entitlements;
pub mod forum;
pub mod forum_v2;
pub mod heartbeat;
pub mod link;
pub mod oauth;
pub mod posts;
pub mod proxy;
pub mod sessions;
pub mod share;
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
        .route("/admin/register-release", post(admin::register_release))
        .route("/admin/restart", post(admin::restart))
        .route("/admin/promote", post(admin::promote))
        .route("/admin/gift-codes", post(admin::mint_gift_codes))
        .route("/admin/posts", post(posts::admin_upsert_post))
        .route("/admin/posts/{id}", delete(posts::admin_delete_post))
        // In-app blog: patch notes and posts (see routes/posts.rs). Public.
        .route("/posts", get(posts::list_posts))
        .route("/posts/{id}", get(posts::get_post))
        // Standard routes (axum default 2MB is fine).
        .route("/proxy/entitlement", get(proxy::entitlement))
        // General entitlements probe — superset of /proxy/entitlement, answers
        // for anonymous callers too. Needs the database to resolve a caller
        // (session/bearer), so control role only (see edge_api_router below).
        .route("/entitlements", get(entitlements::get_entitlements))
        .route("/heartbeat", post(heartbeat::handle_heartbeat))
        .route("/telemetry", post(telemetry::submit_telemetry))
        .route("/updates/latest", get(updates::get_latest))
        .route("/updates/list", get(updates::list_releases))
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
        // Gift/trial code redemption (cookie-session or bearer auth, same as sync).
        .route("/account/redeem", post(account::redeem))
        // Account nick change (cookie-session or bearer auth, same as redeem).
        .route("/account/nick", post(account::set_nick))
        // Chart share links. Creation/listing/revoke are authenticated; the
        // two GETs by token are public — the token is the capability (see
        // routes/share.rs). `/share/mine` is a static segment, which matchit
        // prioritises over the `{token}` parameter, so registration order
        // here carries no meaning.
        .route("/share/live", post(share::create_live_share))
        .route(
            "/share/screenshot",
            post(share::create_screenshot_share)
                // PNG bodies — the one route that outgrows axum's default
                // 2MB body limit (see the note above).
                .layer(DefaultBodyLimit::max(8 * 1024 * 1024)),
        )
        .route("/share/mine", get(share::list_my_shares))
        .route("/share/{token}", get(share::get_share).delete(share::delete_share))
        .route("/share/{token}/png", get(share::get_share_png))
        // Clone-with-strip (rights v1): auth required, needs the `clone`
        // right on the token (see routes/share.rs's module doc).
        .route("/share/{token}/clone", post(share::clone_share))
        // Paid in-app forum (entitlements::Feature::Forum) — every route
        // authed AND paid, no public GET of any kind (see routes/forum.rs).
        .route(
            "/forum/threads",
            get(forum::list_threads).post(forum::create_thread),
        )
        .route(
            "/forum/threads/{id}",
            get(forum::get_thread).delete(forum::delete_thread),
        )
        .route("/forum/threads/{id}/replies", post(forum::create_reply))
        .route("/forum/replies/{id}", delete(forum::delete_reply))
        .route("/admin/forum/hide", post(forum::admin_hide))
        // Forum engine v2 (public boards, role-gated read/write — see
        // routes/forum_v2.rs). Additive: v1's `/forum/*` routes above are
        // untouched.
        .route("/forum/boards", get(forum_v2::list_boards))
        .route(
            "/forum/boards/{slug}/threads",
            get(forum_v2::list_board_threads).post(forum_v2::create_board_thread),
        )
        .route("/forum/v2/threads/{id}", get(forum_v2::get_thread))
        .route("/forum/v2/threads/{id}/replies", post(forum_v2::create_reply))
        .route("/forum/v2/threads/{id}/moderate", post(forum_v2::moderate_thread))
        .route("/forum/v2/replies/{id}", delete(forum_v2::delete_reply))
        .route("/forum/search", get(forum_v2::search))
        .route("/admin/forum/boards", post(forum_v2::admin_create_board))
        .route(
            "/admin/forum/boards/{id}",
            patch(forum_v2::admin_update_board).delete(forum_v2::admin_delete_board),
        )
        .route(
            "/admin/forum/roles/{user_id}",
            axum::routing::put(forum_v2::admin_set_role).delete(forum_v2::admin_remove_role),
        )
        // Direct messages (paid, end-to-end encrypted — see routes/dm.rs).
        // Every route is authed AND paid; no public GET of any kind.
        .route(
            "/dm/identity",
            axum::routing::put(dm::publish_identity),
        )
        .route("/dm/identity/{label}", get(dm::get_identity))
        .route(
            "/dm/conversations",
            get(dm::list_conversations).post(dm::create_conversation),
        )
        .route(
            "/dm/conversations/{id}/messages",
            get(dm::list_messages).post(dm::create_message),
        )
        .route("/dm/conversations/{id}/read", post(dm::mark_read))
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
/// takes no `State` at all — it reads only `entitlements::free_features()`
/// (env var `MLC_FREE_FEATURES`) from the environment, no database. The
/// newer `/entitlements` is NOT kept here: it resolves a caller via
/// session/bearer, which needs the database. `heartbeat` and `telemetry`
/// are intentionally NOT kept here either, even though they too are
/// public/unauthenticated: both write to the database
/// (see routes/heartbeat.rs, routes/telemetry.rs), so mounting them on edge
/// would 500 on every call. Stage 2 (rate-limit lease) is the reason this
/// router exists at all, but it lands as its own follow-up, not a
/// db-shaped hole opened today.
pub fn edge_api_router(_state: Arc<AppState>) -> Router {
    Router::new().route("/proxy/entitlement", get(proxy::entitlement))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The full control route table must register without a conflict panic.
    /// This is what proves `/share/mine` (static) coexists with
    /// `/share/{token}` (parameter) and that the GET+DELETE pair on
    /// `/share/{token}` merges, and — since the 2026-09-05 in-app blog —
    /// that `/posts/{id}` and `/admin/posts/{id}` (parameter) coexist with
    /// the static `/posts` and `/admin/posts` — axum/matchit panics at
    /// registration time on a genuinely conflicting pair, so building the
    /// router once is the whole test. Since the same day's paid forum: the
    /// GET+DELETE pair on `/forum/threads/{id}` merges the same way
    /// `/share/{token}` does, and `/forum/threads/{id}/replies` (two
    /// parameter-then-literal segments) coexists with the single-parameter
    /// `/forum/threads/{id}` and the separate `/forum/replies/{id}`.
    /// `control_plane` is `None`: registration never calls a handler, so no
    /// database is needed.
    #[test]
    fn control_router_registers_without_route_conflicts() {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);
        let state = Arc::new(AppState::new(
            None,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            shutdown_tx,
            Vec::new(),
            false,
            0,
            0,
        ));
        let _router = control_api_router(state);
    }

    /// `main.rs` merges the blog router (`/blog/posts.json`, `/blog/feed.xml`,
    /// `/blog/`, `/blog/{id}`) into the top-level app router alongside the
    /// clean-URL fallback `/{dir}/{page}` — the first literal-prefixed
    /// multi-segment route this codebase has registered next to that fully
    /// wildcard pattern. matchit resolves this by segment specificity
    /// (literal `blog` beats a captured `{dir}`) rather than treating it as
    /// a conflicting pair, but that is exactly the kind of shape that panics
    /// at router-build time if wrong — this proves it does not, without
    /// pulling in `main.rs`'s full boot sequence.
    #[test]
    fn literal_prefixed_route_coexists_with_the_double_wildcard_fallback() {
        async fn stub() -> &'static str {
            "ok"
        }
        let _router: Router = Router::new()
            .route("/blog/posts.json", get(stub))
            .route("/blog/feed.xml", get(stub))
            .route("/blog/", get(stub))
            .route("/blog/{id}", get(stub))
            .route("/{page}", get(stub))
            .route("/{dir}/{page}", get(stub));
    }
}

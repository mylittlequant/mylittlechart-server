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
        // Static, not `/admin/users/{id}` — see this file's `//!` note near
        // the tests module on static-vs-parameter coexistence; nothing here
        // collides with it either way, since no `/admin/users/{...}` route
        // exists.
        .route("/admin/users", get(admin::list_users))
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
        .route("/forum/me", get(forum_v2::me))
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
        // Static, coexists with the parameterized `/admin/forum/roles/{user_id}`
        // right below the same way `/admin/users` coexists above.
        .route("/admin/forum/roles", get(forum_v2::admin_list_roles))
        .route(
            "/admin/forum/roles/{user_id}",
            axum::routing::put(forum_v2::admin_set_role).delete(forum_v2::admin_remove_role),
        )
        // Literal `by-nick` segment under the same `/admin/forum/roles/`
        // prefix as the `{user_id}` parameter directly above — matchit
        // resolves a literal segment over a parameter at the same tree
        // depth (proven by `control_router_registers_without_route_conflicts`
        // below, the same way `/share/mine` coexists with `/share/{token}`),
        // so this is not the shadowing case the static-vs-parameter note
        // above warns about.
        .route(
            "/admin/forum/roles/by-nick/{nick}",
            axum::routing::put(forum_v2::admin_set_role_by_nick)
                .delete(forum_v2::admin_remove_role_by_nick),
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
            None,
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

    /// Build a control-role `AppState` with `control_plane: None` and the
    /// given `ADMIN_SECRET` — every field this admin-gate test suite varies
    /// is `admin_secret`, the rest are the same placeholders
    /// `control_router_registers_without_route_conflicts` above uses.
    fn admin_gate_test_state(admin_secret: &str) -> Arc<AppState> {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);
        Arc::new(AppState::new(
            None,
            admin_secret.to_string(),
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
            None,
        ))
    }

    /// `verify_admin_secret`'s refusal (no bearer at all, here) must be
    /// byte-for-byte the same response axum's own routing gives an unmatched
    /// path under this router — same status, same headers, same (empty)
    /// body. This is what makes the admin surface invisible from outside: a
    /// probe cannot tell "this route exists but the secret is wrong" apart
    /// from "this route was never registered" (see
    /// `routes::admin::verify_admin_secret`'s doc comment).
    #[tokio::test]
    async fn unauthenticated_admin_route_is_indistinguishable_from_an_unknown_path() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let router = control_api_router(admin_gate_test_state("s3cr3t"));

        let unknown = router
            .clone()
            .oneshot(
                Request::get("/admin/this-route-does-not-exist")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("Router::call is infallible");
        let admin_no_auth = router
            .oneshot(
                Request::post("/admin/restart")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("Router::call is infallible");

        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
        assert_eq!(unknown.status(), admin_no_auth.status());

        // `content-length` is excluded on purpose: axum's own top-level
        // `RouteFuture` wrapper (routing/route.rs, `set_content_length`)
        // inserts it for any MATCHED route regardless of what the handler
        // answers — `/admin/restart` gets one because it IS registered,
        // while a path matching nothing never reaches a `Route` at all and
        // skips that wrapper entirely. Both become `content-length: 0` the
        // moment either response is actually serialized over HTTP/1.1 (a
        // complete zero-byte body always gets one), so this is an
        // axum-internal dispatch artifact invisible to a real prober, not a
        // live discriminator — every other header (there are none here) and
        // the body still have to match exactly, which the asserts below do.
        let mut unknown_headers = unknown.headers().clone();
        let mut admin_headers = admin_no_auth.headers().clone();
        unknown_headers.remove(axum::http::header::CONTENT_LENGTH);
        admin_headers.remove(axum::http::header::CONTENT_LENGTH);
        assert_eq!(unknown_headers, admin_headers);

        let unknown_body = to_bytes(unknown.into_body(), usize::MAX)
            .await
            .expect("read unknown-path body");
        let admin_body = to_bytes(admin_no_auth.into_body(), usize::MAX)
            .await
            .expect("read admin-refusal body");
        assert_eq!(unknown_body, admin_body);
        assert!(unknown_body.is_empty());
    }

    /// A wrong (but well-formed) bearer gets the exact same 404 as a missing
    /// one — the refusal shape does not vary with how wrong the caller is.
    #[tokio::test]
    async fn admin_route_refuses_with_404_on_wrong_bearer() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let router = control_api_router(admin_gate_test_state("s3cr3t"));

        let resp = router
            .oneshot(
                Request::post("/admin/restart")
                    .header("Authorization", "Bearer wrong-secret")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("Router::call is infallible");

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// `ADMIN_SECRET` unset at boot must still refuse with the same 404 —
    /// never a 503 that would confirm the route exists, and never accepting
    /// an empty bearer just because the configured secret is also empty
    /// (the empty-secret check in `verify_admin_secret` runs before the
    /// token comparison ever could).
    #[tokio::test]
    async fn admin_route_refuses_with_404_when_admin_secret_is_unset() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let router = control_api_router(admin_gate_test_state(""));

        let resp = router
            .oneshot(
                Request::post("/admin/restart")
                    .header("Authorization", "Bearer ")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("Router::call is infallible");

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}

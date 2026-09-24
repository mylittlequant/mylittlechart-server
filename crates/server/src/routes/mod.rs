//! Route assembly for the `/api` sub-router.
//!
//! Rate limiting: `tower_governor 0.4` is incompatible with `axum 0.8`
//! (axum-core version mismatch), so application-level limiting is a small
//! purpose-built per-IP token-bucket middleware instead — see `ratelimit.rs`,
//! layered onto `api_router` in `main.rs` before `.nest("/api", …)`. Two of
//! the busiest public writes (`/api/telemetry`, `/api/heartbeat`) ALSO get a
//! second, independent limit at the nginx layer in front
//! (`ops/nginx-mlc-ratelimit.conf`); the auth-poll paths get the same
//! nginx-layer treatment now too.
//!
//! Admin surface (2026-09-22 split): every `ADMIN_SECRET`-gated `/admin/*`
//! route lives in [`admin_api_router`], never in [`control_api_router`] —
//! closing the gap `docs/mlc/audits/api-surface-hardening-2026-09-10.md`
//! §3/§6 named (no separate listener carved out for `/api/admin`; it rode
//! the same path as `/api/posts`). Both routers are mounted as
//! `.nest("/api", …)`, so every admin path keeps its `/api/admin/...` shape
//! unchanged — only the listener a caller has to reach differs: `main.rs`
//! binds `admin_api_router` on its own loopback listener (`ADMIN_BIND`/
//! `ADMIN_PORT`, default `127.0.0.1:19238`, control role only), reachable
//! operator-side only through an SSH tunnel (`ops/README.md`).
//! `ADMIN_SECRET` stays the second lock — the tunnel is the first, not a
//! replacement.

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
pub mod matrix;
pub mod notify;
pub mod oauth;
pub mod posts;
pub mod proxy;
pub mod rooms;
pub mod sessions;
pub mod share;
pub mod sync;
pub mod telemetry;
pub mod tg_login;
pub mod updates;

/// Build the `/api` sub-router for a control-role process: every public
/// endpoint except `/admin/*`. Admin endpoints (`ADMIN_SECRET`-gated) are
/// NOT mounted here — see [`admin_api_router`], mounted on its own loopback
/// listener in `main.rs` (`ADMIN_BIND`/`ADMIN_PORT`, default
/// `127.0.0.1:19238`, control role only) so the admin surface is
/// unreachable from this router's listener regardless of bearer (see this
/// module's `//!` doc for the 2026-09-22 split and why).
/// The state is `Arc<AppState>` and is attached via `.with_state()` on the outer router.
pub fn control_api_router(state: Arc<AppState>) -> Router {
    Router::new()
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
        // Shared presets (rooms) — server-hosted, per-nick rights, per-entity
        // LWW patch, no live channel yet (Phase 1 — see routes/rooms.rs's
        // module doc). `{kind}` is reserved for future object kinds; Phase 1
        // resolves only "preset". `/patch` doubles as create-if-absent.
        .route(
            "/objects/{kind}/{object_id}",
            get(rooms::get_room).post(rooms::create_room).delete(rooms::delete_room),
        )
        .route("/objects/{kind}/{object_id}/patch", post(rooms::patch_room))
        .route("/objects/{kind}/{object_id}/entities", get(rooms::get_room_entities))
        .route("/objects/{kind}/{object_id}/clone", post(rooms::clone_room))
        .route(
            "/objects/{kind}/{object_id}/grants",
            get(rooms::list_grants).post(rooms::create_grant),
        )
        .route("/objects/{kind}/{object_id}/grants/{grant_id}", delete(rooms::delete_grant))
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
        // Direct messages (paid, end-to-end encrypted — see routes/dm.rs).
        // Every route is authed AND paid; no public GET of any kind.
        .route(
            "/dm/identity",
            axum::routing::put(dm::publish_identity),
        )
        .route("/dm/identity/{label}", get(dm::get_identity))
        // Recipient search by nick/display name (see routes/dm.rs's module
        // doc) — a plain static single-segment path, same depth as
        // `/dm/conversations` below, no parameter to coexist with.
        .route("/dm/lookup", get(dm::lookup_recipients))
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

/// Build the `/api` sub-router carrying every `ADMIN_SECRET`-gated route —
/// split out of [`control_api_router`] (2026-09-22 admin-listener
/// hardening; see this module's `//!` doc for why). Mounted the same way as
/// `control_api_router` — `.nest("/api", admin_api_router(...))` in
/// `main.rs` — so every route here keeps its `/api/admin/...` path
/// unchanged; only the listener a caller has to reach differs: a separate
/// loopback bind (`ADMIN_BIND`/`ADMIN_PORT`, default `127.0.0.1:19238`,
/// control role only), reachable operator-side only through an SSH tunnel
/// (see `ops/README.md`). `ADMIN_SECRET` is still checked on every route
/// here — the listener split is a first lock, not a replacement for it.
/// The state is `Arc<AppState>` and is attached via `.with_state()` on the outer router.
pub fn admin_api_router(state: Arc<AppState>) -> Router {
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
        // Static two-segment path under the same `/admin/users` prefix —
        // coexists with the single-segment `/admin/users` directly above the
        // same way `/admin/forum/roles/by-nick/{nick}` coexists with
        // `/admin/forum/roles/{user_id}` further down (proven by
        // `admin_router_registers_without_route_conflicts` below).
        .route("/admin/users/merge", post(admin::merge_users))
        // Reserved-nick registry (owner ruling 2026-09-09) — GET is static,
        // PUT/DELETE address one entry by path param, same static-vs-
        // parameter coexistence as `/admin/forum/roles` +
        // `/admin/forum/roles/{user_id}` further down.
        .route("/admin/nicks/reserved", get(admin::list_reserved_nicks))
        .route(
            "/admin/nicks/reserved/{nick}",
            axum::routing::put(admin::upsert_reserved_nick).delete(admin::delete_reserved_nick),
        )
        // Grant a nick to a specific account, bypassing the self-service
        // reserved-list/cooldown gates — a third path segment under
        // `/admin/users/{user_id}`, coexisting with the static `/admin/users`
        // and `/admin/users/merge` above the same way
        // `/forum/threads/{id}/replies` coexists with `/forum/threads/{id}`
        // (in `control_api_router`).
        .route("/admin/users/{user_id}/nick", axum::routing::put(admin::admin_set_user_nick))
        // Extend an account's paid access directly (operator accounts, or a
        // support fix) — a gift code needs the redeeming account's own
        // session, which does not exist here; a fourth path segment under
        // `/admin/users/{user_id}`, same coexistence as the nick route
        // right above it.
        .route("/admin/users/{user_id}/paid-days", post(admin::grant_paid_days))
        // Owner outreach (2026-09-09) — static two-segment path under the
        // one-segment `/admin/notify` right above it, same static-vs-static
        // coexistence as `/admin/users` + `/admin/users/merge` above (see
        // routes/notify.rs for the handlers).
        .route("/admin/notify", post(notify::notify))
        .route("/admin/notify/batches", get(notify::list_batches))
        .route("/admin/posts", post(posts::admin_upsert_post))
        .route("/admin/posts/{id}", delete(posts::admin_delete_post))
        // Hide any v1 forum thread or reply, admin-only (see routes/forum.rs
        // — the paid, non-admin `/forum/*` v1 routes live in
        // `control_api_router`; this is the one ADMIN_SECRET-gated route
        // that module registers).
        .route("/admin/forum/hide", post(forum::admin_hide))
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
        // depth (proven by `admin_router_registers_without_route_conflicts`
        // below, the same way `/share/mine` coexists with `/share/{token}`
        // in `control_api_router`), so this is not the shadowing case the
        // static-vs-parameter note above warns about.
        .route(
            "/admin/forum/roles/by-nick/{nick}",
            axum::routing::put(forum_v2::admin_set_role_by_nick)
                .delete(forum_v2::admin_remove_role_by_nick),
        )
        // Forum v2 trusted standing (`Class::Trusted` — owner ruling
        // 2026-09-09, plan §5). Same static/parameter/by-nick coexistence as
        // the role CRUD directly above.
        .route("/admin/forum/trusted", get(forum_v2::admin_list_trusted))
        .route(
            "/admin/forum/trusted/{user_id}",
            axum::routing::put(forum_v2::admin_set_trusted).delete(forum_v2::admin_remove_trusted),
        )
        .route(
            "/admin/forum/trusted/by-nick/{nick}",
            axum::routing::put(forum_v2::admin_set_trusted_by_nick)
                .delete(forum_v2::admin_remove_trusted_by_nick),
        )
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

/// Build the `/_matrix` sub-router for a control-role process — the Matrix
/// Client-Server API subset (see `routes::matrix`'s module doc and
/// `docs/mlc/plans/messenger-proto-server-matrix-subset-2026-09-24.md`).
/// Mounted as `.nest("/_matrix", …)` in `main.rs`, a sibling of
/// `.nest("/api", …)` — never called for an edge-role process, which holds
/// no `ControlPlane` to resolve a caller or a room against.
pub fn matrix_api_router(state: Arc<AppState>) -> Router {
    matrix::router(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The full control route table (admin routes excluded — see
    /// `admin_router_registers_without_route_conflicts` below for those)
    /// must register without a conflict panic. This is what proves
    /// `/share/mine` (static) coexists with `/share/{token}` (parameter) and
    /// that the GET+DELETE pair on `/share/{token}` merges, and — since the
    /// 2026-09-05 in-app blog — that `/posts/{id}` (parameter) coexists with
    /// the static `/posts` — axum/matchit panics at registration time on a
    /// genuinely conflicting pair, so building the router once is the whole
    /// test. Since the same day's paid forum: the GET+DELETE pair on
    /// `/forum/threads/{id}` merges the same way `/share/{token}` does, and
    /// `/forum/threads/{id}/replies` (two parameter-then-literal segments)
    /// coexists with the single-parameter `/forum/threads/{id}` and the
    /// separate `/forum/replies/{id}`. `control_plane` is `None`:
    /// registration never calls a handler, so no database is needed.
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

    /// The full admin route table must register without a conflict panic —
    /// the counterpart of `control_router_registers_without_route_conflicts`
    /// above, split out 2026-09-22. This is what proves `/admin/users`
    /// (static) coexists with `/admin/users/merge` and
    /// `/admin/users/{user_id}/nick` (both under the same prefix),
    /// `/admin/nicks/reserved` (static) coexists with
    /// `/admin/nicks/reserved/{nick}` (parameter), `/admin/notify` coexists
    /// with `/admin/notify/batches`, `/admin/posts` coexists with
    /// `/admin/posts/{id}`, `/admin/forum/boards` coexists with
    /// `/admin/forum/boards/{id}`, and — the deepest case — the static
    /// `/admin/forum/roles`/`/admin/forum/trusted` each coexist with both
    /// their own `{user_id}` parameter route AND the literal `by-nick/{nick}`
    /// segment at the same tree depth. `control_plane` is `None`:
    /// registration never calls a handler, so no database is needed.
    #[test]
    fn admin_router_registers_without_route_conflicts() {
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
        let _router = admin_api_router(state);
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

    /// Since the 2026-09-22 admin-listener split, `/api/admin/*` is not
    /// registered on `control_api_router` at all — this proves the
    /// invariant the pre-split test of this name used to prove by masking
    /// (`admin_not_found()` answering byte-for-byte like an unmatched path)
    /// now holds structurally instead: an `/admin/*` path on this router
    /// hits matchit's own "nothing registered" fallback, the exact same
    /// code path a path that was never anything hits. Unlike the pre-split
    /// test, `content-length` needs no exclusion here — neither response
    /// ever reaches a matched `Route` (see
    /// `admin_router_unauthenticated_route_is_indistinguishable_from_an_unknown_path`
    /// below for the same proof against `admin_api_router`, where
    /// `/admin/restart` IS a matched route and the exclusion is still
    /// needed).
    #[tokio::test]
    async fn admin_paths_are_ordinary_unknown_paths_on_the_public_router() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let router = control_api_router(admin_gate_test_state("s3cr3t"));

        let unknown = router
            .clone()
            .oneshot(
                Request::get("/totally-unknown-path-2026-09-22")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("Router::call is infallible");
        let admin_path = router
            .oneshot(
                Request::post("/admin/restart")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("Router::call is infallible");

        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
        assert_eq!(unknown.status(), admin_path.status());
        assert_eq!(unknown.headers(), admin_path.headers());

        let unknown_body = to_bytes(unknown.into_body(), usize::MAX)
            .await
            .expect("read unknown-path body");
        let admin_body = to_bytes(admin_path.into_body(), usize::MAX)
            .await
            .expect("read admin-path body");
        assert_eq!(unknown_body, admin_body);
        assert!(unknown_body.is_empty());
    }

    /// On `admin_api_router` itself, `verify_admin_secret`'s refusal (no
    /// bearer at all, here) must still be byte-for-byte the same response
    /// axum's own routing gives an unmatched path under this router — same
    /// status, same headers, same (empty) body. This is what makes the
    /// admin surface invisible from outside a caller who already reached
    /// its listener (the loopback bind + SSH tunnel are the first lock,
    /// this masking is the second): a probe cannot tell "this route exists
    /// but the secret is wrong" apart from "this route was never
    /// registered" (see `routes::admin::verify_admin_secret`'s doc comment).
    #[tokio::test]
    async fn admin_router_unauthenticated_route_is_indistinguishable_from_an_unknown_path() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let router = admin_api_router(admin_gate_test_state("s3cr3t"));

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
    async fn admin_router_refuses_with_404_on_wrong_bearer() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let router = admin_api_router(admin_gate_test_state("s3cr3t"));

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
    async fn admin_router_refuses_with_404_when_admin_secret_is_unset() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let router = admin_api_router(admin_gate_test_state(""));

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

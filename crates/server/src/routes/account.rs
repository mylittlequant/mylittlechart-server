//! Account self-service endpoints that stand on their own rather than
//! belonging to a single provider identity or session (see `sessions.rs`
//! for the `/auth/account/*` ones that do).
//!
//! `POST /api/account/redeem` — gift/trial code redemption. `db.rs`'s
//! `gift_codes` table and `db::redeem_gift_code` hold the actual logic;
//! `routes::admin::mint_gift_codes` is the admin side that produces the
//! codes this endpoint consumes. Authenticates the same way `/api/sync/*`
//! does — `session_id` cookie or `Authorization: Bearer` — so a code can be
//! redeemed from either the web dashboard or the desktop app.
//!
//! `POST /api/account/nick` — change the caller's account nick (operator
//! ruling 2026-09-05). `db::set_nick` holds the validation, uniqueness, and
//! cooldown logic; see its doc comment. Same authentication as `redeem`.

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::collections::HashSet;
use std::sync::Arc;

use crate::auth::{extract_bearer, extract_session_id, extract_ua_hash, hash_token};
use crate::db::{NickError, RedeemOutcome};
use crate::models::types::ErrorResponse;
use crate::state::AppState;

/// Resolve the authenticated `user_id` from either a cookie session or a
/// Bearer token. Mirrors `routes::sync::resolve_user_id` (same credential
/// lookup, same "no credential is a 401" rule) — duplicated rather than
/// shared, following the existing pattern of `routes::entitlements`'s own
/// `resolve_caller`, since each caller's exact anonymous/error handling
/// differs and there is no third caller yet to justify extracting it.
pub(crate) async fn resolve_user_id(state: Arc<AppState>, headers: &HeaderMap) -> Result<i64, StatusCode> {
    let session_id = extract_session_id(headers);
    let ua_hash = extract_ua_hash(headers);
    let bearer: Option<String> = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| extract_bearer(Some(v)))
        .map(|s| s.to_owned());

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<i64>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(sid) = session_id {
            if let Some(uid) = crate::db::resolve_web_session(&conn, &sid, &ua_hash)? {
                return Ok(Some(uid));
            }
        }

        if let Some(raw_token) = bearer {
            let token_hash = hash_token(&raw_token);
            if let Some(uid) = crate::db::resolve_token_hash_with_expiry(&conn, &token_hash)? {
                return Ok(Some(uid));
            }
        }

        Ok(None)
    })
    .await;

    match result {
        Ok(Ok(Some(uid))) => Ok(uid),
        Ok(Ok(None)) => Err(StatusCode::UNAUTHORIZED),
        Ok(Err(_)) | Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Request body for POST /api/account/redeem.
#[derive(serde::Deserialize)]
pub struct RedeemRequest {
    pub code: String,
}

/// POST /api/account/redeem
///
/// Redeems a gift/trial code minted by `POST /api/admin/gift-codes`
/// (`routes::admin::mint_gift_codes`), extending the caller's `paid_until`.
/// See `db::redeem_gift_code` for the extend-not-replace rule and the
/// single-use-under-a-race guarantee.
///
/// Response on success: `{ "paid_until": "2026-10-04T12:00:00Z" }`. Distinct
/// `404` for "no such code" vs `409` for "already used" so the client can
/// show the right message instead of a generic failure. The submitted code
/// is never logged in full — only the resulting `user_id`/`paid_until` on
/// success.
pub async fn redeem(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RedeemRequest>,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(StatusCode::UNAUTHORIZED) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new("Authentication required")),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Internal error")),
            )
                .into_response();
        }
    };

    // Normalise so a code pasted with a stray space, or typed lowercase,
    // still matches what mint_gift_codes generated (uppercase, no spaces).
    let code = body.code.trim().to_uppercase();
    if code.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("code is required")),
        )
            .into_response();
    }

    let now = chrono::Utc::now().to_rfc3339();
    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::redeem_gift_code(&conn, &code, user_id, &now)
    })
    .await;

    match result {
        Ok(Ok(RedeemOutcome::Redeemed(paid_until))) => {
            tracing::info!(
                "gift code redeemed: user_id={} new paid_until={}",
                user_id,
                paid_until
            );
            Json(serde_json::json!({ "paid_until": paid_until })).into_response()
        }
        Ok(Ok(RedeemOutcome::NotFound)) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new("No such code")),
        )
            .into_response(),
        Ok(Ok(RedeemOutcome::AlreadyUsed)) => (
            StatusCode::CONFLICT,
            Json(ErrorResponse::new("This code has already been redeemed")),
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error in account_redeem: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

/// Request body for POST /api/account/nick.
#[derive(serde::Deserialize)]
pub struct SetNickRequest {
    pub nick: String,
}

/// POST /api/account/nick
///
/// Changes the caller's account nick (operator ruling 2026-09-05): on
/// creation the column stays NULL and the OAuth `display_name` is the
/// displayed label (see `db::effective_label_for_user`'s fallback chain);
/// the user may change it to a globally unique (case-insensitive) handle at
/// most once every 30 days.
///
/// Format — 3-24 ASCII characters, letters/digits plus `_`, `-`, `.`,
/// starting with a letter or digit, plus the hard shape rules in
/// `nick_policy::nick_shape_ok` (no trailing separator, no public-id- or
/// URL-shaped handle, no long digit run) — is checked here before the
/// database is ever touched; `db::set_nick` re-checks both as its own
/// backstop, then enforces the forbidden-nick registry, the reserved-name
/// list (exact and impersonation-by-prefix), uniqueness, and the cooldown.
///
/// A successful change also re-stamps the new label as `displayname` into the
/// caller's Matrix member events (every room they are joined or invited in,
/// `routes::matrix::rooms::propagate_display_name_change`) and wakes those
/// rooms' members, so peers' clients pick up the new name.
///
/// Response on success: `{ "nick": "...", "effective_label": "..." }`.
/// `400` invalid format or forbidden nick (distinguished by the `code`
/// field alongside `error`), `409` taken or reserved (distinguished in the
/// `error` string), `429` rate-limited — that response also carries
/// `nick_changed_at` and `next_allowed_at` (both RFC3339) alongside `error`.
pub async fn set_nick(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<SetNickRequest>,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(StatusCode::UNAUTHORIZED) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new("Authentication required")),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Internal error")),
            )
                .into_response();
        }
    };

    let nick = body.nick.trim().to_owned();
    if !crate::db::nick_format_valid(&nick) || !crate::nick_policy::nick_shape_ok(&nick) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Nick must be 3-24 characters: letters, digits, '_', '-', '.', starting with a letter or digit",
                "code": "nick_invalid",
            })),
        )
            .into_response();
    }

    let state_for_wake = state.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<(String, String, String, HashSet<i64>), NickError> {
        let cp = state.control_plane();
        let (old_nick, stored_nick, effective_label) = {
            let conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
            let old_nick = crate::db::nick_for_user(&conn, user_id)?.unwrap_or_default();
            let reserved_cache = cp.reserved_nick_cache_snapshot();
            crate::db::set_nick(&conn, user_id, &nick, &reserved_cache)?;
            // Read back what was actually stored rather than trusting the local
            // `nick` variable — same read-after-write shape as
            // `db::redeem_gift_code` returning the computed `paid_until` instead
            // of echoing the request.
            let stored_nick = crate::db::nick_for_user(&conn, user_id)?.unwrap_or(nick);
            let effective_label = crate::db::effective_label_for_user(&conn, user_id)?;
            (old_nick, stored_nick, effective_label)
        };
        // The identity guard is released before the messenger write (lock
        // order `db` -> `messenger`, and the propagation locks `db` itself):
        // the new nick is re-stamped into the user's Matrix member events so
        // other members' clients show it. The nick change is committed
        // either way; a propagation failure is logged inside.
        let wake_ids = crate::routes::matrix::rooms::propagate_display_name_change(cp, user_id);
        Ok((old_nick, stored_nick, effective_label, wake_ids))
    })
    .await;

    match result {
        Ok(Ok((old_nick, nick, effective_label, wake_ids))) => {
            crate::account_bridge::emit_nick_changed(&old_nick, &nick);
            tracing::info!("nick changed: user_id={} nick={}", user_id, nick);
            state_for_wake.control_plane().live.wake_many(wake_ids.into_iter().map(|id| format!("user:{id}")));
            Json(serde_json::json!({ "nick": nick, "effective_label": effective_label })).into_response()
        }
        Ok(Err(NickError::Invalid)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid nick format", "code": "nick_invalid" })),
        )
            .into_response(),
        Ok(Err(NickError::Forbidden)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "This nick is not allowed", "code": "nick_forbidden" })),
        )
            .into_response(),
        Ok(Err(NickError::Reserved)) => (
            StatusCode::CONFLICT,
            Json(ErrorResponse::new("This nick is reserved")),
        )
            .into_response(),
        Ok(Err(NickError::Taken)) => (
            StatusCode::CONFLICT,
            Json(ErrorResponse::new("This nick is already taken")),
        )
            .into_response(),
        Ok(Err(NickError::RateLimited { changed_at, next_allowed_at })) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "Nick can only be changed once every 30 days",
                "nick_changed_at": changed_at,
                "next_allowed_at": next_allowed_at,
            })),
        )
            .into_response(),
        Ok(Err(NickError::Db(e))) => {
            tracing::error!("DB error in account_set_nick: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct PrivacyBody {
    pub discoverable: bool,
}

/// GET /api/account/friends — discoverable flag and friend nicks.
pub async fn friends(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return status.into_response(),
    };
    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::social_lists(&conn, user_id)
    })
    .await;
    match result {
        Ok(Ok(lists)) => Json(serde_json::json!({
            "discoverable": lists.discoverable,
            "friends": lists.friends,
            "incoming": lists.incoming,
            "outgoing": lists.outgoing,
            "subscriptions": lists.subscriptions,
            "subscribers": lists.subscribers,
            "blocked": lists.blocked,
        }))
        .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Database error")),
        )
            .into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct DiscoverableBody {
    pub on: bool,
}

/// PUT /api/account/discoverable `{on}` -> `200 {"discoverable": on}`.
/// Accounts are NOT discoverable by default: no nick search, directory or
/// by-nick action finds a hidden account except through someone who is already
/// its friend or through a friend invite. Turning it on makes the nick
/// searchable and lets anyone send a friend request (which first makes them a
/// subscriber). The state is also in `GET /api/auth/me` and
/// `GET /api/account/friends`.
pub async fn set_discoverable(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<DiscoverableBody>,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return status.into_response(),
    };
    let on = body.on;
    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::set_account_discoverable(&conn, user_id, on)
    })
    .await;
    match result {
        Ok(Ok(())) => Json(serde_json::json!({ "discoverable": on })).into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Database error")),
        )
            .into_response(),
    }
}

/// PATCH /api/account/privacy — whether nick search may find this account.
pub async fn set_privacy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<PrivacyBody>,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return status.into_response(),
    };
    let on = body.discoverable;
    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::set_account_discoverable(&conn, user_id, on)
    })
    .await;
    match result {
        Ok(Ok(())) => Json(serde_json::json!({ "discoverable": on })).into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Database error")),
        )
            .into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct AddFriendBody {
    pub nick: String,
    #[serde(default)]
    pub action: String,
}

/// POST /api/account/friends — add a nick that search can already see.
pub async fn add_friend(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<AddFriendBody>,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return status.into_response(),
    };
    let nick = body.nick;
    let action = if body.action.is_empty() { "request".to_string() } else { body.action };
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<std::result::Result<(), &'static str>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now().to_rfc3339();
        crate::db::social_act(&conn, user_id, &nick, &action, &now)
    })
    .await;
    match result {
        Ok(Ok(Ok(()))) => Json(serde_json::json!({ "ok": true })).into_response(),
        Ok(Ok(Err("that is you"))) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("that is you")),
        )
            .into_response(),
        Ok(Ok(Err("blocked"))) => (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse::new("blocked")),
        )
            .into_response(),
        Ok(Ok(Err("too many requests"))) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse::new("too many requests")),
        )
            .into_response(),
        Ok(Ok(Err("no request"))) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("no request")),
        )
            .into_response(),
        Ok(Ok(Err(_))) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new("no such nick")),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Database error")),
        )
            .into_response(),
    }
}

/// Request body of `POST /api/account/friend-invites`; every field optional.
#[derive(serde::Deserialize, Default)]
pub struct CreateFriendInviteBody {
    /// How many people may redeem it, 1..=10 (default 1).
    #[serde(default)]
    pub max_uses: Option<i64>,
    /// Days it stays valid, 1..=30 (default 14).
    #[serde(default)]
    pub days: Option<i64>,
}

/// POST /api/account/friend-invites — a link the other person opens to become
/// friends. `{max_uses?, days?}` -> `200 {"token", "url_path", "max_uses",
/// "expires_at"}`. An invite is the only way to reach an account that is not
/// discoverable. `429 too many invites` once 20 are outstanding.
pub async fn create_friend_invite(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Option<Json<CreateFriendInviteBody>>,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return status.into_response(),
    };
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let max_uses = body.max_uses.unwrap_or(1).clamp(1, crate::db::MAX_FRIEND_INVITE_USES);
    let days = body.days.unwrap_or(14).clamp(1, 30);
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<(std::result::Result<String, &'static str>, String)> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now();
        let exp = (now + chrono::Duration::days(days)).to_rfc3339();
        let made = crate::db::create_friend_invite(&conn, user_id, &now.to_rfc3339(), &exp, max_uses)?;
        Ok((made, exp))
    })
    .await;
    match result {
        Ok(Ok((Ok(token), expires_at))) => Json(serde_json::json!({
            "token": token,
            "url_path": format!("/?friend={token}"),
            "max_uses": max_uses,
            "expires_at": expires_at,
        }))
        .into_response(),
        Ok(Ok((Err(_), _))) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse::new("too many invites")),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Database error")),
        )
            .into_response(),
    }
}

/// GET /api/account/friend-invites — the caller's outstanding invites:
/// `[{"token", "max_uses", "uses", "created_at", "expires_at"}]`.
pub async fn list_friend_invites(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return status.into_response(),
    };
    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::list_friend_invites(&conn, user_id, &chrono::Utc::now().to_rfc3339())
    })
    .await;
    match result {
        Ok(Ok(rows)) => Json(rows).into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Database error")),
        )
            .into_response(),
    }
}

/// DELETE /api/account/friend-invites/{token} — withdraw one of the caller's
/// own invites. `200 {"revoked": true}`, `404` for anyone else's or an unknown one.
pub async fn revoke_friend_invite(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return status.into_response(),
    };
    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::revoke_friend_invite(&conn, user_id, &token)
    })
    .await;
    match result {
        Ok(Ok(true)) => Json(serde_json::json!({ "revoked": true })).into_response(),
        Ok(Ok(false)) => (StatusCode::NOT_FOUND, Json(ErrorResponse::new("no such invite"))).into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Database error")),
        )
            .into_response(),
    }
}

/// POST /api/account/friend-invites/{token}/accept
///
/// Redeems the invite: the caller and the inviter become friends directly,
/// whether or not either is discoverable. `200 {"accepted": true, "friend":
/// "<inviter nick or null>"}`. A missing, expired, used-up or own invite, and
/// an invite of someone who blocked the caller (or whom the caller blocked),
/// all answer the same `400 invite is not valid`.
pub async fn accept_friend_invite(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return status.into_response(),
    };
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<Option<String>>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now().to_rfc3339();
        match crate::db::accept_friend_invite(&conn, &token, user_id, &now)? {
            Some(inviter) => Ok(Some(crate::db::nick_for_user(&conn, inviter)?)),
            None => Ok(None),
        }
    })
    .await;
    match result {
        Ok(Ok(Some(friend))) => Json(serde_json::json!({ "accepted": true, "friend": friend })).into_response(),
        Ok(Ok(None)) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("invite is not valid")),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Database error")),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod privacy_tests {
    use super::*;
    use crate::routes::billing::tests::{app_state, get_json, post_json, sign_in};
    use crate::routes::control_api_router;
    use crate::social_db::Role;
    use axum::Router;
    use serde_json::{json, Value};

    /// An account with a nick; returns `(id, bearer token)`. Hidden, like every new account.
    fn user(state: &Arc<AppState>, nick: &str) -> (i64, String) {
        let (uid, token) = sign_in(state, nick);
        let conn = state.control_plane().db.lock().expect("db");
        crate::db::admin_set_nick(&conn, uid, nick).expect("nick");
        (uid, token)
    }

    async fn act(router: &Router, token: &str, nick: &str, action: &str) -> (StatusCode, Value) {
        post_json(router, token, "/account/friends", json!({ "nick": nick, "action": action }), None).await
    }

    async fn set_discoverable(router: &Router, token: &str, on: bool) -> (StatusCode, Value) {
        let authorization = format!("Bearer {token}");
        crate::routes::billing::tests::send(
            router,
            axum::http::Method::PUT,
            "/account/discoverable",
            &[("authorization", authorization.as_str()), ("content-type", "application/json")],
            Some(json!({ "on": on }).to_string()),
        )
        .await
    }

    async fn lists(router: &Router, token: &str) -> Value {
        get_json(router, token, "/account/friends", None).await.1
    }

    fn names(v: &Value) -> Vec<&str> {
        v.as_array().expect("array").iter().map(|n| n.as_str().expect("nick")).collect()
    }

    async fn search(router: &Router, token: &str, q: &str) -> Vec<String> {
        let (status, body) = get_json(router, token, &format!("/share/lookup?q={q}"), None).await;
        assert_eq!(status, StatusCode::OK);
        body["users"].as_array().expect("users").iter().map(|u| u["nick"].as_str().expect("nick").to_string()).collect()
    }

    async fn invite(router: &Router, token: &str, body: Value) -> (StatusCode, Value) {
        post_json(router, token, "/account/friend-invites", body, None).await
    }

    async fn accept(router: &Router, token: &str, invite_token: &str) -> (StatusCode, Value) {
        post_json(router, token, &format!("/account/friend-invites/{invite_token}/accept"), json!({}), None).await
    }

    #[tokio::test]
    async fn accounts_are_hidden_by_default_and_the_state_is_in_me_and_friends() {
        let state = app_state(None);
        let router = control_api_router(state.clone());
        let (_, alice) = user(&state, "alicehidden");
        let (_, me) = get_json(&router, &alice, "/auth/me", None).await;
        assert_eq!(me["discoverable"], false);
        assert_eq!(lists(&router, &alice).await["discoverable"], false);

        let (status, answer) = set_discoverable(&router, &alice, true).await;
        assert_eq!((status, answer), (StatusCode::OK, json!({ "discoverable": true })));
        let (_, me) = get_json(&router, &alice, "/auth/me", None).await;
        assert_eq!(me["discoverable"], true);
        assert_eq!(lists(&router, &alice).await["discoverable"], true);
        set_discoverable(&router, &alice, false).await;
        assert_eq!(lists(&router, &alice).await["discoverable"], false);
    }

    #[tokio::test]
    async fn a_hidden_account_is_invisible_through_every_nick_path_and_visible_once_the_flag_is_on() {
        let state = app_state(None);
        let router = control_api_router(state.clone());
        let (hidden_id, hidden) = user(&state, "ghostwriter");
        let (seeker_id, seeker) = user(&state, "seekerone");

        // Search, the exact-nick resolver behind share grants and group members, DM labels.
        assert!(search(&router, &seeker, "ghost").await.is_empty());
        {
            let conn = state.control_plane().db.lock().expect("db");
            assert_eq!(crate::db::visible_user_id_for_nick(&conn, seeker_id, "ghostwriter").expect("resolve"), None);
            assert_eq!(crate::db::visible_user_id_for_nick(&conn, seeker_id, "nobodyatall").expect("resolve"), None);
            assert_eq!(crate::db::visible_user_id_for_nick(&conn, hidden_id, "ghostwriter").expect("self"), Some(hidden_id));
            assert_eq!(crate::routes::dm::resolve_user_by_label(&conn, seeker_id, "ghostwriter").expect("dm"), None);
            // The raw ops/staff resolver still sees everyone.
            assert_eq!(crate::db::user_id_for_nick(&conn, "ghostwriter").expect("raw"), Some(hidden_id));
        }

        // Every by-nick action answers exactly like an unknown nick.
        let (_, unknown) = act(&router, &seeker, "nobodyatall", "request").await;
        for action in ["request", "subscribe", "approve", "decline", "remove", "block", "unblock", "unsubscribe"] {
            let (status, body) = act(&router, &seeker, "ghostwriter", action).await;
            assert_eq!((status, &body), (StatusCode::NOT_FOUND, &unknown), "{action}");
        }
        assert_eq!(count(&state, "SELECT COUNT(*) FROM friend_requests"), 0);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM subscriptions"), 0);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM blocks"), 0, "a refused block left no row");

        // Flag on: visible everywhere.
        set_discoverable(&router, &hidden, true).await;
        assert_eq!(search(&router, &seeker, "ghost").await, vec!["ghostwriter".to_string()]);
        {
            let conn = state.control_plane().db.lock().expect("db");
            assert_eq!(crate::db::visible_user_id_for_nick(&conn, seeker_id, "GhostWriter").expect("resolve"), Some(hidden_id));
            assert_eq!(crate::routes::dm::resolve_user_by_label(&conn, seeker_id, "ghostwriter").expect("dm"), Some(hidden_id));
        }
        let (status, _) = act(&router, &seeker, "ghostwriter", "request").await;
        assert_eq!(status, StatusCode::OK);

        // Flag off again: a pending relation keeps working, a stranger sees nothing.
        set_discoverable(&router, &hidden, false).await;
        let (_, stranger) = user(&state, "strangerone");
        assert!(search(&router, &stranger, "ghost").await.is_empty());
        let (status, _) = act(&router, &stranger, "ghostwriter", "request").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = act(&router, &hidden, "seekerone", "approve").await;
        assert_eq!(status, StatusCode::OK, "the hidden account can still answer a request it received");
    }

    #[tokio::test]
    async fn staff_still_resolve_a_hidden_account() {
        let state = app_state(None);
        let router = control_api_router(state.clone());
        let (admin_id, admin) = user(&state, "rootadmin");
        crate::social_db::set_role(&state.control_plane().social_conn(), admin_id, Role::Admin, &chrono::Utc::now().to_rfc3339()).expect("role");
        let (hidden_id, _) = user(&state, "hiddenperson");
        let (status, found) = get_json(&router, &admin, "/staff/user?nick=hiddenperson", None).await;
        assert_eq!(status, StatusCode::OK, "{found}");
        assert_eq!(found["user_id"], hidden_id);
    }

    #[tokio::test]
    async fn request_makes_a_subscriber_approve_makes_friends_decline_keeps_the_subscription() {
        let state = app_state(None);
        let router = control_api_router(state.clone());
        let (_, target) = user(&state, "publictarget");
        let (_, asker) = user(&state, "askerone");
        let (_, other) = user(&state, "askertwo");
        set_discoverable(&router, &target, true).await;

        let (status, _) = act(&router, &asker, "publictarget", "request").await;
        assert_eq!(status, StatusCode::OK);
        let asker_view = lists(&router, &asker).await;
        assert_eq!(names(&asker_view["outgoing"]), vec!["publictarget"]);
        assert_eq!(names(&asker_view["subscriptions"]), vec!["publictarget"], "the requester is a subscriber first");
        assert!(names(&asker_view["friends"]).is_empty());
        let target_view = lists(&router, &target).await;
        assert_eq!(names(&target_view["incoming"]), vec!["askerone"]);
        assert_eq!(names(&target_view["subscribers"]), vec!["askerone"]);
        assert!(names(&target_view["friends"]).is_empty());

        // The hidden requester is reachable for the target by that request.
        let (status, _) = act(&router, &target, "askerone", "approve").await;
        assert_eq!(status, StatusCode::OK);
        for token in [&asker, &target] {
            let view = lists(&router, token).await;
            assert!(view["incoming"].as_array().expect("incoming").is_empty() && view["outgoing"].as_array().expect("outgoing").is_empty());
        }
        assert_eq!(names(&lists(&router, &asker).await["friends"]), vec!["publictarget"]);
        assert_eq!(names(&lists(&router, &target).await["friends"]), vec!["askerone"]);
        assert_eq!(names(&lists(&router, &target).await["subscribers"]), vec!["askerone"], "friends stay followers");

        // Decline: the request goes, the subscription stays until the target blocks.
        act(&router, &other, "publictarget", "request").await;
        let (status, _) = act(&router, &target, "askertwo", "decline").await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = act(&router, &target, "askertwo", "decline").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "nothing left to decline");
        let other_view = lists(&router, &other).await;
        assert!(names(&other_view["friends"]).is_empty() && other_view["outgoing"].as_array().expect("outgoing").is_empty());
        assert_eq!(names(&other_view["subscriptions"]), vec!["publictarget"]);
        assert!(names(&lists(&router, &target).await["subscribers"]).contains(&"askertwo"));
        let (status, _) = act(&router, &target, "askertwo", "block").await;
        assert_eq!(status, StatusCode::OK);
        assert!(!names(&lists(&router, &target).await["subscribers"]).contains(&"askertwo"));
        // A blocked pair cannot see each other any more.
        let (status, body) = act(&router, &other, "publictarget", "request").await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::NOT_FOUND, Some("no such nick")), "a blocked sender is not told it is blocked");
    }

    #[tokio::test]
    async fn a_friend_invite_reaches_a_hidden_account_and_is_single_use_by_default() {
        let state = app_state(None);
        let router = control_api_router(state.clone());
        let (_, hidden) = user(&state, "privateone");
        let (_, guest) = user(&state, "guestone");
        let (_, late) = user(&state, "lateguest");

        let (status, made) = invite(&router, &hidden, json!({})).await;
        assert_eq!(status, StatusCode::OK, "{made}");
        let token = made["token"].as_str().expect("token").to_string();
        assert_eq!((made["max_uses"].as_i64(), made["url_path"].as_str()), (Some(1), Some(format!("/?friend={token}").as_str())));
        assert!(made["expires_at"].is_string());
        let (_, listed) = get_json(&router, &hidden, "/account/friend-invites", None).await;
        assert_eq!((listed[0]["token"].as_str(), listed[0]["uses"].as_i64()), (Some(token.as_str()), Some(0)));

        let (status, done) = accept(&router, &guest, &token).await;
        assert_eq!((status, done["friend"].as_str()), (StatusCode::OK, Some("privateone")), "{done}");
        assert_eq!(names(&lists(&router, &guest).await["friends"]), vec!["privateone"]);
        assert_eq!(names(&lists(&router, &hidden).await["friends"]), vec!["guestone"]);
        // Now they are friends, the hidden account is visible to the guest by nick.
        assert_eq!(search(&router, &guest, "private").await, vec!["privateone".to_string()]);
        assert!(search(&router, &late, "private").await.is_empty());
        // Used up: the same answer as an unknown token.
        let (status, used) = accept(&router, &late, &token).await;
        let (_, unknown) = accept(&router, &late, "00000000000000000000000000000000").await;
        assert_eq!((status, &used), (StatusCode::BAD_REQUEST, &unknown));
        // Nobody can redeem their own link.
        let (_, own) = invite(&router, &hidden, json!({})).await;
        let (status, _) = accept(&router, &hidden, own["token"].as_str().expect("token")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn an_invite_has_a_use_cap_an_expiry_and_a_per_account_limit() {
        let state = app_state(None);
        let router = control_api_router(state.clone());
        let (_, owner) = user(&state, "inviterone");
        let (_, g1) = user(&state, "guestaaa");
        let (_, g2) = user(&state, "guestbbb");
        let (_, g3) = user(&state, "guestccc");

        let (_, made) = invite(&router, &owner, json!({ "max_uses": 2, "days": 3 })).await;
        let token = made["token"].as_str().expect("token").to_string();
        assert_eq!(made["max_uses"], 2);
        assert_eq!(accept(&router, &g1, &token).await.0, StatusCode::OK);
        assert_eq!(accept(&router, &g1, &token).await.0, StatusCode::OK, "a repeat by a friend consumes nothing");
        let (_, listed) = get_json(&router, &owner, "/account/friend-invites", None).await;
        assert_eq!(listed[0]["uses"], 1);
        assert_eq!(accept(&router, &g2, &token).await.0, StatusCode::OK);
        assert_eq!(accept(&router, &g3, &token).await.0, StatusCode::BAD_REQUEST, "the cap is 2");
        assert_eq!(count(&state, "SELECT COUNT(*) FROM friend_invites"), 0, "a used-up invite is deleted");

        // Expiry.
        let (_, made) = invite(&router, &owner, json!({})).await;
        let expired = made["token"].as_str().expect("token").to_string();
        state
            .control_plane()
            .db
            .lock()
            .expect("db")
            .execute("UPDATE friend_invites SET expires_at = ?1", [(chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339()])
            .expect("age");
        assert_eq!(accept(&router, &g3, &expired).await.0, StatusCode::BAD_REQUEST);

        // Revoke: only the owner's own.
        let (_, made) = invite(&router, &owner, json!({})).await;
        let token = made["token"].as_str().expect("token").to_string();
        let authorization = format!("Bearer {g3}");
        let (status, _) = crate::routes::billing::tests::send(
            &router,
            axum::http::Method::DELETE,
            &format!("/account/friend-invites/{token}"),
            &[("authorization", authorization.as_str())],
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let authorization = format!("Bearer {owner}");
        let (status, answer) = crate::routes::billing::tests::send(
            &router,
            axum::http::Method::DELETE,
            &format!("/account/friend-invites/{token}"),
            &[("authorization", authorization.as_str())],
            None,
        )
        .await;
        assert_eq!((status, answer), (StatusCode::OK, json!({ "revoked": true })));
        assert_eq!(accept(&router, &g3, &token).await.0, StatusCode::BAD_REQUEST);

        // At most 20 outstanding.
        for _ in 0..20 {
            assert_eq!(invite(&router, &owner, json!({})).await.0, StatusCode::OK);
        }
        assert_eq!(invite(&router, &owner, json!({})).await.0, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn a_blocked_user_cannot_redeem_an_invite_and_the_invite_is_not_consumed() {
        let state = app_state(None);
        let router = control_api_router(state.clone());
        let (_, owner) = user(&state, "blockerone");
        let (_, blocked) = user(&state, "blockedone");
        let (blocker_of_owner_id, blocker_of_owner) = user(&state, "blockedtwo");
        set_discoverable(&router, &blocked, true).await;
        set_discoverable(&router, &blocker_of_owner, true).await;

        act(&router, &owner, "blockedone", "block").await;
        // The owner is hidden, so the second account blocks it the way it would have
        // after meeting it through an earlier invite: straight in the table.
        let second = blocker_of_owner_id;
        state
            .control_plane()
            .db
            .lock()
            .expect("db")
            .execute(
                "INSERT INTO blocks (user_id, blocked_id, created_at) SELECT ?1, id, 't' FROM users WHERE LOWER(nick) = 'blockerone'",
                [second],
            )
            .expect("block");

        let (_, made) = invite(&router, &owner, json!({ "max_uses": 3 })).await;
        let token = made["token"].as_str().expect("token").to_string();
        // Blocked by the inviter, and having blocked the inviter: both refused as any invalid invite.
        for redeemer in [&blocked, &blocker_of_owner] {
            let (status, body) = accept(&router, redeemer, &token).await;
            assert_eq!((status, body["error"].as_str()), (StatusCode::BAD_REQUEST, Some("invite is not valid")));
        }
        assert_eq!(count(&state, "SELECT COUNT(*) FROM friendships"), 0);
        assert_eq!(count(&state, "SELECT uses FROM friend_invites"), 0, "a refused redemption uses nothing");
        let (_, fine) = user(&state, "fineguest");
        assert_eq!(accept(&router, &fine, &token).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn hidden_friends_stay_reachable_by_nick() {
        let state = app_state(None);
        let router = control_api_router(state.clone());
        let (_, hidden) = user(&state, "keepfriend");
        let (friend_id, friend) = user(&state, "oldfriend");
        let (_, made) = invite(&router, &hidden, json!({})).await;
        accept(&router, &friend, made["token"].as_str().expect("token")).await;
        assert_eq!(search(&router, &friend, "keepf").await, vec!["keepfriend".to_string()]);
        let conn = state.control_plane().db.lock().expect("db");
        assert!(crate::db::visible_user_id_for_nick(&conn, friend_id, "keepfriend").expect("resolve").is_some());
        drop(conn);
        let (status, _) = act(&router, &friend, "keepfriend", "remove").await;
        assert_eq!(status, StatusCode::OK);
        assert!(search(&router, &friend, "keepf").await.is_empty(), "no longer friends: hidden again");
    }

    fn count(state: &Arc<AppState>, sql: &str) -> i64 {
        state.control_plane().db.lock().expect("db").query_row(sql, [], |r| r.get(0)).unwrap_or(0)
    }
}

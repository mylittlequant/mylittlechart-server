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
async fn resolve_user_id(state: Arc<AppState>, headers: &HeaderMap) -> Result<i64, StatusCode> {
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

    let result = tokio::task::spawn_blocking(move || -> Result<(String, String), NickError> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let reserved_cache = state.control_plane().reserved_nick_cache_snapshot();
        crate::db::set_nick(&conn, user_id, &nick, &reserved_cache)?;
        // Read back what was actually stored rather than trusting the local
        // `nick` variable — same read-after-write shape as
        // `db::redeem_gift_code` returning the computed `paid_until` instead
        // of echoing the request.
        let stored_nick = crate::db::nick_for_user(&conn, user_id)?.unwrap_or(nick);
        let effective_label = crate::db::effective_label_for_user(&conn, user_id)?;
        Ok((stored_nick, effective_label))
    })
    .await;

    match result {
        Ok(Ok((nick, effective_label))) => {
            tracing::info!("nick changed: user_id={} nick={}", user_id, nick);
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
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<(bool, Vec<String>)> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let on = crate::db::account_discoverable(&conn, user_id)?;
        let nicks = crate::db::list_friend_nicks(&conn, user_id)?;
        Ok((on, nicks))
    })
    .await;
    match result {
        Ok(Ok((discoverable, friends))) => Json(serde_json::json!({
            "discoverable": discoverable,
            "friends": friends,
        }))
        .into_response(),
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

/// POST /api/account/friend-invites — a link the other person opens to become friends.
pub async fn create_friend_invite(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return status.into_response(),
    };
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<String> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now();
        let exp = (now + chrono::Duration::days(14)).to_rfc3339();
        crate::db::create_friend_invite(&conn, user_id, &now.to_rfc3339(), &exp)
    })
    .await;
    match result {
        Ok(Ok(token)) => Json(serde_json::json!({
            "token": token,
            "url_path": format!("/?friend={token}"),
        }))
        .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Database error")),
        )
            .into_response(),
    }
}

/// POST /api/account/friend-invites/{token}/accept
pub async fn accept_friend_invite(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return status.into_response(),
    };
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now().to_rfc3339();
        crate::db::accept_friend_invite(&conn, &token, user_id, &now)
    })
    .await;
    match result {
        Ok(Ok(true)) => Json(serde_json::json!({ "accepted": true })).into_response(),
        Ok(Ok(false)) => (
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

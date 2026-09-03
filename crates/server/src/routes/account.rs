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

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use crate::auth::{extract_bearer, extract_session_id, extract_ua_hash, hash_token};
use crate::db::RedeemOutcome;
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

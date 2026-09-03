//! GET /api/entitlements — the caller's resolved feature set.
//!
//! The general-purpose successor to the single-boolean placeholder that used
//! to live only in `routes/proxy.rs`. Both endpoints read through
//! `entitlements::free_features()` / `entitlements::resolve_for_user` (see
//! `entitlements.rs`) — this is the one mechanism, `routes/proxy.rs` is a
//! narrower view over the same data, not a second source of truth.
//!
//! Authenticates the same way `/api/sync/*` does — `session_id` cookie or
//! `Authorization: Bearer` (see `auth.rs`) — but unlike sync, an
//! unauthenticated caller is not an error: anonymous users have no account
//! and one purely local profile, and this endpoint still answers for them
//! (the free set), rather than 401ing.

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use crate::auth::{extract_bearer, extract_session_id, extract_ua_hash, hash_token};
use crate::entitlements;
use crate::models::types::ErrorResponse;
use crate::state::AppState;

/// How long the client should treat a resolved set as valid before
/// re-asking. Long enough that a normal session doesn't hammer this
/// endpoint, short enough that flipping `MLC_FREE_FEATURES` (removing a
/// feature from the free list) reaches an already-open client within the
/// hour rather than only on its next login.
const ENTITLEMENTS_TTL_SECS: i64 = 3600;

/// Resolve the caller to a `user_id`, or `None` for anonymous.
///
/// Mirrors `routes::sync::resolve_user_id`'s credential lookup (session
/// cookie, then bearer token) but — unlike sync, which requires an account —
/// treats "no credential offered", "credential invalid", and "credential
/// expired" alike as anonymous rather than an error: anonymous is a real,
/// supported caller here, not a failure mode.
async fn resolve_caller(
    state: Arc<AppState>,
    headers: &HeaderMap,
) -> Result<Option<i64>, StatusCode> {
    let session_id = extract_session_id(headers);
    let ua_hash = extract_ua_hash(headers);
    let bearer: Option<String> = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| extract_bearer(Some(v)))
        .map(|s| s.to_owned());

    if session_id.is_none() && bearer.is_none() {
        // No credential offered at all — anonymous, no DB round-trip needed.
        return Ok(None);
    }

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
        Ok(Ok(uid)) => Ok(uid),
        Ok(Err(_)) | Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// GET /api/entitlements
///
/// Response:
/// ```json
/// { "features": ["archive_proxy", "multi_profile"], "expires_at": 1774903600000 }
/// ```
/// `expires_at` is a millisecond Unix timestamp; the client should re-ask
/// after it passes rather than cache the set indefinitely.
pub async fn get_entitlements(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user_id = match resolve_caller(state.clone(), &headers).await {
        Ok(uid) => uid,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Internal error")),
            )
                .into_response();
        }
    };

    // Anonymous (no credential) never touches the database — false without
    // a round-trip. An authenticated caller's paid fact still needs one.
    let is_paid: bool = match user_id {
        None => false,
        Some(uid) => {
            let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
                let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
                crate::db::user_is_paid(&conn, uid)
            })
            .await;
            match result {
                Ok(Ok(paid)) => paid,
                Ok(Err(e)) => {
                    tracing::error!("DB error checking paid status: {}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse::new("Internal error")),
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
            }
        }
    };

    let features = entitlements::resolve_for_user(is_paid);
    let expires_at = chrono::Utc::now().timestamp_millis() + ENTITLEMENTS_TTL_SECS * 1000;

    Json(serde_json::json!({
        "features": features.wire_names(),
        "expires_at": expires_at,
    }))
    .into_response()
}

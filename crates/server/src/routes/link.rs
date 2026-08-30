//! OAuth account linking flow — allows a desktop app to link to a web account.
//!
//! Flow:
//!   1. Desktop calls POST /api/auth/link/init with its device_name and device_id.
//!      Server returns a link token + a URL the user can open.
//!   2. User opens the URL, logs in via OAuth (receives a web session cookie).
//!   3. Logged-in web user calls POST /api/auth/link/confirm with the token.
//!      Server links the token to the user account and marks it 'linked'.
//!   4. Desktop polls GET /api/auth/link/poll?token=<tok>.
//!      Once linked, server returns display_name, user_id, provider, and auth_token.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::{extract_session_id, extract_ua_hash};
use crate::db::LinkTokenStatus;
use crate::models::types::ErrorResponse;
use crate::state::AppState;

// ============================================================================
// Request / response types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct InitLinkRequest {
    pub device_name: String,
    pub device_id: String,
}

#[derive(Debug, Serialize)]
pub struct InitLinkResponse {
    pub token: String,
    pub link_url: String,
}

#[derive(Debug, Deserialize)]
pub struct PollLinkQuery {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct ConfirmLinkRequest {
    pub token: String,
}

// ============================================================================
// POST /api/auth/link/init
// ============================================================================

/// Start a link flow.
///
/// Desktop app calls this with its `device_name` and `device_id`. Server stores a
/// pending link token (TTL 10 minutes) and returns it along with the URL the user
/// should open to confirm the link.
pub async fn init_link(
    State(state): State<Arc<AppState>>,
    Json(req): Json<InitLinkRequest>,
) -> Response {
    // Basic input validation.
    let device_name = req.device_name.trim().to_string();
    let device_id = req.device_id.trim().to_string();

    if device_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("device_id must not be empty")),
        )
            .into_response();
    }
    if device_id.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("device_id too long")),
        )
            .into_response();
    }
    if !device_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Invalid device_id format")),
        )
            .into_response();
    }
    if device_name.len() > 128 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("device_name too long")),
        )
            .into_response();
    }

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let _ = crate::db::cleanup_expired_sessions(&conn);
        crate::db::create_link_token(&conn, &device_name, &device_id)
    })
    .await;

    match result {
        Ok(Ok(token)) => {
            let link_url = format!("https://mylittlechart.org/link?token={}", token);
            Json(InitLinkResponse { token, link_url }).into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("DB error creating link token: {}", e);
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

// ============================================================================
// GET /api/auth/link/poll?token=<tok>
// ============================================================================

/// Poll for the status of a link token.
///
/// Returns:
/// - 202 `{ "status": "pending" }` — not yet confirmed.
/// - 410 `{ "status": "expired" }` — token expired or not found.
/// - 200 `{ "status": "linked", "user_id": 123, "display_name": "Alice", "provider": "github", "auth_token": "..." }` — confirmed.
pub async fn poll_link(
    State(state): State<Arc<AppState>>,
    Query(req): Query<PollLinkQuery>,
) -> Response {
    let token = req.token.clone();

    if token.is_empty() || token.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Invalid token")),
        )
            .into_response();
    }

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::poll_link_token(&conn, &token)
    })
    .await;

    match result {
        Ok(Ok(Some(status))) => match status {
            LinkTokenStatus::Pending { device_name, created_at } => (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "status": "pending",
                    "device_name": device_name,
                    "created_at": created_at,
                })),
            )
                .into_response(),
            LinkTokenStatus::Expired => (
                StatusCode::GONE,
                Json(serde_json::json!({ "status": "expired" })),
            )
                .into_response(),
            LinkTokenStatus::Linked {
                user_id,
                display_name,
                provider,
                auth_token,
            } => Json(serde_json::json!({
                "status": "linked",
                "user_id": user_id,
                "display_name": display_name,
                "provider": provider,
                "auth_token": auth_token,
            }))
            .into_response(),
        },
        Ok(Ok(None)) => (
            StatusCode::GONE,
            Json(serde_json::json!({ "status": "expired" })),
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error polling link token: {}", e);
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

// ============================================================================
// POST /api/auth/link/confirm
// ============================================================================

/// Confirm a link token from a logged-in web user.
///
/// Requires a valid `session_id` cookie. Links the token's device to the
/// authenticated user and transitions the token from 'pending' to 'linked'.
pub async fn confirm_link(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ConfirmLinkRequest>,
) -> Response {
    let session_id = match extract_session_id(&headers) {
        Some(s) => s,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new("No session cookie — please log in")),
            )
                .into_response();
        }
    };

    let token = req.token.trim().to_string();
    if token.is_empty() || token.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Invalid token")),
        )
            .into_response();
    }

    let ua_hash = extract_ua_hash(&headers);

    let result =
        tokio::task::spawn_blocking(move || -> rusqlite::Result<ConfirmLinkOutcome> {
            let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());

            // Validate session.
            let user_id = match crate::db::resolve_web_session(&conn, &session_id, &ua_hash)? {
                Some(id) => id,
                None => return Ok(ConfirmLinkOutcome::Unauthorized),
            };

            // Confirm the token. This also creates the device_users entry.
            let updated = crate::db::confirm_link_token(&conn, &token, user_id)?;
            if updated {
                Ok(ConfirmLinkOutcome::Ok)
            } else {
                // Either not found, already confirmed/expired, or a race.
                // Distinguish by polling to give a better error.
                match crate::db::poll_link_token(&conn, &token)? {
                    None => Ok(ConfirmLinkOutcome::NotFound),
                    Some(LinkTokenStatus::Expired) => Ok(ConfirmLinkOutcome::Expired),
                    Some(LinkTokenStatus::Linked { .. }) => Ok(ConfirmLinkOutcome::AlreadyUsed),
                    Some(LinkTokenStatus::Pending { .. }) => {
                        // Should not happen: update returned 0 rows but status is pending.
                        // Treat as a race condition.
                        Ok(ConfirmLinkOutcome::AlreadyUsed)
                    }
                }
            }
        })
        .await;

    match result {
        Ok(Ok(ConfirmLinkOutcome::Ok)) => {
            Json(serde_json::json!({ "status": "ok" })).into_response()
        }
        Ok(Ok(ConfirmLinkOutcome::Unauthorized)) => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Invalid or expired session")),
        )
            .into_response(),
        Ok(Ok(ConfirmLinkOutcome::NotFound)) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new("Link token not found")),
        )
            .into_response(),
        Ok(Ok(ConfirmLinkOutcome::Expired)) => (
            StatusCode::GONE,
            Json(ErrorResponse::new("Link token has expired")),
        )
            .into_response(),
        Ok(Ok(ConfirmLinkOutcome::AlreadyUsed)) => (
            StatusCode::CONFLICT,
            Json(ErrorResponse::new("Link token already used")),
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error confirming link token: {}", e);
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

/// Internal outcome variants for the confirm_link handler.
enum ConfirmLinkOutcome {
    Ok,
    Unauthorized,
    NotFound,
    Expired,
    AlreadyUsed,
}

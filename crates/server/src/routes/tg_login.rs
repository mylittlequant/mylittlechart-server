//! Telegram bot login flow — create token and poll status.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use crate::auth::{extract_session_id, extract_ua_hash};
use crate::state::AppState;

#[derive(serde::Deserialize)]
pub struct CreateTgLoginQuery {
    /// If present, this is a "link provider" flow.
    #[serde(default, deserialize_with = "crate::models::types::deserialize_link_flag")]
    pub link: bool,
}

#[derive(serde::Serialize)]
pub struct CreateTgLoginResponse {
    pub token: String,
    pub bot_url: String,
}

/// POST /api/auth/tg-login
///
/// Creates a new TG login token and returns a `t.me` deep link for the user to open.
pub async fn create_tg_login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<CreateTgLoginQuery>,
) -> Response {
    // Resolve the current session's user_id when this is a link-provider flow.
    let link_user_id: Option<i64> = if query.link {
        let session_id = extract_session_id(&headers);
        if let Some(sid) = session_id {
            let ua_hash = extract_ua_hash(&headers);
            let state_clone = state.clone();
            tokio::task::spawn_blocking(move || {
                let conn = state_clone.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
                crate::db::resolve_web_session(&conn, &sid, &ua_hash)
            })
            .await
            .ok()
            .and_then(|r| r.ok())
            .flatten()
        } else {
            None
        }
    } else {
        None
    };

    let now = chrono::Utc::now().to_rfc3339();
    let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();

    let state_clone = state.clone();
    let result = tokio::task::spawn_blocking(move || {
        let conn = state_clone.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let _ = crate::db::cleanup_tg_login_tokens(&conn);
        crate::db::create_tg_login_token(&conn, link_user_id, &now, &expires_at)
    })
    .await;

    match result {
        Ok(Ok(token)) => {
            let bot_url = format!(
                "https://t.me/mylittlechart_login_bot?start=web_{}",
                token
            );
            (
                StatusCode::OK,
                Json(CreateTgLoginResponse { token, bot_url }),
            )
                .into_response()
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message": "Failed to create login token"})),
        )
            .into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct PollTgLoginQuery {
    pub token: String,
}

/// GET /api/auth/tg-login/poll?token=X
///
/// Polls the status of a TG login token.
///
/// Responses:
/// - `{ "status": "pending" }` — bot hasn't confirmed yet
/// - `{ "status": "expired" }` — token expired or already claimed
/// - `{ "status": "confirmed", "user_id": N, "session_id": "..." }` — success; also sets `session_id` cookie
pub async fn poll_tg_login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<PollTgLoginQuery>,
) -> Response {
    let token = query.token;

    // Validate token format: must be exactly 32 lowercase hex characters.
    if token.len() != 32 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::OK,
            Json(serde_json::json!({"status": "expired"})),
        )
            .into_response();
    }

    let ua_hash = extract_ua_hash(&headers);

    let state_clone = state.clone();
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<serde_json::Value> {
        let conn = state_clone.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let poll_result = crate::db::poll_tg_login_token(&conn, &token)?;

        match poll_result {
            // Token expired or not found.
            None => Ok(serde_json::json!({"status": "expired"})),

            // Still waiting for the bot.
            Some((ref status, _, _, _)) if status == "pending" => {
                Ok(serde_json::json!({"status": "pending"}))
            }

            // Freshly claimed (atomic transition confirmed → claimed) — create session.
            // MUST be checked before the bare "claimed" arm below.
            Some((ref status, Some(ref tg_user_id), Some(ref display_name), link_user_id))
                if status == "claimed" =>
            {
                let tg_user_id = tg_user_id.clone();
                let display_name = display_name.clone();
                let now = chrono::Utc::now().to_rfc3339();
                let session_expires =
                    (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339();

                // Telegram cannot yield an email at all — see
                // docs/mlc/plans/identity-merge-2026-09-09.md decision 1.
                let user_id = if let Some(existing_uid) = link_user_id {
                    // Link-provider flow: attach TG identity to existing account.
                    crate::db::link_provider_to_user(
                        &conn,
                        existing_uid,
                        "telegram",
                        &tg_user_id,
                        &display_name,
                        None,
                        &now,
                    )?;
                    existing_uid
                } else {
                    // Normal login: resolve to an existing account (known
                    // identity) or create a new one.
                    crate::db::resolve_or_create_user(
                        &conn, "telegram", &tg_user_id, &display_name, None, "", &now,
                    )?
                };

                let session_id = crate::db::create_web_session(
                    &conn,
                    user_id,
                    &now,
                    &session_expires,
                    &ua_hash,
                )?;

                let public_id = crate::db::get_user_public_id(&conn, user_id)
                    .unwrap_or_default();

                Ok(serde_json::json!({
                    "status": "confirmed",
                    "user_id": user_id,
                    "public_id": public_id,
                    "session_id": session_id,
                }))
            }

            // Claimed but missing tg_user_id / display_name — shouldn't happen, surface as error.
            _ => Ok(serde_json::json!({"status": "error"})),
        }
    })
    .await;

    match result {
        Ok(Ok(json)) => {
            // If a fresh session_id was issued, set it as an HttpOnly cookie.
            if let Some(session_id) = json.get("session_id").and_then(|v| v.as_str()) {
                let cookie = format!(
                    "session_id={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400",
                    session_id
                );
                (
                    StatusCode::OK,
                    [(header::SET_COOKIE, cookie)],
                    Json(json),
                )
                    .into_response()
            } else {
                (StatusCode::OK, Json(json)).into_response()
            }
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message": "Internal error"})),
        )
            .into_response(),
    }
}

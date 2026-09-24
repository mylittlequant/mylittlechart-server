//! Session management and account self-service routes.
//!
//! All endpoints in this module require **cookie-session authentication only**.
//! Bearer tokens are intentionally rejected — an agent key must not be able to list
//! or revoke its own session, and certainly not to delete the account.
//!
//! Endpoints:
//!  - `GET    /api/auth/sessions`              — list active Bearer tokens for the user.
//!  - `DELETE /api/auth/sessions/:hash_prefix` — revoke one token by hash prefix.
//!  - `GET    /api/auth/account/export`        — GDPR data export (JSON).
//!  - `POST   /api/auth/account/delete`        — permanently delete the account.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use crate::auth::{extract_session_id, extract_ua_hash};
use crate::db::DeleteKeyOutcome;
use crate::models::types::ErrorResponse;
use crate::state::AppState;
use mylittlechart_server::matrix_keys_store::CredentialKind;

// ============================================================================
// Cookie-only auth helper (intentionally stricter than sync's resolve_user_id)
// ============================================================================

/// Resolve `user_id` from a web session cookie **only**.
///
/// Bearer tokens are rejected so that agent keys cannot reach these endpoints.
async fn require_web_session(
    state: Arc<AppState>,
    headers: &HeaderMap,
) -> Result<i64, StatusCode> {
    let session_id = match extract_session_id(headers) {
        Some(s) => s,
        None => return Err(StatusCode::UNAUTHORIZED),
    };
    let ua_hash = extract_ua_hash(headers);

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::resolve_web_session(&conn, &session_id, &ua_hash)
    })
    .await;

    match result {
        Ok(Ok(Some(uid))) => Ok(uid),
        Ok(Ok(None)) => Err(StatusCode::UNAUTHORIZED),
        Ok(Err(_)) | Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

// ============================================================================
// GET /api/auth/sessions
// ============================================================================

/// List all active Bearer tokens (sessions / device links) for the logged-in user.
///
/// Response:
/// ```json
/// { "sessions": [
///     { "hash_prefix": "abcd1234...", "label": "Desktop App",
///       "initiated_by": "user", "created_at": "...", "expires_at": "...",
///       "last_used_at": "...", "last_ip": "..." }
/// ] }
/// ```
pub async fn list_sessions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let user_id = match require_web_session(state.clone(), &headers).await {
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

    let result = tokio::task::spawn_blocking(move || {
        let cp = state.control_plane();
        let conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
        // Device metadata enrichment reads from the operational database —
        // `devices` moved there in the 2026-08-30 store split.
        let ops_conn = cp.ops_db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::list_sessions_for_user(&conn, &ops_conn, user_id)
    })
    .await;

    match result {
        Ok(Ok(sessions)) => {
            let json_sessions: Vec<serde_json::Value> = sessions
                .into_iter()
                .map(|s| {
                    serde_json::json!({
                        "hash_prefix": s.hash_prefix,
                        "label": s.label,
                        "initiated_by": s.initiated_by,
                        "created_at": s.created_at,
                        "expires_at": s.expires_at,
                        "last_used_at": s.last_used_at,
                        "last_ip": s.last_ip,
                        "device_name": s.device_name,
                        "device_os": s.device_os,
                        "device_app_version": s.device_app_version,
                    })
                })
                .collect();
            Json(serde_json::json!({ "sessions": json_sessions })).into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("DB error listing sessions: {}", e);
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
// DELETE /api/auth/sessions/:hash_prefix
// ============================================================================

/// Revoke (delete) one active token by its hash prefix.
///
/// Requires cookie-session auth. The hash prefix must be at least 8 characters.
///
/// Response: `{ "revoked": true }` on success, `404` if not found.
pub async fn revoke_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(hash_prefix): Path<String>,
) -> Response {
    let user_id = match require_web_session(state.clone(), &headers).await {
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

    if hash_prefix.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("hash_prefix must be at least 8 characters")),
        )
            .into_response();
    }

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<DeleteKeyOutcome> {
        let cp = state.control_plane();
        // Fetch the full hash before deleting — `revoke_key` only knows the
        // LIKE prefix, but `matrix_keys_store.devices.credential_ref` is
        // keyed on the full `token_hash` (plan §1.1), so this is the only
        // chance to learn which Matrix device this credential minted.
        let full_token_hash = {
            let conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
            crate::db::token_hash_for_prefix(&conn, user_id, &hash_prefix)?
        };
        let outcome = {
            let conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
            crate::db::revoke_key(&conn, user_id, &hash_prefix)?
        };
        // Strip the Matrix device this credential minted, if the revoke
        // actually matched a unique row (plan §1.1's revoke hook) — a
        // revoked native-app bearer token must not leave a live device
        // peers keep encrypting room keys to.
        if outcome == DeleteKeyOutcome::Ok {
            if let Some(token_hash) = full_token_hash {
                let now = chrono::Utc::now().to_rfc3339();
                let mut messenger = cp.messenger_conn();
                if let Err(e) = crate::routes::matrix::auth::on_credential_revoked(&mut messenger, &cp.live, CredentialKind::Bearer, &token_hash, &now) {
                    tracing::error!("Failed to revoke the Matrix device for a revoked session: {}", e);
                }
            }
        }
        Ok(outcome)
    })
    .await;

    match result {
        Ok(Ok(DeleteKeyOutcome::Ok)) => {
            Json(serde_json::json!({ "revoked": true })).into_response()
        }
        Ok(Ok(DeleteKeyOutcome::NotFound)) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new("Session not found")),
        )
            .into_response(),
        Ok(Ok(DeleteKeyOutcome::AmbiguousPrefix)) => (
            StatusCode::CONFLICT,
            Json(ErrorResponse::new("Ambiguous prefix — provide more characters")),
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error revoking session: {}", e);
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
// GET /api/auth/account/export
// ============================================================================

/// Export all data the server holds for the authenticated user as a JSON file.
///
/// Returns a `Content-Disposition: attachment` response so browsers download it.
///
/// Note: sync item **content** is excluded from the export — only metadata is
/// included. The content bytes may contain E2E-encrypted data that would be
/// meaningless without the user's passphrase.
pub async fn export_account(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let user_id = match require_web_session(state.clone(), &headers).await {
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

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::export_account_data(&conn, user_id)
    })
    .await;

    match result {
        Ok(Ok((user_json, sync_items, tokens))) => {
            let export = serde_json::json!({
                "exported_at": chrono::Utc::now().to_rfc3339(),
                "user": user_json,
                "sync_items": sync_items,
                "auth_tokens": tokens,
            });
            let body = match serde_json::to_vec_pretty(&export) {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!("Failed to serialise account export: {}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse::new("Serialisation error")),
                    )
                        .into_response();
                }
            };
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/json"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"mylittlechart-export.json\"",
                    ),
                ],
                body,
            )
                .into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("DB error exporting account: {}", e);
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
// POST /api/auth/account/delete
// ============================================================================

/// Permanently delete the authenticated user's account.
///
/// Removes all user data: telemetry, sync items (both the SQL cold plane and
/// the hot file plane — see `syncstore::purge_user`), E2E params, auth
/// tokens, device links, provider links, web sessions, and the user row
/// itself.
///
/// Requires the `X-Confirm-Delete: yes` header **and** a JSON body with
/// `{ "confirm": "DELETE" }` to prevent accidental calls.
///
/// On success: clears the session cookie and returns `{ "deleted": true }`.
#[derive(serde::Deserialize)]
pub struct DeleteAccountRequest {
    pub confirm: String,
}

pub async fn delete_account(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<DeleteAccountRequest>,
) -> Response {
    let user_id = match require_web_session(state.clone(), &headers).await {
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

    // Double-confirmation: header guard.
    let confirm_header = headers
        .get("X-Confirm-Delete")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if confirm_header != "yes" {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("X-Confirm-Delete: yes header required")),
        )
            .into_response();
    }

    // Double-confirmation: body guard.
    if body.confirm != "DELETE" {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Body must contain { \"confirm\": \"DELETE\" }")),
        )
            .into_response();
    }

    let result = tokio::task::spawn_blocking(move || {
        let cp = state.control_plane();

        // Strip every Matrix device this account's credentials ever minted
        // BEFORE the identity-side delete below removes the
        // `auth_tokens`/`web_sessions` rows (plan §1.1) — once those rows are
        // gone, there is nothing left here to enumerate.
        let now = chrono::Utc::now().to_rfc3339();
        let (bearer_hashes, web_session_ids) = {
            let conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
            (crate::db::all_token_hashes_for_user(&conn, user_id), crate::db::all_web_session_ids_for_user(&conn, user_id))
        };
        {
            let mut messenger = cp.messenger_conn();
            match bearer_hashes {
                Ok(hashes) => {
                    for token_hash in hashes {
                        if let Err(e) = crate::routes::matrix::auth::on_credential_revoked(&mut messenger, &cp.live, CredentialKind::Bearer, &token_hash, &now) {
                            tracing::error!("Failed to revoke a Matrix device before account delete: {}", e);
                        }
                    }
                }
                Err(e) => tracing::error!("Failed to list bearer credentials before account delete: {}", e),
            }
            match web_session_ids {
                Ok(ids) => {
                    for session_id in ids {
                        // messenger.db never holds a raw session id at rest
                        // (manager review, 2026-09-24) — hash it the same
                        // way `on_credential_revoked`'s own device row does.
                        let credential_ref = crate::routes::matrix::auth::web_credential_ref(&session_id);
                        if let Err(e) = crate::routes::matrix::auth::on_credential_revoked(&mut messenger, &cp.live, CredentialKind::Web, &credential_ref, &now) {
                            tracing::error!("Failed to revoke a Matrix device before account delete: {}", e);
                        }
                    }
                }
                Err(e) => tracing::error!("Failed to list web-session credentials before account delete: {}", e),
            }
        }

        let outcome = {
            let conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
            crate::db::delete_account(&conn, user_id)
        };
        // The account row lives in identity; its telemetry lives in the
        // operational database (2026-08-30 store split), its hot-plane sync
        // files live on disk (SQLCipher never sees them — see
        // syncstore.rs), and its screenshot-share blobs live under
        // share_root (SQLCipher never sees those either — see
        // routes/share.rs). All four are separate statements/filesystem
        // calls against separate stores, deliberately visible here rather
        // than hidden inside one cascade function. Only run them when the
        // account row actually deleted; log-and-continue rather than fail
        // the whole request if a side store is already clean (idempotent by
        // design — a retried delete, or a user who never wrote
        // telemetry/hot items/shares).
        if let Ok((n, blob_paths)) = &outcome {
            if *n > 0 {
                let ops_conn = cp.ops_db.lock().unwrap_or_else(|e| e.into_inner());
                if let Err(e) = crate::db::delete_account_telemetry(&ops_conn, user_id) {
                    tracing::error!("Failed to delete operational telemetry for user {}: {}", user_id, e);
                }
                drop(ops_conn);
                if let Err(e) = crate::syncstore::purge_user(&cp.sync_store, user_id) {
                    tracing::error!("Failed to purge sync files for user {}: {}", user_id, e);
                }
                // Screenshot blobs: same relative-path guard as the static
                // handler and the periodic reaper (main.rs) — never trust a
                // stored path to stay inside share_root without re-checking it.
                for rel in blob_paths {
                    if !crate::pathutil::is_safe_relative_path(rel) {
                        continue;
                    }
                    if let Err(e) = std::fs::remove_file(cp.share_root.join(rel)) {
                        tracing::warn!("could not unlink share blob {}: {}", rel, e);
                    }
                }
            }
        }
        outcome.map(|(n, _)| n)
    })
    .await;

    match result {
        Ok(Ok(n)) if n > 0 => {
            // Clear the session cookie.
            let clear_cookie =
                "session_id=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0";
            (
                StatusCode::OK,
                [(header::SET_COOKIE, clear_cookie)],
                Json(serde_json::json!({ "deleted": true })),
            )
                .into_response()
        }
        Ok(Ok(_)) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new("User not found")),
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error deleting account: {}", e);
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

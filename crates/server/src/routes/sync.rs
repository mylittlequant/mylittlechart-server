//! Cloud sync route handlers.
//!
//! All endpoints require authentication via either a `session_id` cookie (web dashboard)
//! or a `Authorization: Bearer <token>` header (terminal app).
//!
//! Endpoints:
//!  - `GET  /api/sync/status`          — check whether the user has any cloud data.
//!  - `GET  /api/sync/changes?since=T` — get metadata for items changed after timestamp T.
//!  - `POST /api/sync/push`            — upload changed items (max 50 per request).
//!  - `GET  /api/sync/pull`            — download all items (initial / full sync).
//!  - `DELETE /api/sync/item/:sync_id` — soft-delete one item.
//!  - `DELETE /api/sync/all`           — hard-delete all cloud data for the user.
//!  - `GET  /api/sync/e2e-params`      — retrieve E2E encryption parameters.
//!  - `POST /api/sync/e2e-setup`       — initialise E2E encryption.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use crate::auth::{extract_bearer, extract_session_id, extract_ua_hash, hash_token};
use crate::build_attest;
use crate::models::types::ErrorResponse;
use crate::state::AppState;

// ============================================================================
// Profile-id helper
// ============================================================================

/// Extract the `X-Profile-Id` header value.
///
/// Returns the profile-id string if the header is present and valid UTF-8,
/// or an empty string for backward compatibility with old clients that do not
/// send the header.  Old clients' data lands in the `profile_id = ""` namespace
/// and continues to work without modification.
fn extract_profile_id_or_default(headers: &HeaderMap) -> String {
    headers
        .get("X-Profile-Id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// Extract the `X-Device-Id` header value.
///
/// Returns the device-id string if the header is present and valid UTF-8,
/// or an empty string for backward compatibility with old clients that do not
/// send the header.  Old clients' data lands in the `device_id = ""` namespace
/// and continues to work without modification.
fn extract_device_id_or_default(headers: &HeaderMap) -> String {
    headers
        .get("X-Device-Id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

// ============================================================================
// Auth helper
// ============================================================================

/// Resolve the authenticated `user_id` from either a cookie session or a Bearer token.
///
/// Checks the `session_id` cookie first; falls back to `Authorization: Bearer`.
/// Returns `Ok(user_id)` on success or `Err(StatusCode::UNAUTHORIZED)` if neither
/// credential is present or valid.
async fn resolve_user_id(
    state: Arc<AppState>,
    headers: &HeaderMap,
) -> Result<i64, StatusCode> {
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

// ============================================================================
// Multi-profile entitlement gate
// ============================================================================

/// Enforce the multi-profile entitlement rule for a write that carries
/// `profile_id`, i.e. `sync_push` and `sync_setup_e2e` — the two writes that
/// can introduce a new profile (see `entitlements::profile_write_allowed`
/// for the exact rule: a `profile_id` the server has never seen before for
/// this user is a profile creation and is gated by the free limit /
/// `Feature::MultiProfile`; an already-known `profile_id` always passes).
///
/// Returns `Ok(())` when the write may proceed, or the `Response` to return
/// verbatim when it may not (403 for the entitlement refusal, 500 on a DB
/// failure while checking it).
async fn check_profile_entitlement(
    state: Arc<AppState>,
    user_id: i64,
    profile_id: String,
) -> Result<(), Response> {
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let known = crate::syncstore::known_profile_ids(&conn, &state.control_plane().sync_store, user_id)?;
        let features = crate::entitlements::resolve_for_user(Some(user_id));
        Ok(crate::entitlements::profile_write_allowed(&known, &profile_id, &features))
    })
    .await;

    match result {
        Ok(Ok(true)) => Ok(()),
        Ok(Ok(false)) => Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse::new(
                "profile limit reached: this account may hold 1 profile without the multi-profile entitlement",
            )),
        )
            .into_response()),
        Ok(Err(e)) => {
            tracing::error!("DB error checking profile entitlement: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response())
        }
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response()),
    }
}

// ============================================================================
// GET /api/sync/status
// ============================================================================

/// Check whether the authenticated user has any data in cloud sync.
///
/// Returns:
/// ```json
/// { "has_cloud_data": true, "item_count": 5, "last_modified": 1712345678901 }
/// ```
/// `last_modified` is `null` when the user has no items at all.
pub async fn sync_status_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = build_attest::check_build_attestation(
        &headers,
        &state.build_attest_pubkeys,
        state.build_attest_enforce,
        state.build_attest_max_age_secs,
    ) {
        return resp;
    }

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

    let device_id = extract_device_id_or_default(&headers);
    let profile_id = extract_profile_id_or_default(&headers);

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::syncstore::status(&conn, &state.control_plane().sync_store, user_id, &device_id, &profile_id)
    })
    .await;

    match result {
        Ok(Ok((item_count, last_modified, quota_used_bytes))) => Json(serde_json::json!({
            "has_cloud_data": item_count > 0,
            "item_count": item_count,
            "last_modified": last_modified,
            "quota_used_bytes": quota_used_bytes,
            // Read from the module that enforces it. This file used to
            // carry its own copy of the number, which is how a limit gets
            // changed in one place and reported from another.
            "quota_limit_bytes": crate::db::SYNC_MAX_TOTAL_BYTES,
        }))
        .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error in sync_status: {}", e);
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
// GET /api/sync/changes?since=T
// ============================================================================

/// Query parameters for the changes endpoint.
#[derive(serde::Deserialize)]
pub struct ChangesQuery {
    pub since: i64,
}

/// Return metadata for all items that changed after the given millisecond timestamp.
///
/// Response:
/// ```json
/// { "items": [{ "sync_id": "...", "category": "preset", "name": "...",
///               "checksum": "...", "modified_at": 123, "deleted": false }] }
/// ```
pub async fn sync_changes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<ChangesQuery>,
) -> Response {
    if let Err(resp) = build_attest::check_build_attestation(
        &headers,
        &state.build_attest_pubkeys,
        state.build_attest_enforce,
        state.build_attest_max_age_secs,
    ) {
        return resp;
    }

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

    let since = q.since;
    let device_id = extract_device_id_or_default(&headers);
    let profile_id = extract_profile_id_or_default(&headers);

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::syncstore::changes(&conn, &state.control_plane().sync_store, user_id, &device_id, &profile_id, since)
    })
    .await;

    match result {
        Ok(Ok(items)) => {
            let server_timestamp = chrono::Utc::now().timestamp_millis();
            let json_items: Vec<serde_json::Value> = items
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "sync_id": m.sync_id,
                        "category": m.category,
                        "name": m.name,
                        "checksum": m.checksum,
                        "modified_at": m.modified_at,
                        "deleted": m.deleted,
                    })
                })
                .collect();
            Json(serde_json::json!({
                "items": json_items,
                "server_timestamp": server_timestamp,
            })).into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("DB error in sync_changes: {}", e);
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
// POST /api/sync/push
// ============================================================================

/// A single item in a push request body.
///
/// `content` is an opaque blob from the client (base64-encoded ciphertext or any
/// client-determined format). The server stores it verbatim without inspection.
/// `checksum` must be `SHA-256(content.as_bytes())` encoded as 64 lowercase hex
/// characters.  The server verifies this before writing to the database so that
/// bit-flip corruptions and content/checksum mismatches are rejected early.
#[derive(serde::Deserialize)]
pub struct PushItem {
    pub sync_id: String,
    pub category: String,
    pub name: String,
    /// Opaque content string. Stored as raw bytes in the database.
    pub content: String,
    /// Client-provided checksum (64 lowercase hex chars). Stored as-is for change detection.
    pub checksum: String,
    pub modified_at: i64,
    #[serde(default)]
    pub deleted: bool,
}

/// Request body for the push endpoint.
#[derive(serde::Deserialize)]
pub struct PushRequest {
    pub items: Vec<PushItem>,
}

/// Upload a batch of changed items to cloud sync.
///
/// Validates:
/// 1. At most 50 items per request.
/// 2. Each item's `checksum` matches `SHA-256(content)`.
///
/// Uses last-writer-wins semantics: an existing item is only overwritten when the
/// incoming `modified_at` is strictly greater than the stored value.
///
/// Response: `{ "accepted": N, "rejected": [] }` where N is the number of items actually written.
pub async fn sync_push(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<PushRequest>,
) -> Response {
    if let Err(resp) = build_attest::check_build_attestation(
        &headers,
        &state.build_attest_pubkeys,
        state.build_attest_enforce,
        state.build_attest_max_age_secs,
    ) {
        return resp;
    }

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

    // Sanity check: max 50 items per push.
    if body.items.len() > 50 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Too many items in one push request (max 50)")),
        )
            .into_response();
    }

    // Validate each item's fields before touching the DB.
    for item in &body.items {
        // sync_id format: alphanumeric + hyphens/underscores, max 64 chars.
        if item.sync_id.len() > 64
            || !item.sync_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("Invalid sync_id format")),
            )
                .into_response();
        }

        // checksum format: exactly 64 lowercase hex chars (SHA-256).
        if item.checksum.len() != 64
            || !item.checksum.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("Invalid checksum format")),
            )
                .into_response();
        }

        // modified_at must be a positive timestamp.
        if item.modified_at <= 0 {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("Invalid modified_at timestamp")),
            )
                .into_response();
        }

        // Verify checksum == SHA-256(content) for non-deleted items.
        //
        // Deleted tombstone items have empty content ("") by convention; their
        // checksum is the SHA-256 of the empty string, so the same check applies
        // uniformly.  This guards against bit-flip corruption and client bugs
        // where checksum and content drift apart in transit.
        if !item.deleted || !item.content.is_empty() {
            use sha2::{Digest, Sha256};
            let computed = hex::encode(Sha256::digest(item.content.as_bytes()));
            if computed != item.checksum {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse::new("checksum mismatch: provided checksum does not match SHA-256 of content")),
                )
                    .into_response();
            }
        }

    }

    let device_id = extract_device_id_or_default(&headers);
    let profile_id = extract_profile_id_or_default(&headers);

    // Reject push with empty profile_id — this is always a client bug
    // (e.g. profile.json failed to parse, fell back to defaults).
    if profile_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("profile_id is required (X-Profile-Id header)")),
        )
            .into_response();
    }

    // Multi-profile entitlement gate — see check_profile_entitlement.
    if let Err(resp) = check_profile_entitlement(state.clone(), user_id, profile_id.clone()).await {
        return resp;
    }

    // Convert to db types — content is passed through verbatim as bytes.
    let db_items: Vec<crate::db::SyncPushItem> = body.items.into_iter().map(|item| {
        crate::db::SyncPushItem {
            sync_id: item.sync_id,
            category: item.category,
            name: item.name,
            content: item.content.into_bytes(),
            checksum: item.checksum,
            modified_at: item.modified_at,
            deleted: item.deleted,
        }
    }).collect();

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::syncstore::push(&conn, &state.control_plane().sync_store, user_id, &device_id, &profile_id, &db_items)
    })
    .await;

    match result {
        Ok(Ok(push_result)) => {
            if !push_result.rejected.is_empty() {
                tracing::warn!("sync_push: {} rejected: {:?}", push_result.rejected.len(), push_result.rejected);
            }
            Json(serde_json::json!({
                "accepted": push_result.accepted,
                "rejected": push_result.rejected,
            })).into_response()
        }
        Ok(Err(e)) => {
            let msg = e.to_string();
            if msg.contains("reached the sync item limit") || msg.contains("reached the sync storage limit") {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(ErrorResponse::new(&msg)),
                )
                    .into_response();
            }
            tracing::error!("DB error in sync_push: {}", e);
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
// GET /api/sync/pull
// ============================================================================

/// Download all non-deleted sync items for the user (initial / full sync).
///
/// Content bytes are returned verbatim as the original string sent by the client.
/// The server stores and retrieves content as an opaque blob.
///
/// Response:
/// ```json
/// { "items": [{ "sync_id": "...", "category": "preset", "name": "...",
///               "content": "...", "checksum": "...", "modified_at": 123 }] }
/// ```
pub async fn sync_pull(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = build_attest::check_build_attestation(
        &headers,
        &state.build_attest_pubkeys,
        state.build_attest_enforce,
        state.build_attest_max_age_secs,
    ) {
        return resp;
    }

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

    let device_id = extract_device_id_or_default(&headers);
    let profile_id = extract_profile_id_or_default(&headers);

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::syncstore::pull_all(&conn, &state.control_plane().sync_store, user_id, &device_id, &profile_id)
    })
    .await;

    match result {
        Ok(Ok(items)) => {
            let json_items: Vec<serde_json::Value> = items
                .into_iter()
                .map(|item| {
                    // Content bytes are passed through as-is — they were stored verbatim
                    // from the client's original string (valid UTF-8 by construction).
                    let content = String::from_utf8_lossy(&item.content).into_owned();
                    serde_json::json!({
                        "sync_id": item.sync_id,
                        "category": item.category,
                        "name": item.name,
                        "content": content,
                        "checksum": item.checksum,
                        "modified_at": item.modified_at,
                    })
                })
                .collect();
            Json(serde_json::json!({ "items": json_items })).into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("DB error in sync_pull: {}", e);
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
// DELETE /api/sync/item/:sync_id
// ============================================================================

/// Soft-delete one sync item by its `sync_id`.
///
/// Clears the content bytes (reclaims quota) and marks the row as a tombstone so
/// other devices can see the deletion on their next `changes` poll.
///
/// Returns `404` if the item does not exist for this user (or was already deleted).
pub async fn sync_delete_item_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(sync_id): Path<String>,
) -> Response {
    if let Err(resp) = build_attest::check_build_attestation(
        &headers,
        &state.build_attest_pubkeys,
        state.build_attest_enforce,
        state.build_attest_max_age_secs,
    ) {
        return resp;
    }

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

    let now_ms = chrono::Utc::now().timestamp_millis();
    let device_id = extract_device_id_or_default(&headers);
    let profile_id = extract_profile_id_or_default(&headers);

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::syncstore::delete_item(&conn, &state.control_plane().sync_store, user_id, &device_id, &profile_id, &sync_id, now_ms)
    })
    .await;

    match result {
        Ok(Ok(true)) => Json(serde_json::json!({ "deleted": true })).into_response(),
        Ok(Ok(false)) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new("Sync item not found")),
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error in sync_delete_item: {}", e);
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
// DELETE /api/sync/all
// ============================================================================

/// Hard-delete all cloud sync data for the authenticated user.
///
/// This is the "Delete Cloud Data" action. All rows are permanently removed
/// (not just tombstoned). Other devices will see an empty pull on their next sync.
///
/// Response: `{ "deleted": N }` where N is the number of rows removed.
pub async fn sync_delete_all_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = build_attest::check_build_attestation(
        &headers,
        &state.build_attest_pubkeys,
        state.build_attest_enforce,
        state.build_attest_max_age_secs,
    ) {
        return resp;
    }

    // Require explicit confirmation header to prevent accidental data loss.
    let confirm = headers
        .get("X-Confirm-Delete")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if confirm != "yes" {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "X-Confirm-Delete: yes header required" })),
        )
            .into_response();
    }

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

    let device_id = extract_device_id_or_default(&headers);
    let profile_id = extract_profile_id_or_default(&headers);

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::syncstore::delete_all(&conn, &state.control_plane().sync_store, user_id, &device_id, &profile_id)
    })
    .await;

    match result {
        Ok(Ok(n)) => Json(serde_json::json!({ "deleted": n })).into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error in sync_delete_all: {}", e);
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
// GET /api/sync/e2e-params
// ============================================================================

/// Retrieve the E2E encryption key-derivation parameters for this user.
///
/// Returns `{ "enabled": true, "salt": "...", "iterations": 600000 }` when set up,
/// or `{ "enabled": false }` when not yet configured.
pub async fn sync_get_e2e(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = build_attest::check_build_attestation(
        &headers,
        &state.build_attest_pubkeys,
        state.build_attest_enforce,
        state.build_attest_max_age_secs,
    ) {
        return resp;
    }

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

    let profile_id = extract_profile_id_or_default(&headers);

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::sync_get_e2e_params(&conn, user_id, &profile_id)
    })
    .await;

    match result {
        Ok(Ok(Some((salt, iterations, encrypted_master_key)))) => Json(serde_json::json!({
            "enabled": true,
            "salt": salt,
            "iterations": iterations,
            "encrypted_master_key": encrypted_master_key,
        }))
        .into_response(),
        Ok(Ok(None)) => Json(serde_json::json!({ "enabled": false })).into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error in sync_get_e2e: {}", e);
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
// POST /api/sync/e2e-setup
// ============================================================================

/// Request body for the E2E setup endpoint.
#[derive(serde::Deserialize)]
pub struct E2ESetupRequest {
    /// Hex-encoded random salt (must be exactly 32 hex chars = 16 bytes).
    pub salt: String,
    /// PBKDF2 iteration count. Must be >= 100 000.
    pub iterations: i32,
    /// Optional base64-encoded AES-256-GCM blob: the user's master key
    /// encrypted with their recovery key.  The server stores this opaquely
    /// for account recovery.  Never inspected or decrypted server-side.
    pub encrypted_master_key: Option<String>,
}

/// Initialise (or replace) E2E encryption parameters for the user.
///
/// Validates:
/// - `iterations` >= 100 000.
/// - `salt` is valid lowercase hex.
/// - `salt` is exactly 32 hex characters (16 bytes).
///
/// Response: `{ "enabled": true }`.
pub async fn sync_setup_e2e(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<E2ESetupRequest>,
) -> Response {
    if let Err(resp) = build_attest::check_build_attestation(
        &headers,
        &state.build_attest_pubkeys,
        state.build_attest_enforce,
        state.build_attest_max_age_secs,
    ) {
        return resp;
    }

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

    // Validate iterations floor.
    if body.iterations < 100_000 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("iterations must be at least 100000")),
        )
            .into_response();
    }

    // Validate salt is valid hex.
    if hex::decode(&body.salt).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("salt must be valid hex")),
        )
            .into_response();
    }

    // Validate salt is exactly 32 hex chars (16 bytes).
    if body.salt.len() != 32 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("salt must be exactly 32 hex characters (16 bytes)")),
        )
            .into_response();
    }

    let profile_id = extract_profile_id_or_default(&headers);

    // Multi-profile entitlement gate — see check_profile_entitlement.
    // e2e-setup can be the FIRST write for a brand-new profile_id (a client
    // may set up encryption before ever pushing an item), so it must be
    // enforced here too, not just in sync_push.
    if let Err(resp) = check_profile_entitlement(state.clone(), user_id, profile_id.clone()).await {
        return resp;
    }

    let now = chrono::Utc::now().to_rfc3339();
    let salt = body.salt.clone();
    let iterations = body.iterations;
    let encrypted_master_key = body.encrypted_master_key.clone();

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::sync_set_e2e_params(
            &conn,
            user_id,
            &profile_id,
            &salt,
            iterations,
            encrypted_master_key.as_deref(),
            &now,
        )
    })
    .await;

    match result {
        Ok(Ok(())) => Json(serde_json::json!({ "enabled": true })).into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error in sync_setup_e2e: {}", e);
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
// GET /api/sync/profiles
// ============================================================================

/// List all profiles that have sync data for the authenticated user.
///
/// Aggregates across all devices — returns one entry per distinct `profile_id`
/// regardless of which device originally pushed the data.
///
/// Response:
/// ```json
/// { "profiles": [{ "profile_id": "...", "item_count": 13, "total_bytes": 532423,
///                  "last_modified": 1773673403546, "has_vault": true, "has_recovery_key": true }] }
/// ```
pub async fn sync_list_profiles(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = build_attest::check_build_attestation(
        &headers,
        &state.build_attest_pubkeys,
        state.build_attest_enforce,
        state.build_attest_max_age_secs,
    ) {
        return resp;
    }

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

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::syncstore::list_profiles(&conn, &state.control_plane().sync_store, user_id)
    })
    .await;

    match result {
        Ok(Ok(profiles)) => {
            let json_profiles: Vec<serde_json::Value> = profiles
                .into_iter()
                .map(|p| {
                    serde_json::json!({
                        "profile_id": p.profile_id,
                        "display_name": p.display_name,
                        "item_count": p.item_count,
                        "total_bytes": p.total_bytes,
                        "last_modified": p.last_modified,
                        "has_vault": p.has_vault,
                        "has_recovery_key": p.has_recovery_key,
                    })
                })
                .collect();
            Json(serde_json::json!({ "profiles": json_profiles })).into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("DB error in sync_list_profiles: {}", e);
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
// GET /api/sync/pull-profile
// ============================================================================

/// Query parameters for the pull-profile endpoint.
#[derive(serde::Deserialize)]
pub struct PullProfileQuery {
    pub profile_id: Option<String>,
}

/// Download all non-deleted sync items for a specific profile, across all devices.
///
/// The `profile_id` can be supplied either as a `?profile_id=` query parameter or
/// via the `X-Profile-Id` request header.  The query parameter takes precedence.
/// When both are absent the empty profile (`""`) is used for backward compatibility.
///
/// For items that exist under multiple device rows the version with the latest
/// `modified_at` is selected (last-writer-wins across devices).
///
/// Response: same format as `GET /api/sync/pull`.
pub async fn sync_pull_profile(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PullProfileQuery>,
) -> Response {
    if let Err(resp) = build_attest::check_build_attestation(
        &headers,
        &state.build_attest_pubkeys,
        state.build_attest_enforce,
        state.build_attest_max_age_secs,
    ) {
        return resp;
    }

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

    // Query param takes precedence over header for cross-device restore scenarios.
    let profile_id = q
        .profile_id
        .unwrap_or_else(|| extract_profile_id_or_default(&headers));

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::syncstore::pull_by_profile(&conn, &state.control_plane().sync_store, user_id, &profile_id)
    })
    .await;

    match result {
        Ok(Ok(items)) => {
            let json_items: Vec<serde_json::Value> = items
                .into_iter()
                .map(|item| {
                    // Content bytes are passed through as-is — stored verbatim from the client.
                    let content = String::from_utf8_lossy(&item.content).into_owned();
                    serde_json::json!({
                        "sync_id": item.sync_id,
                        "category": item.category,
                        "name": item.name,
                        "content": content,
                        "checksum": item.checksum,
                        "modified_at": item.modified_at,
                    })
                })
                .collect();
            Json(serde_json::json!({ "items": json_items })).into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("DB error in sync_pull_profile: {}", e);
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

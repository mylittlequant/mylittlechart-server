//! Owner-curated grant groups (docs/mlc/plans/share-policy-2026-09-25.md
//! §1/§8.3): a reusable, named list of accounts a chart-share owner can
//! grant a `db::ShareTier` to as one unit
//! (`routes::share::create_share_grant`'s `grantee_group_id`) instead of one
//! grant row per account. v1 is manual membership only — no automatic sync
//! from any entitlement/paid flag (see `entitlements.rs`'s own note on this).
//!
//! Endpoints (all owner-only, auth required — every route resolves the
//! caller then checks group ownership; a group that exists but belongs to
//! someone else answers the same 404 an unknown id does, so group existence
//! is never leaked, matching `routes::share`'s own discipline):
//!  - `POST   /api/groups`                        — create.
//!  - `GET    /api/groups`                        — the caller's own groups + member counts.
//!  - `PATCH  /api/groups/{id}`                    — rename.
//!  - `DELETE /api/groups/{id}`                    — delete (cascades membership).
//!  - `POST   /api/groups/{id}/members`            — add a member by nick.
//!  - `DELETE /api/groups/{id}/members/{user_id}`  — remove a member.

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use crate::auth::{extract_bearer, extract_session_id, extract_ua_hash, hash_token};
use crate::entitlements;
use crate::models::types::ErrorResponse;
use crate::state::AppState;
use crate::text_policy::clean_user_text;

/// Cap on a group's `name` — same figure as `routes::share`'s share-title
/// cap is overkill for a short label; a group name is UI chrome (a picker
/// row, a settings-panel list), not free-form prose.
const MAX_GROUP_NAME_CHARS: usize = 80;

fn internal_error() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Internal error"))).into_response()
}

fn bad_request(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(ErrorResponse::new(msg))).into_response()
}

/// Bare 404 — an unknown group id and "exists but belongs to someone else"
/// both answer identically (same privacy posture as `routes::share`'s
/// `share_not_found`/`routes::rooms`'s `room_not_found`).
fn group_not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

fn auth_err(status: StatusCode) -> Response {
    match status {
        StatusCode::UNAUTHORIZED => {
            (StatusCode::UNAUTHORIZED, Json(ErrorResponse::new("Authentication required"))).into_response()
        }
        _ => internal_error(),
    }
}

// ============================================================================
// Auth — mirrors routes::share/routes::rooms's resolve_user_id (duplicated
// rather than shared, following this codebase's one-copy-per-route-module
// convention).
// ============================================================================

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

// ============================================================================
// POST /api/groups
// ============================================================================

#[derive(serde::Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
}

enum CreateGroupOutcome {
    Created { group_id: i64 },
    QuotaExceeded,
}

/// POST /api/groups
///
/// Creates a new named group owned by the caller. Quota-checked against
/// [`entitlements::group_create_allowed`] (how many groups the caller
/// already owns) — a group is free to create (no paid requirement, see
/// `entitlements.rs`'s own note), just bounded in count.
pub async fn create_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateGroupRequest>,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };
    let name = match clean_user_text(&body.name, MAX_GROUP_NAME_CHARS) {
        Ok(n) => n,
        Err(e) => return e.into_response(),
    };

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<CreateGroupOutcome> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let current = crate::db::count_grant_groups(&conn, user_id)?;
        if !entitlements::group_create_allowed(current) {
            return Ok(CreateGroupOutcome::QuotaExceeded);
        }
        let now = chrono::Utc::now().to_rfc3339();
        let group_id = crate::db::create_grant_group(&conn, user_id, &name, &now)?;
        Ok(CreateGroupOutcome::Created { group_id })
    })
    .await;

    match result {
        Ok(Ok(CreateGroupOutcome::Created { group_id })) => {
            Json(serde_json::json!({ "group_id": group_id })).into_response()
        }
        Ok(Ok(CreateGroupOutcome::QuotaExceeded)) => (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse::new("group limit reached for this account")),
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error creating grant group: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// GET /api/groups
// ============================================================================

/// GET /api/groups
///
/// The caller's own groups, newest first, each with its live member count.
pub async fn list_my_groups(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Vec<serde_json::Value>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let groups = crate::db::list_grant_groups(&conn, user_id)?;
        Ok(groups
            .into_iter()
            .map(|g| {
                serde_json::json!({
                    "id": g.id,
                    "owner_user_id": g.owner_user_id,
                    "name": g.name,
                    "created_at": g.created_at,
                    "member_count": g.member_count,
                })
            })
            .collect())
    })
    .await;

    match result {
        Ok(Ok(groups)) => Json(serde_json::json!({ "groups": groups })).into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error listing grant groups: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// PATCH /api/groups/{id}
// ============================================================================

#[derive(serde::Deserialize)]
pub struct RenameGroupRequest {
    pub name: String,
}

/// PATCH /api/groups/{id}
///
/// Rename a group, owner-only.
pub async fn rename_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(group_id): Path<i64>,
    Json(body): Json<RenameGroupRequest>,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };
    let name = match clean_user_text(&body.name, MAX_GROUP_NAME_CHARS) {
        Ok(n) => n,
        Err(e) => return e.into_response(),
    };

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::rename_grant_group(&conn, group_id, user_id, &name)
    })
    .await;

    match result {
        Ok(Ok(true)) => Json(serde_json::json!({ "renamed": true })).into_response(),
        Ok(Ok(false)) => group_not_found(),
        Ok(Err(e)) => {
            tracing::error!("DB error renaming grant group: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// DELETE /api/groups/{id}
// ============================================================================

/// DELETE /api/groups/{id}
///
/// Delete a group, owner-only. Cascades its membership rows (`db::
/// delete_grant_group`); any `object_grants` row still targeting it is left
/// in place on purpose (plan §8.3 — see that function's doc comment).
pub async fn delete_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(group_id): Path<i64>,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::delete_grant_group(&conn, group_id, user_id)
    })
    .await;

    match result {
        Ok(Ok(true)) => Json(serde_json::json!({ "deleted": true })).into_response(),
        Ok(Ok(false)) => group_not_found(),
        Ok(Err(e)) => {
            tracing::error!("DB error deleting grant group: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// POST /api/groups/{id}/members
// ============================================================================

#[derive(serde::Deserialize)]
pub struct AddGroupMemberRequest {
    pub nick: String,
}

enum AddMemberOutcome {
    Added,
    GroupNotFound,
    UnknownNick,
    QuotaExceeded,
}

/// POST /api/groups/{id}/members
///
/// Add one member by nick, owner-only. Quota-checked against
/// [`entitlements::group_member_add_allowed`].
pub async fn add_group_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(group_id): Path<i64>,
    Json(body): Json<AddGroupMemberRequest>,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<AddMemberOutcome> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        if !crate::db::grant_group_is_owned_by(&conn, group_id, user_id)? {
            return Ok(AddMemberOutcome::GroupNotFound);
        }
        let Some(member_id) = crate::db::user_id_for_nick(&conn, &body.nick)? else {
            return Ok(AddMemberOutcome::UnknownNick);
        };
        let current = crate::db::count_grant_group_members(&conn, group_id)?;
        if !entitlements::group_member_add_allowed(current) {
            return Ok(AddMemberOutcome::QuotaExceeded);
        }
        let now = chrono::Utc::now().to_rfc3339();
        crate::db::add_grant_group_member(&conn, group_id, user_id, member_id, &now)?;
        Ok(AddMemberOutcome::Added)
    })
    .await;

    match result {
        Ok(Ok(AddMemberOutcome::Added)) => Json(serde_json::json!({ "added": true })).into_response(),
        Ok(Ok(AddMemberOutcome::GroupNotFound)) => group_not_found(),
        Ok(Ok(AddMemberOutcome::UnknownNick)) => bad_request("unknown nick"),
        Ok(Ok(AddMemberOutcome::QuotaExceeded)) => (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse::new("member limit reached for this group")),
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error adding grant group member: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// DELETE /api/groups/{id}/members/{user_id}
// ============================================================================

/// DELETE /api/groups/{id}/members/{user_id}
///
/// Remove one member, owner-only.
pub async fn remove_group_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((group_id, member_user_id)): Path<(i64, i64)>,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::remove_grant_group_member(&conn, group_id, user_id, member_user_id)
    })
    .await;

    match result {
        Ok(Ok(true)) => Json(serde_json::json!({ "removed": true })).into_response(),
        Ok(Ok(false)) => group_not_found(),
        Ok(Err(e)) => {
            tracing::error!("DB error removing grant group member: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

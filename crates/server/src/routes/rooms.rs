//! Shared presets — server-hosted "rooms" with per-nick rights and
//! per-entity LWW patching (docs/mlc/plans/shared-presets-rights-and-
//! live-sync-2026-09-23.md §1-§3/§8, Phase 1: no live channel — that is
//! Phase 2).
//!
//! `{kind}` in every path below is reserved for future object kinds
//! (strategy/template) — Phase 1 resolves ONLY `"preset"`; any other value
//! answers the same bare 404 an unknown room does ([`resolve_kind`]).
//!
//! Endpoints (all under `/api/objects/{kind}/{object_id}`, auth required
//! except the two GETs, which accept an optional caller so an anonymous
//! link-grant viewer still resolves rights):
//!  - `POST   ...`                — bootstrap a room from a whole preset,
//!                                  decomposed server-side
//!                                  (`rooms_codec::decompose_preset`); 409 if
//!                                  the room already exists.
//!  - `POST   .../patch`          — create-if-absent or edit-if-present, the
//!                                  one write verb (§3). Whole-batch
//!                                  `Forbidden` and per-op `Applied`/
//!                                  `Stale`/`Gone` alike ride inside a 200
//!                                  `RoomPatchResponse` — never a bare 403 —
//!                                  matching the plan's "soft, per-entity,
//!                                  not tab-blocking" outcome model (§3).
//!  - `GET    ...`                — reassembled full preset + rights + seq.
//!  - `GET    .../entities?since=`— diff poll (same payload shape Phase 2's
//!                                  SSE frame will reuse verbatim).
//!  - `DELETE ...`                — owner-only teardown.
//!  - `POST   .../clone`          — requires `clone`; reassembles then runs
//!                                  the same strip rule `routes::share`
//!                                  uses (§5, `share::clone_preset_with_strip`).
//!  - `GET/POST .../grants`, `DELETE .../grants/{grant_id}` — owner-only
//!                                  grant CRUD, quota-checked.
//!
//! Paid gate (owner ruling 2026-09-23, "класс и роль нормально" — see
//! `routes::dm::is_dm_paid`'s doc comment): hosting a NEW room requires
//! reaching `social_db::Class::Paid` on the forum ladder, resolved by
//! [`is_shared_presets_paid`] below (byte-for-byte the same shape as
//! `routes::dm::is_dm_paid`, duplicated per this codebase's one-copy-per-
//! route-module convention) — NOT the raw `db::user_is_paid` flag the
//! plan's original §1 code sketch proposed (see `entitlements.rs`'s
//! "Shared presets" module doc for the full reasoning). Being a grantee of
//! someone else's room, or editing one, carries no paid requirement.

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::{extract_bearer, extract_session_id, extract_ua_hash, hash_token};
use crate::db;
use crate::entitlements;
use crate::models::types::ErrorResponse;
use crate::rooms_codec;
use crate::social_db::{self, Class};
use crate::state::AppState;
use crate::text_policy::clean_optional_user_text;

/// Cap on a room's `title` — same figure and same cleaning rule as
/// `routes::share`'s `MAX_TITLE_CHARS`.
const MAX_TITLE_CHARS: usize = 200;

// ============================================================================
// Response helpers
// ============================================================================

fn internal_error() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Internal error"))).into_response()
}

fn bad_request(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(ErrorResponse::new(msg))).into_response()
}

fn forbidden(msg: &str) -> Response {
    (StatusCode::FORBIDDEN, Json(ErrorResponse::new(msg))).into_response()
}

/// Bare 404 — unknown `object_id`, an unresolved `{kind}`, and "exists but
/// caller lacks even `view`" all answer identically (same privacy posture
/// as `routes::share`'s `share_not_found`).
fn room_not_found() -> Response {
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

/// `{kind}` is reserved for future object kinds — Phase 1 resolves only
/// `"preset"` (a shared-preset room).
fn resolve_kind(kind: &str) -> Result<(), Response> {
    if kind == "preset" {
        Ok(())
    } else {
        Err(room_not_found())
    }
}

// ============================================================================
// Auth — mirrors routes::share/routes::dm's resolve_user_id /
// resolve_caller_optional (duplicated rather than shared, following this
// codebase's one-copy-per-route-module convention).
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
            if let Some(uid) = db::resolve_web_session(&conn, &sid, &ua_hash)? {
                return Ok(Some(uid));
            }
        }
        if let Some(raw_token) = bearer {
            let token_hash = hash_token(&raw_token);
            if let Some(uid) = db::resolve_token_hash_with_expiry(&conn, &token_hash)? {
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

/// Resolve the caller to a `user_id`, or `None` for anonymous — the two
/// public-ish GETs (`get_room`, `get_room_entities`) still need to resolve
/// rights for an anonymous "anyone with the link" grantee.
async fn resolve_caller_optional(state: Arc<AppState>, headers: &HeaderMap) -> Result<Option<i64>, StatusCode> {
    let session_id = extract_session_id(headers);
    let ua_hash = extract_ua_hash(headers);
    let bearer: Option<String> = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| extract_bearer(Some(v)))
        .map(|s| s.to_owned());

    if session_id.is_none() && bearer.is_none() {
        return Ok(None);
    }

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<i64>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(sid) = session_id {
            if let Some(uid) = db::resolve_web_session(&conn, &sid, &ua_hash)? {
                return Ok(Some(uid));
            }
        }
        if let Some(raw_token) = bearer {
            let token_hash = hash_token(&raw_token);
            if let Some(uid) = db::resolve_token_hash_with_expiry(&conn, &token_hash)? {
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

// ============================================================================
// Ladder-paid gate for hosting a NEW room (module doc above)
// ============================================================================

/// Whether `user_id` reaches [`Class::Paid`] on the forum ladder —
/// byte-for-byte the same rule `routes::dm::is_dm_paid` applies (an
/// unexpired `paid_until`, trusted standing, or a moderator/admin
/// `forum_roles` row). Takes the already-resolved `is_paid` fact rather
/// than resolving it itself, for the same reason `is_dm_paid` does: the
/// caller already needs to sequence "read identity, drop the lock, then
/// read social" for its own purposes, so threading the bool through keeps
/// the two connections from ever being held at once.
fn is_shared_presets_paid(conn_social: &rusqlite::Connection, user_id: i64, is_paid: bool) -> bool {
    social_db::caller_classes(conn_social, Some(user_id), is_paid).contains(&Class::Paid)
}

// ============================================================================
// Op validation (route-layer, before anything reaches db::apply_room_patch)
// ============================================================================

fn validate_ops(ops: &[db::RoomOp]) -> Result<(), String> {
    for op in ops {
        if !rooms_codec::ENTITY_KINDS.contains(&op.kind.as_str()) {
            return Err(format!("unknown entity kind {:?}", op.kind));
        }
        match op.action {
            db::RoomOpAction::Upsert => {
                let json = op.json.as_ref().ok_or("json is required for an upsert op")?;
                let size = serde_json::to_string(json).map(|s| s.len()).unwrap_or(usize::MAX);
                if size > entitlements::PRESET_MAX_BYTES {
                    return Err("op json exceeds the per-entity size cap".to_string());
                }
                if op.kind == "primitive" && op.base_version == 0 {
                    match op.parent_kind.as_deref() {
                        Some("window") | Some("bubble") => {}
                        _ => return Err("a new primitive requires parent_kind \"window\" or \"bubble\"".to_string()),
                    }
                    if op.parent_id.is_none() {
                        return Err("a new primitive requires parent_id".to_string());
                    }
                }
            }
            db::RoomOpAction::Delete => {}
        }
    }
    Ok(())
}

/// A live storage row → the pure JSON-shape type `rooms_codec` consumes.
/// `None` for a tombstone (`json` is `NULL`) or a row whose `json` failed to
/// parse — both defensive: `room_live_entities` never actually returns a
/// tombstone, and every `json` was validated at write time
/// (`db::apply_room_patch`), so neither branch is expected to fire in
/// practice.
fn row_to_decomposed(row: db::SharedPresetEntityRow) -> Option<rooms_codec::DecomposedEntity> {
    let raw = row.json?;
    let json = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("corrupt shared_preset_entities json kind={} id={}: {}", row.kind, row.entity_id, e);
            return None;
        }
    };
    Some(rooms_codec::DecomposedEntity {
        kind: row.kind,
        entity_id: row.entity_id,
        json,
        parent_kind: row.parent_kind,
        parent_id: row.parent_id,
    })
}

// ============================================================================
// POST /api/objects/{kind}/{object_id}  (create a room FROM a whole preset)
// ============================================================================

#[derive(Deserialize)]
pub struct CreateRoomRequest {
    pub preset: serde_json::Value,
    #[serde(default)]
    pub title: String,
}

enum CreateRoomOutcome {
    Created { seq: i64, entity_count: usize },
    AlreadyExists,
    QuotaExceeded,
}

/// POST /api/objects/{kind}/{object_id}
///
/// Bootstraps a room from a whole `ChartPreset` JSON, decomposed into
/// entities server-side (`rooms_codec::decompose_preset`) and applied as one
/// `Upsert`-every-entity batch through the SAME `db::apply_room_patch` the
/// `/patch` route uses — one write path, not two. This is the "Make this a
/// shared room" action (plan §6): a client with no per-entity diff state yet
/// (the first time a preset is ever shared) sends the whole preset once
/// instead of hand-computing an initial ops batch. `POST .../patch` remains
/// the ONLY route for every subsequent edit.
///
/// Refuses (409) if a room already exists at `object_id` — this is a create,
/// never a silent overwrite of a live room's content. Gated by the same
/// ladder-paid + hosting-quota check `patch_room` runs for a new room (see
/// the module doc).
pub async fn create_room(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((kind, object_id)): Path<(String, String)>,
    Json(body): Json<CreateRoomRequest>,
) -> Response {
    let caller = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };
    if let Err(resp) = resolve_kind(&kind) {
        return resp;
    }
    if !body.preset.is_object() {
        return bad_request("preset must be a JSON object");
    }
    let preset_size = serde_json::to_string(&body.preset).map(|s| s.len()).unwrap_or(usize::MAX);
    if preset_size > entitlements::PRESET_MAX_BYTES {
        return bad_request("preset exceeds the size cap");
    }
    let entities = match rooms_codec::decompose_preset(&body.preset) {
        Ok(e) => e,
        Err(msg) => return bad_request(&format!("malformed preset: {msg}")),
    };
    let title = match clean_optional_user_text(&body.title, MAX_TITLE_CHARS) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let ops: Vec<db::RoomOp> = entities
        .into_iter()
        .map(|e| db::RoomOp {
            kind: e.kind,
            id: e.entity_id,
            action: db::RoomOpAction::Upsert,
            base_version: 0,
            json: Some(e.json),
            parent_kind: e.parent_kind,
            parent_id: e.parent_id,
        })
        .collect();

    let object_id_for_response = object_id.clone();
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<CreateRoomOutcome> {
        {
            let identity_conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            if db::get_shared_preset(&identity_conn, &object_id)?.is_some() {
                return Ok(CreateRoomOutcome::AlreadyExists);
            }
        }

        let is_paid = {
            let identity_conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            db::user_is_paid(&identity_conn, caller)?
        };
        let ladder_paid = {
            let social_conn = state.control_plane().social_conn();
            is_shared_presets_paid(&social_conn, caller, is_paid)
        };
        let hosted = {
            let identity_conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            db::count_hosted_shared_presets(&identity_conn, caller)?
        };
        if !entitlements::shared_preset_create_allowed(hosted, ladder_paid) {
            return Ok(CreateRoomOutcome::QuotaExceeded);
        }

        let entity_count = ops.len();
        let mut identity_conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now().to_rfc3339();
        let (seq, _results, _cascades) =
            db::apply_room_patch(&mut identity_conn, &kind, &object_id, caller, &now, &ops, true)?;
        if !title.is_empty() {
            db::set_shared_preset_title(&identity_conn, &object_id, caller, &title)?;
        }
        Ok(CreateRoomOutcome::Created { seq, entity_count })
    })
    .await;

    match result {
        Ok(Ok(CreateRoomOutcome::Created { seq, entity_count })) => {
            Json(serde_json::json!({ "object_id": object_id_for_response, "seq": seq, "entity_count": entity_count })).into_response()
        }
        Ok(Ok(CreateRoomOutcome::AlreadyExists)) => {
            (StatusCode::CONFLICT, Json(ErrorResponse::new("a room already exists at this object_id"))).into_response()
        }
        Ok(Ok(CreateRoomOutcome::QuotaExceeded)) => {
            forbidden("shared presets require a paid account and are capped per account")
        }
        Ok(Err(e)) => {
            tracing::error!("DB error creating room: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// POST /api/objects/{kind}/{object_id}/patch
// ============================================================================

#[derive(Deserialize)]
pub struct RoomPatchRequestWire {
    /// Advisory only, logged for diagnostics — the actual gate is per-op
    /// `base_version` (see `db::apply_room_patch`'s doc comment).
    #[serde(default)]
    pub base_seq: i64,
    pub ops: Vec<db::RoomOp>,
}

#[derive(Serialize)]
struct RoomPatchResponseWire {
    seq: i64,
    applied: Vec<RoomOpResultWire>,
}

#[derive(Serialize)]
struct RoomOpResultWire {
    kind: String,
    id: String,
    outcome: RoomOpOutcomeWire,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum RoomOpOutcomeWire {
    Applied { version: i64, seq: i64 },
    Stale { current_version: i64, current_json: Option<serde_json::Value> },
    Gone,
    Forbidden,
}

fn outcome_wire(outcome: db::RoomOpOutcome) -> RoomOpOutcomeWire {
    match outcome {
        db::RoomOpOutcome::Applied { version, seq } => RoomOpOutcomeWire::Applied { version, seq },
        db::RoomOpOutcome::Stale { current_version, current_json } => RoomOpOutcomeWire::Stale {
            current_version,
            current_json: current_json.and_then(|s| serde_json::from_str(&s).ok()),
        },
        db::RoomOpOutcome::Gone => RoomOpOutcomeWire::Gone,
        db::RoomOpOutcome::Forbidden => RoomOpOutcomeWire::Forbidden,
    }
}

/// POST /api/objects/{kind}/{object_id}/patch
pub async fn patch_room(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((kind, object_id)): Path<(String, String)>,
    Json(body): Json<RoomPatchRequestWire>,
) -> Response {
    let caller = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };
    if let Err(resp) = resolve_kind(&kind) {
        return resp;
    }
    if let Err(msg) = validate_ops(&body.ops) {
        return bad_request(&msg);
    }
    tracing::debug!("room patch caller={} kind={} object_id={} base_seq={} ops={}", caller, kind, object_id, body.base_seq, body.ops.len());
    let ops = body.ops;

    let result = tokio::task::spawn_blocking(
        move || -> rusqlite::Result<(i64, Vec<(db::RoomOp, db::RoomOpOutcome)>, Vec<(String, db::RoomOpOutcome)>)> {
            // Ladder-paid + hosting-quota check for the "this room does not
            // exist yet" path — see the module doc and `db::apply_room_
            // patch`'s doc comment for why this cannot be resolved inside
            // that function itself.
            let is_paid = {
                let identity_conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
                db::user_is_paid(&identity_conn, caller)?
            };
            let ladder_paid = {
                let social_conn = state.control_plane().social_conn();
                is_shared_presets_paid(&social_conn, caller, is_paid)
            };
            let hosted = {
                let identity_conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
                db::count_hosted_shared_presets(&identity_conn, caller)?
            };
            let create_allowed = entitlements::shared_preset_create_allowed(hosted, ladder_paid);

            let mut identity_conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            let now = chrono::Utc::now().to_rfc3339();
            db::apply_room_patch(&mut identity_conn, &kind, &object_id, caller, &now, &ops, create_allowed)
        },
    )
    .await;

    match result {
        Ok(Ok((seq, results, cascades))) => {
            let mut applied: Vec<RoomOpResultWire> = results
                .into_iter()
                .map(|(op, outcome)| RoomOpResultWire { kind: op.kind, id: op.id, outcome: outcome_wire(outcome) })
                .collect();
            applied.extend(cascades.into_iter().map(|(id, outcome)| RoomOpResultWire {
                kind: "primitive".to_string(),
                id,
                outcome: outcome_wire(outcome),
            }));
            Json(RoomPatchResponseWire { seq, applied }).into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("DB error applying room patch: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// GET /api/objects/{kind}/{object_id}
// ============================================================================

/// GET /api/objects/{kind}/{object_id}
///
/// Reassembled full preset + the caller's effective rights + the room's
/// current `seq`. A caller without `view` gets the same bare 404 an unknown
/// `object_id` does (see [`room_not_found`]).
pub async fn get_room(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((kind, object_id)): Path<(String, String)>,
) -> Response {
    if let Err(resp) = resolve_kind(&kind) {
        return resp;
    }
    let caller = match resolve_caller_optional(state.clone(), &headers).await {
        Ok(c) => c,
        Err(_) => return internal_error(),
    };

    let result = tokio::task::spawn_blocking(
        move || -> rusqlite::Result<Option<(db::SharedPresetRow, Vec<&'static str>, Vec<db::SharedPresetEntityRow>)>> {
            let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            let Some(header) = db::get_shared_preset(&conn, &object_id)? else {
                return Ok(None);
            };
            let rights = db::effective_object_rights(&conn, &kind, &object_id, header.owner_user_id, caller)?;
            if !rights.contains(&"view") {
                return Ok(None);
            }
            let entities = db::room_live_entities(&conn, &object_id)?;
            Ok(Some((header, rights, entities)))
        },
    )
    .await;

    match result {
        Ok(Ok(Some((header, rights, rows)))) => {
            let decomposed: Vec<rooms_codec::DecomposedEntity> = rows.into_iter().filter_map(row_to_decomposed).collect();
            let preset = rooms_codec::reassemble_preset(&decomposed);
            Json(serde_json::json!({
                "object_id": header.object_id,
                "title": header.title,
                "visibility": header.visibility,
                "seq": header.seq,
                "created_at": header.created_at,
                "updated_at": header.updated_at,
                "rights": rights,
                "preset": preset,
            }))
            .into_response()
        }
        Ok(Ok(None)) => room_not_found(),
        Ok(Err(e)) => {
            tracing::error!("DB error reading room: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// GET /api/objects/{kind}/{object_id}/entities?since={seq}
// ============================================================================

#[derive(Deserialize)]
pub struct SinceQuery {
    #[serde(default)]
    pub since: i64,
}

/// GET /api/objects/{kind}/{object_id}/entities?since={seq}
///
/// Diff poll — the same payload shape Phase 2's SSE `entities` frame will
/// reuse verbatim (plan §4). `since=0` already is the full snapshot (see
/// `db::room_entities_since`'s doc comment).
pub async fn get_room_entities(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((kind, object_id)): Path<(String, String)>,
    Query(q): Query<SinceQuery>,
) -> Response {
    if let Err(resp) = resolve_kind(&kind) {
        return resp;
    }
    let caller = match resolve_caller_optional(state.clone(), &headers).await {
        Ok(c) => c,
        Err(_) => return internal_error(),
    };

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<(i64, Vec<serde_json::Value>)>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let Some(header) = db::get_shared_preset(&conn, &object_id)? else {
            return Ok(None);
        };
        let rights = db::effective_object_rights(&conn, &kind, &object_id, header.owner_user_id, caller)?;
        if !rights.contains(&"view") {
            return Ok(None);
        }
        let rows = db::room_entities_since(&conn, &object_id, q.since)?;
        let mut entities = Vec::with_capacity(rows.len());
        for row in rows {
            let updated_by_label = db::effective_label_for_user(&conn, row.updated_by)?;
            let json_value: Option<serde_json::Value> = row.json.as_deref().and_then(|s| serde_json::from_str(s).ok());
            entities.push(serde_json::json!({
                "kind": row.kind,
                "id": row.entity_id,
                "version": row.version,
                "updated_by": updated_by_label,
                "updated_at": row.updated_at,
                "json": json_value,
                "deleted": row.deleted,
                "seq": row.seq,
                "parent_kind": row.parent_kind,
                "parent_id": row.parent_id,
            }));
        }
        Ok(Some((header.seq, entities)))
    })
    .await;

    match result {
        Ok(Ok(Some((seq, entities)))) => Json(serde_json::json!({ "seq": seq, "entities": entities })).into_response(),
        Ok(Ok(None)) => room_not_found(),
        Ok(Err(e)) => {
            tracing::error!("DB error polling room entities: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// DELETE /api/objects/{kind}/{object_id}
// ============================================================================

/// DELETE /api/objects/{kind}/{object_id}
///
/// Owner-only teardown. Unknown room and "not the owner" both answer the
/// same bare 404 (see `db::delete_shared_preset`).
pub async fn delete_room(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((kind, object_id)): Path<(String, String)>,
) -> Response {
    let caller = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };
    if let Err(resp) = resolve_kind(&kind) {
        return resp;
    }

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        db::delete_shared_preset(&conn, &object_id, caller)
    })
    .await;

    match result {
        Ok(Ok(true)) => Json(serde_json::json!({ "deleted": true })).into_response(),
        Ok(Ok(false)) => room_not_found(),
        Ok(Err(e)) => {
            tracing::error!("DB error deleting room: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// POST /api/objects/{kind}/{object_id}/clone
// ============================================================================

enum RoomCloneOutcome {
    Cloned { preset: serde_json::Value, stripped: Vec<serde_json::Value> },
    Forbidden,
}

/// POST /api/objects/{kind}/{object_id}/clone
///
/// Auth required. Requires `clone` in the caller's effective rights — 403
/// otherwise (an unknown room stays a 404, see `room_not_found`). Reassembles
/// the room's live entities into a whole preset, then runs the SAME strip
/// rule `routes::share::clone_share` uses (plan §5).
pub async fn clone_room(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((kind, object_id)): Path<(String, String)>,
) -> Response {
    let caller = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };
    if let Err(resp) = resolve_kind(&kind) {
        return resp;
    }

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<RoomCloneOutcome>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let Some(header) = db::get_shared_preset(&conn, &object_id)? else {
            return Ok(None);
        };
        let rights = db::effective_object_rights(&conn, &kind, &object_id, header.owner_user_id, Some(caller))?;
        if !rights.contains(&"clone") {
            return Ok(Some(RoomCloneOutcome::Forbidden));
        }
        let rows = db::room_live_entities(&conn, &object_id)?;
        let decomposed: Vec<rooms_codec::DecomposedEntity> = rows.into_iter().filter_map(row_to_decomposed).collect();
        let preset = rooms_codec::reassemble_preset(&decomposed);
        // Rooms has no Protected/`clone_protected` concept of its own
        // (Protected is a share-link-only idea, docs/mlc/plans/share-policy-
        // 2026-09-25.md §6) — always an empty protected list and
        // `skip_protected_strip: false`, so the protected-element pass is
        // simply a no-op here, never engaged.
        let (preset, stripped) = super::share::clone_preset_with_strip(&conn, preset, caller, &[], false)?;
        Ok(Some(RoomCloneOutcome::Cloned { preset, stripped }))
    })
    .await;

    match result {
        Ok(Ok(Some(RoomCloneOutcome::Cloned { preset, stripped }))) => {
            Json(serde_json::json!({ "preset": preset, "stripped": stripped })).into_response()
        }
        Ok(Ok(Some(RoomCloneOutcome::Forbidden))) => forbidden("clone is not granted for this room"),
        Ok(Ok(None)) => room_not_found(),
        Ok(Err(e)) => {
            tracing::error!("DB error cloning room: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// GET/POST /api/objects/{kind}/{object_id}/grants, DELETE .../grants/{grant_id}
// ============================================================================

/// GET /api/objects/{kind}/{object_id}/grants
///
/// Owner-only grant-management listing. Non-owner and unknown room both
/// answer the same bare 404.
pub async fn list_grants(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((kind, object_id)): Path<(String, String)>,
) -> Response {
    let caller = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };
    if let Err(resp) = resolve_kind(&kind) {
        return resp;
    }

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<Vec<serde_json::Value>>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let Some(header) = db::get_shared_preset(&conn, &object_id)? else {
            return Ok(None);
        };
        if header.owner_user_id != caller {
            return Ok(None);
        }
        let grants = db::list_object_grants(&conn, &kind, &object_id)?;
        let mut out = Vec::with_capacity(grants.len());
        for g in grants {
            let grantee_label = match g.grantee_user_id {
                Some(uid) => Some(db::effective_label_for_user(&conn, uid)?),
                None => None,
            };
            out.push(serde_json::json!({
                "id": g.id,
                "object_kind": g.object_kind,
                "object_id": g.object_id,
                "owner_user_id": g.owner_user_id,
                "grantee_user_id": g.grantee_user_id,
                "grantee": grantee_label,
                "right": g.right,
                "expires_at": g.expires_at,
                "created_at": g.created_at,
            }));
        }
        Ok(Some(out))
    })
    .await;

    match result {
        Ok(Ok(Some(grants))) => Json(serde_json::json!({ "grants": grants })).into_response(),
        Ok(Ok(None)) => room_not_found(),
        Ok(Err(e)) => {
            tracing::error!("DB error listing room grants: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

#[derive(Deserialize)]
pub struct CreateGrantRequest {
    /// Nick of the grantee, or absent/`null` for a public "anyone with the
    /// link" grant. A public grant can only ever carry `right = "view"` or
    /// `"clone"` — see below.
    #[serde(default)]
    pub grantee: Option<String>,
    /// `"view" | "clone" | "edit"`.
    pub right: String,
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

enum CreateGrantOutcome {
    Created { grant_id: i64 },
    RoomNotFound,
    UnknownNick,
    QuotaExceeded,
}

/// POST /api/objects/{kind}/{object_id}/grants
///
/// Owner-only. `right = "edit"` with no `grantee` is refused before any
/// database work — a public "anyone with the link" grant may only ever be
/// `view`/`clone` (plan's non-goals list: "Public (anonymous, no account)
/// `edit` grants — refused at the route layer regardless of what a grant
/// row could technically encode").
pub async fn create_grant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((kind, object_id)): Path<(String, String)>,
    Json(body): Json<CreateGrantRequest>,
) -> Response {
    let caller = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };
    if let Err(resp) = resolve_kind(&kind) {
        return resp;
    }
    if !matches!(body.right.as_str(), "view" | "clone" | "edit") {
        return bad_request("right must be \"view\", \"clone\", or \"edit\"");
    }
    if body.right == "edit" && body.grantee.is_none() {
        return bad_request("edit cannot be granted publicly — name a grantee");
    }

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<CreateGrantOutcome> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let Some(header) = db::get_shared_preset(&conn, &object_id)? else {
            return Ok(CreateGrantOutcome::RoomNotFound);
        };
        if header.owner_user_id != caller {
            return Ok(CreateGrantOutcome::RoomNotFound);
        }

        let grantee_user_id = match &body.grantee {
            Some(nick) => match db::user_id_for_nick(&conn, nick)? {
                Some(uid) => Some(uid),
                None => return Ok(CreateGrantOutcome::UnknownNick),
            },
            None => None,
        };

        let current = db::count_object_grants(&conn, &kind, &object_id)?;
        if !entitlements::grant_create_allowed(current) {
            return Ok(CreateGrantOutcome::QuotaExceeded);
        }

        let now = chrono::Utc::now();
        let expires_at = body
            .ttl_secs
            .map(|secs| (now + chrono::Duration::seconds(secs.min(i64::MAX as u64) as i64)).to_rfc3339());
        let now_str = now.to_rfc3339();
        let grant_id = db::upsert_object_grant(
            &conn,
            &kind,
            &object_id,
            caller,
            grantee_user_id,
            &body.right,
            expires_at.as_deref(),
            &now_str,
        )?;
        Ok(CreateGrantOutcome::Created { grant_id })
    })
    .await;

    match result {
        Ok(Ok(CreateGrantOutcome::Created { grant_id })) => Json(serde_json::json!({ "grant_id": grant_id })).into_response(),
        Ok(Ok(CreateGrantOutcome::RoomNotFound)) => room_not_found(),
        Ok(Ok(CreateGrantOutcome::UnknownNick)) => bad_request("unknown nick"),
        Ok(Ok(CreateGrantOutcome::QuotaExceeded)) => forbidden("grant limit reached for this room"),
        Ok(Err(e)) => {
            tracing::error!("DB error creating room grant: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

/// DELETE /api/objects/{kind}/{object_id}/grants/{grant_id}
///
/// Owner-only revoke (see `db::revoke_object_grant`) — the grant row's own
/// `owner_user_id` is the only check, matching the plan's literal
/// signature; `object_id` in the path names the resource the client is
/// looking at, not an extra filter.
pub async fn delete_grant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((kind, _object_id, grant_id)): Path<(String, String, i64)>,
) -> Response {
    let caller = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };
    if let Err(resp) = resolve_kind(&kind) {
        return resp;
    }

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        db::revoke_object_grant(&conn, grant_id, caller)
    })
    .await;

    match result {
        Ok(Ok(true)) => Json(serde_json::json!({ "revoked": true })).into_response(),
        Ok(Ok(false)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error revoking room grant: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

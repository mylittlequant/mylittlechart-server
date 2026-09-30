//! Matrix key routes (P9): `keys/upload`, `keys/query`, `keys/claim`,
//! `keys/changes`, cross-signing (`keys/device_signing/upload`,
//! `keys/signatures/upload`), `sendToDevice`, `devices`, `room_keys/*`. See
//! `docs/mlc/plans/messenger-proto-server-matrix-subset-2026-09-24.md` §2
//! second SQL block (the devices/keys/backup schema this module reads and
//! writes through `mylittlechart_server::matrix_keys_store`), §3.7 (the
//! `/sync` delta shapes `keys/changes` mirrors), and its own P9 brief for the
//! per-endpoint rules this module follows.
//!
//! # Crypto stays opaque here too — with one deliberate exception
//!
//! Every `device_keys`/`one_time_keys`/`fallback_keys`/
//! `cross_signing_signatures` blob this module stores is pure opaque JSON,
//! never inspected — matching `matrix_keys_store`'s own stated contract. The
//! ONE exception, scoped to `POST /keys/device_signing/upload` alone: a
//! `self_signing_key`/`user_signing_key` upload's ed25519 signature by the
//! caller's master key IS verified server-side (this module's own P9 brief),
//! using [`canonical_json_without_signatures`] + `ed25519-dalek` (already a
//! server dependency, `Cargo.toml`). `POST /keys/signatures/upload` does NOT
//! verify signature bytes — only the AUTHORIZATION shape of who may file a
//! signature against whom — see that endpoint's own section below.
//!
//! # Share-a-room gate
//!
//! `/keys/query`, `/keys/claim`, `/keys/changes`, and `PUT /sendToDevice` all
//! restrict to the caller themself or a user who shares a room with them
//! ([`peers_sharing_a_room_with`]): the caller must be JOINED to a room in
//! which the peer is JOINED or INVITED — the plan's own anti-directory-
//! scraping rule, widened by the invited half so a client that sends before
//! its invitee joins can still encrypt to them (it shares its first Megolm
//! session with join+invite members; our rooms use `history_visibility:
//! shared`, so the invitee reads it on joining). An invited caller gets no
//! visibility at all. A disallowed target comes back empty/dropped, never an
//! error that would let a caller distinguish "no such user" from "exists but
//! not visible to you".
//!
//! # Every write is one transaction, then one wake
//!
//! Same discipline as every other module in this tree: a handler's whole DB
//! decision runs inside `spawn_blocking` holding `cp.messenger_conn()` (and
//! `cp.db` first, in that lock order, when a handler needs both — matching
//! `routes::matrix::auth`'s own stated convention), and `live.wake_many` is
//! called only AFTER that future resolves.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use rusqlite::Connection;

use mylittlechart_server::matrix_keys_store::{self, CrossSigningUsage};
use mylittlechart_server::matrix_store::{self, Membership, TxnDedupEntry};

use super::auth;
use super::sync_token;
use super::MatrixError;
use crate::state::AppState;

/// Per-request cap on `PUT /sendToDevice`'s flattened target-device count
/// (plan P9 brief: "≤ 1 000 target devices").
const SEND_TO_DEVICE_MAX_TARGETS: usize = 1000;
/// Per-target content-size cap (plan P9 brief: "≤ 64 KiB per content").
const SEND_TO_DEVICE_MAX_CONTENT_BYTES: usize = 64 * 1024;
/// The one key-backup algorithm this server accepts (plan P9 brief, MSC3270
/// naming) — `m.megolm_backup.v1.curve25519-aes-sha2` (the PkEncryption
/// backup) is refused outright, never even reaching storage.
const BACKUP_ALGORITHM: &str = "m.megolm_backup.v1.aes-hmac-sha2";

// ============================================================================
// Router
// ============================================================================

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/client/v3/keys/upload", post(keys_upload))
        .route("/client/v3/keys/query", post(keys_query))
        .route("/client/v3/keys/claim", post(keys_claim))
        .route("/client/v3/keys/changes", get(keys_changes))
        .route("/client/v3/keys/device_signing/upload", post(device_signing_upload))
        .route("/client/v3/keys/signatures/upload", post(signatures_upload))
        .route("/client/v3/sendToDevice/{event_type}/{txn_id}", put(send_to_device))
        .route("/client/v3/devices", get(list_devices_route))
        .route(
            "/client/v3/devices/{device_id}",
            get(get_device_route).put(put_device_route).delete(delete_device_route),
        )
        .route("/client/v3/delete_devices", post(bulk_delete_devices))
        .route(
            "/client/v3/room_keys/version",
            post(post_backup_version).get(get_current_backup_version),
        )
        .route(
            "/client/v3/room_keys/version/{version}",
            get(get_backup_version_route).put(put_backup_version_route).delete(delete_backup_version_route),
        )
        .route(
            "/client/v3/room_keys/keys",
            get(get_backup_keys_all).put(put_backup_keys_all).delete(delete_backup_keys_all),
        )
        .route(
            "/client/v3/room_keys/keys/{room_id}",
            get(get_backup_keys_room).put(put_backup_keys_room).delete(delete_backup_keys_room),
        )
        .route(
            "/client/v3/room_keys/keys/{room_id}/{session_id}",
            get(get_backup_keys_session).put(put_backup_keys_session).delete(delete_backup_keys_session),
        )
}

// ============================================================================
// Shared gate: share-a-room visibility
// ============================================================================

/// Every user id the caller may see key material for through this module's
/// share-a-room gate: `user_id` itself, plus every user who is JOINED or
/// INVITED in a room the caller is JOINED to (plan P9 brief: `/keys/query`/
/// `/keys/claim`/`PUT /sendToDevice` "restrict to users who share a room
/// with the caller, or the caller"; the invited half is P16 S-e — see this
/// module's own doc). The caller must be joined: a room where the caller is
/// only invited, has left, or is banned contributes nothing. A target
/// outside this set is dropped/emptied by the caller, never distinguished
/// from "no such account".
pub(super) fn peers_sharing_a_room_with(conn: &Connection, user_id: i64) -> rusqlite::Result<HashSet<i64>> {
    let mut ids = HashSet::new();
    ids.insert(user_id);
    for room_id in matrix_store::rooms_for_user(conn, user_id, Some(Membership::Join))? {
        for member in matrix_store::room_members(conn, &room_id, None)? {
            if matches!(member.membership, Membership::Join | Membership::Invite) {
                ids.insert(member.user_id);
            }
        }
    }
    Ok(ids)
}

// ============================================================================
// POST /_matrix/client/v3/keys/upload
// ============================================================================

#[derive(serde::Deserialize, Default)]
struct KeysUploadRequest {
    #[serde(default)]
    device_keys: Option<serde_json::Value>,
    #[serde(default)]
    one_time_keys: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default)]
    fallback_keys: Option<BTreeMap<String, serde_json::Value>>,
}

/// `device_keys.user_id`/`device_id` must name the authenticated caller
/// (plan §2 manager decision 5 / P9 brief) — else `M_INVALID_PARAM`.
fn check_device_keys_ownership(device_keys: &serde_json::Value, caller_mxid: &str, caller_device_id: &str) -> Result<(), MatrixError> {
    let user_id = device_keys.get("user_id").and_then(|v| v.as_str());
    let device_id = device_keys.get("device_id").and_then(|v| v.as_str());
    if user_id != Some(caller_mxid) || device_id != Some(caller_device_id) {
        return Err(MatrixError::invalid_param("device_keys.user_id/device_id must name the authenticated caller"));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceKeysUploadAction {
    Insert,
    Noop,
}

/// A device never changes identity keys once set (plan P9 brief: "a CHANGE
/// to an already-stored device key set for the same device id is refused —
/// a device never changes identity keys; the client must log in again").
/// Compares only the `keys` object (the actual curve25519/ed25519 identity),
/// not `algorithms`/`signatures`, which may legitimately be resent — an
/// identical `keys` resubmission is a silent no-op (many clients re-upload
/// their unchanged device keys on every restart).
fn decide_device_keys_upload(existing_keys_json: Option<&str>, new_keys_value: &serde_json::Value) -> Result<DeviceKeysUploadAction, MatrixError> {
    let Some(existing_keys_json) = existing_keys_json else {
        return Ok(DeviceKeysUploadAction::Insert);
    };
    let existing_keys: serde_json::Value = serde_json::from_str(existing_keys_json)?;
    if &existing_keys == new_keys_value {
        Ok(DeviceKeysUploadAction::Noop)
    } else {
        Err(MatrixError::invalid_param(
            "a device's identity keys cannot change once set — log in again to mint a new device",
        ))
    }
}

/// `algorithm:key_id` — every one-time/fallback key's own wire id (plan P9
/// brief: "OTK ids algorithm:key_id format validated").
fn split_algorithm_key_id(full_id: &str) -> Result<(&str, &str), MatrixError> {
    let (algorithm, key_id) = full_id
        .split_once(':')
        .ok_or_else(|| MatrixError::invalid_param(format!("malformed one-time key id: {full_id}")))?;
    if algorithm.is_empty() || key_id.is_empty() {
        return Err(MatrixError::invalid_param(format!("malformed one-time key id: {full_id}")));
    }
    Ok((algorithm, key_id))
}

struct KeysUploadOutcome {
    otk_counts: HashMap<String, i64>,
    device_keys_changed: bool,
}

/// DB-only core for `POST /keys/upload` (plan P9 brief): ownership + no-
/// identity-change checks on `device_keys` (a first upload or an identical
/// resubmission only — a change is refused), OTK-id validation, then pure
/// storage of everything provided. Returns the fresh
/// `one_time_key_counts` plus whether `device_keys` actually changed (the
/// caller only wakes peers when it did).
fn apply_keys_upload(
    conn: &mut Connection,
    caller_user_id: i64,
    caller_mxid: &str,
    caller_device_id: &str,
    request: &KeysUploadRequest,
    now: &str,
) -> Result<KeysUploadOutcome, MatrixError> {
    let mut device_keys_changed = false;

    if let Some(device_keys) = &request.device_keys {
        check_device_keys_ownership(device_keys, caller_mxid, caller_device_id)?;
        let new_keys_value = device_keys.get("keys").cloned().unwrap_or(serde_json::Value::Null);
        let existing = matrix_keys_store::device_keys_for(conn, &[caller_user_id])?
            .into_iter()
            .find(|d| d.device_id == caller_device_id);
        let action = decide_device_keys_upload(existing.as_ref().map(|d| d.keys.as_str()), &new_keys_value)?;
        if action == DeviceKeysUploadAction::Insert {
            let algorithms_json = device_keys.get("algorithms").cloned().unwrap_or(serde_json::json!([])).to_string();
            let keys_json = new_keys_value.to_string();
            let signatures_json = device_keys.get("signatures").cloned().unwrap_or(serde_json::json!({})).to_string();
            matrix_keys_store::upsert_device_keys(conn, caller_user_id, caller_device_id, &algorithms_json, &keys_json, &signatures_json, now)?;
            device_keys_changed = true;
        }
    }

    if let Some(one_time_keys) = &request.one_time_keys {
        let mut batch = Vec::with_capacity(one_time_keys.len());
        for (full_id, value) in one_time_keys {
            let (algorithm, _) = split_algorithm_key_id(full_id)?;
            batch.push((full_id.clone(), algorithm.to_string(), value.to_string()));
        }
        matrix_keys_store::add_one_time_keys(conn, caller_user_id, caller_device_id, &batch)?;
    }

    if let Some(fallback_keys) = &request.fallback_keys {
        for (full_id, value) in fallback_keys {
            let (algorithm, _) = split_algorithm_key_id(full_id)?;
            matrix_keys_store::upsert_fallback_key(conn, caller_user_id, caller_device_id, algorithm, full_id, &value.to_string(), now)?;
        }
    }

    let otk_counts = matrix_keys_store::count_one_time_keys(conn, caller_user_id, caller_device_id)?;
    Ok(KeysUploadOutcome { otk_counts, device_keys_changed })
}

async fn keys_upload(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(request): Json<KeysUploadRequest>) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let state_for_blocking = state.clone();

    let (otk_counts, wake_ids) = tokio::task::spawn_blocking(move || -> Result<(HashMap<String, i64>, Option<HashSet<i64>>), MatrixError> {
        let cp = state_for_blocking.control_plane();
        let now = chrono::Utc::now().to_rfc3339();
        let mut messenger_conn = cp.messenger_conn();
        let outcome = apply_keys_upload(&mut messenger_conn, caller.user_id, &caller.mxid, &caller.device_id, &request, &now)?;
        let wake_ids = if outcome.device_keys_changed {
            Some(peers_sharing_a_room_with(&messenger_conn, caller.user_id)?)
        } else {
            None
        };
        Ok((outcome.otk_counts, wake_ids))
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    if let Some(wake_ids) = wake_ids {
        state.control_plane().live.wake_many(wake_ids.into_iter().map(|id| format!("user:{id}")));
    }
    Ok(Json(serde_json::json!({ "one_time_key_counts": otk_counts })))
}

// ============================================================================
// POST /_matrix/client/v3/keys/query
// ============================================================================

#[derive(serde::Deserialize, Default)]
struct KeysQueryRequest {
    #[serde(default)]
    device_keys: BTreeMap<String, Vec<String>>,
}

/// DB-only core for `POST /keys/query` (plan P9 brief): batch `device_keys`
/// for every requested user this caller may see (self, or a shared-room
/// peer — [`peers_sharing_a_room_with`]), plus `master_keys`/
/// `self_signing_keys` for the same allowed set, and `user_signing_keys`
/// ONLY for the caller (spec: a user-signing key is never shared with anyone
/// else). A requested user this caller may NOT see, or an mxid naming no
/// known account, gets an empty `device_keys` entry (`{}`) rather than being
/// omitted — the caller learns nothing about whether the account even
/// exists.
fn build_keys_query_response(
    conn: &Connection,
    caller_user_id: i64,
    caller_mxid: &str,
    requested: &BTreeMap<String, Vec<String>>,
) -> Result<serde_json::Value, MatrixError> {
    let visible = peers_sharing_a_room_with(conn, caller_user_id)?;

    let mut device_keys_out = serde_json::Map::new();
    let mut master_keys_out = serde_json::Map::new();
    let mut self_signing_keys_out = serde_json::Map::new();

    for (mxid, requested_device_ids) in requested {
        let allowed_user_id = matrix_store::user_id_of(conn, mxid)?.filter(|uid| visible.contains(uid));
        let Some(target_user_id) = allowed_user_id else {
            device_keys_out.insert(mxid.clone(), serde_json::json!({}));
            continue;
        };

        let mut devices_out = serde_json::Map::new();
        for device_keys in matrix_keys_store::device_keys_for(conn, &[target_user_id])? {
            if !requested_device_ids.is_empty() && !requested_device_ids.contains(&device_keys.device_id) {
                continue;
            }
            let algorithms: serde_json::Value = serde_json::from_str(&device_keys.algorithms)?;
            let keys: serde_json::Value = serde_json::from_str(&device_keys.keys)?;
            let signatures: serde_json::Value = serde_json::from_str(&device_keys.signatures)?;
            devices_out.insert(
                device_keys.device_id.clone(),
                serde_json::json!({
                    "user_id": mxid,
                    "device_id": device_keys.device_id,
                    "algorithms": algorithms,
                    "keys": keys,
                    "signatures": signatures,
                }),
            );
        }
        device_keys_out.insert(mxid.clone(), serde_json::Value::Object(devices_out));

        for cross_signing_key in matrix_keys_store::cross_signing_keys_for(conn, &[target_user_id])? {
            let value: serde_json::Value = serde_json::from_str(&cross_signing_key.key_json)?;
            match cross_signing_key.usage {
                CrossSigningUsage::Master => {
                    master_keys_out.insert(mxid.clone(), value);
                }
                CrossSigningUsage::SelfSigning => {
                    self_signing_keys_out.insert(mxid.clone(), value);
                }
                CrossSigningUsage::UserSigning => {} // never exposed for anyone but the caller themself, below
            }
        }
    }

    let mut user_signing_keys_out = serde_json::Map::new();
    if let Some(row) = matrix_keys_store::cross_signing_key_for(conn, caller_user_id, CrossSigningUsage::UserSigning)? {
        user_signing_keys_out.insert(caller_mxid.to_string(), serde_json::from_str(&row.key_json)?);
    }

    Ok(serde_json::json!({
        "device_keys": device_keys_out,
        "master_keys": master_keys_out,
        "self_signing_keys": self_signing_keys_out,
        "user_signing_keys": user_signing_keys_out,
        "failures": {},
    }))
}

async fn keys_query(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(request): Json<KeysQueryRequest>) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let response = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
        let cp = state.control_plane();
        let messenger_conn = cp.messenger_conn();
        build_keys_query_response(&messenger_conn, caller.user_id, &caller.mxid, &request.device_keys)
    })
    .await
    .map_err(|_| MatrixError::internal())??;
    Ok(Json(response))
}

// ============================================================================
// POST /_matrix/client/v3/keys/claim
// ============================================================================

#[derive(serde::Deserialize, Default)]
struct KeysClaimRequest {
    #[serde(default)]
    one_time_keys: BTreeMap<String, BTreeMap<String, String>>,
}

/// Total number of `(mxid, device)` pairs a `/keys/claim` request asks for —
/// the cost charged against
/// [`mylittlechart_server::live::ClaimRateLimiter`] (plan P9 brief: "≤ 100
/// device claims / minute per caller").
fn count_claim_targets(requested: &BTreeMap<String, BTreeMap<String, String>>) -> usize {
    requested.values().map(BTreeMap::len).sum()
}

/// DB-only core for `POST /keys/claim` (plan P9 brief): per requested
/// `(mxid, device, algorithm)`, claims one OTK (or a reusable fallback) —
/// restricted to the SAME share-a-room set as `/keys/query` — silently
/// omitting any device that yields nothing (no such device, no keys left) or
/// any user this caller may not see.
fn build_keys_claim_response(conn: &mut Connection, caller_user_id: i64, requested: &BTreeMap<String, BTreeMap<String, String>>) -> Result<serde_json::Value, MatrixError> {
    let visible = peers_sharing_a_room_with(conn, caller_user_id)?;
    let mut out = serde_json::Map::new();

    for (mxid, per_device) in requested {
        let Some(target_user_id) = matrix_store::user_id_of(conn, mxid)?.filter(|uid| visible.contains(uid)) else {
            continue;
        };
        let mut devices_out = serde_json::Map::new();
        for (device_id, algorithm) in per_device {
            let Some((key_id, key_json)) = matrix_keys_store::claim_one_time_key(conn, target_user_id, device_id, algorithm)? else {
                continue;
            };
            let value: serde_json::Value = serde_json::from_str(&key_json)?;
            devices_out.insert(device_id.clone(), serde_json::json!({ key_id: value }));
        }
        if !devices_out.is_empty() {
            out.insert(mxid.clone(), serde_json::Value::Object(devices_out));
        }
    }

    Ok(serde_json::json!({ "one_time_keys": out, "failures": {} }))
}

async fn keys_claim(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(request): Json<KeysClaimRequest>) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;

    let cost = count_claim_targets(&request.one_time_keys) as f64;
    let allowed = state.control_plane().matrix_claim_rate_limiter.try_consume(caller.user_id, cost, Instant::now());
    if !allowed {
        return Err(MatrixError::limit_exceeded(60_000));
    }

    let response = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
        let cp = state.control_plane();
        let mut messenger_conn = cp.messenger_conn();
        build_keys_claim_response(&mut messenger_conn, caller.user_id, &request.one_time_keys)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(response))
}

// ============================================================================
// GET /_matrix/client/v3/keys/changes
// ============================================================================

#[derive(serde::Deserialize, Default)]
struct KeysChangesQuery {
    from: Option<String>,
    to: Option<String>,
}

/// DB-only core for `GET /keys/changes` (plan §3.7 / P9 brief): device-list
/// changes in `(from, to]` filtered to users the caller currently shares a
/// joined room with (`changed`), plus every user whose `m.room.member`
/// transitioned to `leave`/`ban` in a room the caller is/was part of AND who
/// no longer shares ANY joined room with the caller today (`left`).
fn build_keys_changes_response(conn: &Connection, caller_user_id: i64, from_exclusive: i64, to_inclusive: i64) -> Result<serde_json::Value, MatrixError> {
    let visible = peers_sharing_a_room_with(conn, caller_user_id)?;

    let mut changed = Vec::new();
    for user_id in matrix_keys_store::device_list_changes_between(conn, from_exclusive, to_inclusive)? {
        if visible.contains(&user_id) {
            if let Some(mxid) = matrix_store::mxid_of(conn, user_id)? {
                changed.push(mxid);
            }
        }
    }

    let caller_rooms = matrix_store::rooms_for_user(conn, caller_user_id, None)?;
    let mut left = Vec::new();
    for user_id in matrix_store::user_ids_with_leave_transition_in_rooms(conn, &caller_rooms, from_exclusive, to_inclusive)? {
        if !visible.contains(&user_id) {
            if let Some(mxid) = matrix_store::mxid_of(conn, user_id)? {
                left.push(mxid);
            }
        }
    }

    changed.sort();
    changed.dedup();
    left.sort();
    left.dedup();

    Ok(serde_json::json!({ "changed": changed, "left": left }))
}

async fn keys_changes(State(state): State<Arc<AppState>>, headers: HeaderMap, Query(query): Query<KeysChangesQuery>) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let from = sync_token::parse(query.from.as_deref().ok_or_else(|| MatrixError::invalid_param("from is required"))?)?.stream_id;
    let to = sync_token::parse(query.to.as_deref().ok_or_else(|| MatrixError::invalid_param("to is required"))?)?.stream_id;

    let response = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
        let cp = state.control_plane();
        let messenger_conn = cp.messenger_conn();
        build_keys_changes_response(&messenger_conn, caller.user_id, from, to)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(response))
}

// ============================================================================
// POST /_matrix/client/v3/keys/device_signing/upload
// ============================================================================

#[derive(serde::Deserialize, Default)]
struct DeviceSigningUploadRequest {
    #[serde(default)]
    master_key: Option<serde_json::Value>,
    #[serde(default)]
    self_signing_key: Option<serde_json::Value>,
    #[serde(default)]
    user_signing_key: Option<serde_json::Value>,
}

/// Extract the single `ed25519:<key_id>` entry from a cross-signing key
/// object's `keys` map (Matrix's cross-signing keys always carry exactly
/// one) — `(key_id, decoded 32-byte verifying key)`.
fn master_verifying_key(master_key_object: &serde_json::Value) -> Result<(String, VerifyingKey), MatrixError> {
    let keys = master_key_object
        .get("keys")
        .and_then(|v| v.as_object())
        .ok_or_else(|| MatrixError::invalid_param("master_key.keys missing"))?;
    let (full_key_id, value) = keys
        .iter()
        .find(|(k, _)| k.starts_with("ed25519:"))
        .ok_or_else(|| MatrixError::invalid_param("master_key has no ed25519 key"))?;
    let key_id = full_key_id.trim_start_matches("ed25519:").to_string();
    let b64 = value.as_str().ok_or_else(|| MatrixError::invalid_param("master_key.keys value must be a string"))?;
    let bytes = STANDARD_NO_PAD.decode(b64).map_err(|_| MatrixError::invalid_param("master_key public key is not valid base64"))?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| MatrixError::invalid_param("master_key public key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&array).map_err(|_| MatrixError::invalid_param("master_key is not a valid ed25519 key"))?;
    Ok((key_id, verifying_key))
}

/// Matrix canonical JSON (RFC 8259 subset: sorted keys, no insignificant
/// whitespace) of `value` with `signatures`/`unsigned` stripped — the exact
/// bytes a client signs when producing a cross-signing signature.
/// `serde_json::Value::Object` is backed by a `BTreeMap` everywhere in this
/// workspace (no `preserve_order` feature enabled anywhere in the dependency
/// graph — `Cargo.toml`), so keys are already sorted at every nesting level,
/// and its compact `to_string` emits no insignificant whitespace and leaves
/// non-ASCII UTF-8 unescaped — together already exactly canonical JSON's
/// shape, with no extra re-serialization step needed beyond stripping the
/// two keys.
fn canonical_json_without_signatures(value: &serde_json::Value) -> String {
    let mut stripped = value.clone();
    if let Some(obj) = stripped.as_object_mut() {
        obj.remove("signatures");
        obj.remove("unsigned");
    }
    stripped.to_string()
}

/// Verify that `target_key_object` (a `self_signing_key`/`user_signing_key`
/// upload) carries a valid ed25519 signature by `master_key_object`'s own
/// key, filed under `signatures[caller_mxid]["ed25519:<master_key_id>"]` —
/// Matrix's own cross-signing trust chain (plan P9 brief: "verify with
/// ed25519 over canonical JSON").
fn verify_signed_by_master(target_key_object: &serde_json::Value, caller_mxid: &str, master_key_object: &serde_json::Value) -> Result<(), MatrixError> {
    let (master_key_id, verifying_key) = master_verifying_key(master_key_object)?;
    let signature_b64 = target_key_object
        .get("signatures")
        .and_then(|s| s.get(caller_mxid))
        .and_then(|by_user| by_user.get(format!("ed25519:{master_key_id}").as_str()))
        .and_then(|v| v.as_str())
        .ok_or_else(|| MatrixError::invalid_param("missing signature by the master key"))?;
    let sig_bytes = STANDARD_NO_PAD.decode(signature_b64).map_err(|_| MatrixError::invalid_param("signature is not valid base64"))?;
    let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| MatrixError::invalid_param("signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_array);
    let message = canonical_json_without_signatures(target_key_object);
    verifying_key
        .verify_strict(message.as_bytes(), &signature)
        .map_err(|_| MatrixError::invalid_param("signature does not verify against the master key"))
}

/// `user_id`/`usage` shape validation shared by all three cross-signing key
/// kinds (plan P9 brief).
fn validate_cross_signing_key_object(value: &serde_json::Value, caller_mxid: &str, expected_usage: &str) -> Result<(), MatrixError> {
    let obj = value.as_object().ok_or_else(|| MatrixError::invalid_param("cross-signing key must be an object"))?;
    if obj.get("user_id").and_then(|v| v.as_str()) != Some(caller_mxid) {
        return Err(MatrixError::invalid_param("cross-signing key user_id must be the caller"));
    }
    let usage = obj.get("usage").and_then(|v| v.as_array()).ok_or_else(|| MatrixError::invalid_param("cross-signing key missing usage"))?;
    if usage.len() != 1 || usage[0].as_str() != Some(expected_usage) {
        return Err(MatrixError::invalid_param(format!("cross-signing key usage must be exactly [\"{expected_usage}\"]")));
    }
    if !obj.get("keys").and_then(|v| v.as_object()).is_some_and(|k| !k.is_empty()) {
        return Err(MatrixError::invalid_param("cross-signing key missing keys"));
    }
    Ok(())
}

/// DB-only core for `POST /keys/device_signing/upload` (plan P9 brief):
/// validates each provided key object's shape/ownership, verifies
/// self_signing/user_signing against the master key (freshly uploaded in
/// this SAME call, or the caller's existing one), and stores whatever was
/// provided. No UIA (single factor, matches every other route in this
/// tree). Replacing an existing master key is allowed (user reset). Returns
/// whether anything was actually written — the caller only wakes peers when
/// it did.
fn apply_device_signing_upload(conn: &mut Connection, caller_user_id: i64, caller_mxid: &str, request: &DeviceSigningUploadRequest, now: &str) -> Result<bool, MatrixError> {
    if let Some(master) = &request.master_key {
        validate_cross_signing_key_object(master, caller_mxid, "master")?;
    }
    let master_for_verification: Option<serde_json::Value> = match &request.master_key {
        Some(master) => Some(master.clone()),
        None => matrix_keys_store::cross_signing_key_for(conn, caller_user_id, CrossSigningUsage::Master)?
            .map(|row| serde_json::from_str(&row.key_json))
            .transpose()?,
    };

    if let Some(self_signing) = &request.self_signing_key {
        validate_cross_signing_key_object(self_signing, caller_mxid, "self_signing")?;
        let master = master_for_verification
            .as_ref()
            .ok_or_else(|| MatrixError::invalid_param("no master key on file to verify self_signing_key against"))?;
        verify_signed_by_master(self_signing, caller_mxid, master)?;
    }
    if let Some(user_signing) = &request.user_signing_key {
        validate_cross_signing_key_object(user_signing, caller_mxid, "user_signing")?;
        let master = master_for_verification
            .as_ref()
            .ok_or_else(|| MatrixError::invalid_param("no master key on file to verify user_signing_key against"))?;
        verify_signed_by_master(user_signing, caller_mxid, master)?;
    }

    let mut wrote = false;
    if let Some(master) = &request.master_key {
        matrix_keys_store::upsert_cross_signing_key(conn, caller_user_id, CrossSigningUsage::Master, &master.to_string(), now)?;
        wrote = true;
    }
    if let Some(self_signing) = &request.self_signing_key {
        matrix_keys_store::upsert_cross_signing_key(conn, caller_user_id, CrossSigningUsage::SelfSigning, &self_signing.to_string(), now)?;
        wrote = true;
    }
    if let Some(user_signing) = &request.user_signing_key {
        matrix_keys_store::upsert_cross_signing_key(conn, caller_user_id, CrossSigningUsage::UserSigning, &user_signing.to_string(), now)?;
        wrote = true;
    }
    Ok(wrote)
}

async fn device_signing_upload(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(request): Json<DeviceSigningUploadRequest>) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let state_for_blocking = state.clone();

    let wake_ids = tokio::task::spawn_blocking(move || -> Result<Option<HashSet<i64>>, MatrixError> {
        let cp = state_for_blocking.control_plane();
        let now = chrono::Utc::now().to_rfc3339();
        let mut messenger_conn = cp.messenger_conn();
        let wrote = apply_device_signing_upload(&mut messenger_conn, caller.user_id, &caller.mxid, &request, &now)?;
        if wrote {
            Ok(Some(peers_sharing_a_room_with(&messenger_conn, caller.user_id)?))
        } else {
            Ok(None)
        }
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    if let Some(wake_ids) = wake_ids {
        state.control_plane().live.wake_many(wake_ids.into_iter().map(|id| format!("user:{id}")));
    }
    Ok(Json(serde_json::json!({})))
}

// ============================================================================
// POST /_matrix/client/v3/keys/signatures/upload
// ============================================================================

/// Whether `user_id`'s master cross-signing key names `local_id` as one of
/// its own `ed25519:<local_id>` entries — the user-signing case's
/// authorization check (plan P9 brief: "target must be ... another user's
/// master key").
fn master_key_names_local_id(conn: &Connection, user_id: i64, local_id: &str) -> Result<bool, MatrixError> {
    let Some(row) = matrix_keys_store::cross_signing_key_for(conn, user_id, CrossSigningUsage::Master)? else {
        return Ok(false);
    };
    let value: serde_json::Value = serde_json::from_str(&row.key_json)?;
    let Some(keys) = value.get("keys").and_then(|k| k.as_object()) else {
        return Ok(false);
    };
    Ok(keys.keys().any(|k| k.trim_start_matches("ed25519:") == local_id))
}

/// Whether any of `user_id`'s own cross-signing keys names `local_id` — part
/// of the self-signing case's authorization check (plan P9 brief: "target
/// must be the caller's own device/keys").
fn cross_signing_key_names_local_id(conn: &Connection, user_id: i64, local_id: &str) -> Result<bool, MatrixError> {
    for usage in [CrossSigningUsage::Master, CrossSigningUsage::SelfSigning, CrossSigningUsage::UserSigning] {
        let Some(row) = matrix_keys_store::cross_signing_key_for(conn, user_id, usage)? else {
            continue;
        };
        let value: serde_json::Value = serde_json::from_str(&row.key_json)?;
        if let Some(keys) = value.get("keys").and_then(|k| k.as_object()) {
            if keys.keys().any(|k| k.trim_start_matches("ed25519:") == local_id) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Whether `caller_mxid` may file a signature against `(target_user_id,
/// target_key_id)` (plan P9 brief: "the signer must be the caller; target
/// must be the caller's own device/keys or (for user-signing) another
/// user's master key"). This endpoint never verifies the signature bytes
/// themselves — only this authorization shape — matching
/// `matrix_keys_store::cross_signing_signatures`'s own "opaque, never
/// verified" contract (the one deliberate exception in this module is
/// `/keys/device_signing/upload`'s master-key check, scoped to that
/// endpoint alone — see this module's own doc).
fn signature_target_is_authorized(conn: &Connection, caller_mxid: &str, target_mxid: &str, target_user_id: i64, target_key_id: &str) -> Result<bool, MatrixError> {
    if target_mxid == caller_mxid {
        Ok(matrix_keys_store::get_device(conn, target_user_id, target_key_id)?.is_some() || cross_signing_key_names_local_id(conn, target_user_id, target_key_id)?)
    } else {
        master_key_names_local_id(conn, target_user_id, target_key_id)
    }
}

/// DB-only core for `POST /keys/signatures/upload`: per submitted
/// `(target_user, target_key_id)` pair, checks
/// [`signature_target_is_authorized`] and stores the whole submitted value
/// opaquely on success ([`matrix_keys_store::add_signatures`]), or files a
/// per-entry `M_INVALID_PARAM` failure. Returns the `failures` map (empty on
/// full success).
fn apply_signatures_upload(conn: &mut Connection, caller_user_id: i64, caller_mxid: &str, body: &serde_json::Map<String, serde_json::Value>, now: &str) -> Result<serde_json::Value, MatrixError> {
    let mut failures = serde_json::Map::new();
    for (target_mxid, per_key) in body {
        let Some(per_key_obj) = per_key.as_object() else { continue };
        let mut user_failures = serde_json::Map::new();
        let target_user_id = matrix_store::user_id_of(conn, target_mxid)?;

        for (target_key_id, signed_value) in per_key_obj {
            let authorized = match target_user_id {
                Some(target_user_id) => signature_target_is_authorized(conn, caller_mxid, target_mxid, target_user_id, target_key_id)?,
                None => false,
            };
            if !authorized {
                user_failures.insert(
                    target_key_id.clone(),
                    serde_json::json!({ "errcode": "M_INVALID_PARAM", "error": "signature target not permitted" }),
                );
                continue;
            }
            let target_user_id = target_user_id.ok_or_else(MatrixError::internal)?;
            matrix_keys_store::add_signatures(conn, &[(caller_user_id, target_user_id, target_key_id.clone(), signed_value.to_string(), now.to_string())])?;
        }
        if !user_failures.is_empty() {
            failures.insert(target_mxid.clone(), serde_json::Value::Object(user_failures));
        }
    }
    Ok(serde_json::Value::Object(failures))
}

async fn signatures_upload(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let body_obj = body.as_object().cloned().ok_or_else(|| MatrixError::invalid_param("body must be an object"))?;

    let failures = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
        let cp = state.control_plane();
        let mut messenger_conn = cp.messenger_conn();
        let now = chrono::Utc::now().to_rfc3339();
        apply_signatures_upload(&mut messenger_conn, caller.user_id, &caller.mxid, &body_obj, &now)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(serde_json::json!({ "failures": failures })))
}

// ============================================================================
// PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId}
// ============================================================================

#[derive(serde::Deserialize)]
struct SendToDeviceRequest {
    messages: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
}

/// Resolve `messages` into a flat per-device list, expanding `"*"` to every
/// current device of that recipient (an explicit device entry for the same
/// recipient always overrides the wildcard's content for that one device,
/// never both delivered) and dropping — silently, per this module's own
/// documented policy ("no enumeration via to-device") — any recipient who
/// does not share a joined room with the sender and is not the sender
/// themself. Enforces the per-content-size cap up front; the per-request
/// device-count cap is enforced once, after expansion (a caller mistake,
/// refused outright — unlike the stranger case, a cap violation is
/// unambiguous and refusing it leaks nothing a working client didn't already
/// know about its own request).
fn expand_send_to_device_targets(conn: &Connection, sender_user_id: i64, messages: &BTreeMap<String, BTreeMap<String, serde_json::Value>>) -> Result<Vec<(i64, String, String)>, MatrixError> {
    let visible = peers_sharing_a_room_with(conn, sender_user_id)?;
    let mut targets = Vec::new();

    for (mxid, per_device) in messages {
        let Some(recipient_user_id) = matrix_store::user_id_of(conn, mxid)?.filter(|uid| visible.contains(uid)) else {
            continue;
        };

        let mut per_recipient: HashMap<String, String> = HashMap::new();
        if let Some(wildcard_content) = per_device.get("*") {
            let content_str = wildcard_content.to_string();
            if content_str.len() > SEND_TO_DEVICE_MAX_CONTENT_BYTES {
                return Err(MatrixError::bad_json("to-device content too large"));
            }
            for device in matrix_keys_store::list_devices(conn, recipient_user_id)? {
                per_recipient.insert(device.device_id, content_str.clone());
            }
        }
        for (device_selector, content) in per_device {
            if device_selector == "*" {
                continue;
            }
            let content_str = content.to_string();
            if content_str.len() > SEND_TO_DEVICE_MAX_CONTENT_BYTES {
                return Err(MatrixError::bad_json("to-device content too large"));
            }
            per_recipient.insert(device_selector.clone(), content_str);
        }

        for (device_id, content_str) in per_recipient {
            targets.push((recipient_user_id, device_id, content_str));
        }
    }

    if targets.len() > SEND_TO_DEVICE_MAX_TARGETS {
        return Err(MatrixError::invalid_param("too many target devices in one call"));
    }
    Ok(targets)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SendToDeviceOutcome {
    New(HashSet<i64>),
    AlreadySent,
}

/// DB-only core for `PUT /sendToDevice/{eventType}/{txnId}`: txn-deduped per
/// `(sender_user_id, sender_device_id, txn_id)` — a repeat is a no-op — then
/// [`expand_send_to_device_targets`] and one atomic dedup-checked enqueue
/// ([`matrix_keys_store::enqueue_to_device_deduped`]).
fn apply_send_to_device(
    conn: &mut Connection,
    sender_user_id: i64,
    sender_device_id: &str,
    event_type: &str,
    txn_id: &str,
    messages: &BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    now: &str,
) -> Result<SendToDeviceOutcome, MatrixError> {
    if let TxnDedupEntry::Seen(_) = matrix_store::txn_dedup_lookup(conn, sender_user_id, sender_device_id, txn_id)? {
        return Ok(SendToDeviceOutcome::AlreadySent);
    }
    let targets = expand_send_to_device_targets(conn, sender_user_id, messages)?;
    let wake_ids: HashSet<i64> = targets.iter().map(|(uid, ..)| *uid).collect();
    let rows: Vec<(i64, String, String, String)> = targets.into_iter().map(|(uid, dev, content)| (uid, dev, event_type.to_string(), content)).collect();

    match matrix_keys_store::enqueue_to_device_deduped(conn, sender_user_id, sender_device_id, txn_id, &rows, now)? {
        matrix_keys_store::ToDeviceDedupOutcome::New => Ok(SendToDeviceOutcome::New(wake_ids)),
        matrix_keys_store::ToDeviceDedupOutcome::AlreadySent => Ok(SendToDeviceOutcome::AlreadySent),
    }
}

async fn send_to_device(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((event_type, txn_id)): Path<(String, String)>,
    Json(body): Json<SendToDeviceRequest>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let state_for_blocking = state.clone();
    let device_id = caller.device_id.clone();

    let wake_ids = tokio::task::spawn_blocking(move || -> Result<HashSet<i64>, MatrixError> {
        let cp = state_for_blocking.control_plane();
        let now = chrono::Utc::now().to_rfc3339();
        let mut messenger_conn = cp.messenger_conn();
        match apply_send_to_device(&mut messenger_conn, caller.user_id, &device_id, &event_type, &txn_id, &body.messages, &now)? {
            SendToDeviceOutcome::New(wake_ids) => Ok(wake_ids),
            SendToDeviceOutcome::AlreadySent => Ok(HashSet::new()),
        }
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    if !wake_ids.is_empty() {
        state.control_plane().live.wake_many(wake_ids.into_iter().map(|id| format!("user:{id}")));
    }
    Ok(Json(serde_json::json!({})))
}

// ============================================================================
// Devices: GET/DELETE_devices, GET/PUT/DELETE devices/{id}, POST delete_devices
// ============================================================================

#[derive(serde::Deserialize, Default)]
struct PutDeviceRequest {
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(serde::Deserialize)]
struct DeleteDevicesRequest {
    devices: Vec<String>,
}

fn device_to_json(device: &matrix_keys_store::Device) -> serde_json::Value {
    let last_seen_ts = chrono::DateTime::parse_from_rfc3339(&device.last_seen_at).ok().map(|dt| dt.timestamp_millis());
    serde_json::json!({
        "device_id": device.device_id,
        "display_name": device.display_name,
        "last_seen_ts": last_seen_ts,
    })
}

async fn list_devices_route(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let devices = tokio::task::spawn_blocking(move || -> Result<Vec<serde_json::Value>, MatrixError> {
        let cp = state.control_plane();
        let conn = cp.messenger_conn();
        Ok(matrix_keys_store::list_devices(&conn, caller.user_id)?.iter().map(device_to_json).collect())
    })
    .await
    .map_err(|_| MatrixError::internal())??;
    Ok(Json(serde_json::json!({ "devices": devices })))
}

async fn get_device_route(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(device_id): Path<String>) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let device = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
        let cp = state.control_plane();
        let conn = cp.messenger_conn();
        let device = matrix_keys_store::get_device(&conn, caller.user_id, &device_id)?.ok_or_else(|| MatrixError::not_found("no such device"))?;
        Ok(device_to_json(&device))
    })
    .await
    .map_err(|_| MatrixError::internal())??;
    Ok(Json(device))
}

async fn put_device_route(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Json(body): Json<PutDeviceRequest>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let updated = tokio::task::spawn_blocking(move || -> Result<bool, MatrixError> {
        let cp = state.control_plane();
        let conn = cp.messenger_conn();
        Ok(matrix_keys_store::set_device_display_name(&conn, caller.user_id, &device_id, body.display_name.as_deref())?)
    })
    .await
    .map_err(|_| MatrixError::internal())??;
    if !updated {
        return Err(MatrixError::not_found("no such device"));
    }
    Ok(Json(serde_json::json!({})))
}

/// The manual "log out this device" core (plan P9 brief): revoke the
/// identity-side credential FIRST ([`auth::revoke_identity_credential`]),
/// then the messenger-side device/keys/device-list-change/wake
/// ([`auth::on_credential_revoked`], reusing the exact P4 revoke path).
/// Returns whether `device_id` existed and belonged to `caller_user_id`.
fn apply_delete_device(
    identity_conn: &Connection,
    messenger_conn: &mut Connection,
    live: &mylittlechart_server::live::LiveRegistry,
    caller_user_id: i64,
    device_id: &str,
    now: &str,
) -> Result<bool, MatrixError> {
    let Some(device) = matrix_keys_store::get_device(messenger_conn, caller_user_id, device_id)? else {
        return Ok(false);
    };
    auth::revoke_identity_credential(identity_conn, device.credential_kind, &device.credential_ref)?;
    auth::on_credential_revoked(messenger_conn, live, device.credential_kind, &device.credential_ref, now)?;
    Ok(true)
}

async fn delete_device_route(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(device_id): Path<String>) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let deleted = tokio::task::spawn_blocking(move || -> Result<bool, MatrixError> {
        let cp = state.control_plane();
        let now = chrono::Utc::now().to_rfc3339();
        let identity_conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
        let mut messenger_conn = cp.messenger_conn();
        apply_delete_device(&identity_conn, &mut messenger_conn, &cp.live, caller.user_id, &device_id, &now)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    if !deleted {
        return Err(MatrixError::not_found("no such device"));
    }
    Ok(Json(serde_json::json!({})))
}

async fn bulk_delete_devices(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<DeleteDevicesRequest>) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    tokio::task::spawn_blocking(move || -> Result<(), MatrixError> {
        let cp = state.control_plane();
        let now = chrono::Utc::now().to_rfc3339();
        let identity_conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
        let mut messenger_conn = cp.messenger_conn();
        for device_id in &body.devices {
            apply_delete_device(&identity_conn, &mut messenger_conn, &cp.live, caller.user_id, device_id, &now)?;
        }
        Ok(())
    })
    .await
    .map_err(|_| MatrixError::internal())??;
    Ok(Json(serde_json::json!({})))
}

// ============================================================================
// Key backup: room_keys/version[/{version}]
// ============================================================================

#[derive(serde::Deserialize)]
struct BackupVersionCreateRequest {
    algorithm: String,
    auth_data: serde_json::Value,
}

#[derive(serde::Deserialize)]
struct BackupVersionUpdateRequest {
    #[serde(default)]
    algorithm: Option<String>,
    auth_data: serde_json::Value,
}

/// Refuse anything but this server's one symmetric key-backup algorithm
/// (plan P9 brief, MSC3270 naming) — `m.megolm_backup.v1.curve25519-aes-sha2`
/// (the PkEncryption backup) is refused outright.
fn validate_backup_algorithm(algorithm: &str) -> Result<(), MatrixError> {
    if algorithm == BACKUP_ALGORITHM {
        Ok(())
    } else {
        Err(MatrixError::invalid_param(format!("unsupported key-backup algorithm: {algorithm}")))
    }
}

fn backup_version_to_response(row: &matrix_keys_store::KeyBackupVersion, count: i64) -> Result<serde_json::Value, MatrixError> {
    Ok(serde_json::json!({
        "version": row.version.to_string(),
        "algorithm": row.algorithm,
        "auth_data": serde_json::from_str::<serde_json::Value>(&row.auth_data)?,
        "etag": row.etag.to_string(),
        "count": count,
    }))
}

async fn post_backup_version(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<BackupVersionCreateRequest>) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    validate_backup_algorithm(&body.algorithm)?;

    let version = tokio::task::spawn_blocking(move || -> Result<i64, MatrixError> {
        let cp = state.control_plane();
        let conn = cp.messenger_conn();
        let now = chrono::Utc::now().to_rfc3339();
        Ok(matrix_keys_store::create_backup_version(&conn, caller.user_id, &body.algorithm, &body.auth_data.to_string(), &now)?)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(serde_json::json!({ "version": version.to_string() })))
}

async fn get_current_backup_version(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let response = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
        let cp = state.control_plane();
        let conn = cp.messenger_conn();
        let row = matrix_keys_store::current_backup_version(&conn, caller.user_id)?.ok_or_else(|| MatrixError::not_found("no key backup exists"))?;
        let (count, _) = matrix_keys_store::backup_count_and_etag(&conn, caller.user_id, row.version)?;
        backup_version_to_response(&row, count)
    })
    .await
    .map_err(|_| MatrixError::internal())??;
    Ok(Json(response))
}

async fn get_backup_version_route(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(version): Path<String>) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let version = version.parse::<i64>().map_err(|_| MatrixError::invalid_param("version must be an integer"))?;
    let response = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
        let cp = state.control_plane();
        let conn = cp.messenger_conn();
        let row = matrix_keys_store::get_backup_version(&conn, caller.user_id, version)?
            .filter(|r| !r.is_deleted)
            .ok_or_else(|| MatrixError::not_found("no such backup version"))?;
        let (count, _) = matrix_keys_store::backup_count_and_etag(&conn, caller.user_id, version)?;
        backup_version_to_response(&row, count)
    })
    .await
    .map_err(|_| MatrixError::internal())??;
    Ok(Json(response))
}

async fn put_backup_version_route(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(version): Path<String>,
    Json(body): Json<BackupVersionUpdateRequest>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let version = version.parse::<i64>().map_err(|_| MatrixError::invalid_param("version must be an integer"))?;

    tokio::task::spawn_blocking(move || -> Result<(), MatrixError> {
        let cp = state.control_plane();
        let conn = cp.messenger_conn();
        let existing = matrix_keys_store::get_backup_version(&conn, caller.user_id, version)?
            .filter(|r| !r.is_deleted)
            .ok_or_else(|| MatrixError::not_found("no such backup version"))?;
        if let Some(algorithm) = &body.algorithm {
            if algorithm != &existing.algorithm {
                return Err(MatrixError::invalid_param("a backup version's algorithm cannot change"));
            }
        }
        matrix_keys_store::update_backup_version_auth_data(&conn, caller.user_id, version, &body.auth_data.to_string())?;
        Ok(())
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(serde_json::json!({})))
}

async fn delete_backup_version_route(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(version): Path<String>) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let version = version.parse::<i64>().map_err(|_| MatrixError::invalid_param("version must be an integer"))?;

    let deleted = tokio::task::spawn_blocking(move || -> Result<bool, MatrixError> {
        let cp = state.control_plane();
        let conn = cp.messenger_conn();
        Ok(matrix_keys_store::delete_backup_version(&conn, caller.user_id, version)?)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    if !deleted {
        return Err(MatrixError::not_found("no such backup version"));
    }
    Ok(Json(serde_json::json!({})))
}

// ============================================================================
// Key backup: room_keys/keys[/{roomId}[/{sessionId}]]
// ============================================================================

#[derive(serde::Deserialize, Default)]
struct VersionQuery {
    version: Option<String>,
}

fn parse_required_version(raw: Option<&str>) -> Result<i64, MatrixError> {
    let raw = raw.ok_or_else(|| MatrixError::invalid_param("version is required"))?;
    raw.parse::<i64>().map_err(|_| MatrixError::invalid_param("version must be an integer"))
}

/// `?version=` must name the caller's CURRENT (non-deleted) backup version —
/// plan P9 brief: "wrong/stale version → 403 M_WRONG_ROOM_KEYS_VERSION with
/// current_version". Applies uniformly to GET/PUT/DELETE
/// `room_keys/keys[...]`.
fn require_current_backup_version(conn: &Connection, user_id: i64, requested_version: i64) -> Result<(), MatrixError> {
    let current = matrix_keys_store::current_backup_version(conn, user_id)?;
    match current {
        Some(row) if row.version == requested_version => Ok(()),
        Some(row) => Err(MatrixError::wrong_room_keys_version(Some(row.version))),
        None => Err(MatrixError::wrong_room_keys_version(None)),
    }
}

/// Normalize the three `PUT room_keys/keys[...]` body shapes into a flat
/// `(room_id, session_id, session_data_json)` list — `session_data_json` is
/// the WHOLE submitted `KeyBackupData` object (opaque to this server, see
/// `matrix_keys_store::key_backup_sessions.session_data`'s own doc), not
/// just its inner `session_data` field.
fn normalize_put_backup_body(room_id: Option<&str>, session_id: Option<&str>, body: &serde_json::Value) -> Result<Vec<(String, String, String)>, MatrixError> {
    match (room_id, session_id) {
        (Some(room_id), Some(session_id)) => Ok(vec![(room_id.to_string(), session_id.to_string(), body.to_string())]),
        (Some(room_id), None) => {
            let sessions = body
                .get("sessions")
                .and_then(|v| v.as_object())
                .ok_or_else(|| MatrixError::invalid_param("body must have a sessions object"))?;
            Ok(sessions.iter().map(|(sid, data)| (room_id.to_string(), sid.clone(), data.to_string())).collect())
        }
        (None, _) => {
            let rooms = body
                .get("rooms")
                .and_then(|v| v.as_object())
                .ok_or_else(|| MatrixError::invalid_param("body must have a rooms object"))?;
            let mut out = Vec::new();
            for (rid, room_value) in rooms {
                let sessions = room_value
                    .get("sessions")
                    .and_then(|v| v.as_object())
                    .ok_or_else(|| MatrixError::invalid_param("each room must have a sessions object"))?;
                for (sid, data) in sessions {
                    out.push((rid.clone(), sid.clone(), data.to_string()));
                }
            }
            Ok(out)
        }
    }
}

/// Shape a batch of stored [`matrix_keys_store::KeyBackupSession`] rows into
/// the GET response's three tiers.
fn backup_sessions_to_response(room_id: Option<&str>, session_id: Option<&str>, sessions: Vec<matrix_keys_store::KeyBackupSession>) -> Result<serde_json::Value, MatrixError> {
    match (room_id, session_id) {
        (Some(_), Some(_)) => {
            let one = sessions.into_iter().next().ok_or_else(|| MatrixError::not_found("no such backup session"))?;
            Ok(serde_json::from_str(&one.session_data)?)
        }
        (Some(_), None) => {
            let mut sessions_out = serde_json::Map::new();
            for s in sessions {
                sessions_out.insert(s.session_id.clone(), serde_json::from_str(&s.session_data)?);
            }
            Ok(serde_json::json!({ "sessions": sessions_out }))
        }
        (None, _) => {
            let mut rooms_out = serde_json::Map::new();
            for s in sessions {
                let room_entry = rooms_out.entry(s.room_id.clone()).or_insert_with(|| serde_json::json!({ "sessions": {} }));
                room_entry["sessions"][s.session_id.as_str()] = serde_json::from_str(&s.session_data)?;
            }
            Ok(serde_json::json!({ "rooms": rooms_out }))
        }
    }
}

async fn get_backup_keys_inner(
    state: Arc<AppState>,
    headers: HeaderMap,
    room_id: Option<String>,
    session_id: Option<String>,
    version_query: VersionQuery,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let version = parse_required_version(version_query.version.as_deref())?;

    let response = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
        let cp = state.control_plane();
        let messenger_conn = cp.messenger_conn();
        require_current_backup_version(&messenger_conn, caller.user_id, version)?;
        let sessions = matrix_keys_store::get_backup_sessions(&messenger_conn, caller.user_id, version, room_id.as_deref(), session_id.as_deref())?;
        backup_sessions_to_response(room_id.as_deref(), session_id.as_deref(), sessions)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(response))
}

async fn get_backup_keys_all(State(state): State<Arc<AppState>>, headers: HeaderMap, Query(q): Query<VersionQuery>) -> Result<impl IntoResponse, MatrixError> {
    get_backup_keys_inner(state, headers, None, None, q).await
}

async fn get_backup_keys_room(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Query(q): Query<VersionQuery>,
) -> Result<impl IntoResponse, MatrixError> {
    get_backup_keys_inner(state, headers, Some(room_id), None, q).await
}

async fn get_backup_keys_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((room_id, session_id)): Path<(String, String)>,
    Query(q): Query<VersionQuery>,
) -> Result<impl IntoResponse, MatrixError> {
    get_backup_keys_inner(state, headers, Some(room_id), Some(session_id), q).await
}

async fn put_backup_keys_inner(
    state: Arc<AppState>,
    headers: HeaderMap,
    room_id: Option<String>,
    session_id: Option<String>,
    version_query: VersionQuery,
    body: serde_json::Value,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let version = parse_required_version(version_query.version.as_deref())?;
    let sessions = normalize_put_backup_body(room_id.as_deref(), session_id.as_deref(), &body)?;

    let response = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
        let cp = state.control_plane();
        let mut messenger_conn = cp.messenger_conn();
        let now = chrono::Utc::now().to_rfc3339();
        match matrix_keys_store::put_backup_sessions(&mut messenger_conn, caller.user_id, version, &sessions, &now) {
            Ok(()) => {}
            Err(matrix_keys_store::MatrixKeysStoreError::WrongBackupVersion) => {
                let current = matrix_keys_store::current_backup_version(&messenger_conn, caller.user_id)?;
                return Err(MatrixError::wrong_room_keys_version(current.map(|v| v.version)));
            }
            Err(e) => return Err(e.into()),
        }
        let (count, etag) = matrix_keys_store::backup_count_and_etag(&messenger_conn, caller.user_id, version)?;
        Ok(serde_json::json!({ "etag": etag.to_string(), "count": count }))
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(response))
}

async fn put_backup_keys_all(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<VersionQuery>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, MatrixError> {
    put_backup_keys_inner(state, headers, None, None, q, body).await
}

async fn put_backup_keys_room(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Query(q): Query<VersionQuery>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, MatrixError> {
    put_backup_keys_inner(state, headers, Some(room_id), None, q, body).await
}

async fn put_backup_keys_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((room_id, session_id)): Path<(String, String)>,
    Query(q): Query<VersionQuery>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, MatrixError> {
    put_backup_keys_inner(state, headers, Some(room_id), Some(session_id), q, body).await
}

async fn delete_backup_keys_inner(
    state: Arc<AppState>,
    headers: HeaderMap,
    room_id: Option<String>,
    session_id: Option<String>,
    version_query: VersionQuery,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let version = parse_required_version(version_query.version.as_deref())?;

    let response = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
        let cp = state.control_plane();
        let mut messenger_conn = cp.messenger_conn();
        require_current_backup_version(&messenger_conn, caller.user_id, version)?;
        matrix_keys_store::delete_backup_sessions(&mut messenger_conn, caller.user_id, version, room_id.as_deref(), session_id.as_deref())?;
        let (count, etag) = matrix_keys_store::backup_count_and_etag(&messenger_conn, caller.user_id, version)?;
        Ok(serde_json::json!({ "etag": etag.to_string(), "count": count }))
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(response))
}

async fn delete_backup_keys_all(State(state): State<Arc<AppState>>, headers: HeaderMap, Query(q): Query<VersionQuery>) -> Result<impl IntoResponse, MatrixError> {
    delete_backup_keys_inner(state, headers, None, None, q).await
}

async fn delete_backup_keys_room(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Query(q): Query<VersionQuery>,
) -> Result<impl IntoResponse, MatrixError> {
    delete_backup_keys_inner(state, headers, Some(room_id), None, q).await
}

async fn delete_backup_keys_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((room_id, session_id)): Path<(String, String)>,
    Query(q): Query<VersionQuery>,
) -> Result<impl IntoResponse, MatrixError> {
    delete_backup_keys_inner(state, headers, Some(room_id), Some(session_id), q).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    const T0: &str = "2026-09-24T00:00:00+00:00";
    const ROOM: &str = "!testroom:mylittlechart.org";

    fn test_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        matrix_store::create_matrix_schema(&conn).expect("matrix schema");
        matrix_keys_store::create_matrix_keys_schema(&conn).expect("matrix keys schema");
        conn
    }

    fn identity_test_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        conn.execute_batch(
            "
            CREATE TABLE auth_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id    INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT
            );
            CREATE TABLE web_sessions (
                session_id TEXT PRIMARY KEY,
                user_id    INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                ua_hash    TEXT NOT NULL DEFAULT ''
            );
            ",
        )
        .expect("test schema");
        conn
    }

    fn make_room_with_members(conn: &mut Connection, room_id: &str, members: &[(i64, &str)]) {
        matrix_store::create_room(
            conn,
            room_id,
            matrix_store::RoomKind::Group,
            members[0].0,
            T0,
            false,
            matrix_store::JoinRule::Invite,
            matrix_store::HistoryVisibility::Shared,
            None,
            None,
        )
        .expect("create room");
        for (user_id, mxid) in members {
            matrix_store::apply_state_event(conn, &format!("$member-{user_id}"), room_id, members[0].0, "m.room.member", mxid, r#"{"membership":"join"}"#, 1000, T0)
                .expect("member join");
        }
    }

    /// A room where `joined` is joined and `invited` holds a pending invite
    /// (the inviter-sends-before-the-invitee-joins shape).
    fn make_room_with_invitee(conn: &mut Connection, room_id: &str, joined: (i64, &str), invited: (i64, &str)) {
        matrix_store::create_room(
            conn,
            room_id,
            matrix_store::RoomKind::Dm,
            joined.0,
            T0,
            true,
            matrix_store::JoinRule::Invite,
            matrix_store::HistoryVisibility::Shared,
            None,
            None,
        )
        .expect("create room");
        matrix_store::apply_state_event(conn, "$member-joined", room_id, joined.0, "m.room.member", joined.1, r#"{"membership":"join"}"#, 1000, T0).expect("joined member");
        matrix_store::apply_state_event(conn, "$member-invited", room_id, joined.0, "m.room.member", invited.1, r#"{"membership":"invite"}"#, 1100, T0).expect("invited member");
    }

    /// Upload one device with one one-time key for `user_id`.
    fn upload_device_with_otk(conn: &mut Connection, user_id: i64, mxid: &str, device_id: &str) {
        let request = KeysUploadRequest {
            device_keys: Some(serde_json::json!({
                "user_id": mxid,
                "device_id": device_id,
                "algorithms": [],
                "keys": { format!("curve25519:{device_id}"): "k" },
                "signatures": {},
            })),
            one_time_keys: Some(BTreeMap::from([("signed_curve25519:AAAAAQ".to_string(), serde_json::json!({ "key": "otk" }))])),
            fallback_keys: None,
        };
        apply_keys_upload(conn, user_id, mxid, device_id, &request, T0).expect("upload keys");
    }

    // ---- P16 S-e: an invited peer is visible to the joined inviter, and only to them ----

    #[test]
    fn peers_sharing_a_room_with_counts_an_invited_peer_only_for_a_joined_caller() {
        let mut conn = test_conn();
        let alice = matrix_store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000071", T0).expect("alice");
        let bob = matrix_store::ensure_matrix_user(&conn, 2, "bob0000000000000000000000000071", T0).expect("bob");
        matrix_store::ensure_matrix_user(&conn, 3, "carol0000000000000000000000071a", T0).expect("carol");
        make_room_with_invitee(&mut conn, ROOM, (1, &alice), (2, &bob));

        assert_eq!(peers_sharing_a_room_with(&conn, 1).expect("alice"), HashSet::from([1, 2]), "the joined inviter sees the invitee");
        assert_eq!(peers_sharing_a_room_with(&conn, 2).expect("bob"), HashSet::from([2]), "an invited caller gets no visibility");
        assert_eq!(peers_sharing_a_room_with(&conn, 3).expect("carol"), HashSet::from([3]), "an unrelated user sees nobody");

        matrix_store::apply_state_event(&mut conn, "$bob-join", ROOM, 2, "m.room.member", &bob, r#"{"membership":"join"}"#, 1200, T0).expect("bob joins");
        assert_eq!(peers_sharing_a_room_with(&conn, 2).expect("bob joined"), HashSet::from([1, 2]), "once joined, bob sees alice");

        matrix_store::apply_state_event(&mut conn, "$bob-leave", ROOM, 2, "m.room.member", &bob, r#"{"membership":"leave"}"#, 1300, T0).expect("bob leaves");
        assert_eq!(peers_sharing_a_room_with(&conn, 1).expect("alice after leave"), HashSet::from([1]), "a peer who left is no longer visible");
    }

    #[test]
    fn inviter_can_query_and_claim_an_invited_peers_keys_but_not_the_reverse() {
        let mut conn = test_conn();
        let alice = matrix_store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000072", T0).expect("alice");
        let bob = matrix_store::ensure_matrix_user(&conn, 2, "bob0000000000000000000000000072", T0).expect("bob");
        let carol = matrix_store::ensure_matrix_user(&conn, 3, "carol0000000000000000000000072a", T0).expect("carol");
        make_room_with_invitee(&mut conn, ROOM, (1, &alice), (2, &bob));
        upload_device_with_otk(&mut conn, 1, &alice, "ALICEDEV");
        upload_device_with_otk(&mut conn, 2, &bob, "BOBDEV");
        upload_device_with_otk(&mut conn, 3, &carol, "CAROLDEV");

        // The inviter (joined) sees the invitee; an unrelated user stays hidden.
        let requested = BTreeMap::from([(bob.clone(), Vec::new()), (carol.clone(), Vec::new())]);
        let query = build_keys_query_response(&conn, 1, &alice, &requested).expect("alice queries");
        assert!(query["device_keys"][bob.as_str()]["BOBDEV"].is_object(), "the inviter must see the invitee's device: {query}");
        assert_eq!(query["device_keys"][carol.as_str()], serde_json::json!({}), "an unrelated user stays hidden");

        let claim_request = BTreeMap::from([
            (bob.clone(), BTreeMap::from([("BOBDEV".to_string(), "signed_curve25519".to_string())])),
            (carol.clone(), BTreeMap::from([("CAROLDEV".to_string(), "signed_curve25519".to_string())])),
        ]);
        let claim = build_keys_claim_response(&mut conn, 1, &claim_request).expect("alice claims");
        assert_eq!(claim["one_time_keys"][bob.as_str()]["BOBDEV"]["signed_curve25519:AAAAAQ"]["key"], "otk", "the inviter must be able to claim the invitee's key: {claim}");
        assert!(claim["one_time_keys"].get(carol.as_str()).is_none(), "an unrelated user's keys are never claimable");

        // The invited peer (not joined) gets no new visibility of the inviter.
        let reverse_query = build_keys_query_response(&conn, 2, &bob, &BTreeMap::from([(alice.clone(), Vec::new())])).expect("bob queries");
        assert_eq!(reverse_query["device_keys"][alice.as_str()], serde_json::json!({}), "an invited caller sees nobody");
        let reverse_claim_request = BTreeMap::from([(alice.clone(), BTreeMap::from([("ALICEDEV".to_string(), "signed_curve25519".to_string())]))]);
        let reverse_claim = build_keys_claim_response(&mut conn, 2, &reverse_claim_request).expect("bob claims");
        assert!(reverse_claim["one_time_keys"].get(alice.as_str()).is_none(), "an invited caller cannot claim anything");
    }

    #[test]
    fn send_to_device_reaches_an_invited_peer_but_not_a_stranger_or_from_an_invited_caller() {
        let mut conn = test_conn();
        let alice = matrix_store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000073", T0).expect("alice");
        let bob = matrix_store::ensure_matrix_user(&conn, 2, "bob0000000000000000000000000073", T0).expect("bob");
        let carol = matrix_store::ensure_matrix_user(&conn, 3, "carol0000000000000000000000073a", T0).expect("carol");
        make_room_with_invitee(&mut conn, ROOM, (1, &alice), (2, &bob));
        matrix_keys_store::create_device(&conn, 1, matrix_keys_store::CredentialKind::Bearer, "alice-cred", T0).expect("alice dev");
        let bob_device = matrix_keys_store::create_device(&conn, 2, matrix_keys_store::CredentialKind::Bearer, "bob-cred", T0).expect("bob dev");
        matrix_keys_store::create_device(&conn, 3, matrix_keys_store::CredentialKind::Bearer, "carol-cred", T0).expect("carol dev");

        let messages_to = |mxid: &str| -> BTreeMap<String, BTreeMap<String, serde_json::Value>> {
            BTreeMap::from([(mxid.to_string(), BTreeMap::from([("*".to_string(), serde_json::json!({ "hello": "world" }))]))])
        };

        let to_invitee = expand_send_to_device_targets(&conn, 1, &messages_to(&bob)).expect("expand to the invitee");
        assert_eq!(to_invitee.len(), 1);
        assert_eq!((to_invitee[0].0, to_invitee[0].1.as_str()), (2, bob_device.as_str()));

        assert!(expand_send_to_device_targets(&conn, 1, &messages_to(&carol)).expect("expand to a stranger").is_empty(), "a stranger still receives nothing");
        assert!(
            expand_send_to_device_targets(&conn, 2, &messages_to(&alice)).expect("expand from an invited caller").is_empty(),
            "an invited caller cannot send to-device messages"
        );
    }

    // ---- plan §9 P9 test 1: keys_upload_then_query_round_trips_device_keys_verbatim ----

    #[test]
    fn keys_upload_then_query_round_trips_device_keys_verbatim() {
        let mut conn = test_conn();
        let alice_mxid = matrix_store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000097", T0).expect("alice");
        let device_id = "DEVICE1";

        let device_keys = serde_json::json!({
            "user_id": alice_mxid,
            "device_id": device_id,
            "algorithms": ["m.olm.v1.curve25519-aes-sha2"],
            "keys": { format!("curve25519:{device_id}"): "abc", format!("ed25519:{device_id}"): "def" },
            "signatures": { alice_mxid.clone(): { format!("ed25519:{device_id}"): "sig" } },
        });
        let request = KeysUploadRequest { device_keys: Some(device_keys.clone()), one_time_keys: None, fallback_keys: None };
        let outcome = apply_keys_upload(&mut conn, 1, &alice_mxid, device_id, &request, T0).expect("upload");
        assert!(outcome.device_keys_changed);

        let mut requested = BTreeMap::new();
        requested.insert(alice_mxid.clone(), Vec::new());
        let response = build_keys_query_response(&conn, 1, &alice_mxid, &requested).expect("query");

        let queried = &response["device_keys"][alice_mxid.as_str()][device_id];
        assert_eq!(queried["user_id"], alice_mxid);
        assert_eq!(queried["device_id"], device_id);
        assert_eq!(queried["keys"], device_keys["keys"]);
        assert_eq!(queried["algorithms"], device_keys["algorithms"]);

        // A second, identical upload is a no-op — no second device-list change.
        let repeat = apply_keys_upload(&mut conn, 1, &alice_mxid, device_id, &request, T0).expect("repeat upload");
        assert!(!repeat.device_keys_changed);
    }

    // ---- named test: keys_upload_refuses_another_users_device_keys ----

    #[test]
    fn keys_upload_refuses_another_users_device_keys() {
        let device_keys = serde_json::json!({ "user_id": "@someone_else:mylittlechart.org", "device_id": "DEV", "algorithms": [], "keys": {}, "signatures": {} });
        let err = check_device_keys_ownership(&device_keys, "@caller:mylittlechart.org", "DEV").unwrap_err();
        assert_eq!(err.errcode, "M_INVALID_PARAM");

        let ok_keys = serde_json::json!({ "user_id": "@caller:mylittlechart.org", "device_id": "DEV" });
        check_device_keys_ownership(&ok_keys, "@caller:mylittlechart.org", "DEV").expect("matching ownership is accepted");
    }

    // ---- named test: keys_upload_refuses_changing_identity_keys ----

    #[test]
    fn keys_upload_refuses_changing_identity_keys() {
        let existing = r#"{"curve25519:DEV":"abc","ed25519:DEV":"def"}"#;
        let same = serde_json::json!({"curve25519:DEV":"abc","ed25519:DEV":"def"});
        assert_eq!(decide_device_keys_upload(Some(existing), &same).expect("identical resubmission"), DeviceKeysUploadAction::Noop);

        let changed = serde_json::json!({"curve25519:DEV":"CHANGED","ed25519:DEV":"def"});
        let err = decide_device_keys_upload(Some(existing), &changed).unwrap_err();
        assert_eq!(err.errcode, "M_INVALID_PARAM");

        assert_eq!(decide_device_keys_upload(None, &changed).expect("no existing row"), DeviceKeysUploadAction::Insert);
    }

    // ---- named test: keys_query_hides_users_without_a_shared_room ----

    #[test]
    fn keys_query_hides_users_without_a_shared_room() {
        let mut conn = test_conn();
        matrix_store::ensure_matrix_user(&conn, 1, "caller0000000000000000000000097", T0).expect("caller");
        let stranger_mxid = matrix_store::ensure_matrix_user(&conn, 2, "stranger0000000000000000000097a", T0).expect("stranger");
        let stranger_request = KeysUploadRequest {
            device_keys: Some(serde_json::json!({ "user_id": stranger_mxid, "device_id": "STRANGERDEV", "algorithms": [], "keys": {}, "signatures": {} })),
            one_time_keys: None,
            fallback_keys: None,
        };
        apply_keys_upload(&mut conn, 2, &stranger_mxid, "STRANGERDEV", &stranger_request, T0).expect("stranger uploads keys");

        let mut requested = BTreeMap::new();
        requested.insert(stranger_mxid.clone(), Vec::new());
        let response = build_keys_query_response(&conn, 1, "@caller0000000000000000000000097:mylittlechart.org", &requested).expect("query");
        assert_eq!(response["device_keys"][stranger_mxid.as_str()], serde_json::json!({}), "a stranger's keys are hidden entirely");
    }

    // ---- plan §9 P9 test 2 / named test: keys_changes_is_restricted_to_users_sharing_a_room_with_the_caller ----

    #[test]
    fn keys_changes_is_restricted_to_users_sharing_a_room_with_the_caller() {
        let mut conn = test_conn();
        let alice_mxid = matrix_store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000097", T0).expect("alice");
        let bob_mxid = matrix_store::ensure_matrix_user(&conn, 2, "bob0000000000000000000000000097", T0).expect("bob");
        matrix_store::ensure_matrix_user(&conn, 3, "carol0000000000000000000000097a", T0).expect("carol");
        make_room_with_members(&mut conn, ROOM, &[(1, &alice_mxid), (2, &bob_mxid)]);

        let from = matrix_store::max_stream_id(&conn).expect("from boundary");
        matrix_keys_store::log_device_list_change(&mut conn, 2, T0).expect("bob's device list changes"); // shares a room
        matrix_keys_store::log_device_list_change(&mut conn, 3, T0).expect("carol's device list changes"); // no shared room
        let to = matrix_store::max_stream_id(&conn).expect("to boundary");

        let response = build_keys_changes_response(&conn, 1, from, to).expect("build");
        let changed: Vec<&str> = response["changed"].as_array().expect("changed array").iter().map(|v| v.as_str().expect("mxid")).collect();
        assert!(changed.contains(&bob_mxid.as_str()));
        assert!(!changed.iter().any(|m| m.starts_with("@carol")), "a user sharing no room with the caller must not appear");
    }

    // ---- named test: device_signing_upload_requires_master_signature ----

    #[test]
    fn device_signing_upload_requires_master_signature() {
        use ed25519_dalek::Signer;

        let mut conn = test_conn();
        let caller_mxid = "@alice:mylittlechart.org";
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let master_pub_b64 = STANDARD_NO_PAD.encode(verifying_key.to_bytes());

        let master = serde_json::json!({
            "user_id": caller_mxid,
            "usage": ["master"],
            "keys": { format!("ed25519:{master_pub_b64}"): master_pub_b64 },
        });

        let mut self_signing = serde_json::json!({
            "user_id": caller_mxid,
            "usage": ["self_signing"],
            "keys": { "ed25519:SSK": "somepublickey" },
        });
        let message = canonical_json_without_signatures(&self_signing);
        let signature = signing_key.sign(message.as_bytes());
        let sig_b64 = STANDARD_NO_PAD.encode(signature.to_bytes());
        self_signing["signatures"] = serde_json::json!({ caller_mxid: { format!("ed25519:{master_pub_b64}"): sig_b64 } });

        let request = DeviceSigningUploadRequest { master_key: Some(master), self_signing_key: Some(self_signing.clone()), user_signing_key: None };
        apply_device_signing_upload(&mut conn, 1, caller_mxid, &request, T0).expect("a valid master signature is accepted");

        let mut broken = self_signing.clone();
        broken["signatures"][caller_mxid][format!("ed25519:{master_pub_b64}").as_str()] = serde_json::json!(STANDARD_NO_PAD.encode([0u8; 64]));
        let broken_request = DeviceSigningUploadRequest { master_key: None, self_signing_key: Some(broken), user_signing_key: None };
        let err = apply_device_signing_upload(&mut conn, 1, caller_mxid, &broken_request, T0).unwrap_err();
        assert_eq!(err.errcode, "M_INVALID_PARAM");
    }

    // ---- named test: send_to_device_star_expands_to_all_devices ----

    #[test]
    fn send_to_device_star_expands_to_all_devices() {
        let mut conn = test_conn();
        let alice_mxid = matrix_store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000097", T0).expect("alice");
        let bob_mxid = matrix_store::ensure_matrix_user(&conn, 2, "bob0000000000000000000000000097", T0).expect("bob");
        make_room_with_members(&mut conn, ROOM, &[(1, &alice_mxid), (2, &bob_mxid)]);
        matrix_keys_store::create_device(&conn, 2, matrix_keys_store::CredentialKind::Bearer, "bob-cred-1", T0).expect("bob dev1");
        matrix_keys_store::create_device(&conn, 2, matrix_keys_store::CredentialKind::Bearer, "bob-cred-2", T0).expect("bob dev2");

        let mut messages: BTreeMap<String, BTreeMap<String, serde_json::Value>> = BTreeMap::new();
        let mut per_device = BTreeMap::new();
        per_device.insert("*".to_string(), serde_json::json!({"hello": "world"}));
        messages.insert(bob_mxid, per_device);

        let targets = expand_send_to_device_targets(&conn, 1, &messages).expect("expand");
        assert_eq!(targets.len(), 2, "both of bob's devices must receive the wildcard message");
        for (uid, _, content) in &targets {
            assert_eq!(*uid, 2);
            assert_eq!(content, r#"{"hello":"world"}"#);
        }
    }

    // ---- named test: send_to_device_to_stranger_is_not_delivered ----

    #[test]
    fn send_to_device_to_stranger_is_not_delivered() {
        let conn = test_conn();
        matrix_store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000097", T0).expect("alice");
        let stranger_mxid = matrix_store::ensure_matrix_user(&conn, 2, "stranger0000000000000000000097a", T0).expect("stranger");
        // No shared room between alice and the stranger.
        matrix_keys_store::create_device(&conn, 2, matrix_keys_store::CredentialKind::Bearer, "stranger-cred", T0).expect("stranger dev");

        let mut messages: BTreeMap<String, BTreeMap<String, serde_json::Value>> = BTreeMap::new();
        let mut per_device = BTreeMap::new();
        per_device.insert("*".to_string(), serde_json::json!({}));
        messages.insert(stranger_mxid, per_device);

        let targets = expand_send_to_device_targets(&conn, 1, &messages).expect("expand");
        assert!(targets.is_empty(), "a stranger who shares no room with the sender receives nothing");
    }

    // ---- named test: send_to_device_is_txn_idempotent ----

    #[test]
    fn send_to_device_is_txn_idempotent() {
        let mut conn = test_conn();
        let alice_mxid = matrix_store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000097", T0).expect("alice");
        let bob_mxid = matrix_store::ensure_matrix_user(&conn, 2, "bob0000000000000000000000000097", T0).expect("bob");
        make_room_with_members(&mut conn, ROOM, &[(1, &alice_mxid), (2, &bob_mxid)]);
        let bob_device_id = matrix_keys_store::create_device(&conn, 2, matrix_keys_store::CredentialKind::Bearer, "bob-cred", T0).expect("bob dev");

        let mut messages: BTreeMap<String, BTreeMap<String, serde_json::Value>> = BTreeMap::new();
        let mut per_device = BTreeMap::new();
        per_device.insert("*".to_string(), serde_json::json!({"x": 1}));
        messages.insert(bob_mxid, per_device);

        let first = apply_send_to_device(&mut conn, 1, "alice-dev", "m.test", "txn-1", &messages, T0).expect("first send");
        assert!(matches!(first, SendToDeviceOutcome::New(_)));
        assert_eq!(matrix_keys_store::to_device_for(&conn, 2, &bob_device_id, 0, 10).expect("pending").len(), 1);

        let second = apply_send_to_device(&mut conn, 1, "alice-dev", "m.test", "txn-1", &messages, T0).expect("repeat send");
        assert_eq!(second, SendToDeviceOutcome::AlreadySent);
        assert_eq!(
            matrix_keys_store::to_device_for(&conn, 2, &bob_device_id, 0, 10).expect("pending after repeat").len(),
            1,
            "a repeated txn_id must not enqueue a second copy"
        );
    }

    // ---- named test: delete_device_revokes_its_credential ----

    #[test]
    fn delete_device_revokes_its_credential() {
        let identity_conn = identity_test_conn();
        identity_conn
            .execute("INSERT INTO auth_tokens (token_hash, user_id, created_at, expires_at) VALUES ('tok-hash', 1, ?1, NULL)", params![T0])
            .expect("insert token");

        let mut messenger_conn = test_conn();
        let device_id = matrix_keys_store::create_device(&messenger_conn, 1, matrix_keys_store::CredentialKind::Bearer, "tok-hash", T0).expect("create device");

        let live = mylittlechart_server::live::LiveRegistry::new();
        let deleted = apply_delete_device(&identity_conn, &mut messenger_conn, &live, 1, &device_id, T0).expect("delete");
        assert!(deleted);

        assert_eq!(matrix_keys_store::get_device(&messenger_conn, 1, &device_id).expect("get"), None);
        let remaining_tokens: i64 = identity_conn
            .query_row("SELECT COUNT(*) FROM auth_tokens WHERE token_hash = 'tok-hash'", [], |row| row.get(0))
            .expect("count");
        assert_eq!(remaining_tokens, 0, "the identity-side credential must also be revoked");

        let again = apply_delete_device(&identity_conn, &mut messenger_conn, &live, 1, &device_id, T0).expect("second delete is a no-op");
        assert!(!again);
    }

    // ---- named test: backup_refuses_pk_encryption_algorithm ----

    #[test]
    fn backup_refuses_pk_encryption_algorithm() {
        let err = validate_backup_algorithm("m.megolm_backup.v1.curve25519-aes-sha2").unwrap_err();
        assert_eq!(err.errcode, "M_INVALID_PARAM");
        validate_backup_algorithm(BACKUP_ALGORITHM).expect("our own symmetric algorithm is accepted");
    }

    // ---- named test: backup_put_with_stale_version_is_refused ----

    #[test]
    fn backup_put_with_stale_version_is_refused() {
        let mut conn = test_conn();
        let v1 = matrix_keys_store::create_backup_version(&conn, 1, BACKUP_ALGORITHM, "{}", T0).expect("v1");
        let v2 = matrix_keys_store::create_backup_version(&conn, 1, BACKUP_ALGORITHM, "{}", T0).expect("v2");
        assert!(v2 > v1);

        let sessions = vec![("!room:x".to_string(), "sessA".to_string(), "{}".to_string())];
        let result = match matrix_keys_store::put_backup_sessions(&mut conn, 1, v1, &sessions, T0) {
            Ok(()) => panic!("must be refused against a stale version"),
            Err(matrix_keys_store::MatrixKeysStoreError::WrongBackupVersion) => {
                let current = matrix_keys_store::current_backup_version(&conn, 1).expect("current");
                MatrixError::wrong_room_keys_version(current.map(|v| v.version))
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        };
        assert_eq!(result.errcode, "M_WRONG_ROOM_KEYS_VERSION");
        assert_eq!(result.current_version, Some(v2.to_string()));

        put_backup_sessions_current_ok(&mut conn, v2, &sessions);
    }

    fn put_backup_sessions_current_ok(conn: &mut Connection, version: i64, sessions: &[(String, String, String)]) {
        matrix_keys_store::put_backup_sessions(conn, 1, version, sessions, T0).expect("the current version is accepted");
    }

    // ---- supporting coverage: normalize/response shaping ----

    #[test]
    fn normalize_put_backup_body_handles_all_three_tiers() {
        let session_only = normalize_put_backup_body(Some("!r:x"), Some("s1"), &serde_json::json!({"session_data": "opaque"})).expect("session tier");
        assert_eq!(session_only, vec![("!r:x".to_string(), "s1".to_string(), r#"{"session_data":"opaque"}"#.to_string())]);

        let room_only = normalize_put_backup_body(Some("!r:x"), None, &serde_json::json!({"sessions": {"s1": {"a": 1}}})).expect("room tier");
        assert_eq!(room_only, vec![("!r:x".to_string(), "s1".to_string(), r#"{"a":1}"#.to_string())]);

        let all = normalize_put_backup_body(None, None, &serde_json::json!({"rooms": {"!r:x": {"sessions": {"s1": {"a": 1}}}}})).expect("all tier");
        assert_eq!(all, vec![("!r:x".to_string(), "s1".to_string(), r#"{"a":1}"#.to_string())]);
    }

    #[test]
    fn require_current_backup_version_reports_the_actual_current_version() {
        let conn = test_conn();
        let v1 = matrix_keys_store::create_backup_version(&conn, 1, BACKUP_ALGORITHM, "{}", T0).expect("v1");
        require_current_backup_version(&conn, 1, v1).expect("v1 is current");

        let v2 = matrix_keys_store::create_backup_version(&conn, 1, BACKUP_ALGORITHM, "{}", T0).expect("v2");
        let err = require_current_backup_version(&conn, 1, v1).unwrap_err();
        assert_eq!(err.errcode, "M_WRONG_ROOM_KEYS_VERSION");
        assert_eq!(err.current_version, Some(v2.to_string()));
    }
}

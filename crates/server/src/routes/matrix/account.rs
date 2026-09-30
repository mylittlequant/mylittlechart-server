//! Matrix account routes (P8): account data (global + per-room), tags,
//! filters, profile, `user_directory/search`, and `publicRooms`. See
//! `docs/mlc/plans/messenger-proto-server-matrix-subset-2026-09-24.md` §4
//! (endpoint table + gate definitions) and its own P8 brief for the
//! per-endpoint rules this module follows (`m.fully_read` refusal, tag
//! name/count caps, the profile-is-read-only decision, the
//! `user_directory/search`-reuses-the-DM-lookup-ranking decision, and
//! `publicRooms`' pagination shape).
//!
//! # Every write wakes only the caller's own devices
//!
//! Unlike `routes::matrix::rooms`/`messaging`/`ephemeral` (which routinely
//! wake a whole room), every write this module makes — account data (global
//! or per-room), a tag change, a new filter — is visible only to the account
//! that made it (Matrix never reveals one user's account data to another),
//! so every wake here is `wake_many(["user:{caller.user_id}"])`, never a
//! room's joined/invited set. `user_directory/search` and `publicRooms` are
//! pure reads and wake nobody.
//!
//! # `userId` in the path must be the caller's own mxid
//!
//! Every `/user/{userId}/...` route in this module (account data, tags,
//! filters) refuses with `M_FORBIDDEN` unless the path's `userId` equals the
//! caller's own mxid ([`check_caller_owns_user_id`]) — this server has no
//! notion of one account managing another's account data. `/profile/{userId}`
//! is the one exception (by design: reading another user's displayname is
//! the whole point of a profile lookup).
//!
//! # Testable cores
//!
//! Every DB-only decision (the `userId`-ownership check, the `m.fully_read`
//! refusal, tag validation, the ranking pipeline `user_directory/search`
//! shares with `routes::dm::lookup_recipients`, and profile resolution) is a
//! plain function taking `&Connection`/values — never `MatrixCaller`/
//! `AppState` — matching every other module in this tree's own stated
//! convention.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use rusqlite::Connection;

use mylittlechart_server::matrix_store::{self, Membership};

use super::auth;
use super::MatrixError;
use crate::db;
use crate::recipient_search::{self, PaidCandidate};
use crate::social_db;
use crate::state::AppState;

// ============================================================================
// Router
// ============================================================================

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/client/v3/user/{user_id}/account_data/{event_type}",
            get(get_account_data_global).put(put_account_data_global),
        )
        .route(
            "/client/v3/user/{user_id}/rooms/{room_id}/account_data/{event_type}",
            get(get_account_data_room).put(put_account_data_room),
        )
        .route("/client/v3/user/{user_id}/rooms/{room_id}/tags", get(get_tags))
        .route(
            "/client/v3/user/{user_id}/rooms/{room_id}/tags/{tag}",
            put(put_tag).delete(delete_tag),
        )
        .route("/client/v3/user/{user_id}/filter", post(post_filter))
        .route("/client/v3/user/{user_id}/filter/{filter_id}", get(get_filter))
        .route("/client/v3/profile/{user_id}", get(get_profile))
        .route(
            "/client/v3/profile/{user_id}/displayname",
            get(get_profile_displayname).put(put_displayname),
        )
        .route("/client/v3/user_directory/search", post(user_directory_search))
        .route("/client/v3/publicRooms", get(get_public_rooms).post(post_public_rooms))
        .route("/client/v3/account/whoami", get(whoami))
}

// ============================================================================
// GET /_matrix/client/v3/account/whoami
// ============================================================================

/// `GET /account/whoami`'s wire shape: the caller's own mxid and the device
/// this credential resolved to (minting it on first use — see
/// [`auth::device_id_for`]'s own doc). This is how a client with no
/// `/login` flow (this server has none — plan §1) learns its own device id.
/// `is_guest` is always `false`: this server has no guest accounts.
fn whoami_response(mxid: &str, device_id: &str) -> serde_json::Value {
    serde_json::json!({ "user_id": mxid, "device_id": device_id, "is_guest": false })
}

async fn whoami(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    Ok(Json(whoami_response(&caller.mxid, &caller.device_id)))
}

// ============================================================================
// Shared DB-only gate helpers — own copies per this codebase's convention
// (mirror `routes::matrix::rooms`/`ephemeral`'s own `require_member` byte-
// for-byte).
// ============================================================================

fn require_member(membership: Option<Membership>) -> Result<(), MatrixError> {
    match membership {
        Some(Membership::Join) => Ok(()),
        _ => Err(MatrixError::forbidden("not a member of this room")),
    }
}

/// The tags gate (P8 brief item 3): joined OR invited, unlike plain
/// per-room account data (item 2), which requires a full join.
fn require_member_or_invited(membership: Option<Membership>) -> Result<(), MatrixError> {
    match membership {
        Some(Membership::Join) | Some(Membership::Invite) => Ok(()),
        _ => Err(MatrixError::forbidden("not a member or invitee of this room")),
    }
}

/// Every `/user/{userId}/...` route in this module: the path's `userId`
/// (a full mxid) must be the caller's own — this server has no notion of one
/// account managing another's account data/tags/filters.
fn check_caller_owns_user_id(path_user_id: &str, caller_mxid: &str) -> Result<(), MatrixError> {
    if path_user_id == caller_mxid {
        Ok(())
    } else {
        Err(MatrixError::forbidden("userId must be the caller's own mxid"))
    }
}

// ============================================================================
// Account data (global + per-room)
// ============================================================================

/// `m.fully_read` is refused on both the global and per-room account-data
/// endpoints (P8 brief items 1/2): it belongs to room account data via
/// `POST .../read_markers` ([`super::ephemeral::apply_read_markers`]), which
/// is the only writer this server ever lets touch it — a raw `PUT` here
/// would let a client desync it from the receipt bookkeeping that route also
/// updates in the same call.
fn check_account_data_type_allowed(event_type: &str) -> Result<(), MatrixError> {
    if event_type == "m.fully_read" {
        Err(MatrixError::managed_account_data_type(
            "m.fully_read is managed through POST .../read_markers, not raw account data",
        ))
    } else {
        Ok(())
    }
}

/// `PUT` account-data content must be a JSON object (Matrix's own shape for
/// every account-data type) within [`matrix_store::MATRIX_EVENT_CONTENT_MAX_BYTES`]
/// once serialized — same ceiling `routes::matrix::rooms::put_state` applies
/// to state-event content. Returns the serialized string ready to store.
fn validate_account_data_content(value: &serde_json::Value) -> Result<String, MatrixError> {
    if !value.is_object() {
        return Err(MatrixError::bad_json("account data content must be a JSON object"));
    }
    let serialized = value.to_string();
    if serialized.len() > matrix_store::MATRIX_EVENT_CONTENT_MAX_BYTES {
        return Err(MatrixError::invalid_param("account data content too large"));
    }
    Ok(serialized)
}

async fn get_account_data_global(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((user_id, event_type)): Path<(String, String)>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    check_caller_owns_user_id(&user_id, &caller.mxid)?;

    let content = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
        let cp = state.control_plane();
        let messenger_conn = cp.messenger_conn();
        let row = matrix_store::get_account_data(&messenger_conn, caller.user_id, matrix_store::GLOBAL_ACCOUNT_DATA_ROOM, &event_type)?
            .ok_or_else(|| MatrixError::not_found("no account data of this type"))?;
        Ok(serde_json::from_str(&row.content)?)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(content))
}

async fn put_account_data_global(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((user_id, event_type)): Path<(String, String)>,
    Json(content): Json<serde_json::Value>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    check_caller_owns_user_id(&user_id, &caller.mxid)?;
    check_account_data_type_allowed(&event_type)?;
    let content_str = validate_account_data_content(&content)?;

    let state_for_blocking = state.clone();
    tokio::task::spawn_blocking(move || -> Result<(), MatrixError> {
        let cp = state_for_blocking.control_plane();
        let mut messenger_conn = cp.messenger_conn();
        matrix_store::upsert_account_data(&mut messenger_conn, caller.user_id, matrix_store::GLOBAL_ACCOUNT_DATA_ROOM, &event_type, &content_str)?;
        Ok(())
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    state.control_plane().live.wake_many(std::iter::once(format!("user:{}", caller.user_id)));
    Ok(Json(serde_json::json!({})))
}

async fn get_account_data_room(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((user_id, room_id, event_type)): Path<(String, String, String)>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    check_caller_owns_user_id(&user_id, &caller.mxid)?;

    let content = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
        let cp = state.control_plane();
        let messenger_conn = cp.messenger_conn();
        matrix_store::get_room(&messenger_conn, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        let membership = matrix_store::room_member(&messenger_conn, &room_id, caller.user_id)?.map(|m| m.membership);
        require_member(membership)?;
        let row = matrix_store::get_account_data(&messenger_conn, caller.user_id, &room_id, &event_type)?
            .ok_or_else(|| MatrixError::not_found("no account data of this type"))?;
        Ok(serde_json::from_str(&row.content)?)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(content))
}

async fn put_account_data_room(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((user_id, room_id, event_type)): Path<(String, String, String)>,
    Json(content): Json<serde_json::Value>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    check_caller_owns_user_id(&user_id, &caller.mxid)?;
    check_account_data_type_allowed(&event_type)?;
    let content_str = validate_account_data_content(&content)?;

    let state_for_blocking = state.clone();
    tokio::task::spawn_blocking(move || -> Result<(), MatrixError> {
        let cp = state_for_blocking.control_plane();
        let mut messenger_conn = cp.messenger_conn();
        matrix_store::get_room(&messenger_conn, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        let membership = matrix_store::room_member(&messenger_conn, &room_id, caller.user_id)?.map(|m| m.membership);
        require_member(membership)?;
        matrix_store::upsert_account_data(&mut messenger_conn, caller.user_id, &room_id, &event_type, &content_str)?;
        Ok(())
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    state.control_plane().live.wake_many(std::iter::once(format!("user:{}", caller.user_id)));
    Ok(Json(serde_json::json!({})))
}

// ============================================================================
// Tags — a thin view over room account data type `m.tag`
// ============================================================================

const MAX_TAG_NAME_BYTES: usize = 255;
const MAX_TAGS_PER_ROOM: usize = 100;

#[derive(serde::Deserialize, Default)]
struct TagBody {
    #[serde(default)]
    order: Option<f64>,
}

fn validate_tag_name(tag: &str) -> Result<(), MatrixError> {
    if tag.is_empty() || tag.len() > MAX_TAG_NAME_BYTES {
        Err(MatrixError::invalid_param("tag name must be 1-255 bytes"))
    } else {
        Ok(())
    }
}

/// `order` (P8 brief item 3): when present, must be in `[0, 1]`.
fn validate_tag_order(order: Option<f64>) -> Result<(), MatrixError> {
    match order {
        Some(v) if !(0.0..=1.0).contains(&v) => Err(MatrixError::invalid_param("tag order must be between 0 and 1")),
        _ => Ok(()),
    }
}

/// `{"tags": {...}}`'s `tags` object, or empty when the room has no `m.tag`
/// account-data row yet.
fn read_tags(conn: &Connection, user_id: i64, room_id: &str) -> Result<serde_json::Map<String, serde_json::Value>, MatrixError> {
    match matrix_store::get_account_data(conn, user_id, room_id, "m.tag")? {
        Some(row) => {
            let content: serde_json::Value = serde_json::from_str(&row.content)?;
            Ok(content.get("tags").and_then(|v| v.as_object()).cloned().unwrap_or_default())
        }
        None => Ok(serde_json::Map::new()),
    }
}

fn write_tags(conn: &mut Connection, user_id: i64, room_id: &str, tags: serde_json::Map<String, serde_json::Value>) -> Result<(), MatrixError> {
    let content = serde_json::json!({ "tags": tags }).to_string();
    matrix_store::upsert_account_data(conn, user_id, room_id, "m.tag", &content)?;
    Ok(())
}

/// `PUT .../tags/{tag}`'s whole DB-side decision: validate the tag name and
/// `order`, refuse growing past [`MAX_TAGS_PER_ROOM`] on a genuinely NEW tag
/// (re-setting an existing tag's `order` never counts against the cap), then
/// upsert. Membership is checked by the route handler, not here (this
/// function takes no caller/room-membership context at all — the "testable
/// cores" convention this module states).
fn apply_tag_put(conn: &mut Connection, user_id: i64, room_id: &str, tag: &str, order: Option<f64>) -> Result<(), MatrixError> {
    validate_tag_name(tag)?;
    validate_tag_order(order)?;

    let mut tags = read_tags(conn, user_id, room_id)?;
    if !tags.contains_key(tag) && tags.len() >= MAX_TAGS_PER_ROOM {
        return Err(MatrixError::invalid_param("too many tags on this room"));
    }
    let mut entry = serde_json::Map::new();
    if let Some(order) = order {
        entry.insert("order".to_string(), serde_json::json!(order));
    }
    tags.insert(tag.to_string(), serde_json::Value::Object(entry));
    write_tags(conn, user_id, room_id, tags)
}

/// `DELETE .../tags/{tag}` — idempotent: removing an absent tag is a
/// silent no-op, matching Matrix's own DELETE semantics.
fn apply_tag_delete(conn: &mut Connection, user_id: i64, room_id: &str, tag: &str) -> Result<(), MatrixError> {
    let mut tags = read_tags(conn, user_id, room_id)?;
    tags.remove(tag);
    write_tags(conn, user_id, room_id, tags)
}

async fn get_tags(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((user_id, room_id)): Path<(String, String)>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    check_caller_owns_user_id(&user_id, &caller.mxid)?;

    let tags = tokio::task::spawn_blocking(move || -> Result<serde_json::Map<String, serde_json::Value>, MatrixError> {
        let cp = state.control_plane();
        let messenger_conn = cp.messenger_conn();
        matrix_store::get_room(&messenger_conn, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        let membership = matrix_store::room_member(&messenger_conn, &room_id, caller.user_id)?.map(|m| m.membership);
        require_member_or_invited(membership)?;
        read_tags(&messenger_conn, caller.user_id, &room_id)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(serde_json::json!({ "tags": tags })))
}

async fn put_tag(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((user_id, room_id, tag)): Path<(String, String, String)>,
    Json(body): Json<TagBody>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    check_caller_owns_user_id(&user_id, &caller.mxid)?;

    let state_for_blocking = state.clone();
    tokio::task::spawn_blocking(move || -> Result<(), MatrixError> {
        let cp = state_for_blocking.control_plane();
        let mut messenger_conn = cp.messenger_conn();
        matrix_store::get_room(&messenger_conn, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        let membership = matrix_store::room_member(&messenger_conn, &room_id, caller.user_id)?.map(|m| m.membership);
        require_member_or_invited(membership)?;
        apply_tag_put(&mut messenger_conn, caller.user_id, &room_id, &tag, body.order)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    state.control_plane().live.wake_many(std::iter::once(format!("user:{}", caller.user_id)));
    Ok(Json(serde_json::json!({})))
}

async fn delete_tag(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((user_id, room_id, tag)): Path<(String, String, String)>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    check_caller_owns_user_id(&user_id, &caller.mxid)?;

    let state_for_blocking = state.clone();
    tokio::task::spawn_blocking(move || -> Result<(), MatrixError> {
        let cp = state_for_blocking.control_plane();
        let mut messenger_conn = cp.messenger_conn();
        matrix_store::get_room(&messenger_conn, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        let membership = matrix_store::room_member(&messenger_conn, &room_id, caller.user_id)?.map(|m| m.membership);
        require_member_or_invited(membership)?;
        apply_tag_delete(&mut messenger_conn, caller.user_id, &room_id, &tag)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    state.control_plane().live.wake_many(std::iter::once(format!("user:{}", caller.user_id)));
    Ok(Json(serde_json::json!({})))
}

// ============================================================================
// Filters
// ============================================================================

/// Ceiling on a stored Filter JSON object (P8 brief item 4).
const FILTER_MAX_BYTES: usize = 64 * 1024;

/// A Filter must be a JSON object within [`FILTER_MAX_BYTES`] once
/// serialized — stored verbatim, opaque, interpreted only by a later `/sync`
/// piece. Returns the serialized string ready to store.
fn validate_filter_definition(value: &serde_json::Value) -> Result<String, MatrixError> {
    if !value.is_object() {
        return Err(MatrixError::bad_json("filter must be a JSON object"));
    }
    let serialized = value.to_string();
    if serialized.len() > FILTER_MAX_BYTES {
        return Err(MatrixError::invalid_param("filter definition too large"));
    }
    Ok(serialized)
}

async fn post_filter(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    check_caller_owns_user_id(&user_id, &caller.mxid)?;
    let definition = validate_filter_definition(&body)?;

    let filter_id = tokio::task::spawn_blocking(move || -> Result<i64, MatrixError> {
        let cp = state.control_plane();
        let messenger_conn = cp.messenger_conn();
        Ok(matrix_store::create_filter(&messenger_conn, caller.user_id, &definition)?)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(serde_json::json!({ "filter_id": filter_id.to_string() })))
}

async fn get_filter(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((user_id, filter_id)): Path<(String, String)>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    check_caller_owns_user_id(&user_id, &caller.mxid)?;
    let filter_id: i64 = filter_id.parse().map_err(|_| MatrixError::invalid_param("filterId must be numeric"))?;

    let content = tokio::task::spawn_blocking(move || -> Result<String, MatrixError> {
        let cp = state.control_plane();
        let messenger_conn = cp.messenger_conn();
        matrix_store::get_filter(&messenger_conn, caller.user_id, filter_id)?.ok_or_else(|| MatrixError::not_found("no such filter"))
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(serde_json::from_str::<serde_json::Value>(&content)?))
}

// ============================================================================
// Profile — read-only wrapper over `db::effective_label_for_user`
// ============================================================================

/// The pure resolution core of `GET /profile/{userId}[/displayname]`:
/// `mxid` -> internal `user_id` (via `matrix_users`, [`MatrixError::not_found`]
/// on a miss) -> [`db::effective_label_for_user`]. No avatar in v1 (P8
/// brief item 5), so both profile routes return the exact same shape.
fn profile_displayname(identity_conn: &Connection, messenger_conn: &Connection, mxid: &str) -> Result<String, MatrixError> {
    let target_user_id = matrix_store::user_id_of(messenger_conn, mxid)?.ok_or_else(|| MatrixError::not_found("unknown user"))?;
    Ok(db::effective_label_for_user(identity_conn, target_user_id)?)
}

async fn profile_response(state: Arc<AppState>, headers: HeaderMap, user_id: String) -> Result<impl IntoResponse, MatrixError> {
    auth::resolve_matrix_caller(&headers, &state).await?;

    let displayname = tokio::task::spawn_blocking(move || -> Result<String, MatrixError> {
        let cp = state.control_plane();
        // Lock order: db -> social -> messenger (`ControlPlane::messenger_conn`).
        let identity_conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
        let messenger_conn = cp.messenger_conn();
        profile_displayname(&identity_conn, &messenger_conn, &user_id)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(serde_json::json!({ "displayname": displayname })))
}

async fn get_profile(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(user_id): Path<String>) -> Result<impl IntoResponse, MatrixError> {
    profile_response(state, headers, user_id).await
}

async fn get_profile_displayname(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<impl IntoResponse, MatrixError> {
    profile_response(state, headers, user_id).await
}

/// `PUT /profile/{userId}/displayname`'s fixed refusal (P8 brief item 5): the
/// nick is the source of truth and is changed in account settings, never
/// through the messenger's own profile endpoint.
fn displayname_put_refusal() -> MatrixError {
    MatrixError::forbidden("displayname follows your nick — change it in account settings, not here")
}

async fn put_displayname(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(_user_id): Path<String>,
    Json(_body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, MatrixError> {
    auth::resolve_matrix_caller(&headers, &state).await?;
    Err(displayname_put_refusal())
}

// ============================================================================
// POST /_matrix/client/v3/user_directory/search
// ============================================================================

/// A trimmed, lowercased `search_term` longer than this is truncated rather
/// than refused — matches `routes::dm::lookup_recipients`'s own
/// `MAX_LOOKUP_QUERY_LEN`.
const MAX_SEARCH_TERM_LEN: usize = 64;

/// `limit`'s default when the client omits it — matches
/// `routes::dm::lookup_recipients`'s own `MAX_LOOKUP_RESULTS`.
const DEFAULT_DIRECTORY_RESULTS: usize = 10;

/// Ceiling a client-supplied `limit` is clamped to — the DM lookup has no
/// client-facing `limit` at all (always 10); the Matrix endpoint's own spec
/// shape does take one, so this is the abuse-prevention ceiling on it.
const MAX_DIRECTORY_RESULTS: usize = 50;

#[derive(serde::Deserialize)]
struct UserDirectorySearchRequest {
    search_term: String,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(serde::Serialize)]
struct UserDirectoryResult {
    user_id: String,
    display_name: String,
}

#[derive(serde::Serialize)]
struct UserDirectorySearchResponse {
    results: Vec<UserDirectoryResult>,
    limited: bool,
}

/// One ranked, labeled match — [`rank_directory_candidates`]'s own output
/// row, carrying `public_id` along so the route handler can
/// [`matrix_store::ensure_matrix_user`] it into an mxid without a second
/// identity-database round trip.
struct DirectoryMatch {
    user_id: i64,
    public_id: String,
    label: String,
}

/// The DB-free ranking core `user_directory/search` and
/// `routes::dm::lookup_recipients` both build on: [`recipient_search::rank_candidate`]
/// scores each candidate, [`recipient_search::effective_label_from_parts`]
/// labels it, and the result is sorted `(rank, label)` — byte-for-byte the
/// same comparator `lookup_recipients` uses inline, so the two call sites
/// can never drift in ranking order (plan §6.1's whole reason for extracting
/// `recipient_search` in the first place). The ONE deliberate difference
/// from `lookup_recipients`: no filter on a published DM identity key — that
/// precondition is specific to the legacy ciphertext-DM feature, not to the
/// Matrix messenger (whose own key exchange is `/keys/upload`, a later
/// piece), so a paid-ladder-eligible account is listed here even before it
/// has ever called `/keys/upload`.
///
/// Returns the ranked, truncated matches and whether truncation actually
/// dropped anything (`limited`).
fn rank_directory_candidates(candidates: Vec<PaidCandidate>, query: &str, limit: usize) -> (Vec<DirectoryMatch>, bool) {
    let mut matched: Vec<(u8, DirectoryMatch)> = candidates
        .into_iter()
        .filter_map(|c| {
            let rank = recipient_search::rank_candidate(query, c.nick.as_deref(), &c.display_name)?;
            let label = recipient_search::effective_label_from_parts(c.nick.as_deref(), &c.display_name, &c.public_id);
            Some((rank, DirectoryMatch { user_id: c.id, public_id: c.public_id, label }))
        })
        .collect();
    matched.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.label.cmp(&b.1.label)));
    let limited = matched.len() > limit;
    matched.truncate(limit);
    (matched.into_iter().map(|(_, m)| m).collect(), limited)
}

async fn user_directory_search(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<UserDirectorySearchRequest>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;

    let query = req.search_term.trim().to_lowercase();
    if query.is_empty() {
        return Err(MatrixError::invalid_param("search_term must not be empty"));
    }
    let query: String = query.chars().take(MAX_SEARCH_TERM_LEN).collect();
    let limit = req.limit.map_or(DEFAULT_DIRECTORY_RESULTS, |l| l.clamp(1, MAX_DIRECTORY_RESULTS as i64) as usize);

    let response = tokio::task::spawn_blocking(move || -> Result<UserDirectorySearchResponse, MatrixError> {
        let cp = state.control_plane();

        let is_paid = {
            let identity_conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
            db::user_is_paid(&identity_conn, caller.user_id)?
        };
        let is_paid = {
            let social_conn = cp.social_conn();
            auth::is_messenger_paid(&social_conn, caller.user_id, is_paid)
        };
        auth::require_paid_matrix(is_paid)?;

        let boosted_ids = {
            let social_conn = cp.social_conn();
            social_db::ladder_boosted_user_ids(&social_conn)?
        };
        let now = chrono::Utc::now().to_rfc3339();
        let candidates = {
            let identity_conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
            recipient_search::paid_recipient_candidates(&identity_conn, caller.user_id, &boosted_ids, &now)?
        };

        let (matched, limited) = rank_directory_candidates(candidates, &query, limit);

        let messenger_conn = cp.messenger_conn();
        let mut results = Vec::with_capacity(matched.len());
        for m in matched {
            let mxid = matrix_store::ensure_matrix_user(&messenger_conn, m.user_id, &m.public_id, &now)?;
            results.push(UserDirectoryResult { user_id: mxid, display_name: m.label });
        }
        Ok(UserDirectorySearchResponse { results, limited })
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(response))
}

// ============================================================================
// GET/POST /_matrix/client/v3/publicRooms
// ============================================================================

const DEFAULT_PUBLIC_ROOMS_LIMIT: i64 = 20;
const MAX_PUBLIC_ROOMS_LIMIT: i64 = 100;

fn clamp_public_rooms_limit(limit: Option<i64>) -> usize {
    limit.unwrap_or(DEFAULT_PUBLIC_ROOMS_LIMIT).clamp(1, MAX_PUBLIC_ROOMS_LIMIT) as usize
}

#[derive(serde::Deserialize, Default)]
struct PublicRoomsQuery {
    limit: Option<i64>,
    since: Option<String>,
}

#[derive(serde::Deserialize, Default)]
struct PublicRoomsFilter {
    #[serde(default)]
    generic_search_term: Option<String>,
}

#[derive(serde::Deserialize, Default)]
struct PublicRoomsRequestBody {
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    filter: PublicRoomsFilter,
}

/// One `chunk` entry's wire shape (P8 brief item 7) — `name`/`topic` are
/// omitted entirely (not `null`) when the room never set them, matching
/// Matrix's own convention of omitting rather than nulling absent profile
/// fields.
fn public_room_json(room: &matrix_store::PublicRoomSummary) -> serde_json::Value {
    let mut value = serde_json::json!({
        "room_id": room.room_id,
        "num_joined_members": room.num_joined_members,
        "world_readable": room.world_readable,
        "guest_can_join": false,
        "join_rule": "public",
    });
    if let Some(name) = &room.name {
        value["name"] = serde_json::Value::String(name.clone());
    }
    if let Some(topic) = &room.topic {
        value["topic"] = serde_json::Value::String(topic.clone());
    }
    value
}

async fn public_rooms_response(
    state: Arc<AppState>,
    headers: HeaderMap,
    since: Option<String>,
    limit: usize,
    search_term: Option<String>,
) -> Result<impl IntoResponse, MatrixError> {
    auth::resolve_matrix_caller(&headers, &state).await?;

    let (chunk, next_batch, total) = tokio::task::spawn_blocking(move || -> Result<(Vec<serde_json::Value>, Option<String>, i64), MatrixError> {
        let cp = state.control_plane();
        let messenger_conn = cp.messenger_conn();
        let (page, has_more, total) = matrix_store::public_rooms_page(&messenger_conn, since.as_deref(), limit, search_term.as_deref())?;
        let next_batch = if has_more { page.last().map(|r| r.room_id.clone()) } else { None };
        Ok((page.iter().map(public_room_json).collect(), next_batch, total))
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    let mut response = serde_json::json!({ "chunk": chunk, "total_room_count_estimate": total });
    if let Some(next_batch) = next_batch {
        response["next_batch"] = serde_json::Value::String(next_batch);
    }
    Ok(Json(response))
}

async fn get_public_rooms(State(state): State<Arc<AppState>>, headers: HeaderMap, Query(query): Query<PublicRoomsQuery>) -> Result<impl IntoResponse, MatrixError> {
    public_rooms_response(state, headers, query.since, clamp_public_rooms_limit(query.limit), None).await
}

async fn post_public_rooms(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<PublicRoomsRequestBody>,
) -> Result<impl IntoResponse, MatrixError> {
    public_rooms_response(state, headers, body.since, clamp_public_rooms_limit(body.limit), body.filter.generic_search_term).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: &str = "2026-09-24T00:00:00+00:00";
    const ROOM: &str = "!testroom:mylittlechart.org";
    const PUBLIC_ROOM: &str = "!publicroom:mylittlechart.org";

    fn test_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        matrix_store::create_matrix_schema(&conn).expect("matrix schema");
        conn
    }

    /// A minimal identity-database fixture: just enough of `users` for
    /// [`db::effective_label_for_user`] to read from — mirrors
    /// `recipient_search::tests::identity_test_conn`.
    fn identity_test_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        conn.execute_batch(
            "CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL DEFAULT 'test',
                provider_user_id TEXT NOT NULL DEFAULT '',
                display_name TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT '',
                public_id TEXT,
                nick TEXT
            );",
        )
        .expect("identity test schema");
        conn
    }

    // ---- check_caller_owns_user_id ----

    #[test]
    fn account_data_for_another_user_is_forbidden() {
        let err = check_caller_owns_user_id("@bob:mylittlechart.org", "@alice:mylittlechart.org").unwrap_err();
        assert_eq!(err.errcode, "M_FORBIDDEN");
        assert!(check_caller_owns_user_id("@alice:mylittlechart.org", "@alice:mylittlechart.org").is_ok());
    }

    // ---- check_account_data_type_allowed ----

    #[test]
    fn global_fully_read_is_refused() {
        let err = check_account_data_type_allowed("m.fully_read").unwrap_err();
        assert_eq!(err.errcode, "M_BAD_JSON");
        assert_eq!(err.status, axum::http::StatusCode::METHOD_NOT_ALLOWED);
        assert!(check_account_data_type_allowed("m.tag").is_ok());
        assert!(check_account_data_type_allowed("m.direct").is_ok());
    }

    // ---- tags round trip ----

    #[test]
    fn tag_put_get_delete_round_trip() {
        let mut conn = test_conn();
        matrix_store::create_room(&conn, ROOM, matrix_store::RoomKind::Group, 1, T0, false, matrix_store::JoinRule::Invite, matrix_store::HistoryVisibility::Shared, None, None)
            .expect("create room");

        assert!(read_tags(&conn, 1, ROOM).expect("read empty tags").is_empty());

        apply_tag_put(&mut conn, 1, ROOM, "m.favourite", Some(0.5)).expect("put tag");
        let tags = read_tags(&conn, 1, ROOM).expect("read tags");
        assert_eq!(tags.get("m.favourite").and_then(|v| v.get("order")).and_then(|v| v.as_f64()), Some(0.5));

        apply_tag_delete(&mut conn, 1, ROOM, "m.favourite").expect("delete tag");
        assert!(read_tags(&conn, 1, ROOM).expect("read after delete").is_empty());

        // Deleting an already-absent tag is a silent no-op.
        apply_tag_delete(&mut conn, 1, ROOM, "m.favourite").expect("delete absent tag");
    }

    #[test]
    fn tag_order_out_of_range_is_refused() {
        let mut conn = test_conn();
        matrix_store::create_room(&conn, ROOM, matrix_store::RoomKind::Group, 1, T0, false, matrix_store::JoinRule::Invite, matrix_store::HistoryVisibility::Shared, None, None)
            .expect("create room");

        let err = apply_tag_put(&mut conn, 1, ROOM, "m.favourite", Some(1.5)).unwrap_err();
        assert_eq!(err.errcode, "M_INVALID_PARAM");
        let err = apply_tag_put(&mut conn, 1, ROOM, "m.favourite", Some(-0.1)).unwrap_err();
        assert_eq!(err.errcode, "M_INVALID_PARAM");
        assert!(apply_tag_put(&mut conn, 1, ROOM, "m.favourite", Some(0.0)).is_ok());
        assert!(apply_tag_put(&mut conn, 1, ROOM, "m.favourite", Some(1.0)).is_ok());
    }

    #[test]
    fn tag_name_too_long_is_refused() {
        let long_name = "x".repeat(MAX_TAG_NAME_BYTES + 1);
        assert!(validate_tag_name(&long_name).is_err());
        assert!(validate_tag_name("m.favourite").is_ok());
    }

    // ---- filters ----

    #[test]
    fn filter_round_trip_is_own_only() {
        let conn = test_conn();
        let definition = validate_filter_definition(&serde_json::json!({ "room": { "timeline": { "limit": 10 } } })).expect("validate");
        let filter_id = matrix_store::create_filter(&conn, 1, &definition).expect("create filter");

        assert_eq!(matrix_store::get_filter(&conn, 1, filter_id).expect("owner reads it"), Some(definition));
        assert_eq!(matrix_store::get_filter(&conn, 2, filter_id).expect("a different user cannot"), None);
    }

    #[test]
    fn filter_definition_must_be_a_json_object() {
        assert!(validate_filter_definition(&serde_json::json!([1, 2, 3])).is_err());
        assert!(validate_filter_definition(&serde_json::json!("not an object")).is_err());
        assert!(validate_filter_definition(&serde_json::json!({})).is_ok());
    }

    // ---- profile ----

    #[test]
    fn profile_displayname_follows_nick() {
        let identity_conn = identity_test_conn();
        identity_conn
            .execute(
                "INSERT INTO users (id, display_name, created_at, public_id, nick) VALUES (1, 'Real Name', ?1, 'alice000000000000000000000000a1', 'alicenick')",
                rusqlite::params![T0],
            )
            .expect("insert user");

        let messenger_conn = test_conn();
        let mxid = matrix_store::ensure_matrix_user(&messenger_conn, 1, "alice000000000000000000000000a1", T0).expect("ensure matrix user");

        let label = profile_displayname(&identity_conn, &messenger_conn, &mxid).expect("resolve displayname");
        assert_eq!(label, "alicenick", "the nick, not the display_name, must win");
    }

    #[test]
    fn profile_of_an_unknown_mxid_is_not_found() {
        let identity_conn = identity_test_conn();
        let messenger_conn = test_conn();
        let err = profile_displayname(&identity_conn, &messenger_conn, "@nobody:mylittlechart.org").unwrap_err();
        assert_eq!(err.errcode, "M_NOT_FOUND");
    }

    #[test]
    fn profile_put_is_forbidden() {
        let err = displayname_put_refusal();
        assert_eq!(err.errcode, "M_FORBIDDEN");
        assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);
    }

    // ---- user_directory/search ranking parity with routes::dm::lookup_recipients ----

    /// A byte-for-byte copy of `routes::dm::lookup_recipients`'s own inline
    /// ranking pipeline (minus its DM-identity-key filter and truncation,
    /// which are that route's own concerns, not shared ranking logic): score
    /// via [`recipient_search::rank_candidate`], label via
    /// [`recipient_search::effective_label_from_parts`], sort by
    /// `(rank, label)`. Kept here, separately from
    /// [`rank_directory_candidates`], so this test proves the two
    /// independently-written call sites agree — not merely that a function
    /// agrees with itself.
    fn dm_style_rank_and_sort(candidates: &[PaidCandidate], query: &str) -> Vec<(i64, String, u8)> {
        let mut matched: Vec<(i64, String, u8)> = candidates
            .iter()
            .filter_map(|c| {
                let rank = recipient_search::rank_candidate(query, c.nick.as_deref(), &c.display_name)?;
                let label = recipient_search::effective_label_from_parts(c.nick.as_deref(), &c.display_name, &c.public_id);
                Some((c.id, label, rank))
            })
            .collect();
        matched.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.1.cmp(&b.1)));
        matched
    }

    fn sample_candidates() -> Vec<PaidCandidate> {
        vec![
            PaidCandidate { id: 1, nick: Some("kosti".to_string()), display_name: "Kosti Primary".to_string(), public_id: "pub1".to_string() },
            PaidCandidate { id: 2, nick: Some("kostroma".to_string()), display_name: "Kostroma Events".to_string(), public_id: "pub2".to_string() },
            PaidCandidate { id: 3, nick: None, display_name: "Someone kosit".to_string(), public_id: "pub3".to_string() },
            PaidCandidate { id: 4, nick: Some("unrelated".to_string()), display_name: "Nope".to_string(), public_id: "pub4".to_string() },
        ]
    }

    #[test]
    fn user_directory_search_ranking_matches_dm_lookup_recipients_for_the_same_input() {
        let candidates = sample_candidates();
        let reference = dm_style_rank_and_sort(&candidates, "kos");
        let (matched, limited) = rank_directory_candidates(candidates, "kos", 10);

        assert!(!limited);
        let matched_ids: Vec<i64> = matched.iter().map(|m| m.user_id).collect();
        let reference_ids: Vec<i64> = reference.iter().map(|(id, _, _)| *id).collect();
        assert_eq!(matched_ids, reference_ids, "user_directory/search must rank in the exact same order as the DM lookup for the same input");
        for (m, (_, label, _)) in matched.iter().zip(reference.iter()) {
            assert_eq!(&m.label, label);
        }
    }

    #[test]
    fn user_directory_search_reports_limited_when_truncated() {
        let candidates: Vec<PaidCandidate> =
            (0..5).map(|i| PaidCandidate { id: i, nick: Some(format!("match{i}")), display_name: String::new(), public_id: format!("pub{i}") }).collect();
        let (matched, limited) = rank_directory_candidates(candidates, "match", 3);
        assert_eq!(matched.len(), 3);
        assert!(limited);
    }

    // ---- publicRooms ----

    #[test]
    fn public_rooms_lists_only_public_channels() {
        let mut conn = test_conn();
        matrix_store::create_room(
            &conn,
            PUBLIC_ROOM,
            matrix_store::RoomKind::Channel,
            1,
            T0,
            false,
            matrix_store::JoinRule::Public,
            matrix_store::HistoryVisibility::WorldReadable,
            None,
            None,
        )
        .expect("create public channel");
        matrix_store::apply_state_event(&mut conn, "$name", PUBLIC_ROOM, 1, "m.room.name", "", r#"{"name":"General"}"#, 1000, T0).expect("set name");
        let member = matrix_store::ensure_matrix_user(&conn, 1, "creator0000000000000000000000a1", T0).expect("mxid");
        matrix_store::apply_state_event(&mut conn, "$m1", PUBLIC_ROOM, 1, "m.room.member", &member, r#"{"membership":"join"}"#, 1100, T0).expect("join");

        matrix_store::create_room(&conn, ROOM, matrix_store::RoomKind::Group, 1, T0, true, matrix_store::JoinRule::Invite, matrix_store::HistoryVisibility::Shared, None, None)
            .expect("create private group");

        let (page, has_more, total) = matrix_store::public_rooms_page(&conn, None, 20, None).expect("public rooms page");
        assert_eq!(total, 1, "only the public channel counts toward the estimate");
        assert!(!has_more);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].room_id, PUBLIC_ROOM);
        assert_eq!(page[0].num_joined_members, 1);
        assert!(page[0].world_readable);

        let json = public_room_json(&page[0]);
        assert_eq!(json["name"], "General");
        assert_eq!(json["join_rule"], "public");
        assert!(json.get("topic").is_none(), "an unset topic must be omitted, not null");
    }

    // ---- whoami ----

    #[test]
    fn whoami_returns_mxid_and_the_credentials_device() {
        use mylittlechart_server::matrix_keys_store::{self, CredentialKind};

        let conn = test_conn();
        matrix_keys_store::create_matrix_keys_schema(&conn).expect("keys schema");
        let mxid = matrix_store::ensure_matrix_user(&conn, 1, "alice000000000000000000000000a1", T0).expect("ensure matrix user");

        let device_first = auth::device_id_for(&conn, 1, CredentialKind::Bearer, "cred-a", T0).expect("mint device for cred-a");
        let response_first = whoami_response(&mxid, &device_first);
        assert_eq!(response_first["user_id"], mxid);
        assert_eq!(response_first["device_id"], device_first);
        assert_eq!(response_first["is_guest"], false);

        let device_again = auth::device_id_for(&conn, 1, CredentialKind::Bearer, "cred-a", T0).expect("resolve cred-a again");
        assert_eq!(device_again, device_first, "resolving the same credential twice must return the same device id");

        let device_other_cred = auth::device_id_for(&conn, 1, CredentialKind::Bearer, "cred-b", T0).expect("mint device for cred-b");
        assert_ne!(device_other_cred, device_first, "a second credential of the same user must get a different device id");
    }
}

//! Matrix ephemeral routes — typing, receipts, read markers (P7). See
//! `docs/mlc/plans/messenger-proto-server-matrix-subset-2026-09-24.md` §3.5
//! (`unread_notifications`, whose `notification_count` query lives in
//! `mylittlechart_server::matrix_store` — a lib-crate helper, not this
//! module), §3.6 (typing + receipt coalescing), §3.8 (typing's own 3s
//! throttle, in [`mylittlechart_server::live::TypingRegistry`]), and §4's
//! `typing`/`receipt`/`read_markers` table rows.
//!
//! # `TypingRegistry` lives in `live.rs`, not here
//!
//! Typing state itself ([`mylittlechart_server::live::TypingRegistry`] — the
//! throttle, the auto-expiry, the per-room typer set) is P3's own module;
//! this file only calls it. `state.rs::ControlPlane` holds one instance
//! (`cp.typing`) next to `cp.live`, constructed once at boot.
//!
//! # Wake-set rule per route
//!
//! - `PUT .../typing/{userId}`: wakes the room's joined+invited members, but
//!   ONLY when [`mylittlechart_server::live::TypingRegistry::set_typing`]
//!   returns `true` (an EFFECTIVE change) — never on a throttled repeat or a
//!   refresh of an already-active `true`. See [`apply_typing`].
//! - `POST .../receipt/{receiptType}/{eventId}`: `m.read` wakes every
//!   joined+invited member (it is visible to them by definition); `m.read.
//!   private` wakes ONLY the caller's own devices (`"user:{caller}"`) —
//!   Matrix's own privacy guarantee for that receipt type: it must never
//!   reach another user's `/sync`. See [`apply_receipt`].
//! - `POST .../read_markers`: `m.fully_read` is per-room account data for
//!   the caller only, so it wakes only the caller's own devices; `m.read`/
//!   `m.read.private` embedded in the same call reuse [`apply_receipt`] and
//!   follow its own rule above. See [`apply_read_markers`].
//!
//! Every write is one `spawn_blocking` DB decision, then one wake — same
//! discipline `routes::matrix::rooms`/`routes::matrix::messaging` already
//! state in their own module docs: the wake only fires AFTER the
//! `spawn_blocking` future resolves, never while a `messenger` connection
//! guard is still held.
//!
//! # `thread_id` (receipt route)
//!
//! Accepted in the request body and ignored for v1 (task scope) — this
//! server has no thread concept yet; a client that sends `thread_id` gets
//! exactly the same behavior as one that omits it.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::{post, put};
use axum::{Json, Router};
use rusqlite::Connection;

use mylittlechart_server::live;
use mylittlechart_server::matrix_store::{self, Membership, ReceiptType, Room};

use super::auth;
use super::MatrixError;
use crate::state::AppState;

/// Applied when a `PUT .../typing/{userId}` body omits `timeout` and
/// `typing: true` — matches
/// [`mylittlechart_server::live::TypingRegistry::set_typing`]'s own clamp
/// ceiling (its private `TYPING_MAX_TIMEOUT_MS`), so an omitted timeout
/// behaves the same as the largest timeout a client could ask for.
const DEFAULT_TYPING_TIMEOUT_MS: u64 = 30_000;

// ============================================================================
// Router
// ============================================================================

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/client/v3/rooms/{room_id}/typing/{user_id}", put(put_typing))
        .route("/client/v3/rooms/{room_id}/receipt/{receipt_type}/{event_id}", post(post_receipt))
        .route("/client/v3/rooms/{room_id}/read_markers", post(post_read_markers))
}

// ============================================================================
// DB-only gate helper — own copy per this codebase's convention (mirrors
// `routes::matrix::rooms::require_member`/`routes::matrix::messaging::
// require_member` byte-for-byte).
// ============================================================================

fn require_member(membership: Option<Membership>) -> Result<(), MatrixError> {
    match membership {
        Some(Membership::Join) => Ok(()),
        _ => Err(MatrixError::forbidden("not a member of this room")),
    }
}

// ============================================================================
// Pure decision function — no DB, unit-tested directly
// ============================================================================

/// `PUT /typing/{userId}`'s own gate (plan §4: `userId` must equal the
/// caller's own mxid, else 403) — factored out so it is unit-tested without
/// axum/`AppState` at all.
fn check_typing_target(target_mxid: &str, caller_mxid: &str) -> Result<(), MatrixError> {
    if target_mxid == caller_mxid {
        Ok(())
    } else {
        Err(MatrixError::forbidden("userId must be the caller's own mxid"))
    }
}

// ============================================================================
// DB-only action cores — no `MatrixCaller`/`AppState`, unit-tested directly
// against an in-memory `matrix_store` fixture
// ============================================================================

/// `PUT /typing/{userId}`'s whole DB-side decision (plan §4 `typing` row:
/// Member, then [`live::TypingRegistry::set_typing`]'s own throttle):
/// refuses a nonexistent room or a non-`join`ed caller, then applies the
/// typing flag. Returns the wake set ONLY when `set_typing` reports an
/// EFFECTIVE change — `None` for a throttled repeat, a refresh of an
/// already-active `true`, or a `false` for someone not currently counted as
/// typing (see that function's own doc) — callers must skip waking anyone
/// on `None`.
fn apply_typing(
    conn: &Connection,
    typing_registry: &live::TypingRegistry,
    room_id: &str,
    caller_user_id: i64,
    typing: bool,
    timeout_ms: u64,
    now: Instant,
) -> Result<Option<HashSet<i64>>, MatrixError> {
    matrix_store::get_room(conn, room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
    let membership = matrix_store::room_member(conn, room_id, caller_user_id)?.map(|m| m.membership);
    require_member(membership)?;

    let changed = typing_registry.set_typing(room_id, caller_user_id, typing, timeout_ms, now);
    if !changed {
        return Ok(None);
    }
    Ok(Some(super::rooms::member_and_invited_ids(conn, room_id)?))
}

/// `POST /receipt/{receiptType}/{eventId}`'s whole DB-side decision (plan §4
/// `receipt` row, and the `m.read`/`m.read.private` branches of `POST
/// /read_markers`): Member, then the target event must be visible to the
/// caller ([`matrix_store::visible_upper_bound`] — for a `join`ed member
/// (the only membership this gate accepts) this is always
/// [`matrix_store::HistoryWindow::All`] unless a `world_readable` room's
/// event simply does not exist in THIS room at all, which the room-id filter
/// below already catches), then [`matrix_store::upsert_receipt`]'s own
/// monotonic upsert. Returns `None` (no wake) when the upsert did not
/// actually move the receipt forward — a backwards or repeat receipt is a
/// silent no-op, detected here by comparing the receipt's `stream_id`
/// before and after the upsert, never by re-deriving the monotonic
/// comparison a second time.
fn apply_receipt(
    conn: &mut Connection,
    room: &Room,
    caller_user_id: i64,
    receipt_type: ReceiptType,
    event_id: &str,
    now_ms: i64,
) -> Result<Option<HashSet<i64>>, MatrixError> {
    let caller_membership = matrix_store::room_member(conn, &room.id, caller_user_id)?.map(|m| m.membership);
    require_member(caller_membership)?;

    let window = matrix_store::visible_upper_bound(conn, room, caller_user_id)?;
    let target = matrix_store::get_event(conn, event_id)?
        .filter(|e| e.room_id == room.id)
        .ok_or_else(|| MatrixError::not_found("no such event"))?;
    if !window.contains(target.stream_id) {
        return Err(MatrixError::forbidden("event is outside your visible history"));
    }

    let before = matrix_store::get_receipt(conn, &room.id, caller_user_id, receipt_type)?;
    let new_stream_id = matrix_store::upsert_receipt(conn, &room.id, caller_user_id, receipt_type, event_id, now_ms)?;
    if before.as_ref().map(|r| r.stream_id) == Some(new_stream_id) {
        return Ok(None);
    }

    let wake_ids = match receipt_type {
        // Visible to every joined+invited member by definition — filing a
        // read receipt is itself proof the caller could read the event.
        ReceiptType::Read => super::rooms::member_and_invited_ids(conn, &room.id)?,
        // Matrix's own privacy guarantee: a private receipt must never
        // reach another user's `/sync` — only the caller's own devices.
        ReceiptType::ReadPrivate => HashSet::from([caller_user_id]),
    };
    Ok(Some(wake_ids))
}

/// `POST /read_markers`'s whole DB-side decision (plan §4 `read_markers`
/// row): Member, then `m.fully_read` (stored verbatim as per-room account
/// data for the caller, waking only their own devices) and/or `m.read`/
/// `m.read.private` (each delegated to [`apply_receipt`], which applies its
/// own wake rule per type). Every field is independently optional — a call
/// naming only one of the three touches only that one.
fn apply_read_markers(
    conn: &mut Connection,
    room: &Room,
    caller_user_id: i64,
    fully_read_event_id: Option<&str>,
    read_event_id: Option<&str>,
    read_private_event_id: Option<&str>,
    now_ms: i64,
) -> Result<HashSet<i64>, MatrixError> {
    let caller_membership = matrix_store::room_member(conn, &room.id, caller_user_id)?.map(|m| m.membership);
    require_member(caller_membership)?;

    let mut wake_ids = HashSet::new();

    if let Some(event_id) = fully_read_event_id {
        matrix_store::upsert_account_data(
            conn,
            caller_user_id,
            &room.id,
            "m.fully_read",
            &serde_json::json!({ "event_id": event_id }).to_string(),
        )?;
        wake_ids.insert(caller_user_id);
    }
    if let Some(event_id) = read_event_id {
        if let Some(ids) = apply_receipt(conn, room, caller_user_id, ReceiptType::Read, event_id, now_ms)? {
            wake_ids.extend(ids);
        }
    }
    if let Some(event_id) = read_private_event_id {
        if let Some(ids) = apply_receipt(conn, room, caller_user_id, ReceiptType::ReadPrivate, event_id, now_ms)? {
            wake_ids.extend(ids);
        }
    }

    Ok(wake_ids)
}

// ============================================================================
// PUT /_matrix/client/v3/rooms/{roomId}/typing/{userId}
// ============================================================================

#[derive(serde::Deserialize)]
struct TypingBody {
    typing: bool,
    #[serde(default)]
    timeout: Option<u64>,
}

async fn put_typing(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((room_id, target_mxid)): Path<(String, String)>,
    Json(body): Json<TypingBody>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    check_typing_target(&target_mxid, &caller.mxid)?;

    let timeout_ms = body.timeout.unwrap_or(DEFAULT_TYPING_TIMEOUT_MS);
    let state_for_blocking = state.clone();
    let room_id_for_blocking = room_id.clone();

    let wake_ids = tokio::task::spawn_blocking(move || -> Result<Option<HashSet<i64>>, MatrixError> {
        let cp = state_for_blocking.control_plane();
        let messenger_conn = cp.messenger_conn();
        apply_typing(&messenger_conn, &cp.typing, &room_id_for_blocking, caller.user_id, body.typing, timeout_ms, Instant::now())
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    if let Some(wake_ids) = wake_ids {
        state.control_plane().live.wake_many(wake_ids.into_iter().map(|id| format!("user:{id}")));
    }
    Ok(Json(serde_json::json!({})))
}

// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}
// ============================================================================

async fn post_receipt(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((room_id, receipt_type_raw, event_id)): Path<(String, String, String)>,
    Json(_body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let receipt_type =
        ReceiptType::from_wire_name(&receipt_type_raw).ok_or_else(|| MatrixError::invalid_param("receiptType must be m.read or m.read.private"))?;
    // `thread_id` (and anything else `_body` carries) is accepted and
    // ignored for v1 — see the module doc.

    let state_for_blocking = state.clone();
    let room_id_for_blocking = room_id.clone();

    let wake_ids = tokio::task::spawn_blocking(move || -> Result<Option<HashSet<i64>>, MatrixError> {
        let cp = state_for_blocking.control_plane();
        let mut messenger_conn = cp.messenger_conn();
        let room = matrix_store::get_room(&messenger_conn, &room_id_for_blocking)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        let now_ms = chrono::Utc::now().timestamp_millis();
        apply_receipt(&mut messenger_conn, &room, caller.user_id, receipt_type, &event_id, now_ms)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    if let Some(wake_ids) = wake_ids {
        state.control_plane().live.wake_many(wake_ids.into_iter().map(|id| format!("user:{id}")));
    }
    Ok(Json(serde_json::json!({})))
}

// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/read_markers
// ============================================================================

#[derive(serde::Deserialize, Default)]
struct ReadMarkersBody {
    #[serde(rename = "m.fully_read", default)]
    fully_read: Option<String>,
    #[serde(rename = "m.read", default)]
    read: Option<String>,
    #[serde(rename = "m.read.private", default)]
    read_private: Option<String>,
}

async fn post_read_markers(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Json(body): Json<ReadMarkersBody>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;

    let state_for_blocking = state.clone();
    let room_id_for_blocking = room_id.clone();

    let wake_ids = tokio::task::spawn_blocking(move || -> Result<HashSet<i64>, MatrixError> {
        let cp = state_for_blocking.control_plane();
        let mut messenger_conn = cp.messenger_conn();
        let room = matrix_store::get_room(&messenger_conn, &room_id_for_blocking)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        let now_ms = chrono::Utc::now().timestamp_millis();
        apply_read_markers(
            &mut messenger_conn,
            &room,
            caller.user_id,
            body.fully_read.as_deref(),
            body.read.as_deref(),
            body.read_private.as_deref(),
            now_ms,
        )
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    if !wake_ids.is_empty() {
        state.control_plane().live.wake_many(wake_ids.into_iter().map(|id| format!("user:{id}")));
    }
    Ok(Json(serde_json::json!({})))
}

// ============================================================================
// wake_rooms_with_expired_typing — the P14-scheduled periodic sweep
// ============================================================================

/// The DB-only half of [`wake_rooms_with_expired_typing`]: every room
/// [`live::TypingRegistry::rooms_with_expired_typing`] reports, expanded to
/// its joined+invited member set. Split out from the `spawn_blocking`
/// wrapper below so it is unit-tested against a plain `Connection` +
/// [`live::TypingRegistry`], no `AppState`/`ControlPlane` involved at all —
/// this module's own "testable cores" convention.
fn expired_typing_wake_ids(conn: &Connection, typing_registry: &live::TypingRegistry, now: Instant) -> HashSet<i64> {
    let expired_rooms = typing_registry.rooms_with_expired_typing(now);
    let mut ids = HashSet::new();
    for room_id in expired_rooms {
        match super::rooms::member_and_invited_ids(conn, &room_id) {
            Ok(members) => ids.extend(members),
            Err(e) => tracing::error!("expired_typing_wake_ids: failed to list members of {}: {}", room_id, e),
        }
    }
    ids
}

/// Sweep every room whose typing state has timed out and wake its
/// joined+invited members. Typing expiry is client-driven (the client's own
/// `timeout`), so nothing else ever notices a member who simply stopped
/// typing and never sent another `/sync`-triggering action — without this
/// sweep, a peer's typing indicator would stay stuck on for anyone currently
/// blocked in a long poll (see [`live::TypingRegistry::
/// rooms_with_expired_typing`]'s own doc). P14 schedules this on a periodic
/// tick; P10's own `/sync` handler may also call it opportunistically on
/// every request.
pub async fn wake_rooms_with_expired_typing(state: &Arc<AppState>, now: Instant) {
    let state_for_blocking = state.clone();
    let wake_ids = tokio::task::spawn_blocking(move || -> HashSet<i64> {
        let cp = state_for_blocking.control_plane();
        let messenger_conn = cp.messenger_conn();
        expired_typing_wake_ids(&messenger_conn, &cp.typing, now)
    })
    .await
    .unwrap_or_default();

    if !wake_ids.is_empty() {
        state.control_plane().live.wake_many(wake_ids.into_iter().map(|id| format!("user:{id}")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const T0: &str = "2026-09-24T00:00:00+00:00";
    const ROOM: &str = "!testroom:mylittlechart.org";

    fn test_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        matrix_store::create_matrix_schema(&conn).expect("matrix schema");
        conn
    }

    /// A room with two joined members: user 1 ("alice") and user 2 ("bob").
    fn make_room_with_two_members(conn: &mut Connection) -> (String, String) {
        matrix_store::create_room(
            conn,
            ROOM,
            matrix_store::RoomKind::Group,
            1,
            T0,
            false,
            matrix_store::JoinRule::Invite,
            matrix_store::HistoryVisibility::Shared,
            None,
            None,
        )
        .expect("create room");
        let alice = matrix_store::ensure_matrix_user(conn, 1, "alice00000000000000000000000001", T0).expect("alice");
        let bob = matrix_store::ensure_matrix_user(conn, 2, "bob000000000000000000000000002", T0).expect("bob");
        matrix_store::apply_state_event(conn, "$m1", ROOM, 1, "m.room.member", &alice, r#"{"membership":"join"}"#, 900, T0).expect("alice joins");
        matrix_store::apply_state_event(conn, "$m2", ROOM, 1, "m.room.member", &bob, r#"{"membership":"join"}"#, 1000, T0).expect("bob joins");
        (alice, bob)
    }

    // ---- typing_for_another_user_is_forbidden ----

    #[test]
    fn typing_for_another_user_is_forbidden() {
        let err = check_typing_target("@bob:mylittlechart.org", "@alice:mylittlechart.org").unwrap_err();
        assert_eq!(err.errcode, "M_FORBIDDEN");
        assert!(check_typing_target("@alice:mylittlechart.org", "@alice:mylittlechart.org").is_ok());
    }

    // ---- throttled_typing_does_not_wake ----

    #[test]
    fn throttled_typing_does_not_wake() {
        let mut conn = test_conn();
        make_room_with_two_members(&mut conn);
        let typing = live::TypingRegistry::new();
        let t0 = Instant::now();

        let first = apply_typing(&conn, &typing, ROOM, 1, true, 5_000, t0).expect("first typing accepted");
        assert!(first.is_some(), "the first typing:true must wake the room");

        let second = apply_typing(&conn, &typing, ROOM, 1, true, 5_000, t0 + Duration::from_millis(500)).expect("throttled repeat");
        assert!(second.is_none(), "a throttled repeat must not wake anyone");
    }

    #[test]
    fn typing_by_a_non_member_is_forbidden() {
        let mut conn = test_conn();
        make_room_with_two_members(&mut conn);
        let typing = live::TypingRegistry::new();

        let err = apply_typing(&conn, &typing, ROOM, 999, true, 5_000, Instant::now()).unwrap_err();
        assert_eq!(err.errcode, "M_FORBIDDEN");
    }

    // ---- private_receipt_wakes_only_own_devices ----

    #[test]
    fn private_receipt_wakes_only_own_devices() {
        let mut conn = test_conn();
        make_room_with_two_members(&mut conn);
        let event = matrix_store::insert_timeline_event(&mut conn, "$msg", ROOM, 2, "m.room.message", "{}", 1000, None).expect("message");

        let room = matrix_store::get_room(&conn, ROOM).expect("get room").expect("room exists");
        let wake_ids = apply_receipt(&mut conn, &room, 1, ReceiptType::ReadPrivate, &event.event_id, 1500)
            .expect("apply private receipt")
            .expect("a new receipt must report a change");
        assert_eq!(wake_ids, HashSet::from([1]), "m.read.private must wake ONLY the caller's own devices, never other room members");
    }

    #[test]
    fn read_receipt_wakes_every_joined_member() {
        let mut conn = test_conn();
        make_room_with_two_members(&mut conn);
        let event = matrix_store::insert_timeline_event(&mut conn, "$msg", ROOM, 2, "m.room.message", "{}", 1000, None).expect("message");

        let room = matrix_store::get_room(&conn, ROOM).expect("get room").expect("room exists");
        let wake_ids = apply_receipt(&mut conn, &room, 1, ReceiptType::Read, &event.event_id, 1500)
            .expect("apply read receipt")
            .expect("a new receipt must report a change");
        assert_eq!(wake_ids, HashSet::from([1, 2]), "m.read must wake every joined member, including the caller's own other devices");
    }

    // ---- backwards_receipt_is_a_noop ----

    #[test]
    fn backwards_receipt_is_a_noop() {
        let mut conn = test_conn();
        make_room_with_two_members(&mut conn);
        let e1 = matrix_store::insert_timeline_event(&mut conn, "$e1", ROOM, 2, "m.room.message", "{}", 1000, None).expect("e1");
        let e2 = matrix_store::insert_timeline_event(&mut conn, "$e2", ROOM, 2, "m.room.message", "{}", 2000, None).expect("e2");
        let room = matrix_store::get_room(&conn, ROOM).expect("get room").expect("room exists");

        let forward = apply_receipt(&mut conn, &room, 1, ReceiptType::Read, &e2.event_id, 2500).expect("advance to e2");
        assert!(forward.is_some());

        let backward = apply_receipt(&mut conn, &room, 1, ReceiptType::Read, &e1.event_id, 3000).expect("attempted backward move");
        assert!(backward.is_none(), "a backwards receipt must be a silent no-op, never a wake");

        let stored = matrix_store::get_receipt(&conn, ROOM, 1, ReceiptType::Read).expect("get receipt").expect("receipt exists");
        assert_eq!(stored.event_id, e2.event_id, "the receipt must still point at e2, not have moved backward to e1");
    }

    // ---- fully_read_is_stored_as_room_account_data ----

    #[test]
    fn fully_read_is_stored_as_room_account_data() {
        let mut conn = test_conn();
        make_room_with_two_members(&mut conn);
        let event = matrix_store::insert_timeline_event(&mut conn, "$msg", ROOM, 2, "m.room.message", "{}", 1000, None).expect("message");
        let room = matrix_store::get_room(&conn, ROOM).expect("get room").expect("room exists");

        let wake_ids = apply_read_markers(&mut conn, &room, 1, Some(&event.event_id), None, None, 1500).expect("apply read markers");
        assert_eq!(wake_ids, HashSet::from([1]), "m.fully_read must wake only the caller's own devices");

        let stored = matrix_store::get_account_data(&conn, 1, ROOM, "m.fully_read").expect("get account data").expect("row exists");
        let content: serde_json::Value = serde_json::from_str(&stored.content).expect("json content");
        assert_eq!(content, serde_json::json!({ "event_id": event.event_id }));
    }

    #[test]
    fn read_markers_can_combine_fully_read_with_a_receipt() {
        let mut conn = test_conn();
        make_room_with_two_members(&mut conn);
        let event = matrix_store::insert_timeline_event(&mut conn, "$msg", ROOM, 2, "m.room.message", "{}", 1000, None).expect("message");
        let room = matrix_store::get_room(&conn, ROOM).expect("get room").expect("room exists");

        let wake_ids =
            apply_read_markers(&mut conn, &room, 1, Some(&event.event_id), Some(&event.event_id), None, 1500).expect("apply read markers");
        assert_eq!(wake_ids, HashSet::from([1, 2]), "the embedded m.read receipt must wake every joined member on top of the caller's own devices");
        assert!(matrix_store::get_account_data(&conn, 1, ROOM, "m.fully_read").expect("get account data").is_some());
        assert!(matrix_store::get_receipt(&conn, ROOM, 1, ReceiptType::Read).expect("get receipt").is_some());
    }

    // ---- receipt_on_invisible_event_is_refused ----

    #[test]
    fn receipt_on_invisible_event_is_refused() {
        let mut conn = test_conn();
        make_room_with_two_members(&mut conn);

        const OTHER_ROOM: &str = "!otherroom:mylittlechart.org";
        matrix_store::create_room(
            &conn,
            OTHER_ROOM,
            matrix_store::RoomKind::Group,
            1,
            T0,
            false,
            matrix_store::JoinRule::Invite,
            matrix_store::HistoryVisibility::Shared,
            None,
            None,
        )
        .expect("create other room");
        let foreign_event = matrix_store::insert_timeline_event(&mut conn, "$foreign", OTHER_ROOM, 1, "m.room.message", "{}", 1000, None).expect("foreign event");

        let room = matrix_store::get_room(&conn, ROOM).expect("get room").expect("room exists");
        let err = apply_receipt(&mut conn, &room, 1, ReceiptType::Read, &foreign_event.event_id, 1500).unwrap_err();
        assert_eq!(err.errcode, "M_NOT_FOUND");
    }

    #[test]
    fn receipt_on_a_nonexistent_event_is_refused() {
        let mut conn = test_conn();
        make_room_with_two_members(&mut conn);
        let room = matrix_store::get_room(&conn, ROOM).expect("get room").expect("room exists");

        let err = apply_receipt(&mut conn, &room, 1, ReceiptType::Read, "$never-existed", 1500).unwrap_err();
        assert_eq!(err.errcode, "M_NOT_FOUND");
    }

    // ---- expired_typing_wake_ids (wake_rooms_with_expired_typing's DB-only half) ----

    #[test]
    fn expired_typing_wake_ids_covers_the_expired_rooms_joined_members() {
        let mut conn = test_conn();
        make_room_with_two_members(&mut conn);
        let typing = live::TypingRegistry::new();
        let t0 = Instant::now();
        assert!(typing.set_typing(ROOM, 1, true, 100, t0));

        let ids = expired_typing_wake_ids(&conn, &typing, t0 + Duration::from_millis(500));
        assert_eq!(ids, HashSet::from([1, 2]), "every joined member of the expired room must be woken");

        // A second sweep with nothing newly expired reports nothing.
        let ids_again = expired_typing_wake_ids(&conn, &typing, t0 + Duration::from_millis(600));
        assert!(ids_again.is_empty(), "a room with no NEWLY expired typing flag must not be reported again");
    }

    #[test]
    fn expired_typing_wake_ids_is_empty_when_nothing_is_typing() {
        let conn = test_conn();
        let typing = live::TypingRegistry::new();
        assert!(expired_typing_wake_ids(&conn, &typing, Instant::now()).is_empty());
    }
}

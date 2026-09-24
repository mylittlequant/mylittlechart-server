//! Matrix messaging routes — `send`, `messages`, `event`, `redact`,
//! `relations` (P6). See
//! `docs/mlc/plans/messenger-proto-server-matrix-subset-2026-09-24.md` §4
//! (endpoint table + gate definitions) and the P6 brief's binding rules
//! (send's idempotency/type/encrypted-room refusals, `/messages`'s token
//! format and history-visibility enforcement, redact's own-event bypass,
//! the send-rate limits).
//!
//! # Pagination tokens
//!
//! `GET /messages` and `GET /relations` both page over `messenger.db`'s one
//! global stream order using the SAME opaque token shape:
//! [`format_stream_token`]/[`parse_stream_token`] — `"t{stream_id}"`, a
//! position strictly between two adjacent stream ids (a bare `"0"` also
//! parses, naming the very beginning of the room, before any event ever
//! existed). Both routes clamp their own `limit` to `[1, 100]`
//! ([`MESSAGES_DEFAULT_LIMIT`]/[`MESSAGES_MAX_LIMIT`], `10` default).
//!
//! # History visibility
//!
//! `/messages`, `/event`, and `/relations` all gate on
//! [`matrix_store::visible_upper_bound`] rather than the plain `PubRead` gate
//! `routes::matrix::rooms` uses elsewhere: a member who has since `leave`/
//! `ban`-transitioned must still read everything UP TO their own departure
//! (plan binding rule), which is strictly MORE than a flat Member-or-
//! world-readable check would allow. See that function's own doc for the
//! full rule; every truncation this module applies (window cap, an explicit
//! `to=` boundary) is folded into a single "no further page beyond this
//! point" decision so a client is never handed an `end`/`next_batch` token
//! that would let it page past what it is allowed to see.
//!
//! # No bundled relation aggregations
//!
//! `unsigned.m.relations` (a rolled-up reaction/edit summary Matrix's own
//! spec allows a homeserver to attach) is NOT computed anywhere in this
//! module for v1 — the client aggregates reactions/edits itself from the
//! plain event stream (`GET /relations` and `/sync`'s own timeline), and is
//! expected to queue a relation that arrives before it has seen its target
//! (plan decision, stated here per the P6 brief).
//!
//! # Every write is one transaction, then one wake
//!
//! Same discipline as `routes::matrix::rooms` (see that module's own doc):
//! [`apply_send`]/[`apply_redact`] do their whole DB decision + write inside
//! one `&mut Connection` borrow (their own dedup-check-then-insert is one
//! SQL transaction, `matrix_store::insert_timeline_event_deduped`/
//! `redact_event_deduped`), and the caller wakes
//! [`super::rooms::member_and_invited_ids`] — reused verbatim, not
//! re-derived — only AFTER `spawn_blocking` returns.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::{get, put};
use axum::{Json, Router};
use rusqlite::Connection;

use mylittlechart_server::matrix_store::{self, JoinRule, Membership, PowerAction, Room, TxnDedupEntry};

use super::auth;
use super::{client_event_json, MatrixError};
use crate::db;
use crate::state::AppState;

// ============================================================================
// Rate limits (plan §3.8) — own copies per this codebase's
// one-copy-per-route-module convention (mirrors `dm_db::DM_MESSAGE_DAILY_LIMIT`
// via `routes::dm::create_message`'s own daily check).
// ============================================================================

/// Per-sender messages-per-day cap in private rooms, mirroring
/// [`dm_db`](crate::dm_db)'s own `DM_MESSAGE_DAILY_LIMIT` value.
const MATRIX_SEND_DAILY_LIMIT: i64 = 300;
/// Short-window burst cap: at most this many sends/redacts per device.
const BURST_LIMIT_COUNT: i64 = 20;
/// ...within this many seconds.
const BURST_LIMIT_WINDOW_SECS: i64 = 10;

const ONE_DAY_MS: u64 = 24 * 60 * 60 * 1000;

fn check_rate_limits(conn: &Connection, user_id: i64, device_id: &str, now: &str) -> Result<(), MatrixError> {
    let now_dt = chrono::DateTime::parse_from_rfc3339(now).map_err(|_| MatrixError::internal())?;

    let since_ms = (now_dt - chrono::Duration::hours(24)).timestamp_millis();
    let daily = matrix_store::private_room_messages_sent_since(conn, user_id, since_ms)?;
    if daily >= MATRIX_SEND_DAILY_LIMIT {
        return Err(MatrixError::limit_exceeded(ONE_DAY_MS));
    }

    let burst_since = (now_dt - chrono::Duration::seconds(BURST_LIMIT_WINDOW_SECS)).to_rfc3339();
    let burst = matrix_store::txn_dedup_count_since(conn, user_id, device_id, &burst_since)?;
    if burst >= BURST_LIMIT_COUNT {
        return Err(MatrixError::limit_exceeded(BURST_LIMIT_WINDOW_SECS as u64 * 1000));
    }
    Ok(())
}

// ============================================================================
// Pagination tokens and limits — shared by `/messages` and `/relations`
// ============================================================================

const MESSAGES_DEFAULT_LIMIT: i64 = 10;
const MESSAGES_MAX_LIMIT: i64 = 100;

/// `"t{stream_id}"`, or a bare `"0"` — see the module doc.
fn parse_stream_token(raw: &str) -> Result<i64, MatrixError> {
    let digits = raw.strip_prefix('t').unwrap_or(raw);
    digits.parse::<i64>().map_err(|_| MatrixError::invalid_param("malformed pagination token"))
}

fn format_stream_token(stream_id: i64) -> String {
    format!("t{stream_id}")
}

fn clamp_limit(requested: Option<i64>) -> i64 {
    requested.unwrap_or(MESSAGES_DEFAULT_LIMIT).clamp(1, MESSAGES_MAX_LIMIT)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Backward,
    Forward,
}

impl Direction {
    fn from_query(raw: Option<&str>) -> Result<Self, MatrixError> {
        match raw.unwrap_or("b") {
            "b" => Ok(Direction::Backward),
            "f" => Ok(Direction::Forward),
            _ => Err(MatrixError::invalid_param("dir must be 'b' or 'f'")),
        }
    }
}

#[derive(serde::Deserialize, Default, Clone)]
struct EventFilter {
    #[serde(default)]
    types: Option<Vec<String>>,
    #[serde(default)]
    not_types: Option<Vec<String>>,
    #[serde(default)]
    lazy_load_members: bool,
}

fn event_passes_filter(event_type: &str, filter: &EventFilter) -> bool {
    if let Some(types) = &filter.types {
        if !types.iter().any(|t| t == event_type) {
            return false;
        }
    }
    if let Some(not_types) = &filter.not_types {
        if not_types.iter().any(|t| t == event_type) {
            return false;
        }
    }
    true
}

fn parse_filter(raw: Option<&str>) -> Result<EventFilter, MatrixError> {
    match raw {
        Some(raw) => serde_json::from_str(raw).map_err(|_| MatrixError::invalid_param("malformed filter")),
        None => Ok(EventFilter::default()),
    }
}

// ============================================================================
// DB-only gate/read helpers — own copies of `routes::matrix::rooms`'s small
// checks (per this codebase's one-copy-per-route-module convention); only
// `member_and_invited_ids` (the wake fan-out set) is reused verbatim — see
// the module doc.
// ============================================================================

fn power_levels_of(conn: &Connection, room_id: &str) -> Result<serde_json::Value, MatrixError> {
    match matrix_store::current_state_event(conn, room_id, "m.room.power_levels", "")? {
        Some(event) => Ok(serde_json::from_str(&event.content)?),
        None => Ok(serde_json::json!({})),
    }
}

fn require_member(membership: Option<Membership>) -> Result<(), MatrixError> {
    match membership {
        Some(Membership::Join) => Ok(()),
        _ => Err(MatrixError::forbidden("not a member of this room")),
    }
}

fn require_power(power_levels: &serde_json::Value, mxid: &str, action: PowerAction) -> Result<(), MatrixError> {
    if matrix_store::can(power_levels, action, mxid) {
        Ok(())
    } else {
        Err(MatrixError::forbidden("insufficient power level for this action"))
    }
}

/// [`auth::is_messenger_paid`]'s ladder check, resolved fresh — own copy of
/// `routes::matrix::rooms::is_paid_now`.
fn is_paid_now(cp: &crate::state::ControlPlane, user_id: i64) -> rusqlite::Result<bool> {
    let is_paid_flag = {
        let identity_conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
        db::user_is_paid(&identity_conn, user_id)?
    };
    let social_conn = cp.social_conn();
    Ok(auth::is_messenger_paid(&social_conn, user_id, is_paid_flag))
}

// ============================================================================
// Pure decision functions — no DB, no `MatrixCaller`, unit-tested directly
// ============================================================================

/// Every state-event type `PUT /state/{eventType}/{stateKey}` owns, refused
/// outright on `/send` (P6 binding rule) — includes our own
/// `org.mylittlechart.legacy_dm_key` alongside the standard `m.room.*` state
/// types.
const REFUSED_SEND_STATE_TYPES: [&str; 10] = [
    "m.room.create",
    "m.room.member",
    "m.room.power_levels",
    "m.room.join_rules",
    "m.room.history_visibility",
    "m.room.name",
    "m.room.topic",
    "m.room.avatar",
    "m.room.encryption",
    "m.room.pinned_events",
];
const LEGACY_DM_KEY_STATE_TYPE: &str = "org.mylittlechart.legacy_dm_key";

/// `PUT /send/{eventType}/{txnId}`'s type-refusal rule (P6 binding rule):
/// state-event types and `org.mylittlechart.legacy_dm_key` go through
/// `/state`; `org.mylittlechart.legacy_dm` is migration-only; `m.room.redaction`
/// goes through `/redact`; and, in an encrypted room, only `m.room.encrypted`
/// and `m.reaction` (server-visible metadata, coordinator ruling) are
/// accepted at all.
fn check_send_event_type_allowed(event_type: &str, room_is_encrypted: bool) -> Result<(), MatrixError> {
    if REFUSED_SEND_STATE_TYPES.contains(&event_type) || event_type == LEGACY_DM_KEY_STATE_TYPE {
        return Err(MatrixError::bad_json(format!("{event_type} is a state event; send it via PUT /state/{{eventType}}/{{stateKey}}")));
    }
    if event_type == "org.mylittlechart.legacy_dm" {
        return Err(MatrixError::forbidden("org.mylittlechart.legacy_dm is migration-only and cannot be sent by a client"));
    }
    if event_type == "m.room.redaction" {
        return Err(MatrixError::bad_json("use PUT /rooms/{roomId}/redact/{eventId}/{txnId} to redact an event"));
    }
    if room_is_encrypted && event_type != "m.room.encrypted" && event_type != "m.reaction" {
        return Err(MatrixError::forbidden("only m.room.encrypted and m.reaction may be sent in an encrypted room"));
    }
    Ok(())
}

/// An `m.replace` must come from the target event's ORIGINAL sender (P6
/// binding rule) — a no-op for content with no `m.relates_to`, or a
/// `rel_type` other than `m.replace`.
fn check_replace_target_sender(conn: &Connection, content: &serde_json::Value, sender_user_id: i64) -> Result<(), MatrixError> {
    let Some(relates_to) = content.get("m.relates_to") else { return Ok(()) };
    if relates_to.get("rel_type").and_then(|v| v.as_str()) != Some("m.replace") {
        return Ok(());
    }
    let Some(target_id) = relates_to.get("event_id").and_then(|v| v.as_str()) else { return Ok(()) };
    let target = matrix_store::get_event(conn, target_id)?.ok_or_else(|| MatrixError::not_found("relation target not found"))?;
    if target.sender_user_id != sender_user_id {
        return Err(MatrixError::invalid_param("m.replace must be sent by the target event's original sender"));
    }
    Ok(())
}

// ============================================================================
// DB-only action cores — `&mut Connection`, no `MatrixCaller`, unit-tested
// directly against an in-memory `matrix_store` fixture
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
struct SendOutcome {
    event: matrix_store::MatrixEvent,
    is_new: bool,
    wake_ids: HashSet<i64>,
}

/// `PUT /send/{eventType}/{txnId}`'s whole DB-side decision + write (plan §4
/// `send` row): txn-dedup peek first (a repeat short-circuits everything
/// else and returns the ORIGINAL event, per the idempotency rule); then
/// Member, + Paid iff the room is private (`join_rule = invite`), the
/// type-refusal rule, PowerCheck(`events[type]` else `events_default`), the
/// send-rate limits, and the `m.replace`-sender rule; then the dedup-checked
/// insert itself.
#[allow(clippy::too_many_arguments)]
fn apply_send(
    conn: &mut Connection,
    room: &Room,
    caller_user_id: i64,
    caller_mxid: &str,
    is_paid: bool,
    device_id: &str,
    txn_id: &str,
    event_id: &str,
    event_type: &str,
    content_str: &str,
    now: &str,
    origin_ts: i64,
) -> Result<SendOutcome, MatrixError> {
    if let TxnDedupEntry::Seen(existing_event_id) = matrix_store::txn_dedup_lookup(conn, caller_user_id, device_id, txn_id)? {
        let existing_event_id = existing_event_id.ok_or_else(MatrixError::internal)?;
        let event = matrix_store::get_event(conn, &existing_event_id)?.ok_or_else(MatrixError::internal)?;
        return Ok(SendOutcome { event, is_new: false, wake_ids: HashSet::new() });
    }

    let caller_membership = matrix_store::room_member(conn, &room.id, caller_user_id)?.map(|m| m.membership);
    require_member(caller_membership)?;
    if room.join_rule == JoinRule::Invite && !is_paid {
        return Err(MatrixError::forbidden("paid account required to send in a private room"));
    }
    check_send_event_type_allowed(event_type, room.is_encrypted)?;

    let power_levels = power_levels_of(conn, &room.id)?;
    if matrix_store::user_level(&power_levels, caller_mxid) < matrix_store::event_level(&power_levels, event_type, false) {
        return Err(MatrixError::forbidden("insufficient power level to send this event"));
    }

    check_rate_limits(conn, caller_user_id, device_id, now)?;

    let content: serde_json::Value = serde_json::from_str(content_str)?;
    check_replace_target_sender(conn, &content, caller_user_id)?;

    match matrix_store::insert_timeline_event_deduped(conn, device_id, txn_id, event_id, &room.id, caller_user_id, event_type, content_str, origin_ts, now)? {
        matrix_store::DedupedWrite::New(event) => {
            let wake_ids = super::rooms::member_and_invited_ids(conn, &room.id)?;
            Ok(SendOutcome { event, is_new: true, wake_ids })
        }
        // Cannot happen — the peek above already established `NotSeen`
        // under the same connection, and this module's single-writer
        // discipline means nothing else can have raced it — but handled
        // defensively rather than panicking.
        matrix_store::DedupedWrite::Existing(event) => Ok(SendOutcome { event, is_new: false, wake_ids: HashSet::new() }),
    }
}

#[derive(Debug, Clone, PartialEq)]
struct RedactOutcome {
    event: matrix_store::MatrixEvent,
    is_new: bool,
    wake_ids: HashSet<i64>,
}

/// `PUT /redact/{eventId}/{txnId}`'s whole DB-side decision + write (plan §4
/// `redact` row): txn-dedup peek first; then Member; then own-event OR
/// PowerCheck(redact) — redact does NOT require the sender's level to
/// exceed the target's own level (spec rule, unlike kick/ban/unban); then
/// the dedup-checked redaction itself (which enforces the v11
/// unredactable-event-type rule and maps to 403 via
/// `MatrixStoreError::UnredactableEvent`).
#[allow(clippy::too_many_arguments)]
fn apply_redact(
    conn: &mut Connection,
    room_id: &str,
    caller_user_id: i64,
    caller_mxid: &str,
    device_id: &str,
    txn_id: &str,
    target_event_id: &str,
    redaction_event_id: &str,
    reason: Option<&str>,
    now: &str,
    origin_ts: i64,
) -> Result<RedactOutcome, MatrixError> {
    if let TxnDedupEntry::Seen(existing_event_id) = matrix_store::txn_dedup_lookup(conn, caller_user_id, device_id, txn_id)? {
        let existing_event_id = existing_event_id.ok_or_else(MatrixError::internal)?;
        let event = matrix_store::get_event(conn, &existing_event_id)?.ok_or_else(MatrixError::internal)?;
        return Ok(RedactOutcome { event, is_new: false, wake_ids: HashSet::new() });
    }

    let caller_membership = matrix_store::room_member(conn, room_id, caller_user_id)?.map(|m| m.membership);
    require_member(caller_membership)?;

    let target = matrix_store::get_event(conn, target_event_id)?.ok_or_else(|| MatrixError::not_found("no such event"))?;
    if target.room_id != room_id {
        return Err(MatrixError::not_found("no such event"));
    }
    if target.sender_user_id != caller_user_id {
        let power_levels = power_levels_of(conn, room_id)?;
        require_power(&power_levels, caller_mxid, PowerAction::Redact)?;
    }

    match matrix_store::redact_event_deduped(conn, device_id, txn_id, room_id, target_event_id, redaction_event_id, caller_user_id, reason, origin_ts, now)? {
        matrix_store::DedupedWrite::New(event) => {
            let wake_ids = super::rooms::member_and_invited_ids(conn, room_id)?;
            Ok(RedactOutcome { event, is_new: true, wake_ids })
        }
        matrix_store::DedupedWrite::Existing(event) => Ok(RedactOutcome { event, is_new: false, wake_ids: HashSet::new() }),
    }
}

/// One page of `/messages`' timeline window — [`get_messages`]'s own DB-only
/// core, unit-tested directly.
struct MessagesPage {
    chunk: Vec<matrix_store::MatrixEvent>,
    start: String,
    /// `None` when there is nothing further this caller could ever see
    /// beyond this page (the physical edge of the room, the caller's own
    /// [`matrix_store::HistoryWindow`], or an explicit `to=` boundary) —
    /// NEVER `None` merely because a `types`/`not_types` filter thinned this
    /// particular page (more matching events could still exist further on).
    end: Option<String>,
}

#[allow(clippy::too_many_arguments)]
fn paginate_messages(
    conn: &Connection,
    room_id: &str,
    window: matrix_store::HistoryWindow,
    from_stream: i64,
    to_stream: Option<i64>,
    dir: Direction,
    limit: i64,
    filter: &EventFilter,
) -> rusqlite::Result<MessagesPage> {
    let raw_page = match dir {
        Direction::Backward => matrix_store::events_in_room_before(conn, room_id, from_stream, limit)?,
        Direction::Forward => matrix_store::events_in_room_after(conn, room_id, from_stream, limit)?,
    };
    let raw_len = raw_page.len();

    let hard_truncated = |e: &matrix_store::MatrixEvent| -> bool {
        if !window.contains(e.stream_id) {
            return true;
        }
        match (to_stream, dir) {
            (Some(to), Direction::Backward) => e.stream_id <= to,
            (Some(to), Direction::Forward) => e.stream_id >= to,
            (None, _) => false,
        }
    };
    let any_hard_truncated = raw_page.iter().any(hard_truncated);
    let chunk: Vec<matrix_store::MatrixEvent> =
        raw_page.iter().filter(|e| !hard_truncated(e) && event_passes_filter(&e.event_type, filter)).cloned().collect();

    let end = if raw_len < limit as usize || any_hard_truncated {
        None
    } else {
        raw_page.last().map(|e| format_stream_token(e.stream_id))
    };

    Ok(MessagesPage { chunk, start: format_stream_token(from_stream), end })
}

fn lazy_load_member_state(conn: &Connection, room_id: &str, chunk: &[matrix_store::MatrixEvent]) -> Result<Vec<serde_json::Value>, MatrixError> {
    let mut senders: Vec<i64> = chunk.iter().map(|e| e.sender_user_id).collect();
    senders.sort_unstable();
    senders.dedup();

    let mut out = Vec::new();
    for sender in senders {
        let Some(mxid) = matrix_store::mxid_of(conn, sender)? else { continue };
        if let Some(event) = matrix_store::current_state_event(conn, room_id, "m.room.member", &mxid)? {
            out.push(client_event_json(conn, &event, None)?);
        }
    }
    Ok(out)
}

// ============================================================================
// PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}
// ============================================================================

async fn send_event(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((room_id, event_type, txn_id)): Path<(String, String, String)>,
    Json(content): Json<serde_json::Value>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;

    let content_str = content.to_string();
    if content_str.len() > matrix_store::MATRIX_EVENT_CONTENT_MAX_BYTES {
        return Err(MatrixError::bad_json("event content too large"));
    }

    let device_id = caller.device_id.clone();
    let state_for_blocking = state.clone();
    let (event_id, wake_ids) = tokio::task::spawn_blocking(move || -> Result<(String, HashSet<i64>), MatrixError> {
        let cp = state_for_blocking.control_plane();

        let room = matrix_store::get_room(&cp.messenger_conn(), &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        let is_paid = if room.join_rule == JoinRule::Invite { is_paid_now(cp, caller.user_id)? } else { true };

        let now = chrono::Utc::now().to_rfc3339();
        let origin_ts = chrono::Utc::now().timestamp_millis();
        let event_id = matrix_store::new_event_id();

        let mut messenger_conn = cp.messenger_conn();
        let outcome = apply_send(
            &mut messenger_conn,
            &room,
            caller.user_id,
            &caller.mxid,
            is_paid,
            &device_id,
            &txn_id,
            &event_id,
            &event_type,
            &content_str,
            &now,
            origin_ts,
        )?;
        Ok((outcome.event.event_id, outcome.wake_ids))
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    state.control_plane().live.wake_many(wake_ids.into_iter().map(|id| format!("user:{id}")));
    Ok(Json(serde_json::json!({ "event_id": event_id })))
}

// ============================================================================
// PUT /_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}
// ============================================================================

#[derive(serde::Deserialize, Default)]
struct RedactBody {
    #[serde(default)]
    reason: Option<String>,
}

async fn redact_event_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((room_id, target_event_id, txn_id)): Path<(String, String, String)>,
    Json(body): Json<RedactBody>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let device_id = caller.device_id.clone();
    let state_for_blocking = state.clone();

    let (event_id, wake_ids) = tokio::task::spawn_blocking(move || -> Result<(String, HashSet<i64>), MatrixError> {
        let cp = state_for_blocking.control_plane();
        matrix_store::get_room(&cp.messenger_conn(), &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;

        let now = chrono::Utc::now().to_rfc3339();
        let origin_ts = chrono::Utc::now().timestamp_millis();
        let redaction_event_id = matrix_store::new_event_id();

        let mut messenger_conn = cp.messenger_conn();
        let outcome = apply_redact(
            &mut messenger_conn,
            &room_id,
            caller.user_id,
            &caller.mxid,
            &device_id,
            &txn_id,
            &target_event_id,
            &redaction_event_id,
            body.reason.as_deref(),
            &now,
            origin_ts,
        )?;
        Ok((outcome.event.event_id, outcome.wake_ids))
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    state.control_plane().live.wake_many(wake_ids.into_iter().map(|id| format!("user:{id}")));
    Ok(Json(serde_json::json!({ "event_id": event_id })))
}

// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/messages
// ============================================================================

#[derive(serde::Deserialize)]
struct MessagesQuery {
    from: String,
    #[serde(default)]
    to: Option<String>,
    #[serde(default)]
    dir: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    filter: Option<String>,
}

async fn get_messages(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Query(query): Query<MessagesQuery>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let dir = Direction::from_query(query.dir.as_deref())?;
    let from_stream = parse_stream_token(&query.from)?;
    let to_stream = query.to.as_deref().map(parse_stream_token).transpose()?;
    let limit = clamp_limit(query.limit);
    let filter = parse_filter(query.filter.as_deref())?;

    let body = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
        let cp = state.control_plane();
        let messenger_conn = cp.messenger_conn();
        let room = matrix_store::get_room(&messenger_conn, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        let window = matrix_store::visible_upper_bound(&messenger_conn, &room, caller.user_id)?;
        if window == matrix_store::HistoryWindow::Nothing {
            return Err(MatrixError::forbidden("no read access to this room"));
        }

        let page = paginate_messages(&messenger_conn, &room_id, window, from_stream, to_stream, dir, limit, &filter)?;
        let mut chunk_json = Vec::with_capacity(page.chunk.len());
        for event in &page.chunk {
            let own_txn_id = matrix_store::txn_id_for_event(&messenger_conn, caller.user_id, &caller.device_id, &event.event_id)?;
            chunk_json.push(client_event_json(&messenger_conn, event, own_txn_id.as_deref())?);
        }

        let mut body = serde_json::json!({ "chunk": chunk_json, "start": page.start });
        if let Some(end) = &page.end {
            body["end"] = serde_json::Value::String(end.clone());
        }
        if filter.lazy_load_members {
            body["state"] = serde_json::Value::Array(lazy_load_member_state(&messenger_conn, &room_id, &page.chunk)?);
        }
        Ok(body)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(body))
}

// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/event/{eventId}
// ============================================================================

async fn get_event(State(state): State<Arc<AppState>>, headers: HeaderMap, Path((room_id, event_id)): Path<(String, String)>) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;

    let body = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
        let cp = state.control_plane();
        let messenger_conn = cp.messenger_conn();
        let room = matrix_store::get_room(&messenger_conn, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        let window = matrix_store::visible_upper_bound(&messenger_conn, &room, caller.user_id)?;
        if window == matrix_store::HistoryWindow::Nothing {
            return Err(MatrixError::forbidden("no read access to this room"));
        }
        let event = matrix_store::get_event(&messenger_conn, &event_id)?
            .filter(|e| e.room_id == room_id)
            .ok_or_else(|| MatrixError::not_found("no such event"))?;
        if !window.contains(event.stream_id) {
            return Err(MatrixError::forbidden("event is outside your visible history"));
        }
        let own_txn_id = matrix_store::txn_id_for_event(&messenger_conn, caller.user_id, &caller.device_id, &event.event_id)?;
        client_event_json(&messenger_conn, &event, own_txn_id.as_deref())
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(body))
}

// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/relations/{eventId}[/{relType}[/{eventType}]]
// ============================================================================

#[derive(serde::Deserialize, Default)]
struct RelationsQuery {
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

async fn get_relations_inner(
    state: Arc<AppState>,
    headers: HeaderMap,
    room_id: String,
    event_id: String,
    rel_type: Option<String>,
    event_type: Option<String>,
    query: RelationsQuery,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let before_stream = match &query.from {
        Some(raw) => parse_stream_token(raw)?,
        None => i64::MAX,
    };
    let limit = clamp_limit(query.limit);

    let body = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
        let cp = state.control_plane();
        let messenger_conn = cp.messenger_conn();
        let room = matrix_store::get_room(&messenger_conn, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        let window = matrix_store::visible_upper_bound(&messenger_conn, &room, caller.user_id)?;
        if window == matrix_store::HistoryWindow::Nothing {
            return Err(MatrixError::forbidden("no read access to this room"));
        }
        let target = matrix_store::get_event(&messenger_conn, &event_id)?
            .filter(|e| e.room_id == room_id)
            .ok_or_else(|| MatrixError::not_found("no such event"))?;
        if !window.contains(target.stream_id) {
            return Err(MatrixError::forbidden("event is outside your visible history"));
        }

        let raw_page = matrix_store::relations_of(&messenger_conn, &event_id, rel_type.as_deref(), event_type.as_deref(), before_stream, limit)?;
        let raw_len = raw_page.len();
        let any_window_truncated = raw_page.iter().any(|e| !window.contains(e.stream_id));
        let chunk: Vec<&matrix_store::MatrixEvent> = raw_page.iter().filter(|e| window.contains(e.stream_id)).collect();

        let mut chunk_json = Vec::with_capacity(chunk.len());
        for event in &chunk {
            chunk_json.push(client_event_json(&messenger_conn, event, None)?);
        }

        let mut body = serde_json::json!({ "chunk": chunk_json });
        if raw_len == limit as usize && !any_window_truncated {
            if let Some(last) = raw_page.last() {
                body["next_batch"] = serde_json::Value::String(format_stream_token(last.stream_id));
            }
        }
        Ok(body)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(body))
}

async fn get_relations_all(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((room_id, event_id)): Path<(String, String)>,
    Query(query): Query<RelationsQuery>,
) -> Result<impl IntoResponse, MatrixError> {
    get_relations_inner(state, headers, room_id, event_id, None, None, query).await
}

async fn get_relations_by_rel_type(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((room_id, event_id, rel_type)): Path<(String, String, String)>,
    Query(query): Query<RelationsQuery>,
) -> Result<impl IntoResponse, MatrixError> {
    get_relations_inner(state, headers, room_id, event_id, Some(rel_type), None, query).await
}

async fn get_relations_by_rel_type_and_event_type(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((room_id, event_id, rel_type, event_type)): Path<(String, String, String, String)>,
    Query(query): Query<RelationsQuery>,
) -> Result<impl IntoResponse, MatrixError> {
    get_relations_inner(state, headers, room_id, event_id, Some(rel_type), Some(event_type), query).await
}

// ============================================================================
// Router
// ============================================================================

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}", put(send_event))
        .route("/client/v3/rooms/{room_id}/redact/{event_id}/{txn_id}", put(redact_event_handler))
        .route("/client/v3/rooms/{room_id}/messages", get(get_messages))
        .route("/client/v3/rooms/{room_id}/event/{event_id}", get(get_event))
        .route("/client/v3/rooms/{room_id}/relations/{event_id}", get(get_relations_all))
        .route("/client/v3/rooms/{room_id}/relations/{event_id}/{rel_type}", get(get_relations_by_rel_type))
        .route(
            "/client/v3/rooms/{room_id}/relations/{event_id}/{rel_type}/{event_type}",
            get(get_relations_by_rel_type_and_event_type),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: &str = "2026-09-24T00:00:00+00:00";

    fn test_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        matrix_store::create_matrix_schema(&conn).expect("matrix schema");
        conn
    }

    fn make_room(conn: &Connection, room_id: &str, kind: matrix_store::RoomKind, creator: i64) {
        let (join_rule, history_visibility, is_encrypted) = match kind {
            matrix_store::RoomKind::Dm | matrix_store::RoomKind::Group => (JoinRule::Invite, matrix_store::HistoryVisibility::Shared, true),
            matrix_store::RoomKind::Channel => (JoinRule::Public, matrix_store::HistoryVisibility::WorldReadable, false),
        };
        matrix_store::create_room(conn, room_id, kind, creator, T0, is_encrypted, join_rule, history_visibility, None, None).expect("create room");
    }

    // ---- plan §9 P6 test 1 ----

    #[test]
    fn send_refuses_plaintext_m_room_message_in_an_encrypted_room() {
        assert!(check_send_event_type_allowed("m.room.message", true).is_err());
        assert!(check_send_event_type_allowed("m.room.encrypted", true).is_ok());
    }

    // ---- plan §9 P6 test 2 ----

    #[test]
    fn send_in_a_private_room_requires_paid_send_in_a_public_channel_does_not() {
        let mut conn = test_conn();
        make_room(&conn, "!priv:mylittlechart.org", matrix_store::RoomKind::Group, 1);
        let alice = matrix_store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000060", T0).expect("alice");
        matrix_store::apply_state_event(&mut conn, "$m1", "!priv:mylittlechart.org", 1, "m.room.member", &alice, r#"{"membership":"join"}"#, 1000, T0)
            .expect("alice joins");
        let room = matrix_store::get_room(&conn, "!priv:mylittlechart.org").expect("room").expect("exists");

        let err = apply_send(&mut conn, &room, 1, &alice, false, "DEV1", "txn-1", "$e1", "m.room.encrypted", "{}", T0, 2000).unwrap_err();
        assert_eq!(err.errcode, "M_FORBIDDEN", "an unpaid caller cannot send in a private (invite-join-rule) room");

        let outcome = apply_send(&mut conn, &room, 1, &alice, true, "DEV1", "txn-2", "$e2", "m.room.encrypted", "{}", T0, 3000).expect("a paid caller may send");
        assert!(outcome.is_new);

        make_room(&conn, "!chan:mylittlechart.org", matrix_store::RoomKind::Channel, 1);
        matrix_store::apply_state_event(&mut conn, "$m2", "!chan:mylittlechart.org", 1, "m.room.member", &alice, r#"{"membership":"join"}"#, 1000, T0)
            .expect("alice joins the channel");
        let channel = matrix_store::get_room(&conn, "!chan:mylittlechart.org").expect("room").expect("exists");
        let outcome2 =
            apply_send(&mut conn, &channel, 1, &alice, false, "DEV1", "txn-3", "$e3", "m.room.message", "{}", T0, 4000).expect("an unpaid caller may send in a public channel");
        assert!(outcome2.is_new);
    }

    // ---- plan §9 P6 test 3 ----

    #[test]
    fn redact_own_event_succeeds_without_power_redact_from_another_users_event_requires_it() {
        let mut conn = test_conn();
        make_room(&conn, "!r:mylittlechart.org", matrix_store::RoomKind::Group, 1);
        let alice = matrix_store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000061", T0).expect("alice");
        matrix_store::ensure_matrix_user(&conn, 2, "bob0000000000000000000000000061", T0).expect("bob");
        matrix_store::apply_state_event(&mut conn, "$m1", "!r:mylittlechart.org", 1, "m.room.member", &alice, r#"{"membership":"join"}"#, 1000, T0).expect("alice joins");

        let alice_event = matrix_store::insert_timeline_event(&mut conn, "$alice1", "!r:mylittlechart.org", 1, "m.room.message", "{}", 2000, None).expect("alice sends");
        let outcome = apply_redact(&mut conn, "!r:mylittlechart.org", 1, &alice, "DEV1", "txn-own", &alice_event.event_id, "$red1", None, T0, 3000)
            .expect("own-event redact succeeds without any power_levels grant");
        assert!(outcome.is_new);

        let bob_event = matrix_store::insert_timeline_event(&mut conn, "$bob1", "!r:mylittlechart.org", 2, "m.room.message", "{}", 4000, None).expect("bob sends");
        let err = apply_redact(&mut conn, "!r:mylittlechart.org", 1, &alice, "DEV1", "txn-other", &bob_event.event_id, "$red2", None, T0, 5000).unwrap_err();
        assert_eq!(err.errcode, "M_FORBIDDEN", "redacting someone else's event requires PowerCheck(redact)");
    }

    #[test]
    fn send_is_idempotent_per_txn_id() {
        let mut conn = test_conn();
        make_room(&conn, "!r:mylittlechart.org", matrix_store::RoomKind::Channel, 1);
        let alice = matrix_store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000062", T0).expect("alice");
        matrix_store::apply_state_event(&mut conn, "$m1", "!r:mylittlechart.org", 1, "m.room.member", &alice, r#"{"membership":"join"}"#, 1000, T0).expect("alice joins");
        let room = matrix_store::get_room(&conn, "!r:mylittlechart.org").expect("room").expect("exists");

        let first = apply_send(&mut conn, &room, 1, &alice, true, "DEV1", "txn-dup", "$e1", "m.room.message", "{}", T0, 2000).expect("first send");
        assert!(first.is_new);
        let second =
            apply_send(&mut conn, &room, 1, &alice, true, "DEV1", "txn-dup", "$e2-should-be-ignored", "m.room.message", "{}", T0, 3000).expect("repeat of the same txn_id");
        assert!(!second.is_new, "a repeated txn_id must not insert a second event");
        assert_eq!(first.event.event_id, second.event.event_id, "a repeated txn_id must return the SAME event_id");
    }

    #[test]
    fn send_refuses_state_types_and_redaction_type() {
        for state_type in REFUSED_SEND_STATE_TYPES.iter().chain([&LEGACY_DM_KEY_STATE_TYPE]) {
            let err = check_send_event_type_allowed(state_type, false).unwrap_err();
            assert_eq!(err.errcode, "M_BAD_JSON", "{state_type} must be refused as a state event, not a send");
        }
        let err = check_send_event_type_allowed("m.room.redaction", false).unwrap_err();
        assert_eq!(err.errcode, "M_BAD_JSON");
        let err = check_send_event_type_allowed("org.mylittlechart.legacy_dm", false).unwrap_err();
        assert_eq!(err.errcode, "M_FORBIDDEN");
    }

    #[test]
    fn encrypted_room_allows_only_encrypted_and_reaction() {
        assert!(check_send_event_type_allowed("m.room.encrypted", true).is_ok());
        assert!(check_send_event_type_allowed("m.reaction", true).is_ok());
        for refused in ["m.room.message", "m.sticker", "org.example.custom"] {
            let err = check_send_event_type_allowed(refused, true).unwrap_err();
            assert_eq!(err.errcode, "M_FORBIDDEN");
        }
        for allowed in ["m.room.message", "m.sticker", "org.example.custom", "m.reaction"] {
            assert!(check_send_event_type_allowed(allowed, false).is_ok(), "{allowed} is fine in an unencrypted room");
        }
    }

    #[test]
    fn replace_from_another_sender_is_refused() {
        let mut conn = test_conn();
        make_room(&conn, "!r:mylittlechart.org", matrix_store::RoomKind::Group, 1);
        let target = matrix_store::insert_timeline_event(&mut conn, "$target", "!r:mylittlechart.org", 1, "m.room.encrypted", "{}", 1000, None).expect("target");

        let replace_content = serde_json::json!({ "m.relates_to": { "rel_type": "m.replace", "event_id": target.event_id } });
        let err = check_replace_target_sender(&conn, &replace_content, 2).unwrap_err();
        assert_eq!(err.errcode, "M_INVALID_PARAM");
        check_replace_target_sender(&conn, &replace_content, 1).expect("the original sender may replace their own event");

        let unrelated_content = serde_json::json!({ "body": "hi" });
        check_replace_target_sender(&conn, &unrelated_content, 2).expect("content with no m.relates_to is always fine");
    }

    #[test]
    fn burst_rate_limit_returns_limit_exceeded() {
        let mut conn = test_conn();
        make_room(&conn, "!r:mylittlechart.org", matrix_store::RoomKind::Channel, 1);
        let alice = matrix_store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000063", T0).expect("alice");
        matrix_store::apply_state_event(&mut conn, "$m1", "!r:mylittlechart.org", 1, "m.room.member", &alice, r#"{"membership":"join"}"#, 1000, T0).expect("alice joins");
        let room = matrix_store::get_room(&conn, "!r:mylittlechart.org").expect("room").expect("exists");

        for i in 0..BURST_LIMIT_COUNT {
            let outcome = apply_send(&mut conn, &room, 1, &alice, true, "DEV1", &format!("txn-{i}"), &format!("$e{i}"), "m.room.message", "{}", T0, 2000 + i)
                .expect("under the burst cap");
            assert!(outcome.is_new);
        }

        let err = apply_send(&mut conn, &room, 1, &alice, true, "DEV1", "txn-over", "$e-over", "m.room.message", "{}", T0, 9999).unwrap_err();
        assert_eq!(err.errcode, "M_LIMIT_EXCEEDED");
        assert!(err.retry_after_ms.is_some());
    }

    #[test]
    fn messages_paginates_backwards_and_forwards_with_tokens() {
        let mut conn = test_conn();
        make_room(&conn, "!r:mylittlechart.org", matrix_store::RoomKind::Channel, 1);
        for i in 1..=5i64 {
            matrix_store::insert_timeline_event(&mut conn, &format!("$e{i}"), "!r:mylittlechart.org", 1, "m.room.message", "{}", 1000 * i, None).expect("insert");
        }
        let latest = matrix_store::max_stream_id(&conn).expect("max stream id");

        let page1 = paginate_messages(&conn, "!r:mylittlechart.org", matrix_store::HistoryWindow::All, latest + 1, None, Direction::Backward, 2, &EventFilter::default())
            .expect("page1");
        assert_eq!(page1.chunk.iter().map(|e| e.event_id.clone()).collect::<Vec<_>>(), vec!["$e5", "$e4"]);
        let end_token = page1.end.clone().expect("more to page backward");

        let from2 = parse_stream_token(&end_token).expect("parse token");
        let page2 = paginate_messages(&conn, "!r:mylittlechart.org", matrix_store::HistoryWindow::All, from2, None, Direction::Backward, 2, &EventFilter::default())
            .expect("page2");
        assert_eq!(page2.chunk.iter().map(|e| e.event_id.clone()).collect::<Vec<_>>(), vec!["$e3", "$e2"]);

        let fpage = paginate_messages(&conn, "!r:mylittlechart.org", matrix_store::HistoryWindow::All, 0, None, Direction::Forward, 3, &EventFilter::default())
            .expect("forward page");
        assert_eq!(fpage.chunk.iter().map(|e| e.event_id.clone()).collect::<Vec<_>>(), vec!["$e1", "$e2", "$e3"]);
        assert!(fpage.end.is_some());
    }

    #[test]
    fn left_member_sees_history_only_up_to_leave() {
        let mut conn = test_conn();
        make_room(&conn, "!r:mylittlechart.org", matrix_store::RoomKind::Group, 1);
        let alice = matrix_store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000064", T0).expect("alice");
        matrix_store::apply_state_event(&mut conn, "$m1", "!r:mylittlechart.org", 1, "m.room.member", &alice, r#"{"membership":"join"}"#, 1000, T0).expect("alice joins");
        matrix_store::insert_timeline_event(&mut conn, "$before", "!r:mylittlechart.org", 1, "m.room.message", "{}", 2000, None).expect("before leave");
        let leave_event =
            matrix_store::apply_state_event(&mut conn, "$leave", "!r:mylittlechart.org", 1, "m.room.member", &alice, r#"{"membership":"leave"}"#, 3000, T0).expect("alice leaves");

        let room = matrix_store::get_room(&conn, "!r:mylittlechart.org").expect("room").expect("exists");
        let window = matrix_store::visible_upper_bound(&conn, &room, 1).expect("window");
        assert_eq!(window, matrix_store::HistoryWindow::UpTo(leave_event.stream_id));
        assert!(window.contains(leave_event.stream_id), "the leave event itself is the last thing the leaver witnessed");
        assert!(!window.contains(leave_event.stream_id + 1), "nothing after the leave is visible");
    }

    #[test]
    fn never_member_sees_nothing_in_a_shared_room() {
        let conn = test_conn();
        make_room(&conn, "!r:mylittlechart.org", matrix_store::RoomKind::Group, 1);
        let room = matrix_store::get_room(&conn, "!r:mylittlechart.org").expect("room").expect("exists");
        let window = matrix_store::visible_upper_bound(&conn, &room, 999).expect("window");
        assert_eq!(window, matrix_store::HistoryWindow::Nothing);
    }

    #[test]
    fn world_readable_channel_is_readable_by_any_signed_in_caller() {
        let conn = test_conn();
        make_room(&conn, "!chan:mylittlechart.org", matrix_store::RoomKind::Channel, 1);
        let room = matrix_store::get_room(&conn, "!chan:mylittlechart.org").expect("room").expect("exists");
        let window = matrix_store::visible_upper_bound(&conn, &room, 999).expect("window for a caller who never touched this room");
        assert_eq!(window, matrix_store::HistoryWindow::All);
    }
}

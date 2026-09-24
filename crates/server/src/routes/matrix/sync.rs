//! `GET /_matrix/client/v3/sync` (P10) — the core long-poll endpoint. See
//! `docs/mlc/plans/messenger-proto-server-matrix-subset-2026-09-24.md` §3
//! for the algorithm this implements and the P10 brief's own binding
//! corrections (this module follows the brief where it overrides the plan
//! body — noted inline).
//!
//! # Sync token
//!
//! `s{stream_id}_{typing_gen}` — [`sync_token`] (binding, overrides P9's
//! own note that the format would never need a typing component).
//!
//! # Consistent cut
//!
//! [`build_sync_response`] reads `upto = matrix_store::max_stream_id(conn)`
//! ONCE at the very start and bounds every subsequent stream-ordered query
//! by `(since, upto]` (or `(0, upto]` for a full/initial view — see
//! "the since=0 trick" below). Because the caller holds `messenger_conn()`'s
//! `MutexGuard` for this function's ENTIRE duration (this module's own
//! single-writer discipline, same as every other `routes::matrix::*`
//! module), no write can land between that snapshot and any later read
//! inside this same call — the whole response is one consistent cut by
//! construction, not by re-checking `stream_id <= upto` everywhere by hand
//! (though several queries do exactly that anyway, since they are shared
//! with other bounded-window use sites).
//!
//! # The `since=0` trick
//!
//! Every per-room and global delta query here takes an explicit lower bound
//! (`since_exclusive`) rather than branching "initial vs incremental" query
//! shapes. Passing `0` for that bound (a room's or the account's first-ever
//! stream position is always `> 0`) naturally reproduces "everything that
//! has ever happened" — the initial-sync/`full_state`/newly-joined-room
//! case — through the SAME query as a real incremental delta. This is why
//! [`build_join_room_block`] computes one `effective_since` per room
//! (`0` when that room gets a full view, the caller's real `since` value
//! otherwise) instead of a second code path.
//!
//! # Long-poll wake — register, THEN build, THEN wait
//!
//! [`long_poll`] is the SAME check-then-register idiom
//! `mylittlechart_server::live`'s own module doc requires: register
//! interest in `"user:{user_id}"` BEFORE rebuilding the response, so a wake
//! landing between the rebuild and the wait is still caught on entry to
//! [`mylittlechart_server::live::Registration::wait`]. Every rebuild runs
//! inside its own `tokio::task::spawn_blocking` (never holding
//! `cp.messenger`'s mutex across an `.await`); the wait itself runs in the
//! async context directly.
//!
//! # Changed-room prefilter
//!
//! [`build_sync_response`] never runs [`build_join_room_block`] (a dozen-odd
//! queries on its own) against a joined room that provably has nothing new
//! to report. On an incremental sync it first computes the SUBSET of joined
//! rooms that changed at all — [`mylittlechart_server::matrix_store::
//! rooms_changed_in_window`] (three queries total, not per room, since
//! `timeline`/`state`/room `account_data`/`m.receipt` derive from exactly
//! the `events`/`receipts`/`account_data` tables) plus an in-memory
//! [`mylittlechart_server::live::TypingRegistry::typing_serial`] check per
//! room (no query at all) — and only builds THOSE rooms. This set is
//! EXACT, not a safe over-approximation with false positives: a room with
//! zero rows across all three tables in `(since, upto]` and no typing
//! change is exactly the set [`build_join_room_block`]'s own "nothing
//! changed" gate would have thrown away anyway, just without paying for
//! the dozen queries to find that out. Initial and `full_state` syncs skip
//! this prefilter entirely and build every joined room, since there is no
//! `since` boundary to prefilter against.
//!
//! # Per-incremental-sync query count (a user in `R` joined rooms, `C` of
//! which actually changed)
//!
//! One `max_stream_id`, one `rooms_for_user` per membership kind (join/
//! invite/leave-candidates), THREE queries total (not per room) for the
//! changed-room prefilter ([`mylittlechart_server::matrix_store::
//! rooms_changed_in_window`] — see "Changed-room prefilter" above), then per
//! CHANGED joined room only: `get_room` + `current_state_event` (own
//! membership) + one timeline page query + (2 queries per DISTINCT
//! lazy-loaded sender: `mxid_of` + `current_state_event`) + one
//! `non_member_state_changed_in_window` + (one
//! `member_state_changed_in_window` only when `limited`) + one
//! `receipts_changed_in_room` + one `account_data_since` +
//! `notification_count`'s own ~3-4 queries + `room_heroes` + two
//! `room_members` counts — roughly a dozen queries plus two per lazy
//! sender, times `C`, NOT `R` (the `R - C` untouched rooms cost nothing
//! beyond the three prefilter queries). Global work (account data,
//! to-device, device lists, OTK counts, fallback types) is a fixed handful
//! of queries independent of
//! `R`. No query ever scans the whole `events` table unbounded — every one
//! is indexed by `(room_id, stream_id)` or `(room_id, event_type,
//! state_key)`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use rusqlite::Connection;

use mylittlechart_server::live;
use mylittlechart_server::matrix_keys_store;
use mylittlechart_server::matrix_store::{self, Membership, ReceiptType, Room};

use super::auth;
use super::sync_token;
use super::{client_event_json, MatrixError};
use crate::state::AppState;

/// `timeout` (ms) is clamped to this ceiling regardless of what the client
/// asks for (plan §4 `/sync` row).
const SYNC_MAX_TIMEOUT_MS: u64 = 30_000;
/// `filter.room.timeline.limit` default and ceiling (P10 brief — overrides
/// plan §3.2's own "default 20" wherever they differ).
const SYNC_TIMELINE_DEFAULT_LIMIT: i64 = 10;
const SYNC_TIMELINE_MAX_LIMIT: i64 = 50;
/// `to_device.events` cap per response (P10 brief).
const SYNC_TO_DEVICE_CAP: i64 = 100;
/// `m.heroes` cap (plan §3.4).
const SYNC_HERO_LIMIT: i64 = 5;

// ============================================================================
// Router
// ============================================================================

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/client/v3/sync", get(sync_handler))
}

// ============================================================================
// Filter — `room.timeline.limit/types/not_types`, `room.state.
// lazy_load_members`, `room.include_leave`, `account_data.types/not_types`.
// `presence`/`event_fields` are accepted (serde ignores unrecognized JSON
// keys by default — no `deny_unknown_fields`) and never interpreted.
// ============================================================================

#[derive(serde::Deserialize, Default, Clone)]
struct RoomTimelineFilter {
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    types: Option<Vec<String>>,
    #[serde(default)]
    not_types: Option<Vec<String>>,
}

#[derive(serde::Deserialize, Default, Clone)]
struct RoomStateFilter {
    #[serde(default)]
    lazy_load_members: Option<bool>,
}

#[derive(serde::Deserialize, Default, Clone)]
struct RoomFilter {
    #[serde(default)]
    timeline: RoomTimelineFilter,
    #[serde(default)]
    state: RoomStateFilter,
    #[serde(default)]
    include_leave: bool,
}

#[derive(serde::Deserialize, Default, Clone)]
struct AccountDataFilter {
    #[serde(default)]
    types: Option<Vec<String>>,
    #[serde(default)]
    not_types: Option<Vec<String>>,
}

#[derive(serde::Deserialize, Default, Clone)]
struct SyncFilter {
    #[serde(default)]
    room: RoomFilter,
    #[serde(default)]
    account_data: AccountDataFilter,
}

/// `types`/`not_types` gate shared by the timeline and account-data filter
/// sections — own copy per this codebase's one-copy-per-route-module
/// convention (mirrors `routes::matrix::messaging::event_passes_filter`).
fn passes_type_filter(value: &str, types: &Option<Vec<String>>, not_types: &Option<Vec<String>>) -> bool {
    if let Some(types) = types {
        if !types.iter().any(|t| t == value) {
            return false;
        }
    }
    if let Some(not_types) = not_types {
        if not_types.iter().any(|t| t == value) {
            return false;
        }
    }
    true
}

impl SyncFilter {
    fn timeline_limit(&self) -> i64 {
        self.room.timeline.limit.unwrap_or(SYNC_TIMELINE_DEFAULT_LIMIT).clamp(1, SYNC_TIMELINE_MAX_LIMIT)
    }

    /// Default `true` — every client this server ships sets it, and it is
    /// the single biggest `/sync` payload-size win for anything but a tiny
    /// room (plan §3.3).
    fn lazy_load_members(&self) -> bool {
        self.room.state.lazy_load_members.unwrap_or(true)
    }

    fn include_leave(&self) -> bool {
        self.room.include_leave
    }

    fn timeline_event_passes(&self, event_type: &str) -> bool {
        passes_type_filter(event_type, &self.room.timeline.types, &self.room.timeline.not_types)
    }

    fn account_data_passes(&self, data_type: &str) -> bool {
        passes_type_filter(data_type, &self.account_data.types, &self.account_data.not_types)
    }
}

/// Resolve the `filter` query param: a stored `filter_id` (looked up via
/// [`matrix_store::get_filter`], scoped to `user_id` — the same isolation
/// `routes::matrix::account::get_filter` enforces) or inline JSON (a leading
/// `{`). Absent/empty is [`SyncFilter::default`].
fn parse_filter_param(conn: &Connection, user_id: i64, raw: Option<&str>) -> Result<SyncFilter, MatrixError> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(SyncFilter::default());
    };
    let definition = if raw.starts_with('{') {
        raw.to_string()
    } else {
        let filter_id: i64 = raw.parse().map_err(|_| MatrixError::invalid_param("filter must be a filter id or inline JSON"))?;
        matrix_store::get_filter(conn, user_id, filter_id)?.ok_or_else(|| MatrixError::not_found("no such filter"))?
    };
    serde_json::from_str(&definition).map_err(|_| MatrixError::invalid_param("malformed filter"))
}

// ============================================================================
// Response emptiness — what makes a long-poll keep waiting
// ============================================================================

fn events_array_is_empty(value: &serde_json::Value, key: &str) -> bool {
    value.get(key).and_then(|v| v.get("events")).and_then(|v| v.as_array()).map(|a| a.is_empty()).unwrap_or(true)
}

/// "No rooms/account-data/to-device/device-lists changes, no typing/receipt
/// change" (P10 brief) — `device_one_time_keys_count`/
/// `device_unused_fallback_key_types` are deliberately NOT part of this
/// check: they are static per-device facts always present, never a "new
/// since last time" signal.
fn sync_response_is_empty(value: &serde_json::Value) -> bool {
    let rooms_empty = value
        .get("rooms")
        .map(|rooms| {
            ["join", "invite", "leave"]
                .iter()
                .all(|kind| rooms.get(kind).and_then(|v| v.as_object()).map(|o| o.is_empty()).unwrap_or(true))
        })
        .unwrap_or(true);
    let device_lists_empty = value
        .get("device_lists")
        .map(|dl| {
            ["changed", "left"]
                .iter()
                .all(|k| dl.get(k).and_then(|v| v.as_array()).map(|a| a.is_empty()).unwrap_or(true))
        })
        .unwrap_or(true);
    rooms_empty && events_array_is_empty(value, "account_data") && events_array_is_empty(value, "to_device") && device_lists_empty
}

// ============================================================================
// Long-poll loop
// ============================================================================

/// Drive one `/sync` long-poll: register interest in `key` BEFORE each
/// rebuild (the check-then-register idiom `live.rs`'s own module doc
/// requires), call `build` (a fresh async rebuild every iteration — the SAME
/// closure runs again after every wake, since a wake carries no payload,
/// only the fact that SOMETHING changed), and return as soon as a rebuild is
/// non-empty or `deadline` passes.
async fn long_poll<B, F>(live: &live::LiveRegistry, key: &str, deadline: Instant, mut build: B) -> Result<serde_json::Value, MatrixError>
where
    B: FnMut() -> F,
    F: std::future::Future<Output = Result<serde_json::Value, MatrixError>>,
{
    loop {
        let registration = live.register(key);
        let response = build().await?;
        if !sync_response_is_empty(&response) {
            return Ok(response);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(response);
        }
        if registration.wait(remaining).await == live::WaitOutcome::TimedOut {
            return Ok(response);
        }
        // Woken: loop, re-register, rebuild.
    }
}

// ============================================================================
// Event formatting helpers
// ============================================================================

fn format_event(conn: &Connection, caller_user_id: i64, caller_device_id: &str, event: &matrix_store::MatrixEvent) -> Result<serde_json::Value, MatrixError> {
    let own_txn_id = matrix_store::txn_id_for_event(conn, caller_user_id, caller_device_id, &event.event_id)?;
    client_event_json(conn, event, own_txn_id.as_deref())
}

fn format_pagination_token(stream_id: i64) -> String {
    format!("t{stream_id}")
}

/// One coalesced `m.receipt` ephemeral event (plan §3.6): every `m.read`
/// receipt (visible to the whole room by definition) plus ONLY the caller's
/// own `m.read.private` receipt — Matrix's own privacy rule that a private
/// receipt must never reach another user's `/sync`. `None` when `receipts`
/// contained only OTHER users' private receipts — after the privacy filter
/// there is nothing left worth an (otherwise empty-content) event at all,
/// and an empty-but-present `m.receipt` event would wrongly count as "this
/// room changed" for the emptiness check that gates a room's inclusion.
fn build_receipt_event(conn: &Connection, caller_user_id: i64, receipts: &[matrix_store::ReceiptRow]) -> Result<Option<serde_json::Value>, MatrixError> {
    let mut by_event: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    for receipt in receipts {
        if receipt.receipt_type == ReceiptType::ReadPrivate && receipt.user_id != caller_user_id {
            continue;
        }
        let Some(user_mxid) = matrix_store::mxid_of(conn, receipt.user_id)? else { continue };

        let event_entry = by_event.entry(receipt.event_id.clone()).or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        let event_map = event_entry.as_object_mut().ok_or_else(MatrixError::internal)?;
        let type_entry = event_map
            .entry(receipt.receipt_type.as_str().to_string())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        let type_map = type_entry.as_object_mut().ok_or_else(MatrixError::internal)?;
        type_map.insert(user_mxid, serde_json::json!({ "ts": receipt.ts }));
    }
    if by_event.is_empty() {
        return Ok(None);
    }
    Ok(Some(serde_json::json!({ "type": "m.receipt", "content": serde_json::Value::Object(by_event) })))
}

// ============================================================================
// Per-room block builders
// ============================================================================

/// One `rooms.join.{roomId}` block, or `None` when this is an incremental
/// sync AND nothing changed for this room at all (a room is only listed
/// when something happened — see the module doc's emptiness rule).
#[allow(clippy::too_many_arguments)]
fn build_join_room_block(
    conn: &Connection,
    typing: &live::TypingRegistry,
    room: &Room,
    caller_user_id: i64,
    caller_mxid: &str,
    caller_device_id: &str,
    since_stream: i64,
    upto: i64,
    is_initial_or_full: bool,
    typing_gen_since: u64,
    filter: &SyncFilter,
    now: Instant,
) -> Result<Option<serde_json::Value>, MatrixError> {
    let member_event = matrix_store::current_state_event(conn, &room.id, "m.room.member", caller_mxid)?;
    let joined_stream = member_event.as_ref().map(|e| e.stream_id).unwrap_or(0);
    let newly_joined = !is_initial_or_full && joined_stream > since_stream;
    let full_view = is_initial_or_full || newly_joined;
    let effective_since = if full_view { 0 } else { since_stream };

    let limit = filter.timeline_limit();
    let (mut timeline_events, limited) = if full_view {
        let mut page = matrix_store::events_in_room_before(conn, &room.id, upto.saturating_add(1), limit + 1)?;
        let limited = page.len() as i64 > limit;
        if limited {
            page.pop(); // drop the oldest of the N+1 (page is newest-first)
        }
        page.reverse(); // ascending
        (page, limited)
    } else {
        let mut page = matrix_store::events_in_room_after(conn, &room.id, since_stream, limit + 1)?;
        let limited = page.len() as i64 > limit;
        if limited {
            let drop_count = page.len() - limit as usize;
            page.drain(0..drop_count); // keep only the newest `limit`
        }
        (page, limited)
    };
    // Computed from the RAW (pre-type-filter) page — `limited` signals a gap
    // in raw stream continuity, independent of what a content filter thins
    // out (matches `routes::matrix::messaging::paginate_messages`'s own
    // precedent).
    let prev_batch = timeline_events.first().map(|e| format_pagination_token(e.stream_id - 1));
    timeline_events.retain(|e| filter.timeline_event_passes(&e.event_type));

    // STATE
    let mut state_events: Vec<matrix_store::MatrixEvent> = Vec::new();
    if filter.lazy_load_members() {
        // Clause (a): member events of every DISTINCT sender in the
        // returned (capped) timeline window.
        let mut senders: Vec<i64> = timeline_events.iter().map(|e| e.sender_user_id).collect();
        senders.sort_unstable();
        senders.dedup();
        for sender in senders {
            if let Some(mxid) = matrix_store::mxid_of(conn, sender)? {
                if let Some(ev) = matrix_store::current_state_event(conn, &room.id, "m.room.member", &mxid)? {
                    state_events.push(ev);
                }
            }
        }
        // Clause (b): the matrix-spec#942 gap rule — only when there is
        // actually a gap the timeline did not cover (incremental + limited;
        // a full/initial view has no prior client state to keep consistent
        // with, so nothing to backfill).
        if !full_view && limited {
            for ev in matrix_store::member_state_changed_in_window(conn, &room.id, since_stream, upto)? {
                if !state_events.iter().any(|existing| existing.event_id == ev.event_id) {
                    state_events.push(ev);
                }
            }
        }
    } else {
        state_events.extend(matrix_store::state_events_of_type_at(conn, &room.id, "m.room.member", upto)?);
    }
    // Every OTHER state type: the delta since `effective_since` (never
    // gated on `limited` — see the module doc), MINUS anything already
    // present in the returned `timeline` (manager review, 2026-09-24):
    // `state` is the state at the START of the timeline window, not a
    // second copy of state changes the client is ALREADY receiving as
    // timeline entries. On a non-limited incremental sync this makes
    // non-member `state` collapse to empty (every state change in the
    // window is, by definition, already IN that unlimited timeline); on a
    // limited one, only the gap's changes — the ones the truncated
    // timeline did NOT cover — survive the exclusion below.
    state_events.extend(matrix_store::non_member_state_changed_in_window(conn, &room.id, effective_since, upto)?);
    let timeline_event_ids: std::collections::HashSet<&str> = timeline_events.iter().map(|e| e.event_id.as_str()).collect();
    state_events.retain(|e| !timeline_event_ids.contains(e.event_id.as_str()));

    // EPHEMERAL: typing + receipts
    let mut ephemeral_events = Vec::new();
    let room_typing_serial = typing.typing_serial(&room.id, now);
    if full_view || room_typing_serial > typing_gen_since {
        let user_ids: Vec<String> =
            typing.typing_users(&room.id, now).into_iter().filter_map(|uid| matrix_store::mxid_of(conn, uid).ok().flatten()).collect();
        ephemeral_events.push(serde_json::json!({ "type": "m.typing", "content": { "user_ids": user_ids } }));
    }
    let receipts = matrix_store::receipts_changed_in_room(conn, &room.id, effective_since, upto)?;
    if !receipts.is_empty() {
        if let Some(receipt_event) = build_receipt_event(conn, caller_user_id, &receipts)? {
            ephemeral_events.push(receipt_event);
        }
    }

    // ACCOUNT DATA
    let mut account_data_events = Vec::new();
    for row in matrix_store::account_data_since(conn, caller_user_id, &room.id, effective_since)? {
        if !filter.account_data_passes(&row.data_type) {
            continue;
        }
        let content: serde_json::Value = serde_json::from_str(&row.content).unwrap_or_else(|_| serde_json::json!({}));
        account_data_events.push(serde_json::json!({ "type": row.data_type, "content": content }));
    }

    let is_empty_incremental =
        !full_view && timeline_events.is_empty() && state_events.is_empty() && ephemeral_events.is_empty() && account_data_events.is_empty();
    if is_empty_incremental {
        return Ok(None);
    }

    let mut timeline_json = Vec::with_capacity(timeline_events.len());
    for event in &timeline_events {
        timeline_json.push(format_event(conn, caller_user_id, caller_device_id, event)?);
    }
    let mut state_json = Vec::with_capacity(state_events.len());
    for event in &state_events {
        state_json.push(format_event(conn, caller_user_id, caller_device_id, event)?);
    }

    // `summary` is always attached whenever the room block itself is sent
    // (never gated on detecting a change against a prior sync — this
    // server does not persist a "last reported summary" to compare
    // against; re-sending unchanged, cheap, idempotent metadata is spec-
    // permitted and harmless, unlike re-sending the whole timeline would
    // be).
    let heroes: Vec<String> = matrix_store::room_heroes(conn, &room.id, caller_user_id, SYNC_HERO_LIMIT)?
        .into_iter()
        .filter_map(|uid| matrix_store::mxid_of(conn, uid).ok().flatten())
        .collect();
    let joined_count = matrix_store::room_members(conn, &room.id, Some(Membership::Join))?.len();
    let invited_count = matrix_store::room_members(conn, &room.id, Some(Membership::Invite))?.len();
    let notification_count = matrix_store::notification_count(conn, room, caller_user_id)?;

    let mut timeline = serde_json::json!({ "events": timeline_json, "limited": limited });
    if let Some(prev_batch) = prev_batch {
        timeline["prev_batch"] = serde_json::Value::String(prev_batch);
    }

    Ok(Some(serde_json::json!({
        "summary": {
            "m.heroes": heroes,
            "m.joined_member_count": joined_count,
            "m.invited_member_count": invited_count,
        },
        "state": { "events": state_json },
        "timeline": timeline,
        "ephemeral": { "events": ephemeral_events },
        "account_data": { "events": account_data_events },
        // `highlight_count` is always 0 — no push-rule/keyword-highlight
        // engine in this server (plan §3.5).
        "unread_notifications": { "notification_count": notification_count, "highlight_count": 0 },
    })))
}

/// One `rooms.invite.{roomId}` block, or `None` when the invite is not new
/// (an incremental sync whose invite predates `since_stream`).
fn build_invite_room_block(conn: &Connection, room_id: &str, caller_mxid: &str, is_initial: bool, since_stream: i64) -> Result<Option<serde_json::Value>, MatrixError> {
    let Some(member_event) = matrix_store::current_state_event(conn, room_id, "m.room.member", caller_mxid)? else {
        return Ok(None);
    };
    if !(is_initial || member_event.stream_id > since_stream) {
        return Ok(None);
    }
    let mut events = matrix_store::stripped_invite_state(conn, room_id, member_event.sender_user_id)?;
    events.push(matrix_store::stripped_state_json(conn, &member_event)?);
    Ok(Some(serde_json::json!({ "invite_state": { "events": events } })))
}

/// One `rooms.leave.{roomId}` block: timeline up to and including the
/// leave/kick/ban event itself (naturally bounded — nothing after that
/// point is ever queried), `state` minimal (v1 simplification: the client
/// was previously joined, so it already has the room's bootstrap state from
/// before it left — nothing new is reconstructed here).
fn build_leave_room_block(
    conn: &Connection,
    room: &Room,
    caller_user_id: i64,
    caller_device_id: &str,
    member_event: &matrix_store::MatrixEvent,
    limit: i64,
) -> Result<serde_json::Value, MatrixError> {
    let mut page = matrix_store::events_in_room_before(conn, &room.id, member_event.stream_id.saturating_add(1), limit + 1)?;
    let limited = page.len() as i64 > limit;
    if limited {
        page.pop();
    }
    page.reverse();

    let mut events_json = Vec::with_capacity(page.len());
    for event in &page {
        events_json.push(format_event(conn, caller_user_id, caller_device_id, event)?);
    }

    Ok(serde_json::json!({
        "timeline": { "events": events_json, "limited": limited },
        "state": { "events": [] },
    }))
}

// ============================================================================
// The whole-response builder — one consistent cut (see the module doc)
// ============================================================================

#[allow(clippy::too_many_arguments)]
fn build_sync_response(
    conn: &Connection,
    typing: &live::TypingRegistry,
    caller_user_id: i64,
    caller_mxid: &str,
    caller_device_id: &str,
    since: Option<sync_token::SyncToken>,
    filter: &SyncFilter,
    full_state: bool,
    now: Instant,
) -> Result<serde_json::Value, MatrixError> {
    let upto = matrix_store::max_stream_id(conn)?;
    let since_stream = since.map(|t| t.stream_id).unwrap_or(0);
    let typing_gen_since = since.map(|t| t.typing_gen).unwrap_or(0);
    // Snapshotted BEFORE any per-room typing read (mirrors `live.rs`'s own
    // "register before read" discipline): any typing change racing in
    // AFTER this point still stamps a room serial strictly greater than
    // what we are about to hand back as `next_batch`, so the client's NEXT
    // poll (using that value as its own `typing_gen_since`) is guaranteed
    // to observe it. Capturing this AFTER building rooms would risk the
    // reverse: a change landing after a room's own (already-negative) check
    // but before this snapshot would be stamped INTO next_batch without
    // ever having been reported — silently lost until a later change
    // happens to exceed it.
    let typing_gen_now = typing.current_typing_gen();
    let is_initial = since.is_none() || full_state;

    // Delete-after-ack: the client asking for `since_stream` is itself the
    // proof it already durably received everything up to that point
    // (plan §3.7). A no-op for an initial sync (`since_stream == 0`).
    matrix_keys_store::delete_to_device_up_to(conn, caller_user_id, caller_device_id, since_stream)?;

    let timeline_limit = filter.timeline_limit();

    let joined_room_ids = matrix_store::rooms_for_user(conn, caller_user_id, Some(Membership::Join))?;
    // Changed-room prefilter (manager review, 2026-09-24): on an initial/
    // `full_state` sync every joined room is built regardless (there is no
    // `since` boundary to prefilter against). On an incremental sync,
    // building EVERY joined room's block just to discover most did not
    // change costs a room block builder's own dozen-odd queries per room —
    // with a few hundred rooms that is thousands of queries per wake, all
    // held under the single `messenger.db` mutex, blocking every other
    // user. `rooms_changed_in_window` answers "did anything happen here at
    // all" in three cheap, indexed queries total (not per room), and the
    // in-memory typing check costs nothing; only rooms in the resulting set
    // ever reach [`build_join_room_block`].
    let rooms_to_build: Vec<String> = if is_initial {
        joined_room_ids.clone()
    } else {
        let mut changed = matrix_store::rooms_changed_in_window(conn, &joined_room_ids, caller_user_id, since_stream, upto)?;
        for room_id in &joined_room_ids {
            if typing.typing_serial(room_id, now) > typing_gen_since {
                changed.insert(room_id.clone());
            }
        }
        joined_room_ids.iter().filter(|room_id| changed.contains(*room_id)).cloned().collect()
    };

    let mut rooms_join = serde_json::Map::new();
    for room_id in rooms_to_build {
        let Some(room) = matrix_store::get_room(conn, &room_id)? else { continue };
        if let Some(block) = build_join_room_block(
            conn,
            typing,
            &room,
            caller_user_id,
            caller_mxid,
            caller_device_id,
            since_stream,
            upto,
            is_initial,
            typing_gen_since,
            filter,
            now,
        )? {
            rooms_join.insert(room_id, block);
        }
    }

    let mut rooms_invite = serde_json::Map::new();
    for room_id in matrix_store::rooms_for_user(conn, caller_user_id, Some(Membership::Invite))? {
        if let Some(block) = build_invite_room_block(conn, &room_id, caller_mxid, is_initial, since_stream)? {
            rooms_invite.insert(room_id, block);
        }
    }

    // Left rooms: an initial sync omits them entirely (there is no boundary
    // to test "left inside the window" against), and even on an incremental
    // sync only when the filter opts in (`room.include_leave`, default
    // false — P10 brief).
    let mut rooms_leave = serde_json::Map::new();
    if since.is_some() && filter.include_leave() {
        for membership in [Membership::Leave, Membership::Ban] {
            for room_id in matrix_store::rooms_for_user(conn, caller_user_id, Some(membership))? {
                let Some(room) = matrix_store::get_room(conn, &room_id)? else { continue };
                let Some(member_event) = matrix_store::current_state_event(conn, &room_id, "m.room.member", caller_mxid)? else { continue };
                if member_event.stream_id > since_stream {
                    let block = build_leave_room_block(conn, &room, caller_user_id, caller_device_id, &member_event, timeline_limit)?;
                    rooms_leave.insert(room_id, block);
                }
            }
        }
    }

    let account_data_since_global = if is_initial { 0 } else { since_stream };
    let mut global_account_data = Vec::new();
    for row in matrix_store::account_data_since(conn, caller_user_id, matrix_store::GLOBAL_ACCOUNT_DATA_ROOM, account_data_since_global)? {
        if !filter.account_data_passes(&row.data_type) {
            continue;
        }
        let content: serde_json::Value = serde_json::from_str(&row.content).unwrap_or_else(|_| serde_json::json!({}));
        global_account_data.push(serde_json::json!({ "type": row.data_type, "content": content }));
    }

    // Cap to-device delivery at `SYNC_TO_DEVICE_CAP`. If capped, lower ONLY
    // `next_batch`'s own stream position to the last DELIVERED message's
    // `stream_id` (P10 brief's "deliver in order and let the next sync
    // continue" option) — every other field in THIS response still reflects
    // the full `upto` snapshot; anything past the lowered watermark that
    // would otherwise have been reported now is simply reported again on
    // the next call, which is safe (event ids are stable, receipts/account
    // data are last-write-wins).
    let mut to_device_raw = matrix_keys_store::to_device_for(conn, caller_user_id, caller_device_id, since_stream, SYNC_TO_DEVICE_CAP + 1)?;
    let to_device_capped = to_device_raw.len() as i64 > SYNC_TO_DEVICE_CAP;
    if to_device_capped {
        to_device_raw.truncate(SYNC_TO_DEVICE_CAP as usize);
    }
    let effective_upto = if to_device_capped { to_device_raw.last().map(|m| m.stream_id).unwrap_or(upto) } else { upto };
    let mut to_device_events = Vec::with_capacity(to_device_raw.len());
    for message in &to_device_raw {
        let Some(sender_mxid) = matrix_store::mxid_of(conn, message.sender_user_id)? else { continue };
        let content: serde_json::Value = serde_json::from_str(&message.content).unwrap_or_else(|_| serde_json::json!({}));
        to_device_events.push(serde_json::json!({ "sender": sender_mxid, "type": message.event_type, "content": content }));
    }

    // Device lists: omitted entirely on an initial/`full_state` sync (a
    // fresh client queries `/keys/query` for every room member outright —
    // an incremental DELTA has no meaning against no prior state).
    let (device_lists_changed, device_lists_left) = if is_initial {
        (Vec::<String>::new(), Vec::<String>::new())
    } else {
        let visible_peers = super::keys::peers_sharing_a_room_with(conn, caller_user_id)?;
        let mut changed = Vec::new();
        for user_id in matrix_keys_store::device_list_changes_between(conn, since_stream, upto)? {
            if visible_peers.contains(&user_id) {
                if let Some(mxid) = matrix_store::mxid_of(conn, user_id)? {
                    changed.push(mxid);
                }
            }
        }
        let caller_rooms = matrix_store::rooms_for_user(conn, caller_user_id, None)?;
        let mut left = Vec::new();
        for user_id in matrix_store::user_ids_with_leave_transition_in_rooms(conn, &caller_rooms, since_stream, upto)? {
            if !visible_peers.contains(&user_id) {
                if let Some(mxid) = matrix_store::mxid_of(conn, user_id)? {
                    left.push(mxid);
                }
            }
        }
        changed.sort();
        changed.dedup();
        left.sort();
        left.dedup();
        (changed, left)
    };

    let otk_counts = matrix_keys_store::count_one_time_keys(conn, caller_user_id, caller_device_id)?;
    let unused_fallback = matrix_keys_store::unused_fallback_key_types(conn, caller_user_id, caller_device_id)?;

    let next_batch = sync_token::format(effective_upto, typing_gen_now);

    Ok(serde_json::json!({
        "next_batch": next_batch,
        "account_data": { "events": global_account_data },
        "to_device": { "events": to_device_events },
        "device_lists": { "changed": device_lists_changed, "left": device_lists_left },
        "device_one_time_keys_count": otk_counts,
        "device_unused_fallback_key_types": unused_fallback,
        // No presence pushed at all in this server (plan §4/research §1.6).
        "presence": { "events": [] },
        "rooms": {
            "join": serde_json::Value::Object(rooms_join),
            "invite": serde_json::Value::Object(rooms_invite),
            "leave": serde_json::Value::Object(rooms_leave),
        },
    }))
}

// ============================================================================
// GET /_matrix/client/v3/sync
// ============================================================================

/// `set_presence` is accepted and ignored — omitted from this struct
/// entirely rather than declared-and-unused, since axum's query
/// deserialization (unlike JSON) silently drops unrecognized keys with no
/// `deny_unknown_fields` involved, and declaring-then-never-reading a field
/// would be a real `dead_code` warning this codebase's `-D warnings` gate
/// refuses (see `routes::matrix`'s own module doc on the same rule for
/// `MatrixError::not_json`).
#[derive(serde::Deserialize, Default)]
struct SyncQuery {
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    timeout: Option<u64>,
    #[serde(default)]
    filter: Option<String>,
    #[serde(default)]
    full_state: Option<bool>,
}

async fn sync_handler(State(state): State<Arc<AppState>>, headers: HeaderMap, Query(query): Query<SyncQuery>) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let since = query.since.as_deref().map(sync_token::parse).transpose()?;
    let timeout = Duration::from_millis(query.timeout.unwrap_or(0).min(SYNC_MAX_TIMEOUT_MS));
    let full_state = query.full_state.unwrap_or(false);

    let filter = {
        let state_for_filter = state.clone();
        let caller_user_id = caller.user_id;
        let filter_raw = query.filter.clone();
        tokio::task::spawn_blocking(move || -> Result<SyncFilter, MatrixError> {
            let cp = state_for_filter.control_plane();
            let messenger_conn = cp.messenger_conn();
            parse_filter_param(&messenger_conn, caller_user_id, filter_raw.as_deref())
        })
        .await
        .map_err(|_| MatrixError::internal())??
    };

    let key = format!("user:{}", caller.user_id);
    let deadline = Instant::now() + timeout;
    let live = &state.control_plane().live;

    let response = long_poll(live, &key, deadline, || {
        let state = state.clone();
        let caller = caller.clone();
        let filter = filter.clone();
        async move {
            tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
                let cp = state.control_plane();
                let messenger_conn = cp.messenger_conn();
                build_sync_response(
                    &messenger_conn,
                    &cp.typing,
                    caller.user_id,
                    &caller.mxid,
                    &caller.device_id,
                    since,
                    &filter,
                    full_state,
                    Instant::now(),
                )
            })
            .await
            .map_err(|_| MatrixError::internal())?
        }
    })
    .await?;

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    const T0: &str = "2026-09-24T00:00:00+00:00";

    fn test_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        matrix_store::create_matrix_schema(&conn).expect("matrix schema");
        matrix_keys_store::create_matrix_keys_schema(&conn).expect("matrix keys schema");
        conn
    }

    /// A fresh room with `creator_user_id` as its sole joined member,
    /// returning `(room_id, creator_mxid)`.
    fn make_joined_room(conn: &mut Connection, creator_user_id: i64) -> (String, String) {
        let room_id = format!("!room{creator_user_id}:mylittlechart.org");
        matrix_store::create_room(
            conn,
            &room_id,
            matrix_store::RoomKind::Group,
            creator_user_id,
            T0,
            false,
            matrix_store::JoinRule::Invite,
            matrix_store::HistoryVisibility::Shared,
            None,
            None,
        )
        .expect("create room");
        let mxid = matrix_store::ensure_matrix_user(conn, creator_user_id, &format!("user{creator_user_id:0>28}"), T0).expect("ensure user");
        matrix_store::apply_state_event(conn, &format!("$create{creator_user_id}"), &room_id, creator_user_id, "m.room.create", "", r#"{"room_version":"11"}"#, 100, T0)
            .expect("create event");
        matrix_store::apply_state_event(conn, &format!("$join{creator_user_id}"), &room_id, creator_user_id, "m.room.member", &mxid, r#"{"membership":"join"}"#, 200, T0)
            .expect("join event");
        (room_id, mxid)
    }

    fn join_room(conn: &mut Connection, room_id: &str, user_id: i64, event_id: &str, stream_ts: i64) -> String {
        let mxid = matrix_store::ensure_matrix_user(conn, user_id, &format!("user{user_id:0>28}"), T0).expect("ensure user");
        matrix_store::apply_state_event(conn, event_id, room_id, user_id, "m.room.member", &mxid, r#"{"membership":"join"}"#, stream_ts, T0).expect("join event");
        mxid
    }

    fn next_batch_of(response: &serde_json::Value) -> sync_token::SyncToken {
        sync_token::parse(response["next_batch"].as_str().expect("next_batch is a string")).expect("parse next_batch")
    }

    fn join_room_block<'a>(response: &'a serde_json::Value, room_id: &str) -> Option<&'a serde_json::Value> {
        response["rooms"]["join"].get(room_id)
    }

    // ---- sync_token_is_strictly_monotonic_across_repeated_calls ----

    #[test]
    fn sync_token_is_strictly_monotonic_across_repeated_calls() {
        let mut conn = test_conn();
        let (room_id, alice) = make_joined_room(&mut conn, 1);
        let typing = live::TypingRegistry::new();
        let filter = SyncFilter::default();

        let r1 = build_sync_response(&conn, &typing, 1, &alice, "DEV1", None, &filter, false, Instant::now()).expect("initial sync");
        let token1 = next_batch_of(&r1);

        matrix_store::insert_timeline_event(&mut conn, "$e1", &room_id, 1, "m.room.message", "{}", 1000, None).expect("insert");

        let r2 = build_sync_response(&conn, &typing, 1, &alice, "DEV1", Some(token1), &filter, false, Instant::now()).expect("second sync");
        let token2 = next_batch_of(&r2);
        assert!(token2.stream_id > token1.stream_id, "a real write must advance the token");

        let r3 = build_sync_response(&conn, &typing, 1, &alice, "DEV1", Some(token2), &filter, false, Instant::now()).expect("third sync, nothing new");
        let token3 = next_batch_of(&r3);
        assert_eq!(token3.stream_id, token2.stream_id, "no writes happened between r2 and r3 — the token must not advance on its own");
    }

    // ---- limited_gap_includes_membership_events_for_non_sending_members_who_changed_inside_the_gap ----

    #[test]
    fn limited_gap_includes_membership_events_for_non_sending_members_who_changed_inside_the_gap() {
        let mut conn = test_conn();
        let (room_id, alice) = make_joined_room(&mut conn, 1);
        let bob = join_room(&mut conn, &room_id, 2, "$bobjoin", 300);
        let since = matrix_store::max_stream_id(&conn).expect("max stream id");

        // Bob changes his own displayname inside the gap — he never sends
        // anything, so he must NOT be a lazy-load sender.
        matrix_store::apply_state_event(&mut conn, "$bobname", &room_id, 2, "m.room.member", &bob, r#"{"membership":"join","displayname":"Bobby"}"#, 400, T0)
            .expect("bob renames");

        // Alice sends more messages than the filter's own tiny limit, so
        // the returned timeline window truncates BEFORE bob's rename.
        for i in 0..3 {
            matrix_store::insert_timeline_event(&mut conn, &format!("$msg{i}"), &room_id, 1, "m.room.message", "{}", 500 + i, None).expect("alice sends");
        }

        let mut filter = SyncFilter::default();
        filter.room.timeline.limit = Some(1);
        let typing = live::TypingRegistry::new();

        let response =
            build_sync_response(&conn, &typing, 1, &alice, "DEV1", Some(sync_token::SyncToken { stream_id: since, typing_gen: 0 }), &filter, false, Instant::now())
                .expect("incremental sync");

        let block = join_room_block(&response, &room_id).expect("room must be present — it has new events");
        assert!(block["timeline"]["limited"].as_bool().expect("limited flag"), "the fixture must actually trigger a gap");

        let state_events = block["state"]["events"].as_array().expect("state events");
        assert!(
            state_events.iter().any(|e| e["state_key"] == bob),
            "bob's own membership change inside the gap must be reported even though he never sent anything into the visible window: {state_events:?}"
        );
    }

    // ---- to_device_messages_are_deleted_once_since_advances_past_their_stream_id ----

    #[test]
    fn to_device_messages_are_deleted_once_since_advances_past_their_stream_id() {
        let mut conn = test_conn();
        let (_, alice) = make_joined_room(&mut conn, 1);
        matrix_keys_store::enqueue_to_device(&mut conn, 2, &[(1, "DEV1".to_string(), "m.room_key".to_string(), "{}".to_string())]).expect("enqueue");
        let mark = matrix_store::max_stream_id(&conn).expect("max stream id");

        let typing = live::TypingRegistry::new();
        let filter = SyncFilter::default();
        let response = build_sync_response(&conn, &typing, 1, &alice, "DEV1", Some(sync_token::SyncToken { stream_id: mark, typing_gen: 0 }), &filter, false, Instant::now())
            .expect("sync");
        assert!(response["to_device"]["events"].as_array().expect("array").is_empty(), "a since at/after the message's own stream_id must not redeliver it");

        let remaining = matrix_keys_store::to_device_for(&conn, 1, "DEV1", 0, 10).expect("to_device_for");
        assert!(remaining.is_empty(), "the acked row must have actually been deleted, not merely filtered out of the response");
    }

    // ---- highlight_count_is_always_zero ----

    #[test]
    fn highlight_count_is_always_zero() {
        let mut conn = test_conn();
        let (room_id, alice) = make_joined_room(&mut conn, 1);
        let _bob = join_room(&mut conn, &room_id, 2, "$bobjoin", 300);
        matrix_store::insert_timeline_event(&mut conn, "$m1", &room_id, 2, "m.room.message", "{}", 500, None).expect("bob sends");

        let typing = live::TypingRegistry::new();
        let filter = SyncFilter::default();
        let response = build_sync_response(&conn, &typing, 1, &alice, "DEV1", None, &filter, false, Instant::now()).expect("sync");
        let block = join_room_block(&response, &room_id).expect("room present");
        assert_eq!(block["unread_notifications"]["highlight_count"], 0);
        assert!(block["unread_notifications"]["notification_count"].as_i64().expect("count") >= 1);
    }

    // ---- initial_sync_with_no_since_marks_a_large_room_limited ----

    #[test]
    fn initial_sync_with_no_since_marks_a_large_room_limited() {
        let mut conn = test_conn();
        let (room_id, alice) = make_joined_room(&mut conn, 1);
        for i in 0..5 {
            matrix_store::insert_timeline_event(&mut conn, &format!("$m{i}"), &room_id, 1, "m.room.message", "{}", 500 + i, None).expect("send");
        }

        let mut filter = SyncFilter::default();
        filter.room.timeline.limit = Some(2);
        let typing = live::TypingRegistry::new();
        let response = build_sync_response(&conn, &typing, 1, &alice, "DEV1", None, &filter, false, Instant::now()).expect("initial sync");

        let block = join_room_block(&response, &room_id).expect("room present");
        assert!(block["timeline"]["limited"].as_bool().expect("limited"));
        assert_eq!(block["timeline"]["events"].as_array().expect("events").len(), 2);
    }

    // ---- typing_only_change_returns_ephemeral_without_busy_loop ----

    #[test]
    fn typing_only_change_returns_ephemeral_without_busy_loop() {
        let mut conn = test_conn();
        let (room_id, alice) = make_joined_room(&mut conn, 1);
        let since = matrix_store::max_stream_id(&conn).expect("max stream id");
        let typing = live::TypingRegistry::new();
        let t0 = Instant::now();
        assert!(typing.set_typing(&room_id, 1, true, 5_000, t0));

        let filter = SyncFilter::default();
        let first =
            build_sync_response(&conn, &typing, 1, &alice, "DEV1", Some(sync_token::SyncToken { stream_id: since, typing_gen: 0 }), &filter, false, t0).expect("first sync");
        let block = join_room_block(&first, &room_id).expect("typing must surface the room");
        assert_eq!(block["ephemeral"]["events"][0]["type"], "m.typing");

        let token1 = next_batch_of(&first);
        let second = build_sync_response(&conn, &typing, 1, &alice, "DEV1", Some(token1), &filter, false, t0).expect("second sync, nothing new");
        assert!(join_room_block(&second, &room_id).is_none(), "no further typing change since the last token — the room must not be re-reported");
    }

    // ---- private_receipt_only_in_own_sync ----

    #[test]
    fn private_receipt_only_in_own_sync() {
        let mut conn = test_conn();
        let (room_id, alice) = make_joined_room(&mut conn, 1);
        let bob = join_room(&mut conn, &room_id, 2, "$bobjoin", 300);
        let msg = matrix_store::insert_timeline_event(&mut conn, "$m1", &room_id, 1, "m.room.message", "{}", 500, None).expect("alice sends");
        let since = matrix_store::max_stream_id(&conn).expect("max stream id");
        matrix_store::upsert_receipt(&mut conn, &room_id, 2, ReceiptType::ReadPrivate, &msg.event_id, 600).expect("bob's private receipt");

        let typing = live::TypingRegistry::new();
        let filter = SyncFilter::default();
        let token = sync_token::SyncToken { stream_id: since, typing_gen: 0 };

        let bob_view = build_sync_response(&conn, &typing, 2, &bob, "DEVB", Some(token), &filter, false, Instant::now()).expect("bob's own sync");
        let bob_block = join_room_block(&bob_view, &room_id).expect("bob sees his own receipt");
        assert_eq!(bob_block["ephemeral"]["events"][0]["type"], "m.receipt");

        let alice_view = build_sync_response(&conn, &typing, 1, &alice, "DEV1", Some(token), &filter, false, Instant::now()).expect("alice's own sync");
        assert!(join_room_block(&alice_view, &room_id).is_none(), "a private receipt must never reach another user's /sync");
    }

    // ---- invited_room_appears_with_stripped_state ----

    #[test]
    fn invited_room_appears_with_stripped_state() {
        let mut conn = test_conn();
        let (room_id, _alice) = make_joined_room(&mut conn, 1);
        let bob = matrix_store::ensure_matrix_user(&conn, 2, "bob0000000000000000000000000099", T0).expect("bob");
        matrix_store::apply_state_event(&mut conn, "$invite_bob", &room_id, 1, "m.room.member", &bob, r#"{"membership":"invite"}"#, 400, T0).expect("invite bob");

        let typing = live::TypingRegistry::new();
        let filter = SyncFilter::default();
        let response = build_sync_response(&conn, &typing, 2, &bob, "DEVB", None, &filter, false, Instant::now()).expect("bob's initial sync");

        let block = response["rooms"]["invite"].get(&room_id).expect("invited room must be present");
        let events = block["invite_state"]["events"].as_array().expect("events");
        assert!(events.iter().any(|e| e["type"] == "m.room.create"), "stripped state must include m.room.create: {events:?}");
        assert!(
            events.iter().any(|e| e["type"] == "m.room.member" && e["state_key"] == bob),
            "the invitee's own invite member event must be included: {events:?}"
        );
    }

    // ---- left_room_timeline_ends_at_leave ----

    #[test]
    fn left_room_timeline_ends_at_leave() {
        let mut conn = test_conn();
        let (room_id, alice) = make_joined_room(&mut conn, 1);
        let since = matrix_store::max_stream_id(&conn).expect("max stream id");
        matrix_store::insert_timeline_event(&mut conn, "$before", &room_id, 1, "m.room.message", "{}", 500, None).expect("before leave");
        matrix_store::apply_state_event(&mut conn, "$leave", &room_id, 1, "m.room.member", &alice, r#"{"membership":"leave"}"#, 600, T0).expect("alice leaves");
        matrix_store::insert_timeline_event(&mut conn, "$after", &room_id, 2, "m.room.message", "{}", 700, None).expect("event after the leave (alice must never see it)");

        let mut filter = SyncFilter::default();
        filter.room.include_leave = true;
        let typing = live::TypingRegistry::new();
        let response =
            build_sync_response(&conn, &typing, 1, &alice, "DEV1", Some(sync_token::SyncToken { stream_id: since, typing_gen: 0 }), &filter, false, Instant::now())
                .expect("sync");

        let block = response["rooms"]["leave"].get(&room_id).expect("left room must be present");
        let events = block["timeline"]["events"].as_array().expect("events");
        assert_eq!(events.last().expect("at least one event")["event_id"], "$leave", "the timeline must end at (and include) the leave event");
        assert!(!events.iter().any(|e| e["event_id"] == "$after"), "nothing after the leave may ever be visible");
    }

    // ---- newly_joined_room_gets_full_state ----

    #[test]
    fn newly_joined_room_gets_full_state() {
        let mut conn = test_conn();
        let (room_a, alice) = make_joined_room(&mut conn, 1);
        let since = matrix_store::max_stream_id(&conn).expect("max stream id after room A");

        // Room B is created (with a little history) and alice joins it
        // AFTER `since`.
        matrix_store::ensure_matrix_user(&conn, 2, "creator0000000000000000000000001", T0).expect("ensure room B's creator");
        let room_b = "!roomB:mylittlechart.org".to_string();
        matrix_store::create_room(&conn, &room_b, matrix_store::RoomKind::Group, 2, T0, false, matrix_store::JoinRule::Invite, matrix_store::HistoryVisibility::Shared, None, None)
            .expect("create room B");
        matrix_store::apply_state_event(&mut conn, "$createB", &room_b, 2, "m.room.create", "", r#"{"room_version":"11"}"#, 700, T0).expect("create event B");
        matrix_store::insert_timeline_event(&mut conn, "$msgB1", &room_b, 2, "m.room.message", "{}", 750, None).expect("a message before alice joins");
        matrix_store::apply_state_event(&mut conn, "$joinB", &room_b, 1, "m.room.member", &alice, r#"{"membership":"join"}"#, 800, T0).expect("alice joins B");

        // A tiny timeline limit so room B's visible window (its OWN join
        // event only) does NOT already cover `m.room.create` — otherwise
        // `state` correctly excludes it as already-delivered-via-timeline
        // (manager review: state must not duplicate the timeline), and this
        // test would be asserting nothing meaningful.
        let mut filter = SyncFilter::default();
        filter.room.timeline.limit = Some(1);
        let typing = live::TypingRegistry::new();
        let response =
            build_sync_response(&conn, &typing, 1, &alice, "DEV1", Some(sync_token::SyncToken { stream_id: since, typing_gen: 0 }), &filter, false, Instant::now())
                .expect("incremental sync");

        assert!(join_room_block(&response, &room_a).is_none(), "room A had no changes since `since` and must be omitted");
        let block_b = join_room_block(&response, &room_b).expect("newly joined room B must be present");
        assert!(block_b["timeline"]["limited"].as_bool().expect("limited"), "the fixture must actually cap room B's timeline below its full history");
        let state_events = block_b["state"]["events"].as_array().expect("state events");
        assert!(
            state_events.iter().any(|e| e["type"] == "m.room.create"),
            "a newly joined room must backfill state NOT already covered by its (capped) visible timeline: {state_events:?}"
        );
    }

    // ---- to_device_redelivered_when_since_does_not_advance ----

    #[test]
    fn to_device_redelivered_when_since_does_not_advance() {
        let mut conn = test_conn();
        let (_, alice) = make_joined_room(&mut conn, 1);
        matrix_store::ensure_matrix_user(&conn, 2, "sender00000000000000000000000001", T0).expect("ensure sender");
        let before = matrix_store::max_stream_id(&conn).expect("max stream id");
        matrix_keys_store::enqueue_to_device(&mut conn, 2, &[(1, "DEV1".to_string(), "m.room_key".to_string(), "{}".to_string())]).expect("enqueue");

        let typing = live::TypingRegistry::new();
        let filter = SyncFilter::default();
        let token = sync_token::SyncToken { stream_id: before, typing_gen: 0 };

        let first = build_sync_response(&conn, &typing, 1, &alice, "DEV1", Some(token), &filter, false, Instant::now()).expect("first sync");
        assert_eq!(first["to_device"]["events"].as_array().expect("array").len(), 1);

        // The client does NOT advance `since` (e.g. it never durably
        // persisted the previous response) — the same message must be
        // redelivered, not silently dropped.
        let second = build_sync_response(&conn, &typing, 1, &alice, "DEV1", Some(token), &filter, false, Instant::now()).expect("second sync, same since");
        assert_eq!(second["to_device"]["events"].as_array().expect("array").len(), 1, "a since that never advanced must redeliver the same message");
    }

    // ---- device_lists_changed_and_left_follow_shared_rooms ----

    #[test]
    fn device_lists_changed_and_left_follow_shared_rooms() {
        let mut conn = test_conn();
        let (room_id, alice) = make_joined_room(&mut conn, 1);
        // Bob stays joined for the whole test — his device-list change must
        // land in `changed`.
        let bob = join_room(&mut conn, &room_id, 2, "$bobjoin", 300);
        // Dave leaves the only room he shares with alice inside the
        // window — his device-list change must land in `left`, NOT
        // `changed` (he no longer shares a room with alice as of `upto`).
        let dave = join_room(&mut conn, &room_id, 4, "$davejoin", 350);
        matrix_store::ensure_matrix_user(&conn, 3, "carol000000000000000000000000099", T0).expect("carol"); // never shares a room with alice
        let since = matrix_store::max_stream_id(&conn).expect("max stream id");

        matrix_keys_store::log_device_list_change(&mut conn, 2, T0).expect("bob's device list changed");
        matrix_keys_store::log_device_list_change(&mut conn, 3, T0).expect("carol's device list changed too, but she is not visible to alice");
        matrix_keys_store::log_device_list_change(&mut conn, 4, T0).expect("dave's device list changed just before he leaves");
        matrix_store::apply_state_event(&mut conn, "$daveleave", &room_id, 4, "m.room.member", &dave, r#"{"membership":"leave"}"#, 900, T0).expect("dave leaves");

        let typing = live::TypingRegistry::new();
        let filter = SyncFilter::default();
        let response =
            build_sync_response(&conn, &typing, 1, &alice, "DEV1", Some(sync_token::SyncToken { stream_id: since, typing_gen: 0 }), &filter, false, Instant::now())
                .expect("sync");

        let changed = response["device_lists"]["changed"].as_array().expect("changed");
        assert!(changed.iter().any(|v| v == &bob), "bob still shares a room with alice and his device list changed: {changed:?}");
        assert!(!changed.iter().any(|v| v == &dave), "dave no longer shares any room with alice as of `upto` — he belongs in `left`, not `changed`: {changed:?}");
        assert!(!changed.iter().any(|v| v.as_str() == Some("@carol000000000000000000000000099:mylittlechart.org")), "carol never shared a room with alice");

        let left = response["device_lists"]["left"].as_array().expect("left");
        assert!(left.iter().any(|v| v == &dave), "dave left the only room he shared with alice: {left:?}");
        assert!(!left.iter().any(|v| v == &bob), "bob never left — he must not appear in `left`");
    }

    // ---- consistent_cut_ignores_events_after_upto ----

    #[test]
    fn consistent_cut_ignores_events_after_upto() {
        let mut conn = test_conn();
        let (room_id, _alice) = make_joined_room(&mut conn, 1);
        let before = matrix_store::max_stream_id(&conn).expect("max stream id");
        matrix_store::apply_state_event(&mut conn, "$name1", &room_id, 1, "m.room.name", "", r#"{"name":"first"}"#, 1000, T0).expect("name change 1");
        let mid = matrix_store::max_stream_id(&conn).expect("max stream id after first change");
        matrix_store::apply_state_event(&mut conn, "$name2", &room_id, 1, "m.room.name", "", r#"{"name":"second"}"#, 2000, T0).expect("name change 2");

        let changed = matrix_store::non_member_state_changed_in_window(&conn, &room_id, before, mid).expect("query");
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].event_id, "$name1", "a change after `upto` must never leak into a cut bounded at an earlier point");
    }

    // ---- state_block_excludes_events_present_in_timeline ----

    #[test]
    fn state_block_excludes_events_present_in_timeline() {
        let mut conn = test_conn();
        let (room_id, alice) = make_joined_room(&mut conn, 1);
        let since = matrix_store::max_stream_id(&conn).expect("max stream id");
        matrix_store::apply_state_event(&mut conn, "$name1", &room_id, 1, "m.room.name", "", r#"{"name":"first"}"#, 1000, T0).expect("name change");

        let typing = live::TypingRegistry::new();
        let filter = SyncFilter::default();
        let response =
            build_sync_response(&conn, &typing, 1, &alice, "DEV1", Some(sync_token::SyncToken { stream_id: since, typing_gen: 0 }), &filter, false, Instant::now())
                .expect("non-limited incremental sync");
        let block = join_room_block(&response, &room_id).expect("room present — the name change is a new event");

        let timeline_ids: Vec<&str> = block["timeline"]["events"].as_array().expect("timeline events").iter().map(|e| e["event_id"].as_str().expect("event_id")).collect();
        assert!(timeline_ids.contains(&"$name1"), "the name change must appear in the timeline: {timeline_ids:?}");

        let state_ids: Vec<&str> = block["state"]["events"].as_array().expect("state events").iter().map(|e| e["event_id"].as_str().expect("event_id")).collect();
        assert!(
            !state_ids.contains(&"$name1"),
            "an event already present in the (non-limited) timeline must not be duplicated into state: {state_ids:?}"
        );
    }

    // ---- incremental_sync_touches_only_changed_rooms ----

    #[test]
    fn incremental_sync_touches_only_changed_rooms() {
        let mut conn = test_conn();
        let (room_a, alice) = make_joined_room(&mut conn, 1);
        let extra_room_ids: Vec<String> = (0..4).map(|i| format!("!extra{i}:mylittlechart.org")).collect();
        for (i, room_id) in extra_room_ids.iter().enumerate() {
            matrix_store::create_room(&conn, room_id, matrix_store::RoomKind::Group, 1, T0, false, matrix_store::JoinRule::Invite, matrix_store::HistoryVisibility::Shared, None, None)
                .expect("create extra room");
            matrix_store::apply_state_event(&mut conn, &format!("$extrajoin{i}"), room_id, 1, "m.room.member", &alice, r#"{"membership":"join"}"#, 100, T0)
                .expect("alice joins extra room");
        }
        let since = matrix_store::max_stream_id(&conn).expect("max stream id");

        // Only room_a changes after `since`.
        matrix_store::insert_timeline_event(&mut conn, "$only_change", &room_a, 1, "m.room.message", "{}", 1000, None).expect("alice sends in room A");
        let upto = matrix_store::max_stream_id(&conn).expect("max stream id after the write");

        let joined_room_ids = matrix_store::rooms_for_user(&conn, 1, Some(Membership::Join)).expect("joined rooms");
        assert_eq!(joined_room_ids.len(), 5, "fixture must actually create 5 joined rooms");

        // The prefilter itself must identify EXACTLY the one room that
        // actually changed — this is the mechanism that keeps the full
        // room-block builder from ever running against the other four.
        let changed = matrix_store::rooms_changed_in_window(&conn, &joined_room_ids, 1, since, upto).expect("changed rooms");
        assert_eq!(changed, std::collections::HashSet::from([room_a.clone()]), "the prefilter must report exactly the one changed room: {changed:?}");

        let typing = live::TypingRegistry::new();
        let filter = SyncFilter::default();
        let response =
            build_sync_response(&conn, &typing, 1, &alice, "DEV1", Some(sync_token::SyncToken { stream_id: since, typing_gen: 0 }), &filter, false, Instant::now())
                .expect("incremental sync");
        let join_rooms = response["rooms"]["join"].as_object().expect("join map");
        assert_eq!(join_rooms.len(), 1, "only the one changed room may be reported: {join_rooms:?}");
        assert!(join_rooms.contains_key(&room_a));
    }

    // ---- lazy_load_includes_timeline_senders_only ----

    #[test]
    fn lazy_load_includes_timeline_senders_only() {
        let mut conn = test_conn();
        let (room_id, alice) = make_joined_room(&mut conn, 1);
        let bob = join_room(&mut conn, &room_id, 2, "$bobjoin", 300);
        let _carol = join_room(&mut conn, &room_id, 3, "$caroljoin", 400);
        matrix_store::insert_timeline_event(&mut conn, "$m1", &room_id, 1, "m.room.message", "{}", 500, None).expect("alice sends");

        // A tiny timeline limit so the returned window is only alice's
        // latest message — NOT the three older join events (which would
        // otherwise legitimately put bob/carol in the lazy-load set too,
        // since a member's own join event is itself a timeline entry whose
        // sender is that member).
        let mut filter = SyncFilter::default();
        filter.room.timeline.limit = Some(1);
        let typing = live::TypingRegistry::new();
        let response = build_sync_response(&conn, &typing, 1, &alice, "DEV1", None, &filter, false, Instant::now()).expect("initial sync");
        let block = join_room_block(&response, &room_id).expect("room present");
        let state_events = block["state"]["events"].as_array().expect("state events");

        assert!(state_events.iter().any(|e| e["type"] == "m.room.member" && e["state_key"] == alice), "alice sent — she must be lazy-loaded");
        assert!(!state_events.iter().any(|e| e["type"] == "m.room.member" && e["state_key"] == bob), "bob never sent — he must not be lazy-loaded");
    }

    // ---- long_poll_returns_early_on_wake ----

    #[tokio::test]
    async fn long_poll_returns_early_on_wake() {
        let mut conn = test_conn();
        let (room_id, alice) = make_joined_room(&mut conn, 1);
        let since = matrix_store::max_stream_id(&conn).expect("max stream id");
        let conn = Arc::new(StdMutex::new(conn));
        let live_registry = live::LiveRegistry::new();
        let typing = live::TypingRegistry::new();
        let filter = SyncFilter::default();
        let token = sync_token::SyncToken { stream_id: since, typing_gen: 0 };

        let conn_for_build = conn.clone();
        let typing_ref = &typing;
        let filter_ref = &filter;
        let alice_ref = alice.as_str();
        let deadline = Instant::now() + Duration::from_secs(30);

        let poll_future = long_poll(&live_registry, "user:1", deadline, || {
            let conn = conn_for_build.clone();
            async move {
                let guard = conn.lock().unwrap_or_else(|e| e.into_inner());
                build_sync_response(&guard, typing_ref, 1, alice_ref, "DEV1", Some(token), filter_ref, false, Instant::now())
            }
        });

        let conn_for_writer = conn.clone();
        let writer_future = async {
            let mut guard = conn_for_writer.lock().unwrap_or_else(|e| e.into_inner());
            matrix_store::insert_timeline_event(&mut guard, "$wake1", &room_id, 1, "m.room.message", "{}", 500, None).expect("insert");
            drop(guard);
            live_registry.wake("user:1");
        };

        let response = tokio::time::timeout(Duration::from_secs(2), async {
            let (response, ()) = tokio::join!(poll_future, writer_future);
            response
        })
        .await
        .expect("must return well before the 30s deadline")
        .expect("sync response");

        assert!(!sync_response_is_empty(&response), "the wake must trigger a rebuild that observes the new message");
        let block = join_room_block(&response, &room_id).expect("room present after the wake");
        assert!(block["timeline"]["events"].as_array().expect("events").iter().any(|e| e["event_id"] == "$wake1"));
    }
}

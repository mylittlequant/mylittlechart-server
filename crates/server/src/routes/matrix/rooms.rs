//! Matrix chat rooms — `createRoom`, membership (join/leave/invite/kick/
//! ban/unban/forget), `joined_rooms`, room state (GET/PUT, single and all),
//! members/joined_members (P5). See
//! `docs/mlc/plans/messenger-proto-server-matrix-subset-2026-09-24.md` §4
//! (endpoint table + gate definitions), §5 (power levels + room-kind
//! presets), and the P5 brief's corrections (DM detection,
//! `power_level_content_override`, `m.room.encryption` rules, the
//! `invite_room_state` decision — see `super::client_event_json` and
//! [`mylittlechart_server::matrix_store::stripped_invite_state`]).
//!
//! **Naming collision note**: `routes::rooms` (existing, `routes/rooms.rs`)
//! is the unrelated shared-presets "objects/rooms" feature. This module is
//! the disjoint Matrix chat-rooms path — see `routes::matrix`'s own module
//! doc.
//!
//! # Every write is one transaction, then one wake
//!
//! Every handler below does its DB work inside a single `spawn_blocking`
//! closure, computes the set of `user_id`s the write affects (every current
//! joined+invited member, plus the target of a membership change), and
//! returns that set to the async caller, which calls
//! `state.control_plane().live.wake_many(...)` only AFTER the
//! `spawn_blocking` future resolves — never while the `messenger` connection
//! mutex is still held (`live.rs`'s own module doc states the same rule).
//!
//! # Lock order
//!
//! Identity (`cp.db`) THEN social (`cp.social_conn()`) THEN messenger
//! (`cp.messenger_conn()`) — matching `routes::matrix::auth`'s own stated
//! convention. A handler never acquires `cp.db` while a `messenger_conn`
//! guard from an EARLIER step in the same closure is still alive; every
//! lock is taken, used, and dropped inside its own `{ ... }` block before
//! the next one is taken, so no two locks are ever held out of order even
//! though several handlers touch all three connections in sequence.
//!
//! # Testable cores
//!
//! Every DB-only decision this module makes (kind derivation, power-level-
//! override validation, the encryption-state-change rule, and the actual
//! membership/invite mutation logic) is split into a plain function taking
//! `&Connection`/values — never `MatrixCaller`/`AppState` — so it is unit-
//! tested against an in-memory `matrix_store` fixture with no axum or
//! `tokio::task::spawn_blocking` involved at all.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::routing::post;
use axum::{Json, Router};
use rusqlite::{params, Connection, OptionalExtension};

use mylittlechart_server::matrix_store::{self, HistoryVisibility, JoinRule, Membership, PowerAction, Room, RoomKind};

use super::auth;
use super::{client_event_json, MatrixError};
use crate::db;
use crate::state::AppState;

// ============================================================================
// Router
// ============================================================================

/// The plan §4 room-route table, mounted (via `.merge`) into
/// `routes::matrix::router` before `.with_state` — see this module's own
/// doc for why every path segment count here is deliberate (an empty
/// Matrix `stateKey` needs its own route, since axum path segments cannot
/// themselves be empty).
pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/client/v3/createRoom", post(create_room))
        .route("/client/v3/joined_rooms", get(joined_rooms))
        .route("/client/v3/rooms/{room_id}/join", post(join_room))
        .route("/client/v3/rooms/{room_id}/leave", post(leave_room))
        .route("/client/v3/rooms/{room_id}/invite", post(invite_member))
        .route("/client/v3/rooms/{room_id}/kick", post(kick_member))
        .route("/client/v3/rooms/{room_id}/ban", post(ban_member))
        .route("/client/v3/rooms/{room_id}/unban", post(unban_member))
        .route("/client/v3/rooms/{room_id}/forget", post(forget_room))
        .route("/client/v3/rooms/{room_id}/state", get(get_state_all))
        .route(
            "/client/v3/rooms/{room_id}/state/{event_type}",
            get(get_state_no_key).put(put_state_no_key),
        )
        .route(
            "/client/v3/rooms/{room_id}/state/{event_type}/{state_key}",
            get(get_state).put(put_state),
        )
        .route("/client/v3/rooms/{room_id}/members", get(get_members))
        .route("/client/v3/rooms/{room_id}/joined_members", get(get_joined_members))
}

// ============================================================================
// Request bodies
// ============================================================================

#[derive(serde::Deserialize, Default)]
struct CreateRoomRequest {
    #[serde(default)]
    visibility: Option<String>,
    #[serde(default)]
    is_direct: bool,
    #[serde(default)]
    invite: Vec<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    topic: Option<String>,
    #[serde(default)]
    power_level_content_override: Option<serde_json::Value>,
    /// No room-alias namespace exists at all (plan §10 item 4) — a non-empty
    /// value is refused outright rather than silently dropped, so a client
    /// never believes an alias was actually set.
    #[serde(default)]
    room_alias_name: Option<String>,
    // `preset`/`initial_state` are intentionally NOT fields here: every
    // bootstrap state event is server-derived from `kind` (§5), never
    // client-declared, and serde ignores unrecognized JSON keys by default
    // (no `deny_unknown_fields`) — so a client that still sends them (many
    // Matrix SDKs send `preset` unconditionally) is silently unaffected
    // rather than needing a field this struct would otherwise never read.
}

#[derive(serde::Deserialize)]
struct UserIdBody {
    user_id: String,
}

#[derive(serde::Deserialize)]
struct KickBanBody {
    user_id: String,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(serde::Deserialize, Default)]
struct MembersQuery {
    membership: Option<String>,
    at: Option<i64>,
}

// ============================================================================
// Pure decision functions — no DB, no `MatrixCaller`, unit-tested directly
// ============================================================================

/// Kind derivation (plan P5 correction): `is_direct: true` requires EXACTLY
/// ONE `invite[]` entry (the peer; the creator is the other member) or
/// refuses with `M_INVALID_PARAM`; otherwise `visibility == "public"` ->
/// `channel`; otherwise `group`.
fn derive_room_kind(is_direct: bool, invite_count: usize, visibility_public: bool) -> Result<RoomKind, MatrixError> {
    if is_direct {
        return if invite_count == 1 {
            Ok(RoomKind::Dm)
        } else {
            Err(MatrixError::invalid_param("is_direct requires exactly one invite target"))
        };
    }
    if visibility_public {
        return Ok(RoomKind::Channel);
    }
    Ok(RoomKind::Group)
}

/// `content` with the user's `displayname` stamped in. The server owns this
/// field of every `join`/`invite` member event it writes (the Matrix
/// convention): a client names a DM after the peer's member-event
/// `displayname` and lists members by it, falling back to the mxid localpart
/// (the 32-hex public id) when it is absent. An empty `displayname` (no
/// identity row behind the user) leaves the field out rather than stamping
/// an empty name.
fn with_displayname(mut content: serde_json::Value, displayname: &str) -> serde_json::Value {
    if !displayname.is_empty() {
        content["displayname"] = serde_json::Value::String(displayname.to_string());
    }
    content
}

/// The `content` of a `join` `m.room.member` event for a user whose
/// effective label is `displayname` (see [`with_displayname`]).
/// `pub(crate)` — the legacy-DM migration's bootstrap writes the same event.
pub(crate) fn join_member_content(displayname: &str) -> serde_json::Value {
    with_displayname(serde_json::json!({ "membership": "join" }), displayname)
}

/// The `content` of the invitee's `m.room.member` invite event, carrying the
/// invitee's own effective label as `displayname`. A DM invite also carries
/// `is_direct: true` (the Matrix convention): the invitee's client reads it
/// from `invite_state` to classify the room as a DM and record it in
/// `m.direct`; without it the room would surface as a group. Every other
/// kind carries the membership and the `displayname` only.
fn invite_member_content(kind: RoomKind, displayname: &str) -> serde_json::Value {
    let mut content = with_displayname(serde_json::json!({ "membership": "invite" }), displayname);
    if kind == RoomKind::Dm {
        content["is_direct"] = serde_json::Value::Bool(true);
    }
    content
}

/// A joined user's own `m.room.member` update (`PUT state`, the profile-update
/// exception in [`check_state_event_type_allowed`]) with `displayname`
/// forced to the effective label: the nick is the source of truth (`PUT
/// /profile/{userId}/displayname` is refused for the same reason), so a
/// client-chosen name is overwritten, and dropped when there is no label to
/// stamp instead. Every other field of the client's content is kept.
fn stamp_own_member_displayname(content: &str, displayname: &str) -> Result<String, MatrixError> {
    let mut value: serde_json::Value = serde_json::from_str(content)?;
    let Some(fields) = value.as_object_mut() else {
        return Err(MatrixError::invalid_param("m.room.member content must be an object"));
    };
    if displayname.is_empty() {
        fields.remove("displayname");
    } else {
        fields.insert("displayname".to_string(), serde_json::Value::String(displayname.to_string()));
    }
    Ok(value.to_string())
}

/// The creator's `join` and every invitee's `invite` `m.room.member` state
/// events of a fresh room, each stamped with its own user's effective label
/// (`invitees` is `(mxid, label)` per invited user). The creator's event
/// comes first: `m.room.power_levels` must follow the member events it
/// refers to (see [`matrix_store::create_room_with_state`]).
fn bootstrap_member_events(kind: RoomKind, creator: (i64, &str, &str), invitees: &[(String, String)]) -> Vec<matrix_store::NewStateEvent> {
    let (creator_user_id, creator_mxid, creator_label) = creator;
    let mut events = vec![state_event("m.room.member", creator_mxid, creator_user_id, join_member_content(creator_label))];
    for (mxid, label) in invitees {
        events.push(state_event("m.room.member", mxid, creator_user_id, invite_member_content(kind, label)));
    }
    events
}

/// `join_rule`, `history_visibility`, `is_encrypted` per plan §5's table.
/// `pub(crate)` — also the P12 legacy-DM migration's bootstrap builder (see
/// `routes::matrix::mod`'s own doc comment on `pub(crate) mod rooms`).
pub(crate) fn room_kind_settings(kind: RoomKind) -> (JoinRule, HistoryVisibility, bool) {
    match kind {
        RoomKind::Dm => (JoinRule::Invite, HistoryVisibility::Shared, true),
        RoomKind::Group => (JoinRule::Invite, HistoryVisibility::Shared, true),
        RoomKind::Channel => (JoinRule::Public, HistoryVisibility::WorldReadable, false),
    }
}

/// `power_level_content_override` validation (P5 correction): accepted with
/// ONLY the `invite` key (value `0` or `50`), and only for `group` rooms
/// ("members can add people," §5). Any other key, an out-of-range value, or
/// use on a non-group room is refused with `M_INVALID_PARAM`. Returns the
/// override value to apply (`None` if the object was absent/empty).
fn validate_power_level_override(kind: RoomKind, override_value: &Option<serde_json::Value>) -> Result<Option<i64>, MatrixError> {
    let Some(value) = override_value else { return Ok(None) };
    let obj = value.as_object().ok_or_else(|| MatrixError::invalid_param("power_level_content_override must be an object"))?;
    if obj.keys().any(|k| k != "invite") {
        return Err(MatrixError::invalid_param("power_level_content_override only accepts the 'invite' key"));
    }
    let Some(invite_value) = obj.get("invite") else { return Ok(None) };
    if kind != RoomKind::Group {
        return Err(MatrixError::invalid_param("power_level_content_override is only accepted for group rooms"));
    }
    match invite_value.as_i64() {
        Some(0) => Ok(Some(0)),
        Some(50) => Ok(Some(50)),
        _ => Err(MatrixError::invalid_param("power_level_content_override.invite must be 0 or 50")),
    }
}

/// `power_levels.invite` for a fresh room (plan §5): `dm`/`channel` are
/// fixed at `50`; `group` defaults to `50` unless
/// [`validate_power_level_override`] returned an explicit override.
/// `pub(crate)` — also used by the P12 legacy-DM migration.
pub(crate) fn invite_power_level(kind: RoomKind, override_value: Option<i64>) -> i64 {
    match kind {
        RoomKind::Dm | RoomKind::Channel => 50,
        RoomKind::Group => override_value.unwrap_or(50),
    }
}

/// The `m.room.power_levels` content for a fresh room (plan §5): the
/// creator at `100`, every other field at the table's fixed defaults except
/// `events_default` (raised to `50` for a `channel` — announcement-only).
/// `pub(crate)` — reused verbatim by the P12 legacy-DM migration, so a
/// migrated room's power levels are byte-for-byte what a native `createRoom`
/// call would have produced.
pub(crate) fn power_levels_content(creator_mxid: &str, kind: RoomKind, invite_level: i64) -> serde_json::Value {
    let events_default = if kind == RoomKind::Channel { 50 } else { 0 };
    serde_json::json!({
        "users": { creator_mxid: 100 },
        "users_default": 0,
        "events_default": events_default,
        "state_default": 50,
        "ban": 50,
        "kick": 50,
        "redact": 50,
        "invite": invite_level,
    })
}

/// `PUT state/{eventType}/{stateKey}`'s `m.room.encryption` rule (P5
/// correction): refuse changing/removing an EXISTING encryption event
/// outright, and refuse setting it for the first time on a public room.
/// Every other event type is unconditionally fine as far as this rule goes.
fn check_encryption_state_change(event_type: &str, join_rule: JoinRule, already_encrypted: bool) -> Result<(), MatrixError> {
    if event_type != "m.room.encryption" {
        return Ok(());
    }
    if already_encrypted {
        return Err(MatrixError::forbidden("encryption cannot be changed once set"));
    }
    if join_rule == JoinRule::Public {
        return Err(MatrixError::forbidden("encryption cannot be enabled on a public room"));
    }
    Ok(())
}

/// `PUT state` must never touch `m.room.create` or `m.room.member` (manager
/// review, 2026-09-24 — a real gap: the generic `PUT state/{type}/{key}`
/// route had no type-specific refusal at all, so a Member with enough
/// `state_default` power could rewrite `m.room.create`'s content, or
/// silently kick/invite/ban a target by PUTting their `m.room.member`
/// event directly, bypassing every kick/ban/invite-specific rule this
/// module otherwise enforces (target-level checks, txn-dedup, the right
/// wake set, ...). The ONE exception: a joined user updating their OWN
/// `m.room.member` event while its `membership` stays `join` (a profile
/// update; [`put_state_inner`] then forces its `displayname` to the nick's
/// effective label via [`stamp_own_member_displayname`], so the client's own
/// name never sticks) — membership itself only ever changes through
/// join/leave/invite/kick/ban.
fn check_state_event_type_allowed(event_type: &str, state_key: &str, caller_mxid: &str, content_str: &str) -> Result<(), MatrixError> {
    if event_type == "m.room.create" {
        return Err(MatrixError::forbidden("m.room.create cannot be modified"));
    }
    if event_type == "m.room.member" {
        let membership: Option<String> = serde_json::from_str::<serde_json::Value>(content_str)
            .ok()
            .and_then(|v| v.get("membership").and_then(|m| m.as_str()).map(str::to_string));
        let is_own_join_update = state_key == caller_mxid && membership.as_deref() == Some("join");
        if !is_own_join_update {
            return Err(MatrixError::forbidden(
                "m.room.member only changes via join/leave/invite/kick/ban, except your own profile update while still joined",
            ));
        }
    }
    Ok(())
}

/// `(lo, hi)`-ordered pair key for a DM between two internal user ids — the
/// same trick `dm_conversations` already uses (`dm_db.rs`), reused here for
/// `rooms.dm_pair_key`. `pub(crate)` — also used by the P12 legacy-DM
/// migration.
pub(crate) fn dm_pair_key(a: i64, b: i64) -> String {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    format!("{lo}:{hi}")
}

/// `pub(crate)` — also used by the P12 legacy-DM migration to build its own
/// bootstrap state events through the same helper `create_room` uses.
pub(crate) fn state_event(event_type: &str, state_key: &str, sender_user_id: i64, content: serde_json::Value) -> matrix_store::NewStateEvent {
    matrix_store::NewStateEvent {
        event_id: matrix_store::new_event_id(),
        sender_user_id,
        event_type: event_type.to_string(),
        state_key: state_key.to_string(),
        content: content.to_string(),
    }
}

// ============================================================================
// DB-only gate/read helpers — `&Connection`, no `MatrixCaller`
// ============================================================================

/// `m.room.power_levels`' content, or the empty object (every threshold then
/// resolves to its Matrix default via [`matrix_store::user_level`]/
/// [`matrix_store::event_level`]) if the room has never had one applied.
fn power_levels_of(conn: &Connection, room_id: &str) -> Result<serde_json::Value, MatrixError> {
    match matrix_store::current_state_event(conn, room_id, "m.room.power_levels", "")? {
        Some(event) => Ok(serde_json::from_str(&event.content)?),
        None => Ok(serde_json::json!({})),
    }
}

/// The plan §4 "Member" gate: a `room_members` row with `membership='join'`.
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

/// kick/ban/unban's own gate (manager review, 2026-09-24): beyond the flat
/// [`require_power`] threshold, the caller's level must be STRICTLY
/// GREATER than the target's current level — see
/// [`matrix_store::can_act_on`]'s own doc for why a level-50 admin must
/// never be able to touch a level-100 owner or an equal-level peer.
fn require_power_over_target(power_levels: &serde_json::Value, caller_mxid: &str, target_mxid: &str, action: PowerAction, self_leave: bool) -> Result<(), MatrixError> {
    if matrix_store::can_act_on(power_levels, action, caller_mxid, target_mxid, self_leave) {
        Ok(())
    } else {
        Err(MatrixError::forbidden("insufficient power level for this action"))
    }
}

/// The plan §4 "PubRead" gate: Member, OR any signed-in caller when the
/// room is a public, world-readable channel.
fn require_pub_read(conn: &Connection, room: &Room, user_id: i64) -> Result<(), MatrixError> {
    let membership = matrix_store::room_member(conn, &room.id, user_id)?.map(|m| m.membership);
    if matches!(membership, Some(Membership::Join)) {
        return Ok(());
    }
    if room.join_rule == JoinRule::Public && room.history_visibility == HistoryVisibility::WorldReadable {
        return Ok(());
    }
    Err(MatrixError::forbidden("no read access to this room"))
}

/// Every user id currently `join`ed OR `invite`d in `room_id` — the wake
/// fan-out set for a write that affects the whole room (plan §3.1/§4:
/// "wakes every joined AND invited member"). `pub(crate)` (not `pub(super)`)
/// so both `routes::matrix::messaging` (P6) and `routes::dm`'s legacy-DM
/// bridge (P15, outside this module tree) reuse the SAME wake-set
/// computation rather than a second copy — see each module's own doc.
pub(crate) fn member_and_invited_ids(conn: &Connection, room_id: &str) -> rusqlite::Result<HashSet<i64>> {
    let mut ids = HashSet::new();
    for member in matrix_store::room_members(conn, room_id, Some(Membership::Join))? {
        ids.insert(member.user_id);
    }
    for member in matrix_store::room_members(conn, room_id, Some(Membership::Invite))? {
        ids.insert(member.user_id);
    }
    Ok(ids)
}

/// Resolve `SELECT id FROM users WHERE public_id = ?1` directly (module-
/// local, per this codebase's convention of NOT centralizing every small
/// label/id lookup in `db.rs` — see `routes::dm::resolve_user_by_label`'s
/// own doc for the same pattern).
fn resolve_user_id_by_public_id(conn: &Connection, public_id: &str) -> rusqlite::Result<Option<i64>> {
    conn.query_row("SELECT id FROM users WHERE public_id = ?1", params![public_id], |row| row.get(0))
        .optional()
}

/// Resolve an invite/kick/ban target's mxid to an internal `user_id` (plan
/// P5 correction): try `messenger.db`'s own `matrix_users` mapping first;
/// on a miss, parse the mxid's localpart as a `public_id`, look it up in the
/// identity database, then [`matrix_store::ensure_matrix_user`] it (first
/// touch). Refuses with `M_NOT_FOUND` for an mxid naming no real account.
fn resolve_target_user(identity_conn: &Connection, messenger_conn: &Connection, mxid: &str, now: &str) -> Result<i64, MatrixError> {
    if let Some(user_id) = matrix_store::user_id_of(messenger_conn, mxid)? {
        return Ok(user_id);
    }
    let public_id = matrix_store::public_id_from_mxid(mxid).map_err(|e| MatrixError::invalid_param(e.to_string()))?;
    let user_id = resolve_user_id_by_public_id(identity_conn, public_id)?.ok_or_else(|| MatrixError::not_found(format!("Unknown user: {mxid}")))?;
    matrix_store::ensure_matrix_user(messenger_conn, user_id, public_id, now)?;
    Ok(user_id)
}

/// The DM-reuse lookup (plan P5 correction): if `pair_key` currently names a
/// room, return its id when it is STILL a live DM for both `user_a` and
/// `user_b` (both `join`/`invite`, neither `leave`d out); otherwise free the
/// pair key on that dead room (`rooms.dm_pair_key` is `UNIQUE`, so a fresh
/// room reusing this pair key needs the slot released first) and return
/// `None`, telling the caller to mint a new room. `pub(crate)` — the legacy-DM
/// migration adopts a live native DM through the same lookup.
pub(crate) fn find_reusable_dm_room(conn: &Connection, pair_key: &str, user_a: i64, user_b: i64) -> rusqlite::Result<Option<String>> {
    let Some(existing) = matrix_store::room_by_dm_pair_key(conn, pair_key)? else {
        return Ok(None);
    };
    let members = matrix_store::room_members(conn, &existing.id, None)?;
    let alive = |uid: i64| members.iter().any(|m| m.user_id == uid && matches!(m.membership, Membership::Join | Membership::Invite));
    if alive(user_a) && alive(user_b) {
        return Ok(Some(existing.id));
    }
    matrix_store::clear_dm_pair_key(conn, &existing.id)?;
    Ok(None)
}

/// [`auth::is_messenger_paid`]'s ladder check, resolved fresh against both
/// connections it needs (identity for [`db::user_is_paid`], social for the
/// ladder itself) — every caller here already holds no `messenger` lock at
/// the point it calls this (see the module doc's lock-order note).
fn is_paid_now(cp: &crate::state::ControlPlane, user_id: i64) -> rusqlite::Result<bool> {
    let is_paid_flag = {
        let identity_conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
        db::user_is_paid(&identity_conn, user_id)?
    };
    let social_conn = cp.social_conn();
    Ok(auth::is_messenger_paid(&social_conn, user_id, is_paid_flag))
}

/// Whether `user_id` has ever chosen a nick — the write gate `createRoom`/
/// `invite` share with `routes::dm`'s own `require_nick` (own copy per this
/// codebase's one-copy-per-route-module convention).
fn has_nick_now(cp: &crate::state::ControlPlane, user_id: i64) -> rusqlite::Result<bool> {
    let identity_conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
    Ok(db::user_nick(&identity_conn, user_id)?.is_some())
}

/// `user_id`'s effective label ([`db::effective_label_for_user`]: nick, then
/// the provider display name, then the public id) under a short identity
/// lock — the `displayname` every server-written `join`/`invite` member event
/// carries. The caller must hold NO `messenger` (or `social`) guard: lock
/// order is `db` -> `social` -> `messenger`.
fn effective_label_now(cp: &crate::state::ControlPlane, user_id: i64) -> rusqlite::Result<String> {
    let identity_conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
    db::effective_label_for_user(&identity_conn, user_id)
}

// ============================================================================
// Display-name propagation — a changed nick re-stamps the user's member events
// ============================================================================

/// Re-stamp `user_id`'s current effective label into their `m.room.member`
/// event in every room they are `join`ed or `invite`d in
/// ([`matrix_store::refresh_member_displayname`]), after a nick change
/// committed to the identity database. Returns the users to wake (empty when
/// the user never used the messenger). Never fails the nick change that
/// called it — that change is already committed: a failure here is logged,
/// and the boot backfill ([`backfill_member_displaynames`]) converges the
/// stale event on the next start.
///
/// Locks: `db` (label, released), then `messenger` — in that order, never
/// nested. The caller must hold NO `db` guard (the mutex is not reentrant)
/// and must wake the returned set only after its own `spawn_blocking`
/// resolves, like every other write in this module.
pub(crate) fn propagate_display_name_change(cp: &crate::state::ControlPlane, user_id: i64) -> HashSet<i64> {
    let label = match effective_label_now(cp, user_id) {
        Ok(label) => label,
        Err(e) => {
            tracing::error!("display-name propagation: label lookup for user {} failed: {}", user_id, e);
            return HashSet::new();
        }
    };
    let now = chrono::Utc::now().to_rfc3339();
    let origin_ts = chrono::Utc::now().timestamp_millis();
    let mut messenger_conn = cp.messenger_conn();
    match matrix_store::refresh_member_displayname(&mut messenger_conn, user_id, &label, &now, origin_ts) {
        Ok(refresh) => {
            if refresh.rooms_updated > 0 {
                tracing::info!("display-name propagation: user {} re-stamped in {} room(s)", user_id, refresh.rooms_updated);
            }
            refresh.affected_user_ids
        }
        Err(e) => {
            tracing::error!("display-name propagation: user {} failed: {:?}", user_id, e);
            HashSet::new()
        }
    }
}

/// Boot backfill: stamp every messenger user's effective label into their
/// existing `join`/`invite` member events that lack it or carry a stale one —
/// rooms created before the server wrote `displayname`, and labels that
/// changed while no propagation ran (a provider display name refreshed at
/// login, an account merge). Idempotent: an up-to-date event is skipped, so a
/// repeat pass writes nothing. Returns how many member events were written.
///
/// Runs at boot on the plain connections (identity, then messenger — the
/// crate's lock order; no `ControlPlane` exists yet, so nothing is woken).
pub(crate) fn backfill_member_displaynames(identity_conn: &Connection, messenger_conn: &mut Connection, now: &str) -> Result<usize, matrix_store::MatrixStoreError> {
    let origin_ts = chrono::Utc::now().timestamp_millis();
    let mut events_written = 0;
    for user_id in matrix_store::matrix_user_ids(messenger_conn)? {
        let label = db::effective_label_for_user(identity_conn, user_id)?;
        events_written += matrix_store::refresh_member_displayname(messenger_conn, user_id, &label, now, origin_ts)?.rooms_updated;
    }
    Ok(events_written)
}

// ============================================================================
// DB-only action cores — `&mut Connection`, no `MatrixCaller`, unit-tested
// directly against an in-memory `matrix_store` fixture
// ============================================================================

/// The invitee of [`apply_invite`]: the resolved internal user id and the
/// effective label to stamp into their invite event as `displayname`.
#[derive(Debug, Clone, Copy)]
struct InviteTarget<'a> {
    user_id: i64,
    displayname: &'a str,
}

/// The invite action's whole DB-side decision + write (plan §4's `invite`
/// row: Member + PowerCheck(invite), refuses an already-invited/joined or
/// banned target), used by both the real handler (after resolving
/// `target_user_id` via [`resolve_target_user`], which needs the identity
/// connection this function deliberately does NOT take) and this module's
/// own tests. Returns the wake set (every joined+invited member, including
/// the new invitee).
///
/// The invite event carries the invitee's `displayname` (`target`), resolved
/// by the caller from the identity database BEFORE it takes the messenger
/// connection this function writes through.
fn apply_invite(
    conn: &mut Connection,
    room_id: &str,
    caller_user_id: i64,
    caller_mxid: &str,
    target: InviteTarget<'_>,
    now: &str,
    origin_ts: i64,
) -> Result<HashSet<i64>, MatrixError> {
    let target_user_id = target.user_id;
    let room = matrix_store::get_room(conn, room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
    let caller_membership = matrix_store::room_member(conn, room_id, caller_user_id)?.map(|m| m.membership);
    require_member(caller_membership)?;
    let power_levels = power_levels_of(conn, room_id)?;
    require_power(&power_levels, caller_mxid, PowerAction::Invite)?;

    let target_membership = matrix_store::room_member(conn, room_id, target_user_id)?.map(|m| m.membership);
    match target_membership {
        Some(Membership::Join) | Some(Membership::Invite) => return Err(MatrixError::invalid_param("user is already invited or joined")),
        Some(Membership::Ban) => return Err(MatrixError::forbidden("user is banned from this room")),
        Some(Membership::Leave) | None => {}
    }

    let target_mxid = matrix_store::mxid_of(conn, target_user_id)?.ok_or_else(MatrixError::internal)?;
    matrix_store::apply_state_event(
        conn,
        &matrix_store::StateEventWrite {
            event_id: &matrix_store::new_event_id(),
            room_id,
            sender_user_id: caller_user_id,
            event_type: "m.room.member",
            state_key: &target_mxid,
            content: &invite_member_content(room.kind, target.displayname).to_string(),
            origin_server_ts: origin_ts,
            now,
        },
    )?;

    let mut ids = member_and_invited_ids(conn, room_id)?;
    ids.insert(target_user_id);
    Ok(ids)
}

/// What state a kick/ban/unban target must currently be in for the action
/// to proceed. `pub(super)` — also `routes::matrix::moderation`'s (P11) own
/// room-power fallback path reuses this exact rule set, so a kick/ban/unban
/// reached through `/api/matrix-admin/.../moderate` never drifts from the
/// same action reached through this module's own `/kick`/`/ban`/`/unban`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TargetStateRule {
    /// kick: the target must currently be an active member (`join`/`invite`).
    MustBeActiveMember,
    /// ban: any current state is fine (banning a non-member pre-empts a
    /// future join attempt).
    Any,
    /// unban: the target must currently be `ban`ned.
    MustBeBanned,
}

pub(super) fn check_target_state_rule(rule: TargetStateRule, membership: Option<Membership>) -> Result<(), MatrixError> {
    match rule {
        TargetStateRule::MustBeActiveMember => {
            if matches!(membership, Some(Membership::Join) | Some(Membership::Invite)) {
                Ok(())
            } else {
                Err(MatrixError::not_found("user is not a member of this room"))
            }
        }
        TargetStateRule::MustBeBanned => {
            if membership == Some(Membership::Ban) {
                Ok(())
            } else {
                Err(MatrixError::invalid_param("user is not banned"))
            }
        }
        TargetStateRule::Any => Ok(()),
    }
}

/// The pieces [`apply_membership_power_action`] needs beyond the caller and
/// the connection — grouped so the function itself stays under a plain
/// four-parameter signature instead of needing
/// `#[allow(clippy::too_many_arguments)]`. `pub(super)` alongside
/// [`apply_membership_power_action`] — see that function's own doc for why.
pub(super) struct MembershipPowerAction<'a> {
    pub(super) room_id: &'a str,
    pub(super) action: PowerAction,
    pub(super) target_user_id: i64,
    pub(super) target_rule: TargetStateRule,
    pub(super) new_membership: Membership,
    pub(super) reason: Option<&'a str>,
}

/// The shared core of kick/ban/unban (plan §4: Member + PowerCheck(kick/
/// ban)): checks the caller's own membership+power, checks
/// [`TargetStateRule`] against the target's current membership, then writes
/// the target's new `m.room.member` state event. `target_user_id` is
/// already resolved (identity-DB work happens in the handler, not here —
/// see the module doc's "testable cores" note). Returns the wake set
/// (post-write joined+invited members plus the target, even though the
/// target may no longer be one of those after this write).
///
/// `pub(super)` — `routes::matrix::moderation`'s (P11) room-power fallback
/// gate ("otherwise the caller needs the room's own power," plan §4's
/// `/moderate` row) reuses this verbatim rather than re-deriving the
/// `can_act_on` target-level rule a second time, matching this module's own
/// precedent for [`member_and_invited_ids`] (reused by `messaging.rs`).
pub(super) fn apply_membership_power_action(
    conn: &mut Connection,
    caller_user_id: i64,
    caller_mxid: &str,
    action: MembershipPowerAction<'_>,
    now: &str,
    origin_ts: i64,
) -> Result<HashSet<i64>, MatrixError> {
    let room_id = action.room_id;
    let caller_membership = matrix_store::room_member(conn, room_id, caller_user_id)?.map(|m| m.membership);
    require_member(caller_membership)?;
    let power_levels = power_levels_of(conn, room_id)?;

    let target_mxid = matrix_store::mxid_of(conn, action.target_user_id)?.ok_or_else(MatrixError::internal)?;
    let self_leave = action.new_membership == Membership::Leave;
    require_power_over_target(&power_levels, caller_mxid, &target_mxid, action.action, self_leave)?;

    let target_membership = matrix_store::room_member(conn, room_id, action.target_user_id)?.map(|m| m.membership);
    check_target_state_rule(action.target_rule, target_membership)?;

    let mut content = serde_json::json!({ "membership": action.new_membership.as_str() });
    if let Some(reason) = action.reason {
        content["reason"] = serde_json::Value::String(reason.to_string());
    }
    matrix_store::apply_state_event(conn, &matrix_store::StateEventWrite { event_id: &matrix_store::new_event_id(), room_id, sender_user_id: caller_user_id, event_type: "m.room.member", state_key: &target_mxid, content: &content.to_string(), origin_server_ts: origin_ts, now })?;

    let mut ids = member_and_invited_ids(conn, room_id)?;
    ids.insert(action.target_user_id);
    Ok(ids)
}

/// `POST /join`'s write for an already-invited or newly-public-eligible
/// caller (idempotent-join and ban checks happen in the handler, before the
/// paid gate — see [`join_room`]). Returns the post-join wake set. The join
/// event carries the caller's effective label as `displayname`, resolved by
/// the caller BEFORE it takes the messenger connection this writes through.
fn apply_join(
    conn: &mut Connection,
    room_id: &str,
    caller_user_id: i64,
    caller_mxid: &str,
    displayname: &str,
    now: &str,
    origin_ts: i64,
) -> Result<HashSet<i64>, MatrixError> {
    matrix_store::apply_state_event(
        conn,
        &matrix_store::StateEventWrite {
            event_id: &matrix_store::new_event_id(),
            room_id,
            sender_user_id: caller_user_id,
            event_type: "m.room.member",
            state_key: caller_mxid,
            content: &join_member_content(displayname).to_string(),
            origin_server_ts: origin_ts,
            now,
        },
    )?;
    Ok(member_and_invited_ids(conn, room_id)?)
}

/// `POST /leave`'s write (manager review, 2026-09-24: the plan's plain
/// "Member" gate table entry undersold this — Matrix's own spec behaviour
/// for `/leave` is "leave OR reject a pending invite," so an INVITED, not
/// yet joined, caller must be accepted too). Wake set is captured BEFORE
/// the leave lands, so the leaver's own other devices are included, and —
/// since [`member_and_invited_ids`] already covers every joined+invited
/// member — the inviter (who must be a joined member to have sent the
/// invite at all) is naturally woken as well.
fn apply_leave(conn: &mut Connection, room_id: &str, caller_user_id: i64, caller_mxid: &str, now: &str, origin_ts: i64) -> Result<HashSet<i64>, MatrixError> {
    let caller_membership = matrix_store::room_member(conn, room_id, caller_user_id)?.map(|m| m.membership);
    if !matches!(caller_membership, Some(Membership::Join) | Some(Membership::Invite)) {
        return Err(MatrixError::forbidden("not a member or invitee of this room"));
    }
    let wake_ids = member_and_invited_ids(conn, room_id)?;
    matrix_store::apply_state_event(
        conn,
        &matrix_store::StateEventWrite {
            event_id: &matrix_store::new_event_id(),
            room_id,
            sender_user_id: caller_user_id,
            event_type: "m.room.member",
            state_key: caller_mxid,
            content: &serde_json::json!({ "membership": "leave" }).to_string(),
            origin_server_ts: origin_ts,
            now,
        },
    )?;
    Ok(wake_ids)
}

// ============================================================================
// POST /_matrix/client/v3/createRoom
// ============================================================================

enum RoomCreationOutcome {
    Reused(String),
    Created { room_id: String, wake_ids: HashSet<i64> },
}

async fn create_room(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(req): Json<CreateRoomRequest>) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;

    let kind = derive_room_kind(req.is_direct, req.invite.len(), req.visibility.as_deref() == Some("public"))?;
    let invite_override = validate_power_level_override(kind, &req.power_level_content_override)?;
    if req.room_alias_name.as_deref().is_some_and(|alias| !alias.is_empty()) {
        return Err(MatrixError::invalid_param("room aliases are not supported"));
    }

    let state_for_blocking = state.clone();
    let outcome = tokio::task::spawn_blocking(move || -> Result<RoomCreationOutcome, MatrixError> {
        let cp = state_for_blocking.control_plane();

        if !is_paid_now(cp, caller.user_id)? {
            return Err(MatrixError::forbidden("paid account required for the messenger"));
        }
        if !has_nick_now(cp, caller.user_id)? {
            return Err(MatrixError::forbidden("choose a nick before creating a room"));
        }

        let now = chrono::Utc::now().to_rfc3339();
        let origin_ts = chrono::Utc::now().timestamp_millis();

        // Identity first, then messenger, never nested the other way round:
        // resolve every invitee, then their effective labels (the
        // `displayname` each member event carries) with only `db` held.
        let mut invite_user_ids = Vec::with_capacity(req.invite.len());
        let (caller_label, invitee_labels) = {
            let identity_conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
            {
                let messenger_conn = cp.messenger_conn();
                for mxid in &req.invite {
                    invite_user_ids.push(resolve_target_user(&identity_conn, &messenger_conn, mxid, &now)?);
                }
            }
            let caller_label = db::effective_label_for_user(&identity_conn, caller.user_id)?;
            let invitee_labels = invite_user_ids
                .iter()
                .map(|&invitee_id| db::effective_label_for_user(&identity_conn, invitee_id))
                .collect::<rusqlite::Result<Vec<String>>>()?;
            (caller_label, invitee_labels)
        };
        if invite_user_ids.contains(&caller.user_id) {
            return Err(MatrixError::invalid_param("cannot invite yourself"));
        }

        let mut messenger_conn = cp.messenger_conn();

        if kind == RoomKind::Dm {
            let peer_id = invite_user_ids[0];
            let pair_key = dm_pair_key(caller.user_id, peer_id);
            if let Some(existing_room_id) = find_reusable_dm_room(&messenger_conn, &pair_key, caller.user_id, peer_id)? {
                return Ok(RoomCreationOutcome::Reused(existing_room_id));
            }
        }

        let room_id = matrix_store::new_room_id();
        let (join_rule, history_visibility, is_encrypted) = room_kind_settings(kind);
        let invite_level = invite_power_level(kind, invite_override);

        let mut invitees = Vec::with_capacity(invite_user_ids.len());
        for (&invitee_id, label) in invite_user_ids.iter().zip(invitee_labels) {
            let mxid = matrix_store::mxid_of(&messenger_conn, invitee_id)?.ok_or_else(MatrixError::internal)?;
            invitees.push((mxid, label));
        }
        let mut state_events = vec![state_event("m.room.create", "", caller.user_id, serde_json::json!({ "room_version": matrix_store::MATRIX_ROOM_VERSION }))];
        state_events.extend(bootstrap_member_events(kind, (caller.user_id, &caller.mxid, &caller_label), &invitees));
        state_events.push(state_event("m.room.power_levels", "", caller.user_id, power_levels_content(&caller.mxid, kind, invite_level)));
        state_events.push(state_event("m.room.join_rules", "", caller.user_id, serde_json::json!({ "join_rule": join_rule.as_str() })));
        state_events.push(state_event(
            "m.room.history_visibility",
            "",
            caller.user_id,
            serde_json::json!({ "history_visibility": history_visibility.as_str() }),
        ));
        if let Some(name) = &req.name {
            state_events.push(state_event("m.room.name", "", caller.user_id, serde_json::json!({ "name": name })));
        }
        if let Some(topic) = &req.topic {
            state_events.push(state_event("m.room.topic", "", caller.user_id, serde_json::json!({ "topic": topic })));
        }
        if is_encrypted {
            state_events.push(state_event(
                "m.room.encryption",
                "",
                caller.user_id,
                serde_json::json!({ "algorithm": "m.megolm.v1.aes-sha2" }),
            ));
        }

        let dm_pair = (kind == RoomKind::Dm).then(|| dm_pair_key(caller.user_id, invite_user_ids[0]));
        let bootstrap = matrix_store::RoomBootstrap {
            room_id: &room_id,
            kind,
            creator_user_id: caller.user_id,
            created_at: &now,
            is_encrypted,
            join_rule,
            history_visibility,
            dm_pair_key: dm_pair.as_deref(),
            legacy_dm_id: None,
        };
        matrix_store::create_room_with_state(&mut messenger_conn, bootstrap, &state_events, origin_ts)?;

        let mut wake_ids: HashSet<i64> = invite_user_ids.into_iter().collect();
        wake_ids.insert(caller.user_id);
        Ok(RoomCreationOutcome::Created { room_id, wake_ids })
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    match outcome {
        RoomCreationOutcome::Reused(room_id) => Ok(Json(serde_json::json!({ "room_id": room_id }))),
        RoomCreationOutcome::Created { room_id, wake_ids } => {
            state.control_plane().live.wake_many(wake_ids.into_iter().map(|id| format!("user:{id}")));
            Ok(Json(serde_json::json!({ "room_id": room_id })))
        }
    }
}

// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/join
// ============================================================================

async fn join_room(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(room_id): Path<String>) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let state_for_blocking = state.clone();
    let room_id_for_blocking = room_id.clone();

    let wake_ids = tokio::task::spawn_blocking(move || -> Result<Option<HashSet<i64>>, MatrixError> {
        let cp = state_for_blocking.control_plane();

        let (room, current_membership) = {
            let messenger_conn = cp.messenger_conn();
            let room = matrix_store::get_room(&messenger_conn, &room_id_for_blocking)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
            let current_membership = matrix_store::room_member(&messenger_conn, &room_id_for_blocking, caller.user_id)?.map(|m| m.membership);
            (room, current_membership)
        };

        match current_membership {
            Some(Membership::Join) => return Ok(None),
            Some(Membership::Ban) => return Err(MatrixError::forbidden("banned from this room")),
            Some(Membership::Invite) => {}
            Some(Membership::Leave) | None => {
                if room.join_rule != JoinRule::Public {
                    return Err(MatrixError::forbidden("no invitation to this room"));
                }
                if !is_paid_now(cp, caller.user_id)? {
                    return Err(MatrixError::forbidden("paid account required for the messenger"));
                }
            }
        }

        let displayname = effective_label_now(cp, caller.user_id)?;
        let now = chrono::Utc::now().to_rfc3339();
        let origin_ts = chrono::Utc::now().timestamp_millis();
        let mut messenger_conn = cp.messenger_conn();
        let ids = apply_join(&mut messenger_conn, &room_id_for_blocking, caller.user_id, &caller.mxid, &displayname, &now, origin_ts)?;
        Ok(Some(ids))
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    if let Some(wake_ids) = wake_ids {
        state.control_plane().live.wake_many(wake_ids.into_iter().map(|id| format!("user:{id}")));
    }
    Ok(Json(serde_json::json!({ "room_id": room_id })))
}

// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/leave
// ============================================================================

async fn leave_room(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(room_id): Path<String>) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let state_for_blocking = state.clone();
    let room_id_for_blocking = room_id.clone();

    let wake_ids = tokio::task::spawn_blocking(move || -> Result<HashSet<i64>, MatrixError> {
        let cp = state_for_blocking.control_plane();
        let mut messenger_conn = cp.messenger_conn();
        matrix_store::get_room(&messenger_conn, &room_id_for_blocking)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        let now = chrono::Utc::now().to_rfc3339();
        let origin_ts = chrono::Utc::now().timestamp_millis();
        apply_leave(&mut messenger_conn, &room_id_for_blocking, caller.user_id, &caller.mxid, &now, origin_ts)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    state.control_plane().live.wake_many(wake_ids.into_iter().map(|id| format!("user:{id}")));
    Ok(Json(serde_json::json!({})))
}

// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/invite
// ============================================================================

async fn invite_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Json(body): Json<UserIdBody>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let state_for_blocking = state.clone();
    let room_id_for_blocking = room_id.clone();
    let target_mxid = body.user_id;

    let wake_ids = tokio::task::spawn_blocking(move || -> Result<HashSet<i64>, MatrixError> {
        let cp = state_for_blocking.control_plane();

        if !is_paid_now(cp, caller.user_id)? {
            return Err(MatrixError::forbidden("paid account required for the messenger"));
        }
        if !has_nick_now(cp, caller.user_id)? {
            return Err(MatrixError::forbidden("choose a nick before inviting"));
        }

        matrix_store::get_room(&cp.messenger_conn(), &room_id_for_blocking)?.ok_or_else(|| MatrixError::not_found("no such room"))?;

        let now = chrono::Utc::now().to_rfc3339();
        // `db` first; the invitee's label (the invite event's `displayname`)
        // is read with only `db` held, before the messenger write below.
        let (target_user_id, target_label) = {
            let identity_conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
            let target_user_id = {
                let messenger_conn = cp.messenger_conn();
                resolve_target_user(&identity_conn, &messenger_conn, &target_mxid, &now)?
            };
            (target_user_id, db::effective_label_for_user(&identity_conn, target_user_id)?)
        };
        if target_user_id == caller.user_id {
            return Err(MatrixError::invalid_param("cannot invite yourself"));
        }

        let origin_ts = chrono::Utc::now().timestamp_millis();
        let mut messenger_conn = cp.messenger_conn();
        let target = InviteTarget { user_id: target_user_id, displayname: &target_label };
        apply_invite(&mut messenger_conn, &room_id_for_blocking, caller.user_id, &caller.mxid, target, &now, origin_ts)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    state.control_plane().live.wake_many(wake_ids.into_iter().map(|id| format!("user:{id}")));
    Ok(Json(serde_json::json!({})))
}

// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/kick, /ban, /unban
// ============================================================================

/// [`membership_power_action`]'s own request shape — the HTTP-facing
/// counterpart of [`MembershipPowerAction`], with owned `String`s (crossing
/// the `spawn_blocking` boundary) instead of borrows.
struct MembershipPowerActionRequest {
    room_id: String,
    target_mxid: String,
    reason: Option<String>,
    action: PowerAction,
    target_rule: TargetStateRule,
    new_membership: Membership,
}

async fn membership_power_action(state: Arc<AppState>, caller: auth::MatrixCaller, req: MembershipPowerActionRequest) -> Result<impl IntoResponse, MatrixError> {
    let state_for_blocking = state.clone();

    let wake_ids = tokio::task::spawn_blocking(move || -> Result<HashSet<i64>, MatrixError> {
        let cp = state_for_blocking.control_plane();
        matrix_store::get_room(&cp.messenger_conn(), &req.room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;

        let now = chrono::Utc::now().to_rfc3339();
        let target_user_id = {
            let identity_conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
            let messenger_conn = cp.messenger_conn();
            resolve_target_user(&identity_conn, &messenger_conn, &req.target_mxid, &now)?
        };

        let origin_ts = chrono::Utc::now().timestamp_millis();
        let mut messenger_conn = cp.messenger_conn();
        apply_membership_power_action(
            &mut messenger_conn,
            caller.user_id,
            &caller.mxid,
            MembershipPowerAction {
                room_id: &req.room_id,
                action: req.action,
                target_user_id,
                target_rule: req.target_rule,
                new_membership: req.new_membership,
                reason: req.reason.as_deref(),
            },
            &now,
            origin_ts,
        )
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    state.control_plane().live.wake_many(wake_ids.into_iter().map(|id| format!("user:{id}")));
    Ok(Json(serde_json::json!({})))
}

async fn kick_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Json(body): Json<KickBanBody>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    membership_power_action(
        state,
        caller,
        MembershipPowerActionRequest {
            room_id,
            target_mxid: body.user_id,
            reason: body.reason,
            action: PowerAction::Kick,
            target_rule: TargetStateRule::MustBeActiveMember,
            new_membership: Membership::Leave,
        },
    )
    .await
}

async fn ban_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Json(body): Json<KickBanBody>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    membership_power_action(
        state,
        caller,
        MembershipPowerActionRequest {
            room_id,
            target_mxid: body.user_id,
            reason: body.reason,
            action: PowerAction::Ban,
            target_rule: TargetStateRule::Any,
            new_membership: Membership::Ban,
        },
    )
    .await
}

async fn unban_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Json(body): Json<UserIdBody>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    membership_power_action(
        state,
        caller,
        MembershipPowerActionRequest {
            room_id,
            target_mxid: body.user_id,
            reason: None,
            action: PowerAction::Ban,
            target_rule: TargetStateRule::MustBeBanned,
            new_membership: Membership::Leave,
        },
    )
    .await
}

// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/forget
// ============================================================================

async fn forget_room(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(room_id): Path<String>) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;

    tokio::task::spawn_blocking(move || -> Result<(), MatrixError> {
        let cp = state.control_plane();
        let messenger_conn = cp.messenger_conn();
        let deleted = matrix_store::forget_membership(&messenger_conn, &room_id, caller.user_id)?;
        if deleted == 0 {
            return Err(MatrixError::forbidden("must have left the room before forgetting it"));
        }
        Ok(())
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(serde_json::json!({})))
}

// ============================================================================
// GET /_matrix/client/v3/joined_rooms
// ============================================================================

async fn joined_rooms(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let rooms = tokio::task::spawn_blocking(move || -> Result<Vec<String>, MatrixError> {
        let cp = state.control_plane();
        let messenger_conn = cp.messenger_conn();
        Ok(matrix_store::rooms_for_user(&messenger_conn, caller.user_id, Some(Membership::Join))?)
    })
    .await
    .map_err(|_| MatrixError::internal())??;
    Ok(Json(serde_json::json!({ "joined_rooms": rooms })))
}

// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/state[/...]
// ============================================================================

async fn get_state_all(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(room_id): Path<String>) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;

    let events = tokio::task::spawn_blocking(move || -> Result<Vec<serde_json::Value>, MatrixError> {
        let cp = state.control_plane();
        let messenger_conn = cp.messenger_conn();
        let room = matrix_store::get_room(&messenger_conn, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        require_pub_read(&messenger_conn, &room, caller.user_id)?;
        matrix_store::current_state_all(&messenger_conn, &room_id)?
            .iter()
            .map(|event| client_event_json(&messenger_conn, event, None))
            .collect()
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(events))
}

async fn get_state_inner(state: Arc<AppState>, headers: HeaderMap, room_id: String, event_type: String, state_key: String) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;

    let content = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, MatrixError> {
        let cp = state.control_plane();
        let messenger_conn = cp.messenger_conn();
        let room = matrix_store::get_room(&messenger_conn, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        require_pub_read(&messenger_conn, &room, caller.user_id)?;
        let event =
            matrix_store::current_state_event(&messenger_conn, &room_id, &event_type, &state_key)?.ok_or_else(|| MatrixError::not_found("no such state event"))?;
        Ok(serde_json::from_str(&event.content)?)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(content))
}

async fn get_state(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((room_id, event_type, state_key)): Path<(String, String, String)>,
) -> Result<impl IntoResponse, MatrixError> {
    get_state_inner(state, headers, room_id, event_type, state_key).await
}

async fn get_state_no_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((room_id, event_type)): Path<(String, String)>,
) -> Result<impl IntoResponse, MatrixError> {
    get_state_inner(state, headers, room_id, event_type, String::new()).await
}

async fn put_state_inner(
    state: Arc<AppState>,
    headers: HeaderMap,
    room_id: String,
    event_type: String,
    state_key: String,
    content: serde_json::Value,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;

    let content_str = content.to_string();
    if content_str.len() > matrix_store::MATRIX_EVENT_CONTENT_MAX_BYTES {
        return Err(MatrixError::invalid_param("event content too large"));
    }

    let state_for_blocking = state.clone();
    let room_id_for_blocking = room_id.clone();
    let event_type_for_blocking = event_type.clone();
    let state_key_for_blocking = state_key.clone();

    let (event_id, wake_ids) = tokio::task::spawn_blocking(move || -> Result<(String, HashSet<i64>), MatrixError> {
        let cp = state_for_blocking.control_plane();

        let (room, caller_membership, power_levels, already_encrypted) = {
            let messenger_conn = cp.messenger_conn();
            let room = matrix_store::get_room(&messenger_conn, &room_id_for_blocking)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
            let caller_membership = matrix_store::room_member(&messenger_conn, &room_id_for_blocking, caller.user_id)?.map(|m| m.membership);
            let power_levels = power_levels_of(&messenger_conn, &room_id_for_blocking)?;
            let already_encrypted = matrix_store::current_state_event(&messenger_conn, &room_id_for_blocking, "m.room.encryption", "")?.is_some();
            (room, caller_membership, power_levels, already_encrypted)
        };
        require_member(caller_membership)?;
        check_state_event_type_allowed(&event_type_for_blocking, &state_key_for_blocking, &caller.mxid, &content_str)?;
        check_encryption_state_change(&event_type_for_blocking, room.join_rule, already_encrypted)?;

        // The one `m.room.member` PUT that gets through is the caller's own
        // profile update: the nick decides the `displayname`, never the
        // client. The label is read with no messenger guard held (the block
        // above released it), `db` before the write below.
        let content_str = if event_type_for_blocking == "m.room.member" {
            let label = effective_label_now(cp, caller.user_id)?;
            stamp_own_member_displayname(&content_str, &label)?
        } else {
            content_str
        };

        let sufficient = matrix_store::user_level(&power_levels, &caller.mxid) >= matrix_store::event_level(&power_levels, &event_type_for_blocking, true);
        if !sufficient {
            return Err(MatrixError::forbidden("insufficient power level to set this state event"));
        }

        if event_type_for_blocking == "m.room.power_levels" {
            let new_power_levels: serde_json::Value = serde_json::from_str(&content_str)?;
            matrix_store::validate_power_levels_change(&power_levels, &new_power_levels, &caller.mxid).map_err(MatrixError::forbidden)?;
        }

        let now = chrono::Utc::now().to_rfc3339();
        let origin_ts = chrono::Utc::now().timestamp_millis();
        let event_id = matrix_store::new_event_id();
        let mut messenger_conn = cp.messenger_conn();
        matrix_store::apply_state_event(
            &mut messenger_conn,
            &matrix_store::StateEventWrite {
                event_id: &event_id,
                room_id: &room_id_for_blocking,
                sender_user_id: caller.user_id,
                event_type: &event_type_for_blocking,
                state_key: &state_key_for_blocking,
                content: &content_str,
                origin_server_ts: origin_ts,
                now: &now,
            },
        )?;
        let wake_ids = member_and_invited_ids(&messenger_conn, &room_id_for_blocking)?;
        Ok((event_id, wake_ids))
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    state.control_plane().live.wake_many(wake_ids.into_iter().map(|id| format!("user:{id}")));
    Ok(Json(serde_json::json!({ "event_id": event_id })))
}

async fn put_state(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((room_id, event_type, state_key)): Path<(String, String, String)>,
    Json(content): Json<serde_json::Value>,
) -> Result<impl IntoResponse, MatrixError> {
    put_state_inner(state, headers, room_id, event_type, state_key, content).await
}

async fn put_state_no_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((room_id, event_type)): Path<(String, String)>,
    Json(content): Json<serde_json::Value>,
) -> Result<impl IntoResponse, MatrixError> {
    put_state_inner(state, headers, room_id, event_type, String::new(), content).await
}

// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/members, /joined_members
// ============================================================================

async fn get_members(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Query(query): Query<MembersQuery>,
) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;
    let membership_filter = match &query.membership {
        Some(raw) => Some(Membership::from_wire_name(raw).ok_or_else(|| MatrixError::invalid_param("unknown membership filter"))?),
        None => None,
    };

    let events = tokio::task::spawn_blocking(move || -> Result<Vec<serde_json::Value>, MatrixError> {
        let cp = state.control_plane();
        let messenger_conn = cp.messenger_conn();
        let room = matrix_store::get_room(&messenger_conn, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        require_pub_read(&messenger_conn, &room, caller.user_id)?;

        let member_events = match query.at {
            Some(at_stream_id) => matrix_store::state_events_of_type_at(&messenger_conn, &room_id, "m.room.member", at_stream_id)?,
            None => matrix_store::current_state_all(&messenger_conn, &room_id)?
                .into_iter()
                .filter(|event| event.event_type == "m.room.member")
                .collect(),
        };

        let mut out = Vec::new();
        for event in member_events {
            if let Some(wanted) = membership_filter {
                let content: serde_json::Value = serde_json::from_str(&event.content)?;
                let membership = content.get("membership").and_then(|v| v.as_str()).and_then(Membership::from_wire_name);
                if membership != Some(wanted) {
                    continue;
                }
            }
            out.push(client_event_json(&messenger_conn, &event, None)?);
        }
        Ok(out)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    Ok(Json(serde_json::json!({ "chunk": events })))
}

async fn get_joined_members(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(room_id): Path<String>) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;

    let joined = tokio::task::spawn_blocking(move || -> Result<Vec<(String, String)>, MatrixError> {
        let cp = state.control_plane();
        let members = {
            let messenger_conn = cp.messenger_conn();
            let room = matrix_store::get_room(&messenger_conn, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
            require_pub_read(&messenger_conn, &room, caller.user_id)?;
            matrix_store::room_members(&messenger_conn, &room_id, Some(Membership::Join))?
        };

        let identity_conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
        let messenger_conn = cp.messenger_conn();
        let mut out = Vec::with_capacity(members.len());
        for member in members {
            let mxid = matrix_store::mxid_of(&messenger_conn, member.user_id)?.ok_or_else(MatrixError::internal)?;
            let label = db::effective_label_for_user(&identity_conn, member.user_id)?;
            out.push((mxid, label));
        }
        Ok(out)
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    let joined_map: serde_json::Map<String, serde_json::Value> =
        joined.into_iter().map(|(mxid, label)| (mxid, serde_json::json!({ "display_name": label }))).collect();
    Ok(Json(serde_json::json!({ "joined": joined_map })))
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

    fn make_room(conn: &Connection, room_id: &str, kind: RoomKind, creator: i64) {
        let (join_rule, history_visibility, is_encrypted) = room_kind_settings(kind);
        matrix_store::create_room(conn, room_id, kind, creator, T0, is_encrypted, join_rule, history_visibility, None, None).expect("create room");
    }

    // ---- plan §9 P5 test 1 (adapted to the corrected DM rule): kind derivation ----

    #[test]
    fn create_room_derives_dm_kind_only_for_exactly_one_invite_target_and_is_direct() {
        // Corrected rule (P5 brief): `is_direct` requires EXACTLY ONE
        // invitee (the peer; the creator is the other member) — NOT two, as
        // the plan body's original (superseded) text said.
        assert_eq!(derive_room_kind(true, 1, false).expect("one invitee"), RoomKind::Dm);
        assert!(derive_room_kind(true, 0, false).is_err(), "zero invitees must be refused");
        assert!(derive_room_kind(false, 1, false).is_ok(), "is_direct=false never yields Dm regardless of invite count");
        assert_ne!(derive_room_kind(false, 1, false).expect("group"), RoomKind::Dm);
    }

    #[test]
    fn dm_with_two_invitees_is_refused() {
        let err = derive_room_kind(true, 2, false).unwrap_err();
        assert_eq!(err.errcode, "M_INVALID_PARAM");
    }

    // ---- plan §9 P5 test 2 (reinterpreted: createRoom has no client-facing
    // "request encryption" field at all — kind alone decides it, so the
    // invariant this test actually pins is "a channel can never come out
    // encrypted") ----

    #[test]
    fn create_room_refuses_encryption_on_a_public_room() {
        let (_, _, is_encrypted) = room_kind_settings(RoomKind::Channel);
        assert!(!is_encrypted, "a public channel must never be created encrypted");
        for kind in [RoomKind::Dm, RoomKind::Group] {
            let (_, _, is_encrypted) = room_kind_settings(kind);
            assert!(is_encrypted, "{kind:?} must always be created encrypted");
        }
    }

    #[test]
    fn state_put_cannot_change_encryption() {
        assert!(check_encryption_state_change("m.room.encryption", JoinRule::Invite, true).is_err(), "an existing encryption event can never change");
        assert!(
            check_encryption_state_change("m.room.encryption", JoinRule::Public, false).is_err(),
            "encryption can never be enabled on a public room"
        );
        assert!(
            check_encryption_state_change("m.room.encryption", JoinRule::Invite, false).is_ok(),
            "a private, not-yet-encrypted room may set it for the first time"
        );
        assert!(check_encryption_state_change("m.room.name", JoinRule::Public, false).is_ok(), "any other event type is unaffected by this rule");
    }

    // ---- manager review 2026-09-24: PUT state refuses m.room.create/member ----

    #[test]
    fn state_put_refuses_m_room_create() {
        let err = check_state_event_type_allowed("m.room.create", "", "@alice:mylittlechart.org", "{}").unwrap_err();
        assert_eq!(err.errcode, "M_FORBIDDEN");
    }

    #[test]
    fn state_put_member_allows_only_own_join_update() {
        let alice = "@alice:mylittlechart.org";
        let bob = "@bob:mylittlechart.org";

        // Own event, membership still "join" (a displayname/profile update) — allowed.
        assert!(check_state_event_type_allowed("m.room.member", alice, alice, r#"{"membership":"join","displayname":"Alice"}"#).is_ok());

        // Own event, but changing membership away from "join" — refused
        // (must go through leave/kick/ban instead).
        assert!(check_state_event_type_allowed("m.room.member", alice, alice, r#"{"membership":"leave"}"#).is_err());

        // Someone else's event — refused outright, even with membership "join".
        assert!(check_state_event_type_allowed("m.room.member", bob, alice, r#"{"membership":"join"}"#).is_err());
        assert!(check_state_event_type_allowed("m.room.member", bob, alice, r#"{"membership":"invite"}"#).is_err());
    }

    // ---- plan §9 P5 test 3: power gate uses events[type] before falling back ----

    #[test]
    fn power_check_uses_events_type_override_before_falling_back_to_events_default() {
        let power_levels = serde_json::json!({
            "users": { "@alice:mylittlechart.org": 40 },
            "events": { "m.room.name": 40 },
            "state_default": 50,
            "events_default": 0,
        });
        // Alice (level 40) is under the blanket state_default (50) but meets
        // the m.room.name-specific override (40) — a PUT state gate that
        // ignored the events[type] override would wrongly refuse this.
        let sufficient_for_name = matrix_store::user_level(&power_levels, "@alice:mylittlechart.org")
            >= matrix_store::event_level(&power_levels, "m.room.name", true);
        assert!(sufficient_for_name, "the events[type] override must be checked before state_default");

        let sufficient_for_topic = matrix_store::user_level(&power_levels, "@alice:mylittlechart.org")
            >= matrix_store::event_level(&power_levels, "m.room.topic", true);
        assert!(!sufficient_for_topic, "an unlisted state type must fall back to the blanket state_default");
    }

    // ---- brief test: power_level_content_override validation ----

    #[test]
    fn power_level_override_accepts_only_invite() {
        assert_eq!(validate_power_level_override(RoomKind::Group, &None).expect("no override"), None);
        assert_eq!(
            validate_power_level_override(RoomKind::Group, &Some(serde_json::json!({ "invite": 0 }))).expect("invite 0"),
            Some(0)
        );
        assert_eq!(
            validate_power_level_override(RoomKind::Group, &Some(serde_json::json!({ "invite": 50 }))).expect("invite 50"),
            Some(50)
        );
        assert!(
            validate_power_level_override(RoomKind::Group, &Some(serde_json::json!({ "invite": 25 }))).is_err(),
            "an out-of-range invite value must be refused"
        );
        assert!(
            validate_power_level_override(RoomKind::Group, &Some(serde_json::json!({ "ban": 100 }))).is_err(),
            "any key other than invite must be refused"
        );
        assert!(
            validate_power_level_override(RoomKind::Channel, &Some(serde_json::json!({ "invite": 0 }))).is_err(),
            "the override is only accepted for group rooms"
        );
        assert!(
            validate_power_level_override(RoomKind::Dm, &Some(serde_json::json!({ "invite": 0 }))).is_err(),
            "the override is only accepted for group rooms"
        );
    }

    #[test]
    fn invite_power_level_defaults_to_fifty_without_an_override() {
        assert_eq!(invite_power_level(RoomKind::Group, None), 50);
        assert_eq!(invite_power_level(RoomKind::Group, Some(0)), 0);
        assert_eq!(invite_power_level(RoomKind::Dm, Some(0)), 50, "dm/channel ignore any override — fixed at 50");
        assert_eq!(invite_power_level(RoomKind::Channel, Some(0)), 50);
    }

    // ---- brief test: kick requires power ----

    #[test]
    fn kick_requires_power() {
        let mut conn = test_conn();
        make_room(&conn, "!r:mylittlechart.org", RoomKind::Group, 1);
        let alice = matrix_store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000010", T0).expect("alice");
        let bob = matrix_store::ensure_matrix_user(&conn, 2, "bob0000000000000000000000000010", T0).expect("bob");
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$m1", room_id: "!r:mylittlechart.org", sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join"}"#, origin_server_ts: 1000, now: T0 })
            .expect("alice joins");
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$m2", room_id: "!r:mylittlechart.org", sender_user_id: 1, event_type: "m.room.member", state_key: &bob, content: r#"{"membership":"join"}"#, origin_server_ts: 1100, now: T0 })
            .expect("bob joins");
        // kick's default threshold (Matrix default 50) with no power_levels
        // event at all: alice's level defaults to 0 (users_default), which
        // must NOT reach it.
        let err = apply_membership_power_action(
            &mut conn,
            1,
            &alice,
            MembershipPowerAction {
                room_id: "!r:mylittlechart.org",
                action: PowerAction::Kick,
                target_user_id: 2,
                target_rule: TargetStateRule::MustBeActiveMember,
                new_membership: Membership::Leave,
                reason: None,
            },
            T0,
            2000,
        )
        .unwrap_err();
        assert_eq!(err.errcode, "M_FORBIDDEN");

        // Grant alice kick power via power_levels, then the same call must
        // succeed and wake bob.
        let power_levels_content = serde_json::json!({ "users": { alice.clone(): 100 } }).to_string();
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$pl", room_id: "!r:mylittlechart.org", sender_user_id: 1, event_type: "m.room.power_levels", state_key: "", content: &power_levels_content, origin_server_ts: 1200, now: T0 })
            .expect("power levels");
        let wake_ids = apply_membership_power_action(
            &mut conn,
            1,
            &alice,
            MembershipPowerAction {
                room_id: "!r:mylittlechart.org",
                action: PowerAction::Kick,
                target_user_id: 2,
                target_rule: TargetStateRule::MustBeActiveMember,
                new_membership: Membership::Leave,
                reason: Some("spamming"),
            },
            T0,
            3000,
        )
        .expect("kick succeeds with sufficient power");
        assert!(wake_ids.contains(&2), "the kicked user must be in the wake set");
        assert_eq!(
            matrix_store::room_member(&conn, "!r:mylittlechart.org", 2).expect("bob's row").expect("row exists").membership,
            Membership::Leave
        );
    }

    // ---- manager review 2026-09-24: kick/ban/unban require a STRICTLY
    // greater level than the target, not just the flat threshold ----

    #[test]
    fn admin_cannot_kick_owner() {
        let mut conn = test_conn();
        make_room(&conn, "!r:mylittlechart.org", RoomKind::Group, 1);
        let owner = matrix_store::ensure_matrix_user(&conn, 1, "owner000000000000000000000041", T0).expect("owner");
        let admin = matrix_store::ensure_matrix_user(&conn, 2, "admin000000000000000000000041", T0).expect("admin");
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$m1", room_id: "!r:mylittlechart.org", sender_user_id: 1, event_type: "m.room.member", state_key: &owner, content: r#"{"membership":"join"}"#, origin_server_ts: 1000, now: T0 })
            .expect("owner joins");
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$m2", room_id: "!r:mylittlechart.org", sender_user_id: 1, event_type: "m.room.member", state_key: &admin, content: r#"{"membership":"join"}"#, origin_server_ts: 1100, now: T0 })
            .expect("admin joins");
        let power_levels_content = serde_json::json!({ "users": { owner.clone(): 100, admin.clone(): 50 }, "kick": 50 }).to_string();
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$pl", room_id: "!r:mylittlechart.org", sender_user_id: 1, event_type: "m.room.power_levels", state_key: "", content: &power_levels_content, origin_server_ts: 1200, now: T0 })
            .expect("power levels");

        // admin (level 50) reaches the flat kick threshold (50) but must
        // NOT be able to kick the level-100 owner.
        let err = apply_membership_power_action(
            &mut conn,
            2,
            &admin,
            MembershipPowerAction {
                room_id: "!r:mylittlechart.org",
                action: PowerAction::Kick,
                target_user_id: 1,
                target_rule: TargetStateRule::MustBeActiveMember,
                new_membership: Membership::Leave,
                reason: None,
            },
            T0,
            2000,
        )
        .unwrap_err();
        assert_eq!(err.errcode, "M_FORBIDDEN");
        assert_eq!(
            matrix_store::room_member(&conn, "!r:mylittlechart.org", 1).expect("owner's row").expect("row exists").membership,
            Membership::Join,
            "the owner must remain joined"
        );
    }

    #[test]
    fn equal_levels_cannot_kick_each_other() {
        let mut conn = test_conn();
        make_room(&conn, "!r:mylittlechart.org", RoomKind::Group, 1);
        let alice = matrix_store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000042", T0).expect("alice");
        let bob = matrix_store::ensure_matrix_user(&conn, 2, "bob0000000000000000000000000042", T0).expect("bob");
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$m1", room_id: "!r:mylittlechart.org", sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join"}"#, origin_server_ts: 1000, now: T0 })
            .expect("alice joins");
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$m2", room_id: "!r:mylittlechart.org", sender_user_id: 1, event_type: "m.room.member", state_key: &bob, content: r#"{"membership":"join"}"#, origin_server_ts: 1100, now: T0 })
            .expect("bob joins");
        let power_levels_content = serde_json::json!({ "users": { alice.clone(): 50, bob.clone(): 50 }, "kick": 50 }).to_string();
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$pl", room_id: "!r:mylittlechart.org", sender_user_id: 1, event_type: "m.room.power_levels", state_key: "", content: &power_levels_content, origin_server_ts: 1200, now: T0 })
            .expect("power levels");

        let err = apply_membership_power_action(
            &mut conn,
            1,
            &alice,
            MembershipPowerAction {
                room_id: "!r:mylittlechart.org",
                action: PowerAction::Kick,
                target_user_id: 2,
                target_rule: TargetStateRule::MustBeActiveMember,
                new_membership: Membership::Leave,
                reason: None,
            },
            T0,
            2000,
        )
        .unwrap_err();
        assert_eq!(err.errcode, "M_FORBIDDEN");
    }

    #[test]
    fn a_member_can_always_self_kick_regardless_of_level() {
        let mut conn = test_conn();
        make_room(&conn, "!r:mylittlechart.org", RoomKind::Group, 1);
        let alice = matrix_store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000043", T0).expect("alice");
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$m1", room_id: "!r:mylittlechart.org", sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join"}"#, origin_server_ts: 1000, now: T0 })
            .expect("alice joins");
        // No power_levels event at all — alice's level defaults to 0, far
        // below the default kick threshold of 50 — yet she may still
        // "kick" (leave as) herself.
        let wake_ids = apply_membership_power_action(
            &mut conn,
            1,
            &alice,
            MembershipPowerAction {
                room_id: "!r:mylittlechart.org",
                action: PowerAction::Kick,
                target_user_id: 1,
                target_rule: TargetStateRule::MustBeActiveMember,
                new_membership: Membership::Leave,
                reason: None,
            },
            T0,
            2000,
        )
        .expect("a member may always remove themselves");
        assert!(wake_ids.contains(&1));
    }

    // ---- brief test: invite wakes the invitee ----

    #[test]
    fn invite_wakes_the_invitee() {
        let mut conn = test_conn();
        make_room(&conn, "!r:mylittlechart.org", RoomKind::Group, 1);
        let alice = matrix_store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000011", T0).expect("alice");
        matrix_store::ensure_matrix_user(&conn, 2, "bob0000000000000000000000000011", T0).expect("bob");
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$m1", room_id: "!r:mylittlechart.org", sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join"}"#, origin_server_ts: 1000, now: T0 })
            .expect("alice joins");
        let power_levels_content = serde_json::json!({ "users": { alice.clone(): 100 } }).to_string();
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$pl", room_id: "!r:mylittlechart.org", sender_user_id: 1, event_type: "m.room.power_levels", state_key: "", content: &power_levels_content, origin_server_ts: 1100, now: T0 })
            .expect("power levels grant alice invite power");

        let wake_ids = apply_invite(&mut conn, "!r:mylittlechart.org", 1, &alice, InviteTarget { user_id: 2, displayname: "Bob" }, T0, 2000).expect("invite succeeds");
        assert!(wake_ids.contains(&1), "the inviter's own other devices must be woken");
        assert!(wake_ids.contains(&2), "the invitee must be woken");
        assert_eq!(
            matrix_store::room_member(&conn, "!r:mylittlechart.org", 2).expect("bob's row").expect("row exists").membership,
            Membership::Invite
        );
    }

    #[test]
    fn apply_invite_refuses_an_already_joined_target() {
        let mut conn = test_conn();
        make_room(&conn, "!r:mylittlechart.org", RoomKind::Group, 1);
        let alice = matrix_store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000012", T0).expect("alice");
        let bob = matrix_store::ensure_matrix_user(&conn, 2, "bob0000000000000000000000000012", T0).expect("bob");
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$m1", room_id: "!r:mylittlechart.org", sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join"}"#, origin_server_ts: 1000, now: T0 })
            .expect("alice joins");
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$m2", room_id: "!r:mylittlechart.org", sender_user_id: 1, event_type: "m.room.member", state_key: &bob, content: r#"{"membership":"join"}"#, origin_server_ts: 1100, now: T0 })
            .expect("bob joins");
        let power_levels_content = serde_json::json!({ "users": { alice.clone(): 100 } }).to_string();
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$pl", room_id: "!r:mylittlechart.org", sender_user_id: 1, event_type: "m.room.power_levels", state_key: "", content: &power_levels_content, origin_server_ts: 1200, now: T0 })
            .expect("power levels grant alice invite power");

        let err = apply_invite(&mut conn, "!r:mylittlechart.org", 1, &alice, InviteTarget { user_id: 2, displayname: "Bob" }, T0, 2000).unwrap_err();
        assert_eq!(err.errcode, "M_INVALID_PARAM");
    }

    // ---- P16 S-a: a DM invite carries `is_direct`, a group invite does not ----

    /// The invitee's own `m.room.member` invite event, in the stripped shape
    /// `GET /sync` puts into `rooms.invite.{roomId}.invite_state.events`.
    fn invitee_stripped_member_event(conn: &Connection, room_id: &str, invitee_mxid: &str) -> serde_json::Value {
        let event = matrix_store::current_state_event(conn, room_id, "m.room.member", invitee_mxid).expect("query").expect("invitee member event exists");
        matrix_store::stripped_state_json(conn, &event).expect("stripped json")
    }

    fn invite_bob_into(kind: RoomKind, suffix: &str) -> (Connection, String) {
        let mut conn = test_conn();
        make_room(&conn, "!r:mylittlechart.org", kind, 1);
        let alice = matrix_store::ensure_matrix_user(&conn, 1, &format!("alice000000000000000000000000{suffix}"), T0).expect("alice");
        let bob = matrix_store::ensure_matrix_user(&conn, 2, &format!("bob00000000000000000000000000{suffix}"), T0).expect("bob");
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$m1", room_id: "!r:mylittlechart.org", sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join"}"#, origin_server_ts: 1000, now: T0 })
            .expect("alice joins");
        let power_levels_content = serde_json::json!({ "users": { alice.clone(): 100 } }).to_string();
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$pl", room_id: "!r:mylittlechart.org", sender_user_id: 1, event_type: "m.room.power_levels", state_key: "", content: &power_levels_content, origin_server_ts: 1100, now: T0 })
            .expect("power levels grant alice invite power");
        apply_invite(&mut conn, "!r:mylittlechart.org", 1, &alice, InviteTarget { user_id: 2, displayname: "Bob" }, T0, 2000).expect("invite succeeds");
        (conn, bob)
    }

    #[test]
    fn dm_invite_member_event_carries_is_direct() {
        let (conn, bob) = invite_bob_into(RoomKind::Dm, "61");
        let stripped = invitee_stripped_member_event(&conn, "!r:mylittlechart.org", &bob);
        assert_eq!(stripped["content"]["membership"], "invite");
        assert_eq!(stripped["content"]["is_direct"], serde_json::Value::Bool(true), "a DM invite must tell the invitee the room is direct");
    }

    #[test]
    fn group_invite_member_event_has_no_is_direct() {
        let (conn, bob) = invite_bob_into(RoomKind::Group, "62");
        let stripped = invitee_stripped_member_event(&conn, "!r:mylittlechart.org", &bob);
        assert_eq!(stripped["content"]["membership"], "invite");
        assert!(stripped["content"].get("is_direct").is_none(), "a group invite must not claim the room is direct");
    }

    #[test]
    fn create_room_invite_content_marks_only_a_dm_direct() {
        assert_eq!(invite_member_content(RoomKind::Dm, "Bob"), serde_json::json!({ "membership": "invite", "is_direct": true, "displayname": "Bob" }));
        assert_eq!(invite_member_content(RoomKind::Group, "Bob"), serde_json::json!({ "membership": "invite", "displayname": "Bob" }));
        assert_eq!(invite_member_content(RoomKind::Channel, "Bob"), serde_json::json!({ "membership": "invite", "displayname": "Bob" }));
    }

    // ---- displayname: every join/invite member event carries the TARGET
    // user's effective label (nick, else the provider name, else the public id) ----

    fn identity_conn() -> Connection {
        crate::db::init_db(":memory:", &"0".repeat(64)).expect("init identity test db")
    }

    /// One identity user with only a provider display name; returns
    /// `(user_id, public_id)`.
    fn seed_user(identity: &Connection, provider_user_id: &str, provider_name: &str) -> (i64, String) {
        let user_id = db::upsert_user(identity, "github", provider_user_id, provider_name, None, T0).expect("seed user");
        let public_id = db::get_user_public_id(identity, user_id).expect("public id");
        (user_id, public_id)
    }

    /// `(alice, bob)` in one identity database: alice chose the nick
    /// `alice_nick` (label = nick); bob never did (label = his provider name
    /// `Bob Provider`).
    fn alice_with_nick_and_bob_without() -> (Connection, (i64, String), (i64, String)) {
        let identity = identity_conn();
        let alice = seed_user(&identity, "alice-gh", "Alice Provider");
        let bob = seed_user(&identity, "bob-gh", "Bob Provider");
        db::set_nick(&identity, alice.0, "alice_nick", &[]).expect("alice's nick");
        (identity, alice, bob)
    }

    fn member_content_of(conn: &Connection, room_id: &str, mxid: &str) -> serde_json::Value {
        let event = matrix_store::current_state_event(conn, room_id, "m.room.member", mxid).expect("query").expect("member event exists");
        serde_json::from_str(&event.content).expect("member content is json")
    }

    #[test]
    fn create_room_dm_member_events_carry_each_users_effective_label_and_the_invite_keeps_is_direct() {
        let (identity, (alice_id, alice_public), (bob_id, bob_public)) = alice_with_nick_and_bob_without();
        let alice_label = db::effective_label_for_user(&identity, alice_id).expect("alice label");
        let bob_label = db::effective_label_for_user(&identity, bob_id).expect("bob label");
        assert_eq!(alice_label, "alice_nick");
        assert_eq!(bob_label, "Bob Provider");

        let mut messenger = test_conn();
        let alice_mxid = matrix_store::ensure_matrix_user(&messenger, alice_id, &alice_public, T0).expect("alice");
        let bob_mxid = matrix_store::ensure_matrix_user(&messenger, bob_id, &bob_public, T0).expect("bob");

        // The exact event assembly `create_room` runs, written through the
        // same one-transaction batch entry point.
        let mut state_events = vec![state_event("m.room.create", "", alice_id, serde_json::json!({ "room_version": matrix_store::MATRIX_ROOM_VERSION }))];
        state_events.extend(bootstrap_member_events(RoomKind::Dm, (alice_id, &alice_mxid, &alice_label), &[(bob_mxid.clone(), bob_label.clone())]));
        let (join_rule, history_visibility, is_encrypted) = room_kind_settings(RoomKind::Dm);
        let bootstrap = matrix_store::RoomBootstrap {
            room_id: "!dm:mylittlechart.org",
            kind: RoomKind::Dm,
            creator_user_id: alice_id,
            created_at: T0,
            is_encrypted,
            join_rule,
            history_visibility,
            dm_pair_key: Some("1:2"),
            legacy_dm_id: None,
        };
        matrix_store::create_room_with_state(&mut messenger, bootstrap, &state_events, 1000).expect("create room");

        assert_eq!(
            member_content_of(&messenger, "!dm:mylittlechart.org", &alice_mxid),
            serde_json::json!({ "membership": "join", "displayname": "alice_nick" }),
            "the creator's join carries the creator's nick"
        );
        let invite = invitee_stripped_member_event(&messenger, "!dm:mylittlechart.org", &bob_mxid);
        assert_eq!(
            invite["content"],
            serde_json::json!({ "membership": "invite", "is_direct": true, "displayname": "Bob Provider" }),
            "the invite carries the INVITEE's label and still marks the room direct"
        );
        assert_eq!(invite["sender"], alice_mxid, "the creator sends the invite");
    }

    #[test]
    fn bootstrap_member_events_put_the_creator_first_and_keep_a_group_invite_free_of_is_direct() {
        let events = bootstrap_member_events(
            RoomKind::Group,
            (1, "@alice:mylittlechart.org", "Alice"),
            &[("@bob:mylittlechart.org".to_string(), "Bob".to_string()), ("@carol:mylittlechart.org".to_string(), "Carol".to_string())],
        );
        assert_eq!(events.len(), 3);
        let contents: Vec<serde_json::Value> = events.iter().map(|e| serde_json::from_str(&e.content).expect("json")).collect();
        assert_eq!(events[0].state_key, "@alice:mylittlechart.org");
        assert_eq!(contents[0], serde_json::json!({ "membership": "join", "displayname": "Alice" }));
        assert_eq!(contents[1], serde_json::json!({ "membership": "invite", "displayname": "Bob" }));
        assert_eq!(contents[2], serde_json::json!({ "membership": "invite", "displayname": "Carol" }));
        assert!(events.iter().all(|e| e.event_type == "m.room.member" && e.sender_user_id == 1), "the creator sends every bootstrap member event");
    }

    #[test]
    fn apply_invite_stamps_the_targets_effective_label_nick_first_then_the_provider_name() {
        let (identity, (alice_id, alice_public), (bob_id, bob_public)) = alice_with_nick_and_bob_without();
        let (carol_id, carol_public) = seed_user(&identity, "carol-gh", "Carol Provider");
        db::set_nick(&identity, bob_id, "kestrel", &[]).expect("bob's nick");

        let mut conn = test_conn();
        make_room(&conn, "!r:mylittlechart.org", RoomKind::Group, alice_id);
        let alice = matrix_store::ensure_matrix_user(&conn, alice_id, &alice_public, T0).expect("alice");
        let bob = matrix_store::ensure_matrix_user(&conn, bob_id, &bob_public, T0).expect("bob");
        let carol = matrix_store::ensure_matrix_user(&conn, carol_id, &carol_public, T0).expect("carol");
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$m1", room_id: "!r:mylittlechart.org", sender_user_id: alice_id, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join"}"#, origin_server_ts: 1000, now: T0 })
            .expect("alice joins");
        let power_levels_content = serde_json::json!({ "users": { alice.clone(): 100 } }).to_string();
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$pl", room_id: "!r:mylittlechart.org", sender_user_id: alice_id, event_type: "m.room.power_levels", state_key: "", content: &power_levels_content, origin_server_ts: 1100, now: T0 })
            .expect("power levels grant alice invite power");

        for (target_id, expected_label) in [(bob_id, "kestrel"), (carol_id, "Carol Provider")] {
            let label = db::effective_label_for_user(&identity, target_id).expect("label");
            assert_eq!(label, expected_label);
            let target = InviteTarget { user_id: target_id, displayname: &label };
            apply_invite(&mut conn, "!r:mylittlechart.org", alice_id, &alice, target, T0, 2000).expect("invite succeeds");
        }
        assert_eq!(member_content_of(&conn, "!r:mylittlechart.org", &bob), serde_json::json!({ "membership": "invite", "displayname": "kestrel" }));
        assert_eq!(
            member_content_of(&conn, "!r:mylittlechart.org", &carol),
            serde_json::json!({ "membership": "invite", "displayname": "Carol Provider" }),
            "no nick: the provider display name is the label"
        );
    }

    #[test]
    fn apply_join_stamps_the_callers_effective_label() {
        let (identity, (alice_id, alice_public), (bob_id, bob_public)) = alice_with_nick_and_bob_without();
        let mut conn = test_conn();
        make_room(&conn, "!chan:mylittlechart.org", RoomKind::Channel, alice_id);
        matrix_store::ensure_matrix_user(&conn, alice_id, &alice_public, T0).expect("alice");
        let bob = matrix_store::ensure_matrix_user(&conn, bob_id, &bob_public, T0).expect("bob");

        let label = db::effective_label_for_user(&identity, bob_id).expect("bob label");
        apply_join(&mut conn, "!chan:mylittlechart.org", bob_id, &bob, &label, T0, 2000).expect("bob joins");

        assert_eq!(member_content_of(&conn, "!chan:mylittlechart.org", &bob), serde_json::json!({ "membership": "join", "displayname": "Bob Provider" }));
        assert_eq!(matrix_store::room_member(&conn, "!chan:mylittlechart.org", bob_id).expect("query").expect("row").membership, Membership::Join);
    }

    #[test]
    fn a_member_event_without_any_label_carries_no_displayname() {
        assert_eq!(join_member_content(""), serde_json::json!({ "membership": "join" }));
        assert_eq!(invite_member_content(RoomKind::Dm, ""), serde_json::json!({ "membership": "invite", "is_direct": true }));
    }

    // ---- a client cannot pick its own displayname ----

    #[test]
    fn own_member_update_cannot_spoof_a_displayname() {
        let alice = "@alice:mylittlechart.org";
        let spoofed = r#"{"membership":"join","displayname":"Admin (verified)","avatar_url":"mxc://x/y"}"#;

        // The route lets the update through …
        assert!(check_state_event_type_allowed("m.room.member", alice, alice, spoofed).is_ok());
        // … and overwrites the name with the nick's label, keeping the rest.
        let stamped: serde_json::Value = serde_json::from_str(&stamp_own_member_displayname(spoofed, "alice_nick").expect("stamp")).expect("json");
        assert_eq!(stamped["displayname"], "alice_nick");
        assert_eq!(stamped["membership"], "join");
        assert_eq!(stamped["avatar_url"], "mxc://x/y");

        // No name sent at all: the label is stamped anyway.
        let stamped: serde_json::Value = serde_json::from_str(&stamp_own_member_displayname(r#"{"membership":"join"}"#, "alice_nick").expect("stamp")).expect("json");
        assert_eq!(stamped["displayname"], "alice_nick");

        // Nothing to stamp: the client's name is dropped, never kept.
        let stamped: serde_json::Value = serde_json::from_str(&stamp_own_member_displayname(spoofed, "").expect("stamp")).expect("json");
        assert!(stamped.get("displayname").is_none());

        assert_eq!(stamp_own_member_displayname("[]", "alice_nick").unwrap_err().errcode, "M_INVALID_PARAM");
    }

    #[test]
    fn a_spoofed_own_member_event_is_stored_with_the_nicks_label() {
        let (identity, (alice_id, alice_public), _bob) = alice_with_nick_and_bob_without();
        let mut conn = test_conn();
        make_room(&conn, "!r:mylittlechart.org", RoomKind::Group, alice_id);
        let alice = matrix_store::ensure_matrix_user(&conn, alice_id, &alice_public, T0).expect("alice");
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$m1", room_id: "!r:mylittlechart.org", sender_user_id: alice_id, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join","displayname":"alice_nick"}"#, origin_server_ts: 1000, now: T0 })
            .expect("alice joins");

        // The `PUT state` write path: gate, stamp, store.
        let spoofed = r#"{"membership":"join","displayname":"Somebody Else"}"#;
        check_state_event_type_allowed("m.room.member", &alice, &alice, spoofed).expect("own join update is allowed");
        let label = db::effective_label_for_user(&identity, alice_id).expect("label");
        let stored = stamp_own_member_displayname(spoofed, &label).expect("stamp");
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$m2", room_id: "!r:mylittlechart.org", sender_user_id: alice_id, event_type: "m.room.member", state_key: &alice, content: &stored, origin_server_ts: 2000, now: T0 }).expect("store");

        assert_eq!(member_content_of(&conn, "!r:mylittlechart.org", &alice)["displayname"], "alice_nick");
    }

    // ---- nick change / boot backfill: stale member events are re-stamped ----

    #[test]
    fn backfill_restamps_events_that_predate_the_displayname_and_follows_a_nick_change() {
        let (identity, (alice_id, alice_public), (bob_id, bob_public)) = alice_with_nick_and_bob_without();
        let mut conn = test_conn();
        let alice = matrix_store::ensure_matrix_user(&conn, alice_id, &alice_public, T0).expect("alice");
        let bob = matrix_store::ensure_matrix_user(&conn, bob_id, &bob_public, T0).expect("bob");
        let (room_a, room_b, room_left) = ("!a:mylittlechart.org", "!b:mylittlechart.org", "!left:mylittlechart.org");
        for room in [room_a, room_b, room_left] {
            make_room(&conn, room, RoomKind::Group, alice_id);
            // Events as a server that never stamped a name wrote them.
            matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: &matrix_store::new_event_id(), room_id: room, sender_user_id: alice_id, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join"}"#, origin_server_ts: 1000, now: T0 })
                .expect("alice joins");
            matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: &matrix_store::new_event_id(), room_id: room, sender_user_id: bob_id, event_type: "m.room.member", state_key: &bob, content: r#"{"membership":"join"}"#, origin_server_ts: 1100, now: T0 })
                .expect("bob joins");
        }
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: &matrix_store::new_event_id(), room_id: room_left, sender_user_id: bob_id, event_type: "m.room.member", state_key: &bob, content: r#"{"membership":"leave"}"#, origin_server_ts: 1200, now: T0 })
            .expect("bob leaves the third room");

        let written = backfill_member_displaynames(&identity, &mut conn, T0).expect("backfill");
        assert_eq!(written, 5, "alice in three rooms, bob in the two he is still in");
        for room in [room_a, room_b] {
            assert_eq!(member_content_of(&conn, room, &alice)["displayname"], "alice_nick");
            assert_eq!(member_content_of(&conn, room, &bob)["displayname"], "Bob Provider");
        }
        assert_eq!(member_content_of(&conn, room_left, &bob), serde_json::json!({ "membership": "leave" }), "a room the user left is not touched");
        assert_eq!(backfill_member_displaynames(&identity, &mut conn, T0).expect("second pass"), 0, "an up-to-date event is left alone");

        // Bob picks a nick: the next pass re-stamps him where he is joined,
        // and nobody else.
        db::set_nick(&identity, bob_id, "plum_walrus", &[]).expect("bob's new nick");
        assert_eq!(backfill_member_displaynames(&identity, &mut conn, T0).expect("after the nick change"), 2);
        for room in [room_a, room_b] {
            assert_eq!(member_content_of(&conn, room, &bob)["displayname"], "plum_walrus");
            assert_eq!(member_content_of(&conn, room, &alice)["displayname"], "alice_nick");
        }
        assert_eq!(member_content_of(&conn, room_left, &bob), serde_json::json!({ "membership": "leave" }));
    }

    // ---- manager review 2026-09-24: /leave also accepts an invited caller ----

    #[test]
    fn invited_user_can_reject_via_leave() {
        let mut conn = test_conn();
        make_room(&conn, "!r:mylittlechart.org", RoomKind::Group, 1);
        let alice = matrix_store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000031", T0).expect("alice");
        let bob = matrix_store::ensure_matrix_user(&conn, 2, "bob0000000000000000000000000031", T0).expect("bob");
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$m1", room_id: "!r:mylittlechart.org", sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join"}"#, origin_server_ts: 1000, now: T0 })
            .expect("alice (the inviter) joins");
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$m2", room_id: "!r:mylittlechart.org", sender_user_id: 1, event_type: "m.room.member", state_key: &bob, content: r#"{"membership":"invite"}"#, origin_server_ts: 1100, now: T0 })
            .expect("alice invites bob");

        let wake_ids = apply_leave(&mut conn, "!r:mylittlechart.org", 2, &bob, T0, 2000).expect("bob rejects the invite via leave");
        assert!(wake_ids.contains(&1), "the inviter must be woken");
        assert!(wake_ids.contains(&2), "bob's own other devices must be woken too");
        assert_eq!(
            matrix_store::room_member(&conn, "!r:mylittlechart.org", 2).expect("bob's row").expect("row exists").membership,
            Membership::Leave
        );
    }

    #[test]
    fn a_non_member_cannot_leave() {
        let mut conn = test_conn();
        make_room(&conn, "!r:mylittlechart.org", RoomKind::Group, 1);
        let alice = matrix_store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000032", T0).expect("alice");
        matrix_store::ensure_matrix_user(&conn, 2, "bob0000000000000000000000000032", T0).expect("bob");
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$m1", room_id: "!r:mylittlechart.org", sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join"}"#, origin_server_ts: 1000, now: T0 })
            .expect("alice joins");

        let err = apply_leave(&mut conn, "!r:mylittlechart.org", 2, "@bob:mylittlechart.org", T0, 2000).unwrap_err();
        assert_eq!(err.errcode, "M_FORBIDDEN");
    }

    // ---- brief test: client_event_json uses mxids ----

    #[test]
    fn client_event_json_uses_mxids() {
        let mut conn = test_conn();
        make_room(&conn, "!r:mylittlechart.org", RoomKind::Group, 1);
        let alice = matrix_store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000013", T0).expect("alice");
        let event = matrix_store::apply_state_event(
            &mut conn,
            &matrix_store::StateEventWrite {
                event_id: "$m1",
                room_id: "!r:mylittlechart.org",
                sender_user_id: 1,
                event_type: "m.room.member",
                state_key: &alice,
                content: r#"{"membership":"join"}"#,
                origin_server_ts: 1000,
                now: T0,
            },
        )
        .expect("alice joins");

        let json = client_event_json(&conn, &event, None).expect("format");
        assert_eq!(json["sender"], alice, "sender must be the mxid, never the internal user_id");
        assert_eq!(json["state_key"], alice, "state_key must be the mxid, never the internal user_id");
        assert_eq!(json["room_id"], "!r:mylittlechart.org");
        assert_eq!(json["type"], "m.room.member");
        assert!(json["unsigned"]["age"].as_i64().is_some());
    }

    #[test]
    fn client_event_json_attaches_invite_room_state_only_for_an_invite() {
        let mut conn = test_conn();
        make_room(&conn, "!r:mylittlechart.org", RoomKind::Group, 1);
        let alice = matrix_store::ensure_matrix_user(&conn, 1, "alice00000000000000000000000014", T0).expect("alice");
        let bob = matrix_store::ensure_matrix_user(&conn, 2, "bob0000000000000000000000000014", T0).expect("bob");
        matrix_store::apply_state_event(&mut conn, &matrix_store::StateEventWrite { event_id: "$create", room_id: "!r:mylittlechart.org", sender_user_id: 1, event_type: "m.room.create", state_key: "", content: r#"{"room_version":"11"}"#, origin_server_ts: 900, now: T0 })
            .expect("create");
        let join_event = matrix_store::apply_state_event(
            &mut conn,
            &matrix_store::StateEventWrite {
                event_id: "$m1",
                room_id: "!r:mylittlechart.org",
                sender_user_id: 1,
                event_type: "m.room.member",
                state_key: &alice,
                content: r#"{"membership":"join"}"#,
                origin_server_ts: 1000,
                now: T0,
            },
        )
        .expect("alice joins");
        let invite_event = matrix_store::apply_state_event(
            &mut conn,
            &matrix_store::StateEventWrite {
                event_id: "$m2",
                room_id: "!r:mylittlechart.org",
                sender_user_id: 1,
                event_type: "m.room.member",
                state_key: &bob,
                content: r#"{"membership":"invite"}"#,
                origin_server_ts: 1100,
                now: T0,
            },
        )
        .expect("bob invited");

        let join_json = client_event_json(&conn, &join_event, None).expect("format join");
        assert!(join_json["unsigned"].get("invite_room_state").is_none(), "a join event carries no invite_room_state");

        let invite_json = client_event_json(&conn, &invite_event, None).expect("format invite");
        let stripped = invite_json["unsigned"]["invite_room_state"].as_array().expect("invite_room_state array");
        assert!(!stripped.is_empty(), "the invitee's own event must carry the room's stripped state");
    }

    // ---- routing smoke test: the merged router registers without a route-
    // conflict panic. `axum::Router::route` panics at ADD time (not at
    // first request) for an overlapping path, so simply building the full
    // `/_matrix` router below already proves the three arities of `/state`
    // (`/state`, `/state/{type}`, `/state/{type}/{key}`) coexist — no
    // request needs to be sent, and so no real `ControlPlane` is needed
    // either (every handler here only touches `state.control_plane()`
    // once a request actually dispatches into it). ----

    fn test_state() -> Arc<AppState> {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);
        Arc::new(AppState::new(
            None,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            shutdown_tx,
            Vec::new(),
            false,
            0,
            0,
            None,
        ))
    }

    #[test]
    fn matrix_router_registers_every_p5_route_without_a_conflict_panic() {
        let _router = super::super::router(test_state());
    }
}

//! `POST /api/matrix-admin/rooms/{roomId}/moderate` (P11) — the site's own
//! moderation lever over Matrix chat rooms. See
//! `docs/mlc/plans/messenger-proto-server-matrix-subset-2026-09-24.md` §4's
//! last table row and `routes::forum_v2::moderate_thread`'s dual site-role/
//! object-role gate, which this route mirrors for Matrix rooms instead of
//! forum threads.
//!
//! # Mount point and auth (deliberately NOT under `/_matrix`)
//!
//! This is our own admin surface, not a Matrix Client-Server API endpoint —
//! `routes::mod::control_api_router` mounts [`routes`] as a sibling of every
//! other `/api/*` route, not merged into `routes::matrix::router` (the
//! `/_matrix` sub-router). Auth is the SAME session/bearer resolver every
//! other `/api/*` route uses ([`resolve_caller`], mirroring
//! `routes::dm::resolve_user_id` — own copy per this codebase's
//! one-copy-per-route-module convention), and every error response is this
//! codebase's house JSON shape (`{"error": "..."}`, [`crate::models::types::ErrorResponse`]),
//! never a Matrix errcode.
//!
//! # The gate: two independent levers, never combined
//!
//! - **(a) Site lever** — a site moderator/admin
//!   (`social_db::is_moderator_or_admin`) may act in a PUBLIC room
//!   (`join_rule = public`, i.e. a channel) regardless of that room's own
//!   power levels — [`apply_moderation_redact`]/[`apply_moderation_membership_action`]'s
//!   `site_lever` branch. This is the plan's "server-side lever on public
//!   rooms without appearing in power levels": the moderator need not be a
//!   member of the room at all, and MAY act on a target whose room power
//!   level is higher than the moderator's own (that is the entire point of
//!   a lever that lives outside the room's own authority chain) — the
//!   resulting event carries `"org.mylittlechart.site_moderation": true` in
//!   its content so every client can render it distinctly from an ordinary
//!   member-initiated action.
//! - **(b) Room-power fallback** — otherwise (the caller is not site staff,
//!   OR the room is private), the caller needs the room's own power: own
//!   event OR `PowerCheck(redact)` for `redact_message`;
//!   `can_act_on`'s target-level rule for `kick_member`/`ban_member`/
//!   `unban_member`. This is reused VERBATIM from `routes::matrix::rooms`
//!   ([`rooms::apply_membership_power_action`]) and duplicated only in its
//!   ~10-line redact shape (own copy, per this codebase's convention for a
//!   small gate check — see [`apply_moderation_redact`]'s own doc), so a
//!   kick/ban/unban/redact reached through this route never drifts from the
//!   identical action reached through `/_matrix/client/v3/rooms/{roomId}/(kick|ban|unban|redact/...)`.
//!
//! **Private rooms stay the members' own space.** A DM or group chat is
//! never touched by the site lever — a site moderator with no room power in
//! a private room is refused exactly like any other non-member (see
//! [`apply_moderation_redact`]/[`apply_moderation_membership_action`]'s
//! `site_lever` computation: `is_site_moderator && room.join_rule ==
//! JoinRule::Public`). There is no reporting mechanism yet to carve out a
//! narrower "only the reported message" exception in a private room, so
//! none is built — the only server-side lever over a private room's
//! membership is the existing account-level ban, out of this route's scope.
//!
//! # Testable cores
//!
//! [`apply_moderation_redact`]/[`apply_moderation_membership_action`] take
//! `is_site_moderator: bool` and plain connection/id/mxid values — never
//! `AppState` or a live `social_db` lookup — so every gate combination is
//! unit-tested against an in-memory `matrix_store` fixture with no axum or
//! `social_db` fixture at all; [`moderate_room`] itself resolves
//! `is_site_moderator` via `social_db::caller_classes` right before calling
//! into these cores.
//!
//! # Audit logging
//!
//! Every action that reaches a DB write logs one `tracing::info!` line
//! naming the room, the acting `user_id`, the action, and the target
//! (event id or target mxid) — never event content (see [`moderate_room`]'s
//! own logging call, after the write succeeds).

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use rusqlite::{params, Connection, OptionalExtension};

use mylittlechart_server::matrix_store::{self, JoinRule, Membership, PowerAction, Room};

use super::rooms;
use crate::auth::{extract_bearer, extract_session_id, extract_ua_hash, hash_token};
use crate::db;
use crate::models::types::ErrorResponse;
use crate::social_db;
use crate::state::AppState;

// ============================================================================
// Response helpers — house `/api/*` JSON shape, own copies per this
// codebase's one-copy-per-route-module convention (mirrors `routes::dm`'s
// own `internal_error`/`bad_request`/`unauthorized`).
// ============================================================================

fn internal_error() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Internal error"))).into_response()
}

fn bad_request(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(ErrorResponse::new(msg))).into_response()
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, Json(ErrorResponse::new("Authentication required"))).into_response()
}

// ============================================================================
// ModerationError — this route's own error shape (house JSON, never a
// Matrix errcode), with `From` conversions off every error type the DB-only
// cores below can raise.
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
struct ModerationError {
    status: StatusCode,
    message: String,
}

impl ModerationError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self { status, message: message.into() }
    }
    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
    fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }
    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }
    fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    }
}

impl IntoResponse for ModerationError {
    fn into_response(self) -> Response {
        (self.status, Json(ErrorResponse::new(self.message))).into_response()
    }
}

impl From<rusqlite::Error> for ModerationError {
    fn from(e: rusqlite::Error) -> Self {
        tracing::error!("DB error in the matrix-admin moderation route: {}", e);
        Self::internal()
    }
}

impl From<serde_json::Error> for ModerationError {
    fn from(e: serde_json::Error) -> Self {
        tracing::error!("JSON error in the matrix-admin moderation route: {}", e);
        Self::internal()
    }
}

impl From<mylittlechart_server::matrix_store::MatrixStoreError> for ModerationError {
    fn from(e: mylittlechart_server::matrix_store::MatrixStoreError) -> Self {
        use mylittlechart_server::matrix_store::MatrixStoreError as E;
        match e {
            E::Db(e) => Self::from(e),
            E::Json(e) => Self::from(e),
            E::ReservedLocalpart => Self::forbidden("Reserved localpart"),
            E::DuplicateAnnotation => Self::bad_request("Already reacted with this key"),
            E::UnknownEventId(id) => Self::not_found(format!("Unknown event: {id}")),
            E::UnknownMxid(id) => Self::not_found(format!("Unknown user: {id}")),
            E::InvalidMembership(m) => Self::bad_request(format!("Invalid membership: {m}")),
            E::InvalidRelationTarget(id) => Self::bad_request(format!("Invalid relation target: {id}")),
            E::WrongRoom(id) => Self::bad_request(format!("Event is not in this room: {id}")),
            E::UnredactableEvent(t) => Self::forbidden(format!("This event type cannot be redacted: {t}")),
        }
    }
}

/// `rooms::apply_membership_power_action`/`rooms::check_target_state_rule`
/// both return `routes::matrix::MatrixError` — this route's own room-power
/// fallback gate reuses them verbatim (see this module's own doc), so their
/// error is converted straight through by status/message rather than
/// re-derived.
impl From<super::MatrixError> for ModerationError {
    fn from(e: super::MatrixError) -> Self {
        Self { status: e.status, message: e.error }
    }
}

// ============================================================================
// Caller resolution — own copy of `routes::dm::resolve_user_id` (per this
// codebase's one-copy-per-route-module convention): session cookie first,
// then bearer.
// ============================================================================

async fn resolve_caller(state: Arc<AppState>, headers: &HeaderMap) -> Result<i64, Response> {
    let session_id = extract_session_id(headers);
    let ua_hash = extract_ua_hash(headers);
    let bearer: Option<String> = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| extract_bearer(Some(v)))
        .map(str::to_owned);

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
        Ok(Ok(None)) => Err(unauthorized()),
        Ok(Err(e)) => {
            tracing::error!("DB error resolving matrix-admin moderation caller: {}", e);
            Err(internal_error())
        }
        Err(_) => Err(internal_error()),
    }
}

// ============================================================================
// Request body and action parsing
// ============================================================================

#[derive(serde::Deserialize)]
struct ModerateRoomRequest {
    action: String,
    #[serde(default)]
    event_id: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModerationAction {
    RedactMessage,
    KickMember,
    BanMember,
    UnbanMember,
}

impl ModerationAction {
    fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "redact_message" => Some(Self::RedactMessage),
            "kick_member" => Some(Self::KickMember),
            "ban_member" => Some(Self::BanMember),
            "unban_member" => Some(Self::UnbanMember),
            _ => None,
        }
    }
}

/// The validated target of one moderation call, built once in the async
/// handler (so a missing `event_id`/`user_id` is refused with `400` before
/// any `spawn_blocking` work starts) and carried into the blocking closure —
/// the membership variant already carries the `(PowerAction, TargetStateRule,
/// Membership)` triple for its action, so the closure never re-matches
/// [`ModerationAction`] a second time.
enum ModerationTarget {
    Event(String),
    Member { mxid: String, power_action: PowerAction, target_rule: rooms::TargetStateRule, new_membership: Membership },
}

// ============================================================================
// User resolution by mxid — own copy of
// `routes::matrix::rooms::resolve_target_user` (per this codebase's
// one-copy-per-route-module convention; a handful of lines, not the
// ~150-line exception `recipient_search.rs` documents), returning this
// module's own `ModerationError` instead of `routes::matrix::MatrixError`.
// ============================================================================

fn resolve_user_id_by_public_id(conn: &Connection, public_id: &str) -> rusqlite::Result<Option<i64>> {
    conn.query_row("SELECT id FROM users WHERE public_id = ?1", params![public_id], |row| row.get(0)).optional()
}

fn resolve_target_user_id(identity_conn: &Connection, messenger_conn: &Connection, mxid: &str, now: &str) -> Result<i64, ModerationError> {
    if let Some(user_id) = matrix_store::user_id_of(messenger_conn, mxid)? {
        return Ok(user_id);
    }
    let public_id = matrix_store::public_id_from_mxid(mxid).map_err(|e| ModerationError::bad_request(e.to_string()))?;
    let user_id = resolve_user_id_by_public_id(identity_conn, public_id)?.ok_or_else(|| ModerationError::not_found(format!("Unknown user: {mxid}")))?;
    matrix_store::ensure_matrix_user(messenger_conn, user_id, public_id, now)?;
    Ok(user_id)
}

/// Own copy of `routes::matrix::rooms::power_levels_of` — [`apply_moderation_redact`]'s
/// room-power fallback needs the same "empty object when the room has never
/// had a `m.room.power_levels` event" default every other PowerCheck in this
/// server relies on.
fn power_levels_of(conn: &Connection, room_id: &str) -> Result<serde_json::Value, ModerationError> {
    match matrix_store::current_state_event(conn, room_id, "m.room.power_levels", "")? {
        Some(event) => Ok(serde_json::from_str(&event.content)?),
        None => Ok(serde_json::json!({})),
    }
}

// ============================================================================
// DB-only action cores — `&mut Connection`, plain values, no `AppState`,
// unit-tested directly (see the module doc's "Testable cores" section).
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
struct ModerationOutcome {
    /// `Some` for `redact_message` (the redaction event's own id); `None`
    /// for a membership action (kick/ban/unban), matching the Matrix routes'
    /// own `{}` response for those three.
    event_id: Option<String>,
    wake_ids: HashSet<i64>,
}

/// `redact_message`'s whole DB-side decision + write (this module's own doc,
/// gate (a)/(b)): the site lever ([`matrix_store::redact_event_marked`],
/// stamping `org.mylittlechart.site_moderation`) when `is_site_moderator`
/// and the room is public; otherwise the room's own "Member + (own event OR
/// PowerCheck(redact))" rule — a small own copy of
/// `routes::matrix::messaging::apply_redact`'s gate (that function also
/// threads a device/txn-id dedup pair this house-style admin endpoint has no
/// use for, so it is not reused directly).
#[allow(clippy::too_many_arguments)]
fn apply_moderation_redact(
    conn: &mut Connection,
    room: &Room,
    is_site_moderator: bool,
    caller_user_id: i64,
    caller_mxid: &str,
    target_event_id: &str,
    redaction_event_id: &str,
    reason: Option<&str>,
    origin_ts: i64,
) -> Result<ModerationOutcome, ModerationError> {
    let site_lever = is_site_moderator && room.join_rule == JoinRule::Public;

    let event = if site_lever {
        let extra = serde_json::json!({ "org.mylittlechart.site_moderation": true });
        matrix_store::redact_event_marked(conn, &room.id, target_event_id, redaction_event_id, caller_user_id, reason, &extra, origin_ts)?
    } else {
        let caller_membership = matrix_store::room_member(conn, &room.id, caller_user_id)?.map(|m| m.membership);
        if !matches!(caller_membership, Some(Membership::Join)) {
            return Err(ModerationError::forbidden("not a member of this room"));
        }
        let target = matrix_store::get_event(conn, target_event_id)?.ok_or_else(|| ModerationError::not_found("no such event"))?;
        if target.room_id != room.id {
            return Err(ModerationError::not_found("no such event"));
        }
        if target.sender_user_id != caller_user_id {
            let power_levels = power_levels_of(conn, &room.id)?;
            if !matrix_store::can(&power_levels, PowerAction::Redact, caller_mxid) {
                return Err(ModerationError::forbidden("insufficient power level for this action"));
            }
        }
        matrix_store::redact_event(conn, &room.id, target_event_id, redaction_event_id, caller_user_id, reason, origin_ts)?
    };

    let wake_ids = rooms::member_and_invited_ids(conn, &room.id)?;
    Ok(ModerationOutcome { event_id: Some(event.event_id), wake_ids })
}

/// `kick_member`/`ban_member`/`unban_member`'s whole DB-side decision +
/// write (this module's own doc, gate (a)/(b)): the site lever (a direct
/// `m.room.member` write, bypassing power entirely but still enforcing
/// [`rooms::TargetStateRule`] against the target's current membership, and
/// stamping `org.mylittlechart.site_moderation`) when `is_site_moderator`
/// and the room is public; otherwise
/// [`rooms::apply_membership_power_action`], reused verbatim — see this
/// module's own doc for why.
#[allow(clippy::too_many_arguments)]
fn apply_moderation_membership_action(
    conn: &mut Connection,
    room: &Room,
    is_site_moderator: bool,
    caller_user_id: i64,
    caller_mxid: &str,
    power_action: PowerAction,
    target_user_id: i64,
    target_mxid: &str,
    target_rule: rooms::TargetStateRule,
    new_membership: Membership,
    reason: Option<&str>,
    now: &str,
    origin_ts: i64,
) -> Result<ModerationOutcome, ModerationError> {
    let site_lever = is_site_moderator && room.join_rule == JoinRule::Public;

    if site_lever {
        let target_membership = matrix_store::room_member(conn, &room.id, target_user_id)?.map(|m| m.membership);
        rooms::check_target_state_rule(target_rule, target_membership)?;

        let mut content = serde_json::json!({
            "membership": new_membership.as_str(),
            "org.mylittlechart.site_moderation": true,
        });
        if let Some(reason) = reason {
            content["reason"] = serde_json::Value::String(reason.to_string());
        }
        let event = matrix_store::apply_state_event(
            conn,
            &matrix_store::new_event_id(),
            &room.id,
            caller_user_id,
            "m.room.member",
            target_mxid,
            &content.to_string(),
            origin_ts,
            now,
        )?;

        let mut wake_ids = rooms::member_and_invited_ids(conn, &room.id)?;
        wake_ids.insert(target_user_id);
        Ok(ModerationOutcome { event_id: Some(event.event_id), wake_ids })
    } else {
        let wake_ids = rooms::apply_membership_power_action(
            conn,
            caller_user_id,
            caller_mxid,
            rooms::MembershipPowerAction { room_id: &room.id, action: power_action, target_user_id, target_rule, new_membership, reason },
            now,
            origin_ts,
        )?;
        Ok(ModerationOutcome { event_id: None, wake_ids })
    }
}

// ============================================================================
// POST /api/matrix-admin/rooms/{roomId}/moderate
// ============================================================================

async fn moderate_room(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Json(req): Json<ModerateRoomRequest>,
) -> Response {
    let caller_user_id = match resolve_caller(state.clone(), &headers).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    let Some(action) = ModerationAction::from_wire(&req.action) else {
        return bad_request(&format!("unknown action: {}", req.action));
    };

    let target = match action {
        ModerationAction::RedactMessage => match req.event_id.clone() {
            Some(id) => ModerationTarget::Event(id),
            None => return bad_request("redact_message requires event_id"),
        },
        ModerationAction::KickMember => match req.user_id.clone() {
            Some(mxid) => {
                ModerationTarget::Member { mxid, power_action: PowerAction::Kick, target_rule: rooms::TargetStateRule::MustBeActiveMember, new_membership: Membership::Leave }
            }
            None => return bad_request("kick_member requires user_id"),
        },
        ModerationAction::BanMember => match req.user_id.clone() {
            Some(mxid) => ModerationTarget::Member { mxid, power_action: PowerAction::Ban, target_rule: rooms::TargetStateRule::Any, new_membership: Membership::Ban },
            None => return bad_request("ban_member requires user_id"),
        },
        ModerationAction::UnbanMember => match req.user_id.clone() {
            Some(mxid) => {
                ModerationTarget::Member { mxid, power_action: PowerAction::Ban, target_rule: rooms::TargetStateRule::MustBeBanned, new_membership: Membership::Leave }
            }
            None => return bad_request("unban_member requires user_id"),
        },
    };
    let target_label = match &target {
        ModerationTarget::Event(id) => id.clone(),
        ModerationTarget::Member { mxid, .. } => mxid.clone(),
    };
    let reason = req.reason.clone();

    let room_id_for_blocking = room_id.clone();
    let state_for_blocking = state.clone();

    let result = tokio::task::spawn_blocking(move || -> Result<ModerationOutcome, ModerationError> {
        let cp = state_for_blocking.control_plane();

        let caller_public_id = {
            let identity_conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
            db::get_user_public_id(&identity_conn, caller_user_id)?
        };
        let is_site_moderator = {
            let social_conn = cp.social_conn();
            social_db::is_moderator_or_admin(&social_db::caller_classes(&social_conn, Some(caller_user_id), false))
        };

        let now = chrono::Utc::now().to_rfc3339();
        let origin_ts = chrono::Utc::now().timestamp_millis();

        let caller_mxid = {
            let messenger_conn = cp.messenger_conn();
            matrix_store::ensure_matrix_user(&messenger_conn, caller_user_id, &caller_public_id, &now)?
        };

        let room = {
            let messenger_conn = cp.messenger_conn();
            matrix_store::get_room(&messenger_conn, &room_id_for_blocking)?.ok_or_else(|| ModerationError::not_found("no such room"))?
        };

        match target {
            ModerationTarget::Event(target_event_id) => {
                let redaction_event_id = matrix_store::new_event_id();
                let mut messenger_conn = cp.messenger_conn();
                apply_moderation_redact(&mut messenger_conn, &room, is_site_moderator, caller_user_id, &caller_mxid, &target_event_id, &redaction_event_id, reason.as_deref(), origin_ts)
            }
            ModerationTarget::Member { mxid: target_mxid_raw, power_action, target_rule, new_membership } => {
                let target_user_id = {
                    let identity_conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
                    let messenger_conn = cp.messenger_conn();
                    resolve_target_user_id(&identity_conn, &messenger_conn, &target_mxid_raw, &now)?
                };
                let target_mxid = {
                    let messenger_conn = cp.messenger_conn();
                    matrix_store::mxid_of(&messenger_conn, target_user_id)?.ok_or_else(ModerationError::internal)?
                };
                let mut messenger_conn = cp.messenger_conn();
                apply_moderation_membership_action(
                    &mut messenger_conn,
                    &room,
                    is_site_moderator,
                    caller_user_id,
                    &caller_mxid,
                    power_action,
                    target_user_id,
                    &target_mxid,
                    target_rule,
                    new_membership,
                    reason.as_deref(),
                    &now,
                    origin_ts,
                )
            }
        }
    })
    .await;

    match result {
        Ok(Ok(outcome)) => {
            tracing::info!(
                room_id = %room_id,
                actor = caller_user_id,
                action = %req.action,
                target = %target_label,
                "matrix-admin moderation action applied"
            );
            state.control_plane().live.wake_many(outcome.wake_ids.into_iter().map(|id| format!("user:{id}")));
            match outcome.event_id {
                Some(event_id) => Json(serde_json::json!({ "event_id": event_id })).into_response(),
                None => Json(serde_json::json!({})).into_response(),
            }
        }
        Ok(Err(e)) => e.into_response(),
        Err(_) => internal_error(),
    }
}

// ============================================================================
// Router
// ============================================================================

/// Mounted by `routes::mod::control_api_router` as a sibling of every other
/// `/api/*` route — NOT merged into `routes::matrix::router` (the `/_matrix`
/// sub-router), per this module's own doc.
pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/matrix-admin/rooms/{room_id}/moderate", post(moderate_room))
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

    // ---- plan §9 P11 test 1 ----

    #[test]
    fn site_moderator_can_redact_without_holding_room_power_level() {
        let mut conn = test_conn();
        make_room(&conn, "!chan:mylittlechart.org", matrix_store::RoomKind::Channel, 1);
        let caller_mxid = matrix_store::ensure_matrix_user(&conn, 99, "siteadmin00000000000000000000001", T0).expect("caller mxid");
        let author_event = matrix_store::insert_timeline_event(&mut conn, "$msg1", "!chan:mylittlechart.org", 1, "m.room.message", "{}", 1000, None).expect("author sends");
        let room = matrix_store::get_room(&conn, "!chan:mylittlechart.org").expect("room").expect("exists");

        let outcome = apply_moderation_redact(&mut conn, &room, true, 99, &caller_mxid, &author_event.event_id, "$red1", None, 2000)
            .expect("a site moderator may redact in a public room without holding any room power");
        assert!(outcome.event_id.is_some());
    }

    // ---- plan §9 P11 test 2 ----

    #[test]
    fn room_admin_without_site_moderator_role_can_still_redact_in_their_own_room() {
        let mut conn = test_conn();
        make_room(&conn, "!r:mylittlechart.org", matrix_store::RoomKind::Group, 1);
        let owner_mxid = matrix_store::ensure_matrix_user(&conn, 1, "owner0000000000000000000000001", T0).expect("owner mxid");
        matrix_store::apply_state_event(&mut conn, "$m1", "!r:mylittlechart.org", 1, "m.room.member", &owner_mxid, r#"{"membership":"join"}"#, 1000, T0).expect("owner joins");
        matrix_store::apply_state_event(
            &mut conn,
            "$pl1",
            "!r:mylittlechart.org",
            1,
            "m.room.power_levels",
            "",
            &serde_json::json!({ "users": { owner_mxid.clone(): 100 }, "redact": 50 }).to_string(),
            1100,
            T0,
        )
        .expect("power levels");
        let bob_event = matrix_store::insert_timeline_event(&mut conn, "$bob1", "!r:mylittlechart.org", 2, "m.room.message", "{}", 2000, None).expect("bob sends");
        let room = matrix_store::get_room(&conn, "!r:mylittlechart.org").expect("room").expect("exists");

        let outcome = apply_moderation_redact(&mut conn, &room, false, 1, &owner_mxid, &bob_event.event_id, "$red1", None, 3000)
            .expect("a room admin without a site moderator role can still redact via the room's own power");
        assert!(outcome.event_id.is_some());
    }

    // ---- site staff have no lever in a private room ----

    #[test]
    fn site_moderator_has_no_lever_in_a_private_room() {
        let mut conn = test_conn();
        make_room(&conn, "!priv:mylittlechart.org", matrix_store::RoomKind::Group, 1);
        let caller_mxid = matrix_store::ensure_matrix_user(&conn, 99, "siteadmin00000000000000000000002", T0).expect("caller mxid");
        let author_event = matrix_store::insert_timeline_event(&mut conn, "$msg1", "!priv:mylittlechart.org", 1, "m.room.message", "{}", 1000, None).expect("author sends");
        let room = matrix_store::get_room(&conn, "!priv:mylittlechart.org").expect("room").expect("exists");

        let err = apply_moderation_redact(&mut conn, &room, true, 99, &caller_mxid, &author_event.event_id, "$red1", None, 2000).unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN, "a site moderator has no lever in a private room — it falls back to room power, which they don't hold");
    }

    // ---- the site-moderation marker lands on the event ----

    #[test]
    fn site_moderation_marks_the_event() {
        let mut conn = test_conn();
        make_room(&conn, "!chan:mylittlechart.org", matrix_store::RoomKind::Channel, 1);
        let caller_mxid = matrix_store::ensure_matrix_user(&conn, 99, "siteadmin00000000000000000000003", T0).expect("caller mxid");
        let author_event = matrix_store::insert_timeline_event(&mut conn, "$msg1", "!chan:mylittlechart.org", 1, "m.room.message", "{}", 1000, None).expect("author sends");
        let room = matrix_store::get_room(&conn, "!chan:mylittlechart.org").expect("room").expect("exists");

        let outcome = apply_moderation_redact(&mut conn, &room, true, 99, &caller_mxid, &author_event.event_id, "$red1", Some("spam"), 2000).expect("site redact");
        let event_id = outcome.event_id.expect("a redaction always produces an event id");
        let stored = matrix_store::get_event(&conn, &event_id).expect("query").expect("event exists");
        let content: serde_json::Value = serde_json::from_str(&stored.content).expect("json content");
        assert_eq!(content["org.mylittlechart.site_moderation"], serde_json::json!(true));
        assert_eq!(content["reason"], serde_json::json!("spam"));
    }

    // ---- a non-staff caller with no room power is refused ----

    #[test]
    fn non_staff_without_power_is_refused() {
        let mut conn = test_conn();
        make_room(&conn, "!chan:mylittlechart.org", matrix_store::RoomKind::Channel, 1);
        let caller_mxid = matrix_store::ensure_matrix_user(&conn, 2, "plainuser0000000000000000000001", T0).expect("caller mxid");
        matrix_store::apply_state_event(&mut conn, "$m2", "!chan:mylittlechart.org", 2, "m.room.member", &caller_mxid, r#"{"membership":"join"}"#, 1000, T0).expect("caller joins");
        let target_mxid = matrix_store::ensure_matrix_user(&conn, 3, "target00000000000000000000000001", T0).expect("target mxid");
        matrix_store::apply_state_event(&mut conn, "$m3", "!chan:mylittlechart.org", 1, "m.room.member", &target_mxid, r#"{"membership":"join"}"#, 1100, T0).expect("target joins");
        let room = matrix_store::get_room(&conn, "!chan:mylittlechart.org").expect("room").expect("exists");

        let err = apply_moderation_membership_action(
            &mut conn,
            &room,
            false,
            2,
            &caller_mxid,
            PowerAction::Kick,
            3,
            &target_mxid,
            rooms::TargetStateRule::MustBeActiveMember,
            Membership::Leave,
            None,
            T0,
            2000,
        )
        .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN, "a non-staff caller with no room power cannot kick");
    }

    // ---- an unrecognized action name is rejected before any DB work ----

    #[test]
    fn unknown_action_is_rejected() {
        assert_eq!(ModerationAction::from_wire("frobnicate"), None);
        assert_eq!(ModerationAction::from_wire("redact_message"), Some(ModerationAction::RedactMessage));
        assert_eq!(ModerationAction::from_wire("kick_member"), Some(ModerationAction::KickMember));
        assert_eq!(ModerationAction::from_wire("ban_member"), Some(ModerationAction::BanMember));
        assert_eq!(ModerationAction::from_wire("unban_member"), Some(ModerationAction::UnbanMember));
    }
}

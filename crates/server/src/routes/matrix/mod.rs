//! Matrix Client-Server API subset — router assembly, the shared
//! [`MatrixError`] response shape, and [`client_event_json`] (the one place
//! every route formats a stored event for a client) every handler in this
//! module tree answers with. See
//! `docs/mlc/plans/messenger-proto-server-matrix-subset-2026-09-24.md` for
//! the full plan this implements; P4 (caller/device resolution, credential-
//! revoke hooks — [`auth`]) landed the foundation; P5 ([`rooms`]) adds
//! `createRoom`, membership (join/leave/invite/kick/ban/unban/forget),
//! `joined_rooms`, room state (GET/PUT), members/joined_members.
//!
//! **Naming collision note**: `routes::rooms` (existing, `routes/rooms.rs`)
//! is the unrelated shared-presets "objects/rooms" feature. The Matrix chat
//! rooms this plan adds live in `routes::matrix::rooms`, a disjoint module
//! path — do not conflate the two.
//!
//! P4 mounts `GET /_matrix/client/versions`, `GET /_matrix/client/v3/capabilities`
//! (the smallest Auth-only read in the plan's §4 table — the natural first
//! production caller for [`auth::resolve_matrix_caller`]) and the catch-all
//! `M_UNRECOGNIZED` fallback for everything else under `/_matrix/*`. P5
//! merges [`rooms::routes`] in before that fallback; P8 (`account`, private —
//! nothing outside this module needs to name it) adds account data (global +
//! per-room), tags, filters, profile, `user_directory/search`, and
//! `publicRooms`. Every other endpoint in the plan's §4 table is a later
//! piece (P6, P7, P9-P11).
//!
//! `MatrixError::not_json` is deliberately NOT built yet (a not-JSON errcode
//! has no caller until a body-parsing piece needs it) — `-D warnings`'
//! dead-code lint flags a pub constructor with zero callers anywhere in this
//! binary crate (unlike a library crate's pub API, exempt by design; see
//! `lib.rs`'s own module doc for the same rule applied to `live`). Add it
//! back the moment a real call site exists. `::limit_exceeded` (below) is no
//! longer in that category — P6's send-rate limits (plan §3.8) are its first
//! caller.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

use crate::state::AppState;

mod account;
pub mod auth;
pub mod ephemeral;
mod messaging;
mod rooms;

/// This deployment's one supported Client-Server API version (plan §1,
/// manager decision 1: v1.19, not the body's original v1.13 pin).
const SUPPORTED_VERSION: &str = "v1.19";

/// `{"errcode": "...", "error": "..."}` — the Matrix spec's own error
/// envelope, plus the two optional extra fields this server actually emits
/// (`retry_after_ms` for `M_LIMIT_EXCEEDED`, `soft_logout` for
/// `M_UNKNOWN_TOKEN`). `status` drives the HTTP status line and is never
/// serialized into the body.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct MatrixError {
    #[serde(skip)]
    pub status: StatusCode,
    pub errcode: &'static str,
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub soft_logout: Option<bool>,
}

impl MatrixError {
    fn new(status: StatusCode, errcode: &'static str, error: impl Into<String>) -> Self {
        Self { status, errcode, error: error.into(), retry_after_ms: None, soft_logout: None }
    }

    /// `M_MISSING_TOKEN` (401) — no credential (cookie session or bearer) was
    /// supplied at all.
    pub fn missing_token() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "M_MISSING_TOKEN", "Missing access token")
    }

    /// `M_UNKNOWN_TOKEN` (401), with `soft_logout: false` — a credential was
    /// supplied but does not resolve (wrong, revoked, or expired). Matrix's
    /// `soft_logout` tells the client whether a token refresh might help;
    /// this server never refreshes tokens (plan §1, manager decision 3), so
    /// it is always `false` — the client must re-authenticate from scratch.
    pub fn unknown_token() -> Self {
        Self { soft_logout: Some(false), ..Self::new(StatusCode::UNAUTHORIZED, "M_UNKNOWN_TOKEN", "Unrecognised access token") }
    }

    /// `M_FORBIDDEN` (403) — authenticated, but refused (not paid, lacks the
    /// power level for the action, room rule violated, ...).
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "M_FORBIDDEN", msg)
    }

    /// `M_NOT_FOUND` (404) — a named room/event/user does not exist.
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", msg)
    }

    /// `M_UNRECOGNIZED` (404) — the path itself is not a route this server
    /// answers (the `/_matrix/*` fallback below).
    pub fn unrecognized() -> Self {
        Self::new(StatusCode::NOT_FOUND, "M_UNRECOGNIZED", "Unrecognized request")
    }

    /// `M_BAD_JSON` (400) — the body parsed as JSON but not into the shape
    /// this endpoint expects.
    pub fn bad_json(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "M_BAD_JSON", msg)
    }

    /// `M_BAD_JSON` (405) — a write to an account-data type this server
    /// manages entirely through its own dedicated endpoint rather than raw
    /// account-data storage (`m.fully_read`, via `POST .../read_markers` —
    /// see `account::check_account_data_type_allowed`). 405 (Method Not
    /// Allowed) rather than 403/400 per this plan's own P8 brief: the type
    /// name itself is fine, it is this HTTP verb against this path for that
    /// type that is refused.
    pub fn managed_account_data_type(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::METHOD_NOT_ALLOWED, "M_BAD_JSON", msg)
    }

    /// `M_INVALID_PARAM` (400) — a path/query parameter or a JSON field's
    /// value is malformed or out of range.
    pub fn invalid_param(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", msg)
    }

    /// `M_DUPLICATE_ANNOTATION` (400) — a second identical `m.annotation`
    /// relation from the same sender ([`crate::routes::matrix`]'s own
    /// mapping of [`mylittlechart_server::matrix_store::MatrixStoreError::DuplicateAnnotation`]).
    pub fn duplicate_annotation() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "M_DUPLICATE_ANNOTATION", "Already reacted with this key")
    }

    /// `M_LIMIT_EXCEEDED` (429) — the caller is rate-limited; `retry_after_ms`
    /// tells them how long to back off (plan §3.8: P6's own per-sender
    /// daily/burst send caps are this constructor's first caller).
    pub fn limit_exceeded(retry_after_ms: u64) -> Self {
        Self { retry_after_ms: Some(retry_after_ms), ..Self::new(StatusCode::TOO_MANY_REQUESTS, "M_LIMIT_EXCEEDED", "Too many requests") }
    }

    /// `M_UNKNOWN` (500) — an internal failure with no more specific Matrix
    /// errcode (a database error, a logic bug). `msg` is shown to the caller,
    /// so it must never carry anything sensitive — callers pass a fixed
    /// string and log the real cause via `tracing::error!` themselves.
    pub fn unknown(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "M_UNKNOWN", msg)
    }

    /// The fixed internal-error shape every `spawn_blocking` join failure or
    /// otherwise-unclassified error collapses to.
    pub fn internal() -> Self {
        Self::unknown("Internal error")
    }
}

impl IntoResponse for MatrixError {
    fn into_response(self) -> Response {
        let status = self.status;
        (status, Json(self)).into_response()
    }
}

impl From<rusqlite::Error> for MatrixError {
    fn from(e: rusqlite::Error) -> Self {
        tracing::error!("DB error in a Matrix route: {}", e);
        Self::internal()
    }
}

impl From<mylittlechart_server::matrix_store::MatrixStoreError> for MatrixError {
    fn from(e: mylittlechart_server::matrix_store::MatrixStoreError) -> Self {
        use mylittlechart_server::matrix_store::MatrixStoreError as E;
        match e {
            E::Db(e) => MatrixError::from(e),
            E::Json(e) => {
                tracing::error!("Matrix store JSON error: {}", e);
                MatrixError::bad_json("Malformed event content")
            }
            E::ReservedLocalpart => MatrixError::forbidden("Reserved localpart"),
            E::DuplicateAnnotation => MatrixError::duplicate_annotation(),
            E::UnknownEventId(id) => MatrixError::not_found(format!("Unknown event: {id}")),
            E::UnknownMxid(id) => MatrixError::not_found(format!("Unknown user: {id}")),
            E::InvalidMembership(m) => MatrixError::invalid_param(format!("Invalid membership: {m}")),
            E::InvalidRelationTarget(id) => MatrixError::invalid_param(format!("Invalid relation target: {id}")),
            E::WrongRoom(id) => MatrixError::invalid_param(format!("Event is not in this room: {id}")),
            E::UnredactableEvent(t) => MatrixError::forbidden(format!("This event type cannot be redacted: {t}")),
        }
    }
}

impl From<mylittlechart_server::matrix_keys_store::MatrixKeysStoreError> for MatrixError {
    fn from(e: mylittlechart_server::matrix_keys_store::MatrixKeysStoreError) -> Self {
        use mylittlechart_server::matrix_keys_store::MatrixKeysStoreError as E;
        match e {
            E::Db(e) => MatrixError::from(e),
            E::OneTimeKeyConflict(key_id) => {
                MatrixError::invalid_param(format!("One-time key {key_id} already exists with different content"))
            }
            E::WrongBackupVersion => MatrixError::invalid_param("Not the current key-backup version"),
        }
    }
}

impl From<serde_json::Error> for MatrixError {
    fn from(e: serde_json::Error) -> Self {
        tracing::error!("JSON error in a Matrix route: {}", e);
        Self::bad_json("Malformed JSON")
    }
}

// ============================================================================
// client_event_json — the one place every route formats a stored
// `MatrixEvent` for a client (mxids, never internal `user_id`s; see the
// module doc and P5's own scope note for why this lives here rather than
// once per route module).
// ============================================================================

/// Format one stored [`mylittlechart_server::matrix_store::MatrixEvent`] the
/// way every `/_matrix/client/v3/*` response must shape it: `event_id`,
/// `type`, `sender` (mxid), `origin_server_ts`, `content`, `room_id`,
/// `state_key` (state events only), and `unsigned.age`. `unsigned` also
/// carries:
/// - `redacted_because` — the formatted redaction event, when this event has
///   been redacted (recurses one level; a redaction event redacting another
///   redaction event does not occur through this server's own write paths).
/// - `invite_room_state` — for an `m.room.member` event whose `content`
///   currently reads `membership: "invite"`, the room's stripped state
///   ([`mylittlechart_server::matrix_store::stripped_invite_state`]),
///   recomputed fresh on every call rather than stored (see that function's
///   own doc for why).
/// - `transaction_id` — only when `own_txn_id` is `Some`, i.e. the caller is
///   re-reading their own just-sent event on the SAME device that sent it;
///   Matrix never reveals a sender's own transaction id to anyone else.
pub fn client_event_json(
    conn: &rusqlite::Connection,
    event: &mylittlechart_server::matrix_store::MatrixEvent,
    own_txn_id: Option<&str>,
) -> Result<serde_json::Value, MatrixError> {
    use mylittlechart_server::matrix_store;

    let sender = matrix_store::mxid_of(conn, event.sender_user_id)?.ok_or_else(|| {
        tracing::error!("client_event_json: sender {} has no matrix_users row", event.sender_user_id);
        MatrixError::internal()
    })?;
    let content: serde_json::Value = serde_json::from_str(&event.content).unwrap_or_else(|_| serde_json::json!({}));
    let now_ms = chrono::Utc::now().timestamp_millis();
    let age = (now_ms - event.origin_server_ts).max(0);

    let mut unsigned = serde_json::json!({ "age": age });
    if let Some(redaction_event_id) = &event.redacted_by {
        if let Some(redaction_event) = matrix_store::get_event(conn, redaction_event_id)? {
            unsigned["redacted_because"] = client_event_json(conn, &redaction_event, None)?;
        }
    }
    if event.event_type == "m.room.member" {
        if let Ok(member_content) = serde_json::from_str::<serde_json::Value>(&event.content) {
            if member_content.get("membership").and_then(|v| v.as_str()) == Some("invite") {
                let stripped = matrix_store::stripped_invite_state(conn, &event.room_id, event.sender_user_id)?;
                unsigned["invite_room_state"] = serde_json::Value::Array(stripped);
            }
        }
    }
    if let Some(txn_id) = own_txn_id {
        unsigned["transaction_id"] = serde_json::Value::String(txn_id.to_string());
    }

    let mut value = serde_json::json!({
        "event_id": event.event_id,
        "type": event.event_type,
        "sender": sender,
        "origin_server_ts": event.origin_server_ts,
        "content": content,
        "room_id": event.room_id,
        "unsigned": unsigned,
    });
    if let Some(state_key) = &event.state_key {
        value["state_key"] = serde_json::Value::String(state_key.clone());
    }
    Ok(value)
}

// ============================================================================
// GET /_matrix/client/versions
// ============================================================================

async fn versions() -> impl IntoResponse {
    Json(serde_json::json!({
        "versions": [SUPPORTED_VERSION],
        "unstable_features": {},
    }))
}

// ============================================================================
// GET /_matrix/client/v3/capabilities
// ============================================================================

/// The plan §4 table's smallest Auth-only read: `m.room_versions` (this
/// deployment only ever creates room version 11 — plan §1) and
/// `m.change_password.enabled=false` (no in-app password change flow).
/// Also reports a custom-namespaced `org.mylittlechart.messenger` capability
/// (Matrix's own extension point for server-specific keys, already used
/// elsewhere in this deployment — e.g. `matrix_store`'s
/// `org.mylittlechart.legacy_dm_key` state event) so a client can tell
/// upfront whether Paid-gated writes (createRoom, invite, ...) will succeed,
/// without a wasted round trip.
async fn capabilities(headers: axum::http::HeaderMap, axum::extract::State(state): axum::extract::State<Arc<AppState>>) -> Result<impl IntoResponse, MatrixError> {
    let caller = auth::resolve_matrix_caller(&headers, &state).await?;

    let user_id = caller.user_id;
    let state_for_paid = state.clone();
    let is_paid_messenger = tokio::task::spawn_blocking(move || -> Result<bool, MatrixError> {
        let cp = state_for_paid.control_plane();
        let is_paid = {
            let identity_conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
            crate::db::user_is_paid(&identity_conn, user_id)?
        };
        let social_conn = cp.social_conn();
        Ok(auth::is_messenger_paid(&social_conn, user_id, is_paid))
    })
    .await
    .map_err(|_| MatrixError::internal())??;

    let mut capabilities = serde_json::json!({
        "m.room_versions": {
            "default": mylittlechart_server::matrix_store::MATRIX_ROOM_VERSION,
            "available": { mylittlechart_server::matrix_store::MATRIX_ROOM_VERSION: "stable" },
        },
        "m.change_password": { "enabled": false },
    });
    if auth::require_paid_matrix(is_paid_messenger).is_ok() {
        capabilities["org.mylittlechart.messenger"] = serde_json::json!({ "paid": true });
    }

    Ok(Json(serde_json::json!({ "capabilities": capabilities })))
}

// ============================================================================
// Fallback: any other unmatched `/_matrix/*` path
// ============================================================================

async fn matrix_unrecognized() -> MatrixError {
    MatrixError::unrecognized()
}

/// Build the `/_matrix` sub-router — nested at that prefix by `main.rs`
/// (`.nest("/_matrix", …)`, mirroring how `control_api_router` is nested at
/// `/api`). P4: `GET /client/versions`, `GET /client/v3/capabilities`, and
/// the `M_UNRECOGNIZED` fallback; P5 ([`rooms`]) adds room/membership/state
/// routes; P6 ([`messaging`]) adds send/messages/event/redact/relations;
/// P7 ([`ephemeral`]) adds typing/receipt/read_markers; P8-P11 add the rest
/// of plan §4's endpoint table here.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/client/versions", get(versions))
        .route("/client/v3/capabilities", get(capabilities))
        .merge(rooms::routes())
        .merge(messaging::routes())
        .merge(ephemeral::routes())
        .merge(account::routes())
        .fallback(matrix_unrecognized)
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn matrix_error_serializes_errcode_and_error() {
        let err = MatrixError::not_found("no such room");
        let value = serde_json::to_value(&err).expect("serialize");
        assert_eq!(value, serde_json::json!({ "errcode": "M_NOT_FOUND", "error": "no such room" }));
    }

    #[test]
    fn matrix_error_unknown_token_carries_soft_logout_false() {
        let err = MatrixError::unknown_token();
        let value = serde_json::to_value(&err).expect("serialize");
        assert_eq!(
            value,
            serde_json::json!({ "errcode": "M_UNKNOWN_TOKEN", "error": "Unrecognised access token", "soft_logout": false })
        );
    }

    #[tokio::test]
    async fn versions_reports_the_pinned_spec_version() {
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        let resp = router(test_state())
            .oneshot(Request::get("/client/versions").body(Body::empty()).expect("build request"))
            .await
            .expect("Router::call is infallible");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), usize::MAX).await.expect("read body");
        let value: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(value, serde_json::json!({ "versions": ["v1.19"], "unstable_features": {} }));
    }

    #[tokio::test]
    async fn unrecognized_matrix_path_returns_m_unrecognized() {
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        let resp = router(test_state())
            .oneshot(Request::get("/client/v3/nonexistent").body(Body::empty()).expect("build request"))
            .await
            .expect("Router::call is infallible");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let body = to_bytes(resp.into_body(), usize::MAX).await.expect("read body");
        let value: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(value, serde_json::json!({ "errcode": "M_UNRECOGNIZED", "error": "Unrecognized request" }));
    }
}

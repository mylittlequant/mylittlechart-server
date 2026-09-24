//! Matrix Client-Server API subset — router assembly and the shared
//! [`MatrixError`] response shape every handler in this module tree answers
//! with. See
//! `docs/mlc/plans/messenger-proto-server-matrix-subset-2026-09-24.md` for
//! the full plan this implements; this piece (P4) lands the foundation
//! every other `/_matrix/client/v3/*` route (P5-P10) builds on: caller/
//! device resolution and the credential-revoke hooks live in [`auth`].
//!
//! **Naming collision note**: `routes::rooms` (existing, `routes/rooms.rs`)
//! is the unrelated shared-presets "objects/rooms" feature. The Matrix chat
//! rooms this plan adds live in `routes::matrix::rooms` (a later piece), a
//! disjoint module path — do not conflate the two.
//!
//! P4 mounts `GET /_matrix/client/versions`, `GET /_matrix/client/v3/capabilities`
//! (the smallest Auth-only read in the plan's §4 table — the natural first
//! production caller for [`auth::resolve_matrix_caller`], since every other
//! endpoint needing it is a later piece), and the catch-all `M_UNRECOGNIZED`
//! fallback for everything else under `/_matrix/*`. Every other endpoint in
//! the plan's §4 table is a later piece (P5-P11).
//!
//! `MatrixError::not_json`/`::limit_exceeded` are deliberately NOT built yet
//! (`retry_after_ms`/a not-JSON errcode have no caller until a body-parsing
//! or rate-limit-integration piece needs them) — `-D warnings`' dead-code
//! lint flags a pub constructor with zero callers anywhere in this binary
//! crate (unlike a library crate's pub API, exempt by design; see
//! `lib.rs`'s own module doc for the same rule applied to `live`). Add them
//! back the moment a real call site exists.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

use crate::state::AppState;

pub mod auth;

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
/// the `M_UNRECOGNIZED` fallback; P5-P11 add the rest of plan §4's endpoint
/// table here.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/client/versions", get(versions))
        .route("/client/v3/capabilities", get(capabilities))
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

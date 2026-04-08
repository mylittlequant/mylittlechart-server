//! Agent API key management routes.
//!
//! Two flows are supported:
//!
//! **Manual generation** (user dashboard):
//!   1. Logged-in user calls `POST /api/auth/keys/generate` → receives raw key shown once.
//!
//! **Agent-initiated flow** (like device-code flow but for agent keys):
//!   1. Agent calls `POST /api/auth/agent-key/request` → receives `{ code, confirm_url }`.
//!   2. User opens `confirm_url` in browser, sees request info via `GET /api/auth/agent-key/info?code=X`.
//!   3. User approves: `POST /api/auth/agent-key/confirm` → raw key stored server-side.
//!   4. Agent polls `GET /api/auth/agent-key/poll?code=X` → gets `{ status: "confirmed", raw_key }` once.
//!
//! **Key management**:
//!   - `GET /api/auth/keys` — list keys (cookie session for dashboard, Bearer token for terminal sync)
//!   - `DELETE /api/auth/keys/{hash_prefix}` — revoke a key by prefix (cookie session required)

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use crate::auth::{extract_bearer, extract_session_id, extract_ua_hash, hash_token};
use crate::build_attest;
use crate::db::{AgentKeyRow, DeleteKeyOutcome, KeySyncEntryRow};
use crate::models::types::ErrorResponse;
use crate::state::AppState;

// ============================================================================
// Shared types
// ============================================================================

fn default_permissions() -> Vec<String> {
    vec![
        "read_bars",
        "read_indicators",
        "read_viewport",
        "read_config",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

/// Allowlist of valid permission strings.
const VALID_PERMISSIONS: &[&str] = &[
    "read_bars",
    "read_indicators",
    "read_viewport",
    "read_config",
    "execute_trades",
    "manage_alerts",
];

/// Validate that permissions are within the allowlist and not too many.
fn validate_permissions(permissions: &[String]) -> Result<(), String> {
    if permissions.len() > 10 {
        return Err("Too many permissions (max 10)".to_string());
    }
    for perm in permissions {
        if !VALID_PERMISSIONS.contains(&perm.as_str()) {
            return Err(format!("Unknown permission: {}", perm));
        }
    }
    Ok(())
}

#[derive(serde::Deserialize)]
pub struct GenerateKeyRequest {
    pub label: String,
    #[serde(default = "default_permissions")]
    pub permissions: Vec<String>,
}

#[derive(serde::Deserialize)]
pub struct AgentKeyRequestBody {
    #[serde(default)]
    pub label: String,
    #[serde(default = "default_permissions")]
    pub permissions: Vec<String>,
}

#[derive(serde::Deserialize)]
pub struct PollAgentKeyQuery {
    pub code: String,
}

#[derive(serde::Deserialize)]
pub struct ConfirmAgentKeyBody {
    pub code: String,
    #[serde(default)]
    pub label: String,
    #[serde(default = "default_permissions")]
    pub permissions: Vec<String>,
}

#[derive(serde::Deserialize)]
pub struct ListKeysQuery {
    #[serde(default)]
    pub format: String,
}

// ============================================================================
// POST /api/auth/keys/generate — manual key generation (cookie session required)
// ============================================================================

/// Generate an agent API key for the currently logged-in user.
///
/// Requires a valid `session_id` cookie. Returns the raw key once — it is never
/// stored in plaintext and cannot be retrieved again.
pub async fn generate_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<GenerateKeyRequest>,
) -> Response {
    if let Err(resp) = build_attest::check_build_attestation(
        &headers,
        &state.build_attest_pubkeys,
        state.build_attest_enforce,
        state.build_attest_max_age_secs,
    ) {
        return resp;
    }

    let session_id = match extract_session_id(&headers) {
        Some(s) => s,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new("No session cookie — please log in")),
            )
                .into_response();
        }
    };

    if body.label.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("label must not be empty")),
        )
            .into_response();
    }
    if body.label.len() > 128 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Label too long (max 128 chars)")),
        )
            .into_response();
    }
    if let Err(e) = validate_permissions(&body.permissions) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(&e)),
        )
            .into_response();
    }

    let ua_hash = extract_ua_hash(&headers);
    let label = body.label.trim().to_owned();
    let permissions_json = match serde_json::to_string(&body.permissions) {
        Ok(j) => j,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("Invalid permissions")),
            )
                .into_response();
        }
    };

    let now = chrono::Utc::now().to_rfc3339();
    let expires_at = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<GenerateOutcome> {
        let conn = state.db.lock().unwrap_or_else(|e| e.into_inner());

        let user_id = match crate::db::resolve_web_session(&conn, &session_id, &ua_hash)? {
            Some(id) => id,
            None => return Ok(GenerateOutcome::Unauthorized),
        };

        let raw_key =
            crate::db::create_agent_key(&conn, user_id, &label, &permissions_json, "user", &now, &expires_at)?;

        Ok(GenerateOutcome::Created {
            raw_key,
            label,
            permissions_json,
            expires_at,
        })
    })
    .await;

    match result {
        Ok(Ok(GenerateOutcome::Created {
            raw_key,
            label,
            permissions_json,
            expires_at,
        })) => Json(serde_json::json!({
            "raw_key": raw_key,
            "label": label,
            "permissions": serde_json::from_str::<serde_json::Value>(&permissions_json).unwrap_or(serde_json::Value::Array(vec![])),
            "expires_at": expires_at,
        }))
        .into_response(),
        Ok(Ok(GenerateOutcome::Unauthorized)) => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Invalid or expired session")),
        )
            .into_response(),
        Ok(Err(e)) => {
            // The create_agent_key function returns SQLITE_FULL when the limit is exceeded.
            let msg = e.to_string();
            if msg.contains("limit: 20") || msg.contains("already has") {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(ErrorResponse::new("Key limit reached (max 20 active keys per user)")),
                )
                    .into_response();
            }
            tracing::error!("DB error generating agent key: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

enum GenerateOutcome {
    Created {
        raw_key: String,
        label: String,
        permissions_json: String,
        expires_at: String,
    },
    Unauthorized,
}

// ============================================================================
// POST /api/auth/agent-key/request — agent requests a key (no auth)
// ============================================================================

/// Agent initiates a key request without any authentication.
///
/// Returns a short code and a confirmation URL for the user to open in their browser.
/// The request expires in 10 minutes.
pub async fn request_agent_key(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AgentKeyRequestBody>,
) -> Response {
    // Label length limit (even if using default "Agent key", user-supplied labels must be bounded).
    if body.label.len() > 128 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Label too long (max 128 chars)")),
        )
            .into_response();
    }
    if let Err(e) = validate_permissions(&body.permissions) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(&e)),
        )
            .into_response();
    }

    let label = if body.label.trim().is_empty() {
        "Agent key".to_owned()
    } else {
        body.label.trim().to_owned()
    };

    let permissions_json = match serde_json::to_string(&body.permissions) {
        Ok(j) => j,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("Invalid permissions")),
            )
                .into_response();
        }
    };

    let now = chrono::Utc::now().to_rfc3339();
    let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.db.lock().unwrap_or_else(|e| e.into_inner());
        let _ = crate::db::cleanup_agent_key_requests(&conn);

        // Global throttle: prevent request floods without per-IP middleware.
        let pending_count = crate::db::count_pending_agent_key_requests(&conn)
            .unwrap_or(0);
        if pending_count >= 20 {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
                Some("rate_limit: too many pending agent key requests".to_string()),
            ));
        }

        crate::db::create_agent_key_request(&conn, &label, &permissions_json, &now, &expires_at)
    })
    .await;

    match result {
        Ok(Ok(code)) => {
            let confirm_url = format!(
                "https://mylittlechart.org/keys/confirm?code={}",
                code
            );
            Json(serde_json::json!({
                "code": code,
                "confirm_url": confirm_url,
                "expires_in": 600,
            }))
            .into_response()
        }
        Ok(Err(e)) => {
            let msg = e.to_string();
            if msg.contains("rate_limit:") {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(ErrorResponse::new("Too many pending agent key requests — please try again later")),
                )
                    .into_response();
            }
            tracing::error!("DB error creating agent key request: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

// ============================================================================
// GET /api/auth/agent-key/poll?code=X — agent polls (no auth)
// ============================================================================

/// Agent polls for the result of a key request.
///
/// Responses:
/// - 202 `{ "status": "pending" }` — user has not confirmed yet.
/// - 200 `{ "status": "confirmed", "raw_key": "..." }` — approved; key delivered exactly once.
/// - 410 `{ "status": "expired" }` — code expired, denied, or already claimed.
pub async fn poll_agent_key(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PollAgentKeyQuery>,
) -> Response {
    let code = query.code.to_uppercase();

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<(String, Option<String>)>> {
        let conn = state.db.lock().unwrap_or_else(|e| e.into_inner());
        let poll_result = crate::db::poll_agent_key_request(&conn, &code)?;
        // After delivering the raw key to the agent (confirmed → claimed transition),
        // immediately null out claimed_key so the plaintext is not retained server-side.
        if let Some((ref status, Some(_))) = poll_result {
            if status == "confirmed" {
                let _ = crate::db::clear_claimed_key(&conn, &code);
            }
        }
        Ok(poll_result)
    })
    .await;

    match result {
        Ok(Ok(Some((status, raw_key)))) => match status.as_str() {
            "confirmed" => {
                let key = raw_key.unwrap_or_default();
                Json(serde_json::json!({
                    "status": "confirmed",
                    "raw_key": key,
                }))
                .into_response()
            }
            "pending" => (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({ "status": "pending" })),
            )
                .into_response(),
            "denied" => (
                StatusCode::GONE,
                Json(serde_json::json!({ "status": "denied" })),
            )
                .into_response(),
            _ => (
                StatusCode::GONE,
                Json(serde_json::json!({ "status": "expired" })),
            )
                .into_response(),
        },
        Ok(Ok(None)) => (
            StatusCode::GONE,
            Json(serde_json::json!({ "status": "expired" })),
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error polling agent key request: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

// ============================================================================
// POST /api/auth/agent-key/confirm — user confirms from browser (cookie session required)
// ============================================================================

/// Confirm an agent key request from the logged-in web user.
///
/// Requires a valid `session_id` cookie. Generates a raw key, stores its hash, and
/// makes it available for the agent to pick up via the poll endpoint.
/// Returns the raw key once for display on the confirmation page.
pub async fn confirm_agent_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ConfirmAgentKeyBody>,
) -> Response {
    if let Err(resp) = build_attest::check_build_attestation(
        &headers,
        &state.build_attest_pubkeys,
        state.build_attest_enforce,
        state.build_attest_max_age_secs,
    ) {
        return resp;
    }

    let session_id = match extract_session_id(&headers) {
        Some(s) => s,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new("No session cookie — please log in")),
            )
                .into_response();
        }
    };

    let code = body.code.to_uppercase();

    // Label length limit.
    if body.label.len() > 128 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Label too long (max 128 chars)")),
        )
            .into_response();
    }
    if let Err(e) = validate_permissions(&body.permissions) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(&e)),
        )
            .into_response();
    }

    let label = if body.label.trim().is_empty() {
        "Agent key".to_owned()
    } else {
        body.label.trim().to_owned()
    };

    let permissions_json = match serde_json::to_string(&body.permissions) {
        Ok(j) => j,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("Invalid permissions")),
            )
                .into_response();
        }
    };

    let ua_hash = extract_ua_hash(&headers);
    let now = chrono::Utc::now().to_rfc3339();
    let key_expires_at = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();

    let result =
        tokio::task::spawn_blocking(move || -> rusqlite::Result<ConfirmKeyOutcome> {
            let conn = state.db.lock().unwrap_or_else(|e| e.into_inner());

            let user_id = match crate::db::resolve_web_session(&conn, &session_id, &ua_hash)? {
                Some(id) => id,
                None => return Ok(ConfirmKeyOutcome::Unauthorized),
            };

            // Check the request exists before trying to confirm.
            let req = match crate::db::get_agent_key_request(&conn, &code)? {
                Some(r) => r,
                None => return Ok(ConfirmKeyOutcome::NotFound),
            };

            if req.expires_at < now {
                return Ok(ConfirmKeyOutcome::Expired);
            }

            if req.status != "pending" {
                return Ok(ConfirmKeyOutcome::AlreadyUsed);
            }

            let raw_key = crate::db::confirm_agent_key_request(
                &conn,
                &code,
                user_id,
                &label,
                &permissions_json,
                &now,
                &key_expires_at,
            )?;

            Ok(ConfirmKeyOutcome::Confirmed {
                raw_key,
                label,
                permissions_json,
            })
        })
        .await;

    match result {
        Ok(Ok(ConfirmKeyOutcome::Confirmed {
            raw_key,
            label,
            permissions_json,
        })) => Json(serde_json::json!({
            "raw_key": raw_key,
            "label": label,
            "permissions": serde_json::from_str::<serde_json::Value>(&permissions_json).unwrap_or(serde_json::Value::Array(vec![])),
        }))
        .into_response(),
        Ok(Ok(ConfirmKeyOutcome::Unauthorized)) => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Invalid or expired session")),
        )
            .into_response(),
        Ok(Ok(ConfirmKeyOutcome::NotFound)) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new("Agent key request not found")),
        )
            .into_response(),
        Ok(Ok(ConfirmKeyOutcome::Expired)) => (
            StatusCode::GONE,
            Json(ErrorResponse::new("Agent key request has expired")),
        )
            .into_response(),
        Ok(Ok(ConfirmKeyOutcome::AlreadyUsed)) => (
            StatusCode::CONFLICT,
            Json(ErrorResponse::new("Agent key request already confirmed or denied")),
        )
            .into_response(),
        Ok(Err(e)) => {
            let msg = e.to_string();
            if msg.contains("not found, not pending, or expired") {
                return (
                    StatusCode::GONE,
                    Json(ErrorResponse::new("Agent key request has expired or is not pending")),
                )
                    .into_response();
            }
            tracing::error!("DB error confirming agent key request: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

enum ConfirmKeyOutcome {
    Confirmed {
        raw_key: String,
        label: String,
        permissions_json: String,
    },
    Unauthorized,
    NotFound,
    Expired,
    AlreadyUsed,
}

// ============================================================================
// POST /api/auth/agent-key/deny — user denies from browser (cookie session required)
// ============================================================================

#[derive(serde::Deserialize)]
pub struct DenyAgentKeyBody {
    pub code: String,
}

/// Deny an agent key request from the logged-in web user.
///
/// Requires a valid `session_id` cookie. Sets the request status to "denied",
/// making it permanently unavailable. Returns 404 if the code is not found
/// or the request has already been processed.
pub async fn deny_agent_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<DenyAgentKeyBody>,
) -> Response {
    if let Err(resp) = build_attest::check_build_attestation(
        &headers,
        &state.build_attest_pubkeys,
        state.build_attest_enforce,
        state.build_attest_max_age_secs,
    ) {
        return resp;
    }

    let session_id = match extract_session_id(&headers) {
        Some(s) => s,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new("No session cookie — please log in")),
            )
                .into_response();
        }
    };

    let code = body.code.to_uppercase();
    let ua_hash = extract_ua_hash(&headers);

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<DenyKeyOutcome> {
        let conn = state.db.lock().unwrap_or_else(|e| e.into_inner());

        let user_id = match crate::db::resolve_web_session(&conn, &session_id, &ua_hash)? {
            Some(id) => id,
            None => return Ok(DenyKeyOutcome::Unauthorized),
        };

        let found = crate::db::deny_agent_key_request(&conn, &code, user_id)?;
        if found {
            Ok(DenyKeyOutcome::Denied)
        } else {
            Ok(DenyKeyOutcome::NotFound)
        }
    })
    .await;

    match result {
        Ok(Ok(DenyKeyOutcome::Denied)) => {
            Json(serde_json::json!({ "denied": true })).into_response()
        }
        Ok(Ok(DenyKeyOutcome::NotFound)) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new("Agent key request not found or already processed")),
        )
            .into_response(),
        Ok(Ok(DenyKeyOutcome::Unauthorized)) => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Invalid or expired session")),
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error denying agent key request: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

enum DenyKeyOutcome {
    Denied,
    NotFound,
    Unauthorized,
}

// ============================================================================
// GET /api/auth/agent-key/info?code=X — get request info for confirmation page
//   (cookie session required)
// ============================================================================

/// Return info about a pending agent key request for display on the confirmation page.
///
/// Requires a valid `session_id` cookie. Only returns data if the request is still
/// pending — does not leak information about confirmed or claimed requests.
pub async fn get_agent_key_info(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<PollAgentKeyQuery>,
) -> Response {
    if let Err(resp) = build_attest::check_build_attestation(
        &headers,
        &state.build_attest_pubkeys,
        state.build_attest_enforce,
        state.build_attest_max_age_secs,
    ) {
        return resp;
    }

    let session_id = match extract_session_id(&headers) {
        Some(s) => s,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new("No session cookie — please log in")),
            )
                .into_response();
        }
    };

    let code = query.code.to_uppercase();
    let ua_hash = extract_ua_hash(&headers);

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<InfoOutcome> {
        let conn = state.db.lock().unwrap_or_else(|e| e.into_inner());

        // Verify session.
        match crate::db::resolve_web_session(&conn, &session_id, &ua_hash)? {
            Some(_) => {}
            None => return Ok(InfoOutcome::Unauthorized),
        };

        let req = match crate::db::get_agent_key_request(&conn, &code)? {
            Some(r) => r,
            None => return Ok(InfoOutcome::NotFound),
        };

        // Only expose pending requests — do not reveal confirmed/claimed/denied status
        // to avoid leaking key delivery information.
        if req.status != "pending" {
            return Ok(InfoOutcome::NotFound);
        }

        Ok(InfoOutcome::Found(req))
    })
    .await;

    match result {
        Ok(Ok(InfoOutcome::Found(req))) => {
            let perms: serde_json::Value = serde_json::from_str(&req.permissions)
                .unwrap_or(serde_json::Value::Array(vec![]));
            Json(serde_json::json!({
                "code": req.code,
                "label": req.label,
                "permissions": perms,
                "created_at": req.created_at,
                "expires_at": req.expires_at,
                "status": req.status,
            }))
            .into_response()
        }
        Ok(Ok(InfoOutcome::Unauthorized)) => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Invalid or expired session")),
        )
            .into_response(),
        Ok(Ok(InfoOutcome::NotFound)) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new("Agent key request not found or not pending")),
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error fetching agent key request info: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

enum InfoOutcome {
    Found(crate::db::AgentKeyRequestRow),
    Unauthorized,
    NotFound,
}

// ============================================================================
// GET /api/auth/keys[?format=sync] — list keys (cookie session or Bearer token)
// ============================================================================

/// List active agent keys for the authenticated user.
///
/// Auth: cookie session (dashboard) OR Bearer token (terminal sync).
/// Format: default returns dashboard view (hash_prefix + metadata);
///         `?format=sync` returns full token_hash list for local validation.
pub async fn list_keys(
    State(state): State<Arc<AppState>>,
    uri: Uri,
    headers: HeaderMap,
    Query(query): Query<ListKeysQuery>,
) -> Response {
    if let Err(resp) = build_attest::check_build_attestation(
        &headers,
        &state.build_attest_pubkeys,
        state.build_attest_enforce,
        state.build_attest_max_age_secs,
    ) {
        return resp;
    }

    // Determine auth method.
    let session_id = extract_session_id(&headers);
    let ua_hash = extract_ua_hash(&headers);
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| extract_bearer(Some(v)))
        .map(|s| s.to_owned());

    // If this is a Bearer-authenticated request, optionally verify HMAC signature.
    // GET requests have no body, so we sign against an empty payload.
    if let Some(ref raw_token) = bearer {
        if session_id.is_none() {
            if let Err(resp) = check_agent_hmac(&headers, raw_token, uri.path(), b"") {
                return resp;
            }
        }
    }

    let want_sync = query.format == "sync";

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<ListOutcome> {
        let conn = state.db.lock().unwrap_or_else(|e| e.into_inner());

        // Resolve user_id — try cookie first, then Bearer.
        let user_id = if let Some(sid) = session_id {
            crate::db::resolve_web_session(&conn, &sid, &ua_hash)?
        } else if let Some(raw_token) = bearer {
            let token_hash = hash_token(&raw_token);
            crate::db::resolve_token_hash_with_expiry(&conn, &token_hash)?
        } else {
            None
        };

        let user_id = match user_id {
            Some(id) => id,
            None => return Ok(ListOutcome::Unauthorized),
        };

        if want_sync {
            let entries = crate::db::list_key_hashes_for_sync(&conn, user_id)?;
            Ok(ListOutcome::Sync(entries))
        } else {
            let keys = crate::db::list_keys_for_user(&conn, user_id)?;
            Ok(ListOutcome::Dashboard(keys))
        }
    })
    .await;

    match result {
        Ok(Ok(ListOutcome::Dashboard(keys))) => {
            let json_keys: Vec<serde_json::Value> = keys
                .iter()
                .map(|k| {
                    let perms: serde_json::Value = serde_json::from_str(&k.permissions)
                        .unwrap_or(serde_json::Value::Array(vec![]));
                    serde_json::json!({
                        "hash_prefix": k.hash_prefix,
                        "label": k.label,
                        "permissions": perms,
                        "initiated_by": k.initiated_by,
                        "created_at": k.created_at,
                        "expires_at": k.expires_at,
                        "last_used_at": k.last_used_at,
                        "last_ip": k.last_ip,
                    })
                })
                .collect();
            Json(serde_json::json!({ "keys": json_keys })).into_response()
        }
        Ok(Ok(ListOutcome::Sync(entries))) => {
            let json_entries: Vec<serde_json::Value> = entries
                .iter()
                .map(|e| {
                    let perms: serde_json::Value = serde_json::from_str(&e.permissions)
                        .unwrap_or(serde_json::Value::Array(vec![]));
                    serde_json::json!({
                        "token_hash": e.token_hash,
                        "label": e.label,
                        "permissions": perms,
                        "expires_at": e.expires_at,
                    })
                })
                .collect();
            Json(serde_json::json!({ "keys": json_entries })).into_response()
        }
        Ok(Ok(ListOutcome::Unauthorized)) => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Authentication required — provide a session cookie or Bearer token")),
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error listing agent keys: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

enum ListOutcome {
    Dashboard(Vec<AgentKeyRow>),
    Sync(Vec<KeySyncEntryRow>),
    Unauthorized,
}

// ============================================================================
// DELETE /api/auth/keys/{hash_prefix} — revoke a key (cookie session required)
// ============================================================================

/// Revoke (delete) an agent key by its hash prefix.
///
/// Requires a valid `session_id` cookie. The prefix must uniquely identify one key
/// for this user. Returns 409 if the prefix is ambiguous (too short).
pub async fn revoke_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(hash_prefix): Path<String>,
) -> Response {
    if let Err(resp) = build_attest::check_build_attestation(
        &headers,
        &state.build_attest_pubkeys,
        state.build_attest_enforce,
        state.build_attest_max_age_secs,
    ) {
        return resp;
    }

    let session_id = match extract_session_id(&headers) {
        Some(s) => s,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new("No session cookie — please log in")),
            )
                .into_response();
        }
    };

    if hash_prefix.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("hash_prefix must be at least 8 characters")),
        )
            .into_response();
    }

    let ua_hash = extract_ua_hash(&headers);

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<RevokeOutcome> {
        let conn = state.db.lock().unwrap_or_else(|e| e.into_inner());

        let user_id = match crate::db::resolve_web_session(&conn, &session_id, &ua_hash)? {
            Some(id) => id,
            None => return Ok(RevokeOutcome::Unauthorized),
        };

        let outcome = crate::db::delete_key_by_prefix(&conn, user_id, &hash_prefix)?;
        Ok(RevokeOutcome::Done(outcome))
    })
    .await;

    match result {
        Ok(Ok(RevokeOutcome::Done(DeleteKeyOutcome::Ok))) => {
            Json(serde_json::json!({ "deleted": true })).into_response()
        }
        Ok(Ok(RevokeOutcome::Done(DeleteKeyOutcome::NotFound))) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new("Key not found")),
        )
            .into_response(),
        Ok(Ok(RevokeOutcome::Done(DeleteKeyOutcome::AmbiguousPrefix))) => (
            StatusCode::CONFLICT,
            Json(ErrorResponse::new(
                "Prefix matches multiple keys — provide more characters",
            )),
        )
            .into_response(),
        Ok(Ok(RevokeOutcome::Unauthorized)) => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Invalid or expired session")),
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error revoking agent key: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

enum RevokeOutcome {
    Done(DeleteKeyOutcome),
    Unauthorized,
}

// ============================================================================
// HMAC signature verification for agent API requests
// ============================================================================

/// Check HMAC signature headers on an agent request.
///
/// - Both `X-Nemo-Timestamp` and `X-Nemo-Signature` present → verify; return `Err` response if invalid.
/// - Neither header present → allow (backward compatible; Bearer token alone is sufficient).
/// - Exactly one header present → reject as malformed.
///
/// The `raw_api_key` is the raw Bearer token value (before hashing). This is the
/// HMAC key used by the client to sign the request.
fn check_agent_hmac(
    headers: &HeaderMap,
    raw_api_key: &str,
    path: &str,
    body: &[u8],
) -> Result<(), Response> {
    let ts_header = headers
        .get("X-Nemo-Timestamp")
        .and_then(|v| v.to_str().ok());
    let sig_header = headers
        .get("X-Nemo-Signature")
        .and_then(|v| v.to_str().ok());

    match (ts_header, sig_header) {
        (Some(ts), Some(sig)) => {
            if verify_agent_hmac(raw_api_key, ts, path, body, sig) {
                Ok(())
            } else {
                Err((
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse::new("Invalid or expired request signature")),
                )
                    .into_response())
            }
        }
        (None, None) => {
            // No HMAC headers — Bearer token alone is sufficient.
            Ok(())
        }
        _ => {
            // Exactly one header is present — treat as malformed.
            Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(
                    "Malformed request: both X-Nemo-Timestamp and X-Nemo-Signature must be provided together",
                )),
            )
                .into_response())
        }
    }
}

/// Verify an HMAC-SHA256 request signature sent by an agent client.
///
/// The agent must send two headers with every protected request:
/// - `X-Nemo-Timestamp`: current Unix timestamp in seconds (string)
/// - `X-Nemo-Signature`: lowercase hex-encoded HMAC-SHA256 of the canonical message
///
/// The canonical message is:
/// ```text
/// {timestamp}:{path}:{sha256_hex_of_body}
/// ```
///
/// Where `sha256_hex_of_body` is the lowercase hex-encoded SHA-256 digest of
/// the raw request body bytes (empty string `""` for GET requests with no body).
///
/// Returns `true` if the signature is valid and the timestamp is within ±5 minutes
/// of the server clock. Returns `false` on any validation failure.
///
/// # Example
///
/// ```rust,ignore
/// // In a route handler:
/// let ts  = headers.get("X-Nemo-Timestamp").and_then(|v| v.to_str().ok()).unwrap_or("");
/// let sig = headers.get("X-Nemo-Signature").and_then(|v| v.to_str().ok()).unwrap_or("");
/// if !verify_agent_hmac(&raw_api_key, ts, req.uri().path(), &body_bytes, sig) {
///     return (StatusCode::UNAUTHORIZED, "invalid signature").into_response();
/// }
/// ```
pub fn verify_agent_hmac(
    api_key: &str,
    timestamp: &str,
    path: &str,
    body: &[u8],
    signature: &str,
) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    // Reject requests with a stale or future timestamp (replay protection).
    let ts = match timestamp.parse::<i64>() {
        Ok(t) => t,
        Err(_) => return false,
    };
    let now = chrono::Utc::now().timestamp();
    if (now - ts).abs() > 300 {
        return false;
    }

    // Build canonical message: "{timestamp}:{path}:{hex(sha256(body))}"
    let body_hash = hex::encode(Sha256::digest(body));
    let message = format!("{}:{}:{}", timestamp, path, body_hash);

    // Compute expected HMAC.
    let mut mac = match Hmac::<Sha256>::new_from_slice(api_key.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(message.as_bytes());

    // Decode the provided hex signature and compare in constant time.
    match hex::decode(signature) {
        Ok(sig_bytes) => mac.verify_slice(&sig_bytes).is_ok(),
        Err(_) => false,
    }
}

// ============================================================================
// PATCH /api/auth/keys/usage — terminal reports when API keys were last used
// ============================================================================

#[derive(serde::Deserialize)]
pub struct KeyUsageEntry {
    pub hash_prefix: String,
    pub last_ip: String,
}

#[derive(serde::Deserialize)]
pub struct UpdateKeyUsageBody {
    pub usage: Vec<KeyUsageEntry>,
}

/// Report last-used information for one or more agent keys.
///
/// Requires a Bearer device token (terminal sync auth). Accepts up to 50 entries,
/// each with a 6–12 character alphanumeric `hash_prefix` and a `last_ip` of at
/// most 45 characters. Returns the count of rows updated in the database.
pub async fn update_key_usage(
    State(state): State<Arc<AppState>>,
    uri: Uri,
    headers: HeaderMap,
    body_bytes: Bytes,
) -> Response {
    // Parse body from raw bytes (needed for HMAC verification over the request body).
    let body: UpdateKeyUsageBody = match serde_json::from_slice(&body_bytes) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("Invalid JSON body")),
            )
                .into_response();
        }
    };

    // Require Bearer token auth (device token).
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| extract_bearer(Some(v)))
        .map(|s| s.to_owned());

    let raw_token = match bearer {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new("Bearer token required")),
            )
                .into_response();
        }
    };

    // Optionally verify HMAC signature over the raw request body.
    if let Err(resp) = check_agent_hmac(&headers, &raw_token, uri.path(), &body_bytes) {
        return resp;
    }

    // Validate entry count.
    if body.usage.len() > 50 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Too many entries (max 50)")),
        )
            .into_response();
    }

    // Validate each entry.
    for entry in &body.usage {
        let len = entry.hash_prefix.len();
        if len < 6 || len > 12 {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(
                    "hash_prefix must be 6–12 characters",
                )),
            )
                .into_response();
        }
        if !entry.hash_prefix.chars().all(|c| c.is_ascii_alphanumeric()) {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("hash_prefix must be alphanumeric")),
            )
                .into_response();
        }
        if entry.last_ip.len() > 45 {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("last_ip too long (max 45 chars)")),
            )
                .into_response();
        }
    }

    // Collect validated updates before moving into spawn_blocking.
    let updates: Vec<(String, String)> = body
        .usage
        .into_iter()
        .map(|e| (e.hash_prefix, e.last_ip))
        .collect();

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<usize>> {
        let conn = state.db.lock().unwrap_or_else(|e| e.into_inner());

        let token_hash = hash_token(&raw_token);
        let user_id = match crate::db::resolve_token_hash_with_expiry(&conn, &token_hash)? {
            Some(id) => id,
            None => return Ok(None),
        };

        let updated = crate::db::batch_update_key_usage(&conn, user_id, &updates)?;
        Ok(Some(updated))
    })
    .await;

    match result {
        Ok(Ok(Some(updated))) => Json(serde_json::json!({ "updated": updated })).into_response(),
        Ok(Ok(None)) => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Invalid or expired token")),
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error updating key usage: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

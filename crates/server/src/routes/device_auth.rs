//! Device authorization flow — allows a desktop app to authenticate via a web browser.
//!
//! Flow:
//!   1. Desktop calls POST /api/auth/device-code with its device_id.
//!      Server returns a short human-readable code (e.g. "AB12CD34") valid for 10 minutes.
//!   2. User opens mylittlechart.org, logs in via OAuth (receives a web session cookie).
//!   3. Logged-in web user calls POST /api/auth/confirm with the code.
//!      Server links the code to the user account and marks it 'confirmed'.
//!   4. Desktop polls GET /api/auth/poll?code=AB12CD34.
//!      Once confirmed, server issues an auth token, marks code 'claimed', returns the token.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use crate::auth::{extract_session_id, extract_ua_hash, generate_token, hash_token};
use crate::build_attest;
use crate::models::types::{
    ConfirmRequest, DeviceCodeRequest, DeviceCodeResponse, ErrorResponse, MeResponse, PollQuery,
    ProviderInfo,
};
use crate::state::AppState;
use mylittlechart_server::matrix_keys_store::CredentialKind;

// ============================================================================
// POST /api/auth/device-code
// ============================================================================

/// Start the device authorization flow.
///
/// Desktop app calls this with its `device_id`. Server stores a new pending code
/// (TTL 10 minutes) and returns it for the user to type into the web UI.
pub async fn create_code(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<DeviceCodeRequest>,
) -> Response {
    if let Err(resp) = build_attest::check_build_attestation(
        &headers,
        &state.build_attest_pubkeys,
        state.build_attest_enforce,
        state.build_attest_max_age_secs,
    ) {
        return resp;
    }

    if req.device_id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("device_id must not be empty")),
        )
            .into_response();
    }
    if req.device_id.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("device_id too long")),
        )
            .into_response();
    }
    // Only allow alphanumeric + hyphens (UUID format).
    if !req.device_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Invalid device_id format")),
        )
            .into_response();
    }

    let device_id = req.device_id.clone();
    let now = chrono::Utc::now().to_rfc3339();
    let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let _ = crate::db::cleanup_expired_sessions(&conn);
        crate::db::create_device_code(&conn, &device_id, &now, &expires_at)
    })
    .await;

    match result {
        Ok(Ok(code)) => Json(DeviceCodeResponse {
            code,
            expires_in: 600,
        })
        .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error creating device code: {}", e);
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
// GET /api/auth/poll?code=AB12CD34
// ============================================================================

/// Poll for the status of a device code.
///
/// Returns:
/// - 202 `{ "status": "pending" }` — not yet confirmed.
/// - 200 `{ "status": "confirmed", "token": "...", "display_name": "...", "user_id": 123 }` — confirmed; issues token (once only).
/// - 410 `{ "status": "expired" }` — code expired or already claimed.
pub async fn poll_code(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(req): Query<PollQuery>,
) -> Response {
    if let Err(resp) = build_attest::check_build_attestation(
        &headers,
        &state.build_attest_pubkeys,
        state.build_attest_enforce,
        state.build_attest_max_age_secs,
    ) {
        return resp;
    }

    let code = req.code.to_uppercase();

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<PollOutcome> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let row = crate::db::get_device_code(&conn, &code)?;

        let row = match row {
            Some(r) => r,
            None => return Ok(PollOutcome::Gone),
        };

        // Check expiry in application code as well (belt-and-suspenders).
        let now = chrono::Utc::now().to_rfc3339();
        if row.expires_at < now && row.status == "pending" {
            return Ok(PollOutcome::Expired);
        }

        match row.status.as_str() {
            "pending" => Ok(PollOutcome::Pending),
            "confirmed" => {
                // Issue token — exactly once.
                let user_id = match row.user_id {
                    Some(id) => id,
                    None => return Ok(PollOutcome::Gone),
                };

                // Fetch display_name and provider for the user.
                let (display_name, provider) = {
                    let mut stmt = conn.prepare(
                        "SELECT display_name, provider FROM users WHERE id = ?1 LIMIT 1",
                    )?;
                    let mut rows = stmt.query(rusqlite::params![user_id])?;
                    match rows.next()? {
                        Some(r) => (r.get::<_, String>(0)?, r.get::<_, String>(1)?),
                        None => return Ok(PollOutcome::Gone),
                    }
                };

                let raw_token = generate_token();
                let token_hash = hash_token(&raw_token);
                let now_str = chrono::Utc::now().to_rfc3339();
                let expires_at = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();

                crate::db::insert_auth_token_with_expiry(
                    &conn, &token_hash, user_id, &now_str, &expires_at,
                )?;

                // Link device to user.
                crate::db::link_device_user(&conn, &row.device_id, user_id, &now_str)?;

                // Mark code as claimed so it cannot be polled again.
                crate::db::claim_device_code(&conn, &code)?;

                let public_id = crate::db::get_user_public_id(&conn, user_id)
                    .unwrap_or_default();

                Ok(PollOutcome::Confirmed {
                    token: raw_token,
                    display_name,
                    provider,
                    user_id,
                    public_id,
                })
            }
            // "claimed" or anything else — gone.
            _ => Ok(PollOutcome::Gone),
        }
    })
    .await;

    match result {
        Ok(Ok(outcome)) => outcome_to_response(outcome),
        Ok(Err(e)) => {
            tracing::error!("DB error polling device code: {}", e);
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

/// Internal outcome for poll logic.
enum PollOutcome {
    Pending,
    Expired,
    Gone,
    Confirmed {
        token: String,
        display_name: String,
        provider: String,
        user_id: i64,
        public_id: String,
    },
}

fn outcome_to_response(outcome: PollOutcome) -> Response {
    match outcome {
        PollOutcome::Pending => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "status": "pending" })),
        )
            .into_response(),
        PollOutcome::Expired => (
            StatusCode::GONE,
            Json(serde_json::json!({ "status": "expired" })),
        )
            .into_response(),
        PollOutcome::Gone => (
            StatusCode::GONE,
            Json(serde_json::json!({ "status": "expired" })),
        )
            .into_response(),
        PollOutcome::Confirmed {
            token,
            display_name,
            provider,
            user_id,
            public_id,
        } => Json(serde_json::json!({
            "status": "confirmed",
            "token": token,
            "display_name": display_name,
            "provider": provider,
            "user_id": user_id,
            "public_id": public_id,
        }))
        .into_response(),
    }
}

// ============================================================================
// POST /api/auth/confirm
// ============================================================================

/// Confirm a device code from a logged-in web user.
///
/// Requires a valid `session_id` cookie. Links the code's device to the
/// authenticated user and transitions the code from 'pending' to 'confirmed'.
pub async fn confirm_code(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ConfirmRequest>,
) -> Response {
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

    let code = req.code.to_uppercase();
    let ua_hash = extract_ua_hash(&headers);

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<ConfirmOutcome> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());

        // Validate session.
        let user_id = match crate::db::resolve_web_session(&conn, &session_id, &ua_hash)? {
            Some(id) => id,
            None => return Ok(ConfirmOutcome::Unauthorized),
        };

        // Check the code exists and is still pending.
        let row = match crate::db::get_device_code(&conn, &code)? {
            Some(r) => r,
            None => return Ok(ConfirmOutcome::NotFound),
        };

        let now = chrono::Utc::now().to_rfc3339();
        if row.expires_at < now {
            return Ok(ConfirmOutcome::Expired);
        }

        if row.status != "pending" {
            return Ok(ConfirmOutcome::AlreadyUsed);
        }

        let updated = crate::db::confirm_device_code(&conn, &code, user_id)?;
        if updated {
            Ok(ConfirmOutcome::Ok)
        } else {
            // Race: another request confirmed it first.
            Ok(ConfirmOutcome::AlreadyUsed)
        }
    })
    .await;

    match result {
        Ok(Ok(ConfirmOutcome::Ok)) => {
            Json(serde_json::json!({ "status": "confirmed" })).into_response()
        }
        Ok(Ok(ConfirmOutcome::Unauthorized)) => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Invalid or expired session")),
        )
            .into_response(),
        Ok(Ok(ConfirmOutcome::NotFound)) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new("Device code not found")),
        )
            .into_response(),
        Ok(Ok(ConfirmOutcome::Expired)) => (
            StatusCode::GONE,
            Json(ErrorResponse::new("Device code has expired")),
        )
            .into_response(),
        Ok(Ok(ConfirmOutcome::AlreadyUsed)) => (
            StatusCode::CONFLICT,
            Json(ErrorResponse::new("Device code already used")),
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error confirming device code: {}", e);
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

/// Internal outcome variants for confirm logic.
enum ConfirmOutcome {
    Ok,
    Unauthorized,
    NotFound,
    Expired,
    AlreadyUsed,
}

// ============================================================================
// GET /api/auth/me
// ============================================================================

/// Return basic profile info for the currently logged-in web user.
///
/// Reads the `session_id` cookie. Returns 401 if missing or expired.
pub async fn me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    // Either credential. This endpoint answered only to a browser's
    // `session_id` cookie, so a desktop client — which has no cookie and sends
    // `Authorization: Bearer` — got 401 for a perfectly live token. That is not
    // an academic gap: the desktop updater probes this endpoint at startup to
    // find out whether its stored token is still real, read the 401 as "the
    // server rejected me", and signed the user out on every launch
    // (owner, 2026-09-04). "Who am I" must accept every way a client can say
    // who it is; `routes::account::redeem` already resolves both.
    let session_id = extract_session_id(&headers);
    let bearer: Option<String> = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| crate::auth::extract_bearer(Some(v)))
        .map(|s| s.to_owned());

    if session_id.is_none() && bearer.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Not logged in")),
        )
            .into_response();
    }

    let ua_hash = extract_ua_hash(&headers);

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<MeResponse>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());

        let mut resolved: Option<i64> = None;
        if let Some(ref sid) = session_id {
            resolved = crate::db::resolve_web_session(&conn, sid, &ua_hash)?;
        }
        if resolved.is_none() {
            if let Some(ref raw) = bearer {
                let token_hash = crate::auth::hash_token(raw);
                resolved = crate::db::resolve_token_hash_with_expiry(&conn, &token_hash)?;
            }
        }
        let user_id = match resolved {
            Some(id) => id,
            None => return Ok(None),
        };

        let mut stmt = conn.prepare(
            "SELECT display_name, provider, COALESCE(public_id, ''), nick FROM users WHERE id = ?1 LIMIT 1",
        )?;
        let mut rows = stmt.query(rusqlite::params![user_id])?;
        if let Some(row) = rows.next()? {
            let display_name: String = row.get(0)?;
            let primary_provider: String = row.get(1)?;
            let public_id: String = row.get(2)?;
            let nick: Option<String> = row.get(3)?;

            // Fetch all linked providers.
            let linked = crate::db::get_providers_for_user(&conn, user_id)?;
            let providers: Vec<ProviderInfo> = linked
                .into_iter()
                .map(|(p, _pid, dn)| ProviderInfo { provider: p, display_name: dn })
                .collect();

            let effective_label = crate::db::effective_label_for_user(&conn, user_id)?;

            Ok(Some(MeResponse {
                user_id,
                public_id,
                display_name,
                nick,
                effective_label,
                provider: primary_provider,
                providers,
            }))
        } else {
            Ok(None)
        }
    })
    .await;

    match result {
        Ok(Ok(Some(me))) => Json(me).into_response(),
        Ok(Ok(None)) => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Invalid or expired session")),
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error in /auth/me: {}", e);
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
// POST /api/auth/logout
// ============================================================================

/// Logout: delete the web session and clear the cookie.
pub async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Some(session_id) = extract_session_id(&headers) {
        let revoke_state = state.clone();
        let session_id_for_revoke = session_id.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            crate::db::delete_web_session(&conn, &session_id)
        })
        .await;

        // Strip the Matrix device this web session minted, if any (plan
        // §1.1's revoke hook — see routes/matrix/auth.rs's
        // `on_credential_revoked`).
        let revoke_result = tokio::task::spawn_blocking(move || {
            let cp = revoke_state.control_plane();
            let now = chrono::Utc::now().to_rfc3339();
            // messenger.db never holds a raw session id at rest (manager
            // review, 2026-09-24) — hash it the same way `resolve_matrix_
            // caller`'s own AuthCredential::Web does.
            let credential_ref = crate::routes::matrix::auth::web_credential_ref(&session_id_for_revoke);
            let mut messenger = cp.messenger_conn();
            crate::routes::matrix::auth::on_credential_revoked(&mut messenger, &cp.live, CredentialKind::Web, &credential_ref, &now)
        })
        .await;
        if let Ok(Err(e)) = revoke_result {
            tracing::error!("Failed to revoke the Matrix device on logout: {}", e);
        }
    }

    // Clear the cookie by setting Max-Age=0.
    let clear_cookie = "session_id=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0";
    (
        StatusCode::OK,
        [(header::SET_COOKIE, clear_cookie)],
        Json(serde_json::json!({ "status": "logged_out" })),
    )
        .into_response()
}

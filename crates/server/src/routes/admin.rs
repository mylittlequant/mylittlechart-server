//! Admin endpoints — protected by ADMIN_SECRET bearer token.

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;
use subtle::ConstantTimeEq;

use crate::models::types::{
    ErrorResponse, PromoteQuery, PromoteResponse, RegisterReleaseRequest, RegisterReleaseResponse,
};
use crate::pathutil::is_safe_path_component;
use crate::state::AppState;

/// Verify ADMIN_SECRET from Authorization header. Returns error response if invalid.
fn verify_admin_secret(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    if state.admin_secret.is_empty() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse::new("Admin endpoint disabled")),
        )
            .into_response());
    }

    let auth = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match auth {
        Some(token) if token.as_bytes().ct_eq(state.admin_secret.as_bytes()).into() => Ok(()),
        _ => Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Invalid or missing admin secret")),
        )
            .into_response()),
    }
}

/// POST /api/admin/restart
///
/// Triggers a graceful shutdown. The wrapper script will restart the process
/// with the newly built binary. Requires `Authorization: Bearer {ADMIN_SECRET}`.
pub async fn restart(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = verify_admin_secret(&state, &headers) {
        return e;
    }

    tracing::info!("Admin restart requested — initiating graceful shutdown");
    let _ = state.shutdown_tx.send(());

    Json(serde_json::json!({ "status": "restarting" })).into_response()
}

/// POST /api/admin/register-release
///
/// Metadata-only manifest registration. Requires
/// `Authorization: Bearer {ADMIN_SECRET}` header. The artifact bytes never
/// reach the control box: since the 2026-08-30 publish redesign,
/// `mlc-opsd` uploads and sha256-verifies the file on every public edge
/// before ever calling here — this endpoint's only job is to write the
/// manifest row (see `mlc-opsd`'s `POST /api/release/publish`, which is the
/// only intended caller). It replaces the old body-accepting
/// `POST /api/admin/upload`, which stored artifacts on the control box —
/// a box that stores nothing now that downloads redirect to the edges.
///
/// NOTE: the JSON body is parsed only AFTER the bearer check — same reason
/// the old upload route parsed its query string late: an unauthenticated
/// probe gets a flat 401 and nothing about the endpoint's shape.
pub async fn register_release(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(e) = verify_admin_secret(&state, &headers) {
        return e;
    }

    let req: RegisterReleaseRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("Invalid JSON body")),
            )
                .into_response();
        }
    };

    if req.platform.is_empty() || req.version.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("platform and version are required")),
        )
            .into_response();
    }
    if !is_safe_path_component(&req.platform) || !is_safe_path_component(&req.version) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Invalid platform or version format")),
        )
            .into_response();
    }
    if !is_safe_path_component(&req.filename) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Invalid filename format")),
        )
            .into_response();
    }
    if req.sha256.len() != 64 || !req.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("sha256 must be 64 hex characters")),
        )
            .into_response();
    }
    if req.file_size == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("file_size must be > 0")),
        )
            .into_response();
    }
    if req.release_notes.len() > 4096 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("release_notes too long (max 4096)")),
        )
            .into_response();
    }
    if req.signature.len() > 256 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("signature too long (max 256)")),
        )
            .into_response();
    }
    if req.channel != "stable" && req.channel != "dev" {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("channel must be 'stable' or 'dev'")),
        )
            .into_response();
    }

    let now = chrono::Utc::now().to_rfc3339();
    let platform = req.platform.clone();
    let version = req.version.clone();
    let channel = req.channel.clone();
    // `file_path` is the column name (unchanged schema) — the value stored
    // is now just the filename under the edges' static `/dl/` tree, never a
    // path, since the control box holds no filesystem copy to build a path
    // to. See `routes::updates::download_binary`, which reads it back that way.
    let file_path = req.filename.clone();
    let sha256 = req.sha256.clone();
    let release_notes = req.release_notes.clone();
    let signature = req.signature.clone();
    let file_size = req.file_size;

    let db_result = tokio::task::spawn_blocking(move || {
        // `releases` lives in the operational database (2026-08-30 store split).
        let conn = state.control_plane().ops_db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::upsert_release(
            &conn,
            &version,
            &platform,
            &channel,
            &sha256,
            &file_path,
            file_size as i64,
            &release_notes,
            &signature,
            &now,
        )
    })
    .await;

    match db_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::error!("DB error during release registration: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database insert failed")),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Internal error")),
            )
                .into_response();
        }
    }

    tracing::info!(
        "Release registered: platform={} version={} channel={} filename={} size={} sha256={} signed={}",
        req.platform,
        req.version,
        req.channel,
        req.filename,
        req.file_size,
        req.sha256,
        !req.signature.is_empty(),
    );

    Json(RegisterReleaseResponse {
        status: "ok",
        platform: req.platform,
        version: req.version,
        channel: req.channel,
        filename: req.filename,
        sha256: req.sha256,
    })
    .into_response()
}

/// Request body for POST /api/admin/gift-codes.
#[derive(serde::Deserialize)]
pub struct MintGiftCodesRequest {
    /// Days of paid access each code grants, from the moment it is redeemed.
    pub days: i64,
    /// How many codes to mint in this call. Defaults to 1.
    #[serde(default = "default_gift_code_count")]
    pub count: u32,
    /// Why this batch was minted — support needs this, the redeeming
    /// account never sees it.
    #[serde(default)]
    pub note: String,
}

fn default_gift_code_count() -> u32 {
    1
}

/// Response for POST /api/admin/gift-codes.
#[derive(serde::Serialize)]
pub struct MintGiftCodesResponse {
    pub codes: Vec<String>,
}

/// A typo in `count` (an extra zero, say) should not be able to flood the
/// table in one call — this is the ceiling on a single mint request.
const MAX_GIFT_CODES_PER_REQUEST: u32 = 200;

/// POST /api/admin/gift-codes
///
/// Mints `count` (default 1) single-use gift/trial codes, each granting
/// `days` days of paid access from the moment an account redeems it (see
/// `db::mint_gift_codes`, `db::redeem_gift_code`, and
/// `routes::account::redeem` for the redemption side). Requires
/// `Authorization: Bearer {ADMIN_SECRET}`.
///
/// Response: `{ "codes": ["AB3D...", ...] }`. This is the only place a
/// minted code is ever returned — no read path anywhere exposes an existing
/// code (see `db::mint_gift_codes`'s doc comment), and this response is
/// never logged in full.
pub async fn mint_gift_codes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(e) = verify_admin_secret(&state, &headers) {
        return e;
    }

    let req: MintGiftCodesRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("Invalid JSON body")),
            )
                .into_response();
        }
    };

    if req.days <= 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("days must be > 0")),
        )
            .into_response();
    }
    if req.count == 0 || req.count > MAX_GIFT_CODES_PER_REQUEST {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(format!(
                "count must be between 1 and {}",
                MAX_GIFT_CODES_PER_REQUEST
            ))),
        )
            .into_response();
    }
    if req.note.len() > 512 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("note too long (max 512)")),
        )
            .into_response();
    }

    let now = chrono::Utc::now().to_rfc3339();
    let count = req.count;
    let days = req.days;
    let note = req.note.clone();

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::mint_gift_codes(&conn, count, days, &note, &now)
    })
    .await;

    match result {
        Ok(Ok(codes)) => {
            // Count and metadata only — never the codes themselves.
            tracing::info!(
                "Minted {} gift code(s): days={} note={:?}",
                codes.len(),
                days,
                req.note,
            );
            Json(MintGiftCodesResponse { codes }).into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("DB error minting gift codes: {}", e);
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

/// POST /api/admin/promote?version=0.5.1&platform=win64
///
/// Copies a dev release to stable channel. Binary file is NOT duplicated on disk.
/// Requires `Authorization: Bearer {ADMIN_SECRET}`.
pub async fn promote(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
) -> Response {
    if let Err(e) = verify_admin_secret(&state, &headers) {
        return e;
    }

    // Same auth-before-parse rule as register_release above.
    let Query(query) = match Query::<PromoteQuery>::try_from_uri(&uri) {
        Ok(q) => q,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("Invalid query parameters")),
            )
                .into_response();
        }
    };

    if !is_safe_path_component(&query.platform) || !is_safe_path_component(&query.version) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Invalid platform or version format")),
        )
            .into_response();
    }

    let now = chrono::Utc::now().to_rfc3339();
    let version = query.version.clone();
    let platform = query.platform.clone();

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().ops_db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::promote_release(&conn, &version, &platform, &now)
    })
    .await;

    match result {
        Ok(Ok(true)) => {
            tracing::info!(
                "Promoted dev→stable: platform={} version={}",
                query.platform,
                query.version
            );
            Json(PromoteResponse {
                status: "ok",
                version: query.version,
                platform: query.platform,
            })
            .into_response()
        }
        Ok(Ok(false)) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(format!(
                "No dev release found for platform='{}' version='{}'",
                query.platform, query.version
            ))),
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error during promote: {}", e);
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

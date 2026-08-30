//! Admin endpoints — protected by ADMIN_SECRET bearer token.

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc};
use subtle::ConstantTimeEq;

use crate::models::types::{ErrorResponse, PromoteQuery, PromoteResponse, UploadQuery, UploadResponse};
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

/// POST /api/admin/upload?platform=win64&version=0.2.0&release_notes=...
///
/// Requires `Authorization: Bearer {ADMIN_SECRET}` header.
/// Accepts raw binary body (max 200 MB enforced by middleware).
/// Computes SHA-256, saves to `data/binaries/{platform}/{version}/`, inserts into DB.
///
/// NOTE: the query string is parsed only AFTER the bearer check. With
/// `Query<UploadQuery>` as an extractor, axum rejected unauthenticated
/// requests with 400 "missing field platform" — leaking the endpoint's
/// parameter shape to anyone probing it. Now an unauthenticated probe gets
/// a flat 401 and nothing else.
pub async fn upload_binary(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    body: Bytes,
) -> Response {
    if let Err(e) = verify_admin_secret(&state, &headers) {
        return e;
    }

    let Query(query) = match Query::<UploadQuery>::try_from_uri(&uri) {
        Ok(q) => q,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("Invalid query parameters")),
            )
                .into_response();
        }
    };

    // Issue 2: Validate params — reject path traversal characters before touching the filesystem.
    if query.platform.is_empty() || query.version.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("platform and version are required")),
        )
            .into_response();
    }
    if !is_safe_path_component(&query.platform) || !is_safe_path_component(&query.version) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Invalid platform or version format")),
        )
            .into_response();
    }
    if query.release_notes.len() > 4096 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("release_notes too long (max 4096)")),
        )
            .into_response();
    }
    if query.signature.len() > 256 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("signature too long (max 256)")),
        )
            .into_response();
    }
    if query.channel != "stable" && query.channel != "dev" {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("channel must be 'stable' or 'dev'")),
        )
            .into_response();
    }
    if body.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Empty body")),
        )
            .into_response();
    }

    // Compute SHA-256 of the uploaded bytes.
    let sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(&body);
        hex::encode(hasher.finalize())
    };

    let file_size = body.len() as u64;

    // Determine storage path: data/binaries/{platform}/{version}/
    let dir = PathBuf::from(&state.data_dir)
        .join("binaries")
        .join(&query.platform)
        .join(&query.version);

    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        tracing::error!("Failed to create binary dir {:?}: {}", dir, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Failed to create storage directory")),
        )
            .into_response();
    }

    // Filename: mylittlechart-{platform}-{version}.bin (or .exe on win64)
    let ext = if query.platform.contains("win") { "exe" } else { "bin" };
    let filename = format!("mylittlechart-{}-{}.{}", query.platform, query.version, ext);
    let file_path = dir.join(&filename);

    if let Err(e) = tokio::fs::write(&file_path, &body).await {
        tracing::error!("Failed to write binary {:?}: {}", file_path, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Failed to write binary to disk")),
        )
            .into_response();
    }

    let file_path_str = file_path.to_string_lossy().into_owned();
    let now = chrono::Utc::now().to_rfc3339();
    let platform = query.platform.clone();
    let version = query.version.clone();
    let release_notes = query.release_notes.clone();
    let signature = query.signature.clone();
    let channel = query.channel.clone();
    let sha256_clone = sha256.clone();

    let db_result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::upsert_release(
            &conn,
            &version,
            &platform,
            &channel,
            &sha256_clone,
            &file_path_str,
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
            tracing::error!("DB error during upload: {}", e);
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
        "Binary uploaded: platform={} version={} channel={} size={} sha256={} signed={}",
        query.platform,
        query.version,
        query.channel,
        file_size,
        sha256,
        !query.signature.is_empty(),
    );

    Json(UploadResponse {
        status: "ok",
        sha256,
        file_size,
        platform: query.platform,
        version: query.version,
        signature: query.signature,
        channel: query.channel,
    })
    .into_response()
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

    // Same auth-before-parse rule as upload_binary above.
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
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
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

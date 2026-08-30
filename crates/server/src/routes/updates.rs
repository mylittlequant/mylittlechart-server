//! Update manifest and binary download endpoints.

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;
use tokio_util::io::ReaderStream;

use crate::models::types::{DownloadPath, DownloadQuery, ErrorResponse, LatestQuery, VersionManifest};
use crate::state::AppState;

/// GET /api/updates/latest?platform=win64
///
/// Returns the latest `VersionManifest` for the requested platform.
pub async fn get_latest(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LatestQuery>,
) -> Response {
    let platform = query.platform.clone();
    let channel = query.channel.clone();

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::get_latest_release(&conn, &platform, &channel)
    })
    .await;

    match result {
        Ok(Ok(Some(row))) => {
            let download_url = format!(
                "https://mylittlechart.org/api/updates/download/{}/{}?channel={}",
                query.platform, row.version, row.channel
            );
            let manifest = VersionManifest {
                version: row.version,
                sha256: row.sha256,
                download_url,
                release_notes: row.release_notes,
                file_size: row.file_size as u64,
                signature: row.signature,
                channel: row.channel,
            };
            Json(manifest).into_response()
        }
        Ok(Ok(None)) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(format!("No release found for platform '{}'", query.platform))),
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error in get_latest: {}", e);
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

/// GET /api/updates/download/:platform/:version
///
/// Streams the binary file for the given platform and version.
pub async fn download_binary(
    State(state): State<Arc<AppState>>,
    Path(params): Path<DownloadPath>,
    Query(query): Query<DownloadQuery>,
) -> Response {
    let platform = params.platform.clone();
    let version = params.version.clone();
    let channel = query.channel.clone();

    // Look up the release record to find the stored file path.
    // "latest" is resolved to the actual latest version for the platform.
    let row = {
        let result = tokio::task::spawn_blocking({
            let platform = platform.clone();
            let version = version.clone();
            move || {
                let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
                if version == "latest" {
                    crate::db::get_latest_release(&conn, &platform, &channel)
                } else {
                    crate::db::get_release(&conn, &platform, &version, &channel)
                }
            }
        })
        .await;

        match result {
            Ok(Ok(Some(row))) => row,
            Ok(Ok(None)) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse::new(format!(
                        "No release for platform='{}' version='{}'",
                        platform, version
                    ))),
                )
                    .into_response();
            }
            Ok(Err(e)) => {
                tracing::error!("DB error in download_binary: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse::new("Database error")),
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
    };

    // Redirect to the artifact on the edge instead of streaming it from here.
    //
    // Since 2026-08-30 this process runs on the control box, reachable only
    // across the WireGuard link. Streaming an 82 MB binary through it would put
    // bulk client traffic on the control channel and make every download depend
    // on the control box being up — for a file that is neither user data nor
    // control state. The edges already hold it and serve it from their own disk
    // at /dl/, the way they serve the wasm bundle.
    //
    // The Location is relative on purpose: the client stays on whichever edge
    // answered it, and no hostname is baked in.
    //
    // The filename comes from the manifest's own path, and that path is not
    // uniform: rows written while the server ran on Windows carry
    // `./data\binaries\win64\…` while newer ones carry an absolute Linux
    // path. Split on both separators rather than trusting either.
    let filename = row
        .file_path
        .rsplit(|c| c == '/' || c == '\\')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("download");

    let location = format!("/dl/{}/{}/{}", platform, row.version, filename);

    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        // The mapping can change; never let a client or proxy remember it.
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

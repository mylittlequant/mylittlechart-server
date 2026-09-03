//! Update manifest and binary download endpoints.

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use crate::models::types::{
    DownloadPath, DownloadQuery, ErrorResponse, LatestQuery, ReleaseListQuery, VersionManifest,
};
use crate::state::AppState;

/// GET /api/updates/list?channel=stable
///
/// Every published release, newest first, across every platform — what a
/// downloads page shows as history and as the catalogue of "other platforms".
///
/// Reads the same `releases` table `latest` does, which is the authoritative
/// record of what is on the edges: a row exists only after every edge received
/// the artifact and verified its sha256. A page built from this cannot offer a
/// file that is not there, which is the failure mode of a list maintained by
/// hand.
pub async fn list_releases(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ReleaseListQuery>,
) -> Response {
    let channel = query.channel.clone();
    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().ops_db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::list_releases(&conn, &channel)
    })
    .await;

    match result {
        Ok(Ok(rows)) => {
            let items: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|r| {
                    let download_url = format!(
                        "https://mylittlechart.org/api/updates/download/{}/{}?channel={}",
                        r.platform, r.version, r.channel
                    );
                    serde_json::json!({
                        "platform": r.platform,
                        "version": r.version,
                        "channel": r.channel,
                        "sha256": r.sha256,
                        "file_size": r.file_size,
                        "release_notes": r.release_notes,
                        "created_at": r.created_at,
                        "download_url": download_url,
                    })
                })
                .collect();
            Json(serde_json::json!({ "releases": items })).into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("DB error in list_releases: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("join error in list_releases: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Internal error")),
            )
                .into_response()
        }
    }
}

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
        // `releases` lives in the operational database (2026-08-30 store split).
        let conn = state.control_plane().ops_db.lock().unwrap_or_else(|e| e.into_inner());
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
                let conn = state.control_plane().ops_db.lock().unwrap_or_else(|e| e.into_inner());
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
    // `file_path` is no longer a path: since the 2026-08-30 publish redesign
    // (`mlc-opsd`'s `POST /api/release/publish` registering via
    // `POST /api/admin/register-release`) the control box stores no
    // artifacts at all, so there is nothing on this box's filesystem for a
    // path to point at — the column holds just the filename that exists
    // under each edge's `/opt/mlc/static/dl/{platform}/{version}/`. The
    // rsplit below is defense in depth against older rows written before
    // this cutover, which carried a real path (Windows `./data\binaries\…`
    // or an absolute Linux one) — either shape still yields the right
    // basename.
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

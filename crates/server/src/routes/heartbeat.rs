//! POST /api/heartbeat — device registration and keep-alive.

use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use std::sync::Arc;

use crate::models::types::{HeartbeatRequest, HeartbeatResponse};
use crate::state::AppState;

/// POST /api/heartbeat
///
/// Upserts a device record in SQLite and returns a simple acknowledgement.
pub async fn handle_heartbeat(
    State(state): State<Arc<AppState>>,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, StatusCode> {
    let now = chrono::Utc::now().to_rfc3339();

    // Sanitize device_id: only hex digits and hyphens (UUID format), max 36 chars.
    let device_id: String = req
        .device_id
        .chars()
        .filter(|c| c.is_ascii_hexdigit() || *c == '-')
        .take(36)
        .collect();

    // Sanitize device_name: printable ASCII + space, max 64 chars.
    let device_name: String = req
        .device_name
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(64)
        .collect();

    // Sanitize app_version: printable ASCII + space, max 32 chars.
    let app_version: String = req
        .app_version
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(32)
        .collect();

    // Sanitize os: printable ASCII + space, max 64 chars.
    let os: String = req
        .os
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(64)
        .collect();

    tokio::task::spawn_blocking(move || {
        // `devices` lives in the operational database (2026-08-30 store split).
        let conn = state.control_plane().ops_db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::upsert_device(&conn, &device_id, &device_name, &app_version, &os, &now)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|e| {
        tracing::error!("Heartbeat DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::debug!("Heartbeat from device={} version={}", req.device_id, req.app_version);

    Ok(Json(HeartbeatResponse { status: "ok" }))
}

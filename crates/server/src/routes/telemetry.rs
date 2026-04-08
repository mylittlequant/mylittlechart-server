//! POST /api/telemetry — accept metrics from updater clients.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use std::sync::Arc;

use crate::auth::{extract_bearer, hash_token};
use crate::models::types::{TelemetryRequest, TelemetryResponse};
use crate::state::AppState;

/// POST /api/telemetry
///
/// Stores a fixed-schema telemetry record. GPU name is sanitized.
/// Optional `Authorization: Bearer <token>` header links the record to a user.
pub async fn submit_telemetry(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<TelemetryRequest>,
) -> Result<Json<TelemetryResponse>, StatusCode> {
    // Issue 5: Sanitize all unbounded string fields — only printable ASCII + space,
    // with field-appropriate length caps.

    // Sanitize device_id: only hex digits and hyphens (UUID format), max 36 chars.
    let device_id: Option<String> = req.device_id.as_deref().map(|s| {
        s.chars()
            .filter(|c| c.is_ascii_hexdigit() || *c == '-')
            .take(36)
            .collect()
    }).filter(|s: &String| !s.is_empty());

    let gpu_name: String = req
        .gpu_name
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(128)
        .collect();
    let app_version: String = req
        .app_version
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(32)
        .collect();
    let os: String = req
        .os
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(64)
        .collect();
    let arch: String = req
        .arch
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(32)
        .collect();

    // Clamp numeric values to reasonable ranges.
    let screen_width = req.screen_width.min(32_768) as i64;
    let screen_height = req.screen_height.min(32_768) as i64;
    let connector_count = req.connector_count.min(10_000) as i64;
    let window_count = req.window_count.min(1_000) as i64;
    let avg_fps = (req.avg_fps as f64).clamp(0.0, 100_000.0);
    let uptime_secs = req.uptime_secs.min(365 * 24 * 3600) as i64;
    let total_bars = req.total_bars.min(1_000_000_000) as i64;
    let ws_connections = req.ws_connections.min(10_000) as i64;

    // Keep copies for the log line — the originals move into the spawn_blocking closure.
    let log_version = app_version.clone();
    let log_os = os.clone();
    let log_arch = arch.clone();
    let log_fps = req.avg_fps;
    let log_uptime = req.uptime_secs;
    let log_bars = req.total_bars;

    // Optionally resolve bearer token to user_id.
    let raw_token = extract_bearer(headers.get("Authorization").and_then(|v| v.to_str().ok()))
        .map(|s| s.to_owned());

    let now = chrono::Utc::now().to_rfc3339();

    tokio::task::spawn_blocking(move || {
        let conn = state.db.lock().unwrap_or_else(|e| e.into_inner());

        let user_id = raw_token.as_deref().and_then(|t| {
            let hash = hash_token(t);
            crate::db::resolve_token_hash(&conn, &hash).ok().flatten()
        });

        crate::db::insert_telemetry(
            &conn,
            device_id.as_deref(),
            user_id,
            &now,
            &app_version,
            &os,
            &arch,
            &gpu_name,
            screen_width,
            screen_height,
            connector_count,
            window_count,
            avg_fps,
            uptime_secs,
            total_bars,
            ws_connections,
        )
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|e| {
        tracing::error!("Telemetry DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::info!(
        "Telemetry: version={} os={} arch={} fps={:.0} uptime={}s bars={}",
        log_version, log_os, log_arch, log_fps, log_uptime, log_bars
    );

    Ok(Json(TelemetryResponse { status: "ok" }))
}

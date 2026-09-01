//! POST /api/telemetry — accept metrics from updater clients.
//!
//! Storage is split by mutability (2026-08-31): `device_profile` holds the
//! near-immutable hardware/build facts and is written only when they change;
//! `device_metrics` is the time series and is what the per-device daily cap
//! (`MLC_TELEMETRY_DAILY_CAP`) and the retention ring apply to. The cap is
//! the one control here that does not depend on a well-behaved client — the
//! client's own OTA-tick cadence is exactly what let one dev machine post
//! tens of thousands of rows. See
//! docs/mlc/plans/data-domains-identity-and-fingerprinting-2026-08-30.md §3.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use std::sync::Arc;

use crate::auth::{extract_bearer, hash_token};
use crate::db::DeviceProfileFields;
use crate::models::types::{TelemetryRequest, TelemetryResponse};
use crate::opswriter::{OpsWrite, TelemetrySample};
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
    // Every row exists to be counted against one device's daily cap — a post
    // with no usable device_id after sanitising cannot be capped, so it is
    // rejected outright rather than stored under an uncapped NULL bucket.
    let device_id: String = match req
        .device_id
        .as_deref()
        .map(|s| {
            s.chars()
                .filter(|c| c.is_ascii_hexdigit() || *c == '-')
                .take(36)
                .collect::<String>()
        })
        .filter(|s: &String| !s.is_empty())
    {
        Some(id) => id,
        None => return Err(StatusCode::BAD_REQUEST),
    };

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

    // Bearer token resolution still needs the identity database, so it
    // still runs in `spawn_blocking` against `control_plane().db`. Nothing
    // after this point touches a mutex or awaits a database write: the
    // profile/cap/metrics work that used to happen here now happens on the
    // dedicated ops-writer thread (see opswriter.rs) — this handler just
    // builds the sample and hands it off.
    let identity_state = state.clone();
    let user_id = tokio::task::spawn_blocking(move || {
        raw_token.as_deref().and_then(|t| {
            let hash = hash_token(t);
            let conn = identity_state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            crate::db::resolve_token_hash(&conn, &hash).ok().flatten()
        })
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let profile = DeviceProfileFields {
        app_version,
        os,
        arch,
        gpu_name,
        screen_width,
        screen_height,
    };

    // Same promise as the over-cap drop below: accepted, not necessarily
    // stored. The cap check itself now happens on the writer thread, right
    // next to the insert it guards, with nothing racing between the two —
    // see `opswriter::apply_telemetry`.
    state.control_plane().ops_writer.enqueue(OpsWrite::Telemetry(TelemetrySample {
        device_id,
        user_id,
        now,
        daily_cap: state.telemetry_daily_cap,
        profile,
        connector_count,
        window_count,
        avg_fps,
        uptime_secs,
        total_bars,
        ws_connections,
    }));

    tracing::info!(
        "Telemetry: version={} os={} arch={} fps={:.0} uptime={}s bars={}",
        log_version, log_os, log_arch, log_fps, log_uptime, log_bars
    );

    Ok(Json(TelemetryResponse { status: "ok" }))
}

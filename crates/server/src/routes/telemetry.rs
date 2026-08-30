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

    tokio::task::spawn_blocking(move || -> rusqlite::Result<()> {
        // Bearer token resolves against identity (auth_tokens); both storage
        // calls below land in the operational database — `device_profile` /
        // `device_metrics` moved there in the 2026-08-30 store split.
        let user_id = raw_token.as_deref().and_then(|t| {
            let hash = hash_token(t);
            let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            crate::db::resolve_token_hash(&conn, &hash).ok().flatten()
        });

        let ops_conn = state.control_plane().ops_db.lock().unwrap_or_else(|e| e.into_inner());

        // Profile: the near-immutable half. `upsert_device_profile` compares
        // against the stored row itself and skips the write when nothing
        // changed — a device with unchanged hardware produces no write here
        // no matter how often it posts.
        let profile_fields = DeviceProfileFields {
            app_version,
            os,
            arch,
            gpu_name,
            screen_width,
            screen_height,
        };
        crate::db::upsert_device_profile(&ops_conn, &device_id, &profile_fields, &now)?;

        // Per-device daily cap — the one volume control that does not depend
        // on a well-behaved client (see module doc). Over-cap silently drops
        // the metrics row; the caller still gets a success response, since
        // telling a runaway client anything useful here is exactly what
        // would let it adapt around the cap.
        let today = &now[..10]; // RFC 3339 "YYYY-MM-DD" date prefix, UTC
        let count_today = crate::db::count_device_metrics_today(&ops_conn, &device_id, today)?;
        if count_today >= state.telemetry_daily_cap {
            return Ok(());
        }

        crate::db::insert_device_metrics(
            &ops_conn,
            &device_id,
            user_id,
            &now,
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

//! GET / — localhost-only admin dashboard.
//!
//! Renders a single HTML page with summary statistics and data tables pulled
//! from the SQLite database. Intended to run on 127.0.0.1 only — no auth needed.

use axum::{extract::State, http::StatusCode, response::Html};
use std::collections::HashMap;
use std::sync::Arc;

use crate::state::AppState;

// ---------------------------------------------------------------------------
// Data structures for query results
// ---------------------------------------------------------------------------

struct ReleaseEntry {
    platform: String,
    version: String,
    file_size: i64,
    release_notes: String,
    created_at: String,
}

/// Unified device view: telemetry data enriched with heartbeat data from `devices` table.
struct UnifiedDevice {
    device_id: String,
    device_name: String,     // from devices table, empty string if no heartbeat yet
    app_version: String,
    os: String,
    arch: String,
    gpu_name: String,
    screen: String,          // "1920x1080"
    avg_fps: f64,
    max_uptime_secs: i64,
    last_seen: String,       // RFC 3339
    telemetry_count: i64,
    total_heartbeats: i64,   // from devices table, 0 if no heartbeat
    linked_users: Vec<(String, i64)>, // (display_name, user_id)
}

struct TelemetryEntry {
    device_id: Option<String>, // short prefix shown in table
    received_at: String,
    app_version: String,
    os: String,
    arch: String,
    gpu_name: String,
    screen_width: i64,
    screen_height: i64,
    avg_fps: f64,
    uptime_secs: i64,
    connector_count: i64,
    window_count: i64,
    ws_connections: i64,
    total_bars: i64,
}

struct UserEntry {
    id: i64,
    public_id: String,
    display_name: String,
    created_at: String,
    /// Comma-separated list of linked providers, e.g. "github:Alice, google:Alice G."
    providers: String,
    linked_devices: Vec<String>, // device_names linked to this user
}

struct SummaryStats {
    unique_devices: i64,     // devices seen via telemetry
    registered_devices: i64, // devices that sent heartbeat
    active_last_24h: i64,    // devices with telemetry in last 24h
    total_telemetry: i64,
    total_releases: i64,
    total_users: i64,
    latest_versions: Vec<(String, String)>, // (platform, version)
    // Cloud sync stats
    total_sync_items: i64,
    total_sync_bytes: i64,
    e2e_users: i64,
    syncing_users: i64,
}

struct SyncUserSummary {
    user_id: i64,
    display_name: String,
    total_items: i64,
    live_items: i64,         // deleted = 0
    tombstones: i64,         // deleted = 1
    total_bytes: i64,        // SUM(LENGTH(content))
    categories: String,      // comma-separated distinct categories
    last_modified: String,   // formatted from max modified_at (unix ms → RFC 3339)
    e2e_enabled: bool,       // has row in sync_e2e_params
    e2e_salt_prefix: String, // first 8 chars of salt, or "—"
    e2e_iterations: i64,
    e2e_created_at: String,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// GET / — render the admin dashboard as HTML.
pub async fn render(
    State(state): State<Arc<AppState>>,
) -> Result<Html<String>, StatusCode> {
    let html = tokio::task::spawn_blocking(move || {
        let conn = state.db.lock().unwrap_or_else(|e| e.into_inner());
        build_dashboard(&conn)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|e| {
        tracing::error!("Dashboard DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Html(html))
}

// ---------------------------------------------------------------------------
// Database queries
// ---------------------------------------------------------------------------

fn build_dashboard(conn: &rusqlite::Connection) -> rusqlite::Result<String> {
    let summary = query_summary(conn)?;
    let releases = query_releases(conn)?;
    let devices = query_unified_devices(conn)?;
    let telemetry = query_telemetry(conn)?;
    let users = query_users(conn)?;
    let sync_users = query_sync_users(conn)?;
    Ok(render_html(&summary, &releases, &devices, &telemetry, &users, &sync_users))
}

fn query_summary(conn: &rusqlite::Connection) -> rusqlite::Result<SummaryStats> {
    let unique_devices: i64 = conn.query_row(
        "SELECT COUNT(DISTINCT device_id) FROM telemetry WHERE device_id IS NOT NULL",
        [],
        |row| row.get(0),
    )?;

    let registered_devices: i64 = conn.query_row(
        "SELECT COUNT(*) FROM devices",
        [],
        |row| row.get(0),
    )?;

    let active_last_24h: i64 = conn.query_row(
        "SELECT COUNT(DISTINCT device_id) FROM telemetry \
         WHERE device_id IS NOT NULL \
           AND received_at >= datetime('now', '-24 hours')",
        [],
        |row| row.get(0),
    )?;

    let total_telemetry: i64 = conn.query_row(
        "SELECT COUNT(*) FROM telemetry",
        [],
        |row| row.get(0),
    )?;

    let total_releases: i64 = conn.query_row(
        "SELECT COUNT(*) FROM releases",
        [],
        |row| row.get(0),
    )?;

    let total_users: i64 = conn.query_row(
        "SELECT COUNT(*) FROM users",
        [],
        |row| row.get(0),
    )?;

    // Latest version per platform.
    let mut stmt = conn.prepare(
        "SELECT platform, version FROM releases
         WHERE (platform, created_at) IN (
             SELECT platform, MAX(created_at) FROM releases GROUP BY platform
         )
         ORDER BY platform",
    )?;
    let mut rows = stmt.query([])?;
    let mut latest_versions = Vec::new();
    while let Some(row) = rows.next()? {
        let platform: String = row.get(0)?;
        let version: String = row.get(1)?;
        latest_versions.push((platform, version));
    }

    // Cloud sync summary stats — these tables may not exist yet; treat missing as 0.
    let total_sync_items: i64 = conn
        .query_row("SELECT COUNT(*) FROM sync_items", [], |row| row.get(0))
        .unwrap_or(0);

    let total_sync_bytes: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(LENGTH(content)), 0) FROM sync_items",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let e2e_users: i64 = conn
        .query_row("SELECT COUNT(*) FROM sync_e2e_params", [], |row| row.get(0))
        .unwrap_or(0);

    let syncing_users: i64 = conn
        .query_row(
            "SELECT COUNT(DISTINCT user_id) FROM sync_items",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    Ok(SummaryStats {
        unique_devices,
        registered_devices,
        active_last_24h,
        total_telemetry,
        total_releases,
        total_users,
        latest_versions,
        total_sync_items,
        total_sync_bytes,
        e2e_users,
        syncing_users,
    })
}

fn query_releases(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<ReleaseEntry>> {
    let mut stmt = conn.prepare(
        "SELECT platform, version, file_size, release_notes, created_at
         FROM releases
         ORDER BY created_at DESC",
    )?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(ReleaseEntry {
            platform: row.get(0)?,
            version: row.get(1)?,
            file_size: row.get(2)?,
            release_notes: row.get(3)?,
            created_at: row.get(4)?,
        });
    }
    Ok(out)
}

/// Query the `devices` table (heartbeat data) into a HashMap keyed by device_id.
fn query_heartbeat_map(
    conn: &rusqlite::Connection,
) -> rusqlite::Result<HashMap<String, (String, i64)>> {
    // Returns (device_name, total_heartbeats) per device_id
    let mut stmt = conn.prepare(
        "SELECT device_id, device_name, total_heartbeats FROM devices",
    )?;
    let mut rows = stmt.query([])?;
    let mut map = HashMap::new();
    while let Some(row) = rows.next()? {
        let device_id: String = row.get(0)?;
        let device_name: String = row.get(1).unwrap_or_default();
        let total_heartbeats: i64 = row.get(2).unwrap_or(0);
        map.insert(device_id, (device_name, total_heartbeats));
    }
    Ok(map)
}

fn query_unified_devices(
    conn: &rusqlite::Connection,
) -> rusqlite::Result<Vec<UnifiedDevice>> {
    // Step 1: per-device aggregate from telemetry using window function.
    let mut stmt = conn.prepare(
        "WITH latest AS (
            SELECT *,
                   ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY received_at DESC) AS rn
            FROM telemetry
            WHERE device_id IS NOT NULL
        )
        SELECT
            latest.device_id,
            COALESCE(latest.app_version, '') AS app_version,
            COALESCE(latest.os, '') AS os,
            COALESCE(latest.arch, '') AS arch,
            COALESCE(latest.gpu_name, '') AS gpu_name,
            COALESCE(latest.screen_width, 0) AS screen_width,
            COALESCE(latest.screen_height, 0) AS screen_height,
            COALESCE(latest.avg_fps, 0.0) AS avg_fps,
            COALESCE(latest.received_at, '') AS last_seen,
            (SELECT COUNT(*) FROM telemetry t2 WHERE t2.device_id = latest.device_id) AS telemetry_count,
            (SELECT MAX(uptime_secs) FROM telemetry t3 WHERE t3.device_id = latest.device_id) AS max_uptime
        FROM latest
        WHERE rn = 1
        ORDER BY latest.received_at DESC",
    )?;

    let mut rows = stmt.query([])?;

    // Step 2: load heartbeat data for merging.
    let heartbeat_map = query_heartbeat_map(conn)?;

    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let device_id: String = row.get(0)?;
        let app_version: String = row.get(1)?;
        let os: String = row.get(2)?;
        let arch: String = row.get(3)?;
        let gpu_name: String = row.get(4)?;
        let screen_width: i64 = row.get(5)?;
        let screen_height: i64 = row.get(6)?;
        let avg_fps: f64 = row.get(7)?;
        let last_seen: String = row.get(8)?;
        let telemetry_count: i64 = row.get(9)?;
        let max_uptime_secs: i64 = row.get::<_, Option<i64>>(10)?.unwrap_or(0);

        let (device_name, total_heartbeats) = heartbeat_map
            .get(&device_id)
            .cloned()
            .unwrap_or_else(|| (String::new(), 0));

        let screen = if screen_width > 0 || screen_height > 0 {
            format!("{}x{}", screen_width, screen_height)
        } else {
            String::new()
        };

        out.push(UnifiedDevice {
            device_id,
            device_name,
            app_version,
            os,
            arch,
            gpu_name,
            screen,
            avg_fps,
            max_uptime_secs,
            last_seen,
            telemetry_count,
            total_heartbeats,
            linked_users: Vec::new(), // populated below
        });
    }

    // Step 3: load linked users per device.
    let mut user_map: HashMap<String, Vec<(String, i64)>> = HashMap::new();
    {
        let mut stmt = conn.prepare(
            "SELECT du.device_id, u.display_name, u.id
             FROM device_users du
             JOIN users u ON u.id = du.user_id
             ORDER BY du.linked_at DESC",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let device_id: String = row.get(0)?;
            let display_name: String = row.get(1)?;
            let user_id: i64 = row.get(2)?;
            user_map.entry(device_id).or_default().push((display_name, user_id));
        }
    }
    for d in &mut out {
        d.linked_users = user_map.remove(&d.device_id).unwrap_or_default();
    }

    Ok(out)
}

fn query_telemetry(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<TelemetryEntry>> {
    let mut stmt = conn.prepare(
        "SELECT device_id, received_at, app_version, os, arch, gpu_name,
                screen_width, screen_height, avg_fps, uptime_secs,
                connector_count, window_count, ws_connections, total_bars
         FROM telemetry
         ORDER BY received_at DESC
         LIMIT 50",
    )?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(TelemetryEntry {
            device_id: row.get(0)?,
            received_at: row.get(1)?,
            app_version: row.get(2)?,
            os: row.get(3)?,
            arch: row.get(4)?,
            gpu_name: row.get(5)?,
            screen_width: row.get(6)?,
            screen_height: row.get(7)?,
            avg_fps: row.get(8)?,
            uptime_secs: row.get(9)?,
            connector_count: row.get(10)?,
            window_count: row.get(11)?,
            ws_connections: row.get(12)?,
            total_bars: row.get(13)?,
        });
    }
    Ok(out)
}

fn query_users(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<UserEntry>> {
    let mut stmt = conn.prepare(
        "SELECT u.id,
                COALESCE(u.public_id, ''),
                u.display_name,
                u.created_at,
                COALESCE(GROUP_CONCAT(up.provider || ':' || up.display_name, ', '), '')
         FROM users u
         LEFT JOIN user_providers up ON up.user_id = u.id
         GROUP BY u.id
         ORDER BY u.created_at DESC",
    )?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(UserEntry {
            id: row.get(0)?,
            public_id: row.get(1)?,
            display_name: row.get(2)?,
            created_at: row.get(3)?,
            providers: row.get(4)?,
            linked_devices: Vec::new(), // populated below
        });
    }

    // Load linked devices per user.
    let mut device_map: HashMap<i64, Vec<String>> = HashMap::new();
    {
        let mut stmt = conn.prepare(
            "SELECT du.user_id, COALESCE(d.device_name, du.device_id)
             FROM device_users du
             LEFT JOIN devices d ON d.device_id = du.device_id",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let user_id: i64 = row.get(0)?;
            let device_name: String = row.get(1)?;
            device_map.entry(user_id).or_default().push(device_name);
        }
    }
    for u in &mut out {
        u.linked_devices = device_map.remove(&u.id).unwrap_or_default();
    }

    Ok(out)
}

fn query_sync_users(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<SyncUserSummary>> {
    // Build a combined view of every user that has sync_items or e2e_params.
    // We do two separate queries and merge in Rust to avoid complex SQL that
    // differs across SQLite versions.

    // --- sync_items per user ---
    let mut items_map: HashMap<i64, (i64, i64, i64, i64, String, String)> = HashMap::new();
    // key: user_id  value: (total, live, tombstones, bytes, categories, last_modified_rfc3339)
    {
        let result = conn.prepare(
            "SELECT user_id,
                    COUNT(*) AS total,
                    SUM(CASE WHEN deleted = 0 THEN 1 ELSE 0 END) AS live,
                    SUM(CASE WHEN deleted = 1 THEN 1 ELSE 0 END) AS dead,
                    COALESCE(SUM(LENGTH(content)), 0) AS bytes,
                    GROUP_CONCAT(DISTINCT category) AS cats,
                    MAX(modified_at) AS last_ms
             FROM sync_items
             GROUP BY user_id",
        );
        if let Ok(mut stmt) = result {
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let user_id: i64 = row.get(0)?;
                let total: i64 = row.get(1)?;
                let live: i64 = row.get(2)?;
                let dead: i64 = row.get(3)?;
                let bytes: i64 = row.get(4)?;
                let cats: String = row.get::<_, Option<String>>(5)?.unwrap_or_default();
                let last_ms: Option<i64> = row.get(6)?;
                let last_modified = match last_ms {
                    Some(ms) => {
                        use chrono::TimeZone;
                        chrono::Utc
                            .timestamp_millis_opt(ms)
                            .single()
                            .map(|dt| dt.to_rfc3339())
                            .unwrap_or_default()
                    }
                    None => String::new(),
                };
                items_map.insert(user_id, (total, live, dead, bytes, cats, last_modified));
            }
        }
    }

    // --- e2e_params per user ---
    let mut e2e_map: HashMap<i64, (String, i64, String)> = HashMap::new();
    // key: user_id  value: (salt, iterations, created_at)
    {
        let result = conn.prepare(
            "SELECT user_id, salt, iterations, created_at FROM sync_e2e_params",
        );
        if let Ok(mut stmt) = result {
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let user_id: i64 = row.get(0)?;
                let salt: String = row.get(1)?;
                let iterations: i64 = row.get(2)?;
                let created_at: String = row.get(3)?;
                e2e_map.insert(user_id, (salt, iterations, created_at));
            }
        }
    }

    // --- Collect all user_ids that have either sync_items or e2e_params ---
    let mut all_user_ids: std::collections::HashSet<i64> = std::collections::HashSet::new();
    for &uid in items_map.keys() {
        all_user_ids.insert(uid);
    }
    for &uid in e2e_map.keys() {
        all_user_ids.insert(uid);
    }

    if all_user_ids.is_empty() {
        return Ok(Vec::new());
    }

    // --- Load display names from users table ---
    let mut name_map: HashMap<i64, String> = HashMap::new();
    {
        let mut stmt = conn.prepare("SELECT id, display_name FROM users")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let name: String = row.get(1)?;
            name_map.insert(id, name);
        }
    }

    // --- Assemble results ---
    let mut out: Vec<SyncUserSummary> = all_user_ids
        .into_iter()
        .map(|user_id| {
            let display_name = name_map
                .get(&user_id)
                .cloned()
                .unwrap_or_else(|| format!("#{}", user_id));

            let (total_items, live_items, tombstones, total_bytes, categories, last_modified) =
                items_map
                    .get(&user_id)
                    .cloned()
                    .unwrap_or_else(|| (0, 0, 0, 0, String::new(), String::new()));

            let (e2e_enabled, e2e_salt_prefix, e2e_iterations, e2e_created_at) =
                if let Some((salt, iters, created)) = e2e_map.get(&user_id) {
                    let prefix = if salt.len() >= 8 {
                        salt[..8].to_string()
                    } else {
                        salt.clone()
                    };
                    (true, prefix, *iters, created.clone())
                } else {
                    (false, "\u{2014}".to_string(), 0, String::new())
                };

            SyncUserSummary {
                user_id,
                display_name,
                total_items,
                live_items,
                tombstones,
                total_bytes,
                categories,
                last_modified,
                e2e_enabled,
                e2e_salt_prefix,
                e2e_iterations,
                e2e_created_at,
            }
        })
        .collect();

    // Sort by total_items descending.
    out.sort_by(|a, b| b.total_items.cmp(&a.total_items));

    Ok(out)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn format_bytes_mb(bytes: i64) -> String {
    format!("{:.2}", bytes as f64 / 1_048_576.0)
}

fn format_uptime(secs: i64) -> String {
    if secs <= 0 {
        return "—".to_string();
    }
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    if days > 0 {
        format!("{}d {}h", days, hours)
    } else if hours > 0 {
        format!("{}h {}m", hours, mins)
    } else {
        format!("{}m", mins)
    }
}

/// Convert an RFC 3339 timestamp string into a human-readable relative time.
/// Returns strings like "just now", "5m ago", "2h ago", "3d ago".
fn relative_time(rfc3339: &str) -> String {
    use chrono::{DateTime, Utc};

    let Ok(dt) = DateTime::parse_from_rfc3339(rfc3339) else {
        // SQLite datetime() format: "2024-01-15 10:30:00" — try parsing as that.
        // Append +00:00 and try again.
        let with_tz = format!("{}+00:00", rfc3339.trim().replace(' ', "T"));
        let Ok(dt2) = DateTime::parse_from_rfc3339(&with_tz) else {
            return rfc3339.to_string();
        };
        let secs = Utc::now()
            .signed_duration_since(dt2.with_timezone(&Utc))
            .num_seconds();
        return format_relative_secs(secs);
    };

    let secs = Utc::now()
        .signed_duration_since(dt.with_timezone(&Utc))
        .num_seconds();
    format_relative_secs(secs)
}

fn format_relative_secs(secs: i64) -> String {
    if secs < 60 {
        "just now".to_string()
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

// ---------------------------------------------------------------------------
// HTML rendering
// ---------------------------------------------------------------------------

fn render_html(
    summary: &SummaryStats,
    releases: &[ReleaseEntry],
    devices: &[UnifiedDevice],
    telemetry: &[TelemetryEntry],
    users: &[UserEntry],
    sync_users: &[SyncUserSummary],
) -> String {
    let style = r#"
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background: #0d0d1a;
            color: #e0e0e0;
            font-family: 'Segoe UI', system-ui, sans-serif;
            font-size: 14px;
            line-height: 1.5;
        }
        header {
            background: #12122a;
            border-bottom: 1px solid #2a2a4a;
            padding: 16px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        header h1 { font-size: 18px; color: #a0a8ff; letter-spacing: 0.05em; }
        header .refresh-note { font-size: 12px; color: #606080; }
        main { padding: 24px; max-width: 1600px; margin: 0 auto; }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 12px;
            margin-bottom: 32px;
        }
        .stat-card {
            background: #12122a;
            border: 1px solid #2a2a4a;
            border-radius: 6px;
            padding: 16px;
            text-align: center;
        }
        .stat-card.highlight { border-color: #4040a0; }
        .stat-card .value {
            font-size: 28px;
            font-weight: 700;
            color: #a0a8ff;
            font-variant-numeric: tabular-nums;
        }
        .stat-card .value.green { color: #60d080; }
        .stat-card .label { color: #888; font-size: 12px; margin-top: 4px; text-transform: uppercase; }
        .versions-card {
            background: #12122a;
            border: 1px solid #2a2a4a;
            border-radius: 6px;
            padding: 16px;
        }
        .versions-card .label { color: #888; font-size: 12px; text-transform: uppercase; margin-bottom: 8px; }
        .versions-card .ver-row { display: flex; justify-content: space-between; padding: 2px 0; }
        .versions-card .plat { color: #9090c0; font-family: monospace; font-size: 12px; }
        .versions-card .ver  { color: #a0a8ff; font-family: monospace; font-size: 13px; font-weight: 600; }
        section { margin-bottom: 40px; }
        section h2 {
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: #7070a0;
            border-bottom: 1px solid #2a2a4a;
            padding-bottom: 8px;
            margin-bottom: 12px;
        }
        .table-wrap { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th {
            background: #12122a;
            color: #7080c0;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            padding: 8px 12px;
            text-align: left;
            white-space: nowrap;
            border-bottom: 1px solid #2a2a4a;
        }
        td {
            padding: 7px 12px;
            border-bottom: 1px solid #1a1a30;
            vertical-align: top;
            white-space: nowrap;
        }
        tr:hover td { background: #141428; }
        .mono { font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; color: #c0c8ff; }
        .dim { color: #606080; }
        .reltime { color: #8080b0; font-size: 12px; }
        .tag {
            display: inline-block;
            background: #1e1e40;
            border: 1px solid #3a3a6a;
            border-radius: 3px;
            padding: 1px 6px;
            font-size: 11px;
            color: #9090c0;
            font-family: monospace;
        }
        .tag.green { border-color: #2a5a3a; color: #60d080; background: #0d2018; }
        .devid { font-family: 'Consolas', 'Courier New', monospace; font-size: 11px; color: #7080a0; }
        .fps  { color: #a0d0a0; font-family: monospace; font-size: 12px; }
        .empty { color: #444; font-style: italic; padding: 16px 12px; }
        .sub { font-size: 11px; color: #606080; margin-top: 2px; }
    "#;

    // Summary grid
    let version_rows: String = if summary.latest_versions.is_empty() {
        "<div class=\"dim\" style=\"font-size:12px;\">No releases yet</div>".to_string()
    } else {
        summary
            .latest_versions
            .iter()
            .map(|(p, v)| {
                format!(
                    "<div class=\"ver-row\">\
                        <span class=\"plat\">{}</span>\
                        <span class=\"ver\">{}</span>\
                    </div>",
                    esc(p),
                    esc(v)
                )
            })
            .collect()
    };

    let summary_html = format!(
        r#"<div class="summary-grid">
            <div class="stat-card highlight">
                <div class="value">{unique_devices}</div>
                <div class="label">Unique Devices</div>
                <div class="sub">seen via telemetry</div>
            </div>
            <div class="stat-card">
                <div class="value">{registered_devices}</div>
                <div class="label">Registered</div>
                <div class="sub">sent heartbeat</div>
            </div>
            <div class="stat-card">
                <div class="value green">{active_24h}</div>
                <div class="label">Active 24h</div>
                <div class="sub">recent telemetry</div>
            </div>
            <div class="stat-card">
                <div class="value">{telemetry}</div>
                <div class="label">Telemetry Records</div>
            </div>
            <div class="stat-card">
                <div class="value">{releases}</div>
                <div class="label">Releases</div>
            </div>
            <div class="stat-card">
                <div class="value">{users}</div>
                <div class="label">Users</div>
            </div>
            <div class="stat-card">
                <div class="value">{total_sync_items}</div>
                <div class="label">Sync Items</div>
            </div>
            <div class="stat-card">
                <div class="value">{sync_size_mb} MB</div>
                <div class="label">Sync Size</div>
            </div>
            <div class="stat-card">
                <div class="value">{syncing_users}</div>
                <div class="label">Syncing Users</div>
            </div>
            <div class="stat-card">
                <div class="value green">{e2e_users}</div>
                <div class="label">E2E Enabled</div>
            </div>
            <div class="versions-card">
                <div class="label">Latest per Platform</div>
                {version_rows}
            </div>
        </div>"#,
        unique_devices = summary.unique_devices,
        registered_devices = summary.registered_devices,
        active_24h = summary.active_last_24h,
        telemetry = summary.total_telemetry,
        releases = summary.total_releases,
        users = summary.total_users,
        total_sync_items = summary.total_sync_items,
        sync_size_mb = format_bytes_mb(summary.total_sync_bytes),
        syncing_users = summary.syncing_users,
        e2e_users = summary.e2e_users,
        version_rows = version_rows,
    );

    // Releases table
    let releases_rows: String = if releases.is_empty() {
        "<tr><td class=\"empty\" colspan=\"5\">No releases</td></tr>".to_string()
    } else {
        releases
            .iter()
            .map(|r| {
                format!(
                    "<tr>\
                        <td><span class=\"tag\">{platform}</span></td>\
                        <td class=\"mono\">{version}</td>\
                        <td class=\"mono\">{size} MB</td>\
                        <td class=\"dim\">{notes}</td>\
                        <td class=\"reltime\" title=\"{raw}\">{rel}</td>\
                    </tr>",
                    platform = esc(&r.platform),
                    version = esc(&r.version),
                    size = format_bytes_mb(r.file_size),
                    notes = esc(&r.release_notes),
                    raw = esc(&r.created_at),
                    rel = esc(&relative_time(&r.created_at)),
                )
            })
            .collect()
    };

    // Unified Devices table
    let devices_rows: String = if devices.is_empty() {
        "<tr><td class=\"empty\" colspan=\"13\">No devices seen yet</td></tr>".to_string()
    } else {
        devices
            .iter()
            .map(|d| {
                let short_id = if d.device_id.len() >= 8 {
                    &d.device_id[..8]
                } else {
                    &d.device_id
                };

                let name_cell = if d.device_name.is_empty() {
                    "<span class=\"dim\">—</span>".to_string()
                } else {
                    esc(&d.device_name)
                };

                let heartbeats_cell = if d.total_heartbeats > 0 {
                    format!(
                        "<span class=\"tag green\">{}</span>",
                        d.total_heartbeats
                    )
                } else {
                    "<span class=\"dim\">—</span>".to_string()
                };

                let fps_cell = if d.avg_fps > 0.0 {
                    format!("<span class=\"fps\">{:.0}</span>", d.avg_fps)
                } else {
                    "<span class=\"dim\">—</span>".to_string()
                };

                let screen_cell = if d.screen.is_empty() {
                    "<span class=\"dim\">—</span>".to_string()
                } else {
                    format!("<span class=\"mono\">{}</span>", esc(&d.screen))
                };

                let gpu_cell = if d.gpu_name.is_empty() {
                    "<span class=\"dim\">—</span>".to_string()
                } else {
                    format!(
                        "<span class=\"dim\" style=\"font-size:11px;\">{}</span>",
                        esc(&d.gpu_name)
                    )
                };

                let users_cell = if d.linked_users.is_empty() {
                    "<span class=\"dim\">—</span>".to_string()
                } else {
                    d.linked_users
                        .iter()
                        .map(|(name, _id)| format!("<span class=\"tag\">{}</span> ", esc(name)))
                        .collect()
                };

                format!(
                    "<tr>\
                        <td><span class=\"devid\" title=\"{full_id}\">{short_id}</span></td>\
                        <td>{name_cell}</td>\
                        <td class=\"mono\">{app_version}</td>\
                        <td><span class=\"tag\">{os}</span></td>\
                        <td class=\"mono\">{arch}</td>\
                        <td>{screen_cell}</td>\
                        <td>{fps_cell}</td>\
                        <td>{gpu_cell}</td>\
                        <td class=\"mono\">{uptime}</td>\
                        <td class=\"reltime\" title=\"{raw_ts}\">{rel_ts}</td>\
                        <td class=\"mono\">{telemetry_count}</td>\
                        <td>{heartbeats_cell}</td>\
                        <td>{users_cell}</td>\
                    </tr>",
                    full_id = esc(&d.device_id),
                    short_id = esc(short_id),
                    name_cell = name_cell,
                    app_version = esc(&d.app_version),
                    os = esc(&d.os),
                    arch = esc(&d.arch),
                    screen_cell = screen_cell,
                    fps_cell = fps_cell,
                    gpu_cell = gpu_cell,
                    uptime = format_uptime(d.max_uptime_secs),
                    raw_ts = esc(&d.last_seen),
                    rel_ts = esc(&relative_time(&d.last_seen)),
                    telemetry_count = d.telemetry_count,
                    heartbeats_cell = heartbeats_cell,
                    users_cell = users_cell,
                )
            })
            .collect()
    };

    // Telemetry table (last 50)
    let telemetry_rows: String = if telemetry.is_empty() {
        "<tr><td class=\"empty\" colspan=\"13\">No telemetry</td></tr>".to_string()
    } else {
        telemetry
            .iter()
            .map(|t| {
                let dev_id_cell = match &t.device_id {
                    Some(id) if !id.is_empty() => {
                        let short = if id.len() >= 8 { &id[..8] } else { id.as_str() };
                        format!(
                            "<span class=\"devid\" title=\"{full}\">{short}</span>",
                            full = esc(id),
                            short = esc(short),
                        )
                    }
                    _ => "<span class=\"dim\">—</span>".to_string(),
                };

                format!(
                    "<tr>\
                        <td>{dev_id_cell}</td>\
                        <td class=\"reltime\" title=\"{raw_ts}\">{rel_ts}</td>\
                        <td class=\"mono\">{app_version}</td>\
                        <td><span class=\"tag\">{os}</span></td>\
                        <td class=\"mono\">{arch}</td>\
                        <td class=\"dim\" style=\"max-width:180px;overflow:hidden;text-overflow:ellipsis;\">{gpu_name}</td>\
                        <td class=\"mono\">{screen_width}x{screen_height}</td>\
                        <td class=\"fps\">{avg_fps:.0}</td>\
                        <td class=\"mono\">{uptime}</td>\
                        <td class=\"mono\">{connector_count}</td>\
                        <td class=\"mono\">{window_count}</td>\
                        <td class=\"mono\">{ws_connections}</td>\
                        <td class=\"mono\">{total_bars}</td>\
                    </tr>",
                    dev_id_cell = dev_id_cell,
                    raw_ts = esc(&t.received_at),
                    rel_ts = esc(&relative_time(&t.received_at)),
                    app_version = esc(&t.app_version),
                    os = esc(&t.os),
                    arch = esc(&t.arch),
                    gpu_name = esc(&t.gpu_name),
                    screen_width = t.screen_width,
                    screen_height = t.screen_height,
                    avg_fps = t.avg_fps,
                    uptime = format_uptime(t.uptime_secs),
                    connector_count = t.connector_count,
                    window_count = t.window_count,
                    ws_connections = t.ws_connections,
                    total_bars = t.total_bars,
                )
            })
            .collect()
    };

    // Users table
    let users_rows: String = if users.is_empty() {
        "<tr><td class=\"empty\" colspan=\"6\">No users</td></tr>".to_string()
    } else {
        users
            .iter()
            .map(|u| {
                // Render providers as individual tags.
                let providers_html: String = if u.providers.is_empty() {
                    "<span class=\"dim\">—</span>".to_string()
                } else {
                    u.providers
                        .split(", ")
                        .map(|p| format!("<span class=\"tag\">{}</span> ", esc(p)))
                        .collect()
                };
                let short_public_id = if u.public_id.len() >= 8 {
                    &u.public_id[..8]
                } else {
                    &u.public_id
                };
                let devices_html: String = if u.linked_devices.is_empty() {
                    "<span class=\"dim\">standalone</span>".to_string()
                } else {
                    u.linked_devices
                        .iter()
                        .map(|name| format!("<span class=\"tag green\">{}</span> ", esc(name)))
                        .collect()
                };
                format!(
                    "<tr>\
                        <td class=\"mono\">{id}</td>\
                        <td><span class=\"devid\" title=\"{full_pub}\">{short_pub}</span></td>\
                        <td>{display_name}</td>\
                        <td>{providers_html}</td>\
                        <td>{devices_html}</td>\
                        <td class=\"reltime\" title=\"{raw}\">{rel}</td>\
                    </tr>",
                    id = u.id,
                    full_pub = esc(&u.public_id),
                    short_pub = esc(short_public_id),
                    display_name = esc(&u.display_name),
                    providers_html = providers_html,
                    devices_html = devices_html,
                    raw = esc(&u.created_at),
                    rel = esc(&relative_time(&u.created_at)),
                )
            })
            .collect()
    };

    // Cloud Sync table rows
    let sync_rows: String = if sync_users.is_empty() {
        "<tr><td class=\"empty\" colspan=\"11\">No sync data yet</td></tr>".to_string()
    } else {
        sync_users
            .iter()
            .map(|s| {
                let e2e_cell = if s.e2e_enabled {
                    "<span class=\"tag green\">Yes</span>".to_string()
                } else {
                    "<span class=\"dim\">\u{2014}</span>".to_string()
                };

                let salt_cell = if s.e2e_enabled {
                    format!("<span class=\"mono\">{}</span>", esc(&s.e2e_salt_prefix))
                } else {
                    "<span class=\"dim\">\u{2014}</span>".to_string()
                };

                let iters_cell = if s.e2e_enabled {
                    format!("<span class=\"mono\">{}</span>", s.e2e_iterations)
                } else {
                    "<span class=\"dim\">\u{2014}</span>".to_string()
                };

                let e2e_since_cell = if s.e2e_enabled && !s.e2e_created_at.is_empty() {
                    format!(
                        "<span class=\"reltime\" title=\"{}\">{}</span>",
                        esc(&s.e2e_created_at),
                        esc(&relative_time(&s.e2e_created_at))
                    )
                } else {
                    "<span class=\"dim\">\u{2014}</span>".to_string()
                };

                let last_sync_cell = if s.last_modified.is_empty() {
                    "<span class=\"dim\">\u{2014}</span>".to_string()
                } else {
                    format!(
                        "<span class=\"reltime\" title=\"{}\">{}</span>",
                        esc(&s.last_modified),
                        esc(&relative_time(&s.last_modified))
                    )
                };

                let cats_cell: String = if s.categories.is_empty() {
                    "<span class=\"dim\">\u{2014}</span>".to_string()
                } else {
                    s.categories
                        .split(',')
                        .map(|c| format!("<span class=\"tag\">{}</span> ", esc(c.trim())))
                        .collect()
                };

                format!(
                    "<tr>\
                        <td class=\"mono\">{user_id}</td>\
                        <td>{display_name}</td>\
                        <td class=\"mono\">{live}</td>\
                        <td class=\"mono\">{tombstones}</td>\
                        <td class=\"mono\">{size_mb} MB</td>\
                        <td>{cats_cell}</td>\
                        <td>{last_sync_cell}</td>\
                        <td>{e2e_cell}</td>\
                        <td>{salt_cell}</td>\
                        <td>{iters_cell}</td>\
                        <td>{e2e_since_cell}</td>\
                    </tr>",
                    user_id = s.user_id,
                    display_name = esc(&s.display_name),
                    live = s.live_items,
                    tombstones = s.tombstones,
                    size_mb = format_bytes_mb(s.total_bytes),
                    cats_cell = cats_cell,
                    last_sync_cell = last_sync_cell,
                    e2e_cell = e2e_cell,
                    salt_cell = salt_cell,
                    iters_cell = iters_cell,
                    e2e_since_cell = e2e_since_cell,
                )
            })
            .collect()
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>mylittlechart-server admin</title>
<style>{style}</style>
</head>
<body>
<header>
    <h1>mylittlechart-server &mdash; admin dashboard</h1>
    <span class="refresh-note">auto-refresh every 30s</span>
</header>
<main>
{summary_html}
<section>
    <h2>Releases</h2>
    <div class="table-wrap">
    <table>
        <thead><tr>
            <th>Platform</th><th>Version</th><th>Size (MB)</th><th>Notes</th><th>Uploaded</th>
        </tr></thead>
        <tbody>{releases_rows}</tbody>
    </table>
    </div>
</section>
<section>
    <h2>Devices ({device_count})</h2>
    <div class="table-wrap">
    <table>
        <thead><tr>
            <th>Device ID</th><th>Name</th><th>Version</th><th>OS</th><th>Arch</th>
            <th>Screen</th><th>FPS</th><th>GPU</th><th>Max Uptime</th><th>Last Seen</th>
            <th>Telemetry</th><th>Heartbeats</th><th>Users</th>
        </tr></thead>
        <tbody>{devices_rows}</tbody>
    </table>
    </div>
</section>
<section>
    <h2>Telemetry (last 50)</h2>
    <div class="table-wrap">
    <table>
        <thead><tr>
            <th>Device</th><th>Received</th><th>Version</th><th>OS</th><th>Arch</th><th>GPU</th>
            <th>Screen</th><th>FPS</th><th>Uptime</th>
            <th>Connectors</th><th>Windows</th><th>WS Conns</th><th>Total Bars</th>
        </tr></thead>
        <tbody>{telemetry_rows}</tbody>
    </table>
    </div>
</section>
<section>
    <h2>Users</h2>
    <div class="table-wrap">
    <table>
        <thead><tr>
            <th>ID</th><th>Public ID</th><th>Name</th><th>Linked Providers</th><th>Devices</th><th>Registered</th>
        </tr></thead>
        <tbody>{users_rows}</tbody>
    </table>
    </div>
</section>
<section>
    <h2>Cloud Sync ({sync_user_count})</h2>
    <div class="table-wrap">
    <table>
        <thead><tr>
            <th>User ID</th><th>Name</th><th>Live Items</th><th>Tombstones</th><th>Size (MB)</th>
            <th>Categories</th><th>Last Sync</th><th>E2E</th><th>Salt</th><th>Iterations</th><th>E2E Since</th>
        </tr></thead>
        <tbody>{sync_rows}</tbody>
    </table>
    </div>
</section>
</main>
</body>
</html>"#,
        style = style,
        summary_html = summary_html,
        releases_rows = releases_rows,
        device_count = devices.len(),
        devices_rows = devices_rows,
        telemetry_rows = telemetry_rows,
        users_rows = users_rows,
        sync_user_count = sync_users.len(),
        sync_rows = sync_rows,
    )
}

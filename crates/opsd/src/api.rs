//! HTTP API (axum, 127.0.0.1:18360) and the supervised background loops.
//!
//! `GET /health` is open; everything under `/api` goes through the bearer
//! middleware (`crate::auth`). Handlers are thin wrappers over `crate::ops`.
//!
//! The router is built through `nemo_service::router::DocRouter`, which
//! records `(method, path, description, auth)` for every route as it is
//! added and hands the list back alongside the real `axum::Router` —
//! `crate::registration::service_manifest` uses that list to describe this
//! daemon to d-watchdog, so a route can never drift from the manifest the
//! way `.nemo-services/mlc-opsd.toml` did (see
//! `nemo/docs/d-watchdog/plans/service-registration-and-pid-ownership-2026-09-22.md`).

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json, Router,
};
use nemo_service::manifest::Endpoint;
use nemo_service::router::{DocRouter, RouteDoc};
use serde::Deserialize;

use crate::ops;
use crate::state::OpsdState;

/// Re-spawn a background loop on any task exit (panic / unexpected return)
/// with bounded backoff — a single panic must not permanently kill the
/// watch loop. Pattern from mirage operator-box `spawn_supervised`.
fn spawn_supervised<F, Fut>(name: &'static str, state: Arc<OpsdState>, run: F)
where
    F: Fn(Arc<OpsdState>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let mut backoff = std::time::Duration::from_secs(1);
        loop {
            let started = std::time::Instant::now();
            match tokio::spawn(run(state.clone())).await {
                Ok(()) => tracing::error!(loop_name = name, "[supervise] loop returned — respawning"),
                Err(e) => tracing::error!(
                    loop_name = name,
                    err = %e,
                    "[supervise] loop task died — respawning"
                ),
            }
            // Reset backoff when the loop ran a meaningful while — an isolated
            // incident hours apart must not inherit a stale long backoff.
            if started.elapsed() >= std::time::Duration::from_secs(60) {
                backoff = std::time::Duration::from_secs(1);
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(std::time::Duration::from_secs(30));
        }
    });
}

const STATUS_DESC: &str = "One SSH round-trip to control: systemd ActiveState/SubState for \
mlc-server/nginx/nftables/fail2ban, app health, disk/mem, uptime. Read-only, safe.";
const RESTART_DESC: &str = "Body {unit}. Restarts one systemd unit on control — whitelist only: \
mlc-server | nginx | nftables | fail2ban (state::UNIT_WHITELIST); anything else is rejected before a \
command string is built. Drops the unit's traffic/connections for the restart duration.";
const LOGS_DESC: &str = "Journal tail from control (query unit=, default mlc-server; lines=, default 50, \
clamped 1..500 server-side; unit restricted to the same whitelist as /api/restart). Read-only, safe.";
const UNLOCK_DESC: &str = "Boot-unlock: pushes the canonical sqlcipher.key + server.env to control's tmpfs \
(0600, root), starts mlc-server, verifies health. Also the watch loop's own recovery action. Places a live \
secret on the box, even if only in tmpfs.";
const BOX_STATE_DESC: &str = "mlc-server state on control: is the SQLCipher key present in tmpfs, is the \
journal stuck waiting for it. Read-only, safe.";
const DEPLOY_DESC: &str = "Body {path} — local path on the opbox to a musl server binary. Uploads to \
control, sha256-verifies, saves the running binary as .prev, stops/swaps/starts the unit, health-polls \
(30x3s) against the unit's own BIND_ADDR, auto-rolls back to .prev on failure. Replaces the running \
production server binary.";
const RELEASE_PUBLISH_DESC: &str = "Body {path, platform, version, channel, release_notes, signature}. \
Uploads a client release artifact to BOTH public edges, sha256-verifies each, unwinds anything already \
landed if either edge fails, then registers the release manifest row on control (calls the backend's own \
admin-listener /api/admin/register-release over an in-box ssh session). Publishes to production; channel \
defaults to \"stable\" when omitted.";
const BACKUP_NOW_DESC: &str = "Triggers an on-demand DB snapshot on control (systemctl start \
mlc-backup.service) and lists the resulting archive dir. Safe, but touches the box.";
const BACKUP_PULL_DESC: &str = "SFTP-pulls the newest *.db + config-*.tar.gz from control to the opbox \
(E:\\backups\\mlc-c2-1\\), encrypts at rest (AES-256-GCM), prunes to the 30 newest archives. Read-only \
against the box, writes locally; also runs automatically every hour.";
const BACKUP_LIST_DESC: &str =
    "Local listing (names, sizes, mtimes) of the opbox-side encrypted backup archive. Read-only, safe.";
const WATCH_STATE_DESC: &str = "Watch-loop counters: consecutive public-health misses, last intervention \
timestamp, cooldown horizon. Read-only, safe.";
const HEALTH_DESC: &str = "Liveness for d-watchdog. No auth.";

/// The two sub-routers `build_router` composes, plus the endpoint list
/// `DocRouter` recorded while building them — split out from the bearer
/// layer and the live `OpsdState` so the route *shape* (method, path, auth)
/// can be asserted in a test without constructing one (see `tests` below).
struct RouterDocs {
    health: Router<Arc<OpsdState>>,
    api: Router<Arc<OpsdState>>,
    endpoints: Vec<Endpoint>,
}

/// Build the health and (still bearer-unguarded) API sub-routers through
/// `DocRouter`, and the endpoint list that is their by-product. Needs no
/// `OpsdState` value — only its type, since `DocRouter` does not require a
/// live state until `.with_state()` is called, which happens in
/// `build_router`, not here.
fn build_docs() -> RouterDocs {
    let (api, api_endpoints): (Router<Arc<OpsdState>>, Vec<Endpoint>) = DocRouter::<Arc<OpsdState>>::new()
        .get("/status", handle_status, RouteDoc::bearer(STATUS_DESC))
        .post("/restart", handle_restart, RouteDoc::bearer(RESTART_DESC))
        .get("/logs", handle_logs, RouteDoc::bearer(LOGS_DESC))
        .post("/unlock", handle_unlock, RouteDoc::bearer(UNLOCK_DESC))
        .get("/box/state", handle_box_state, RouteDoc::bearer(BOX_STATE_DESC))
        .post("/deploy", handle_deploy, RouteDoc::bearer(DEPLOY_DESC))
        .post(
            "/release/publish",
            handle_release_publish,
            RouteDoc::bearer(RELEASE_PUBLISH_DESC),
        )
        .post("/backup/now", handle_backup_now, RouteDoc::bearer(BACKUP_NOW_DESC))
        .post("/backup/pull", handle_backup_pull, RouteDoc::bearer(BACKUP_PULL_DESC))
        .get("/backup/list", handle_backup_list, RouteDoc::bearer(BACKUP_LIST_DESC))
        .get("/watch/state", handle_watch_state, RouteDoc::bearer(WATCH_STATE_DESC))
        .into_parts();

    let (health, health_endpoints): (Router<Arc<OpsdState>>, Vec<Endpoint>) = DocRouter::<Arc<OpsdState>>::new()
        .get("/health", || async { "ok" }, HEALTH_DESC)
        .into_parts();

    let mut endpoints = health_endpoints;
    endpoints.extend(api_endpoints.into_iter().map(|mut ep| {
        ep.path = format!("/api{}", ep.path);
        ep
    }));

    RouterDocs { health, api, endpoints }
}

/// Assemble the served router: the bearer layer guards only the routes
/// recorded above (`route_layer`, not `layer` — `DocRouter` exposes no
/// `route_layer`, so it is applied to the raw `axum::Router` `into_parts()`
/// handed back, the same way the pre-`DocRouter` code applied it), so an
/// unmapped path under `/api` still 404s without a bearer, exactly as
/// before this conversion.
fn build_router(state: Arc<OpsdState>) -> (Router, Vec<Endpoint>) {
    let docs = build_docs();
    let api = docs.api.route_layer(axum::middleware::from_fn_with_state(
        state.clone(),
        crate::auth::require_bearer,
    ));
    let app = docs.health.nest("/api", api).with_state(state);
    (app, docs.endpoints)
}

pub async fn serve(state: Arc<OpsdState>) -> Result<(), Box<dyn std::error::Error>> {
    spawn_supervised("watch", state.clone(), crate::watch::run_watch_loop);
    // Hourly backup pull — the sole owner of the pull cycle (replaces the
    // Windows Task Scheduler `mlc-backup-pull` task).
    spawn_supervised("backup_pull", state.clone(), crate::backup::run_pull_loop);

    let (app, endpoints) = build_router(state.clone());

    let bind = crate::state::bind_addr();
    tracing::info!("mlc-opsd listening on http://{bind}");
    let listener = tokio::net::TcpListener::bind(&bind).await?;

    // Register with d-watchdog now that the socket is live. `spawn` is
    // synchronous and fire-and-forget (nemo-service/CLAUDE.md's contract:
    // registration can never fail or delay a service's own startup) — no
    // `.await`, no `?` on its result, just a background task handle this
    // function does not need to hold onto.
    let _reassert = nemo_service::register::spawn(
        crate::registration::service_manifest(endpoints),
        nemo_service::register::DEFAULT_REASSERT_INTERVAL,
    );

    axum::serve(listener, app).await?;
    Ok(())
}

fn err_response(e: crate::error::OpsdError) -> axum::response::Response {
    (
        StatusCode::BAD_GATEWAY,
        Json(serde_json::json!({"error": e.to_string()})),
    )
        .into_response()
}

async fn handle_status(State(state): State<Arc<OpsdState>>) -> axum::response::Response {
    match ops::collect_status(&state).await {
        Ok(s) => Json(serde_json::to_value(s).unwrap()).into_response(),
        Err(e) => err_response(e),
    }
}

async fn handle_box_state(State(state): State<Arc<OpsdState>>) -> axum::response::Response {
    match ops::box_state(&state).await {
        Ok(s) => Json(serde_json::to_value(s).unwrap()).into_response(),
        Err(e) => err_response(e),
    }
}

#[derive(Deserialize)]
struct RestartBody {
    unit: String,
}

async fn handle_restart(
    State(state): State<Arc<OpsdState>>,
    Json(body): Json<RestartBody>,
) -> axum::response::Response {
    match ops::restart_unit(&state, &body.unit).await {
        Ok(s) => Json(serde_json::json!({"unit": body.unit, "state": s})).into_response(),
        Err(e) => err_response(e),
    }
}

#[derive(Deserialize)]
struct LogsQuery {
    unit: Option<String>,
    lines: Option<u32>,
}

async fn handle_logs(
    State(state): State<Arc<OpsdState>>,
    Query(q): Query<LogsQuery>,
) -> axum::response::Response {
    let unit = q.unit.unwrap_or_else(|| "mlc-server".to_string());
    let lines = q.lines.unwrap_or(50);
    match ops::logs(&state, &unit, lines).await {
        Ok(text) => Json(serde_json::json!({"unit": unit, "lines": lines, "log": text}))
            .into_response(),
        Err(e) => err_response(e),
    }
}

async fn handle_unlock(State(state): State<Arc<OpsdState>>) -> axum::response::Response {
    match ops::unlock(&state).await {
        Ok(o) => Json(serde_json::to_value(o).unwrap()).into_response(),
        Err(e) => err_response(e),
    }
}

#[derive(Deserialize)]
struct DeployBody {
    /// Local path on the opbox to the musl binary.
    path: String,
}

async fn handle_deploy(
    State(state): State<Arc<OpsdState>>,
    Json(body): Json<DeployBody>,
) -> axum::response::Response {
    match crate::deploy::deploy(&state, std::path::Path::new(&body.path)).await {
        Ok(o) => Json(serde_json::to_value(o).unwrap()).into_response(),
        Err(e) => err_response(e),
    }
}

/// The track a publish lands on when the caller does not say.
///
/// `"stable"`, and it has to be: there is exactly one track now (owner,
/// 2026-09-03 — the client's `dev` channel and its `UPDATE_CHANNEL` override
/// are gone), so a publish that quietly defaulted to `dev` would register a
/// manifest row no client ever asks for. An invisible release is worse than a
/// refused one, because nothing about it looks wrong.
fn default_channel() -> String {
    "stable".to_string()
}

#[derive(Deserialize)]
struct PublishBody {
    /// Local path on the opbox to the release artifact.
    path: String,
    platform: String,
    version: String,
    #[serde(default = "default_channel")]
    channel: String,
    #[serde(default)]
    release_notes: String,
    /// Base64-encoded Ed25519 signature over the artifact bytes.
    #[serde(default)]
    signature: String,
}

async fn handle_release_publish(
    State(state): State<Arc<OpsdState>>,
    Json(body): Json<PublishBody>,
) -> axum::response::Response {
    let req = crate::release::PublishRequest {
        local: std::path::Path::new(&body.path),
        platform: &body.platform,
        version: &body.version,
        channel: &body.channel,
        release_notes: &body.release_notes,
        signature: &body.signature,
    };
    match crate::release::publish(&state, req).await {
        Ok(o) => Json(serde_json::to_value(o).unwrap()).into_response(),
        Err(e) => err_response(e),
    }
}

async fn handle_backup_now(State(state): State<Arc<OpsdState>>) -> axum::response::Response {
    match crate::backup::backup_now(&state).await {
        Ok(listing) => Json(serde_json::json!({"ok": true, "files": listing})).into_response(),
        Err(e) => err_response(e),
    }
}

async fn handle_backup_pull(State(state): State<Arc<OpsdState>>) -> axum::response::Response {
    match crate::backup::backup_pull(&state).await {
        Ok(o) => Json(serde_json::to_value(o).unwrap()).into_response(),
        Err(e) => err_response(e),
    }
}

async fn handle_watch_state(State(state): State<Arc<OpsdState>>) -> axum::response::Response {
    Json(serde_json::to_value(crate::watch::view(&state)).unwrap()).into_response()
}

async fn handle_backup_list(State(state): State<Arc<OpsdState>>) -> axum::response::Response {
    match crate::backup::list_local(&state.backup_pull_dir) {
        Ok(entries) => Json(serde_json::json!({
            "dir": state.backup_pull_dir,
            "entries": entries,
        }))
        .into_response(),
        Err(e) => err_response(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (method, path, auth) for the 12 endpoints that lived in the now-deleted
    /// `.nemo-services/mlc-opsd.toml` — captured here before its deletion so a
    /// route silently dropped (or its auth class silently loosened) from the
    /// `DocRouter` build shows up as a test failure here, instead of a
    /// manifest that quietly drifts from what d-watchdog is told.
    const EXPECTED: &[(&str, &str, &str)] = &[
        ("GET", "/health", "none"),
        ("GET", "/api/status", "bearer"),
        ("POST", "/api/restart", "bearer"),
        ("GET", "/api/logs", "bearer"),
        ("POST", "/api/unlock", "bearer"),
        ("GET", "/api/box/state", "bearer"),
        ("POST", "/api/deploy", "bearer"),
        ("POST", "/api/release/publish", "bearer"),
        ("POST", "/api/backup/now", "bearer"),
        ("POST", "/api/backup/pull", "bearer"),
        ("GET", "/api/backup/list", "bearer"),
        ("GET", "/api/watch/state", "bearer"),
    ];

    #[test]
    fn endpoints_match_the_retired_manifest_file() {
        let docs = build_docs();
        let actual: Vec<(&str, &str, &str)> = docs
            .endpoints
            .iter()
            .map(|e| (e.method.as_str(), e.path.as_str(), e.auth.as_str()))
            .collect();
        assert_eq!(actual, EXPECTED);
    }

    #[test]
    fn endpoint_count_matches_the_retired_manifest_file() {
        let docs = build_docs();
        assert_eq!(docs.endpoints.len(), 12, "mlc-opsd's real endpoint count");
    }
}

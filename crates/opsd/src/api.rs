//! HTTP API (axum, 127.0.0.1:18360) and the supervised background loops.
//!
//! `GET /health` is open; everything under `/api` goes through the bearer
//! middleware (`crate::auth`). Handlers are thin wrappers over `crate::ops`.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
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

pub async fn serve(state: Arc<OpsdState>) -> Result<(), Box<dyn std::error::Error>> {
    spawn_supervised("watch", state.clone(), crate::watch::run_watch_loop);
    // Hourly backup pull — the sole owner of the pull cycle (replaces the
    // Windows Task Scheduler `mlc-backup-pull` task).
    spawn_supervised("backup_pull", state.clone(), crate::backup::run_pull_loop);

    let api = Router::new()
        .route("/status", get(handle_status))
        .route("/restart", post(handle_restart))
        .route("/logs", get(handle_logs))
        .route("/unlock", post(handle_unlock))
        .route("/box/state", get(handle_box_state))
        .route("/deploy", post(handle_deploy))
        .route("/backup/now", post(handle_backup_now))
        .route("/backup/pull", post(handle_backup_pull))
        .route("/backup/list", get(handle_backup_list))
        .route("/watch/state", get(handle_watch_state))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::auth::require_bearer,
        ))
        .with_state(state.clone());

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .nest("/api", api);

    let bind = crate::state::bind_addr();
    tracing::info!("mlc-opsd listening on http://{bind}");
    let listener = tokio::net::TcpListener::bind(&bind).await?;
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

//! mlc-opsd — operator control plane for the mylittlechart.org production
//! box (mlc-utah-1). Standalone infra in the spirit of the mirage
//! operator-box, minus mesh/fleet.
//!
//! `daemon` (default) serves the local HTTP API on 127.0.0.1:18360 and runs
//! the watch loop. The other subcommands are a thin CLI that talks to that
//! API over bearer-authed localhost HTTP — they never ssh anywhere directly.

use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};

mod api;
mod auth;
mod error;
mod ops;
mod ssh;
mod state;
mod watch;

#[derive(Parser)]
#[command(
    name = "mlc-opsd",
    version,
    about = "operator control plane for the mylittlechart.org production box (mlc-utah-1)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve the HTTP API + watch loop (default when no subcommand is given).
    Daemon,
    /// systemd states, app health, disk/mem, uptime of the box.
    Status,
    /// Deliver dbkey + server.env to box tmpfs, start mlc-server, verify.
    Unlock,
    /// Restart a whitelisted unit: mlc-server | nginx | fail2ban.
    Restart { unit: String },
    /// Journal tail (default: mlc-server, 50 lines).
    Logs { unit: Option<String>, lines: Option<u32> },
}

/// Read the daemon API key from the state dir and call the local API.
async fn call_api(
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<(reqwest::StatusCode, String), error::OpsdError> {
    let (state_dir, _) = state::resolve_paths()?;
    let key = std::fs::read_to_string(state_dir.join("api-key"))
        .map_err(|e| error::OpsdError::CanonSecret(format!(
            "read api-key (is the daemon state dir initialized?): {e}"
        )))?;
    let client = reqwest::Client::new();
    let mut req = client
        .request(method, format!("http://{}/api{}", state::BIND_ADDR, path))
        .bearer_auth(key.trim());
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req.send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    Ok((status, text))
}

fn print_response(status: reqwest::StatusCode, text: &str) -> ExitCode {
    // Pretty-print when the body is JSON; pass through otherwise.
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
        Err(_) => println!("{text}"),
    }
    if status.is_success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mlc_opsd=info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd.unwrap_or(Cmd::Daemon) {
        Cmd::Daemon => {
            let state = match state::OpsdState::load() {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    tracing::error!("state init failed: {e}");
                    return ExitCode::FAILURE;
                }
            };
            tracing::info!("state dir: {}", state.state_dir.display());
            if let Err(e) = api::serve(state).await {
                tracing::error!("server error: {e}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Cmd::Status => match call_api(reqwest::Method::GET, "/status", None).await {
            Ok((s, t)) => print_response(s, &t),
            Err(e) => {
                eprintln!("mlc-opsd status: {e}");
                ExitCode::FAILURE
            }
        },
        Cmd::Unlock => match call_api(reqwest::Method::POST, "/unlock", None).await {
            Ok((s, t)) => print_response(s, &t),
            Err(e) => {
                eprintln!("mlc-opsd unlock: {e}");
                ExitCode::FAILURE
            }
        },
        Cmd::Restart { unit } => {
            match call_api(
                reqwest::Method::POST,
                "/restart",
                Some(serde_json::json!({"unit": unit})),
            )
            .await
            {
                Ok((s, t)) => print_response(s, &t),
                Err(e) => {
                    eprintln!("mlc-opsd restart: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::Logs { unit, lines } => {
            let mut path = "/logs".to_string();
            let mut sep = '?';
            if let Some(u) = unit {
                path.push_str(&format!("{sep}unit={u}"));
                sep = '&';
            }
            if let Some(n) = lines {
                path.push_str(&format!("{sep}lines={n}"));
            }
            match call_api(reqwest::Method::GET, &path, None).await {
                Ok((s, t)) => print_response(s, &t),
                Err(e) => {
                    eprintln!("mlc-opsd logs: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

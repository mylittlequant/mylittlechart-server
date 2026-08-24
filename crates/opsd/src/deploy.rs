//! `/api/deploy` — accept a locally-built musl binary and roll it out to the
//! box with health-verified rollback.
//!
//! Control flow (mirage `deploy_apply` pattern, trimmed to one service):
//!   1. Validate the local artifact (exists, >1 MB, not a Windows .exe).
//!   2. SFTP upload to `/opt/mlc/mylittlechart-server.new` (atomic upload —
//!      see `crate::ssh`), then compare local vs remote sha256.
//!   3. Snapshot the live binary to `.prev` (the rollback target).
//!   4. `systemctl stop` → atomic `mv .new` over the live binary → `start`.
//!   5. Poll loopback health up to 30×3s. First HTTP 200 wins.
//!   6. On failure, roll back: `mv .prev` back, start, verify again, and
//!      report the verdict either way.
//!
//! Command builders and the verdict reducer are pure functions, unit-tested
//! without a box; [`deploy`] is the async orchestrator over `crate::ssh`.

use std::path::Path;
use std::sync::Arc;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::OpsdError;
use crate::state::OpsdState;

const REMOTE_BIN: &str = "/opt/mlc/mylittlechart-server";
/// Health poll ceiling after (re)start. Bounds the SLOWEST legitimate boot,
/// never the typical one — a false failure rolls back a good rollout
/// (mirage incident 2026-08-03).
const HEALTH_POLL_ATTEMPTS: u32 = 30;
const HEALTH_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3);

#[derive(Debug, Serialize)]
pub struct DeployOutcome {
    pub ok: bool,
    pub rolled_back: bool,
    pub sha256: String,
    pub size: u64,
    pub steps: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One health observation from the box: HTTP status of the loopback
/// `/health`, or `None` when the probe itself could not produce a status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthProbe {
    Ok,
    Bad(Option<u16>),
}

/// Final verdict of a rollout, reduced from observable evidence only.
///
/// `swap_exit` follows the mirage rule: an SSH channel that closed without
/// an exit status (`None`) is NOT evidence of failure — defer to the health
/// polls, which ask the box directly. (Mirage incident 2026-08-02: a missing
/// exit status read as "restart failed" and rolled back a live service.)
pub fn verdict(
    swap_exit: Option<u32>,
    health: HealthProbe,
    rollback_health: Option<HealthProbe>,
) -> (bool, bool, Option<String>) {
    if let Some(code) = swap_exit {
        if code != 0 {
            return (false, false, Some(format!("swap command exited {code}")));
        }
    }
    match (health, rollback_health) {
        (HealthProbe::Ok, _) => (true, false, None),
        (HealthProbe::Bad(got), Some(HealthProbe::Ok)) => (
            false,
            true,
            Some(format!(
                "health never came up (last: {got:?}); rolled back, previous binary verified healthy"
            )),
        ),
        (HealthProbe::Bad(got), Some(HealthProbe::Bad(rb))) => (
            false,
            true,
            Some(format!(
                "health never came up (last: {got:?}); rollback attempted but previous binary also unhealthy (last: {rb:?})"
            )),
        ),
        (HealthProbe::Bad(got), None) => (
            false,
            true,
            Some(format!(
                "health never came up (last: {got:?}); rollback itself failed — box needs manual intervention"
            )),
        ),
    }
}

/// Validate the operator-supplied local artifact path. Rejects Windows
/// binaries (`.exe`) — the box wants a linux musl ELF, and deploying a
/// Windows build by mistake would take prod down until rollback.
pub fn validate_local_binary(path: &Path) -> Result<u64, OpsdError> {
    let meta = std::fs::metadata(path)
        .map_err(|e| OpsdError::Remote(format!("binary {}: {e}", path.display())))?;
    if !meta.is_file() {
        return Err(OpsdError::Remote(format!("{} is not a file", path.display())));
    }
    if meta.len() < 1024 * 1024 {
        return Err(OpsdError::Remote(format!(
            "{} is suspiciously small ({} bytes) — not a musl server binary?",
            path.display(),
            meta.len()
        )));
    }
    if path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("exe"))
        .unwrap_or(false)
    {
        return Err(OpsdError::Remote(format!(
            "{} has a .exe extension — refusing to deploy a Windows binary to the linux box",
            path.display()
        )));
    }
    Ok(meta.len())
}

/// `sha256sum` of a remote path, parsed by [`parse_remote_sha256`].
pub fn remote_sha256_cmd(remote_path: &str) -> String {
    format!("sha256sum '{remote_path}' | awk '{{print $1}}'")
}

/// Parse `sha256sum | awk` stdout into a lowercase hex digest.
pub fn parse_remote_sha256(stdout: &str) -> Option<String> {
    let s = stdout.trim();
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(s.to_lowercase())
    } else {
        None
    }
}

/// Snapshot the live binary as the rollback target (no-op when absent).
pub fn save_prev_cmd() -> String {
    format!("cp -f '{REMOTE_BIN}' '{REMOTE_BIN}.prev' 2>/dev/null || true")
}

/// stop → atomic mv → start. `mv` within one filesystem is atomic, so a
/// concurrent reader never sees a half-written binary.
pub fn swap_cmd() -> String {
    format!(
        "systemctl stop mlc-server && mv '{REMOTE_BIN}.new' '{REMOTE_BIN}' && systemctl start mlc-server"
    )
}

/// Restore the snapshot over the live binary and start.
pub fn rollback_cmd() -> String {
    format!(
        "systemctl stop mlc-server; mv -f '{REMOTE_BIN}.prev' '{REMOTE_BIN}' && systemctl start mlc-server"
    )
}

/// Loopback health probe on the box — the app is bound to 127.0.0.1 only.
pub fn health_cmd() -> String {
    format!(
        "curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 {}",
        crate::state::APP_HEALTH_REMOTE
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Poll loopback health until 200 or the attempt ceiling.
async fn poll_health(session: &crate::ssh::SshSession, attempts: u32) -> HealthProbe {
    let mut last = HealthProbe::Bad(None);
    for _ in 0..attempts {
        tokio::time::sleep(HEALTH_POLL_INTERVAL).await;
        match session.exec(&health_cmd()).await {
            Ok(out) => {
                let code = out.stdout.trim().parse::<u16>().ok();
                if code == Some(200) {
                    return HealthProbe::Ok;
                }
                last = HealthProbe::Bad(code);
            }
            Err(e) => {
                tracing::warn!("deploy health poll ssh error: {e}");
                last = HealthProbe::Bad(None);
            }
        }
    }
    last
}

pub async fn deploy(state: &Arc<OpsdState>, local: &Path) -> Result<DeployOutcome, OpsdError> {
    let mut steps: Vec<String> = Vec::new();
    let size = validate_local_binary(local)?;
    let bytes = std::fs::read(local)?;
    let sha = sha256_hex(&bytes);
    steps.push(format!("local artifact ok: {} bytes sha256={sha}", bytes.len()));

    let key_pem = std::fs::read(&state.box_cfg.ssh_key_path)?;
    let session = crate::ssh::open_session(&crate::ssh::SshOptions {
        host: &state.box_cfg.host,
        port: state.box_cfg.port,
        user: &state.box_cfg.user,
        key_pem: &key_pem,
    })
    .await?;

    let remote_new = format!("{REMOTE_BIN}.new");
    session.upload(&bytes, &remote_new, 0o755).await?;
    steps.push("uploaded to /opt/mlc/mylittlechart-server.new".into());

    let remote_sha = session.exec(&remote_sha256_cmd(&remote_new)).await?;
    let remote_sha = parse_remote_sha256(&remote_sha.stdout)
        .ok_or_else(|| OpsdError::Remote(format!("unparsable remote sha256: {:?}", remote_sha.stdout)))?;
    if remote_sha != sha {
        let _ = session.exec(&format!("rm -f '{remote_new}'")).await;
        return Err(OpsdError::Remote(format!(
            "sha256 mismatch: local {sha} != remote {remote_sha}"
        )));
    }
    steps.push("sha256 verified local==remote".into());

    session.exec(&save_prev_cmd()).await?;
    steps.push("previous binary saved as .prev".into());

    let swap = session.exec(&swap_cmd()).await?;
    if swap.exit_code == Some(0) {
        steps.push("swapped and started".into());
    } else {
        steps.push(format!(
            "swap exit {:?} — deferring to health evidence",
            swap.exit_code
        ));
    }

    let health = poll_health(&session, HEALTH_POLL_ATTEMPTS).await;
    let mut rollback_health = None;
    if health != HealthProbe::Ok {
        tracing::error!("deploy health check failed — rolling back");
        let rb = session.exec(&rollback_cmd()).await;
        rollback_health = match rb {
            Ok(out) if out.exit_code == Some(0) || out.exit_code.is_none() => {
                Some(poll_health(&session, HEALTH_POLL_ATTEMPTS).await)
            }
            Ok(out) => {
                steps.push(format!("rollback command exited {:?}", out.exit_code));
                None
            }
            Err(e) => {
                steps.push(format!("rollback ssh error: {e}"));
                None
            }
        };
    }

    let (ok, rolled_back, error) = verdict(swap.exit_code, health, rollback_health);
    steps.push(format!("verdict: ok={ok} rolled_back={rolled_back}"));
    state.record_build(&local.to_string_lossy(), size);
    state.audit(
        "deploy",
        &format!(
            "ok={ok} rolled_back={rolled_back} sha256={sha} size={size} err={}",
            error.as_deref().unwrap_or("-")
        ),
    );
    Ok(DeployOutcome {
        ok,
        rolled_back,
        sha256: sha,
        size,
        steps,
        error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_ok_when_health_up() {
        let (ok, rb, err) = verdict(Some(0), HealthProbe::Ok, None);
        assert!(ok && !rb && err.is_none());
    }

    #[test]
    fn verdict_defers_to_health_on_missing_exit_status() {
        // SSH closed without exit-status but the service came up: success.
        let (ok, rb, _) = verdict(None, HealthProbe::Ok, None);
        assert!(ok && !rb);
    }

    #[test]
    fn verdict_rollback_when_health_dead_and_prev_ok() {
        let (ok, rb, err) = verdict(Some(0), HealthProbe::Bad(Some(000)), Some(HealthProbe::Ok));
        assert!(!ok && rb);
        assert!(err.unwrap().contains("rolled back"));
    }

    #[test]
    fn verdict_rollback_also_dead() {
        let (ok, rb, err) =
            verdict(Some(0), HealthProbe::Bad(None), Some(HealthProbe::Bad(Some(500))));
        assert!(!ok && rb);
        assert!(err.unwrap().contains("also unhealthy"));
    }

    #[test]
    fn verdict_swap_failed_no_health_verdict() {
        let (ok, rb, err) = verdict(Some(1), HealthProbe::Ok, None);
        assert!(!ok && !rb && err.unwrap().contains("exited 1"));
    }

    #[test]
    fn parse_remote_sha256_accepts_clean_hex() {
        let s = "ab".repeat(32);
        assert_eq!(parse_remote_sha256(&format!("{s}\n")), Some(s));
        assert_eq!(parse_remote_sha256("not a sha"), None);
        assert_eq!(parse_remote_sha256(""), None);
    }

    #[test]
    fn command_builders_are_shell_safe_shapes() {
        assert!(swap_cmd().contains("systemctl stop mlc-server && mv"));
        assert!(rollback_cmd().contains("mv -f"));
        assert!(save_prev_cmd().contains(".prev"));
        assert!(health_cmd().contains("127.0.0.1:19200/health"));
    }
}

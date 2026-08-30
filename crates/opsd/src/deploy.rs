//! `/api/deploy` — accept a locally-built musl binary and roll it out to the
//! box with health-verified rollback.
//!
//! Control flow (mirage `deploy_apply` pattern, trimmed to one service):
//!   1. Validate the local artifact (exists, >1 MB, not a Windows .exe).
//!   2. SFTP upload to `/opt/mlc/mylittlechart-server.new` (atomic upload —
//!      see `crate::ssh`), then compare local vs remote sha256.
//!   3. Snapshot the live binary to `.prev` (the rollback target).
//!   4. `systemctl stop` → atomic `mv .new` over the live binary → `start`.
//!   5. Poll health up to 30×3s, against the address the unit actually binds.
//!      First HTTP 200 wins.
//!   6. On failure, roll back: `mv .prev` back, start, verify again. If the
//!      previous binary fails the same probe, undo the rollback — a rollback
//!      that restores nothing has only discarded the newer artifact — and
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
/// `forward_health` is the observation after a rollback that did NOT restore
/// health and was therefore undone — see [`restore_forward_cmd`].
pub fn verdict(
    swap_exit: Option<u32>,
    health: HealthProbe,
    rollback_health: Option<HealthProbe>,
    forward_health: Option<HealthProbe>,
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
        // Both binaries fail the same probe, so the probe or the box is the
        // suspect, not the artifact — and the rollback restored nothing while
        // discarding the newer build. The new binary is put back and the
        // rollout is still reported as failed, because it was: a human has to
        // look. (2026-08-30: this arm rolled back over a completed one-way
        // database migration after a probe that pointed at the wrong address,
        // leaving the old binary running against a schema it did not expect.)
        (HealthProbe::Bad(got), Some(HealthProbe::Bad(rb))) => (
            false,
            false,
            Some(format!(
                "health never came up (last: {got:?}) and the previous binary also failed the same probe (last: {rb:?}) — \
                 the probe or the box is suspect, not the artifact; new binary kept in place (health after restore: {forward:?}). \
                 Investigate before deploying again.",
                forward = forward_health
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

/// Validate that a local artifact exists, is a regular file, and is not
/// suspiciously small. Shared by [`validate_local_binary`] (the linux musl
/// server binary this module deploys) and `release::validate_local_artifact`
/// (client release artifacts across platforms, which — unlike the server
/// binary — legitimately includes `.exe` on win64).
pub fn validate_artifact_size(path: &Path) -> Result<u64, OpsdError> {
    let meta = std::fs::metadata(path)
        .map_err(|e| OpsdError::Remote(format!("artifact {}: {e}", path.display())))?;
    if !meta.is_file() {
        return Err(OpsdError::Remote(format!("{} is not a file", path.display())));
    }
    if meta.len() < 1024 * 1024 {
        return Err(OpsdError::Remote(format!(
            "{} is suspiciously small ({} bytes)",
            path.display(),
            meta.len()
        )));
    }
    Ok(meta.len())
}

/// Validate the operator-supplied local artifact path for a [`deploy`]
/// roll-out. Rejects Windows binaries (`.exe`) on top of the shared
/// [`validate_artifact_size`] checks — the box wants a linux musl ELF, and
/// deploying a Windows build by mistake would take prod down until rollback.
/// This rejection is specific to the server binary this module deploys and
/// must NOT apply to release artifacts (a win64 client release IS an .exe) —
/// see `release::validate_local_artifact`, which shares the size check only.
pub fn validate_local_binary(path: &Path) -> Result<u64, OpsdError> {
    let size = validate_artifact_size(path)?;
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
    Ok(size)
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
/// concurrent reader never sees a half-written binary. Tier-2 integration:
/// the warden must open a kill-window BEFORE `systemctl stop` (otherwise the
/// SIGTERM is denied and the stop job hangs to TimeoutStopSec), and re-arm
/// AFTER start (the new MainPID lives in a new, unprotected cgroup). rearm
/// is best-effort here — its reply is captured in stdout, and the chain's rc
/// still comes from stop/mv/start alone (health polling is the real gate).
pub fn swap_cmd() -> String {
    format!(
        "/usr/local/bin/mlc-warden open-window 120; \
         systemctl stop mlc-server && mv '{REMOTE_BIN}.new' '{REMOTE_BIN}' && systemctl start mlc-server; \
         RC=$?; /usr/local/bin/mlc-warden rearm-protege 2>&1 || true; exit $RC"
    )
}

/// Restore the snapshot over the live binary and start. Same Tier-2 window +
/// rearm dance as [`swap_cmd`]; open-window may legitimately fail when the
/// protege is already dead (no resolvable cgroup) — best-effort either way.
/// The just-deployed binary is set aside as `.failed` rather than overwritten,
/// so a rollback that turns out not to have restored health can be undone by
/// [`restore_forward_cmd`] instead of having destroyed the newer artifact.
pub fn rollback_cmd() -> String {
    format!(
        "/usr/local/bin/mlc-warden open-window 120 2>/dev/null || true; \
         systemctl stop mlc-server; mv -f '{REMOTE_BIN}' '{REMOTE_BIN}.failed'; \
         mv -f '{REMOTE_BIN}.prev' '{REMOTE_BIN}' && systemctl start mlc-server; \
         RC=$?; /usr/local/bin/mlc-warden rearm-protege 2>&1 || true; exit $RC"
    )
}

/// Undo a rollback that did not restore health: put the deployed binary back.
/// Only reached when the previous binary failed the same probe, which makes
/// the probe — not the artifact — the thing to doubt.
pub fn restore_forward_cmd() -> String {
    format!(
        "/usr/local/bin/mlc-warden open-window 120 2>/dev/null || true; \
         systemctl stop mlc-server; mv -f '{REMOTE_BIN}' '{REMOTE_BIN}.prev'; \
         mv -f '{REMOTE_BIN}.failed' '{REMOTE_BIN}' && systemctl start mlc-server; \
         RC=$?; /usr/local/bin/mlc-warden rearm-protege 2>&1 || true; exit $RC"
    )
}

/// Health probe on the box, against whatever address the unit actually binds.
pub fn health_cmd() -> String {
    format!(
        "{}curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 \"$H\"",
        crate::state::APP_HEALTH_RESOLVE
    )
}

/// Shared with `release::publish` — one sha256 helper for both artifact
/// kinds this crate ships to a box.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
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

    let session = crate::ops::connect(state).await?;

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

    // A rollback earns its keep only by restoring health. When the previous
    // binary fails the same probe, the rollback has proved nothing and has
    // discarded the newer artifact — so undo it and leave a human to judge.
    let mut forward_health = None;
    if let Some(HealthProbe::Bad(_)) = rollback_health {
        tracing::error!("rollback did not restore health either — restoring the deployed binary");
        match session.exec(&restore_forward_cmd()).await {
            Ok(out) if out.exit_code == Some(0) || out.exit_code.is_none() => {
                forward_health = Some(poll_health(&session, HEALTH_POLL_ATTEMPTS).await);
                steps.push(format!("rollback undone, deployed binary restored (health: {forward_health:?})"));
            }
            Ok(out) => steps.push(format!("restore-forward exited {:?}", out.exit_code)),
            Err(e) => steps.push(format!("restore-forward ssh error: {e}")),
        }
    }

    let (ok, rolled_back, error) = verdict(swap.exit_code, health, rollback_health, forward_health);
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
        let (ok, rb, err) = verdict(Some(0), HealthProbe::Ok, None, None);
        assert!(ok && !rb && err.is_none());
    }

    #[test]
    fn verdict_defers_to_health_on_missing_exit_status() {
        // SSH closed without exit-status but the service came up: success.
        let (ok, rb, _) = verdict(None, HealthProbe::Ok, None, None);
        assert!(ok && !rb);
    }

    #[test]
    fn verdict_rollback_when_health_dead_and_prev_ok() {
        let (ok, rb, err) = verdict(Some(0), HealthProbe::Bad(Some(000)), Some(HealthProbe::Ok), None);
        assert!(!ok && rb);
        assert!(err.unwrap().contains("rolled back"));
    }

    /// Both binaries failing the same probe indicts the probe, not the
    /// artifact: the rollback is undone, so the rollout reports failure
    /// WITHOUT claiming to have rolled back.
    #[test]
    fn verdict_rollback_also_dead_keeps_the_new_binary() {
        let (ok, rb, err) = verdict(
            Some(0),
            HealthProbe::Bad(None),
            Some(HealthProbe::Bad(Some(500))),
            Some(HealthProbe::Ok),
        );
        assert!(!ok);
        assert!(!rb, "the rollback was undone — reporting it as rolled back would be a lie");
        assert!(err.unwrap().contains("probe or the box is suspect"));
    }

    #[test]
    fn verdict_swap_failed_no_health_verdict() {
        let (ok, rb, err) = verdict(Some(1), HealthProbe::Ok, None, None);
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
        assert!(health_cmd().contains("BIND_ADDR"));
        assert!(health_cmd().contains(":19200/health"));
    }
}

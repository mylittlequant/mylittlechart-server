//! Box operations shared by the HTTP handlers and the watch loop.
//!
//! One rule holds for every function here: the opbox never spawns external
//! processes — all remote work goes through `crate::ssh`, all local HTTP
//! through reqwest. (`curl` appears ONLY inside remote shell strings executed
//! on the box, where it probes the loopback-only app port.)

use std::sync::Arc;

use serde::Serialize;

use crate::error::OpsdError;
use crate::ssh::{self, SshSession};
use crate::state::{OpsdState, UNIT_WHITELIST};

#[derive(Debug, Serialize)]
pub struct BoxStatus {
    pub units: serde_json::Map<String, serde_json::Value>,
    pub app_health: Option<u16>,
    pub disk: Option<String>,
    pub mem: Option<String>,
    pub uptime: Option<String>,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Active,
    Inactive,
    Failed,
    Activating,
    Other,
}

#[derive(Debug, Serialize)]
pub struct BoxState {
    pub service: ServiceState,
    pub service_raw: String,
    /// systemd SubState (running / auto-restart / dead / ...).
    pub sub_state: String,
    pub main_pid: u32,
    /// ExecMainStatus from `systemctl show` — non-zero on a crashed start.
    pub exec_main_status: i32,
    /// SQLCipher key file present in box tmpfs (lost on every reboot).
    pub keyfile_present: bool,
    /// Recent journal shows the service stuck at the dbkey wait. Fallback
    /// signal — the primary service state above comes from `systemctl show`.
    pub waiting_for_key: bool,
}

#[derive(Debug, Serialize)]
pub struct UnlockOutcome {
    pub ok: bool,
    pub steps: Vec<String>,
}

fn ssh_opts<'a>(state: &'a OpsdState, key_pem: &'a [u8]) -> ssh::SshOptions<'a> {
    ssh::SshOptions {
        host: &state.box_cfg.host,
        port: state.box_cfg.port,
        user: &state.box_cfg.user,
        key_pem,
    }
}

pub(crate) async fn connect(state: &Arc<OpsdState>) -> Result<SshSession, OpsdError> {
    let key_pem = std::fs::read(&state.box_cfg.ssh_key_path)?;
    let opts = ssh_opts(state, &key_pem);
    Ok(ssh::open_session(&opts).await?)
}

pub fn check_unit(unit: &str) -> Result<(), OpsdError> {
    if UNIT_WHITELIST.contains(&unit) {
        Ok(())
    } else {
        Err(OpsdError::Remote(format!(
            "unit {unit:?} not in whitelist {UNIT_WHITELIST:?}"
        )))
    }
}

/// One ssh round-trip: systemd states, loopback app health, disk/mem, uptime.
pub async fn collect_status(state: &Arc<OpsdState>) -> Result<BoxStatus, OpsdError> {
    let session = connect(state).await?;
    let out = session
        .exec(&format!(
            "for u in {units}; do echo \"unit:$u:$(systemctl is-active $u)\"; done; \
             echo \"app_health:$(curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 {app})\"; \
             echo \"disk:$(df -h / | awk 'NR==2{{print $4\" free of \"$2}}')\"; \
             echo \"mem:$(free -m | awk '/Mem:/{{print $3\"/\"$2\" MB\"}}')\"; \
             echo \"uptime:$(uptime -p)\"",
            units = UNIT_WHITELIST.join(" "),
            app = crate::state::APP_HEALTH_REMOTE,
        ))
        .await?;
    Ok(parse_status(&out.stdout))
}

/// Parse the `key:value` lines emitted by [`collect_status`].
fn parse_status(stdout: &str) -> BoxStatus {
    let mut units = serde_json::Map::new();
    let mut app_health = None;
    let mut disk = None;
    let mut mem = None;
    let mut uptime = None;
    for line in stdout.lines() {
        let Some((key, val)) = line.split_once(':') else { continue };
        match key {
            "unit" => {
                // unit:<name>:<state>
                if let Some((name, st)) = val.split_once(':') {
                    units.insert(name.to_string(), serde_json::Value::from(st.trim()));
                }
            }
            "app_health" => app_health = val.trim().parse::<u16>().ok(),
            "disk" => disk = Some(val.trim().to_string()),
            "mem" => mem = Some(val.trim().to_string()),
            "uptime" => uptime = Some(val.trim().to_string()),
            _ => {}
        }
    }
    BoxStatus {
        units,
        app_health,
        disk,
        mem,
        uptime,
    }
}

/// Service state, dbkey presence, key-wait detection. Primary signal is
/// `systemctl show` (ActiveState/SubState/MainPID/ExecMainStatus); the
/// journal grep stays as the fallback marker for "stuck waiting for key".
/// Watch loop decides interventions from this.
pub async fn box_state(state: &Arc<OpsdState>) -> Result<BoxState, OpsdError> {
    let session = connect(state).await?;
    let out = session
        .exec(
            "systemctl show mlc-server -p ActiveState,SubState,MainPID,ExecMainStatus 2>/dev/null; \
             echo \"keyfile:$(test -f /run/mlc/dbkey && echo present || echo absent)\"; \
             echo \"waiting:$(journalctl -u mlc-server --no-pager -n 300 2>/dev/null \
                 | grep -q 'waiting for /run/mlc/dbkey' && echo yes || echo no)\"",
        )
        .await?;
    let mut bs = parse_box_state(&out.stdout);
    if bs.service == ServiceState::Other {
        // Fallback: `systemctl show` output missing/unparsable — degrade to
        // the v1 is-active probe rather than report Other forever.
        let out = session
            .exec("systemctl is-active mlc-server 2>/dev/null")
            .await?;
        bs.service_raw = out.stdout.trim().to_string();
        bs.service = classify_service(&bs.service_raw);
    }
    Ok(bs)
}

fn classify_service(raw: &str) -> ServiceState {
    match raw {
        "active" => ServiceState::Active,
        "inactive" => ServiceState::Inactive,
        "failed" => ServiceState::Failed,
        "activating" => ServiceState::Activating,
        _ => ServiceState::Other,
    }
}

fn parse_box_state(stdout: &str) -> BoxState {
    let mut service_raw = String::new();
    let mut sub_state = String::new();
    let mut main_pid = 0u32;
    let mut exec_main_status = 0i32;
    let mut keyfile_present = false;
    let mut waiting_for_key = false;
    for line in stdout.lines() {
        if let Some((key, val)) = line.split_once('=') {
            // systemctl show emits Key=Value lines.
            match key {
                "ActiveState" => service_raw = val.trim().to_string(),
                "SubState" => sub_state = val.trim().to_string(),
                "MainPID" => main_pid = val.trim().parse().unwrap_or(0),
                "ExecMainStatus" => exec_main_status = val.trim().parse().unwrap_or(0),
                _ => {}
            }
            continue;
        }
        let Some((key, val)) = line.split_once(':') else { continue };
        match key {
            "keyfile" => keyfile_present = val.trim() == "present",
            "waiting" => waiting_for_key = val.trim() == "yes",
            _ => {}
        }
    }
    let service = classify_service(&service_raw);
    BoxState {
        service,
        service_raw,
        sub_state,
        main_pid,
        exec_main_status,
        keyfile_present,
        waiting_for_key,
    }
}

/// boot-unlock: push the canonical SQLCipher key + server.env into the box
/// tmpfs, start mlc-server, verify loopback health. The box keeps no copy of
/// either secret on disk (`/run` is tmpfs; modes 0600 root).
pub async fn unlock(state: &Arc<OpsdState>) -> Result<UnlockOutcome, OpsdError> {
    let mut steps: Vec<String> = Vec::new();

    let dbkey = std::fs::read_to_string(&state.box_cfg.canon_key_path)
        .map_err(|e| OpsdError::CanonSecret(format!("read sqlcipher.key: {e}")))?;
    if dbkey.trim().len() < 32 {
        return Err(OpsdError::CanonSecret("sqlcipher.key looks too short".into()));
    }
    let server_env = std::fs::read(&state.box_cfg.canon_env_path)
        .map_err(|e| OpsdError::CanonSecret(format!("read server.env: {e}")))?;

    let session = connect(state).await?;
    let out = session
        .exec("install -d -m 770 -o root -g mlc /run/mlc && echo DIR_OK")
        .await?;
    if !out.stdout.contains("DIR_OK") {
        return Err(OpsdError::Remote(format!(
            "install /run/mlc failed: {} {}",
            out.stdout.trim(),
            out.stderr.trim()
        )));
    }
    steps.push("tmpfs dir /run/mlc ready".into());

    session
        .upload(dbkey.trim().as_bytes(), "/run/mlc/dbkey", 0o600)
        .await?;
    steps.push("dbkey delivered (0600 root)".into());
    session
        .upload(&server_env, "/run/mlc/server.env", 0o600)
        .await?;
    steps.push("server.env delivered (0600 root)".into());

    let out = session.exec("systemctl start mlc-server").await?;
    if out.exit_code != Some(0) {
        return Err(OpsdError::Remote(format!(
            "systemctl start mlc-server rc={:?}: {}",
            out.exit_code,
            out.stderr.trim()
        )));
    }
    steps.push("mlc-server started".into());

    // The app binds only after it has read+unlinked the key — poll loopback
    // health for up to ~15s before declaring the unlock done.
    let mut healthy = false;
    for _ in 0..5 {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let out = session
            .exec(&format!(
                "curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 {}",
                crate::state::APP_HEALTH_REMOTE
            ))
            .await?;
        if out.stdout.trim() == "200" {
            healthy = true;
            break;
        }
    }
    steps.push(if healthy {
        "health verified (200)".into()
    } else {
        "health NOT verified after 15s".into()
    });

    state.audit(
        "unlock",
        &format!("ok={healthy} steps={}", steps.len()),
    );
    Ok(UnlockOutcome { ok: healthy, steps })
}

pub async fn restart_unit(state: &Arc<OpsdState>, unit: &str) -> Result<String, OpsdError> {
    check_unit(unit)?;
    let session = connect(state).await?;
    let out = session
        .exec(&format!(
            "systemctl restart {unit} && sleep 2 && systemctl is-active {unit}"
        ))
        .await?;
    let state_str = out.stdout.trim().to_string();
    state.audit("restart", &format!("unit={unit} result={state_str}"));
    if out.exit_code != Some(0) || state_str != "active" {
        return Err(OpsdError::Remote(format!(
            "restart {unit}: rc={:?} is-active={state_str} stderr={}",
            out.exit_code,
            out.stderr.trim()
        )));
    }
    Ok(state_str)
}

pub async fn logs(state: &Arc<OpsdState>, unit: &str, lines: u32) -> Result<String, OpsdError> {
    check_unit(unit)?;
    let lines = lines.clamp(1, 500);
    let session = connect(state).await?;
    let out = session
        .exec(&format!("journalctl -u {unit} --no-pager -n {lines}"))
        .await?;
    Ok(out.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_status_full_output() {
        let out = "unit:mlc-server:active\nunit:nginx:active\nunit:nftables:active\n\
                   unit:fail2ban:active\napp_health:200\ndisk:9.4G free of 25G\n\
                   mem:412/1979 MB\nuptime:up 3 days, 2 hours\n";
        let s = parse_status(out);
        assert_eq!(s.units["mlc-server"], "active");
        assert_eq!(s.units["fail2ban"], "active");
        assert_eq!(s.app_health, Some(200));
        assert_eq!(s.disk.as_deref(), Some("9.4G free of 25G"));
        assert_eq!(s.mem.as_deref(), Some("412/1979 MB"));
        assert_eq!(s.uptime.as_deref(), Some("up 3 days, 2 hours"));
    }

    #[test]
    fn parse_status_tolerates_garbage_lines() {
        let s = parse_status("junk without colon\napp_health:000\napp_health:notanumber\n");
        assert_eq!(s.app_health, None);
        assert!(s.units.is_empty());
    }

    #[test]
    fn parse_box_state_waiting() {
        let s = parse_box_state(
            "ActiveState=activating\nSubState=auto-restart\nMainPID=0\nExecMainStatus=1\n\
             keyfile:absent\nwaiting:yes\n",
        );
        assert_eq!(s.service, ServiceState::Activating);
        assert_eq!(s.sub_state, "auto-restart");
        assert_eq!(s.main_pid, 0);
        assert_eq!(s.exec_main_status, 1);
        assert!(!s.keyfile_present);
        assert!(s.waiting_for_key);
    }

    #[test]
    fn parse_box_state_healthy() {
        let s = parse_box_state(
            "ActiveState=active\nSubState=running\nMainPID=8357\nExecMainStatus=0\n\
             keyfile:present\nwaiting:no\n",
        );
        assert_eq!(s.service, ServiceState::Active);
        assert_eq!(s.sub_state, "running");
        assert_eq!(s.main_pid, 8357);
        assert!(s.keyfile_present);
        assert!(!s.waiting_for_key);
    }

    #[test]
    fn parse_box_state_missing_show_output_is_other() {
        // systemctl show failed entirely → caller falls back to is-active.
        let s = parse_box_state("keyfile:present\nwaiting:no\n");
        assert_eq!(s.service, ServiceState::Other);
        assert_eq!(s.service_raw, "");
    }

    #[test]
    fn unit_whitelist_rejects_injection() {
        assert!(check_unit("mlc-server").is_ok());
        assert!(check_unit("mlc-server; rm -rf /").is_err());
        assert!(check_unit("$(id)").is_err());
    }
}

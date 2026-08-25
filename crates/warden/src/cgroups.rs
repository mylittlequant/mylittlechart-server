//! cgroup-v2 / systemd resolution for the warden's own cgroup and the
//! protege unit's cgroup. Ported from mirage-secd's `hardening.rs` cgroup
//! helpers (the parts mlc-warden actually needs — the mirage
//! exact-binary-allowlist fleet scan is dropped: there is exactly ONE
//! protege unit here).
//!
//! The pure string parsing ([`parse_cgroup_v2_rel_path`]) is platform-free
//! so its tests run on the Windows dev box; everything that touches
//! `/proc`/`/sys`/`systemctl` is `#[cfg(target_os = "linux")]`.

/// Extract the unified-hierarchy relative cgroup path from
/// `/proc/<pid>/cgroup` content (cgroup-v2 line shape:
/// `0::/system.slice/foo.service`). Returns `None` on a v1/hybrid file or
/// empty input. Pure — unit-tested on every platform.
pub fn parse_cgroup_v2_rel_path(content: &str) -> Option<&str> {
    content
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::trim)
        .filter(|p| !p.is_empty())
}

/// Resolve the cgroup-v2 id of `pid` (or the literal string `"self"`) via
/// `/proc/<pid>/cgroup` (unified hierarchy: a single `0::<path>` line) + the
/// INODE number of the cgroupfs directory at that path. cgroup v2 has NO
/// `cgroup.id` file — the cgroup id IS the directory's inode (`stat %i`),
/// which is exactly the value `kernfs_node.id & 0xffffffff` /
/// `bpf_get_current_cgroup_id()` expose kernel-side. The eBPF Tier-2 walk
/// reads `kernfs_node.id`; this must return the SAME number so
/// `PROTECTED_CGROUP_MAP` matches the target task's cgroup in the kernel.
/// Returns `None` on any read failure (cgroup-v1 hybrid hierarchy,
/// permission error, process exited between the scan and this read).
#[cfg(target_os = "linux")]
pub fn cgroup_id_of_pid(pid: &str) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    let content = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let rel_path = parse_cgroup_v2_rel_path(&content)?;
    let dir_path = format!("/sys/fs/cgroup{rel_path}");
    std::fs::metadata(dir_path).ok().map(|m| m.ino())
}

/// The warden's own cgroup id — the SOLE allowlist for the `bpf`
/// lock-the-door hook (scoped by cgroup id, not PID, so the warden's own
/// restarts never self-lock-out). Returns `0` (inert) on any read failure —
/// the eBPF side treats `0` as "un-armed," and an unarmed self-allowlist
/// fails OPEN, not closed (see `warden-ebpf`'s `OWNER_CGROUP` static doc).
#[cfg(target_os = "linux")]
#[must_use]
pub fn own_cgroup_id() -> u64 {
    cgroup_id_of_pid("self").unwrap_or(0)
}

/// What `systemctl show -p MainPID` actually told us about a unit.
///
/// The three cases must stay distinct all the way up to whoever decides to
/// restart something. Collapsing `Unreachable` into "not running" is what
/// took three mirage boxes down on 2026-07-28: when systemd's own D-Bus
/// interface stops answering, `systemctl` exits non-zero with empty stdout,
/// the supervisor read that as "the unit is dead", and restarted a perfectly
/// healthy service. That restart could not complete (Tier2 denies the kill
/// once the allow-window lapses), so it jammed systemd's job queue, after
/// which EVERY unit probed as `Unreachable` and the supervisor
/// restart-stormed forever. A box in that state is only recoverable by
/// reboot.
///
/// So: `Unreachable` means *we learned nothing*, and learning nothing is
/// never grounds for acting.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitPid {
    /// systemd answered and named a live main process.
    Pid(u32),
    /// systemd answered, and the unit has no main process (`MainPID == 0`)
    /// — not loaded, not running, or exited. This is the only variant that
    /// justifies acting on the unit.
    NoMainPid,
    /// systemd did not answer: `systemctl` failed to spawn, exited
    /// non-zero, or printed something unparseable. Says nothing about the
    /// unit; it is a statement about the init system.
    Unreachable,
}

/// Resolve a systemd unit to its MainPID via `systemctl show -p MainPID`,
/// keeping "systemd did not answer" distinct from "the unit is not running"
/// — see [`UnitPid`] for why that distinction is load-bearing.
#[cfg(target_os = "linux")]
pub fn probe_main_pid_of_unit(unit: &str) -> UnitPid {
    let Ok(out) = std::process::Command::new("systemctl")
        .args(["show", "-p", "MainPID", "--value", unit])
        .output()
    else {
        return UnitPid::Unreachable;
    };
    if !out.status.success() {
        return UnitPid::Unreachable;
    }
    let Ok(pid) = String::from_utf8_lossy(&out.stdout).trim().parse::<u32>() else {
        return UnitPid::Unreachable;
    };
    if pid == 0 {
        UnitPid::NoMainPid
    } else {
        UnitPid::Pid(pid)
    }
}

/// [`probe_main_pid_of_unit`] for callers that genuinely cannot act on the
/// difference — cgroup resolution, where "no pid" and "no answer" both mean
/// "there is no cgroup to arm a window for". Never use this to decide
/// whether a unit is alive.
#[cfg(target_os = "linux")]
pub fn main_pid_of_unit(unit: &str) -> Option<u32> {
    match probe_main_pid_of_unit(unit) {
        UnitPid::Pid(pid) => Some(pid),
        UnitPid::NoMainPid | UnitPid::Unreachable => None,
    }
}

/// Resolve a unit's CURRENT cgroup id (MainPID → `/proc/PID/cgroup` →
/// cgroupfs dir inode). `None` if the unit is not running or systemd is
/// unreachable.
#[cfg(target_os = "linux")]
pub fn cgroup_id_of_unit(unit: &str) -> Option<u64> {
    cgroup_id_of_pid(&main_pid_of_unit(unit)?.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unified_hierarchy_line() {
        let content = "0::/system.slice/mlc-server.service\n";
        assert_eq!(
            parse_cgroup_v2_rel_path(content),
            Some("/system.slice/mlc-server.service")
        );
    }

    #[test]
    fn ignores_v1_lines_and_picks_the_v2_line() {
        let content = "5:cpu,cpuacct:/foo\n4:memory:/bar\n0::/user.slice/user-1000.slice\n";
        assert_eq!(
            parse_cgroup_v2_rel_path(content),
            Some("/user.slice/user-1000.slice")
        );
    }

    #[test]
    fn no_v2_line_is_none() {
        assert_eq!(parse_cgroup_v2_rel_path("1:name=systemd:/x\n"), None);
        assert_eq!(parse_cgroup_v2_rel_path(""), None);
        assert_eq!(parse_cgroup_v2_rel_path("0::\n"), None);
    }
}

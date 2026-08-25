//! `mlc-warden` — standalone eBPF-LSM (BPF-LSM "Tier-2") hardening daemon
//! for ONE protege process: mlc-server on mlc-utah-1 (Ubuntu 24.04, kernel
//! 6.8, cgroup-v2 unified).
//!
//! Mechanics ported from mirage2web's mirage-secd (`secd-ebpf`,
//! `bpf_lsm/loader.rs`, `kernel_btf_offsets.rs`, `hardening.rs` cgroup
//! helpers) and mirage-warden (`tier2.rs` window logic) — no identity, no
//! capsules, no mesh. Deny events go to `tracing` (journald on the box);
//! managed-restart windows are driven over a root-only unix socket by this
//! same binary's CLI subcommands.
//!
//! # Why a control socket
//!
//! The `bpf` lock-the-door LSM hook denies every `bpf()` syscall from any
//! cgroup other than the armed daemon's own — so `mlc-warden open-window`
//! run from an admin shell CANNOT write the window maps itself. The running
//! daemon (whose cgroup IS the allowlisted owner) does it instead: the CLI
//! sends a one-line command to `/run/mlc-warden/control.sock`, the daemon
//! executes it, and replies with one line (`ok ...` / `err ...`).
//!
//! # Enforcement lifetime
//!
//! The LSM attach links are deliberately LEAKED (process-lived, see
//! `bpf_lsm/loader.rs`): enforcement dies the instant this process exits.
//! `arm`/`run` therefore park forever after arming; systemd
//! `Restart=always` re-arms after any crash. `disarm` opens a window on the
//! daemon's OWN cgroup so `systemctl stop mlc-warden` can actually kill it
//! (its own cgroup is kill-protected too — the protector must not be
//! killable without a window).

mod btf;
mod cgroups;
mod sensor;
mod tier2;

#[cfg(target_os = "linux")]
mod bpf_lsm;

use std::path::PathBuf;

#[cfg(target_os = "linux")]
use std::time::Duration;

use clap::{Parser, Subcommand};

/// Flat-fill protected-slot count — MUST stay numerically in sync with
/// `warden-ebpf`'s `PROTECTED_SLOTS` (that crate is `no_std`/separately
/// compiled, so this userspace crate cannot import it directly — a
/// documented-not-derived contract).
pub const MAX_PROTECTED_SLOTS: usize = 64;

#[derive(Parser)]
#[command(
    name = "mlc-warden",
    about = "eBPF-LSM Tier-2 hardening for mlc-server (single-protege warden)"
)]
struct Cli {
    /// systemd unit of the protege.
    #[arg(long, default_value = "mlc-server.service", global = true)]
    unit: String,

    /// On-disk path of the protege's binary (BpfFileDeny tamper protection).
    #[arg(long, default_value = "/opt/mlc/mylittlechart-server", global = true)]
    binary: String,

    /// Control socket path (`run` binds it; CLI commands connect to it).
    #[arg(long, default_value = "/run/mlc-warden/control.sock", global = true)]
    socket: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Load + attach + arm protection for the protege and this process, then
    /// park FOREVER (enforcement is tied to this process's lifetime). No
    /// control socket — use `run` for the full daemon.
    Arm,
    /// Full daemon: arm, run the deny-event sensor, and serve the control
    /// socket. This is the systemd ExecStart mode.
    Run,
    /// Read-only report: kernel BPF-LSM availability, bpffs, current cgroup
    /// resolution for the protege and (if running) the daemon's own status.
    Status,
    /// Ask the running daemon to open a managed-restart allow-window for the
    /// protege's cgroup (kills against it are allowed while it is open).
    OpenWindow {
        /// Window length in seconds.
        secs: u64,
    },
    /// Ask the running daemon to do a full managed restart of the protege:
    /// open window → systemctl restart → re-resolve new cgroup → re-arm.
    RestartProtege {
        /// Window length in seconds (must cover the whole restart).
        #[arg(long, default_value_t = 30)]
        window_secs: u64,
    },
    /// Ask the running daemon to open a window on its OWN cgroup, so
    /// `systemctl stop mlc-warden` can kill it (this fully disarms Tier-2 —
    /// enforcement dies with the daemon process).
    Disarm,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let rc = match run(cli) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("mlc-warden: error: {e}");
            1
        }
    };
    std::process::exit(rc);
}

#[cfg(target_os = "linux")]
fn run(cli: Cli) -> Result<(), String> {
    match cli.cmd {
        Cmd::Arm => {
            let state = arm(&cli.unit, &cli.binary)?;
            tracing::info!(
                "[mlc-warden] armed — parking forever (enforcement dies if this process exits)"
            );
            park(state);
        }
        Cmd::Run => daemon_main(&cli),
        Cmd::Status => status(&cli),
        Cmd::OpenWindow { secs } => {
            send_command(&cli.socket, &format!("open-window {secs}"))
        }
        Cmd::RestartProtege { window_secs } => {
            send_command(&cli.socket, &format!("restart-protege {window_secs}"))
        }
        Cmd::Disarm => send_command(&cli.socket, "disarm"),
    }
}

#[cfg(not(target_os = "linux"))]
fn run(cli: Cli) -> Result<(), String> {
    // Status still gives a (fully-degraded) readout off-box; every other
    // command is meaningless without the kernel paths.
    if matches!(cli.cmd, Cmd::Status) {
        println!("mlc-warden: non-linux host — no kernel state to report");
        return Ok(());
    }
    Err("mlc-warden is Linux-only (eBPF-LSM); this binary is a dev-box build \
         with an empty eBPF placeholder — nothing can be armed here"
        .to_string())
}

// ── daemon (linux) ───────────────────────────────────────────────────────────

/// Everything the daemon needs after a successful arm.
#[cfg(target_os = "linux")]
struct DaemonState {
    tier2: tier2::Tier2,
    handles: bpf_lsm::loader::BpfLsmHandles,
    own_cgroup: u64,
}

/// Resolve cgroups, load+attach+pin the eBPF object, write the initial
/// protected-slot maps, and hand the writable map handles to `Tier2`.
#[cfg(target_os = "linux")]
fn arm(unit: &str, binary: &str) -> Result<DaemonState, String> {
    use cgroups::UnitPid;

    let own_cgroup = cgroups::own_cgroup_id();
    if own_cgroup == 0 {
        tracing::warn!(
            "[mlc-warden] own cgroup id unresolved — bpf lock-the-door allowlist will fail OPEN \
             (see warden-ebpf OWNER_CGROUP doc); arm continues, but ANY cgroup can issue bpf()"
        );
    }

    let protege_cgroup = match cgroups::probe_main_pid_of_unit(unit) {
        UnitPid::Pid(pid) => cgroups::cgroup_id_of_pid(&pid.to_string()).ok_or_else(|| {
            format!("protege unit {unit} main pid {pid} has no resolvable cgroup")
        })?,
        UnitPid::NoMainPid => {
            return Err(format!(
                "protege unit {unit} is not running (MainPID=0) — start it first"
            ))
        }
        UnitPid::Unreachable => {
            return Err(format!(
                "systemctl unreachable for unit {unit} — refusing to arm against unknown state"
            ))
        }
    };

    // Protege first, then self; both kill-protected (the protege is
    // recovered via restart-protege through a targeted window, the warden
    // self-restarts via systemd Restart=always).
    let mut slots: Vec<(u64, bool)> = vec![(protege_cgroup, true)];
    if own_cgroup != 0 && own_cgroup != protege_cgroup {
        slots.push((own_cgroup, true));
    }

    let (dev_mem_inode, kcore_inode) = bpf_lsm::loader::precompute_inodes();
    let mut handles = bpf_lsm::loader::load_and_pin(
        &slots,
        own_cgroup,
        dev_mem_inode,
        kcore_inode,
        binary,
    )?;

    let tier2 = tier2::Tier2::new();
    tier2.store(&mut handles, &slots);

    tracing::info!(
        "[mlc-warden] Tier-2 armed: unit={unit} protege_cgroup={protege_cgroup} \
         own_cgroup={own_cgroup} slots={:?}",
        slots
    );

    Ok(DaemonState {
        tier2,
        handles,
        own_cgroup,
    })
}

/// Never return: the leaked attach links die with the process. Sleeps
/// forever; SIGTERM/SIGINT end enforcement by ending the process (only
/// possible while a window on our own cgroup is open, since we are
/// kill-protected too).
#[cfg(target_os = "linux")]
fn park(_state: DaemonState) -> ! {
    loop {
        std::thread::park();
    }
}

#[cfg(target_os = "linux")]
fn daemon_main(cli: &Cli) -> Result<(), String> {
    let state = arm(&cli.unit, &cli.binary)?;

    // Deny-event sensor on its own blocking thread (observability only —
    // enforcement is kernel-side regardless).
    let sensor_handles = state.handles;
    std::thread::Builder::new()
        .name("deny-sensor".into())
        .spawn(move || sensor::run_sensor_loop(sensor_handles))
        .map_err(|e| format!("spawn sensor thread: {e}"))?;

    serve_control_socket(&cli.socket, state.tier2, state.own_cgroup, &cli.unit)
}

/// Root-only unix socket command loop: one line in, one line out. Runs
/// forever; a bind/listen failure is fatal (the daemon without its control
/// channel cannot open windows — including the one `disarm` needs to ever
/// stop it — so failing loudly at boot beats discovering it later).
#[cfg(target_os = "linux")]
fn serve_control_socket(
    socket: &std::path::Path,
    tier2: tier2::Tier2,
    own_cgroup: u64,
    unit: &str,
) -> Result<(), String> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    let dir = socket
        .parent()
        .ok_or_else(|| format!("socket path {} has no parent", socket.display()))?;
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    // 0700 root-only: window/restart/disarm are privileged operations.
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod {}: {e}", dir.display()))?;
    }
    let _ = std::fs::remove_file(socket); // stale socket from a previous run
    let listener = UnixListener::bind(socket)
        .map_err(|e| format!("bind {}: {e}", socket.display()))?;

    tracing::info!("[mlc-warden] control socket listening on {}", socket.display());

    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let tier2 = tier2.clone();
        let unit = unit.to_string();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                return;
            }
            let reply = dispatch(line.trim(), &tier2, own_cgroup, &unit);
            let mut stream = stream;
            let _ = stream.write_all(reply.as_bytes());
            let _ = stream.write_all(b"\n");
        });
    }
    Err("control socket listener loop ended unexpectedly".to_string())
}

/// Execute one control-socket command line. Always returns a reply; never
/// panics.
#[cfg(target_os = "linux")]
fn dispatch(line: &str, tier2: &tier2::Tier2, own_cgroup: u64, unit: &str) -> String {
    let mut it = line.split_whitespace();
    match it.next() {
        Some("open-window") => {
            let Some(secs) = it.next().and_then(|s| s.parse::<u64>().ok()) else {
                return "err usage: open-window <secs>".to_string();
            };
            match cgroups::cgroup_id_of_unit(unit) {
                Some(cg) => match tier2.open_window(cg, Duration::from_secs(secs)) {
                    Ok(()) => format!("ok window open for cgroup {cg}, {secs}s"),
                    Err(e) => format!("err {e}"),
                },
                None => format!("err protege unit {unit} has no resolvable cgroup (not running?)"),
            }
        }
        Some("restart-protege") => {
            let secs = it
                .next()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(30);
            restart_protege(tier2, own_cgroup, unit, Duration::from_secs(secs))
        }
        Some("disarm") => {
            // Open a window on our OWN cgroup so `systemctl stop mlc-warden`
            // can actually kill us; enforcement dies with the process.
            match tier2.open_window(own_cgroup, Duration::from_secs(120)) {
                Ok(()) => "ok disarm window open on warden cgroup for 120s — run \
                           `systemctl stop mlc-warden` now"
                    .to_string(),
                Err(e) => format!("err {e}"),
            }
        }
        Some("status") => {
            let (enforcing, armed, kill) = tier2.status();
            let protege = cgroups::cgroup_id_of_unit(unit);
            format!(
                "ok enforcing={enforcing} armed_cgroups={armed} kill_protected={kill} \
                 own_cgroup={own_cgroup} protege_cgroup={protege:?}"
            )
        }
        Some(other) => format!("err unknown command '{other}'"),
        None => "err empty command".to_string(),
    }
}

/// Managed restart of the protege: open a targeted window on its CURRENT
/// cgroup, `systemctl restart`, wait for the new MainPID, re-resolve its NEW
/// cgroup id, full-reconcile re-arm, close the old window. The window is
/// closed on every path — a window must never outlive its caller.
#[cfg(target_os = "linux")]
fn restart_protege(
    tier2: &tier2::Tier2,
    own_cgroup: u64,
    unit: &str,
    window: Duration,
) -> String {
    use cgroups::UnitPid;

    let old_pid = match cgroups::probe_main_pid_of_unit(unit) {
        UnitPid::Pid(pid) => pid,
        UnitPid::NoMainPid => {
            return format!("err protege unit {unit} not running (MainPID=0) — plain `systemctl start {unit}` suffices, no window needed");
        }
        UnitPid::Unreachable => {
            // Load-bearing: systemd unreachable is NOT "unit dead" — acting
            // on it restart-stormed mirage boxes into reboot-only states.
            return format!("err systemctl unreachable for {unit} — refusing to act on unknown state");
        }
    };
    let old_cgroup = match cgroups::cgroup_id_of_pid(&old_pid.to_string()) {
        Some(cg) => cg,
        None => return format!("err protege pid {old_pid} cgroup unresolvable"),
    };

    if let Err(e) = tier2.open_window(old_cgroup, window) {
        return format!("err open window: {e}");
    }
    tracing::info!("[mlc-warden] window open for {unit} cgroup {old_cgroup}, restarting");

    let restart_rc = std::process::Command::new("systemctl")
        .args(["restart", unit])
        .status();

    // Wait for a NEW MainPID (bounded: the window auto-expires anyway).
    let mut new_pid = None;
    for _ in 0..80 {
        std::thread::sleep(Duration::from_millis(250));
        if let UnitPid::Pid(pid) = cgroups::probe_main_pid_of_unit(unit) {
            if pid != old_pid {
                new_pid = Some(pid);
                break;
            }
        }
    }

    let outcome = match (restart_rc, new_pid) {
        (Ok(status), Some(pid)) if status.success() => {
            match cgroups::cgroup_id_of_pid(&pid.to_string()) {
                Some(new_cgroup) => {
                    let mut slots = vec![(new_cgroup, true)];
                    if own_cgroup != 0 && own_cgroup != new_cgroup {
                        slots.push((own_cgroup, true));
                    }
                    match tier2.rearm(&slots) {
                        Ok(()) => format!(
                            "ok restarted {unit} (pid {old_pid}->{pid}), re-armed cgroup {new_cgroup}"
                        ),
                        Err(e) => format!("err restarted but re-arm failed: {e}"),
                    }
                }
                None => format!("err restarted (pid {pid}) but new cgroup unresolvable — re-arm skipped"),
            }
        }
        (Ok(status), _) => format!("err systemctl restart exit {status} or no new MainPID within 20s"),
        (Err(e), _) => format!("err systemctl restart spawn: {e}"),
    };

    if let Err(e) = tier2.close_window(old_cgroup) {
        tracing::warn!("[mlc-warden] close window for cgroup {old_cgroup} failed: {e}");
    }
    outcome
}

// ── CLI client side ─────────────────────────────────────────────────────────

/// Send one command line to the running daemon and print its reply.
#[cfg(target_os = "linux")]
fn send_command(socket: &std::path::Path, line: &str) -> Result<(), String> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket).map_err(|e| {
        format!(
            "connect {}: {e} — is the daemon running (`systemctl status mlc-warden`)?",
            socket.display()
        )
    })?;
    stream
        .write_all(line.as_bytes())
        .and_then(|()| stream.write_all(b"\n"))
        .map_err(|e| format!("write command: {e}"))?;
    let mut reply = String::new();
    BufReader::new(stream)
        .read_line(&mut reply)
        .map_err(|e| format!("read reply: {e}"))?;
    println!("{}", reply.trim_end());
    if reply.starts_with("ok") {
        Ok(())
    } else {
        Err(reply.trim().to_string())
    }
}

/// Read-only status: kernel capability + current cgroup resolution. Issues
/// NO `bpf()` syscalls (a shell-side `status` runs in a non-owner cgroup —
/// the lock-the-door hook would deny it) and does not require the daemon.
#[cfg(target_os = "linux")]
fn status(cli: &Cli) -> Result<(), String> {
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "?".into());
    let lsms = std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "?".into());
    let bpf_lsm_active = lsms.split(',').any(|l| l.trim() == "bpf");
    let bpffs = std::fs::metadata("/sys/fs/bpf").is_ok();
    let pin_root = std::fs::metadata("/sys/fs/bpf/mlc").is_ok();

    println!("kernel:            {kernel}");
    println!("active LSMs:       {lsms}");
    println!(
        "bpf in lsm= list:  {} {}",
        bpf_lsm_active,
        if bpf_lsm_active { "" } else { "(REQUIRED — boot with lsm=...,bpf)" }
    );
    println!("bpffs mounted:     {bpffs}");
    println!("pin root present:  {pin_root} (/sys/fs/bpf/mlc)");

    match cgroups::probe_main_pid_of_unit(&cli.unit) {
        cgroups::UnitPid::Pid(pid) => {
            let cg = cgroups::cgroup_id_of_pid(&pid.to_string());
            println!("protege:           {} pid={} cgroup={:?}", cli.unit, pid, cg);
        }
        cgroups::UnitPid::NoMainPid => println!("protege:           {} NOT RUNNING", cli.unit),
        cgroups::UnitPid::Unreachable => println!("protege:           {} — systemctl UNREACHABLE", cli.unit),
    }
    println!("protege binary:    {} (inode/device resolved at arm time)", cli.binary);

    // Best-effort daemon liveness via the control socket (read-only query).
    match send_command(&cli.socket, "status") {
        Ok(()) => {}
        Err(e) => println!("daemon:            not answering ({e})"),
    }
    Ok(())
}

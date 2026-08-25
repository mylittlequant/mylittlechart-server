//! mlc-warden kernel-side aya BPF-LSM programs (Tier-2), ported near-verbatim
//! from mirage2web's `mirage-secd/secd-ebpf/src/main.rs` (Wave-2 Stage G),
//! adapted for a single protege: the `mlc-server` process on mlc-utah-1
//! (Ubuntu 24.04, kernel 6.8, cgroup-v2 unified).
//!
//! # Validation status
//!
//! The mirage source crate validated `cargo +nightly check --target
//! bpfel-unknown-none -Z build-std=core` (RUSTFLAGS="-D warnings") clean
//! against this program set, and shipped it live on a 6.8-kernel fleet.
//! This port changes only naming/documentation, no mechanics. **UNVALIDATED
//! HERE**: the link step (`bpf-linker`), verifier acceptance, and live-kernel
//! behavior on mlc-utah-1 — real validation is the linux Docker build stage
//! + deployment.
//!
//! # Program set
//!
//! 1. `ptrace_access_check` — deny if the TARGET task's cgroup is in the
//!    protected set. Closes `ptrace(2)` AND `process_vm_readv(2)`/
//!    `process_vm_writev(2)` (both funnel into the same
//!    `security_ptrace_access_check()` LSM call, stable since the 4.5-era
//!    `PTRACE_MODE_*CREDS` refactor).
//! 2. `ptrace_traceme` — same protected-cgroup check, reverse direction
//!    (protects the CALLING task from a hostile parent tracer).
//! 3. `task_kill` — deny signal delivery to a protected-cgroup target
//!    (closes the kill-then-ptrace-fresh-process race).
//! 4. `file_open` — deny open on `/dev/mem` + `/proc/kcore` (precomputed
//!    (dev, inode) identity, compared via `file->f_inode` — no path string
//!    compare in-kernel) AND deny write-open on the protected binary's inode
//!    (BpfFileDeny).
//! 5. `bpf` — "lock the door": deny every `bpf()` syscall from any cgroup
//!    other than the warden's OWN cgroup (the warden owns the ENTIRE eBPF
//!    lifecycle). Allowlist by cgroup id not PID, so the warden's own
//!    restart-with-new-PID never self-locks-out.
//! 6. `file_mprotect` — deny `PROT_EXEC` transitions (W^X) scoped to the
//!    protected cgroup (our Rust static daemons never JIT, so this is free
//!    anti-shellcode depth).
//!
//! Every deny returns the literal `-1` (`-EPERM`) — aya's `no_std` eBPF side
//! exposes no `EPERM` symbol. Every allow returns `Ok(0)`. Every program
//! propagates a nonzero PRIOR verdict (`ctx.arg(N)` — the extra "previous
//! eBPF LSM program's return value" argument aya's `LsmContext` exposes
//! beyond the hook's C arg count) rather than silently overriding it,
//! through [`propagate_prior`], which refuses to relay a verdict the LSM ABI
//! does not permit. Echoing that value raw is what kept this whole file from
//! loading; see that function's own doc.
#![no_std]
#![no_main]

mod cgroup;
mod vmlinux;

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{lsm, map},
    maps::{Array, RingBuf},
    programs::LsmContext,
};
use aya_log_ebpf::info;

/// `-EPERM` — aya's `no_std` side exposes no `EPERM` symbol; deny return
/// value for every LSM hook here.
const EPERM: i32 = -1;

/// The most negative value an LSM hook may return. The kernel's BPF verifier
/// enforces `[-4095, 0]` on every LSM program's exit register; anything else
/// is refused at load time, not at call time.
const MAX_ERRNO: i32 = -4095;

/// Propagate a PRIOR eBPF LSM program's verdict, refusing to echo one the
/// LSM ABI does not allow.
///
/// Every hook in this file opens by reading the extra trailing `ctx.arg(N)`
/// aya exposes — the previous program's return value — and passing a nonzero
/// one straight through rather than silently overriding it. The value it
/// reads is whatever sat in that register; nothing upstream guarantees it is
/// a legal LSM return, and this function is the place that stops assuming it
/// is.
///
/// # Why this is not cosmetic
///
/// Returning the raw value made every program in this file **fail to load**
/// on the mirage fleet. `ctx.arg::<i32>` narrows a 64-bit register, and the
/// narrowing that reaches the exit register is a ZERO-extension: a prior `-1`
/// leaves the hook as `0x0000_0000_FFFF_FFFF`, i.e. 4294967295. The verifier
/// rejects that at `BPF_PROG_LOAD`, so the warden never armed Tier2 at all
/// and degraded to supervisor-only on every start — measured live, seventeen
/// consecutive warden starts from first boot:
///
/// ```text
/// At program exit the register R0 has smin=1 smax=4294967295
/// should have been in [-4095, 0]
/// ```
///
/// Clamping fixes that as a side effect. The reason to clamp is the first
/// paragraph: a verdict outside `[-4095, 0]` is not a denial this hook can
/// faithfully relay, and turning it into `EPERM` fails CLOSED — the caller
/// is refused, which is what a nonzero prior verdict meant in the first
/// place. Giving the verifier a provable range is what makes the program
/// loadable; keeping the semantics honest is what makes it correct.
#[inline(always)]
fn propagate_prior(prior_ret: i32) -> i32 {
    if prior_ret >= MAX_ERRNO && prior_ret < 0 {
        prior_ret
    } else {
        EPERM
    }
}

/// 32 KiB ringbuf — deny-event sensor. Page-aligned power of two; ample
/// headroom for a low-event-rate security sensor.
#[map]
static DENY_EVENTS: RingBuf = RingBuf::with_byte_size(32 * 1024, 0);

/// Targeted managed-restart allow-window slot count — a small fixed table of
/// `(cgroup_id, expiry_ns)` pairs so a managed restart exposes ONLY the
/// cgroup it targets (never a global "open season" flag). 8 ≫ concurrent
/// managed-restarts on one box. The warden is the SOLE writer of this map
/// (it owns the entire eBPF lifecycle, including opening windows to restart
/// the protege, and it self-restarts through its own systemd
/// `Restart=always` rather than a window). This eBPF side has no opinion on
/// how the writer allocates slots; it only ever scans the FULL table.
const WINDOW_SLOTS: u32 = 8;

/// Targeted managed-restart allow-window — cgroup id half of the
/// `(cgroup_id, expiry_ns)` pair at slot `k` (parallel to
/// [`WINDOW_EXPIRY`]`[k]`). `0` = free/unused slot. ONLY the warden's
/// userspace can write this map — the `bpf` LSM hook (program 5 below)
/// already denies every `bpf()` syscall (which includes
/// `BPF_MAP_UPDATE_ELEM`) from any cgroup other than the owner-allowlisted
/// cgroup, so an attacker inside the protected cgroup (or anywhere else)
/// physically cannot open a window themselves. `try_task_kill` (program 3)
/// is the ONLY hook that ever reads either of these two maps — every other
/// hook (ptrace/file/bpf/mprotect) is untouched by their existence.
#[map]
static WINDOW_CGROUP: Array<u64> = Array::with_max_entries(WINDOW_SLOTS, 0);

/// Targeted managed-restart allow-window — expiry half of the
/// `(cgroup_id, expiry_ns)` pair at slot `k` (parallel to
/// [`WINDOW_CGROUP`]`[k]`), value = `bpf_ktime_get_ns()` expiry timestamp;
/// `0` means that slot is closed/free regardless of what `WINDOW_CGROUP[k]`
/// holds (auto-expire; a crash mid-restart cannot leave a slot open past its
/// own timestamp). Same write-access guard as `WINDOW_CGROUP` above.
#[map]
static WINDOW_EXPIRY: Array<u64> = Array::with_max_entries(WINDOW_SLOTS, 0);

/// Total `PROTECTED_CGROUP_MAP`/`KILL_PROTECTED_SLOTS` slots. Slot index is
/// FILL ORDER: userspace resolves the protected set (protege cgroup + the
/// warden's own cgroup) into a flat `Vec<(cgroup_id, kill)>` and fills slots
/// `0..N` in that order (`bpf_lsm/loader.rs`), so which unit lands in which
/// slot is not meaningful — only "is this slot's cgroup id armed" matters.
/// `0` (unarmed) is the inert default for every slot. MUST equal
/// `mlc_warden`'s userspace-side `MAX_PROTECTED_SLOTS` exactly. 64 is
/// mirage's fleet-sized headroom, kept verbatim — the mlc deployment fills
/// only slots 0..2.
const PROTECTED_SLOTS: u32 = 64;

/// Flat, fill-order array of protected cgroup ids — a WRITABLE N-entry array
/// (index = fill order, NOT a `.rodata` const). Load-bearing: `systemctl
/// restart <protege>` gives the new process a DIFFERENT cgroup id, since
/// systemd recreates the service cgroup on every restart; a load-time-only
/// `.rodata` constant can never be updated afterwards, so every restart used
/// to leave the freshly-restarted process permanently unprotected until the
/// warden itself reloaded. The warden's userspace re-resolves the FULL set
/// and re-arms every slot (a full reconcile, not a single-slot rewrite)
/// immediately after ANY managed restart. `0` is the inert default — never
/// matches a real cgroup id, so an un-set slot denies nothing rather than
/// denying everything. Write access is guarded by the same `bpf` LSM
/// lock-the-door hook (program 5 below) that already protects
/// `WINDOW_CGROUP`/`WINDOW_EXPIRY`.
#[map]
static PROTECTED_CGROUP_MAP: Array<u64> = Array::with_max_entries(PROTECTED_SLOTS, 0);

/// Subset of `PROTECTED_CGROUP_MAP` slot INDICES eligible for `task_kill`
/// denial. Value is a plain `u8` boolean marker (1 = kill-checked), keyed by
/// the SAME slot index `PROTECTED_CGROUP_MAP` uses. Both mlc slots (protege
/// and warden-own) are armed here — the protege is recovered by
/// `restart-protege` through a targeted window, the warden self-restarts via
/// systemd `Restart=always`. The warden is the SOLE arming writer of this
/// map.
#[map]
static KILL_PROTECTED_SLOTS: Array<u8> = Array::with_max_entries(PROTECTED_SLOTS, 0);

/// The warden's OWN cgroup id — the SOLE bpf lock-the-door allowlist (the
/// warden owns the entire eBPF lifecycle). Patched via `override_global` at
/// the warden's own load. Used ONLY by the `bpf` lock-the-door hook's
/// self-allowlist (allowlist by cgroup id, not PID, so the warden's own
/// restart-with-new-PID never self-locks-out).
#[unsafe(no_mangle)]
static OWNER_CGROUP: u64 = 0;

/// Precomputed inode number of `/dev/mem` on THIS box, patched at load time
/// (compare `file->f_inode->i_ino`, never a path string, to avoid an
/// in-kernel string compare). `0` is inert (no real inode is 0).
#[unsafe(no_mangle)]
static DEV_MEM_INODE: u64 = 0;

/// Precomputed inode number of `/proc/kcore` on THIS box, patched at load
/// time. `0` is inert.
#[unsafe(no_mangle)]
static KCORE_INODE: u64 = 0;

/// Precomputed inode number of the protected daemon's OWN binary on disk
/// (BpfFileDeny — deny write-open on the daemon's own executable while its
/// protecting cgroup is live). `0` is inert (skips this check).
#[unsafe(no_mangle)]
static PROTECTED_BINARY_INODE: u64 = 0;

// ── the OTHER half of a file's identity ─────────────────────────────────────
//
// An inode number is unique within ONE filesystem. Every deny below compares
// a number taken from one filesystem against every file opened on the box,
// and until 2026-08-12 it compared nothing else.
//
// Measured that day on the live mirage fleet: `/dev/mem` is inode 4 on
// devtmpfs and `/sys/fs/cgroup/cgroup.controllers` is inode 4 on cgroup2fs.
// Every box was therefore refusing to open the cgroup file, believing it was
// `/dev/mem`. systemd reads that file on every re-exec; an
// `unattended-upgrades` run upgraded the systemd package, systemd
// re-executed, could not read it, and FROZE PID 1 on seven of nine boxes.
// Nothing else noticed for two and a half hours, because a frozen init keeps
// its children running.
//
// The superblock device closes it. `0` is inert on purpose and on the SAFE
// side: a device the loader could not compute disables that entry's deny
// rather than widening it, because a deny we cannot aim is the defect above.
#[unsafe(no_mangle)]
static DEV_MEM_DEV: u64 = 0;

/// Superblock device of `/proc/kcore`. `0` is inert — see [`DEV_MEM_DEV`].
#[unsafe(no_mangle)]
static KCORE_DEV: u64 = 0;

/// Superblock device of the protected binary. `0` is inert — see [`DEV_MEM_DEV`].
#[unsafe(no_mangle)]
static PROTECTED_BINARY_DEV: u64 = 0;

/// Kernel-agnostic struct field offsets — patched at load time by the
/// userspace loader (`bpf_lsm/loader.rs`'s `resolve_kernel_offsets`, which
/// derives each value from the RUNNING kernel's own BTF via
/// `EbpfLoader::override_global`, same mechanism as every other global on
/// this page). DEFAULT to the KERNEL 6.8.0-130-generic values validated in
/// `crate::vmlinux` — if the userspace BTF walk fails for any reason (no
/// BTF, type/member not found, implausible offset) it falls back to exactly
/// the same defaults, so an un-patched or partially-patched load behaves
/// identically to the pre-BTF-derivation code (never a silent behavior
/// change, never a load failure over offset resolution).
///
/// Offset of `task_struct.cgroups` (a `struct css_set *`). Read from
/// `crate::cgroup`'s walk via [`core::ptr::read_volatile`] (`pub(crate)` so
/// that sibling module can see it — `#[unsafe(no_mangle)]` fixes the ELF
/// symbol name aya patches regardless of Rust visibility). Default sourced
/// from [`vmlinux::TASK_STRUCT_OFFSETS`] — single source of truth for the
/// KERNEL 6.8.0-130-generic fallback value.
#[unsafe(no_mangle)]
pub(crate) static TASK_STRUCT_CGROUPS_OFF: u64 = vmlinux::TASK_STRUCT_OFFSETS.cgroups as u64;

/// Offset of `css_set.dfl_cgrp` (a `struct cgroup *`).
#[unsafe(no_mangle)]
pub(crate) static CSS_SET_DFL_CGRP_OFF: u64 = vmlinux::CSS_SET_OFFSETS.dfl_cgrp as u64;

/// Offset of `cgroup.kn` (a `struct kernfs_node *`).
#[unsafe(no_mangle)]
pub(crate) static CGROUP_KN_OFF: u64 = vmlinux::CGROUP_OFFSETS.kn as u64;

/// Offset of `kernfs_node.id` (a plain `u64` field on every validated kernel
/// line so far — not a nested union; read directly).
#[unsafe(no_mangle)]
pub(crate) static KERNFS_NODE_ID_OFF: u64 = vmlinux::KERNFS_NODE_OFFSETS.id as u64;

/// Offset of `file.f_inode` (a `struct inode *`) within `struct file`.
#[unsafe(no_mangle)]
static FILE_F_INODE_OFF: u64 = vmlinux::FILE_OFFSETS.f_inode as u64;

/// Offset of `inode.i_ino` (a plain `u64`/`unsigned long` field) within
/// `struct inode`.
#[unsafe(no_mangle)]
static INODE_I_INO_OFF: u64 = vmlinux::INODE_OFFSETS.i_ino as u64;

/// Byte offset of `inode.i_sb` — see [`DEV_MEM_DEV`] for why the device is
/// needed at all. Patched at load time from the running kernel's BTF.
#[unsafe(no_mangle)]
static INODE_I_SB_OFF: u64 = vmlinux::INODE_OFFSETS.i_sb as u64;

/// Byte offset of `super_block.s_dev`. Patched at load time from BTF.
#[unsafe(no_mangle)]
static SUPER_BLOCK_S_DEV_OFF: u64 = vmlinux::SUPER_BLOCK_OFFSETS.s_dev as u64;

/// Event kind discriminants — kept as a plain `u8` constant set here
/// (no_std); the userspace sensor (`bpf_lsm/sensor.rs`) maps these same
/// numeric values to human-readable names when logging, so the two sides
/// must stay numerically in sync.
mod event_kind {
    pub const PTRACE_DENIED: u8 = 0x01;
    pub const FILE_OPEN_DENIED: u8 = 0x02;
    pub const TASK_KILL_DENIED: u8 = 0x03;
    pub const BPF_LOAD_DENIED: u8 = 0x04;
    pub const MPROTECT_DENIED: u8 = 0x08;
    /// Targeted managed-restart allow-window — emitted when `try_task_kill`
    /// allows a kill against the protected cgroup because a
    /// `WINDOW_CGROUP`/`WINDOW_EXPIRY` slot matching that cgroup is open,
    /// instead of the usual deny. Distinct value so the audit trail can tell
    /// a warden-authorised in-place restart apart from a genuine attacker
    /// TASK_KILL_DENIED — same event fields, just a different kind byte.
    pub const MANAGED_RESTART_ALLOWED: u8 = 0x10;
}

/// Fixed-layout ringbuf event — POD, no padding surprises: emitted verbatim
/// as raw bytes (`RingBuf::reserve_bytes`) rather than `reserve::<T>()`, so
/// no `Pod`/alignment trait bound is needed on the eBPF side and the
/// userspace `sensor.rs` decodes the same fixed byte layout explicitly.
///
/// Layout (little-endian, matches `bpfel-unknown-none`):
/// ```text
/// event_kind          1 byte
/// _pad                3 bytes (align next u64/u32 fields)
/// ts_ns               8 bytes  (bpf_ktime_get_ns — boot-relative; userspace
///                                converts to wall-clock at emit time)
/// protected_cgroup_id  8 bytes
/// offender_cgroup_id   8 bytes
/// offender_pid         4 bytes
/// ```
const EVENT_LEN: usize = 1 + 3 + 8 + 8 + 8 + 4;

#[inline(always)]
fn emit_deny_event(event_kind: u8, protected_cgroup_id: u64, offender_cgroup_id: u64, offender_pid: u32) {
    let Some(mut entry) = DENY_EVENTS.reserve_bytes(EVENT_LEN, 0) else {
        // Ring full — event silently dropped. No drop-counter map in this
        // port (the DENY already happened regardless of whether the
        // observability event lands).
        return;
    };

    entry[0] = event_kind;
    entry[1..4].copy_from_slice(&[0u8; 3]);
    let ts_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    entry[4..12].copy_from_slice(&ts_ns.to_le_bytes());
    entry[12..20].copy_from_slice(&protected_cgroup_id.to_le_bytes());
    entry[20..28].copy_from_slice(&offender_cgroup_id.to_le_bytes());
    entry[28..32].copy_from_slice(&offender_pid.to_le_bytes());

    entry.submit(0);
}

#[inline(always)]
fn current_pid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

#[inline(always)]
fn current_cgroup() -> u64 {
    // `bpf_get_current_cgroup_id()` returns the FULL kernfs id
    // `(generation << 32) | ino`. Mask to the low 32 bits (`kernfs_ino`) so it
    // lives in the SAME space as `PROTECTED_CGROUP_MAP`'s entry, which the
    // warden derives from the cgroupfs dir `stat().ino()` (= `kn->id &
    // 0xffffffff`). Without this mask the `ptrace_traceme` self-check (and
    // the offender id in deny events) never matches once the cgroup
    // generation is non-zero. See `cgroup::read_cgroup_id` for the full
    // rationale.
    (unsafe { aya_ebpf::helpers::bpf_get_current_cgroup_id() }) & 0xffff_ffff
}

/// `Some((slot, matched_protected_id))` iff `cgroup_id` equals ANY armed
/// (non-zero) slot in [`PROTECTED_CGROUP_MAP`]. Bounded loop over a
/// compile-time constant (`PROTECTED_SLOTS`) — verifier-friendly, no
/// unbounded iteration. `None` cgroup_id (resolution failed upstream) never
/// matches, same fail-safe meaning the old code carried.
#[inline(always)]
fn matched_protected_slot_with_index(cgroup_id: Option<u64>) -> Option<(u32, u64)> {
    let Some(cgroup_id) = cgroup_id else { return None };
    if cgroup_id == 0 {
        return None; // never treat an unresolved (0) target as "protected"
    }
    for i in 0..PROTECTED_SLOTS {
        let Some(entry) = PROTECTED_CGROUP_MAP.get(i) else { continue };
        let armed = unsafe { core::ptr::read_volatile(entry) };
        if armed != 0 && armed == cgroup_id {
            return Some((i, armed));
        }
    }
    None
}

/// `Some(matched_protected_id)` iff `cgroup_id` equals ANY armed (non-zero)
/// slot in [`PROTECTED_CGROUP_MAP`] — see
/// [`matched_protected_slot_with_index`] for the full doc; this is that fn
/// with the slot index dropped, for the (majority) call sites that only need
/// the matched cgroup id for the deny-event payload.
#[inline(always)]
fn matched_protected_slot(cgroup_id: Option<u64>) -> Option<u64> {
    matched_protected_slot_with_index(cgroup_id).map(|(_, id)| id)
}

// ── 1. ptrace_access_check ──────────────────────────────────────────────────
//
// LSM_HOOK(int, 0, ptrace_access_check, struct task_struct *child,
//          unsigned int mode)
// `child` = the TARGET/tracee — the task being scrutinized for ptrace.
// aya's LsmContext exposes one extra trailing arg beyond the C signature:
// the previous eBPF LSM program's return value.

#[lsm(hook = "ptrace_access_check")]
pub fn ptrace_access_check(ctx: LsmContext) -> i32 {
    match try_ptrace_access_check(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ptrace_access_check(ctx: LsmContext) -> Result<i32, i32> {
    let prior_ret: i32 = ctx.arg(2);
    if prior_ret != 0 {
        return Err(propagate_prior(prior_ret));
    }

    let child: *const core::ffi::c_void = ctx.arg(0);
    let child_cgroup = unsafe { cgroup::cgroup_id_of_task(child) };

    if let Some(matched) = matched_protected_slot(child_cgroup) {
        emit_deny_event(
            event_kind::PTRACE_DENIED,
            matched,
            current_cgroup(),
            current_pid(),
        );
        info!(&ctx, "ptrace_access_check denied — protected cgroup target");
        return Err(EPERM);
    }

    Ok(0)
}

// ── 2. ptrace_traceme ────────────────────────────────────────────────────────
//
// LSM_HOOK(int, 0, ptrace_traceme, struct task_struct *parent)
// `parent` here is the WOULD-BE TRACER, not the protected process — this
// hook protects the CALLING task (via PTRACE_TRACEME) from a hostile parent,
// included for completeness/symmetry. Scoped identically: deny if the
// CALLING task (the one invoking PTRACE_TRACEME) is itself in the protected
// cgroup — i.e. don't let an unexpected process become the tracer of a
// protected-cgroup task via the traceme path either.

#[lsm(hook = "ptrace_traceme")]
pub fn ptrace_traceme(ctx: LsmContext) -> i32 {
    match try_ptrace_traceme(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ptrace_traceme(ctx: LsmContext) -> Result<i32, i32> {
    let prior_ret: i32 = ctx.arg(1);
    if prior_ret != 0 {
        return Err(propagate_prior(prior_ret));
    }

    // The CALLING task (the one asking for PTRACE_TRACEME) is the protected
    // side here — `bpf_get_current_cgroup_id()` is CORRECT for this hook
    // specifically (unlike ptrace_access_check/task_kill) because the
    // calling task IS the potential tracee, not an attacker.
    if let Some(matched) = matched_protected_slot(Some(current_cgroup())) {
        emit_deny_event(
            event_kind::PTRACE_DENIED,
            matched,
            current_cgroup(),
            current_pid(),
        );
        return Err(EPERM);
    }

    Ok(0)
}

// ── 3. task_kill ─────────────────────────────────────────────────────────────
//
// LSM_HOOK(int, 0, task_kill, struct task_struct *p, struct kernel_siginfo
//          *info, int sig, const struct cred *cred)
// `p` = TARGET of the signal — deny if `p`'s cgroup is protected (defends
// against the kill-then-ptrace-fresh-process race).

#[lsm(hook = "task_kill")]
pub fn task_kill(ctx: LsmContext) -> i32 {
    match try_task_kill(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// `true` iff a targeted managed-restart allow-window is currently open FOR
/// `target_cgroup`: some slot `k` in `0..WINDOW_SLOTS` has
/// `WINDOW_CGROUP[k] == target_cgroup && WINDOW_EXPIRY[k] != 0 &&
/// bpf_ktime_get_ns() < WINDOW_EXPIRY[k]`. Bounded loop over the compile-time
/// constant [`WINDOW_SLOTS`] — verifier-friendly, no unbounded iteration,
/// same style as [`matched_protected_slot_with_index`]. A missing/unreadable
/// map entry at any slot is simply skipped (never treated as a match) —
/// fails to the existing, safe DENY path, never opens on a read failure.
#[inline(always)]
fn managed_restart_window_open_for(target_cgroup: u64) -> bool {
    if target_cgroup == 0 {
        return false; // never treat an unresolved (0) target as window-eligible
    }
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    for k in 0..WINDOW_SLOTS {
        let Some(cg_entry) = WINDOW_CGROUP.get(k) else { continue };
        let Some(exp_entry) = WINDOW_EXPIRY.get(k) else { continue };
        let cg = unsafe { core::ptr::read_volatile(cg_entry) };
        let exp = unsafe { core::ptr::read_volatile(exp_entry) };
        if cg == target_cgroup && exp != 0 && now < exp {
            return true;
        }
    }
    false
}

fn try_task_kill(ctx: LsmContext) -> Result<i32, i32> {
    let prior_ret: i32 = ctx.arg(4);
    if prior_ret != 0 {
        return Err(propagate_prior(prior_ret));
    }

    let target: *const core::ffi::c_void = ctx.arg(0);
    let target_cgroup = unsafe { cgroup::cgroup_id_of_task(target) };

    let Some((slot, matched)) = matched_protected_slot_with_index(target_cgroup) else {
        return Ok(0); // not protected at all — nothing to gate
    };

    // Kill-vs-scrape split: a slot can be present in PROTECTED_CGROUP_MAP
    // WITHOUT being kill-protected (absent from KILL_PROTECTED_SLOTS).
    // Missing map entry → `unwrap_or(false)` → fail-open to killable (the
    // safe direction for `task_kill` specifically — a window-less kill of a
    // wedge is still possible if the arming write never landed).
    let kill_checked = KILL_PROTECTED_SLOTS
        .get(slot)
        .map(|v| unsafe { core::ptr::read_volatile(v) } != 0)
        .unwrap_or(false);
    if !kill_checked {
        return Ok(0); // protected but NOT kill-protected — allow the kill
    }

    // Targeted managed-restart allow-window (ADDITIVE — checked BEFORE the
    // existing deny, never weakens it): only the warden's userspace can ever
    // open a slot (the `bpf` LSM hook below already denies every OTHER
    // cgroup's `bpf()` syscalls, which is what a map write needs), and every
    // slot auto-expires (time-bounded), so a crash mid-restart cannot leave
    // a protected daemon permanently killable. TARGETED: only the SPECIFIC
    // target cgroup's own slot(s) can ever match. Window closed/expired for
    // `matched` (the default, always) → falls straight through to the EXACT
    // SAME deny below.
    if managed_restart_window_open_for(matched) {
        emit_deny_event(
            event_kind::MANAGED_RESTART_ALLOWED,
            matched,
            current_cgroup(),
            current_pid(),
        );
        info!(&ctx, "task_kill allowed — managed-restart window open");
        return Ok(0);
    }

    emit_deny_event(
        event_kind::TASK_KILL_DENIED,
        matched,
        current_cgroup(),
        current_pid(),
    );
    info!(&ctx, "task_kill denied — protected cgroup target");
    Err(EPERM)
}

// ── 4. file_open ─────────────────────────────────────────────────────────────
//
// LSM_HOOK(int, 0, file_open, struct file *file)
// Only `file` — no separate path string. Deny by precomputed (dev, inode)
// identity compare against `/dev/mem` + `/proc/kcore` UNCONDITIONALLY (these
// have no legitimate use case on this box), and against the protected
// binary's OWN identity SCOPED to the protected cgroup (BpfFileDeny — deny
// tamper writes to the daemon's own executable while it's the protected
// process).
//
// NOTE: this program does not read `file->f_inode->i_ino` via
// `BPF_CORE_READ` (would need full CO-RE relocation support, unavailable in
// this aya-ebpf version — see `crate::vmlinux` doc). It instead calls the
// raw `aya_ebpf::helpers::bpf_probe_read_kernel` primitive at a
// runtime-derived byte offset (`FILE_F_INODE_OFF`/`INODE_I_INO_OFF`, patched
// at load time from the running kernel's BTF — see those globals' docs),
// isolated in `file_inode_ident` below.

/// The file's FULL identity: `(superblock device, inode number)`.
///
/// Both halves, always. An inode number on its own is unique inside one
/// filesystem and meaningless across two — see [`DEV_MEM_DEV`] for what that
/// cost.
#[inline(always)]
unsafe fn file_inode_ident(file: *const core::ffi::c_void) -> Option<(u64, u64)> {
    if file.is_null() {
        return None;
    }
    let f_inode_off = unsafe { core::ptr::read_volatile(&FILE_F_INODE_OFF) } as usize;
    let i_ino_off = unsafe { core::ptr::read_volatile(&INODE_I_INO_OFF) } as usize;
    let i_sb_off = unsafe { core::ptr::read_volatile(&INODE_I_SB_OFF) } as usize;
    let s_dev_off = unsafe { core::ptr::read_volatile(&SUPER_BLOCK_S_DEV_OFF) } as usize;

    let inode_ptr = unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel(
            (file as *const u8).add(f_inode_off).cast::<*const core::ffi::c_void>(),
        )
        .ok()?
    };
    if inode_ptr.is_null() {
        return None;
    }
    let ino: u64 = unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel(
            (inode_ptr as *const u8).add(i_ino_off).cast::<u64>(),
        )
        .ok()?
    };
    let sb_ptr = unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel(
            (inode_ptr as *const u8).add(i_sb_off).cast::<*const core::ffi::c_void>(),
        )
        .ok()?
    };
    if sb_ptr.is_null() {
        return None;
    }
    // `dev_t` is a u32 in the kernel; widened here so both halves compare as
    // u64 against the loader-patched globals.
    let dev: u32 = unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel(
            (sb_ptr as *const u8).add(s_dev_off).cast::<u32>(),
        )
        .ok()?
    };
    Some((dev as u64, ino))
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match try_file_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    let prior_ret: i32 = ctx.arg(1);
    if prior_ret != 0 {
        return Err(propagate_prior(prior_ret));
    }

    let file: *const core::ffi::c_void = ctx.arg(0);
    let Some((dev, ino)) = (unsafe { file_inode_ident(file) }) else {
        return Ok(0);
    };

    // BOTH halves must match. `0` on either side of a pair is inert: an entry
    // the loader could not fully resolve denies nothing, rather than denying
    // by inode number alone across every filesystem on the box.
    let dev_mem_ino = unsafe { core::ptr::read_volatile(&DEV_MEM_INODE) };
    let dev_mem_dev = unsafe { core::ptr::read_volatile(&DEV_MEM_DEV) };
    let kcore_ino = unsafe { core::ptr::read_volatile(&KCORE_INODE) };
    let kcore_dev = unsafe { core::ptr::read_volatile(&KCORE_DEV) };
    let is_dev_mem = dev_mem_ino != 0 && dev_mem_dev != 0 && ino == dev_mem_ino && dev == dev_mem_dev;
    let is_kcore = kcore_ino != 0 && kcore_dev != 0 && ino == kcore_ino && dev == kcore_dev;
    if is_dev_mem || is_kcore {
        emit_deny_event(event_kind::FILE_OPEN_DENIED, 0, current_cgroup(), current_pid());
        info!(&ctx, "file_open denied — /dev/mem or /proc/kcore");
        return Err(EPERM);
    }

    // BpfFileDeny — protected binary tamper-write deny, scoped to the
    // protected cgroup (only the protected process itself is defended;
    // opening the SAME on-disk binary path from an unrelated cgroup, e.g.
    // `cat`-ing it for inspection, is not denied here).
    let protected_bin_ino = unsafe { core::ptr::read_volatile(&PROTECTED_BINARY_INODE) };
    let protected_bin_dev = unsafe { core::ptr::read_volatile(&PROTECTED_BINARY_DEV) };
    if protected_bin_ino != 0
        && protected_bin_dev != 0
        && ino == protected_bin_ino
        && dev == protected_bin_dev
    {
        if let Some(matched) = matched_protected_slot(Some(current_cgroup())) {
            emit_deny_event(
                event_kind::FILE_OPEN_DENIED,
                matched,
                current_cgroup(),
                current_pid(),
            );
            info!(&ctx, "file_open denied — protected binary tamper (BpfFileDeny)");
            return Err(EPERM);
        }
    }

    Ok(0)
}

// ── 5. bpf (lock the door) ──────────────────────────────────────────────────
//
// LSM_HOOK(int, 0, bpf, int cmd, union bpf_attr *attr, unsigned int size)
// Confirmed against a live 6.8.0-generic kernel BTF (`bpf_lsm_bpf`): THREE
// real args (`cmd`, `attr`, `size`), no `bool kernel` fourth arg. The
// `kernel` arg exists on the newer bpf-token-era hooks (`bpf_prog_load`/
// `bpf_map_create`), not on this plain `bpf` syscall hook, and not on 6.8.
// The prior-eBPF-LSM-program's-return-value slot aya's `LsmContext` exposes
// beyond the C arg count therefore sits at index 3 (3 real args, 0-indexed
// arg(0..2), ret at arg(3)) — not arg(4).
//
// No kernel-internal-caller exemption is needed either: this hook is only
// reached from the userspace `bpf()` syscall path (`security_bpf()` inside
// `__sys_bpf`), so every invocation here already originates from a userspace
// caller with a real calling cgroup.
//
// Deny every bpf() syscall from any cgroup other than the warden's OWN (the
// warden owns the entire eBPF lifecycle and is the ONLY process that ever
// calls `bpf()` post-boot) — allowlist by cgroup id, not PID, so the
// warden's own restart-with-new-PID never self-locks-out.

#[lsm(hook = "bpf")]
pub fn bpf_hook(ctx: LsmContext) -> i32 {
    match try_bpf_hook(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_bpf_hook(ctx: LsmContext) -> Result<i32, i32> {
    let prior_ret: i32 = ctx.arg(3);
    if prior_ret != 0 {
        return Err(propagate_prior(prior_ret));
    }

    let owner_cgroup = unsafe { core::ptr::read_volatile(&OWNER_CGROUP) };
    if owner_cgroup == 0 {
        // Un-patched — the lock-the-door program should not have been
        // attached without a live OWNER_CGROUP value; fail OPEN here (allow)
        // rather than locking out every bpf() call box-wide on a
        // misconfigured load. The warden's own loader is responsible for
        // never attaching this program before patching OWNER_CGROUP via
        // `override_global` — this is exactly why the load itself always
        // re-establishes cleanly on the warden's own restart: during the
        // brief pre-attach window bpf() is unrestricted, no chicken-egg.
        return Ok(0);
    }

    let caller_cgroup = current_cgroup();
    if caller_cgroup == owner_cgroup {
        return Ok(0); // the owner's own bpf() calls (reload/reattach) — allowed
    }

    emit_deny_event(event_kind::BPF_LOAD_DENIED, owner_cgroup, caller_cgroup, current_pid());
    info!(&ctx, "bpf() denied — lock the door (non-owner cgroup)");
    Err(EPERM)
}

// ── 6. file_mprotect (W^X) ───────────────────────────────────────────────────
//
// LSM_HOOK(int, 0, file_mprotect, struct vm_area_struct *vma,
//          unsigned long reqprot, unsigned long prot)
// Deny a PROT_EXEC transition for the protected cgroup's own process — our
// Rust static daemons never JIT/self-modify, so denying any RW->RX (or
// fresh X) mprotect while the CALLING task is in the protected cgroup is
// free anti-shellcode depth.

/// `PROT_EXEC` bit — from `<sys/mman.h>` (`0x4`), duplicated here rather
/// than pulled from a libc-style crate (this crate is `no_std`/`no_main`, no
/// `libc` dependency).
const PROT_EXEC: u64 = 0x4;

#[lsm(hook = "file_mprotect")]
pub fn file_mprotect(ctx: LsmContext) -> i32 {
    match try_file_mprotect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_file_mprotect(ctx: LsmContext) -> Result<i32, i32> {
    let prior_ret: i32 = ctx.arg(3);
    if prior_ret != 0 {
        return Err(propagate_prior(prior_ret));
    }

    let prot: u64 = ctx.arg(2);
    if prot & PROT_EXEC == 0 {
        return Ok(0); // not an executable-mapping request — nothing to deny
    }

    if let Some(matched) = matched_protected_slot(Some(current_cgroup())) {
        emit_deny_event(
            event_kind::MPROTECT_DENIED,
            matched,
            current_cgroup(),
            current_pid(),
        );
        info!(&ctx, "file_mprotect denied — W^X (PROT_EXEC in protected cgroup)");
        return Err(EPERM);
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

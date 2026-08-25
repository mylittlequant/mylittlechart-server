//! Load → attach → pin — the Tier-2 aya BPF-LSM program set.
//!
//! Ported from mirage-secd's `bpf_lsm/loader.rs`: same loader mechanics,
//! same graceful-degrade contract (every step that can fail returns
//! `Err(String)` up to [`load_and_pin`]'s caller — never panics, never
//! crash-loops), same kernel-agnostic BTF offset derivation. Differences:
//! pin root is `/sys/fs/bpf/mlc`, the object filename is `mlc-warden-tier2`,
//! and the protected-slot count contract is `crate::MAX_PROTECTED_SLOTS`.
//!
//! # Kernel-agnostic offset derivation (kernel-upgrade loop)
//!
//! [`resolve_kernel_offsets`] reads the RUNNING kernel's own BTF
//! (`/sys/kernel/btf/vmlinux`, read once up front — BEFORE
//! `EbpfLoader::load`, since its result feeds `override_global` calls that
//! must happen before `.load()`) and derives the 8 struct field offsets
//! `warden-ebpf` needs for its cgroup-v2 walk (`cgroup.rs`) and inode
//! compare (`main.rs`'s `file_open` hook), via
//! [`crate::btf::resolve_member_offset`]. After a kernel upgrade + reboot,
//! the warden re-derives every offset from the NEW kernel's BTF at next boot
//! with no manual pahole/table update per kernel line.
//!
//! Every individual field falls back to the hardcoded KERNEL 6.8.0-130
//! default (`warden-ebpf::vmlinux`) on ANY resolution failure for THAT field
//! specifically (no BTF, struct/member not found, non-byte-aligned/bitfield
//! offset) — this function itself never fails the load; worst case is the
//! exact pre-BTF-derivation behavior.

use std::path::Path;

use anyhow::{Context, Result};
use aya::programs::Lsm;
use aya::{Btf, Ebpf, EbpfLoader};

use crate::btf::resolve_member_offset;

/// bpffs pin root for every mlc-warden-loaded program/map. Parent
/// directories are NOT auto-created by aya — `ensure_pin_dir` below creates
/// this (and the per-hook subpath) before any pinning happens.
const PIN_ROOT: &str = "/sys/fs/bpf/mlc";

/// The eBPF object embedded at compile time by `build.rs`'s
/// `aya-build::build_ebpf` step. `ML_WARDEN_BUILD_EBPF` unset (the default
/// on any non-Docker build — see `build.rs`) produces an EMPTY placeholder
/// file here, so `EbpfLoader::load` against it would fail with a parse
/// error — which is exactly the correct, honest outcome: a dev/CI build that
/// never ran the Docker eBPF stage has no real object to load, and
/// `load_and_pin` surfaces that as a normal `Err`, not a panic or a link
/// failure.
static EBPF_OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/mlc-warden-tier2"));

/// The full set of `#[lsm(hook = "...")]` program names in `warden-ebpf`,
/// matching the function names in `warden-ebpf/src/main.rs` — aya keys
/// `Ebpf::program_mut` by the Rust fn name (the ELF symbol under the
/// `lsm/<hook>` section), not the LSM hook string itself, so each entry here
/// pairs the aya program key with the actual LSM hook name `Lsm::load` needs
/// (which happens to differ for the `bpf` meta-hook, whose Rust function is
/// named `bpf_hook` to avoid shadowing the `bpf` keyword-adjacent
/// identifier).
const LSM_PROGRAMS: &[(&str, &str)] = &[
    ("ptrace_access_check", "ptrace_access_check"),
    ("ptrace_traceme", "ptrace_traceme"),
    ("task_kill", "task_kill"),
    ("file_open", "file_open"),
    ("bpf_hook", "bpf"),
    ("file_mprotect", "file_mprotect"),
];

/// KERNEL 6.8.0-130-generic fallback values — MUST stay numerically in sync
/// with `warden-ebpf/src/vmlinux.rs`'s own constants (that crate is
/// `no_std`/separately compiled, so this userspace crate cannot import them
/// directly; both sides document the same source: a live 6.8.0-generic box's
/// BTF/pahole dump). Used only when [`resolve_kernel_offsets`]'s BTF walk
/// fails for a given field — the corresponding eBPF global's own static
/// initializer already defaults to the same value independently, so a total
/// resolution failure here reproduces the exact pre-BTF-derivation behavior
/// even if `override_global` is skipped entirely for that field.
mod fallback_6_8_0_130 {
    pub(super) const TASK_STRUCT_CGROUPS: u64 = 3656;
    pub(super) const CSS_SET_DFL_CGRP: u64 = 128;
    pub(super) const CGROUP_KN: u64 = 248;
    pub(super) const KERNFS_NODE_ID: u64 = 104;
    pub(super) const FILE_F_INODE: u64 = 168;
    pub(super) const INODE_I_INO: u64 = 80;
    pub(super) const INODE_I_SB: u64 = 56;
    pub(super) const SUPER_BLOCK_S_DEV: u64 = 16;
}

/// The 8 struct field byte offsets `warden-ebpf` needs, resolved once per
/// [`load_and_pin`] call by [`resolve_kernel_offsets`].
struct KernelOffsets {
    task_struct_cgroups: u64,
    css_set_dfl_cgrp: u64,
    cgroup_kn: u64,
    kernfs_node_id: u64,
    file_f_inode: u64,
    inode_i_ino: u64,
    inode_i_sb: u64,
    super_block_s_dev: u64,
    /// `true` iff EVERY field resolved from live BTF (none fell back) —
    /// drives the one-time observability log line's `source=` field.
    all_from_btf: bool,
}

/// Resolve one field's offset from `btf`, falling back to `default` (and
/// flipping `*all_from_btf` to `false`) on any error. The specific failure
/// reason is folded into a `debug!` line — not surfaced further, since a
/// per-field fallback is an expected, handled outcome, not a load failure.
fn resolve_one_field(
    btf_bytes: &[u8],
    struct_name: &str,
    member_name: &str,
    default: u64,
    all_from_btf: &mut bool,
) -> u64 {
    match resolve_member_offset(btf_bytes, struct_name, member_name) {
        Ok(offset) => offset as u64,
        Err(reason) => {
            *all_from_btf = false;
            tracing::debug!(
                "[mlc-warden/bpf_lsm] BTF offset resolution failed for {struct_name}.{member_name}, \
                 falling back to {default}: {reason}"
            );
            default
        }
    }
}

/// Derive [`KernelOffsets`] from the running kernel's own BTF, falling back
/// field-by-field to the KERNEL 6.8.0-130-generic defaults on any failure.
/// Never fails — a total BTF read failure (e.g. `CONFIG_DEBUG_INFO_BTF`
/// unset) simply produces every field as a fallback default, which is
/// exactly the hardcoded pre-BTF-derivation behavior.
fn resolve_kernel_offsets(btf_bytes: &[u8]) -> KernelOffsets {
    let mut all_from_btf = true;

    let offsets = KernelOffsets {
        task_struct_cgroups: resolve_one_field(
            btf_bytes,
            "task_struct",
            "cgroups",
            fallback_6_8_0_130::TASK_STRUCT_CGROUPS,
            &mut all_from_btf,
        ),
        css_set_dfl_cgrp: resolve_one_field(
            btf_bytes,
            "css_set",
            "dfl_cgrp",
            fallback_6_8_0_130::CSS_SET_DFL_CGRP,
            &mut all_from_btf,
        ),
        cgroup_kn: resolve_one_field(
            btf_bytes,
            "cgroup",
            "kn",
            fallback_6_8_0_130::CGROUP_KN,
            &mut all_from_btf,
        ),
        kernfs_node_id: resolve_one_field(
            btf_bytes,
            "kernfs_node",
            "id",
            fallback_6_8_0_130::KERNFS_NODE_ID,
            &mut all_from_btf,
        ),
        file_f_inode: resolve_one_field(
            btf_bytes,
            "file",
            "f_inode",
            fallback_6_8_0_130::FILE_F_INODE,
            &mut all_from_btf,
        ),
        inode_i_ino: resolve_one_field(
            btf_bytes,
            "inode",
            "i_ino",
            fallback_6_8_0_130::INODE_I_INO,
            &mut all_from_btf,
        ),
        inode_i_sb: resolve_one_field(
            btf_bytes,
            "inode",
            "i_sb",
            fallback_6_8_0_130::INODE_I_SB,
            &mut all_from_btf,
        ),
        super_block_s_dev: resolve_one_field(
            btf_bytes,
            "super_block",
            "s_dev",
            fallback_6_8_0_130::SUPER_BLOCK_S_DEV,
            &mut all_from_btf,
        ),
        all_from_btf,
    };

    let source = if offsets.all_from_btf { "BTF" } else { "fallback" };
    tracing::info!(
        "[mlc-warden/bpf_lsm] kernel offsets source={source}: task.cgroups={} css.dfl_cgrp={} \
         cgroup.kn={} kernfs.id={} file.f_inode={} inode.i_ino={} inode.i_sb={} \
         super_block.s_dev={}",
        offsets.task_struct_cgroups,
        offsets.css_set_dfl_cgrp,
        offsets.cgroup_kn,
        offsets.kernfs_node_id,
        offsets.file_f_inode,
        offsets.inode_i_ino,
        offsets.inode_i_sb,
        offsets.super_block_s_dev,
    );

    offsets
}

/// Live handles for the loaded+attached Tier-2 program set. Dropping this
/// does NOT detach the kernel-side enforcement by itself — enforcement is
/// tied to the leaked attach-link fds, which live exactly as long as THIS
/// process (see the `std::mem::forget(links)` note in `load_and_pin_inner`).
/// This struct's only jobs are to keep the ringbuf map's fd alive for the
/// sensor consumer loop and to hand out the writable map handles
/// (`WINDOW_*`, `PROTECTED_CGROUP_MAP`, `KILL_PROTECTED_SLOTS`) to
/// `crate::tier2::Tier2`.
pub struct BpfLsmHandles {
    /// The loaded `aya::Ebpf` instance — kept alive so `ebpf.take_map(...)`
    /// remains valid for the lifetime of this process.
    ebpf: Ebpf,
}

impl BpfLsmHandles {
    /// Take ownership of the `DENY_EVENTS` ringbuf map out of the held
    /// `Ebpf` instance, for `sensor::run_sensor_loop` to consume. Returns
    /// `None` if the map is missing or already taken elsewhere (a daemon
    /// only ever calls this once, at boot). Taking the map does NOT affect
    /// the already-attached LSM programs — those live independently of this
    /// handle (process-lived link fds).
    pub fn take_ringbuf(&mut self) -> Option<aya::maps::RingBuf<aya::maps::MapData>> {
        let map = self.ebpf.take_map("DENY_EVENTS")?;
        aya::maps::RingBuf::try_from(map).ok()
    }

    /// Take ownership of the `WINDOW_CGROUP` N-slot array map — the
    /// cgroup-id half of each `(cgroup_id, expiry_ns)` targeted
    /// managed-restart window slot. Returns `None` if the map is missing
    /// (e.g. an older `warden-ebpf` object) or already taken — callers must
    /// treat that as "the managed-restart window is unavailable," never
    /// panic.
    pub fn take_window_cgroup(&mut self) -> Option<aya::maps::Array<aya::maps::MapData, u64>> {
        let map = self.ebpf.take_map("WINDOW_CGROUP")?;
        aya::maps::Array::try_from(map).ok()
    }

    /// Take ownership of the `WINDOW_EXPIRY` N-slot array map — the
    /// expiry-timestamp half of each `(cgroup_id, expiry_ns)` window slot,
    /// parallel to [`Self::take_window_cgroup`] exactly (same map/slot
    /// count, same missing/already-taken semantics).
    pub fn take_window_expiry(&mut self) -> Option<aya::maps::Array<aya::maps::MapData, u64>> {
        let map = self.ebpf.take_map("WINDOW_EXPIRY")?;
        aya::maps::Array::try_from(map).ok()
    }

    /// Take ownership of the `PROTECTED_CGROUP_MAP` N-slot array map — the
    /// flat-fill protected-cgroup table, rewritten in full by
    /// `crate::tier2::Tier2::rearm` after any managed restart (slot index is
    /// fill order, never a per-unit identity). Returns `None` if the map is
    /// missing or already taken — callers must treat that as "protected
    /// re-arm is unavailable," never panic.
    pub fn take_protected_cgroup_map(&mut self) -> Option<aya::maps::Array<aya::maps::MapData, u64>> {
        let map = self.ebpf.take_map("PROTECTED_CGROUP_MAP")?;
        aya::maps::Array::try_from(map).ok()
    }

    /// Take ownership of the `KILL_PROTECTED_SLOTS` N-slot array map —
    /// mirrors [`Self::take_protected_cgroup_map`] exactly, the parallel
    /// per-slot kill-eligibility boolean table. `None` if the map is missing
    /// or already taken.
    pub fn take_kill_protected_slots(&mut self) -> Option<aya::maps::Array<aya::maps::MapData, u8>> {
        let map = self.ebpf.take_map("KILL_PROTECTED_SLOTS")?;
        aya::maps::Array::try_from(map).ok()
    }
}

/// Load, attach, and pin every Tier-2 program, patch the global config
/// statics (`OWNER_CGROUP`/`DEV_MEM_*`/`KCORE_*`/`PROTECTED_BINARY_*`) AND
/// the 8 kernel-agnostic struct offset globals (resolved by
/// [`resolve_kernel_offsets`] from the running kernel's own BTF), SET the
/// initial value of every slot in the writable `PROTECTED_CGROUP_MAP` +
/// `KILL_PROTECTED_SLOTS` (post-load, since map writes are not
/// `override_global` patches), and return the live handles.
///
/// # Parameters
///
/// - `protected_slots` — a FLAT, fill-order `(cgroup_id, is_kill_protected)`
///   list (the protege's cgroup + the warden's own, both `kill=true`).
///   Written into `PROTECTED_CGROUP_MAP`/`KILL_PROTECTED_SLOTS` slots
///   `0..len`; slots `len..MAX_PROTECTED_SLOTS` are explicitly zeroed
///   (reconcile — clears any stale entry from a prior load). Re-armed later
///   (after a managed restart changes the protege's cgroup id) via
///   `crate::tier2::Tier2::rearm`.
/// - `owner_cgroup_id` — the SOLE bpf lock-the-door allowlist cgroup id (the
///   warden's OWN cgroup, patched into `OWNER_CGROUP`).
/// - `dev_mem_inode` / `kcore_inode` — precomputed inode numbers of
///   `/dev/mem` / `/proc/kcore` on THIS box (see [`precompute_inodes`]).
/// - `protected_binary_path` — the protege's on-disk binary (BpfFileDeny). A
///   PATH and not an inode, because the deny needs the superblock device as
///   well and the caller has no business computing half an identity — see
///   [`precompute_devices`]. An empty path skips this check.
///
/// Never panics. Every failure path returns `Err(String)` with a
/// human-readable reason — the graceful-degrade contract this whole module
/// exists to satisfy.
pub fn load_and_pin(
    protected_slots: &[(u64, bool)],
    owner_cgroup_id: u64,
    dev_mem_inode: u64,
    kcore_inode: u64,
    protected_binary_path: &str,
) -> Result<BpfLsmHandles, String> {
    load_and_pin_inner(
        protected_slots,
        owner_cgroup_id,
        dev_mem_inode,
        kcore_inode,
        protected_binary_path,
    )
    .map_err(|e| format!("{e:#}"))
}

fn load_and_pin_inner(
    protected_slots: &[(u64, bool)],
    owner_cgroup_id: u64,
    dev_mem_inode: u64,
    kcore_inode: u64,
    protected_binary_path: &str,
) -> Result<BpfLsmHandles> {
    // The device half of each identity is derived HERE, from the same paths
    // the inode half came from, so the two can never be resolved from
    // different sources or by different callers.
    let (dev_mem_dev, kcore_dev) = precompute_devices();
    let protected_binary_inode =
        if protected_binary_path.is_empty() { 0 } else { inode_of(protected_binary_path) };
    let protected_binary_dev = if protected_binary_path.is_empty() {
        0
    } else {
        precompute_binary_device(protected_binary_path)
    };
    if EBPF_OBJECT.is_empty() {
        anyhow::bail!(
            "warden-ebpf object is empty — this build never ran the Docker Tier-2 stage \
             (ML_WARDEN_BUILD_EBPF unset, see build.rs); Tier-2 is not available from this binary"
        );
    }

    // Bump the memlock rlimit — needed on older kernels that don't use
    // memcg-based BPF accounting (aya-template's own documented reason).
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: setrlimit with RLIMIT_MEMLOCK and a well-formed rlimit struct
    // is a documented, side-effect-bounded syscall; a failure here is
    // non-fatal (older-kernel accommodation only) and is logged, not
    // propagated as an error.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if rc != 0 {
        tracing::debug!("[mlc-warden/bpf_lsm] setrlimit(RLIMIT_MEMLOCK) failed — proceeding anyway");
    }

    ensure_pin_dir(PIN_ROOT).context("create bpffs pin directory")?;

    // Read the running kernel's raw BTF blob BEFORE `EbpfLoader::load` —
    // `resolve_kernel_offsets` needs it to compute the `override_global`
    // values the loader call below depends on. A missing/unreadable BTF
    // file (older kernel, `CONFIG_DEBUG_INFO_BTF` unset) is handled at the
    // per-field level inside `resolve_kernel_offsets` (empty bytes fail
    // every field's resolution identically to a real parse failure), so
    // this read itself never aborts the load.
    let btf_bytes = std::fs::read("/sys/kernel/btf/vmlinux").unwrap_or_default();
    let offsets = resolve_kernel_offsets(&btf_bytes);

    let mut ebpf = EbpfLoader::new()
        .default_map_pin_directory(PIN_ROOT)
        .override_global("OWNER_CGROUP", &owner_cgroup_id, true)
        .override_global("DEV_MEM_INODE", &dev_mem_inode, true)
        .override_global("DEV_MEM_DEV", &dev_mem_dev, true)
        .override_global("KCORE_INODE", &kcore_inode, true)
        .override_global("KCORE_DEV", &kcore_dev, true)
        .override_global("PROTECTED_BINARY_INODE", &protected_binary_inode, true)
        .override_global("PROTECTED_BINARY_DEV", &protected_binary_dev, true)
        .override_global("TASK_STRUCT_CGROUPS_OFF", &offsets.task_struct_cgroups, true)
        .override_global("CSS_SET_DFL_CGRP_OFF", &offsets.css_set_dfl_cgrp, true)
        .override_global("CGROUP_KN_OFF", &offsets.cgroup_kn, true)
        .override_global("KERNFS_NODE_ID_OFF", &offsets.kernfs_node_id, true)
        .override_global("FILE_F_INODE_OFF", &offsets.file_f_inode, true)
        .override_global("INODE_I_INO_OFF", &offsets.inode_i_ino, true)
        .override_global("INODE_I_SB_OFF", &offsets.inode_i_sb, true)
        .override_global("SUPER_BLOCK_S_DEV_OFF", &offsets.super_block_s_dev, true)
        .load(EBPF_OBJECT)
        .context("EbpfLoader::load warden-ebpf object")?;

    // `PROTECTED_CGROUP_MAP` is a WRITABLE N-slot map (not a `.rodata`
    // const), so its boot value is SET here post-load rather than patched
    // via `override_global` pre-load — the whole point of the const→map
    // conversion (see that static's doc in `warden-ebpf/src/main.rs`) is
    // that this same write path is reachable again later, after a managed
    // restart, via `Tier2::rearm`. FLAT fill: slot index is fill order, not
    // a per-unit compile-time slot. Slots beyond `protected_slots.len()` are
    // explicitly zeroed (reconcile — clears any stale entry from a prior
    // load). Missing map (a `warden-ebpf` object built before this map
    // existed) degrades to "no protected cgroup armed" — logged, never a
    // load failure.
    match ebpf.map_mut("PROTECTED_CGROUP_MAP") {
        Some(map) => match aya::maps::Array::<_, u64>::try_from(map) {
            Ok(mut arr) => {
                for (i, (id, _kill)) in protected_slots.iter().enumerate() {
                    if i >= crate::MAX_PROTECTED_SLOTS {
                        break;
                    }
                    if let Err(e) = arr.set(i as u32, *id, 0) {
                        tracing::warn!("[mlc-warden/bpf_lsm] PROTECTED_CGROUP_MAP slot {i} set failed: {e}");
                    }
                }
                for i in protected_slots.len()..crate::MAX_PROTECTED_SLOTS {
                    if let Err(e) = arr.set(i as u32, 0u64, 0) {
                        tracing::warn!("[mlc-warden/bpf_lsm] PROTECTED_CGROUP_MAP slot {i} zero failed: {e}");
                    }
                }
            }
            Err(e) => tracing::warn!("[mlc-warden/bpf_lsm] PROTECTED_CGROUP_MAP wrong map type: {e}"),
        },
        None => tracing::warn!(
            "[mlc-warden/bpf_lsm] PROTECTED_CGROUP_MAP missing from eBPF object — protected-cgroup \
             deny scoping is inert until a rebuilt object is deployed"
        ),
    }

    // `KILL_PROTECTED_SLOTS` — the SAME flat fill order as
    // `PROTECTED_CGROUP_MAP` above, one `kill` bool per slot. Missing map
    // degrades to "nothing kill-protected" — logged, never a load failure.
    match ebpf.map_mut("KILL_PROTECTED_SLOTS") {
        Some(map) => match aya::maps::Array::<_, u8>::try_from(map) {
            Ok(mut arr) => {
                for (i, (_id, kill)) in protected_slots.iter().enumerate() {
                    if i >= crate::MAX_PROTECTED_SLOTS {
                        break;
                    }
                    if let Err(e) = arr.set(i as u32, u8::from(*kill), 0) {
                        tracing::warn!("[mlc-warden/bpf_lsm] KILL_PROTECTED_SLOTS slot {i} set failed: {e}");
                    }
                }
                for i in protected_slots.len()..crate::MAX_PROTECTED_SLOTS {
                    if let Err(e) = arr.set(i as u32, 0u8, 0) {
                        tracing::warn!("[mlc-warden/bpf_lsm] KILL_PROTECTED_SLOTS slot {i} zero failed: {e}");
                    }
                }
            }
            Err(e) => tracing::warn!("[mlc-warden/bpf_lsm] KILL_PROTECTED_SLOTS wrong map type: {e}"),
        },
        None => tracing::warn!(
            "[mlc-warden/bpf_lsm] KILL_PROTECTED_SLOTS missing from eBPF object — every protected unit \
             is scrape-only (fail-open to killable) until a rebuilt object is deployed"
        ),
    }

    let btf = Btf::from_sys_fs().context("Btf::from_sys_fs — kernel lacks BTF (CONFIG_DEBUG_INFO_BTF)")?;

    let mut links = Vec::with_capacity(LSM_PROGRAMS.len());
    for (program_key, lsm_hook) in LSM_PROGRAMS {
        let link = attach_one(&mut ebpf, &btf, program_key, lsm_hook)
            .with_context(|| format!("program '{program_key}' (hook '{lsm_hook}')"))?;
        links.push(link);
    }

    // Enforce for the WHOLE process lifetime by LEAKING the attach links. A
    // `BPF_LSM_MAC` program enforces its `-EPERM` only while its link fd is
    // open, and that fd also holds the program loaded. Tying that fd to any
    // droppable owner let the attachment die the moment that owner dropped —
    // Tier-2 silently inert (`bpftool prog show` = 0 lsm programs). Pinning
    // the link to bpffs would also persist it, but kernels reject
    // `BPF_OBJ_PIN` of an LSM link (EPERM). mlc-warden wants these hooks
    // enforced for exactly as long as it lives, so we leak the fds: they
    // close on process exit (old attach detaches, a restart re-attaches
    // cleanly — no pile-up), which is precisely the desired scope.
    // Consequence: `arm`/`run` MUST NOT exit — enforcement dies with the
    // process (systemd `Restart=always` re-arms).
    std::mem::forget(links);

    Ok(BpfLsmHandles { ebpf })
}

/// Load + attach ONE LSM program and return its OWNED link. The caller must
/// keep the returned link alive for as long as enforcement is wanted — a
/// `BPF_LSM_MAC` program stops enforcing the instant its link is dropped. We
/// deliberately do NOT pin the program or the link: pinning only the program
/// left the hooks loaded-but-unattached (Tier-2 inert), and pinning the LINK
/// is rejected with EPERM — so the link is leaked process-lived by the
/// caller.
fn attach_one(
    ebpf: &mut Ebpf,
    btf: &Btf,
    program_key: &str,
    lsm_hook: &str,
) -> Result<aya::programs::lsm::LsmLink> {
    let program: &mut Lsm = ebpf
        .program_mut(program_key)
        .ok_or_else(|| anyhow::anyhow!("program '{program_key}' not found in eBPF object"))?
        .try_into()
        .context("program is not an Lsm program")?;

    program.load(lsm_hook, btf).context("Lsm::load")?;
    let link_id = program.attach().context("Lsm::attach")?;
    let link = program.take_link(link_id).context("Lsm::take_link")?;
    Ok(link)
}

/// `mkdir -p` the bpffs pin directory — aya does NOT create parent
/// directories itself.
fn ensure_pin_dir(path: &str) -> Result<()> {
    std::fs::create_dir_all(Path::new(path)).with_context(|| format!("create_dir_all({path})"))
}

/// Precompute the inode numbers of `/dev/mem` and `/proc/kcore` on this box
/// (compare `file->f_inode->i_ino` in-kernel, never a path string). Returns
/// `(dev_mem_inode, kcore_inode)`, `0` for either that doesn't exist or
/// isn't readable (the eBPF side treats `0` as "skip this check" — see
/// `warden-ebpf/src/main.rs`'s `DEV_MEM_INODE`/`KCORE_INODE` static docs).
#[must_use]
pub fn precompute_inodes() -> (u64, u64) {
    (inode_of("/dev/mem"), inode_of("/proc/kcore"))
}

/// The superblock devices of `/dev/mem` and `/proc/kcore`, in the KERNEL's
/// `dev_t` encoding — the other half of the identity the deny hooks compare.
///
/// Returns `(dev_mem_dev, kcore_dev)`, `0` for either that cannot be read.
/// The eBPF side treats `0` as "skip this entry entirely", which is the safe
/// direction: an entry we cannot aim denies nothing.
#[must_use]
pub fn precompute_devices() -> (u64, u64) {
    (kernel_dev_of("/dev/mem"), kernel_dev_of("/proc/kcore"))
}

/// The superblock device of `binary_path`, kernel-encoded. `0` if unreadable.
#[must_use]
pub fn precompute_binary_device(binary_path: &str) -> u64 {
    kernel_dev_of(binary_path)
}

/// `stat().st_dev` re-encoded the way the KERNEL stores it in
/// `super_block.s_dev`.
///
/// These are two different encodings and the difference is not cosmetic.
/// glibc packs `st_dev` as (roughly) `major << 8 | minor` with extension
/// bits; the kernel's `dev_t` is `MKDEV(major, minor) = major << 20 |
/// minor`. They coincide only when the major is 0 — true for the anonymous
/// devices sysfs/cgroup2/proc get, and false for the real block device the
/// protected binary lives on. Comparing the raw `st_dev` would have silently
/// disabled the binary-tamper deny on every box while looking correct.
fn kernel_dev_of(path: &str) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let Ok(md) = std::fs::metadata(path) else { return 0 };
    let st_dev = md.dev();
    // libc::major/minor without pulling libc's macros in: the glibc layout.
    let major = ((st_dev >> 8) & 0xfff) | ((st_dev >> 32) & !0xfffu64);
    let minor = (st_dev & 0xff) | ((st_dev >> 12) & !0xffu64);
    (major << 20) | minor
}

fn inode_of(path: &str) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).map(|m| m.ino()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inode_of_nonexistent_path_is_zero() {
        assert_eq!(inode_of("/this/path/does/not/exist/on/any/box"), 0);
    }

    #[test]
    fn precompute_inodes_never_panics() {
        let (dev_mem, kcore) = precompute_inodes();
        // On a container without /dev/mem or /proc/kcore these are
        // legitimately 0 — the function must not panic either way.
        let _ = dev_mem;
        let _ = kcore;
    }

    #[test]
    fn lsm_programs_table_has_no_duplicate_keys() {
        let mut keys: Vec<&str> = LSM_PROGRAMS.iter().map(|(k, _)| *k).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), LSM_PROGRAMS.len(), "no duplicate program keys");
    }
}

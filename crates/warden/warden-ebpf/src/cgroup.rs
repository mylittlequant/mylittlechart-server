//! Cgroup-of-TARGET resolution — the load-bearing nuance:
//! `bpf_get_current_cgroup_id()` reads the CALLING task's cgroup, which is
//! the WRONG task for every deny hook here (`ptrace_access_check`,
//! `task_kill`, `file_mprotect`) — those must scope on the TARGET/tracee's
//! cgroup, not the attacker's.
//!
//! Ported verbatim (mechanics) from mirage-secd's `secd-ebpf/src/cgroup.rs`.
//!
//! # cgroup-v2 manual struct-offset walk (the only path)
//!
//! The target box (mlc-utah-1, Ubuntu 24.04) is cgroup-v2-unified
//! (`cgroup2fs`). aya-ebpf 0.2 has no load-time CO-RE relocation (aya issue
//! #349 — no `BPF_CORE_READ`-equivalent in this crate version), and the
//! `bpf_task_get_cgroup1`/`bpf_cgroup_release` kfunc pair is NOT relocatable
//! by aya's kfunc-call codegen (`extern "C"` + `#[link_name]` lowers to a
//! bogus BPF-to-BPF call rather than a real kfunc call relocation), which is
//! exactly the load failure this module avoids (`error relocating
//! 'ptrace_access_check': function 0x38 not found`). The v1
//! `subsys[]`-index walk (which needs a CO-RE-resolved `cgroup_subsys_id`
//! enum value anyway, equally unavailable) is likewise not usable. The only
//! path left is a straight-line pointer walk down the v2 unified hierarchy:
//!
//! ```text
//! task_struct.cgroups   (css_set*)      -> css_set.dfl_cgrp (cgroup*)
//! cgroup.kn              (kernfs_node*) -> kernfs_node.id (u64, plain field)
//! ```
//!
//! Every hop is read via `aya_ebpf::helpers::bpf_probe_read_kernel` with a
//! null/error check before the next hop — the verifier does not trust a
//! kernel-internal pointer reached by walking away from the trusted LSM hook
//! argument, so each intermediate pointer must be re-validated by a fresh
//! helper call rather than dereferenced directly.
//!
//! Offsets are read at runtime from `crate::{TASK_STRUCT_CGROUPS_OFF,
//! CSS_SET_DFL_CGRP_OFF, CGROUP_KN_OFF, KERNFS_NODE_ID_OFF}` — globals
//! patched at load time by the userspace loader
//! (`bpf_lsm/loader.rs::resolve_kernel_offsets`) from the RUNNING kernel's
//! own BTF, kernel-agnostic. Each global DEFAULTS to the KERNEL
//! 6.8.0-130-generic value from [`crate::vmlinux`] (used verbatim if BTF
//! derivation fails for any reason), so this module's own logic never needs
//! to change across kernel lines — only the resolved values do.

use aya_ebpf::helpers::bpf_probe_read_kernel;

use crate::{CGROUP_KN_OFF, CSS_SET_DFL_CGRP_OFF, KERNFS_NODE_ID_OFF, TASK_STRUCT_CGROUPS_OFF};

/// Resolve the cgroup id of an arbitrary `task_struct` pointer (the TARGET,
/// e.g. `ctx.arg(0)` in `ptrace_access_check`/`task_kill` — never the
/// calling task). Returns `None` if resolution fails at any step (verifier
/// safety: every kernel-memory read here can legitimately fail — a
/// partially-torn-down task, a null intermediate pointer, or a kernel layout
/// this build doesn't understand). Callers MUST treat `None` as "deny scope
/// unknown" and fail toward the safer branch for their specific hook (see
/// each hook's comment in `main.rs`).
///
/// # Safety
///
/// `task` must be a valid, non-null `task_struct*` obtained from a trusted
/// LSM hook argument (`ctx.arg::<*mut _>(n)`), not attacker-controlled data.
#[inline(always)]
pub unsafe fn cgroup_id_of_task(task: *const core::ffi::c_void) -> Option<u64> {
    if task.is_null() {
        return None;
    }

    let task_struct_cgroups_off = unsafe { core::ptr::read_volatile(&TASK_STRUCT_CGROUPS_OFF) } as usize;
    let css_set_dfl_cgrp_off = unsafe { core::ptr::read_volatile(&CSS_SET_DFL_CGRP_OFF) } as usize;

    // Hop 1: task_struct -> cgroups (css_set*).
    let css_set_ptr = unsafe {
        bpf_probe_read_kernel(
            (task as *const u8).add(task_struct_cgroups_off).cast::<*const core::ffi::c_void>(),
        )
        .ok()?
    };
    if css_set_ptr.is_null() {
        return None;
    }

    // Hop 2: css_set -> dfl_cgrp (cgroup*) — the v2 unified hierarchy's
    // cgroup for this task.
    let cgroup_ptr = unsafe {
        bpf_probe_read_kernel(
            (css_set_ptr as *const u8).add(css_set_dfl_cgrp_off).cast::<*const core::ffi::c_void>(),
        )
        .ok()?
    };
    if cgroup_ptr.is_null() {
        return None;
    }

    unsafe { read_cgroup_id(cgroup_ptr) }
}

/// Read `cgroup.kn.id` given a `cgroup*` — the shared tail of the walk
/// (hops 3 and 4).
#[inline(always)]
unsafe fn read_cgroup_id(cgroup_ptr: *const core::ffi::c_void) -> Option<u64> {
    let cgroup_kn_off = unsafe { core::ptr::read_volatile(&CGROUP_KN_OFF) } as usize;
    let kernfs_node_id_off = unsafe { core::ptr::read_volatile(&KERNFS_NODE_ID_OFF) } as usize;

    // Hop 3: cgroup -> kn (kernfs_node*).
    let kn_ptr = unsafe {
        bpf_probe_read_kernel(
            (cgroup_ptr as *const u8).add(cgroup_kn_off).cast::<*const core::ffi::c_void>(),
        )
        .ok()?
    };
    if kn_ptr.is_null() {
        return None;
    }

    // Hop 4: kernfs_node -> id (a plain u64 field). The kernel packs this as
    // `(generation << 32) | ino` (`kernfs_gen(kn) << 32 | kernfs_ino(kn)`);
    // `bpf_get_current_cgroup_id()` returns this FULL value. The warden's
    // userspace resolves `PROTECTED_CGROUP_MAP`'s entry via `stat().ino()` on
    // the cgroupfs dir, which the kernel sets to `inode->i_ino =
    // kernfs_ino(kn) = kn->id & 0xffffffff` (the LOW 32 bits only — no
    // generation). So we MUST mask to the low 32 bits here, or the compare
    // against `PROTECTED_CGROUP_MAP`'s entry never matches once a cgroup's
    // generation is non-zero (every service cgroup created after early boot)
    // — which silently disabled every cgroup-scoped deny. The low-32 ino
    // uniquely identifies a live cgroup at any instant, so masking is exact.
    let id = unsafe {
        bpf_probe_read_kernel((kn_ptr as *const u8).add(kernfs_node_id_off).cast::<u64>()).ok()?
    };
    Some(id & 0xffff_ffff)
}

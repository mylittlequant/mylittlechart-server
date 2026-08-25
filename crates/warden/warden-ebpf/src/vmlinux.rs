//! Kernel struct field-offset FALLBACK DEFAULTS (`task_struct`/`css_set`/
//! `cgroup`/`kernfs_node`/`file`/`inode`) for the cgroup-v2 manual walk in
//! [`crate::cgroup`] and the `file_open` inode-compare hook in `main.rs`.
//!
//! Ported verbatim from mirage-secd's `secd-ebpf/src/vmlinux.rs`.
//!
//! # Fallback defaults, not the primary path
//!
//! aya-ebpf 0.2 has no load-time CO-RE relocation for arbitrary kernel
//! structs (aya issue #349): there is no `BPF_CORE_READ`-equivalent macro
//! that re-resolves a field offset against the RUNNING kernel's BTF from
//! INSIDE the eBPF program itself in this crate version. The PRIMARY path is
//! therefore kernel-agnostic runtime derivation done in USERSPACE, before
//! load: the loader (`mlc-warden`'s `bpf_lsm/loader.rs::resolve_kernel_offsets`)
//! walks the running kernel's own `/sys/kernel/btf/vmlinux` BTF at boot,
//! resolves each field's real byte offset on THAT kernel, and patches it
//! into the eBPF program's globals via `EbpfLoader::override_global` before
//! `.load()` — the same mechanism used for `OWNER_CGROUP`/the inode globals.
//! This closes the kernel-upgrade loop: after a kernel upgrade + reboot, the
//! warden re-derives offsets from the NEW kernel's BTF with no manual
//! pahole/table update.
//!
//! The constants in this file are the FALLBACK values used only if that BTF
//! walk fails for any reason (no BTF exposed, type/member not found,
//! implausible resolved offset) — worst case, behavior is identical to the
//! pre-BTF-derivation code: exactly the KERNEL 6.8.0-130-generic table
//! below, extracted from a live box's BTF via `pahole` (same 6.8.0-generic
//! kernel line as the mlc-utah-1 target's 6.8.0-90-generic, so the fallback
//! is close but NOT guaranteed identical — Ubuntu generic kernels always
//! ship `CONFIG_DEBUG_INFO_BTF=y`, so the BTF path is the expected one).
//!
//! # cgroup-v2 walk (the only path — v1 removed)
//!
//! The target box is cgroup-v2-unified (`cgroup2fs`). The v2 chain is a
//! straight-line pointer walk with a fixed field at each hop, independent of
//! `CONFIG_CGROUPS` subsystem enablement:
//!
//! ```text
//! task_struct.cgroups   (css_set*)   -> css_set.dfl_cgrp (cgroup*)
//! cgroup.kn              (kernfs_node*) -> kernfs_node.id (u64, plain field)
//! ```

/// Offsets within `struct task_struct` (KERNEL 6.8.0-130-generic).
pub struct TaskStructOffsets {
    /// Offset of `task_struct.cgroups` (a `struct css_set *`).
    pub cgroups: usize,
}

/// KERNEL 6.8.0-130-generic — validated via live box BTF/pahole.
pub const TASK_STRUCT_OFFSETS: TaskStructOffsets = TaskStructOffsets { cgroups: 3656 };

/// Offsets within `struct css_set` (KERNEL 6.8.0-130-generic).
pub struct CssSetOffsets {
    /// Offset of `css_set.dfl_cgrp` (a `struct cgroup *`) — the v2 unified
    /// hierarchy's cgroup for this task.
    pub dfl_cgrp: usize,
}

/// KERNEL 6.8.0-130-generic — validated via live box BTF/pahole.
pub const CSS_SET_OFFSETS: CssSetOffsets = CssSetOffsets { dfl_cgrp: 128 };

/// Offsets within `struct cgroup` (KERNEL 6.8.0-130-generic).
pub struct CgroupOffsets {
    /// Offset of `cgroup.kn` (a `struct kernfs_node *`).
    pub kn: usize,
}

/// KERNEL 6.8.0-130-generic — validated via live box BTF/pahole.
pub const CGROUP_OFFSETS: CgroupOffsets = CgroupOffsets { kn: 248 };

/// Offsets within `struct kernfs_node` (KERNEL 6.8.0-130-generic).
pub struct KernfsNodeOffsets {
    /// Offset of `kernfs_node.id` — a plain `u64` (NOT a nested union on
    /// this kernel line; read directly, no `.id.id`/`.ino` sub-hop). This is
    /// the stable cgroup id exposed to userspace via
    /// `/sys/fs/cgroup/.../cgroup.id`, matching what
    /// `bpf_get_current_cgroup_id()` returns for the CALLING task — so the
    /// manual chain's final read lands on the same field, making ids
    /// directly comparable between the two.
    pub id: usize,
}

/// KERNEL 6.8.0-130-generic — validated via live box BTF/pahole.
pub const KERNFS_NODE_OFFSETS: KernfsNodeOffsets = KernfsNodeOffsets { id: 104 };

/// Offsets within `struct file` (KERNEL 6.8.0-130-generic) — used by the
/// `file_open` hook's inode compare in `main.rs`.
pub struct FileOffsets {
    /// Offset of `file.f_inode` (a `struct inode *`). Snapped via `bpftool
    /// btf dump file /sys/kernel/btf/vmlinux format c` on kernel
    /// `6.8.0-130-generic` (BTF `bits_offset=1344` / 8 = byte 168).
    pub f_inode: usize,
}

/// KERNEL 6.8.0-130-generic — validated via live box BTF/pahole.
pub const FILE_OFFSETS: FileOffsets = FileOffsets { f_inode: 168 };

/// Offsets within `struct inode` (KERNEL 6.8.0-130-generic).
pub struct InodeOffsets {
    /// Offset of `inode.i_ino` (a plain `u64`/`unsigned long`). Snapped from
    /// the same `6.8.0-130-generic` BTF dump (`bits_offset=640` / 8 = byte
    /// 80).
    pub i_ino: usize,
    /// Offset of `inode.i_sb` (`struct super_block *`).
    ///
    /// **An inode number alone does not identify a file.** It is unique only
    /// within one filesystem, and the deny hooks compare it against numbers
    /// precomputed from paths on OTHER filesystems. Measured 2026-08-12 on
    /// the live mirage fleet: `/dev/mem` is inode 4 on devtmpfs and
    /// `/sys/fs/cgroup/cgroup.controllers` is inode 4 on cgroup2fs, so every
    /// box denied the cgroup file as if it were `/dev/mem`. systemd reads
    /// exactly that file on re-exec, could not, and froze PID 1 on seven of
    /// nine boxes. The superblock's device is the other half of the identity.
    ///
    /// `56`, MEASURED — a live BTF resolution on kernel 6.8.0-136-generic
    /// reported `inode.i_sb=56` while the previous constant said 40, which
    /// was a guess from reading the struct layout. BTF overrides it on any
    /// box with `CONFIG_DEBUG_INFO_BTF`, so the wrong value never enforced
    /// anything; on a box without BTF it would have made the device read
    /// garbage and every deny silently stop matching. Fallbacks are a claim
    /// about a kernel — measure them or the fail-open is invisible.
    pub i_sb: usize,
}

/// KERNEL 6.8.0-130-generic — validated via live box BTF/pahole.
pub const INODE_OFFSETS: InodeOffsets = InodeOffsets { i_ino: 80, i_sb: 56 };

/// Offsets within `struct super_block` (KERNEL 6.8.0-130-generic).
pub struct SuperBlockOffsets {
    /// Offset of `super_block.s_dev` (`dev_t`, a `u32`). Sits right after
    /// the leading `struct list_head s_list` (two pointers).
    pub s_dev: usize,
}

/// KERNEL 6.8.0-130-generic — validated via live box BTF/pahole.
pub const SUPER_BLOCK_OFFSETS: SuperBlockOffsets = SuperBlockOffsets { s_dev: 16 };

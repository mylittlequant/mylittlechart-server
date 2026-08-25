//! Tier-2 BPF-LSM userspace glue (Linux-only): load/attach/pin.
//!
//! Ported from mirage-secd's `bpf_lsm/` with mirage-specific state/plumbing
//! removed: the deny-event ringbuf decode/consumer lives in the
//! platform-free `crate::sensor` module (pure decode is unit-tested on the
//! Windows dev box; only the poll loop is Linux-gated there), and the
//! writable-map handles are handed to `crate::tier2::Tier2` for
//! managed-restart windows and re-arm.

pub mod loader;

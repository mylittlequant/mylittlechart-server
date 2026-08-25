//! Deny-event sensor — decodes `warden-ebpf`'s fixed-layout `DENY_EVENTS`
//! ringbuf entries and logs each one to `tracing`.
//!
//! Ported from mirage-secd's `bpf_lsm/sensor.rs`, stripped down: no signed
//! facts, no kernel-event accumulator, no mesh delivery — mlc-warden's only
//! observability sink is its own journal (systemd `journalctl -u
//! mlc-warden`).
//!
//! # Byte layout — MUST match `warden-ebpf/src/main.rs`'s `EVENT_LEN`/layout
//! doc exactly (both sides hand-encode; no shared crate between the `no_std`
//! eBPF side and this userspace side)
//!
//! ```text
//! event_kind          1 byte
//! _pad                3 bytes
//! ts_ns               8 bytes little-endian u64 (bpf_ktime_get_ns, boot-relative)
//! protected_cgroup_id  8 bytes little-endian u64
//! offender_cgroup_id   8 bytes little-endian u64
//! offender_pid         4 bytes little-endian u32
//! ```
//!
//! `ts_ns` is boot-relative (`CLOCK_MONOTONIC`-ish, per `bpf_ktime_get_ns`'s
//! kernel semantics); the log line reports it raw — ordering and rough
//! recency are what a deny sensor's consumer cares about, not sub-second
//! wall-clock precision.
//!
//! The decode half ([`SensorEvent`]) is pure byte parsing and unit-tested on
//! every platform, including the Windows dev box; only the poll loop is
//! `#[cfg(target_os = "linux")]`.

const EVENT_LEN: usize = 1 + 3 + 8 + 8 + 8 + 4;

/// Event-kind discriminants — MUST stay numerically in sync with
/// `warden-ebpf/src/main.rs`'s `mod event_kind`.
pub mod event_kind {
    pub const PTRACE_DENIED: u8 = 0x01;
    pub const FILE_OPEN_DENIED: u8 = 0x02;
    pub const TASK_KILL_DENIED: u8 = 0x03;
    pub const BPF_LOAD_DENIED: u8 = 0x04;
    pub const MPROTECT_DENIED: u8 = 0x08;
    pub const MANAGED_RESTART_ALLOWED: u8 = 0x10;
}

/// Human-readable name for an event-kind byte (log rendering only).
#[must_use]
pub fn kind_name(kind: u8) -> &'static str {
    match kind {
        event_kind::PTRACE_DENIED => "PTRACE_DENIED",
        event_kind::FILE_OPEN_DENIED => "FILE_OPEN_DENIED",
        event_kind::TASK_KILL_DENIED => "TASK_KILL_DENIED",
        event_kind::BPF_LOAD_DENIED => "BPF_LOAD_DENIED",
        event_kind::MPROTECT_DENIED => "MPROTECT_DENIED",
        event_kind::MANAGED_RESTART_ALLOWED => "MANAGED_RESTART_ALLOWED",
        _ => "UNKNOWN",
    }
}

/// One decoded sensor event.
#[derive(Debug, Clone, Copy)]
pub struct SensorEvent {
    pub event_kind: u8,
    pub ts_ns_boot: u64,
    pub protected_cgroup_id: u64,
    pub offender_cgroup_id: u64,
    pub offender_pid: u32,
}

impl SensorEvent {
    /// Decode one fixed-layout `EVENT_LEN`-byte entry. Returns `None` for a
    /// short/malformed read (defensive — a verifier-correct eBPF program
    /// only ever writes exactly `EVENT_LEN` bytes per entry, but userspace
    /// must not panic on a torn/short read regardless).
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < EVENT_LEN {
            return None;
        }
        let event_kind = bytes[0];
        let ts_ns_boot = u64::from_le_bytes(bytes[4..12].try_into().ok()?);
        let protected_cgroup_id = u64::from_le_bytes(bytes[12..20].try_into().ok()?);
        let offender_cgroup_id = u64::from_le_bytes(bytes[20..28].try_into().ok()?);
        let offender_pid = u32::from_le_bytes(bytes[28..32].try_into().ok()?);
        Some(Self {
            event_kind,
            ts_ns_boot,
            protected_cgroup_id,
            offender_cgroup_id,
            offender_pid,
        })
    }
}

/// Run the ringbuf sensor consumer loop forever (until the ringbuf fd is
/// closed, which only happens on process exit). Never panics — decode
/// failures are logged and skipped; the loop itself never returns `Err`.
///
/// Blocking-thread version (no tokio): `poll(2)` on the ringbuf fd for
/// `POLLPRI` (the readiness bit a ring buffer map raises, per the aya
/// ringbuf consumer idiom), then drain. A `poll` error or unexpected
/// readiness flags simply re-loops after a short sleep — this sensor is
/// observability, not enforcement; the DENY already happened kernel-side
/// regardless of whether the event lands here.
#[cfg(target_os = "linux")]
pub fn run_sensor_loop(mut handles: crate::bpf_lsm::loader::BpfLsmHandles) {
    use std::os::unix::io::AsRawFd;

    let Some(mut ringbuf) = handles.take_ringbuf() else {
        tracing::warn!("[mlc-warden/sensor] DENY_EVENTS ringbuf map not found — sensor loop exiting");
        return;
    };

    let fd = ringbuf.as_raw_fd();
    // Keep `handles` alive for the lifetime of this loop — the ringbuf map
    // fd taken out of it must not outlive the `Ebpf` instance on some
    // kernel/aya versions; holding both here avoids relying on that being
    // safe.
    let _keep_handles_alive = &handles;

    loop {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLPRI | libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll on a valid, stack-owned pollfd with a 1s timeout is a
        // documented, side-effect-free syscall.
        let rc = unsafe { libc::poll(&mut pfd, 1, 1000) };
        if rc < 0 {
            tracing::debug!("[mlc-warden/sensor] poll failed — retrying");
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        }
        while let Some(item) = ringbuf.next() {
            let Some(decoded) = SensorEvent::decode(&item) else {
                tracing::debug!("[mlc-warden/sensor] short/malformed ringbuf entry — skipped");
                continue;
            };
            tracing::warn!(
                "[mlc-warden/sensor] {} ts_boot_ns={} protected_cgroup={} offender_cgroup={} offender_pid={}",
                kind_name(decoded.event_kind),
                decoded.ts_ns_boot,
                decoded.protected_cgroup_id,
                decoded.offender_cgroup_id,
                decoded.offender_pid,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bytes() -> [u8; EVENT_LEN] {
        let mut b = [0u8; EVENT_LEN];
        b[0] = 0x01; // PTRACE_DENIED
        b[4..12].copy_from_slice(&123_456_789u64.to_le_bytes());
        b[12..20].copy_from_slice(&999u64.to_le_bytes());
        b[20..28].copy_from_slice(&888u64.to_le_bytes());
        b[28..32].copy_from_slice(&4242u32.to_le_bytes());
        b
    }

    #[test]
    fn decode_roundtrips_fixed_layout() {
        let bytes = sample_bytes();
        let event = SensorEvent::decode(&bytes).expect("decode");
        assert_eq!(event.event_kind, 0x01);
        assert_eq!(event.ts_ns_boot, 123_456_789);
        assert_eq!(event.protected_cgroup_id, 999);
        assert_eq!(event.offender_cgroup_id, 888);
        assert_eq!(event.offender_pid, 4242);
    }

    #[test]
    fn decode_short_buffer_is_none() {
        assert!(SensorEvent::decode(&[0u8; 10]).is_none());
    }

    #[test]
    fn kind_name_covers_every_discriminant() {
        assert_eq!(kind_name(event_kind::PTRACE_DENIED), "PTRACE_DENIED");
        assert_eq!(kind_name(event_kind::FILE_OPEN_DENIED), "FILE_OPEN_DENIED");
        assert_eq!(kind_name(event_kind::TASK_KILL_DENIED), "TASK_KILL_DENIED");
        assert_eq!(kind_name(event_kind::BPF_LOAD_DENIED), "BPF_LOAD_DENIED");
        assert_eq!(kind_name(event_kind::MPROTECT_DENIED), "MPROTECT_DENIED");
        assert_eq!(
            kind_name(event_kind::MANAGED_RESTART_ALLOWED),
            "MANAGED_RESTART_ALLOWED"
        );
        assert_eq!(kind_name(0xff), "UNKNOWN");
    }
}

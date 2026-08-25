//! Tier2 arm/window state — the warden's own eBPF map-write holder.
//!
//! Ported from mirage-warden's `tier2.rs` (itself reincarnated from the
//! pre-Option-D `mirage_secd::policy_engine::Tier2State`), simplified for
//! mlc-warden: `std::sync::Mutex` instead of `tokio::sync::Mutex` (all call
//! sites are synchronous), single writer (this daemon) with the full
//! `0..WINDOW_SLOTS` slot range — mirage's secd/warden slot partition only
//! existed because TWO processes held writer handles to the same maps.
//!
//! Every map write here issues `bpf()` syscalls — which the lock-the-door
//! LSM hook allows ONLY from the warden's own cgroup (`OWNER_CGROUP`). The
//! daemon's cgroup is resolved at arm time and patched into that global, so
//! these writes work here and nowhere else on the box.

use std::time::Duration;

#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};

/// Total window slots — MUST stay numerically in sync with
/// `warden-ebpf`'s `WINDOW_SLOTS` (that crate is `no_std`/separately
/// compiled, so this userspace crate cannot import it directly — a
/// documented-not-derived contract).
#[cfg(target_os = "linux")]
const WINDOW_SLOTS: u32 = 8;

/// Shared, cloneable handle to the warden's Tier2 map-write state. Present
/// on every platform with an identical public API so call sites never need
/// platform-conditional code — permanently inert (`status()` always `(false,
/// 0, 0)`, every write a silent `Ok(())` no-op) on non-Linux.
#[derive(Clone)]
pub struct Tier2 {
    #[cfg(target_os = "linux")]
    inner: Arc<Mutex<Tier2Inner>>,
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct Tier2Inner {
    /// The cgroup-id half of each `(cgroup_id, expiry_ns)` targeted
    /// managed-restart window slot.
    window_cgroup: Option<aya::maps::Array<aya::maps::MapData, u64>>,
    /// The expiry-timestamp half, parallel to `window_cgroup`.
    window_expiry: Option<aya::maps::Array<aya::maps::MapData, u64>>,
    /// The flat-fill `PROTECTED_CGROUP_MAP` — rewritten in full by
    /// [`Tier2::rearm`] after any managed restart (slot index is fill order,
    /// never a per-unit identity).
    protected_cgroup: Option<aya::maps::Array<aya::maps::MapData, u64>>,
    /// The parallel per-slot kill-eligibility boolean table.
    kill_protected: Option<aya::maps::Array<aya::maps::MapData, u8>>,
    /// `true` once [`Tier2::store`] has run against a successful eBPF load —
    /// [`Tier2::status`]'s `enforcing` bit.
    enforcing: bool,
    /// Last-armed protected-cgroup count — informational, surfaced in
    /// `status` output and this daemon's own logs.
    armed_cgroups: u32,
    /// Last-armed kill-protected count — same informational role.
    kill_count: u32,
}

impl Tier2 {
    #[must_use]
    #[cfg(target_os = "linux")]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Tier2Inner::default())),
        }
    }

    #[must_use]
    #[cfg(not(target_os = "linux"))]
    pub fn new() -> Self {
        Self {}
    }

    /// Move the four writable Tier2 maps out of freshly loaded `handles`
    /// into this holder and record the initial arm counts. `protected_slots`
    /// is the SAME flat `(cgroup_id, is_kill)` list already passed to
    /// `bpf_lsm::loader::load_and_pin` (that call already SET the initial
    /// map contents post-load — this just remembers the counts and takes
    /// ownership of the writable handles for later
    /// [`Self::open_window`]/[`Self::rearm`] calls). Marks Tier2 as
    /// enforcing.
    #[cfg(target_os = "linux")]
    pub fn store(
        &self,
        handles: &mut crate::bpf_lsm::loader::BpfLsmHandles,
        protected_slots: &[(u64, bool)],
    ) {
        let mut inner = lock(&self.inner);
        inner.window_cgroup = handles.take_window_cgroup();
        inner.window_expiry = handles.take_window_expiry();
        inner.protected_cgroup = handles.take_protected_cgroup_map();
        inner.kill_protected = handles.take_kill_protected_slots();
        inner.enforcing = true;
        inner.armed_cgroups = protected_slots.len() as u32;
        inner.kill_count = protected_slots.iter().filter(|(_, kill)| *kill).count() as u32;
    }

    /// Open a TARGETED managed-restart allow-window for `cgroup_id`, so a
    /// subsequent `task_kill` against THAT SPECIFIC cgroup is ALLOWED
    /// instead of denied (`warden-ebpf::try_task_kill`), without exposing
    /// any other kill-protected daemon. Reuses the slot already holding
    /// `cgroup_id` if one exists (idempotent re-open just refreshes the
    /// expiry), else the first slot whose expiry is `0`/already expired.
    /// Returns `Err` only if EVERY slot is currently occupied by a live,
    /// DIFFERENT cgroup's window — a deliberately conservative failure
    /// (never silently steals another in-flight managed-restart's slot).
    ///
    /// No-op `Ok(())` if Tier2 isn't live or either map is unavailable —
    /// the protege isn't kernel-enforced in that case, so a plain
    /// `systemctl restart` already works without any window at all.
    #[cfg(target_os = "linux")]
    pub fn open_window(&self, cgroup_id: u64, dur: Duration) -> Result<(), String> {
        let mut guard = lock(&self.inner);
        // Reborrow once — see `rearm`'s doc for why this avoids E0499 when
        // two fields need `.as_mut()` in the same statement.
        let inner = &mut *guard;
        let (Some(cg_map), Some(exp_map)) =
            (inner.window_cgroup.as_mut(), inner.window_expiry.as_mut())
        else {
            return Ok(());
        };

        let now = current_ktime_ns();
        let expiry = now.saturating_add(dur.as_nanos() as u64);

        let mut target_slot: Option<u32> = None;
        for k in 0..WINDOW_SLOTS {
            if matches!(cg_map.get(&k, 0), Ok(id) if id == cgroup_id) {
                target_slot = Some(k);
                break;
            }
        }
        if target_slot.is_none() {
            for k in 0..WINDOW_SLOTS {
                let exp = exp_map.get(&k, 0).unwrap_or(0);
                if exp == 0 || exp <= now {
                    target_slot = Some(k);
                    break;
                }
            }
        }

        let Some(slot) = target_slot else {
            return Err(format!(
                "no free window slot (0..{WINDOW_SLOTS} all hold live windows)"
            ));
        };

        cg_map
            .set(slot, cgroup_id, 0)
            .map_err(|e| format!("WINDOW_CGROUP slot {slot} set failed: {e}"))?;
        exp_map
            .set(slot, expiry, 0)
            .map_err(|e| format!("WINDOW_EXPIRY slot {slot} set failed: {e}"))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn open_window(&self, _cgroup_id: u64, _dur: Duration) -> Result<(), String> {
        Ok(())
    }

    /// Close the targeted managed-restart allow-window for `cgroup_id`
    /// (write `0` to every slot currently holding it). Always called even on
    /// restart failure — a window must never be left open past its own
    /// caller's use. No-op `Ok(())` under the same conditions as
    /// [`Self::open_window`].
    #[cfg(target_os = "linux")]
    pub fn close_window(&self, cgroup_id: u64) -> Result<(), String> {
        let mut guard = lock(&self.inner);
        let inner = &mut *guard;
        let (Some(cg_map), Some(exp_map)) =
            (inner.window_cgroup.as_mut(), inner.window_expiry.as_mut())
        else {
            return Ok(());
        };

        for k in 0..WINDOW_SLOTS {
            if matches!(cg_map.get(&k, 0), Ok(id) if id == cgroup_id) {
                exp_map
                    .set(k, 0u64, 0)
                    .map_err(|e| format!("WINDOW_EXPIRY slot {k} clear failed: {e}"))?;
                cg_map
                    .set(k, 0u64, 0)
                    .map_err(|e| format!("WINDOW_CGROUP slot {k} clear failed: {e}"))?;
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn close_window(&self, _cgroup_id: u64) -> Result<(), String> {
        Ok(())
    }

    /// Full reconcile: rewrite BOTH `PROTECTED_CGROUP_MAP` and
    /// `KILL_PROTECTED_SLOTS` from a freshly-resolved flat `(cgroup_id,
    /// kill)` list — arms/re-arms the kernel-side protected-cgroup deny
    /// scoping for every Tier2 hook that reads it. Called once at load (the
    /// initial [`Self::store`]'s counts already reflect the load-time write
    /// `load_and_pin` itself performed) and again immediately after ANY
    /// managed restart — since slot index is fill-order, a restart cannot be
    /// re-armed as a single-slot rewrite; the WHOLE set is re-resolved and
    /// every slot `0..slots.len()` is rewritten, with
    /// `slots.len()..MAX_PROTECTED_SLOTS` explicitly zeroed (clears any
    /// now-stale entry).
    ///
    /// No-op `Ok(())` if Tier2 isn't live or EITHER map is unavailable.
    #[cfg(target_os = "linux")]
    pub fn rearm(&self, slots: &[(u64, bool)]) -> Result<(), String> {
        let mut guard = lock(&self.inner);
        // Reborrow the MutexGuard to `&mut Tier2Inner` ONCE — otherwise
        // `inner.protected_cgroup.as_mut()` + `inner.kill_protected.as_mut()`
        // each go through the guard's `DerefMut` (borrowing the whole
        // guard), so taking both in one tuple is two mutable borrows of the
        // guard (E0499). Through a single `&mut Tier2Inner` the two
        // `.as_mut()` borrows are disjoint fields, which NLL allows.
        let inner = &mut *guard;
        let (Some(cgroup_map), Some(kill_map)) =
            (inner.protected_cgroup.as_mut(), inner.kill_protected.as_mut())
        else {
            return Ok(());
        };

        for (i, (id, _kill)) in slots.iter().enumerate() {
            if i >= crate::MAX_PROTECTED_SLOTS {
                break;
            }
            cgroup_map
                .set(i as u32, *id, 0)
                .map_err(|e| format!("PROTECTED_CGROUP_MAP slot {i} set failed: {e}"))?;
        }
        for i in slots.len()..crate::MAX_PROTECTED_SLOTS {
            cgroup_map
                .set(i as u32, 0u64, 0)
                .map_err(|e| format!("PROTECTED_CGROUP_MAP slot {i} zero failed: {e}"))?;
        }

        for (i, (_id, kill)) in slots.iter().enumerate() {
            if i >= crate::MAX_PROTECTED_SLOTS {
                break;
            }
            kill_map
                .set(i as u32, u8::from(*kill), 0)
                .map_err(|e| format!("KILL_PROTECTED_SLOTS slot {i} set failed: {e}"))?;
        }
        for i in slots.len()..crate::MAX_PROTECTED_SLOTS {
            kill_map
                .set(i as u32, 0u8, 0)
                .map_err(|e| format!("KILL_PROTECTED_SLOTS slot {i} zero failed: {e}"))?;
        }

        inner.armed_cgroups = slots.len() as u32;
        inner.kill_count = slots.iter().filter(|(_, kill)| *kill).count() as u32;

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn rearm(&self, _slots: &[(u64, bool)]) -> Result<(), String> {
        Ok(())
    }

    /// Snapshot `(enforcing, armed_cgroups, kill_count)`. Always `(false, 0,
    /// 0)` on non-Linux or before the first successful [`Self::store`].
    #[cfg(target_os = "linux")]
    pub fn status(&self) -> (bool, u32, u32) {
        let inner = lock(&self.inner);
        (inner.enforcing, inner.armed_cgroups, inner.kill_count)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn status(&self) -> (bool, u32, u32) {
        (false, 0, 0)
    }
}

impl Default for Tier2 {
    fn default() -> Self {
        Self::new()
    }
}

/// Lock helper: a poisoned mutex here means a previous holder panicked
/// mid-map-write; the maps themselves are kernel-side and the panic already
/// unwound, so recovering the inner state is safe (and failing the whole
/// daemon over a poisoned lock would take enforcement down with it — the
/// wrong direction).
#[cfg(target_os = "linux")]
fn lock(
    m: &Mutex<Tier2Inner>,
) -> std::sync::MutexGuard<'_, Tier2Inner> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Approximate `bpf_ktime_get_ns()` (boot-relative, `CLOCK_MONOTONIC`-ish —
/// same clock family the kernel-side ringbuf timestamp uses) via
/// `clock_gettime(CLOCK_MONOTONIC)`. Exact bit-for-bit equivalence with the
/// kernel's own clock is not required — the window is seconds-wide, so any
/// sub-millisecond clock-family drift is immaterial. Falls back to `0` on a
/// (practically unreachable) syscall failure, which still yields a valid,
/// bounded-into-the-future expiry, never negative/wrapped.
#[cfg(target_os = "linux")]
fn current_ktime_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime(CLOCK_MONOTONIC, ..) with a valid, stack-owned
    // timespec out-pointer is a documented, side-effect-free syscall.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_defaults_to_not_enforcing() {
        let tier2 = Tier2::new();
        assert_eq!(tier2.status(), (false, 0, 0));
    }

    #[test]
    fn open_close_window_never_panics_before_a_load() {
        let tier2 = Tier2::new();
        assert!(tier2.open_window(42, Duration::from_secs(1)).is_ok());
        assert!(tier2.close_window(42).is_ok());
    }

    #[test]
    fn rearm_never_panics_before_a_load() {
        let tier2 = Tier2::new();
        assert!(tier2.rearm(&[(1, true), (2, false)]).is_ok());
    }
}

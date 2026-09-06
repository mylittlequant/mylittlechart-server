//! [`DaemonStats`] — process-lifetime evaluation counters — plus their JSON
//! snapshot shape ([`HealthBody`]), shared by both the standalone binary's
//! own `GET /health` (`main.rs`) and, when this crate runs embedded inside
//! `mylittlechart-server`, that server's own `/health` endpoint (see this
//! crate's module doc for the two run modes).
//!
//! Counters are cumulative since process start, not per-cycle — a
//! dashboard polling either endpoint diffs successive reads itself.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use serde::Serialize;

/// Process-lifetime evaluation counters, one atomic per outcome, plus the
/// timestamp of the most recently completed evaluation cycle.
#[derive(Default)]
pub struct DaemonStats {
    /// A price-cross check was attempted for one alert (successful price
    /// fetch, prior to the crossing test itself).
    pub checked: AtomicU64,
    /// A crossing check fired (regardless of whether delivery succeeded).
    pub fired: AtomicU64,
    /// A fired alert was successfully delivered via Telegram.
    pub delivered: AtomicU64,
    /// One account skipped for the whole cycle because it is not paid —
    /// counted once per account per cycle, not once per alert.
    pub skipped_unpaid: AtomicU64,
    /// One account skipped for the whole cycle because it has no linked
    /// Telegram identity — counted once per account per cycle.
    pub skipped_unlinked: AtomicU64,
    /// Unix millis at which the most recently completed evaluation cycle
    /// finished, or `0` before the first cycle completes (see
    /// [`DaemonStats::snapshot`], which turns that sentinel into `None`).
    pub last_cycle_at: AtomicI64,
}

impl DaemonStats {
    pub fn snapshot(&self) -> HealthBody {
        let last_cycle_at = self.last_cycle_at.load(Ordering::Relaxed);
        HealthBody {
            status: "ok",
            checked: self.checked.load(Ordering::Relaxed),
            fired: self.fired.load(Ordering::Relaxed),
            delivered: self.delivered.load(Ordering::Relaxed),
            skipped_unpaid: self.skipped_unpaid.load(Ordering::Relaxed),
            skipped_unlinked: self.skipped_unlinked.load(Ordering::Relaxed),
            last_cycle_at: if last_cycle_at == 0 { None } else { Some(last_cycle_at) },
        }
    }
}

#[derive(Serialize)]
pub struct HealthBody {
    pub status: &'static str,
    pub checked: u64,
    pub fired: u64,
    pub delivered: u64,
    pub skipped_unpaid: u64,
    pub skipped_unlinked: u64,
    pub last_cycle_at: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_reports_no_cycle_yet_as_none() {
        let stats = DaemonStats::default();
        assert_eq!(stats.snapshot().last_cycle_at, None);
    }

    #[test]
    fn snapshot_reports_a_recorded_cycle_timestamp() {
        let stats = DaemonStats::default();
        stats.last_cycle_at.store(1_735_689_600_000, Ordering::Relaxed);
        stats.checked.store(3, Ordering::Relaxed);
        let body = stats.snapshot();
        assert_eq!(body.last_cycle_at, Some(1_735_689_600_000));
        assert_eq!(body.checked, 3);
    }
}

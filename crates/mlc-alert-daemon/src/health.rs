//! `GET /health` — health + delivery counters (plan §3, item 3): "everyone
//! else is skipped silently with a counter in the daemon's `/health` JSON
//! (`checked, fired, delivered, skipped_unpaid, skipped_unlinked`)".
//!
//! Counters are cumulative since process start, not per-cycle — a
//! dashboard polling this endpoint diffs successive reads itself.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::Serialize;

/// Process-lifetime evaluation counters, one atomic per outcome.
#[derive(Default)]
pub struct Counters {
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
}

impl Counters {
    pub fn snapshot(&self) -> HealthBody {
        HealthBody {
            status: "ok",
            checked: self.checked.load(Ordering::Relaxed),
            fired: self.fired.load(Ordering::Relaxed),
            delivered: self.delivered.load(Ordering::Relaxed),
            skipped_unpaid: self.skipped_unpaid.load(Ordering::Relaxed),
            skipped_unlinked: self.skipped_unlinked.load(Ordering::Relaxed),
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
}

pub async fn health_handler(State(counters): State<Arc<Counters>>) -> Json<HealthBody> {
    Json(counters.snapshot())
}

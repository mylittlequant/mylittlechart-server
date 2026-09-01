//! `OpsWriter` — the single writer thread for the operational database.
//!
//! Before this module, `routes::telemetry::submit_telemetry` took the
//! `ControlPlane::ops_db` mutex inside `spawn_blocking` and awaited the
//! write before answering. Every posting device therefore queued behind
//! every other posting device, and behind every dashboard read that shares
//! that same mutex — a `Mutex<Connection>` makes no distinction between "a
//! reader wants a snapshot" and "a writer needs to commit", so the busiest
//! path in the whole server (client telemetry, one post per device per
//! hour, times however many devices exist) sat behind the same lock as
//! everything else.
//!
//! The owner's condition for telemetry staying in SQL at all: there must be
//! no pattern where the writer blocks. One writer, with a cache in front of
//! it collecting the write queue. This module is that writer: it owns the
//! *only* connection anyone ever writes through, and it runs on a dedicated
//! OS thread rather than a tokio task — the work is synchronous SQLite, and
//! parking a runtime worker on it is the same mistake in a different
//! costume. Callers hand it a message and move on; `try_send` on a bounded
//! channel means a caller can never be made to wait on write throughput it
//! has no control over.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};

/// Bounded channel capacity for the writer queue.
///
/// Clients post telemetry roughly once an hour (see `routes/telemetry.rs`'s
/// module doc). 1024 buffered writes is on the order of a minute of every
/// currently-registered device posting at once during a very bad day (a
/// mass reconnect storm, a botched rollout that makes every client retry) —
/// comfortably more than steady-state ever needs, small enough that a queue
/// stuck this deep is itself a signal something is wrong, at which point
/// dropping newer writes (see `OpsWriter::enqueue`) is the correct response,
/// not growing the buffer further.
pub const OPS_WRITER_QUEUE_CAPACITY: usize = 1024;

/// How many messages the writer thread drains into a single transaction
/// before committing, on top of the one that woke it from `recv()`.
const DRAIN_BATCH_LIMIT: usize = 256;

/// Minimum spacing, in milliseconds, between "queue full" log lines. A flood
/// of drops must not become a flood of log lines — the total-dropped count
/// still grows every time, it just isn't printed every time.
const DROP_LOG_INTERVAL_MS: u64 = 60_000;

/// The six near-immutable profile facts plus the time-series fields a
/// telemetry post carries, fully resolved and ready to apply — everything
/// `routes::telemetry::submit_telemetry` used to pass directly to
/// `db::upsert_device_profile` and `db::insert_device_metrics`, plus the
/// identity (`user_id`) and cap (`daily_cap`) inputs the writer thread now
/// needs to make "count today, then insert" atomic against its own
/// connection instead of racing another connection between the two steps.
pub struct TelemetrySample {
    pub device_id: String,
    pub user_id: Option<i64>,
    pub now: String,
    pub daily_cap: i64,
    pub profile: crate::db::DeviceProfileFields,
    pub connector_count: i64,
    pub window_count: i64,
    pub avg_fps: f64,
    pub uptime_secs: i64,
    pub total_bars: i64,
    pub ws_connections: i64,
}

/// Everything the writer thread can be asked to do. One variant today
/// (telemetry, the only write that used to block behind the shared mutex);
/// shaped as an enum so a second fire-and-forget writer can move behind the
/// same thread and channel later without a new thread.
pub enum OpsWrite {
    Telemetry(TelemetrySample),
}

/// Handle to the dedicated writer thread. This is the only way any other
/// code reaches the operational database's write path — everywhere that
/// used to lock `ControlPlane::ops_db` to write now calls `enqueue` here
/// instead. Read-only access to `ops_db` (dashboards, heartbeat, release
/// registration) is unaffected and keeps using the mutex directly; with WAL
/// enabled, a reader on that mutex never blocks this thread's writes.
pub struct OpsWriter {
    tx: SyncSender<OpsWrite>,
    dropped: AtomicU64,
    last_drop_log_ms: AtomicU64,
}

impl OpsWriter {
    /// Start the writer thread against `conn` (a connection the caller has
    /// already opened against the operational database file — see
    /// `main.rs`, which opens a second connection dedicated to this thread
    /// so it never shares a `rusqlite::Connection` value with `ops_db`) and
    /// return the handle other code enqueues writes through.
    pub fn spawn(conn: rusqlite::Connection, capacity: usize) -> OpsWriter {
        let (tx, rx) = mpsc::sync_channel::<OpsWrite>(capacity);

        // Thread creation only fails under OS-level resource exhaustion
        // (out of memory, out of thread/handle quota) — at that point the
        // process cannot serve requests either way, so this follows the
        // same fail-fast-at-boot discipline `main.rs` uses for the database
        // opens right next to this call (`std::process::exit(1)` on error).
        std::thread::Builder::new()
            .name("ops-writer".to_string())
            .spawn(move || run(conn, rx))
            .expect(
                "failed to spawn the ops-writer OS thread — this only happens under OS \
                 resource exhaustion, at which point the process cannot usefully continue \
                 booting either",
            );

        OpsWriter {
            tx,
            dropped: AtomicU64::new(0),
            last_drop_log_ms: AtomicU64::new(0),
        }
    }

    /// Hand a write to the writer thread. Never blocks the caller: a full
    /// queue means the write is dropped, not queued further and not waited
    /// on — see this module's doc comment for why that is the whole point.
    pub fn enqueue(&self, write: OpsWrite) {
        match self.tx.try_send(write) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => self.record_drop(),
            Err(TrySendError::Disconnected(_)) => {
                // The writer thread panicked or was never running — a real
                // fault, not backpressure, so it always logs (no rate
                // limit) rather than being folded into the drop counter.
                tracing::error!(
                    "ops-writer thread is gone (channel disconnected) — write dropped"
                );
            }
        }
    }

    /// Record one dropped write and, at most once per `DROP_LOG_INTERVAL_MS`,
    /// log the running total. A dropped event must name itself, but a flood
    /// of drops must not become a flood of log lines — the counter always
    /// advances; the log line is rate-limited.
    fn record_drop(&self) {
        let total = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;

        let now_ms = current_millis();
        let last = self.last_drop_log_ms.load(Ordering::Relaxed);
        let due = now_ms.saturating_sub(last) >= DROP_LOG_INTERVAL_MS;
        if due
            && self
                .last_drop_log_ms
                .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            tracing::warn!(
                "ops-writer queue full — dropping write (total dropped so far: {})",
                total
            );
        }
    }
}

/// Current wall-clock time in milliseconds since the Unix epoch, used only
/// to rate-limit the "queue full" log line above. A clock read that somehow
/// fails (pre-1970 system clock) falls back to 0, which just means the very
/// next drop logs immediately instead of waiting out the interval —
/// harmless for a rate limiter.
fn current_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The writer thread body. Blocks on `recv()` for the first message of a
/// batch, then drains up to `DRAIN_BATCH_LIMIT` more with non-blocking
/// `try_recv()` (stopping early once the queue is empty), then applies the
/// whole batch inside one transaction. `recv()` returning `Err` means every
/// `SyncSender` — the one `OpsWriter` holds, and anything cloned from it —
/// has been dropped, which only happens at process shutdown; the thread
/// exits rather than looping on a channel nothing will ever write to again.
fn run(mut conn: rusqlite::Connection, rx: Receiver<OpsWrite>) {
    loop {
        let first = match rx.recv() {
            Ok(msg) => msg,
            Err(_) => {
                tracing::info!("ops-writer: all senders dropped, thread exiting");
                return;
            }
        };

        let mut batch = Vec::with_capacity(DRAIN_BATCH_LIMIT);
        batch.push(first);
        while batch.len() < DRAIN_BATCH_LIMIT {
            match rx.try_recv() {
                Ok(msg) => batch.push(msg),
                Err(_) => break,
            }
        }

        let batch_len = batch.len();
        if let Err(e) = apply_batch(&mut conn, &batch) {
            // Telemetry is not worth retrying and must never wedge the
            // queue behind a batch that keeps failing — log and move on to
            // the next `recv()`.
            tracing::error!(
                "ops-writer: batch of {} write(s) failed and was dropped: {}",
                batch_len, e
            );
        }
    }
}

/// Apply one drained batch inside a single transaction so a batch either
/// lands completely or not at all.
fn apply_batch(conn: &mut rusqlite::Connection, batch: &[OpsWrite]) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    for write in batch {
        match write {
            OpsWrite::Telemetry(sample) => apply_telemetry(&tx, sample)?,
        }
    }
    tx.commit()
}

/// Apply one telemetry sample: upsert the near-immutable profile half, then
/// enforce the per-device daily cap and insert the metrics row — the same
/// two calls `routes::telemetry::submit_telemetry` used to make directly,
/// now running on the one connection that ever writes here, with nothing
/// racing between the cap count and the insert.
fn apply_telemetry(conn: &rusqlite::Connection, sample: &TelemetrySample) -> rusqlite::Result<()> {
    crate::db::upsert_device_profile(conn, &sample.device_id, &sample.profile, &sample.now)?;

    // RFC 3339 "YYYY-MM-DD" date prefix, UTC — see
    // `db::count_device_metrics_today`'s doc comment.
    let today = &sample.now[..10];
    let count_today = crate::db::count_device_metrics_today(conn, &sample.device_id, today)?;
    if count_today >= sample.daily_cap {
        return Ok(());
    }

    crate::db::insert_device_metrics(
        conn,
        &sample.device_id,
        sample.user_id,
        &sample.now,
        sample.connector_count,
        sample.window_count,
        sample.avg_fps,
        sample.uptime_secs,
        sample.total_bars,
        sample.ws_connections,
    )
}

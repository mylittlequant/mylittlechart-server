//! Shared fixtures for the billing unit tests (compiled only under `cfg(test)`).

use chrono::Utc;
use rusqlite::Connection;

/// The full identity schema through the real `db::init_db` — a plain
/// in-memory database with a dummy SQLCipher key, the same fixture
/// `account_merge`'s tests use, so billing tests run against the production
/// table shapes (including `users` with the entitlement columns).
pub fn conn() -> Connection {
    crate::db::init_db(":memory:", &"0".repeat(64)).expect("init identity test db")
}

/// Create an account and return its id.
pub fn seed_user(conn: &Connection, name: &str) -> i64 {
    crate::db::upsert_user(conn, "github", name, name, None, &Utc::now().to_rfc3339()).expect("seed user")
}

// ---------------------------------------------------------------------------
// Log capture
// ---------------------------------------------------------------------------

static CAPTURED: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());
static INSTALL: std::sync::Once = std::sync::Once::new();

struct Sink;

impl std::io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        CAPTURED.lock().unwrap_or_else(|e| e.into_inner()).extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Install (once per test process) a global `tracing` subscriber that keeps
/// every event at any level, from any thread, in memory. Nothing else in the
/// test binary installs a global subscriber, so a test can run a flow and then
/// ask [`captured_logs`] whether a secret leaked into a log line.
pub fn capture_logs() {
    INSTALL.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_writer(|| Sink)
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}

/// Everything logged since [`capture_logs`] was first called.
pub fn captured_logs() -> String {
    String::from_utf8_lossy(&CAPTURED.lock().unwrap_or_else(|e| e.into_inner())).into_owned()
}

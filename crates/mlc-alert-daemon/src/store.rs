//! Daemon-owned bookkeeping: `alert_daemon.db`, sitting next to
//! `mylittlechart.db`/`social.db`/`operational.db` in the same
//! `MLC_DATA_DIR`, but a SEPARATE file with exactly one writer — this
//! process. It never shares the identity SQLCipher database (that one is
//! read-only from here, see `identity_db.rs`).
//!
//! Holds only `last_fired_at` per `(user_id, alert_id)` — no secrets, so a
//! plain (non-SQLCipher) SQLite database suffices, same precedent as
//! `mlc-opsd`'s `opsd.sqlite` (`crates/opsd/Cargo.toml`'s comment: "holds no
//! secrets (audit/kv only), so plain bundled SQLite suffices").

use rusqlite::{params, Connection, OptionalExtension, Result};

/// Open (creating if absent) the daemon's own bookkeeping database and
/// ensure its schema exists.
pub fn open_store(path: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS fired_alerts (
            user_id       INTEGER NOT NULL,
            alert_id      INTEGER NOT NULL,
            last_fired_at INTEGER NOT NULL,
            PRIMARY KEY (user_id, alert_id)
        );",
    )?;
    Ok(conn)
}

/// The last time `(user_id, alert_id)` fired, as Unix millis, if ever.
pub fn last_fired_at(conn: &Connection, user_id: i64, alert_id: u64) -> Result<Option<i64>> {
    conn.query_row(
        "SELECT last_fired_at FROM fired_alerts WHERE user_id = ?1 AND alert_id = ?2",
        params![user_id, alert_id as i64],
        |row| row.get(0),
    )
    .optional()
}

/// Record that `(user_id, alert_id)` just fired, at `now_ms`.
pub fn mark_fired(conn: &Connection, user_id: i64, alert_id: u64, now_ms: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO fired_alerts (user_id, alert_id, last_fired_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(user_id, alert_id) DO UPDATE SET last_fired_at = excluded.last_fired_at",
        params![user_id, alert_id as i64, now_ms],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_then_read_round_trips() {
        let conn = Connection::open_in_memory().expect("in-memory sqlite must open");
        conn.execute_batch(
            "CREATE TABLE fired_alerts (
                user_id INTEGER NOT NULL, alert_id INTEGER NOT NULL,
                last_fired_at INTEGER NOT NULL, PRIMARY KEY (user_id, alert_id));",
        )
        .expect("schema must create");

        assert_eq!(last_fired_at(&conn, 1, 42).expect("query must succeed"), None);

        mark_fired(&conn, 1, 42, 1_000).expect("first mark must succeed");
        assert_eq!(last_fired_at(&conn, 1, 42).expect("query must succeed"), Some(1_000));

        mark_fired(&conn, 1, 42, 2_000).expect("re-mark must succeed");
        assert_eq!(last_fired_at(&conn, 1, 42).expect("query must succeed"), Some(2_000));

        // A different alert on the same user is a distinct row.
        assert_eq!(last_fired_at(&conn, 1, 43).expect("query must succeed"), None);
    }
}

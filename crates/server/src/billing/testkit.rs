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

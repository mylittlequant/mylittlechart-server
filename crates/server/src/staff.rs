//! The staff audit trail behind the in-app admin tab (`routes/staff.rs`).
//!
//! Every staff action — a minted batch of gift codes, a revoked batch, a paid
//! days grant, a lifetime grant or its revocation, an account lookup — leaves
//! one `staff_audit` row: who (the account id, and the nick they had then),
//! what, against what, with which parameters, and when. The row is written in
//! the SAME transaction as the action, so there is never an action without its
//! row or a row for an action that did not happen.
//!
//! What a row must never hold is a gift-code VALUE: `params` carry counts,
//! days, notes and ids only. The codes exist in exactly one place — the
//! response that hands them to the operator who minted them.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, Result};
use serde_json::Value;

/// Writes one staff account may make per minute.
pub const WRITES_PER_MINUTE: usize = 30;

/// Create the audit table (additive, idempotent).
pub fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS staff_audit (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ts            TEXT    NOT NULL,
            actor_user_id INTEGER NOT NULL,
            actor_nick    TEXT,
            action        TEXT    NOT NULL,
            target        TEXT    NOT NULL,
            params_json   TEXT    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_staff_audit_actor ON staff_audit(actor_user_id, id);",
    )
}

/// Append one audit row.
pub fn record(
    conn: &Connection,
    actor_user_id: i64,
    actor_nick: Option<&str>,
    action: &str,
    target: &str,
    params_value: &Value,
    now: DateTime<Utc>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO staff_audit (ts, actor_user_id, actor_nick, action, target, params_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![now.to_rfc3339(), actor_user_id, actor_nick, action, target, params_value.to_string()],
    )?;
    Ok(())
}

/// One audit row as read back (tests only — production never reads the trail
/// through the application; it is for a human with database access).
#[cfg(test)]
#[derive(Debug, Clone, PartialEq)]
pub struct AuditRow {
    /// Actor account id.
    pub actor_user_id: i64,
    /// Actor nick at the time.
    pub actor_nick: Option<String>,
    /// e.g. `gift_codes.mint`.
    pub action: String,
    /// e.g. `batch:gb_…` or `user:42`.
    pub target: String,
    /// The recorded parameters.
    pub params: Value,
}

/// Every audit row, oldest first (tests only).
#[cfg(test)]
pub fn all(conn: &Connection) -> Result<Vec<AuditRow>> {
    let mut stmt = conn.prepare(
        "SELECT actor_user_id, actor_nick, action, target, params_json FROM staff_audit ORDER BY id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        let raw: String = row.get(4)?;
        Ok(AuditRow {
            actor_user_id: row.get(0)?,
            actor_nick: row.get(1)?,
            action: row.get(2)?,
            target: row.get(3)?,
            params: serde_json::from_str(&raw).unwrap_or(Value::Null),
        })
    })?;
    rows.collect()
}

//! Read-only access to the identity database's `sync_items`/`users`/
//! `user_providers` tables — the ONLY use this daemon has for
//! `mylittlechart.db`, which `mylittlechart-server`'s `db.rs` owns as its
//! single writer. This module never executes an INSERT/UPDATE/DELETE; the
//! connection itself is opened `SQLITE_OPEN_READ_ONLY`
//! ([`open_identity_db_readonly`]) so a coding mistake here cannot become a
//! write.
//!
//! # Why a second process reads the SAME SQLCipher-encrypted file, keyed
//! # differently from the server
//!
//! `mylittlechart-server`'s `db::read_sqlcipher_key` deletes the tmpfs key
//! file after its one read at boot (that function's own doc comment: "the
//! tmpfs file is deleted after this call, so it can only ever be read once
//! per boot") — a second process racing to read the same file gets
//! nothing, by design. This daemon therefore takes its OWN copy of the
//! same key material via the `MLC_DB_KEY_HEX` environment variable instead
//! (see `config.rs`), which whatever starts this process must set from the
//! same secret the server's tmpfs delivery uses.
//!
//! This is strictly MORE exposure than the tmpfs handoff: an env var stays
//! readable from this process's own environment (e.g. `/proc/<pid>/environ`
//! on Linux) for as long as it runs, where the tmpfs file existed for one
//! read only. Documented here rather than hidden, per the task's explicit
//! call-out — a future iteration could instead have the server push the
//! key to this daemon over a private channel at boot, but that is not what
//! this step builds.

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Result};

use crate::alert_item::{self, AlertItemWire};

/// The sync category this daemon reads. Must match the client piece's
/// `category` string on `POST /api/sync/push` — see `alert_item.rs`'s
/// module doc for the full wire contract.
pub const ALERT_SYNC_CATEGORY: &str = "alerts";

/// Open `mylittlechart.db` read-only. `key_hex` is the same SQLCipher key
/// the server booted with — see this module's doc for why it arrives via
/// env var here instead of the tmpfs handoff `db::read_sqlcipher_key` uses.
pub fn open_identity_db_readonly(path: &str, key_hex: &str) -> Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags)?;
    // SQLCipher: the key must be the very first statement on the connection
    // (mirrors `db::init_db`'s own comment).
    conn.execute_batch(&format!("PRAGMA key = \"x'{key_hex}'\";"))?;
    // Confirms the key actually opens the schema, without ever writing —
    // an open read-only connection with the wrong key fails lazily on the
    // first real query otherwise, which would surface a confusing error
    // deep inside the evaluation loop instead of at boot.
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get::<_, i64>(0))?;
    Ok(conn)
}

/// Every `user_id` that currently has at least one non-deleted `alerts`
/// sync item, across every device/profile scope that account has pushed
/// from.
pub fn candidate_user_ids(conn: &Connection) -> Result<Vec<i64>> {
    let mut stmt = conn.prepare("SELECT DISTINCT user_id FROM sync_items WHERE category = ?1 AND deleted = 0")?;
    let rows = stmt.query_map(params![ALERT_SYNC_CATEGORY], |row| row.get(0))?;
    rows.collect()
}

/// Every parsed `alerts` item for one user, across every device/profile
/// scope that account has pushed from. Rows whose content fails to parse
/// as [`AlertItemWire`] are logged and skipped, never propagated as an
/// error — one malformed row must not stop evaluation for the rest of the
/// account's alerts.
pub fn user_alert_items(conn: &Connection, user_id: i64) -> Result<Vec<AlertItemWire>> {
    let mut stmt =
        conn.prepare("SELECT sync_id, content FROM sync_items WHERE user_id = ?1 AND category = ?2 AND deleted = 0")?;
    let rows = stmt.query_map(params![user_id, ALERT_SYNC_CATEGORY], |row| {
        let sync_id: String = row.get(0)?;
        let content: Vec<u8> = row.get(1)?;
        Ok((sync_id, content))
    })?;

    let mut items = Vec::new();
    for row in rows {
        let (sync_id, content) = row?;
        match alert_item::parse_alert_item(&content) {
            Ok(item) => items.push(item),
            Err(e) => {
                tracing::warn!("user {user_id}: sync_items row {sync_id:?} is not a valid alerts item: {e}")
            }
        }
    }
    Ok(items)
}

/// Whether `user_id`'s paid access is currently in effect — same rule as
/// `mylittlechart-server`'s `db::user_is_paid` (`paid_until` compared to
/// now), reimplemented here rather than shared: that crate ships no
/// library surface to depend on (`crates/server/src/lib.rs` is empty; the
/// server is a bin-only crate).
pub fn user_is_paid(conn: &Connection, user_id: i64) -> Result<bool> {
    let paid_until: Option<String> = conn
        .query_row("SELECT paid_until FROM users WHERE id = ?1", params![user_id], |row| row.get(0))
        .optional()?
        .flatten();
    Ok(match paid_until {
        Some(until) => until.as_str() > chrono::Utc::now().to_rfc3339().as_str(),
        None => false,
    })
}

/// The Telegram DM `chat_id` for `user_id` — its linked `user_providers`
/// row for `provider = 'telegram'`, the same identity
/// `routes/tg_login.rs::link_provider_to_user` writes. `None` means the
/// account has no Telegram link at all (linking itself is not paid-gated —
/// only delivery is, see `gate.rs`).
pub fn tg_chat_id_for_user(conn: &Connection, user_id: i64) -> Result<Option<i64>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT provider_user_id FROM user_providers WHERE user_id = ?1 AND provider = 'telegram' LIMIT 1",
            params![user_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(match raw {
        Some(s) => match s.parse::<i64>() {
            Ok(id) => Some(id),
            Err(_) => {
                tracing::warn!("user {user_id}: telegram provider_user_id {s:?} is not a valid chat id");
                None
            }
        },
        None => None,
    })
}

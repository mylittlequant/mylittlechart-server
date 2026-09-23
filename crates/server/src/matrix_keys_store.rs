//! Devices, E2E key material, to-device inbox, device-list change log,
//! cross-signing, and key backup — the devices/keys/backup half of
//! `messenger.db` (the rooms/events/state half is `matrix_store.rs`, a
//! separate work item). See
//! `docs/mlc/plans/messenger-proto-server-matrix-subset-2026-09-24.md` §2
//! second SQL block for the DDL this module implements, §1.1 for the
//! device-per-credential model, and §3.7 for the `/sync` delta shapes this
//! module's read functions serve.
//!
//! Crypto stays entirely client-side here too: `device_keys.keys`,
//! `one_time_keys.key_json`, `fallback_keys.key_json`,
//! `cross_signing_keys.key_json`, `cross_signing_signatures.signature_json`,
//! `key_backup_versions.auth_data`, and `key_backup_sessions.session_data`
//! are all opaque JSON this module never inspects or verifies — pure
//! storage/relay, identical in spirit to `matrix_store.rs`'s own treatment
//! of event `content`.
//!
//! # Single-writer discipline
//!
//! Same rule as `matrix_store.rs`: every function here takes an
//! already-open [`Connection`]; the caller holds it behind one
//! `std::sync::Mutex`. Every stream-ordered table in this module
//! (`to_device_messages`, `device_list_changes`) shares `matrix_store`'s
//! one global `stream_counter` — this module never mints its own counter,
//! it calls [`matrix_store::next_stream_id`] inside the same transaction as
//! the row it stamps, exactly like `matrix_store.rs` does for its own
//! tables.
//!
//! # Deviation from the plan's literal DDL text
//!
//! `fallback_keys` gains a `key_id TEXT NOT NULL` column not present in the
//! plan's printed DDL — see [`create_matrix_keys_schema`]'s doc comment for
//! why: the plan's own CRUD contract for [`claim_one_time_key`] requires a
//! real `key_id` for a fallback-key claim, exactly like it already returns
//! one for a real one-time-key claim, and there was no column to source
//! that from.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use std::collections::HashMap;

use crate::matrix_store;

// ============================================================================
// Errors
// ============================================================================

/// Why a write into this store was refused, on top of a real database
/// failure — same shape as `matrix_store::MatrixStoreError`.
#[derive(Debug)]
pub enum MatrixKeysStoreError {
    Db(rusqlite::Error),
    /// [`add_one_time_keys`] found an existing `key_id` whose stored
    /// `key_json` differs from the newly submitted one — the Matrix spec's
    /// rule is that a resubmission with identical content is a silent
    /// no-op, but different content for the same `key_id` is refused. The
    /// `String` is the conflicting `key_id`.
    OneTimeKeyConflict(String),
    /// [`put_backup_sessions`] was called with a `version` that is not the
    /// caller's current non-deleted key-backup version.
    WrongBackupVersion,
}

impl From<rusqlite::Error> for MatrixKeysStoreError {
    fn from(e: rusqlite::Error) -> Self {
        MatrixKeysStoreError::Db(e)
    }
}

/// Decode a TEXT column this module itself always writes from one of the
/// enums below — see `matrix_store::decode_enum`'s doc comment for why a
/// decode failure is a data-integrity bug (`InvalidColumnType`), not a
/// normal "not found" case.
fn decode_enum<T>(idx: usize, column: &'static str, raw: &str, parse: fn(&str) -> Option<T>) -> rusqlite::Result<T> {
    parse(raw).ok_or_else(|| rusqlite::Error::InvalidColumnType(idx, column.to_string(), rusqlite::types::Type::Text))
}

// ============================================================================
// Small TEXT-backed enums
// ============================================================================

/// Which of the two existing auth mechanisms (plan §1.1) minted a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    Bearer,
    Web,
}

impl CredentialKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialKind::Bearer => "bearer",
            CredentialKind::Web => "web",
        }
    }

    pub fn from_wire_name(s: &str) -> Option<Self> {
        match s {
            "bearer" => Some(CredentialKind::Bearer),
            "web" => Some(CredentialKind::Web),
            _ => None,
        }
    }
}

/// A cross-signing key's usage, per the Matrix cross-signing model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossSigningUsage {
    Master,
    SelfSigning,
    UserSigning,
}

impl CrossSigningUsage {
    pub fn as_str(self) -> &'static str {
        match self {
            CrossSigningUsage::Master => "master",
            CrossSigningUsage::SelfSigning => "self_signing",
            CrossSigningUsage::UserSigning => "user_signing",
        }
    }

    pub fn from_wire_name(s: &str) -> Option<Self> {
        match s {
            "master" => Some(CrossSigningUsage::Master),
            "self_signing" => Some(CrossSigningUsage::SelfSigning),
            "user_signing" => Some(CrossSigningUsage::UserSigning),
            _ => None,
        }
    }
}

/// Mint 8 random bytes, URL-safe base64, no padding (~11 chars) — a fresh
/// device id (plan §1.1).
fn random_device_id() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use rand::Rng;
    let bytes: [u8; 8] = rand::thread_rng().gen();
    URL_SAFE_NO_PAD.encode(bytes)
}

// ============================================================================
// Schema
// ============================================================================

/// Create every table/index this module needs — idempotent, called from
/// `matrix_store::init_messenger_db` right after `create_matrix_schema`,
/// and directly by this module's own tests.
///
/// Deviation from the plan's literal DDL text (§2 second block, noted
/// inline as `-- DEVIATION`): `fallback_keys` gains a `key_id TEXT NOT
/// NULL` column. The plan's own P2 CRUD contract
/// (`claim_one_time_key(...) -> Option<(key_id, key_json)>`) must return a
/// real `key_id` for a fallback-key claim exactly the way it already does
/// for a real one-time-key claim (`one_time_keys.key_id` exists for that
/// reason) — without this column the fallback branch would have no
/// `key_id` to hand back to the claiming client. Only one fallback key is
/// ever live per `(user_id, device_id, algorithm)` (that triple stays the
/// primary key), so this is one extra scalar column, not a new dimension
/// of the table.
pub fn create_matrix_keys_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS devices (
            user_id          INTEGER NOT NULL,
            device_id        TEXT NOT NULL,
            credential_kind  TEXT NOT NULL,
            credential_ref   TEXT NOT NULL,
            display_name     TEXT,
            created_at       TEXT NOT NULL,
            last_seen_at     TEXT NOT NULL,
            PRIMARY KEY (user_id, device_id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_credential ON devices(credential_kind, credential_ref);

        CREATE TABLE IF NOT EXISTS device_keys (
            user_id     INTEGER NOT NULL,
            device_id   TEXT NOT NULL,
            algorithms  TEXT NOT NULL,
            keys        TEXT NOT NULL,
            signatures  TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            PRIMARY KEY (user_id, device_id)
        );

        CREATE TABLE IF NOT EXISTS one_time_keys (
            user_id   INTEGER NOT NULL,
            device_id TEXT NOT NULL,
            key_id    TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            key_json  TEXT NOT NULL,
            PRIMARY KEY (user_id, device_id, key_id)
        );
        CREATE INDEX IF NOT EXISTS idx_otk_owner_algorithm ON one_time_keys(user_id, device_id, algorithm);

        -- DEVIATION: `key_id` column added — see this function's doc comment.
        CREATE TABLE IF NOT EXISTS fallback_keys (
            user_id     INTEGER NOT NULL,
            device_id   TEXT NOT NULL,
            algorithm   TEXT NOT NULL,
            key_id      TEXT NOT NULL,
            key_json    TEXT NOT NULL,
            used        INTEGER NOT NULL DEFAULT 0,
            uploaded_at TEXT NOT NULL,
            PRIMARY KEY (user_id, device_id, algorithm)
        );

        CREATE TABLE IF NOT EXISTS to_device_messages (
            stream_id             INTEGER PRIMARY KEY,
            recipient_user_id     INTEGER NOT NULL,
            recipient_device_id   TEXT NOT NULL,
            sender_user_id        INTEGER NOT NULL,
            event_type            TEXT NOT NULL,
            content               TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_to_device_recipient ON to_device_messages(recipient_user_id, recipient_device_id, stream_id);

        CREATE TABLE IF NOT EXISTS device_list_changes (
            stream_id  INTEGER PRIMARY KEY,
            user_id    INTEGER NOT NULL,
            changed_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_device_list_changes_user ON device_list_changes(user_id, stream_id);

        CREATE TABLE IF NOT EXISTS cross_signing_keys (
            user_id     INTEGER NOT NULL,
            usage       TEXT NOT NULL,
            key_json    TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            PRIMARY KEY (user_id, usage)
        );

        CREATE TABLE IF NOT EXISTS cross_signing_signatures (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            signer_user_id INTEGER NOT NULL,
            target_user_id INTEGER NOT NULL,
            target_key_id  TEXT NOT NULL,
            signature_json TEXT NOT NULL,
            uploaded_at    TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_xsig_target ON cross_signing_signatures(target_user_id, target_key_id);

        CREATE TABLE IF NOT EXISTS key_backup_versions (
            version            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id            INTEGER NOT NULL,
            algorithm          TEXT NOT NULL,
            auth_data          TEXT NOT NULL,
            etag               INTEGER NOT NULL DEFAULT 0,
            is_deleted         INTEGER NOT NULL DEFAULT 0,
            created_at         TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_key_backup_versions_user ON key_backup_versions(user_id, version);

        CREATE TABLE IF NOT EXISTS key_backup_sessions (
            user_id      INTEGER NOT NULL,
            version      INTEGER NOT NULL REFERENCES key_backup_versions(version),
            room_id      TEXT NOT NULL,
            session_id   TEXT NOT NULL,
            session_data TEXT NOT NULL,
            updated_at   TEXT NOT NULL,
            PRIMARY KEY (user_id, version, room_id, session_id)
        );
        "#,
    )
}

// ============================================================================
// Devices
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct Device {
    pub user_id: i64,
    pub device_id: String,
    pub credential_kind: CredentialKind,
    pub credential_ref: String,
    pub display_name: Option<String>,
    pub created_at: String,
    pub last_seen_at: String,
}

const DEVICE_SELECT_COLUMNS: &str = "user_id, device_id, credential_kind, credential_ref, display_name, created_at, last_seen_at";

fn device_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Device> {
    let credential_kind_raw: String = row.get(2)?;
    Ok(Device {
        user_id: row.get(0)?,
        device_id: row.get(1)?,
        credential_kind: decode_enum(2, "credential_kind", &credential_kind_raw, CredentialKind::from_wire_name)?,
        credential_ref: row.get(3)?,
        display_name: row.get(4)?,
        created_at: row.get(5)?,
        last_seen_at: row.get(6)?,
    })
}

/// The device already minted for `(credential_kind, credential_ref)`, if
/// any (the unique-index lookup behind `device_id_for`, P4).
pub fn device_for_credential(conn: &Connection, credential_kind: CredentialKind, credential_ref: &str) -> rusqlite::Result<Option<Device>> {
    conn.query_row(
        &format!("SELECT {DEVICE_SELECT_COLUMNS} FROM devices WHERE credential_kind = ?1 AND credential_ref = ?2"),
        params![credential_kind.as_str(), credential_ref],
        device_from_row,
    )
    .optional()
}

/// Mint a fresh device for `user_id` authenticated by
/// `(credential_kind, credential_ref)`, returning the new device id. Does
/// not check for an existing row for this credential — callers use
/// [`device_for_credential`] first (the get-or-create orchestration is
/// P4's `device_id_for`, not this module's job).
pub fn create_device(conn: &Connection, user_id: i64, credential_kind: CredentialKind, credential_ref: &str, now: &str) -> rusqlite::Result<String> {
    let device_id = random_device_id();
    conn.execute(
        "INSERT INTO devices (user_id, device_id, credential_kind, credential_ref, display_name, created_at, last_seen_at)
         VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6)",
        params![user_id, device_id, credential_kind.as_str(), credential_ref, now, now],
    )?;
    Ok(device_id)
}

/// Bump `last_seen_at` on an existing device — a no-op if the device does
/// not exist.
pub fn touch_device(conn: &Connection, user_id: i64, device_id: &str, now: &str) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE devices SET last_seen_at = ?1 WHERE user_id = ?2 AND device_id = ?3",
        params![now, user_id, device_id],
    )?;
    Ok(())
}

/// Every device `user_id` owns.
pub fn list_devices(conn: &Connection, user_id: i64) -> rusqlite::Result<Vec<Device>> {
    let mut stmt = conn.prepare(&format!("SELECT {DEVICE_SELECT_COLUMNS} FROM devices WHERE user_id = ?1"))?;
    let rows = stmt.query_map(params![user_id], device_from_row)?;
    rows.collect()
}

/// One of `user_id`'s own devices, by id.
pub fn get_device(conn: &Connection, user_id: i64, device_id: &str) -> rusqlite::Result<Option<Device>> {
    conn.query_row(
        &format!("SELECT {DEVICE_SELECT_COLUMNS} FROM devices WHERE user_id = ?1 AND device_id = ?2"),
        params![user_id, device_id],
        device_from_row,
    )
    .optional()
}

/// Rename (or clear, with `None`) a device's `display_name`. Returns
/// whether a row was found and updated.
pub fn set_device_display_name(conn: &Connection, user_id: i64, device_id: &str, display_name: Option<&str>) -> rusqlite::Result<bool> {
    let changed = conn.execute(
        "UPDATE devices SET display_name = ?1 WHERE user_id = ?2 AND device_id = ?3",
        params![display_name, user_id, device_id],
    )?;
    Ok(changed > 0)
}

/// Delete every row belonging to `(user_id, device_id)` across
/// `device_keys`/`one_time_keys`/`fallback_keys`/`to_device_messages` — the
/// key-material half of a device revoke. Does NOT delete the `devices` row
/// itself or log a device-list change; callers ([`delete_device`],
/// [`delete_device_by_credential`]) do that, since one deletes the
/// `devices` row before calling this and the other after (the `RETURNING`
/// form).
fn delete_device_key_material(tx: &Transaction, user_id: i64, device_id: &str) -> rusqlite::Result<()> {
    tx.execute("DELETE FROM device_keys WHERE user_id = ?1 AND device_id = ?2", params![user_id, device_id])?;
    tx.execute("DELETE FROM one_time_keys WHERE user_id = ?1 AND device_id = ?2", params![user_id, device_id])?;
    tx.execute("DELETE FROM fallback_keys WHERE user_id = ?1 AND device_id = ?2", params![user_id, device_id])?;
    tx.execute(
        "DELETE FROM to_device_messages WHERE recipient_user_id = ?1 AND recipient_device_id = ?2",
        params![user_id, device_id],
    )?;
    Ok(())
}

/// The manual "log out this device" path (`DELETE /devices/{deviceId}`,
/// P9): delete the device, cascade its key material and pending to-device
/// rows, and append one [`device_list_changes`] row for `user_id`. One
/// transaction. Returns whether a device existed to delete.
pub fn delete_device(conn: &mut Connection, user_id: i64, device_id: &str, now: &str) -> rusqlite::Result<bool> {
    let tx = conn.transaction()?;
    let existed = tx.execute("DELETE FROM devices WHERE user_id = ?1 AND device_id = ?2", params![user_id, device_id])? > 0;
    if existed {
        delete_device_key_material(&tx, user_id, device_id)?;
        log_device_list_change_tx(&tx, user_id, now)?;
    }
    tx.commit()?;
    Ok(existed)
}

/// The credential-revoke path (plan §1.1, `on_credential_revoked` steps
/// 1-3 — the wake fan-out, step 4, is the caller's job in P4): find the
/// device minted for `(credential_kind, credential_ref)`, delete it and
/// its key material and pending to-device rows, and append one
/// `device_list_changes` row for its owner. One transaction. Returns
/// `Some((user_id, device_id))` on a hit, `None` if no device was ever
/// minted for this credential.
pub fn delete_device_by_credential(
    conn: &mut Connection,
    credential_kind: CredentialKind,
    credential_ref: &str,
    now: &str,
) -> rusqlite::Result<Option<(i64, String)>> {
    let tx = conn.transaction()?;
    let found: Option<(i64, String)> = tx
        .query_row(
            "DELETE FROM devices WHERE credential_kind = ?1 AND credential_ref = ?2 RETURNING user_id, device_id",
            params![credential_kind.as_str(), credential_ref],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((user_id, device_id)) = &found {
        delete_device_key_material(&tx, *user_id, device_id)?;
        log_device_list_change_tx(&tx, *user_id, now)?;
    }
    tx.commit()?;
    Ok(found)
}

/// Every device in the system, for the P14 boot+hourly reaper sweep (plan
/// manager decision 3): the sweep itself checks each credential against
/// the identity database and calls [`delete_device_by_credential`] for the
/// ones that are gone or expired — not this module's job.
pub fn devices_for_reaper(conn: &Connection) -> rusqlite::Result<Vec<(i64, String, CredentialKind, String)>> {
    let mut stmt = conn.prepare("SELECT user_id, device_id, credential_kind, credential_ref FROM devices")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let kind_raw: String = row.get(2)?;
        let credential_kind = decode_enum(2, "credential_kind", &kind_raw, CredentialKind::from_wire_name)?;
        out.push((row.get(0)?, row.get(1)?, credential_kind, row.get(3)?));
    }
    Ok(out)
}

// ============================================================================
// Device keys
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct DeviceKeys {
    pub user_id: i64,
    pub device_id: String,
    pub algorithms: String,
    pub keys: String,
    pub signatures: String,
    pub uploaded_at: String,
}

const DEVICE_KEYS_SELECT_COLUMNS: &str = "user_id, device_id, algorithms, keys, signatures, uploaded_at";

fn device_keys_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeviceKeys> {
    Ok(DeviceKeys {
        user_id: row.get(0)?,
        device_id: row.get(1)?,
        algorithms: row.get(2)?,
        keys: row.get(3)?,
        signatures: row.get(4)?,
        uploaded_at: row.get(5)?,
    })
}

/// Store (or replace) `POST /keys/upload`'s device-keys object verbatim.
/// Appends one [`device_list_changes`] row for `user_id` — every peer
/// sharing a room learns about the change on their next `/sync`. One
/// transaction.
pub fn upsert_device_keys(
    conn: &mut Connection,
    user_id: i64,
    device_id: &str,
    algorithms_json: &str,
    keys_json: &str,
    signatures_json: &str,
    now: &str,
) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO device_keys (user_id, device_id, algorithms, keys, signatures, uploaded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(user_id, device_id) DO UPDATE SET
            algorithms = excluded.algorithms, keys = excluded.keys, signatures = excluded.signatures, uploaded_at = excluded.uploaded_at",
        params![user_id, device_id, algorithms_json, keys_json, signatures_json, now],
    )?;
    log_device_list_change_tx(&tx, user_id, now)?;
    tx.commit()?;
    Ok(())
}

/// Every device-keys row belonging to any of `user_ids` — the `/keys/query`
/// batch shape. Empty input returns an empty vec without touching the
/// database.
pub fn device_keys_for(conn: &Connection, user_ids: &[i64]) -> rusqlite::Result<Vec<DeviceKeys>> {
    if user_ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = vec!["?"; user_ids.len()].join(",");
    let sql = format!("SELECT {DEVICE_KEYS_SELECT_COLUMNS} FROM device_keys WHERE user_id IN ({placeholders})");
    let mut stmt = conn.prepare(&sql)?;
    let bound: Vec<&dyn rusqlite::ToSql> = user_ids.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
    let rows = stmt.query_map(bound.as_slice(), device_keys_from_row)?;
    rows.collect()
}

// ============================================================================
// One-time keys
// ============================================================================

/// Upload a batch of one-time keys. Per key: a brand-new `key_id` is
/// inserted; a `key_id` that already exists with byte-identical
/// `key_json` is a silent no-op (idempotent resubmission); a `key_id` that
/// already exists with DIFFERENT `key_json` refuses the WHOLE batch with
/// [`MatrixKeysStoreError::OneTimeKeyConflict`] (one transaction — a
/// refused call leaves no partial insert from this batch).
pub fn add_one_time_keys(conn: &mut Connection, user_id: i64, device_id: &str, keys: &[(String, String, String)]) -> Result<(), MatrixKeysStoreError> {
    let tx = conn.transaction()?;
    for (key_id, algorithm, key_json) in keys {
        let existing: Option<String> = tx
            .query_row(
                "SELECT key_json FROM one_time_keys WHERE user_id = ?1 AND device_id = ?2 AND key_id = ?3",
                params![user_id, device_id, key_id],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            None => {
                tx.execute(
                    "INSERT INTO one_time_keys (user_id, device_id, key_id, algorithm, key_json) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![user_id, device_id, key_id, algorithm, key_json],
                )?;
            }
            Some(ref existing_json) if existing_json == key_json => {
                // Identical resubmission — no-op, per spec.
            }
            Some(_) => {
                return Err(MatrixKeysStoreError::OneTimeKeyConflict(key_id.clone()));
            }
        }
    }
    tx.commit()?;
    Ok(())
}

/// How many one-time keys remain per algorithm — `/keys/upload`'s response
/// and `/sync`'s `device_one_time_keys_count`.
pub fn count_one_time_keys(conn: &Connection, user_id: i64, device_id: &str) -> rusqlite::Result<HashMap<String, i64>> {
    let mut stmt = conn.prepare("SELECT algorithm, COUNT(*) FROM one_time_keys WHERE user_id = ?1 AND device_id = ?2 GROUP BY algorithm")?;
    let rows = stmt.query_map(params![user_id, device_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))?;
    let mut out = HashMap::new();
    for row in rows {
        let (algorithm, count) = row?;
        out.insert(algorithm, count);
    }
    Ok(out)
}

/// Claim one one-time key of `algorithm` for `(user_id, device_id)`: an
/// atomic `DELETE ... RETURNING` on the lowest `key_id` — the "exactly
/// once" guarantee, no window where two claimants could race the same key.
/// If none remain, falls back to the (reusable, never-deleted) fallback
/// key for that algorithm and marks it `used = 1` — the client reads its
/// own [`unused_fallback_key_types`] to know when it should upload a fresh
/// one.
pub fn claim_one_time_key(conn: &mut Connection, user_id: i64, device_id: &str, algorithm: &str) -> rusqlite::Result<Option<(String, String)>> {
    let tx = conn.transaction()?;
    let claimed: Option<(String, String)> = tx
        .query_row(
            "DELETE FROM one_time_keys
             WHERE user_id = ?1 AND device_id = ?2 AND algorithm = ?3
               AND key_id = (
                   SELECT key_id FROM one_time_keys
                   WHERE user_id = ?1 AND device_id = ?2 AND algorithm = ?3
                   ORDER BY key_id ASC LIMIT 1
               )
             RETURNING key_id, key_json",
            params![user_id, device_id, algorithm],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let result = match claimed {
        Some(pair) => Some(pair),
        None => {
            let fallback: Option<(String, String)> = tx
                .query_row(
                    "SELECT key_id, key_json FROM fallback_keys WHERE user_id = ?1 AND device_id = ?2 AND algorithm = ?3",
                    params![user_id, device_id, algorithm],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if fallback.is_some() {
                tx.execute(
                    "UPDATE fallback_keys SET used = 1 WHERE user_id = ?1 AND device_id = ?2 AND algorithm = ?3",
                    params![user_id, device_id, algorithm],
                )?;
            }
            fallback
        }
    };
    tx.commit()?;
    Ok(result)
}

// ============================================================================
// Fallback keys
// ============================================================================

/// Upload (or replace) the one active fallback key for `algorithm` —
/// replacing always resets `used` back to `0`, per spec ("a new fallback
/// key is unused until it is actually claimed").
pub fn upsert_fallback_key(
    conn: &Connection,
    user_id: i64,
    device_id: &str,
    algorithm: &str,
    key_id: &str,
    key_json: &str,
    now: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO fallback_keys (user_id, device_id, algorithm, key_id, key_json, used, uploaded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)
         ON CONFLICT(user_id, device_id, algorithm) DO UPDATE SET
            key_id = excluded.key_id, key_json = excluded.key_json, used = 0, uploaded_at = excluded.uploaded_at",
        params![user_id, device_id, algorithm, key_id, key_json, now],
    )?;
    Ok(())
}

/// Every fallback-key algorithm that has not yet been claimed — the client
/// uses this to decide which algorithms need a fresh fallback key
/// uploaded.
pub fn unused_fallback_key_types(conn: &Connection, user_id: i64, device_id: &str) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT algorithm FROM fallback_keys WHERE user_id = ?1 AND device_id = ?2 AND used = 0")?;
    let rows = stmt.query_map(params![user_id, device_id], |row| row.get(0))?;
    rows.collect()
}

// ============================================================================
// To-device
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct ToDeviceMessage {
    pub stream_id: i64,
    pub recipient_user_id: i64,
    pub recipient_device_id: String,
    pub sender_user_id: i64,
    pub event_type: String,
    pub content: String,
}

const TO_DEVICE_SELECT_COLUMNS: &str = "stream_id, recipient_user_id, recipient_device_id, sender_user_id, event_type, content";

fn to_device_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ToDeviceMessage> {
    Ok(ToDeviceMessage {
        stream_id: row.get(0)?,
        recipient_user_id: row.get(1)?,
        recipient_device_id: row.get(2)?,
        sender_user_id: row.get(3)?,
        event_type: row.get(4)?,
        content: row.get(5)?,
    })
}

/// Fan out one `PUT /sendToDevice` call's `messages` map (already flattened
/// to one row per `(recipient_user_id, recipient_device_id)` — a `*`
/// device wildcard is resolved by the caller before this function ever
/// sees it) as one transaction sharing `matrix_store`'s global stream
/// counter. Returns the last stream id minted, or the counter's current
/// value unchanged if `messages` is empty.
pub fn enqueue_to_device(conn: &mut Connection, sender_user_id: i64, messages: &[(i64, String, String, String)]) -> rusqlite::Result<i64> {
    let tx = conn.transaction()?;
    let mut last_stream_id = matrix_store::max_stream_id(&tx)?;
    for (recipient_user_id, recipient_device_id, event_type, content) in messages {
        let stream_id = matrix_store::next_stream_id(&tx)?;
        tx.execute(
            "INSERT INTO to_device_messages (stream_id, recipient_user_id, recipient_device_id, sender_user_id, event_type, content)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![stream_id, recipient_user_id, recipient_device_id, sender_user_id, event_type, content],
        )?;
        last_stream_id = stream_id;
    }
    tx.commit()?;
    Ok(last_stream_id)
}

/// Every to-device message still pending for `(user_id, device_id)` after
/// `after_stream`, oldest first — `/sync`'s `to_device.events`.
pub fn to_device_for(conn: &Connection, user_id: i64, device_id: &str, after_stream: i64, limit: i64) -> rusqlite::Result<Vec<ToDeviceMessage>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {TO_DEVICE_SELECT_COLUMNS} FROM to_device_messages
         WHERE recipient_user_id = ?1 AND recipient_device_id = ?2 AND stream_id > ?3
         ORDER BY stream_id ASC LIMIT ?4"
    ))?;
    let rows = stmt.query_map(params![user_id, device_id, after_stream, limit], to_device_from_row)?;
    rows.collect()
}

/// Delete every to-device row for `(user_id, device_id)` at or before
/// `stream_id` — plan §3.7's delete-after-ack rule: a `/sync` call with
/// `since=stream_id` is itself the proof the client already durably
/// received everything up to that point. Returns the number of rows
/// removed.
pub fn delete_to_device_up_to(conn: &Connection, user_id: i64, device_id: &str, stream_id: i64) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM to_device_messages WHERE recipient_user_id = ?1 AND recipient_device_id = ?2 AND stream_id <= ?3",
        params![user_id, device_id, stream_id],
    )
}

// ============================================================================
// Device-list changes
// ============================================================================

fn log_device_list_change_tx(tx: &Transaction, user_id: i64, now: &str) -> rusqlite::Result<i64> {
    let stream_id = matrix_store::next_stream_id(tx)?;
    tx.execute(
        "INSERT INTO device_list_changes (stream_id, user_id, changed_at) VALUES (?1, ?2, ?3)",
        params![stream_id, user_id, now],
    )?;
    Ok(stream_id)
}

/// Standalone entry point for a caller that is not already inside one of
/// this module's own multi-step transactions (e.g. a future piece that
/// needs to log a change without also writing a keys row). Every write in
/// THIS module that is documented to log a change does so inline, in the
/// same transaction as that write — this function is for everyone else.
pub fn log_device_list_change(conn: &mut Connection, user_id: i64, now: &str) -> rusqlite::Result<i64> {
    let tx = conn.transaction()?;
    let stream_id = log_device_list_change_tx(&tx, user_id, now)?;
    tx.commit()?;
    Ok(stream_id)
}

/// Every distinct `user_id` whose device list changed in
/// `(from_exclusive, to_inclusive]` — `/sync`'s `device_lists.changed`
/// candidate set, before the caller restricts it to shared-room users
/// (plan §3.7).
pub fn device_list_changes_between(conn: &Connection, from_exclusive: i64, to_inclusive: i64) -> rusqlite::Result<Vec<i64>> {
    let mut stmt = conn.prepare("SELECT DISTINCT user_id FROM device_list_changes WHERE stream_id > ?1 AND stream_id <= ?2")?;
    let rows = stmt.query_map(params![from_exclusive, to_inclusive], |row| row.get(0))?;
    rows.collect()
}

// ============================================================================
// Cross-signing
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct CrossSigningKey {
    pub user_id: i64,
    pub usage: CrossSigningUsage,
    pub key_json: String,
    pub uploaded_at: String,
}

const CROSS_SIGNING_KEY_SELECT_COLUMNS: &str = "user_id, usage, key_json, uploaded_at";

fn cross_signing_key_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CrossSigningKey> {
    let usage_raw: String = row.get(1)?;
    Ok(CrossSigningKey {
        user_id: row.get(0)?,
        usage: decode_enum(1, "usage", &usage_raw, CrossSigningUsage::from_wire_name)?,
        key_json: row.get(2)?,
        uploaded_at: row.get(3)?,
    })
}

/// Store (or replace) one of `user_id`'s three cross-signing keys.
/// Appends one [`device_list_changes`] row, same as [`upsert_device_keys`]
/// — a peer's trust chain changed, not just a device.
pub fn upsert_cross_signing_key(conn: &mut Connection, user_id: i64, usage: CrossSigningUsage, key_json: &str, now: &str) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO cross_signing_keys (user_id, usage, key_json, uploaded_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(user_id, usage) DO UPDATE SET key_json = excluded.key_json, uploaded_at = excluded.uploaded_at",
        params![user_id, usage.as_str(), key_json, now],
    )?;
    log_device_list_change_tx(&tx, user_id, now)?;
    tx.commit()?;
    Ok(())
}

/// Every cross-signing key belonging to any of `user_ids` — the
/// `/keys/query` batch shape. Empty input returns an empty vec.
pub fn cross_signing_keys_for(conn: &Connection, user_ids: &[i64]) -> rusqlite::Result<Vec<CrossSigningKey>> {
    if user_ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = vec!["?"; user_ids.len()].join(",");
    let sql = format!("SELECT {CROSS_SIGNING_KEY_SELECT_COLUMNS} FROM cross_signing_keys WHERE user_id IN ({placeholders})");
    let mut stmt = conn.prepare(&sql)?;
    let bound: Vec<&dyn rusqlite::ToSql> = user_ids.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
    let rows = stmt.query_map(bound.as_slice(), cross_signing_key_from_row)?;
    rows.collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct CrossSigningSignature {
    pub id: i64,
    pub signer_user_id: i64,
    pub target_user_id: i64,
    pub target_key_id: String,
    pub signature_json: String,
    pub uploaded_at: String,
}

const CROSS_SIGNING_SIGNATURE_SELECT_COLUMNS: &str = "id, signer_user_id, target_user_id, target_key_id, signature_json, uploaded_at";

fn cross_signing_signature_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CrossSigningSignature> {
    Ok(CrossSigningSignature {
        id: row.get(0)?,
        signer_user_id: row.get(1)?,
        target_user_id: row.get(2)?,
        target_key_id: row.get(3)?,
        signature_json: row.get(4)?,
        uploaded_at: row.get(5)?,
    })
}

/// Append a batch of `/keys/signatures/upload` signatures — pure storage,
/// never verified server-side (opaque, per this module's own doc comment).
/// One transaction.
pub fn add_signatures(conn: &mut Connection, signatures: &[(i64, i64, String, String, String)]) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    for (signer_user_id, target_user_id, target_key_id, signature_json, uploaded_at) in signatures {
        tx.execute(
            "INSERT INTO cross_signing_signatures (signer_user_id, target_user_id, target_key_id, signature_json, uploaded_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![signer_user_id, target_user_id, target_key_id, signature_json, uploaded_at],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Every signature filed against `(target_user_id, target_key_id)`.
pub fn signatures_for(conn: &Connection, target_user_id: i64, target_key_id: &str) -> rusqlite::Result<Vec<CrossSigningSignature>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {CROSS_SIGNING_SIGNATURE_SELECT_COLUMNS} FROM cross_signing_signatures WHERE target_user_id = ?1 AND target_key_id = ?2"
    ))?;
    let rows = stmt.query_map(params![target_user_id, target_key_id], cross_signing_signature_from_row)?;
    rows.collect()
}

// ============================================================================
// Key backup
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct KeyBackupVersion {
    pub version: i64,
    pub user_id: i64,
    pub algorithm: String,
    pub auth_data: String,
    pub etag: i64,
    pub is_deleted: bool,
    pub created_at: String,
}

const KEY_BACKUP_VERSION_SELECT_COLUMNS: &str = "version, user_id, algorithm, auth_data, etag, is_deleted, created_at";

fn key_backup_version_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<KeyBackupVersion> {
    Ok(KeyBackupVersion {
        version: row.get(0)?,
        user_id: row.get(1)?,
        algorithm: row.get(2)?,
        auth_data: row.get(3)?,
        etag: row.get(4)?,
        is_deleted: row.get(5)?,
        created_at: row.get(6)?,
    })
}

/// Create a brand-new key-backup version — a version number is never
/// reused (soft-delete only, see [`delete_backup_version`]), so this is a
/// plain insert.
pub fn create_backup_version(conn: &Connection, user_id: i64, algorithm: &str, auth_data: &str, now: &str) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO key_backup_versions (user_id, algorithm, auth_data, etag, is_deleted, created_at)
         VALUES (?1, ?2, ?3, 0, 0, ?4)",
        params![user_id, algorithm, auth_data, now],
    )?;
    Ok(conn.last_insert_rowid())
}

/// `user_id`'s current (highest-numbered, non-deleted) backup version, if
/// any.
pub fn current_backup_version(conn: &Connection, user_id: i64) -> rusqlite::Result<Option<KeyBackupVersion>> {
    conn.query_row(
        &format!(
            "SELECT {KEY_BACKUP_VERSION_SELECT_COLUMNS} FROM key_backup_versions
             WHERE user_id = ?1 AND is_deleted = 0 ORDER BY version DESC LIMIT 1"
        ),
        params![user_id],
        key_backup_version_from_row,
    )
    .optional()
}

/// One specific backup version by number, regardless of its `is_deleted`
/// state — the caller decides how to treat a deleted version (a fetch by
/// an explicit version number is a different question than "what's
/// current").
pub fn get_backup_version(conn: &Connection, user_id: i64, version: i64) -> rusqlite::Result<Option<KeyBackupVersion>> {
    conn.query_row(
        &format!("SELECT {KEY_BACKUP_VERSION_SELECT_COLUMNS} FROM key_backup_versions WHERE user_id = ?1 AND version = ?2"),
        params![user_id, version],
        key_backup_version_from_row,
    )
    .optional()
}

/// Update a non-deleted backup version's opaque `auth_data`, bumping its
/// `etag`. Returns whether a row was found and updated.
pub fn update_backup_version_auth_data(conn: &Connection, user_id: i64, version: i64, auth_data: &str) -> rusqlite::Result<bool> {
    let changed = conn.execute(
        "UPDATE key_backup_versions SET auth_data = ?1, etag = etag + 1 WHERE user_id = ?2 AND version = ?3 AND is_deleted = 0",
        params![auth_data, user_id, version],
    )?;
    Ok(changed > 0)
}

/// Soft-delete a backup version (the version number is never reused, so
/// its `key_backup_sessions` rows are left in place as inert history).
/// Idempotent: deleting an already-deleted version returns `false`.
pub fn delete_backup_version(conn: &Connection, user_id: i64, version: i64) -> rusqlite::Result<bool> {
    let changed = conn.execute(
        "UPDATE key_backup_versions SET is_deleted = 1, etag = etag + 1 WHERE user_id = ?1 AND version = ?2 AND is_deleted = 0",
        params![user_id, version],
    )?;
    Ok(changed > 0)
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeyBackupSession {
    pub user_id: i64,
    pub version: i64,
    pub room_id: String,
    pub session_id: String,
    pub session_data: String,
    pub updated_at: String,
}

const KEY_BACKUP_SESSION_SELECT_COLUMNS: &str = "user_id, version, room_id, session_id, session_data, updated_at";

fn key_backup_session_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<KeyBackupSession> {
    Ok(KeyBackupSession {
        user_id: row.get(0)?,
        version: row.get(1)?,
        room_id: row.get(2)?,
        session_id: row.get(3)?,
        session_data: row.get(4)?,
        updated_at: row.get(5)?,
    })
}

/// Upload a batch of backup sessions into `version` — refuses with
/// [`MatrixKeysStoreError::WrongBackupVersion`] unless `version` is
/// `user_id`'s current non-deleted version (plan §2 manager decision 5).
/// Bumps `etag` once for the whole batch. One transaction.
pub fn put_backup_sessions(
    conn: &mut Connection,
    user_id: i64,
    version: i64,
    sessions: &[(String, String, String)],
    now: &str,
) -> Result<(), MatrixKeysStoreError> {
    let tx = conn.transaction()?;
    let current_version: Option<i64> = tx.query_row(
        "SELECT MAX(version) FROM key_backup_versions WHERE user_id = ?1 AND is_deleted = 0",
        params![user_id],
        |row| row.get(0),
    )?;
    if current_version != Some(version) {
        return Err(MatrixKeysStoreError::WrongBackupVersion);
    }
    for (room_id, session_id, session_data) in sessions {
        tx.execute(
            "INSERT INTO key_backup_sessions (user_id, version, room_id, session_id, session_data, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(user_id, version, room_id, session_id) DO UPDATE SET
                session_data = excluded.session_data, updated_at = excluded.updated_at",
            params![user_id, version, room_id, session_id, session_data, now],
        )?;
    }
    tx.execute(
        "UPDATE key_backup_versions SET etag = etag + 1 WHERE user_id = ?1 AND version = ?2",
        params![user_id, version],
    )?;
    tx.commit()?;
    Ok(())
}

/// Read backup sessions for `version`, optionally narrowed to one room
/// and/or one session (mirroring `GET /room_keys/keys[/{roomId}[/{sessionId}]]`'s
/// three shapes). A `session_id` without a `room_id` is treated the same
/// as neither being given — the wire path never allows that combination.
pub fn get_backup_sessions(
    conn: &Connection,
    user_id: i64,
    version: i64,
    room_id: Option<&str>,
    session_id: Option<&str>,
) -> rusqlite::Result<Vec<KeyBackupSession>> {
    match (room_id, session_id) {
        (Some(room_id), Some(session_id)) => {
            let mut stmt = conn.prepare(&format!(
                "SELECT {KEY_BACKUP_SESSION_SELECT_COLUMNS} FROM key_backup_sessions
                 WHERE user_id = ?1 AND version = ?2 AND room_id = ?3 AND session_id = ?4"
            ))?;
            let rows = stmt.query_map(params![user_id, version, room_id, session_id], key_backup_session_from_row)?;
            rows.collect()
        }
        (Some(room_id), None) => {
            let mut stmt = conn.prepare(&format!(
                "SELECT {KEY_BACKUP_SESSION_SELECT_COLUMNS} FROM key_backup_sessions
                 WHERE user_id = ?1 AND version = ?2 AND room_id = ?3"
            ))?;
            let rows = stmt.query_map(params![user_id, version, room_id], key_backup_session_from_row)?;
            rows.collect()
        }
        (None, _) => {
            let mut stmt = conn.prepare(&format!(
                "SELECT {KEY_BACKUP_SESSION_SELECT_COLUMNS} FROM key_backup_sessions WHERE user_id = ?1 AND version = ?2"
            ))?;
            let rows = stmt.query_map(params![user_id, version], key_backup_session_from_row)?;
            rows.collect()
        }
    }
}

/// Delete backup sessions for `version`, same three-shape narrowing as
/// [`get_backup_sessions`]. Bumps `etag` once iff at least one row was
/// removed. One transaction. Returns the number of rows deleted.
pub fn delete_backup_sessions(
    conn: &mut Connection,
    user_id: i64,
    version: i64,
    room_id: Option<&str>,
    session_id: Option<&str>,
) -> rusqlite::Result<usize> {
    let tx = conn.transaction()?;
    let deleted = match (room_id, session_id) {
        (Some(room_id), Some(session_id)) => tx.execute(
            "DELETE FROM key_backup_sessions WHERE user_id = ?1 AND version = ?2 AND room_id = ?3 AND session_id = ?4",
            params![user_id, version, room_id, session_id],
        )?,
        (Some(room_id), None) => tx.execute(
            "DELETE FROM key_backup_sessions WHERE user_id = ?1 AND version = ?2 AND room_id = ?3",
            params![user_id, version, room_id],
        )?,
        (None, _) => tx.execute(
            "DELETE FROM key_backup_sessions WHERE user_id = ?1 AND version = ?2",
            params![user_id, version],
        )?,
    };
    if deleted > 0 {
        tx.execute(
            "UPDATE key_backup_versions SET etag = etag + 1 WHERE user_id = ?1 AND version = ?2",
            params![user_id, version],
        )?;
    }
    tx.commit()?;
    Ok(deleted)
}

/// `(session count, current etag)` for `version` — the `GET
/// /room_keys/version[/{version}]` response shape's `count`/`etag` pair.
pub fn backup_count_and_etag(conn: &Connection, user_id: i64, version: i64) -> rusqlite::Result<(i64, i64)> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM key_backup_sessions WHERE user_id = ?1 AND version = ?2",
        params![user_id, version],
        |row| row.get(0),
    )?;
    let etag: i64 = conn.query_row(
        "SELECT etag FROM key_backup_versions WHERE user_id = ?1 AND version = ?2",
        params![user_id, version],
        |row| row.get(0),
    )?;
    Ok((count, etag))
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: &str = "2026-09-24T00:00:00+00:00";

    fn test_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        matrix_store::create_matrix_schema(&conn).expect("matrix schema (stream_counter lives there)");
        create_matrix_keys_schema(&conn).expect("matrix keys schema");
        conn
    }

    fn count_device_list_changes(conn: &Connection, user_id: i64) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM device_list_changes WHERE user_id = ?1", params![user_id], |row| row.get(0))
            .expect("count device_list_changes")
    }

    // ---- P2 test 1: claim deletes so a second claim differs ----

    #[test]
    fn claim_one_time_key_deletes_it_so_a_second_claim_gets_a_different_key_or_none() {
        let mut conn = test_conn();
        add_one_time_keys(
            &mut conn,
            1,
            "DEV1",
            &[
                ("signed_curve25519:AAAAAQ".to_string(), "signed_curve25519".to_string(), r#"{"key":"k1"}"#.to_string()),
                ("signed_curve25519:AAAAAg".to_string(), "signed_curve25519".to_string(), r#"{"key":"k2"}"#.to_string()),
            ],
        )
        .expect("add otks");

        let first = claim_one_time_key(&mut conn, 1, "DEV1", "signed_curve25519").expect("claim 1").expect("has a key");
        let second = claim_one_time_key(&mut conn, 1, "DEV1", "signed_curve25519").expect("claim 2").expect("has a different key");
        assert_ne!(first.0, second.0, "the two claims must return different key ids");

        let third = claim_one_time_key(&mut conn, 1, "DEV1", "signed_curve25519").expect("claim 3");
        assert_eq!(third, None, "no one-time keys or fallback keys remain");
    }

    // ---- P2 test 2: fallback is not deleted, is marked used ----

    #[test]
    fn claim_falls_back_to_a_fallback_key_without_deleting_it_and_marks_it_used() {
        let mut conn = test_conn();
        upsert_fallback_key(&conn, 1, "DEV1", "signed_curve25519", "signed_curve25519:FALLBACK", r#"{"key":"fb"}"#, T0).expect("upsert fallback");

        let claimed = claim_one_time_key(&mut conn, 1, "DEV1", "signed_curve25519").expect("claim").expect("fallback returned");
        assert_eq!(claimed.0, "signed_curve25519:FALLBACK");
        assert_eq!(claimed.1, r#"{"key":"fb"}"#);

        let claimed_again = claim_one_time_key(&mut conn, 1, "DEV1", "signed_curve25519").expect("claim again").expect("fallback still there");
        assert_eq!(claimed_again.0, "signed_curve25519:FALLBACK", "a fallback key is never deleted on claim");

        let unused = unused_fallback_key_types(&conn, 1, "DEV1").expect("unused types");
        assert!(unused.is_empty(), "the fallback key must be marked used after its first claim");
    }

    // ---- P2 test 3: unused fallback types excludes a used one ----

    #[test]
    fn device_unused_fallback_key_types_excludes_a_used_one() {
        let mut conn = test_conn();
        upsert_fallback_key(&conn, 1, "DEV1", "signed_curve25519", "signed_curve25519:FB1", r#"{"key":"fb1"}"#, T0).expect("fallback 1");
        upsert_fallback_key(&conn, 1, "DEV1", "olm_curve25519", "olm_curve25519:FB2", r#"{"key":"fb2"}"#, T0).expect("fallback 2");

        let before = unused_fallback_key_types(&conn, 1, "DEV1").expect("before claim");
        assert_eq!(before.len(), 2);

        claim_one_time_key(&mut conn, 1, "DEV1", "signed_curve25519").expect("claim marks it used");

        let after = unused_fallback_key_types(&conn, 1, "DEV1").expect("after claim");
        assert_eq!(after, vec!["olm_curve25519".to_string()]);
    }

    // ---- P2 test 4 (on_credential_revoked steps 1-3, tested at this
    // module's own entry point, delete_device_by_credential) ----

    #[test]
    fn delete_device_by_credential_deletes_the_device_and_its_key_rows_and_logs_a_device_list_change() {
        let mut conn = test_conn();
        let device_id = create_device(&conn, 1, CredentialKind::Bearer, "tok-hash-1", T0).expect("create device");
        upsert_device_keys(&mut conn, 1, &device_id, "[]", "{}", "{}", T0).expect("upload device keys");
        add_one_time_keys(
            &mut conn,
            1,
            &device_id,
            &[("signed_curve25519:AAAAAQ".to_string(), "signed_curve25519".to_string(), "{}".to_string())],
        )
        .expect("otk");
        upsert_fallback_key(&conn, 1, &device_id, "signed_curve25519", "signed_curve25519:FB", "{}", T0).expect("fallback");
        enqueue_to_device(&mut conn, 2, &[(1, device_id.clone(), "m.text".to_string(), "{}".to_string())]).expect("to-device");

        let before = count_device_list_changes(&conn, 1);
        let deleted = delete_device_by_credential(&mut conn, CredentialKind::Bearer, "tok-hash-1", T0).expect("revoke");
        assert_eq!(deleted, Some((1, device_id.clone())));

        assert_eq!(get_device(&conn, 1, &device_id).expect("get"), None);
        let keys_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM device_keys WHERE user_id = 1 AND device_id = ?1", params![device_id], |row| row.get(0))
            .expect("keys count");
        assert_eq!(keys_count, 0);
        let otk_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM one_time_keys WHERE user_id = 1 AND device_id = ?1", params![device_id], |row| row.get(0))
            .expect("otk count");
        assert_eq!(otk_count, 0);
        let fallback_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM fallback_keys WHERE user_id = 1 AND device_id = ?1", params![device_id], |row| row.get(0))
            .expect("fallback count");
        assert_eq!(fallback_count, 0);
        let to_device_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM to_device_messages WHERE recipient_device_id = ?1", params![device_id], |row| row.get(0))
            .expect("to-device count");
        assert_eq!(to_device_count, 0);

        let after = count_device_list_changes(&conn, 1);
        assert_eq!(after, before + 1, "exactly one device_list_changes row must be appended");

        assert_eq!(
            delete_device_by_credential(&mut conn, CredentialKind::Bearer, "tok-hash-1", T0).expect("second revoke is a no-op"),
            None
        );
    }

    // ---- explicit brief test 1: one-time key idempotency/conflict ----

    #[test]
    fn add_one_time_keys_is_idempotent_for_identical_json_and_refuses_changed_json() {
        let mut conn = test_conn();
        let key = ("signed_curve25519:AAAAAQ".to_string(), "signed_curve25519".to_string(), r#"{"key":"k1"}"#.to_string());
        add_one_time_keys(&mut conn, 1, "DEV1", &[key.clone()]).expect("first add");
        add_one_time_keys(&mut conn, 1, "DEV1", &[key.clone()]).expect("identical resubmission is a no-op");

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM one_time_keys WHERE user_id = 1 AND device_id = 'DEV1'", [], |row| row.get(0))
            .expect("count");
        assert_eq!(count, 1);

        let changed = ("signed_curve25519:AAAAAQ".to_string(), "signed_curve25519".to_string(), r#"{"key":"k2-different"}"#.to_string());
        let err = add_one_time_keys(&mut conn, 1, "DEV1", &[changed]).unwrap_err();
        assert!(matches!(err, MatrixKeysStoreError::OneTimeKeyConflict(ref id) if id == "signed_curve25519:AAAAAQ"));
    }

    // ---- explicit brief test 2: to-device delete-up-to leaves later ones ----

    #[test]
    fn to_device_delete_up_to_leaves_later_messages() {
        let mut conn = test_conn();
        let s1 = enqueue_to_device(&mut conn, 2, &[(1, "DEV1".to_string(), "m.a".to_string(), "{}".to_string())]).expect("send 1");
        let s2 = enqueue_to_device(&mut conn, 2, &[(1, "DEV1".to_string(), "m.b".to_string(), "{}".to_string())]).expect("send 2");
        assert!(s2 > s1);

        let deleted = delete_to_device_up_to(&conn, 1, "DEV1", s1).expect("delete up to s1");
        assert_eq!(deleted, 1);

        let remaining = to_device_for(&conn, 1, "DEV1", 0, 10).expect("remaining");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].stream_id, s2);
    }

    // ---- explicit brief test 3: device_keys change logs a device-list change ----

    #[test]
    fn device_keys_change_logs_a_device_list_change() {
        let mut conn = test_conn();
        let before = count_device_list_changes(&conn, 1);
        upsert_device_keys(&mut conn, 1, "DEV1", "[\"m.olm.v1\"]", "{}", "{}", T0).expect("upload keys");
        let after = count_device_list_changes(&conn, 1);
        assert_eq!(after, before + 1);

        let rows = device_keys_for(&conn, &[1]).expect("query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].device_id, "DEV1");

        assert_eq!(device_keys_for(&conn, &[]).expect("empty input"), Vec::new());
    }

    // ---- explicit brief test 4: put_backup_sessions refuses a stale version ----

    #[test]
    fn put_backup_sessions_refuses_a_stale_version() {
        let mut conn = test_conn();
        let v1 = create_backup_version(&conn, 1, "m.megolm_backup.v1", "{}", T0).expect("v1");
        let v2 = create_backup_version(&conn, 1, "m.megolm_backup.v1", "{}", T0).expect("v2");
        assert!(v2 > v1);

        let err = put_backup_sessions(&mut conn, 1, v1, &[("!room:x".to_string(), "sess1".to_string(), "{}".to_string())], T0).unwrap_err();
        assert!(matches!(err, MatrixKeysStoreError::WrongBackupVersion));

        put_backup_sessions(&mut conn, 1, v2, &[("!room:x".to_string(), "sess1".to_string(), "{}".to_string())], T0).expect("current version accepted");
    }

    // ---- explicit brief test 5: delete_device cascades keys + pending to-device ----

    #[test]
    fn delete_device_cascades_keys_and_pending_to_device() {
        let mut conn = test_conn();
        let device_id = create_device(&conn, 1, CredentialKind::Web, "sess-1", T0).expect("create device");
        upsert_device_keys(&mut conn, 1, &device_id, "[]", "{}", "{}", T0).expect("device keys");
        add_one_time_keys(
            &mut conn,
            1,
            &device_id,
            &[("signed_curve25519:AAAAAQ".to_string(), "signed_curve25519".to_string(), "{}".to_string())],
        )
        .expect("otk");
        upsert_fallback_key(&conn, 1, &device_id, "signed_curve25519", "signed_curve25519:FB", "{}", T0).expect("fallback");
        enqueue_to_device(&mut conn, 9, &[(1, device_id.clone(), "m.text".to_string(), "{}".to_string())]).expect("to-device");

        let before = count_device_list_changes(&conn, 1);
        let deleted = delete_device(&mut conn, 1, &device_id, T0).expect("delete");
        assert!(deleted);

        assert_eq!(get_device(&conn, 1, &device_id).expect("get"), None);
        assert!(device_keys_for(&conn, &[1]).expect("keys").is_empty());
        assert_eq!(count_one_time_keys(&conn, 1, &device_id).expect("otk count").len(), 0);
        assert!(unused_fallback_key_types(&conn, 1, &device_id).expect("fallback").is_empty());
        assert!(to_device_for(&conn, 1, &device_id, 0, 10).expect("to-device").is_empty());

        let after = count_device_list_changes(&conn, 1);
        assert_eq!(after, before + 1);

        let deleted_again = delete_device(&mut conn, 1, &device_id, T0).expect("second delete is a no-op");
        assert!(!deleted_again);
    }

    // ---- supporting coverage ----

    #[test]
    fn create_device_mints_a_fresh_device_id_and_touch_device_updates_last_seen() {
        let conn = test_conn();
        let d1 = create_device(&conn, 1, CredentialKind::Bearer, "tok-a", T0).expect("create 1");
        let d2 = create_device(&conn, 1, CredentialKind::Bearer, "tok-b", T0).expect("create 2");
        assert_ne!(d1, d2, "two different credentials must mint different device ids");

        touch_device(&conn, 1, &d1, "2026-09-24T01:00:00+00:00").expect("touch");
        let row = get_device(&conn, 1, &d1).expect("get").expect("row exists");
        assert_eq!(row.last_seen_at, "2026-09-24T01:00:00+00:00");
        assert_eq!(row.created_at, T0, "created_at must not move on touch");
    }

    #[test]
    fn device_for_credential_finds_the_row_created_by_create_device() {
        let conn = test_conn();
        let device_id = create_device(&conn, 5, CredentialKind::Web, "sess-xyz", T0).expect("create");
        let found = device_for_credential(&conn, CredentialKind::Web, "sess-xyz").expect("lookup").expect("row exists");
        assert_eq!(found.user_id, 5);
        assert_eq!(found.device_id, device_id);

        assert_eq!(device_for_credential(&conn, CredentialKind::Bearer, "sess-xyz").expect("wrong kind"), None);
    }

    #[test]
    fn set_device_display_name_updates_only_the_named_device() {
        let conn = test_conn();
        let d1 = create_device(&conn, 1, CredentialKind::Bearer, "a", T0).expect("d1");
        let d2 = create_device(&conn, 1, CredentialKind::Bearer, "b", T0).expect("d2");

        assert!(set_device_display_name(&conn, 1, &d1, Some("My Phone")).expect("set"));
        assert!(!set_device_display_name(&conn, 1, "nonexistent", Some("x")).expect("missing device is a no-op returning false"));

        let devices = list_devices(&conn, 1).expect("list");
        assert_eq!(devices.len(), 2);
        let named = devices.iter().find(|d| d.device_id == d1).expect("d1 present");
        assert_eq!(named.display_name.as_deref(), Some("My Phone"));
        let unnamed = devices.iter().find(|d| d.device_id == d2).expect("d2 present");
        assert_eq!(unnamed.display_name, None);
    }

    #[test]
    fn devices_for_reaper_lists_every_device_with_its_credential() {
        let conn = test_conn();
        create_device(&conn, 1, CredentialKind::Bearer, "tok-1", T0).expect("d1");
        create_device(&conn, 2, CredentialKind::Web, "sess-2", T0).expect("d2");

        let mut all = devices_for_reaper(&conn).expect("reaper list");
        all.sort_by_key(|(user_id, ..)| *user_id);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].0, 1);
        assert_eq!(all[0].2, CredentialKind::Bearer);
        assert_eq!(all[0].3, "tok-1");
        assert_eq!(all[1].0, 2);
        assert_eq!(all[1].2, CredentialKind::Web);
    }

    #[test]
    fn count_one_time_keys_groups_by_algorithm() {
        let mut conn = test_conn();
        add_one_time_keys(
            &mut conn,
            1,
            "DEV1",
            &[
                ("signed_curve25519:A".to_string(), "signed_curve25519".to_string(), "{}".to_string()),
                ("signed_curve25519:B".to_string(), "signed_curve25519".to_string(), "{}".to_string()),
                ("other_algo:C".to_string(), "other_algo".to_string(), "{}".to_string()),
            ],
        )
        .expect("add");

        let counts = count_one_time_keys(&conn, 1, "DEV1").expect("count");
        assert_eq!(counts.get("signed_curve25519"), Some(&2));
        assert_eq!(counts.get("other_algo"), Some(&1));
    }

    #[test]
    fn cross_signing_upsert_round_trips_and_logs_a_device_list_change() {
        let mut conn = test_conn();
        let before = count_device_list_changes(&conn, 1);
        upsert_cross_signing_key(&mut conn, 1, CrossSigningUsage::Master, r#"{"keys":{}}"#, T0).expect("master");
        upsert_cross_signing_key(&mut conn, 1, CrossSigningUsage::SelfSigning, r#"{"keys":{}}"#, T0).expect("self signing");

        let after = count_device_list_changes(&conn, 1);
        assert_eq!(after, before + 2);

        let keys = cross_signing_keys_for(&conn, &[1]).expect("query");
        assert_eq!(keys.len(), 2);
        assert!(keys.iter().any(|k| k.usage == CrossSigningUsage::Master));
        assert!(keys.iter().any(|k| k.usage == CrossSigningUsage::SelfSigning));

        assert_eq!(cross_signing_keys_for(&conn, &[]).expect("empty input"), Vec::new());
    }

    #[test]
    fn add_signatures_and_signatures_for_round_trip() {
        let mut conn = test_conn();
        add_signatures(&mut conn, &[(1, 2, "DEVICEX".to_string(), r#"{"sig":"abc"}"#.to_string(), T0.to_string())]).expect("add");

        let sigs = signatures_for(&conn, 2, "DEVICEX").expect("query");
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].signer_user_id, 1);
        assert_eq!(sigs[0].signature_json, r#"{"sig":"abc"}"#);

        assert!(signatures_for(&conn, 2, "OTHER").expect("no match").is_empty());
    }

    #[test]
    fn backup_version_lifecycle_create_get_update_delete() {
        let conn = test_conn();
        let version = create_backup_version(&conn, 1, "m.megolm_backup.v1", r#"{"a":1}"#, T0).expect("create");

        assert_eq!(current_backup_version(&conn, 1).expect("current").expect("row").version, version);

        assert!(update_backup_version_auth_data(&conn, 1, version, r#"{"a":2}"#).expect("update"));
        let updated = get_backup_version(&conn, 1, version).expect("get").expect("row");
        assert_eq!(updated.auth_data, r#"{"a":2}"#);
        assert_eq!(updated.etag, 1);

        assert!(delete_backup_version(&conn, 1, version).expect("delete"));
        assert_eq!(current_backup_version(&conn, 1).expect("current after delete"), None);
        assert!(!delete_backup_version(&conn, 1, version).expect("second delete is a no-op"));
    }

    #[test]
    fn backup_sessions_put_get_delete_and_etag_bumps() {
        let mut conn = test_conn();
        let version = create_backup_version(&conn, 1, "m.megolm_backup.v1", "{}", T0).expect("create");

        put_backup_sessions(
            &mut conn,
            1,
            version,
            &[
                ("!room1:x".to_string(), "sessA".to_string(), r#"{"d":1}"#.to_string()),
                ("!room1:x".to_string(), "sessB".to_string(), r#"{"d":2}"#.to_string()),
                ("!room2:x".to_string(), "sessC".to_string(), r#"{"d":3}"#.to_string()),
            ],
            T0,
        )
        .expect("put");

        let (count, etag_after_put) = backup_count_and_etag(&conn, 1, version).expect("count+etag");
        assert_eq!(count, 3);
        assert_eq!(etag_after_put, 1);

        let room1_sessions = get_backup_sessions(&conn, 1, version, Some("!room1:x"), None).expect("room1");
        assert_eq!(room1_sessions.len(), 2);

        let one = get_backup_sessions(&conn, 1, version, Some("!room1:x"), Some("sessA")).expect("one");
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].session_data, r#"{"d":1}"#);

        let deleted = delete_backup_sessions(&mut conn, 1, version, Some("!room1:x"), None).expect("delete room1");
        assert_eq!(deleted, 2);
        let (count_after, etag_after_delete) = backup_count_and_etag(&conn, 1, version).expect("count+etag after delete");
        assert_eq!(count_after, 1);
        assert_eq!(etag_after_delete, 2);
    }

    #[test]
    fn device_list_changes_between_is_distinct_and_bounded() {
        let mut conn = test_conn();
        log_device_list_change(&mut conn, 1, T0).expect("change 1");
        let boundary = matrix_store::max_stream_id(&conn).expect("boundary");
        log_device_list_change(&mut conn, 1, T0).expect("change 2 for the same user");
        log_device_list_change(&mut conn, 2, T0).expect("change for a different user");

        let mut changed = device_list_changes_between(&conn, boundary, matrix_store::max_stream_id(&conn).expect("max")).expect("query");
        changed.sort();
        assert_eq!(changed, vec![1, 2]);
    }

    #[test]
    fn enqueue_to_device_fans_out_and_is_scoped_to_the_recipient_device() {
        let mut conn = test_conn();
        let last = enqueue_to_device(
            &mut conn,
            9,
            &[
                (1, "DEV1".to_string(), "m.room_key".to_string(), r#"{"k":1}"#.to_string()),
                (1, "DEV2".to_string(), "m.room_key".to_string(), r#"{"k":1}"#.to_string()),
            ],
        )
        .expect("enqueue");
        assert_eq!(matrix_store::max_stream_id(&conn).expect("max"), last);

        let for_dev1 = to_device_for(&conn, 1, "DEV1", 0, 10).expect("dev1");
        assert_eq!(for_dev1.len(), 1);
        let for_dev2 = to_device_for(&conn, 1, "DEV2", 0, 10).expect("dev2");
        assert_eq!(for_dev2.len(), 1);
        assert_ne!(for_dev1[0].stream_id, for_dev2[0].stream_id);

        let empty_batch = enqueue_to_device(&mut conn, 9, &[]).expect("empty batch is a no-op");
        assert_eq!(empty_batch, last, "an empty batch must not mint a fresh stream id");
    }
}

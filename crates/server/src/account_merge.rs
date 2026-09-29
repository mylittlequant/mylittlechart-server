//! Admin account merge — fold a duplicate account (`from`) into its
//! survivor (`into`), one person's several OAuth-identity accounts becoming
//! one (docs/mlc/plans/identity-merge-2026-09-09.md decisions 4-6; the exact
//! per-table playbook and merge order are
//! docs/mlc/research/identity-merge-inventory-2026-09-09.md §1/§5/§6).
//!
//! [`plan`] computes the summary a merge would produce — row counts per
//! table, hard conflicts, hot-plane files that would move or collide — and
//! writes nothing. [`execute`] performs the real merge: a `social.db`
//! transaction, then an `identity.db` transaction (ending in `DELETE FROM
//! users WHERE id = from` — "the point of no return"), then the hot-plane
//! filesystem move outside any transaction, then the `account_merges` audit
//! row.
//!
//! **Lock discipline**: `db` (identity) and `social` are two independently
//! lockable `Mutex<Connection>`s (see `state.rs`'s `ControlPlane`), and
//! `social_db.rs`'s module doc establishes a hard rule for this whole
//! codebase — never hold both locked at the same instant, since two call
//! sites locking them in opposite orders would deadlock. Every function
//! below that touches a database takes exactly ONE `&Connection`; [`plan`]
//! and [`execute`] are the only functions that see both `Mutex`es, and each
//! locks one, finishes every read/write it needs on it, and drops the guard
//! before ever locking the other — never both alive at once, same discipline
//! `routes::forum_v2::resolve_caller_classes` already documents.
//!
//! Hard conflicts (a `vault`/`recovery_key`/`salt` singleton or a
//! `sync_e2e_params` row held by BOTH accounts for the same key, or both
//! accounts holding a `dm_identity_keys` row) cannot be resolved by a
//! mechanical rule — the server never holds a key that could merge two
//! independently-encrypted containers (see the inventory's §5). `execute`
//! refuses with [`MergeError::Conflicts`] unless the caller's `keep_vault`
//! names which side survives; the loser's conflicting rows are archived to
//! `<data_dir>/merge-archive/<from>-into-<into>-<ts>.json` before deletion —
//! the server cannot decrypt them, but the person can, client-side, from
//! that export.

use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;

use crate::dm_db;
use crate::social_db::{self, Role};
use crate::syncstore::{self, SyncStore};

// ============================================================================
// Types
// ============================================================================

/// Which side of a hard conflict survives — the `keep_vault` field of
/// `POST /api/admin/users/merge`'s body. `None` (the default) means no
/// conflict may be resolved automatically: `execute` refuses with 409
/// instead of guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepVault {
    Into,
    From,
}

impl KeepVault {
    pub fn from_wire(s: &str) -> Option<KeepVault> {
        match s {
            "into" => Some(KeepVault::Into),
            "from" => Some(KeepVault::From),
            _ => None,
        }
    }
}

/// One hard conflict `execute` refuses to resolve without an explicit
/// `keep_vault` — see this module's doc comment. Structured, not a bare
/// string, so `CICD/mlc/scripts/account-merge.py` can act on `kind` rather
/// than parse prose.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(tag = "kind")]
pub enum Conflict {
    #[serde(rename = "sync_items")]
    SyncItem {
        category: String,
        device_id: String,
        profile_id: String,
        sync_id: String,
    },
    #[serde(rename = "sync_e2e_params")]
    E2eParams { profile_id: String },
    #[serde(rename = "dm_identity_key")]
    DmIdentityKey,
}

/// Why [`plan`]/[`execute`] refused before writing anything (or, for
/// [`execute`], after already committing the `social.db` transaction but
/// before `identity.db`'s begins — see this module's doc comment on why a
/// failure there is safe to retry: every identity.db step is either a plain
/// idempotent `UPDATE` or a checked `INSERT OR IGNORE`).
#[derive(Debug)]
pub enum MergeError {
    /// `from == into`.
    SameUser,
    /// `from` or `into` names no existing account.
    UserNotFound { side: &'static str, user_id: i64 },
    /// `from` or `into` is an anonymous (numbered) account: it has no OAuth
    /// identity and takes none, so it is never merged with, or into, another
    /// account.
    AnonymousAccount { side: &'static str, user_id: i64 },
    /// Hard conflicts exist and no `keep_vault` was given to resolve them —
    /// `execute` only; `plan` reports conflicts in its summary instead.
    Conflicts(Vec<Conflict>),
    Db(rusqlite::Error),
    Io(std::io::Error),
    Serde(serde_json::Error),
}

impl From<rusqlite::Error> for MergeError {
    fn from(e: rusqlite::Error) -> Self {
        MergeError::Db(e)
    }
}
impl From<std::io::Error> for MergeError {
    fn from(e: std::io::Error) -> Self {
        MergeError::Io(e)
    }
}
impl From<serde_json::Error> for MergeError {
    fn from(e: serde_json::Error) -> Self {
        MergeError::Serde(e)
    }
}

/// The result of [`plan`] (nothing written, `dry_run: true`) or [`execute`]
/// (everything below already committed, `dry_run: false`) — same shape
/// either way, so a dry run and the real merge it predicts are directly
/// comparable. `counts` is keyed by table name and reports how many of
/// `from`'s rows the merge touches — `dm_conversations` is split by outcome
/// (`dm_conversations_dropped_self`/`_merged_into_existing_peer`/
/// `_repointed`) and `object_grants` by column
/// (`object_grants_owner`/`_grantee`), since the row count alone would not
/// say what happened to it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MergeSummary {
    pub from_user_id: i64,
    pub into_user_id: i64,
    pub dry_run: bool,
    pub conflicts: Vec<Conflict>,
    pub counts: std::collections::BTreeMap<String, i64>,
    pub hot_files_moved: usize,
    pub hot_files_archived: usize,
}

/// The loser's conflicting rows, captured before deletion — written to
/// `<data_dir>/merge-archive/<from>-into-<into>-<ts>.json` (decision 5). The
/// server holds no key that could decrypt any of this; it exists purely so
/// the person can recover it client-side.
#[derive(Debug, Default, serde::Serialize)]
struct ArchivedConflictData {
    from_user_id: i64,
    into_user_id: i64,
    keep_vault: Option<&'static str>,
    ts: String,
    sync_items: Vec<serde_json::Value>,
    sync_e2e_params: Vec<serde_json::Value>,
    dm_identity_keys: Vec<serde_json::Value>,
}

// ============================================================================
// plan — read-only
// ============================================================================

/// Compute the summary [`execute`] would produce for `(from, into)` without
/// writing anything — row counts per table, hard conflicts, hot-plane files
/// that would move or collide. `keep_vault` plays no role here: a dry run
/// reports what exists, not what a chosen resolution would do to it.
///
/// Locks `db` first, does every identity-side read, drops that guard, then
/// locks `social` — never both at once (see this module's doc comment).
pub fn plan(
    db: &Mutex<Connection>,
    social: &Mutex<Connection>,
    store: &SyncStore,
    from: i64,
    into: i64,
) -> Result<MergeSummary, MergeError> {
    let (identity_conflicts, mut counts) = {
        let identity_conn = db.lock().unwrap_or_else(|e| e.into_inner());
        validate_pair(&identity_conn, from, into)?;
        let conflicts = find_identity_conflicts(&identity_conn, from, into)?;
        let counts = count_identity(&identity_conn, from)?;
        (conflicts, counts)
    };

    let (social_conflict, social_counts) = {
        let social_conn = social.lock().unwrap_or_else(|e| e.into_inner());
        let conflict = find_social_conflict(&social_conn, from, into)?;
        let counts = count_social(&social_conn, from, into)?;
        (conflict, counts)
    };

    let mut conflicts = identity_conflicts;
    conflicts.extend(social_conflict);
    counts.insert("users".to_string(), 1);
    counts.extend(social_counts);

    let hot = syncstore::preview_merge_user_into(store, from, into)?;

    Ok(MergeSummary {
        from_user_id: from,
        into_user_id: into,
        dry_run: true,
        conflicts,
        counts,
        hot_files_moved: hot.moved,
        hot_files_archived: hot.archived,
    })
}

// ============================================================================
// execute — the real merge
// ============================================================================

/// Fold `from` into `into` for real — see this module's doc comment for the
/// exact order, and for the lock discipline every phase below follows.
/// Refuses with [`MergeError::Conflicts`] if a hard conflict exists and
/// `keep_vault` is `None`; a colliding hot-plane file is never a hard
/// conflict (decision 4 says "archive it", not "refuse the merge") and needs
/// no `keep_vault` at all.
pub fn execute(
    db: &Mutex<Connection>,
    social: &Mutex<Connection>,
    store: &SyncStore,
    data_dir: &Path,
    from: i64,
    into: i64,
    keep_vault: Option<KeepVault>,
) -> Result<MergeSummary, MergeError> {
    // --- phase 0: validate, gather conflicts + counts (read-only) ---
    let (identity_conflicts, mut counts) = {
        let identity_conn = db.lock().unwrap_or_else(|e| e.into_inner());
        validate_pair(&identity_conn, from, into)?;
        let conflicts = find_identity_conflicts(&identity_conn, from, into)?;
        let counts = count_identity(&identity_conn, from)?;
        (conflicts, counts)
    };
    let (social_conflict, social_counts) = {
        let social_conn = social.lock().unwrap_or_else(|e| e.into_inner());
        let conflict = find_social_conflict(&social_conn, from, into)?;
        let counts = count_social(&social_conn, from, into)?;
        (conflict, counts)
    };

    let mut conflicts = identity_conflicts;
    conflicts.extend(social_conflict);
    if !conflicts.is_empty() && keep_vault.is_none() {
        return Err(MergeError::Conflicts(conflicts));
    }
    counts.insert("users".to_string(), 1);
    counts.extend(social_counts);

    let now = chrono::Utc::now();
    let now_str = now.to_rfc3339();
    // Filesystem-safe timestamp (RFC3339 has `:` — invalid in a Windows path
    // component) for both the archive subdirectory and the archive JSON's name.
    let ts = now.format("%Y%m%dT%H%M%S%.3fZ").to_string();
    let archive_stub = format!("{from}-into-{into}-{ts}");
    let mut archive = ArchivedConflictData {
        from_user_id: from,
        into_user_id: into,
        keep_vault: keep_vault.map(|k| match k {
            KeepVault::Into => "into",
            KeepVault::From => "from",
        }),
        ts: now_str.clone(),
        ..Default::default()
    };

    // --- phase 1: social.db transaction ---
    {
        let social_conn = social.lock().unwrap_or_else(|e| e.into_inner());
        run_transaction(&social_conn, |conn| apply_social_merge(conn, from, into, keep_vault, &mut archive))?;
    }

    // --- phase 2: identity.db transaction — ends with the point of no return ---
    {
        let identity_conn = db.lock().unwrap_or_else(|e| e.into_inner());
        run_transaction(&identity_conn, |conn| apply_identity_merge(conn, from, into, keep_vault, &mut archive))?;
    }

    // --- phase 3: filesystem, outside any transaction and any lock (decision 4) ---
    let archive_files_dir = data_dir.join("merge-archive").join(&archive_stub);
    let hot = syncstore::merge_user_into(store, from, into, &archive_files_dir)?;

    // Archive JSON for the loser's conflicting rows, only if any exist.
    if !archive.sync_items.is_empty()
        || !archive.sync_e2e_params.is_empty()
        || !archive.dm_identity_keys.is_empty()
    {
        let archive_dir = data_dir.join("merge-archive");
        std::fs::create_dir_all(&archive_dir)?;
        let archive_json_path = archive_dir.join(format!("{archive_stub}.json"));
        std::fs::write(&archive_json_path, serde_json::to_vec_pretty(&archive)?)?;
    }

    let summary = MergeSummary {
        from_user_id: from,
        into_user_id: into,
        dry_run: false,
        conflicts,
        counts,
        hot_files_moved: hot.moved,
        hot_files_archived: hot.archived,
    };

    // --- phase 4: audit row, now that the real hot-plane counts are known ---
    // Nothing above requires this row to exist, so writing it after every
    // other step (rather than inside the identity.db transaction) costs
    // nothing and gives the operator the true final numbers instead of a
    // pre-filesystem-move prediction.
    {
        let identity_conn = db.lock().unwrap_or_else(|e| e.into_inner());
        identity_conn.execute(
            "INSERT INTO account_merges (from_user_id, into_user_id, ts, summary_json) VALUES (?1, ?2, ?3, ?4)",
            params![from, into, now_str, serde_json::to_string(&summary)?],
        )?;
    }

    Ok(summary)
}

/// The `social.db` transaction body — every step keyed by `WHERE user_id =
/// from` (or, for `dm_conversations`, `user_lo = from OR user_hi = from`),
/// so a `from` that has already been fully migrated here (a retried merge
/// after `identity.db`'s transaction failed on a previous attempt — see this
/// module's doc comment) finds nothing left to touch and every statement
/// below is a safe no-op.
fn apply_social_merge(
    conn: &Connection,
    from: i64,
    into: i64,
    keep_vault: Option<KeepVault>,
    archive: &mut ArchivedConflictData,
) -> rusqlite::Result<()> {
    merge_forum_roles(conn, from, into)?;
    merge_forum_trusted(conn, from, into)?;
    conn.execute(
        "UPDATE forum_threads_v2 SET author_user_id = ?1 WHERE author_user_id = ?2",
        params![into, from],
    )?;
    conn.execute(
        "UPDATE forum_replies_v2 SET author_user_id = ?1 WHERE author_user_id = ?2",
        params![into, from],
    )?;
    merge_dm_identity_key(conn, from, into, keep_vault, archive)?;
    merge_dm_conversations(conn, from, into)?;
    conn.execute(
        "UPDATE dm_messages SET sender_user_id = ?1 WHERE sender_user_id = ?2",
        params![into, from],
    )?;
    Ok(())
}

/// The `identity.db` transaction body — ends with the point of no return
/// (`DELETE FROM users WHERE id = from`). Every step above that delete is
/// the same idempotent-by-construction shape `apply_social_merge` is.
fn apply_identity_merge(
    conn: &Connection,
    from: i64,
    into: i64,
    keep_vault: Option<KeepVault>,
    archive: &mut ArchivedConflictData,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE user_providers SET user_id = ?1 WHERE user_id = ?2",
        params![into, from],
    )?;
    conn.execute(
        "UPDATE auth_tokens SET user_id = ?1 WHERE user_id = ?2",
        params![into, from],
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO device_users (device_id, user_id, linked_at)
         SELECT device_id, ?1, linked_at FROM device_users WHERE user_id = ?2",
        params![into, from],
    )?;
    conn.execute("DELETE FROM device_users WHERE user_id = ?1", params![from])?;
    conn.execute(
        "UPDATE web_sessions SET user_id = ?1 WHERE user_id = ?2",
        params![into, from],
    )?;
    merge_sync_items(conn, from, into, keep_vault, archive)?;
    merge_sync_e2e_params(conn, from, into, keep_vault, archive)?;
    conn.execute(
        "UPDATE gift_codes SET redeemed_by = ?1 WHERE redeemed_by = ?2",
        params![into, from],
    )?;
    conn.execute(
        "UPDATE share_links SET user_id = ?1 WHERE user_id = ?2",
        params![into, from],
    )?;
    conn.execute(
        "UPDATE object_grants SET owner_user_id = ?1 WHERE owner_user_id = ?2",
        params![into, from],
    )?;
    conn.execute(
        "UPDATE object_grants SET grantee_user_id = ?1 WHERE grantee_user_id = ?2",
        params![into, from],
    )?;
    conn.execute(
        "UPDATE published_indicators SET owner_user_id = ?1 WHERE owner_user_id = ?2",
        params![into, from],
    )?;
    conn.execute(
        "UPDATE indicator_grants SET grantee_user_id = ?1 WHERE grantee_user_id = ?2",
        params![into, from],
    )?;
    conn.execute(
        "UPDATE forum_threads SET author_user_id = ?1 WHERE author_user_id = ?2",
        params![into, from],
    )?;
    conn.execute(
        "UPDATE forum_replies SET author_user_id = ?1 WHERE author_user_id = ?2",
        params![into, from],
    )?;
    merge_paid_until_and_nick(conn, from, into)?;
    // dig2pay billing: entitlements OR-ed / later quant period kept / credit
    // summed, and the subscription, invoice and event rows re-pointed so the
    // purchases (and their refunds) follow the surviving account.
    crate::billing::store::merge_user(conn, from, into)?;
    conn.execute("DELETE FROM users WHERE id = ?1", params![from])?;
    Ok(())
}

/// Run `body` inside `BEGIN IMMEDIATE ... COMMIT`, rolling back on any error.
fn run_transaction<F>(conn: &Connection, body: F) -> Result<(), MergeError>
where
    F: FnOnce(&Connection) -> rusqlite::Result<()>,
{
    conn.execute_batch("BEGIN IMMEDIATE;")?;
    match body(conn) {
        Ok(()) => {
            conn.execute_batch("COMMIT;")?;
            Ok(())
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(MergeError::Db(e))
        }
    }
}

// ============================================================================
// Validation
// ============================================================================

fn validate_pair(identity_conn: &Connection, from: i64, into: i64) -> Result<(), MergeError> {
    if from == into {
        return Err(MergeError::SameUser);
    }
    if !user_exists(identity_conn, from)? {
        return Err(MergeError::UserNotFound { side: "from", user_id: from });
    }
    if !user_exists(identity_conn, into)? {
        return Err(MergeError::UserNotFound { side: "into", user_id: into });
    }
    for (side, user_id) in [("from", from), ("into", into)] {
        if crate::billing::anon::is_anonymous(identity_conn, user_id)? {
            return Err(MergeError::AnonymousAccount { side, user_id });
        }
    }
    Ok(())
}

fn user_exists(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(conn
        .query_row("SELECT 1 FROM users WHERE id = ?1", params![id], |_| Ok(()))
        .optional()?
        .is_some())
}

// ============================================================================
// Conflict detection (shared by plan and execute) — split by database so
// each half needs only the one connection it locks.
// ============================================================================

fn find_identity_conflicts(identity_conn: &Connection, from: i64, into: i64) -> rusqlite::Result<Vec<Conflict>> {
    let mut conflicts = Vec::new();

    {
        let mut stmt = identity_conn.prepare(
            "SELECT device_id, profile_id, sync_id, category FROM sync_items WHERE user_id = ?1",
        )?;
        let rows = stmt
            .query_map(params![from], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (device_id, profile_id, sync_id, category) in rows {
            let exists: bool = identity_conn
                .query_row(
                    "SELECT 1 FROM sync_items WHERE user_id = ?1 AND device_id = ?2 AND profile_id = ?3 AND sync_id = ?4",
                    params![into, device_id, profile_id, sync_id],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if exists {
                conflicts.push(Conflict::SyncItem { category, device_id, profile_id, sync_id });
            }
        }
    }

    {
        let mut stmt = identity_conn.prepare("SELECT profile_id FROM sync_e2e_params WHERE user_id = ?1")?;
        let profile_ids = stmt
            .query_map(params![from], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for profile_id in profile_ids {
            let exists: bool = identity_conn
                .query_row(
                    "SELECT 1 FROM sync_e2e_params WHERE user_id = ?1 AND profile_id = ?2",
                    params![into, profile_id],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if exists {
                conflicts.push(Conflict::E2eParams { profile_id });
            }
        }
    }

    Ok(conflicts)
}

fn find_social_conflict(social_conn: &Connection, from: i64, into: i64) -> rusqlite::Result<Option<Conflict>> {
    let from_has = identity_key_exists(social_conn, from)?;
    let into_has = identity_key_exists(social_conn, into)?;
    Ok((from_has && into_has).then_some(Conflict::DmIdentityKey))
}

fn identity_key_exists(social_conn: &Connection, user_id: i64) -> rusqlite::Result<bool> {
    Ok(social_conn
        .query_row("SELECT 1 FROM dm_identity_keys WHERE user_id = ?1", params![user_id], |_| Ok(()))
        .optional()?
        .is_some())
}

// ============================================================================
// Counting (shared by plan and execute) — split by database, same reason.
// ============================================================================

fn count_where(conn: &Connection, table: &str, column: &str, value: i64) -> rusqlite::Result<i64> {
    conn.query_row(
        &format!("SELECT COUNT(*) FROM {table} WHERE {column} = ?1"),
        params![value],
        |row| row.get(0),
    )
}

fn count_identity(identity_conn: &Connection, from: i64) -> rusqlite::Result<std::collections::BTreeMap<String, i64>> {
    let mut counts = std::collections::BTreeMap::new();
    counts.insert("user_providers".to_string(), count_where(identity_conn, "user_providers", "user_id", from)?);
    counts.insert("auth_tokens".to_string(), count_where(identity_conn, "auth_tokens", "user_id", from)?);
    counts.insert("device_users".to_string(), count_where(identity_conn, "device_users", "user_id", from)?);
    counts.insert("web_sessions".to_string(), count_where(identity_conn, "web_sessions", "user_id", from)?);
    counts.insert("sync_items".to_string(), count_where(identity_conn, "sync_items", "user_id", from)?);
    counts.insert("sync_e2e_params".to_string(), count_where(identity_conn, "sync_e2e_params", "user_id", from)?);
    counts.insert("gift_codes".to_string(), count_where(identity_conn, "gift_codes", "redeemed_by", from)?);
    counts.insert("share_links".to_string(), count_where(identity_conn, "share_links", "user_id", from)?);
    counts.insert(
        "object_grants_owner".to_string(),
        count_where(identity_conn, "object_grants", "owner_user_id", from)?,
    );
    counts.insert(
        "object_grants_grantee".to_string(),
        count_where(identity_conn, "object_grants", "grantee_user_id", from)?,
    );
    counts.insert(
        "published_indicators".to_string(),
        count_where(identity_conn, "published_indicators", "owner_user_id", from)?,
    );
    counts.insert(
        "indicator_grants".to_string(),
        count_where(identity_conn, "indicator_grants", "grantee_user_id", from)?,
    );
    counts.insert("forum_threads".to_string(), count_where(identity_conn, "forum_threads", "author_user_id", from)?);
    counts.insert("forum_replies".to_string(), count_where(identity_conn, "forum_replies", "author_user_id", from)?);
    Ok(counts)
}

/// How `from`'s `dm_conversations` rows classify under
/// [`merge_dm_conversations`]'s three-way rule — computed the same way that
/// function walks them, but read-only.
struct DmConversationPlan {
    dropped_self: i64,
    merged_into_existing_peer: i64,
    repointed: i64,
}

fn classify_dm_conversations(social_conn: &Connection, from: i64, into: i64) -> rusqlite::Result<DmConversationPlan> {
    let mut stmt = social_conn.prepare(
        "SELECT user_lo, user_hi FROM dm_conversations WHERE user_lo = ?1 OR user_hi = ?1",
    )?;
    let rows = stmt
        .query_map(params![from], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let mut result = DmConversationPlan { dropped_self: 0, merged_into_existing_peer: 0, repointed: 0 };
    for (lo, hi) in rows {
        let peer = if lo == from { hi } else { lo };
        if peer == into {
            result.dropped_self += 1;
            continue;
        }
        let (plo, phi) = dm_db::ordered_pair(into, peer);
        let exists: bool = social_conn
            .query_row(
                "SELECT 1 FROM dm_conversations WHERE user_lo = ?1 AND user_hi = ?2",
                params![plo, phi],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if exists {
            result.merged_into_existing_peer += 1;
        } else {
            result.repointed += 1;
        }
    }
    Ok(result)
}

fn count_social(social_conn: &Connection, from: i64, into: i64) -> rusqlite::Result<std::collections::BTreeMap<String, i64>> {
    let mut counts = std::collections::BTreeMap::new();
    counts.insert("forum_roles".to_string(), count_where(social_conn, "forum_roles", "user_id", from)?);
    counts.insert("forum_trusted".to_string(), count_where(social_conn, "forum_trusted", "user_id", from)?);
    counts.insert(
        "forum_threads_v2".to_string(),
        count_where(social_conn, "forum_threads_v2", "author_user_id", from)?,
    );
    counts.insert(
        "forum_replies_v2".to_string(),
        count_where(social_conn, "forum_replies_v2", "author_user_id", from)?,
    );
    counts.insert("dm_identity_keys".to_string(), count_where(social_conn, "dm_identity_keys", "user_id", from)?);

    let dm_plan = classify_dm_conversations(social_conn, from, into)?;
    counts.insert("dm_conversations_dropped_self".to_string(), dm_plan.dropped_self);
    counts.insert("dm_conversations_merged_into_existing_peer".to_string(), dm_plan.merged_into_existing_peer);
    counts.insert("dm_conversations_repointed".to_string(), dm_plan.repointed);
    counts.insert("dm_messages".to_string(), count_where(social_conn, "dm_messages", "sender_user_id", from)?);
    Ok(counts)
}

// ============================================================================
// social.db mutations
// ============================================================================

fn role_rank(role: Role) -> u8 {
    match role {
        Role::Moderator => social_db::Class::Moderator.rank(),
        Role::Admin => social_db::Class::Admin.rank(),
    }
}

/// Dedupe `forum_roles` by rank: the higher of the two survives on `into`.
fn merge_forum_roles(social_conn: &Connection, from: i64, into: i64) -> rusqlite::Result<()> {
    if let Some(from_role) = social_db::role_for_user(social_conn, from)? {
        let into_role = social_db::role_for_user(social_conn, into)?;
        let keep = match into_role {
            Some(existing) if role_rank(existing) >= role_rank(from_role) => existing,
            _ => from_role,
        };
        social_db::set_role(social_conn, into, keep, &chrono::Utc::now().to_rfc3339())?;
    }
    social_conn.execute("DELETE FROM forum_roles WHERE user_id = ?1", params![from])?;
    Ok(())
}

/// Dedupe `forum_trusted` by union: if EITHER account holds a row, `into`
/// ends up trusted. `into`'s own row (if any) is left exactly as-is —
/// `from`'s `granted_at`/`note` are only copied over when `into` had none.
fn merge_forum_trusted(social_conn: &Connection, from: i64, into: i64) -> rusqlite::Result<()> {
    if !social_db::is_trusted(social_conn, into)? {
        let from_row: Option<(String, Option<String>)> = social_conn
            .query_row(
                "SELECT granted_at, note FROM forum_trusted WHERE user_id = ?1",
                params![from],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((granted_at, note)) = from_row {
            social_db::set_trusted(social_conn, into, note.as_deref(), &granted_at)?;
        }
    }
    social_conn.execute("DELETE FROM forum_trusted WHERE user_id = ?1", params![from])?;
    Ok(())
}

fn fetch_identity_key_json(social_conn: &Connection, user_id: i64) -> rusqlite::Result<Option<serde_json::Value>> {
    social_conn
        .query_row(
            "SELECT public_key, fingerprint, created_at, rotated_at FROM dm_identity_keys WHERE user_id = ?1",
            params![user_id],
            |row| {
                let public_key: Vec<u8> = row.get(0)?;
                Ok(serde_json::json!({
                    "user_id": user_id,
                    "public_key_hex": hex::encode(public_key),
                    "fingerprint": row.get::<_, String>(1)?,
                    "created_at": row.get::<_, String>(2)?,
                    "rotated_at": row.get::<_, Option<String>>(3)?,
                }))
            },
        )
        .optional()
}

/// MOVE if only `from` published a DM identity key; if only `into` did,
/// nothing to do; if BOTH did, this is a hard conflict already gated by
/// `execute` — a `None` `keep_vault` reaching the "both hold a key" arm
/// cannot happen in practice (it is a no-op there rather than a panic, since
/// this function has no way to re-refuse once called).
fn merge_dm_identity_key(
    social_conn: &Connection,
    from: i64,
    into: i64,
    keep_vault: Option<KeepVault>,
    archive: &mut ArchivedConflictData,
) -> rusqlite::Result<()> {
    let from_key = fetch_identity_key_json(social_conn, from)?;
    let into_key = fetch_identity_key_json(social_conn, into)?;
    match (from_key, into_key) {
        (Some(from_json), Some(into_json)) => match keep_vault {
            Some(KeepVault::Into) => {
                archive.dm_identity_keys.push(from_json);
                social_conn.execute("DELETE FROM dm_identity_keys WHERE user_id = ?1", params![from])?;
            }
            Some(KeepVault::From) => {
                archive.dm_identity_keys.push(into_json);
                social_conn.execute("DELETE FROM dm_identity_keys WHERE user_id = ?1", params![into])?;
                social_conn.execute(
                    "UPDATE dm_identity_keys SET user_id = ?1 WHERE user_id = ?2",
                    params![into, from],
                )?;
            }
            None => {}
        },
        (Some(_), None) => {
            social_conn.execute(
                "UPDATE dm_identity_keys SET user_id = ?1 WHERE user_id = ?2",
                params![into, from],
            )?;
        }
        (None, Some(_)) | (None, None) => {}
    }
    Ok(())
}

/// Compare two optional RFC3339 timestamps lexicographically (the same
/// convention `users.paid_until`/`share_links.expires_at` already use) and
/// return the later one — `None` only when both are `None`.
fn max_opt_timestamp(a: Option<&str>, b: Option<&str>) -> Option<String> {
    match (a, b) {
        (None, None) => None,
        (Some(x), None) => Some(x.to_string()),
        (None, Some(y)) => Some(y.to_string()),
        (Some(x), Some(y)) => Some(if x >= y { x } else { y }.to_string()),
    }
}

/// The three-way `dm_conversations` procedure (inventory §5): a conversation
/// with the survivor itself is meaningless post-merge and is dropped with
/// its messages; a conversation with a peer the survivor already talks to
/// has its messages moved into that existing row (`last_message_at` = MAX)
/// and is then dropped itself; otherwise the row is repointed to
/// `ordered_pair(into, peer)`, which cannot collide (this is exactly the "no
/// existing peer" branch). `dm_messages.sender_user_id` is reassigned by the
/// caller afterward, once every conversation row above is settled.
fn merge_dm_conversations(social_conn: &Connection, from: i64, into: i64) -> rusqlite::Result<()> {
    let mut stmt = social_conn.prepare(
        "SELECT id, user_lo, user_hi, last_message_at FROM dm_conversations WHERE user_lo = ?1 OR user_hi = ?1",
    )?;
    let rows = stmt
        .query_map(params![from], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    for (conv_id, lo, hi, last_message_at) in rows {
        let peer = if lo == from { hi } else { lo };

        if peer == into {
            social_conn.execute("DELETE FROM dm_messages WHERE conversation_id = ?1", params![conv_id])?;
            social_conn.execute("DELETE FROM dm_conversations WHERE id = ?1", params![conv_id])?;
            continue;
        }

        let (plo, phi) = dm_db::ordered_pair(into, peer);
        let survivor: Option<(i64, Option<String>)> = social_conn
            .query_row(
                "SELECT id, last_message_at FROM dm_conversations WHERE user_lo = ?1 AND user_hi = ?2",
                params![plo, phi],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        match survivor {
            Some((survivor_id, survivor_last)) => {
                social_conn.execute(
                    "UPDATE dm_messages SET conversation_id = ?1 WHERE conversation_id = ?2",
                    params![survivor_id, conv_id],
                )?;
                let merged_last = max_opt_timestamp(survivor_last.as_deref(), last_message_at.as_deref());
                social_conn.execute(
                    "UPDATE dm_conversations SET last_message_at = ?1 WHERE id = ?2",
                    params![merged_last, survivor_id],
                )?;
                social_conn.execute("DELETE FROM dm_conversations WHERE id = ?1", params![conv_id])?;
            }
            None => {
                social_conn.execute(
                    "UPDATE dm_conversations SET user_lo = ?1, user_hi = ?2 WHERE id = ?3",
                    params![plo, phi, conv_id],
                )?;
            }
        }
    }
    Ok(())
}

// ============================================================================
// identity.db mutations
// ============================================================================

/// One `sync_items` row, read generically enough to both MOVE it and, on a
/// conflict, archive it verbatim (content included) before it is dropped.
struct SyncItemRow {
    device_id: String,
    profile_id: String,
    sync_id: String,
    category: String,
    name: String,
    content: Vec<u8>,
    checksum: String,
    modified_at: i64,
    deleted: i64,
    created_at: String,
    display_name: String,
}

const SYNC_ITEM_COLUMNS: &str =
    "device_id, profile_id, sync_id, category, name, content, checksum, modified_at, deleted, created_at, display_name";

fn sync_item_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SyncItemRow> {
    Ok(SyncItemRow {
        device_id: row.get(0)?,
        profile_id: row.get(1)?,
        sync_id: row.get(2)?,
        category: row.get(3)?,
        name: row.get(4)?,
        content: row.get(5)?,
        checksum: row.get(6)?,
        modified_at: row.get(7)?,
        deleted: row.get(8)?,
        created_at: row.get(9)?,
        display_name: row.get(10)?,
    })
}

impl SyncItemRow {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "device_id": self.device_id,
            "profile_id": self.profile_id,
            "sync_id": self.sync_id,
            "category": self.category,
            "name": self.name,
            "content_hex": hex::encode(&self.content),
            "checksum": self.checksum,
            "modified_at": self.modified_at,
            "deleted": self.deleted != 0,
            "created_at": self.created_at,
            "display_name": self.display_name,
        })
    }
}

fn fetch_sync_item(
    conn: &Connection,
    user_id: i64,
    device_id: &str,
    profile_id: &str,
    sync_id: &str,
) -> rusqlite::Result<Option<SyncItemRow>> {
    conn.query_row(
        &format!(
            "SELECT {SYNC_ITEM_COLUMNS} FROM sync_items WHERE user_id = ?1 AND device_id = ?2 AND profile_id = ?3 AND sync_id = ?4"
        ),
        params![user_id, device_id, profile_id, sync_id],
        sync_item_from_row,
    )
    .optional()
}

/// Per-row MOVE with the singleton dedupe-check (inventory §1a): a row whose
/// `(device_id, profile_id, sync_id)` `into` does not already hold moves
/// freely; one it does hold is a hard conflict already gated by `execute`
/// (see [`merge_dm_identity_key`]'s doc comment for the same `None` case).
fn merge_sync_items(
    identity_conn: &Connection,
    from: i64,
    into: i64,
    keep_vault: Option<KeepVault>,
    archive: &mut ArchivedConflictData,
) -> rusqlite::Result<()> {
    let mut stmt = identity_conn.prepare(&format!("SELECT {SYNC_ITEM_COLUMNS} FROM sync_items WHERE user_id = ?1"))?;
    let rows = stmt.query_map(params![from], sync_item_from_row)?.collect::<rusqlite::Result<Vec<_>>>()?;

    for row in rows {
        let into_has = fetch_sync_item(identity_conn, into, &row.device_id, &row.profile_id, &row.sync_id)?;
        match into_has {
            Some(into_row) => match keep_vault {
                Some(KeepVault::Into) => {
                    archive.sync_items.push(row.to_json());
                    identity_conn.execute(
                        "DELETE FROM sync_items WHERE user_id = ?1 AND device_id = ?2 AND profile_id = ?3 AND sync_id = ?4",
                        params![from, row.device_id, row.profile_id, row.sync_id],
                    )?;
                }
                Some(KeepVault::From) => {
                    archive.sync_items.push(into_row.to_json());
                    identity_conn.execute(
                        "DELETE FROM sync_items WHERE user_id = ?1 AND device_id = ?2 AND profile_id = ?3 AND sync_id = ?4",
                        params![into, row.device_id, row.profile_id, row.sync_id],
                    )?;
                    identity_conn.execute(
                        "UPDATE sync_items SET user_id = ?1 WHERE user_id = ?2 AND device_id = ?3 AND profile_id = ?4 AND sync_id = ?5",
                        params![into, from, row.device_id, row.profile_id, row.sync_id],
                    )?;
                }
                None => {}
            },
            None => {
                identity_conn.execute(
                    "UPDATE sync_items SET user_id = ?1 WHERE user_id = ?2 AND device_id = ?3 AND profile_id = ?4 AND sync_id = ?5",
                    params![into, from, row.device_id, row.profile_id, row.sync_id],
                )?;
            }
        }
    }
    Ok(())
}

/// Same per-row MOVE-or-conflict shape as [`merge_sync_items`], keyed on
/// `profile_id` alone (this table's own PK shape — no `device_id`).
fn merge_sync_e2e_params(
    identity_conn: &Connection,
    from: i64,
    into: i64,
    keep_vault: Option<KeepVault>,
    archive: &mut ArchivedConflictData,
) -> rusqlite::Result<()> {
    let mut stmt = identity_conn.prepare(
        "SELECT profile_id, salt, iterations, created_at, encrypted_master_key FROM sync_e2e_params WHERE user_id = ?1",
    )?;
    let rows = stmt
        .query_map(params![from], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    for (profile_id, from_salt, from_iterations, from_created_at, from_key) in rows {
        let into_row: Option<(String, i64, String, Option<Vec<u8>>)> = identity_conn
            .query_row(
                "SELECT salt, iterations, created_at, encrypted_master_key FROM sync_e2e_params WHERE user_id = ?1 AND profile_id = ?2",
                params![into, profile_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;

        match into_row {
            Some((into_salt, into_iterations, into_created_at, into_key)) => match keep_vault {
                Some(KeepVault::Into) => {
                    archive.sync_e2e_params.push(e2e_params_json(
                        &profile_id,
                        &from_salt,
                        from_iterations,
                        &from_created_at,
                        from_key.as_deref(),
                    ));
                    identity_conn.execute(
                        "DELETE FROM sync_e2e_params WHERE user_id = ?1 AND profile_id = ?2",
                        params![from, profile_id],
                    )?;
                }
                Some(KeepVault::From) => {
                    archive.sync_e2e_params.push(e2e_params_json(
                        &profile_id,
                        &into_salt,
                        into_iterations,
                        &into_created_at,
                        into_key.as_deref(),
                    ));
                    identity_conn.execute(
                        "DELETE FROM sync_e2e_params WHERE user_id = ?1 AND profile_id = ?2",
                        params![into, profile_id],
                    )?;
                    identity_conn.execute(
                        "UPDATE sync_e2e_params SET user_id = ?1 WHERE user_id = ?2 AND profile_id = ?3",
                        params![into, from, profile_id],
                    )?;
                }
                None => {}
            },
            None => {
                identity_conn.execute(
                    "UPDATE sync_e2e_params SET user_id = ?1 WHERE user_id = ?2 AND profile_id = ?3",
                    params![into, from, profile_id],
                )?;
            }
        }
    }
    Ok(())
}

fn e2e_params_json(
    profile_id: &str,
    salt: &str,
    iterations: i64,
    created_at: &str,
    encrypted_master_key: Option<&[u8]>,
) -> serde_json::Value {
    serde_json::json!({
        "profile_id": profile_id,
        "salt": salt,
        "iterations": iterations,
        "created_at": created_at,
        "encrypted_master_key_hex": encrypted_master_key.map(hex::encode),
    })
}

/// `paid_until` extends (MAX of the two, same rule `redeem_gift_code`
/// already uses); `nick` keeps `into`'s, taking `from`'s only if `into` has
/// none. The loser's nick is cleared FIRST — `UNIQUE(LOWER(nick))` is
/// checked immediately per statement, not deferred to commit, so `into`
/// cannot briefly hold the same nick as `from`'s still-un-deleted row.
fn merge_paid_until_and_nick(identity_conn: &Connection, from: i64, into: i64) -> rusqlite::Result<()> {
    let from_nick: Option<String> =
        identity_conn.query_row("SELECT nick FROM users WHERE id = ?1", params![from], |row| row.get(0))?;
    let from_paid: Option<String> =
        identity_conn.query_row("SELECT paid_until FROM users WHERE id = ?1", params![from], |row| row.get(0))?;
    let into_nick: Option<String> =
        identity_conn.query_row("SELECT nick FROM users WHERE id = ?1", params![into], |row| row.get(0))?;
    let into_paid: Option<String> =
        identity_conn.query_row("SELECT paid_until FROM users WHERE id = ?1", params![into], |row| row.get(0))?;

    identity_conn.execute("UPDATE users SET nick = NULL WHERE id = ?1", params![from])?;

    let merged_nick = into_nick.or(from_nick);
    let merged_paid = max_opt_timestamp(into_paid.as_deref(), from_paid.as_deref());
    identity_conn.execute(
        "UPDATE users SET nick = ?1, paid_until = ?2 WHERE id = ?3",
        params![merged_nick, merged_paid, into],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    // ------------------------------------------------------------------
    // Fixtures
    // ------------------------------------------------------------------

    /// The full identity schema (users, user_providers, auth_tokens,
    /// device_users, web_sessions, sync_items, sync_e2e_params, gift_codes,
    /// share_links, object_grants, published_indicators, indicator_grants,
    /// forum_threads/replies v1, account_merges) via the real `db::init_db`
    /// — a plain in-memory `:memory:` database with a dummy 64-hex-char
    /// SQLCipher key. Setting `PRAGMA key` on a database that is never read
    /// under a different key is a harmless no-op (proven already by every
    /// other in-memory fixture in this crate, none of which sets a key at
    /// all) — using the real schema function here, rather than a hand
    /// rolled copy, is what keeps this test fixture from drifting out of
    /// sync with production's actual table shapes.
    fn identity_conn() -> Connection {
        crate::db::init_db(":memory:", &"0".repeat(64)).expect("init identity test db")
    }

    /// The full social schema (forum_roles/trusted, forum_threads_v2/
    /// replies_v2, dm_identity_keys/conversations/messages) via the same
    /// real schema functions `social_db::tests`/`dm_db::tests` use for their
    /// own fixtures.
    fn social_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        social_db::create_social_schema(&conn).expect("social schema");
        crate::dm_db::create_dm_schema(&conn).expect("dm schema");
        conn
    }

    fn now() -> String {
        chrono::Utc::now().to_rfc3339()
    }

    fn seed_user(conn: &Connection, provider: &str, provider_id: &str, display_name: &str) -> i64 {
        crate::db::upsert_user(conn, provider, provider_id, display_name, None, &now()).expect("seed user")
    }

    /// Unique temp dir per test for the hot-plane `SyncStore` and
    /// `merge-archive` writes — same pattern `syncstore.rs`'s own test
    /// module uses, duplicated here rather than shared since it is a dozen
    /// lines of test-only infrastructure with no other consumer.
    struct TestDir(PathBuf);
    static SEQ: AtomicU64 = AtomicU64::new(0);
    impl TestDir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "mlc-account-merge-test-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&p).expect("create test dir");
            Self(p)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // ------------------------------------------------------------------
    // Dedupe rules
    // ------------------------------------------------------------------

    #[test]
    fn merge_forum_roles_dedupes_by_rank_keeping_the_higher() {
        let social = social_conn();
        let now = now();
        social_db::set_role(&social, 1, Role::Moderator, &now).expect("set role");
        social_db::set_role(&social, 2, Role::Admin, &now).expect("set role");

        // `from` (moderator) folds into `into` (admin) — admin outranks, survives untouched.
        merge_forum_roles(&social, 1, 2).expect("merge");
        assert_eq!(social_db::role_for_user(&social, 2).expect("role"), Some(Role::Admin));
        assert_eq!(social_db::role_for_user(&social, 1).expect("role"), None);
    }

    #[test]
    fn merge_forum_roles_moves_when_into_has_no_role() {
        let social = social_conn();
        social_db::set_role(&social, 1, Role::Moderator, &now()).expect("set role");
        // `into` (3) holds no role at all.
        merge_forum_roles(&social, 1, 3).expect("merge");
        assert_eq!(social_db::role_for_user(&social, 3).expect("role"), Some(Role::Moderator));
    }

    #[test]
    fn merge_forum_trusted_is_a_union_not_a_rank() {
        let social = social_conn();
        let now = now();
        social_db::set_trusted(&social, 1, Some("from's note"), &now).expect("set trusted");
        merge_forum_trusted(&social, 1, 2).expect("merge");
        assert!(social_db::is_trusted(&social, 2).expect("trusted"));
        assert!(!social_db::is_trusted(&social, 1).expect("trusted"));

        // `into` already trusted with its own note — that note survives untouched.
        let social2 = social_conn();
        social_db::set_trusted(&social2, 10, Some("from's note"), &now).expect("set trusted");
        social_db::set_trusted(&social2, 20, Some("into's own note"), &now).expect("set trusted");
        merge_forum_trusted(&social2, 10, 20).expect("merge");
        let row = social_db::list_trusted(&social2)
            .expect("list")
            .into_iter()
            .find(|r| r.user_id == 20)
            .expect("into's row");
        assert_eq!(row.note.as_deref(), Some("into's own note"));
    }

    #[test]
    fn merge_paid_until_and_nick_keeps_intos_nick_and_extends_paid_until() {
        let conn = identity_conn();
        let from = seed_user(&conn, "github", "f1", "from-user");
        let into = seed_user(&conn, "google", "i1", "into-user");
        crate::db::set_nick(&conn, into, "keepme", &[]).expect("set into nick");
        crate::db::set_nick(&conn, from, "losenick", &[]).expect("set from nick");
        crate::db::set_user_paid_until(&conn, from, Some("2027-01-01T00:00:00+00:00")).expect("set paid");
        crate::db::set_user_paid_until(&conn, into, Some("2026-06-01T00:00:00+00:00")).expect("set paid");

        merge_paid_until_and_nick(&conn, from, into).expect("merge");

        let nick: Option<String> = conn.query_row("SELECT nick FROM users WHERE id = ?1", params![into], |r| r.get(0)).expect("nick");
        assert_eq!(nick.as_deref(), Some("keepme"));
        let paid: Option<String> =
            conn.query_row("SELECT paid_until FROM users WHERE id = ?1", params![into], |r| r.get(0)).expect("paid");
        // from's paid_until (2027) is later than into's (2026) — the later one wins.
        assert_eq!(paid.as_deref(), Some("2027-01-01T00:00:00+00:00"));
    }

    #[test]
    fn merge_paid_until_and_nick_takes_froms_nick_only_when_into_has_none() {
        let conn = identity_conn();
        let from = seed_user(&conn, "github", "f2", "from-user");
        let into = seed_user(&conn, "google", "i2", "into-user");
        crate::db::set_nick(&conn, from, "onlyfromhasone", &[]).expect("set from nick");

        merge_paid_until_and_nick(&conn, from, into).expect("merge");

        let nick: Option<String> = conn.query_row("SELECT nick FROM users WHERE id = ?1", params![into], |r| r.get(0)).expect("nick");
        assert_eq!(nick.as_deref(), Some("onlyfromhasone"));
    }

    #[test]
    fn device_users_move_is_pk_collision_safe() {
        let conn = identity_conn();
        let from = seed_user(&conn, "github", "f3", "from-user");
        let into = seed_user(&conn, "google", "i3", "into-user");
        let now = now();
        // The exact shape that produces duplicates: the SAME device already
        // linked to both accounts.
        crate::db::link_device_user(&conn, "shared-device", from, &now).expect("link");
        crate::db::link_device_user(&conn, "shared-device", into, &now).expect("link");
        crate::db::link_device_user(&conn, "from-only-device", from, &now).expect("link");

        conn.execute(
            "INSERT OR IGNORE INTO device_users (device_id, user_id, linked_at)
             SELECT device_id, ?1, linked_at FROM device_users WHERE user_id = ?2",
            params![into, from],
        )
        .expect("insert or ignore");
        conn.execute("DELETE FROM device_users WHERE user_id = ?1", params![from]).expect("delete");

        let rows: Vec<(String, i64)> = {
            let mut stmt = conn.prepare("SELECT device_id, user_id FROM device_users ORDER BY device_id").expect("prepare");
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).expect("query").collect::<rusqlite::Result<Vec<_>>>().expect("rows")
        };
        assert_eq!(rows, vec![("from-only-device".to_string(), into), ("shared-device".to_string(), into)]);
    }

    // ------------------------------------------------------------------
    // DM three-way
    // ------------------------------------------------------------------

    #[test]
    fn merge_dm_conversations_three_way() {
        let social = social_conn();
        let now = "2026-09-09T00:00:00+00:00";
        let from = 1;
        let into = 2;
        let peer_with_existing_into_conversation = 3;
        let peer_with_no_into_conversation = 4;

        // Case 1: self-conversation (from <-> into) — must be dropped with its messages.
        let self_conv = dm_db::get_or_create_conversation(&social, from, into, now).expect("create");
        dm_db::create_message(&social, self_conv.id, from, &[0u8; 12], b"hi", now).expect("insert");

        // Case 2: into already talks to peer 3 — from's conversation with 3
        // must be merged into that existing row.
        let into_p3 = dm_db::get_or_create_conversation(&social, into, peer_with_existing_into_conversation, now).expect("create");
        dm_db::create_message(&social, into_p3.id, into, &[0u8; 12], b"into to p3", now).expect("insert");
        let from_p3 = dm_db::get_or_create_conversation(&social, from, peer_with_existing_into_conversation, now).expect("create");
        dm_db::create_message(&social, from_p3.id, from, &[0u8; 12], b"from to p3", "2026-09-09T01:00:00+00:00").expect("insert");

        // Case 3: from talks to peer 4, into never has — plain repoint.
        let from_p4 = dm_db::get_or_create_conversation(&social, from, peer_with_no_into_conversation, now).expect("create");
        dm_db::create_message(&social, from_p4.id, from, &[0u8; 12], b"from to p4", now).expect("insert");

        merge_dm_conversations(&social, from, into).expect("merge");
        social
            .execute("UPDATE dm_messages SET sender_user_id = ?1 WHERE sender_user_id = ?2", params![into, from])
            .expect("reassign sender");

        // Case 1: gone entirely.
        assert_eq!(dm_db::get_conversation(&social, self_conv.id).expect("get"), None);
        assert_eq!(
            social.query_row("SELECT COUNT(*) FROM dm_messages WHERE conversation_id = ?1", params![self_conv.id], |r| r.get::<_, i64>(0)).expect("count"),
            0
        );

        // Case 2: from_p3's messages moved into into_p3; from_p3 itself is gone.
        assert_eq!(dm_db::get_conversation(&social, from_p3.id).expect("get"), None);
        let messages = dm_db::list_messages(&social, into_p3.id, dm_db::MessagePage::Newest, 10).expect("list");
        assert_eq!(messages.len(), 2);
        assert!(messages.iter().all(|m| m.sender_user_id == into));
        let survivor = dm_db::get_conversation(&social, into_p3.id).expect("get").expect("survives");
        assert_eq!(survivor.last_message_at.as_deref(), Some("2026-09-09T01:00:00+00:00"));

        // Case 3: repointed to (into, peer4) — same conversation id, new pair.
        let repointed = dm_db::get_conversation(&social, from_p4.id).expect("get").expect("still exists");
        assert_eq!((repointed.user_lo, repointed.user_hi), dm_db::ordered_pair(into, peer_with_no_into_conversation));
        let messages = dm_db::list_messages(&social, from_p4.id, dm_db::MessagePage::Newest, 10).expect("list");
        assert_eq!(messages[0].sender_user_id, into);
    }

    // ------------------------------------------------------------------
    // Full plan/execute integration
    // ------------------------------------------------------------------

    #[test]
    fn plan_writes_nothing() {
        let identity = identity_conn();
        let social = social_conn();
        let dir = TestDir::new();
        let store = SyncStore::new(dir.0.join("sync"));
        let db = Mutex::new(identity);
        let social_m = Mutex::new(social);

        let from = seed_user(&db.lock().expect("lock"), "github", "f4", "from-user");
        let into = seed_user(&db.lock().expect("lock"), "google", "i4", "into-user");
        {
            let conn = db.lock().expect("lock");
            conn.execute(
                "INSERT INTO auth_tokens (token_hash, user_id, created_at) VALUES ('tok', ?1, ?2)",
                params![from, now()],
            )
            .expect("insert token");
        }

        let summary = plan(&db, &social_m, &store, from, into).expect("plan");
        assert!(summary.dry_run);
        assert_eq!(summary.counts.get("auth_tokens"), Some(&1));

        // Nothing written: `from` still exists with its token, `into` untouched.
        let conn = db.lock().expect("lock");
        let from_exists: bool = conn
            .query_row("SELECT 1 FROM users WHERE id = ?1", params![from], |_| Ok(()))
            .optional()
            .expect("query")
            .is_some();
        assert!(from_exists, "dry_run must not delete the `from` row");
        let token_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM auth_tokens WHERE user_id = ?1", params![from], |r| r.get(0))
            .expect("count");
        assert_eq!(token_count, 1, "dry_run must not move auth_tokens");
    }

    #[test]
    fn execute_refuses_hard_conflict_without_keep_vault_and_archives_with_it() {
        let identity = identity_conn();
        let social = social_conn();
        let dir = TestDir::new();
        let store = SyncStore::new(dir.0.join("sync"));
        let db = Mutex::new(identity);
        let social_m = Mutex::new(social);

        let (from, into) = {
            let conn = db.lock().expect("lock");
            let from = seed_user(&conn, "github", "f5", "from-user");
            let into = seed_user(&conn, "google", "i5", "into-user");
            // Both accounts hold a `vault` singleton at the exact same
            // (device_id, profile_id) — the hard conflict.
            conn.execute(
                "INSERT INTO sync_items (user_id, device_id, profile_id, sync_id, category, name, content, checksum, modified_at, created_at)
                 VALUES (?1, 'dev', 'prof', 'vault', 'vault', 'vault.enc', X'AABB', 'chk-from', 100, ?2)",
                params![from, now()],
            ).expect("insert from vault");
            conn.execute(
                "INSERT INTO sync_items (user_id, device_id, profile_id, sync_id, category, name, content, checksum, modified_at, created_at)
                 VALUES (?1, 'dev', 'prof', 'vault', 'vault', 'vault.enc', X'CCDD', 'chk-into', 200, ?2)",
                params![into, now()],
            ).expect("insert into vault");
            (from, into)
        };

        let refused = execute(&db, &social_m, &store, &dir.0, from, into, None).expect_err("must refuse");
        match refused {
            MergeError::Conflicts(conflicts) => {
                assert_eq!(conflicts.len(), 1);
                assert!(matches!(&conflicts[0], Conflict::SyncItem { category, .. } if category == "vault"));
            }
            other => panic!("expected Conflicts, got {other:?}"),
        }
        // Refused before any transaction began — `from` is untouched.
        let from_exists: bool = db
            .lock()
            .expect("lock")
            .query_row("SELECT 1 FROM users WHERE id = ?1", params![from], |_| Ok(()))
            .optional()
            .expect("query")
            .is_some();
        assert!(from_exists);

        let summary =
            execute(&db, &social_m, &store, &dir.0, from, into, Some(KeepVault::Into)).expect("execute with keep_vault");
        assert_eq!(summary.conflicts.len(), 1);

        // `into`'s vault survives untouched; `from`'s is gone from sync_items.
        let conn = db.lock().expect("lock");
        let into_checksum: String = conn
            .query_row(
                "SELECT checksum FROM sync_items WHERE user_id = ?1 AND category = 'vault'",
                params![into],
                |r| r.get(0),
            )
            .expect("into vault");
        assert_eq!(into_checksum, "chk-into");
        let from_row_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM sync_items WHERE user_id = ?1", params![from], |r| r.get(0))
            .expect("count");
        assert_eq!(from_row_count, 0);
        let from_gone: bool = conn
            .query_row("SELECT 1 FROM users WHERE id = ?1", params![from], |_| Ok(()))
            .optional()
            .expect("query")
            .is_none();
        assert!(from_gone);
        drop(conn);

        // The loser's conflicting row was archived (not silently dropped).
        let archive_dir = dir.0.join("merge-archive");
        let archive_file = fs::read_dir(&archive_dir)
            .expect("read archive dir")
            .filter_map(|e| e.ok())
            .find(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
            .expect("one archive json file");
        let payload: serde_json::Value =
            serde_json::from_slice(&fs::read(archive_file.path()).expect("read archive")).expect("parse archive");
        let archived_items = payload["sync_items"].as_array().expect("sync_items array");
        assert_eq!(archived_items.len(), 1);
        assert_eq!(archived_items[0]["checksum"], "chk-from");
    }

    #[test]
    fn execute_retried_after_social_phase_already_applied_converges() {
        let db = Mutex::new(identity_conn());
        let social = social_conn();
        let dir = TestDir::new();
        let store = SyncStore::new(dir.0.join("sync"));

        let (from, into) = {
            let conn = db.lock().expect("lock");
            let from = seed_user(&conn, "github", "f6", "from-user");
            let into = seed_user(&conn, "google", "i6", "into-user");
            (from, into)
        };
        social_db::set_role(&social, from, Role::Moderator, &now()).expect("set role");

        // Simulate a previous attempt whose social.db transaction committed
        // but whose identity.db transaction then failed/rolled back — `from`
        // is still a real account at this point.
        let mut archive = ArchivedConflictData::default();
        apply_social_merge(&social, from, into, None, &mut archive).expect("first social pass");
        assert_eq!(social_db::role_for_user(&social, into).expect("role"), Some(Role::Moderator));

        let social_m = Mutex::new(social);

        // Retry the whole merge — the social phase runs again (a no-op this
        // time) and the identity phase runs for the first time.
        let summary = execute(&db, &social_m, &store, &dir.0, from, into, None).expect("retried execute");
        assert!(!summary.dry_run);

        let social_conn = social_m.lock().expect("lock");
        assert_eq!(social_db::role_for_user(&social_conn, into).expect("role"), Some(Role::Moderator));
        // Exactly one role row total — the retried social pass did not duplicate it.
        let role_count: i64 =
            social_conn.query_row("SELECT COUNT(*) FROM forum_roles", [], |r| r.get(0)).expect("count");
        assert_eq!(role_count, 1);
    }

    #[test]
    fn execute_moves_hot_plane_files_and_never_overwrites_a_collision() {
        let db = Mutex::new(identity_conn());
        let social_m = Mutex::new(social_conn());
        let dir = TestDir::new();
        let store = SyncStore::new(dir.0.join("sync"));

        let (from, into) = {
            let conn = db.lock().expect("lock");
            (
                seed_user(&conn, "github", "f7", "from-user"),
                seed_user(&conn, "google", "i7", "into-user"),
            )
        };

        fn preset(sync_id: &str, modified_at: i64) -> crate::db::SyncPushItem {
            crate::db::SyncPushItem {
                sync_id: sync_id.to_string(),
                category: "preset".to_string(),
                name: "n".to_string(),
                content: b"blob".to_vec(),
                checksum: "chk".to_string(),
                modified_at,
                deleted: false,
            }
        }

        {
            let conn = db.lock().expect("lock");
            crate::syncstore::push(&conn, &store, into, "dev", "prof", &[preset("p1", 100)], false)
                .expect("seed into preset");
            crate::syncstore::push(&conn, &store, from, "dev", "prof", &[preset("p1", 999)], false)
                .expect("seed from colliding preset");
            crate::syncstore::push(&conn, &store, from, "dev2", "prof2", &[preset("p2", 100)], false)
                .expect("seed from non-colliding preset");
        }

        let summary = execute(&db, &social_m, &store, &dir.0, from, into, None).expect("execute");

        assert_eq!(summary.hot_files_moved, 1);
        assert_eq!(summary.hot_files_archived, 1);

        // The survivor's own file (modified_at 100) was never overwritten by
        // the loser's colliding one (modified_at 999) — read back through the
        // same public pull path a client would use.
        let conn = db.lock().expect("lock");
        let items = crate::syncstore::pull_by_profile(&conn, &store, into, "prof").expect("pull");
        let survivor = items.iter().find(|i| i.sync_id == "p1").expect("survivor item");
        assert_eq!(survivor.modified_at, 100);
    }

    /// An anonymous account is refused on either side of a merge, and nothing
    /// is written.
    #[test]
    fn merging_an_anonymous_account_with_an_oauth_account_is_refused_both_ways() {
        let db = Mutex::new(identity_conn());
        let social_m = Mutex::new(social_conn());
        let dir = TestDir::new();
        let store = SyncStore::new(dir.0.join("sync"));
        let (anon, oauth) = {
            let conn = db.lock().expect("lock");
            let key = crate::billing::anon::AccountKey::generate();
            let anon = crate::billing::anon::create_pending(&conn, &key, chrono::Utc::now()).expect("anon");
            (anon, seed_user(&conn, "github", "oauth-1", "oauth-user"))
        };
        for (from, into, side) in [(anon, oauth, "from"), (oauth, anon, "into")] {
            let err = execute(&db, &social_m, &store, &dir.0, from, into, None).expect_err("must refuse");
            assert!(matches!(err, MergeError::AnonymousAccount { side: s, .. } if s == side), "{err:?}");
            let plan_err = plan(&db, &social_m, &store, from, into).expect_err("a dry run refuses too");
            assert!(matches!(plan_err, MergeError::AnonymousAccount { .. }), "{plan_err:?}");
        }
        let conn = db.lock().expect("lock");
        let survivors: i64 = conn
            .query_row("SELECT COUNT(*) FROM users WHERE id IN (?1, ?2)", params![anon, oauth], |r| r.get(0))
            .expect("count");
        assert_eq!(survivors, 2, "nothing was merged or deleted");
    }

    /// A merge carries the loser's purchases to the survivor: entitlements
    /// combine, credit adds up, and the subscription/invoice rows follow — so
    /// a later refund webhook still finds (and can revoke) what was bought.
    #[test]
    fn execute_carries_billing_state_to_the_survivor() {
        let db = Mutex::new(identity_conn());
        let social_m = Mutex::new(social_conn());
        let dir = TestDir::new();
        let store = SyncStore::new(dir.0.join("sync"));
        let now = chrono::Utc::now();

        let (from, into) = {
            let conn = db.lock().expect("lock");
            let from = seed_user(&conn, "github", "f9", "from-user");
            let into = seed_user(&conn, "google", "i9", "into-user");
            crate::billing::grants::grant_for_invoice(
                &conn,
                from,
                crate::billing::plans::Grant::LifetimeAnon,
                "grp_9",
                now,
            )
            .expect("from anon");
            crate::billing::entitle::add_credit(&conn, from, 2_000_000, now).expect("from credit");
            crate::billing::entitle::add_credit(&conn, into, 500_000, now).expect("into credit");
            crate::billing::store::record_customer(&conn, from, "cus_from", &from.to_string(), now)
                .expect("customer");
            conn.execute(
                "INSERT INTO billing_subscriptions
                    (checkout_key, user_id, plan_id, subscription_id, external_user_ref, state, created_at, updated_at)
                 VALUES ('k', ?1, 'mlc-anon-account-v1', 'sub_9', ?2, 'paid', ?3, ?3)",
                params![from, from.to_string(), now.to_rfc3339()],
            )
            .expect("subscription");
            conn.execute(
                "INSERT INTO billing_invoices
                    (invoice_id, user_id, subscription_id, plan_id, kind, status, grant_kind, grant_state, created_at, updated_at)
                 VALUES ('grp_9', ?1, 'sub_9', 'mlc-anon-account-v1', 'initial', 'settled', 'lifetime_anon', 'granted', ?2, ?2)",
                params![from, now.to_rfc3339()],
            )
            .expect("invoice");
            (from, into)
        };

        execute(&db, &social_m, &store, &dir.0, from, into, None).expect("execute");

        let conn = db.lock().expect("lock");
        let view = crate::billing::entitle::entitlement_view(&conn, into, chrono::Utc::now()).expect("view");
        assert!(view.lifetime_anon && view.paid);
        let carried: Vec<String> = crate::billing::grants::list(&conn, into)
            .expect("grants")
            .into_iter()
            .map(|g| g.source_ref)
            .collect();
        assert_eq!(carried, vec!["grp_9".to_string(), "grp_9".to_string()], "anonymous + paid, still answering to their invoice");
        assert_eq!(crate::billing::entitle::credit_balance(&conn, into).expect("credit"), 2_500_000);
        assert_eq!(crate::billing::store::customer_for_user(&conn, into).expect("customer").as_deref(), Some("cus_from"));
        let invoice = crate::billing::store::invoice_for_user(&conn, into, "grp_9").expect("query").expect("moved");
        assert_eq!(invoice.user_id, into);
        let sub = crate::billing::store::subscription_by_id(&conn, "sub_9").expect("query").expect("moved");
        assert_eq!(sub.user_id, into);
        assert_eq!(sub.external_user_ref, from.to_string(), "dig2pay still knows the purchase by its original reference");
    }
}

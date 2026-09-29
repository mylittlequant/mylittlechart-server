//! The lifetime-grant ledger.
//!
//! `lifetime_paid` and `lifetime_anon` are not bare flags that events flip:
//! an account holds a lifetime paid (or anonymous) status exactly while at
//! least one NON-REVOKED row of `billing_grants` says so. Each row names where
//! it came from (`source` = `invoice` with the invoice id as `source_ref`, or
//! `admin` with the operator's account id and a note), so a refund revokes the
//! rows its own invoice created and nothing else: an operator grant, or a
//! second purchase, keeps the status alive.
//!
//! The `users.lifetime_paid` / `users.lifetime_anon` columns are only a cache,
//! kept for the batched paid queries (`entitle::entitled_among`,
//! `db::users_paid_batch`) and rebuilt from the ledger by [`rebuild_cache`] on
//! every change made here. Nothing else writes them.
//!
//! An anonymous account is anonymous AND paid, so a `mlc-anon-account*`
//! invoice creates two rows: `lifetime_anon` and `lifetime_paid`.
//!
//! A payment reverted by a reorg revokes its rows provisionally
//! ([`revoke_for_invoice`]); [`grant_for_invoice`] brings back exactly those
//! rows when the invoice settles again. A refund is final — the caller never
//! restores a refunded invoice.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, Result, Row};

use super::plans::Grant;

/// `source` of a row created by a settled invoice.
pub const SOURCE_INVOICE: &str = "invoice";
/// `source` of a row created by an operator.
pub const SOURCE_ADMIN: &str = "admin";

/// One row of `billing_grants`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRow {
    /// Row id.
    pub id: i64,
    /// Owning account.
    pub user_id: i64,
    /// `lifetime_paid` or `lifetime_anon`.
    pub grant: Grant,
    /// [`SOURCE_INVOICE`] or [`SOURCE_ADMIN`].
    pub source: String,
    /// The invoice id, or `"{admin user id}:{note}"`.
    pub source_ref: String,
    /// When the row was created, RFC 3339.
    pub created_at: String,
    /// When it was revoked, RFC 3339; `None` while in force.
    pub revoked_at: Option<String>,
}

const COLUMNS: &str = "id, user_id, grant_kind, source, source_ref, created_at, revoked_at";

fn row_from(row: &Row<'_>) -> Result<GrantRow> {
    let kind: String = row.get(2)?;
    let grant = Grant::parse(&kind).filter(|g| is_lifetime(*g)).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Text,
            format!("unknown lifetime grant {kind:?}").into(),
        )
    })?;
    Ok(GrantRow {
        id: row.get(0)?,
        user_id: row.get(1)?,
        grant,
        source: row.get(3)?,
        source_ref: row.get(4)?,
        created_at: row.get(5)?,
        revoked_at: row.get(6)?,
    })
}

/// Whether `grant` is one of the two ledger grants.
pub fn is_lifetime(grant: Grant) -> bool {
    matches!(grant, Grant::LifetimePaid | Grant::LifetimeAnon)
}

/// A ledger grant from its wire spelling (`lifetime_paid` / `lifetime_anon`).
pub fn parse_lifetime(raw: &str) -> Option<Grant> {
    Grant::parse(raw.trim()).filter(|g| is_lifetime(*g))
}

/// Longest operator note kept in a `source_ref`.
pub const MAX_NOTE_CHARS: usize = 200;

/// An operator note as stored: trimmed, non-empty, at most
/// [`MAX_NOTE_CHARS`] characters and no control characters.
pub fn clean_note(raw: &str) -> Option<String> {
    let note = raw.trim();
    let acceptable = !note.is_empty() && note.chars().count() <= MAX_NOTE_CHARS && !note.chars().any(char::is_control);
    acceptable.then(|| note.to_string())
}

/// Whether the account exists.
pub fn user_exists(conn: &Connection, user_id: i64) -> Result<bool> {
    Ok(conn
        .query_row("SELECT 1 FROM users WHERE id = ?1", params![user_id], |_| Ok(()))
        .optional()?
        .is_some())
}

/// The ledger rows a settled plan creates: a paid account is paid; an
/// anonymous account is anonymous AND paid. Empty for a quant tier (its
/// entitlement is a subscription period, not a ledger row).
pub fn rows_of_plan(plan_grant: Grant) -> &'static [Grant] {
    match plan_grant {
        Grant::LifetimePaid => &[Grant::LifetimePaid],
        Grant::LifetimeAnon => &[Grant::LifetimeAnon, Grant::LifetimePaid],
        Grant::Quant => &[],
    }
}

/// Rebuild the cache columns of `user_id` from the ledger. `false` when the
/// account no longer exists.
pub fn rebuild_cache(conn: &Connection, user_id: i64) -> Result<bool> {
    let changed = conn.execute(
        "UPDATE users SET
            lifetime_paid = EXISTS (SELECT 1 FROM billing_grants g
                WHERE g.user_id = users.id AND g.grant_kind = 'lifetime_paid' AND g.revoked_at IS NULL),
            lifetime_anon = EXISTS (SELECT 1 FROM billing_grants g
                WHERE g.user_id = users.id AND g.grant_kind = 'lifetime_anon' AND g.revoked_at IS NULL)
         WHERE id = ?1",
        params![user_id],
    )?;
    Ok(changed > 0)
}

/// Rebuild the cache of every account whose cached flags disagree with the
/// ledger — run by the migration on every boot, so the cache cannot drift.
pub fn rebuild_all_caches(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "UPDATE users SET
            lifetime_paid = EXISTS (SELECT 1 FROM billing_grants g
                WHERE g.user_id = users.id AND g.grant_kind = 'lifetime_paid' AND g.revoked_at IS NULL),
            lifetime_anon = EXISTS (SELECT 1 FROM billing_grants g
                WHERE g.user_id = users.id AND g.grant_kind = 'lifetime_anon' AND g.revoked_at IS NULL)
         WHERE lifetime_paid != EXISTS (SELECT 1 FROM billing_grants g
                WHERE g.user_id = users.id AND g.grant_kind = 'lifetime_paid' AND g.revoked_at IS NULL)
            OR lifetime_anon != EXISTS (SELECT 1 FROM billing_grants g
                WHERE g.user_id = users.id AND g.grant_kind = 'lifetime_anon' AND g.revoked_at IS NULL);",
    )
}

/// Create (or restore) the rows `invoice_id` grants for a `plan_grant` plan,
/// then rebuild the cache. A row already in force is left alone; a row this
/// invoice created and a reorg revoked is brought back rather than
/// duplicated. `false` when the account no longer exists.
pub fn grant_for_invoice(
    conn: &Connection,
    user_id: i64,
    plan_grant: Grant,
    invoice_id: &str,
    now: DateTime<Utc>,
) -> Result<bool> {
    for kind in rows_of_plan(plan_grant) {
        let existing: Option<(i64, Option<String>)> = conn
            .query_row(
                "SELECT id, revoked_at FROM billing_grants
                 WHERE user_id = ?1 AND grant_kind = ?2 AND source = ?3 AND source_ref = ?4
                 ORDER BY id DESC LIMIT 1",
                params![user_id, kind.as_str(), SOURCE_INVOICE, invoice_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match existing {
            Some((_, None)) => {}
            Some((id, Some(_))) => {
                conn.execute("UPDATE billing_grants SET revoked_at = NULL WHERE id = ?1", params![id])?;
            }
            None => {
                conn.execute(
                    "INSERT INTO billing_grants (user_id, grant_kind, source, source_ref, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![user_id, kind.as_str(), SOURCE_INVOICE, invoice_id, now.to_rfc3339()],
                )?;
            }
        }
    }
    rebuild_cache(conn, user_id)
}

/// Revoke exactly the rows whose `source_ref` is `invoice_id` — never an
/// operator grant, never another invoice's row — and rebuild the cache.
/// Returns how many rows were in force and are now revoked.
pub fn revoke_for_invoice(conn: &Connection, user_id: i64, invoice_id: &str, now: DateTime<Utc>) -> Result<usize> {
    let revoked = conn.execute(
        "UPDATE billing_grants SET revoked_at = ?1
         WHERE user_id = ?2 AND source = ?3 AND source_ref = ?4 AND revoked_at IS NULL",
        params![now.to_rfc3339(), user_id, SOURCE_INVOICE, invoice_id],
    )?;
    rebuild_cache(conn, user_id)?;
    Ok(revoked)
}

/// Result of [`add_admin`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddedGrant {
    /// The row's id.
    pub id: i64,
    /// `false` when an identical row was already in force.
    pub created: bool,
    /// The `source_ref` stored.
    pub source_ref: String,
}

/// Add an operator grant of `grant` (`source = admin`, `source_ref =
/// "{admin_user_id}:{note}"`) and rebuild the cache. Only the two lifetime
/// grants exist in the ledger. `None` when the account does not exist.
pub fn add_admin(
    conn: &Connection,
    user_id: i64,
    grant: Grant,
    admin_user_id: i64,
    note: &str,
    now: DateTime<Utc>,
) -> Result<Option<AddedGrant>> {
    if !is_lifetime(grant) {
        return Err(rusqlite::Error::InvalidParameterName("quant is not a lifetime grant".to_string()));
    }
    let exists = conn
        .query_row("SELECT 1 FROM users WHERE id = ?1", params![user_id], |_| Ok(()))
        .optional()?
        .is_some();
    if !exists {
        return Ok(None);
    }
    let source_ref = format!("{admin_user_id}:{note}");
    let active: Option<i64> = conn
        .query_row(
            "SELECT id FROM billing_grants
             WHERE user_id = ?1 AND grant_kind = ?2 AND source = ?3 AND source_ref = ?4 AND revoked_at IS NULL",
            params![user_id, grant.as_str(), SOURCE_ADMIN, source_ref],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(id) = active {
        return Ok(Some(AddedGrant { id, created: false, source_ref }));
    }
    conn.execute(
        "INSERT INTO billing_grants (user_id, grant_kind, source, source_ref, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![user_id, grant.as_str(), SOURCE_ADMIN, source_ref, now.to_rfc3339()],
    )?;
    let id = conn.last_insert_rowid();
    rebuild_cache(conn, user_id)?;
    Ok(Some(AddedGrant { id, created: true, source_ref }))
}

/// Result of [`revoke_admin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminRevoke {
    /// The operator grant was in force and is now revoked.
    Revoked,
    /// It was already revoked.
    AlreadyRevoked,
    /// No such row for this account.
    NotFound,
    /// The row belongs to an invoice; only the invoice's events revoke it.
    NotAdminGrant,
}

/// Revoke the operator grant `grant_id` of `user_id` and rebuild the cache.
pub fn revoke_admin(conn: &Connection, user_id: i64, grant_id: i64, now: DateTime<Utc>) -> Result<AdminRevoke> {
    let row: Option<(String, Option<String>)> = conn
        .query_row(
            "SELECT source, revoked_at FROM billing_grants WHERE id = ?1 AND user_id = ?2",
            params![grant_id, user_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((source, revoked_at)) = row else {
        return Ok(AdminRevoke::NotFound);
    };
    if source != SOURCE_ADMIN {
        return Ok(AdminRevoke::NotAdminGrant);
    }
    if revoked_at.is_some() {
        return Ok(AdminRevoke::AlreadyRevoked);
    }
    conn.execute(
        "UPDATE billing_grants SET revoked_at = ?1 WHERE id = ?2",
        params![now.to_rfc3339(), grant_id],
    )?;
    rebuild_cache(conn, user_id)?;
    Ok(AdminRevoke::Revoked)
}

/// Revoke every operator grant of kind `grant` that is in force for
/// `user_id` (rows created by an invoice are never touched) and rebuild the
/// cache. Returns how many rows were revoked.
pub fn revoke_admin_kind(conn: &Connection, user_id: i64, grant: Grant, now: DateTime<Utc>) -> Result<usize> {
    let revoked = conn.execute(
        "UPDATE billing_grants SET revoked_at = ?1
         WHERE user_id = ?2 AND grant_kind = ?3 AND source = ?4 AND revoked_at IS NULL",
        params![now.to_rfc3339(), user_id, grant.as_str(), SOURCE_ADMIN],
    )?;
    rebuild_cache(conn, user_id)?;
    Ok(revoked)
}

/// Every ledger row of `user_id`, oldest first.
pub fn list(conn: &Connection, user_id: i64) -> Result<Vec<GrantRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLUMNS} FROM billing_grants WHERE user_id = ?1 ORDER BY id ASC"
    ))?;
    let rows = stmt.query_map(params![user_id], row_from)?;
    rows.collect()
}

/// Seed the ledger from invoices a pre-ledger version had already granted:
/// every `granted` lifetime invoice gets the rows its plan creates. Idempotent
/// (an existing row for the same invoice is kept), so it can run on every boot.
pub fn backfill_from_invoices(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT user_id, invoice_id, grant_kind, COALESCE(period_from, created_at) FROM billing_invoices
         WHERE grant_state = 'granted' AND grant_kind IN ('lifetime_paid', 'lifetime_anon')",
    )?;
    let granted: Vec<(i64, String, String, String)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?
        .collect::<Result<_>>()?;
    for (user_id, invoice_id, kind, at) in granted {
        let Some(plan_grant) = Grant::parse(&kind) else { continue };
        for row_kind in rows_of_plan(plan_grant) {
            conn.execute(
                "INSERT INTO billing_grants (user_id, grant_kind, source, source_ref, created_at)
                 SELECT ?1, ?2, ?3, ?4, ?5
                 WHERE NOT EXISTS (SELECT 1 FROM billing_grants
                     WHERE user_id = ?1 AND grant_kind = ?2 AND source = ?3 AND source_ref = ?4)",
                params![user_id, row_kind.as_str(), SOURCE_INVOICE, invoice_id, at],
            )?;
        }
    }
    Ok(())
}

/// Move `from`'s ledger rows to `into` (account merge) and rebuild `into`'s
/// cache. A row `into` already holds in force is kept once.
pub fn merge(conn: &Connection, from: i64, into: i64) -> Result<()> {
    conn.execute(
        "UPDATE OR IGNORE billing_grants SET user_id = ?1 WHERE user_id = ?2",
        params![into, from],
    )?;
    conn.execute("DELETE FROM billing_grants WHERE user_id = ?1", params![from])?;
    rebuild_cache(conn, into)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::entitle::entitlement_view;
    use crate::billing::testkit::{conn, seed_user};
    use chrono::Duration;

    fn flags(conn: &Connection, uid: i64) -> (bool, bool) {
        let v = entitlement_view(conn, uid, Utc::now()).expect("view");
        (v.lifetime_paid, v.lifetime_anon)
    }

    fn active_refs(conn: &Connection, uid: i64) -> Vec<(String, String)> {
        list(conn, uid)
            .expect("list")
            .into_iter()
            .filter(|r| r.revoked_at.is_none())
            .map(|r| (r.grant.as_str().to_string(), r.source_ref))
            .collect()
    }

    #[test]
    fn a_paid_plan_creates_one_row_and_an_anonymous_plan_creates_two() {
        let conn = conn();
        let now = Utc::now();
        let paid = seed_user(&conn, "paid");
        let anon = seed_user(&conn, "anon");
        assert!(grant_for_invoice(&conn, paid, Grant::LifetimePaid, "inv_p", now).expect("grant"));
        assert!(grant_for_invoice(&conn, anon, Grant::LifetimeAnon, "inv_a", now).expect("grant"));
        assert_eq!(active_refs(&conn, paid), vec![("lifetime_paid".to_string(), "inv_p".to_string())]);
        let mut anon_rows = active_refs(&conn, anon);
        anon_rows.sort();
        assert_eq!(
            anon_rows,
            vec![
                ("lifetime_anon".to_string(), "inv_a".to_string()),
                ("lifetime_paid".to_string(), "inv_a".to_string()),
            ]
        );
        assert_eq!(flags(&conn, paid), (true, false));
        assert_eq!(flags(&conn, anon), (true, true));
    }

    #[test]
    fn granting_twice_creates_no_duplicate_rows() {
        let conn = conn();
        let now = Utc::now();
        let uid = seed_user(&conn, "twice");
        grant_for_invoice(&conn, uid, Grant::LifetimePaid, "inv_1", now).expect("grant");
        grant_for_invoice(&conn, uid, Grant::LifetimePaid, "inv_1", now).expect("grant again");
        assert_eq!(list(&conn, uid).expect("list").len(), 1);
    }

    #[test]
    fn a_refund_of_one_invoice_leaves_the_admin_grant_and_the_other_invoice_alone() {
        let conn = conn();
        let now = Utc::now();
        let uid = seed_user(&conn, "many");
        grant_for_invoice(&conn, uid, Grant::LifetimePaid, "inv_a", now).expect("a");
        grant_for_invoice(&conn, uid, Grant::LifetimePaid, "inv_b", now).expect("b");
        let admin = add_admin(&conn, uid, Grant::LifetimePaid, 7, "support fix", now).expect("admin").expect("user");
        assert!(admin.created);
        assert_eq!(admin.source_ref, "7:support fix");

        assert_eq!(revoke_for_invoice(&conn, uid, "inv_a", now).expect("revoke a"), 1);
        assert_eq!(flags(&conn, uid), (true, false), "b and the admin grant still hold it");
        let refs: Vec<String> = active_refs(&conn, uid).into_iter().map(|(_, r)| r).collect();
        assert_eq!(refs, vec!["inv_b".to_string(), "7:support fix".to_string()]);

        assert_eq!(revoke_for_invoice(&conn, uid, "inv_b", now).expect("revoke b"), 1);
        assert_eq!(flags(&conn, uid), (true, false), "the admin grant alone still holds it");
        assert_eq!(revoke_admin(&conn, uid, admin.id, now).expect("revoke admin"), AdminRevoke::Revoked);
        assert_eq!(flags(&conn, uid), (false, false), "nothing left");
    }

    #[test]
    fn a_refund_never_touches_a_grant_it_did_not_create() {
        // The bug this ledger fixes: an account whose status came from
        // somewhere else must not lose it when an unrelated invoice is refunded.
        let conn = conn();
        let now = Utc::now();
        let uid = seed_user(&conn, "grandfathered");
        add_admin(&conn, uid, Grant::LifetimePaid, 1, "early supporter", now).expect("admin").expect("user");
        grant_for_invoice(&conn, uid, Grant::LifetimePaid, "inv_x", now).expect("grant");
        revoke_for_invoice(&conn, uid, "inv_x", now).expect("refund");
        assert_eq!(flags(&conn, uid), (true, false));
        // A refund of an invoice that granted nothing is a no-op.
        assert_eq!(revoke_for_invoice(&conn, uid, "inv_never", now).expect("refund"), 0);
        assert_eq!(flags(&conn, uid), (true, false));
    }

    #[test]
    fn a_resettled_invoice_restores_only_its_own_rows() {
        let conn = conn();
        let now = Utc::now();
        let uid = seed_user(&conn, "restore");
        grant_for_invoice(&conn, uid, Grant::LifetimeAnon, "inv_a", now).expect("a");
        grant_for_invoice(&conn, uid, Grant::LifetimePaid, "inv_b", now).expect("b");
        let admin = add_admin(&conn, uid, Grant::LifetimePaid, 1, "note", now).expect("admin").expect("user");
        // The operator revokes their own grant; both invoices are reverted.
        revoke_admin(&conn, uid, admin.id, now).expect("revoke admin");
        revoke_for_invoice(&conn, uid, "inv_a", now).expect("revert a");
        revoke_for_invoice(&conn, uid, "inv_b", now).expect("revert b");
        assert_eq!(flags(&conn, uid), (false, false));

        // Only invoice A settles again.
        grant_for_invoice(&conn, uid, Grant::LifetimeAnon, "inv_a", now + Duration::minutes(5)).expect("restore a");
        assert_eq!(flags(&conn, uid), (true, true), "A carries anonymous AND paid");
        let refs = active_refs(&conn, uid);
        assert!(refs.iter().all(|(_, r)| r == "inv_a"), "B and the admin grant stay revoked: {refs:?}");
        assert_eq!(list(&conn, uid).expect("list").len(), 4, "restoring reused the rows, it created none");
    }

    #[test]
    fn admin_grants_are_deduplicated_listed_and_only_admin_rows_are_revocable_by_the_operator() {
        let conn = conn();
        let now = Utc::now();
        let uid = seed_user(&conn, "ops");
        let first = add_admin(&conn, uid, Grant::LifetimeAnon, 3, "beta", now).expect("add").expect("user");
        let again = add_admin(&conn, uid, Grant::LifetimeAnon, 3, "beta", now).expect("add").expect("user");
        assert!(first.created && !again.created);
        assert_eq!(first.id, again.id);
        assert_eq!(flags(&conn, uid), (false, true), "an admin anonymous grant is only what it says");

        grant_for_invoice(&conn, uid, Grant::LifetimePaid, "inv_1", now).expect("grant");
        let invoice_row = list(&conn, uid).expect("list").into_iter().find(|r| r.source == SOURCE_INVOICE).expect("row");
        assert_eq!(revoke_admin(&conn, uid, invoice_row.id, now).expect("revoke"), AdminRevoke::NotAdminGrant);
        assert_eq!(revoke_admin(&conn, uid, 9999, now).expect("revoke"), AdminRevoke::NotFound);
        assert_eq!(revoke_admin(&conn, uid + 1, first.id, now).expect("revoke"), AdminRevoke::NotFound, "another account's row");
        assert_eq!(revoke_admin(&conn, uid, first.id, now).expect("revoke"), AdminRevoke::Revoked);
        assert_eq!(revoke_admin(&conn, uid, first.id, now).expect("revoke"), AdminRevoke::AlreadyRevoked);
        assert!(add_admin(&conn, 4242, Grant::LifetimePaid, 1, "x", now).expect("add").is_none(), "unknown account");
        assert!(add_admin(&conn, uid, Grant::Quant, 1, "x", now).is_err());
    }

    #[test]
    fn revoking_an_admin_kind_touches_only_admin_rows_of_that_kind() {
        let conn = conn();
        let now = Utc::now();
        let uid = seed_user(&conn, "kinds");
        grant_for_invoice(&conn, uid, Grant::LifetimePaid, "inv_1", now).expect("invoice");
        add_admin(&conn, uid, Grant::LifetimePaid, 1, "a", now).expect("a").expect("user");
        add_admin(&conn, uid, Grant::LifetimePaid, 2, "b", now).expect("b").expect("user");
        add_admin(&conn, uid, Grant::LifetimeAnon, 1, "c", now).expect("c").expect("user");
        assert_eq!(revoke_admin_kind(&conn, uid, Grant::LifetimePaid, now).expect("revoke"), 2);
        assert_eq!(flags(&conn, uid), (true, true), "the invoice row and the anonymous admin row remain");
        assert_eq!(revoke_admin_kind(&conn, uid, Grant::LifetimePaid, now).expect("again"), 0);
        assert_eq!(revoke_admin_kind(&conn, uid, Grant::LifetimeAnon, now).expect("revoke"), 1);
        assert_eq!(flags(&conn, uid), (true, false));
    }

    #[test]
    fn notes_and_grant_names_are_validated() {
        assert_eq!(parse_lifetime(" lifetime_paid "), Some(Grant::LifetimePaid));
        assert_eq!(parse_lifetime("lifetime_anon"), Some(Grant::LifetimeAnon));
        assert_eq!(parse_lifetime("quant"), None);
        assert_eq!(parse_lifetime(""), None);
        assert_eq!(clean_note("  beta tester  ").as_deref(), Some("beta tester"));
        for bad in ["", "   ", "line\nbreak", &"x".repeat(MAX_NOTE_CHARS + 1)] {
            assert_eq!(clean_note(bad), None, "{bad:?}");
        }
        assert!(clean_note(&"x".repeat(MAX_NOTE_CHARS)).is_some());
    }

    #[test]
    fn the_cache_is_rebuilt_from_the_ledger_not_trusted() {
        let conn = conn();
        let now = Utc::now();
        let uid = seed_user(&conn, "cache");
        conn.execute("UPDATE users SET lifetime_paid = 1, lifetime_anon = 1 WHERE id = ?1", params![uid]).expect("poison");
        rebuild_all_caches(&conn).expect("rebuild");
        assert_eq!(flags(&conn, uid), (false, false), "a flag with no ledger row does not survive a rebuild");
        grant_for_invoice(&conn, uid, Grant::LifetimePaid, "inv_1", now).expect("grant");
        conn.execute("UPDATE users SET lifetime_paid = 0 WHERE id = ?1", params![uid]).expect("poison");
        rebuild_all_caches(&conn).expect("rebuild");
        assert_eq!(flags(&conn, uid), (true, false));
    }

    #[test]
    fn the_migration_seeds_the_ledger_from_invoices_a_pre_ledger_version_granted() {
        let conn = conn();
        let now = Utc::now();
        let uid = seed_user(&conn, "legacy");
        for (invoice, kind, state) in [("inv_paid", "lifetime_paid", "granted"), ("inv_anon", "lifetime_anon", "granted"), ("inv_refunded", "lifetime_paid", "revoked")] {
            conn.execute(
                "INSERT INTO billing_invoices (invoice_id, user_id, subscription_id, plan_id, kind, status, grant_kind, grant_state, created_at, updated_at)
                 VALUES (?1, ?2, 'sub', 'p', 'initial', 'settled', ?3, ?4, ?5, ?5)",
                params![invoice, uid, kind, state, now.to_rfc3339()],
            )
            .expect("invoice");
        }
        backfill_from_invoices(&conn).expect("backfill");
        backfill_from_invoices(&conn).expect("backfill again");
        rebuild_all_caches(&conn).expect("rebuild");
        assert_eq!(flags(&conn, uid), (true, true));
        let refs: Vec<String> = list(&conn, uid).expect("list").into_iter().map(|r| r.source_ref).collect();
        assert_eq!(refs.len(), 3, "paid: one row, anonymous: two rows, refunded: none");
        assert!(!refs.iter().any(|r| r == "inv_refunded"));
    }

    #[test]
    fn merging_moves_the_rows_and_rebuilds_the_survivors_cache() {
        let conn = conn();
        let now = Utc::now();
        let from = seed_user(&conn, "from");
        let into = seed_user(&conn, "into");
        grant_for_invoice(&conn, from, Grant::LifetimeAnon, "inv_a", now).expect("a");
        grant_for_invoice(&conn, into, Grant::LifetimePaid, "inv_b", now).expect("b");
        merge(&conn, from, into).expect("merge");
        merge(&conn, from, into).expect("merge again changes nothing");
        assert_eq!(flags(&conn, into), (true, true));
        assert!(list(&conn, from).expect("list").is_empty());
        // The moved rows still answer to their invoice.
        assert_eq!(revoke_for_invoice(&conn, into, "inv_a", now).expect("refund"), 2);
        assert_eq!(flags(&conn, into), (true, false), "inv_b still holds paid");
    }
}

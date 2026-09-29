//! Anonymous ("numbered") accounts: the account with no OAuth, bought with
//! `mlc-anon-account*` and entered with an account key alone.
//!
//! # Lifecycle
//!
//! 1. `POST /api/billing/anon-checkout` creates a PENDING user
//!    (`users.provider = 'anon'`, no email, no OAuth link) and an
//!    account key, then opens the dig2pay subscription with that user's id as
//!    the `external_user_ref`. The key is returned once.
//! 2. `payment_confirmed` for that subscription activates the account and
//!    creates its `lifetime_anon` + `lifetime_paid` grants (source = the
//!    invoice). Until then the key can only read its own invoice.
//! 3. `POST /api/auth/account-key` turns the key of an ACTIVE account into a
//!    session. `POST /api/account/key/rotate` replaces the key.
//! 4. A pending account whose invoice expired more than a day ago is deleted
//!    with its billing rows ([`gc_pending`]); a late webhook for it then
//!    matches nothing and is recorded as `unmatched`.
//!
//! # The key
//!
//! 128 random bits, shown as 26 Crockford base32 characters in groups of
//! four (`XXXX-XXXX-…-XX`). Only its SHA-256 is stored — a key with 128 bits
//! of entropy needs no slow hash, and the index on the hash is the
//! comparator. [`AccountKey`] has no `Display` and a redacted `Debug`, and no
//! code path in this crate formats it into a log line or an error body; the
//! only place it is rendered is [`AccountKey::reveal`], for the one response
//! that hands it to the buyer.

use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use rusqlite::{params, Connection, OptionalExtension, Result};
use sha2::{Digest, Sha256};

/// `users.provider` of an anonymous account. Not an OAuth provider name, so
/// no sign-in flow can ever resolve to it.
pub const PROVIDER: &str = "anon";

/// A pending account whose invoice expired longer ago than this is deleted.
pub const GC_GRACE: Duration = Duration::hours(24);

const KEY_BYTES: usize = 16;
const KEY_CHARS: usize = 26;
const GROUP: usize = 4;
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A 128-bit account key.
#[derive(Clone)]
pub struct AccountKey([u8; KEY_BYTES]);

impl std::fmt::Debug for AccountKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountKey(<redacted>)")
    }
}

impl AccountKey {
    /// A fresh random key.
    pub fn generate() -> Self {
        Self(rand::thread_rng().gen())
    }

    /// The key as the buyer sees it: Crockford base32, groups of four.
    /// Call only when building the response that hands it over.
    pub fn reveal(&self) -> String {
        let n = u128::from_be_bytes(self.0);
        let mut out = String::with_capacity(KEY_CHARS + KEY_CHARS / GROUP);
        for i in 0..KEY_CHARS {
            if i > 0 && i % GROUP == 0 {
                out.push('-');
            }
            let shift = 5 * (KEY_CHARS - 1 - i);
            let index = ((n >> shift) & 31) as usize;
            out.push(char::from(CROCKFORD[index]));
        }
        out
    }

    /// Parse what a user typed or pasted: case, hyphens and spaces are
    /// ignored, and Crockford's look-alike rules apply (`O` reads as `0`,
    /// `I` and `L` as `1`). `None` for anything that is not a key.
    pub fn parse(input: &str) -> Option<Self> {
        let mut n: u128 = 0;
        let mut chars = 0usize;
        for c in input.chars() {
            if c == '-' || c.is_whitespace() {
                continue;
            }
            let c = match c.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                other => other,
            };
            let value = u128::try_from(CROCKFORD.iter().position(|b| char::from(*b) == c)?).ok()?;
            // Exactly 26 characters; the first carries only the top 3 bits of 128.
            if chars >= KEY_CHARS || (chars == 0 && value > 7) {
                return None;
            }
            n = (n << 5) | value;
            chars += 1;
        }
        (chars == KEY_CHARS).then(|| Self(n.to_be_bytes()))
    }

    /// Hex SHA-256 of the key bytes — the only form that is stored.
    pub fn hash_hex(&self) -> String {
        hex::encode(Sha256::digest(self.0))
    }
}

/// Where an anonymous account stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStatus {
    /// Created by a checkout; the invoice is not paid.
    Pending,
    /// Paid: may sign in.
    Active,
}

impl AccountStatus {
    fn as_str(self) -> &'static str {
        match self {
            AccountStatus::Pending => "pending",
            AccountStatus::Active => "active",
        }
    }

    fn parse(raw: &str) -> Option<AccountStatus> {
        match raw {
            "pending" => Some(AccountStatus::Pending),
            "active" => Some(AccountStatus::Active),
            _ => None,
        }
    }
}

/// An anonymous account found by its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnonAccount {
    /// The account's user id.
    pub user_id: i64,
    /// Pending or active.
    pub status: AccountStatus,
}

/// Whether `user_id` is an anonymous account (whatever its status).
pub fn is_anonymous(conn: &Connection, user_id: i64) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM users WHERE id = ?1 AND provider = ?2",
            params![user_id, PROVIDER],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Create a PENDING anonymous user holding `key`, and return its id. The user
/// has no email, no display name and no OAuth link.
pub fn create_pending(conn: &Connection, key: &AccountKey, now: DateTime<Utc>) -> Result<i64> {
    let stamp = now.to_rfc3339();
    let opaque: [u8; 16] = rand::thread_rng().gen();
    let user_id = crate::db::upsert_user(conn, PROVIDER, &hex::encode(opaque), "", None, &stamp)?;
    conn.execute(
        "INSERT INTO billing_anon_accounts (user_id, key_hash, status, created_at) VALUES (?1, ?2, 'pending', ?3)",
        params![user_id, key.hash_hex(), stamp],
    )?;
    Ok(user_id)
}

/// The anonymous account holding `key`, if it exists and its user does too.
pub fn find_by_key(conn: &Connection, key: &AccountKey) -> Result<Option<AnonAccount>> {
    let row: Option<(i64, String)> = conn
        .query_row(
            "SELECT a.user_id, a.status FROM billing_anon_accounts a
             JOIN users u ON u.id = a.user_id AND u.provider = ?2
             WHERE a.key_hash = ?1",
            params![key.hash_hex(), PROVIDER],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    Ok(row.and_then(|(user_id, status)| {
        AccountStatus::parse(&status).map(|status| AnonAccount { user_id, status })
    }))
}

/// The status of anonymous account `user_id`, if it is one.
pub fn status_of(conn: &Connection, user_id: i64) -> Result<Option<AccountStatus>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT status FROM billing_anon_accounts WHERE user_id = ?1",
            params![user_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(raw.and_then(|s| AccountStatus::parse(&s)))
}

/// Activate a pending anonymous account (payment confirmed). A no-op for any
/// other user and for an account that is already active.
pub fn activate(conn: &Connection, user_id: i64, now: DateTime<Utc>) -> Result<()> {
    conn.execute(
        "UPDATE billing_anon_accounts SET status = ?1, activated_at = ?2 WHERE user_id = ?3 AND status = 'pending'",
        params![AccountStatus::Active.as_str(), now.to_rfc3339(), user_id],
    )?;
    Ok(())
}

/// Replace the key of ACTIVE anonymous account `user_id`; the old key stops
/// working at once. `false` when the account is not an active anonymous one.
pub fn rotate_key(conn: &Connection, user_id: i64, new_key: &AccountKey, now: DateTime<Utc>) -> Result<bool> {
    let changed = conn.execute(
        "UPDATE billing_anon_accounts SET key_hash = ?1, rotated_at = ?2 WHERE user_id = ?3 AND status = 'active'",
        params![new_key.hash_hex(), now.to_rfc3339(), user_id],
    )?;
    Ok(changed > 0)
}

/// Delete an anonymous account and every billing row that hangs off it
/// (subscriptions, invoices, the dig2pay customer mapping, the key). Grants
/// and payment events are left: they are records, not state.
fn delete_account(conn: &Connection, user_id: i64) -> Result<()> {
    for table in ["billing_subscriptions", "billing_invoices", "billing_subscribers", "billing_anon_accounts"] {
        conn.execute(&format!("DELETE FROM {table} WHERE user_id = ?1"), params![user_id])?;
    }
    crate::db::delete_account(conn, user_id)?;
    Ok(())
}

/// Roll back an anonymous checkout that never produced an invoice (dig2pay
/// refused or was unreachable). Only ever removes a PENDING account with no
/// invoice, so it cannot touch one a payer already holds an address for.
pub fn discard_unfinished(conn: &Connection, user_id: i64) -> Result<bool> {
    let pending = status_of(conn, user_id)? == Some(AccountStatus::Pending);
    let invoices: i64 = conn.query_row(
        "SELECT COUNT(*) FROM billing_invoices WHERE user_id = ?1",
        params![user_id],
        |row| row.get(0),
    )?;
    if !pending || invoices > 0 {
        return Ok(false);
    }
    delete_account(conn, user_id)?;
    Ok(true)
}

/// What one [`gc_pending`] pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GcReport {
    /// Pending accounts deleted.
    pub deleted: usize,
    /// Pending accounts kept although old, because money or a payment event
    /// is attached to their invoice and a human has to resolve it.
    pub kept_with_payment: usize,
}

/// Delete pending anonymous accounts whose invoice expired more than
/// [`GC_GRACE`] ago (an account whose checkout never produced an invoice is
/// measured from its creation), together with their billing rows. Also drops
/// key rows whose user is gone. A pending account whose invoice carries a
/// payment flag (partial, over, funds pending, late) or any grant is KEPT.
pub fn gc_pending(conn: &Connection, now: DateTime<Utc>) -> Result<GcReport> {
    let mut report = GcReport::default();
    let pending: Vec<(i64, String)> = {
        let mut stmt =
            conn.prepare("SELECT user_id, created_at FROM billing_anon_accounts WHERE status = 'pending'")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<Result<_>>()?
    };
    for (user_id, created_at) in pending {
        let invoices = super::store::invoices_for_user(conn, user_id)?;
        let money_attached = invoices.iter().any(|i| {
            i.grant_state != super::store::GrantState::None
                || i.status != super::store::INVOICE_NEW
                || !i.flags.is_empty()
        });
        if money_attached {
            report.kept_with_payment += 1;
            continue;
        }
        let expiry = invoices
            .iter()
            .filter_map(|i| i.expires_at.as_deref())
            .filter_map(|t| DateTime::parse_from_rfc3339(t).ok())
            .map(|t| t.with_timezone(&Utc))
            .max()
            .or_else(|| DateTime::parse_from_rfc3339(&created_at).ok().map(|t| t.with_timezone(&Utc)));
        if expiry.is_some_and(|t| t + GC_GRACE < now) {
            delete_account(conn, user_id)?;
            report.deleted += 1;
        }
    }
    conn.execute(
        "DELETE FROM billing_anon_accounts WHERE user_id NOT IN (SELECT id FROM users)",
        [],
    )?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::store::{self, GrantState, InvoiceKind, InvoiceRow, INVOICE_NEW};
    use crate::billing::testkit::{conn, seed_user};

    fn invoice(user_id: i64, id: &str, expires: DateTime<Utc>) -> InvoiceRow {
        InvoiceRow {
            invoice_id: id.to_string(),
            user_id,
            subscription_id: format!("sub_{id}"),
            plan_id: "mlc-anon-account-v1".to_string(),
            kind: InvoiceKind::Initial,
            status: INVOICE_NEW.to_string(),
            pay_json: "[]".to_string(),
            expires_at: Some(expires.to_rfc3339()),
            flags: Vec::new(),
            grant_kind: None,
            grant_state: GrantState::None,
            period_from: None,
            period_to: None,
            detail: serde_json::json!({}),
        }
    }

    fn pending_with_invoice(conn: &Connection, id: &str, expires: DateTime<Utc>, now: DateTime<Utc>) -> (AccountKey, i64) {
        let key = AccountKey::generate();
        let uid = create_pending(conn, &key, now).expect("create");
        conn.execute(
            "INSERT INTO billing_subscriptions
                (checkout_key, user_id, plan_id, subscription_id, external_user_ref, state, created_at, updated_at)
             VALUES (?1, ?2, 'mlc-anon-account-v1', ?3, ?2, 'open', ?4, ?4)",
            params![format!("k_{id}"), uid, format!("sub_{id}"), now.to_rfc3339()],
        )
        .expect("subscription");
        store::insert_invoice(conn, &invoice(uid, id, expires), now).expect("invoice");
        store::record_customer(conn, uid, &format!("cus_{id}"), &uid.to_string(), now).expect("customer");
        (key, uid)
    }

    fn exists(conn: &Connection, uid: i64) -> bool {
        conn.query_row("SELECT 1 FROM users WHERE id = ?1", params![uid], |_| Ok(())).optional().expect("query").is_some()
    }

    // ------------------------------------------------------------- the key

    #[test]
    fn a_key_is_26_crockford_characters_in_groups_of_four() {
        for _ in 0..50 {
            let shown = AccountKey::generate().reveal();
            assert_eq!(shown.len(), 26 + 6, "26 characters and 6 hyphens: {shown}");
            let groups: Vec<&str> = shown.split('-').collect();
            assert_eq!(groups.len(), 7);
            assert!(groups[..6].iter().all(|g| g.len() == 4));
            assert_eq!(groups[6].len(), 2);
            assert!(shown.chars().filter(|c| *c != '-').all(|c| CROCKFORD.contains(&(c as u8))));
            assert!(shown.chars().next().is_some_and(|c| "01234567".contains(c)), "128 bits leave the first character at 3 bits");
        }
    }

    #[test]
    fn a_key_round_trips_and_forgives_case_hyphens_spaces_and_lookalikes() {
        let key = AccountKey::generate();
        let shown = key.reveal();
        let parsed = AccountKey::parse(&shown).expect("parse");
        assert_eq!(parsed.hash_hex(), key.hash_hex());

        let sloppy = shown.to_lowercase().replace('-', " ");
        assert_eq!(AccountKey::parse(&sloppy).expect("lower case, spaces").hash_hex(), key.hash_hex());
        assert_eq!(AccountKey::parse(&shown.replace('-', "")).expect("no hyphens").hash_hex(), key.hash_hex());

        // A key that contains a 0 or a 1 reads the same with O, I and L typed instead.
        let zeros_and_ones = (0..)
            .map(|_| AccountKey::generate())
            .find(|k| {
                let s = k.reveal();
                s.contains('0') && s.contains('1')
            })
            .expect("a key with both digits turns up quickly");
        let typed = zeros_and_ones.reveal().replace('0', "o").replace('1', "l");
        assert_eq!(AccountKey::parse(&typed).expect("look-alikes").hash_hex(), zeros_and_ones.hash_hex());
    }

    #[test]
    fn anything_that_is_not_a_key_does_not_parse() {
        let good = AccountKey::generate().reveal();
        let plain = good.replace('-', "");
        for bad in [
            "",
            "hello",
            &plain[..25],
            &format!("{plain}0"),
            &format!("{}U{}", &plain[..10], &plain[11..]),
            &format!("8{}", &plain[1..]),
            &format!("{}!", &plain[..25]),
        ] {
            assert!(AccountKey::parse(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn keys_do_not_collide_and_the_stored_form_is_a_hash() {
        let a = AccountKey::generate();
        let b = AccountKey::generate();
        assert_ne!(a.hash_hex(), b.hash_hex());
        assert_eq!(a.hash_hex().len(), 64);
        assert!(!a.hash_hex().contains(&a.reveal().replace('-', "")));
    }

    #[test]
    fn the_key_never_renders_through_debug() {
        let key = AccountKey::generate();
        let shown = key.reveal();
        assert_eq!(format!("{key:?}"), "AccountKey(<redacted>)");
        let account = AnonAccount { user_id: 1, status: AccountStatus::Active };
        assert!(!format!("{account:?}").contains(&shown));
    }

    // ------------------------------------------------------------ accounts

    #[test]
    fn a_pending_account_has_no_email_no_oauth_link_and_only_its_key_hash_stored() {
        let conn = conn();
        let key = AccountKey::generate();
        let uid = create_pending(&conn, &key, Utc::now()).expect("create");
        assert!(is_anonymous(&conn, uid).expect("anon"));
        assert!(!is_anonymous(&conn, seed_user(&conn, "oauth")).expect("oauth user"));

        let (provider, display_name): (String, String) = conn
            .query_row("SELECT provider, display_name FROM users WHERE id = ?1", params![uid], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("user");
        assert_eq!((provider.as_str(), display_name.as_str()), ("anon", ""));
        let emails: i64 = conn
            .query_row("SELECT COUNT(*) FROM user_providers WHERE user_id = ?1 AND (email IS NOT NULL OR provider != 'anon')", params![uid], |r| r.get(0))
            .expect("providers");
        assert_eq!(emails, 0);

        let stored: String = conn.query_row("SELECT key_hash FROM billing_anon_accounts WHERE user_id = ?1", params![uid], |r| r.get(0)).expect("hash");
        assert_eq!(stored, key.hash_hex());
        assert_eq!(status_of(&conn, uid).expect("status"), Some(AccountStatus::Pending));
        let found = find_by_key(&conn, &key).expect("find").expect("account");
        assert_eq!(found, AnonAccount { user_id: uid, status: AccountStatus::Pending });
        assert!(find_by_key(&conn, &AccountKey::generate()).expect("find").is_none());
    }

    #[test]
    fn activation_rotation_and_the_old_key() {
        let conn = conn();
        let now = Utc::now();
        let old = AccountKey::generate();
        let uid = create_pending(&conn, &old, now).expect("create");
        let new = AccountKey::generate();
        assert!(!rotate_key(&conn, uid, &new, now).expect("rotate"), "a pending account has no key to rotate");

        activate(&conn, uid, now).expect("activate");
        activate(&conn, uid, now).expect("activate again");
        assert_eq!(status_of(&conn, uid).expect("status"), Some(AccountStatus::Active));
        assert!(rotate_key(&conn, uid, &new, now).expect("rotate"));
        assert!(find_by_key(&conn, &old).expect("find").is_none(), "the old key is dead");
        assert_eq!(find_by_key(&conn, &new).expect("find").map(|a| a.user_id), Some(uid));
        assert!(!rotate_key(&conn, seed_user(&conn, "oauth"), &new, now).expect("rotate"), "not an anonymous account");
    }

    #[test]
    fn a_key_whose_user_is_gone_finds_nothing() {
        let conn = conn();
        let key = AccountKey::generate();
        let uid = create_pending(&conn, &key, Utc::now()).expect("create");
        crate::db::delete_account(&conn, uid).expect("delete");
        assert!(find_by_key(&conn, &key).expect("find").is_none());
        gc_pending(&conn, Utc::now()).expect("gc");
        let rows: i64 = conn.query_row("SELECT COUNT(*) FROM billing_anon_accounts", [], |r| r.get(0)).expect("count");
        assert_eq!(rows, 0, "the dangling key row is swept");
    }

    // ------------------------------------------------------------------ GC

    #[test]
    fn gc_deletes_a_pending_account_a_day_after_its_invoice_expired_with_its_billing_rows() {
        let conn = conn();
        let now = Utc::now();
        let expired = now - Duration::hours(25);
        let (key, uid) = pending_with_invoice(&conn, "old", expired, now - Duration::hours(30));
        let (fresh_key, fresh) = pending_with_invoice(&conn, "fresh", now + Duration::hours(1), now);
        let (recent_key, recent) = pending_with_invoice(&conn, "recent", now - Duration::hours(23), now - Duration::hours(24));

        let report = gc_pending(&conn, now).expect("gc");
        assert_eq!(report, GcReport { deleted: 1, kept_with_payment: 0 });
        assert!(!exists(&conn, uid));
        assert!(find_by_key(&conn, &key).expect("find").is_none());
        for table in ["billing_subscriptions", "billing_invoices", "billing_subscribers", "billing_anon_accounts"] {
            let left: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {table} WHERE user_id = ?1"), params![uid], |r| r.get(0)).expect("count");
            assert_eq!(left, 0, "{table}");
        }
        assert!(exists(&conn, fresh) && find_by_key(&conn, &fresh_key).expect("find").is_some(), "an unexpired invoice is kept");
        assert!(exists(&conn, recent) && find_by_key(&conn, &recent_key).expect("find").is_some(), "expired less than a day ago is kept");
        // A second pass finds nothing more to do.
        assert_eq!(gc_pending(&conn, now).expect("gc").deleted, 0);
    }

    #[test]
    fn gc_never_touches_an_active_account_or_an_oauth_account() {
        let conn = conn();
        let now = Utc::now();
        let (_, active) = pending_with_invoice(&conn, "paid", now - Duration::days(30), now - Duration::days(31));
        activate(&conn, active, now).expect("activate");
        let oauth = seed_user(&conn, "oauth");
        gc_pending(&conn, now).expect("gc");
        assert!(exists(&conn, active) && exists(&conn, oauth));
    }

    #[test]
    fn gc_keeps_an_old_pending_account_that_has_money_attached() {
        let conn = conn();
        let now = Utc::now();
        let (_, partial) = pending_with_invoice(&conn, "partial", now - Duration::days(3), now - Duration::days(4));
        conn.execute("UPDATE billing_invoices SET flags_json = '[\"partial\"]' WHERE user_id = ?1", params![partial]).expect("flag");
        let (_, granted) = pending_with_invoice(&conn, "granted", now - Duration::days(3), now - Duration::days(4));
        conn.execute("UPDATE billing_invoices SET grant_state = 'granted' WHERE user_id = ?1", params![granted]).expect("grant");
        let report = gc_pending(&conn, now).expect("gc");
        assert_eq!(report, GcReport { deleted: 0, kept_with_payment: 2 });
        assert!(exists(&conn, partial) && exists(&conn, granted));
    }

    #[test]
    fn gc_measures_an_account_without_an_invoice_from_its_creation() {
        let conn = conn();
        let now = Utc::now();
        let old = create_pending(&conn, &AccountKey::generate(), now - Duration::hours(30)).expect("old");
        let young = create_pending(&conn, &AccountKey::generate(), now - Duration::hours(2)).expect("young");
        assert_eq!(gc_pending(&conn, now).expect("gc").deleted, 1);
        assert!(!exists(&conn, old) && exists(&conn, young));
    }

    #[test]
    fn a_late_webhook_for_a_collected_account_is_recorded_unmatched_and_grants_nothing() {
        use crate::billing::plans::{AccountPlanIds, Catalog};
        use crate::billing::webhook::{process, Outcome};
        let conn = conn();
        let now = Utc::now();
        let (_, uid) = pending_with_invoice(&conn, "late", now - Duration::hours(30), now - Duration::hours(40));
        gc_pending(&conn, now).expect("gc");
        assert!(!exists(&conn, uid));

        let catalog = Catalog::build(&AccountPlanIds::default(), &std::collections::BTreeMap::new());
        let body = serde_json::json!({
            "event_id": "late-1", "kind": "payment_confirmed", "subscriber_id": "sub_late",
            "external_user_ref": uid.to_string(), "invoice_id": "late",
            "plan_id": "mlc-anon-account-v1", "billing_interval": "one_time",
            "period": { "from": now.to_rfc3339(), "to": null },
        })
        .to_string();
        assert_eq!(process(&conn, &catalog, None, &body, now).expect("process"), Outcome::Unmatched);
        let grants: i64 = conn.query_row("SELECT COUNT(*) FROM billing_grants", [], |r| r.get(0)).expect("count");
        assert_eq!(grants, 0);
        let recorded: String = conn.query_row("SELECT outcome FROM billing_events WHERE event_id = 'late-1'", [], |r| r.get(0)).expect("event");
        assert_eq!(recorded, "unmatched");
    }

    #[test]
    fn discarding_an_unfinished_checkout_removes_only_a_pending_account_with_no_invoice() {
        let conn = conn();
        let now = Utc::now();
        let key = AccountKey::generate();
        let unfinished = create_pending(&conn, &key, now).expect("create");
        assert!(discard_unfinished(&conn, unfinished).expect("discard"));
        assert!(!exists(&conn, unfinished));

        let (_, with_invoice) = pending_with_invoice(&conn, "held", now + Duration::hours(1), now);
        assert!(!discard_unfinished(&conn, with_invoice).expect("discard"), "a payer already holds an address for it");
        let active = create_pending(&conn, &AccountKey::generate(), now).expect("create");
        activate(&conn, active, now).expect("activate");
        assert!(!discard_unfinished(&conn, active).expect("discard"));
        assert!(!discard_unfinished(&conn, seed_user(&conn, "oauth")).expect("discard"));
    }

    // ------------------------------------------- an account with no OAuth

    #[test]
    fn no_flow_attaches_an_oauth_identity_to_an_anonymous_account() {
        let conn = conn();
        let now = Utc::now();
        let anon = create_pending(&conn, &AccountKey::generate(), now).expect("create");
        // Explicit linking is refused outright.
        let err = crate::db::link_provider_to_user(&conn, anon, "github", "gh-1", "gh", None, &now.to_rfc3339())
            .expect_err("an anonymous account takes no provider identity");
        assert!(err.to_string().contains("anonymous"), "{err}");

        // A sign-in from a device the anonymous account is signed in on does
        // not attach to it either: the identity gets an account of its own.
        conn.execute(
            "INSERT INTO device_users (device_id, user_id, linked_at) VALUES ('dev-1', ?1, ?2)",
            params![anon, now.to_rfc3339()],
        )
        .expect("link device");
        let other = crate::db::resolve_or_create_user(&conn, "github", "gh-2", "gh two", None, "dev-1", &now.to_rfc3339())
            .expect("resolve");
        assert_ne!(other, anon);
        let providers: i64 = conn
            .query_row("SELECT COUNT(*) FROM user_providers WHERE user_id = ?1", params![anon], |r| r.get(0))
            .expect("count");
        assert_eq!(providers, 1, "still only its own self mirror");
        // An ordinary account on a linked device still attaches, as before.
        let oauth = seed_user(&conn, "existing");
        conn.execute(
            "INSERT INTO device_users (device_id, user_id, linked_at) VALUES ('dev-2', ?1, ?2)",
            params![oauth, now.to_rfc3339()],
        )
        .expect("link device");
        let attached = crate::db::resolve_or_create_user(&conn, "google", "g-1", "g", None, "dev-2", &now.to_rfc3339())
            .expect("resolve");
        assert_eq!(attached, oauth);
    }

    #[test]
    fn the_orphan_sweep_leaves_a_fresh_anonymous_account_alone() {
        let conn = conn();
        let now = Utc::now();
        let anon = create_pending(&conn, &AccountKey::generate(), now).expect("create");
        activate(&conn, anon, now).expect("activate");
        let report = crate::db::cleanup_orphan_users(&conn).expect("sweep");
        assert_eq!(report.removed_recent_self_ref, 0);
        assert!(exists(&conn, anon), "a paid account nobody has entered yet is not an orphan");
    }
}

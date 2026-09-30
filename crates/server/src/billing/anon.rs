//! Anonymous ("numbered") accounts: the account with no OAuth, bought with
//! `mlc-anon-account*` (or created by a registration invite, see
//! [`super::invite`]) and entered with a client-derived credential alone.
//!
//! # Lifecycle
//!
//! 1. `POST /api/billing/anon-checkout` creates a PENDING user
//!    (`users.provider = 'anon'`, no email, no OAuth link) holding the
//!    credential's hash, then opens the dig2pay subscription with that user's
//!    id as the `external_user_ref`.
//! 2. `payment_confirmed` for that subscription activates the account and
//!    creates its `lifetime_anon` + `lifetime_paid` grants (source = the
//!    invoice). Until then the credential can only read its own invoice.
//! 3. `POST /api/auth/account-key` turns the credential of an ACTIVE account
//!    into a session. `POST /api/account/key/rotate` replaces it.
//! 4. A pending account whose invoice expired more than a day ago is deleted
//!    with its billing rows ([`gc_pending`]); a late webhook for it then
//!    matches nothing and is recorded as `unmatched`.
//!
//! # The credential
//!
//! The client holds a 32-byte secret `K` and sends `C = HKDF(K, "auth")`,
//! 32 bytes as 64 hex characters (docs/mlc/plans/anon-account-one-key-a1b).
//! The server never sees `K`, never generates a credential, and stores only
//! `SHA-256(C)` over the 32 raw bytes: `C` has 256 bits of entropy, so no slow
//! hash is needed and the unique index on the hash is the comparator.
//! [`Credential`] has no `Display` and a redacted `Debug`, and no code path in
//! this crate formats it into a log line or an error body.

use chrono::{DateTime, Duration, Utc};
use mylittlechart_server::live::LiveRegistry;
use rand::Rng;
use rusqlite::{params, Connection, OptionalExtension, Result};
use sha2::{Digest, Sha256};

/// `users.provider` of an anonymous account. Not an OAuth provider name, so
/// no sign-in flow can ever resolve to it.
pub const PROVIDER: &str = "anon";

/// A pending account whose invoice expired longer ago than this is deleted.
pub const GC_GRACE: Duration = Duration::hours(24);

const CREDENTIAL_BYTES: usize = 32;

/// The client-derived login credential: 32 bytes, sent as 64 hex characters.
#[derive(Clone)]
pub struct Credential([u8; CREDENTIAL_BYTES]);

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credential(<redacted>)")
    }
}

impl Credential {
    /// Parse what a client sent: exactly 64 hex characters (either case), no
    /// surrounding whitespace. `None` for anything else, the old 26-character
    /// Crockford keys included.
    pub fn parse(input: &str) -> Option<Self> {
        if input.len() != CREDENTIAL_BYTES * 2 {
            return None;
        }
        let mut bytes = [0u8; CREDENTIAL_BYTES];
        hex::decode_to_slice(input, &mut bytes).ok()?;
        Some(Self(bytes))
    }

    /// Hex SHA-256 of the credential bytes: the only form that is stored.
    pub fn hash_hex(&self) -> String {
        hex::encode(Sha256::digest(self.0))
    }

    /// A random credential, for tests that stand in for a client.
    #[cfg(test)]
    pub fn random() -> Self {
        Self(rand::thread_rng().gen())
    }

    /// The credential as a client sends it, for tests.
    #[cfg(test)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
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

/// Whether some anonymous account already holds `credential`.
pub fn credential_in_use(conn: &Connection, credential: &Credential) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM billing_anon_accounts WHERE key_hash = ?1",
            params![credential.hash_hex()],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Create an anonymous user and its credential row with `status`; returns the
/// user id. The user has no email, no display name and no OAuth link. One
/// savepoint, so a refused credential row (the unique hash) leaves no user.
fn insert_account(conn: &Connection, credential: &Credential, status: AccountStatus, now: DateTime<Utc>) -> Result<i64> {
    let stamp = now.to_rfc3339();
    let opaque: [u8; 16] = rand::thread_rng().gen();
    conn.execute_batch("SAVEPOINT anon_account;")?;
    let created = (|| -> Result<i64> {
        let user_id = crate::db::upsert_user(conn, PROVIDER, &hex::encode(opaque), "", None, &stamp)?;
        let activated_at = (status == AccountStatus::Active).then_some(stamp.as_str());
        conn.execute(
            "INSERT INTO billing_anon_accounts (user_id, key_hash, status, created_at, activated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![user_id, credential.hash_hex(), status.as_str(), stamp, activated_at],
        )?;
        Ok(user_id)
    })();
    match created {
        Ok(user_id) => {
            conn.execute_batch("RELEASE anon_account;")?;
            Ok(user_id)
        }
        Err(e) => {
            // The original failure is what the caller needs.
            let _ = conn.execute_batch("ROLLBACK TO anon_account; RELEASE anon_account;");
            Err(e)
        }
    }
}

/// Create a PENDING anonymous user holding `credential` (a checkout), and
/// return its id.
pub fn create_pending(conn: &Connection, credential: &Credential, now: DateTime<Utc>) -> Result<i64> {
    insert_account(conn, credential, AccountStatus::Pending, now)
}

/// Create an ACTIVE anonymous user holding `credential` (a redeemed
/// registration invite), and return its id.
pub fn create_active(conn: &Connection, credential: &Credential, now: DateTime<Utc>) -> Result<i64> {
    insert_account(conn, credential, AccountStatus::Active, now)
}

/// The anonymous account holding `key`, if it exists and its user does too.
pub fn find_by_key(conn: &Connection, key: &Credential) -> Result<Option<AnonAccount>> {
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

/// What [`rotate_key`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rotation {
    /// The hash was swapped; the old credential is dead.
    Done,
    /// The account is not an active anonymous one.
    NotAnonymous,
    /// Another account already holds the new credential.
    InUse,
}

/// Replace the credential of ACTIVE anonymous account `user_id`; the old one
/// stops working at once.
pub fn rotate_key(conn: &Connection, user_id: i64, new_key: &Credential, now: DateTime<Utc>) -> Result<Rotation> {
    let changed = conn.execute(
        "UPDATE billing_anon_accounts SET key_hash = ?1, rotated_at = ?2 WHERE user_id = ?3 AND status = 'active'",
        params![new_key.hash_hex(), now.to_rfc3339(), user_id],
    );
    match changed {
        Ok(0) => Ok(Rotation::NotAnonymous),
        Ok(_) => Ok(Rotation::Done),
        Err(rusqlite::Error::SqliteFailure(err, _)) if err.code == rusqlite::ErrorCode::ConstraintViolation => {
            Ok(Rotation::InUse)
        }
        Err(e) => Err(e),
    }
}

/// Delete an anonymous account and every billing row that hangs off it
/// (subscriptions, invoices, the dig2pay customer mapping, the key). Grants
/// and payment events are left: they are records, not state.
///
/// The account's Matrix devices go first, through the same hook every other
/// credential deletion uses (`revoke_all_devices_of_user`), because the
/// identity-side delete below removes the token and session rows that hook
/// enumerates. `conn` is the identity connection, already locked by the
/// caller; `messenger` is locked after it (identity THEN messenger).
fn delete_account(conn: &Connection, messenger: &mut Connection, live: &LiveRegistry, user_id: i64) -> Result<()> {
    crate::routes::matrix::auth::revoke_all_devices_of_user(conn, messenger, live, user_id, &Utc::now().to_rfc3339());
    for table in ["billing_subscriptions", "billing_invoices", "billing_subscribers", "billing_anon_accounts"] {
        conn.execute(&format!("DELETE FROM {table} WHERE user_id = ?1"), params![user_id])?;
    }
    crate::db::delete_account(conn, user_id)?;
    Ok(())
}

/// Roll back an anonymous checkout that never produced an invoice (dig2pay
/// refused or was unreachable). Only ever removes a PENDING account with no
/// invoice, so it cannot touch one a payer already holds an address for.
/// `messenger` and `live` are the Matrix side of the deletion (see
/// [`delete_account`]).
pub fn discard_unfinished(conn: &Connection, messenger: &mut Connection, live: &LiveRegistry, user_id: i64) -> Result<bool> {
    let pending = status_of(conn, user_id)? == Some(AccountStatus::Pending);
    let invoices: i64 = conn.query_row(
        "SELECT COUNT(*) FROM billing_invoices WHERE user_id = ?1",
        params![user_id],
        |row| row.get(0),
    )?;
    if !pending || invoices > 0 {
        return Ok(false);
    }
    delete_account(conn, messenger, live, user_id)?;
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
/// `messenger` and `live` are the Matrix side of each deletion (see
/// [`delete_account`]).
pub fn gc_pending(conn: &Connection, messenger: &mut Connection, live: &LiveRegistry, now: DateTime<Utc>) -> Result<GcReport> {
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
            delete_account(conn, messenger, live, user_id)?;
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
    use crate::billing::testkit::{conn, matrix_side, seed_user};

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

    fn pending_with_invoice(conn: &Connection, id: &str, expires: DateTime<Utc>, now: DateTime<Utc>) -> (Credential, i64) {
        let key = Credential::random();
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

    // ------------------------------------------------------- the credential

    #[test]
    fn a_credential_is_exactly_64_hex_characters_in_either_case() {
        let credential = Credential::random();
        let shown = credential.to_hex();
        assert_eq!(shown.len(), 64);
        assert_eq!(Credential::parse(&shown).expect("lower").hash_hex(), credential.hash_hex());
        assert_eq!(Credential::parse(&shown.to_uppercase()).expect("upper").hash_hex(), credential.hash_hex());
    }

    #[test]
    fn anything_that_is_not_a_credential_does_not_parse() {
        let good = Credential::random().to_hex();
        for bad in [
            "",
            "hello",
            &good[..63],
            &format!("{good}0"),
            &format!(" {good}"),
            &format!("{good} "),
            &format!("{}g{}", &good[..10], &good[11..]),
            &format!("{}-{}", &good[..32], &good[32..]),
            // The retired 128-bit Crockford key format.
            "0F4Z-ABCD-EFGH-JKMN-PQRS-TV",
            "0F4ZABCDEFGHJKMNPQRSTV",
        ] {
            assert!(Credential::parse(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn credentials_do_not_collide_and_the_stored_form_is_the_sha256_of_the_bytes() {
        let a = Credential::random();
        let b = Credential::random();
        assert_ne!(a.hash_hex(), b.hash_hex());
        assert_eq!(a.hash_hex().len(), 64);
        assert!(!a.hash_hex().contains(&a.to_hex()));
        // SHA-256 of 32 zero bytes: a fixed answer a client can reproduce.
        let zero = Credential::parse(&"0".repeat(64)).expect("zero credential");
        assert_eq!(zero.hash_hex(), "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925");
    }

    #[test]
    fn the_credential_never_renders_through_debug() {
        let credential = Credential::random();
        let shown = credential.to_hex();
        assert_eq!(format!("{credential:?}"), "Credential(<redacted>)");
        let account = AnonAccount { user_id: 1, status: AccountStatus::Active };
        assert!(!format!("{account:?}").contains(&shown));
    }

    // ------------------------------------------------------------ accounts

    #[test]
    fn a_pending_account_has_no_email_no_oauth_link_and_only_its_key_hash_stored() {
        let conn = conn();
        let key = Credential::random();
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
        assert!(find_by_key(&conn, &Credential::random()).expect("find").is_none());
    }

    #[test]
    fn activation_rotation_and_the_old_key() {
        let conn = conn();
        let now = Utc::now();
        let old = Credential::random();
        let uid = create_pending(&conn, &old, now).expect("create");
        let new = Credential::random();
        assert_eq!(rotate_key(&conn, uid, &new, now).expect("rotate"), Rotation::NotAnonymous, "a pending account has no key to rotate");

        activate(&conn, uid, now).expect("activate");
        activate(&conn, uid, now).expect("activate again");
        assert_eq!(status_of(&conn, uid).expect("status"), Some(AccountStatus::Active));
        assert_eq!(rotate_key(&conn, uid, &new, now).expect("rotate"), Rotation::Done);
        assert!(find_by_key(&conn, &old).expect("find").is_none(), "the old key is dead");
        assert_eq!(find_by_key(&conn, &new).expect("find").map(|a| a.user_id), Some(uid));
        assert_eq!(rotate_key(&conn, seed_user(&conn, "oauth"), &new, now).expect("rotate"), Rotation::NotAnonymous, "not an anonymous account");
        let other = create_pending(&conn, &Credential::random(), now).expect("other");
        activate(&conn, other, now).expect("activate");
        assert_eq!(rotate_key(&conn, other, &new, now).expect("rotate"), Rotation::InUse, "a credential another account holds");
        assert!(find_by_key(&conn, &new).expect("find").is_some_and(|a| a.user_id == uid), "the holder is unchanged");
        assert!(credential_in_use(&conn, &new).expect("in use"));
        assert!(!credential_in_use(&conn, &Credential::random()).expect("in use"));
    }

    #[test]
    fn a_refused_credential_row_leaves_no_user_behind() {
        let conn = conn();
        let credential = Credential::random();
        create_pending(&conn, &credential, Utc::now()).expect("first");
        let users: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)).expect("count");
        assert!(create_pending(&conn, &credential, Utc::now()).is_err(), "the hash is unique");
        assert!(create_active(&conn, &credential, Utc::now()).is_err());
        let after: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)).expect("count");
        assert_eq!(users, after);
    }

    #[test]
    fn an_active_account_can_be_created_directly() {
        let conn = conn();
        let credential = Credential::random();
        let uid = create_active(&conn, &credential, Utc::now()).expect("active");
        assert_eq!(status_of(&conn, uid).expect("status"), Some(AccountStatus::Active));
        assert_eq!(find_by_key(&conn, &credential).expect("find").map(|a| a.user_id), Some(uid));
        assert!(is_anonymous(&conn, uid).expect("anon"));
    }

    #[test]
    fn a_key_whose_user_is_gone_finds_nothing() {
        let conn = conn();
        let (mut mx, live) = matrix_side();
        let key = Credential::random();
        let uid = create_pending(&conn, &key, Utc::now()).expect("create");
        crate::db::delete_account(&conn, uid).expect("delete");
        assert!(find_by_key(&conn, &key).expect("find").is_none());
        gc_pending(&conn, &mut mx, &live, Utc::now()).expect("gc");
        let rows: i64 = conn.query_row("SELECT COUNT(*) FROM billing_anon_accounts", [], |r| r.get(0)).expect("count");
        assert_eq!(rows, 0, "the dangling key row is swept");
    }

    // ------------------------------------------------------------------ GC

    #[test]
    fn gc_deletes_a_pending_account_a_day_after_its_invoice_expired_with_its_billing_rows() {
        let conn = conn();
        let (mut mx, live) = matrix_side();
        let now = Utc::now();
        let expired = now - Duration::hours(25);
        let (key, uid) = pending_with_invoice(&conn, "old", expired, now - Duration::hours(30));
        let (fresh_key, fresh) = pending_with_invoice(&conn, "fresh", now + Duration::hours(1), now);
        let (recent_key, recent) = pending_with_invoice(&conn, "recent", now - Duration::hours(23), now - Duration::hours(24));

        let report = gc_pending(&conn, &mut mx, &live, now).expect("gc");
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
        assert_eq!(gc_pending(&conn, &mut mx, &live, now).expect("gc").deleted, 0);
    }

    #[test]
    fn gc_never_touches_an_active_account_or_an_oauth_account() {
        let conn = conn();
        let (mut mx, live) = matrix_side();
        let now = Utc::now();
        let (_, active) = pending_with_invoice(&conn, "paid", now - Duration::days(30), now - Duration::days(31));
        activate(&conn, active, now).expect("activate");
        let oauth = seed_user(&conn, "oauth");
        gc_pending(&conn, &mut mx, &live, now).expect("gc");
        assert!(exists(&conn, active) && exists(&conn, oauth));
    }

    #[test]
    fn gc_keeps_an_old_pending_account_that_has_money_attached() {
        let conn = conn();
        let (mut mx, live) = matrix_side();
        let now = Utc::now();
        let (_, partial) = pending_with_invoice(&conn, "partial", now - Duration::days(3), now - Duration::days(4));
        conn.execute("UPDATE billing_invoices SET flags_json = '[\"partial\"]' WHERE user_id = ?1", params![partial]).expect("flag");
        let (_, granted) = pending_with_invoice(&conn, "granted", now - Duration::days(3), now - Duration::days(4));
        conn.execute("UPDATE billing_invoices SET grant_state = 'granted' WHERE user_id = ?1", params![granted]).expect("grant");
        let report = gc_pending(&conn, &mut mx, &live, now).expect("gc");
        assert_eq!(report, GcReport { deleted: 0, kept_with_payment: 2 });
        assert!(exists(&conn, partial) && exists(&conn, granted));
    }

    #[test]
    fn gc_measures_an_account_without_an_invoice_from_its_creation() {
        let conn = conn();
        let (mut mx, live) = matrix_side();
        let now = Utc::now();
        let old = create_pending(&conn, &Credential::random(), now - Duration::hours(30)).expect("old");
        let young = create_pending(&conn, &Credential::random(), now - Duration::hours(2)).expect("young");
        assert_eq!(gc_pending(&conn, &mut mx, &live, now).expect("gc").deleted, 1);
        assert!(!exists(&conn, old) && exists(&conn, young));
    }

    #[test]
    fn a_late_webhook_for_a_collected_account_is_recorded_unmatched_and_grants_nothing() {
        use crate::billing::plans::{AccountPlanIds, Catalog};
        use crate::billing::webhook::{process, Outcome};
        let conn = conn();
        let (mut mx, live) = matrix_side();
        let now = Utc::now();
        let (_, uid) = pending_with_invoice(&conn, "late", now - Duration::hours(30), now - Duration::hours(40));
        gc_pending(&conn, &mut mx, &live, now).expect("gc");
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
    fn deleting_an_account_strips_its_matrix_devices_at_once_and_only_its_own() {
        use crate::routes::matrix::auth::web_credential_ref;
        use mylittlechart_server::matrix_keys_store::{create_device, list_devices, CredentialKind};
        let conn = conn();
        let (mut mx, live) = matrix_side();
        let now = Utc::now();
        let stamp = now.to_rfc3339();
        let (_, doomed) = pending_with_invoice(&conn, "doomed", now - Duration::hours(30), now - Duration::hours(40));
        let (_, kept) = pending_with_invoice(&conn, "kept", now + Duration::hours(1), now);
        for (uid, hash, session) in [(doomed, "hash-doomed", "sess-doomed"), (kept, "hash-kept", "sess-kept")] {
            conn.execute(
                "INSERT INTO auth_tokens (token_hash, user_id, created_at) VALUES (?1, ?2, ?3)",
                params![hash, uid, stamp],
            )
            .expect("token");
            conn.execute(
                "INSERT INTO web_sessions (session_id, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
                params![session, uid, stamp, (now + Duration::days(1)).to_rfc3339()],
            )
            .expect("session");
            create_device(&mx, uid, CredentialKind::Bearer, hash, &stamp).expect("bearer device");
            create_device(&mx, uid, CredentialKind::Web, &web_credential_ref(session), &stamp).expect("web device");
        }
        assert_eq!(list_devices(&mx, doomed).expect("list").len(), 2);

        assert_eq!(gc_pending(&conn, &mut mx, &live, now).expect("gc").deleted, 1);

        assert!(list_devices(&mx, doomed).expect("list").is_empty(), "the deleted account's devices are gone at once");
        assert_eq!(list_devices(&mx, kept).expect("list").len(), 2, "another account's devices stay");
    }

    #[test]
    fn discarding_an_unfinished_checkout_removes_only_a_pending_account_with_no_invoice() {
        let conn = conn();
        let (mut mx, live) = matrix_side();
        let now = Utc::now();
        let key = Credential::random();
        let unfinished = create_pending(&conn, &key, now).expect("create");
        assert!(discard_unfinished(&conn, &mut mx, &live, unfinished).expect("discard"));
        assert!(!exists(&conn, unfinished));

        let (_, with_invoice) = pending_with_invoice(&conn, "held", now + Duration::hours(1), now);
        assert!(!discard_unfinished(&conn, &mut mx, &live, with_invoice).expect("discard"), "a payer already holds an address for it");
        let active = create_pending(&conn, &Credential::random(), now).expect("create");
        activate(&conn, active, now).expect("activate");
        assert!(!discard_unfinished(&conn, &mut mx, &live, active).expect("discard"));
        assert!(!discard_unfinished(&conn, &mut mx, &live, seed_user(&conn, "oauth")).expect("discard"));
    }

    // ------------------------------------------- an account with no OAuth

    #[test]
    fn no_flow_attaches_an_oauth_identity_to_an_anonymous_account() {
        let conn = conn();
        let now = Utc::now();
        let anon = create_pending(&conn, &Credential::random(), now).expect("create");
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
        let anon = create_pending(&conn, &Credential::random(), now).expect("create");
        activate(&conn, anon, now).expect("activate");
        let report = crate::db::cleanup_orphan_users(&conn).expect("sweep");
        assert_eq!(report.removed_recent_self_ref, 0);
        assert!(exists(&conn, anon), "a paid account nobody has entered yet is not an orphan");
    }
}

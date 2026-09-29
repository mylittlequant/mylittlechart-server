//! What an account is entitled to, derived from billing state.
//!
//! "Paid" is the union of four independent legs, all decided in
//! `db::user_is_paid` / [`entitlement_view`]:
//!
//! 1. `users.paid_until` in the future — the legacy leg (gift/trial codes,
//!    operator grants, and every account paid before billing shipped);
//! 2. `users.lifetime_paid = 1` — a paid account, for life;
//! 3. `users.lifetime_anon = 1` — an anonymous account, for life;
//! 4. `users.quant_active_until` in the future — a quant subscription that is
//!    inside a paid period. Quant tiers ALSO carry paid status, per day.
//!
//! The two lifetime flags are a cache of the grant ledger (`grants.rs`: an
//! account holds one exactly while a non-revoked `billing_grants` row says
//! so, so a refund can only take back what its own invoice granted). The
//! quant columns are a cache of the granted invoices' paid periods
//! (`recompute_quant`). Nothing outside `grants.rs` and this module writes
//! either.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, Result};

use super::plans::{Catalog, Grant};
use super::store::{self, GrantState, SubState, SubscriptionRow};

/// Longest run of integer digits accepted in a decimal amount.
const MAX_INTEGER_DIGITS: usize = 12;

/// Micro-units per whole unit.
const MICROS_PER_UNIT: i64 = 1_000_000;

/// The full paid picture of one account.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EntitlementView {
    /// The legacy `paid_until`, only while it is still in the future.
    pub paid_until: Option<String>,
    /// Owns a lifetime paid account.
    pub lifetime_paid: bool,
    /// Owns a lifetime anonymous account.
    pub lifetime_anon: bool,
    /// The quant tier plan id, if the account ever held one.
    pub quant_tier: Option<String>,
    /// End of the quant paid period.
    pub quant_active_until: Option<String>,
    /// The quant period is still running.
    pub quant_active: bool,
    /// Any of the four legs holds.
    pub paid: bool,
}

struct BillingColumns {
    lifetime_paid: bool,
    lifetime_anon: bool,
    quant_tier: Option<String>,
    quant_active_until: Option<String>,
}

fn read_columns(conn: &Connection, user_id: i64) -> Result<Option<BillingColumns>> {
    conn.query_row(
        "SELECT lifetime_paid, lifetime_anon, quant_tier, quant_active_until FROM users WHERE id = ?1",
        params![user_id],
        |row| {
            Ok(BillingColumns {
                lifetime_paid: row.get::<_, i64>(0)? != 0,
                lifetime_anon: row.get::<_, i64>(1)? != 0,
                quant_tier: row.get(2)?,
                quant_active_until: row.get(3)?,
            })
        },
    )
    .optional()
}

/// The paid picture of `user_id`. An unknown account is entitled to nothing.
pub fn entitlement_view(conn: &Connection, user_id: i64, now: DateTime<Utc>) -> Result<EntitlementView> {
    let paid_until = crate::db::user_paid_until(conn, user_id)?;
    let Some(columns) = read_columns(conn, user_id)? else {
        return Ok(EntitlementView::default());
    };
    let quant_active = columns.quant_active_until.as_deref().is_some_and(|t| store::is_future(t, now));
    let paid = paid_until.is_some() || columns.lifetime_paid || columns.lifetime_anon || quant_active;
    Ok(EntitlementView {
        paid_until,
        lifetime_paid: columns.lifetime_paid,
        lifetime_anon: columns.lifetime_anon,
        quant_tier: columns.quant_tier,
        quant_active_until: columns.quant_active_until,
        quant_active,
        paid,
    })
}

/// Whether a billing leg (lifetime flag or running quant period) makes
/// `user_id` paid. The legacy `paid_until` leg is checked by the caller.
pub fn has_entitlement(conn: &Connection, user_id: i64, now: DateTime<Utc>) -> Result<bool> {
    Ok(read_columns(conn, user_id)?.is_some_and(|c| {
        c.lifetime_paid
            || c.lifetime_anon
            || c.quant_active_until.as_deref().is_some_and(|t| store::is_future(t, now))
    }))
}

/// Which of `user_ids` a billing leg makes paid — the batched counterpart of
/// [`has_entitlement`].
pub fn entitled_among(conn: &Connection, user_ids: &[i64], now: DateTime<Utc>) -> Result<HashSet<i64>> {
    let mut entitled = HashSet::new();
    if user_ids.is_empty() {
        return Ok(entitled);
    }
    let placeholders = user_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let mut stmt = conn.prepare(&format!(
        "SELECT id, lifetime_paid, lifetime_anon, quant_active_until FROM users WHERE id IN ({placeholders})"
    ))?;
    let bound: Vec<&dyn rusqlite::ToSql> = user_ids.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
    let mut rows = stmt.query(bound.as_slice())?;
    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let lifetime = row.get::<_, i64>(1)? != 0 || row.get::<_, i64>(2)? != 0;
        let until: Option<String> = row.get(3)?;
        if lifetime || until.as_deref().is_some_and(|t| store::is_future(t, now)) {
            entitled.insert(id);
        }
    }
    Ok(entitled)
}

/// Recompute a monthly subscription's paid-through moment from the invoices
/// that currently grant it, and settle its state to match. Saves `sub`.
pub fn recompute_subscription(conn: &Connection, sub: &mut SubscriptionRow, now: DateTime<Utc>) -> Result<()> {
    let mut latest: Option<DateTime<Utc>> = None;
    if let Some(subscription_id) = sub.subscription_id.as_deref() {
        for invoice in store::invoices_for_subscription(conn, subscription_id)? {
            if invoice.grant_kind != Some(Grant::Quant) || invoice.grant_state != GrantState::Granted {
                continue;
            }
            let Some(end) = invoice
                .period_to
                .as_deref()
                .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
                .map(|t| t.with_timezone(&Utc))
            else {
                continue;
            };
            latest = Some(latest.map_or(end, |current| current.max(end)));
        }
    }
    sub.active_until = latest.map(|t| t.to_rfc3339());
    sub.state = match (sub.state, sub.active_until.is_some()) {
        (SubState::Creating | SubState::Open | SubState::PastDue, true) => SubState::Active,
        (SubState::Active, false) => SubState::Open,
        (state, _) => state,
    };
    store::save_subscription(conn, sub, now)
}

/// Recompute `users.quant_tier` / `quant_active_until` from the account's
/// monthly subscriptions: the running one with the highest tier wins, else
/// the one that ended last, else nothing. `false` when the account is gone.
pub fn recompute_quant(conn: &Connection, catalog: &Catalog, user_id: i64, now: DateTime<Utc>) -> Result<bool> {
    let mut best: Option<(bool, u8, DateTime<Utc>, String, String)> = None;
    for sub in store::subscriptions_for_user(conn, user_id)? {
        let Some(plan) = catalog.get(&sub.plan_id).filter(|p| p.grant == Grant::Quant) else {
            continue;
        };
        let Some(until_text) = sub.active_until.clone() else { continue };
        let Some(until) = DateTime::parse_from_rfc3339(&until_text).ok().map(|t| t.with_timezone(&Utc)) else {
            continue;
        };
        let key = (until > now, plan.tier_rank.unwrap_or(0), until, sub.plan_id.clone(), until_text);
        let better = match &best {
            None => true,
            Some(current) => (key.0, key.1, key.2) > (current.0, current.1, current.2),
        };
        if better {
            best = Some(key);
        }
    }
    let (tier, until) = match best {
        Some((_, _, _, tier, until)) => (Some(tier), Some(until)),
        None => (None, None),
    };
    let changed = conn.execute(
        "UPDATE users SET quant_tier = ?1, quant_active_until = ?2 WHERE id = ?3",
        params![tier, until, user_id],
    )?;
    Ok(changed > 0)
}

// ============================================================================
// Credit
// ============================================================================

/// Parse a non-negative decimal amount (`"3"`, `"3.5"`, `"3.000000"`) into
/// micro-units. More than six fractional digits are truncated, never
/// rounded up. Signs, exponents, empty parts and oversized values are
/// refused.
pub fn parse_micros(raw: &str) -> Option<i64> {
    let raw = raw.trim();
    let (integer, fraction) = raw.split_once('.').unwrap_or((raw, ""));
    let digits_only = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if integer.is_empty()
        || integer.len() > MAX_INTEGER_DIGITS
        || !digits_only(integer)
        || !digits_only(fraction)
        || (raw.contains('.') && fraction.is_empty())
    {
        return None;
    }
    let whole: i64 = integer.parse().ok()?;
    let mut micros: i64 = 0;
    let mut scale = MICROS_PER_UNIT / 10;
    for digit in fraction.bytes().take(6) {
        micros += i64::from(digit - b'0') * scale;
        scale /= 10;
    }
    whole.checked_mul(MICROS_PER_UNIT)?.checked_add(micros)
}

/// Add `micros` (USD micro-units) to the account's credit balance.
pub fn add_credit(conn: &Connection, user_id: i64, micros: i64, now: DateTime<Utc>) -> Result<()> {
    conn.execute(
        "INSERT INTO billing_credit (user_id, balance_micros, updated_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(user_id) DO UPDATE SET
            balance_micros = balance_micros + excluded.balance_micros,
            updated_at = excluded.updated_at",
        params![user_id, micros, now.to_rfc3339()],
    )?;
    Ok(())
}

/// The account's credit balance in USD micro-units (0 when none).
pub fn credit_balance(conn: &Connection, user_id: i64) -> Result<i64> {
    Ok(conn
        .query_row(
            "SELECT balance_micros FROM billing_credit WHERE user_id = ?1",
            params![user_id],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0))
}

// ============================================================================
// Account merge
// ============================================================================

/// Fold `from`'s quant period and credit into `into`: the later quant period
/// wins, credit adds up. (The lifetime grants move with `grants::merge`.)
pub fn merge_entitlements(conn: &Connection, from: i64, into: i64) -> Result<()> {
    if let (Some(a), Some(b)) = (read_columns(conn, from)?, read_columns(conn, into)?) {
        let end = |c: &BillingColumns| {
            c.quant_active_until
                .as_deref()
                .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
                .map(|t| t.with_timezone(&Utc))
        };
        let from_wins = end(&a) > end(&b);
        let (tier, until) = if from_wins {
            (a.quant_tier.clone(), a.quant_active_until.clone())
        } else {
            (b.quant_tier.clone(), b.quant_active_until.clone())
        };
        conn.execute(
            "UPDATE users SET quant_tier = ?1, quant_active_until = ?2 WHERE id = ?3",
            params![tier, until, into],
        )?;
    }
    let from_credit = credit_balance(conn, from)?;
    if from_credit != 0 {
        add_credit(conn, into, from_credit, Utc::now())?;
    }
    conn.execute("DELETE FROM billing_credit WHERE user_id = ?1", params![from])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::plans::AccountPlanIds;
    use crate::billing::store::{InvoiceKind, InvoiceRow};
    use crate::billing::testkit::{conn, seed_user};
    use chrono::Duration;
    use std::collections::BTreeMap;

    fn catalog() -> Catalog {
        Catalog::build(&AccountPlanIds::default(), &BTreeMap::new())
    }

    #[test]
    fn a_fresh_account_is_entitled_to_nothing() {
        let conn = conn();
        let uid = seed_user(&conn, "a");
        let view = entitlement_view(&conn, uid, Utc::now()).expect("view");
        assert_eq!(view, EntitlementView::default());
        assert!(!has_entitlement(&conn, uid, Utc::now()).expect("has"));
    }

    #[test]
    fn an_unknown_account_is_entitled_to_nothing() {
        let conn = conn();
        assert_eq!(entitlement_view(&conn, 9999, Utc::now()).expect("view"), EntitlementView::default());
        assert!(!has_entitlement(&conn, 9999, Utc::now()).expect("has"));
    }

    #[test]
    fn each_leg_alone_makes_the_account_paid() {
        let conn = conn();
        let now = Utc::now();
        let legacy = seed_user(&conn, "legacy");
        let paid = seed_user(&conn, "paid");
        let anon = seed_user(&conn, "anon");
        let quant = seed_user(&conn, "quant");
        let none = seed_user(&conn, "none");
        crate::db::set_user_paid_until(&conn, legacy, Some(&(now + Duration::days(3)).to_rfc3339())).expect("legacy");
        crate::billing::grants::grant_for_invoice(&conn, paid, Grant::LifetimePaid, "inv_p", now).expect("paid");
        crate::billing::grants::grant_for_invoice(&conn, anon, Grant::LifetimeAnon, "inv_a", now).expect("anon");
        conn.execute(
            "UPDATE users SET quant_tier = 'mlc-monthly-20-v1', quant_active_until = ?1 WHERE id = ?2",
            params![(now + Duration::days(1)).to_rfc3339(), quant],
        )
        .expect("quant");
        for uid in [legacy, paid, anon, quant] {
            assert!(entitlement_view(&conn, uid, now).expect("view").paid, "user {uid}");
            assert!(crate::db::user_is_paid(&conn, uid).expect("is_paid"), "user {uid}");
        }
        assert!(!entitlement_view(&conn, none, now).expect("view").paid);
        assert!(!crate::db::user_is_paid(&conn, none).expect("is_paid"));

        let batch = crate::db::users_paid_batch(&conn, &[legacy, paid, anon, quant, none]).expect("batch");
        assert_eq!(batch.get(&legacy), Some(&true));
        assert_eq!(batch.get(&paid), Some(&true));
        assert_eq!(batch.get(&anon), Some(&true));
        assert_eq!(batch.get(&quant), Some(&true));
        assert_eq!(batch.get(&none), Some(&false));
    }

    #[test]
    fn an_ended_quant_period_stops_being_paid_without_anyone_flipping_a_flag() {
        let conn = conn();
        let now = Utc::now();
        let uid = seed_user(&conn, "lapsed");
        conn.execute(
            "UPDATE users SET quant_tier = 'mlc-monthly-20-v1', quant_active_until = ?1 WHERE id = ?2",
            params![(now - Duration::hours(1)).to_rfc3339(), uid],
        )
        .expect("quant");
        let view = entitlement_view(&conn, uid, now).expect("view");
        assert!(!view.paid);
        assert!(!view.quant_active);
        assert_eq!(view.quant_tier.as_deref(), Some("mlc-monthly-20-v1"));
        assert!(!crate::db::user_is_paid(&conn, uid).expect("is_paid"));
    }

    #[test]
    fn a_legacy_paid_until_user_stays_paid_with_no_billing_columns_set() {
        let conn = conn();
        let uid = seed_user(&conn, "grandfathered");
        crate::db::set_user_paid_until(&conn, uid, Some("2999-01-01T00:00:00+00:00")).expect("paid");
        assert!(crate::db::user_is_paid(&conn, uid).expect("is_paid"));
        let view = entitlement_view(&conn, uid, Utc::now()).expect("view");
        assert!(view.paid);
        assert!(!view.lifetime_paid && !view.lifetime_anon);
    }

    #[test]
    fn parse_micros_is_exact_and_strict() {
        assert_eq!(parse_micros("3"), Some(3_000_000));
        assert_eq!(parse_micros("3.5"), Some(3_500_000));
        assert_eq!(parse_micros("3.000001"), Some(3_000_001));
        assert_eq!(parse_micros("0.000000"), Some(0));
        assert_eq!(parse_micros("1.1234567"), Some(1_123_456));
        assert_eq!(parse_micros(" 12.50 "), Some(12_500_000));
        for bad in ["", ".", "1.", ".5", "-1", "+1", "1e3", "1,5", "abc", "1.2.3", "9999999999999"] {
            assert_eq!(parse_micros(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn credit_accumulates_and_reads_back() {
        let conn = conn();
        let uid = seed_user(&conn, "credit");
        assert_eq!(credit_balance(&conn, uid).expect("balance"), 0);
        add_credit(&conn, uid, 2_500_000, Utc::now()).expect("credit");
        add_credit(&conn, uid, 500_000, Utc::now()).expect("credit");
        assert_eq!(credit_balance(&conn, uid).expect("balance"), 3_000_000);
    }

    fn quant_invoice(user_id: i64, subscription_id: &str, invoice_id: &str, to: DateTime<Utc>, state: GrantState) -> InvoiceRow {
        InvoiceRow {
            invoice_id: invoice_id.to_string(),
            user_id,
            subscription_id: subscription_id.to_string(),
            plan_id: "mlc-monthly-20-v1".to_string(),
            kind: InvoiceKind::Renewal,
            status: "settled".to_string(),
            pay_json: "[]".to_string(),
            expires_at: None,
            flags: Vec::new(),
            grant_kind: Some(Grant::Quant),
            grant_state: state,
            period_from: Some((to - Duration::days(30)).to_rfc3339()),
            period_to: Some(to.to_rfc3339()),
            detail: serde_json::json!({}),
        }
    }

    fn seed_subscription(conn: &Connection, user_id: i64, key: &str, sub_id: &str, plan_id: &str) -> SubscriptionRow {
        let now = Utc::now();
        conn.execute(
            "INSERT INTO billing_subscriptions
                (checkout_key, user_id, plan_id, subscription_id, external_user_ref, state, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?2, 'open', ?5, ?5)",
            params![key, user_id, plan_id, sub_id, now.to_rfc3339()],
        )
        .expect("seed subscription");
        store::subscription_by_id(conn, sub_id).expect("read").expect("row")
    }

    #[test]
    fn the_subscription_period_is_the_latest_granted_invoice_and_falls_back_on_revoke() {
        let conn = conn();
        let now = Utc::now();
        let uid = seed_user(&conn, "sub");
        let mut sub = seed_subscription(&conn, uid, "k1", "sub_1", "mlc-monthly-20-v1");
        let first_end = now + Duration::days(10);
        let second_end = now + Duration::days(40);
        store::insert_invoice(&conn, &quant_invoice(uid, "sub_1", "inv_1", first_end, GrantState::Granted), now).expect("inv1");
        store::insert_invoice(&conn, &quant_invoice(uid, "sub_1", "inv_2", second_end, GrantState::Granted), now).expect("inv2");
        recompute_subscription(&conn, &mut sub, now).expect("recompute");
        assert_eq!(sub.state, SubState::Active);
        assert_eq!(sub.active_until.as_deref(), Some(second_end.to_rfc3339().as_str()));

        // Revoke the latest one: the period falls back to the earlier grant.
        let mut second = store::invoice_by_id(&conn, "inv_2").expect("read").expect("inv2");
        second.grant_state = GrantState::Revoked;
        store::save_invoice(&conn, &second, now).expect("save");
        recompute_subscription(&conn, &mut sub, now).expect("recompute");
        assert_eq!(sub.active_until.as_deref(), Some(first_end.to_rfc3339().as_str()));

        // Revoke the last one: nothing is running any more.
        let mut first = store::invoice_by_id(&conn, "inv_1").expect("read").expect("inv1");
        first.grant_state = GrantState::Revoked;
        store::save_invoice(&conn, &first, now).expect("save");
        recompute_subscription(&conn, &mut sub, now).expect("recompute");
        assert_eq!(sub.active_until, None);
        assert_eq!(sub.state, SubState::Open);
    }

    #[test]
    fn the_running_highest_tier_wins_the_user_columns() {
        let conn = conn();
        let now = Utc::now();
        let uid = seed_user(&conn, "tiers");
        let catalog = catalog();
        let mut low = seed_subscription(&conn, uid, "k1", "sub_low", "mlc-monthly-20-v1");
        let mut high = seed_subscription(&conn, uid, "k2", "sub_high", "mlc-monthly-100-v1");
        store::insert_invoice(&conn, &quant_invoice(uid, "sub_low", "i_low", now + Duration::days(20), GrantState::Granted), now).expect("low");
        let mut high_invoice = quant_invoice(uid, "sub_high", "i_high", now + Duration::days(5), GrantState::Granted);
        high_invoice.plan_id = "mlc-monthly-100-v1".to_string();
        store::insert_invoice(&conn, &high_invoice, now).expect("high");
        recompute_subscription(&conn, &mut low, now).expect("low");
        recompute_subscription(&conn, &mut high, now).expect("high");
        assert!(recompute_quant(&conn, &catalog, uid, now).expect("recompute"));
        let view = entitlement_view(&conn, uid, now).expect("view");
        assert_eq!(view.quant_tier.as_deref(), Some("mlc-monthly-100-v1"));
        assert!(view.quant_active && view.paid);
    }

    #[test]
    fn recompute_quant_clears_the_columns_when_nothing_is_left() {
        let conn = conn();
        let now = Utc::now();
        let uid = seed_user(&conn, "clear");
        conn.execute(
            "UPDATE users SET quant_tier = 'mlc-monthly-20-v1', quant_active_until = ?1 WHERE id = ?2",
            params![(now + Duration::days(1)).to_rfc3339(), uid],
        )
        .expect("quant");
        assert!(recompute_quant(&conn, &catalog(), uid, now).expect("recompute"));
        let view = entitlement_view(&conn, uid, now).expect("view");
        assert_eq!(view.quant_tier, None);
        assert!(!view.paid);
    }

    #[test]
    fn merging_accounts_keeps_the_later_quant_adds_credit_and_moves_the_grants() {
        let conn = conn();
        let now = Utc::now();
        let from = seed_user(&conn, "from");
        let into = seed_user(&conn, "into");
        crate::billing::grants::grant_for_invoice(&conn, from, Grant::LifetimeAnon, "inv_a", now).expect("anon");
        crate::billing::grants::grant_for_invoice(&conn, into, Grant::LifetimePaid, "inv_p", now).expect("paid");
        conn.execute(
            "UPDATE users SET quant_tier = 'mlc-monthly-50-v1', quant_active_until = ?1 WHERE id = ?2",
            params![(now + Duration::days(20)).to_rfc3339(), from],
        )
        .expect("from quant");
        conn.execute(
            "UPDATE users SET quant_tier = 'mlc-monthly-20-v1', quant_active_until = ?1 WHERE id = ?2",
            params![(now + Duration::days(5)).to_rfc3339(), into],
        )
        .expect("into quant");
        add_credit(&conn, from, 1_000_000, now).expect("credit from");
        add_credit(&conn, into, 250_000, now).expect("credit into");

        merge_entitlements(&conn, from, into).expect("merge");
        crate::billing::grants::merge(&conn, from, into).expect("merge grants");
        let view = entitlement_view(&conn, into, now).expect("view");
        assert!(view.lifetime_paid && view.lifetime_anon);
        assert_eq!(view.quant_tier.as_deref(), Some("mlc-monthly-50-v1"));
        assert_eq!(credit_balance(&conn, into).expect("balance"), 1_250_000);
        assert_eq!(credit_balance(&conn, from).expect("balance"), 0);
    }

    #[test]
    fn migrate_is_idempotent_and_upgrades_a_pre_billing_users_table() {
        let conn = Connection::open_in_memory().expect("mem");
        conn.execute_batch("CREATE TABLE users (id INTEGER PRIMARY KEY, paid_until TEXT);").expect("legacy users");
        store::migrate(&conn).expect("first migrate");
        store::migrate(&conn).expect("second migrate");
        store::migrate(&conn).expect("third migrate");
        conn.execute("INSERT INTO users (id) VALUES (1)", []).expect("insert");
        let (paid, anon): (i64, i64) = conn
            .query_row("SELECT lifetime_paid, lifetime_anon FROM users WHERE id = 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("defaults");
        assert_eq!((paid, anon), (0, 0));
        let columns: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('users') WHERE name IN ('lifetime_paid','lifetime_anon','quant_tier','quant_active_until')",
                [],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(columns, 4);
        for table in ["billing_subscribers", "billing_subscriptions", "billing_invoices", "billing_events", "billing_credit"] {
            let exists: i64 = conn
                .query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1", params![table], |r| r.get(0))
                .expect("exists");
            assert_eq!(exists, 1, "{table}");
        }
    }
}

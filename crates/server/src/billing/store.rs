//! Billing tables in the identity database: schema, row types, and the plain
//! reads and writes over them. Entitlement arithmetic lives in
//! `entitle.rs`; event handling in `webhook.rs`.
//!
//! None of these tables has a foreign key to `users`: a payment record must
//! outlive its account (a deleted or merged account must never block, or be
//! resurrected by, a late webhook), so `user_id` is a plain integer.
//!
//! Tables:
//! * `billing_subscribers` — `user_id` → the dig2pay customer id
//!   (`POST /subscribers`), one per account.
//! * `billing_subscriptions` — one row per dig2pay subscription MLC created.
//!   The row exists before dig2pay is called (state `creating`) and its
//!   `checkout_key` is the `Idempotency-Key` of `POST /subscriptions`, so a
//!   retry after a timeout resumes the same purchase.
//! * `billing_invoices` — every invoice MLC knows about, with what it granted
//!   (`grant_kind`/`grant_state`), so a refund or a reorg can revoke exactly
//!   that. Also what makes `GET /api/billing/invoice/{id}` owner-scoped.
//! * `billing_events` — every webhook delivery, keyed by dig2pay's event id
//!   (the dedup key), with the raw body and what was done about it.
//! * `billing_credit` — the per-account credit balance (overpayments).
//! * `billing_grants` — the lifetime-grant ledger (see `grants.rs`): the
//!   lifetime flags are derived from it.
//! * `billing_anon_accounts` — anonymous ("numbered") accounts: the SHA-256
//!   of their account key and whether payment has activated them (see
//!   `anon.rs`).

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, Result, Row};
use serde_json::Value;

use super::plans::{Catalog, Grant, Plan};

// ============================================================================
// Schema
// ============================================================================

/// Create every billing table and add the entitlement columns to `users`.
///
/// Additive and idempotent: every statement is `IF NOT EXISTS` or guarded by
/// a `pragma_table_info` check, so running it on every boot, on a fresh
/// database, or on a database a previous version already migrated changes
/// nothing. Errors propagate — unlike the older `let _ = ALTER ...` idiom in
/// `db::init_db`, a real failure here is not swallowed.
pub fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS billing_subscribers (
            user_id           INTEGER PRIMARY KEY,
            subscriber_id     TEXT    NOT NULL UNIQUE,
            external_user_ref TEXT    NOT NULL,
            created_at        TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS billing_subscriptions (
            checkout_key       TEXT    PRIMARY KEY,
            user_id            INTEGER NOT NULL,
            plan_id            TEXT    NOT NULL,
            subscription_id    TEXT    UNIQUE,
            external_user_ref  TEXT    NOT NULL,
            state              TEXT    NOT NULL,
            active_until       TEXT,
            pending_change_id  TEXT,
            pending_plan_id    TEXT,
            last_change_id     TEXT,
            change_seq         INTEGER NOT NULL DEFAULT 0,
            created_at         TEXT    NOT NULL,
            updated_at         TEXT    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_billing_subscriptions_user
            ON billing_subscriptions(user_id);

        CREATE TABLE IF NOT EXISTS billing_invoices (
            invoice_id      TEXT    PRIMARY KEY,
            user_id         INTEGER NOT NULL,
            subscription_id TEXT    NOT NULL,
            plan_id         TEXT    NOT NULL,
            kind            TEXT    NOT NULL,
            status          TEXT    NOT NULL,
            pay_json        TEXT    NOT NULL DEFAULT '[]',
            expires_at      TEXT,
            flags_json      TEXT    NOT NULL DEFAULT '[]',
            grant_kind      TEXT,
            grant_state     TEXT    NOT NULL DEFAULT 'none',
            period_from     TEXT,
            period_to       TEXT,
            detail_json     TEXT    NOT NULL DEFAULT '{}',
            created_at      TEXT    NOT NULL,
            updated_at      TEXT    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_billing_invoices_user
            ON billing_invoices(user_id);
        CREATE INDEX IF NOT EXISTS idx_billing_invoices_subscription
            ON billing_invoices(subscription_id);

        CREATE TABLE IF NOT EXISTS billing_events (
            event_id        TEXT    PRIMARY KEY,
            kind            TEXT    NOT NULL,
            user_id         INTEGER,
            subscription_id TEXT,
            invoice_id      TEXT,
            outcome         TEXT    NOT NULL,
            body            TEXT    NOT NULL,
            received_at     TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS billing_credit (
            user_id        INTEGER PRIMARY KEY,
            balance_micros INTEGER NOT NULL DEFAULT 0,
            updated_at     TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS billing_grants (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            grant_kind  TEXT    NOT NULL,
            source      TEXT    NOT NULL,
            source_ref  TEXT    NOT NULL,
            created_at  TEXT    NOT NULL,
            revoked_at  TEXT
        );
        CREATE UNIQUE INDEX IF NOT EXISTS uq_billing_grants_in_force
            ON billing_grants(user_id, grant_kind, source, source_ref) WHERE revoked_at IS NULL;
        CREATE INDEX IF NOT EXISTS idx_billing_grants_user ON billing_grants(user_id);
        CREATE INDEX IF NOT EXISTS idx_billing_grants_source ON billing_grants(source, source_ref);

        CREATE TABLE IF NOT EXISTS billing_anon_accounts (
            user_id      INTEGER PRIMARY KEY,
            key_hash     TEXT    NOT NULL UNIQUE,
            status       TEXT    NOT NULL,
            created_at   TEXT    NOT NULL,
            activated_at TEXT,
            rotated_at   TEXT
        );",
    )?;
    add_column_if_missing(conn, "users", "lifetime_paid", "INTEGER NOT NULL DEFAULT 0")?;
    add_column_if_missing(conn, "users", "lifetime_anon", "INTEGER NOT NULL DEFAULT 0")?;
    add_column_if_missing(conn, "users", "quant_tier", "TEXT")?;
    add_column_if_missing(conn, "users", "quant_active_until", "TEXT")?;
    // The lifetime flags are a cache of the grant ledger: seed the ledger
    // from anything a pre-ledger version granted, then make the cache match
    // it. Both steps are idempotent and cheap, so they run on every boot.
    super::grants::backfill_from_invoices(conn)?;
    super::grants::rebuild_all_caches(conn)?;
    Ok(())
}

pub(crate) fn add_column_if_missing(conn: &Connection, table: &str, column: &str, declaration: &str) -> Result<()> {
    let present: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name = ?2",
        params![table, column],
        |row| row.get(0),
    )?;
    if present == 0 {
        conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {declaration};"))?;
    }
    Ok(())
}

// ============================================================================
// Row types
// ============================================================================

/// Where a dig2pay subscription stands from MLC's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubState {
    /// The row exists; dig2pay has not answered `POST /subscriptions` yet.
    Creating,
    /// dig2pay created it; the first invoice is unpaid.
    Open,
    /// A monthly subscription with a paid period.
    Active,
    /// dig2pay reported a renewal invoice went unpaid.
    PastDue,
    /// dig2pay reported the subscription cancelled (paid time stays valid).
    Cancelled,
    /// A one-time plan settled: terminal.
    Paid,
}

impl SubState {
    /// Storage/wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            SubState::Creating => "creating",
            SubState::Open => "open",
            SubState::Active => "active",
            SubState::PastDue => "past_due",
            SubState::Cancelled => "cancelled",
            SubState::Paid => "paid",
        }
    }

    fn parse(raw: &str) -> Option<SubState> {
        match raw {
            "creating" => Some(SubState::Creating),
            "open" => Some(SubState::Open),
            "active" => Some(SubState::Active),
            "past_due" => Some(SubState::PastDue),
            "cancelled" => Some(SubState::Cancelled),
            "paid" => Some(SubState::Paid),
            _ => None,
        }
    }
}

/// Which kind of invoice a row is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvoiceKind {
    /// The first invoice of a subscription.
    Initial,
    /// A later period's invoice, created by dig2pay.
    Renewal,
    /// The side charge of a plan upgrade; the entitlement follows
    /// `subscription_changed`, not this invoice.
    Proration,
}

impl InvoiceKind {
    /// Storage/wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            InvoiceKind::Initial => "initial",
            InvoiceKind::Renewal => "renewal",
            InvoiceKind::Proration => "proration",
        }
    }

    fn parse(raw: &str) -> Option<InvoiceKind> {
        match raw {
            "initial" => Some(InvoiceKind::Initial),
            "renewal" => Some(InvoiceKind::Renewal),
            "proration" => Some(InvoiceKind::Proration),
            _ => None,
        }
    }
}

/// What an invoice currently contributes to the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantState {
    /// Nothing granted (unpaid, or nothing to grant).
    None,
    /// The entitlement is in force.
    Granted,
    /// A settled payment was reorged out; revoked provisionally and restored
    /// if the invoice is seen settled again.
    Reverted,
    /// Refunded: final.
    Revoked,
}

impl GrantState {
    /// Storage/wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            GrantState::None => "none",
            GrantState::Granted => "granted",
            GrantState::Reverted => "reverted",
            GrantState::Revoked => "revoked",
        }
    }

    fn parse(raw: &str) -> Option<GrantState> {
        match raw {
            "none" => Some(GrantState::None),
            "granted" => Some(GrantState::Granted),
            "reverted" => Some(GrantState::Reverted),
            "revoked" => Some(GrantState::Revoked),
            _ => None,
        }
    }
}

/// `invoice.status` values MLC writes itself.
pub const INVOICE_NEW: &str = "new";
/// A settled payment was recorded.
pub const INVOICE_SETTLED: &str = "settled";
/// A settled payment was reorged out.
pub const INVOICE_REVERTED: &str = "reverted";
/// A refund was recorded.
pub const INVOICE_REFUNDED: &str = "refunded";

/// One `billing_subscriptions` row.
#[derive(Debug, Clone)]
pub struct SubscriptionRow {
    /// `Idempotency-Key` of `POST /subscriptions`; the primary key.
    pub checkout_key: String,
    /// Owning account.
    pub user_id: i64,
    /// The subscription's CURRENT plan (a monthly plan changes over time).
    pub plan_id: String,
    /// dig2pay's subscription id; `None` while `creating`.
    pub subscription_id: Option<String>,
    /// The `external_user_ref` dig2pay knows this account by. Kept on the row
    /// so a webhook can be cross-checked even after an account merge.
    pub external_user_ref: String,
    /// Lifecycle state.
    pub state: SubState,
    /// Latest paid-through moment of a monthly subscription.
    pub active_until: Option<String>,
    /// A requested change not yet applied.
    pub pending_change_id: Option<String>,
    /// The plan that pending change moves to.
    pub pending_plan_id: Option<String>,
    /// The last change applied (kept for reconciliation).
    pub last_change_id: Option<String>,
    /// Counts change requests; part of their `Idempotency-Key`.
    pub change_seq: i64,
}

const SUB_COLUMNS: &str = "checkout_key, user_id, plan_id, subscription_id, external_user_ref, state, \
     active_until, pending_change_id, pending_plan_id, last_change_id, change_seq";

fn conversion_error(column: usize, what: &str, value: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        rusqlite::types::Type::Text,
        format!("unknown {what} {value:?}").into(),
    )
}

fn subscription_from_row(row: &Row<'_>) -> Result<SubscriptionRow> {
    let state: String = row.get(5)?;
    Ok(SubscriptionRow {
        checkout_key: row.get(0)?,
        user_id: row.get(1)?,
        plan_id: row.get(2)?,
        subscription_id: row.get(3)?,
        external_user_ref: row.get(4)?,
        state: SubState::parse(&state).ok_or_else(|| conversion_error(5, "subscription state", &state))?,
        active_until: row.get(6)?,
        pending_change_id: row.get(7)?,
        pending_plan_id: row.get(8)?,
        last_change_id: row.get(9)?,
        change_seq: row.get(10)?,
    })
}

/// One `billing_invoices` row.
#[derive(Debug, Clone)]
pub struct InvoiceRow {
    /// dig2pay's invoice-group id.
    pub invoice_id: String,
    /// Owning account.
    pub user_id: i64,
    /// dig2pay's subscription id.
    pub subscription_id: String,
    /// The plan this invoice was issued under.
    pub plan_id: String,
    /// Initial, renewal, or proration.
    pub kind: InvoiceKind,
    /// MLC's own status word (`new`, `settled`, `reverted`, `refunded`).
    pub status: String,
    /// The `pay[]` options handed out at checkout, as JSON.
    pub pay_json: String,
    /// When the payment options expire, RFC 3339.
    pub expires_at: Option<String>,
    /// Integrity flags recorded from webhooks (`late`, `partial`, `over`, ...).
    pub flags: Vec<String>,
    /// What settling this invoice granted.
    pub grant_kind: Option<Grant>,
    /// Whether that grant is in force.
    pub grant_state: GrantState,
    /// The paid period start (quant invoices).
    pub period_from: Option<String>,
    /// The paid period end (quant invoices).
    pub period_to: Option<String>,
    /// Structured notes from integrity events, keyed by event kind.
    pub detail: Value,
}

const INVOICE_COLUMNS: &str = "invoice_id, user_id, subscription_id, plan_id, kind, status, pay_json, \
     expires_at, flags_json, grant_kind, grant_state, period_from, period_to, detail_json";

fn invoice_from_row(row: &Row<'_>) -> Result<InvoiceRow> {
    let kind: String = row.get(4)?;
    let flags_json: String = row.get(8)?;
    let grant_kind: Option<String> = row.get(9)?;
    let grant_state: String = row.get(10)?;
    let detail_json: String = row.get(13)?;
    Ok(InvoiceRow {
        invoice_id: row.get(0)?,
        user_id: row.get(1)?,
        subscription_id: row.get(2)?,
        plan_id: row.get(3)?,
        kind: InvoiceKind::parse(&kind).ok_or_else(|| conversion_error(4, "invoice kind", &kind))?,
        status: row.get(5)?,
        pay_json: row.get(6)?,
        expires_at: row.get(7)?,
        flags: serde_json::from_str(&flags_json).map_err(|e| conversion_error(8, "flags json", &e.to_string()))?,
        grant_kind: match grant_kind {
            Some(raw) => Some(Grant::parse(&raw).ok_or_else(|| conversion_error(9, "grant kind", &raw))?),
            None => None,
        },
        grant_state: GrantState::parse(&grant_state)
            .ok_or_else(|| conversion_error(10, "grant state", &grant_state))?,
        period_from: row.get(11)?,
        period_to: row.get(12)?,
        detail: serde_json::from_str(&detail_json)
            .map_err(|e| conversion_error(13, "detail json", &e.to_string()))?,
    })
}

// ============================================================================
// Time
// ============================================================================

/// Whether the RFC 3339 `ts` lies after `now`. Unparsable is not future.
pub fn is_future(ts: &str, now: DateTime<Utc>) -> bool {
    DateTime::parse_from_rfc3339(ts).is_ok_and(|t| t.with_timezone(&Utc) > now)
}

// ============================================================================
// Customers
// ============================================================================

/// The dig2pay customer id recorded for `user_id`, if any.
pub fn customer_for_user(conn: &Connection, user_id: i64) -> Result<Option<String>> {
    conn.query_row(
        "SELECT subscriber_id FROM billing_subscribers WHERE user_id = ?1",
        params![user_id],
        |row| row.get(0),
    )
    .optional()
}

/// Record the dig2pay customer for `user_id`. A second call for the same
/// account keeps the first row.
pub fn record_customer(
    conn: &Connection,
    user_id: i64,
    subscriber_id: &str,
    external_user_ref: &str,
    now: DateTime<Utc>,
) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO billing_subscribers (user_id, subscriber_id, external_user_ref, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![user_id, subscriber_id, external_user_ref, now.to_rfc3339()],
    )?;
    Ok(())
}

// ============================================================================
// Subscriptions
// ============================================================================

/// The subscription with dig2pay id `subscription_id`.
pub fn subscription_by_id(conn: &Connection, subscription_id: &str) -> Result<Option<SubscriptionRow>> {
    conn.query_row(
        &format!("SELECT {SUB_COLUMNS} FROM billing_subscriptions WHERE subscription_id = ?1"),
        params![subscription_id],
        subscription_from_row,
    )
    .optional()
}

/// Every subscription of `user_id`, newest first.
pub fn subscriptions_for_user(conn: &Connection, user_id: i64) -> Result<Vec<SubscriptionRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {SUB_COLUMNS} FROM billing_subscriptions WHERE user_id = ?1 ORDER BY created_at DESC, rowid DESC"
    ))?;
    let rows = stmt.query_map(params![user_id], subscription_from_row)?;
    rows.collect()
}

/// Write back every mutable column of `sub`.
pub fn save_subscription(conn: &Connection, sub: &SubscriptionRow, now: DateTime<Utc>) -> Result<()> {
    conn.execute(
        "UPDATE billing_subscriptions SET
            user_id = ?2, plan_id = ?3, subscription_id = ?4, state = ?5, active_until = ?6,
            pending_change_id = ?7, pending_plan_id = ?8, last_change_id = ?9, change_seq = ?10,
            updated_at = ?11
         WHERE checkout_key = ?1",
        params![
            sub.checkout_key,
            sub.user_id,
            sub.plan_id,
            sub.subscription_id,
            sub.state.as_str(),
            sub.active_until,
            sub.pending_change_id,
            sub.pending_plan_id,
            sub.last_change_id,
            sub.change_seq,
            now.to_rfc3339(),
        ],
    )?;
    Ok(())
}

/// The monthly subscription that is currently in force for `user_id`
/// (`active` or `past_due`), if any. `catalog` says which plans are monthly.
pub fn live_quant_subscription(
    conn: &Connection,
    catalog: &Catalog,
    user_id: i64,
) -> Result<Option<SubscriptionRow>> {
    Ok(subscriptions_for_user(conn, user_id)?.into_iter().find(|sub| {
        matches!(sub.state, SubState::Active | SubState::PastDue)
            && catalog.get(&sub.plan_id).is_some_and(|p| p.grant == Grant::Quant)
    }))
}

// ============================================================================
// Invoices
// ============================================================================

/// The invoice with this id, whoever owns it. Webhook use only; anything
/// user-facing goes through [`invoice_for_user`].
pub fn invoice_by_id(conn: &Connection, invoice_id: &str) -> Result<Option<InvoiceRow>> {
    conn.query_row(
        &format!("SELECT {INVOICE_COLUMNS} FROM billing_invoices WHERE invoice_id = ?1"),
        params![invoice_id],
        invoice_from_row,
    )
    .optional()
}

/// The invoice with this id IF it belongs to `user_id`. Another account's
/// invoice and an unknown id are indistinguishable (`None`).
pub fn invoice_for_user(conn: &Connection, user_id: i64, invoice_id: &str) -> Result<Option<InvoiceRow>> {
    conn.query_row(
        &format!("SELECT {INVOICE_COLUMNS} FROM billing_invoices WHERE invoice_id = ?1 AND user_id = ?2"),
        params![invoice_id, user_id],
        invoice_from_row,
    )
    .optional()
}

/// Every invoice of `subscription_id`, oldest first.
pub fn invoices_for_subscription(conn: &Connection, subscription_id: &str) -> Result<Vec<InvoiceRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {INVOICE_COLUMNS} FROM billing_invoices WHERE subscription_id = ?1 ORDER BY created_at ASC, rowid ASC"
    ))?;
    let rows = stmt.query_map(params![subscription_id], invoice_from_row)?;
    rows.collect()
}

/// Every invoice of `user_id`, newest first.
pub fn invoices_for_user(conn: &Connection, user_id: i64) -> Result<Vec<InvoiceRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {INVOICE_COLUMNS} FROM billing_invoices WHERE user_id = ?1 ORDER BY created_at DESC, rowid DESC"
    ))?;
    let rows = stmt.query_map(params![user_id], invoice_from_row)?;
    rows.collect()
}

/// Invoices of `user_id` that are still waiting for payment.
pub fn unpaid_invoices_for_user(conn: &Connection, user_id: i64) -> Result<Vec<InvoiceRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {INVOICE_COLUMNS} FROM billing_invoices
         WHERE user_id = ?1 AND grant_state = 'none' AND status = 'new'
         ORDER BY created_at DESC, rowid DESC"
    ))?;
    let rows = stmt.query_map(params![user_id], invoice_from_row)?;
    rows.collect()
}

/// Correct an invoice's kind to what the processor reports
/// (`GET /invoices/{id}`'s `kind`). Only ever applied to an invoice that has
/// granted nothing yet, so no entitlement is left resting on the old kind.
pub fn set_invoice_kind(conn: &Connection, invoice_id: &str, kind: InvoiceKind, now: DateTime<Utc>) -> Result<()> {
    conn.execute(
        "UPDATE billing_invoices SET kind = ?2, updated_at = ?3 WHERE invoice_id = ?1 AND grant_state = 'none'",
        params![invoice_id, kind.as_str(), now.to_rfc3339()],
    )?;
    Ok(())
}

/// Insert `invoice`; an id already present is left untouched.
pub fn insert_invoice(conn: &Connection, invoice: &InvoiceRow, now: DateTime<Utc>) -> Result<()> {
    let now = now.to_rfc3339();
    conn.execute(
        "INSERT OR IGNORE INTO billing_invoices
            (invoice_id, user_id, subscription_id, plan_id, kind, status, pay_json, expires_at,
             flags_json, grant_kind, grant_state, period_from, period_to, detail_json, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?15)",
        params![
            invoice.invoice_id,
            invoice.user_id,
            invoice.subscription_id,
            invoice.plan_id,
            invoice.kind.as_str(),
            invoice.status,
            invoice.pay_json,
            invoice.expires_at,
            Value::from(invoice.flags.clone()).to_string(),
            invoice.grant_kind.map(Grant::as_str),
            invoice.grant_state.as_str(),
            invoice.period_from,
            invoice.period_to,
            invoice.detail.to_string(),
            now,
        ],
    )?;
    Ok(())
}

/// Write back every mutable column of `invoice`.
pub fn save_invoice(conn: &Connection, invoice: &InvoiceRow, now: DateTime<Utc>) -> Result<()> {
    conn.execute(
        "UPDATE billing_invoices SET
            status = ?2, flags_json = ?3, grant_kind = ?4, grant_state = ?5,
            period_from = ?6, period_to = ?7, detail_json = ?8, updated_at = ?9
         WHERE invoice_id = ?1",
        params![
            invoice.invoice_id,
            invoice.status,
            Value::from(invoice.flags.clone()).to_string(),
            invoice.grant_kind.map(Grant::as_str),
            invoice.grant_state.as_str(),
            invoice.period_from,
            invoice.period_to,
            invoice.detail.to_string(),
            now.to_rfc3339(),
        ],
    )?;
    Ok(())
}

// ============================================================================
// Checkout
// ============================================================================

/// Why a checkout was refused before dig2pay was called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The account already holds a lifetime paid account.
    AlreadyOwned,
    /// The account already has a running monthly subscription; use change.
    SubscriptionExists,
}

/// What `POST /api/billing/checkout` has to do next.
#[derive(Debug)]
pub enum Prepared {
    /// Refused; nothing was written.
    Refused(Refusal),
    /// An unpaid, unexpired invoice for this exact plan exists: hand it back.
    Existing(Box<InvoiceRow>),
    /// Call dig2pay. `checkout_key` is the `Idempotency-Key` of
    /// `POST /subscriptions` (stable across a retry); `customer` is the
    /// dig2pay customer id if one is already recorded.
    Create {
        /// `Idempotency-Key` for `POST /subscriptions`.
        checkout_key: String,
        /// Recorded dig2pay customer id.
        customer: Option<String>,
        /// The `external_user_ref` for this account.
        external_user_ref: String,
    },
}

/// Decide what checkout of `plan` by `user_id` has to do, and reserve the
/// idempotency key. `new_key` supplies a fresh key when one is needed.
pub fn prepare_checkout(
    conn: &Connection,
    catalog: &Catalog,
    user_id: i64,
    plan: &Plan,
    now: DateTime<Utc>,
    new_key: impl FnOnce() -> String,
) -> Result<Prepared> {
    match plan.grant {
        // A paid account the caller already holds (bought directly, or
        // implied by an anonymous purchase) is not sold twice, and nothing is
        // created on the processor for the refused attempt.
        Grant::LifetimePaid => {
            if super::entitle::entitlement_view(conn, user_id, now)?.lifetime_paid {
                return Ok(Prepared::Refused(Refusal::AlreadyOwned));
            }
        }
        // An anonymous purchase creates a NEW account, so it can never
        // collide with what the caller already owns.
        Grant::LifetimeAnon => {}
        Grant::Quant => {
            if live_quant_subscription(conn, catalog, user_id)?.is_some() {
                return Ok(Prepared::Refused(Refusal::SubscriptionExists));
            }
        }
    }

    let external_user_ref = user_id.to_string();
    let customer = customer_for_user(conn, user_id)?;

    for sub in subscriptions_for_user(conn, user_id)? {
        if sub.plan_id != plan.id {
            continue;
        }
        match (sub.state, &sub.subscription_id) {
            (SubState::Open, Some(subscription_id)) => {
                let reusable = invoices_for_subscription(conn, subscription_id)?.into_iter().find(|inv| {
                    inv.kind == InvoiceKind::Initial
                        && inv.grant_state == GrantState::None
                        && inv.status == INVOICE_NEW
                        && inv.expires_at.as_deref().is_some_and(|t| is_future(t, now))
                });
                if let Some(invoice) = reusable {
                    return Ok(Prepared::Existing(Box::new(invoice)));
                }
            }
            (SubState::Creating, _) => {
                return Ok(Prepared::Create { checkout_key: sub.checkout_key, customer, external_user_ref });
            }
            _ => {}
        }
    }

    let checkout_key = new_key();
    let stamp = now.to_rfc3339();
    conn.execute(
        "INSERT INTO billing_subscriptions
            (checkout_key, user_id, plan_id, subscription_id, external_user_ref, state, created_at, updated_at)
         VALUES (?1, ?2, ?3, NULL, ?4, 'creating', ?5, ?5)",
        params![checkout_key, user_id, plan.id, external_user_ref, stamp],
    )?;
    Ok(Prepared::Create { checkout_key, customer, external_user_ref })
}

/// Bind the reserved `checkout_key` to the subscription dig2pay created and
/// store its first invoice. Idempotent: a repeat with the same dig2pay
/// answer changes nothing.
pub fn complete_checkout(
    conn: &Connection,
    checkout_key: &str,
    invoice: &InvoiceRow,
    now: DateTime<Utc>,
) -> Result<()> {
    conn.execute(
        "UPDATE billing_subscriptions SET subscription_id = ?2, state = 'open', updated_at = ?3
         WHERE checkout_key = ?1 AND subscription_id IS NULL",
        params![checkout_key, invoice.subscription_id, now.to_rfc3339()],
    )?;
    insert_invoice(conn, invoice, now)
}

// ============================================================================
// Account merge
// ============================================================================

/// Fold `from`'s billing rows into `into` (`account_merge` calls this inside
/// its identity transaction, right before it deletes `from`). Idempotent:
/// once `from` has nothing left, it changes nothing.
pub fn merge_user(conn: &Connection, from: i64, into: i64) -> Result<()> {
    super::entitle::merge_entitlements(conn, from, into)?;
    super::grants::merge(conn, from, into)?;
    if customer_for_user(conn, into)?.is_none() {
        conn.execute(
            "UPDATE billing_subscribers SET user_id = ?1 WHERE user_id = ?2",
            params![into, from],
        )?;
    } else {
        conn.execute("DELETE FROM billing_subscribers WHERE user_id = ?1", params![from])?;
    }
    for table in ["billing_subscriptions", "billing_invoices", "billing_events"] {
        conn.execute(
            &format!("UPDATE {table} SET user_id = ?1 WHERE user_id = ?2"),
            params![into, from],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::plans::{AccountPlanIds, DEFAULT_PAID_TOR_ID};
    use crate::billing::testkit::{conn, seed_user};
    use chrono::Duration;
    use std::collections::BTreeMap;

    fn catalog() -> Catalog {
        Catalog::build(&AccountPlanIds::default(), &BTreeMap::new())
    }

    fn open_invoice(user_id: i64, plan_id: &str, sub_id: &str, invoice_id: &str, expires: DateTime<Utc>) -> InvoiceRow {
        InvoiceRow {
            invoice_id: invoice_id.to_string(),
            user_id,
            subscription_id: sub_id.to_string(),
            plan_id: plan_id.to_string(),
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

    fn key_source(key: &'static str) -> impl FnOnce() -> String {
        move || key.to_string()
    }

    #[test]
    fn a_fresh_checkout_reserves_a_key_and_a_retry_resumes_it() {
        let conn = conn();
        let catalog = catalog();
        let plan = catalog.get("mlc-monthly-20-v1").expect("plan").clone();
        let uid = seed_user(&conn, "fresh");
        let now = Utc::now();
        let first = prepare_checkout(&conn, &catalog, uid, &plan, now, key_source("key-1")).expect("prepare");
        let Prepared::Create { checkout_key, customer, external_user_ref } = first else {
            panic!("expected Create, got {first:?}");
        };
        assert_eq!(checkout_key, "key-1");
        assert_eq!(customer, None);
        assert_eq!(external_user_ref, uid.to_string());

        // dig2pay never answered: the retry replays the SAME key.
        let retry = prepare_checkout(&conn, &catalog, uid, &plan, now, key_source("key-2")).expect("prepare");
        let Prepared::Create { checkout_key, .. } = retry else {
            panic!("expected Create, got {retry:?}");
        };
        assert_eq!(checkout_key, "key-1");
    }

    #[test]
    fn an_unexpired_unpaid_invoice_is_reused_and_an_expired_one_is_replaced() {
        let conn = conn();
        let catalog = catalog();
        let plan = catalog.get("mlc-paid-account-v1").expect("plan").clone();
        let uid = seed_user(&conn, "reuse");
        let now = Utc::now();
        prepare_checkout(&conn, &catalog, uid, &plan, now, key_source("key-1")).expect("prepare");
        complete_checkout(&conn, "key-1", &open_invoice(uid, &plan.id, "sub_1", "grp_1", now + Duration::hours(1)), now)
            .expect("complete");

        let again = prepare_checkout(&conn, &catalog, uid, &plan, now, key_source("key-2")).expect("prepare");
        let Prepared::Existing(invoice) = again else {
            panic!("expected Existing, got {again:?}");
        };
        assert_eq!(invoice.invoice_id, "grp_1");

        // An hour and a minute later the invoice has expired: a new purchase.
        let later = now + Duration::minutes(61);
        let replaced = prepare_checkout(&conn, &catalog, uid, &plan, later, key_source("key-3")).expect("prepare");
        let Prepared::Create { checkout_key, .. } = replaced else {
            panic!("expected Create, got {replaced:?}");
        };
        assert_eq!(checkout_key, "key-3");
    }

    #[test]
    fn a_held_paid_account_and_running_subscriptions_are_refused_but_anonymous_purchases_never_collide() {
        let conn = conn();
        let catalog = catalog();
        let now = Utc::now();
        let uid = seed_user(&conn, "owner");
        let anon = catalog.get("mlc-anon-account-v1").expect("plan").clone();
        let paid = catalog.get("mlc-paid-account-v1").expect("plan").clone();
        let paid_tor = catalog.get(DEFAULT_PAID_TOR_ID).expect("plan").clone();

        // An anonymous purchase grants anonymous AND paid, so a paid account
        // (either origin) is then already held...
        crate::billing::grants::grant_for_invoice(&conn, uid, Grant::LifetimeAnon, "inv_anon", now).expect("grant");
        for plan in [&paid, &paid_tor] {
            let refused = prepare_checkout(&conn, &catalog, uid, plan, now, key_source("k")).expect("prepare");
            assert!(matches!(refused, Prepared::Refused(Refusal::AlreadyOwned)), "{}: {refused:?}", plan.id);
        }
        // ...while another anonymous purchase creates a new account and never collides.
        let allowed = prepare_checkout(&conn, &catalog, uid, &anon, now, key_source("k2")).expect("prepare");
        assert!(matches!(allowed, Prepared::Create { .. }), "{allowed:?}");

        conn.execute(
            "INSERT INTO billing_subscriptions
                (checkout_key, user_id, plan_id, subscription_id, external_user_ref, state, created_at, updated_at)
             VALUES ('run', ?1, 'mlc-monthly-50-v1', 'sub_run', ?1, 'active', ?2, ?2)",
            params![uid, now.to_rfc3339()],
        )
        .expect("running subscription");
        let tier = catalog.get("mlc-monthly-20-v1").expect("plan").clone();
        let refused = prepare_checkout(&conn, &catalog, uid, &tier, now, key_source("k3")).expect("prepare");
        assert!(matches!(refused, Prepared::Refused(Refusal::SubscriptionExists)), "{refused:?}");
    }

    #[test]
    fn an_invoice_is_only_found_by_its_owner() {
        let conn = conn();
        let now = Utc::now();
        let owner = seed_user(&conn, "owner");
        let other = seed_user(&conn, "other");
        insert_invoice(&conn, &open_invoice(owner, "mlc-paid-account-v1", "sub_1", "grp_1", now), now).expect("insert");
        assert!(invoice_for_user(&conn, owner, "grp_1").expect("query").is_some());
        assert!(invoice_for_user(&conn, other, "grp_1").expect("query").is_none());
        assert!(invoice_for_user(&conn, owner, "grp_x").expect("query").is_none());
    }

    #[test]
    fn merging_repoints_the_rows_and_keeps_the_survivors_customer() {
        let conn = conn();
        let now = Utc::now();
        let from = seed_user(&conn, "from");
        let into = seed_user(&conn, "into");
        record_customer(&conn, from, "cus_from", "f", now).expect("customer");
        record_customer(&conn, into, "cus_into", "i", now).expect("customer");
        insert_invoice(&conn, &open_invoice(from, "mlc-paid-account-v1", "sub_1", "grp_1", now), now).expect("insert");
        conn.execute(
            "INSERT INTO billing_events (event_id, kind, user_id, outcome, body, received_at)
             VALUES ('e1', 'payment_confirmed', ?1, 'granted', '{}', ?2)",
            params![from, now.to_rfc3339()],
        )
        .expect("event");

        merge_user(&conn, from, into).expect("merge");
        merge_user(&conn, from, into).expect("merging again changes nothing");

        assert_eq!(customer_for_user(&conn, into).expect("customer").as_deref(), Some("cus_into"));
        assert_eq!(customer_for_user(&conn, from).expect("customer"), None);
        assert!(invoice_for_user(&conn, into, "grp_1").expect("query").is_some());
        let event_owner: i64 = conn
            .query_row("SELECT user_id FROM billing_events WHERE event_id = 'e1'", [], |r| r.get(0))
            .expect("event owner");
        assert_eq!(event_owner, into);
    }

    #[test]
    fn is_future_compares_moments_not_text() {
        let now = Utc::now();
        assert!(is_future(&(now + Duration::seconds(5)).to_rfc3339(), now));
        assert!(!is_future(&(now - Duration::seconds(5)).to_rfc3339(), now));
        // A different offset spelling of a past moment is still past.
        assert!(!is_future("2020-01-01T05:00:00+05:00", now));
        assert!(!is_future("not a timestamp", now));
    }
}

//! Applying dig2pay webhook events to MLC's billing state.
//!
//! [`process`] is the whole pipeline for one already-authenticated delivery
//! (the route verifies the signature first): parse, dedup on the event id,
//! resolve which account and subscription it is about, apply its effect, and
//! record what was done — all inside ONE database transaction, so a crash
//! never leaves an event stored but unapplied (dig2pay would then see a 2xx
//! on the retry and never redeliver).
//!
//! Effects, by event kind (`docs/dig2pay/plans/mlc-integration-2026-09-25.md`
//! §3, `payment-integrity-reporting-2026-09-25.md`):
//!
//! | kind | effect |
//! |---|---|
//! | `payment_confirmed`, `renewal_confirmed` | GRANT: permanent flags (account plans) or the paid period (quant tiers) |
//! | `subscription_changed` `applied` | the subscription moves to the new plan; `change_id` is kept |
//! | `subscription_changed` `cancelled` | the pending change is dropped |
//! | `refund_recorded` | REVOKE what that invoice granted (final) |
//! | `payment_reverted` | REVOKE provisionally; restored if the invoice is seen settled again |
//! | `payment_over` | excess credited to the account's balance (stablecoins only) |
//! | `payment_partial`, `payment_failed`, `payment_no_show`, `funds_pending_on_expiry`, `payment_anomaly` | recorded on the invoice; no entitlement change |
//! | `subscription_past_due`, `subscription_cancelled` | subscription state recorded; paid time already bought stays valid |
//! | `processor_incident` | recorded |
//! | anything else | stored and acknowledged (`UnknownKind`) — never failed |
//!
//! A `late` flag on a confirmation is recorded on the invoice; the payment
//! still grants normally.
//!
//! A one-time (account) plan settles with exactly ONE `payment_confirmed`
//! whose period is `{from: settled_at, to: null}`; the entitlement it grants
//! is permanent and no date column is written. It never renews: a
//! `renewal_confirmed` for one is ignored. The lifetime paid plans set
//! `lifetime_paid`; the anonymous ones set `lifetime_anon` AND `lifetime_paid`.
//! A monthly plan needs a closed period: a null `to` (or a `one_time`
//! interval) on a monthly plan is a malformed event — logged, stored, not
//! granted, as is a `monthly` interval on an account plan.
//!
//! Every body may carry the additive optional fields `plan_id` and
//! `billing_interval` (`"one_time"` / `"monthly"`); older bodies without them
//! decode as before. A refund is final: nothing re-grants a refunded
//! invoice.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde_json::{Map, Value};

use super::plans::{Catalog, Grant, Interval};
use super::{anon, entitle, grants};
use super::store::{
    self, GrantState, InvoiceKind, InvoiceRow, SubState, SubscriptionRow, INVOICE_NEW, INVOICE_REFUNDED,
    INVOICE_REVERTED, INVOICE_SETTLED,
};

/// Assets whose amount is one-to-one with USD, so an overpayment in them can
/// be credited to the balance.
const STABLE_ASSETS: [&str; 2] = ["USDT", "USDC"];

/// What [`process`] did with a delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The event id was seen before; nothing was done.
    Duplicate,
    /// An entitlement was granted.
    Granted,
    /// A grant was revoked for good (refund).
    Revoked,
    /// A grant was revoked provisionally (reorg).
    Reverted,
    /// An overpayment was credited to the balance.
    Credited,
    /// A subscription moved to another plan.
    PlanChanged,
    /// A pending plan change was dropped.
    ChangeCancelled,
    /// Recorded; no entitlement change.
    Recorded,
    /// Deliberately not acted on (a renewal of a one-time plan, a grant
    /// after a refund).
    Ignored,
    /// No known invoice or subscription matches.
    Unmatched,
    /// The event contradicts what MLC knows (its invoice and subscription
    /// disagree, or the account reference differs).
    Mismatch,
    /// A kind this version does not know.
    UnknownKind,
    /// The plan id is not in the catalog.
    UnknownPlan,
    /// The account no longer exists.
    UserMissing,
    /// The event contradicts the plan's billing interval (a monthly plan
    /// without a closed period, a one-time plan billed monthly): logged,
    /// stored, not granted.
    Malformed,
    /// A `subscription_changed` for a change MLC never requested.
    UnknownChange,
}

impl Outcome {
    /// Stable spelling stored in `billing_events.outcome` and returned to
    /// dig2pay.
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Duplicate => "duplicate",
            Outcome::Granted => "granted",
            Outcome::Revoked => "revoked",
            Outcome::Reverted => "reverted",
            Outcome::Credited => "credited",
            Outcome::PlanChanged => "plan_changed",
            Outcome::ChangeCancelled => "change_cancelled",
            Outcome::Recorded => "recorded",
            Outcome::Ignored => "ignored",
            Outcome::Unmatched => "unmatched",
            Outcome::Mismatch => "mismatch",
            Outcome::UnknownKind => "unknown_kind",
            Outcome::UnknownPlan => "unknown_plan",
            Outcome::UserMissing => "user_missing",
            Outcome::Malformed => "malformed",
            Outcome::UnknownChange => "unknown_change",
        }
    }
}

/// Why a signed delivery could not be processed at all.
#[derive(Debug)]
pub enum ProcessError {
    /// The body is not the JSON shape the contract describes.
    BadBody(&'static str),
    /// The database failed; the delivery must be retried.
    Db(rusqlite::Error),
}

impl From<rusqlite::Error> for ProcessError {
    fn from(e: rusqlite::Error) -> Self {
        ProcessError::Db(e)
    }
}

/// The parts of a webhook body this module reads.
struct Event {
    kind: String,
    subscriber_id: Option<String>,
    external_user_ref: Option<String>,
    invoice_id: Option<String>,
    /// Additive: the plan this event is about.
    plan_id: Option<String>,
    /// Additive: `"one_time"` or `"monthly"`.
    billing_interval: Option<String>,
    period_from: Option<DateTime<Utc>>,
    period_to: Option<DateTime<Utc>>,
    /// A `period` object is present but its `to` is null or absent — how a
    /// one-time plan's settlement is reported.
    period_open_ended: bool,
    flags: Vec<String>,
    change_id: Option<String>,
    state: Option<String>,
    raw: Value,
}

impl Event {
    /// The paid period, only when both ends are real moments.
    fn closed_period(&self) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
        Some((self.period_from?, self.period_to?))
    }

    fn says_one_time(&self) -> bool {
        self.billing_interval.as_deref() == Some("one_time") || self.period_open_ended
    }

    fn says_monthly(&self) -> bool {
        self.billing_interval.as_deref() == Some("monthly")
    }
}

fn text_field(obj: &Map<String, Value>, key: &str) -> Option<String> {
    obj.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn timestamp(value: Option<&Value>) -> Option<DateTime<Utc>> {
    value
        .and_then(Value::as_str)
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&Utc))
}

fn parse_event(raw_body: &str) -> Result<(Option<String>, Event), ProcessError> {
    let raw: Value = serde_json::from_str(raw_body).map_err(|_| ProcessError::BadBody("body is not JSON"))?;
    let obj = raw.as_object().ok_or(ProcessError::BadBody("body is not an object"))?;
    let kind = text_field(obj, "kind").ok_or(ProcessError::BadBody("kind is missing"))?;
    let period = obj.get("period").filter(|p| p.is_object());
    let period_from = period.and_then(|p| timestamp(p.get("from")));
    let period_to = period.and_then(|p| timestamp(p.get("to")));
    let period_open_ended = period.is_some_and(|p| p.get("to").is_none_or(Value::is_null));
    let flags = obj
        .get("flags")
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(|f| f.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let event_id = text_field(obj, "event_id");
    let event = Event {
        kind,
        subscriber_id: text_field(obj, "subscriber_id"),
        external_user_ref: text_field(obj, "external_user_ref"),
        invoice_id: text_field(obj, "invoice_id"),
        plan_id: text_field(obj, "plan_id"),
        billing_interval: text_field(obj, "billing_interval"),
        period_from,
        period_to,
        period_open_ended,
        flags,
        change_id: text_field(obj, "change_id"),
        state: text_field(obj, "state"),
        raw,
    };
    Ok((event_id, event))
}

/// `amount.<key>` as text (a JSON string or number).
fn amount_text(event: &Event, key: &str) -> Option<String> {
    match event.raw.get("amount")?.get(key)? {
        Value::String(s) => Some(s.trim().to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

const KNOWN_KINDS: [&str; 14] = [
    "payment_confirmed",
    "renewal_confirmed",
    "subscription_changed",
    "refund_recorded",
    "payment_reverted",
    "payment_over",
    "payment_partial",
    "payment_failed",
    "payment_no_show",
    "funds_pending_on_expiry",
    "payment_anomaly",
    "subscription_past_due",
    "subscription_cancelled",
    "processor_incident",
];

/// Process one authenticated delivery. `header_event_id` is the
/// `X-Dig2pay-Event-Id` header, used when the body carries no `event_id`.
pub fn process(
    conn: &Connection,
    catalog: &Catalog,
    header_event_id: Option<&str>,
    raw_body: &str,
    now: DateTime<Utc>,
) -> Result<Outcome, ProcessError> {
    let (body_event_id, event) = parse_event(raw_body)?;
    let event_id = body_event_id
        .or_else(|| header_event_id.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string))
        .ok_or(ProcessError::BadBody("event id is missing"))?;

    let tx = conn.unchecked_transaction()?;
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO billing_events
            (event_id, kind, user_id, subscription_id, invoice_id, outcome, body, received_at)
         VALUES (?1, ?2, NULL, ?3, ?4, 'received', ?5, ?6)",
        params![event_id, event.kind, event.subscriber_id, event.invoice_id, raw_body, now.to_rfc3339()],
    )?;
    if inserted == 0 {
        return Ok(Outcome::Duplicate);
    }
    let (outcome, user_id) = apply(&tx, catalog, &event, now)?;
    tx.execute(
        "UPDATE billing_events SET outcome = ?1, user_id = ?2 WHERE event_id = ?3",
        params![outcome.as_str(), user_id, event_id],
    )?;
    tx.commit()?;
    Ok(outcome)
}

struct Context {
    subscription: SubscriptionRow,
    invoice: Option<InvoiceRow>,
}

enum Resolved {
    Found(Box<Context>),
    Unmatched,
    Mismatch(i64),
}

/// Find the subscription (and invoice) an event is about. The invoice id is
/// the most specific key; the webhook's `subscriber_id` is dig2pay's
/// subscription id. When both resolve they must agree.
fn resolve(conn: &Connection, event: &Event) -> rusqlite::Result<Resolved> {
    let invoice = match event.invoice_id.as_deref() {
        Some(id) => store::invoice_by_id(conn, id)?,
        None => None,
    };
    let named = match event.subscriber_id.as_deref() {
        Some(id) => store::subscription_by_id(conn, id)?,
        None => None,
    };
    let subscription = match (&invoice, named) {
        (Some(inv), named) => match (store::subscription_by_id(conn, &inv.subscription_id)?, named) {
            (Some(owner), Some(named)) if owner.checkout_key != named.checkout_key => {
                return Ok(Resolved::Mismatch(owner.user_id));
            }
            (Some(owner), _) => owner,
            (None, _) => return Ok(Resolved::Unmatched),
        },
        (None, Some(named)) => named,
        (None, None) => return Ok(Resolved::Unmatched),
    };
    if let Some(reference) = event.external_user_ref.as_deref() {
        if reference != subscription.external_user_ref {
            return Ok(Resolved::Mismatch(subscription.user_id));
        }
    }
    Ok(Resolved::Found(Box::new(Context { subscription, invoice })))
}

fn apply(
    conn: &Connection,
    catalog: &Catalog,
    event: &Event,
    now: DateTime<Utc>,
) -> rusqlite::Result<(Outcome, Option<i64>)> {
    if event.kind == "processor_incident" {
        // A processor-wide fact about a chain, not about any account.
        return Ok((Outcome::Recorded, None));
    }
    if !KNOWN_KINDS.contains(&event.kind.as_str()) {
        return Ok((Outcome::UnknownKind, None));
    }
    let context = match resolve(conn, event)? {
        Resolved::Found(context) => *context,
        Resolved::Unmatched => return Ok((Outcome::Unmatched, None)),
        Resolved::Mismatch(user_id) => return Ok((Outcome::Mismatch, Some(user_id))),
    };
    let user_id = context.subscription.user_id;
    let outcome = match event.kind.as_str() {
        "payment_confirmed" | "renewal_confirmed" => grant(conn, catalog, event, context, now)?,
        "subscription_changed" => change(conn, catalog, event, context, now)?,
        "refund_recorded" => revoke(conn, catalog, context, GrantState::Revoked, now)?,
        "payment_reverted" => revoke(conn, catalog, context, GrantState::Reverted, now)?,
        "payment_over" => over(conn, catalog, event, context, now)?,
        "payment_partial" => note(conn, catalog, event, context, "partial", now)?,
        "payment_failed" => note(conn, catalog, event, context, "failed", now)?,
        "payment_no_show" => note(conn, catalog, event, context, "no_show", now)?,
        "funds_pending_on_expiry" => note(conn, catalog, event, context, "funds_pending", now)?,
        "payment_anomaly" => note(conn, catalog, event, context, "anomaly", now)?,
        "subscription_past_due" => subscription_state(conn, context, SubState::PastDue, now)?,
        "subscription_cancelled" => subscription_state(conn, context, SubState::Cancelled, now)?,
        _ => Outcome::UnknownKind,
    };
    Ok((outcome, Some(user_id)))
}

/// The invoice row an event is about, creating it when dig2pay issued it
/// without MLC knowing (a renewal, or a proration).
fn ensure_invoice(
    conn: &Connection,
    catalog: &Catalog,
    event: &Event,
    context: &mut Context,
    now: DateTime<Utc>,
) -> rusqlite::Result<Option<InvoiceRow>> {
    if let Some(invoice) = context.invoice.take() {
        return Ok(Some(invoice));
    }
    let Some(invoice_id) = event.invoice_id.clone() else {
        return Ok(None);
    };
    let sub = &context.subscription;
    let subscription_id = sub.subscription_id.clone().unwrap_or_default();
    let has_initial = store::invoices_for_subscription(conn, &subscription_id)?
        .iter()
        .any(|i| i.kind == InvoiceKind::Initial);
    let kind = if event.kind == "renewal_confirmed" {
        InvoiceKind::Renewal
    } else if pending_upgrade(catalog, sub) {
        InvoiceKind::Proration
    } else if has_initial {
        InvoiceKind::Renewal
    } else {
        InvoiceKind::Initial
    };
    let invoice = InvoiceRow {
        invoice_id,
        user_id: sub.user_id,
        subscription_id,
        plan_id: event_plan(catalog, event).unwrap_or_else(|| sub.plan_id.clone()),
        kind,
        status: INVOICE_NEW.to_string(),
        pay_json: "[]".to_string(),
        expires_at: None,
        flags: Vec::new(),
        grant_kind: None,
        grant_state: GrantState::None,
        period_from: None,
        period_to: None,
        detail: Value::Object(Map::new()),
    };
    store::insert_invoice(conn, &invoice, now)?;
    Ok(Some(invoice))
}

/// The event's own `plan_id`, when it names a plan in the catalog.
fn event_plan(catalog: &Catalog, event: &Event) -> Option<String> {
    event.plan_id.clone().filter(|id| catalog.get(id).is_some())
}

/// Whether the subscription has a pending change to a HIGHER tier — the only
/// kind that comes with a proration invoice.
fn pending_upgrade(catalog: &Catalog, sub: &SubscriptionRow) -> bool {
    let rank = |id: &str| catalog.get(id).and_then(|p| p.tier_rank);
    match (sub.pending_plan_id.as_deref().and_then(rank), rank(&sub.plan_id)) {
        (Some(target), Some(current)) => target > current,
        _ => false,
    }
}

fn add_flag(invoice: &mut InvoiceRow, flag: &str) {
    if !invoice.flags.iter().any(|f| f == flag) {
        invoice.flags.push(flag.to_string());
    }
}

fn grant(
    conn: &Connection,
    catalog: &Catalog,
    event: &Event,
    mut context: Context,
    now: DateTime<Utc>,
) -> rusqlite::Result<Outcome> {
    // The plan of a known invoice is the one it was issued under; for one
    // MLC has not seen (a renewal) the event's own `plan_id` wins over the
    // subscription's last known plan.
    let plan_id = context
        .invoice
        .as_ref()
        .map(|i| i.plan_id.clone())
        .or_else(|| event_plan(catalog, event))
        .unwrap_or_else(|| context.subscription.plan_id.clone());
    let Some(plan) = catalog.get(&plan_id) else {
        return Ok(Outcome::UnknownPlan);
    };
    // A one-time plan settles with exactly ONE `payment_confirmed` and then
    // sits in the terminal `paid` status: a renewal, or a further invoice on a
    // subscription that already settled, is ignored before anything is
    // written (no invoice row is invented for it).
    if plan.interval == Interval::OneTime
        && (event.kind == "renewal_confirmed"
            || (context.invoice.is_none() && context.subscription.state == SubState::Paid))
    {
        tracing::warn!(
            "billing webhook: {} for one-time plan {} ignored (it settles once and never renews)",
            event.kind,
            plan.id
        );
        return Ok(Outcome::Ignored);
    }
    let Some(mut invoice) = ensure_invoice(conn, catalog, event, &mut context, now)? else {
        return Ok(Outcome::Unmatched);
    };
    let mut sub = context.subscription;
    let user_id = sub.user_id;

    if invoice.grant_state == GrantState::Revoked {
        return Ok(Outcome::Ignored);
    }
    if event.flags.iter().any(|f| f == "late") {
        add_flag(&mut invoice, "late");
    }

    match plan.grant {
        Grant::LifetimePaid | Grant::LifetimeAnon => {
            debug_assert_eq!(plan.interval, Interval::OneTime, "lifetime grants are one-time plans");
            if event.says_monthly() {
                tracing::warn!(
                    "billing webhook: {} for one-time plan {} claims a monthly interval; not granting",
                    event.kind,
                    plan.id
                );
                store::save_invoice(conn, &invoice, now)?;
                return Ok(Outcome::Malformed);
            }
            // Only the first invoice of a one-time subscription grants.
            if invoice.kind != InvoiceKind::Initial {
                store::save_invoice(conn, &invoice, now)?;
                return Ok(Outcome::Ignored);
            }
            // Permanent: the settlement moment is kept, there is no end date
            // (`period.to` is null for a one-time plan) and no date column
            // of the account is written.
            invoice.grant_kind = Some(plan.grant);
            invoice.grant_state = GrantState::Granted;
            invoice.status = INVOICE_SETTLED.to_string();
            invoice.period_from = event.period_from.map(|t| t.to_rfc3339());
            store::save_invoice(conn, &invoice, now)?;
            sub.state = SubState::Paid;
            store::save_subscription(conn, &sub, now)?;
            // The grants are ledger rows created by THIS invoice (an anonymous
            // plan creates anonymous + paid); a refund can only take these back.
            if !grants::grant_for_invoice(conn, user_id, plan.grant, &invoice.invoice_id, now)? {
                return Ok(Outcome::UserMissing);
            }
            // Payment is what turns a pending anonymous account into a usable one.
            if plan.grant == Grant::LifetimeAnon {
                anon::activate(conn, user_id, now)?;
            }
            Ok(Outcome::Granted)
        }
        Grant::Quant => {
            if invoice.kind == InvoiceKind::Proration {
                // The upgrade lands on `subscription_changed`, not here.
                invoice.status = INVOICE_SETTLED.to_string();
                store::save_invoice(conn, &invoice, now)?;
                return Ok(Outcome::Recorded);
            }
            // A monthly plan needs a closed period. A null `to` (or a
            // one-time interval) on one is a malformed event: never turned
            // into a date, never granted.
            let period = if event.says_one_time() { None } else { event.closed_period() };
            let Some((from, to)) = period else {
                tracing::warn!(
                    "billing webhook: {} for monthly plan {} has no closed period (null `to` or one-time interval); not granting",
                    event.kind,
                    plan.id
                );
                store::save_invoice(conn, &invoice, now)?;
                return Ok(Outcome::Malformed);
            };
            invoice.grant_kind = Some(Grant::Quant);
            invoice.grant_state = GrantState::Granted;
            invoice.status = INVOICE_SETTLED.to_string();
            invoice.period_from = Some(from.to_rfc3339());
            invoice.period_to = Some(to.to_rfc3339());
            store::save_invoice(conn, &invoice, now)?;
            entitle::recompute_subscription(conn, &mut sub, now)?;
            if !entitle::recompute_quant(conn, catalog, user_id, now)? {
                return Ok(Outcome::UserMissing);
            }
            Ok(Outcome::Granted)
        }
    }
}

/// Withdraw what the event's invoice granted. `target` is `Revoked` for a
/// refund (final) or `Reverted` for a reorg (restorable).
fn revoke(
    conn: &Connection,
    catalog: &Catalog,
    context: Context,
    target: GrantState,
    now: DateTime<Utc>,
) -> rusqlite::Result<Outcome> {
    let Some(mut invoice) = context.invoice else {
        return Ok(Outcome::Unmatched);
    };
    let mut sub = context.subscription;
    let in_force = matches!(invoice.grant_state, GrantState::Granted | GrantState::Reverted);
    if !in_force {
        // Nothing was granted (or it is already refunded): just note it.
        if target == GrantState::Revoked && invoice.grant_state == GrantState::None {
            invoice.status = INVOICE_REFUNDED.to_string();
            store::save_invoice(conn, &invoice, now)?;
        }
        return Ok(Outcome::Recorded);
    }
    invoice.grant_state = target;
    invoice.status = if target == GrantState::Revoked { INVOICE_REFUNDED } else { INVOICE_REVERTED }.to_string();
    store::save_invoice(conn, &invoice, now)?;
    withdraw_entitlement(conn, catalog, &invoice, &mut sub, now)?;
    Ok(if target == GrantState::Revoked { Outcome::Revoked } else { Outcome::Reverted })
}

/// Bring the account's cached entitlement in line after `invoice` stopped
/// (or started) granting.
fn withdraw_entitlement(
    conn: &Connection,
    catalog: &Catalog,
    invoice: &InvoiceRow,
    sub: &mut SubscriptionRow,
    now: DateTime<Utc>,
) -> rusqlite::Result<()> {
    match invoice.grant_kind {
        Some(Grant::LifetimePaid | Grant::LifetimeAnon) => {
            // Exactly the ledger rows this invoice created; nothing else.
            grants::revoke_for_invoice(conn, invoice.user_id, &invoice.invoice_id, now)?;
            Ok(())
        }
        Some(Grant::Quant) => {
            entitle::recompute_subscription(conn, sub, now)?;
            entitle::recompute_quant(conn, catalog, invoice.user_id, now)?;
            Ok(())
        }
        None => Ok(()),
    }
}

/// Re-grant an invoice that was revoked provisionally by `payment_reverted`
/// once the processor reports it settled again. dig2pay's event ids are
/// deterministic, so a re-settlement is NOT announced by a second
/// `payment_confirmed`; the invoice route calls this after it has read the
/// live status. Returns whether anything was restored.
pub fn restore_reverted(
    conn: &Connection,
    catalog: &Catalog,
    user_id: i64,
    invoice_id: &str,
    now: DateTime<Utc>,
) -> rusqlite::Result<bool> {
    let Some(mut invoice) = store::invoice_for_user(conn, user_id, invoice_id)? else {
        return Ok(false);
    };
    if invoice.grant_state != GrantState::Reverted {
        return Ok(false);
    }
    let tx = conn.unchecked_transaction()?;
    invoice.grant_state = GrantState::Granted;
    invoice.status = INVOICE_SETTLED.to_string();
    store::save_invoice(&tx, &invoice, now)?;
    match invoice.grant_kind {
        Some(grant @ (Grant::LifetimePaid | Grant::LifetimeAnon)) => {
            // Only this invoice's own rows come back.
            grants::grant_for_invoice(&tx, user_id, grant, &invoice.invoice_id, now)?;
        }
        Some(Grant::Quant) => {
            if let Some(mut sub) = store::subscription_by_id(&tx, &invoice.subscription_id)? {
                entitle::recompute_subscription(&tx, &mut sub, now)?;
            }
            entitle::recompute_quant(&tx, catalog, user_id, now)?;
        }
        None => {}
    }
    tx.commit()?;
    Ok(true)
}

/// Move `sub` to `target_plan` because change `change_id` applied, keeping
/// the change id. Saves the subscription and refreshes the account's quant
/// columns. `false` when the account no longer exists.
pub fn apply_plan_change(
    conn: &Connection,
    catalog: &Catalog,
    sub: &mut SubscriptionRow,
    change_id: &str,
    target_plan: &str,
    now: DateTime<Utc>,
) -> rusqlite::Result<bool> {
    sub.plan_id = target_plan.to_string();
    sub.pending_change_id = None;
    sub.pending_plan_id = None;
    sub.last_change_id = Some(change_id.to_string());
    store::save_subscription(conn, sub, now)?;
    entitle::recompute_quant(conn, catalog, sub.user_id, now)
}

fn change(
    conn: &Connection,
    catalog: &Catalog,
    event: &Event,
    context: Context,
    now: DateTime<Utc>,
) -> rusqlite::Result<Outcome> {
    let Some(change_id) = event.change_id.as_deref() else {
        return Ok(Outcome::UnknownChange);
    };
    let mut sub = context.subscription;
    match event.state.as_deref() {
        Some("applied") => {
            if sub.last_change_id.as_deref() == Some(change_id) {
                return Ok(Outcome::Recorded);
            }
            // The plan MLC asked for; failing that (its record of the request
            // is gone) the plan the event itself names.
            let requested = sub.pending_change_id.as_deref() == Some(change_id);
            let named = if requested { sub.pending_plan_id.clone() } else { event.plan_id.clone() };
            let target = named.filter(|id| catalog.get(id).is_some_and(|p| p.grant == Grant::Quant));
            let Some(target) = target else {
                return Ok(if requested { Outcome::UnknownPlan } else { Outcome::UnknownChange });
            };
            if !apply_plan_change(conn, catalog, &mut sub, change_id, &target, now)? {
                return Ok(Outcome::UserMissing);
            }
            Ok(Outcome::PlanChanged)
        }
        Some("cancelled") => {
            if sub.pending_change_id.as_deref() == Some(change_id) {
                sub.pending_change_id = None;
                sub.pending_plan_id = None;
                store::save_subscription(conn, &sub, now)?;
                return Ok(Outcome::ChangeCancelled);
            }
            Ok(Outcome::Recorded)
        }
        _ => Ok(Outcome::Recorded),
    }
}

fn subscription_state(
    conn: &Connection,
    context: Context,
    state: SubState,
    now: DateTime<Utc>,
) -> rusqlite::Result<Outcome> {
    let mut sub = context.subscription;
    let allowed = match state {
        // Only a running subscription can fall behind on a renewal.
        SubState::PastDue => matches!(sub.state, SubState::Active | SubState::Open),
        // Cancelling stops renewals; a settled one-time plan stays `paid`.
        _ => sub.state != SubState::Paid,
    };
    if allowed {
        sub.state = state;
        store::save_subscription(conn, &sub, now)?;
    }
    Ok(Outcome::Recorded)
}

/// `payment_over`: credit the excess (stablecoins only) and note the flag.
fn over(
    conn: &Connection,
    catalog: &Catalog,
    event: &Event,
    context: Context,
    now: DateTime<Utc>,
) -> rusqlite::Result<Outcome> {
    let user_id = context.subscription.user_id;
    let excess = amount_text(event, "excess")
        .and_then(|s| entitle::parse_micros(&s))
        .or_else(|| {
            let received = entitle::parse_micros(&amount_text(event, "received")?)?;
            let expected = entitle::parse_micros(&amount_text(event, "expected")?)?;
            received.checked_sub(expected)
        })
        .filter(|micros| *micros > 0);
    let stable = amount_text(event, "asset").is_some_and(|asset| {
        STABLE_ASSETS.iter().any(|known| known.eq_ignore_ascii_case(&asset))
    });
    note(conn, catalog, event, context, "over", now)?;
    match excess {
        Some(micros) if stable => {
            entitle::add_credit(conn, user_id, micros, now)?;
            Ok(Outcome::Credited)
        }
        _ => Ok(Outcome::Recorded),
    }
}

/// Record an integrity event on its invoice: a flag plus the payload the
/// event carried, so the owner (and support) can see what happened.
fn note(
    conn: &Connection,
    catalog: &Catalog,
    event: &Event,
    mut context: Context,
    flag: &str,
    now: DateTime<Utc>,
) -> rusqlite::Result<Outcome> {
    if let Some(mut invoice) = ensure_invoice(conn, catalog, event, &mut context, now)? {
        add_flag(&mut invoice, flag);
        if event.flags.iter().any(|f| f == "late") {
            add_flag(&mut invoice, "late");
        }
        let payload = if flag == "anomaly" { event.raw.get("anomaly") } else { event.raw.get("amount") };
        if let Some(payload) = payload {
            if !invoice.detail.is_object() {
                invoice.detail = Value::Object(Map::new());
            }
            if let Some(details) = invoice.detail.as_object_mut() {
                details.insert(flag.to_string(), payload.clone());
            }
        }
        store::save_invoice(conn, &invoice, now)?;
    }
    Ok(Outcome::Recorded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::plans::{AccountPlanIds, DEFAULT_ANON_TOR_ID, DEFAULT_PAID_TOR_ID};
    use crate::billing::testkit::{conn, seed_user};
    use chrono::Duration;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn catalog() -> Catalog {
        Catalog::build(&AccountPlanIds::default(), &BTreeMap::new())
    }

    /// An account that has started checkout of `plan_id`: an `open`
    /// subscription and its unpaid first invoice.
    fn seed_purchase(conn: &Connection, user_id: i64, plan_id: &str, sub_id: &str, invoice_id: &str) {
        let now = Utc::now();
        conn.execute(
            "INSERT INTO billing_subscriptions
                (checkout_key, user_id, plan_id, subscription_id, external_user_ref, state, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'open', ?6, ?6)",
            params![format!("key-{sub_id}"), user_id, plan_id, sub_id, user_id.to_string(), now.to_rfc3339()],
        )
        .expect("seed subscription");
        store::insert_invoice(
            conn,
            &InvoiceRow {
                invoice_id: invoice_id.to_string(),
                user_id,
                subscription_id: sub_id.to_string(),
                plan_id: plan_id.to_string(),
                kind: InvoiceKind::Initial,
                status: INVOICE_NEW.to_string(),
                pay_json: "[]".to_string(),
                expires_at: Some((now + Duration::hours(1)).to_rfc3339()),
                flags: Vec::new(),
                grant_kind: None,
                grant_state: GrantState::None,
                period_from: None,
                period_to: None,
                detail: json!({}),
            },
            now,
        )
        .expect("seed invoice");
    }

    fn event(kind: &str, user_id: i64, sub_id: &str, invoice_id: &str, extra: Value) -> String {
        let mut body = json!({
            "event_id": format!("evt-{}", uuid_like()),
            "kind": kind,
            "subscriber_id": sub_id,
            "external_user_ref": user_id.to_string(),
            "invoice_id": invoice_id,
            "occurred_at": Utc::now().to_rfc3339(),
        });
        if let (Some(target), Some(extra)) = (body.as_object_mut(), extra.as_object()) {
            for (k, v) in extra {
                target.insert(k.clone(), v.clone());
            }
        }
        body.to_string()
    }

    fn uuid_like() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        format!("{}", SEQ.fetch_add(1, Ordering::Relaxed))
    }

    fn period(days: i64) -> Value {
        let now = Utc::now();
        json!({ "period": { "from": now.to_rfc3339(), "to": (now + Duration::days(days)).to_rfc3339() } })
    }

    fn run(conn: &Connection, body: &str) -> Outcome {
        process(conn, &catalog(), None, body, Utc::now()).expect("process")
    }

    fn view(conn: &Connection, uid: i64) -> entitle::EntitlementView {
        entitle::entitlement_view(conn, uid, Utc::now()).expect("view")
    }

    // ---------------------------------------------------------------- grants

    #[test]
    fn every_account_plan_grants_exactly_its_lifetime_flags() {
        // A paid account is paid; an anonymous account is anonymous AND paid.
        for (plan, paid, anon) in [
            ("mlc-paid-account-v1", true, false),
            ("mlc-anon-account-v1", true, true),
            (DEFAULT_PAID_TOR_ID, true, false),
            (DEFAULT_ANON_TOR_ID, true, true),
        ] {
            let conn = conn();
            let uid = seed_user(&conn, "buyer");
            seed_purchase(&conn, uid, plan, "sub_1", "inv_1");
            assert!(!view(&conn, uid).paid, "{plan}: unpaid before the event");

            let outcome = run(&conn, &event("payment_confirmed", uid, "sub_1", "inv_1", json!({})));
            assert_eq!(outcome, Outcome::Granted, "{plan}");
            let v = view(&conn, uid);
            assert_eq!((v.lifetime_paid, v.lifetime_anon), (paid, anon), "{plan}");
            assert!(v.paid, "{plan}");
            assert_eq!(v.quant_tier, None, "{plan}: account plans grant no quant tier");
            let sub = store::subscription_by_id(&conn, "sub_1").expect("read").expect("row");
            assert_eq!(sub.state, SubState::Paid, "{plan}");
            let inv = store::invoice_by_id(&conn, "inv_1").expect("read").expect("row");
            assert_eq!((inv.grant_state, inv.status.as_str()), (GrantState::Granted, "settled"), "{plan}");
        }
    }

    #[test]
    fn every_quant_tier_grants_its_tier_and_the_paid_period() {
        for tier in ["mlc-monthly-20-v1", "mlc-monthly-50-v1", "mlc-monthly-100-v1", "mlc-monthly-200-v1"] {
            let conn = conn();
            let uid = seed_user(&conn, "quant");
            seed_purchase(&conn, uid, tier, "sub_1", "inv_1");
            let body = event("payment_confirmed", uid, "sub_1", "inv_1", period(30));
            assert_eq!(run(&conn, &body), Outcome::Granted, "{tier}");
            let v = view(&conn, uid);
            assert_eq!(v.quant_tier.as_deref(), Some(tier));
            assert!(v.quant_active && v.paid, "{tier}");
            assert!(!v.lifetime_paid && !v.lifetime_anon, "{tier}: a tier is not a lifetime account");
            let sub = store::subscription_by_id(&conn, "sub_1").expect("read").expect("row");
            assert_eq!(sub.state, SubState::Active);
        }
    }

    #[test]
    fn a_renewal_of_an_unknown_invoice_extends_the_period() {
        let conn = conn();
        let uid = seed_user(&conn, "renew");
        seed_purchase(&conn, uid, "mlc-monthly-50-v1", "sub_1", "inv_1");
        run(&conn, &event("payment_confirmed", uid, "sub_1", "inv_1", period(30)));
        let first_end = view(&conn, uid).quant_active_until.expect("first period");

        let renewal = event("renewal_confirmed", uid, "sub_1", "inv_2", period(60));
        assert_eq!(run(&conn, &renewal), Outcome::Granted);
        let second_end = view(&conn, uid).quant_active_until.expect("second period");
        assert!(second_end > first_end);
        let inv = store::invoice_by_id(&conn, "inv_2").expect("read").expect("created on the fly");
        assert_eq!(inv.kind, InvoiceKind::Renewal);
        assert_eq!(inv.plan_id, "mlc-monthly-50-v1");
    }

    #[test]
    fn a_quant_payment_without_a_period_grants_nothing() {
        let conn = conn();
        let uid = seed_user(&conn, "noperiod");
        seed_purchase(&conn, uid, "mlc-monthly-20-v1", "sub_1", "inv_1");
        assert_eq!(run(&conn, &event("payment_confirmed", uid, "sub_1", "inv_1", json!({}))), Outcome::Malformed);
        assert!(!view(&conn, uid).paid);
    }

    #[test]
    fn a_one_time_plan_never_renews() {
        let conn = conn();
        let uid = seed_user(&conn, "onetime");
        seed_purchase(&conn, uid, "mlc-paid-account-v1", "sub_1", "inv_1");
        run(&conn, &event("payment_confirmed", uid, "sub_1", "inv_1", json!({})));
        let renewal = event("renewal_confirmed", uid, "sub_1", "inv_2", period(30));
        assert_eq!(run(&conn, &renewal), Outcome::Ignored);
        assert!(view(&conn, uid).lifetime_paid);
    }

    #[test]
    fn a_late_flag_is_recorded_and_the_payment_still_grants() {
        let conn = conn();
        let uid = seed_user(&conn, "late");
        seed_purchase(&conn, uid, "mlc-anon-account-v1", "sub_1", "inv_1");
        let body = event("payment_confirmed", uid, "sub_1", "inv_1", json!({ "flags": ["late"] }));
        assert_eq!(run(&conn, &body), Outcome::Granted);
        assert!(view(&conn, uid).lifetime_anon);
        let inv = store::invoice_by_id(&conn, "inv_1").expect("read").expect("row");
        assert_eq!(inv.flags, vec!["late".to_string()]);
    }

    #[test]
    fn a_grant_for_a_deleted_account_is_recorded_and_resurrects_nothing() {
        let conn = conn();
        seed_purchase(&conn, 4242, "mlc-paid-account-v1", "sub_1", "inv_1");
        let outcome = run(&conn, &event("payment_confirmed", 4242, "sub_1", "inv_1", json!({})));
        assert_eq!(outcome, Outcome::UserMissing);
        let users: i64 = conn.query_row("SELECT COUNT(*) FROM users WHERE id = 4242", [], |r| r.get(0)).expect("count");
        assert_eq!(users, 0);
    }

    // ------------------------------------------------------ dedup and replay

    #[test]
    fn a_replayed_event_id_is_a_no_op() {
        let conn = conn();
        let uid = seed_user(&conn, "replay");
        seed_purchase(&conn, uid, "mlc-monthly-20-v1", "sub_1", "inv_1");
        let body = event("payment_confirmed", uid, "sub_1", "inv_1", period(30));
        assert_eq!(run(&conn, &body), Outcome::Granted);
        let after_first = view(&conn, uid);
        assert_eq!(run(&conn, &body), Outcome::Duplicate);
        assert_eq!(view(&conn, uid), after_first);
        let stored: i64 = conn.query_row("SELECT COUNT(*) FROM billing_events", [], |r| r.get(0)).expect("count");
        assert_eq!(stored, 1);
    }

    #[test]
    fn a_replayed_overpayment_is_credited_once() {
        let conn = conn();
        let uid = seed_user(&conn, "overreplay");
        seed_purchase(&conn, uid, "mlc-paid-account-v1", "sub_1", "inv_1");
        let body = event(
            "payment_over",
            uid,
            "sub_1",
            "inv_1",
            json!({ "amount": { "asset": "USDT", "chain": "tron", "value": "8.000000", "received": "8.000000", "expected": "5.000000", "excess": "3.000000" } }),
        );
        assert_eq!(run(&conn, &body), Outcome::Credited);
        assert_eq!(run(&conn, &body), Outcome::Duplicate);
        assert_eq!(entitle::credit_balance(&conn, uid).expect("balance"), 3_000_000);
    }

    #[test]
    fn the_header_event_id_is_used_when_the_body_has_none() {
        let conn = conn();
        let uid = seed_user(&conn, "hdr");
        seed_purchase(&conn, uid, "mlc-paid-account-v1", "sub_1", "inv_1");
        let mut body: Value = serde_json::from_str(&event("payment_confirmed", uid, "sub_1", "inv_1", json!({}))).expect("json");
        body.as_object_mut().expect("object").remove("event_id");
        let raw = body.to_string();
        assert!(matches!(process(&conn, &catalog(), None, &raw, Utc::now()), Err(ProcessError::BadBody(_))));
        assert_eq!(process(&conn, &catalog(), Some("hdr-1"), &raw, Utc::now()).expect("process"), Outcome::Granted);
        assert_eq!(process(&conn, &catalog(), Some("hdr-1"), &raw, Utc::now()).expect("process"), Outcome::Duplicate);
    }

    #[test]
    fn malformed_bodies_are_refused_without_being_stored() {
        let conn = conn();
        for body in ["not json", "[]", "{}", r#"{"event_id":"e1"}"#, r#"{"event_id":"e1","kind":"  "}"#] {
            assert!(matches!(process(&conn, &catalog(), None, body, Utc::now()), Err(ProcessError::BadBody(_))), "{body}");
        }
        let stored: i64 = conn.query_row("SELECT COUNT(*) FROM billing_events", [], |r| r.get(0)).expect("count");
        assert_eq!(stored, 0);
    }

    // ------------------------------------------------------------- unmatched

    #[test]
    fn an_unknown_kind_is_stored_and_acknowledged() {
        let conn = conn();
        let uid = seed_user(&conn, "unk");
        seed_purchase(&conn, uid, "mlc-paid-account-v1", "sub_1", "inv_1");
        let body = event("payment_teleported", uid, "sub_1", "inv_1", json!({}));
        assert_eq!(run(&conn, &body), Outcome::UnknownKind);
        let (kind, outcome): (String, String) = conn
            .query_row("SELECT kind, outcome FROM billing_events", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("stored");
        assert_eq!((kind.as_str(), outcome.as_str()), ("payment_teleported", "unknown_kind"));
        assert!(!view(&conn, uid).paid);
    }

    #[test]
    fn an_event_for_nothing_we_know_is_stored_and_changes_nothing() {
        let conn = conn();
        let uid = seed_user(&conn, "stranger");
        assert_eq!(run(&conn, &event("payment_confirmed", uid, "sub_x", "inv_x", json!({}))), Outcome::Unmatched);
        assert!(!view(&conn, uid).paid);
        let stored: i64 = conn.query_row("SELECT COUNT(*) FROM billing_events", [], |r| r.get(0)).expect("count");
        assert_eq!(stored, 1);
    }

    #[test]
    fn a_different_account_reference_is_a_mismatch_and_grants_nothing() {
        let conn = conn();
        let uid = seed_user(&conn, "mismatch");
        seed_purchase(&conn, uid, "mlc-paid-account-v1", "sub_1", "inv_1");
        let body = event("payment_confirmed", uid + 1000, "sub_1", "inv_1", json!({}));
        assert_eq!(run(&conn, &body), Outcome::Mismatch);
        assert!(!view(&conn, uid).paid);
    }

    #[test]
    fn an_invoice_and_a_subscription_that_disagree_are_a_mismatch() {
        let conn = conn();
        let a = seed_user(&conn, "a");
        let b = seed_user(&conn, "b");
        seed_purchase(&conn, a, "mlc-paid-account-v1", "sub_a", "inv_a");
        seed_purchase(&conn, b, "mlc-paid-account-v1", "sub_b", "inv_b");
        let body = event("payment_confirmed", a, "sub_b", "inv_a", json!({}));
        assert_eq!(run(&conn, &body), Outcome::Mismatch);
        assert!(!view(&conn, a).paid && !view(&conn, b).paid);
    }

    #[test]
    fn a_plan_outside_the_catalog_grants_nothing() {
        let conn = conn();
        let uid = seed_user(&conn, "odd");
        seed_purchase(&conn, uid, "mlc-mystery-v9", "sub_1", "inv_1");
        assert_eq!(run(&conn, &event("payment_confirmed", uid, "sub_1", "inv_1", json!({}))), Outcome::UnknownPlan);
        assert!(!view(&conn, uid).paid);
    }

    // ---------------------------------------------------------------- revoke

    #[test]
    fn a_refund_revokes_a_lifetime_grant_for_good() {
        let conn = conn();
        let uid = seed_user(&conn, "refund");
        seed_purchase(&conn, uid, "mlc-paid-account-v1", "sub_1", "inv_1");
        run(&conn, &event("payment_confirmed", uid, "sub_1", "inv_1", json!({})));
        assert!(view(&conn, uid).lifetime_paid);

        assert_eq!(run(&conn, &event("refund_recorded", uid, "sub_1", "inv_1", json!({}))), Outcome::Revoked);
        assert!(!view(&conn, uid).paid);
        let inv = store::invoice_by_id(&conn, "inv_1").expect("read").expect("row");
        assert_eq!((inv.grant_state, inv.status.as_str()), (GrantState::Revoked, "refunded"));

        // Nothing re-grants a refunded invoice, not even a late confirmation.
        assert_eq!(run(&conn, &event("payment_confirmed", uid, "sub_1", "inv_1", json!({}))), Outcome::Ignored);
        assert!(!view(&conn, uid).paid);
        assert!(!restore_reverted(&conn, &catalog(), uid, "inv_1", Utc::now()).expect("restore"));
    }

    #[test]
    fn a_refund_of_the_latest_quant_period_falls_back_to_the_earlier_one() {
        let conn = conn();
        let uid = seed_user(&conn, "qrefund");
        seed_purchase(&conn, uid, "mlc-monthly-20-v1", "sub_1", "inv_1");
        run(&conn, &event("payment_confirmed", uid, "sub_1", "inv_1", period(30)));
        let first_end = view(&conn, uid).quant_active_until.expect("first");
        run(&conn, &event("renewal_confirmed", uid, "sub_1", "inv_2", period(60)));
        assert_ne!(view(&conn, uid).quant_active_until.as_deref(), Some(first_end.as_str()));

        assert_eq!(run(&conn, &event("refund_recorded", uid, "sub_1", "inv_2", json!({}))), Outcome::Revoked);
        assert_eq!(view(&conn, uid).quant_active_until.as_deref(), Some(first_end.as_str()));
        assert!(view(&conn, uid).paid, "the first, unrefunded period still runs");

        assert_eq!(run(&conn, &event("refund_recorded", uid, "sub_1", "inv_1", json!({}))), Outcome::Revoked);
        assert!(!view(&conn, uid).paid);
        assert_eq!(view(&conn, uid).quant_tier, None);
    }

    #[test]
    fn a_second_purchase_keeps_the_lifetime_flag_when_the_first_is_refunded() {
        let conn = conn();
        let uid = seed_user(&conn, "double");
        seed_purchase(&conn, uid, "mlc-paid-account-v1", "sub_1", "inv_1");
        seed_purchase(&conn, uid, DEFAULT_PAID_TOR_ID, "sub_2", "inv_2");
        run(&conn, &event("payment_confirmed", uid, "sub_1", "inv_1", json!({})));
        run(&conn, &event("payment_confirmed", uid, "sub_2", "inv_2", json!({})));
        run(&conn, &event("refund_recorded", uid, "sub_1", "inv_1", json!({})));
        assert!(view(&conn, uid).lifetime_paid, "inv_2 still backs it");
        run(&conn, &event("refund_recorded", uid, "sub_2", "inv_2", json!({})));
        assert!(!view(&conn, uid).lifetime_paid);
    }

    #[test]
    fn a_reorg_revokes_provisionally_and_a_resettlement_restores_it() {
        let conn = conn();
        let uid = seed_user(&conn, "reorg");
        seed_purchase(&conn, uid, "mlc-monthly-100-v1", "sub_1", "inv_1");
        run(&conn, &event("payment_confirmed", uid, "sub_1", "inv_1", period(30)));
        assert!(view(&conn, uid).paid);

        let reverted = event("payment_reverted", uid, "sub_1", "inv_1", json!({ "previous_status": "settled", "new_status": "processing" }));
        assert_eq!(run(&conn, &reverted), Outcome::Reverted);
        assert!(!view(&conn, uid).paid);
        let inv = store::invoice_by_id(&conn, "inv_1").expect("read").expect("row");
        assert_eq!((inv.grant_state, inv.status.as_str()), (GrantState::Reverted, "reverted"));

        assert!(restore_reverted(&conn, &catalog(), uid, "inv_1", Utc::now()).expect("restore"));
        assert!(view(&conn, uid).paid);
        assert_eq!(view(&conn, uid).quant_tier.as_deref(), Some("mlc-monthly-100-v1"));
        assert!(!restore_reverted(&conn, &catalog(), uid, "inv_1", Utc::now()).expect("restore again"));
    }

    #[test]
    fn restoring_is_owner_scoped() {
        let conn = conn();
        let owner = seed_user(&conn, "owner");
        let other = seed_user(&conn, "other");
        seed_purchase(&conn, owner, "mlc-paid-account-v1", "sub_1", "inv_1");
        run(&conn, &event("payment_confirmed", owner, "sub_1", "inv_1", json!({})));
        run(&conn, &event("payment_reverted", owner, "sub_1", "inv_1", json!({})));
        assert!(!restore_reverted(&conn, &catalog(), other, "inv_1", Utc::now()).expect("restore"));
        assert!(!view(&conn, owner).paid);
    }

    #[test]
    fn a_refund_of_an_invoice_that_granted_nothing_is_only_recorded() {
        let conn = conn();
        let uid = seed_user(&conn, "norefund");
        seed_purchase(&conn, uid, "mlc-paid-account-v1", "sub_1", "inv_1");
        assert_eq!(run(&conn, &event("refund_recorded", uid, "sub_1", "inv_1", json!({}))), Outcome::Recorded);
        assert!(!view(&conn, uid).paid);
    }

    // ------------------------------------------------------------- integrity

    #[test]
    fn a_partial_payment_is_recorded_with_its_amounts_and_grants_nothing() {
        let conn = conn();
        let uid = seed_user(&conn, "partial");
        seed_purchase(&conn, uid, "mlc-paid-account-v1", "sub_1", "inv_1");
        let amount = json!({ "asset": "USDT", "chain": "tron", "value": "2.000000", "received": "2.000000", "expected": "5.000000", "shortfall": "3.000000" });
        let body = event("payment_partial", uid, "sub_1", "inv_1", json!({ "amount": amount }));
        assert_eq!(run(&conn, &body), Outcome::Recorded);
        assert!(!view(&conn, uid).paid);
        let inv = store::invoice_by_id(&conn, "inv_1").expect("read").expect("row");
        assert_eq!(inv.flags, vec!["partial".to_string()]);
        assert_eq!(inv.detail["partial"]["shortfall"], "3.000000");
        assert_eq!((inv.grant_state, inv.status.as_str()), (GrantState::None, "new"));
    }

    #[test]
    fn an_overpayment_is_credited_only_for_stablecoins_and_only_the_excess() {
        let conn = conn();
        let uid = seed_user(&conn, "over");
        seed_purchase(&conn, uid, "mlc-anon-account-v1", "sub_1", "inv_1");
        let stable = event("payment_over", uid, "sub_1", "inv_1", json!({ "amount": { "asset": "usdc", "received": "12.500000", "expected": "10.000000" } }));
        assert_eq!(run(&conn, &stable), Outcome::Credited);
        assert_eq!(entitle::credit_balance(&conn, uid).expect("balance"), 2_500_000);

        let other_asset = event("payment_over", uid, "sub_1", "inv_1", json!({ "amount": { "asset": "ETH", "excess": "1.000000" } }));
        assert_eq!(run(&conn, &other_asset), Outcome::Recorded);
        let garbage = event("payment_over", uid, "sub_1", "inv_1", json!({ "amount": { "asset": "USDT", "excess": "lots" } }));
        assert_eq!(run(&conn, &garbage), Outcome::Recorded);
        assert_eq!(entitle::credit_balance(&conn, uid).expect("balance"), 2_500_000);
        let inv = store::invoice_by_id(&conn, "inv_1").expect("read").expect("row");
        assert!(inv.flags.iter().any(|f| f == "over"));
    }

    #[test]
    fn failed_no_show_funds_pending_and_anomaly_are_recorded_without_touching_entitlements() {
        let conn = conn();
        let uid = seed_user(&conn, "integrity");
        seed_purchase(&conn, uid, "mlc-monthly-20-v1", "sub_1", "inv_1");
        for (kind, flag, extra) in [
            ("payment_failed", "failed", json!({})),
            ("payment_no_show", "no_show", json!({})),
            ("funds_pending_on_expiry", "funds_pending", json!({ "amount": { "received": "1.000000" } })),
            ("payment_anomaly", "anomaly", json!({ "anomaly": { "subkind": "dust", "count": 3 } })),
        ] {
            assert_eq!(run(&conn, &event(kind, uid, "sub_1", "inv_1", extra)), Outcome::Recorded, "{kind}");
            let inv = store::invoice_by_id(&conn, "inv_1").expect("read").expect("row");
            assert!(inv.flags.iter().any(|f| f == flag), "{kind} -> {flag}");
        }
        assert!(!view(&conn, uid).paid);
        let inv = store::invoice_by_id(&conn, "inv_1").expect("read").expect("row");
        assert_eq!(inv.detail["anomaly"]["subkind"], "dust");
    }

    #[test]
    fn a_processor_incident_is_recorded_with_no_account() {
        let conn = conn();
        let body = json!({ "event_id": "inc-1", "kind": "processor_incident", "incident": { "chain": "evm:1", "incident_kind": "quorum_disagreement" } }).to_string();
        assert_eq!(run(&conn, &body), Outcome::Recorded);
        let (outcome, user): (String, Option<i64>) = conn
            .query_row("SELECT outcome, user_id FROM billing_events WHERE event_id = 'inc-1'", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("stored");
        assert_eq!((outcome.as_str(), user), ("recorded", None));
    }

    // -------------------------------------------------------- plan changes

    fn seed_active_20(conn: &Connection, uid: i64) {
        seed_purchase(conn, uid, "mlc-monthly-20-v1", "sub_1", "inv_1");
        run(conn, &event("payment_confirmed", uid, "sub_1", "inv_1", period(30)));
        conn.execute(
            "UPDATE billing_subscriptions SET pending_change_id = 'chg_1', pending_plan_id = 'mlc-monthly-100-v1' WHERE subscription_id = 'sub_1'",
            [],
        )
        .expect("pending change");
    }

    #[test]
    fn an_applied_change_moves_the_tier_and_keeps_the_change_id() {
        let conn = conn();
        let uid = seed_user(&conn, "upgrade");
        seed_active_20(&conn, uid);
        assert_eq!(view(&conn, uid).quant_tier.as_deref(), Some("mlc-monthly-20-v1"));

        let applied = event("subscription_changed", uid, "sub_1", "inv_1", json!({ "change_id": "chg_1", "state": "applied" }));
        assert_eq!(run(&conn, &applied), Outcome::PlanChanged);
        assert_eq!(view(&conn, uid).quant_tier.as_deref(), Some("mlc-monthly-100-v1"));
        let sub = store::subscription_by_id(&conn, "sub_1").expect("read").expect("row");
        assert_eq!(sub.plan_id, "mlc-monthly-100-v1");
        assert_eq!(sub.last_change_id.as_deref(), Some("chg_1"));
        assert_eq!(sub.pending_change_id, None);

        // A second delivery of the same change (new event id) changes nothing.
        let again = event("subscription_changed", uid, "sub_1", "inv_1", json!({ "change_id": "chg_1", "state": "applied" }));
        assert_eq!(run(&conn, &again), Outcome::Recorded);
    }

    #[test]
    fn a_change_mlc_never_requested_is_recorded_not_applied() {
        let conn = conn();
        let uid = seed_user(&conn, "stray");
        seed_active_20(&conn, uid);
        let stray = event("subscription_changed", uid, "sub_1", "inv_1", json!({ "change_id": "chg_other", "state": "applied" }));
        assert_eq!(run(&conn, &stray), Outcome::UnknownChange);
        assert_eq!(view(&conn, uid).quant_tier.as_deref(), Some("mlc-monthly-20-v1"));
        let no_id = event("subscription_changed", uid, "sub_1", "inv_1", json!({ "state": "applied" }));
        assert_eq!(run(&conn, &no_id), Outcome::UnknownChange);
    }

    #[test]
    fn a_cancelled_change_drops_the_pending_one_and_keeps_the_plan() {
        let conn = conn();
        let uid = seed_user(&conn, "cancel");
        seed_active_20(&conn, uid);
        let cancelled = event("subscription_changed", uid, "sub_1", "inv_1", json!({ "change_id": "chg_1", "state": "cancelled" }));
        assert_eq!(run(&conn, &cancelled), Outcome::ChangeCancelled);
        let sub = store::subscription_by_id(&conn, "sub_1").expect("read").expect("row");
        assert_eq!((sub.plan_id.as_str(), sub.pending_change_id), ("mlc-monthly-20-v1", None));
    }

    #[test]
    fn the_payment_of_a_proration_invoice_grants_no_period_by_itself() {
        let conn = conn();
        let uid = seed_user(&conn, "proration");
        seed_active_20(&conn, uid);
        let before = view(&conn, uid);
        let pay = event("payment_confirmed", uid, "sub_1", "inv_prorate", period(400));
        assert_eq!(run(&conn, &pay), Outcome::Recorded);
        assert_eq!(view(&conn, uid), before, "the upgrade lands on subscription_changed only");
        let inv = store::invoice_by_id(&conn, "inv_prorate").expect("read").expect("row");
        assert_eq!(inv.kind, InvoiceKind::Proration);
    }

    // --------------------------------------------------- subscription state

    #[test]
    fn past_due_then_a_renewal_returns_to_active_and_cancel_keeps_paid_time() {
        let conn = conn();
        let uid = seed_user(&conn, "lifecycle");
        seed_purchase(&conn, uid, "mlc-monthly-20-v1", "sub_1", "inv_1");
        run(&conn, &event("payment_confirmed", uid, "sub_1", "inv_1", period(30)));

        assert_eq!(run(&conn, &event("subscription_past_due", uid, "sub_1", "inv_2", json!({}))), Outcome::Recorded);
        let sub = store::subscription_by_id(&conn, "sub_1").expect("read").expect("row");
        assert_eq!(sub.state, SubState::PastDue);
        assert!(view(&conn, uid).paid, "the period already bought still runs");

        run(&conn, &event("renewal_confirmed", uid, "sub_1", "inv_2", period(60)));
        let sub = store::subscription_by_id(&conn, "sub_1").expect("read").expect("row");
        assert_eq!(sub.state, SubState::Active);

        run(&conn, &event("subscription_cancelled", uid, "sub_1", "inv_2", json!({})));
        let sub = store::subscription_by_id(&conn, "sub_1").expect("read").expect("row");
        assert_eq!(sub.state, SubState::Cancelled);
        assert!(view(&conn, uid).paid);
    }

    #[test]
    fn a_settled_one_time_plan_stays_paid_through_subscription_events() {
        let conn = conn();
        let uid = seed_user(&conn, "terminal");
        seed_purchase(&conn, uid, "mlc-paid-account-v1", "sub_1", "inv_1");
        run(&conn, &event("payment_confirmed", uid, "sub_1", "inv_1", json!({})));
        run(&conn, &event("subscription_cancelled", uid, "sub_1", "inv_1", json!({})));
        run(&conn, &event("subscription_past_due", uid, "sub_1", "inv_1", json!({})));
        let sub = store::subscription_by_id(&conn, "sub_1").expect("read").expect("row");
        assert_eq!(sub.state, SubState::Paid);
        assert!(view(&conn, uid).lifetime_paid);
    }

    // ----------------------------------------- one-time contract (dig2pay)

    fn settled_one_time(extra: Value) -> Value {
        let mut body = json!({
            "billing_interval": "one_time",
            "period": { "from": Utc::now().to_rfc3339(), "to": null },
        });
        if let (Some(target), Some(extra)) = (body.as_object_mut(), extra.as_object()) {
            for (k, v) in extra {
                target.insert(k.clone(), v.clone());
            }
        }
        body
    }

    fn date_columns(conn: &Connection, uid: i64) -> (Option<String>, Option<String>) {
        conn.query_row(
            "SELECT paid_until, quant_active_until FROM users WHERE id = ?1",
            params![uid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("date columns")
    }

    #[test]
    fn a_one_time_settlement_with_a_null_to_grants_permanently_and_writes_no_date() {
        for plan in ["mlc-paid-account-v1", DEFAULT_PAID_TOR_ID] {
            let conn = conn();
            let uid = seed_user(&conn, "forever");
            seed_purchase(&conn, uid, plan, "sub_1", "inv_1");
            let body = event("payment_confirmed", uid, "sub_1", "inv_1", settled_one_time(json!({ "plan_id": plan })));
            assert_eq!(run(&conn, &body), Outcome::Granted, "{plan}");

            let v = view(&conn, uid);
            assert!(v.lifetime_paid && !v.lifetime_anon && v.paid, "{plan}");
            assert_eq!(date_columns(&conn, uid), (None, None), "{plan}: no date column is written");
            let inv = store::invoice_by_id(&conn, "inv_1").expect("read").expect("row");
            assert!(inv.period_from.is_some(), "the settlement moment is kept");
            assert_eq!(inv.period_to, None, "{plan}: a one-time grant has no end");
            // Ten years on the account is still paid: nothing expires.
            let far_future = Utc::now() + Duration::days(3650);
            assert!(entitle::entitlement_view(&conn, uid, far_future).expect("view").paid, "{plan}");
        }
    }

    #[test]
    fn an_anonymous_account_plan_grants_anonymous_and_paid_and_a_refund_clears_both() {
        for plan in ["mlc-anon-account-v1", DEFAULT_ANON_TOR_ID] {
            let conn = conn();
            let uid = seed_user(&conn, "anon");
            seed_purchase(&conn, uid, plan, "sub_1", "inv_1");
            let body = event("payment_confirmed", uid, "sub_1", "inv_1", settled_one_time(json!({ "plan_id": plan })));
            assert_eq!(run(&conn, &body), Outcome::Granted, "{plan}");
            let v = view(&conn, uid);
            assert!(v.lifetime_anon && v.lifetime_paid && v.paid, "{plan}");
            assert_eq!(date_columns(&conn, uid), (None, None));

            assert_eq!(run(&conn, &event("refund_recorded", uid, "sub_1", "inv_1", json!({}))), Outcome::Revoked);
            let v = view(&conn, uid);
            assert!(!v.lifetime_anon && !v.lifetime_paid && !v.paid, "{plan}: both flags go");
        }
    }

    #[test]
    fn refunding_an_anonymous_purchase_keeps_paid_when_a_paid_purchase_backs_it() {
        let conn = conn();
        let uid = seed_user(&conn, "both");
        seed_purchase(&conn, uid, "mlc-paid-account-v1", "sub_p", "inv_p");
        seed_purchase(&conn, uid, "mlc-anon-account-v1", "sub_a", "inv_a");
        run(&conn, &event("payment_confirmed", uid, "sub_p", "inv_p", settled_one_time(json!({}))));
        run(&conn, &event("payment_confirmed", uid, "sub_a", "inv_a", settled_one_time(json!({}))));
        let v = view(&conn, uid);
        assert!(v.lifetime_paid && v.lifetime_anon);

        assert_eq!(run(&conn, &event("refund_recorded", uid, "sub_a", "inv_a", json!({}))), Outcome::Revoked);
        let v = view(&conn, uid);
        assert!(v.lifetime_paid && !v.lifetime_anon, "the paid purchase still backs lifetime_paid");
        assert!(v.paid);
    }

    #[test]
    fn either_signal_alone_marks_a_settlement_one_time() {
        // billing_interval only, no period at all.
        let first = conn();
        let uid = seed_user(&first, "interval-only");
        seed_purchase(&first, uid, "mlc-paid-account-v1", "sub_1", "inv_1");
        let body = event("payment_confirmed", uid, "sub_1", "inv_1", json!({ "billing_interval": "one_time" }));
        assert_eq!(run(&first, &body), Outcome::Granted);
        assert!(view(&first, uid).lifetime_paid);

        // A null `to` only, no billing_interval (an older body shape).
        let second = conn();
        let uid = seed_user(&second, "null-to-only");
        seed_purchase(&second, uid, "mlc-anon-account-v1", "sub_1", "inv_1");
        let body = event("payment_confirmed", uid, "sub_1", "inv_1", json!({ "period": { "from": Utc::now().to_rfc3339(), "to": null } }));
        assert_eq!(run(&second, &body), Outcome::Granted);
        assert!(view(&second, uid).lifetime_anon);

        // `to` absent from the period object entirely.
        let third = conn();
        let uid = seed_user(&third, "absent-to");
        seed_purchase(&third, uid, "mlc-paid-account-v1", "sub_1", "inv_1");
        let body = event("payment_confirmed", uid, "sub_1", "inv_1", json!({ "period": { "from": Utc::now().to_rfc3339() } }));
        assert_eq!(run(&third, &body), Outcome::Granted);
    }

    #[test]
    fn a_monthly_plan_with_a_null_to_or_a_one_time_interval_is_malformed_and_grants_nothing() {
        let now = Utc::now();
        let bodies = [
            ("null to", json!({ "period": { "from": now.to_rfc3339(), "to": null } })),
            ("absent to", json!({ "period": { "from": now.to_rfc3339() } })),
            ("no period", json!({})),
            ("unparsable to", json!({ "period": { "from": now.to_rfc3339(), "to": "soon" } })),
            (
                "one_time interval on a closed period",
                json!({ "billing_interval": "one_time", "period": { "from": now.to_rfc3339(), "to": (now + Duration::days(30)).to_rfc3339() } }),
            ),
        ];
        for (label, extra) in bodies {
            let conn = conn();
            let uid = seed_user(&conn, "malformed");
            seed_purchase(&conn, uid, "mlc-monthly-50-v1", "sub_1", "inv_1");
            let outcome = run(&conn, &event("payment_confirmed", uid, "sub_1", "inv_1", extra));
            assert_eq!(outcome, Outcome::Malformed, "{label}");
            let v = view(&conn, uid);
            assert!(!v.paid && v.quant_tier.is_none(), "{label}: nothing granted");
            assert_eq!(date_columns(&conn, uid), (None, None), "{label}: no date written");
            let inv = store::invoice_by_id(&conn, "inv_1").expect("read").expect("row");
            assert_eq!((inv.grant_state, inv.period_to), (GrantState::None, None), "{label}");
            let stored: String = conn
                .query_row("SELECT outcome FROM billing_events", [], |r| r.get(0))
                .expect("the event is still stored");
            assert_eq!(stored, "malformed", "{label}");
        }
    }

    #[test]
    fn a_one_time_plan_billed_monthly_is_malformed_and_grants_nothing() {
        let conn = conn();
        let uid = seed_user(&conn, "contradiction");
        seed_purchase(&conn, uid, "mlc-paid-account-v1", "sub_1", "inv_1");
        let body = event("payment_confirmed", uid, "sub_1", "inv_1", json!({ "billing_interval": "monthly", "period": period(30)["period"].clone() }));
        assert_eq!(run(&conn, &body), Outcome::Malformed);
        assert!(!view(&conn, uid).paid);
    }

    #[test]
    fn additive_fields_are_optional_and_unknown_fields_are_ignored() {
        let conn = conn();
        let uid = seed_user(&conn, "decode");
        seed_purchase(&conn, uid, "mlc-monthly-20-v1", "sub_1", "inv_1");
        // The older monthly body: closed period, none of the new fields.
        let old = event("payment_confirmed", uid, "sub_1", "inv_1", period(30));
        assert_eq!(run(&conn, &old), Outcome::Granted);
        // The newer one, with the additive fields and something unheard of.
        let mut newer = period(60);
        if let Some(obj) = newer.as_object_mut() {
            obj.insert("plan_id".to_string(), json!("mlc-monthly-20-v1"));
            obj.insert("billing_interval".to_string(), json!("monthly"));
            obj.insert("some_future_field".to_string(), json!({ "nested": [1, 2, 3] }));
        }
        let renewal = event("renewal_confirmed", uid, "sub_1", "inv_2", newer);
        assert_eq!(run(&conn, &renewal), Outcome::Granted);
        assert_eq!(view(&conn, uid).quant_tier.as_deref(), Some("mlc-monthly-20-v1"));
    }

    #[test]
    fn a_renewal_event_names_its_plan_for_an_invoice_mlc_has_not_seen() {
        let conn = conn();
        let uid = seed_user(&conn, "plan-named");
        seed_purchase(&conn, uid, "mlc-monthly-20-v1", "sub_1", "inv_1");
        run(&conn, &event("payment_confirmed", uid, "sub_1", "inv_1", period(30)));
        let mut renewal = period(60);
        if let Some(obj) = renewal.as_object_mut() {
            obj.insert("plan_id".to_string(), json!("mlc-monthly-100-v1"));
        }
        assert_eq!(run(&conn, &event("renewal_confirmed", uid, "sub_1", "inv_2", renewal)), Outcome::Granted);
        let inv = store::invoice_by_id(&conn, "inv_2").expect("read").expect("created");
        assert_eq!(inv.plan_id, "mlc-monthly-100-v1");
        // An id outside the catalog is ignored in favour of the subscription's plan.
        let mut bogus = period(90);
        if let Some(obj) = bogus.as_object_mut() {
            obj.insert("plan_id".to_string(), json!("mlc-not-a-plan"));
        }
        assert_eq!(run(&conn, &event("renewal_confirmed", uid, "sub_1", "inv_3", bogus)), Outcome::Granted);
        let inv = store::invoice_by_id(&conn, "inv_3").expect("read").expect("created");
        assert_eq!(inv.plan_id, "mlc-monthly-20-v1");
    }

    #[test]
    fn an_applied_change_the_event_names_lands_even_if_mlcs_pending_record_is_gone() {
        let conn = conn();
        let uid = seed_user(&conn, "healed");
        seed_purchase(&conn, uid, "mlc-monthly-20-v1", "sub_1", "inv_1");
        run(&conn, &event("payment_confirmed", uid, "sub_1", "inv_1", period(30)));
        // No pending row at all, but the event says which plan the change moved to.
        let applied = event(
            "subscription_changed",
            uid,
            "sub_1",
            "inv_1",
            json!({ "change_id": "chg_lost", "state": "applied", "plan_id": "mlc-monthly-50-v1" }),
        );
        assert_eq!(run(&conn, &applied), Outcome::PlanChanged);
        assert_eq!(view(&conn, uid).quant_tier.as_deref(), Some("mlc-monthly-50-v1"));
        // A plan outside the quant catalog is never applied.
        let bogus = event(
            "subscription_changed",
            uid,
            "sub_1",
            "inv_1",
            json!({ "change_id": "chg_bad", "state": "applied", "plan_id": "mlc-paid-account-v1" }),
        );
        assert_eq!(run(&conn, &bogus), Outcome::UnknownChange);
        assert_eq!(view(&conn, uid).quant_tier.as_deref(), Some("mlc-monthly-50-v1"));
    }
    // ------------------------------------------------------- grant ledger

    fn ledger(conn: &Connection, uid: i64) -> Vec<(String, String, bool)> {
        crate::billing::grants::list(conn, uid)
            .expect("ledger")
            .into_iter()
            .map(|g| (g.grant.as_str().to_string(), g.source_ref, g.revoked_at.is_none()))
            .collect()
    }

    #[test]
    fn a_refund_leaves_an_admin_grant_and_another_invoices_grant_alone_and_a_resettle_restores_only_its_own() {
        let conn = conn();
        let uid = seed_user(&conn, "ledger");
        seed_purchase(&conn, uid, "mlc-paid-account-v1", "sub_a", "inv_a");
        seed_purchase(&conn, uid, DEFAULT_PAID_TOR_ID, "sub_b", "inv_b");
        run(&conn, &event("payment_confirmed", uid, "sub_a", "inv_a", settled_one_time(json!({}))));
        run(&conn, &event("payment_confirmed", uid, "sub_b", "inv_b", settled_one_time(json!({}))));
        crate::billing::grants::add_admin(&conn, uid, Grant::LifetimePaid, 9, "support", Utc::now())
            .expect("admin grant")
            .expect("user");
        assert_eq!(ledger(&conn, uid).len(), 3);

        // Invoice A is refunded: only A's row is revoked.
        assert_eq!(run(&conn, &event("refund_recorded", uid, "sub_a", "inv_a", json!({}))), Outcome::Revoked);
        assert!(view(&conn, uid).lifetime_paid, "B and the admin grant still hold it");
        assert_eq!(
            ledger(&conn, uid),
            vec![
                ("lifetime_paid".to_string(), "inv_a".to_string(), false),
                ("lifetime_paid".to_string(), "inv_b".to_string(), true),
                ("lifetime_paid".to_string(), "9:support".to_string(), true),
            ]
        );

        // B is reorged out: provisional, and the admin grant still holds it.
        assert_eq!(run(&conn, &event("payment_reverted", uid, "sub_b", "inv_b", json!({}))), Outcome::Reverted);
        assert!(view(&conn, uid).lifetime_paid);
        let admin_row = crate::billing::grants::list(&conn, uid).expect("ledger").into_iter().find(|g| g.source == "admin").expect("admin row");
        crate::billing::grants::revoke_admin(&conn, uid, admin_row.id, Utc::now()).expect("revoke admin");
        assert!(!view(&conn, uid).lifetime_paid, "A refunded, B reverted, admin revoked: nothing left");

        // B settles again: exactly B's row comes back. A (refunded) and the admin row do not.
        assert!(restore_reverted(&conn, &catalog(), uid, "inv_b", Utc::now()).expect("restore"));
        assert!(view(&conn, uid).lifetime_paid);
        assert_eq!(
            ledger(&conn, uid),
            vec![
                ("lifetime_paid".to_string(), "inv_a".to_string(), false),
                ("lifetime_paid".to_string(), "inv_b".to_string(), true),
                ("lifetime_paid".to_string(), "9:support".to_string(), false),
            ]
        );
        assert!(!restore_reverted(&conn, &catalog(), uid, "inv_a", Utc::now()).expect("a refund is final"));
    }

    #[test]
    fn an_anonymous_purchase_writes_two_ledger_rows_and_activates_a_pending_account() {
        let conn = conn();
        let now = Utc::now();
        let key = crate::billing::anon::Credential::random();
        let uid = crate::billing::anon::create_pending(&conn, &key, now).expect("pending");
        seed_purchase(&conn, uid, "mlc-anon-account-v1", "sub_1", "inv_1");
        assert_eq!(
            crate::billing::anon::status_of(&conn, uid).expect("status"),
            Some(crate::billing::anon::AccountStatus::Pending)
        );
        assert_eq!(run(&conn, &event("payment_confirmed", uid, "sub_1", "inv_1", settled_one_time(json!({})))), Outcome::Granted);
        assert_eq!(
            crate::billing::anon::status_of(&conn, uid).expect("status"),
            Some(crate::billing::anon::AccountStatus::Active)
        );
        let mut rows = ledger(&conn, uid);
        rows.sort();
        assert_eq!(
            rows,
            vec![
                ("lifetime_anon".to_string(), "inv_1".to_string(), true),
                ("lifetime_paid".to_string(), "inv_1".to_string(), true),
            ]
        );
        // A refund revokes both and leaves the (now active) account in place.
        assert_eq!(run(&conn, &event("refund_recorded", uid, "sub_1", "inv_1", json!({}))), Outcome::Revoked);
        let v = view(&conn, uid);
        assert!(!v.lifetime_anon && !v.lifetime_paid);
        assert_eq!(
            crate::billing::anon::status_of(&conn, uid).expect("status"),
            Some(crate::billing::anon::AccountStatus::Active)
        );
    }
}

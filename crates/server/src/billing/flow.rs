//! The signed-in billing operations: what a route does between the database
//! and the dig2pay merchant API.
//!
//! Every operation follows the same discipline: read and decide inside one
//! short database call, make the HTTP call with NO database lock held, then
//! write the result in a second short database call. The database mutex is a
//! blocking `std::sync::Mutex`; it is never held across an `.await`.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use rand::Rng;
use rusqlite::Connection;

use super::anon::{self, AccountKey};
use super::client::{GatewayError, PayOption, Proration};
use super::entitle::{self, EntitlementView};
use super::plans::Grant;
use super::store::{
    self, GrantState, InvoiceKind, InvoiceRow, Prepared, Refusal, SubscriptionRow, INVOICE_NEW,
};
use super::webhook;
use crate::state::AppState;

/// Why an operation did not complete.
#[derive(Debug)]
pub enum FlowError {
    /// Billing (or the merchant API side of it) is not configured.
    NotConfigured,
    /// The plan does not exist, or is not offered to this request's origin.
    PlanNotAvailable,
    /// MLC sells the plan but the processor does not have it (yet).
    PlanUnavailable,
    /// An anonymous-account plan asked for through the signed-in checkout:
    /// those are sold only by `POST /api/billing/anon-checkout`, which
    /// creates the new account they belong to.
    AnonymousOnly,
    /// Refused before dig2pay was called.
    Refused(Refusal),
    /// A plan change was asked for without a running monthly subscription.
    NoSubscription,
    /// The requested plan is the current one.
    SamePlan,
    /// A change is already waiting to be applied.
    ChangePending,
    /// No such invoice for this account (also: someone else's).
    NotFound,
    /// dig2pay failed or refused.
    Gateway(GatewayError),
    /// The database failed.
    Db(String),
}

impl From<GatewayError> for FlowError {
    fn from(e: GatewayError) -> Self {
        FlowError::Gateway(e)
    }
}

/// Run `work` on the identity database connection off the async runtime.
async fn with_db<T, F>(state: &Arc<AppState>, work: F) -> Result<T, FlowError>
where
    T: Send + 'static,
    F: FnOnce(&Connection) -> rusqlite::Result<T> + Send + 'static,
{
    let state = state.clone();
    tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        work(&conn)
    })
    .await
    .map_err(|_| FlowError::Db("database task failed".to_string()))?
    .map_err(|e| FlowError::Db(e.to_string()))
}

/// [`with_db`] plus the messenger connection and its wake registry, for work
/// that deletes an account and so has to strip its Matrix devices too. The
/// identity lock is taken first, then the messenger lock (the lock order).
async fn with_db_and_messenger<T, F>(state: &Arc<AppState>, work: F) -> Result<T, FlowError>
where
    T: Send + 'static,
    F: FnOnce(&Connection, &mut Connection, &mylittlechart_server::live::LiveRegistry) -> rusqlite::Result<T>
        + Send
        + 'static,
{
    let state = state.clone();
    tokio::task::spawn_blocking(move || {
        let cp = state.control_plane();
        let conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
        let mut messenger = cp.messenger_conn();
        work(&conn, &mut messenger, &cp.live)
    })
    .await
    .map_err(|_| FlowError::Db("database task failed".to_string()))?
    .map_err(|e| FlowError::Db(e.to_string()))
}

/// dig2pay answers 404 for a plan it does not have (yet) — the one-time
/// account plans are created on the processor separately from MLC's catalog.
fn processor_error(e: GatewayError) -> FlowError {
    match e {
        GatewayError::Refused { status: 404, .. } => FlowError::PlanUnavailable,
        other => FlowError::Gateway(other),
    }
}

fn new_checkout_key() -> String {
    let bytes: [u8; 16] = rand::thread_rng().gen();
    format!("mlc-co-{}", hex::encode(bytes))
}

/// The earliest `expires_at` among the options, as stored on the invoice.
fn earliest_expiry(pay: &[PayOption]) -> Option<String> {
    pay.iter()
        .filter_map(|o| DateTime::parse_from_rfc3339(&o.expires_at).ok())
        .map(|t| t.with_timezone(&Utc))
        .min()
        .map(|t| t.to_rfc3339())
}

fn pay_of(invoice: &InvoiceRow) -> Vec<PayOption> {
    match serde_json::from_str(&invoice.pay_json) {
        Ok(pay) => pay,
        Err(e) => {
            tracing::error!("billing invoice {} has unreadable pay_json: {e}", invoice.invoice_id);
            Vec::new()
        }
    }
}

// ============================================================================
// Checkout
// ============================================================================

/// `POST /api/billing/checkout` result.
pub struct CheckoutView {
    /// dig2pay's invoice id.
    pub invoice_id: String,
    /// The plan being bought.
    pub plan_id: String,
    /// Every way to pay it.
    pub pay: Vec<PayOption>,
}

/// Start (or resume) the purchase of `plan_id` by the signed-in `user_id`.
/// `onion` says whether the request came through the onion vhost. Anonymous
/// account plans are refused here (see [`FlowError::AnonymousOnly`]).
pub async fn checkout(
    state: &Arc<AppState>,
    user_id: i64,
    plan_id: &str,
    onion: bool,
) -> Result<CheckoutView, FlowError> {
    checkout_for(state, user_id, plan_id, onion, false).await
}

/// The purchase itself. `anonymous_purchase` is true only for the account
/// [`anon_checkout`] has just created for the payer.
async fn checkout_for(
    state: &Arc<AppState>,
    user_id: i64,
    plan_id: &str,
    onion: bool,
    anonymous_purchase: bool,
) -> Result<CheckoutView, FlowError> {
    let billing = state.billing().ok_or(FlowError::NotConfigured)?;
    let client = billing.client().ok_or(FlowError::NotConfigured)?;
    let plan = billing
        .catalog()
        .get(plan_id)
        .filter(|p| p.offered_to(onion))
        .cloned()
        .ok_or(FlowError::PlanNotAvailable)?;
    if plan.grant == Grant::LifetimeAnon && !anonymous_purchase {
        return Err(FlowError::AnonymousOnly);
    }

    let prepared = {
        let billing = billing.clone();
        let plan = plan.clone();
        with_db(state, move |conn| {
            store::prepare_checkout(conn, billing.catalog(), user_id, &plan, Utc::now(), new_checkout_key)
        })
        .await?
    };
    let (checkout_key, customer, external_user_ref) = match prepared {
        Prepared::Refused(refusal) => return Err(FlowError::Refused(refusal)),
        Prepared::Existing(invoice) => {
            return Ok(CheckoutView {
                pay: pay_of(&invoice),
                invoice_id: invoice.invoice_id,
                plan_id: invoice.plan_id,
            });
        }
        Prepared::Create { checkout_key, customer, external_user_ref } => {
            (checkout_key, customer, external_user_ref)
        }
    };

    let subscriber_id = match customer {
        Some(id) => id,
        None => {
            let id = client
                .create_subscriber(&external_user_ref, &format!("mlc-customer-{external_user_ref}"))
                .await?;
            let (recorded_id, reference) = (id.clone(), external_user_ref.clone());
            with_db(state, move |conn| {
                store::record_customer(conn, user_id, &recorded_id, &reference, Utc::now())
            })
            .await?;
            id
        }
    };

    let created = client
        .create_subscription(&subscriber_id, &plan.id, &checkout_key)
        .await
        .map_err(processor_error)?;
    let pay_json = serde_json::to_string(&created.pay).map_err(|e| FlowError::Db(e.to_string()))?;
    let invoice = InvoiceRow {
        invoice_id: created.invoice_id.clone(),
        user_id,
        subscription_id: created.subscription_id.clone(),
        plan_id: plan.id.clone(),
        kind: InvoiceKind::Initial,
        status: INVOICE_NEW.to_string(),
        pay_json,
        expires_at: earliest_expiry(&created.pay),
        flags: Vec::new(),
        grant_kind: None,
        grant_state: GrantState::None,
        period_from: None,
        period_to: None,
        detail: serde_json::json!({}),
    };
    with_db(state, move |conn| {
        let tx = conn.unchecked_transaction()?;
        store::complete_checkout(&tx, &checkout_key, &invoice, Utc::now())?;
        tx.commit()
    })
    .await?;

    Ok(CheckoutView { invoice_id: created.invoice_id, plan_id: plan.id, pay: created.pay })
}

/// `POST /api/billing/anon-checkout` result.
pub struct AnonCheckoutView {
    /// The account key, shown once. Never stored in this form.
    pub account_key: String,
    /// dig2pay's invoice id.
    pub invoice_id: String,
    /// Every way to pay it.
    pub pay: Vec<PayOption>,
}

/// Buy an anonymous account: create a PENDING anonymous user holding a fresh
/// key, open the dig2pay subscription under that user's id, and hand back the
/// key with the invoice. If the invoice cannot be opened the pending account
/// is removed again: the payer holds no key and no address.
pub async fn anon_checkout(state: &Arc<AppState>, plan_id: &str, onion: bool) -> Result<AnonCheckoutView, FlowError> {
    let billing = state.billing().ok_or(FlowError::NotConfigured)?;
    billing.client().ok_or(FlowError::NotConfigured)?;
    let sold_anonymously = billing
        .catalog()
        .get(plan_id)
        .is_some_and(|p| p.grant == Grant::LifetimeAnon && p.offered_to(onion));
    if !sold_anonymously {
        return Err(FlowError::PlanNotAvailable);
    }

    let key = AccountKey::generate();
    let for_db = key.clone();
    let user_id = with_db(state, move |conn| anon::create_pending(conn, &for_db, Utc::now())).await?;
    match checkout_for(state, user_id, plan_id, onion, true).await {
        Ok(view) => Ok(AnonCheckoutView { account_key: key.reveal(), invoice_id: view.invoice_id, pay: view.pay }),
        Err(e) => {
            if let Err(cleanup) = with_db_and_messenger(state, move |conn, messenger, live| anon::discard_unfinished(conn, messenger, live, user_id)).await {
                tracing::warn!("billing: could not discard the unfinished anonymous account {user_id}: {cleanup:?}");
            }
            Err(e)
        }
    }
}

// ============================================================================
// Invoice
// ============================================================================

/// `GET /api/billing/invoice/{id}` result.
pub struct InvoiceView {
    /// The stored invoice.
    pub invoice: InvoiceRow,
    /// The `pay[]` handed out at checkout (empty for renewal invoices MLC
    /// never handed out).
    pub pay: Vec<PayOption>,
    /// The processor's live status line, when it could be read.
    pub live_status: Option<String>,
}

/// One invoice of `user_id`. Another account's invoice is `NotFound`, exactly
/// like an unknown id. The live status is best effort: if the processor is
/// unreachable the stored view is returned without it.
pub async fn invoice(state: &Arc<AppState>, user_id: i64, invoice_id: &str) -> Result<InvoiceView, FlowError> {
    let billing = state.billing().ok_or(FlowError::NotConfigured)?;
    let id = invoice_id.to_string();
    let mut invoice = with_db(state, move |conn| store::invoice_for_user(conn, user_id, &id))
        .await?
        .ok_or(FlowError::NotFound)?;

    let mut live_status = None;
    if let Some(client) = billing.client() {
        match client.get_invoice(&invoice.invoice_id).await {
            Ok(live) => {
                if let Some(processor_kind) = live.kind.as_deref() {
                    invoice = adopt_processor_kind(state, invoice, processor_kind).await?;
                }
                let settled_again = matches!(live.status.as_str(), "settled" | "complete");
                if invoice.grant_state == GrantState::Reverted && settled_again {
                    let (b, id) = (billing.clone(), invoice.invoice_id.clone());
                    let restored = with_db(state, move |conn| {
                        webhook::restore_reverted(conn, b.catalog(), user_id, &id, Utc::now())
                    })
                    .await?;
                    if restored {
                        let id = invoice.invoice_id.clone();
                        if let Some(fresh) =
                            with_db(state, move |conn| store::invoice_for_user(conn, user_id, &id)).await?
                        {
                            invoice = fresh;
                        }
                    }
                }
                live_status = Some(live.status);
            }
            Err(e) => tracing::warn!("billing: live status of invoice {} unavailable: {e}", invoice.invoice_id),
        }
    }
    Ok(InvoiceView { pay: pay_of(&invoice), invoice, live_status })
}

/// The invoice kind the processor reports (`"subscription"` or
/// `"proration"`) mapped onto ours, when it differs from what MLC inferred
/// (MLC learns of a renewal or proration invoice from its webhook and can
/// only guess which it is). Corrected only while the invoice has granted
/// nothing; an already-granted invoice that disagrees is logged instead.
async fn adopt_processor_kind(
    state: &Arc<AppState>,
    mut invoice: InvoiceRow,
    processor_kind: &str,
) -> Result<InvoiceRow, FlowError> {
    let processor_kind = processor_kind.to_string();
    let (invoice_id, subscription_id) = (invoice.invoice_id.clone(), invoice.subscription_id.clone());
    let (stored_kind, grant_state) = (invoice.kind, invoice.grant_state);
    let corrected = with_db(state, move |conn| {
        let wanted = match processor_kind.as_str() {
            "proration" => Some(InvoiceKind::Proration),
            // A subscription invoice is the first one or a renewal.
            "subscription" if stored_kind == InvoiceKind::Proration => {
                let has_initial = store::invoices_for_subscription(conn, &subscription_id)?
                    .iter()
                    .any(|i| i.kind == InvoiceKind::Initial && i.invoice_id != invoice_id);
                Some(if has_initial { InvoiceKind::Renewal } else { InvoiceKind::Initial })
            }
            _ => None,
        };
        match wanted {
            Some(kind) if kind != stored_kind && grant_state == GrantState::None => {
                store::set_invoice_kind(conn, &invoice_id, kind, Utc::now())?;
                Ok(Some(kind))
            }
            Some(kind) if kind != stored_kind => {
                tracing::warn!(
                    "billing: invoice {invoice_id} is {} at the processor but was recorded as {} and has already granted",
                    kind.as_str(),
                    stored_kind.as_str()
                );
                Ok(None)
            }
            _ => Ok(None),
        }
    })
    .await?;
    if let Some(kind) = corrected {
        invoice.kind = kind;
    }
    Ok(invoice)
}

// ============================================================================
// Me
// ============================================================================

/// `GET /api/billing/me` result.
pub struct MeView {
    /// The four-legged paid picture.
    pub entitlement: EntitlementView,
    /// Credit balance, USD micro-units.
    pub credit_micros: i64,
    /// Configured quota of the account's quant tier.
    pub quant_quota: Option<u64>,
    /// The subscription that matters right now, if any.
    pub subscription: Option<SubscriptionRow>,
    /// Invoices still waiting for payment.
    pub unpaid: Vec<InvoiceRow>,
}

/// Rank the subscriptions worth showing: a running one first, then a settled
/// one-time purchase, then a cancelled one. A subscription still waiting for
/// its first payment is not shown here — its invoice is in `unpaid`, and an
/// abandoned checkout must not outrank what the account actually bought.
fn display_rank(state: store::SubState) -> Option<u8> {
    use store::SubState::{Active, Cancelled, Creating, Open, Paid, PastDue};
    match state {
        Active | PastDue => Some(0),
        Paid => Some(1),
        Cancelled => Some(2),
        Open | Creating => None,
    }
}

/// The account's billing picture.
pub async fn me(state: &Arc<AppState>, user_id: i64) -> Result<MeView, FlowError> {
    let billing = state.billing().ok_or(FlowError::NotConfigured)?;
    let (entitlement, credit_micros, subscriptions, unpaid) = with_db(state, move |conn| {
        Ok((
            entitle::entitlement_view(conn, user_id, Utc::now())?,
            entitle::credit_balance(conn, user_id)?,
            store::subscriptions_for_user(conn, user_id)?,
            store::unpaid_invoices_for_user(conn, user_id)?,
        ))
    })
    .await?;
    let quant_quota = entitlement
        .quant_tier
        .as_deref()
        .and_then(|tier| billing.catalog().get(tier))
        .and_then(|plan| plan.quota);
    // `subscriptions` arrives newest first, and `min_by_key` keeps the first
    // of equal ranks, so ties resolve to the newest.
    let subscription = subscriptions
        .into_iter()
        .filter(|s| s.subscription_id.is_some())
        .filter_map(|s| display_rank(s.state).map(|rank| (rank, s)))
        .min_by_key(|(rank, _)| *rank)
        .map(|(_, s)| s);
    Ok(MeView { entitlement, credit_micros, quant_quota, subscription, unpaid })
}

// ============================================================================
// Change
// ============================================================================

/// `POST /api/billing/change` result.
pub struct ChangeView {
    /// dig2pay's change id (stable across this answer and the webhook).
    pub change_id: String,
    /// `pending | applied | cancelled`.
    pub state: String,
    /// The plan before the change.
    pub from_plan_id: String,
    /// The plan being moved to.
    pub to_plan_id: String,
    /// `charge_now` (upgrade) or `none` (downgrade at renewal).
    pub proration: &'static str,
    /// USD micros charged now, when dig2pay computed one.
    pub charge_usd_micros: Option<String>,
    /// When a deferred change takes effect.
    pub pending_effective_at: Option<String>,
    /// The proration invoice, when dig2pay names it.
    pub invoice_id: Option<String>,
    /// Ways to pay the proration invoice.
    pub pay: Vec<PayOption>,
}

fn charge_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Move the account's running quant subscription to `plan_id`: an upgrade is
/// charged now (prorated), a downgrade takes effect at the next renewal.
pub async fn change(state: &Arc<AppState>, user_id: i64, plan_id: &str) -> Result<ChangeView, FlowError> {
    let billing = state.billing().ok_or(FlowError::NotConfigured)?;
    let client = billing.client().ok_or(FlowError::NotConfigured)?;
    let target = billing
        .catalog()
        .get(plan_id)
        .filter(|p| p.grant == Grant::Quant)
        .cloned()
        .ok_or(FlowError::PlanNotAvailable)?;

    let sub = {
        let billing = billing.clone();
        with_db(state, move |conn| store::live_quant_subscription(conn, billing.catalog(), user_id)).await?
    }
    .ok_or(FlowError::NoSubscription)?;
    let subscription_id = sub.subscription_id.clone().ok_or(FlowError::NoSubscription)?;
    let current = billing.catalog().get(&sub.plan_id).ok_or(FlowError::NoSubscription)?;
    if current.id == target.id {
        return Err(FlowError::SamePlan);
    }
    if sub.pending_change_id.is_some() {
        return Err(FlowError::ChangePending);
    }
    let upgrade = target.tier_rank > current.tier_rank;
    let proration = if upgrade { Proration::ChargeNow } else { Proration::None };
    let from_plan_id = current.id.clone();
    // The sequence number is part of the key and only advances once a
    // request's outcome is stored, so a retry after a timeout replays it.
    let idempotency_key = format!("mlc-chg-{subscription_id}-{}", sub.change_seq);

    let answer = client
        .change_subscription(&subscription_id, &target.id, proration, &idempotency_key)
        .await
        .map_err(processor_error)?;

    let stored = answer.clone();
    let (target_id, checkout_key) = (target.id.clone(), sub.checkout_key.clone());
    let billing_for_db = billing.clone();
    with_db(state, move |conn| {
        let tx = conn.unchecked_transaction()?;
        if let Some(mut sub) = store::subscriptions_for_user(&tx, user_id)?
            .into_iter()
            .find(|s| s.checkout_key == checkout_key)
        {
            sub.change_seq += 1;
            match stored.state.as_str() {
                "applied" => {
                    webhook::apply_plan_change(&tx, billing_for_db.catalog(), &mut sub, &stored.change_id, &target_id, Utc::now())?;
                }
                "cancelled" => store::save_subscription(&tx, &sub, Utc::now())?,
                _ => {
                    sub.pending_change_id = Some(stored.change_id.clone());
                    sub.pending_plan_id = Some(target_id.clone());
                    store::save_subscription(&tx, &sub, Utc::now())?;
                }
            }
            if let (Some(invoice_id), false) = (stored.invoice_id.clone(), stored.pay.is_empty()) {
                store::insert_invoice(
                    &tx,
                    &InvoiceRow {
                        invoice_id,
                        user_id,
                        subscription_id: subscription_id.clone(),
                        plan_id: target_id.clone(),
                        kind: InvoiceKind::Proration,
                        status: INVOICE_NEW.to_string(),
                        pay_json: serde_json::to_string(&stored.pay).unwrap_or_else(|_| "[]".to_string()),
                        expires_at: earliest_expiry(&stored.pay),
                        flags: Vec::new(),
                        grant_kind: None,
                        grant_state: GrantState::None,
                        period_from: None,
                        period_to: None,
                        detail: serde_json::json!({}),
                    },
                    Utc::now(),
                )?;
            }
        }
        tx.commit()
    })
    .await?;

    Ok(ChangeView {
        change_id: answer.change_id,
        state: answer.state,
        from_plan_id,
        to_plan_id: target.id,
        proration: proration.as_str(),
        charge_usd_micros: answer.computed_charge_usd_micros.as_ref().and_then(charge_text),
        pending_effective_at: answer.pending_effective_at,
        invoice_id: answer.invoice_id,
        pay: answer.pay,
    })
}

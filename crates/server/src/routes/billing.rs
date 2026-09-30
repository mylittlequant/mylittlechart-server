//! `/api/billing/*` — the dig2pay billing adapter.
//!
//! One public route, open to signed-out visitors (an anonymous account is
//! bought by someone with no session yet; the general per-IP read limiter in
//! front of `/api` covers it like every other public GET):
//!
//! | Route | Purpose |
//! |---|---|
//! | `GET /api/billing/plans` | the plans offered to THIS request (Tor variants only on the onion vhost); no per-user state |
//!
//! Signed-in routes (session cookie or bearer, like `/api/account/*`):
//!
//! | Route | Purpose |
//! |---|---|
//! | `GET /api/billing/me` | the account's paid picture, credit, subscription, open invoices |
//! | `POST /api/billing/checkout {plan_id}` | start (or resume) a purchase → `{invoice_id, plan_id, pay:[…]}` |
//! | `GET /api/billing/invoice/{id}` | one of the caller's own invoices, with the processor's live status |
//! | `POST /api/billing/change {plan_id}` | move a running quant subscription (upgrade charged now, downgrade at renewal) |
//!
//! And the processor's callback, authenticated by signature instead of a
//! session: `POST /api/billing/webhook` (see `billing::webhook`).
//!
//! The browser never talks to dig2pay; only this server does, over a
//! dedicated tunnel, with the merchant key (see `billing::client`).

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::billing::client::GatewayError;
use crate::billing::flow::{self, ChangeView, FlowError, InvoiceView, MeView};
use crate::billing::plans::{Audience, Grant, Plan};
use crate::billing::signature;
use crate::billing::store::Refusal;
use crate::billing::webhook::{self, ProcessError};
use crate::models::types::ErrorResponse;
use crate::routes::account::resolve_user_id;
use crate::state::AppState;

/// Webhook bodies are small JSON documents; anything larger is refused
/// before it is read (the route layers this limit on itself in
/// `routes::control_api_router`).
pub const WEBHOOK_MAX_BODY_BYTES: usize = 256 * 1024;

pub(crate) fn error(status: StatusCode, code: &str) -> Response {
    (status, Json(ErrorResponse::new(code))).into_response()
}

/// The signed-in caller's user id, or the response to send instead.
pub(crate) async fn signed_in(state: &Arc<AppState>, headers: &HeaderMap) -> Result<i64, Response> {
    match resolve_user_id(state.clone(), headers).await {
        Ok(id) => Ok(id),
        Err(StatusCode::UNAUTHORIZED) => Err(error(StatusCode::UNAUTHORIZED, "Authentication required")),
        Err(_) => Err(error(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")),
    }
}

/// Map a failed operation to its response. The wire `error` is a stable
/// snake_case code; dig2pay's own message rides in `detail` for a refusal.
pub(crate) fn flow_error(e: FlowError) -> Response {
    match e {
        FlowError::NotConfigured => error(StatusCode::SERVICE_UNAVAILABLE, "billing_not_configured"),
        FlowError::PlanNotAvailable => error(StatusCode::BAD_REQUEST, "plan_not_available"),
        // An anonymous account is bought by someone with no account yet.
        FlowError::AnonymousOnly => error(StatusCode::BAD_REQUEST, "anonymous_only"),
        // The catalog lists it, the processor does not have it yet: a clean,
        // retryable refusal (nothing was created).
        FlowError::PlanUnavailable => {
            tracing::warn!("billing: the processor does not know the requested plan");
            error(StatusCode::SERVICE_UNAVAILABLE, "plan_unavailable")
        }
        FlowError::Refused(Refusal::AlreadyOwned) => error(StatusCode::CONFLICT, "already_owned"),
        FlowError::Refused(Refusal::SubscriptionExists) => error(StatusCode::CONFLICT, "subscription_exists"),
        FlowError::NoSubscription => error(StatusCode::CONFLICT, "no_active_subscription"),
        FlowError::SamePlan => error(StatusCode::BAD_REQUEST, "same_plan"),
        FlowError::ChangePending => error(StatusCode::CONFLICT, "change_pending"),
        FlowError::NotFound => error(StatusCode::NOT_FOUND, "not_found"),
        // dig2pay refused the request itself (a change it will not make, a
        // change already pending): the caller's business, so say why.
        FlowError::Gateway(GatewayError::Refused { status: status @ (400 | 409 | 422), message }) => {
            let code = if status == 409 { StatusCode::CONFLICT } else { StatusCode::BAD_REQUEST };
            (code, Json(json!({ "error": "gateway_refused", "detail": message }))).into_response()
        }
        // Anything else from dig2pay (a rejected merchant key, an unknown
        // plan, rate limiting, a server error) is MLC's problem, not the
        // caller's: log it, answer generically.
        FlowError::Gateway(GatewayError::Refused { status, message }) => {
            tracing::error!("billing: dig2pay answered {status}: {message}");
            error(StatusCode::BAD_GATEWAY, "payment_gateway_unavailable")
        }
        FlowError::Gateway(other) => {
            tracing::warn!("billing: {other}");
            error(StatusCode::BAD_GATEWAY, "payment_gateway_unavailable")
        }
        FlowError::Db(e) => {
            tracing::error!("billing: database error: {e}");
            error(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
        }
    }
}

fn plan_json(plan: &Plan) -> Value {
    json!({
        "id": plan.id,
        "kind": match plan.grant {
            Grant::LifetimePaid => "paid_account",
            Grant::LifetimeAnon => "anon_account",
            Grant::Quant => "quant",
        },
        "interval": plan.interval.as_str(),
        "price_usd": plan.price_usd,
        "tier": plan.tier_rank,
        "quota": plan.quota,
        "onion_only": plan.audience == Audience::Onion,
    })
}

/// `GET /api/billing/plans` — public: no session is needed and none is read.
/// The answer holds no per-user state (the catalog depends only on the Host
/// the request came in on), so a signed-in caller gets exactly what a
/// signed-out one does.
///
/// ```json
/// { "onion": false, "checkout_enabled": true,
///   "plans": [ { "id": "mlc-paid-account-v1", "kind": "paid_account",
///                "interval": "one_time", "price_usd": 5, "tier": null,
///                "quota": null, "onion_only": false }, … ] }
/// ```
/// `kind` is `paid_account | anon_account | quant`. The two Tor account
/// variants (`onion_only: true`) appear only when the request came through
/// the onion vhost; there the clearnet account plans are not offered. `quota`
/// is the operator-configured quant quota of a tier (`null` when unset).
/// An `anon_account` plan is not bought here: it is sold, to someone with no
/// account yet, by the public `POST /api/billing/anon-checkout`
/// (`routes/anon_account.rs`); this signed-in checkout answers
/// `400 anonymous_only` for it.
pub async fn plans(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(billing) = state.billing() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "billing_not_configured");
    };
    let onion = billing.is_onion_request(&headers);
    let offered: Vec<Value> = billing.catalog().offered(onion).map(plan_json).collect();
    Json(json!({
        "onion": onion,
        "checkout_enabled": billing.client().is_some(),
        "plans": offered,
    }))
    .into_response()
}

fn me_json(view: MeView) -> Value {
    let e = &view.entitlement;
    let subscription = view.subscription.as_ref().map(|s| {
        json!({
            "subscription_id": s.subscription_id,
            "plan_id": s.plan_id,
            "state": s.state.as_str(),
            "active_until": s.active_until,
            "pending_change": s.pending_change_id.as_ref().map(|change_id| json!({
                "change_id": change_id,
                "plan_id": s.pending_plan_id,
            })),
        })
    });
    let open_invoices: Vec<Value> = view
        .unpaid
        .iter()
        .map(|i| {
            json!({
                "invoice_id": i.invoice_id,
                "plan_id": i.plan_id,
                "kind": i.kind.as_str(),
                "expires_at": i.expires_at,
            })
        })
        .collect();
    json!({
        "paid": e.paid,
        "paid_until": e.paid_until,
        "lifetime_paid": e.lifetime_paid,
        "lifetime_anon": e.lifetime_anon,
        "quant": {
            "tier": e.quant_tier,
            "active": e.quant_active,
            "active_until": e.quant_active_until,
            "quota": view.quant_quota,
        },
        "credit_usd_micros": view.credit_micros,
        "subscription": subscription,
        "open_invoices": open_invoices,
    })
}

/// `GET /api/billing/me`
///
/// ```json
/// { "paid": true, "paid_until": null,
///   "lifetime_paid": false, "lifetime_anon": true,
///   "quant": { "tier": "mlc-monthly-50-v1", "active": true,
///              "active_until": "2026-10-25T…+00:00", "quota": 300 },
///   "credit_usd_micros": 0,
///   "subscription": { "subscription_id": "…", "plan_id": "…", "state": "active",
///                     "active_until": "…", "pending_change": null },
///   "open_invoices": [ { "invoice_id": "…", "plan_id": "…", "kind": "initial",
///                        "expires_at": "…" } ] }
/// ```
/// `paid` is true if any of: a future `paid_until` (the legacy column), a
/// lifetime flag, or a running quant period.
pub async fn me(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user_id = match signed_in(&state, &headers).await {
        Ok(id) => id,
        Err(response) => return response,
    };
    match flow::me(&state, user_id).await {
        Ok(view) => Json(me_json(view)).into_response(),
        Err(e) => flow_error(e),
    }
}

/// Request body of `POST /api/billing/checkout`.
#[derive(Deserialize)]
pub struct CheckoutBody {
    /// The plan to buy.
    pub plan_id: String,
}

/// `POST /api/billing/checkout {plan_id}`
///
/// ```json
/// { "invoice_id": "grp_…", "plan_id": "mlc-monthly-20-v1",
///   "pay": [ { "chain": "evm:1", "asset": "USDC", "address": "0x…",
///              "amount": "20.000000", "expires_at": "…", "qr_svg": "<svg…>" }, … ] }
/// ```
/// Every option the processor enabled rides one invoice (`pay[]` is passed
/// through as issued, never filtered or assumed); the payer picks. Repeating
/// the call while the invoice is unpaid and unexpired returns the same
/// invoice. Errors: `400 plan_not_available`, `409 already_owned` (a paid
/// account is already held, directly or through an anonymous purchase; an
/// anonymous purchase never collides; nothing is created on the processor),
/// `409 subscription_exists`, `503 plan_unavailable` (the processor does not
/// have the plan yet), `503 billing_not_configured`,
/// `502 payment_gateway_unavailable`.
pub async fn checkout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CheckoutBody>,
) -> Response {
    let user_id = match signed_in(&state, &headers).await {
        Ok(id) => id,
        Err(response) => return response,
    };
    let Some(billing) = state.billing() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "billing_not_configured");
    };
    let onion = billing.is_onion_request(&headers);
    match flow::checkout(&state, user_id, body.plan_id.trim(), onion).await {
        Ok(view) => Json(json!({
            "invoice_id": view.invoice_id,
            "plan_id": view.plan_id,
            "pay": view.pay,
        }))
        .into_response(),
        Err(e) => flow_error(e),
    }
}

pub(crate) fn invoice_json(view: InvoiceView) -> Value {
    let i = &view.invoice;
    let period = match (&i.period_from, &i.period_to) {
        (Some(from), Some(to)) => json!({ "from": from, "to": to }),
        _ => Value::Null,
    };
    json!({
        "invoice_id": i.invoice_id,
        "plan_id": i.plan_id,
        "kind": i.kind.as_str(),
        "status": i.status,
        "live_status": view.live_status,
        "grant_state": i.grant_state.as_str(),
        "flags": i.flags,
        "detail": i.detail,
        "period": period,
        "expires_at": i.expires_at,
        "pay": view.pay,
    })
}

/// `GET /api/billing/invoice/{id}` — owner-scoped: another account's invoice
/// and an unknown id both answer `404 not_found`.
///
/// ```json
/// { "invoice_id": "grp_…", "plan_id": "…", "kind": "initial",
///   "status": "new", "live_status": "processing", "grant_state": "none",
///   "flags": ["partial"], "detail": { "partial": { "received": "2.0", "shortfall": "3.0", … } },
///   "period": null, "expires_at": "…", "pay": [ … ] }
/// ```
/// `live_status` is the processor's own status line (`null` if it could not
/// be read); `status` and `grant_state` are MLC's record. A partial payment
/// shows under `detail.partial` — the rest is to be paid to the same address.
pub async fn invoice(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let user_id = match signed_in(&state, &headers).await {
        Ok(id) => id,
        Err(response) => return response,
    };
    match flow::invoice(&state, user_id, &id).await {
        Ok(view) => Json(invoice_json(view)).into_response(),
        Err(e) => flow_error(e),
    }
}

/// Request body of `POST /api/billing/change`.
#[derive(Deserialize)]
pub struct ChangeBody {
    /// The quant plan to move to.
    pub plan_id: String,
}

fn change_json(view: ChangeView) -> Value {
    json!({
        "change_id": view.change_id,
        "state": view.state,
        "from_plan_id": view.from_plan_id,
        "to_plan_id": view.to_plan_id,
        "proration": view.proration,
        "charge_usd_micros": view.charge_usd_micros,
        "pending_effective_at": view.pending_effective_at,
        "invoice_id": view.invoice_id,
        "pay": view.pay,
    })
}

/// `POST /api/billing/change {plan_id}`
///
/// ```json
/// { "change_id": "chg_…", "state": "pending", "from_plan_id": "…",
///   "to_plan_id": "…", "proration": "charge_now",
///   "charge_usd_micros": "12000000", "pending_effective_at": null,
///   "invoice_id": null, "pay": [ … ] }
/// ```
/// An upgrade (`proration: charge_now`) returns the prorated charge and its
/// `pay[]`; the new tier is granted only when the `subscription_changed`
/// webhook (or a synchronous `state: applied`) says so. A downgrade
/// (`proration: none`, `pending_effective_at` set) takes effect at renewal
/// with no refund. Errors: `409 no_active_subscription`, `400 same_plan`,
/// `409 change_pending`, `400 plan_not_available`, `400|409 gateway_refused`.
pub async fn change(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ChangeBody>,
) -> Response {
    let user_id = match signed_in(&state, &headers).await {
        Ok(id) => id,
        Err(response) => return response,
    };
    match flow::change(&state, user_id, body.plan_id.trim()).await {
        Ok(view) => Json(change_json(view)).into_response(),
        Err(e) => flow_error(e),
    }
}

/// `POST /api/billing/webhook` — dig2pay's signed callback.
///
/// Authenticated by `X-Dig2pay-Signature` (`t=…,v1=…`, HMAC-SHA256 over
/// `"{t}.{raw body}"`, any secret of the rotation set, 5-minute window), not
/// by a session. Answers `200 {"ok":true,"outcome":…}` for everything that
/// was verified and stored — including a duplicate, an unmatched event and a
/// kind this version does not know — so the processor never retries those.
/// `401` for a bad or missing signature, `503` when no secret is loaded,
/// `400` for a signed body that is not the documented JSON, `500` when the
/// database failed (the processor retries).
pub async fn webhook(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(billing) = state.billing() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "billing_not_configured");
    };
    if billing.webhook_secrets().is_empty() {
        return error(StatusCode::SERVICE_UNAVAILABLE, "webhook_not_configured");
    }
    let signature_header = headers
        .get("x-dig2pay-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if let Err(reason) = signature::verify(
        billing.webhook_secrets(),
        signature_header,
        &body,
        chrono::Utc::now().timestamp(),
    ) {
        tracing::warn!("billing webhook refused: {reason:?}");
        return error(StatusCode::UNAUTHORIZED, "invalid signature");
    }
    let Ok(text) = std::str::from_utf8(&body) else {
        return error(StatusCode::BAD_REQUEST, "body is not UTF-8");
    };
    let text = text.to_string();
    let header_event_id = headers
        .get("x-dig2pay-event-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let db_state = state.clone();
    let db_billing = billing.clone();
    let result = tokio::task::spawn_blocking(move || {
        let conn = db_state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        webhook::process(&conn, db_billing.catalog(), header_event_id.as_deref(), &text, chrono::Utc::now())
    })
    .await;
    match result {
        Ok(Ok(outcome)) => {
            tracing::info!("billing webhook processed: {}", outcome.as_str());
            Json(json!({ "ok": true, "outcome": outcome.as_str() })).into_response()
        }
        Ok(Err(ProcessError::BadBody(why))) => error(StatusCode::BAD_REQUEST, why),
        Ok(Err(ProcessError::Db(e))) => {
            tracing::error!("billing webhook: database error: {e}");
            error(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
        }
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::billing::client::Dig2payClient;
    use crate::billing::config::{BillingRuntime, BillingSettings};
    use crate::billing::plans::{DEFAULT_ANON_TOR_ID, DEFAULT_PAID_TOR_ID};
    use crate::billing::signature::sign_for_test;
    use crate::billing::store;
    use crate::routes::control_api_router;
    use axum::body::{to_bytes, Body};
    use axum::http::{Method, Request};
    use axum::routing::{get, post};
    use axum::Router;
    use chrono::{Duration, Utc};
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;
    use tower::ServiceExt;

    pub(crate) const MERCHANT_KEY: &str = "test-merchant-key";
    pub(crate) const WEBHOOK_SECRET: &str = "whsec_test_secret";
    pub(crate) const ONION_HOST: &str = "mlcexample.onion";

    // ------------------------------------------------- in-process merchant

    /// One request the mock merchant saw.
    #[derive(Debug, Clone)]
    pub(crate) struct Call {
        pub(crate) path: String,
        pub(crate) authorised: bool,
        pub(crate) idempotency_key: Option<String>,
        pub(crate) body: Value,
    }

    #[derive(Default)]
    pub(crate) struct MockMerchant {
        pub(crate) calls: Vec<Call>,
        /// `Idempotency-Key` → the answer already given to it.
        pub(crate) answers: HashMap<String, Value>,
        pub(crate) created: u32,
        pub(crate) fail_next_subscription: bool,
        /// Plans the processor does not have (yet): `POST /subscriptions` answers 404.
        pub(crate) unknown_plans: HashSet<String>,
        pub(crate) invoice_status: String,
        pub(crate) change_answer: Option<Value>,
    }

    pub(crate) type Shared = Arc<Mutex<MockMerchant>>;

    pub(crate) fn pay_options(amount: &str) -> Value {
        json!([
            { "chain": "evm:1", "asset": "USDC", "address": "0x00000000000000000000000000000000000000aa",
              "amount": amount, "expires_at": (Utc::now() + Duration::hours(1)).to_rfc3339(),
              "qr_svg": "<svg viewBox=\"0 0 1 1\"><rect width=\"1\" height=\"1\"/></svg>" },
            { "chain": "tron", "asset": "USDT", "address": "TMockAddress000000000000000000000000",
              "amount": amount, "expires_at": (Utc::now() + Duration::hours(1)).to_rfc3339(),
              "qr_svg": "<svg><script>alert(1)</script></svg>" },
        ])
    }

    fn record(shared: &Shared, path: &str, headers: &HeaderMap, body: Value) -> bool {
        let authorised = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == format!("Bearer {MERCHANT_KEY}"));
        let idempotency_key = headers.get("idempotency-key").and_then(|v| v.to_str().ok()).map(str::to_string);
        shared.lock().expect("mock lock").calls.push(Call {
            path: path.to_string(),
            authorised,
            idempotency_key,
            body,
        });
        authorised
    }

    async fn mock_subscribers(State(shared): State<Shared>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
        if !record(&shared, "/subscribers", &headers, body.clone()) {
            return error(StatusCode::UNAUTHORIZED, "unauthorized");
        }
        let reference = body["external_user_ref"].as_str().unwrap_or_default();
        (StatusCode::CREATED, Json(json!({ "subscriber_id": format!("cus_{reference}") }))).into_response()
    }

    async fn mock_subscriptions(State(shared): State<Shared>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
        if !record(&shared, "/subscriptions", &headers, body.clone()) {
            return error(StatusCode::UNAUTHORIZED, "unauthorized");
        }
        let mut mock = shared.lock().expect("mock lock");
        if body["plan_id"].as_str().is_some_and(|plan| mock.unknown_plans.contains(plan)) {
            return error(StatusCode::NOT_FOUND, "not found");
        }
        if mock.fail_next_subscription {
            mock.fail_next_subscription = false;
            return error(StatusCode::INTERNAL_SERVER_ERROR, "boom");
        }
        let key = headers
            .get("idempotency-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        if let Some(previous) = mock.answers.get(&key) {
            return (StatusCode::CREATED, Json(previous.clone())).into_response();
        }
        mock.created += 1;
        let n = mock.created;
        let answer = json!({
            "subscription_id": format!("sub_{n}"),
            "invoice_id": format!("grp_{n}"),
            "pay": pay_options("5.000000"),
        });
        mock.answers.insert(key, answer.clone());
        (StatusCode::CREATED, Json(answer)).into_response()
    }

    async fn mock_invoice(
        State(shared): State<Shared>,
        headers: HeaderMap,
        Path(id): Path<String>,
    ) -> Response {
        if !record(&shared, &format!("/invoices/{id}"), &headers, Value::Null) {
            return error(StatusCode::UNAUTHORIZED, "unauthorized");
        }
        let status = shared.lock().expect("mock lock").invoice_status.clone();
        Json(json!({ "invoice_id": id, "status": status, "flags": [] })).into_response()
    }

    async fn mock_change(
        State(shared): State<Shared>,
        headers: HeaderMap,
        Path(id): Path<String>,
        Json(body): Json<Value>,
    ) -> Response {
        if !record(&shared, &format!("/subscriptions/{id}/change"), &headers, body.clone()) {
            return error(StatusCode::UNAUTHORIZED, "unauthorized");
        }
        let answer = shared.lock().expect("mock lock").change_answer.clone();
        match answer {
            Some(answer) => (StatusCode::OK, Json(answer)).into_response(),
            None => error(StatusCode::BAD_REQUEST, "no scripted change answer"),
        }
    }

    pub(crate) async fn spawn_merchant() -> (String, Shared) {
        let shared: Shared = Arc::new(Mutex::new(MockMerchant {
            invoice_status: "new".to_string(),
            ..MockMerchant::default()
        }));
        let app = Router::new()
            .route("/subscribers", post(mock_subscribers))
            .route("/subscriptions", post(mock_subscriptions))
            .route("/invoices/{id}", get(mock_invoice))
            .route("/subscriptions/{id}/change", post(mock_change))
            .with_state(shared.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind mock merchant");
        let addr = listener.local_addr().expect("mock merchant address");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}"), shared)
    }

    // ------------------------------------------------------ app under test

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "mlc-billing-route-test-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    pub(crate) fn control_plane() -> crate::state::ControlPlane {
        let key = "0".repeat(64);
        let dir = temp_dir("cp");
        crate::state::ControlPlane {
            db: Mutex::new(crate::db::init_db(":memory:", &key).expect("identity db")),
            social: Mutex::new(crate::social_db::init_social_db(":memory:", &key).expect("social db")),
            messenger: Mutex::new(
                mylittlechart_server::matrix_store::init_messenger_db(":memory:", &key).expect("messenger db"),
            ),
            ops_db: Mutex::new(crate::db::init_ops_db(":memory:").expect("ops db")),
            ops_writer: crate::opswriter::OpsWriter::spawn(
                rusqlite::Connection::open_in_memory().expect("ops writer db"),
                crate::opswriter::OPS_WRITER_QUEUE_CAPACITY,
            ),
            sync_store: crate::syncstore::SyncStore::new(dir.join("sync")),
            share_root: dir.join("share"),
            data_dir: dir,
            reserved_nick_cache: std::sync::RwLock::new(Vec::new()),
            live: mylittlechart_server::live::LiveRegistry::new(),
            typing: mylittlechart_server::live::TypingRegistry::new(),
            matrix_claim_rate_limiter: mylittlechart_server::live::ClaimRateLimiter::new(),
        }
    }

    pub(crate) fn app_state(billing: Option<BillingRuntime>) -> Arc<AppState> {
        app_state_with_admin(billing, "")
    }

    /// Like [`app_state`], with `ADMIN_SECRET` set so the admin routes answer.
    pub(crate) fn app_state_with_admin(billing: Option<BillingRuntime>, admin_secret: &str) -> Arc<AppState> {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);
        let state = AppState::new(
            Some(control_plane()),
            admin_secret.to_string(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            shutdown_tx,
            Vec::new(),
            false,
            0,
            0,
            None,
        );
        Arc::new(match billing {
            Some(billing) => state.with_billing(billing),
            None => state,
        })
    }

    pub(crate) fn runtime(base_url: Option<&str>) -> BillingRuntime {
        runtime_with(base_url, &[])
    }

    /// Like [`runtime`], with extra environment settings (e.g. a smaller abuse budget).
    pub(crate) fn runtime_with(base_url: Option<&str>, extra: &[(&str, &str)]) -> BillingRuntime {
        let settings = BillingSettings::from_lookup(|name| {
            if let Some((_, value)) = extra.iter().find(|(k, _)| *k == name) {
                return Some((*value).to_string());
            }
            match name {
                "MLC_BILLING_ONION_HOSTS" => Some(ONION_HOST.to_string()),
                "MLC_BILLING_QUANT_QUOTAS" => Some("mlc-monthly-50-v1=300,mlc-monthly-20-v1=100".to_string()),
                _ => None,
            }
        });
        let client = base_url.map(|url| {
            Dig2payClient::new(url, MERCHANT_KEY, std::time::Duration::from_secs(5)).expect("client")
        });
        BillingRuntime::new(&settings, client, vec![WEBHOOK_SECRET.as_bytes().to_vec()])
    }

    pub(crate) fn sign_in(state: &Arc<AppState>, name: &str) -> (i64, String) {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let uid = crate::db::upsert_user(&conn, "github", name, name, None, &Utc::now().to_rfc3339())
            .expect("seed user");
        let token = format!("token-{name}");
        crate::db::insert_auth_token(&conn, &crate::auth::hash_token(&token), uid, &Utc::now().to_rfc3339())
            .expect("token");
        (uid, token)
    }

    /// The client address every request carries unless a test says otherwise.
    pub(crate) const DEFAULT_CLIENT_IP: [u8; 4] = [198, 51, 100, 7];

    pub(crate) async fn send(
        router: &Router,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
        body: Option<String>,
    ) -> (StatusCode, Value) {
        let (status, _, json) = send_from(router, DEFAULT_CLIENT_IP, method, uri, headers, body).await;
        (status, json)
    }

    /// Like [`send`], from client address `ip`, also returning the response headers.
    pub(crate) async fn send_from(
        router: &Router,
        ip: [u8; 4],
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
        body: Option<String>,
    ) -> (StatusCode, axum::http::HeaderMap, Value) {
        let mut request = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let mut request = request
            .body(body.map_or_else(Body::empty, Body::from))
            .expect("build request");
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((ip, 40_000))));
        let response = router.clone().oneshot(request).await.expect("router is infallible");
        let status = response.status();
        let response_headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.expect("read body");
        (status, response_headers, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    pub(crate) fn auth(token: &str) -> String {
        format!("Bearer {token}")
    }

    pub(crate) async fn get_json(router: &Router, token: &str, uri: &str, host: Option<&str>) -> (StatusCode, Value) {
        let authorization = auth(token);
        let mut headers = vec![("authorization", authorization.as_str())];
        if let Some(host) = host {
            headers.push(("host", host));
        }
        send(router, Method::GET, uri, &headers, None).await
    }

    pub(crate) async fn post_json(router: &Router, token: &str, uri: &str, body: Value, host: Option<&str>) -> (StatusCode, Value) {
        let authorization = auth(token);
        let mut headers = vec![("authorization", authorization.as_str()), ("content-type", "application/json")];
        if let Some(host) = host {
            headers.push(("host", host));
        }
        send(router, Method::POST, uri, &headers, Some(body.to_string())).await
    }

    /// Deliver a webhook signed with `secret` at time `t`.
    pub(crate) async fn deliver(router: &Router, secret: &str, t: i64, body: &Value) -> (StatusCode, Value) {
        let raw = body.to_string();
        let header = sign_for_test(&[secret.as_bytes()], t, raw.as_bytes());
        send(
            router,
            Method::POST,
            "/billing/webhook",
            &[("x-dig2pay-signature", header.as_str()), ("content-type", "application/json")],
            Some(raw),
        )
        .await
    }

    pub(crate) async fn deliver_ok(router: &Router, body: &Value) -> Value {
        let (status, answer) = deliver(router, WEBHOOK_SECRET, Utc::now().timestamp(), body).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        answer
    }

    pub(crate) fn webhook_body(event_id: &str, kind: &str, uid: i64, subscription_id: &str, invoice_id: &str, extra: Value) -> Value {
        let mut body = json!({
            "event_id": event_id,
            "kind": kind,
            "subscriber_id": subscription_id,
            "external_user_ref": uid.to_string(),
            "invoice_id": invoice_id,
            "occurred_at": Utc::now().to_rfc3339(),
        });
        if let (Some(target), Some(extra)) = (body.as_object_mut(), extra.as_object()) {
            for (k, v) in extra {
                target.insert(k.clone(), v.clone());
            }
        }
        body
    }

    pub(crate) fn period_days(days: i64) -> Value {
        let now = Utc::now();
        json!({ "period": { "from": now.to_rfc3339(), "to": (now + Duration::days(days)).to_rfc3339() } })
    }

    fn plan_ids(answer: &Value) -> Vec<String> {
        answer["plans"]
            .as_array()
            .expect("plans array")
            .iter()
            .map(|p| p["id"].as_str().expect("plan id").to_string())
            .collect()
    }

    // ---------------------------------------------------------------- plans

    #[tokio::test]
    async fn plans_are_public_and_carry_no_per_user_state() {
        let state = app_state(Some(runtime(None)));
        let (_, token) = sign_in(&state, "planner-public");
        let router = control_api_router(state);

        // Signed out, clearnet Host: the clearnet catalog.
        let (status, clearnet) =
            send(&router, Method::GET, "/billing/plans", &[("host", "mylittlechart.org")], None).await;
        assert_eq!(status, StatusCode::OK, "{clearnet}");
        assert_eq!(clearnet["onion"], false);
        let ids = plan_ids(&clearnet);
        assert!(ids.contains(&"mlc-paid-account-v1".to_string()));
        assert!(ids.contains(&"mlc-anon-account-v1".to_string()));
        assert!(!ids.contains(&DEFAULT_PAID_TOR_ID.to_string()));
        assert!(!ids.contains(&DEFAULT_ANON_TOR_ID.to_string()));

        // Signed out, onion Host: only the Tor variants of the account plans.
        let (status, onion) = send(&router, Method::GET, "/billing/plans", &[("host", ONION_HOST)], None).await;
        assert_eq!(status, StatusCode::OK, "{onion}");
        assert_eq!(onion["onion"], true);
        let ids = plan_ids(&onion);
        assert!(ids.contains(&DEFAULT_PAID_TOR_ID.to_string()));
        assert!(ids.contains(&DEFAULT_ANON_TOR_ID.to_string()));
        assert!(!ids.contains(&"mlc-paid-account-v1".to_string()));
        assert!(!ids.contains(&"mlc-anon-account-v1".to_string()));

        // The body is the catalog and nothing about a caller.
        for body in [&clearnet, &onion] {
            let mut keys: Vec<&str> = body.as_object().expect("object").keys().map(String::as_str).collect();
            keys.sort_unstable();
            assert_eq!(keys, ["checkout_enabled", "onion", "plans"]);
        }

        // A session changes nothing.
        let (status, signed_in_clearnet) = get_json(&router, &token, "/billing/plans", Some("mylittlechart.org")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(signed_in_clearnet, clearnet);
    }

    #[tokio::test]
    async fn tor_variants_appear_only_on_the_onion_host() {
        let state = app_state(Some(runtime(None)));
        let (_, token) = sign_in(&state, "planner");
        let router = control_api_router(state);

        let (status, clearnet) = get_json(&router, &token, "/billing/plans", Some("mylittlechart.org")).await;
        assert_eq!(status, StatusCode::OK);
        let ids = plan_ids(&clearnet);
        assert_eq!(clearnet["onion"], false);
        assert!(ids.contains(&"mlc-paid-account-v1".to_string()));
        assert!(ids.contains(&"mlc-anon-account-v1".to_string()));
        assert!(!ids.contains(&DEFAULT_PAID_TOR_ID.to_string()));
        assert!(!ids.contains(&DEFAULT_ANON_TOR_ID.to_string()));

        let (status, onion) = get_json(&router, &token, "/billing/plans", Some(ONION_HOST)).await;
        assert_eq!(status, StatusCode::OK);
        let ids = plan_ids(&onion);
        assert_eq!(onion["onion"], true);
        assert!(ids.contains(&DEFAULT_PAID_TOR_ID.to_string()));
        assert!(ids.contains(&DEFAULT_ANON_TOR_ID.to_string()));
        assert!(!ids.contains(&"mlc-paid-account-v1".to_string()), "no surcharge bypass");
        for tier in ["mlc-monthly-20-v1", "mlc-monthly-50-v1", "mlc-monthly-100-v1", "mlc-monthly-200-v1"] {
            assert!(ids.contains(&tier.to_string()), "{tier} on onion");
        }
        let tor = onion["plans"].as_array().expect("plans").iter().find(|p| p["id"] == DEFAULT_ANON_TOR_ID).expect("anon tor");
        assert_eq!((tor["kind"].as_str(), tor["price_usd"].as_u64(), tor["onion_only"].as_bool()), (Some("anon_account"), Some(20), Some(true)));
    }

    #[tokio::test]
    async fn the_quota_shown_is_the_configured_one_and_absent_when_unset() {
        let state = app_state(Some(runtime(None)));
        let (_, token) = sign_in(&state, "quota");
        let router = control_api_router(state);
        let (_, answer) = get_json(&router, &token, "/billing/plans", None).await;
        let quota = |id: &str| {
            answer["plans"].as_array().expect("plans").iter().find(|p| p["id"] == id).expect("plan")["quota"].clone()
        };
        assert_eq!(quota("mlc-monthly-50-v1"), 300);
        assert_eq!(quota("mlc-monthly-20-v1"), 100);
        assert_eq!(quota("mlc-monthly-200-v1"), Value::Null);
        assert_eq!(quota("mlc-paid-account-v1"), Value::Null);
    }

    #[tokio::test]
    async fn without_billing_configured_every_route_answers_503() {
        let state = app_state(None);
        let (uid, token) = sign_in(&state, "unconfigured");
        let router = control_api_router(state);
        for uri in ["/billing/plans", "/billing/me", "/billing/invoice/x"] {
            let (status, answer) = get_json(&router, &token, uri, None).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{uri}");
            assert_eq!(answer["error"], "billing_not_configured");
        }
        let (status, _) = post_json(&router, &token, "/billing/checkout", json!({"plan_id": "mlc-paid-account-v1"}), None).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let (status, _) = deliver(&router, WEBHOOK_SECRET, Utc::now().timestamp(), &webhook_body("e1", "payment_confirmed", uid, "s", "i", json!({}))).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn checkout_is_unavailable_when_only_the_merchant_api_is_unconfigured() {
        let state = app_state(Some(runtime(None)));
        let (_, token) = sign_in(&state, "nomerchant");
        let router = control_api_router(state);
        let (status, answer) = post_json(&router, &token, "/billing/checkout", json!({"plan_id": "mlc-paid-account-v1"}), None).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(answer["error"], "billing_not_configured");
    }

    // -------------------------------------------------------------- webhook

    #[tokio::test]
    async fn the_webhook_refuses_bad_signatures_stale_timestamps_and_missing_headers() {
        let state = app_state(Some(runtime(None)));
        let (uid, _) = sign_in(&state, "hooked");
        let router = control_api_router(state.clone());
        let body = webhook_body("e1", "payment_confirmed", uid, "sub_1", "grp_1", json!({}));

        let (status, _) = deliver(&router, "some-other-secret", Utc::now().timestamp(), &body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "wrong secret");
        let (status, _) = deliver(&router, WEBHOOK_SECRET, Utc::now().timestamp() - 3600, &body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "replay outside the window");
        let (status, _) = send(&router, Method::POST, "/billing/webhook", &[], Some(body.to_string())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "no header");
        let raw = body.to_string();
        let header = sign_for_test(&[WEBHOOK_SECRET.as_bytes()], Utc::now().timestamp(), raw.as_bytes());
        let tampered = raw.replace("e1", "e2");
        let (status, _) = send(&router, Method::POST, "/billing/webhook", &[("x-dig2pay-signature", header.as_str())], Some(tampered)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "tampered body");

        let stored: i64 = state.control_plane().db.lock().expect("db").query_row("SELECT COUNT(*) FROM billing_events", [], |r| r.get(0)).expect("count");
        assert_eq!(stored, 0, "nothing unauthenticated is stored");
    }

    #[tokio::test]
    async fn the_webhook_accepts_any_secret_of_the_rotation_set() {
        let settings = BillingSettings::from_lookup(|_| None);
        let runtime = BillingRuntime::new(&settings, None, vec![b"old".to_vec(), b"new".to_vec()]);
        let state = app_state(Some(runtime));
        let router = control_api_router(state);
        let body = json!({ "event_id": "rot-1", "kind": "processor_incident" });
        let (status, _) = deliver(&router, "new", Utc::now().timestamp(), &body).await;
        assert_eq!(status, StatusCode::OK);
        let raw = body.to_string().replace("rot-1", "rot-2");
        let header = sign_for_test(&[b"old", b"new"], Utc::now().timestamp(), raw.as_bytes());
        let (status, _) = send(&router, Method::POST, "/billing/webhook", &[("x-dig2pay-signature", header.as_str())], Some(raw)).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn an_unknown_kind_and_a_replay_are_both_answered_200() {
        let state = app_state(Some(runtime(None)));
        let router = control_api_router(state.clone());
        let unknown = json!({ "event_id": "u1", "kind": "payment_teleported", "subscriber_id": "x" });
        let answer = deliver_ok(&router, &unknown).await;
        assert_eq!(answer["outcome"], "unknown_kind");
        let answer = deliver_ok(&router, &unknown).await;
        assert_eq!(answer["outcome"], "duplicate");
        let stored: i64 = state.control_plane().db.lock().expect("db").query_row("SELECT COUNT(*) FROM billing_events", [], |r| r.get(0)).expect("count");
        assert_eq!(stored, 1);
    }

    #[tokio::test]
    async fn a_signed_body_that_is_not_the_documented_json_is_a_400() {
        let state = app_state(Some(runtime(None)));
        let router = control_api_router(state);
        let raw = "not json".to_string();
        let header = sign_for_test(&[WEBHOOK_SECRET.as_bytes()], Utc::now().timestamp(), raw.as_bytes());
        let (status, _) = send(&router, Method::POST, "/billing/webhook", &[("x-dig2pay-signature", header.as_str())], Some(raw)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // ------------------------------------------------- end to end: accounts

    #[tokio::test]
    async fn end_to_end_purchase_of_a_paid_account_against_the_mock_merchant() {
        let (base, merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let (uid, token) = sign_in(&state, "buyer");
        let router = control_api_router(state.clone());

        let (_, me) = get_json(&router, &token, "/billing/me", None).await;
        assert_eq!(me["paid"], false);

        // Checkout: the merchant sees the bearer key and both idempotency keys.
        let (status, checkout) = post_json(&router, &token, "/billing/checkout", json!({"plan_id": "mlc-paid-account-v1"}), None).await;
        assert_eq!(status, StatusCode::OK, "{checkout}");
        assert_eq!(checkout["invoice_id"], "grp_1");
        assert_eq!(checkout["plan_id"], "mlc-paid-account-v1");
        let pay = checkout["pay"].as_array().expect("pay array");
        assert_eq!(pay.len(), 2);
        assert_eq!(pay[0]["chain"], "evm:1");
        assert_eq!(pay[0]["address"], "0x00000000000000000000000000000000000000aa");
        assert!(pay[0]["qr_svg"].as_str().expect("qr").starts_with("<svg"));
        assert_eq!(pay[1]["qr_svg"], "", "an SVG carrying script is dropped");
        {
            let mock = merchant.lock().expect("mock");
            let subscribers: Vec<_> = mock.calls.iter().filter(|c| c.path == "/subscribers").collect();
            let subscriptions: Vec<_> = mock.calls.iter().filter(|c| c.path == "/subscriptions").collect();
            assert_eq!(subscribers.len(), 1);
            assert_eq!(subscriptions.len(), 1);
            assert!(mock.calls.iter().all(|c| c.authorised), "every call carries the merchant key");
            assert_eq!(subscribers[0].body["external_user_ref"], uid.to_string());
            assert_eq!(subscribers[0].idempotency_key.as_deref(), Some(format!("mlc-customer-{uid}").as_str()));
            assert_eq!(subscriptions[0].body["plan_id"], "mlc-paid-account-v1");
            assert_eq!(subscriptions[0].body["subscriber_id"], format!("cus_{uid}"));
            assert!(subscriptions[0].idempotency_key.as_deref().is_some_and(|k| k.starts_with("mlc-co-")));
        }

        // Same request again: the same unpaid invoice, no second subscription.
        let (_, again) = post_json(&router, &token, "/billing/checkout", json!({"plan_id": "mlc-paid-account-v1"}), None).await;
        assert_eq!(again["invoice_id"], "grp_1");
        assert_eq!(merchant.lock().expect("mock").created, 1);

        // It shows up as open, unpaid.
        let (_, me) = get_json(&router, &token, "/billing/me", None).await;
        assert_eq!(me["open_invoices"][0]["invoice_id"], "grp_1");
        assert_eq!(me["paid"], false);

        // The owner can read it, with the processor's live status.
        merchant.lock().expect("mock").invoice_status = "processing".to_string();
        let (status, invoice) = get_json(&router, &token, "/billing/invoice/grp_1", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(invoice["live_status"], "processing");
        assert_eq!(invoice["grant_state"], "none");
        assert_eq!(invoice["pay"].as_array().expect("pay").len(), 2);

        // The signed webhook grants it.
        let confirmed = webhook_body("evt-1", "payment_confirmed", uid, "sub_1", "grp_1", json!({}));
        assert_eq!(deliver_ok(&router, &confirmed).await["outcome"], "granted");
        let (_, me) = get_json(&router, &token, "/billing/me", None).await;
        assert_eq!(me["paid"], true);
        assert_eq!(me["lifetime_paid"], true);
        assert_eq!(me["lifetime_anon"], false);
        assert_eq!(me["open_invoices"].as_array().expect("open").len(), 0);
        assert_eq!(me["subscription"]["state"], "paid");

        // A replay is a no-op.
        assert_eq!(deliver_ok(&router, &confirmed).await["outcome"], "duplicate");

        // A second checkout of what is already owned is refused.
        let (status, refused) = post_json(&router, &token, "/billing/checkout", json!({"plan_id": "mlc-paid-account-v1"}), None).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(refused["error"], "already_owned");

        // A refund revokes exactly that.
        let refund = webhook_body("evt-2", "refund_recorded", uid, "sub_1", "grp_1", json!({}));
        assert_eq!(deliver_ok(&router, &refund).await["outcome"], "revoked");
        let (_, me) = get_json(&router, &token, "/billing/me", None).await;
        assert_eq!(me["paid"], false);
        assert_eq!(me["lifetime_paid"], false);
    }

    #[tokio::test]
    async fn each_paid_account_plan_grants_its_flag_end_to_end_and_tor_ids_need_the_onion_host() {
        let (base, _merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let router = control_api_router(state.clone());

        for (plan, host, paid, anon) in [
            ("mlc-paid-account-v1", "mylittlechart.org", true, false),
            (DEFAULT_PAID_TOR_ID, ONION_HOST, true, false),
        ] {
            let (uid, token) = sign_in(&state, &format!("acct-{plan}"));
            let (status, checkout) = post_json(&router, &token, "/billing/checkout", json!({"plan_id": plan}), Some(host)).await;
            assert_eq!(status, StatusCode::OK, "{plan}: {checkout}");
            let invoice_id = checkout["invoice_id"].as_str().expect("invoice id").to_string();
            let subscription_id = invoice_id.replace("grp_", "sub_");
            let confirmed = webhook_body(&format!("evt-{plan}"), "payment_confirmed", uid, &subscription_id, &invoice_id, json!({}));
            assert_eq!(deliver_ok(&router, &confirmed).await["outcome"], "granted", "{plan}");
            let (_, me) = get_json(&router, &token, "/billing/me", None).await;
            assert_eq!((me["lifetime_paid"].as_bool(), me["lifetime_anon"].as_bool()), (Some(paid), Some(anon)), "{plan}");
            assert_eq!(me["paid"], true, "{plan}");
            assert_eq!(me["quant"]["tier"], Value::Null, "{plan}");
        }

        // The Tor ids are refused from the clearnet, and the clearnet ids from the onion.
        let (_, token) = sign_in(&state, "refused");
        for (plan, host) in [
            (DEFAULT_PAID_TOR_ID, "mylittlechart.org"),
            (DEFAULT_ANON_TOR_ID, "mylittlechart.org"),
            ("mlc-paid-account-v1", ONION_HOST),
            ("mlc-anon-account-v1", ONION_HOST),
            ("mlc-no-such-plan", "mylittlechart.org"),
        ] {
            let (status, answer) = post_json(&router, &token, "/billing/checkout", json!({"plan_id": plan}), Some(host)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{plan} via {host}");
            assert_eq!(answer["error"], "plan_not_available");
        }

        // An anonymous account is bought by someone who has none yet: the
        // signed-in checkout refuses those plans on their own vhost, too.
        for (plan, host) in [("mlc-anon-account-v1", "mylittlechart.org"), (DEFAULT_ANON_TOR_ID, ONION_HOST)] {
            let (status, answer) = post_json(&router, &token, "/billing/checkout", json!({"plan_id": plan}), Some(host)).await;
            assert_eq!((status, answer["error"].as_str()), (StatusCode::BAD_REQUEST, Some("anonymous_only")), "{plan}");
        }
        assert_eq!(merchant_calls(&_merchant, "/subscriptions"), 2, "only the two paid purchases reached the processor");
    }

    #[tokio::test]
    async fn a_forged_host_header_style_claim_through_x_forwarded_host_gets_no_tor_plan() {
        let (base, _merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let (_, token) = sign_in(&state, "forger");
        let router = control_api_router(state);
        let authorization = auth(&token);
        let (status, answer) = send(
            &router,
            Method::POST,
            "/billing/checkout",
            &[
                ("authorization", authorization.as_str()),
                ("content-type", "application/json"),
                ("host", "mylittlechart.org"),
                ("x-forwarded-host", ONION_HOST),
            ],
            Some(json!({"plan_id": DEFAULT_PAID_TOR_ID}).to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(answer["error"], "plan_not_available");
    }

    // ------------------------------------------------- owner scoping / retry

    #[tokio::test]
    async fn an_invoice_is_visible_to_its_owner_only() {
        let (base, _merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let (_, owner) = sign_in(&state, "owner");
        let (_, other) = sign_in(&state, "other");
        let router = control_api_router(state);

        let (_, checkout) = post_json(&router, &owner, "/billing/checkout", json!({"plan_id": "mlc-paid-account-v1"}), None).await;
        let invoice_id = checkout["invoice_id"].as_str().expect("invoice id");

        let (status, _) = get_json(&router, &owner, &format!("/billing/invoice/{invoice_id}"), None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, stranger) = get_json(&router, &other, &format!("/billing/invoice/{invoice_id}"), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, unknown) = get_json(&router, &other, "/billing/invoice/grp_never", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(stranger, unknown, "another account's invoice looks exactly like an unknown one");
        let (status, _) = send(&router, Method::GET, &format!("/billing/invoice/{invoice_id}"), &[], None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_failed_checkout_is_retried_under_the_same_idempotency_key() {
        let (base, merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let (_, token) = sign_in(&state, "retry");
        let router = control_api_router(state);

        merchant.lock().expect("mock").fail_next_subscription = true;
        let (status, answer) = post_json(&router, &token, "/billing/checkout", json!({"plan_id": "mlc-monthly-20-v1"}), None).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(answer["error"], "payment_gateway_unavailable");

        let (status, answer) = post_json(&router, &token, "/billing/checkout", json!({"plan_id": "mlc-monthly-20-v1"}), None).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        let mock = merchant.lock().expect("mock");
        let keys: Vec<_> = mock
            .calls
            .iter()
            .filter(|c| c.path == "/subscriptions")
            .map(|c| c.idempotency_key.clone().expect("key"))
            .collect();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], keys[1], "the retry replays the reserved key");
        assert_eq!(mock.created, 1, "one subscription minted for one intended purchase");
        assert_eq!(mock.calls.iter().filter(|c| c.path == "/subscribers").count(), 1, "the customer is recorded after its first success");
    }

    // ------------------------------------------- end to end: quant tiers

    #[tokio::test]
    async fn end_to_end_quant_subscription_renewal_upgrade_downgrade_and_refund() {
        let (base, merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let (uid, token) = sign_in(&state, "quant");
        let router = control_api_router(state.clone());

        let (status, checkout) = post_json(&router, &token, "/billing/checkout", json!({"plan_id": "mlc-monthly-20-v1"}), None).await;
        assert_eq!(status, StatusCode::OK, "{checkout}");
        let confirmed = webhook_body("q-1", "payment_confirmed", uid, "sub_1", "grp_1", period_days(30));
        assert_eq!(deliver_ok(&router, &confirmed).await["outcome"], "granted");

        let (_, me) = get_json(&router, &token, "/billing/me", None).await;
        assert_eq!(me["paid"], true);
        assert_eq!(me["quant"]["tier"], "mlc-monthly-20-v1");
        assert_eq!(me["quant"]["active"], true);
        assert_eq!(me["quant"]["quota"], 100);
        assert_eq!(me["lifetime_paid"], false);
        assert_eq!(me["subscription"]["state"], "active");

        // A second monthly subscription while one runs is refused: change it instead.
        let (status, refused) = post_json(&router, &token, "/billing/checkout", json!({"plan_id": "mlc-monthly-50-v1"}), None).await;
        assert_eq!((status, refused["error"].as_str()), (StatusCode::CONFLICT, Some("subscription_exists")));

        // Renewal extends the period.
        let first_end = me["quant"]["active_until"].as_str().expect("period end").to_string();
        let renewal = webhook_body("q-2", "renewal_confirmed", uid, "sub_1", "grp_2", period_days(60));
        assert_eq!(deliver_ok(&router, &renewal).await["outcome"], "granted");
        let (_, me) = get_json(&router, &token, "/billing/me", None).await;
        assert!(me["quant"]["active_until"].as_str().expect("period end") > first_end.as_str());

        // Upgrade: charged now, entitlement only on subscription_changed.
        merchant.lock().expect("mock").change_answer = Some(json!({
            "change_id": "chg_1", "state": "pending", "from_plan_id": "mlc-monthly-20-v1",
            "to_plan_id": "mlc-monthly-100-v1", "proration": "charge_now",
            "computed_charge_usd_micros": "60000000", "invoice_id": "grp_p1",
            "pay": pay_options("60.000000"),
        }));
        let (status, changed) = post_json(&router, &token, "/billing/change", json!({"plan_id": "mlc-monthly-100-v1"}), None).await;
        assert_eq!(status, StatusCode::OK, "{changed}");
        assert_eq!(changed["change_id"], "chg_1");
        assert_eq!(changed["proration"], "charge_now");
        assert_eq!(changed["charge_usd_micros"], "60000000");
        assert_eq!(changed["pay"].as_array().expect("pay").len(), 2);
        {
            let mock = merchant.lock().expect("mock");
            let call = mock.calls.iter().find(|c| c.path == "/subscriptions/sub_1/change").expect("change call");
            assert_eq!(call.body, json!({ "plan_id": "mlc-monthly-100-v1", "proration": "charge_now" }));
            assert!(call.idempotency_key.is_some());
        }
        let (_, me) = get_json(&router, &token, "/billing/me", None).await;
        assert_eq!(me["quant"]["tier"], "mlc-monthly-20-v1", "not upgraded until the processor says so");
        assert_eq!(me["subscription"]["pending_change"]["change_id"], "chg_1");
        let (status, again) = post_json(&router, &token, "/billing/change", json!({"plan_id": "mlc-monthly-200-v1"}), None).await;
        assert_eq!((status, again["error"].as_str()), (StatusCode::CONFLICT, Some("change_pending")));

        let applied = webhook_body("q-3", "subscription_changed", uid, "sub_1", "grp_2", json!({ "change_id": "chg_1", "state": "applied" }));
        assert_eq!(deliver_ok(&router, &applied).await["outcome"], "plan_changed");
        let (_, me) = get_json(&router, &token, "/billing/me", None).await;
        assert_eq!(me["quant"]["tier"], "mlc-monthly-100-v1");
        assert_eq!(me["subscription"]["plan_id"], "mlc-monthly-100-v1");
        assert_eq!(me["subscription"]["pending_change"], Value::Null);

        // The proration invoice can be read by its owner.
        let (status, proration) = get_json(&router, &token, "/billing/invoice/grp_p1", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(proration["kind"], "proration");

        // Downgrade: no charge, takes effect at renewal.
        merchant.lock().expect("mock").change_answer = Some(json!({
            "change_id": "chg_2", "state": "pending", "from_plan_id": "mlc-monthly-100-v1",
            "to_plan_id": "mlc-monthly-50-v1", "proration": "none",
            "pending_effective_at": (Utc::now() + Duration::days(20)).to_rfc3339(),
        }));
        let (status, down) = post_json(&router, &token, "/billing/change", json!({"plan_id": "mlc-monthly-50-v1"}), None).await;
        assert_eq!(status, StatusCode::OK, "{down}");
        assert_eq!(down["proration"], "none");
        assert!(down["pending_effective_at"].is_string());
        assert_eq!(down["pay"].as_array().expect("pay").len(), 0);
        {
            let mock = merchant.lock().expect("mock");
            let calls: Vec<_> = mock.calls.iter().filter(|c| c.path == "/subscriptions/sub_1/change").collect();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[1].body["proration"], "none");
            assert_ne!(calls[0].idempotency_key, calls[1].idempotency_key, "a new change gets a new key");
        }
        let (_, me) = get_json(&router, &token, "/billing/me", None).await;
        assert_eq!(me["quant"]["tier"], "mlc-monthly-100-v1", "the downgrade waits for the renewal");
        let applied_down = webhook_body("q-4", "subscription_changed", uid, "sub_1", "grp_3", json!({ "change_id": "chg_2", "state": "applied" }));
        assert_eq!(deliver_ok(&router, &applied_down).await["outcome"], "plan_changed");
        let (_, me) = get_json(&router, &token, "/billing/me", None).await;
        assert_eq!(me["quant"]["tier"], "mlc-monthly-50-v1");
        assert_eq!(me["quant"]["quota"], 300);

        // Same plan and unknown plan are refused before dig2pay is asked.
        let calls_before = merchant.lock().expect("mock").calls.len();
        let (status, same) = post_json(&router, &token, "/billing/change", json!({"plan_id": "mlc-monthly-50-v1"}), None).await;
        assert_eq!((status, same["error"].as_str()), (StatusCode::BAD_REQUEST, Some("same_plan")));
        let (status, _) = post_json(&router, &token, "/billing/change", json!({"plan_id": "mlc-paid-account-v1"}), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(merchant.lock().expect("mock").calls.len(), calls_before);

        // Refunding both paid periods ends the entitlement.
        for (event, invoice) in [("q-5", "grp_2"), ("q-6", "grp_1")] {
            let refund = webhook_body(event, "refund_recorded", uid, "sub_1", invoice, json!({}));
            assert_eq!(deliver_ok(&router, &refund).await["outcome"], "revoked");
        }
        let (_, me) = get_json(&router, &token, "/billing/me", None).await;
        assert_eq!(me["paid"], false);
        assert_eq!(me["quant"]["tier"], Value::Null);
    }

    #[tokio::test]
    async fn an_immediately_applied_change_moves_the_tier_without_waiting_for_the_webhook() {
        let (base, merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let (uid, token) = sign_in(&state, "instant");
        let router = control_api_router(state);
        post_json(&router, &token, "/billing/checkout", json!({"plan_id": "mlc-monthly-20-v1"}), None).await;
        deliver_ok(&router, &webhook_body("i-1", "payment_confirmed", uid, "sub_1", "grp_1", period_days(30))).await;

        merchant.lock().expect("mock").change_answer = Some(json!({
            "change_id": "chg_z", "state": "applied", "from_plan_id": "mlc-monthly-20-v1",
            "to_plan_id": "mlc-monthly-50-v1", "proration": "charge_now", "computed_charge_usd_micros": 0,
        }));
        let (status, changed) = post_json(&router, &token, "/billing/change", json!({"plan_id": "mlc-monthly-50-v1"}), None).await;
        assert_eq!(status, StatusCode::OK, "{changed}");
        assert_eq!(changed["state"], "applied");
        assert_eq!(changed["charge_usd_micros"], "0");
        let (_, me) = get_json(&router, &token, "/billing/me", None).await;
        assert_eq!(me["quant"]["tier"], "mlc-monthly-50-v1");

        // The webhook for the same change is then a no-op, not a second change.
        let applied = webhook_body("i-2", "subscription_changed", uid, "sub_1", "grp_1", json!({ "change_id": "chg_z", "state": "applied" }));
        assert_eq!(deliver_ok(&router, &applied).await["outcome"], "recorded");
    }

    #[tokio::test]
    async fn change_without_a_running_subscription_is_refused() {
        let (base, merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let (_, token) = sign_in(&state, "nosub");
        let router = control_api_router(state);
        let (status, answer) = post_json(&router, &token, "/billing/change", json!({"plan_id": "mlc-monthly-50-v1"}), None).await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::CONFLICT, Some("no_active_subscription")));
        assert!(merchant.lock().expect("mock").calls.is_empty());
    }

    // -------------------------------------------------------- integrity

    #[tokio::test]
    async fn partial_over_late_reverted_and_anomaly_are_recorded_and_visible_to_the_owner() {
        let (base, merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let (uid, token) = sign_in(&state, "integrity");
        let router = control_api_router(state);
        post_json(&router, &token, "/billing/checkout", json!({"plan_id": "mlc-paid-account-v1"}), None).await;

        let partial = webhook_body("p-1", "payment_partial", uid, "sub_1", "grp_1", json!({
            "amount": { "asset": "USDT", "chain": "tron", "value": "4.000000", "received": "4.000000", "expected": "10.000000", "shortfall": "6.000000" }
        }));
        assert_eq!(deliver_ok(&router, &partial).await["outcome"], "recorded");
        let (_, invoice) = get_json(&router, &token, "/billing/invoice/grp_1", None).await;
        assert_eq!(invoice["flags"], json!(["partial"]));
        assert_eq!(invoice["detail"]["partial"]["shortfall"], "6.000000");
        let (_, me) = get_json(&router, &token, "/billing/me", None).await;
        assert_eq!(me["paid"], false, "a partial payment grants nothing");

        let over = webhook_body("p-2", "payment_over", uid, "sub_1", "grp_1", json!({
            "amount": { "asset": "USDC", "chain": "evm:1", "value": "13.500000", "received": "13.500000", "expected": "10.000000", "excess": "3.500000" }
        }));
        assert_eq!(deliver_ok(&router, &over).await["outcome"], "credited");
        let (_, me) = get_json(&router, &token, "/billing/me", None).await;
        assert_eq!(me["credit_usd_micros"], 3_500_000);

        let late = webhook_body("p-3", "payment_confirmed", uid, "sub_1", "grp_1", json!({ "flags": ["late"] }));
        assert_eq!(deliver_ok(&router, &late).await["outcome"], "granted");
        let (_, invoice) = get_json(&router, &token, "/billing/invoice/grp_1", None).await;
        assert_eq!(invoice["flags"], json!(["partial", "over", "late"]));

        let anomaly = webhook_body("p-4", "payment_anomaly", uid, "sub_1", "grp_1", json!({
            "anomaly": { "subkind": "dust", "chain": "evm:1", "count": 2 }
        }));
        assert_eq!(deliver_ok(&router, &anomaly).await["outcome"], "recorded");

        // A reorg revokes; the owner polling after a re-settlement gets it back.
        let reverted = webhook_body("p-5", "payment_reverted", uid, "sub_1", "grp_1", json!({ "previous_status": "settled", "new_status": "processing" }));
        assert_eq!(deliver_ok(&router, &reverted).await["outcome"], "reverted");
        let (_, me) = get_json(&router, &token, "/billing/me", None).await;
        assert_eq!(me["paid"], false);
        merchant.lock().expect("mock").invoice_status = "processing".to_string();
        let (_, invoice) = get_json(&router, &token, "/billing/invoice/grp_1", None).await;
        assert_eq!(invoice["grant_state"], "reverted");
        merchant.lock().expect("mock").invoice_status = "settled".to_string();
        let (_, invoice) = get_json(&router, &token, "/billing/invoice/grp_1", None).await;
        assert_eq!(invoice["grant_state"], "granted");
        let (_, me) = get_json(&router, &token, "/billing/me", None).await;
        assert_eq!((me["paid"].as_bool(), me["lifetime_paid"].as_bool()), (Some(true), Some(true)));
    }

    #[tokio::test]
    async fn the_paid_until_column_keeps_working_beside_billing() {
        let state = app_state(Some(runtime(None)));
        let (uid, token) = sign_in(&state, "legacy");
        {
            let conn = state.control_plane().db.lock().expect("db");
            crate::db::set_user_paid_until(&conn, uid, Some(&(Utc::now() + Duration::days(9)).to_rfc3339())).expect("paid_until");
        }
        let router = control_api_router(state);
        let (_, me) = get_json(&router, &token, "/billing/me", None).await;
        assert_eq!(me["paid"], true);
        assert!(me["paid_until"].is_string());
        assert_eq!((me["lifetime_paid"].as_bool(), me["lifetime_anon"].as_bool()), (Some(false), Some(false)));
        let (_, entitlements) = get_json(&router, &token, "/entitlements", None).await;
        assert_eq!(entitlements["paid"], true);
    }

    #[test]
    fn stored_events_carry_the_outcome_and_the_raw_body() {
        let conn = crate::billing::testkit::conn();
        let catalog = runtime(None);
        let raw = json!({ "event_id": "raw-1", "kind": "payment_teleported" }).to_string();
        webhook::process(&conn, catalog.catalog(), None, &raw, Utc::now()).expect("process");
        let (outcome, body): (String, String) = conn
            .query_row("SELECT outcome, body FROM billing_events WHERE event_id = 'raw-1'", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("stored");
        assert_eq!(outcome, "unknown_kind");
        assert_eq!(body, raw);
        assert!(store::invoice_by_id(&conn, "nope").expect("query").is_none());
    }

    // ------------------------------------------- one-time contract (dig2pay)

    /// Sign in as `name` and check out `plan`; returns the account, its token
    /// and the checkout answer.
    pub(crate) async fn buy(router: &Router, state: &Arc<AppState>, name: &str, plan: &str, host: Option<&str>) -> (i64, String, Value) {
        let (uid, token) = sign_in(state, name);
        let (status, checkout) = post_json(router, &token, "/billing/checkout", json!({ "plan_id": plan }), host).await;
        assert_eq!(status, StatusCode::OK, "{plan}: {checkout}");
        (uid, token, checkout)
    }

    /// The webhook body dig2pay sends when a one-time plan settles.
    pub(crate) fn one_time_settlement(event_id: &str, uid: i64, plan: &str, sub: &str, invoice: &str) -> Value {
        webhook_body(
            event_id,
            "payment_confirmed",
            uid,
            sub,
            invoice,
            json!({
                "plan_id": plan,
                "billing_interval": "one_time",
                "period": { "from": Utc::now().to_rfc3339(), "to": null },
            }),
        )
    }

    pub(crate) fn user_dates(state: &Arc<AppState>, uid: i64) -> (Option<String>, Option<String>) {
        state
            .control_plane()
            .db
            .lock()
            .expect("db")
            .query_row("SELECT paid_until, quant_active_until FROM users WHERE id = ?1", [uid], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("user dates")
    }

    pub(crate) fn merchant_calls(merchant: &Shared, path: &str) -> usize {
        merchant.lock().expect("mock").calls.iter().filter(|c| c.path == path).count()
    }

    #[tokio::test]
    async fn a_plan_the_processor_does_not_have_yet_is_a_clean_503_that_recovers_once_it_exists() {
        let (base, merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let (_, token) = sign_in(&state, "early");
        let router = control_api_router(state);
        merchant.lock().expect("mock").unknown_plans.insert("mlc-paid-account-v1".to_string());

        let (status, answer) = post_json(&router, &token, "/billing/checkout", json!({ "plan_id": "mlc-paid-account-v1" }), None).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(answer["error"], "plan_unavailable");
        assert_eq!(merchant.lock().expect("mock").created, 0, "nothing was created");

        // dig2pay adds the plan: the same purchase goes through, replaying the reserved key.
        merchant.lock().expect("mock").unknown_plans.clear();
        let (status, answer) = post_json(&router, &token, "/billing/checkout", json!({ "plan_id": "mlc-paid-account-v1" }), None).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        let mock = merchant.lock().expect("mock");
        let keys: Vec<_> = mock.calls.iter().filter(|c| c.path == "/subscriptions").map(|c| c.idempotency_key.clone()).collect();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], keys[1]);
        assert_eq!(mock.created, 1);
    }

    #[tokio::test]
    async fn contract_a_one_time_plan_uses_the_monthly_routes_and_settles_once_into_terminal_paid() {
        let (base, merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let router = control_api_router(state.clone());

        // Same routes as monthly: POST /subscribers, then POST /subscriptions with an Idempotency-Key.
        let (uid, token, checkout) = buy(&router, &state, "one-timer", "mlc-paid-account-v1", None).await;
        assert_eq!(checkout["invoice_id"], "grp_1");
        assert!(checkout["pay"].as_array().is_some_and(|p| !p.is_empty()), "pay[] is passed through as issued");
        {
            let mock = merchant.lock().expect("mock");
            let paths: Vec<_> = mock.calls.iter().map(|c| c.path.as_str()).collect();
            assert_eq!(paths, ["/subscribers", "/subscriptions"], "no /orders, no other route");
            assert!(mock.calls.iter().all(|c| c.idempotency_key.is_some()), "both creates carry an Idempotency-Key");
        }
        // Poll with GET /invoices/{id}.
        merchant.lock().expect("mock").invoice_status = "processing".to_string();
        let (_, invoice) = get_json(&router, &token, "/billing/invoice/grp_1", None).await;
        assert_eq!(invoice["live_status"], "processing");
        assert_eq!(merchant_calls(&merchant, "/invoices/grp_1"), 1);

        // Exactly ONE payment_confirmed settles it.
        let settled = one_time_settlement("ot-1", uid, "mlc-paid-account-v1", "sub_1", "grp_1");
        assert_eq!(deliver_ok(&router, &settled).await["outcome"], "granted");
        let (_, me) = get_json(&router, &token, "/billing/me", None).await;
        assert_eq!((me["lifetime_anon"].as_bool(), me["lifetime_paid"].as_bool(), me["paid"].as_bool()), (Some(false), Some(true), Some(true)));
        assert_eq!(me["subscription"]["state"], "paid", "the subscription is terminal paid");
        assert_eq!(me["subscription"]["active_until"], Value::Null);
        assert_eq!(me["quant"]["tier"], Value::Null);

        // A one-time plan never gets renewal_confirmed; if one arrives anyway nothing changes.
        let stray = webhook_body("ot-2", "renewal_confirmed", uid, "sub_1", "grp_2", json!({
            "plan_id": "mlc-paid-account-v1",
            "billing_interval": "one_time",
            "period": { "from": Utc::now().to_rfc3339(), "to": null },
        }));
        assert_eq!(deliver_ok(&router, &stray).await["outcome"], "ignored");
        let (status, _) = get_json(&router, &token, "/billing/invoice/grp_2", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "no invoice row is invented for it");
        let (_, after) = get_json(&router, &token, "/billing/me", None).await;
        assert_eq!(after["subscription"]["state"], "paid");
        assert_eq!((after["lifetime_paid"].as_bool(), after["paid"].as_bool()), (Some(true), Some(true)));

        // Replaying the settlement is a no-op.
        assert_eq!(deliver_ok(&router, &settled).await["outcome"], "duplicate");
    }

    #[tokio::test]
    async fn contract_webhook_bodies_decode_with_or_without_the_additive_fields() {
        let (base, _merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let router = control_api_router(state.clone());

        // Older body: no plan_id, no billing_interval, a dated period on a monthly plan.
        let (uid, token, _) = buy(&router, &state, "old-body", "mlc-monthly-20-v1", None).await;
        let old = webhook_body("d-1", "payment_confirmed", uid, "sub_1", "grp_1", period_days(30));
        assert_eq!(deliver_ok(&router, &old).await["outcome"], "granted");

        // Newer body: the additive fields, plus one nobody has heard of.
        let (uid2, token2, _) = buy(&router, &state, "new-body", "mlc-paid-account-v1", None).await;
        let mut newer = one_time_settlement("d-2", uid2, "mlc-paid-account-v1", "sub_2", "grp_2");
        if let Some(obj) = newer.as_object_mut() {
            obj.insert("a_future_field".to_string(), json!({ "x": [1, 2, 3] }));
        }
        assert_eq!(deliver_ok(&router, &newer).await["outcome"], "granted");

        // Older one-time body: closed to nothing, no interval, no plan_id — still permanent.
        let (uid3, token3, _) = buy(&router, &state, "old-onetime", "mlc-paid-account-v1", None).await;
        let older_one_time = webhook_body("d-3", "payment_confirmed", uid3, "sub_3", "grp_3", json!({}));
        assert_eq!(deliver_ok(&router, &older_one_time).await["outcome"], "granted");

        for (t, label, paid_flag) in [(&token, "monthly", false), (&token2, "new one-time", true), (&token3, "old one-time", true)] {
            let (_, me) = get_json(&router, t, "/billing/me", None).await;
            assert_eq!(me["paid"], true, "{label}");
            assert_eq!(me["lifetime_paid"], paid_flag, "{label}");
        }
    }

    #[tokio::test]
    async fn contract_a_one_time_grant_is_permanent_and_never_writes_a_date() {
        let (base, _merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let router = control_api_router(state.clone());

        for (name, plan, host, anon) in [
            ("perm-paid", "mlc-paid-account-v1", "mylittlechart.org", false),
            ("perm-paid-tor", DEFAULT_PAID_TOR_ID, ONION_HOST, false),
        ] {
            let (uid, token, checkout) = buy(&router, &state, name, plan, Some(host)).await;
            let invoice_id = checkout["invoice_id"].as_str().expect("invoice").to_string();
            let sub_id = invoice_id.replace("grp_", "sub_");
            let settled = one_time_settlement(&format!("perm-{name}"), uid, plan, &sub_id, &invoice_id);
            assert_eq!(deliver_ok(&router, &settled).await["outcome"], "granted", "{plan}");

            let (_, me) = get_json(&router, &token, "/billing/me", None).await;
            assert_eq!((me["lifetime_paid"].as_bool(), me["lifetime_anon"].as_bool()), (Some(true), Some(anon)), "{plan}");
            assert_eq!(user_dates(&state, uid), (None, None), "{plan}: no date column is written");
            let (_, invoice) = get_json(&router, &token, &format!("/billing/invoice/{invoice_id}"), None).await;
            assert_eq!(invoice["period"], Value::Null, "{plan}: a permanent grant has no period to report");
            assert_eq!(invoice["grant_state"], "granted");
            // Nothing about it expires with the calendar.
            let far_future = Utc::now() + Duration::days(36_500);
            let conn = state.control_plane().db.lock().expect("db");
            assert!(crate::billing::entitle::entitlement_view(&conn, uid, far_future).expect("view").paid, "{plan}");
        }
    }

    #[tokio::test]
    async fn contract_a_null_to_on_a_monthly_plan_is_rejected_stored_and_not_granted() {
        let (base, _merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let router = control_api_router(state.clone());
        let (uid, token, _) = buy(&router, &state, "malformed", "mlc-monthly-100-v1", None).await;

        let null_to = webhook_body("m-1", "payment_confirmed", uid, "sub_1", "grp_1", json!({
            "plan_id": "mlc-monthly-100-v1",
            "billing_interval": "monthly",
            "period": { "from": Utc::now().to_rfc3339(), "to": null },
        }));
        let (status, answer) = deliver(&router, WEBHOOK_SECRET, Utc::now().timestamp(), &null_to).await;
        assert_eq!(status, StatusCode::OK, "still acknowledged so it is not redelivered forever");
        assert_eq!(answer["outcome"], "malformed");

        let claims_one_time = webhook_body("m-2", "payment_confirmed", uid, "sub_1", "grp_1", json!({
            "billing_interval": "one_time",
            "period": { "from": Utc::now().to_rfc3339(), "to": (Utc::now() + Duration::days(30)).to_rfc3339() },
        }));
        assert_eq!(deliver_ok(&router, &claims_one_time).await["outcome"], "malformed");

        let (_, me) = get_json(&router, &token, "/billing/me", None).await;
        assert_eq!(me["paid"], false);
        assert_eq!(me["quant"]["tier"], Value::Null);
        assert_eq!(user_dates(&state, uid), (None, None));
        let stored: i64 = state
            .control_plane()
            .db
            .lock()
            .expect("db")
            .query_row("SELECT COUNT(*) FROM billing_events WHERE outcome = 'malformed'", [], |r| r.get(0))
            .expect("count");
        assert_eq!(stored, 2, "both are on record");

        // The same subscription, delivered correctly, grants.
        let good = webhook_body("m-3", "payment_confirmed", uid, "sub_1", "grp_1", period_days(30));
        assert_eq!(deliver_ok(&router, &good).await["outcome"], "granted");
    }

    #[tokio::test]
    async fn contract_repeat_purchases_of_a_held_paid_account_are_409_and_create_nothing() {
        let (base, merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let router = control_api_router(state.clone());

        let (uid, token, _) = buy(&router, &state, "holder", "mlc-paid-account-v1", None).await;
        deliver_ok(&router, &one_time_settlement("r-1", uid, "mlc-paid-account-v1", "sub_1", "grp_1")).await;
        let calls_before = merchant.lock().expect("mock").calls.len();

        // Neither the clearnet nor the Tor paid account can be bought again.
        for (plan, host) in [("mlc-paid-account-v1", "mylittlechart.org"), (DEFAULT_PAID_TOR_ID, ONION_HOST)] {
            let (status, answer) = post_json(&router, &token, "/billing/checkout", json!({ "plan_id": plan }), Some(host)).await;
            assert_eq!(status, StatusCode::CONFLICT, "{plan}");
            assert_eq!(answer["error"], "already_owned", "{plan}");
        }
        assert_eq!(merchant.lock().expect("mock").calls.len(), calls_before, "nothing was created on the processor");
        assert_eq!(merchant.lock().expect("mock").created, 1);

        // A quant tier is a different purchase and stays open to a paid account.
        let (status, _) = post_json(&router, &token, "/billing/checkout", json!({ "plan_id": "mlc-monthly-20-v1" }), None).await;
        assert_eq!(status, StatusCode::OK);
    }
    // ------------------------------------------- the grant ledger, admin side

    async fn admin_call(admin: &Router, secret: &str, method: Method, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
        let authorization = format!("Bearer {secret}");
        send(
            admin,
            method,
            uri,
            &[("authorization", authorization.as_str()), ("content-type", "application/json")],
            body.map(|b| b.to_string()),
        )
        .await
    }

    #[tokio::test]
    async fn an_operator_grant_survives_the_refund_of_an_invoice_and_is_managed_through_the_admin_routes() {
        let (base, _merchant) = spawn_merchant().await;
        let state = app_state_with_admin(Some(runtime(Some(&base))), "s3cret");
        let router = control_api_router(state.clone());
        let admin = crate::routes::admin_api_router(state.clone());
        let (uid, token, _) = buy(&router, &state, "ledger-user", "mlc-paid-account-v1", None).await;
        deliver_ok(&router, &one_time_settlement("l-1", uid, "mlc-paid-account-v1", "sub_1", "grp_1")).await;

        // Add: 201, then the same again is a 200 that creates nothing.
        let grants_uri = format!("/admin/users/{uid}/grants");
        let body = json!({ "grant": "lifetime_paid", "admin_user_id": 7, "note": "early supporter" });
        let (status, added) = admin_call(&admin, "s3cret", Method::POST, &grants_uri, Some(body.clone())).await;
        assert_eq!(status, StatusCode::CREATED, "{added}");
        assert_eq!(added["source"], "admin");
        assert_eq!(added["source_ref"], "7:early supporter");
        assert_eq!(added["created"], true);
        let grant_id = added["grant_id"].as_i64().expect("grant id");
        let (status, again) = admin_call(&admin, "s3cret", Method::POST, &grants_uri, Some(body)).await;
        assert_eq!((status, again["created"].as_bool(), again["grant_id"].as_i64()), (StatusCode::OK, Some(false), Some(grant_id)));

        // The invoice is refunded: the account keeps the status the operator gave it.
        let refund = webhook_body("l-2", "refund_recorded", uid, "sub_1", "grp_1", json!({}));
        assert_eq!(deliver_ok(&router, &refund).await["outcome"], "revoked");
        let (_, me) = get_json(&router, &token, "/billing/me", None).await;
        assert_eq!((me["lifetime_paid"].as_bool(), me["paid"].as_bool()), (Some(true), Some(true)));

        // The list shows both rows, the invoice's revoked.
        let (status, listed) = admin_call(&admin, "s3cret", Method::GET, &grants_uri, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!((listed["lifetime_paid"].as_bool(), listed["lifetime_anon"].as_bool()), (Some(true), Some(false)));
        let rows = listed["grants"].as_array().expect("grants");
        assert_eq!(rows.len(), 2);
        let invoice_row = rows.iter().find(|r| r["source"] == "invoice").expect("invoice row");
        assert_eq!(invoice_row["source_ref"], "grp_1");
        assert!(invoice_row["revoked_at"].is_string());
        let admin_row = rows.iter().find(|r| r["source"] == "admin").expect("admin row");
        assert!(admin_row["revoked_at"].is_null());

        // An invoice's row is not the operator's to revoke; the operator's is.
        let invoice_grant_id = invoice_row["grant_id"].as_i64().expect("id");
        let (status, _) = admin_call(&admin, "s3cret", Method::DELETE, &format!("{grants_uri}/{invoice_grant_id}"), None).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let (status, revoked) = admin_call(&admin, "s3cret", Method::DELETE, &format!("{grants_uri}/{grant_id}"), None).await;
        assert_eq!((status, revoked["revoked"].as_bool()), (StatusCode::OK, Some(true)));
        let (_, revoked_again) = admin_call(&admin, "s3cret", Method::DELETE, &format!("{grants_uri}/{grant_id}"), None).await;
        assert_eq!(revoked_again["revoked"], false);
        let (_, me) = get_json(&router, &token, "/billing/me", None).await;
        assert_eq!((me["lifetime_paid"].as_bool(), me["paid"].as_bool()), (Some(false), Some(false)));
    }

    #[tokio::test]
    async fn the_admin_grant_routes_are_gated_and_validate_their_input() {
        let (base, _merchant) = spawn_merchant().await;
        let state = app_state_with_admin(Some(runtime(Some(&base))), "s3cret");
        let (uid, _) = sign_in(&state, "target");
        let admin = crate::routes::admin_api_router(state.clone());
        let uri = format!("/admin/users/{uid}/grants");
        let ok = json!({ "grant": "lifetime_anon", "admin_user_id": 1, "note": "n" });

        // A wrong or missing secret is indistinguishable from no such route.
        for secret in ["wrong", ""] {
            let (status, body) = admin_call(&admin, secret, Method::POST, &uri, Some(ok.clone())).await;
            assert_eq!((status, body), (StatusCode::NOT_FOUND, Value::Null), "secret {secret:?}");
        }
        let (status, _) = send(&admin, Method::GET, &uri, &[], None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        for (label, body, want) in [
            ("unknown grant", json!({ "grant": "quant", "admin_user_id": 1, "note": "n" }), StatusCode::BAD_REQUEST),
            ("no note", json!({ "grant": "lifetime_paid", "admin_user_id": 1, "note": "  " }), StatusCode::BAD_REQUEST),
            ("long note", json!({ "grant": "lifetime_paid", "admin_user_id": 1, "note": "x".repeat(201) }), StatusCode::BAD_REQUEST),
            ("no admin id", json!({ "grant": "lifetime_paid", "admin_user_id": 0, "note": "n" }), StatusCode::BAD_REQUEST),
            ("missing field", json!({ "grant": "lifetime_paid" }), StatusCode::BAD_REQUEST),
        ] {
            let (status, _) = admin_call(&admin, "s3cret", Method::POST, &uri, Some(body)).await;
            assert_eq!(status, want, "{label}");
        }
        let (status, _) = admin_call(&admin, "s3cret", Method::POST, "/admin/users/424242/grants", Some(ok.clone())).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unknown user");
        let (status, _) = admin_call(&admin, "s3cret", Method::GET, "/admin/users/424242/grants", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = admin_call(&admin, "s3cret", Method::DELETE, &format!("{uri}/999"), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unknown row");
        assert_eq!(
            state.control_plane().db.lock().expect("db").query_row("SELECT COUNT(*) FROM billing_grants", [], |r| r.get::<_, i64>(0)).expect("count"),
            0,
            "every refusal left the ledger empty"
        );
    }
}

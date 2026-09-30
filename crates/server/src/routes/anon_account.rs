//! Anonymous ("numbered") account routes: buy one, read its invoice, enter it
//! with its credential, rotate the credential, or open one with a registration
//! invite. The account has no OAuth identity and no email; the credential is
//! the whole login. The design lives in `billing/anon.rs` and
//! `billing/invite.rs`.
//!
//! The credential `C` is derived on the client from a secret the server never
//! sees (docs/mlc/plans/anon-account-one-key-a1b): 32 bytes as 64 hex
//! characters. The server stores `SHA-256(C)` and generates nothing.
//!
//! | Route | Auth | Purpose |
//! |---|---|---|
//! | `POST /api/billing/anon-checkout {plan_id, credential}` | none (per-IP hourly budget + a global one) | create a PENDING account and its invoice -> `201 {invoice_id, pay[]}` |
//! | `GET /api/billing/anon-invoice/{id}` | `Authorization: AccountKey <credential>` | read the account's own invoice (any status) |
//! | `POST /api/auth/account-key {credential}` | none (per-IP failure throttle) | ACTIVE account -> a session, the same shape the Telegram sign-in returns |
//! | `POST /api/account/key/rotate {credential}` | session | signed-in anonymous account -> the new credential replaces the old one |
//! | `POST /api/auth/invite/redeem {invite_code, credential}` | none (the same per-IP failure throttle) | burn a registration invite -> a new ACTIVE account and a session |
//!
//! Nothing in this file formats a credential or an invite code into a log
//! line or an error body. Sign-in, invoice reads and invite redemption answer
//! every unusable secret with the same `401` (`invalid account key`, resp.
//! `invalid invite code`) and count it as a failure of the caller's address;
//! the routes that create or change a credential (`anon-checkout`, `rotate`,
//! `redeem`) answer a malformed one with `400 invalid_credential`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{ConnectInfo, Extension, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::auth::extract_ua_hash;
use crate::billing::anon::{self, AccountStatus, AnonAccount, Credential, Rotation};
use crate::billing::flow;
use crate::billing::invite::{self, RedeemRefusal};
use crate::billing::throttle::SlidingLimiter;
use crate::billing::BillingRuntime;
use crate::models::types::ErrorResponse;
use crate::routes::billing::{error, flow_error, invoice_json, signed_in};
use crate::state::AppState;

/// Lifetime of the session a key sign-in mints — the same as the other
/// sign-ins.
const SESSION_HOURS: i64 = 24;

/// The one answer to every unusable credential.
fn invalid_key() -> Response {
    error(StatusCode::UNAUTHORIZED, "invalid account key")
}

/// The one answer to every unusable invite code.
fn invalid_invite() -> Response {
    error(StatusCode::UNAUTHORIZED, "invalid invite code")
}

/// A credential that is not 64 hex characters.
fn invalid_credential() -> Response {
    error(StatusCode::BAD_REQUEST, "invalid_credential")
}

/// `429` with a `Retry-After` of the limiter's whole window (the safe upper
/// bound; the oldest hit leaves sooner).
fn rate_limited(limiter: &SlidingLimiter<IpAddr>) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, limiter.window().as_secs().to_string())],
        Json(ErrorResponse::new("rate_limited")),
    )
        .into_response()
}

/// The address a request is budgeted against — the same resolution the
/// app-wide limiter uses (`X-Forwarded-For` only from a trusted proxy peer).
/// Without connection info (never in production) all callers share one bucket.
fn caller_ip(headers: &HeaderMap, peer: Option<Extension<ConnectInfo<SocketAddr>>>) -> IpAddr {
    let peer_ip = peer.map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |Extension(ConnectInfo(addr))| addr.ip());
    crate::ratelimit::client_ip(headers, peer_ip)
}

/// Request body of `POST /api/billing/anon-checkout`.
#[derive(Deserialize)]
pub struct AnonCheckoutBody {
    /// A `mlc-anon-account*` plan; on the onion vhost, the Tor one.
    pub plan_id: String,
    /// The client-derived credential, 64 hex characters.
    #[serde(default)]
    pub credential: String,
}

/// `POST /api/billing/anon-checkout` — public.
///
/// Creates a PENDING anonymous user holding `SHA-256(credential)`, opens the
/// dig2pay subscription under that user's id, and answers `201`:
///
/// ```json
/// { "invoice_id": "grp_…",
///   "pay": [ { "chain": "evm:1", "asset": "USDC", "address": "0x…",
///              "amount": "10.000000", "expires_at": "…", "qr_svg": "<svg…>" }, … ] }
/// ```
/// No key comes back: the client already holds it. Errors:
/// `400 plan_not_available` (not an anonymous-account plan, or not the plan of
/// this vhost), `400 invalid_credential`, `409 credential_in_use`,
/// `429 rate_limited` (5 per client IP per hour and a global cap, both
/// configurable), `503 plan_unavailable`, `503 billing_not_configured`,
/// `502 payment_gateway_unavailable`.
pub async fn anon_checkout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Json(body): Json<AnonCheckoutBody>,
) -> Response {
    let Some(billing) = state.billing() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "billing_not_configured");
    };
    if billing.client().is_none() {
        return error(StatusCode::SERVICE_UNAVAILABLE, "billing_not_configured");
    }
    let onion = billing.is_onion_request(&headers);
    let plan_id = body.plan_id.trim();
    // A request for the wrong plan or with a malformed credential must not
    // spend anyone's budget.
    let sold_here = billing
        .catalog()
        .get(plan_id)
        .is_some_and(|p| p.grant == crate::billing::plans::Grant::LifetimeAnon && p.offered_to(onion));
    if !sold_here {
        return error(StatusCode::BAD_REQUEST, "plan_not_available");
    }
    let Some(credential) = Credential::parse(&body.credential) else {
        return invalid_credential();
    };
    let limiter = billing.anon_create_limiter();
    if !limiter.try_acquire(caller_ip(&headers, peer), Instant::now()) {
        return rate_limited(limiter);
    }
    match flow::anon_checkout(&state, plan_id, onion, credential).await {
        Ok(view) => (StatusCode::CREATED, Json(json!({ "invoice_id": view.invoice_id, "pay": view.pay }))).into_response(),
        Err(e) => flow_error(e),
    }
}

/// The `Authorization: AccountKey <credential>` value, if that is what was sent.
fn presented_key(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("AccountKey "))
}

/// Look a presented credential up, under the per-IP failure throttle.
///
/// `Err` is the response to send (`429` once the address has used up its
/// failures; the credential is not even looked at then). `Ok(None)` is an
/// unusable credential — malformed or unknown — and has been counted as a
/// failure.
async fn account_for_key(
    state: &Arc<AppState>,
    billing: &BillingRuntime,
    presented: Option<&str>,
    ip: IpAddr,
) -> Result<Option<AnonAccount>, Response> {
    let failures = billing.key_failure_limiter();
    if failures.is_blocked(ip, Instant::now()) {
        return Err(rate_limited(failures));
    }
    let Some(key) = presented.and_then(Credential::parse) else {
        failures.record(ip, Instant::now());
        return Ok(None);
    };
    let state = state.clone();
    let found = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        anon::find_by_key(&conn, &key)
    })
    .await;
    match found {
        Ok(Ok(Some(account))) => Ok(Some(account)),
        Ok(Ok(None)) => {
            failures.record(ip, Instant::now());
            Ok(None)
        }
        Ok(Err(e)) => {
            tracing::error!("anonymous account lookup failed: {e}");
            Err(error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))
        }
        Err(_) => Err(error(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")),
    }
}

/// `GET /api/billing/anon-invoice/{id}` — `Authorization: AccountKey <credential>`.
///
/// The credential (pending or active account) can read its own account's
/// invoices and nothing else; the answer is the same shape as
/// `GET /api/billing/invoice/{id}`. `401 invalid account key` for any unusable
/// credential, `404 not_found` for an invoice that is not this account's,
/// `429 rate_limited` after too many failed credentials from one address.
pub async fn anon_invoice(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(id): Path<String>,
) -> Response {
    let Some(billing) = state.billing() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "billing_not_configured");
    };
    let ip = caller_ip(&headers, peer);
    let account = match account_for_key(&state, &billing, presented_key(&headers), ip).await {
        Ok(Some(account)) => account,
        Ok(None) => return invalid_key(),
        Err(response) => return response,
    };
    match flow::invoice(&state, account.user_id, &id).await {
        Ok(view) => Json(invoice_json(view)).into_response(),
        Err(e) => flow_error(e),
    }
}

/// Mint a web session for `user_id` and answer in the shape the Telegram
/// sign-in poll returns, plus the same `session_id` cookie:
///
/// ```json
/// { "status": "confirmed", "user_id": 42, "public_id": "…", "session_id": "…" }
/// ```
async fn open_session(state: Arc<AppState>, headers: &HeaderMap, user_id: i64) -> Response {
    let ua_hash = extract_ua_hash(headers);
    let minted = tokio::task::spawn_blocking(move || -> rusqlite::Result<(String, String)> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now();
        let expires = (now + chrono::Duration::hours(SESSION_HOURS)).to_rfc3339();
        let session_id = crate::db::create_web_session(&conn, user_id, &now.to_rfc3339(), &expires, &ua_hash)?;
        let public_id = crate::db::get_user_public_id(&conn, user_id)?;
        Ok((session_id, public_id))
    })
    .await;
    match minted {
        Ok(Ok((session_id, public_id))) => {
            let cookie = format!(
                "session_id={session_id}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={}",
                SESSION_HOURS * 3600
            );
            (
                StatusCode::OK,
                [(header::SET_COOKIE, cookie)],
                Json(json!({
                    "status": "confirmed",
                    "user_id": user_id,
                    "public_id": public_id,
                    "session_id": session_id,
                })),
            )
                .into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("anonymous sign-in could not mint a session: {e}");
            error(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
        }
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
    }
}

/// Request body of `POST /api/auth/account-key`.
#[derive(Deserialize)]
pub struct SignInBody {
    /// The client-derived credential, 64 hex characters.
    #[serde(default)]
    pub credential: String,
}

/// `POST /api/auth/account-key {credential}` — public.
///
/// The credential of an ACTIVE anonymous account becomes a session (see
/// [`open_session`] for the shape). A malformed (an old-format key included),
/// unknown or still-pending credential all get the same
/// `401 {"error":"invalid account key"}`. After too many failures from one
/// address that address gets `429 rate_limited` until they age out.
pub async fn sign_in(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Json(body): Json<SignInBody>,
) -> Response {
    let Some(billing) = state.billing() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "billing_not_configured");
    };
    let ip = caller_ip(&headers, peer);
    let account = match account_for_key(&state, &billing, Some(body.credential.as_str()), ip).await {
        Ok(Some(account)) => account,
        Ok(None) => return invalid_key(),
        Err(response) => return response,
    };
    if account.status != AccountStatus::Active {
        billing.key_failure_limiter().record(ip, Instant::now());
        return invalid_key();
    }
    open_session(state, &headers, account.user_id).await
}

/// Request body of `POST /api/account/key/rotate`.
#[derive(Deserialize)]
pub struct RotateBody {
    /// The NEW client-derived credential, 64 hex characters.
    #[serde(default)]
    pub credential: String,
}

/// `POST /api/account/key/rotate {credential}` — a signed-in ACTIVE anonymous
/// account.
///
/// The client derived the new credential from a new secret (and re-keyed its
/// vault) before calling; the server swaps the stored hash and answers
/// `200 {"rotated": true}`. The old credential stops working at once.
/// Sessions already open stay open. `400 invalid_credential`, `401` without a
/// session, `403 not_an_anonymous_account` for any other account,
/// `409 credential_in_use` when another account holds it.
pub async fn rotate(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<RotateBody>) -> Response {
    let user_id = match signed_in(&state, &headers).await {
        Ok(id) => id,
        Err(response) => return response,
    };
    let Some(credential) = Credential::parse(&body.credential) else {
        return invalid_credential();
    };
    let rotated = tokio::task::spawn_blocking(move || -> rusqlite::Result<Rotation> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        anon::rotate_key(&conn, user_id, &credential, chrono::Utc::now())
    })
    .await;
    match rotated {
        Ok(Ok(Rotation::Done)) => Json(json!({ "rotated": true })).into_response(),
        Ok(Ok(Rotation::NotAnonymous)) => error(StatusCode::FORBIDDEN, "not_an_anonymous_account"),
        Ok(Ok(Rotation::InUse)) => error(StatusCode::CONFLICT, "credential_in_use"),
        Ok(Err(e)) => {
            tracing::error!("account key rotation failed: {e}");
            error(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
        }
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
    }
}

/// Request body of `POST /api/auth/invite/redeem`.
#[derive(Deserialize)]
pub struct RedeemBody {
    /// The invite code an admin handed out (case, hyphens and spaces are forgiven).
    #[serde(default)]
    pub invite_code: String,
    /// The client-derived credential of the new account, 64 hex characters.
    #[serde(default)]
    pub credential: String,
}

/// `POST /api/auth/invite/redeem {invite_code, credential}` — public.
///
/// Burns the invite and creates an ACTIVE anonymous-kind account: no OAuth,
/// key login, the invite's nick, `paid_until` extended by the invite's days.
/// Answers like `POST /api/auth/account-key` (see [`open_session`]).
///
/// A malformed, unknown, used, revoked or expired code all get the same
/// `401 {"error":"invalid invite code"}` and count against the caller's
/// address in the same per-IP failure throttle as key sign-in (`429
/// rate_limited` once it is used up). Other errors: `400 invalid_credential`,
/// `409 credential_in_use`, `409 nick_unavailable` (an account took the nick
/// since the invite was issued; the code stays valid).
pub async fn redeem_invite(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Json(body): Json<RedeemBody>,
) -> Response {
    let Some(billing) = state.billing() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "billing_not_configured");
    };
    let ip = caller_ip(&headers, peer);
    let failures = billing.key_failure_limiter();
    if failures.is_blocked(ip, Instant::now()) {
        return rate_limited(failures);
    }
    let Some(credential) = Credential::parse(&body.credential) else {
        return invalid_credential();
    };
    let code = body.invite_code;
    let db_state = state.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let conn = db_state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        invite::redeem(&conn, &code, &credential, chrono::Utc::now())
    })
    .await;
    match outcome {
        Ok(Ok(Ok(redeemed))) => {
            tracing::info!("registration invite redeemed: new anonymous account {}", redeemed.user_id);
            open_session(state, &headers, redeemed.user_id).await
        }
        Ok(Ok(Err(RedeemRefusal::InvalidCode))) => {
            failures.record(ip, Instant::now());
            invalid_invite()
        }
        Ok(Ok(Err(RedeemRefusal::NickUnavailable))) => error(StatusCode::CONFLICT, "nick_unavailable"),
        Ok(Ok(Err(RedeemRefusal::CredentialInUse))) => error(StatusCode::CONFLICT, "credential_in_use"),
        Ok(Err(e)) => {
            tracing::error!("invite redemption failed: {e}");
            error(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
        }
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::plans::{DEFAULT_ANON_TOR_ID, DEFAULT_PAID_TOR_ID};
    use crate::billing::testkit::{capture_logs, captured_logs};
    use crate::routes::billing::tests::{
        app_state, deliver_ok, get_json, one_time_settlement, post_json, runtime, runtime_with, send_from, sign_in,
        spawn_merchant, ONION_HOST,
    };
    use crate::routes::control_api_router;
    use crate::social_db::Role;
    use axum::http::Method;
    use axum::Router;
    use chrono::Utc;
    use serde_json::Value;

    const CLEARNET: &str = "mylittlechart.org";
    const ANON: &str = "mlc-anon-account-v1";
    const IP_A: [u8; 4] = [203, 0, 113, 1];
    const IP_B: [u8; 4] = [203, 0, 113, 2];

    /// A client-derived credential, as the wire carries it.
    fn fresh() -> String {
        Credential::random().to_hex()
    }

    async fn checkout_from(router: &Router, ip: [u8; 4], plan: &str, host: &str, credential: &str) -> (StatusCode, HeaderMap, Value) {
        send_from(
            router,
            ip,
            Method::POST,
            "/billing/anon-checkout",
            &[("content-type", "application/json"), ("host", host)],
            Some(json!({ "plan_id": plan, "credential": credential }).to_string()),
        )
        .await
    }

    async fn key_sign_in(router: &Router, ip: [u8; 4], credential: &str) -> (StatusCode, HeaderMap, Value) {
        send_from(
            router,
            ip,
            Method::POST,
            "/auth/account-key",
            &[("content-type", "application/json")],
            Some(json!({ "credential": credential }).to_string()),
        )
        .await
    }

    async fn invoice_with_key(router: &Router, ip: [u8; 4], credential: &str, invoice: &str) -> (StatusCode, HeaderMap, Value) {
        let authorization = format!("AccountKey {credential}");
        send_from(
            router,
            ip,
            Method::GET,
            &format!("/billing/anon-invoice/{invoice}"),
            &[("authorization", authorization.as_str())],
            None,
        )
        .await
    }

    async fn rotate_to(router: &Router, ip: [u8; 4], session_cookie: &str, credential: &str) -> (StatusCode, HeaderMap, Value) {
        send_from(
            router,
            ip,
            Method::POST,
            "/account/key/rotate",
            &[("cookie", session_cookie), ("content-type", "application/json")],
            Some(json!({ "credential": credential }).to_string()),
        )
        .await
    }

    fn account_of(state: &Arc<AppState>, credential: &str) -> AnonAccount {
        let parsed = Credential::parse(credential).expect("a well-formed credential");
        let conn = state.control_plane().db.lock().expect("db");
        anon::find_by_key(&conn, &parsed).expect("lookup").expect("the account exists")
    }

    fn count(state: &Arc<AppState>, sql: &str) -> i64 {
        state.control_plane().db.lock().expect("db").query_row(sql, [], |r| r.get(0)).expect("count")
    }

    fn session_cookie_of(answer: &Value) -> String {
        format!("session_id={}", answer["session_id"].as_str().expect("session id"))
    }

    /// Buy an anonymous account and settle it; returns `(credential, user id)`.
    async fn paid_account(router: &Router, state: &Arc<AppState>, ip: [u8; 4], n: u32) -> (String, i64) {
        let credential = fresh();
        let (status, _, answer) = checkout_from(router, ip, ANON, CLEARNET, &credential).await;
        assert_eq!(status, StatusCode::CREATED, "{answer}");
        let user_id = account_of(state, &credential).user_id;
        let invoice = answer["invoice_id"].as_str().expect("invoice").to_string();
        let sub = invoice.replace("grp_", "sub_");
        deliver_ok(router, &one_time_settlement(&format!("paid-{n}"), user_id, ANON, &sub, &invoice)).await;
        (credential, user_id)
    }

    // ------------------------------------------------------------- the flow

    #[tokio::test]
    async fn the_whole_flow_checkout_pending_webhook_active_sign_in_rotate_old_credential_dead() {
        capture_logs();
        let (base, merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let router = control_api_router(state.clone());

        // -- checkout: a PENDING account and its invoice; no key in the answer.
        let credential = fresh();
        let (status, _, answer) = checkout_from(&router, IP_A, ANON, CLEARNET, &credential).await;
        assert_eq!(status, StatusCode::CREATED, "{answer}");
        assert_eq!(answer["invoice_id"], "grp_1");
        assert_eq!(answer["pay"].as_array().map(Vec::len), Some(2), "pay[] as the processor issued it");
        assert_eq!(answer.as_object().map(|o| o.len()), Some(2), "exactly {{invoice_id, pay}}: the server hands back no key");
        let account = account_of(&state, &credential);
        assert_eq!(account.status, AccountStatus::Pending);
        {
            let mock = merchant.lock().expect("mock");
            let subscribers: Vec<_> = mock.calls.iter().filter(|c| c.path == "/subscribers").collect();
            assert_eq!(subscribers.len(), 1);
            assert_eq!(subscribers[0].body["external_user_ref"], account.user_id.to_string(), "the reference IS the new user id");
            let subscriptions: Vec<_> = mock.calls.iter().filter(|c| c.path == "/subscriptions").collect();
            assert_eq!(subscriptions[0].body["plan_id"], ANON);
        }
        {
            // Only the hash is stored, and the account has no email and no OAuth link.
            let conn = state.control_plane().db.lock().expect("db");
            let stored: String = conn
                .query_row("SELECT key_hash FROM billing_anon_accounts WHERE user_id = ?1", [account.user_id], |r| r.get(0))
                .expect("hash");
            assert_eq!(stored, Credential::parse(&credential).expect("parse").hash_hex());
            assert_ne!(stored, credential);
            let (provider, name): (String, String) = conn
                .query_row("SELECT provider, display_name FROM users WHERE id = ?1", [account.user_id], |r| Ok((r.get(0)?, r.get(1)?)))
                .expect("user");
            assert_eq!((provider.as_str(), name.as_str()), ("anon", ""));
            let links: i64 = conn
                .query_row("SELECT COUNT(*) FROM user_providers WHERE user_id = ?1 AND (provider != 'anon' OR email IS NOT NULL)", [account.user_id], |r| r.get(0))
                .expect("links");
            assert_eq!(links, 0);
        }

        // -- before payment: no session, but the credential reads its own invoice only.
        let (status, _, refusal) = key_sign_in(&router, IP_A, &credential).await;
        assert_eq!((status, refusal["error"].as_str()), (StatusCode::UNAUTHORIZED, Some("invalid account key")));
        let (status, _, invoice) = invoice_with_key(&router, IP_A, &credential, "grp_1").await;
        assert_eq!(status, StatusCode::OK, "{invoice}");
        assert_eq!((invoice["invoice_id"].as_str(), invoice["grant_state"].as_str()), (Some("grp_1"), Some("none")));
        let (status, _, _) = invoice_with_key(&router, IP_A, &"0".repeat(64), "grp_1").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let other = fresh();
        let (status, _, _) = checkout_from(&router, IP_B, ANON, CLEARNET, &other).await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, _, stranger) = invoice_with_key(&router, IP_B, &other, "grp_1").await;
        assert_eq!((status, stranger["error"].as_str()), (StatusCode::NOT_FOUND, Some("not_found")), "another account's credential cannot read it");

        // -- the webhook: payment_confirmed activates it with both grants, sourced from the invoice.
        let settled = one_time_settlement("anon-1", account.user_id, ANON, "sub_1", "grp_1");
        assert_eq!(deliver_ok(&router, &settled).await["outcome"], "granted");
        assert_eq!(account_of(&state, &credential).status, AccountStatus::Active);
        {
            let conn = state.control_plane().db.lock().expect("db");
            let rows = crate::billing::grants::list(&conn, account.user_id).expect("grants");
            let mut kinds: Vec<_> = rows.iter().map(|g| (g.grant.as_str().to_string(), g.source.clone(), g.source_ref.clone())).collect();
            kinds.sort();
            assert_eq!(
                kinds,
                vec![
                    ("lifetime_anon".to_string(), "invoice".to_string(), "grp_1".to_string()),
                    ("lifetime_paid".to_string(), "invoice".to_string(), "grp_1".to_string()),
                ]
            );
        }

        // -- sign in: an ordinary session, in the shape the other sign-ins return.
        let (status, headers, session) = key_sign_in(&router, IP_A, &credential.to_uppercase()).await;
        assert_eq!(status, StatusCode::OK, "{session}");
        assert_eq!(session["status"], "confirmed");
        assert_eq!(session["user_id"], account.user_id);
        assert!(session["public_id"].as_str().is_some_and(|p| !p.is_empty()));
        let session_id = session["session_id"].as_str().expect("session id").to_string();
        let cookie = headers.get(header::SET_COOKIE).and_then(|v| v.to_str().ok()).expect("cookie").to_string();
        assert!(cookie.starts_with(&format!("session_id={session_id};")) && cookie.contains("HttpOnly") && cookie.contains("Secure"));
        let session_cookie = format!("session_id={session_id}");
        let (status, _, me) = send_from(&router, IP_A, Method::GET, "/billing/me", &[("cookie", session_cookie.as_str())], None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!((me["lifetime_anon"].as_bool(), me["lifetime_paid"].as_bool(), me["paid"].as_bool()), (Some(true), Some(true), Some(true)));

        // -- rotate: the client sends the credential of its NEW secret; the old one is dead.
        let new_credential = fresh();
        let (status, _, rotated) = rotate_to(&router, IP_A, &session_cookie, &new_credential).await;
        assert_eq!((status, rotated), (StatusCode::OK, json!({ "rotated": true })));
        let (status, _, _) = key_sign_in(&router, IP_A, &credential).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "the old credential is dead");
        let (status, _, _) = invoice_with_key(&router, IP_A, &credential, "grp_1").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "and reads nothing");
        let (status, _, again) = key_sign_in(&router, IP_A, &new_credential).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(again["user_id"], account.user_id);

        // -- no credential ever reached a log line.
        let logs = captured_logs();
        assert!(!logs.is_empty(), "the capture is live");
        for secret in [&credential, &other, &new_credential] {
            assert!(!logs.contains(secret.as_str()) && !logs.contains(&secret.to_uppercase()), "a credential was logged");
        }
        assert!(!logs.contains(&session_id), "nor a session id");
    }

    #[tokio::test]
    async fn rotation_needs_a_session_an_anonymous_account_and_a_usable_credential() {
        let (base, _merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let router = control_api_router(state.clone());
        let body = json!({ "credential": fresh() });
        let (status, _, _) = send_from(&router, IP_A, Method::POST, "/account/key/rotate", &[("content-type", "application/json")], Some(body.to_string())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (_, oauth_token) = sign_in(&state, "oauth-user");
        let (status, answer) = post_json(&router, &oauth_token, "/account/key/rotate", body, None).await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::FORBIDDEN, Some("not_an_anonymous_account")));

        // A malformed credential is a 400 and changes nothing.
        let (credential, _) = paid_account(&router, &state, IP_B, 1).await;
        let (_, _, session) = key_sign_in(&router, IP_B, &credential).await;
        let cookie = session_cookie_of(&session);
        for bad in ["", "hello", &credential[..63], &format!("{credential}0"), "0F4Z-ABCD-EFGH-JKMN-PQRS-TV"] {
            let (status, _, answer) = rotate_to(&router, IP_B, &cookie, bad).await;
            assert_eq!((status, answer["error"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid_credential")), "{bad:?}");
        }
        let (status, _, _) = key_sign_in(&router, IP_B, &credential).await;
        assert_eq!(status, StatusCode::OK, "the credential is unchanged");

        // A credential another account holds is a 409 and changes nothing.
        let (other, _) = paid_account(&router, &state, IP_A, 2).await;
        let (status, _, answer) = rotate_to(&router, IP_B, &cookie, &other).await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::CONFLICT, Some("credential_in_use")));
        let (status, _, _) = key_sign_in(&router, IP_B, &credential).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_malformed_credential_is_a_400_at_checkout_and_costs_nothing() {
        let (base, merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let router = control_api_router(state.clone());
        let good = fresh();
        for bad in [
            String::new(),
            "hello".to_string(),
            good[..63].to_string(),
            format!("{good}0"),
            format!("{}g", &good[..63]),
            // The retired 128-bit Crockford key format.
            "0F4Z-ABCD-EFGH-JKMN-PQRS-TV".to_string(),
        ] {
            let (status, _, answer) = checkout_from(&router, IP_A, ANON, CLEARNET, &bad).await;
            assert_eq!((status, answer["error"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid_credential")), "{bad:?}");
        }
        // No field at all is the same refusal, not a parse error.
        let (status, _, answer) = send_from(
            &router,
            IP_A,
            Method::POST,
            "/billing/anon-checkout",
            &[("content-type", "application/json"), ("host", CLEARNET)],
            Some(json!({ "plan_id": ANON, "account_key": "whatever" }).to_string()),
        )
        .await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid_credential")));
        assert_eq!(count(&state, "SELECT COUNT(*) FROM billing_anon_accounts"), 0);
        assert!(merchant.lock().expect("mock").calls.is_empty());
        // Refusals spent no budget: five real checkouts still fit.
        for n in 1..=5 {
            let (status, _, _) = checkout_from(&router, IP_A, ANON, CLEARNET, &fresh()).await;
            assert_eq!(status, StatusCode::CREATED, "checkout {n}");
        }
    }

    #[tokio::test]
    async fn a_credential_another_account_holds_is_a_409_at_checkout_and_the_old_key_format_never_signs_in() {
        let (base, _merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let router = control_api_router(state.clone());
        let (credential, _) = paid_account(&router, &state, IP_A, 1).await;
        let (status, _, answer) = checkout_from(&router, IP_B, ANON, CLEARNET, &credential).await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::CONFLICT, Some("credential_in_use")));
        assert_eq!(count(&state, "SELECT COUNT(*) FROM billing_anon_accounts"), 1, "no second account");

        // An old-format key (or the old request field) is refused like any unknown secret.
        let (status, _, answer) = key_sign_in(&router, IP_B, "0F4Z-ABCD-EFGH-JKMN-PQRS-TV").await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::UNAUTHORIZED, Some("invalid account key")));
        let (status, _, answer) = send_from(
            &router,
            IP_B,
            Method::POST,
            "/auth/account-key",
            &[("content-type", "application/json")],
            Some(json!({ "account_key": "0F4Z-ABCD-EFGH-JKMN-PQRS-TV" }).to_string()),
        )
        .await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::UNAUTHORIZED, Some("invalid account key")));
    }

    // ------------------------------------------------------------ the rules

    #[tokio::test]
    async fn only_anonymous_account_plans_and_on_the_onion_host_only_the_tor_one() {
        let (base, merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let router = control_api_router(state.clone());

        for (plan, host) in [
            ("mlc-paid-account-v1", CLEARNET),
            (DEFAULT_PAID_TOR_ID, ONION_HOST),
            ("mlc-monthly-20-v1", CLEARNET),
            ("mlc-no-such-plan", CLEARNET),
            (DEFAULT_ANON_TOR_ID, CLEARNET),
            (ANON, ONION_HOST),
        ] {
            let (status, _, answer) = checkout_from(&router, IP_A, plan, host, &fresh()).await;
            assert_eq!((status, answer["error"].as_str()), (StatusCode::BAD_REQUEST, Some("plan_not_available")), "{plan} via {host}");
        }
        assert_eq!(count(&state, "SELECT COUNT(*) FROM billing_anon_accounts"), 0, "refusals create nothing");
        assert!(merchant.lock().expect("mock").calls.is_empty(), "and never reach the processor");

        let (status, _, _) = checkout_from(&router, IP_A, ANON, CLEARNET, &fresh()).await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, _, _) = checkout_from(&router, IP_A, DEFAULT_ANON_TOR_ID, ONION_HOST, &fresh()).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM billing_anon_accounts WHERE status = 'pending'"), 2);
    }

    #[tokio::test]
    async fn the_signed_in_checkout_does_not_sell_an_anonymous_account() {
        let (base, merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let (_, token) = sign_in(&state, "oauth-buyer");
        let router = control_api_router(state);
        let (status, answer) = post_json(&router, &token, "/billing/checkout", json!({ "plan_id": ANON }), None).await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::BAD_REQUEST, Some("anonymous_only")));
        assert!(merchant.lock().expect("mock").calls.is_empty());
    }

    #[tokio::test]
    async fn without_a_merchant_api_the_checkout_answers_503_and_creates_nothing() {
        let state = app_state(Some(runtime(None)));
        let router = control_api_router(state.clone());
        let (status, _, answer) = checkout_from(&router, IP_A, ANON, CLEARNET, &fresh()).await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("billing_not_configured")));
        let bare = control_api_router(app_state(None));
        let (status, _, _) = checkout_from(&bare, IP_A, ANON, CLEARNET, &fresh()).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM billing_anon_accounts"), 0);
    }

    #[tokio::test]
    async fn a_checkout_the_processor_refuses_leaves_no_account_behind_and_can_be_retried_with_the_same_credential() {
        let (base, merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let router = control_api_router(state.clone());
        let users_before = count(&state, "SELECT COUNT(*) FROM users");
        let credential = fresh();

        merchant.lock().expect("mock").fail_next_subscription = true;
        let (status, _, answer) = checkout_from(&router, IP_A, ANON, CLEARNET, &credential).await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::BAD_GATEWAY, Some("payment_gateway_unavailable")));
        merchant.lock().expect("mock").unknown_plans.insert(ANON.to_string());
        let (status, _, answer) = checkout_from(&router, IP_A, ANON, CLEARNET, &credential).await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("plan_unavailable")));
        assert_eq!(count(&state, "SELECT COUNT(*) FROM users"), users_before, "both pending accounts were rolled back");
        assert_eq!(count(&state, "SELECT COUNT(*) FROM billing_anon_accounts"), 0);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM billing_subscriptions"), 0);

        merchant.lock().expect("mock").unknown_plans.clear();
        let (status, _, _) = checkout_from(&router, IP_A, ANON, CLEARNET, &credential).await;
        assert_eq!(status, StatusCode::CREATED, "the rolled-back credential is free again");
    }

    // ----------------------------------------------------------- rate limits

    #[tokio::test]
    async fn five_checkouts_per_ip_per_hour_and_a_bad_plan_costs_nothing() {
        let (base, merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let router = control_api_router(state.clone());

        for _ in 0..10 {
            let (status, _, _) = checkout_from(&router, IP_A, "mlc-paid-account-v1", CLEARNET, &fresh()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        for n in 1..=5 {
            let (status, _, answer) = checkout_from(&router, IP_A, ANON, CLEARNET, &fresh()).await;
            assert_eq!(status, StatusCode::CREATED, "checkout {n}: {answer}");
        }
        let (status, headers, answer) = checkout_from(&router, IP_A, ANON, CLEARNET, &fresh()).await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")));
        assert_eq!(headers.get(header::RETRY_AFTER).and_then(|v| v.to_str().ok()), Some("3600"));
        assert_eq!(merchant.lock().expect("mock").created, 5, "the sixth reached nothing");
        assert_eq!(count(&state, "SELECT COUNT(*) FROM billing_anon_accounts"), 5);

        let (status, _, _) = checkout_from(&router, IP_B, ANON, CLEARNET, &fresh()).await;
        assert_eq!(status, StatusCode::CREATED, "another address has its own budget");
    }

    #[tokio::test]
    async fn a_global_cap_binds_across_addresses() {
        let (base, merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime_with(Some(&base), &[("MLC_BILLING_ANON_GLOBAL_PER_HOUR", "3")])));
        let router = control_api_router(state);
        for last in 1..=3u8 {
            let (status, _, _) = checkout_from(&router, [203, 0, 113, last], ANON, CLEARNET, &fresh()).await;
            assert_eq!(status, StatusCode::CREATED, "address {last}");
        }
        let (status, _, answer) = checkout_from(&router, [203, 0, 113, 4], ANON, CLEARNET, &fresh()).await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")));
        assert_eq!(merchant.lock().expect("mock").created, 3);
    }

    #[tokio::test]
    async fn failed_credentials_are_throttled_per_address_and_every_refusal_looks_the_same() {
        capture_logs();
        let (base, _merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime_with(Some(&base), &[("MLC_BILLING_KEY_FAILS_PER_IP_PER_HOUR", "3")])));
        let router = control_api_router(state.clone());
        let (good, _) = paid_account(&router, &state, IP_B, 1).await;
        // A still-pending credential, an unknown well-formed one, and garbage.
        let pending = fresh();
        checkout_from(&router, IP_B, ANON, CLEARNET, &pending).await;
        let unknown = fresh();

        let mut refusals = Vec::new();
        for attempt in [pending.as_str(), unknown.as_str(), "not a key at all"] {
            refusals.push(key_sign_in(&router, IP_A, attempt).await);
        }
        for (status, headers, body) in &refusals {
            assert_eq!(*status, StatusCode::UNAUTHORIZED);
            assert_eq!(body, &refusals[0].2, "the same body for malformed, unknown and pending");
            assert!(headers.get(header::SET_COOKIE).is_none());
        }
        assert_eq!(refusals[0].2, json!({ "error": "invalid account key" }));

        // The address has now spent its three failures: even the right credential is refused.
        let (status, headers, blocked) = key_sign_in(&router, IP_A, &good).await;
        assert_eq!((status, blocked["error"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")));
        assert!(headers.get(header::SET_COOKIE).is_none());
        let (status, _, _) = invoice_with_key(&router, IP_A, &good, "grp_1").await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "the invoice read shares the throttle");
        // Another address is untouched.
        let (status, _, _) = key_sign_in(&router, IP_B, &good).await;
        assert_eq!(status, StatusCode::OK);

        let logs = captured_logs();
        for secret in [&good, &pending, &unknown] {
            assert!(!logs.contains(secret.as_str()), "a credential was logged");
        }
    }

    // ------------------------------------------------------------------- GC

    #[tokio::test]
    async fn an_unpaid_account_is_collected_a_day_after_its_invoice_expired_and_a_late_payment_is_unmatched() {
        let (base, _merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let router = control_api_router(state.clone());
        let credential = fresh();
        checkout_from(&router, IP_A, ANON, CLEARNET, &credential).await;
        let user_id = account_of(&state, &credential).user_id;

        // The invoice expires more than a day ago.
        let long_ago = (Utc::now() - chrono::Duration::hours(30)).to_rfc3339();
        state
            .control_plane()
            .db
            .lock()
            .expect("db")
            .execute("UPDATE billing_invoices SET expires_at = ?1", [long_ago.as_str()])
            .expect("age the invoice");
        let report = {
            let cp = state.control_plane();
            let conn = cp.db.lock().expect("db");
            let mut messenger = cp.messenger_conn();
            anon::gc_pending(&conn, &mut messenger, &cp.live, Utc::now()).expect("gc")
        };
        assert_eq!(report.deleted, 1);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM users WHERE provider = 'anon'"), 0);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM billing_subscriptions"), 0);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM billing_subscribers"), 0);
        let (status, _, _) = key_sign_in(&router, IP_B, &credential).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "the credential is gone with its account");

        // The payment shows up anyway: recorded, no crash, no grant, no account.
        let late = one_time_settlement("late-1", user_id, ANON, "sub_1", "grp_1");
        assert_eq!(deliver_ok(&router, &late).await["outcome"], "unmatched");
        assert_eq!(count(&state, "SELECT COUNT(*) FROM billing_grants"), 0);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM billing_events WHERE outcome = 'unmatched'"), 1);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM users WHERE provider = 'anon'"), 0);
    }

    #[tokio::test]
    async fn a_paid_account_is_never_collected() {
        let (base, _merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let router = control_api_router(state.clone());
        let (credential, _) = paid_account(&router, &state, IP_A, 1).await;
        let long_ago = (Utc::now() - chrono::Duration::days(90)).to_rfc3339();
        state.control_plane().db.lock().expect("db").execute("UPDATE billing_invoices SET expires_at = ?1", [long_ago.as_str()]).expect("age");
        let report = {
            let cp = state.control_plane();
            let conn = cp.db.lock().expect("db");
            let mut messenger = cp.messenger_conn();
            anon::gc_pending(&conn, &mut messenger, &cp.live, Utc::now()).expect("gc")
        };
        assert_eq!(report.deleted, 0);
        let (status, _, _) = key_sign_in(&router, IP_B, &credential).await;
        assert_eq!(status, StatusCode::OK);
    }

    // -------------------------------------------------- registration invites

    /// A signed-in admin with a nick; returns its bearer token.
    fn admin_token(state: &Arc<AppState>) -> String {
        let (uid, token) = sign_in(state, "rootadmin");
        {
            let conn = state.control_plane().db.lock().expect("db");
            crate::db::admin_set_nick(&conn, uid, "rootadmin").expect("nick");
        }
        let social = state.control_plane().social_conn();
        crate::social_db::set_role(&social, uid, Role::Admin, &Utc::now().to_rfc3339()).expect("role");
        token
    }

    async fn issue_invite(router: &Router, token: &str, body: Value) -> (StatusCode, Value) {
        post_json(router, token, "/staff/invites", body, None).await
    }

    async fn redeem_from(router: &Router, ip: [u8; 4], code: &str, credential: &str) -> (StatusCode, HeaderMap, Value) {
        send_from(
            router,
            ip,
            Method::POST,
            "/auth/invite/redeem",
            &[("content-type", "application/json")],
            Some(json!({ "invite_code": code, "credential": credential }).to_string()),
        )
        .await
    }

    fn paid_until_of(state: &Arc<AppState>, user_id: i64) -> Option<String> {
        state
            .control_plane()
            .db
            .lock()
            .expect("db")
            .query_row("SELECT paid_until FROM users WHERE id = ?1", [user_id], |r| r.get(0))
            .expect("paid_until")
    }

    #[tokio::test]
    async fn the_invite_lifecycle_issue_list_redeem_sign_in_rotate() {
        capture_logs();
        let state = app_state(Some(runtime(None)));
        let router = control_api_router(state.clone());
        let admin = admin_token(&state);

        // -- issue: 201, the code comes back once, with the fields documented.
        let (status, issued) = issue_invite(&router, &admin, json!({ "nick": "nix", "paid_days": 365, "note": "early friend" })).await;
        assert_eq!(status, StatusCode::CREATED, "{issued}");
        let code = issued["invite_code"].as_str().expect("code").to_string();
        let invite_id = issued["id"].as_str().expect("id").to_string();
        assert!(invite_id.starts_with("inv_"));
        assert_eq!(code.len(), 24, "20 characters in groups of four");
        assert_eq!((issued["nick"].as_str(), issued["paid_days"].as_i64(), issued["note"].as_str()), (Some("nix"), Some(365), Some("early friend")));
        assert!(issued["expires_at"].is_string());
        assert_eq!(issued.as_object().map(|o| o.len()), Some(6));

        // -- list: pending, no code anywhere.
        let (status, list) = get_json(&router, &admin, "/staff/invites", None).await;
        assert_eq!(status, StatusCode::OK);
        let rows = list.as_array().expect("array");
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0]["id"].as_str(), rows[0]["nick"].as_str(), rows[0]["status"].as_str()), (Some(invite_id.as_str()), Some("nix"), Some("pending")));
        assert_eq!((rows[0]["paid_days"].as_i64(), rows[0]["created_by_nick"].as_str()), (Some(365), Some("rootadmin")));
        assert_eq!(rows[0].as_object().map(|o| o.len()), Some(10), "exactly the documented fields");
        assert!(!list.to_string().contains(&code.replace('-', "")) && !list.to_string().contains(&code));
        // At rest: a digest of the normalized code, not the code.
        assert_eq!(count(&state, "SELECT COUNT(*) FROM registration_invites WHERE LENGTH(code_hash) = 64"), 1);
        assert_eq!(count(&state, &format!("SELECT COUNT(*) FROM registration_invites WHERE code_hash LIKE '%{}%'", code.replace('-', ""))), 0);

        // -- redeem (case and hyphens forgiven): an active anonymous account and a session.
        let credential = fresh();
        let typed = code.to_lowercase().replace('-', " ");
        let (status, headers, session) = redeem_from(&router, IP_A, &typed, &credential).await;
        assert_eq!(status, StatusCode::OK, "{session}");
        assert_eq!(session["status"], "confirmed");
        assert!(session["public_id"].as_str().is_some_and(|p| !p.is_empty()));
        let user_id = session["user_id"].as_i64().expect("user id");
        let cookie = headers.get(header::SET_COOKIE).and_then(|v| v.to_str().ok()).expect("cookie");
        assert!(cookie.starts_with("session_id=") && cookie.contains("HttpOnly") && cookie.contains("Secure"));
        {
            let conn = state.control_plane().db.lock().expect("db");
            let (provider, nick): (String, Option<String>) = conn
                .query_row("SELECT provider, nick FROM users WHERE id = ?1", [user_id], |r| Ok((r.get(0)?, r.get(1)?)))
                .expect("user");
            assert_eq!((provider.as_str(), nick.as_deref()), ("anon", Some("nix")));
            let links: i64 = conn
                .query_row("SELECT COUNT(*) FROM user_providers WHERE user_id = ?1 AND (provider != 'anon' OR email IS NOT NULL)", [user_id], |r| r.get(0))
                .expect("links");
            assert_eq!(links, 0, "no OAuth identity");
            let (stored, status): (String, String) = conn
                .query_row("SELECT key_hash, status FROM billing_anon_accounts WHERE user_id = ?1", [user_id], |r| Ok((r.get(0)?, r.get(1)?)))
                .expect("anon row");
            assert_eq!((stored, status.as_str()), (Credential::parse(&credential).expect("parse").hash_hex(), "active"));
        }
        let (_, list) = get_json(&router, &admin, "/staff/invites", None).await;
        assert_eq!(list[0]["status"], "redeemed");
        assert!(list[0]["redeemed_at"].is_string());

        // -- the account is an ordinary key account: sign in by the credential, rotate it.
        let (status, _, again) = key_sign_in(&router, IP_A, &credential).await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(again["user_id"], user_id);
        let session_cookie = session_cookie_of(&again);
        let new_credential = fresh();
        let (status, _, rotated) = rotate_to(&router, IP_A, &session_cookie, &new_credential).await;
        assert_eq!((status, rotated), (StatusCode::OK, json!({ "rotated": true })));
        let (status, _, _) = key_sign_in(&router, IP_A, &credential).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "the old credential is dead");
        let (status, _, third) = key_sign_in(&router, IP_A, &new_credential).await;
        assert_eq!((status, &third["user_id"]), (StatusCode::OK, &json!(user_id)));

        // -- the audit trail names the actions and never the code.
        let actions: Vec<String> = {
            let conn = state.control_plane().db.lock().expect("db");
            let mut stmt = conn.prepare("SELECT action FROM staff_audit ORDER BY id").expect("prepare");
            stmt.query_map([], |r| r.get(0)).expect("query").collect::<Result<_, _>>().expect("rows")
        };
        assert_eq!(actions, vec!["invites.issue", "invites.list", "invites.list"]);
        let audit_text = format!("{:?}", crate::staff::all(&state.control_plane().db.lock().expect("db")).expect("audit"));
        assert!(!audit_text.contains(&code.replace('-', "")) && !audit_text.contains(&code), "the code is not in the audit trail");

        // -- and never in a log line.
        let logs = captured_logs();
        assert!(!logs.is_empty(), "the capture is live");
        let plain = code.replace('-', "");
        for form in [code.clone(), plain.clone(), code.to_lowercase(), plain.to_lowercase(), credential.clone(), new_credential.clone()] {
            assert!(!logs.contains(&form), "a secret was logged");
        }
    }

    #[tokio::test]
    async fn a_revoked_used_expired_or_unknown_code_gets_the_same_401() {
        let state = app_state(Some(runtime(None)));
        let router = control_api_router(state.clone());
        let admin = admin_token(&state);
        let (_, used) = issue_invite(&router, &admin, json!({ "nick": "usedone" })).await;
        let (_, revoked) = issue_invite(&router, &admin, json!({ "nick": "revokedone" })).await;
        let (_, expired) = issue_invite(&router, &admin, json!({ "nick": "expiredone" })).await;
        let (_, live) = issue_invite(&router, &admin, json!({ "nick": "liveone" })).await;
        let code = |v: &Value| v["invite_code"].as_str().expect("code").to_string();

        let (status, _, _) = redeem_from(&router, IP_B, &code(&used), &fresh()).await;
        assert_eq!(status, StatusCode::OK);
        let revoke_uri = format!("/staff/invites/{}/revoke", revoked["id"].as_str().expect("id"));
        let (status, answer) = post_json(&router, &admin, &revoke_uri, json!({}), None).await;
        assert_eq!((status, answer["revoked"].as_bool()), (StatusCode::OK, Some(true)));
        let (status, answer) = post_json(&router, &admin, &revoke_uri, json!({}), None).await;
        assert_eq!((status, answer["revoked"].as_bool()), (StatusCode::OK, Some(false)), "a repeat revoke is harmless");
        state
            .control_plane()
            .db
            .lock()
            .expect("db")
            .execute(
                "UPDATE registration_invites SET expires_at = ?2 WHERE id = ?1",
                rusqlite::params![expired["id"].as_str().expect("id"), (Utc::now() - chrono::Duration::days(1)).to_rfc3339()],
            )
            .expect("age the invite");

        let mut refusals = Vec::new();
        for attempt in [code(&used), code(&revoked), code(&expired), "ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ".to_string(), "junk".to_string(), String::new()] {
            refusals.push(redeem_from(&router, IP_A, &attempt, &fresh()).await);
        }
        for (status, headers, body) in &refusals {
            assert_eq!(*status, StatusCode::UNAUTHORIZED);
            assert_eq!(body, &json!({ "error": "invalid invite code" }), "used, revoked, expired, unknown and malformed look alike");
            assert!(headers.get(header::SET_COOKIE).is_none());
        }
        // Nothing was created by the refusals; the live code still works.
        assert_eq!(count(&state, "SELECT COUNT(*) FROM users WHERE provider = 'anon'"), 1);
        let (status, _, _) = redeem_from(&router, IP_B, &code(&live), &fresh()).await;
        assert_eq!(status, StatusCode::OK);

        // A redeemed invite cannot be revoked; an unknown one is a 404.
        let used_uri = format!("/staff/invites/{}/revoke", used["id"].as_str().expect("id"));
        let (status, answer) = post_json(&router, &admin, &used_uri, json!({}), None).await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::CONFLICT, Some("already redeemed")));
        let (status, _) = post_json(&router, &admin, "/staff/invites/inv_nope/revoke", json!({}), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (_, list) = get_json(&router, &admin, "/staff/invites", None).await;
        let statuses: Vec<(&str, &str)> = list
            .as_array()
            .expect("array")
            .iter()
            .map(|r| (r["nick"].as_str().expect("nick"), r["status"].as_str().expect("status")))
            .collect();
        assert!(statuses.contains(&("usedone", "redeemed")));
        assert!(statuses.contains(&("revokedone", "revoked")));
        assert!(statuses.contains(&("expiredone", "expired")));
        assert!(statuses.contains(&("liveone", "redeemed")));
    }

    #[tokio::test]
    async fn staff_may_assign_a_reserved_nick_and_a_pending_invite_holds_its_nick() {
        let state = app_state(Some(runtime(None)));
        let router = control_api_router(state.clone());
        let admin = admin_token(&state);
        let (other_id, _) = sign_in(&state, "someone-else");
        {
            let conn = state.control_plane().db.lock().expect("db");
            crate::db::upsert_reserved_nick(&conn, "nix", "project", Some("held for a friend")).expect("reserve");
            // Self-service cannot take a reserved nick ...
            assert!(matches!(
                crate::db::set_nick(&conn, other_id, "nix", &[]),
                Err(crate::db::NickError::Reserved)
            ));
        }
        // ... the invite can carry it.
        let (status, issued) = issue_invite(&router, &admin, json!({ "nick": "Nix", "paid_days": 0 })).await;
        assert_eq!(status, StatusCode::CREATED, "{issued}");
        let (status, answer) = issue_invite(&router, &admin, json!({ "nick": "nix" })).await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::CONFLICT, Some("nick taken")), "one pending invite per nick");

        // A pending invite holds an ordinary nick against self-service too.
        let (status, held) = issue_invite(&router, &admin, json!({ "nick": "heldname" })).await;
        assert_eq!(status, StatusCode::CREATED);
        {
            let conn = state.control_plane().db.lock().expect("db");
            assert!(matches!(
                crate::db::set_nick(&conn, other_id, "heldname", &[]),
                Err(crate::db::NickError::Reserved)
            ));
        }
        let revoke_uri = format!("/staff/invites/{}/revoke", held["id"].as_str().expect("id"));
        post_json(&router, &admin, &revoke_uri, json!({}), None).await;
        {
            let conn = state.control_plane().db.lock().expect("db");
            crate::db::set_nick(&conn, other_id, "heldname", &[]).expect("a revoked invite releases its nick");
        }
        let (status, answer) = issue_invite(&router, &admin, json!({ "nick": "heldname" })).await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::CONFLICT, Some("nick taken")), "now an account holds it");

        // Redeem: the account gets the reserved nick and the registry row points at it.
        let (status, _, session) = redeem_from(&router, IP_A, issued["invite_code"].as_str().expect("code"), &fresh()).await;
        assert_eq!(status, StatusCode::OK, "{session}");
        let user_id = session["user_id"].as_i64().expect("user id");
        let conn = state.control_plane().db.lock().expect("db");
        assert_eq!(crate::db::nick_for_user(&conn, user_id).expect("nick").as_deref(), Some("Nix"));
        let granted: Option<i64> = conn
            .query_row("SELECT granted_to FROM reserved_nicks WHERE nick_lower = 'nix'", [], |r| r.get(0))
            .expect("registry row");
        assert_eq!(granted, Some(user_id));
    }

    #[tokio::test]
    async fn the_invites_paid_days_extend_paid_until() {
        let state = app_state(Some(runtime(None)));
        let router = control_api_router(state.clone());
        let admin = admin_token(&state);
        let (_, with_days) = issue_invite(&router, &admin, json!({ "nick": "yearly", "paid_days": 365 })).await;
        let (_, without) = issue_invite(&router, &admin, json!({ "nick": "nodays" })).await;

        let before = Utc::now();
        let (_, _, session) = redeem_from(&router, IP_A, with_days["invite_code"].as_str().expect("code"), &fresh()).await;
        let until = paid_until_of(&state, session["user_id"].as_i64().expect("user id")).expect("paid_until is set");
        let until = chrono::DateTime::parse_from_rfc3339(&until).expect("rfc3339").with_timezone(&Utc);
        assert!(
            until >= before + chrono::Duration::days(365) && until <= Utc::now() + chrono::Duration::days(365),
            "now + 365 days, got {until}"
        );
        let (_, _, session) = redeem_from(&router, IP_A, without["invite_code"].as_str().expect("code"), &fresh()).await;
        assert_eq!(paid_until_of(&state, session["user_id"].as_i64().expect("user id")), None, "no days, no paid_until");

        // Bounds: 0 or 1..=3650.
        for days in [-1, 3651] {
            let (status, _) = issue_invite(&router, &admin, json!({ "nick": "badbounds", "paid_days": days })).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "paid_days {days}");
        }
        let (status, _) = issue_invite(&router, &admin, json!({ "nick": "maxdays", "paid_days": 3650 })).await;
        assert_eq!(status, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn invite_redemption_is_throttled_per_address_like_key_sign_in() {
        let state = app_state(Some(runtime_with(None, &[("MLC_BILLING_KEY_FAILS_PER_IP_PER_HOUR", "3")])));
        let router = control_api_router(state.clone());
        let admin = admin_token(&state);
        let (_, issued) = issue_invite(&router, &admin, json!({ "nick": "throttled" })).await;
        let code = issued["invite_code"].as_str().expect("code").to_string();

        for guess in ["AAAA-AAAA-AAAA-AAAA-AAAA", "BBBB-BBBB-BBBB-BBBB-BBBB", "junk"] {
            let (status, _, _) = redeem_from(&router, IP_A, guess, &fresh()).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        let (status, headers, blocked) = redeem_from(&router, IP_A, &code, &fresh()).await;
        assert_eq!((status, blocked["error"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")), "even the right code");
        assert!(headers.get(header::RETRY_AFTER).is_some() && headers.get(header::SET_COOKIE).is_none());
        // The throttle is shared with key sign-in.
        let (status, _, _) = key_sign_in(&router, IP_A, &fresh()).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM users WHERE provider = 'anon'"), 0, "nothing was created");
        // Another address is untouched, and the code was not burnt by the blocked attempt.
        let (status, _, _) = redeem_from(&router, IP_B, &code, &fresh()).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn redemption_checks_the_credential_format_and_a_refusal_keeps_the_code() {
        let state = app_state(Some(runtime(None)));
        let router = control_api_router(state.clone());
        let admin = admin_token(&state);
        let (_, issued) = issue_invite(&router, &admin, json!({ "nick": "careful", "paid_days": 7 })).await;
        let code = issued["invite_code"].as_str().expect("code").to_string();

        let good = fresh();
        for bad in ["", "hello", &good[..63], &format!("{good}0"), "0F4Z-ABCD-EFGH-JKMN-PQRS-TV"] {
            let (status, _, answer) = redeem_from(&router, IP_A, &code, bad).await;
            assert_eq!((status, answer["error"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid_credential")), "{bad:?}");
        }
        // A credential another account holds: 409, and the invite survives it.
        let (_, _, first) = {
            let (_, other) = issue_invite(&router, &admin, json!({ "nick": "firstone" })).await;
            redeem_from(&router, IP_B, other["invite_code"].as_str().expect("code"), &good).await
        };
        assert!(first["user_id"].is_i64());
        let (status, _, answer) = redeem_from(&router, IP_A, &code, &good).await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::CONFLICT, Some("credential_in_use")));
        assert_eq!(count(&state, "SELECT COUNT(*) FROM users WHERE provider = 'anon'"), 1);

        let (status, _, _) = redeem_from(&router, IP_A, &code, &fresh()).await;
        assert_eq!(status, StatusCode::OK, "the code survived every refusal");
    }

    #[tokio::test]
    async fn the_invite_routes_are_admin_only_and_validate_their_input() {
        let state = app_state(Some(runtime(None)));
        let router = control_api_router(state.clone());
        let admin = admin_token(&state);
        let (mod_id, moderator) = sign_in(&state, "modperson");
        crate::social_db::set_role(&state.control_plane().social_conn(), mod_id, Role::Moderator, &Utc::now().to_rfc3339()).expect("role");
        let (_, member) = sign_in(&state, "plainmember");

        let routes: [(Method, &str, Option<Value>); 3] = [
            (Method::POST, "/staff/invites", Some(json!({ "nick": "nope" }))),
            (Method::GET, "/staff/invites", None),
            (Method::POST, "/staff/invites/inv_x/revoke", Some(json!({}))),
        ];
        for (method, uri, body) in &routes {
            for token in [Some(&moderator), Some(&member), None] {
                let authorization = token.map(|t| format!("Bearer {t}"));
                let mut headers = vec![("content-type", "application/json")];
                if let Some(value) = &authorization {
                    headers.push(("authorization", value.as_str()));
                }
                let (status, _, answer) = send_from(&router, IP_A, method.clone(), uri, &headers, body.as_ref().map(Value::to_string)).await;
                assert_eq!((status, answer), (StatusCode::FORBIDDEN, json!({ "error": "forbidden" })), "{method} {uri}");
            }
        }
        assert_eq!(count(&state, "SELECT COUNT(*) FROM registration_invites"), 0);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM staff_audit"), 0, "a refused request is not an action");

        for (body, expected) in [
            (json!({ "nick": "" }), StatusCode::BAD_REQUEST),
            (json!({ "nick": "has space" }), StatusCode::BAD_REQUEST),
            (json!({ "nick": "x" }), StatusCode::BAD_REQUEST),
            (json!({ "nick": "fine", "note": "line\nbreak" }), StatusCode::BAD_REQUEST),
            (json!({ "nick": "fine", "note": "x".repeat(201) }), StatusCode::BAD_REQUEST),
        ] {
            let (status, _) = issue_invite(&router, &admin, body.clone()).await;
            assert_eq!(status, expected, "{body}");
        }
        assert_eq!(count(&state, "SELECT COUNT(*) FROM registration_invites"), 0, "refusals issue nothing");
        assert_eq!(count(&state, "SELECT COUNT(*) FROM staff_audit"), 0);
        // The account of the admin itself holds its nick.
        let (status, answer) = issue_invite(&router, &admin, json!({ "nick": "rootadmin" })).await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::CONFLICT, Some("nick taken")));
    }
}

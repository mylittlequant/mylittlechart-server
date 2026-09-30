//! Anonymous ("numbered") account routes: buy one, read its invoice, enter it
//! with its key, rotate the key. The account has no OAuth identity and no
//! email; the key is the whole credential. The design lives in
//! `billing/anon.rs`.
//!
//! | Route | Auth | Purpose |
//! |---|---|---|
//! | `POST /api/billing/anon-checkout {plan_id}` | none (per-IP hourly budget + a global one) | create a PENDING account and its invoice → `201 {account_key, invoice_id, pay[]}` |
//! | `GET /api/billing/anon-invoice/{id}` | `Authorization: AccountKey <key>` | read the account's own invoice (any status) |
//! | `POST /api/auth/account-key {account_key}` | none (per-IP failure throttle) | ACTIVE account → a session, the same shape the Telegram sign-in returns |
//! | `POST /api/account/key/rotate` | session | signed-in anonymous account → a new key; the old one stops working |
//!
//! The key is shown exactly once, in the `anon-checkout` (or `rotate`)
//! answer. Nothing in this file formats it into a log line or an error body,
//! and every refusal of a key — malformed, unknown, pending — is the same
//! `401 {"error":"invalid account key"}`.

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
use crate::billing::anon::{self, AccountKey, AccountStatus, AnonAccount};
use crate::billing::flow;
use crate::billing::throttle::SlidingLimiter;
use crate::billing::BillingRuntime;
use crate::models::types::ErrorResponse;
use crate::routes::billing::{error, flow_error, invoice_json, signed_in};
use crate::state::AppState;

/// Lifetime of the session a key sign-in mints — the same as the other
/// sign-ins.
const SESSION_HOURS: i64 = 24;

/// The one answer to every unusable key.
fn invalid_key() -> Response {
    error(StatusCode::UNAUTHORIZED, "invalid account key")
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
}

/// `POST /api/billing/anon-checkout` — public.
///
/// Creates a PENDING anonymous user, opens the dig2pay subscription under that
/// user's id, and answers `201`:
///
/// ```json
/// { "account_key": "0F4Z-…-XY", "invoice_id": "grp_…",
///   "pay": [ { "chain": "evm:1", "asset": "USDC", "address": "0x…",
///              "amount": "10.000000", "expires_at": "…", "qr_svg": "<svg…>" }, … ] }
/// ```
/// The key is 128 random bits as 26 Crockford base32 characters in groups of
/// four; it is shown here ONCE and only its SHA-256 is stored. Errors:
/// `400 plan_not_available` (not an anonymous-account plan, or not the plan of
/// this vhost), `429 rate_limited` (5 per client IP per hour and a global cap,
/// both configurable), `503 plan_unavailable`, `503 billing_not_configured`,
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
    // A request for the wrong plan must not spend anyone's budget.
    let sold_here = billing
        .catalog()
        .get(plan_id)
        .is_some_and(|p| p.grant == crate::billing::plans::Grant::LifetimeAnon && p.offered_to(onion));
    if !sold_here {
        return error(StatusCode::BAD_REQUEST, "plan_not_available");
    }
    let limiter = billing.anon_create_limiter();
    if !limiter.try_acquire(caller_ip(&headers, peer), Instant::now()) {
        return rate_limited(limiter);
    }
    match flow::anon_checkout(&state, plan_id, onion).await {
        Ok(view) => (
            StatusCode::CREATED,
            Json(json!({
                "account_key": view.account_key,
                "invoice_id": view.invoice_id,
                "pay": view.pay,
            })),
        )
            .into_response(),
        Err(e) => flow_error(e),
    }
}

/// The `Authorization: AccountKey <key>` value, if that is what was sent.
fn presented_key(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("AccountKey "))
}

/// Look a presented key up, under the per-IP failure throttle.
///
/// `Err` is the response to send (`429` once the address has used up its
/// failures; the key is not even looked at then). `Ok(None)` is an unusable
/// key — malformed or unknown — and has been counted as a failure.
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
    let Some(key) = presented.and_then(AccountKey::parse) else {
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

/// `GET /api/billing/anon-invoice/{id}` — `Authorization: AccountKey <key>`.
///
/// The key (pending or active) can read its own account's invoices and
/// nothing else; the answer is the same shape as `GET /api/billing/invoice/{id}`.
/// `401 invalid account key` for any unusable key, `404 not_found` for an
/// invoice that is not this account's, `429 rate_limited` after too many
/// failed keys from one address.
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

/// Request body of `POST /api/auth/account-key`.
#[derive(Deserialize)]
pub struct SignInBody {
    /// The account key, as shown (case, hyphens and spaces are forgiven).
    pub account_key: String,
}

/// `POST /api/auth/account-key` — public.
///
/// A key of an ACTIVE anonymous account becomes a session, in the shape the
/// Telegram sign-in poll returns, plus the same `session_id` cookie:
///
/// ```json
/// { "status": "confirmed", "user_id": 42, "public_id": "…", "session_id": "…" }
/// ```
/// A malformed, unknown or still-pending key all get the same
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
    let account = match account_for_key(&state, &billing, Some(body.account_key.as_str()), ip).await {
        Ok(Some(account)) => account,
        Ok(None) => return invalid_key(),
        Err(response) => return response,
    };
    if account.status != AccountStatus::Active {
        billing.key_failure_limiter().record(ip, Instant::now());
        return invalid_key();
    }

    let ua_hash = extract_ua_hash(&headers);
    let user_id = account.user_id;
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

/// `POST /api/account/key/rotate` — a signed-in ACTIVE anonymous account.
///
/// Answers `200 {"account_key": "…"}` with a new key, shown once; the old key
/// stops working at once. Sessions already open stay open. `401` without a
/// session, `403 not_an_anonymous_account` for any other account.
pub async fn rotate(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user_id = match signed_in(&state, &headers).await {
        Ok(id) => id,
        Err(response) => return response,
    };
    let rotated = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<String>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let key = AccountKey::generate();
        Ok(anon::rotate_key(&conn, user_id, &key, chrono::Utc::now())?.then(|| key.reveal()))
    })
    .await;
    match rotated {
        Ok(Ok(Some(account_key))) => Json(json!({ "account_key": account_key })).into_response(),
        Ok(Ok(None)) => error(StatusCode::FORBIDDEN, "not_an_anonymous_account"),
        Ok(Err(e)) => {
            tracing::error!("account key rotation failed: {e}");
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
        app_state, deliver_ok, one_time_settlement, post_json, runtime, runtime_with, send_from, sign_in,
        spawn_merchant, ONION_HOST,
    };
    use crate::routes::control_api_router;
    use axum::http::Method;
    use axum::Router;
    use chrono::Utc;
    use serde_json::Value;

    const CLEARNET: &str = "mylittlechart.org";
    const ANON: &str = "mlc-anon-account-v1";
    const IP_A: [u8; 4] = [203, 0, 113, 1];
    const IP_B: [u8; 4] = [203, 0, 113, 2];

    async fn checkout_from(router: &Router, ip: [u8; 4], plan: &str, host: &str) -> (StatusCode, HeaderMap, Value) {
        send_from(
            router,
            ip,
            Method::POST,
            "/billing/anon-checkout",
            &[("content-type", "application/json"), ("host", host)],
            Some(json!({ "plan_id": plan }).to_string()),
        )
        .await
    }

    async fn key_sign_in(router: &Router, ip: [u8; 4], key: &str) -> (StatusCode, HeaderMap, Value) {
        send_from(
            router,
            ip,
            Method::POST,
            "/auth/account-key",
            &[("content-type", "application/json")],
            Some(json!({ "account_key": key }).to_string()),
        )
        .await
    }

    async fn invoice_with_key(router: &Router, ip: [u8; 4], key: &str, invoice: &str) -> (StatusCode, HeaderMap, Value) {
        let authorization = format!("AccountKey {key}");
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

    fn account_of(state: &Arc<AppState>, key: &str) -> AnonAccount {
        let parsed = AccountKey::parse(key).expect("a well-formed key");
        let conn = state.control_plane().db.lock().expect("db");
        anon::find_by_key(&conn, &parsed).expect("lookup").expect("the account exists")
    }

    fn count(state: &Arc<AppState>, sql: &str) -> i64 {
        state.control_plane().db.lock().expect("db").query_row(sql, [], |r| r.get(0)).expect("count")
    }

    fn well_formed(key: &str) -> bool {
        let groups: Vec<&str> = key.split('-').collect();
        groups.len() == 7
            && groups[..6].iter().all(|g| g.len() == 4)
            && groups[6].len() == 2
            && key.chars().filter(|c| *c != '-').all(|c| "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c))
    }

    /// Buy an anonymous account and settle it; returns `(key, user id)`.
    async fn paid_account(router: &Router, state: &Arc<AppState>, ip: [u8; 4], n: u32) -> (String, i64) {
        let (status, _, answer) = checkout_from(router, ip, ANON, CLEARNET).await;
        assert_eq!(status, StatusCode::CREATED, "{answer}");
        let key = answer["account_key"].as_str().expect("key").to_string();
        let user_id = account_of(state, &key).user_id;
        let invoice = answer["invoice_id"].as_str().expect("invoice").to_string();
        let sub = invoice.replace("grp_", "sub_");
        deliver_ok(router, &one_time_settlement(&format!("paid-{n}"), user_id, ANON, &sub, &invoice)).await;
        (key, user_id)
    }

    // ------------------------------------------------------------- the flow

    #[tokio::test]
    async fn the_whole_flow_checkout_pending_webhook_active_sign_in_rotate_old_key_dead() {
        capture_logs();
        let (base, merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let router = control_api_router(state.clone());

        // -- checkout: a PENDING account and its invoice, the key shown once.
        let (status, _, answer) = checkout_from(&router, IP_A, ANON, CLEARNET).await;
        assert_eq!(status, StatusCode::CREATED, "{answer}");
        let key = answer["account_key"].as_str().expect("key").to_string();
        assert!(well_formed(&key), "26 Crockford characters in groups of four: {key}");
        assert_eq!(answer["invoice_id"], "grp_1");
        assert_eq!(answer["pay"].as_array().map(Vec::len), Some(2), "pay[] as the processor issued it");
        assert_eq!(answer.as_object().map(|o| o.len()), Some(3), "exactly {{account_key, invoice_id, pay}}");
        let account = account_of(&state, &key);
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
            assert_eq!(stored, AccountKey::parse(&key).expect("parse").hash_hex());
            assert!(!stored.contains(&key.replace('-', "")));
            let (provider, name): (String, String) = conn
                .query_row("SELECT provider, display_name FROM users WHERE id = ?1", [account.user_id], |r| Ok((r.get(0)?, r.get(1)?)))
                .expect("user");
            assert_eq!((provider.as_str(), name.as_str()), ("anon", ""));
            let links: i64 = conn
                .query_row("SELECT COUNT(*) FROM user_providers WHERE user_id = ?1 AND (provider != 'anon' OR email IS NOT NULL)", [account.user_id], |r| r.get(0))
                .expect("links");
            assert_eq!(links, 0);
        }

        // -- before payment: no session, but the key reads its own invoice only.
        let (status, _, refusal) = key_sign_in(&router, IP_A, &key).await;
        assert_eq!((status, refusal["error"].as_str()), (StatusCode::UNAUTHORIZED, Some("invalid account key")));
        let (status, _, invoice) = invoice_with_key(&router, IP_A, &key, "grp_1").await;
        assert_eq!(status, StatusCode::OK, "{invoice}");
        assert_eq!((invoice["invoice_id"].as_str(), invoice["grant_state"].as_str()), (Some("grp_1"), Some("none")));
        let (status, _, _) = invoice_with_key(&router, IP_A, "0000-0000-0000-0000-0000-0000-00", "grp_1").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (_, _, second) = checkout_from(&router, IP_B, ANON, CLEARNET).await;
        let other_key = second["account_key"].as_str().expect("second key").to_string();
        let (status, _, stranger) = invoice_with_key(&router, IP_B, &other_key, "grp_1").await;
        assert_eq!((status, stranger["error"].as_str()), (StatusCode::NOT_FOUND, Some("not_found")), "another account's key cannot read it");

        // -- the webhook: payment_confirmed activates it with both grants, sourced from the invoice.
        let settled = one_time_settlement("anon-1", account.user_id, ANON, "sub_1", "grp_1");
        assert_eq!(deliver_ok(&router, &settled).await["outcome"], "granted");
        assert_eq!(account_of(&state, &key).status, AccountStatus::Active);
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
        let (status, headers, session) = key_sign_in(&router, IP_A, &key.to_lowercase()).await;
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

        // -- rotate: a new key, the old one is dead.
        let (status, _, rotated) = send_from(&router, IP_A, Method::POST, "/account/key/rotate", &[("cookie", session_cookie.as_str())], None).await;
        assert_eq!(status, StatusCode::OK, "{rotated}");
        let new_key = rotated["account_key"].as_str().expect("new key").to_string();
        assert!(well_formed(&new_key) && new_key != key);
        let (status, _, _) = key_sign_in(&router, IP_A, &key).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "the old key is dead");
        let (status, _, _) = invoice_with_key(&router, IP_A, &key, "grp_1").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "and reads nothing");
        let (status, _, again) = key_sign_in(&router, IP_A, &new_key).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(again["user_id"], account.user_id);

        // -- no key ever reached a log line.
        let logs = captured_logs();
        assert!(!logs.is_empty(), "the capture is live");
        for secret in [&key, &other_key, &new_key] {
            for form in [secret.clone(), secret.replace('-', ""), secret.to_lowercase(), secret.replace('-', "").to_lowercase()] {
                assert!(!logs.contains(&form), "an account key was logged");
            }
        }
        assert!(!logs.contains(&session_id), "nor a session id");
    }

    #[tokio::test]
    async fn rotation_needs_a_session_and_an_anonymous_account() {
        let (base, _merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let router = control_api_router(state.clone());
        let (status, _, _) = send_from(&router, IP_A, Method::POST, "/account/key/rotate", &[], None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (_, oauth_token) = sign_in(&state, "oauth-user");
        let (status, body) = post_json(&router, &oauth_token, "/account/key/rotate", json!({}), None).await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("not_an_anonymous_account")));
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
            let (status, _, answer) = checkout_from(&router, IP_A, plan, host).await;
            assert_eq!((status, answer["error"].as_str()), (StatusCode::BAD_REQUEST, Some("plan_not_available")), "{plan} via {host}");
        }
        assert_eq!(count(&state, "SELECT COUNT(*) FROM billing_anon_accounts"), 0, "refusals create nothing");
        assert!(merchant.lock().expect("mock").calls.is_empty(), "and never reach the processor");

        let (status, _, _) = checkout_from(&router, IP_A, ANON, CLEARNET).await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, _, _) = checkout_from(&router, IP_A, DEFAULT_ANON_TOR_ID, ONION_HOST).await;
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
        let (status, _, answer) = checkout_from(&router, IP_A, ANON, CLEARNET).await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("billing_not_configured")));
        let bare = control_api_router(app_state(None));
        let (status, _, _) = checkout_from(&bare, IP_A, ANON, CLEARNET).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM billing_anon_accounts"), 0);
    }

    #[tokio::test]
    async fn a_checkout_the_processor_refuses_leaves_no_account_behind_and_can_be_retried() {
        let (base, merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let router = control_api_router(state.clone());
        let users_before = count(&state, "SELECT COUNT(*) FROM users");

        merchant.lock().expect("mock").fail_next_subscription = true;
        let (status, _, answer) = checkout_from(&router, IP_A, ANON, CLEARNET).await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::BAD_GATEWAY, Some("payment_gateway_unavailable")));
        assert!(answer.get("account_key").is_none(), "no key for an invoice that does not exist");
        merchant.lock().expect("mock").unknown_plans.insert(ANON.to_string());
        let (status, _, answer) = checkout_from(&router, IP_A, ANON, CLEARNET).await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("plan_unavailable")));
        assert_eq!(count(&state, "SELECT COUNT(*) FROM users"), users_before, "both pending accounts were rolled back");
        assert_eq!(count(&state, "SELECT COUNT(*) FROM billing_anon_accounts"), 0);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM billing_subscriptions"), 0);

        merchant.lock().expect("mock").unknown_plans.clear();
        let (status, _, _) = checkout_from(&router, IP_A, ANON, CLEARNET).await;
        assert_eq!(status, StatusCode::CREATED);
    }

    // ----------------------------------------------------------- rate limits

    #[tokio::test]
    async fn five_checkouts_per_ip_per_hour_and_a_bad_plan_costs_nothing() {
        let (base, merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let router = control_api_router(state.clone());

        for _ in 0..10 {
            let (status, _, _) = checkout_from(&router, IP_A, "mlc-paid-account-v1", CLEARNET).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        for n in 1..=5 {
            let (status, _, answer) = checkout_from(&router, IP_A, ANON, CLEARNET).await;
            assert_eq!(status, StatusCode::CREATED, "checkout {n}: {answer}");
        }
        let (status, headers, answer) = checkout_from(&router, IP_A, ANON, CLEARNET).await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")));
        assert_eq!(headers.get(header::RETRY_AFTER).and_then(|v| v.to_str().ok()), Some("3600"));
        assert!(answer.get("account_key").is_none());
        assert_eq!(merchant.lock().expect("mock").created, 5, "the sixth reached nothing");
        assert_eq!(count(&state, "SELECT COUNT(*) FROM billing_anon_accounts"), 5);

        let (status, _, _) = checkout_from(&router, IP_B, ANON, CLEARNET).await;
        assert_eq!(status, StatusCode::CREATED, "another address has its own budget");
    }

    #[tokio::test]
    async fn a_global_cap_binds_across_addresses() {
        let (base, merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime_with(Some(&base), &[("MLC_BILLING_ANON_GLOBAL_PER_HOUR", "3")])));
        let router = control_api_router(state);
        for last in 1..=3u8 {
            let (status, _, _) = checkout_from(&router, [203, 0, 113, last], ANON, CLEARNET).await;
            assert_eq!(status, StatusCode::CREATED, "address {last}");
        }
        let (status, _, answer) = checkout_from(&router, [203, 0, 113, 4], ANON, CLEARNET).await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")));
        assert_eq!(merchant.lock().expect("mock").created, 3);
    }

    #[tokio::test]
    async fn failed_keys_are_throttled_per_address_and_every_refusal_looks_the_same() {
        capture_logs();
        let (base, _merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime_with(Some(&base), &[("MLC_BILLING_KEY_FAILS_PER_IP_PER_HOUR", "3")])));
        let router = control_api_router(state.clone());
        let (good_key, _) = paid_account(&router, &state, IP_B, 1).await;
        // A still-pending key, an unknown well-formed key, and garbage.
        let (_, _, pending) = checkout_from(&router, IP_B, ANON, CLEARNET).await;
        let pending_key = pending["account_key"].as_str().expect("key").to_string();
        let unknown_key = AccountKey::generate().reveal();

        let mut refusals = Vec::new();
        for attempt in [pending_key.as_str(), unknown_key.as_str(), "not a key at all"] {
            refusals.push(key_sign_in(&router, IP_A, attempt).await);
        }
        for (status, headers, body) in &refusals {
            assert_eq!(*status, StatusCode::UNAUTHORIZED);
            assert_eq!(body, &refusals[0].2, "the same body for malformed, unknown and pending");
            assert!(headers.get(header::SET_COOKIE).is_none());
        }
        assert_eq!(refusals[0].2, json!({ "error": "invalid account key" }));

        // The address has now spent its three failures: even the right key is refused.
        let (status, headers, blocked) = key_sign_in(&router, IP_A, &good_key).await;
        assert_eq!((status, blocked["error"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")));
        assert!(headers.get(header::SET_COOKIE).is_none());
        let (status, _, _) = invoice_with_key(&router, IP_A, &good_key, "grp_1").await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "the invoice read shares the throttle");
        // Another address is untouched.
        let (status, _, _) = key_sign_in(&router, IP_B, &good_key).await;
        assert_eq!(status, StatusCode::OK);

        let logs = captured_logs();
        for secret in [&good_key, &pending_key, &unknown_key] {
            assert!(!logs.contains(secret.as_str()) && !logs.contains(&secret.replace('-', "")), "a key was logged");
        }
    }

    // ------------------------------------------------------------------- GC

    #[tokio::test]
    async fn an_unpaid_account_is_collected_a_day_after_its_invoice_expired_and_a_late_payment_is_unmatched() {
        let (base, _merchant) = spawn_merchant().await;
        let state = app_state(Some(runtime(Some(&base))));
        let router = control_api_router(state.clone());
        let (_, _, answer) = checkout_from(&router, IP_A, ANON, CLEARNET).await;
        let key = answer["account_key"].as_str().expect("key").to_string();
        let user_id = account_of(&state, &key).user_id;

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
        let (status, _, _) = key_sign_in(&router, IP_B, &key).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "the key is gone with its account");

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
        let (key, _) = paid_account(&router, &state, IP_A, 1).await;
        let long_ago = (Utc::now() - chrono::Duration::days(90)).to_rfc3339();
        state.control_plane().db.lock().expect("db").execute("UPDATE billing_invoices SET expires_at = ?1", [long_ago.as_str()]).expect("age");
        let report = {
            let cp = state.control_plane();
            let conn = cp.db.lock().expect("db");
            let mut messenger = cp.messenger_conn();
            anon::gc_pending(&conn, &mut messenger, &cp.live, Utc::now()).expect("gc")
        };
        assert_eq!(report.deleted, 0);
        let (status, _, _) = key_sign_in(&router, IP_B, &key).await;
        assert_eq!(status, StatusCode::OK);
    }
}

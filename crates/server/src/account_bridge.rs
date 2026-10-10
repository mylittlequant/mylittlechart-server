//! Chart side of the messenger bridge.
//!
//! The product process is the authenticator. When `MLC_BRIDGE_SECRET` is
//! set it signs `X-Account-Assertion` on the `/_matrix` proxy and it accepts
//! `POST /api/bridge/admit` plus `GET /api/bridge/credentials`. When
//! `MLC_BRIDGE_EVENTS_URL` is also set, revoke, account delete, and nick
//! change POST a signed event. Neither variable is read from this file's
//! tests. Unset, every function here is a no-op and the live messenger is
//! unchanged.
//!
//! The secret is the raw UTF-8 string, used as HMAC-SHA256 key bytes. It is
//! not hex. It is not logged. The other side must use the same bytes.
//!
//! Assertion header `x-account-assertion`:
//! `v1.<base64url(json)>.<hex hmac>`.
//! The HMAC covers this canonical UTF-8 text, not the JSON bytes:
//!
//! ```text
//! v1
//! <METHOD>
//! <path and query, as forwarded>
//! <nick>
//! 1
//! <paid 0 or 1>
//! <cred_ref>
//! <iat unix seconds>
//! <exp unix seconds>
//! <nonce hex>
//! ```
//!
//! `exp` is `iat` plus 60. A missing header means unauthenticated. The proxy
//! strips a client-supplied copy before it decides whether to add its own.
//! The nick is the chart nick as stored. The messenger lowercases it for the
//! localpart. `cred_ref` is the chart's existing SHA-256 hex of the bearer
//! or of the web session id.
//!
//! Event `POST` body is the exact JSON below. Header `x-mlc-event-signature`
//! is hex HMAC-SHA256 of those raw body bytes.
//!
//! ```text
//! {"id":"<32 hex>","type":"credential.revoked","cred_ref":"<cred_ref>"}
//! {"id":"<32 hex>","type":"account.deleted","nick":"<nick>"}
//! {"id":"<32 hex>","type":"nick.changed","old":"<old>","new":"<new>"}
//! ```
//!
//! Admit and the credentials list use header `x-mlc-bridge-signature`, hex
//! HMAC of `admit\n<unix ts>\n<body>` or `credentials\n<unix ts>\n`. The
//! timestamp must be within 60 seconds. Admit's body is
//! `{"source":"...","subject":"..."}`. `source` and `subject` are the login
//! key. They are never written into `users.nick`.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::json;
use sha2::Sha256;
use std::sync::Arc;
use std::time::Duration;

use crate::state::AppState;

type HmacSha256 = Hmac<Sha256>;

const ASSERTION_TTL_SECS: i64 = 60;
const HEADER_ASSERTION: &str = "x-account-assertion";
const HEADER_EVENT_SIG: &str = "x-mlc-event-signature";
const HEADER_BRIDGE_SIG: &str = "x-mlc-bridge-signature";
const HEADER_BRIDGE_TS: &str = "x-mlc-bridge-ts";

pub fn secret() -> Option<String> {
    std::env::var("MLC_BRIDGE_SECRET").ok().and_then(|value| {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn events_url() -> Option<String> {
    std::env::var("MLC_BRIDGE_EVENTS_URL").ok().and_then(|value| {
        let trimmed = value.trim().trim_end_matches('/').to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn sign(secret: &str, message: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(message);
    hex::encode(mac.finalize().into_bytes())
}

fn signature_matches(secret: &str, message: &[u8], presented_hex: &str) -> bool {
    let Ok(presented) = hex::decode(presented_hex.trim()) else {
        return false;
    };
    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(message);
    mac.verify_slice(&presented).is_ok()
}

fn canonical_assertion(
    method: &str,
    path_and_query: &str,
    nick: &str,
    paid: bool,
    cred_ref: &str,
    iat: i64,
    exp: i64,
    nonce: &str,
) -> String {
    format!(
        "v1\n{method}\n{path_and_query}\n{nick}\n1\n{paid}\n{cred_ref}\n{iat}\n{exp}\n{nonce}\n",
        paid = if paid { "1" } else { "0" },
    )
}

pub fn assertion_header(
    secret: &str,
    method: &str,
    path_and_query: &str,
    nick: &str,
    paid: bool,
    cred_ref: &str,
) -> String {
    let iat = chrono::Utc::now().timestamp();
    let exp = iat + ASSERTION_TTL_SECS;
    let nonce_bytes: [u8; 16] = rand::random();
    let nonce = hex::encode(nonce_bytes);
    let canonical = canonical_assertion(method, path_and_query, nick, paid, cred_ref, iat, exp, &nonce);
    let mac = sign(secret, canonical.as_bytes());
    let body = json!({
        "authenticated": true,
        "cred_ref": cred_ref,
        "exp": exp,
        "iat": iat,
        "nick": nick,
        "nonce": nonce,
        "paid": paid,
    });
    let encoded = URL_SAFE_NO_PAD.encode(body.to_string().as_bytes());
    format!("v1.{encoded}.{mac}")
}

/// Check a header this process could have produced. `now` is unix seconds.
/// The method and path are the ones on the request being verified, not the
/// ones inside the JSON.
pub fn verify_assertion(
    secret: &str,
    method: &str,
    path_and_query: &str,
    header: &str,
    now: i64,
) -> Result<Asserted, ()> {
    let mut parts = header.split('.');
    let version = parts.next().ok_or(())?;
    let encoded = parts.next().ok_or(())?;
    let mac = parts.next().ok_or(())?;
    if version != "v1" || parts.next().is_some() {
        return Err(());
    }
    let raw = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| ())?;
    let value: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| ())?;
    let nick = value.get("nick").and_then(|v| v.as_str()).ok_or(())?.to_string();
    let cred_ref = value.get("cred_ref").and_then(|v| v.as_str()).ok_or(())?.to_string();
    let nonce = value.get("nonce").and_then(|v| v.as_str()).ok_or(())?.to_string();
    let authenticated = value.get("authenticated").and_then(|v| v.as_bool()).ok_or(())?;
    let paid = value.get("paid").and_then(|v| v.as_bool()).ok_or(())?;
    let iat = value.get("iat").and_then(|v| v.as_i64()).ok_or(())?;
    let exp = value.get("exp").and_then(|v| v.as_i64()).ok_or(())?;
    if !authenticated || exp != iat + ASSERTION_TTL_SECS || now < iat || now > exp {
        return Err(());
    }
    let canonical = canonical_assertion(method, path_and_query, &nick, paid, &cred_ref, iat, exp, &nonce);
    if !signature_matches(secret, canonical.as_bytes(), mac) {
        return Err(());
    }
    Ok(Asserted { nick, paid, cred_ref, iat, exp, nonce })
}

#[derive(Debug, PartialEq, Eq)]
pub struct Asserted {
    pub nick: String,
    pub paid: bool,
    pub cred_ref: String,
    pub iat: i64,
    pub exp: i64,
    pub nonce: String,
}

pub fn external_source_ok(source: &str) -> bool {
    !source.is_empty()
        && source.len() <= 32
        && source.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

pub fn external_subject_ok(subject: &str) -> bool {
    !subject.is_empty()
        && subject.len() <= 200
        && !subject.bytes().any(|b| b.is_ascii_whitespace() || b < 0x20)
}

fn fresh_id() -> String {
    let bytes: [u8; 16] = rand::random();
    hex::encode(bytes)
}

pub fn emit_credential_revoked(cred_ref: &str) {
    let id = fresh_id();
    emit(format!(
        "{{\"id\":\"{id}\",\"type\":\"credential.revoked\",\"cred_ref\":\"{cred_ref}\"}}"
    ));
}

pub fn emit_account_deleted(nick: &str) {
    if nick.is_empty() {
        return;
    }
    let id = fresh_id();
    emit(format!(
        "{{\"id\":\"{id}\",\"type\":\"account.deleted\",\"nick\":\"{nick}\"}}"
    ));
}

pub fn emit_nick_changed(old: &str, new: &str) {
    if old == new || new.is_empty() {
        return;
    }
    let id = fresh_id();
    emit(format!(
        "{{\"id\":\"{id}\",\"type\":\"nick.changed\",\"old\":\"{old}\",\"new\":\"{new}\"}}"
    ));
}

fn emit(body: String) {
    let (Some(secret), Some(url)) = (secret(), events_url()) else {
        return;
    };
    let signature = sign(&secret, body.as_bytes());
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    handle.spawn(async move {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build();
        let Ok(client) = client else {
            return;
        };
        for delay in [0_u64, 200, 1000] {
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            let sent = client
                .post(&url)
                .header(HEADER_EVENT_SIG, &signature)
                .header("content-type", "application/json")
                .body(body.clone())
                .send()
                .await;
            match sent {
                Ok(response) if response.status().is_success() => return,
                Ok(response) => tracing::warn!("bridge event status {}", response.status()),
                Err(error) => tracing::warn!("bridge event post: {error}"),
            }
        }
    });
}

fn bridge_message(kind: &str, ts: i64, body: &[u8]) -> Vec<u8> {
    let mut message = format!("{kind}\n{ts}\n").into_bytes();
    message.extend_from_slice(body);
    message
}

fn authorized(headers: &HeaderMap, kind: &str, body: &[u8]) -> Result<(), StatusCode> {
    let Some(secret) = secret() else {
        return Err(StatusCode::NOT_FOUND);
    };
    let ts: i64 = headers
        .get(HEADER_BRIDGE_TS)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let now = chrono::Utc::now().timestamp();
    if (now - ts).abs() > ASSERTION_TTL_SECS {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let presented = headers
        .get(HEADER_BRIDGE_SIG)
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if signature_matches(&secret, &bridge_message(kind, ts, body), presented) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

#[derive(Deserialize)]
struct AdmitBody {
    source: String,
    subject: String,
}

pub async fn admit(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(status) = authorized(&headers, "admit", &body) {
        return status.into_response();
    }
    let parsed: AdmitBody = match serde_json::from_slice(&body) {
        Ok(parsed) => parsed,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if !external_source_ok(&parsed.source) || !external_subject_ok(&parsed.subject) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let source = parsed.source;
    let subject = parsed.subject;
    let admitted = tokio::task::spawn_blocking(move || {
        let cp = state.control_plane();
        let conn = cp.db.lock().unwrap_or_else(|error| error.into_inner());
        let now = chrono::Utc::now().to_rfc3339();
        // Display name stays empty. The subject is the login key, not a nick.
        let user_id = crate::db::upsert_user(&conn, &source, &subject, "", None, &now)?;
        let nick = crate::db::nick_for_user(&conn, user_id)?;
        Ok::<Option<String>, rusqlite::Error>(nick)
    })
    .await;
    match admitted {
        Ok(Ok(Some(nick))) => Json(json!({ "nick": nick })).into_response(),
        _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub async fn credentials(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(status) = authorized(&headers, "credentials", b"") {
        return status.into_response();
    }
    let listed = tokio::task::spawn_blocking(move || {
        let cp = state.control_plane();
        let conn = cp.db.lock().unwrap_or_else(|error| error.into_inner());
        let mut refs = Vec::new();
        let mut tokens = conn.prepare(
            "SELECT token_hash FROM auth_tokens WHERE expires_at IS NULL OR datetime(expires_at) > datetime('now')",
        )?;
        let rows = tokens.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            refs.push(row?);
        }
        let mut sessions = conn.prepare(
            "SELECT session_id FROM web_sessions WHERE datetime(expires_at) > datetime('now')",
        )?;
        let rows = sessions.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            refs.push(crate::auth::hash_token(&row?));
        }
        Ok::<Vec<String>, rusqlite::Error>(refs)
    })
    .await;
    match listed {
        Ok(Ok(cred_refs)) => Json(json!({ "cred_refs": cred_refs })).into_response(),
        _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub const ASSERTION_HEADER: &str = HEADER_ASSERTION;

/// Edge link. All three values must be set, or the product keeps the
/// loopback messenger proxy. The secret is raw UTF-8, the same bytes the
/// core uses. It is not logged.
#[derive(Clone)]
pub struct SeamLink {
    pub base: String,
    pub secret: Vec<u8>,
    pub token: String,
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().and_then(|value| {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

pub fn seam_link() -> Option<SeamLink> {
    let base = nonempty_env("M4A_PRODUCT_EDGE_URL")?;
    let secret = nonempty_env("M4A_ASSERTION_SECRET")?;
    let token = nonempty_env("M4A_LINK_TOKEN")?;
    let base = base.trim_end_matches('/').to_string();
    if base.is_empty() {
        return None;
    }
    Some(SeamLink { base, secret: secret.into_bytes(), token })
}

/// Path the core checks: the edge removes a leading `/_matrix`.
pub fn core_path(path_and_query: &str) -> &str {
    let stripped = path_and_query.strip_prefix("/_matrix").unwrap_or(path_and_query);
    if stripped.is_empty() {
        "/"
    } else {
        stripped
    }
}

/// Sign with `m4a-seam` over [`core_path`], not over the path the client used.
pub fn seam_assertion(
    secret: &[u8],
    method: &str,
    path_and_query: &str,
    nick: &str,
    paid: bool,
    cred_ref: &str,
) -> String {
    let iat = chrono::Utc::now().timestamp();
    let nonce_bytes: [u8; 16] = rand::random();
    let assertion = m4a_seam::Assertion {
        nick: nick.to_string(),
        cred_ref: cred_ref.to_string(),
        authenticated: 1,
        paid: if paid { 1 } else { 0 },
        iat,
        exp: iat + m4a_seam::ASSERTION_TTL_S,
        nonce: hex::encode(nonce_bytes),
    };
    m4a_seam::sign_assertion(secret, method, core_path(path_and_query), &assertion)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assertion_roundtrip_and_it_rejects_a_moved_path() {
        let header = assertion_header("test-secret", "GET", "/_matrix/client/v3/sync?timeout=0", "ada", true, "abc");
        let now = chrono::Utc::now().timestamp();
        let ok = verify_assertion("test-secret", "GET", "/_matrix/client/v3/sync?timeout=0", &header, now).expect("verify");
        assert_eq!(ok.nick, "ada");
        assert!(ok.paid);
        assert_eq!(ok.cred_ref, "abc");
        assert!(verify_assertion("test-secret", "GET", "/_matrix/client/v3/sync", &header, now).is_err());
        assert!(verify_assertion("other-secret", "GET", "/_matrix/client/v3/sync?timeout=0", &header, now).is_err());
        assert!(verify_assertion("test-secret", "POST", "/_matrix/client/v3/sync?timeout=0", &header, now).is_err());
        assert!(verify_assertion("test-secret", "GET", "/_matrix/client/v3/sync?timeout=0", &header, now + 120).is_err());
    }

    #[test]
    fn seam_signs_the_path_the_core_sees() {
        let secret = b"test-secret";
        let header = seam_assertion(secret, "GET", "/_matrix/client/v3/sync?timeout=0", "ada", true, "abc");
        let now_ms = chrono::Utc::now().timestamp_millis();
        let ok = m4a_seam::verify_assertion(
            &[secret.to_vec()],
            &header,
            "GET",
            "/client/v3/sync?timeout=0",
            now_ms,
            30_000,
        )
        .expect("core path");
        assert_eq!((ok.nick.as_str(), ok.paid, ok.cred_ref.as_str()), ("ada", 1, "abc"));
        assert!(m4a_seam::verify_assertion(
            &[secret.to_vec()],
            &header,
            "GET",
            "/_matrix/client/v3/sync?timeout=0",
            now_ms,
            30_000,
        )
        .is_err());
    }

    #[test]
    fn external_key_is_not_a_nick_shape_check() {
        assert!(external_source_ok("mail"));
        assert!(external_source_ok("mx"));
        assert!(!external_source_ok("Mail"));
        assert!(!external_source_ok(""));
        assert!(external_subject_ok("ada:their.example"));
        assert!(!external_subject_ok("has space"));
        assert!(!external_subject_ok("line\nbreak"));
    }

    #[test]
    fn event_signature_covers_the_body_bytes() {
        let body = r#"{"id":"00112233445566778899aabbccddeeff","type":"nick.changed","old":"aaaaeeee","new":"ada"}"#;
        let mac = sign("test-secret", body.as_bytes());
        assert!(signature_matches("test-secret", body.as_bytes(), &mac));
        assert!(!signature_matches("test-secret", b"tampered", &mac));
    }
}

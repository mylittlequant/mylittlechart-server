//! Login challenge in front of the unauthenticated sign-in routes.
//!
//! Off unless a staff toggle says otherwise (`app_settings` key
//! `login_challenge`). While it is on, `POST /api/auth/account-key`,
//! `POST /api/auth/invite/redeem` and `GET /api/oauth/{provider}/authorize`
//! require a solution. A missing or bad one on the two POSTs is
//! `403 {"error":"challenge_required"}` and does not spend a failure bucket.
//! The authorize GET answers the interstitial page instead, which loads
//! `/api/auth/challenge.js`. Checkout is not behind this gate.
//!
//! The header on the POSTs is `X-Login-Challenge: <id>.<solution>`. The only
//! implementation is proof of work: SHA-256 of the UTF-8 preimage
//! `id + "." + nonce`, accepted when the leading zero bits (MSB first) are
//! at least [`POW_DIFFICULTY`]. A later widget replaces [`PowChallenge`] and
//! the script; the header and the toggle stay.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::models::types::ErrorResponse;
use crate::state::AppState;

/// Leading zero bits (MSB first) a SHA-256 proof of work must show.
/// The staff toggle does not change it.
pub const POW_DIFFICULTY: u32 = 18;

const CHALLENGE_TTL_SECS: i64 = 120;
const MAX_OUTSTANDING: usize = 4096;

const CHALLENGE_JS: &str = include_str!("login_gate.js");
const INTERSTITIAL_HTML: &str = include_str!("login_gate.html");

const SETTINGS_KEY: &str = "login_challenge";

/// One issued challenge, safe to hand to the client.
pub struct IssuedChallenge {
    /// 32 lowercase hex characters.
    pub id: String,
    /// Wire name, `pow` for [`PowChallenge`].
    pub kind: &'static str,
    /// Leading zero bits required. [`POW_DIFFICULTY`] for proof of work.
    pub difficulty: u32,
    /// When the challenge stops being acceptable.
    pub expires_at: DateTime<Utc>,
}

/// Issuing refused: the outstanding cap is still full after expired rows were dropped.
#[derive(Debug, PartialEq, Eq)]
pub struct IssueRefusal;

/// A swappable login challenge. Proof of work is the only implementation.
pub trait LoginChallenge: Send + Sync {
    /// Wire `kind` (`pow` today).
    fn kind(&self) -> &'static str;

    /// Mint one challenge.
    fn issue(&self, now: DateTime<Utc>) -> Result<IssuedChallenge, IssueRefusal>;

    /// `presented` is `id.solution`. `true` has consumed that challenge.
    fn verify(&self, presented: &str, now: DateTime<Utc>) -> bool;
}

/// SHA-256 proof of work. Outstanding challenges live in this process.
pub struct PowChallenge {
    live: Mutex<HashMap<String, DateTime<Utc>>>,
}

impl PowChallenge {
    /// An empty pool.
    pub fn new() -> Self {
        Self { live: Mutex::new(HashMap::new()) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, DateTime<Utc>>> {
        self.live.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl LoginChallenge for PowChallenge {
    fn kind(&self) -> &'static str {
        "pow"
    }

    fn issue(&self, now: DateTime<Utc>) -> Result<IssuedChallenge, IssueRefusal> {
        let mut live = self.lock();
        live.retain(|_, expires_at| *expires_at > now);
        if live.len() >= MAX_OUTSTANDING {
            return Err(IssueRefusal);
        }
        let id = loop {
            let id = random_id();
            if !live.contains_key(&id) {
                break id;
            }
        };
        let expires_at = now + Duration::seconds(CHALLENGE_TTL_SECS);
        live.insert(id.clone(), expires_at);
        Ok(IssuedChallenge { id, kind: self.kind(), difficulty: POW_DIFFICULTY, expires_at })
    }

    fn verify(&self, presented: &str, now: DateTime<Utc>) -> bool {
        let Some((id, nonce)) = split_presented(presented) else {
            return false;
        };
        // A bad nonce must not consume the id. Only a solution that meets the
        // difficulty is taken out of the pool, and only while it is unexpired.
        if !pow_meets(id, nonce) {
            return false;
        }
        let mut live = self.lock();
        match live.remove(id) {
            Some(expires_at) if expires_at > now => true,
            _ => false,
        }
    }
}

fn random_id() -> String {
    let bytes: [u8; 16] = rand::thread_rng().gen();
    hex::encode(bytes)
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn split_presented(presented: &str) -> Option<(&str, &str)> {
    let (id, nonce) = presented.split_once('.')?;
    (is_lower_hex(id, 32) && is_lower_hex(nonce, 16)).then_some((id, nonce))
}

fn pow_meets(id: &str, nonce: &str) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    hasher.update(b".");
    hasher.update(nonce.as_bytes());
    let digest = hasher.finalize();
    leading_zero_bits(&digest) >= POW_DIFFICULTY
}

fn leading_zero_bits(digest: &[u8]) -> u32 {
    let mut bits = 0u32;
    for byte in digest {
        if *byte == 0 {
            bits += 8;
            continue;
        }
        return bits + byte.leading_zeros();
    }
    bits
}

/// `id` and `solution` as the POST header would carry them. `true` consumes the challenge.
pub fn solution_accepted(
    challenge: &(dyn LoginChallenge + Send + Sync),
    id: &str,
    solution: &str,
    now: DateTime<Utc>,
) -> bool {
    challenge.verify(&format!("{id}.{solution}"), now)
}

fn challenge_required() -> Response {
    (StatusCode::FORBIDDEN, Json(ErrorResponse::new("challenge_required"))).into_response()
}

/// `Ok` when the toggle is off or the `X-Login-Challenge` header solves a live challenge.
/// The `Err` response is the 403 and has not spent a failure bucket.
pub fn enforce(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    if !state.login_challenge_enabled() {
        return Ok(());
    }
    let presented = headers.get("x-login-challenge").and_then(|value| value.to_str().ok()).unwrap_or("").trim();
    if state.login_challenge().verify(presented, Utc::now()) {
        Ok(())
    } else {
        Err(challenge_required())
    }
}

/// The page `GET /api/oauth/{provider}/authorize` returns while the toggle is on
/// and the query has no valid solution. No inline script.
pub fn interstitial() -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, "text/html")], INTERSTITIAL_HTML).into_response()
}

/// `GET /api/auth/login-policy`.
pub async fn login_policy(State(state): State<Arc<AppState>>) -> Response {
    if state.login_challenge_enabled() {
        Json(serde_json::json!({ "on": true, "kind": state.login_challenge().kind() })).into_response()
    } else {
        Json(serde_json::json!({ "on": false })).into_response()
    }
}

/// `GET /api/auth/challenge`. 404 while the toggle is off.
pub async fn issue_challenge(State(state): State<Arc<AppState>>) -> Response {
    if !state.login_challenge_enabled() {
        return (StatusCode::NOT_FOUND, Json(ErrorResponse::new("not_found"))).into_response();
    }
    match state.login_challenge().issue(Utc::now()) {
        Ok(issued) => Json(serde_json::json!({
            "id": issued.id,
            "kind": issued.kind,
            "difficulty": issued.difficulty,
            "expires_at": issued.expires_at.to_rfc3339(),
        }))
        .into_response(),
        Err(IssueRefusal) => {
            (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse::new("challenge_unavailable"))).into_response()
        }
    }
}

/// `GET /api/auth/challenge.js`.
pub async fn challenge_script() -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/javascript")], CHALLENGE_JS).into_response()
}

/// The settings table. Missing `login_challenge` row means off.
pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS app_settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );",
    )
}

/// Whether the stored toggle is `on`. Any other value, including no row, is off.
pub fn stored_enabled(conn: &Connection) -> rusqlite::Result<bool> {
    let value: Option<String> = conn
        .query_row("SELECT value FROM app_settings WHERE key = ?1", [SETTINGS_KEY], |row| row.get(0))
        .optional()?;
    Ok(value.as_deref() == Some("on"))
}

/// Write `on` or `off`. Caller holds the transaction that also writes the audit row.
pub fn set_stored(conn: &Connection, on: bool) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO app_settings (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [SETTINGS_KEY, if on { "on" } else { "off" }],
    )?;
    Ok(())
}

/// Brute-force a nonce. Difficulty 18 is expected to land well below `u64::MAX`.
#[cfg(test)]
pub(crate) fn solve_for_test(id: &str) -> String {
    let mut counter = 0u64;
    loop {
        let nonce = format!("{counter:016x}");
        if pow_meets(id, &nonce) {
            return nonce;
        }
        counter = counter.checked_add(1).expect("a difficulty-18 solution exists below u64::MAX");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        is_lower_hex, leading_zero_bits, solve_for_test, CHALLENGE_JS, CHALLENGE_TTL_SECS, INTERSTITIAL_HTML,
        LoginChallenge, MAX_OUTSTANDING, POW_DIFFICULTY, IssueRefusal, PowChallenge,
    };
    use crate::routes::billing::tests::app_state;
    use crate::routes::control_api_router;
    use axum::body::to_bytes;
    use axum::http::{header, HeaderMap, Request, StatusCode};
    use chrono::{DateTime, Duration, Utc};
    use tower::ServiceExt;

    fn t0() -> DateTime<Utc> {
        DateTime::from_timestamp(1_735_689_600, 0).expect("timestamp")
    }

    #[test]
    fn leading_zero_bits_are_counted_from_the_high_bit() {
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x3f]), 18);
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x40]), 17);
        assert_eq!(leading_zero_bits(&[0x80]), 0);
        assert_eq!(POW_DIFFICULTY, 18);
    }

    #[test]
    fn issue_accepts_one_solution_and_rejects_replay_expiry_and_a_short_nonce() {
        let pow = PowChallenge::new();
        let at = t0();
        let issued = pow.issue(at).expect("issue");
        assert_eq!(issued.id.len(), 32);
        assert!(is_lower_hex(&issued.id, 32));
        assert_eq!(issued.kind, "pow");
        assert_eq!(issued.difficulty, POW_DIFFICULTY);
        assert_eq!(issued.expires_at, at + Duration::seconds(CHALLENGE_TTL_SECS));

        let nonce = solve_for_test(&issued.id);
        assert_eq!(nonce.len(), 16);
        let header = format!("{}.{nonce}", issued.id);
        assert!(pow.verify(&header, at), "one solution");
        assert!(!pow.verify(&header, at), "replay");

        let other = pow.issue(at).expect("second issue");
        let stolen = format!("{}.{}", other.id, solve_for_test(&issued.id));
        assert!(!pow.verify(&stolen, at), "a solution does not transfer");
        let own = format!("{}.{}", other.id, solve_for_test(&other.id));
        assert!(!pow.verify(&own, at + Duration::seconds(CHALLENGE_TTL_SECS)), "expired");

        let live = pow.issue(at).expect("third issue");
        assert!(!pow.verify(&format!("{}.abc", live.id), at), "short nonce");
        assert!(!pow.verify(&format!("{}.{}", live.id, "000000000000000"), at), "15 hex chars");
        assert!(
            pow.verify(&format!("{}.{}", live.id, solve_for_test(&live.id)), at),
            "a short nonce does not consume the challenge"
        );
    }

    #[test]
    fn a_full_pool_evicts_expired_challenges_before_refusing_a_new_one() {
        let pow = PowChallenge::new();
        let at = t0();
        for _ in 0..MAX_OUTSTANDING {
            pow.issue(at).expect("fill");
        }
        assert_eq!(pow.issue(at).err(), Some(IssueRefusal));
        assert!(pow.issue(at + Duration::seconds(CHALLENGE_TTL_SECS)).is_ok(), "expired rows are dropped first");
    }

    #[test]
    fn the_interstitial_loads_the_script_and_the_script_keeps_the_query() {
        assert_eq!(INTERSTITIAL_HTML.matches("<script").count(), 1);
        assert!(INTERSTITIAL_HTML.contains("<script src=\"/api/auth/challenge.js\"></script>"));
        assert!(!INTERSTITIAL_HTML.contains("http://") && !INTERSTITIAL_HTML.contains("https://"));
        assert!(CHALLENGE_JS.contains("\"/api/auth/challenge\""));
        assert!(CHALLENGE_JS.contains("searchParams.set(\"challenge_id\""));
        assert!(CHALLENGE_JS.contains("searchParams.set(\"challenge_solution\""));
        assert!(CHALLENGE_JS.contains("window.location"));
        assert!(!CHALLENGE_JS.contains("http://") && !CHALLENGE_JS.contains("https://"));
        assert!(!CHALLENGE_JS.contains("document.cookie"));
    }

    async fn raw(router: &axum::Router, uri: &str) -> (StatusCode, HeaderMap, String) {
        let request = Request::builder().uri(uri).body(axum::body::Body::empty()).expect("request");
        let response = router.clone().oneshot(request).await.expect("router");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.expect("body");
        (status, headers, String::from_utf8(bytes.to_vec()).expect("utf-8"))
    }

    #[tokio::test]
    async fn authorize_shows_the_interstitial_until_the_query_solves_the_challenge() {
        let state = app_state(None);
        let router = control_api_router(state.clone());
        let open = "/oauth/github/authorize?redirect_port=17421&device_code=AB12&link=1";

        let (status, headers, _) = raw(&router, open).await;
        assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
        let location = headers.get(header::LOCATION).and_then(|v| v.to_str().ok()).unwrap_or("");
        assert!(location.starts_with("https://github.com/login/oauth/authorize"), "{location}");

        state.set_login_challenge_enabled(true);
        let (status, headers, body) = raw(&router, open).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()), Some("text/html"));
        assert!(headers.get(header::LOCATION).is_none());
        assert_eq!(body, INTERSTITIAL_HTML);

        let (status, headers, bad) = raw(&router, &format!("{open}&challenge_id=ab&challenge_solution=00")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()), Some("text/html"));
        assert_eq!(bad, body, "a bad solution and a missing one are the same page");

        let (status, headers, script) = raw(&router, "/auth/challenge.js").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()), Some("application/javascript"));
        assert_eq!(script, CHALLENGE_JS);

        let issued = state.login_challenge().issue(Utc::now()).expect("issue");
        let nonce = solve_for_test(&issued.id);
        let solved = format!("{open}&challenge_id={}&challenge_solution={nonce}", issued.id);
        let (status, headers, _) = raw(&router, &solved).await;
        assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
        assert!(headers.get(header::LOCATION).and_then(|v| v.to_str().ok()).unwrap_or("").starts_with("https://github.com/"));
        let (status, _, again) = raw(&router, &solved).await;
        assert_eq!(status, StatusCode::OK, "replay is not a redirect");
        assert_eq!(again, INTERSTITIAL_HTML);
    }
}

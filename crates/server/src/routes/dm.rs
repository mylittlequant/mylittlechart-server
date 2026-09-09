//! Direct messages — paid, end-to-end encrypted (owner ruling 2026-09-05,
//! `docs/mlc/plans/social-sharing-access-gates-and-agent-control-2026-09-05.md`
//! §3 item 6 + §6). Storage is `dm_db.rs`, in `social.db` — see that
//! module's doc for the exact tables and the crypto contract
//! (`mlc_vault::dm`) this server never participates in.
//!
//! **What the server sees:** who published a DM identity key, who talked to
//! whom and when, and each message's size. **What it never sees: message
//! contents.** `nonce`/`ciphertext` are opaque bytes end to end — there is
//! no server-side key to open them, so there is no moderation action for a
//! DM's body the way `routes::forum_v2::moderate_thread` has one for a
//! thread's. The only lever over an abusive DM account is revoking its paid
//! status, which closes every route below (see [`require_dm_access`]).
//!
//! Every route requires both an authenticated AND a paid caller
//! ([`require_dm_access`], same `entitlements::Feature::Forum` gate
//! `routes::forum` uses — the plan's own words for it: "Feature::Forum
//! today stands for the paid social tier"). Wherever a route also names a
//! second account (conversation creation, sending a message), that
//! account's OWN paid status is checked too ([`require_peer_paid`]) —
//! together the two checks are the plan's "both parties must be paid".
//!
//! Endpoints (all under `/api`, all authed + paid):
//!  - `PUT    /dm/identity`                              — publish/rotate
//!                                                          own DM public key.
//!  - `GET    /dm/identity/{public_id_or_nick}`           — a user's public
//!                                                          key + fingerprint.
//!  - `GET    /dm/lookup?q=`                              — recipient search
//!                                                          by nick/display
//!                                                          name: paid
//!                                                          accounts with a
//!                                                          published DM
//!                                                          identity key
//!                                                          only, ranked
//!                                                          exact/prefix/
//!                                                          substring/fuzzy
//!                                                          (see
//!                                                          [`lookup_recipients`]).
//!  - `POST   /dm/conversations`                          — `{with}` ->
//!                                                          existing or new
//!                                                          conversation.
//!  - `GET    /dm/conversations`                          — mine, with peer
//!                                                          label + unread.
//!  - `POST   /dm/conversations/{id}/messages`             — send a sealed
//!                                                          message.
//!  - `GET    /dm/conversations/{id}/messages?after=&limit=` — page through
//!                                                          ciphertext rows.
//!  - `POST   /dm/conversations/{id}/read`                 — `{up_to_id}`.
//!
//! No admin endpoints exist for this module — see the module doc above on
//! why moderation of DM content is not a thing that can exist here.

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::sync::Arc;

use crate::auth::{extract_bearer, extract_session_id, extract_ua_hash, hash_token};
use crate::db;
use crate::dm_db;
use crate::entitlements::{self, Feature};
use crate::models::types::ErrorResponse;
use crate::state::AppState;

const DEFAULT_MESSAGE_LIMIT: i64 = 50;
const MAX_MESSAGE_LIMIT: i64 = 200;

/// Fixed reporting window for [`dm_rate_limited`]'s `retry_after_secs` —
/// same simplification `routes::forum`'s `rate_limited` makes: a client
/// hitting a daily cap already implies backing off for a while, so an exact
/// remainder is not worth computing.
const DM_RATE_LIMIT_WINDOW_SECS: i64 = 24 * 60 * 60;

// ============================================================================
// Response helpers
// ============================================================================

fn internal_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse::new("Internal error")),
    )
        .into_response()
}

fn bad_request(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(ErrorResponse::new(msg))).into_response()
}

fn forbidden(msg: &str) -> Response {
    (StatusCode::FORBIDDEN, Json(ErrorResponse::new(msg))).into_response()
}

fn payload_too_large(msg: &str) -> Response {
    (StatusCode::PAYLOAD_TOO_LARGE, Json(ErrorResponse::new(msg))).into_response()
}

fn dm_rate_limited() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(serde_json::json!({
            "error": "rate limit exceeded",
            "retry_after_secs": DM_RATE_LIMIT_WINDOW_SECS,
        })),
    )
        .into_response()
}

fn message_error_response(e: dm_db::MessageError) -> Response {
    match e {
        dm_db::MessageError::InvalidNonceLength => {
            bad_request(&format!("nonce_b64 must decode to exactly {} bytes", dm_db::DM_NONCE_LEN))
        }
        dm_db::MessageError::TooLarge => payload_too_large(&format!(
            "ciphertext_b64 must decode to at most {} bytes",
            dm_db::DM_MAX_CIPHERTEXT_BYTES
        )),
        dm_db::MessageError::Db(e) => {
            tracing::error!("DB error in dm route: {}", e);
            internal_error()
        }
    }
}

// ============================================================================
// Auth + paid-entitlement gate — mirrors routes::forum's
// resolve_user_id/require_forum_access (duplicated rather than shared,
// following this codebase's one-copy-per-route-module convention).
// ============================================================================

async fn resolve_user_id(state: Arc<AppState>, headers: &HeaderMap) -> Result<i64, StatusCode> {
    let session_id = extract_session_id(headers);
    let ua_hash = extract_ua_hash(headers);
    let bearer: Option<String> = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| extract_bearer(Some(v)))
        .map(|s| s.to_owned());

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<i64>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(sid) = session_id {
            if let Some(uid) = db::resolve_web_session(&conn, &sid, &ua_hash)? {
                return Ok(Some(uid));
            }
        }
        if let Some(raw_token) = bearer {
            let token_hash = hash_token(&raw_token);
            if let Some(uid) = db::resolve_token_hash_with_expiry(&conn, &token_hash)? {
                return Ok(Some(uid));
            }
        }
        Ok(None)
    })
    .await;

    match result {
        Ok(Ok(Some(uid))) => Ok(uid),
        Ok(Ok(None)) => Err(StatusCode::UNAUTHORIZED),
        Ok(Err(_)) | Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn auth_err(status: StatusCode) -> Response {
    match status {
        StatusCode::UNAUTHORIZED => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Authentication required")),
        )
            .into_response(),
        _ => internal_error(),
    }
}

fn not_paid_err() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorResponse::new("paid account required for direct messages")),
    )
        .into_response()
}

/// The one entitlement gate every route in this module runs through:
/// resolve the caller (401 if anonymous), then require `Feature::Forum`
/// (403 if not paid) — see `routes::forum::require_forum_access`, the same
/// shape. Returns the caller's `user_id` on success.
async fn require_dm_access(state: Arc<AppState>, headers: &HeaderMap) -> Result<i64, Response> {
    let user_id = resolve_user_id(state.clone(), headers).await.map_err(auth_err)?;

    let paid_result = tokio::task::spawn_blocking({
        let state = state.clone();
        move || -> rusqlite::Result<bool> {
            let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            db::user_is_paid(&conn, user_id)
        }
    })
    .await;

    let is_paid = match paid_result {
        Ok(Ok(paid)) => paid,
        Ok(Err(e)) => {
            tracing::error!("DB error checking paid status for dm access: {}", e);
            return Err(internal_error());
        }
        Err(_) => return Err(internal_error()),
    };

    if !entitlements::resolve_for_user(is_paid).contains(Feature::Forum) {
        return Err(not_paid_err());
    }
    Ok(user_id)
}

/// Refuse an action naming a second account that is not currently paid —
/// the other half of the plan's "both parties must be paid" (the caller's
/// own half is [`require_dm_access`], which every route runs first).
fn require_peer_paid(peer_is_paid: bool) -> Result<(), Response> {
    if peer_is_paid {
        Ok(())
    } else {
        Err(forbidden("the other account does not have a paid plan"))
    }
}

// ============================================================================
// User resolution by public_id or nick — not in `db.rs` (this module's own
// files are the only ones touched besides registration lines), so this is a
// direct query against the identity connection rather than a shared helper.
// ============================================================================

/// Resolve a `public_id` or nick (case-insensitive) to a `user_id`.
fn resolve_user_by_label(conn: &rusqlite::Connection, label: &str) -> rusqlite::Result<Option<i64>> {
    use rusqlite::{params, OptionalExtension};
    conn.query_row(
        "SELECT id FROM users WHERE public_id = ?1 OR LOWER(nick) = LOWER(?1) LIMIT 1",
        params![label],
        |row| row.get(0),
    )
    .optional()
}

/// `public_id` for `user_id`, or a fixed placeholder if the account is gone
/// — same "never let a stale foreign id 500 a listing" posture
/// `db::forum_author_label` takes for a display label.
fn public_id_or_placeholder(conn: &rusqlite::Connection, user_id: i64) -> rusqlite::Result<String> {
    use rusqlite::{params, OptionalExtension};
    Ok(conn
        .query_row(
            "SELECT public_id FROM users WHERE id = ?1",
            params![user_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten()
        .unwrap_or_else(|| "deleted-account".to_string()))
}

// ============================================================================
// PUT /api/dm/identity
// ============================================================================

#[derive(serde::Deserialize)]
pub struct PublishIdentityRequest {
    pub public_key_b64: String,
}

/// `PUT /dm/identity` — `{"public_key_b64": "..."}` -> `{"fingerprint": "..."}`.
/// A second call rotates the key in place (see `dm_db::upsert_identity_key`).
pub async fn publish_identity(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<PublishIdentityRequest>,
) -> Response {
    let user_id = match require_dm_access(state.clone(), &headers).await {
        Ok(uid) => uid,
        Err(resp) => return resp,
    };
    let public_key = match STANDARD.decode(&req.public_key_b64) {
        Ok(bytes) => bytes,
        Err(_) => return bad_request("public_key_b64 must be valid base64"),
    };

    let result = tokio::task::spawn_blocking(move || -> std::result::Result<String, dm_db::IdentityKeyError> {
        let conn = state.control_plane().social_conn();
        dm_db::upsert_identity_key(&conn, user_id, &public_key, &chrono::Utc::now().to_rfc3339())
    })
    .await;

    match result {
        Ok(Ok(fingerprint)) => Json(serde_json::json!({ "fingerprint": fingerprint })).into_response(),
        Ok(Err(dm_db::IdentityKeyError::InvalidLength)) => {
            bad_request(&format!("public_key_b64 must decode to exactly {} bytes", dm_db::DM_PUBLIC_KEY_LEN))
        }
        Ok(Err(dm_db::IdentityKeyError::Db(e))) => {
            tracing::error!("DB error publishing dm identity key: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// GET /api/dm/identity/{public_id_or_nick}
// ============================================================================

/// `GET /dm/identity/{public_id_or_nick}` -> `{"public_id","label",
/// "public_key_b64","fingerprint"}`. 404 if the label names no user, or the
/// user exists but has never published a DM identity key — both cases are
/// indistinguishable to the caller, same "no distinguishable states"
/// posture `routes::forum` uses for a hidden thread.
pub async fn get_identity(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(label): Path<String>) -> Response {
    if let Err(resp) = require_dm_access(state.clone(), &headers).await {
        return resp;
    }

    type IdentityLookup = Option<(String, String, Option<dm_db::DmIdentityKey>)>;
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<IdentityLookup> {
        let identity_conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let Some(target_id) = resolve_user_by_label(&identity_conn, &label)? else {
            return Ok(None);
        };
        let public_id = db::get_user_public_id(&identity_conn, target_id)?;
        let display_label = db::effective_label_for_user(&identity_conn, target_id)?;
        drop(identity_conn);

        let social_conn = state.control_plane().social_conn();
        let key = dm_db::get_identity_key(&social_conn, target_id)?;
        Ok(Some((public_id, display_label, key)))
    })
    .await;

    match result {
        Ok(Ok(Some((public_id, display_label, Some(key))))) => Json(serde_json::json!({
            "public_id": public_id,
            "label": display_label,
            "public_key_b64": STANDARD.encode(&key.public_key),
            "fingerprint": key.fingerprint,
        }))
        .into_response(),
        Ok(Ok(Some((_, _, None)))) | Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error fetching dm identity: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// GET /api/dm/lookup?q=
// ============================================================================

/// A trimmed, lowercased query longer than this is truncated rather than
/// refused — generous for a real nick/display-name search while bounding the
/// cost of scoring every candidate against it.
const MAX_LOOKUP_QUERY_LEN: usize = 64;

/// How many ranked matches [`lookup_recipients`] returns at most.
const MAX_LOOKUP_RESULTS: usize = 10;

/// Ceiling on how many currently-paid accounts one lookup call loads from the
/// identity database before scoring in Rust — the table is small enough that
/// a single unfiltered-by-text query plus in-process ranking beats a second
/// LIKE-shaped query per keystroke (same reasoning `db::search_users` skips
/// for its own, admin-only, already-`LIKE`-filtered query).
const PAID_CANDIDATE_LIMIT: i64 = 5000;

/// A fuzzy match is only offered once the query is long enough that a
/// distance-1 typo is unlikely to also match something unrelated; a longer
/// query is allowed a distance of 2.
const FUZZY_SHORT_QUERY_MAX_LEN: usize = 4;
const FUZZY_DISTANCE_SHORT_QUERY: usize = 1;
const FUZZY_DISTANCE_LONG_QUERY: usize = 2;

#[derive(serde::Deserialize)]
pub struct LookupQuery {
    pub q: Option<String>,
}

#[derive(serde::Serialize)]
struct LookupUser {
    public_id: String,
    nick: Option<String>,
    label: String,
    rank: u8,
}

/// One row loaded from the identity database: a currently-paid account,
/// before it is known whether it also published a DM identity key (checked
/// separately against the social connection — see [`lookup_recipients`]).
struct PaidCandidate {
    id: i64,
    nick: Option<String>,
    display_name: String,
    public_id: String,
}

/// The label [`db::effective_label_for_user`] would compute for the same
/// three columns — inlined here (rather than a second per-row identity
/// query) because [`lookup_recipients`] already has `nick`/`display_name`/
/// `public_id` in hand from its one candidate-loading query.
fn effective_label_from_parts(nick: Option<&str>, display_name: &str, public_id: &str) -> String {
    nick.filter(|n| !n.is_empty())
        .or_else(|| Some(display_name).filter(|d| !d.is_empty()))
        .unwrap_or(public_id)
        .to_string()
}

/// Optimal-string-alignment (restricted) Damerau-Levenshtein distance
/// between `a` and `b`: insertion, deletion, substitution, and swapping two
/// ADJACENT characters each cost 1 — a transposed pair such as `"ab"` vs
/// `"ba"` is distance 1, not 2, but (unlike full Damerau-Levenshtein) a
/// character already involved in a transposition cannot be edited again in
/// the same step. Counts Unicode scalar values, not bytes, so it works the
/// same on non-ASCII nicks/names.
fn osa_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (len_a, len_b) = (a.len(), b.len());
    if len_a == 0 {
        return len_b;
    }
    if len_b == 0 {
        return len_a;
    }

    let mut dp = vec![vec![0usize; len_b + 1]; len_a + 1];
    for (i, row) in dp.iter_mut().enumerate() {
        row[0] = i;
    }
    for j in 0..=len_b {
        dp[0][j] = j;
    }
    for i in 1..=len_a {
        for j in 1..=len_b {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (dp[i - 1][j] + 1) // deletion
                .min(dp[i][j - 1] + 1) // insertion
                .min(dp[i - 1][j - 1] + cost); // match/substitution
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(dp[i - 2][j - 2] + 1); // adjacent transposition
            }
            dp[i][j] = best;
        }
    }
    dp[len_a][len_b]
}

/// Score one candidate against an already-trimmed-lowercased `query`,
/// ranked exactly as `routes::dm`'s module doc lists (lower is a better
/// match): exact nick (0), nick prefix (1), display-name prefix (2),
/// substring in either (3), fuzzy match on the nick or on any
/// whitespace-separated word of the display name (4). `None` if nothing
/// matches at all. `nick`/`display_name` are the candidate's raw (mixed-
/// case) stored values; this function lowercases its own copies rather than
/// requiring the caller to.
fn rank_candidate(query: &str, nick: Option<&str>, display_name: &str) -> Option<u8> {
    let nick_lower = nick.map(str::to_lowercase);
    let display_lower = display_name.to_lowercase();

    if nick_lower.as_deref() == Some(query) {
        return Some(0);
    }
    if nick_lower.as_deref().is_some_and(|n| n.starts_with(query)) {
        return Some(1);
    }
    if display_lower.starts_with(query) {
        return Some(2);
    }
    if nick_lower.as_deref().is_some_and(|n| n.contains(query)) || display_lower.contains(query) {
        return Some(3);
    }

    let max_distance = if query.chars().count() <= FUZZY_SHORT_QUERY_MAX_LEN {
        FUZZY_DISTANCE_SHORT_QUERY
    } else {
        FUZZY_DISTANCE_LONG_QUERY
    };
    if nick_lower.as_deref().is_some_and(|n| osa_distance(n, query) <= max_distance) {
        return Some(4);
    }
    if display_lower.split_whitespace().any(|word| osa_distance(word, query) <= max_distance) {
        return Some(4);
    }
    None
}

/// `GET /dm/lookup?q=<text>` -> `{"users": [{"public_id","nick","label",
/// "rank"}]}`, sorted by rank then label, at most [`MAX_LOOKUP_RESULTS`].
/// Same [`require_dm_access`] gate as every other route here — only a paid
/// caller can search for a DM recipient. A candidate must be BOTH currently
/// paid (a DM recipient's own gate) AND have published a DM identity key (a
/// paid account that never called `PUT /dm/identity` cannot receive
/// anything yet, same posture [`get_identity`] takes) — two queries, one
/// against the identity connection and one batched against the social
/// connection, never a cross-database join (see `dm_db`'s module doc). The
/// caller itself is excluded from its own results.
pub async fn lookup_recipients(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<LookupQuery>,
) -> Response {
    let caller_id = match require_dm_access(state.clone(), &headers).await {
        Ok(uid) => uid,
        Err(resp) => return resp,
    };

    let q = match query.q.as_deref().map(|s| s.trim().to_lowercase()) {
        Some(q) if !q.is_empty() => q,
        _ => return bad_request("q required"),
    };
    let q: String = q.chars().take(MAX_LOOKUP_QUERY_LEN).collect();

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Vec<LookupUser>> {
        use rusqlite::params;

        let identity_conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now().to_rfc3339();
        let mut candidates = Vec::new();
        {
            let mut stmt = identity_conn.prepare(
                "SELECT id, nick, display_name, public_id FROM users
                 WHERE paid_until IS NOT NULL AND paid_until > ?1 AND id != ?2
                 LIMIT ?3",
            )?;
            let mut rows = stmt.query(params![now, caller_id, PAID_CANDIDATE_LIMIT])?;
            while let Some(row) = rows.next()? {
                candidates.push(PaidCandidate {
                    id: row.get(0)?,
                    nick: row.get(1)?,
                    display_name: row.get(2)?,
                    public_id: row.get(3)?,
                });
            }
        }
        drop(identity_conn);
        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        let ids: Vec<i64> = candidates.iter().map(|c| c.id).collect();
        let social_conn = state.control_plane().social_conn();
        let keyed = dm_db::identity_key_owner_ids(&social_conn, &ids)?;
        drop(social_conn);

        let mut matched: Vec<LookupUser> = candidates
            .into_iter()
            .filter(|c| keyed.contains(&c.id))
            .filter_map(|c| {
                let rank = rank_candidate(&q, c.nick.as_deref(), &c.display_name)?;
                let label = effective_label_from_parts(c.nick.as_deref(), &c.display_name, &c.public_id);
                Some(LookupUser {
                    public_id: c.public_id,
                    nick: c.nick,
                    label,
                    rank,
                })
            })
            .collect();
        matched.sort_by(|a, b| a.rank.cmp(&b.rank).then_with(|| a.label.cmp(&b.label)));
        matched.truncate(MAX_LOOKUP_RESULTS);
        Ok(matched)
    })
    .await;

    match result {
        Ok(Ok(users)) => Json(serde_json::json!({ "users": users })).into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error in dm recipient lookup: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// POST /api/dm/conversations
// ============================================================================

#[derive(serde::Deserialize)]
pub struct CreateConversationRequest {
    pub with: String,
}

/// `POST /dm/conversations` — `{"with":"<public_id_or_nick>"}` -> existing
/// or new `{"id", "peer": {"label","public_id","fingerprint"}}`.
pub async fn create_conversation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateConversationRequest>,
) -> Response {
    let user_id = match require_dm_access(state.clone(), &headers).await {
        Ok(uid) => uid,
        Err(resp) => return resp,
    };
    let with_label = req.with.trim().to_string();
    if with_label.is_empty() {
        return bad_request("with must not be empty");
    }

    type PeerLookup = Option<(i64, bool, String, String)>;
    let peer = tokio::task::spawn_blocking({
        let state = state.clone();
        move || -> rusqlite::Result<PeerLookup> {
            let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            let Some(peer_id) = resolve_user_by_label(&conn, &with_label)? else {
                return Ok(None);
            };
            let peer_paid = db::user_is_paid(&conn, peer_id)?;
            let public_id = db::get_user_public_id(&conn, peer_id)?;
            let label = db::effective_label_for_user(&conn, peer_id)?;
            Ok(Some((peer_id, peer_paid, public_id, label)))
        }
    })
    .await;

    let (peer_id, peer_paid, peer_public_id, peer_label) = match peer {
        Ok(Ok(Some(v))) => v,
        Ok(Ok(None)) => return StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error resolving dm conversation peer: {}", e);
            return internal_error();
        }
        Err(_) => return internal_error(),
    };

    if peer_id == user_id {
        return bad_request("cannot start a conversation with yourself");
    }
    if let Err(resp) = require_peer_paid(peer_paid) {
        return resp;
    }

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<(i64, Option<String>)> {
        let conn = state.control_plane().social_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let conversation = dm_db::get_or_create_conversation(&conn, user_id, peer_id, &now)?;
        let fingerprint = dm_db::get_identity_key(&conn, peer_id)?.map(|k| k.fingerprint);
        Ok((conversation.id, fingerprint))
    })
    .await;

    match result {
        Ok(Ok((id, fingerprint))) => Json(serde_json::json!({
            "id": id,
            "peer": {
                "label": peer_label,
                "public_id": peer_public_id,
                "fingerprint": fingerprint,
            },
        }))
        .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error creating dm conversation: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// GET /api/dm/conversations
// ============================================================================

/// `GET /dm/conversations` -> `{"conversations": [{"id","peer":{"label",
/// "public_id"},"last_message_at","unread_count"}]}`, newest activity first.
pub async fn list_conversations(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user_id = match require_dm_access(state.clone(), &headers).await {
        Ok(uid) => uid,
        Err(resp) => return resp,
    };

    type Row = (dm_db::ConversationSummary, String, String);
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Vec<Row>> {
        let social_conn = state.control_plane().social_conn();
        let summaries = dm_db::list_conversations_for_user(&social_conn, user_id)?;
        drop(social_conn);

        let identity_conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::with_capacity(summaries.len());
        for summary in summaries {
            // Every row here came from a query filtered to conversations
            // where `user_id` IS a party (see `list_conversations_for_user`),
            // so `peer_of` is always `Some` — the fallback is unreachable
            // defensive code, not a real branch.
            let peer_id = summary.conversation.peer_of(user_id).unwrap_or(user_id);
            let peer_public_id = public_id_or_placeholder(&identity_conn, peer_id)?;
            let peer_label = db::effective_label_for_user(&identity_conn, peer_id)?;
            out.push((summary, peer_public_id, peer_label));
        }
        Ok(out)
    })
    .await;

    match result {
        Ok(Ok(rows)) => Json(serde_json::json!({
            "conversations": rows.iter().map(|(summary, peer_public_id, peer_label)| serde_json::json!({
                "id": summary.conversation.id,
                "peer": { "label": peer_label, "public_id": peer_public_id },
                "last_message_at": summary.conversation.last_message_at,
                "unread_count": summary.unread_count,
            })).collect::<Vec<_>>(),
        }))
        .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error listing dm conversations: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// POST /api/dm/conversations/{id}/messages
// ============================================================================

enum SendMessageRefusal {
    /// The conversation does not exist, or `user_id` is not one of its two
    /// parties — indistinguishable, same as a hidden forum thread.
    NotFound,
    PeerNotPaid,
    RateLimited,
    Message(dm_db::MessageError),
}

impl From<rusqlite::Error> for SendMessageRefusal {
    fn from(e: rusqlite::Error) -> Self {
        SendMessageRefusal::Message(dm_db::MessageError::Db(e))
    }
}

fn send_message_refusal_response(e: SendMessageRefusal) -> Response {
    match e {
        SendMessageRefusal::NotFound => StatusCode::NOT_FOUND.into_response(),
        SendMessageRefusal::PeerNotPaid => forbidden("the other account does not have a paid plan"),
        SendMessageRefusal::RateLimited => dm_rate_limited(),
        SendMessageRefusal::Message(e) => message_error_response(e),
    }
}

#[derive(serde::Deserialize)]
pub struct SendMessageRequest {
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

/// `POST /dm/conversations/{id}/messages` —
/// `{"nonce_b64":"...","ciphertext_b64":"..."}` -> `{"id","created_at"}`.
/// The sender must be a party to the conversation; the OTHER party must
/// currently be paid (re-checked here, not just at conversation creation —
/// see the module doc); rate-limited to
/// [`dm_db::DM_MESSAGE_DAILY_LIMIT`] per rolling day per sender.
pub async fn create_message(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(conversation_id): Path<i64>,
    Json(req): Json<SendMessageRequest>,
) -> Response {
    let user_id = match require_dm_access(state.clone(), &headers).await {
        Ok(uid) => uid,
        Err(resp) => return resp,
    };
    let nonce = match STANDARD.decode(&req.nonce_b64) {
        Ok(b) => b,
        Err(_) => return bad_request("nonce_b64 must be valid base64"),
    };
    let ciphertext = match STANDARD.decode(&req.ciphertext_b64) {
        Ok(b) => b,
        Err(_) => return bad_request("ciphertext_b64 must be valid base64"),
    };
    if ciphertext.len() > dm_db::DM_MAX_CIPHERTEXT_BYTES {
        return payload_too_large(&format!(
            "ciphertext_b64 must decode to at most {} bytes",
            dm_db::DM_MAX_CIPHERTEXT_BYTES
        ));
    }

    let result = tokio::task::spawn_blocking(
        move || -> std::result::Result<(i64, String), SendMessageRefusal> {
            let social_conn = state.control_plane().social_conn();
            let Some(conversation) = dm_db::get_conversation(&social_conn, conversation_id)? else {
                return Err(SendMessageRefusal::NotFound);
            };
            let Some(peer_id) = conversation.peer_of(user_id) else {
                return Err(SendMessageRefusal::NotFound);
            };
            drop(social_conn);

            let identity_conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            let peer_paid = db::user_is_paid(&identity_conn, peer_id)?;
            drop(identity_conn);
            if !peer_paid {
                return Err(SendMessageRefusal::PeerNotPaid);
            }

            let social_conn = state.control_plane().social_conn();
            let now = chrono::Utc::now();
            let since = (now - chrono::Duration::hours(24)).to_rfc3339();
            let recent = dm_db::messages_sent_since(&social_conn, user_id, &since)?;
            if recent >= dm_db::DM_MESSAGE_DAILY_LIMIT {
                return Err(SendMessageRefusal::RateLimited);
            }
            let now_str = now.to_rfc3339();
            let id = dm_db::create_message(&social_conn, conversation_id, user_id, &nonce, &ciphertext, &now_str)
                .map_err(SendMessageRefusal::Message)?;
            Ok((id, now_str))
        },
    )
    .await;

    match result {
        Ok(Ok((id, created_at))) => Json(serde_json::json!({ "id": id, "created_at": created_at })).into_response(),
        Ok(Err(e)) => send_message_refusal_response(e),
        Err(_) => internal_error(),
    }
}

// ============================================================================
// GET /api/dm/conversations/{id}/messages
// ============================================================================

#[derive(serde::Deserialize)]
pub struct ListMessagesQuery {
    pub after: Option<i64>,
    pub limit: Option<i64>,
}

/// `GET /dm/conversations/{id}/messages?after=&limit=` -> `{"messages":
/// [{"id","sender_public_id","sender_is_me","nonce_b64","ciphertext_b64",
/// "created_at","read_at"}], "next_after"}`. 404 if the conversation does
/// not exist or the caller is not a party.
pub async fn list_messages(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(conversation_id): Path<i64>,
    Query(query): Query<ListMessagesQuery>,
) -> Response {
    let user_id = match require_dm_access(state.clone(), &headers).await {
        Ok(uid) => uid,
        Err(resp) => return resp,
    };
    let limit = query.limit.unwrap_or(DEFAULT_MESSAGE_LIMIT).clamp(1, MAX_MESSAGE_LIMIT);

    type Row = (dm_db::DmMessage, String);
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<Vec<Row>>> {
        let social_conn = state.control_plane().social_conn();
        let Some(conversation) = dm_db::get_conversation(&social_conn, conversation_id)? else {
            return Ok(None);
        };
        if conversation.peer_of(user_id).is_none() {
            return Ok(None);
        }
        let messages = dm_db::list_messages(&social_conn, conversation_id, query.after, limit)?;
        drop(social_conn);

        let identity_conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::with_capacity(messages.len());
        for message in messages {
            let sender_public_id = public_id_or_placeholder(&identity_conn, message.sender_user_id)?;
            out.push((message, sender_public_id));
        }
        Ok(Some(out))
    })
    .await;

    match result {
        Ok(Ok(Some(rows))) => {
            let next_after = rows.last().map(|(m, _)| m.id);
            Json(serde_json::json!({
                "messages": rows.iter().map(|(m, sender_public_id)| serde_json::json!({
                    "id": m.id,
                    "sender_public_id": sender_public_id,
                    "sender_is_me": m.sender_user_id == user_id,
                    "nonce_b64": STANDARD.encode(&m.nonce),
                    "ciphertext_b64": STANDARD.encode(&m.ciphertext),
                    "created_at": m.created_at,
                    "read_at": m.read_at,
                })).collect::<Vec<_>>(),
                "next_after": next_after,
            }))
            .into_response()
        }
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error listing dm messages: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// POST /api/dm/conversations/{id}/read
// ============================================================================

#[derive(serde::Deserialize)]
pub struct MarkReadRequest {
    pub up_to_id: i64,
}

/// `POST /dm/conversations/{id}/read` — `{"up_to_id": N}`. Marks every
/// message sent by the OTHER party with `id <= up_to_id` as read. 204 on
/// success, 404 if the conversation does not exist or the caller is not a
/// party.
pub async fn mark_read(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(conversation_id): Path<i64>,
    Json(req): Json<MarkReadRequest>,
) -> Response {
    let user_id = match require_dm_access(state.clone(), &headers).await {
        Ok(uid) => uid,
        Err(resp) => return resp,
    };

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
        let conn = state.control_plane().social_conn();
        let Some(conversation) = dm_db::get_conversation(&conn, conversation_id)? else {
            return Ok(false);
        };
        if conversation.peer_of(user_id).is_none() {
            return Ok(false);
        }
        let now = chrono::Utc::now().to_rfc3339();
        dm_db::mark_read(&conn, conversation_id, user_id, req.up_to_id, &now)?;
        Ok(true)
    })
    .await;

    match result {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error marking dm messages read: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- paid gate ----

    #[test]
    fn require_peer_paid_allows_a_paid_peer_and_refuses_an_unpaid_one() {
        assert!(require_peer_paid(true).is_ok());
        assert!(require_peer_paid(false).is_err());
    }

    // ---- lookup: osa_distance ----

    #[test]
    fn osa_distance_of_identical_strings_is_zero() {
        assert_eq!(osa_distance("kosti", "kosti"), 0);
        assert_eq!(osa_distance("", ""), 0);
    }

    #[test]
    fn osa_distance_counts_an_adjacent_transposition_as_one_not_two() {
        // Plain Levenshtein would need a delete + insert (2) for this pair;
        // OSA recognises the swapped adjacent pair as a single edit.
        assert_eq!(osa_distance("ab", "ba"), 1);
        assert_eq!(osa_distance("kosti", "kosit"), 1);
    }

    #[test]
    fn osa_distance_against_empty_input_is_the_other_strings_length() {
        assert_eq!(osa_distance("", "abc"), 3);
        assert_eq!(osa_distance("abc", ""), 3);
    }

    #[test]
    fn osa_distance_counts_unicode_scalar_values_not_bytes() {
        // "über" vs "uber": one substitution (ü -> u), not the multi-byte
        // UTF-8 distance a byte-wise comparison would report.
        assert_eq!(osa_distance("über", "uber"), 1);
    }

    // ---- lookup: rank_candidate ----

    #[test]
    fn rank_candidate_prefers_exact_nick_over_every_other_tier() {
        assert_eq!(rank_candidate("kosti", Some("kosti"), "Someone Else"), Some(0));
    }

    #[test]
    fn rank_candidate_orders_nick_prefix_above_display_name_prefix() {
        assert_eq!(rank_candidate("kos", Some("kosti"), "kostroma events"), Some(1));
        assert_eq!(rank_candidate("kos", None, "kostroma events"), Some(2));
    }

    #[test]
    fn rank_candidate_falls_back_to_substring_then_fuzzy() {
        // "ost" is a substring of "kosti" but not a prefix of either field.
        assert_eq!(rank_candidate("ost", Some("kosti"), "Someone Else"), Some(3));
        // "kosit" (5 chars, threshold 2) is neither a substring of "kosti"
        // nor vice versa, but is distance 1 from it (one adjacent
        // transposition) — a fuzzy match.
        assert_eq!(rank_candidate("kosit", Some("kosti"), "Someone Else"), Some(4));
    }

    #[test]
    fn rank_candidate_matches_a_word_inside_display_name_by_fuzzy_distance() {
        // "vann" (4 chars, threshold 1) fuzzy-matches "van" inside "Kosti van Trading" via one insertion.
        assert_eq!(rank_candidate("vann", None, "Kosti van Trading"), Some(4));
    }

    #[test]
    fn rank_candidate_none_when_nothing_matches() {
        assert_eq!(rank_candidate("zzzzzzzzzz", Some("kosti"), "Someone Else"), None);
    }

    #[test]
    fn rank_candidate_handles_empty_and_unicode_inputs() {
        assert_eq!(rank_candidate("", Some(""), ""), Some(0));
        assert_eq!(rank_candidate("über", Some("Über"), "Someone Else"), Some(0));
    }
}

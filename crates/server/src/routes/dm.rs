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
//! Every route requires an authenticated caller who reaches
//! [`social_db::Class::Paid`] on the forum ladder ([`require_dm_access`] via
//! [`is_dm_paid`]) — the SAME rule `GET /forum/me` reports
//! (`social_db::caller_classes`), not a second copy of it: an unexpired
//! `paid_until`, trusted standing, or a moderator/admin `forum_roles` row
//! all satisfy this, even when the account's own subscription has lapsed
//! (owner ruling 2026-09-23: "класс и роль нормально"). Wherever a route
//! also names a second account (conversation creation, sending a message),
//! that account's OWN ladder standing is checked too ([`require_peer_paid`])
//! — together the two checks are the plan's "both parties must be paid",
//! now read off the ladder instead of the raw subscription flag.
//! [`create_conversation`] and [`create_message`] additionally require the
//! caller to have chosen a nick ([`require_nick`], run right after
//! [`require_dm_access`]) — owner ruling 2026-09-09: an account without a
//! nick may only read.
//!
//! Endpoints (all under `/api`, all authed + paid):
//!  - `PUT    /dm/identity`                              — publish/rotate
//!                                                          own DM public key.
//!  - `GET    /dm/identity/{public_id_or_nick}`           — a user's public
//!                                                          key + fingerprint.
//!  - `GET    /dm/lookup?q=`                              — recipient search
//!                                                          by nick/display
//!                                                          name: ladder-paid
//!                                                          accounts (see
//!                                                          [`is_dm_paid`])
//!                                                          with a
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
use std::collections::HashSet;
use std::sync::Arc;

use crate::auth::{extract_bearer, extract_session_id, extract_ua_hash, hash_token};
use crate::db;
use crate::dm_db;
use crate::models::types::ErrorResponse;
use crate::recipient_search::{effective_label_from_parts, paid_recipient_candidates, rank_candidate};
use crate::social_db::{self, Class};
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

/// Whether `user_id` reaches [`Class::Paid`] on the forum ladder — the SAME
/// rule `GET /forum/me` reports via `social_db::caller_classes`
/// (owner ruling 2026-09-23: "класс и роль нормально"). A moderator/admin
/// `forum_roles` row or trusted standing satisfies this exactly like an
/// unexpired `paid_until` does, even when the account's own subscription has
/// lapsed. Every DM payment check in this module goes through this one
/// function — the caller's own gate ([`require_dm_access`]) and every "the
/// OTHER account must be paid" check ([`create_conversation`],
/// [`create_message`], [`lookup_recipients`]'s candidate filter) — so there
/// is exactly one copy of the ladder rule, not a second one duplicating
/// `social_db::caller_classes`.
///
/// Takes `is_paid` (from `db::user_is_paid` on the identity connection)
/// rather than resolving it itself: every call site already needs to
/// sequence "read identity, drop the lock, then read social" for its own
/// other purposes (a label, a public id, a key), so threading the bool
/// through keeps the two connections from ever being held at once — same
/// discipline `routes::forum_v2::resolve_caller_classes` documents.
fn is_dm_paid(conn_social: &rusqlite::Connection, user_id: i64, is_paid: bool) -> bool {
    social_db::caller_classes(conn_social, Some(user_id), is_paid).contains(&Class::Paid)
}

/// The one access gate every route in this module runs through: resolve the
/// caller (401 if anonymous), then require [`is_dm_paid`] (403 if the ladder
/// does not reach `Paid`). Returns the caller's `user_id` on success.
async fn require_dm_access(state: Arc<AppState>, headers: &HeaderMap) -> Result<i64, Response> {
    let user_id = resolve_user_id(state.clone(), headers).await.map_err(auth_err)?;

    let paid_result = tokio::task::spawn_blocking({
        let state = state.clone();
        move || -> rusqlite::Result<bool> {
            let is_paid = {
                let identity_conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
                db::user_is_paid(&identity_conn, user_id)?
            };
            let social_conn = state.control_plane().social_conn();
            Ok(is_dm_paid(&social_conn, user_id, is_paid))
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

    if !is_paid {
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

/// 403 shape for "authed and paid, but never chosen a nick" — `code` lets
/// the client route the caller to the nick picker instead of showing a bare
/// permission error (owner ruling 2026-09-09: an account without a nick may
/// only read).
fn nick_required_err() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "Choose a nick before writing",
            "code": "nick_required",
        })),
    )
        .into_response()
}

/// Refuse `user_id` if it has never chosen a nick — the write gate shared by
/// [`create_conversation`] and [`create_message`], run right after
/// [`require_dm_access`] resolves the caller (owner ruling 2026-09-09).
async fn require_nick(state: Arc<AppState>, user_id: i64) -> Result<(), Response> {
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<String>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        db::user_nick(&conn, user_id)
    })
    .await;

    match result {
        Ok(Ok(Some(_))) => Ok(()),
        Ok(Ok(None)) => Err(nick_required_err()),
        Ok(Err(e)) => {
            tracing::error!("DB error checking dm nick requirement: {}", e);
            Err(internal_error())
        }
        Err(_) => Err(internal_error()),
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

/// `GET /dm/lookup?q=<text>` -> `{"users": [{"public_id","nick","label",
/// "rank"}]}`, sorted by rank then label, at most [`MAX_LOOKUP_RESULTS`].
/// Same [`require_dm_access`] gate as every other route here — only a
/// ladder-paid caller can search for a DM recipient. A candidate must be
/// BOTH ladder-paid ([`is_dm_paid`]'s rule — an unexpired `paid_until`,
/// trusted standing, or a moderator/admin role: [`paid_recipient_candidates`])
/// AND have published a DM identity key (a paid account that never called
/// `PUT /dm/identity` cannot receive anything yet, same posture
/// [`get_identity`] takes) — queries against the identity connection and a
/// batched one against the social connection, never a cross-database join
/// (see `dm_db`'s module doc). The caller itself is excluded from its own
/// results.
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
        // Ladder-boosted accounts (trusted standing, or a moderator/admin
        // role) — read before the identity connection is taken, same
        // "never hold both locks at once" discipline as elsewhere in this
        // module.
        let boosted_ids: Vec<i64> = {
            let social_conn = state.control_plane().social_conn();
            social_db::ladder_boosted_user_ids(&social_conn)?
        };

        let identity_conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now().to_rfc3339();
        let candidates = paid_recipient_candidates(&identity_conn, caller_id, &boosted_ids, &now)?;
        let candidates: Vec<_> = candidates
            .into_iter()
            .filter(|c| crate::db::visible_in_search(&identity_conn, caller_id, c.id).unwrap_or(true))
            .collect();
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
    if let Err(resp) = require_nick(state.clone(), user_id).await {
        return resp;
    }
    let with_label = req.with.trim().to_string();
    if with_label.is_empty() {
        return bad_request("with must not be empty");
    }

    type PeerLookup = Option<(i64, bool, String, String)>;
    let peer = tokio::task::spawn_blocking({
        let state = state.clone();
        move || -> rusqlite::Result<PeerLookup> {
            let identity_conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            let Some(peer_id) = resolve_user_by_label(&identity_conn, &with_label)? else {
                return Ok(None);
            };
            let peer_is_paid = db::user_is_paid(&identity_conn, peer_id)?;
            let public_id = db::get_user_public_id(&identity_conn, peer_id)?;
            let label = db::effective_label_for_user(&identity_conn, peer_id)?;
            drop(identity_conn);

            let social_conn = state.control_plane().social_conn();
            let peer_paid = is_dm_paid(&social_conn, peer_id, peer_is_paid);
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
/// currently reach [`Class::Paid`] on the ladder ([`is_dm_paid`], re-checked
/// here, not just at conversation creation — see the module doc);
/// rate-limited to [`dm_db::DM_MESSAGE_DAILY_LIMIT`] per rolling day per
/// sender.
///
/// # Bridge into the migrated Matrix room (P15)
///
/// Right after this route's own insert commits, it bridges the message into
/// `conversation`'s Matrix DM room — migrating the conversation from scratch
/// if this is its first message ever, or catching up an already-migrated
/// room otherwise (`crate::matrix_migration::bridge_legacy_dm_send`) — and,
/// on success, wakes that room's members ([`super::matrix::rooms`]'s own
/// `member_and_invited_ids`, plus `ControlPlane::live`) exactly the way
/// `routes::matrix::messaging::send_event` wakes a room after a native
/// Matrix send, so an updated client's open `/sync` long-poll returns at
/// once. A bridge failure never fails this route — the legacy send already
/// committed above — it is logged once with the conversation id and the
/// next boot's `matrix_migration::migrate_legacy_dms` catch-up closes the
/// gap.
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
    if let Err(resp) = require_nick(state.clone(), user_id).await {
        return resp;
    }
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

    let state_for_blocking = state.clone();
    let result = tokio::task::spawn_blocking(
        move || -> std::result::Result<(i64, String, Option<HashSet<i64>>), SendMessageRefusal> {
            let state = state_for_blocking;
            let social_conn = state.control_plane().social_conn();
            let Some(conversation) = dm_db::get_conversation(&social_conn, conversation_id)? else {
                return Err(SendMessageRefusal::NotFound);
            };
            let Some(peer_id) = conversation.peer_of(user_id) else {
                return Err(SendMessageRefusal::NotFound);
            };
            drop(social_conn);

            let peer_is_paid = {
                let identity_conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
                db::user_is_paid(&identity_conn, peer_id)?
            };

            let social_conn = state.control_plane().social_conn();
            if !is_dm_paid(&social_conn, peer_id, peer_is_paid) {
                return Err(SendMessageRefusal::PeerNotPaid);
            }

            let now = chrono::Utc::now();
            let since = (now - chrono::Duration::hours(24)).to_rfc3339();
            let recent = dm_db::messages_sent_since(&social_conn, user_id, &since)?;
            if recent >= dm_db::DM_MESSAGE_DAILY_LIMIT {
                return Err(SendMessageRefusal::RateLimited);
            }
            let now_str = now.to_rfc3339();
            let id = dm_db::create_message(&social_conn, conversation_id, user_id, &nonce, &ciphertext, &now_str)
                .map_err(SendMessageRefusal::Message)?;
            // The bridge takes `db` -> `social` -> `messenger` in that order
            // (see its doc); `social` must not still be held here.
            drop(social_conn);

            let wake_ids = bridge_legacy_dm_send_and_resolve_wake_set(&state, conversation_id, &conversation, &now_str);
            Ok((id, now_str, wake_ids))
        },
    )
    .await;

    match result {
        Ok(Ok((id, created_at, wake_ids))) => {
            if let Some(wake_ids) = wake_ids {
                state.control_plane().live.wake_many(wake_ids.into_iter().map(|id| format!("user:{id}")));
            }
            Json(serde_json::json!({ "id": id, "created_at": created_at })).into_response()
        }
        Ok(Err(e)) => send_message_refusal_response(e),
        Err(_) => internal_error(),
    }
}

/// The bridge step [`create_message`] runs right after its own insert
/// commits (module doc above) — pulled out to its own function so
/// `create_message` stays readable.
///
/// Lock order is `db` -> `social` -> `messenger`, the same order every
/// other path that holds more than one of them uses (the device reaper and
/// `device_auth` take `db` then `messenger`). The caller must hold none of
/// them. Taking `messenger` before `db` here would deadlock against the
/// hourly reaper. `social` is only read from here on, same as every other
/// `matrix_migration` read. Returns the room's wake set on success, `None`
/// on ANY failure (bridging, or the follow-up wake-set lookup) — already
/// logged here, never the caller's to handle.
fn bridge_legacy_dm_send_and_resolve_wake_set(
    state: &AppState,
    conversation_id: i64,
    conversation: &dm_db::DmConversation,
    now: &str,
) -> Option<HashSet<i64>> {
    let identity_conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
    let social_conn = state.control_plane().social_conn();
    let mut messenger_conn = state.control_plane().messenger_conn();
    let bridge_result =
        crate::matrix_migration::bridge_legacy_dm_send(&mut messenger_conn, &social_conn, &identity_conn, conversation, now);
    drop(social_conn);
    drop(identity_conn);

    let room_id = match bridge_result {
        Ok(room_id) => room_id,
        Err(e) => {
            tracing::error!("legacy DM bridge: conversation {} failed: {}", conversation_id, e);
            return None;
        }
    };
    resolve_wake_set(&messenger_conn, conversation_id, &room_id)
}

/// The bridge step [`mark_read`] runs right after its own update commits —
/// same posture as [`bridge_legacy_dm_send_and_resolve_wake_set`], but never
/// migrates a conversation that has no room yet (a read marker alone must
/// never be what creates a room — see
/// [`crate::matrix_migration::catch_up_legacy_dm_read`]'s own doc). Returns
/// `None` both on failure AND on the routine "no room yet" case — either way
/// there is nothing for the caller to wake.
fn bridge_legacy_dm_read_and_resolve_wake_set(
    state: &AppState,
    social: &rusqlite::Connection,
    conversation_id: i64,
    conversation: &dm_db::DmConversation,
) -> Option<HashSet<i64>> {
    let mut messenger_conn = state.control_plane().messenger_conn();
    let room_id = match crate::matrix_migration::catch_up_legacy_dm_read(&mut messenger_conn, social, conversation) {
        Ok(Some(room_id)) => room_id,
        Ok(None) => return None,
        Err(e) => {
            tracing::error!("legacy DM read bridge: conversation {} failed: {}", conversation_id, e);
            return None;
        }
    };
    resolve_wake_set(&messenger_conn, conversation_id, &room_id)
}

/// The wake-set lookup shared by both bridge helpers above — reused, not
/// re-derived, so a send-bridged and a read-bridged room wake the exact same
/// way ([`crate::routes::matrix::rooms::member_and_invited_ids`], plus
/// `ControlPlane::live` back in the caller, exactly how
/// `routes::matrix::messaging::send_event` wakes a room after a native
/// Matrix send).
fn resolve_wake_set(messenger_conn: &rusqlite::Connection, conversation_id: i64, room_id: &str) -> Option<HashSet<i64>> {
    match crate::routes::matrix::rooms::member_and_invited_ids(messenger_conn, room_id) {
        Ok(ids) => Some(ids),
        Err(e) => {
            tracing::error!(
                "legacy DM bridge: conversation {} wake-set lookup failed for room {}: {}",
                conversation_id, room_id, e
            );
            None
        }
    }
}

// ============================================================================
// GET /api/dm/conversations/{id}/messages
// ============================================================================

#[derive(serde::Deserialize)]
pub struct ListMessagesQuery {
    pub after: Option<i64>,
    pub before: Option<i64>,
    pub limit: Option<i64>,
}

/// Resolve `after`/`before` query params into the [`dm_db::MessagePage`]
/// [`list_messages`] should fetch — `None` if both were given, since they
/// are mutually exclusive (the route turns that into a 400 rather than
/// picking one silently). No cursor at all resolves to
/// [`dm_db::MessagePage::Newest`] — see that variant's doc for why this
/// case, not "from the start", is what an absent cursor now means.
fn resolve_message_page(after: Option<i64>, before: Option<i64>) -> Option<dm_db::MessagePage> {
    match (after, before) {
        (Some(_), Some(_)) => None,
        (Some(after), None) => Some(dm_db::MessagePage::After(after)),
        (None, Some(before)) => Some(dm_db::MessagePage::Before(before)),
        (None, None) => Some(dm_db::MessagePage::Newest),
    }
}

/// `GET /dm/conversations/{id}/messages?after=&before=&limit=` -> `{"messages":
/// [{"id","sender_public_id","sender_is_me","nonce_b64","ciphertext_b64",
/// "created_at","read_at"}], "next_after"}`, always oldest-first. No cursor
/// -> the newest `limit` messages (see [`dm_db::MessagePage::Newest`]);
/// `after` -> unchanged "what's new" polling; `before` -> "load older";
/// `after` and `before` together -> 400. 404 if the conversation does not
/// exist or the caller is not a party.
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
    let page = match resolve_message_page(query.after, query.before) {
        Some(page) => page,
        None => return bad_request("after and before are mutually exclusive"),
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
        let messages = dm_db::list_messages(&social_conn, conversation_id, page, limit)?;
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

enum MarkReadOutcome {
    /// The conversation does not exist, or `user_id` is not one of its two
    /// parties — same "indistinguishable from missing" posture as every
    /// other route here.
    NotFound,
    /// The legacy update itself always succeeds when the conversation
    /// exists; `Some` carries the room's wake set when the read bridge
    /// found (and caught up) an already-migrated room, `None` when there
    /// was nothing to bridge or the bridge itself failed (already logged).
    Marked(Option<HashSet<i64>>),
}

/// `POST /dm/conversations/{id}/read` — `{"up_to_id": N}`. Marks every
/// message sent by the OTHER party with `id <= up_to_id` as read. 204 on
/// success, 404 if the conversation does not exist or the caller is not a
/// party.
///
/// # Bridge into the migrated Matrix room (P15)
///
/// Right after this route's own update commits, it catches up
/// `conversation`'s Matrix DM room if one already exists
/// (`crate::matrix_migration::catch_up_legacy_dm_read` — never migrates a
/// conversation that has no room yet, unlike [`create_message`]'s own
/// bridge) and wakes it the same way `create_message` does. A bridge failure
/// never fails this route — the legacy read update already committed above.
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

    let state_for_blocking = state.clone();
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<MarkReadOutcome> {
        let state = state_for_blocking;
        let conn = state.control_plane().social_conn();
        let Some(conversation) = dm_db::get_conversation(&conn, conversation_id)? else {
            return Ok(MarkReadOutcome::NotFound);
        };
        if conversation.peer_of(user_id).is_none() {
            return Ok(MarkReadOutcome::NotFound);
        }
        let now = chrono::Utc::now().to_rfc3339();
        dm_db::mark_read(&conn, conversation_id, user_id, req.up_to_id, &now)?;

        let wake_ids = bridge_legacy_dm_read_and_resolve_wake_set(&state, &conn, conversation_id, &conversation);
        Ok(MarkReadOutcome::Marked(wake_ids))
    })
    .await;

    match result {
        Ok(Ok(MarkReadOutcome::Marked(wake_ids))) => {
            if let Some(wake_ids) = wake_ids {
                state.control_plane().live.wake_many(wake_ids.into_iter().map(|id| format!("user:{id}")));
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Ok(MarkReadOutcome::NotFound)) => StatusCode::NOT_FOUND.into_response(),
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

    // ---- ladder-based paid gate: is_dm_paid (owner ruling 2026-09-23) ----

    /// An in-memory `social.db` — both schemas [`is_dm_paid`] and
    /// [`paid_recipient_candidates`] read from (`forum_roles`/`forum_trusted`
    /// via `social_db`, `dm_identity_keys` via `dm_db`) live in the same
    /// physical file in production, so tests build both on one connection.
    fn social_test_conn() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().expect("in-memory sqlite");
        social_db::create_social_schema(&conn).expect("social schema");
        dm_db::create_dm_schema(&conn).expect("dm schema");
        conn
    }

    #[test]
    fn is_dm_paid_true_for_an_unpaid_admin_role_account() {
        let conn = social_test_conn();
        social_db::set_role(&conn, 42, social_db::Role::Admin, "2026-09-23T00:00:00+00:00").expect("set role");
        assert!(is_dm_paid(&conn, 42, false));
    }

    #[test]
    fn is_dm_paid_true_for_an_unpaid_moderator_role_account() {
        let conn = social_test_conn();
        social_db::set_role(&conn, 43, social_db::Role::Moderator, "2026-09-23T00:00:00+00:00").expect("set role");
        assert!(is_dm_paid(&conn, 43, false));
    }

    #[test]
    fn is_dm_paid_false_for_an_unpaid_plain_user() {
        let conn = social_test_conn();
        assert!(!is_dm_paid(&conn, 44, false));
    }

    #[test]
    fn is_dm_paid_true_for_a_paid_user() {
        let conn = social_test_conn();
        assert!(is_dm_paid(&conn, 45, true));
    }

    /// The refusal an unpaid plain-user caller gets from [`require_dm_access`]
    /// is exactly [`not_paid_err`] — this pins its shape (status + body) so a
    /// future change to the ladder rule cannot silently change what an
    /// unpaid caller sees.
    #[tokio::test]
    async fn not_paid_err_response_shape_is_unchanged() {
        use axum::body::to_bytes;

        let resp = not_paid_err();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(resp.into_body(), usize::MAX).await.expect("read body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(json["error"], "paid account required for direct messages");
    }

    // ---- message pagination: resolve_message_page ----

    #[test]
    fn resolve_message_page_rejects_after_and_before_together() {
        assert_eq!(resolve_message_page(Some(55), Some(11)), None);
    }

    #[test]
    fn resolve_message_page_defaults_to_newest_with_no_cursor() {
        assert_eq!(resolve_message_page(None, None), Some(dm_db::MessagePage::Newest));
    }

    #[test]
    fn resolve_message_page_maps_after_and_before_to_their_own_variant() {
        assert_eq!(resolve_message_page(Some(55), None), Some(dm_db::MessagePage::After(55)));
        assert_eq!(resolve_message_page(None, Some(11)), Some(dm_db::MessagePage::Before(11)));
    }
}

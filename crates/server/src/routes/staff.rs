//! `/api/staff/*` — the in-app admin tab's routes, on the MAIN listener.
//!
//! The loopback `ADMIN_SECRET` routes (`routes/admin.rs`, reachable only over
//! an SSH tunnel) stay as the ops path. These are the same operations for a
//! person signed in to the app: the caller must hold the `admin` role in
//! `forum_roles`, proven by the ordinary session (cookie or bearer). Both
//! paths call the same `db::` / `billing::grants` functions.
//!
//! **Access.** Anything that is not a signed-in admin — no session, an invalid
//! one, a moderator, a member with no role — gets the same
//! `403 {"error":"forbidden"}`; a wrong role is indistinguishable from no
//! session.
//!
//! **Accountability.** Every action writes one `staff_audit` row (actor,
//! action, target, parameters, time) in the same transaction as the action.
//! Parameters are counts, days, notes and ids — never a gift-code value. Every
//! WRITE is limited to 30 per minute per actor (`429 rate_limited`).
//!
//! | Route | Purpose |
//! |---|---|
//! | `POST /api/staff/gift-codes {days, count, note}` | mint a batch of single-use codes; the codes come back ONCE |
//! | `GET /api/staff/gift-batches` | the batches, no code values |
//! | `POST /api/staff/gift-batches/{id}/revoke` | unredeemed codes of the batch stop working |
//! | `POST /api/staff/grants/paid-days {nick, days}` | extend a time-bound paid grant |
//! | `POST /api/staff/grants/lifetime {nick, grant, note}` | add an operator lifetime grant to the ledger |
//! | `POST /api/staff/grants/lifetime/revoke {nick, grant}` | revoke the operator lifetime grants of that kind |
//! | `GET /api/staff/user?nick=` | one account's grants and roles (exact nick only) |
//! | `POST /api/staff/invites {nick, paid_days, note}` | issue a one-time registration invite; the code comes back ONCE |
//! | `GET /api/staff/invites` | the invites and their status, no code values |
//! | `POST /api/staff/invites/{id}/revoke` | withdraw a pending invite and release its nick |
//! | `PUT /api/staff/login-challenge {"on": bool}` | turn the login challenge on or off |

use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::billing::grants;
use crate::billing::invite::{IssueRefusal, Revoked};
use crate::models::types::ErrorResponse;
use crate::routes::account::resolve_user_id;
use crate::routes::admin::{paid_days_in_bounds, MAX_PAID_DAYS, MIN_PAID_DAYS};
use crate::social_db::Role;
use crate::state::AppState;

/// Days a gift code may grant.
const MIN_GIFT_DAYS: i64 = 1;
const MAX_GIFT_DAYS: i64 = 365;
/// Codes one batch may hold.
const MAX_GIFT_COUNT: i64 = 200;
/// Longest batch note.
const MAX_GIFT_NOTE_CHARS: usize = 200;
/// Longest nick accepted in a request.
const MAX_NICK_CHARS: usize = 64;

/// The signed-in admin making a request.
struct Actor {
    user_id: i64,
    nick: Option<String>,
}

fn reply(status: StatusCode, code: &str) -> Response {
    (status, Json(ErrorResponse::new(code))).into_response()
}

fn forbidden() -> Response {
    reply(StatusCode::FORBIDDEN, "forbidden")
}

fn internal(what: &str, e: &dyn std::fmt::Display) -> Response {
    tracing::error!("staff {what}: {e}");
    reply(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
}

/// The caller, if and only if they are a signed-in `admin`.
async fn staff(state: &Arc<AppState>, headers: &HeaderMap) -> Result<Actor, Response> {
    let user_id = match resolve_user_id(state.clone(), headers).await {
        Ok(id) => id,
        Err(StatusCode::UNAUTHORIZED) => return Err(forbidden()),
        Err(_) => return Err(reply(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")),
    };
    let state = state.clone();
    let checked = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<Actor>> {
        let control = state.control_plane();
        let role = {
            let social = control.social_conn();
            crate::social_db::role_for_user(&social, user_id)?
        };
        if role != Some(Role::Admin) {
            return Ok(None);
        }
        let conn = control.db.lock().unwrap_or_else(|e| e.into_inner());
        Ok(Some(Actor { user_id, nick: crate::db::nick_for_user(&conn, user_id)? }))
    })
    .await;
    match checked {
        Ok(Ok(Some(actor))) => Ok(actor),
        Ok(Ok(None)) => Err(forbidden()),
        Ok(Err(e)) => Err(internal("role lookup", &e)),
        Err(_) => Err(reply(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")),
    }
}

/// Spend one of the actor's writes for this minute.
fn spend_write(state: &AppState, actor: &Actor) -> Result<(), Response> {
    let limiter = state.staff_write_limiter();
    if limiter.try_acquire(actor.user_id, Instant::now()) {
        return Ok(());
    }
    Err((
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, limiter.window().as_secs().to_string())],
        Json(ErrorResponse::new("rate_limited")),
    )
        .into_response())
}

/// What an action did, for the audit row.
struct Done<T> {
    value: T,
    /// e.g. `batch:gb_…` or `user:42`.
    target: String,
    /// Counts, days, notes, ids — never a gift-code value.
    params: Value,
}

/// A refusal decided inside the action: nothing was written, so nothing is
/// audited.
type Refusal = (StatusCode, &'static str);

/// Run `work` and the audit row for it in ONE transaction.
async fn audited<T, F>(state: &Arc<AppState>, actor: &Actor, action: &'static str, work: F) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce(&Connection) -> rusqlite::Result<Result<Done<T>, Refusal>> + Send + 'static,
{
    let state = state.clone();
    let (actor_id, actor_nick) = (actor.user_id, actor.nick.clone());
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Result<T, Refusal>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.unchecked_transaction()?;
        match work(&tx)? {
            Ok(done) => {
                crate::staff::record(
                    &tx,
                    actor_id,
                    actor_nick.as_deref(),
                    action,
                    &done.target,
                    &done.params,
                    chrono::Utc::now(),
                )?;
                tx.commit()?;
                Ok(Ok(done.value))
            }
            Err(refusal) => Ok(Err(refusal)),
        }
    })
    .await;
    match result {
        Ok(Ok(Ok(value))) => Ok(value),
        Ok(Ok(Err((status, code)))) => Err(reply(status, code)),
        Ok(Err(e)) => Err(internal(action, &e)),
        Err(_) => Err(reply(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")),
    }
}

/// A nick as sent: trimmed, non-empty, bounded.
fn clean_nick(raw: &str) -> Option<String> {
    let nick = raw.trim();
    (!nick.is_empty() && nick.chars().count() <= MAX_NICK_CHARS).then(|| nick.to_string())
}

/// A batch note: optional, trimmed, bounded, no control characters.
fn clean_gift_note(raw: &str) -> Option<String> {
    let note = raw.trim();
    (note.chars().count() <= MAX_GIFT_NOTE_CHARS && !note.chars().any(char::is_control)).then(|| note.to_string())
}

// ============================================================================
// Gift codes
// ============================================================================

/// Request body of `POST /api/staff/gift-codes`.
#[derive(Deserialize)]
pub struct MintBody {
    /// Days each code grants once redeemed, 1..=365.
    pub days: i64,
    /// Codes to mint, 1..=200.
    pub count: i64,
    /// Why (optional, at most 200 characters).
    #[serde(default)]
    pub note: String,
}

/// `POST /api/staff/gift-codes {days, count, note}` → `201`
///
/// ```json
/// { "batch_id": "gb_…", "days": 30, "count": 3, "note": "beta wave",
///   "codes": ["K7Q2M9XPTA", "…", "…"] }
/// ```
/// The codes are single-use, stored only as a SHA-256 digest, and returned
/// here ONCE — nothing can read them back. `400` for `days` outside 1..=365,
/// `count` outside 1..=200, or a bad note.
pub async fn mint_gift_codes(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<MintBody>) -> Response {
    let actor = match staff(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    if let Err(response) = spend_write(&state, &actor) {
        return response;
    }
    if !(MIN_GIFT_DAYS..=MAX_GIFT_DAYS).contains(&body.days) {
        return reply(StatusCode::BAD_REQUEST, "days must be between 1 and 365");
    }
    if !(1..=MAX_GIFT_COUNT).contains(&body.count) {
        return reply(StatusCode::BAD_REQUEST, "count must be between 1 and 200");
    }
    let Some(note) = clean_gift_note(&body.note) else {
        return reply(StatusCode::BAD_REQUEST, "note must be at most 200 printable characters");
    };
    let (days, count) = (body.days, body.count);
    let actor_id = actor.user_id;
    let minted = audited(&state, &actor, "gift_codes.mint", move |conn| {
        let batch = crate::db::mint_gift_batch(conn, u32::try_from(count).unwrap_or(0), days, &note, Some(actor_id), &chrono::Utc::now().to_rfc3339())?;
        let params = json!({ "batch_id": batch.batch_id, "days": days, "count": count, "note": note });
        Ok(Ok(Done { target: format!("batch:{}", batch.batch_id), params, value: (batch.batch_id, batch.codes, note) }))
    })
    .await;
    match minted {
        Ok((batch_id, codes, note)) => {
            // Ids and counts only — a code value never reaches a log line.
            tracing::info!("staff {} minted gift batch {batch_id}: {} code(s), {days} day(s)", actor.user_id, codes.len());
            (
                StatusCode::CREATED,
                Json(json!({ "batch_id": batch_id, "days": days, "count": count, "note": note, "codes": codes })),
            )
                .into_response()
        }
        Err(response) => response,
    }
}

/// `GET /api/staff/gift-batches` → `200`, newest first, no code values:
///
/// ```json
/// [ { "batch_id": "gb_…", "note": "beta wave", "days": 30, "count": 3,
///     "redeemed": 1, "revoked": 2, "created_at": "2026-…", "created_by_nick": "alice" } ]
/// ```
/// `redeemed` counts codes redeemed; `revoked` counts unredeemed codes that
/// were revoked; `created_by_nick` is `null` for a batch minted from the ops
/// path or by an account with no nick.
pub async fn list_gift_batches(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let actor = match staff(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    match audited(&state, &actor, "gift_batches.list", |conn| {
        let batches = crate::db::list_gift_batches(conn)?;
        let params = json!({ "batches": batches.len() });
        Ok(Ok(Done { value: batches, target: "gift_batches".to_string(), params }))
    })
    .await
    {
        Ok(batches) => Json(batches).into_response(),
        Err(response) => response,
    }
}

/// `POST /api/staff/gift-batches/{id}/revoke` → `200 {"batch_id", "revoked": N}`
/// where `N` is how many unredeemed codes stopped working just now (`0` on a
/// repeat). Codes already redeemed keep their days. `404` for an unknown batch.
pub async fn revoke_gift_batch(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(batch_id): Path<String>) -> Response {
    let actor = match staff(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    if let Err(response) = spend_write(&state, &actor) {
        return response;
    }
    let id = batch_id.clone();
    match audited(&state, &actor, "gift_batches.revoke", move |conn| {
        let Some(revoked) = crate::db::revoke_gift_batch(conn, &id, &chrono::Utc::now().to_rfc3339())? else {
            return Ok(Err((StatusCode::NOT_FOUND, "no such batch")));
        };
        Ok(Ok(Done { value: revoked, target: format!("batch:{id}"), params: json!({ "batch_id": id, "revoked": revoked }) }))
    })
    .await
    {
        Ok(revoked) => Json(json!({ "batch_id": batch_id, "revoked": revoked })).into_response(),
        Err(response) => response,
    }
}

// ============================================================================
// Grants
// ============================================================================

/// Request body of `POST /api/staff/grants/paid-days`.
#[derive(Deserialize)]
pub struct PaidDaysBody {
    /// The account's exact nick.
    pub nick: String,
    /// Days to extend by, 1..=3650 (the same bounds as the ops route).
    pub days: i64,
}

/// `POST /api/staff/grants/paid-days {nick, days}` → `200 {"nick", "paid_until"}`.
/// Extends from `max(now, current paid_until)` (`db::grant_paid_days`, the
/// rule the ops route and gift codes share). `404` for an unknown nick.
pub async fn grant_paid_days(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<PaidDaysBody>) -> Response {
    let actor = match staff(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    if let Err(response) = spend_write(&state, &actor) {
        return response;
    }
    let Some(nick) = clean_nick(&body.nick) else {
        return reply(StatusCode::BAD_REQUEST, "nick is required");
    };
    if !paid_days_in_bounds(body.days) {
        return reply(StatusCode::BAD_REQUEST, &format!("days must be between {MIN_PAID_DAYS} and {MAX_PAID_DAYS}"));
    }
    let days = body.days;
    match audited(&state, &actor, "grant.paid_days", move |conn| {
        let Some(user_id) = crate::db::user_id_for_nick(conn, &nick)? else {
            return Ok(Err((StatusCode::NOT_FOUND, "no such user")));
        };
        let Some(paid_until) = crate::db::grant_paid_days(conn, user_id, days)? else {
            return Ok(Err((StatusCode::NOT_FOUND, "no such user")));
        };
        let stored_nick = crate::db::nick_for_user(conn, user_id)?.unwrap_or(nick);
        let params = json!({ "nick": stored_nick, "days": days, "paid_until": paid_until });
        Ok(Ok(Done { value: (stored_nick, paid_until), target: format!("user:{user_id}"), params }))
    })
    .await
    {
        Ok((nick, paid_until)) => Json(json!({ "nick": nick, "paid_until": paid_until })).into_response(),
        Err(response) => response,
    }
}

/// Request body of `POST /api/staff/grants/lifetime`.
#[derive(Deserialize)]
pub struct LifetimeBody {
    /// The account's exact nick.
    pub nick: String,
    /// `lifetime_paid` or `lifetime_anon`.
    pub grant: String,
    /// Why (1..=200 characters); recorded with the actor's id.
    pub note: String,
}

/// `POST /api/staff/grants/lifetime {nick, grant, note}` → `201` (or `200`
/// when the identical grant is already in force)
///
/// ```json
/// { "nick": "alice", "grant": "lifetime_paid", "grant_id": 12,
///   "source": "admin", "source_ref": "7:early supporter", "created": true }
/// ```
/// An operator row in the lifetime-grant ledger (`billing/grants.rs`); it is
/// never touched by an invoice's refund. `400` for a bad grant or note, `404`
/// for an unknown nick.
pub async fn grant_lifetime(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<LifetimeBody>) -> Response {
    let actor = match staff(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    if let Err(response) = spend_write(&state, &actor) {
        return response;
    }
    let Some(nick) = clean_nick(&body.nick) else {
        return reply(StatusCode::BAD_REQUEST, "nick is required");
    };
    let Some(grant) = grants::parse_lifetime(&body.grant) else {
        return reply(StatusCode::BAD_REQUEST, "grant must be lifetime_paid or lifetime_anon");
    };
    let Some(note) = grants::clean_note(&body.note) else {
        return reply(StatusCode::BAD_REQUEST, "note must be 1-200 printable characters");
    };
    let actor_id = actor.user_id;
    match audited(&state, &actor, "grant.lifetime.add", move |conn| {
        let Some(user_id) = crate::db::user_id_for_nick(conn, &nick)? else {
            return Ok(Err((StatusCode::NOT_FOUND, "no such user")));
        };
        let Some(added) = grants::add_admin(conn, user_id, grant, actor_id, &note, chrono::Utc::now())? else {
            return Ok(Err((StatusCode::NOT_FOUND, "no such user")));
        };
        let stored_nick = crate::db::nick_for_user(conn, user_id)?.unwrap_or(nick);
        let params = json!({ "nick": stored_nick, "grant": grant.as_str(), "grant_id": added.id, "created": added.created, "note": note });
        Ok(Ok(Done { value: (stored_nick, added), target: format!("user:{user_id}"), params }))
    })
    .await
    {
        Ok((nick, added)) => {
            let status = if added.created { StatusCode::CREATED } else { StatusCode::OK };
            (
                status,
                Json(json!({
                    "nick": nick,
                    "grant": grant.as_str(),
                    "grant_id": added.id,
                    "source": grants::SOURCE_ADMIN,
                    "source_ref": added.source_ref,
                    "created": added.created,
                })),
            )
                .into_response()
        }
        Err(response) => response,
    }
}

/// Request body of `POST /api/staff/grants/lifetime/revoke`.
#[derive(Deserialize)]
pub struct LifetimeRevokeBody {
    /// The account's exact nick.
    pub nick: String,
    /// `lifetime_paid` or `lifetime_anon`.
    pub grant: String,
}

/// `POST /api/staff/grants/lifetime/revoke {nick, grant}` →
/// `200 {"nick", "grant", "revoked": N}` — the operator grants of that kind
/// that were in force and are now revoked (`0` if there were none). Only
/// `source = admin` rows are touched: a grant that came from an invoice
/// follows its invoice. `404` for an unknown nick.
pub async fn revoke_lifetime(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<LifetimeRevokeBody>) -> Response {
    let actor = match staff(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    if let Err(response) = spend_write(&state, &actor) {
        return response;
    }
    let Some(nick) = clean_nick(&body.nick) else {
        return reply(StatusCode::BAD_REQUEST, "nick is required");
    };
    let Some(grant) = grants::parse_lifetime(&body.grant) else {
        return reply(StatusCode::BAD_REQUEST, "grant must be lifetime_paid or lifetime_anon");
    };
    match audited(&state, &actor, "grant.lifetime.revoke", move |conn| {
        let Some(user_id) = crate::db::user_id_for_nick(conn, &nick)? else {
            return Ok(Err((StatusCode::NOT_FOUND, "no such user")));
        };
        let revoked = grants::revoke_admin_kind(conn, user_id, grant, chrono::Utc::now())?;
        let stored_nick = crate::db::nick_for_user(conn, user_id)?.unwrap_or(nick);
        let params = json!({ "nick": stored_nick, "grant": grant.as_str(), "revoked": revoked });
        Ok(Ok(Done { value: (stored_nick, revoked), target: format!("user:{user_id}"), params }))
    })
    .await
    {
        Ok((nick, revoked)) => Json(json!({ "nick": nick, "grant": grant.as_str(), "revoked": revoked })).into_response(),
        Err(response) => response,
    }
}

// ============================================================================
// Registration invites
// ============================================================================

/// Request body of `POST /api/staff/invites`.
#[derive(Deserialize)]
pub struct IssueInviteBody {
    /// The nick the new account will get. A reserved nick is allowed; one held
    /// by an account or by another pending invite is not.
    pub nick: String,
    /// Paid days the account starts with: 0 (none) or 1..=3650.
    #[serde(default)]
    pub paid_days: i64,
    /// Why (optional, at most 200 characters).
    #[serde(default)]
    pub note: String,
}

/// `POST /api/staff/invites {nick, paid_days, note}` -> `201`
///
/// ```json
/// { "id": "inv_…", "invite_code": "K7Q2-M9XP-TA4B-C8DE-F0GH", "nick": "nix",
///   "paid_days": 365, "note": "early friend", "expires_at": "2026-…" }
/// ```
/// The code is single-use, stored only as a SHA-256 digest, and returned here
/// ONCE. The nick is held for the invite until it is redeemed, revoked or
/// expired (30 days). `400` for a bad nick, days or note, `409 nick taken`.
pub async fn issue_invite(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<IssueInviteBody>) -> Response {
    let actor = match staff(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    if let Err(response) = spend_write(&state, &actor) {
        return response;
    }
    let Some(nick) = clean_nick(&body.nick) else {
        return reply(StatusCode::BAD_REQUEST, "nick is required");
    };
    if body.paid_days != 0 && !paid_days_in_bounds(body.paid_days) {
        return reply(StatusCode::BAD_REQUEST, &format!("paid_days must be 0 or between {MIN_PAID_DAYS} and {MAX_PAID_DAYS}"));
    }
    let Some(note) = clean_gift_note(&body.note) else {
        return reply(StatusCode::BAD_REQUEST, "note must be at most 200 printable characters");
    };
    let (paid_days, actor_id) = (body.paid_days, actor.user_id);
    let issued = audited(&state, &actor, "invites.issue", move |conn| {
        let issued = match crate::billing::invite::issue(conn, &nick, paid_days, &note, actor_id, chrono::Utc::now())? {
            Ok(issued) => issued,
            Err(IssueRefusal::NickInvalid) => return Ok(Err((StatusCode::BAD_REQUEST, "nick is not valid"))),
            Err(IssueRefusal::NickForbidden) => return Ok(Err((StatusCode::BAD_REQUEST, "this nick is not allowed"))),
            Err(IssueRefusal::NickTaken) => return Ok(Err((StatusCode::CONFLICT, "nick taken"))),
        };
        // The code itself is never part of the audit row.
        let params = json!({ "invite_id": issued.id, "nick": nick, "paid_days": paid_days, "note": note, "expires_at": issued.expires_at });
        let answer = json!({
            "id": issued.id,
            "invite_code": issued.code,
            "nick": nick,
            "paid_days": paid_days,
            "note": note,
            "expires_at": issued.expires_at,
        });
        Ok(Ok(Done { target: format!("invite:{}", issued.id), params, value: answer }))
    })
    .await;
    match issued {
        Ok(answer) => {
            // The id only: a code never reaches a log line.
            tracing::info!("staff {} issued registration invite {}", actor.user_id, answer["id"].as_str().unwrap_or_default());
            (StatusCode::CREATED, Json(answer)).into_response()
        }
        Err(response) => response,
    }
}

/// `GET /api/staff/invites` -> `200`, newest first, no code values:
///
/// ```json
/// [ { "id": "inv_…", "nick": "nix", "paid_days": 365, "note": "early friend",
///     "status": "pending", "created_at": "…", "expires_at": "…",
///     "redeemed_at": null, "revoked_at": null, "created_by_nick": "alice" } ]
/// ```
/// `status` is `pending`, `redeemed`, `revoked` or `expired`.
pub async fn list_invites(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let actor = match staff(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    match audited(&state, &actor, "invites.list", |conn| {
        let rows = crate::billing::invite::list(conn, chrono::Utc::now())?;
        let params = json!({ "invites": rows.len() });
        Ok(Ok(Done { value: rows, target: "invites".to_string(), params }))
    })
    .await
    {
        Ok(rows) => Json(rows).into_response(),
        Err(response) => response,
    }
}

/// `POST /api/staff/invites/{id}/revoke` -> `200 {"id", "revoked": true}`, or
/// `"revoked": false` on a repeat. The invite's nick is released. `404` for an
/// unknown invite, `409 already redeemed` once the account exists.
pub async fn revoke_invite(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(invite_id): Path<String>) -> Response {
    let actor = match staff(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    if let Err(response) = spend_write(&state, &actor) {
        return response;
    }
    let id = invite_id.clone();
    match audited(&state, &actor, "invites.revoke", move |conn| {
        let revoked = match crate::billing::invite::revoke(conn, &id, chrono::Utc::now())? {
            Revoked::NotFound => return Ok(Err((StatusCode::NOT_FOUND, "no such invite"))),
            Revoked::AlreadyRedeemed => return Ok(Err((StatusCode::CONFLICT, "already redeemed"))),
            Revoked::Now => true,
            Revoked::Before => false,
        };
        Ok(Ok(Done { value: revoked, target: format!("invite:{id}"), params: json!({ "invite_id": id, "revoked": revoked }) }))
    })
    .await
    {
        Ok(revoked) => Json(json!({ "id": invite_id, "revoked": revoked })).into_response(),
        Err(response) => response,
    }
}

/// Body of `PUT /api/staff/login-challenge`.
#[derive(Deserialize)]
pub struct LoginChallengeBody {
    /// `true` requires a solution on the sign-in routes; `false` is today's behaviour.
    on: bool,
}

/// `PUT /api/staff/login-challenge {"on": bool}` — a signed-in admin.
///
/// Writes `app_settings.login_challenge` (`on` or `off`) and one
/// `staff_audit` row (`login_challenge.set`, target `login_challenge`,
/// params `{"on": ...}` only) in the same transaction, then publishes the
/// flag the hot path reads. `403 forbidden` for anyone else. One of the
/// actor's 30 writes a minute.
pub async fn set_login_challenge(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<LoginChallengeBody>,
) -> Response {
    let actor = match staff(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    if let Err(response) = spend_write(&state, &actor) {
        return response;
    }
    let on = body.on;
    match audited(&state, &actor, "login_challenge.set", move |conn| {
        crate::login_gate::set_stored(conn, on)?;
        Ok(Ok(Done { value: (), target: "login_challenge".to_string(), params: json!({ "on": on }) }))
    })
    .await
    {
        Ok(()) => {
            state.set_login_challenge_enabled(on);
            tracing::info!("staff {} set login challenge on={on}", actor.user_id);
            Json(json!({ "on": on })).into_response()
        }
        Err(response) => response,
    }
}

// ============================================================================
// Lookup
// ============================================================================

/// Query of `GET /api/staff/user`.
#[derive(Deserialize)]
pub struct UserQuery {
    /// The account's exact nick (no search, no partial match).
    #[serde(default)]
    pub nick: String,
}

/// `GET /api/staff/user?nick=` → `200`
///
/// ```json
/// { "nick": "alice", "user_id": 42,
///   "paid_until": "2026-11-01T…+00:00",
///   "lifetime_paid": true, "lifetime_anon": false,
///   "lifetime_grants": [ { "grant_id": 12, "grant": "lifetime_paid", "source": "admin",
///                          "source_ref": "7:early supporter", "created_at": "…", "revoked_at": null } ],
///   "quant_tier": null, "quant_active_until": null, "roles": ["moderator"] }
/// ```
/// `paid_until` is the time-bound grant while it is still running (`null`
/// otherwise); `lifetime_grants` lists every ledger row, revoked ones with
/// `revoked_at`; `roles` is the account's `forum_roles` entry (0 or 1 names).
/// Exact nick only: `400` without one, `404` for no such account.
pub async fn user_lookup(State(state): State<Arc<AppState>>, headers: HeaderMap, Query(query): Query<UserQuery>) -> Response {
    let actor = match staff(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    let Some(nick) = clean_nick(&query.nick) else {
        return reply(StatusCode::BAD_REQUEST, "nick is required");
    };
    // The forum role lives in the social database: read it first, holding no
    // identity lock, so the two locks are never held together.
    let target = {
        let (state, nick) = (state.clone(), nick.clone());
        tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<(i64, Option<Role>)>> {
            let control = state.control_plane();
            let user_id = {
                let conn = control.db.lock().unwrap_or_else(|e| e.into_inner());
                crate::db::user_id_for_nick(&conn, &nick)?
            };
            let Some(user_id) = user_id else { return Ok(None) };
            let role = crate::social_db::role_for_user(&control.social_conn(), user_id)?;
            Ok(Some((user_id, role)))
        })
        .await
    };
    let (user_id, role) = match target {
        Ok(Ok(Some(found))) => found,
        Ok(Ok(None)) => return reply(StatusCode::NOT_FOUND, "no such user"),
        Ok(Err(e)) => return internal("user lookup", &e),
        Err(_) => return reply(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
    };
    let found = audited(&state, &actor, "user.lookup", move |conn| {
        let view = crate::billing::entitle::entitlement_view(conn, user_id, chrono::Utc::now())?;
        let rows = grants::list(conn, user_id)?;
        let stored_nick = crate::db::nick_for_user(conn, user_id)?.unwrap_or(nick);
        let lifetime_grants: Vec<Value> = rows
            .iter()
            .map(|g| {
                json!({
                    "grant_id": g.id,
                    "grant": g.grant.as_str(),
                    "source": g.source,
                    "source_ref": g.source_ref,
                    "created_at": g.created_at,
                    "revoked_at": g.revoked_at,
                })
            })
            .collect();
        let value = json!({
            "nick": stored_nick,
            "user_id": user_id,
            "paid_until": view.paid_until,
            "lifetime_paid": view.lifetime_paid,
            "lifetime_anon": view.lifetime_anon,
            "lifetime_grants": lifetime_grants,
            "quant_tier": view.quant_tier,
            "quant_active_until": view.quant_active_until,
            "roles": role.map(|r| vec![r.as_str()]).unwrap_or_default(),
        });
        Ok(Ok(Done { value, target: format!("user:{user_id}"), params: json!({ "nick": stored_nick }) }))
    })
    .await;
    match found {
        Ok(value) => Json(value).into_response(),
        Err(response) => response,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::testkit::{capture_logs, captured_logs};
    use crate::routes::billing::tests::{app_state, get_json, post_json, send_from, sign_in, DEFAULT_CLIENT_IP};
    use crate::routes::control_api_router;
    use axum::http::Method;
    use axum::Router;
    use chrono::Utc;

    /// An account with a nick (and optionally a forum role); returns `(id, bearer token)`.
    fn account(state: &Arc<AppState>, nick: &str, role: Option<Role>) -> (i64, String) {
        let (uid, token) = sign_in(state, nick);
        {
            let conn = state.control_plane().db.lock().expect("db");
            crate::db::admin_set_nick(&conn, uid, nick).expect("nick");
        }
        if let Some(role) = role {
            let social = state.control_plane().social_conn();
            crate::social_db::set_role(&social, uid, role, &Utc::now().to_rfc3339()).expect("role");
        }
        (uid, token)
    }

    fn count(state: &Arc<AppState>, sql: &str) -> i64 {
        state.control_plane().db.lock().expect("db").query_row(sql, [], |r| r.get(0)).expect("count")
    }

    fn audit(state: &Arc<AppState>) -> Vec<crate::staff::AuditRow> {
        crate::staff::all(&state.control_plane().db.lock().expect("db")).expect("audit rows")
    }

    async fn mint(router: &Router, token: &str, days: i64, count: i64, note: &str) -> (StatusCode, Value) {
        post_json(router, token, "/staff/gift-codes", json!({ "days": days, "count": count, "note": note }), None).await
    }

    fn codes_of(answer: &Value) -> Vec<String> {
        answer["codes"].as_array().expect("codes").iter().map(|c| c.as_str().expect("code").to_string()).collect()
    }

    async fn redeem(router: &Router, token: &str, code: &str) -> (StatusCode, Value) {
        post_json(router, token, "/account/redeem", json!({ "code": code }), None).await
    }

    // ------------------------------------------------------------ the gate

    #[tokio::test]
    async fn only_a_signed_in_admin_passes_and_every_other_caller_gets_the_same_403() {
        let state = app_state(None);
        let router = control_api_router(state.clone());
        let (_, admin) = account(&state, "rootadmin", Some(Role::Admin));
        let (_, moderator) = account(&state, "modperson", Some(Role::Moderator));
        let (_, member) = account(&state, "plainmember", None);

        let (status, list) = get_json(&router, &admin, "/staff/gift-batches", None).await;
        assert_eq!((status, list), (StatusCode::OK, json!([])));

        let routes: [(Method, &str, Option<Value>); 8] = [
            (Method::POST, "/staff/gift-codes", Some(json!({ "days": 5, "count": 1, "note": "" }))),
            (Method::GET, "/staff/gift-batches", None),
            (Method::POST, "/staff/gift-batches/gb_x/revoke", Some(json!({}))),
            (Method::POST, "/staff/grants/paid-days", Some(json!({ "nick": "plainmember", "days": 3 }))),
            (Method::POST, "/staff/grants/lifetime", Some(json!({ "nick": "plainmember", "grant": "lifetime_paid", "note": "x" }))),
            (Method::POST, "/staff/grants/lifetime/revoke", Some(json!({ "nick": "plainmember", "grant": "lifetime_paid" }))),
            (Method::GET, "/staff/user?nick=plainmember", None),
            (Method::PUT, "/staff/login-challenge", Some(json!({ "on": true }))),
        ];
        let mut refusals = Vec::new();
        for (method, uri, body) in &routes {
            for token in [Some(&moderator), Some(&member), Some(&"not-a-real-token".to_string()), None] {
                let authorization = token.map(|t| format!("Bearer {t}"));
                let mut headers = vec![("content-type", "application/json")];
                if let Some(value) = &authorization {
                    headers.push(("authorization", value.as_str()));
                }
                let (status, _, answer) =
                    send_from(&router, DEFAULT_CLIENT_IP, method.clone(), uri, &headers, body.as_ref().map(Value::to_string)).await;
                refusals.push((status, answer));
            }
        }
        assert_eq!(refusals.len(), 32);
        for (status, answer) in &refusals {
            assert_eq!(*status, StatusCode::FORBIDDEN);
            assert_eq!(answer, &json!({ "error": "forbidden" }), "moderator, member, bad token and no session look alike");
        }
        assert_eq!(count(&state, "SELECT COUNT(*) FROM staff_audit"), 1, "only the admin's own list call left a row");
        assert_eq!(count(&state, "SELECT COUNT(*) FROM gift_codes"), 0);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM billing_grants"), 0);
    }

    // ---------------------------------------------------------- gift codes

    #[tokio::test]
    async fn mint_redeem_through_the_existing_route_and_the_counts() {
        let state = app_state(None);
        let router = control_api_router(state.clone());
        let (admin_id, admin) = account(&state, "rootadmin", Some(Role::Admin));
        let (_, member) = account(&state, "plainmember", None);
        let (_, other) = account(&state, "otheruser", None);

        let (status, minted) = mint(&router, &admin, 30, 3, "beta wave").await;
        assert_eq!(status, StatusCode::CREATED, "{minted}");
        let batch_id = minted["batch_id"].as_str().expect("batch id").to_string();
        assert!(batch_id.starts_with("gb_"));
        assert_eq!((minted["days"].as_i64(), minted["count"].as_i64(), minted["note"].as_str()), (Some(30), Some(3), Some("beta wave")));
        let codes = codes_of(&minted);
        assert_eq!(codes.len(), 3);
        assert_eq!(codes.iter().collect::<std::collections::HashSet<_>>().len(), 3, "distinct");
        assert!(codes.iter().all(|c| c.len() == 10));

        // At rest: a digest, not the code; the batch, note and creator are recorded.
        {
            let conn = state.control_plane().db.lock().expect("db");
            for code in &codes {
                let plain: i64 = conn.query_row("SELECT COUNT(*) FROM gift_codes WHERE code = ?1", [code.as_str()], |r| r.get(0)).expect("count");
                assert_eq!(plain, 0, "the code itself is not stored");
            }
            let (digest_len, batch, created_by): (i64, String, i64) = conn
                .query_row("SELECT LENGTH(code), batch_id, created_by FROM gift_codes LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .expect("row");
            assert_eq!((digest_len, batch.as_str(), created_by), (64, batch_id.as_str(), admin_id));
        }

        // The existing redeem route accepts the code (case and spaces forgiven) and only once.
        let (status, redeemed) = redeem(&router, &member, &format!(" {} ", codes[0].to_lowercase())).await;
        assert_eq!(status, StatusCode::OK, "{redeemed}");
        assert!(redeemed["paid_until"].is_string());
        let (status, _) = redeem(&router, &other, &codes[0]).await;
        assert_eq!(status, StatusCode::CONFLICT, "single use");
        let (_, entitlements) = get_json(&router, &member, "/entitlements", None).await;
        assert_eq!(entitlements["paid"], true);
        let (status, _) = redeem(&router, &other, "ZZZZZZZZZZ").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // The list: counts, creator nick, and no code value anywhere in it.
        let (status, list) = get_json(&router, &admin, "/staff/gift-batches", None).await;
        assert_eq!(status, StatusCode::OK);
        let rows = list.as_array().expect("array");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["batch_id"], batch_id.as_str());
        assert_eq!((rows[0]["note"].as_str(), rows[0]["days"].as_i64(), rows[0]["count"].as_i64()), (Some("beta wave"), Some(30), Some(3)));
        assert_eq!((rows[0]["redeemed"].as_i64(), rows[0]["revoked"].as_i64()), (Some(1), Some(0)));
        assert_eq!(rows[0]["created_by_nick"], "rootadmin");
        assert!(rows[0]["created_at"].is_string());
        assert_eq!(rows[0].as_object().map(|o| o.len()), Some(8), "exactly the documented fields");
        let text = list.to_string();
        assert!(codes.iter().all(|c| !text.contains(c.as_str())));
    }

    #[tokio::test]
    async fn the_caps_are_enforced_and_a_refused_mint_creates_nothing() {
        let state = app_state(None);
        let router = control_api_router(state.clone());
        let (_, admin) = account(&state, "rootadmin", Some(Role::Admin));
        for (days, count, note) in [(0, 1, ""), (366, 1, ""), (30, 0, ""), (30, 201, ""), (-1, 5, ""), (30, 1, "line\nbreak")] {
            let (status, _) = mint(&router, &admin, days, count, note).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "days={days} count={count} note={note:?}");
        }
        let (status, _) = mint(&router, &admin, 30, 1, &"x".repeat(201)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM gift_codes"), 0);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM staff_audit"), 0, "a refused request is not an action");
        // The edges themselves are allowed.
        let (status, minted) = mint(&router, &admin, 365, 200, "").await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(codes_of(&minted).len(), 200);
        let (status, _) = mint(&router, &admin, 1, 1, "").await;
        assert_eq!(status, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn a_legacy_plaintext_code_still_redeems_beside_the_hashed_ones() {
        let state = app_state(None);
        let router = control_api_router(state.clone());
        let (_, member) = account(&state, "plainmember", None);
        state
            .control_plane()
            .db
            .lock()
            .expect("db")
            .execute("INSERT INTO gift_codes (code, grants_days, note, created_at) VALUES ('LEGACYCODE', 5, '', ?1)", [Utc::now().to_rfc3339()])
            .expect("legacy row");
        let (status, _) = redeem(&router, &member, "LEGACYCODE").await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn revoking_a_batch_stops_the_unredeemed_codes_and_keeps_the_redeemed_days() {
        let state = app_state(None);
        let router = control_api_router(state.clone());
        let (_, admin) = account(&state, "rootadmin", Some(Role::Admin));
        let (_, first) = account(&state, "firstuser", None);
        let (_, second) = account(&state, "seconduser", None);
        let (_, third) = account(&state, "thirduser", None);

        let (_, minted) = mint(&router, &admin, 30, 3, "to revoke").await;
        let batch_id = minted["batch_id"].as_str().expect("batch").to_string();
        let codes = codes_of(&minted);
        let (_, control) = mint(&router, &admin, 7, 1, "untouched").await;
        let control_code = codes_of(&control)[0].clone();
        assert_eq!(redeem(&router, &first, &codes[0]).await.0, StatusCode::OK);

        let (status, revoked) = post_json(&router, &admin, &format!("/staff/gift-batches/{batch_id}/revoke"), json!({}), None).await;
        assert_eq!((status, revoked), (StatusCode::OK, json!({ "batch_id": batch_id, "revoked": 2 })));
        for (user, code) in [(&second, &codes[1]), (&third, &codes[2])] {
            let (status, _) = redeem(&router, user, code).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "a revoked code is no code at all");
        }
        let (_, entitlements) = get_json(&router, &first, "/entitlements", None).await;
        assert_eq!(entitlements["paid"], true, "the redeemed code keeps its days");

        let (_, list) = get_json(&router, &admin, "/staff/gift-batches", None).await;
        let row = list.as_array().expect("array").iter().find(|b| b["batch_id"] == batch_id.as_str()).expect("batch row").clone();
        assert_eq!((row["count"].as_i64(), row["redeemed"].as_i64(), row["revoked"].as_i64()), (Some(3), Some(1), Some(2)));

        // Repeating it changes nothing; an unknown batch is a 404; another batch is unaffected.
        let (_, again) = post_json(&router, &admin, &format!("/staff/gift-batches/{batch_id}/revoke"), json!({}), None).await;
        assert_eq!(again["revoked"], 0);
        let (status, _) = post_json(&router, &admin, "/staff/gift-batches/gb_nope/revoke", json!({}), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(redeem(&router, &second, &control_code).await.0, StatusCode::OK);
    }

    // -------------------------------------------------------------- grants

    #[tokio::test]
    async fn paid_days_follow_the_shared_rule_and_bounds() {
        let state = app_state(None);
        let router = control_api_router(state.clone());
        let (_, admin) = account(&state, "rootadmin", Some(Role::Admin));
        let (_, member) = account(&state, "plainmember", None);

        let (status, granted) = post_json(&router, &admin, "/staff/grants/paid-days", json!({ "nick": "PlainMember", "days": 10 }), None).await;
        assert_eq!(status, StatusCode::OK, "{granted}");
        assert_eq!(granted["nick"], "plainmember", "the stored spelling, whatever the case sent");
        let first_until = granted["paid_until"].as_str().expect("paid_until").to_string();
        let (_, entitlements) = get_json(&router, &member, "/entitlements", None).await;
        assert_eq!(entitlements["paid"], true);
        // Extends from the running grant, never replaces it.
        let (_, more) = post_json(&router, &admin, "/staff/grants/paid-days", json!({ "nick": "plainmember", "days": 10 }), None).await;
        assert!(more["paid_until"].as_str().expect("paid_until") > first_until.as_str());

        for (nick, days, want) in [("plainmember", 0, 400), ("plainmember", 3651, 400), ("plainmember", -2, 400), ("  ", 5, 400), ("nobodyhere", 5, 404)] {
            let (status, _) = post_json(&router, &admin, "/staff/grants/paid-days", json!({ "nick": nick, "days": days }), None).await;
            assert_eq!(status.as_u16(), want, "nick={nick:?} days={days}");
        }
    }

    #[tokio::test]
    async fn lifetime_grants_go_through_the_ledger_and_revoking_touches_only_admin_rows() {
        let state = app_state(None);
        let router = control_api_router(state.clone());
        let (admin_id, admin) = account(&state, "rootadmin", Some(Role::Admin));
        let (member_id, member) = account(&state, "plainmember", None);

        let body = json!({ "nick": "plainmember", "grant": "lifetime_paid", "note": "early supporter" });
        let (status, added) = post_json(&router, &admin, "/staff/grants/lifetime", body.clone(), None).await;
        assert_eq!(status, StatusCode::CREATED, "{added}");
        assert_eq!(added["nick"], "plainmember");
        assert_eq!(added["grant"], "lifetime_paid");
        assert_eq!(added["source"], "admin");
        assert_eq!(added["source_ref"], format!("{admin_id}:early supporter"));
        assert_eq!(added["created"], true);
        let (status, again) = post_json(&router, &admin, "/staff/grants/lifetime", body, None).await;
        assert_eq!((status, again["created"].as_bool(), again["grant_id"].as_i64()), (StatusCode::OK, Some(false), added["grant_id"].as_i64()));
        let (_, me) = get_json(&router, &member, "/entitlements", None).await;
        assert_eq!((me["lifetime_paid"].as_bool(), me["lifetime_anon"].as_bool(), me["paid"].as_bool()), (Some(true), Some(false), Some(true)));

        // A grant that came from an invoice sits beside it.
        {
            let conn = state.control_plane().db.lock().expect("db");
            crate::billing::grants::grant_for_invoice(&conn, member_id, crate::billing::plans::Grant::LifetimePaid, "grp_9", Utc::now()).expect("invoice grant");
        }
        let (status, looked) = get_json(&router, &admin, "/staff/user?nick=plainmember", None).await;
        assert_eq!(status, StatusCode::OK);
        let sources: Vec<(String, String)> = looked["lifetime_grants"]
            .as_array()
            .expect("grants")
            .iter()
            .map(|g| (g["source"].as_str().expect("source").to_string(), g["source_ref"].as_str().expect("ref").to_string()))
            .collect();
        assert_eq!(sources, vec![("admin".to_string(), format!("{admin_id}:early supporter")), ("invoice".to_string(), "grp_9".to_string())]);

        // Revoke: the admin row only.
        let (status, revoked) = post_json(&router, &admin, "/staff/grants/lifetime/revoke", json!({ "nick": "plainmember", "grant": "lifetime_paid" }), None).await;
        assert_eq!((status, revoked), (StatusCode::OK, json!({ "nick": "plainmember", "grant": "lifetime_paid", "revoked": 1 })));
        let (_, me) = get_json(&router, &member, "/entitlements", None).await;
        assert_eq!(me["lifetime_paid"], true, "the invoice's grant still holds it");
        let (_, looked) = get_json(&router, &admin, "/staff/user?nick=plainmember", None).await;
        let rows = looked["lifetime_grants"].as_array().expect("grants");
        assert!(rows.iter().find(|g| g["source"] == "admin").expect("admin row")["revoked_at"].is_string());
        assert!(rows.iter().find(|g| g["source"] == "invoice").expect("invoice row")["revoked_at"].is_null());
        let (_, nothing) = post_json(&router, &admin, "/staff/grants/lifetime/revoke", json!({ "nick": "plainmember", "grant": "lifetime_paid" }), None).await;
        assert_eq!(nothing["revoked"], 0);

        // Bad input and unknown accounts.
        for (body, want) in [
            (json!({ "nick": "plainmember", "grant": "quant", "note": "x" }), 400),
            (json!({ "nick": "plainmember", "grant": "lifetime_paid", "note": "  " }), 400),
            (json!({ "nick": "", "grant": "lifetime_paid", "note": "x" }), 400),
            (json!({ "nick": "nobodyhere", "grant": "lifetime_paid", "note": "x" }), 404),
        ] {
            let (status, _) = post_json(&router, &admin, "/staff/grants/lifetime", body.clone(), None).await;
            assert_eq!(status.as_u16(), want, "{body}");
        }
        let (status, _) = post_json(&router, &admin, "/staff/grants/lifetime/revoke", json!({ "nick": "nobodyhere", "grant": "lifetime_paid" }), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn the_user_lookup_takes_an_exact_nick_only_and_reports_roles() {
        let state = app_state(None);
        let router = control_api_router(state.clone());
        let (_, admin) = account(&state, "rootadmin", Some(Role::Admin));
        let (moderator_id, _) = account(&state, "modperson", Some(Role::Moderator));

        let (status, found) = get_json(&router, &admin, "/staff/user?nick=MODPERSON", None).await;
        assert_eq!(status, StatusCode::OK, "{found}");
        assert_eq!((found["nick"].as_str(), found["user_id"].as_i64()), (Some("modperson"), Some(moderator_id)));
        assert_eq!(found["roles"], json!(["moderator"]));
        assert_eq!((found["lifetime_paid"].as_bool(), found["lifetime_anon"].as_bool()), (Some(false), Some(false)));
        assert!(found["paid_until"].is_null() && found["quant_tier"].is_null() && found["quant_active_until"].is_null());
        assert_eq!(found["lifetime_grants"], json!([]));
        for query in ["/staff/user?nick=modper", "/staff/user?nick=person", "/staff/user?nick=%25", "/staff/user?nick=nobodyhere"] {
            let (status, _) = get_json(&router, &admin, query, None).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{query}");
        }
        for query in ["/staff/user", "/staff/user?nick=", "/staff/user?nick=%20"] {
            let (status, _) = get_json(&router, &admin, query, None).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
        }
    }

    // ------------------------------------------------- audit and the limits

    #[tokio::test]
    async fn every_action_leaves_one_audit_row_and_none_holds_a_code() {
        let state = app_state(None);
        let router = control_api_router(state.clone());
        let (admin_id, admin) = account(&state, "rootadmin", Some(Role::Admin));
        let (member_id, _) = account(&state, "plainmember", None);

        let (_, minted) = mint(&router, &admin, 14, 2, "audit me").await;
        let batch_id = minted["batch_id"].as_str().expect("batch").to_string();
        let codes = codes_of(&minted);
        get_json(&router, &admin, "/staff/gift-batches", None).await;
        post_json(&router, &admin, &format!("/staff/gift-batches/{batch_id}/revoke"), json!({}), None).await;
        post_json(&router, &admin, "/staff/grants/paid-days", json!({ "nick": "plainmember", "days": 9 }), None).await;
        post_json(&router, &admin, "/staff/grants/lifetime", json!({ "nick": "plainmember", "grant": "lifetime_anon", "note": "why" }), None).await;
        post_json(&router, &admin, "/staff/grants/lifetime/revoke", json!({ "nick": "plainmember", "grant": "lifetime_anon" }), None).await;
        get_json(&router, &admin, "/staff/user?nick=plainmember", None).await;
        // Refusals write nothing.
        post_json(&router, &admin, "/staff/grants/paid-days", json!({ "nick": "nobodyhere", "days": 9 }), None).await;
        post_json(&router, &admin, "/staff/gift-batches/gb_nope/revoke", json!({}), None).await;
        mint(&router, &admin, 0, 1, "").await;

        let rows = audit(&state);
        let summary: Vec<(&str, &str)> = rows.iter().map(|r| (r.action.as_str(), r.target.as_str())).collect();
        let user = format!("user:{member_id}");
        let batch = format!("batch:{batch_id}");
        assert_eq!(
            summary,
            vec![
                ("gift_codes.mint", batch.as_str()),
                ("gift_batches.list", "gift_batches"),
                ("gift_batches.revoke", batch.as_str()),
                ("grant.paid_days", user.as_str()),
                ("grant.lifetime.add", user.as_str()),
                ("grant.lifetime.revoke", user.as_str()),
                ("user.lookup", user.as_str()),
            ]
        );
        assert!(rows.iter().all(|r| r.actor_user_id == admin_id && r.actor_nick.as_deref() == Some("rootadmin")));
        assert_eq!(rows[0].params, json!({ "batch_id": batch_id, "days": 14, "count": 2, "note": "audit me" }));
        assert_eq!(rows[2].params["revoked"], 2);
        assert_eq!(rows[3].params["days"], 9);
        assert_eq!(rows[4].params["grant"], "lifetime_anon");
        let everything = serde_json::to_string(&rows.iter().map(|r| r.params.clone()).collect::<Vec<_>>()).expect("json");
        assert!(codes.iter().all(|c| !everything.contains(c.as_str())), "no code value in the audit trail");
    }

    #[tokio::test]
    async fn writes_are_limited_to_thirty_a_minute_per_actor_and_reads_are_not() {
        let state = app_state(None);
        let router = control_api_router(state.clone());
        let (_, admin) = account(&state, "rootadmin", Some(Role::Admin));
        let (_, other_admin) = account(&state, "secondadmin", Some(Role::Admin));
        let noop = json!({ "nick": "rootadmin", "grant": "lifetime_paid" });
        for n in 1..=30 {
            let (status, _) = post_json(&router, &admin, "/staff/grants/lifetime/revoke", noop.clone(), None).await;
            assert_eq!(status, StatusCode::OK, "write {n}");
        }
        let (status, answer) = post_json(&router, &admin, "/staff/grants/lifetime/revoke", noop.clone(), None).await;
        assert_eq!((status, answer["error"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")));
        let (status, _) = get_json(&router, &admin, "/staff/gift-batches", None).await;
        assert_eq!(status, StatusCode::OK, "a read is not a write");
        let (status, _) = post_json(&router, &other_admin, "/staff/grants/lifetime/revoke", noop, None).await;
        assert_eq!(status, StatusCode::OK, "the budget is per actor");
        assert_eq!(count(&state, "SELECT COUNT(*) FROM staff_audit WHERE action = 'grant.lifetime.revoke'"), 31, "the refused 31st left no row");
    }

    #[tokio::test]
    async fn gift_code_values_never_reach_a_log_line() {
        capture_logs();
        let state = app_state(None);
        let router = control_api_router(state.clone());
        let (_, admin) = account(&state, "rootadmin", Some(Role::Admin));
        let (_, member) = account(&state, "plainmember", None);
        let (_, minted) = mint(&router, &admin, 30, 5, "logging check").await;
        let batch_id = minted["batch_id"].as_str().expect("batch").to_string();
        let codes = codes_of(&minted);
        redeem(&router, &member, &codes[0]).await;
        redeem(&router, &member, &codes[0]).await;
        redeem(&router, &member, "WRONGWRONG").await;
        get_json(&router, &admin, "/staff/gift-batches", None).await;
        post_json(&router, &admin, &format!("/staff/gift-batches/{batch_id}/revoke"), json!({}), None).await;
        redeem(&router, &member, &codes[1]).await;

        let logs = captured_logs();
        assert!(logs.contains("minted gift batch"), "the capture is live and the mint was logged by id and count");
        for code in &codes {
            assert!(!logs.contains(code.as_str()), "a gift code was logged");
            assert!(!logs.contains(&code.to_lowercase()), "a gift code was logged");
        }
    }

    #[tokio::test]
    async fn setting_the_login_challenge_writes_one_audit_row_and_the_hot_flag() {
        let state = app_state(None);
        let router = control_api_router(state.clone());
        let (admin_id, admin) = account(&state, "rootadmin", Some(Role::Admin));
        assert!(!state.login_challenge_enabled());

        let authorization = format!("Bearer {admin}");
        let (status, _, answer) = send_from(
            &router,
            DEFAULT_CLIENT_IP,
            Method::PUT,
            "/staff/login-challenge",
            &[("authorization", authorization.as_str()), ("content-type", "application/json")],
            Some(json!({ "on": true }).to_string()),
        )
        .await;
        assert_eq!((status, answer), (StatusCode::OK, json!({ "on": true })));
        assert!(state.login_challenge_enabled());
        {
            let conn = state.control_plane().db.lock().expect("db");
            let value: String = conn
                .query_row("SELECT value FROM app_settings WHERE key = 'login_challenge'", [], |row| row.get(0))
                .expect("row");
            assert_eq!(value, "on");
        }
        let rows = audit(&state);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].actor_user_id, admin_id);
        assert_eq!(rows[0].action, "login_challenge.set");
        assert_eq!(rows[0].target, "login_challenge");
        assert_eq!(rows[0].params, json!({ "on": true }));

        let (status, _, answer) = send_from(
            &router,
            DEFAULT_CLIENT_IP,
            Method::PUT,
            "/staff/login-challenge",
            &[("authorization", authorization.as_str()), ("content-type", "application/json")],
            Some(json!({ "on": false }).to_string()),
        )
        .await;
        assert_eq!((status, answer), (StatusCode::OK, json!({ "on": false })));
        assert!(!state.login_challenge_enabled());
        let rows = audit(&state);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].params, json!({ "on": false }));
    }
}

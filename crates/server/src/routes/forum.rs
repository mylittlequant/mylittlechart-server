//! Paid in-app forum: threads and replies between accounts (owner ruling
//! 2026-09-05, `docs/mlc/plans/users-paid-features-scope-2026-09-05.md` §4)
//! — a communication surface between users, gated to paid accounts only
//! (paid = trusted alpha testers) via `entitlements::Feature::Forum`. There
//! is NO public GET of any kind here — every route below requires both an
//! authenticated caller and a paid one (see `require_forum_access`).
//! Authors display by `db::forum_author_label` (nick -> display_name ->
//! public_id, or "deleted user" once the account is gone).
//!
//! Endpoints (all under `/api`, all authed + paid unless noted):
//!  - `GET    /forum/threads?limit=&before=`      — list visible threads,
//!                                                   newest activity first.
//!  - `POST   /forum/threads`                     — create a thread.
//!  - `GET    /forum/threads/{id}`                — one thread + its replies.
//!  - `POST   /forum/threads/{id}/replies`        — create a reply.
//!  - `DELETE /forum/threads/{id}`                — author hides their own.
//!  - `DELETE /forum/replies/{id}`                — author hides their own.
//!  - `POST   /admin/forum/hide`                  — bearer `ADMIN_SECRET`,
//!                                                   hides any thread/reply.
//!
//! `entitlements::Feature::Forum` is never in the free set (see
//! `entitlements.rs`) — an anonymous caller gets 401, an authenticated but
//! unpaid caller gets 403, matching `routes::share`'s auth posture but with
//! an added paid gate share links do not have.

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use crate::auth::{extract_bearer, extract_session_id, extract_ua_hash, hash_token};
use crate::db::{self, ForumError};
use crate::entitlements::{self, Feature};
use crate::models::types::ErrorResponse;
use crate::state::AppState;

/// Default page size for `GET /forum/threads` when `limit` is omitted.
const DEFAULT_LIMIT: i64 = 50;

/// Ceiling on `limit` regardless of what the caller asks for.
const MAX_LIMIT: i64 = 200;

/// Characters kept in a thread's list-view excerpt.
const EXCERPT_CHARS: usize = 160;

/// Rate-limit window, shared by threads and replies: at most
/// [`THREAD_RATE_LIMIT_MAX`] threads and [`REPLY_RATE_LIMIT_MAX`] replies per
/// account per this many seconds. On refusal the client is told to retry in
/// exactly this many seconds — a fixed value rather than a precisely
/// computed remainder, since the window is small and a 429 already implies
/// backoff.
const RATE_LIMIT_WINDOW_SECS: i64 = 60;
const THREAD_RATE_LIMIT_MAX: i64 = 1;
const REPLY_RATE_LIMIT_MAX: i64 = 10;

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

fn forum_error_response(e: ForumError) -> Response {
    match e {
        ForumError::InvalidTitle => bad_request("title must be 3-120 characters"),
        ForumError::InvalidBody => bad_request("body must be 1-8192 bytes"),
        ForumError::Db(e) => {
            tracing::error!("DB error in forum route: {}", e);
            internal_error()
        }
    }
}

fn rate_limited() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(serde_json::json!({
            "error": "rate limit exceeded",
            "retry_after_secs": RATE_LIMIT_WINDOW_SECS,
        })),
    )
        .into_response()
}

// ============================================================================
// Auth + paid-entitlement gate
// ============================================================================

/// Resolve the authenticated `user_id` from either a cookie session or a
/// Bearer token. Mirrors `routes::share::resolve_user_id` — duplicated
/// rather than shared, following the existing pattern of one copy per route
/// module (`routes::account`, `routes::entitlements`, `routes::share`).
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

/// Same body `routes::share`'s auth failures answer with — see
/// `routes::share::auth_err`.
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
        Json(ErrorResponse::new("paid account required")),
    )
        .into_response()
}

/// The one entitlement gate every route in this module runs through: resolve
/// the caller (401 if anonymous), then require `Feature::Forum` via the same
/// `entitlements::resolve_for_user` mechanism `GET /api/entitlements` uses
/// (403 if not paid). Returns the caller's `user_id` on success.
async fn require_forum_access(state: Arc<AppState>, headers: &HeaderMap) -> Result<i64, Response> {
    let user_id = resolve_user_id(state.clone(), headers)
        .await
        .map_err(auth_err)?;

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
            tracing::error!("DB error checking paid status for forum access: {}", e);
            return Err(internal_error());
        }
        Err(_) => return Err(internal_error()),
    };

    if !entitlements::resolve_for_user(is_paid).contains(Feature::Forum) {
        return Err(not_paid_err());
    }
    Ok(user_id)
}

// ============================================================================
// Pagination cursor — "<last_activity>|<id>", same shape as routes::posts's
// "<date>|<id>" but with an integer id (thread ids are auto-increment, not
// slugs).
// ============================================================================

fn parse_before_cursor(raw: &str) -> Option<(String, i64)> {
    let (activity, id) = raw.split_once('|')?;
    if activity.is_empty() {
        return None;
    }
    let id: i64 = id.parse().ok()?;
    Some((activity.to_string(), id))
}

/// First [`EXCERPT_CHARS`] characters of `body`, for the list view —
/// character-based so a multi-byte character is never split mid-way.
fn excerpt(body: &str) -> String {
    body.chars().take(EXCERPT_CHARS).collect()
}

// ============================================================================
// GET /api/forum/threads
// ============================================================================

/// Query params for `GET /forum/threads`.
#[derive(serde::Deserialize)]
pub struct ListThreadsQuery {
    pub limit: Option<i64>,
    pub before: Option<String>,
}

/// `GET /forum/threads?limit=&before=`
///
/// ```json
/// {
///   "threads": [{
///     "id": 1, "title": "...", "author": "...", "author_is_me": false,
///     "created_at": "...", "last_reply_at": "..." | null,
///     "reply_count": 3, "excerpt": "..."
///   }],
///   "next_before": "<last_activity>|<id>" | null
/// }
/// ```
/// Same one-row-lookahead pagination as `routes::posts::list_posts`.
pub async fn list_threads(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ListThreadsQuery>,
) -> Response {
    let caller_id = match require_forum_access(state.clone(), &headers).await {
        Ok(uid) => uid,
        Err(resp) => return resp,
    };

    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let before = match query.before.as_deref() {
        Some(raw) => match parse_before_cursor(raw) {
            Some(cursor) => Some(cursor),
            None => return bad_request("before must be '<last_activity>|<id>'"),
        },
        None => None,
    };

    let result = tokio::task::spawn_blocking(
        move || -> rusqlite::Result<Vec<(db::ForumThread, String)>> {
            let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            let before_ref = before.as_ref().map(|(a, i)| (a.as_str(), *i));
            let threads = db::list_threads(&conn, limit.saturating_add(1), before_ref)?;
            threads
                .into_iter()
                .map(|t| {
                    let author = db::forum_author_label(&conn, t.author_user_id)?;
                    Ok((t, author))
                })
                .collect()
        },
    )
    .await;

    match result {
        Ok(Ok(mut rows)) => {
            let has_more = rows.len() as i64 > limit;
            if has_more {
                rows.truncate(limit as usize);
            }
            let next_before = if has_more {
                rows.last().map(|(t, _)| {
                    let activity = t.last_reply_at.clone().unwrap_or_else(|| t.created_at.clone());
                    format!("{}|{}", activity, t.id)
                })
            } else {
                None
            };
            Json(serde_json::json!({
                "threads": rows.iter().map(|(t, author)| serde_json::json!({
                    "id": t.id,
                    "title": t.title,
                    "author": author,
                    "author_is_me": t.author_user_id == caller_id,
                    "created_at": t.created_at,
                    "last_reply_at": t.last_reply_at,
                    "reply_count": t.reply_count,
                    "excerpt": excerpt(&t.body),
                })).collect::<Vec<_>>(),
                "next_before": next_before,
            }))
            .into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("DB error listing forum threads: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// POST /api/forum/threads
// ============================================================================

/// Refusal reasons that only make sense inside the create-thread/create-reply
/// transaction, layered on top of [`ForumError`] — the rate-limit decision is
/// a route-level policy, not something `db.rs` decides.
enum CreateRefusal {
    Forum(ForumError),
    RateLimited,
}

impl From<rusqlite::Error> for CreateRefusal {
    fn from(e: rusqlite::Error) -> Self {
        CreateRefusal::Forum(ForumError::Db(e))
    }
}

fn create_refusal_response(e: CreateRefusal) -> Response {
    match e {
        CreateRefusal::Forum(e) => forum_error_response(e),
        CreateRefusal::RateLimited => rate_limited(),
    }
}

/// Request body for `POST /forum/threads`.
#[derive(serde::Deserialize)]
pub struct CreateThreadRequest {
    pub title: String,
    pub body: String,
}

/// `POST /forum/threads` — `{"title": "...", "body": "..."}` -> `{"id": 1}`.
/// Rate-limited to [`THREAD_RATE_LIMIT_MAX`] per [`RATE_LIMIT_WINDOW_SECS`]
/// seconds per account (429 with `retry_after_secs` on refusal).
pub async fn create_thread(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateThreadRequest>,
) -> Response {
    let user_id = match require_forum_access(state.clone(), &headers).await {
        Ok(uid) => uid,
        Err(resp) => return resp,
    };

    let result = tokio::task::spawn_blocking(
        move || -> std::result::Result<i64, CreateRefusal> {
            let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            let now = chrono::Utc::now();
            let since = (now - chrono::Duration::seconds(RATE_LIMIT_WINDOW_SECS)).to_rfc3339();
            let recent = db::threads_created_since(&conn, user_id, &since)?;
            if recent >= THREAD_RATE_LIMIT_MAX {
                return Err(CreateRefusal::RateLimited);
            }
            db::create_thread(&conn, user_id, &req.title, &req.body, &now.to_rfc3339())
                .map_err(CreateRefusal::Forum)
        },
    )
    .await;

    match result {
        Ok(Ok(id)) => Json(serde_json::json!({ "id": id })).into_response(),
        Ok(Err(e)) => create_refusal_response(e),
        Err(_) => internal_error(),
    }
}

// ============================================================================
// GET /api/forum/threads/{id}
// ============================================================================

/// `GET /forum/threads/{id}`
///
/// ```json
/// {
///   "thread": {"id":1,"title":"...","author":"...","author_is_me":false,
///              "body":"...","created_at":"..."},
///   "replies": [{"id":1,"author":"...","author_is_me":false,
///                "body":"...","created_at":"..."}]
/// }
/// ```
/// Bare 404 if the thread does not exist or is hidden.
pub async fn get_thread(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(thread_id): Path<i64>,
) -> Response {
    let caller_id = match require_forum_access(state.clone(), &headers).await {
        Ok(uid) => uid,
        Err(resp) => return resp,
    };

    type ThreadWithReplies = (db::ForumThread, String, Vec<(db::ForumReply, String)>);

    let result = tokio::task::spawn_blocking(
        move || -> rusqlite::Result<Option<ThreadWithReplies>> {
            let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            let thread = match db::get_thread(&conn, thread_id)? {
                Some(t) => t,
                None => return Ok(None),
            };
            let author = db::forum_author_label(&conn, thread.author_user_id)?;
            let replies = db::list_replies(&conn, thread_id)?;
            let mut reply_rows = Vec::with_capacity(replies.len());
            for reply in replies {
                let reply_author = db::forum_author_label(&conn, reply.author_user_id)?;
                reply_rows.push((reply, reply_author));
            }
            Ok(Some((thread, author, reply_rows)))
        },
    )
    .await;

    match result {
        Ok(Ok(Some((thread, author, replies)))) => Json(serde_json::json!({
            "thread": {
                "id": thread.id,
                "title": thread.title,
                "author": author,
                "author_is_me": thread.author_user_id == caller_id,
                "body": thread.body,
                "created_at": thread.created_at,
            },
            "replies": replies.into_iter().map(|(r, author)| serde_json::json!({
                "id": r.id,
                "author": author,
                "author_is_me": r.author_user_id == caller_id,
                "body": r.body,
                "created_at": r.created_at,
            })).collect::<Vec<_>>(),
        }))
        .into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error fetching forum thread: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// POST /api/forum/threads/{id}/replies
// ============================================================================

/// Request body for `POST /forum/threads/{id}/replies`.
#[derive(serde::Deserialize)]
pub struct CreateReplyRequest {
    pub body: String,
}

/// `POST /forum/threads/{id}/replies` — `{"body": "..."}` -> `{"id": 1}`.
/// Bare 404 if the thread does not exist or is hidden. Rate-limited to
/// [`REPLY_RATE_LIMIT_MAX`] per [`RATE_LIMIT_WINDOW_SECS`] seconds per
/// account (429 with `retry_after_secs` on refusal).
pub async fn create_reply(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(thread_id): Path<i64>,
    Json(req): Json<CreateReplyRequest>,
) -> Response {
    let user_id = match require_forum_access(state.clone(), &headers).await {
        Ok(uid) => uid,
        Err(resp) => return resp,
    };

    let result = tokio::task::spawn_blocking(
        move || -> std::result::Result<Option<i64>, CreateRefusal> {
            let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            if db::get_thread(&conn, thread_id)?.is_none() {
                return Ok(None);
            }
            let now = chrono::Utc::now();
            let since = (now - chrono::Duration::seconds(RATE_LIMIT_WINDOW_SECS)).to_rfc3339();
            let recent = db::replies_created_since(&conn, user_id, &since)?;
            if recent >= REPLY_RATE_LIMIT_MAX {
                return Err(CreateRefusal::RateLimited);
            }
            db::create_reply(&conn, thread_id, user_id, &req.body, &now.to_rfc3339())
                .map(Some)
                .map_err(CreateRefusal::Forum)
        },
    )
    .await;

    match result {
        Ok(Ok(Some(id))) => Json(serde_json::json!({ "id": id })).into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => create_refusal_response(e),
        Err(_) => internal_error(),
    }
}

// ============================================================================
// DELETE /api/forum/threads/{id}, DELETE /api/forum/replies/{id}
// ============================================================================

/// `DELETE /forum/threads/{id}` — the author hides their own thread. 204 on
/// success, bare 403 otherwise (not the author, already hidden, or unknown
/// id — all three are refused alike, no distinguishable states).
pub async fn delete_thread(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(thread_id): Path<i64>,
) -> Response {
    let user_id = match require_forum_access(state.clone(), &headers).await {
        Ok(uid) => uid,
        Err(resp) => return resp,
    };

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        db::hide_thread(&conn, thread_id, Some(user_id))
    })
    .await;

    match result {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => StatusCode::FORBIDDEN.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error hiding forum thread: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

/// `DELETE /forum/replies/{id}` — same contract as [`delete_thread`].
pub async fn delete_reply(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(reply_id): Path<i64>,
) -> Response {
    let user_id = match require_forum_access(state.clone(), &headers).await {
        Ok(uid) => uid,
        Err(resp) => return resp,
    };

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        db::hide_reply(&conn, reply_id, Some(user_id))
    })
    .await;

    match result {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => StatusCode::FORBIDDEN.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error hiding forum reply: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// POST /api/admin/forum/hide  (bearer ADMIN_SECRET)
// ============================================================================

/// Request body for `POST /admin/forum/hide`.
#[derive(serde::Deserialize)]
pub struct AdminHideRequest {
    pub kind: String,
    pub id: i64,
}

/// `POST /admin/forum/hide` — `{"kind":"thread"|"reply","id":N}`. Requires
/// `Authorization: Bearer {ADMIN_SECRET}`, checked before the body is ever
/// parsed (same rule `admin::register_release` documents). 204 if a visible
/// row was hidden, 404 if no such row existed (unknown id or already
/// hidden).
pub async fn admin_hide(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(e) = super::admin::verify_admin_secret(&state, &headers) {
        return e;
    }

    let req: AdminHideRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return bad_request("Invalid JSON body"),
    };
    if req.kind != "thread" && req.kind != "reply" {
        return bad_request("kind must be 'thread' or 'reply'");
    }

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        if req.kind == "thread" {
            db::hide_thread(&conn, req.id, None)
        } else {
            db::hide_reply(&conn, req.id, None)
        }
    })
    .await;

    match result {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error in admin forum hide: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_before_cursor_splits_on_pipe_and_rejects_malformed_input() {
        assert_eq!(
            parse_before_cursor("2026-09-05T00:00:00+00:00|42"),
            Some(("2026-09-05T00:00:00+00:00".to_string(), 42))
        );
        assert_eq!(parse_before_cursor("no-pipe-here"), None);
        assert_eq!(parse_before_cursor("|42"), None);
        assert_eq!(parse_before_cursor("2026-09-05T00:00:00+00:00|not-a-number"), None);
    }

    #[test]
    fn excerpt_truncates_by_character_not_byte() {
        let body = "a".repeat(200);
        assert_eq!(excerpt(&body).chars().count(), EXCERPT_CHARS);

        let short = "short body";
        assert_eq!(excerpt(short), short);

        // A multi-byte character sitting right at the boundary must not be
        // split — `chars().take(n)` never can, unlike a byte slice would.
        let multibyte = "é".repeat(200);
        let cut = excerpt(&multibyte);
        assert_eq!(cut.chars().count(), EXCERPT_CHARS);
        assert!(cut.chars().all(|c| c == 'é'));
    }
}

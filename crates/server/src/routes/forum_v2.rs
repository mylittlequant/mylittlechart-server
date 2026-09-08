//! Forum engine v2 — public boards, role-gated read/write, threaded replies,
//! moderation, and search (owner ruling 2026-09-05,
//! `docs/mlc/plans/social-sharing-access-gates-and-agent-control-2026-09-05.md`
//! §4-6). Unlike v1 (`routes/forum.rs`, still mounted unchanged), NOT every
//! route here requires a paid account — a board's own `read_class`/
//! `write_class` decide that per `social_db::can_read`/`can_write`, and an
//! anonymous caller can read a `public` board. Storage lives entirely in
//! `social.db` (`social_db.rs`) — this module never opens `AppState`'s
//! identity connection except to look up an author's display label
//! (`db::forum_author_label`) or a caller's paid status
//! (`db::user_is_paid`), exactly as v1 does.
//!
//! Endpoints (all under `/api`):
//!  - `GET    /forum/me`                               — caller's classes, held
//!                                                       role(s), and identity
//!                                                       (label/public_id) — the
//!                                                       client's moderation-row
//!                                                       gate reads this.
//!  - `GET    /forum/boards`                          — boards the caller can read.
//!  - `GET    /forum/boards/{slug}/threads?limit=&before=` — paged thread list.
//!  - `POST   /forum/boards/{slug}/threads`           — create a thread (write class).
//!  - `GET    /forum/v2/threads/{id}`                 — thread + reply tree
//!                                                       (hidden replies omitted
//!                                                       unless the caller is a
//!                                                       moderator/admin).
//!  - `POST   /forum/v2/threads/{id}/replies`         — create a reply, optionally
//!                                                       nested (`parent_reply_id`).
//!  - `DELETE /forum/v2/replies/{id}`                 — own reply, or moderator/admin.
//!  - `GET    /forum/search?q=&board=`                — FTS5 search, readable boards only.
//!  - `POST   /forum/v2/threads/{id}/moderate`        — moderator/admin: hide/unhide/
//!                                                       lock/unlock/pin/unpin/move.
//!  - `POST   /admin/forum/boards`                    — ADMIN_SECRET: create a board.
//!  - `PATCH  /admin/forum/boards/{id}`                — ADMIN_SECRET: partial update.
//!  - `DELETE /admin/forum/boards/{id}`                — ADMIN_SECRET: delete (refuses
//!                                                       a board that still has threads).
//!  - `PUT    /admin/forum/roles/{user_id}`            — ADMIN_SECRET: grant a role.
//!  - `DELETE /admin/forum/roles/{user_id}`            — ADMIN_SECRET: revoke it.
//!
//! Board CRUD and role CRUD are ADMIN_SECRET-gated (same bearer as every
//! other `/api/admin/*` route, including v1's `POST /admin/forum/hide`) —
//! they are operator actions, not something a `forum_roles` admin row grants
//! by itself. The per-thread `/moderate` action, by contrast, is gated by
//! the CALLER's own classes (`social_db::is_moderator_or_admin`): a signed-in
//! account holding a `forum_roles` row can moderate without ever touching
//! `ADMIN_SECRET`.

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::collections::HashMap;
use std::sync::Arc;

use crate::auth::{extract_bearer, extract_session_id, extract_ua_hash, hash_token};
use crate::db::{self, ForumError};
use crate::models::types::ErrorResponse;
use crate::social_db::{self, Class, ReplyError};
use crate::state::AppState;

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;
const SEARCH_LIMIT: i64 = 50;
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

fn forbidden(msg: &str) -> Response {
    (StatusCode::FORBIDDEN, Json(ErrorResponse::new(msg))).into_response()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse::new("Authentication required")),
    )
        .into_response()
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

fn forum_error_response(e: ForumError) -> Response {
    match e {
        ForumError::InvalidTitle => bad_request("title must be 3-120 characters"),
        ForumError::InvalidBody => bad_request("body must be 1-8192 bytes"),
        ForumError::Db(e) => {
            tracing::error!("DB error in forum_v2 route: {}", e);
            internal_error()
        }
    }
}

// ============================================================================
// Caller resolution — mirrors routes::forum's `resolve_user_id`, but
// anonymous is a valid outcome here (`Ok(None)`), not a 401: a `public`
// board must answer a signed-out caller.
// ============================================================================

async fn resolve_caller(state: Arc<AppState>, headers: &HeaderMap) -> Result<Option<i64>, Response> {
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
        Ok(Ok(caller)) => Ok(caller),
        Ok(Err(e)) => {
            tracing::error!("DB error resolving forum_v2 caller: {}", e);
            Err(internal_error())
        }
        Err(_) => Err(internal_error()),
    }
}

/// Resolve the caller's classes: looks up paid status on identity (if
/// signed in) then role on social, and combines them via
/// `social_db::caller_classes`. The identity lock is dropped before the
/// social lock is taken — the two connections are never held at once (see
/// this module's doc comment).
async fn resolve_caller_classes(state: Arc<AppState>, caller: Option<i64>) -> Result<Vec<Class>, Response> {
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Vec<Class>> {
        let is_paid = match caller {
            Some(uid) => {
                let identity_conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
                let paid = db::user_is_paid(&identity_conn, uid)?;
                drop(identity_conn);
                paid
            }
            None => false,
        };
        let social_conn = state.control_plane().social_conn();
        Ok(social_db::caller_classes(&social_conn, caller, is_paid))
    })
    .await;

    match result {
        Ok(Ok(classes)) => Ok(classes),
        Ok(Err(e)) => {
            tracing::error!("DB error resolving forum_v2 classes: {}", e);
            Err(internal_error())
        }
        Err(_) => Err(internal_error()),
    }
}

fn parse_before_cursor(raw: &str) -> Option<(String, i64)> {
    let (activity, id) = raw.split_once('|')?;
    if activity.is_empty() {
        return None;
    }
    let id: i64 = id.parse().ok()?;
    Some((activity.to_string(), id))
}

fn board_json(b: &social_db::Board) -> serde_json::Value {
    serde_json::json!({
        "id": b.id,
        "slug": b.slug,
        "title": b.title,
        "description": b.description,
        "read_class": b.read_class.as_str(),
        "write_class": b.write_class.as_str(),
        "position": b.position,
    })
}

// ============================================================================
// GET /api/forum/me
// ============================================================================

/// The caller's own classes, held role(s), and identity — what the client
/// needs to decide whether to show the moderation row on a thread/reply at
/// all, without guessing at the server's own gate. Same caller resolution as
/// every other v2 GET (`resolve_caller`/`resolve_caller_classes`): an
/// anonymous caller gets `{"classes": ["public"], "roles": [], "label":
/// null, "public_id": null}`, not a 401.
///
/// `roles` names the [`social_db::Role`] rows this caller actually holds via
/// [`social_db::caller_classes`] — at most one entry today, since a
/// `forum_roles` row is one managed role per account (`social_db::set_role`
/// upserts, it does not accumulate). `classes` is the full ladder the caller
/// satisfies (`public`, plus `user`/`paid`/`moderator`/`admin` as earned) —
/// what `social_db::can_read`/`can_write` compare a board's gate against.
///
/// Moderation permission table — MUST match [`moderate_thread`]'s action
/// arms exactly, since the client gates its moderation UI off this route's
/// `roles` field:
///
/// | Action                            | moderator | admin |
/// |------------------------------------|-----------|-------|
/// | hide / unhide a thread             | yes       | yes   |
/// | lock / unlock a thread             | yes       | yes   |
/// | pin / unpin a thread               | yes       | yes   |
/// | move a thread to another board     | yes       | yes   |
/// | delete (hide) any reply            | yes       | yes   |
/// | create/update/delete a board       | no — `ADMIN_SECRET` bearer only, regardless of `forum_roles` |
/// | grant/revoke a `forum_roles` row   | no — `ADMIN_SECRET` bearer only, regardless of `forum_roles` |
///
/// `moderator` and `admin` hold identical per-thread moderation permission —
/// [`social_db::is_moderator_or_admin`] (which [`moderate_thread`] and
/// [`create_reply`]/[`delete_reply`] all gate on) does not distinguish the
/// two ranks, it only checks `>= Class::Moderator`. Board CRUD and role CRUD
/// are a separate, stricter gate (`super::admin::verify_admin_secret`) that
/// a `forum_roles` row never satisfies by itself — those two admin-only rows
/// in the table above are not something this route's `roles` field can ever
/// unlock client-side.
pub async fn me(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let caller = match resolve_caller(state.clone(), &headers).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let classes = match resolve_caller_classes(state.clone(), caller).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let roles: Vec<&'static str> = classes.iter().filter(|c| **c >= Class::Moderator).map(|c| c.as_str()).collect();
    let classes_json: Vec<&'static str> = classes.iter().map(|c| c.as_str()).collect();

    let Some(user_id) = caller else {
        return Json(serde_json::json!({
            "classes": classes_json,
            "roles": roles,
            "label": serde_json::Value::Null,
            "public_id": serde_json::Value::Null,
        }))
        .into_response();
    };

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<(String, Option<String>)> {
        let identity_conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let label = db::effective_label_for_user(&identity_conn, user_id)?;
        let public_id = db::get_user_public_id(&identity_conn, user_id).ok();
        Ok((label, public_id))
    })
    .await;

    match result {
        Ok(Ok((label, public_id))) => Json(serde_json::json!({
            "classes": classes_json,
            "roles": roles,
            "label": label,
            "public_id": public_id,
        }))
        .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error resolving forum_v2 caller identity: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// GET /api/forum/boards
// ============================================================================

pub async fn list_boards(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let caller = match resolve_caller(state.clone(), &headers).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let classes = match resolve_caller_classes(state.clone(), caller).await {
        Ok(c) => c,
        Err(e) => return e,
    };

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Vec<social_db::Board>> {
        let conn = state.control_plane().social_conn();
        social_db::list_boards(&conn)
    })
    .await;

    match result {
        Ok(Ok(boards)) => {
            let visible: Vec<_> = boards.into_iter().filter(|b| social_db::can_read(b, &classes)).collect();
            Json(serde_json::json!({
                "boards": visible.iter().map(board_json).collect::<Vec<_>>(),
            }))
            .into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("DB error listing forum boards: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// GET /api/forum/boards/{slug}/threads
// ============================================================================

#[derive(serde::Deserialize)]
pub struct ListThreadsQuery {
    pub limit: Option<i64>,
    pub before: Option<String>,
}

pub async fn list_board_threads(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Query(query): Query<ListThreadsQuery>,
) -> Response {
    let caller = match resolve_caller(state.clone(), &headers).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let classes = match resolve_caller_classes(state.clone(), caller).await {
        Ok(c) => c,
        Err(e) => return e,
    };

    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let before = match query.before.as_deref() {
        Some(raw) => match parse_before_cursor(raw) {
            Some(cursor) => Some(cursor),
            None => return bad_request("before must be '<last_activity>|<id>'"),
        },
        None => None,
    };

    type ThreadRows = Vec<(social_db::ForumThreadV2, String)>;
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<ThreadRows>> {
        let conn = state.control_plane().social_conn();
        let Some(board) = social_db::get_board_by_slug(&conn, &slug)? else {
            return Ok(None);
        };
        if !social_db::can_read(&board, &classes) {
            return Ok(None);
        }
        let before_ref = before.as_ref().map(|(a, i)| (a.as_str(), *i));
        let threads = social_db::list_threads_v2(&conn, board.id, limit.saturating_add(1), before_ref)?;
        drop(conn);

        let identity_conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::with_capacity(threads.len());
        for t in threads {
            let author = db::forum_author_label(&identity_conn, t.author_user_id)?;
            out.push((t, author));
        }
        Ok(Some(out))
    })
    .await;

    match result {
        Ok(Ok(Some(mut rows))) => {
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
                    "board_id": t.board_id,
                    "title": t.title,
                    "author": author,
                    "author_is_me": Some(t.author_user_id) == caller,
                    "created_at": t.created_at,
                    "updated_at": t.updated_at,
                    "last_reply_at": t.last_reply_at,
                    "reply_count": t.reply_count,
                    "pinned": t.pinned,
                    "locked": t.locked,
                })).collect::<Vec<_>>(),
                "next_before": next_before,
            }))
            .into_response()
        }
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error listing forum_v2 threads: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// POST /api/forum/boards/{slug}/threads
// ============================================================================

enum ThreadCreateRefusal {
    Forum(ForumError),
    RateLimited,
    Forbidden,
}

impl From<rusqlite::Error> for ThreadCreateRefusal {
    fn from(e: rusqlite::Error) -> Self {
        ThreadCreateRefusal::Forum(ForumError::Db(e))
    }
}

#[derive(serde::Deserialize)]
pub struct CreateThreadRequest {
    pub title: String,
    pub body: String,
}

pub async fn create_board_thread(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Json(req): Json<CreateThreadRequest>,
) -> Response {
    let caller = match resolve_caller(state.clone(), &headers).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let Some(user_id) = caller else {
        return unauthorized();
    };
    let classes = match resolve_caller_classes(state.clone(), caller).await {
        Ok(c) => c,
        Err(e) => return e,
    };

    let result = tokio::task::spawn_blocking(
        move || -> std::result::Result<Option<i64>, ThreadCreateRefusal> {
            let conn = state.control_plane().social_conn();
            let Some(board) = social_db::get_board_by_slug(&conn, &slug)? else {
                return Ok(None);
            };
            if !social_db::can_write(&board, &classes) {
                return Err(ThreadCreateRefusal::Forbidden);
            }
            let now = chrono::Utc::now();
            let since = (now - chrono::Duration::seconds(RATE_LIMIT_WINDOW_SECS)).to_rfc3339();
            let recent = social_db::threads_v2_created_since(&conn, user_id, &since)?;
            if recent >= THREAD_RATE_LIMIT_MAX {
                return Err(ThreadCreateRefusal::RateLimited);
            }
            social_db::create_thread_v2(&conn, board.id, user_id, &req.title, &req.body, &now.to_rfc3339())
                .map(Some)
                .map_err(ThreadCreateRefusal::Forum)
        },
    )
    .await;

    match result {
        Ok(Ok(Some(id))) => Json(serde_json::json!({ "id": id })).into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(ThreadCreateRefusal::Forum(e))) => forum_error_response(e),
        Ok(Err(ThreadCreateRefusal::RateLimited)) => rate_limited(),
        Ok(Err(ThreadCreateRefusal::Forbidden)) => forbidden("write access to this board requires a higher class"),
        Err(_) => internal_error(),
    }
}

// ============================================================================
// GET /api/forum/v2/threads/{id}
// ============================================================================

fn render_reply_tree(nodes: &[social_db::ReplyNode], labels: &HashMap<i64, String>, caller: Option<i64>) -> Vec<serde_json::Value> {
    nodes
        .iter()
        .map(|n| {
            let author = labels.get(&n.reply.id).cloned().unwrap_or_else(|| "deleted user".to_string());
            serde_json::json!({
                "id": n.reply.id,
                "parent_reply_id": n.reply.parent_reply_id,
                "depth": n.reply.depth,
                "author": author,
                "author_is_me": Some(n.reply.author_user_id) == caller,
                "body": n.reply.body,
                "created_at": n.reply.created_at,
                "hidden": n.reply.hidden,
                "children": render_reply_tree(&n.children, labels, caller),
            })
        })
        .collect()
}

pub async fn get_thread(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(thread_id): Path<i64>) -> Response {
    let caller = match resolve_caller(state.clone(), &headers).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let classes = match resolve_caller_classes(state.clone(), caller).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let is_mod = social_db::is_moderator_or_admin(&classes);

    type ThreadWithReplies = (social_db::ForumThreadV2, String, Vec<(social_db::ForumReplyV2, String)>);
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<ThreadWithReplies>> {
        let conn = state.control_plane().social_conn();
        let Some(thread) = social_db::get_thread_v2(&conn, thread_id, is_mod)? else {
            return Ok(None);
        };
        let Some(board) = social_db::get_board_by_id(&conn, thread.board_id)? else {
            return Ok(None);
        };
        if !social_db::can_read(&board, &classes) {
            return Ok(None);
        }
        let replies = social_db::list_replies_v2(&conn, thread_id, is_mod)?;
        drop(conn);

        let identity_conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let thread_author = db::forum_author_label(&identity_conn, thread.author_user_id)?;
        let mut reply_rows = Vec::with_capacity(replies.len());
        for r in replies {
            let author = db::forum_author_label(&identity_conn, r.author_user_id)?;
            reply_rows.push((r, author));
        }
        Ok(Some((thread, thread_author, reply_rows)))
    })
    .await;

    match result {
        Ok(Ok(Some((thread, thread_author, reply_rows)))) => {
            let labels: HashMap<i64, String> = reply_rows.iter().map(|(r, label)| (r.id, label.clone())).collect();
            let flat: Vec<social_db::ForumReplyV2> = reply_rows.into_iter().map(|(r, _)| r).collect();
            let tree = social_db::assemble_reply_tree(flat);
            Json(serde_json::json!({
                "thread": {
                    "id": thread.id,
                    "board_id": thread.board_id,
                    "title": thread.title,
                    "author": thread_author,
                    "author_is_me": Some(thread.author_user_id) == caller,
                    "body": thread.body,
                    "created_at": thread.created_at,
                    "updated_at": thread.updated_at,
                    "pinned": thread.pinned,
                    "locked": thread.locked,
                    "hidden": thread.hidden,
                },
                "replies": render_reply_tree(&tree, &labels, caller),
            }))
            .into_response()
        }
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error fetching forum_v2 thread: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// POST /api/forum/v2/threads/{id}/replies
// ============================================================================

enum ReplyCreateRefusal {
    Reply(ReplyError),
    RateLimited,
    Forbidden,
    Locked,
}

impl From<rusqlite::Error> for ReplyCreateRefusal {
    fn from(e: rusqlite::Error) -> Self {
        ReplyCreateRefusal::Reply(ReplyError::Forum(ForumError::Db(e)))
    }
}

#[derive(serde::Deserialize)]
pub struct CreateReplyRequest {
    pub body: String,
    pub parent_reply_id: Option<i64>,
}

pub async fn create_reply(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(thread_id): Path<i64>,
    Json(req): Json<CreateReplyRequest>,
) -> Response {
    let caller = match resolve_caller(state.clone(), &headers).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let Some(user_id) = caller else {
        return unauthorized();
    };
    let classes = match resolve_caller_classes(state.clone(), caller).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let is_mod = social_db::is_moderator_or_admin(&classes);

    let result = tokio::task::spawn_blocking(
        move || -> std::result::Result<Option<i64>, ReplyCreateRefusal> {
            let conn = state.control_plane().social_conn();
            let Some(thread) = social_db::get_thread_v2(&conn, thread_id, is_mod)? else {
                return Ok(None);
            };
            if thread.locked && !is_mod {
                return Err(ReplyCreateRefusal::Locked);
            }
            let Some(board) = social_db::get_board_by_id(&conn, thread.board_id)? else {
                return Ok(None);
            };
            if !social_db::can_write(&board, &classes) {
                return Err(ReplyCreateRefusal::Forbidden);
            }
            let now = chrono::Utc::now();
            let since = (now - chrono::Duration::seconds(RATE_LIMIT_WINDOW_SECS)).to_rfc3339();
            let recent = social_db::replies_v2_created_since(&conn, user_id, &since)?;
            if recent >= REPLY_RATE_LIMIT_MAX {
                return Err(ReplyCreateRefusal::RateLimited);
            }
            social_db::create_reply_v2(&conn, thread_id, req.parent_reply_id, user_id, &req.body, &now.to_rfc3339())
                .map(Some)
                .map_err(ReplyCreateRefusal::Reply)
        },
    )
    .await;

    match result {
        Ok(Ok(Some(id))) => Json(serde_json::json!({ "id": id })).into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(ReplyCreateRefusal::Reply(ReplyError::Forum(e)))) => forum_error_response(e),
        Ok(Err(ReplyCreateRefusal::Reply(ReplyError::ParentNotFound))) => {
            bad_request("parent_reply_id must name a visible reply in the same thread")
        }
        Ok(Err(ReplyCreateRefusal::RateLimited)) => rate_limited(),
        Ok(Err(ReplyCreateRefusal::Forbidden)) => forbidden("write access to this board requires a higher class"),
        Ok(Err(ReplyCreateRefusal::Locked)) => forbidden("thread is locked"),
        Err(_) => internal_error(),
    }
}

// ============================================================================
// DELETE /api/forum/v2/replies/{id}
// ============================================================================

pub async fn delete_reply(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(reply_id): Path<i64>) -> Response {
    let caller = match resolve_caller(state.clone(), &headers).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let Some(user_id) = caller else {
        return unauthorized();
    };
    let classes = match resolve_caller_classes(state.clone(), caller).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let is_mod = social_db::is_moderator_or_admin(&classes);

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
        let conn = state.control_plane().social_conn();
        let owner = if is_mod { None } else { Some(user_id) };
        social_db::delete_reply_v2(&conn, reply_id, owner)
    })
    .await;

    match result {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => StatusCode::FORBIDDEN.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error hiding forum_v2 reply: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// GET /api/forum/search
// ============================================================================

#[derive(serde::Deserialize)]
pub struct SearchQuery {
    pub q: Option<String>,
    pub board: Option<String>,
}

fn search_hit_json(hit: &social_db::SearchHit, author: &str) -> serde_json::Value {
    serde_json::json!({
        "kind": hit.kind,
        "board_id": hit.board_id,
        "thread_id": hit.thread_id,
        "reply_id": hit.reply_id,
        "title": hit.title,
        "snippet": hit.snippet,
        "author": author,
        "created_at": hit.created_at,
    })
}

pub async fn search(State(state): State<Arc<AppState>>, headers: HeaderMap, Query(query): Query<SearchQuery>) -> Response {
    let q = match query.q.as_deref() {
        Some(q) if social_db::is_valid_search_query(q) => q.to_string(),
        _ => return bad_request("q must be 1-200 characters"),
    };
    let caller = match resolve_caller(state.clone(), &headers).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let classes = match resolve_caller_classes(state.clone(), caller).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let board_filter = query.board.clone();

    type HitRows = Vec<(social_db::SearchHit, String)>;
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<HitRows> {
        let conn = state.control_plane().social_conn();
        let boards = social_db::list_boards(&conn)?;
        let readable: Vec<i64> = boards
            .iter()
            .filter(|b| social_db::can_read(b, &classes))
            .filter(|b| board_filter.as_deref().is_none_or(|slug| slug == b.slug))
            .map(|b| b.id)
            .collect();
        let hits = social_db::search(&conn, &q, &readable, SEARCH_LIMIT)?;
        drop(conn);

        let identity_conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::with_capacity(hits.len());
        for hit in hits {
            let author = db::forum_author_label(&identity_conn, hit.author_user_id)?;
            out.push((hit, author));
        }
        Ok(out)
    })
    .await;

    match result {
        Ok(Ok(rows)) => Json(serde_json::json!({
            "results": rows.iter().map(|(hit, author)| search_hit_json(hit, author)).collect::<Vec<_>>(),
        }))
        .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error searching forum: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// POST /api/forum/v2/threads/{id}/moderate
// ============================================================================

#[derive(serde::Deserialize)]
pub struct ModerateRequest {
    pub action: String,
    pub board: Option<String>,
}

pub async fn moderate_thread(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(thread_id): Path<i64>,
    Json(req): Json<ModerateRequest>,
) -> Response {
    let caller = match resolve_caller(state.clone(), &headers).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    if caller.is_none() {
        return unauthorized();
    }
    let classes = match resolve_caller_classes(state.clone(), caller).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    if !social_db::is_moderator_or_admin(&classes) {
        return forbidden("moderator or admin role required");
    }

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<bool>> {
        let conn = state.control_plane().social_conn();
        if social_db::get_thread_v2(&conn, thread_id, true)?.is_none() {
            return Ok(None);
        }
        let ok = match req.action.as_str() {
            "hide" => social_db::hide_thread_v2(&conn, thread_id)?,
            "unhide" => social_db::unhide_thread_v2(&conn, thread_id)?,
            "lock" => social_db::lock_thread_v2(&conn, thread_id)?,
            "unlock" => social_db::unlock_thread_v2(&conn, thread_id)?,
            "pin" => social_db::pin_thread_v2(&conn, thread_id)?,
            "unpin" => social_db::unpin_thread_v2(&conn, thread_id)?,
            "move" => match req.board.as_deref().and_then(|slug| social_db::get_board_by_slug(&conn, slug).transpose()) {
                Some(Ok(board)) => social_db::move_thread_v2(&conn, thread_id, board.id)?,
                Some(Err(e)) => return Err(e),
                None => false,
            },
            _ => false,
        };
        Ok(Some(ok))
    })
    .await;

    match result {
        Ok(Ok(Some(true))) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(Some(false))) => bad_request("unknown action, or 'move' missing a valid target board"),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error moderating forum_v2 thread: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// Admin: board + role CRUD (bearer ADMIN_SECRET)
// ============================================================================

#[derive(serde::Deserialize)]
pub struct AdminCreateBoardRequest {
    pub slug: String,
    pub title: String,
    pub description: Option<String>,
    pub read_class: String,
    pub write_class: String,
    pub position: Option<i64>,
}

fn parse_class_field(name: &str, raw: &str) -> Result<Class, Response> {
    Class::from_wire_name(raw)
        .ok_or_else(|| bad_request(&format!("{name} must be one of public|user|paid|moderator|admin")))
}

pub async fn admin_create_board(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(e) = super::admin::verify_admin_secret(&state, &headers) {
        return e;
    }
    let req: AdminCreateBoardRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return bad_request("Invalid JSON body"),
    };
    if req.slug.trim().is_empty() || req.title.trim().is_empty() {
        return bad_request("slug and title are required");
    }
    let read_class = match parse_class_field("read_class", &req.read_class) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let write_class = match parse_class_field("write_class", &req.write_class) {
        Ok(c) => c,
        Err(e) => return e,
    };

    let result = tokio::task::spawn_blocking(move || -> std::result::Result<i64, social_db::BoardError> {
        let conn = state.control_plane().social_conn();
        let now = chrono::Utc::now().to_rfc3339();
        social_db::create_board(
            &conn,
            &req.slug,
            &req.title,
            req.description.as_deref().unwrap_or(""),
            read_class,
            write_class,
            req.position.unwrap_or(0),
            &now,
        )
    })
    .await;

    match result {
        Ok(Ok(id)) => Json(serde_json::json!({ "id": id })).into_response(),
        Ok(Err(social_db::BoardError::SlugTaken)) => {
            (StatusCode::CONFLICT, Json(ErrorResponse::new("slug already exists"))).into_response()
        }
        Ok(Err(social_db::BoardError::Db(e))) => {
            tracing::error!("DB error creating forum board: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

#[derive(serde::Deserialize)]
pub struct AdminUpdateBoardRequest {
    pub title: Option<String>,
    pub description: Option<String>,
    pub read_class: Option<String>,
    pub write_class: Option<String>,
    pub position: Option<i64>,
}

pub async fn admin_update_board(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    body: Bytes,
) -> Response {
    if let Err(e) = super::admin::verify_admin_secret(&state, &headers) {
        return e;
    }
    let req: AdminUpdateBoardRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return bad_request("Invalid JSON body"),
    };
    let read_class = match req.read_class.as_deref().map(|s| parse_class_field("read_class", s)) {
        Some(Ok(c)) => Some(c),
        Some(Err(e)) => return e,
        None => None,
    };
    let write_class = match req.write_class.as_deref().map(|s| parse_class_field("write_class", s)) {
        Some(Ok(c)) => Some(c),
        Some(Err(e)) => return e,
        None => None,
    };

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
        let conn = state.control_plane().social_conn();
        social_db::update_board(
            &conn,
            id,
            req.title.as_deref(),
            req.description.as_deref(),
            read_class,
            write_class,
            req.position,
        )
    })
    .await;

    match result {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error updating forum board: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

pub async fn admin_delete_board(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<i64>) -> Response {
    if let Err(e) = super::admin::verify_admin_secret(&state, &headers) {
        return e;
    }

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<bool>> {
        let conn = state.control_plane().social_conn();
        if social_db::board_thread_count(&conn, id)? > 0 {
            return Ok(None);
        }
        Ok(Some(social_db::delete_board(&conn, id)?))
    })
    .await;

    match result {
        Ok(Ok(Some(true))) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(Some(false))) => StatusCode::NOT_FOUND.into_response(),
        Ok(Ok(None)) => (StatusCode::CONFLICT, Json(ErrorResponse::new("board still has threads"))).into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error deleting forum board: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

#[derive(serde::Deserialize)]
pub struct AdminSetRoleRequest {
    pub role: String,
}

pub async fn admin_set_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(user_id): Path<i64>,
    body: Bytes,
) -> Response {
    if let Err(e) = super::admin::verify_admin_secret(&state, &headers) {
        return e;
    }
    let req: AdminSetRoleRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return bad_request("Invalid JSON body"),
    };
    let Some(role) = social_db::Role::from_wire_name(&req.role) else {
        return bad_request("role must be 'moderator' or 'admin'");
    };

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<()> {
        let conn = state.control_plane().social_conn();
        social_db::set_role(&conn, user_id, role, &chrono::Utc::now().to_rfc3339())
    })
    .await;

    match result {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error setting forum role: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

pub async fn admin_remove_role(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(user_id): Path<i64>) -> Response {
    if let Err(e) = super::admin::verify_admin_secret(&state, &headers) {
        return e;
    }

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
        let conn = state.control_plane().social_conn();
        social_db::remove_role(&conn, user_id)
    })
    .await;

    match result {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error removing forum role: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

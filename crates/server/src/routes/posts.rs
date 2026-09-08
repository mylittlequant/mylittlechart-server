//! In-app blog: patch notes and posts, pushed one at a time by an operator
//! script (see docs/mlc/plans/web-surface-cleanup-and-in-app-blog-2026-09-05.md).
//! Replaces the static `web/blog/posts.json`/`web/blog/index.html` that used
//! to be redeployed whole for every entry — the database is now the single
//! source, and every surface below reads it (see db.rs's "Posts" section).
//!
//! Endpoints:
//!  - `GET    /api/posts`            — public list, `?kind=&limit=&before=`.
//!  - `GET    /api/posts/{id}`       — public single post, bare 404 if absent
//!                                     or not public.
//!  - `POST   /api/admin/posts`      — bearer `ADMIN_SECRET`, upsert by id
//!                                     (same shape as `admin::register_release`:
//!                                     auth before the body is ever parsed).
//!  - `DELETE /api/admin/posts/{id}` — bearer `ADMIN_SECRET`.
//!  - `GET    /blog/posts.json`      — compatibility shape for already-
//!                                     released native clients (0.5.588+)
//!                                     that fetch this URL directly; public,
//!                                     up to 200 rows, newest first.
//!  - `GET    /blog/feed.xml`        — Atom 1.0, for crawlers that poll feeds
//!                                     rather than render JS.
//!  - `GET    /blog/`, `GET /blog/{id}` — server-rendered HTML mirror, same
//!                                     bytes for every user agent (no
//!                                     cloaking), replacing the deleted
//!                                     static `web/blog/*`.
//!
//! All public reads are `visibility = 'public'` only — `'paid'` rows exist
//! for a future gated tier and are invisible on every route in this module.
//! The `/blog/*` routes are control-role only (they read `state.control_plane()`
//! directly, same as `routes::dashboard` and the admin routes) — see
//! `main.rs`, which only mounts them when `role == ServerRole::Control`.

use axum::{
    body::Bytes,
    extract::{ConnectInfo, Extension, Path, Query, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    Json,
};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::db::{Post, PostError};
use crate::models::types::ErrorResponse;
use crate::state::AppState;

/// Public origin every absolute URL in the feed/HTML mirror is built from —
/// same hardcoded constant the rest of the server already uses (see
/// `routes::oauth::WEB_CALLBACK_BASE`, `routes::link::init_link`, etc.).
const SITE_ORIGIN: &str = "https://mylittlechart.org";

/// Default page size for `GET /api/posts` when `limit` is omitted.
const DEFAULT_LIMIT: i64 = 50;

/// Ceiling on `limit` regardless of what the caller asks for.
const MAX_LIMIT: i64 = 200;

/// Row cap for the unpaginated surfaces (`/blog/posts.json`, `/blog/feed.xml`,
/// `/blog/`) — generous enough that no real blog hits it, small enough that
/// none of the three can be made to render an unbounded page.
const UNPAGINATED_LIMIT: i64 = 200;

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

fn post_error_response(e: PostError) -> Response {
    match e {
        PostError::InvalidId => bad_request("id must match [a-z0-9][a-z0-9-]{1,80}"),
        PostError::InvalidKind => bad_request("kind must be 'patch' or 'post'"),
        PostError::InvalidDate => bad_request("date must be a real YYYY-MM-DD date"),
        PostError::InvalidVisibility => bad_request("visibility must be 'public' or 'paid'"),
        PostError::Db(e) => {
            tracing::error!("DB error upserting post: {}", e);
            internal_error()
        }
    }
}

/// The wire shape every public/compat read answers with: `id`, `kind`,
/// `version`, `date`, `title`, `summary`, `body`, `url` — `visibility`,
/// `created_at`, `updated_at` stay internal.
fn post_json(p: &Post) -> serde_json::Value {
    serde_json::json!({
        "id": p.id,
        "kind": p.kind,
        "version": p.version,
        "date": p.date,
        "title": p.title,
        "summary": p.summary,
        "body": p.body,
        "url": p.url,
    })
}

/// `/blog/<id>` — the path every generated link and Atom entry points at.
fn post_path(p: &Post) -> String {
    format!("/blog/{}", p.id)
}

/// Parse a `before` cursor of the exact form `"<date>|<id>"` the `next_before`
/// field of `GET /api/posts` hands back. Returns `None` on any other shape —
/// callers must map that to a 400, not a silently-ignored filter.
fn parse_before_cursor(raw: &str) -> Option<(String, String)> {
    let (date, id) = raw.split_once('|')?;
    if date.is_empty() || id.is_empty() {
        return None;
    }
    Some((date.to_string(), id.to_string()))
}

// ============================================================================
// GET /api/posts  (public)
// ============================================================================

/// Query params for `GET /api/posts`.
#[derive(serde::Deserialize)]
pub struct ListPostsQuery {
    pub kind: Option<String>,
    pub limit: Option<i64>,
    pub before: Option<String>,
}

/// `GET /api/posts?kind=&limit=&before=`
///
/// Public, `visibility = 'public'` only. Answers
/// `{"posts": [...], "next_before": "<date>|<id>" | null}` — `next_before` is
/// `null` once the caller has reached the oldest post. Pagination is a
/// one-row lookahead (`limit + 1` fetched, the extra row dropped and used
/// only to decide whether a next page exists) rather than trusting "got
/// exactly `limit` rows" — a real next page and a page that just happens to
/// end exactly on a limit boundary are otherwise indistinguishable.
pub async fn list_posts(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListPostsQuery>,
) -> Response {
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    let kind = match query.kind {
        Some(ref k) if k == "patch" || k == "post" => Some(k.clone()),
        Some(_) => return bad_request("kind must be 'patch' or 'post'"),
        None => None,
    };

    let before = match query.before.as_deref() {
        Some(raw) => match parse_before_cursor(raw) {
            Some(cursor) => Some(cursor),
            None => return bad_request("before must be '<date>|<id>'"),
        },
        None => None,
    };

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Vec<Post>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let before_ref = before.as_ref().map(|(d, i)| (d.as_str(), i.as_str()));
        crate::db::list_posts(&conn, kind.as_deref(), limit.saturating_add(1), before_ref)
    })
    .await;

    match result {
        Ok(Ok(mut posts)) => {
            let has_more = posts.len() as i64 > limit;
            if has_more {
                posts.truncate(limit as usize);
            }
            let next_before = if has_more {
                posts.last().map(|p| format!("{}|{}", p.date, p.id))
            } else {
                None
            };
            Json(serde_json::json!({
                "posts": posts.iter().map(post_json).collect::<Vec<_>>(),
                "next_before": next_before,
            }))
            .into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("DB error listing posts: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// GET /api/posts/{id}  (public)
// ============================================================================

/// `GET /api/posts/{id}` — one public post, or a bare 404.
pub async fn get_post(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::get_post(&conn, &id, false)
    })
    .await;

    match result {
        Ok(Ok(Some(post))) => Json(post_json(&post)).into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error fetching post: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// POST /api/admin/posts  (bearer ADMIN_SECRET)
// ============================================================================

/// Request body for `POST /api/admin/posts` — the post object verbatim.
/// `url` is optional and defaults to `/blog/<id>`; `visibility` defaults to
/// `'public'`.
#[derive(serde::Deserialize)]
pub struct UpsertPostRequest {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub version: Option<String>,
    pub date: String,
    pub title: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default = "default_post_visibility")]
    pub visibility: String,
}

fn default_post_visibility() -> String {
    "public".to_string()
}

/// `POST /api/admin/posts`
///
/// Requires `Authorization: Bearer {ADMIN_SECRET}`, checked before the body
/// is ever parsed — same rule `admin::register_release` documents: an
/// unauthenticated probe gets a bare 404 (see `admin::verify_admin_secret`)
/// and nothing about the endpoint's shape. Upserts by `id`; answers
/// `{"id": ..., "created": bool}`.
pub async fn admin_upsert_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Bytes,
) -> Response {
    if let Err(e) = super::admin::verify_admin_secret(&state, &headers, &uri, super::admin::peer_addr(peer)) {
        return e;
    }

    let req: UpsertPostRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return bad_request("Invalid JSON body"),
    };

    let now = chrono::Utc::now().to_rfc3339();
    let url = req.url.unwrap_or_else(|| format!("/blog/{}", req.id));
    let post = Post {
        id: req.id,
        kind: req.kind,
        version: req.version,
        date: req.date,
        title: req.title,
        summary: req.summary,
        body: req.body,
        url,
        visibility: req.visibility,
        created_at: now.clone(),
        updated_at: now.clone(),
    };
    let id_for_response = post.id.clone();

    let result = tokio::task::spawn_blocking(move || -> std::result::Result<bool, PostError> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::upsert_post(&conn, &post, &now)
    })
    .await;

    match result {
        Ok(Ok(created)) => Json(serde_json::json!({ "id": id_for_response, "created": created }))
            .into_response(),
        Ok(Err(e)) => post_error_response(e),
        Err(_) => internal_error(),
    }
}

// ============================================================================
// DELETE /api/admin/posts/{id}  (bearer ADMIN_SECRET)
// ============================================================================

/// `DELETE /api/admin/posts/{id}` — 204 on delete, 404 if no such post.
pub async fn admin_delete_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(id): Path<String>,
) -> Response {
    if let Err(e) = super::admin::verify_admin_secret(&state, &headers, &uri, super::admin::peer_addr(peer)) {
        return e;
    }

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::delete_post(&conn, &id)
    })
    .await;

    match result {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error deleting post: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// GET /blog/posts.json  (public, compatibility)
// ============================================================================

/// `GET /blog/posts.json`
///
/// Compatibility shape for already-released native clients (0.5.588+) that
/// fetch this URL directly rather than `/api/posts` — see this module's doc
/// comment. Public, newest first, up to [`UNPAGINATED_LIMIT`] rows, no
/// pagination (none of the shipped readers understand `next_before`).
pub async fn compat_posts_json(State(state): State<Arc<AppState>>) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::list_posts(&conn, None, UNPAGINATED_LIMIT, None)
    })
    .await;

    match result {
        Ok(Ok(posts)) => Json(serde_json::json!({
            "posts": posts.iter().map(post_json).collect::<Vec<_>>(),
        }))
        .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error serving /blog/posts.json: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// HTML escaping + paragraph splitting — shared by the Atom feed and the HTML
// mirror below.
// ============================================================================

/// Escape the five characters that matter in both HTML and XML text content
/// — the two formats share the same escaping rules, so one function serves
/// both call sites below.
fn escape_markup(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Split `body` into paragraphs on blank (or whitespace-only) lines — the
/// convention `db.rs`'s doc comment on the `posts` table describes ("plain
/// text, paragraphs separated by a blank line — no markdown"), matching the
/// client-side renderers today's static `blog/index.html` used.
fn split_paragraphs(body: &str) -> Vec<String> {
    let mut paragraphs = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    for line in body.lines() {
        if line.trim().is_empty() {
            if !current.is_empty() {
                paragraphs.push(current.join("\n"));
                current.clear();
            }
        } else {
            current.push(line);
        }
    }
    if !current.is_empty() {
        paragraphs.push(current.join("\n"));
    }
    paragraphs
}

/// Render `body` as `<p>` paragraphs, HTML-escaped, with a single embedded
/// newline inside a paragraph rendered as `<br>`.
fn paragraphs_to_html(body: &str) -> String {
    split_paragraphs(body)
        .into_iter()
        .map(|p| format!("<p>{}</p>", escape_markup(&p).replace('\n', "<br>")))
        .collect::<Vec<_>>()
        .join("\n")
}

// ============================================================================
// GET /blog/feed.xml  (public, Atom 1.0)
// ============================================================================

fn render_atom_feed(posts: &[Post]) -> String {
    let feed_updated = posts
        .first()
        .map(|p| p.updated_at.clone())
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

    let entries: String = posts
        .iter()
        .map(|p| {
            let url = format!("{}{}", SITE_ORIGIN, post_path(p));
            // `type="html"` content is escaped HTML: the `<p>` markup itself
            // must be escaped again so it survives as XML text content — a
            // reader unescapes the XML layer once to recover the HTML
            // string, then its own HTML parser unescapes that.
            let content = escape_markup(&paragraphs_to_html(&p.body));
            format!(
                "<entry><id>{url}</id><title>{title}</title><link href=\"{url}\"/>\
                 <updated>{updated}</updated><published>{published}</published>\
                 <summary>{summary}</summary><content type=\"html\">{content}</content></entry>",
                url = url,
                title = escape_markup(&p.title),
                updated = escape_markup(&p.updated_at),
                published = escape_markup(&p.created_at),
                summary = escape_markup(&p.summary),
                content = content,
            )
        })
        .collect();

    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <feed xmlns=\"http://www.w3.org/2005/Atom\">\
         <id>{origin}/blog/feed.xml</id><title>mylittlechart blog</title>\
         <link href=\"{origin}/blog/feed.xml\" rel=\"self\"/><link href=\"{origin}/blog/\"/>\
         <updated>{updated}</updated>{entries}</feed>",
        origin = SITE_ORIGIN,
        updated = escape_markup(&feed_updated),
        entries = entries,
    )
}

/// `GET /blog/feed.xml` — Atom 1.0, public, newest [`UNPAGINATED_LIMIT`]
/// posts. Polled by feed-aware crawlers (Perplexity et al.) rather than
/// rendered — see the SEO/AEO research this module's doc comment links.
pub async fn feed_xml(State(state): State<Arc<AppState>>) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::list_posts(&conn, None, UNPAGINATED_LIMIT, None)
    })
    .await;

    match result {
        Ok(Ok(posts)) => Response::builder()
            .status(200)
            .header("content-type", "application/atom+xml; charset=utf-8")
            .header("cache-control", "public, max-age=300")
            .body(axum::body::Body::from(render_atom_feed(&posts)))
            .unwrap(),
        Ok(Err(e)) => {
            tracing::error!("DB error rendering /blog/feed.xml: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ============================================================================
// GET /blog/, GET /blog/{id}  (public, server-rendered HTML mirror)
// ============================================================================

/// Inline stylesheet shared by the index and single-post pages — small on
/// purpose (see this module's doc comment: "keep the markup small").
const PAGE_STYLE: &str = "body{max-width:720px;margin:0 auto;padding:24px 16px 80px;\
font-family:system-ui,sans-serif;line-height:1.6;background:#0a0f1a;color:#FEFFEE}\
a{color:#8ecdf0}.kind{display:inline-block;font-size:12px;padding:2px 8px;\
border-radius:4px;background:#1b2436;margin-right:8px}\
.date{color:#9aa4b8;font-size:14px}\
article{margin-bottom:32px;padding-bottom:24px;border-bottom:1px solid #1b2436}\
h1{font-size:22px}\
h2{font-size:15px;text-transform:uppercase;letter-spacing:.05em;color:#9aa4b8;margin:32px 0 12px}";

fn render_blog_index(posts: &[Post]) -> String {
    let patches: Vec<&Post> = posts.iter().filter(|p| p.kind == "patch").collect();
    let posts_only: Vec<&Post> = posts.iter().filter(|p| p.kind != "patch").collect();

    fn section(heading: &str, items: &[&Post]) -> String {
        if items.is_empty() {
            return String::new();
        }
        let articles: String = items
            .iter()
            .map(|p| {
                format!(
                    "<article><span class=\"date\">{date}</span> \
                     <span class=\"kind\">{kind}</span>\
                     <h1><a href=\"{path}\">{title}</a></h1><p>{summary}</p></article>",
                    date = escape_markup(&p.date),
                    kind = escape_markup(&p.kind),
                    path = escape_markup(&post_path(p)),
                    title = escape_markup(&p.title),
                    summary = escape_markup(&p.summary),
                )
            })
            .collect();
        format!("<h2>{}</h2>{}", escape_markup(heading), articles)
    }

    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>Blog — mylittlechart</title>\
         <meta name=\"description\" content=\"mylittlechart devlog — release notes and posts.\">\
         <link rel=\"canonical\" href=\"{origin}/blog/\">\
         <link rel=\"alternate\" type=\"application/atom+xml\" href=\"/blog/feed.xml\">\
         <style>{style}</style></head><body>\
         <p><a href=\"/\">&larr; mylittlechart</a></p><h1>Blog</h1>\
         {patch_section}{post_section}</body></html>",
        origin = SITE_ORIGIN,
        style = PAGE_STYLE,
        patch_section = section("Patch notes", &patches),
        post_section = section("Posts", &posts_only),
    )
}

fn render_blog_single(post: &Post) -> String {
    let url = format!("{}{}", SITE_ORIGIN, post_path(post));
    let body_html = paragraphs_to_html(&post.body);
    // `</` inside a JSON string literal would otherwise close the
    // surrounding `<script>` element early — escape it the same way a
    // browser's own JSON.stringify-in-HTML guidance recommends.
    let json_ld = serde_json::json!({
        "@context": "https://schema.org",
        "@type": "BlogPosting",
        "headline": post.title,
        "datePublished": post.created_at,
        "dateModified": post.updated_at,
        "description": post.summary,
        "url": url,
        "publisher": { "@type": "Organization", "name": "mylittlechart" },
    })
    .to_string()
    .replace("</", "<\\/");

    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title} — mylittlechart</title>\
         <meta name=\"description\" content=\"{summary}\">\
         <link rel=\"canonical\" href=\"{url}\">\
         <link rel=\"alternate\" type=\"application/atom+xml\" href=\"/blog/feed.xml\">\
         <style>{style}</style>\
         <script type=\"application/ld+json\">{json_ld}</script>\
         </head><body>\
         <p><a href=\"/\">&larr; mylittlechart</a></p>\
         <article><span class=\"date\">{date}</span> <span class=\"kind\">{kind}</span>\
         <h1>{title}</h1>{body}</article></body></html>",
        title = escape_markup(&post.title),
        summary = escape_markup(&post.summary),
        url = url,
        style = PAGE_STYLE,
        json_ld = json_ld,
        date = escape_markup(&post.date),
        kind = escape_markup(&post.kind),
        body = body_html,
    )
}

/// `GET /blog/` — index, "Patch notes" and "Posts" sections, newest first.
pub async fn blog_index(State(state): State<Arc<AppState>>) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::list_posts(&conn, None, UNPAGINATED_LIMIT, None)
    })
    .await;

    match result {
        Ok(Ok(posts)) => Html(render_blog_index(&posts)).into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error rendering /blog/: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

/// `GET /blog/{id}` — one full post, or a bare 404.
pub async fn blog_single(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::get_post(&conn, &id, false)
    })
    .await;

    match result {
        Ok(Ok(Some(post))) => Html(render_blog_single(&post)).into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error rendering /blog/{{id}}: {}", e);
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: &str, date: &str, title: &str, body: &str) -> Post {
        Post {
            id: id.to_string(),
            kind: "post".to_string(),
            version: None,
            date: date.to_string(),
            title: title.to_string(),
            summary: format!("summary of {}", title),
            body: body.to_string(),
            url: format!("/blog/{}", id),
            visibility: "public".to_string(),
            created_at: format!("{}T00:00:00+00:00", date),
            updated_at: format!("{}T00:00:00+00:00", date),
        }
    }

    #[test]
    fn parse_before_cursor_splits_on_pipe_and_rejects_malformed_input() {
        assert_eq!(
            parse_before_cursor("2026-09-01|v1"),
            Some(("2026-09-01".to_string(), "v1".to_string()))
        );
        assert_eq!(parse_before_cursor("no-pipe-here"), None);
        assert_eq!(parse_before_cursor("|v1"), None);
        assert_eq!(parse_before_cursor("2026-09-01|"), None);
    }

    #[test]
    fn split_paragraphs_breaks_on_blank_lines_and_trims_edges() {
        let body = "line one\nline one b\n\nline two\n\n\nline three";
        assert_eq!(
            split_paragraphs(body),
            vec![
                "line one\nline one b".to_string(),
                "line two".to_string(),
                "line three".to_string(),
            ]
        );
    }

    #[test]
    fn escape_markup_covers_the_five_special_characters() {
        assert_eq!(
            escape_markup("<a href=\"x\">&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;"
        );
    }

    #[test]
    fn post_json_exposes_only_the_public_wire_fields() {
        let p = sample("v1", "2026-09-01", "Title", "body text");
        let v = post_json(&p);
        let obj = v.as_object().expect("object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["body", "date", "id", "kind", "summary", "title", "url", "version"]
        );
    }

    #[test]
    fn atom_feed_is_well_formed_and_lists_entries_in_the_given_order() {
        let posts = vec![
            sample("newer", "2026-09-05", "Newer post", "para one\n\npara two"),
            sample("older", "2026-09-01", "Older post", "only paragraph"),
        ];
        let xml = render_atom_feed(&posts);

        assert!(xml.starts_with("<?xml"));
        assert!(xml.contains("<feed xmlns=\"http://www.w3.org/2005/Atom\">"));
        assert_eq!(xml.matches("<entry>").count(), 2);
        assert_eq!(xml.matches("</entry>").count(), 2);

        // Entries appear in the order they were given (caller is responsible
        // for newest-first ordering — this function does not re-sort).
        let newer_pos = xml.find("blog/newer").expect("newer entry present");
        let older_pos = xml.find("blog/older").expect("older entry present");
        assert!(newer_pos < older_pos);

        // The body's two paragraphs both made it into the (double-escaped)
        // HTML content.
        assert!(xml.contains("para one"));
        assert!(xml.contains("para two"));
        // Paragraph markup is XML-escaped, not raw, inside <content>.
        assert!(xml.contains("&lt;p&gt;para one&lt;/p&gt;"));
    }

    #[test]
    fn atom_feed_on_no_posts_is_still_well_formed() {
        let xml = render_atom_feed(&[]);
        assert!(xml.starts_with("<?xml"));
        assert!(xml.contains("<feed"));
        assert_eq!(xml.matches("<entry>").count(), 0);
    }

    #[test]
    fn blog_index_splits_patch_and_post_sections() {
        let mut patch = sample("v0-5-594", "2026-09-05", "0.5.594", "notes");
        patch.kind = "patch".to_string();
        let post = sample("hello-world", "2026-09-01", "Hello world", "notes");

        let html = render_blog_index(&[patch, post]);
        assert!(html.contains("Patch notes"));
        assert!(html.contains("Posts"));
        assert!(html.contains("/blog/v0-5-594"));
        assert!(html.contains("/blog/hello-world"));
    }

    #[test]
    fn blog_single_escapes_title_and_includes_json_ld() {
        let post = sample("v1", "2026-09-01", "<script>alert(1)</script>", "body");
        let html = render_blog_single(&post);
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("\"@type\":\"BlogPosting\""));
    }
}

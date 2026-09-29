//! Public chart-share endpoints.
//!
//! Two kinds of share (see `entitlements::ShareKind` and the "Share links"
//! section in `db.rs`):
//!  - 'live'       — a frozen ChartPreset JSON, rendered read-only by the web
//!                   viewer at `/?share=<token>`.
//!  - 'screenshot' — a PNG blob stored under `<data_dir>/share/<user_id>/`
//!                   (`state::ControlPlane::share_root`), streamed back verbatim.
//!
//! Endpoints:
//!  - `POST   /api/share/live`           — create a live share (auth).
//!  - `POST   /api/share/screenshot`     — create a screenshot share (auth, multipart).
//!  - `GET    /api/share/mine`           — list the caller's active shares (auth).
//!  - `GET    /api/share/{token}`        — public share metadata + payload, with the
//!                                          caller's effective rights (session/bearer optional).
//!  - `GET    /api/share/{token}/png`    — public PNG blob stream.
//!  - `POST   /api/share/{token}/clone`  — clone a live share into the caller's own
//!                                          preset, stripping ungranted indicators (auth,
//!                                          requires the `clone` right).
//!  - `DELETE /api/share/{token}`        — revoke, owner-only (auth).
//!
//! Creation is authenticated (session cookie or Bearer, same as `/api/sync/*`)
//! and entitlement-gated (`entitlements::share_create_allowed`, counted via
//! `db::share_usage`). Reading is PUBLIC by design — the token is the
//! capability — and unknown, expired, and revoked tokens all answer the same
//! bare 404 so none of the three states is distinguishable from outside
//! (same posture as the static-file fallback in `main.rs`).
//!
//! Rights v1 (docs/mlc/plans/native-share-viewer-and-chart-rights-2026-09-06.md
//! §2-3): a link always grants `read`; it grants `clone` when the owner opted
//! in at creation (`CreateLiveShareRequest::clone_allowed`) or the caller IS
//! the owner (who also gets `edit`, implicit — see `db::effective_rights`).
//! `GET /api/share/{token}` reports the caller's resolved set in `"rights"`;
//! `POST /api/share/{token}/clone` requires `clone` in that set and strips
//! any indicator the caller has no standing to use (`db::indicator_should_strip`).

use axum::{
    body::Body,
    extract::{Multipart, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use crate::auth::{extract_bearer, extract_session_id, extract_ua_hash, hash_token};
use crate::entitlements::{self, ShareKind};
use crate::models::types::ErrorResponse;
use crate::state::AppState;
use crate::text_policy::clean_optional_user_text;

/// Cap on a share's `title` — optional (an empty title is a blank chart,
/// not an error, see `clean_optional_user_text`), NFC-normalized and
/// control-character-cleaned the same way every other user-text field is
/// (`text_policy::clean_user_text`'s module doc).
const MAX_TITLE_CHARS: usize = 200;

/// PNG magic bytes — the only content check a screenshot gets.
const PNG_MAGIC: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/// Cap on `CreateLiveShareRequest::protected`/`UpdateShareLinkPolicyRequest::
/// protected`'s element count. `preset_json` is bounded by
/// `entitlements::PRESET_MAX_BYTES`, but `protected_json` is a SEPARATE
/// column with no size check of its own before this cap existed — an
/// unbounded `protected` array could grow the row's storage footprint
/// independent of the preset itself. A real chart has, at most, a few dozen
/// protectable elements; 500 is generous headroom, not a design ceiling.
const MAX_PROTECTED_ELEMENTS: usize = 500;

// ============================================================================
// Auth helper
// ============================================================================

/// Resolve the authenticated `user_id` from either a cookie session or a
/// Bearer token. Mirrors `routes::sync::resolve_user_id` (same credential
/// lookup, same "no credential is a 401" rule) — duplicated rather than
/// shared, following the existing pattern of `routes::account` and
/// `routes::entitlements`.
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
            if let Some(uid) = crate::db::resolve_web_session(&conn, &sid, &ua_hash)? {
                return Ok(Some(uid));
            }
        }

        if let Some(raw_token) = bearer {
            let token_hash = hash_token(&raw_token);
            if let Some(uid) = crate::db::resolve_token_hash_with_expiry(&conn, &token_hash)? {
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

/// Resolve the caller to a `user_id`, or `None` for anonymous — the rights-
/// v1 counterpart of `resolve_user_id` above for `GET /api/share/{token}`,
/// which must keep answering anonymous callers (unchanged behaviour) while
/// also reporting rights for a signed-in one. Mirrors
/// `routes::entitlements::resolve_caller`'s credential lookup exactly
/// (session cookie, then bearer token; "no credential", "invalid", and
/// "expired" all fold to anonymous rather than an error) — duplicated per
/// this file's existing pattern rather than shared.
async fn resolve_caller_optional(
    state: Arc<AppState>,
    headers: &HeaderMap,
) -> Result<Option<i64>, StatusCode> {
    let session_id = extract_session_id(headers);
    let ua_hash = extract_ua_hash(headers);
    let bearer: Option<String> = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| extract_bearer(Some(v)))
        .map(|s| s.to_owned());

    if session_id.is_none() && bearer.is_none() {
        return Ok(None);
    }

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<i64>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(sid) = session_id {
            if let Some(uid) = crate::db::resolve_web_session(&conn, &sid, &ua_hash)? {
                return Ok(Some(uid));
            }
        }

        if let Some(raw_token) = bearer {
            let token_hash = hash_token(&raw_token);
            if let Some(uid) = crate::db::resolve_token_hash_with_expiry(&conn, &token_hash)? {
                return Ok(Some(uid));
            }
        }

        Ok(None)
    })
    .await;

    match result {
        Ok(Ok(uid)) => Ok(uid),
        Ok(Err(_)) | Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Map an auth failure to the response every authenticated share endpoint
/// returns for it.
fn auth_err(status: StatusCode) -> Response {
    match status {
        StatusCode::UNAUTHORIZED => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Authentication required")),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

// ============================================================================
// Share-limit entitlement gate
// ============================================================================

/// Enforce the per-kind active-share ceiling for a creation (see
/// `entitlements::share_create_allowed` for the rule and
/// `entitlements::share_limit` for the numbers). Mirrors
/// `routes::sync::check_profile_entitlement`: the count and the paid fact are
/// read under one DB lock inside `spawn_blocking`, the decision itself is the
/// pure function.
///
/// Returns `Ok(())` when the creation may proceed, or the `Response` to
/// return verbatim when it may not (403 for the limit refusal, 500 on a DB
/// failure while checking it).
async fn check_share_entitlement(
    state: Arc<AppState>,
    user_id: i64,
    kind: ShareKind,
) -> Result<(), Response> {
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let (live_count, shot_count) = crate::db::share_usage(&conn, user_id)?;
        let is_paid = crate::db::user_is_paid(&conn, user_id)?;
        let current = match kind {
            ShareKind::Live => live_count,
            ShareKind::Screenshot => shot_count,
        };
        let kind_str = kind.as_str();
        let limit = entitlements::share_limit(kind, is_paid);
        let mut current = current;
        while current >= limit {
            if !crate::db::burn_oldest_unpinned_share(&conn, user_id, kind_str)? {
                break;
            }
            current -= 1;
        }
        Ok(entitlements::share_create_allowed(kind, current, is_paid))
    })
    .await;

    match result {
        Ok(Ok(true)) => Ok(()),
        Ok(Ok(false)) => Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse::new(
                "share limit reached: every share of this kind is pinned — unpin or revoke one",
            )),
        )
            .into_response()),
        Ok(Err(e)) => {
            tracing::error!("DB error checking share entitlement: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response())
        }
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response()),
    }
}

// ============================================================================
// POST /api/share/live
// ============================================================================

fn default_clone_allowed() -> bool {
    true
}

/// Request body for POST /api/share/live.
#[derive(serde::Deserialize)]
pub struct CreateLiveShareRequest {
    #[serde(default)]
    pub title: String,
    pub preset: serde_json::Value,
    /// Author chart id. A repeat publish of the same id reuses the token.
    /// Empty (old clients) mints a new link every call.
    #[serde(default)]
    pub chart_id: String,
    /// Rights v1: the link grants `clone` unless the caller explicitly
    /// sends `false`. Absent means on.
    #[serde(default = "default_clone_allowed")]
    pub clone_allowed: bool,
    /// Chart-share policy v1 (docs/mlc/plans/share-policy-2026-09-25.md §1):
    /// "view" | "interactive". Unknown/missing = "view" — the safe default:
    /// an old client omitting the field gets the MORE restrictive behaviour.
    #[serde(default)]
    pub interaction: ShareInteraction,
    /// Element refs the sharer marked Protected at share time — present in
    /// the live view, stripped on clone unless the caller's resolved tier is
    /// `clone_protected` (§1). Empty by default.
    #[serde(default)]
    pub protected: Vec<ProtectedElementRef>,
    /// [Rev 2] "public" (default, unchanged behaviour) | "private" — a
    /// private link resolves to ZERO rights for anyone without an explicit
    /// `object_grants` row (§8.5); `clone_allowed`/`interaction` above become
    /// inert floors that never apply on a private link (§1's tier-resolution
    /// rule, `db::effective_share_tier`).
    #[serde(default)]
    pub visibility: ShareVisibility,
    /// [Rev 3] Whether OUR OWN clients should offer a "Forward" action on a
    /// card built from this link. `None` (the field absent, or an explicit
    /// JSON `null`) means "not set — follow `visibility`'s own default":
    /// `true` for a public link, `false` for a private one
    /// (`db::ShareLinkRow::effective_allow_forward`). `Some(v)` pins the
    /// value regardless of `visibility`, including through a LATER `PATCH`
    /// that changes only `visibility` (§1's Rev 3 addition — see
    /// `UpdateShareLinkPolicyRequest::allow_forward`'s doc comment for the
    /// "does not silently flip" rule this enables). This is a client-side
    /// courtesy, not a security boundary: the hard guarantee for "nobody
    /// else can open this" is still `visibility: private` plus a real grant
    /// — copied link text can never be un-copied.
    #[serde(default)]
    pub allow_forward: Option<bool>,
}

/// One live-view interaction floor a share link grants (§1). `View` allows
/// pan/zoom/crosshair only; `Interactive` lets the recipient click and
/// adjust things locally (never persisted — see `mlc-app/src/share_viewer.rs`,
/// unaffected by this server-side change).
#[derive(serde::Deserialize, serde::Serialize, Clone, Copy, PartialEq, Eq, Default, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ShareInteraction {
    #[default]
    View,
    Interactive,
}

impl ShareInteraction {
    pub fn as_str(self) -> &'static str {
        match self {
            ShareInteraction::View => "view",
            ShareInteraction::Interactive => "interactive",
        }
    }
}

/// [Rev 2] A link's own visibility floor (§1/§8.5). `Public` is Rev 1's
/// unchanged behaviour — reachable by anyone holding the token, subject to
/// its own `interaction`/`clone_allowed` floor. `Private` refuses anyone
/// without an explicit per-account/group grant, even with the token in hand.
#[derive(serde::Deserialize, serde::Serialize, Clone, Copy, PartialEq, Eq, Default, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ShareVisibility {
    #[default]
    Public,
    Private,
}

impl ShareVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            ShareVisibility::Public => "public",
            ShareVisibility::Private => "private",
        }
    }
}

/// One element the sharer marked Protected. `kind` matches the entity-kind
/// vocabulary `db::ShareTier`/`clone_preset_with_strip` use:
/// `"indicator" | "primitive" | "alert"`. `id` is the element's own id
/// STRINGIFIED in the sharer's own id-space (u64 for indicator/primitive/
/// alert per `mlc-core/src/preset/snapshots.rs`) — valid because
/// `preset_json` is stored and served WITHOUT any id remap ever touching it
/// server-side (that only runs client-side, on open/clone) — the id the
/// sharer marked at creation is the exact id `clone_preset_with_strip` will
/// see in `preset_json` later.
#[derive(serde::Deserialize, serde::Serialize, Clone, Debug)]
pub struct ProtectedElementRef {
    pub kind: String,
    pub id: String,
}

/// POST /api/share/live
///
/// Freezes `preset` into a share row and answers:
/// ```json
/// { "token": "…", "url_path": "/?share=…", "expires_at": "<RFC3339>" }
/// ```
/// The preset must be a JSON object of at most [`entitlements::PRESET_MAX_BYTES`] bytes
/// serialized. TTL is stamped at creation (`entitlements::share_ttl_secs`);
/// reading the share never extends it.
pub async fn create_live_share(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateLiveShareRequest>,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };

    if !body.preset.is_object() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("preset must be a JSON object")),
        )
            .into_response();
    }
    if body.protected.len() > MAX_PROTECTED_ELEMENTS {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("protected exceeds the maximum element count")),
        )
            .into_response();
    }
    let preset_json = match serde_json::to_string(&body.preset) {
        Ok(s) if s.len() <= entitlements::PRESET_MAX_BYTES => s,
        Ok(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(ErrorResponse::new("preset exceeds 256 KiB")),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("preset is not serializable")),
            )
                .into_response();
        }
    };

    let chart_id = body.chart_id.trim().to_string();
    let republish = if chart_id.is_empty() {
        false
    } else {
        let state_lookup = state.clone();
        let chart_lookup = chart_id.clone();
        match tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
            let conn = state_lookup.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            Ok(crate::db::find_active_live_share_for_chart(&conn, user_id, &chart_lookup)?.is_some())
        })
        .await
        {
            Ok(Ok(found)) => found,
            Ok(Err(e)) => {
                tracing::error!("DB error looking up chart share: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse::new("Database error")),
                )
                    .into_response();
            }
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse::new("Internal error")),
                )
                    .into_response();
            }
        }
    };
    if !republish {
        if let Err(resp) = check_share_entitlement(state.clone(), user_id, ShareKind::Live).await {
            return resp;
        }
    }

    let title = match clean_optional_user_text(&body.title, MAX_TITLE_CHARS) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let clone_allowed = body.clone_allowed;
    let interaction = body.interaction.as_str();
    let visibility = body.visibility.as_str();
    let allow_forward = body.allow_forward;
    let protected_json = match serde_json::to_string(&body.protected) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("protected is not serializable")),
            )
                .into_response();
        }
    };
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<(String, String, i64)> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let is_paid = crate::db::user_is_paid(&conn, user_id)?;
        let now = chrono::Utc::now();
        let created_at = now.to_rfc3339();
        let expires_at = (now
            + chrono::Duration::seconds(entitlements::share_ttl_secs(ShareKind::Live, is_paid) as i64))
            .to_rfc3339();
        let (token, revision, expires_at, _created) = crate::db::publish_live_share(
            &conn,
            user_id,
            &chart_id,
            &title,
            &preset_json,
            &created_at,
            &expires_at,
            clone_allowed,
            interaction,
            &protected_json,
            visibility,
            allow_forward,
        )?;
        Ok((token, expires_at, revision))
    })
    .await;

    match result {
        Ok(Ok((token, expires_at, revision))) => Json(serde_json::json!({
            "token": token,
            "url_path": format!("/?share={}&v={}", token, revision),
            "expires_at": expires_at,
            "revision": revision,
        }))
        .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error creating live share: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

// ============================================================================
// POST /api/share/screenshot
// ============================================================================

/// POST /api/share/screenshot
///
/// Multipart body: one `png` field (the bytes) plus an optional `title`
/// field. The request body is capped at 8 MiB by the `DefaultBodyLimit`
/// override on this route (see `routes/mod.rs`); the PNG must carry the
/// magic bytes. The blob lands at `<data_dir>/share/<user_id>/<token>.png`
/// via atomic tmp+rename (the `syncstore::write_file` pattern) and the row
/// records the relative path. Answers like `create_live_share`.
pub async fn create_screenshot_share(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };

    let mut png: Option<Vec<u8>> = None;
    let mut title = String::new();
    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => match field.name() {
                Some("png") => match field.bytes().await {
                    Ok(bytes) => png = Some(bytes.to_vec()),
                    Err(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(ErrorResponse::new("could not read png field")),
                        )
                            .into_response();
                    }
                },
                Some("title") => {
                    if let Ok(text) = field.text().await {
                        title = text;
                    }
                }
                _ => {}
            },
            Ok(None) => break,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse::new("invalid multipart body")),
                )
                    .into_response();
            }
        }
    }

    let png = match png {
        Some(bytes) if !bytes.is_empty() => bytes,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("png field is required")),
            )
                .into_response();
        }
    };
    if png.len() < PNG_MAGIC.len() || png[..PNG_MAGIC.len()] != PNG_MAGIC {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("png field is not a PNG file")),
        )
            .into_response();
    }

    if let Err(resp) = check_share_entitlement(state.clone(), user_id, ShareKind::Screenshot).await {
        return resp;
    }

    let title = match clean_optional_user_text(&title, MAX_TITLE_CHARS) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let blob_bytes = png.len() as i64;
    let result =
        tokio::task::spawn_blocking(move || -> rusqlite::Result<(String, String)> {
            let cp = state.control_plane();
            let conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
            let is_paid = crate::db::user_is_paid(&conn, user_id)?;
            let now = chrono::Utc::now();
            let created_at = now.to_rfc3339();
            let expires_at = (now
                + chrono::Duration::seconds(
                    entitlements::share_ttl_secs(ShareKind::Screenshot, is_paid) as i64,
                ))
            .to_rfc3339();

            // The row goes in first (blob_path empty) because the blob's path
            // contains the token, which only exists once the insert draws it.
            // A screenshot carries no preset to clone, so clone_allowed is
            // always false here, and interaction/protected/visibility stay
            // at their "view"/"[]"/"public" defaults — no request field
            // offers to set any of them (a screenshot is pure view-only by
            // construction, §0). `allow_forward` stays `None` (unset) too,
            // for the same reason — it then follows `"public"`'s own
            // effective default (`true`), same as before this column
            // existed.
            let token = crate::db::create_share_link(
                &conn,
                user_id,
                ShareKind::Screenshot.as_str(),
                &title,
                "",
                blob_bytes,
                &created_at,
                &expires_at,
                false,
                "view",
                "[]",
                "public",
                None,
            )?;

            // user_id and token are server-generated (integer / hex), so
            // sanitize can only ever pass — it runs anyway so this path has
            // exactly one spelling of "safe component" (see syncstore).
            let rel_path = format!(
                "{}/{}.png",
                crate::syncstore::sanitize(&user_id.to_string())?,
                crate::syncstore::sanitize(&token)?
            );
            let abs_path = cp.share_root.join(&rel_path);

            // Atomic write: tmp file in the same directory + rename
            // (syncstore::write_file's pattern). On failure the row is
            // revoked again so a half-written share can never be served.
            let write_result = (|| -> std::io::Result<()> {
                if let Some(dir) = abs_path.parent() {
                    std::fs::create_dir_all(dir)?;
                }
                let tmp = abs_path.with_extension("png.tmp");
                std::fs::write(&tmp, &png)?;
                std::fs::rename(&tmp, &abs_path)?;
                Ok(())
            })();
            if let Err(e) = write_result {
                tracing::error!("IO error writing share blob {}: {}", rel_path, e);
                let _ = crate::db::revoke_share(&conn, user_id, &token);
                return Err(rusqlite::Error::ToSqlConversionFailure(Box::new(e)));
            }
            crate::db::set_share_blob_path(&conn, &token, &rel_path)?;

            Ok((token, expires_at))
        })
        .await;

    match result {
        Ok(Ok((token, expires_at))) => Json(serde_json::json!({
            "token": token,
            "url_path": format!("/?share={}", token),
            "expires_at": expires_at,
        }))
        .into_response(),
        Ok(Err(e)) => {
            tracing::error!("error creating screenshot share: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

// ============================================================================
// GET /api/share/{token}  (public)
// ============================================================================

/// Bare 404 — the one answer for unknown, expired, and revoked tokens alike.
fn share_not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

/// Fetch the live share row plus its owner label and the resolved caller's
/// effective rights (`db::effective_rights`), or None. Shared by `get_share`
/// and `get_share_png` — the latter passes `caller: None` and ignores the
/// rights element, since a PNG stream has no rights to report.
async fn fetch_public_share(
    state: Arc<AppState>,
    token: String,
    caller: Option<i64>,
) -> Result<Option<(crate::db::ShareLinkRow, String, Vec<&'static str>)>, Response> {
    let result = tokio::task::spawn_blocking(
        move || -> rusqlite::Result<Option<(crate::db::ShareLinkRow, String, Vec<&'static str>)>> {
            let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            let row = crate::db::get_share_link(&conn, &token)?;
            match row {
                Some(row) => {
                    // display_name with public_id fallback; a dedicated public
                    // nick column lands in a later wave.
                    let owner = crate::db::share_owner_label(&conn, row.user_id)?
                        .unwrap_or_default();
                    let rights = crate::db::effective_rights(&conn, &row, caller);
                    Ok(Some((row, owner, rights)))
                }
                None => Ok(None),
            }
        },
    )
    .await;

    match result {
        Ok(Ok(row)) => Ok(row),
        Ok(Err(e)) => {
            tracing::error!("DB error fetching share: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response())
        }
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response()),
    }
}

/// [Rev 2] `get_share`'s own fetch: row + owner label + the caller's
/// FRESHLY re-derived `ShareTier` (`db::effective_share_tier`, never a
/// cached/client-supplied value, §1/§8.1) — `None` means "this token is
/// real, but `caller` holds no tier on it" (the private-link lock case,
/// §8.5), distinct from the row not existing at all (still the outer
/// `Option`, same "unknown/expired/revoked" 404 opacity as `fetch_public_share`).
/// A separate function from `fetch_public_share` rather than a shared one:
/// `get_share_png` never used the rights/owner it got back either (`_owner`,
/// `_rights` are discarded at both its call sites) — this file's own
/// existing pattern of duplicating a small credential/fetch helper rather
/// than forcing one shape onto two different callers (see `resolve_user_id`
/// vs `resolve_caller_optional`'s doc comment).
async fn fetch_public_share_with_tier(
    state: Arc<AppState>,
    token: String,
    caller: Option<i64>,
) -> Result<Option<(crate::db::ShareLinkRow, String, Option<crate::db::ShareTier>, bool)>, Response> {
    let result = tokio::task::spawn_blocking(
        move || -> rusqlite::Result<Option<(crate::db::ShareLinkRow, String, Option<crate::db::ShareTier>, bool)>> {
            let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            let row = crate::db::get_share_link(&conn, &token)?;
            match row {
                Some(row) => {
                    let owner = crate::db::share_owner_label(&conn, row.user_id)?
                        .unwrap_or_default();
                    let tier = crate::db::effective_share_tier(&conn, &row, caller)?;
                    let can_edit = match caller {
                        Some(uid) => crate::db::share_caller_can_edit(&conn, &row, uid)?,
                        None => false,
                    };
                    Ok(Some((row, owner, tier, can_edit)))
                }
                None => Ok(None),
            }
        },
    )
    .await;

    match result {
        Ok(Ok(row)) => Ok(row),
        Ok(Err(e)) => {
            tracing::error!("DB error fetching share: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response())
        }
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response()),
    }
}

/// `["read"]` + `"clone"` when `tier` is at least `Clone` — Rev 1's own
/// `"rights"` wire shape (§1), now derived from the resolved `ShareTier`
/// instead of the old link-only `effective_rights`. `"edit"` stays tied to
/// actual ownership, not to the tier value: `CloneProtected` is also
/// reachable by a non-owner recipient holding that grant, who must NOT see
/// `"edit"` in their own rights list (co-editing is out of scope — the
/// owner is the only caller `is_owner` is ever true for).
fn rights_for_tier(tier: crate::db::ShareTier, can_edit: bool) -> Vec<&'static str> {
    let mut rights = vec!["read"];
    if tier >= crate::db::ShareTier::Clone {
        rights.push("clone");
    }
    if can_edit {
        rights.push("edit");
    }
    rights
}

/// `{"locked": true}` — nothing else. The distinguishable 403 body
/// `GET /api/share/{token}` answers for a real, private share the caller
/// holds no tier on (§8.5) — a SCOPED, explicit exception to this module's
/// own "unknown/expired/revoked all answer the same bare 404" opacity
/// doctrine: a prober who already has the exact token learns "this one
/// exists and is private," accepted by direct owner instruction (plan §8.5).
/// `clone_share`'s own 403 keeps its old plain `ErrorResponse` shape
/// unconditionally — the client tells the two apart by the presence of this
/// `"locked"` key, checked only on the open path.
#[derive(serde::Serialize)]
struct ShareLockedResponse {
    locked: bool,
}

/// GET /api/share/{token}
///
/// PUBLIC — the token is the capability, no session and no build attestation.
/// The bearer/session, if any, is OPTIONAL (`resolve_caller_optional`): an
/// anonymous caller still gets a response, plus a `"rights"` array
/// ([`rights_for_tier`]) reporting what it may do with the token —
/// `["read"]` without `clone`, `["read","clone"]` at tier `Clone` or above,
/// `["read","clone","edit"]` for the owner — plus a `"clone_protected"` bool
/// (tier `== CloneProtected`, §1 Rev 2) for the clone-strip decision and the
/// UI's "Clone (full)" badge. The caller's tier is re-derived FRESH on every
/// call (`db::effective_share_tier`) — never cached, never trusted from the
/// client. A real, PRIVATE share the caller holds no tier on answers the
/// distinguishable [`ShareLockedResponse`] (§8.5) instead of the preset — a
/// SCOPED exception to this module's "unknown/expired/revoked all answer the
/// same bare 404" opacity doctrine, which stays unchanged for those three
/// cases. Live shares answer the frozen preset; screenshot shares answer the
/// URL of the PNG endpoint. [Rev 3] Both kinds also echo `"allow_forward"`
/// (`row.effective_allow_forward()`) — the client-side "offer a Forward
/// action" courtesy flag, resolved the same way regardless of `caller`'s
/// tier (unlike `"rights"`/`"clone_protected"`, it is not a per-recipient
/// grant, just this link's own policy).
pub async fn get_share(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    let caller = match resolve_caller_optional(state.clone(), &headers).await {
        Ok(uid) => uid,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Internal error")),
            )
                .into_response();
        }
    };

    let (row, owner, tier, can_edit) = match fetch_public_share_with_tier(state, token, caller).await {
        Ok(Some(found)) => found,
        Ok(None) => return share_not_found(),
        Err(resp) => return resp,
    };

    let Some(tier) = tier else {
        return (
            StatusCode::FORBIDDEN,
            Json(ShareLockedResponse { locked: true }),
        )
            .into_response();
    };
    let rights = rights_for_tier(tier, can_edit);
    let clone_protected = tier == crate::db::ShareTier::CloneProtected;
    // [Rev 3] The resolved forwarding flag — explicit if the owner ever set
    // one, otherwise `visibility`'s own default (`ShareLinkRow::
    // effective_allow_forward`'s doc comment has the full rule).
    let allow_forward = row.effective_allow_forward();

    match ShareKind::from_wire_name(&row.kind) {
        Some(ShareKind::Live) => {
            let preset: serde_json::Value = match serde_json::from_str(&row.preset_json) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("corrupt preset_json on share {}: {}", row.token, e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse::new("Internal error")),
                    )
                        .into_response();
                }
            };
            // Malformed `protected_json` (should never happen — it is
            // validated as `Vec<ProtectedElementRef>` at creation time, see
            // `create_live_share`) degrades to "nothing marked Protected"
            // rather than failing the whole read — the protected list is an
            // advisory hint for the recipient's object-tree lock glyph, not
            // a security boundary (the real enforcement is server-side, at
            // clone time — see `clone_preset_with_strip`).
            let protected: Vec<ProtectedElementRef> =
                serde_json::from_str(&row.protected_json).unwrap_or_default();
            Json(serde_json::json!({
                "kind": "live",
                "title": row.title,
                "owner": owner,
                "preset": preset,
                "created_at": row.created_at,
                "expires_at": row.expires_at,
                "rights": rights,
                "interaction": row.interaction,
                "protected": protected,
                "clone_protected": clone_protected,
                "allow_forward": allow_forward,
                "visibility": row.visibility,
                "clone_allowed": row.clone_allowed,
                "pinned": row.pinned,
                "revision": row.revision,
                "op_seq": row.op_seq,
            }))
            .into_response()
        }
        Some(ShareKind::Screenshot) => Json(serde_json::json!({
            "kind": "screenshot",
            "title": row.title,
            "owner": owner,
            "png_url": format!("/api/share/{}/png", row.token),
            "bytes": row.blob_bytes,
            "expires_at": row.expires_at,
            "rights": rights,
            "clone_protected": clone_protected,
            "allow_forward": allow_forward,
            "visibility": row.visibility,
            "pinned": row.pinned,
        }))
        .into_response(),
        // A kind this build does not know is treated as not found — an older
        // server must not half-serve a newer row.
        None => share_not_found(),
    }
}

/// GET /api/share/{token}/png
///
/// PUBLIC, same 404 discipline as `get_share`. Streams the blob file with a
/// short cache: the bytes are immutable for the share's lifetime (the token
/// names them), but revocation must show up within minutes, not days.
pub async fn get_share_png(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> Response {
    let share_root = state.control_plane().share_root.clone();
    let (row, _owner, _rights) = match fetch_public_share(state, token, None).await {
        Ok(Some(found)) => found,
        Ok(None) => return share_not_found(),
        Err(resp) => return resp,
    };

    if row.kind != ShareKind::Screenshot.as_str() || row.blob_path.is_empty() {
        return share_not_found();
    }
    // blob_path comes from our own rows, but it is still a string crossing
    // into the filesystem — same relative-path guard as the static handler.
    if !crate::pathutil::is_safe_relative_path(&row.blob_path) {
        return share_not_found();
    }

    match tokio::fs::read(share_root.join(&row.blob_path)).await {
        Ok(body) => Response::builder()
            .status(200)
            .header("content-type", "image/png")
            .header("cache-control", "public, max-age=300")
            .body(Body::from(body))
            .unwrap(),
        Err(_) => share_not_found(),
    }
}

// ============================================================================
// GET /api/share/mine
// ============================================================================

/// GET /api/share/mine
///
/// The caller's active shares, newest first (see `db::list_share_links`).
pub async fn list_my_shares(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Vec<serde_json::Value>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let rows = crate::db::list_share_links(&conn, user_id)?;
        Ok(rows
            .into_iter()
            .map(|row| {
                serde_json::json!({
                    "token": row.token,
                    "kind": row.kind,
                    "title": row.title,
                    "url_path": format!("/?share={}", row.token),
                    "bytes": row.blob_bytes,
                    "created_at": row.created_at,
                    "expires_at": row.expires_at,
                    "pinned": row.pinned,
                    "clone_allowed": row.clone_allowed,
                    "interaction": row.interaction,
                    "visibility": row.visibility,
                    "allow_forward": row.effective_allow_forward(),
                    "chart_id": row.chart_id,
                })
            })
            .collect())
    })
    .await;

    match result {
        Ok(Ok(shares)) => Json(serde_json::json!({ "shares": shares })).into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error listing shares: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

// ============================================================================
// DELETE /api/share/{token}
// ============================================================================

/// DELETE /api/share/{token}
///
/// Owner-only revoke. Unknown, expired-and-cleaned, already-revoked, and
/// someone-else's tokens all answer the same bare 404 (see
/// `db::revoke_share`). A screenshot's blob file is unlinked alongside the
/// row; a file that fails to unlink is logged and left for the periodic
/// cleanup's successor to reconcile, never reported to the client.
pub async fn delete_share(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };

    let share_root = state.control_plane().share_root.clone();
    let result =
        tokio::task::spawn_blocking(move || -> rusqlite::Result<(bool, Option<String>)> {
            let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            // Read the blob path before revoking so the file can be unlinked
            // even for an expired (but not yet reaped) row.
            let blob_path: Option<String> = conn
                .query_row(
                    "SELECT blob_path FROM share_links WHERE token = ?1 AND user_id = ?2",
                    rusqlite::params![token, user_id],
                    |row| row.get(0),
                )
                .ok();
            let revoked = crate::db::revoke_share(&conn, user_id, &token)?;
            Ok((revoked, blob_path))
        })
        .await;

    match result {
        Ok(Ok((true, blob_path))) => {
            if let Some(rel) = blob_path {
                if !rel.is_empty() && crate::pathutil::is_safe_relative_path(&rel) {
                    if let Err(e) = std::fs::remove_file(share_root.join(&rel)) {
                        tracing::warn!("could not unlink share blob {}: {}", rel, e);
                    }
                }
            }
            Json(serde_json::json!({ "revoked": true })).into_response()
        }
        Ok(Ok((false, _))) => share_not_found(),
        Ok(Err(e)) => {
            tracing::error!("DB error revoking share: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

// ============================================================================
// POST/GET /api/share/{token}/grants, DELETE .../grants/{grant_id}
// ============================================================================

/// Request body for POST /api/share/{token}/grants. Exactly one of
/// `grantee_nick`/`grantee_group_id` must be set — a share-tier grant always
/// targets one account (resolved server-side from its nick, mirroring
/// `routes::rooms::CreateGrantRequest`'s own by-nick shape) or one of the
/// caller's own groups, never both and never "public" (a link's own public
/// floor is `interaction`/`clone_allowed`/`visibility`, not a grant row).
#[derive(serde::Deserialize)]
pub struct CreateShareGrantRequest {
    #[serde(default)]
    pub grantee_nick: Option<String>,
    #[serde(default)]
    pub grantee_group_id: Option<i64>,
    /// "view" | "interactive" | "clone" | "clone_protected" — see `db::ShareTier`.
    pub tier: String,
    pub expires_at: Option<String>,
}

enum CreateShareGrantOutcome {
    Created { grant_id: i64 },
    ShareNotFound,
    UnknownNick,
    UnknownGroup,
    QuotaExceeded,
}

/// POST /api/share/{token}/grants
///
/// Owner-only (§8.2). Unknown token AND a non-owner caller both answer the
/// same bare 404 (same "someone else's token" discipline as `delete_share`).
/// `grantee_nick` is resolved to a `user_id` server-side
/// (`db::user_id_for_nick`) — a caller never supplies a raw numeric id
/// directly, matching `routes::rooms::create_grant`'s own by-nick shape.
/// `grantee_group_id` must name one of the CALLER's OWN groups
/// (`db::grant_group_is_owned_by`) — granting through a group you do not own
/// would let a caller extend someone else's curated membership list rights
/// on a share it never touches. Quota-checked via
/// `entitlements::grant_create_allowed` against the token's own live grant
/// count, the same fan-out ceiling `routes::rooms::create_grant` applies to
/// a room. Writes straight into `object_grants` via `db::upsert_share_grant`
/// — the per-account/group layer `db::effective_share_tier` reads fresh on
/// every subsequent `GET`/clone (§1).
pub async fn create_share_grant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Json(body): Json<CreateShareGrantRequest>,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };

    if body.grantee_nick.is_some() == body.grantee_group_id.is_some() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "grant must target exactly one of grantee_nick or grantee_group_id",
            )),
        )
            .into_response();
    }
    let edit_grant = body.tier == "edit";
    let tier = if edit_grant {
        None
    } else {
        match crate::db::ShareTier::from_str(&body.tier) {
            Some(tier) => Some(tier),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse::new("invalid tier")),
                )
                    .into_response();
            }
        }
    };

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<CreateShareGrantOutcome> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let row = match crate::db::get_share_link(&conn, &token)? {
            Some(row) => row,
            None => return Ok(CreateShareGrantOutcome::ShareNotFound),
        };
        if row.user_id != user_id {
            return Ok(CreateShareGrantOutcome::ShareNotFound);
        }

        let grantee_user_id = match &body.grantee_nick {
            Some(nick) => match crate::db::user_id_for_nick(&conn, nick)? {
                Some(uid) => Some(uid),
                None => return Ok(CreateShareGrantOutcome::UnknownNick),
            },
            None => None,
        };
        let grantee_group_id = match body.grantee_group_id {
            Some(gid) => {
                if !crate::db::grant_group_is_owned_by(&conn, gid, user_id)? {
                    return Ok(CreateShareGrantOutcome::UnknownGroup);
                }
                Some(gid)
            }
            None => None,
        };

        let current = crate::db::count_object_grants(&conn, "chart", &row.token)?;
        if !entitlements::grant_create_allowed(current) {
            return Ok(CreateShareGrantOutcome::QuotaExceeded);
        }

        let now = chrono::Utc::now().to_rfc3339();
        let id = if edit_grant {
            crate::db::upsert_share_edit_grant(
                &conn,
                &row.token,
                user_id,
                grantee_user_id,
                grantee_group_id,
                body.expires_at.as_deref(),
                &now,
            )?
        } else {
            crate::db::upsert_share_grant(
                &conn,
                &row.token,
                user_id,
                grantee_user_id,
                grantee_group_id,
                tier.expect("tier checked before spawn"),
                body.expires_at.as_deref(),
                &now,
            )?
        };
        Ok(CreateShareGrantOutcome::Created { grant_id: id })
    })
    .await;

    match result {
        Ok(Ok(CreateShareGrantOutcome::Created { grant_id })) => {
            Json(serde_json::json!({ "grant_id": grant_id })).into_response()
        }
        Ok(Ok(CreateShareGrantOutcome::ShareNotFound)) => share_not_found(),
        Ok(Ok(CreateShareGrantOutcome::UnknownNick)) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("unknown nick")),
        )
            .into_response(),
        Ok(Ok(CreateShareGrantOutcome::UnknownGroup)) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("unknown group")),
        )
            .into_response(),
        Ok(Ok(CreateShareGrantOutcome::QuotaExceeded)) => (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse::new("grant limit reached for this share")),
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error creating share grant: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct ShareNickLookupQuery {
    q: Option<String>,
}

/// `GET /api/share/lookup?q=` — nick search for share settings.
///
/// Any signed-in caller. Hits are accounts that have a nick, excluding the
/// caller. A published messenger key is not required: this list is who can
/// be granted on a chart, and `POST /api/share/{token}/grants` resolves the
/// same nick. Fewer than two characters returns an empty list.
pub async fn lookup_share_nicks(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ShareNickLookupQuery>,
) -> Response {
    let caller_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };
    let q: String = query.q.unwrap_or_default().trim().chars().take(64).collect();
    if q.chars().count() < 2 {
        return Json(serde_json::json!({ "users": [] })).into_response();
    }

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::search_share_nicks(&conn, caller_id, &q, 8)
    })
    .await;

    match result {
        Ok(Ok(users)) => {
            let users: Vec<_> = users
                .into_iter()
                .map(|u| serde_json::json!({ "nick": u.nick, "label": u.label }))
                .collect();
            Json(serde_json::json!({ "users": users })).into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("DB error in share nick lookup: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

const SHARE_OP_KINDS: &[&str] = &[
    "primitive_upsert",
    "primitive_delete",
    "indicator_upsert",
    "indicator_delete",
    "gesture",
    "viewport",
];
const SHARE_OPS_MAX: usize = 24;
const SHARE_OP_BODY_MAX: usize = 48_000;

#[derive(serde::Deserialize)]
pub(crate) struct ShareOpsQuery {
    after: Option<i64>,
}

#[derive(serde::Deserialize)]
pub(crate) struct ShareOpIn {
    kind: String,
    object_id: String,
    #[serde(default)]
    body: String,
}

#[derive(serde::Deserialize)]
pub(crate) struct ShareOpsBody {
    ops: Vec<ShareOpIn>,
}

/// `POST /api/share/{token}/ops` — append chart ops. Owner, or an edit
/// grant. A view or clone grant is not enough. Screenshot tokens 404.
pub async fn post_share_ops(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Json(body): Json<ShareOpsBody>,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };
    if body.ops.is_empty() || body.ops.len() > SHARE_OPS_MAX {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("ops must contain 1 to 24 entries")),
        )
            .into_response();
    }
    let mut cleaned = Vec::with_capacity(body.ops.len());
    for op in body.ops {
        if !SHARE_OP_KINDS.contains(&op.kind.as_str()) {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("invalid op kind")),
            )
                .into_response();
        }
        if op.object_id.is_empty() || op.object_id.len() > 80 || op.body.len() > SHARE_OP_BODY_MAX {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("invalid op")),
            )
                .into_response();
        }
        cleaned.push((op.kind, op.object_id, op.body));
    }

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Result<Vec<i64>, StatusCode>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let Some(row) = crate::db::get_share_link(&conn, &token)? else {
            return Ok(Err(StatusCode::NOT_FOUND));
        };
        if row.kind != "live" || !crate::db::share_caller_can_edit(&conn, &row, user_id)? {
            return Ok(Err(StatusCode::FORBIDDEN));
        }
        let now = chrono::Utc::now().to_rfc3339();
        let seqs = crate::db::append_share_ops(&conn, &row.token, user_id, &cleaned, &now)?;
        Ok(Ok(seqs))
    })
    .await;

    match result {
        Ok(Ok(Ok(seqs))) => Json(serde_json::json!({ "seqs": seqs })).into_response(),
        Ok(Ok(Err(status))) => status.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error appending share ops: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

/// `GET /api/share/{token}/stream-open` — one lookup before a live socket.
/// The edge relay forwards the browser cookie and sets `X-Mlc-Edge`.
/// A publisher claims the edge while `live_edge` is empty. Frames after
/// this do not come back here.
fn edge_public_origin(edge: &str) -> &'static str {
    match edge {
        "utah" => "https://utah.mylittlechart.org",
        "ams" => "https://ams.mylittlechart.org",
        _ => "",
    }
}

pub async fn stream_open(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    if let Some(ticket) = headers.get("x-mlc-ticket").and_then(|v| v.to_str().ok()) {
        if let Some((publish, owner)) = state.lookup_live_ticket(ticket, &token) {
            return Json(serde_json::json!({
                "publish": publish,
                "owner": owner,
                "origin": edge_public_origin(&owner),
            }))
            .into_response();
        }
        return StatusCode::NOT_FOUND.into_response();
    }
    let caller = match resolve_caller_optional(state.clone(), &headers).await {
        Ok(uid) => uid,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Internal error")),
            )
                .into_response();
        }
    };
    let edge = headers
        .get("x-mlc-edge")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Result<serde_json::Value, StatusCode>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let Some(row) = crate::db::get_share_link(&conn, &token)? else {
            return Ok(Err(StatusCode::NOT_FOUND));
        };
        if row.kind != "live" {
            return Ok(Err(StatusCode::NOT_FOUND));
        }
        if crate::db::effective_share_tier(&conn, &row, caller)?.is_none() {
            return Ok(Err(StatusCode::NOT_FOUND));
        }
        let publish = match caller {
            Some(uid) => crate::db::share_caller_can_edit(&conn, &row, uid)?,
            None => false,
        };
        let owner = if publish {
            crate::db::claim_share_live_edge(&conn, &row.token, &edge)?.unwrap_or_default()
        } else {
            crate::db::share_live_edge(&conn, &row.token)?.unwrap_or_default()
        };
        let ticket = state.mint_live_ticket(&row.token, publish, &owner);
        Ok(Ok(serde_json::json!({
            "publish": publish,
            "owner": owner,
            "origin": edge_public_origin(&owner),
            "ticket": ticket,
        })))
    })
    .await;
    match result {
        Ok(Ok(Ok(body))) => Json(body).into_response(),
        Ok(Ok(Err(status))) => status.into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Database error")),
        )
            .into_response(),
    }
}

/// `GET /api/share/{token}/ops?after=` — ops the caller may follow.
/// Same open gate as `GET /api/share/{token}`. `reset` is true when `after`
/// is past the head (the preset was republished and the log restarted);
/// the ops in that response are everything since the new baseline.
pub async fn get_share_ops(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Query(query): Query<ShareOpsQuery>,
) -> Response {
    let caller = match resolve_caller_optional(state.clone(), &headers).await {
        Ok(uid) => uid,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Internal error")),
            )
                .into_response();
        }
    };
    let after = query.after.unwrap_or(0).max(0);

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Result<serde_json::Value, StatusCode>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let Some(row) = crate::db::get_share_link(&conn, &token)? else {
            return Ok(Err(StatusCode::NOT_FOUND));
        };
        if row.kind != "live" {
            return Ok(Err(StatusCode::NOT_FOUND));
        }
        let tier = crate::db::effective_share_tier(&conn, &row, caller)?;
        if tier.is_none() {
            return Ok(Err(StatusCode::NOT_FOUND));
        }
        let can_send = match caller {
            Some(uid) => crate::db::share_caller_can_edit(&conn, &row, uid)?,
            None => false,
        };
        let reset = after > row.op_seq;
        let read_after = if reset { 0 } else { after };
        let (head, ops) = crate::db::list_share_ops_after(&conn, &row.token, read_after, 100)?;
        let ops: Vec<_> = ops
            .into_iter()
            .map(|op| {
                serde_json::json!({
                    "seq": op.seq,
                    "kind": op.kind,
                    "object_id": op.object_id,
                    "body": op.body,
                })
            })
            .collect();
        Ok(Ok(serde_json::json!({ "head": head, "reset": reset, "can_send": can_send, "live": row.live, "ops": ops })))
    })
    .await;

    match result {
        Ok(Ok(Ok(body))) => Json(body).into_response(),
        Ok(Ok(Err(status))) => status.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error reading share ops: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

/// GET /api/share/{token}/grants
///
/// Owner-only listing (§8.2) — unfiltered: an expired grant still lists (so
/// the owner can see and clean it up), same posture as
/// `db::list_object_grants`'s own doc comment. Each grant's target is
/// resolved to a display label: a nick-targeted grant shows the grantee's
/// `effective_label_for_user`; a group-targeted grant shows the group's own
/// name (or `null` for either once the underlying account/group is gone —
/// the grant row itself still lists, matching `routes::rooms::list_grants`'s
/// own "a stale label is not an error" posture).
pub async fn list_share_grants(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<Vec<serde_json::Value>>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let row = match crate::db::get_share_link(&conn, &token)? {
            Some(row) => row,
            None => return Ok(None),
        };
        if row.user_id != user_id {
            return Ok(None);
        }
        let grants = crate::db::list_object_grants(&conn, "chart", &row.token)?;
        let mut out = Vec::with_capacity(grants.len());
        for g in grants {
            let grantee = if let Some(uid) = g.grantee_user_id {
                let label = crate::db::effective_label_for_user(&conn, uid)?;
                serde_json::json!({ "kind": "nick", "user_id": uid, "label": label })
            } else if let Some(gid) = g.grantee_group_id {
                let name = crate::db::grant_group_name(&conn, gid)?;
                serde_json::json!({ "kind": "group", "group_id": gid, "name": name })
            } else {
                serde_json::Value::Null
            };
            out.push(serde_json::json!({
                "id": g.id,
                "grantee": grantee,
                "tier": g.right,
                "expires_at": g.expires_at,
                "created_at": g.created_at,
            }));
        }
        Ok(Some(out))
    })
    .await;

    match result {
        Ok(Ok(Some(grants))) => Json(serde_json::json!({ "grants": grants })).into_response(),
        Ok(Ok(None)) => share_not_found(),
        Ok(Err(e)) => {
            tracing::error!("DB error listing share grants: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

/// DELETE /api/share/{token}/grants/{grant_id}
///
/// Owner-only revoke (`db::revoke_object_grant`, already owner-scoped by its
/// own `owner_user_id` column check) — the `token` in the path names the
/// resource the client is looking at, not an extra filter, same shape as
/// `routes::rooms::delete_grant`.
pub async fn delete_share_grant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((_token, grant_id)): Path<(String, i64)>,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::revoke_object_grant(&conn, grant_id, user_id)
    })
    .await;

    match result {
        Ok(Ok(true)) => Json(serde_json::json!({ "revoked": true })).into_response(),
        Ok(Ok(false)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error revoking share grant: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

// ============================================================================
// PATCH /api/share/{token}  (owner-only policy update)
// ============================================================================

/// Request body for PATCH /api/share/{token}. Each field is optional and
/// independent: sending only `visibility` leaves `interaction`/`protected`
/// untouched, and so on. `clone_allowed` and `title` are deliberately NOT
/// here — this route revisits ONLY the plan's non-goal on explicit product
/// instruction (docs/mlc/plans/share-policy-2026-09-25.md §3 called changing
/// a link's policy post-creation out of scope for v1; the owner has since
/// asked for exactly this for `visibility`/`interaction`/`protected`, so
/// those three become mutable through this one path). `clone_allowed` and
/// `pinned` are mutable here too: the ring burns unpinned links, and the
/// owner turns clone on or off without revoking the token the tab holds.
#[derive(serde::Deserialize)]
pub struct UpdateShareLinkPolicyRequest {
    pub interaction: Option<ShareInteraction>,
    pub visibility: Option<ShareVisibility>,
    pub protected: Option<Vec<ProtectedElementRef>>,
    /// [Rev 3] `None`/absent leaves `allow_forward` exactly as it is —
    /// including "still unset, still following `visibility`'s default" if
    /// that was its state before this call. `Some(v)` pins it explicitly.
    /// This is why sending ONLY `visibility` in the same request that
    /// changes it never flips an already-explicit `allow_forward`: this
    /// field is simply absent from that request, so
    /// `db::update_share_link_policy` never touches the column — see its
    /// own doc comment for the exact mechanism.
    #[serde(default)]
    pub allow_forward: Option<bool>,
    /// Absent leaves `clone_allowed` as it was set at creation.
    #[serde(default)]
    pub clone_allowed: Option<bool>,
    /// Absent leaves the ring-pin as it is.
    #[serde(default)]
    pub pinned: Option<bool>,
    /// Absent leaves channel mode as it is. `false` is a cadence link.
    #[serde(default)]
    pub live: Option<bool>,
}

/// PATCH /api/share/{token}
///
/// Owner-only. Unknown token AND a non-owner caller both answer the same
/// bare 404 (`db::update_share_link_policy`'s own ownership check). Every
/// field a caller supplies takes effect immediately: a link already open in
/// a recipient's tab re-resolves its tier fresh on the recipient's NEXT
/// `GET`/clone (`db::effective_share_tier` never caches), so a tightened
/// `visibility`/`interaction` takes effect without waiting for the link's
/// own TTL.
pub async fn update_share_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Json(body): Json<UpdateShareLinkPolicyRequest>,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };
    if let Some(protected) = &body.protected {
        if protected.len() > MAX_PROTECTED_ELEMENTS {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("protected exceeds the maximum element count")),
            )
                .into_response();
        }
    }
    let protected_json = match &body.protected {
        Some(protected) => match serde_json::to_string(protected) {
            Ok(s) => Some(s),
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse::new("protected is not serializable")),
                )
                    .into_response();
            }
        },
        None => None,
    };
    let interaction = body.interaction.map(|i| i.as_str());
    let visibility = body.visibility.map(|v| v.as_str());
    let allow_forward = body.allow_forward;
    let clone_allowed = body.clone_allowed;
    let pinned = body.pinned;
    let live = body.live;

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(live) = live {
            return crate::db::set_share_live(&conn, &token, user_id, live);
        }
        crate::db::update_share_link_policy(
            &conn,
            &token,
            user_id,
            interaction,
            visibility,
            protected_json.as_deref(),
            allow_forward,
            clone_allowed,
            pinned,
        )
    })
    .await;

    match result {
        Ok(Ok(true)) => Json(serde_json::json!({ "updated": true })).into_response(),
        Ok(Ok(false)) => share_not_found(),
        Ok(Err(e)) => {
            tracing::error!("DB error updating share policy: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

// ============================================================================
// POST /api/share/{token}/clone
// ============================================================================

/// The DB-side outcome of a clone attempt — carries enough for the outer
/// match (after the `spawn_blocking` boundary) to pick the right HTTP
/// response without a second round-trip to the database.
enum CloneOutcome {
    /// Cloned: the (possibly stripped) preset plus the strip list.
    Cloned {
        preset: serde_json::Value,
        stripped: Vec<serde_json::Value>,
    },
    /// The caller's effective rights on this token do not include `clone`.
    Forbidden,
    /// The token names a screenshot share — nothing to clone.
    NotClonable,
    /// `preset_json` failed to parse as JSON (should never happen — it was
    /// validated at creation time; see `create_live_share`).
    Corrupt,
}

/// Walk `preset.indicators[*].type_id` and drop any entry
/// `db::indicator_should_strip` flags for `recipient`, recording each as
/// `{type_id, name, reason: "license"}`. Every other part of `preset`
/// (windows, bubbles, layout, alerts, primitives, …) is carried through
/// unchanged — only the `indicators` array is filtered.
///
/// A SECOND, independent pass (docs/mlc/plans/share-policy-2026-09-25.md §5)
/// then strips every element the sharer marked Protected — primitives
/// (nested under `windows[*].drawings.primitives`/`stashed_primitives`/
/// `symbol_drawings_snapshots[*]` and `bubbles[*].primitives`), any
/// surviving indicator, and alerts — UNLESS `skip_protected_strip` is `true`
/// (the caller's resolved `ShareTier` is `CloneProtected`, §1). The two
/// passes are independent: holding `CloneProtected` on a share never grants
/// a license on someone else's published indicator, and a missing indicator
/// license is never bypassed by a Protected grant.
///
/// Extracted out of [`clone_share`]'s own inline loop
/// (docs/mlc/plans/shared-presets-rights-and-live-sync-2026-09-23.md §5) so
/// `routes::rooms`'s own clone route can run the exact same strip rule over
/// a room's reassembled preset — one strip implementation, not two that
/// could drift apart. Rooms has no `protected`/`clone_protected` concept of
/// its own (Protected is a share-link-only idea, §6) — it always passes
/// `protected: &[]` and `skip_protected_strip: false`.
pub(crate) fn clone_preset_with_strip(
    conn: &rusqlite::Connection,
    mut preset: serde_json::Value,
    recipient: i64,
    protected: &[ProtectedElementRef],
    skip_protected_strip: bool,
) -> rusqlite::Result<(serde_json::Value, Vec<serde_json::Value>)> {
    let mut stripped = Vec::new();

    if let Some(indicators) = preset.get_mut("indicators").and_then(|v| v.as_array_mut()) {
        let mut kept = Vec::with_capacity(indicators.len());
        for entry in indicators.drain(..) {
            let type_id = entry.get("type_id").and_then(|v| v.as_str()).unwrap_or("");
            let should_strip =
                !type_id.is_empty() && crate::db::indicator_should_strip(conn, type_id, recipient)?;
            if should_strip {
                let name = entry.get("name").and_then(|v| v.as_str()).unwrap_or("");
                stripped.push(serde_json::json!({ "type_id": type_id, "name": name, "reason": "license" }));
            } else {
                kept.push(entry);
            }
        }
        *indicators = kept;
    }

    if !skip_protected_strip && !protected.is_empty() {
        strip_protected_elements(&mut preset, protected, &mut stripped);
    }

    Ok((preset, stripped))
}

/// Does `(kind, id)` match any entry in `protected`?
fn is_protected(protected: &[ProtectedElementRef], kind: &str, id: &str) -> bool {
    protected.iter().any(|p| p.kind == kind && p.id == id)
}

/// Read a `PrimitiveSnapshot`-shaped value's own id: `prim.json` is a STRING
/// (the primitive's own serialized state), parsed as JSON, then `.data.id`
/// read off of THAT (mirrors `mlc-core::drawing::primitive_snapshot::
/// PrimitiveSnapshot::id()` / `rooms_codec::primitive_entity_id`, duplicated
/// here per this module's own "inline, don't depend on rooms_codec" rule,
/// §5). `None` on anything that does not parse — a Protected mark that
/// cannot be matched is simply never stripped, the same defensive posture
/// the license pass's own `unwrap_or("")` already uses; this never fails the
/// whole clone over one malformed primitive.
fn primitive_snapshot_id(prim: &serde_json::Value) -> Option<u64> {
    let inner = prim.get("json")?.as_str()?;
    let parsed: serde_json::Value = serde_json::from_str(inner).ok()?;
    parsed.get("data")?.get("id")?.as_u64()
}

/// Remove every `PrimitiveSnapshot`-shaped entry in `arr` whose own id is
/// marked Protected, recording each as
/// `{"kind":"primitive","id":..,"name":<type_id>,"reason":"protected"}`.
fn strip_protected_primitives(
    arr: &mut Vec<serde_json::Value>,
    protected: &[ProtectedElementRef],
    stripped: &mut Vec<serde_json::Value>,
) {
    arr.retain(|prim| {
        let Some(id) = primitive_snapshot_id(prim) else {
            return true;
        };
        let id_str = id.to_string();
        if is_protected(protected, "primitive", &id_str) {
            let type_id = prim.get("type_id").and_then(|v| v.as_str()).unwrap_or("");
            stripped.push(serde_json::json!({ "kind": "primitive", "id": id_str, "name": type_id, "reason": "protected" }));
            false
        } else {
            true
        }
    });
}

/// Strip every Protected-marked primitive, indicator, and alert out of
/// `preset` in place. Tolerant of a preset missing `windows`/`bubbles`
/// entirely (an older or minimal preset) — never errors the whole clone on
/// a malformed shape, same posture as the rest of this module's JSON
/// walking (`clone_share` already treats `preset` as opaque `serde_json::
/// Value`, never deserializing into `ChartPreset`).
fn strip_protected_elements(
    preset: &mut serde_json::Value,
    protected: &[ProtectedElementRef],
    stripped: &mut Vec<serde_json::Value>,
) {
    if let Some(windows) = preset.get_mut("windows").and_then(|v| v.as_array_mut()) {
        for window in windows {
            if let Some(prims) = window
                .get_mut("drawings")
                .and_then(|d| d.get_mut("primitives"))
                .and_then(|v| v.as_array_mut())
            {
                strip_protected_primitives(prims, protected, stripped);
            }
            if let Some(prims) = window.get_mut("stashed_primitives").and_then(|v| v.as_array_mut()) {
                strip_protected_primitives(prims, protected, stripped);
            }
            if let Some(symbol_map) = window.get_mut("symbol_drawings_snapshots").and_then(|v| v.as_object_mut()) {
                for (_symbol, arr) in symbol_map.iter_mut() {
                    if let Some(prims) = arr.as_array_mut() {
                        strip_protected_primitives(prims, protected, stripped);
                    }
                }
            }
        }
    }

    if let Some(bubbles) = preset.get_mut("bubbles").and_then(|v| v.as_array_mut()) {
        for bubble in bubbles {
            if let Some(prims) = bubble.get_mut("primitives").and_then(|v| v.as_array_mut()) {
                strip_protected_primitives(prims, protected, stripped);
            }
        }
    }

    if let Some(indicators) = preset.get_mut("indicators").and_then(|v| v.as_array_mut()) {
        indicators.retain(|entry| {
            let Some(id) = entry.get("id").and_then(|v| v.as_u64()) else {
                return true;
            };
            let id_str = id.to_string();
            if is_protected(protected, "indicator", &id_str) {
                let name = entry.get("name").and_then(|v| v.as_str()).unwrap_or("");
                stripped.push(serde_json::json!({ "kind": "indicator", "id": id_str, "name": name, "reason": "protected" }));
                false
            } else {
                true
            }
        });
    }

    if let Some(alerts) = preset.get_mut("alerts").and_then(|v| v.as_array_mut()) {
        alerts.retain(|entry| {
            let Some(id) = entry.get("id").and_then(|v| v.as_u64()) else {
                return true;
            };
            let id_str = id.to_string();
            if is_protected(protected, "alert", &id_str) {
                let name = entry.get("name").and_then(|v| v.as_str()).unwrap_or("");
                stripped.push(serde_json::json!({ "kind": "alert", "id": id_str, "name": name, "reason": "protected" }));
                false
            } else {
                true
            }
        });
    }
}

/// POST /api/share/{token}/clone
///
/// Auth required (see `resolve_user_id`). Requires the caller's freshly
/// re-derived [`crate::db::ShareTier`] (`db::effective_share_tier`, called
/// here, never a client-supplied or previously-cached rights claim — plan
/// §1/§4/§8.1) to be at least `Clone` — 403 otherwise, same plain shape as
/// before rights v2. Only a `live` share carries a preset to clone; a
/// `screenshot` token answers 400. Unknown, expired, and revoked tokens
/// answer the same bare 404 as `GET /api/share/{token}`.
///
/// Walks `preset.indicators[*].type_id` (`IndicatorSnapshot`, mlc-core) and
/// drops any entry `db::indicator_should_strip` flags for the caller,
/// recording each as `{type_id, name, reason: "license"}` — unconditionally.
/// Then, UNLESS the caller's tier is `CloneProtected`, strips every element
/// the sharer marked Protected the same way, tagged `reason: "protected"`
/// (`clone_preset_with_strip`, §5). Every other part of the preset (windows,
/// bubbles, layout, alerts not Protected, …) is carried through unchanged.
/// Answers:
/// ```json
/// { "preset": { …stripped preset… }, "stripped": [{"kind or type_id": "…", "name": "…", "reason": "…"}] }
/// ```
pub async fn clone_share(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<CloneOutcome>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let row = match crate::db::get_share_link(&conn, &token)? {
            Some(row) => row,
            None => return Ok(None),
        };

        let tier = crate::db::effective_share_tier(&conn, &row, Some(user_id))?;
        let tier = match tier {
            Some(tier) if tier >= crate::db::ShareTier::Clone => tier,
            _ => return Ok(Some(CloneOutcome::Forbidden)),
        };
        if row.kind != ShareKind::Live.as_str() {
            return Ok(Some(CloneOutcome::NotClonable));
        }

        let preset: serde_json::Value = match serde_json::from_str(&row.preset_json) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("corrupt preset_json on share {}: {}", row.token, e);
                return Ok(Some(CloneOutcome::Corrupt));
            }
        };

        let protected: Vec<ProtectedElementRef> = serde_json::from_str(&row.protected_json).unwrap_or_default();
        let skip_protected_strip = tier == crate::db::ShareTier::CloneProtected;
        let (preset, stripped) =
            clone_preset_with_strip(&conn, preset, user_id, &protected, skip_protected_strip)?;
        Ok(Some(CloneOutcome::Cloned { preset, stripped }))
    })
    .await;

    match result {
        Ok(Ok(Some(CloneOutcome::Cloned { preset, stripped }))) => Json(serde_json::json!({
            "preset": preset,
            "stripped": stripped,
        }))
        .into_response(),
        Ok(Ok(Some(CloneOutcome::Forbidden))) => (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse::new("clone is not granted for this share")),
        )
            .into_response(),
        Ok(Ok(Some(CloneOutcome::NotClonable))) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("only a live share can be cloned")),
        )
            .into_response(),
        Ok(Ok(Some(CloneOutcome::Corrupt))) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
        Ok(Ok(None)) => share_not_found(),
        Ok(Err(e)) => {
            tracing::error!("DB error cloning share: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

// ============================================================================
// POST /api/share/{token}/preview, GET /api/share/{token}/preview.png (§9)
// ============================================================================

/// Upload cap for `POST /api/share/{token}/preview`'s raw PNG body — also
/// the `DefaultBodyLimit` override `routes/mod.rs` layers onto that route,
/// so an over-cap request is refused by axum itself before ever reaching
/// [`build_preview_png`]'s own explicit check below.
pub(crate) const PREVIEW_MAX_BYTES: usize = 2 * 1024 * 1024;
/// Per-side decode cap — refused before any resize work, so a "valid PNG,
/// absurd dimensions" upload cannot spend CPU decompressing a huge canvas
/// just to be rejected afterward.
const PREVIEW_MAX_DIM: u32 = 2048;
/// The re-encoded preview's fixed canvas size — the standard Open Graph
/// card aspect ratio (1.91:1). The source image is scaled to FIT inside
/// this canvas (never cropped, never upscaled past its own resolution) and
/// centered on a solid background — letterboxed, not filled — so a
/// non-16:9-ish chart screenshot never has its edges cut off. Only the card
/// test reads these two (nothing in a non-test build does).
#[cfg(test)]
const PREVIEW_OUTPUT_WIDTH: u32 = 1200;
const PREVIEW_OUTPUT_HEIGHT: u32 = 630;
/// Long edge of the chart PNG stored on disk. The served card is always
/// [`PREVIEW_OUTPUT_WIDTH`]×[`PREVIEW_OUTPUT_HEIGHT`]; this cap is only the
/// source that gets fitted into the empty frame.
const PREVIEW_STORE_MAX_EDGE: u32 = 1280;


/// Why [`build_preview_png`] refused an upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreviewError {
    TooLarge,
    NotPng,
    DecodeFailed,
    DimensionsOutOfBounds,
    EncodeFailed,
}
#[cfg(test)]

impl PreviewError {
    fn to_response(self) -> Response {
        let (status, msg) = match self {
            PreviewError::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "preview exceeds the upload size cap"),
            PreviewError::NotPng => (StatusCode::BAD_REQUEST, "preview must be a PNG file"),
            PreviewError::DecodeFailed => (StatusCode::BAD_REQUEST, "preview could not be decoded as PNG"),
            PreviewError::DimensionsOutOfBounds => {
                (StatusCode::BAD_REQUEST, "preview dimensions are out of bounds")
            }
            PreviewError::EncodeFailed => (StatusCode::INTERNAL_SERVER_ERROR, "preview re-encode failed"),
        };
        (status, Json(ErrorResponse::new(msg))).into_response()
    }
}

/// Decode `bytes` as a PNG, validate size/dimensions, and re-encode the
/// chart at its own aspect (long edge capped). The re-encode is what
/// "strip metadata" buys: any non-pixel chunk smuggled into a
/// technically-valid PNG container (a `tEXt` comment, an embedded colour
/// profile, …) never survives the round trip, because only the DECODED
/// pixel buffer is ever touched again. The branded frame is applied later,
/// on the way out, over a blank card.
fn build_preview_png(bytes: &[u8]) -> Result<Vec<u8>, PreviewError> {
    if bytes.len() > PREVIEW_MAX_BYTES {
        return Err(PreviewError::TooLarge);
    }
    if bytes.len() < PNG_MAGIC.len() || bytes[..PNG_MAGIC.len()] != PNG_MAGIC {
        return Err(PreviewError::NotPng);
    }
    let img = image::load_from_memory_with_format(bytes, image::ImageFormat::Png)
        .map_err(|_| PreviewError::DecodeFailed)?;
    let (w, h) = (img.width(), img.height());
    if w == 0 || h == 0 || w > PREVIEW_MAX_DIM || h > PREVIEW_MAX_DIM {
        return Err(PreviewError::DimensionsOutOfBounds);
    }

    // Keep the chart's own aspect. The card frame is applied when the
    // preview is served, onto a blank card that has no chart of its own.
    let long = w.max(h);
    let (ow, oh) = if long > PREVIEW_STORE_MAX_EDGE {
        let scale = PREVIEW_STORE_MAX_EDGE as f64 / long as f64;
        (
            ((w as f64 * scale).round() as u32).max(1),
            ((h as f64 * scale).round() as u32).max(1),
        )
    } else {
        (w, h)
    };
    let stored = if (ow, oh) == (w, h) {
        img.to_rgba8()
    } else {
        img.resize_exact(ow, oh, image::imageops::FilterType::Lanczos3)
            .to_rgba8()
    };

    let mut out = Vec::new();
    image::DynamicImage::ImageRgba8(stored)
        .write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
        .map_err(|_| PreviewError::EncodeFailed)?;
    Ok(out)
}

/// POST /api/share/{token}/preview
///
/// Owner-only, auth required. Body is the raw PNG bytes (no multipart
/// envelope — see this route's `DefaultBodyLimit` override in
/// `routes/mod.rs`, sized to [`PREVIEW_MAX_BYTES`]). Decoded, validated, and
/// re-encoded by [`build_preview_png`] before anything touches disk; the
/// result lands at `<data_dir>/share/<user_id>/<token>-preview.png` via the
/// same atomic tmp+rename write `create_screenshot_share` already uses.
pub async fn upload_share_preview(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let user_id = match resolve_user_id(state.clone(), &headers).await {
        Ok(id) => id,
        Err(status) => return auth_err(status),
    };

    let png_bytes = match build_preview_png(&body) {
        Ok(bytes) => bytes,
        Err(e) => return e.to_response(),
    };

    let token_for_response = token.clone();
    let share_root = state.control_plane().share_root.clone();
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let row = match crate::db::get_share_link(&conn, &token)? {
            Some(row) => row,
            None => return Ok(false),
        };
        if row.user_id != user_id {
            return Ok(false);
        }

        let rel_path = format!(
            "{}/{}-preview.png",
            crate::syncstore::sanitize(&user_id.to_string())?,
            crate::syncstore::sanitize(&token)?
        );
        let abs_path = share_root.join(&rel_path);
        let write_result = (|| -> std::io::Result<()> {
            if let Some(dir) = abs_path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let tmp = abs_path.with_extension("png.tmp");
            std::fs::write(&tmp, &png_bytes)?;
            std::fs::rename(&tmp, &abs_path)?;
            Ok(())
        })();
        if let Err(e) = write_result {
            tracing::error!("IO error writing preview blob {}: {}", rel_path, e);
            return Err(rusqlite::Error::ToSqlConversionFailure(Box::new(e)));
        }
        crate::db::set_share_preview_path(&conn, &token, user_id, &rel_path)?;
        Ok(true)
    })
    .await;

    match result {
        Ok(Ok(true)) => Json(serde_json::json!({
            "preview_url": format!("/api/share/{}/preview.png", token_for_response),
        }))
        .into_response(),
        Ok(Ok(false)) => share_not_found(),
        Ok(Err(e)) => {
            tracing::error!("DB error saving share preview: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Internal error")),
        )
            .into_response(),
    }
}

/// Whether `row` may ever serve a preview image, and its relative path if
/// so — factored out of [`get_share_preview`] so the "a private share never
/// serves its preview" rule is a plain, unit-testable function rather than
/// logic buried inside a `spawn_blocking` closure.
fn share_preview_rel_path(row: &crate::db::ShareLinkRow) -> Option<&str> {
    if row.visibility == "private" || row.preview_path.is_empty() {
        None
    } else {
        Some(row.preview_path.as_str())
    }
}

/// GET /api/share/{token}/preview.png
///
/// PUBLIC, same 404 opacity discipline as `get_share_png`. A PRIVATE share's
/// preview endpoint 404s UNCONDITIONALLY regardless of file presence — belt
/// on top of the OG-injection route's own "never point at the image for a
/// private share" rule (defense in depth, §9).
pub async fn get_share_preview(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> Response {
    let share_root = state.control_plane().share_root.clone();
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<String>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let Some(row) = crate::db::get_share_link(&conn, &token)? else {
            return Ok(None);
        };
        Ok(share_preview_rel_path(&row).map(|p| p.to_string()))
    })
    .await;

    let rel_path = match result {
        Ok(Ok(Some(p))) => p,
        Ok(Ok(None)) => return share_not_found(),
        Ok(Err(e)) => {
            tracing::error!("DB error fetching share preview: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error")),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Internal error")),
            )
                .into_response();
        }
    };
    if !crate::pathutil::is_safe_relative_path(&rel_path) {
        return share_not_found();
    }

    match tokio::fs::read(share_root.join(&rel_path)).await {
        Ok(body) => {
            // The file on disk is the chart crop. The bytes we serve are
            // that crop set into the branded card (hat on the left, this
            // chart on the right). A compose failure serves the crop itself.
            let png = match tokio::task::spawn_blocking(move || {
                compose_share_card_png(&body).unwrap_or(body)
            })
            .await
            {
                Ok(png) => png,
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse::new("Internal error")),
                    )
                        .into_response();
                }
            };
            Response::builder()
                .status(200)
                .header("content-type", "image/png")
                .header("cache-control", "public, max-age=300")
                .body(Body::from(png))
                .unwrap()
        }
        Err(_) => share_not_found(),
    }
}

/// Shot window inside `assets/og-card.png`, matching
/// `mylittlechart-landing/tools/og-cards/og_card.html`.
const SHOT_X: u32 = 600;
const SHOT_Y: u32 = 58;
const SHOT_W: u32 = 560;
const SHOT_H: u32 = 557;
const SHOT_RADIUS: i32 = 12;
const FADE_X: u32 = 560;
const FADE_W: u32 = 90;
const CARD_BG: [u8; 4] = [0x13, 0x17, 0x22, 255];

fn card_template() -> &'static image::RgbaImage {
    static CELL: std::sync::OnceLock<image::RgbaImage> = std::sync::OnceLock::new();
    CELL.get_or_init(|| {
        image::load_from_memory_with_format(
            include_bytes!("../../assets/og-card.png"),
            image::ImageFormat::Png,
        )
        .expect("share card template")
        .to_rgba8()
    })
}

fn in_rounded_rect(x: i32, y: i32, w: i32, h: i32, r: i32) -> bool {
    if x < 0 || y < 0 || x >= w || y >= h {
        return false;
    }
/// The card template as shipped. Only the card test compares against it
/// (nothing in a non-test build does).
#[cfg(test)]
    let r = r.max(0).min(w / 2).min(h / 2);
    if r == 0 {
        return true;
    }
    let (cx, cy) = if x < r && y < r {
        (r, r)
    } else if x >= w - r && y < r {
        (w - r, r)
    } else if x < r && y >= h - r {
        (r, h - r)
    } else if x >= w - r && y >= h - r {
        (w - r, h - r)
    } else {
        return true;
    };
    let dx = x - cx;
    let dy = y - cy;
    dx * dx + dy * dy <= r * r
}

/// Branded card with an empty right-hand frame (`assets/og-card-blank.png`).
/// A chart, a QR, or anything else is placed into that frame. The file has
/// no chart of its own.
/// Branded card with the words in the frame. A private link must not fall
/// back to the site card, which still contains a sample chart.
pub async fn get_private_share_card() -> Response {
    Response::builder()
        .status(200)
        .header("content-type", "image/png")
        .header("cache-control", "public, max-age=86400")
        .body(Body::from(private_share_card_png().to_vec()))
        .unwrap()
}

fn private_share_card_png() -> &'static [u8] {
    static CELL: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    CELL.get_or_init(|| {
        let mut card = blank_card().clone();
        paint_card_label(&mut card, "PRIVATE", SHOT_Y + SHOT_H / 2 - 70);
        paint_card_label(&mut card, "CHART", SHOT_Y + SHOT_H / 2 + 20);
        let mut buf = Vec::new();
        let _ = image::DynamicImage::ImageRgba8(card).write_to(
            &mut std::io::Cursor::new(&mut buf),
            image::ImageFormat::Png,
        );
        buf
    })
    .as_slice()
}

fn glyph_rows(c: char) -> [u8; 7] {
    match c {
        'A' => [0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001],
        'C' => [0b01110, 0b10001, 0b10000, 0b10000, 0b10000, 0b10001, 0b01110],
        'E' => [0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111],
        'H' => [0b10001, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001],
        'I' => [0b01110, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110],
        'P' => [0b11110, 0b10001, 0b10001, 0b11110, 0b10000, 0b10000, 0b10000],
        'R' => [0b11110, 0b10001, 0b10001, 0b11110, 0b10100, 0b10010, 0b10001],
        'T' => [0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100],
        'V' => [0b10001, 0b10001, 0b10001, 0b10001, 0b01010, 0b01010, 0b00100],
        _ => [0, 0, 0, 0, 0, 0, 0],
    }
}

fn paint_card_label(card: &mut image::RgbaImage, text: &str, top: u32) {
    const SCALE: u32 = 10;
    const GAP: u32 = 4;
    let cols = 5u32;
    let advance = (cols + 1) * SCALE + GAP;
    let width = text.chars().count() as u32 * advance;
    let mut x0 = SHOT_X + SHOT_W.saturating_sub(width) / 2;
    let ink = [0xE8, 0xEC, 0xF4, 255];
    for ch in text.chars() {
        let rows = glyph_rows(ch);
        for (ry, bits) in rows.iter().enumerate() {
            for cx in 0..cols {
                if bits & (1u8 << (cols - 1 - cx)) == 0 {
                    continue;
                }
                let px = x0 + cx * SCALE;
                let py = top + ry as u32 * SCALE;
                for dy in 0..SCALE {
                    for dx in 0..SCALE {
                        if let Some(p) = card.get_pixel_mut_checked(px + dx, py + dy) {
                            *p = image::Rgba(ink);
                        }
                    }
                }
            }
        }
        x0 += advance;
    }
}

fn blank_card() -> &'static image::RgbaImage {
    static CELL: std::sync::OnceLock<image::RgbaImage> = std::sync::OnceLock::new();
    CELL.get_or_init(|| {
        image::load_from_memory_with_format(
            include_bytes!("../../assets/og-card-blank.png"),
            image::ImageFormat::Png,
        )
        .expect("blank share card")
        .to_rgba8()
    })
}

fn blend_toward(px: &mut image::Rgba<u8>, src: [u8; 4], coverage: f32) {
    let a = coverage.clamp(0.0, 1.0);
    let inv = 1.0 - a;
    for i in 0..3 {
        px.0[i] = (src[i] as f32 * a + px.0[i] as f32 * inv).round() as u8;
    }
    px.0[3] = 255;
}

/// Fit the whole chart inside the empty frame. Nothing is cropped, and the
/// sample chart from the source artwork is not under it: [`blank_card`]
/// already cleared that side.
fn compose_share_card(chart: &image::DynamicImage) -> image::RgbaImage {
    let mut card = blank_card().clone();
    let sw = chart.width().max(1) as f64;
    let sh = chart.height().max(1) as f64;
    let scale = (SHOT_W as f64 / sw).min(SHOT_H as f64 / sh);
    let dw = ((sw * scale).round() as u32).clamp(1, SHOT_W);
    let dh = ((sh * scale).round() as u32).clamp(1, SHOT_H);
    let resized = chart
        .resize_exact(dw, dh, image::imageops::FilterType::Lanczos3)
        .to_rgba8();
    let ox = SHOT_X + (SHOT_W - dw) / 2;
    let oy = SHOT_Y + (SHOT_H - dh) / 2;
    let (fw, fh, r) = (SHOT_W as i32, SHOT_H as i32, SHOT_RADIUS - 1);
    for y in 0..dh {
        for x in 0..dw {
            let lx = (ox + x - SHOT_X) as i32;
            let ly = (oy + y - SHOT_Y) as i32;
            if !in_rounded_rect(lx, ly, fw, fh, r) {
                continue;
            }
            card.put_pixel(ox + x, oy + y, *resized.get_pixel(x, y));
        }
    }
    for x in 0..FADE_W {
        let coverage = 1.0 - (x as f32 / FADE_W as f32);
        let dx = FADE_X + x;
        if dx >= card.width() {
            break;
        }
        for y in 0..card.height() {
            blend_toward(card.get_pixel_mut(dx, y), CARD_BG, coverage);
        }
    }
    card
}

fn compose_share_card_png(chart_png: &[u8]) -> Result<Vec<u8>, PreviewError> {
    let chart = image::load_from_memory_with_format(chart_png, image::ImageFormat::Png)
        .map_err(|_| PreviewError::DecodeFailed)?;
    let card = compose_share_card(&chart);
    let mut out = Vec::new();
    image::DynamicImage::ImageRgba8(card)
        .write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
        .map_err(|_| PreviewError::EncodeFailed)?;
    Ok(out)
}

// ============================================================================
// OG/twitter meta-tag injection for the crawler-facing `GET /` route (§9) —
// pure functions, called from `main.rs`'s root handler (which owns the file
// I/O and the DB round trip; everything here is a plain, unit-testable
// string transform).
// ============================================================================

/// The neutral title a PRIVATE share's link-preview card shows — never the
/// chart's own title, never a hint that a preview image exists (§9: "Private
/// shares get a neutral card, never the chart image").
pub(crate) const PRIVATE_SHARE_OG_TITLE: &str = "A private chart on MyLittleChart";

/// The per-token override for the served `index.html`'s OG/twitter meta
/// tags — a `None` field means "leave that tag at its app-wide default",
/// never "blank it out".
pub(crate) struct OgTags {
    pub title: Option<String>,
    /// Replaces `og:description` / `twitter:description`. The link title
    /// stays the product name; this line is `nick - chart`.
    pub description: Option<String>,
    pub image_url: Option<String>,
}

/// Resolve the OG-tag override for a fetched, live [`crate::db::ShareLinkRow`]
/// (§9's selection matrix — the "token not found/expired/revoked" branch is
/// the caller's own `None` case, one level up, before this ever runs):
/// - private → the fixed [`PRIVATE_SHARE_OG_TITLE`], no image, no chart
///   name in the description.
/// - public → the link title stays the app default ("mylittlechart — the
///   terminal"). The description is `nick - chart title`.
/// - image is overridden ONLY when `preview_path` is set AND the link is
///   public — a private link never points at its preview even when one was
///   uploaded (defense in depth alongside [`get_share_preview`]'s own
///   refusal).
pub(crate) fn og_tags_for_share(row: &crate::db::ShareLinkRow, owner_label: &str) -> OgTags {
    if row.visibility == "private" {
        return OgTags {
            title: Some(PRIVATE_SHARE_OG_TITLE.to_string()),
            description: None,
            // Not the site default card: that one still has a sample chart.
            // This image is the same frame with the words in place of a chart.
            image_url: Some("https://mylittlechart.org/api/share/private-card.png".to_string()),
        };
    }
    let image_url = if row.preview_path.is_empty() {
        None
    } else {
        Some(format!(
            "https://mylittlechart.org/api/share/{}/preview.png?v={}",
            row.token, row.revision.max(1)
        ))
    };
    OgTags {
        title: None,
        description: share_card_description(owner_label, &row.title),
        image_url,
    }
}

/// `nick - chart title`. Either half may be missing. Both missing → no
/// description override.
fn share_card_description(owner_label: &str, chart_title: &str) -> Option<String> {
    let who = owner_label.trim();
    let title = chart_title.trim();
    match (who.is_empty(), title.is_empty()) {
        (false, false) => Some(format!("{who} - {title}")),
        (false, true) => Some(who.to_string()),
        (true, false) => Some(title.to_string()),
        (true, true) => None,
    }
}

/// HTML-attribute-escape `s` — the one place caller-supplied text (a share
/// title) reaches raw HTML output in this whole crate. Escapes the five
/// characters that matter inside a double-quoted attribute value; `'` is
/// included even though it cannot break a double-quoted value, cheaply
/// closing off the single-quoted-attribute variant too.
fn escape_html_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

/// Replace the `content="…"` value of the FIRST `<meta …>` tag whose exact
/// attribute prefix is `prefix` (e.g. `r#"property="og:title" content=""#`)
/// with `value`, HTML-attribute-escaped. Returns `html` UNCHANGED when
/// `prefix` is not found — a missing tag is never invented, so an
/// unexpected template shape degrades to "no override" rather than
/// corrupting the page.
fn replace_meta_content(html: &str, prefix: &str, value: &str) -> String {
    let Some(tag_start) = html.find(prefix) else {
        return html.to_string();
    };
    let value_start = tag_start + prefix.len();
    let Some(rel_end) = html[value_start..].find('"') else {
        return html.to_string();
    };
    let value_end = value_start + rel_end;
    let mut out = String::with_capacity(html.len() + value.len());
    out.push_str(&html[..value_start]);
    out.push_str(&escape_html_attr(value));
    out.push_str(&html[value_end..]);
    out
}

/// Override the served `index.html`'s per-share OG/twitter meta tags in
/// place — the crawler-facing `GET /` route (`main.rs`, §9). Self-contained:
/// it locates each tag by its own stable attribute prefix in the
/// ALREADY-SHIPPED template (`mylittlechart-landing/web/app/index.html`'s
/// `og:title`/`og:image`/`twitter:title`/`twitter:image` tags) rather than
/// depending on a `<!--OG_META-->` marker added to that file — no cross-repo
/// change is needed for this to work against the real, deployed template.
/// Never touches `og:type`/`og:url` or the document `<title>`. Title tags
/// change only when `tags.title` is `Some` (a private card). Description
/// tags change only when `tags.description` is `Some`. Image tags change
/// only when `tags.image_url` is `Some`, leaving the app's own default
/// logo tag untouched otherwise.
pub(crate) fn inject_og_tags(html: &str, tags: &OgTags) -> String {
    let mut out = html.to_string();
    if let Some(title) = &tags.title {
        out = replace_meta_content(&out, r#"property="og:title" content=""#, title);
        out = replace_meta_content(&out, r#"name="twitter:title" content=""#, title);
    }
    if let Some(description) = &tags.description {
        out = replace_meta_content(&out, r#"property="og:description" content=""#, description);
        out = replace_meta_content(&out, r#"name="twitter:description" content=""#, description);
    }
    if let Some(image_url) = &tags.image_url {
        out = replace_meta_content(&out, r#"property="og:image" content=""#, image_url);
        out = replace_meta_content(&out, r#"name="twitter:image" content=""#, image_url);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Chart-share policy v1 (docs/mlc/plans/share-policy-2026-09-25.md §1,
    /// §11 step 1): a pre-existing client sending only the two original
    /// fields (`{title, preset}` — no `clone_allowed`, no `interaction`, no
    /// `protected`) must still deserialize, with every new field taking its
    /// safe `#[serde(default)]` value.
    #[test]
    fn create_live_share_request_parses_the_old_two_field_shape() {
        let body = serde_json::json!({ "title": "old client", "preset": { "windows": [] } });
        let parsed: CreateLiveShareRequest =
            serde_json::from_value(body).expect("old-shape request must still parse");
        assert_eq!(parsed.title, "old client");
        assert!(parsed.clone_allowed);
        assert_eq!(parsed.interaction, ShareInteraction::View);
        assert!(parsed.protected.is_empty());
        // Rev 3: an old client sending no `allow_forward` at all gets `None`
        // — "never set explicitly", follows `visibility`'s own default.
        assert_eq!(parsed.allow_forward, None);
    }

    /// The current, full-shape request round-trips every field, including a
    /// non-default interaction, a non-empty protected list, and (Rev 3) an
    /// explicit `allow_forward`.
    #[test]
    fn create_live_share_request_parses_the_full_rev2_shape() {
        let body = serde_json::json!({
            "title": "new client",
            "preset": {},
            "clone_allowed": true,
            "interaction": "interactive",
            "protected": [{ "kind": "primitive", "id": "42" }],
            "allow_forward": false,
        });
        let parsed: CreateLiveShareRequest =
            serde_json::from_value(body).expect("full-shape request must parse");
        assert!(parsed.clone_allowed);
        assert_eq!(parsed.interaction, ShareInteraction::Interactive);
        assert_eq!(parsed.protected.len(), 1);
        assert_eq!(parsed.protected[0].kind, "primitive");
        assert_eq!(parsed.protected[0].id, "42");
        assert_eq!(parsed.allow_forward, Some(false));
    }

    // ---- §8.4 acceptance test + clone_preset_with_strip unit coverage ----
    // (docs/mlc/plans/share-policy-2026-09-25.md §8.4/§11 step 3)

    /// Minimal in-memory schema for the tables `create_share_link`,
    /// `upsert_share_grant`, `effective_share_tier`, and
    /// `indicator_should_strip` touch — a local, `routes::share`-owned
    /// fixture (this crate's test fixtures are private to each module's own
    /// `mod tests`, `db.rs`'s own `share_test_conn`/`share_rights_test_conn`
    /// included, so this module builds its own rather than reaching across).
    fn strip_test_conn() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().expect("in-memory sqlite");
        conn.execute_batch(
            "
            PRAGMA foreign_keys=ON;

            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL,
                provider_user_id TEXT NOT NULL,
                display_name TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                public_id TEXT,
                UNIQUE(provider, provider_user_id)
            );

            CREATE TABLE share_links (
                token       TEXT    PRIMARY KEY,
                user_id     INTEGER NOT NULL REFERENCES users(id),
                kind        TEXT    NOT NULL,
                title       TEXT    NOT NULL DEFAULT '',
                preset_json TEXT    NOT NULL DEFAULT '',
                blob_path   TEXT    NOT NULL DEFAULT '',
                blob_bytes  INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT    NOT NULL,
                expires_at  TEXT    NOT NULL,
                revoked     INTEGER NOT NULL DEFAULT 0,
                clone_allowed INTEGER NOT NULL DEFAULT 0,
                interaction TEXT NOT NULL DEFAULT 'view',
                protected_json TEXT NOT NULL DEFAULT '[]',
                visibility TEXT NOT NULL DEFAULT 'public',
                preview_path TEXT NOT NULL DEFAULT '',
                allow_forward INTEGER,
                pinned INTEGER NOT NULL DEFAULT 0,
                chart_id TEXT NOT NULL DEFAULT '',
                revision INTEGER NOT NULL DEFAULT 1,
                op_seq INTEGER NOT NULL DEFAULT 0,
                live INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE share_ops (
                token TEXT NOT NULL,
                seq INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                object_id TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (token, seq)
            );

            CREATE TABLE grant_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_user_id INTEGER NOT NULL REFERENCES users(id),
                name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE grant_group_members (
                group_id INTEGER NOT NULL REFERENCES grant_groups(id),
                user_id  INTEGER NOT NULL REFERENCES users(id),
                added_at TEXT NOT NULL,
                PRIMARY KEY (group_id, user_id)
            );
            CREATE TABLE object_grants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                object_kind TEXT NOT NULL,
                object_id TEXT NOT NULL,
                owner_user_id INTEGER NOT NULL REFERENCES users(id),
                grantee_user_id INTEGER REFERENCES users(id),
                grantee_group_id INTEGER REFERENCES grant_groups(id),
                right TEXT NOT NULL,
                expires_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE published_indicators (
                type_id TEXT PRIMARY KEY,
                owner_user_id INTEGER NOT NULL REFERENCES users(id),
                visibility TEXT NOT NULL DEFAULT 'private',
                created_at TEXT NOT NULL
            );
            CREATE TABLE indicator_grants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type_id TEXT NOT NULL REFERENCES published_indicators(type_id),
                grantee_user_id INTEGER NOT NULL REFERENCES users(id),
                expires_at TEXT,
                created_at TEXT NOT NULL
            );
            ",
        )
        .expect("strip test schema");
        conn
    }

    fn insert_user(conn: &rusqlite::Connection, name: &str) -> i64 {
        conn.execute(
            "INSERT INTO users (provider, provider_user_id, display_name, created_at) VALUES ('test', ?1, ?1, '2026-01-01T00:00:00+00:00')",
            rusqlite::params![name],
        )
        .expect("insert user");
        conn.last_insert_rowid()
    }

    fn future_ts() -> String {
        (chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339()
    }

    /// One window with one `elliott_impulse` primitive (id 501) in
    /// `drawings.primitives` — `PrimitiveSnapshot`-shaped
    /// (`{"type_id","json"}`, the real id nested at `json.data.id`), the
    /// real Elliott Wave primitive kind (`mlc-core/src/toolbar.rs`), per the
    /// plan's own instruction to use the real primitive type for this test.
    fn elliott_preset_fixture() -> serde_json::Value {
        let inner = serde_json::json!({ "data": { "id": 501 } });
        serde_json::json!({
            "windows": [{
                "window_id": 1,
                "drawings": {
                    "window_id": 1,
                    "primitives": [{
                        "type_id": "elliott_impulse",
                        "json": serde_json::to_string(&inner).expect("serialize inner"),
                    }],
                },
            }],
            "bubbles": [],
            "indicators": [],
            "alerts": [],
        })
    }

    /// §8.4's own acceptance test, built BEFORE the rest of step 3 lands
    /// (owner instruction 2): a preset with a Protected `elliott_impulse`
    /// primitive, shared on a PRIVATE link, with account A granted `Clone`
    /// and account B granted `CloneProtected`.
    #[test]
    fn ewa_protected_clone_strip_and_private_link_lock_end_to_end() {
        let conn = strip_test_conn();
        let owner = insert_user(&conn, "owner");
        let account_a = insert_user(&conn, "account_a");
        let account_b = insert_user(&conn, "account_b");
        let account_c = insert_user(&conn, "account_c");

        let preset = elliott_preset_fixture();
        let preset_json = serde_json::to_string(&preset).expect("serialize preset");
        let protected_refs = vec![ProtectedElementRef {
            kind: "primitive".to_string(),
            id: "501".to_string(),
        }];
        let protected_json = serde_json::to_string(&protected_refs).expect("serialize protected");

        let now = chrono::Utc::now().to_rfc3339();
        let token = crate::db::create_share_link(
            &conn,
            owner,
            "live",
            "ewa test",
            &preset_json,
            0,
            &now,
            &future_ts(),
            false,
            "view",
            &protected_json,
            "private",
            None,
        )
        .expect("create share");

        crate::db::upsert_share_grant(
            &conn, &token, owner, Some(account_a), None, crate::db::ShareTier::Clone, None, &now,
        )
        .expect("grant A clone");
        crate::db::upsert_share_grant(
            &conn, &token, owner, Some(account_b), None, crate::db::ShareTier::CloneProtected, None, &now,
        )
        .expect("grant B clone_protected");

        let row = crate::db::get_share_link(&conn, &token).expect("query").expect("row");

        // 1. An ungranted account C's open path resolves to no tier at all —
        //    `get_share` answers the distinguishable locked response
        //    (§8.5), not the preset, for exactly this case.
        assert_eq!(
            crate::db::effective_share_tier(&conn, &row, Some(account_c)).expect("tier"),
            None
        );
        assert_eq!(
            serde_json::to_value(ShareLockedResponse { locked: true }).expect("serialize"),
            serde_json::json!({ "locked": true }),
        );

        // 2. Account A (tier Clone): the clone strips the Protected Elliott
        //    primitive, tagged reason "protected".
        let tier_a = crate::db::effective_share_tier(&conn, &row, Some(account_a))
            .expect("tier")
            .expect("account A holds a tier");
        assert_eq!(tier_a, crate::db::ShareTier::Clone);
        let preset_for_a: serde_json::Value = serde_json::from_str(&row.preset_json).expect("parse preset");
        let (cloned_a, stripped_a) = clone_preset_with_strip(
            &conn,
            preset_for_a,
            account_a,
            &protected_refs,
            tier_a == crate::db::ShareTier::CloneProtected,
        )
        .expect("clone for A");
        assert!(cloned_a["windows"][0]["drawings"]["primitives"]
            .as_array()
            .expect("array")
            .is_empty());
        assert_eq!(stripped_a.len(), 1);
        assert_eq!(stripped_a[0]["kind"], "primitive");
        assert_eq!(stripped_a[0]["id"], "501");
        assert_eq!(stripped_a[0]["reason"], "protected");

        // 3. Account B (tier CloneProtected): the clone carries the
        //    Protected Elliott primitive through unchanged, nothing stripped.
        let tier_b = crate::db::effective_share_tier(&conn, &row, Some(account_b))
            .expect("tier")
            .expect("account B holds a tier");
        assert_eq!(tier_b, crate::db::ShareTier::CloneProtected);
        let preset_for_b: serde_json::Value = serde_json::from_str(&row.preset_json).expect("parse preset");
        let (cloned_b, stripped_b) = clone_preset_with_strip(
            &conn,
            preset_for_b,
            account_b,
            &protected_refs,
            tier_b == crate::db::ShareTier::CloneProtected,
        )
        .expect("clone for B");
        assert_eq!(
            cloned_b["windows"][0]["drawings"]["primitives"]
                .as_array()
                .expect("array")
                .len(),
            1
        );
        assert!(stripped_b.is_empty());

        // 4. Account A's OPEN view (not clone) still shows the primitive —
        //    Protected means "not carried into a Clone," never "hidden from
        //    the live view" (unchanged honesty note, §1). Neither clone
        //    above ever mutated the stored row — re-reading it fresh proves it.
        let live_view: serde_json::Value = serde_json::from_str(&row.preset_json).expect("parse preset");
        assert_eq!(
            live_view["windows"][0]["drawings"]["primitives"]
                .as_array()
                .expect("array")
                .len(),
            1
        );

        // 5. A leaked link opened by a non-granted account is still
        //    refused: the same token, re-checked for account C, resolves to
        //    no tier again — enforcement is per-caller, never link-secrecy.
        assert_eq!(
            crate::db::effective_share_tier(&conn, &row, Some(account_c)).expect("tier"),
            None
        );
    }

    /// `clone_preset_with_strip`'s license pass runs UNCONDITIONALLY —
    /// independent of `skip_protected_strip`, proven here with
    /// `skip_protected_strip: true` and an empty `protected` list (so only
    /// the license pass can possibly account for the strip).
    #[test]
    fn clone_preset_with_strip_license_pass_is_independent_of_skip_protected_strip() {
        let conn = strip_test_conn();
        let vendor = insert_user(&conn, "vendor");
        let recipient = insert_user(&conn, "recipient");
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO published_indicators (type_id, owner_user_id, visibility, created_at) VALUES ('vendor_ind', ?1, 'public', ?2)",
            rusqlite::params![vendor, now],
        )
        .expect("publish indicator");

        let preset = serde_json::json!({
            "windows": [],
            "bubbles": [],
            "indicators": [{ "id": 1, "type_id": "vendor_ind", "name": "Vendor Indicator" }],
            "alerts": [],
        });

        let (cloned, stripped) =
            clone_preset_with_strip(&conn, preset, recipient, &[], true).expect("clone");
        assert!(cloned["indicators"].as_array().expect("array").is_empty());
        assert_eq!(stripped.len(), 1);
        assert_eq!(stripped[0]["reason"], "license");
    }

    // ---- §8.2 grants: owner-only, revoked stops on the next check ----

    /// Grant CRUD end to end, at the `db::` layer `create_share_grant`/
    /// `list_share_grants`/`delete_share_grant` call: the owner can grant and
    /// revoke; a non-owner's attempt to revoke someone else's grant refuses
    /// (`db::revoke_object_grant`'s own owner-scoped WHERE); a revoked grant
    /// stops counting on the very next `effective_share_tier` check (already
    /// proven for the DB layer directly in `db.rs`'s own
    /// `revoking_a_share_grant_stops_it_on_the_next_effective_share_tier_call`
    /// — this test additionally proves `count_object_grants`/`list_object_grants`
    /// agree with that outcome, the two functions `create_share_grant`/
    /// `list_share_grants` actually call).
    #[test]
    fn share_grant_owner_ok_non_owner_refused_revoked_stops_working() {
        let conn = strip_test_conn();
        let owner = insert_user(&conn, "owner");
        let grantee = insert_user(&conn, "grantee");
        let stranger = insert_user(&conn, "stranger");
        let now = chrono::Utc::now().to_rfc3339();
        let token = crate::db::create_share_link(
            &conn, owner, "live", "t", "{}", 0, &now, &future_ts(), false, "view", "[]", "private", None,
        )
        .expect("create share");

        let grant_id = crate::db::upsert_share_grant(
            &conn, &token, owner, Some(grantee), None, crate::db::ShareTier::Clone, None, &now,
        )
        .expect("grant");
        assert_eq!(crate::db::count_object_grants(&conn, "chart", &token).expect("count"), 1);
        assert_eq!(crate::db::list_object_grants(&conn, "chart", &token).expect("list").len(), 1);

        // A stranger cannot revoke the owner's grant.
        assert!(!crate::db::revoke_object_grant(&conn, grant_id, stranger).expect("revoke"));
        assert_eq!(crate::db::count_object_grants(&conn, "chart", &token).expect("count"), 1);

        // The owner can, and the grantee's tier is gone on the next check.
        assert!(crate::db::revoke_object_grant(&conn, grant_id, owner).expect("revoke"));
        let row = crate::db::get_share_link(&conn, &token).expect("query").expect("row");
        assert_eq!(crate::db::effective_share_tier(&conn, &row, Some(grantee)).expect("tier"), None);
        assert_eq!(crate::db::list_object_grants(&conn, "chart", &token).expect("list").len(), 0);
    }

    /// `update_share_policy`'s DB write (`db::update_share_link_policy`):
    /// owner OK, non-owner refused, and each field is independently
    /// optional.
    #[test]
    fn update_share_link_policy_owner_only_and_fields_are_independent() {
        let conn = strip_test_conn();
        let owner = insert_user(&conn, "owner");
        let stranger = insert_user(&conn, "stranger");
        let now = chrono::Utc::now().to_rfc3339();
        let token = crate::db::create_share_link(
            &conn, owner, "live", "t", "{}", 0, &now, &future_ts(), false, "view", "[]", "public", None,
        )
        .expect("create share");

        // A stranger's update is refused entirely.
        assert!(!crate::db::update_share_link_policy(
            &conn, &token, stranger, Some("interactive"), None, None, None, None, None,
        )
        .expect("update"));
        let row = crate::db::get_share_link(&conn, &token).expect("query").expect("row");
        assert_eq!(row.interaction, "view");

        // The owner can update just `interaction`, leaving `visibility` and
        // `protected_json` untouched.
        assert!(crate::db::update_share_link_policy(
            &conn, &token, owner, Some("interactive"), None, None, None, None, None,
        )
        .expect("update"));
        let row = crate::db::get_share_link(&conn, &token).expect("query").expect("row");
        assert_eq!(row.interaction, "interactive");
        assert_eq!(row.visibility, "public");
        assert_eq!(row.protected_json, "[]");

        // …and `visibility`/`protected` independently of `interaction`.
        assert!(crate::db::update_share_link_policy(
            &conn, &token, owner, None, Some("private"), Some(r#"[{"kind":"primitive","id":"1"}]"#), None, None, None,
        )
        .expect("update"));
        let row = crate::db::get_share_link(&conn, &token).expect("query").expect("row");
        assert_eq!(row.interaction, "interactive");
        assert_eq!(row.visibility, "private");
        assert_eq!(row.protected_json, r#"[{"kind":"primitive","id":"1"}]"#);
    }

    // ---- Rev 3: allow_forward — defaults, explicit set, PATCH, ownership ----
    // (docs/mlc/plans/share-policy-2026-09-25.md "Rev 3")

    /// Defaults per `visibility` when `allow_forward` is never set explicitly
    /// at create time, PLUS an explicit value at create time pinning
    /// regardless of `visibility` (owner instruction: "default `true` for
    /// public links, `false` for private ones, unless the create body sets
    /// it explicitly").
    #[test]
    fn create_share_link_allow_forward_defaults_per_visibility_unless_explicit() {
        let conn = strip_test_conn();
        let owner = insert_user(&conn, "owner");
        let now = chrono::Utc::now().to_rfc3339();

        // Unset (`None`) on a public link — follows the public default: true.
        let public_unset = crate::db::create_share_link(
            &conn, owner, "live", "t", "{}", 0, &now, &future_ts(), false, "view", "[]", "public", None,
        )
        .expect("create share");
        let row = crate::db::get_share_link(&conn, &public_unset).expect("query").expect("row");
        assert_eq!(row.allow_forward, None, "never set explicitly");
        assert!(row.effective_allow_forward());

        // Unset on a private link — follows the private default: false.
        let private_unset = crate::db::create_share_link(
            &conn, owner, "live", "t", "{}", 0, &now, &future_ts(), false, "view", "[]", "private", None,
        )
        .expect("create share");
        let row = crate::db::get_share_link(&conn, &private_unset).expect("query").expect("row");
        assert_eq!(row.allow_forward, None);
        assert!(!row.effective_allow_forward());

        // Explicit `Some(false)` on a public link overrides the public
        // default of `true`.
        let public_explicit_off = crate::db::create_share_link(
            &conn, owner, "live", "t", "{}", 0, &now, &future_ts(), false, "view", "[]", "public", Some(false),
        )
        .expect("create share");
        let row = crate::db::get_share_link(&conn, &public_explicit_off).expect("query").expect("row");
        assert_eq!(row.allow_forward, Some(false));
        assert!(!row.effective_allow_forward());

        // Explicit `Some(true)` on a private link overrides the private
        // default of `false`.
        let private_explicit_on = crate::db::create_share_link(
            &conn, owner, "live", "t", "{}", 0, &now, &future_ts(), false, "view", "[]", "private", Some(true),
        )
        .expect("create share");
        let row = crate::db::get_share_link(&conn, &private_explicit_on).expect("query").expect("row");
        assert_eq!(row.allow_forward, Some(true));
        assert!(row.effective_allow_forward());
    }

    /// `PATCH`'s DB write can set `allow_forward` explicitly, owner-only —
    /// same "someone else's token" refusal (mapped to a bare 404 by
    /// `update_share_policy`, unchanged for this new field) already proven
    /// for `interaction`/`visibility`/`protected` above.
    #[test]
    fn update_share_link_policy_allow_forward_owner_only_and_explicit() {
        let conn = strip_test_conn();
        let owner = insert_user(&conn, "owner");
        let stranger = insert_user(&conn, "stranger");
        let now = chrono::Utc::now().to_rfc3339();
        let token = crate::db::create_share_link(
            &conn, owner, "live", "t", "{}", 0, &now, &future_ts(), false, "view", "[]", "public", None,
        )
        .expect("create share");

        // A stranger's attempt is refused entirely — the row is untouched,
        // same 404-opacity discipline as every other field this route can
        // set.
        assert!(!crate::db::update_share_link_policy(
            &conn, &token, stranger, None, None, None, Some(false), None, None,
        )
        .expect("update"));
        let row = crate::db::get_share_link(&conn, &token).expect("query").expect("row");
        assert_eq!(row.allow_forward, None);

        // The owner pins it explicitly.
        assert!(crate::db::update_share_link_policy(
            &conn, &token, owner, None, None, None, Some(false), None, None,
        )
        .expect("update"));
        let row = crate::db::get_share_link(&conn, &token).expect("query").expect("row");
        assert_eq!(row.allow_forward, Some(false));
        assert!(!row.effective_allow_forward());
    }

    /// The load-bearing Rev 3 rule: changing `visibility` through `PATCH`
    /// alone (passing `allow_forward: None`, i.e. "not sent this call") never
    /// flips an ALREADY-explicit `allow_forward`, but DOES move the
    /// EFFECTIVE default for a link where it was never set.
    #[test]
    fn update_share_link_policy_visibility_change_never_flips_an_explicit_allow_forward() {
        let conn = strip_test_conn();
        let owner = insert_user(&conn, "owner");
        let now = chrono::Utc::now().to_rfc3339();

        // Link A: allow_forward pinned explicitly to `false` on a PUBLIC
        // link (fighting its own default of `true`).
        let token_a = crate::db::create_share_link(
            &conn, owner, "live", "t", "{}", 0, &now, &future_ts(), false, "view", "[]", "public", Some(false),
        )
        .expect("create share");
        // Flip visibility to private WITHOUT touching allow_forward.
        assert!(crate::db::update_share_link_policy(
            &conn, &token_a, owner, None, Some("private"), None, None, None, None,
        )
        .expect("update"));
        let row_a = crate::db::get_share_link(&conn, &token_a).expect("query").expect("row");
        assert_eq!(row_a.visibility, "private");
        assert_eq!(
            row_a.allow_forward,
            Some(false),
            "an explicit value must survive a visibility-only PATCH untouched"
        );
        assert!(!row_a.effective_allow_forward());

        // Link B: allow_forward NEVER set explicitly on a PUBLIC link (true
        // by default). Flip visibility to private, again without touching
        // allow_forward.
        let token_b = crate::db::create_share_link(
            &conn, owner, "live", "t", "{}", 0, &now, &future_ts(), false, "view", "[]", "public", None,
        )
        .expect("create share");
        let row_b = crate::db::get_share_link(&conn, &token_b).expect("query").expect("row");
        assert!(row_b.effective_allow_forward(), "public default, before the PATCH");
        assert!(crate::db::update_share_link_policy(
            &conn, &token_b, owner, None, Some("private"), None, None, None, None,
        )
        .expect("update"));
        let row_b = crate::db::get_share_link(&conn, &token_b).expect("query").expect("row");
        assert_eq!(row_b.visibility, "private");
        assert_eq!(
            row_b.allow_forward, None,
            "still never set explicitly — the PATCH must not have written it"
        );
        assert!(
            !row_b.effective_allow_forward(),
            "an unset link follows its NEW visibility's default, not its old one"
        );
    }

    // ---- §9: preview image validation + OG-tag injection ----

    /// A minimal, valid PNG of `w`×`h` — flat colour, no ancillary chunks —
    /// built with the SAME `image` crate the production code decodes with,
    /// so these tests exercise the real encode/decode round trip rather than
    /// a hand-rolled fixture format.
    fn make_test_png(w: u32, h: u32) -> Vec<u8> {
        let img = image::RgbaImage::from_pixel(w, h, image::Rgba([200, 30, 30, 255]));
        let mut out = Vec::new();
        image::DynamicImage::ImageRgba8(img)
            .write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
            .expect("encode test png");
        out
    }

    /// Standard IEEE CRC32 (the PNG chunk checksum algorithm) — used only to
    /// hand-build a `tEXt` chunk for
    /// `build_preview_png_strips_a_text_chunk` below; no production code
    /// needs a CRC32 of its own (the `image`/`png` crates compute their own
    /// internally).
    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &b in bytes {
            crc ^= b as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
            }
        }
        !crc
    }

    /// Splice a `tEXt` chunk (keyword `"Comment"`) into a valid PNG's byte
    /// stream, immediately after its IHDR chunk — the first chunk after the
    /// 8-byte signature, located generically by reading IHDR's own length
    /// field rather than assuming a fixed offset.
    fn png_with_text_chunk(png: &[u8]) -> Vec<u8> {
        let ihdr_len = u32::from_be_bytes(png[8..12].try_into().expect("4 bytes"));
        // 8 (signature) + 4 (this chunk's own length field) + 4 (chunk type
        // "IHDR") + ihdr_len (data) + 4 (crc).
        let ihdr_end = 8 + 4 + 4 + ihdr_len as usize + 4;
        let mut chunk_body = b"tEXt".to_vec();
        chunk_body.extend_from_slice(b"Comment\0hello world");
        let data_len = (chunk_body.len() - 4) as u32;
        let crc = crc32(&chunk_body);

        let mut out = Vec::with_capacity(png.len() + 8 + chunk_body.len());
        out.extend_from_slice(&png[..ihdr_end]);
        out.extend_from_slice(&data_len.to_be_bytes());
        out.extend_from_slice(&chunk_body);
        out.extend_from_slice(&crc.to_be_bytes());
        out.extend_from_slice(&png[ihdr_end..]);
        out
    }

    #[test]
    fn build_preview_png_rejects_oversized_upload() {
        let oversized = vec![0u8; PREVIEW_MAX_BYTES + 1];
        assert_eq!(build_preview_png(&oversized), Err(PreviewError::TooLarge));
    }

    #[test]
    fn build_preview_png_rejects_a_non_png_payload() {
        let not_png = b"this is not a png file at all, just plain text bytes".to_vec();
        assert_eq!(build_preview_png(&not_png), Err(PreviewError::NotPng));
    }

    #[test]
    fn build_preview_png_rejects_dimensions_over_the_decode_cap() {
        let huge = make_test_png(PREVIEW_MAX_DIM + 1, 10);
        assert_eq!(build_preview_png(&huge), Err(PreviewError::DimensionsOutOfBounds));
    }

    #[test]
    fn build_preview_png_reencodes_a_valid_upload_keeping_its_aspect() {
        let src = make_test_png(400, 300);
        let out = build_preview_png(&src).expect("valid upload re-encodes");
        let decoded = image::load_from_memory_with_format(&out, image::ImageFormat::Png)
            .expect("re-encoded output must itself be a valid PNG");
        assert_eq!(decoded.width(), 400);
        assert_eq!(decoded.height(), 300);
    }

    /// A PNG carrying a `tEXt` ancillary chunk is re-encoded WITHOUT it —
    /// the whole point of never re-serializing anything but the decoded
    /// pixel buffer.
    #[test]
    fn build_preview_png_strips_a_text_chunk() {
        let src = make_test_png(100, 60);
        let with_text = png_with_text_chunk(&src);
        assert!(
            with_text.windows(4).any(|w| w == b"tEXt"),
            "fixture must actually carry a tEXt chunk"
        );

        let out = build_preview_png(&with_text).expect("valid upload re-encodes");
        assert!(
            !out.windows(4).any(|w| w == b"tEXt"),
            "re-encoded output must carry no tEXt chunk"
        );
    }

    /// `get_share_preview`'s "never serve a private share's preview" rule,
    /// factored into [`share_preview_rel_path`] for direct testing —
    /// unconditional on file presence: a private row with a real
    /// `preview_path` still resolves to `None`.
    #[test]
    fn share_preview_rel_path_never_visible_for_a_private_share() {
        let conn = strip_test_conn();
        let owner = insert_user(&conn, "owner");
        let now = chrono::Utc::now().to_rfc3339();
        let token = crate::db::create_share_link(
            &conn, owner, "live", "t", "{}", 0, &now, &future_ts(), false, "view", "[]", "private", None,
        )
        .expect("create share");
        assert!(crate::db::set_share_preview_path(&conn, &token, owner, "1/abc-preview.png").expect("set path"));
        let row = crate::db::get_share_link(&conn, &token).expect("query").expect("row");

        assert_eq!(share_preview_rel_path(&row), None);
    }

    #[test]
    fn share_preview_rel_path_visible_for_a_public_share_with_a_preview() {
        let conn = strip_test_conn();
        let owner = insert_user(&conn, "owner");
        let now = chrono::Utc::now().to_rfc3339();
        let token = crate::db::create_share_link(
            &conn, owner, "live", "t", "{}", 0, &now, &future_ts(), false, "view", "[]", "public", None,
        )
        .expect("create share");
        crate::db::set_share_preview_path(&conn, &token, owner, "1/abc-preview.png").expect("set path");
        let row = crate::db::get_share_link(&conn, &token).expect("query").expect("row");

        assert_eq!(share_preview_rel_path(&row), Some("1/abc-preview.png"));
    }

    /// Public links keep the product title. The description carries the
    /// nick and the chart name. The image is set only when a preview exists.
    /// Private links stay the neutral title with no image and no chart name.
    #[test]
    fn og_tags_for_share_selection_matrix() {
        let base = crate::db::ShareLinkRow {
            token: "tok".to_string(),
            user_id: 1,
            kind: "live".to_string(),
            title: String::new(),
            preset_json: "{}".to_string(),
            blob_path: String::new(),
            blob_bytes: 0,
            created_at: String::new(),
            expires_at: String::new(),
            clone_allowed: false,
            interaction: "view".to_string(),
            protected_json: "[]".to_string(),
            visibility: "public".to_string(),
            preview_path: String::new(),
            allow_forward: None,
            pinned: false,
            chart_id: String::new(),
            revision: 1,
            op_seq: 0,
            live: false,
        };

        let tags = og_tags_for_share(&base, "");
        assert_eq!(tags.title, None);
        assert_eq!(tags.description, None);
        assert_eq!(tags.image_url, None);

        let with_title = crate::db::ShareLinkRow { title: "My BTC setup".to_string(), ..clone_row(&base) };
        let tags = og_tags_for_share(&with_title, "admin");
        assert_eq!(tags.title, None);
        assert_eq!(tags.description.as_deref(), Some("admin - My BTC setup"));
        assert_eq!(tags.image_url, None);

        let with_preview = crate::db::ShareLinkRow {
            preview_path: "1/tok-preview.png".to_string(),
            ..clone_row(&with_title)
        };
        let tags = og_tags_for_share(&with_preview, "admin");
        assert_eq!(tags.title, None);
        assert_eq!(
            tags.image_url.as_deref(),
            Some("https://mylittlechart.org/api/share/tok/preview.png?v=1")
        );

        let private = crate::db::ShareLinkRow { visibility: "private".to_string(), ..clone_row(&with_preview) };
        let tags = og_tags_for_share(&private, "admin");
        assert_eq!(tags.title, Some(PRIVATE_SHARE_OG_TITLE.to_string()));
        assert_eq!(tags.description, None);
        assert_eq!(
            tags.image_url.as_deref(),
            Some("https://mylittlechart.org/api/share/private-card.png")
        );
    }

    #[test]
    fn compose_share_card_keeps_the_brand_and_fills_the_frame() {
        let src = image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
            80,
            40,
            image::Rgba([200, 30, 30, 255]),
        ));
        let card = compose_share_card(&src);
        assert_eq!((card.width(), card.height()), (PREVIEW_OUTPUT_WIDTH, PREVIEW_OUTPUT_HEIGHT));
        assert_eq!(card.get_pixel(120, 300), card_template().get_pixel(120, 300));
        // The sample chart is gone. The gap above a wide image is the card background.
        let gap = card.get_pixel(SHOT_X + SHOT_W / 2, SHOT_Y + 8);
        assert_eq!(gap.0, CARD_BG, "sample chart still shows above the frame: {gap:?}");
        let shot = card.get_pixel(SHOT_X + SHOT_W / 2, SHOT_Y + SHOT_H / 2);
        assert!(shot[0] > 150 && shot[1] < 80, "frame pixel {shot:?} is not the chart");
    }

    /// `ShareLinkRow` carries no `Clone` derive in production (nothing else
    /// needs it) — this test-only helper builds a copy field by field so the
    /// selection-matrix test above can vary one field at a time without
    /// hand-repeating every other field on each fixture.
    fn clone_row(row: &crate::db::ShareLinkRow) -> crate::db::ShareLinkRow {
        crate::db::ShareLinkRow {
            token: row.token.clone(),
            user_id: row.user_id,
            kind: row.kind.clone(),
            title: row.title.clone(),
            preset_json: row.preset_json.clone(),
            blob_path: row.blob_path.clone(),
            blob_bytes: row.blob_bytes,
            created_at: row.created_at.clone(),
            expires_at: row.expires_at.clone(),
            clone_allowed: row.clone_allowed,
            interaction: row.interaction.clone(),
            protected_json: row.protected_json.clone(),
            visibility: row.visibility.clone(),
            preview_path: row.preview_path.clone(),
            allow_forward: row.allow_forward,
            pinned: row.pinned,
            chart_id: row.chart_id.clone(),
            revision: row.revision,
            op_seq: row.op_seq,
            live: row.live,
        }
    }

    const SAMPLE_INDEX_HTML: &str = concat!(
        "<!DOCTYPE html><html><head>",
        "<title>mylittlechart</title>",
        "<meta property=\"og:type\" content=\"website\" />",
        "<meta property=\"og:title\" content=\"mylittlechart — the terminal\" />",
        "<meta property=\"og:description\" content=\"Windows · macOS · Linux · Browser\" />",
        "<meta property=\"og:image\" content=\"https://mylittlechart.org/og-card.png\" />",
        "<meta name=\"twitter:card\" content=\"summary_large_image\" />",
        "<meta name=\"twitter:title\" content=\"mylittlechart — the terminal\" />",
        "<meta name=\"twitter:description\" content=\"Windows · macOS · Linux · Browser\" />",
        "<meta name=\"twitter:image\" content=\"https://mylittlechart.org/og-card.png\" />",
        "</head><body></body></html>",
    );

    #[test]
    fn inject_og_tags_overrides_title_and_image_when_both_present() {
        let tags = OgTags {
            title: Some("My BTC setup".to_string()),
            description: None,
            image_url: Some("https://mylittlechart.org/api/share/tok/preview.png".to_string()),
        };
        let out = inject_og_tags(SAMPLE_INDEX_HTML, &tags);

        assert!(out.contains(r#"property="og:title" content="My BTC setup""#));
        assert!(out.contains(r#"name="twitter:title" content="My BTC setup""#));
        assert!(out.contains(
            r#"property="og:image" content="https://mylittlechart.org/api/share/tok/preview.png""#
        ));
        assert!(out.contains(
            r#"name="twitter:image" content="https://mylittlechart.org/api/share/tok/preview.png""#
        ));
        // Untouched tags survive verbatim.
        assert!(out.contains(r#"og:description" content="Windows · macOS · Linux · Browser""#));
        assert!(out.contains("<title>mylittlechart</title>"));
        assert!(!out.contains("mylittlechart — the terminal"));
    }

    /// The private-card case: title overridden, image tags left at the
    /// app's own default (no `image_url` in `tags`) — proves the "no
    /// og:image, app default logo only" rule.
    #[test]
    fn inject_og_tags_leaves_image_untouched_when_none_provided() {
        let tags = OgTags {
            title: Some(PRIVATE_SHARE_OG_TITLE.to_string()),
            description: None,
            image_url: None,
        };
        let out = inject_og_tags(SAMPLE_INDEX_HTML, &tags);

        assert!(out.contains(&format!(r#"property="og:title" content="{PRIVATE_SHARE_OG_TITLE}""#)));
        assert!(out.contains(r#"property="og:image" content="https://mylittlechart.org/og-card.png""#));
        assert!(out.contains(r#"name="twitter:image" content="https://mylittlechart.org/og-card.png""#));
    }

    #[test]
    fn inject_og_tags_sets_the_shared_line_and_keeps_the_product_title() {
        let tags = OgTags {
            title: None,
            description: Some("admin - My BTC setup".to_string()),
            image_url: Some("https://mylittlechart.org/api/share/tok/preview.png".to_string()),
        };
        let out = inject_og_tags(SAMPLE_INDEX_HTML, &tags);
        assert!(out.contains(r#"property="og:title" content="mylittlechart — the terminal""#));
        assert!(out.contains(r#"property="og:description" content="admin - My BTC setup""#));
        assert!(out.contains(r#"name="twitter:description" content="admin - My BTC setup""#));
    }

    /// No tags at all → byte-identical output.
    #[test]
    fn inject_og_tags_is_a_no_op_with_no_overrides() {
        let tags = OgTags { title: None, description: None, image_url: None };
        assert_eq!(inject_og_tags(SAMPLE_INDEX_HTML, &tags), SAMPLE_INDEX_HTML);
    }

    /// A hostile title never breaks out of the `content="…"` attribute —
    /// the escaped output contains no raw `<script>` tag.
    #[test]
    fn inject_og_tags_escapes_a_nasty_title() {
        let nasty = "\"><script>alert(1)</script>";
        let tags = OgTags { title: Some(nasty.to_string()), description: None, image_url: None };
        let out = inject_og_tags(SAMPLE_INDEX_HTML, &tags);

        assert!(!out.contains("<script>"), "raw script tag must never appear: {out}");
        assert!(out.contains("&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"));
    }
}

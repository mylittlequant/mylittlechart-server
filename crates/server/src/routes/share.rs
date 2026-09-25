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
    extract::{Multipart, Path, State},
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
        Ok(entitlements::share_create_allowed(kind, current, is_paid))
    })
    .await;

    match result {
        Ok(Ok(true)) => Ok(()),
        Ok(Ok(false)) => Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse::new(
                "share limit reached: revoke an existing share or upgrade the account",
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

/// Request body for POST /api/share/live.
#[derive(serde::Deserialize)]
pub struct CreateLiveShareRequest {
    #[serde(default)]
    pub title: String,
    pub preset: serde_json::Value,
    /// Rights v1 (plan §2): opt this link into the `clone` right. Default
    /// `false` — unchanged behaviour for every caller that doesn't send it.
    #[serde(default)]
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

    if let Err(resp) = check_share_entitlement(state.clone(), user_id, ShareKind::Live).await {
        return resp;
    }

    let title = match clean_optional_user_text(&body.title, MAX_TITLE_CHARS) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let clone_allowed = body.clone_allowed;
    let interaction = body.interaction.as_str();
    let visibility = body.visibility.as_str();
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
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<(String, String)> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let is_paid = crate::db::user_is_paid(&conn, user_id)?;
        let now = chrono::Utc::now();
        let created_at = now.to_rfc3339();
        let expires_at = (now
            + chrono::Duration::seconds(entitlements::share_ttl_secs(ShareKind::Live, is_paid) as i64))
            .to_rfc3339();
        let token = crate::db::create_share_link(
            &conn,
            user_id,
            ShareKind::Live.as_str(),
            &title,
            &preset_json,
            0,
            &created_at,
            &expires_at,
            clone_allowed,
            interaction,
            &protected_json,
            visibility,
        )?;
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
            // construction, §0).
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
) -> Result<Option<(crate::db::ShareLinkRow, String, Option<crate::db::ShareTier>)>, Response> {
    let result = tokio::task::spawn_blocking(
        move || -> rusqlite::Result<Option<(crate::db::ShareLinkRow, String, Option<crate::db::ShareTier>)>> {
            let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            let row = crate::db::get_share_link(&conn, &token)?;
            match row {
                Some(row) => {
                    let owner = crate::db::share_owner_label(&conn, row.user_id)?
                        .unwrap_or_default();
                    let tier = crate::db::effective_share_tier(&conn, &row, caller)?;
                    Ok(Some((row, owner, tier)))
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
fn rights_for_tier(tier: crate::db::ShareTier, is_owner: bool) -> Vec<&'static str> {
    let mut rights = vec!["read"];
    if tier >= crate::db::ShareTier::Clone {
        rights.push("clone");
    }
    if is_owner {
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
/// URL of the PNG endpoint.
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

    let (row, owner, tier) = match fetch_public_share_with_tier(state, token, caller).await {
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
    let is_owner = caller == Some(row.user_id);
    let rights = rights_for_tier(tier, is_owner);
    let clone_protected = tier == crate::db::ShareTier::CloneProtected;

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
// POST /api/share/{token}/grants
// ============================================================================

/// Request body for POST /api/share/{token}/grants. A minimal, id-based
/// shape: exactly one of `grantee_user_id`/`grantee_group_id` must be set.
/// The sharer-facing nick/group-name lookup plan §8.2 describes
/// (`GrantRequest`/`GrantTarget::{Nick,Group}`) is deferred to whoever wires
/// a client for this route — this is the write path `db::upsert_share_grant`
/// / `db::effective_share_tier` need to exist and be reachable from
/// production code, not the full grant-management UI surface (§8.2's GET/DELETE
/// listing routes and §8.3's group-CRUD routes are likewise out of this wave).
#[derive(serde::Deserialize)]
pub struct CreateShareGrantRequest {
    pub grantee_user_id: Option<i64>,
    pub grantee_group_id: Option<i64>,
    /// "view" | "interactive" | "clone" | "clone_protected" — see `db::ShareTier`.
    pub tier: String,
    pub expires_at: Option<String>,
}

/// POST /api/share/{token}/grants
///
/// Owner-only (§8.2). Unknown token AND a non-owner caller both answer the
/// same bare 404 (same "someone else's token" discipline as `delete_share`).
/// Writes straight into `object_grants` via `db::upsert_share_grant` — the
/// per-account/group layer `db::effective_share_tier` reads fresh on every
/// subsequent `GET`/clone (§1).
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

    if body.grantee_user_id.is_some() == body.grantee_group_id.is_some() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "grant must target exactly one of grantee_user_id or grantee_group_id",
            )),
        )
            .into_response();
    }
    let Some(tier) = crate::db::ShareTier::from_str(&body.tier) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("invalid tier")),
        )
            .into_response();
    };

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<i64>> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let row = match crate::db::get_share_link(&conn, &token)? {
            Some(row) => row,
            None => return Ok(None),
        };
        if row.user_id != user_id {
            return Ok(None);
        }
        let now = chrono::Utc::now().to_rfc3339();
        let id = crate::db::upsert_share_grant(
            &conn,
            &row.token,
            user_id,
            body.grantee_user_id,
            body.grantee_group_id,
            tier,
            body.expires_at.as_deref(),
            &now,
        )?;
        Ok(Some(id))
    })
    .await;

    match result {
        Ok(Ok(Some(id))) => Json(serde_json::json!({ "grant_id": id })).into_response(),
        Ok(Ok(None)) => share_not_found(),
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
        assert!(!parsed.clone_allowed);
        assert_eq!(parsed.interaction, ShareInteraction::View);
        assert!(parsed.protected.is_empty());
    }

    /// The current, full-shape request round-trips every field, including a
    /// non-default interaction and a non-empty protected list.
    #[test]
    fn create_live_share_request_parses_the_full_rev2_shape() {
        let body = serde_json::json!({
            "title": "new client",
            "preset": {},
            "clone_allowed": true,
            "interaction": "interactive",
            "protected": [{ "kind": "primitive", "id": "42" }],
        });
        let parsed: CreateLiveShareRequest =
            serde_json::from_value(body).expect("full-shape request must parse");
        assert!(parsed.clone_allowed);
        assert_eq!(parsed.interaction, ShareInteraction::Interactive);
        assert_eq!(parsed.protected.len(), 1);
        assert_eq!(parsed.protected[0].kind, "primitive");
        assert_eq!(parsed.protected[0].id, "42");
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
                preview_path TEXT NOT NULL DEFAULT ''
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
}

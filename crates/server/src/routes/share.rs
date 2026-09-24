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
            // always false here, and interaction/protected stay at their
            // "view"/"[]" defaults — no request field offers to set any of
            // them (a screenshot is pure view-only by construction, §0).
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

/// GET /api/share/{token}
///
/// PUBLIC — the token is the capability, no session and no build attestation.
/// The bearer/session, if any, is OPTIONAL (`resolve_caller_optional`): an
/// anonymous caller still gets the full response, unchanged from before
/// rights v1, plus a `"rights"` array (`db::effective_rights`) reporting what
/// it may do with the token — `["read"]` for an anonymous or non-owner
/// caller without `clone_allowed`, `["read","clone"]` when the link opted in,
/// `["read","clone","edit"]` for the owner. Live shares answer the frozen
/// preset; screenshot shares answer the URL of the PNG endpoint. Unknown,
/// expired, and revoked tokens all get the same bare 404.
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

    let (row, owner, rights) = match fetch_public_share(state, token, caller).await {
        Ok(Some(found)) => found,
        Ok(None) => return share_not_found(),
        Err(resp) => return resp,
    };

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
/// `{type_id, name}`. Every other part of `preset` (windows, bubbles,
/// layout, alerts, primitives, …) is carried through unchanged — only the
/// `indicators` array is filtered.
///
/// Extracted out of [`clone_share`]'s own inline loop
/// (docs/mlc/plans/shared-presets-rights-and-live-sync-2026-09-23.md §5) so
/// `routes::rooms`'s own clone route can run the exact same strip rule over
/// a room's reassembled preset — one strip implementation, not two that
/// could drift apart.
pub(crate) fn clone_preset_with_strip(
    conn: &rusqlite::Connection,
    mut preset: serde_json::Value,
    recipient: i64,
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
                stripped.push(serde_json::json!({ "type_id": type_id, "name": name }));
            } else {
                kept.push(entry);
            }
        }
        *indicators = kept;
    }
    Ok((preset, stripped))
}

/// POST /api/share/{token}/clone
///
/// Auth required (see `resolve_user_id`). Requires `clone` in the caller's
/// effective rights (`db::effective_rights`) — 403 otherwise. Only a `live`
/// share carries a preset to clone; a `screenshot` token answers 400.
/// Unknown, expired, and revoked tokens answer the same bare 404 as
/// `GET /api/share/{token}`.
///
/// Walks `preset.indicators[*].type_id` (`IndicatorSnapshot`, mlc-core) and
/// drops any entry `db::indicator_should_strip` flags for the caller,
/// recording each as `{type_id, name}`. Every other part of the preset
/// (windows, bubbles, layout, alerts, …) is carried through unchanged — only
/// the `indicators` array is filtered. Answers:
/// ```json
/// { "preset": { …stripped preset… }, "stripped": [{"type_id": "…", "name": "…"}] }
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

        let rights = crate::db::effective_rights(&conn, &row, Some(user_id));
        if !rights.contains(&"clone") {
            return Ok(Some(CloneOutcome::Forbidden));
        }
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

        let (preset, stripped) = clone_preset_with_strip(&conn, preset, user_id)?;
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
}

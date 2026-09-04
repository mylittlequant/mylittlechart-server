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
//!  - `GET    /api/share/{token}`        — public share metadata + payload.
//!  - `GET    /api/share/{token}/png`    — public PNG blob stream.
//!  - `DELETE /api/share/{token}`        — revoke, owner-only (auth).
//!
//! Creation is authenticated (session cookie or Bearer, same as `/api/sync/*`)
//! and entitlement-gated (`entitlements::share_create_allowed`, counted via
//! `db::share_usage`). Reading is PUBLIC by design — the token is the
//! capability — and unknown, expired, and revoked tokens all answer the same
//! bare 404 so none of the three states is distinguishable from outside
//! (same posture as the static-file fallback in `main.rs`).

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

/// Maximum serialized size of a live share's ChartPreset JSON.
const MAX_PRESET_BYTES: usize = 256 * 1024;

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
}

/// POST /api/share/live
///
/// Freezes `preset` into a share row and answers:
/// ```json
/// { "token": "…", "url_path": "/?share=…", "expires_at": "<RFC3339>" }
/// ```
/// The preset must be a JSON object of at most [`MAX_PRESET_BYTES`] bytes
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
        Ok(s) if s.len() <= MAX_PRESET_BYTES => s,
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

    let title = body.title;
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
            let token = crate::db::create_share_link(
                &conn,
                user_id,
                ShareKind::Screenshot.as_str(),
                &title,
                "",
                blob_bytes,
                &created_at,
                &expires_at,
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

/// Fetch the live share row plus its owner label, or None. Shared by
/// `get_share` and `get_share_png`.
async fn fetch_public_share(
    state: Arc<AppState>,
    token: String,
) -> Result<Option<(crate::db::ShareLinkRow, String)>, Response> {
    let result = tokio::task::spawn_blocking(
        move || -> rusqlite::Result<Option<(crate::db::ShareLinkRow, String)>> {
            let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            let row = crate::db::get_share_link(&conn, &token)?;
            match row {
                Some(row) => {
                    // display_name with public_id fallback; a dedicated public
                    // nick column lands in a later wave.
                    let owner = crate::db::share_owner_label(&conn, row.user_id)?
                        .unwrap_or_default();
                    Ok(Some((row, owner)))
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
/// Live shares answer the frozen preset; screenshot shares answer the URL of
/// the PNG endpoint. Unknown, expired, and revoked tokens all get the same
/// bare 404.
pub async fn get_share(State(state): State<Arc<AppState>>, Path(token): Path<String>) -> Response {
    let (row, owner) = match fetch_public_share(state, token).await {
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
            Json(serde_json::json!({
                "kind": "live",
                "title": row.title,
                "owner": owner,
                "preset": preset,
                "created_at": row.created_at,
                "expires_at": row.expires_at,
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
    let (row, _owner) = match fetch_public_share(state, token).await {
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

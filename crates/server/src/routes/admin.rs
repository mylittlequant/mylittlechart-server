//! Admin endpoints — protected by ADMIN_SECRET bearer token. Includes
//! `GET /admin/users` (search, with each row's linked providers/email/
//! Telegram id) and `POST /admin/users/merge` (fold a duplicate account into
//! its survivor — see `merge_users`' own doc comment and `account_merge.rs`
//! for the full contract and per-table order), plus the reserved-nick
//! registry (owner ruling 2026-09-09: occupy the good handles now, hand
//! them to specific accounts later, rather than minting fake accounts to
//! sit on them):
//!  - `GET    /admin/nicks/reserved`             — every reserved-nick row,
//!                                                 sorted by category then
//!                                                 nick (`list_reserved_nicks`).
//!  - `PUT    /admin/nicks/reserved/{nick}`      — upsert a row's
//!                                                 category/note, never its
//!                                                 `granted_to`
//!                                                 (`upsert_reserved_nick`).
//!  - `DELETE /admin/nicks/reserved/{nick}`      — release a reservation
//!                                                 entirely (`delete_reserved_nick`).
//!  - `PUT    /admin/users/{user_id}/nick`       — assign a nick to an
//!                                                 account, bypassing the
//!                                                 self-service reserved-list
//!                                                 and cooldown gates
//!                                                 (`admin_set_user_nick`);
//!                                                 this is how a reservation
//!                                                 above is actually handed
//!                                                 to someone.
//!  - `POST   /admin/users/{user_id}/paid-days`  — extend an account's paid
//!                                                 access by N days directly
//!                                                 (`grant_paid_days`), for
//!                                                 operator accounts or a
//!                                                 support fix — a gift code
//!                                                 needs the redeeming
//!                                                 account's own session,
//!                                                 which this route does not
//!                                                 need.

use axum::{
    body::Bytes,
    extract::{ConnectInfo, Extension, Path, Query, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
    Json,
};
use std::net::SocketAddr;
use std::sync::Arc;
use subtle::ConstantTimeEq;

use crate::models::types::{
    ErrorResponse, PromoteQuery, PromoteResponse, RegisterReleaseRequest, RegisterReleaseResponse,
};
use crate::pathutil::is_safe_path_component;
use crate::state::AppState;

/// The one answer every admin route gives on ANY refusal — `ADMIN_SECRET`
/// unset at boot, a missing bearer, a malformed one, or a wrong one: exactly
/// what an unmatched path under `/api` gets from axum's own routing (see
/// `routes::control_api_router`, mounted via `.nest("/api", ...)` in
/// `main.rs` — a path that does not match anything registered there never
/// reaches the outer router's static-file fallback; it is answered by this
/// nested `Router`'s own built-in "no route matched" handler, which is
/// `StatusCode::NOT_FOUND` with an empty body and no extra headers). Mirrored
/// byte-for-byte here rather than re-derived so an operator scanning for the
/// admin surface — wrong secret, right secret, or no secret at all — cannot
/// tell any of those apart from a path that was never registered.
fn admin_not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

/// Verify ADMIN_SECRET from the Authorization header.
///
/// On any failure the caller gets [`admin_not_found`] — never a 401 or a 503
/// that would confirm an admin route exists at all. Every refusal is logged
/// server-side with the request path and peer address (never the presented
/// token, whether it's wrong or entirely absent).
///
/// The comparison itself is constant-time (`subtle::ConstantTimeEq`, already
/// a workspace dependency — no new one added for this).
///
/// `pub(crate)`: reused by `routes::posts`/`routes::forum`/
/// `routes::forum_v2`'s admin endpoints so the bearer check has exactly one
/// implementation, not a copy per module.
pub(crate) fn verify_admin_secret(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    peer: Option<SocketAddr>,
) -> Result<(), Response> {
    if state.admin_secret.is_empty() {
        tracing::warn!(
            path = %uri.path(),
            peer = ?peer,
            "admin route refused: ADMIN_SECRET is not configured"
        );
        return Err(admin_not_found());
    }

    let auth = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match auth {
        Some(token) if token.as_bytes().ct_eq(state.admin_secret.as_bytes()).into() => Ok(()),
        _ => {
            tracing::warn!(
                path = %uri.path(),
                peer = ?peer,
                "admin route refused: invalid or missing bearer"
            );
            Err(admin_not_found())
        }
    }
}

/// Unwrap the peer-address extractor into a plain `SocketAddr` for
/// `verify_admin_secret` — `None` when the listener was not served through
/// `into_make_service_with_connect_info` (see `main.rs`), which
/// `verify_admin_secret` treats as "peer unknown", not a reason to refuse.
///
/// Wrapped as `Option<Extension<ConnectInfo<SocketAddr>>>` rather than the
/// more obvious `Option<Extension<ConnectInfo<SocketAddr>>>`: `ConnectInfo` itself has
/// no `OptionalFromRequestParts` impl (only `Extension`, `MatchedPath`, and
/// `Path` do, as of axum 0.8), so the bare `Option<ConnectInfo<_>>` shape
/// fails to implement `FromRequestParts` at all. `ConnectInfo`'s own
/// (non-optional) extractor is itself implemented as an `Extension` lookup
/// under the hood, so reaching for `Extension` directly, wrapped in
/// `Option`, reads the exact same request-extensions slot without ever
/// panicking or 500ing when it is absent.
///
/// `pub(crate)`: every admin handler across `routes::posts`/`routes::forum`/
/// `routes::forum_v2` unwraps its own extractor through this, same reuse
/// reason as `verify_admin_secret` itself.
pub(crate) fn peer_addr(peer: Option<Extension<ConnectInfo<SocketAddr>>>) -> Option<SocketAddr> {
    peer.map(|Extension(ConnectInfo(addr))| addr)
}

/// POST /api/admin/restart
///
/// Triggers a graceful shutdown. The wrapper script will restart the process
/// with the newly built binary. Requires `Authorization: Bearer {ADMIN_SECRET}`.
pub async fn restart(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Response {
    if let Err(e) = verify_admin_secret(&state, &headers, &uri, peer_addr(peer)) {
        return e;
    }

    tracing::info!("Admin restart requested — initiating graceful shutdown");
    let _ = state.shutdown_tx.send(());

    Json(serde_json::json!({ "status": "restarting" })).into_response()
}

/// POST /api/admin/register-release
///
/// Metadata-only manifest registration. Requires
/// `Authorization: Bearer {ADMIN_SECRET}` header. The artifact bytes never
/// reach the control box: since the 2026-08-30 publish redesign,
/// `mlc-opsd` uploads and sha256-verifies the file on every public edge
/// before ever calling here — this endpoint's only job is to write the
/// manifest row (see `mlc-opsd`'s `POST /api/release/publish`, which is the
/// only intended caller). It replaces the old body-accepting
/// `POST /api/admin/upload`, which stored artifacts on the control box —
/// a box that stores nothing now that downloads redirect to the edges.
///
/// NOTE: the JSON body is parsed only AFTER the bearer check — same reason
/// the old upload route parsed its query string late: an unauthenticated
/// probe gets a bare 404 (see `verify_admin_secret`) and nothing about the
/// endpoint's shape.
pub async fn register_release(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Bytes,
) -> Response {
    if let Err(e) = verify_admin_secret(&state, &headers, &uri, peer_addr(peer)) {
        return e;
    }

    let req: RegisterReleaseRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("Invalid JSON body")),
            )
                .into_response();
        }
    };

    if req.platform.is_empty() || req.version.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("platform and version are required")),
        )
            .into_response();
    }
    if !is_safe_path_component(&req.platform) || !is_safe_path_component(&req.version) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Invalid platform or version format")),
        )
            .into_response();
    }
    if !is_safe_path_component(&req.filename) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Invalid filename format")),
        )
            .into_response();
    }
    if req.sha256.len() != 64 || !req.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("sha256 must be 64 hex characters")),
        )
            .into_response();
    }
    if req.file_size == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("file_size must be > 0")),
        )
            .into_response();
    }
    if req.release_notes.len() > 4096 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("release_notes too long (max 4096)")),
        )
            .into_response();
    }
    if req.signature.len() > 256 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("signature too long (max 256)")),
        )
            .into_response();
    }
    if req.channel != "stable" && req.channel != "dev" {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("channel must be 'stable' or 'dev'")),
        )
            .into_response();
    }

    let now = chrono::Utc::now().to_rfc3339();
    let platform = req.platform.clone();
    let version = req.version.clone();
    let channel = req.channel.clone();
    // `file_path` is the column name (unchanged schema) — the value stored
    // is now just the filename under the edges' static `/dl/` tree, never a
    // path, since the control box holds no filesystem copy to build a path
    // to. See `routes::updates::download_binary`, which reads it back that way.
    let file_path = req.filename.clone();
    let sha256 = req.sha256.clone();
    let release_notes = req.release_notes.clone();
    let signature = req.signature.clone();
    let file_size = req.file_size;

    let db_result = tokio::task::spawn_blocking(move || {
        // `releases` lives in the operational database (2026-08-30 store split).
        let conn = state.control_plane().ops_db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::upsert_release(
            &conn,
            &version,
            &platform,
            &channel,
            &sha256,
            &file_path,
            file_size as i64,
            &release_notes,
            &signature,
            &now,
        )
    })
    .await;

    match db_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::error!("DB error during release registration: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database insert failed")),
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

    tracing::info!(
        "Release registered: platform={} version={} channel={} filename={} size={} sha256={} signed={}",
        req.platform,
        req.version,
        req.channel,
        req.filename,
        req.file_size,
        req.sha256,
        !req.signature.is_empty(),
    );

    Json(RegisterReleaseResponse {
        status: "ok",
        platform: req.platform,
        version: req.version,
        channel: req.channel,
        filename: req.filename,
        sha256: req.sha256,
    })
    .into_response()
}

/// Request body for POST /api/admin/gift-codes.
#[derive(serde::Deserialize)]
pub struct MintGiftCodesRequest {
    /// Days of paid access each code grants, from the moment it is redeemed.
    pub days: i64,
    /// How many codes to mint in this call. Defaults to 1.
    #[serde(default = "default_gift_code_count")]
    pub count: u32,
    /// Why this batch was minted — support needs this, the redeeming
    /// account never sees it.
    #[serde(default)]
    pub note: String,
}

fn default_gift_code_count() -> u32 {
    1
}

/// Response for POST /api/admin/gift-codes.
#[derive(serde::Serialize)]
pub struct MintGiftCodesResponse {
    pub codes: Vec<String>,
}

/// A typo in `count` (an extra zero, say) should not be able to flood the
/// table in one call — this is the ceiling on a single mint request.
const MAX_GIFT_CODES_PER_REQUEST: u32 = 200;

/// POST /api/admin/gift-codes
///
/// Mints `count` (default 1) single-use gift/trial codes, each granting
/// `days` days of paid access from the moment an account redeems it (see
/// `db::mint_gift_codes`, `db::redeem_gift_code`, and
/// `routes::account::redeem` for the redemption side). Requires
/// `Authorization: Bearer {ADMIN_SECRET}`.
///
/// Response: `{ "codes": ["AB3D...", ...] }`. This is the only place a
/// minted code is ever returned — no read path anywhere exposes an existing
/// code (see `db::mint_gift_codes`'s doc comment), and this response is
/// never logged in full.
pub async fn mint_gift_codes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Bytes,
) -> Response {
    if let Err(e) = verify_admin_secret(&state, &headers, &uri, peer_addr(peer)) {
        return e;
    }

    let req: MintGiftCodesRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("Invalid JSON body")),
            )
                .into_response();
        }
    };

    if req.days <= 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("days must be > 0")),
        )
            .into_response();
    }
    if req.count == 0 || req.count > MAX_GIFT_CODES_PER_REQUEST {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(format!(
                "count must be between 1 and {}",
                MAX_GIFT_CODES_PER_REQUEST
            ))),
        )
            .into_response();
    }
    if req.note.len() > 512 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("note too long (max 512)")),
        )
            .into_response();
    }

    let now = chrono::Utc::now().to_rfc3339();
    let count = req.count;
    let days = req.days;
    let note = req.note.clone();

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::mint_gift_codes(&conn, count, days, &note, &now)
    })
    .await;

    match result {
        Ok(Ok(codes)) => {
            // Count and metadata only — never the codes themselves.
            tracing::info!(
                "Minted {} gift code(s): days={} note={:?}",
                codes.len(),
                days,
                req.note,
            );
            Json(MintGiftCodesResponse { codes }).into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("DB error minting gift codes: {}", e);
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

/// Request body for `POST /api/admin/users/{id}/paid-days`.
#[derive(serde::Deserialize)]
pub struct GrantPaidDaysRequest {
    pub days: i64,
}

/// Closed range [`GrantPaidDaysRequest::days`] must fall in — the lower
/// bound rules out a no-op/negative grant, the upper bound (10 years) rules
/// out a typo turning into an effectively permanent account.
const MIN_PAID_DAYS: i64 = 1;
const MAX_PAID_DAYS: i64 = 3650;

/// Whether `days` falls inside the closed `[MIN_PAID_DAYS, MAX_PAID_DAYS]`
/// range `grant_paid_days` accepts — split out of the handler so the bound
/// itself is unit-testable without a database.
fn paid_days_in_bounds(days: i64) -> bool {
    (MIN_PAID_DAYS..=MAX_PAID_DAYS).contains(&days)
}

/// POST /api/admin/users/{id}/paid-days
///
/// Extend `user_id`'s paid access by `days` days, from `max(now, existing
/// paid_until)` (`db::grant_paid_days`, the same extension rule a gift-code
/// redemption uses — see that function's doc comment). For operator
/// accounts or a support fix that need paid time granted directly: a gift
/// code (`POST /api/admin/gift-codes`) needs the redeeming account's own
/// session, which does not exist for an account being granted time
/// out-of-band. `days` must be in `[1, 3650]`. `404 {"error":"no such
/// user"}` for an unknown `user_id`. Requires `Authorization: Bearer
/// {ADMIN_SECRET}`.
///
/// Response: `{"user_id", "paid_until"}`.
pub async fn grant_paid_days(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(user_id): Path<i64>,
    body: Bytes,
) -> Response {
    if let Err(e) = verify_admin_secret(&state, &headers, &uri, peer_addr(peer)) {
        return e;
    }

    let req: GrantPaidDaysRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(ErrorResponse::new("Invalid JSON body"))).into_response();
        }
    };
    if !paid_days_in_bounds(req.days) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(format!(
                "days must be between {} and {}",
                MIN_PAID_DAYS, MAX_PAID_DAYS
            ))),
        )
            .into_response();
    }

    let days = req.days;
    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::grant_paid_days(&conn, user_id, days)
    })
    .await;

    match result {
        Ok(Ok(Some(paid_until))) => {
            tracing::info!(
                "Admin granted {} paid day(s) to user {} -> paid_until={}",
                days,
                user_id,
                paid_until,
            );
            Json(serde_json::json!({ "user_id": user_id, "paid_until": paid_until })).into_response()
        }
        Ok(Ok(None)) => (StatusCode::NOT_FOUND, Json(ErrorResponse::new("no such user"))).into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error granting paid days: {}", e);
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

/// POST /api/admin/promote?version=0.5.1&platform=win64
///
/// Copies a dev release to stable channel. Binary file is NOT duplicated on disk.
/// Requires `Authorization: Bearer {ADMIN_SECRET}`.
pub async fn promote(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Response {
    if let Err(e) = verify_admin_secret(&state, &headers, &uri, peer_addr(peer)) {
        return e;
    }

    // Same auth-before-parse rule as register_release above.
    let Query(query) = match Query::<PromoteQuery>::try_from_uri(&uri) {
        Ok(q) => q,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("Invalid query parameters")),
            )
                .into_response();
        }
    };

    if !is_safe_path_component(&query.platform) || !is_safe_path_component(&query.version) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Invalid platform or version format")),
        )
            .into_response();
    }

    let now = chrono::Utc::now().to_rfc3339();
    let version = query.version.clone();
    let platform = query.platform.clone();

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().ops_db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::promote_release(&conn, &version, &platform, &now)
    })
    .await;

    match result {
        Ok(Ok(true)) => {
            tracing::info!(
                "Promoted dev→stable: platform={} version={}",
                query.platform,
                query.version
            );
            Json(PromoteResponse {
                status: "ok",
                version: query.version,
                platform: query.platform,
            })
            .into_response()
        }
        Ok(Ok(false)) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(format!(
                "No dev release found for platform='{}' version='{}'",
                query.platform, query.version
            ))),
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error during promote: {}", e);
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

/// Query parameters for GET /api/admin/users.
#[derive(serde::Deserialize)]
pub struct AdminUsersQuery {
    pub q: Option<String>,
}

/// GET /api/admin/users?q=<text>
///
/// Case-insensitive substring search over an account's chosen nick and
/// display name (`db::search_users`, at most 50 rows, ordered by user id
/// ascending) — the read half of resolving a nick to the numeric id
/// `PUT /api/admin/forum/roles/{user_id}` requires; nothing on the API
/// resolves that today. `paid_until` rides along because it lives on the
/// same `users` row this query already reads. Each row also carries
/// `providers` (every linked provider name, deduplicated and sorted),
/// `has_email` (whether any linked identity captured a verified email —
/// docs/mlc/plans/identity-merge-2026-09-09.md decision 1),
/// `telegram_id` (the `provider_user_id` of the account's `telegram`
/// identity, if any — who the operator can reach through the Telegram
/// login bot), and `dormant` (has a linked provider but no activity in
/// any table — see `db::AdminUserRow::dormant`; this is what the merge
/// endpoint below is for). Requires `Authorization: Bearer {ADMIN_SECRET}`.
pub async fn list_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Response {
    if let Err(e) = verify_admin_secret(&state, &headers, &uri, peer_addr(peer)) {
        return e;
    }

    // Same auth-before-parse rule as register_release/promote above.
    let Query(query) = match Query::<AdminUsersQuery>::try_from_uri(&uri) {
        Ok(q) => q,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("Invalid query parameters")),
            )
                .into_response();
        }
    };

    let q = match query.q.as_deref().map(str::trim) {
        Some(q) if !q.is_empty() => q.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("q is required")),
            )
                .into_response();
        }
    };

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::search_users(&conn, &q)
    })
    .await;

    match result {
        Ok(Ok(users)) => Json(serde_json::json!({ "users": users })).into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error searching admin users: {}", e);
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

/// JSON body for `POST /api/admin/users/merge`.
#[derive(serde::Deserialize)]
pub struct MergeUsersRequest {
    pub from: i64,
    pub into: i64,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub keep_vault: Option<String>,
}

/// POST /api/admin/users/merge
///
/// Fold `from` into `into` — one person's several OAuth-identity accounts
/// becoming one (docs/mlc/plans/identity-merge-2026-09-09.md decisions 4-6;
/// implementation and exact per-table order in `account_merge.rs`). Body
/// `{"from": <id>, "into": <id>, "dry_run": bool, "keep_vault":
/// "into"|"from"|null}`. 400 when `from == into` or either names no
/// existing account; 409 `{"error":"hard conflicts","conflicts":[…]}` when a
/// `vault`/`recovery_key`/`salt` singleton or a `sync_e2e_params` row is held
/// by BOTH accounts for the same key, or both hold a `dm_identity_keys`
/// row — unless `keep_vault` names the survivor, in which case the loser's
/// conflicting rows are archived (not silently dropped) to
/// `<data_dir>/merge-archive/<from>-into-<into>-<ts>.json` before deletion.
/// `dry_run: true` returns the same summary shape a real merge would write
/// (row counts per table, conflicts, hot-plane files that would move or
/// collide) and writes nothing — `keep_vault` has no effect on a dry run.
/// The response body on success is the `MergeSummary` JSON itself, not
/// wrapped in another envelope. Requires `Authorization: Bearer
/// {ADMIN_SECRET}`.
///
/// Static, not `/admin/users/{id}` — coexists with the static `/admin/users`
/// above the same way `/admin/forum/roles/by-nick/{nick}` coexists with
/// `/admin/forum/roles/{user_id}` (see routes/mod.rs's registration comment
/// for this route).
pub async fn merge_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Bytes,
) -> Response {
    if let Err(e) = verify_admin_secret(&state, &headers, &uri, peer_addr(peer)) {
        return e;
    }

    let req: MergeUsersRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(ErrorResponse::new("Invalid JSON body"))).into_response();
        }
    };

    if req.from == req.into {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("from and into must be different user ids")),
        )
            .into_response();
    }

    let keep_vault = match req.keep_vault.as_deref() {
        None => None,
        Some(s) => match crate::account_merge::KeepVault::from_wire(s) {
            Some(k) => Some(k),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse::new("keep_vault must be \"into\" or \"from\"")),
                )
                    .into_response();
            }
        },
    };

    let from = req.from;
    let into = req.into;
    let dry_run = req.dry_run;

    let result = tokio::task::spawn_blocking(move || {
        let control = state.control_plane();
        if dry_run {
            crate::account_merge::plan(&control.db, &control.social, &control.sync_store, from, into)
        } else {
            crate::account_merge::execute(
                &control.db,
                &control.social,
                &control.sync_store,
                &control.data_dir,
                from,
                into,
                keep_vault,
            )
        }
    })
    .await;

    match result {
        Ok(Ok(summary)) => Json(summary).into_response(),
        Ok(Err(crate::account_merge::MergeError::SameUser)) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("from and into must be different user ids")),
        )
            .into_response(),
        Ok(Err(crate::account_merge::MergeError::UserNotFound { side, user_id })) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(format!("{side} user {user_id} does not exist"))),
        )
            .into_response(),
        Ok(Err(crate::account_merge::MergeError::Conflicts(conflicts))) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "hard conflicts", "conflicts": conflicts })),
        )
            .into_response(),
        Ok(Err(crate::account_merge::MergeError::Db(e))) => {
            tracing::error!("DB error in account merge: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Database error"))).into_response()
        }
        Ok(Err(crate::account_merge::MergeError::Io(e))) => {
            tracing::error!("IO error in account merge: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Filesystem error"))).into_response()
        }
        Ok(Err(crate::account_merge::MergeError::Serde(e))) => {
            tracing::error!("Serialization error in account merge: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Internal error"))).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Internal error"))).into_response(),
    }
}

// ============================================================================
// Reserved-nick registry (owner ruling 2026-09-09) — see this module's `//!`
// doc for the four routes below. `db::reserved_nicks` itself is seeded at
// boot from `crates/server/reserved_nicks.txt`; these routes are the only
// way to edit that registry, or an account's nick, past boot time.
// ============================================================================

/// GET /api/admin/nicks/reserved
///
/// Every row in the reserved-nick registry, sorted by category then nick
/// (`db::list_reserved_nicks`) — the read half an operator uses before
/// granting or releasing a handle. Requires `Authorization: Bearer
/// {ADMIN_SECRET}`.
pub async fn list_reserved_nicks(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Response {
    if let Err(e) = verify_admin_secret(&state, &headers, &uri, peer_addr(peer)) {
        return e;
    }

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::list_reserved_nicks(&conn)
    })
    .await;

    match result {
        Ok(Ok(rows)) => Json(serde_json::json!({ "reserved": rows })).into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error listing reserved nicks: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Database error"))).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Internal error"))).into_response(),
    }
}

/// JSON body for `PUT /api/admin/nicks/reserved/{nick}`.
#[derive(serde::Deserialize)]
pub struct UpsertReservedNickRequest {
    pub category: String,
    #[serde(default)]
    pub note: Option<String>,
}

/// PUT /api/admin/nicks/reserved/{nick}
///
/// Upsert `nick`'s `category`/`note` in the reserved-nick registry
/// (`db::upsert_reserved_nick`) — claiming a new handle for the project, or
/// reclassifying an existing one. Never touches `granted_to`: handing the
/// nick to an account is the separate `PUT /api/admin/users/{user_id}/nick`
/// route below. `400 {"error":...}` when `nick` fails the format check;
/// `200 {"nick","created":bool}` on success, where `created` is `false`
/// when the row already existed and only its category/note changed.
/// Requires `Authorization: Bearer {ADMIN_SECRET}`.
pub async fn upsert_reserved_nick(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(nick): Path<String>,
    body: Bytes,
) -> Response {
    if let Err(e) = verify_admin_secret(&state, &headers, &uri, peer_addr(peer)) {
        return e;
    }
    let req: UpsertReservedNickRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(ErrorResponse::new("Invalid JSON body"))).into_response();
        }
    };

    let nick_lower = nick.to_lowercase();
    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let outcome = crate::db::upsert_reserved_nick(&conn, &nick, &req.category, req.note.as_deref());
        if outcome.is_ok() {
            if let Err(e) = state.control_plane().refresh_reserved_nick_cache(&conn) {
                tracing::error!("failed to refresh the reserved-nick cache after upsert: {}", e);
            }
        }
        outcome
    })
    .await;

    match result {
        Ok(Ok(created)) => Json(serde_json::json!({ "nick": nick_lower, "created": created })).into_response(),
        Ok(Err(crate::db::ReservedNickError::Invalid)) => {
            (StatusCode::BAD_REQUEST, Json(ErrorResponse::new("Invalid nick format"))).into_response()
        }
        Ok(Err(crate::db::ReservedNickError::Db(e))) => {
            tracing::error!("DB error upserting reserved nick: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Database error"))).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Internal error"))).into_response(),
    }
}

/// DELETE /api/admin/nicks/reserved/{nick}
///
/// Remove `nick` from the reserved-nick registry entirely, `granted_to`
/// included (`db::delete_reserved_nick`) — releasing a name for good, not
/// the same operation as moving an account off it while it stays reserved
/// for someone else. `204` on success, `404` if `nick` was not reserved.
/// Requires `Authorization: Bearer {ADMIN_SECRET}`.
pub async fn delete_reserved_nick(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(nick): Path<String>,
) -> Response {
    if let Err(e) = verify_admin_secret(&state, &headers, &uri, peer_addr(peer)) {
        return e;
    }

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let outcome = crate::db::delete_reserved_nick(&conn, &nick);
        if matches!(outcome, Ok(true)) {
            if let Err(e) = state.control_plane().refresh_reserved_nick_cache(&conn) {
                tracing::error!("failed to refresh the reserved-nick cache after delete: {}", e);
            }
        }
        outcome
    })
    .await;

    match result {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error deleting reserved nick: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Database error"))).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Internal error"))).into_response(),
    }
}

/// JSON body for `PUT /api/admin/users/{user_id}/nick`.
#[derive(serde::Deserialize)]
pub struct AdminSetUserNickRequest {
    pub nick: String,
}

/// PUT /api/admin/users/{user_id}/nick
///
/// Set `user_id`'s nick directly (`db::admin_set_nick`) — bypasses the
/// reserved-name list and the 30-day cooldown a self-service `POST
/// /api/account/nick` is bound by; still enforces the format check and
/// global uniqueness against every OTHER account. This is how a
/// reservation made through `PUT /api/admin/nicks/reserved/{nick}` above is
/// actually handed to an account: the response's `reserved` field is `true`
/// exactly when `nick` is a row in that registry, and that row's
/// `granted_to` is now `user_id`. `400` invalid format, `404 {"error":"no
/// such user"}`, `409 {"error":"nick taken"}` held by a different account.
/// Requires `Authorization: Bearer {ADMIN_SECRET}`.
pub async fn admin_set_user_nick(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(user_id): Path<i64>,
    body: Bytes,
) -> Response {
    if let Err(e) = verify_admin_secret(&state, &headers, &uri, peer_addr(peer)) {
        return e;
    }
    let req: AdminSetUserNickRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(ErrorResponse::new("Invalid JSON body"))).into_response();
        }
    };

    let nick = req.nick;
    let nick_for_response = nick.clone();
    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::admin_set_nick(&conn, user_id, &nick)
    })
    .await;

    match result {
        Ok(Ok(reserved)) => Json(serde_json::json!({
            "user_id": user_id,
            "nick": nick_for_response,
            "reserved": reserved,
        }))
        .into_response(),
        Ok(Err(crate::db::AdminNickError::Invalid)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid nick format", "code": "nick_invalid" })),
        )
            .into_response(),
        Ok(Err(crate::db::AdminNickError::Forbidden)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "This nick is not allowed", "code": "nick_forbidden" })),
        )
            .into_response(),
        Ok(Err(crate::db::AdminNickError::NoSuchUser)) => {
            (StatusCode::NOT_FOUND, Json(ErrorResponse::new("no such user"))).into_response()
        }
        Ok(Err(crate::db::AdminNickError::Taken)) => {
            (StatusCode::CONFLICT, Json(ErrorResponse::new("nick taken"))).into_response()
        }
        Ok(Err(crate::db::AdminNickError::Db(e))) => {
            tracing::error!("DB error setting user nick via admin: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Database error"))).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Internal error"))).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- paid_days_in_bounds (POST /admin/users/{id}/paid-days) ----

    #[test]
    fn paid_days_in_bounds_accepts_the_closed_range_and_rejects_outside_it() {
        assert!(!paid_days_in_bounds(0));
        assert!(paid_days_in_bounds(MIN_PAID_DAYS));
        assert!(paid_days_in_bounds(365));
        assert!(paid_days_in_bounds(MAX_PAID_DAYS));
        assert!(!paid_days_in_bounds(MAX_PAID_DAYS + 1));
        assert!(!paid_days_in_bounds(-5));
    }
}

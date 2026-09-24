//! Caller/device resolution, the credential-revoke hooks, and the
//! paid-ladder gate every other `/_matrix/client/v3/*` route (P5-P10) builds
//! on. See `docs/mlc/plans/messenger-proto-server-matrix-subset-2026-09-24.md`
//! §1.1 for the device-per-credential model this module implements and the
//! "Manager decisions" section (top of that file) item 3 for the
//! expired-credential reaping this module also owns. Power-level helpers
//! (`PowerAction`/`user_level`/`event_level`/`can`) live in
//! `mylittlechart_server::matrix_store` instead — pure `m.room.power_levels`
//! JSON logic with no identity/`AppState` dependency, so they belong with
//! the rest of that lib-crate module's Matrix-domain helpers.
//!
//! # Cross-database rule
//!
//! Every function here that needs both the identity database (`db`,
//! sessions/tokens/`users.public_id`) and the messenger database
//! (`mylittlechart_server::matrix_store`/`matrix_keys_store`) takes each
//! connection as a separate parameter and never joins across them in SQL —
//! the same discipline `matrix_store.rs`'s own module doc states. Where both
//! must be locked at once, the lock order is always identity THEN messenger,
//! matching `routes::dm`'s "identity, drop, then social" convention — never
//! the reverse, so a future caller locking both in the same order never
//! deadlocks against this module.
//!
//! # Testability
//!
//! Every decision function below ([`resolve_bearer_credential`],
//! [`resolve_web_credential`], [`on_credential_revoked`],
//! [`reap_expired_devices`], [`device_id_for`])
//! takes plain `&Connection`/`&mut Connection`/[`live::LiveRegistry`]
//! parameters rather than [`AppState`] — so every one of them is unit-tested
//! against in-memory SQLite fixtures with no HTTP layer at all. Only
//! [`resolve_matrix_caller`] itself, the axum-facing entry point, needs
//! `AppState` (to reach `ControlPlane`'s locks from inside `spawn_blocking`).

use std::collections::HashSet;
use std::sync::Arc;

use axum::http::{header, HeaderMap};
use rusqlite::{params, Connection, OptionalExtension};

use mylittlechart_server::matrix_keys_store::{self, CredentialKind};
use mylittlechart_server::{live, matrix_store};

use super::MatrixError;
use crate::auth::{extract_bearer, extract_session_id, extract_ua_hash};
use crate::db;
use crate::social_db::{self, Class};
use crate::state::AppState;

/// A minute — [`device_id_for`]'s `last_seen_at` touch throttle, so a
/// chatty client's own long-poll cadence never turns into a write on every
/// single `/_matrix/*` request.
const DEVICE_TOUCH_THROTTLE_SECS: i64 = 60;

// ============================================================================
// Credential + caller identity
// ============================================================================

/// Which of the two existing auth mechanisms (plan §1.1) authenticated a
/// call, carrying the credential's own natural key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthCredential {
    /// `auth_tokens.token_hash` (native app / agent key).
    Bearer { token_hash: String },
    /// `web_sessions.session_id` (cookie session).
    Web { session_id: String },
}

impl AuthCredential {
    fn kind_and_ref(&self) -> (CredentialKind, &str) {
        match self {
            AuthCredential::Bearer { token_hash } => (CredentialKind::Bearer, token_hash.as_str()),
            AuthCredential::Web { session_id } => (CredentialKind::Web, session_id.as_str()),
        }
    }
}

/// The fully-resolved caller of a `/_matrix/*` request: internal identity,
/// Matrix identity, and which device this call is speaking as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixCaller {
    pub user_id: i64,
    pub public_id: String,
    pub mxid: String,
    pub device_id: String,
    pub credential: AuthCredential,
}

// ============================================================================
// Bearer/web credential classification — pure decision functions
// ============================================================================

/// Classification of a bearer token against the identity database, before
/// any side effect runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BearerLookup {
    Valid(i64),
    /// The row exists but is past its own `expires_at`.
    Expired,
    /// No such `token_hash` at all.
    NotFound,
}

fn lookup_bearer_credential(identity_conn: &Connection, token_hash: &str) -> rusqlite::Result<BearerLookup> {
    if let Some(user_id) = db::resolve_token_hash_with_expiry(identity_conn, token_hash)? {
        return Ok(BearerLookup::Valid(user_id));
    }
    let exists: Option<i64> = identity_conn
        .query_row("SELECT 1 FROM auth_tokens WHERE token_hash = ?1", params![token_hash], |row| row.get(0))
        .optional()?;
    Ok(if exists.is_some() { BearerLookup::Expired } else { BearerLookup::NotFound })
}

/// Resolve a bearer credential, revoking its Matrix device on
/// `messenger_conn` (plan §1.1 manager decision 3) if it is found but
/// expired. `Ok(Some(user_id))` on a valid credential; `Ok(None)` otherwise
/// (just-revoked, or never existed) — [`resolve_matrix_caller`] turns
/// `Ok(None)` into [`MatrixError::unknown_token`] either way, so this
/// function's own job is only the revoke side effect, not the HTTP shape.
fn resolve_bearer_credential(
    identity_conn: &Connection,
    messenger_conn: &mut Connection,
    live: &live::LiveRegistry,
    token_hash: &str,
    now: &str,
) -> rusqlite::Result<Option<i64>> {
    match lookup_bearer_credential(identity_conn, token_hash)? {
        BearerLookup::Valid(user_id) => Ok(Some(user_id)),
        BearerLookup::Expired => {
            on_credential_revoked(messenger_conn, live, CredentialKind::Bearer, token_hash, now)?;
            Ok(None)
        }
        BearerLookup::NotFound => Ok(None),
    }
}

/// Same classification as [`BearerLookup`], for a web session. A `ua_hash`
/// mismatch (still-live session, wrong browser fingerprint) is deliberately
/// folded into `NotFound`, not `Expired` — only a genuine expiry revokes the
/// device; a fingerprint mismatch might just be a client update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebLookup {
    Valid(i64),
    Expired,
    NotFound,
}

fn lookup_web_credential(identity_conn: &Connection, session_id: &str, ua_hash: &str) -> rusqlite::Result<WebLookup> {
    if let Some(user_id) = db::resolve_web_session(identity_conn, session_id, ua_hash)? {
        return Ok(WebLookup::Valid(user_id));
    }
    let expired: Option<i64> = identity_conn
        .query_row(
            "SELECT 1 FROM web_sessions WHERE session_id = ?1 AND expires_at <= datetime('now')",
            params![session_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(if expired.is_some() { WebLookup::Expired } else { WebLookup::NotFound })
}

/// The web-credential counterpart of [`resolve_bearer_credential`].
fn resolve_web_credential(
    identity_conn: &Connection,
    messenger_conn: &mut Connection,
    live: &live::LiveRegistry,
    session_id: &str,
    ua_hash: &str,
    now: &str,
) -> rusqlite::Result<Option<i64>> {
    match lookup_web_credential(identity_conn, session_id, ua_hash)? {
        WebLookup::Valid(user_id) => Ok(Some(user_id)),
        WebLookup::Expired => {
            on_credential_revoked(messenger_conn, live, CredentialKind::Web, session_id, now)?;
            Ok(None)
        }
        WebLookup::NotFound => Ok(None),
    }
}

// ============================================================================
// Device identity — the one place a device is born
// ============================================================================

/// Whether enough time has passed since `last_seen_at` to justify another
/// write ([`DEVICE_TOUCH_THROTTLE_SECS`]). A malformed timestamp touches
/// anyway (self-healing) rather than wedging a device's `last_seen_at`
/// forever.
fn should_touch_device(last_seen_at: &str, now: &str) -> bool {
    match (chrono::DateTime::parse_from_rfc3339(last_seen_at), chrono::DateTime::parse_from_rfc3339(now)) {
        (Ok(last), Ok(now)) => now.signed_duration_since(last).num_seconds() >= DEVICE_TOUCH_THROTTLE_SECS,
        _ => true,
    }
}

/// Get-or-create the device minted for `(credential_kind, credential_ref)`
/// under `user_id` — the one place a device identity is born (plan §1.1).
/// On a hit, `last_seen_at` is bumped only when [`should_touch_device`] says
/// enough time has passed.
pub fn device_id_for(
    conn: &Connection,
    user_id: i64,
    credential_kind: CredentialKind,
    credential_ref: &str,
    now: &str,
) -> rusqlite::Result<String> {
    match matrix_keys_store::device_for_credential(conn, credential_kind, credential_ref)? {
        Some(device) => {
            if should_touch_device(&device.last_seen_at, now) {
                matrix_keys_store::touch_device(conn, user_id, &device.device_id, now)?;
            }
            Ok(device.device_id)
        }
        None => matrix_keys_store::create_device(conn, user_id, credential_kind, credential_ref, now),
    }
}

// ============================================================================
// resolve_matrix_caller — the axum-facing entry point
// ============================================================================

/// Resolve the caller of a `/_matrix/*` request: cookie session first, then
/// `Authorization: Bearer`, mirroring `routes::dm::resolve_user_id`
/// (`routes/dm.rs:146-178`) — including its fall-through (a present-but-
/// unresolved session does not short-circuit the whole call; a bearer token
/// is still tried). An EXPIRED credential is treated as revoked: its Matrix
/// device is stripped ([`on_credential_revoked`]) before this returns
/// [`MatrixError::unknown_token`]. On success, [`device_id_for`] resolves
/// (minting on first touch) the device this call is speaking as — the one
/// place a device identity is born.
pub async fn resolve_matrix_caller(headers: &HeaderMap, state: &Arc<AppState>) -> Result<MatrixCaller, MatrixError> {
    let session_id = extract_session_id(headers);
    let ua_hash = extract_ua_hash(headers);
    let bearer_token: Option<String> = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| extract_bearer(Some(v)))
        .map(str::to_owned);
    let had_any_credential = session_id.is_some() || bearer_token.is_some();

    let state_for_resolve = state.clone();
    let resolved = tokio::task::spawn_blocking(move || -> Result<(i64, AuthCredential), MatrixError> {
        let now = chrono::Utc::now().to_rfc3339();
        let cp = state_for_resolve.control_plane();

        if let Some(session_id) = session_id {
            let outcome = {
                let identity_conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
                let mut messenger_conn = cp.messenger_conn();
                resolve_web_credential(&identity_conn, &mut messenger_conn, &cp.live, &session_id, &ua_hash, &now)?
            };
            if let Some(user_id) = outcome {
                return Ok((user_id, AuthCredential::Web { session_id }));
            }
        }

        if let Some(token_hash) = bearer_token {
            let outcome = {
                let identity_conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
                let mut messenger_conn = cp.messenger_conn();
                resolve_bearer_credential(&identity_conn, &mut messenger_conn, &cp.live, &token_hash, &now)?
            };
            if let Some(user_id) = outcome {
                return Ok((user_id, AuthCredential::Bearer { token_hash }));
            }
        }

        if had_any_credential {
            Err(MatrixError::unknown_token())
        } else {
            Err(MatrixError::missing_token())
        }
    })
    .await;

    let (user_id, credential) = match resolved {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(MatrixError::internal()),
    };

    let state_for_device = state.clone();
    let device_result = tokio::task::spawn_blocking(move || -> Result<MatrixCaller, MatrixError> {
        let now = chrono::Utc::now().to_rfc3339();
        let cp = state_for_device.control_plane();

        let public_id = {
            let identity_conn = cp.db.lock().unwrap_or_else(|e| e.into_inner());
            db::get_user_public_id(&identity_conn, user_id)?
        };

        let messenger_conn = cp.messenger_conn();
        let mxid = matrix_store::ensure_matrix_user(&messenger_conn, user_id, &public_id, &now)?;
        let (credential_kind, credential_ref) = credential.kind_and_ref();
        let device_id = device_id_for(&messenger_conn, user_id, credential_kind, credential_ref, &now)?;

        Ok(MatrixCaller { user_id, public_id, mxid, device_id, credential })
    })
    .await;

    match device_result {
        Ok(Ok(caller)) => Ok(caller),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(MatrixError::internal()),
    }
}

// ============================================================================
// on_credential_revoked — the shared revoke hook
// ============================================================================

/// Strip the Matrix device minted for `(credential_kind, credential_ref)`,
/// if any, and wake every affected user's `/sync` long-poll (plan §1.1
/// steps 1-4). Steps 1-3 (delete the device, its key material, and log the
/// device-list change) are [`matrix_keys_store::delete_device_by_credential`];
/// step 4 (wake the revoked user's own other devices plus everyone sharing a
/// joined room with them) is this function's own job. A no-op if the
/// credential never minted a device (nothing to strip, nothing to wake).
///
/// Call sites: `routes::sessions::revoke_session` (a UI session revoke),
/// `routes::device_auth::logout` (cookie logout), and
/// `routes::sessions::delete_account` (once per credential the account ever
/// held, before the identity-side delete runs) — plus this module's own
/// [`resolve_bearer_credential`]/[`resolve_web_credential`] (an
/// opportunistic revoke on first use of an expired credential) and
/// [`reap_expired_devices`] (the periodic backstop for every other deletion
/// path).
pub fn on_credential_revoked(
    messenger_conn: &mut Connection,
    live: &live::LiveRegistry,
    credential_kind: CredentialKind,
    credential_ref: &str,
    now: &str,
) -> rusqlite::Result<()> {
    let revoked = matrix_keys_store::delete_device_by_credential(messenger_conn, credential_kind, credential_ref, now)?;
    let Some((revoked_user_id, _device_id)) = revoked else {
        return Ok(());
    };

    let mut wake_user_ids: HashSet<i64> = HashSet::new();
    wake_user_ids.insert(revoked_user_id);
    for room_id in matrix_store::rooms_for_user(messenger_conn, revoked_user_id, None)? {
        for member in matrix_store::room_members(messenger_conn, &room_id, None)? {
            wake_user_ids.insert(member.user_id);
        }
    }

    live.wake_many(wake_user_ids.into_iter().map(|id| format!("user:{id}")));
    Ok(())
}

// ============================================================================
// reap_expired_devices — the P14-scheduled boot+hourly backstop
// ============================================================================

/// Whether `(credential_kind, credential_ref)` still names a live, unexpired
/// row in the identity database — [`reap_expired_devices`]'s own "is this
/// device's credential still good?" test.
fn credential_is_valid(identity_conn: &Connection, credential_kind: CredentialKind, credential_ref: &str) -> rusqlite::Result<bool> {
    let found: Option<i64> = match credential_kind {
        CredentialKind::Bearer => identity_conn
            .query_row(
                "SELECT 1 FROM auth_tokens WHERE token_hash = ?1 AND (expires_at IS NULL OR expires_at > datetime('now'))",
                params![credential_ref],
                |row| row.get(0),
            )
            .optional()?,
        CredentialKind::Web => identity_conn
            .query_row(
                "SELECT 1 FROM web_sessions WHERE session_id = ?1 AND expires_at > datetime('now')",
                params![credential_ref],
                |row| row.get(0),
            )
            .optional()?,
    };
    Ok(found.is_some())
}

/// Sweep every device in `messenger_conn` and revoke any whose credential is
/// gone or past its own expiry in `identity_conn` (plan §1.1 manager
/// decision 3) — the backstop for every credential-deletion path that does
/// NOT go through [`on_credential_revoked`] directly (e.g. an agent key
/// revoked via `routes::agent_keys::revoke_key`, or a token that simply aged
/// past `expires_at` without the caller ever making another `/_matrix/*`
/// call to trigger [`resolve_bearer_credential`]'s own opportunistic
/// revoke). P14 schedules this at boot and hourly; this function is only the
/// decision + the revoke, not the scheduling. Returns how many devices were
/// reaped.
pub fn reap_expired_devices(identity_conn: &Connection, messenger_conn: &mut Connection, live: &live::LiveRegistry, now: &str) -> usize {
    let devices = match matrix_keys_store::devices_for_reaper(messenger_conn) {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("reap_expired_devices: failed to list devices: {}", e);
            return 0;
        }
    };

    let mut reaped = 0usize;
    for (_user_id, _device_id, credential_kind, credential_ref) in devices {
        let valid = match credential_is_valid(identity_conn, credential_kind, &credential_ref) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("reap_expired_devices: failed to check a credential: {}", e);
                continue;
            }
        };
        if valid {
            continue;
        }
        if let Err(e) = on_credential_revoked(messenger_conn, live, credential_kind, &credential_ref, now) {
            tracing::error!("reap_expired_devices: failed to revoke a device: {}", e);
            continue;
        }
        reaped += 1;
    }
    reaped
}

// ============================================================================
// Paid-ladder gate — own copy per this codebase's convention
// ============================================================================

/// Whether `user_id` reaches [`Class::Paid`] on the forum ladder — byte-for-
/// byte the same ladder check as `routes::dm::is_dm_paid` (own copy per this
/// codebase's one-copy-per-route-module convention, `routes/dm.rs:200-220`),
/// so a moderator/admin role or trusted standing satisfies "paid" for the
/// messenger exactly like it does for DMs and the forum. `pub(crate)` so
/// `routes::matrix::capabilities` (the one Auth-only endpoint P4 ships,
/// which reports messenger-paid status as a capability rather than gating on
/// it) and every later Paid-gated `routes::matrix::*` route can reach it.
pub(crate) fn is_messenger_paid(conn_social: &rusqlite::Connection, user_id: i64, is_paid: bool) -> bool {
    social_db::caller_classes(conn_social, Some(user_id), is_paid).contains(&Class::Paid)
}

/// The gate every `Paid`-marked route in plan §4's endpoint table runs
/// through: refuse with [`MatrixError::forbidden`] unless [`is_messenger_paid`]
/// already determined the caller reaches the ladder's `Paid` class.
pub fn require_paid_matrix(is_paid: bool) -> Result<(), MatrixError> {
    if is_paid {
        Ok(())
    } else {
        Err(MatrixError::forbidden("paid account required for the messenger"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- fixtures ----

    fn identity_test_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        conn.execute_batch(
            "
            CREATE TABLE auth_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id    INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT
            );
            CREATE TABLE web_sessions (
                session_id TEXT PRIMARY KEY,
                user_id    INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                ua_hash    TEXT NOT NULL DEFAULT ''
            );
            ",
        )
        .expect("test schema");
        conn
    }

    fn keys_test_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        matrix_store::create_matrix_schema(&conn).expect("matrix schema");
        matrix_keys_store::create_matrix_keys_schema(&conn).expect("matrix keys schema");
        conn
    }

    fn social_test_conn() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().expect("in-memory sqlite");
        social_db::create_social_schema(&conn).expect("social schema");
        conn
    }

    const T0: &str = "2026-09-24T00:00:00+00:00";

    // ---- P4 test: is_messenger_paid matches is_dm_paid's own ladder boundaries ----

    #[test]
    fn is_messenger_paid_matches_is_dm_paid_for_every_ladder_boundary() {
        let conn = social_test_conn();
        social_db::set_role(&conn, 42, social_db::Role::Admin, T0).expect("set role");
        assert!(is_messenger_paid(&conn, 42, false), "an unpaid admin reaches Paid");

        let conn = social_test_conn();
        social_db::set_role(&conn, 43, social_db::Role::Moderator, T0).expect("set role");
        assert!(is_messenger_paid(&conn, 43, false), "an unpaid moderator reaches Paid");

        let conn = social_test_conn();
        assert!(!is_messenger_paid(&conn, 44, false), "an unpaid plain user does not reach Paid");

        let conn = social_test_conn();
        assert!(is_messenger_paid(&conn, 45, true), "a paid user reaches Paid");
    }

    #[test]
    fn require_paid_matrix_allows_paid_and_refuses_unpaid() {
        assert!(require_paid_matrix(true).is_ok());
        assert!(require_paid_matrix(false).is_err());
    }

    // ---- P4 test: device_id_for mints once, reuses, and separates by credential ----

    #[test]
    fn device_id_for_mints_once_then_reuses_for_the_same_credential() {
        let conn = keys_test_conn();
        let first = device_id_for(&conn, 1, CredentialKind::Bearer, "hash-a", T0).expect("mint");
        let second = device_id_for(&conn, 1, CredentialKind::Bearer, "hash-a", T0).expect("reuse");
        assert_eq!(first, second);
        assert_eq!(matrix_keys_store::list_devices(&conn, 1).expect("list").len(), 1);
    }

    #[test]
    fn device_id_for_mints_a_different_device_for_a_different_credential_same_user() {
        let conn = keys_test_conn();
        let a = device_id_for(&conn, 1, CredentialKind::Bearer, "hash-a", T0).expect("mint a");
        let b = device_id_for(&conn, 1, CredentialKind::Web, "session-b", T0).expect("mint b");
        assert_ne!(a, b);
        assert_eq!(matrix_keys_store::list_devices(&conn, 1).expect("list").len(), 2);
    }

    // ---- P4 test: an expired bearer credential revokes its device ----

    #[test]
    fn expired_bearer_credential_revokes_its_device_and_returns_unknown_token() {
        let identity_conn = identity_test_conn();
        identity_conn
            .execute(
                "INSERT INTO auth_tokens (token_hash, user_id, created_at, expires_at) VALUES ('expired-hash', 1, ?1, '2020-01-02T00:00:00+00:00')",
                params![T0],
            )
            .expect("insert expired token");

        let mut messenger_conn = keys_test_conn();
        device_id_for(&messenger_conn, 1, CredentialKind::Bearer, "expired-hash", T0).expect("mint device");
        assert_eq!(matrix_keys_store::list_devices(&messenger_conn, 1).expect("list").len(), 1);

        let live = live::LiveRegistry::new();
        let now = "2026-09-24T00:00:00+00:00";
        let result = resolve_bearer_credential(&identity_conn, &mut messenger_conn, &live, "expired-hash", now).expect("resolve");

        assert_eq!(result, None, "an expired credential must not resolve to a caller");
        assert!(
            matrix_keys_store::list_devices(&messenger_conn, 1).expect("list").is_empty(),
            "the device this credential minted must be revoked"
        );
    }

    #[test]
    fn unknown_bearer_credential_resolves_to_none_without_touching_any_device() {
        let identity_conn = identity_test_conn();
        let mut messenger_conn = keys_test_conn();
        device_id_for(&messenger_conn, 1, CredentialKind::Bearer, "someone-elses-hash", T0).expect("mint device");

        let live = live::LiveRegistry::new();
        let result = resolve_bearer_credential(&identity_conn, &mut messenger_conn, &live, "never-issued-hash", T0).expect("resolve");

        assert_eq!(result, None);
        assert_eq!(
            matrix_keys_store::list_devices(&messenger_conn, 1).expect("list").len(),
            1,
            "a credential that never existed must not revoke an unrelated device"
        );
    }

    // ---- reap_expired_devices ----

    #[test]
    fn reap_expired_devices_revokes_devices_whose_credential_is_gone_or_expired() {
        let identity_conn = identity_test_conn();
        identity_conn
            .execute("INSERT INTO auth_tokens (token_hash, user_id, created_at, expires_at) VALUES ('still-valid', 1, ?1, NULL)", params![T0])
            .expect("insert valid token");
        identity_conn
            .execute(
                "INSERT INTO auth_tokens (token_hash, user_id, created_at, expires_at) VALUES ('expired-hash', 2, ?1, '2020-01-01T00:00:00+00:00')",
                params![T0],
            )
            .expect("insert expired token");
        // 'deleted-hash' (user 3) has no identity-side row at all.

        let mut messenger_conn = keys_test_conn();
        device_id_for(&messenger_conn, 1, CredentialKind::Bearer, "still-valid", T0).expect("mint");
        device_id_for(&messenger_conn, 2, CredentialKind::Bearer, "expired-hash", T0).expect("mint");
        device_id_for(&messenger_conn, 3, CredentialKind::Bearer, "deleted-hash", T0).expect("mint");

        let live = live::LiveRegistry::new();
        let reaped = reap_expired_devices(&identity_conn, &mut messenger_conn, &live, T0);

        assert_eq!(reaped, 2);
        assert_eq!(matrix_keys_store::list_devices(&messenger_conn, 1).expect("list").len(), 1, "a still-valid credential keeps its device");
        assert!(matrix_keys_store::list_devices(&messenger_conn, 2).expect("list").is_empty());
        assert!(matrix_keys_store::list_devices(&messenger_conn, 3).expect("list").is_empty());
    }
}

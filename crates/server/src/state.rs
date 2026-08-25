//! Shared application state passed through axum via `Arc<AppState>`.

use std::sync::Mutex;

/// Shared application state.
///
/// `rusqlite::Connection` is `!Send`, so we wrap it in a `std::sync::Mutex`.
/// SQLite queries are sub-millisecond, so blocking on this lock is acceptable.
pub struct AppState {
    /// SQLite connection protected by a standard (blocking) mutex.
    pub db: Mutex<rusqlite::Connection>,

    /// Root directory where runtime data is stored (binaries, DB file, etc.)
    pub data_dir: String,

    /// Hot file store for chart-persistence sync categories (see syncstore.rs).
    /// Root is `<data_dir>/sync/`. Cold categories stay in the SQLCipher DB.
    pub sync_store: crate::syncstore::SyncStore,

    /// Secret required for admin endpoints (set via `ADMIN_SECRET` env var).
    pub admin_secret: String,

    // OAuth credentials
    pub github_client_id: String,
    pub github_client_secret: String,
    pub discord_client_id: String,
    pub discord_client_secret: String,
    pub telegram_bot_token: String,
    pub google_client_id: String,
    pub google_client_secret: String,
    pub twitter_client_id: String,
    pub twitter_client_secret: String,

    /// Broadcast channel for triggering graceful shutdown (e.g. from /api/admin/restart).
    pub shutdown_tx: tokio::sync::broadcast::Sender<()>,

    // ---- Build attestation ----

    /// Ed25519 public keys used to verify client binary attestation tokens.
    ///
    /// Loaded from `BUILD_ATTEST_PUBKEY` (hex, comma-separated for multiple keys).
    /// When empty, all clients pass (no signature verification).
    pub build_attest_pubkeys: Vec<[u8; 32]>,

    /// When `true`, unsigned clients are rejected with `403`. When `false` (grace period),
    /// they are allowed through but logged.
    ///
    /// Controlled by `BUILD_ATTEST_ENFORCE` env var (default: `false`).
    pub build_attest_enforce: bool,

    /// Maximum allowed age of the build timestamp in seconds.
    ///
    /// Controlled by `BUILD_ATTEST_MAX_AGE_DAYS` env var (default: 365 days).
    pub build_attest_max_age_secs: u64,
}

//! Shared application state passed through axum via `Arc<AppState>`.

use std::sync::Mutex;

/// Which role this process plays in the production topology.
///
/// 2026-08-30 split: production runs one control box (this binary + the
/// SQLCipher database) and two edge boxes (nginx serving static + a relay).
/// Stage 2 needs an edge to also run this binary — stripped down, holding a
/// rate-limit lease — so the role has to exist as a real boot-time choice,
/// not just a plan.
///
/// Read once at boot from `MLC_ROLE` (see `ServerRole::from_env`); defaults
/// to `Control` so a fresh checkout with no new env var set behaves exactly
/// like today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerRole {
    /// Runs the database and every identity/sync/admin endpoint. Today's
    /// only role, and the default.
    Control,
    /// Runs a stripped subset with no database at all (see `ControlPlane`
    /// and `routes::edge_api_router`).
    Edge,
}

impl ServerRole {
    /// Read `MLC_ROLE` from the environment (`"control"` / `"edge"`,
    /// case-insensitive). Unset or unrecognised values default to `Control`
    /// — the only role that existed before this split, so an operator who
    /// never heard of `MLC_ROLE` gets unchanged behaviour.
    pub fn from_env() -> Self {
        match std::env::var("MLC_ROLE") {
            Ok(v) if v.eq_ignore_ascii_case("edge") => ServerRole::Edge,
            Ok(v) if v.eq_ignore_ascii_case("control") => ServerRole::Control,
            Ok(other) => {
                tracing::warn!(
                    "Unrecognised MLC_ROLE={:?} — defaulting to control",
                    other
                );
                ServerRole::Control
            }
            Err(_) => ServerRole::Control,
        }
    }
}

impl std::fmt::Display for ServerRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ServerRole::Control => "control",
            ServerRole::Edge => "edge",
        })
    }
}

/// Resources that exist only on a control-role process: the SQLCipher
/// database and the hot sync-file store. An edge-role process never
/// constructs one of these — see `ServerRole` and the boot gate in
/// `main.rs`, which skips `db::init_db` (and its wait for the SQLCipher key
/// file) entirely on edge.
pub struct ControlPlane {
    /// SQLCipher (identity) connection, protected by a standard (blocking) mutex.
    ///
    /// `rusqlite::Connection` is `!Send`, so we wrap it in a `std::sync::Mutex`.
    /// SQLite queries are sub-millisecond, so blocking on this lock is acceptable.
    pub db: Mutex<rusqlite::Connection>,

    /// Operational (unencrypted) connection: `devices`, `device_profile`,
    /// `device_metrics`, `releases`.
    ///
    /// Split out of `db` on 2026-08-30 (see
    /// docs/mlc/audits/2026-08-30-entry-lock-vault-and-user-persistence.md §6/§11)
    /// — none of these tables are irreplaceable identity data, and none of
    /// them need the SQLCipher key. Opened with a plain `Connection::open`
    /// (see `db::init_ops_db`), independent of the tmpfs key wait that gates
    /// `db` above, so a box with no key pushed yet still accepts heartbeats
    /// and serves OTA manifests. `device_users` is NOT here — it is a
    /// relationship between an account and a device, not a heartbeat, and
    /// stays in `db`.
    pub ops_db: Mutex<rusqlite::Connection>,

    /// The only writer for the operational database, running on its own OS
    /// thread (see `opswriter.rs`).
    ///
    /// Added 2026-09-01: `ops_db` above is a `Mutex<Connection>` shared by
    /// every route that touches the operational database, writers and
    /// readers alike — telemetry (by far the highest-rate write, one post
    /// per device per hour, times every registered device) used to take
    /// that same lock and await the write before answering, so it queued
    /// behind every dashboard read holding the mutex and behind every other
    /// device's post. `ops_writer` owns a second connection to the same
    /// file, opened independently at boot (see `main.rs`), and every write
    /// that does not need its result before answering (currently just
    /// telemetry — see `routes::telemetry`) goes through `enqueue` instead
    /// of `ops_db.lock()`. `ops_db` itself is now read-mostly; with WAL a
    /// reader on it never blocks this thread's writes.
    pub ops_writer: crate::opswriter::OpsWriter,

    /// Hot file store for chart-persistence sync categories (see syncstore.rs).
    /// Root is `<data_dir>/sync/`. Cold categories stay in the SQLCipher DB.
    pub sync_store: crate::syncstore::SyncStore,
}

/// Shared application state.
pub struct AppState {
    /// Control-plane resources (database + hot sync store), or `None` on an
    /// edge-role process. Private: reach it through the `control_plane()`
    /// accessor below so there is exactly one place that decides what
    /// happens when a control-only handler runs on an edge process — never
    /// possible in practice (step 3 in routes/mod.rs does not mount those
    /// handlers on edge), but a clear invariant beats a silent `None` deref.
    control_plane: Option<ControlPlane>,

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

    /// Maximum `device_metrics` rows accepted per device per UTC calendar
    /// day (see `routes::telemetry::submit_telemetry`) — the one telemetry
    /// volume control that does not depend on a well-behaved client.
    ///
    /// Controlled by `MLC_TELEMETRY_DAILY_CAP` env var (default: 48), read
    /// once at boot next to `MLC_TELEMETRY_RETENTION_DAYS`.
    pub telemetry_daily_cap: i64,
}

impl AppState {
    /// Construct `AppState` with an explicit control plane (`Some` on a
    /// control-role process, `None` on edge). This is the only place that
    /// sets `control_plane` — the field is private, so every other call
    /// site (all route handlers) is forced through `control_plane()` below.
    pub fn new(
        control_plane: Option<ControlPlane>,
        admin_secret: String,
        github_client_id: String,
        github_client_secret: String,
        discord_client_id: String,
        discord_client_secret: String,
        telegram_bot_token: String,
        google_client_id: String,
        google_client_secret: String,
        twitter_client_id: String,
        twitter_client_secret: String,
        shutdown_tx: tokio::sync::broadcast::Sender<()>,
        build_attest_pubkeys: Vec<[u8; 32]>,
        build_attest_enforce: bool,
        build_attest_max_age_secs: u64,
        telemetry_daily_cap: i64,
    ) -> Self {
        Self {
            control_plane,
            admin_secret,
            github_client_id,
            github_client_secret,
            discord_client_id,
            discord_client_secret,
            telegram_bot_token,
            google_client_id,
            google_client_secret,
            twitter_client_id,
            twitter_client_secret,
            shutdown_tx,
            build_attest_pubkeys,
            build_attest_enforce,
            build_attest_max_age_secs,
            telemetry_daily_cap,
        }
    }

    /// The single accessor for control-plane resources (database + hot sync
    /// store).
    ///
    /// Panics if called on an edge-role process. That is acceptable ONLY
    /// because every caller of this accessor is a control-only route, and
    /// `routes::edge_api_router` (routes/mod.rs) does not mount any of them
    /// on edge — the panic documents an invariant that a routing bug would
    /// have to break first, it does not paper over a reachable edge case.
    pub fn control_plane(&self) -> &ControlPlane {
        self.control_plane.as_ref().expect(
            "control_plane accessed on an edge-role process — this handler must not be mounted by edge_api_router",
        )
    }
}

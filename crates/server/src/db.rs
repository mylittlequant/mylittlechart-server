//! SQLite database initialization and query helpers.

use rusqlite::{Connection, OptionalExtension, Result, params};

/// Default path to the SQLCipher key file (tmpfs, pushed by the operator).
const DEFAULT_DBKEY_PATH: &str = "/run/mlc/dbkey";

/// Parse database key file contents into a hex string for `PRAGMA key`.
///
/// Accepts either 64 hex characters (a 32-byte key in hex) or raw key bytes;
/// trailing whitespace is stripped. Returns None if nothing is left.
fn db_key_hex(raw: &[u8]) -> Option<String> {
    let mut end = raw.len();
    while end > 0 && raw[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let trimmed = &raw[..end];
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() == 64 && trimmed.iter().all(|b| b.is_ascii_hexdigit()) {
        // Already hex — normalize to lowercase for the blob literal.
        return Some(String::from_utf8_lossy(trimmed).to_lowercase());
    }
    Some(hex::encode(trimmed))
}

/// Read the SQLCipher key, waiting until the operator pushes the key file.
///
/// The key is delivered into tmpfs after service start; until the file
/// appears we poll every 5 seconds and log every 30 seconds. There is no
/// overall timeout — systemd RestartSec handles a service that never gets
/// a key, and once the file appears startup continues normally.
fn wait_for_db_key(path: &str) -> String {
    let mut waited_secs = 0u64;
    loop {
        match std::fs::read(path) {
            Ok(raw) => {
                if let Some(key_hex) = db_key_hex(&raw) {
                    return key_hex;
                }
                if waited_secs % 30 == 0 {
                    tracing::error!("Database key file {} is empty — waiting for a valid key", path);
                }
            }
            Err(_) => {
                if waited_secs % 30 == 0 {
                    tracing::info!("waiting for {}", path);
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
        waited_secs += 5;
    }
}

/// Initialize the database and create all tables.
pub fn init_db(path: &str) -> Result<Connection> {
    let key_path =
        std::env::var("MLC_DBKEY_PATH").unwrap_or_else(|_| DEFAULT_DBKEY_PATH.to_string());
    let key_hex = wait_for_db_key(&key_path);

    let conn = Connection::open(path)?;

    // SQLCipher: the key must be the very first statement on the connection.
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", key_hex))?;

    // The key now lives only in process memory — remove the tmpfs file.
    if let Err(e) = std::fs::remove_file(&key_path) {
        tracing::warn!("Failed to remove database key file {}: {}", key_path, e);
    }

    // Enable WAL mode for better concurrent read performance.
    if let Err(e) = conn.execute_batch("PRAGMA journal_mode=WAL;") {
        tracing::error!(
            "Cannot read database {} with the provided key: {}. \
             If this is an existing plaintext database, run the offline SQLCipher migration first.",
            path,
            e
        );
        return Err(e);
    }
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;

    conn.execute_batch(r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            provider_user_id TEXT NOT NULL,
            display_name TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            UNIQUE(provider, provider_user_id)
        );

        CREATE TABLE IF NOT EXISTS auth_tokens (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS oauth_states (
            state TEXT PRIMARY KEY,
            provider TEXT NOT NULL,
            redirect_port INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS device_users (
            device_id TEXT NOT NULL,
            user_id INTEGER NOT NULL REFERENCES users(id),
            linked_at TEXT NOT NULL,
            PRIMARY KEY(device_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS web_sessions (
            session_id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS device_codes (
            code TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            user_id INTEGER,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS user_providers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            provider TEXT NOT NULL,
            provider_user_id TEXT NOT NULL,
            display_name TEXT NOT NULL DEFAULT '',
            linked_at TEXT NOT NULL,
            UNIQUE(provider, provider_user_id)
        );

        CREATE TABLE IF NOT EXISTS tg_login_tokens (
            token TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'pending',
            telegram_user_id TEXT,
            display_name TEXT,
            link_user_id INTEGER,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS agent_key_requests (
            code        TEXT    PRIMARY KEY,
            label       TEXT    NOT NULL DEFAULT '',
            permissions TEXT    NOT NULL DEFAULT '["read_bars","read_indicators","read_viewport","read_config"]',
            user_id     INTEGER REFERENCES users(id),
            status      TEXT    NOT NULL DEFAULT 'pending',
            claimed_key TEXT,
            created_at  TEXT    NOT NULL,
            expires_at  TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sync_items (
            user_id     INTEGER NOT NULL,
            device_id   TEXT    NOT NULL DEFAULT '',
            profile_id  TEXT    NOT NULL DEFAULT '',
            sync_id     TEXT    NOT NULL,
            category    TEXT    NOT NULL,
            name        TEXT    NOT NULL,
            content     BLOB    NOT NULL,
            checksum    TEXT    NOT NULL,
            modified_at INTEGER NOT NULL,
            deleted     INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT    NOT NULL,
            PRIMARY KEY (user_id, device_id, profile_id, sync_id)
        );

        CREATE TABLE IF NOT EXISTS sync_e2e_params (
            user_id              INTEGER PRIMARY KEY,
            salt                 TEXT    NOT NULL,
            iterations           INTEGER NOT NULL DEFAULT 600000,
            created_at           TEXT    NOT NULL,
            encrypted_master_key BLOB    DEFAULT NULL
        );

        CREATE TABLE IF NOT EXISTS link_tokens (
            token       TEXT    PRIMARY KEY,
            device_name TEXT    NOT NULL,
            device_id   TEXT    NOT NULL,
            created_at  INTEGER NOT NULL,
            expires_at  INTEGER NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'pending',
            user_id     INTEGER
        );

        -- Gift / trial codes: an admin mints one, an account redeems it once
        -- and gains paid time (see db::mint_gift_codes / db::redeem_gift_code).
        -- `code` is generated server-side, never accepted from a caller — see
        -- generate_gift_code. `redeemed_by`/`redeemed_at` stay NULL until the
        -- single conditional UPDATE in redeem_gift_code claims the row.
        CREATE TABLE IF NOT EXISTS gift_codes (
            code         TEXT    PRIMARY KEY,
            grants_days  INTEGER NOT NULL,
            note         TEXT    NOT NULL DEFAULT '',
            created_at   TEXT    NOT NULL,
            redeemed_by  INTEGER REFERENCES users(id),
            redeemed_at  TEXT
        );

        -- Public share links (see the "Share links" section below). Two
        -- kinds, spelled by entitlements::ShareKind::as_str: 'live' (a frozen
        -- ChartPreset in `preset_json`, rendered read-only by the web viewer)
        -- and 'screenshot' (a PNG blob on disk, `blob_path` relative to
        -- `<data_dir>/share/`). `revoked` flips to 1 on owner delete; a row
        -- past `expires_at` is dead either way and is reaped by
        -- cleanup_expired_share_links.
        CREATE TABLE IF NOT EXISTS share_links (
            token       TEXT    PRIMARY KEY,
            user_id     INTEGER NOT NULL REFERENCES users(id),
            kind        TEXT    NOT NULL,
            title       TEXT    NOT NULL DEFAULT '',
            preset_json TEXT    NOT NULL DEFAULT '',
            blob_path   TEXT    NOT NULL DEFAULT '',
            blob_bytes  INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT    NOT NULL,
            expires_at  TEXT    NOT NULL,
            revoked     INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_share_links_user ON share_links(user_id, kind, revoked);

        -- In-app blog (2026-09-05 web-surface-cleanup plan): patch notes and
        -- posts pushed one at a time by the operator (`POST /api/admin/posts`,
        -- see routes/posts.rs), replacing the static `web/blog/posts.json`
        -- that used to be redeployed whole for every entry. `kind` is
        -- 'patch' or 'post'; `visibility` is 'public' or 'paid' (paid rows
        -- exist for a future gated forum/post tier — every reader in this
        -- wave filters to 'public' only, see db::list_posts / db::get_post).
        -- `body` is plain text, paragraphs separated by a blank line — no
        -- markdown, same convention the client-side renderers already use.
        CREATE TABLE IF NOT EXISTS posts (
            id          TEXT    PRIMARY KEY,
            kind        TEXT    NOT NULL,
            version     TEXT,
            date        TEXT    NOT NULL,
            title       TEXT    NOT NULL,
            summary     TEXT    NOT NULL DEFAULT '',
            body        TEXT    NOT NULL DEFAULT '',
            url         TEXT    NOT NULL,
            visibility  TEXT    NOT NULL DEFAULT 'public',
            created_at  TEXT    NOT NULL,
            updated_at  TEXT    NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_posts_date ON posts(date DESC, id DESC);
    "#)?;

    // Safe migration: add signature column to releases if not present. `releases`
    // moved to the operational database (2026-08-30 store split, see
    // `init_ops_db`/`migrate_legacy_ops_tables` below) — this and the two
    // releases-shape migrations further down only still matter for the one
    // boot on a given box where `releases` has not been dropped from identity
    // yet; both are self-guarded (`unwrap_or(false)` / `let _ =`) and become
    // permanent no-ops once the move has happened.
    let _ = conn.execute("ALTER TABLE releases ADD COLUMN signature TEXT NOT NULL DEFAULT ''", []);
    // Safe migration: add channel column to releases if not present.
    let _ = conn.execute(
        "ALTER TABLE releases ADD COLUMN channel TEXT NOT NULL DEFAULT 'stable'",
        [],
    );
    // Safe migration: when this account's paid access ends, RFC3339, NULL for
    // an account that has never paid.
    //
    // A date and not a boolean, because a subscription has an end: a flag would
    // have to become this the day billing lands, and every reader written
    // against the flag would have to be found again. `CREATE TABLE IF NOT
    // EXISTS` above does not add a column to a table that already exists —
    // only this line does, on a live database.
    let _ = conn.execute("ALTER TABLE users ADD COLUMN paid_until TEXT", []);
    // Safe migration: add expires_at column to auth_tokens if not present.
    let _ = conn.execute("ALTER TABLE auth_tokens ADD COLUMN expires_at TEXT", []);
    // Safe migration: add device_id column to oauth_states if not present.
    let _ = conn.execute("ALTER TABLE oauth_states ADD COLUMN device_id TEXT NOT NULL DEFAULT ''", []);
    // Safe migration: add ua_hash column to web_sessions if not present.
    let _ = conn.execute("ALTER TABLE web_sessions ADD COLUMN ua_hash TEXT NOT NULL DEFAULT ''", []);
    // Safe migration: add link_user_id column to oauth_states if not present.
    let _ = conn.execute("ALTER TABLE oauth_states ADD COLUMN link_user_id INTEGER", []);
    // Safe migration: add device_code column to oauth_states if not present.
    // Carries the sign-in modal's device code through the OAuth round-trip so
    // the web-callback can confirm the device without manual code entry.
    let _ = conn.execute("ALTER TABLE oauth_states ADD COLUMN device_code TEXT", []);
    // Safe migrations: add agent-key columns to auth_tokens if not present.
    let _ = conn.execute("ALTER TABLE auth_tokens ADD COLUMN label TEXT NOT NULL DEFAULT ''", []);
    let _ = conn.execute("ALTER TABLE auth_tokens ADD COLUMN permissions TEXT NOT NULL DEFAULT '[\"read_bars\",\"read_indicators\",\"read_viewport\",\"read_config\"]'", []);
    let _ = conn.execute("ALTER TABLE auth_tokens ADD COLUMN initiated_by TEXT NOT NULL DEFAULT 'user'", []);
    let _ = conn.execute("ALTER TABLE auth_tokens ADD COLUMN last_used_at TEXT", []);
    let _ = conn.execute("ALTER TABLE auth_tokens ADD COLUMN last_ip TEXT", []);
    // Safe migration: add device_id column to auth_tokens if not present.
    let _ = conn.execute("ALTER TABLE auth_tokens ADD COLUMN device_id TEXT NOT NULL DEFAULT ''", []);
    // Safe migration: add auth_token column to link_tokens if not present.
    let _ = conn.execute("ALTER TABLE link_tokens ADD COLUMN auth_token TEXT NOT NULL DEFAULT ''", []);
    // Safe migration: add display_name column to sync_items.
    let _ = conn.execute("ALTER TABLE sync_items ADD COLUMN display_name TEXT NOT NULL DEFAULT ''", []);
    // One-time cleanup: remove device_users entries where device_id doesn't exist
    // in the devices table (old profile_id entries from pre-v0.2.11 bug).
    // `devices` lives in the operational database now (2026-08-30 store
    // split) — this only still fires on the one boot where identity's copy
    // hasn't been dropped yet; `let _ =` makes it a silent no-op afterwards.
    // The steady-state equivalent is `cleanup_orphan_device_users` (below,
    // cross-database), run from the periodic cleanup task in main.rs.
    let _ = conn.execute(
        "DELETE FROM device_users WHERE device_id NOT IN (SELECT device_id FROM devices)", [],
    );
    // Safe migration: populate user_providers from users for existing accounts.
    let _ = conn.execute_batch("
        INSERT OR IGNORE INTO user_providers (user_id, provider, provider_user_id, display_name, linked_at)
        SELECT id, provider, provider_user_id, display_name, created_at FROM users;
    ");

    // Safe migration: add encrypted_master_key column to sync_e2e_params if not present.
    let _ = conn.execute("ALTER TABLE sync_e2e_params ADD COLUMN encrypted_master_key BLOB DEFAULT NULL", []);

    // Safe migration: add public_id column to users if not present.
    let has_public_id = conn.prepare("SELECT public_id FROM users LIMIT 0").is_ok();
    if !has_public_id {
        conn.execute_batch("ALTER TABLE users ADD COLUMN public_id TEXT;")?;
    }

    // Populate public_id for existing rows that don't have one.
    {
        use rand::Rng;
        let mut stmt = conn.prepare("SELECT id FROM users WHERE public_id IS NULL")?;
        let ids: Vec<i64> = stmt
            .query_map([], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        for id in ids {
            let bytes: [u8; 16] = rand::thread_rng().gen();
            let public_id = hex::encode(bytes);
            conn.execute(
                "UPDATE users SET public_id = ?1 WHERE id = ?2",
                params![public_id, id],
            )?;
        }
    }

    // Create unique index on public_id (if not exists).
    conn.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_public_id ON users(public_id);",
    )?;

    // Safe migration: add the account nick to users (operator ruling
    // 2026-09-05). NULL means "not chosen" — the displayed label falls back
    // to display_name, then public_id (see db::effective_label_for_user);
    // nick is never backfilled from display_name because OAuth display
    // names are not guaranteed unique. Like paid_until and public_id above,
    // an existing installation only ever gains these columns through the
    // ALTERs below — CREATE TABLE users up top is never edited for them.
    let _ = conn.execute("ALTER TABLE users ADD COLUMN nick TEXT", []);
    let _ = conn.execute("ALTER TABLE users ADD COLUMN nick_changed_at TEXT", []);
    // Case-insensitive uniqueness, only enforced once a nick is chosen — must
    // run after the ALTERs above so the column exists on every installation.
    conn.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_nick_lower ON users(LOWER(nick)) WHERE nick IS NOT NULL;",
    )?;

    // Safe migration: add profile_id column to sync_items (for multi-profile scoping).
    let _ = conn.execute("ALTER TABLE sync_items ADD COLUMN profile_id TEXT NOT NULL DEFAULT ''", []);

    // Safe migration: add device_id column to sync_items (for per-device scoping).
    let _ = conn.execute("ALTER TABLE sync_items ADD COLUMN device_id TEXT NOT NULL DEFAULT ''", []);

    // Safe migration: drop old unique indexes and create device+profile-scoped ones for sync_items.
    // This replaces any earlier (user_id, profile_id, category, name) index with one that also
    // includes device_id, so each device/profile combination has its own namespace.
    let _ = conn.execute_batch("
        DROP INDEX IF EXISTS sqlite_autoindex_sync_items_1;
        DROP INDEX IF EXISTS idx_sync_items_user_profile_cat_name;
        -- Removed: UNIQUE(user_id, device_id, profile_id, category, name) — PK now covers this.
        DROP INDEX IF EXISTS idx_sync_user_modified;
        DROP INDEX IF EXISTS idx_sync_user_profile_modified;
        CREATE INDEX IF NOT EXISTS idx_sync_user_device_profile_modified
            ON sync_items(user_id, device_id, profile_id, modified_at);
        DROP INDEX IF EXISTS idx_sync_user_deleted;
        DROP INDEX IF EXISTS idx_sync_user_profile_deleted;
        CREATE INDEX IF NOT EXISTS idx_sync_user_device_profile_deleted
            ON sync_items(user_id, device_id, profile_id, deleted, modified_at);
    ");

    // Safe migration: recreate sync_e2e_params with composite PK (user_id, profile_id).
    // SQLite cannot ALTER PRIMARY KEY, so we create a v2 table, migrate data, then rename.
    let has_e2e_v2 = conn
        .prepare("SELECT profile_id FROM sync_e2e_params LIMIT 0")
        .is_ok();
    if !has_e2e_v2 {
        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS sync_e2e_params_v2 (
                user_id              INTEGER NOT NULL,
                profile_id           TEXT    NOT NULL DEFAULT '',
                salt                 TEXT    NOT NULL,
                iterations           INTEGER NOT NULL DEFAULT 600000,
                created_at           TEXT    NOT NULL,
                encrypted_master_key BLOB    DEFAULT NULL,
                PRIMARY KEY (user_id, profile_id)
            );
            INSERT OR IGNORE INTO sync_e2e_params_v2
                (user_id, profile_id, salt, iterations, created_at, encrypted_master_key)
                SELECT user_id, '' AS profile_id, salt, iterations, created_at, encrypted_master_key
                FROM sync_e2e_params;
            DROP TABLE sync_e2e_params;
            ALTER TABLE sync_e2e_params_v2 RENAME TO sync_e2e_params;
        ")?;
    }

    // Migrate sync_items: PK from (sync_id) to (user_id, device_id, profile_id, sync_id).
    // Check if old schema by looking for the old PK structure.
    let needs_sync_migration: bool = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='sync_items'",
            [],
            |row| row.get::<_, String>(0),
        )
        .map(|sql| sql.contains("sync_id     TEXT    PRIMARY KEY") || sql.contains("sync_id TEXT PRIMARY KEY"))
        .unwrap_or(false);
    if needs_sync_migration {
        tracing::info!("Migrating sync_items: PK (sync_id) → (user_id, device_id, profile_id, sync_id)");
        conn.execute_batch("
            CREATE TABLE sync_items_v2 (
                user_id     INTEGER NOT NULL,
                device_id   TEXT    NOT NULL DEFAULT '',
                profile_id  TEXT    NOT NULL DEFAULT '',
                sync_id     TEXT    NOT NULL,
                category    TEXT    NOT NULL,
                name        TEXT    NOT NULL,
                content     BLOB    NOT NULL,
                checksum    TEXT    NOT NULL,
                modified_at INTEGER NOT NULL,
                deleted     INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT    NOT NULL,
                PRIMARY KEY (user_id, device_id, profile_id, sync_id)
            );
            INSERT OR IGNORE INTO sync_items_v2
                (user_id, device_id, profile_id, sync_id, category, name, content, checksum, modified_at, deleted, created_at)
                SELECT user_id, device_id, profile_id, sync_id, category, name, content, checksum, modified_at, deleted, created_at
                FROM sync_items;
            DROP TABLE sync_items;
            ALTER TABLE sync_items_v2 RENAME TO sync_items;
            CREATE INDEX IF NOT EXISTS idx_sync_user_device_profile_modified
                ON sync_items(user_id, device_id, profile_id, modified_at);
            CREATE INDEX IF NOT EXISTS idx_sync_user_device_profile_deleted
                ON sync_items(user_id, device_id, profile_id, deleted, modified_at);
        ")?;
        tracing::info!("sync_items migration complete");
    }

    // Clean up orphan users left behind by merge/link operations.
    let cleaned = cleanup_orphan_users(&conn)?;
    if cleaned > 0 {
        tracing::info!("Cleaned up {} orphan user(s) with no linked providers", cleaned);
    }

    // Safe migration: widen releases UNIQUE from (version, platform) to (version, platform, channel).
    let needs_releases_migration: bool = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='releases'",
            [],
            |row| row.get::<_, String>(0),
        )
        .map(|sql| sql.contains("UNIQUE(version, platform)"))
        .unwrap_or(false);

    if needs_releases_migration {
        conn.execute_batch("
            CREATE TABLE releases_v2 (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                version      TEXT    NOT NULL,
                platform     TEXT    NOT NULL,
                channel      TEXT    NOT NULL DEFAULT 'stable',
                sha256       TEXT    NOT NULL,
                file_path    TEXT    NOT NULL,
                file_size    INTEGER NOT NULL DEFAULT 0,
                release_notes TEXT   NOT NULL DEFAULT '',
                signature    TEXT    NOT NULL DEFAULT '',
                created_at   TEXT    NOT NULL,
                UNIQUE(version, platform, channel)
            );
            INSERT OR IGNORE INTO releases_v2
                (id, version, platform, channel, sha256, file_path, file_size, release_notes, signature, created_at)
                SELECT id, version, platform,
                       COALESCE(channel, 'stable') AS channel,
                       sha256, file_path, file_size,
                       release_notes, signature, created_at
                FROM releases;
            DROP TABLE releases;
            ALTER TABLE releases_v2 RENAME TO releases;
        ")?;
    }

    Ok(conn)
}

/// Delete users who have no entries in `user_providers`.
///
/// These orphan rows are sometimes left behind when a merge or link operation
/// moves all provider identities to a canonical user account without removing
/// the now-empty source row from `users`.
///
/// Returns the number of deleted rows.
pub fn cleanup_orphan_users(conn: &rusqlite::Connection) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM users WHERE id NOT IN (SELECT DISTINCT user_id FROM user_providers)",
        [],
    )
}

// ============================================================================
// Operational database (2026-08-30 store split)
//
// `devices`, `device_profile`/`device_metrics` and `releases` live here, not
// in the SQLCipher identity database — none of them is irreplaceable
// identity data, and none needs the SQLCipher key. See
// docs/mlc/audits/2026-08-30-entry-lock-vault-and-user-persistence.md §6/§11.
// `device_users` deliberately stays in identity: it is a relationship between
// an account and a device, not a heartbeat.
//
// `telemetry` (one wide table, every column on every post) was replaced on
// 2026-08-31 by `device_profile` (near-immutable hardware/software facts,
// written only when they change) + `device_metrics` (the actual time series,
// capped per device per day) — see
// docs/mlc/plans/data-domains-identity-and-fingerprinting-2026-08-30.md §3.
// The old table is dropped by `drop_legacy_telemetry_table`, called from
// `init_ops_db`.
//
// Every function below the "Devices" / "Telemetry" / "Releases" section
// headers still takes a plain `&Connection` — same as before the split — the
// caller is simply expected to pass the operational connection
// (`ControlPlane::ops_db`) instead of the identity one now.
// ============================================================================

/// Initialize the operational database: `devices`, `device_profile`,
/// `device_metrics`, `releases`.
///
/// Plain SQLite, no SQLCipher key (see `ControlPlane::ops_db`'s doc comment
/// for why) — opened independently of the identity database's key wait, so a
/// box with no key pushed yet can still accept heartbeats and serve OTA
/// manifests.
pub fn init_ops_db(path: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    // 2026-09-01: a second connection to this same file now exists — the
    // dedicated `OpsWriter` thread (see `opswriter.rs`) — so this is no
    // longer the only connection touching the database. WAL already lets
    // readers and a writer coexist without blocking each other, but two
    // connections contending for the same page during a checkpoint is
    // exactly the case a missing busy timeout turns into a bare
    // `SQLITE_BUSY` error instead of a short, bounded wait.
    conn.execute_batch("PRAGMA busy_timeout=5000;")?;

    // Same columns and constraints as the identity tables these replace —
    // `releases` here is the already-migrated shape (channel + signature +
    // the widened UNIQUE), since that is what a fresh operational database
    // should start as, not the pre-migration shape identity's own history
    // carries.
    //
    // `device_profile` / `device_metrics` replace the single wide `telemetry`
    // table (2026-08-31 split, see the section header above this function):
    // `device_profile` holds the six facts that only change when the
    // hardware or build does (one row per device, upserted only on an actual
    // change — see `upsert_device_profile`); `device_metrics` is the real
    // time series and is what the per-device daily cap and the retention
    // ring both apply to. The `(device_id, received_at)` index serves both.
    conn.execute_batch(r#"
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            device_name TEXT NOT NULL DEFAULT '',
            app_version TEXT NOT NULL,
            os TEXT NOT NULL DEFAULT '',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            total_heartbeats INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS device_profile (
            device_id TEXT PRIMARY KEY,
            app_version TEXT NOT NULL DEFAULT '',
            os TEXT NOT NULL DEFAULT '',
            arch TEXT NOT NULL DEFAULT '',
            gpu_name TEXT NOT NULL DEFAULT '',
            screen_width INTEGER NOT NULL DEFAULT 0,
            screen_height INTEGER NOT NULL DEFAULT 0,
            first_seen TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS device_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            user_id INTEGER,
            received_at TEXT NOT NULL,
            connector_count INTEGER NOT NULL DEFAULT 0,
            window_count INTEGER NOT NULL DEFAULT 0,
            avg_fps REAL NOT NULL DEFAULT 0,
            uptime_secs INTEGER NOT NULL DEFAULT 0,
            total_bars INTEGER NOT NULL DEFAULT 0,
            ws_connections INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_device_metrics_device_received
            ON device_metrics(device_id, received_at);

        CREATE TABLE IF NOT EXISTS releases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version TEXT NOT NULL,
            platform TEXT NOT NULL,
            channel TEXT NOT NULL DEFAULT 'stable',
            sha256 TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER NOT NULL DEFAULT 0,
            release_notes TEXT NOT NULL DEFAULT '',
            signature TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            UNIQUE(version, platform, channel)
        );
    "#)?;

    // `telemetry` (the pre-split wide table) is superseded by `device_profile`
    // + `device_metrics` above. It held zero rows in production at the time
    // of this change; this still verifies rather than assumes — see the
    // function doc.
    drop_legacy_telemetry_table(&conn)?;

    Ok(conn)
}

/// Does a table with this name exist in `conn`?
fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
        params![name],
        |_| Ok(()),
    )
    .optional()
    .map(|found| found.is_some())
}

/// Drop the pre-2026-08-31 `telemetry` table from the operational database,
/// now that `device_profile` + `device_metrics` replace it.
///
/// Verified, not assumed: a non-empty `telemetry` table is left in place with
/// a loud error instead of being silently dropped, the same discipline
/// `move_legacy_table` (below) uses for the 2026-08-30 identity→operational
/// move. Idempotent: a `telemetry` table already gone (fresh install, or any
/// boot after the first successful drop) is a silent no-op.
fn drop_legacy_telemetry_table(ops_conn: &Connection) -> Result<()> {
    if !table_exists(ops_conn, "telemetry")? {
        return Ok(());
    }
    let count: i64 = ops_conn.query_row("SELECT COUNT(*) FROM telemetry", [], |row| row.get(0))?;
    if count > 0 {
        tracing::error!(
            "telemetry table holds {} row(s) — NOT dropping. Expected empty per the \
             2026-08-31 device_profile/device_metrics split; investigate before removing.",
            count
        );
        return Ok(());
    }
    ops_conn.execute("DROP TABLE telemetry", [])?;
    tracing::info!("Dropped legacy empty telemetry table (replaced by device_profile/device_metrics)");
    Ok(())
}

/// One-time move of `devices` and `releases` out of the identity database
/// into the operational database. Called once at boot, after both
/// connections are open (see main.rs).
///
/// For each table: if it still exists in `identity_conn`, copy every row into
/// `ops_conn` (`INSERT OR IGNORE`, so a crash between the copy and the drop
/// on a previous boot doesn't fail a retry), compare row counts, and only
/// then `DROP TABLE` it from identity. A count mismatch aborts that table's
/// drop — both copies are left in place — and logs a loud error rather than
/// silently losing rows.
///
/// `telemetry` was a third leg of this same 2026-08-30 move and is no longer
/// copied: the wide `telemetry` shape has no destination table after the
/// 2026-08-31 device_profile/device_metrics split, and production's copy was
/// confirmed empty before that split. It is now *retired* rather than moved —
/// see [`drop_legacy_identity_telemetry`] below for the identity side and
/// `drop_legacy_telemetry_table` (called from `init_ops_db`) for the
/// operational one. Both refuse to drop a table that turns out to hold rows.
///
/// Idempotent: a table missing from `sqlite_master` in identity (already
/// moved, or a fresh install — identity's own `init_db` no longer creates
/// these) is skipped with no log line. A table that does get moved logs
/// exactly one line with its row count, including zero.
pub fn migrate_legacy_ops_tables(identity_conn: &Connection, ops_conn: &Connection) -> Result<()> {
    move_legacy_table(
        identity_conn,
        ops_conn,
        "devices",
        "device_id, device_name, app_version, os, first_seen, last_seen, total_heartbeats",
        7,
    )?;
    move_legacy_table(
        identity_conn,
        ops_conn,
        "releases",
        "id, version, platform, channel, sha256, file_path, file_size, \
         release_notes, signature, created_at",
        10,
    )?;
    drop_legacy_identity_telemetry(identity_conn)?;
    Ok(())
}

/// Retire an identity-side `telemetry` table left over from before the
/// 2026-08-30 store split.
///
/// The migration leg that used to copy this table is gone — its destination
/// no longer exists after the device_profile/device_metrics split. Without
/// this, a box restored from a pre-split backup would carry a stray
/// `telemetry` table in the identity database forever, quietly breaking the
/// property the split exists to establish: identity holds only identity.
///
/// Same discipline as [`drop_legacy_telemetry_table`] on the operational
/// side — a non-empty table is left alone with a loud error, because the only
/// reason it would be non-empty is that an assumption behind the split was
/// wrong, and that deserves a human rather than a `DROP`.
fn drop_legacy_identity_telemetry(identity_conn: &Connection) -> Result<()> {
    if !table_exists(identity_conn, "telemetry")? {
        return Ok(());
    }
    let count: i64 =
        identity_conn.query_row("SELECT COUNT(*) FROM telemetry", [], |row| row.get(0))?;
    if count > 0 {
        tracing::error!(
            "identity.telemetry holds {} row(s) — NOT dropping. The 2026-08-31 split assumed \
             every box had already emptied it; investigate before removing.",
            count
        );
        return Ok(());
    }
    identity_conn.execute("DROP TABLE telemetry", [])?;
    tracing::info!("Dropped the empty legacy identity.telemetry table");
    Ok(())
}

/// Copy every row of `table` from `identity_conn` to `ops_conn` using the
/// exact column list in `columns`, verify the row count, then drop it from
/// identity. `column_count` is `columns`' length, needed up front to build
/// the `?1..?N` placeholder list generically for either caller.
///
/// Rows are read and re-inserted as `rusqlite::types::Value` — the schema is
/// identical on both sides (see `init_ops_db`), so no per-column type
/// conversion is needed, and a single generic function covers both tables
/// instead of one hand-written copy per table.
fn move_legacy_table(
    identity_conn: &Connection,
    ops_conn: &Connection,
    table: &str,
    columns: &str,
    column_count: usize,
) -> Result<()> {
    if !table_exists(identity_conn, table)? {
        return Ok(());
    }

    let rows: Vec<Vec<rusqlite::types::Value>> = {
        let mut stmt = identity_conn.prepare(&format!("SELECT {} FROM {}", columns, table))?;
        let mapped = stmt.query_map([], |row| {
            let mut vals: Vec<rusqlite::types::Value> = Vec::with_capacity(column_count);
            for i in 0..column_count {
                vals.push(row.get(i)?);
            }
            Ok(vals)
        })?;
        mapped.collect::<Result<Vec<Vec<rusqlite::types::Value>>>>()?
    };
    let source_count = rows.len();

    let dest_before: i64 =
        ops_conn.query_row(&format!("SELECT COUNT(*) FROM {}", table), [], |row| row.get(0))?;

    let placeholders = (1..=column_count).map(|i| format!("?{}", i)).collect::<Vec<_>>().join(", ");
    let insert_sql = format!(
        "INSERT OR IGNORE INTO {} ({}) VALUES ({})",
        table, columns, placeholders
    );
    for row in &rows {
        let bound: Vec<&dyn rusqlite::ToSql> = row.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
        ops_conn.execute(&insert_sql, bound.as_slice())?;
    }

    let dest_after: i64 =
        ops_conn.query_row(&format!("SELECT COUNT(*) FROM {}", table), [], |row| row.get(0))?;

    // On a fresh operational database the copy must be exact. On a re-run after
    // an interrupted migration the destination already holds these rows and
    // `INSERT OR IGNORE` skips them, so the test relaxes to "nothing is
    // missing" — otherwise an interrupted migration could never finish, and the
    // identity table would be carried forever.
    let verified = if dest_before == 0 {
        dest_after == source_count as i64
    } else {
        dest_after >= source_count as i64
    };
    if !verified {
        tracing::error!(
            "{} migration verification FAILED: identity had {} row(s), operational held {} before \
             and {} after — leaving both copies in place, NOT dropping identity.{}",
            table, source_count, dest_before, dest_after, table
        );
        return Ok(());
    }

    identity_conn.execute(&format!("DROP TABLE {}", table), [])?;
    tracing::info!("Migrated {} row(s) from identity.{} to the operational database", source_count, table);
    Ok(())
}

/// Delete `device_metrics` rows older than `retention_days` from the
/// operational database — the retention ring for the telemetry time series
/// (see `device_metrics`' doc comment in `init_ops_db` for the split from
/// `device_profile`). Applied by the periodic cleanup task in main.rs; the
/// day count comes from `MLC_TELEMETRY_RETENTION_DAYS` (default 30).
///
/// Returns the number of rows deleted.
pub fn cleanup_old_telemetry(conn: &Connection, retention_days: i64) -> rusqlite::Result<usize> {
    let threshold = (chrono::Utc::now() - chrono::Duration::days(retention_days)).to_rfc3339();
    conn.execute("DELETE FROM device_metrics WHERE received_at < ?1", params![threshold])
}

/// Delete `device_profile` rows untouched for `retention_days` — a much
/// longer horizon than `device_metrics` gets, since a profile row is one per
/// device and near-free to keep. Pruned by its own `updated_at`, NOT by
/// joining against `devices`: an empty or reset operational store must never
/// be able to delete rows on the strength of what it does *not* contain —
/// see `purge_orphan_device_users`'s doc comment for the incident that
/// pattern already caused once (seven `device_users` rows lost).
///
/// `retention_days` comes from `MLC_DEVICE_PROFILE_RETENTION_DAYS` (default 180).
///
/// Returns the number of rows deleted.
pub fn cleanup_stale_device_profiles(conn: &Connection, retention_days: i64) -> rusqlite::Result<usize> {
    let threshold = (chrono::Utc::now() - chrono::Duration::days(retention_days)).to_rfc3339();
    conn.execute("DELETE FROM device_profile WHERE updated_at < ?1", params![threshold])
}

/// Query every `device_id` currently known to the operational database.
fn known_device_ids(ops_conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = ops_conn.prepare("SELECT device_id FROM devices")?;
    let ids = stmt.query_map([], |row| row.get::<_, String>(0))?.collect();
    ids
}

/// Delete `device_users` rows (identity) whose `device_id` is not among
/// `known_ids` (from the operational `devices` table), optionally scoped to
/// one user. Shared by `cleanup_orphan_device_users` and
/// `confirm_link_token` — both used to do this with a single SQL subquery
/// before `devices` moved to a separate database file; a subquery can't span
/// two connections, so the known-id set is fetched once and passed in here.
fn purge_orphan_device_users(
    identity_conn: &Connection,
    known_ids: &[String],
    user_id: Option<i64>,
) -> Result<usize> {
    // An empty operational store means "no information", never "no device
    // exists". The operational database is disposable and unbacked by design —
    // it can be deleted, reset, or emptied by retention at any time. The old
    // single-database form of this cleanup was a `NOT IN (SELECT ...)`
    // subquery, which against an empty `devices` table matches every row and
    // would delete every account-to-device link in the backed-up identity
    // database. That coupling must not survive the split.
    if known_ids.is_empty() {
        return Ok(0);
    }

    let placeholders = known_ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let mut sql = format!("DELETE FROM device_users WHERE device_id NOT IN ({})", placeholders);
    let mut bound: Vec<&dyn rusqlite::ToSql> = known_ids.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
    if let Some(uid) = user_id.as_ref() {
        sql.push_str(" AND user_id = ?");
        bound.push(uid);
    }
    identity_conn.execute(&sql, bound.as_slice())
}

/// Remove `device_users` rows (identity) whose device no longer exists in the
/// operational `devices` table — the steady-state counterpart of the
/// one-time cleanup in `init_db` (which stops firing once `devices` is gone
/// from identity). Run from the periodic cleanup task alongside
/// `cleanup_stale_devices`.
///
/// Returns the number of rows deleted.
pub fn cleanup_orphan_device_users(identity_conn: &Connection, ops_conn: &Connection) -> Result<usize> {
    let known_ids = known_device_ids(ops_conn)?;
    purge_orphan_device_users(identity_conn, &known_ids, None)
}

// ============================================================================
// Devices
// ============================================================================

/// Upsert a device heartbeat record.
pub fn upsert_device(
    conn: &Connection,
    device_id: &str,
    device_name: &str,
    app_version: &str,
    os: &str,
    now: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO devices (device_id, device_name, app_version, os, first_seen, last_seen, total_heartbeats)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1)
         ON CONFLICT(device_id) DO UPDATE SET
             device_name = CASE WHEN ?2 != '' THEN ?2 ELSE device_name END,
             app_version = ?3,
             os = CASE WHEN ?4 != '' THEN ?4 ELSE os END,
             last_seen = ?5,
             total_heartbeats = total_heartbeats + 1",
        params![device_id, device_name, app_version, os, now],
    )?;
    Ok(())
}

// ============================================================================
// Telemetry
//
// Split by mutability (2026-08-31, see `init_ops_db`'s doc comment):
// `device_profile` — one row per device, the near-immutable hardware/build
// facts, written only when they change (`upsert_device_profile`);
// `device_metrics` — the actual time series, subject to the per-device daily
// cap (`count_device_metrics_today`) and the retention ring
// (`cleanup_old_telemetry`, above).
// ============================================================================

/// The six near-immutable hardware/software facts tracked per device in
/// `device_profile`. Grouped into one struct so `upsert_device_profile` can
/// compare "did anything change" as a single equality check instead of six
/// separate parameters.
#[derive(Debug, PartialEq)]
pub struct DeviceProfileFields {
    pub app_version: String,
    pub os: String,
    pub arch: String,
    pub gpu_name: String,
    pub screen_width: i64,
    pub screen_height: i64,
}

/// Write `device_id`'s profile row only if `fields` differs from what is
/// already stored (or nothing is stored yet). A device whose hardware and
/// build are unchanged since its last post produces no write at all here —
/// `updated_at` only moves when something actually changed, which is also
/// what `cleanup_stale_device_profiles` prunes by.
///
/// Returns `true` if a row was inserted or updated, `false` if the existing
/// row already matched `fields` and nothing was written.
pub fn upsert_device_profile(
    conn: &Connection,
    device_id: &str,
    fields: &DeviceProfileFields,
    now: &str,
) -> Result<bool> {
    let existing: Option<DeviceProfileFields> = conn
        .query_row(
            "SELECT app_version, os, arch, gpu_name, screen_width, screen_height
             FROM device_profile WHERE device_id = ?1",
            params![device_id],
            |row| {
                Ok(DeviceProfileFields {
                    app_version: row.get(0)?,
                    os: row.get(1)?,
                    arch: row.get(2)?,
                    gpu_name: row.get(3)?,
                    screen_width: row.get(4)?,
                    screen_height: row.get(5)?,
                })
            },
        )
        .optional()?;

    if existing.as_ref() == Some(fields) {
        return Ok(false);
    }

    conn.execute(
        "INSERT INTO device_profile
            (device_id, app_version, os, arch, gpu_name, screen_width, screen_height, first_seen, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
         ON CONFLICT(device_id) DO UPDATE SET
             app_version = ?2, os = ?3, arch = ?4, gpu_name = ?5,
             screen_width = ?6, screen_height = ?7, updated_at = ?8",
        params![
            device_id, fields.app_version, fields.os, fields.arch, fields.gpu_name,
            fields.screen_width, fields.screen_height, now,
        ],
    )?;
    Ok(true)
}

/// Count `device_metrics` rows for `device_id` received on `today`
/// (`"YYYY-MM-DD"`, UTC). `received_at` is stored as RFC 3339 UTC, so a
/// 10-byte date-prefix match is exact with no timezone conversion needed.
/// Used by the ingest route to enforce `MLC_TELEMETRY_DAILY_CAP` — the one
/// volume control that does not depend on a well-behaved client.
pub fn count_device_metrics_today(conn: &Connection, device_id: &str, today: &str) -> Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM device_metrics WHERE device_id = ?1 AND substr(received_at, 1, 10) = ?2",
        params![device_id, today],
        |row| row.get(0),
    )
}

/// Insert one `device_metrics` row — the time-varying half of a telemetry
/// post (see `upsert_device_profile` for the near-immutable half). The
/// caller is expected to have already checked `count_device_metrics_today`
/// against the daily cap; this function does not enforce it.
#[allow(clippy::too_many_arguments)]
pub fn insert_device_metrics(
    conn: &Connection,
    device_id: &str,
    user_id: Option<i64>,
    received_at: &str,
    connector_count: i64,
    window_count: i64,
    avg_fps: f64,
    uptime_secs: i64,
    total_bars: i64,
    ws_connections: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO device_metrics
            (device_id, user_id, received_at, connector_count, window_count, avg_fps,
             uptime_secs, total_bars, ws_connections)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            device_id, user_id, received_at, connector_count, window_count, avg_fps,
            uptime_secs, total_bars, ws_connections,
        ],
    )?;
    Ok(())
}

// ============================================================================
// Users & tokens
// ============================================================================

/// Upsert a user by provider + provider_user_id.
/// Returns the user's internal id.
pub fn upsert_user(
    conn: &Connection,
    provider: &str,
    provider_user_id: &str,
    display_name: &str,
    now: &str,
) -> Result<i64> {
    // Generate a public_id for new users (ignored on conflict — existing rows keep theirs).
    let public_id = {
        use rand::Rng;
        let bytes: [u8; 16] = rand::thread_rng().gen();
        hex::encode(bytes)
    };
    conn.execute(
        "INSERT INTO users (provider, provider_user_id, display_name, created_at, public_id)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(provider, provider_user_id) DO UPDATE SET
             display_name = ?3",
        params![provider, provider_user_id, display_name, now, public_id],
    )?;
    let id: i64 = conn.query_row(
        "SELECT id FROM users WHERE provider = ?1 AND provider_user_id = ?2",
        params![provider, provider_user_id],
        |row| row.get(0),
    )?;
    Ok(id)
}

/// Link a provider identity to an existing user account.
/// Used when a logged-in user adds a new provider from the dashboard.
///
/// Guards:
/// - If the provider identity is already linked to the same user, just updates display_name.
/// - If the provider identity is already linked to a *different* user, returns a constraint error.
/// - Never touches the `users` table.
pub fn link_provider_to_user(
    conn: &Connection,
    user_id: i64,
    provider: &str,
    provider_user_id: &str,
    display_name: &str,
    now: &str,
) -> Result<()> {
    // Check if this provider identity is already linked to any user.
    let existing_owner: Option<i64> = conn
        .query_row(
            "SELECT user_id FROM user_providers WHERE provider = ?1 AND provider_user_id = ?2",
            params![provider, provider_user_id],
            |row| row.get(0),
        )
        .optional()?;

    if let Some(owner_id) = existing_owner {
        if owner_id == user_id {
            // Already linked to this user — just update display_name.
            conn.execute(
                "UPDATE user_providers SET display_name = ?1, linked_at = ?2 \
                 WHERE user_id = ?3 AND provider = ?4 AND provider_user_id = ?5",
                params![display_name, now, user_id, provider, provider_user_id],
            )?;
            return Ok(());
        } else {
            // Linked to a different user — refuse to steal identity.
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
                Some(format!(
                    "Provider identity {}:{} is already linked to user_id={}",
                    provider, provider_user_id, owner_id
                )),
            ));
        }
    }

    // Not linked yet — insert new row.
    conn.execute(
        "INSERT INTO user_providers (user_id, provider, provider_user_id, display_name, linked_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![user_id, provider, provider_user_id, display_name, now],
    )?;
    Ok(())
}

/// Get the `public_id` for a user. Returns an error if not found.
pub fn get_user_public_id(conn: &Connection, user_id: i64) -> Result<String> {
    conn.query_row(
        "SELECT public_id FROM users WHERE id = ?1",
        params![user_id],
        |row| row.get(0),
    )
}

// ============================================================================
// Account nicks (operator ruling 2026-09-05)
//
// A nick is an account attribute, not a separate identity: on creation the
// column stays NULL and the account is labeled by its OAuth display_name
// (see `effective_label_for_user`'s fallback chain). The user may CHANGE it
// once every `NICK_CHANGE_COOLDOWN_DAYS` to a globally unique (case
// insensitive) handle via `set_nick`. Never backfilled automatically —
// OAuth display names collide across accounts, a chosen nick must not.
// ============================================================================

/// Handles reserved for the project itself — never assignable regardless of
/// case, checked before the uniqueness lookup so they never need a row in
/// `users` to be protected.
const RESERVED_NICKS: &[&str] = &["zengeld", "kosti_x_itsok", "kosti_itsok"];

/// Minimum time between two nick changes on the same account.
const NICK_CHANGE_COOLDOWN_DAYS: i64 = 30;

/// Format rules for a chosen nick: 3-24 ASCII characters, letters/digits plus
/// `_`, `-`, `.`, and the first character must be a letter or digit (so a
/// nick never opens with a separator). Case is preserved in storage —
/// uniqueness is enforced separately, case-insensitively.
pub fn nick_format_valid(nick: &str) -> bool {
    let len = nick.chars().count();
    if !(3..=24).contains(&len) {
        return false;
    }
    let Some(first) = nick.chars().next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    nick.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Why a nick-change attempt was refused (or the DB call itself failed).
#[derive(Debug)]
pub enum NickError {
    /// Fails [`nick_format_valid`]. `routes::account` validates the format
    /// before ever calling `set_nick`, so this is a backstop for any other
    /// caller, not the primary path.
    Invalid,
    /// One of [`RESERVED_NICKS`] (case-insensitive).
    Reserved,
    /// Already claimed by a different account (case-insensitive).
    Taken,
    /// Changed too recently — carries the RFC3339 instant of the last change
    /// and the RFC3339 instant this account may try again.
    RateLimited {
        changed_at: String,
        next_allowed_at: String,
    },
    /// The database call itself failed.
    Db(rusqlite::Error),
}

impl From<rusqlite::Error> for NickError {
    fn from(e: rusqlite::Error) -> Self {
        NickError::Db(e)
    }
}

/// Get the chosen nick for a user, if any. `None` both when the user has
/// never chosen one and when the user row itself is gone.
pub fn nick_for_user(conn: &Connection, user_id: i64) -> Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT nick FROM users WHERE id = ?1",
            params![user_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten())
}

/// The label to show for a user: chosen nick, then `display_name`, then
/// `public_id` — same fallback order as [`share_owner_label`]. Empty string
/// only when the user row itself is gone (an orphaned reference).
pub fn effective_label_for_user(conn: &Connection, user_id: i64) -> Result<String> {
    let row: Option<(Option<String>, String, Option<String>)> = conn
        .query_row(
            "SELECT nick, display_name, public_id FROM users WHERE id = ?1",
            params![user_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    Ok(row
        .map(|(nick, display_name, public_id)| {
            nick.filter(|n| !n.is_empty())
                .or_else(|| Some(display_name).filter(|d| !d.is_empty()))
                .or(public_id)
                .unwrap_or_default()
        })
        .unwrap_or_default())
}

/// Change `user_id`'s nick to `nick`, enforcing format, reserved names,
/// global case-insensitive uniqueness, and the 30-day change cooldown.
///
/// Uniqueness is decided twice, deliberately: the `SELECT ... WHERE
/// LOWER(nick) = ...` pre-check below gives the common case a clear
/// [`NickError::Taken`] without ever reaching the database's own error path
/// (same pattern as [`link_provider_to_user`]'s existing-owner check); the
/// `idx_users_nick_lower` unique index is the actual guarantee under a race
/// between two callers claiming the same nick at once — the loser's `UPDATE`
/// hits the index and is mapped to `Taken` here too, rather than surfaced as
/// a raw constraint error.
pub fn set_nick(conn: &Connection, user_id: i64, nick: &str) -> Result<(), NickError> {
    if !nick_format_valid(nick) {
        return Err(NickError::Invalid);
    }
    let lower = nick.to_lowercase();
    if RESERVED_NICKS.contains(&lower.as_str()) {
        return Err(NickError::Reserved);
    }

    let now = chrono::Utc::now();
    let changed_at: Option<String> = conn
        .query_row(
            "SELECT nick_changed_at FROM users WHERE id = ?1",
            params![user_id],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    if let Some(ref changed_at_str) = changed_at {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(changed_at_str) {
            let next_allowed = dt.with_timezone(&chrono::Utc) + chrono::Duration::days(NICK_CHANGE_COOLDOWN_DAYS);
            if next_allowed > now {
                return Err(NickError::RateLimited {
                    changed_at: changed_at_str.clone(),
                    next_allowed_at: next_allowed.to_rfc3339(),
                });
            }
        }
    }

    let taken_by_other: bool = conn
        .query_row(
            "SELECT 1 FROM users WHERE LOWER(nick) = ?1 AND id != ?2",
            params![lower, user_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if taken_by_other {
        return Err(NickError::Taken);
    }

    let result = conn.execute(
        "UPDATE users SET nick = ?1, nick_changed_at = ?2 WHERE id = ?3",
        params![nick, now.to_rfc3339(), user_id],
    );
    match result {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(err, _)) if err.code == rusqlite::ErrorCode::ConstraintViolation => {
            Err(NickError::Taken)
        }
        Err(e) => Err(NickError::Db(e)),
    }
}

/// Get all provider identities linked to a user.
/// Returns `Vec<(provider, provider_user_id, display_name)>`.
pub fn get_providers_for_user(conn: &Connection, user_id: i64) -> Result<Vec<(String, String, String)>> {
    let mut stmt = conn.prepare(
        "SELECT provider, provider_user_id, display_name FROM user_providers WHERE user_id = ?1 ORDER BY linked_at",
    )?;
    let mut rows = stmt.query(params![user_id])?;
    let mut providers = Vec::new();
    while let Some(row) = rows.next()? {
        providers.push((row.get(0)?, row.get(1)?, row.get(2)?));
    }
    Ok(providers)
}

/// Check if a provider identity is already linked to any user.
/// Returns the `user_id` if linked, `None` otherwise.
#[allow(dead_code)]
pub fn find_user_by_provider(conn: &Connection, provider: &str, provider_user_id: &str) -> Result<Option<i64>> {
    let mut stmt = conn.prepare(
        "SELECT user_id FROM user_providers WHERE provider = ?1 AND provider_user_id = ?2 LIMIT 1",
    )?;
    let mut rows = stmt.query(params![provider, provider_user_id])?;
    if let Some(row) = rows.next()? {
        Ok(Some(row.get(0)?))
    } else {
        Ok(None)
    }
}

/// Insert a hashed token for a user (legacy: no expiry).
#[allow(dead_code)]
pub fn insert_auth_token(conn: &Connection, token_hash: &str, user_id: i64, now: &str) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO auth_tokens (token_hash, user_id, created_at) VALUES (?1, ?2, ?3)",
        params![token_hash, user_id, now],
    )?;
    Ok(())
}

/// Look up user_id by token hash. Returns None if not found.
pub fn resolve_token_hash(conn: &Connection, token_hash: &str) -> Result<Option<i64>> {
    let mut stmt = conn.prepare(
        "SELECT user_id FROM auth_tokens WHERE token_hash = ?1",
    )?;
    let mut rows = stmt.query(params![token_hash])?;
    if let Some(row) = rows.next()? {
        Ok(Some(row.get(0)?))
    } else {
        Ok(None)
    }
}

/// Insert a hashed token with expiration.
pub fn insert_auth_token_with_expiry(
    conn: &Connection,
    token_hash: &str,
    user_id: i64,
    now: &str,
    expires_at: &str,
) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO auth_tokens (token_hash, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![token_hash, user_id, now, expires_at],
    )?;
    Ok(())
}

/// Resolve token hash to user_id, checking expiration.
#[allow(dead_code)]
pub fn resolve_token_hash_with_expiry(conn: &Connection, token_hash: &str) -> Result<Option<i64>> {
    let mut stmt = conn.prepare(
        "SELECT user_id FROM auth_tokens WHERE token_hash = ?1 AND (expires_at IS NULL OR expires_at > datetime('now'))",
    )?;
    let mut rows = stmt.query(params![token_hash])?;
    if let Some(row) = rows.next()? {
        Ok(Some(row.get(0)?))
    } else {
        Ok(None)
    }
}

// ============================================================================
// OAuth states (CSRF protection)
// ============================================================================

/// Insert an OAuth state for CSRF validation.
/// `link_user_id` is `Some(uid)` when this state is part of a "link provider" flow.
pub fn insert_oauth_state(
    conn: &Connection,
    state: &str,
    provider: &str,
    redirect_port: u16,
    now: &str,
    device_id: &str,
    link_user_id: Option<i64>,
    device_code: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO oauth_states (state, provider, redirect_port, created_at, device_id, link_user_id, device_code) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![state, provider, redirect_port as i64, now, device_id, link_user_id, device_code],
    )?;
    Ok(())
}

/// Validate and consume an OAuth state.
/// Returns `(provider, redirect_port, device_id, link_user_id, device_code)` if valid.
/// Deletes the state after consumption (one-time use).
pub fn consume_oauth_state(
    conn: &Connection,
    state: &str,
) -> Result<Option<(String, u16, String, Option<i64>, Option<String>)>> {
    let result: Option<(String, i64, String, Option<i64>, Option<String>)> = {
        let mut stmt = conn.prepare(
            "SELECT provider, redirect_port, device_id, link_user_id, device_code FROM oauth_states WHERE state = ?1",
        )?;
        let mut rows = stmt.query(params![state])?;
        if let Some(row) = rows.next()? {
            Some((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
        } else {
            None
        }
    };
    if result.is_some() {
        conn.execute("DELETE FROM oauth_states WHERE state = ?1", params![state])?;
    }
    Ok(result.map(|(p, port, dev, link_uid, dcode)| (p, port as u16, dev, link_uid, dcode)))
}

/// Clean up expired OAuth states (older than 10 minutes).
pub fn cleanup_oauth_states(conn: &Connection) -> Result<()> {
    conn.execute(
        "DELETE FROM oauth_states WHERE created_at < datetime('now', '-10 minutes')",
        [],
    )?;
    Ok(())
}

// ============================================================================
// Device-user linking
// ============================================================================

/// Link a device to a user. Uses INSERT OR IGNORE so re-linking is a no-op.
pub fn link_device_user(conn: &Connection, device_id: &str, user_id: i64, now: &str) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO device_users (device_id, user_id, linked_at) VALUES (?1, ?2, ?3)",
        params![device_id, user_id, now],
    )?;
    Ok(())
}

/// Return the user_id already linked to this device, if any.
pub fn get_user_for_device(conn: &Connection, device_id: &str) -> Result<Option<i64>> {
    let mut stmt = conn.prepare(
        "SELECT user_id FROM device_users WHERE device_id = ?1 LIMIT 1",
    )?;
    let mut rows = stmt.query(params![device_id])?;
    if let Some(row) = rows.next()? {
        Ok(Some(row.get(0)?))
    } else {
        Ok(None)
    }
}

/// Return all device_ids linked to a user.
#[allow(dead_code)]
pub fn get_devices_for_user(conn: &Connection, user_id: i64) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT device_id FROM device_users WHERE user_id = ?1",
    )?;
    let mut rows = stmt.query(params![user_id])?;
    let mut devices = Vec::new();
    while let Some(row) = rows.next()? {
        devices.push(row.get(0)?);
    }
    Ok(devices)
}

/// Reassign all auth_tokens from `from_user_id` to `to_user_id`.
/// Used during device-merge to consolidate identities under one account.
pub fn reassign_auth_tokens(conn: &Connection, from_user_id: i64, to_user_id: i64) -> Result<()> {
    conn.execute(
        "UPDATE auth_tokens SET user_id = ?1 WHERE user_id = ?2",
        params![to_user_id, from_user_id],
    )?;
    Ok(())
}

// ============================================================================
// Releases
// ============================================================================

/// Insert or replace a release record.
#[allow(clippy::too_many_arguments)]
pub fn upsert_release(
    conn: &Connection,
    version: &str,
    platform: &str,
    channel: &str,
    sha256: &str,
    file_path: &str,
    file_size: i64,
    release_notes: &str,
    signature: &str,
    now: &str,
) -> Result<()> {
    // One version, one binary. Re-registering a version whose BYTES have
    // changed is refused: the updater decides whether a client is current by
    // comparing version numbers alone, so two different binaries under one
    // number are one release to every client that looks — and the second
    // silently replaces the first for everyone who has not updated yet. The
    // web bundle grew the same guard on 2026-09-04 after the same near-miss;
    // this is that guard on the artifact side.
    //
    // Re-registering the IDENTICAL sha256 stays allowed: that is a retry, or a
    // republish after an edge lost a file, and it must not be turned into an
    // error the operator has to work around.
    let existing: Option<String> = conn
        .query_row(
            "SELECT sha256 FROM releases WHERE version = ?1 AND platform = ?2 AND channel = ?3",
            params![version, platform, channel],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(prev) = existing {
        if prev != sha256 {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
                Some(format!(
                    "release {version} for {platform}/{channel} is already registered with a                      different binary (registered sha256={prev}, offered sha256={sha256}) —                      bump the version instead of replacing what clients already trust"
                )),
            ));
        }
    }

    conn.execute(
        "INSERT INTO releases (version, platform, channel, sha256, file_path, file_size, release_notes, signature, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(version, platform, channel) DO UPDATE SET
             file_path = ?5,
             file_size = ?6,
             release_notes = ?7,
             signature = ?8",
        params![version, platform, channel, sha256, file_path, file_size, release_notes, signature, now],
    )?;
    Ok(())
}

/// Get the latest release for a given platform and channel (highest version by created_at).
/// The moment this account's paid access ends, or `None` if it is not
/// currently paid.
///
/// `paid_until` is a moment, so this compares against now rather than
/// trusting a stored yes/no: an expired subscription stops granting anything
/// without anybody having to remember to flip a flag. `Some` is returned only
/// when that moment is still in the future; no row, a `NULL`, and an expired
/// timestamp all read as `None`. This is the one place that decides what
/// "paid" means.
pub fn user_paid_until(conn: &Connection, user_id: i64) -> Result<Option<String>> {
    let until: Option<String> = conn
        .query_row(
            "SELECT paid_until FROM users WHERE id = ?1",
            params![user_id],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    let Some(until) = until else { return Ok(None) };
    if until.as_str() > chrono::Utc::now().to_rfc3339().as_str() {
        Ok(Some(until))
    } else {
        Ok(None)
    }
}

/// Whether this account's paid access is currently in effect.
///
/// `paid_until` is a moment, so this is a comparison against now rather than a
/// stored yes/no: an expired subscription stops granting anything without
/// anybody having to remember to flip a flag. The rule itself lives in
/// `user_paid_until`; this is just its presence check.
pub fn user_is_paid(conn: &Connection, user_id: i64) -> Result<bool> {
    Ok(user_paid_until(conn, user_id)?.is_some())
}

/// Grant or revoke paid access by writing the moment it ends.
///
/// `None` revokes. Used by the admin endpoint today and by the billing
/// webhook once it exists — one writer, so the two cannot disagree about what
/// paid means.
pub fn set_user_paid_until(conn: &Connection, user_id: i64, until: Option<&str>) -> Result<()> {
    conn.execute(
        "UPDATE users SET paid_until = ?1 WHERE id = ?2",
        params![until, user_id],
    )?;
    Ok(())
}

pub fn get_latest_release(
    conn: &Connection,
    platform: &str,
    channel: &str,
) -> Result<Option<ReleaseRow>> {
    let mut stmt = conn.prepare(
        "SELECT version, sha256, file_path, file_size, release_notes, signature, channel
         FROM releases
         WHERE platform = ?1 AND channel = ?2
         ORDER BY created_at DESC
         LIMIT 1",
    )?;
    let mut rows = stmt.query(params![platform, channel])?;
    if let Some(row) = rows.next()? {
        Ok(Some(ReleaseRow {
            version: row.get(0)?,
            sha256: row.get(1)?,
            file_path: row.get(2)?,
            file_size: row.get(3)?,
            release_notes: row.get(4)?,
            signature: row.get(5)?,
            channel: row.get(6)?,
        }))
    } else {
        Ok(None)
    }
}

/// Get a specific release by platform + version + channel.
pub fn get_release(
    conn: &Connection,
    platform: &str,
    version: &str,
    channel: &str,
) -> Result<Option<ReleaseRow>> {
    let mut stmt = conn.prepare(
        "SELECT version, sha256, file_path, file_size, release_notes, signature, channel
         FROM releases
         WHERE platform = ?1 AND version = ?2 AND channel = ?3
         LIMIT 1",
    )?;
    let mut rows = stmt.query(params![platform, version, channel])?;
    if let Some(row) = rows.next()? {
        Ok(Some(ReleaseRow {
            version: row.get(0)?,
            sha256: row.get(1)?,
            file_path: row.get(2)?,
            file_size: row.get(3)?,
            release_notes: row.get(4)?,
            signature: row.get(5)?,
            channel: row.get(6)?,
        }))
    } else {
        Ok(None)
    }
}

/// Copy a dev release row to stable channel in-place (same binary file path).
/// Returns `Ok(false)` if the dev release doesn't exist.
pub fn promote_release(
    conn: &Connection,
    version: &str,
    platform: &str,
    now: &str,
) -> Result<bool> {
    let dev_row = get_release(conn, platform, version, "dev")?;
    let Some(row) = dev_row else {
        return Ok(false);
    };

    upsert_release(
        conn,
        version,
        platform,
        "stable",
        &row.sha256,
        &row.file_path,
        row.file_size,
        &row.release_notes,
        &row.signature,
        now,
    )?;
    Ok(true)
}

/// One row of the published-release catalogue, as `GET /api/updates/list`
/// returns it.
///
/// Separate from [`ReleaseRow`] because that one answers "what should this
/// client install" and deliberately carries the signature; this one answers
/// "what exists" for a human reading a downloads page, and carries the
/// platform and the date instead.
pub struct ReleaseListRow {
    pub platform: String,
    pub version: String,
    pub channel: String,
    pub sha256: String,
    pub file_size: i64,
    pub release_notes: String,
    pub created_at: String,
}

/// Every published release, newest first.
///
/// The `releases` table is the authoritative record of what is actually on the
/// edges: `opsd`'s `release::publish` registers a row only after every edge has
/// received the artifact and verified its sha256, and unwinds what landed if
/// any edge failed. So a downloads page built from this cannot advertise a file
/// that is not there — which is exactly what a hand-maintained list does the
/// first time someone forgets to edit it.
///
/// A full scan, deliberately: the table holds one row per (version, platform,
/// channel) and the whole point is to return all of them. Filtering by channel
/// happens in SQL so the caller cannot accidentally page through a track it
/// does not serve.
pub fn list_releases(conn: &Connection, channel: &str) -> Result<Vec<ReleaseListRow>> {
    let mut stmt = conn.prepare(
        "SELECT platform, version, channel, sha256, file_size, release_notes, created_at
         FROM releases
         WHERE channel = ?1
         ORDER BY created_at DESC, platform ASC",
    )?;
    let rows = stmt.query_map(params![channel], |row| {
        Ok(ReleaseListRow {
            platform: row.get(0)?,
            version: row.get(1)?,
            channel: row.get(2)?,
            sha256: row.get(3)?,
            file_size: row.get(4)?,
            release_notes: row.get(5)?,
            created_at: row.get(6)?,
        })
    })?;
    rows.collect()
}

/// A row from the releases table.
#[derive(Debug, Clone)]
pub struct ReleaseRow {
    pub version: String,
    pub sha256: String,
    pub file_path: String,
    pub file_size: i64,
    pub release_notes: String,
    /// Base64-encoded Ed25519 signature over the binary bytes. Empty string for unsigned releases.
    pub signature: String,
    /// Release channel: "stable" or "dev".
    pub channel: String,
}

// ============================================================================
// Gift / trial codes
//
// An admin mints a code (`mint_gift_codes`); an account redeems it once
// (`redeem_gift_code`) and its `paid_until` moves forward. This is how a
// paid account is granted today, ahead of billing, and it stays the vehicle
// for support-issued gifts/trials once billing exists too.
// ============================================================================

/// Characters usable in a generated gift code: uppercase letters and digits,
/// minus the pairs a human misreads over the phone or copying by hand
/// (`O`/`0`, `I`/`1`). Never accepted from a caller — see [`mint_gift_codes`],
/// the only producer of a code.
const GIFT_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Length of one generated gift code.
const GIFT_CODE_LEN: usize = 10;

/// Generate one random gift code from [`GIFT_CODE_ALPHABET`]. A collision
/// with an already-minted code is possible but vanishingly unlikely at this
/// alphabet size and length (32^10) — [`mint_gift_codes`] still retries on
/// the rare `PRIMARY KEY` collision rather than trusting uniqueness.
fn generate_gift_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..GIFT_CODE_LEN)
        .map(|_| GIFT_CODE_ALPHABET[rng.gen_range(0..GIFT_CODE_ALPHABET.len())] as char)
        .collect()
}

/// Mint `count` new single-use gift/trial codes, each granting `grants_days`
/// days of paid access from the moment it is redeemed (see
/// [`redeem_gift_code`]). `note` is stored for support to see why a batch
/// was minted — it is never shown to the redeeming account.
///
/// Returns the generated codes. This is the only place a gift code is ever
/// readable: no query anywhere else selects `code` back out of the table, so
/// a code that already went out cannot be recovered by reading the
/// database — only reissued as a new one.
pub fn mint_gift_codes(
    conn: &Connection,
    count: u32,
    grants_days: i64,
    note: &str,
    now: &str,
) -> Result<Vec<String>> {
    let mut codes = Vec::with_capacity(count as usize);
    for _ in 0..count {
        loop {
            let code = generate_gift_code();
            let inserted = conn.execute(
                "INSERT OR IGNORE INTO gift_codes (code, grants_days, note, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![code, grants_days, note, now],
            )?;
            if inserted == 1 {
                codes.push(code);
                break;
            }
            // PRIMARY KEY collision (vanishingly unlikely) — draw another code.
        }
    }
    Ok(codes)
}

/// Outcome of a gift/trial code redemption attempt.
pub enum RedeemOutcome {
    /// Redeemed successfully — carries the account's new `paid_until`.
    Redeemed(String),
    /// No `gift_codes` row exists for this code at all.
    NotFound,
    /// The code exists but was already claimed (by this account or another).
    AlreadyUsed,
}

/// Redeem `code` for `user_id`, extending their paid access.
///
/// Single-use under a race: the only state-changing step is the one
/// conditional `UPDATE gift_codes SET redeemed_by = ?1, redeemed_at = ?2
/// WHERE code = ?3 AND redeemed_by IS NULL` below. SQLite serialises writers
/// against the same database, so of two requests racing on the same code at
/// most one `UPDATE` can match `redeemed_by IS NULL` — the loser sees
/// `rows_affected() != 1` and is reported [`RedeemOutcome::AlreadyUsed`],
/// never a second grant. That is why the redemption decision lives entirely
/// inside this one statement rather than a prior `SELECT redeemed_by`
/// followed by a separate `UPDATE` (read-then-write): two concurrent readers
/// could both observe "not yet redeemed" and both then write.
///
/// The `grants_days` lookup ahead of the `UPDATE` does not carry that same
/// race risk: it is immutable once a code is minted (see
/// [`mint_gift_codes`]), so nothing about it can go stale between the read
/// and the write — it exists only to size the grant, not to decide whether
/// one happens.
///
/// `paid_until` is extended, not replaced: `max(now, existing paid_until) +
/// grants_days`, so an account still under an earlier grant gains time
/// instead of losing whatever was left of it.
pub fn redeem_gift_code(
    conn: &Connection,
    code: &str,
    user_id: i64,
    now: &str,
) -> Result<RedeemOutcome> {
    let grants_days: Option<i64> = conn
        .query_row(
            "SELECT grants_days FROM gift_codes WHERE code = ?1",
            params![code],
            |row| row.get(0),
        )
        .optional()?;
    let Some(grants_days) = grants_days else {
        return Ok(RedeemOutcome::NotFound);
    };

    // The one statement that decides single-use — see the doc comment above.
    let rows = conn.execute(
        "UPDATE gift_codes SET redeemed_by = ?1, redeemed_at = ?2 WHERE code = ?3 AND redeemed_by IS NULL",
        params![user_id, now, code],
    )?;
    if rows != 1 {
        return Ok(RedeemOutcome::AlreadyUsed);
    }

    let existing_until: Option<String> = conn
        .query_row(
            "SELECT paid_until FROM users WHERE id = ?1",
            params![user_id],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    let now_dt = chrono::Utc::now();
    let base = existing_until
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .filter(|dt| *dt > now_dt)
        .unwrap_or(now_dt);
    let new_until = (base + chrono::Duration::days(grants_days)).to_rfc3339();

    set_user_paid_until(conn, user_id, Some(&new_until))?;

    Ok(RedeemOutcome::Redeemed(new_until))
}

// ============================================================================
// Share links
//
// An authenticated account publishes one chart either as a 'live' share (the
// frozen ChartPreset JSON sits in `preset_json`, rendered read-only by the
// web viewer) or as a 'screenshot' share (the PNG bytes sit on disk under
// `<data_dir>/share/`, `blob_path` holds the path relative to that root).
// The kind strings are owned by `entitlements::ShareKind::as_str` — the two
// spellings must not drift apart. Timestamps are RFC3339, so `expires_at`
// compares lexicographically (same convention as `users.paid_until`).
//
// Limits and TTLs are decided in `entitlements.rs` (`share_create_allowed`,
// `share_ttl_secs`); this section stores and counts rows, nothing more.
// ============================================================================

/// One row of the `share_links` table.
pub struct ShareLinkRow {
    pub token: String,
    pub user_id: i64,
    pub kind: String,
    pub title: String,
    pub preset_json: String,
    /// Path of the PNG blob relative to `<data_dir>/share/` — empty for live
    /// shares, which carry no file.
    pub blob_path: String,
    pub blob_bytes: i64,
    pub created_at: String,
    pub expires_at: String,
}

/// Read one query row into a [`ShareLinkRow`]. Column order must match the
/// SELECT lists below.
fn share_link_from_row(row: &rusqlite::Row<'_>) -> Result<ShareLinkRow> {
    Ok(ShareLinkRow {
        token: row.get(0)?,
        user_id: row.get(1)?,
        kind: row.get(2)?,
        title: row.get(3)?,
        preset_json: row.get(4)?,
        blob_path: row.get(5)?,
        blob_bytes: row.get(6)?,
        created_at: row.get(7)?,
        expires_at: row.get(8)?,
    })
}

/// Generate one share token: 16 random bytes as 32 lowercase hex characters —
/// the same scheme as `create_link_token`, so share URLs and link tokens are
/// indistinguishable in shape.
fn generate_share_token() -> String {
    use rand::Rng;
    let bytes: [u8; 16] = rand::thread_rng().gen();
    hex::encode(bytes)
}

/// Create one share link and return its token. `created_at`/`expires_at` are
/// RFC3339 strings the caller computed (see `entitlements::share_ttl_secs` for
/// the TTL rule). `blob_path`/`blob_bytes` are empty/0 for a live share; for
/// a screenshot the caller passes the relative blob path it already derived
/// from the token… except the token only exists inside this function, so the
/// caller passes an empty `blob_path` first and stamps the real one with
/// [`set_share_blob_path`] once the token is known and the file is written.
///
/// Retries on the vanishingly unlikely PRIMARY KEY collision, same as
/// [`mint_gift_codes`].
pub fn create_share_link(
    conn: &Connection,
    user_id: i64,
    kind: &str,
    title: &str,
    preset_json: &str,
    blob_bytes: i64,
    created_at: &str,
    expires_at: &str,
) -> Result<String> {
    loop {
        let token = generate_share_token();
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO share_links (token, user_id, kind, title, preset_json, blob_path, blob_bytes, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, '', ?6, ?7, ?8)",
            params![token, user_id, kind, title, preset_json, blob_bytes, created_at, expires_at],
        )?;
        if inserted == 1 {
            return Ok(token);
        }
        // PRIMARY KEY collision (vanishingly unlikely) — draw another token.
    }
}

/// Stamp the real blob path onto a freshly created screenshot share (see
/// [`create_share_link`] for why the path cannot be known at INSERT time).
pub fn set_share_blob_path(conn: &Connection, token: &str, blob_path: &str) -> Result<()> {
    conn.execute(
        "UPDATE share_links SET blob_path = ?2 WHERE token = ?1",
        params![token, blob_path],
    )?;
    Ok(())
}

/// Fetch one share link for public viewing: only a live row comes back —
/// revoked or past-`expires_at` shares are indistinguishable from unknown
/// tokens here, so the public route can answer one bare 404 for all three.
pub fn get_share_link(conn: &Connection, token: &str) -> Result<Option<ShareLinkRow>> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.query_row(
        "SELECT token, user_id, kind, title, preset_json, blob_path, blob_bytes, created_at, expires_at
         FROM share_links
         WHERE token = ?1 AND revoked = 0 AND expires_at > ?2",
        params![token, now],
        share_link_from_row,
    )
    .optional()
}

/// Count the caller's active (non-revoked, non-expired) shares of each kind:
/// (live, screenshot). This is the number the entitlement gate in
/// `routes/share.rs` compares against `entitlements::share_limit`.
pub fn share_usage(conn: &Connection, user_id: i64) -> Result<(u64, u64)> {
    let now = chrono::Utc::now().to_rfc3339();
    let live: i64 = conn.query_row(
        "SELECT COUNT(*) FROM share_links WHERE user_id = ?1 AND kind = 'live' AND revoked = 0 AND expires_at > ?2",
        params![user_id, now],
        |row| row.get(0),
    )?;
    let screenshot: i64 = conn.query_row(
        "SELECT COUNT(*) FROM share_links WHERE user_id = ?1 AND kind = 'screenshot' AND revoked = 0 AND expires_at > ?2",
        params![user_id, now],
        |row| row.get(0),
    )?;
    Ok((live as u64, screenshot as u64))
}

/// List the caller's active shares, newest first — the body of
/// `GET /api/share/mine`.
pub fn list_share_links(conn: &Connection, user_id: i64) -> Result<Vec<ShareLinkRow>> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut stmt = conn.prepare(
        "SELECT token, user_id, kind, title, preset_json, blob_path, blob_bytes, created_at, expires_at
         FROM share_links
         WHERE user_id = ?1 AND revoked = 0 AND expires_at > ?2
         ORDER BY created_at DESC",
    )?;
    let mut rows = stmt.query(params![user_id, now])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(share_link_from_row(row)?);
    }
    Ok(out)
}

/// Revoke one share link, owner-only: the `user_id` in the WHERE clause is
/// what makes "someone else's token" answer `false` exactly like "no such
/// token", so the route can 404 both without leaking existence. Already-
/// revoked rows likewise answer `false`.
pub fn revoke_share(conn: &Connection, user_id: i64, token: &str) -> Result<bool> {
    let n = conn.execute(
        "UPDATE share_links SET revoked = 1 WHERE token = ?1 AND user_id = ?2 AND revoked = 0",
        params![token, user_id],
    )?;
    Ok(n > 0)
}

/// Delete every expired share link (any owner, revoked or not) and return the
/// `(token, blob_path)` pairs so the caller can unlink the PNG files — the
/// database cannot reach the filesystem itself. Live shares have an empty
/// `blob_path`; callers must skip those.
pub fn cleanup_expired_share_links(conn: &Connection) -> Result<Vec<(String, String)>> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut stmt = conn.prepare(
        "SELECT token, blob_path FROM share_links WHERE expires_at <= ?1",
    )?;
    let mut rows = stmt.query(params![now])?;
    let mut expired = Vec::new();
    while let Some(row) = rows.next()? {
        expired.push((row.get::<_, String>(0)?, row.get::<_, String>(1)?));
    }
    drop(rows);
    drop(stmt);
    conn.execute(
        "DELETE FROM share_links WHERE expires_at <= ?1",
        params![now],
    )?;
    Ok(expired)
}

/// The public owner label for a share: chosen nick, then `display_name`,
/// then `public_id` — [`effective_label_for_user`]'s fallback chain, the one
/// name a share ever exposes. Returns `None` only when the user row itself
/// is gone (a share outliving its account); wraps rather than duplicates the
/// chain so the two can never drift apart.
pub fn share_owner_label(conn: &Connection, user_id: i64) -> Result<Option<String>> {
    let exists: bool = conn
        .query_row("SELECT 1 FROM users WHERE id = ?1", params![user_id], |_| Ok(()))
        .optional()?
        .is_some();
    if !exists {
        return Ok(None);
    }
    Ok(Some(effective_label_for_user(conn, user_id)?))
}

// ============================================================================
// Web sessions
// ============================================================================

/// Create a web session. Returns the session_id (32-byte hex, 64 chars).
/// `ua_hash` is a fingerprint of the User-Agent header for session binding.
pub fn create_web_session(conn: &Connection, user_id: i64, now: &str, expires_at: &str, ua_hash: &str) -> Result<String> {
    let session_id: String = {
        use rand::Rng;
        let bytes: [u8; 32] = rand::thread_rng().gen();
        hex::encode(bytes)
    };
    conn.execute(
        "INSERT INTO web_sessions (session_id, user_id, created_at, expires_at, ua_hash) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![session_id, user_id, now, expires_at, ua_hash],
    )?;
    Ok(session_id)
}

/// Resolve session_id to user_id, validating the User-Agent fingerprint.
/// Returns None if expired, not found, or if the ua_hash does not match.
pub fn resolve_web_session(conn: &Connection, session_id: &str, ua_hash: &str) -> Result<Option<i64>> {
    let mut stmt = conn.prepare(
        "SELECT user_id FROM web_sessions WHERE session_id = ?1 AND ua_hash = ?2 AND expires_at > datetime('now')",
    )?;
    let mut rows = stmt.query(params![session_id, ua_hash])?;
    if let Some(row) = rows.next()? {
        Ok(Some(row.get(0)?))
    } else {
        Ok(None)
    }
}

/// Delete a web session (logout).
pub fn delete_web_session(conn: &Connection, session_id: &str) -> Result<()> {
    conn.execute("DELETE FROM web_sessions WHERE session_id = ?1", params![session_id])?;
    Ok(())
}

// ============================================================================
// Device codes
// ============================================================================

/// A row from the device_codes table.
#[derive(Debug, Clone)]
pub struct DeviceCodeRow {
    pub device_id: String,
    pub user_id: Option<i64>,
    pub status: String,
    pub expires_at: String,
}

/// Create a device code. Returns the code (8 uppercase alphanumeric chars).
pub fn create_device_code(conn: &Connection, device_id: &str, now: &str, expires_at: &str) -> Result<String> {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let code: String = {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..8).map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char).collect()
    };
    conn.execute(
        "INSERT INTO device_codes (code, device_id, user_id, status, created_at, expires_at)
         VALUES (?1, ?2, NULL, 'pending', ?3, ?4)",
        params![code, device_id, now, expires_at],
    )?;
    Ok(code)
}

/// Get device code info. Returns None if the code does not exist.
pub fn get_device_code(conn: &Connection, code: &str) -> Result<Option<DeviceCodeRow>> {
    let mut stmt = conn.prepare(
        "SELECT device_id, user_id, status, expires_at FROM device_codes WHERE code = ?1",
    )?;
    let mut rows = stmt.query(params![code])?;
    if let Some(row) = rows.next()? {
        Ok(Some(DeviceCodeRow {
            device_id: row.get(0)?,
            user_id: row.get(1)?,
            status: row.get(2)?,
            expires_at: row.get(3)?,
        }))
    } else {
        Ok(None)
    }
}

/// Confirm a device code — sets user_id and status='confirmed'.
/// Returns true if the code was found and updated, false otherwise.
pub fn confirm_device_code(conn: &Connection, code: &str, user_id: i64) -> Result<bool> {
    let n = conn.execute(
        "UPDATE device_codes SET user_id = ?1, status = 'confirmed' WHERE code = ?2 AND status = 'pending'",
        params![user_id, code],
    )?;
    Ok(n > 0)
}

/// Mark a device code as 'claimed' (token has been returned to the device).
pub fn claim_device_code(conn: &Connection, code: &str) -> Result<()> {
    conn.execute(
        "UPDATE device_codes SET status = 'claimed' WHERE code = ?1",
        params![code],
    )?;
    Ok(())
}

/// Cleanup expired device codes and web sessions.
pub fn cleanup_expired_sessions(conn: &Connection) -> Result<()> {
    conn.execute(
        "DELETE FROM device_codes WHERE expires_at < datetime('now')",
        [],
    )?;
    conn.execute(
        "DELETE FROM web_sessions WHERE expires_at < datetime('now')",
        [],
    )?;
    cleanup_agent_key_requests(conn)?;
    // Remove sync tombstones older than 30 days.
    let thirty_days_ago_ms = (chrono::Utc::now() - chrono::Duration::days(30)).timestamp_millis();
    let _ = sync_cleanup_tombstones(conn, thirty_days_ago_ms);
    Ok(())
}

// ============================================================================
// Telegram login tokens
// ============================================================================

/// Create a new TG login token. Returns the token string (32-char hex).
pub fn create_tg_login_token(
    conn: &Connection,
    link_user_id: Option<i64>,
    now: &str,
    expires_at: &str,
) -> Result<String> {
    use rand::Rng;
    let bytes: [u8; 16] = rand::thread_rng().gen();
    let token = hex::encode(bytes);
    conn.execute(
        "INSERT INTO tg_login_tokens (token, status, created_at, expires_at, link_user_id) VALUES (?1, 'pending', ?2, ?3, ?4)",
        params![token, now, expires_at, link_user_id],
    )?;
    Ok(token)
}

/// Bot calls this to confirm a token. Returns true if successfully confirmed.
pub fn confirm_tg_login_token(
    conn: &Connection,
    token: &str,
    telegram_user_id: &str,
    display_name: &str,
) -> Result<bool> {
    let now = chrono::Utc::now().to_rfc3339();
    let rows = conn.execute(
        "UPDATE tg_login_tokens SET status = 'confirmed', telegram_user_id = ?1, display_name = ?2 WHERE token = ?3 AND status = 'pending' AND expires_at > ?4",
        params![telegram_user_id, display_name, token, now],
    )?;
    Ok(rows > 0)
}

/// Poll a token's status. Returns `(status, telegram_user_id, display_name, link_user_id)` if found.
/// If status is 'confirmed', atomically transitions to 'claimed' (exactly-once delivery).
pub fn poll_tg_login_token(
    conn: &Connection,
    token: &str,
) -> Result<Option<(String, Option<String>, Option<String>, Option<i64>)>> {
    let now = chrono::Utc::now().to_rfc3339();
    // Try to claim a confirmed token atomically.
    let rows = conn.execute(
        "UPDATE tg_login_tokens SET status = 'claimed' WHERE token = ?1 AND status = 'confirmed'",
        params![token],
    )?;
    if rows > 0 {
        // Was confirmed, now claimed — return the full data.
        let mut stmt = conn.prepare(
            "SELECT telegram_user_id, display_name, link_user_id FROM tg_login_tokens WHERE token = ?1",
        )?;
        let result = stmt.query_row(params![token], |row| {
            Ok((
                "claimed".to_string(),
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<i64>>(2)?,
            ))
        })?;
        return Ok(Some(result));
    }
    // Check if token exists and is still pending (not expired).
    let mut stmt = conn.prepare(
        "SELECT status FROM tg_login_tokens WHERE token = ?1 AND expires_at > ?2",
    )?;
    match stmt.query_row(params![token, now], |row| row.get::<_, String>(0)) {
        Ok(status) => Ok(Some((status, None, None, None))),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Clean up expired TG login tokens. Returns number of rows deleted.
pub fn cleanup_tg_login_tokens(conn: &Connection) -> Result<usize> {
    let now = chrono::Utc::now().to_rfc3339();
    Ok(conn.execute(
        "DELETE FROM tg_login_tokens WHERE expires_at < ?1",
        params![now],
    )?)
}

// ============================================================================
// Agent key requests
// ============================================================================

/// A row from the `agent_key_requests` table.
#[derive(Debug, Clone)]
pub struct AgentKeyRequestRow {
    pub code: String,
    pub label: String,
    pub permissions: String,
    pub user_id: Option<i64>,
    pub status: String,
    /// The raw key stored temporarily between confirm and claim.
    pub claimed_key: Option<String>,
    pub created_at: String,
    pub expires_at: String,
}

/// Create an agent key request. Returns the 8-char alphanumeric code.
pub fn create_agent_key_request(
    conn: &Connection,
    label: &str,
    permissions: &str,
    now: &str,
    expires_at: &str,
) -> Result<String> {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let code: String = {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..8)
            .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
            .collect()
    };
    conn.execute(
        "INSERT INTO agent_key_requests (code, label, permissions, user_id, status, claimed_key, created_at, expires_at)
         VALUES (?1, ?2, ?3, NULL, 'pending', NULL, ?4, ?5)",
        params![code, label, permissions, now, expires_at],
    )?;
    Ok(code)
}

/// Get an agent key request by code. Returns `None` if not found.
pub fn get_agent_key_request(conn: &Connection, code: &str) -> Result<Option<AgentKeyRequestRow>> {
    let mut stmt = conn.prepare(
        "SELECT code, label, permissions, user_id, status, claimed_key, created_at, expires_at
         FROM agent_key_requests WHERE code = ?1",
    )?;
    let mut rows = stmt.query(params![code])?;
    if let Some(row) = rows.next()? {
        Ok(Some(AgentKeyRequestRow {
            code: row.get(0)?,
            label: row.get(1)?,
            permissions: row.get(2)?,
            user_id: row.get(3)?,
            status: row.get(4)?,
            claimed_key: row.get(5)?,
            created_at: row.get(6)?,
            expires_at: row.get(7)?,
        }))
    } else {
        Ok(None)
    }
}

/// User confirms an agent key request from the dashboard.
///
/// Guards:
/// - Code must exist, status must be 'pending', must not be expired.
/// - Generates a raw key, stores its SHA-256 hash in `auth_tokens`.
/// - Stores the raw key in `agent_key_requests.claimed_key` for the agent to poll.
/// - Updates `agent_key_requests.status` to 'confirmed'.
///
/// Returns the raw key (shown once to the user on the confirmation page).
pub fn confirm_agent_key_request(
    conn: &Connection,
    code: &str,
    user_id: i64,
    label: &str,
    permissions: &str,
    now: &str,
    key_expires_at: &str,
) -> Result<String> {
    use sha2::{Digest, Sha256};

    // Verify the request is pending and not expired.
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM agent_key_requests
         WHERE code = ?1 AND status = 'pending' AND expires_at > ?2",
        params![code, now],
        |row| row.get(0),
    )?;
    if count == 0 {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
            Some(format!("Agent key request '{}' not found, not pending, or expired", code)),
        ));
    }

    // Generate raw key.
    let raw_key: String = {
        use rand::Rng;
        let bytes: [u8; 32] = rand::thread_rng().gen();
        hex::encode(bytes)
    };

    // Compute SHA-256 hash.
    let token_hash = hex::encode(Sha256::digest(raw_key.as_bytes()));

    // Insert into auth_tokens.
    conn.execute(
        "INSERT INTO auth_tokens (token_hash, user_id, label, permissions, initiated_by, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, 'agent', ?5, ?6)",
        params![token_hash, user_id, label, permissions, now, key_expires_at],
    )?;

    // Update agent_key_requests: set status='confirmed', user_id, claimed_key=raw_key.
    conn.execute(
        "UPDATE agent_key_requests
         SET status = 'confirmed', user_id = ?1, claimed_key = ?2
         WHERE code = ?3 AND status = 'pending'",
        params![user_id, raw_key, code],
    )?;

    Ok(raw_key)
}

/// User denies an agent key request. Returns `true` if a pending request was found and denied.
pub fn deny_agent_key_request(conn: &Connection, code: &str, user_id: i64) -> Result<bool> {
    let n = conn.execute(
        "UPDATE agent_key_requests SET status = 'denied', user_id = ?1
         WHERE code = ?2 AND status = 'pending'",
        params![user_id, code],
    )?;
    Ok(n > 0)
}

/// Agent polls for the result of a key request. Uses exactly-once delivery:
/// - If status='confirmed': atomically transitions to 'claimed', returns `("confirmed", Some(raw_key))`.
/// - If status='pending' and not expired: returns `("pending", None)`.
/// - If not found or expired: returns `None`.
pub fn poll_agent_key_request(
    conn: &Connection,
    code: &str,
) -> Result<Option<(String, Option<String>)>> {
    let now = chrono::Utc::now().to_rfc3339();

    // Try atomic confirmed → claimed transition.
    let claimed = conn.execute(
        "UPDATE agent_key_requests SET status = 'claimed'
         WHERE code = ?1 AND status = 'confirmed'",
        params![code],
    )?;
    if claimed > 0 {
        // Retrieve the raw key stored in claimed_key.
        let raw_key: Option<String> = conn
            .query_row(
                "SELECT claimed_key FROM agent_key_requests WHERE code = ?1",
                params![code],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        return Ok(Some(("confirmed".to_string(), raw_key)));
    }

    // Check if still pending (not expired).
    let status: Option<String> = conn
        .query_row(
            "SELECT status FROM agent_key_requests WHERE code = ?1 AND expires_at > ?2",
            params![code, now],
            |row| row.get(0),
        )
        .optional()?;

    match status {
        Some(s) => Ok(Some((s, None))),
        None => Ok(None),
    }
}

/// Mark an agent key request as 'claimed' explicitly (used after poll delivers the key).
pub fn claim_agent_key_request(conn: &Connection, code: &str) -> Result<()> {
    conn.execute(
        "UPDATE agent_key_requests SET status = 'claimed' WHERE code = ?1",
        params![code],
    )?;
    Ok(())
}

/// Clear the raw key from `claimed_key` after it has been delivered to the agent.
///
/// Called immediately after the agent receives the key via the poll endpoint.
/// Nulls out the `claimed_key` column so the raw key is no longer stored
/// server-side once delivery is confirmed.
pub fn clear_claimed_key(conn: &Connection, code: &str) -> Result<()> {
    conn.execute(
        "UPDATE agent_key_requests SET claimed_key = NULL WHERE code = ?1",
        params![code],
    )?;
    Ok(())
}

/// Delete expired agent key requests and claimed rows (cleanup job).
pub fn cleanup_agent_key_requests(conn: &Connection) -> Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "DELETE FROM agent_key_requests WHERE expires_at < ?1 OR status = 'claimed'",
        params![now],
    )?;
    Ok(())
}

/// Count pending (unexpired) agent key requests globally.
/// Used for simple global rate limiting in the request endpoint.
pub fn count_pending_agent_key_requests(conn: &Connection) -> Result<i64> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.query_row(
        "SELECT COUNT(*) FROM agent_key_requests WHERE status = 'pending' AND expires_at > ?1",
        params![now],
        |row| row.get(0),
    )
}

// ============================================================================
// Agent keys (auth_tokens with new columns)
// ============================================================================

/// A row representing an agent key, for dashboard display.
#[derive(Debug, Clone)]
pub struct AgentKeyRow {
    /// First 16 chars of the full hash, for display purposes.
    pub hash_prefix: String,
    pub label: String,
    pub permissions: String,
    pub initiated_by: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub last_ip: Option<String>,
}

/// A row used for terminal key-sync responses.
#[derive(Debug, Clone)]
pub struct KeySyncEntryRow {
    pub token_hash: String,
    pub label: String,
    pub permissions: String,
    pub expires_at: Option<String>,
}

/// Outcome of a key-revoke-by-prefix operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteKeyOutcome {
    Ok,
    NotFound,
    AmbiguousPrefix,
}

/// Insert an agent key into `auth_tokens` (manual generation flow).
///
/// Enforces a limit of 20 active keys per user. Returns an error if the limit
/// is exceeded.
///
/// Returns the raw key (shown once).
#[allow(clippy::too_many_arguments)]
pub fn create_agent_key(
    conn: &Connection,
    user_id: i64,
    label: &str,
    permissions: &str,
    initiated_by: &str,
    now: &str,
    expires_at: &str,
) -> Result<String> {
    use sha2::{Digest, Sha256};

    // Enforce per-user key limit.
    let active_count = count_active_keys_for_user(conn, user_id)?;
    if active_count >= 20 {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
            Some(format!(
                "User {} already has {} active agent keys (limit: 20)",
                user_id, active_count
            )),
        ));
    }

    // Generate raw key.
    let raw_key: String = {
        use rand::Rng;
        let bytes: [u8; 32] = rand::thread_rng().gen();
        hex::encode(bytes)
    };

    // Compute SHA-256 hash.
    let token_hash = hex::encode(Sha256::digest(raw_key.as_bytes()));

    conn.execute(
        "INSERT INTO auth_tokens (token_hash, user_id, label, permissions, initiated_by, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![token_hash, user_id, label, permissions, initiated_by, now, expires_at],
    )?;

    Ok(raw_key)
}

/// Count active (non-expired, non-empty-label) agent keys for a user.
pub fn count_active_keys_for_user(conn: &Connection, user_id: i64) -> Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM auth_tokens
         WHERE user_id = ?1 AND label != ''
           AND (expires_at IS NULL OR expires_at > datetime('now'))",
        params![user_id],
        |row| row.get(0),
    )
}

/// List active agent keys for a user (dashboard format).
///
/// Returns keys with `label != ''` only — device-session tokens (empty label) are excluded.
pub fn list_keys_for_user(conn: &Connection, user_id: i64) -> Result<Vec<AgentKeyRow>> {
    let mut stmt = conn.prepare(
        "SELECT SUBSTR(token_hash, 1, 16), label, permissions, initiated_by,
                created_at, expires_at, last_used_at, last_ip
         FROM auth_tokens
         WHERE user_id = ?1
           AND label != ''
           AND (expires_at IS NULL OR expires_at > datetime('now'))
         ORDER BY created_at DESC",
    )?;
    let mut rows = stmt.query(params![user_id])?;
    let mut keys = Vec::new();
    while let Some(row) = rows.next()? {
        keys.push(AgentKeyRow {
            hash_prefix: row.get(0)?,
            label: row.get(1)?,
            permissions: row.get(2)?,
            initiated_by: row.get(3)?,
            created_at: row.get(4)?,
            expires_at: row.get(5)?,
            last_used_at: row.get(6)?,
            last_ip: row.get(7)?,
        });
    }
    Ok(keys)
}

/// List key hashes for a user (terminal sync format). Includes all non-expired tokens.
pub fn list_key_hashes_for_sync(
    conn: &Connection,
    user_id: i64,
) -> Result<Vec<KeySyncEntryRow>> {
    let mut stmt = conn.prepare(
        "SELECT token_hash, label, permissions, expires_at
         FROM auth_tokens
         WHERE user_id = ?1
           AND (expires_at IS NULL OR expires_at > datetime('now'))
         ORDER BY created_at DESC",
    )?;
    let mut rows = stmt.query(params![user_id])?;
    let mut entries = Vec::new();
    while let Some(row) = rows.next()? {
        entries.push(KeySyncEntryRow {
            token_hash: row.get(0)?,
            label: row.get(1)?,
            permissions: row.get(2)?,
            expires_at: row.get(3)?,
        });
    }
    Ok(entries)
}

/// List active key hashes for a user (token_hash, permissions, label).
/// Used by the terminal sync endpoint.
pub fn list_user_keys(
    conn: &Connection,
    user_id: i64,
) -> Result<Vec<(String, String, String, String, Option<String>, Option<String>)>> {
    let mut stmt = conn.prepare(
        "SELECT token_hash, label, permissions, initiated_by, last_used_at, last_ip
         FROM auth_tokens
         WHERE user_id = ?1
           AND (expires_at IS NULL OR expires_at > datetime('now'))
         ORDER BY created_at DESC",
    )?;
    let mut rows = stmt.query(params![user_id])?;
    let mut keys = Vec::new();
    while let Some(row) = rows.next()? {
        keys.push((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
        ));
    }
    Ok(keys)
}

/// Revoke (delete) a key by hash prefix. The prefix must be at least 8 chars.
///
/// Returns:
/// - `DeleteKeyOutcome::Ok` — key found and deleted.
/// - `DeleteKeyOutcome::NotFound` — no key matched for this user.
/// - `DeleteKeyOutcome::AmbiguousPrefix` — multiple keys share the prefix (caller should
///   provide more characters).
pub fn revoke_key(
    conn: &Connection,
    user_id: i64,
    hash_prefix: &str,
) -> Result<DeleteKeyOutcome> {
    if hash_prefix.len() < 8 {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISUSE),
            Some("hash_prefix must be at least 8 characters".to_string()),
        ));
    }

    // Escape LIKE metacharacters to prevent wildcard injection.
    let escaped = hash_prefix
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    let like_pattern = format!("{}%", escaped);

    // Count matches first.
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM auth_tokens WHERE user_id = ?1 AND token_hash LIKE ?2 ESCAPE '\\'",
        params![user_id, like_pattern],
        |row| row.get(0),
    )?;

    match count {
        0 => Ok(DeleteKeyOutcome::NotFound),
        1 => {
            conn.execute(
                "DELETE FROM auth_tokens WHERE user_id = ?1 AND token_hash LIKE ?2 ESCAPE '\\'",
                params![user_id, like_pattern],
            )?;
            Ok(DeleteKeyOutcome::Ok)
        }
        _ => Ok(DeleteKeyOutcome::AmbiguousPrefix),
    }
}

/// Update the last_used_at and last_ip for a token hash.
pub fn update_key_usage(
    conn: &Connection,
    token_hash: &str,
    now: &str,
    ip: &str,
) -> Result<()> {
    conn.execute(
        "UPDATE auth_tokens SET last_used_at = ?1, last_ip = ?2 WHERE token_hash = ?3",
        params![now, ip, token_hash],
    )?;
    Ok(())
}

/// Batch-update last_used_at and last_ip for multiple token hashes in one lock acquisition.
pub fn batch_update_usage(
    conn: &Connection,
    updates: &[(&str, &str, &str)],
) -> Result<()> {
    let mut stmt = conn.prepare(
        "UPDATE auth_tokens SET last_used_at = ?1, last_ip = ?2 WHERE token_hash = ?3",
    )?;
    for (token_hash, last_used_at, last_ip) in updates {
        stmt.execute(params![last_used_at, last_ip, token_hash])?;
    }
    Ok(())
}

/// Update `last_used_at` and `last_ip` for multiple keys identified by hash prefix.
///
/// Each entry in `updates` is `(hash_prefix, last_ip)`. The function matches rows
/// where `token_hash LIKE '<escaped_prefix>%'` and `user_id = ?`, ensuring that only
/// keys belonging to the authenticated user are updated.
///
/// Returns the total number of rows affected across all updates.
pub fn batch_update_key_usage(
    conn: &Connection,
    user_id: i64,
    updates: &[(String, String)],
) -> Result<usize> {
    let mut stmt = conn.prepare(
        "UPDATE auth_tokens SET last_used_at = datetime('now'), last_ip = ?1 \
         WHERE user_id = ?2 AND token_hash LIKE ?3 ESCAPE '\\'",
    )?;
    let mut total: usize = 0;
    for (hash_prefix, last_ip) in updates {
        // Escape LIKE metacharacters to prevent wildcard injection.
        let escaped = hash_prefix
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let like_pattern = format!("{}%", escaped);
        let affected = stmt.execute(params![last_ip, user_id, like_pattern])?;
        total += affected;
    }
    Ok(total)
}

/// Insert an agent key directly (used internally; prefer `create_agent_key` for user-facing flows).
#[allow(dead_code, clippy::too_many_arguments)]
pub fn insert_agent_key(
    conn: &Connection,
    token_hash: &str,
    user_id: i64,
    label: &str,
    permissions_json: &str,
    initiated_by: &str,
    now: &str,
    expires_at: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO auth_tokens (token_hash, user_id, label, permissions, initiated_by, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![token_hash, user_id, label, permissions_json, initiated_by, now, expires_at],
    )?;
    Ok(())
}

/// Delete a key by prefix, returning outcome (alias for `revoke_key`).
pub fn delete_key_by_prefix(
    conn: &Connection,
    user_id: i64,
    hash_prefix: &str,
) -> Result<DeleteKeyOutcome> {
    revoke_key(conn, user_id, hash_prefix)
}

// ============================================================================
// Cloud sync
// ============================================================================

/// A full sync item row, including content bytes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SyncItem {
    pub sync_id: String,
    pub user_id: i64,
    pub category: String,
    pub name: String,
    pub content: Vec<u8>,
    pub checksum: String,
    pub modified_at: i64,
    pub deleted: bool,
    pub created_at: String,
}

/// Lightweight metadata for a sync item (no content bytes).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SyncItemMeta {
    pub sync_id: String,
    pub category: String,
    pub name: String,
    pub checksum: String,
    pub modified_at: i64,
    pub deleted: bool,
}

/// An item submitted by the client in a push request.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SyncPushItem {
    pub sync_id: String,
    pub category: String,
    pub name: String,
    pub content: Vec<u8>,
    pub checksum: String,
    pub modified_at: i64,
    pub deleted: bool,
}

/// Allowed sync categories. Any other value is rejected.
pub(crate) const VALID_SYNC_CATEGORIES: &[&str] = &[
    "preset",
    "watchlist",
    "template",
    "template_primitive",
    "template_indicator",
    "template_compare",
    "template_indicator_set",
    "template_chart",
    "theme",
    "vault",
    "recovery_key",
    "salt",
    "settings_snapshot",
    "notification_settings",
    "indicator_set_manager",
    "window_layout",
    "profile_meta",
];

// Every figure below was set against measurement, not guessed. Production on
// 2026-09-02: the entire hot sync store is 105 KiB and the identity database
// 172 KiB — for ALL accounts together. A heavy real profile set (18 profiles,
// 76 presets, years of use) syncs to 1.6 MiB once `strip_preset_for_sync` has
// removed bars, viewports and cached indicator values — 87.6% of what sits on
// disk never leaves the machine. Synced preset sizes: median 10.9 KiB, p90
// 29.5 KiB, largest 315 KiB.

/// Maximum content size per item (default): 64 KiB.
///
/// Everything that is not a preset is small by construction — a watchlist is
/// ~1 KiB, a template ~40 bytes, `profile_meta` a two-field object. 64 KiB is
/// already three orders of magnitude of headroom over any of them.
const SYNC_MAX_ITEM_BYTES: usize = 64 * 1024;

/// Maximum content size for preset items: 512 KiB.
///
/// The largest preset ever measured after stripping is 315 KiB; only two of
/// 76 exceed 100 KiB. 512 KiB leaves room for a genuinely heavy chart without
/// leaving room for a 2 MiB one that could only be padding.
const SYNC_MAX_PRESET_BYTES: usize = 512 * 1024;

/// Per-category size limit.
pub(crate) fn max_item_bytes(category: &str) -> usize {
    match category {
        "preset" => SYNC_MAX_PRESET_BYTES,
        _ => SYNC_MAX_ITEM_BYTES,
    }
}

/// Maximum total content stored per ACCOUNT in the COLD plane (SQLCipher): 256 KiB.
///
/// The cold plane holds exactly three categories — `vault`, `recovery_key`,
/// `salt` — and it is the identity database, the one that gets backed up.
/// Measured on production 2026-08-31: 14 rows, 2 360 bytes across seven
/// accounts, largest single item 376 bytes. Letting that plane share a 50 MiB
/// ceiling meant the backed-up database could legally be filled with four
/// orders of magnitude more than the thing it exists to hold.
///
/// Not smaller than this, because `vault.enc` is the encrypted container for
/// every stored exchange key and notification secret, so it grows with use —
/// just nowhere near megabytes.
pub(crate) const SYNC_MAX_COLD_BYTES: i64 = 256 * 1024;

/// Maximum total content stored per ACCOUNT in the hot plane: 8 MiB.
///
/// The bulk figure, and bulk lives in the hot file store — presets,
/// templates, layouts, watchlists. The cold plane is measured against
/// [`SYNC_MAX_COLD_BYTES`] instead, not against this.
///
/// Five times the heaviest real account measured, and eighty times the whole
/// production hot store as it stands. It was 50 MiB, which was never derived
/// from anything.
pub(crate) const SYNC_MAX_TOTAL_BYTES: i64 = 8 * 1024 * 1024;

/// Maximum number of PRESET items per account.
///
/// Presets and templates are the only categories that legitimately grow; the
/// other ten are singletons bounded by their own shape (see
/// `syncstore::SINGLETON_CATEGORIES`). The heaviest real account measured
/// holds 76 presets across 18 profiles.
pub(crate) const SYNC_MAX_PRESETS: i64 = 100;

/// Maximum number of TEMPLATE items per account, across all five template
/// categories together.
pub(crate) const SYNC_MAX_TEMPLATES: i64 = 200;

/// Return `(item_count, last_modified_at, quota_used_bytes)` for the user + profile.
///
/// `item_count` is the number of non-deleted items.
/// `last_modified_at` is `None` if the user has no items at all.
/// `quota_used_bytes` is the total byte length of content for non-deleted items.
/// Cold-plane usage for an ACCOUNT: `(item_count, quota_used_bytes)` summed
/// over every device and profile the user has.
///
/// Quota belongs to the account. `device_id` and `profile_id` say where an
/// object is stored, not how much the account may store — an account may
/// have any number of devices, and counting per `(user, device, profile)`
/// meant each new device handed out a fresh full allowance. Since
/// `X-Device-Id` is a client-supplied header, that made the ceiling
/// effectively unbounded for anyone who bothered to vary it.
/// `(category, sync_id)` for every live cold item the account holds.
///
/// The cold plane is entirely singleton categories, so this is what
/// `syncstore::push` compares against to tell "updating the one vault I have"
/// apart from "pushing a second vault".
pub fn sync_cold_ids_for_user(conn: &Connection, user_id: i64) -> Result<Vec<(String, String)>> {
    let mut stmt = conn.prepare(
        "SELECT category, sync_id FROM sync_items WHERE user_id = ?1 AND deleted = 0",
    )?;
    let rows = stmt.query_map(params![user_id], |row| Ok((row.get(0)?, row.get(1)?)))?;
    rows.collect()
}

pub fn sync_usage_for_user(conn: &Connection, user_id: i64) -> Result<(i64, i64)> {
    let item_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sync_items WHERE user_id = ?1 AND deleted = 0",
        params![user_id],
        |row| row.get(0),
    )?;
    let quota_used_bytes: i64 = conn.query_row(
        "SELECT COALESCE(SUM(LENGTH(content)), 0) FROM sync_items WHERE user_id = ?1 AND deleted = 0",
        params![user_id],
        |row| row.get(0),
    )?;
    Ok((item_count, quota_used_bytes))
}

pub fn sync_status(conn: &Connection, user_id: i64, device_id: &str, profile_id: &str) -> Result<(i64, Option<i64>, i64)> {
    let item_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sync_items WHERE user_id = ?1 AND device_id = ?2 AND profile_id = ?3 AND deleted = 0",
        params![user_id, device_id, profile_id],
        |row| row.get(0),
    )?;
    let last_modified: Option<i64> = conn
        .query_row(
            "SELECT MAX(modified_at) FROM sync_items WHERE user_id = ?1 AND device_id = ?2 AND profile_id = ?3",
            params![user_id, device_id, profile_id],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    let quota_used_bytes: i64 = conn.query_row(
        "SELECT COALESCE(SUM(LENGTH(content)), 0) FROM sync_items WHERE user_id = ?1 AND device_id = ?2 AND profile_id = ?3 AND deleted = 0",
        params![user_id, device_id, profile_id],
        |row| row.get(0),
    )?;
    Ok((item_count, last_modified, quota_used_bytes))
}

/// Return metadata for all items changed (inserted, updated, or tombstoned) since `since` ms.
pub fn sync_get_changes(conn: &Connection, user_id: i64, device_id: &str, profile_id: &str, since: i64) -> Result<Vec<SyncItemMeta>> {
    let mut stmt = conn.prepare(
        "SELECT sync_id, category, name, checksum, modified_at, deleted
         FROM sync_items
         WHERE user_id = ?1 AND device_id = ?2 AND profile_id = ?3 AND modified_at > ?4
         ORDER BY modified_at ASC",
    )?;
    let mut rows = stmt.query(params![user_id, device_id, profile_id, since])?;
    let mut items = Vec::new();
    while let Some(row) = rows.next()? {
        items.push(SyncItemMeta {
            sync_id: row.get(0)?,
            category: row.get(1)?,
            name: row.get(2)?,
            checksum: row.get(3)?,
            modified_at: row.get(4)?,
            deleted: row.get::<_, i64>(5)? != 0,
        });
    }
    Ok(items)
}

/// Upsert a batch of items for `user_id` + `profile_id`.
///
/// Validation per item:
/// - `category` must be one of the allowed values.
/// - `name` must not exceed 128 bytes and must not contain control characters.
/// - `content` is capped by `max_item_bytes(category)` (64 KiB, or 512 KiB
///   for presets) — checked in `syncstore::push`, not here.
///
/// Quota checks: none. Both the count and the byte ceiling for everything
/// that reaches this function are enforced per ACCOUNT in `syncstore::push`
/// before it is called — see the note where the old byte check used to sit.
///
/// Last-writer-wins: an existing row is only overwritten when the incoming
/// `modified_at` is strictly greater than the stored value.
///
/// Returns the number of rows actually inserted or updated.
/// Result of a granular push: each item is accepted or rejected independently.
pub struct SyncPushResult {
    pub accepted: usize,
    pub rejected: Vec<String>,
}

pub fn sync_push_items(
    conn: &Connection,
    user_id: i64,
    device_id: &str,
    profile_id: &str,
    items: &[SyncPushItem],
) -> rusqlite::Result<SyncPushResult> {
    if items.is_empty() {
        return Ok(SyncPushResult { accepted: 0, rejected: vec![] });
    }

    // --- Quota checks (once, before any inserts) ---
    //
    // No item-count check here any more. This function only ever receives
    // cold categories (`syncstore::push` routes hot ones to the file store
    // and hands it only the rest), and every cold category is a singleton
    // bounded by its own shape — `syncstore::push` refuses a second one
    // before this is reached. A blanket count was the wrong instrument for a
    // plane that structurally holds three rows.

    // No byte check here either, for the same reason and one more. This
    // function only sees cold categories, whose ceiling is
    // `SYNC_MAX_COLD_BYTES` and is charged to the ACCOUNT in
    // `syncstore::push`. The check that stood here summed
    // `WHERE user_id AND device_id AND profile_id` and compared it to
    // `SYNC_MAX_TOTAL_BYTES` — the hot plane's ceiling, thirty-two times the
    // cold one — so it was scoped to a device, measured against the wrong
    // plane, and could only ever fire on the wrong input. Its message named
    // a limit (50 MiB) that no constant in this crate has held for some time,
    // which is how it survived: nothing it said could be checked against
    // anything real.

    // --- Per-item upsert with validation ---
    let now = chrono::Utc::now().to_rfc3339();
    let mut accepted = 0usize;
    let mut rejected = Vec::new();
    let mut stmt = conn.prepare(
        "INSERT INTO sync_items (user_id, device_id, profile_id, sync_id, category, name, content, checksum, modified_at, deleted, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(user_id, device_id, profile_id, sync_id) DO UPDATE SET
             name        = excluded.name,
             content     = excluded.content,
             checksum    = excluded.checksum,
             modified_at = excluded.modified_at,
             deleted     = excluded.deleted
         WHERE excluded.modified_at > sync_items.modified_at
            OR (excluded.modified_at = sync_items.modified_at AND excluded.checksum != sync_items.checksum)",
    )?;

    for item in items {
        // Per-item validation — reject this item, continue with the rest.
        if !VALID_SYNC_CATEGORIES.contains(&item.category.as_str()) {
            rejected.push(format!("{}: unknown category '{}'", item.sync_id, item.category));
            continue;
        }
        if item.name.len() > 128 {
            rejected.push(format!("{}: name exceeds 128 bytes", item.sync_id));
            continue;
        }
        if item.name.chars().any(|c| c.is_control()) {
            rejected.push(format!("{}: name contains control chars", item.sync_id));
            continue;
        }
        let limit = max_item_bytes(&item.category);
        if item.content.len() > limit {
            rejected.push(format!("{}: content exceeds {} KiB ({} bytes)", item.sync_id, limit / 1024, item.content.len()));
            continue;
        }

        let deleted_i: i64 = if item.deleted { 1 } else { 0 };
        match stmt.execute(params![
            user_id,
            device_id,
            profile_id,
            item.sync_id,
            item.category,
            item.name,
            item.content,
            item.checksum,
            item.modified_at,
            deleted_i,
            now,
        ]) {
            Ok(n) => {
                accepted += n;
                // When profile_meta is pushed, extract display_name and store it
                // on ALL rows for this (user_id, profile_id) so GROUP BY can read it.
                if item.category == "profile_meta" {
                    if let Ok(s) = std::str::from_utf8(&item.content) {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
                            if let Some(name) = v.get("display_name").and_then(|n| n.as_str()) {
                                let _ = conn.execute(
                                    "UPDATE sync_items SET display_name = ?1 WHERE user_id = ?2 AND profile_id = ?3",
                                    params![name, user_id, profile_id],
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                rejected.push(format!("{}: db error: {}", item.sync_id, e));
            }
        }
    }
    Ok(SyncPushResult { accepted, rejected })
}

/// Return all non-deleted items for the user + device + profile (full content, for initial pull).
pub fn sync_pull_all(conn: &Connection, user_id: i64, device_id: &str, profile_id: &str) -> Result<Vec<SyncItem>> {
    let mut stmt = conn.prepare(
        "SELECT sync_id, user_id, category, name, content, checksum, modified_at, deleted, created_at
         FROM sync_items
         WHERE user_id = ?1 AND device_id = ?2 AND profile_id = ?3 AND deleted = 0
         ORDER BY modified_at ASC",
    )?;
    let mut rows = stmt.query(params![user_id, device_id, profile_id])?;
    let mut items = Vec::new();
    while let Some(row) = rows.next()? {
        items.push(SyncItem {
            sync_id: row.get(0)?,
            user_id: row.get(1)?,
            category: row.get(2)?,
            name: row.get(3)?,
            content: row.get(4)?,
            checksum: row.get(5)?,
            modified_at: row.get(6)?,
            deleted: row.get::<_, i64>(7)? != 0,
            created_at: row.get(8)?,
        });
    }
    Ok(items)
}

/// Return one item by `sync_id`, scoped to `user_id`. Returns `None` if not found.
pub fn sync_pull_item(conn: &Connection, user_id: i64, sync_id: &str) -> Result<Option<SyncItem>> {
    let mut stmt = conn.prepare(
        "SELECT sync_id, user_id, category, name, content, checksum, modified_at, deleted, created_at
         FROM sync_items
         WHERE sync_id = ?1 AND user_id = ?2
         LIMIT 1",
    )?;
    let mut rows = stmt.query(params![sync_id, user_id])?;
    if let Some(row) = rows.next()? {
        Ok(Some(SyncItem {
            sync_id: row.get(0)?,
            user_id: row.get(1)?,
            category: row.get(2)?,
            name: row.get(3)?,
            content: row.get(4)?,
            checksum: row.get(5)?,
            modified_at: row.get(6)?,
            deleted: row.get::<_, i64>(7)? != 0,
            created_at: row.get(8)?,
        }))
    } else {
        Ok(None)
    }
}

/// Soft-delete one item (tombstone). Clears content to reclaim space.
///
/// Returns `true` if a row was found and marked deleted; `false` if the item
/// was not found for this user + profile (or was already deleted — idempotent).
pub fn sync_delete_item(
    conn: &Connection,
    user_id: i64,
    device_id: &str,
    profile_id: &str,
    sync_id: &str,
    now_ms: i64,
) -> Result<bool> {
    let n = conn.execute(
        "UPDATE sync_items SET deleted = 1, modified_at = ?1, content = x''
         WHERE sync_id = ?2 AND user_id = ?3 AND device_id = ?4 AND profile_id = ?5",
        params![now_ms, sync_id, user_id, device_id, profile_id],
    )?;
    Ok(n > 0)
}

/// Hard-delete all sync data for a user + device + profile (e.g. "Delete Cloud Data" action).
///
/// Returns the number of rows deleted.
pub fn sync_delete_all(conn: &Connection, user_id: i64, device_id: &str, profile_id: &str) -> Result<usize> {
    Ok(conn.execute(
        "DELETE FROM sync_items WHERE user_id = ?1 AND device_id = ?2 AND profile_id = ?3",
        params![user_id, device_id, profile_id],
    )?)
}

/// Purge tombstone rows whose `modified_at` is older than `older_than_ms`.
///
/// Called from the periodic cleanup cycle to remove 30-day-old tombstones.
/// Returns the number of rows deleted.
pub fn sync_cleanup_tombstones(conn: &Connection, older_than_ms: i64) -> Result<usize> {
    Ok(conn.execute(
        "DELETE FROM sync_items WHERE deleted = 1 AND modified_at < ?1",
        params![older_than_ms],
    )?)
}

/// Distinct `profile_id`s that appear anywhere in `sync_items` for a user,
/// INCLUDING tombstoned (`deleted = 1`) rows.
///
/// This is the cold-plane half of the multi-profile entitlement's "has the
/// server ever seen this profile_id" / count check (see
/// `syncstore::known_profile_ids`, `entitlements::profile_write_allowed`,
/// and their callers in `routes/sync.rs`). It is deliberately NOT the same
/// query as `sync_list_profiles_for_user`, which filters to non-deleted
/// rows for the profile-list UI — a profile the user soft-deleted every
/// item of has still been seen by the server and must not become
/// re-creatable for free.
pub fn sync_distinct_profile_ids(conn: &Connection, user_id: i64) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT DISTINCT profile_id FROM sync_items WHERE user_id = ?1")?;
    let mut rows = stmt.query(params![user_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(row.get(0)?);
    }
    Ok(out)
}

/// Summary info for one profile as seen across all devices.
#[derive(Debug, Clone)]
pub struct ProfileSyncInfo {
    pub profile_id: String,
    pub display_name: Option<String>,
    pub item_count: i64,
    pub total_bytes: i64,
    pub last_modified: i64,
    pub has_vault: bool,
    pub has_recovery_key: bool,
}

/// List all profiles that have sync data for `user_id`, aggregated across all devices.
///
/// Returns one `ProfileSyncInfo` per distinct `profile_id` found in `sync_items`.
pub fn sync_list_profiles_for_user(conn: &Connection, user_id: i64) -> Result<Vec<ProfileSyncInfo>> {
    let mut stmt = conn.prepare(
        "SELECT profile_id,
                COUNT(*) AS item_count,
                SUM(length(content)) AS total_bytes,
                MAX(modified_at) AS last_modified,
                MAX(CASE WHEN category = 'vault' THEN 1 ELSE 0 END) AS has_vault,
                MAX(CASE WHEN category = 'recovery_key' THEN 1 ELSE 0 END) AS has_recovery_key,
                MAX(display_name) AS display_name
         FROM sync_items
         WHERE user_id = ?1 AND deleted = 0
         GROUP BY profile_id",
    )?;
    let mut rows = stmt.query(params![user_id])?;
    let mut items = Vec::new();
    while let Some(row) = rows.next()? {
        let raw_name: String = row.get::<_, String>(6).unwrap_or_default();
        let display_name = if raw_name.is_empty() { None } else { Some(raw_name) };
        items.push(ProfileSyncInfo {
            profile_id: row.get(0)?,
            display_name,
            item_count: row.get(1)?,
            total_bytes: row.get::<_, Option<i64>>(2)?.unwrap_or(0),
            last_modified: row.get(3)?,
            has_vault: row.get::<_, i64>(4)? != 0,
            has_recovery_key: row.get::<_, i64>(5)? != 0,
        });
    }
    Ok(items)
}

/// Return all non-deleted items for `user_id` + `profile_id`, ignoring `device_id`.
///
/// When the same `sync_id` exists under multiple device rows, the version with
/// the latest `modified_at` is selected (last-writer-wins across devices).
pub fn sync_pull_by_profile(conn: &Connection, user_id: i64, profile_id: &str) -> Result<Vec<SyncItem>> {
    let mut stmt = conn.prepare(
        "SELECT si.sync_id, si.user_id, si.category, si.name, si.content,
                si.checksum, si.modified_at, si.deleted, si.created_at
         FROM sync_items si
         INNER JOIN (
             SELECT sync_id, MAX(modified_at) AS max_mod
             FROM sync_items
             WHERE user_id = ?1 AND profile_id = ?2 AND deleted = 0
             GROUP BY sync_id
         ) latest ON si.sync_id = latest.sync_id AND si.modified_at = latest.max_mod
         WHERE si.user_id = ?1 AND si.profile_id = ?2 AND si.deleted = 0
         ORDER BY si.modified_at ASC",
    )?;
    let mut rows = stmt.query(params![user_id, profile_id])?;
    let mut items = Vec::new();
    while let Some(row) = rows.next()? {
        items.push(SyncItem {
            sync_id: row.get(0)?,
            user_id: row.get(1)?,
            category: row.get(2)?,
            name: row.get(3)?,
            content: row.get(4)?,
            checksum: row.get(5)?,
            modified_at: row.get(6)?,
            deleted: row.get::<_, i64>(7)? != 0,
            created_at: row.get(8)?,
        });
    }
    Ok(items)
}

/// Return `(salt, iterations, encrypted_master_key)` for E2E key derivation, or `None` if not set up.
///
/// `encrypted_master_key` is `None` when not set (recovery key not yet stored).
pub fn sync_get_e2e_params(conn: &Connection, user_id: i64, profile_id: &str) -> Result<Option<(String, i32, Option<String>)>> {
    let mut stmt = conn.prepare(
        "SELECT salt, iterations, encrypted_master_key FROM sync_e2e_params WHERE user_id = ?1 AND profile_id = ?2",
    )?;
    let mut rows = stmt.query(params![user_id, profile_id])?;
    if let Some(row) = rows.next()? {
        Ok(Some((row.get(0)?, row.get(1)?, row.get(2)?)))
    } else {
        Ok(None)
    }
}

/// Store (or replace) E2E key derivation parameters for a user + profile.
///
/// `encrypted_master_key` is an optional opaque blob (base64 string from the
/// client) that stores the user's master key encrypted with their recovery key.
/// The server stores it without inspecting its contents.
pub fn sync_set_e2e_params(
    conn: &Connection,
    user_id: i64,
    profile_id: &str,
    salt: &str,
    iterations: i32,
    encrypted_master_key: Option<&str>,
    now: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO sync_e2e_params
         (user_id, profile_id, salt, iterations, encrypted_master_key, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(user_id, profile_id) DO UPDATE SET
             salt = excluded.salt,
             iterations = excluded.iterations,
             encrypted_master_key = COALESCE(excluded.encrypted_master_key, sync_e2e_params.encrypted_master_key),
             created_at = excluded.created_at",
        params![user_id, profile_id, salt, iterations, encrypted_master_key, now],
    )?;
    Ok(())
}

// ============================================================================
// Sessions management
// ============================================================================

/// A row from `auth_tokens` for display in the sessions list.
#[derive(Debug, Clone)]
pub struct SessionRow {
    pub hash_prefix: String,
    pub label: String,
    pub initiated_by: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub last_ip: Option<String>,
    pub device_name: String,
    pub device_os: String,
    pub device_app_version: String,
}

/// List all non-expired auth tokens for a user (sessions/devices list).
///
/// Returns all token rows regardless of label to include device-session tokens.
/// Enriched with device metadata from the operational database's `devices`
/// table (`ops_conn`) — used to be one `LEFT JOIN`, but `devices` moved out of
/// identity in the 2026-08-30 store split, so a subquery can no longer span
/// the two files; the enrichment is a second pass in Rust instead.
pub fn list_sessions_for_user(
    conn: &Connection,
    ops_conn: &Connection,
    user_id: i64,
) -> Result<Vec<SessionRow>> {
    let mut stmt = conn.prepare(
        "SELECT SUBSTR(a.token_hash, 1, 16), a.label, a.initiated_by,
                a.created_at, a.expires_at, a.last_used_at, a.last_ip, a.device_id
         FROM auth_tokens a
         WHERE a.user_id = ?1
           AND (a.expires_at IS NULL OR a.expires_at > datetime('now'))
         ORDER BY a.created_at DESC",
    )?;
    let mut rows = stmt.query(params![user_id])?;
    // device_id kept alongside each row only to look up device metadata
    // below; it is not part of `SessionRow` itself.
    let mut sessions: Vec<(SessionRow, String)> = Vec::new();
    while let Some(row) = rows.next()? {
        let device_id: String = row.get(7)?;
        sessions.push((
            SessionRow {
                hash_prefix: row.get(0)?,
                label: row.get(1)?,
                initiated_by: row.get(2)?,
                created_at: row.get(3)?,
                expires_at: row.get(4)?,
                last_used_at: row.get(5)?,
                last_ip: row.get(6)?,
                device_name: String::new(),
                device_os: String::new(),
                device_app_version: String::new(),
            },
            device_id,
        ));
    }
    drop(rows);
    drop(stmt);

    // device_id -> (device_name, os, app_version)
    let mut device_meta: std::collections::HashMap<String, (String, String, String)> =
        std::collections::HashMap::new();
    {
        let mut stmt = ops_conn.prepare("SELECT device_id, device_name, os, app_version FROM devices")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            device_meta.insert(row.get(0)?, (row.get(1)?, row.get(2)?, row.get(3)?));
        }
    }

    Ok(sessions
        .into_iter()
        .map(|(mut session, device_id)| {
            if let Some((name, os, app_version)) = device_meta.get(&device_id) {
                session.device_name = name.clone();
                session.device_os = os.clone();
                session.device_app_version = app_version.clone();
            }
            session
        })
        .collect())
}

// ============================================================================
// Account deletion
// ============================================================================

/// Delete all identity-database data for a user and the user row itself.
///
/// Cascade order: share_links → sync_e2e_params → sync_items → auth_tokens →
/// device_users → user_providers → web_sessions → users. `share_links` must
/// go first: its `user_id` is `REFERENCES users(id)` and production runs
/// with `PRAGMA foreign_keys=ON` (see `init_db`) — leaving it out of the
/// cascade, as this function used to, made the final `DELETE FROM users`
/// itself fail for any account that had ever created a share.
///
/// `device_metrics` is NOT in this cascade — it moved to the operational
/// database in the 2026-08-30 store split, so it is a separate statement
/// against a separate connection now: `delete_account_telemetry`, below. The
/// hot-plane
/// sync files (`<data_dir>/sync/<user_id>/…`) are likewise NOT touched by
/// this function — the caller (routes/sessions.rs::delete_account) calls
/// both that and `syncstore::purge_user`, since this module has no
/// cross-database or filesystem reach on its own; the caller is where the
/// two-database nature of a full account deletion is meant to be visible.
///
/// Returns `(rows deleted from users, screenshot blob paths to unlink)` — 1
/// and the deleted account's screenshot-share blobs on success, `(0, _)` if
/// the user was not found. Live shares (empty `blob_path`) are never
/// included. Same reasoning as the sync files above: this function cannot
/// reach the filesystem, so the caller unlinks each path under
/// `ControlPlane::share_root` once the lock is dropped — the same pattern
/// `cleanup_expired_share_links` uses for the periodic reaper.
pub fn delete_account(conn: &Connection, user_id: i64) -> Result<(usize, Vec<String>)> {
    let blob_paths: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT blob_path FROM share_links WHERE user_id = ?1 AND blob_path != ''",
        )?;
        let rows = stmt.query_map(params![user_id], |row| row.get::<_, String>(0))?;
        rows.filter_map(|r| r.ok()).collect()
    };
    conn.execute("DELETE FROM share_links WHERE user_id = ?1", params![user_id])?;
    conn.execute("DELETE FROM sync_e2e_params WHERE user_id = ?1", params![user_id])?;
    conn.execute("DELETE FROM sync_items WHERE user_id = ?1", params![user_id])?;
    conn.execute("DELETE FROM auth_tokens WHERE user_id = ?1", params![user_id])?;
    conn.execute("DELETE FROM device_users WHERE user_id = ?1", params![user_id])?;
    conn.execute("DELETE FROM user_providers WHERE user_id = ?1", params![user_id])?;
    conn.execute("DELETE FROM web_sessions WHERE user_id = ?1", params![user_id])?;
    let n = conn.execute("DELETE FROM users WHERE id = ?1", params![user_id])?;
    Ok((n, blob_paths))
}

/// Delete `device_metrics` rows for a user from the **operational** database
/// (2026-08-31 split: `device_profile` carries no `user_id`, so there is
/// nothing of the deleted account's left in it either way).
///
/// The operational-side half of account deletion — see `delete_account`'s
/// doc comment for why this is a separate function on a separate connection
/// rather than a line inside that cascade.
///
/// Returns the number of `device_metrics` rows deleted.
pub fn delete_account_telemetry(ops_conn: &Connection, user_id: i64) -> rusqlite::Result<usize> {
    ops_conn.execute("DELETE FROM device_metrics WHERE user_id = ?1", params![user_id])
}

/// Export all data the server holds for a user.
///
/// Returns a tuple of (user_row, sync_items, auth_tokens) as raw JSON-serialisable data.
pub fn export_account_data(
    conn: &Connection,
    user_id: i64,
) -> Result<(serde_json::Value, Vec<serde_json::Value>, Vec<serde_json::Value>)> {
    // User row.
    let user_json = {
        let mut stmt = conn.prepare(
            "SELECT id, provider, display_name, created_at, public_id FROM users WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![user_id])?;
        if let Some(row) = rows.next()? {
            serde_json::json!({
                "id": row.get::<_, i64>(0)?,
                "provider": row.get::<_, String>(1)?,
                "display_name": row.get::<_, String>(2)?,
                "created_at": row.get::<_, String>(3)?,
                "public_id": row.get::<_, String>(4)?,
            })
        } else {
            serde_json::Value::Null
        }
    };

    // Sync items (content bytes excluded for size, only metadata).
    let sync_items = {
        let mut stmt = conn.prepare(
            "SELECT sync_id, category, name, checksum, modified_at, deleted, created_at
             FROM sync_items WHERE user_id = ?1 ORDER BY modified_at DESC",
        )?;
        let mut rows = stmt.query(params![user_id])?;
        let mut items = Vec::new();
        while let Some(row) = rows.next()? {
            items.push(serde_json::json!({
                "sync_id": row.get::<_, String>(0)?,
                "category": row.get::<_, String>(1)?,
                "name": row.get::<_, String>(2)?,
                "checksum": row.get::<_, String>(3)?,
                "modified_at": row.get::<_, i64>(4)?,
                "deleted": row.get::<_, i64>(5)? != 0,
                "created_at": row.get::<_, String>(6)?,
            }));
        }
        items
    };

    // Auth tokens (hash prefix only, never full hash).
    let tokens = {
        let mut stmt = conn.prepare(
            "SELECT SUBSTR(token_hash, 1, 16), label, initiated_by, created_at, expires_at, last_used_at
             FROM auth_tokens WHERE user_id = ?1 ORDER BY created_at DESC",
        )?;
        let mut rows = stmt.query(params![user_id])?;
        let mut toks = Vec::new();
        while let Some(row) = rows.next()? {
            toks.push(serde_json::json!({
                "hash_prefix": row.get::<_, String>(0)?,
                "label": row.get::<_, String>(1)?,
                "initiated_by": row.get::<_, String>(2)?,
                "created_at": row.get::<_, String>(3)?,
                "expires_at": row.get::<_, Option<String>>(4)?,
                "last_used_at": row.get::<_, Option<String>>(5)?,
            }));
        }
        toks
    };

    Ok((user_json, sync_items, tokens))
}

// ============================================================================
// Link tokens (OAuth account linking flow)
// ============================================================================

/// The status of a link token as returned by `poll_link_token`.
#[derive(Debug, Clone)]
pub enum LinkTokenStatus {
    /// Token is still waiting for the web user to confirm.
    Pending {
        device_name: String,
        created_at: i64,
    },
    /// Token has expired (past `expires_at`).
    Expired,
    /// Token was confirmed; carries the linked user's info and a raw bearer token.
    Linked {
        user_id: i64,
        display_name: String,
        provider: String,
        /// Raw (unhashed) auth token to return to the desktop client.
        auth_token: String,
    },
}

/// Create a link token. Stores `device_name`, `device_id`, `created_at` (Unix ms),
/// `expires_at` (Unix ms, 10 minutes out), status='pending', user_id=NULL.
///
/// Returns the raw 32-char hex token.
pub fn create_link_token(
    conn: &Connection,
    device_name: &str,
    device_id: &str,
) -> Result<String> {
    use rand::Rng;
    let bytes: [u8; 16] = rand::thread_rng().gen();
    let token = hex::encode(bytes);

    let now_ms = chrono::Utc::now().timestamp_millis();
    let expires_ms = now_ms + 10 * 60 * 1000; // 10 minutes

    conn.execute(
        "INSERT INTO link_tokens (token, device_name, device_id, created_at, expires_at, status, user_id)
         VALUES (?1, ?2, ?3, ?4, ?5, 'pending', NULL)",
        params![token, device_name, device_id, now_ms, expires_ms],
    )?;
    Ok(token)
}

/// Poll the status of a link token.
///
/// Returns:
/// - `None` — token not found.
/// - `Some(LinkTokenStatus::Expired)` — token is past `expires_at`.
/// - `Some(LinkTokenStatus::Pending)` — token exists and is still waiting.
/// - `Some(LinkTokenStatus::Linked { .. })` — web user confirmed; user info is included.
pub fn poll_link_token(conn: &Connection, token: &str) -> Result<Option<LinkTokenStatus>> {
    let now_ms = chrono::Utc::now().timestamp_millis();

    let row: Option<(i64, String, Option<i64>, String, String, i64)> = {
        let mut stmt = conn.prepare(
            "SELECT expires_at, status, user_id, auth_token, device_name, created_at FROM link_tokens WHERE token = ?1",
        )?;
        let mut rows = stmt.query(params![token])?;
        if let Some(r) = rows.next()? {
            Some((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
        } else {
            None
        }
    };

    let (expires_at, status, user_id_opt, auth_token_raw, device_name, created_at) = match row {
        Some(r) => r,
        None => return Ok(None),
    };

    if expires_at < now_ms && status == "pending" {
        return Ok(Some(LinkTokenStatus::Expired));
    }

    match status.as_str() {
        "pending" => Ok(Some(LinkTokenStatus::Pending { device_name, created_at })),
        "linked" => {
            let user_id = match user_id_opt {
                Some(id) => id,
                None => return Ok(Some(LinkTokenStatus::Expired)),
            };
            // Fetch display_name and provider for the linked user.
            let mut stmt = conn.prepare(
                "SELECT display_name, provider FROM users WHERE id = ?1 LIMIT 1",
            )?;
            let mut rows = stmt.query(params![user_id])?;
            match rows.next()? {
                Some(r) => Ok(Some(LinkTokenStatus::Linked {
                    user_id,
                    display_name: r.get(0)?,
                    provider: r.get(1)?,
                    auth_token: auth_token_raw,
                })),
                None => Ok(Some(LinkTokenStatus::Expired)),
            }
        }
        // Any other status (e.g. an old "expired" marker) → treat as expired.
        _ => Ok(Some(LinkTokenStatus::Expired)),
    }
}

/// Confirm a link token from a logged-in web user.
///
/// Sets `user_id` and transitions `status` from 'pending' to 'linked'.
/// Also creates a `device_users` entry linking the device to the user,
/// generates a 30-day auth token, stores it (raw) in `link_tokens.auth_token`
/// and (hashed) in `auth_tokens`.
///
/// `ops_conn` is only used for the orphaned-`device_users` cleanup at the
/// end (`devices` moved to the operational database — see
/// `purge_orphan_device_users`); everything else here is identity-only.
///
/// Returns `true` if a pending, non-expired token was found and updated,
/// or `false` if the token was not found / already used / expired.
pub fn confirm_link_token(conn: &Connection, ops_conn: &Connection, token: &str, user_id: i64) -> Result<bool> {
    use crate::auth::{generate_token, hash_token};

    let now_ms = chrono::Utc::now().timestamp_millis();

    // Generate the bearer token before the UPDATE so we can store it atomically.
    let raw_token = generate_token();
    let token_hash = hash_token(&raw_token);
    let now_str = chrono::Utc::now().to_rfc3339();
    let expires_at = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();

    // Atomically transition pending → linked, guarding against expiry and races.
    // Also store the raw auth_token in the same row so poll can return it.
    let n = conn.execute(
        "UPDATE link_tokens SET user_id = ?1, status = 'linked', auth_token = ?4
         WHERE token = ?2 AND status = 'pending' AND expires_at >= ?3",
        params![user_id, token, now_ms, raw_token],
    )?;

    if n == 0 {
        return Ok(false);
    }

    // Revoke previous device-session tokens for this user before issuing a new one.
    // This prevents duplicate "Desktop App" entries on the dashboard.
    conn.execute(
        "DELETE FROM auth_tokens WHERE user_id = ?1 AND initiated_by = 'user' AND label = ''",
        params![user_id],
    )?;

    // Fetch device_id so we can store it in auth_tokens and create the device_users link.
    let device_id: String = conn
        .query_row(
            "SELECT device_id FROM link_tokens WHERE token = ?1",
            params![token],
            |row| row.get(0),
        )
        .unwrap_or_default();

    // Insert the hashed token into auth_tokens with device_id and 30-day expiry.
    conn.execute(
        "INSERT OR REPLACE INTO auth_tokens (token_hash, user_id, created_at, expires_at, device_id)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![token_hash, user_id, now_str, expires_at, device_id],
    )?;

    if !device_id.is_empty() {
        link_device_user(conn, &device_id, user_id, &now_str)?;

        // Clean up orphaned device_users entries for this user — old rows where
        // device_id was actually a profile_id (pre-v0.2.11 bug) and doesn't
        // exist in the real `devices` table (operational database now).
        let known_ids = known_device_ids(ops_conn)?;
        purge_orphan_device_users(conn, &known_ids, Some(user_id))?;
    }

    Ok(true)
}

/// Delete sync data for users who haven't synced in `inactive_days` days.
///
/// Preserves the user account and auth — only removes `sync_items` rows (both live
/// and tombstones) for users whose most-recent `modified_at` is older than the
/// threshold. Also cleans up orphaned `sync_e2e_params` rows for users who no
/// longer have any sync items.
///
/// This covers the cold plane only (`sync_items` in SQLCipher). The hot plane
/// — presets/layouts/watchlists/… under `<data_dir>/sync/<user_id>/…` — is a
/// separate counterpart, `syncstore::cleanup_inactive`, called alongside this
/// function from the same periodic task in `main.rs`; a hot-only user (one who
/// never wrote a cold category) never appears in this query at all, so the two
/// sweeps cannot be merged into one.
///
/// Returns the number of `sync_items` rows deleted.
pub fn cleanup_inactive_sync_data(conn: &Connection, inactive_days: i64) -> rusqlite::Result<usize> {
    let threshold_ms = (chrono::Utc::now() - chrono::Duration::days(inactive_days)).timestamp_millis();
    let deleted = conn.execute(
        "DELETE FROM sync_items WHERE user_id IN (
            SELECT user_id FROM sync_items
            GROUP BY user_id
            HAVING MAX(modified_at) < ?1
        )",
        params![threshold_ms],
    )?;
    // Remove e2e params for users who no longer have any sync items.
    let _ = conn.execute(
        "DELETE FROM sync_e2e_params WHERE user_id NOT IN (
            SELECT DISTINCT user_id FROM sync_items
        )",
        [],
    );
    Ok(deleted)
}

/// Delete expired `auth_tokens` — those with a non-null `expires_at` that is in the past.
///
/// The existing `cleanup_expired_sessions` only deletes `device_codes` and `web_sessions`.
/// This function extends coverage to long-lived bearer tokens.
///
/// Returns the number of rows deleted.
pub fn cleanup_expired_auth_tokens(conn: &Connection) -> rusqlite::Result<usize> {
    let now = chrono::Utc::now().to_rfc3339();
    Ok(conn.execute(
        "DELETE FROM auth_tokens WHERE expires_at IS NOT NULL AND expires_at < ?1",
        params![now],
    )?)
}

/// Delete devices not seen in `stale_days` days, from the operational database.
///
/// `device_users` is no longer cleaned up here — it lives in identity and
/// `devices` here lives in the operational database (2026-08-30 store
/// split), so a single connection can no longer do both. The companion sweep
/// is `cleanup_orphan_device_users`, called alongside this from the periodic
/// cleanup task in main.rs.
///
/// Returns the number of `devices` rows deleted.
pub fn cleanup_stale_devices(conn: &Connection, stale_days: i64) -> rusqlite::Result<usize> {
    let threshold_dt = (chrono::Utc::now() - chrono::Duration::days(stale_days)).to_rfc3339();
    conn.execute(
        "DELETE FROM devices WHERE last_seen < ?1",
        params![threshold_dt],
    )
}

// ============================================================================
// Posts (in-app blog, 2026-09-05 web-surface-cleanup plan)
//
// One post is pushed at a time by an operator script through
// `POST /api/admin/posts` (see routes/posts.rs) — this replaces the static
// `web/blog/posts.json` file that used to be redeployed whole for every
// patch note. Public reads (`GET /api/posts`, the compatibility
// `GET /blog/posts.json`, and the server-rendered `/blog/*` mirror) only ever
// see `visibility = 'public'` rows; `'paid'` exists for a future gated
// forum/post tier and is not read by anything in this wave.
// ============================================================================

/// One row of the `posts` table.
#[derive(Debug, Clone, PartialEq)]
pub struct Post {
    pub id: String,
    pub kind: String,
    pub version: Option<String>,
    pub date: String,
    pub title: String,
    pub summary: String,
    pub body: String,
    pub url: String,
    pub visibility: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Read one query row into a [`Post`]. Column order must match the SELECT
/// lists below.
fn post_from_row(row: &rusqlite::Row<'_>) -> Result<Post> {
    Ok(Post {
        id: row.get(0)?,
        kind: row.get(1)?,
        version: row.get(2)?,
        date: row.get(3)?,
        title: row.get(4)?,
        summary: row.get(5)?,
        body: row.get(6)?,
        url: row.get(7)?,
        visibility: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

const POST_SELECT_COLUMNS: &str =
    "id, kind, version, date, title, summary, body, url, visibility, created_at, updated_at";

/// Slug rule for a post `id`: `[a-z0-9][a-z0-9-]{1,80}` — an ASCII lowercase
/// letter or digit, followed by 1 to 80 further ASCII lowercase
/// letters/digits/hyphens (2 to 81 characters total). This is also the id's
/// filesystem- and URL-safety guarantee: it is never percent-decoded or
/// path-joined, but every reader downstream (routes/posts.rs's HTML mirror,
/// the Atom feed) assumes this shape rather than re-checking it.
pub fn is_valid_post_id(id: &str) -> bool {
    let len = id.chars().count();
    if !(2..=81).contains(&len) {
        return false;
    }
    let mut chars = id.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// `YYYY-MM-DD`, and a real calendar date — not just the right shape (a
/// syntactically valid but nonexistent date like `2026-02-30` is rejected by
/// `NaiveDate::parse_from_str` itself). The length check keeps out
/// non-4-digit years chrono would otherwise still parse.
pub fn is_valid_post_date(date: &str) -> bool {
    date.len() == 10 && chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").is_ok()
}

/// Why an [`upsert_post`] call was refused before ever touching the database.
#[derive(Debug)]
pub enum PostError {
    /// Fails [`is_valid_post_id`].
    InvalidId,
    /// Not exactly `"patch"` or `"post"`.
    InvalidKind,
    /// Fails [`is_valid_post_date`].
    InvalidDate,
    /// Not exactly `"public"` or `"paid"`.
    InvalidVisibility,
    /// The database call itself failed.
    Db(rusqlite::Error),
}

impl From<rusqlite::Error> for PostError {
    fn from(e: rusqlite::Error) -> Self {
        PostError::Db(e)
    }
}

/// Insert or update one post by `id`. Validates `id`/`kind`/`date`/
/// `visibility` before touching the database — `title`/`summary`/`body`/`url`
/// carry no format constraint beyond what the column types already enforce.
///
/// `created_at` is stamped once, at first insert, and never moves; `now` is
/// written to `updated_at` on every call, insert or update alike — same
/// convention as [`upsert_device_profile`].
///
/// Returns `Ok(true)` if this call created the row, `Ok(false)` if it updated
/// an existing one.
pub fn upsert_post(conn: &Connection, post: &Post, now: &str) -> std::result::Result<bool, PostError> {
    if !is_valid_post_id(&post.id) {
        return Err(PostError::InvalidId);
    }
    if post.kind != "patch" && post.kind != "post" {
        return Err(PostError::InvalidKind);
    }
    if !is_valid_post_date(&post.date) {
        return Err(PostError::InvalidDate);
    }
    if post.visibility != "public" && post.visibility != "paid" {
        return Err(PostError::InvalidVisibility);
    }

    let existed: bool = conn
        .query_row("SELECT 1 FROM posts WHERE id = ?1", params![post.id], |_| Ok(()))
        .optional()?
        .is_some();

    conn.execute(
        "INSERT INTO posts (id, kind, version, date, title, summary, body, url, visibility, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)
         ON CONFLICT(id) DO UPDATE SET
             kind = ?2, version = ?3, date = ?4, title = ?5, summary = ?6,
             body = ?7, url = ?8, visibility = ?9, updated_at = ?10",
        params![
            post.id, post.kind, post.version, post.date, post.title,
            post.summary, post.body, post.url, post.visibility, now,
        ],
    )?;

    Ok(!existed)
}

/// Fetch one post by `id`. `include_non_public` is `false` for every reader
/// in this wave (`GET /api/posts/{id}`, the compatibility and HTML routes) —
/// it exists so a future authenticated/paid reader does not need a second,
/// near-identical query function.
pub fn get_post(conn: &Connection, id: &str, include_non_public: bool) -> Result<Option<Post>> {
    if include_non_public {
        conn.query_row(
            &format!("SELECT {} FROM posts WHERE id = ?1", POST_SELECT_COLUMNS),
            params![id],
            post_from_row,
        )
        .optional()
    } else {
        conn.query_row(
            &format!(
                "SELECT {} FROM posts WHERE id = ?1 AND visibility = 'public'",
                POST_SELECT_COLUMNS
            ),
            params![id],
            post_from_row,
        )
        .optional()
    }
}

/// List public posts, newest first by `(date, id)`, optionally filtered to
/// one `kind` and paginated with a `(date, id)` keyset cursor: `before`
/// returns only rows strictly older than that cursor in the `(date DESC, id
/// DESC)` ordering, so a page boundary that lands mid-day never skips or
/// repeats a same-day post.
pub fn list_posts(
    conn: &Connection,
    kind: Option<&str>,
    limit: i64,
    before: Option<(&str, &str)>,
) -> Result<Vec<Post>> {
    let mut sql = format!("SELECT {} FROM posts WHERE visibility = 'public'", POST_SELECT_COLUMNS);
    let mut bound: Vec<&dyn rusqlite::ToSql> = Vec::new();

    if let Some(k) = kind.as_ref() {
        sql.push_str(" AND kind = ?");
        bound.push(k as &dyn rusqlite::ToSql);
    }
    if let Some((date, id)) = before.as_ref() {
        sql.push_str(" AND (date < ? OR (date = ? AND id < ?))");
        bound.push(date as &dyn rusqlite::ToSql);
        bound.push(date as &dyn rusqlite::ToSql);
        bound.push(id as &dyn rusqlite::ToSql);
    }
    sql.push_str(" ORDER BY date DESC, id DESC LIMIT ?");
    bound.push(&limit as &dyn rusqlite::ToSql);

    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(bound.as_slice())?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(post_from_row(row)?);
    }
    Ok(out)
}

/// Delete one post by `id`. Returns `true` if a row was deleted, `false` if
/// no post had that id.
pub fn delete_post(conn: &Connection, id: &str) -> Result<bool> {
    let n = conn.execute("DELETE FROM posts WHERE id = ?1", params![id])?;
    Ok(n > 0)
}

#[cfg(test)]
mod tests {
    use super::{Connection, db_key_hex};

    #[test]
    fn db_key_hex_parses_hex_raw_and_whitespace() {
        let hex64 = "ab".repeat(32); // 32 bytes as 64 hex chars
        let raw32: Vec<u8> = (0u8..32).collect();

        // 64 hex characters are used as-is (normalized to lowercase).
        assert_eq!(db_key_hex(hex64.as_bytes()).as_deref(), Some(hex64.as_str()));
        assert_eq!(
            db_key_hex(hex64.to_uppercase().as_bytes()).as_deref(),
            Some(hex64.as_str())
        );

        // Raw bytes are hex-encoded verbatim.
        assert_eq!(
            db_key_hex(&raw32).as_deref(),
            Some(hex::encode(&raw32).as_str())
        );

        // Trailing whitespace is stripped before parsing.
        let with_ws = format!("{} \r\n", hex64);
        assert_eq!(db_key_hex(with_ws.as_bytes()).as_deref(), Some(hex64.as_str()));

        // Empty / whitespace-only input yields no key.
        assert_eq!(db_key_hex(b""), None);
        assert_eq!(db_key_hex(b"  \n"), None);
    }

    /// The users + share_links halves of the production schema, on top of the
    /// sync tables `init_test_conn` already builds — plus the four other
    /// tables `db::delete_account`'s cascade touches (auth_tokens,
    /// device_users, user_providers, web_sessions), so that cascade can be
    /// tested end to end. `PRAGMA foreign_keys=ON` matches production
    /// (`init_db`) so a wrong cascade order fails the test the same way it
    /// would fail in production, instead of silently passing in-memory.
    fn share_test_conn() -> Connection {
        let conn = super::init_test_conn();
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
                nick TEXT,
                nick_changed_at TEXT,
                UNIQUE(provider, provider_user_id)
            );
            CREATE UNIQUE INDEX idx_users_nick_lower ON users(LOWER(nick)) WHERE nick IS NOT NULL;

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
                revoked     INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE auth_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                created_at TEXT NOT NULL
            );

            CREATE TABLE device_users (
                device_id TEXT NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id),
                linked_at TEXT NOT NULL,
                PRIMARY KEY(device_id, user_id)
            );

            CREATE TABLE user_providers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                provider TEXT NOT NULL,
                provider_user_id TEXT NOT NULL,
                display_name TEXT NOT NULL DEFAULT '',
                linked_at TEXT NOT NULL,
                UNIQUE(provider, provider_user_id)
            );

            CREATE TABLE web_sessions (
                session_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            ",
        )
        .expect("share test schema");
        conn
    }

    fn insert_share_user(conn: &Connection, display_name: &str, public_id: Option<&str>) -> i64 {
        conn.execute(
            "INSERT INTO users (provider, provider_user_id, display_name, created_at, public_id)
             VALUES ('test', ?1, ?2, '2026-01-01T00:00:00+00:00', ?3)",
            rusqlite::params![display_name, display_name, public_id],
        )
        .expect("insert user");
        conn.last_insert_rowid()
    }

    fn future_ts() -> String {
        (chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339()
    }

    fn past_ts() -> String {
        (chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339()
    }

    #[test]
    fn share_link_roundtrip_and_owner_only_revoke() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "alice", Some("pub-alice"));
        let now = chrono::Utc::now().to_rfc3339();

        let token = super::create_share_link(&conn, uid, "live", "t", "{}", 0, &now, &future_ts())
            .expect("create");
        assert_eq!(token.len(), 32);

        let row = super::get_share_link(&conn, &token).expect("query").expect("row");
        assert_eq!(row.user_id, uid);
        assert_eq!(row.kind, "live");
        assert_eq!(row.blob_path, "");

        // Not the owner — revoke must refuse and the share must stay live.
        let other = insert_share_user(&conn, "mallory", Some("pub-mallory"));
        assert!(!super::revoke_share(&conn, other, &token).expect("revoke"));
        assert!(super::get_share_link(&conn, &token).expect("query").is_some());

        // The owner revokes; the share is then gone from every read path.
        assert!(super::revoke_share(&conn, uid, &token).expect("revoke"));
        assert!(super::get_share_link(&conn, &token).expect("query").is_none());
        // Revoking twice is not a success either.
        assert!(!super::revoke_share(&conn, uid, &token).expect("revoke"));
    }

    #[test]
    fn share_usage_counts_only_active_rows_per_kind() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "bob", Some("pub-bob"));
        let now = chrono::Utc::now().to_rfc3339();

        assert_eq!(super::share_usage(&conn, uid).expect("usage"), (0, 0));

        super::create_share_link(&conn, uid, "live", "l1", "{}", 0, &now, &future_ts())
            .expect("create");
        let shot = super::create_share_link(&conn, uid, "screenshot", "s1", "", 42, &now, &future_ts())
            .expect("create");
        assert_eq!(super::share_usage(&conn, uid).expect("usage"), (1, 1));

        // Expired and revoked rows stop counting.
        super::create_share_link(&conn, uid, "live", "l2", "{}", 0, &now, &past_ts())
            .expect("create");
        super::revoke_share(&conn, uid, &shot).expect("revoke");
        assert_eq!(super::share_usage(&conn, uid).expect("usage"), (1, 0));
    }

    #[test]
    fn list_share_links_returns_active_newest_first() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "carol", Some("pub-carol"));

        let older = super::create_share_link(
            &conn, uid, "live", "old", "{}", 0,
            "2026-01-01T00:00:00+00:00", &future_ts(),
        )
        .expect("create");
        let newer = super::create_share_link(
            &conn, uid, "screenshot", "new", "", 1,
            "2026-02-01T00:00:00+00:00", &future_ts(),
        )
        .expect("create");
        super::create_share_link(
            &conn, uid, "live", "dead", "{}", 0,
            "2026-03-01T00:00:00+00:00", &past_ts(),
        )
        .expect("create");

        let rows = super::list_share_links(&conn, uid).expect("list");
        let tokens: Vec<&str> = rows.iter().map(|r| r.token.as_str()).collect();
        assert_eq!(tokens, vec![newer.as_str(), older.as_str()]);
    }

    #[test]
    fn cleanup_expired_share_links_deletes_and_reports_blob_paths() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "dave", Some("pub-dave"));
        let now = chrono::Utc::now().to_rfc3339();

        let live_expired = super::create_share_link(&conn, uid, "live", "l", "{}", 0, &now, &past_ts())
            .expect("create");
        let shot_expired = super::create_share_link(&conn, uid, "screenshot", "s", "", 7, &now, &past_ts())
            .expect("create");
        super::set_share_blob_path(&conn, &shot_expired, &format!("{}/{}.png", uid, shot_expired))
            .expect("stamp blob path");
        let alive = super::create_share_link(&conn, uid, "live", "ok", "{}", 0, &now, &future_ts())
            .expect("create");

        let removed = super::cleanup_expired_share_links(&conn).expect("cleanup");
        assert_eq!(removed.len(), 2);
        // Live shares report an empty blob path — nothing to unlink.
        assert!(removed
            .iter()
            .any(|(t, p)| *t == live_expired && p.is_empty()));
        assert!(removed
            .iter()
            .any(|(t, p)| *t == shot_expired && *p == format!("{}/{}.png", uid, shot_expired)));

        assert!(super::get_share_link(&conn, &alive).expect("query").is_some());
        assert_eq!(super::cleanup_expired_share_links(&conn).expect("cleanup").len(), 0);
    }

    #[test]
    fn share_owner_label_prefers_display_name_then_public_id() {
        let conn = share_test_conn();
        let named = insert_share_user(&conn, "erin", Some("pub-erin"));
        let unnamed = insert_share_user(&conn, "", Some("pub-anon"));

        assert_eq!(
            super::share_owner_label(&conn, named).expect("label").as_deref(),
            Some("erin")
        );
        assert_eq!(
            super::share_owner_label(&conn, unnamed).expect("label").as_deref(),
            Some("pub-anon")
        );
        // No such user — None, never a fabricated name.
        assert!(super::share_owner_label(&conn, 99999).expect("label").is_none());
    }

    #[test]
    fn delete_account_cascades_share_links_and_returns_blob_paths() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "gina", Some("pub-gina"));
        let now = chrono::Utc::now().to_rfc3339();

        super::create_share_link(&conn, uid, "live", "l", "{}", 0, &now, &future_ts())
            .expect("create live");
        let shot = super::create_share_link(&conn, uid, "screenshot", "s", "", 7, &now, &future_ts())
            .expect("create screenshot");
        let blob_path = format!("{}/{}.png", uid, shot);
        super::set_share_blob_path(&conn, &shot, &blob_path).expect("stamp blob path");

        assert_eq!(super::share_usage(&conn, uid).expect("usage before"), (1, 1));

        let (deleted, blob_paths) = super::delete_account(&conn, uid).expect("delete account");
        assert_eq!(deleted, 1);
        assert_eq!(blob_paths, vec![blob_path]);
        // The rows are gone, not just unreachable — foreign_keys=ON above
        // means a leftover row referencing the deleted user would already
        // have failed the `DELETE FROM users` statement.
        assert_eq!(super::share_usage(&conn, uid).expect("usage after"), (0, 0));
    }

    // ------------------------------------------------------------------
    // Account nicks (operator ruling 2026-09-05)
    // ------------------------------------------------------------------

    #[test]
    fn nick_format_valid_boundaries() {
        assert!(super::nick_format_valid("abc"));
        assert!(super::nick_format_valid(&"a".repeat(24)));
        assert!(!super::nick_format_valid("ab"));
        assert!(!super::nick_format_valid(&"a".repeat(25)));
        assert!(!super::nick_format_valid("-abc"));
        assert!(!super::nick_format_valid("_abc"));
        assert!(!super::nick_format_valid("abc def"));
        assert!(!super::nick_format_valid("abc!"));
        assert!(super::nick_format_valid("a1_b-c.d"));
    }

    #[test]
    fn set_nick_happy_path() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "alice", Some("pub-alice"));

        super::set_nick(&conn, uid, "Al1ce").expect("set nick");

        assert_eq!(
            super::nick_for_user(&conn, uid).expect("nick").as_deref(),
            Some("Al1ce")
        );
        assert_eq!(
            super::effective_label_for_user(&conn, uid).expect("label"),
            "Al1ce"
        );
    }

    #[test]
    fn set_nick_uniqueness_is_case_insensitive() {
        let conn = share_test_conn();
        let a = insert_share_user(&conn, "alice", Some("pub-alice"));
        let b = insert_share_user(&conn, "bob", Some("pub-bob"));

        super::set_nick(&conn, a, "Foo").expect("first claim");
        match super::set_nick(&conn, b, "foo") {
            Err(super::NickError::Taken) => {}
            other => panic!("expected Taken, got {other:?}"),
        }
    }

    #[test]
    fn set_nick_rejects_reserved_names_case_insensitively() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "alice", Some("pub-alice"));

        for reserved in ["ZenGeld", "Kosti_X_ItsOK", "KOSTI_ITSOK"] {
            match super::set_nick(&conn, uid, reserved) {
                Err(super::NickError::Reserved) => {}
                other => panic!("expected Reserved for {reserved}, got {other:?}"),
            }
        }
    }

    #[test]
    fn set_nick_rejects_invalid_formats() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "alice", Some("pub-alice"));

        let too_long = "a".repeat(25);
        for bad in ["ab", too_long.as_str(), "bad char!", "_leading"] {
            match super::set_nick(&conn, uid, bad) {
                Err(super::NickError::Invalid) => {}
                other => panic!("expected Invalid for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn set_nick_rate_limits_second_change_within_30_days() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "alice", Some("pub-alice"));

        super::set_nick(&conn, uid, "first").expect("first change");
        match super::set_nick(&conn, uid, "second") {
            Err(super::NickError::RateLimited { .. }) => {}
            other => panic!("expected RateLimited, got {other:?}"),
        }
        // The rejected attempt must not have touched the stored nick.
        assert_eq!(
            super::nick_for_user(&conn, uid).expect("nick").as_deref(),
            Some("first")
        );
    }

    #[test]
    fn set_nick_allows_change_after_cooldown_elapsed() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "alice", Some("pub-alice"));

        super::set_nick(&conn, uid, "first").expect("first change");
        // Back-date nick_changed_at past the 30-day cooldown.
        let past = (chrono::Utc::now() - chrono::Duration::days(31)).to_rfc3339();
        conn.execute(
            "UPDATE users SET nick_changed_at = ?1 WHERE id = ?2",
            rusqlite::params![past, uid],
        )
        .expect("backdate nick_changed_at");

        super::set_nick(&conn, uid, "second").expect("change after cooldown");
        assert_eq!(
            super::nick_for_user(&conn, uid).expect("nick").as_deref(),
            Some("second")
        );
    }

    #[test]
    fn share_owner_label_prefers_nick_over_display_name() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "erin", Some("pub-erin"));

        super::set_nick(&conn, uid, "erin_nick").expect("set nick");

        assert_eq!(
            super::share_owner_label(&conn, uid).expect("label").as_deref(),
            Some("erin_nick")
        );
    }

    #[test]
    fn effective_label_for_user_fallback_chain() {
        let conn = share_test_conn();
        let named = insert_share_user(&conn, "frank", Some("pub-frank"));
        let anon = insert_share_user(&conn, "", Some("pub-anon2"));

        // No nick yet — falls back to display_name.
        assert_eq!(
            super::effective_label_for_user(&conn, named).expect("label"),
            "frank"
        );
        // No nick, empty display_name — falls back to public_id.
        assert_eq!(
            super::effective_label_for_user(&conn, anon).expect("label"),
            "pub-anon2"
        );

        // Nick set — wins over display_name.
        super::set_nick(&conn, named, "franknick").expect("set nick");
        assert_eq!(
            super::effective_label_for_user(&conn, named).expect("label"),
            "franknick"
        );

        // No such user — empty string, not an error.
        assert_eq!(super::effective_label_for_user(&conn, 99999).expect("label"), "");
    }

    // ------------------------------------------------------------------
    // Posts
    // ------------------------------------------------------------------

    /// Standalone `posts` table — no foreign keys, so this does not need
    /// `share_test_conn`'s users/share_links schema, just `init_test_conn`'s
    /// bare in-memory connection.
    fn posts_test_conn() -> Connection {
        let conn = super::init_test_conn();
        conn.execute_batch(
            "
            CREATE TABLE posts (
                id          TEXT    PRIMARY KEY,
                kind        TEXT    NOT NULL,
                version     TEXT,
                date        TEXT    NOT NULL,
                title       TEXT    NOT NULL,
                summary     TEXT    NOT NULL DEFAULT '',
                body        TEXT    NOT NULL DEFAULT '',
                url         TEXT    NOT NULL,
                visibility  TEXT    NOT NULL DEFAULT 'public',
                created_at  TEXT    NOT NULL,
                updated_at  TEXT    NOT NULL
            );
            CREATE INDEX idx_posts_date ON posts(date DESC, id DESC);
            ",
        )
        .expect("posts test schema");
        conn
    }

    fn sample_post(id: &str, kind: &str, date: &str, visibility: &str) -> super::Post {
        super::Post {
            id: id.to_string(),
            kind: kind.to_string(),
            version: Some("0.5.594".to_string()),
            date: date.to_string(),
            title: format!("Title {}", id),
            summary: "summary".to_string(),
            body: "para one\n\npara two".to_string(),
            url: format!("/blog/{}", id),
            visibility: visibility.to_string(),
            created_at: "2026-01-01T00:00:00+00:00".to_string(),
            updated_at: "2026-01-01T00:00:00+00:00".to_string(),
        }
    }

    #[test]
    fn post_id_and_date_validation() {
        assert!(super::is_valid_post_id("v0-5-594"));
        assert!(super::is_valid_post_id("ab"));
        assert!(!super::is_valid_post_id("a")); // too short (needs >= 2 chars)
        assert!(!super::is_valid_post_id("-abc")); // must not start with '-'
        assert!(!super::is_valid_post_id("Abc")); // no uppercase
        assert!(!super::is_valid_post_id("abc_def")); // no underscore
        assert!(!super::is_valid_post_id(&"a".repeat(82))); // too long

        assert!(super::is_valid_post_date("2026-09-05"));
        assert!(!super::is_valid_post_date("2026-02-30")); // not a real day
        assert!(!super::is_valid_post_date("2026/09/05")); // wrong separator
        assert!(!super::is_valid_post_date("26-09-05")); // wrong year width
        assert!(!super::is_valid_post_date("2026-09-5")); // wrong day width
    }

    #[test]
    fn upsert_post_reports_created_then_updated_and_preserves_created_at() {
        let conn = posts_test_conn();
        let post = sample_post("v1", "patch", "2026-09-01", "public");

        assert!(super::upsert_post(&conn, &post, "2026-09-01T00:00:00+00:00").expect("insert"));

        let mut updated = post.clone();
        updated.title = "New title".to_string();
        assert!(!super::upsert_post(&conn, &updated, "2026-09-02T00:00:00+00:00").expect("update"));

        let row = super::get_post(&conn, "v1", false).expect("get").expect("row");
        assert_eq!(row.title, "New title");
        // created_at is stamped from the first call's `now` and never moves
        // again; updated_at follows every call's `now` (the `Post` struct's
        // own created_at/updated_at fields are write-only convenience and
        // are not what lands in the row — `now` is the single source).
        assert_eq!(row.created_at, "2026-09-01T00:00:00+00:00");
        assert_eq!(row.updated_at, "2026-09-02T00:00:00+00:00");
    }

    #[test]
    fn upsert_post_rejects_invalid_fields() {
        let conn = posts_test_conn();
        let now = "2026-09-01T00:00:00+00:00";

        let bad_id = sample_post("Bad Id!", "patch", "2026-09-01", "public");
        assert!(matches!(super::upsert_post(&conn, &bad_id, now), Err(super::PostError::InvalidId)));

        let bad_kind = sample_post("v1", "news", "2026-09-01", "public");
        assert!(matches!(super::upsert_post(&conn, &bad_kind, now), Err(super::PostError::InvalidKind)));

        let bad_date = sample_post("v1", "patch", "not-a-date", "public");
        assert!(matches!(super::upsert_post(&conn, &bad_date, now), Err(super::PostError::InvalidDate)));

        let bad_visibility = sample_post("v1", "patch", "2026-09-01", "secret");
        assert!(matches!(
            super::upsert_post(&conn, &bad_visibility, now),
            Err(super::PostError::InvalidVisibility)
        ));

        // None of the rejected calls left a row behind.
        assert!(super::get_post(&conn, "v1", true).expect("get").is_none());
    }

    #[test]
    fn get_post_hides_paid_rows_unless_asked() {
        let conn = posts_test_conn();
        let now = "2026-09-01T00:00:00+00:00";
        super::upsert_post(&conn, &sample_post("paid-1", "post", "2026-09-01", "paid"), now)
            .expect("insert");

        assert!(super::get_post(&conn, "paid-1", false).expect("get").is_none());
        assert!(super::get_post(&conn, "paid-1", true).expect("get").is_some());
    }

    #[test]
    fn list_posts_orders_newest_first_and_filters_kind_and_visibility() {
        let conn = posts_test_conn();
        let now = "2026-09-01T00:00:00+00:00";
        super::upsert_post(&conn, &sample_post("older", "patch", "2026-09-01", "public"), now)
            .expect("insert");
        super::upsert_post(&conn, &sample_post("newer-post", "post", "2026-09-03", "public"), now)
            .expect("insert");
        super::upsert_post(&conn, &sample_post("newer-patch", "patch", "2026-09-03", "public"), now)
            .expect("insert");
        super::upsert_post(&conn, &sample_post("hidden-paid", "post", "2026-09-04", "paid"), now)
            .expect("insert");

        // Default: every public post, newest first; same-day rows tie-break
        // on id DESC ("newer-post" > "newer-patch" lexicographically).
        let all = super::list_posts(&conn, None, 50, None).expect("list");
        let ids: Vec<&str> = all.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["newer-post", "newer-patch", "older"]);

        // kind filter.
        let patches = super::list_posts(&conn, Some("patch"), 50, None).expect("list");
        let patch_ids: Vec<&str> = patches.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(patch_ids, vec!["newer-patch", "older"]);
    }

    #[test]
    fn list_posts_before_cursor_paginates_without_gap_or_repeat() {
        let conn = posts_test_conn();
        let now = "2026-09-01T00:00:00+00:00";
        super::upsert_post(&conn, &sample_post("p1", "post", "2026-09-01", "public"), now).expect("insert");
        super::upsert_post(&conn, &sample_post("p2", "post", "2026-09-02", "public"), now).expect("insert");
        super::upsert_post(&conn, &sample_post("p3", "post", "2026-09-03", "public"), now).expect("insert");

        let page1 = super::list_posts(&conn, None, 2, None).expect("list");
        let page1_ids: Vec<&str> = page1.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(page1_ids, vec!["p3", "p2"]);

        let cursor = page1.last().expect("last of page1");
        let page2 = super::list_posts(&conn, None, 2, Some((&cursor.date, &cursor.id))).expect("list");
        let page2_ids: Vec<&str> = page2.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(page2_ids, vec!["p1"]);
    }

    #[test]
    fn delete_post_removes_row_and_reports_whether_one_existed() {
        let conn = posts_test_conn();
        let now = "2026-09-01T00:00:00+00:00";
        super::upsert_post(&conn, &sample_post("v1", "patch", "2026-09-01", "public"), now).expect("insert");

        assert!(super::delete_post(&conn, "v1").expect("delete"));
        assert!(super::get_post(&conn, "v1", true).expect("get").is_none());
        assert!(!super::delete_post(&conn, "v1").expect("delete again"));
    }
}

/// In-memory plaintext connection with the parts of the production schema the
/// sync plane touches — for unit tests only (no SQLCipher key dance, no file).
#[cfg(test)]
pub(crate) fn init_test_conn() -> Connection {
    let conn = Connection::open_in_memory().expect("in-memory sqlite");
    conn.execute_batch(
        "
        CREATE TABLE sync_items (
            user_id      INTEGER NOT NULL,
            device_id    TEXT    NOT NULL DEFAULT '',
            profile_id   TEXT    NOT NULL DEFAULT '',
            sync_id      TEXT    NOT NULL,
            category     TEXT    NOT NULL,
            name         TEXT    NOT NULL,
            content      BLOB    NOT NULL,
            checksum     TEXT    NOT NULL,
            modified_at  INTEGER NOT NULL,
            deleted      INTEGER NOT NULL DEFAULT 0,
            created_at   TEXT    NOT NULL,
            display_name TEXT    NOT NULL DEFAULT '',
            PRIMARY KEY (user_id, device_id, profile_id, sync_id)
        );

        CREATE TABLE sync_e2e_params (
            user_id              INTEGER NOT NULL,
            profile_id           TEXT    NOT NULL DEFAULT '',
            salt                 TEXT    NOT NULL,
            iterations           INTEGER NOT NULL DEFAULT 600000,
            created_at           TEXT    NOT NULL,
            encrypted_master_key BLOB    DEFAULT NULL,
            PRIMARY KEY (user_id, profile_id)
        );
        ",
    )
    .expect("test schema");
    conn
}

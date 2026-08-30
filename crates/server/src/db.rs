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
// `devices`, `telemetry` and `releases` live here, not in the SQLCipher
// identity database — none of the three is irreplaceable identity data, and
// none needs the SQLCipher key. See
// docs/mlc/audits/2026-08-30-entry-lock-vault-and-user-persistence.md §6/§11.
// `device_users` deliberately stays in identity: it is a relationship between
// an account and a device, not a heartbeat.
//
// Every function below the "Devices" / "Telemetry" / "Releases" section
// headers still takes a plain `&Connection` — same as before the split — the
// caller is simply expected to pass the operational connection
// (`ControlPlane::ops_db`) instead of the identity one now.
// ============================================================================

/// Initialize the operational database: `devices`, `telemetry`, `releases`.
///
/// Plain SQLite, no SQLCipher key (see `ControlPlane::ops_db`'s doc comment
/// for why) — opened independently of the identity database's key wait, so a
/// box with no key pushed yet can still accept heartbeats and serve OTA
/// manifests.
pub fn init_ops_db(path: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;

    // Same columns and constraints as the identity tables these replace —
    // `releases` here is the already-migrated shape (channel + signature +
    // the widened UNIQUE), since that is what a fresh operational database
    // should start as, not the pre-migration shape identity's own history
    // carries.
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

        CREATE TABLE IF NOT EXISTS telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            user_id INTEGER,
            received_at TEXT NOT NULL,
            app_version TEXT NOT NULL,
            os TEXT NOT NULL DEFAULT '',
            arch TEXT NOT NULL DEFAULT '',
            gpu_name TEXT NOT NULL DEFAULT '',
            screen_width INTEGER NOT NULL DEFAULT 0,
            screen_height INTEGER NOT NULL DEFAULT 0,
            connector_count INTEGER NOT NULL DEFAULT 0,
            window_count INTEGER NOT NULL DEFAULT 0,
            avg_fps REAL NOT NULL DEFAULT 0,
            uptime_secs INTEGER NOT NULL DEFAULT 0,
            total_bars INTEGER NOT NULL DEFAULT 0,
            ws_connections INTEGER NOT NULL DEFAULT 0
        );

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

/// One-time move of `devices`, `telemetry` and `releases` out of the identity
/// database into the operational database. Called once at boot, after both
/// connections are open (see main.rs).
///
/// For each table: if it still exists in `identity_conn`, copy every row into
/// `ops_conn` (`INSERT OR IGNORE`, so a crash between the copy and the drop
/// on a previous boot doesn't fail a retry), compare row counts, and only
/// then `DROP TABLE` it from identity. A count mismatch aborts that table's
/// drop — both copies are left in place — and logs a loud error rather than
/// silently losing rows.
///
/// Idempotent: a table missing from `sqlite_master` in identity (already
/// moved, or a fresh install — identity's own `init_db` no longer creates
/// these three) is skipped with no log line. A table that does get moved logs
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
        "telemetry",
        "id, device_id, user_id, received_at, app_version, os, arch, gpu_name, \
         screen_width, screen_height, connector_count, window_count, avg_fps, \
         uptime_secs, total_bars, ws_connections",
        16,
    )?;
    move_legacy_table(
        identity_conn,
        ops_conn,
        "releases",
        "id, version, platform, channel, sha256, file_path, file_size, \
         release_notes, signature, created_at",
        10,
    )?;
    Ok(())
}

/// Copy every row of `table` from `identity_conn` to `ops_conn` using the
/// exact column list in `columns`, verify the row count, then drop it from
/// identity. `column_count` is `columns`' length, needed up front to build
/// the `?1..?N` placeholder list generically for any of the three tables.
///
/// Rows are read and re-inserted as `rusqlite::types::Value` — the schema is
/// identical on both sides (see `init_ops_db`), so no per-column type
/// conversion is needed, and a single generic function covers all three
/// tables instead of one hand-written copy per table.
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

/// Delete `telemetry` rows older than `retention_days` from the operational
/// database. Applied by the periodic cleanup task in main.rs; the day count
/// comes from `MLC_TELEMETRY_RETENTION_DAYS` (default 30).
///
/// Returns the number of rows deleted.
pub fn cleanup_old_telemetry(conn: &Connection, retention_days: i64) -> rusqlite::Result<usize> {
    let threshold = (chrono::Utc::now() - chrono::Duration::days(retention_days)).to_rfc3339();
    conn.execute("DELETE FROM telemetry WHERE received_at < ?1", params![threshold])
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
// ============================================================================

/// Insert a telemetry record.
#[allow(clippy::too_many_arguments)]
pub fn insert_telemetry(
    conn: &Connection,
    device_id: Option<&str>,
    user_id: Option<i64>,
    received_at: &str,
    app_version: &str,
    os: &str,
    arch: &str,
    gpu_name: &str,
    screen_width: i64,
    screen_height: i64,
    connector_count: i64,
    window_count: i64,
    avg_fps: f64,
    uptime_secs: i64,
    total_bars: i64,
    ws_connections: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO telemetry
            (device_id, user_id, received_at, app_version, os, arch, gpu_name,
             screen_width, screen_height, connector_count, window_count, avg_fps,
             uptime_secs, total_bars, ws_connections)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            device_id, user_id, received_at, app_version, os, arch, gpu_name,
            screen_width, screen_height, connector_count, window_count, avg_fps,
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
    conn.execute(
        "INSERT INTO releases (version, platform, channel, sha256, file_path, file_size, release_notes, signature, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(version, platform, channel) DO UPDATE SET
             sha256 = ?4,
             file_path = ?5,
             file_size = ?6,
             release_notes = ?7,
             signature = ?8",
        params![version, platform, channel, sha256, file_path, file_size, release_notes, signature, now],
    )?;
    Ok(())
}

/// Get the latest release for a given platform and channel (highest version by created_at).
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

/// Maximum content size per item (default): 512 KiB.
const SYNC_MAX_ITEM_BYTES: usize = 512 * 1024;

/// Maximum content size for preset items: 2 MiB.
const SYNC_MAX_PRESET_BYTES: usize = 2 * 1024 * 1024;

/// Per-category size limit.
pub(crate) fn max_item_bytes(category: &str) -> usize {
    match category {
        "preset" => SYNC_MAX_PRESET_BYTES,
        _ => SYNC_MAX_ITEM_BYTES,
    }
}

/// Maximum total content stored per user: 50 MiB.
pub(crate) const SYNC_MAX_TOTAL_BYTES: i64 = 50 * 1024 * 1024;

/// Maximum number of non-deleted items per user.
pub(crate) const SYNC_MAX_ITEMS: i64 = 200;

/// Return `(item_count, last_modified_at, quota_used_bytes)` for the user + profile.
///
/// `item_count` is the number of non-deleted items.
/// `last_modified_at` is `None` if the user has no items at all.
/// `quota_used_bytes` is the total byte length of content for non-deleted items.
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
/// - `content` must not exceed 1 MiB.
///
/// Quota checks (before any insert):
/// - Non-deleted items per user must be < `SYNC_MAX_ITEMS`.
/// - Total content bytes per user must be < `SYNC_MAX_TOTAL_BYTES`.
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
    let current_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sync_items WHERE user_id = ?1 AND device_id = ?2 AND profile_id = ?3 AND deleted = 0",
        params![user_id, device_id, profile_id],
        |row| row.get(0),
    )?;
    if current_count >= SYNC_MAX_ITEMS {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
            Some(format!(
                "User {} device '{}' profile '{}' has reached the sync item limit ({} items)",
                user_id, device_id, profile_id, SYNC_MAX_ITEMS
            )),
        ));
    }

    let current_bytes: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(LENGTH(content)), 0) FROM sync_items WHERE user_id = ?1 AND device_id = ?2 AND profile_id = ?3",
            params![user_id, device_id, profile_id],
            |row| row.get(0),
        )
        .unwrap_or(0);
    if current_bytes >= SYNC_MAX_TOTAL_BYTES {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
            Some(format!(
                "User {} device '{}' profile '{}' has reached the sync storage limit (50 MiB)",
                user_id, device_id, profile_id
            )),
        ));
    }

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
/// Cascade order: sync_e2e_params → sync_items → auth_tokens → device_users →
/// user_providers → web_sessions → users.
///
/// `telemetry` is NOT in this cascade — it moved to the operational database
/// in the 2026-08-30 store split, so it is a separate statement against a
/// separate connection now: `delete_account_telemetry`, below. The hot-plane
/// sync files (`<data_dir>/sync/<user_id>/…`) are likewise NOT touched by
/// this function — the caller (routes/sessions.rs::delete_account) calls
/// both that and `syncstore::purge_user`, since this module has no
/// cross-database or filesystem reach on its own; the caller is where the
/// two-database nature of a full account deletion is meant to be visible.
///
/// Returns the number of rows deleted from `users` (1 on success, 0 if user not found).
pub fn delete_account(conn: &Connection, user_id: i64) -> Result<usize> {
    conn.execute("DELETE FROM sync_e2e_params WHERE user_id = ?1", params![user_id])?;
    conn.execute("DELETE FROM sync_items WHERE user_id = ?1", params![user_id])?;
    conn.execute("DELETE FROM auth_tokens WHERE user_id = ?1", params![user_id])?;
    conn.execute("DELETE FROM device_users WHERE user_id = ?1", params![user_id])?;
    conn.execute("DELETE FROM user_providers WHERE user_id = ?1", params![user_id])?;
    conn.execute("DELETE FROM web_sessions WHERE user_id = ?1", params![user_id])?;
    let n = conn.execute("DELETE FROM users WHERE id = ?1", params![user_id])?;
    Ok(n)
}

/// Delete `telemetry` rows for a user from the **operational** database.
///
/// The operational-side half of account deletion — see `delete_account`'s
/// doc comment for why this is a separate function on a separate connection
/// rather than a line inside that cascade.
///
/// Returns the number of telemetry rows deleted.
pub fn delete_account_telemetry(ops_conn: &Connection, user_id: i64) -> rusqlite::Result<usize> {
    ops_conn.execute("DELETE FROM telemetry WHERE user_id = ?1", params![user_id])
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


#[cfg(test)]
mod tests {
    use super::db_key_hex;

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

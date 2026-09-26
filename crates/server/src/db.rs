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

/// Read the SQLCipher key once at boot (waiting on the tmpfs key file — see
/// [`wait_for_db_key`] — then deleting it), as a hex string suitable for
/// `PRAGMA key = "x'...'"`.
///
/// Split out of [`init_db`] (2026-09-06, social-plane storage split) so
/// `main.rs` can read the key exactly once and hand the same `key_hex` to
/// both [`init_db`] (identity) and `social_db::init_social_db` (social) —
/// the tmpfs file is deleted after this call, so it can only ever be read
/// once per boot.
pub fn read_sqlcipher_key() -> String {
    let key_path =
        std::env::var("MLC_DBKEY_PATH").unwrap_or_else(|_| DEFAULT_DBKEY_PATH.to_string());
    let key_hex = wait_for_db_key(&key_path);

    // The key now lives only in process memory — remove the tmpfs file. Done
    // here (not in `init_db`) since this is the one place the path is known
    // and this is the only read of it for the whole boot — both `init_db`
    // and `social_db::init_social_db` reuse the returned `key_hex`.
    if let Err(e) = std::fs::remove_file(&key_path) {
        tracing::warn!("Failed to remove database key file {}: {}", key_path, e);
    }
    key_hex
}

/// Initialize the identity database and create all tables. `key_hex` is the
/// SQLCipher key, already read via [`read_sqlcipher_key`].
pub fn init_db(path: &str, key_hex: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;

    // SQLCipher: the key must be the very first statement on the connection.
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", key_hex))?;

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

        -- Chart/indicator/strategy rights v1 (docs/mlc/plans/native-share-
        -- viewer-and-chart-rights-2026-09-06.md §2-3, docs/mlc/plans/
        -- social-sharing-access-gates-and-agent-control-2026-09-05.md §2). A
        -- grant that is NOT a share link: nick-to-nick or vendor-to-user,
        -- keyed by object id rather than a bearer token. `grantee_user_id`
        -- NULL means public. Nothing reads this table yet in v1 — a live
        -- share's own `read`/`clone` come from `share_links.clone_allowed`
        -- (see the ALTER below and `db::effective_rights`) — it exists now so
        -- the shape never needs to change once non-link grants are wired in.
        CREATE TABLE IF NOT EXISTS object_grants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            object_kind TEXT NOT NULL,   -- 'chart'|'indicator'|'strategy'|'template'
            object_id TEXT NOT NULL,
            owner_user_id INTEGER NOT NULL REFERENCES users(id),
            grantee_user_id INTEGER REFERENCES users(id),  -- NULL = public
            right TEXT NOT NULL,
            expires_at TEXT,
            created_at TEXT NOT NULL
        );

        -- Owner-curated named groups (docs/mlc/plans/share-policy-2026-09-25.md
        -- §1/§8.3) — v1 is manual membership only, no automatic sync from any
        -- entitlement/paid flag. `object_grants.grantee_group_id` (see the
        -- ALTER below) references a row here the same way `grantee_user_id`
        -- references `users(id)`: a share-tier grant targets EITHER one
        -- account OR one group, never both.
        CREATE TABLE IF NOT EXISTS grant_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_user_id INTEGER NOT NULL REFERENCES users(id),
            name TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS grant_group_members (
            group_id INTEGER NOT NULL REFERENCES grant_groups(id),
            user_id  INTEGER NOT NULL REFERENCES users(id),
            added_at TEXT NOT NULL,
            PRIMARY KEY (group_id, user_id)
        );
        CREATE INDEX IF NOT EXISTS idx_grant_group_members_user ON grant_group_members(user_id);

        -- Minimal vendor model for strip-on-clone (plan §3, routes/share.rs
        -- clone_share). A `type_id` present here is a user-published
        -- indicator with an owner; a `type_id` absent is a built-in `mli`
        -- script and is never stripped (see db::indicator_should_strip).
        CREATE TABLE IF NOT EXISTS published_indicators (
            type_id TEXT PRIMARY KEY,
            owner_user_id INTEGER NOT NULL REFERENCES users(id),
            visibility TEXT NOT NULL DEFAULT 'private',
            created_at TEXT NOT NULL
        );

        -- A vendor's grant of one published indicator to one recipient,
        -- optionally TTL'd (`expires_at` NULL = no expiry). clone_share keeps
        -- an indicator whose type_id has no `published_indicators` row, or
        -- whose owner IS the recipient, or that has a live row here.
        CREATE TABLE IF NOT EXISTS indicator_grants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type_id TEXT NOT NULL REFERENCES published_indicators(type_id),
            grantee_user_id INTEGER NOT NULL REFERENCES users(id),
            expires_at TEXT,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_indicator_grants_type_grantee
            ON indicator_grants(type_id, grantee_user_id);

        -- Shared presets (rooms) — Phase 1 (docs/mlc/plans/shared-presets-
        -- rights-and-live-sync-2026-09-23.md §1). A room header: no preset
        -- blob and no single version live here — those live in
        -- shared_preset_entities below (per-entity LWW, §3). `object_id`
        -- reuses the client's own ChartPreset.id verbatim (see
        -- `db::apply_room_patch`, which never remaps it). `seq` is a
        -- room-level monotonic counter, +1 per successfully applied entity
        -- op (including a cascade tombstone) — the input `room_entities_
        -- since` polls against.
        CREATE TABLE IF NOT EXISTS shared_presets (
            object_id     TEXT    PRIMARY KEY,
            owner_user_id INTEGER NOT NULL REFERENCES users(id),
            title         TEXT    NOT NULL DEFAULT '',
            visibility    TEXT    NOT NULL DEFAULT 'private',
            seq           INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT    NOT NULL,
            updated_at    TEXT    NOT NULL
        );

        -- One row per entity a room's preset decomposes into (window,
        -- bubble, indicator, alert, primitive, or the singleton "layout"
        -- catch-all — see `rooms_codec::decompose_preset`). A real table
        -- per entity, not a JSON blob patched in place: a per-entity write
        -- is a trivial single-row `UPDATE ... WHERE version=?` (atomic,
        -- cheap), and the table doubles as its own diff/replay ring for the
        -- live channel (`SELECT WHERE seq > ?`, see `db::room_entities_
        -- since`) with zero extra bookkeeping. `parent_kind`/`parent_id`
        -- are real, indexed columns (not buried in `json`) so a window/
        -- bubble delete can cascade to its primitives with one indexed
        -- `UPDATE`, no JSON1 extension dependency — set only for
        -- kind = 'primitive'. `json` is NULL exactly when `deleted = 1`
        -- (a tombstone).
        CREATE TABLE IF NOT EXISTS shared_preset_entities (
            room_id     TEXT    NOT NULL REFERENCES shared_presets(object_id),
            kind        TEXT    NOT NULL,
            entity_id   TEXT    NOT NULL,
            version     INTEGER NOT NULL DEFAULT 1,
            updated_by  INTEGER NOT NULL REFERENCES users(id),
            updated_at  TEXT    NOT NULL,
            json        TEXT,
            deleted     INTEGER NOT NULL DEFAULT 0,
            seq         INTEGER NOT NULL,
            parent_kind TEXT,
            parent_id   TEXT,
            PRIMARY KEY (room_id, kind, entity_id)
        );
        CREATE INDEX IF NOT EXISTS idx_shared_preset_entities_room_seq ON shared_preset_entities(room_id, seq);
        CREATE INDEX IF NOT EXISTS idx_shared_preset_entities_parent ON shared_preset_entities(room_id, parent_kind, parent_id);

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

        -- In-app forum (2026-09-05 users-paid-features scope doc §4): a
        -- communication surface BETWEEN accounts (threads + replies, links to
        -- shared charts), gated to paid accounts only via
        -- entitlements::Feature::Forum — never free, never public (see
        -- routes/forum.rs). `hidden` is moderation: a thread/reply the author
        -- deleted themselves, or an admin hid — a hidden row is never
        -- physically deleted, because a reply's thread must survive even
        -- once every OTHER row referencing it (a reply, or the author's own
        -- account) is gone. Authors display via `effective_label_for_user`
        -- (nick -> display_name -> public_id), or "deleted user" once that
        -- account itself is gone (see db::forum_author_label).
        --
        -- `author_user_id` is deliberately NOT `REFERENCES users(id)`, unlike
        -- every other user-owned table in this file: forum content must
        -- outlive the account that created it (see `delete_account`, which
        -- hides — never deletes — a deleted account's forum rows so that
        -- other users' replies keep their thread). `PRAGMA foreign_keys=ON`
        -- (above) enforces a real REFERENCES clause immediately and
        -- non-deferred, so a hard FK here would make `DELETE FROM users`
        -- fail the moment that account had ever posted once. `thread_id` on
        -- `forum_replies`, by contrast, DOES reference `forum_threads(id)`
        -- safely: threads are likewise never deleted, only hidden.
        CREATE TABLE IF NOT EXISTS forum_threads (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            author_user_id INTEGER NOT NULL,
            title          TEXT    NOT NULL,
            body           TEXT    NOT NULL,
            created_at     TEXT    NOT NULL,
            updated_at     TEXT    NOT NULL,
            last_reply_at  TEXT,
            reply_count    INTEGER NOT NULL DEFAULT 0,
            hidden         INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_forum_threads_visible
            ON forum_threads(hidden, last_reply_at DESC, id DESC);

        CREATE TABLE IF NOT EXISTS forum_replies (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            thread_id      INTEGER NOT NULL REFERENCES forum_threads(id),
            author_user_id INTEGER NOT NULL,
            body           TEXT    NOT NULL,
            created_at     TEXT    NOT NULL,
            hidden         INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_forum_replies_thread
            ON forum_replies(thread_id, hidden, id);

        -- Audit trail for `POST /api/admin/users/merge` (docs/mlc/plans/
        -- identity-merge-2026-09-09.md decision 4) — one row per merge,
        -- `summary_json` the full `account_merge::MergeSummary` (counts per
        -- table, conflicts, hot-plane file counts). `from_user_id`/
        -- `into_user_id` deliberately carry no FK: by the time this row is
        -- written `from_user_id` no longer exists in `users` (the merge's
        -- whole point), same reasoning `forum_threads.author_user_id`
        -- already documents for outliving an account.
        CREATE TABLE IF NOT EXISTS account_merges (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user_id  INTEGER NOT NULL,
            into_user_id  INTEGER NOT NULL,
            ts            TEXT    NOT NULL,
            summary_json  TEXT    NOT NULL
        );

        -- Outreach notifications (owner ruling 2026-09-09, `POST
        -- /api/admin/notify` — see the "Outreach notifications" section
        -- above this file's `redeem_gift_code`). `notify_batches` stores the
        -- message text exactly once per non-dry-run call; `notify_log` never
        -- repeats it, one row per (batch, recipient) attempt instead.
        CREATE TABLE IF NOT EXISTS notify_batches (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ts           TEXT    NOT NULL,
            channel      TEXT    NOT NULL,
            text         TEXT    NOT NULL,
            requested_by TEXT    NOT NULL DEFAULT 'admin'
        );

        CREATE TABLE IF NOT EXISTS notify_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT    NOT NULL,
            channel   TEXT    NOT NULL,
            user_id   INTEGER NOT NULL,
            ok        INTEGER NOT NULL,
            error     TEXT,
            text_hash TEXT    NOT NULL,
            batch_id  INTEGER NOT NULL REFERENCES notify_batches(id)
        );

        CREATE INDEX IF NOT EXISTS idx_notify_log_batch ON notify_log(batch_id);
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
    // Safe migration: add clone_allowed column to share_links (rights v1, see
    // docs/mlc/plans/native-share-viewer-and-chart-rights-2026-09-06.md §2).
    // 0 = unchanged behaviour for every row created before this column
    // existed; chosen explicitly at creation time from here on
    // (CreateLiveShareRequest.clone_allowed, routes/share.rs). Like
    // paid_until above, CREATE TABLE share_links up top is never edited for
    // this column — only this ALTER adds it, on a live database.
    let _ = conn.execute("ALTER TABLE share_links ADD COLUMN clone_allowed INTEGER NOT NULL DEFAULT 0", []);
    // Safe migration: chart-share policy, link kinds v1 (docs/mlc/plans/
    // share-policy-2026-09-25.md §1/§11 step 1). `interaction` is "view" |
    // "interactive" — 'view' is the safe default for every row created
    // before this column existed (an old client that never chose "view" vs
    // "interactive" gets the MORE restrictive behaviour). `protected_json`
    // is a serialized `Vec<ProtectedElementRef>` (routes/share.rs) the
    // sharer marked Protected at creation time — '[]' for every pre-existing
    // row, matching "nothing was ever marked Protected before this feature
    // existed". Like `clone_allowed` above, `CREATE TABLE share_links` up
    // top is never edited for these two columns — only these ALTERs add
    // them, on a live database.
    let _ = conn.execute("ALTER TABLE share_links ADD COLUMN interaction TEXT NOT NULL DEFAULT 'view'", []);
    let _ = conn.execute("ALTER TABLE share_links ADD COLUMN protected_json TEXT NOT NULL DEFAULT '[]'", []);
    // Safe migration: chart-share policy v1, Rev 2 (§1/§11 step 2).
    // `visibility` is "public" | "private" — 'public' for every pre-existing
    // row, exactly today's behaviour (every link was reachable by anyone who
    // had it). `preview_path` is reserved for the per-link preview card
    // (§9, unused until that step lands) — added here to keep this
    // migration wave's ALTER TABLEs in one batch rather than spread across
    // two boots. Both, like `interaction`/`protected_json` above, are never
    // added to `CREATE TABLE share_links` up top — only these ALTERs add
    // them, on a live database.
    let _ = conn.execute("ALTER TABLE share_links ADD COLUMN visibility TEXT NOT NULL DEFAULT 'public'", []);
    let _ = conn.execute("ALTER TABLE share_links ADD COLUMN preview_path TEXT NOT NULL DEFAULT ''", []);
    // Safe migration: chart-share policy, Rev 3 (docs/mlc/plans/share-policy-
    // 2026-09-25.md, "Rev 3"). `allow_forward` is a NULLABLE integer, not a
    // `NOT NULL ... DEFAULT` column like its siblings above — deliberately:
    // NULL means "never explicitly set", and the *effective* value is derived
    // at READ time from the link's own `visibility` (see
    // [`ShareLinkRow::effective_allow_forward`]): `true` for a public link,
    // `false` for a private one. This is what makes a later `PATCH`
    // visibility change able to move the effective default without ever
    // touching this column, while a caller who DID set `allow_forward`
    // explicitly (0 or 1, at create or via PATCH) keeps that exact value
    // forever, regardless of any later visibility change — the one row this
    // plan does not want a `NOT NULL DEFAULT` for. Every pre-existing row
    // reads back NULL here (unset), so it silently starts following its own
    // `visibility`'s default — `true` for the public links that are the
    // overwhelming majority of existing rows, matching today's actual
    // behaviour of "recipients can already forward the raw link text".
    let _ = conn.execute("ALTER TABLE share_links ADD COLUMN allow_forward INTEGER", []);
    // Pin keeps a link out of the ring. Unpinned links are the ones creation
    // burns, oldest first, once the account is at its cap. Existing rows
    // start unpinned.
    let _ = conn.execute(
        "ALTER TABLE share_links ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0",
        [],
    );
    // One live link per author chart. Empty chart_id is a legacy row that
    // was minted once and is never reused. `revision` bumps every time the
    // author republishes that chart onto the same token.
    let _ = conn.execute(
        "ALTER TABLE share_links ADD COLUMN chart_id TEXT NOT NULL DEFAULT ''",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE share_links ADD COLUMN revision INTEGER NOT NULL DEFAULT 1",
        [],
    );
    // Monotonic op log head for live follow and co-edit. Republishing the
    // preset resets this to 0 and deletes the log: the preset is the new
    // baseline, later ops are the delta.
    let _ = conn.execute(
        "ALTER TABLE share_links ADD COLUMN op_seq INTEGER NOT NULL DEFAULT 0",
        [],
    );
    // Live is a channel. Off (default) means the link updates on a cadence.
    let _ = conn.execute(
        "ALTER TABLE share_links ADD COLUMN live INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE users ADD COLUMN discoverable INTEGER NOT NULL DEFAULT 1",
        [],
    );
    let _ = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS friendships (
            user_id INTEGER NOT NULL,
            friend_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (user_id, friend_id)
        );
        CREATE TABLE IF NOT EXISTS friend_invites (
            token TEXT PRIMARY KEY,
            inviter_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );",
    );
    let _ = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS share_ops (
            token TEXT NOT NULL,
            seq INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            object_id TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (token, seq)
        );",
    );
    // Safe migration: per-account/group share rights (§1's new `ShareTier`
    // core). NULL for every existing `object_grants` row — a grant with no
    // group target simply never matches via `grant_group_members`, the same
    // way a NULL `grantee_user_id` already means "no per-account target".
    let _ = conn.execute("ALTER TABLE object_grants ADD COLUMN grantee_group_id INTEGER REFERENCES grant_groups(id)", []);
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

    // Safe migration: per-identity email (docs/mlc/plans/identity-merge-2026-09-09.md
    // decision 1). Filled/refreshed at every sign-in and explicit link (see
    // `upsert_user` / `link_provider_to_user`); NULL/0 for identities recorded
    // before this column existed, and for providers that structurally cannot
    // supply one (Twitter/X, Telegram). The partial index only covers
    // verified rows — auto-attach (decision 2, `user_id_by_verified_email`)
    // must never match on an unverified claim.
    let _ = conn.execute("ALTER TABLE user_providers ADD COLUMN email TEXT", []);
    let _ = conn.execute("ALTER TABLE user_providers ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0", []);
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_user_providers_email_verified
            ON user_providers(LOWER(email)) WHERE email_verified = 1;",
    )?;

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

    // Reserved-nick registry (owner ruling 2026-09-09: occupy the good
    // handles now, hand them to specific accounts later through an admin
    // route — see [`seed_reserved_nicks`] and [`is_nick_reserved`]).
    // `granted_to` is NULL until an operator hands the row to an account via
    // `admin_set_nick`; `INSERT OR IGNORE` in the seed below never touches an
    // existing row, so a grant is never clobbered by a reboot re-seeding the
    // same file.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS reserved_nicks (
            nick_lower  TEXT PRIMARY KEY,
            category    TEXT NOT NULL,
            note        TEXT,
            reserved_at TEXT NOT NULL,
            granted_to  INTEGER
        );",
    )?;
    let (seeded, rejected) = seed_reserved_nicks(&conn)?;
    if seeded > 0 || !rejected.is_empty() {
        tracing::info!(
            "reserved_nicks: seeded {} new entr{} from reserved_nicks.txt, {} rejected",
            seeded,
            if seeded == 1 { "y" } else { "ies" },
            rejected.len(),
        );
    }

    // Forbidden-nick registry (owner order 2026-09-09) — parsed once here so
    // the cost and any warnings land in the startup log rather than on the
    // first nick-change request; see `nick_policy::init_forbidden_list`.
    let forbidden_report = crate::nick_policy::init_forbidden_list();
    let degenerate_count = forbidden_report.degenerate_substrings.len();
    tracing::info!(
        "forbidden_nicks: loaded {} substring, {} token, {} numeric rule(s), {} degenerate substring entr{} kept token-only",
        forbidden_report.substring_count,
        forbidden_report.token_count,
        forbidden_report.numeric_count,
        degenerate_count,
        if degenerate_count == 1 { "y" } else { "ies" },
    );
    if !forbidden_report.empty_after_normalize.is_empty() {
        tracing::warn!(
            "forbidden_nicks.txt: {} entr{} normalize to nothing, dropped: {:?}",
            forbidden_report.empty_after_normalize.len(),
            if forbidden_report.empty_after_normalize.len() == 1 { "y" } else { "ies" },
            forbidden_report.empty_after_normalize,
        );
    }

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
    if cleaned.removed_no_provider > 0 || cleaned.removed_recent_self_ref > 0 {
        tracing::info!(
            "Cleaned up {} orphan user(s) with no linked providers, {} self-referencing orphan(s) created in the last 24h",
            cleaned.removed_no_provider,
            cleaned.removed_recent_self_ref,
        );
    }
    if cleaned.skipped_dormant > 0 {
        tracing::info!(
            "Left {} dormant self-referencing user(s) older than 24h in place (admin merge territory)",
            cleaned.skipped_dormant,
        );
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

/// Outcome of [`cleanup_orphan_users`] — how many rows each rule removed,
/// plus how many self-referencing candidates were left in place for being
/// too old to be the throwaway shape the rule targets.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OrphanCleanup {
    /// Rows deleted for having no `user_providers` entry at all.
    pub removed_no_provider: usize,
    /// Self-referencing-orphan-shape rows created within the last 24h.
    pub removed_recent_self_ref: usize,
    /// Self-referencing-orphan-shape rows older than 24h, left alone —
    /// these are dormant accounts the admin merge flow handles, not the
    /// throwaway rows this rule targets.
    pub skipped_dormant: usize,
}

/// Delete users who have no entries in `user_providers`, plus the subtler
/// shape the pre-fix `finish_oauth` device-merge branch used to leave behind
/// (docs/mlc/plans/identity-merge-2026-09-09.md decision 3): a `users` row
/// whose ONLY `user_providers` row is its own automatic self-mirror (the
/// `(provider, provider_user_id)` matches the `users` row itself), holding no
/// `auth_tokens`, `web_sessions`, `device_users`, `sync_items`, `share_links`,
/// or forum authorship — nothing will ever resolve to it again, but it isn't
/// "no providers at all" so the first rule alone misses it.
///
/// These orphan rows are sometimes left behind when a merge or link operation
/// moves all provider identities to a canonical user account without removing
/// the now-empty source row from `users`.
///
/// The self-referencing rule only fires on rows created in the last 24
/// hours: on 2026-09-09 it deleted two dormant-but-real accounts (a second
/// provider linked once, months ago, then never used again) — for people
/// other than an account's own owner, that dormant shape is exactly what the
/// admin merge (`POST /api/admin/users/merge`) exists to fold, not something
/// boot-time cleanup should silently erase. Only the throwaway rows the old
/// device flow left behind seconds after creation are still swept
/// automatically.
pub fn cleanup_orphan_users(conn: &rusqlite::Connection) -> rusqlite::Result<OrphanCleanup> {
    let removed_no_provider = conn.execute(
        "DELETE FROM users WHERE id NOT IN (SELECT DISTINCT user_id FROM user_providers)",
        [],
    )?;

    // The self-referencing shape: find the candidates (with their creation
    // time) first, then delete each recent one's self-mirror
    // `user_providers` row before the `users` row itself —
    // `PRAGMA foreign_keys=ON` (see `init_db`) refuses `DELETE FROM users`
    // while a `user_providers` row still references it, and this shape by
    // definition has exactly one such row.
    //
    // The age cutoff is computed in Rust and bound as a parameter, compared
    // directly against the RFC3339 `created_at` text (both sides use
    // `to_rfc3339()`'s fixed-width, always-UTC-offset format, so plain text
    // comparison sorts chronologically) — unlike `cleanup_oauth_states`'
    // `datetime('now', ...)` idiom, this avoids SQLite's `datetime()`
    // rendering a space-separated, offset-less string that would compare
    // unreliably against the `T`-separated, offset-carrying column.
    let cutoff = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();

    let candidates: Vec<(i64, String)> = {
        let mut stmt = conn.prepare(
            "SELECT u.id, u.created_at FROM users u
             WHERE (SELECT COUNT(*) FROM user_providers up WHERE up.user_id = u.id) = 1
               AND EXISTS (
                   SELECT 1 FROM user_providers up
                   WHERE up.user_id = u.id
                     AND up.provider = u.provider
                     AND up.provider_user_id = u.provider_user_id
               )
               AND NOT EXISTS (SELECT 1 FROM auth_tokens WHERE user_id = u.id)
               AND NOT EXISTS (SELECT 1 FROM web_sessions WHERE user_id = u.id)
               AND NOT EXISTS (SELECT 1 FROM device_users WHERE user_id = u.id)
               AND NOT EXISTS (SELECT 1 FROM sync_items WHERE user_id = u.id)
               AND NOT EXISTS (SELECT 1 FROM share_links WHERE user_id = u.id)
               AND NOT EXISTS (SELECT 1 FROM forum_threads WHERE author_user_id = u.id)
               AND NOT EXISTS (SELECT 1 FROM forum_replies WHERE author_user_id = u.id)",
        )?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<(i64, String)>>>()?;
        rows
    };

    let mut removed_recent_self_ref = 0;
    let mut skipped_dormant = 0;
    for (id, created_at) in candidates {
        if created_at < cutoff {
            skipped_dormant += 1;
            continue;
        }
        conn.execute("DELETE FROM user_providers WHERE user_id = ?1", params![id])?;
        removed_recent_self_ref += conn.execute("DELETE FROM users WHERE id = ?1", params![id])?;
    }

    Ok(OrphanCleanup {
        removed_no_provider,
        removed_recent_self_ref,
        skipped_dormant,
    })
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

/// Split an optional `(email, verified)` pair into the `(Option<&str>, i64)`
/// shape every `user_providers` write below binds — `None` maps to `(NULL, 0)`.
fn email_bind_params(email: Option<(&str, bool)>) -> (Option<&str>, i64) {
    match email {
        Some((addr, verified)) => (Some(addr), verified as i64),
        None => (None, 0),
    }
}

/// Upsert a user by provider + provider_user_id, and keep that identity's
/// `user_providers` self-mirror row in sync in the same call (previously this
/// only happened via the once-per-boot backfill in `init_db`, which left a
/// freshly created account's own identity invisible to
/// `user_id_for_identity`/`user_id_by_verified_email` until the next
/// restart). `email` is `Some((address, verified))` when the provider
/// reported one this sign-in; `None` leaves a previously stored email
/// untouched rather than clearing it.
///
/// Returns the user's internal id.
pub fn upsert_user(
    conn: &Connection,
    provider: &str,
    provider_user_id: &str,
    display_name: &str,
    email: Option<(&str, bool)>,
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

    let (email_addr, email_verified) = email_bind_params(email);
    conn.execute(
        "INSERT INTO user_providers (user_id, provider, provider_user_id, display_name, linked_at, email, email_verified)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(provider, provider_user_id) DO UPDATE SET
             display_name = ?4,
             linked_at = ?5,
             email = COALESCE(?6, email),
             email_verified = CASE WHEN ?6 IS NOT NULL THEN ?7 ELSE email_verified END",
        params![id, provider, provider_user_id, display_name, now, email_addr, email_verified],
    )?;

    Ok(id)
}

/// Link a provider identity to an existing user account.
/// Used when a logged-in user adds a new provider from the dashboard.
///
/// Guards:
/// - If the provider identity is already linked to the same user, just updates display_name/email.
/// - If the provider identity is already linked to a *different* user, returns a constraint error.
/// - Never touches the `users` table.
///
/// `email` is `Some((address, verified))` when the provider reported one this
/// sign-in/link; `None` leaves a previously stored email untouched.
pub fn link_provider_to_user(
    conn: &Connection,
    user_id: i64,
    provider: &str,
    provider_user_id: &str,
    display_name: &str,
    email: Option<(&str, bool)>,
    now: &str,
) -> Result<()> {
    let existing_owner = user_id_for_identity(conn, provider, provider_user_id)?;
    let (email_addr, email_verified) = email_bind_params(email);

    if let Some(owner_id) = existing_owner {
        if owner_id == user_id {
            // Already linked to this user — just refresh display_name/email.
            conn.execute(
                "UPDATE user_providers SET display_name = ?1, linked_at = ?2,
                     email = COALESCE(?3, email),
                     email_verified = CASE WHEN ?3 IS NOT NULL THEN ?4 ELSE email_verified END
                 WHERE user_id = ?5 AND provider = ?6 AND provider_user_id = ?7",
                params![display_name, now, email_addr, email_verified, user_id, provider, provider_user_id],
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
        "INSERT INTO user_providers (user_id, provider, provider_user_id, display_name, linked_at, email, email_verified) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![user_id, provider, provider_user_id, display_name, now, email_addr, email_verified],
    )?;
    Ok(())
}

/// The account id already holding this exact `(provider, provider_user_id)`
/// identity, if any. Authoritative immediately after `upsert_user`/
/// `link_provider_to_user` write it — see those functions' doc comments.
fn user_id_for_identity(conn: &Connection, provider: &str, provider_user_id: &str) -> Result<Option<i64>> {
    conn.query_row(
        "SELECT user_id FROM user_providers WHERE provider = ?1 AND provider_user_id = ?2",
        params![provider, provider_user_id],
        |row| row.get(0),
    )
    .optional()
}

/// Every account id already holding this VERIFIED email on some provider
/// identity, ordered ascending (the lowest id is the auto-attach target —
/// docs/mlc/plans/identity-merge-2026-09-09.md decision 2). `email_lower`
/// must already be lower-cased by the caller — the index
/// (`idx_user_providers_email_verified`) is built on `LOWER(email)` and a
/// case-mismatched literal would defeat it.
pub fn user_id_by_verified_email(conn: &Connection, email_lower: &str) -> Result<Vec<i64>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT user_id FROM user_providers
         WHERE LOWER(email) = ?1 AND email_verified = 1
         ORDER BY user_id ASC",
    )?;
    let ids = stmt
        .query_map(params![email_lower], |row| row.get(0))?
        .collect::<Result<Vec<i64>>>()?;
    Ok(ids)
}

/// Resolve or create the account a freshly-authenticated provider identity
/// belongs to — the auto-attach decision every non-explicit-link OAuth path
/// makes (`web_callback`, `telegram_web_callback`, `finish_oauth`, the
/// Telegram-bot login poll). See
/// docs/mlc/plans/identity-merge-2026-09-09.md decisions 2–3.
///
/// Order:
/// 1. The identity is already KNOWN (a `user_providers` row exists for
///    `(provider, provider_user_id)`) — resolves to its own owner regardless
///    of `device_id`; only display_name/email are refreshed.
/// 2. UNKNOWN identity, `device_id` non-empty and already linked
///    (`device_users`) to an account — the identity attaches to that account
///    directly. This is the device-flow-orphan fix (decision 3): no `users`
///    row is ever created for an identity that turns out to belong to an
///    already-linked device, so there is nothing left to reassign tokens away
///    from and nothing left to clean up afterward.
/// 3. UNKNOWN identity, no device match, but the provider reported a VERIFIED
///    email that already belongs to one or more accounts — attaches to the
///    lowest id (`user_id_by_verified_email`), logging a `warn` naming the
///    other candidate ids when more than one exists (pre-existing
///    duplicates the admin merge folds together later).
/// 4. Otherwise: a brand new account (`upsert_user`).
pub fn resolve_or_create_user(
    conn: &Connection,
    provider: &str,
    provider_user_id: &str,
    display_name: &str,
    email: Option<(&str, bool)>,
    device_id: &str,
    now: &str,
) -> Result<i64> {
    if let Some(owner) = user_id_for_identity(conn, provider, provider_user_id)? {
        link_provider_to_user(conn, owner, provider, provider_user_id, display_name, email, now)?;
        return Ok(owner);
    }

    if !device_id.is_empty() {
        if let Some(existing) = get_user_for_device(conn, device_id)? {
            link_provider_to_user(conn, existing, provider, provider_user_id, display_name, email, now)?;
            return Ok(existing);
        }
    }

    if let Some((addr, true)) = email {
        let lower = addr.to_lowercase();
        let candidates = user_id_by_verified_email(conn, &lower)?;
        if let Some((lowest, others)) = candidates.split_first() {
            if !others.is_empty() {
                let other_ids = others.iter().map(|id| id.to_string()).collect::<Vec<_>>().join(", ");
                tracing::warn!(
                    "Verified email match for {}:{} found {} existing accounts (attaching to \
                     lowest id={}, also present on: {})",
                    provider, provider_user_id, candidates.len(), lowest, other_ids
                );
            }
            link_provider_to_user(conn, *lowest, provider, provider_user_id, display_name, email, now)?;
            return Ok(*lowest);
        }
    }

    upsert_user(conn, provider, provider_user_id, display_name, email, now)
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
    /// Fails [`nick_format_valid`] or [`crate::nick_policy::nick_shape_ok`].
    /// `routes::account` validates both before ever calling `set_nick`, so
    /// this is a backstop for any other caller, not the primary path.
    Invalid,
    /// Matches the forbidden-nick registry (`crate::nick_policy::forbidden_hit`)
    /// — never assignable, self-service or admin grant alike.
    Forbidden,
    /// Reserved (an exact match in `reserved_nicks`) or an impersonation of
    /// one (`crate::nick_policy::impersonation_hit`) — self-service only,
    /// [`admin_set_nick`] is the only way onto either.
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

/// Resolve a nick to its `user_id`, case-insensitively, exact match — the
/// reverse of [`nick_for_user`]. Built for the by-nick admin role routes
/// (`routes::forum_v2::admin_set_role_by_nick`/`admin_remove_role_by_nick`):
/// an operator addressing a role grant by nick instead of the numeric id
/// `PUT /api/admin/forum/roles/{user_id}` otherwise requires. `None` when no
/// account has that nick (case-insensitively) — [`nick_for_user`]'s
/// `idx_users_nick_lower` unique index guarantees at most one match.
pub fn user_id_for_nick(conn: &Connection, nick: &str) -> Result<Option<i64>> {
    conn.query_row(
        "SELECT id FROM users WHERE LOWER(nick) = LOWER(?1)",
        params![nick],
        |row| row.get(0),
    )
    .optional()
}

/// One account a share-settings nick box can grant. `label` stays empty:
/// the box shows the nick and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareNickHit {
    pub nick: String,
    pub label: String,
}

/// Accounts with a nick, excluding `caller_id`. Match is case-insensitive
/// substring on the nick only. An account with no nick is not a hit, and a
/// display name is neither searched nor returned. Exact nick, then nick
/// prefix, then substring. A published DM key is not required.
pub fn search_share_nicks(
    conn: &Connection,
    caller_id: i64,
    query: &str,
    limit: i64,
) -> Result<Vec<ShareNickHit>> {
    let q = query.trim().to_lowercase();
    if q.is_empty() || limit <= 0 {
        return Ok(Vec::new());
    }
    let escaped = q.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
    let like = format!("%{escaped}%");
    let prefix = format!("{escaped}%");
    let mut stmt = conn.prepare(
        "SELECT nick FROM users
         WHERE id != ?1
           AND nick IS NOT NULL AND nick != ''
           AND LOWER(nick) LIKE ?2 ESCAPE '\\'
           AND (
             IFNULL(discoverable, 1) = 1
             OR EXISTS (
               SELECT 1 FROM friendships
               WHERE user_id = ?1 AND friend_id = users.id
             )
           )
         ORDER BY
           CASE
             WHEN LOWER(nick) = ?3 THEN 0
             WHEN LOWER(nick) LIKE ?4 ESCAPE '\\' THEN 1
             ELSE 2
           END,
           LOWER(nick)
         LIMIT ?5",
    )?;
    let mut rows = stmt.query(params![caller_id, like, q, prefix, limit])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let nick: String = row.get(0)?;
        out.push(ShareNickHit { nick, label: String::new() });
    }
    Ok(out)
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

/// Change `user_id`'s nick to `nick`, enforcing shape, the forbidden-nick
/// registry, reserved names (exact and impersonation-by-prefix), global
/// case-insensitive uniqueness, and the 30-day change cooldown — checked in
/// that order (owner order 2026-09-09): a candidate that fails an earlier,
/// cheaper gate never reaches a later, more expensive one.
///
/// `reserved_cache` is a snapshot of every `reserved_nicks` row's `(nick,
/// category)` — `ControlPlane::reserved_nick_cache_snapshot` in production,
/// so the impersonation check (which must compare against every row) never
/// scans the table on this request; tests that do not exercise it may pass
/// `&[]`. The EXACT reserved check just below still queries the database
/// directly — a single indexed lookup, not the scan this cache exists to
/// avoid.
///
/// Uniqueness is decided twice, deliberately: the `SELECT ... WHERE
/// LOWER(nick) = ...` pre-check below gives the common case a clear
/// [`NickError::Taken`] without ever reaching the database's own error path
/// (same pattern as [`link_provider_to_user`]'s existing-owner check); the
/// `idx_users_nick_lower` unique index is the actual guarantee under a race
/// between two callers claiming the same nick at once — the loser's `UPDATE`
/// hits the index and is mapped to `Taken` here too, rather than surfaced as
/// a raw constraint error.
pub fn set_nick(
    conn: &Connection,
    user_id: i64,
    nick: &str,
    reserved_cache: &[ReservedNickEntry],
) -> Result<(), NickError> {
    if !nick_format_valid(nick) || !crate::nick_policy::nick_shape_ok(nick) {
        return Err(NickError::Invalid);
    }
    if let Some(hit) = crate::nick_policy::forbidden_hit(nick) {
        tracing::warn!("set_nick: refused {:?} — forbidden {} rule matched {:?}", nick, hit.rule, hit.entry);
        return Err(NickError::Forbidden);
    }

    let lower = nick.to_lowercase();
    if is_nick_reserved(conn, &lower)? {
        return Err(NickError::Reserved);
    }
    let reserved_handles: Vec<crate::nick_policy::ReservedHandle<'_>> = reserved_cache
        .iter()
        .map(|e| crate::nick_policy::ReservedHandle { nick_lower: &e.nick, category: &e.category })
        .collect();
    if let Some(impersonated) = crate::nick_policy::impersonation_hit(nick, &reserved_handles) {
        tracing::warn!("set_nick: refused {:?} — reads as an impersonation of {:?}", nick, impersonated);
        return Err(NickError::Reserved);
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

    let now = chrono::Utc::now();
    let (old_nick, changed_at): (Option<String>, Option<String>) = conn
        .query_row(
            "SELECT nick, nick_changed_at FROM users WHERE id = ?1",
            params![user_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .unwrap_or((None, None));
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

    let result = conn.execute(
        "UPDATE users SET nick = ?1, nick_changed_at = ?2 WHERE id = ?3",
        params![nick, now.to_rfc3339(), user_id],
    );
    match result {
        Ok(_) => {
            release_old_nick_grant(conn, user_id, old_nick.as_deref())?;
            Ok(())
        }
        Err(rusqlite::Error::SqliteFailure(err, _)) if err.code == rusqlite::ErrorCode::ConstraintViolation => {
            Err(NickError::Taken)
        }
        Err(e) => Err(NickError::Db(e)),
    }
}

/// Whether `user_id` has chosen a nick — the write gate the forum
/// (`routes::forum_v2::create_board_thread`/`create_reply`) and DM
/// (`routes::dm::create_conversation`/`create_message`) routes run before
/// accepting a write (owner ruling 2026-09-09: an account without a nick may
/// only read). Thin wrapper over [`nick_for_user`] — same query, kept under
/// its own name because those call sites ask "does this account have SOME
/// nick" rather than "what is this account's nick".
pub fn user_nick(conn: &Connection, user_id: i64) -> Result<Option<String>> {
    nick_for_user(conn, user_id)
}

// ============================================================================
// Reserved-nick registry (owner ruling 2026-09-09)
//
// Occupy the good handles now, hand them to specific accounts later through
// an admin route (`routes::admin::admin_set_user_nick`, `db::admin_set_nick`)
// rather than minting fake accounts to sit on them. `reserved_nicks` is
// seeded at boot from the checked-in `reserved_nicks.txt` (`include_str!`d
// below) and can also be edited live through
// `routes::admin::{list_reserved_nicks,upsert_reserved_nick,
// delete_reserved_nick}`. A row's `granted_to` names the account it was
// handed to, if any — self-service `set_nick` never checks `granted_to`, it
// simply refuses ANY reserved nick outright (see [`is_nick_reserved`]); only
// `admin_set_nick` can put an account onto one.
// ============================================================================

/// One entry parsed from `reserved_nicks.txt` by [`parse_reserved_nicks`]: a
/// lowercase nick and the `[section]` category it was declared under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedNickEntry {
    pub nick: String,
    pub category: String,
}

/// The checked-in reserved-nick list — see that file's own header comment
/// for the exact format [`parse_reserved_nicks`] expects.
const RESERVED_NICKS_TXT: &str = include_str!("../reserved_nicks.txt");

/// Parse a `reserved_nicks.txt`-shaped list: `#` starts a comment, `[name]`
/// opens a category every following nick line is stamped with until the
/// next header or end of file, blank lines are skipped. Returns the valid
/// entries (nick lowercased) plus every line that failed
/// [`nick_format_valid`], verbatim, for the caller to warn about — a bad
/// line is dropped, not merely deferred.
pub fn parse_reserved_nicks(text: &str) -> (Vec<ReservedNickEntry>, Vec<String>) {
    let mut entries = Vec::new();
    let mut rejected = Vec::new();
    let mut category = String::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            category = name.trim().to_string();
            continue;
        }
        if !nick_format_valid(line) {
            rejected.push(line.to_string());
            continue;
        }
        entries.push(ReservedNickEntry {
            nick: line.to_lowercase(),
            category: category.clone(),
        });
    }
    (entries, rejected)
}

/// Seed `reserved_nicks` from [`RESERVED_NICKS_TXT`] — called once at the
/// end of [`init_db`]. Idempotent: `INSERT OR IGNORE` never touches a row
/// that already exists, so a later boot re-running this against the same
/// (or an appended) file never clobbers a `granted_to` an admin already
/// set. Returns `(seeded, rejected)`: how many NEW rows this call inserted,
/// and every line that failed the format check (already logged via
/// `tracing::warn!` here, so the caller only needs the count for its own
/// boot-summary line).
pub fn seed_reserved_nicks(conn: &Connection) -> Result<(usize, Vec<String>)> {
    let (entries, rejected) = parse_reserved_nicks(RESERVED_NICKS_TXT);
    for bad in &rejected {
        tracing::warn!("reserved_nicks.txt: skipping invalid entry {:?}", bad);
    }
    let now = chrono::Utc::now().to_rfc3339();
    let mut seeded = 0;
    for entry in &entries {
        seeded += conn.execute(
            "INSERT OR IGNORE INTO reserved_nicks (nick_lower, category, note, reserved_at, granted_to)
             VALUES (?1, ?2, NULL, ?3, NULL)",
            params![entry.nick, entry.category, now],
        )?;
    }
    Ok((seeded, rejected))
}

/// Whether `nick_lower` (already lowercased) is a reserved handle — checked
/// before the uniqueness lookup in [`set_nick`], the same gate the retired
/// `RESERVED_NICKS` const used to provide. A row that has been GRANTED
/// (`granted_to` set) still counts as reserved here for every account that
/// isn't its holder: this function only answers "is this nick off-limits to
/// self-service", not "who holds it" — [`set_nick`] refuses the claim
/// outright regardless of `granted_to`, since the only way onto a reserved
/// nick is [`admin_set_nick`].
pub fn is_nick_reserved(conn: &Connection, nick_lower: &str) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM reserved_nicks WHERE nick_lower = ?1",
            params![nick_lower],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Clear `reserved_nicks.granted_to` for `old_nick` if it names a row
/// currently granted to `user_id` — run from both [`set_nick`] and
/// [`admin_set_nick`] right after `user_id`'s nick changes to something
/// else, so a reserved handle the holder moves away from becomes free for
/// an operator to grant again (owner ruling 2026-09-09). A no-op when
/// `old_nick` is `None` (the account never had a nick) or names a row held
/// by a DIFFERENT account (nothing of this account's to release).
fn release_old_nick_grant(conn: &Connection, user_id: i64, old_nick: Option<&str>) -> Result<()> {
    let Some(old_nick) = old_nick else {
        return Ok(());
    };
    let old_lower = old_nick.to_lowercase();
    conn.execute(
        "UPDATE reserved_nicks SET granted_to = NULL WHERE nick_lower = ?1 AND granted_to = ?2",
        params![old_lower, user_id],
    )?;
    Ok(())
}

/// One row returned by [`list_reserved_nicks`] — `nick` carries the stored
/// (lowercase) `nick_lower` value; the wire field is named `nick` because
/// the admin API has no separate concept of "the reserved form" vs "the
/// nick" the way `users.nick` (case-preserved) does.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReservedNickRow {
    pub nick: String,
    pub category: String,
    pub note: Option<String>,
    pub reserved_at: String,
    pub granted_to: Option<i64>,
}

/// Every row in the reserved-nick registry, sorted by category then nick —
/// the read half of `GET /api/admin/nicks/reserved`.
pub fn list_reserved_nicks(conn: &Connection) -> Result<Vec<ReservedNickRow>> {
    let mut stmt = conn.prepare(
        "SELECT nick_lower, category, note, reserved_at, granted_to
         FROM reserved_nicks
         ORDER BY category ASC, nick_lower ASC",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(ReservedNickRow {
                nick: row.get(0)?,
                category: row.get(1)?,
                note: row.get(2)?,
                reserved_at: row.get(3)?,
                granted_to: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>>>()?;
    Ok(rows)
}

/// The `(nick, category)` of every row in the reserved-nick registry — the
/// lean read behind `ControlPlane::reserved_nick_cache`: loaded once at
/// boot (right after [`seed_reserved_nicks`]) and reloaded by
/// `routes::admin::{upsert_reserved_nick,delete_reserved_nick}` whenever
/// they change a row, so [`set_nick`]'s impersonation check
/// (`crate::nick_policy::impersonation_hit`) never queries `reserved_nicks`
/// itself on a self-service request.
pub fn reserved_nick_entries(conn: &Connection) -> Result<Vec<ReservedNickEntry>> {
    let mut stmt = conn.prepare("SELECT nick_lower, category FROM reserved_nicks")?;
    let rows = stmt
        .query_map([], |row| Ok(ReservedNickEntry { nick: row.get(0)?, category: row.get(1)? }))?
        .collect::<Result<Vec<_>>>()?;
    Ok(rows)
}

/// Why [`upsert_reserved_nick`] refused a call — the format check is the
/// only refusal that isn't a bare database error, so this stays a two-arm
/// enum rather than reusing [`NickError`]'s wider set of self-service-only
/// variants (`Reserved`/`Taken`/`RateLimited` make no sense for an admin
/// upsert of the registry itself).
#[derive(Debug)]
pub enum ReservedNickError {
    /// Fails [`nick_format_valid`].
    Invalid,
    /// The database call itself failed.
    Db(rusqlite::Error),
}

impl From<rusqlite::Error> for ReservedNickError {
    fn from(e: rusqlite::Error) -> Self {
        ReservedNickError::Db(e)
    }
}

/// Upsert `nick`'s `category`/`note` in the reserved-nick registry —
/// `routes::admin::upsert_reserved_nick`'s DB half. Never touches
/// `granted_to`: handing the nick to an account is
/// [`admin_set_nick`]/`PUT /api/admin/users/{user_id}/nick`, a separate
/// operation. Returns `true` when this call created a brand new row,
/// `false` when an existing row's category/note was updated in place.
pub fn upsert_reserved_nick(
    conn: &Connection,
    nick: &str,
    category: &str,
    note: Option<&str>,
) -> std::result::Result<bool, ReservedNickError> {
    if !nick_format_valid(nick) {
        return Err(ReservedNickError::Invalid);
    }
    let lower = nick.to_lowercase();
    let existed: bool = conn
        .query_row(
            "SELECT 1 FROM reserved_nicks WHERE nick_lower = ?1",
            params![lower],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if existed {
        conn.execute(
            "UPDATE reserved_nicks SET category = ?1, note = ?2 WHERE nick_lower = ?3",
            params![category, note, lower],
        )?;
    } else {
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO reserved_nicks (nick_lower, category, note, reserved_at, granted_to)
             VALUES (?1, ?2, ?3, ?4, NULL)",
            params![lower, category, note, now],
        )?;
    }
    Ok(!existed)
}

/// Remove `nick` from the reserved-nick registry entirely, `granted_to`
/// included — `routes::admin::delete_reserved_nick`'s DB half. Returns
/// `false` when `nick` was not reserved (nothing to delete).
pub fn delete_reserved_nick(conn: &Connection, nick: &str) -> Result<bool> {
    let lower = nick.to_lowercase();
    let changed = conn.execute("DELETE FROM reserved_nicks WHERE nick_lower = ?1", params![lower])?;
    Ok(changed > 0)
}

/// Why [`admin_set_nick`] refused a call.
#[derive(Debug)]
pub enum AdminNickError {
    /// Fails [`nick_format_valid`] or [`crate::nick_policy::nick_shape_ok`].
    Invalid,
    /// Matches the forbidden-nick registry (`crate::nick_policy::forbidden_hit`)
    /// — never assignable, an admin grant included.
    Forbidden,
    /// Held by a DIFFERENT account already.
    Taken,
    /// `user_id` names no row in `users`.
    NoSuchUser,
    /// The database call itself failed.
    Db(rusqlite::Error),
}

impl From<rusqlite::Error> for AdminNickError {
    fn from(e: rusqlite::Error) -> Self {
        AdminNickError::Db(e)
    }
}

/// Set `user_id`'s nick directly — `routes::admin::admin_set_user_nick`'s DB
/// half. Same shape and forbidden-nick checks as self-service [`set_nick`],
/// but bypasses the reserved-name/impersonation list AND the 30-day cooldown
/// entirely: an operator handing out a reserved handle, or fixing a mistake,
/// does neither. Uniqueness against every OTHER account still applies — two
/// accounts never hold the same nick regardless of who assigns it.
///
/// `user_id`'s previous nick, if any, is released the same way [`set_nick`]
/// releases it ([`release_old_nick_grant`]) — moving an account off a
/// reserved nick it held frees that row for the next grant. Returns whether
/// `nick` is itself a reserved handle; when it is, that row's `granted_to`
/// is set to `user_id`, overwriting whatever it held before.
pub fn admin_set_nick(conn: &Connection, user_id: i64, nick: &str) -> std::result::Result<bool, AdminNickError> {
    if !nick_format_valid(nick) || !crate::nick_policy::nick_shape_ok(nick) {
        return Err(AdminNickError::Invalid);
    }
    if let Some(hit) = crate::nick_policy::forbidden_hit(nick) {
        tracing::warn!("admin_set_nick: refused {:?} — forbidden {} rule matched {:?}", nick, hit.rule, hit.entry);
        return Err(AdminNickError::Forbidden);
    }
    let user_exists: bool = conn
        .query_row("SELECT 1 FROM users WHERE id = ?1", params![user_id], |_| Ok(()))
        .optional()?
        .is_some();
    if !user_exists {
        return Err(AdminNickError::NoSuchUser);
    }

    let lower = nick.to_lowercase();
    let taken_by_other: bool = conn
        .query_row(
            "SELECT 1 FROM users WHERE LOWER(nick) = ?1 AND id != ?2",
            params![lower, user_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if taken_by_other {
        return Err(AdminNickError::Taken);
    }

    let old_nick = nick_for_user(conn, user_id)?;
    let now = chrono::Utc::now().to_rfc3339();
    let result = conn.execute(
        "UPDATE users SET nick = ?1, nick_changed_at = ?2 WHERE id = ?3",
        params![nick, now, user_id],
    );
    match result {
        Ok(_) => {}
        Err(rusqlite::Error::SqliteFailure(err, _)) if err.code == rusqlite::ErrorCode::ConstraintViolation => {
            return Err(AdminNickError::Taken);
        }
        Err(e) => return Err(AdminNickError::Db(e)),
    }

    release_old_nick_grant(conn, user_id, old_nick.as_deref())?;

    let reserved = is_nick_reserved(conn, &lower)?;
    if reserved {
        conn.execute(
            "UPDATE reserved_nicks SET granted_to = ?1 WHERE nick_lower = ?2",
            params![user_id, lower],
        )?;
    }
    Ok(reserved)
}

/// One row returned by [`search_users`] — an operator-facing nick/label
/// lookup, not the client-facing identity shapes above.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AdminUserRow {
    pub user_id: i64,
    pub nick: Option<String>,
    /// `display_name`, or `None` when the column is empty — same
    /// "empty means nothing to show" rule [`effective_label_for_user`]
    /// applies to its own fallback chain.
    pub label: Option<String>,
    pub created_at: String,
    pub paid_until: Option<String>,
    /// Every provider linked to this account (`user_providers.provider`),
    /// deduplicated and sorted — an account can hold more than one identity
    /// on the same provider (e.g. two Google accounts), so this is a set of
    /// names, not a one-per-provider list.
    pub providers: Vec<String>,
    /// Whether ANY linked identity has captured a verified email
    /// (docs/mlc/plans/identity-merge-2026-09-09.md decision 1).
    pub has_email: bool,
    /// The `provider_user_id` of this account's `telegram` `user_providers`
    /// row, if any — who the operator can reach through the Telegram login
    /// bot. `None` when no Telegram identity is linked.
    pub telegram_id: Option<String>,
    /// `true` when the account holds at least one `user_providers` row but
    /// none of `auth_tokens`, `web_sessions`, `device_users`, `sync_items`,
    /// `share_links`, or forum authorship — signed in once and never used
    /// again. This is the same activity predicate
    /// `cleanup_orphan_users`'s self-referencing rule checks, without the
    /// self-mirror or age restriction: a dormant account with several
    /// providers linked over time still reads as dormant here, and stays
    /// that way regardless of when it was created — it's what
    /// `POST /api/admin/users/merge` is for, not boot-time cleanup
    /// (docs/mlc/plans/identity-merge-2026-09-09.md decision 3, revised
    /// 2026-09-09 after boot-time cleanup deleted two real dormant accounts).
    pub dormant: bool,
}

/// Cap on `search_users`' result set — an operator resolving a nick to an
/// id needs a handful of candidates, not the whole table.
const ADMIN_USER_SEARCH_LIMIT: i64 = 50;

/// Case-insensitive substring search over `nick` and `display_name`,
/// ordered by `id` ascending, capped at [`ADMIN_USER_SEARCH_LIMIT`] rows.
/// Built for `GET /api/admin/users?q=`: an operator script resolving a nick
/// to the numeric id `PUT /api/admin/forum/roles/{user_id}` requires; also
/// surfaces each account's linked providers, whether a verified email was
/// ever captured, and its Telegram id (if any) — one extra query against
/// `user_providers` for the whole matched set, not one per row.
pub fn search_users(conn: &Connection, q: &str) -> Result<Vec<AdminUserRow>> {
    let q_lower = q.to_lowercase();
    // Escape LIKE metacharacters to prevent wildcard injection (same idiom
    // as `revoke_key`'s hash-prefix search above).
    let escaped = q_lower
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    let like_pattern = format!("%{}%", escaped);

    let mut stmt = conn.prepare(
        "SELECT id, nick, display_name, created_at, paid_until
         FROM users
         WHERE LOWER(nick) LIKE ?1 ESCAPE '\\' OR LOWER(display_name) LIKE ?1 ESCAPE '\\'
         ORDER BY id ASC
         LIMIT ?2",
    )?;
    let mut rows = stmt.query(params![like_pattern, ADMIN_USER_SEARCH_LIMIT])?;
    let mut users = Vec::new();
    while let Some(row) = rows.next()? {
        let display_name: String = row.get(2)?;
        users.push(AdminUserRow {
            user_id: row.get(0)?,
            nick: row.get(1)?,
            label: Some(display_name).filter(|d| !d.is_empty()),
            created_at: row.get(3)?,
            paid_until: row.get(4)?,
            providers: Vec::new(),
            has_email: false,
            telegram_id: None,
            dormant: false,
        });
    }
    if users.is_empty() {
        return Ok(users);
    }

    let ids: Vec<i64> = users.iter().map(|u| u.user_id).collect();
    let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let provider_sql = format!(
        "SELECT user_id, provider, provider_user_id, email, email_verified
         FROM user_providers WHERE user_id IN ({placeholders}) ORDER BY user_id ASC, linked_at ASC"
    );
    let mut provider_stmt = conn.prepare(&provider_sql)?;
    let bound: Vec<&dyn rusqlite::ToSql> = ids.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
    let mut provider_rows = provider_stmt.query(bound.as_slice())?;

    use std::collections::HashMap;
    let mut providers_by_user: HashMap<i64, Vec<String>> = HashMap::new();
    let mut has_email_by_user: HashMap<i64, bool> = HashMap::new();
    let mut telegram_id_by_user: HashMap<i64, String> = HashMap::new();
    while let Some(row) = provider_rows.next()? {
        let user_id: i64 = row.get(0)?;
        let provider: String = row.get(1)?;
        let provider_user_id: String = row.get(2)?;
        let email: Option<String> = row.get(3)?;
        let email_verified: i64 = row.get(4)?;

        providers_by_user.entry(user_id).or_default().push(provider.clone());
        if email.is_some() && email_verified != 0 {
            has_email_by_user.insert(user_id, true);
        }
        if provider == "telegram" {
            telegram_id_by_user.entry(user_id).or_insert(provider_user_id);
        }
    }

    // `dormant`: has at least one provider row (checked below, after
    // `u.providers` is filled in) and no row in any activity table — same
    // predicate `cleanup_orphan_users`'s self-referencing rule uses, batched
    // over the whole matched set the same way the provider query above is,
    // not one query per row. The placeholder list is repeated once per
    // `UNION ALL` arm since each `IN (...)` binds its own copy of `ids`.
    let activity_sql = format!(
        "SELECT user_id FROM (
             SELECT user_id FROM auth_tokens WHERE user_id IN ({placeholders})
             UNION ALL SELECT user_id FROM web_sessions WHERE user_id IN ({placeholders})
             UNION ALL SELECT user_id FROM device_users WHERE user_id IN ({placeholders})
             UNION ALL SELECT user_id FROM sync_items WHERE user_id IN ({placeholders})
             UNION ALL SELECT user_id FROM share_links WHERE user_id IN ({placeholders})
             UNION ALL SELECT author_user_id AS user_id FROM forum_threads WHERE author_user_id IN ({placeholders})
             UNION ALL SELECT author_user_id AS user_id FROM forum_replies WHERE author_user_id IN ({placeholders})
         )"
    );
    let mut activity_stmt = conn.prepare(&activity_sql)?;
    let mut activity_bound: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(ids.len() * 7);
    for _ in 0..7 {
        activity_bound.extend(ids.iter().map(|id| id as &dyn rusqlite::ToSql));
    }
    let mut activity_rows = activity_stmt.query(activity_bound.as_slice())?;
    let mut has_activity: std::collections::HashSet<i64> = std::collections::HashSet::new();
    while let Some(row) = activity_rows.next()? {
        has_activity.insert(row.get(0)?);
    }

    for u in users.iter_mut() {
        let mut names = providers_by_user.remove(&u.user_id).unwrap_or_default();
        names.sort();
        names.dedup();
        u.has_email = has_email_by_user.contains_key(&u.user_id);
        u.telegram_id = telegram_id_by_user.remove(&u.user_id);
        u.dormant = !names.is_empty() && !has_activity.contains(&u.user_id);
        u.providers = names;
    }

    Ok(users)
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
        "SELECT user_id FROM auth_tokens WHERE token_hash = ?1 AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))",
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
        "DELETE FROM oauth_states WHERE datetime(created_at) < datetime('now', '-10 minutes')",
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

/// Paid status for many accounts at once — the batched counterpart to
/// [`user_is_paid`] for `routes::forum_v2`'s `author_rank` field, which
/// needs every distinct author a response names resolved in one round trip
/// rather than one `user_is_paid` call per author. Same `paid_until`
/// comparison against now as [`user_paid_until`], just over a whole `IN
/// (...)` set.
///
/// A key is present in the result only if `user_id` still names a row in
/// `users` — `social_db::author_classes_batch`'s caller
/// (`routes::forum_v2::resolve_author_ranks`) uses that absence to tell a
/// live account (some rank) apart from a deleted/unknown one (`author_rank:
/// null`), the same account `db::forum_author_label` already falls back to
/// `"deleted user"` for.
pub fn users_paid_batch(conn: &Connection, user_ids: &[i64]) -> Result<std::collections::HashMap<i64, bool>> {
    let mut out = std::collections::HashMap::with_capacity(user_ids.len());
    if user_ids.is_empty() {
        return Ok(out);
    }
    let placeholders = user_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!("SELECT id, paid_until FROM users WHERE id IN ({placeholders})");
    let mut stmt = conn.prepare(&sql)?;
    let bound: Vec<&dyn rusqlite::ToSql> = user_ids.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
    let mut rows = stmt.query(bound.as_slice())?;
    let now = chrono::Utc::now().to_rfc3339();
    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let until: Option<String> = row.get(1)?;
        let paid = until.is_some_and(|u| u.as_str() > now.as_str());
        out.insert(id, paid);
    }
    Ok(out)
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

/// `max(now, existing paid_until) + days` — the one place the "extend, never
/// replace, never lose remaining time" rule is computed. Shared by
/// [`redeem_gift_code`] (a gift code, one per account per code) and
/// [`grant_paid_days`] (an admin grant, `routes::admin::grant_paid_days`'s DB
/// half) — both give an account still under an earlier grant more time
/// instead of losing whatever was left of it, and this is why the two can
/// never disagree about what "extend" means.
fn extend_paid_until(existing: Option<&str>, days: i64, now: chrono::DateTime<chrono::Utc>) -> String {
    let base = existing
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .filter(|dt| *dt > now)
        .unwrap_or(now);
    (base + chrono::Duration::days(days)).to_rfc3339()
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
/// `paid_until` is extended via [`extend_paid_until`], not replaced: an
/// account still under an earlier grant gains time instead of losing
/// whatever was left of it.
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
    let new_until = extend_paid_until(existing_until.as_deref(), grants_days, chrono::Utc::now());

    set_user_paid_until(conn, user_id, Some(&new_until))?;

    Ok(RedeemOutcome::Redeemed(new_until))
}

/// Extend `user_id`'s paid access by `days` days from `max(now, existing
/// paid_until)` — `routes::admin::grant_paid_days`'s DB half, for operator
/// accounts (or any support fix) that need paid time granted directly: a
/// gift code needs the redeeming user's own session ([`redeem_gift_code`]),
/// which does not exist for an account an operator is granting time to
/// out-of-band. Same extension rule as a gift code redemption, via
/// [`extend_paid_until`] — one shared implementation of "extend, never
/// replace, never lose remaining time". `None` if `user_id` names no row in
/// `users`; `days` bounds are the caller's job (`routes::admin`), not this
/// function's.
pub fn grant_paid_days(conn: &Connection, user_id: i64, days: i64) -> Result<Option<String>> {
    // Outer `Option` is "does a `users` row exist at all" (`None` -> no such
    // user); inner is `paid_until` itself, which is separately `Option` —
    // one query answers both, no second existence check needed.
    let row: Option<Option<String>> = conn
        .query_row(
            "SELECT paid_until FROM users WHERE id = ?1",
            params![user_id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(existing_until) = row else {
        return Ok(None);
    };

    let new_until = extend_paid_until(existing_until.as_deref(), days, chrono::Utc::now());
    set_user_paid_until(conn, user_id, Some(&new_until))?;
    Ok(Some(new_until))
}

// ============================================================================
// Outreach notifications
//
// Owner ruling 2026-09-09: the only channel to reach an existing user
// outside the app is the one they already opened themselves — a private
// chat with `mylittlechart_login_bot` (see `tg-login-bot`), whose chat id
// IS `user_providers.provider_user_id` for that account's `telegram` row
// (same identity `mlc-alert-daemon`'s alert delivery already resolves this
// way). `POST /api/admin/notify` (routes/notify.rs) resolves recipients via
// [`telegram_recipients`] below and hands the actual send off to
// `crate::notify::send_batch`, which is transport-agnostic (see that
// module's doc comment) — this section only owns resolution and the two
// tables an outreach call writes:
//
// - `notify_batches`: one row per `POST /api/admin/notify` call that was
//   NOT a dry run — the message text lives here, written exactly once.
// - `notify_log`: one row per (batch, recipient) attempt — `ok`/`error`
//   record the outcome, `text_hash` carries the sha256 of the same batch's
//   text for a quick per-row audit without a join back to `notify_batches`,
//   and `batch_id` is the actual key `list_notify_batches` groups on.
//
// A dry run never reaches either table: it calls [`telegram_recipients`]
// directly and returns the preview without writing anything.
// ============================================================================

/// Which accounts one outreach call targets — the `to` field of
/// `POST /api/admin/notify`'s body, already parsed (see
/// `routes::notify::parse_target`).
#[derive(Debug, Clone)]
pub enum NotifyTarget {
    /// Every account with a linked Telegram identity.
    All,
    /// Exactly these account ids. An id with no Telegram identity is
    /// silently excluded by [`telegram_recipients`] — it is not an error,
    /// there is simply no channel to reach that account through.
    Users(Vec<i64>),
}

/// One resolved outreach recipient: the account, the Telegram chat id to
/// send to (parsed from `user_providers.provider_user_id`), and its nick
/// (if chosen) for the dry-run preview.
#[derive(Debug, Clone)]
pub struct NotifyRecipient {
    pub user_id: i64,
    pub chat_id: i64,
    pub nick: Option<String>,
}

/// Resolve `target` to every account holding a `telegram`
/// `user_providers` row, joined back to `users` for `nick`. `provider_user_id`
/// is stored as text (see `tg-login-bot`'s `telegram_user_id`); a row that
/// somehow fails to parse as an integer chat id is skipped with a warning
/// rather than failing the whole batch — it cannot be reached either way.
pub fn telegram_recipients(conn: &Connection, target: &NotifyTarget) -> Result<Vec<NotifyRecipient>> {
    fn collect(rows: &mut rusqlite::Rows<'_>) -> Result<Vec<NotifyRecipient>> {
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let user_id: i64 = row.get(0)?;
            let chat_id_raw: String = row.get(1)?;
            let nick: Option<String> = row.get(2)?;
            match chat_id_raw.parse::<i64>() {
                Ok(chat_id) => out.push(NotifyRecipient { user_id, chat_id, nick }),
                Err(_) => tracing::warn!(
                    "notify: user {user_id} has a non-numeric telegram provider_user_id {chat_id_raw:?}, skipped"
                ),
            }
        }
        Ok(out)
    }

    match target {
        NotifyTarget::All => {
            let mut stmt = conn.prepare(
                "SELECT u.id, up.provider_user_id, u.nick
                 FROM user_providers up
                 JOIN users u ON u.id = up.user_id
                 WHERE up.provider = 'telegram'
                 ORDER BY u.id ASC",
            )?;
            let mut rows = stmt.query([])?;
            collect(&mut rows)
        }
        NotifyTarget::Users(ids) => {
            if ids.is_empty() {
                return Ok(Vec::new());
            }
            let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let sql = format!(
                "SELECT u.id, up.provider_user_id, u.nick
                 FROM user_providers up
                 JOIN users u ON u.id = up.user_id
                 WHERE up.provider = 'telegram' AND u.id IN ({placeholders})
                 ORDER BY u.id ASC"
            );
            let mut stmt = conn.prepare(&sql)?;
            let bound: Vec<&dyn rusqlite::ToSql> = ids.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
            let mut rows = stmt.query(bound.as_slice())?;
            collect(&mut rows)
        }
    }
}

/// Write the one `notify_batches` row for a non-dry-run
/// `POST /api/admin/notify` call. Returns the new `id` (`last_insert_rowid`)
/// — the `batch_id` every `notify_log` row for this call references.
pub fn insert_notify_batch(conn: &Connection, channel: &str, text: &str, requested_by: &str, ts: &str) -> Result<i64> {
    conn.execute(
        "INSERT INTO notify_batches (ts, channel, text, requested_by) VALUES (?1, ?2, ?3, ?4)",
        params![ts, channel, text, requested_by],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Record one send attempt against `batch_id`. `error` is `None` on
/// success; `text_hash` is the sha256 of the batch's text (the same value
/// for every row in a batch — see this section's doc comment on why it
/// rides along here instead of only living in `notify_batches`).
pub fn insert_notify_log(
    conn: &Connection,
    batch_id: i64,
    channel: &str,
    user_id: i64,
    ok: bool,
    error: Option<&str>,
    text_hash: &str,
    ts: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO notify_log (ts, channel, user_id, ok, error, text_hash, batch_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![ts, channel, user_id, ok as i64, error, text_hash, batch_id],
    )?;
    Ok(())
}

/// One row of `GET /api/admin/notify/batches` — a `notify_batches` row plus
/// its `notify_log` rows' outcome counts (`sent` = `ok`, `failed` = not
/// `ok`), grouped by `batch_id`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NotifyBatchSummary {
    pub batch_id: i64,
    pub ts: String,
    pub channel: String,
    pub text: String,
    pub requested_by: String,
    pub sent: i64,
    pub failed: i64,
}

/// Most recent `limit` outreach batches, newest first.
pub fn list_notify_batches(conn: &Connection, limit: i64) -> Result<Vec<NotifyBatchSummary>> {
    let mut stmt = conn.prepare(
        "SELECT b.id, b.ts, b.channel, b.text, b.requested_by,
                COALESCE(SUM(CASE WHEN l.ok = 1 THEN 1 ELSE 0 END), 0) AS sent,
                COALESCE(SUM(CASE WHEN l.ok = 0 THEN 1 ELSE 0 END), 0) AS failed
         FROM notify_batches b
         LEFT JOIN notify_log l ON l.batch_id = b.id
         GROUP BY b.id
         ORDER BY b.id DESC
         LIMIT ?1",
    )?;
    let mut rows = stmt.query(params![limit])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(NotifyBatchSummary {
            batch_id: row.get(0)?,
            ts: row.get(1)?,
            channel: row.get(2)?,
            text: row.get(3)?,
            requested_by: row.get(4)?,
            sent: row.get(5)?,
            failed: row.get(6)?,
        });
    }
    Ok(out)
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
    /// Rights v1 (see `effective_rights`): true when the owner opted this
    /// link into the `clone` right at creation time.
    pub clone_allowed: bool,
    /// Chart-share policy v1 (docs/mlc/plans/share-policy-2026-09-25.md §1):
    /// `"view"` | `"interactive"` — the live-view interaction floor a link
    /// grants, consulted by [`effective_share_tier`]. Raw string, same
    /// storage idiom as `kind` — the `ShareInteraction` enum lives in
    /// `routes::share`, the one wire-facing layer that parses it.
    pub interaction: String,
    /// Serialized `Vec<routes::share::ProtectedElementRef>` — the elements
    /// the sharer marked Protected at creation time, `'[]'` for every link
    /// created before this column existed or that never marked anything.
    pub protected_json: String,
    /// `"public"` | `"private"` (§1 Rev 2). A private link resolves to no
    /// rights at all for anyone without an explicit `object_grants` row —
    /// see [`effective_share_tier`]. `"public"` for every link created
    /// before this column existed, matching that link's actual historical
    /// behaviour (reachable by anyone holding the token).
    pub visibility: String,
    /// Path of the re-encoded preview PNG relative to `<data_dir>/share/`
    /// (§9), or empty when no preview has been uploaded yet — same idiom as
    /// `blob_path`. Set by [`set_share_preview_path`], read by
    /// `routes::share::get_share_preview` (serving) and
    /// `routes::share::og_tags_for_share` (OG-tag selection for the
    /// crawler-facing `GET /` route in `main.rs`).
    pub preview_path: String,
    /// [Rev 3] `Some(true)`/`Some(false)` once the owner has explicitly set
    /// forwarding at create time or via `PATCH /api/share/{token}`; `None`
    /// for every link that never had it set explicitly (including every row
    /// created before this column existed) — see the ALTER TABLE's own
    /// comment above and [`Self::effective_allow_forward`], the ONE place
    /// that turns this raw, possibly-unset value into the answer a caller
    /// actually wants.
    pub allow_forward: Option<bool>,
    /// Kept out of the ring. Creation burns the oldest unpinned link of the
    /// same kind once the account is at its cap; a pinned link is never that
    /// victim.
    pub pinned: bool,
    /// Author chart this live link is bound to. Empty on screenshot rows and
    /// on live rows created before the binding existed.
    pub chart_id: String,
    /// Bumps when the author republishes the chart onto this token. The
    /// clipboard URL carries it as `v` so a messenger refetches the card.
    pub revision: i64,
    /// Head of `share_ops` for this token. 0 means no ops since the last
    /// preset publish.
    pub op_seq: i64,
    /// Channel mode. False: viewers catch up on a cadence. True: the same
    /// log is the live channel.
    pub live: bool,
}

impl ShareLinkRow {
    /// The forwarding flag a caller/UI actually acts on: the explicit value
    /// if the owner ever set one, otherwise the visibility-keyed default —
    /// `true` for `"public"`, `false` for anything else (in practice just
    /// `"private"`). Reading this fresh off `self.visibility` on every call,
    /// rather than baking a default into the column at write time, is
    /// exactly what lets a `PATCH` that changes ONLY `visibility` move an
    /// unset link's effective forwarding without ever writing to
    /// `allow_forward` — and, symmetrically, lets an explicit value survive
    /// that same `PATCH` untouched (docs/mlc/plans/share-policy-2026-09-25.md
    /// Rev 3).
    pub fn effective_allow_forward(&self) -> bool {
        self.allow_forward.unwrap_or(self.visibility == "public")
    }
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
        clone_allowed: row.get::<_, i64>(9)? != 0,
        interaction: row.get(10)?,
        protected_json: row.get(11)?,
        visibility: row.get(12)?,
        preview_path: row.get(13)?,
        allow_forward: row.get::<_, Option<i64>>(14)?.map(|v| v != 0),
        pinned: row.get::<_, i64>(15)? != 0,
        chart_id: row.get(16)?,
        revision: row.get(17)?,
        op_seq: row.get(18)?,
        live: row.get::<_, i64>(19)? != 0,
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
/// `clone_allowed` is the owner's rights-v1 choice at creation time (see
/// `effective_rights`) — always `false` for a screenshot share today, since
/// only a live share carries a preset to clone. `interaction`/`protected_json`
/// are the chart-share-policy v1 fields (docs/mlc/plans/share-policy-
/// 2026-09-25.md §1) — `"view"`/`"[]"` for a screenshot share (same reasoning
/// as `clone_allowed`: nothing offers to set them for that kind).
/// `visibility` is `"public"`/`"private"` (§1 Rev 2); `preview_path` starts
/// empty always — it is stamped later, once a preview image exists (§9).
/// `allow_forward` is Rev 3's forwarding flag: `None` when the caller never
/// set it explicitly — the row then follows its own `visibility`'s default
/// (see [`ShareLinkRow::effective_allow_forward`]) — `Some(v)` when it did;
/// always `None` for a screenshot share, same reasoning as `clone_allowed`.
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
    clone_allowed: bool,
    interaction: &str,
    protected_json: &str,
    visibility: &str,
    allow_forward: Option<bool>,
) -> Result<String> {
    loop {
        let token = generate_share_token();
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO share_links (token, user_id, kind, title, preset_json, blob_path, blob_bytes, created_at, expires_at, clone_allowed, interaction, protected_json, visibility, allow_forward)
             VALUES (?1, ?2, ?3, ?4, ?5, '', ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![token, user_id, kind, title, preset_json, blob_bytes, created_at, expires_at, clone_allowed as i64, interaction, protected_json, visibility, allow_forward.map(|v| v as i64)],
        )?;
        if inserted == 1 {
            return Ok(token);
        }
        // PRIMARY KEY collision (vanishingly unlikely) — draw another token.
    }
}

/// Active live token bound to this author's chart, if one still resolves.
pub fn find_active_live_share_for_chart(
    conn: &Connection,
    user_id: i64,
    chart_id: &str,
) -> Result<Option<(String, i64)>> {
    if chart_id.is_empty() {
        return Ok(None);
    }
    let now = chrono::Utc::now().to_rfc3339();
    conn.query_row(
        "SELECT token, revision FROM share_links
         WHERE user_id = ?1 AND chart_id = ?2 AND kind = 'live' AND revoked = 0 AND expires_at > ?3
         ORDER BY created_at DESC LIMIT 1",
        params![user_id, chart_id, now],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
}

/// Publish the author's current chart onto one stable live link.
///
/// An empty `chart_id` always mints a new token (legacy clients). A non-empty
/// id reuses the active row for that chart and bumps `revision`. Returns
/// `(token, revision, expires_at, created)`.
pub fn publish_live_share(
    conn: &Connection,
    user_id: i64,
    chart_id: &str,
    title: &str,
    preset_json: &str,
    created_at: &str,
    expires_at: &str,
    clone_allowed: bool,
    interaction: &str,
    protected_json: &str,
    visibility: &str,
    allow_forward: Option<bool>,
) -> Result<(String, i64, String, bool)> {
    if let Some((token, revision)) = find_active_live_share_for_chart(conn, user_id, chart_id)? {
        let next = revision.saturating_add(1).max(1);
        conn.execute(
            "UPDATE share_links
             SET title = ?1, preset_json = ?2, expires_at = ?3, revision = ?4,
                 clone_allowed = ?5, interaction = ?6, protected_json = ?7,
                 visibility = ?8, allow_forward = ?9
             WHERE token = ?10 AND user_id = ?11",
            params![
                title,
                preset_json,
                expires_at,
                next,
                clone_allowed as i64,
                interaction,
                protected_json,
                visibility,
                allow_forward.map(|v| v as i64),
                token,
                user_id,
            ],
        )?;
        reset_share_ops(conn, &token)?;
        return Ok((token, next, expires_at.to_string(), false));
    }
    let token = create_share_link(
        conn,
        user_id,
        "live",
        title,
        preset_json,
        0,
        created_at,
        expires_at,
        clone_allowed,
        interaction,
        protected_json,
        visibility,
        allow_forward,
    )?;
    if !chart_id.is_empty() {
        conn.execute(
            "UPDATE share_links SET chart_id = ?1, revision = 1 WHERE token = ?2 AND user_id = ?3",
            params![chart_id, token, user_id],
        )?;
    }
    Ok((token, 1, expires_at.to_string(), true))
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
        "SELECT token, user_id, kind, title, preset_json, blob_path, blob_bytes, created_at, expires_at, clone_allowed, interaction, protected_json, visibility, preview_path, allow_forward, pinned, chart_id, revision, op_seq, live
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
        "SELECT token, user_id, kind, title, preset_json, blob_path, blob_bytes, created_at, expires_at, clone_allowed, interaction, protected_json, visibility, preview_path, allow_forward, pinned, chart_id, revision, op_seq, live
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

/// Stamp the re-encoded preview PNG's path onto a share link, owner-only —
/// the `user_id` in the WHERE clause makes "someone else's token" answer
/// `false` exactly like "no such token" (same discipline as [`revoke_share`]).
/// `routes::share::upload_share_preview`'s write path.
pub fn set_share_preview_path(
    conn: &Connection,
    token: &str,
    owner_user_id: i64,
    preview_path: &str,
) -> Result<bool> {
    let n = conn.execute(
        "UPDATE share_links SET preview_path = ?1 WHERE token = ?2 AND user_id = ?3",
        params![preview_path, token, owner_user_id],
    )?;
    Ok(n > 0)
}

/// Update a subset of a link's own policy fields after creation, owner-only
/// (docs/mlc/plans/share-policy-2026-09-25.md §3 called changing a link's
/// policy post-creation a non-goal for v1 — revisited here on explicit
/// product instruction: `interaction`/`visibility`/`protected_json` may now
/// be changed through this one path; `clone_allowed` still cannot, see
/// `routes::share::update_share_policy`'s doc comment). Each `Some`
/// argument is written; `None` leaves that column untouched. Returns
/// `false` for an unknown token or a non-owner caller — same "someone
/// else's token" 404 discipline as every other owner-scoped write here.
///
/// `allow_forward` (Rev 3) follows the exact same "`None` = untouched"
/// convention as the other three — writing `Some(v)` here is what makes a
/// value "explicit" for [`ShareLinkRow::effective_allow_forward`]'s purposes
/// from this call onward, including surviving a LATER call that changes only
/// `visibility`: that later call passes `allow_forward: None` and this
/// function then does not touch the column at all, leaving the earlier
/// explicit value exactly as it was.
pub fn update_share_link_policy(
    conn: &Connection,
    token: &str,
    owner_user_id: i64,
    interaction: Option<&str>,
    visibility: Option<&str>,
    protected_json: Option<&str>,
    allow_forward: Option<bool>,
    clone_allowed: Option<bool>,
    pinned: Option<bool>,
) -> Result<bool> {
    let owns: bool = conn
        .query_row(
            "SELECT 1 FROM share_links WHERE token = ?1 AND user_id = ?2",
            params![token, owner_user_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !owns {
        return Ok(false);
    }
    if let Some(v) = interaction {
        conn.execute("UPDATE share_links SET interaction = ?1 WHERE token = ?2", params![v, token])?;
    }
    if let Some(v) = visibility {
        conn.execute(
            "UPDATE share_links SET visibility = ?1, revision = revision + 1 WHERE token = ?2",
            params![v, token],
        )?;
    }
    if let Some(v) = protected_json {
        conn.execute("UPDATE share_links SET protected_json = ?1 WHERE token = ?2", params![v, token])?;
    }
    if let Some(v) = allow_forward {
        conn.execute(
            "UPDATE share_links SET allow_forward = ?1 WHERE token = ?2",
            params![v as i64, token],
        )?;
    }
    if let Some(v) = clone_allowed {
        conn.execute(
            "UPDATE share_links SET clone_allowed = ?1 WHERE token = ?2",
            params![v as i64, token],
        )?;
    }
    if let Some(v) = pinned {
        conn.execute(
            "UPDATE share_links SET pinned = ?1 WHERE token = ?2",
            params![v as i64, token],
        )?;
    }
    Ok(true)
}

/// Hidden accounts stay out of nick search unless `caller` already friended them.
pub fn visible_in_search(conn: &Connection, caller: i64, target: i64) -> Result<bool> {
    if caller == target {
        return Ok(false);
    }
    let discoverable: i64 = conn
        .query_row(
            "SELECT IFNULL(discoverable, 1) FROM users WHERE id = ?1",
            params![target],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(1);
    if discoverable != 0 {
        return Ok(true);
    }
    let friend: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM friendships WHERE user_id = ?1 AND friend_id = ?2",
            params![caller, target],
            |row| row.get(0),
        )
        .optional()?;
    Ok(friend.is_some())
}

pub fn account_discoverable(conn: &Connection, user_id: i64) -> Result<bool> {
    let v: Option<i64> = conn
        .query_row(
            "SELECT IFNULL(discoverable, 1) FROM users WHERE id = ?1",
            params![user_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(v.unwrap_or(1) != 0)
}

pub fn set_account_discoverable(conn: &Connection, user_id: i64, on: bool) -> Result<()> {
    conn.execute(
        "UPDATE users SET discoverable = ?1 WHERE id = ?2",
        params![on as i64, user_id],
    )?;
    Ok(())
}

pub fn list_friend_nicks(conn: &Connection, user_id: i64) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT u.nick FROM friendships f
         JOIN users u ON u.id = f.friend_id
         WHERE f.user_id = ?1 AND u.nick IS NOT NULL AND u.nick != ''
         ORDER BY LOWER(u.nick)",
    )?;
    let mut rows = stmt.query(params![user_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(row.get(0)?);
    }
    Ok(out)
}

pub fn create_friend_invite(conn: &Connection, inviter: i64, now: &str, expires: &str) -> Result<String> {
    let token = generate_share_token();
    conn.execute(
        "INSERT INTO friend_invites (token, inviter_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![token, inviter, now, expires],
    )?;
    Ok(token)
}

/// Both directions, so each side finds the other. Returns false if the
/// invite is missing, expired, or is the inviter accepting their own link.
pub fn accept_friend_invite(conn: &Connection, token: &str, accepter: i64, now: &str) -> Result<bool> {
    let inviter: Option<i64> = conn
        .query_row(
            "SELECT inviter_id FROM friend_invites WHERE token = ?1 AND expires_at > ?2",
            params![token, now],
            |row| row.get(0),
        )
        .optional()?;
    let Some(inviter) = inviter else {
        return Ok(false);
    };
    if inviter == accepter {
        return Ok(false);
    }
    conn.execute(
        "INSERT OR IGNORE INTO friendships (user_id, friend_id, created_at) VALUES (?1, ?2, ?3)",
        params![inviter, accepter, now],
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO friendships (user_id, friend_id, created_at) VALUES (?1, ?2, ?3)",
        params![accepter, inviter, now],
    )?;
    conn.execute("DELETE FROM friend_invites WHERE token = ?1", params![token])?;
    Ok(true)
}

/// Owner sets whether this token is a live channel or a cadence link.
pub fn set_share_live(conn: &Connection, token: &str, owner_user_id: i64, live: bool) -> Result<bool> {
    let n = conn.execute(
        "UPDATE share_links SET live = ?1 WHERE token = ?2 AND user_id = ?3 AND kind = 'live'",
        params![live as i64, token, owner_user_id],
    )?;
    Ok(n > 0)
}

/// Revoke the oldest active unpinned share of `kind` for this account.
/// Returns false when every active share of that kind is pinned, so the
/// caller can still refuse creation instead of burning a pinned link.
pub fn burn_oldest_unpinned_share(conn: &Connection, user_id: i64, kind: &str) -> Result<bool> {
    let now = chrono::Utc::now().to_rfc3339();
    let token: Option<String> = conn
        .query_row(
            "SELECT token FROM share_links
             WHERE user_id = ?1 AND kind = ?2 AND revoked = 0 AND pinned = 0 AND expires_at > ?3
             ORDER BY created_at ASC LIMIT 1",
            params![user_id, kind, now],
            |row| row.get(0),
        )
        .optional()?;
    let Some(token) = token else {
        return Ok(false);
    };
    revoke_share(conn, user_id, &token)
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
// Rights v1 (docs/mlc/plans/native-share-viewer-and-chart-rights-2026-09-06.md
// §2-3, docs/mlc/plans/social-sharing-access-gates-and-agent-control-
// 2026-09-05.md §2)
// ============================================================================

/// Effective rights `row` grants to `caller` (`None` = anonymous). `conn` is
/// unused today — `object_grants` covers non-link grants and is not
/// consulted for a share link's own rights — but stays part of the signature
/// so a future non-link contribution (e.g. an `object_grants` row on the same
/// chart) does not have to change every call site.
///
/// `read` always accompanies a fetched row (a revoked or expired one is never
/// fetched at all — see `get_share_link`). `clone` is present when the owner
/// opted the link in at creation (`row.clone_allowed`) or `caller` IS the
/// owner. The owner additionally always gets `edit` — implicit, not stored:
/// co-editing itself is out of scope for v1 (plan §4), but the right already
/// being in the set means the rights list needs no revisit once it lands.
pub fn effective_rights(_conn: &Connection, row: &ShareLinkRow, caller: Option<i64>) -> Vec<&'static str> {
    let is_owner = caller == Some(row.user_id);
    let mut rights = vec!["read"];
    if row.clone_allowed || is_owner {
        rights.push("clone");
    }
    if is_owner {
        rights.push("edit");
    }
    rights
}

/// The `owner_user_id` of a published indicator `type_id`, or `None` if it is
/// a built-in `mli` script — never published, never gated, never stripped
/// (see `indicator_should_strip`). `visibility` is stored on the table (see
/// its DDL) but not consulted by v1's strip decision (plan §3: ownership +
/// grant only), so it is not projected here.
pub fn published_indicator_owner(conn: &Connection, type_id: &str) -> Result<Option<i64>> {
    conn.query_row(
        "SELECT owner_user_id FROM published_indicators WHERE type_id = ?1",
        params![type_id],
        |row| row.get(0),
    )
    .optional()
}

/// Does `recipient` hold a live (unexpired, `expires_at` NULL = no expiry)
/// `indicator_grants` row for `type_id`?
pub fn indicator_grant_is_live(conn: &Connection, type_id: &str, recipient: i64) -> Result<bool> {
    let now = chrono::Utc::now().to_rfc3339();
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM indicator_grants
             WHERE type_id = ?1 AND grantee_user_id = ?2 AND (expires_at IS NULL OR expires_at > ?3)
             LIMIT 1",
            params![type_id, recipient, now],
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

/// Should `type_id` be stripped from a clone for `recipient` (plan §3)? A
/// built-in indicator (no `published_indicators` row) is never stripped; a
/// published one strips unless `recipient` is its owner or holds a live
/// [`indicator_grant_is_live`] row.
pub fn indicator_should_strip(conn: &Connection, type_id: &str, recipient: i64) -> Result<bool> {
    let Some(owner_user_id) = published_indicator_owner(conn, type_id)? else {
        return Ok(false);
    };
    if owner_user_id == recipient {
        return Ok(false);
    }
    Ok(!indicator_grant_is_live(conn, type_id, recipient)?)
}

// ============================================================================
// Object grants (docs/mlc/plans/shared-presets-rights-and-live-sync-
// 2026-09-23.md §2) — the `object_grants` table finally gets writers/readers.
// `object_kind` is `"chart"|"indicator"|"strategy"|"template"` per its DDL
// comment; Phase 1 (`routes::rooms`) only ever writes/reads `"preset"`
// (a shared-preset room). `grantee_user_id = NULL` means public — "anyone
// with the link" — for `view`/`clone` only: a public `edit` row is refused
// at grant-creation time (`routes::rooms`'s grant-CRUD handler), never here.
// ============================================================================

/// One row of the `object_grants` table.
pub struct ObjectGrantRow {
    pub id: i64,
    pub object_kind: String,
    pub object_id: String,
    pub owner_user_id: i64,
    /// `None` = public ("anyone with the link").
    pub grantee_user_id: Option<i64>,
    /// `None` unless this row targets a [`grant_groups`] row instead of one
    /// account. Widened in alongside chart-share policy v1 Rev 2 (§1/§8.1);
    /// rooms' own grants (`routes::rooms`) never set this — a room grant
    /// always targets one account or is public, never a group.
    pub grantee_group_id: Option<i64>,
    pub right: String,
    pub expires_at: Option<String>,
    pub created_at: String,
}

fn object_grant_from_row(row: &rusqlite::Row<'_>) -> Result<ObjectGrantRow> {
    Ok(ObjectGrantRow {
        id: row.get(0)?,
        object_kind: row.get(1)?,
        object_id: row.get(2)?,
        owner_user_id: row.get(3)?,
        grantee_user_id: row.get(4)?,
        grantee_group_id: row.get(5)?,
        right: row.get(6)?,
        expires_at: row.get(7)?,
        created_at: row.get(8)?,
    })
}

/// Create or refresh a grant. "Upsert" against the tuple `(object_kind,
/// object_id, grantee_user_id, right)` — the table carries no UNIQUE
/// constraint on that tuple (an admin-style CRUD row, not a high-frequency
/// write path), so this does an explicit find-then-update-or-insert rather
/// than `ON CONFLICT`. Re-granting the SAME right to the SAME grantee just
/// refreshes `expires_at`/`created_at` in place instead of piling up
/// duplicate rows. Returns the resulting row's id.
pub fn upsert_object_grant(
    conn: &Connection,
    object_kind: &str,
    object_id: &str,
    owner_user_id: i64,
    grantee_user_id: Option<i64>,
    right: &str,
    expires_at: Option<&str>,
    now: &str,
) -> Result<i64> {
    let existing: Option<i64> = conn
        .query_row(
            "SELECT id FROM object_grants
             WHERE object_kind = ?1 AND object_id = ?2 AND right = ?3
               AND ((grantee_user_id IS NULL AND ?4 IS NULL) OR grantee_user_id = ?4)",
            params![object_kind, object_id, right, grantee_user_id],
            |row| row.get(0),
        )
        .optional()?;

    if let Some(id) = existing {
        conn.execute(
            "UPDATE object_grants SET expires_at = ?1, created_at = ?2 WHERE id = ?3",
            params![expires_at, now, id],
        )?;
        return Ok(id);
    }

    conn.execute(
        "INSERT INTO object_grants (object_kind, object_id, owner_user_id, grantee_user_id, right, expires_at, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![object_kind, object_id, owner_user_id, grantee_user_id, right, expires_at, now],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Revoke one grant, owner-only — the `owner_user_id` in the WHERE clause is
/// what makes "someone else's grant" answer `false` exactly like "no such
/// grant" (same discipline as [`revoke_share`]).
pub fn revoke_object_grant(conn: &Connection, grant_id: i64, owner_user_id: i64) -> Result<bool> {
    let n = conn.execute(
        "DELETE FROM object_grants WHERE id = ?1 AND owner_user_id = ?2",
        params![grant_id, owner_user_id],
    )?;
    Ok(n > 0)
}

/// Every grant on one object, newest first — the owner's grant-management
/// view (`GET .../grants`). Unfiltered: an expired grant still lists (so the
/// owner can see and clean it up), unlike [`count_object_grants`], which
/// only counts live ones.
pub fn list_object_grants(conn: &Connection, object_kind: &str, object_id: &str) -> Result<Vec<ObjectGrantRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, object_kind, object_id, owner_user_id, grantee_user_id, grantee_group_id, right, expires_at, created_at
         FROM object_grants WHERE object_kind = ?1 AND object_id = ?2 ORDER BY created_at DESC",
    )?;
    let mut rows = stmt.query(params![object_kind, object_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(object_grant_from_row(row)?);
    }
    Ok(out)
}

/// Count of currently-live (non-expired) grants on one object — the input to
/// [`entitlements::grant_create_allowed`]'s fan-out ceiling.
pub fn count_object_grants(conn: &Connection, object_kind: &str, object_id: &str) -> Result<i64> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.query_row(
        "SELECT COUNT(*) FROM object_grants
         WHERE object_kind = ?1 AND object_id = ?2 AND (expires_at IS NULL OR expires_at > ?3)",
        params![object_kind, object_id, now],
        |row| row.get(0),
    )
}

/// Effective rights `caller` holds on `(kind, object_id)`, owned by
/// `owner_user_id`. The owner always holds every right (implicit, not
/// stored — same posture as [`effective_rights`]'s share-link owner).
/// Otherwise the union of every live (non-expired) grant row matching
/// EITHER `grantee_user_id = caller` OR `grantee_user_id IS NULL` (the
/// public "anyone with the link" row) — `caller: None` (anonymous) only
/// ever matches the public half. Returned in a fixed `view, clone, edit`
/// order, not the query's own row order.
pub fn effective_object_rights(
    conn: &Connection,
    kind: &str,
    object_id: &str,
    owner_user_id: i64,
    caller: Option<i64>,
) -> Result<Vec<&'static str>> {
    if caller == Some(owner_user_id) {
        return Ok(vec!["view", "clone", "edit"]);
    }

    let now = chrono::Utc::now().to_rfc3339();
    let mut stmt = conn.prepare(
        "SELECT DISTINCT right FROM object_grants
         WHERE object_kind = ?1 AND object_id = ?2
           AND (grantee_user_id = ?3 OR grantee_user_id IS NULL)
           AND (expires_at IS NULL OR expires_at > ?4)",
    )?;
    let mut rows = stmt.query(params![kind, object_id, caller, now])?;
    let mut has_view = false;
    let mut has_clone = false;
    let mut has_edit = false;
    while let Some(row) = rows.next()? {
        match row.get::<_, String>(0)?.as_str() {
            "view" => has_view = true,
            "clone" => has_clone = true,
            "edit" => has_edit = true,
            _ => {}
        }
    }
    let mut rights = Vec::with_capacity(3);
    if has_view {
        rights.push("view");
    }
    if has_clone {
        rights.push("clone");
    }
    if has_edit {
        rights.push("edit");
    }
    Ok(rights)
}

// ============================================================================
// Chart-share policy v1, Rev 2 — per-account/group share rights
// (docs/mlc/plans/share-policy-2026-09-25.md §1/§8.1-§8.3). A share-object
// grant row is `object_grants.object_kind = "chart"`, `object_id = <share
// token>` (not the underlying preset id — the token is server-minted,
// globally unique by construction, and ties the grant's natural lifecycle to
// the share's own: revoking the share makes its grants moot without a
// separate cascade). `right` carries one of `ShareTier::as_str`'s four
// strings — a vocabulary distinct from rooms' own `{view,clone,edit}` set on
// the SAME table, never confused because every reader here filters by
// `object_kind = 'chart'` first.
// ============================================================================

/// One of the four tiers a share link (or a per-account/group grant on it)
/// can resolve to, low -> high (`Ord`/`PartialOrd` follow declaration order,
/// so `max()` picks the strongest tier a caller holds from any source).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ShareTier {
    View,
    Interactive,
    Clone,
    CloneProtected,
}

impl ShareTier {
    pub fn as_str(self) -> &'static str {
        match self {
            ShareTier::View => "view",
            ShareTier::Interactive => "interactive",
            ShareTier::Clone => "clone",
            ShareTier::CloneProtected => "clone_protected",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "view" => Some(ShareTier::View),
            "interactive" => Some(ShareTier::Interactive),
            "clone" => Some(ShareTier::Clone),
            "clone_protected" => Some(ShareTier::CloneProtected),
            _ => None,
        }
    }
}

/// The highest [`ShareTier`] `caller` holds on `row` — the ONE function both
/// `GET /api/share/{token}` and `POST /api/share/{token}/clone` call, fresh,
/// on every request, so neither route ever trusts a client-supplied rights
/// claim (owner requirement: "even if a link leaks, the server re-checks the
/// requester's rights on open and on clone").
///
/// - Owner (`caller == Some(row.user_id)`): always [`ShareTier::CloneProtected`]
///   — implicit, matches [`effective_rights`]'s owner rule.
/// - Otherwise: the MAX of (a) every live (non-expired) `object_grants` row
///   on `("chart", row.token)` matching `caller` directly (`grantee_user_id`)
///   OR via `grant_group_members` (`grantee_group_id`), parsed through
///   [`ShareTier::from_str`] (a row with an unrecognized `right` string is
///   skipped, not treated as an error), and (b), ONLY when
///   `row.visibility == "public"`, the link's own floor: `View` always,
///   `+Interactive` if `row.interaction == "interactive"`, `+Clone` if
///   `row.clone_allowed`.
/// - A PRIVATE row skips (b) entirely — an ungranted caller (anonymous or
///   not) gets `None`. `caller: None` (anonymous) never matches (a): SQLite's
///   `= NULL` predicate is never true, including against a NULL-valued
///   column, so an anonymous caller's grant query returns no rows by
///   construction, with no special case needed. A PUBLIC row always yields
///   at least `Some(View)`.
pub fn effective_share_tier(
    conn: &Connection,
    row: &ShareLinkRow,
    caller: Option<i64>,
) -> Result<Option<ShareTier>> {
    if caller == Some(row.user_id) {
        return Ok(Some(ShareTier::CloneProtected));
    }

    let mut best: Option<ShareTier> = None;

    if let Some(caller_id) = caller {
        let now = chrono::Utc::now().to_rfc3339();
        let mut stmt = conn.prepare(
            "SELECT right FROM object_grants
             WHERE object_kind = 'chart' AND object_id = ?1
               AND (expires_at IS NULL OR expires_at > ?2)
               AND (
                 grantee_user_id = ?3
                 OR grantee_group_id IN (SELECT group_id FROM grant_group_members WHERE user_id = ?3)
               )",
        )?;
        let mut rows = stmt.query(params![row.token, now, caller_id])?;
        while let Some(r) = rows.next()? {
            let right: String = r.get(0)?;
            // `edit` is not a ShareTier. It lets the grantee open a private
            // link (at least View) and is checked again by
            // `share_caller_can_edit`. It does not grant clone.
            if right == "edit" {
                best = Some(best.map_or(ShareTier::View, |b: ShareTier| b.max(ShareTier::View)));
                continue;
            }
            if let Some(tier) = ShareTier::from_str(&right) {
                best = Some(best.map_or(tier, |b: ShareTier| b.max(tier)));
            }
        }
    }

    if row.visibility == "public" {
        let mut floor = ShareTier::View;
        if row.interaction == "interactive" {
            floor = floor.max(ShareTier::Interactive);
        }
        if row.clone_allowed {
            floor = floor.max(ShareTier::Clone);
        }
        best = Some(best.map_or(floor, |b: ShareTier| b.max(floor)));
    }

    Ok(best)
}

/// Create or refresh one per-account/group [`ShareTier`] grant on a share
/// token — the write side of [`effective_share_tier`]. Exactly one of
/// `grantee_user_id`/`grantee_group_id` must be `Some`; upserts against the
/// tuple `(object_id, grantee_user_id, grantee_group_id)` the same way
/// [`upsert_object_grant`] does for its own `right` column, so re-granting a
/// DIFFERENT tier to the same target replaces the row rather than piling up
/// duplicates with conflicting tiers.
pub fn upsert_share_grant(
    conn: &Connection,
    token: &str,
    owner_user_id: i64,
    grantee_user_id: Option<i64>,
    grantee_group_id: Option<i64>,
    tier: ShareTier,
    expires_at: Option<&str>,
    now: &str,
) -> Result<i64> {
    let existing: Option<i64> = conn
        .query_row(
            "SELECT id FROM object_grants
             WHERE object_kind = 'chart' AND object_id = ?1
               AND right != 'edit'
               AND ((grantee_user_id IS NULL AND ?2 IS NULL) OR grantee_user_id = ?2)
               AND ((grantee_group_id IS NULL AND ?3 IS NULL) OR grantee_group_id = ?3)",
            params![token, grantee_user_id, grantee_group_id],
            |row| row.get(0),
        )
        .optional()?;

    if let Some(id) = existing {
        conn.execute(
            "UPDATE object_grants SET right = ?1, expires_at = ?2, created_at = ?3 WHERE id = ?4",
            params![tier.as_str(), expires_at, now, id],
        )?;
        return Ok(id);
    }

    conn.execute(
        "INSERT INTO object_grants (object_kind, object_id, owner_user_id, grantee_user_id, grantee_group_id, right, expires_at, created_at)
         VALUES ('chart', ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![token, owner_user_id, grantee_user_id, grantee_group_id, tier.as_str(), expires_at, now],
    )?;
    Ok(conn.last_insert_rowid())
}

/// One applied chart op. `seq` is the token's monotonic head at insert time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareOpRow {
    pub seq: i64,
    pub user_id: i64,
    pub kind: String,
    pub object_id: String,
    pub body: String,
}

/// Drop the op log and zero the head. The preset just published is the
/// baseline; a subscriber whose cursor is past the new head treats that as
/// a reset and reads from 0.
pub fn reset_share_ops(conn: &Connection, token: &str) -> Result<()> {
    conn.execute("DELETE FROM share_ops WHERE token = ?1", params![token])?;
    conn.execute(
        "UPDATE share_links SET op_seq = 0 WHERE token = ?1",
        params![token],
    )?;
    Ok(())
}

/// Owner, or a live `object_grants` row with `right = 'edit'`. Clone and
/// view grants do not count. Screenshot links are not editable.
pub fn share_caller_can_edit(conn: &Connection, row: &ShareLinkRow, caller: i64) -> Result<bool> {
    if row.kind != "live" {
        return Ok(false);
    }
    if caller == row.user_id {
        return Ok(true);
    }
    let now = chrono::Utc::now().to_rfc3339();
    let hit: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM object_grants
             WHERE object_kind = 'chart' AND object_id = ?1
               AND right = 'edit'
               AND (expires_at IS NULL OR expires_at > ?2)
               AND (
                 grantee_user_id = ?3
                 OR grantee_group_id IN (SELECT group_id FROM grant_group_members WHERE user_id = ?3)
               )
             LIMIT 1",
            params![row.token, now, caller],
            |r| r.get(0),
        )
        .optional()?;
    Ok(hit.is_some())
}

/// Insert an edit grant without replacing a view/clone row for the same nick.
pub fn upsert_share_edit_grant(
    conn: &Connection,
    token: &str,
    owner_user_id: i64,
    grantee_user_id: Option<i64>,
    grantee_group_id: Option<i64>,
    expires_at: Option<&str>,
    now: &str,
) -> Result<i64> {
    let existing: Option<i64> = conn
        .query_row(
            "SELECT id FROM object_grants
             WHERE object_kind = 'chart' AND object_id = ?1
               AND right = 'edit'
               AND ((grantee_user_id IS NULL AND ?2 IS NULL) OR grantee_user_id = ?2)
               AND ((grantee_group_id IS NULL AND ?3 IS NULL) OR grantee_group_id = ?3)",
            params![token, grantee_user_id, grantee_group_id],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(id) = existing {
        conn.execute(
            "UPDATE object_grants SET expires_at = ?1, created_at = ?2 WHERE id = ?3",
            params![expires_at, now, id],
        )?;
        return Ok(id);
    }
    conn.execute(
        "INSERT INTO object_grants (object_kind, object_id, owner_user_id, grantee_user_id, grantee_group_id, right, expires_at, created_at)
         VALUES ('chart', ?1, ?2, ?3, ?4, 'edit', ?5, ?6)",
        params![token, owner_user_id, grantee_user_id, grantee_group_id, expires_at, now],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Append ops in one transaction. Returns the assigned seqs, in order.
/// Empty input returns the current head as an empty vec and does not bump.
pub fn append_share_ops(
    conn: &Connection,
    token: &str,
    user_id: i64,
    ops: &[(String, String, String)],
    now: &str,
) -> Result<Vec<i64>> {
    if ops.is_empty() {
        return Ok(Vec::new());
    }
    // The caller holds the identity connection lock for this whole call,
    // so two appends cannot interleave.
    let head: i64 = conn.query_row(
        "SELECT op_seq FROM share_links WHERE token = ?1",
        params![token],
        |row| row.get(0),
    )?;
    let mut seqs = Vec::with_capacity(ops.len());
    let mut seq = head;
    for (kind, object_id, body) in ops {
        seq = seq.saturating_add(1);
        conn.execute(
            "INSERT INTO share_ops (token, seq, user_id, kind, object_id, body, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![token, seq, user_id, kind, object_id, body, now],
        )?;
        seqs.push(seq);
    }
    conn.execute(
        "UPDATE share_links SET op_seq = ?1 WHERE token = ?2",
        params![seq, token],
    )?;
    Ok(seqs)
}

/// Ops with `seq > after`, ascending, at most `limit`.
pub fn list_share_ops_after(
    conn: &Connection,
    token: &str,
    after: i64,
    limit: i64,
) -> Result<(i64, Vec<ShareOpRow>)> {
    let head: i64 = conn
        .query_row(
            "SELECT op_seq FROM share_links WHERE token = ?1",
            params![token],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0);
    let mut stmt = conn.prepare(
        "SELECT seq, user_id, kind, object_id, body FROM share_ops
         WHERE token = ?1 AND seq > ?2
         ORDER BY seq ASC
         LIMIT ?3",
    )?;
    let mut rows = stmt.query(params![token, after, limit])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(ShareOpRow {
            seq: row.get(0)?,
            user_id: row.get(1)?,
            kind: row.get(2)?,
            object_id: row.get(3)?,
            body: row.get(4)?,
        });
    }
    Ok((head, out))
}

// ============================================================================
// Owner-curated grant groups (docs/mlc/plans/share-policy-2026-09-25.md
// §1/§8.3): a reusable, named list of accounts a chart-share owner can grant
// a ShareTier to as one unit (`upsert_share_grant`'s `grantee_group_id`)
// instead of one grant row per account. v1 is manual membership only — no
// automatic sync from any entitlement/paid flag (see `entitlements.rs`'s own
// note on this).
// ============================================================================

/// One row of `grant_groups`, with its live member count.
pub struct GrantGroupRow {
    pub id: i64,
    pub owner_user_id: i64,
    pub name: String,
    pub created_at: String,
    pub member_count: i64,
}

/// Create a new group, owned by `owner_user_id`.
pub fn create_grant_group(conn: &Connection, owner_user_id: i64, name: &str, now: &str) -> Result<i64> {
    conn.execute(
        "INSERT INTO grant_groups (owner_user_id, name, created_at) VALUES (?1, ?2, ?3)",
        params![owner_user_id, name, now],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Whether `group_id` exists and is owned by `owner_user_id` — the one
/// ownership check every group route, and `routes::share::create_share_grant`
/// (validating a `grantee_group_id` grant target), run before touching a
/// group.
pub fn grant_group_is_owned_by(conn: &Connection, group_id: i64, owner_user_id: i64) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM grant_groups WHERE id = ?1 AND owner_user_id = ?2",
            params![group_id, owner_user_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// A group's own name, or `None` once the id is gone — the label
/// `routes::share::list_share_grants` shows for a group-targeted grant.
pub fn grant_group_name(conn: &Connection, group_id: i64) -> Result<Option<String>> {
    conn.query_row(
        "SELECT name FROM grant_groups WHERE id = ?1",
        params![group_id],
        |row| row.get(0),
    )
    .optional()
}

/// Rename a group, owner-only — `false` for someone else's group or an
/// unknown id (same "someone else's row answers like no such row"
/// discipline as [`revoke_share`]).
pub fn rename_grant_group(conn: &Connection, group_id: i64, owner_user_id: i64, name: &str) -> Result<bool> {
    let n = conn.execute(
        "UPDATE grant_groups SET name = ?1 WHERE id = ?2 AND owner_user_id = ?3",
        params![name, group_id, owner_user_id],
    )?;
    Ok(n > 0)
}

/// Delete a group, owner-only. Cascades its own membership rows. Any
/// `object_grants` row still targeting the deleted id is orphaned (its
/// `grantee_group_id` set to `NULL`) rather than deleted — plan §8.3's
/// intent ("it simply never matches anyone again") requires exactly this
/// UPDATE first: `object_grants.grantee_group_id` carries a real
/// `REFERENCES grant_groups(id)` under `PRAGMA foreign_keys=ON` (see
/// `init_db`), so deleting the group row FIRST, with a live grant still
/// pointing at it, fails with a foreign-key-constraint error in production
/// exactly the same way it does in this crate's own test fixtures — nulling
/// the reference first is not an optimization, it is what makes the delete
/// possible at all. A row with `grantee_user_id` ALSO `NULL` (a group-only
/// grant) does not thereby become a "public" grant: [`effective_share_tier`]'s
/// own query only ever matches a row via `grantee_user_id = caller` or
/// `grantee_group_id IN (...)` — a row with both `NULL` matches neither
/// condition and is inert, exactly the "never matches anyone again" outcome
/// this function promises.
pub fn delete_grant_group(conn: &Connection, group_id: i64, owner_user_id: i64) -> Result<bool> {
    if !grant_group_is_owned_by(conn, group_id, owner_user_id)? {
        return Ok(false);
    }
    conn.execute(
        "UPDATE object_grants SET grantee_group_id = NULL WHERE grantee_group_id = ?1",
        params![group_id],
    )?;
    conn.execute("DELETE FROM grant_group_members WHERE group_id = ?1", params![group_id])?;
    conn.execute("DELETE FROM grant_groups WHERE id = ?1", params![group_id])?;
    Ok(true)
}

/// The caller's own groups, newest first, each with its live member count —
/// `GET /api/groups`.
pub fn list_grant_groups(conn: &Connection, owner_user_id: i64) -> Result<Vec<GrantGroupRow>> {
    let mut stmt = conn.prepare(
        "SELECT g.id, g.owner_user_id, g.name, g.created_at,
                (SELECT COUNT(*) FROM grant_group_members m WHERE m.group_id = g.id) AS member_count
         FROM grant_groups g WHERE g.owner_user_id = ?1 ORDER BY g.created_at DESC",
    )?;
    let mut rows = stmt.query(params![owner_user_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(GrantGroupRow {
            id: row.get(0)?,
            owner_user_id: row.get(1)?,
            name: row.get(2)?,
            created_at: row.get(3)?,
            member_count: row.get(4)?,
        });
    }
    Ok(out)
}

/// Count of a group's live members — the input to
/// [`entitlements::group_member_add_allowed`]'s fan-out ceiling.
pub fn count_grant_group_members(conn: &Connection, group_id: i64) -> Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM grant_group_members WHERE group_id = ?1",
        params![group_id],
        |row| row.get(0),
    )
}

/// Count of groups `owner_user_id` owns — the input to
/// [`entitlements::group_create_allowed`]'s ceiling.
pub fn count_grant_groups(conn: &Connection, owner_user_id: i64) -> Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM grant_groups WHERE owner_user_id = ?1",
        params![owner_user_id],
        |row| row.get(0),
    )
}

/// Add one member by already-resolved `user_id`, owner-only — `false` for a
/// group the caller does not own. `INSERT OR IGNORE` makes re-adding an
/// existing member a harmless no-op rather than a duplicate-row error.
pub fn add_grant_group_member(
    conn: &Connection,
    group_id: i64,
    owner_user_id: i64,
    user_id: i64,
    now: &str,
) -> Result<bool> {
    if !grant_group_is_owned_by(conn, group_id, owner_user_id)? {
        return Ok(false);
    }
    conn.execute(
        "INSERT OR IGNORE INTO grant_group_members (group_id, user_id, added_at) VALUES (?1, ?2, ?3)",
        params![group_id, user_id, now],
    )?;
    Ok(true)
}

/// Remove one member, owner-only — `false` for a group the caller does not
/// own; removing a member who was never in the group is a harmless no-op
/// (same `DELETE ... WHERE` idiom as [`revoke_share`], just not reported
/// separately from "not your group" — both already answer the same way the
/// route needs: proceed silently either way once ownership holds).
pub fn remove_grant_group_member(
    conn: &Connection,
    group_id: i64,
    owner_user_id: i64,
    user_id: i64,
) -> Result<bool> {
    if !grant_group_is_owned_by(conn, group_id, owner_user_id)? {
        return Ok(false);
    }
    conn.execute(
        "DELETE FROM grant_group_members WHERE group_id = ?1 AND user_id = ?2",
        params![group_id, user_id],
    )?;
    Ok(true)
}

// ============================================================================
// Shared presets (rooms) — Phase 1 (docs/mlc/plans/shared-presets-rights-
// and-live-sync-2026-09-23.md §1/§3). Storage for a server-hosted preset
// room: the header (`shared_presets`) plus its per-entity LWW rows
// (`shared_preset_entities`). Entity JSON shape (window/bubble/indicator/
// alert/primitive/layout) is `rooms_codec`'s concern, not this module's —
// every function here treats an entity's `json` as an opaque
// already-serialized string.
// ============================================================================

/// One row of the `shared_presets` header table.
pub struct SharedPresetRow {
    pub object_id: String,
    pub owner_user_id: i64,
    pub title: String,
    pub visibility: String,
    pub seq: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// Fetch a room's header row, or `None` if no room with this id exists.
pub fn get_shared_preset(conn: &Connection, object_id: &str) -> Result<Option<SharedPresetRow>> {
    conn.query_row(
        "SELECT object_id, owner_user_id, title, visibility, seq, created_at, updated_at
         FROM shared_presets WHERE object_id = ?1",
        params![object_id],
        |row| {
            Ok(SharedPresetRow {
                object_id: row.get(0)?,
                owner_user_id: row.get(1)?,
                title: row.get(2)?,
                visibility: row.get(3)?,
                seq: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        },
    )
    .optional()
}

/// Rooms `owner_user_id` currently hosts — the input to
/// [`entitlements::shared_preset_create_allowed`]'s hosting ceiling.
pub fn count_hosted_shared_presets(conn: &Connection, owner_user_id: i64) -> Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM shared_presets WHERE owner_user_id = ?1",
        params![owner_user_id],
        |row| row.get(0),
    )
}

/// Stamp a room's `title`, owner-only. Used at room creation
/// (`routes::rooms::create_room`) when the caller supplies one — Phase 1 has
/// no separate "rename a room" route.
pub fn set_shared_preset_title(conn: &Connection, object_id: &str, owner_user_id: i64, title: &str) -> Result<bool> {
    let n = conn.execute(
        "UPDATE shared_presets SET title = ?1 WHERE object_id = ?2 AND owner_user_id = ?3",
        params![title, object_id, owner_user_id],
    )?;
    Ok(n > 0)
}

/// Owner-only teardown: deletes every entity row, every `object_grants` row
/// on this room, then the header itself, in that order (children before the
/// parent — `shared_preset_entities.room_id` references `shared_presets.
/// object_id` under `PRAGMA foreign_keys=ON`, so deleting the header first
/// while entities remain would fail the constraint). Ownership is checked
/// BEFORE anything is deleted, so a non-owner's call touches no row at all.
/// Returns `false` for an unknown room or a caller who is not its owner —
/// the route answers the same 404 for both (see `routes::rooms::
/// room_not_found`).
pub fn delete_shared_preset(conn: &Connection, object_id: &str, owner_user_id: i64) -> Result<bool> {
    let is_owner: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM shared_presets WHERE object_id = ?1 AND owner_user_id = ?2",
            params![object_id, owner_user_id],
            |row| row.get(0),
        )
        .optional()?;
    if is_owner.is_none() {
        return Ok(false);
    }
    conn.execute("DELETE FROM shared_preset_entities WHERE room_id = ?1", params![object_id])?;
    conn.execute(
        "DELETE FROM object_grants WHERE object_kind = 'preset' AND object_id = ?1",
        params![object_id],
    )?;
    conn.execute("DELETE FROM shared_presets WHERE object_id = ?1", params![object_id])?;
    Ok(true)
}

/// One row of `shared_preset_entities`, read back for a GET/poll/clone/live
/// frame. `json` is `None` exactly when `deleted` is `true` (a tombstone).
#[derive(Debug, Clone)]
pub struct SharedPresetEntityRow {
    pub kind: String,
    pub entity_id: String,
    pub version: i64,
    pub updated_by: i64,
    pub updated_at: String,
    pub json: Option<String>,
    pub deleted: bool,
    pub seq: i64,
    pub parent_kind: Option<String>,
    pub parent_id: Option<String>,
}

fn shared_preset_entity_from_row(row: &rusqlite::Row<'_>) -> Result<SharedPresetEntityRow> {
    Ok(SharedPresetEntityRow {
        kind: row.get(0)?,
        entity_id: row.get(1)?,
        version: row.get(2)?,
        updated_by: row.get(3)?,
        updated_at: row.get(4)?,
        json: row.get(5)?,
        deleted: row.get::<_, i64>(6)? != 0,
        seq: row.get(7)?,
        parent_kind: row.get(8)?,
        parent_id: row.get(9)?,
    })
}

const SHARED_PRESET_ENTITY_COLUMNS: &str =
    "kind, entity_id, version, updated_by, updated_at, json, deleted, seq, parent_kind, parent_id";

/// Every entity row a room has ever touched with `seq > since_seq`, seq
/// order — tombstones (`deleted = true`) included. This IS the live-channel
/// resume ring (plan §4): because the table holds one row per entity
/// (latest state only), this naturally coalesces several intermediate edits
/// to the SAME entity into one row. `since_seq = 0` (a brand-new subscriber
/// or the first poll) already is the full snapshot via this same query —
/// there is no separate snapshot code path.
pub fn room_entities_since(conn: &Connection, room_id: &str, since_seq: i64) -> Result<Vec<SharedPresetEntityRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {SHARED_PRESET_ENTITY_COLUMNS} FROM shared_preset_entities
         WHERE room_id = ?1 AND seq > ?2 ORDER BY seq"
    ))?;
    let mut rows = stmt.query(params![room_id, since_seq])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(shared_preset_entity_from_row(row)?);
    }
    Ok(out)
}

/// Every currently-live (non-tombstoned) entity a room holds, insertion
/// order — the read path for `GET` (full reassembly) and `clone`. Unlike
/// [`room_entities_since`], tombstones are excluded: a full-preset read has
/// nothing to show for a deleted entity.
pub fn room_live_entities(conn: &Connection, room_id: &str) -> Result<Vec<SharedPresetEntityRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {SHARED_PRESET_ENTITY_COLUMNS} FROM shared_preset_entities
         WHERE room_id = ?1 AND deleted = 0 ORDER BY seq"
    ))?;
    let mut rows = stmt.query(params![room_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(shared_preset_entity_from_row(row)?);
    }
    Ok(out)
}

// ---- apply_room_patch: per-entity LWW patch application (plan §3) ----

/// One op in a `POST .../patch` batch. Deserialized directly off the wire
/// by `routes::rooms` (same one-copy pattern `dm_db::MessageError` uses —
/// this type is reused verbatim by the route rather than mirrored into a
/// second, converted copy) and fed straight into [`apply_room_patch`].
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RoomOp {
    /// `"window" | "bubble" | "indicator" | "alert" | "primitive" | "layout"`
    /// — validated by `routes::rooms` before this ever reaches
    /// [`apply_room_patch`], which treats it as an opaque storage key.
    pub kind: String,
    /// The entity's stable id (stringified).
    pub id: String,
    #[serde(rename = "op")]
    pub action: RoomOpAction,
    /// The entity's version this op was computed against. `0` means "I
    /// believe this entity does not exist yet" (create path).
    pub base_version: i64,
    /// Required unless `action == Delete` — validated by `routes::rooms`.
    #[serde(default)]
    pub json: Option<serde_json::Value>,
    /// Only meaningful for `kind = "primitive"`: which window/bubble entity
    /// owns it. Required on an Upsert creating a new primitive id; ignored
    /// (read back from storage) on Delete.
    #[serde(default)]
    pub parent_kind: Option<String>,
    #[serde(default)]
    pub parent_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoomOpAction {
    Upsert,
    Delete,
}

/// The per-op (or per-cascade-row) result of [`apply_room_patch`].
#[derive(Debug, Clone, PartialEq)]
pub enum RoomOpOutcome {
    Applied { version: i64, seq: i64 },
    /// The entity exists but `base_version` didn't match current — someone
    /// else's write already landed on THIS entity. Carries the current row
    /// so the client can re-anchor without a second round trip.
    Stale {
        current_version: i64,
        current_json: Option<String>,
    },
    /// `base_version` pointed at a version the caller believed live, but the
    /// entity is gone (deleted directly, or cascade-deleted with its parent
    /// window/bubble).
    Gone,
    /// Whole-batch gate: caller lacked `edit` on an existing room, or — for
    /// a not-yet-existing room — `room_create_allowed` (the caller's
    /// resolved create/quota check) was `false`. Every op in the batch
    /// carries this SAME outcome; no per-op write is attempted.
    Forbidden,
}

/// Read `(version, json, deleted)` for one entity, or `None` if no row
/// exists at all — the shared re-select both [`apply_upsert_op`] and
/// [`apply_delete_op`] run after a `version=?` UPDATE affects zero rows, to
/// tell `Stale` (row exists, different version) apart from `Gone` (no row,
/// or a tombstone).
fn select_current_entity(
    tx: &rusqlite::Transaction,
    room_id: &str,
    kind: &str,
    entity_id: &str,
) -> Result<Option<(i64, Option<String>, i64)>> {
    tx.query_row(
        "SELECT version, json, deleted FROM shared_preset_entities
         WHERE room_id = ?1 AND kind = ?2 AND entity_id = ?3",
        params![room_id, kind, entity_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get::<_, i64>(2)?)),
    )
    .optional()
}

fn apply_upsert_op(
    tx: &rusqlite::Transaction,
    room_id: &str,
    caller: i64,
    now: &str,
    op: &RoomOp,
    seq: &mut i64,
) -> Result<RoomOpOutcome> {
    // `op.json` presence for an Upsert is validated by `routes::rooms`
    // before this is ever called — an empty string here would only be
    // reachable through a routing bug, not a caller-controlled input.
    let json_str = op.json.as_ref().map(|v| v.to_string()).unwrap_or_default();

    if op.base_version == 0 {
        // "I believe this doesn't exist yet." A row already occupying this
        // PK — live OR a tombstone — is a collision, never silently
        // overwritten (the tombstone case also avoids a PK violation on the
        // INSERT below).
        if let Some((cur_version, cur_json, _deleted)) = select_current_entity(tx, room_id, &op.kind, &op.id)? {
            return Ok(RoomOpOutcome::Stale { current_version: cur_version, current_json: cur_json });
        }
        let candidate_seq = *seq + 1;
        tx.execute(
            "INSERT INTO shared_preset_entities
                (room_id, kind, entity_id, version, updated_by, updated_at, json, deleted, seq, parent_kind, parent_id)
             VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, 0, ?7, ?8, ?9)",
            params![room_id, op.kind, op.id, caller, now, json_str, candidate_seq, op.parent_kind, op.parent_id],
        )?;
        *seq = candidate_seq;
        return Ok(RoomOpOutcome::Applied { version: 1, seq: candidate_seq });
    }

    let candidate_seq = *seq + 1;
    let affected = tx.execute(
        "UPDATE shared_preset_entities
         SET json = ?1, version = version + 1, updated_by = ?2, updated_at = ?3, deleted = 0, seq = ?4
         WHERE room_id = ?5 AND kind = ?6 AND entity_id = ?7 AND version = ?8 AND deleted = 0",
        params![json_str, caller, now, candidate_seq, room_id, op.kind, op.id, op.base_version],
    )?;
    if affected == 1 {
        *seq = candidate_seq;
        return Ok(RoomOpOutcome::Applied { version: op.base_version + 1, seq: candidate_seq });
    }

    match select_current_entity(tx, room_id, &op.kind, &op.id)? {
        Some((cur_version, cur_json, deleted)) if deleted == 0 => {
            Ok(RoomOpOutcome::Stale { current_version: cur_version, current_json: cur_json })
        }
        _ => Ok(RoomOpOutcome::Gone),
    }
}

fn apply_delete_op(
    tx: &rusqlite::Transaction,
    room_id: &str,
    caller: i64,
    now: &str,
    op: &RoomOp,
    seq: &mut i64,
) -> Result<RoomOpOutcome> {
    let candidate_seq = *seq + 1;
    let affected = tx.execute(
        "UPDATE shared_preset_entities
         SET deleted = 1, version = version + 1, updated_by = ?1, updated_at = ?2, seq = ?3, json = NULL
         WHERE room_id = ?4 AND kind = ?5 AND entity_id = ?6 AND version = ?7 AND deleted = 0",
        params![caller, now, candidate_seq, room_id, op.kind, op.id, op.base_version],
    )?;
    if affected == 1 {
        *seq = candidate_seq;
        return Ok(RoomOpOutcome::Applied { version: op.base_version + 1, seq: candidate_seq });
    }

    match select_current_entity(tx, room_id, &op.kind, &op.id)? {
        Some((cur_version, cur_json, deleted)) if deleted == 0 => {
            Ok(RoomOpOutcome::Stale { current_version: cur_version, current_json: cur_json })
        }
        _ => Ok(RoomOpOutcome::Gone),
    }
}

/// Tombstone every live `primitive` row parented to `(parent_kind,
/// parent_id)` — run in the SAME transaction right after a `window`/
/// `bubble` Delete op applies (plan §1/§3), so a viewer never sees an
/// orphaned primitive whose parent silently vanished. Each cascaded row
/// burns its own `seq` (a real applied write, same as any direct op).
fn cascade_delete_primitives(
    tx: &rusqlite::Transaction,
    room_id: &str,
    parent_kind: &str,
    parent_id: &str,
    caller: i64,
    now: &str,
    seq: &mut i64,
) -> Result<Vec<(String, RoomOpOutcome)>> {
    let ids: Vec<(String, i64)> = {
        let mut stmt = tx.prepare(
            "SELECT entity_id, version FROM shared_preset_entities
             WHERE room_id = ?1 AND kind = 'primitive' AND parent_kind = ?2 AND parent_id = ?3 AND deleted = 0",
        )?;
        let rows = stmt.query_map(params![room_id, parent_kind, parent_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        rows.collect::<Result<Vec<_>>>()?
    };

    let mut out = Vec::with_capacity(ids.len());
    for (entity_id, old_version) in ids {
        *seq += 1;
        tx.execute(
            "UPDATE shared_preset_entities
             SET deleted = 1, version = version + 1, updated_by = ?1, updated_at = ?2, seq = ?3, json = NULL
             WHERE room_id = ?4 AND kind = 'primitive' AND entity_id = ?5 AND deleted = 0",
            params![caller, now, *seq, room_id, entity_id],
        )?;
        out.push((entity_id, RoomOpOutcome::Applied { version: old_version + 1, seq: *seq }));
    }
    Ok(out)
}

/// Apply one patch batch, per-entity LWW, inside one sqlite transaction —
/// the batch is atomic as a unit of COMMIT (a partial per-op outcome is
/// normal and expected; only an actual DB error rolls back the whole
/// batch). Bumps `shared_presets.seq` once per successfully applied op
/// (rejected ops don't burn a seq number; cascade tombstones DO, each one).
///
/// `room_create_allowed` is resolved by the CALLER before this runs
/// (`routes::rooms::is_shared_presets_paid` + `entitlements::
/// shared_preset_create_allowed`) — this function cannot resolve it itself
/// because the ladder-paid fact needs the social-plane connection
/// (`ControlPlane::social`), which is a different connection from `conn`
/// here (see `entitlements.rs`'s "Shared presets" module doc for the
/// 2026-09-23 ladder ruling this reflects). This is the one deviation from
/// the plan's literal signature. Editing an EXISTING room needs no such
/// externally-resolved fact — `effective_object_rights` (identity-DB only)
/// is resolved right here.
///
/// Returns the room's seq after the batch, one outcome per INPUT op in
/// request order, PLUS zero or more synthetic cascade outcomes
/// (`kind = "primitive"`, `Applied`-as-tombstone) for any window/bubble
/// Delete that removed primitives. If the room does not exist yet and
/// `room_create_allowed`, the first successfully-applied op implicitly
/// creates `shared_presets` with `caller` as owner, in the same
/// transaction as every op below it.
pub fn apply_room_patch(
    conn: &mut Connection,
    kind: &str,
    room_id: &str,
    caller: i64,
    now: &str,
    ops: &[RoomOp],
    room_create_allowed: bool,
) -> Result<(i64, Vec<(RoomOp, RoomOpOutcome)>, Vec<(String, RoomOpOutcome)>)> {
    let header: Option<(i64, i64)> = conn
        .query_row(
            "SELECT owner_user_id, seq FROM shared_presets WHERE object_id = ?1",
            params![room_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    let (is_new_room, owner_user_id, mut seq) = match header {
        Some((owner, seq)) => (false, owner, seq),
        None => (true, caller, 0),
    };

    let authorized = if is_new_room {
        room_create_allowed
    } else {
        effective_object_rights(conn, kind, room_id, owner_user_id, Some(caller))?.contains(&"edit")
    };

    if !authorized {
        let forbidden = ops.iter().cloned().map(|op| (op, RoomOpOutcome::Forbidden)).collect();
        return Ok((seq, forbidden, Vec::new()));
    }

    let tx = conn.transaction()?;
    if is_new_room {
        tx.execute(
            "INSERT INTO shared_presets (object_id, owner_user_id, title, visibility, seq, created_at, updated_at)
             VALUES (?1, ?2, '', 'private', 0, ?3, ?3)",
            params![room_id, caller, now],
        )?;
    }

    let mut results = Vec::with_capacity(ops.len());
    let mut cascades = Vec::new();
    for op in ops {
        let outcome = match op.action {
            RoomOpAction::Upsert => apply_upsert_op(&tx, room_id, caller, now, op, &mut seq)?,
            RoomOpAction::Delete => apply_delete_op(&tx, room_id, caller, now, op, &mut seq)?,
        };
        if matches!(outcome, RoomOpOutcome::Applied { .. })
            && op.action == RoomOpAction::Delete
            && (op.kind == "window" || op.kind == "bubble")
        {
            let cascaded = cascade_delete_primitives(&tx, room_id, &op.kind, &op.id, caller, now, &mut seq)?;
            cascades.extend(cascaded);
        }
        results.push((op.clone(), outcome));
    }

    tx.execute(
        "UPDATE shared_presets SET seq = ?1, updated_at = ?2 WHERE object_id = ?3",
        params![seq, now, room_id],
    )?;
    tx.commit()?;

    Ok((seq, results, cascades))
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
        "SELECT user_id FROM web_sessions WHERE session_id = ?1 AND ua_hash = ?2 AND datetime(expires_at) > datetime('now')",
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
        "DELETE FROM device_codes WHERE datetime(expires_at) < datetime('now')",
        [],
    )?;
    conn.execute(
        "DELETE FROM web_sessions WHERE datetime(expires_at) < datetime('now')",
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

/// A row from the `agent_key_requests` table, as exposed to callers.
///
/// `user_id` and `claimed_key` (the raw key stored temporarily between
/// confirm and claim) live on the table but are deliberately NOT projected
/// here: `routes::agent_keys::get_agent_key_info` must never echo the raw key
/// back over this read path, and no caller needs `user_id` off this struct —
/// `poll_agent_key_request` reads `claimed_key` with its own direct query
/// instead, precisely so this struct can stay free of it.
#[derive(Debug, Clone)]
pub struct AgentKeyRequestRow {
    pub code: String,
    pub label: String,
    pub permissions: String,
    pub status: String,
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
        "SELECT code, label, permissions, status, created_at, expires_at
         FROM agent_key_requests WHERE code = ?1",
    )?;
    let mut rows = stmt.query(params![code])?;
    if let Some(row) = rows.next()? {
        Ok(Some(AgentKeyRequestRow {
            code: row.get(0)?,
            label: row.get(1)?,
            permissions: row.get(2)?,
            status: row.get(3)?,
            created_at: row.get(4)?,
            expires_at: row.get(5)?,
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
           AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))",
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
           AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
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
           AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
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
    // Account-wide alert definitions (A3): the client pushes its alerts.json
    // items here; mlc-alert-daemon reads them read-only for server-side
    // price-alert evaluation. Shape: crates/mlc-alert-daemon/src/alert_item.rs.
    "alerts",
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
           AND (a.expires_at IS NULL OR datetime(a.expires_at) > datetime('now'))
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
/// Forum content (`forum_threads`/`forum_replies`) is NOT in this cascade at
/// all: it is HIDDEN, not deleted, one statement per table before the rest
/// of the cascade runs, and — unlike every table above — it carries no
/// foreign key to `users` (see the CREATE TABLE comment in `init_db`), so it
/// cannot block the final `DELETE FROM users` regardless of ordering. A
/// thread the deleted account started keeps every other account's replies;
/// `db::forum_author_label` reports "deleted user" for the gone account
/// either way.
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
    // Forum rows are hidden, never deleted — see this function's doc
    // comment. No foreign key exists from these tables to `users`, so this
    // can run in any order relative to the `DELETE FROM users` below.
    conn.execute(
        "UPDATE forum_threads SET hidden = 1 WHERE author_user_id = ?1",
        params![user_id],
    )?;
    conn.execute(
        "UPDATE forum_replies SET hidden = 1 WHERE author_user_id = ?1",
        params![user_id],
    )?;
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

/// Length ceilings for a post's free-text fields, counted in `chars` (a
/// human-facing limit, not a storage one — same convention as
/// [`is_valid_forum_title`]). Cleaning (NFC-normalize, control-character
/// rejection) happens at the route layer (`routes::posts::admin_upsert_post`,
/// via `text_policy::clean_user_text`/`clean_optional_user_text`); these
/// ceilings are the database layer's own backstop in case a future caller
/// ever bypasses that route-level cleaning.
pub const MAX_POST_TITLE_CHARS: usize = 200;
pub const MAX_POST_SUMMARY_CHARS: usize = 500;
pub const MAX_POST_BODY_CHARS: usize = 64_000;

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
    /// Longer than [`MAX_POST_TITLE_CHARS`].
    TitleTooLong,
    /// Longer than [`MAX_POST_SUMMARY_CHARS`].
    SummaryTooLong,
    /// Longer than [`MAX_POST_BODY_CHARS`].
    BodyTooLong,
    /// The database call itself failed.
    Db(rusqlite::Error),
}

impl From<rusqlite::Error> for PostError {
    fn from(e: rusqlite::Error) -> Self {
        PostError::Db(e)
    }
}

/// Insert or update one post by `id`. Validates `id`/`kind`/`date`/
/// `visibility` before touching the database, plus a length ceiling on
/// `title`/`summary`/`body` (see [`MAX_POST_TITLE_CHARS`] and siblings) —
/// `url` still carries no format constraint beyond what the column type
/// already enforces.
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
    if post.title.chars().count() > MAX_POST_TITLE_CHARS {
        return Err(PostError::TitleTooLong);
    }
    if post.summary.chars().count() > MAX_POST_SUMMARY_CHARS {
        return Err(PostError::SummaryTooLong);
    }
    if post.body.chars().count() > MAX_POST_BODY_CHARS {
        return Err(PostError::BodyTooLong);
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

// ============================================================================
// Forum (paid in-app communication, 2026-09-05 users-paid-features scope §4)
//
// A thread (`forum_threads`) carries a title + body and belongs to one
// author; a reply (`forum_replies`) belongs to one thread and one author.
// Both are gated at the route layer by `entitlements::Feature::Forum` (see
// routes/forum.rs) — nothing in this section itself checks paid status.
// `hidden` is moderation, applied by the author to their own row or by an
// admin to any row (see `hide_thread`/`hide_reply`); a hidden row is filtered
// out of every list/get here, never physically removed. See the CREATE
// TABLE comment in `init_db` for why `author_user_id` carries no foreign key
// to `users`.
// ============================================================================

/// One row of the `forum_threads` table.
#[derive(Debug, Clone, PartialEq)]
pub struct ForumThread {
    pub id: i64,
    pub author_user_id: i64,
    pub title: String,
    pub body: String,
    pub created_at: String,
    pub updated_at: String,
    pub last_reply_at: Option<String>,
    pub reply_count: i64,
    pub hidden: bool,
}

/// One row of the `forum_replies` table.
#[derive(Debug, Clone, PartialEq)]
pub struct ForumReply {
    pub id: i64,
    pub thread_id: i64,
    pub author_user_id: i64,
    pub body: String,
    pub created_at: String,
    pub hidden: bool,
}

/// Read one query row into a [`ForumThread`]. Column order must match the
/// SELECT lists below.
fn forum_thread_from_row(row: &rusqlite::Row<'_>) -> Result<ForumThread> {
    Ok(ForumThread {
        id: row.get(0)?,
        author_user_id: row.get(1)?,
        title: row.get(2)?,
        body: row.get(3)?,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
        last_reply_at: row.get(6)?,
        reply_count: row.get(7)?,
        hidden: row.get::<_, i64>(8)? != 0,
    })
}

const FORUM_THREAD_SELECT_COLUMNS: &str =
    "id, author_user_id, title, body, created_at, updated_at, last_reply_at, reply_count, hidden";

/// Read one query row into a [`ForumReply`]. Column order must match the
/// SELECT lists below.
fn forum_reply_from_row(row: &rusqlite::Row<'_>) -> Result<ForumReply> {
    Ok(ForumReply {
        id: row.get(0)?,
        thread_id: row.get(1)?,
        author_user_id: row.get(2)?,
        body: row.get(3)?,
        created_at: row.get(4)?,
        hidden: row.get::<_, i64>(5)? != 0,
    })
}

const FORUM_REPLY_SELECT_COLUMNS: &str = "id, thread_id, author_user_id, body, created_at, hidden";

/// Title length rule for a thread: 3-120 characters (`chars`, not bytes —
/// this is a human-facing length limit, unlike [`is_valid_forum_body`]).
pub fn is_valid_forum_title(title: &str) -> bool {
    (3..=120).contains(&title.chars().count())
}

/// Body length rule for a thread or a reply: 1-8192 BYTES — this bounds the
/// row size, which is what storage and the wire pay for, so it is measured
/// in bytes rather than characters.
pub fn is_valid_forum_body(body: &str) -> bool {
    (1..=8192).contains(&body.len())
}

/// Why a [`create_thread`] or [`create_reply`] call was refused before ever
/// touching the database.
#[derive(Debug)]
pub enum ForumError {
    /// Fails [`is_valid_forum_title`]. Threads only — replies have no title.
    InvalidTitle,
    /// Fails [`is_valid_forum_body`].
    InvalidBody,
    /// The database call itself failed.
    Db(rusqlite::Error),
}

impl From<rusqlite::Error> for ForumError {
    fn from(e: rusqlite::Error) -> Self {
        ForumError::Db(e)
    }
}

/// Create one thread. Validates `title`/`body` before touching the database.
/// Returns the new thread's id.
pub fn create_thread(
    conn: &Connection,
    author_user_id: i64,
    title: &str,
    body: &str,
    now: &str,
) -> std::result::Result<i64, ForumError> {
    if !is_valid_forum_title(title) {
        return Err(ForumError::InvalidTitle);
    }
    if !is_valid_forum_body(body) {
        return Err(ForumError::InvalidBody);
    }
    conn.execute(
        "INSERT INTO forum_threads (author_user_id, title, body, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?4)",
        params![author_user_id, title, body, now],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Fetch one visible (non-hidden) thread by id, or `None` if it does not
/// exist or is hidden — the two are indistinguishable here on purpose, same
/// posture as [`get_share_link`].
pub fn get_thread(conn: &Connection, thread_id: i64) -> Result<Option<ForumThread>> {
    conn.query_row(
        &format!(
            "SELECT {} FROM forum_threads WHERE id = ?1 AND hidden = 0",
            FORUM_THREAD_SELECT_COLUMNS
        ),
        params![thread_id],
        forum_thread_from_row,
    )
    .optional()
}

/// List visible threads ordered by last activity — `COALESCE(last_reply_at,
/// created_at)` — newest first, then `id DESC` as the tie-break, optionally
/// paginated with a `(last_activity, id)` keyset cursor: `before` returns
/// only rows strictly older than that cursor in this ordering, matching
/// [`list_posts`]'s `(date, id)` cursor shape.
pub fn list_threads(
    conn: &Connection,
    limit: i64,
    before: Option<(&str, i64)>,
) -> Result<Vec<ForumThread>> {
    let activity_expr = "COALESCE(last_reply_at, created_at)";
    let mut sql = format!(
        "SELECT {}, {} AS last_activity FROM forum_threads WHERE hidden = 0",
        FORUM_THREAD_SELECT_COLUMNS, activity_expr
    );
    let mut bound: Vec<&dyn rusqlite::ToSql> = Vec::new();

    if let Some((activity, id)) = before.as_ref() {
        sql.push_str(&format!(
            " AND ({activity_expr} < ? OR ({activity_expr} = ? AND id < ?))",
            activity_expr = activity_expr
        ));
        bound.push(activity as &dyn rusqlite::ToSql);
        bound.push(activity as &dyn rusqlite::ToSql);
        bound.push(id as &dyn rusqlite::ToSql);
    }
    sql.push_str(" ORDER BY last_activity DESC, id DESC LIMIT ?");
    bound.push(&limit as &dyn rusqlite::ToSql);

    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(bound.as_slice())?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(forum_thread_from_row(row)?);
    }
    Ok(out)
}

/// Create one reply under `thread_id` and bump that thread's `reply_count`
/// and `last_reply_at`/`updated_at` to `now`. Validates `body` before
/// touching the database. Does NOT check that `thread_id` exists or is
/// visible — the route calls [`get_thread`] first (404 if missing/hidden)
/// so this function stays a plain write. Returns the new reply's id.
pub fn create_reply(
    conn: &Connection,
    thread_id: i64,
    author_user_id: i64,
    body: &str,
    now: &str,
) -> std::result::Result<i64, ForumError> {
    if !is_valid_forum_body(body) {
        return Err(ForumError::InvalidBody);
    }
    conn.execute(
        "INSERT INTO forum_replies (thread_id, author_user_id, body, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![thread_id, author_user_id, body, now],
    )?;
    let reply_id = conn.last_insert_rowid();
    conn.execute(
        "UPDATE forum_threads
         SET reply_count = reply_count + 1, last_reply_at = ?2, updated_at = ?2
         WHERE id = ?1",
        params![thread_id, now],
    )?;
    Ok(reply_id)
}

/// List visible replies to `thread_id`, oldest first.
pub fn list_replies(conn: &Connection, thread_id: i64) -> Result<Vec<ForumReply>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {} FROM forum_replies WHERE thread_id = ?1 AND hidden = 0 ORDER BY id ASC",
        FORUM_REPLY_SELECT_COLUMNS
    ))?;
    let mut rows = stmt.query(params![thread_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(forum_reply_from_row(row)?);
    }
    Ok(out)
}

/// Hide one thread. `owner_user_id = Some(uid)` requires `uid` to be the
/// thread's author (the self-service `DELETE /api/forum/threads/{id}`
/// route); `None` hides unconditionally (the admin route, which has already
/// checked `verify_admin_secret`). Already-hidden and unknown ids both
/// return `false` — same "no distinguishable states" posture as
/// [`revoke_share`].
pub fn hide_thread(conn: &Connection, thread_id: i64, owner_user_id: Option<i64>) -> Result<bool> {
    let n = match owner_user_id {
        Some(uid) => conn.execute(
            "UPDATE forum_threads SET hidden = 1 WHERE id = ?1 AND author_user_id = ?2 AND hidden = 0",
            params![thread_id, uid],
        )?,
        None => conn.execute(
            "UPDATE forum_threads SET hidden = 1 WHERE id = ?1 AND hidden = 0",
            params![thread_id],
        )?,
    };
    Ok(n > 0)
}

/// Hide one reply. Same `owner_user_id` contract as [`hide_thread`].
pub fn hide_reply(conn: &Connection, reply_id: i64, owner_user_id: Option<i64>) -> Result<bool> {
    let n = match owner_user_id {
        Some(uid) => conn.execute(
            "UPDATE forum_replies SET hidden = 1 WHERE id = ?1 AND author_user_id = ?2 AND hidden = 0",
            params![reply_id, uid],
        )?,
        None => conn.execute(
            "UPDATE forum_replies SET hidden = 1 WHERE id = ?1 AND hidden = 0",
            params![reply_id],
        )?,
    };
    Ok(n > 0)
}

/// Count of threads `user_id` has created with `created_at` strictly after
/// `since` (an RFC3339 instant) — the input to the 1-thread-per-60-seconds
/// rate limit in `routes/forum.rs`. Counts hidden rows too: a hidden thread
/// still happened and still counts against the window.
pub fn threads_created_since(conn: &Connection, user_id: i64, since: &str) -> Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM forum_threads WHERE author_user_id = ?1 AND created_at > ?2",
        params![user_id, since],
        |row| row.get(0),
    )
}

/// Count of replies `user_id` has created with `created_at` strictly after
/// `since` — the input to the 10-replies-per-60-seconds rate limit. Same
/// "hidden still counts" rule as [`threads_created_since`].
pub fn replies_created_since(conn: &Connection, user_id: i64, since: &str) -> Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM forum_replies WHERE author_user_id = ?1 AND created_at > ?2",
        params![user_id, since],
        |row| row.get(0),
    )
}

/// The label to show for a forum author: [`effective_label_for_user`]'s
/// nick -> display_name -> public_id chain, or `"deleted user"` once that
/// account is gone. `forum_threads`/`forum_replies` deliberately carry no
/// foreign key to `users` (see the CREATE TABLE comment in `init_db`), so a
/// hidden row surviving its author's `delete_account` still needs something
/// to display here rather than the empty string
/// [`effective_label_for_user`] returns for a gone user.
pub fn forum_author_label(conn: &Connection, user_id: i64) -> Result<String> {
    let label = effective_label_for_user(conn, user_id)?;
    Ok(if label.is_empty() {
        "deleted user".to_string()
    } else {
        label
    })
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
    /// device_users, user_providers, web_sessions) and the two forum tables
    /// it hides rows in (forum_threads, forum_replies), so that cascade can
    /// be tested end to end. `PRAGMA foreign_keys=ON` matches production
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
                paid_until TEXT,
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
                email TEXT,
                email_verified INTEGER NOT NULL DEFAULT 0,
                UNIQUE(provider, provider_user_id)
            );
            CREATE INDEX idx_user_providers_email_verified
                ON user_providers(LOWER(email)) WHERE email_verified = 1;

            CREATE TABLE web_sessions (
                session_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );

            -- Deliberately NOT REFERENCES users(id) on author_user_id —
            -- matches production (see the CREATE TABLE comment in init_db).
            CREATE TABLE forum_threads (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                author_user_id INTEGER NOT NULL,
                title          TEXT    NOT NULL,
                body           TEXT    NOT NULL,
                created_at     TEXT    NOT NULL,
                updated_at     TEXT    NOT NULL,
                last_reply_at  TEXT,
                reply_count    INTEGER NOT NULL DEFAULT 0,
                hidden         INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE forum_replies (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                thread_id      INTEGER NOT NULL REFERENCES forum_threads(id),
                author_user_id INTEGER NOT NULL,
                body           TEXT    NOT NULL,
                created_at     TEXT    NOT NULL,
                hidden         INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE notify_batches (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ts           TEXT    NOT NULL,
                channel      TEXT    NOT NULL,
                text         TEXT    NOT NULL,
                requested_by TEXT    NOT NULL DEFAULT 'admin'
            );

            CREATE TABLE notify_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        TEXT    NOT NULL,
                channel   TEXT    NOT NULL,
                user_id   INTEGER NOT NULL,
                ok        INTEGER NOT NULL,
                error     TEXT,
                text_hash TEXT    NOT NULL,
                batch_id  INTEGER NOT NULL REFERENCES notify_batches(id)
            );

            CREATE TABLE reserved_nicks (
                nick_lower  TEXT PRIMARY KEY,
                category    TEXT NOT NULL,
                note        TEXT,
                reserved_at TEXT NOT NULL,
                granted_to  INTEGER
            );
            INSERT INTO reserved_nicks (nick_lower, category, note, reserved_at, granted_to) VALUES
                ('zengeld', 'project', NULL, '2026-01-01T00:00:00+00:00', NULL),
                ('kosti_x_itsok', 'project', NULL, '2026-01-01T00:00:00+00:00', NULL),
                ('kosti_itsok', 'project', NULL, '2026-01-01T00:00:00+00:00', NULL);
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

        let token = super::create_share_link(&conn, uid, "live", "t", "{}", 0, &now, &future_ts(), false, "view", "[]", "public", None)
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

    /// Chart-share policy v1 (docs/mlc/plans/share-policy-2026-09-25.md §1,
    /// §11 step 1): `interaction`/`protected_json` round-trip through
    /// `create_share_link` -> `get_share_link` unchanged, and a row inserted
    /// with the ALTER TABLE's own bare defaults (simulating a link created
    /// before this column existed) reads back as `"view"`/`"[]"` — the "old
    /// links keep today's behaviour" migration guarantee.
    #[test]
    fn share_link_interaction_and_protected_json_roundtrip() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "erin", Some("pub-erin"));
        let now = chrono::Utc::now().to_rfc3339();

        let protected = r#"[{"kind":"primitive","id":"7"}]"#;
        let token = super::create_share_link(
            &conn, uid, "live", "t", "{}", 0, &now, &future_ts(), false, "interactive", protected, "public", None,
        )
        .expect("create");
        let row = super::get_share_link(&conn, &token).expect("query").expect("row");
        assert_eq!(row.interaction, "interactive");
        assert_eq!(row.protected_json, protected);

        // A bare INSERT that never names these two columns (an old row) gets
        // the ALTER TABLE's own defaults, not a NULL/panic.
        conn.execute(
            "INSERT INTO share_links (token, user_id, kind, title, preset_json, blob_path, blob_bytes, created_at, expires_at, revoked, clone_allowed)
             VALUES ('legacytoken000000000000000000legacy', ?1, 'live', 'old', '{}', '', 0, ?2, ?3, 0, 0)",
            rusqlite::params![uid, now, future_ts()],
        )
        .expect("insert legacy row");
        let legacy = super::get_share_link(&conn, "legacytoken000000000000000000legacy")
            .expect("query")
            .expect("row");
        assert_eq!(legacy.interaction, "view");
        assert_eq!(legacy.protected_json, "[]");
    }

    // ---- extend_paid_until / grant_paid_days (admin `paid-days` grant) ----

    #[test]
    fn extend_paid_until_extends_from_now_when_never_paid() {
        let now = chrono::Utc::now();
        let until = super::extend_paid_until(None, 7, now);
        let until_dt = chrono::DateTime::parse_from_rfc3339(&until)
            .expect("parse")
            .with_timezone(&chrono::Utc);
        assert_eq!(until_dt, now + chrono::Duration::days(7));
    }

    #[test]
    fn extend_paid_until_extends_from_now_when_the_existing_grant_already_expired() {
        let now = chrono::Utc::now();
        let expired = (now - chrono::Duration::days(30)).to_rfc3339();
        let until = super::extend_paid_until(Some(&expired), 5, now);
        let until_dt = chrono::DateTime::parse_from_rfc3339(&until)
            .expect("parse")
            .with_timezone(&chrono::Utc);
        assert_eq!(until_dt, now + chrono::Duration::days(5));
    }

    #[test]
    fn extend_paid_until_extends_from_an_existing_future_paid_until() {
        let now = chrono::Utc::now();
        let existing = (now + chrono::Duration::days(10)).to_rfc3339();
        let until = super::extend_paid_until(Some(&existing), 5, now);
        let until_dt = chrono::DateTime::parse_from_rfc3339(&until)
            .expect("parse")
            .with_timezone(&chrono::Utc);
        // Extends the existing future grant by 5 days, not from `now`.
        assert_eq!(until_dt, now + chrono::Duration::days(15));
    }

    #[test]
    fn grant_paid_days_refuses_an_unknown_user() {
        let conn = share_test_conn();
        assert!(super::grant_paid_days(&conn, 999, 7).expect("db ok").is_none());
    }

    #[test]
    fn grant_paid_days_extends_from_now_and_writes_paid_until_through() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "nyx", Some("pub-nyx"));
        let new_until = super::grant_paid_days(&conn, uid, 3).expect("db ok").expect("user exists");
        assert_eq!(super::user_paid_until(&conn, uid).expect("query"), Some(new_until));
    }

    #[test]
    fn grant_paid_days_extends_from_an_existing_future_paid_until() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "orin", Some("pub-orin"));
        let now = chrono::Utc::now();
        let existing = (now + chrono::Duration::days(10)).to_rfc3339();
        super::set_user_paid_until(&conn, uid, Some(&existing)).expect("set paid_until");

        let new_until = super::grant_paid_days(&conn, uid, 5).expect("db ok").expect("user exists");
        let new_until_dt = chrono::DateTime::parse_from_rfc3339(&new_until)
            .expect("parse")
            .with_timezone(&chrono::Utc);
        // Extended from the existing future grant (10 days out), not from
        // `now`: ~15 days out, well past what a bare 5-day grant from `now`
        // would give.
        assert!(new_until_dt > now + chrono::Duration::days(14));
    }

    #[test]
    fn users_paid_batch_resolves_paid_unpaid_expired_and_omits_unknown_ids() {
        let conn = share_test_conn();
        let paid_uid = insert_share_user(&conn, "paidy", Some("pub-paidy"));
        let unpaid_uid = insert_share_user(&conn, "plain", Some("pub-plain"));
        let expired_uid = insert_share_user(&conn, "lapsed", Some("pub-lapsed"));

        let future = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();
        let past = (chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339();
        super::set_user_paid_until(&conn, paid_uid, Some(&future)).expect("set paid");
        super::set_user_paid_until(&conn, expired_uid, Some(&past)).expect("set expired");

        let unknown_uid = 999_999;
        let result =
            super::users_paid_batch(&conn, &[paid_uid, unpaid_uid, expired_uid, unknown_uid]).expect("batch");

        assert_eq!(result.get(&paid_uid), Some(&true));
        assert_eq!(result.get(&unpaid_uid), Some(&false));
        assert_eq!(result.get(&expired_uid), Some(&false));
        assert_eq!(result.get(&unknown_uid), None, "an unknown user_id must be absent, not false");
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn users_paid_batch_empty_ids_returns_empty_map() {
        let conn = share_test_conn();
        assert!(super::users_paid_batch(&conn, &[]).expect("batch").is_empty());
    }

    #[test]
    fn share_usage_counts_only_active_rows_per_kind() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "bob", Some("pub-bob"));
        let now = chrono::Utc::now().to_rfc3339();

        assert_eq!(super::share_usage(&conn, uid).expect("usage"), (0, 0));

        super::create_share_link(&conn, uid, "live", "l1", "{}", 0, &now, &future_ts(), false, "view", "[]", "public", None)
            .expect("create");
        let shot = super::create_share_link(&conn, uid, "screenshot", "s1", "", 42, &now, &future_ts(), false, "view", "[]", "public", None)
            .expect("create");
        assert_eq!(super::share_usage(&conn, uid).expect("usage"), (1, 1));

        // Expired and revoked rows stop counting.
        super::create_share_link(&conn, uid, "live", "l2", "{}", 0, &now, &past_ts(), false, "view", "[]", "public", None)
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
            "2026-01-01T00:00:00+00:00", &future_ts(), false, "view", "[]", "public", None,
        )
        .expect("create");
        let newer = super::create_share_link(
            &conn, uid, "screenshot", "new", "", 1,
            "2026-02-01T00:00:00+00:00", &future_ts(), false, "view", "[]", "public", None,
        )
        .expect("create");
        super::create_share_link(
            &conn, uid, "live", "dead", "{}", 0,
            "2026-03-01T00:00:00+00:00", &past_ts(), false, "view", "[]", "public", None,
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

        let live_expired = super::create_share_link(&conn, uid, "live", "l", "{}", 0, &now, &past_ts(), false, "view", "[]", "public", None)
            .expect("create");
        let shot_expired =
            super::create_share_link(&conn, uid, "screenshot", "s", "", 7, &now, &past_ts(), false, "view", "[]", "public", None)
                .expect("create");
        super::set_share_blob_path(&conn, &shot_expired, &format!("{}/{}.png", uid, shot_expired))
            .expect("stamp blob path");
        let alive = super::create_share_link(&conn, uid, "live", "ok", "{}", 0, &now, &future_ts(), false, "view", "[]", "public", None)
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

        super::create_share_link(&conn, uid, "live", "l", "{}", 0, &now, &future_ts(), false, "view", "[]", "public", None)
            .expect("create live");
        let shot = super::create_share_link(&conn, uid, "screenshot", "s", "", 7, &now, &future_ts(), false, "view", "[]", "public", None)
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

    #[test]
    fn delete_account_hides_forum_rows_and_preserves_others_replies() {
        let conn = share_test_conn();
        let author = insert_share_user(&conn, "harry", Some("pub-harry"));
        let replier = insert_share_user(&conn, "iris", Some("pub-iris"));
        let now = chrono::Utc::now().to_rfc3339();

        let thread_id = super::create_thread(&conn, author, "Deleted author's thread", "body", &now)
            .expect("create thread");
        super::create_reply(&conn, thread_id, replier, "still here", &now).expect("create reply");

        // No foreign key means the deletion itself does not fail — that is
        // the point of the CREATE TABLE deviation this test exercises.
        let (deleted, _) = super::delete_account(&conn, author).expect("delete account");
        assert_eq!(deleted, 1);

        // The thread is hidden — invisible to every ordinary reader…
        assert!(super::get_thread(&conn, thread_id).expect("get").is_none());
        assert!(super::list_threads(&conn, 50, None).expect("list").is_empty());
        // …but the row itself, and `iris`'s reply under it, both survive.
        let raw_hidden: i64 = conn
            .query_row(
                "SELECT hidden FROM forum_threads WHERE id = ?1",
                rusqlite::params![thread_id],
                |row| row.get(0),
            )
            .expect("raw thread row");
        assert_eq!(raw_hidden, 1);
        let reply_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM forum_replies WHERE thread_id = ?1",
                rusqlite::params![thread_id],
                |row| row.get(0),
            )
            .expect("raw reply count");
        assert_eq!(reply_count, 1);

        // The author's label now falls back to "deleted user".
        assert_eq!(
            super::forum_author_label(&conn, author).expect("label"),
            "deleted user"
        );
        // The replier's own account is untouched.
        assert_eq!(super::forum_author_label(&conn, replier).expect("label"), "iris");
    }

    // ------------------------------------------------------------------
    // Identity merge — email capture, auto-attach, device-flow orphan fix
    // (docs/mlc/plans/identity-merge-2026-09-09.md decisions 1-3)
    // ------------------------------------------------------------------

    /// Read back `(email, email_verified)` for one `user_providers` row.
    fn provider_email(conn: &Connection, provider: &str, provider_user_id: &str) -> (Option<String>, bool) {
        conn.query_row(
            "SELECT email, email_verified FROM user_providers WHERE provider = ?1 AND provider_user_id = ?2",
            rusqlite::params![provider, provider_user_id],
            |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, i64>(1)? != 0)),
        )
        .expect("provider row")
    }

    fn user_count(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
            .expect("count")
    }

    #[test]
    fn upsert_user_persists_email_per_provider_shape() {
        let conn = share_test_conn();
        let now = chrono::Utc::now().to_rfc3339();

        let uid = super::upsert_user(&conn, "github", "gh1", "alice", Some(("alice@example.com", true)), &now)
            .expect("upsert");
        assert_eq!(
            provider_email(&conn, "github", "gh1"),
            (Some("alice@example.com".to_string()), true)
        );

        // A subsequent sign-in that reports no email leaves the stored one alone.
        let uid2 = super::upsert_user(&conn, "github", "gh1", "alice", None, &now).expect("upsert again");
        assert_eq!(uid, uid2);
        assert_eq!(
            provider_email(&conn, "github", "gh1"),
            (Some("alice@example.com".to_string()), true)
        );

        // A later unverified email refreshes both fields (still the same identity row).
        super::upsert_user(&conn, "github", "gh1", "alice", Some(("alice2@example.com", false)), &now)
            .expect("upsert refresh");
        assert_eq!(
            provider_email(&conn, "github", "gh1"),
            (Some("alice2@example.com".to_string()), false)
        );
    }

    #[test]
    fn resolve_or_create_user_attaches_unknown_identity_on_verified_email_match() {
        let conn = share_test_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let existing = super::upsert_user(&conn, "google", "g1", "Alice", Some(("alice@example.com", true)), &now)
            .expect("seed account");
        let before = user_count(&conn);

        // A different provider identity, same verified email (case-insensitive) — attaches, no new user.
        let resolved = super::resolve_or_create_user(
            &conn, "discord", "d1", "alice#0001", Some(("Alice@Example.com", true)), "", &now,
        )
        .expect("resolve");
        assert_eq!(resolved, existing);
        assert_eq!(user_count(&conn), before, "no new users row should have been created");
        assert_eq!(
            conn.query_row(
                "SELECT user_id FROM user_providers WHERE provider = 'discord' AND provider_user_id = 'd1'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("linked row"),
            existing
        );
    }

    #[test]
    fn resolve_or_create_user_does_not_attach_on_unverified_or_absent_email() {
        let conn = share_test_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let existing = super::upsert_user(&conn, "google", "g2", "Bob", Some(("bob@example.com", true)), &now)
            .expect("seed account");

        // Same email, but NOT verified — must not attach.
        let unverified = super::resolve_or_create_user(
            &conn, "discord", "d2", "bob#0002", Some(("bob@example.com", false)), "", &now,
        )
        .expect("resolve unverified");
        assert_ne!(unverified, existing);

        // No email at all — must not attach.
        let no_email = super::resolve_or_create_user(&conn, "twitter", "t2", "@bob", None, "", &now)
            .expect("resolve no email");
        assert_ne!(no_email, existing);
        assert_ne!(no_email, unverified);
    }

    #[test]
    fn resolve_or_create_user_known_identity_resolves_to_its_own_user_and_refreshes_email() {
        let conn = share_test_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let owner = super::upsert_user(&conn, "github", "gh3", "carol", None, &now).expect("seed owner");
        let other = super::upsert_user(&conn, "google", "g3", "dave", None, &now).expect("seed other");

        // `other`'s device is already linked to `other` — a KNOWN identity must
        // still resolve to its own owner regardless of device linkage.
        super::link_device_user(&conn, "device-x", other, &now).expect("link device");

        let resolved = super::resolve_or_create_user(
            &conn, "github", "gh3", "carol", Some(("carol@example.com", true)), "device-x", &now,
        )
        .expect("resolve known identity");
        assert_eq!(resolved, owner);
        assert_ne!(resolved, other);
        assert_eq!(
            provider_email(&conn, "github", "gh3"),
            (Some("carol@example.com".to_string()), true)
        );
    }

    #[test]
    fn resolve_or_create_user_device_flow_no_longer_orphans() {
        let conn = share_test_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let existing = super::upsert_user(&conn, "github", "gh4", "erin", None, &now).expect("seed account");
        super::link_device_user(&conn, "device-y", existing, &now).expect("link device");
        let before = user_count(&conn);

        // A brand new identity signs in on a device already linked to `existing`
        // — must attach directly, never create a throwaway `users` row.
        let resolved = super::resolve_or_create_user(
            &conn, "discord", "d4", "erin#0004", None, "device-y", &now,
        )
        .expect("resolve on known device");
        assert_eq!(resolved, existing);
        assert_eq!(user_count(&conn), before, "device-flow attach must not create a new users row");
        assert_eq!(
            conn.query_row(
                "SELECT user_id FROM user_providers WHERE provider = 'discord' AND provider_user_id = 'd4'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("linked row"),
            existing
        );
    }

    #[test]
    fn search_users_reports_providers_email_and_telegram_id() {
        let conn = share_test_conn();
        let now = chrono::Utc::now().to_rfc3339();

        // frank: github (verified email) + telegram — multi-provider account.
        let frank = super::upsert_user(&conn, "github", "gh9", "frank", Some(("frank@example.com", true)), &now)
            .expect("seed frank");
        super::link_provider_to_user(&conn, frank, "telegram", "tg-frank", "@frank", None, &now)
            .expect("link telegram");

        // gina: discord only, no email ever captured.
        let gina = super::upsert_user(&conn, "discord", "d9", "gina", None, &now).expect("seed gina");

        let rows = super::search_users(&conn, "fra").expect("search frank");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].user_id, frank);
        assert_eq!(rows[0].providers, vec!["github".to_string(), "telegram".to_string()]);
        assert!(rows[0].has_email);
        assert_eq!(rows[0].telegram_id.as_deref(), Some("tg-frank"));

        let rows = super::search_users(&conn, "gina").expect("search gina");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].user_id, gina);
        assert_eq!(rows[0].providers, vec!["discord".to_string()]);
        assert!(!rows[0].has_email);
        assert_eq!(rows[0].telegram_id, None);
    }

    #[test]
    fn cleanup_orphan_users_removes_self_referencing_orphan_shape_only() {
        let conn = share_test_conn();
        let now = chrono::Utc::now().to_rfc3339();

        // A: a live account with an auth token — must survive.
        let a = super::upsert_user(&conn, "github", "a1", "alive", None, &now).expect("seed a");
        conn.execute(
            "INSERT INTO auth_tokens (token_hash, user_id, created_at) VALUES ('tok-a', ?1, ?2)",
            rusqlite::params![a, now],
        )
        .expect("insert token");

        // B: the exact orphan shape the pre-fix finish_oauth device-merge
        // branch left behind — one self-mirror user_providers row, nothing
        // else anywhere. Must be removed.
        let b = super::upsert_user(&conn, "github", "b1", "orphan", None, &now).expect("seed b");

        // C: same self-mirror shape as B, but still holds a live token —
        // must survive despite having exactly one (self) provider row.
        let c = super::upsert_user(&conn, "github", "c1", "token-holder", None, &now).expect("seed c");
        conn.execute(
            "INSERT INTO auth_tokens (token_hash, user_id, created_at) VALUES ('tok-c', ?1, ?2)",
            rusqlite::params![c, now],
        )
        .expect("insert token");

        // D: no user_providers row at all (the plain pre-existing orphan rule) — must be removed.
        let d = super::upsert_user(&conn, "github", "d1", "no-providers", None, &now).expect("seed d");
        conn.execute("DELETE FROM user_providers WHERE user_id = ?1", rusqlite::params![d])
            .expect("strip providers");

        let cleaned = super::cleanup_orphan_users(&conn).expect("cleanup");
        assert_eq!(cleaned.removed_no_provider, 1, "D (no providers) should be removed");
        assert_eq!(
            cleaned.removed_recent_self_ref, 1,
            "B (self-referencing, created just now) should be removed"
        );
        assert_eq!(cleaned.skipped_dormant, 0);

        let remaining: Vec<i64> = {
            let mut stmt = conn.prepare("SELECT id FROM users ORDER BY id").expect("prepare");
            stmt.query_map([], |row| row.get(0)).expect("query").collect::<rusqlite::Result<Vec<i64>>>().expect("rows")
        };
        assert_eq!(remaining, vec![a, c]);
        assert!(!remaining.contains(&b));
        assert!(!remaining.contains(&d));
    }

    #[test]
    fn cleanup_orphan_users_self_referencing_rule_respects_24h_cutoff() {
        let conn = share_test_conn();

        // A 30-day-old self-referencing orphan — a real dormant account
        // someone signed into once, months ago. The admin merge flow
        // (`POST /api/admin/users/merge`) handles this shape now; boot-time
        // cleanup must leave it in place.
        let old_created_at = (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339();
        let old = super::upsert_user(&conn, "github", "old1", "dormant", None, &old_created_at)
            .expect("seed old");

        // A 5-minute-old self-referencing orphan — the throwaway shape the
        // old device-merge flow left behind seconds after creation. Still
        // swept automatically.
        let recent_created_at = (chrono::Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
        let recent = super::upsert_user(&conn, "github", "new1", "throwaway", None, &recent_created_at)
            .expect("seed recent");

        let cleaned = super::cleanup_orphan_users(&conn).expect("cleanup");
        assert_eq!(cleaned.removed_no_provider, 0);
        assert_eq!(cleaned.removed_recent_self_ref, 1, "the 5-minute-old row should be removed");
        assert_eq!(cleaned.skipped_dormant, 1, "the 30-day-old row should be skipped");

        let remaining: Vec<i64> = {
            let mut stmt = conn.prepare("SELECT id FROM users ORDER BY id").expect("prepare");
            stmt.query_map([], |row| row.get(0)).expect("query").collect::<rusqlite::Result<Vec<i64>>>().expect("rows")
        };
        assert_eq!(remaining, vec![old]);
        assert!(!remaining.contains(&recent));
    }

    #[test]
    fn search_users_reports_dormant() {
        let conn = share_test_conn();
        let now = chrono::Utc::now().to_rfc3339();

        // idle: has a linked provider, never touched any activity table —
        // dormant.
        let _idle = super::upsert_user(&conn, "github", "idle1", "idle", None, &now).expect("seed idle");

        // active: has a linked provider AND a live auth token — not dormant.
        let active = super::upsert_user(&conn, "github", "active1", "active", None, &now).expect("seed active");
        conn.execute(
            "INSERT INTO auth_tokens (token_hash, user_id, created_at) VALUES ('tok-active', ?1, ?2)",
            rusqlite::params![active, now],
        )
        .expect("insert token");

        // stripped: no provider row at all — not dormant (the "has a
        // provider row" half of the predicate fails).
        let stripped = super::upsert_user(&conn, "github", "stripped1", "stripped", None, &now)
            .expect("seed stripped");
        conn.execute("DELETE FROM user_providers WHERE user_id = ?1", rusqlite::params![stripped])
            .expect("strip providers");

        let rows = super::search_users(&conn, "idle").expect("search idle");
        assert_eq!(rows.len(), 1);
        assert!(rows[0].dormant);

        let rows = super::search_users(&conn, "active").expect("search active");
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].dormant);

        let rows = super::search_users(&conn, "stripped").expect("search stripped");
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].dormant);
    }

    // ------------------------------------------------------------------
    // Outreach notifications (owner ruling 2026-09-09)
    // ------------------------------------------------------------------

    #[test]
    fn telegram_recipients_all_and_list_exclude_non_telegram() {
        let conn = share_test_conn();
        let now = chrono::Utc::now().to_rfc3339();

        let alice = super::upsert_user(&conn, "github", "gh-a", "alice", None, &now).expect("seed alice");
        super::link_provider_to_user(&conn, alice, "telegram", "111", "@alice", None, &now)
            .expect("link telegram alice");

        // bob has no telegram identity at all.
        let bob = super::upsert_user(&conn, "discord", "d-b", "bob", None, &now).expect("seed bob");

        let carol = super::upsert_user(&conn, "github", "gh-c", "carol", None, &now).expect("seed carol");
        super::link_provider_to_user(&conn, carol, "telegram", "333", "@carol", None, &now)
            .expect("link telegram carol");

        let all = super::telegram_recipients(&conn, &super::NotifyTarget::All).expect("resolve all");
        let mut all_ids: Vec<i64> = all.iter().map(|r| r.user_id).collect();
        all_ids.sort();
        assert_eq!(all_ids, vec![alice, carol], "bob has no telegram identity, must be excluded");
        let alice_row = all.iter().find(|r| r.user_id == alice).expect("alice row");
        assert_eq!(alice_row.chat_id, 111);

        let list = super::telegram_recipients(&conn, &super::NotifyTarget::Users(vec![alice, bob]))
            .expect("resolve explicit list");
        assert_eq!(list.len(), 1, "bob is in the requested list but has no telegram identity");
        assert_eq!(list[0].user_id, alice);

        let empty = super::telegram_recipients(&conn, &super::NotifyTarget::Users(Vec::new()))
            .expect("resolve empty list");
        assert!(empty.is_empty());
    }

    #[test]
    fn notify_batches_and_log_round_trip() {
        let conn = share_test_conn();
        let now = chrono::Utc::now().to_rfc3339();

        let batch_id = super::insert_notify_batch(&conn, "telegram", "hello", "admin", &now).expect("insert batch");
        super::insert_notify_log(&conn, batch_id, "telegram", 1, true, None, "hash1", &now).expect("log ok");
        super::insert_notify_log(&conn, batch_id, "telegram", 2, false, Some("boom"), "hash1", &now)
            .expect("log fail");

        let batches = super::list_notify_batches(&conn, 50).expect("list");
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].batch_id, batch_id);
        assert_eq!(batches[0].sent, 1);
        assert_eq!(batches[0].failed, 1);
        assert_eq!(batches[0].text, "hello");
        assert_eq!(batches[0].requested_by, "admin");
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

        super::set_nick(&conn, uid, "Al1ce", &[]).expect("set nick");

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

        super::set_nick(&conn, a, "Foo", &[]).expect("first claim");
        match super::set_nick(&conn, b, "foo", &[]) {
            Err(super::NickError::Taken) => {}
            other => panic!("expected Taken, got {other:?}"),
        }
    }

    #[test]
    fn set_nick_rejects_reserved_names_case_insensitively() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "alice", Some("pub-alice"));

        for reserved in ["ZenGeld", "Kosti_X_ItsOK", "KOSTI_ITSOK"] {
            match super::set_nick(&conn, uid, reserved, &[]) {
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
            match super::set_nick(&conn, uid, bad, &[]) {
                Err(super::NickError::Invalid) => {}
                other => panic!("expected Invalid for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn set_nick_rejects_forbidden_nicks() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "alice", Some("pub-alice"));

        for bad in ["hitler1488", "kkk", "pizdec"] {
            match super::set_nick(&conn, uid, bad, &[]) {
                Err(super::NickError::Forbidden) => {}
                other => panic!("expected Forbidden for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn set_nick_rejects_impersonation_of_a_reserved_handle_but_not_a_short_ticker() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "alice", Some("pub-alice"));
        let reserved = vec![
            super::ReservedNickEntry { nick: "binance".to_string(), category: "trading".to_string() },
            super::ReservedNickEntry { nick: "admin".to_string(), category: "roles".to_string() },
        ];

        match super::set_nick(&conn, uid, "binance1", &reserved) {
            Err(super::NickError::Reserved) => {}
            other => panic!("expected Reserved for binance1, got {other:?}"),
        }
        match super::set_nick(&conn, uid, "admin_john", &reserved) {
            Err(super::NickError::Reserved) => {}
            other => panic!("expected Reserved for admin_john, got {other:?}"),
        }
        // Neither "binance" nor "admin" is a prefix of this nick — an
        // ordinary compound on a short ticker must still succeed.
        super::set_nick(&conn, uid, "eth_trader", &reserved).expect("eth_trader is not impersonation");
    }

    #[test]
    fn set_nick_rate_limits_second_change_within_30_days() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "alice", Some("pub-alice"));

        super::set_nick(&conn, uid, "first", &[]).expect("first change");
        match super::set_nick(&conn, uid, "second", &[]) {
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

        super::set_nick(&conn, uid, "first", &[]).expect("first change");
        // Back-date nick_changed_at past the 30-day cooldown.
        let past = (chrono::Utc::now() - chrono::Duration::days(31)).to_rfc3339();
        conn.execute(
            "UPDATE users SET nick_changed_at = ?1 WHERE id = ?2",
            rusqlite::params![past, uid],
        )
        .expect("backdate nick_changed_at");

        super::set_nick(&conn, uid, "second", &[]).expect("change after cooldown");
        assert_eq!(
            super::nick_for_user(&conn, uid).expect("nick").as_deref(),
            Some("second")
        );
    }

    #[test]
    fn share_owner_label_prefers_nick_over_display_name() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "erin", Some("pub-erin"));

        super::set_nick(&conn, uid, "erin_nick", &[]).expect("set nick");

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
        super::set_nick(&conn, named, "franknick", &[]).expect("set nick");
        assert_eq!(
            super::effective_label_for_user(&conn, named).expect("label"),
            "franknick"
        );

        // No such user — empty string, not an error.
        assert_eq!(super::effective_label_for_user(&conn, 99999).expect("label"), "");
    }

    #[test]
    fn user_nick_matches_nick_for_user() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "gina", Some("pub-gina"));

        assert_eq!(super::user_nick(&conn, uid).expect("nick"), None);
        super::set_nick(&conn, uid, "gina_nick", &[]).expect("set nick");
        assert_eq!(
            super::user_nick(&conn, uid).expect("nick").as_deref(),
            Some("gina_nick")
        );
    }

    // ------------------------------------------------------------------
    // Reserved-nick registry (owner ruling 2026-09-09)
    // ------------------------------------------------------------------

    #[test]
    fn parse_reserved_nicks_reads_sections_and_skips_comments_and_bad_lines() {
        let text = "\
# a leading comment
[project]
zengeld
# a comment inside a section

[roles]
admin
bad char!
mod
";
        let (entries, rejected) = super::parse_reserved_nicks(text);
        assert_eq!(
            entries,
            vec![
                super::ReservedNickEntry { nick: "zengeld".to_string(), category: "project".to_string() },
                super::ReservedNickEntry { nick: "admin".to_string(), category: "roles".to_string() },
                super::ReservedNickEntry { nick: "mod".to_string(), category: "roles".to_string() },
            ]
        );
        assert_eq!(rejected, vec!["bad char!".to_string()]);
    }

    #[test]
    fn parse_reserved_nicks_lowercases_and_ignores_blank_lines() {
        let (entries, rejected) = super::parse_reserved_nicks("[Project]\n\nZenGeld\n\n");
        assert_eq!(
            entries,
            vec![super::ReservedNickEntry { nick: "zengeld".to_string(), category: "Project".to_string() }]
        );
        assert!(rejected.is_empty());
    }

    /// The checked-in `reserved_nicks.txt` this crate ships must never
    /// contain a line that fails its own format check — a bad entry would
    /// otherwise be silently dropped at every boot forever.
    #[test]
    fn shipped_reserved_nicks_file_has_no_invalid_entries() {
        let (entries, rejected) = super::parse_reserved_nicks(super::RESERVED_NICKS_TXT);
        assert!(rejected.is_empty(), "invalid entries in reserved_nicks.txt: {rejected:?}");
        assert!(!entries.is_empty());
    }

    #[test]
    fn seed_reserved_nicks_is_idempotent_and_never_touches_an_existing_grant() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "holder", Some("pub-holder"));
        conn.execute(
            "UPDATE reserved_nicks SET granted_to = ?1 WHERE nick_lower = 'zengeld'",
            rusqlite::params![uid],
        )
        .expect("grant zengeld");

        let (seeded_first, rejected) = super::seed_reserved_nicks(&conn).expect("seed");
        assert!(rejected.is_empty());
        // The three names `share_test_conn` pre-seeds are already present —
        // only the file's remaining entries are newly inserted.
        assert!(seeded_first > 0);

        let (seeded_second, _) = super::seed_reserved_nicks(&conn).expect("re-seed");
        assert_eq!(seeded_second, 0, "a second seed pass must insert nothing new");

        let granted: Option<i64> = conn
            .query_row(
                "SELECT granted_to FROM reserved_nicks WHERE nick_lower = 'zengeld'",
                [],
                |row| row.get(0),
            )
            .expect("read grant");
        assert_eq!(granted, Some(uid), "re-seeding must never clear an existing grant");
    }

    #[test]
    fn is_nick_reserved_true_for_seeded_names_false_otherwise() {
        let conn = share_test_conn();
        assert!(super::is_nick_reserved(&conn, "zengeld").expect("check"));
        assert!(super::is_nick_reserved(&conn, "kosti_itsok").expect("check"));
        assert!(!super::is_nick_reserved(&conn, "totally_free_nick").expect("check"));
    }

    #[test]
    fn set_nick_releases_grant_when_holder_moves_away() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "holder", Some("pub-holder"));
        super::admin_set_nick(&conn, uid, "zengeld").expect("admin grant");
        assert_eq!(
            conn.query_row::<Option<i64>, _, _>(
                "SELECT granted_to FROM reserved_nicks WHERE nick_lower = 'zengeld'",
                [],
                |row| row.get(0),
            )
            .expect("read grant"),
            Some(uid)
        );

        // Self-service move to a non-reserved nick must free the grant.
        let past = (chrono::Utc::now() - chrono::Duration::days(31)).to_rfc3339();
        conn.execute(
            "UPDATE users SET nick_changed_at = ?1 WHERE id = ?2",
            rusqlite::params![past, uid],
        )
        .expect("backdate nick_changed_at");
        super::set_nick(&conn, uid, "freeform_nick", &[]).expect("move away");

        assert_eq!(
            conn.query_row::<Option<i64>, _, _>(
                "SELECT granted_to FROM reserved_nicks WHERE nick_lower = 'zengeld'",
                [],
                |row| row.get(0),
            )
            .expect("read grant"),
            None,
            "moving away from a granted reserved nick must clear its grant"
        );
    }

    #[test]
    fn set_nick_never_lets_self_service_claim_a_reserved_nick() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "alice", Some("pub-alice"));
        match super::set_nick(&conn, uid, "zengeld", &[]) {
            Err(super::NickError::Reserved) => {}
            other => panic!("expected Reserved, got {other:?}"),
        }
    }

    #[test]
    fn admin_set_nick_bypasses_reserved_list_and_cooldown() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "alice", Some("pub-alice"));

        let reserved = super::admin_set_nick(&conn, uid, "zengeld").expect("admin set");
        assert!(reserved);
        assert_eq!(super::nick_for_user(&conn, uid).expect("nick").as_deref(), Some("zengeld"));

        // Immediately setting again (well within the 30-day cooldown) must
        // still succeed — the admin route is not bound by it.
        let reserved2 = super::admin_set_nick(&conn, uid, "kosti_itsok").expect("admin set again");
        assert!(reserved2);
    }

    #[test]
    fn admin_set_nick_rejects_bad_format_taken_and_missing_user() {
        let conn = share_test_conn();
        let a = insert_share_user(&conn, "alice", Some("pub-alice"));
        let b = insert_share_user(&conn, "bob", Some("pub-bob"));
        super::set_nick(&conn, a, "alicenick", &[]).expect("set nick");

        match super::admin_set_nick(&conn, b, "al") {
            Err(super::AdminNickError::Invalid) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
        match super::admin_set_nick(&conn, b, "alicenick") {
            Err(super::AdminNickError::Taken) => {}
            other => panic!("expected Taken, got {other:?}"),
        }
        match super::admin_set_nick(&conn, 99999, "nobodys_nick") {
            Err(super::AdminNickError::NoSuchUser) => {}
            other => panic!("expected NoSuchUser, got {other:?}"),
        }
    }

    #[test]
    fn upsert_reserved_nick_creates_then_updates_in_place() {
        let conn = share_test_conn();

        let created = super::upsert_reserved_nick(&conn, "brandnew", "brands", Some("first note")).expect("insert");
        assert!(created);
        let rows = super::list_reserved_nicks(&conn).expect("list");
        let row = rows.iter().find(|r| r.nick == "brandnew").expect("row present");
        assert_eq!(row.category, "brands");
        assert_eq!(row.note.as_deref(), Some("first note"));

        let created_again =
            super::upsert_reserved_nick(&conn, "BrandNew", "trading", Some("second note")).expect("update");
        assert!(!created_again, "an existing row must be updated, not re-created");
        let rows = super::list_reserved_nicks(&conn).expect("list");
        let row = rows.iter().find(|r| r.nick == "brandnew").expect("row present");
        assert_eq!(row.category, "trading");
        assert_eq!(row.note.as_deref(), Some("second note"));
    }

    #[test]
    fn upsert_reserved_nick_rejects_bad_format() {
        let conn = share_test_conn();
        match super::upsert_reserved_nick(&conn, "ab", "brands", None) {
            Err(super::ReservedNickError::Invalid) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn delete_reserved_nick_removes_existing_and_reports_missing() {
        let conn = share_test_conn();
        assert!(super::delete_reserved_nick(&conn, "zengeld").expect("delete"));
        assert!(!super::is_nick_reserved(&conn, "zengeld").expect("check"));
        assert!(!super::delete_reserved_nick(&conn, "zengeld").expect("delete again"));
        assert!(!super::delete_reserved_nick(&conn, "never_was_reserved").expect("delete missing"));
    }

    #[test]
    fn list_reserved_nicks_sorted_by_category_then_nick() {
        let conn = share_test_conn();
        let rows = super::list_reserved_nicks(&conn).expect("list");
        let pairs: Vec<(&str, &str)> = rows.iter().map(|r| (r.category.as_str(), r.nick.as_str())).collect();
        let mut sorted = pairs.clone();
        sorted.sort();
        assert_eq!(pairs, sorted);
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
    fn upsert_post_rejects_fields_over_their_length_ceiling() {
        let conn = posts_test_conn();
        let now = "2026-09-01T00:00:00+00:00";

        let mut bad_title = sample_post("v1", "patch", "2026-09-01", "public");
        bad_title.title = "a".repeat(super::MAX_POST_TITLE_CHARS + 1);
        assert!(matches!(
            super::upsert_post(&conn, &bad_title, now),
            Err(super::PostError::TitleTooLong)
        ));

        let mut bad_summary = sample_post("v2", "patch", "2026-09-01", "public");
        bad_summary.summary = "a".repeat(super::MAX_POST_SUMMARY_CHARS + 1);
        assert!(matches!(
            super::upsert_post(&conn, &bad_summary, now),
            Err(super::PostError::SummaryTooLong)
        ));

        let mut bad_body = sample_post("v3", "patch", "2026-09-01", "public");
        bad_body.body = "a".repeat(super::MAX_POST_BODY_CHARS + 1);
        assert!(matches!(
            super::upsert_post(&conn, &bad_body, now),
            Err(super::PostError::BodyTooLong)
        ));

        // Exactly at the ceiling still passes.
        let mut ok_title = sample_post("v4", "patch", "2026-09-01", "public");
        ok_title.title = "a".repeat(super::MAX_POST_TITLE_CHARS);
        assert!(super::upsert_post(&conn, &ok_title, now).is_ok());
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

    // ------------------------------------------------------------------
    // Forum
    // ------------------------------------------------------------------

    #[test]
    fn forum_validation_boundaries() {
        assert!(super::is_valid_forum_title("abc"));
        assert!(super::is_valid_forum_title(&"a".repeat(120)));
        assert!(!super::is_valid_forum_title("ab"));
        assert!(!super::is_valid_forum_title(&"a".repeat(121)));

        assert!(super::is_valid_forum_body("a"));
        assert!(super::is_valid_forum_body(&"a".repeat(8192)));
        assert!(!super::is_valid_forum_body(""));
        assert!(!super::is_valid_forum_body(&"a".repeat(8193)));
    }

    #[test]
    fn create_thread_rejects_invalid_title_and_body() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "jack", Some("pub-jack"));
        let now = chrono::Utc::now().to_rfc3339();

        assert!(matches!(
            super::create_thread(&conn, uid, "ab", "body", &now),
            Err(super::ForumError::InvalidTitle)
        ));
        assert!(matches!(
            super::create_thread(&conn, uid, "a valid title", "", &now),
            Err(super::ForumError::InvalidBody)
        ));
        assert!(super::list_threads(&conn, 50, None).expect("list").is_empty());
    }

    #[test]
    fn create_reply_rejects_invalid_body() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "kate", Some("pub-kate"));
        let now = chrono::Utc::now().to_rfc3339();
        let thread_id = super::create_thread(&conn, uid, "a valid title", "body", &now).expect("create");

        assert!(matches!(
            super::create_reply(&conn, thread_id, uid, "", &now),
            Err(super::ForumError::InvalidBody)
        ));
        assert!(super::list_replies(&conn, thread_id).expect("list").is_empty());
    }

    #[test]
    fn create_reply_bumps_thread_count_and_last_activity() {
        let conn = share_test_conn();
        let author = insert_share_user(&conn, "leo", Some("pub-leo"));
        let replier = insert_share_user(&conn, "mia", Some("pub-mia"));
        let created = "2026-09-01T00:00:00+00:00";
        let thread_id =
            super::create_thread(&conn, author, "a valid title", "body", created).expect("create");

        let before = super::get_thread(&conn, thread_id).expect("get").expect("row");
        assert_eq!(before.reply_count, 0);
        assert_eq!(before.last_reply_at, None);

        let replied_at = "2026-09-02T00:00:00+00:00";
        super::create_reply(&conn, thread_id, replier, "first reply", replied_at).expect("reply");

        let after = super::get_thread(&conn, thread_id).expect("get").expect("row");
        assert_eq!(after.reply_count, 1);
        assert_eq!(after.last_reply_at.as_deref(), Some(replied_at));
        assert_eq!(after.updated_at, replied_at);

        let replies = super::list_replies(&conn, thread_id).expect("list");
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].author_user_id, replier);
        assert_eq!(replies[0].body, "first reply");
    }

    #[test]
    fn list_replies_returns_visible_rows_oldest_first() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "nina", Some("pub-nina"));
        let now = chrono::Utc::now().to_rfc3339();
        let thread_id = super::create_thread(&conn, uid, "a valid title", "body", &now).expect("create");

        super::create_reply(&conn, thread_id, uid, "one", "2026-09-01T00:00:00+00:00").expect("r1");
        let hidden_id =
            super::create_reply(&conn, thread_id, uid, "two", "2026-09-02T00:00:00+00:00").expect("r2");
        super::create_reply(&conn, thread_id, uid, "three", "2026-09-03T00:00:00+00:00").expect("r3");

        assert!(super::hide_reply(&conn, hidden_id, Some(uid)).expect("hide"));

        let visible = super::list_replies(&conn, thread_id).expect("list");
        let bodies: Vec<&str> = visible.iter().map(|r| r.body.as_str()).collect();
        assert_eq!(bodies, vec!["one", "three"]);
    }

    #[test]
    fn list_threads_orders_by_last_activity_and_paginates() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "oscar", Some("pub-oscar"));

        // t1: created early, never replied to — sorts by created_at.
        let t1 = super::create_thread(&conn, uid, "thread one", "body", "2026-09-01T00:00:00+00:00")
            .expect("t1");
        // t2: created after t1 but replied to even later — sorts by last_reply_at.
        let t2 = super::create_thread(&conn, uid, "thread two", "body", "2026-09-02T00:00:00+00:00")
            .expect("t2");
        // t3: created after both, no replies.
        let t3 = super::create_thread(&conn, uid, "thread three", "body", "2026-09-03T00:00:00+00:00")
            .expect("t3");
        super::create_reply(&conn, t2, uid, "bump", "2026-09-10T00:00:00+00:00").expect("reply");

        // Newest activity first: t2 (bumped to 09-10) > t3 (created 09-03) > t1 (created 09-01).
        let all = super::list_threads(&conn, 50, None).expect("list");
        let ids: Vec<i64> = all.iter().map(|t| t.id).collect();
        assert_eq!(ids, vec![t2, t3, t1]);

        // Pagination: page of 2, then the remainder via the cursor.
        let page1 = super::list_threads(&conn, 2, None).expect("page1");
        let page1_ids: Vec<i64> = page1.iter().map(|t| t.id).collect();
        assert_eq!(page1_ids, vec![t2, t3]);

        let cursor_thread = page1.last().expect("last of page1");
        let cursor_activity = cursor_thread
            .last_reply_at
            .clone()
            .unwrap_or_else(|| cursor_thread.created_at.clone());
        let page2 = super::list_threads(&conn, 2, Some((&cursor_activity, cursor_thread.id)))
            .expect("page2");
        let page2_ids: Vec<i64> = page2.iter().map(|t| t.id).collect();
        assert_eq!(page2_ids, vec![t1]);
    }

    #[test]
    fn hide_thread_is_owner_only_unless_admin() {
        let conn = share_test_conn();
        let owner = insert_share_user(&conn, "paul", Some("pub-paul"));
        let other = insert_share_user(&conn, "quinn", Some("pub-quinn"));
        let now = chrono::Utc::now().to_rfc3339();
        let thread_id = super::create_thread(&conn, owner, "a valid title", "body", &now).expect("create");

        // Not the owner — refused, thread stays visible.
        assert!(!super::hide_thread(&conn, thread_id, Some(other)).expect("hide"));
        assert!(super::get_thread(&conn, thread_id).expect("get").is_some());

        // The owner hides their own thread.
        assert!(super::hide_thread(&conn, thread_id, Some(owner)).expect("hide"));
        assert!(super::get_thread(&conn, thread_id).expect("get").is_none());

        // Hiding an already-hidden thread is not a fresh success either.
        assert!(!super::hide_thread(&conn, thread_id, Some(owner)).expect("hide again"));

        // The admin path (None) hides unconditionally — exercised on a fresh thread.
        let thread2 = super::create_thread(&conn, owner, "another title", "body", &now).expect("create");
        assert!(super::hide_thread(&conn, thread2, None).expect("admin hide"));
        assert!(super::get_thread(&conn, thread2).expect("get").is_none());
    }

    #[test]
    fn hide_reply_is_owner_only_unless_admin() {
        let conn = share_test_conn();
        let owner = insert_share_user(&conn, "rex", Some("pub-rex"));
        let other = insert_share_user(&conn, "sam", Some("pub-sam"));
        let now = chrono::Utc::now().to_rfc3339();
        let thread_id = super::create_thread(&conn, owner, "a valid title", "body", &now).expect("create");
        let reply_id = super::create_reply(&conn, thread_id, owner, "reply body", &now).expect("reply");

        assert!(!super::hide_reply(&conn, reply_id, Some(other)).expect("hide"));
        assert!(super::hide_reply(&conn, reply_id, Some(owner)).expect("hide"));
        assert_eq!(super::list_replies(&conn, thread_id).expect("list").len(), 0);

        let reply2 = super::create_reply(&conn, thread_id, owner, "reply two", &now).expect("reply2");
        assert!(super::hide_reply(&conn, reply2, None).expect("admin hide"));
        assert_eq!(super::list_replies(&conn, thread_id).expect("list").len(), 0);
    }

    #[test]
    fn threads_and_replies_created_since_count_only_the_window() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "tara", Some("pub-tara"));

        super::create_thread(&conn, uid, "old thread", "body", "2026-09-01T00:00:00+00:00")
            .expect("old");
        super::create_thread(&conn, uid, "new thread", "body", "2026-09-05T00:00:30+00:00")
            .expect("new");

        let since = "2026-09-05T00:00:00+00:00";
        assert_eq!(
            super::threads_created_since(&conn, uid, since).expect("count"),
            1
        );

        let thread_id = super::create_thread(&conn, uid, "reply target", "body", since).expect("t");
        for i in 0..3 {
            super::create_reply(
                &conn,
                thread_id,
                uid,
                "r",
                &format!("2026-09-05T00:0{}:00+00:00", i),
            )
            .expect("reply");
        }
        assert_eq!(
            super::replies_created_since(&conn, uid, "2026-09-05T00:01:00+00:00").expect("count"),
            1
        );
    }

    #[test]
    fn forum_author_label_falls_back_to_deleted_user() {
        let conn = share_test_conn();
        assert_eq!(
            super::forum_author_label(&conn, 424242).expect("label"),
            "deleted user"
        );
        let uid = insert_share_user(&conn, "uma", Some("pub-uma"));
        assert_eq!(super::forum_author_label(&conn, uid).expect("label"), "uma");
    }

    // ---- Shared presets (rooms) — Phase 1 ----
    // (docs/mlc/plans/shared-presets-rights-and-live-sync-2026-09-23.md §8)

    /// `share_test_conn`'s users/share_links schema, plus `object_grants`,
    /// `shared_presets`, `shared_preset_entities` — the three tables Phase 1
    /// adds. Same `PRAGMA foreign_keys=ON` discipline: a wrong FK (e.g. a
    /// `shared_preset_entities.updated_by` naming no user) fails the same
    /// way it would in production instead of silently passing in-memory —
    /// exercised on purpose by
    /// `apply_room_patch_db_error_rolls_back_whole_batch`. `object_grants`
    /// carries `grantee_group_id` (a bare column, no FK — this fixture never
    /// creates `grant_groups`) only so `list_object_grants`'s widened SELECT
    /// (chart-share policy v1 Rev 2, §8.2) matches this table's shape too;
    /// rooms' own tests still never populate it.
    fn rooms_test_conn() -> Connection {
        let conn = share_test_conn();
        conn.execute_batch(
            "
            CREATE TABLE object_grants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                object_kind TEXT NOT NULL,
                object_id TEXT NOT NULL,
                owner_user_id INTEGER NOT NULL REFERENCES users(id),
                grantee_user_id INTEGER REFERENCES users(id),
                grantee_group_id INTEGER,
                right TEXT NOT NULL,
                expires_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE shared_presets (
                object_id     TEXT    PRIMARY KEY,
                owner_user_id INTEGER NOT NULL REFERENCES users(id),
                title         TEXT    NOT NULL DEFAULT '',
                visibility    TEXT    NOT NULL DEFAULT 'private',
                seq           INTEGER NOT NULL DEFAULT 0,
                created_at    TEXT    NOT NULL,
                updated_at    TEXT    NOT NULL
            );

            CREATE TABLE shared_preset_entities (
                room_id     TEXT    NOT NULL REFERENCES shared_presets(object_id),
                kind        TEXT    NOT NULL,
                -- Test-only trap for apply_room_patch_db_error_rolls_back_
                -- the_whole_batch: every legitimate write an AUTHORIZED
                -- caller can make already satisfies every real FK/PRIMARY
                -- KEY constraint by construction (the rights gate itself
                -- already refuses an unauthorized caller before any write is
                -- attempted), so there is no naturally occurring DB error to
                -- provoke from valid inputs alone. This CHECK is the
                -- deliberate, narrow exception that lets one test prove the
                -- transaction actually rolls back on a genuine backend
                -- error, without weakening any real constraint.
                entity_id   TEXT    NOT NULL CHECK (entity_id != 'FORCE_DB_ERROR'),
                version     INTEGER NOT NULL DEFAULT 1,
                updated_by  INTEGER NOT NULL REFERENCES users(id),
                updated_at  TEXT    NOT NULL,
                json        TEXT,
                deleted     INTEGER NOT NULL DEFAULT 0,
                seq         INTEGER NOT NULL,
                parent_kind TEXT,
                parent_id   TEXT,
                PRIMARY KEY (room_id, kind, entity_id)
            );
            CREATE INDEX idx_shared_preset_entities_room_seq ON shared_preset_entities(room_id, seq);
            CREATE INDEX idx_shared_preset_entities_parent ON shared_preset_entities(room_id, parent_kind, parent_id);
            ",
        )
        .expect("rooms test schema");
        conn
    }

    fn upsert_op(kind: &str, id: &str, base_version: i64, json: serde_json::Value) -> super::RoomOp {
        super::RoomOp {
            kind: kind.to_string(),
            id: id.to_string(),
            action: super::RoomOpAction::Upsert,
            base_version,
            json: Some(json),
            parent_kind: None,
            parent_id: None,
        }
    }

    fn primitive_upsert_op(id: &str, base_version: i64, parent_kind: &str, parent_id: &str) -> super::RoomOp {
        super::RoomOp {
            kind: "primitive".to_string(),
            id: id.to_string(),
            action: super::RoomOpAction::Upsert,
            base_version,
            json: Some(serde_json::json!({ "collection": "drawings" })),
            parent_kind: Some(parent_kind.to_string()),
            parent_id: Some(parent_id.to_string()),
        }
    }

    fn delete_op(kind: &str, id: &str, base_version: i64) -> super::RoomOp {
        super::RoomOp {
            kind: kind.to_string(),
            id: id.to_string(),
            action: super::RoomOpAction::Delete,
            base_version,
            json: None,
            parent_kind: None,
            parent_id: None,
        }
    }

    #[test]
    fn object_grant_upsert_list_count_and_revoke_roundtrip() {
        let conn = rooms_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let grantee = insert_share_user(&conn, "grantee", Some("pub-grantee"));
        let now = chrono::Utc::now().to_rfc3339();

        let id = super::upsert_object_grant(&conn, "preset", "room-1", owner, Some(grantee), "view", None, &now)
            .expect("upsert");
        assert_eq!(super::count_object_grants(&conn, "preset", "room-1").expect("count"), 1);

        // Re-granting the SAME (kind, object_id, grantee, right) refreshes in
        // place rather than creating a duplicate row.
        let id2 = super::upsert_object_grant(&conn, "preset", "room-1", owner, Some(grantee), "view", None, &now)
            .expect("upsert again");
        assert_eq!(id, id2);
        assert_eq!(super::count_object_grants(&conn, "preset", "room-1").expect("count"), 1);

        let rows = super::list_object_grants(&conn, "preset", "room-1").expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].grantee_user_id, Some(grantee));

        // Revoke by a non-owner is refused.
        assert!(!super::revoke_object_grant(&conn, id, grantee).expect("revoke"));
        assert!(super::revoke_object_grant(&conn, id, owner).expect("revoke"));
        assert_eq!(super::count_object_grants(&conn, "preset", "room-1").expect("count"), 0);
    }

    #[test]
    fn effective_object_rights_owner_always_holds_every_right() {
        let conn = rooms_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let rights = super::effective_object_rights(&conn, "preset", "room-1", owner, Some(owner)).expect("rights");
        assert_eq!(rights, vec!["view", "clone", "edit"]);
    }

    #[test]
    fn effective_object_rights_non_grantee_holds_nothing() {
        let conn = rooms_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let stranger = insert_share_user(&conn, "stranger", Some("pub-stranger"));
        let rights =
            super::effective_object_rights(&conn, "preset", "room-1", owner, Some(stranger)).expect("rights");
        assert!(rights.is_empty());
    }

    #[test]
    fn effective_object_rights_reads_a_live_view_grant() {
        let conn = rooms_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let grantee = insert_share_user(&conn, "grantee", Some("pub-grantee"));
        let now = chrono::Utc::now().to_rfc3339();
        super::upsert_object_grant(&conn, "preset", "room-1", owner, Some(grantee), "view", None, &now)
            .expect("grant");

        let rights =
            super::effective_object_rights(&conn, "preset", "room-1", owner, Some(grantee)).expect("rights");
        assert_eq!(rights, vec!["view"]);
    }

    #[test]
    fn effective_object_rights_ignores_an_expired_grant() {
        let conn = rooms_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let grantee = insert_share_user(&conn, "grantee", Some("pub-grantee"));
        let now = chrono::Utc::now().to_rfc3339();
        super::upsert_object_grant(&conn, "preset", "room-1", owner, Some(grantee), "edit", Some(&past_ts()), &now)
            .expect("grant");

        let rights =
            super::effective_object_rights(&conn, "preset", "room-1", owner, Some(grantee)).expect("rights");
        assert!(rights.is_empty());
    }

    #[test]
    fn effective_object_rights_public_grant_applies_to_any_caller_including_anonymous() {
        let conn = rooms_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let visitor = insert_share_user(&conn, "visitor", Some("pub-visitor"));
        let now = chrono::Utc::now().to_rfc3339();
        // grantee_user_id = None — "anyone with the link".
        super::upsert_object_grant(&conn, "preset", "room-1", owner, None, "view", None, &now).expect("grant");
        super::upsert_object_grant(&conn, "preset", "room-1", owner, None, "clone", None, &now).expect("grant");

        let anon_rights = super::effective_object_rights(&conn, "preset", "room-1", owner, None).expect("rights");
        assert_eq!(anon_rights, vec!["view", "clone"]);

        let visitor_rights =
            super::effective_object_rights(&conn, "preset", "room-1", owner, Some(visitor)).expect("rights");
        assert_eq!(visitor_rights, vec!["view", "clone"]);
    }

    #[test]
    fn apply_room_patch_fresh_create_batch_applies_windows_bubbles_and_primitives_together() {
        let mut conn = rooms_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let now = chrono::Utc::now().to_rfc3339();

        let ops = vec![
            upsert_op("window", "10", 0, serde_json::json!({ "window_id": 10 })),
            upsert_op("bubble", "20", 0, serde_json::json!({ "id": 20 })),
            primitive_upsert_op("101", 0, "window", "10"),
        ];
        let (seq, results, cascades) =
            super::apply_room_patch(&mut conn, "preset", "room-1", owner, &now, &ops, true).expect("apply");

        assert_eq!(seq, 3);
        assert!(cascades.is_empty());
        assert_eq!(results.len(), 3);
        for (_, outcome) in &results {
            assert!(matches!(outcome, super::RoomOpOutcome::Applied { .. }), "expected Applied, got {outcome:?}");
        }

        let header = super::get_shared_preset(&conn, "room-1").expect("header").expect("row");
        assert_eq!(header.owner_user_id, owner);
        assert_eq!(header.seq, 3);
    }

    #[test]
    fn apply_room_patch_two_editors_drawing_on_the_same_window_both_applied_window_untouched() {
        let mut conn = rooms_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let editor = insert_share_user(&conn, "editor", Some("pub-editor"));
        let now = chrono::Utc::now().to_rfc3339();
        super::upsert_object_grant(&conn, "preset", "room-1", owner, Some(editor), "edit", None, &now)
            .expect("grant");

        // Room + window created by the owner first.
        let create_ops = vec![upsert_op("window", "10", 0, serde_json::json!({ "window_id": 10 }))];
        super::apply_room_patch(&mut conn, "preset", "room-1", owner, &now, &create_ops, true).expect("create");

        // Two editors independently draw a DIFFERENT primitive on the SAME
        // window, each in their own patch batch (the concrete scenario this
        // design exists for — see rooms_codec's module doc).
        let owner_ops = vec![primitive_upsert_op("101", 0, "window", "10")];
        let (_, owner_results, _) =
            super::apply_room_patch(&mut conn, "preset", "room-1", owner, &now, &owner_ops, false).expect("owner draw");
        let editor_ops = vec![primitive_upsert_op("102", 0, "window", "10")];
        let (_, editor_results, _) = super::apply_room_patch(&mut conn, "preset", "room-1", editor, &now, &editor_ops, false)
            .expect("editor draw");

        assert!(matches!(owner_results[0].1, super::RoomOpOutcome::Applied { .. }));
        assert!(matches!(editor_results[0].1, super::RoomOpOutcome::Applied { .. }));

        // The window entity itself was never touched by either draw — still
        // version 1, exactly as `create_ops` left it.
        let window_version: i64 = conn
            .query_row(
                "SELECT version FROM shared_preset_entities WHERE room_id='room-1' AND kind='window' AND entity_id='10'",
                [],
                |row| row.get(0),
            )
            .expect("window version");
        assert_eq!(window_version, 1);
    }

    #[test]
    fn apply_room_patch_two_edits_to_the_same_primitive_the_second_is_stale() {
        let mut conn = rooms_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let now = chrono::Utc::now().to_rfc3339();
        let create_ops = vec![primitive_upsert_op("101", 0, "window", "10")];
        super::apply_room_patch(&mut conn, "preset", "room-1", owner, &now, &create_ops, true).expect("create");

        // Two ops in the SAME batch, both computed against version 1 — the
        // second to actually apply within the transaction loses.
        let ops = vec![
            upsert_op("primitive", "101", 1, serde_json::json!({ "collection": "drawings", "x": 1 })),
            upsert_op("primitive", "101", 1, serde_json::json!({ "collection": "drawings", "x": 2 })),
        ];
        let (_, results, _) =
            super::apply_room_patch(&mut conn, "preset", "room-1", owner, &now, &ops, false).expect("apply");

        assert!(matches!(results[0].1, super::RoomOpOutcome::Applied { version: 2, .. }));
        match &results[1].1 {
            super::RoomOpOutcome::Stale { current_version, .. } => assert_eq!(*current_version, 2),
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[test]
    fn apply_room_patch_concurrent_create_of_the_same_new_entity_one_applied_one_stale() {
        let mut conn = rooms_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let now = chrono::Utc::now().to_rfc3339();

        let ops = vec![
            upsert_op("indicator", "30", 0, serde_json::json!({ "id": 30, "variant": "a" })),
            upsert_op("indicator", "30", 0, serde_json::json!({ "id": 30, "variant": "b" })),
        ];
        let (_, results, _) =
            super::apply_room_patch(&mut conn, "preset", "room-1", owner, &now, &ops, true).expect("apply");

        assert!(matches!(results[0].1, super::RoomOpOutcome::Applied { version: 1, .. }));
        assert!(matches!(results[1].1, super::RoomOpOutcome::Stale { .. }));
    }

    #[test]
    fn apply_room_patch_deleting_a_window_cascades_to_its_primitives() {
        let mut conn = rooms_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let now = chrono::Utc::now().to_rfc3339();
        let create_ops = vec![
            upsert_op("window", "10", 0, serde_json::json!({ "window_id": 10 })),
            primitive_upsert_op("101", 0, "window", "10"),
            primitive_upsert_op("102", 0, "window", "10"),
        ];
        let (seq_after_create, _, _) =
            super::apply_room_patch(&mut conn, "preset", "room-1", owner, &now, &create_ops, true).expect("create");
        assert_eq!(seq_after_create, 3);

        let delete_ops = vec![delete_op("window", "10", 1)];
        let (seq_after_delete, results, cascades) =
            super::apply_room_patch(&mut conn, "preset", "room-1", owner, &now, &delete_ops, false).expect("delete");

        assert!(matches!(results[0].1, super::RoomOpOutcome::Applied { .. }));
        assert_eq!(cascades.len(), 2, "both primitives parented to the deleted window are tombstoned");
        let cascaded_ids: std::collections::BTreeSet<&str> = cascades.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(cascaded_ids, std::collections::BTreeSet::from(["101", "102"]));
        for (_, outcome) in &cascades {
            assert!(matches!(outcome, super::RoomOpOutcome::Applied { version: 2, .. }));
        }
        // One seq for the window delete + one each for the two cascaded
        // tombstones — every cascaded row is a real applied write.
        assert_eq!(seq_after_delete, seq_after_create + 3);

        let live_primitives: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM shared_preset_entities WHERE room_id='room-1' AND kind='primitive' AND deleted=0",
                [],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(live_primitives, 0);
    }

    #[test]
    fn apply_room_patch_seq_only_advances_on_applied_never_on_stale_or_gone() {
        let mut conn = rooms_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let now = chrono::Utc::now().to_rfc3339();
        let create_ops = vec![upsert_op("indicator", "30", 0, serde_json::json!({ "id": 30 }))];
        let (seq0, _, _) =
            super::apply_room_patch(&mut conn, "preset", "room-1", owner, &now, &create_ops, true).expect("create");
        assert_eq!(seq0, 1);

        let ops = vec![
            upsert_op("indicator", "30", 1, serde_json::json!({ "id": 30, "changed": true })), // Applied
            upsert_op("indicator", "30", 1, serde_json::json!({ "id": 30, "loses": true })),   // Stale (now v2)
            delete_op("indicator", "999", 5),                                                 // Gone (never existed)
        ];
        let (seq1, results, _) =
            super::apply_room_patch(&mut conn, "preset", "room-1", owner, &now, &ops, false).expect("apply");

        assert!(matches!(results[0].1, super::RoomOpOutcome::Applied { .. }));
        assert!(matches!(results[1].1, super::RoomOpOutcome::Stale { .. }));
        assert!(matches!(results[2].1, super::RoomOpOutcome::Gone));
        // Only ONE of the three ops actually applied.
        assert_eq!(seq1, seq0 + 1);
    }

    #[test]
    fn apply_room_patch_db_error_rolls_back_the_whole_batch() {
        let mut conn = rooms_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let now = chrono::Utc::now().to_rfc3339();
        let create_ops = vec![upsert_op("indicator", "30", 0, serde_json::json!({ "id": 30 }))];
        super::apply_room_patch(&mut conn, "preset", "room-1", owner, &now, &create_ops, true).expect("create");
        let seq_before = super::get_shared_preset(&conn, "room-1").expect("header").expect("row").seq;

        // The owner is fully authorized (implicit edit) — every FK/PRIMARY
        // KEY constraint a real caller can hit is already satisfied by
        // construction once the rights gate passes, so there is no
        // naturally occurring DB error to provoke here. `entity_id =
        // "FORCE_DB_ERROR"` trips the test-only CHECK constraint
        // `rooms_test_conn` adds for exactly this purpose (see its doc
        // comment) — a real backend error, not a per-op outcome. A second,
        // otherwise unrelated op rides in the same batch to prove NEITHER
        // lands.
        let ops = vec![
            upsert_op("indicator", "30", 1, serde_json::json!({ "id": 30, "changed": true })),
            upsert_op("alert", "FORCE_DB_ERROR", 0, serde_json::json!({ "id": 999 })),
        ];
        let result = super::apply_room_patch(&mut conn, "preset", "room-1", owner, &now, &ops, false);
        assert!(result.is_err(), "a genuine backend error must surface as Err, not a per-op outcome");

        // Nothing committed: the indicator is still at version 1 and the new
        // alert entity was never created.
        let indicator_version: i64 = conn
            .query_row(
                "SELECT version FROM shared_preset_entities WHERE room_id='room-1' AND kind='indicator' AND entity_id='30'",
                [],
                |row| row.get(0),
            )
            .expect("indicator version");
        assert_eq!(indicator_version, 1);
        let alert_exists: i64 = conn
            .query_row("SELECT COUNT(*) FROM shared_preset_entities WHERE room_id='room-1' AND kind='alert'", [], |row| {
                row.get(0)
            })
            .expect("alert count");
        assert_eq!(alert_exists, 0);
        let seq_after = super::get_shared_preset(&conn, "room-1").expect("header").expect("row").seq;
        assert_eq!(seq_after, seq_before, "seq must not advance on a rolled-back batch");
    }

    #[test]
    fn apply_room_patch_view_only_grantee_cannot_patch() {
        let mut conn = rooms_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let viewer = insert_share_user(&conn, "viewer", Some("pub-viewer"));
        let now = chrono::Utc::now().to_rfc3339();
        let create_ops = vec![upsert_op("indicator", "30", 0, serde_json::json!({ "id": 30 }))];
        super::apply_room_patch(&mut conn, "preset", "room-1", owner, &now, &create_ops, true).expect("create");
        super::upsert_object_grant(&conn, "preset", "room-1", owner, Some(viewer), "view", None, &now)
            .expect("grant");

        let ops = vec![upsert_op("indicator", "31", 0, serde_json::json!({ "id": 31 }))];
        let (_, results, _) =
            super::apply_room_patch(&mut conn, "preset", "room-1", viewer, &now, &ops, false).expect("apply");
        assert!(matches!(results[0].1, super::RoomOpOutcome::Forbidden));

        // Nothing was written.
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM shared_preset_entities WHERE room_id='room-1' AND kind='indicator' AND entity_id='31'",
                [],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(exists, 0);
    }

    #[test]
    fn apply_room_patch_expired_edit_grant_is_denied() {
        let mut conn = rooms_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let editor = insert_share_user(&conn, "editor", Some("pub-editor"));
        let now = chrono::Utc::now().to_rfc3339();
        let create_ops = vec![upsert_op("indicator", "30", 0, serde_json::json!({ "id": 30 }))];
        super::apply_room_patch(&mut conn, "preset", "room-1", owner, &now, &create_ops, true).expect("create");
        super::upsert_object_grant(&conn, "preset", "room-1", owner, Some(editor), "edit", Some(&past_ts()), &now)
            .expect("grant");

        let ops = vec![upsert_op("indicator", "31", 0, serde_json::json!({ "id": 31 }))];
        let (_, results, _) =
            super::apply_room_patch(&mut conn, "preset", "room-1", editor, &now, &ops, false).expect("apply");
        assert!(matches!(results[0].1, super::RoomOpOutcome::Forbidden));
    }

    #[test]
    fn apply_room_patch_revoked_edit_grant_is_denied() {
        let mut conn = rooms_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let editor = insert_share_user(&conn, "editor", Some("pub-editor"));
        let now = chrono::Utc::now().to_rfc3339();
        let create_ops = vec![upsert_op("indicator", "30", 0, serde_json::json!({ "id": 30 }))];
        super::apply_room_patch(&mut conn, "preset", "room-1", owner, &now, &create_ops, true).expect("create");
        let grant_id = super::upsert_object_grant(&conn, "preset", "room-1", owner, Some(editor), "edit", None, &now)
            .expect("grant");

        // Confirm the grant works before revoking it.
        let probe_ops = vec![upsert_op("indicator", "31", 0, serde_json::json!({ "id": 31 }))];
        let (_, probe_results, _) =
            super::apply_room_patch(&mut conn, "preset", "room-1", editor, &now, &probe_ops, false).expect("apply");
        assert!(matches!(probe_results[0].1, super::RoomOpOutcome::Applied { .. }));

        assert!(super::revoke_object_grant(&conn, grant_id, owner).expect("revoke"));

        let ops = vec![upsert_op("indicator", "32", 0, serde_json::json!({ "id": 32 }))];
        let (_, results, _) =
            super::apply_room_patch(&mut conn, "preset", "room-1", editor, &now, &ops, false).expect("apply");
        assert!(matches!(results[0].1, super::RoomOpOutcome::Forbidden));
    }

    #[test]
    fn apply_room_patch_link_grant_gives_view_and_clone_but_never_edit_for_an_anonymous_visitor() {
        let conn = rooms_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let now = chrono::Utc::now().to_rfc3339();
        // "Anyone with the link" — grantee_user_id = None.
        super::upsert_object_grant(&conn, "preset", "room-1", owner, None, "view", None, &now).expect("grant");
        super::upsert_object_grant(&conn, "preset", "room-1", owner, None, "clone", None, &now).expect("grant");

        let rights = super::effective_object_rights(&conn, "preset", "room-1", owner, None).expect("rights");
        assert_eq!(rights, vec!["view", "clone"]);
        assert!(!rights.contains(&"edit"));
    }

    #[test]
    fn apply_room_patch_create_forbidden_when_room_create_not_allowed() {
        let mut conn = rooms_test_conn();
        let caller = insert_share_user(&conn, "caller", Some("pub-caller"));
        let now = chrono::Utc::now().to_rfc3339();

        let ops = vec![upsert_op("indicator", "30", 0, serde_json::json!({ "id": 30 }))];
        let (seq, results, _) =
            super::apply_room_patch(&mut conn, "preset", "room-1", caller, &now, &ops, false).expect("apply");

        assert_eq!(seq, 0);
        assert!(matches!(results[0].1, super::RoomOpOutcome::Forbidden));
        assert!(super::get_shared_preset(&conn, "room-1").expect("header").is_none(), "no room was created");
    }

    // ------------------------------------------------------------------
    // Expiry comparisons — day-boundary regressions
    //
    // `expires_at`/`paid_until`/`created_at` are always written via
    // `to_rfc3339()` (`2026-09-24T03:15:31+00:00`), but several queries
    // used to compare that text directly against SQLite's own
    // `datetime('now')`, which renders `2026-09-24 03:15:31` (a space, no
    // offset). Lexicographically `T` (0x54) sorts after ` ` (0x20), so on
    // any day the two share a date prefix, `expires_at > datetime('now')`
    // read as true no matter the time of day — up to ~24h of extra
    // validity. Fixed by wrapping the stored column in `datetime(...)` too,
    // so SQLite parses and re-compares both sides in its own normalized
    // form. Fixed sites: db.rs's `resolve_token_hash_with_expiry`,
    // `resolve_web_session`, `cleanup_expired_sessions`,
    // `cleanup_oauth_states`, `count_active_keys_for_user`,
    // `list_keys_for_user`, `list_key_hashes_for_sync`,
    // `list_sessions_for_user`, and `routes::dashboard::query_summary`'s
    // `device_metrics` 24h-active count.
    // ------------------------------------------------------------------

    /// Standalone `auth_tokens`/`web_sessions`/`device_codes`/
    /// `agent_key_requests` schema — exactly the tables/columns
    /// `resolve_token_hash_with_expiry`, `resolve_web_session` and
    /// `cleanup_expired_sessions` (which also sweeps `agent_key_requests`)
    /// touch. No `users` FK: none of these functions ever join against
    /// `users`.
    fn expiry_test_conn() -> Connection {
        let conn = super::init_test_conn();
        conn.execute_batch(
            "
            CREATE TABLE auth_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id    INTEGER NOT NULL,
                created_at TEXT    NOT NULL,
                expires_at TEXT
            );

            CREATE TABLE web_sessions (
                session_id TEXT    PRIMARY KEY,
                user_id    INTEGER NOT NULL,
                created_at TEXT    NOT NULL,
                expires_at TEXT    NOT NULL,
                ua_hash    TEXT    NOT NULL DEFAULT ''
            );

            CREATE TABLE device_codes (
                code       TEXT    PRIMARY KEY,
                device_id  TEXT    NOT NULL,
                user_id    INTEGER,
                status     TEXT    NOT NULL DEFAULT 'pending',
                created_at TEXT    NOT NULL,
                expires_at TEXT    NOT NULL
            );

            CREATE TABLE agent_key_requests (
                code       TEXT    PRIMARY KEY,
                status     TEXT    NOT NULL DEFAULT 'pending',
                expires_at TEXT    NOT NULL
            );
            ",
        )
        .expect("expiry test schema");
        conn
    }

    /// An instant on the SAME UTC calendar date `datetime('now')` renders at
    /// test time, but chronologically before it — 00:00:01 UTC that day.
    /// This is exactly the shape the `datetime('now')` text-comparison bug
    /// needs to manifest (matching date prefix, earlier time), and it can
    /// never itself cross back into "yesterday", so the test stays valid
    /// even when run within the first hour of the UTC day.
    fn today_before_now_ts() -> String {
        let now = chrono::Utc::now();
        let early = now
            .date_naive()
            .and_hms_opt(0, 0, 1)
            .expect("00:00:01 is a valid time");
        chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(early, chrono::Utc).to_rfc3339()
    }

    #[test]
    fn token_expired_earlier_the_same_utc_day_is_rejected() {
        let conn = expiry_test_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let expires_at = today_before_now_ts();
        conn.execute(
            "INSERT INTO auth_tokens (token_hash, user_id, created_at, expires_at) VALUES ('tok', 7, ?1, ?2)",
            rusqlite::params![now, expires_at],
        )
        .expect("insert token");

        assert_eq!(
            super::resolve_token_hash_with_expiry(&conn, "tok").expect("query"),
            None,
            "a token that expired earlier today must read as expired"
        );
    }

    #[test]
    fn token_expiring_later_is_accepted() {
        let conn = expiry_test_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        conn.execute(
            "INSERT INTO auth_tokens (token_hash, user_id, created_at, expires_at) VALUES ('tok', 7, ?1, ?2)",
            rusqlite::params![now, expires_at],
        )
        .expect("insert token");

        assert_eq!(
            super::resolve_token_hash_with_expiry(&conn, "tok").expect("query"),
            Some(7)
        );
    }

    #[test]
    fn web_session_expired_earlier_the_same_day_is_rejected() {
        let conn = expiry_test_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let expires_at = today_before_now_ts();
        conn.execute(
            "INSERT INTO web_sessions (session_id, user_id, created_at, expires_at, ua_hash) \
             VALUES ('sess', 7, ?1, ?2, 'ua')",
            rusqlite::params![now, expires_at],
        )
        .expect("insert session");

        assert_eq!(
            super::resolve_web_session(&conn, "sess", "ua").expect("query"),
            None,
            "a web session that expired earlier today must read as expired"
        );
    }

    #[test]
    fn web_session_expiring_later_is_accepted() {
        let conn = expiry_test_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        conn.execute(
            "INSERT INTO web_sessions (session_id, user_id, created_at, expires_at, ua_hash) \
             VALUES ('sess', 7, ?1, ?2, 'ua')",
            rusqlite::params![now, expires_at],
        )
        .expect("insert session");

        assert_eq!(
            super::resolve_web_session(&conn, "sess", "ua").expect("query"),
            Some(7)
        );
    }

    #[test]
    fn cleanup_expired_sessions_deletes_a_web_session_expired_earlier_today() {
        let conn = expiry_test_conn();
        let now = chrono::Utc::now().to_rfc3339();
        let expired_at = today_before_now_ts();
        let live_at = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        conn.execute(
            "INSERT INTO web_sessions (session_id, user_id, created_at, expires_at, ua_hash) \
             VALUES ('expired', 7, ?1, ?2, 'ua')",
            rusqlite::params![now, expired_at],
        )
        .expect("insert expired session");
        conn.execute(
            "INSERT INTO web_sessions (session_id, user_id, created_at, expires_at, ua_hash) \
             VALUES ('live', 7, ?1, ?2, 'ua')",
            rusqlite::params![now, live_at],
        )
        .expect("insert live session");

        super::cleanup_expired_sessions(&conn).expect("cleanup");

        let mut stmt = conn.prepare("SELECT session_id FROM web_sessions").expect("prepare");
        let remaining: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect");
        assert_eq!(remaining, vec!["live".to_string()]);
    }

    #[test]
    fn paid_until_expiring_earlier_the_same_day_reads_as_not_paid() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "alice", Some("pub-alice"));
        super::set_user_paid_until(&conn, uid, Some(&today_before_now_ts())).expect("set paid_until");

        assert_eq!(super::user_paid_until(&conn, uid).expect("query"), None);
        assert!(!super::user_is_paid(&conn, uid).expect("query"));
    }

    #[test]
    fn paid_until_expiring_later_reads_as_paid() {
        let conn = share_test_conn();
        let uid = insert_share_user(&conn, "alice", Some("pub-alice"));
        let until = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        super::set_user_paid_until(&conn, uid, Some(&until)).expect("set paid_until");

        assert_eq!(super::user_paid_until(&conn, uid).expect("query"), Some(until));
        assert!(super::user_is_paid(&conn, uid).expect("query"));
    }

    #[test]
    fn object_grant_expiring_earlier_the_same_day_is_not_counted_live() {
        let conn = rooms_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let grantee = insert_share_user(&conn, "grantee", Some("pub-grantee"));
        let now = chrono::Utc::now().to_rfc3339();
        super::upsert_object_grant(
            &conn,
            "preset",
            "room-1",
            owner,
            Some(grantee),
            "view",
            Some(&today_before_now_ts()),
            &now,
        )
        .expect("grant");

        assert_eq!(super::count_object_grants(&conn, "preset", "room-1").expect("count"), 0);
        let rights = super::effective_object_rights(&conn, "preset", "room-1", owner, Some(grantee)).expect("rights");
        assert!(rights.is_empty());
    }

    #[test]
    fn object_grant_expiring_later_is_counted_live() {
        let conn = rooms_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let grantee = insert_share_user(&conn, "grantee", Some("pub-grantee"));
        let now = chrono::Utc::now().to_rfc3339();
        let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        super::upsert_object_grant(
            &conn,
            "preset",
            "room-1",
            owner,
            Some(grantee),
            "view",
            Some(&expires_at),
            &now,
        )
        .expect("grant");

        assert_eq!(super::count_object_grants(&conn, "preset", "room-1").expect("count"), 1);
        let rights = super::effective_object_rights(&conn, "preset", "room-1", owner, Some(grantee)).expect("rights");
        assert_eq!(rights, vec!["view"]);
    }

    // ---- Chart-share policy v1, Rev 2 — effective_share_tier ----
    // (docs/mlc/plans/share-policy-2026-09-25.md §1/§11 step 2)

    /// `share_test_conn`'s schema plus the per-account/group grant tables
    /// this feature needs: `object_grants` WITH `grantee_group_id` (unlike
    /// `rooms_test_conn`'s own copy, which predates it and is left alone —
    /// rooms' own tests never exercise group grants), `grant_groups`,
    /// `grant_group_members`.
    fn share_rights_test_conn() -> Connection {
        let conn = share_test_conn();
        conn.execute_batch(
            "
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
            ",
        )
        .expect("share rights test schema");
        conn
    }

    /// Create a live share row with an explicit `visibility`/`interaction`/
    /// `clone_allowed` — the knobs `effective_share_tier`'s tests vary.
    fn make_share(
        conn: &Connection,
        owner: i64,
        interaction: &str,
        clone_allowed: bool,
        visibility: &str,
    ) -> super::ShareLinkRow {
        let now = chrono::Utc::now().to_rfc3339();
        let token = super::create_share_link(
            conn, owner, "live", "t", "{}", 0, &now, &future_ts(), clone_allowed, interaction, "[]", visibility, None,
        )
        .expect("create");
        super::get_share_link(conn, &token).expect("query").expect("row")
    }

    #[test]
    fn effective_share_tier_owner_is_always_clone_protected() {
        let conn = share_rights_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let row = make_share(&conn, owner, "view", false, "private");

        assert_eq!(
            super::effective_share_tier(&conn, &row, Some(owner)).expect("tier"),
            Some(super::ShareTier::CloneProtected)
        );
    }

    #[test]
    fn effective_share_tier_public_link_floor_alone_no_grants() {
        let conn = share_rights_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let stranger = insert_share_user(&conn, "stranger", Some("pub-stranger"));

        let view_only = make_share(&conn, owner, "view", false, "public");
        assert_eq!(
            super::effective_share_tier(&conn, &view_only, Some(stranger)).expect("tier"),
            Some(super::ShareTier::View)
        );
        assert_eq!(
            super::effective_share_tier(&conn, &view_only, None).expect("tier"),
            Some(super::ShareTier::View),
            "an anonymous caller gets the same public floor"
        );

        let interactive_clonable = make_share(&conn, owner, "interactive", true, "public");
        assert_eq!(
            super::effective_share_tier(&conn, &interactive_clonable, Some(stranger)).expect("tier"),
            Some(super::ShareTier::Clone)
        );
    }

    #[test]
    fn effective_share_tier_private_link_with_no_grant_is_none() {
        let conn = share_rights_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let stranger = insert_share_user(&conn, "stranger", Some("pub-stranger"));
        let row = make_share(&conn, owner, "interactive", true, "private");

        assert_eq!(super::effective_share_tier(&conn, &row, Some(stranger)).expect("tier"), None);
        assert_eq!(
            super::effective_share_tier(&conn, &row, None).expect("tier"),
            None,
            "an anonymous caller on a private link is also locked out"
        );
    }

    #[test]
    fn effective_share_tier_private_link_with_a_direct_grant() {
        let conn = share_rights_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let grantee = insert_share_user(&conn, "grantee", Some("pub-grantee"));
        let row = make_share(&conn, owner, "view", false, "private");
        let now = chrono::Utc::now().to_rfc3339();

        super::upsert_share_grant(&conn, &row.token, owner, Some(grantee), None, super::ShareTier::Clone, None, &now)
            .expect("grant");

        assert_eq!(
            super::effective_share_tier(&conn, &row, Some(grantee)).expect("tier"),
            Some(super::ShareTier::Clone)
        );

        let other = insert_share_user(&conn, "other", Some("pub-other"));
        assert_eq!(super::effective_share_tier(&conn, &row, Some(other)).expect("tier"), None);
    }

    #[test]
    fn effective_share_tier_private_link_with_a_group_grant() {
        let conn = share_rights_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let member = insert_share_user(&conn, "member", Some("pub-member"));
        let non_member = insert_share_user(&conn, "nonmember", Some("pub-nonmember"));
        let row = make_share(&conn, owner, "view", false, "private");
        let now = chrono::Utc::now().to_rfc3339();

        let group_id = super::create_grant_group(&conn, owner, "subscribers", &now).expect("create group");
        super::add_grant_group_member(&conn, group_id, owner, member, &now).expect("add member");
        super::upsert_share_grant(
            &conn, &row.token, owner, None, Some(group_id), super::ShareTier::CloneProtected, None, &now,
        )
        .expect("grant");

        assert_eq!(
            super::effective_share_tier(&conn, &row, Some(member)).expect("tier"),
            Some(super::ShareTier::CloneProtected)
        );
        assert_eq!(super::effective_share_tier(&conn, &row, Some(non_member)).expect("tier"), None);
    }

    #[test]
    fn effective_share_tier_an_expired_grant_does_not_count() {
        let conn = share_rights_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let grantee = insert_share_user(&conn, "grantee", Some("pub-grantee"));
        let row = make_share(&conn, owner, "view", false, "private");
        let now = chrono::Utc::now().to_rfc3339();

        super::upsert_share_grant(
            &conn, &row.token, owner, Some(grantee), None, super::ShareTier::Clone, Some(&past_ts()), &now,
        )
        .expect("grant");

        assert_eq!(super::effective_share_tier(&conn, &row, Some(grantee)).expect("tier"), None);
    }

    #[test]
    fn effective_share_tier_grant_below_the_public_floor_never_lowers_the_result() {
        let conn = share_rights_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let grantee = insert_share_user(&conn, "grantee", Some("pub-grantee"));
        // Public floor already reaches Clone (interactive + clone_allowed);
        // the grant below it (View) must never win over the floor — max, not
        // override.
        let row = make_share(&conn, owner, "interactive", true, "public");
        let now = chrono::Utc::now().to_rfc3339();

        super::upsert_share_grant(&conn, &row.token, owner, Some(grantee), None, super::ShareTier::View, None, &now)
            .expect("grant");

        assert_eq!(
            super::effective_share_tier(&conn, &row, Some(grantee)).expect("tier"),
            Some(super::ShareTier::Clone)
        );
    }

    /// Revoking a share grant (`revoke_object_grant`, the same generic
    /// function rooms' own grant CRUD uses) stops it from counting on the
    /// very next `effective_share_tier` call — owner instruction 1's "even
    /// if a link leaks, the server re-checks the requester's rights" holds
    /// for a grant that existed and was pulled, not just for one that never
    /// existed (already proven by `effective_share_tier_private_link_with_no_grant_is_none`).
    #[test]
    fn revoking_a_share_grant_stops_it_on_the_next_effective_share_tier_call() {
        let conn = share_rights_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let grantee = insert_share_user(&conn, "grantee", Some("pub-grantee"));
        let row = make_share(&conn, owner, "view", false, "private");
        let now = chrono::Utc::now().to_rfc3339();

        let grant_id = super::upsert_share_grant(
            &conn, &row.token, owner, Some(grantee), None, super::ShareTier::Clone, None, &now,
        )
        .expect("grant");
        assert_eq!(
            super::effective_share_tier(&conn, &row, Some(grantee)).expect("tier"),
            Some(super::ShareTier::Clone)
        );

        assert!(super::revoke_object_grant(&conn, grant_id, owner).expect("revoke"));
        assert_eq!(super::effective_share_tier(&conn, &row, Some(grantee)).expect("tier"), None);
    }

    /// `list_object_grants` projects `grantee_group_id` (widened alongside
    /// `ObjectGrantRow` for §8.2's grant-listing route) — a group-targeted
    /// share grant round-trips through it with `grantee_user_id: None`,
    /// `grantee_group_id: Some(group_id)`.
    #[test]
    fn list_object_grants_projects_grantee_group_id() {
        let conn = share_rights_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let row = make_share(&conn, owner, "view", false, "private");
        let now = chrono::Utc::now().to_rfc3339();
        let group_id = super::create_grant_group(&conn, owner, "subscribers", &now).expect("create group");

        super::upsert_share_grant(
            &conn, &row.token, owner, None, Some(group_id), super::ShareTier::Clone, None, &now,
        )
        .expect("grant");

        let grants = super::list_object_grants(&conn, "chart", &row.token).expect("list");
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].grantee_user_id, None);
        assert_eq!(grants[0].grantee_group_id, Some(group_id));
    }

    // ---- Chart-share policy v1, Rev 2 — grant groups (§8.3) ----

    #[test]
    fn grant_group_create_rename_delete_owner_only() {
        let conn = share_rights_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let stranger = insert_share_user(&conn, "stranger", Some("pub-stranger"));
        let now = chrono::Utc::now().to_rfc3339();

        let group_id = super::create_grant_group(&conn, owner, "subscribers", &now).expect("create");
        assert!(super::grant_group_is_owned_by(&conn, group_id, owner).expect("owned"));
        assert!(!super::grant_group_is_owned_by(&conn, group_id, stranger).expect("owned"));

        // A non-owner cannot rename or delete it.
        assert!(!super::rename_grant_group(&conn, group_id, stranger, "hijacked").expect("rename"));
        assert!(!super::delete_grant_group(&conn, group_id, stranger).expect("delete"));
        assert_eq!(
            super::grant_group_name(&conn, group_id).expect("name"),
            Some("subscribers".to_string())
        );

        // The owner can.
        assert!(super::rename_grant_group(&conn, group_id, owner, "vip").expect("rename"));
        assert_eq!(super::grant_group_name(&conn, group_id).expect("name"), Some("vip".to_string()));
        assert!(super::delete_grant_group(&conn, group_id, owner).expect("delete"));
        assert_eq!(super::grant_group_name(&conn, group_id).expect("name"), None);
    }

    #[test]
    fn grant_group_membership_add_remove_owner_only() {
        let conn = share_rights_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let stranger = insert_share_user(&conn, "stranger", Some("pub-stranger"));
        let member = insert_share_user(&conn, "member", Some("pub-member"));
        let now = chrono::Utc::now().to_rfc3339();
        let group_id = super::create_grant_group(&conn, owner, "subscribers", &now).expect("create");

        // A non-owner cannot add or remove a member.
        assert!(!super::add_grant_group_member(&conn, group_id, stranger, member, &now).expect("add"));
        assert_eq!(super::count_grant_group_members(&conn, group_id).expect("count"), 0);

        // The owner can, idempotently.
        assert!(super::add_grant_group_member(&conn, group_id, owner, member, &now).expect("add"));
        assert!(super::add_grant_group_member(&conn, group_id, owner, member, &now).expect("add again"));
        assert_eq!(super::count_grant_group_members(&conn, group_id).expect("count"), 1);

        assert!(!super::remove_grant_group_member(&conn, group_id, stranger, member).expect("remove"));
        assert_eq!(super::count_grant_group_members(&conn, group_id).expect("count"), 1);
        assert!(super::remove_grant_group_member(&conn, group_id, owner, member).expect("remove"));
        assert_eq!(super::count_grant_group_members(&conn, group_id).expect("count"), 0);
    }

    #[test]
    fn list_grant_groups_is_scoped_to_the_caller_and_carries_member_counts() {
        let conn = share_rights_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let other_owner = insert_share_user(&conn, "other-owner", Some("pub-other-owner"));
        let member = insert_share_user(&conn, "member", Some("pub-member"));
        let now = chrono::Utc::now().to_rfc3339();

        let g1 = super::create_grant_group(&conn, owner, "subscribers", &now).expect("create g1");
        super::add_grant_group_member(&conn, g1, owner, member, &now).expect("add");
        super::create_grant_group(&conn, other_owner, "not-mine", &now).expect("create g2");

        let groups = super::list_grant_groups(&conn, owner).expect("list");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].id, g1);
        assert_eq!(groups[0].member_count, 1);
    }

    /// Deleting a group leaves any `object_grants` row still targeting it in
    /// place (plan §8.3's "no cascade needed" rule) — `effective_share_tier`
    /// simply stops matching anyone for it, since `grant_group_members` has
    /// nothing left to join against.
    #[test]
    fn deleting_a_grant_group_leaves_its_share_grant_inert_not_erroring() {
        let conn = share_rights_test_conn();
        let owner = insert_share_user(&conn, "owner", Some("pub-owner"));
        let member = insert_share_user(&conn, "member", Some("pub-member"));
        let row = make_share(&conn, owner, "view", false, "private");
        let now = chrono::Utc::now().to_rfc3339();

        let group_id = super::create_grant_group(&conn, owner, "subscribers", &now).expect("create");
        super::add_grant_group_member(&conn, group_id, owner, member, &now).expect("add");
        super::upsert_share_grant(
            &conn, &row.token, owner, None, Some(group_id), super::ShareTier::Clone, None, &now,
        )
        .expect("grant");
        assert_eq!(
            super::effective_share_tier(&conn, &row, Some(member)).expect("tier"),
            Some(super::ShareTier::Clone)
        );

        assert!(super::delete_grant_group(&conn, group_id, owner).expect("delete"));
        assert_eq!(super::effective_share_tier(&conn, &row, Some(member)).expect("tier"), None);
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

#[cfg(test)]
mod share_nick_search_tests {
    use super::search_share_nicks;
    use rusqlite::Connection;

    fn conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                nick TEXT,
                display_name TEXT NOT NULL DEFAULT '',
                discoverable INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE friendships (
                user_id INTEGER NOT NULL,
                friend_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (user_id, friend_id)
            );",
        )
        .unwrap();
        conn
    }

    fn insert(conn: &Connection, id: i64, nick: Option<&str>, display: &str) {
        conn.execute(
            "INSERT INTO users (id, nick, display_name) VALUES (?1, ?2, ?3)",
            rusqlite::params![id, nick, display],
        )
        .unwrap();
    }

    #[test]
    fn search_share_nicks_finds_a_nick_without_a_dm_key_and_skips_the_caller() {
        let conn = conn();
        insert(&conn, 1, Some("zeng3ld"), "ZENG3LD");
        insert(&conn, 32, Some("moderator"), "к кк");
        insert(&conn, 37, Some("admin"), "KONSTANTIN NO");
        insert(&conn, 2, None, "anti");

        let as_admin = search_share_nicks(&conn, 37, "mod", 8).unwrap();
        assert_eq!(as_admin.len(), 1);
        assert_eq!(as_admin[0].nick, "moderator");
        assert_eq!(as_admin[0].label, "");

        let self_search = search_share_nicks(&conn, 37, "admin", 8).unwrap();
        assert!(self_search.is_empty());

        // Display name is not a search key and is not returned.
        let by_display = search_share_nicks(&conn, 37, "к", 8).unwrap();
        assert!(by_display.is_empty());

        // No nick: not searchable, even when the display name matches the query.
        let unnamed = search_share_nicks(&conn, 37, "anti", 8).unwrap();
        assert!(unnamed.is_empty());
    }
}

#[cfg(test)]
mod share_op_tests {
    use super::{append_share_ops, list_share_ops_after, share_caller_can_edit, upsert_share_edit_grant, upsert_share_grant, ShareTier};
    use rusqlite::Connection;

    fn conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE share_links (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                op_seq INTEGER NOT NULL DEFAULT 0
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
            CREATE TABLE object_grants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                object_kind TEXT NOT NULL,
                object_id TEXT NOT NULL,
                owner_user_id INTEGER NOT NULL,
                grantee_user_id INTEGER,
                grantee_group_id INTEGER,
                right TEXT NOT NULL,
                expires_at TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE grant_group_members (
                group_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO share_links (token, user_id, kind) VALUES ('t', 1, 'live')",
            [],
        )
        .unwrap();
        conn
    }

    #[test]
    fn ops_append_in_order_and_edit_grant_does_not_replace_clone() {
        let conn = conn();
        let seqs = append_share_ops(
            &conn,
            "t",
            1,
            &[
                ("primitive_upsert".into(), "p:1".into(), "{}".into()),
                ("primitive_delete".into(), "p:1".into(), String::new()),
            ],
            "now",
        )
        .unwrap();
        assert_eq!(seqs, vec![1, 2]);
        let (head, page) = list_share_ops_after(&conn, "t", 1, 10).unwrap();
        assert_eq!(head, 2);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].kind, "primitive_delete");

        let link = super::ShareLinkRow {
            token: "t".into(),
            user_id: 1,
            kind: "live".into(),
            title: String::new(),
            preset_json: String::new(),
            blob_path: String::new(),
            blob_bytes: 0,
            created_at: String::new(),
            expires_at: "2999".into(),
            clone_allowed: true,
            interaction: "view".into(),
            protected_json: "[]".into(),
            visibility: "private".into(),
            preview_path: String::new(),
            allow_forward: None,
            pinned: false,
            chart_id: String::new(),
            revision: 1,
            op_seq: 2,
            live: false,
        };
        assert!(!share_caller_can_edit(&conn, &link, 2).unwrap());
        upsert_share_grant(&conn, "t", 1, Some(2), None, ShareTier::Clone, None, "now").unwrap();
        upsert_share_edit_grant(&conn, "t", 1, Some(2), None, None, "now").unwrap();
        assert!(share_caller_can_edit(&conn, &link, 2).unwrap());
        let tier = super::effective_share_tier(&conn, &link, Some(2)).unwrap();
        assert_eq!(tier, Some(ShareTier::Clone));
    }
}

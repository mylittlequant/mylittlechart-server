//! Social-plane SQLCipher database (`social.db`) — forum engine v2 (owner
//! ruling 2026-09-05, `docs/mlc/plans/social-sharing-access-gates-and-agent-
//! control-2026-09-05.md` §4-5): boards, role-gated read/write, threaded
//! replies, moderation, and full-text search — physically separate from the
//! identity database (`mylittlechart.db`), same SQLCipher key, different
//! file (`init_social_db`, called once at boot from `main.rs` with the same
//! `key_hex` `db::read_sqlcipher_key` already produced for identity).
//!
//! Cross-database rule (plan §5): this file stores only `user_id` — never a
//! display name, never anything else about an account. A caller's display
//! label is always looked up live from the identity connection
//! (`db::forum_author_label`/`db::effective_label_for_user`), the same way
//! the v1 forum already does it. Every join across the identity/social
//! boundary happens in Rust, not SQL: two connections, two queries. See
//! `routes::forum_v2`'s handlers, which are the only code that ever holds
//! both connections at once (never at the same instant — one is locked,
//! read, and dropped before the other is locked; see e.g.
//! `routes::forum_v2::resolve_caller_classes`).
//!
//! `forum_threads`/`forum_replies` (the paid-only v1 forum, `routes/
//! forum.rs`) still live in the identity database. TODO (plan §5's
//! migration note): once the client moves onto v2, copy those two tables'
//! rows into `forum_threads_v2`/`forum_replies_v2` (board = a new "legacy"
//! board), switch `routes/forum.rs`'s callers over, and drop the old tables
//! from identity in a later release. Nothing in this module reads or writes
//! them.
//!
//! FTS5 availability: confirmed present in this build. `libsqlite3-sys`'s
//! `bundled`/`bundled-sqlcipher` build script (both used by this crate — see
//! `Cargo.toml`) unconditionally passes `-DSQLITE_ENABLE_FTS5` to the C
//! compiler; there is no separate rusqlite/libsqlite3-sys Cargo feature that
//! gates it. `forum_threads_fts`/`forum_replies_fts` below are real FTS5
//! virtual tables, not a `LIKE` fallback.

use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use rusqlite::{params, Connection, OptionalExtension, Result};

use crate::db::ForumError;

// ============================================================================
// Boot: open + schema
// ============================================================================

/// Open `social.db` with the same SQLCipher key identity uses (`key_hex` —
/// see `db::read_sqlcipher_key`, called once at boot and handed to both
/// databases) and create the forum-v2 schema if it does not exist yet.
pub fn init_social_db(path: &str, key_hex: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;
    // SQLCipher: the key must be the very first statement on the connection
    // (same rule `db::init_db` follows for identity).
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", key_hex))?;
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;
    create_social_schema(&conn)?;
    // DM tables (`dm_db.rs`) live in this same file — same storage split,
    // separate module because the crypto/paid-gate posture is unrelated to
    // the forum's class ladder.
    crate::dm_db::create_dm_schema(&conn)?;
    Ok(conn)
}

/// Create every table, index, FTS5 virtual table, sync trigger, and seed row
/// this module needs — idempotent (`IF NOT EXISTS` / `INSERT OR IGNORE`
/// throughout), so it runs on every boot. Split out of `init_social_db` so
/// tests can build the schema on a plain in-memory connection with no
/// SQLCipher key at all (see the `tests` module below).
pub(crate) fn create_social_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        -- Reference table of caller classes (plan §4: "roles are a
        -- server-side table, not code paths"). The RANK of these six names
        -- is fixed in `Class`'s enum declaration order below, not in this
        -- table — this table is metadata (name + description) for an admin
        -- UI, not the source of truth for ordering. Adding a seventh class
        -- still needs a code change to `Class` — the plan's promise that "a
        -- new class never needs a code change" is about moderation
        -- permissions attached to `forum_roles` rows, not about widening the
        -- rank ladder itself.
        CREATE TABLE IF NOT EXISTS forum_classes (
            name        TEXT PRIMARY KEY,
            description TEXT NOT NULL DEFAULT ''
        );

        -- One managed role per account: 'moderator' or 'admin'. Absence of a
        -- row means neither — the account's classes are whatever
        -- `caller_classes` derives from signed-in/paid/trusted alone. See
        -- `Role`.
        CREATE TABLE IF NOT EXISTS forum_roles (
            user_id    INTEGER PRIMARY KEY,
            role       TEXT NOT NULL,
            granted_at TEXT NOT NULL
        );

        -- One row = the account holds `Class::Trusted` standing ("paid with
        -- standing" — owner ruling, `docs/mlc/plans/community-modal-and-
        -- forum-ladder-2026-09-09.md` §5): a flag an admin grants, additive
        -- to whatever `is_paid` alone would give. Absence of a row means not
        -- trusted. `note` is an optional free-text reason for the grant (an
        -- operator's own record — never shown to other callers).
        CREATE TABLE IF NOT EXISTS forum_trusted (
            user_id    INTEGER PRIMARY KEY,
            granted_at TEXT NOT NULL,
            note       TEXT
        );

        -- A board's `read_class`/`write_class` name a row in `forum_classes`
        -- (`Class::as_str`), not a foreign key — the class ladder is fixed
        -- Rust, not a table an admin can delete rows out from under a board.
        CREATE TABLE IF NOT EXISTS forum_boards (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            slug        TEXT NOT NULL UNIQUE,
            title       TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            read_class  TEXT NOT NULL,
            write_class TEXT NOT NULL,
            position    INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT NOT NULL
        );

        -- `author_user_id` deliberately carries no foreign key to `users` —
        -- that table lives in a different database file entirely now, so a
        -- same-database REFERENCES clause is not even expressible. Forum
        -- content outlives the account that created it, same posture v1's
        -- `forum_threads` already documents.
        CREATE TABLE IF NOT EXISTS forum_threads_v2 (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            board_id       INTEGER NOT NULL REFERENCES forum_boards(id),
            author_user_id INTEGER NOT NULL,
            title          TEXT NOT NULL,
            body           TEXT NOT NULL,
            created_at     TEXT NOT NULL,
            updated_at     TEXT NOT NULL,
            last_reply_at  TEXT,
            reply_count    INTEGER NOT NULL DEFAULT 0,
            pinned         INTEGER NOT NULL DEFAULT 0,
            locked         INTEGER NOT NULL DEFAULT 0,
            hidden         INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_forum_threads_v2_board
            ON forum_threads_v2(board_id, hidden, pinned DESC, id DESC);

        -- `parent_reply_id` NULL = top-level reply to the thread itself;
        -- otherwise a reply to another reply, one level deeper (`depth`).
        CREATE TABLE IF NOT EXISTS forum_replies_v2 (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            thread_id       INTEGER NOT NULL REFERENCES forum_threads_v2(id),
            parent_reply_id INTEGER REFERENCES forum_replies_v2(id),
            author_user_id  INTEGER NOT NULL,
            body            TEXT NOT NULL,
            created_at      TEXT NOT NULL,
            hidden          INTEGER NOT NULL DEFAULT 0,
            depth           INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_forum_replies_v2_thread
            ON forum_replies_v2(thread_id, hidden, id);

        -- External-content FTS5 index over threads (title + body) and
        -- replies (body). `content=`/`content_rowid=` point at the real
        -- table so the index carries no duplicate copy of the text; the six
        -- triggers below keep it in sync on every insert/update/delete.
        CREATE VIRTUAL TABLE IF NOT EXISTS forum_threads_fts USING fts5(
            title, body, content='forum_threads_v2', content_rowid='id'
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS forum_replies_fts USING fts5(
            body, content='forum_replies_v2', content_rowid='id'
        );

        CREATE TRIGGER IF NOT EXISTS forum_threads_v2_ai AFTER INSERT ON forum_threads_v2 BEGIN
            INSERT INTO forum_threads_fts(rowid, title, body) VALUES (new.id, new.title, new.body);
        END;
        CREATE TRIGGER IF NOT EXISTS forum_threads_v2_ad AFTER DELETE ON forum_threads_v2 BEGIN
            INSERT INTO forum_threads_fts(forum_threads_fts, rowid, title, body)
                VALUES('delete', old.id, old.title, old.body);
        END;
        CREATE TRIGGER IF NOT EXISTS forum_threads_v2_au AFTER UPDATE ON forum_threads_v2 BEGIN
            INSERT INTO forum_threads_fts(forum_threads_fts, rowid, title, body)
                VALUES('delete', old.id, old.title, old.body);
            INSERT INTO forum_threads_fts(rowid, title, body) VALUES (new.id, new.title, new.body);
        END;

        CREATE TRIGGER IF NOT EXISTS forum_replies_v2_ai AFTER INSERT ON forum_replies_v2 BEGIN
            INSERT INTO forum_replies_fts(rowid, body) VALUES (new.id, new.body);
        END;
        CREATE TRIGGER IF NOT EXISTS forum_replies_v2_ad AFTER DELETE ON forum_replies_v2 BEGIN
            INSERT INTO forum_replies_fts(forum_replies_fts, rowid, body) VALUES('delete', old.id, old.body);
        END;
        CREATE TRIGGER IF NOT EXISTS forum_replies_v2_au AFTER UPDATE ON forum_replies_v2 BEGIN
            INSERT INTO forum_replies_fts(forum_replies_fts, rowid, body) VALUES('delete', old.id, old.body);
            INSERT INTO forum_replies_fts(rowid, body) VALUES (new.id, new.body);
        END;
        "#,
    )?;

    for (name, description) in [
        ("public", "Anyone, including signed-out visitors"),
        ("user", "Any signed-in account"),
        ("paid", "Signed-in accounts with paid access"),
        ("trusted", "Paid accounts holding admin-granted trusted standing"),
        ("moderator", "Accounts holding the moderator role"),
        ("admin", "Accounts holding the admin role"),
    ] {
        conn.execute(
            "INSERT OR IGNORE INTO forum_classes (name, description) VALUES (?1, ?2)",
            params![name, description],
        )?;
    }

    // Seeded boards (plan §"Seeded boards (idempotent)") — `INSERT OR IGNORE`
    // so re-running this on an existing database only fills in slugs that
    // are still missing; an existing board's title/read_class/write_class
    // (and, for `general`/`paid`, `position`) are never touched by this loop.
    let now = chrono::Utc::now().to_rfc3339();
    for (slug, title, description, read_class, write_class, position) in [
        ("announcements", "Announcements", "Project news, posted by the team.", Class::Public, Class::Admin, 0),
        ("general", "General", "Open discussion.", Class::Public, Class::Paid, 1),
        ("members", "Members", "Any signed-in account can post here.", Class::User, Class::User, 2),
        ("paid", "Paid", "Paid-only discussion.", Class::Paid, Class::Paid, 3),
        ("trusted", "Trusted", "Paid accounts holding trusted standing.", Class::Trusted, Class::Trusted, 4),
        ("staff", "Staff", "Moderators and admins.", Class::Moderator, Class::Moderator, 5),
        ("admins", "Admins", "Admins only.", Class::Admin, Class::Admin, 6),
    ] {
        conn.execute(
            "INSERT OR IGNORE INTO forum_boards
                (slug, title, description, read_class, write_class, position, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![slug, title, description, read_class, write_class, position, now],
        )?;
    }

    Ok(())
}

// ============================================================================
// Class — the caller-class ladder (plan §4)
// ============================================================================

/// A caller class, ranked by declaration order (owner ruling 2026-09-09,
/// `docs/mlc/plans/community-modal-and-forum-ladder-2026-09-09.md` §5):
/// `Public < User < Paid < Trusted < Moderator < Admin`. [`can_read`]/
/// [`can_write`] compare a board's required class against a caller's held
/// classes by [`rank`](Class::rank), so a moderator or admin automatically
/// satisfies every board's gate without a special case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    Public,
    User,
    Paid,
    /// Paid "with standing" — an admin-granted flag ([`forum_trusted`
    /// admin routes](set_trusted)/`social_db::is_trusted`), not automatic
    /// from `is_paid` alone.
    Trusted,
    Moderator,
    Admin,
}

impl Class {
    /// Numeric rank on the ladder, `0` (least) to `5` (most) — the value
    /// [`can_read`]/[`can_write`]/[`is_moderator_or_admin`] compare with
    /// `>=`. Written out explicitly (not `self as u8`) so the ladder's order
    /// stays a single obvious source of truth next to [`as_str`](Class::as_str)/
    /// [`from_wire_name`](Class::from_wire_name).
    pub fn rank(self) -> u8 {
        match self {
            Class::Public => 0,
            Class::User => 1,
            Class::Paid => 2,
            Class::Trusted => 3,
            Class::Moderator => 4,
            Class::Admin => 5,
        }
    }

    /// Stable wire/storage name — also the six rows seeded into
    /// `forum_classes`.
    pub fn as_str(self) -> &'static str {
        match self {
            Class::Public => "public",
            Class::User => "user",
            Class::Paid => "paid",
            Class::Trusted => "trusted",
            Class::Moderator => "moderator",
            Class::Admin => "admin",
        }
    }

    pub fn from_wire_name(s: &str) -> Option<Class> {
        match s {
            "public" => Some(Class::Public),
            "user" => Some(Class::User),
            "paid" => Some(Class::Paid),
            "trusted" => Some(Class::Trusted),
            "moderator" => Some(Class::Moderator),
            "admin" => Some(Class::Admin),
            _ => None,
        }
    }

    /// Every class name, ladder order — the list a 400 refusal on an invalid
    /// `read_class`/`write_class` shows the caller.
    pub fn all_wire_names() -> &'static [&'static str] {
        &["public", "user", "paid", "trusted", "moderator", "admin"]
    }
}

impl FromSql for Class {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        Class::from_wire_name(value.as_str()?).ok_or(FromSqlError::InvalidType)
    }
}

impl ToSql for Class {
    fn to_sql(&self) -> Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.as_str()))
    }
}

/// A managed role row in `forum_roles` — the source of the `Moderator`/
/// `Admin` classes in [`caller_classes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Moderator,
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Moderator => "moderator",
            Role::Admin => "admin",
        }
    }

    pub fn from_wire_name(s: &str) -> Option<Role> {
        match s {
            "moderator" => Some(Role::Moderator),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }
}

impl FromSql for Role {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        Role::from_wire_name(value.as_str()?).ok_or(FromSqlError::InvalidType)
    }
}

impl ToSql for Role {
    fn to_sql(&self) -> Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.as_str()))
    }
}

/// Resolve one user's role row, if any.
pub fn role_for_user(conn: &Connection, user_id: i64) -> Result<Option<Role>> {
    conn.query_row(
        "SELECT role FROM forum_roles WHERE user_id = ?1",
        params![user_id],
        |row| row.get(0),
    )
    .optional()
}

/// Upsert `user_id`'s role — one managed role per account, so a second call
/// replaces the first (e.g. promoting a moderator to admin).
pub fn set_role(conn: &Connection, user_id: i64, role: Role, now: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO forum_roles (user_id, role, granted_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(user_id) DO UPDATE SET role = excluded.role, granted_at = excluded.granted_at",
        params![user_id, role, now],
    )?;
    Ok(())
}

/// Remove `user_id`'s role, if any. Returns whether a row was removed.
pub fn remove_role(conn: &Connection, user_id: i64) -> Result<bool> {
    let n = conn.execute("DELETE FROM forum_roles WHERE user_id = ?1", params![user_id])?;
    Ok(n > 0)
}

/// One row returned by [`list_roles`] — `routes::forum_v2::admin_list_roles`
/// resolves `nick` from the identity connection per row (this module stores
/// only `user_id`, per the cross-database rule above).
pub struct RoleRow {
    pub user_id: i64,
    pub role: Role,
    pub granted_at: String,
}

/// Every managed `forum_roles` row, ordered by user id ascending.
pub fn list_roles(conn: &Connection) -> Result<Vec<RoleRow>> {
    let mut stmt = conn.prepare("SELECT user_id, role, granted_at FROM forum_roles ORDER BY user_id ASC")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(RoleRow {
            user_id: row.get(0)?,
            role: row.get(1)?,
            granted_at: row.get(2)?,
        });
    }
    Ok(out)
}

/// Grant `user_id` trusted standing ([`Class::Trusted`]) — upsert, same
/// idiom as [`set_role`]: a second call just replaces `note`/`granted_at`.
pub fn set_trusted(conn: &Connection, user_id: i64, note: Option<&str>, now: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO forum_trusted (user_id, granted_at, note) VALUES (?1, ?2, ?3)
         ON CONFLICT(user_id) DO UPDATE SET granted_at = excluded.granted_at, note = excluded.note",
        params![user_id, now, note],
    )?;
    Ok(())
}

/// Revoke `user_id`'s trusted standing, if any. Returns whether a row was
/// removed.
pub fn remove_trusted(conn: &Connection, user_id: i64) -> Result<bool> {
    let n = conn.execute("DELETE FROM forum_trusted WHERE user_id = ?1", params![user_id])?;
    Ok(n > 0)
}

/// Whether `user_id` holds a `forum_trusted` row.
pub fn is_trusted(conn: &Connection, user_id: i64) -> Result<bool> {
    Ok(conn
        .query_row("SELECT 1 FROM forum_trusted WHERE user_id = ?1", params![user_id], |_| Ok(()))
        .optional()?
        .is_some())
}

/// One row returned by [`list_trusted`] — `routes::forum_v2::admin_list_trusted`
/// resolves `nick` from the identity connection per row, same cross-database
/// discipline as [`RoleRow`].
pub struct TrustedRow {
    pub user_id: i64,
    pub granted_at: String,
    pub note: Option<String>,
}

/// Every managed `forum_trusted` row, ordered by user id ascending.
pub fn list_trusted(conn: &Connection) -> Result<Vec<TrustedRow>> {
    let mut stmt = conn.prepare("SELECT user_id, granted_at, note FROM forum_trusted ORDER BY user_id ASC")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(TrustedRow {
            user_id: row.get(0)?,
            granted_at: row.get(1)?,
            note: row.get(2)?,
        });
    }
    Ok(out)
}

/// Resolve the caller's classes as the full cumulative ladder up to their
/// rank (plan §5: "cumulative, one rank per account") — `[Public]` for an
/// anonymous caller; otherwise every class from `Public` up to
/// `max(User, Paid if is_paid, Trusted if a `forum_trusted` row exists, the
/// class a `forum_roles` row maps to)`. `is_paid` is already resolved by the
/// route via `db::user_is_paid` on the identity connection — same shape
/// `entitlements::resolve_for_user` already takes, and for the same reason:
/// it keeps this module's tests running against `conn_social` alone, with no
/// identity-database fixture at all. `forum_trusted`/`forum_roles` both live
/// on `conn_social` — the pieces of this that DO live in the social
/// database, per the storage split (plan §5).
///
/// Cumulative means a moderator or admin's classes include `Paid`/`Trusted`
/// even when the account itself is not paid or not flagged trusted — the
/// plan's own framing ("a moderator can read/write everything up to rank
/// 4") makes the ladder's rank the single source of truth, not a per-class
/// flag union.
///
/// Deviates from the plan's sketched `fn caller_classes(conn_identity,
/// caller) -> Vec<Class>` signature: `forum_trusted`/`forum_roles` live in
/// `social.db`, not identity, so a real implementation needs `conn_social`,
/// not `conn_identity` — and once a database connection is threaded through,
/// the already-resolved-fact shape below (matching `entitlements.rs`'s own
/// documented reasoning) is the better fit than a second live query this
/// module would otherwise have to make against tables it does not own.
pub fn caller_classes(conn_social: &Connection, caller: Option<i64>, is_paid: bool) -> Vec<Class> {
    let Some(user_id) = caller else {
        return vec![Class::Public];
    };

    let mut rank = Class::User.rank();
    if is_paid {
        rank = rank.max(Class::Paid.rank());
    }
    if is_trusted(conn_social, user_id).unwrap_or(false) {
        rank = rank.max(Class::Trusted.rank());
    }
    if let Ok(Some(role)) = role_for_user(conn_social, user_id) {
        let role_class = match role {
            Role::Moderator => Class::Moderator,
            Role::Admin => Class::Admin,
        };
        rank = rank.max(role_class.rank());
    }

    [Class::Public, Class::User, Class::Paid, Class::Trusted, Class::Moderator, Class::Admin]
        .into_iter()
        .filter(|c| c.rank() <= rank)
        .collect()
}

/// Highest rank held anywhere in `classes` — `0` (`Public`) for an empty
/// slice, which should not happen since [`caller_classes`] always includes
/// at least `Public`.
fn caller_rank(classes: &[Class]) -> u8 {
    classes.iter().map(|c| c.rank()).max().unwrap_or(0)
}

/// Whether `classes` reaches or exceeds `board`'s read gate.
pub fn can_read(board: &Board, classes: &[Class]) -> bool {
    caller_rank(classes) >= board.read_class.rank()
}

/// Whether `classes` reaches or exceeds `board`'s write gate.
pub fn can_write(board: &Board, classes: &[Class]) -> bool {
    caller_rank(classes) >= board.write_class.rank()
}

/// Whether `classes` holds moderation permission (moderator = hide/unhide/
/// lock/pin/move within a board and delete any reply; admin = everything —
/// see [`Class::rank`], which already makes `Admin` satisfy this).
pub fn is_moderator_or_admin(classes: &[Class]) -> bool {
    caller_rank(classes) >= Class::Moderator.rank()
}

// ============================================================================
// Boards
// ============================================================================

/// One row of the `forum_boards` table.
#[derive(Debug, Clone, PartialEq)]
pub struct Board {
    pub id: i64,
    pub slug: String,
    pub title: String,
    pub description: String,
    pub read_class: Class,
    pub write_class: Class,
    pub position: i64,
    pub created_at: String,
}

const BOARD_SELECT_COLUMNS: &str =
    "id, slug, title, description, read_class, write_class, position, created_at";

fn board_from_row(row: &rusqlite::Row<'_>) -> Result<Board> {
    Ok(Board {
        id: row.get(0)?,
        slug: row.get(1)?,
        title: row.get(2)?,
        description: row.get(3)?,
        read_class: row.get(4)?,
        write_class: row.get(5)?,
        position: row.get(6)?,
        created_at: row.get(7)?,
    })
}

/// Every board, ordered by `position` then `id`.
pub fn list_boards(conn: &Connection) -> Result<Vec<Board>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {BOARD_SELECT_COLUMNS} FROM forum_boards ORDER BY position ASC, id ASC"
    ))?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(board_from_row(row)?);
    }
    Ok(out)
}

pub fn get_board_by_slug(conn: &Connection, slug: &str) -> Result<Option<Board>> {
    conn.query_row(
        &format!("SELECT {BOARD_SELECT_COLUMNS} FROM forum_boards WHERE slug = ?1"),
        params![slug],
        board_from_row,
    )
    .optional()
}

pub fn get_board_by_id(conn: &Connection, id: i64) -> Result<Option<Board>> {
    conn.query_row(
        &format!("SELECT {BOARD_SELECT_COLUMNS} FROM forum_boards WHERE id = ?1"),
        params![id],
        board_from_row,
    )
    .optional()
}

/// Why [`create_board`] was refused before ever touching the database.
#[derive(Debug)]
pub enum BoardError {
    /// A board with this slug already exists. Checked with a `SELECT`
    /// before the `INSERT` (same idiom `db::set_nick` uses for nick
    /// uniqueness) rather than by matching the UNIQUE constraint's error —
    /// one lookup, one clear refusal reason.
    SlugTaken,
    Db(rusqlite::Error),
}

impl From<rusqlite::Error> for BoardError {
    fn from(e: rusqlite::Error) -> Self {
        BoardError::Db(e)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn create_board(
    conn: &Connection,
    slug: &str,
    title: &str,
    description: &str,
    read_class: Class,
    write_class: Class,
    position: i64,
    now: &str,
) -> std::result::Result<i64, BoardError> {
    if get_board_by_slug(conn, slug)?.is_some() {
        return Err(BoardError::SlugTaken);
    }
    conn.execute(
        "INSERT INTO forum_boards (slug, title, description, read_class, write_class, position, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![slug, title, description, read_class, write_class, position, now],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Partial update: any `None` field keeps its current value (`COALESCE`).
/// Returns whether a board with `id` existed.
#[allow(clippy::too_many_arguments)]
pub fn update_board(
    conn: &Connection,
    id: i64,
    title: Option<&str>,
    description: Option<&str>,
    read_class: Option<Class>,
    write_class: Option<Class>,
    position: Option<i64>,
) -> Result<bool> {
    let n = conn.execute(
        "UPDATE forum_boards SET
            title = COALESCE(?2, title),
            description = COALESCE(?3, description),
            read_class = COALESCE(?4, read_class),
            write_class = COALESCE(?5, write_class),
            position = COALESCE(?6, position)
         WHERE id = ?1",
        params![id, title, description, read_class, write_class, position],
    )?;
    Ok(n > 0)
}

/// Number of threads (visible or hidden) belonging to `board_id` — the guard
/// [`routes::forum_v2::admin_delete_board`] runs before deleting a board, so
/// deleting one never orphans a thread's `board_id` foreign key.
pub fn board_thread_count(conn: &Connection, board_id: i64) -> Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM forum_threads_v2 WHERE board_id = ?1",
        params![board_id],
        |row| row.get(0),
    )
}

pub fn delete_board(conn: &Connection, id: i64) -> Result<bool> {
    let n = conn.execute("DELETE FROM forum_boards WHERE id = ?1", params![id])?;
    Ok(n > 0)
}

/// One board plus live activity stats (owner ruling 2026-09-09: "the forum
/// must look like a forum" — every board row shows how many threads/posts
/// it holds and when the last activity was). `thread_count`/`reply_count`
/// are recomputed fresh from `forum_threads_v2`/`forum_replies_v2` on every
/// call — NEVER read from `forum_threads_v2.reply_count`, which is a
/// monotonic counter [`create_reply_v2`] only ever increments and never
/// decrements when a reply is later hidden, so it does not track "visible"
/// replies. `last_post_at`/`last_thread_title` name the newest VISIBLE
/// activity on the board — either a thread's own creation or any visible
/// reply on a visible thread — `None` for a board with no visible activity
/// at all (a brand-new board, or one where every thread/reply has been
/// hidden). "Visible" here matches [`list_threads_v2`]/[`list_replies_v2`]'s
/// own `hidden = 0` filter exactly, uniformly for every caller — same as
/// the paged thread list, this does NOT give a moderator a peek at hidden
/// rows (unlike [`get_thread_v2`]'s `include_hidden` override, which is a
/// thread-DETAIL concession, not something the board list makes).
#[derive(Debug, Clone, PartialEq)]
pub struct BoardWithStats {
    pub board: Board,
    pub thread_count: i64,
    pub reply_count: i64,
    pub last_post_at: Option<String>,
    pub last_thread_title: Option<String>,
}

fn board_with_stats_from_row(row: &rusqlite::Row<'_>) -> Result<BoardWithStats> {
    Ok(BoardWithStats {
        board: Board {
            id: row.get(0)?,
            slug: row.get(1)?,
            title: row.get(2)?,
            description: row.get(3)?,
            read_class: row.get(4)?,
            write_class: row.get(5)?,
            position: row.get(6)?,
            created_at: row.get(7)?,
        },
        thread_count: row.get(8)?,
        reply_count: row.get(9)?,
        last_post_at: row.get(10)?,
        last_thread_title: row.get(11)?,
    })
}

/// Every board, ordered by `position` then `id`, each carrying live
/// [`BoardWithStats`] fields — ONE query for the whole list (a `WITH` CTE
/// plus a `ROW_NUMBER()` window function ranks each board's visible
/// activity newest-first; two more CTEs aggregate visible thread/reply
/// counts), never one query per board. `routes::forum_v2::list_boards`
/// filters the result by [`can_read`] afterward (the class ladder lives in
/// Rust, not SQL) — stats are computed here for every board regardless of
/// read gate, same division of labour as [`list_boards`].
pub fn list_boards_with_stats(conn: &Connection) -> Result<Vec<BoardWithStats>> {
    let mut stmt = conn.prepare(
        "WITH activity AS (
            SELECT t.board_id AS board_id, t.id AS thread_id, t.title AS thread_title,
                   t.created_at AS activity_at
            FROM forum_threads_v2 t
            WHERE t.hidden = 0
            UNION ALL
            SELECT t.board_id AS board_id, t.id AS thread_id, t.title AS thread_title,
                   r.created_at AS activity_at
            FROM forum_replies_v2 r
            JOIN forum_threads_v2 t ON t.id = r.thread_id
            WHERE r.hidden = 0 AND t.hidden = 0
        ),
        ranked_activity AS (
            SELECT board_id, thread_title, activity_at,
                   ROW_NUMBER() OVER (
                       PARTITION BY board_id ORDER BY activity_at DESC, thread_id DESC
                   ) AS rn
            FROM activity
        ),
        thread_counts AS (
            SELECT board_id, COUNT(*) AS thread_count
            FROM forum_threads_v2
            WHERE hidden = 0
            GROUP BY board_id
        ),
        reply_counts AS (
            SELECT t.board_id AS board_id, COUNT(*) AS reply_count
            FROM forum_replies_v2 r
            JOIN forum_threads_v2 t ON t.id = r.thread_id
            WHERE r.hidden = 0 AND t.hidden = 0
            GROUP BY t.board_id
        )
        SELECT b.id, b.slug, b.title, b.description, b.read_class, b.write_class, b.position, b.created_at,
               COALESCE(tc.thread_count, 0), COALESCE(rc.reply_count, 0),
               ra.activity_at, ra.thread_title
        FROM forum_boards b
        LEFT JOIN thread_counts tc ON tc.board_id = b.id
        LEFT JOIN reply_counts rc ON rc.board_id = b.id
        LEFT JOIN ranked_activity ra ON ra.board_id = b.id AND ra.rn = 1
        ORDER BY b.position ASC, b.id ASC",
    )?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(board_with_stats_from_row(row)?);
    }
    Ok(out)
}

// ============================================================================
// Threads v2
// ============================================================================

/// One row of the `forum_threads_v2` table.
#[derive(Debug, Clone, PartialEq)]
pub struct ForumThreadV2 {
    pub id: i64,
    pub board_id: i64,
    pub author_user_id: i64,
    pub title: String,
    pub body: String,
    pub created_at: String,
    pub updated_at: String,
    pub last_reply_at: Option<String>,
    pub reply_count: i64,
    pub pinned: bool,
    pub locked: bool,
    pub hidden: bool,
}

const THREAD_V2_SELECT_COLUMNS: &str = "id, board_id, author_user_id, title, body, created_at, \
    updated_at, last_reply_at, reply_count, pinned, locked, hidden";

fn thread_v2_from_row(row: &rusqlite::Row<'_>) -> Result<ForumThreadV2> {
    Ok(ForumThreadV2 {
        id: row.get(0)?,
        board_id: row.get(1)?,
        author_user_id: row.get(2)?,
        title: row.get(3)?,
        body: row.get(4)?,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
        last_reply_at: row.get(7)?,
        reply_count: row.get(8)?,
        pinned: row.get::<_, i64>(9)? != 0,
        locked: row.get::<_, i64>(10)? != 0,
        hidden: row.get::<_, i64>(11)? != 0,
    })
}

/// Create one thread on `board_id`. Validates `title`/`body` with the same
/// rules v1 uses ([`crate::db::is_valid_forum_title`]/
/// [`crate::db::is_valid_forum_body`]) — one validation rule for both forum
/// generations, not a duplicate copy. Returns the new thread's id.
pub fn create_thread_v2(
    conn: &Connection,
    board_id: i64,
    author_user_id: i64,
    title: &str,
    body: &str,
    now: &str,
) -> std::result::Result<i64, ForumError> {
    if !crate::db::is_valid_forum_title(title) {
        return Err(ForumError::InvalidTitle);
    }
    if !crate::db::is_valid_forum_body(body) {
        return Err(ForumError::InvalidBody);
    }
    conn.execute(
        "INSERT INTO forum_threads_v2 (board_id, author_user_id, title, body, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        params![board_id, author_user_id, title, body, now],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Fetch one thread by id. `include_hidden = false` (the default for every
/// non-moderator caller) treats a hidden thread as absent, same
/// "indistinguishable from missing" posture v1's `get_thread` uses.
pub fn get_thread_v2(conn: &Connection, thread_id: i64, include_hidden: bool) -> Result<Option<ForumThreadV2>> {
    let sql = if include_hidden {
        format!("SELECT {THREAD_V2_SELECT_COLUMNS} FROM forum_threads_v2 WHERE id = ?1")
    } else {
        format!("SELECT {THREAD_V2_SELECT_COLUMNS} FROM forum_threads_v2 WHERE id = ?1 AND hidden = 0")
    };
    conn.query_row(&sql, params![thread_id], thread_v2_from_row).optional()
}

/// List threads on `board_id`, pinned first, then by last activity
/// (`COALESCE(last_reply_at, created_at)`) descending, `id DESC` as the
/// tie-break — same keyset cursor shape as [`crate::db::list_threads`].
///
/// Known simplification: the `(activity, id)` cursor does not carry a
/// separate "still in the pinned bucket" marker, so a page boundary that
/// falls inside the pinned set is drawn by activity/id alone, same as the
/// unpinned set. With the handful of pinned threads a board realistically
/// holds this does not lose or duplicate a page's worth of rows in practice;
/// revisit if a board ever pins dozens of threads.
pub fn list_threads_v2(
    conn: &Connection,
    board_id: i64,
    limit: i64,
    before: Option<(&str, i64)>,
) -> Result<Vec<ForumThreadV2>> {
    let activity_expr = "COALESCE(last_reply_at, created_at)";
    let mut sql = format!(
        "SELECT {THREAD_V2_SELECT_COLUMNS} FROM forum_threads_v2 \
         WHERE board_id = ? AND hidden = 0"
    );
    let mut bound: Vec<&dyn ToSql> = vec![&board_id];

    if let Some((activity, id)) = before.as_ref() {
        sql.push_str(&format!(
            " AND ({activity_expr} < ? OR ({activity_expr} = ? AND id < ?))"
        ));
        bound.push(activity as &dyn ToSql);
        bound.push(activity as &dyn ToSql);
        bound.push(id as &dyn ToSql);
    }
    sql.push_str(" ORDER BY pinned DESC, ");
    sql.push_str(activity_expr);
    sql.push_str(" DESC, id DESC LIMIT ?");
    bound.push(&limit as &dyn ToSql);

    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(bound.as_slice())?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(thread_v2_from_row(row)?);
    }
    Ok(out)
}

/// Count of threads `user_id` has created on any board since `since`
/// (RFC3339) — the input to the create-thread rate limit in
/// `routes::forum_v2`.
pub fn threads_v2_created_since(conn: &Connection, user_id: i64, since: &str) -> Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM forum_threads_v2 WHERE author_user_id = ?1 AND created_at > ?2",
        params![user_id, since],
        |row| row.get(0),
    )
}

fn set_thread_flag(conn: &Connection, thread_id: i64, column: &str, value: bool) -> Result<bool> {
    let sql = format!("UPDATE forum_threads_v2 SET {column} = ?2 WHERE id = ?1");
    let n = conn.execute(&sql, params![thread_id, value as i64])?;
    Ok(n > 0)
}

pub fn hide_thread_v2(conn: &Connection, thread_id: i64) -> Result<bool> {
    set_thread_flag(conn, thread_id, "hidden", true)
}
pub fn unhide_thread_v2(conn: &Connection, thread_id: i64) -> Result<bool> {
    set_thread_flag(conn, thread_id, "hidden", false)
}
pub fn lock_thread_v2(conn: &Connection, thread_id: i64) -> Result<bool> {
    set_thread_flag(conn, thread_id, "locked", true)
}
pub fn unlock_thread_v2(conn: &Connection, thread_id: i64) -> Result<bool> {
    set_thread_flag(conn, thread_id, "locked", false)
}
pub fn pin_thread_v2(conn: &Connection, thread_id: i64) -> Result<bool> {
    set_thread_flag(conn, thread_id, "pinned", true)
}
pub fn unpin_thread_v2(conn: &Connection, thread_id: i64) -> Result<bool> {
    set_thread_flag(conn, thread_id, "pinned", false)
}

pub fn move_thread_v2(conn: &Connection, thread_id: i64, new_board_id: i64) -> Result<bool> {
    let n = conn.execute(
        "UPDATE forum_threads_v2 SET board_id = ?2 WHERE id = ?1",
        params![thread_id, new_board_id],
    )?;
    Ok(n > 0)
}

// ============================================================================
// Replies v2
// ============================================================================

/// One row of the `forum_replies_v2` table.
#[derive(Debug, Clone, PartialEq)]
pub struct ForumReplyV2 {
    pub id: i64,
    pub thread_id: i64,
    pub parent_reply_id: Option<i64>,
    pub author_user_id: i64,
    pub body: String,
    pub created_at: String,
    pub hidden: bool,
    pub depth: i64,
}

const REPLY_V2_SELECT_COLUMNS: &str =
    "id, thread_id, parent_reply_id, author_user_id, body, created_at, hidden, depth";

fn reply_v2_from_row(row: &rusqlite::Row<'_>) -> Result<ForumReplyV2> {
    Ok(ForumReplyV2 {
        id: row.get(0)?,
        thread_id: row.get(1)?,
        parent_reply_id: row.get(2)?,
        author_user_id: row.get(3)?,
        body: row.get(4)?,
        created_at: row.get(5)?,
        hidden: row.get::<_, i64>(6)? != 0,
        depth: row.get(7)?,
    })
}

/// Why [`create_reply_v2`] was refused before ever touching the database, on
/// top of [`ForumError`] — a bad `parent_reply_id` is a v2-only concern (v1
/// has no reply tree).
#[derive(Debug)]
pub enum ReplyError {
    Forum(ForumError),
    /// `parent_reply_id` named a reply that does not exist, is hidden, or
    /// belongs to a different thread than the one being replied to.
    ParentNotFound,
}

impl From<rusqlite::Error> for ReplyError {
    fn from(e: rusqlite::Error) -> Self {
        ReplyError::Forum(ForumError::Db(e))
    }
}

/// Create one reply under `thread_id`, optionally nested under
/// `parent_reply_id` (`None` = top level, `depth = 0`). Bumps the thread's
/// `reply_count`/`last_reply_at`/`updated_at`. Does NOT check that
/// `thread_id` exists, is visible, or is unlocked — the route calls
/// [`get_thread_v2`] first, same division of labour v1 uses. Returns the new
/// reply's id.
pub fn create_reply_v2(
    conn: &Connection,
    thread_id: i64,
    parent_reply_id: Option<i64>,
    author_user_id: i64,
    body: &str,
    now: &str,
) -> std::result::Result<i64, ReplyError> {
    if !crate::db::is_valid_forum_body(body) {
        return Err(ReplyError::Forum(ForumError::InvalidBody));
    }
    let depth = match parent_reply_id {
        None => 0,
        Some(parent_id) => {
            let parent: Option<(i64, i64)> = conn
                .query_row(
                    "SELECT thread_id, depth FROM forum_replies_v2 WHERE id = ?1 AND hidden = 0",
                    params![parent_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            match parent {
                Some((parent_thread_id, parent_depth)) if parent_thread_id == thread_id => parent_depth + 1,
                _ => return Err(ReplyError::ParentNotFound),
            }
        }
    };
    conn.execute(
        "INSERT INTO forum_replies_v2 (thread_id, parent_reply_id, author_user_id, body, created_at, depth)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![thread_id, parent_reply_id, author_user_id, body, now, depth],
    )?;
    let reply_id = conn.last_insert_rowid();
    conn.execute(
        "UPDATE forum_threads_v2
         SET reply_count = reply_count + 1, last_reply_at = ?2, updated_at = ?2
         WHERE id = ?1",
        params![thread_id, now],
    )?;
    Ok(reply_id)
}

/// List replies to `thread_id`, oldest first — the order [`assemble_reply_tree`]
/// depends on for deterministic child ordering within each parent.
/// `include_hidden = true` for a moderator viewing a thread; `false`
/// otherwise.
pub fn list_replies_v2(conn: &Connection, thread_id: i64, include_hidden: bool) -> Result<Vec<ForumReplyV2>> {
    let sql = if include_hidden {
        format!("SELECT {REPLY_V2_SELECT_COLUMNS} FROM forum_replies_v2 WHERE thread_id = ?1 ORDER BY id ASC")
    } else {
        format!(
            "SELECT {REPLY_V2_SELECT_COLUMNS} FROM forum_replies_v2 \
             WHERE thread_id = ?1 AND hidden = 0 ORDER BY id ASC"
        )
    };
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(params![thread_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(reply_v2_from_row(row)?);
    }
    Ok(out)
}

/// Count of replies `user_id` has created since `since` (RFC3339) — the
/// input to the create-reply rate limit in `routes::forum_v2`.
pub fn replies_v2_created_since(conn: &Connection, user_id: i64, since: &str) -> Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM forum_replies_v2 WHERE author_user_id = ?1 AND created_at > ?2",
        params![user_id, since],
        |row| row.get(0),
    )
}

/// Hide one reply. `owner_user_id = Some(uid)` requires `uid` to be the
/// reply's author (self-service delete); `None` hides unconditionally (a
/// moderator/admin caller — `routes::forum_v2` has already checked
/// [`is_moderator_or_admin`]). Same "no distinguishable states" contract as
/// v1's `db::hide_reply`.
pub fn delete_reply_v2(conn: &Connection, reply_id: i64, owner_user_id: Option<i64>) -> Result<bool> {
    let n = match owner_user_id {
        Some(uid) => conn.execute(
            "UPDATE forum_replies_v2 SET hidden = 1 WHERE id = ?1 AND author_user_id = ?2 AND hidden = 0",
            params![reply_id, uid],
        )?,
        None => conn.execute(
            "UPDATE forum_replies_v2 SET hidden = 1 WHERE id = ?1 AND hidden = 0",
            params![reply_id],
        )?,
    };
    Ok(n > 0)
}

// ============================================================================
// Reply tree assembly (pure — no database access)
// ============================================================================

/// One reply plus its nested children, built by [`assemble_reply_tree`].
#[derive(Debug, Clone, PartialEq)]
pub struct ReplyNode {
    pub reply: ForumReplyV2,
    pub children: Vec<ReplyNode>,
}

/// Build the reply tree from a flat list ordered oldest-first (the order
/// [`list_replies_v2`] returns). Top-level replies (`parent_reply_id ==
/// None`) become the roots; every other reply nests under its parent.
/// Children preserve the input's relative order (oldest first) because each
/// parent's bucket is built by pushing in input order — no re-sort.
///
/// A reply whose `parent_reply_id` names an id absent from `replies` (should
/// not happen — [`create_reply_v2`] verifies the parent exists in the same
/// thread before insert) is silently dropped from the tree rather than
/// panicking; the input list is exactly what [`list_replies_v2`] returned,
/// so this is the caller (i.e. this module) trusting its own writer.
pub fn assemble_reply_tree(replies: Vec<ForumReplyV2>) -> Vec<ReplyNode> {
    use std::collections::HashMap;

    let mut children_of: HashMap<Option<i64>, Vec<ForumReplyV2>> = HashMap::new();
    for reply in replies {
        children_of.entry(reply.parent_reply_id).or_default().push(reply);
    }

    fn build(parent: Option<i64>, children_of: &mut HashMap<Option<i64>, Vec<ForumReplyV2>>) -> Vec<ReplyNode> {
        let Some(bucket) = children_of.remove(&parent) else {
            return Vec::new();
        };
        bucket
            .into_iter()
            .map(|reply| {
                let id = reply.id;
                let children = build(Some(id), children_of);
                ReplyNode { reply, children }
            })
            .collect()
    }

    build(None, &mut children_of)
}

// ============================================================================
// Search (FTS5)
// ============================================================================

/// One search hit — either a thread (title match) or a reply (body match).
#[derive(Debug, Clone, PartialEq)]
pub struct SearchHit {
    pub kind: &'static str,
    pub board_id: i64,
    pub thread_id: i64,
    pub reply_id: Option<i64>,
    pub title: Option<String>,
    pub snippet: String,
    pub author_user_id: i64,
    pub created_at: String,
}

/// Length rule for a search query: 1-200 characters.
pub fn is_valid_search_query(q: &str) -> bool {
    (1..=200).contains(&q.chars().count())
}

/// Turn a free-text query into a safe FTS5 `MATCH` argument: each whitespace-
/// separated token is quoted (doubling any embedded `"`), so FTS5 syntax
/// characters in user input (`-`, `:`, `*`, `(`, …) are treated as literal
/// text rather than query operators. Tokens are ANDed together (FTS5's
/// default for adjacent quoted phrases). Empty input (all-whitespace, or
/// tokens that were entirely quote characters) yields the empty string —
/// callers must check for that before running a query.
fn sanitize_fts_query(q: &str) -> String {
    q.split_whitespace()
        .map(|tok| format!("\"{}\"", tok.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Search threads (title/body) and replies (body) restricted to
/// `board_ids` — the boards the caller may read, already filtered by
/// [`can_read`] — and merge the results newest-first, capped at `limit`.
/// Returns no rows (no query run at all) if `board_ids` is empty.
pub fn search(conn: &Connection, query: &str, board_ids: &[i64], limit: i64) -> Result<Vec<SearchHit>> {
    if board_ids.is_empty() {
        return Ok(Vec::new());
    }
    let fts_query = sanitize_fts_query(query);
    if fts_query.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = board_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");

    let mut hits = Vec::new();

    let thread_sql = format!(
        "SELECT t.board_id, t.id, t.title, t.author_user_id, t.created_at,
                snippet(forum_threads_fts, -1, '[', ']', '...', 12)
         FROM forum_threads_fts
         JOIN forum_threads_v2 t ON t.id = forum_threads_fts.rowid
         WHERE forum_threads_fts MATCH ? AND t.hidden = 0 AND t.board_id IN ({placeholders})
         ORDER BY t.created_at DESC
         LIMIT ?"
    );
    let mut bound: Vec<&dyn ToSql> = vec![&fts_query];
    for id in board_ids {
        bound.push(id as &dyn ToSql);
    }
    bound.push(&limit as &dyn ToSql);
    {
        let mut stmt = conn.prepare(&thread_sql)?;
        let mut rows = stmt.query(bound.as_slice())?;
        while let Some(row) = rows.next()? {
            hits.push(SearchHit {
                kind: "thread",
                board_id: row.get(0)?,
                thread_id: row.get(1)?,
                reply_id: None,
                title: Some(row.get(2)?),
                author_user_id: row.get(3)?,
                created_at: row.get(4)?,
                snippet: row.get(5)?,
            });
        }
    }

    let reply_sql = format!(
        "SELECT th.board_id, r.thread_id, r.id, r.author_user_id, r.created_at,
                snippet(forum_replies_fts, -1, '[', ']', '...', 12)
         FROM forum_replies_fts
         JOIN forum_replies_v2 r ON r.id = forum_replies_fts.rowid
         JOIN forum_threads_v2 th ON th.id = r.thread_id
         WHERE forum_replies_fts MATCH ? AND r.hidden = 0 AND th.hidden = 0 AND th.board_id IN ({placeholders})
         ORDER BY r.created_at DESC
         LIMIT ?"
    );
    let mut bound: Vec<&dyn ToSql> = vec![&fts_query];
    for id in board_ids {
        bound.push(id as &dyn ToSql);
    }
    bound.push(&limit as &dyn ToSql);
    {
        let mut stmt = conn.prepare(&reply_sql)?;
        let mut rows = stmt.query(bound.as_slice())?;
        while let Some(row) = rows.next()? {
            hits.push(SearchHit {
                kind: "reply",
                board_id: row.get(0)?,
                thread_id: row.get(1)?,
                reply_id: Some(row.get(2)?),
                title: None,
                author_user_id: row.get(3)?,
                created_at: row.get(4)?,
                snippet: row.get(5)?,
            });
        }
    }

    hits.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    hits.truncate(limit.max(0) as usize);
    Ok(hits)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        create_social_schema(&conn).expect("schema");
        conn
    }

    fn reply(id: i64, parent: Option<i64>, thread_id: i64, body: &str) -> ForumReplyV2 {
        ForumReplyV2 {
            id,
            thread_id,
            parent_reply_id: parent,
            author_user_id: 1,
            body: body.to_string(),
            created_at: "2026-09-06T00:00:00+00:00".to_string(),
            hidden: false,
            depth: 0,
        }
    }

    // ---- Class ranking ----

    #[test]
    fn class_rank_orders_public_below_admin() {
        assert!(Class::Public < Class::User);
        assert!(Class::User < Class::Paid);
        assert!(Class::Paid < Class::Trusted);
        assert!(Class::Trusted < Class::Moderator);
        assert!(Class::Moderator < Class::Admin);
    }

    #[test]
    fn class_rank_values_match_ladder_position() {
        assert_eq!(Class::Public.rank(), 0);
        assert_eq!(Class::User.rank(), 1);
        assert_eq!(Class::Paid.rank(), 2);
        assert_eq!(Class::Trusted.rank(), 3);
        assert_eq!(Class::Moderator.rank(), 4);
        assert_eq!(Class::Admin.rank(), 5);
    }

    #[test]
    fn class_wire_names_roundtrip() {
        for c in [
            Class::Public,
            Class::User,
            Class::Paid,
            Class::Trusted,
            Class::Moderator,
            Class::Admin,
        ] {
            assert_eq!(Class::from_wire_name(c.as_str()), Some(c));
        }
        assert_eq!(Class::from_wire_name("bogus"), None);
    }

    // ---- caller_classes: cumulative ladder for each rank ----

    #[test]
    fn caller_classes_anonymous_is_public_only() {
        let conn = test_conn();
        assert_eq!(caller_classes(&conn, None, false), vec![Class::Public]);
    }

    #[test]
    fn caller_classes_signed_in_unpaid_adds_user() {
        let conn = test_conn();
        assert_eq!(caller_classes(&conn, Some(1), false), vec![Class::Public, Class::User]);
    }

    #[test]
    fn caller_classes_paid_adds_paid() {
        let conn = test_conn();
        assert_eq!(
            caller_classes(&conn, Some(1), true),
            vec![Class::Public, Class::User, Class::Paid]
        );
    }

    #[test]
    fn caller_classes_trusted_row_adds_trusted() {
        let conn = test_conn();
        set_trusted(&conn, 2, Some("owner grant"), "2026-09-09T00:00:00+00:00").expect("set trusted");
        assert_eq!(
            caller_classes(&conn, Some(2), true),
            vec![Class::Public, Class::User, Class::Paid, Class::Trusted]
        );
        // Trusted without paid: rank is still Trusted (3), which sits above
        // Paid (2) on the ladder, so the cumulative list includes Paid too.
        assert_eq!(
            caller_classes(&conn, Some(2), false),
            vec![Class::Public, Class::User, Class::Paid, Class::Trusted]
        );
    }

    #[test]
    fn caller_classes_role_row_is_cumulative_through_moderator_and_admin() {
        let conn = test_conn();
        set_role(&conn, 7, Role::Moderator, "2026-09-06T00:00:00+00:00").expect("set role");
        // A moderator's classes reach every rank up to Moderator (4), even
        // though this account is neither paid nor flagged trusted — the
        // ladder's rank, not a per-class flag union, is the source of truth.
        assert_eq!(
            caller_classes(&conn, Some(7), false),
            vec![Class::Public, Class::User, Class::Paid, Class::Trusted, Class::Moderator]
        );

        set_role(&conn, 8, Role::Admin, "2026-09-06T00:00:00+00:00").expect("set role");
        assert_eq!(
            caller_classes(&conn, Some(8), true),
            vec![
                Class::Public,
                Class::User,
                Class::Paid,
                Class::Trusted,
                Class::Moderator,
                Class::Admin
            ]
        );
    }

    // ---- can_read / can_write ----

    fn board_fixture(read_class: Class, write_class: Class) -> Board {
        Board {
            id: 1,
            slug: "test".to_string(),
            title: "Test".to_string(),
            description: String::new(),
            read_class,
            write_class,
            position: 0,
            created_at: "2026-09-06T00:00:00+00:00".to_string(),
        }
    }

    #[test]
    fn can_read_requires_at_least_the_board_class() {
        let board = board_fixture(Class::Paid, Class::Admin);
        assert!(!can_read(&board, &[Class::Public]));
        assert!(!can_read(&board, &[Class::Public, Class::User]));
        assert!(can_read(&board, &[Class::Public, Class::User, Class::Paid]));
        // Admin's rank exceeds Paid, so it satisfies a Paid gate too.
        assert!(can_read(&board, &[Class::Public, Class::User, Class::Admin]));
    }

    #[test]
    fn can_write_requires_at_least_the_board_class() {
        let board = board_fixture(Class::Public, Class::Paid);
        assert!(!can_write(&board, &[Class::Public, Class::User]));
        assert!(can_write(&board, &[Class::Public, Class::User, Class::Paid]));
        assert!(can_write(&board, &[Class::Public, Class::User, Class::Moderator]));
    }

    #[test]
    fn is_moderator_or_admin_matches_rank() {
        assert!(!is_moderator_or_admin(&[Class::Public, Class::User, Class::Paid]));
        assert!(is_moderator_or_admin(&[Class::Public, Class::User, Class::Moderator]));
        assert!(is_moderator_or_admin(&[Class::Public, Class::User, Class::Admin]));
    }

    // ---- ladder scenarios from the plan's owner-approved test list ----

    #[test]
    fn moderator_reads_staff_but_not_admins() {
        let conn = test_conn();
        let staff = get_board_by_slug(&conn, "staff").expect("query").expect("staff board seeded");
        let admins = get_board_by_slug(&conn, "admins").expect("query").expect("admins board seeded");
        let moderator_classes =
            vec![Class::Public, Class::User, Class::Paid, Class::Trusted, Class::Moderator];
        assert!(can_read(&staff, &moderator_classes));
        assert!(!can_read(&admins, &moderator_classes));
    }

    #[test]
    fn trusted_paid_user_writes_trusted_and_paid_boards() {
        let conn = test_conn();
        let trusted_board = get_board_by_slug(&conn, "trusted").expect("query").expect("trusted board seeded");
        let paid_board = get_board_by_slug(&conn, "paid").expect("query").expect("paid board seeded");
        let trusted_paid_classes = vec![Class::Public, Class::User, Class::Paid, Class::Trusted];
        assert!(can_write(&trusted_board, &trusted_paid_classes));
        assert!(can_write(&paid_board, &trusted_paid_classes));
    }

    #[test]
    fn admin_only_write_on_announcements_refuses_a_paid_caller() {
        let conn = test_conn();
        let announcements =
            get_board_by_slug(&conn, "announcements").expect("query").expect("announcements board seeded");
        let paid_classes = vec![Class::Public, Class::User, Class::Paid];
        assert!(can_read(&announcements, &paid_classes));
        assert!(!can_write(&announcements, &paid_classes));
    }

    // ---- seed idempotency ----

    #[test]
    fn seed_boards_is_idempotent_and_never_overwrites_existing_rows() {
        let conn = test_conn();
        // Re-running the seed (as every boot does) must not duplicate rows
        // or change an existing board's title/classes.
        create_social_schema(&conn).expect("schema re-run");
        let boards = list_boards(&conn).expect("list boards");
        assert_eq!(boards.len(), 7);

        let expected: &[(&str, Class, Class)] = &[
            ("announcements", Class::Public, Class::Admin),
            ("general", Class::Public, Class::Paid),
            ("members", Class::User, Class::User),
            ("paid", Class::Paid, Class::Paid),
            ("trusted", Class::Trusted, Class::Trusted),
            ("staff", Class::Moderator, Class::Moderator),
            ("admins", Class::Admin, Class::Admin),
        ];
        for (slug, read_class, write_class) in expected {
            let board = boards.iter().find(|b| b.slug == *slug).unwrap_or_else(|| panic!("{slug} board seeded"));
            assert_eq!(board.read_class, *read_class, "{slug} read_class");
            assert_eq!(board.write_class, *write_class, "{slug} write_class");
        }
    }

    // ---- tree assembly ----

    #[test]
    fn assemble_reply_tree_nests_by_parent_and_preserves_order() {
        // Thread with: r1 (top), r2 (top), r3 (child of r1), r4 (child of r3).
        let replies = vec![
            reply(1, None, 10, "top one"),
            reply(2, None, 10, "top two"),
            reply(3, Some(1), 10, "child of one"),
            reply(4, Some(3), 10, "grandchild"),
        ];
        let tree = assemble_reply_tree(replies);

        assert_eq!(tree.len(), 2);
        assert_eq!(tree[0].reply.id, 1);
        assert_eq!(tree[1].reply.id, 2);
        assert!(tree[1].children.is_empty());

        assert_eq!(tree[0].children.len(), 1);
        assert_eq!(tree[0].children[0].reply.id, 3);
        assert_eq!(tree[0].children[0].children.len(), 1);
        assert_eq!(tree[0].children[0].children[0].reply.id, 4);
        assert!(tree[0].children[0].children[0].children.is_empty());
    }

    #[test]
    fn assemble_reply_tree_drops_orphans_with_unknown_parent() {
        // r2 names a parent (99) absent from the list — dropped, not panicking.
        let replies = vec![reply(1, None, 10, "top"), reply(2, Some(99), 10, "orphan")];
        let tree = assemble_reply_tree(replies);
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].reply.id, 1);
        assert!(tree[0].children.is_empty());
    }

    // ---- list_boards_with_stats: live counts + newest-activity tracking ----

    #[test]
    fn list_boards_with_stats_empty_board_yields_zero_counts_and_null_activity() {
        let conn = test_conn();
        let stats = list_boards_with_stats(&conn).expect("list with stats");
        let general = stats.iter().find(|s| s.board.slug == "general").expect("general stats");
        assert_eq!(general.thread_count, 0);
        assert_eq!(general.reply_count, 0);
        assert_eq!(general.last_post_at, None);
        assert_eq!(general.last_thread_title, None);
    }

    #[test]
    fn list_boards_with_stats_counts_exclude_hidden_and_track_latest_activity() {
        let conn = test_conn();
        let general = get_board_by_slug(&conn, "general").expect("query").expect("general board seeded");

        let t1 = create_thread_v2(&conn, general.id, 1, "First thread", "body one", "2026-09-09T00:00:00+00:00")
            .expect("create thread 1");
        let t2 = create_thread_v2(&conn, general.id, 1, "Second thread", "body two", "2026-09-09T01:00:00+00:00")
            .expect("create thread 2");
        create_reply_v2(&conn, t1, None, 2, "a reply", "2026-09-09T02:00:00+00:00").expect("create reply");

        let stats = list_boards_with_stats(&conn).expect("list with stats");
        let general_stats = stats.iter().find(|s| s.board.slug == "general").expect("general stats");
        assert_eq!(general_stats.thread_count, 2);
        assert_eq!(general_stats.reply_count, 1);
        assert_eq!(general_stats.last_post_at.as_deref(), Some("2026-09-09T02:00:00+00:00"));
        assert_eq!(general_stats.last_thread_title.as_deref(), Some("First thread"));

        // Hide the reply: reply_count drops, and the newest visible activity
        // falls back to the second thread's own creation time — not the now-
        // hidden reply, even though its row still exists in the table.
        let reply_id: i64 = conn
            .query_row("SELECT id FROM forum_replies_v2 WHERE thread_id = ?1", params![t1], |row| row.get(0))
            .expect("reply id");
        delete_reply_v2(&conn, reply_id, None).expect("hide reply");
        let stats = list_boards_with_stats(&conn).expect("list with stats");
        let general_stats = stats.iter().find(|s| s.board.slug == "general").expect("general stats");
        assert_eq!(general_stats.thread_count, 2);
        assert_eq!(general_stats.reply_count, 0);
        assert_eq!(general_stats.last_post_at.as_deref(), Some("2026-09-09T01:00:00+00:00"));
        assert_eq!(general_stats.last_thread_title.as_deref(), Some("Second thread"));

        // Hide both threads too: the board goes back to zero counts and null
        // activity even though the rows are still in the table.
        hide_thread_v2(&conn, t1).expect("hide t1");
        hide_thread_v2(&conn, t2).expect("hide t2");
        let stats = list_boards_with_stats(&conn).expect("list with stats");
        let general_stats = stats.iter().find(|s| s.board.slug == "general").expect("general stats");
        assert_eq!(general_stats.thread_count, 0);
        assert_eq!(general_stats.reply_count, 0);
        assert_eq!(general_stats.last_post_at, None);
        assert_eq!(general_stats.last_thread_title, None);
    }

    #[test]
    fn list_boards_with_stats_covers_every_seeded_board_ordered_by_position() {
        let conn = test_conn();
        let stats = list_boards_with_stats(&conn).expect("list with stats");
        assert_eq!(stats.len(), 7);
        let positions: Vec<i64> = stats.iter().map(|s| s.board.position).collect();
        let mut sorted = positions.clone();
        sorted.sort();
        assert_eq!(positions, sorted, "rows must already come back position-ordered");
    }

    // ---- schema smoke test (boards seeded, FTS5 present) ----

    #[test]
    fn schema_seeds_classes_and_boards_and_fts5_is_queryable() {
        let conn = test_conn();
        let boards = list_boards(&conn).expect("list boards");
        assert_eq!(boards.len(), 7);
        let general = boards.iter().find(|b| b.slug == "general").expect("general board");
        assert_eq!(general.read_class, Class::Public);
        assert_eq!(general.write_class, Class::Paid);
        let paid = boards.iter().find(|b| b.slug == "paid").expect("paid board");
        assert_eq!(paid.read_class, Class::Paid);

        let thread_id =
            create_thread_v2(&conn, general.id, 1, "Hello world", "First post body", "2026-09-06T00:00:00+00:00")
                .expect("create thread");
        let hits = search(&conn, "hello", &[general.id], 10).expect("search");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].thread_id, thread_id);
    }
}

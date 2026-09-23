//! Community messenger storage — `conversations`/`kind IN ('dm','group',
//! 'channel')`, one object model for direct messages, private groups, and
//! public channels (owner-approved plan, `docs/mlc/plans/community-
//! messenger-arc-2026-09-24.md` §1.1-§1.4). Lives in `social.db`, next to
//! `dm_*`/`forum_*`/`shared_presets*` (same storage split `social_db.rs`
//! documents), created by [`create_conversations_schema`], called from
//! `social_db::init_social_db` right after `dm_db::create_dm_schema`.
//!
//! This module compiles as part of this package's library target
//! (`lib.rs`), not the `mylittlechart-server` binary crate `dm_db.rs`/
//! `social_db.rs` live in — see `lib.rs`'s doc for why. It therefore cannot
//! name `dm_db` as a Rust dependency; anywhere it would otherwise say
//! `dm_db::X`, it duplicates the tiny piece it needs by hand instead (see
//! "Local mirrors of `dm_db` constants" below) and reads/writes
//! `dm_db`'s own tables (`dm_identity_keys`) purely as SQL against the
//! same `social.db` connection, which needs no Rust-level link at all.
//!
//! # Relationship to `dm_db.rs`
//!
//! This module does **not** replace `dm_db.rs` — `dm_conversations`/
//! `dm_messages`/`dm_identity_keys` and `routes::dm` stay exactly as they
//! are; the plan's migration (§1.8) that copies old DM rows into this
//! module's tables is a separate piece (S6 of the plan's work split, not
//! built here). What this module DOES reuse from `dm_db.rs` is the identity
//! keypair table itself: a group's per-member key wrap (§1.2) is wrapped
//! under the same `dm_identity_keys` row a DM conversation already
//! resolves — there is no second "messaging identity" table for groups.
//! [`has_identity_key`] is the one place this module reads `dm_identity_keys`.
//!
//! # What the server can and cannot see
//!
//! Same posture `dm_db.rs`'s module doc states, per conversation kind:
//! - **dm/group**: `conversation_messages.nonce`/`ciphertext` are opaque
//!   AES-256-GCM output (`mlc_vault`'s `DmCiphertext` shape) — this module
//!   never sees plaintext. A group's raw key never touches this process
//!   either — only `group_key_wraps.ciphertext`, itself an opaque seal of
//!   32 key bytes under a per-member ECDH wrap.
//! - **channel**: `body` is plaintext (posts are meant to be publicly
//!   readable) with an Ed25519 `signature` over it the server stores and
//!   returns verbatim but never itself verifies (a client-side trust
//!   decision — see [`create_signed_message`]'s doc).
//! - **always plaintext, every kind**: `sender_user_id`, timestamps,
//!   `conversation_reactions` (coordinator ruling, plan §7/§6.1 — a
//!   reaction is server-visible metadata, same posture `dm_messages.
//!   read_at` already has today).
//!
//! # Group re-key (plan §1.2, coordinator ruling §7/§6.2)
//!
//! Removing a member always re-keys: [`remove_member_and_rekey`] deletes the
//! membership row, inserts the next `group_key_epochs` row, and inserts one
//! `group_key_wraps` row per REMAINING member, all in one transaction —
//! refusing (before ever committing) a non-sequential epoch or a wrap count
//! that does not match the remaining membership exactly, so a client can
//! never leave a group half-rekeyed. Adding a member never re-keys — a new
//! member's own wrap ([`insert_group_key_wrap`]) covers only the epoch
//! current at join time, never history (Signal-style forward secrecy).
//! Editing a sealed message is refused once the group has re-keyed past
//! that message's own epoch ([`edit_sealed_message`]) — the coordinator's
//! ruling that an edit must never widen a message's original audience.
//!
//! # Cross-database rule (plan §5, restated from `social_db.rs`)
//!
//! Only `user_id` integers are ever stored here — never a display name. A
//! caller's label is resolved live from the identity connection by
//! `routes::conversations`, never joined against in SQL.

use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use rusqlite::{params, Connection, OptionalExtension, Result};

// ============================================================================
// Local mirrors of `dm_db` constants
// ============================================================================
//
// This module cannot depend on `dm_db.rs` (see the module doc) — these
// three values duplicate `dm_db::DM_NONCE_LEN`/`dm_db::DM_PUBLIC_KEY_LEN`/
// `dm_db::DM_MAX_CIPHERTEXT_BYTES` and `dm_db::ordered_pair`'s logic
// exactly, by hand, the same documented-not-derived pattern `src/bin/
// mlc-dbadmin.rs`'s `HOT_CATEGORIES` already uses in this crate for the
// identical "one binary/library cannot import another's binary crate"
// problem. MUST stay equal — both describe the same `mlc_vault::dm::
// DmCiphertext` wire shape and the same ordered-pair trick.

/// AES-256-GCM nonce length — mirrors `DM_NONCE_LEN`.
const DM_NONCE_LEN: usize = 12;
/// X25519 public key length — mirrors `dm_db::DM_PUBLIC_KEY_LEN`. Used only
/// by this module's own tests (publishing a fake `dm_identity_keys` row).
#[cfg(test)]
const DM_PUBLIC_KEY_LEN: usize = 32;
/// Ceiling on one sealed message's ciphertext — mirrors `dm_db::
/// DM_MAX_CIPHERTEXT_BYTES`.
const DM_MAX_CIPHERTEXT_BYTES: usize = 16 * 1024;

/// Sort two user ids into `(lo, hi)` — mirrors `dm_db::ordered_pair`.
fn ordered_pair(a: i64, b: i64) -> (i64, i64) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

// ============================================================================
// Schema
// ============================================================================

/// Create every conversations-messenger table and index this module needs —
/// idempotent (`IF NOT EXISTS` throughout), so it runs on every boot. Called
/// from `social_db::init_social_db` right after `dm_db::create_dm_schema`,
/// and directly by this module's own tests against a plain in-memory
/// connection that already ran this module's own `dm_identity_keys`-only
/// test schema helper (this module's `has_identity_key`/group-wrap paths
/// read `dm_identity_keys`).
pub fn create_conversations_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS conversations (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            kind             TEXT NOT NULL,                  -- 'dm' | 'group' | 'channel'
            title            TEXT,                            -- NULL for dm (peer label computed client-side)
            description      TEXT,
            visibility       TEXT NOT NULL DEFAULT 'private',  -- 'private' | 'public' (channel only)
            comments_enabled INTEGER NOT NULL DEFAULT 1,       -- channel only
            members_can_add  INTEGER NOT NULL DEFAULT 0,       -- group only ("Members can add people")
            created_by       INTEGER NOT NULL,
            created_at       TEXT NOT NULL,
            last_message_at  TEXT,
            dm_pair_key      TEXT UNIQUE,                      -- "<lo>:<hi>" for kind='dm', NULL otherwise
            legacy_dm_id     INTEGER UNIQUE                    -- back-pointer set by the S6 migration, NULL for native rows
        );
        CREATE INDEX IF NOT EXISTS idx_conversations_kind ON conversations(kind);

        CREATE TABLE IF NOT EXISTS conversation_members (
            conversation_id INTEGER NOT NULL REFERENCES conversations(id),
            user_id         INTEGER NOT NULL,
            role            TEXT NOT NULL,                -- 'owner' | 'admin' | 'member' | 'subscriber'
            joined_at       TEXT NOT NULL,
            read_cursor_id  INTEGER NOT NULL DEFAULT 0,   -- highest conversation_messages.id read
            muted_until     TEXT,                          -- NULL=not muted, RFC3339, or the sentinel 'forever'
            pinned          INTEGER NOT NULL DEFAULT 0,   -- pinned to top of THIS caller's own chat list
            archived        INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (conversation_id, user_id)
        );
        CREATE INDEX IF NOT EXISTS idx_conversation_members_user ON conversation_members(user_id);

        CREATE TABLE IF NOT EXISTS conversation_messages (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER NOT NULL REFERENCES conversations(id),
            sender_user_id  INTEGER NOT NULL,
            nonce           BLOB,      -- dm/group only
            ciphertext      BLOB,      -- dm/group only
            epoch           INTEGER,   -- group only: which group_key_epochs row sealed this row
            body            TEXT,      -- channel only: plaintext MessagePayload JSON
            signature       BLOB,      -- channel only: Ed25519(body) under author's channel_signing_keys row
            reply_to_id     INTEGER REFERENCES conversation_messages(id),
            edited_at       TEXT,
            deleted_at      TEXT,
            pinned_at       TEXT,
            created_at      TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_conversation_messages_conv ON conversation_messages(conversation_id, id);

        CREATE TABLE IF NOT EXISTS conversation_reactions (
            message_id INTEGER NOT NULL REFERENCES conversation_messages(id),
            user_id    INTEGER NOT NULL,
            emoji      TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (message_id, user_id, emoji)
        );

        CREATE TABLE IF NOT EXISTS group_key_epochs (
            conversation_id INTEGER NOT NULL REFERENCES conversations(id),
            epoch           INTEGER NOT NULL,   -- 1, 2, 3... strictly increasing per conversation
            created_at      TEXT NOT NULL,
            created_by      INTEGER NOT NULL,
            PRIMARY KEY (conversation_id, epoch)
        );
        CREATE TABLE IF NOT EXISTS group_key_wraps (
            conversation_id    INTEGER NOT NULL REFERENCES conversations(id),
            epoch              INTEGER NOT NULL,
            member_user_id     INTEGER NOT NULL,
            wrapper_public_key BLOB NOT NULL,   -- wrapping sender's OWN dm_identity_keys.public_key at wrap time
            nonce              BLOB NOT NULL,
            ciphertext         BLOB NOT NULL,   -- AES-256-GCM(raw 32-byte group key) under ECDH(wrapper, member)
            created_at         TEXT NOT NULL,
            PRIMARY KEY (conversation_id, epoch, member_user_id)
        );
        CREATE INDEX IF NOT EXISTS idx_group_key_wraps_member ON group_key_wraps(member_user_id, conversation_id);

        CREATE TABLE IF NOT EXISTS channel_signing_keys (
            user_id     INTEGER PRIMARY KEY,
            public_key  BLOB NOT NULL,   -- Ed25519 verifying key, 32 bytes
            created_at  TEXT NOT NULL,
            rotated_at  TEXT
        );

        CREATE TABLE IF NOT EXISTS conversation_folders (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id               INTEGER NOT NULL,
            name                  TEXT NOT NULL,
            icon                  TEXT NOT NULL DEFAULT 'folder',
            position              INTEGER NOT NULL,
            include_all_dms       INTEGER NOT NULL DEFAULT 0,
            include_all_groups    INTEGER NOT NULL DEFAULT 0,
            include_all_channels  INTEGER NOT NULL DEFAULT 0,
            exclude_muted         INTEGER NOT NULL DEFAULT 0,
            exclude_read          INTEGER NOT NULL DEFAULT 0,
            exclude_archived      INTEGER NOT NULL DEFAULT 0,
            created_at            TEXT NOT NULL,
            updated_at            TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS conversation_folder_chats (
            folder_id       INTEGER NOT NULL REFERENCES conversation_folders(id),
            conversation_id INTEGER NOT NULL REFERENCES conversations(id),
            PRIMARY KEY (folder_id, conversation_id)
        );
        "#,
    )
}

// ============================================================================
// Kind / role / visibility enums — same FromSql/ToSql shape as
// `social_db::Class`/`Role`.
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationKind {
    Dm,
    Group,
    Channel,
}

impl ConversationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ConversationKind::Dm => "dm",
            ConversationKind::Group => "group",
            ConversationKind::Channel => "channel",
        }
    }

    pub fn from_wire_name(s: &str) -> Option<Self> {
        match s {
            "dm" => Some(ConversationKind::Dm),
            "group" => Some(ConversationKind::Group),
            "channel" => Some(ConversationKind::Channel),
            _ => None,
        }
    }
}

impl FromSql for ConversationKind {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        ConversationKind::from_wire_name(value.as_str()?).ok_or(FromSqlError::InvalidType)
    }
}

impl ToSql for ConversationKind {
    fn to_sql(&self) -> Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.as_str()))
    }
}

/// A conversation member's standing. DM members are always `Member` (a DM
/// has no owner/admin distinction — see the migration note in the plan).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberRole {
    Owner,
    Admin,
    Member,
    Subscriber,
}

impl MemberRole {
    pub fn as_str(self) -> &'static str {
        match self {
            MemberRole::Owner => "owner",
            MemberRole::Admin => "admin",
            MemberRole::Member => "member",
            MemberRole::Subscriber => "subscriber",
        }
    }

    pub fn from_wire_name(s: &str) -> Option<Self> {
        match s {
            "owner" => Some(MemberRole::Owner),
            "admin" => Some(MemberRole::Admin),
            "member" => Some(MemberRole::Member),
            "subscriber" => Some(MemberRole::Subscriber),
            _ => None,
        }
    }
}

impl FromSql for MemberRole {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        MemberRole::from_wire_name(value.as_str()?).ok_or(FromSqlError::InvalidType)
    }
}

impl ToSql for MemberRole {
    fn to_sql(&self) -> Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.as_str()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Private,
    Public,
}

impl Visibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Visibility::Private => "private",
            Visibility::Public => "public",
        }
    }

    pub fn from_wire_name(s: &str) -> Option<Self> {
        match s {
            "private" => Some(Visibility::Private),
            "public" => Some(Visibility::Public),
            _ => None,
        }
    }
}

impl FromSql for Visibility {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        Visibility::from_wire_name(value.as_str()?).ok_or(FromSqlError::InvalidType)
    }
}

impl ToSql for Visibility {
    fn to_sql(&self) -> Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.as_str()))
    }
}

// ============================================================================
// Conversations
// ============================================================================

/// One row of `conversations`.
#[derive(Debug, Clone, PartialEq)]
pub struct Conversation {
    pub id: i64,
    pub kind: ConversationKind,
    pub title: Option<String>,
    pub description: Option<String>,
    pub visibility: Visibility,
    pub comments_enabled: bool,
    pub members_can_add: bool,
    pub created_by: i64,
    pub created_at: String,
    pub last_message_at: Option<String>,
    pub dm_pair_key: Option<String>,
    pub legacy_dm_id: Option<i64>,
}

const CONVERSATION_SELECT_COLUMNS: &str = "id, kind, title, description, visibility, comments_enabled, \
     members_can_add, created_by, created_at, last_message_at, dm_pair_key, legacy_dm_id";

fn conversation_from_row(row: &rusqlite::Row<'_>) -> Result<Conversation> {
    Ok(Conversation {
        id: row.get(0)?,
        kind: row.get(1)?,
        title: row.get(2)?,
        description: row.get(3)?,
        visibility: row.get(4)?,
        comments_enabled: row.get::<_, i64>(5)? != 0,
        members_can_add: row.get::<_, i64>(6)? != 0,
        created_by: row.get(7)?,
        created_at: row.get(8)?,
        last_message_at: row.get(9)?,
        dm_pair_key: row.get(10)?,
        legacy_dm_id: row.get(11)?,
    })
}

pub fn get_conversation(conn: &Connection, id: i64) -> Result<Option<Conversation>> {
    conn.query_row(
        &format!("SELECT {CONVERSATION_SELECT_COLUMNS} FROM conversations WHERE id = ?1"),
        params![id],
        conversation_from_row,
    )
    .optional()
}

/// The `"<lo>:<hi>"` pair key a dm-kind `conversations` row is keyed by —
/// same ordered-pair trick `dm_db::ordered_pair` uses, so the same two
/// accounts always resolve to the same row regardless of call order.
pub fn dm_pair_key(a: i64, b: i64) -> String {
    let (lo, hi) = ordered_pair(a, b);
    format!("{lo}:{hi}")
}

/// Resolve the dm-kind conversation between `a` and `b`, creating it (plus
/// both parties' `conversation_members` rows) if it does not exist yet.
/// Idempotent regardless of argument order, mirroring
/// `dm_db::get_or_create_conversation`. Does not check either party has
/// published a `dm_identity_keys` row — same division of labour `dm_db`
/// uses, left to the route's own candidate filtering.
pub fn get_or_create_dm_conversation(conn: &Connection, a: i64, b: i64, now: &str) -> Result<Conversation> {
    let (lo, hi) = ordered_pair(a, b);
    let pair_key = dm_pair_key(a, b);
    let inserted = conn.execute(
        "INSERT INTO conversations (kind, created_by, created_at, dm_pair_key)
         VALUES ('dm', ?1, ?2, ?3)
         ON CONFLICT(dm_pair_key) DO NOTHING",
        params![lo, now, pair_key],
    )? > 0;
    let conversation = conn.query_row(
        &format!("SELECT {CONVERSATION_SELECT_COLUMNS} FROM conversations WHERE dm_pair_key = ?1"),
        params![pair_key],
        conversation_from_row,
    )?;
    if inserted {
        insert_member_row(conn, conversation.id, lo, MemberRole::Member, now)?;
        insert_member_row(conn, conversation.id, hi, MemberRole::Member, now)?;
    }
    Ok(conversation)
}

/// Create a group conversation: the `conversations` row, its first
/// `group_key_epochs` row (epoch 1, `created_by`), an `owner`
/// `conversation_members` row for `created_by`, and one `member` row per
/// `initial_member_user_ids` — all in one transaction. Refuses (rolling
/// back everything) if any initial member has not published a
/// `dm_identity_keys` row (see [`AddMemberError::NoMessagingKey`]) — the
/// server has nothing to wrap that member's key epoch under.
pub fn create_group_conversation(
    conn: &mut Connection,
    created_by: i64,
    title: &str,
    members_can_add: bool,
    initial_member_user_ids: &[i64],
    now: &str,
) -> std::result::Result<Conversation, AddMemberError> {
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO conversations (kind, title, members_can_add, created_by, created_at)
         VALUES ('group', ?1, ?2, ?3, ?4)",
        params![title, members_can_add as i64, created_by, now],
    )?;
    let conversation_id = tx.last_insert_rowid();
    tx.execute(
        "INSERT INTO group_key_epochs (conversation_id, epoch, created_at, created_by) VALUES (?1, 1, ?2, ?3)",
        params![conversation_id, now, created_by],
    )?;
    insert_member_row(&tx, conversation_id, created_by, MemberRole::Owner, now)?;
    for &member_user_id in initial_member_user_ids {
        add_member(&tx, conversation_id, member_user_id, MemberRole::Member, now)?;
    }
    tx.commit()?;
    Ok(Conversation {
        id: conversation_id,
        kind: ConversationKind::Group,
        title: Some(title.to_string()),
        description: None,
        visibility: Visibility::Private,
        comments_enabled: true,
        members_can_add,
        created_by,
        created_at: now.to_string(),
        last_message_at: None,
        dm_pair_key: None,
        legacy_dm_id: None,
    })
}

/// Create a channel conversation: the `conversations` row plus an `owner`
/// `conversation_members` row for `created_by`. Channels have no group key
/// epoch — posts are plaintext + Ed25519-signed (see
/// [`create_signed_message`]), not sealed.
pub fn create_channel_conversation(
    conn: &Connection,
    created_by: i64,
    title: &str,
    description: Option<&str>,
    visibility: Visibility,
    comments_enabled: bool,
    now: &str,
) -> Result<Conversation> {
    conn.execute(
        "INSERT INTO conversations (kind, title, description, visibility, comments_enabled, created_by, created_at)
         VALUES ('channel', ?1, ?2, ?3, ?4, ?5, ?6)",
        params![title, description, visibility, comments_enabled as i64, created_by, now],
    )?;
    let id = conn.last_insert_rowid();
    insert_member_row(conn, id, created_by, MemberRole::Owner, now)?;
    Ok(Conversation {
        id,
        kind: ConversationKind::Channel,
        title: Some(title.to_string()),
        description: description.map(|d| d.to_string()),
        visibility,
        comments_enabled,
        members_can_add: false,
        created_by,
        created_at: now.to_string(),
        last_message_at: None,
        dm_pair_key: None,
        legacy_dm_id: None,
    })
}

/// `PATCH /api/conversations/{id}` — replaces every settable field at once;
/// the route assembles the merged (existing-field-or-new-value) state
/// before calling this, same "no partial-diff SQL" discipline
/// `social_db::move_thread_v2`-style single-column setters use elsewhere in
/// this crate, just widened to the handful of fields a group/channel PATCH
/// can touch together.
pub fn update_conversation(
    conn: &Connection,
    id: i64,
    title: Option<&str>,
    description: Option<&str>,
    visibility: Visibility,
    comments_enabled: bool,
    members_can_add: bool,
) -> Result<bool> {
    Ok(conn.execute(
        "UPDATE conversations SET title = ?2, description = ?3, visibility = ?4, comments_enabled = ?5, members_can_add = ?6
         WHERE id = ?1",
        params![id, title, description, visibility, comments_enabled as i64, members_can_add as i64],
    )? > 0)
}

// ============================================================================
// Members
// ============================================================================

/// One row of `conversation_members`.
#[derive(Debug, Clone, PartialEq)]
pub struct ConversationMember {
    pub conversation_id: i64,
    pub user_id: i64,
    pub role: MemberRole,
    pub joined_at: String,
    pub read_cursor_id: i64,
    pub muted_until: Option<String>,
    pub pinned: bool,
    pub archived: bool,
}

const MEMBER_SELECT_COLUMNS: &str =
    "conversation_id, user_id, role, joined_at, read_cursor_id, muted_until, pinned, archived";

fn member_from_row(row: &rusqlite::Row<'_>) -> Result<ConversationMember> {
    Ok(ConversationMember {
        conversation_id: row.get(0)?,
        user_id: row.get(1)?,
        role: row.get(2)?,
        joined_at: row.get(3)?,
        read_cursor_id: row.get(4)?,
        muted_until: row.get(5)?,
        pinned: row.get::<_, i64>(6)? != 0,
        archived: row.get::<_, i64>(7)? != 0,
    })
}

/// Why [`add_member`] (and, transitively, [`create_group_conversation`])
/// refused before ever committing a membership row.
#[derive(Debug)]
pub enum AddMemberError {
    /// `user_id` has not published a `dm_identity_keys` row — there is
    /// nothing an owner/admin could wrap a group key epoch under. This is
    /// the `"code":"no_messaging_key"` case the plan's New Group dialog
    /// shows a keyless candidate.
    NoMessagingKey { user_id: i64 },
    Db(rusqlite::Error),
}

impl From<rusqlite::Error> for AddMemberError {
    fn from(e: rusqlite::Error) -> Self {
        AddMemberError::Db(e)
    }
}

fn has_identity_key(conn: &Connection, user_id: i64) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM dm_identity_keys WHERE user_id = ?1)",
        params![user_id],
        |row| row.get::<_, i64>(0),
    )
    .map(|n| n != 0)
}

fn insert_member_row(conn: &Connection, conversation_id: i64, user_id: i64, role: MemberRole, now: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO conversation_members (conversation_id, user_id, role, joined_at, read_cursor_id, pinned, archived)
         VALUES (?1, ?2, ?3, ?4, 0, 0, 0)",
        params![conversation_id, user_id, role, now],
    )?;
    Ok(())
}

/// Add `user_id` to `conversation_id` with `role`. Refuses
/// [`AddMemberError::NoMessagingKey`] if `user_id` has no published DM
/// identity key. Does NOT insert a `group_key_wraps` row — a group add is
/// two calls (this one, then [`insert_group_key_wrap`] for the current
/// epoch only), same "server never sees a raw key" separation the module
/// doc describes.
pub fn add_member(
    conn: &Connection,
    conversation_id: i64,
    user_id: i64,
    role: MemberRole,
    now: &str,
) -> std::result::Result<(), AddMemberError> {
    if !has_identity_key(conn, user_id)? {
        return Err(AddMemberError::NoMessagingKey { user_id });
    }
    insert_member_row(conn, conversation_id, user_id, role, now)?;
    Ok(())
}

pub fn get_member(conn: &Connection, conversation_id: i64, user_id: i64) -> Result<Option<ConversationMember>> {
    conn.query_row(
        &format!("SELECT {MEMBER_SELECT_COLUMNS} FROM conversation_members WHERE conversation_id = ?1 AND user_id = ?2"),
        params![conversation_id, user_id],
        member_from_row,
    )
    .optional()
}

pub fn list_members(conn: &Connection, conversation_id: i64) -> Result<Vec<ConversationMember>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {MEMBER_SELECT_COLUMNS} FROM conversation_members WHERE conversation_id = ?1 ORDER BY joined_at ASC"
    ))?;
    let mut rows = stmt.query(params![conversation_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(member_from_row(row)?);
    }
    Ok(out)
}

/// Plain leave/kick with no re-key — the removed member already has no
/// further access to grant (leaving) or the caller is removing someone from
/// a `dm`/`channel` conversation, neither of which has a group key epoch to
/// rotate. A `group` removal that must re-key goes through
/// [`remove_member_and_rekey`] instead.
pub fn remove_member(conn: &Connection, conversation_id: i64, user_id: i64) -> Result<bool> {
    Ok(conn.execute(
        "DELETE FROM conversation_members WHERE conversation_id = ?1 AND user_id = ?2",
        params![conversation_id, user_id],
    )? > 0)
}

pub fn set_pinned(conn: &Connection, conversation_id: i64, user_id: i64, pinned: bool) -> Result<bool> {
    Ok(conn.execute(
        "UPDATE conversation_members SET pinned = ?3 WHERE conversation_id = ?1 AND user_id = ?2",
        params![conversation_id, user_id, pinned as i64],
    )? > 0)
}

pub fn set_archived(conn: &Connection, conversation_id: i64, user_id: i64, archived: bool) -> Result<bool> {
    Ok(conn.execute(
        "UPDATE conversation_members SET archived = ?3 WHERE conversation_id = ?1 AND user_id = ?2",
        params![conversation_id, user_id, archived as i64],
    )? > 0)
}

/// `muted_until = None` clears the mute; `Some(ts)` sets it (RFC3339, or the
/// `"forever"` sentinel the schema comment documents).
pub fn set_muted_until(conn: &Connection, conversation_id: i64, user_id: i64, muted_until: Option<&str>) -> Result<bool> {
    Ok(conn.execute(
        "UPDATE conversation_members SET muted_until = ?3 WHERE conversation_id = ?1 AND user_id = ?2",
        params![conversation_id, user_id, muted_until],
    )? > 0)
}

/// Advance `user_id`'s own read cursor in `conversation_id` to `up_to_id` —
/// never regresses it (the `read_cursor_id < ?` guard), and only ever
/// touches the calling reader's own row, mirroring `dm_db::mark_read`'s
/// "never marks another party's cursor" contract.
pub fn mark_read(conn: &Connection, conversation_id: i64, user_id: i64, up_to_id: i64) -> Result<bool> {
    Ok(conn.execute(
        "UPDATE conversation_members SET read_cursor_id = ?3
         WHERE conversation_id = ?1 AND user_id = ?2 AND read_cursor_id < ?3",
        params![conversation_id, user_id, up_to_id],
    )? > 0)
}

// ============================================================================
// Group key epochs + per-member wraps
// ============================================================================

/// Highest `group_key_epochs.epoch` for `conversation_id`, or `0` if the
/// conversation has none yet (not a group, or a group whose first epoch
/// insert has not run — should not happen for a real group conversation,
/// which always gets epoch 1 at creation).
pub fn current_group_epoch(conn: &Connection, conversation_id: i64) -> Result<i64> {
    conn.query_row(
        "SELECT COALESCE(MAX(epoch), 0) FROM group_key_epochs WHERE conversation_id = ?1",
        params![conversation_id],
        |row| row.get(0),
    )
}

/// One `group_key_wraps` row `remove_member_and_rekey`/`insert_group_key_wrap`
/// writes — the caller already computed the wrap client-side; this module
/// never touches the raw key.
pub struct GroupKeyWrapInput<'a> {
    pub member_user_id: i64,
    pub wrapper_public_key: &'a [u8],
    pub nonce: &'a [u8],
    pub ciphertext: &'a [u8],
}

/// One row of `group_key_wraps`.
#[derive(Debug, Clone, PartialEq)]
pub struct GroupKeyWrap {
    pub conversation_id: i64,
    pub epoch: i64,
    pub member_user_id: i64,
    pub wrapper_public_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub created_at: String,
}

const GROUP_KEY_WRAP_SELECT_COLUMNS: &str =
    "conversation_id, epoch, member_user_id, wrapper_public_key, nonce, ciphertext, created_at";

fn group_key_wrap_from_row(row: &rusqlite::Row<'_>) -> Result<GroupKeyWrap> {
    Ok(GroupKeyWrap {
        conversation_id: row.get(0)?,
        epoch: row.get(1)?,
        member_user_id: row.get(2)?,
        wrapper_public_key: row.get(3)?,
        nonce: row.get(4)?,
        ciphertext: row.get(5)?,
        created_at: row.get(6)?,
    })
}

/// Insert one member's key wrap for one epoch — the second half of adding a
/// member to a group (see [`add_member`]'s doc). Covers only the epoch
/// named, never a retroactive one — the caller is responsible for always
/// passing [`current_group_epoch`] here, never an earlier one, so a new
/// member can never be handed the means to decrypt history from before they
/// joined.
pub fn insert_group_key_wrap(
    conn: &Connection,
    conversation_id: i64,
    epoch: i64,
    member_user_id: i64,
    wrapper_public_key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    now: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO group_key_wraps (conversation_id, epoch, member_user_id, wrapper_public_key, nonce, ciphertext, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![conversation_id, epoch, member_user_id, wrapper_public_key, nonce, ciphertext, now],
    )?;
    Ok(())
}

pub fn list_group_key_wraps_for_member(conn: &Connection, conversation_id: i64, member_user_id: i64) -> Result<Vec<GroupKeyWrap>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {GROUP_KEY_WRAP_SELECT_COLUMNS} FROM group_key_wraps
         WHERE conversation_id = ?1 AND member_user_id = ?2 ORDER BY epoch ASC"
    ))?;
    let mut rows = stmt.query(params![conversation_id, member_user_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(group_key_wrap_from_row(row)?);
    }
    Ok(out)
}

/// Why [`remove_member_and_rekey`] refused before ever committing — in
/// every case the whole transaction rolls back (dropped, never `commit`ted),
/// so the group is never left half-rekeyed.
#[derive(Debug)]
pub enum RekeyError {
    /// `new_epoch` was not exactly `current_epoch + 1`.
    EpochNotSequential { expected: i64, got: i64 },
    /// `wraps.len()` did not equal the membership count remaining AFTER the
    /// removal.
    WrapCountMismatch { expected: usize, got: usize },
    Db(rusqlite::Error),
}

impl From<rusqlite::Error> for RekeyError {
    fn from(e: rusqlite::Error) -> Self {
        RekeyError::Db(e)
    }
}

/// Remove `target_user_id` from `conversation_id` and re-key it in one
/// transaction: deletes the membership row, inserts the `new_epoch`
/// `group_key_epochs` row, and inserts one `group_key_wraps` row per
/// `wraps` entry. Refuses (and rolls back everything, including the
/// removal) if `new_epoch != current_epoch + 1` or `wraps.len()` does not
/// equal the membership count remaining after the removal — see
/// [`RekeyError`].
pub fn remove_member_and_rekey(
    conn: &mut Connection,
    conversation_id: i64,
    target_user_id: i64,
    new_epoch: i64,
    created_by: i64,
    wraps: &[GroupKeyWrapInput<'_>],
    now: &str,
) -> std::result::Result<(), RekeyError> {
    let tx = conn.transaction()?;

    let current_epoch: i64 = tx.query_row(
        "SELECT COALESCE(MAX(epoch), 0) FROM group_key_epochs WHERE conversation_id = ?1",
        params![conversation_id],
        |row| row.get(0),
    )?;
    if new_epoch != current_epoch + 1 {
        return Err(RekeyError::EpochNotSequential { expected: current_epoch + 1, got: new_epoch });
    }

    tx.execute(
        "DELETE FROM conversation_members WHERE conversation_id = ?1 AND user_id = ?2",
        params![conversation_id, target_user_id],
    )?;

    let remaining: i64 = tx.query_row(
        "SELECT COUNT(*) FROM conversation_members WHERE conversation_id = ?1",
        params![conversation_id],
        |row| row.get(0),
    )?;
    if wraps.len() as i64 != remaining {
        return Err(RekeyError::WrapCountMismatch { expected: remaining as usize, got: wraps.len() });
    }

    tx.execute(
        "INSERT INTO group_key_epochs (conversation_id, epoch, created_at, created_by) VALUES (?1, ?2, ?3, ?4)",
        params![conversation_id, new_epoch, now, created_by],
    )?;
    for wrap in wraps {
        tx.execute(
            "INSERT INTO group_key_wraps (conversation_id, epoch, member_user_id, wrapper_public_key, nonce, ciphertext, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                conversation_id,
                new_epoch,
                wrap.member_user_id,
                wrap.wrapper_public_key,
                wrap.nonce,
                wrap.ciphertext,
                now
            ],
        )?;
    }

    tx.commit()?;
    Ok(())
}

// ============================================================================
// Channel signing keys
// ============================================================================

/// Ed25519 verifying-key length.
pub const CHANNEL_SIGNING_PUBLIC_KEY_LEN: usize = 32;

/// One row of `channel_signing_keys`.
#[derive(Debug, Clone, PartialEq)]
pub struct ChannelSigningKey {
    pub user_id: i64,
    pub public_key: Vec<u8>,
    pub created_at: String,
    pub rotated_at: Option<String>,
}

#[derive(Debug)]
pub enum ChannelSigningKeyError {
    InvalidLength,
    Db(rusqlite::Error),
}

impl From<rusqlite::Error> for ChannelSigningKeyError {
    fn from(e: rusqlite::Error) -> Self {
        ChannelSigningKeyError::Db(e)
    }
}

/// Publish or rotate `user_id`'s channel signing key — same upsert-in-place
/// shape as `dm_db::upsert_identity_key` (no key history kept).
pub fn upsert_channel_signing_key(
    conn: &Connection,
    user_id: i64,
    public_key: &[u8],
    now: &str,
) -> std::result::Result<(), ChannelSigningKeyError> {
    if public_key.len() != CHANNEL_SIGNING_PUBLIC_KEY_LEN {
        return Err(ChannelSigningKeyError::InvalidLength);
    }
    conn.execute(
        "INSERT INTO channel_signing_keys (user_id, public_key, created_at, rotated_at)
         VALUES (?1, ?2, ?3, NULL)
         ON CONFLICT(user_id) DO UPDATE SET public_key = excluded.public_key, rotated_at = ?3",
        params![user_id, public_key, now],
    )?;
    Ok(())
}

pub fn get_channel_signing_key(conn: &Connection, user_id: i64) -> Result<Option<ChannelSigningKey>> {
    conn.query_row(
        "SELECT user_id, public_key, created_at, rotated_at FROM channel_signing_keys WHERE user_id = ?1",
        params![user_id],
        |row| {
            Ok(ChannelSigningKey {
                user_id: row.get(0)?,
                public_key: row.get(1)?,
                created_at: row.get(2)?,
                rotated_at: row.get(3)?,
            })
        },
    )
    .optional()
}

// ============================================================================
// Messages
// ============================================================================

/// One row of `conversation_messages`. `nonce`/`ciphertext` are opaque
/// (dm/group); `body`/`signature` are plaintext + signature (channel) — see
/// the module doc.
#[derive(Debug, Clone, PartialEq)]
pub struct ConversationMessage {
    pub id: i64,
    pub conversation_id: i64,
    pub sender_user_id: i64,
    pub nonce: Option<Vec<u8>>,
    pub ciphertext: Option<Vec<u8>>,
    pub epoch: Option<i64>,
    pub body: Option<String>,
    pub signature: Option<Vec<u8>>,
    pub reply_to_id: Option<i64>,
    pub edited_at: Option<String>,
    pub deleted_at: Option<String>,
    pub pinned_at: Option<String>,
    pub created_at: String,
}

const MESSAGE_SELECT_COLUMNS: &str = "id, conversation_id, sender_user_id, nonce, ciphertext, epoch, body, \
     signature, reply_to_id, edited_at, deleted_at, pinned_at, created_at";

fn message_from_row(row: &rusqlite::Row<'_>) -> Result<ConversationMessage> {
    Ok(ConversationMessage {
        id: row.get(0)?,
        conversation_id: row.get(1)?,
        sender_user_id: row.get(2)?,
        nonce: row.get(3)?,
        ciphertext: row.get(4)?,
        epoch: row.get(5)?,
        body: row.get(6)?,
        signature: row.get(7)?,
        reply_to_id: row.get(8)?,
        edited_at: row.get(9)?,
        deleted_at: row.get(10)?,
        pinned_at: row.get(11)?,
        created_at: row.get(12)?,
    })
}

/// Why [`create_sealed_message`] was refused, on top of a real database
/// failure — same shape as `dm_db::MessageError`. Validates against this
/// module's own `DM_NONCE_LEN`/`DM_MAX_CIPHERTEXT_BYTES` (mirrors of
/// `dm_db`'s constants — see "Local mirrors of `dm_db` constants" above) —
/// a sealed `conversation_messages` row and a `dm_messages` row hold the
/// exact same `DmCiphertext` shape.
#[derive(Debug)]
pub enum MessageError {
    InvalidNonceLength,
    TooLarge,
    Db(rusqlite::Error),
}

impl From<rusqlite::Error> for MessageError {
    fn from(e: rusqlite::Error) -> Self {
        MessageError::Db(e)
    }
}

/// Insert a sealed (dm/group) message and bump the conversation's
/// `last_message_at`. `epoch` is `Some` for a group message (the epoch that
/// sealed it), `None` for a dm message (dm has no group key epoch).
pub fn create_sealed_message(
    conn: &Connection,
    conversation_id: i64,
    sender_user_id: i64,
    nonce: &[u8],
    ciphertext: &[u8],
    epoch: Option<i64>,
    reply_to_id: Option<i64>,
    now: &str,
) -> std::result::Result<i64, MessageError> {
    if nonce.len() != DM_NONCE_LEN {
        return Err(MessageError::InvalidNonceLength);
    }
    if ciphertext.len() > DM_MAX_CIPHERTEXT_BYTES {
        return Err(MessageError::TooLarge);
    }
    conn.execute(
        "INSERT INTO conversation_messages (conversation_id, sender_user_id, nonce, ciphertext, epoch, reply_to_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![conversation_id, sender_user_id, nonce, ciphertext, epoch, reply_to_id, now],
    )?;
    let id = conn.last_insert_rowid();
    conn.execute("UPDATE conversations SET last_message_at = ?2 WHERE id = ?1", params![conversation_id, now])?;
    Ok(id)
}

/// Insert a plaintext, Ed25519-signed channel post and bump the
/// conversation's `last_message_at`. The server stores `signature` verbatim
/// and never verifies it itself — see the module doc.
pub fn create_signed_message(
    conn: &Connection,
    conversation_id: i64,
    sender_user_id: i64,
    body: &str,
    signature: &[u8],
    reply_to_id: Option<i64>,
    now: &str,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO conversation_messages (conversation_id, sender_user_id, body, signature, reply_to_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![conversation_id, sender_user_id, body, signature, reply_to_id, now],
    )?;
    let id = conn.last_insert_rowid();
    conn.execute("UPDATE conversations SET last_message_at = ?2 WHERE id = ?1", params![conversation_id, now])?;
    Ok(id)
}

pub fn get_message(conn: &Connection, id: i64) -> Result<Option<ConversationMessage>> {
    conn.query_row(
        &format!("SELECT {MESSAGE_SELECT_COLUMNS} FROM conversation_messages WHERE id = ?1"),
        params![id],
        message_from_row,
    )
    .optional()
}

/// Which page of a conversation's messages [`list_messages`] should fetch —
/// identical shape to `dm_db::MessagePage` (see that type's doc for why
/// `Newest` exists and what each variant means).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessagePage {
    Newest,
    After(i64),
    Before(i64),
}

fn collect_messages(rows: &mut rusqlite::Rows<'_>) -> Result<Vec<ConversationMessage>> {
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(message_from_row(row)?);
    }
    Ok(out)
}

/// List one page of `conversation_id`'s messages per [`MessagePage`],
/// always returned oldest-first, capped at `limit` — same paging shape
/// `dm_db::list_messages` uses.
pub fn list_messages(conn: &Connection, conversation_id: i64, page: MessagePage, limit: i64) -> Result<Vec<ConversationMessage>> {
    match page {
        MessagePage::After(after) => {
            let mut stmt = conn.prepare(&format!(
                "SELECT {MESSAGE_SELECT_COLUMNS} FROM conversation_messages
                 WHERE conversation_id = ?1 AND id > ?2
                 ORDER BY id ASC LIMIT ?3"
            ))?;
            let mut rows = stmt.query(params![conversation_id, after, limit])?;
            collect_messages(&mut rows)
        }
        MessagePage::Newest => {
            let mut stmt = conn.prepare(&format!(
                "SELECT {MESSAGE_SELECT_COLUMNS} FROM conversation_messages
                 WHERE conversation_id = ?1
                 ORDER BY id DESC LIMIT ?2"
            ))?;
            let mut rows = stmt.query(params![conversation_id, limit])?;
            let mut out = collect_messages(&mut rows)?;
            out.reverse();
            Ok(out)
        }
        MessagePage::Before(before) => {
            let mut stmt = conn.prepare(&format!(
                "SELECT {MESSAGE_SELECT_COLUMNS} FROM conversation_messages
                 WHERE conversation_id = ?1 AND id < ?2
                 ORDER BY id DESC LIMIT ?3"
            ))?;
            let mut rows = stmt.query(params![conversation_id, before, limit])?;
            let mut out = collect_messages(&mut rows)?;
            out.reverse();
            Ok(out)
        }
    }
}

/// Why [`edit_sealed_message`] refused, on top of a real database failure.
#[derive(Debug)]
pub enum EditMessageError {
    NotFound,
    /// Coordinator ruling (plan §7/§6.2): an edit is sealed under the
    /// message's own epoch; once the group has re-keyed past that epoch the
    /// edit is refused rather than widening the message's original
    /// audience.
    EpochSuperseded { message_epoch: i64, current_epoch: i64 },
    Db(rusqlite::Error),
}

impl From<rusqlite::Error> for EditMessageError {
    fn from(e: rusqlite::Error) -> Self {
        EditMessageError::Db(e)
    }
}

/// Reseal a dm/group message under `new_nonce`/`new_ciphertext`. For a
/// group message (`epoch` is `Some`), refuses once the conversation's
/// current epoch has moved past the message's own — see [`EditMessageError::
/// EpochSuperseded`] and the module doc's re-key section. A dm message
/// (`epoch` is `None`) has no epoch boundary to cross and is always
/// resealable (subject to the route's own "own message" ownership check,
/// which this function does not perform — same division of labour
/// `dm_db::create_message` uses for its party check).
pub fn edit_sealed_message(
    conn: &Connection,
    message_id: i64,
    new_nonce: &[u8],
    new_ciphertext: &[u8],
    now: &str,
) -> std::result::Result<(), EditMessageError> {
    let row: Option<(i64, Option<i64>)> = conn
        .query_row(
            "SELECT conversation_id, epoch FROM conversation_messages WHERE id = ?1",
            params![message_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (conversation_id, epoch) = row.ok_or(EditMessageError::NotFound)?;
    if let Some(message_epoch) = epoch {
        let current_epoch = current_group_epoch(conn, conversation_id)?;
        if message_epoch < current_epoch {
            return Err(EditMessageError::EpochSuperseded { message_epoch, current_epoch });
        }
    }
    conn.execute(
        "UPDATE conversation_messages SET nonce = ?2, ciphertext = ?3, edited_at = ?4 WHERE id = ?1",
        params![message_id, new_nonce, new_ciphertext, now],
    )?;
    Ok(())
}

/// Edit a channel post's plaintext `body`/`signature` — a channel has no
/// group key epoch, so there is no supersede boundary to check.
pub fn edit_signed_message(conn: &Connection, message_id: i64, new_body: &str, new_signature: &[u8], now: &str) -> Result<bool> {
    Ok(conn.execute(
        "UPDATE conversation_messages SET body = ?2, signature = ?3, edited_at = ?4 WHERE id = ?1",
        params![message_id, new_body, new_signature, now],
    )? > 0)
}

/// Soft-delete one message (`deleted_at` stamped, content left in place — a
/// client renders a "message deleted" tombstone from `deleted_at`'s
/// presence, same non-destructive posture `social_db::delete_reply_v2`
/// uses). `owner_user_id = Some(uid)` requires `uid` to be the message's own
/// sender (self-service delete); `None` deletes unconditionally (an
/// owner/admin caller for group/channel — the route has already checked
/// that).
pub fn delete_message(conn: &Connection, message_id: i64, owner_user_id: Option<i64>, now: &str) -> Result<bool> {
    let n = match owner_user_id {
        Some(uid) => conn.execute(
            "UPDATE conversation_messages SET deleted_at = ?2 WHERE id = ?1 AND sender_user_id = ?3 AND deleted_at IS NULL",
            params![message_id, now, uid],
        )?,
        None => conn.execute(
            "UPDATE conversation_messages SET deleted_at = ?2 WHERE id = ?1 AND deleted_at IS NULL",
            params![message_id, now],
        )?,
    };
    Ok(n > 0)
}

pub fn pin_message(conn: &Connection, message_id: i64, now: &str) -> Result<bool> {
    Ok(conn.execute(
        "UPDATE conversation_messages SET pinned_at = ?2 WHERE id = ?1 AND pinned_at IS NULL",
        params![message_id, now],
    )? > 0)
}

pub fn unpin_message(conn: &Connection, message_id: i64) -> Result<bool> {
    Ok(conn.execute("UPDATE conversation_messages SET pinned_at = NULL WHERE id = ?1 AND pinned_at IS NOT NULL", params![message_id])? > 0)
}

pub fn list_pinned_messages(conn: &Connection, conversation_id: i64) -> Result<Vec<ConversationMessage>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {MESSAGE_SELECT_COLUMNS} FROM conversation_messages
         WHERE conversation_id = ?1 AND pinned_at IS NOT NULL ORDER BY pinned_at DESC"
    ))?;
    let mut rows = stmt.query(params![conversation_id])?;
    collect_messages(&mut rows)
}

// ============================================================================
// Reactions
// ============================================================================

/// One row of `conversation_reactions` — plaintext, server-visible metadata
/// for every conversation kind including a sealed dm/group (coordinator
/// ruling, plan §7/§6.1 — see the module doc).
#[derive(Debug, Clone, PartialEq)]
pub struct Reaction {
    pub message_id: i64,
    pub user_id: i64,
    pub emoji: String,
    pub created_at: String,
}

pub fn add_reaction(conn: &Connection, message_id: i64, user_id: i64, emoji: &str, now: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO conversation_reactions (message_id, user_id, emoji, created_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(message_id, user_id, emoji) DO NOTHING",
        params![message_id, user_id, emoji, now],
    )?;
    Ok(())
}

pub fn remove_reaction(conn: &Connection, message_id: i64, user_id: i64, emoji: &str) -> Result<bool> {
    Ok(conn.execute(
        "DELETE FROM conversation_reactions WHERE message_id = ?1 AND user_id = ?2 AND emoji = ?3",
        params![message_id, user_id, emoji],
    )? > 0)
}

pub fn list_reactions(conn: &Connection, message_id: i64) -> Result<Vec<Reaction>> {
    let mut stmt =
        conn.prepare("SELECT message_id, user_id, emoji, created_at FROM conversation_reactions WHERE message_id = ?1 ORDER BY created_at ASC")?;
    let mut rows = stmt.query(params![message_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(Reaction {
            message_id: row.get(0)?,
            user_id: row.get(1)?,
            emoji: row.get(2)?,
            created_at: row.get(3)?,
        });
    }
    Ok(out)
}

// ============================================================================
// Folders
// ============================================================================

/// The include/exclude columns of one `conversation_folders` row — the
/// built-in folders (All chats / Personal / Groups / Channels / Archive)
/// are computed client-side and never stored here (plan §1.4); this is only
/// a CUSTOM folder's own filter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FolderFilters {
    pub include_all_dms: bool,
    pub include_all_groups: bool,
    pub include_all_channels: bool,
    pub exclude_muted: bool,
    pub exclude_read: bool,
    pub exclude_archived: bool,
}

/// One row of `conversation_folders`.
#[derive(Debug, Clone, PartialEq)]
pub struct ConversationFolder {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub icon: String,
    pub position: i64,
    pub filters: FolderFilters,
    pub created_at: String,
    pub updated_at: String,
}

const FOLDER_SELECT_COLUMNS: &str = "id, user_id, name, icon, position, include_all_dms, include_all_groups, \
     include_all_channels, exclude_muted, exclude_read, exclude_archived, created_at, updated_at";

fn folder_from_row(row: &rusqlite::Row<'_>) -> Result<ConversationFolder> {
    Ok(ConversationFolder {
        id: row.get(0)?,
        user_id: row.get(1)?,
        name: row.get(2)?,
        icon: row.get(3)?,
        position: row.get(4)?,
        filters: FolderFilters {
            include_all_dms: row.get::<_, i64>(5)? != 0,
            include_all_groups: row.get::<_, i64>(6)? != 0,
            include_all_channels: row.get::<_, i64>(7)? != 0,
            exclude_muted: row.get::<_, i64>(8)? != 0,
            exclude_read: row.get::<_, i64>(9)? != 0,
            exclude_archived: row.get::<_, i64>(10)? != 0,
        },
        created_at: row.get(11)?,
        updated_at: row.get(12)?,
    })
}

pub fn create_folder(conn: &Connection, user_id: i64, name: &str, icon: &str, position: i64, filters: FolderFilters, now: &str) -> Result<i64> {
    conn.execute(
        "INSERT INTO conversation_folders
            (user_id, name, icon, position, include_all_dms, include_all_groups, include_all_channels,
             exclude_muted, exclude_read, exclude_archived, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)",
        params![
            user_id,
            name,
            icon,
            position,
            filters.include_all_dms as i64,
            filters.include_all_groups as i64,
            filters.include_all_channels as i64,
            filters.exclude_muted as i64,
            filters.exclude_read as i64,
            filters.exclude_archived as i64,
            now,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn update_folder(
    conn: &Connection,
    folder_id: i64,
    user_id: i64,
    name: &str,
    icon: &str,
    filters: FolderFilters,
    now: &str,
) -> Result<bool> {
    Ok(conn.execute(
        "UPDATE conversation_folders SET name = ?3, icon = ?4, include_all_dms = ?5, include_all_groups = ?6,
             include_all_channels = ?7, exclude_muted = ?8, exclude_read = ?9, exclude_archived = ?10, updated_at = ?11
         WHERE id = ?1 AND user_id = ?2",
        params![
            folder_id,
            user_id,
            name,
            icon,
            filters.include_all_dms as i64,
            filters.include_all_groups as i64,
            filters.include_all_channels as i64,
            filters.exclude_muted as i64,
            filters.exclude_read as i64,
            filters.exclude_archived as i64,
            now,
        ],
    )? > 0)
}

pub fn list_folders_for_user(conn: &Connection, user_id: i64) -> Result<Vec<ConversationFolder>> {
    let mut stmt = conn.prepare(&format!("SELECT {FOLDER_SELECT_COLUMNS} FROM conversation_folders WHERE user_id = ?1 ORDER BY position ASC"))?;
    let mut rows = stmt.query(params![user_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(folder_from_row(row)?);
    }
    Ok(out)
}

/// Delete `folder_id` (and its `conversation_folder_chats` membership rows)
/// if it is owned by `user_id`.
pub fn delete_folder(conn: &Connection, folder_id: i64, user_id: i64) -> Result<bool> {
    let owned: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM conversation_folders WHERE id = ?1 AND user_id = ?2)",
        params![folder_id, user_id],
        |row| row.get::<_, i64>(0),
    )? != 0;
    if !owned {
        return Ok(false);
    }
    conn.execute("DELETE FROM conversation_folder_chats WHERE folder_id = ?1", params![folder_id])?;
    Ok(conn.execute("DELETE FROM conversation_folders WHERE id = ?1 AND user_id = ?2", params![folder_id, user_id])? > 0)
}

/// Why [`reorder_folders`] refused before ever committing — the whole batch
/// rolls back (see the function's own doc).
#[derive(Debug)]
pub enum ReorderError {
    /// `folder_id` is not owned by the caller — either it belongs to
    /// another account or does not exist.
    NotOwner { folder_id: i64 },
    Db(rusqlite::Error),
}

impl From<rusqlite::Error> for ReorderError {
    fn from(e: rusqlite::Error) -> Self {
        ReorderError::Db(e)
    }
}

/// Set `ordered_folder_ids[i]`'s `position` to `i`, atomically, for
/// `user_id`'s own folders only — one transaction, refusing (and rolling
/// back every position already written this call) the instant any id does
/// not belong to `user_id`, so a caller's drag-reorder can never leave the
/// list in a half-applied order.
pub fn reorder_folders(conn: &mut Connection, user_id: i64, ordered_folder_ids: &[i64], now: &str) -> std::result::Result<(), ReorderError> {
    let tx = conn.transaction()?;
    for (index, &folder_id) in ordered_folder_ids.iter().enumerate() {
        let updated = tx.execute(
            "UPDATE conversation_folders SET position = ?3, updated_at = ?4 WHERE id = ?1 AND user_id = ?2",
            params![folder_id, user_id, index as i64, now],
        )?;
        if updated == 0 {
            return Err(ReorderError::NotOwner { folder_id });
        }
    }
    tx.commit()?;
    Ok(())
}

pub fn add_chat_to_folder(conn: &Connection, folder_id: i64, conversation_id: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO conversation_folder_chats (folder_id, conversation_id) VALUES (?1, ?2)
         ON CONFLICT(folder_id, conversation_id) DO NOTHING",
        params![folder_id, conversation_id],
    )?;
    Ok(())
}

pub fn remove_chat_from_folder(conn: &Connection, folder_id: i64, conversation_id: i64) -> Result<bool> {
    Ok(conn.execute(
        "DELETE FROM conversation_folder_chats WHERE folder_id = ?1 AND conversation_id = ?2",
        params![folder_id, conversation_id],
    )? > 0)
}

pub fn list_chats_in_folder(conn: &Connection, folder_id: i64) -> Result<Vec<i64>> {
    let mut stmt = conn.prepare("SELECT conversation_id FROM conversation_folder_chats WHERE folder_id = ?1")?;
    let mut rows = stmt.query(params![folder_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(row.get(0)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: &str = "2026-09-24T00:00:00+00:00";
    const T1: &str = "2026-09-24T00:01:00+00:00";
    const T2: &str = "2026-09-24T00:02:00+00:00";

    /// This module's tests need only `dm_identity_keys` from `dm_db.rs`'s
    /// schema (for `has_identity_key`/`add_member`) — not the other two
    /// `dm_*` tables, and this module cannot call `dm_db::create_dm_schema`
    /// directly (see the module doc: different crate). A minimal, literal
    /// copy of just that one `CREATE TABLE` statement, kept in sync by hand
    /// with `dm_db::create_dm_schema`.
    fn create_dm_identity_keys_table(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS dm_identity_keys (
                user_id     INTEGER PRIMARY KEY,
                public_key  BLOB NOT NULL,
                fingerprint TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                rotated_at  TEXT
            );",
        )
        .expect("dm_identity_keys table");
    }

    fn test_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        create_dm_identity_keys_table(&conn);
        create_conversations_schema(&conn).expect("conversations schema");
        conn
    }

    fn publish_key(conn: &Connection, user_id: i64, seed: u8) {
        let key = vec![seed; DM_PUBLIC_KEY_LEN];
        conn.execute(
            "INSERT INTO dm_identity_keys (user_id, public_key, fingerprint, created_at) VALUES (?1, ?2, 'fp', ?3)",
            params![user_id, key, T0],
        )
        .expect("publish identity key");
    }

    // ---- dm conversations ----

    #[test]
    fn create_dm_conversation_is_idempotent_by_pair_key() {
        let conn = test_conn();
        let a = get_or_create_dm_conversation(&conn, 1, 2, T0).expect("create");
        let b = get_or_create_dm_conversation(&conn, 2, 1, T1).expect("resolve existing regardless of order");
        assert_eq!(a.id, b.id);
        assert_eq!(a.dm_pair_key.as_deref(), Some("1:2"));
        // The second call's `now` never overwrote the original created_at.
        assert_eq!(b.created_at, T0);

        let count: i64 = conn.query_row("SELECT COUNT(*) FROM conversations", [], |row| row.get(0)).expect("count");
        assert_eq!(count, 1);

        let members = list_members(&conn, a.id).expect("members");
        assert_eq!(members.len(), 2);
        assert!(members.iter().all(|m| m.role == MemberRole::Member));
    }

    // ---- group creation ----

    #[test]
    fn create_group_inserts_owner_plus_member_rows_with_correct_roles() {
        let mut conn = test_conn();
        publish_key(&conn, 2, 1);
        publish_key(&conn, 3, 2);

        let conv = create_group_conversation(&mut conn, 1, "Trading Desk", true, &[2, 3], T0).expect("create group");
        assert_eq!(conv.kind, ConversationKind::Group);
        assert_eq!(conv.members_can_add, true);

        let members = list_members(&conn, conv.id).expect("members");
        assert_eq!(members.len(), 3);
        let owner = members.iter().find(|m| m.user_id == 1).expect("owner row");
        assert_eq!(owner.role, MemberRole::Owner);
        let m2 = members.iter().find(|m| m.user_id == 2).expect("member row");
        assert_eq!(m2.role, MemberRole::Member);
        let m3 = members.iter().find(|m| m.user_id == 3).expect("member row");
        assert_eq!(m3.role, MemberRole::Member);

        assert_eq!(current_group_epoch(&conn, conv.id).expect("epoch"), 1);
    }

    #[test]
    fn create_group_refuses_and_rolls_back_when_an_initial_member_has_no_key() {
        let mut conn = test_conn();
        publish_key(&conn, 2, 1);
        // user 3 never publishes a key.
        let err = create_group_conversation(&mut conn, 1, "Trading Desk", false, &[2, 3], T0).unwrap_err();
        assert!(matches!(err, AddMemberError::NoMessagingKey { user_id: 3 }));

        let count: i64 = conn.query_row("SELECT COUNT(*) FROM conversations", [], |row| row.get(0)).expect("count");
        assert_eq!(count, 0, "the whole transaction rolled back, including the conversation row itself");
    }

    // ---- add_member ----

    #[test]
    fn add_member_refuses_without_a_published_dm_identity_key() {
        let mut conn = test_conn();
        let conv = create_group_conversation(&mut conn, 1, "Solo Group", false, &[], T0).expect("create group");

        let err = add_member(&conn, conv.id, 99, MemberRole::Member, T1).unwrap_err();
        assert!(matches!(err, AddMemberError::NoMessagingKey { user_id: 99 }));
        assert_eq!(get_member(&conn, conv.id, 99).expect("get"), None);
    }

    #[test]
    fn add_member_wrap_only_covers_the_current_epoch_not_history() {
        let mut conn = test_conn();
        publish_key(&conn, 2, 1);
        publish_key(&conn, 3, 2);
        publish_key(&conn, 4, 3);
        let conv = create_group_conversation(&mut conn, 1, "G", false, &[2, 3], T0).expect("create group");

        // Bump the group to epoch 2 by removing member 3, re-keying for the
        // two remaining members (1, 2).
        remove_member_and_rekey(
            &mut conn,
            conv.id,
            3,
            2,
            1,
            &[
                GroupKeyWrapInput { member_user_id: 1, wrapper_public_key: b"wpk1", nonce: b"nonce-abcd12", ciphertext: b"ct1" },
                GroupKeyWrapInput { member_user_id: 2, wrapper_public_key: b"wpk1", nonce: b"nonce-abcd34", ciphertext: b"ct2" },
            ],
            T1,
        )
        .expect("rekey to epoch 2");
        assert_eq!(current_group_epoch(&conn, conv.id).expect("epoch"), 2);

        // Member 4 joins now, at epoch 2 — their own wrap covers epoch 2 only.
        add_member(&conn, conv.id, 4, MemberRole::Member, T2).expect("add member 4");
        insert_group_key_wrap(&conn, conv.id, 2, 4, b"wpk1", b"nonce-abcd56", b"ct4", T2).expect("wrap for current epoch");

        let wraps = list_group_key_wraps_for_member(&conn, conv.id, 4).expect("wraps for member 4");
        assert_eq!(wraps.len(), 1);
        assert_eq!(wraps[0].epoch, 2);
        // No wrap row exists for epoch 1 — member 4 joined after it, and
        // cannot read history from before they joined.
        let epoch1_wrap: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM group_key_wraps WHERE conversation_id = ?1 AND member_user_id = 4 AND epoch = 1",
                params![conv.id],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(epoch1_wrap, 0);
    }

    // ---- remove_member_and_rekey ----

    fn group_with_three_members(conn: &mut Connection) -> Conversation {
        publish_key(conn, 2, 1);
        publish_key(conn, 3, 2);
        create_group_conversation(conn, 1, "G", false, &[2, 3], T0).expect("create group")
    }

    #[test]
    fn remove_member_and_rekey_bumps_epoch_and_writes_one_wrap_per_remaining_member() {
        let mut conn = test_conn();
        let conv = group_with_three_members(&mut conn);

        remove_member_and_rekey(
            &mut conn,
            conv.id,
            3,
            2,
            1,
            &[
                GroupKeyWrapInput { member_user_id: 1, wrapper_public_key: b"wpk1", nonce: b"nonce-abcd12", ciphertext: b"ct1" },
                GroupKeyWrapInput { member_user_id: 2, wrapper_public_key: b"wpk1", nonce: b"nonce-abcd34", ciphertext: b"ct2" },
            ],
            T1,
        )
        .expect("rekey");

        assert_eq!(current_group_epoch(&conn, conv.id).expect("epoch"), 2);
        let members = list_members(&conn, conv.id).expect("members");
        assert_eq!(members.len(), 2);
        assert!(members.iter().all(|m| m.user_id != 3));

        let wrap_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM group_key_wraps WHERE conversation_id = ?1 AND epoch = 2",
                params![conv.id],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(wrap_count, 2);
    }

    #[test]
    fn remove_member_and_rekey_refuses_a_non_sequential_epoch() {
        let mut conn = test_conn();
        let conv = group_with_three_members(&mut conn);

        let err = remove_member_and_rekey(
            &mut conn,
            conv.id,
            3,
            3, // should be 2
            1,
            &[
                GroupKeyWrapInput { member_user_id: 1, wrapper_public_key: b"wpk1", nonce: b"nonce-abcd12", ciphertext: b"ct1" },
                GroupKeyWrapInput { member_user_id: 2, wrapper_public_key: b"wpk1", nonce: b"nonce-abcd34", ciphertext: b"ct2" },
            ],
            T1,
        )
        .unwrap_err();
        assert!(matches!(err, RekeyError::EpochNotSequential { expected: 2, got: 3 }));

        // Rolled back: member 3 is still present, still at epoch 1.
        assert_eq!(current_group_epoch(&conn, conv.id).expect("epoch"), 1);
        assert!(get_member(&conn, conv.id, 3).expect("get").is_some());
    }

    #[test]
    fn remove_member_and_rekey_refuses_a_wrap_count_mismatch() {
        let mut conn = test_conn();
        let conv = group_with_three_members(&mut conn);

        let err = remove_member_and_rekey(
            &mut conn,
            conv.id,
            3,
            2,
            1,
            &[GroupKeyWrapInput { member_user_id: 1, wrapper_public_key: b"wpk1", nonce: b"nonce-abcd12", ciphertext: b"ct1" }],
            T1,
        )
        .unwrap_err();
        assert!(matches!(err, RekeyError::WrapCountMismatch { expected: 2, got: 1 }));

        // Rolled back: member 3 is still present, still at epoch 1, no wraps written.
        assert_eq!(current_group_epoch(&conn, conv.id).expect("epoch"), 1);
        assert!(get_member(&conn, conv.id, 3).expect("get").is_some());
        let wrap_count: i64 = conn.query_row("SELECT COUNT(*) FROM group_key_wraps", [], |row| row.get(0)).expect("count");
        assert_eq!(wrap_count, 0);
    }

    // ---- messages / paging ----

    #[test]
    fn list_messages_pages_the_same_way_dm_db_does() {
        let conn = test_conn();
        let conv = get_or_create_dm_conversation(&conn, 1, 2, T0).expect("create");
        let nonce = [0u8; DM_NONCE_LEN];
        let ids: Vec<i64> = (0..60)
            .map(|i| create_sealed_message(&conn, conv.id, 1, &nonce, format!("m{i}").as_bytes(), None, None, T0).expect("insert"))
            .collect();
        assert_eq!(ids.len(), 60);

        let newest = list_messages(&conn, conv.id, MessagePage::Newest, 50).expect("newest");
        let got: Vec<i64> = newest.iter().map(|m| m.id).collect();
        assert_eq!(got, ids[10..60]);

        let after = list_messages(&conn, conv.id, MessagePage::After(ids[54]), 50).expect("after");
        let got: Vec<i64> = after.iter().map(|m| m.id).collect();
        assert_eq!(got, ids[55..60]);

        let before = list_messages(&conn, conv.id, MessagePage::Before(ids[10]), 50).expect("before");
        let got: Vec<i64> = before.iter().map(|m| m.id).collect();
        assert_eq!(got, ids[0..10]);
    }

    #[test]
    fn create_sealed_message_refuses_oversized_ciphertext() {
        let conn = test_conn();
        let conv = get_or_create_dm_conversation(&conn, 1, 2, T0).expect("create");
        let nonce = [0u8; DM_NONCE_LEN];
        let oversized = vec![0u8; DM_MAX_CIPHERTEXT_BYTES + 1];
        let err = create_sealed_message(&conn, conv.id, 1, &nonce, &oversized, None, None, T0).unwrap_err();
        assert!(matches!(err, MessageError::TooLarge));
    }

    #[test]
    fn edit_sealed_message_refuses_once_the_group_has_rekeyed_past_the_messages_epoch() {
        let mut conn = test_conn();
        let conv = group_with_three_members(&mut conn);
        let nonce = [0u8; DM_NONCE_LEN];
        let message_id = create_sealed_message(&conn, conv.id, 1, &nonce, b"epoch1 text", Some(1), None, T0).expect("insert");

        remove_member_and_rekey(
            &mut conn,
            conv.id,
            3,
            2,
            1,
            &[
                GroupKeyWrapInput { member_user_id: 1, wrapper_public_key: b"wpk1", nonce: b"nonce-abcd12", ciphertext: b"ct1" },
                GroupKeyWrapInput { member_user_id: 2, wrapper_public_key: b"wpk1", nonce: b"nonce-abcd34", ciphertext: b"ct2" },
            ],
            T1,
        )
        .expect("rekey to epoch 2");

        let err = edit_sealed_message(&conn, message_id, &nonce, b"edited text", T2).unwrap_err();
        assert!(matches!(err, EditMessageError::EpochSuperseded { message_epoch: 1, current_epoch: 2 }));

        // A dm message (epoch = None) has no such boundary.
        let dm_conv = get_or_create_dm_conversation(&conn, 5, 6, T0).expect("dm");
        let dm_message = create_sealed_message(&conn, dm_conv.id, 5, &nonce, b"hi", None, None, T0).expect("insert dm");
        edit_sealed_message(&conn, dm_message, &nonce, b"edited hi", T1).expect("dm edit always allowed");
    }

    // ---- mark_read ----

    #[test]
    fn mark_read_only_advances_the_readers_own_cursor() {
        let conn = test_conn();
        let conv = get_or_create_dm_conversation(&conn, 1, 2, T0).expect("create");
        let nonce = [0u8; DM_NONCE_LEN];
        let m1 = create_sealed_message(&conn, conv.id, 1, &nonce, b"a", None, None, T0).expect("insert");
        let m2 = create_sealed_message(&conn, conv.id, 2, &nonce, b"b", None, None, T1).expect("insert");

        assert!(mark_read(&conn, conv.id, 1, m2).expect("mark read"));
        let reader = get_member(&conn, conv.id, 1).expect("get").expect("row");
        assert_eq!(reader.read_cursor_id, m2);
        let peer = get_member(&conn, conv.id, 2).expect("get").expect("row");
        assert_eq!(peer.read_cursor_id, 0, "the peer's own cursor is untouched");

        // Never regresses.
        assert!(!mark_read(&conn, conv.id, 1, m1).expect("mark read lower id"));
        let reader_after = get_member(&conn, conv.id, 1).expect("get").expect("row");
        assert_eq!(reader_after.read_cursor_id, m2);
    }

    // ---- pins + reactions ----

    #[test]
    fn pin_and_reaction_toggle_round_trip() {
        let conn = test_conn();
        let conv = get_or_create_dm_conversation(&conn, 1, 2, T0).expect("create");
        let nonce = [0u8; DM_NONCE_LEN];
        let message_id = create_sealed_message(&conn, conv.id, 1, &nonce, b"hi", None, None, T0).expect("insert");

        assert!(pin_message(&conn, message_id, T1).expect("pin"));
        assert_eq!(list_pinned_messages(&conn, conv.id).expect("pinned").len(), 1);
        // Pinning an already-pinned message is a no-op, not a second row.
        assert!(!pin_message(&conn, message_id, T2).expect("pin again"));
        assert!(unpin_message(&conn, message_id).expect("unpin"));
        assert_eq!(list_pinned_messages(&conn, conv.id).expect("pinned").len(), 0);

        add_reaction(&conn, message_id, 2, "👍", T1).expect("react");
        assert_eq!(list_reactions(&conn, message_id).expect("reactions").len(), 1);
        // Idempotent — the same reaction twice is still one row.
        add_reaction(&conn, message_id, 2, "👍", T2).expect("react again");
        assert_eq!(list_reactions(&conn, message_id).expect("reactions").len(), 1);
        assert!(remove_reaction(&conn, message_id, 2, "👍").expect("un-react"));
        assert_eq!(list_reactions(&conn, message_id).expect("reactions").len(), 0);
    }

    // ---- delete_message ----

    #[test]
    fn delete_message_self_service_only_touches_the_authors_own_message() {
        let conn = test_conn();
        let conv = get_or_create_dm_conversation(&conn, 1, 2, T0).expect("create");
        let nonce = [0u8; DM_NONCE_LEN];
        let mine = create_sealed_message(&conn, conv.id, 1, &nonce, b"mine", None, None, T0).expect("insert");
        let theirs = create_sealed_message(&conn, conv.id, 2, &nonce, b"theirs", None, None, T0).expect("insert");

        assert!(!delete_message(&conn, theirs, Some(1), T1).expect("refused: not the author"));
        assert!(delete_message(&conn, mine, Some(1), T1).expect("own message deletes"));
        assert!(get_message(&conn, mine).expect("get").expect("row").deleted_at.is_some());

        // Privileged (owner/admin) delete: unconditional.
        assert!(delete_message(&conn, theirs, None, T2).expect("privileged delete"));
    }

    // ---- channel ----

    #[test]
    fn channel_creation_signing_and_posting_round_trip() {
        let conn = test_conn();
        let conv = create_channel_conversation(&conn, 1, "Announcements", Some("desc"), Visibility::Public, true, T0).expect("create channel");
        assert_eq!(conv.kind, ConversationKind::Channel);
        let members = list_members(&conn, conv.id).expect("members");
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].role, MemberRole::Owner);

        let key = vec![9u8; CHANNEL_SIGNING_PUBLIC_KEY_LEN];
        upsert_channel_signing_key(&conn, 1, &key, T0).expect("publish signing key");
        let published = get_channel_signing_key(&conn, 1).expect("get").expect("row");
        assert_eq!(published.public_key, key);

        let message_id = create_signed_message(&conn, conv.id, 1, "hello channel", b"sig-bytes", None, T1).expect("post");
        let stored = get_message(&conn, message_id).expect("get").expect("row");
        assert_eq!(stored.body.as_deref(), Some("hello channel"));
        assert_eq!(stored.signature.as_deref(), Some(b"sig-bytes".as_slice()));

        assert!(edit_signed_message(&conn, message_id, "hello channel v2", b"sig-bytes-2", T2).expect("edit"));
        let edited = get_message(&conn, message_id).expect("get").expect("row");
        assert_eq!(edited.body.as_deref(), Some("hello channel v2"));
        assert!(edited.edited_at.is_some());
    }

    #[test]
    fn upsert_channel_signing_key_refuses_wrong_length() {
        let conn = test_conn();
        let short_key = vec![1u8; 4];
        let err = upsert_channel_signing_key(&conn, 1, &short_key, T0).unwrap_err();
        assert!(matches!(err, ChannelSigningKeyError::InvalidLength));
    }

    // ---- membership prefs ----

    #[test]
    fn set_membership_prefs_only_touch_the_named_members_own_row() {
        let conn = test_conn();
        let conv = get_or_create_dm_conversation(&conn, 1, 2, T0).expect("create");

        assert!(set_pinned(&conn, conv.id, 1, true).expect("pin"));
        assert!(set_archived(&conn, conv.id, 1, true).expect("archive"));
        assert!(set_muted_until(&conn, conv.id, 1, Some("forever")).expect("mute"));

        let mine = get_member(&conn, conv.id, 1).expect("get").expect("row");
        assert!(mine.pinned);
        assert!(mine.archived);
        assert_eq!(mine.muted_until.as_deref(), Some("forever"));

        let theirs = get_member(&conn, conv.id, 2).expect("get").expect("row");
        assert!(!theirs.pinned);
        assert!(!theirs.archived);
        assert_eq!(theirs.muted_until, None);
    }

    // ---- folders ----

    #[test]
    fn folder_order_persists_and_reorders_atomically() {
        let mut conn = test_conn();
        let f1 = create_folder(&conn, 1, "Work", "folder", 0, FolderFilters::default(), T0).expect("create f1");
        let f2 = create_folder(&conn, 1, "Trading", "chart", 1, FolderFilters::default(), T0).expect("create f2");
        let f3 = create_folder(&conn, 1, "Friends", "heart", 2, FolderFilters::default(), T0).expect("create f3");

        reorder_folders(&mut conn, 1, &[f3, f1, f2], T1).expect("reorder");
        let ids: Vec<i64> = list_folders_for_user(&conn, 1).expect("list").iter().map(|f| f.id).collect();
        assert_eq!(ids, vec![f3, f1, f2]);

        // Atomicity: an id not owned by user 1 refuses the WHOLE batch, and
        // the order established above is left exactly as it was.
        let other_users_folder = create_folder(&conn, 2, "Other", "folder", 0, FolderFilters::default(), T0).expect("create for user 2");
        let err = reorder_folders(&mut conn, 1, &[f1, other_users_folder, f2], T2).unwrap_err();
        assert!(matches!(err, ReorderError::NotOwner { folder_id } if folder_id == other_users_folder));

        let positions: Vec<i64> = list_folders_for_user(&conn, 1).expect("list").iter().map(|f| f.position).collect();
        assert_eq!(positions, vec![0, 1, 2]);
        let ids_after: Vec<i64> = list_folders_for_user(&conn, 1).expect("list").iter().map(|f| f.id).collect();
        assert_eq!(ids_after, vec![f3, f1, f2]);
    }

    #[test]
    fn folder_chats_add_remove_and_delete_cascade() {
        let conn = test_conn();
        let folder_id = create_folder(&conn, 1, "Work", "folder", 0, FolderFilters::default(), T0).expect("create folder");
        let conv = get_or_create_dm_conversation(&conn, 1, 2, T0).expect("create conversation");

        add_chat_to_folder(&conn, folder_id, conv.id).expect("add");
        assert_eq!(list_chats_in_folder(&conn, folder_id).expect("list"), vec![conv.id]);
        // Idempotent.
        add_chat_to_folder(&conn, folder_id, conv.id).expect("add again");
        assert_eq!(list_chats_in_folder(&conn, folder_id).expect("list"), vec![conv.id]);

        assert!(remove_chat_from_folder(&conn, folder_id, conv.id).expect("remove"));
        assert!(list_chats_in_folder(&conn, folder_id).expect("list").is_empty());

        add_chat_to_folder(&conn, folder_id, conv.id).expect("add back");
        assert!(delete_folder(&conn, folder_id, 1).expect("delete owned folder"));
        assert!(list_chats_in_folder(&conn, folder_id).expect("list").is_empty(), "folder_chats cascade-cleared");

        // Deleting a folder not owned by the caller is a no-op.
        let other_folder = create_folder(&conn, 2, "Other", "folder", 0, FolderFilters::default(), T0).expect("create");
        assert!(!delete_folder(&conn, other_folder, 1).expect("not owned"));
    }
}

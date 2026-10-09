//! Matrix-shaped event store — rooms/events/state/members/relations/
//! receipts/account-data/txn-dedup/filters half of `messenger.db` (the
//! devices/keys/backup half is `matrix_keys_store.rs`, a separate work
//! item). See `docs/mlc/plans/messenger-proto-server-matrix-subset-2026-09-24.md`
//! §2 for the full DDL this module implements (the "Manager decisions on
//! this plan" section at the top of that file overrides the body — this
//! module follows those corrections, noted inline where they apply) and §1
//! for the id-format rules.
//!
//! This server adopts Matrix's own event envelope, state-resolution model,
//! and CS API shape for everything except federation and `/login` — CS API
//! v1.19, room version 11. Crypto stays entirely client-side: every
//! `content` blob this module stores is opaque JSON it never inspects
//! except for `m.relates_to` (relation bookkeeping, kept in cleartext at
//! the top level of `content` even for `m.room.encrypted`, per the Matrix
//! spec's own accepted trade-off — plan §10 item 3) and the redaction
//! allow-list (§2's `redact_event`, which strips by `event_type`, never by
//! interpreting the payload's meaning).
//!
//! # Single-writer discipline
//!
//! Every function here takes an already-open [`Connection`]; the caller
//! (`state.rs`, from P14 onward) holds it behind one `std::sync::Mutex`,
//! the same discipline `db`/`social_db` already use — this module never
//! locks anything itself and never calls `std::sync::Mutex` internally.
//! That single-writer guarantee is what makes [`next_stream_id`] safe: it
//! is always called inside the same transaction as the row it stamps, and
//! there is never a second writer racing it.
//!
//! # Cross-database rule
//!
//! Like `dm_db.rs`, this module stores only `user_id INTEGER` — never a
//! display name or a nick — labels are resolved live from the identity
//! connection by callers. The one exception is [`matrix_users`], the table
//! that maps `user_id` to its Matrix id (`mxid`) once and for all (plan §2
//! manager decision: `public_id` is immutable, so this mapping never
//! changes and is safe to cache here rather than re-deriving it from the
//! identity database on every response).
//!
//! The one place a label does end up in this database is the `displayname`
//! field of an `m.room.member` event's `content` — the Matrix convention,
//! and what a client names a DM and lists members by. Callers stamp the
//! identity database's effective label into every `join`/`invite` member
//! event they write, and [`refresh_member_displayname`] re-stamps it into
//! the user's existing member events when the label changes.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use std::collections::HashSet;
use std::fmt;

// ============================================================================
// Server name, id formats
// ============================================================================

/// The one Matrix server name this deployment ever answers as — used
/// everywhere an mxid/room id is formatted or parsed. Never a second
/// literal (plan §1).
pub const MATRIX_SERVER_NAME: &str = "mylittlechart.org";

/// Room version pinned for every room this server creates (plan §1) — v11
/// still lists the creator explicitly in `m.room.power_levels.users`,
/// unlike v12's "infinite implicit power" simplification, which this plan
/// does not adopt.
pub const MATRIX_ROOM_VERSION: &str = "11";

/// Ceiling on the serialized `content` of any state/timeline event this
/// server accepts (plan §3.8, mirroring `dm_db::DM_MAX_CIPHERTEXT_BYTES`) —
/// checked by every route that takes client-supplied event content
/// (`routes::matrix::rooms::put_state` first; messaging/to-device pieces
/// reuse the same constant rather than minting their own).
pub const MATRIX_EVENT_CONTENT_MAX_BYTES: usize = 16 * 1024;

/// Localpart prefix reserved for a future Application Service (bridge)
/// namespace (plan §10 item 6). `matrix_store`'s own id generators never
/// mint a localpart starting with this — see [`ensure_matrix_user`] — so a
/// later AS registration slots in without a retroactive id-collision audit.
pub const RESERVED_LOCALPART_PREFIX: &str = "_bridge_";

/// True if `localpart` is reserved for the future Application Service
/// namespace (plan §10 item 6) and must never be minted as a real user's
/// mxid localpart.
pub fn is_reserved_localpart(localpart: &str) -> bool {
    localpart.starts_with(RESERVED_LOCALPART_PREFIX)
}

/// Why parsing an mxid failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixIdError {
    /// Did not start with `@`.
    MissingSigil,
    /// No `:server_name` suffix at all.
    MissingServerName,
    /// Addressed to a server other than [`MATRIX_SERVER_NAME`] — this
    /// deployment does not federate, so such an id can never resolve to a
    /// real local account.
    ForeignServerName,
}

impl fmt::Display for MatrixIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MatrixIdError::MissingSigil => write!(f, "mxid is missing its '@' sigil"),
            MatrixIdError::MissingServerName => write!(f, "mxid is missing a ':server_name' suffix"),
            MatrixIdError::ForeignServerName => write!(f, "mxid is addressed to a foreign server name"),
        }
    }
}

/// Format `public_id` (the identity database's immutable `users.public_id`)
/// as this server's own mxid: `@<public_id>:mylittlechart.org`.
pub fn mxid_for_public_id(public_id: &str) -> String {
    format!("@{public_id}:{MATRIX_SERVER_NAME}")
}

/// Parse `@localpart:server_name`, returning the localpart — refusing
/// anything not addressed to [`MATRIX_SERVER_NAME`] (plan §1: no
/// federation, so a foreign-server mxid can never be a real local user).
pub fn public_id_from_mxid(mxid: &str) -> Result<&str, MatrixIdError> {
    let rest = mxid.strip_prefix('@').ok_or(MatrixIdError::MissingSigil)?;
    let (localpart, server_name) = rest.split_once(':').ok_or(MatrixIdError::MissingServerName)?;
    if server_name != MATRIX_SERVER_NAME {
        return Err(MatrixIdError::ForeignServerName);
    }
    Ok(localpart)
}

/// Mint 16 random bytes, URL-safe base64, no padding (~22 chars) — the
/// random component shared by room ids and event ids (plan §1).
fn random_id_component() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use rand::Rng;
    let bytes: [u8; 16] = rand::thread_rng().gen();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Mint a fresh room id: `"!" + 22 random URL-safe-base64 chars + ":mylittlechart.org"`.
pub fn new_room_id() -> String {
    format!("!{}:{}", random_id_component(), MATRIX_SERVER_NAME)
}

/// Mint a fresh event id: `"$" + 22 random URL-safe-base64 chars` — opaque,
/// no reference-hash content addressing (no federation to need it).
pub fn new_event_id() -> String {
    format!("${}", random_id_component())
}

// ============================================================================
// Errors
// ============================================================================

/// Why a write into this store was refused, on top of a real database
/// failure — same shape as `dm_db::MessageError`/`IdentityKeyError`.
#[derive(Debug)]
pub enum MatrixStoreError {
    Db(rusqlite::Error),
    /// An event's `content` was not valid JSON where this module needed to
    /// read a field out of it (membership, power levels, `m.relates_to`).
    Json(serde_json::Error),
    /// [`ensure_matrix_user`] was asked to mint a reserved localpart (plan
    /// §10 item 6) — see [`is_reserved_localpart`].
    ReservedLocalpart,
    /// A second `m.annotation` relation with the same sender, target, and
    /// aggregation key as an existing one (plan §2/§9: maps to
    /// `M_DUPLICATE_ANNOTATION`/400 at the route layer, a later piece).
    DuplicateAnnotation,
    /// A referenced event id does not exist in `events`.
    UnknownEventId(String),
    /// A referenced mxid does not exist in `matrix_users` — the caller must
    /// [`ensure_matrix_user`] before naming that user in room state.
    UnknownMxid(String),
    /// An `m.room.member` event's `content.membership` was missing or not
    /// one of `join`/`invite`/`leave`/`ban`.
    InvalidMembership(String),
    /// A relation's `m.relates_to` target (the `String` is the target event
    /// id) does not exist, or exists in a different room than the relation
    /// event being inserted — a relation can never point out of its own
    /// room.
    InvalidRelationTarget(String),
    /// A referenced event (the `String` is its event id) exists but is in a
    /// different room than the one the caller named — refused rather than
    /// silently acted on, since acting on it would let a caller redact or
    /// mark-read an event that was never a member of the room they claimed.
    WrongRoom(String),
    /// [`redact_event`] was asked to redact an event type this server never
    /// allows to be redacted (the `String` is that `event_type`) — see
    /// [`redact_event`]'s doc comment.
    UnredactableEvent(String),
}

impl From<rusqlite::Error> for MatrixStoreError {
    fn from(e: rusqlite::Error) -> Self {
        MatrixStoreError::Db(e)
    }
}

impl From<serde_json::Error> for MatrixStoreError {
    fn from(e: serde_json::Error) -> Self {
        MatrixStoreError::Json(e)
    }
}

// ============================================================================
// Small TEXT-backed enums (`as_str`/`from_wire_name`, matching
// `social_db::Class`'s own convention)
// ============================================================================

/// Our own room-kind label (`rooms.kind`) — drives the power-level/history-
/// visibility defaults of plan §5. Not a Matrix wire field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomKind {
    Dm,
    Group,
    Channel,
}

impl RoomKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RoomKind::Dm => "dm",
            RoomKind::Group => "group",
            RoomKind::Channel => "channel",
        }
    }

    pub fn from_wire_name(s: &str) -> Option<Self> {
        match s {
            "dm" => Some(RoomKind::Dm),
            "group" => Some(RoomKind::Group),
            "channel" => Some(RoomKind::Channel),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinRule {
    Invite,
    Public,
}

impl JoinRule {
    pub fn as_str(self) -> &'static str {
        match self {
            JoinRule::Invite => "invite",
            JoinRule::Public => "public",
        }
    }

    pub fn from_wire_name(s: &str) -> Option<Self> {
        match s {
            "invite" => Some(JoinRule::Invite),
            "public" => Some(JoinRule::Public),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryVisibility {
    Shared,
    WorldReadable,
    Invited,
    Joined,
}

impl HistoryVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            HistoryVisibility::Shared => "shared",
            HistoryVisibility::WorldReadable => "world_readable",
            HistoryVisibility::Invited => "invited",
            HistoryVisibility::Joined => "joined",
        }
    }

    pub fn from_wire_name(s: &str) -> Option<Self> {
        match s {
            "shared" => Some(HistoryVisibility::Shared),
            "world_readable" => Some(HistoryVisibility::WorldReadable),
            "invited" => Some(HistoryVisibility::Invited),
            "joined" => Some(HistoryVisibility::Joined),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Membership {
    Join,
    Invite,
    Leave,
    Ban,
}

impl Membership {
    pub fn as_str(self) -> &'static str {
        match self {
            Membership::Join => "join",
            Membership::Invite => "invite",
            Membership::Leave => "leave",
            Membership::Ban => "ban",
        }
    }

    pub fn from_wire_name(s: &str) -> Option<Self> {
        match s {
            "join" => Some(Membership::Join),
            "invite" => Some(Membership::Invite),
            "leave" => Some(Membership::Leave),
            "ban" => Some(Membership::Ban),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptType {
    Read,
    ReadPrivate,
}

impl ReceiptType {
    pub fn as_str(self) -> &'static str {
        match self {
            ReceiptType::Read => "m.read",
            ReceiptType::ReadPrivate => "m.read.private",
        }
    }

    pub fn from_wire_name(s: &str) -> Option<Self> {
        match s {
            "m.read" => Some(ReceiptType::Read),
            "m.read.private" => Some(ReceiptType::ReadPrivate),
            _ => None,
        }
    }
}

/// Decode a TEXT column this module itself always writes from one of the
/// enums above — a `None` from `parse` means the row was written by
/// something other than this module's own CRUD, which is a data-integrity
/// bug, not a normal "not found" case, hence `InvalidColumnType` rather
/// than silently defaulting.
fn decode_enum<T>(idx: usize, column: &'static str, raw: &str, parse: fn(&str) -> Option<T>) -> rusqlite::Result<T> {
    parse(raw).ok_or_else(|| rusqlite::Error::InvalidColumnType(idx, column.to_string(), rusqlite::types::Type::Text))
}

// ============================================================================
// Schema
// ============================================================================

/// Create every table/index this module needs — idempotent (`IF NOT
/// EXISTS`/`INSERT OR IGNORE` throughout), so it runs on every boot. Called
/// from [`init_messenger_db`] and directly by this module's own tests
/// against a plain in-memory connection (no SQLCipher key needed for schema
/// creation) — same split `social_db::create_social_schema` uses.
///
/// Deviation from the plan's literal DDL text (§2, both noted inline as
/// `-- DEVIATION`): `account_data.room_id` drops its `REFERENCES rooms(id)`
/// — the manager's own correction makes `room_id` `NOT NULL DEFAULT ''` for
/// global account data, and `''` never matches a real room id, so keeping
/// the foreign key would make every global upsert fail once `PRAGMA
/// foreign_keys=ON` is set (as [`init_messenger_db`] does).
pub fn create_matrix_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        -- Global stream ordering — see this module's doc comment on the
        -- single-writer guarantee that makes `UPDATE ... RETURNING` safe.
        CREATE TABLE IF NOT EXISTS stream_counter (
            id    INTEGER PRIMARY KEY CHECK (id = 1),
            value INTEGER NOT NULL
        );
        INSERT OR IGNORE INTO stream_counter (id, value) VALUES (1, 0);

        -- user_id -> mxid, filled on first touch by ensure_matrix_user
        -- (plan §2 manager decision: new table, not in the original DDL
        -- text). public_id is immutable, so this mapping never changes.
        CREATE TABLE IF NOT EXISTS matrix_users (
            user_id    INTEGER PRIMARY KEY,
            mxid       TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS rooms (
            id                  TEXT PRIMARY KEY,
            kind                TEXT NOT NULL,
            room_version        TEXT NOT NULL DEFAULT '11',
            creator_user_id     INTEGER NOT NULL,
            created_at          TEXT NOT NULL,
            is_encrypted        INTEGER NOT NULL DEFAULT 0,
            join_rule           TEXT NOT NULL DEFAULT 'invite',
            history_visibility  TEXT NOT NULL DEFAULT 'shared',
            dm_pair_key         TEXT UNIQUE,
            legacy_dm_id        INTEGER UNIQUE
        );
        CREATE INDEX IF NOT EXISTS idx_rooms_kind ON rooms(kind);

        CREATE TABLE IF NOT EXISTS events (
            stream_id        INTEGER PRIMARY KEY,
            event_id         TEXT NOT NULL UNIQUE,
            room_id          TEXT NOT NULL REFERENCES rooms(id),
            sender_user_id   INTEGER NOT NULL,
            event_type       TEXT NOT NULL,
            state_key        TEXT,
            content          TEXT NOT NULL,
            origin_server_ts INTEGER NOT NULL,
            txn_id           TEXT,
            redacts          TEXT REFERENCES events(event_id),
            redacted_by      TEXT REFERENCES events(event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_events_room_stream ON events(room_id, stream_id);
        CREATE INDEX IF NOT EXISTS idx_events_room_type_state ON events(room_id, event_type, state_key);
        CREATE INDEX IF NOT EXISTS idx_events_sender ON events(sender_user_id, stream_id);

        CREATE TABLE IF NOT EXISTS current_state (
            room_id    TEXT NOT NULL REFERENCES rooms(id),
            event_type TEXT NOT NULL,
            state_key  TEXT NOT NULL,
            event_id   TEXT NOT NULL REFERENCES events(event_id),
            PRIMARY KEY (room_id, event_type, state_key)
        );

        CREATE TABLE IF NOT EXISTS room_members (
            room_id     TEXT NOT NULL REFERENCES rooms(id),
            user_id     INTEGER NOT NULL,
            membership  TEXT NOT NULL,
            power_level INTEGER,
            updated_at  TEXT NOT NULL,
            PRIMARY KEY (room_id, user_id)
        );
        CREATE INDEX IF NOT EXISTS idx_room_members_user ON room_members(user_id, membership);

        CREATE TABLE IF NOT EXISTS relations (
            event_id  TEXT PRIMARY KEY REFERENCES events(event_id),
            room_id   TEXT NOT NULL REFERENCES rooms(id),
            rel_type  TEXT NOT NULL,
            target_id TEXT NOT NULL REFERENCES events(event_id),
            agg_key   TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_relations_target ON relations(target_id, rel_type);

        CREATE TABLE IF NOT EXISTS receipts (
            room_id      TEXT NOT NULL REFERENCES rooms(id),
            user_id      INTEGER NOT NULL,
            receipt_type TEXT NOT NULL,
            event_id     TEXT NOT NULL REFERENCES events(event_id),
            ts           INTEGER NOT NULL,
            stream_id    INTEGER NOT NULL,
            PRIMARY KEY (room_id, user_id, receipt_type)
        );
        CREATE INDEX IF NOT EXISTS idx_receipts_room_stream ON receipts(room_id, stream_id);

        -- DEVIATION from plan §2's literal text: room_id has no
        -- `REFERENCES rooms(id)` — see this function's doc comment.
        CREATE TABLE IF NOT EXISTS account_data (
            user_id   INTEGER NOT NULL,
            room_id   TEXT NOT NULL DEFAULT '',
            data_type TEXT NOT NULL,
            content   TEXT NOT NULL,
            stream_id INTEGER NOT NULL,
            PRIMARY KEY (user_id, room_id, data_type)
        );
        CREATE INDEX IF NOT EXISTS idx_account_data_user_stream ON account_data(user_id, stream_id);

        CREATE TABLE IF NOT EXISTS txn_dedup (
            user_id    INTEGER NOT NULL,
            device_id  TEXT NOT NULL,
            txn_id     TEXT NOT NULL,
            event_id   TEXT REFERENCES events(event_id),
            created_at TEXT NOT NULL,
            PRIMARY KEY (user_id, device_id, txn_id)
        );

        CREATE TABLE IF NOT EXISTS filters (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            definition TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS legacy_dm_message_map (
            legacy_message_id INTEGER PRIMARY KEY,
            event_id          TEXT NOT NULL UNIQUE REFERENCES events(event_id)
        );
        "#,
    )
}

/// Open (creating if absent) the SQLCipher-encrypted `messenger.db` at
/// `path`, key it, and create BOTH halves of the schema. Mirrors
/// `social_db::init_social_db`: the key is the very first statement on the
/// connection, then WAL + foreign keys, then schema. Calls
/// `matrix_keys_store::create_matrix_keys_schema` right after this module's
/// own [`create_matrix_schema`] — both idempotent, so this is the one place
/// the whole `messenger.db` schema comes into existence on boot.
pub fn init_messenger_db(path: &str, key_hex: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(&format!("PRAGMA key = \"x'{key_hex}'\";"))?;
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;
    // Product server and messenger process both open this file: the product
    // server still revokes devices on session revoke and account delete.
    conn.execute_batch("PRAGMA busy_timeout=5000;")?;
    create_matrix_schema(&conn)?;
    crate::matrix_keys_store::create_matrix_keys_schema(&conn)?;
    Ok(conn)
}

// ============================================================================
// Stream ordering
// ============================================================================

/// Take the next value from the single global counter, inside `tx` — always
/// called in the SAME transaction as the row it stamps (this module's one
/// hard invariant; see the module doc's single-writer note on why this
/// stays race-free with no additional locking). `pub(crate)` so
/// `matrix_keys_store.rs` can stamp its own stream-ordered tables
/// (`to_device_messages`, `device_list_changes`) off this same counter
/// rather than minting a second one.
pub(crate) fn next_stream_id(tx: &Transaction) -> rusqlite::Result<i64> {
    tx.query_row("UPDATE stream_counter SET value = value + 1 WHERE id = 1 RETURNING value", [], |row| row.get(0))
}

/// The last stream id issued to any table — the counter's current value.
/// Since every stream-ordered table shares this one counter, this is also
/// the highest `stream_id` that exists anywhere in the database right now.
pub fn max_stream_id(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT value FROM stream_counter WHERE id = 1", [], |row| row.get(0))
}

// ============================================================================
// Matrix users (user_id <-> mxid)
// ============================================================================

/// Register `user_id`'s mxid on first touch (idempotent — a later call for
/// the same `user_id` is a no-op) and return it. Refuses to mint a
/// [reserved][is_reserved_localpart] localpart.
pub fn ensure_matrix_user(conn: &Connection, user_id: i64, public_id: &str, now: &str) -> Result<String, MatrixStoreError> {
    if is_reserved_localpart(public_id) {
        return Err(MatrixStoreError::ReservedLocalpart);
    }
    let mxid = mxid_for_public_id(public_id);
    conn.execute(
        "INSERT INTO matrix_users (user_id, mxid, created_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(user_id) DO NOTHING",
        params![user_id, mxid, now],
    )?;
    Ok(mxid)
}

/// `user_id`'s mxid, if [`ensure_matrix_user`] has ever run for it.
pub fn mxid_of(conn: &Connection, user_id: i64) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT mxid FROM matrix_users WHERE user_id = ?1", params![user_id], |row| row.get(0))
        .optional()
}

/// The internal `user_id` behind `mxid`, if known.
pub fn user_id_of(conn: &Connection, mxid: &str) -> rusqlite::Result<Option<i64>> {
    conn.query_row("SELECT user_id FROM matrix_users WHERE mxid = ?1", params![mxid], |row| row.get(0))
        .optional()
}

// ============================================================================
// Rooms
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct Room {
    pub id: String,
    pub kind: RoomKind,
    pub room_version: String,
    pub creator_user_id: i64,
    pub created_at: String,
    pub is_encrypted: bool,
    pub join_rule: JoinRule,
    pub history_visibility: HistoryVisibility,
    pub dm_pair_key: Option<String>,
    pub legacy_dm_id: Option<i64>,
}

const ROOM_SELECT_COLUMNS: &str =
    "id, kind, room_version, creator_user_id, created_at, is_encrypted, join_rule, history_visibility, dm_pair_key, legacy_dm_id";

fn room_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Room> {
    let kind_raw: String = row.get(1)?;
    let join_rule_raw: String = row.get(6)?;
    let history_visibility_raw: String = row.get(7)?;
    Ok(Room {
        id: row.get(0)?,
        kind: decode_enum(1, "kind", &kind_raw, RoomKind::from_wire_name)?,
        room_version: row.get(2)?,
        creator_user_id: row.get(3)?,
        created_at: row.get(4)?,
        is_encrypted: row.get(5)?,
        join_rule: decode_enum(6, "join_rule", &join_rule_raw, JoinRule::from_wire_name)?,
        history_visibility: decode_enum(7, "history_visibility", &history_visibility_raw, HistoryVisibility::from_wire_name)?,
        dm_pair_key: row.get(8)?,
        legacy_dm_id: row.get(9)?,
    })
}

/// The shared core of [`create_room`]/[`create_room_with_state`]: one INSERT
/// into `rooms`. Takes a plain `&Connection` — callable as `insert_room_row(conn, ...)`
/// from the standalone [`create_room`] or as `insert_room_row(&tx, ...)` from
/// inside [`create_room_with_state`]'s transaction (`rusqlite::Transaction`
/// derefs to `Connection`, so the same function body serves both, per this
/// module's "single-event API and the batch share code" rule).
#[allow(clippy::too_many_arguments)]
fn insert_room_row(
    conn: &Connection,
    room_id: &str,
    kind: RoomKind,
    creator_user_id: i64,
    created_at: &str,
    is_encrypted: bool,
    join_rule: JoinRule,
    history_visibility: HistoryVisibility,
    dm_pair_key: Option<&str>,
    legacy_dm_id: Option<i64>,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO rooms (id, kind, room_version, creator_user_id, created_at, is_encrypted, join_rule, history_visibility, dm_pair_key, legacy_dm_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            room_id,
            kind.as_str(),
            MATRIX_ROOM_VERSION,
            creator_user_id,
            created_at,
            is_encrypted,
            join_rule.as_str(),
            history_visibility.as_str(),
            dm_pair_key,
            legacy_dm_id,
        ],
    )?;
    Ok(())
}

/// Insert a room's metadata row only — no bootstrap state events (those go
/// through [`apply_state_event`] separately, e.g. `m.room.create`,
/// `m.room.member`, `m.room.power_levels`, per plan §5/§7). Kept as a
/// standalone single-row entry point for a future non-transactional caller
/// and for this module's own tests; [`create_room_with_state`] is the P5
/// batch entry point everything under `routes::matrix::rooms` uses instead.
#[allow(clippy::too_many_arguments)]
pub fn create_room(
    conn: &Connection,
    room_id: &str,
    kind: RoomKind,
    creator_user_id: i64,
    created_at: &str,
    is_encrypted: bool,
    join_rule: JoinRule,
    history_visibility: HistoryVisibility,
    dm_pair_key: Option<&str>,
    legacy_dm_id: Option<i64>,
) -> rusqlite::Result<()> {
    insert_room_row(conn, room_id, kind, creator_user_id, created_at, is_encrypted, join_rule, history_visibility, dm_pair_key, legacy_dm_id)
}

pub fn get_room(conn: &Connection, room_id: &str) -> rusqlite::Result<Option<Room>> {
    conn.query_row(&format!("SELECT {ROOM_SELECT_COLUMNS} FROM rooms WHERE id = ?1"), params![room_id], room_from_row)
        .optional()
}

/// The room currently holding `pair_key` as its `dm_pair_key`, if any — the
/// binary crate's `routes::matrix::rooms::create_room`'s DM-reuse lookup
/// (plan P5 correction: "a second DM between the same pair returns the
/// existing room id only if it is still a live DM for both").
pub fn room_by_dm_pair_key(conn: &Connection, pair_key: &str) -> rusqlite::Result<Option<Room>> {
    conn.query_row(&format!("SELECT {ROOM_SELECT_COLUMNS} FROM rooms WHERE dm_pair_key = ?1"), params![pair_key], room_from_row)
        .optional()
}

/// The room already migrated from `dm_conversations.id = legacy_dm_id`, if
/// any — the binary crate's own `matrix_migration` module's idempotency gate
/// (plan §7 step 2: "For each `dm_conversations` row without a
/// `rooms.legacy_dm_id` match").
pub fn room_by_legacy_dm_id(conn: &Connection, legacy_dm_id: i64) -> rusqlite::Result<Option<Room>> {
    conn.query_row(&format!("SELECT {ROOM_SELECT_COLUMNS} FROM rooms WHERE legacy_dm_id = ?1"), params![legacy_dm_id], room_from_row)
        .optional()
}

/// Free `room_id`'s `dm_pair_key` slot (set it to `NULL`) — called when a
/// prior DM between the same pair is no longer live (one party left), so a
/// freshly created room between the same two users can claim that pair key
/// without violating `rooms.dm_pair_key`'s `UNIQUE` constraint. The old room
/// keeps every other field; only its claim on the pair key is released.
pub fn clear_dm_pair_key(conn: &Connection, room_id: &str) -> rusqlite::Result<()> {
    conn.execute("UPDATE rooms SET dm_pair_key = NULL WHERE id = ?1", params![room_id])?;
    Ok(())
}

// ============================================================================
// Events (timeline + state)
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct MatrixEvent {
    pub stream_id: i64,
    pub event_id: String,
    pub room_id: String,
    pub sender_user_id: i64,
    pub event_type: String,
    /// `None` for a timeline event; `Some("")` or more for a state event.
    pub state_key: Option<String>,
    pub content: String,
    pub origin_server_ts: i64,
    pub txn_id: Option<String>,
    pub redacts: Option<String>,
    pub redacted_by: Option<String>,
}

const EVENT_SELECT_COLUMNS: &str =
    "stream_id, event_id, room_id, sender_user_id, event_type, state_key, content, origin_server_ts, txn_id, redacts, redacted_by";

const EVENT_SELECT_COLUMNS_ALIASED: &str = "e.stream_id, e.event_id, e.room_id, e.sender_user_id, e.event_type, e.state_key, e.content, e.origin_server_ts, e.txn_id, e.redacts, e.redacted_by";

fn event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MatrixEvent> {
    Ok(MatrixEvent {
        stream_id: row.get(0)?,
        event_id: row.get(1)?,
        room_id: row.get(2)?,
        sender_user_id: row.get(3)?,
        event_type: row.get(4)?,
        state_key: row.get(5)?,
        content: row.get(6)?,
        origin_server_ts: row.get(7)?,
        txn_id: row.get(8)?,
        redacts: row.get(9)?,
        redacted_by: row.get(10)?,
    })
}

fn collect_events(rows: &mut rusqlite::Rows<'_>) -> rusqlite::Result<Vec<MatrixEvent>> {
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(event_from_row(row)?);
    }
    Ok(out)
}

/// The columns of one timeline event row, grouped for
/// [`insert_timeline_event_in_tx`] (its callers all build one; the public
/// writers spell the same fields out as separate arguments).
#[derive(Debug, Clone, Copy)]
struct TimelineEventRow<'a> {
    event_id: &'a str,
    room_id: &'a str,
    sender_user_id: i64,
    event_type: &'a str,
    content: &'a str,
    origin_server_ts: i64,
    txn_id: Option<&'a str>,
}

/// The `&Transaction`-scoped core of [`insert_timeline_event`]. Room
/// creation (`createRoom`) never sends a message, so [`create_room_with_state`]
/// has no timeline events to insert and this function's only caller today is
/// [`insert_timeline_event`] itself — it is split out anyway, matching
/// [`apply_state_event_in_tx`]'s shape, so a future batch that DOES need to
/// mix timeline and state events (e.g. the P12 migration's legacy-message
/// replay) can call it directly instead of re-deriving a transaction-scoped
/// version of this logic.
fn insert_timeline_event_in_tx(tx: &Transaction, row: &TimelineEventRow<'_>) -> Result<MatrixEvent, MatrixStoreError> {
    let TimelineEventRow { event_id, room_id, sender_user_id, event_type, content, origin_server_ts, txn_id } = *row;
    let stream_id = next_stream_id(tx)?;
    tx.execute(
        "INSERT INTO events (stream_id, event_id, room_id, sender_user_id, event_type, state_key, content, origin_server_ts, txn_id)
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8)",
        params![stream_id, event_id, room_id, sender_user_id, event_type, content, origin_server_ts, txn_id],
    )?;
    populate_relations(tx, event_id, room_id, sender_user_id, content)?;
    Ok(MatrixEvent {
        stream_id,
        event_id: event_id.to_string(),
        room_id: room_id.to_string(),
        sender_user_id,
        event_type: event_type.to_string(),
        state_key: None,
        content: content.to_string(),
        origin_server_ts,
        txn_id: txn_id.map(str::to_string),
        redacts: None,
        redacted_by: None,
    })
}

/// Insert one timeline event (`state_key` always `NULL`) inside its own
/// transaction: mint the next stream id, insert the row, and — if
/// `content` carries a top-level `m.relates_to` (cleartext even for
/// `m.room.encrypted`, plan §10 item 3) — populate [`relations`]. Refusing
/// a duplicate `m.annotation` rolls back the whole transaction, so a
/// refused call leaves no partial `events` row. It never records a `txn_id`:
/// a write that carries one goes through [`insert_timeline_event_deduped`],
/// which stores it next to its dedup record in the same transaction.
pub fn insert_timeline_event(
    conn: &mut Connection,
    event_id: &str,
    room_id: &str,
    sender_user_id: i64,
    event_type: &str,
    content: &str,
    origin_server_ts: i64,
) -> Result<MatrixEvent, MatrixStoreError> {
    let tx = conn.transaction()?;
    let row = TimelineEventRow { event_id, room_id, sender_user_id, event_type, content, origin_server_ts, txn_id: None };
    let event = insert_timeline_event_in_tx(&tx, &row)?;
    tx.commit()?;
    Ok(event)
}

/// What [`insert_timeline_event_deduped`]/[`redact_event_deduped`] found: a
/// brand-new write, or the SAME event a prior submission of this
/// `(user, device, txn_id)` already produced (plan §4 `send`/`redact` rows:
/// "idempotent per (user, device, txn_id): a repeat returns the SAME
/// event_id with no second insert").
#[derive(Debug, Clone, PartialEq)]
pub enum DedupedWrite {
    New(MatrixEvent),
    Existing(MatrixEvent),
}

/// [`insert_timeline_event`], but dedup-checked and recorded in the SAME
/// transaction as the insert (P6 binding rule) — a repeat of
/// `(sender_user_id, device_id, txn_id)` returns the ORIGINAL event without a
/// second `events` row, and this is race-free even under a hypothetical
/// second writer (never actually possible under this module's single-writer
/// discipline) because the lookup, the insert, and the dedup record all
/// commit or roll back together. `txn_dedup_lookup`/`txn_dedup_record` take
/// `&Connection`; passing `&tx` (a `Transaction`) works via `Deref` — see
/// `apply_state_event_in_tx`'s own sibling functions for the same pattern.
#[allow(clippy::too_many_arguments)]
pub fn insert_timeline_event_deduped(
    conn: &mut Connection,
    device_id: &str,
    txn_id: &str,
    event_id: &str,
    room_id: &str,
    sender_user_id: i64,
    event_type: &str,
    content: &str,
    origin_server_ts: i64,
    now: &str,
) -> Result<DedupedWrite, MatrixStoreError> {
    let tx = conn.transaction()?;
    if let TxnDedupEntry::Seen(existing_event_id) = txn_dedup_lookup(&tx, sender_user_id, device_id, txn_id)? {
        let existing_event_id = existing_event_id.ok_or_else(|| MatrixStoreError::UnknownEventId(txn_id.to_string()))?;
        let event = get_event(&tx, &existing_event_id)?.ok_or_else(|| MatrixStoreError::UnknownEventId(existing_event_id.clone()))?;
        tx.commit()?;
        return Ok(DedupedWrite::Existing(event));
    }
    let row = TimelineEventRow { event_id, room_id, sender_user_id, event_type, content, origin_server_ts, txn_id: Some(txn_id) };
    let event = insert_timeline_event_in_tx(&tx, &row)?;
    txn_dedup_record(&tx, sender_user_id, device_id, txn_id, Some(event_id), now)?;
    tx.commit()?;
    Ok(DedupedWrite::New(event))
}

/// The shared core of [`apply_state_event`] and the P5 batch entry point
/// [`create_room_with_state`] — every bootstrap state event a room creation
/// inserts (`m.room.create`, both `m.room.member`s, `m.room.power_levels`,
/// ...) goes through this SAME function, once per event, all inside the
/// batch's one transaction, so a failure on any one of them rolls back the
/// entire room creation (plan P5 correction: "Room creation is ONE
/// transaction").
#[allow(clippy::too_many_arguments)]
fn apply_state_event_in_tx(
    tx: &Transaction,
    event_id: &str,
    room_id: &str,
    sender_user_id: i64,
    event_type: &str,
    state_key: &str,
    content: &str,
    origin_server_ts: i64,
    now: &str,
) -> Result<MatrixEvent, MatrixStoreError> {
    let stream_id = next_stream_id(tx)?;
    tx.execute(
        "INSERT INTO events (stream_id, event_id, room_id, sender_user_id, event_type, state_key, content, origin_server_ts, txn_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)",
        params![stream_id, event_id, room_id, sender_user_id, event_type, state_key, content, origin_server_ts],
    )?;
    tx.execute(
        "INSERT INTO current_state (room_id, event_type, state_key, event_id) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(room_id, event_type, state_key) DO UPDATE SET event_id = excluded.event_id",
        params![room_id, event_type, state_key, event_id],
    )?;
    if event_type == "m.room.member" {
        refresh_room_member(tx, room_id, state_key, content, now)?;
    }
    if event_type == "m.room.power_levels" {
        refresh_power_levels(tx, room_id, content)?;
    }
    Ok(MatrixEvent {
        stream_id,
        event_id: event_id.to_string(),
        room_id: room_id.to_string(),
        sender_user_id,
        event_type: event_type.to_string(),
        state_key: Some(state_key.to_string()),
        content: content.to_string(),
        origin_server_ts,
        txn_id: None,
        redacts: None,
        redacted_by: None,
    })
}

/// One state event for [`apply_state_event`]: its identity, the state slot
/// it fills, its content, and the two clocks (`origin_server_ts` in
/// milliseconds for the event row, `now` as RFC 3339 for the membership
/// cache's `updated_at`).
#[derive(Debug, Clone, Copy)]
pub struct StateEventWrite<'a> {
    pub event_id: &'a str,
    pub room_id: &'a str,
    pub sender_user_id: i64,
    pub event_type: &'a str,
    pub state_key: &'a str,
    pub content: &'a str,
    pub origin_server_ts: i64,
    pub now: &'a str,
}

/// Insert one state event and refresh the two projections that read off it:
/// `current_state` (always) and, for `m.room.member`/`m.room.power_levels`,
/// the denormalized `room_members` cache (plan §2). All inside one
/// transaction with the event row.
pub fn apply_state_event(conn: &mut Connection, write: &StateEventWrite<'_>) -> Result<MatrixEvent, MatrixStoreError> {
    let tx = conn.transaction()?;
    let event = apply_state_event_in_tx(
        &tx,
        write.event_id,
        write.room_id,
        write.sender_user_id,
        write.event_type,
        write.state_key,
        write.content,
        write.origin_server_ts,
        write.now,
    )?;
    tx.commit()?;
    Ok(event)
}

/// What one [`refresh_member_displayname`] pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DisplaynameRefresh {
    /// How many rooms got a new `m.room.member` event for the user.
    pub rooms_updated: usize,
    /// Every `user_id` that must be woken for those new events: each updated
    /// room's joined and invited members, the refreshed user included.
    pub affected_user_ids: HashSet<i64>,
}

/// Re-stamp `displayname` into `user_id`'s own `m.room.member` event in every
/// room where they are currently `join`ed or `invite`d, so the other
/// members' clients see the new name. A room whose current member event
/// already carries exactly `displayname` is skipped (the pass is idempotent,
/// which is what lets the boot backfill call it for every user on every
/// start). The new event keeps the current content (an invite keeps its
/// `is_direct` marker) and only replaces `displayname`; a `join` refresh is
/// sent by the user, an `invite` refresh keeps the inviter as its sender —
/// [`stripped_invite_state`] reads the inviter off that field. `leave`/`ban`
/// rows are never touched.
///
/// A user with no [`matrix_users`] row (never used the messenger) or an empty
/// `displayname` is a no-op. All rooms land in ONE transaction: a failure
/// leaves every room exactly as it was. The label itself comes from the
/// identity database, which this module never reads — the caller resolves it
/// BEFORE taking the messenger connection (lock order `db` -> `social` ->
/// `messenger`).
pub fn refresh_member_displayname(
    conn: &mut Connection,
    user_id: i64,
    displayname: &str,
    now: &str,
    origin_server_ts: i64,
) -> Result<DisplaynameRefresh, MatrixStoreError> {
    let mut outcome = DisplaynameRefresh::default();
    if displayname.is_empty() {
        return Ok(outcome);
    }
    let Some(mxid) = mxid_of(conn, user_id)? else {
        return Ok(outcome);
    };

    let tx = conn.transaction()?;
    for membership in [Membership::Join, Membership::Invite] {
        for room_id in rooms_for_user(&tx, user_id, Some(membership))? {
            let Some(current) = current_state_event(&tx, &room_id, "m.room.member", &mxid)? else {
                continue;
            };
            let mut content: serde_json::Value = serde_json::from_str(&current.content)?;
            if content.get("displayname").and_then(|v| v.as_str()) == Some(displayname) {
                continue;
            }
            let Some(fields) = content.as_object_mut() else {
                continue;
            };
            fields.insert("displayname".to_string(), serde_json::Value::String(displayname.to_string()));

            let sender_user_id = if membership == Membership::Join { user_id } else { current.sender_user_id };
            apply_state_event_in_tx(
                &tx,
                &new_event_id(),
                &room_id,
                sender_user_id,
                "m.room.member",
                &mxid,
                &content.to_string(),
                origin_server_ts,
                now,
            )?;
            outcome.rooms_updated += 1;
            outcome.affected_user_ids.insert(user_id);
            for member in room_members(&tx, &room_id, None)? {
                if matches!(member.membership, Membership::Join | Membership::Invite) {
                    outcome.affected_user_ids.insert(member.user_id);
                }
            }
        }
    }
    tx.commit()?;
    Ok(outcome)
}

/// Every `user_id` that has a [`matrix_users`] row — the boot backfill's
/// worklist of users whose member events may predate the `displayname`
/// stamping.
pub fn matrix_user_ids(conn: &Connection) -> rusqlite::Result<Vec<i64>> {
    let mut stmt = conn.prepare("SELECT user_id FROM matrix_users ORDER BY user_id")?;
    let rows = stmt.query_map([], |row| row.get(0))?;
    rows.collect()
}

// ============================================================================
// Room creation batch (plan P5 correction: room + every bootstrap state
// event, in ONE transaction)
// ============================================================================

/// One state event queued for [`create_room_with_state`] — the same shape
/// [`apply_state_event`] takes per-field, minus `room_id`/`origin_server_ts`/
/// `now` (shared by the whole batch, passed once to
/// [`create_room_with_state`] itself rather than repeated per event).
#[derive(Debug, Clone, PartialEq)]
pub struct NewStateEvent {
    pub event_id: String,
    pub sender_user_id: i64,
    pub event_type: String,
    pub state_key: String,
    pub content: String,
}

/// The room-metadata half of [`create_room_with_state`]'s input — every
/// field [`insert_room_row`] needs, grouped into one value instead of nine
/// positional arguments (this function's own params stay lint-clean without
/// an `#[allow(clippy::too_many_arguments)]`, unlike the legacy single-row
/// [`create_room`]/[`insert_room_row`] this batch shares its INSERT with).
#[derive(Debug, Clone, Copy)]
pub struct RoomBootstrap<'a> {
    pub room_id: &'a str,
    pub kind: RoomKind,
    pub creator_user_id: i64,
    pub created_at: &'a str,
    pub is_encrypted: bool,
    pub join_rule: JoinRule,
    pub history_visibility: HistoryVisibility,
    pub dm_pair_key: Option<&'a str>,
    pub legacy_dm_id: Option<i64>,
}

/// Create a room AND its full bootstrap event set in ONE transaction (plan
/// P5 correction) — the room row ([`insert_room_row`]), then every entry of
/// `state_events` in order via [`apply_state_event_in_tx`] (so, e.g., the
/// creator's own `m.room.member` MUST precede `m.room.power_levels` in
/// `state_events` for [`refresh_power_levels`] to see them as an existing
/// member to stamp — see that function's own doc comment), then commit. A
/// failure on the room insert OR on any one state event leaves NEITHER a
/// room row NOR any event row behind (rusqlite rolls back a `Transaction`
/// dropped without `commit()`, the same guarantee
/// [`populate_relations`]'s duplicate-annotation refusal already relies on).
pub fn create_room_with_state(
    conn: &mut Connection,
    bootstrap: RoomBootstrap<'_>,
    state_events: &[NewStateEvent],
    origin_server_ts: i64,
) -> Result<(Room, Vec<MatrixEvent>), MatrixStoreError> {
    let tx = conn.transaction()?;
    insert_room_row(
        &tx,
        bootstrap.room_id,
        bootstrap.kind,
        bootstrap.creator_user_id,
        bootstrap.created_at,
        bootstrap.is_encrypted,
        bootstrap.join_rule,
        bootstrap.history_visibility,
        bootstrap.dm_pair_key,
        bootstrap.legacy_dm_id,
    )?;

    let mut applied = Vec::with_capacity(state_events.len());
    for event in state_events {
        applied.push(apply_state_event_in_tx(
            &tx,
            &event.event_id,
            bootstrap.room_id,
            event.sender_user_id,
            &event.event_type,
            &event.state_key,
            &event.content,
            origin_server_ts,
            bootstrap.created_at,
        )?);
    }
    tx.commit()?;

    Ok((
        Room {
            id: bootstrap.room_id.to_string(),
            kind: bootstrap.kind,
            room_version: MATRIX_ROOM_VERSION.to_string(),
            creator_user_id: bootstrap.creator_user_id,
            created_at: bootstrap.created_at.to_string(),
            is_encrypted: bootstrap.is_encrypted,
            join_rule: bootstrap.join_rule,
            history_visibility: bootstrap.history_visibility,
            dm_pair_key: bootstrap.dm_pair_key.map(str::to_string),
            legacy_dm_id: bootstrap.legacy_dm_id,
        },
        applied,
    ))
}

/// Refresh `room_members` off an `m.room.member` state event. `state_key`
/// is the member's mxid (Matrix's own wire convention) — resolved to our
/// internal `user_id` via [`user_id_of`]; the member must already have been
/// through [`ensure_matrix_user`] or this refuses with
/// [`MatrixStoreError::UnknownMxid`]. `power_level` is left untouched on an
/// existing row (only [`refresh_power_levels`] ever sets it) and starts
/// `NULL` (falls back to `users_default`) on a brand-new one.
fn refresh_room_member(tx: &Transaction, room_id: &str, state_key: &str, content: &str, now: &str) -> Result<(), MatrixStoreError> {
    let value: serde_json::Value = serde_json::from_str(content)?;
    let membership_str = value
        .get("membership")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MatrixStoreError::InvalidMembership("missing 'membership' field".to_string()))?;
    let membership =
        Membership::from_wire_name(membership_str).ok_or_else(|| MatrixStoreError::InvalidMembership(membership_str.to_string()))?;
    let user_id = user_id_of(tx, state_key)?.ok_or_else(|| MatrixStoreError::UnknownMxid(state_key.to_string()))?;
    tx.execute(
        "INSERT INTO room_members (room_id, user_id, membership, power_level, updated_at)
         VALUES (?1, ?2, ?3, NULL, ?4)
         ON CONFLICT(room_id, user_id) DO UPDATE SET membership = excluded.membership, updated_at = excluded.updated_at",
        params![room_id, user_id, membership.as_str(), now],
    )?;
    Ok(())
}

/// Refresh `room_members.power_level` off an `m.room.power_levels` state
/// event's `users` map: every current member is reset to `NULL` (falls
/// back to `users_default`), then every `users` entry that resolves to a
/// known member is applied. An entry naming a user who is not (yet) a
/// member is silently skipped — their level will apply once they join,
/// resolved fresh from the room's current `m.room.power_levels` by whatever
/// reads it (a later piece; this table is a cache of the last-seen event,
/// not re-derived from an entry that never had a member row to land on).
fn refresh_power_levels(tx: &Transaction, room_id: &str, content: &str) -> Result<(), MatrixStoreError> {
    let value: serde_json::Value = serde_json::from_str(content)?;
    tx.execute("UPDATE room_members SET power_level = NULL WHERE room_id = ?1", params![room_id])?;
    if let Some(users) = value.get("users").and_then(|v| v.as_object()) {
        for (mxid, level) in users {
            let Some(level) = level.as_i64() else { continue };
            let Some(user_id) = user_id_of(tx, mxid)? else { continue };
            tx.execute(
                "UPDATE room_members SET power_level = ?1 WHERE room_id = ?2 AND user_id = ?3",
                params![level, room_id, user_id],
            )?;
        }
    }
    Ok(())
}

// ============================================================================
// Power levels (m.room.power_levels content) — plan §5, used by
// `routes::matrix::auth`'s PowerCheck gate. Pure `serde_json::Value` logic,
// no identity/messenger connection needed, hence living here (a lib-crate
// module with no bin-crate dependency) rather than in the binary crate's own
// `routes/matrix/auth.rs` alongside the rest of that module's caller/device
// resolution.
// ============================================================================

/// An action `m.room.power_levels` gates by a named threshold field, plus
/// `StateDefault` for "may send an otherwise-unlisted state event type".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerAction {
    Invite,
    Kick,
    Ban,
    Redact,
    StateDefault,
}

impl PowerAction {
    fn field_and_default(self) -> (&'static str, i64) {
        match self {
            PowerAction::Invite => ("invite", 50),
            PowerAction::Kick => ("kick", 50),
            PowerAction::Ban => ("ban", 50),
            PowerAction::Redact => ("redact", 50),
            PowerAction::StateDefault => ("state_default", 50),
        }
    }
}

/// `power_levels.users[mxid]`, falling back to `users_default` (Matrix
/// default `0`) when either field is missing.
pub fn user_level(power_levels: &serde_json::Value, mxid: &str) -> i64 {
    power_levels
        .get("users")
        .and_then(|users| users.get(mxid))
        .and_then(serde_json::Value::as_i64)
        .unwrap_or_else(|| power_levels.get("users_default").and_then(serde_json::Value::as_i64).unwrap_or(0))
}

/// The power level required to send an event of `event_type`:
/// `power_levels.events[event_type]` if present, else `state_default`
/// (Matrix default `50`) for a state event or `events_default` (Matrix
/// default `0`) for a timeline event.
pub fn event_level(power_levels: &serde_json::Value, event_type: &str, is_state: bool) -> i64 {
    if let Some(level) = power_levels.get("events").and_then(|events| events.get(event_type)).and_then(serde_json::Value::as_i64) {
        return level;
    }
    let (key, default) = if is_state { ("state_default", 50) } else { ("events_default", 0) };
    power_levels.get(key).and_then(serde_json::Value::as_i64).unwrap_or(default)
}

/// Whether `mxid`'s [`user_level`] reaches the threshold `action` names
/// (falling back to the Matrix default when the corresponding field is
/// missing — see [`PowerAction::field_and_default`]).
pub fn can(power_levels: &serde_json::Value, action: PowerAction, mxid: &str) -> bool {
    let (field, default) = action.field_and_default();
    let required = power_levels.get(field).and_then(serde_json::Value::as_i64).unwrap_or(default);
    user_level(power_levels, mxid) >= required
}

/// Matrix's room-v11 membership-change authorization rule for acting on
/// ANOTHER user (manager review, 2026-09-24 — a real gap in the first cut of
/// [`can`] alone): reaching the flat `action` threshold via [`can`] is
/// necessary but not sufficient — the sender's own level must ALSO be
/// STRICTLY GREATER than the target's current level, so a level-50 admin
/// can never kick/ban/unban a level-100 owner or an equal-level peer, even
/// though 50 reaches the flat kick/ban threshold. `self_leave` is the one
/// exception the spec carves out: a member may always change their OWN
/// membership to `leave` (declining an invite, or a self-kick, is just a
/// leave) regardless of level — pass `true` only when `new_membership` for
/// this call is `leave` and let the identity check below decide whether it
/// actually applies.
pub fn can_act_on(power_levels: &serde_json::Value, action: PowerAction, sender_mxid: &str, target_mxid: &str, self_leave: bool) -> bool {
    if self_leave && sender_mxid == target_mxid {
        return true;
    }
    can(power_levels, action, sender_mxid) && user_level(power_levels, sender_mxid) > user_level(power_levels, target_mxid)
}

/// The default an `m.room.power_levels` scalar field resolves to when
/// absent — `50` for every threshold field, `0` for the two `*_default`
/// fields (matches [`PowerAction::field_and_default`] for the fields that
/// enum names, plus the two it does not).
fn power_levels_scalar_default(key: &str) -> i64 {
    match key {
        "events_default" | "users_default" => 0,
        _ => 50,
    }
}

/// Every top-level scalar field of `m.room.power_levels` this server
/// enforces a change rule on (manager review, 2026-09-24). `events[type]`
/// entries and `notifications.room` are handled separately below (they are
/// nested, not top-level scalars).
const POWER_LEVELS_SCALAR_KEYS: [&str; 7] = ["ban", "kick", "redact", "invite", "state_default", "events_default", "users_default"];

/// Reject a scalar field change whose OLD or NEW value exceeds `sender_level`
/// — shared by every scalar/nested-scalar field [`validate_power_levels_change`]
/// checks (the top-level keys, each `events[type]` entry, and
/// `notifications.room` all follow the identical "both sides must be ≤ your
/// own level" rule; only `users` has the different, asymmetric rule).
fn reject_if_either_side_exceeds(old_value: Option<i64>, new_value: Option<i64>, sender_level: i64) -> Result<(), &'static str> {
    if old_value != new_value && (old_value.is_some_and(|v| v > sender_level) || new_value.is_some_and(|v| v > sender_level)) {
        return Err("cannot change a power-level field at or above your own level");
    }
    Ok(())
}

/// The `m.room.power_levels` v11 change-authorization rules beyond the flat
/// `PUT state` PowerCheck already gating who may send this event type at
/// all (manager review, 2026-09-24 — a real gap: without this, any admin
/// who merely reaches `state_default` could PUT themselves straight to
/// `100`). `sender_mxid`'s level is read from `old` (their authority BEFORE
/// this change takes effect):
///
/// - Every top-level scalar field ([`POWER_LEVELS_SCALAR_KEYS`]) that
///   CHANGES: both the old and the new (Matrix-default-resolved) value must
///   be at or below the sender's level.
/// - Every `events[type]` entry and `notifications.room` that CHANGES:
///   same rule, but with NO invented default for a side where the key is
///   simply absent (an absent side is not compared against the sender's
///   level at all — only a side that is actually PRESENT and exceeds it
///   is refused).
/// - `users`: for every mxid whose EFFECTIVE level ([`user_level`], which
///   already falls back to `users_default`) differs between `old` and
///   `new`: a target OTHER than the sender may never be touched if their
///   CURRENT (old) level is already at or above the sender's own level
///   (even to lower them) — a peer can never act on an equal-or-higher
///   peer; AND no entry's NEW level may exceed the sender's own level
///   (the sender may lower their own level, but never raise it, and can
///   never promote anyone above themselves).
pub fn validate_power_levels_change(old: &serde_json::Value, new: &serde_json::Value, sender_mxid: &str) -> Result<(), &'static str> {
    let sender_level = user_level(old, sender_mxid);

    for key in POWER_LEVELS_SCALAR_KEYS {
        let default = power_levels_scalar_default(key);
        let old_value = old.get(key).and_then(serde_json::Value::as_i64).unwrap_or(default);
        let new_value = new.get(key).and_then(serde_json::Value::as_i64).unwrap_or(default);
        reject_if_either_side_exceeds(Some(old_value), Some(new_value), sender_level)?;
    }

    let old_events = old.get("events").and_then(serde_json::Value::as_object);
    let new_events = new.get("events").and_then(serde_json::Value::as_object);
    let mut event_type_keys: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    if let Some(map) = old_events {
        event_type_keys.extend(map.keys().map(String::as_str));
    }
    if let Some(map) = new_events {
        event_type_keys.extend(map.keys().map(String::as_str));
    }
    for event_type in event_type_keys {
        let old_value = old_events.and_then(|m| m.get(event_type)).and_then(serde_json::Value::as_i64);
        let new_value = new_events.and_then(|m| m.get(event_type)).and_then(serde_json::Value::as_i64);
        reject_if_either_side_exceeds(old_value, new_value, sender_level)?;
    }

    let old_notif_room = old.get("notifications").and_then(|v| v.get("room")).and_then(serde_json::Value::as_i64);
    let new_notif_room = new.get("notifications").and_then(|v| v.get("room")).and_then(serde_json::Value::as_i64);
    reject_if_either_side_exceeds(old_notif_room, new_notif_room, sender_level)?;

    let old_users = old.get("users").and_then(serde_json::Value::as_object);
    let new_users = new.get("users").and_then(serde_json::Value::as_object);
    let mut user_keys: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    if let Some(map) = old_users {
        user_keys.extend(map.keys().map(String::as_str));
    }
    if let Some(map) = new_users {
        user_keys.extend(map.keys().map(String::as_str));
    }
    for target_mxid in user_keys {
        let old_effective = user_level(old, target_mxid);
        let new_effective = user_level(new, target_mxid);
        if old_effective == new_effective {
            continue;
        }
        if target_mxid != sender_mxid && old_effective >= sender_level {
            return Err("cannot change the level of a user at or above your own level");
        }
        if new_effective > sender_level {
            return Err("cannot set a user's level above your own");
        }
    }

    Ok(())
}

// ============================================================================
// Stripped invite-room-state (plan P5 correction: `unsigned.invite_room_state`
// on an invite's own `m.room.member` event, computed at read/serialize time —
// see this function's own doc for why, and `routes::matrix::client_event_json`
// (mod.rs) for its one call site today).
// ============================================================================

/// One `{content, state_key, type, sender}` Matrix `StrippedStateEvent` —
/// `sender` already resolved to an mxid, `content` already parsed JSON.
/// `pub` (beyond this module's own [`stripped_invite_state`]) for the
/// binary crate's `routes::matrix::sync` module: `GET /sync`'s
/// `invite_state.events` needs the SAME stripped shape for the invitee's
/// OWN `m.room.member` event, which [`stripped_invite_state`] does not
/// itself include (see that function's own doc — it strips the INVITER's
/// state, not the invitee's own invite event, since its other call site,
/// `routes::matrix::client_event_json`'s `unsigned.invite_room_state`, is
/// already attaching it TO that very event).
pub fn stripped_state_json(conn: &Connection, event: &MatrixEvent) -> Result<serde_json::Value, MatrixStoreError> {
    let sender = mxid_of(conn, event.sender_user_id)?.unwrap_or_default();
    let content: serde_json::Value = serde_json::from_str(&event.content)?;
    Ok(serde_json::json!({
        "content": content,
        "state_key": event.state_key.clone().unwrap_or_default(),
        "type": event.event_type,
        "sender": sender,
    }))
}

/// The stripped state Matrix attaches as `unsigned.invite_room_state` on an
/// invite's own `m.room.member` event (name/join_rules/encryption/create,
/// plus the inviter's own membership event) — recomputed fresh every time
/// it is served, NEVER stored on the member event itself: `unsigned` is not
/// part of the canonical, signed event, and this server's `events.content`
/// column holds only the canonical, signed shape. Computing it at read time
/// also means it always reflects the room's CURRENT state (e.g. a rename
/// after the invite was sent), which is what a client opening an invite it
/// received a while ago actually wants to see. `inviter_user_id` is the
/// member event's own `sender_user_id` — the caller already has it.
pub fn stripped_invite_state(conn: &Connection, room_id: &str, inviter_user_id: i64) -> Result<Vec<serde_json::Value>, MatrixStoreError> {
    let mut out = Vec::new();
    for event_type in ["m.room.create", "m.room.join_rules", "m.room.encryption", "m.room.name"] {
        if let Some(event) = current_state_event(conn, room_id, event_type, "")? {
            out.push(stripped_state_json(conn, &event)?);
        }
    }
    if let Some(inviter_mxid) = mxid_of(conn, inviter_user_id)? {
        if let Some(event) = current_state_event(conn, room_id, "m.room.member", &inviter_mxid)? {
            out.push(stripped_state_json(conn, &event)?);
        }
    }
    Ok(out)
}

pub fn get_event(conn: &Connection, event_id: &str) -> rusqlite::Result<Option<MatrixEvent>> {
    conn.query_row(&format!("SELECT {EVENT_SELECT_COLUMNS} FROM events WHERE event_id = ?1"), params![event_id], event_from_row)
        .optional()
}

pub fn current_state_event(conn: &Connection, room_id: &str, event_type: &str, state_key: &str) -> rusqlite::Result<Option<MatrixEvent>> {
    conn.query_row(
        &format!(
            "SELECT {EVENT_SELECT_COLUMNS_ALIASED} FROM current_state cs JOIN events e ON e.event_id = cs.event_id
             WHERE cs.room_id = ?1 AND cs.event_type = ?2 AND cs.state_key = ?3"
        ),
        params![room_id, event_type, state_key],
        event_from_row,
    )
    .optional()
}

pub fn current_state_all(conn: &Connection, room_id: &str) -> rusqlite::Result<Vec<MatrixEvent>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {EVENT_SELECT_COLUMNS_ALIASED} FROM current_state cs JOIN events e ON e.event_id = cs.event_id WHERE cs.room_id = ?1"
    ))?;
    let mut rows = stmt.query(params![room_id])?;
    collect_events(&mut rows)
}

/// The point-in-time projection of every `event_type` state event as of
/// `at_stream_id` — the latest such event per `state_key` with
/// `stream_id <= at_stream_id` — for `GET /rooms/{roomId}/members?at=`
/// (plan §3.3: a client fetching the full member list as of a given `/sync`
/// token, rather than the live [`current_state_all`] projection). A
/// `state_key` whose first event lands AFTER `at_stream_id` is correctly
/// absent (it did not exist yet at that point in the room's history).
pub fn state_events_of_type_at(conn: &Connection, room_id: &str, event_type: &str, at_stream_id: i64) -> rusqlite::Result<Vec<MatrixEvent>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {EVENT_SELECT_COLUMNS_ALIASED} FROM events e
         WHERE e.room_id = ?1 AND e.event_type = ?2 AND e.state_key IS NOT NULL AND e.stream_id <= ?3
           AND e.stream_id = (
             SELECT MAX(stream_id) FROM events e2
             WHERE e2.room_id = e.room_id AND e2.event_type = e.event_type AND e2.state_key = e.state_key AND e2.stream_id <= ?3
           )"
    ))?;
    let mut rows = stmt.query(params![room_id, event_type, at_stream_id])?;
    collect_events(&mut rows)
}

/// Every `m.room.member` state event whose CURRENT value as of
/// `upto_inclusive` was itself set within `(since_exclusive,
/// upto_inclusive]` — `routes::matrix::sync`'s §3.3 clause-(b) lazy-load
/// "gap rule" (matrix-spec#942): a member who joined/left/changed profile
/// inside a truncated timeline gap must still be reported even when they
/// never sent anything into the visible window. Bounded to
/// `upto_inclusive` throughout (never the LIVE `current_state` projection,
/// which could have moved past a `/sync` build's own snapshot) so this
/// stays part of one consistent cut.
pub fn member_state_changed_in_window(conn: &Connection, room_id: &str, since_exclusive: i64, upto_inclusive: i64) -> rusqlite::Result<Vec<MatrixEvent>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {EVENT_SELECT_COLUMNS_ALIASED} FROM events e
         WHERE e.room_id = ?1 AND e.event_type = 'm.room.member' AND e.state_key IS NOT NULL
           AND e.stream_id = (
             SELECT MAX(e2.stream_id) FROM events e2
             WHERE e2.room_id = e.room_id AND e2.event_type = 'm.room.member' AND e2.state_key = e.state_key AND e2.stream_id <= ?3
           )
           AND e.stream_id > ?2"
    ))?;
    let mut rows = stmt.query(params![room_id, since_exclusive, upto_inclusive])?;
    collect_events(&mut rows)
}

/// Every state event type OTHER than `m.room.member` whose CURRENT value as
/// of `upto_inclusive` was itself set within `(since_exclusive,
/// upto_inclusive]` — `routes::matrix::sync`'s per-room state delta for
/// every state type this server does not lazy-load ("every OTHER
/// state-event type changed since `since` ... always included in full").
/// `since_exclusive = 0` naturally reproduces every current state event of
/// these types (the initial-sync/`full_state` case), since every such
/// event's own `stream_id` is `> 0` — one code path serves both.
pub fn non_member_state_changed_in_window(conn: &Connection, room_id: &str, since_exclusive: i64, upto_inclusive: i64) -> rusqlite::Result<Vec<MatrixEvent>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {EVENT_SELECT_COLUMNS_ALIASED} FROM events e
         WHERE e.room_id = ?1 AND e.event_type != 'm.room.member' AND e.state_key IS NOT NULL
           AND e.stream_id = (
             SELECT MAX(e2.stream_id) FROM events e2
             WHERE e2.room_id = e.room_id AND e2.event_type = e.event_type AND e2.state_key = e.state_key AND e2.stream_id <= ?3
           )
           AND e.stream_id > ?2"
    ))?;
    let mut rows = stmt.query(params![room_id, since_exclusive, upto_inclusive])?;
    collect_events(&mut rows)
}

/// The oldest-first timeline window strictly after `since_stream`, capped
/// at `limit` — the incremental-`/sync` and forward-`/messages` shape.
pub fn events_in_room_after(conn: &Connection, room_id: &str, since_stream: i64, limit: i64) -> rusqlite::Result<Vec<MatrixEvent>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {EVENT_SELECT_COLUMNS} FROM events WHERE room_id = ?1 AND stream_id > ?2 ORDER BY stream_id ASC LIMIT ?3"
    ))?;
    let mut rows = stmt.query(params![room_id, since_stream, limit])?;
    collect_events(&mut rows)
}

/// The newest-first page strictly before `before_stream`, capped at
/// `limit` — `GET /messages?dir=b` and the initial-`/sync` "newest N"
/// window (§3.2: the caller reverses it if an ascending page is needed).
pub fn events_in_room_before(conn: &Connection, room_id: &str, before_stream: i64, limit: i64) -> rusqlite::Result<Vec<MatrixEvent>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {EVENT_SELECT_COLUMNS} FROM events WHERE room_id = ?1 AND stream_id < ?2 ORDER BY stream_id DESC LIMIT ?3"
    ))?;
    let mut rows = stmt.query(params![room_id, before_stream, limit])?;
    collect_events(&mut rows)
}

// ============================================================================
// Relations (m.annotation / m.replace / m.in_reply_to / m.thread)
// ============================================================================

/// Populate `relations` from `content`'s top-level `m.relates_to`, if any —
/// a no-op if `content` is not JSON, has no `m.relates_to`, or the relation
/// shape is unrecognized. Two shapes are handled: the common
/// `{"rel_type":..., "event_id":..., "key": "..."}` (annotation/replace/
/// thread) and the nested `{"m.in_reply_to": {"event_id": "..."}}` reply
/// form.
///
/// The target must exist and be in the SAME room as `room_id` — refused
/// with [`MatrixStoreError::InvalidRelationTarget`] otherwise (a relation
/// can never point out of its own room, and a target that does not exist
/// would otherwise only surface as an opaque foreign-key `Db` error from
/// the `INSERT` below).
///
/// A second identical `m.annotation` (same sender, target, key) is refused
/// with [`MatrixStoreError::DuplicateAnnotation`] — checked BEFORE insert,
/// so the caller's whole transaction rolls back and no partial `events` row
/// survives the refusal. A REDACTED prior annotation does not count: once a
/// reaction is redacted, its sender is free to react with the same key
/// again (`e.redacted_by IS NULL` in the duplicate check).
fn populate_relations(tx: &Transaction, event_id: &str, room_id: &str, sender_user_id: i64, content: &str) -> Result<(), MatrixStoreError> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(content) else {
        return Ok(());
    };
    let Some(relates_to) = value.get("m.relates_to") else {
        return Ok(());
    };

    let (rel_type, target_id, agg_key): (String, String, Option<String>) = if let Some(reply) = relates_to.get("m.in_reply_to") {
        match reply.get("event_id").and_then(|v| v.as_str()) {
            Some(target) => ("m.in_reply_to".to_string(), target.to_string(), None),
            None => return Ok(()),
        }
    } else {
        let rel_type = relates_to.get("rel_type").and_then(|v| v.as_str());
        let target = relates_to.get("event_id").and_then(|v| v.as_str());
        match (rel_type, target) {
            (Some(rt), Some(target)) => {
                let key = relates_to.get("key").and_then(|v| v.as_str()).map(str::to_string);
                (rt.to_string(), target.to_string(), key)
            }
            _ => return Ok(()),
        }
    };

    let target_room: Option<String> = tx
        .query_row("SELECT room_id FROM events WHERE event_id = ?1", params![target_id], |row| row.get(0))
        .optional()?;
    match target_room {
        Some(ref found_room) if found_room == room_id => {}
        _ => return Err(MatrixStoreError::InvalidRelationTarget(target_id)),
    }

    if rel_type == "m.annotation" {
        let duplicate: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM relations r JOIN events e ON e.event_id = r.event_id
                 WHERE r.target_id = ?1 AND r.rel_type = 'm.annotation' AND r.agg_key IS ?2 AND e.sender_user_id = ?3
                    AND e.redacted_by IS NULL
                 LIMIT 1",
                params![target_id, agg_key, sender_user_id],
                |row| row.get(0),
            )
            .optional()?;
        if duplicate.is_some() {
            return Err(MatrixStoreError::DuplicateAnnotation);
        }
    }

    tx.execute(
        "INSERT INTO relations (event_id, room_id, rel_type, target_id, agg_key) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![event_id, room_id, rel_type, target_id, agg_key],
    )?;
    Ok(())
}

/// Every event related to `target_event_id`, newest-first (Matrix's own
/// default order for `GET /relations`), optionally narrowed to one
/// `rel_type` and/or one `event_type`, strictly before `before_stream`
/// (pass [`i64::MAX`] for a first page), capped at `limit` — P6's
/// `routes::matrix::messaging::get_relations`.
pub fn relations_of(
    conn: &Connection,
    target_event_id: &str,
    rel_type: Option<&str>,
    event_type: Option<&str>,
    before_stream: i64,
    limit: i64,
) -> rusqlite::Result<Vec<MatrixEvent>> {
    // Anonymous `?` placeholders (not `?N`) — purely positional, so building
    // the SQL text and the bound-value list in the SAME order below can
    // never desync the way explicit numbered placeholders would if a
    // variant's text skipped a number.
    let mut sql = format!("SELECT {EVENT_SELECT_COLUMNS_ALIASED} FROM relations r JOIN events e ON e.event_id = r.event_id WHERE r.target_id = ? AND e.stream_id < ?");
    let mut values: Vec<&dyn rusqlite::ToSql> = vec![&target_event_id, &before_stream];
    if let Some(rt) = &rel_type {
        sql.push_str(" AND r.rel_type = ?");
        values.push(rt);
    }
    if let Some(et) = &event_type {
        sql.push_str(" AND e.event_type = ?");
        values.push(et);
    }
    sql.push_str(" ORDER BY e.stream_id DESC LIMIT ?");
    values.push(&limit);

    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(values.as_slice())?;
    collect_events(&mut rows)
}

// ============================================================================
// Redaction (room v11 content allow-list)
// ============================================================================

/// Strip `content` to the room-version-11 redaction allow-list for
/// `event_type` (Matrix Client-Server API, room version 11 redaction
/// algorithm — `spec.matrix.org/v1.12/rooms/v11/#redactions`, cited by plan
/// §1/§2): `m.room.create` keeps everything; `m.room.member` keeps
/// `membership`, `join_authorised_via_users_server`, and
/// `third_party_invite.signed` (nested — only `signed` survives inside
/// `third_party_invite`); `m.room.join_rules` keeps `join_rule`, `allow`;
/// `m.room.power_levels` keeps `ban`, `events`, `events_default`,
/// `invite`, `kick`, `redact`, `state_default`, `users`, `users_default`;
/// `m.room.history_visibility` keeps `history_visibility`; every other
/// type is stripped to `{}`.
fn redact_content_per_v11(event_type: &str, content: &str) -> Result<String, MatrixStoreError> {
    let value: serde_json::Value = serde_json::from_str(content)?;
    let obj = value.as_object().cloned().unwrap_or_default();
    let mut kept = serde_json::Map::new();

    match event_type {
        "m.room.create" => kept = obj,
        "m.room.member" => {
            for key in ["membership", "join_authorised_via_users_server"] {
                if let Some(v) = obj.get(key) {
                    kept.insert(key.to_string(), v.clone());
                }
            }
            if let Some(signed) = obj.get("third_party_invite").and_then(|v| v.get("signed")) {
                let mut third_party_invite = serde_json::Map::new();
                third_party_invite.insert("signed".to_string(), signed.clone());
                kept.insert("third_party_invite".to_string(), serde_json::Value::Object(third_party_invite));
            }
        }
        "m.room.join_rules" => {
            for key in ["join_rule", "allow"] {
                if let Some(v) = obj.get(key) {
                    kept.insert(key.to_string(), v.clone());
                }
            }
        }
        "m.room.power_levels" => {
            for key in [
                "ban",
                "events",
                "events_default",
                "invite",
                "kick",
                "redact",
                "state_default",
                "users",
                "users_default",
            ] {
                if let Some(v) = obj.get(key) {
                    kept.insert(key.to_string(), v.clone());
                }
            }
        }
        "m.room.history_visibility" => {
            if let Some(v) = obj.get("history_visibility") {
                kept.insert("history_visibility".to_string(), v.clone());
            }
        }
        _ => {}
    }

    Ok(serde_json::Value::Object(kept).to_string())
}

/// Redact `target_event_id`: store the `m.room.redaction` event itself
/// (`redacts = target_event_id`, and `content.redacts = target_event_id`,
/// the room-version-11 location clients read), set the target's
/// `redacted_by`, and strip the target's `content` per
/// [`redact_content_per_v11`]. All inside one transaction.
///
/// Refuses with:
/// - [`MatrixStoreError::UnknownEventId`] if `target_event_id` does not
///   exist;
/// - [`MatrixStoreError::WrongRoom`] if it exists but is in a different
///   room than `room_id`;
/// - [`MatrixStoreError::UnredactableEvent`] for `m.room.create` or
///   `m.room.encryption` — `m.room.create` is the room's own identity
///   anchor (its v11 allow-list already keeps every key, so "redacting" it
///   would be a no-op at best), and `m.room.encryption`'s v11 allow-list
///   has NO keys at all, meaning a redacted encryption event strips to
///   `{}` — indistinguishable from an unencrypted room to anything reading
///   current state. This server's rule is that encryption never turns off
///   once set (`rooms.is_encrypted`'s own doc comment says the same), so
///   the event that turned it on must never become redactable.
fn redact_event_in_tx(
    tx: &Transaction,
    room_id: &str,
    target_event_id: &str,
    redaction_event_id: &str,
    sender_user_id: i64,
    reason: Option<&str>,
    origin_server_ts: i64,
) -> Result<MatrixEvent, MatrixStoreError> {
    let target: Option<(String, String, String)> = tx
        .query_row(
            "SELECT event_type, content, room_id FROM events WHERE event_id = ?1",
            params![target_event_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let (target_type, target_content, target_room) = target.ok_or_else(|| MatrixStoreError::UnknownEventId(target_event_id.to_string()))?;
    if target_room != room_id {
        return Err(MatrixStoreError::WrongRoom(target_event_id.to_string()));
    }
    if target_type == "m.room.create" || target_type == "m.room.encryption" {
        return Err(MatrixStoreError::UnredactableEvent(target_type));
    }

    let stream_id = next_stream_id(tx)?;
    // Room version 11 carries the redaction's target in `content.redacts`
    // (the `redacts` column keeps serving the older top-level shape).
    let mut redaction_content = serde_json::json!({ "redacts": target_event_id });
    if let Some(r) = reason {
        redaction_content["reason"] = serde_json::Value::String(r.to_string());
    }
    let redaction_content = redaction_content.to_string();
    tx.execute(
        "INSERT INTO events (stream_id, event_id, room_id, sender_user_id, event_type, state_key, content, origin_server_ts, txn_id, redacts)
         VALUES (?1, ?2, ?3, ?4, 'm.room.redaction', NULL, ?5, ?6, NULL, ?7)",
        params![stream_id, redaction_event_id, room_id, sender_user_id, redaction_content, origin_server_ts, target_event_id],
    )?;

    let stripped_content = redact_content_per_v11(&target_type, &target_content)?;
    tx.execute(
        "UPDATE events SET content = ?1, redacted_by = ?2 WHERE event_id = ?3",
        params![stripped_content, redaction_event_id, target_event_id],
    )?;

    Ok(MatrixEvent {
        stream_id,
        event_id: redaction_event_id.to_string(),
        room_id: room_id.to_string(),
        sender_user_id,
        event_type: "m.room.redaction".to_string(),
        state_key: None,
        content: redaction_content,
        origin_server_ts,
        txn_id: None,
        redacts: Some(target_event_id.to_string()),
        redacted_by: None,
    })
}

pub fn redact_event(
    conn: &mut Connection,
    room_id: &str,
    target_event_id: &str,
    redaction_event_id: &str,
    sender_user_id: i64,
    reason: Option<&str>,
    origin_server_ts: i64,
) -> Result<MatrixEvent, MatrixStoreError> {
    let tx = conn.transaction()?;
    let event = redact_event_in_tx(&tx, room_id, target_event_id, redaction_event_id, sender_user_id, reason, origin_server_ts)?;
    tx.commit()?;
    Ok(event)
}

/// The redaction [`redact_event_marked`] writes: which event, in which room,
/// by whom, under which new event id.
#[derive(Debug, Clone, Copy)]
pub struct Redaction<'a> {
    pub room_id: &'a str,
    pub target_event_id: &'a str,
    pub redaction_event_id: &'a str,
    pub sender_user_id: i64,
    pub reason: Option<&'a str>,
    pub origin_server_ts: i64,
}

/// [`redact_event`], but merges `extra_content` into the resulting
/// `m.room.redaction` event's own content, in the SAME transaction as the
/// redaction itself — `routes::matrix::moderation`'s (P11) ONLY caller,
/// which stamps `{"org.mylittlechart.site_moderation": true}` on a
/// site-moderator's redaction of a public-room message (plan §4's
/// `/api/matrix-admin/rooms/{roomId}/moderate` row) so every client can
/// render it distinctly from an ordinary member-initiated redaction. Every
/// other redaction path ([`redact_event`], [`redact_event_deduped`]) never
/// needs this and stays untouched.
pub fn redact_event_marked(
    conn: &mut Connection,
    redaction: &Redaction<'_>,
    extra_content: &serde_json::Value,
) -> Result<MatrixEvent, MatrixStoreError> {
    let Redaction { room_id, target_event_id, redaction_event_id, sender_user_id, reason, origin_server_ts } = *redaction;
    let tx = conn.transaction()?;
    let mut event = redact_event_in_tx(&tx, room_id, target_event_id, redaction_event_id, sender_user_id, reason, origin_server_ts)?;
    let mut content: serde_json::Value = serde_json::from_str(&event.content)?;
    if let (Some(content_obj), Some(extra_obj)) = (content.as_object_mut(), extra_content.as_object()) {
        for (key, value) in extra_obj {
            content_obj.insert(key.clone(), value.clone());
        }
    }
    let content_str = content.to_string();
    tx.execute("UPDATE events SET content = ?1 WHERE event_id = ?2", params![content_str, redaction_event_id])?;
    event.content = content_str;
    tx.commit()?;
    Ok(event)
}

/// [`redact_event`], but dedup-checked and recorded in the SAME transaction
/// as the redaction (P6 binding rule, mirroring
/// [`insert_timeline_event_deduped`] — see its own doc for the race-freedom
/// argument).
#[allow(clippy::too_many_arguments)]
pub fn redact_event_deduped(
    conn: &mut Connection,
    device_id: &str,
    txn_id: &str,
    room_id: &str,
    target_event_id: &str,
    redaction_event_id: &str,
    sender_user_id: i64,
    reason: Option<&str>,
    origin_server_ts: i64,
    now: &str,
) -> Result<DedupedWrite, MatrixStoreError> {
    let tx = conn.transaction()?;
    if let TxnDedupEntry::Seen(existing_event_id) = txn_dedup_lookup(&tx, sender_user_id, device_id, txn_id)? {
        let existing_event_id = existing_event_id.ok_or_else(|| MatrixStoreError::UnknownEventId(txn_id.to_string()))?;
        let event = get_event(&tx, &existing_event_id)?.ok_or_else(|| MatrixStoreError::UnknownEventId(existing_event_id.clone()))?;
        tx.commit()?;
        return Ok(DedupedWrite::Existing(event));
    }
    let event = redact_event_in_tx(&tx, room_id, target_event_id, redaction_event_id, sender_user_id, reason, origin_server_ts)?;
    txn_dedup_record(&tx, sender_user_id, device_id, txn_id, Some(redaction_event_id), now)?;
    tx.commit()?;
    Ok(DedupedWrite::New(event))
}

// ============================================================================
// Membership projection
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct RoomMember {
    pub room_id: String,
    pub user_id: i64,
    pub membership: Membership,
    pub power_level: Option<i64>,
    pub updated_at: String,
}

fn room_member_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RoomMember> {
    let membership_raw: String = row.get(2)?;
    Ok(RoomMember {
        room_id: row.get(0)?,
        user_id: row.get(1)?,
        membership: decode_enum(2, "membership", &membership_raw, Membership::from_wire_name)?,
        power_level: row.get(3)?,
        updated_at: row.get(4)?,
    })
}

const ROOM_MEMBER_SELECT_COLUMNS: &str = "room_id, user_id, membership, power_level, updated_at";

/// Every member row of `room_id`, optionally filtered to one `membership`.
pub fn room_members(conn: &Connection, room_id: &str, membership: Option<Membership>) -> rusqlite::Result<Vec<RoomMember>> {
    match membership {
        Some(m) => {
            let mut stmt = conn.prepare(&format!(
                "SELECT {ROOM_MEMBER_SELECT_COLUMNS} FROM room_members WHERE room_id = ?1 AND membership = ?2"
            ))?;
            let rows = stmt.query_map(params![room_id, m.as_str()], room_member_from_row)?;
            rows.collect()
        }
        None => {
            let mut stmt = conn.prepare(&format!("SELECT {ROOM_MEMBER_SELECT_COLUMNS} FROM room_members WHERE room_id = ?1"))?;
            let rows = stmt.query_map(params![room_id], room_member_from_row)?;
            rows.collect()
        }
    }
}

/// `(room_id, user_id)`'s single `room_members` row, if any — the targeted
/// counterpart of [`room_members`] for a "is this one user a member, and
/// what membership/power level do they hold" check (every gate in
/// `routes::matrix::rooms` needs exactly this, not a full-room scan).
pub fn room_member(conn: &Connection, room_id: &str, user_id: i64) -> rusqlite::Result<Option<RoomMember>> {
    conn.query_row(
        &format!("SELECT {ROOM_MEMBER_SELECT_COLUMNS} FROM room_members WHERE room_id = ?1 AND user_id = ?2"),
        params![room_id, user_id],
        room_member_from_row,
    )
    .optional()
}

/// Delete `user_id`'s `room_members` row in `room_id`, but ONLY if its
/// current membership is `leave` — `POST /rooms/{roomId}/forget`'s own gate
/// AND its effect are the same one-row conditional delete, so there is no
/// separate read-then-write race to worry about. Returns the number of rows
/// deleted (`0` if the row was absent or not currently `leave`), so the
/// route layer can tell a genuine forget from a no-op gate refusal.
pub fn forget_membership(conn: &Connection, room_id: &str, user_id: i64) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM room_members WHERE room_id = ?1 AND user_id = ?2 AND membership = 'leave'",
        params![room_id, user_id],
    )
}

/// Up to `limit` other members (`join`/`invite`) of `room_id`, oldest
/// membership-change first, excluding `exclude_user_id` — `/sync`'s
/// `m.heroes` (plan §3.4).
pub fn room_heroes(conn: &Connection, room_id: &str, exclude_user_id: i64, limit: i64) -> rusqlite::Result<Vec<i64>> {
    let mut stmt = conn.prepare(
        "SELECT user_id FROM room_members
         WHERE room_id = ?1 AND user_id != ?2 AND membership IN ('join', 'invite')
         ORDER BY updated_at ASC LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![room_id, exclude_user_id, limit], |row| row.get(0))?;
    rows.collect()
}

/// Every room id `user_id` has a `room_members` row in, optionally filtered
/// to one `membership` — the "which rooms is this user in" query behind
/// `/sync`'s room list and `on_credential_revoked`'s wake fan-out.
pub fn rooms_for_user(conn: &Connection, user_id: i64, membership: Option<Membership>) -> rusqlite::Result<Vec<String>> {
    match membership {
        Some(m) => {
            let mut stmt = conn.prepare("SELECT room_id FROM room_members WHERE user_id = ?1 AND membership = ?2")?;
            let rows = stmt.query_map(params![user_id, m.as_str()], |row| row.get(0))?;
            rows.collect()
        }
        None => {
            let mut stmt = conn.prepare("SELECT room_id FROM room_members WHERE user_id = ?1")?;
            let rows = stmt.query_map(params![user_id], |row| row.get(0))?;
            rows.collect()
        }
    }
}

/// Every room in `room_ids` (typically the caller's currently joined rooms)
/// with at least one `events`, `receipts`, or room-scoped `account_data` row
/// whose `stream_id` falls in `(since_exclusive, upto_inclusive]` —
/// `routes::matrix::sync`'s changed-room prefilter: an incremental sync must
/// not run a room block builder's own dozen-odd queries against EVERY
/// joined room just to discover that most did not change (with a few
/// hundred rooms that is thousands of queries per wake, all held under the
/// single `messenger.db` mutex). This set is EXACT, not merely a safe
/// over-approximation: every field a room's `/sync` block can ever report
/// (`timeline`, `state`, per-room `account_data`, and `m.receipt`) derives
/// from exactly these three tables — the one exception, typing, is an
/// in-memory `live::TypingRegistry` fact this function has no visibility
/// into and the caller checks separately. Returns an empty set without
/// querying when `room_ids` is empty.
pub fn rooms_changed_in_window(
    conn: &Connection,
    room_ids: &[String],
    caller_user_id: i64,
    since_exclusive: i64,
    upto_inclusive: i64,
) -> rusqlite::Result<HashSet<String>> {
    let mut changed = HashSet::new();
    if room_ids.is_empty() {
        return Ok(changed);
    }
    let placeholders = vec!["?"; room_ids.len()].join(",");

    // `events` and `receipts` are not scoped to `caller_user_id` at all
    // (any member's write counts), so both need the `room_id IN (...)`
    // restriction to the caller's own joined-room set.
    for table in ["events", "receipts"] {
        let sql = format!("SELECT DISTINCT room_id FROM {table} WHERE stream_id > ? AND stream_id <= ? AND room_id IN ({placeholders})");
        let mut stmt = conn.prepare(&sql)?;
        let mut bound: Vec<&dyn rusqlite::ToSql> = vec![&since_exclusive, &upto_inclusive];
        for room_id in room_ids {
            bound.push(room_id as &dyn rusqlite::ToSql);
        }
        let mut rows = stmt.query(bound.as_slice())?;
        while let Some(row) = rows.next()? {
            changed.insert(row.get::<_, String>(0)?);
        }
    }

    // `account_data` rows are already scoped to ONE user — narrowing by
    // `user_id` first (its own indexed column, `idx_account_data_user_stream`)
    // is cheaper than another `room_id IN (...)` list, then intersect with
    // `room_ids` in Rust (global account data, `room_id = ''`, never
    // matches a real room id and is naturally excluded by that intersection).
    let room_id_set: HashSet<&str> = room_ids.iter().map(String::as_str).collect();
    let mut stmt = conn.prepare("SELECT DISTINCT room_id FROM account_data WHERE user_id = ?1 AND stream_id > ?2 AND stream_id <= ?3")?;
    let mut rows = stmt.query(params![caller_user_id, since_exclusive, upto_inclusive])?;
    while let Some(row) = rows.next()? {
        let room_id: String = row.get(0)?;
        if room_id_set.contains(room_id.as_str()) {
            changed.insert(room_id);
        }
    }

    Ok(changed)
}

/// `mxid`'s membership in `room_id` as of `at_stream_id`: the latest
/// `m.room.member` event for that state key with `stream_id <= at_stream_id`,
/// or `None` when there was none yet (or its content carries no known
/// membership). The point-in-time counterpart of [`room_member`] — the
/// device-list delta needs "what was this user's membership BEFORE the sync
/// window opened" to tell a newly shared room from a profile update.
pub fn membership_at(conn: &Connection, room_id: &str, mxid: &str, at_stream_id: i64) -> rusqlite::Result<Option<Membership>> {
    let content: Option<String> = conn
        .query_row(
            "SELECT content FROM events
             WHERE room_id = ?1 AND event_type = 'm.room.member' AND state_key = ?2 AND stream_id <= ?3
             ORDER BY stream_id DESC LIMIT 1",
            params![room_id, mxid, at_stream_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(content
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|value| value.get("membership").and_then(|m| m.as_str()).and_then(Membership::from_wire_name)))
}

/// Every room in `room_ids` that has at least one `m.room.member` event with
/// `stream_id` in `(from_exclusive, to_inclusive]` — ONE indexed query for
/// the whole room set, so the device-list delta only does per-room work for
/// rooms where a membership could have changed (an incremental `/sync` runs
/// it on every wake; see [`rooms_changed_in_window`] for the same rule).
/// Returns an empty vec without querying when `room_ids` is empty.
pub fn rooms_with_member_events_in_window(conn: &Connection, room_ids: &[String], from_exclusive: i64, to_inclusive: i64) -> rusqlite::Result<Vec<String>> {
    if room_ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = vec!["?"; room_ids.len()].join(",");
    let sql = format!(
        "SELECT DISTINCT room_id FROM events
         WHERE event_type = 'm.room.member' AND stream_id > ? AND stream_id <= ? AND room_id IN ({placeholders})"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut bound: Vec<&dyn rusqlite::ToSql> = vec![&from_exclusive, &to_inclusive];
    for room_id in room_ids {
        bound.push(room_id as &dyn rusqlite::ToSql);
    }
    let rows = stmt.query_map(bound.as_slice(), |row| row.get(0))?;
    rows.collect()
}

/// Every mxid (state key) that has an `m.room.member` event in `room_id`
/// with `stream_id` in `(from_exclusive, to_inclusive]` — the candidates
/// whose membership MAY have changed inside the window; the caller compares
/// [`room_member`] against [`membership_at`] to find the real transitions.
pub fn member_state_keys_in_window(conn: &Connection, room_id: &str, from_exclusive: i64, to_inclusive: i64) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT state_key FROM events
         WHERE room_id = ?1 AND event_type = 'm.room.member' AND state_key IS NOT NULL AND stream_id > ?2 AND stream_id <= ?3",
    )?;
    let rows = stmt.query_map(params![room_id, from_exclusive, to_inclusive], |row| row.get(0))?;
    rows.collect()
}

/// Every `user_id` whose `m.room.member` state transitioned to `leave` or
/// `ban` in one of `room_ids`, with `stream_id` in `(from_exclusive,
/// to_inclusive]` — `routes::matrix::keys`'s `GET /keys/changes`
/// `device_lists.left` set (plan §3.7): a user who no longer shares any room
/// with the caller. This function only finds the CANDIDATE departures inside
/// the given room set; the caller (which already knows its own current
/// shared-room membership) is responsible for the second half of the plan's
/// rule — excluding anyone who still shares SOME OTHER room with it today.
/// Bounded to `room_ids` (typically every room the caller is or was in)
/// rather than scanning every room this server has ever created. Returns an
/// empty vec without querying when `room_ids` is empty.
pub fn user_ids_with_leave_transition_in_rooms(
    conn: &Connection,
    room_ids: &[String],
    from_exclusive: i64,
    to_inclusive: i64,
) -> rusqlite::Result<Vec<i64>> {
    if room_ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = vec!["?"; room_ids.len()].join(",");
    let sql = format!(
        "SELECT DISTINCT e.state_key, e.content FROM events e
         WHERE e.event_type = 'm.room.member' AND e.state_key IS NOT NULL
           AND e.stream_id > ? AND e.stream_id <= ?
           AND e.room_id IN ({placeholders})"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut bound: Vec<&dyn rusqlite::ToSql> = vec![&from_exclusive, &to_inclusive];
    for room_id in room_ids {
        bound.push(room_id as &dyn rusqlite::ToSql);
    }
    let mut rows = stmt.query(bound.as_slice())?;
    let mut mxids = Vec::new();
    while let Some(row) = rows.next()? {
        let mxid: String = row.get(0)?;
        let content: String = row.get(1)?;
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) {
            if matches!(value.get("membership").and_then(|m| m.as_str()), Some("leave") | Some("ban")) {
                mxids.push(mxid);
            }
        }
    }
    let mut user_ids = Vec::new();
    for mxid in mxids {
        if let Some(user_id) = user_id_of(conn, &mxid)? {
            user_ids.push(user_id);
        }
    }
    Ok(user_ids)
}

/// Timeline (non-state, non-redaction) events `sender_user_id` has sent into
/// any PRIVATE room (`join_rule = 'invite'`) with `origin_server_ts >=
/// since_ms` — `routes::matrix::messaging`'s per-sender daily send-rate
/// counter (plan §3.8: "mirroring `DM_MESSAGE_DAILY_LIMIT`... own copy of
/// the constant" — the constant itself lives in the route module per this
/// codebase's convention; this function is only the count query, since raw
/// SQL against `events`/`rooms` stays inside this module). State events
/// (`state_key IS NOT NULL`, sent via `/state`) and redactions are excluded
/// — this counts actual message-shaped sends, not every write a sender
/// makes.
pub fn private_room_messages_sent_since(conn: &Connection, sender_user_id: i64, since_ms: i64) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM events e JOIN rooms r ON r.id = e.room_id
         WHERE e.sender_user_id = ?1 AND e.state_key IS NULL AND e.event_type != 'm.room.redaction'
           AND e.origin_server_ts >= ?2 AND r.join_rule = 'invite'",
        params![sender_user_id, since_ms],
        |row| row.get(0),
    )
}

/// How many `(user_id, device_id)` sends/redacts were recorded since `since`
/// (an RFC-3339 timestamp, compared as a plain string against `created_at`
/// values this server ALWAYS writes in that same shape — safe without the
/// `datetime()` normalization `lookup_web_credential`'s own doc warns about,
/// which is specifically about comparing against SQLite's own `datetime()`
/// output, a different textual shape) — `routes::matrix::messaging`'s
/// short-window burst-rate counter (plan §3.8: "20 events / 10s per
/// device"). Reads `txn_dedup`, the one table that already carries a
/// per-DEVICE identity for a write (`events` itself has no `device_id`
/// column).
pub fn txn_dedup_count_since(conn: &Connection, user_id: i64, device_id: &str, since: &str) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM txn_dedup WHERE user_id = ?1 AND device_id = ?2 AND created_at >= ?3",
        params![user_id, device_id, since],
        |row| row.get(0),
    )
}

// ============================================================================
// History visibility (P6 binding rule, shared by `/messages`, `/event`,
// `/relations`, and exported for P10's `/sync`)
// ============================================================================

/// How much of a room's timeline a caller may read, per
/// [`visible_upper_bound`]. `UpTo` is INCLUSIVE (a caller who left the room
/// still sees the `m.room.member` leave event itself, since that is the last
/// event they witnessed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryWindow {
    /// No read access to this room's timeline at all.
    Nothing,
    /// Every event, unbounded.
    All,
    /// Every event with `stream_id <= this`.
    UpTo(i64),
}

impl HistoryWindow {
    pub fn contains(self, stream_id: i64) -> bool {
        match self {
            HistoryWindow::Nothing => false,
            HistoryWindow::All => true,
            HistoryWindow::UpTo(upto) => stream_id <= upto,
        }
    }
}

/// The history-visibility rule every timeline-reading route enforces
/// (`routes::matrix::messaging`'s `/messages`, `/event`, `/relations`; P10's
/// `/sync` reuses this too):
///
/// - `world_readable`: ANY signed-in caller sees the WHOLE timeline
///   ([`HistoryWindow::All`]), regardless of their own membership — this is
///   the one case where a caller who was never a member of the room at all
///   still reads it.
/// - Every other `history_visibility` value (`shared`, and this server's
///   simplified handling of `invited`/`joined` — v1 does not implement their
///   finer per-event lower bound, see the module doc): a currently `join`ed
///   member sees the whole timeline ([`HistoryWindow::All`]); a member whose
///   CURRENT membership is `leave`/`ban` sees only up to the stream position
///   of that leave/ban event itself ([`HistoryWindow::UpTo`], read off the
///   `m.room.member` state event's own `stream_id` — it is, by definition,
///   the LATEST such event for that member, since that is what "current
///   membership" means); anyone else (never touched this room's membership
///   at all, or is merely `invite`d without ever having joined) sees
///   [`HistoryWindow::Nothing`].
pub fn visible_upper_bound(conn: &Connection, room: &Room, caller_user_id: i64) -> Result<HistoryWindow, MatrixStoreError> {
    if room.history_visibility == HistoryVisibility::WorldReadable {
        return Ok(HistoryWindow::All);
    }
    let Some(mxid) = mxid_of(conn, caller_user_id)? else {
        return Ok(HistoryWindow::Nothing);
    };
    let Some(member_event) = current_state_event(conn, &room.id, "m.room.member", &mxid)? else {
        return Ok(HistoryWindow::Nothing);
    };
    let content: serde_json::Value = serde_json::from_str(&member_event.content)?;
    match content.get("membership").and_then(|v| v.as_str()) {
        Some("join") => Ok(HistoryWindow::All),
        Some("leave") | Some("ban") => Ok(HistoryWindow::UpTo(member_event.stream_id)),
        _ => Ok(HistoryWindow::Nothing),
    }
}

// ============================================================================
// Receipts
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct ReceiptRow {
    pub room_id: String,
    pub user_id: i64,
    pub receipt_type: ReceiptType,
    pub event_id: String,
    pub ts: i64,
    pub stream_id: i64,
}

fn receipt_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReceiptRow> {
    let receipt_type_raw: String = row.get(2)?;
    Ok(ReceiptRow {
        room_id: row.get(0)?,
        user_id: row.get(1)?,
        receipt_type: decode_enum(2, "receipt_type", &receipt_type_raw, ReceiptType::from_wire_name)?,
        event_id: row.get(3)?,
        ts: row.get(4)?,
        stream_id: row.get(5)?,
    })
}

const RECEIPT_SELECT_COLUMNS: &str = "room_id, user_id, receipt_type, event_id, ts, stream_id";

pub fn get_receipt(conn: &Connection, room_id: &str, user_id: i64, receipt_type: ReceiptType) -> rusqlite::Result<Option<ReceiptRow>> {
    conn.query_row(
        &format!("SELECT {RECEIPT_SELECT_COLUMNS} FROM receipts WHERE room_id = ?1 AND user_id = ?2 AND receipt_type = ?3"),
        params![room_id, user_id, receipt_type.as_str()],
        receipt_from_row,
    )
    .optional()
}

/// Every receipt row in `room_id` whose own write-order `stream_id` (NOT the
/// TARGET event's position — see [`upsert_receipt`]'s own doc on that
/// distinction) falls in `(since_exclusive, upto_inclusive]` —
/// `routes::matrix::sync`'s per-room `m.receipt` ephemeral delta (plan
/// §3.6).
pub fn receipts_changed_in_room(conn: &Connection, room_id: &str, since_exclusive: i64, upto_inclusive: i64) -> rusqlite::Result<Vec<ReceiptRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {RECEIPT_SELECT_COLUMNS} FROM receipts WHERE room_id = ?1 AND stream_id > ?2 AND stream_id <= ?3"
    ))?;
    let rows = stmt.query_map(params![room_id, since_exclusive, upto_inclusive], receipt_from_row)?;
    rows.collect()
}

/// Upsert `user_id`'s `receipt_type` receipt in `room_id`, refusing to move
/// it BACKWARDS: compared by the TARGET events' own `stream_id` (timeline
/// position), never by the receipt row's own `stream_id` column (which
/// orders receipt *writes* for `/sync`'s ephemeral-since-last-batch filter,
/// a different axis). Returns the resulting `stream_id` stamped on the
/// row — the existing one, unchanged, on a refused backward move.
///
/// Refuses with [`MatrixStoreError::UnknownEventId`] if `event_id` does not
/// exist, or [`MatrixStoreError::WrongRoom`] if it exists but is in a
/// different room than `room_id` — a receipt can never point at an event
/// outside the room it is filed in.
pub fn upsert_receipt(
    conn: &mut Connection,
    room_id: &str,
    user_id: i64,
    receipt_type: ReceiptType,
    event_id: &str,
    ts: i64,
) -> Result<i64, MatrixStoreError> {
    let tx = conn.transaction()?;
    let stream_id = upsert_receipt_in_tx(&tx, room_id, user_id, receipt_type, event_id, ts)?;
    tx.commit()?;
    Ok(stream_id)
}

/// The `&Transaction`-scoped core of [`upsert_receipt`] — split out the same
/// way [`insert_timeline_event_in_tx`] is split from [`insert_timeline_event`],
/// so [`catch_up_dm_conversation`] (P15: bridging a live legacy DM send, or a
/// boot pass catching one up) can advance a reader's receipt in the SAME
/// transaction as the messages that reader's receipt targets, rather than a
/// second one — `upsert_receipt` itself opens its own transaction and so
/// cannot be nested inside a caller's own `Transaction` on the same
/// connection.
fn upsert_receipt_in_tx(
    tx: &Transaction,
    room_id: &str,
    user_id: i64,
    receipt_type: ReceiptType,
    event_id: &str,
    ts: i64,
) -> Result<i64, MatrixStoreError> {
    let target: Option<(i64, String)> = tx
        .query_row("SELECT stream_id, room_id FROM events WHERE event_id = ?1", params![event_id], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .optional()?;
    let (target_position, target_room) = target.ok_or_else(|| MatrixStoreError::UnknownEventId(event_id.to_string()))?;
    if target_room != room_id {
        return Err(MatrixStoreError::WrongRoom(event_id.to_string()));
    }

    let existing: Option<(String, i64)> = tx
        .query_row(
            "SELECT event_id, stream_id FROM receipts WHERE room_id = ?1 AND user_id = ?2 AND receipt_type = ?3",
            params![room_id, user_id, receipt_type.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    if let Some((existing_event_id, existing_stream_id)) = &existing {
        let existing_position: i64 =
            tx.query_row("SELECT stream_id FROM events WHERE event_id = ?1", params![existing_event_id], |row| row.get(0))?;
        if target_position <= existing_position {
            return Ok(*existing_stream_id);
        }
    }

    let stream_id = next_stream_id(tx)?;
    tx.execute(
        "INSERT INTO receipts (room_id, user_id, receipt_type, event_id, ts, stream_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(room_id, user_id, receipt_type) DO UPDATE SET
            event_id = excluded.event_id, ts = excluded.ts, stream_id = excluded.stream_id",
        params![room_id, user_id, receipt_type.as_str(), event_id, ts, stream_id],
    )?;
    Ok(stream_id)
}

// ============================================================================
// Unread notifications (plan §3.5) — `/sync`'s `unread_notifications` block
// ============================================================================

/// Message-like timeline event types that count toward
/// `unread_notifications.notification_count` (plan §3.5) — everything else
/// (state events, `m.reaction`, `m.room.redaction`) is excluded. A legacy DM
/// migrated from `dm_conversations` (plan §7) lands as
/// `org.mylittlechart.legacy_dm`, which counts the same as a live message.
const NOTIFICATION_MESSAGE_TYPES_SQL: &str = "('m.room.message', 'm.room.encrypted', 'org.mylittlechart.legacy_dm')";

/// `unread_notifications.notification_count` for `user_id` in `room` (plan
/// §3.5): the count of message-like timeline events (see
/// [`NOTIFICATION_MESSAGE_TYPES_SQL`]) strictly after the FURTHER-AHEAD of
/// the caller's own `m.read`/`m.read.private` receipt — resolved by the
/// target events' own `stream_id` (timeline position), never by a receipt
/// row's own `stream_id` column (a different axis — see [`upsert_receipt`]'s
/// own doc) — and bounded above by [`visible_upper_bound`] (a `leave`/
/// `ban`'d member's count never includes anything past their own
/// departure). Excludes the caller's own sends (nobody is notified about
/// their own message) and, being restricted to
/// [`NOTIFICATION_MESSAGE_TYPES_SQL`], every state event and `m.reaction`.
/// Not a member of the room at all ([`HistoryWindow::Nothing`]) is always
/// `0` — there is nothing this caller could be notified about.
///
/// `highlight_count` is always `0` from this server (plan §3.5: no push-
/// rule/keyword-highlight engine in v1, encrypted or not) — that is a
/// constant the `/sync` response builder (P10) sets directly, not a second
/// query here.
pub fn notification_count(conn: &Connection, room: &Room, user_id: i64) -> Result<i64, MatrixStoreError> {
    let upper_bound = match visible_upper_bound(conn, room, user_id)? {
        HistoryWindow::Nothing => return Ok(0),
        HistoryWindow::All => i64::MAX,
        HistoryWindow::UpTo(upper) => upper,
    };

    let mut after_stream_id: i64 = 0;
    for receipt_type in [ReceiptType::Read, ReceiptType::ReadPrivate] {
        if let Some(receipt) = get_receipt(conn, &room.id, user_id, receipt_type)? {
            if let Some(target) = get_event(conn, &receipt.event_id)? {
                after_stream_id = after_stream_id.max(target.stream_id);
            }
        }
    }

    let count = conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM events
             WHERE room_id = ?1 AND state_key IS NULL AND sender_user_id != ?2
               AND stream_id > ?3 AND stream_id <= ?4
               AND event_type IN {NOTIFICATION_MESSAGE_TYPES_SQL}"
        ),
        params![room.id, user_id, after_stream_id, upper_bound],
        |row| row.get(0),
    )?;
    Ok(count)
}

// ============================================================================
// Account data
// ============================================================================

/// `room_id` value meaning "global account data" — see [`create_matrix_schema`]'s
/// doc comment on why this is `""`, never `NULL`.
pub const GLOBAL_ACCOUNT_DATA_ROOM: &str = "";

#[derive(Debug, Clone, PartialEq)]
pub struct AccountDataRow {
    pub user_id: i64,
    pub room_id: String,
    pub data_type: String,
    pub content: String,
    pub stream_id: i64,
}

fn account_data_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccountDataRow> {
    Ok(AccountDataRow {
        user_id: row.get(0)?,
        room_id: row.get(1)?,
        data_type: row.get(2)?,
        content: row.get(3)?,
        stream_id: row.get(4)?,
    })
}

const ACCOUNT_DATA_SELECT_COLUMNS: &str = "user_id, room_id, data_type, content, stream_id";

/// Upsert one account-data entry. Pass [`GLOBAL_ACCOUNT_DATA_ROOM`] for
/// global data (`m.direct`, `m.push_rules`, ...); a real room id for
/// per-room data.
pub fn upsert_account_data(conn: &mut Connection, user_id: i64, room_id: &str, data_type: &str, content: &str) -> Result<i64, MatrixStoreError> {
    let tx = conn.transaction()?;
    let stream_id = next_stream_id(&tx)?;
    tx.execute(
        "INSERT INTO account_data (user_id, room_id, data_type, content, stream_id) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(user_id, room_id, data_type) DO UPDATE SET content = excluded.content, stream_id = excluded.stream_id",
        params![user_id, room_id, data_type, content, stream_id],
    )?;
    tx.commit()?;
    Ok(stream_id)
}

pub fn get_account_data(conn: &Connection, user_id: i64, room_id: &str, data_type: &str) -> rusqlite::Result<Option<AccountDataRow>> {
    conn.query_row(
        &format!("SELECT {ACCOUNT_DATA_SELECT_COLUMNS} FROM account_data WHERE user_id = ?1 AND room_id = ?2 AND data_type = ?3"),
        params![user_id, room_id, data_type],
        account_data_from_row,
    )
    .optional()
}

/// Every `(user_id, room_id)` account-data row changed strictly after
/// `since_stream` — the `/sync` delta shape for both global and per-room
/// account data (caller passes [`GLOBAL_ACCOUNT_DATA_ROOM`] or a real room
/// id).
pub fn account_data_since(conn: &Connection, user_id: i64, room_id: &str, since_stream: i64) -> rusqlite::Result<Vec<AccountDataRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {ACCOUNT_DATA_SELECT_COLUMNS} FROM account_data WHERE user_id = ?1 AND room_id = ?2 AND stream_id > ?3 ORDER BY stream_id ASC"
    ))?;
    let rows = stmt.query_map(params![user_id, room_id, since_stream], account_data_from_row)?;
    rows.collect()
}

// ============================================================================
// Txn-id idempotency
// ============================================================================

/// What [`txn_dedup_lookup`] found for a given `(user_id, device_id, txn_id)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxnDedupEntry {
    /// No prior submission recorded — the caller should proceed to create
    /// the event/to-device-send and then [`txn_dedup_record`] it.
    NotSeen,
    /// Already recorded. `Some(event_id)` for a send/redact that produced
    /// an event; `None` for a to-device send (which has no `events` row).
    Seen(Option<String>),
}

/// Check whether `(user_id, device_id, txn_id)` was already handled,
/// without recording anything.
pub fn txn_dedup_lookup(conn: &Connection, user_id: i64, device_id: &str, txn_id: &str) -> rusqlite::Result<TxnDedupEntry> {
    let found: Option<Option<String>> = conn
        .query_row(
            "SELECT event_id FROM txn_dedup WHERE user_id = ?1 AND device_id = ?2 AND txn_id = ?3",
            params![user_id, device_id, txn_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(match found {
        None => TxnDedupEntry::NotSeen,
        Some(event_id) => TxnDedupEntry::Seen(event_id),
    })
}

/// Record that `(user_id, device_id, txn_id)` has now been handled,
/// producing `event_id` (or `None` for a to-device send). Call only after
/// [`txn_dedup_lookup`] returned [`TxnDedupEntry::NotSeen`] — this does not
/// itself check for a race, per this module's single-writer discipline.
pub fn txn_dedup_record(conn: &Connection, user_id: i64, device_id: &str, txn_id: &str, event_id: Option<&str>, now: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO txn_dedup (user_id, device_id, txn_id, event_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![user_id, device_id, txn_id, event_id, now],
    )?;
    Ok(())
}

/// The `txn_id` `(user_id, device_id)` used to produce `event_id`, if any —
/// [`client_event_json`](crate::routes::matrix::client_event_json)'s
/// `unsigned.transaction_id`, which Matrix reveals ONLY to the same device
/// that sent the event, never to any other viewer (including the sender's
/// OTHER devices). A miss (`None`) is the overwhelmingly common case (every
/// event not authored by this exact device on this exact send) and costs a
/// single indexed `txn_dedup` primary-key lookup.
pub fn txn_id_for_event(conn: &Connection, user_id: i64, device_id: &str, event_id: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT txn_id FROM txn_dedup WHERE user_id = ?1 AND device_id = ?2 AND event_id = ?3",
        params![user_id, device_id, event_id],
        |row| row.get(0),
    )
    .optional()
}

// ============================================================================
// Filters
// ============================================================================

/// Store an opaque Filter JSON object, returning its new `filter_id`.
pub fn create_filter(conn: &Connection, user_id: i64, definition: &str) -> rusqlite::Result<i64> {
    conn.execute("INSERT INTO filters (user_id, definition) VALUES (?1, ?2)", params![user_id, definition])?;
    Ok(conn.last_insert_rowid())
}

/// Fetch `user_id`'s own `filter_id`'s definition — scoped to `user_id` so
/// one account can never read another's stored filter by guessing an id.
pub fn get_filter(conn: &Connection, user_id: i64, filter_id: i64) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT definition FROM filters WHERE id = ?1 AND user_id = ?2",
        params![filter_id, user_id],
        |row| row.get(0),
    )
    .optional()
}

// ============================================================================
// Legacy DM migration map
// ============================================================================

pub fn insert_legacy_dm_message_map(conn: &Connection, legacy_message_id: i64, event_id: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO legacy_dm_message_map (legacy_message_id, event_id) VALUES (?1, ?2)",
        params![legacy_message_id, event_id],
    )?;
    Ok(())
}

pub fn legacy_dm_message_event_id(conn: &Connection, legacy_message_id: i64) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT event_id FROM legacy_dm_message_map WHERE legacy_message_id = ?1",
        params![legacy_message_id],
        |row| row.get(0),
    )
    .optional()
}

/// The highest `legacy_message_id` already imported into `room_id`'s
/// `org.mylittlechart.legacy_dm` timeline (P15: `matrix_migration`'s own
/// catch-up cursor). `legacy_dm_message_map` carries no `room_id` of its
/// own — `dm_messages.id` is a single autoincrement column shared by every
/// legacy conversation, not scoped per conversation — so this joins through
/// `events` to find only the rows imported into THIS room. Message ids are
/// ascending within one conversation and every migration/catch-up pass
/// imports every not-yet-mapped row up to "now", so `id > this` is exactly
/// that conversation's not-yet-imported set — the caller's own cheap
/// alternative to re-checking `legacy_dm_message_event_id` once per message.
/// `None` for a room with no legacy message imported yet (a conversation
/// that had zero messages at migration time).
pub fn highest_mapped_legacy_message_id(conn: &Connection, room_id: &str) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT MAX(m.legacy_message_id) FROM legacy_dm_message_map m
         JOIN events e ON e.event_id = m.event_id
         WHERE e.room_id = ?1",
        params![room_id],
        |row| row.get(0),
    )
}

// ============================================================================
// Legacy DM migration batch (P12) — the binary crate's own `matrix_migration`
// module is the only caller. Everything one `dm_conversations` row needs
// (room + bootstrap state events + every not-yet-imported message + read
// receipts + the `m.direct` account-data hint for both parties) lands in
// ONE transaction here, for the same reason `create_room_with_state` is a
// batch entry point rather than several independent calls (P5 correction):
// a crash partway through must never leave a room with some but not all of
// its own bootstrap state, or a room with some but not all of its messages.
// This reuses the SAME private `_in_tx` helpers `create_room_with_state`
// itself uses (`insert_room_row`, `apply_state_event_in_tx`,
// `insert_timeline_event_in_tx`), so a migrated room's rows are written by
// the exact same code paths a live `createRoom`/`send` call would use.
// ============================================================================

/// One legacy `dm_messages` row queued for import (plan §7 step 5).
/// `event_id` is minted by the caller ([`crate::matrix_migration`] in the
/// binary crate) so it can be recorded in the caller's own bookkeeping (the
/// idempotency proof compares event ids across two runs) without a second
/// round trip back into this module. `content` is already the full
/// `org.mylittlechart.legacy_dm` JSON body
/// (`{"legacy_message_id","legacy_conversation_id","nonce_b64","ciphertext_b64"}`).
///
/// # `legacy_conversation_id`
///
/// Both this message's own content AND the room's
/// `org.mylittlechart.legacy_dm_key` state event content (plan §2 manager
/// decision 5) carry the legacy `dm_conversations.id` (as
/// `legacy_conversation_id`) — a client derives
/// `mlc_vault::dm::conversation_key` from that id plus the sender's and its
/// own keys, and has no other way to learn which legacy conversation a
/// migrated room came from. A `messenger.db` migrated by a build before this
/// field existed is missing it on every already-migrated row; that is a
/// dev-only concern (nothing has shipped) — recreate the database rather
/// than backfill it.
#[derive(Debug, Clone, PartialEq)]
pub struct LegacyDmMessageImport {
    pub legacy_message_id: i64,
    pub event_id: String,
    pub sender_user_id: i64,
    pub content: String,
    pub origin_server_ts: i64,
}

/// One reader's `m.read` receipt to set once its target message has been
/// imported — `up_to_legacy_message_id` is the LAST `dm_messages.id` this
/// reader actually had `read_at` stamped for in `social.db` (never a later
/// one — plan P12 scope: "never over-count as read"). `ts_ms` is that same
/// message's own `read_at`, converted to epoch milliseconds.
#[derive(Debug, Clone, PartialEq)]
pub struct LegacyDmReadReceipt {
    pub reader_user_id: i64,
    pub up_to_legacy_message_id: i64,
    pub ts_ms: i64,
}

/// One `m.direct` merge hint (plan P12 scope: "merge into their existing
/// `m.direct`, do not overwrite other entries") — `user_id`'s global
/// `m.direct` account data gains `peer_mxid` mapped to the migrated room id,
/// alongside whatever entries it already has.
#[derive(Debug, Clone, PartialEq)]
pub struct LegacyDmDirectHint {
    pub user_id: i64,
    pub peer_mxid: String,
}

/// Everything [`migrate_dm_conversation`] needs beyond the room bootstrap
/// itself, grouped into one value for the same "stays lint-clean without
/// `#[allow(clippy::too_many_arguments)]`" reason [`RoomBootstrap`]'s own doc
/// comment states.
#[derive(Debug, Clone, Copy)]
pub struct DmMigrationExtras<'a> {
    pub messages: &'a [LegacyDmMessageImport],
    pub receipts: &'a [LegacyDmReadReceipt],
    pub direct_hints: &'a [LegacyDmDirectHint],
}

/// What one [`migrate_dm_conversation`] call actually wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DmMigrationCounts {
    pub messages_imported: usize,
    pub receipts_set: usize,
}

/// Merge `{peer_mxid: [room_id]}` into `user_id`'s existing GLOBAL `m.direct`
/// account data, inside `tx` — every other peer's entry already in the
/// object is left untouched, and a `room_id` already present under
/// `peer_mxid` is not duplicated.
fn merge_m_direct_in_tx(tx: &Transaction, user_id: i64, peer_mxid: &str, room_id: &str) -> Result<(), MatrixStoreError> {
    let existing: Option<String> = tx
        .query_row(
            "SELECT content FROM account_data WHERE user_id = ?1 AND room_id = ?2 AND data_type = 'm.direct'",
            params![user_id, GLOBAL_ACCOUNT_DATA_ROOM],
            |row| row.get(0),
        )
        .optional()?;

    let mut direct: serde_json::Map<String, serde_json::Value> = match existing {
        Some(content) => serde_json::from_str(&content)?,
        None => serde_json::Map::new(),
    };
    let rooms_entry = direct.entry(peer_mxid.to_string()).or_insert_with(|| serde_json::Value::Array(Vec::new()));
    if !rooms_entry.is_array() {
        *rooms_entry = serde_json::Value::Array(Vec::new());
    }
    if let serde_json::Value::Array(list) = rooms_entry {
        if !list.iter().any(|v| v.as_str() == Some(room_id)) {
            list.push(serde_json::Value::String(room_id.to_string()));
        }
    }

    let stream_id = next_stream_id(tx)?;
    tx.execute(
        "INSERT INTO account_data (user_id, room_id, data_type, content, stream_id) VALUES (?1, ?2, 'm.direct', ?3, ?4)
         ON CONFLICT(user_id, room_id, data_type) DO UPDATE SET content = excluded.content, stream_id = excluded.stream_id",
        params![user_id, GLOBAL_ACCOUNT_DATA_ROOM, serde_json::Value::Object(direct).to_string(), stream_id],
    )?;
    Ok(())
}

/// The P12 migration's own batch entry point: `bootstrap`'s room row, then
/// every entry of `state_events` (identical shape to
/// [`create_room_with_state`]'s own loop — same order requirement: a
/// member's `m.room.member` must precede `m.room.power_levels` for
/// [`refresh_power_levels`] to see them, see that function's own doc), then
/// every `extras.messages` entry as an `org.mylittlechart.legacy_dm`
/// timeline event plus its `legacy_dm_message_map` row, then
/// `extras.receipts`, then `extras.direct_hints` — all in ONE transaction.
/// `extras.messages` must already be filtered by the caller to exclude any
/// `legacy_message_id` already present in `legacy_dm_message_map` and
/// ordered ascending by `legacy_message_id`; this function does not
/// re-check either, since the binary crate's own `matrix_migration` module
/// already established the room does not exist yet via
/// [`room_by_legacy_dm_id`] before ever calling this.
pub fn migrate_dm_conversation(
    conn: &mut Connection,
    bootstrap: RoomBootstrap<'_>,
    state_events: &[NewStateEvent],
    bootstrap_origin_server_ts: i64,
    extras: DmMigrationExtras<'_>,
) -> Result<(Room, DmMigrationCounts), MatrixStoreError> {
    let tx = conn.transaction()?;

    insert_room_row(
        &tx,
        bootstrap.room_id,
        bootstrap.kind,
        bootstrap.creator_user_id,
        bootstrap.created_at,
        bootstrap.is_encrypted,
        bootstrap.join_rule,
        bootstrap.history_visibility,
        bootstrap.dm_pair_key,
        bootstrap.legacy_dm_id,
    )?;
    for event in state_events {
        apply_state_event_in_tx(
            &tx,
            &event.event_id,
            bootstrap.room_id,
            event.sender_user_id,
            &event.event_type,
            &event.state_key,
            &event.content,
            bootstrap_origin_server_ts,
            bootstrap.created_at,
        )?;
    }

    let mut event_id_by_legacy_id: std::collections::HashMap<i64, String> = std::collections::HashMap::new();
    for message in extras.messages {
        insert_timeline_event_in_tx(
            &tx,
            &TimelineEventRow {
                event_id: &message.event_id,
                room_id: bootstrap.room_id,
                sender_user_id: message.sender_user_id,
                event_type: "org.mylittlechart.legacy_dm",
                content: &message.content,
                origin_server_ts: message.origin_server_ts,
                txn_id: None,
            },
        )?;
        insert_legacy_dm_message_map(&tx, message.legacy_message_id, &message.event_id)?;
        event_id_by_legacy_id.insert(message.legacy_message_id, message.event_id.clone());
    }

    let mut receipts_set = 0usize;
    for receipt in extras.receipts {
        let Some(target_event_id) = event_id_by_legacy_id.get(&receipt.up_to_legacy_message_id) else { continue };
        let target_stream_id: i64 =
            tx.query_row("SELECT stream_id FROM events WHERE event_id = ?1", params![target_event_id], |row| row.get(0))?;
        tx.execute(
            "INSERT INTO receipts (room_id, user_id, receipt_type, event_id, ts, stream_id) VALUES (?1, ?2, 'm.read', ?3, ?4, ?5)",
            params![bootstrap.room_id, receipt.reader_user_id, target_event_id, receipt.ts_ms, target_stream_id],
        )?;
        receipts_set += 1;
    }

    for hint in extras.direct_hints {
        merge_m_direct_in_tx(&tx, hint.user_id, &hint.peer_mxid, bootstrap.room_id)?;
    }

    tx.commit()?;

    Ok((
        Room {
            id: bootstrap.room_id.to_string(),
            kind: bootstrap.kind,
            room_version: MATRIX_ROOM_VERSION.to_string(),
            creator_user_id: bootstrap.creator_user_id,
            created_at: bootstrap.created_at.to_string(),
            is_encrypted: bootstrap.is_encrypted,
            join_rule: bootstrap.join_rule,
            history_visibility: bootstrap.history_visibility,
            dm_pair_key: bootstrap.dm_pair_key.map(str::to_string),
            legacy_dm_id: bootstrap.legacy_dm_id,
        },
        DmMigrationCounts { messages_imported: extras.messages.len(), receipts_set },
    ))
}

/// A catch-up pass for an ALREADY migrated room (P15) — the binary crate's
/// own `matrix_migration` module calls this both from a live legacy DM
/// send's bridge (`routes::dm::create_message`, right after its own insert
/// commits) and from a boot pass over a conversation
/// [`room_by_legacy_dm_id`] already finds a room for. `messages` (already
/// filtered by the caller to exclude anything already in
/// `legacy_dm_message_map`, ordered ascending by `legacy_message_id`) lands
/// as new `org.mylittlechart.legacy_dm` timeline events plus their
/// `legacy_dm_message_map` rows; then each of `receipts` advances that
/// reader's `m.read` receipt — never moved backwards
/// ([`upsert_receipt_in_tx`]'s own guarantee, the SAME one a live `/receipt`
/// call gets) — all in ONE transaction. Reuses the exact per-event helpers
/// [`migrate_dm_conversation`] itself uses, so a caught-up room's rows are
/// indistinguishable from ones a fresh migration (or a live Matrix send)
/// would have produced.
///
/// Each `receipt.up_to_legacy_message_id` is resolved via
/// [`legacy_dm_message_event_id`] against the FULL map (this transaction's
/// own just-inserted rows are visible to it too, same connection) — not just
/// this call's own `messages` — because the caller's own read-position query
/// considers EVERY read message in the conversation, including ones a
/// PRIOR pass already imported (a message read only after it was already
/// bridged must still move the receipt here; manager review, P15). A target
/// this catch-up's own `messages` did not just insert AND that is not yet in
/// the map at all (should not happen — a receipt only ever targets a message
/// that exists) is skipped rather than erroring, same defensive posture
/// [`migrate_dm_conversation`]'s own receipt loop takes.
pub fn catch_up_dm_conversation(
    conn: &mut Connection,
    room_id: &str,
    messages: &[LegacyDmMessageImport],
    receipts: &[LegacyDmReadReceipt],
) -> Result<DmMigrationCounts, MatrixStoreError> {
    let tx = conn.transaction()?;
    let counts = catch_up_dm_in_tx(&tx, room_id, messages, receipts)?;
    tx.commit()?;
    Ok(counts)
}

/// The body of [`catch_up_dm_conversation`], inside the caller's transaction —
/// shared with [`adopt_dm_room_for_legacy`], so an adopted native room takes
/// its legacy messages and read positions through exactly the same code as
/// an already-migrated room's catch-up.
fn catch_up_dm_in_tx(
    tx: &Transaction,
    room_id: &str,
    messages: &[LegacyDmMessageImport],
    receipts: &[LegacyDmReadReceipt],
) -> Result<DmMigrationCounts, MatrixStoreError> {
    for message in messages {
        insert_timeline_event_in_tx(
            tx,
            &TimelineEventRow {
                event_id: &message.event_id,
                room_id,
                sender_user_id: message.sender_user_id,
                event_type: "org.mylittlechart.legacy_dm",
                content: &message.content,
                origin_server_ts: message.origin_server_ts,
                txn_id: None,
            },
        )?;
        insert_legacy_dm_message_map(tx, message.legacy_message_id, &message.event_id)?;
    }

    let mut receipts_set = 0usize;
    for receipt in receipts {
        let Some(target_event_id) = legacy_dm_message_event_id(tx, receipt.up_to_legacy_message_id)? else { continue };
        upsert_receipt_in_tx(tx, room_id, receipt.reader_user_id, ReceiptType::Read, &target_event_id, receipt.ts_ms)?;
        receipts_set += 1;
    }

    Ok(DmMigrationCounts { messages_imported: messages.len(), receipts_set })
}

/// What [`adopt_dm_room_for_legacy`] needs to bind a native DM room to a
/// legacy conversation, grouped for the same lint-clean reason
/// [`RoomBootstrap`]'s doc states.
#[derive(Debug, Clone, Copy)]
pub struct DmAdoption<'a> {
    /// The live native DM room that already holds the pair's `dm_pair_key`.
    pub room_id: &'a str,
    /// The legacy `dm_conversations.id` the room is bound to.
    pub legacy_dm_id: i64,
    /// The pair's `org.mylittlechart.legacy_dm_key` state events. Each is
    /// written only when the room has no current event for its
    /// `(event_type, state_key)` yet — an existing key event is never
    /// overwritten.
    pub key_events: &'a [NewStateEvent],
    pub key_events_origin_server_ts: i64,
    /// RFC3339 stamp for the member/state bookkeeping of the key events.
    pub now: &'a str,
}

/// Bind an EXISTING native DM room to legacy conversation
/// `adoption.legacy_dm_id`, instead of minting a second room for the same
/// pair (`rooms.dm_pair_key` is `UNIQUE`, so a second insert is refused):
/// sets `rooms.legacy_dm_id`, writes any missing legacy key state event,
/// then imports `messages` and `receipts` through the shared catch-up
/// body ([`catch_up_dm_in_tx`]) — all in ONE transaction, so a failure
/// leaves the room exactly as it was. `messages` follow
/// [`catch_up_dm_conversation`]'s contract (not yet in
/// `legacy_dm_message_map`, ascending by `legacy_message_id`).
///
/// Returns `Ok(None)`, having written nothing, when `room_id` is not a DM
/// room without a legacy binding (missing, another kind, or already bound to
/// a legacy conversation) — the caller decides what that means.
pub fn adopt_dm_room_for_legacy(
    conn: &mut Connection,
    adoption: DmAdoption<'_>,
    messages: &[LegacyDmMessageImport],
    receipts: &[LegacyDmReadReceipt],
) -> Result<Option<DmMigrationCounts>, MatrixStoreError> {
    let tx = conn.transaction()?;

    let bound = tx.execute(
        "UPDATE rooms SET legacy_dm_id = ?1 WHERE id = ?2 AND kind = 'dm' AND legacy_dm_id IS NULL",
        params![adoption.legacy_dm_id, adoption.room_id],
    )?;
    if bound == 0 {
        return Ok(None);
    }

    for event in adoption.key_events {
        if current_state_event(&tx, adoption.room_id, &event.event_type, &event.state_key)?.is_some() {
            continue;
        }
        apply_state_event_in_tx(
            &tx,
            &event.event_id,
            adoption.room_id,
            event.sender_user_id,
            &event.event_type,
            &event.state_key,
            &event.content,
            adoption.key_events_origin_server_ts,
            adoption.now,
        )?;
    }

    let counts = catch_up_dm_in_tx(&tx, adoption.room_id, messages, receipts)?;
    tx.commit()?;
    Ok(Some(counts))
}

// ============================================================================
// Public room directory (P8: `routes::matrix::account`'s `GET`/`POST
// /publicRooms`)
// ============================================================================

/// One row of `GET /publicRooms`'s `chunk` — a public-`join_rule` room's
/// directory summary. `name`/`topic` are `None` when the room never had an
/// `m.room.name`/`m.room.topic` state event (plan §5: only a `channel`-kind
/// room is ever `join_rule = 'public'`, but this reads the column directly
/// rather than also filtering on `kind`, so it stays correct even if a
/// future piece ever makes a `group` room public).
#[derive(Debug, Clone, PartialEq)]
pub struct PublicRoomSummary {
    pub room_id: String,
    pub name: Option<String>,
    pub topic: Option<String>,
    pub num_joined_members: i64,
    pub world_readable: bool,
}

/// One page of the public-room directory, ordered by `rooms.id` — a stable
/// pagination key (a room id never changes once minted). `after_room_id` is
/// the previous page's own last room id (`None` for the first page);
/// `search_term`, when non-empty, keeps only rooms whose current
/// `m.room.name` contains it (case-insensitive substring — Matrix's own
/// `generic_search_term`).
///
/// This scans every public room in Rust rather than pushing the search/
/// pagination interaction into SQL: a non-federated single server's public-
/// channel count is small and moderator-managed (channels are not something
/// a bot mass-creates), so an O(public rooms) scan per call is cheaper to
/// keep correct than a SQL query that would otherwise have to paginate
/// `LIMIT`-first and then discover a `search_term` filtered a whole page
/// down to nothing.
///
/// Returns `(page, has_more, total_room_count_estimate)` — `has_more` is
/// whether another page exists beyond this one (the route layer's own
/// `next_batch` decision); `total_room_count_estimate` is the count of every
/// public room regardless of `search_term`/pagination, matching the spec's
/// "estimate of the total number of public rooms" wording.
pub fn public_rooms_page(
    conn: &Connection,
    after_room_id: Option<&str>,
    limit: usize,
    search_term: Option<&str>,
) -> Result<(Vec<PublicRoomSummary>, bool, i64), MatrixStoreError> {
    let mut stmt = conn.prepare(
        "SELECT r.id, r.history_visibility,
                (SELECT COUNT(*) FROM room_members WHERE room_id = r.id AND membership = 'join')
         FROM rooms r WHERE r.join_rule = 'public' ORDER BY r.id ASC",
    )?;
    let mut rows = stmt.query([])?;
    let mut all = Vec::new();
    while let Some(row) = rows.next()? {
        let room_id: String = row.get(0)?;
        let history_visibility_raw: String = row.get(1)?;
        let num_joined_members: i64 = row.get(2)?;
        let world_readable = history_visibility_raw == HistoryVisibility::WorldReadable.as_str();

        let name = current_state_event(conn, &room_id, "m.room.name", "")?
            .and_then(|e| serde_json::from_str::<serde_json::Value>(&e.content).ok())
            .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(str::to_string));
        let topic = current_state_event(conn, &room_id, "m.room.topic", "")?
            .and_then(|e| serde_json::from_str::<serde_json::Value>(&e.content).ok())
            .and_then(|v| v.get("topic").and_then(|t| t.as_str()).map(str::to_string));

        all.push(PublicRoomSummary { room_id, name, topic, num_joined_members, world_readable });
    }
    drop(rows);
    drop(stmt);

    let total_room_count_estimate = all.len() as i64;

    let filtered: Vec<PublicRoomSummary> = match search_term {
        Some(term) if !term.is_empty() => {
            let term_lower = term.to_lowercase();
            all.into_iter().filter(|room| room.name.as_deref().is_some_and(|n| n.to_lowercase().contains(&term_lower))).collect()
        }
        _ => all,
    };

    let start = match after_room_id {
        Some(cursor) => filtered.iter().position(|r| r.room_id == cursor).map_or(0, |idx| idx + 1),
        None => 0,
    };
    let has_more = filtered.len() > start + limit;
    let page: Vec<PublicRoomSummary> = filtered.into_iter().skip(start).take(limit).collect();
    Ok((page, has_more, total_room_count_estimate))
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: &str = "2026-09-24T00:00:00+00:00";
    const ROOM: &str = "!testroom:mylittlechart.org";

    fn test_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        create_matrix_schema(&conn).expect("schema");
        conn
    }

    fn make_room(conn: &Connection) {
        create_room(conn, ROOM, RoomKind::Group, 1, T0, false, JoinRule::Invite, HistoryVisibility::Shared, None, None).expect("create room");
    }

    // ---- P1 test 1: stream ordering ----

    #[test]
    fn next_stream_id_is_strictly_monotonic_across_every_table() {
        let mut conn = test_conn();
        make_room(&conn);

        let event = insert_timeline_event(&mut conn, "$event1", ROOM, 1, "m.room.message", "{}", 1000).expect("insert event");
        let account_data_stream = upsert_account_data(&mut conn, 1, GLOBAL_ACCOUNT_DATA_ROOM, "m.direct", "{}").expect("account data");
        let receipt_stream = upsert_receipt(&mut conn, ROOM, 1, ReceiptType::Read, "$event1", 1500).expect("receipt");

        assert!(event.stream_id < account_data_stream, "event {} should precede account data {}", event.stream_id, account_data_stream);
        assert!(
            account_data_stream < receipt_stream,
            "account data {account_data_stream} should precede receipt {receipt_stream}"
        );
    }

    // ---- P1 test 2: current_state replaces, events keeps history ----

    #[test]
    fn apply_state_event_replaces_current_state_but_keeps_history_in_events() {
        let mut conn = test_conn();
        make_room(&conn);

        apply_state_event(&mut conn, &StateEventWrite { event_id: "$e1", room_id: ROOM, sender_user_id: 1, event_type: "m.room.name", state_key: "", content: r#"{"name":"first"}"#, origin_server_ts: 1000, now: T0 }).expect("apply first");
        apply_state_event(&mut conn, &StateEventWrite { event_id: "$e2", room_id: ROOM, sender_user_id: 1, event_type: "m.room.name", state_key: "", content: r#"{"name":"second"}"#, origin_server_ts: 2000, now: T0 }).expect("apply second");

        let current = current_state_event(&conn, ROOM, "m.room.name", "").expect("query").expect("row exists");
        assert_eq!(current.event_id, "$e2");
        assert_eq!(current.content, r#"{"name":"second"}"#);

        let e1 = get_event(&conn, "$e1").expect("get e1").expect("row exists");
        let e2 = get_event(&conn, "$e2").expect("get e2").expect("row exists");
        assert_eq!(e1.content, r#"{"name":"first"}"#);
        assert_eq!(e2.content, r#"{"name":"second"}"#);
    }

    // ---- P1 test 3: v11 redaction allow-list, table-driven ----

    #[test]
    fn redact_event_strips_content_per_v11_allow_list_by_type() {
        let cases: Vec<(&str, &str, serde_json::Value)> = vec![
            (
                "m.room.member",
                r#"{"membership":"join","join_authorised_via_users_server":"@x:mylittlechart.org","avatar_url":"mxc://x","displayname":"Bob","third_party_invite":{"display_name":"bob@example.com","signed":{"mxid":"@bob:mylittlechart.org"}}}"#,
                serde_json::json!({
                    "membership": "join",
                    "join_authorised_via_users_server": "@x:mylittlechart.org",
                    "third_party_invite": {"signed": {"mxid": "@bob:mylittlechart.org"}}
                }),
            ),
            (
                "m.room.power_levels",
                r#"{"ban":50,"events":{},"events_default":0,"invite":50,"kick":50,"redact":50,"state_default":50,"users":{"@a:x":100},"users_default":0,"extra":"drop me"}"#,
                serde_json::json!({
                    "ban": 50, "events": {}, "events_default": 0, "invite": 50, "kick": 50,
                    "redact": 50, "state_default": 50, "users": {"@a:x": 100}, "users_default": 0
                }),
            ),
            (
                "m.room.history_visibility",
                r#"{"history_visibility":"shared","extra":"drop"}"#,
                serde_json::json!({"history_visibility": "shared"}),
            ),
            // `m.room.create` is NOT exercised end-to-end here: `redact_event`
            // refuses it outright (see `redact_event_refuses_create_and_
            // encryption_events`); its "keep everything" allow-list branch
            // is covered directly below, against `redact_content_per_v11`.
            (
                "m.room.message",
                r#"{"body":"hi","msgtype":"m.text"}"#,
                serde_json::json!({}),
            ),
        ];

        for (event_type, content, expected) in cases {
            let mut conn = test_conn();
            make_room(&conn);
            insert_timeline_event(&mut conn, "$target", ROOM, 1, event_type, content, 1000).expect("insert target");
            redact_event(&mut conn, ROOM, "$target", "$redaction", 1, None, 2000).expect("redact");

            let target = get_event(&conn, "$target").expect("get target").expect("row exists");
            let got: serde_json::Value = serde_json::from_str(&target.content).expect("parse stripped content");
            assert_eq!(got, expected, "event_type={event_type}");
            assert_eq!(target.redacted_by.as_deref(), Some("$redaction"), "event_type={event_type}");
        }
    }

    #[test]
    fn redaction_content_carries_the_target_as_redacts_for_every_write_path() {
        let mut conn = test_conn();
        make_room(&conn);
        insert_timeline_event(&mut conn, "$t1", ROOM, 1, "m.room.message", "{}", 1000).expect("insert t1");
        insert_timeline_event(&mut conn, "$t2", ROOM, 1, "m.room.message", "{}", 1100).expect("insert t2");
        insert_timeline_event(&mut conn, "$t3", ROOM, 1, "m.room.message", "{}", 1200).expect("insert t3");

        let plain = redact_event(&mut conn, ROOM, "$t1", "$r1", 1, None, 2000).expect("plain redact");
        assert_eq!(serde_json::from_str::<serde_json::Value>(&plain.content).expect("json"), serde_json::json!({ "redacts": "$t1" }));
        assert_eq!(plain.redacts.as_deref(), Some("$t1"));

        let marked = redact_event_marked(
            &mut conn,
            &Redaction { room_id: ROOM, target_event_id: "$t2", redaction_event_id: "$r2", sender_user_id: 1, reason: Some("spam"), origin_server_ts: 2100 },
            &serde_json::json!({ "org.mylittlechart.site_moderation": true }),
        )
            .expect("marked redact");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&marked.content).expect("json"),
            serde_json::json!({ "redacts": "$t2", "reason": "spam", "org.mylittlechart.site_moderation": true })
        );

        let deduped = redact_event_deduped(&mut conn, "DEV1", "txn-1", ROOM, "$t3", "$r3", 1, None, 2200, T0).expect("deduped redact");
        let DedupedWrite::New(event) = deduped else { panic!("first write is new") };
        let stored = get_event(&conn, &event.event_id).expect("get").expect("row exists");
        assert_eq!(serde_json::from_str::<serde_json::Value>(&stored.content).expect("json")["redacts"], "$t3");
    }

    #[test]
    fn redact_content_per_v11_keeps_everything_for_m_room_create() {
        let content = r#"{"room_version":"11","creator":"@a:mylittlechart.org"}"#;
        let stripped = redact_content_per_v11("m.room.create", content).expect("strip");
        let got: serde_json::Value = serde_json::from_str(&stripped).expect("parse");
        assert_eq!(got, serde_json::json!({"room_version": "11", "creator": "@a:mylittlechart.org"}));
    }

    // ---- P1 test 4: txn dedup ----

    #[test]
    fn txn_dedup_returns_the_same_event_id_on_a_repeated_txn_id() {
        let mut conn = test_conn();
        make_room(&conn);

        assert_eq!(txn_dedup_lookup(&conn, 1, "DEV1", "txn-1").expect("lookup 1"), TxnDedupEntry::NotSeen);

        let event = {
            let tx = conn.transaction().expect("tx");
            let row = TimelineEventRow {
                event_id: "$e1",
                room_id: ROOM,
                sender_user_id: 1,
                event_type: "m.room.message",
                content: "{}",
                origin_server_ts: 1000,
                txn_id: Some("txn-1"),
            };
            let event = insert_timeline_event_in_tx(&tx, &row).expect("insert");
            tx.commit().expect("commit");
            event
        };
        txn_dedup_record(&conn, 1, "DEV1", "txn-1", Some(&event.event_id), T0).expect("record");

        assert_eq!(
            txn_dedup_lookup(&conn, 1, "DEV1", "txn-1").expect("lookup 2"),
            TxnDedupEntry::Seen(Some(event.event_id.clone()))
        );

        let count: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0)).expect("count");
        assert_eq!(count, 1, "a repeated txn_id must never create a second events row");
    }

    // ---- P1 test 5: relations survive ciphertext content ----

    #[test]
    fn relations_index_populated_from_cleartext_relates_to_even_when_content_is_ciphertext() {
        let mut conn = test_conn();
        make_room(&conn);
        insert_timeline_event(&mut conn, "$target", ROOM, 1, "m.room.message", "{}", 1000).expect("target");

        let content = r#"{"algorithm":"m.megolm.v1.aes-sha2","ciphertext":"opaque-base64==","sender_key":"opaque","m.relates_to":{"rel_type":"m.annotation","event_id":"$target","key":"a"}}"#;
        let reaction = insert_timeline_event(&mut conn, "$reaction", ROOM, 2, "m.room.encrypted", content, 2000).expect("insert reaction");

        let (rel_type, target_id, agg_key): (String, String, Option<String>) = conn
            .query_row(
                "SELECT rel_type, target_id, agg_key FROM relations WHERE event_id = ?1",
                params![reaction.event_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("relation row exists");
        assert_eq!(rel_type, "m.annotation");
        assert_eq!(target_id, "$target");
        assert_eq!(agg_key.as_deref(), Some("a"));
    }

    // ---- extra test: global account data is unique ----

    #[test]
    fn account_data_global_row_is_unique() {
        let mut conn = test_conn();
        upsert_account_data(&mut conn, 1, GLOBAL_ACCOUNT_DATA_ROOM, "m.direct", r#"{"v":1}"#).expect("first upsert");
        upsert_account_data(&mut conn, 1, GLOBAL_ACCOUNT_DATA_ROOM, "m.direct", r#"{"v":2}"#).expect("second upsert");

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM account_data WHERE user_id = 1 AND room_id = ''",
                [],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(count, 1, "two global upserts of the same type must leave one row");

        let row = get_account_data(&conn, 1, GLOBAL_ACCOUNT_DATA_ROOM, "m.direct").expect("get").expect("row exists");
        assert_eq!(row.content, r#"{"v":2}"#);
    }

    // ---- extra test: receipts never move backwards ----

    #[test]
    fn receipt_never_moves_backwards() {
        let mut conn = test_conn();
        make_room(&conn);
        let e1 = insert_timeline_event(&mut conn, "$e1", ROOM, 1, "m.room.message", "{}", 1000).expect("e1");
        let e2 = insert_timeline_event(&mut conn, "$e2", ROOM, 1, "m.room.message", "{}", 2000).expect("e2");

        upsert_receipt(&mut conn, ROOM, 9, ReceiptType::Read, &e2.event_id, 5000).expect("advance to e2");
        upsert_receipt(&mut conn, ROOM, 9, ReceiptType::Read, &e1.event_id, 6000).expect("attempted backward move is a no-op");

        let receipt = get_receipt(&conn, ROOM, 9, ReceiptType::Read).expect("get").expect("row exists");
        assert_eq!(receipt.event_id, e2.event_id, "a receipt must never move back to an earlier event");
    }

    // ---- P7 tests: notification_count (plan §3.5) ----

    #[test]
    fn receipt_further_ahead_of_the_two_types_wins_for_notification_count() {
        let mut conn = test_conn();
        make_room(&conn);
        let alice = ensure_matrix_user(&conn, 1, "alice00000000000000000000000001", T0).expect("alice");
        apply_state_event(&mut conn, &StateEventWrite { event_id: "$m1", room_id: ROOM, sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join"}"#, origin_server_ts: 900, now: T0 }).expect("alice joins");

        insert_timeline_event(&mut conn, "$e1", ROOM, 2, "m.room.message", "{}", 1000).expect("e1");
        let e2 = insert_timeline_event(&mut conn, "$e2", ROOM, 2, "m.room.message", "{}", 2000).expect("e2");
        insert_timeline_event(&mut conn, "$e3", ROOM, 2, "m.room.message", "{}", 3000).expect("e3");
        let e4 = insert_timeline_event(&mut conn, "$e4", ROOM, 2, "m.room.message", "{}", 4000).expect("e4");
        let e5 = insert_timeline_event(&mut conn, "$e5", ROOM, 2, "m.room.message", "{}", 5000).expect("e5");

        // m.read at e2, m.read.private FURTHER AHEAD at e4 — the private
        // receipt must win even though "private" has nothing to do with
        // ordering: notification_count takes the MAX of the two positions.
        upsert_receipt(&mut conn, ROOM, 1, ReceiptType::Read, &e2.event_id, 2500).expect("read receipt");
        upsert_receipt(&mut conn, ROOM, 1, ReceiptType::ReadPrivate, &e4.event_id, 4500).expect("private receipt further ahead");

        let room = get_room(&conn, ROOM).expect("get room").expect("room exists");
        assert_eq!(notification_count(&conn, &room, 1).expect("count"), 1, "only $e5 is after the further-ahead receipt ($e4)");

        // Reverse: m.read now further ahead than m.read.private — m.read
        // must win this time.
        upsert_receipt(&mut conn, ROOM, 1, ReceiptType::Read, &e5.event_id, 5500).expect("read receipt advances past e5");
        assert_eq!(notification_count(&conn, &room, 1).expect("count"), 0, "m.read now covers every message");
    }

    #[test]
    fn notification_count_ignores_own_state_and_reactions() {
        let mut conn = test_conn();
        make_room(&conn);
        let alice = ensure_matrix_user(&conn, 1, "alice00000000000000000000000001", T0).expect("alice");
        apply_state_event(&mut conn, &StateEventWrite { event_id: "$m1", room_id: ROOM, sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join"}"#, origin_server_ts: 900, now: T0 }).expect("alice joins");

        // Bob's message-like sends — these count.
        insert_timeline_event(&mut conn, "$bob-msg", ROOM, 2, "m.room.message", "{}", 1000).expect("bob message");
        insert_timeline_event(&mut conn, "$bob-enc", ROOM, 2, "m.room.encrypted", "{}", 1100).expect("bob encrypted");
        insert_timeline_event(&mut conn, "$bob-legacy", ROOM, 2, "org.mylittlechart.legacy_dm", "{}", 1200).expect("bob legacy dm");

        // Excluded: alice's own message, a state event, and a reaction.
        insert_timeline_event(&mut conn, "$alice-msg", ROOM, 1, "m.room.message", "{}", 1300).expect("alice's own message");
        apply_state_event(&mut conn, &StateEventWrite { event_id: "$name", room_id: ROOM, sender_user_id: 2, event_type: "m.room.name", state_key: "", content: r#"{"name":"x"}"#, origin_server_ts: 1400, now: T0 }).expect("state event");
        insert_timeline_event(&mut conn, "$reaction", ROOM, 2, "m.reaction", "{}", 1500).expect("reaction");

        let room = get_room(&conn, ROOM).expect("get room").expect("room exists");
        assert_eq!(notification_count(&conn, &room, 1).expect("count"), 3, "only bob's 3 message-like sends count");
    }

    #[test]
    fn notification_count_is_zero_for_a_non_member() {
        let mut conn = test_conn();
        make_room(&conn);
        insert_timeline_event(&mut conn, "$e1", ROOM, 2, "m.room.message", "{}", 1000).expect("e1");

        let room = get_room(&conn, ROOM).expect("get room").expect("room exists");
        assert_eq!(notification_count(&conn, &room, 999).expect("count"), 0, "a caller with no membership row at all sees nothing");
    }

    // ---- extra test: duplicate annotation refused ----

    #[test]
    fn duplicate_annotation_is_refused() {
        let mut conn = test_conn();
        make_room(&conn);
        insert_timeline_event(&mut conn, "$target", ROOM, 1, "m.room.message", "{}", 1000).expect("target");

        let content = r#"{"m.relates_to":{"rel_type":"m.annotation","event_id":"$target","key":"a"}}"#;
        insert_timeline_event(&mut conn, "$react1", ROOM, 5, "m.reaction", content, 2000).expect("first reaction");

        let err = insert_timeline_event(&mut conn, "$react2", ROOM, 5, "m.reaction", content, 3000).unwrap_err();
        assert!(matches!(err, MatrixStoreError::DuplicateAnnotation));

        // The whole transaction must have rolled back — no partial events row.
        assert_eq!(get_event(&conn, "$react2").expect("get"), None);

        // A DIFFERENT sender reacting with the same key is a distinct,
        // accepted annotation (not covered by the refusal).
        let other = insert_timeline_event(&mut conn, "$react3", ROOM, 6, "m.reaction", content, 4000).expect("different sender reacts");
        assert_eq!(other.event_id, "$react3");
    }

    // ---- manager-review fixes (2026-09-24 follow-up) ----

    #[test]
    fn reannotation_after_redaction_is_allowed() {
        let mut conn = test_conn();
        make_room(&conn);
        insert_timeline_event(&mut conn, "$target", ROOM, 1, "m.room.message", "{}", 1000).expect("target");

        let content = r#"{"m.relates_to":{"rel_type":"m.annotation","event_id":"$target","key":"a"}}"#;
        let first = insert_timeline_event(&mut conn, "$react1", ROOM, 5, "m.reaction", content, 2000).expect("first reaction");

        redact_event(&mut conn, ROOM, &first.event_id, "$redaction", 1, None, 2500).expect("redact the reaction");

        // The same sender may now react with the same key again — the
        // redacted prior annotation no longer counts as a duplicate.
        let second = insert_timeline_event(&mut conn, "$react2", ROOM, 5, "m.reaction", content, 3000)
            .expect("re-annotation after redaction must succeed");
        assert_eq!(second.event_id, "$react2");
    }

    #[test]
    fn relation_target_must_exist() {
        let mut conn = test_conn();
        make_room(&conn);

        let content = r#"{"m.relates_to":{"rel_type":"m.annotation","event_id":"$missing","key":"a"}}"#;
        let err = insert_timeline_event(&mut conn, "$react1", ROOM, 5, "m.reaction", content, 2000).unwrap_err();
        assert!(matches!(err, MatrixStoreError::InvalidRelationTarget(ref id) if id == "$missing"));
    }

    #[test]
    fn relation_target_must_be_in_the_same_room() {
        let mut conn = test_conn();
        make_room(&conn);
        let other_room = format!("!other:{MATRIX_SERVER_NAME}");
        create_room(&conn, &other_room, RoomKind::Group, 1, T0, false, JoinRule::Invite, HistoryVisibility::Shared, None, None)
            .expect("other room");
        insert_timeline_event(&mut conn, "$target", &other_room, 1, "m.room.message", "{}", 1000).expect("target in other room");

        let content = r#"{"m.relates_to":{"rel_type":"m.annotation","event_id":"$target","key":"a"}}"#;
        let err = insert_timeline_event(&mut conn, "$react1", ROOM, 5, "m.reaction", content, 2000).unwrap_err();
        assert!(matches!(err, MatrixStoreError::InvalidRelationTarget(ref id) if id == "$target"));
    }

    #[test]
    fn redact_event_refuses_a_target_in_a_different_room() {
        let mut conn = test_conn();
        make_room(&conn);
        let other_room = format!("!other:{MATRIX_SERVER_NAME}");
        create_room(&conn, &other_room, RoomKind::Group, 1, T0, false, JoinRule::Invite, HistoryVisibility::Shared, None, None)
            .expect("other room");
        insert_timeline_event(&mut conn, "$target", &other_room, 1, "m.room.message", "{}", 1000).expect("target in other room");

        let err = redact_event(&mut conn, ROOM, "$target", "$redaction", 1, None, 2000).unwrap_err();
        assert!(matches!(err, MatrixStoreError::WrongRoom(ref id) if id == "$target"));
    }

    #[test]
    fn redact_event_refuses_create_and_encryption_events() {
        for event_type in ["m.room.create", "m.room.encryption"] {
            let mut conn = test_conn();
            make_room(&conn);
            apply_state_event(&mut conn, &StateEventWrite { event_id: "$target", room_id: ROOM, sender_user_id: 1, event_type, state_key: "", content: r#"{"a":1}"#, origin_server_ts: 1000, now: T0 }).expect("apply state event");

            let err = redact_event(&mut conn, ROOM, "$target", "$redaction", 1, None, 2000).unwrap_err();
            assert!(
                matches!(err, MatrixStoreError::UnredactableEvent(ref t) if t == event_type),
                "event_type={event_type}"
            );
        }
    }

    #[test]
    fn upsert_receipt_refuses_a_target_in_a_different_room() {
        let mut conn = test_conn();
        make_room(&conn);
        let other_room = format!("!other:{MATRIX_SERVER_NAME}");
        create_room(&conn, &other_room, RoomKind::Group, 1, T0, false, JoinRule::Invite, HistoryVisibility::Shared, None, None)
            .expect("other room");
        let event = insert_timeline_event(&mut conn, "$e1", &other_room, 1, "m.room.message", "{}", 1000).expect("event in other room");

        let err = upsert_receipt(&mut conn, ROOM, 9, ReceiptType::Read, &event.event_id, 5000).unwrap_err();
        assert!(matches!(err, MatrixStoreError::WrongRoom(ref id) if id == &event.event_id));
    }

    // ---- extra test: mxid parsing refuses a foreign server ----

    #[test]
    fn mxid_parse_refuses_foreign_server() {
        assert_eq!(public_id_from_mxid("@abc123:mylittlechart.org"), Ok("abc123"));
        assert_eq!(public_id_from_mxid("@abc123:otherserver.example"), Err(MatrixIdError::ForeignServerName));
        assert_eq!(public_id_from_mxid("abc123:mylittlechart.org"), Err(MatrixIdError::MissingSigil));
        assert_eq!(public_id_from_mxid("@abc123"), Err(MatrixIdError::MissingServerName));
    }

    // ---- supporting coverage for the CRUD surface the tests above don't already exercise ----

    #[test]
    fn ensure_matrix_user_is_idempotent_and_refuses_a_reserved_localpart() {
        let conn = test_conn();
        let mxid = ensure_matrix_user(&conn, 1, "abc123", T0).expect("first ensure");
        assert_eq!(mxid, "@abc123:mylittlechart.org");
        let mxid_again = ensure_matrix_user(&conn, 1, "abc123", T0).expect("second ensure is a no-op");
        assert_eq!(mxid_again, mxid);
        assert_eq!(mxid_of(&conn, 1).expect("mxid_of"), Some(mxid.clone()));
        assert_eq!(user_id_of(&conn, &mxid).expect("user_id_of"), Some(1));

        let err = ensure_matrix_user(&conn, 2, "_bridge_evil", T0).unwrap_err();
        assert!(matches!(err, MatrixStoreError::ReservedLocalpart));
    }

    #[test]
    fn apply_state_event_member_refreshes_room_members_and_power_levels() {
        let mut conn = test_conn();
        make_room(&conn);
        let alice = ensure_matrix_user(&conn, 1, "alice00000000000000000000000001", T0).expect("alice");
        let bob = ensure_matrix_user(&conn, 2, "bob000000000000000000000000002", T0).expect("bob");

        apply_state_event(&mut conn, &StateEventWrite { event_id: "$m1", room_id: ROOM, sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join"}"#, origin_server_ts: 1000, now: T0 }).expect("alice joins");
        apply_state_event(&mut conn, &StateEventWrite { event_id: "$m2", room_id: ROOM, sender_user_id: 1, event_type: "m.room.member", state_key: &bob, content: r#"{"membership":"invite"}"#, origin_server_ts: 1100, now: T0 }).expect("bob invited");

        let joined = room_members(&conn, ROOM, Some(Membership::Join)).expect("joined members");
        assert_eq!(joined.len(), 1);
        assert_eq!(joined[0].user_id, 1);
        assert_eq!(joined[0].power_level, None);

        let power_levels_content = serde_json::json!({"users": {alice.clone(): 100}, "users_default": 0}).to_string();
        apply_state_event(&mut conn, &StateEventWrite { event_id: "$pl1", room_id: ROOM, sender_user_id: 1, event_type: "m.room.power_levels", state_key: "", content: &power_levels_content, origin_server_ts: 1200, now: T0 }).expect("power levels");

        let alice_row = room_members(&conn, ROOM, None)
            .expect("all members")
            .into_iter()
            .find(|m| m.user_id == 1)
            .expect("alice row");
        assert_eq!(alice_row.power_level, Some(100));

        let bob_rooms = rooms_for_user(&conn, 2, Some(Membership::Invite)).expect("bob's invited rooms");
        assert_eq!(bob_rooms, vec![ROOM.to_string()]);
    }

    #[test]
    fn events_in_room_after_and_before_page_in_the_documented_order() {
        let mut conn = test_conn();
        make_room(&conn);
        let e1 = insert_timeline_event(&mut conn, "$e1", ROOM, 1, "m.room.message", "{}", 1000).expect("e1");
        let e2 = insert_timeline_event(&mut conn, "$e2", ROOM, 1, "m.room.message", "{}", 2000).expect("e2");
        let e3 = insert_timeline_event(&mut conn, "$e3", ROOM, 1, "m.room.message", "{}", 3000).expect("e3");

        let after = events_in_room_after(&conn, ROOM, e1.stream_id, 10).expect("after");
        assert_eq!(after.iter().map(|e| e.event_id.clone()).collect::<Vec<_>>(), vec![e2.event_id.clone(), e3.event_id.clone()]);

        let before = events_in_room_before(&conn, ROOM, e3.stream_id, 10).expect("before");
        assert_eq!(before.iter().map(|e| e.event_id.clone()).collect::<Vec<_>>(), vec![e2.event_id.clone(), e1.event_id.clone()]);

        assert_eq!(max_stream_id(&conn).expect("max"), e3.stream_id);
    }

    #[test]
    fn txn_dedup_lookup_of_a_to_device_send_has_no_event_id() {
        let conn = test_conn();
        assert_eq!(txn_dedup_lookup(&conn, 1, "DEV1", "txn-td").expect("lookup"), TxnDedupEntry::NotSeen);
        txn_dedup_record(&conn, 1, "DEV1", "txn-td", None, T0).expect("record to-device send");
        assert_eq!(txn_dedup_lookup(&conn, 1, "DEV1", "txn-td").expect("lookup again"), TxnDedupEntry::Seen(None));
    }

    #[test]
    fn filters_create_and_get_are_scoped_to_their_owner() {
        let conn = test_conn();
        let filter_id = create_filter(&conn, 1, r#"{"room":{"timeline":{"limit":20}}}"#).expect("create");
        assert_eq!(get_filter(&conn, 1, filter_id).expect("owner reads it"), Some(r#"{"room":{"timeline":{"limit":20}}}"#.to_string()));
        assert_eq!(get_filter(&conn, 2, filter_id).expect("a different user cannot"), None);
    }

    #[test]
    fn legacy_dm_message_map_insert_and_get_round_trip() {
        let mut conn = test_conn();
        make_room(&conn);
        let event = insert_timeline_event(&mut conn, "$legacy1", ROOM, 1, "org.mylittlechart.legacy_dm", "{}", 1000).expect("insert");
        insert_legacy_dm_message_map(&conn, 42, &event.event_id).expect("map insert");
        assert_eq!(legacy_dm_message_event_id(&conn, 42).expect("map get"), Some(event.event_id));
        assert_eq!(legacy_dm_message_event_id(&conn, 999).expect("missing"), None);
    }

    // ---- P4 test: power-level defaults ----

    #[test]
    fn power_level_defaults_apply_when_fields_missing() {
        let pl = serde_json::json!({});
        assert_eq!(user_level(&pl, "@nobody:mylittlechart.org"), 0, "users_default defaults to 0");
        assert_eq!(event_level(&pl, "m.room.message", false), 0, "events_default defaults to 0");
        assert_eq!(event_level(&pl, "m.room.name", true), 50, "state_default defaults to 50");
        for action in [PowerAction::Invite, PowerAction::Kick, PowerAction::Ban, PowerAction::Redact, PowerAction::StateDefault] {
            assert!(!can(&pl, action, "@nobody:mylittlechart.org"), "level 0 must not reach the default 50 threshold for {action:?}");
        }

        let pl_with_creator = serde_json::json!({ "users": { "@creator:mylittlechart.org": 100 } });
        assert!(can(&pl_with_creator, PowerAction::Ban, "@creator:mylittlechart.org"));
        assert!(can(&pl_with_creator, PowerAction::StateDefault, "@creator:mylittlechart.org"));
    }

    #[test]
    fn event_level_uses_the_events_type_override_before_falling_back_to_a_default() {
        let pl = serde_json::json!({ "events": { "m.room.name": 60 }, "events_default": 0, "state_default": 50 });
        assert_eq!(event_level(&pl, "m.room.name", true), 60, "an explicit events[type] override wins");
        assert_eq!(event_level(&pl, "m.room.topic", true), 50, "an unlisted state type falls back to state_default");
        assert_eq!(event_level(&pl, "m.room.message", false), 0, "an unlisted timeline type falls back to events_default");
    }

    // ---- manager review 2026-09-24: can_act_on / validate_power_levels_change ----

    #[test]
    fn can_act_on_requires_strictly_greater_level_except_self_leave() {
        let pl = serde_json::json!({
            "users": { "@owner:mylittlechart.org": 100, "@admin:mylittlechart.org": 50, "@peer:mylittlechart.org": 50 },
            "kick": 50,
            "ban": 50,
        });

        // A level-50 admin reaches the flat kick threshold (50) but must
        // NOT be able to kick the level-100 owner.
        assert!(!can_act_on(&pl, PowerAction::Kick, "@admin:mylittlechart.org", "@owner:mylittlechart.org", false));
        // Nor an equal-level peer.
        assert!(!can_act_on(&pl, PowerAction::Kick, "@admin:mylittlechart.org", "@peer:mylittlechart.org", false));
        // The owner CAN kick the admin (100 > 50).
        assert!(can_act_on(&pl, PowerAction::Kick, "@owner:mylittlechart.org", "@admin:mylittlechart.org", false));
        // A member may always leave (reject an invite / self-kick) regardless
        // of level, when self_leave is set and sender == target.
        assert!(can_act_on(&pl, PowerAction::Kick, "@admin:mylittlechart.org", "@admin:mylittlechart.org", true));
        // ...but NOT when the action does not actually result in a leave.
        assert!(!can_act_on(&pl, PowerAction::Ban, "@admin:mylittlechart.org", "@admin:mylittlechart.org", false));
    }

    #[test]
    fn validate_power_levels_change_refuses_raising_self_above_own_level() {
        let old = serde_json::json!({ "users": { "@admin:mylittlechart.org": 50 } });
        let new = serde_json::json!({ "users": { "@admin:mylittlechart.org": 100 } });
        assert!(validate_power_levels_change(&old, &new, "@admin:mylittlechart.org").is_err());
    }

    #[test]
    fn validate_power_levels_change_refuses_demoting_a_peer_at_an_equal_level() {
        let old = serde_json::json!({ "users": { "@a:mylittlechart.org": 50, "@b:mylittlechart.org": 50 } });
        let new = serde_json::json!({ "users": { "@a:mylittlechart.org": 50, "@b:mylittlechart.org": 0 } });
        assert!(validate_power_levels_change(&old, &new, "@a:mylittlechart.org").is_err());
    }

    #[test]
    fn validate_power_levels_change_allows_demoting_self() {
        let old = serde_json::json!({ "users": { "@admin:mylittlechart.org": 50 } });
        let new = serde_json::json!({ "users": { "@admin:mylittlechart.org": 10 } });
        assert!(validate_power_levels_change(&old, &new, "@admin:mylittlechart.org").is_ok());
    }

    #[test]
    fn validate_power_levels_change_refuses_raising_events_default_above_own_level() {
        let old = serde_json::json!({ "users": { "@admin:mylittlechart.org": 50 }, "events_default": 0 });
        let new = serde_json::json!({ "users": { "@admin:mylittlechart.org": 50 }, "events_default": 60 });
        assert!(validate_power_levels_change(&old, &new, "@admin:mylittlechart.org").is_err());
    }

    #[test]
    fn validate_power_levels_change_allows_the_owner_changing_anything_up_to_their_own_level() {
        let old = serde_json::json!({ "users": { "@owner:mylittlechart.org": 100, "@a:mylittlechart.org": 50 } });
        let new = serde_json::json!({
            "users": { "@owner:mylittlechart.org": 100, "@a:mylittlechart.org": 90 },
            "ban": 100,
            "kick": 100,
            "events_default": 100,
        });
        assert!(validate_power_levels_change(&old, &new, "@owner:mylittlechart.org").is_ok());
    }

    #[test]
    fn validate_power_levels_change_refuses_a_scalar_field_change_above_own_level() {
        let old = serde_json::json!({ "users": { "@admin:mylittlechart.org": 50 }, "ban": 50 });
        let new = serde_json::json!({ "users": { "@admin:mylittlechart.org": 50 }, "ban": 75 });
        assert!(validate_power_levels_change(&old, &new, "@admin:mylittlechart.org").is_err());
    }

    #[test]
    fn validate_power_levels_change_ignores_unchanged_fields() {
        let old = serde_json::json!({ "users": { "@admin:mylittlechart.org": 50 }, "ban": 50, "events": { "m.room.name": 40 } });
        let new = old.clone();
        assert!(validate_power_levels_change(&old, &new, "@admin:mylittlechart.org").is_ok());
    }

    // ---- P5 test: create_room_with_state is one transaction ----

    fn bootstrap<'a>(room_id: &'a str, kind: RoomKind, creator: i64) -> RoomBootstrap<'a> {
        RoomBootstrap {
            room_id,
            kind,
            creator_user_id: creator,
            created_at: T0,
            is_encrypted: kind != RoomKind::Channel,
            join_rule: if kind == RoomKind::Channel { JoinRule::Public } else { JoinRule::Invite },
            history_visibility: HistoryVisibility::Shared,
            dm_pair_key: None,
            legacy_dm_id: None,
        }
    }

    fn state_event(event_id: &str, sender: i64, event_type: &str, state_key: &str, content: &str) -> NewStateEvent {
        NewStateEvent {
            event_id: event_id.to_string(),
            sender_user_id: sender,
            event_type: event_type.to_string(),
            state_key: state_key.to_string(),
            content: content.to_string(),
        }
    }

    #[test]
    fn create_room_with_state_inserts_the_room_and_every_bootstrap_event_atomically() {
        let mut conn = test_conn();
        let creator_mxid = ensure_matrix_user(&conn, 1, "creator0000000000000000000001", T0).expect("creator");
        let room_id = "!batch:mylittlechart.org";

        let events = vec![
            state_event("$create", 1, "m.room.create", "", r#"{"room_version":"11"}"#),
            state_event("$m1", 1, "m.room.member", &creator_mxid, r#"{"membership":"join"}"#),
            state_event(
                "$pl",
                1,
                "m.room.power_levels",
                "",
                &serde_json::json!({"users": {creator_mxid.clone(): 100}, "users_default": 0}).to_string(),
            ),
        ];

        let (room, applied) = create_room_with_state(&mut conn, bootstrap(room_id, RoomKind::Group, 1), &events, 1000).expect("create batch");
        assert_eq!(room.id, room_id);
        assert_eq!(applied.len(), 3);
        assert!(get_room(&conn, room_id).expect("get room").is_some());
        for event in &applied {
            assert!(get_event(&conn, &event.event_id).expect("get event").is_some());
        }
        let creator_row = room_member(&conn, room_id, 1).expect("member row").expect("row exists");
        assert_eq!(creator_row.power_level, Some(100), "power_levels applied after the member row existed");
    }

    #[test]
    fn create_room_is_atomic_on_failure() {
        let mut conn = test_conn();
        let creator_mxid = ensure_matrix_user(&conn, 1, "creator0000000000000000000002", T0).expect("creator");
        let room_id = "!atomic:mylittlechart.org";

        let events = vec![
            state_event("$create", 1, "m.room.create", "", r#"{"room_version":"11"}"#),
            state_event("$m1", 1, "m.room.member", &creator_mxid, r#"{"membership":"join"}"#),
            // Never `ensure_matrix_user`'d — `refresh_room_member` must
            // refuse this with `UnknownMxid`, rolling back the WHOLE batch.
            state_event("$bad", 1, "m.room.member", "@ghost:mylittlechart.org", r#"{"membership":"invite"}"#),
        ];

        let err = create_room_with_state(&mut conn, bootstrap(room_id, RoomKind::Group, 1), &events, 1000).unwrap_err();
        assert!(matches!(err, MatrixStoreError::UnknownMxid(ref m) if m == "@ghost:mylittlechart.org"));

        assert_eq!(get_room(&conn, room_id).expect("get room"), None, "a failed batch must leave no room row");
        assert_eq!(get_event(&conn, "$create").expect("get"), None, "a failed batch must leave no event rows at all");
        assert_eq!(get_event(&conn, "$m1").expect("get"), None);
    }

    // ---- P5 test: DM pair-key reuse frees a dead pair's slot ----

    #[test]
    fn dm_pair_key_reuse_is_freed_once_the_room_is_not_reused() {
        let conn = test_conn();
        create_room(&conn, "!dm1:mylittlechart.org", RoomKind::Dm, 1, T0, true, JoinRule::Invite, HistoryVisibility::Shared, Some("1:2"), None)
            .expect("first dm room");
        assert_eq!(room_by_dm_pair_key(&conn, "1:2").expect("lookup").map(|r| r.id), Some("!dm1:mylittlechart.org".to_string()));

        clear_dm_pair_key(&conn, "!dm1:mylittlechart.org").expect("clear");
        assert_eq!(room_by_dm_pair_key(&conn, "1:2").expect("lookup after clear"), None);

        // The freed pair key can now be claimed by a second room.
        create_room(&conn, "!dm2:mylittlechart.org", RoomKind::Dm, 1, T0, true, JoinRule::Invite, HistoryVisibility::Shared, Some("1:2"), None)
            .expect("second dm room reuses the freed pair key");
        assert_eq!(room_by_dm_pair_key(&conn, "1:2").expect("lookup").map(|r| r.id), Some("!dm2:mylittlechart.org".to_string()));
    }

    // ---- P5 test: room_member / forget_membership ----

    #[test]
    fn room_member_finds_the_one_row_forget_membership_deletes_only_when_left() {
        let mut conn = test_conn();
        make_room(&conn);
        let alice = ensure_matrix_user(&conn, 1, "alice00000000000000000000000099", T0).expect("alice");
        apply_state_event(&mut conn, &StateEventWrite { event_id: "$m1", room_id: ROOM, sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join"}"#, origin_server_ts: 1000, now: T0 }).expect("join");

        assert_eq!(room_member(&conn, ROOM, 1).expect("member").map(|m| m.membership), Some(Membership::Join));
        assert_eq!(room_member(&conn, ROOM, 999).expect("no such member"), None);

        // Still joined — forget must refuse (0 rows deleted), matching the
        // route-layer gate "Member with membership='leave'".
        assert_eq!(forget_membership(&conn, ROOM, 1).expect("forget while joined"), 0);
        assert!(room_member(&conn, ROOM, 1).expect("still a member").is_some());

        apply_state_event(&mut conn, &StateEventWrite { event_id: "$m2", room_id: ROOM, sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"leave"}"#, origin_server_ts: 2000, now: T0 }).expect("leave");
        assert_eq!(forget_membership(&conn, ROOM, 1).expect("forget after leaving"), 1);
        assert_eq!(room_member(&conn, ROOM, 1).expect("gone"), None);
    }

    // ---- P5 test: state_events_of_type_at reconstructs a point-in-time projection ----

    #[test]
    fn state_events_of_type_at_excludes_state_keys_created_after_the_cutoff() {
        let mut conn = test_conn();
        make_room(&conn);
        let alice = ensure_matrix_user(&conn, 1, "alice00000000000000000000000098", T0).expect("alice");
        let bob = ensure_matrix_user(&conn, 2, "bob0000000000000000000000000098", T0).expect("bob");

        let e1 = apply_state_event(&mut conn, &StateEventWrite { event_id: "$m1", room_id: ROOM, sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join"}"#, origin_server_ts: 1000, now: T0 }).expect("alice joins");
        let cutoff = e1.stream_id;
        apply_state_event(&mut conn, &StateEventWrite { event_id: "$m2", room_id: ROOM, sender_user_id: 1, event_type: "m.room.member", state_key: &bob, content: r#"{"membership":"invite"}"#, origin_server_ts: 1100, now: T0 }).expect("bob invited later");

        let at_cutoff = state_events_of_type_at(&conn, ROOM, "m.room.member", cutoff).expect("at cutoff");
        assert_eq!(at_cutoff.len(), 1, "bob's invite lands strictly after the cutoff and must be excluded");
        assert_eq!(at_cutoff[0].event_id, "$m1");

        let after_both = state_events_of_type_at(&conn, ROOM, "m.room.member", cutoff + 1).expect("after both");
        assert_eq!(after_both.len(), 2);
    }

    // ---- P5 test: stripped_invite_state ----

    #[test]
    fn stripped_invite_state_includes_room_basics_and_the_inviters_own_member_event() {
        let mut conn = test_conn();
        make_room(&conn);
        let alice = ensure_matrix_user(&conn, 1, "alice00000000000000000000000097", T0).expect("alice");
        let bob = ensure_matrix_user(&conn, 2, "bob0000000000000000000000000097", T0).expect("bob");

        apply_state_event(&mut conn, &StateEventWrite { event_id: "$create", room_id: ROOM, sender_user_id: 1, event_type: "m.room.create", state_key: "", content: r#"{"room_version":"11"}"#, origin_server_ts: 900, now: T0 }).expect("create");
        apply_state_event(&mut conn, &StateEventWrite { event_id: "$m1", room_id: ROOM, sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join"}"#, origin_server_ts: 1000, now: T0 }).expect("alice joins");
        apply_state_event(&mut conn, &StateEventWrite { event_id: "$jr", room_id: ROOM, sender_user_id: 1, event_type: "m.room.join_rules", state_key: "", content: r#"{"join_rule":"invite"}"#, origin_server_ts: 1100, now: T0 }).expect("join rules");
        apply_state_event(&mut conn, &StateEventWrite { event_id: "$m2", room_id: ROOM, sender_user_id: 1, event_type: "m.room.member", state_key: &bob, content: r#"{"membership":"invite"}"#, origin_server_ts: 1200, now: T0 }).expect("bob invited");

        let stripped = stripped_invite_state(&conn, ROOM, 1).expect("stripped state");
        let types: Vec<&str> = stripped.iter().map(|v| v["type"].as_str().expect("type")).collect();
        assert!(types.contains(&"m.room.create"));
        assert!(types.contains(&"m.room.join_rules"));
        assert!(!types.contains(&"m.room.encryption"), "no encryption event exists in this room");

        let inviter_member = stripped
            .iter()
            .find(|v| v["type"] == "m.room.member" && v["state_key"] == alice)
            .expect("the inviter's own member event is included");
        assert_eq!(inviter_member["sender"], alice);
        assert_eq!(inviter_member["content"]["membership"], "join");
    }

    // ---- P9 support: user_ids_with_leave_transition_in_rooms ----

    #[test]
    fn user_ids_with_leave_transition_in_rooms_finds_only_leave_and_ban_inside_the_window() {
        let mut conn = test_conn();
        make_room(&conn);
        let alice = ensure_matrix_user(&conn, 2, "alice00000000000000000000000097", T0).expect("alice");
        let bob = ensure_matrix_user(&conn, 3, "bob0000000000000000000000000097", T0).expect("bob");
        let carol = ensure_matrix_user(&conn, 4, "carol0000000000000000000000097a", T0).expect("carol");

        apply_state_event(&mut conn, &StateEventWrite { event_id: "$a1", room_id: ROOM, sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join"}"#, origin_server_ts: 1000, now: T0 }).expect("alice joins");
        let boundary = apply_state_event(&mut conn, &StateEventWrite { event_id: "$b1", room_id: ROOM, sender_user_id: 1, event_type: "m.room.member", state_key: &bob, content: r#"{"membership":"join"}"#, origin_server_ts: 1100, now: T0 })
            .expect("bob joins")
            .stream_id;
        apply_state_event(&mut conn, &StateEventWrite { event_id: "$a2", room_id: ROOM, sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"leave"}"#, origin_server_ts: 1200, now: T0 }).expect("alice leaves");
        apply_state_event(&mut conn, &StateEventWrite { event_id: "$b2", room_id: ROOM, sender_user_id: 1, event_type: "m.room.member", state_key: &bob, content: r#"{"membership":"ban"}"#, origin_server_ts: 1300, now: T0 }).expect("bob banned");
        apply_state_event(&mut conn, &StateEventWrite { event_id: "$c1", room_id: ROOM, sender_user_id: 1, event_type: "m.room.member", state_key: &carol, content: r#"{"membership":"join"}"#, origin_server_ts: 1400, now: T0 }).expect("carol joins (not a departure)");

        let mut left = user_ids_with_leave_transition_in_rooms(&conn, &[ROOM.to_string()], boundary, i64::MAX).expect("query");
        left.sort_unstable();
        assert_eq!(left, vec![2, 3], "alice (leave) and bob (ban) both count; carol's join does not");

        let empty = user_ids_with_leave_transition_in_rooms(&conn, &[], 0, i64::MAX).expect("empty room set");
        assert!(empty.is_empty());
    }

    // ---- P16 S-f: point-in-time membership and the window's member candidates ----

    #[test]
    fn membership_at_reads_the_state_as_of_a_stream_position() {
        let mut conn = test_conn();
        make_room(&conn);
        let alice = ensure_matrix_user(&conn, 2, "alice00000000000000000000000081", T0).expect("alice");
        let bob = ensure_matrix_user(&conn, 3, "bob0000000000000000000000000081", T0).expect("bob");

        let alice_joined = apply_state_event(&mut conn, &StateEventWrite { event_id: "$a1", room_id: ROOM, sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join"}"#, origin_server_ts: 1000, now: T0 }).expect("alice joins").stream_id;
        let bob_invited = apply_state_event(&mut conn, &StateEventWrite { event_id: "$b1", room_id: ROOM, sender_user_id: 1, event_type: "m.room.member", state_key: &bob, content: r#"{"membership":"invite"}"#, origin_server_ts: 1100, now: T0 }).expect("bob invited").stream_id;
        let bob_joined = apply_state_event(&mut conn, &StateEventWrite { event_id: "$b2", room_id: ROOM, sender_user_id: 3, event_type: "m.room.member", state_key: &bob, content: r#"{"membership":"join","displayname":"Bob"}"#, origin_server_ts: 1200, now: T0 }).expect("bob joins").stream_id;

        assert_eq!(membership_at(&conn, ROOM, &bob, alice_joined).expect("query"), None, "bob had no member event yet");
        assert_eq!(membership_at(&conn, ROOM, &bob, bob_invited).expect("query"), Some(Membership::Invite));
        assert_eq!(membership_at(&conn, ROOM, &bob, bob_joined).expect("query"), Some(Membership::Join));
        assert_eq!(membership_at(&conn, ROOM, &alice, bob_invited).expect("query"), Some(Membership::Join));

        let mut window = member_state_keys_in_window(&conn, ROOM, bob_invited, bob_joined).expect("window");
        window.sort();
        assert_eq!(window, vec![bob.clone()], "only bob has a member event after `bob_invited`");
        let mut all = member_state_keys_in_window(&conn, ROOM, 0, bob_joined).expect("whole history");
        all.sort();
        let mut expected = vec![alice, bob];
        expected.sort();
        assert_eq!(all, expected);

        let rooms = [ROOM.to_string(), "!other:mylittlechart.org".to_string()];
        assert_eq!(rooms_with_member_events_in_window(&conn, &rooms, bob_invited, bob_joined).expect("rooms"), vec![ROOM.to_string()]);
        assert!(rooms_with_member_events_in_window(&conn, &rooms, bob_joined, i64::MAX).expect("rooms after the last member event").is_empty());
        assert!(rooms_with_member_events_in_window(&conn, &[], 0, i64::MAX).expect("empty room set").is_empty());
    }

    // ---- a changed label is re-stamped into the user's member events ----

    const ROOM_A: &str = "!roomA:mylittlechart.org";
    const ROOM_B: &str = "!roomB:mylittlechart.org";
    const ROOM_C: &str = "!roomC:mylittlechart.org";

    fn make_room_with_kind(conn: &Connection, room_id: &str, kind: RoomKind) {
        create_room(conn, room_id, kind, 1, T0, false, JoinRule::Invite, HistoryVisibility::Shared, None, None).expect("create room");
    }

    fn member_content_in(conn: &Connection, room_id: &str, mxid: &str) -> serde_json::Value {
        let event = current_state_event(conn, room_id, "m.room.member", mxid).expect("query").expect("member event exists");
        serde_json::from_str(&event.content).expect("member content is json")
    }

    fn member_event_count(conn: &Connection, room_id: &str, mxid: &str) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM events WHERE room_id = ?1 AND event_type = 'm.room.member' AND state_key = ?2",
            params![room_id, mxid],
            |row| row.get(0),
        )
        .expect("count member events")
    }

    #[test]
    fn refresh_member_displayname_restamps_every_joined_room_and_skips_a_room_the_user_left() {
        let mut conn = test_conn();
        let alice = ensure_matrix_user(&conn, 1, "alice00000000000000000000000091", T0).expect("alice");
        let bob = ensure_matrix_user(&conn, 2, "bob0000000000000000000000000091", T0).expect("bob");
        for room in [ROOM_A, ROOM_B, ROOM_C] {
            make_room_with_kind(&conn, room, RoomKind::Group);
            apply_state_event(&mut conn, &StateEventWrite { event_id: &new_event_id(), room_id: room, sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join","displayname":"old_alice"}"#, origin_server_ts: 1000, now: T0 })
                .expect("alice joins");
            apply_state_event(&mut conn, &StateEventWrite { event_id: &new_event_id(), room_id: room, sender_user_id: 2, event_type: "m.room.member", state_key: &bob, content: r#"{"membership":"join","displayname":"bob_nick"}"#, origin_server_ts: 1100, now: T0 })
                .expect("bob joins");
        }
        apply_state_event(&mut conn, &StateEventWrite { event_id: &new_event_id(), room_id: ROOM_C, sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"leave"}"#, origin_server_ts: 1200, now: T0 }).expect("alice leaves C");

        let refresh = refresh_member_displayname(&mut conn, 1, "new_alice", T0, 5000).expect("refresh");

        assert_eq!(refresh.rooms_updated, 2, "the two rooms alice is still joined in");
        for room in [ROOM_A, ROOM_B] {
            let content = member_content_in(&conn, room, &alice);
            assert_eq!(content["membership"], "join");
            assert_eq!(content["displayname"], "new_alice");
            assert_eq!(member_event_count(&conn, room, &alice), 2, "a NEW member event lands; the old one stays in history");
            let event = current_state_event(&conn, room, "m.room.member", &alice).expect("query").expect("exists");
            assert_eq!(event.sender_user_id, 1, "a join refresh is sent by the user themself");
            assert_eq!(event.origin_server_ts, 5000);
            assert_eq!(member_content_in(&conn, room, &bob)["displayname"], "bob_nick", "another member's event is never touched");
        }
        assert_eq!(member_content_in(&conn, ROOM_C, &alice), serde_json::json!({ "membership": "leave" }), "the left room gets no new event");
        assert_eq!(member_event_count(&conn, ROOM_C, &alice), 2, "join + leave, nothing more");
        assert_eq!(refresh.affected_user_ids, HashSet::from([1, 2]), "alice and bob are woken; room C's members are not part of it");

        let repeat = refresh_member_displayname(&mut conn, 1, "new_alice", T0, 6000).expect("second pass");
        assert_eq!(repeat, DisplaynameRefresh::default(), "an up-to-date event is skipped, so a repeat pass writes nothing");
        assert_eq!(member_event_count(&conn, ROOM_A, &alice), 2);
    }

    #[test]
    fn refresh_member_displayname_keeps_an_invite_events_sender_and_is_direct() {
        let mut conn = test_conn();
        let alice = ensure_matrix_user(&conn, 1, "alice00000000000000000000000092", T0).expect("alice");
        let bob = ensure_matrix_user(&conn, 2, "bob0000000000000000000000000092", T0).expect("bob");
        make_room_with_kind(&conn, ROOM_A, RoomKind::Dm);
        apply_state_event(&mut conn, &StateEventWrite { event_id: &new_event_id(), room_id: ROOM_A, sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join","displayname":"alice_nick"}"#, origin_server_ts: 1000, now: T0 })
            .expect("alice joins");
        apply_state_event(
            &mut conn,
            &StateEventWrite {
                event_id: &new_event_id(),
                room_id: ROOM_A,
                sender_user_id: 1,
                event_type: "m.room.member",
                state_key: &bob,
                content: r#"{"membership":"invite","is_direct":true}"#,
                origin_server_ts: 1100,
                now: T0,
            },
        )
        .expect("alice invites bob");

        let refresh = refresh_member_displayname(&mut conn, 2, "bob_nick", T0, 5000).expect("refresh");

        assert_eq!(refresh.rooms_updated, 1);
        let content = member_content_in(&conn, ROOM_A, &bob);
        assert_eq!(content, serde_json::json!({ "membership": "invite", "is_direct": true, "displayname": "bob_nick" }));
        let event = current_state_event(&conn, ROOM_A, "m.room.member", &bob).expect("query").expect("exists");
        assert_eq!(event.sender_user_id, 1, "the inviter stays the sender: stripped invite state reads the inviter off it");
        assert_eq!(room_member(&conn, ROOM_A, 2).expect("query").expect("row").membership, Membership::Invite, "still an invitation");
        assert_eq!(refresh.affected_user_ids, HashSet::from([1, 2]));
    }

    #[test]
    fn refresh_member_displayname_is_a_noop_without_a_matrix_user_or_a_label() {
        let mut conn = test_conn();
        let alice = ensure_matrix_user(&conn, 1, "alice00000000000000000000000093", T0).expect("alice");
        make_room_with_kind(&conn, ROOM_A, RoomKind::Group);
        apply_state_event(&mut conn, &StateEventWrite { event_id: &new_event_id(), room_id: ROOM_A, sender_user_id: 1, event_type: "m.room.member", state_key: &alice, content: r#"{"membership":"join"}"#, origin_server_ts: 1000, now: T0 }).expect("alice joins");

        assert_eq!(refresh_member_displayname(&mut conn, 99, "ghost", T0, 5000).expect("unknown user"), DisplaynameRefresh::default());
        assert_eq!(refresh_member_displayname(&mut conn, 1, "", T0, 5000).expect("empty label"), DisplaynameRefresh::default());
        assert_eq!(member_event_count(&conn, ROOM_A, &alice), 1);
        assert_eq!(matrix_user_ids(&conn).expect("ids"), vec![1]);
    }

    // ---- P16 S-d: adopting a native DM room for a legacy conversation ----

    fn native_dm_room(conn: &Connection) {
        create_room(conn, ROOM, RoomKind::Dm, 1, T0, true, JoinRule::Invite, HistoryVisibility::Shared, Some("1:2"), None).expect("create dm room");
    }

    fn legacy_import(legacy_message_id: i64, event_id: &str) -> LegacyDmMessageImport {
        LegacyDmMessageImport {
            legacy_message_id,
            event_id: event_id.to_string(),
            sender_user_id: 1,
            content: "{}".to_string(),
            origin_server_ts: 1000 + legacy_message_id,
        }
    }

    fn adoption_of(legacy_dm_id: i64) -> DmAdoption<'static> {
        DmAdoption { room_id: ROOM, legacy_dm_id, key_events: &[], key_events_origin_server_ts: 500, now: T0 }
    }

    #[test]
    fn adopt_dm_room_for_legacy_binds_the_room_and_imports_the_messages() {
        let mut conn = test_conn();
        native_dm_room(&conn);

        let counts = adopt_dm_room_for_legacy(&mut conn, adoption_of(7), &[legacy_import(1, "$l1"), legacy_import(2, "$l2")], &[])
            .expect("adopt")
            .expect("the room is adoptable");
        assert_eq!(counts.messages_imported, 2);
        assert_eq!(room_by_legacy_dm_id(&conn, 7).expect("query").expect("bound").id, ROOM);
        assert_eq!(highest_mapped_legacy_message_id(&conn, ROOM).expect("query"), Some(2));
        assert_eq!(get_event(&conn, "$l1").expect("query").expect("imported").room_id, ROOM);
    }

    #[test]
    fn adopt_dm_room_for_legacy_writes_a_key_event_only_where_the_room_has_none() {
        let mut conn = test_conn();
        native_dm_room(&conn);
        let existing = apply_state_event(&mut conn, &StateEventWrite { event_id: "$k-existing", room_id: ROOM, sender_user_id: 1, event_type: "org.mylittlechart.legacy_dm_key", state_key: "@a:mylittlechart.org", content: r#"{"public_key_b64":"AAAA"}"#, origin_server_ts: 900, now: T0 })
            .expect("existing key event");
        let key_events = [
            NewStateEvent {
                event_id: "$k-a".to_string(),
                sender_user_id: 1,
                event_type: "org.mylittlechart.legacy_dm_key".to_string(),
                state_key: "@a:mylittlechart.org".to_string(),
                content: r#"{"public_key_b64":"BBBB"}"#.to_string(),
            },
            NewStateEvent {
                event_id: "$k-b".to_string(),
                sender_user_id: 2,
                event_type: "org.mylittlechart.legacy_dm_key".to_string(),
                state_key: "@b:mylittlechart.org".to_string(),
                content: r#"{"public_key_b64":"CCCC"}"#.to_string(),
            },
        ];
        let adoption = DmAdoption { key_events: &key_events, ..adoption_of(7) };
        adopt_dm_room_for_legacy(&mut conn, adoption, &[], &[]).expect("adopt").expect("adoptable");

        let a = current_state_event(&conn, ROOM, "org.mylittlechart.legacy_dm_key", "@a:mylittlechart.org").expect("query").expect("still present");
        assert_eq!(a.event_id, existing.event_id, "an existing key event is never overwritten");
        let b = current_state_event(&conn, ROOM, "org.mylittlechart.legacy_dm_key", "@b:mylittlechart.org").expect("query").expect("added");
        assert_eq!(b.event_id, "$k-b");
    }

    #[test]
    fn adopt_dm_room_for_legacy_refuses_a_room_that_is_bound_or_not_a_dm() {
        let mut conn = test_conn();
        make_room(&conn);
        assert!(adopt_dm_room_for_legacy(&mut conn, adoption_of(7), &[legacy_import(1, "$l1")], &[]).expect("adopt").is_none(), "a group room is never adopted");
        assert!(room_by_legacy_dm_id(&conn, 7).expect("query").is_none());

        let mut bound = test_conn();
        create_room(&bound, ROOM, RoomKind::Dm, 1, T0, true, JoinRule::Invite, HistoryVisibility::Shared, Some("1:2"), Some(9)).expect("create bound room");
        assert!(adopt_dm_room_for_legacy(&mut bound, adoption_of(7), &[legacy_import(1, "$l1")], &[]).expect("adopt").is_none(), "an already-bound room is never re-bound");
        assert_eq!(room_by_legacy_dm_id(&bound, 9).expect("query").expect("still bound to 9").id, ROOM);
        assert!(get_event(&bound, "$l1").expect("query").is_none(), "a refused adoption writes nothing");
    }

    #[test]
    fn adopt_dm_room_for_legacy_rolls_back_the_binding_when_an_import_fails() {
        let mut conn = test_conn();
        native_dm_room(&conn);

        // The second import reuses the first one's event id — refused by the
        // UNIQUE index, after the room was already bound inside the transaction.
        let result = adopt_dm_room_for_legacy(&mut conn, adoption_of(7), &[legacy_import(1, "$dup"), legacy_import(2, "$dup")], &[]);
        assert!(result.is_err());

        assert!(room_by_legacy_dm_id(&conn, 7).expect("query").is_none(), "the binding must roll back with the failed import");
        assert!(get_event(&conn, "$dup").expect("query").is_none(), "no imported event survives");
        assert_eq!(highest_mapped_legacy_message_id(&conn, ROOM).expect("query"), None);
    }
}

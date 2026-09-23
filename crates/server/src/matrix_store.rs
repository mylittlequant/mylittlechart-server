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

use rusqlite::{params, Connection, OptionalExtension, Transaction};
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
/// `path`, key it, and create this module's half of the schema. Mirrors
/// `social_db::init_social_db` exactly: the key is the very first statement
/// on the connection, then WAL + foreign keys, then schema. The
/// devices/keys/backup half (`matrix_keys_store::create_matrix_keys_schema`)
/// is a separate call the boot sequence makes on the same connection (plan
/// §6.2) — not this function's job.
pub fn init_messenger_db(path: &str, key_hex: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(&format!("PRAGMA key = \"x'{key_hex}'\";"))?;
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;
    create_matrix_schema(&conn)?;
    Ok(conn)
}

// ============================================================================
// Stream ordering
// ============================================================================

/// Take the next value from the single global counter, inside `tx` — always
/// called in the SAME transaction as the row it stamps (this module's one
/// hard invariant; see the module doc's single-writer note on why this
/// stays race-free with no additional locking).
fn next_stream_id(tx: &Transaction) -> rusqlite::Result<i64> {
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

/// Insert a room's metadata row only — no bootstrap state events (those go
/// through [`apply_state_event`] separately, e.g. `m.room.create`,
/// `m.room.member`, `m.room.power_levels`, per plan §5/§7).
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

pub fn get_room(conn: &Connection, room_id: &str) -> rusqlite::Result<Option<Room>> {
    conn.query_row(&format!("SELECT {ROOM_SELECT_COLUMNS} FROM rooms WHERE id = ?1"), params![room_id], room_from_row)
        .optional()
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

/// Insert one timeline event (`state_key` always `NULL`) inside its own
/// transaction: mint the next stream id, insert the row, and — if
/// `content` carries a top-level `m.relates_to` (cleartext even for
/// `m.room.encrypted`, plan §10 item 3) — populate [`relations`]. Refusing
/// a duplicate `m.annotation` rolls back the whole transaction, so a
/// refused call leaves no partial `events` row.
pub fn insert_timeline_event(
    conn: &mut Connection,
    event_id: &str,
    room_id: &str,
    sender_user_id: i64,
    event_type: &str,
    content: &str,
    origin_server_ts: i64,
    txn_id: Option<&str>,
) -> Result<MatrixEvent, MatrixStoreError> {
    let tx = conn.transaction()?;
    let stream_id = next_stream_id(&tx)?;
    tx.execute(
        "INSERT INTO events (stream_id, event_id, room_id, sender_user_id, event_type, state_key, content, origin_server_ts, txn_id)
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8)",
        params![stream_id, event_id, room_id, sender_user_id, event_type, content, origin_server_ts, txn_id],
    )?;
    populate_relations(&tx, event_id, room_id, sender_user_id, content)?;
    tx.commit()?;
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

/// Insert one state event and refresh the two projections that read off it:
/// `current_state` (always) and, for `m.room.member`/`m.room.power_levels`,
/// the denormalized `room_members` cache (plan §2). All inside one
/// transaction with the event row.
pub fn apply_state_event(
    conn: &mut Connection,
    event_id: &str,
    room_id: &str,
    sender_user_id: i64,
    event_type: &str,
    state_key: &str,
    content: &str,
    origin_server_ts: i64,
    now: &str,
) -> Result<MatrixEvent, MatrixStoreError> {
    let tx = conn.transaction()?;
    let stream_id = next_stream_id(&tx)?;
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
        refresh_room_member(&tx, room_id, state_key, content, now)?;
    }
    if event_type == "m.room.power_levels" {
        refresh_power_levels(&tx, room_id, content)?;
    }
    tx.commit()?;
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
/// (`redacts = target_event_id`), set the target's `redacted_by`, and
/// strip the target's `content` per [`redact_content_per_v11`]. All inside
/// one transaction.
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

    let stream_id = next_stream_id(&tx)?;
    let redaction_content = match reason {
        Some(r) => serde_json::json!({ "reason": r }).to_string(),
        None => "{}".to_string(),
    };
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

    tx.commit()?;
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
            tx.commit()?;
            return Ok(*existing_stream_id);
        }
    }

    let stream_id = next_stream_id(&tx)?;
    tx.execute(
        "INSERT INTO receipts (room_id, user_id, receipt_type, event_id, ts, stream_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(room_id, user_id, receipt_type) DO UPDATE SET
            event_id = excluded.event_id, ts = excluded.ts, stream_id = excluded.stream_id",
        params![room_id, user_id, receipt_type.as_str(), event_id, ts, stream_id],
    )?;
    tx.commit()?;
    Ok(stream_id)
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

        let event = insert_timeline_event(&mut conn, "$event1", ROOM, 1, "m.room.message", "{}", 1000, None).expect("insert event");
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

        apply_state_event(&mut conn, "$e1", ROOM, 1, "m.room.name", "", r#"{"name":"first"}"#, 1000, T0).expect("apply first");
        apply_state_event(&mut conn, "$e2", ROOM, 1, "m.room.name", "", r#"{"name":"second"}"#, 2000, T0).expect("apply second");

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
            insert_timeline_event(&mut conn, "$target", ROOM, 1, event_type, content, 1000, None).expect("insert target");
            redact_event(&mut conn, ROOM, "$target", "$redaction", 1, None, 2000).expect("redact");

            let target = get_event(&conn, "$target").expect("get target").expect("row exists");
            let got: serde_json::Value = serde_json::from_str(&target.content).expect("parse stripped content");
            assert_eq!(got, expected, "event_type={event_type}");
            assert_eq!(target.redacted_by.as_deref(), Some("$redaction"), "event_type={event_type}");
        }
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

        let event = insert_timeline_event(&mut conn, "$e1", ROOM, 1, "m.room.message", "{}", 1000, Some("txn-1")).expect("insert");
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
        insert_timeline_event(&mut conn, "$target", ROOM, 1, "m.room.message", "{}", 1000, None).expect("target");

        let content = r#"{"algorithm":"m.megolm.v1.aes-sha2","ciphertext":"opaque-base64==","sender_key":"opaque","m.relates_to":{"rel_type":"m.annotation","event_id":"$target","key":"a"}}"#;
        let reaction = insert_timeline_event(&mut conn, "$reaction", ROOM, 2, "m.room.encrypted", content, 2000, None).expect("insert reaction");

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
        let e1 = insert_timeline_event(&mut conn, "$e1", ROOM, 1, "m.room.message", "{}", 1000, None).expect("e1");
        let e2 = insert_timeline_event(&mut conn, "$e2", ROOM, 1, "m.room.message", "{}", 2000, None).expect("e2");

        upsert_receipt(&mut conn, ROOM, 9, ReceiptType::Read, &e2.event_id, 5000).expect("advance to e2");
        upsert_receipt(&mut conn, ROOM, 9, ReceiptType::Read, &e1.event_id, 6000).expect("attempted backward move is a no-op");

        let receipt = get_receipt(&conn, ROOM, 9, ReceiptType::Read).expect("get").expect("row exists");
        assert_eq!(receipt.event_id, e2.event_id, "a receipt must never move back to an earlier event");
    }

    // ---- extra test: duplicate annotation refused ----

    #[test]
    fn duplicate_annotation_is_refused() {
        let mut conn = test_conn();
        make_room(&conn);
        insert_timeline_event(&mut conn, "$target", ROOM, 1, "m.room.message", "{}", 1000, None).expect("target");

        let content = r#"{"m.relates_to":{"rel_type":"m.annotation","event_id":"$target","key":"a"}}"#;
        insert_timeline_event(&mut conn, "$react1", ROOM, 5, "m.reaction", content, 2000, None).expect("first reaction");

        let err = insert_timeline_event(&mut conn, "$react2", ROOM, 5, "m.reaction", content, 3000, None).unwrap_err();
        assert!(matches!(err, MatrixStoreError::DuplicateAnnotation));

        // The whole transaction must have rolled back — no partial events row.
        assert_eq!(get_event(&conn, "$react2").expect("get"), None);

        // A DIFFERENT sender reacting with the same key is a distinct,
        // accepted annotation (not covered by the refusal).
        let other = insert_timeline_event(&mut conn, "$react3", ROOM, 6, "m.reaction", content, 4000, None).expect("different sender reacts");
        assert_eq!(other.event_id, "$react3");
    }

    // ---- manager-review fixes (2026-09-24 follow-up) ----

    #[test]
    fn reannotation_after_redaction_is_allowed() {
        let mut conn = test_conn();
        make_room(&conn);
        insert_timeline_event(&mut conn, "$target", ROOM, 1, "m.room.message", "{}", 1000, None).expect("target");

        let content = r#"{"m.relates_to":{"rel_type":"m.annotation","event_id":"$target","key":"a"}}"#;
        let first = insert_timeline_event(&mut conn, "$react1", ROOM, 5, "m.reaction", content, 2000, None).expect("first reaction");

        redact_event(&mut conn, ROOM, &first.event_id, "$redaction", 1, None, 2500).expect("redact the reaction");

        // The same sender may now react with the same key again — the
        // redacted prior annotation no longer counts as a duplicate.
        let second = insert_timeline_event(&mut conn, "$react2", ROOM, 5, "m.reaction", content, 3000, None)
            .expect("re-annotation after redaction must succeed");
        assert_eq!(second.event_id, "$react2");
    }

    #[test]
    fn relation_target_must_exist() {
        let mut conn = test_conn();
        make_room(&conn);

        let content = r#"{"m.relates_to":{"rel_type":"m.annotation","event_id":"$missing","key":"a"}}"#;
        let err = insert_timeline_event(&mut conn, "$react1", ROOM, 5, "m.reaction", content, 2000, None).unwrap_err();
        assert!(matches!(err, MatrixStoreError::InvalidRelationTarget(ref id) if id == "$missing"));
    }

    #[test]
    fn relation_target_must_be_in_the_same_room() {
        let mut conn = test_conn();
        make_room(&conn);
        let other_room = format!("!other:{MATRIX_SERVER_NAME}");
        create_room(&conn, &other_room, RoomKind::Group, 1, T0, false, JoinRule::Invite, HistoryVisibility::Shared, None, None)
            .expect("other room");
        insert_timeline_event(&mut conn, "$target", &other_room, 1, "m.room.message", "{}", 1000, None).expect("target in other room");

        let content = r#"{"m.relates_to":{"rel_type":"m.annotation","event_id":"$target","key":"a"}}"#;
        let err = insert_timeline_event(&mut conn, "$react1", ROOM, 5, "m.reaction", content, 2000, None).unwrap_err();
        assert!(matches!(err, MatrixStoreError::InvalidRelationTarget(ref id) if id == "$target"));
    }

    #[test]
    fn redact_event_refuses_a_target_in_a_different_room() {
        let mut conn = test_conn();
        make_room(&conn);
        let other_room = format!("!other:{MATRIX_SERVER_NAME}");
        create_room(&conn, &other_room, RoomKind::Group, 1, T0, false, JoinRule::Invite, HistoryVisibility::Shared, None, None)
            .expect("other room");
        insert_timeline_event(&mut conn, "$target", &other_room, 1, "m.room.message", "{}", 1000, None).expect("target in other room");

        let err = redact_event(&mut conn, ROOM, "$target", "$redaction", 1, None, 2000).unwrap_err();
        assert!(matches!(err, MatrixStoreError::WrongRoom(ref id) if id == "$target"));
    }

    #[test]
    fn redact_event_refuses_create_and_encryption_events() {
        for event_type in ["m.room.create", "m.room.encryption"] {
            let mut conn = test_conn();
            make_room(&conn);
            apply_state_event(&mut conn, "$target", ROOM, 1, event_type, "", r#"{"a":1}"#, 1000, T0).expect("apply state event");

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
        let event = insert_timeline_event(&mut conn, "$e1", &other_room, 1, "m.room.message", "{}", 1000, None).expect("event in other room");

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

        apply_state_event(&mut conn, "$m1", ROOM, 1, "m.room.member", &alice, r#"{"membership":"join"}"#, 1000, T0).expect("alice joins");
        apply_state_event(&mut conn, "$m2", ROOM, 1, "m.room.member", &bob, r#"{"membership":"invite"}"#, 1100, T0).expect("bob invited");

        let joined = room_members(&conn, ROOM, Some(Membership::Join)).expect("joined members");
        assert_eq!(joined.len(), 1);
        assert_eq!(joined[0].user_id, 1);
        assert_eq!(joined[0].power_level, None);

        let power_levels_content = serde_json::json!({"users": {alice.clone(): 100}, "users_default": 0}).to_string();
        apply_state_event(&mut conn, "$pl1", ROOM, 1, "m.room.power_levels", "", &power_levels_content, 1200, T0).expect("power levels");

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
        let e1 = insert_timeline_event(&mut conn, "$e1", ROOM, 1, "m.room.message", "{}", 1000, None).expect("e1");
        let e2 = insert_timeline_event(&mut conn, "$e2", ROOM, 1, "m.room.message", "{}", 2000, None).expect("e2");
        let e3 = insert_timeline_event(&mut conn, "$e3", ROOM, 1, "m.room.message", "{}", 3000, None).expect("e3");

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
        let event = insert_timeline_event(&mut conn, "$legacy1", ROOM, 1, "org.mylittlechart.legacy_dm", "{}", 1000, None).expect("insert");
        insert_legacy_dm_message_map(&conn, 42, &event.event_id).expect("map insert");
        assert_eq!(legacy_dm_message_event_id(&conn, 42).expect("map get"), Some(event.event_id));
        assert_eq!(legacy_dm_message_event_id(&conn, 999).expect("missing"), None);
    }
}

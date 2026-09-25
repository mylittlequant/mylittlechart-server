//! Boot-time, idempotent migration of legacy 1:1 DMs (`social.db`'s
//! `dm_conversations`/`dm_messages`/`dm_identity_keys`) into Matrix DM rooms
//! in `messenger.db` (P12). Called exactly once at boot, right after
//! `messenger.db` is opened and before `state::ControlPlane` exists
//! (`main.rs`) — see
//! `docs/mlc/plans/messenger-proto-server-matrix-subset-2026-09-24.md` §7 for
//! the plan this implements.
//!
//! # `dm_*` and `/api/dm/*` are untouched
//!
//! Every read against `social` (the `social.db` connection) below is a
//! `SELECT` — this module never writes to `dm_conversations`, `dm_messages`,
//! or `dm_identity_keys`. The existing DM feature and its routes keep
//! working exactly as before; this migration only ever adds rows to
//! `messenger.db`.
//!
//! # Reusing the native `createRoom` bootstrap
//!
//! A migrated room is built from the SAME pieces
//! [`crate::routes::matrix::rooms`] uses for a fresh `is_direct` room —
//! `power_levels_content`, `room_kind_settings`, `invite_power_level`, and
//! `state_event` — so a migrated room's `m.room.power_levels`/
//! `m.room.join_rules`/`m.room.history_visibility` content is byte-for-byte
//! what a native DM creation would have produced. The one deliberate
//! difference (plan §7 step 3): both parties land as `join` immediately,
//! never `invite` — a migrated conversation was already a live, mutual DM in
//! the legacy system, so there is no pending-invite state to reconstruct.
//!
//! # Transactional granularity
//!
//! ONE transaction per conversation ([`mylittlechart_server::matrix_store::migrate_dm_conversation`]),
//! not one giant transaction over the whole `dm_conversations` table — a
//! large DM table must not hold the messenger connection's mutex for the
//! entire boot. Trade-off, stated rather than hidden: a crash mid-run leaves
//! some conversations fully migrated and the rest untouched, picked up again
//! (cheaply — every check is a fast indexed lookup) on the next boot; it
//! never leaves a single conversation half-migrated, since that one
//! conversation's room, bootstrap state, messages, receipts, and `m.direct`
//! hints all commit or roll back together.
//!
//! # Failure handling
//!
//! Reading the conversation LIST itself failing (`social.db` unreachable or
//! missing its schema) is fatal and propagated to the caller (`main.rs`
//! stops boot on it, like every other `init_*_db` failure). A failure
//! migrating any ONE conversation (an identity lookup error, a messenger
//! write error, an unparseable timestamp) is caught here, logged with that
//! conversation's id, and never touches any other conversation.
//!
//! # Catch-up (P15): the old `/dm/conversations*` routes stay live
//!
//! `routes::dm`'s legacy send-message route keeps working for native clients
//! that have not moved to the Matrix subset yet — any message it accepts
//! after boot lands in `social.db`'s `dm_messages` only, never in the
//! migrated room, unless something re-runs the import for that one
//! conversation. [`catch_up_conversation`] is that re-run: it appends every
//! `dm_messages` row not yet in `legacy_dm_message_map`, using the exact
//! same per-message content/timestamp derivation [`migrate_one_conversation`]
//! uses ([`legacy_dm_message_import`]/[`track_read_receipt`], factored out so
//! the two paths can never drift). [`migrate_legacy_dms`] runs it on every
//! `AlreadyMigrated` conversation at boot, closing any gap since the last
//! run. A live bridge that also runs it right after
//! `routes::dm::create_message`'s own insert commits (so an already-open
//! `/sync` long-poll sees the message at once, not just at the next boot) is
//! a later piece.

use std::collections::HashMap;
use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rusqlite::{params, Connection};

use mylittlechart_server::matrix_store::{self, RoomKind};

use crate::db;
use crate::dm_db;
use crate::routes::matrix::rooms::{dm_pair_key, invite_power_level, power_levels_content, room_kind_settings, state_event};

/// State event type for a migrated room's copy of each member's DM identity
/// key (plan §2 manager decision 5). Content:
/// `{"public_key_b64", "legacy_conversation_id"}` — `legacy_conversation_id`
/// is the legacy `dm_conversations.id`, present so a client can derive
/// `mlc_vault::dm::conversation_key` from room state alone, without ever
/// having to be told the legacy conversation id out of band. Every
/// `org.mylittlechart.legacy_dm` message event in the same room carries the
/// same `legacy_conversation_id` in its own content.
const LEGACY_DM_KEY_EVENT_TYPE: &str = "org.mylittlechart.legacy_dm_key";

// ============================================================================
// Report
// ============================================================================

/// What one boot-time [`migrate_legacy_dms`] pass did — logged once at INFO.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationReport {
    pub conversations_migrated: usize,
    pub conversations_skipped: usize,
    pub messages_imported: usize,
    pub receipts_set: usize,
    /// Messages appended by [`catch_up_conversation`] across every
    /// already-migrated conversation this pass touched (P15) — disjoint from
    /// `messages_imported`, which only ever counts a conversation's FIRST,
    /// full migration.
    pub messages_caught_up: usize,
    pub skipped: Vec<SkippedConversation>,
}

/// One `dm_conversations` row [`migrate_legacy_dms`] declined to migrate,
/// and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedConversation {
    pub conversation_id: i64,
    pub reason: String,
}

// ============================================================================
// Per-conversation error (never propagated past `migrate_legacy_dms` itself —
// caught, logged, and turned into a `SkippedConversation`)
// ============================================================================

#[derive(Debug)]
enum ConversationMigrationError {
    Db(rusqlite::Error),
    Store(matrix_store::MatrixStoreError),
    BadTimestamp(String),
}

impl fmt::Display for ConversationMigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConversationMigrationError::Db(e) => write!(f, "database error: {e}"),
            ConversationMigrationError::Store(e) => write!(f, "matrix store error: {e:?}"),
            ConversationMigrationError::BadTimestamp(raw) => write!(f, "unparseable timestamp: {raw:?}"),
        }
    }
}

impl From<rusqlite::Error> for ConversationMigrationError {
    fn from(e: rusqlite::Error) -> Self {
        ConversationMigrationError::Db(e)
    }
}

impl From<matrix_store::MatrixStoreError> for ConversationMigrationError {
    fn from(e: matrix_store::MatrixStoreError) -> Self {
        ConversationMigrationError::Store(e)
    }
}

enum ConversationOutcome {
    /// Carries what [`catch_up_conversation`] found on this pass — `0`/`0`
    /// is the routine case (nothing new since the last run).
    AlreadyMigrated { messages_caught_up: usize, receipts_caught_up: usize },
    Migrated { messages_imported: usize, receipts_set: usize },
    Skipped(String),
}

// ============================================================================
// Read-only `social.db` fixtures
// ============================================================================

struct LegacyConversation {
    id: i64,
    user_lo: i64,
    user_hi: i64,
    created_at: String,
}

fn list_dm_conversations(social: &Connection) -> rusqlite::Result<Vec<LegacyConversation>> {
    let mut stmt = social.prepare("SELECT id, user_lo, user_hi, created_at FROM dm_conversations ORDER BY id ASC")?;
    let rows = stmt.query_map([], |row| {
        Ok(LegacyConversation { id: row.get(0)?, user_lo: row.get(1)?, user_hi: row.get(2)?, created_at: row.get(3)? })
    })?;
    rows.collect()
}

struct LegacyMessage {
    id: i64,
    sender_user_id: i64,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    created_at: String,
    read_at: Option<String>,
}

fn list_dm_messages(social: &Connection, conversation_id: i64) -> rusqlite::Result<Vec<LegacyMessage>> {
    let mut stmt = social.prepare(
        "SELECT id, sender_user_id, nonce, ciphertext, created_at, read_at
         FROM dm_messages WHERE conversation_id = ?1 ORDER BY id ASC",
    )?;
    let rows = stmt.query_map(params![conversation_id], |row| {
        Ok(LegacyMessage {
            id: row.get(0)?,
            sender_user_id: row.get(1)?,
            nonce: row.get(2)?,
            ciphertext: row.get(3)?,
            created_at: row.get(4)?,
            read_at: row.get(5)?,
        })
    })?;
    rows.collect()
}

fn rfc3339_to_millis(raw: &str) -> Result<i64, ConversationMigrationError> {
    chrono::DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.timestamp_millis())
        .map_err(|_| ConversationMigrationError::BadTimestamp(raw.to_string()))
}

// ============================================================================
// Entry point
// ============================================================================

/// Migrate every `dm_conversations` row that has no matching
/// `rooms.legacy_dm_id` yet into a Matrix DM room (plan §7). `identity` is
/// the main identity database connection (`public_id` lookups only);
/// `social` is `social.db`, read-only throughout; `now` (RFC3339) stamps
/// [`mylittlechart_server::matrix_store::ensure_matrix_user`]'s
/// `matrix_users.created_at` for any party touched for the first time here.
///
/// Idempotent: a second call makes no changes at all, and produces the exact
/// same room/event ids as the first (see this module's own tests, plus the
/// plan §9 test `migrate_legacy_dms_is_idempotent_and_preserves_event_ids`).
pub fn migrate_legacy_dms(
    messenger: &mut Connection,
    social: &Connection,
    identity: &Connection,
    now: &str,
) -> rusqlite::Result<MigrationReport> {
    let conversations = list_dm_conversations(social)?;
    let mut report = MigrationReport::default();

    for conv in &conversations {
        match migrate_one_conversation(messenger, social, identity, conv, now) {
            Ok(ConversationOutcome::AlreadyMigrated { messages_caught_up, receipts_caught_up }) => {
                report.messages_caught_up += messages_caught_up;
                report.receipts_set += receipts_caught_up;
            }
            Ok(ConversationOutcome::Migrated { messages_imported, receipts_set }) => {
                report.conversations_migrated += 1;
                report.messages_imported += messages_imported;
                report.receipts_set += receipts_set;
            }
            Ok(ConversationOutcome::Skipped(reason)) => {
                tracing::warn!("legacy DM migration: skipping conversation {}: {}", conv.id, reason);
                report.conversations_skipped += 1;
                report.skipped.push(SkippedConversation { conversation_id: conv.id, reason });
            }
            Err(e) => {
                tracing::error!("legacy DM migration: conversation {} failed: {}", conv.id, e);
                report.conversations_skipped += 1;
                report.skipped.push(SkippedConversation { conversation_id: conv.id, reason: e.to_string() });
            }
        }
    }

    tracing::info!(
        "Legacy DM migration: {} conversation(s) migrated, {} skipped, {} message(s) imported, {} receipt(s) set, {} message(s) caught up",
        report.conversations_migrated,
        report.conversations_skipped,
        report.messages_imported,
        report.receipts_set,
        report.messages_caught_up,
    );

    Ok(report)
}

/// One conversation's worth of work — see this module's own doc for the
/// transactional/idempotency guarantees (all provided by
/// [`mylittlechart_server::matrix_store::migrate_dm_conversation`] itself,
/// once this function has assembled its input).
fn migrate_one_conversation(
    messenger: &mut Connection,
    social: &Connection,
    identity: &Connection,
    conv: &LegacyConversation,
    now: &str,
) -> Result<ConversationOutcome, ConversationMigrationError> {
    if let Some(room) = matrix_store::room_by_legacy_dm_id(messenger, conv.id)? {
        let counts = catch_up_conversation(messenger, social, &room.id, conv)?;
        return Ok(ConversationOutcome::AlreadyMigrated {
            messages_caught_up: counts.messages_imported,
            receipts_caught_up: counts.receipts_set,
        });
    }

    let lo_public_id = match db::get_user_public_id(identity, conv.user_lo) {
        Ok(id) => id,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return Ok(ConversationOutcome::Skipped(format!("user {} no longer exists", conv.user_lo)));
        }
        Err(e) => return Err(e.into()),
    };
    let hi_public_id = match db::get_user_public_id(identity, conv.user_hi) {
        Ok(id) => id,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return Ok(ConversationOutcome::Skipped(format!("user {} no longer exists", conv.user_hi)));
        }
        Err(e) => return Err(e.into()),
    };

    // First touch of either party registers their mxid — idempotent and
    // harmless even if this conversation's own migration is aborted below by
    // a later error, since `matrix_users` is a user-level mapping, not a
    // conversation-level one.
    let lo_mxid = matrix_store::ensure_matrix_user(messenger, conv.user_lo, &lo_public_id, now)?;
    let hi_mxid = matrix_store::ensure_matrix_user(messenger, conv.user_hi, &hi_public_id, now)?;

    let (join_rule, history_visibility, is_encrypted) = room_kind_settings(RoomKind::Dm);
    let invite_level = invite_power_level(RoomKind::Dm, None);
    let bootstrap_origin_ts = rfc3339_to_millis(&conv.created_at)?;

    let mut state_events = vec![
        state_event("m.room.create", "", conv.user_lo, serde_json::json!({ "room_version": matrix_store::MATRIX_ROOM_VERSION })),
        state_event("m.room.member", &lo_mxid, conv.user_lo, serde_json::json!({ "membership": "join" })),
        state_event("m.room.member", &hi_mxid, conv.user_hi, serde_json::json!({ "membership": "join" })),
        state_event("m.room.power_levels", "", conv.user_lo, power_levels_content(&lo_mxid, RoomKind::Dm, invite_level)),
        state_event("m.room.join_rules", "", conv.user_lo, serde_json::json!({ "join_rule": join_rule.as_str() })),
        state_event(
            "m.room.history_visibility",
            "",
            conv.user_lo,
            serde_json::json!({ "history_visibility": history_visibility.as_str() }),
        ),
    ];
    if is_encrypted {
        state_events.push(state_event(
            "m.room.encryption",
            "",
            conv.user_lo,
            serde_json::json!({ "algorithm": "m.megolm.v1.aes-sha2" }),
        ));
    }
    for (user_id, mxid) in [(conv.user_lo, lo_mxid.as_str()), (conv.user_hi, hi_mxid.as_str())] {
        if let Some(identity_key) = dm_db::get_identity_key(social, user_id)? {
            state_events.push(state_event(
                LEGACY_DM_KEY_EVENT_TYPE,
                mxid,
                user_id,
                serde_json::json!({
                    "public_key_b64": STANDARD.encode(&identity_key.public_key),
                    "legacy_conversation_id": conv.id,
                }),
            ));
        }
    }

    let messages = list_dm_messages(social, conv.id)?;
    let mut message_imports = Vec::with_capacity(messages.len());
    // reader_user_id -> (highest dm_messages.id this reader has read, its own read_at in ms).
    let mut last_read_by_reader: HashMap<i64, (i64, i64)> = HashMap::new();

    for message in &messages {
        message_imports.push(legacy_dm_message_import(conv.id, message)?);
        track_read_receipt(conv, message, &mut last_read_by_reader)?;
    }

    let receipts: Vec<matrix_store::LegacyDmReadReceipt> = last_read_by_reader
        .into_iter()
        .map(|(reader_user_id, (up_to_legacy_message_id, ts_ms))| matrix_store::LegacyDmReadReceipt {
            reader_user_id,
            up_to_legacy_message_id,
            ts_ms,
        })
        .collect();

    let direct_hints =
        vec![
            matrix_store::LegacyDmDirectHint { user_id: conv.user_lo, peer_mxid: hi_mxid.clone() },
            matrix_store::LegacyDmDirectHint { user_id: conv.user_hi, peer_mxid: lo_mxid.clone() },
        ];

    let room_id = matrix_store::new_room_id();
    let pair_key = dm_pair_key(conv.user_lo, conv.user_hi);
    let bootstrap = matrix_store::RoomBootstrap {
        room_id: &room_id,
        kind: RoomKind::Dm,
        creator_user_id: conv.user_lo,
        created_at: &conv.created_at,
        is_encrypted,
        join_rule,
        history_visibility,
        dm_pair_key: Some(pair_key.as_str()),
        legacy_dm_id: Some(conv.id),
    };
    let extras = matrix_store::DmMigrationExtras { messages: &message_imports, receipts: &receipts, direct_hints: &direct_hints };

    let (_room, counts) = matrix_store::migrate_dm_conversation(messenger, bootstrap, &state_events, bootstrap_origin_ts, extras)?;

    Ok(ConversationOutcome::Migrated { messages_imported: counts.messages_imported, receipts_set: counts.receipts_set })
}

// ============================================================================
// Shared per-message building blocks — used by [`migrate_one_conversation`]
// (a full first-time migration) AND [`catch_up_conversation`] (P15: an
// already-migrated room's gap-closer), factored out here so the two paths
// can never drift on content shape, `origin_server_ts` derivation, or the
// read-receipt "never over-count as read" rule.
// ============================================================================

/// Build one `dm_messages` row's `org.mylittlechart.legacy_dm` timeline
/// import — the exact content shape and `origin_server_ts` derivation
/// [`migrate_one_conversation`] always used. `event_id` is minted fresh on
/// every call; safe because every caller only ever calls this for a
/// `legacy_message_id` it has already confirmed is NOT yet in
/// `legacy_dm_message_map`.
fn legacy_dm_message_import(
    conversation_id: i64,
    message: &LegacyMessage,
) -> Result<matrix_store::LegacyDmMessageImport, ConversationMigrationError> {
    let origin_server_ts = rfc3339_to_millis(&message.created_at)?;
    Ok(matrix_store::LegacyDmMessageImport {
        legacy_message_id: message.id,
        event_id: matrix_store::new_event_id(),
        sender_user_id: message.sender_user_id,
        content: serde_json::json!({
            "legacy_message_id": message.id,
            "legacy_conversation_id": conversation_id,
            "nonce_b64": STANDARD.encode(&message.nonce),
            "ciphertext_b64": STANDARD.encode(&message.ciphertext),
        })
        .to_string(),
        origin_server_ts,
    })
}

/// Fold one `dm_messages` row's `read_at` (if any) into `last_read_by_reader`
/// (`reader_user_id -> (highest dm_messages.id read, its own read_at in
/// ms)`). The reader is always "the other one" of `conv`'s fixed pair
/// (`read_at` is only ever stamped for the party who did NOT send it,
/// `dm_db::mark_read`), and only the HIGHEST `dm_messages.id` a reader has
/// read is kept — never over-count as read (plan P12 scope, unchanged by
/// P15).
fn track_read_receipt(
    conv: &LegacyConversation,
    message: &LegacyMessage,
    last_read_by_reader: &mut HashMap<i64, (i64, i64)>,
) -> Result<(), ConversationMigrationError> {
    let Some(read_at) = &message.read_at else { return Ok(()) };
    let reader_user_id = if message.sender_user_id == conv.user_lo { conv.user_hi } else { conv.user_lo };
    let ts_ms = rfc3339_to_millis(read_at)?;
    last_read_by_reader
        .entry(reader_user_id)
        .and_modify(|(best_id, best_ts)| {
            if message.id > *best_id {
                *best_id = message.id;
                *best_ts = ts_ms;
            }
        })
        .or_insert((message.id, ts_ms));
    Ok(())
}

// ============================================================================
// Catch-up (P15) — an already-migrated conversation's gap-closer
// ============================================================================

/// Catch up ONE already-migrated conversation's Matrix room with any
/// `dm_messages` rows added since its last migration/catch-up pass — every
/// `dm_messages.id` not yet in `legacy_dm_message_map`, appended ascending
/// (`list_dm_messages`'s own `ORDER BY id ASC`) as `org.mylittlechart.legacy_dm`
/// timeline events in ONE transaction
/// ([`mylittlechart_server::matrix_store::catch_up_dm_conversation`]). A
/// reader's `m.read` receipt only ever advances to the newest of THESE newly
/// appended messages they have `read_at` for — an older message's `read_at`
/// stamped between passes is out of scope here, since that message was
/// already reflected (if at all) the moment IT was imported.
///
/// `room_id` must already be `conv`'s migrated room — every caller
/// ([`migrate_one_conversation`], and a later piece's live-send bridge) has
/// just confirmed this via [`matrix_store::room_by_legacy_dm_id`].
/// `messages_imported` in the returned counts is `0` for the routine case:
/// nothing new since `conv`'s room was last touched.
fn catch_up_conversation(
    messenger: &mut Connection,
    social: &Connection,
    room_id: &str,
    conv: &LegacyConversation,
) -> Result<matrix_store::DmMigrationCounts, ConversationMigrationError> {
    let messages = list_dm_messages(social, conv.id)?;
    let mut message_imports = Vec::new();
    let mut last_read_by_reader: HashMap<i64, (i64, i64)> = HashMap::new();

    for message in &messages {
        if matrix_store::legacy_dm_message_event_id(messenger, message.id)?.is_some() {
            continue;
        }
        message_imports.push(legacy_dm_message_import(conv.id, message)?);
        track_read_receipt(conv, message, &mut last_read_by_reader)?;
    }

    if message_imports.is_empty() {
        return Ok(matrix_store::DmMigrationCounts::default());
    }

    let receipts: Vec<matrix_store::LegacyDmReadReceipt> = last_read_by_reader
        .into_iter()
        .map(|(reader_user_id, (up_to_legacy_message_id, ts_ms))| matrix_store::LegacyDmReadReceipt {
            reader_user_id,
            up_to_legacy_message_id,
            ts_ms,
        })
        .collect();

    let counts = matrix_store::catch_up_dm_conversation(messenger, room_id, &message_imports, &receipts)?;
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mylittlechart_server::matrix_store::{HistoryVisibility, JoinRule, ReceiptType};

    // ---- fixtures ----

    fn identity_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        conn.execute_batch("CREATE TABLE users (id INTEGER PRIMARY KEY, public_id TEXT NOT NULL);").expect("schema");
        conn
    }

    fn add_user(conn: &Connection, user_id: i64, public_id: &str) {
        conn.execute("INSERT INTO users (id, public_id) VALUES (?1, ?2)", params![user_id, public_id]).expect("insert user");
    }

    fn social_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        dm_db::create_dm_schema(&conn).expect("dm schema");
        conn
    }

    fn messenger_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        matrix_store::create_matrix_schema(&conn).expect("matrix schema");
        conn
    }

    const NOW: &str = "2026-09-24T00:00:00+00:00";

    /// One conversation between users 1 (`public_id` `"lo00...01"`) and 2
    /// (`"hi00...02"`), with identity rows for both, no messages yet — the
    /// shared starting point most tests below extend.
    fn base_fixture() -> (Connection, Connection, Connection, dm_db::DmConversation) {
        let identity = identity_conn();
        add_user(&identity, 1, "0000000000000000000000000000lo1");
        add_user(&identity, 2, "0000000000000000000000000000hi2");
        let social = social_conn();
        let conv = dm_db::get_or_create_conversation(&social, 1, 2, "2026-09-01T00:00:00+00:00").expect("create conversation");
        let messenger = messenger_conn();
        (identity, social, messenger, conv)
    }

    // ---- P12 plan §9 tests ----

    #[test]
    fn migrate_legacy_dms_is_idempotent_and_preserves_event_ids() {
        let (identity, social, mut messenger, conv) = base_fixture();
        let nonce = [0u8; dm_db::DM_NONCE_LEN];
        dm_db::create_message(&social, conv.id, 1, &nonce, b"hello", "2026-09-01T00:01:00+00:00").expect("insert message");

        let first = migrate_legacy_dms(&mut messenger, &social, &identity, NOW).expect("first run");
        assert_eq!(first.conversations_migrated, 1);

        let room_after_first = matrix_store::room_by_legacy_dm_id(&messenger, conv.id).expect("query").expect("room exists");
        let event_id_after_first = matrix_store::legacy_dm_message_event_id(&messenger, 1).expect("query").expect("mapped");

        let room_count_before: i64 = messenger.query_row("SELECT COUNT(*) FROM rooms", [], |r| r.get(0)).expect("count");
        let event_count_before: i64 = messenger.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0)).expect("count");
        let member_count_before: i64 = messenger.query_row("SELECT COUNT(*) FROM room_members", [], |r| r.get(0)).expect("count");

        let second = migrate_legacy_dms(&mut messenger, &social, &identity, NOW).expect("second run");
        assert_eq!(second.conversations_migrated, 0);
        assert_eq!(second.messages_imported, 0);

        let room_count_after: i64 = messenger.query_row("SELECT COUNT(*) FROM rooms", [], |r| r.get(0)).expect("count");
        let event_count_after: i64 = messenger.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0)).expect("count");
        let member_count_after: i64 = messenger.query_row("SELECT COUNT(*) FROM room_members", [], |r| r.get(0)).expect("count");
        assert_eq!(room_count_before, room_count_after);
        assert_eq!(event_count_before, event_count_after);
        assert_eq!(member_count_before, member_count_after);

        let room_after_second = matrix_store::room_by_legacy_dm_id(&messenger, conv.id).expect("query").expect("room exists");
        let event_id_after_second = matrix_store::legacy_dm_message_event_id(&messenger, 1).expect("query").expect("mapped");
        assert_eq!(room_after_first.id, room_after_second.id);
        assert_eq!(event_id_after_first, event_id_after_second);
    }

    #[test]
    fn migrate_legacy_dms_sets_encryption_and_shared_history_visibility_on_every_migrated_room() {
        let (identity, social, mut messenger, conv) = base_fixture();
        migrate_legacy_dms(&mut messenger, &social, &identity, NOW).expect("migrate");

        let room = matrix_store::room_by_legacy_dm_id(&messenger, conv.id).expect("query").expect("room exists");
        assert!(room.is_encrypted);
        assert_eq!(room.join_rule, JoinRule::Invite);
        assert_eq!(room.history_visibility, HistoryVisibility::Shared);

        let encryption = matrix_store::current_state_event(&messenger, &room.id, "m.room.encryption", "")
            .expect("query")
            .expect("encryption event exists");
        let content: serde_json::Value = serde_json::from_str(&encryption.content).expect("json");
        assert_eq!(content["algorithm"], "m.megolm.v1.aes-sha2");
    }

    #[test]
    fn migrate_legacy_dms_never_touches_dm_conversations_or_dm_messages() {
        let (identity, social, mut messenger, conv) = base_fixture();
        let nonce = [0u8; dm_db::DM_NONCE_LEN];
        dm_db::create_message(&social, conv.id, 1, &nonce, b"hello", "2026-09-01T00:01:00+00:00").expect("insert message");
        dm_db::create_message(&social, conv.id, 2, &nonce, b"hi back", "2026-09-01T00:02:00+00:00").expect("insert message");

        let conversations_before: i64 = social.query_row("SELECT COUNT(*) FROM dm_conversations", [], |r| r.get(0)).expect("count");
        let messages_before: i64 = social.query_row("SELECT COUNT(*) FROM dm_messages", [], |r| r.get(0)).expect("count");
        let conv_row_before = dm_db::get_conversation(&social, conv.id).expect("get").expect("exists");

        migrate_legacy_dms(&mut messenger, &social, &identity, NOW).expect("migrate");

        let conversations_after: i64 = social.query_row("SELECT COUNT(*) FROM dm_conversations", [], |r| r.get(0)).expect("count");
        let messages_after: i64 = social.query_row("SELECT COUNT(*) FROM dm_messages", [], |r| r.get(0)).expect("count");
        let conv_row_after = dm_db::get_conversation(&social, conv.id).expect("get").expect("exists");
        assert_eq!(conversations_before, conversations_after);
        assert_eq!(messages_before, messages_after);
        assert_eq!(conv_row_before, conv_row_after);
    }

    // ---- additional required tests ----

    #[test]
    fn migrated_room_bootstrap_matches_native_dm_room() {
        let (identity, social, mut messenger, conv) = base_fixture();
        migrate_legacy_dms(&mut messenger, &social, &identity, NOW).expect("migrate");

        let room = matrix_store::room_by_legacy_dm_id(&messenger, conv.id).expect("query").expect("room exists");
        let state = matrix_store::current_state_all(&messenger, &room.id).expect("state");
        let mut types: Vec<&str> = state.iter().map(|e| e.event_type.as_str()).collect();
        types.sort_unstable();
        assert_eq!(
            types,
            vec![
                "m.room.create",
                "m.room.encryption",
                "m.room.history_visibility",
                "m.room.join_rules",
                "m.room.member",
                "m.room.member",
                "m.room.power_levels",
            ]
        );

        let lo_mxid = matrix_store::mxid_of(&messenger, conv.user_lo).expect("query").expect("registered");
        let power_levels_event =
            matrix_store::current_state_event(&messenger, &room.id, "m.room.power_levels", "").expect("query").expect("exists");
        let expected = power_levels_content(&lo_mxid, RoomKind::Dm, invite_power_level(RoomKind::Dm, None));
        let actual: serde_json::Value = serde_json::from_str(&power_levels_event.content).expect("json");
        assert_eq!(actual, expected);

        let join_rules = matrix_store::current_state_event(&messenger, &room.id, "m.room.join_rules", "").expect("query").expect("exists");
        let join_rules_content: serde_json::Value = serde_json::from_str(&join_rules.content).expect("json");
        assert_eq!(join_rules_content["join_rule"], "invite");
    }

    #[test]
    fn legacy_dm_events_carry_the_legacy_conversation_id() {
        let (identity, social, mut messenger, conv) = base_fixture();
        let nonce = [0u8; dm_db::DM_NONCE_LEN];
        let msg = dm_db::create_message(&social, conv.id, conv.user_lo, &nonce, b"hello", "2026-09-01T00:01:00+00:00").expect("insert");

        migrate_legacy_dms(&mut messenger, &social, &identity, NOW).expect("migrate");

        let event_id = matrix_store::legacy_dm_message_event_id(&messenger, msg).expect("query").expect("mapped");
        let event = matrix_store::get_event(&messenger, &event_id).expect("query").expect("exists");
        let content: serde_json::Value = serde_json::from_str(&event.content).expect("json");
        assert_eq!(content["legacy_conversation_id"], serde_json::json!(conv.id));
    }

    #[test]
    fn legacy_key_state_events_carry_each_members_public_key() {
        let (identity, social, mut messenger, conv) = base_fixture();
        let lo_key = vec![1u8; dm_db::DM_PUBLIC_KEY_LEN];
        let hi_key = vec![2u8; dm_db::DM_PUBLIC_KEY_LEN];
        dm_db::upsert_identity_key(&social, conv.user_lo, &lo_key, "2026-09-01T00:00:00+00:00").expect("publish lo key");
        dm_db::upsert_identity_key(&social, conv.user_hi, &hi_key, "2026-09-01T00:00:00+00:00").expect("publish hi key");

        migrate_legacy_dms(&mut messenger, &social, &identity, NOW).expect("migrate");

        let room = matrix_store::room_by_legacy_dm_id(&messenger, conv.id).expect("query").expect("room exists");
        let lo_mxid = matrix_store::mxid_of(&messenger, conv.user_lo).expect("query").expect("registered");
        let hi_mxid = matrix_store::mxid_of(&messenger, conv.user_hi).expect("query").expect("registered");

        let lo_event = matrix_store::current_state_event(&messenger, &room.id, LEGACY_DM_KEY_EVENT_TYPE, &lo_mxid)
            .expect("query")
            .expect("lo key event exists");
        let lo_content: serde_json::Value = serde_json::from_str(&lo_event.content).expect("json");
        let lo_decoded = STANDARD.decode(lo_content["public_key_b64"].as_str().expect("string")).expect("valid base64");
        assert_eq!(lo_decoded, lo_key);
        assert_eq!(lo_content["legacy_conversation_id"], serde_json::json!(conv.id));

        let hi_event = matrix_store::current_state_event(&messenger, &room.id, LEGACY_DM_KEY_EVENT_TYPE, &hi_mxid)
            .expect("query")
            .expect("hi key event exists");
        let hi_content: serde_json::Value = serde_json::from_str(&hi_event.content).expect("json");
        let hi_decoded = STANDARD.decode(hi_content["public_key_b64"].as_str().expect("string")).expect("valid base64");
        assert_eq!(hi_decoded, hi_key);
        assert_eq!(hi_content["legacy_conversation_id"], serde_json::json!(conv.id));
    }

    #[test]
    fn read_receipts_never_overcount() {
        let (identity, social, mut messenger, conv) = base_fixture();
        let nonce = [0u8; dm_db::DM_NONCE_LEN];
        // Two messages from user 1 (conv.user_lo): only the first is read by user 2.
        let msg_a = dm_db::create_message(&social, conv.id, conv.user_lo, &nonce, b"a", "2026-09-01T00:01:00+00:00").expect("insert a");
        let _msg_b = dm_db::create_message(&social, conv.id, conv.user_lo, &nonce, b"b", "2026-09-01T00:02:00+00:00").expect("insert b");
        dm_db::mark_read(&social, conv.id, conv.user_hi, msg_a, "2026-09-01T00:05:00+00:00").expect("mark read up to a only");
        // One message from user 2, read by user 1.
        let msg_c = dm_db::create_message(&social, conv.id, conv.user_hi, &nonce, b"c", "2026-09-01T00:03:00+00:00").expect("insert c");
        dm_db::mark_read(&social, conv.id, conv.user_lo, msg_c, "2026-09-01T00:06:00+00:00").expect("mark read");

        migrate_legacy_dms(&mut messenger, &social, &identity, NOW).expect("migrate");

        let room = matrix_store::room_by_legacy_dm_id(&messenger, conv.id).expect("query").expect("room exists");
        let event_a = matrix_store::legacy_dm_message_event_id(&messenger, msg_a).expect("query").expect("mapped");
        let event_c = matrix_store::legacy_dm_message_event_id(&messenger, msg_c).expect("query").expect("mapped");

        let hi_receipt = matrix_store::get_receipt(&messenger, &room.id, conv.user_hi, ReceiptType::Read)
            .expect("query")
            .expect("receipt set");
        assert_eq!(hi_receipt.event_id, event_a, "user_hi's receipt must stop at the last message they actually read");

        let lo_receipt = matrix_store::get_receipt(&messenger, &room.id, conv.user_lo, ReceiptType::Read)
            .expect("query")
            .expect("receipt set");
        assert_eq!(lo_receipt.event_id, event_c);
    }

    #[test]
    fn m_direct_is_merged_not_overwritten() {
        let (identity, social, mut messenger, conv) = base_fixture();
        let existing = serde_json::json!({ "@someone-else:mylittlechart.org": ["!preexisting:mylittlechart.org"] }).to_string();
        matrix_store::upsert_account_data(&mut messenger, conv.user_lo, matrix_store::GLOBAL_ACCOUNT_DATA_ROOM, "m.direct", &existing)
            .expect("seed existing m.direct");

        migrate_legacy_dms(&mut messenger, &social, &identity, NOW).expect("migrate");

        let room = matrix_store::room_by_legacy_dm_id(&messenger, conv.id).expect("query").expect("room exists");
        let hi_mxid = matrix_store::mxid_of(&messenger, conv.user_hi).expect("query").expect("registered");

        let direct = matrix_store::get_account_data(&messenger, conv.user_lo, matrix_store::GLOBAL_ACCOUNT_DATA_ROOM, "m.direct")
            .expect("query")
            .expect("m.direct exists");
        let content: serde_json::Value = serde_json::from_str(&direct.content).expect("json");
        assert_eq!(content["@someone-else:mylittlechart.org"], serde_json::json!(["!preexisting:mylittlechart.org"]));
        assert_eq!(content[&hi_mxid], serde_json::json!([room.id]));
    }

    #[test]
    fn conversation_with_a_deleted_user_is_skipped_and_reported() {
        let identity = identity_conn();
        add_user(&identity, 1, "0000000000000000000000000000lo1");
        // user 2 (user_hi) has no row at all — a deleted account.
        let social = social_conn();
        let conv = dm_db::get_or_create_conversation(&social, 1, 2, "2026-09-01T00:00:00+00:00").expect("create conversation");
        let mut messenger = messenger_conn();

        let report = migrate_legacy_dms(&mut messenger, &social, &identity, NOW).expect("migrate");
        assert_eq!(report.conversations_migrated, 0);
        assert_eq!(report.conversations_skipped, 1);
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].conversation_id, conv.id);
        assert_eq!(report.skipped[0].reason, "user 2 no longer exists");

        assert!(matrix_store::room_by_legacy_dm_id(&messenger, conv.id).expect("query").is_none());
    }

    #[test]
    fn second_run_is_a_noop_with_identical_ids() {
        let (identity, social, mut messenger, conv) = base_fixture();
        let nonce = [0u8; dm_db::DM_NONCE_LEN];
        dm_db::create_message(&social, conv.id, conv.user_lo, &nonce, b"one", "2026-09-01T00:01:00+00:00").expect("insert 1");
        dm_db::create_message(&social, conv.id, conv.user_hi, &nonce, b"two", "2026-09-01T00:02:00+00:00").expect("insert 2");

        migrate_legacy_dms(&mut messenger, &social, &identity, NOW).expect("first run");
        let room_id_first = matrix_store::room_by_legacy_dm_id(&messenger, conv.id).expect("query").expect("room exists").id;
        let event_ids_first: Vec<String> = (1..=2)
            .map(|id| matrix_store::legacy_dm_message_event_id(&messenger, id).expect("query").expect("mapped"))
            .collect();

        let report = migrate_legacy_dms(&mut messenger, &social, &identity, NOW).expect("second run");
        assert_eq!(report, MigrationReport::default());

        let room_id_second = matrix_store::room_by_legacy_dm_id(&messenger, conv.id).expect("query").expect("room exists").id;
        let event_ids_second: Vec<String> = (1..=2)
            .map(|id| matrix_store::legacy_dm_message_event_id(&messenger, id).expect("query").expect("mapped"))
            .collect();
        assert_eq!(room_id_first, room_id_second);
        assert_eq!(event_ids_first, event_ids_second);
    }

    #[test]
    fn messages_keep_original_timestamps_and_order() {
        let (identity, social, mut messenger, conv) = base_fixture();
        let nonce = [0u8; dm_db::DM_NONCE_LEN];
        let msg1 = dm_db::create_message(&social, conv.id, conv.user_lo, &nonce, b"first", "2026-09-01T00:01:00+00:00").expect("insert 1");
        let msg2 = dm_db::create_message(&social, conv.id, conv.user_hi, &nonce, b"second", "2026-09-01T00:02:00+00:00").expect("insert 2");
        let msg3 = dm_db::create_message(&social, conv.id, conv.user_lo, &nonce, b"third", "2026-09-01T00:03:00+00:00").expect("insert 3");

        migrate_legacy_dms(&mut messenger, &social, &identity, NOW).expect("migrate");

        let event1_id = matrix_store::legacy_dm_message_event_id(&messenger, msg1).expect("query").expect("mapped");
        let event2_id = matrix_store::legacy_dm_message_event_id(&messenger, msg2).expect("query").expect("mapped");
        let event3_id = matrix_store::legacy_dm_message_event_id(&messenger, msg3).expect("query").expect("mapped");
        let event1 = matrix_store::get_event(&messenger, &event1_id).expect("query").expect("exists");
        let event2 = matrix_store::get_event(&messenger, &event2_id).expect("query").expect("exists");
        let event3 = matrix_store::get_event(&messenger, &event3_id).expect("query").expect("exists");

        assert_eq!(event1.origin_server_ts, rfc3339_to_millis("2026-09-01T00:01:00+00:00").expect("parse"));
        assert_eq!(event2.origin_server_ts, rfc3339_to_millis("2026-09-01T00:02:00+00:00").expect("parse"));
        assert_eq!(event3.origin_server_ts, rfc3339_to_millis("2026-09-01T00:03:00+00:00").expect("parse"));
        assert!(event1.stream_id < event2.stream_id);
        assert!(event2.stream_id < event3.stream_id);
    }

    // ---- P15: catch-up + live bridge ----

    #[test]
    fn catch_up_appends_only_new_legacy_messages_once() {
        let (identity, social, mut messenger, conv) = base_fixture();
        let nonce = [0u8; dm_db::DM_NONCE_LEN];
        dm_db::create_message(&social, conv.id, conv.user_lo, &nonce, b"one", "2026-09-01T00:01:00+00:00").expect("insert 1");
        migrate_legacy_dms(&mut messenger, &social, &identity, NOW).expect("initial migration");

        dm_db::create_message(&social, conv.id, conv.user_hi, &nonce, b"two", "2026-09-01T00:02:00+00:00").expect("insert 2");
        dm_db::create_message(&social, conv.id, conv.user_lo, &nonce, b"three", "2026-09-01T00:03:00+00:00").expect("insert 3");

        let room = matrix_store::room_by_legacy_dm_id(&messenger, conv.id).expect("query").expect("room exists");
        let legacy_conv = LegacyConversation { id: conv.id, user_lo: conv.user_lo, user_hi: conv.user_hi, created_at: conv.created_at.clone() };

        let counts = catch_up_conversation(&mut messenger, &social, &room.id, &legacy_conv).expect("catch up");
        assert_eq!(counts.messages_imported, 2);

        let counts_again = catch_up_conversation(&mut messenger, &social, &room.id, &legacy_conv).expect("catch up again");
        assert_eq!(counts_again.messages_imported, 0);

        let map_rows: i64 = messenger.query_row("SELECT COUNT(*) FROM legacy_dm_message_map", [], |r| r.get(0)).expect("count");
        assert_eq!(map_rows, 3, "one map row per dm_messages row across both passes");
    }

    #[test]
    fn catch_up_content_is_identical_to_migration_content() {
        let (identity, social, mut messenger, conv) = base_fixture();
        let nonce = [7u8; dm_db::DM_NONCE_LEN];
        let ciphertext = b"same payload shape";
        let migrated_msg =
            dm_db::create_message(&social, conv.id, conv.user_lo, &nonce, ciphertext, "2026-09-01T00:01:00+00:00").expect("insert 1");
        migrate_legacy_dms(&mut messenger, &social, &identity, NOW).expect("initial migration");

        let caught_up_msg =
            dm_db::create_message(&social, conv.id, conv.user_lo, &nonce, ciphertext, "2026-09-01T00:02:00+00:00").expect("insert 2");
        let room = matrix_store::room_by_legacy_dm_id(&messenger, conv.id).expect("query").expect("room exists");
        let legacy_conv = LegacyConversation { id: conv.id, user_lo: conv.user_lo, user_hi: conv.user_hi, created_at: conv.created_at.clone() };
        let counts = catch_up_conversation(&mut messenger, &social, &room.id, &legacy_conv).expect("catch up");
        assert_eq!(counts.messages_imported, 1);

        let migrated_event_id = matrix_store::legacy_dm_message_event_id(&messenger, migrated_msg).expect("query").expect("mapped");
        let caught_up_event_id = matrix_store::legacy_dm_message_event_id(&messenger, caught_up_msg).expect("query").expect("mapped");
        let migrated_event = matrix_store::get_event(&messenger, &migrated_event_id).expect("query").expect("exists");
        let caught_up_event = matrix_store::get_event(&messenger, &caught_up_event_id).expect("query").expect("exists");

        let migrated_content: serde_json::Value = serde_json::from_str(&migrated_event.content).expect("json");
        let caught_up_content: serde_json::Value = serde_json::from_str(&caught_up_event.content).expect("json");

        // Same shape, same conversation, same nonce/ciphertext — the only
        // field that legitimately differs is `legacy_message_id`, since
        // these are two different `dm_messages` rows (proves
        // `legacy_dm_message_import` is the one shared source both the
        // full-migration and catch-up paths call).
        assert_eq!(migrated_content["legacy_conversation_id"], caught_up_content["legacy_conversation_id"]);
        assert_eq!(migrated_content["nonce_b64"], caught_up_content["nonce_b64"]);
        assert_eq!(migrated_content["ciphertext_b64"], caught_up_content["ciphertext_b64"]);
        assert_eq!(migrated_content["legacy_message_id"], serde_json::json!(migrated_msg));
        assert_eq!(caught_up_content["legacy_message_id"], serde_json::json!(caught_up_msg));
        assert_eq!(migrated_event.event_type, "org.mylittlechart.legacy_dm");
        assert_eq!(caught_up_event.event_type, "org.mylittlechart.legacy_dm");
        assert_eq!(caught_up_event.origin_server_ts, rfc3339_to_millis("2026-09-01T00:02:00+00:00").expect("parse"));
    }

    #[test]
    fn boot_migration_catches_up_already_migrated_conversations() {
        let (identity, social, mut messenger, conv) = base_fixture();
        let nonce = [0u8; dm_db::DM_NONCE_LEN];
        dm_db::create_message(&social, conv.id, conv.user_lo, &nonce, b"one", "2026-09-01T00:01:00+00:00").expect("insert 1");

        let first = migrate_legacy_dms(&mut messenger, &social, &identity, NOW).expect("first boot");
        assert_eq!(first.conversations_migrated, 1);
        assert_eq!(first.messages_caught_up, 0);

        // A message arrives through the OLD `/dm/conversations/*` route
        // after boot — lands only in `social.db`, exactly like
        // `routes::dm::create_message`'s own insert, until the live bridge
        // or the next boot's catch-up closes the gap.
        dm_db::create_message(&social, conv.id, conv.user_hi, &nonce, b"two", "2026-09-01T00:02:00+00:00").expect("insert 2");

        let second = migrate_legacy_dms(&mut messenger, &social, &identity, NOW).expect("second boot");
        assert_eq!(second.conversations_migrated, 0, "the conversation already has a room");
        assert_eq!(second.conversations_skipped, 0);
        assert_eq!(second.messages_caught_up, 1);

        let event_id = matrix_store::legacy_dm_message_event_id(&messenger, 2).expect("query").expect("mapped — boot caught it up");
        let event = matrix_store::get_event(&messenger, &event_id).expect("query").expect("exists");
        assert_eq!(event.event_type, "org.mylittlechart.legacy_dm");
    }
}

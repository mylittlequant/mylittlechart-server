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
//! `routes::dm`'s legacy send-message and read-marker routes keep working
//! for native clients that have not moved to the Matrix subset yet — any
//! message or read marker they accept after boot lands in `social.db` only,
//! never in the migrated room, unless something re-runs the import for that
//! one conversation. [`catch_up_conversation`] is that re-run:
//!
//! - It appends every `dm_messages` row not yet in `legacy_dm_message_map`
//!   — found via a cursor
//!   ([`mylittlechart_server::matrix_store::highest_mapped_legacy_message_id`]),
//!   never a re-scan of every message in the conversation — using the exact
//!   same content/timestamp derivation [`migrate_one_conversation`] uses
//!   ([`legacy_dm_message_import`], factored out so the two paths can never
//!   drift).
//! - It re-derives BOTH readers' `m.read` receipts straight off `social.db`'s
//!   own `read_at` column ([`conversation_read_receipts`], one indexed query
//!   per reader), not just messages new to this pass — a message read only
//!   AFTER it was already bridged in an earlier pass must still move the
//!   room's receipt (manager review, P15).
//!
//! [`migrate_legacy_dms`] runs it on every `AlreadyMigrated` conversation at
//! boot, closing any gap since the last run. Two live entry points run it
//! right after their own `social.db` write commits, so an already-open
//! `/sync` long-poll on an updated client sees the change at once:
//! [`bridge_legacy_dm_send`] (a full first-time migration if the
//! conversation has no room yet, else a catch-up) after
//! `routes::dm::create_message`'s insert, and [`catch_up_legacy_dm_read`]
//! (catch-up ONLY — a read marker alone never creates a room) after
//! `routes::dm::mark_read`'s update. A failure in either is caught, logged,
//! and never fails the legacy call — the next boot's catch-up closes the
//! gap.

use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rusqlite::{params, Connection, OptionalExtension};

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

/// `pub(crate)`, not module-private — [`bridge_legacy_dm_send`]'s `Result`
/// crosses into `routes::dm` (P15), so this type must be at least as visible
/// as that function's own `pub(crate)`.
#[derive(Debug)]
pub(crate) enum ConversationMigrationError {
    Db(rusqlite::Error),
    Store(matrix_store::MatrixStoreError),
    BadTimestamp(String),
    /// [`bridge_legacy_dm_send`] only: the conversation could not be
    /// migrated/caught up for a non-database reason (mirrors
    /// [`ConversationOutcome::Skipped`]'s own reason) — never produced by
    /// [`migrate_legacy_dms`]'s own boot loop, which turns that outcome into
    /// a [`SkippedConversation`] report row instead of an `Err`.
    Skipped(String),
}

impl fmt::Display for ConversationMigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConversationMigrationError::Db(e) => write!(f, "database error: {e}"),
            ConversationMigrationError::Store(e) => write!(f, "matrix store error: {e:?}"),
            ConversationMigrationError::BadTimestamp(raw) => write!(f, "unparseable timestamp: {raw:?}"),
            ConversationMigrationError::Skipped(reason) => write!(f, "skipped: {reason}"),
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

impl From<&dm_db::DmConversation> for LegacyConversation {
    fn from(conv: &dm_db::DmConversation) -> Self {
        LegacyConversation { id: conv.id, user_lo: conv.user_lo, user_hi: conv.user_hi, created_at: conv.created_at.clone() }
    }
}

fn list_dm_conversations(social: &Connection) -> rusqlite::Result<Vec<LegacyConversation>> {
    let mut stmt = social.prepare("SELECT id, user_lo, user_hi, created_at FROM dm_conversations ORDER BY id ASC")?;
    let rows = stmt.query_map([], |row| {
        Ok(LegacyConversation { id: row.get(0)?, user_lo: row.get(1)?, user_hi: row.get(2)?, created_at: row.get(3)? })
    })?;
    rows.collect()
}

/// A `dm_messages` row's content half — never `read_at` (P15: every read
/// position is now resolved straight off `social.db` by
/// [`highest_read_message`]/[`conversation_read_receipts`], not by carrying
/// this column through a struct nothing else reads).
struct LegacyMessage {
    id: i64,
    sender_user_id: i64,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    created_at: String,
}

/// Every `dm_messages` row of `conversation_id` with `id > after_id`, in
/// ascending order — pass `0` for "from the start" (every real
/// `dm_messages.id` is a positive `AUTOINCREMENT` value, so `id > 0` matches
/// everything). [`migrate_one_conversation`] (a first-time migration) always
/// passes `0`; [`catch_up_conversation`] passes its own cursor
/// ([`mylittlechart_server::matrix_store::highest_mapped_legacy_message_id`]),
/// so a catch-up never re-lists a message it (or a prior pass) already
/// imported.
fn list_dm_messages(social: &Connection, conversation_id: i64, after_id: i64) -> rusqlite::Result<Vec<LegacyMessage>> {
    let mut stmt = social.prepare(
        "SELECT id, sender_user_id, nonce, ciphertext, created_at
         FROM dm_messages WHERE conversation_id = ?1 AND id > ?2 ORDER BY id ASC",
    )?;
    let rows = stmt.query_map(params![conversation_id, after_id], |row| {
        Ok(LegacyMessage {
            id: row.get(0)?,
            sender_user_id: row.get(1)?,
            nonce: row.get(2)?,
            ciphertext: row.get(3)?,
            created_at: row.get(4)?,
        })
    })?;
    rows.collect()
}

fn rfc3339_to_millis(raw: &str) -> Result<i64, ConversationMigrationError> {
    chrono::DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.timestamp_millis())
        .map_err(|_| ConversationMigrationError::BadTimestamp(raw.to_string()))
}

/// The highest-id `dm_messages` row `sender_user_id` sent in `conversation_id`
/// that has `read_at` set — i.e. the furthest the OTHER party (the reader)
/// has read, straight off `social.db` (manager review, P15: this must
/// consider EVERY read message ever, not just ones touched by the current
/// pass, so a message marked read long after it was already bridged still
/// moves the receipt). One indexed query, never a scan of the conversation's
/// messages. `None` if `sender_user_id` has sent nothing the other party has
/// read yet.
fn highest_read_message(social: &Connection, conversation_id: i64, sender_user_id: i64) -> rusqlite::Result<Option<(i64, String)>> {
    social
        .query_row(
            "SELECT id, read_at FROM dm_messages
             WHERE conversation_id = ?1 AND sender_user_id = ?2 AND read_at IS NOT NULL
             ORDER BY id DESC LIMIT 1",
            params![conversation_id, sender_user_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
}

/// Both readers' current furthest-read position in `conv`
/// ([`highest_read_message`], once per reader) — the shared source
/// [`migrate_one_conversation`] and [`catch_up_conversation`] both build
/// their `extras.receipts`/`receipts` from, so neither can drift from
/// "read straight off `social.db`, never from a HashMap built while
/// iterating some SUBSET of messages".
fn conversation_read_receipts(
    social: &Connection,
    conv: &LegacyConversation,
) -> Result<Vec<matrix_store::LegacyDmReadReceipt>, ConversationMigrationError> {
    let mut receipts = Vec::new();
    for (reader_user_id, sender_user_id) in [(conv.user_hi, conv.user_lo), (conv.user_lo, conv.user_hi)] {
        if let Some((up_to_legacy_message_id, read_at)) = highest_read_message(social, conv.id, sender_user_id)? {
            let ts_ms = rfc3339_to_millis(&read_at)?;
            receipts.push(matrix_store::LegacyDmReadReceipt { reader_user_id, up_to_legacy_message_id, ts_ms });
        }
    }
    Ok(receipts)
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

    let messages = list_dm_messages(social, conv.id, 0)?;
    let message_imports: Vec<matrix_store::LegacyDmMessageImport> =
        messages.iter().map(|message| legacy_dm_message_import(conv.id, message)).collect::<Result<_, _>>()?;
    let receipts = conversation_read_receipts(social, conv)?;

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
// can never drift on content shape or `origin_server_ts` derivation.
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

// ============================================================================
// Catch-up (P15) — an already-migrated conversation's gap-closer
// ============================================================================

/// Catch up ONE already-migrated conversation's Matrix room:
///
/// - Every `dm_messages` row with `id` past
///   [`mylittlechart_server::matrix_store::highest_mapped_legacy_message_id`]
///   ([`list_dm_messages`]'s own cursor parameter — never a re-scan of every
///   message in the conversation) is appended as an
///   `org.mylittlechart.legacy_dm` timeline event.
/// - BOTH readers' `m.read` receipts are re-derived straight off
///   `social.db`'s own `read_at` column ([`conversation_read_receipts`]),
///   not just messages new to THIS pass — a message read only after it was
///   already bridged in an earlier pass must still move the receipt
///   (manager review, P15).
///
/// Both land in ONE transaction
/// ([`mylittlechart_server::matrix_store::catch_up_dm_conversation`]),
/// which resolves each receipt's target through the FULL
/// `legacy_dm_message_map` (not just this call's own newly-inserted rows),
/// so an old message's receipt still resolves correctly.
///
/// `room_id` must already be `conv`'s migrated room — every caller
/// ([`migrate_one_conversation`], [`bridge_legacy_dm_send`],
/// [`catch_up_legacy_dm_read`]) has just confirmed this via
/// [`matrix_store::room_by_legacy_dm_id`]. Both counts are `0` for the
/// routine case: nothing new and no read-position change since `conv`'s room
/// was last touched.
fn catch_up_conversation(
    messenger: &mut Connection,
    social: &Connection,
    room_id: &str,
    conv: &LegacyConversation,
) -> Result<matrix_store::DmMigrationCounts, ConversationMigrationError> {
    let after_id = matrix_store::highest_mapped_legacy_message_id(messenger, room_id)?.unwrap_or(0);
    let new_messages = list_dm_messages(social, conv.id, after_id)?;
    let message_imports: Vec<matrix_store::LegacyDmMessageImport> =
        new_messages.iter().map(|message| legacy_dm_message_import(conv.id, message)).collect::<Result<_, _>>()?;

    let receipts = conversation_read_receipts(social, conv)?;

    if message_imports.is_empty() && receipts.is_empty() {
        return Ok(matrix_store::DmMigrationCounts::default());
    }

    let counts = matrix_store::catch_up_dm_conversation(messenger, room_id, &message_imports, &receipts)?;
    Ok(counts)
}

// ============================================================================
// Live bridge (P15) — `routes::dm::create_message`'s send path and
// `routes::dm::mark_read`'s read-marker path
// ============================================================================

/// Bridge one legacy DM send (`routes::dm::create_message`'s own insert,
/// already committed to `social.db` by the time this runs) into its Matrix
/// room: migrates the conversation from scratch if this is its first message
/// ever ([`migrate_one_conversation`] then naturally picks up the
/// just-inserted row too, since it reads every `dm_messages` row for the
/// conversation), or [`catch_up_conversation`]s it if a room already exists.
/// Returns the affected room id, for the caller's own live-registry wake
/// (`routes::dm` reuses
/// [`crate::routes::matrix::rooms::member_and_invited_ids`], exactly the way
/// `routes::matrix::messaging` wakes a room after a native Matrix send).
///
/// Per this module's own doc ("a bridge failure must NOT fail the legacy
/// send"): this function's `Err` is `routes::dm`'s to log once (with the
/// conversation id) and swallow, never to turn into an HTTP failure — the
/// legacy send already committed before this ever runs, and the next boot's
/// [`migrate_legacy_dms`] pass closes any gap this call leaves behind.
pub(crate) fn bridge_legacy_dm_send(
    messenger: &mut Connection,
    social: &Connection,
    identity: &Connection,
    conversation: &dm_db::DmConversation,
    now: &str,
) -> Result<String, ConversationMigrationError> {
    let conv = LegacyConversation::from(conversation);

    if let Some(room) = matrix_store::room_by_legacy_dm_id(messenger, conv.id)? {
        catch_up_conversation(messenger, social, &room.id, &conv)?;
        return Ok(room.id);
    }

    match migrate_one_conversation(messenger, social, identity, &conv, now)? {
        ConversationOutcome::Skipped(reason) => Err(ConversationMigrationError::Skipped(reason)),
        // A race with another writer is not possible under this module's
        // single-writer discipline (see the module doc) — handled
        // defensively rather than assumed, same posture
        // `routes::matrix::messaging::apply_send` takes for its own
        // "cannot happen" dedup race.
        ConversationOutcome::Migrated { .. } | ConversationOutcome::AlreadyMigrated { .. } => {
            matrix_store::room_by_legacy_dm_id(messenger, conv.id)?
                .map(|room| room.id)
                .ok_or_else(|| ConversationMigrationError::Skipped("migrated but room lookup failed".to_string()))
        }
    }
}

/// Bridge one legacy `POST /dm/conversations/{id}/read` update
/// (`routes::dm::mark_read`'s own update, already committed to `social.db`
/// by the time this runs). Unlike [`bridge_legacy_dm_send`], this NEVER
/// migrates a conversation that has no room yet — a read marker alone must
/// never be what creates a room (the FIRST MESSAGE does that, per
/// [`bridge_legacy_dm_send`]). Returns `Ok(None)` when `conversation` has no
/// migrated room yet — routine, not an error: nothing to catch up, nothing
/// for the caller to wake. Returns `Ok(Some(room_id))` after a successful
/// catch-up — [`catch_up_conversation`] re-derives every reader's receipt
/// straight from `social.db`'s own `read_at` column, so this closes the gap
/// even when there is no new MESSAGE to import, only a changed read
/// position (manager review, P15).
pub(crate) fn catch_up_legacy_dm_read(
    messenger: &mut Connection,
    social: &Connection,
    conversation: &dm_db::DmConversation,
) -> Result<Option<String>, ConversationMigrationError> {
    let Some(room) = matrix_store::room_by_legacy_dm_id(messenger, conversation.id)? else {
        return Ok(None);
    };
    let conv = LegacyConversation::from(conversation);
    catch_up_conversation(messenger, social, &room.id, &conv)?;
    Ok(Some(room.id))
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
        let legacy_conv = LegacyConversation::from(&conv);

        let counts = catch_up_conversation(&mut messenger, &social, &room.id, &legacy_conv).expect("catch up");
        assert_eq!(counts.messages_imported, 2);

        let counts_again = catch_up_conversation(&mut messenger, &social, &room.id, &legacy_conv).expect("catch up again");
        assert_eq!(counts_again.messages_imported, 0);

        let map_rows: i64 = messenger.query_row("SELECT COUNT(*) FROM legacy_dm_message_map", [], |r| r.get(0)).expect("count");
        assert_eq!(map_rows, 3, "one map row per dm_messages row across both passes");
    }

    #[test]
    fn catch_up_lists_only_messages_newer_than_the_last_bridged_one() {
        let (identity, social, mut messenger, conv) = base_fixture();
        let nonce = [0u8; dm_db::DM_NONCE_LEN];
        let msg1 = dm_db::create_message(&social, conv.id, conv.user_lo, &nonce, b"one", "2026-09-01T00:01:00+00:00").expect("insert 1");
        migrate_legacy_dms(&mut messenger, &social, &identity, NOW).expect("initial migration");

        let room = matrix_store::room_by_legacy_dm_id(&messenger, conv.id).expect("query").expect("room exists");
        assert_eq!(matrix_store::highest_mapped_legacy_message_id(&messenger, &room.id).expect("query"), Some(msg1));

        let msg2 = dm_db::create_message(&social, conv.id, conv.user_hi, &nonce, b"two", "2026-09-01T00:02:00+00:00").expect("insert 2");
        let legacy_conv = LegacyConversation::from(&conv);
        let counts = catch_up_conversation(&mut messenger, &social, &room.id, &legacy_conv).expect("catch up");
        assert_eq!(counts.messages_imported, 1, "only msg2 is past the cursor");
        assert_eq!(matrix_store::highest_mapped_legacy_message_id(&messenger, &room.id).expect("query"), Some(msg2));

        // A second catch-up with nothing new must not re-list msg1 or msg2.
        let counts_again = catch_up_conversation(&mut messenger, &social, &room.id, &legacy_conv).expect("catch up again");
        assert_eq!(counts_again.messages_imported, 0);
    }

    #[test]
    fn read_after_migration_advances_the_matrix_receipt() {
        let (identity, social, mut messenger, conv) = base_fixture();
        let nonce = [0u8; dm_db::DM_NONCE_LEN];
        let msg = dm_db::create_message(&social, conv.id, conv.user_lo, &nonce, b"hello", "2026-09-01T00:01:00+00:00").expect("insert");
        migrate_legacy_dms(&mut messenger, &social, &identity, NOW).expect("initial migration");

        let room = matrix_store::room_by_legacy_dm_id(&messenger, conv.id).expect("query").expect("room exists");
        // Nobody had read anything at migration time — no receipt yet.
        assert!(matrix_store::get_receipt(&messenger, &room.id, conv.user_hi, ReceiptType::Read).expect("query").is_none());

        // The OLD client marks it read AFTER the message was already bridged
        // — this must still move the Matrix receipt (manager review, P15).
        dm_db::mark_read(&social, conv.id, conv.user_hi, msg, "2026-09-01T00:05:00+00:00").expect("mark read");

        let legacy_conv = LegacyConversation::from(&conv);
        let counts = catch_up_conversation(&mut messenger, &social, &room.id, &legacy_conv).expect("catch up");
        assert_eq!(counts.messages_imported, 0, "the message itself was already bridged");
        assert_eq!(counts.receipts_set, 1);

        let event_id = matrix_store::legacy_dm_message_event_id(&messenger, msg).expect("query").expect("mapped");
        let receipt = matrix_store::get_receipt(&messenger, &room.id, conv.user_hi, ReceiptType::Read).expect("query").expect("receipt now set");
        assert_eq!(receipt.event_id, event_id);

        // A second, no-op catch-up must never move the receipt backwards —
        // `upsert_receipt_in_tx`'s own guarantee, reused here rather than
        // re-derived.
        let counts_again = catch_up_conversation(&mut messenger, &social, &room.id, &legacy_conv).expect("catch up again");
        assert_eq!(counts_again.receipts_set, 1, "still resolves and re-confirms the SAME position, not a backward move");
        let receipt_again = matrix_store::get_receipt(&messenger, &room.id, conv.user_hi, ReceiptType::Read).expect("query").expect("receipt still set");
        assert_eq!(receipt_again.event_id, event_id);
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
        let legacy_conv = LegacyConversation::from(&conv);
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

    #[test]
    fn bridge_legacy_dm_send_migrates_the_first_message_then_catches_up_the_next() {
        let (identity, social, mut messenger, conv) = base_fixture();
        let nonce = [0u8; dm_db::DM_NONCE_LEN];
        dm_db::create_message(&social, conv.id, conv.user_lo, &nonce, b"first", "2026-09-01T00:01:00+00:00").expect("insert 1");

        // No room yet — the first send bridges via a full migration.
        let room_id_first = bridge_legacy_dm_send(&mut messenger, &social, &identity, &conv, NOW).expect("bridge first send");
        let room = matrix_store::room_by_legacy_dm_id(&messenger, conv.id).expect("query").expect("room exists");
        assert_eq!(room_id_first, room.id);
        let event_id_1 = matrix_store::legacy_dm_message_event_id(&messenger, 1).expect("query").expect("mapped");

        dm_db::create_message(&social, conv.id, conv.user_hi, &nonce, b"second", "2026-09-01T00:02:00+00:00").expect("insert 2");

        // A room already exists — the second send bridges via catch-up, not
        // a second migration.
        let room_id_second = bridge_legacy_dm_send(&mut messenger, &social, &identity, &conv, NOW).expect("bridge second send");
        assert_eq!(room_id_second, room.id);
        let event_id_2 = matrix_store::legacy_dm_message_event_id(&messenger, 2).expect("query").expect("mapped");
        assert_ne!(event_id_1, event_id_2);

        let room_count: i64 = messenger.query_row("SELECT COUNT(*) FROM rooms", [], |r| r.get(0)).expect("count");
        assert_eq!(room_count, 1, "the second send must not create a second room");
    }

    #[test]
    fn bridge_legacy_dm_send_reports_a_skipped_conversation_as_an_error() {
        let identity = identity_conn();
        add_user(&identity, 1, "0000000000000000000000000000lo1");
        // user 2 (user_hi) has no row at all — a deleted account, same
        // fixture `conversation_with_a_deleted_user_is_skipped_and_reported`
        // uses.
        let social = social_conn();
        let conv = dm_db::get_or_create_conversation(&social, 1, 2, "2026-09-01T00:00:00+00:00").expect("create conversation");
        let nonce = [0u8; dm_db::DM_NONCE_LEN];
        dm_db::create_message(&social, conv.id, 1, &nonce, b"hello", "2026-09-01T00:01:00+00:00").expect("insert message");
        let mut messenger = messenger_conn();

        let err = bridge_legacy_dm_send(&mut messenger, &social, &identity, &conv, NOW).expect_err("no such user 2 — must refuse, not panic");
        assert!(matches!(err, ConversationMigrationError::Skipped(_)), "got {err:?}");
        assert!(matrix_store::room_by_legacy_dm_id(&messenger, conv.id).expect("query").is_none());
    }
}

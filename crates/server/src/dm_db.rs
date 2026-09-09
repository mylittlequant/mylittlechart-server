//! Direct-message storage — end-to-end encrypted, server holds ciphertext
//! only (owner ruling 2026-09-05, `docs/mlc/plans/social-sharing-access-
//! gates-and-agent-control-2026-09-05.md` §3 item 6 + §6). Lives in
//! `social.db` (the same physically-separate database `social_db.rs`
//! owns — see that module's doc for the storage split), created by
//! [`create_dm_schema`], called once from `social_db::init_social_db`.
//!
//! The client-side cryptography is fixed by `mylittlechart`'s `mlc-vault`
//! crate (`crates/mlc-vault/src/dm.rs`): X25519 identity keypairs (32-byte
//! public keys), a per-conversation key via ECDH + HKDF-SHA256, and
//! AES-256-GCM sealed messages (`DmCiphertext { nonce: [u8; 12], ciphertext:
//! Vec<u8> }`) with AAD binding the conversation id and sender id. This
//! module never sees a plaintext byte, a private key, or a conversation
//! key — it stores exactly the three columns a `DmCiphertext` has (nonce,
//! ciphertext) plus who sent it and when.
//!
//! # What the server can and cannot see
//!
//! **Visible (metadata):** who published a DM identity key and its
//! fingerprint (`dm_identity_keys`); which two accounts share a
//! conversation and when it was created/last active (`dm_conversations`);
//! who sent each message, its size, and when (`dm_messages`'s
//! `sender_user_id`/`created_at`/`read_at`). `routes::dm` states this in
//! its own doc and the client UI is expected to say so too (plan §6).
//!
//! **Never visible: the message contents.** `nonce`/`ciphertext` are opaque
//! blobs to every piece of code in this process — there is no key on the
//! server side to open them with. This is also why **moderation of DM
//! content is impossible by design**: an admin/moderator role (see
//! `social_db::Role`) can act on forum threads because their bodies are
//! plaintext in `social.db`; a DM's body never is, so there is no hide/edit
//! action for one to reach. The only lever the server has over an abusive
//! DM user is the same one it has over any account — revoking paid status,
//! which closes [`crate::routes::dm`]'s access gate entirely.
//!
//! # Cross-database rule (plan §5)
//!
//! Same rule `social_db.rs` documents: this module stores only `user_id`
//! integers, never a display name — labels are looked up live from the
//! identity connection by `routes::dm` (via
//! `db::effective_label_for_user`/`db::get_user_public_id`), the same
//! two-connections-never-held-at-once discipline `routes::forum_v2` uses.

use rusqlite::{params, Connection, OptionalExtension, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

// ============================================================================
// Schema
// ============================================================================

/// Create every DM table and index this module needs — idempotent
/// (`IF NOT EXISTS` throughout), so it runs on every boot. Called from
/// `social_db::init_social_db` right after `create_social_schema`, and
/// directly by this module's own tests against a plain in-memory
/// connection (no SQLCipher key needed for schema creation).
pub(crate) fn create_dm_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        -- One published identity keypair's public half per account. A
        -- second `upsert_identity_key` call rotates it in place (`rotated_at`
        -- stamped, `created_at` untouched) rather than inserting a second
        -- row — a conversation's peer always resolves today's key, by
        -- design; there is no history of prior keys to look up.
        CREATE TABLE IF NOT EXISTS dm_identity_keys (
            user_id     INTEGER PRIMARY KEY,
            public_key  BLOB NOT NULL,
            fingerprint TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            rotated_at  TEXT
        );

        -- `user_lo`/`user_hi` is the pair sorted ascending (see
        -- `ordered_pair`) so the same two accounts, regardless of who
        -- started the conversation or which order a caller names them in,
        -- always resolve to the same row — the UNIQUE constraint is what
        -- makes `get_or_create_conversation` idempotent. The CHECK is a
        -- second line of defence against a future call site that forgets to
        -- order its arguments: such a bug would otherwise silently create a
        -- duplicate conversation for the same pair instead of failing loudly.
        CREATE TABLE IF NOT EXISTS dm_conversations (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_lo         INTEGER NOT NULL,
            user_hi         INTEGER NOT NULL,
            created_at      TEXT NOT NULL,
            last_message_at TEXT,
            UNIQUE(user_lo, user_hi),
            CHECK (user_lo < user_hi)
        );

        CREATE INDEX IF NOT EXISTS idx_dm_conversations_user_lo ON dm_conversations(user_lo);
        CREATE INDEX IF NOT EXISTS idx_dm_conversations_user_hi ON dm_conversations(user_hi);

        -- `nonce`/`ciphertext` are the two fields of a `mlc_vault::dm::
        -- DmCiphertext`, stored verbatim — see this module's doc comment on
        -- why nothing here can ever read them. `read_at` is stamped only on
        -- a message whose `sender_user_id` is NOT the reader (see
        -- `mark_read`) — a sender's own messages are never "unread" to
        -- itself.
        CREATE TABLE IF NOT EXISTS dm_messages (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER NOT NULL REFERENCES dm_conversations(id),
            sender_user_id  INTEGER NOT NULL,
            nonce           BLOB NOT NULL,
            ciphertext      BLOB NOT NULL,
            created_at      TEXT NOT NULL,
            read_at         TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_dm_messages_conversation ON dm_messages(conversation_id, id);
        "#,
    )
}

// ============================================================================
// Limits
// ============================================================================

/// X25519 public key length — the wire size `mlc_vault::dm::DmIdentity`
/// publishes.
pub const DM_PUBLIC_KEY_LEN: usize = 32;

/// AES-256-GCM nonce length — `mlc_vault::dm::DmCiphertext::nonce`'s size.
pub const DM_NONCE_LEN: usize = 12;

/// Ceiling on one message's ciphertext, in bytes. Generous for a chat
/// message (GCM only adds a 16-byte tag on top of the plaintext) while
/// bounding one row's storage cost regardless of what a client sends.
pub const DM_MAX_CIPHERTEXT_BYTES: usize = 16 * 1024;

/// Per-sender anti-abuse ceiling: messages accepted across every
/// conversation, per rolling day. Generous for real conversation use,
/// bounded against a compromised or scripted sender.
pub const DM_MESSAGE_DAILY_LIMIT: i64 = 300;

// ============================================================================
// Identity keys
// ============================================================================

/// One row of `dm_identity_keys`.
#[derive(Debug, Clone, PartialEq)]
pub struct DmIdentityKey {
    pub user_id: i64,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub created_at: String,
    pub rotated_at: Option<String>,
}

/// Why [`upsert_identity_key`] was refused before ever touching the
/// database.
#[derive(Debug)]
pub enum IdentityKeyError {
    /// `public_key` was not exactly [`DM_PUBLIC_KEY_LEN`] bytes.
    InvalidLength,
    Db(rusqlite::Error),
}

impl From<rusqlite::Error> for IdentityKeyError {
    fn from(e: rusqlite::Error) -> Self {
        IdentityKeyError::Db(e)
    }
}

/// Hex-encoded SHA-256 fingerprint of a DM public key — the exact
/// computation `mlc_vault::dm::fingerprint` performs client-side; the server
/// recomputes it from the bytes it was handed rather than trusting a
/// client-supplied fingerprint string, so the two can never disagree.
pub fn fingerprint_hex(public_key: &[u8]) -> String {
    hex::encode(Sha256::digest(public_key))
}

/// Publish or rotate `user_id`'s DM identity key. Returns the fingerprint on
/// success. A second call for the same `user_id` overwrites the key in
/// place (`rotated_at` stamped to `now`, `created_at` left at its original
/// value) — see [`create_dm_schema`]'s doc comment on why there is no key
/// history to preserve.
pub fn upsert_identity_key(
    conn: &Connection,
    user_id: i64,
    public_key: &[u8],
    now: &str,
) -> std::result::Result<String, IdentityKeyError> {
    if public_key.len() != DM_PUBLIC_KEY_LEN {
        return Err(IdentityKeyError::InvalidLength);
    }
    let fingerprint = fingerprint_hex(public_key);
    conn.execute(
        "INSERT INTO dm_identity_keys (user_id, public_key, fingerprint, created_at, rotated_at)
         VALUES (?1, ?2, ?3, ?4, NULL)
         ON CONFLICT(user_id) DO UPDATE SET
            public_key = excluded.public_key,
            fingerprint = excluded.fingerprint,
            rotated_at = ?4",
        params![user_id, public_key, fingerprint, now],
    )?;
    Ok(fingerprint)
}

fn identity_key_from_row(row: &rusqlite::Row<'_>) -> Result<DmIdentityKey> {
    Ok(DmIdentityKey {
        user_id: row.get(0)?,
        public_key: row.get(1)?,
        fingerprint: row.get(2)?,
        created_at: row.get(3)?,
        rotated_at: row.get(4)?,
    })
}

/// Fetch `user_id`'s published DM identity key, if any.
pub fn get_identity_key(conn: &Connection, user_id: i64) -> Result<Option<DmIdentityKey>> {
    conn.query_row(
        "SELECT user_id, public_key, fingerprint, created_at, rotated_at
         FROM dm_identity_keys WHERE user_id = ?1",
        params![user_id],
        identity_key_from_row,
    )
    .optional()
}

/// Which of `user_ids` have published a DM identity key — the social-plane
/// half of `routes::dm::lookup_recipients`'s two-query candidate filter (the
/// identity-plane half, "is this account currently paid", is a separate
/// query against the identity database; the two are never joined in SQL,
/// per this module's cross-database rule). One batched `IN (...)` query
/// regardless of how many ids are passed, not one query per candidate.
/// Empty input returns an empty set without touching the database.
pub fn identity_key_owner_ids(conn: &Connection, user_ids: &[i64]) -> Result<HashSet<i64>> {
    if user_ids.is_empty() {
        return Ok(HashSet::new());
    }
    let placeholders = user_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!("SELECT user_id FROM dm_identity_keys WHERE user_id IN ({placeholders})");
    let mut stmt = conn.prepare(&sql)?;
    let bound: Vec<&dyn rusqlite::ToSql> = user_ids.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
    let mut rows = stmt.query(bound.as_slice())?;
    let mut out = HashSet::new();
    while let Some(row) = rows.next()? {
        out.insert(row.get(0)?);
    }
    Ok(out)
}

// ============================================================================
// Conversations
// ============================================================================

/// One row of `dm_conversations`.
#[derive(Debug, Clone, PartialEq)]
pub struct DmConversation {
    pub id: i64,
    pub user_lo: i64,
    pub user_hi: i64,
    pub created_at: String,
    pub last_message_at: Option<String>,
}

impl DmConversation {
    /// The other party's `user_id`, if `user_id` is actually a party to this
    /// conversation — `None` otherwise. This is the whole of the "party
    /// check" every message/read route in `routes::dm` runs before doing
    /// anything else: a caller who is not `user_lo` or `user_hi` gets `None`
    /// and the route answers 404, the same "indistinguishable from missing"
    /// posture the forum uses for a caller who cannot read a board.
    pub fn peer_of(&self, user_id: i64) -> Option<i64> {
        if user_id == self.user_lo {
            Some(self.user_hi)
        } else if user_id == self.user_hi {
            Some(self.user_lo)
        } else {
            None
        }
    }
}

/// Sort two user ids into `(lo, hi)` — the canonical form every
/// `dm_conversations` row is stored and looked up in, so the same pair of
/// accounts always resolves to the same row regardless of call-site order.
pub fn ordered_pair(a: i64, b: i64) -> (i64, i64) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

fn conversation_from_row(row: &rusqlite::Row<'_>) -> Result<DmConversation> {
    Ok(DmConversation {
        id: row.get(0)?,
        user_lo: row.get(1)?,
        user_hi: row.get(2)?,
        created_at: row.get(3)?,
        last_message_at: row.get(4)?,
    })
}

const CONVERSATION_SELECT_COLUMNS: &str = "id, user_lo, user_hi, created_at, last_message_at";

pub fn get_conversation(conn: &Connection, id: i64) -> Result<Option<DmConversation>> {
    conn.query_row(
        &format!("SELECT {CONVERSATION_SELECT_COLUMNS} FROM dm_conversations WHERE id = ?1"),
        params![id],
        conversation_from_row,
    )
    .optional()
}

/// Resolve the conversation between `a` and `b`, creating it if it does not
/// exist yet. Idempotent regardless of argument order — both `(a, b)` and
/// `(b, a)` land on the exact same row (see [`ordered_pair`] and the
/// `UNIQUE(user_lo, user_hi)` constraint [`create_dm_schema`] declares).
/// `a == b` is a caller bug (a self-conversation is meaningless) — this
/// function does not special-case it, so it would insert a row failing the
/// `CHECK (user_lo < user_hi)` constraint; `routes::dm` refuses that case
/// before ever calling this.
pub fn get_or_create_conversation(conn: &Connection, a: i64, b: i64, now: &str) -> Result<DmConversation> {
    let (lo, hi) = ordered_pair(a, b);
    conn.execute(
        "INSERT INTO dm_conversations (user_lo, user_hi, created_at, last_message_at)
         VALUES (?1, ?2, ?3, NULL)
         ON CONFLICT(user_lo, user_hi) DO NOTHING",
        params![lo, hi, now],
    )?;
    conn.query_row(
        &format!("SELECT {CONVERSATION_SELECT_COLUMNS} FROM dm_conversations WHERE user_lo = ?1 AND user_hi = ?2"),
        params![lo, hi],
        conversation_from_row,
    )
}

/// One conversation plus how many of its messages `user_id` has not yet
/// read (see [`mark_read`]).
#[derive(Debug, Clone, PartialEq)]
pub struct ConversationSummary {
    pub conversation: DmConversation,
    pub unread_count: i64,
}

/// Every conversation `user_id` is a party to, newest activity first
/// (`last_message_at`, falling back to `created_at` for a conversation with
/// no messages yet).
pub fn list_conversations_for_user(conn: &Connection, user_id: i64) -> Result<Vec<ConversationSummary>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {CONVERSATION_SELECT_COLUMNS},
            (SELECT COUNT(*) FROM dm_messages m
             WHERE m.conversation_id = c.id AND m.sender_user_id != ?1 AND m.read_at IS NULL)
         FROM dm_conversations c
         WHERE c.user_lo = ?1 OR c.user_hi = ?1
         ORDER BY COALESCE(c.last_message_at, c.created_at) DESC, c.id DESC"
    ))?;
    let mut rows = stmt.query(params![user_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(ConversationSummary {
            conversation: conversation_from_row(row)?,
            unread_count: row.get(5)?,
        });
    }
    Ok(out)
}

// ============================================================================
// Messages
// ============================================================================

/// One row of `dm_messages`. `nonce`/`ciphertext` are opaque to this
/// process — see the module doc.
#[derive(Debug, Clone, PartialEq)]
pub struct DmMessage {
    pub id: i64,
    pub conversation_id: i64,
    pub sender_user_id: i64,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub created_at: String,
    pub read_at: Option<String>,
}

/// Why a [`create_message`] call was refused, on top of a real database
/// failure — same shape as `db::ForumError`.
#[derive(Debug)]
pub enum MessageError {
    /// `nonce` was not exactly [`DM_NONCE_LEN`] bytes.
    InvalidNonceLength,
    /// `ciphertext` exceeded [`DM_MAX_CIPHERTEXT_BYTES`].
    TooLarge,
    /// The database call itself failed.
    Db(rusqlite::Error),
}

impl From<rusqlite::Error> for MessageError {
    fn from(e: rusqlite::Error) -> Self {
        MessageError::Db(e)
    }
}

/// Pure size validation, split out of [`create_message`] so it can be
/// tested with no database at all (see this module's tests).
fn validate_message_sizes(nonce_len: usize, ciphertext_len: usize) -> std::result::Result<(), MessageError> {
    if nonce_len != DM_NONCE_LEN {
        return Err(MessageError::InvalidNonceLength);
    }
    if ciphertext_len > DM_MAX_CIPHERTEXT_BYTES {
        return Err(MessageError::TooLarge);
    }
    Ok(())
}

fn message_from_row(row: &rusqlite::Row<'_>) -> Result<DmMessage> {
    Ok(DmMessage {
        id: row.get(0)?,
        conversation_id: row.get(1)?,
        sender_user_id: row.get(2)?,
        nonce: row.get(3)?,
        ciphertext: row.get(4)?,
        created_at: row.get(5)?,
        read_at: row.get(6)?,
    })
}

const MESSAGE_SELECT_COLUMNS: &str = "id, conversation_id, sender_user_id, nonce, ciphertext, created_at, read_at";

/// Insert one message and bump the conversation's `last_message_at`. Does
/// NOT check that `sender_user_id` is a party to `conversation_id` — the
/// route calls [`get_conversation`] + [`DmConversation::peer_of`] first,
/// same division of labour `social_db`'s reply/thread functions use.
pub fn create_message(
    conn: &Connection,
    conversation_id: i64,
    sender_user_id: i64,
    nonce: &[u8],
    ciphertext: &[u8],
    now: &str,
) -> std::result::Result<i64, MessageError> {
    validate_message_sizes(nonce.len(), ciphertext.len())?;
    conn.execute(
        "INSERT INTO dm_messages (conversation_id, sender_user_id, nonce, ciphertext, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![conversation_id, sender_user_id, nonce, ciphertext, now],
    )?;
    let id = conn.last_insert_rowid();
    conn.execute(
        "UPDATE dm_conversations SET last_message_at = ?2 WHERE id = ?1",
        params![conversation_id, now],
    )?;
    Ok(id)
}

/// List messages in `conversation_id` with `id > after` (or from the start
/// if `after` is `None`), oldest first, capped at `limit`.
pub fn list_messages(conn: &Connection, conversation_id: i64, after: Option<i64>, limit: i64) -> Result<Vec<DmMessage>> {
    let after = after.unwrap_or(0);
    let mut stmt = conn.prepare(&format!(
        "SELECT {MESSAGE_SELECT_COLUMNS} FROM dm_messages
         WHERE conversation_id = ?1 AND id > ?2
         ORDER BY id ASC LIMIT ?3"
    ))?;
    let mut rows = stmt.query(params![conversation_id, after, limit])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(message_from_row(row)?);
    }
    Ok(out)
}

/// Mark every message in `conversation_id` sent by the OTHER party (not
/// `reader_user_id`) with `id <= up_to_id` and no `read_at` yet as read at
/// `now`. Returns the number of rows updated. A reader can never mark their
/// own sent messages "read" this way — there is nothing to mark for a
/// message the reader authored.
pub fn mark_read(conn: &Connection, conversation_id: i64, reader_user_id: i64, up_to_id: i64, now: &str) -> Result<usize> {
    conn.execute(
        "UPDATE dm_messages SET read_at = ?1
         WHERE conversation_id = ?2 AND sender_user_id != ?3 AND id <= ?4 AND read_at IS NULL",
        params![now, conversation_id, reader_user_id, up_to_id],
    )
}

/// Count of messages `user_id` has sent, across every conversation, since
/// `since` (RFC3339) — the input to the daily rate limit in `routes::dm`.
pub fn messages_sent_since(conn: &Connection, user_id: i64, since: &str) -> Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM dm_messages WHERE sender_user_id = ?1 AND created_at > ?2",
        params![user_id, since],
        |row| row.get(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        create_dm_schema(&conn).expect("schema");
        conn
    }

    // ---- identity keys ----

    #[test]
    fn upsert_identity_key_refuses_wrong_length() {
        let conn = test_conn();
        let short_key = vec![1u8; 16];
        let err = upsert_identity_key(&conn, 1, &short_key, "2026-09-06T00:00:00+00:00").unwrap_err();
        assert!(matches!(err, IdentityKeyError::InvalidLength));
    }

    #[test]
    fn upsert_identity_key_round_trips_and_rotates() {
        let conn = test_conn();
        let key_a = vec![7u8; DM_PUBLIC_KEY_LEN];
        let fp_a = upsert_identity_key(&conn, 1, &key_a, "2026-09-06T00:00:00+00:00").expect("first publish");
        assert_eq!(fp_a, fingerprint_hex(&key_a));

        let row = get_identity_key(&conn, 1).expect("get").expect("row exists");
        assert_eq!(row.public_key, key_a);
        assert_eq!(row.created_at, "2026-09-06T00:00:00+00:00");
        assert_eq!(row.rotated_at, None);

        let key_b = vec![9u8; DM_PUBLIC_KEY_LEN];
        upsert_identity_key(&conn, 1, &key_b, "2026-09-06T01:00:00+00:00").expect("rotate");
        let rotated = get_identity_key(&conn, 1).expect("get").expect("row exists");
        assert_eq!(rotated.public_key, key_b);
        // created_at is untouched by a rotation; rotated_at now carries it.
        assert_eq!(rotated.created_at, "2026-09-06T00:00:00+00:00");
        assert_eq!(rotated.rotated_at.as_deref(), Some("2026-09-06T01:00:00+00:00"));
    }

    #[test]
    fn get_identity_key_missing_is_none() {
        let conn = test_conn();
        assert_eq!(get_identity_key(&conn, 999).expect("get"), None);
    }

    #[test]
    fn identity_key_owner_ids_returns_only_the_published_subset() {
        let conn = test_conn();
        let key = vec![1u8; DM_PUBLIC_KEY_LEN];
        upsert_identity_key(&conn, 1, &key, "2026-09-06T00:00:00+00:00").expect("publish for user 1");
        upsert_identity_key(&conn, 3, &key, "2026-09-06T00:00:00+00:00").expect("publish for user 3");

        let owners = identity_key_owner_ids(&conn, &[1, 2, 3, 4]).expect("batch lookup");
        assert_eq!(owners, [1, 3].into_iter().collect());
    }

    #[test]
    fn identity_key_owner_ids_of_empty_input_is_empty_without_a_query() {
        let conn = test_conn();
        assert_eq!(identity_key_owner_ids(&conn, &[]).expect("empty lookup"), HashSet::new());
    }

    // ---- ordered-pair uniqueness ----

    #[test]
    fn ordered_pair_sorts_ascending_regardless_of_input_order() {
        assert_eq!(ordered_pair(5, 9), (5, 9));
        assert_eq!(ordered_pair(9, 5), (5, 9));
        assert_eq!(ordered_pair(3, 3), (3, 3));
    }

    #[test]
    fn get_or_create_conversation_is_unique_regardless_of_argument_order() {
        let conn = test_conn();
        let first = get_or_create_conversation(&conn, 1, 2, "2026-09-06T00:00:00+00:00").expect("create");
        let second = get_or_create_conversation(&conn, 2, 1, "2026-09-06T00:05:00+00:00").expect("resolve existing");
        assert_eq!(first.id, second.id);
        assert_eq!(first.user_lo, 1);
        assert_eq!(first.user_hi, 2);
        // The second call's `now` never overwrote the original created_at —
        // ON CONFLICT DO NOTHING leaves the existing row untouched.
        assert_eq!(second.created_at, "2026-09-06T00:00:00+00:00");

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM dm_conversations", [], |row| row.get(0))
            .expect("count");
        assert_eq!(count, 1);
    }

    // ---- party check ----

    #[test]
    fn peer_of_identifies_the_other_party_and_rejects_strangers() {
        let conv = DmConversation {
            id: 1,
            user_lo: 1,
            user_hi: 2,
            created_at: "2026-09-06T00:00:00+00:00".to_string(),
            last_message_at: None,
        };
        assert_eq!(conv.peer_of(1), Some(2));
        assert_eq!(conv.peer_of(2), Some(1));
        assert_eq!(conv.peer_of(3), None);
    }

    // ---- messages + size cap ----

    #[test]
    fn create_message_refuses_oversized_ciphertext() {
        let conn = test_conn();
        let conv = get_or_create_conversation(&conn, 1, 2, "2026-09-06T00:00:00+00:00").expect("create");
        let nonce = [0u8; DM_NONCE_LEN];
        let oversized = vec![0u8; DM_MAX_CIPHERTEXT_BYTES + 1];
        let err = create_message(&conn, conv.id, 1, &nonce, &oversized, "2026-09-06T00:00:00+00:00").unwrap_err();
        assert!(matches!(err, MessageError::TooLarge));

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM dm_messages", [], |row| row.get(0))
            .expect("count");
        assert_eq!(count, 0);
    }

    #[test]
    fn create_message_refuses_wrong_nonce_length() {
        let conn = test_conn();
        let conv = get_or_create_conversation(&conn, 1, 2, "2026-09-06T00:00:00+00:00").expect("create");
        let short_nonce = [0u8; 4];
        let err = create_message(&conn, conv.id, 1, &short_nonce, b"hi", "2026-09-06T00:00:00+00:00").unwrap_err();
        assert!(matches!(err, MessageError::InvalidNonceLength));
    }

    #[test]
    fn create_message_at_the_cap_succeeds_and_bumps_last_message_at() {
        let conn = test_conn();
        let conv = get_or_create_conversation(&conn, 1, 2, "2026-09-06T00:00:00+00:00").expect("create");
        let nonce = [0u8; DM_NONCE_LEN];
        let at_cap = vec![0u8; DM_MAX_CIPHERTEXT_BYTES];
        let id = create_message(&conn, conv.id, 1, &nonce, &at_cap, "2026-09-06T00:10:00+00:00").expect("insert");
        assert!(id > 0);

        let refreshed = get_conversation(&conn, conv.id).expect("get").expect("exists");
        assert_eq!(refreshed.last_message_at.as_deref(), Some("2026-09-06T00:10:00+00:00"));
    }

    #[test]
    fn list_messages_pages_by_id_and_returns_opaque_bytes_verbatim() {
        let conn = test_conn();
        let conv = get_or_create_conversation(&conn, 1, 2, "2026-09-06T00:00:00+00:00").expect("create");
        let nonce = [0u8; DM_NONCE_LEN];
        let id1 = create_message(&conn, conv.id, 1, &nonce, b"first", "2026-09-06T00:01:00+00:00").expect("insert 1");
        let id2 = create_message(&conn, conv.id, 2, &nonce, b"second", "2026-09-06T00:02:00+00:00").expect("insert 2");

        let all = list_messages(&conn, conv.id, None, 10).expect("list all");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, id1);
        assert_eq!(all[0].ciphertext, b"first");
        assert_eq!(all[1].id, id2);
        assert_eq!(all[1].ciphertext, b"second");

        let after_first = list_messages(&conn, conv.id, Some(id1), 10).expect("list after");
        assert_eq!(after_first.len(), 1);
        assert_eq!(after_first[0].id, id2);
    }

    #[test]
    fn mark_read_only_touches_the_peers_messages_up_to_the_bound() {
        let conn = test_conn();
        let conv = get_or_create_conversation(&conn, 1, 2, "2026-09-06T00:00:00+00:00").expect("create");
        let nonce = [0u8; DM_NONCE_LEN];
        let from_1 = create_message(&conn, conv.id, 1, &nonce, b"a", "2026-09-06T00:01:00+00:00").expect("insert");
        let from_2 = create_message(&conn, conv.id, 2, &nonce, b"b", "2026-09-06T00:02:00+00:00").expect("insert");

        // User 1 reads up through the latest message: only the message
        // AUTHORED BY THE PEER (user 2) is marked read, never user 1's own.
        let updated = mark_read(&conn, conv.id, 1, from_2, "2026-09-06T00:05:00+00:00").expect("mark read");
        assert_eq!(updated, 1);

        let all = list_messages(&conn, conv.id, None, 10).expect("list");
        let mine = all.iter().find(|m| m.id == from_1).expect("own message");
        assert_eq!(mine.read_at, None);
        let peers = all.iter().find(|m| m.id == from_2).expect("peer message");
        assert_eq!(peers.read_at.as_deref(), Some("2026-09-06T00:05:00+00:00"));
    }

    #[test]
    fn list_conversations_for_user_reports_unread_count_from_the_peer_only() {
        let conn = test_conn();
        let conv = get_or_create_conversation(&conn, 1, 2, "2026-09-06T00:00:00+00:00").expect("create");
        let nonce = [0u8; DM_NONCE_LEN];
        create_message(&conn, conv.id, 1, &nonce, b"from 1", "2026-09-06T00:01:00+00:00").expect("insert");
        create_message(&conn, conv.id, 2, &nonce, b"from 2", "2026-09-06T00:02:00+00:00").expect("insert");

        let mine = list_conversations_for_user(&conn, 1).expect("list");
        assert_eq!(mine.len(), 1);
        // Only the peer's (user 2's) message counts as unread for user 1.
        assert_eq!(mine[0].unread_count, 1);

        let theirs = list_conversations_for_user(&conn, 2).expect("list");
        assert_eq!(theirs[0].unread_count, 1);
    }

    #[test]
    fn messages_sent_since_counts_only_the_given_sender_after_the_cutoff() {
        let conn = test_conn();
        let conv = get_or_create_conversation(&conn, 1, 2, "2026-09-06T00:00:00+00:00").expect("create");
        let nonce = [0u8; DM_NONCE_LEN];
        create_message(&conn, conv.id, 1, &nonce, b"a", "2026-09-06T00:01:00+00:00").expect("insert");
        create_message(&conn, conv.id, 1, &nonce, b"b", "2026-09-06T00:02:00+00:00").expect("insert");
        create_message(&conn, conv.id, 2, &nonce, b"c", "2026-09-06T00:03:00+00:00").expect("insert");

        assert_eq!(
            messages_sent_since(&conn, 1, "2026-09-06T00:00:00+00:00").expect("count"),
            2
        );
        assert_eq!(
            messages_sent_since(&conn, 1, "2026-09-06T00:01:30+00:00").expect("count"),
            1
        );
        assert_eq!(
            messages_sent_since(&conn, 2, "2026-09-06T00:00:00+00:00").expect("count"),
            1
        );
    }
}

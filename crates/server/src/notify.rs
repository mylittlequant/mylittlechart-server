//! Outreach notifications — owner ruling 2026-09-09: the only channel to
//! reach an existing user outside the app is the private Telegram chat they
//! already opened with `mylittlechart_login_bot` (see `tg-login-bot`), whose
//! chat id IS `user_providers.provider_user_id` for that account's
//! `telegram` row (`db::telegram_recipients` resolves it).
//!
//! [`send_batch`] is transport-agnostic: it takes the actual Telegram
//! delivery as an injected [`NotifySender`] closure rather than depending on
//! `reqwest` or the Bot API itself — see `routes::notify::live_telegram_sender`
//! for the one production sender, and this module's own tests for a stub
//! that never opens a socket.
//!
//! **Lock discipline**: same rule `account_merge.rs`'s module doc
//! establishes for this codebase — [`send_batch`] takes `&Mutex<Connection>`,
//! locks it only for the duration of one synchronous read or write, and
//! never holds the guard across an `.await` (each send is a network call
//! awaited with the lock already released — see the loop body below).
//!
//! A dry run never calls [`send_batch`] at all: it resolves recipients
//! directly via `db::telegram_recipients` and returns the preview, writing
//! nothing (see `routes::notify::notify`).

use rusqlite::Connection;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};

pub use crate::db::NotifyTarget;

/// Telegram's own hard limit is 4096 characters; this leaves margin rather
/// than sitting exactly on the wire limit (`routes::notify::notify` returns
/// 400 above this, before any recipient is resolved).
pub const MAX_NOTIFY_TEXT_LEN: usize = 3900;

/// Outcome of one outbound message attempt, delivered by [`send_batch`]'s
/// injected sender: `Ok(())` delivered, `Err(message)` failed — the message
/// is recorded verbatim in `notify_log.error` and returned to the caller in
/// [`SendOutcome::failed`].
pub type SendResult = Result<(), String>;

type BoxSendFuture = Pin<Box<dyn Future<Output = SendResult> + Send>>;

/// One Telegram send call, boxed so a test can inject a stub that never
/// touches the network — the only production implementation is
/// `routes::notify::live_telegram_sender`.
pub type NotifySender = Arc<dyn Fn(i64, String) -> BoxSendFuture + Send + Sync>;

/// Why [`send_batch`] refused before writing anything.
#[derive(Debug)]
pub enum NotifyError {
    /// `text` exceeds [`MAX_NOTIFY_TEXT_LEN`].
    TextTooLong,
    Db(rusqlite::Error),
}

impl From<rusqlite::Error> for NotifyError {
    fn from(e: rusqlite::Error) -> Self {
        NotifyError::Db(e)
    }
}

/// One recipient [`send_batch`] failed to reach.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SendFailure {
    pub user_id: i64,
    pub error: String,
}

/// Result of a real (non-dry-run) [`send_batch`] call.
#[derive(Debug)]
pub struct SendOutcome {
    pub batch_id: i64,
    pub sent: usize,
    pub failed: Vec<SendFailure>,
}

/// Deliver `text` to every recipient `db::telegram_recipients` resolves for
/// `target`, one at a time with `delay` between sends (skipped before the
/// first), via the injected `sender`. Every attempt — success or failure —
/// is recorded in `notify_log`; the message itself is written once, up
/// front, to `notify_batches` (see that table's doc comment in
/// `db::init_db`).
///
/// Refuses with [`NotifyError::TextTooLong`] before resolving any recipient
/// or writing anything if `text` exceeds [`MAX_NOTIFY_TEXT_LEN`].
pub async fn send_batch(
    db: &Mutex<Connection>,
    channel: &str,
    target: &NotifyTarget,
    text: &str,
    requested_by: &str,
    sender: &NotifySender,
    delay: Duration,
) -> Result<SendOutcome, NotifyError> {
    if text.len() > MAX_NOTIFY_TEXT_LEN {
        return Err(NotifyError::TextTooLong);
    }

    let now = chrono::Utc::now().to_rfc3339();
    let text_hash = hex::encode(Sha256::digest(text.as_bytes()));

    let (recipients, batch_id) = {
        let conn = db.lock().unwrap_or_else(|e| e.into_inner());
        let recipients = crate::db::telegram_recipients(&conn, target)?;
        let batch_id = crate::db::insert_notify_batch(&conn, channel, text, requested_by, &now)?;
        (recipients, batch_id)
    };

    let mut sent = 0usize;
    let mut failed = Vec::new();

    for (idx, recipient) in recipients.iter().enumerate() {
        if idx > 0 && !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }

        let result = sender(recipient.chat_id, text.to_string()).await;

        {
            let conn = db.lock().unwrap_or_else(|e| e.into_inner());
            crate::db::insert_notify_log(
                &conn,
                batch_id,
                channel,
                recipient.user_id,
                result.is_ok(),
                result.as_ref().err().map(String::as_str),
                &text_hash,
                &now,
            )?;
        }

        match result {
            Ok(()) => sent += 1,
            Err(error) => failed.push(SendFailure { user_id: recipient.user_id, error }),
        }
    }

    Ok(SendOutcome { batch_id, sent, failed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    /// A reduced schema: only what [`send_batch`] and `db::telegram_recipients`
    /// touch — `users`, `user_providers`, `notify_batches`, `notify_log`.
    fn test_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        conn.execute_batch(
            "
            CREATE TABLE users (
                id   INTEGER PRIMARY KEY AUTOINCREMENT,
                nick TEXT
            );
            CREATE TABLE user_providers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                provider TEXT NOT NULL,
                provider_user_id TEXT NOT NULL
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
            ",
        )
        .expect("test schema");
        conn
    }

    fn seed_user(conn: &Connection, nick: &str, telegram_chat_id: Option<i64>) -> i64 {
        conn.execute("INSERT INTO users (nick) VALUES (?1)", params![nick]).expect("insert user");
        let user_id = conn.last_insert_rowid();
        if let Some(chat_id) = telegram_chat_id {
            conn.execute(
                "INSERT INTO user_providers (user_id, provider, provider_user_id) VALUES (?1, 'telegram', ?2)",
                params![user_id, chat_id.to_string()],
            )
            .expect("insert provider");
        }
        user_id
    }

    /// Stub sender — never touches the network. Fails for every `chat_id`
    /// in `fail_for`, succeeds otherwise.
    fn stub_sender(fail_for: Vec<i64>) -> NotifySender {
        Arc::new(move |chat_id: i64, _text: String| {
            let should_fail = fail_for.contains(&chat_id);
            Box::pin(async move {
                if should_fail {
                    Err("simulated failure".to_string())
                } else {
                    Ok(())
                }
            })
        })
    }

    #[tokio::test]
    async fn send_batch_writes_batch_and_log_rows_via_stub_sender() {
        let conn = test_conn();
        let alice = seed_user(&conn, "alice", Some(111));
        let bob = seed_user(&conn, "bob", Some(222));
        // carol has no telegram identity — must never be a recipient.
        seed_user(&conn, "carol", None);

        let db = Mutex::new(conn);
        let sender = stub_sender(vec![222]); // bob's send fails

        let outcome = send_batch(&db, "telegram", &NotifyTarget::All, "hello", "admin", &sender, Duration::ZERO)
            .await
            .expect("send_batch");

        assert_eq!(outcome.sent, 1);
        assert_eq!(outcome.failed.len(), 1);
        assert_eq!(outcome.failed[0].user_id, bob);

        let conn = db.lock().expect("lock");
        let batch_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM notify_batches", [], |r| r.get(0)).expect("count");
        assert_eq!(batch_count, 1);
        let log_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM notify_log WHERE batch_id = ?1",
                params![outcome.batch_id],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(log_count, 2, "one log row per telegram-linked recipient, carol excluded");

        let alice_ok: i64 = conn
            .query_row("SELECT ok FROM notify_log WHERE user_id = ?1", params![alice], |r| r.get(0))
            .expect("alice row");
        assert_eq!(alice_ok, 1);
        let bob_error: Option<String> = conn
            .query_row("SELECT error FROM notify_log WHERE user_id = ?1", params![bob], |r| r.get(0))
            .expect("bob row");
        assert_eq!(bob_error.as_deref(), Some("simulated failure"));
    }

    #[tokio::test]
    async fn send_batch_refuses_text_over_the_length_guard_and_writes_nothing() {
        let db = Mutex::new(test_conn());
        let sender = stub_sender(vec![]);
        let text = "x".repeat(MAX_NOTIFY_TEXT_LEN + 1);

        let err = send_batch(&db, "telegram", &NotifyTarget::All, &text, "admin", &sender, Duration::ZERO)
            .await
            .expect_err("must refuse an over-length text");
        assert!(matches!(err, NotifyError::TextTooLong));

        let conn = db.lock().expect("lock");
        let batch_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM notify_batches", [], |r| r.get(0)).expect("count");
        assert_eq!(batch_count, 0, "a refused send must write nothing");
    }

    #[tokio::test]
    async fn send_batch_targets_an_explicit_user_list() {
        let conn = test_conn();
        let alice = seed_user(&conn, "alice", Some(111));
        let _bob = seed_user(&conn, "bob", Some(222));

        let db = Mutex::new(conn);
        let sender = stub_sender(vec![]);

        let outcome = send_batch(
            &db,
            "telegram",
            &NotifyTarget::Users(vec![alice]),
            "hi",
            "admin",
            &sender,
            Duration::ZERO,
        )
        .await
        .expect("send_batch");

        assert_eq!(outcome.sent, 1);
        assert!(outcome.failed.is_empty());
    }
}

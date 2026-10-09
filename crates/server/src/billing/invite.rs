//! Registration invites: a one-time code an admin issues so a person can open
//! an anonymous-kind account with no OAuth, no email and no payment.
//!
//! An invite carries the nick the account will get (a reserved nick is fine:
//! staff decide) and optional paid days. The nick is held for the invite while
//! it is pending, so neither self-service `set_nick` nor a second invite can
//! take it; the hold ends when the invite is redeemed, revoked or expired.
//!
//! The code is 100 random bits as 20 Crockford base32 characters in groups of
//! four, returned to the admin once and stored only as the SHA-256 of its
//! normalized form. [`redeem`] burns it with one conditional `UPDATE`, creates
//! an ACTIVE anonymous account holding the client's credential hash
//! ([`super::anon`]), assigns the nick through `db::admin_set_nick` (the path
//! that bypasses the reserved list) and extends `paid_until` by the invite's
//! days through `db::grant_paid_days` (the rule gift codes and the admin grant
//! share). All of that happens in one savepoint: a refusal leaves the code
//! unburnt.
//!
//! No function here logs or formats a code.

use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use rusqlite::{params, Connection, OptionalExtension, Result};
use sha2::{Digest, Sha256};

use super::anon::{self, Credential};

/// Create the `registration_invites` table (idempotent). `db::set_nick` reads
/// it, so every identity database and test fixture that has `users` needs it.
pub(crate) fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS registration_invites (
            id          TEXT    PRIMARY KEY,
            code_hash   TEXT    NOT NULL UNIQUE,
            nick        TEXT    NOT NULL,
            nick_lower  TEXT    NOT NULL,
            paid_days   INTEGER NOT NULL DEFAULT 0,
            note        TEXT    NOT NULL DEFAULT '',
            created_at  TEXT    NOT NULL,
            expires_at  TEXT    NOT NULL,
            created_by  INTEGER,
            redeemed_at TEXT,
            redeemed_by INTEGER,
            revoked_at  TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_registration_invites_nick ON registration_invites(nick_lower);",
    )
}

/// How long an invite stays redeemable.
pub const TTL: Duration = Duration::days(30);

const CODE_CHARS: usize = 20;
const GROUP: usize = 4;
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A fresh invite code, grouped for reading: `XXXX-XXXX-XXXX-XXXX-XXXX`.
fn generate_code() -> String {
    let mut rng = rand::thread_rng();
    let mut out = String::with_capacity(CODE_CHARS + CODE_CHARS / GROUP);
    for i in 0..CODE_CHARS {
        if i > 0 && i % GROUP == 0 {
            out.push('-');
        }
        out.push(char::from(CROCKFORD[rng.gen_range(0..CROCKFORD.len())]));
    }
    out
}

/// The canonical form of what a user typed: case, hyphens and spaces are
/// ignored and Crockford's look-alikes apply (`O` reads `0`, `I` and `L` read
/// `1`). `None` unless it is exactly [`CODE_CHARS`] alphabet characters.
pub(crate) fn normalize_code(input: &str) -> Option<String> {
    let mut out = String::with_capacity(CODE_CHARS);
    for c in input.chars() {
        if c == '-' || c.is_whitespace() {
            continue;
        }
        let c = match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        };
        if !c.is_ascii() || !CROCKFORD.contains(&(c as u8)) || out.len() >= CODE_CHARS {
            return None;
        }
        out.push(c);
    }
    (out.len() == CODE_CHARS).then_some(out)
}

fn code_hash(normalized: &str) -> String {
    hex::encode(Sha256::digest(normalized.as_bytes()))
}

/// Where an invite stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Redeemable, and its nick is held.
    Pending,
    /// Burnt by a redemption.
    Redeemed,
    /// Withdrawn by staff.
    Revoked,
    /// Past its expiry without being redeemed.
    Expired,
}

/// One row of the staff list: metadata only, never a code.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InviteRow {
    /// The invite id (`inv_…`), the handle for revoking.
    pub id: String,
    /// The nick the account will get.
    pub nick: String,
    /// Paid days the account starts with (0 = none).
    pub paid_days: i64,
    /// Why the invite was issued.
    pub note: String,
    /// Pending, redeemed, revoked or expired.
    pub status: Status,
    /// When it was issued, RFC 3339.
    pub created_at: String,
    /// When it stops being redeemable.
    pub expires_at: String,
    /// When it was redeemed.
    pub redeemed_at: Option<String>,
    /// When it was revoked.
    pub revoked_at: Option<String>,
    /// The nick of the staff account that issued it, if it has one.
    pub created_by_nick: Option<String>,
}

fn status_of(redeemed_at: Option<&str>, revoked_at: Option<&str>, expires_at: &str, now: DateTime<Utc>) -> Status {
    if redeemed_at.is_some() {
        Status::Redeemed
    } else if revoked_at.is_some() {
        Status::Revoked
    } else if !is_future(expires_at, now) {
        Status::Expired
    } else {
        Status::Pending
    }
}

fn is_future(stamp: &str, now: DateTime<Utc>) -> bool {
    DateTime::parse_from_rfc3339(stamp).is_ok_and(|t| t.with_timezone(&Utc) > now)
}

/// Whether a PENDING invite holds `nick_lower`.
pub fn nick_held(conn: &Connection, nick_lower: &str, now: DateTime<Utc>) -> Result<bool> {
    let mut stmt = conn.prepare(
        "SELECT expires_at FROM registration_invites
         WHERE nick_lower = ?1 AND redeemed_at IS NULL AND revoked_at IS NULL",
    )?;
    let expiries = stmt.query_map(params![nick_lower], |row| row.get::<_, String>(0))?.collect::<Result<Vec<_>>>()?;
    Ok(expiries.iter().any(|e| is_future(e, now)))
}

/// Why an invite could not be issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueRefusal {
    /// The nick fails the format or shape rules.
    NickInvalid,
    /// The nick matches the forbidden-nick registry.
    NickForbidden,
    /// An account or another pending invite holds the nick.
    NickTaken,
}

/// A freshly issued invite.
pub struct Issued {
    /// The invite id.
    pub id: String,
    /// The plain code: it exists here, in the response that hands it to the
    /// admin, and nowhere else.
    pub code: String,
    /// When it stops being redeemable, RFC 3339.
    pub expires_at: String,
}

/// Issue an invite for `nick` with `paid_days` (0 = none). A reserved nick is
/// allowed; a nick already held by an account or by another pending invite is
/// not. `paid_days` and `note` bounds are the caller's job.
pub fn issue(
    conn: &Connection,
    nick: &str,
    paid_days: i64,
    note: &str,
    created_by: i64,
    now: DateTime<Utc>,
) -> Result<std::result::Result<Issued, IssueRefusal>> {
    if !crate::db::nick_format_valid(nick) || !crate::nick_policy::nick_shape_ok(nick) {
        return Ok(Err(IssueRefusal::NickInvalid));
    }
    if crate::nick_policy::forbidden_hit(nick).is_some() {
        return Ok(Err(IssueRefusal::NickForbidden));
    }
    let lower = nick.to_lowercase();
    let held_by_account = conn
        .query_row("SELECT 1 FROM users WHERE LOWER(nick) = ?1", params![lower], |_| Ok(()))
        .optional()?
        .is_some();
    if held_by_account || nick_held(conn, &lower, now)? {
        return Ok(Err(IssueRefusal::NickTaken));
    }
    let id = format!("inv_{}", hex::encode(rand::thread_rng().gen::<[u8; 8]>()));
    let code = generate_code();
    let normalized = normalize_code(&code).unwrap_or_default();
    let expires_at = (now + TTL).to_rfc3339();
    conn.execute(
        "INSERT INTO registration_invites (id, code_hash, nick, nick_lower, paid_days, note, created_at, expires_at, created_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![id, code_hash(&normalized), nick, lower, paid_days, note, now.to_rfc3339(), expires_at, created_by],
    )?;
    Ok(Ok(Issued { id, code, expires_at }))
}

/// Every invite, newest first.
pub fn list(conn: &Connection, now: DateTime<Utc>) -> Result<Vec<InviteRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, nick, paid_days, note, created_at, expires_at, redeemed_at, revoked_at, created_by
         FROM registration_invites ORDER BY created_at DESC, rowid DESC",
    )?;
    type Raw = (String, String, i64, String, String, String, Option<String>, Option<String>, Option<i64>);
    let raw = stmt
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
            ))
        })?
        .collect::<Result<Vec<Raw>>>()?;
    let mut rows = Vec::with_capacity(raw.len());
    for (id, nick, paid_days, note, created_at, expires_at, redeemed_at, revoked_at, created_by) in raw {
        let created_by_nick = match created_by {
            Some(user_id) => crate::db::nick_for_user(conn, user_id)?,
            None => None,
        };
        rows.push(InviteRow {
            status: status_of(redeemed_at.as_deref(), revoked_at.as_deref(), &expires_at, now),
            id,
            nick,
            paid_days,
            note,
            created_at,
            expires_at,
            redeemed_at,
            revoked_at,
            created_by_nick,
        });
    }
    Ok(rows)
}

/// What [`revoke`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revoked {
    /// No such invite.
    NotFound,
    /// Already redeemed: the account exists, nothing to withdraw.
    AlreadyRedeemed,
    /// Withdrawn just now.
    Now,
    /// Was already revoked.
    Before,
}

/// Withdraw invite `id`; its nick is released.
pub fn revoke(conn: &Connection, id: &str, now: DateTime<Utc>) -> Result<Revoked> {
    let row: Option<(Option<String>, Option<String>)> = conn
        .query_row(
            "SELECT redeemed_at, revoked_at FROM registration_invites WHERE id = ?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((redeemed_at, revoked_at)) = row else {
        return Ok(Revoked::NotFound);
    };
    if redeemed_at.is_some() {
        return Ok(Revoked::AlreadyRedeemed);
    }
    if revoked_at.is_some() {
        return Ok(Revoked::Before);
    }
    let changed = conn.execute(
        "UPDATE registration_invites SET revoked_at = ?2 WHERE id = ?1 AND redeemed_at IS NULL AND revoked_at IS NULL",
        params![id, now.to_rfc3339()],
    )?;
    Ok(if changed == 1 { Revoked::Now } else { Revoked::AlreadyRedeemed })
}

/// Why a redemption failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedeemRefusal {
    /// Malformed, unknown, used, revoked or expired: one answer for all.
    InvalidCode,
    /// The nick was taken by an account in the meantime.
    NickUnavailable,
    /// Another account already holds the credential.
    CredentialInUse,
}

/// A redeemed invite.
pub struct Redeemed {
    /// The new account's id.
    pub user_id: i64,
}

/// Redeem `code` for a new ACTIVE anonymous account holding `credential`. One
/// savepoint: any refusal leaves the code unburnt and nothing created.
pub fn redeem(
    conn: &Connection,
    code: &str,
    credential: &Credential,
    now: DateTime<Utc>,
) -> Result<std::result::Result<Redeemed, RedeemRefusal>> {
    let Some(normalized) = normalize_code(code) else {
        return Ok(Err(RedeemRefusal::InvalidCode));
    };
    conn.execute_batch("SAVEPOINT invite_redeem;")?;
    let outcome = redeem_in_savepoint(conn, &code_hash(&normalized), credential, now);
    match &outcome {
        Ok(Ok(_)) => conn.execute_batch("RELEASE invite_redeem;")?,
        // The original result is what the caller needs; a failed rollback on
        // top of it adds nothing.
        _ => {
            let _ = conn.execute_batch("ROLLBACK TO invite_redeem; RELEASE invite_redeem;");
        }
    }
    outcome
}

fn redeem_in_savepoint(
    conn: &Connection,
    hash: &str,
    credential: &Credential,
    now: DateTime<Utc>,
) -> Result<std::result::Result<Redeemed, RedeemRefusal>> {
    let row: Option<(String, String, i64, String)> = conn
        .query_row(
            "SELECT id, nick, paid_days, expires_at FROM registration_invites
             WHERE code_hash = ?1 AND redeemed_at IS NULL AND revoked_at IS NULL",
            params![hash],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((id, nick, paid_days, expires_at)) = row else {
        return Ok(Err(RedeemRefusal::InvalidCode));
    };
    if !is_future(&expires_at, now) {
        return Ok(Err(RedeemRefusal::InvalidCode));
    }
    // The one statement that decides single use.
    let burnt = conn.execute(
        "UPDATE registration_invites SET redeemed_at = ?2 WHERE id = ?1 AND redeemed_at IS NULL AND revoked_at IS NULL",
        params![id, now.to_rfc3339()],
    )?;
    if burnt != 1 {
        return Ok(Err(RedeemRefusal::InvalidCode));
    }
    if anon::credential_in_use(conn, credential)? {
        return Ok(Err(RedeemRefusal::CredentialInUse));
    }
    let user_id = anon::create_active(conn, credential, now)?;
    let old_nick = crate::db::nick_for_user(conn, user_id).ok().flatten().unwrap_or_default();
    match crate::db::admin_set_nick(conn, user_id, &nick) {
        Ok(_) => crate::account_bridge::emit_nick_changed(&old_nick, &nick),
        Err(crate::db::AdminNickError::Db(e)) => return Err(e),
        Err(_) => return Ok(Err(RedeemRefusal::NickUnavailable)),
    }
    if paid_days > 0 {
        crate::db::grant_paid_days(conn, user_id, paid_days)?;
    }
    conn.execute("UPDATE registration_invites SET redeemed_by = ?2 WHERE id = ?1", params![id, user_id])?;
    Ok(Ok(Redeemed { user_id }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::testkit::{conn, seed_user};

    #[test]
    fn a_code_is_20_crockford_characters_in_groups_of_four_and_round_trips() {
        for _ in 0..50 {
            let code = generate_code();
            assert_eq!(code.len(), 20 + 4);
            assert!(code.split('-').all(|g| g.len() == 4));
            let normalized = normalize_code(&code).expect("normalizes");
            assert_eq!(normalized, code.replace('-', ""));
            assert_eq!(normalize_code(&code.to_lowercase().replace('-', " ")).as_deref(), Some(normalized.as_str()));
        }
        assert_eq!(normalize_code("OIL0-0000-0000-0000-0000").as_deref(), Some("01100000000000000000"));
    }

    #[test]
    fn anything_that_is_not_a_code_does_not_normalize() {
        let good = generate_code().replace('-', "");
        for bad in ["", "hello", &good[..19], &format!("{good}0"), &format!("{}U{}", &good[..5], &good[6..]), &format!("{}!{}", &good[..5], &good[6..])] {
            assert!(normalize_code(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn issue_holds_the_nick_until_redeemed_revoked_or_expired() {
        let conn = conn();
        let now = Utc::now();
        let first = issue(&conn, "Fresh-Nick", 10, "n", 1, now).expect("issue").expect("issued");
        assert!(first.id.starts_with("inv_"));
        assert!(nick_held(&conn, "fresh-nick", now).expect("held"));
        assert_eq!(issue(&conn, "fresh-nick", 0, "", 1, now).expect("issue").err(), Some(IssueRefusal::NickTaken));
        assert_eq!(revoke(&conn, &first.id, now).expect("revoke"), Revoked::Now);
        assert_eq!(revoke(&conn, &first.id, now).expect("revoke"), Revoked::Before);
        assert_eq!(revoke(&conn, "inv_nope", now).expect("revoke"), Revoked::NotFound);
        assert!(!nick_held(&conn, "fresh-nick", now).expect("held"));
        let second = issue(&conn, "fresh-nick", 0, "", 1, now).expect("issue").expect("issued again");
        assert!(!nick_held(&conn, "fresh-nick", now + TTL + Duration::seconds(1)).expect("expired"));
        let listed = list(&conn, now + TTL + Duration::seconds(1)).expect("list");
        assert_eq!(listed.len(), 2);
        assert_eq!((listed[0].id.as_str(), listed[0].status), (second.id.as_str(), Status::Expired));
        assert_eq!(listed[1].status, Status::Revoked);
    }

    #[test]
    fn issue_refuses_bad_forbidden_and_held_nicks() {
        let conn = conn();
        let now = Utc::now();
        let holder = seed_user(&conn, "some-github-user");
        crate::db::admin_set_nick(&conn, holder, "Taken-Nick").expect("nick");
        assert_eq!(issue(&conn, "taken-nick", 0, "", 1, now).expect("issue").err(), Some(IssueRefusal::NickTaken));
        assert_eq!(issue(&conn, "a", 0, "", 1, now).expect("issue").err(), Some(IssueRefusal::NickInvalid));
        assert_eq!(issue(&conn, "has space", 0, "", 1, now).expect("issue").err(), Some(IssueRefusal::NickInvalid));
    }

    #[test]
    fn redeem_burns_the_code_and_a_second_try_is_the_same_refusal() {
        let conn = conn();
        let now = Utc::now();
        let issued = issue(&conn, "newcomer", 30, "", 1, now).expect("issue").expect("issued");
        let credential = Credential::random();
        let redeemed = redeem(&conn, &issued.code, &credential, now).expect("redeem").expect("redeemed");
        assert_eq!(anon::status_of(&conn, redeemed.user_id).expect("status"), Some(anon::AccountStatus::Active));
        assert_eq!(crate::db::nick_for_user(&conn, redeemed.user_id).expect("nick").as_deref(), Some("newcomer"));
        assert_eq!(redeem(&conn, &issued.code, &Credential::random(), now).expect("again").err(), Some(RedeemRefusal::InvalidCode));
        assert_eq!(redeem(&conn, "not a code", &Credential::random(), now).expect("junk").err(), Some(RedeemRefusal::InvalidCode));
        assert_eq!(revoke(&conn, &issued.id, now).expect("revoke"), Revoked::AlreadyRedeemed);
    }

    #[test]
    fn a_refused_redemption_leaves_the_code_unburnt_and_nothing_created() {
        let conn = conn();
        let now = Utc::now();
        let taken = Credential::random();
        anon::create_active(&conn, &taken, now).expect("existing");
        let users: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)).expect("count");
        let issued = issue(&conn, "careful", 5, "", 1, now).expect("issue").expect("issued");
        assert_eq!(redeem(&conn, &issued.code, &taken, now).expect("redeem").err(), Some(RedeemRefusal::CredentialInUse));
        let after: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)).expect("count");
        assert_eq!(users, after);
        assert!(redeem(&conn, &issued.code, &Credential::random(), now).expect("retry").is_ok(), "the code survived the refusal");
    }

    #[test]
    fn an_expired_invite_cannot_be_redeemed() {
        let conn = conn();
        let now = Utc::now();
        let issued = issue(&conn, "toolate", 0, "", 1, now).expect("issue").expect("issued");
        let later = now + TTL + Duration::seconds(1);
        assert_eq!(redeem(&conn, &issued.code, &Credential::random(), later).expect("redeem").err(), Some(RedeemRefusal::InvalidCode));
    }
}

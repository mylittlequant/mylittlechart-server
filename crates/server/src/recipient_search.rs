//! Recipient-lookup ranking machinery, shared between
//! `GET /api/dm/lookup` ([`crate::routes::dm::lookup_recipients`]) and the
//! future Matrix `GET /_matrix/client/v3/user_directory/search`, which must
//! reuse today's DM recipient-lookup ranking/limits verbatim. Extracted out
//! of `routes/dm.rs` rather than duplicated, deviating on purpose from this
//! codebase's one-copy-per-route-module convention
//! (`routes/dm.rs:141-144`): that convention is for small, cheap-to-
//! duplicate gate checks (3-15 lines), not for a ~150-line fuzzy-ranking
//! algorithm, which two independently maintained copies would drift apart
//! (`docs/mlc/plans/messenger-proto-server-matrix-subset-2026-09-24.md`
//! §6.1).

/// Ceiling on how many currently-subscription-paid accounts one lookup call
/// loads from the identity database before scoring in Rust — the table is
/// small enough that a single unfiltered-by-text query plus in-process
/// ranking beats a second LIKE-shaped query per keystroke (same reasoning
/// `db::search_users` skips for its own, admin-only, already-`LIKE`-filtered
/// query). Ladder-boosted accounts (see [`paid_recipient_candidates`]) are
/// loaded separately and are not bounded by this — `forum_roles`/
/// `forum_trusted` are small, admin-managed tables.
const PAID_CANDIDATE_LIMIT: i64 = 5000;

/// A fuzzy match is only offered once the query is long enough that a
/// distance-1 typo is unlikely to also match something unrelated; a longer
/// query is allowed a distance of 2.
const FUZZY_SHORT_QUERY_MAX_LEN: usize = 4;
const FUZZY_DISTANCE_SHORT_QUERY: usize = 1;
const FUZZY_DISTANCE_LONG_QUERY: usize = 2;

/// One row loaded from the identity database: a ladder-paid account (see
/// [`paid_recipient_candidates`]), before it is known whether it also
/// published a DM identity key (checked separately against the social
/// connection — see [`crate::routes::dm::lookup_recipients`]).
pub(crate) struct PaidCandidate {
    pub(crate) id: i64,
    pub(crate) nick: Option<String>,
    pub(crate) display_name: String,
    pub(crate) public_id: String,
}

/// Every recipient candidate for [`crate::routes::dm::lookup_recipients`]:
/// accounts with an unexpired `paid_until` (bounded by
/// [`PAID_CANDIDATE_LIMIT`]) PLUS `boosted_ids` — accounts that reach
/// [`crate::social_db::Class::Paid`] via
/// [`crate::social_db::ladder_boosted_user_ids`] (trusted standing, or a
/// moderator/admin role) regardless of their own subscription (owner ruling
/// 2026-09-23, same rule `routes::dm::is_dm_paid`'s rule applies to the
/// caller and to a conversation peer). `caller_id` is always excluded; a
/// `boosted_ids` entry already covered by the `paid_until` query is not
/// loaded twice.
pub(crate) fn paid_recipient_candidates(
    identity_conn: &rusqlite::Connection,
    caller_id: i64,
    boosted_ids: &[i64],
    now: &str,
) -> rusqlite::Result<Vec<PaidCandidate>> {
    use rusqlite::{params, OptionalExtension};

    let mut candidates = Vec::new();
    let mut seen_ids = std::collections::HashSet::new();
    {
        let mut stmt = identity_conn.prepare(
            "SELECT id, nick, display_name, public_id FROM users
             WHERE paid_until IS NOT NULL AND paid_until > ?1 AND id != ?2
             LIMIT ?3",
        )?;
        let mut rows = stmt.query(params![now, caller_id, PAID_CANDIDATE_LIMIT])?;
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            seen_ids.insert(id);
            candidates.push(PaidCandidate {
                id,
                nick: row.get(1)?,
                display_name: row.get(2)?,
                public_id: row.get(3)?,
            });
        }
    }

    for &id in boosted_ids {
        if id == caller_id || seen_ids.contains(&id) {
            continue;
        }
        let row: Option<(Option<String>, String, String)> = identity_conn
            .query_row(
                "SELECT nick, display_name, public_id FROM users WHERE id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((nick, display_name, public_id)) = row {
            seen_ids.insert(id);
            candidates.push(PaidCandidate { id, nick, display_name, public_id });
        }
    }

    Ok(candidates)
}

/// The label [`crate::db::effective_label_for_user`] would compute for the
/// same three columns — inlined here (rather than a second per-row identity
/// query) because [`crate::routes::dm::lookup_recipients`] already has
/// `nick`/`display_name`/`public_id` in hand from its one candidate-loading
/// query.
pub(crate) fn effective_label_from_parts(nick: Option<&str>, display_name: &str, public_id: &str) -> String {
    nick.filter(|n| !n.is_empty())
        .or_else(|| Some(display_name).filter(|d| !d.is_empty()))
        .unwrap_or(public_id)
        .to_string()
}

/// Optimal-string-alignment (restricted) Damerau-Levenshtein distance
/// between `a` and `b`: insertion, deletion, substitution, and swapping two
/// ADJACENT characters each cost 1 — a transposed pair such as `"ab"` vs
/// `"ba"` is distance 1, not 2, but (unlike full Damerau-Levenshtein) a
/// character already involved in a transposition cannot be edited again in
/// the same step. Counts Unicode scalar values, not bytes, so it works the
/// same on non-ASCII nicks/names.
pub(crate) fn osa_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (len_a, len_b) = (a.len(), b.len());
    if len_a == 0 {
        return len_b;
    }
    if len_b == 0 {
        return len_a;
    }

    let mut dp = vec![vec![0usize; len_b + 1]; len_a + 1];
    for (i, row) in dp.iter_mut().enumerate() {
        row[0] = i;
    }
    for j in 0..=len_b {
        dp[0][j] = j;
    }
    for i in 1..=len_a {
        for j in 1..=len_b {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (dp[i - 1][j] + 1) // deletion
                .min(dp[i][j - 1] + 1) // insertion
                .min(dp[i - 1][j - 1] + cost); // match/substitution
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(dp[i - 2][j - 2] + 1); // adjacent transposition
            }
            dp[i][j] = best;
        }
    }
    dp[len_a][len_b]
}

/// Score one candidate against an already-trimmed-lowercased `query`,
/// ranked exactly as `routes::dm`'s module doc lists (lower is a better
/// match): exact nick (0), nick prefix (1), display-name prefix (2),
/// substring in either (3), fuzzy match on the nick or on any
/// whitespace-separated word of the display name (4). `None` if nothing
/// matches at all. `nick`/`display_name` are the candidate's raw (mixed-
/// case) stored values; this function lowercases its own copies rather than
/// requiring the caller to.
pub(crate) fn rank_candidate(query: &str, nick: Option<&str>, display_name: &str) -> Option<u8> {
    let nick_lower = nick.map(str::to_lowercase);
    let display_lower = display_name.to_lowercase();

    if nick_lower.as_deref() == Some(query) {
        return Some(0);
    }
    if nick_lower.as_deref().is_some_and(|n| n.starts_with(query)) {
        return Some(1);
    }
    if display_lower.starts_with(query) {
        return Some(2);
    }
    if nick_lower.as_deref().is_some_and(|n| n.contains(query)) || display_lower.contains(query) {
        return Some(3);
    }

    let max_distance = if query.chars().count() <= FUZZY_SHORT_QUERY_MAX_LEN {
        FUZZY_DISTANCE_SHORT_QUERY
    } else {
        FUZZY_DISTANCE_LONG_QUERY
    };
    if nick_lower.as_deref().is_some_and(|n| osa_distance(n, query) <= max_distance) {
        return Some(4);
    }
    if display_lower.split_whitespace().any(|word| osa_distance(word, query) <= max_distance) {
        return Some(4);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dm_db, social_db};

    /// An in-memory `social.db` — both schemas [`social_db::set_role`]/
    /// [`social_db::ladder_boosted_user_ids`] and `dm_db`'s identity-key
    /// table read from live in the same physical file in production, so
    /// tests build both on one connection.
    fn social_test_conn() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().expect("in-memory sqlite");
        social_db::create_social_schema(&conn).expect("social schema");
        dm_db::create_dm_schema(&conn).expect("dm schema");
        conn
    }

    // ---- lookup candidate resolution: paid_recipient_candidates ----

    fn identity_test_conn() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().expect("in-memory sqlite");
        conn.execute_batch(
            "CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL DEFAULT 'test',
                provider_user_id TEXT NOT NULL DEFAULT '',
                display_name TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT '',
                public_id TEXT,
                nick TEXT,
                paid_until TEXT
            );",
        )
        .expect("identity test schema");
        conn
    }

    fn insert_identity_test_user(
        conn: &rusqlite::Connection,
        nick: &str,
        public_id: &str,
        paid_until: Option<&str>,
    ) -> i64 {
        conn.execute(
            "INSERT INTO users (provider, provider_user_id, display_name, created_at, public_id, nick, paid_until)
             VALUES ('test', ?1, ?1, '2026-01-01T00:00:00+00:00', ?2, ?1, ?3)",
            rusqlite::params![nick, public_id, paid_until],
        )
        .expect("insert user");
        conn.last_insert_rowid()
    }

    fn future_ts() -> String {
        (chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339()
    }

    /// The exact scenario the brief names: an unpaid admin-role account with
    /// a published DM identity key is a valid lookup result — reachable
    /// through `paid_recipient_candidates` (the ladder half) and
    /// `dm_db::identity_key_owner_ids` (the published-key half), the same
    /// two queries `lookup_recipients` runs.
    #[test]
    fn lookup_recipient_candidates_includes_an_unpaid_admin_role_account_with_a_published_key() {
        let identity_conn = identity_test_conn();
        let social_conn = social_test_conn();

        let caller_id = insert_identity_test_user(&identity_conn, "caller", "pub-caller", Some(&future_ts()));
        let admin_id = insert_identity_test_user(&identity_conn, "admino", "pub-admino", None);

        social_db::set_role(&social_conn, admin_id, social_db::Role::Admin, "2026-09-23T00:00:00+00:00")
            .expect("set role");
        dm_db::upsert_identity_key(
            &social_conn,
            admin_id,
            &[7u8; dm_db::DM_PUBLIC_KEY_LEN],
            "2026-09-23T00:00:00+00:00",
        )
        .expect("publish key");

        let boosted_ids = social_db::ladder_boosted_user_ids(&social_conn).expect("boosted ids");
        assert!(boosted_ids.contains(&admin_id));

        let now = chrono::Utc::now().to_rfc3339();
        let candidates =
            paid_recipient_candidates(&identity_conn, caller_id, &boosted_ids, &now).expect("candidates");
        assert!(candidates.iter().any(|c| c.id == admin_id));

        let ids: Vec<i64> = candidates.iter().map(|c| c.id).collect();
        let keyed = dm_db::identity_key_owner_ids(&social_conn, &ids).expect("keyed");
        assert!(keyed.contains(&admin_id));

        let matched: Vec<i64> = candidates
            .into_iter()
            .filter(|c| keyed.contains(&c.id))
            .filter_map(|c| rank_candidate("admino", c.nick.as_deref(), &c.display_name).map(|_| c.id))
            .collect();
        assert!(matched.contains(&admin_id));
    }

    #[test]
    fn lookup_recipient_candidates_excludes_the_caller_and_deduplicates_a_boosted_id_already_paid() {
        let identity_conn = identity_test_conn();
        let caller_id = insert_identity_test_user(&identity_conn, "caller", "pub-caller", Some(&future_ts()));
        let paid_and_boosted_id =
            insert_identity_test_user(&identity_conn, "trusty", "pub-trusty", Some(&future_ts()));

        let now = chrono::Utc::now().to_rfc3339();
        let boosted_ids = vec![caller_id, paid_and_boosted_id];
        let candidates =
            paid_recipient_candidates(&identity_conn, caller_id, &boosted_ids, &now).expect("candidates");

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].id, paid_and_boosted_id);
    }

    // ---- lookup: osa_distance ----

    #[test]
    fn osa_distance_of_identical_strings_is_zero() {
        assert_eq!(osa_distance("kosti", "kosti"), 0);
        assert_eq!(osa_distance("", ""), 0);
    }

    #[test]
    fn osa_distance_counts_an_adjacent_transposition_as_one_not_two() {
        // Plain Levenshtein would need a delete + insert (2) for this pair;
        // OSA recognises the swapped adjacent pair as a single edit.
        assert_eq!(osa_distance("ab", "ba"), 1);
        assert_eq!(osa_distance("kosti", "kosit"), 1);
    }

    #[test]
    fn osa_distance_against_empty_input_is_the_other_strings_length() {
        assert_eq!(osa_distance("", "abc"), 3);
        assert_eq!(osa_distance("abc", ""), 3);
    }

    #[test]
    fn osa_distance_counts_unicode_scalar_values_not_bytes() {
        // "über" vs "uber": one substitution (ü -> u), not the multi-byte
        // UTF-8 distance a byte-wise comparison would report.
        assert_eq!(osa_distance("über", "uber"), 1);
    }

    // ---- lookup: rank_candidate ----

    #[test]
    fn rank_candidate_prefers_exact_nick_over_every_other_tier() {
        assert_eq!(rank_candidate("kosti", Some("kosti"), "Someone Else"), Some(0));
    }

    #[test]
    fn rank_candidate_orders_nick_prefix_above_display_name_prefix() {
        assert_eq!(rank_candidate("kos", Some("kosti"), "kostroma events"), Some(1));
        assert_eq!(rank_candidate("kos", None, "kostroma events"), Some(2));
    }

    #[test]
    fn rank_candidate_falls_back_to_substring_then_fuzzy() {
        // "ost" is a substring of "kosti" but not a prefix of either field.
        assert_eq!(rank_candidate("ost", Some("kosti"), "Someone Else"), Some(3));
        // "kosit" (5 chars, threshold 2) is neither a substring of "kosti"
        // nor vice versa, but is distance 1 from it (one adjacent
        // transposition) — a fuzzy match.
        assert_eq!(rank_candidate("kosit", Some("kosti"), "Someone Else"), Some(4));
    }

    #[test]
    fn rank_candidate_matches_a_word_inside_display_name_by_fuzzy_distance() {
        // "vann" (4 chars, threshold 1) fuzzy-matches "van" inside "Kosti van Trading" via one insertion.
        assert_eq!(rank_candidate("vann", None, "Kosti van Trading"), Some(4));
    }

    #[test]
    fn rank_candidate_none_when_nothing_matches() {
        assert_eq!(rank_candidate("zzzzzzzzzz", Some("kosti"), "Someone Else"), None);
    }

    #[test]
    fn rank_candidate_handles_empty_and_unicode_inputs() {
        assert_eq!(rank_candidate("", Some(""), ""), Some(0));
        assert_eq!(rank_candidate("über", Some("Über"), "Someone Else"), Some(0));
    }
}

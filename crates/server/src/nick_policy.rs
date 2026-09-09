//! Nick hardening (owner order 2026-09-09): normalization used to defeat
//! leetspeak/elongation obfuscation, the forbidden-nick matcher built on top
//! of it, hard shape rules that reject public-id-shaped or URL-shaped
//! handles, and the impersonation-by-prefix check that keeps a self-service
//! nick from reading as an official brand/role presence.
//!
//! Every function here is pure — no database, no I/O beyond the one
//! `include_str!`d list below — so `db.rs`'s `set_nick`/`admin_set_nick` can
//! call straight into it and every rule stays unit-testable without a
//! connection.

/// The three ASCII separators a nick may contain (`db::nick_format_valid`
/// allows no others).
fn is_separator(c: char) -> bool {
    matches!(c, '_' | '-' | '.')
}

/// Lowercase → fold common leetspeak digits/symbols to the letter they
/// stand in for → drop the `_-.` separators → collapse runs of the same
/// letter to one (`hiiitler` → `hitler`). Used both to normalize a
/// candidate nick and, identically, to normalize every forbidden-list entry
/// before it is matched — see [`forbidden_hit`].
pub fn normalize_nick(raw: &str) -> String {
    let mut folded = String::with_capacity(raw.len());
    for c in raw.chars() {
        let mapped = match c.to_ascii_lowercase() {
            '0' => 'o',
            '1' => 'i',
            '2' => 'z',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '6' => 'g',
            '7' => 't',
            '8' => 'b',
            '9' => 'g',
            '@' => 'a',
            '$' => 's',
            other => other,
        };
        if is_separator(mapped) {
            continue;
        }
        folded.push(mapped);
    }

    let mut collapsed = String::with_capacity(folded.len());
    let mut last: Option<char> = None;
    for c in folded.chars() {
        if last != Some(c) {
            collapsed.push(c);
        }
        last = Some(c);
    }
    collapsed
}

/// Lowercase, `_-.`-delimited parts of `raw` — no leetspeak fold, no letter
/// collapse (each part is normalized separately by whoever compares it;
/// see [`forbidden_hit`]'s `[token]` rule and [`impersonation_hit`]'s
/// `roles`-category rule).
pub fn raw_tokens(raw: &str) -> Vec<String> {
    raw.to_ascii_lowercase()
        .split(is_separator)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// [`raw_tokens`], each normalized (see [`normalize_nick`]), dropping any
/// token that was a single character BEFORE normalization. A real nick
/// routinely carries a lone initial as one of its separator-delimited parts
/// (`Kosti_X_ItsOK`) — without this floor, that single `x` collapses to
/// itself and trips a `[token]` entry like `xxx` (a doubled or tripled
/// letter that ALSO collapses to one character) as if it were the whole
/// obfuscated word. A token that was already 2+ characters (`ss` in
/// `ss_trader`) still collapses and still matches — only a genuinely
/// single-letter part is exempt.
fn normalized_raw_tokens(raw: &str) -> Vec<String> {
    raw_tokens(raw)
        .into_iter()
        .filter(|t| t.chars().count() >= 2)
        .map(|t| normalize_nick(&t))
        .collect()
}

/// Maximal runs of ASCII digits in `raw`, plus the same runs computed after
/// dropping any separator that sits directly between two digits — so
/// `14_88` contributes both `"14"`/`"88"` (as written) and `"1488"` (the
/// obfuscation a numeric forbidden-list entry like `1488` is meant to
/// catch). Chained separators (`1_4_8_8`) collapse the same way: the bridge
/// only looks at immediate neighbours, but that is enough to fully merge a
/// chain one gap at a time.
pub fn digit_runs(raw: &str) -> Vec<String> {
    let mut runs = collect_digit_runs(raw);
    let bridged = bridge_separators_between_digits(raw);
    if bridged != raw {
        runs.extend(collect_digit_runs(&bridged));
    }
    runs
}

fn collect_digit_runs(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for c in s.chars() {
        if c.is_ascii_digit() {
            current.push(c);
        } else if !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn bridge_separators_between_digits(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    let mut result = String::with_capacity(chars.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if is_separator(c) {
            let prev_digit = result.chars().last().is_some_and(|p| p.is_ascii_digit());
            let mut j = i + 1;
            while j < chars.len() && is_separator(chars[j]) {
                j += 1;
            }
            let next_digit = chars.get(j).is_some_and(|c| c.is_ascii_digit());
            if prev_digit && next_digit {
                i += 1;
                continue;
            }
        }
        result.push(c);
        i += 1;
    }
    result
}

// ============================================================================
// Forbidden-nick matcher (owner order 2026-09-09) — see
// `crates/server/forbidden_nicks.txt`'s own header for the exact
// `[substring]`/`[token]`/`[numeric]` semantics this mirrors.
// ============================================================================

/// A forbidden nick is never assignable — not by self-service ([`db::set_nick`],
/// via [`forbidden_hit`]) and not by an admin grant ([`db::admin_set_nick`]).
/// This is the log-facing record of WHY: the section that matched and the
/// list entry (as it appears in the file, lowercase) — never surfaced to
/// the client, which only ever sees "This nick is not allowed".
///
/// [`db::set_nick`]: crate::db::set_nick
/// [`db::admin_set_nick`]: crate::db::admin_set_nick
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForbiddenHit {
    pub rule: &'static str,
    pub entry: String,
}

/// How many active rules [`parse_forbidden_nicks`] loaded per section, plus
/// everything it declined to load and why.
#[derive(Debug, Clone, Default)]
pub struct ForbiddenParseReport {
    pub substring_count: usize,
    pub token_count: usize,
    pub numeric_count: usize,
    /// Entries that normalize to nothing — dropped, never matched against.
    pub empty_after_normalize: Vec<String>,
    /// `[substring]` entries that normalize to a single character (e.g.
    /// `kkk` → `k`, `hiiitler`-style collapse eating the whole run) —
    /// dropped from CONTAINMENT matching to avoid flagging every nick that
    /// merely contains that one letter. Still enforced wherever the same
    /// word is also listed as a `[token]` (whole-word equality is immune to
    /// this, since collapsing the SAME way on both sides of an equality
    /// check never turns "contains a k" into a match).
    pub degenerate_substrings: Vec<String>,
}

struct ForbiddenList {
    /// `(normalized pattern, source entry as written in the file)`.
    substrings: Vec<(String, String)>,
    /// `(normalized pattern, source entry as written in the file)`.
    tokens: Vec<(String, String)>,
    /// Entries as written in the file (lowercase) — matched against the raw
    /// nick's digit runs or, for entries with a separator, as a literal
    /// substring of the raw nick. See [`forbidden_hit`].
    numerics: Vec<String>,
}

/// A `[substring]` entry is excluded from containment matching once
/// normalizing it leaves fewer than this many characters — see
/// [`ForbiddenParseReport::degenerate_substrings`].
const MIN_FORBIDDEN_SUBSTRING_LEN: usize = 2;

/// The checked-in forbidden-nick list — see that file's own header comment
/// for the exact format [`parse_forbidden_nicks`] expects.
const FORBIDDEN_NICKS_TXT: &str = include_str!("../forbidden_nicks.txt");

/// Parse a `forbidden_nicks.txt`-shaped list: `#` starts a comment, a
/// `[substring]`/`[token]`/`[numeric]` header switches which bucket
/// following lines fall into (sections repeat — a later header of the same
/// name keeps appending to the same bucket), blank lines are skipped.
fn parse_forbidden_nicks(text: &str) -> (ForbiddenList, ForbiddenParseReport) {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Section {
        None,
        Substring,
        Token,
        Numeric,
    }

    let mut section = Section::None;
    let mut substrings = Vec::new();
    let mut tokens = Vec::new();
    let mut numerics = Vec::new();
    let mut empty_after_normalize = Vec::new();
    let mut degenerate_substrings = Vec::new();

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = match name.trim().to_ascii_lowercase().as_str() {
                "substring" => Section::Substring,
                "token" => Section::Token,
                "numeric" => Section::Numeric,
                _ => Section::None,
            };
            continue;
        }

        let source = line.to_ascii_lowercase();
        match section {
            Section::Substring => {
                let pattern = normalize_nick(&source);
                if pattern.is_empty() {
                    empty_after_normalize.push(source);
                } else if pattern.chars().count() < MIN_FORBIDDEN_SUBSTRING_LEN {
                    degenerate_substrings.push(source);
                } else {
                    substrings.push((pattern, source));
                }
            }
            Section::Token => {
                let pattern = normalize_nick(&source);
                if pattern.is_empty() {
                    empty_after_normalize.push(source);
                } else {
                    tokens.push((pattern, source));
                }
            }
            Section::Numeric => numerics.push(source),
            // A line before any recognised header can never be matched —
            // report it the same way a normalizes-to-nothing entry is.
            Section::None => empty_after_normalize.push(source),
        }
    }

    let report = ForbiddenParseReport {
        substring_count: substrings.len(),
        token_count: tokens.len(),
        numeric_count: numerics.len(),
        empty_after_normalize,
        degenerate_substrings,
    };
    (ForbiddenList { substrings, tokens, numerics }, report)
}

static FORBIDDEN_LIST: std::sync::OnceLock<ForbiddenList> = std::sync::OnceLock::new();

/// Force-parse [`FORBIDDEN_NICKS_TXT`] and cache it — called once at boot
/// (`db::init_db`) so the parse cost and any warnings land in the startup
/// log rather than on the first nick-change request. Safe to call more than
/// once (e.g. from a test that also calls [`forbidden_hit`] directly): only
/// the first call's parse wins, matching every other reader of the same
/// static list.
pub fn init_forbidden_list() -> ForbiddenParseReport {
    let (list, report) = parse_forbidden_nicks(FORBIDDEN_NICKS_TXT);
    let _ = FORBIDDEN_LIST.set(list);
    report
}

fn forbidden_list() -> &'static ForbiddenList {
    FORBIDDEN_LIST.get_or_init(|| parse_forbidden_nicks(FORBIDDEN_NICKS_TXT).0)
}

/// Whether `nick` matches the forbidden-nick registry — checked in
/// [`crate::db::set_nick`] and [`crate::db::admin_set_nick`] alike, since a
/// forbidden nick is off-limits even to an operator's grant. `nick` is the
/// RAW candidate (not yet normalized); every rule normalizes what it needs
/// itself.
pub fn forbidden_hit(nick: &str) -> Option<ForbiddenHit> {
    let list = forbidden_list();
    let normalized = normalize_nick(nick);
    let raw_lower = nick.to_ascii_lowercase();
    let normalized_tokens = normalized_raw_tokens(nick);
    let runs = digit_runs(nick);

    for (pattern, source) in &list.substrings {
        if normalized.contains(pattern.as_str()) {
            return Some(ForbiddenHit { rule: "substring", entry: source.clone() });
        }
    }
    for (pattern, source) in &list.tokens {
        if normalized == *pattern || normalized_tokens.iter().any(|t| t == pattern) {
            return Some(ForbiddenHit { rule: "token", entry: source.clone() });
        }
    }
    for entry in &list.numerics {
        let hit = if entry.chars().any(is_separator) {
            raw_lower.contains(entry.as_str())
        } else {
            runs.iter().any(|r| r == entry)
        };
        if hit {
            return Some(ForbiddenHit { rule: "numeric", entry: entry.clone() });
        }
    }
    None
}

// ============================================================================
// Hard nick-shape rules (owner order 2026-09-09) — layered on top of
// `db::nick_format_valid`'s charset/length gate, everywhere that gate is
// applied to a user-chosen candidate.
// ============================================================================

/// TLD-shaped suffixes that make a nick read as a domain name rather than a
/// handle.
const FORBIDDEN_TLD_SUFFIXES: &[&str] =
    &[".com", ".net", ".org", ".io", ".ru", ".su", ".xyz", ".app", ".dev"];

/// A digit run longer than this reads as a phone number, an amount, or an
/// obfuscated word rather than a handle.
const MAX_DIGIT_RUN: usize = 6;

/// A candidate at least this long, made ENTIRELY of hex digits, reads as a
/// public id rather than a chosen handle.
const MIN_HEX_LOOKALIKE_LEN: usize = 12;

/// Extra shape rules beyond `db::nick_format_valid`'s charset/length check:
/// the last character must be alphanumeric (no nick opens OR closes on a
/// separator), no two separators may sit back to back, the nick may not be
/// all digits, may not be a hex string 12+ characters long (looks like a
/// public id), may not contain `http`/`www.` or end in a TLD-shaped suffix
/// (looks like a URL), and may not contain more than [`MAX_DIGIT_RUN`]
/// consecutive digits.
pub fn nick_shape_ok(nick: &str) -> bool {
    let Some(last) = nick.chars().last() else {
        return false;
    };
    if !last.is_ascii_alphanumeric() {
        return false;
    }

    let chars: Vec<char> = nick.chars().collect();
    for pair in chars.windows(2) {
        if is_separator(pair[0]) && is_separator(pair[1]) {
            return false;
        }
    }

    if chars.iter().all(|c| c.is_ascii_digit()) {
        return false;
    }

    if chars.len() >= MIN_HEX_LOOKALIKE_LEN && chars.iter().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }

    let lower = nick.to_ascii_lowercase();
    if lower.contains("http") || lower.contains("www.") {
        return false;
    }
    if FORBIDDEN_TLD_SUFFIXES.iter().any(|tld| lower.ends_with(tld)) {
        return false;
    }

    let mut run = 0usize;
    for c in &chars {
        if c.is_ascii_digit() {
            run += 1;
            if run > MAX_DIGIT_RUN {
                return false;
            }
        } else {
            run = 0;
        }
    }

    true
}

// ============================================================================
// Impersonation-by-prefix (owner order 2026-09-09) — `db::set_nick` only,
// never `db::admin_set_nick`: an operator handing out a reserved handle
// is the intended way onto it, not something this rule should ever block.
// ============================================================================

/// Words that, appended to a reserved handle, still read as an attempt to
/// speak for it (`binance_support`, `admin_care`).
const IMPERSONATION_SUFFIX_WORDS: &[&str] =
    &["official", "support", "help", "team", "admin", "staff", "bot", "service", "care", "mod", "moderator"];

/// A reserved entry shorter than this (`eth`, `sol`) is too common as an
/// ordinary substring to safely anchor a prefix or whole-token match.
const MIN_IMPERSONATION_LEN: usize = 4;

/// One row of the in-memory reserved-nick cache
/// (`ControlPlane::reserved_nick_cache`), as [`impersonation_hit`] needs it
/// — the `(nick, category)` [`crate::db::ReservedNickEntry`] carries,
/// borrowed rather than owned so the caller can hand it a cache snapshot
/// without an extra clone per entry.
#[derive(Debug, Clone, Copy)]
pub struct ReservedHandle<'a> {
    pub nick_lower: &'a str,
    pub category: &'a str,
}

/// Whether `candidate` reads as an attempt to impersonate one of `reserved`
/// — the caller (`db::set_nick`) is expected to have already refused an
/// EXACT reserved match before calling this; this only catches candidates
/// that dodge the exact check by decorating a reserved handle. Two
/// independent rules, either one refuses:
///
/// 1. `candidate` with separators dropped (lowercased, no leetspeak fold —
///    a literal digit suffix must stay literal digits) starts with a
///    reserved entry at least [`MIN_IMPERSONATION_LEN`] characters long
///    (separators dropped the same way), and whatever follows is either
///    all digits (`binance1`, `coinbase2024`) or one of
///    [`IMPERSONATION_SUFFIX_WORDS`] (`coinbase_support`).
/// 2. Any `_`/`-`/`.`-delimited part of `candidate`, normalized the same
///    way [`forbidden_hit`]'s `[token]` rule normalizes a raw token,
///    exactly equals a `category == "roles"` reserved entry at least
///    [`MIN_IMPERSONATION_LEN`] characters long (`admin_john`,
///    `john.support`).
///
/// Returns the reserved entry that was impersonated, for the caller to log
/// — never surfaced to the client (`NickError::Reserved`'s `409`).
pub fn impersonation_hit<'a>(candidate: &str, reserved: &[ReservedHandle<'a>]) -> Option<&'a str> {
    let candidate_joined = drop_separators_lower(candidate);
    let candidate_tokens = normalized_raw_tokens(candidate);

    for handle in reserved {
        let joined = drop_separators_lower(handle.nick_lower);
        if joined.chars().count() >= MIN_IMPERSONATION_LEN {
            if let Some(remainder) = candidate_joined.strip_prefix(joined.as_str()) {
                let looks_like_a_suffix =
                    remainder.chars().all(|c| c.is_ascii_digit()) || IMPERSONATION_SUFFIX_WORDS.contains(&remainder);
                if looks_like_a_suffix {
                    return Some(handle.nick_lower);
                }
            }
        }

        if handle.category.eq_ignore_ascii_case("roles") {
            let role = normalize_nick(handle.nick_lower);
            if role.chars().count() >= MIN_IMPERSONATION_LEN && candidate_tokens.iter().any(|t| t == &role) {
                return Some(handle.nick_lower);
            }
        }
    }
    None
}

/// Lowercase and drop `_`/`-`/`.` — the de-punctuation half of
/// [`normalize_nick`] without its leetspeak fold or letter-run collapse, so
/// a literal digit suffix (`binance1`) stays literal digits instead of
/// being folded into a letter.
fn drop_separators_lower(raw: &str) -> String {
    raw.chars().filter(|c| !is_separator(*c)).collect::<String>().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // normalize_nick / raw_tokens / digit_runs
    // ------------------------------------------------------------------

    #[test]
    fn normalize_nick_folds_leetspeak_and_collapses_repeats() {
        assert_eq!(normalize_nick("hiiitler"), "hitler");
        assert_eq!(normalize_nick("h1tl3r"), "hitler");
        assert_eq!(normalize_nick("h.i.t.l.e.r"), "hitler");
        assert_eq!(normalize_nick("Hitler1488"), "hitleriab");
        assert_eq!(normalize_nick("xX_hitler_Xx"), "xhitlerx");
    }

    #[test]
    fn raw_tokens_lowercases_and_splits_on_separators() {
        assert_eq!(raw_tokens("Ss_Trader"), vec!["ss".to_string(), "trader".to_string()]);
        assert_eq!(raw_tokens("crisis_trader"), vec!["crisis".to_string(), "trader".to_string()]);
        assert_eq!(raw_tokens("nosep"), vec!["nosep".to_string()]);
    }

    #[test]
    fn digit_runs_bridges_separators_between_digits() {
        let runs = digit_runs("pro14_88");
        assert!(runs.contains(&"14".to_string()));
        assert!(runs.contains(&"88".to_string()));
        assert!(runs.contains(&"1488".to_string()));

        let chained = digit_runs("1_4_8_8");
        assert!(chained.contains(&"1488".to_string()));

        assert_eq!(digit_runs("trader88"), vec!["88".to_string()]);
    }

    // ------------------------------------------------------------------
    // forbidden_hit
    // ------------------------------------------------------------------

    #[test]
    fn forbidden_hit_catches_hate_and_slur_variants() {
        for bad in [
            "hitler",
            "Hitler1488",
            "h1tl3r",
            "h.i.t.l.e.r",
            "xX_hitler_Xx",
            "nazi_trader",
            "kkk",
            "ss_trader",
            "user1488",
            "pro14_88",
            "blowjob_king",
            "pizdec",
        ] {
            assert!(forbidden_hit(bad).is_some(), "expected {bad:?} to be forbidden");
        }
    }

    #[test]
    fn forbidden_hit_passes_ordinary_nicks() {
        for ok in ["crisis_trader", "cassandra", "analyst", "trader88"] {
            assert_eq!(forbidden_hit(ok), None, "expected {ok:?} to pass");
        }
    }

    /// `kkk` collapses to a single letter under `normalize_nick` — proof
    /// that dropping it from containment matching (see
    /// `ForbiddenParseReport::degenerate_substrings`) does not turn "any
    /// nick containing the letter k" into a false positive, while the
    /// identical `[token]` entry still catches `kkk` itself (see the FAIL
    /// case above).
    #[test]
    fn forbidden_hit_does_not_flag_ordinary_words_containing_k() {
        for ok in ["banker", "koala", "kraken_fan", "market_maker"] {
            assert_eq!(forbidden_hit(ok), None, "expected {ok:?} to pass");
        }
    }

    /// A lone middle initial is an ordinary separator-delimited part of a
    /// real name — it must never collide with a `[token]` entry that only
    /// reads as a single letter because it is itself a doubled/tripled
    /// letter (`ss`, `xxx`) collapsing under `normalize_nick`.
    #[test]
    fn forbidden_hit_does_not_flag_a_lone_middle_initial() {
        for ok in ["Kosti_X_ItsOK", "Anna_S_Ivanova", "Jane_K_Smith"] {
            assert_eq!(forbidden_hit(ok), None, "expected {ok:?} to pass");
        }
    }

    #[test]
    fn forbidden_hit_numeric_rule_ignores_a_bare_88() {
        assert_eq!(forbidden_hit("trader88"), None);
    }

    #[test]
    fn shipped_forbidden_nicks_file_normalizes_every_entry_and_reports_counts() {
        let (_, report) = parse_forbidden_nicks(FORBIDDEN_NICKS_TXT);
        assert!(
            report.empty_after_normalize.is_empty(),
            "entries that cannot normalize: {:?}",
            report.empty_after_normalize
        );
        assert!(report.substring_count > 0);
        assert!(report.token_count > 0);
        assert!(report.numeric_count > 0);
    }

    // ------------------------------------------------------------------
    // nick_shape_ok
    // ------------------------------------------------------------------

    #[test]
    fn nick_shape_ok_last_char_must_be_alphanumeric() {
        assert!(!nick_shape_ok("trader_"));
        assert!(!nick_shape_ok("trader."));
        assert!(nick_shape_ok("trader1"));
    }

    #[test]
    fn nick_shape_ok_rejects_consecutive_separators() {
        assert!(!nick_shape_ok("a__b"));
        assert!(!nick_shape_ok("a.-b"));
        assert!(nick_shape_ok("a_b-c"));
    }

    #[test]
    fn nick_shape_ok_rejects_all_digits() {
        assert!(!nick_shape_ok("123456"));
        assert!(nick_shape_ok("trader1"));
    }

    #[test]
    fn nick_shape_ok_rejects_long_hex_lookalikes() {
        assert!(!nick_shape_ok("deadbeef0123"));
        assert!(nick_shape_ok("deadbeef01"));
    }

    #[test]
    fn nick_shape_ok_rejects_url_lookalikes() {
        assert!(!nick_shape_ok("http_trader"));
        assert!(!nick_shape_ok("www.market1"));
        assert!(!nick_shape_ok("trader.com"));
        assert!(nick_shape_ok("trader.chart"));
    }

    #[test]
    fn nick_shape_ok_rejects_long_digit_runs() {
        assert!(!nick_shape_ok("user1234567"));
        assert!(nick_shape_ok("user123456"));
    }

    // ------------------------------------------------------------------
    // impersonation_hit
    // ------------------------------------------------------------------

    fn sample_reserved() -> Vec<ReservedHandle<'static>> {
        vec![
            ReservedHandle { nick_lower: "binance", category: "trading" },
            ReservedHandle { nick_lower: "coinbase", category: "trading" },
            ReservedHandle { nick_lower: "admin", category: "roles" },
            ReservedHandle { nick_lower: "support", category: "roles" },
            ReservedHandle { nick_lower: "eth", category: "trading" },
            ReservedHandle { nick_lower: "solana", category: "trading" },
            ReservedHandle { nick_lower: "tradingview", category: "trading" },
        ]
    }

    #[test]
    fn impersonation_hit_catches_prefix_plus_digits() {
        let reserved = sample_reserved();
        assert_eq!(impersonation_hit("binance1", &reserved), Some("binance"));
        assert_eq!(impersonation_hit("coinbase2024", &reserved), Some("coinbase"));
    }

    #[test]
    fn impersonation_hit_catches_prefix_plus_role_suffix_word() {
        let reserved = sample_reserved();
        assert_eq!(impersonation_hit("coinbase_support", &reserved), Some("coinbase"));
    }

    #[test]
    fn impersonation_hit_catches_a_roles_category_token_anywhere_in_the_nick() {
        let reserved = sample_reserved();
        assert_eq!(impersonation_hit("admin_john", &reserved), Some("admin"));
    }

    #[test]
    fn impersonation_hit_lets_short_tickers_and_unrelated_compounds_through() {
        let reserved = sample_reserved();
        assert_eq!(impersonation_hit("eth_trader", &reserved), None);
        assert_eq!(impersonation_hit("solana_fan", &reserved), None);
    }
}

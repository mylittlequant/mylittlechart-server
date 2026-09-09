//! Shared user-text hardening.
//!
//! [`clean_user_text`] is the one place every route that accepts free-form
//! text from a caller (share titles, forum thread/reply titles and bodies,
//! admin blog post fields, board metadata) runs it through before the text
//! ever reaches a database write:
//!  - NFC-normalizes (so two visually identical strings — e.g. one using a
//!    combining accent, one precomposed — compare equal downstream, in FTS5
//!    search and in any future duplicate check).
//!  - Strips `\r` (CRLF/CR-only line endings collapse to plain `\n`).
//!  - Refuses any OTHER control character (a null byte, an ANSI escape, …)
//!    outright — this is a hard refusal, not a silent strip, so a caller
//!    sending one is told why rather than having it quietly vanish.
//!  - Trims leading/trailing whitespace, then collapses runs of 3+
//!    consecutive newlines (2+ blank lines) down to exactly one blank line.
//!  - Refuses empty (after the above) or longer than a caller-chosen
//!    character cap (counted in `chars`, not bytes — a human-facing length
//!    limit, not a storage one).
//!
//! Existing per-field FORMAT rules (forum title 3-120 chars, forum body
//! 1-8192 bytes, post id shape, board slug shape, …) still live in
//! `db.rs`/`social_db.rs` exactly as before — this only adds the cleaning
//! and the outer character cap those checks never covered.
//!
//! [`sanitize_display_name`] is the lenient sibling used for OAuth-provided
//! display names: those never come from an unauthenticated caller directly
//! (the value comes back-channel from GitHub/Discord/Google/Twitter/
//! Telegram), so a malformed one should degrade the stored name rather than
//! fail the login — it never returns an error.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use unicode_normalization::UnicodeNormalization;

/// Why [`clean_user_text`] refused an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextError {
    /// Empty once trimmed and cleaned — including an input that was
    /// entirely whitespace, or entirely the `\r` this cleans silently.
    Empty,
    /// A control character other than `\n`/`\t` was present.
    ControlChar,
    /// More than `max_chars` Unicode scalar values after cleaning.
    TooLong { max_chars: usize },
}

impl TextError {
    /// The wire `code` field — `"text_too_long"` is its own code so a
    /// client can tell "shorten it" apart from "something in it is not
    /// allowed" without parsing `error`.
    pub fn code(self) -> &'static str {
        match self {
            TextError::TooLong { .. } => "text_too_long",
            TextError::Empty | TextError::ControlChar => "text_invalid",
        }
    }

    pub fn message(self) -> String {
        match self {
            TextError::Empty => "text must not be empty".to_string(),
            TextError::ControlChar => {
                "text contains a disallowed control character".to_string()
            }
            TextError::TooLong { max_chars } => {
                format!("text exceeds {max_chars} characters")
            }
        }
    }
}

impl IntoResponse for TextError {
    fn into_response(self) -> Response {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": self.message(), "code": self.code() })),
        )
            .into_response()
    }
}

/// Clean and validate one piece of caller-supplied text. See the module doc
/// for exactly what this does and does not enforce.
pub fn clean_user_text(input: &str, max_chars: usize) -> Result<String, TextError> {
    // `\r` is the one control character silently dropped rather than
    // refused — CRLF and lone-CR line endings both collapse to `\n`.
    let no_cr: String = input.chars().filter(|&c| c != '\r').collect();

    if no_cr.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
        return Err(TextError::ControlChar);
    }

    // NFC-normalize before trimming/measuring — canonical form is what
    // every length check and every downstream comparison should see.
    let normalized: String = no_cr.nfc().collect();
    let trimmed = normalized.trim();
    let collapsed = collapse_blank_lines(trimmed);

    if collapsed.is_empty() {
        return Err(TextError::Empty);
    }

    let char_count = collapsed.chars().count();
    if char_count > max_chars {
        return Err(TextError::TooLong { max_chars });
    }

    Ok(collapsed)
}

/// Collapse runs of 3+ consecutive `\n` (2+ blank lines) down to exactly 2
/// (one blank line, kept as a paragraph break). `trim` already removed any
/// leading/trailing run; this only bounds one in the middle.
fn collapse_blank_lines(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut newline_run = 0usize;
    for c in s.chars() {
        if c == '\n' {
            newline_run += 1;
            if newline_run <= 2 {
                out.push(c);
            }
        } else {
            newline_run = 0;
            out.push(c);
        }
    }
    out
}

/// [`clean_user_text`], but a value that is empty (or entirely whitespace)
/// passes through as an empty string instead of being refused — the right
/// behavior for a field that is genuinely OPTIONAL (an admin post's
/// `summary`, a share's `title`, a board's `description`): "nothing was
/// given" is not the same refusal as "something invalid was given". Still
/// refuses a control character or an over-length value once something
/// non-blank IS given.
pub fn clean_optional_user_text(input: &str, max_chars: usize) -> Result<String, TextError> {
    if input.trim().is_empty() {
        return Ok(String::new());
    }
    clean_user_text(input, max_chars)
}

/// Best-effort cleanup for text that must never fail the caller's request —
/// see the module doc. NFC-normalizes, drops every control character
/// (`\n`/`\t` included — a display name has no legitimate use for either),
/// trims, and truncates to `max_chars` Unicode scalar values. Never errors;
/// an input that cleans down to nothing just returns an empty string.
pub fn sanitize_display_name(input: &str, max_chars: usize) -> String {
    let cleaned: String = input.nfc().filter(|c| !c.is_control()).collect();
    cleaned.trim().chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfc_normalizes_combining_sequences() {
        // "e" + COMBINING ACUTE ACCENT (NFD) must normalize to the single
        // precomposed codepoint (NFC) — otherwise two visually-identical
        // titles would compare unequal downstream.
        let nfd = "e\u{0301}";
        let cleaned = clean_user_text(nfd, 100).expect("valid text");
        assert_eq!(cleaned, "\u{00e9}");
        assert_eq!(cleaned.chars().count(), 1);
    }

    #[test]
    fn control_characters_are_refused_except_tab_and_newline() {
        assert_eq!(clean_user_text("hello\tworld", 100), Ok("hello\tworld".to_string()));
        assert_eq!(clean_user_text("hello\nworld", 100), Ok("hello\nworld".to_string()));
        assert_eq!(clean_user_text("hello\u{0007}world", 100), Err(TextError::ControlChar));
        assert_eq!(clean_user_text("hello\u{001b}[31mworld", 100), Err(TextError::ControlChar));
    }

    #[test]
    fn carriage_return_is_stripped_not_refused() {
        assert_eq!(clean_user_text("hello\r\nworld", 100), Ok("hello\nworld".to_string()));
    }

    #[test]
    fn empty_after_trim_is_refused() {
        assert_eq!(clean_user_text("   \n\t  ", 100), Err(TextError::Empty));
        assert_eq!(clean_user_text("", 100), Err(TextError::Empty));
        assert_eq!(clean_user_text("\r\r\r", 100), Err(TextError::Empty));
    }

    #[test]
    fn too_long_is_measured_in_chars_not_bytes() {
        let multibyte = "é".repeat(10); // 2 bytes each in UTF-8, 1 char each.
        assert!(clean_user_text(&multibyte, 10).is_ok());
        assert_eq!(
            clean_user_text(&multibyte, 9),
            Err(TextError::TooLong { max_chars: 9 })
        );
    }

    #[test]
    fn collapses_more_than_two_consecutive_blank_lines() {
        let cleaned = clean_user_text("one\n\n\n\n\ntwo", 100).expect("valid text");
        assert_eq!(cleaned, "one\n\ntwo");
    }

    #[test]
    fn sanitize_display_name_drops_controls_and_truncates() {
        assert_eq!(sanitize_display_name("Alice\u{0007}", 10), "Alice");
        assert_eq!(sanitize_display_name("A very long name indeed", 7), "A very ");
        assert_eq!(sanitize_display_name("  spaced  ", 20), "spaced");
        assert_eq!(sanitize_display_name("\u{0001}\u{0002}", 10), "");
    }

    #[test]
    fn clean_optional_user_text_lets_blank_input_through_as_empty() {
        assert_eq!(clean_optional_user_text("", 100), Ok(String::new()));
        assert_eq!(clean_optional_user_text("   ", 100), Ok(String::new()));
        assert_eq!(clean_optional_user_text("hello", 100), Ok("hello".to_string()));
        assert_eq!(
            clean_optional_user_text("hello\u{0007}", 100),
            Err(TextError::ControlChar)
        );
    }

    #[test]
    fn error_code_matches_the_documented_wire_shape() {
        assert_eq!(TextError::Empty.code(), "text_invalid");
        assert_eq!(TextError::ControlChar.code(), "text_invalid");
        assert_eq!(TextError::TooLong { max_chars: 5 }.code(), "text_too_long");
    }
}

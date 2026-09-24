//! The Matrix sync-token format `GET /keys/changes?from=&to=` (P9) consumes
//! and `GET /sync` (P10, not yet implemented) will emit — defined here,
//! once, ahead of P10, per that piece's own binding rule: "token format must
//! match what P10's `/sync` will emit". Every future caller that needs a
//! sync token parses through [`parse`] rather than growing a second
//! implementation.
//!
//! A `format(stream_id) -> String` companion (`format!("s{stream_id}")`) is
//! deliberately NOT built yet: P9 has no producer of a sync token (only a
//! consumer, `GET /keys/changes`'s `from`/`to`), and `-D warnings`' dead-code
//! lint flags a `pub` function with zero callers anywhere in this binary
//! crate (see `routes::matrix`'s own module doc for the same rule applied to
//! `MatrixError::not_json`). P10's `/sync` handler — this format's first
//! actual emitter (`next_batch`, `prev_batch`) — adds it back the moment a
//! real call site exists.
//!
//! # Format: `s{stream_id}`
//!
//! `stream_id` is `messenger.db`'s own global `stream_counter` value — the
//! same axis [`mylittlechart_server::matrix_store::next_stream_id`]/
//! [`mylittlechart_server::matrix_store::max_stream_id`] and
//! `routes::matrix::messaging`'s own `"t{stream_id}"` `/messages` pagination
//! token already use. A sync token names a POSITION in that one global
//! order, exactly like every other stream-ordered cursor in this codebase.
//! The leading `s` is Matrix's own conventional sync-token sigil
//! (distinguishing it from `/messages`' `t`-prefixed pagination tokens at a
//! glance in a log line), not a format version — there is exactly one sync
//! token shape, and it is not expected to grow a second one.
//!
//! # Why no typing component
//!
//! An early sketch of this format considered folding
//! [`mylittlechart_server::live::TypingRegistry`]'s per-room serial into the
//! token (`s{stream_id}_{typing_serial}`). Typing state is never delta'd
//! against `since` at all (plan §3.6: "read fresh on every /sync, never
//! delta'd against since" — the CURRENT typers are reported unconditionally,
//! regardless of the token's position), so a typing component would be dead
//! weight this format would carry forever with no consumer ever reading it —
//! omitted here rather than added and left unused.

use super::MatrixError;

/// Parse a sync token back into its `stream_id`. Accepts the `s`-prefixed
/// form this module emits; also accepts a bare integer (a client that
/// echoes back a token verbatim never needs this leniency, but it costs
/// nothing and matches `routes::matrix::messaging`'s own `parse_stream_token`
/// leniency for the same reason).
pub fn parse(raw: &str) -> Result<i64, MatrixError> {
    let digits = raw.strip_prefix('s').unwrap_or(raw);
    digits.parse::<i64>().map_err(|_| MatrixError::invalid_param("malformed sync token"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_token_round_trips() {
        for stream_id in [0_i64, 1, 42, 1_000_000] {
            let token = format!("s{stream_id}");
            assert_eq!(parse(&token).expect("parse"), stream_id);
        }
    }

    #[test]
    fn sync_token_accepts_a_bare_integer_too() {
        assert_eq!(parse("42").expect("parse"), 42);
    }

    #[test]
    fn sync_token_rejects_garbage() {
        let err = parse("not-a-token").unwrap_err();
        assert_eq!(err.errcode, "M_INVALID_PARAM");
    }
}

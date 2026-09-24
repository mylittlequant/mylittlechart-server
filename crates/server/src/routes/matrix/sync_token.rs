//! The Matrix sync-token format `GET /sync` (P10) emits and `GET
//! /keys/changes` (P9) also consumes — defined here, once, so every future
//! caller that needs a sync token parses/formats through this module rather
//! than growing a second implementation.
//!
//! # Format: `s{stream_id}_{typing_gen}`
//!
//! `stream_id` is `messenger.db`'s own global `stream_counter` value — the
//! same axis [`mylittlechart_server::matrix_store::next_stream_id`]/
//! [`mylittlechart_server::matrix_store::max_stream_id`] and
//! `routes::matrix::messaging`'s own `"t{stream_id}"` `/messages` pagination
//! token already use. `typing_gen` is
//! [`mylittlechart_server::live::TypingRegistry`]'s GLOBAL typing
//! generation (see that module's own doc for why it is global, not
//! per-room) as of the moment this token was minted — `routes::matrix::sync`
//! compares it against a room's own current typing serial to tell "this
//! room's typing set changed since this token" apart from "nothing changed
//! at all" without a busy long-poll loop. The leading `s` is Matrix's own
//! conventional sync-token sigil (distinguishing it from `/messages`'
//! `t`-prefixed pagination tokens at a glance in a log line), not a format
//! version — there is exactly one sync token shape, and it is not expected
//! to grow a second one.
//!
//! # Backward compatibility with the pre-typing-gen form
//!
//! `GET /keys/changes` (P9) predates this format's typing component and
//! only ever emitted/consumed a bare `s{stream_id}` (or a plain integer).
//! [`parse`] still accepts that shorter form, defaulting `typing_gen` to
//! `0` — never greater than any real room serial a fresh
//! [`mylittlechart_server::live::TypingRegistry`] could have assigned by
//! the time such a token is used, so this default never wrongly suppresses
//! a real typing change (see [`mylittlechart_server::live::TypingRegistry::
//! current_typing_gen`]'s own doc).

use super::MatrixError;

/// A parsed sync token: a position in `messenger.db`'s global stream order,
/// plus the typing generation observed at that position — see the module
/// doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncToken {
    pub stream_id: i64,
    pub typing_gen: u64,
}

/// Format a sync token — `routes::matrix::sync`'s own `next_batch` is this
/// format's one emitter.
pub fn format(stream_id: i64, typing_gen: u64) -> String {
    format!("s{stream_id}_{typing_gen}")
}

/// Parse a sync token back into its `(stream_id, typing_gen)` pair. Accepts
/// the full `s{stream_id}_{typing_gen}` form [`format`] emits, the bare
/// `s{stream_id}` form (typing_gen defaults to `0` — see the module doc),
/// and a plain integer (a client that echoes a token verbatim never needs
/// this leniency, but it costs nothing and matches
/// `routes::matrix::messaging`'s own `parse_stream_token` leniency for the
/// same reason).
pub fn parse(raw: &str) -> Result<SyncToken, MatrixError> {
    let digits = raw.strip_prefix('s').unwrap_or(raw);
    let (stream_part, typing_part) = match digits.split_once('_') {
        Some((stream_part, typing_part)) => (stream_part, Some(typing_part)),
        None => (digits, None),
    };
    let stream_id = stream_part.parse::<i64>().map_err(|_| MatrixError::invalid_param("malformed sync token"))?;
    let typing_gen = match typing_part {
        Some(raw_gen) => raw_gen.parse::<u64>().map_err(|_| MatrixError::invalid_param("malformed sync token"))?,
        None => 0,
    };
    Ok(SyncToken { stream_id, typing_gen })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_token_round_trips_the_full_form() {
        for (stream_id, typing_gen) in [(0_i64, 0_u64), (1, 1), (42, 7), (1_000_000, 12_345)] {
            let token = format(stream_id, typing_gen);
            assert_eq!(parse(&token).expect("parse"), SyncToken { stream_id, typing_gen });
        }
    }

    #[test]
    fn sync_token_accepts_the_legacy_bare_stream_id_form_with_typing_gen_zero() {
        assert_eq!(parse("s42").expect("parse"), SyncToken { stream_id: 42, typing_gen: 0 });
    }

    #[test]
    fn sync_token_accepts_a_bare_integer_too() {
        assert_eq!(parse("42").expect("parse"), SyncToken { stream_id: 42, typing_gen: 0 });
    }

    #[test]
    fn sync_token_rejects_garbage() {
        let err = parse("not-a-token").unwrap_err();
        assert_eq!(err.errcode, "M_INVALID_PARAM");
    }

    #[test]
    fn sync_token_rejects_a_malformed_typing_gen() {
        let err = parse("s42_not-a-number").unwrap_err();
        assert_eq!(err.errcode, "M_INVALID_PARAM");
    }
}

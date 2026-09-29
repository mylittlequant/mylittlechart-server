//! Verifier for dig2pay's `X-Dig2pay-Signature` header
//! (`docs/dig2pay/plans/merchant-contract-2026-09-10.md` §1).
//!
//! ```text
//! X-Dig2pay-Signature: t=<unix seconds>,v1=<hex hmac>[,v1=<hex hmac>]
//! ```
//!
//! * The signed payload is the byte string `"{t}.{raw body}"` — the exact
//!   bytes received. The caller must hand this module the raw request body,
//!   never a re-serialised copy.
//! * HMAC-SHA256, compared in constant time (`Mac::verify_slice`).
//! * `t` is covered by the signature; a delivery whose `t` is more than five
//!   minutes from this server's clock, in either direction, is refused.
//! * During a secret rotation the processor sends one `v1=` per live secret.
//!   A delivery is accepted if ANY `v1=` verifies against ANY secret held.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Replay window, in seconds, in either direction.
pub const MAX_CLOCK_SKEW_SECS: i64 = 5 * 60;

/// More `v1=` values than any rotation window can produce is treated as
/// abuse (each one costs an HMAC finalisation).
const MAX_SIGNATURE_VALUES: usize = 8;

/// A hex-encoded SHA-256 HMAC is 32 bytes.
const SIGNATURE_LEN: usize = 32;

/// Why a delivery was refused. Deliberately coarse on the wire (the route
/// answers a bare 401 for all of them) but distinct here for tests and logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// No webhook secret is configured, so nothing can be verified.
    NoSecrets,
    /// The header is missing, or is not `t=...,v1=...` shaped.
    Malformed,
    /// `t` is more than [`MAX_CLOCK_SKEW_SECS`] from now.
    OutsideWindow,
    /// No `v1=` verified against any secret.
    Mismatch,
}

struct ParsedHeader<'a> {
    /// `t` exactly as sent — the signed payload uses these bytes verbatim.
    t_text: &'a str,
    t: i64,
    signatures: Vec<[u8; SIGNATURE_LEN]>,
}

fn parse_header(header: &str) -> Result<ParsedHeader<'_>, SignatureError> {
    let mut t_text: Option<&str> = None;
    let mut signatures = Vec::new();
    for part in header.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = part.split_once('=').ok_or(SignatureError::Malformed)?;
        match key {
            "t" => {
                // Digits only, so the text we sign is also the number we
                // range-check; 18 digits cannot overflow an i64.
                let digits_only = !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit());
                if t_text.is_some() || !digits_only || value.len() > 18 {
                    return Err(SignatureError::Malformed);
                }
                t_text = Some(value);
            }
            "v1" => {
                if signatures.len() >= MAX_SIGNATURE_VALUES {
                    return Err(SignatureError::Malformed);
                }
                let bytes = hex::decode(value).map_err(|_| SignatureError::Malformed)?;
                let signature: [u8; SIGNATURE_LEN] =
                    bytes.try_into().map_err(|_| SignatureError::Malformed)?;
                signatures.push(signature);
            }
            // A signature scheme this server does not know (a future `v2`)
            // is ignored, not an error: the `v1` value still decides.
            _ => {}
        }
    }
    let t_text = t_text.ok_or(SignatureError::Malformed)?;
    if signatures.is_empty() {
        return Err(SignatureError::Malformed);
    }
    let t = t_text.parse::<i64>().map_err(|_| SignatureError::Malformed)?;
    Ok(ParsedHeader { t_text, t, signatures })
}

/// Verify `header` over `raw_body` against every secret in `secrets`.
///
/// `now_unix` is this server's clock in Unix seconds (a parameter so tests
/// can pin it). An empty `secrets` list fails closed.
pub fn verify(
    secrets: &[Vec<u8>],
    header: &str,
    raw_body: &[u8],
    now_unix: i64,
) -> Result<(), SignatureError> {
    if secrets.is_empty() {
        return Err(SignatureError::NoSecrets);
    }
    let parsed = parse_header(header)?;
    if now_unix.saturating_sub(parsed.t).abs() > MAX_CLOCK_SKEW_SECS {
        return Err(SignatureError::OutsideWindow);
    }
    for secret in secrets {
        let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
            continue;
        };
        mac.update(parsed.t_text.as_bytes());
        mac.update(b".");
        mac.update(raw_body);
        for signature in &parsed.signatures {
            if mac.clone().verify_slice(signature).is_ok() {
                return Ok(());
            }
        }
    }
    Err(SignatureError::Mismatch)
}

/// Build a header value the way the processor does — tests only.
#[cfg(test)]
pub fn sign_for_test(secrets: &[&[u8]], t: i64, raw_body: &[u8]) -> String {
    let mut header = format!("t={t}");
    for secret in secrets {
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
        mac.update(t.to_string().as_bytes());
        mac.update(b".");
        mac.update(raw_body);
        header.push_str(",v1=");
        header.push_str(&hex::encode(mac.finalize().into_bytes()));
    }
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;
    const BODY: &[u8] = br#"{"event_id":"evt_1","kind":"payment_confirmed"}"#;

    fn secrets(list: &[&str]) -> Vec<Vec<u8>> {
        list.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    #[test]
    fn a_correctly_signed_delivery_verifies() {
        let header = sign_for_test(&[b"s1"], NOW, BODY);
        assert_eq!(verify(&secrets(&["s1"]), &header, BODY, NOW), Ok(()));
    }

    #[test]
    fn a_wrong_secret_is_refused() {
        let header = sign_for_test(&[b"s1"], NOW, BODY);
        assert_eq!(
            verify(&secrets(&["other"]), &header, BODY, NOW),
            Err(SignatureError::Mismatch)
        );
    }

    #[test]
    fn a_tampered_body_is_refused() {
        let header = sign_for_test(&[b"s1"], NOW, BODY);
        assert_eq!(
            verify(&secrets(&["s1"]), &header, b"{\"event_id\":\"evt_2\"}", NOW),
            Err(SignatureError::Mismatch)
        );
    }

    #[test]
    fn a_re_serialised_body_is_refused() {
        // The signature covers the exact bytes: same JSON value, different
        // whitespace, must not verify.
        let header = sign_for_test(&[b"s1"], NOW, br#"{"a":1}"#);
        assert_eq!(
            verify(&secrets(&["s1"]), &header, br#"{ "a": 1 }"#, NOW),
            Err(SignatureError::Mismatch)
        );
    }

    #[test]
    fn a_rewritten_timestamp_is_refused_because_t_is_signed() {
        let header = sign_for_test(&[b"s1"], NOW - 10, BODY);
        let forged = header.replacen(&format!("t={}", NOW - 10), &format!("t={NOW}"), 1);
        assert_eq!(
            verify(&secrets(&["s1"]), &forged, BODY, NOW),
            Err(SignatureError::Mismatch)
        );
    }

    #[test]
    fn any_v1_against_any_secret_is_enough_for_rotation() {
        // Sent with the new secret's signature only, and with both.
        let only_new = sign_for_test(&[b"new"], NOW, BODY);
        let both = sign_for_test(&[b"old", b"new"], NOW, BODY);
        let held = secrets(&["old", "new"]);
        assert_eq!(verify(&held, &only_new, BODY, NOW), Ok(()));
        assert_eq!(verify(&held, &both, BODY, NOW), Ok(()));
        // Held only the old one, but the header still carries its v1.
        assert_eq!(verify(&secrets(&["old"]), &both, BODY, NOW), Ok(()));
        // Held neither.
        assert_eq!(
            verify(&secrets(&["unrelated"]), &both, BODY, NOW),
            Err(SignatureError::Mismatch)
        );
    }

    #[test]
    fn the_five_minute_window_is_enforced_in_both_directions() {
        for skew in [MAX_CLOCK_SKEW_SECS, -MAX_CLOCK_SKEW_SECS] {
            let header = sign_for_test(&[b"s1"], NOW + skew, BODY);
            assert_eq!(verify(&secrets(&["s1"]), &header, BODY, NOW), Ok(()), "edge {skew}");
        }
        for skew in [MAX_CLOCK_SKEW_SECS + 1, -(MAX_CLOCK_SKEW_SECS + 1)] {
            let header = sign_for_test(&[b"s1"], NOW + skew, BODY);
            assert_eq!(
                verify(&secrets(&["s1"]), &header, BODY, NOW),
                Err(SignatureError::OutsideWindow),
                "just outside {skew}"
            );
        }
    }

    #[test]
    fn replay_of_an_old_delivery_is_refused_by_the_window() {
        let captured = sign_for_test(&[b"s1"], NOW, BODY);
        assert_eq!(verify(&secrets(&["s1"]), &captured, BODY, NOW + 3600), Err(SignatureError::OutsideWindow));
    }

    #[test]
    fn no_secrets_fails_closed() {
        let header = sign_for_test(&[b"s1"], NOW, BODY);
        assert_eq!(verify(&[], &header, BODY, NOW), Err(SignatureError::NoSecrets));
    }

    #[test]
    fn malformed_headers_are_refused() {
        let held = secrets(&["s1"]);
        for header in [
            "",
            "garbage",
            "t=1800000000",
            "v1=00",
            "t=abc,v1=00",
            "t=-5,v1=00",
            "t=1800000000,v1=zz",
            "t=1800000000,v1=abcd",
            "t=1800000000,t=1800000000,v1=00",
            "t=99999999999999999999,v1=00",
        ] {
            assert_eq!(
                verify(&held, header, BODY, NOW),
                Err(SignatureError::Malformed),
                "header {header:?}"
            );
        }
    }

    #[test]
    fn too_many_signature_values_are_refused() {
        let mut header = format!("t={NOW}");
        for _ in 0..(MAX_SIGNATURE_VALUES + 1) {
            header.push_str(&format!(",v1={}", "00".repeat(SIGNATURE_LEN)));
        }
        assert_eq!(
            verify(&secrets(&["s1"]), &header, BODY, NOW),
            Err(SignatureError::Malformed)
        );
    }

    #[test]
    fn an_unknown_scheme_is_ignored_but_v1_still_decides() {
        let header = format!("{},v2=deadbeef", sign_for_test(&[b"s1"], NOW, BODY));
        assert_eq!(verify(&secrets(&["s1"]), &header, BODY, NOW), Ok(()));
    }
}

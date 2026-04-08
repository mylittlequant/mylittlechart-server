//! Token validation and generation utilities.

use axum::http::HeaderMap;
use sha2::{Digest, Sha256};
use rand::Rng;

/// Hash a raw token with SHA-256, returning the lowercase hex string.
pub fn hash_token(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate a new random token: 32 random bytes → hex-encoded (64 chars).
/// The raw value is returned to the client; only the hash is stored.
pub fn generate_token() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(bytes)
}

/// Extract a Bearer token value from an Authorization header string.
/// Returns `None` if the header is missing or malformed.
pub fn extract_bearer(header: Option<&str>) -> Option<&str> {
    let h = header?;
    let stripped = h.strip_prefix("Bearer ")?;
    if stripped.is_empty() {
        None
    } else {
        Some(stripped)
    }
}

/// Resolve a raw token to a user_id via the database.
/// Performs a synchronous SQLite lookup — intended for use inside `spawn_blocking`.
#[allow(dead_code)]
pub fn resolve_user(
    conn: &rusqlite::Connection,
    raw_token: &str,
) -> Option<i64> {
    let hash = hash_token(raw_token);
    crate::db::resolve_token_hash(conn, &hash).ok().flatten()
}

/// Hash the User-Agent string for session fingerprinting.
/// Uses the first 8 bytes (16 hex chars) of SHA-256 — enough to detect UA changes,
/// not enough to reverse the original string.
pub fn hash_user_agent(ua: &str) -> String {
    let hash = Sha256::digest(ua.as_bytes());
    hex::encode(&hash[..8])
}

/// Extract the User-Agent from request headers and return its fingerprint hash.
/// If the header is absent or non-UTF-8, returns the hash of an empty string.
pub fn extract_ua_hash(headers: &HeaderMap) -> String {
    let ua = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    hash_user_agent(ua)
}

/// Extract the `session_id` value from the `Cookie` request header.
/// Returns `None` if the Cookie header is absent or `session_id` is not present.
pub fn extract_session_id(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix("session_id=") {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
}

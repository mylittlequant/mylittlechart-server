//! Server-side build attestation verification.
//!
//! Every official release of the client binary is signed at CI build time by the
//! `RELEASE_SIGNING_KEY` (an Ed25519 private key stored in GitHub Secrets). The
//! signature covers a canonical message:
//!
//! ```text
//! BUILD_ATTESTATION_V1:{version}:{build_timestamp_unix}:{platform}
//! ```
//!
//! The client sends four HTTP headers with every protected request:
//!
//! - `X-Build-Attestation` — base64-encoded 64-byte Ed25519 signature
//! - `X-Build-Version` — e.g. "0.2.8"
//! - `X-Build-Platform` — e.g. "win64"
//! - `X-Build-Timestamp` — Unix seconds baked in at build time
//!
//! The server verifies the signature against `build_attest_pubkeys` from [`AppState`].
//! Behaviour when a signature is absent or invalid is controlled by
//! `build_attest_enforce` — during the grace/rollout period enforcement is off and
//! unsigned clients are only logged, not rejected.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, VerifyingKey};

// ============================================================================
// Types
// ============================================================================

/// Parsed attestation claim extracted from request headers.
#[derive(Debug)]
pub struct BuildAttestClaim {
    /// Semver version string embedded at build time (e.g. "0.2.8").
    pub version: String,
    /// Target platform string embedded at build time (e.g. "win64").
    pub platform: String,
    /// Unix timestamp (seconds) at which the binary was signed.
    pub timestamp: u64,
    /// Base64-encoded Ed25519 signature.
    pub signature_b64: String,
}

/// Reasons why an attestation claim failed verification.
#[derive(Debug)]
#[allow(dead_code)] // payload strings are observed via Debug in tracing::warn!
pub enum AttestError {
    /// Signature does not verify against any known public key.
    InvalidSignature(String),
    /// Build timestamp is older than `max_age_secs`.
    Expired,
    /// Build timestamp is more than 5 minutes in the future (clock skew / tampering).
    FutureTimestamp,
    /// A header value was present but could not be parsed.
    MalformedHeader(String),
}

// ============================================================================
// Claim extraction
// ============================================================================

/// Extract an [`BuildAttestClaim`] from request headers.
///
/// Returns `None` when the `X-Build-Attestation` header is absent or empty —
/// this represents an unsigned (dev / standalone) build.
pub fn extract_claim(headers: &HeaderMap) -> Option<BuildAttestClaim> {
    let attestation = headers.get("X-Build-Attestation")?.to_str().ok()?;
    if attestation.is_empty() {
        return None;
    }

    let version = headers
        .get("X-Build-Version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let platform = headers
        .get("X-Build-Platform")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let timestamp = headers
        .get("X-Build-Timestamp")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);

    Some(BuildAttestClaim {
        version,
        platform,
        timestamp,
        signature_b64: attestation.to_string(),
    })
}

// ============================================================================
// Claim verification
// ============================================================================

/// Verify an [`BuildAttestClaim`] against a set of known public keys.
///
/// # Arguments
///
/// - `claim` — the parsed claim to verify.
/// - `pubkeys` — slice of raw 32-byte Ed25519 public keys. Empty slice means
///   all signed clients pass (no verification configured).
/// - `max_age_secs` — maximum allowed age of the build timestamp in seconds.
///
/// Returns `Ok(())` on success or an [`AttestError`] describing the failure.
pub fn verify_claim(
    claim: &BuildAttestClaim,
    pubkeys: &[[u8; 32]],
    max_age_secs: u64,
) -> Result<(), AttestError> {
    // If no public keys are configured, skip verification entirely.
    if pubkeys.is_empty() {
        return Ok(());
    }

    // --- Timestamp checks ---
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Allow up to 5-minute clock skew in either direction for future timestamps.
    if claim.timestamp > now + 300 {
        return Err(AttestError::FutureTimestamp);
    }

    if now.saturating_sub(claim.timestamp) > max_age_secs {
        return Err(AttestError::Expired);
    }

    // --- Reconstruct canonical message ---
    let message = format!(
        "BUILD_ATTESTATION_V1:{}:{}:{}",
        claim.version, claim.timestamp, claim.platform
    );

    // --- Decode signature ---
    let sig_bytes = STANDARD
        .decode(&claim.signature_b64)
        .map_err(|e| AttestError::MalformedHeader(format!("bad base64 in signature: {}", e)))?;

    if sig_bytes.len() != 64 {
        return Err(AttestError::MalformedHeader(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        )));
    }

    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .expect("length already checked to be 64");
    let signature = Signature::from_bytes(&sig_array);

    // --- Try each public key ---
    for pubkey_bytes in pubkeys {
        match VerifyingKey::from_bytes(pubkey_bytes) {
            Ok(verifying_key) => {
                if verifying_key
                    .verify_strict(message.as_bytes(), &signature)
                    .is_ok()
                {
                    return Ok(());
                }
            }
            Err(_) => {
                // Skip malformed pubkey entries — log once during startup, not per-request.
                continue;
            }
        }
    }

    Err(AttestError::InvalidSignature(
        "no matching public key found".to_string(),
    ))
}

// ============================================================================
// Handler integration helper
// ============================================================================

/// Check build attestation on an incoming request.
///
/// Call this at the very top of any protected handler, before user auth:
///
/// ```ignore
/// if let Err(resp) = build_attest::check_build_attestation(
///     &headers,
///     &state.build_attest_pubkeys,
///     state.build_attest_enforce,
///     state.build_attest_max_age_secs,
/// ) {
///     return resp;
/// }
/// ```
///
/// Returns `Ok(())` when the request is allowed to proceed, or `Err(Response)` with
/// a `403 Forbidden` body that the handler can immediately return.
pub fn check_build_attestation(
    headers: &HeaderMap,
    pubkeys: &[[u8; 32]],
    enforce: bool,
    max_age_secs: u64,
) -> Result<(), Response> {
    match extract_claim(headers) {
        None => {
            // No attestation header — this is an unsigned (dev / standalone) build.
            if enforce {
                tracing::warn!("Build attestation: rejected unsigned client (enforce=true)");
                Err((
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": "invalid_client",
                        "detail": "build attestation required"
                    })),
                )
                    .into_response())
            } else {
                tracing::debug!(
                    "Build attestation: allowing unsigned client (grace period)"
                );
                Ok(())
            }
        }

        Some(claim) => match verify_claim(&claim, pubkeys, max_age_secs) {
            Ok(()) => {
                tracing::debug!(
                    "Build attestation: valid for v{} ({})",
                    claim.version,
                    claim.platform
                );
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    "Build attestation: rejected — {:?} (v={}, platform={})",
                    e,
                    claim.version,
                    claim.platform
                );
                Err((
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": "invalid_client",
                        "detail": "build attestation failed"
                    })),
                )
                    .into_response())
            }
        },
    }
}

// ============================================================================
// Env-var parsing helpers (called from main.rs)
// ============================================================================

/// Parse `BUILD_ATTEST_PUBKEY` environment variable.
///
/// The value may be a single hex-encoded 32-byte key, or multiple keys separated
/// by commas. Invalid entries are logged and skipped.
///
/// Returns an empty `Vec` when the variable is unset or empty.
pub fn parse_pubkeys_from_env() -> Vec<[u8; 32]> {
    let raw = match std::env::var("BUILD_ATTEST_PUBKEY") {
        Ok(v) if !v.is_empty() => v,
        _ => return Vec::new(),
    };

    let mut keys = Vec::new();
    for (i, entry) in raw.split(',').enumerate() {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        match hex::decode(trimmed) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                // Validate the key is a well-formed Ed25519 verifying key before storing.
                match VerifyingKey::from_bytes(&arr) {
                    Ok(_) => {
                        tracing::info!(
                            "Build attestation: loaded public key #{} ({}...)",
                            i + 1,
                            &trimmed[..8]
                        );
                        keys.push(arr);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Build attestation: public key #{} is not a valid Ed25519 key: {}",
                            i + 1,
                            e
                        );
                    }
                }
            }
            Ok(bytes) => {
                tracing::warn!(
                    "Build attestation: public key #{} has wrong length (expected 32 bytes, got {})",
                    i + 1,
                    bytes.len()
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Build attestation: public key #{} is not valid hex: {}",
                    i + 1,
                    e
                );
            }
        }
    }

    if keys.is_empty() && !raw.is_empty() {
        tracing::warn!(
            "BUILD_ATTEST_PUBKEY was set but no valid keys could be parsed — \
             attestation verification is disabled (no keys = all clients allowed)"
        );
    }

    keys
}

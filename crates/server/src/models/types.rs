//! All request and response types used by the server API.

use serde::{Deserialize, Serialize};

// ============================================================================
// Heartbeat
// ============================================================================

/// Request body for POST /api/heartbeat
#[derive(Debug, Deserialize)]
pub struct HeartbeatRequest {
    pub device_id: String,
    pub app_version: String,
    /// Uptime in seconds — stored for informational purposes.
    #[allow(dead_code)]
    pub uptime_seconds: u64,
    pub os: String,
    #[serde(default)]
    pub device_name: String,
}

/// Response for POST /api/heartbeat
#[derive(Debug, Serialize)]
pub struct HeartbeatResponse {
    pub status: &'static str,
}

// ============================================================================
// Updates / Version manifest
// ============================================================================

fn default_stable_channel() -> String {
    "stable".to_string()
}

/// Query params for GET /api/updates/latest
#[derive(Debug, Deserialize)]
pub struct LatestQuery {
    pub platform: String,
    /// Release channel to query. Defaults to "stable" (backward compatible — existing clients omit this).
    #[serde(default = "default_stable_channel")]
    pub channel: String,
}

/// Response for GET /api/updates/latest — matches VersionManifest in updater client.
#[derive(Debug, Serialize)]
pub struct VersionManifest {
    pub version: String,
    pub sha256: String,
    pub download_url: String,
    pub release_notes: String,
    pub file_size: u64,
    /// Base64-encoded Ed25519 signature over the binary bytes.
    /// Empty string for unsigned releases (backward compatible — old clients ignore unknown fields).
    pub signature: String,
    /// Release channel this manifest was fetched from ("stable" or "dev").
    /// Old clients ignore unknown fields — fully backward compatible.
    pub channel: String,
}

/// Path params for GET /api/updates/download/:platform/:version
#[derive(Debug, Deserialize)]
pub struct DownloadPath {
    pub platform: String,
    pub version: String,
}

/// Query params for GET /api/updates/download/:platform/:version?channel=dev
#[derive(Debug, Deserialize)]
pub struct DownloadQuery {
    #[serde(default = "default_stable_channel")]
    pub channel: String,
}

// ============================================================================
// Telemetry
// ============================================================================

/// Request body for POST /api/telemetry — fixed schema, matches updater client.
#[derive(Debug, Deserialize)]
pub struct TelemetryRequest {
    /// Persistent random UUID generated and saved by the client on first launch.
    pub device_id: Option<String>,
    pub app_version: String,
    pub os: String,
    pub arch: String,
    pub gpu_name: String,
    pub screen_width: u32,
    pub screen_height: u32,
    pub connector_count: u32,
    pub window_count: u32,
    pub avg_fps: f32,
    pub uptime_secs: u64,
    pub total_bars: u64,
    pub ws_connections: u32,
}

/// Response for POST /api/telemetry
#[derive(Debug, Serialize)]
pub struct TelemetryResponse {
    pub status: &'static str,
}

// ============================================================================
// Admin upload
// ============================================================================

fn default_dev_channel() -> String {
    "dev".to_string()
}

/// Query params for POST /api/admin/upload
#[derive(Debug, Deserialize)]
pub struct UploadQuery {
    pub platform: String,
    pub version: String,
    #[serde(default)]
    pub release_notes: String,
    /// Base64-encoded Ed25519 signature over the binary bytes. Optional — empty string if not provided.
    #[serde(default)]
    pub signature: String,
    /// Release channel: "stable" or "dev". Defaults to "dev" so local builds don't go to stable.
    #[serde(default = "default_dev_channel")]
    pub channel: String,
}

/// Response for POST /api/admin/upload
#[derive(Debug, Serialize)]
pub struct UploadResponse {
    pub status: &'static str,
    pub sha256: String,
    pub file_size: u64,
    pub platform: String,
    pub version: String,
    /// Echoed back from the upload query — allows CI to confirm the server stored the exact signature.
    pub signature: String,
    /// Echoed back — confirms which channel the binary was stored under.
    pub channel: String,
}

// ============================================================================
// Admin promote
// ============================================================================

/// Query params for POST /api/admin/promote
#[derive(Debug, Deserialize)]
pub struct PromoteQuery {
    pub version: String,
    pub platform: String,
}

/// Response for POST /api/admin/promote
#[derive(Debug, Serialize)]
pub struct PromoteResponse {
    pub status: &'static str,
    pub version: String,
    pub platform: String,
}

// ============================================================================
// OAuth
// ============================================================================

/// Query params for GET /api/oauth/:provider/authorize
#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    /// Port of the local desktop callback server.
    /// If 0 or absent, this is a web OAuth flow (no desktop redirect).
    #[serde(default)]
    pub redirect_port: Option<u16>,
    /// Optional device identifier for device-user linking.
    #[serde(default)]
    pub device_id: Option<String>,
    /// If present (any value like `1`, `true`, etc.), this is a "link provider" flow —
    /// the session's `user_id` will be stored in the oauth_state so the callback merges
    /// this provider into the existing account.
    #[serde(default, deserialize_with = "deserialize_link_flag")]
    pub link: bool,
    /// Optional device code from the wasm/desktop sign-in modal. When present,
    /// the web-callback confirms this device code after a successful login, so
    /// the device poll completes without manual code entry.
    #[serde(default)]
    pub device_code: Option<String>,
}

/// Deserializes a query string flag that can be `"1"`, `"true"`, `"yes"`, or absent.
pub fn deserialize_link_flag<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    let opt: Option<String> = Option::deserialize(deserializer)?;
    Ok(match opt.as_deref() {
        Some("1") | Some("true") | Some("yes") => true,
        _ => false,
    })
}

/// Request body for POST /api/oauth/:provider/callback
#[derive(Debug, Deserialize)]
pub struct OAuthCallbackRequest {
    pub code: String,
    pub redirect_port: u16,
    /// OAuth state parameter for CSRF validation / PKCE code verifier.
    #[serde(default)]
    pub state: Option<String>,
    /// Optional device identifier — flows through from the authorize step.
    #[serde(default)]
    pub device_id: Option<String>,
}

/// Response for POST /api/oauth/:provider/callback
#[derive(Debug, Serialize)]
pub struct OAuthCallbackResponse {
    pub token: String,
    pub display_name: String,
    pub user_id: i64,
    /// Non-sequential public identifier — safe to expose in APIs.
    pub public_id: String,
}

/// Request body for POST /api/oauth/telegram/callback
#[derive(Debug, Deserialize)]
pub struct TelegramCallbackRequest {
    pub id: String,
    pub first_name: String,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub username: String,
    pub auth_date: u64,
    pub hash: String,
    /// Optional device identifier for device-user linking.
    #[serde(default)]
    pub device_id: Option<String>,
}

// ============================================================================
// Device authorization flow
// ============================================================================

/// Request body for POST /api/auth/device-code
#[derive(Debug, Deserialize)]
pub struct DeviceCodeRequest {
    pub device_id: String,
}

/// Response for POST /api/auth/device-code
#[derive(Debug, Serialize)]
pub struct DeviceCodeResponse {
    pub code: String,
    pub expires_in: u64,
}

/// Query params for GET /api/auth/poll?code=AB12CD34
#[derive(Debug, Deserialize)]
pub struct PollQuery {
    pub code: String,
}

/// Request body for POST /api/auth/confirm
#[derive(Debug, Deserialize)]
pub struct ConfirmRequest {
    pub code: String,
}

/// A single linked OAuth provider in a user's profile.
#[derive(Debug, Serialize)]
pub struct ProviderInfo {
    pub provider: String,
    pub display_name: String,
}

/// Response for GET /api/auth/me
#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub user_id: i64,
    /// Non-sequential public identifier — safe to expose in APIs.
    pub public_id: String,
    pub display_name: String,
    /// Primary provider (kept for backwards compatibility).
    pub provider: String,
    /// All providers linked to this account.
    pub providers: Vec<ProviderInfo>,
}

// ============================================================================
// Generic error
// ============================================================================

/// Generic JSON error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl ErrorResponse {
    pub fn new(msg: impl Into<String>) -> Self {
        Self { error: msg.into() }
    }
}

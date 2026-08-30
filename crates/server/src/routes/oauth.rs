//! OAuth authentication flows for GitHub, Discord, Google, Twitter/X, and Telegram.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::auth::{extract_session_id, extract_ua_hash, generate_token, hash_token};
use crate::models::types::{
    AuthorizeQuery, ErrorResponse, OAuthCallbackRequest, OAuthCallbackResponse,
    TelegramCallbackRequest,
};
use crate::state::AppState;

/// The base URL for web OAuth callbacks (provider redirects here for browser-based logins).
const WEB_CALLBACK_BASE: &str = "https://mylittlechart.org/api/oauth";

// ============================================================================
// Authorize redirect
// ============================================================================

/// GET /api/oauth/:provider/authorize?redirect_port=17421
///
/// Redirects the browser to the provider's OAuth authorization page.
/// Stores a CSRF state token in the database for later validation.
///
/// When `redirect_port` is 0 or absent, this is a **web OAuth login**: the provider
/// will redirect back to `WEB_CALLBACK_BASE/{provider}/web-callback` and the server
/// will set a session cookie and redirect to `/dashboard`.
pub async fn authorize(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Query(query): Query<AuthorizeQuery>,
) -> Response {
    let redirect_port = query.redirect_port.unwrap_or(0);
    let is_web_flow = redirect_port == 0;

    let redirect_uri = if is_web_flow {
        format!("{}/{}/web-callback", WEB_CALLBACK_BASE, provider)
    } else {
        format!("http://127.0.0.1:{}/callback", redirect_port)
    };

    // Generate CSRF state.
    let state_param: String = {
        use rand::Rng;
        let bytes: [u8; 16] = rand::thread_rng().gen();
        hex::encode(bytes)
    };

    // Determine link_user_id for the "link provider" flow.
    // Only applicable for web flows where the user is already logged in.
    let link_user_id: Option<i64> = if query.link && is_web_flow {
        let session_id = extract_session_id(&headers);
        if let Some(sid) = session_id {
            let ua_hash = extract_ua_hash(&headers);
            let state_clone = state.clone();
            tokio::task::spawn_blocking(move || {
                let conn = state_clone.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
                crate::db::resolve_web_session(&conn, &sid, &ua_hash)
            })
            .await
            .ok()
            .and_then(|r| r.ok())
            .flatten()
        } else {
            None
        }
    } else {
        None
    };

    // Store state in DB for validation on callback.
    let device_id = query.device_id.clone().unwrap_or_default();
    // Device code from the sign-in modal (normalized; empty = absent).
    let device_code = query
        .device_code
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(|c| c.to_uppercase());
    {
        let now = chrono::Utc::now().to_rfc3339();
        let state_clone = state.clone();
        let state_param_clone = state_param.clone();
        let provider_clone = provider.clone();
        let device_id_clone = device_id.clone();
        let device_code_clone = device_code.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || {
            let conn = state_clone.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            let _ = crate::db::cleanup_oauth_states(&conn);
            crate::db::insert_oauth_state(&conn, &state_param_clone, &provider_clone, redirect_port, &now, &device_id_clone, link_user_id, device_code_clone.as_deref())
        })
        .await
        {
            tracing::error!("Failed to store OAuth state: {:?}", e);
        }
    }

    let auth_url = match provider.as_str() {
        "github" => {
            format!(
                "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}&scope=read:user",
                urlencoding_simple(&state.github_client_id),
                urlencoding_simple(&redirect_uri),
                state_param,
            )
        }
        "discord" => {
            format!(
                "https://discord.com/api/oauth2/authorize?client_id={}&redirect_uri={}&response_type=code&scope=identify&state={}",
                urlencoding_simple(&state.discord_client_id),
                urlencoding_simple(&redirect_uri),
                state_param,
            )
        }
        "google" => {
            format!(
                "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20profile&state={}&access_type=offline&prompt=consent",
                urlencoding_simple(&state.google_client_id),
                urlencoding_simple(&redirect_uri),
                state_param,
            )
        }
        "twitter" => {
            // Twitter OAuth 2.0 with PKCE (S256 method).
            // We reuse the state param as the code_verifier for simplicity.
            let code_verifier = &state_param;
            let code_challenge = {
                let mut hasher = Sha256::new();
                hasher.update(code_verifier.as_bytes());
                base64_url_encode(&hasher.finalize())
            };
            format!(
                "https://twitter.com/i/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&scope=users.read%20tweet.read&state={}&code_challenge={}&code_challenge_method=S256",
                urlencoding_simple(&state.twitter_client_id),
                urlencoding_simple(&redirect_uri),
                state_param,
                code_challenge,
            )
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(
                    "Unknown provider. Supported: github, discord, google, twitter.",
                )),
            )
                .into_response();
        }
    };

    Redirect::temporary(&auth_url).into_response()}

// ============================================================================
// Web OAuth callback (GET — provider redirects browser here)
// ============================================================================

/// Query params sent by providers on GET web-callback redirect.
#[derive(serde::Deserialize)]
pub struct WebCallbackQuery {
    pub code: String,
    pub state: Option<String>,
}

/// GET /api/oauth/{provider}/web-callback?code=X&state=Y
///
/// Provider redirects the browser here after the user approves access.
/// The server exchanges the code, upserts the user, creates a web session,
/// sets a `session_id` cookie, and redirects the browser to `/dashboard`.
pub async fn web_callback(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Query(query): Query<WebCallbackQuery>,
) -> Response {
    // Build the redirect_uri that was registered with the provider.
    let redirect_uri = format!("{}/{}/web-callback", WEB_CALLBACK_BASE, provider);

    // --- CSRF validation ---
    let state_param = query.state.clone();
    // link_user_id is populated when the state was stored as part of a "link provider" flow.
    let mut link_user_id: Option<i64> = None;
    let mut device_code: Option<String> = None;
    if provider.as_str() != "twitter" {
        if let Some(ref sp) = state_param {
            let state_clone = state.clone();
            let sp_clone = sp.clone();
            let consumed = tokio::task::spawn_blocking(move || {
                let conn = state_clone.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
                crate::db::consume_oauth_state(&conn, &sp_clone)
            })
            .await;

            match consumed {
                Ok(Ok(Some((_prov, _port, _dev, luid, dcode)))) => {
                    link_user_id = luid;
                    device_code = dcode;
                }
                Ok(Ok(None)) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse::new("Invalid or expired OAuth state (CSRF check failed)")),
                    )
                        .into_response();
                }
                Ok(Err(e)) => {
                    tracing::error!("DB error consuming OAuth state: {}", e);
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Database error"))).into_response();
                }
                Err(_) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Internal error"))).into_response();
                }
            }
        }
    }

    // --- Exchange code for provider identity ---
    let (provider_name, provider_user_id, display_name) =
        match exchange_code_for_identity(&state, &provider, &query.code, &redirect_uri, state_param.as_deref()).await {
            Ok(t) => t,
            Err(resp) => return resp,
        };

    // --- Upsert/link user and create web session ---
    let now = chrono::Utc::now().to_rfc3339();
    let session_expires_at = (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339();
    let display_name_log = display_name.clone();
    let ua_hash = extract_ua_hash(&headers);
    // `state` moves into the session-creation closure below; the device-code
    // confirm in the success arm needs its own handle.
    let state_for_device = state.clone();

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<(i64, String)> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());

        let user_id = if let Some(existing_uid) = link_user_id {
            // Link flow: add this provider to the existing account.
            crate::db::link_provider_to_user(
                &conn, existing_uid, &provider_name, &provider_user_id, &display_name, &now,
            )?;
            existing_uid
        } else {
            // Normal login flow: upsert user and ensure user_providers is populated.
            let uid = crate::db::upsert_user(&conn, &provider_name, &provider_user_id, &display_name, &now)?;
            crate::db::link_provider_to_user(&conn, uid, &provider_name, &provider_user_id, &display_name, &now)?;
            uid
        };

        let session_id = crate::db::create_web_session(&conn, user_id, &now, &session_expires_at, &ua_hash)?;
        Ok((user_id, session_id))
    })
    .await;

    match result {
        Ok(Ok((user_id, session_id))) => {
            tracing::info!("Web OAuth login: provider={} display_name={} user_id={}", provider, display_name_log, user_id);
            let cookie = format!(
                "session_id={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400",
                session_id
            );

            // Sign-in modal flow: confirm the pending device code so the
            // device's /api/auth/poll completes on its own.
            if let Some(code) = device_code {
                let state_clone = state_for_device.clone();
                let code_clone = code.clone();
                let confirmed = tokio::task::spawn_blocking(move || {
                    let conn = state_clone.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
                    let now = chrono::Utc::now().to_rfc3339();
                    match crate::db::get_device_code(&conn, &code_clone) {
                        Ok(Some(row)) if row.expires_at >= now && row.status == "pending" => {
                            crate::db::confirm_device_code(&conn, &code_clone, user_id).unwrap_or(false)
                        }
                        _ => false,
                    }
                })
                .await
                .unwrap_or(false);
                if confirmed {
                    tracing::info!("Device code confirmed via OAuth web-callback: user_id={}", user_id);
                } else {
                    tracing::warn!("Device code {} not confirmed (expired/used/missing)", code);
                }
                let note = if confirmed {
                    "This device is now signed in."
                } else {
                    "Signed in, but the device code was expired or already used — request a new one in the app."
                };
                let html = format!(
                    concat!(
                        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>mylittlechart</title></head>",
                        "<body style=\"background:#0a0f1a;color:#feffee;font-family:sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;text-align:center\">",
                        "<div><h2 style=\"color:#f4cd63\">Signed in</h2><p>{}</p>",
                        "<p style=\"opacity:0.6\">You can close this tab.</p></div></body></html>"
                    ),
                    note
                );
                return (
                    StatusCode::OK,
                    [(header::SET_COOKIE, cookie.as_str()), (header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    html,
                )
                    .into_response();
            }

            (
                StatusCode::FOUND,
                [
                    (header::SET_COOKIE, cookie.as_str()),
                    (header::LOCATION, "https://mylittlechart.org/dashboard"),
                ],
                "",
            )
                .into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("DB error in web_callback: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Database error"))).into_response()
        }
        Err(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Internal error"))).into_response()
        }
    }
}

/// Exchange an OAuth authorization code for (provider_name, provider_user_id, display_name).
async fn exchange_code_for_identity(
    state: &Arc<AppState>,
    provider: &str,
    code: &str,
    redirect_uri: &str,
    state_param: Option<&str>,
) -> Result<(String, String, String), Response> {
    let http = build_http_client().map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new(e))).into_response()
    })?;

    match provider {
        "github" => {
            #[derive(serde::Deserialize)]
            struct GithubTokenResponse {
                access_token: Option<String>,
                error: Option<String>,
                error_description: Option<String>,
            }
            let token_resp: GithubTokenResponse = http
                .post("https://github.com/login/oauth/access_token")
                .header("Accept", "application/json")
                .json(&serde_json::json!({
                    "client_id": state.github_client_id,
                    "client_secret": state.github_client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri,
                }))
                .send()
                .await
                .map_err(|e| {
                    tracing::error!("GitHub token exchange failed: {}", e);
                    (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("GitHub token exchange failed"))).into_response()
                })?
                .json()
                .await
                .map_err(|_| (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("Failed to parse GitHub token response"))).into_response())?;

            if let Some(err) = token_resp.error {
                let desc = token_resp.error_description.unwrap_or_default();
                return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse::new(format!("GitHub OAuth error: {} — {}", err, desc)))).into_response());
            }
            let access_token = token_resp.access_token.ok_or_else(|| {
                (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("No access_token in GitHub response"))).into_response()
            })?;

            #[derive(serde::Deserialize)]
            struct GithubUser { id: u64, login: String, name: Option<String> }
            let user: GithubUser = fetch_json(&http, "https://api.github.com/user", &access_token, Some("mylittlechart-server/0.1"))
                .await
                .map_err(|e| e)?;

            let display_name = user.name.unwrap_or(user.login);
            Ok(("github".to_string(), user.id.to_string(), display_name))
        }
        "discord" => {
            #[derive(serde::Deserialize)]
            struct DiscordTokenResponse { access_token: Option<String>, error: Option<String> }
            let token_resp: DiscordTokenResponse = http
                .post("https://discord.com/api/v10/oauth2/token")
                .form(&[
                    ("client_id", state.discord_client_id.as_str()),
                    ("client_secret", state.discord_client_secret.as_str()),
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("redirect_uri", redirect_uri),
                ])
                .send()
                .await
                .map_err(|e| {
                    tracing::error!("Discord token exchange failed: {}", e);
                    (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("Discord token exchange failed"))).into_response()
                })?
                .json()
                .await
                .map_err(|_| (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("Failed to parse Discord token response"))).into_response())?;

            if let Some(err) = token_resp.error {
                return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse::new(format!("Discord OAuth error: {}", err)))).into_response());
            }
            let access_token = token_resp.access_token.ok_or_else(|| {
                (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("No access_token in Discord response"))).into_response()
            })?;

            #[derive(serde::Deserialize)]
            struct DiscordUser { id: String, username: String, global_name: Option<String> }
            let user: DiscordUser = fetch_json(&http, "https://discord.com/api/v10/users/@me", &access_token, None)
                .await
                .map_err(|e| e)?;

            let display_name = user.global_name.unwrap_or(user.username);
            Ok(("discord".to_string(), user.id, display_name))
        }
        "google" => {
            #[derive(serde::Deserialize)]
            struct GoogleTokenResponse {
                access_token: Option<String>,
                error: Option<String>,
                error_description: Option<String>,
            }
            let token_resp: GoogleTokenResponse = http
                .post("https://oauth2.googleapis.com/token")
                .form(&[
                    ("client_id", state.google_client_id.as_str()),
                    ("client_secret", state.google_client_secret.as_str()),
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("redirect_uri", redirect_uri),
                ])
                .send()
                .await
                .map_err(|e| {
                    tracing::error!("Google token exchange failed: {}", e);
                    (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("Google token exchange failed"))).into_response()
                })?
                .json()
                .await
                .map_err(|_| (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("Failed to parse Google token response"))).into_response())?;

            if let Some(err) = token_resp.error {
                let desc = token_resp.error_description.unwrap_or_default();
                return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse::new(format!("Google OAuth error: {} — {}", err, desc)))).into_response());
            }
            let access_token = token_resp.access_token.ok_or_else(|| {
                (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("No access_token in Google response"))).into_response()
            })?;

            #[derive(serde::Deserialize)]
            struct GoogleUser { sub: String, name: Option<String>, email: Option<String> }
            let user: GoogleUser = fetch_json(&http, "https://www.googleapis.com/oauth2/v3/userinfo", &access_token, None)
                .await
                .map_err(|e| e)?;

            let display_name = user.name.or(user.email)
                .unwrap_or_else(|| format!("google:{}", &user.sub[..8.min(user.sub.len())]));
            Ok(("google".to_string(), user.sub, display_name))
        }
        "twitter" => {
            let code_verifier = match state_param {
                Some(s) => s.to_owned(),
                None => return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse::new("Missing state for Twitter PKCE"))).into_response()),
            };

            #[derive(serde::Deserialize)]
            struct TwitterTokenResponse {
                access_token: Option<String>,
                error: Option<String>,
                error_description: Option<String>,
            }
            let token_resp: TwitterTokenResponse = http
                .post("https://api.twitter.com/2/oauth2/token")
                .basic_auth(&state.twitter_client_id, Some(&state.twitter_client_secret))
                .form(&[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("redirect_uri", redirect_uri),
                    ("code_verifier", &code_verifier),
                ])
                .send()
                .await
                .map_err(|e| {
                    tracing::error!("Twitter token exchange failed: {}", e);
                    (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("Twitter token exchange failed"))).into_response()
                })?
                .json()
                .await
                .map_err(|_| (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("Failed to parse Twitter token response"))).into_response())?;

            if let Some(err) = token_resp.error {
                let desc = token_resp.error_description.unwrap_or_default();
                return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse::new(format!("Twitter OAuth error: {} — {}", err, desc)))).into_response());
            }
            let access_token = token_resp.access_token.ok_or_else(|| {
                (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("No access_token in Twitter response"))).into_response()
            })?;

            #[derive(serde::Deserialize)]
            #[allow(dead_code)]
            struct TwitterUserData { id: String, name: String, username: String }
            #[derive(serde::Deserialize)]
            struct TwitterUserResponse { data: Option<TwitterUserData> }
            let user_resp: TwitterUserResponse = fetch_json(&http, "https://api.twitter.com/2/users/me", &access_token, None)
                .await
                .map_err(|e| e)?;

            let user = user_resp.data.ok_or_else(|| {
                (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("No user data in Twitter response"))).into_response()
            })?;
            let display_name = format!("@{}", user.username);
            Ok(("twitter".to_string(), user.id, display_name))
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Unknown provider. Supported: github, discord, google, twitter.")),
        )
            .into_response()),
    }
}

// ============================================================================
// Code exchange callback
// ============================================================================

/// POST /api/oauth/:provider/callback
///
/// Exchanges the authorization code for a user token.
/// Validates the CSRF state before proceeding with the code exchange.
pub async fn callback(
    State(state): State<Arc<AppState>>,
    Path(provider): Path<String>,
    Json(mut req): Json<OAuthCallbackRequest>,
) -> Response {
    // CSRF validation: consume the state from the DB and verify it was issued by us.
    // For Twitter we skip this check here because the state doubles as the PKCE
    // code_verifier — it is validated implicitly by the token exchange.
    if provider.as_str() != "twitter" {
        if let Some(ref state_param) = req.state.clone() {
            let state_clone = state.clone();
            let state_param_clone = state_param.clone();
            let consumed = tokio::task::spawn_blocking(move || {
                let conn = state_clone.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
                crate::db::consume_oauth_state(&conn, &state_param_clone)
            })
            .await;

            match consumed {
                Ok(Ok(Some((_provider_stored, _port, device_id_stored, _link_uid, _dcode)))) => {
                    // State is valid. If the request didn't include a device_id,
                    // populate it from the stored state so it propagates to finish_oauth.
                    if req.device_id.is_none() && !device_id_stored.is_empty() {
                        req.device_id = Some(device_id_stored);
                    }
                }
                Ok(Ok(None)) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse::new("Invalid or expired OAuth state (CSRF check failed)")),
                    )
                        .into_response();
                }
                Ok(Err(e)) => {
                    tracing::error!("DB error consuming OAuth state: {}", e);
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Database error"))).into_response();
                }
                Err(_) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Internal error"))).into_response();
                }
            }
        }
    }

    match provider.as_str() {
        "github" => github_callback(state, req).await,
        "discord" => discord_callback(state, req).await,
        "google" => google_callback(state, req).await,
        "twitter" => twitter_callback(state, req).await,
        _ => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Unknown provider. Supported: github, discord, google, twitter.")),
        )
            .into_response(),
    }
}

/// JSON body sent by the `/telegram-redirect` client page after decoding `#tgAuthResult`.
#[derive(serde::Deserialize)]
pub struct TelegramWebCallbackQuery {
    pub id: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub username: Option<String>,
    #[allow(dead_code)]
    pub photo_url: Option<String>,
    pub auth_date: u64,
    pub hash: String,
    /// If `true`, this is a "link provider" flow — the session's user_id will be used
    /// to link this Telegram identity to the existing account.
    #[serde(default)]
    pub link: bool,
}

/// POST /api/oauth/telegram/web-callback
///
/// Called by the `/telegram-redirect` page after decoding `#tgAuthResult` from the
/// `oauth.telegram.org` redirect. Verifies the HMAC-SHA256 hash, checks freshness,
/// upserts the user, creates a web session cookie, and returns JSON `{ ok: true }`.
/// The client JS then redirects to `/dashboard`.
pub async fn telegram_web_callback(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(query): Json<TelegramWebCallbackQuery>,
) -> Response {
    // --- Verify Telegram hash ---
    if !verify_telegram_web_hash(&query, &state.telegram_bot_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Invalid Telegram authentication hash")),
        )
            .into_response();
    }

    // --- Check auth_date freshness (must be within 1 day) ---
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now_secs.saturating_sub(query.auth_date) > 86_400 {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Telegram auth_date is too old")),
        )
            .into_response();
    }

    // --- Determine display name: prefer @username, fall back to first_name ---
    let display_name = if let Some(ref uname) = query.username {
        if !uname.is_empty() {
            format!("@{}", uname)
        } else {
            query.first_name.clone().unwrap_or_else(|| query.id.clone())
        }
    } else {
        query.first_name.clone().unwrap_or_else(|| query.id.clone())
    };

    // --- Resolve link_user_id if this is a "link provider" flow ---
    let link_user_id: Option<i64> = if query.link {
        let session_id = extract_session_id(&headers);
        if let Some(sid) = session_id {
            let ua_hash_for_link = extract_ua_hash(&headers);
            let state_clone = state.clone();
            tokio::task::spawn_blocking(move || {
                let conn = state_clone.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
                crate::db::resolve_web_session(&conn, &sid, &ua_hash_for_link)
            })
            .await
            .ok()
            .and_then(|r| r.ok())
            .flatten()
        } else {
            None
        }
    } else {
        None
    };

    // --- Upsert/link user and create web session ---
    let now = chrono::Utc::now().to_rfc3339();
    let session_expires_at = (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339();
    let display_name_log = display_name.clone();
    let ua_hash = extract_ua_hash(&headers);
    let provider_user_id = query.id.clone();

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<(i64, String)> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());

        let user_id = if let Some(existing_uid) = link_user_id {
            // Link flow: add Telegram identity to existing account.
            crate::db::link_provider_to_user(
                &conn, existing_uid, "telegram", &provider_user_id, &display_name, &now,
            )?;
            existing_uid
        } else {
            // Normal login flow: upsert user and ensure user_providers is populated.
            let uid = crate::db::upsert_user(&conn, "telegram", &provider_user_id, &display_name, &now)?;
            crate::db::link_provider_to_user(&conn, uid, "telegram", &provider_user_id, &display_name, &now)?;
            uid
        };

        let session_id = crate::db::create_web_session(&conn, user_id, &now, &session_expires_at, &ua_hash)?;
        Ok((user_id, session_id))
    })
    .await;

    match result {
        Ok(Ok((user_id, session_id))) => {
            tracing::info!(
                "Web Telegram login: display_name={} user_id={}",
                display_name_log,
                user_id
            );
            let cookie = format!(
                "session_id={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400",
                session_id
            );
            (
                StatusCode::OK,
                [(header::SET_COOKIE, cookie)],
                Json(serde_json::json!({ "ok": true, "user_id": user_id })),
            )
                .into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("DB error in telegram_web_callback: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Database error"))).into_response()
        }
        Err(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Internal error"))).into_response()
        }
    }
}

/// POST /api/oauth/telegram/callback
///
/// Verifies the Telegram login widget data (HMAC-SHA256) and returns a token.
pub async fn telegram_callback(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TelegramCallbackRequest>,
) -> Response {
    if !verify_telegram_hash(&req, &state.telegram_bot_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Invalid Telegram authentication hash")),
        )
            .into_response();
    }

    // Check auth_date is not too stale (allow up to 1 day).
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now_secs.saturating_sub(req.auth_date) > 86_400 {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Telegram auth_date is too old")),
        )
            .into_response();
    }

    let display_name = if req.username.is_empty() {
        req.first_name.clone()
    } else {
        format!("@{}", req.username)
    };

    let device_id = req.device_id.as_deref().unwrap_or("");
    finish_oauth(state, "telegram", &req.id, &display_name, device_id).await
}

// ============================================================================
// Provider-specific code exchange
// ============================================================================

async fn github_callback(state: Arc<AppState>, req: OAuthCallbackRequest) -> Response {
    let redirect_uri = format!("http://127.0.0.1:{}/callback", req.redirect_port);

    let http = match build_http_client() {
        Ok(c) => c,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new(e))).into_response();
        }
    };

    #[derive(serde::Deserialize)]
    struct GithubTokenResponse {
        access_token: Option<String>,
        error: Option<String>,
        error_description: Option<String>,
    }

    let token_resp = http
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .json(&serde_json::json!({
            "client_id": state.github_client_id,
            "client_secret": state.github_client_secret,
            "code": req.code,
            "redirect_uri": redirect_uri,
        }))
        .send()
        .await;

    let token_resp = match token_resp {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("GitHub token exchange failed: {}", e);
            return (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("GitHub token exchange request failed"))).into_response();
        }
    };

    let github_token: GithubTokenResponse = match token_resp.json().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("GitHub token parse failed: {}", e);
            return (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("Failed to parse GitHub token response"))).into_response();
        }
    };

    if let Some(err) = github_token.error {
        let desc = github_token.error_description.unwrap_or_default();
        return (StatusCode::BAD_REQUEST, Json(ErrorResponse::new(format!("GitHub OAuth error: {} \u{2014} {}", err, desc)))).into_response();
    }

    let access_token = match github_token.access_token {
        Some(t) => t,
        None => {
            return (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("No access_token in GitHub response"))).into_response();
        }
    };

    #[derive(serde::Deserialize)]
    struct GithubUser {
        id: u64,
        login: String,
        name: Option<String>,
    }

    let user: GithubUser = match fetch_json(&http, "https://api.github.com/user", &access_token, Some("mylittlechart-server/0.1")).await {
        Ok(u) => u,
        Err(e) => return e,
    };

    let display_name = user.name.unwrap_or_else(|| user.login.clone());
    let device_id = req.device_id.as_deref().unwrap_or("");
    finish_oauth(state, "github", &user.id.to_string(), &display_name, device_id).await
}

async fn discord_callback(state: Arc<AppState>, req: OAuthCallbackRequest) -> Response {
    let redirect_uri = format!("http://127.0.0.1:{}/callback", req.redirect_port);

    let http = match build_http_client() {
        Ok(c) => c,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new(e))).into_response();
        }
    };

    #[derive(serde::Deserialize)]
    struct DiscordTokenResponse {
        access_token: Option<String>,
        error: Option<String>,
    }

    let token_resp = http
        .post("https://discord.com/api/v10/oauth2/token")
        .form(&[
            ("client_id", state.discord_client_id.as_str()),
            ("client_secret", state.discord_client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code", req.code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
        ])
        .send()
        .await;

    let token_resp = match token_resp {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Discord token exchange failed: {}", e);
            return (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("Discord token exchange request failed"))).into_response();
        }
    };

    let discord_token: DiscordTokenResponse = match token_resp.json().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Discord token parse failed: {}", e);
            return (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("Failed to parse Discord token response"))).into_response();
        }
    };

    if let Some(err) = discord_token.error {
        return (StatusCode::BAD_REQUEST, Json(ErrorResponse::new(format!("Discord OAuth error: {}", err)))).into_response();
    }

    let access_token = match discord_token.access_token {
        Some(t) => t,
        None => {
            return (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("No access_token in Discord response"))).into_response();
        }
    };

    #[derive(serde::Deserialize)]
    struct DiscordUser {
        id: String,
        username: String,
        global_name: Option<String>,
    }

    let user: DiscordUser = match fetch_json(&http, "https://discord.com/api/v10/users/@me", &access_token, None).await {
        Ok(u) => u,
        Err(e) => return e,
    };

    let display_name = user.global_name.unwrap_or_else(|| user.username.clone());
    let device_id = req.device_id.as_deref().unwrap_or("");
    finish_oauth(state, "discord", &user.id, &display_name, device_id).await
}

async fn google_callback(state: Arc<AppState>, req: OAuthCallbackRequest) -> Response {
    let redirect_uri = format!("http://127.0.0.1:{}/callback", req.redirect_port);

    let http = match build_http_client() {
        Ok(c) => c,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new(e))).into_response();
        }
    };

    #[derive(serde::Deserialize)]
    struct GoogleTokenResponse {
        access_token: Option<String>,
        error: Option<String>,
        error_description: Option<String>,
    }

    let token_resp = http
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", state.google_client_id.as_str()),
            ("client_secret", state.google_client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code", req.code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
        ])
        .send()
        .await;

    let token_resp = match token_resp {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Google token exchange failed: {}", e);
            return (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("Google token exchange request failed"))).into_response();
        }
    };

    let google_token: GoogleTokenResponse = match token_resp.json().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Google token parse failed: {}", e);
            return (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("Failed to parse Google token response"))).into_response();
        }
    };

    if let Some(err) = google_token.error {
        let desc = google_token.error_description.unwrap_or_default();
        return (StatusCode::BAD_REQUEST, Json(ErrorResponse::new(format!("Google OAuth error: {} \u{2014} {}", err, desc)))).into_response();
    }

    let access_token = match google_token.access_token {
        Some(t) => t,
        None => {
            return (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("No access_token in Google response"))).into_response();
        }
    };

    #[derive(serde::Deserialize)]
    struct GoogleUser {
        sub: String,
        name: Option<String>,
        email: Option<String>,
    }

    let user: GoogleUser = match fetch_json(&http, "https://www.googleapis.com/oauth2/v3/userinfo", &access_token, None).await {
        Ok(u) => u,
        Err(e) => return e,
    };

    let display_name = user
        .name
        .or(user.email)
        .unwrap_or_else(|| format!("google:{}", &user.sub[..8.min(user.sub.len())]));
    let device_id = req.device_id.as_deref().unwrap_or("");
    finish_oauth(state, "google", &user.sub, &display_name, device_id).await
}

async fn twitter_callback(state: Arc<AppState>, req: OAuthCallbackRequest) -> Response {
    let redirect_uri = format!("http://127.0.0.1:{}/callback", req.redirect_port);

    let http = match build_http_client() {
        Ok(c) => c,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new(e))).into_response();
        }
    };

    // For PKCE we need the code_verifier. During authorize we used state_param as
    // the code_verifier; the client passes the state value back in the callback request.
    let code_verifier = match &req.state {
        Some(s) => s.clone(),
        None => {
            return (StatusCode::BAD_REQUEST, Json(ErrorResponse::new("Missing state parameter for Twitter PKCE"))).into_response();
        }
    };

    #[derive(serde::Deserialize)]
    struct TwitterTokenResponse {
        access_token: Option<String>,
        error: Option<String>,
        error_description: Option<String>,
    }

    let token_resp = http
        .post("https://api.twitter.com/2/oauth2/token")
        .basic_auth(&state.twitter_client_id, Some(&state.twitter_client_secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", req.code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("code_verifier", code_verifier.as_str()),
        ])
        .send()
        .await;

    let token_resp = match token_resp {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Twitter token exchange failed: {}", e);
            return (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("Twitter token exchange request failed"))).into_response();
        }
    };

    let twitter_token: TwitterTokenResponse = match token_resp.json().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Twitter token parse failed: {}", e);
            return (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("Failed to parse Twitter token response"))).into_response();
        }
    };

    if let Some(err) = twitter_token.error {
        let desc = twitter_token.error_description.unwrap_or_default();
        return (StatusCode::BAD_REQUEST, Json(ErrorResponse::new(format!("Twitter OAuth error: {} \u{2014} {}", err, desc)))).into_response();
    }

    let access_token = match twitter_token.access_token {
        Some(t) => t,
        None => {
            return (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("No access_token in Twitter response"))).into_response();
        }
    };

    #[derive(serde::Deserialize)]
    struct TwitterUserData {
        id: String,
        #[allow(dead_code)]
        name: String,
        username: String,
    }
    #[derive(serde::Deserialize)]
    struct TwitterUserResponse {
        data: Option<TwitterUserData>,
    }

    let user_resp: TwitterUserResponse = match fetch_json(&http, "https://api.twitter.com/2/users/me", &access_token, None).await {
        Ok(u) => u,
        Err(e) => return e,
    };

    let user = match user_resp.data {
        Some(d) => d,
        None => {
            return (StatusCode::BAD_GATEWAY, Json(ErrorResponse::new("No user data in Twitter response"))).into_response();
        }
    };

    let display_name = format!("@{}", user.username);
    let device_id = req.device_id.as_deref().unwrap_or("");
    finish_oauth(state, "twitter", &user.id, &display_name, device_id).await
}

// ============================================================================
// Shared: upsert user + generate token
// ============================================================================

/// Upsert user, create token (expires in 30 days), link device, return `OAuthCallbackResponse`.
///
/// Device-merge logic: if `device_id` is non-empty and the device already has a linked
/// user, we reuse that existing user rather than creating a new row.  This prevents one
/// physical device from accumulating multiple accounts across providers.  All new auth
/// tokens are issued under the canonical (existing) `user_id`.
async fn finish_oauth(
    state: Arc<AppState>,
    provider: &str,
    provider_user_id: &str,
    display_name: &str,
    device_id: &str,
) -> Response {
    let raw_token = generate_token();
    let token_hash = hash_token(&raw_token);
    let now = chrono::Utc::now().to_rfc3339();
    let expires_at = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();

    let provider = provider.to_owned();
    let provider_user_id = provider_user_id.to_owned();
    let display_name = display_name.to_owned();
    let device_id = device_id.to_owned();
    let token_hash_clone = token_hash.clone();
    let raw_token_clone = raw_token.clone();
    let display_name_clone = display_name.clone();
    let provider_clone = provider.clone();

    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<(i64, String)> {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());

        // Upsert the user row for this provider identity.
        let new_user_id = crate::db::upsert_user(&conn, &provider, &provider_user_id, &display_name, &now)?;

        // Determine canonical user_id: if the device already has a user, adopt it.
        let canonical_user_id = if !device_id.is_empty() {
            match crate::db::get_user_for_device(&conn, &device_id)? {
                Some(existing_user_id) if existing_user_id != new_user_id => {
                    // Device belongs to a different account — reassign new tokens to
                    // the existing user so both provider identities share one account.
                    tracing::info!(
                        "Device {} already linked to user {}; merging new user {} into it",
                        device_id, existing_user_id, new_user_id
                    );
                    crate::db::reassign_auth_tokens(&conn, new_user_id, existing_user_id)?;
                    existing_user_id
                }
                _ => new_user_id,
            }
        } else {
            new_user_id
        };

        crate::db::insert_auth_token_with_expiry(&conn, &token_hash_clone, canonical_user_id, &now, &expires_at)?;

        // Link device to the canonical user.
        if !device_id.is_empty() {
            crate::db::link_device_user(&conn, &device_id, canonical_user_id, &now)?;
        }

        let public_id = crate::db::get_user_public_id(&conn, canonical_user_id)
            .unwrap_or_default();

        Ok((canonical_user_id, public_id))
    })
    .await;

    let (user_id, public_id) = match result {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => {
            tracing::error!("DB error in finish_oauth: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Database error"))).into_response();
        }
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Internal error"))).into_response();
        }
    };

    tracing::info!("OAuth login: provider={} display_name={} user_id={}", provider_clone, display_name_clone, user_id);

    Json(OAuthCallbackResponse {
        token: raw_token_clone,
        display_name: display_name_clone,
        user_id,
        public_id,
    })
    .into_response()
}

// ============================================================================
// Helpers
// ============================================================================

/// Build a reqwest client with a 10s timeout.
fn build_http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))
}

/// Fetch JSON from an API endpoint with Bearer auth.
async fn fetch_json<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    url: &str,
    access_token: &str,
    user_agent: Option<&str>,
) -> Result<T, Response> {
    let mut req = http
        .get(url)
        .header("Authorization", format!("Bearer {}", access_token));
    if let Some(ua) = user_agent {
        req = req.header("User-Agent", ua);
    }
    let resp = req.send().await.map_err(|e| {
        tracing::error!("Fetch {} failed: {}", url, e);
        (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse::new(format!("Failed to fetch {}", url))),
        )
            .into_response()
    })?;
    resp.json().await.map_err(|e| {
        tracing::error!("Parse {} failed: {}", url, e);
        (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse::new(format!(
                "Failed to parse response from {}",
                url
            ))),
        )
            .into_response()
    })
}

/// Minimal percent-encoding for URL parameters (encodes everything except
/// unreserved chars: A-Z a-z 0-9 - _ . ~).
fn urlencoding_simple(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{:02X}", byte));
            }
        }
    }
    out
}

/// Base64 URL-safe encoding without padding (for PKCE code_challenge).
fn base64_url_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() { data[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if i + 1 < data.len() {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        }
        if i + 2 < data.len() {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        }
        i += 3;
    }
    result
}

/// Verify the Telegram login widget hash.
///
/// Algorithm:
/// 1. Collect all fields except `hash` as `key=value` pairs, sort, join with `\n`.
/// 2. Secret key = SHA256(bot_token).
/// 3. Compute HMAC-SHA256 of the data string using the secret key.
/// 4. Compare hex(HMAC) with the provided hash.
fn verify_telegram_hash(req: &TelegramCallbackRequest, bot_token: &str) -> bool {
    let mut pairs: Vec<String> = vec![
        format!("auth_date={}", req.auth_date),
        format!("first_name={}", req.first_name),
        format!("id={}", req.id),
    ];
    if let Some(ref last_name) = req.last_name {
        if !last_name.is_empty() {
            pairs.push(format!("last_name={}", last_name));
        }
    }
    if !req.username.is_empty() {
        pairs.push(format!("username={}", req.username));
    }
    pairs.sort();
    let data_check_string = pairs.join("\n");

    let secret_key = {
        let mut hasher = Sha256::new();
        hasher.update(bot_token.as_bytes());
        hasher.finalize()
    };

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = match HmacSha256::new_from_slice(&secret_key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(data_check_string.as_bytes());
    let result = mac.finalize().into_bytes();
    let computed = hex::encode(result);

    constant_time_eq(computed.as_bytes(), req.hash.as_bytes())
}

/// Verify the Telegram Login Widget hash for query-parameter based web callback.
///
/// Same algorithm as `verify_telegram_hash` but operates on `TelegramWebCallbackQuery`.
fn verify_telegram_web_hash(query: &TelegramWebCallbackQuery, bot_token: &str) -> bool {
    let mut pairs: Vec<String> = vec![
        format!("auth_date={}", query.auth_date),
        format!("id={}", query.id),
    ];
    if let Some(ref first_name) = query.first_name {
        if !first_name.is_empty() {
            pairs.push(format!("first_name={}", first_name));
        }
    }
    if let Some(ref last_name) = query.last_name {
        if !last_name.is_empty() {
            pairs.push(format!("last_name={}", last_name));
        }
    }
    if let Some(ref username) = query.username {
        if !username.is_empty() {
            pairs.push(format!("username={}", username));
        }
    }
    if let Some(ref photo_url) = query.photo_url {
        if !photo_url.is_empty() {
            pairs.push(format!("photo_url={}", photo_url));
        }
    }
    pairs.sort();
    let data_check_string = pairs.join("\n");

    let secret_key = {
        let mut hasher = Sha256::new();
        hasher.update(bot_token.as_bytes());
        hasher.finalize()
    };

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = match HmacSha256::new_from_slice(&secret_key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(data_check_string.as_bytes());
    let result = mac.finalize().into_bytes();
    let computed = hex::encode(result);

    constant_time_eq(computed.as_bytes(), query.hash.as_bytes())
}

/// Constant-time byte slice comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

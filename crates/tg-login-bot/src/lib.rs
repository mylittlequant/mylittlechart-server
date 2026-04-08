//! Telegram login bot — handles /start commands for web login flow.
//!
//! Runs as a background tokio task inside zengeld-server using raw Telegram
//! Bot API via reqwest (no teloxide dependency).

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Callback that the server passes in. Called when a `/start web_<token>`
/// message arrives. Arguments: `(token, telegram_user_id, display_name)`.
/// Returns `true` if the token was valid and pending, `false` otherwise.
pub type ConfirmFn = Arc<dyn Fn(&str, &str, &str) -> bool + Send + Sync>;

/// Starts the Telegram bot long-polling loop.
///
/// Returns a `JoinHandle` that runs until the shutdown signal is received.
pub fn start(
    bot_token: String,
    confirm_login: ConfirmFn,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("failed to build reqwest client");

        info!("tg-login-bot: starting long-polling loop");

        let mut offset: i64 = 0;

        loop {
            tokio::select! {
                _ = shutdown.recv() => {
                    info!("tg-login-bot: shutdown signal received, stopping");
                    break;
                }
                result = get_updates(&client, &bot_token, offset, 30) => {
                    match result {
                        Ok(updates) => {
                            for update in &updates {
                                offset = offset.max(update.update_id + 1);
                                handle_update(&client, &bot_token, update, &confirm_login).await;
                            }
                            if updates.is_empty() {
                                debug!("tg-login-bot: no new updates");
                            }
                        }
                        Err(e) => {
                            warn!("tg-login-bot: getUpdates error: {e}. Retrying in 5s");
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        }
                    }
                }
            }
        }

        info!("tg-login-bot: stopped");
    })
}

// ---------------------------------------------------------------------------
// Telegram API types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TgResponse<T> {
    ok: bool,
    result: Option<T>,
    description: Option<String>,
}

#[derive(Deserialize)]
struct Update {
    update_id: i64,
    message: Option<Message>,
}

#[derive(Deserialize)]
struct Message {
    chat: Chat,
    from: Option<User>,
    text: Option<String>,
}

#[derive(Deserialize)]
struct Chat {
    id: i64,
}

#[derive(Deserialize)]
struct User {
    id: i64,
    first_name: String,
    last_name: Option<String>,
    username: Option<String>,
}

#[derive(Serialize)]
struct GetUpdatesBody<'a> {
    offset: i64,
    timeout: u32,
    allowed_updates: &'a [&'a str],
}

#[derive(Serialize)]
struct SendMessageBody<'a> {
    chat_id: i64,
    text: &'a str,
    parse_mode: &'a str,
}

// ---------------------------------------------------------------------------
// Telegram API calls
// ---------------------------------------------------------------------------

async fn get_updates(
    client: &reqwest::Client,
    bot_token: &str,
    offset: i64,
    timeout_secs: u32,
) -> Result<Vec<Update>, reqwest::Error> {
    let url = format!("https://api.telegram.org/bot{bot_token}/getUpdates");

    let body = GetUpdatesBody {
        offset,
        timeout: timeout_secs,
        allowed_updates: &["message"],
    };

    let resp: TgResponse<Vec<Update>> = client
        .post(&url)
        .json(&body)
        .send()
        .await?
        .json()
        .await?;

    if !resp.ok {
        let desc = resp
            .description
            .unwrap_or_else(|| "unknown error".to_owned());
        warn!("tg-login-bot: getUpdates returned ok=false: {desc}");
    }

    Ok(resp.result.unwrap_or_default())
}

async fn send_message(client: &reqwest::Client, bot_token: &str, chat_id: i64, text: &str) {
    let url = format!("https://api.telegram.org/bot{bot_token}/sendMessage");

    let body = SendMessageBody {
        chat_id,
        text,
        parse_mode: "HTML",
    };

    match client.post(&url).json(&body).send().await {
        Ok(resp) if resp.status().is_success() => {
            debug!("tg-login-bot: sent message to chat {chat_id}");
        }
        Ok(resp) => {
            warn!(
                "tg-login-bot: sendMessage HTTP {} for chat {chat_id}",
                resp.status()
            );
        }
        Err(e) => {
            error!("tg-login-bot: sendMessage error for chat {chat_id}: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Update handler
// ---------------------------------------------------------------------------

async fn handle_update(
    client: &reqwest::Client,
    bot_token: &str,
    update: &Update,
    confirm_login: &ConfirmFn,
) {
    let Some(msg) = &update.message else {
        return;
    };

    let chat_id = msg.chat.id;
    let text = msg.text.as_deref().unwrap_or("");

    debug!("tg-login-bot: chat={chat_id} text={text:?}");

    if let Some(web_token) = parse_web_token(text) {
        handle_web_login(client, bot_token, chat_id, web_token, &msg.from, confirm_login).await;
    } else if text.starts_with("/start") {
        // /start without web_ prefix
        send_message(
            client,
            bot_token,
            chat_id,
            "👋 Hi! I'm the mylittlechart.org login bot. Use the website to sign in.",
        )
        .await;
    }
    // Ignore all other messages silently.
}

/// Extracts the token string from `/start web_<token>` commands.
/// Returns `None` if the text does not match that pattern.
fn parse_web_token(text: &str) -> Option<&str> {
    let rest = text.strip_prefix("/start")?;
    // Allow `/start web_TOKEN` (with space) or `/startWeb_TOKEN` (no space, rare).
    let rest = rest.trim_start();
    rest.strip_prefix("web_")
}

async fn handle_web_login(
    client: &reqwest::Client,
    bot_token: &str,
    chat_id: i64,
    web_token: &str,
    from: &Option<User>,
    confirm_login: &ConfirmFn,
) {
    let (telegram_user_id, display_name) = match from {
        Some(user) => {
            let uid = user.id.to_string();

            // Build display name: first_name [last_name]
            let full_name = match &user.last_name {
                Some(last) => format!("{} {}", user.first_name, last),
                None => user.first_name.clone(),
            };

            // Prefer @username as display name if available, fall back to full name.
            let display = match &user.username {
                Some(uname) => format!("@{uname}"),
                None => full_name,
            };

            (uid, display)
        }
        None => {
            warn!("tg-login-bot: received /start from anonymous sender, ignoring");
            return;
        }
    };

    info!(
        "tg-login-bot: web login attempt — token={web_token} user={display_name} tg_id={telegram_user_id}"
    );

    let confirmed = confirm_login(web_token, &telegram_user_id, &display_name);

    if confirmed {
        info!("tg-login-bot: confirmed login for {display_name}");
        send_message(
            client,
            bot_token,
            chat_id,
            "✅ You are now signed in to <b>mylittlechart.org</b>!",
        )
        .await;
    } else {
        warn!("tg-login-bot: token not found or expired — token={web_token}");
        send_message(
            client,
            bot_token,
            chat_id,
            "❌ Login link expired or invalid. Please try again from the website.",
        )
        .await;
    }
}

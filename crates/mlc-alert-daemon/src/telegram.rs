//! Minimal Telegram `sendMessage` client — the SAME bot identity
//! `tg-login-bot` uses (`TELEGRAM_BOT_TOKEN`, `mylittlechart_login_bot`),
//! reused here for account-wide alert delivery to the DM `chat_id` (which
//! IS `tg_user_id` — see `routes/tg_login.rs`'s existing resolution and
//! plan §3 "Web — centralized bot, paid": "Reuses `mylittlechart_login_bot`'s
//! own token … not a second bot").
//!
//! Deliberately not a dependency on the `tg-login-bot` crate: that crate's
//! `send_message` is a private helper of its own long-polling loop, not a
//! published API — this is the one function this daemon needs, kept small
//! rather than widening that crate's surface for one caller.

use serde::Serialize;

#[derive(Serialize)]
struct SendMessageBody<'a> {
    chat_id: i64,
    text: &'a str,
    parse_mode: &'a str,
}

/// Send one HTML-formatted message to `chat_id` via the bot API.
pub async fn send_message(
    client: &reqwest::Client,
    bot_token: &str,
    chat_id: i64,
    text: &str,
) -> Result<(), reqwest::Error> {
    let url = format!("https://api.telegram.org/bot{bot_token}/sendMessage");
    let body = SendMessageBody {
        chat_id,
        text,
        parse_mode: "HTML",
    };
    client.post(&url).json(&body).send().await?.error_for_status()?;
    Ok(())
}

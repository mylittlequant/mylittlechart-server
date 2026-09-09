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
//!
//! Public since the 2026-09-09 owner-outreach route
//! (`mylittlechart-server`'s `routes::notify`): [`send_plain_message`] is the
//! second function here, reusing the same bot identity for an admin-composed
//! broadcast rather than an HTML-templated alert — the two never share a
//! caller, so widening this module's visibility beats a third near-identical
//! `sendMessage` helper in `server`.

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

#[derive(Serialize)]
struct SendPlainMessageBody<'a> {
    chat_id: i64,
    text: &'a str,
    disable_web_page_preview: bool,
}

/// Send one PLAIN TEXT message to `chat_id` via the bot API — no
/// `parse_mode` at all (Telegram treats the body as literal text, so an
/// admin-composed broadcast containing `<`, `>`, `&`, or Markdown-looking
/// punctuation is never misparsed as markup), and previews left on
/// (`disable_web_page_preview: false`, spelled out rather than left to
/// Telegram's own default). Used by `mylittlechart-server`'s
/// `POST /api/admin/notify` — see this module's doc comment.
pub async fn send_plain_message(
    client: &reqwest::Client,
    bot_token: &str,
    chat_id: i64,
    text: &str,
) -> Result<(), reqwest::Error> {
    let url = format!("https://api.telegram.org/bot{bot_token}/sendMessage");
    let body = SendPlainMessageBody {
        chat_id,
        text,
        disable_web_page_preview: false,
    };
    client.post(&url).json(&body).send().await?.error_for_status()?;
    Ok(())
}

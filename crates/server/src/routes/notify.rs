//! Owner outreach (owner ruling 2026-09-09): `POST /api/admin/notify` sends
//! one message to every account with a linked Telegram identity (or an
//! explicit subset), and `GET /api/admin/notify/batches` lists the last 50
//! calls. Both admin-secret gated (see `routes::admin::verify_admin_secret`).
//!
//! The actual recipient resolution, send loop, and `notify_batches`/
//! `notify_log` bookkeeping live in `crate::notify` (transport-agnostic —
//! see that module's doc comment); this file only wires the HTTP shape and
//! the one production sender ([`live_telegram_sender`]), which reuses
//! `mlc_alert_daemon::telegram::send_plain_message` — the same bot identity
//! `tg-login-bot` and `mlc-alert-daemon` already use, plain text rather than
//! either of their HTML-templated sends (see that function's doc comment).

use axum::{
    body::Bytes,
    extract::{ConnectInfo, Extension, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
    Json,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::models::types::ErrorResponse;
use crate::notify::{self, NotifyTarget};
use crate::routes::admin::{peer_addr, verify_admin_secret};
use crate::state::AppState;

/// Telegram allows roughly 30 messages/second to distinct chats; this is
/// comfortably under that ceiling for a sequential admin broadcast (see
/// `crate::notify::send_batch`'s `delay` parameter).
const SEND_DELAY: Duration = Duration::from_millis(100);

/// JSON body for `POST /api/admin/notify`.
#[derive(serde::Deserialize)]
pub struct NotifyRequest {
    /// Only `"telegram"` is accepted today — there is no other outreach
    /// channel this account has agreed to (see this module's doc comment).
    pub channel: String,
    /// `"all"` (every Telegram-linked account) or a JSON array of integer
    /// user ids — parsed by [`parse_target`].
    pub to: serde_json::Value,
    pub text: String,
    #[serde(default)]
    pub dry_run: bool,
}

fn bad_request(msg: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, Json(ErrorResponse::new(msg))).into_response()
}

fn internal_error() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Internal error"))).into_response()
}

/// Parse the `to` field: `"all"`, or a JSON array of integer user ids.
/// `pub(crate)` so `crate::notify`'s tests can exercise it directly without
/// going through the HTTP layer.
pub(crate) fn parse_target(to: &serde_json::Value) -> Result<NotifyTarget, &'static str> {
    match to {
        serde_json::Value::String(s) if s == "all" => Ok(NotifyTarget::All),
        serde_json::Value::Array(items) => {
            let mut ids = Vec::with_capacity(items.len());
            for item in items {
                match item.as_i64() {
                    Some(id) => ids.push(id),
                    None => return Err("to must be \"all\" or an array of integer user ids"),
                }
            }
            Ok(NotifyTarget::Users(ids))
        }
        _ => Err("to must be \"all\" or an array of integer user ids"),
    }
}

/// The one production [`notify::NotifySender`]: reuses
/// `mlc_alert_daemon::telegram::send_plain_message` (plain text, previews
/// on — see that function's doc comment) against one `reqwest::Client`
/// built once per call and shared across every recipient in the batch, not
/// rebuilt per message.
fn live_telegram_sender(client: reqwest::Client, bot_token: String) -> notify::NotifySender {
    Arc::new(move |chat_id: i64, text: String| {
        let client = client.clone();
        let bot_token = bot_token.clone();
        Box::pin(async move {
            mlc_alert_daemon::telegram::send_plain_message(&client, &bot_token, chat_id, &text)
                .await
                .map_err(|e| e.to_string())
        })
    })
}

/// POST /api/admin/notify
///
/// Body `{"channel":"telegram","to":"all"|[user_id,...],"text":"...",
/// "dry_run":bool}`. `text` over `notify::MAX_NOTIFY_TEXT_LEN` characters
/// (3900 — margin under Telegram's own 4096) is refused with 400 before
/// anything is resolved. `dry_run: true` resolves recipients and returns
/// `{"recipients":[{"user_id","nick","chat_id_present":true}],"count":n}`
/// without sending or writing a single row; otherwise every recipient is
/// sent to sequentially (`crate::notify::send_batch`) and the response is
/// `{"batch_id","sent","failed":[{"user_id","error"}]}`. Empty recipients
/// (e.g. an explicit list with no Telegram identity among them) still
/// answers 200 with `count`/`sent` 0. If `TELEGRAM_BOT_TOKEN` was never set
/// at boot, answers 503 `{"error":"telegram bot token not configured"}` —
/// the token itself is never logged. Requires
/// `Authorization: Bearer {ADMIN_SECRET}`.
pub async fn notify(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Bytes,
) -> Response {
    if let Err(e) = verify_admin_secret(&state, &headers, &uri, peer_addr(peer)) {
        return e;
    }

    let req: NotifyRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return bad_request("Invalid JSON body"),
    };

    if req.channel != "telegram" {
        return bad_request("channel must be \"telegram\"");
    }
    let target = match parse_target(&req.to) {
        Ok(t) => t,
        Err(msg) => return bad_request(msg),
    };
    if req.text.is_empty() {
        return bad_request("text must not be empty");
    }
    if req.text.len() > notify::MAX_NOTIFY_TEXT_LEN {
        return bad_request(format!("text too long (max {} characters)", notify::MAX_NOTIFY_TEXT_LEN));
    }

    if req.dry_run {
        let result = tokio::task::spawn_blocking(move || {
            let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            crate::db::telegram_recipients(&conn, &target)
        })
        .await;

        return match result {
            Ok(Ok(recipients)) => {
                let count = recipients.len();
                let preview: Vec<_> = recipients
                    .into_iter()
                    .map(|r| {
                        serde_json::json!({
                            "user_id": r.user_id,
                            "nick": r.nick,
                            "chat_id_present": true,
                        })
                    })
                    .collect();
                Json(serde_json::json!({ "recipients": preview, "count": count })).into_response()
            }
            Ok(Err(e)) => {
                tracing::error!("DB error resolving notify recipients: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Database error"))).into_response()
            }
            Err(_) => internal_error(),
        };
    }

    let bot_token = state.telegram_bot_token.clone();
    if bot_token.is_empty() {
        tracing::warn!("admin notify refused: TELEGRAM_BOT_TOKEN is not configured");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse::new("telegram bot token not configured")),
        )
            .into_response();
    }

    let client = match reqwest::Client::builder().timeout(Duration::from_secs(15)).build() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("failed to build the outreach HTTP client: {}", e);
            return internal_error();
        }
    };
    let sender = live_telegram_sender(client, bot_token);

    let outcome = {
        let db = &state.control_plane().db;
        notify::send_batch(db, "telegram", &target, &req.text, "admin", &sender, SEND_DELAY).await
    };

    match outcome {
        Ok(o) => Json(serde_json::json!({
            "batch_id": o.batch_id,
            "sent": o.sent,
            "failed": o.failed,
        }))
        .into_response(),
        Err(notify::NotifyError::TextTooLong) => bad_request("text too long"),
        Err(notify::NotifyError::Db(e)) => {
            tracing::error!("DB error sending notify batch: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Database error"))).into_response()
        }
    }
}

/// GET /api/admin/notify/batches
///
/// Last 50 outreach batches (`crate::db::list_notify_batches`), newest
/// first, each with its `sent`/`failed` counts. Requires
/// `Authorization: Bearer {ADMIN_SECRET}`.
pub async fn list_batches(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Response {
    if let Err(e) = verify_admin_secret(&state, &headers, &uri, peer_addr(peer)) {
        return e;
    }

    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::list_notify_batches(&conn, 50)
    })
    .await;

    match result {
        Ok(Ok(batches)) => Json(serde_json::json!({ "batches": batches })).into_response(),
        Ok(Err(e)) => {
            tracing::error!("DB error listing notify batches: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Database error"))).into_response()
        }
        Err(_) => internal_error(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_accepts_all() {
        assert!(matches!(parse_target(&serde_json::json!("all")), Ok(NotifyTarget::All)));
    }

    #[test]
    fn parse_target_accepts_an_integer_list() {
        match parse_target(&serde_json::json!([1, 2, 3])) {
            Ok(NotifyTarget::Users(ids)) => assert_eq!(ids, vec![1, 2, 3]),
            other => panic!("expected NotifyTarget::Users, got {other:?}"),
        }
    }

    #[test]
    fn parse_target_rejects_anything_else() {
        assert!(parse_target(&serde_json::json!("everyone")).is_err());
        assert!(parse_target(&serde_json::json!(["not-a-number"])).is_err());
        assert!(parse_target(&serde_json::json!(42)).is_err());
    }
}

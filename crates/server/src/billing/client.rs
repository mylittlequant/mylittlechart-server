//! HTTP client for the dig2pay merchant API
//! (`docs/dig2pay/plans/merchant-contract-2026-09-10.md` §2).
//!
//! The merchant bearer key authenticates every call. The transport is a
//! dedicated WireGuard tunnel (`wg-mlc`); nothing here is exposed to a
//! browser — the browser only ever talks to this server.
//!
//! Every call has a connect timeout and an overall timeout, and redirects are
//! never followed (a redirect must not carry the bearer key to another
//! host). `POST /subscribers` and `POST /subscriptions` (and the change
//! route) carry an `Idempotency-Key`, so a retry after a timeout returns the
//! same resource rather than minting a second invoice and address.

use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Longest response body read from dig2pay. The largest legitimate answer
/// (a `pay[]` with a dozen QR SVGs) is far below this.
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Longest slice of a refusal message kept.
const MAX_MESSAGE_CHARS: usize = 200;

/// Connect timeout, capped by the overall timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// A failed call to dig2pay. Never wraps the merchant key.
#[derive(Debug)]
pub enum GatewayError {
    /// No HTTP answer was obtained (connect failure, timeout, ...).
    Transport(String),
    /// dig2pay answered with a non-2xx status.
    Refused {
        /// HTTP status code.
        status: u16,
        /// dig2pay's `{"error": ...}` message, truncated.
        message: String,
    },
    /// A 2xx answer did not have the documented shape.
    Decode(String),
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GatewayError::Transport(e) => write!(f, "payment gateway unreachable: {e}"),
            GatewayError::Refused { status, message } => {
                write!(f, "payment gateway refused ({status}): {message}")
            }
            GatewayError::Decode(e) => write!(f, "payment gateway answer did not parse: {e}"),
        }
    }
}

/// One `(chain, asset)` way to pay an invoice. Every enabled option rides
/// one invoice; the payer picks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PayOption {
    /// Chain label, e.g. `evm:1` or `tron`.
    pub chain: String,
    /// Asset symbol, e.g. `USDT`.
    pub asset: String,
    /// Recipient address.
    pub address: String,
    /// Amount owed, human decimal string.
    pub amount: String,
    /// When this option stops being watched, RFC 3339.
    pub expires_at: String,
    /// SVG QR encoding the bare `address`.
    #[serde(default)]
    pub qr_svg: String,
}

/// `POST /subscriptions` answer.
#[derive(Debug, Clone, Deserialize)]
pub struct CreatedSubscription {
    /// dig2pay's subscription id; webhooks name it as `subscriber_id`.
    pub subscription_id: String,
    /// The first invoice (an `invoice_group` id).
    pub invoice_id: String,
    /// Every enabled way to pay it.
    #[serde(default)]
    pub pay: Vec<PayOption>,
}

/// The live status line of `GET /invoices/{id}`.
#[derive(Debug, Clone, Deserialize)]
pub struct LiveInvoice {
    /// `new | processing | settled | complete | expired | invalid`.
    pub status: String,
}

/// `POST /subscriptions/{id}/change` answer.
#[derive(Debug, Clone, Deserialize)]
pub struct ChangeResponse {
    /// Stable across this response and the eventual webhook.
    pub change_id: String,
    /// `pending | applied | cancelled`.
    pub state: String,
    /// The proration invoice, when dig2pay names it (optional in the contract).
    #[serde(default)]
    pub invoice_id: Option<String>,
    /// USD micros charged now, as a decimal string or number.
    #[serde(default)]
    pub computed_charge_usd_micros: Option<Value>,
    /// When a deferred change will take effect, RFC 3339.
    #[serde(default)]
    pub pending_effective_at: Option<String>,
    /// Pay options of the proration invoice, when one was issued.
    #[serde(default)]
    pub pay: Vec<PayOption>,
}

/// How a plan change is charged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proration {
    /// Takes effect at the next renewal; nothing charged now.
    None,
    /// Upgrade: charge the prorated difference now.
    ChargeNow,
}

impl Proration {
    /// Wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Proration::None => "none",
            Proration::ChargeNow => "charge_now",
        }
    }
}

#[derive(Deserialize)]
struct SubscriberAnswer {
    subscriber_id: String,
}

/// The merchant client.
pub struct Dig2payClient {
    http: reqwest::Client,
    base_url: String,
    api_key: String,
}

/// An id that may safely be spliced into a URL path segment.
fn is_safe_segment(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
}

/// Drop a `qr_svg` that is not a plain SVG. dig2pay's QR is a single
/// `<rect>` plus one `<path>`; anything carrying script or event handlers is
/// not that, and this string ends up in a page.
fn sanitize_qr(svg: &str) -> String {
    let lower = svg.to_ascii_lowercase();
    let plain = lower.trim_start().starts_with("<svg")
        && !lower.contains("<script")
        && !lower.contains("javascript:")
        && !lower.contains("<foreignobject")
        && !lower.contains("<iframe")
        && !lower.contains(" on");
    if plain {
        svg.to_string()
    } else {
        String::new()
    }
}

fn sanitize_pay(pay: &mut [PayOption]) {
    for option in pay {
        option.qr_svg = sanitize_qr(&option.qr_svg);
    }
}

/// The `error` string of a refusal body, or a truncated copy of the body.
fn refusal_message(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let message = serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_else(|| text.to_string());
    message
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_MESSAGE_CHARS)
        .collect()
}

impl Dig2payClient {
    /// Build a client for `base_url` (no trailing slash needed) with the
    /// merchant `api_key`. `timeout` bounds each whole call.
    pub fn new(base_url: &str, api_key: &str, timeout: Duration) -> Result<Self, GatewayError> {
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT.min(timeout))
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            // The bearer key must only ever travel to the configured
            // address, never through an ambient HTTP(S)_PROXY.
            .no_proxy()
            .build()
            .map_err(|e| GatewayError::Transport(e.to_string()))?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
        })
    }

    async fn send<T: DeserializeOwned>(&self, request: reqwest::RequestBuilder) -> Result<T, GatewayError> {
        let response = request
            .bearer_auth(&self.api_key)
            .send()
            .await
            .map_err(|e| GatewayError::Transport(e.without_url().to_string()))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|e| GatewayError::Transport(e.without_url().to_string()))?;
        if !status.is_success() {
            return Err(GatewayError::Refused {
                status: status.as_u16(),
                message: refusal_message(&body),
            });
        }
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(GatewayError::Decode("answer too large".to_string()));
        }
        serde_json::from_slice(&body).map_err(|e| GatewayError::Decode(e.to_string()))
    }

    /// `POST /subscribers {external_user_ref}` → the merchant's customer id.
    /// Idempotent per `(merchant, external_user_ref)`; the `Idempotency-Key`
    /// makes a timed-out retry return the same answer regardless.
    pub async fn create_subscriber(
        &self,
        external_user_ref: &str,
        idempotency_key: &str,
    ) -> Result<String, GatewayError> {
        let request = self
            .http
            .post(format!("{}/subscribers", self.base_url))
            .header("Idempotency-Key", idempotency_key)
            .json(&serde_json::json!({ "external_user_ref": external_user_ref }));
        let answer: SubscriberAnswer = self.send(request).await?;
        Ok(answer.subscriber_id)
    }

    /// `POST /subscriptions {subscriber_id, plan_id}` → subscription, first
    /// invoice, and every way to pay it.
    pub async fn create_subscription(
        &self,
        subscriber_id: &str,
        plan_id: &str,
        idempotency_key: &str,
    ) -> Result<CreatedSubscription, GatewayError> {
        let request = self
            .http
            .post(format!("{}/subscriptions", self.base_url))
            .header("Idempotency-Key", idempotency_key)
            .json(&serde_json::json!({ "subscriber_id": subscriber_id, "plan_id": plan_id }));
        let mut created: CreatedSubscription = self.send(request).await?;
        sanitize_pay(&mut created.pay);
        Ok(created)
    }

    /// `GET /invoices/{id}` → the live status line.
    pub async fn get_invoice(&self, invoice_id: &str) -> Result<LiveInvoice, GatewayError> {
        if !is_safe_segment(invoice_id) {
            return Err(GatewayError::Decode("invoice id is not a plain id".to_string()));
        }
        self.send(self.http.get(format!("{}/invoices/{}", self.base_url, invoice_id))).await
    }

    /// `POST /subscriptions/{id}/change {plan_id, proration}`.
    pub async fn change_subscription(
        &self,
        subscription_id: &str,
        plan_id: &str,
        proration: Proration,
        idempotency_key: &str,
    ) -> Result<ChangeResponse, GatewayError> {
        if !is_safe_segment(subscription_id) {
            return Err(GatewayError::Decode("subscription id is not a plain id".to_string()));
        }
        let request = self
            .http
            .post(format!("{}/subscriptions/{}/change", self.base_url, subscription_id))
            .header("Idempotency-Key", idempotency_key)
            .json(&serde_json::json!({ "plan_id": plan_id, "proration": proration.as_str() }));
        let mut changed: ChangeResponse = self.send(request).await?;
        sanitize_pay(&mut changed.pay);
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_qr_svgs_pass_and_active_content_is_dropped() {
        let plain = r#"<svg viewBox="0 0 10 10" shape-rendering="crispEdges"><rect width="10" height="10"/><path d="M1 1h1v1h-1z"/></svg>"#;
        assert_eq!(sanitize_qr(plain), plain);
        for hostile in [
            "<svg><script>alert(1)</script></svg>",
            r#"<svg onload="x()"></svg>"#,
            r#"<svg><a href="javascript:x()"/></svg>"#,
            "<svg><foreignObject/></svg>",
            "<div>not an svg</div>",
            "",
        ] {
            assert_eq!(sanitize_qr(hostile), "", "{hostile}");
        }
    }

    #[test]
    fn path_segments_reject_anything_that_could_change_the_route() {
        assert!(is_safe_segment("grp_0f3a-9c"));
        for bad in ["", "a/b", "a?b", "..%2f", "a b", "a#b", &"x".repeat(129)] {
            assert!(!is_safe_segment(bad), "{bad}");
        }
    }

    #[test]
    fn refusal_messages_prefer_the_error_field_and_are_bounded() {
        assert_eq!(refusal_message(br#"{"error":"not found"}"#), "not found");
        assert_eq!(refusal_message(b"plain text\n"), "plain text");
        let long = format!(r#"{{"error":"{}"}}"#, "x".repeat(1000));
        assert_eq!(refusal_message(long.as_bytes()).chars().count(), MAX_MESSAGE_CHARS);
    }

    #[test]
    fn change_response_accepts_string_or_number_charges_and_optional_fields() {
        let with_string: ChangeResponse =
            serde_json::from_str(r#"{"change_id":"c1","state":"pending","computed_charge_usd_micros":"12000000"}"#)
                .expect("string charge");
        assert_eq!(with_string.computed_charge_usd_micros, Some(Value::String("12000000".into())));
        assert!(with_string.pay.is_empty());
        assert!(with_string.invoice_id.is_none());
        let with_number: ChangeResponse =
            serde_json::from_str(r#"{"change_id":"c2","state":"applied","computed_charge_usd_micros":0}"#)
                .expect("numeric charge");
        assert_eq!(with_number.computed_charge_usd_micros, Some(Value::from(0)));
    }

    #[tokio::test]
    async fn a_merchant_that_never_answers_times_out_instead_of_hanging() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        // Accept connections and hold them open without ever replying.
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let client = Dig2payClient::new(&format!("http://{addr}"), "k", Duration::from_millis(300)).expect("client");
        let started = std::time::Instant::now();
        let outcome = client.get_invoice("grp_1").await;
        assert!(matches!(outcome, Err(GatewayError::Transport(_))), "{outcome:?}");
        assert!(started.elapsed() < Duration::from_secs(5), "the timeout bounded the call");
    }

    #[tokio::test]
    async fn a_redirect_is_never_followed_so_the_key_cannot_leave() {
        use axum::response::Redirect;
        use axum::routing::get;
        let app = axum::Router::new().route("/invoices/{id}", get(|| async { Redirect::temporary("http://127.0.0.1:1/elsewhere") }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = Dig2payClient::new(&format!("http://{addr}"), "k", Duration::from_secs(5)).expect("client");
        let outcome = client.get_invoice("grp_1").await;
        assert!(matches!(outcome, Err(GatewayError::Refused { status: 307, .. })), "{outcome:?}");
    }

    #[tokio::test]
    async fn a_malformed_success_body_is_a_decode_error_not_a_panic() {
        use axum::routing::get;
        let app = axum::Router::new().route("/invoices/{id}", get(|| async { "definitely not json" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = Dig2payClient::new(&format!("http://{addr}"), "k", Duration::from_secs(5)).expect("client");
        let outcome = client.get_invoice("grp_1").await;
        assert!(matches!(outcome, Err(GatewayError::Decode(_))), "{outcome:?}");
    }

    #[tokio::test]
    async fn an_id_that_could_change_the_route_never_reaches_the_wire() {
        let client = Dig2payClient::new("http://127.0.0.1:1", "k", Duration::from_secs(1)).expect("client");
        let outcome = client.get_invoice("../subscribers").await;
        assert!(matches!(outcome, Err(GatewayError::Decode(_))), "{outcome:?}");
        let outcome = client.change_subscription("a/b", "p", Proration::None, "k").await;
        assert!(matches!(outcome, Err(GatewayError::Decode(_))), "{outcome:?}");
    }
}

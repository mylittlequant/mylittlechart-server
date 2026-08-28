//! GET /api/proxy/entitlement — public policy for the whole `/archive-proxy`.
//!
//! Today the gate is `open` (must-proxy stays in the free catalog). Flipping
//! `MLC_PROXY_GATE=entitled` is the paywall: must-proxy AND the future geo
//! relay both require a paid claim. Regular registered users then get
//! `entitled: false` until billing writes a claim (not wired yet).
//!
//! This endpoint is the contract wasm will fetch on boot once the paywall
//! is live. Do not set the env var until that claim exists — it would take
//! BingX/KuCoin/… off every anonymous and free session at once.

use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct ProxyEntitlement {
    /// `"open"` (everyone may use the proxy) or `"entitled"` (paid claim).
    pub gate: &'static str,
    /// Whether THIS caller may use `/archive-proxy`. Always `true` while
    /// `gate=open`. When `gate=entitled` this is `false` until a paid
    /// session claim is wired.
    pub entitled: bool,
    /// `"planned"` — geo-relay is not sold yet, errors mention it.
    /// `"paid"` — relay is a paid feature (same gate as must-proxy).
    pub relay: &'static str,
}

/// GET /api/proxy/entitlement
pub async fn entitlement() -> Json<ProxyEntitlement> {
    let paywall = std::env::var("MLC_PROXY_GATE")
        .map(|v| v.eq_ignore_ascii_case("entitled"))
        .unwrap_or(false);
    if paywall {
        Json(ProxyEntitlement {
            gate: "entitled",
            entitled: false,
            relay: "paid",
        })
    } else {
        Json(ProxyEntitlement {
            gate: "open",
            entitled: true,
            relay: "planned",
        })
    }
}

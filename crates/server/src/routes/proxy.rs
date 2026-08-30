//! GET /api/proxy/entitlement — public policy for the whole `/archive-proxy`.
//!
//! Derives its answer from `entitlements::free_features()` (see
//! `entitlements.rs`) — the same mechanism `GET /api/entitlements`
//! (`routes/entitlements.rs`) uses — so there is one source of truth rather
//! than a `MLC_PROXY_GATE` env var living beside a `MLC_FREE_FEATURES` one.
//! Today the gate is `open` by default (must-proxy stays in the free
//! catalog). Flipping it — removing `archive_proxy` from `MLC_FREE_FEATURES`
//! — is the paywall: must-proxy AND the future geo relay both require a paid
//! claim. Regular registered users then get `entitled: false` until billing
//! writes a claim (not wired yet — see `entitlements::paid_features_for_user`).
//!
//! Deliberately keeps its no-argument signature: `routes::edge_api_router`
//! mounts this exact handler with no `AppState` at all (see routes/mod.rs),
//! and `entitlements::free_features()` reads only the environment, so this
//! still answers on an edge process that holds no database. There is
//! genuinely no per-caller difference to report today anyway — no billing
//! is wired, so an authenticated caller's set is identical to an anonymous
//! one (see `entitlements::resolve_for_user`) — so not resolving the caller
//! here costs nothing.
//!
//! This endpoint is the contract wasm will fetch on boot once the paywall
//! is live. Do not remove `archive_proxy` from `MLC_FREE_FEATURES` until
//! that claim exists — it would take BingX/KuCoin/… off every anonymous and
//! free session at once.

use axum::Json;
use serde::Serialize;

use crate::entitlements::{self, Feature};

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
    let open = entitlements::free_features().contains(Feature::ArchiveProxy);
    if open {
        Json(ProxyEntitlement {
            gate: "open",
            entitled: true,
            relay: "planned",
        })
    } else {
        Json(ProxyEntitlement {
            gate: "entitled",
            entitled: false,
            relay: "paid",
        })
    }
}

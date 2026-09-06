//! Wire shape for one `alerts`-category sync item's `content` bytes (UTF-8
//! JSON), as pushed by the client via `POST /api/sync/push` with
//! `category: "alerts"`. This module is the contract the client piece
//! (`mylittlechart`'s `mlc-app`/`mlc-backend`, plan step 2) must match —
//! this daemon only ever reads it, never writes it.
//!
//! ```json
//! {
//!   "id": 42,
//!   "address": { "exchange": "binance", "symbol": "BTCUSDT", "account_type": "spot" },
//!   "condition": { "kind": "price_cross", "price": 65000.0, "direction": "up" },
//!   "enabled": true,
//!   "created_at": 1735689600000
//! }
//! ```
//!
//! - `id` is the account-scoped id `AccountAlertStore` stamps in
//!   `mylittlechart`'s `mlc-backend/src/alert/store.rs` — NOT a `sync_id`.
//!   The client piece should push one sync item per alert with
//!   `sync_id = format!("alert-{id}")`, so every device converges on one
//!   row per alert through the existing per-item checksum upsert
//!   (`mylittlechart-server`'s `db::sync_push`). This daemon does not
//!   assume any particular `sync_id` shape — it dedups by this `id` field
//!   per account before evaluating (see `eval.rs`), so a transient
//!   multi-device duplicate never double-fires.
//! - `address.account_type` is a free-form string (`"spot"`,
//!   `"futures_isolated"`, …, matching `mlc-core::instrument::AccountType`'s
//!   labels loosely). This daemon only uses it to pick a spot vs. futures
//!   REST endpoint (see `price_source.rs`) — anything it does not
//!   recognise as futures is treated as spot.
//! - `condition.direction` is optional, defaulting to `"either"` (fires on
//!   a cross in either direction — mirrors `AlertCondition::Crossing`).
//!   `"up"`/`"down"` mirror `CrossingUp`/`CrossingDown`.
//! - `enabled` is optional, defaulting to `true`.
//!
//! This shape is a deliberately narrower cousin of `mylittlechart`'s full
//! native `mlc-core::alert::AlertItem` (which also carries `AlertSource`,
//! many more `AlertCondition` variants, trigger modes, transports, and
//! drawing/indicator state) — the server evaluation loop only ever runs
//! Price-source crossing/threshold checks (plan
//! `docs/mlc/plans/alerts-account-wide-and-telegram-delivery-2026-09-06.md`
//! §3, "Server evaluation — Price-source only"), so this is the honest
//! subset, not a mirror, and the two types are NOT interchangeable. This
//! crate cannot depend on `mlc-core` at all — `mylittlechart` and
//! `mylittlechart-server` are separate Cargo workspaces (separate git
//! submodules under `nemo`).

use serde::Deserialize;

/// One parsed `alerts`-category sync item.
#[derive(Debug, Clone, Deserialize)]
pub struct AlertItemWire {
    pub id: u64,
    pub address: AddressWire,
    pub condition: ConditionWire,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Unix timestamp millis. Informational only — this daemon never acts
    /// on it.
    #[serde(default)]
    pub created_at: i64,
}

fn default_enabled() -> bool {
    true
}

/// The instrument this alert watches.
#[derive(Debug, Clone, Deserialize)]
pub struct AddressWire {
    pub exchange: String,
    pub symbol: String,
    #[serde(default)]
    pub account_type: String,
}

/// The condition that fires the alert. Only `price_cross` exists today —
/// see this module's doc for why the server evaluation loop stays a
/// narrow subset of the native `AlertCondition` set.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConditionWire {
    PriceCross {
        price: f64,
        #[serde(default)]
        direction: Direction,
    },
}

/// Which way a price crossing must go to fire. `Either` mirrors
/// `AlertCondition::Crossing`; `Up`/`Down` mirror `CrossingUp`/`CrossingDown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Up,
    Down,
    #[default]
    Either,
}

/// Parse one sync item's `content` bytes as an [`AlertItemWire`].
pub fn parse_alert_item(bytes: &[u8]) -> Result<AlertItemWire, serde_json::Error> {
    serde_json::from_slice(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_documented_shape() {
        let json = br#"{
            "id": 42,
            "address": { "exchange": "binance", "symbol": "BTCUSDT", "account_type": "spot" },
            "condition": { "kind": "price_cross", "price": 65000.0, "direction": "up" },
            "enabled": true,
            "created_at": 1735689600000
        }"#;
        let item = parse_alert_item(json).expect("documented shape must parse");
        assert_eq!(item.id, 42);
        assert_eq!(item.address.exchange, "binance");
        assert_eq!(item.address.symbol, "BTCUSDT");
        assert_eq!(item.address.account_type, "spot");
        assert!(item.enabled);
        assert_eq!(item.created_at, 1735689600000);
        let ConditionWire::PriceCross { price, direction } = item.condition;
        assert_eq!(price, 65000.0);
        assert_eq!(direction, Direction::Up);
    }

    #[test]
    fn direction_and_enabled_default_when_absent() {
        let json = br#"{
            "id": 7,
            "address": { "exchange": "bybit", "symbol": "ETHUSDT" },
            "condition": { "kind": "price_cross", "price": 3000.0 },
            "created_at": 0
        }"#;
        let item = parse_alert_item(json).expect("minimal shape must parse");
        assert!(item.enabled, "enabled must default to true");
        assert_eq!(item.address.account_type, "", "account_type must default to empty");
        let ConditionWire::PriceCross { direction, .. } = item.condition;
        assert_eq!(direction, Direction::Either, "direction must default to Either");
    }

    #[test]
    fn unknown_condition_kind_is_rejected() {
        let json = br#"{
            "id": 1,
            "address": { "exchange": "binance", "symbol": "BTCUSDT" },
            "condition": { "kind": "signal_crossover" },
            "created_at": 0
        }"#;
        assert!(parse_alert_item(json).is_err(), "an unsupported condition kind must not silently parse");
    }

    #[test]
    fn missing_price_is_rejected() {
        let json = br#"{
            "id": 1,
            "address": { "exchange": "binance", "symbol": "BTCUSDT" },
            "condition": { "kind": "price_cross" },
            "created_at": 0
        }"#;
        assert!(parse_alert_item(json).is_err());
    }
}

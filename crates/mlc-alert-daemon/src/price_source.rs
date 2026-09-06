//! Minimal REST last-price fetch — one public ticker endpoint per
//! exchange, no auth (public market data only), with a per-instrument
//! in-memory cache that also acts as the rate limiter (a fresh cache hit
//! skips the network call entirely). This is deliberately NOT a v5
//! connector (`.claude/rules/v5-connectors.md`'s trait+auth module shape is
//! for authenticated trading connectors); this daemon reads one public
//! price and holds no exchange credentials at all.
//!
//! Exchanges are matched case-insensitively against `AddressWire::exchange`
//! (plan step 4 asks for "the exchanges present in the alerts" — Binance
//! and Bybit today; add a match arm here when another exchange shows up in
//! real alert data, not before).

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use serde::Deserialize;

#[derive(Debug)]
pub enum PriceError {
    UnsupportedExchange(String),
    Http(reqwest::Error),
    /// The exchange answered but the response carried no usable price
    /// (empty ticker list, unparsable price string, unknown symbol).
    NoPrice,
}

impl fmt::Display for PriceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PriceError::UnsupportedExchange(name) => write!(f, "unsupported exchange {name:?}"),
            PriceError::Http(e) => write!(f, "http error: {e}"),
            PriceError::NoPrice => write!(f, "no price in response"),
        }
    }
}

impl std::error::Error for PriceError {}

impl From<reqwest::Error> for PriceError {
    fn from(e: reqwest::Error) -> Self {
        PriceError::Http(e)
    }
}

struct CacheEntry {
    price: f64,
    fetched_at: Instant,
}

/// Per-instrument last-price cache, keyed by `exchange:account_type:symbol`
/// (lowercased/uppercased for stable keys regardless of the caller's
/// casing). Held for the lifetime of the process in `EvalState` — shared
/// across every alert that targets the same instrument, so N alerts on one
/// symbol cost one network call per `min_refetch` window, not N.
pub struct PriceCache {
    entries: HashMap<String, CacheEntry>,
    min_refetch: Duration,
}

impl PriceCache {
    pub fn new(min_refetch: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            min_refetch,
        }
    }

    fn cache_key(exchange: &str, account_type: &str, symbol: &str) -> String {
        format!(
            "{}:{}:{}",
            exchange.to_ascii_lowercase(),
            account_type.to_ascii_lowercase(),
            symbol.to_ascii_uppercase()
        )
    }

    fn fresh(&self, key: &str) -> Option<f64> {
        self.entries
            .get(key)
            .filter(|entry| entry.fetched_at.elapsed() < self.min_refetch)
            .map(|entry| entry.price)
    }

    /// Last price for `exchange`/`account_type`/`symbol`, from cache if
    /// still fresh, otherwise fetched over the network and cached.
    pub async fn last_price(
        &mut self,
        client: &reqwest::Client,
        exchange: &str,
        account_type: &str,
        symbol: &str,
    ) -> Result<f64, PriceError> {
        let key = Self::cache_key(exchange, account_type, symbol);
        if let Some(price) = self.fresh(&key) {
            return Ok(price);
        }
        let price = fetch_last_price(client, exchange, account_type, symbol).await?;
        self.entries.insert(
            key,
            CacheEntry {
                price,
                fetched_at: Instant::now(),
            },
        );
        Ok(price)
    }
}

/// Whether `account_type` names a futures account (as opposed to spot).
/// Matches both the full `mlc-core::instrument::AccountType` variant names
/// and their short labels, case-insensitively — the wire shape's
/// `account_type` is a free-form string (see `alert_item.rs`'s module doc).
fn is_futures(account_type: &str) -> bool {
    matches!(
        account_type.to_ascii_lowercase().as_str(),
        // "f" / "fi" are what the client actually sends: mlc-core's
        // `AccountType::as_label()` → FuturesCross = "F", FuturesIsolated = "FI"
        // (the sync item carries `account_type().as_label()`).
        "futures" | "futurescross" | "futuresisolated" | "futures_cross" | "futures_isolated" | "f" | "fc" | "fi"
    )
}

async fn fetch_last_price(
    client: &reqwest::Client,
    exchange: &str,
    account_type: &str,
    symbol: &str,
) -> Result<f64, PriceError> {
    match exchange.to_ascii_lowercase().as_str() {
        "binance" => fetch_binance(client, account_type, symbol).await,
        "bybit" => fetch_bybit(client, account_type, symbol).await,
        other => Err(PriceError::UnsupportedExchange(other.to_string())),
    }
}

#[derive(Deserialize)]
struct BinanceTicker {
    price: String,
}

async fn fetch_binance(client: &reqwest::Client, account_type: &str, symbol: &str) -> Result<f64, PriceError> {
    let base = if is_futures(account_type) {
        "https://fapi.binance.com/fapi/v1/ticker/price"
    } else {
        "https://api.binance.com/api/v3/ticker/price"
    };
    let ticker: BinanceTicker = client
        .get(base)
        .query(&[("symbol", symbol)])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    ticker.price.parse::<f64>().map_err(|_| PriceError::NoPrice)
}

#[derive(Deserialize)]
struct BybitTickerResponse {
    result: BybitResult,
}

#[derive(Deserialize)]
struct BybitResult {
    list: Vec<BybitTicker>,
}

#[derive(Deserialize)]
struct BybitTicker {
    #[serde(rename = "lastPrice")]
    last_price: String,
}

async fn fetch_bybit(client: &reqwest::Client, account_type: &str, symbol: &str) -> Result<f64, PriceError> {
    let category = if is_futures(account_type) { "linear" } else { "spot" };
    let resp: BybitTickerResponse = client
        .get("https://api.bybit.com/v5/market/tickers")
        .query(&[("category", category), ("symbol", symbol)])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let ticker = resp.result.list.into_iter().next().ok_or(PriceError::NoPrice)?;
    ticker.last_price.parse::<f64>().map_err(|_| PriceError::NoPrice)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_futures_recognises_both_full_and_short_labels() {
        assert!(is_futures("FuturesCross"));
        assert!(is_futures("futures_isolated"));
        assert!(is_futures("FI"));
        assert!(!is_futures("spot"));
        assert!(!is_futures(""));
        assert!(!is_futures("Margin"));
    }

    #[test]
    fn cache_key_normalises_case() {
        assert_eq!(
            PriceCache::cache_key("Binance", "Spot", "btcusdt"),
            PriceCache::cache_key("binance", "spot", "BTCUSDT")
        );
    }
}

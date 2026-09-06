//! Evaluation loop — every `poll_interval`, for each account that has at
//! least one `alerts`-category sync item: gate the account (paid AND
//! tg-linked, see `gate.rs`), then for each of its enabled price-cross
//! alerts, fetch the instrument's last price, run the stateless crossing
//! check (`crossing.rs`) against the previous sample this process has
//! observed, and on a crossing send a Telegram DM (`telegram.rs`) plus
//! record `last_fired_at` (`store.rs`).
//!
//! Non-Price sources and every `AlertCondition` other than a plain
//! crossing/threshold are out of scope here (plan §3, "Server evaluation —
//! Price-source only") — the wire shape (`alert_item.rs`) has no room to
//! express them at all, so there is nothing to branch on.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use rusqlite::Connection;
use tokio::sync::Mutex;

use crate::alert_item::{AlertItemWire, ConditionWire};
use crate::crossing;
use crate::gate::{self, Gate};
use crate::health::DaemonStats;
use crate::identity_db;
use crate::price_source::PriceCache;
use crate::store;
use crate::telegram;

/// Everything one evaluation cycle needs, shared across the whole process
/// lifetime. `identity_conn`/`store_conn` use `tokio::sync::Mutex` (never
/// `std::sync::Mutex`) because both are held across `.await` points inside
/// `run_once`/`evaluate_one` (the HTTP price fetch and Telegram send).
pub(crate) struct EvalState {
    pub identity_conn: Mutex<Connection>,
    pub store_conn: Mutex<Connection>,
    pub http: reqwest::Client,
    pub price_cache: Mutex<PriceCache>,
    /// Previous observed price per alert, keyed by `"{user_id}:{alert_id}"`
    /// — kept per-ALERT rather than per-instrument so that two alerts on
    /// the same symbol with different levels never share a crossing
    /// baseline (unlike [`PriceCache`], which IS shared per instrument to
    /// cut network calls). Reset on process restart — the first
    /// observation after a restart only seeds the baseline, it never
    /// fires (see [`evaluate_one`]).
    pub prev_price: Mutex<HashMap<String, f64>>,
    pub telegram_bot_token: String,
    pub counters: Arc<DaemonStats>,
}

/// Runs one evaluation cycle over every candidate account. Errors surface
/// to the caller (`crate::run`'s ticker loop), which logs them and
/// continues at the next tick — a transient database or network hiccup
/// must not end the process.
pub(crate) async fn run_once(state: &EvalState) -> rusqlite::Result<()> {
    let user_ids = {
        let conn = state.identity_conn.lock().await;
        identity_db::candidate_user_ids(&conn)?
    };

    for user_id in user_ids {
        let (is_paid, tg_chat_id, items) = {
            let conn = state.identity_conn.lock().await;
            let is_paid = identity_db::user_is_paid(&conn, user_id)?;
            let tg_chat_id = identity_db::tg_chat_id_for_user(&conn, user_id)?;
            let items = identity_db::user_alert_items(&conn, user_id)?;
            (is_paid, tg_chat_id, items)
        };

        let chat_id = match gate::evaluate(is_paid, tg_chat_id) {
            Gate::SkippedUnpaid => {
                state.counters.skipped_unpaid.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            Gate::SkippedUnlinked => {
                state.counters.skipped_unlinked.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            Gate::Deliver(chat_id) => chat_id,
        };

        // Dedup by `id` — the same account-wide alert can ride in more than
        // one device-scoped `sync_items` row (see `alert_item.rs`'s module
        // doc). Evaluate each alert exactly once per cycle regardless of
        // how many devices pushed it.
        let mut by_id: HashMap<u64, AlertItemWire> = HashMap::new();
        for item in items {
            by_id.insert(item.id, item);
        }

        for item in by_id.into_values() {
            if !item.enabled {
                continue;
            }
            evaluate_one(state, user_id, chat_id, &item).await;
        }
    }
    Ok(())
}

async fn evaluate_one(state: &EvalState, user_id: i64, chat_id: i64, item: &AlertItemWire) {
    let ConditionWire::PriceCross { price: level, direction } = item.condition;

    let price = {
        let mut cache = state.price_cache.lock().await;
        match cache
            .last_price(&state.http, &item.address.exchange, &item.address.account_type, &item.address.symbol)
            .await
        {
            Ok(price) => price,
            Err(e) => {
                tracing::warn!(
                    "alert {} (user {user_id}): price fetch failed for {}:{}: {e}",
                    item.id,
                    item.address.exchange,
                    item.address.symbol
                );
                return;
            }
        }
    };

    state.counters.checked.fetch_add(1, Ordering::Relaxed);

    let prev_key = format!("{user_id}:{}", item.id);
    let prev = {
        let mut prev_map = state.prev_price.lock().await;
        let prev = prev_map.get(&prev_key).copied();
        prev_map.insert(prev_key, price);
        prev
    };

    // First observation for this alert (fresh item, or first tick after a
    // process restart) — seeds the baseline only, no crossing is possible
    // without a prior sample.
    let Some(prev) = prev else {
        return;
    };

    if !crossing::crosses(direction, prev, price, level) {
        return;
    }

    state.counters.fired.fetch_add(1, Ordering::Relaxed);

    let previously_fired_at = {
        let conn = state.store_conn.lock().await;
        store::last_fired_at(&conn, user_id, item.id).unwrap_or(None)
    };
    tracing::info!(
        "alert {} (user {user_id}, created_at={}) fired: {}:{} crossed {level} (now {price}); last fired at {previously_fired_at:?}",
        item.id,
        item.created_at,
        item.address.exchange,
        item.address.symbol
    );

    let text = format!(
        "\u{1f514} <b>{}</b> {} crossed {level} (now {price})",
        item.address.exchange, item.address.symbol
    );

    match telegram::send_message(&state.http, &state.telegram_bot_token, chat_id, &text).await {
        Ok(()) => {
            state.counters.delivered.fetch_add(1, Ordering::Relaxed);
            let now_ms = chrono::Utc::now().timestamp_millis();
            let conn = state.store_conn.lock().await;
            if let Err(e) = store::mark_fired(&conn, user_id, item.id, now_ms) {
                tracing::error!("failed to record last_fired_at for alert {} (user {user_id}): {e}", item.id);
            }
        }
        Err(e) => {
            tracing::error!("telegram delivery failed for user {user_id} alert {}: {e}", item.id);
        }
    }
}

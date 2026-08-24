//! Watch loop — the automated half of boot-unlock.
//!
//! Every 60s: public `https://mylittlechart.org/health` via reqwest. Two
//! consecutive misses trigger an ssh probe of `box_state`; if the service is
//! waiting for the dbkey / failed / inactive, the same unlock flow as
//! `POST /api/unlock` runs, then public health is re-verified. A 5-minute
//! cooldown after any intervention keeps a wedged box from being hammered.
//!
//! The cooldown is persisted in the `kv` table so a daemon restart does not
//! reset it.

use std::sync::Arc;
use std::time::Duration;

use crate::ops::{self, ServiceState};
use crate::state::{OpsdState, PUBLIC_HEALTH_URL};

const TICK: Duration = Duration::from_secs(60);
const COOLDOWN: Duration = Duration::from_secs(5 * 60);
const MISS_THRESHOLD: u32 = 2;
const KV_LAST_INTERVENTION: &str = "watch_last_intervention";

async fn public_health_ok(state: &Arc<OpsdState>) -> bool {
    match state.http.get(PUBLIC_HEALTH_URL).send().await {
        Ok(resp) => resp.status().is_success(),
        Err(e) => {
            tracing::warn!("public health probe error: {e}");
            false
        }
    }
}

fn cooldown_active(state: &Arc<OpsdState>) -> bool {
    let Some(ts) = state
        .kv_get(KV_LAST_INTERVENTION)
        .and_then(|v| v.parse::<i64>().ok())
    else {
        return false;
    };
    let age = chrono::Utc::now().timestamp() - ts;
    age < COOLDOWN.as_secs() as i64
}

fn mark_intervention(state: &Arc<OpsdState>) {
    state.kv_set(
        KV_LAST_INTERVENTION,
        &chrono::Utc::now().timestamp().to_string(),
    );
}

pub async fn run_watch_loop(state: Arc<OpsdState>) {
    let mut interval = tokio::time::interval(TICK);
    // Skip the immediate first tick — give the daemon a calm startup.
    interval.tick().await;
    let mut misses: u32 = 0;
    loop {
        interval.tick().await;
        if public_health_ok(&state).await {
            if misses > 0 {
                tracing::info!("public health recovered after {misses} miss(es)");
            }
            misses = 0;
            continue;
        }
        misses += 1;
        tracing::warn!("public health miss {misses}/{MISS_THRESHOLD}");
        if misses < MISS_THRESHOLD {
            continue;
        }
        misses = 0;
        if cooldown_active(&state) {
            tracing::warn!("intervention cooldown active — skipping unlock attempt");
            continue;
        }

        let bs = match ops::box_state(&state).await {
            Ok(bs) => bs,
            Err(e) => {
                tracing::error!("box_state probe failed: {e}");
                continue;
            }
        };
        tracing::info!(
            service = %bs.service_raw,
            keyfile_present = bs.keyfile_present,
            waiting_for_key = bs.waiting_for_key,
            "public health down; box state probed"
        );
        let needs_unlock = bs.waiting_for_key
            || matches!(bs.service, ServiceState::Inactive | ServiceState::Failed)
            // Post-reboot state: tmpfs wiped, service stuck in ExecStartPre
            // waiting for the key — systemctl reports "activating".
            || (!bs.keyfile_present && !matches!(bs.service, ServiceState::Active));
        if !needs_unlock {
            // Service is up but public health fails — that is a tunnel/DNS/
            // nginx class problem, not something unlock can fix.
            tracing::error!("service active but public health down — not an unlock case, manual look needed");
            state.audit(
                "watch_skip",
                &format!(
                    "service={} keyfile_present={} waiting={}",
                    bs.service_raw, bs.keyfile_present, bs.waiting_for_key
                ),
            );
            continue;
        }

        mark_intervention(&state);
        match ops::unlock(&state).await {
            Ok(outcome) => {
                let public_ok = public_health_ok(&state).await;
                tracing::info!(
                    unlock_ok = outcome.ok,
                    public_ok,
                    "watch-loop unlock finished"
                );
                state.audit(
                    "watch_unlock",
                    &format!("unlock_ok={} public_ok={public_ok}", outcome.ok),
                );
            }
            Err(e) => {
                tracing::error!("watch-loop unlock failed: {e}");
                state.audit("watch_unlock", &format!("error={e}"));
            }
        }
    }
}

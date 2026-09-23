//! Shared server-to-client live event plumbing (community messenger plan,
//! `docs/mlc/plans/community-messenger-arc-2026-09-24.md` §1.6): one
//! [`LiveRegistry`], generic over a string topic key, so `routes::
//! conversations` (this arc's `GET /api/conversations/{id}/live`, S4 — not
//! built yet) and `routes::rooms` (shared-presets Phase 2's own live sync,
//! `docs/mlc/plans/shared-presets-rights-and-live-sync-2026-09-23.md` §4,
//! also not built yet) can publish into and subscribe from the same
//! registry instead of two parallel implementations. Topic convention (from
//! the messenger plan): `"conversation:{id}"` for this arc,
//! `"room:{kind}:{object_id}"` reserved for shared-presets — disjoint key
//! namespaces in the same map, no collision possible.
//!
//! This module builds the registry and its publish/subscribe API only. The
//! axum SSE handler that turns a [`LiveSubscription`] into an HTTP response
//! (`GET .../live?since=`) is a later piece (plan's S4) — deliberately not
//! built here, so this module adds no new crate dependency (no `dashmap`,
//! no `futures`): everything below rides on `tokio::sync` (already a
//! dependency via the `tokio` crate's `full` feature) and `std::sync`.
//!
//! # Backpressure: bounded PER-SUBSCRIBER queues, not a shared ring buffer
//!
//! Every [`LiveSubscription`] owns its own bounded queue
//! ([`SUBSCRIBER_QUEUE_CAPACITY`] events). [`LiveRegistry::publish`] never
//! awaits and never blocks on a slow subscriber: it takes a short
//! `std::sync::Mutex` per subscriber, and if that subscriber's queue is
//! already full, drops the OLDEST pending event to make room before pushing
//! the new one — logging the drop at `WARN`, naming the subscriber id, its
//! topic, and the dropped event's own kind (`LiveEvent::event`). A
//! `tokio::sync::broadcast` channel was considered instead (it is what the
//! plan sketches) but rejected here: its ring buffer is shared across every
//! subscriber of a topic, and a lagging receiver only learns "N events were
//! lost" after the fact, with no way to say which kind was lost — this
//! module's own per-subscriber queue keeps that information at the moment
//! of the drop, which the "log the drop naming ... the event kind"
//! requirement needs.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

/// One server-to-client event a route publishes onto a live topic. `event`
/// is the SSE frame name a later handler (S4) will send (`"message"`,
/// `"message_edited"`, `"reaction"`, `"typing"`, `"grant_revoked"`, …);
/// `data` is that frame's JSON body.
#[derive(Debug, Clone)]
pub struct LiveEvent {
    pub event: &'static str,
    pub data: serde_json::Value,
}

/// Bound on one subscriber's own pending-event queue — matches the
/// shared-presets plan's own backpressure figure (capacity 32).
const SUBSCRIBER_QUEUE_CAPACITY: usize = 32;

/// One subscriber's shared state: the registry side (`publish`) and the
/// subscriber side ([`LiveSubscription::recv`]) both hold an `Arc` to this;
/// neither ever holds the other's lock across an `.await`.
struct SubscriberState {
    id: u64,
    topic: String,
    queue: Mutex<VecDeque<LiveEvent>>,
    notify: Notify,
    /// Set by [`LiveSubscription`]'s `Drop` impl. [`LiveRegistry::publish`]
    /// prunes closed subscribers opportunistically the next time it visits
    /// their topic — a subscription that never sees another publish after
    /// its handle drops is cleaned up the next time [`LiveRegistry::
    /// subscribe`] or [`LiveRegistry::publish`] touches that same topic.
    closed: AtomicBool,
}

/// Registry of live topics, each with zero or more bounded-queue
/// subscribers. One instance lives on `state.rs::ControlPlane` (`pub live:
/// LiveRegistry`), constructed once at boot.
pub struct LiveRegistry {
    topics: Mutex<HashMap<String, Vec<Arc<SubscriberState>>>>,
    next_subscriber_id: AtomicU64,
}

impl Default for LiveRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LiveRegistry {
    pub fn new() -> Self {
        Self { topics: Mutex::new(HashMap::new()), next_subscriber_id: AtomicU64::new(1) }
    }

    /// Subscribe to `topic`, creating it on first subscribe if it does not
    /// exist yet. Every subscription gets a fresh, empty queue — a
    /// subscriber never sees an event published before it subscribed.
    pub fn subscribe(&self, topic: &str) -> LiveSubscription {
        let id = self.next_subscriber_id.fetch_add(1, Ordering::Relaxed);
        let state = Arc::new(SubscriberState {
            id,
            topic: topic.to_string(),
            queue: Mutex::new(VecDeque::with_capacity(SUBSCRIBER_QUEUE_CAPACITY)),
            notify: Notify::new(),
            closed: AtomicBool::new(false),
        });
        let mut topics = self.topics.lock().unwrap_or_else(|e| e.into_inner());
        let subscribers = topics.entry(topic.to_string()).or_default();
        subscribers.retain(|sub| !sub.closed.load(Ordering::Acquire));
        subscribers.push(Arc::clone(&state));
        LiveSubscription { state }
    }

    /// Publish `event` to every live subscriber of `topic`. A no-op (does
    /// not create the topic) if nobody has ever subscribed to `topic` yet —
    /// there is nothing to publish to and nothing worth remembering. Never
    /// blocks: each subscriber's queue is touched under a short
    /// `std::sync::Mutex`, and a full queue has its oldest entry dropped
    /// (logged) rather than growing or making this call wait.
    pub fn publish(&self, topic: &str, event: LiveEvent) {
        let mut topics = self.topics.lock().unwrap_or_else(|e| e.into_inner());
        let Some(subscribers) = topics.get_mut(topic) else {
            return;
        };
        subscribers.retain(|sub| !sub.closed.load(Ordering::Acquire));
        for sub in subscribers.iter() {
            let mut queue = sub.queue.lock().unwrap_or_else(|e| e.into_inner());
            if queue.len() >= SUBSCRIBER_QUEUE_CAPACITY {
                if let Some(dropped) = queue.pop_front() {
                    tracing::warn!(
                        subscriber_id = sub.id,
                        topic = %sub.topic,
                        dropped_event = dropped.event,
                        capacity = SUBSCRIBER_QUEUE_CAPACITY,
                        "live subscriber queue full — dropping its oldest pending event",
                    );
                }
            }
            queue.push_back(event.clone());
            drop(queue);
            sub.notify.notify_one();
        }
    }

    /// Number of distinct topics this registry currently tracks (live
    /// subscribers or not — see [`Self::publish`]'s doc on why a topic is
    /// never removed just because its subscribers all dropped). Ops
    /// visibility only (e.g. a boot log or a future `/health` counter) —
    /// no route depends on this value.
    pub fn topic_count(&self) -> usize {
        self.topics.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// A live subscription's receiving half — returned by [`LiveRegistry::
/// subscribe`]. Dropping it (e.g. an SSE client disconnecting, in the S4
/// handler that will own one of these) marks the subscriber closed; the
/// registry stops delivering to it and reclaims it on the topic's next
/// `subscribe`/`publish`.
pub struct LiveSubscription {
    state: Arc<SubscriberState>,
}

impl LiveSubscription {
    /// This subscriber's id — stable for the life of the subscription, used
    /// only for logging (see [`LiveRegistry::publish`]'s drop warning).
    pub fn id(&self) -> u64 {
        self.state.id
    }

    pub fn topic(&self) -> &str {
        &self.state.topic
    }

    /// Wait for and return the next event for this subscriber. Never
    /// returns on its own — a subscription stays open until its handle is
    /// dropped (the S4 SSE handler drops it on client disconnect).
    pub async fn recv(&mut self) -> LiveEvent {
        loop {
            // Register interest BEFORE checking the queue, so an event
            // published between the check and the `.await` below is never
            // missed (the standard `Notify` "check-then-wait" idiom).
            let notified = self.state.notify.notified();
            {
                let mut queue = self.state.queue.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(event) = queue.pop_front() {
                    return event;
                }
            }
            notified.await;
        }
    }
}

impl Drop for LiveSubscription {
    fn drop(&mut self) {
        self.state.closed.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: &'static str) -> LiveEvent {
        LiveEvent { event: kind, data: serde_json::json!({ "k": kind }) }
    }

    #[tokio::test]
    async fn subscribe_then_publish_delivers_on_the_same_topic_only() {
        let registry = LiveRegistry::new();
        let mut sub_a = registry.subscribe("conversation:1");
        let mut sub_b = registry.subscribe("conversation:2");

        registry.publish("conversation:1", event("message"));

        let got = sub_a.recv().await;
        assert_eq!(got.event, "message");

        // The other topic's subscriber never sees it.
        registry.publish("conversation:2", event("typing"));
        let got_b = sub_b.recv().await;
        assert_eq!(got_b.event, "typing");
    }

    #[tokio::test]
    async fn publish_before_subscribe_is_not_delivered_to_a_later_subscriber() {
        let registry = LiveRegistry::new();
        registry.publish("conversation:1", event("message"));
        let mut sub = registry.subscribe("conversation:1");
        registry.publish("conversation:1", event("typing"));
        let got = sub.recv().await;
        assert_eq!(got.event, "typing");
    }

    #[tokio::test]
    async fn publish_with_no_subscribers_is_a_harmless_no_op() {
        let registry = LiveRegistry::new();
        // No subscriber has ever touched this topic — must not panic, must
        // not create unbounded state.
        registry.publish("conversation:404", event("message"));
        let topics = registry.topics.lock().unwrap_or_else(|e| e.into_inner());
        assert!(!topics.contains_key("conversation:404"));
    }

    #[tokio::test]
    async fn a_full_subscriber_queue_drops_the_oldest_event_and_keeps_the_newest() {
        let registry = LiveRegistry::new();
        let mut sub = registry.subscribe("conversation:1");

        for i in 0..(SUBSCRIBER_QUEUE_CAPACITY + 5) {
            registry.publish("conversation:1", LiveEvent { event: "message", data: serde_json::json!({ "i": i }) });
        }

        // The queue never grew past its cap, and the oldest 5 were dropped
        // — the first delivered event is #5, not #0.
        let first = sub.recv().await;
        assert_eq!(first.data["i"], 5);

        let mut count = 1;
        loop {
            let queue_len = {
                let state = &sub.state;
                let q = state.queue.lock().unwrap_or_else(|e| e.into_inner());
                q.len()
            };
            if queue_len == 0 {
                break;
            }
            sub.recv().await;
            count += 1;
        }
        assert_eq!(count, SUBSCRIBER_QUEUE_CAPACITY);
    }

    #[tokio::test]
    async fn dropping_a_subscription_lets_the_registry_reclaim_it_on_the_next_touch() {
        let registry = LiveRegistry::new();
        let sub = registry.subscribe("conversation:1");
        assert!(sub.id() > 0);
        drop(sub);

        // Publishing after the only subscriber dropped must not panic, and
        // a fresh subscribe on the same topic must not see the dead entry
        // linger forever (pruned opportunistically).
        registry.publish("conversation:1", event("message"));
        let _new_sub = registry.subscribe("conversation:1");
        let topics = registry.topics.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(topics.get("conversation:1").map(|v| v.len()), Some(1));
    }
}

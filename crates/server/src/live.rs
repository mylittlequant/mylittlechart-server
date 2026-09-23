//! Wake-only long-poll plumbing for `GET /_matrix/client/v3/sync`
//! (`docs/mlc/plans/messenger-proto-server-matrix-subset-2026-09-24.md`
//! §3.1) plus the in-memory typing registry §3.6 needs. Superseded design:
//! this module used to hand every subscriber its own bounded payload queue
//! (`LiveEvent`/`SubscriberState`/`SUBSCRIBER_QUEUE_CAPACITY`) — that shape
//! fit a push/SSE model this codebase no longer builds. The `/sync` model
//! is pull, not push: a client polls with `since=<token>`, the server
//! blocks up to `timeout` for something new, and on wake it **always
//! rebuilds the response from `messenger.db`** rather than replaying
//! whatever was queued. That single fact is why this registry carries no
//! payloads at all — there is nothing to drop under backpressure, and a
//! burst of ten writes against the same key coalesces into exactly one
//! rebuilt response, not ten queued frames.
//!
//! # `LiveRegistry` — one `Notify` + one generation counter per key
//!
//! Every key (this arc's convention: `"user:{user_id}"`, one `/sync`
//! long-poll loop per signed-in user; a later shared-presets live sync can
//! use its own disjoint key namespace — nothing here is messenger-specific)
//! maps to a `u64` generation counter and a `tokio::sync::Notify`. A write
//! handler calls [`LiveRegistry::wake`]/[`LiveRegistry::wake_many`] once its
//! `messenger.db` commit has returned (never while still holding the
//! connection mutex); a long-poll loop calls [`LiveRegistry::wait_for_change`].
//!
//! The one subtlety `tokio::sync::Notify::notify_waiters` has, and the
//! entire reason this module carries a generation counter instead of a bare
//! `Notify`: `notify_waiters` has no memory. If it fires while nobody has a
//! `Notified` future registered, that wake is gone — the next `notified()`
//! call has to wait for a *later* `notify_waiters`/`notify_one` call, it
//! never sees the one it missed. A naive "check the DB, then `.await` a
//! fresh `notified()`" loop can miss a write that lands in exactly that gap.
//! The generation counter closes it: [`LiveRegistry::wait_for_change`]
//! creates its `Notified` future and calls `enable()` on it (registering it
//! with `Notify` immediately, before doing anything else — this is the
//! stdlib-recommended way to register interest from synchronous code, see
//! `tokio::sync::Notify`'s own docs on `enable()`), and only *then* compares
//! the current generation against the value the caller observed before its
//! own DB read. If a wake already bumped the generation in that window, the
//! call returns [`WaitOutcome::Woken`] immediately without ever needing the
//! `Notify` to fire — the wake is never lost, even though `notify_waiters`
//! itself has no memory of it.
//!
//! # Pruning — an entry only exists while someone is waiting on it
//!
//! [`LiveRegistry::wake`]/[`LiveRegistry::wake_many`] are a no-op for a key
//! nobody has ever called [`LiveRegistry::wait_for_change`] on — there is no
//! generation counter to bump and no waiter to notify, and creating one
//! just to immediately have zero waiters would be the unbounded-growth
//! trap this design has to avoid (a room with hundreds of members would
//! otherwise mint one entry per member per write, most of whom are not
//! currently blocked in `/sync` at all). The only method that creates an
//! entry is `wait_for_change`, and it removes its own entry once it is the
//! last waiter leaving (checked again under the lock right before removal,
//! so a new waiter that registers in the meantime keeps the entry alive
//! instead of racing the removal). The result: the map can never hold more
//! entries than there are concurrently blocked `wait_for_change` calls.
//!
//! One accepted consequence: a key's generation counter resets to 0 when
//! its entry is pruned and later recreated. This cannot lose a write —
//! `/sync`'s response is always rebuilt from `messenger.db`, which already
//! has the write durably committed by the time any wake was ever sent for
//! it — it can, in the narrowest case (a `wake` landing in the brief window
//! between an entry's last waiter leaving and a new call recreating it),
//! cost that one still-waiting caller the rest of its own poll `timeout`
//! before it naturally rebuilds and sees the same data anyway. That is a
//! bounded latency cost, never a dropped event, so it is not worth an extra
//! `#[cfg]`-free background sweep task or an LRU to close.
//!
//! # `TypingRegistry` — the one ephemeral fact never written to `messenger.db`
//!
//! Typing indicators are the spec-sanctioned exception to "everything is
//! re-derived from the DB": they are meaningless after a restart and would
//! be pure write load for a fact that expires client-side within seconds
//! anyway (§3.6). `TypingRegistry` is a plain in-memory
//! `room_id -> user_id -> state` map, no relation to `LiveRegistry`'s keys —
//! callers combine the two themselves (flip a typing flag, then call
//! `LiveRegistry::wake_many` for the affected room's members using their
//! own `"user:{id}"` keys). Every accessor takes an explicit `now: Instant`
//! instead of reading the clock itself, so callers (and this module's own
//! tests) get a single, consistent notion of "now" per call without needing
//! `tokio::time::pause`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

/// One key's shared wake state: a generation counter bumped by every
/// [`LiveRegistry::wake`], the `Notify` that wakes any registered
/// [`LiveRegistry::wait_for_change`] call, and a live-waiter count used
/// purely to decide when this entry can be pruned (see the module doc).
struct KeyEntry {
    notify: Notify,
    generation: AtomicU64,
    waiters: AtomicUsize,
}

/// What a [`LiveRegistry::wait_for_change`] call resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// The key's generation moved — either observed immediately (it had
    /// already moved before this call finished registering) or via an
    /// actual `Notify` wake while waiting.
    Woken,
    /// `timeout` elapsed with no generation change.
    TimedOut,
}

/// Registry of wake-only long-poll keys. One instance lives on
/// `state.rs::ControlPlane` (`pub live: LiveRegistry`), constructed once at
/// boot. See the module doc for the design this replaces and why.
pub struct LiveRegistry {
    keys: Mutex<HashMap<String, Arc<KeyEntry>>>,
}

impl Default for LiveRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LiveRegistry {
    pub fn new() -> Self {
        Self { keys: Mutex::new(HashMap::new()) }
    }

    /// `key`'s current generation, or `0` if nobody has ever waited on it
    /// (see the module doc's pruning policy — that is indistinguishable
    /// from "an entry exists and nothing has woken it yet", which is
    /// exactly the value a fresh [`Self::wait_for_change`] call also starts
    /// from). Callers read this BEFORE re-deriving their own state (e.g. a
    /// `messenger.db` query) and pass it back into [`Self::wait_for_change`]
    /// so a wake landing in between is never silently missed.
    pub fn generation(&self, key: &str) -> u64 {
        let keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        keys.get(key).map(|entry| entry.generation.load(Ordering::Acquire)).unwrap_or(0)
    }

    /// Bump `key`'s generation and wake every current waiter via
    /// `notify_waiters` (not `notify_one` — every device/tab of the same
    /// user waiting on the same key must all wake). A no-op if nobody has
    /// ever called [`Self::wait_for_change`] on `key` — see the module doc
    /// on why that is safe and deliberate, not a missed wake.
    pub fn wake(&self, key: &str) {
        let keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = keys.get(key) {
            entry.generation.fetch_add(1, Ordering::AcqRel);
            entry.notify.notify_waiters();
        }
    }

    /// [`Self::wake`] every key in `keys_to_wake` — the shape every write
    /// handler's own affected-user-set fan-out actually calls (§3.1).
    pub fn wake_many(&self, keys_to_wake: impl IntoIterator<Item = String>) {
        for key in keys_to_wake {
            self.wake(&key);
        }
    }

    /// Wait for `key`'s generation to move past `seen_generation`, or for
    /// `timeout` to elapse. Registers with `key`'s `Notify` before checking
    /// the generation (see the module doc's "no memory" note on
    /// `notify_waiters`) so a wake racing this call is never lost; prunes
    /// its own entry if it is the last waiter to leave.
    pub async fn wait_for_change(
        &self,
        key: &str,
        seen_generation: u64,
        timeout: Duration,
    ) -> WaitOutcome {
        let entry = {
            let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
            Arc::clone(keys.entry(key.to_string()).or_insert_with(|| {
                Arc::new(KeyEntry {
                    notify: Notify::new(),
                    generation: AtomicU64::new(0),
                    waiters: AtomicUsize::new(0),
                })
            }))
        };
        entry.waiters.fetch_add(1, Ordering::AcqRel);

        // Register interest and enable it BEFORE re-checking the
        // generation — the standard `Notify` check-then-register idiom for
        // a condition that is itself checked synchronously.
        let notified = entry.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        let outcome = if entry.generation.load(Ordering::Acquire) != seen_generation {
            WaitOutcome::Woken
        } else {
            match tokio::time::timeout(timeout, notified).await {
                Ok(()) => WaitOutcome::Woken,
                Err(_) => WaitOutcome::TimedOut,
            }
        };

        // Last waiter leaving prunes the entry — re-checked under the lock
        // so a waiter that registered in the gap keeps it alive instead of
        // racing this removal (see the module doc).
        if entry.waiters.fetch_sub(1, Ordering::AcqRel) == 1 {
            let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(current) = keys.get(key) {
                if Arc::ptr_eq(current, &entry) && current.waiters.load(Ordering::Acquire) == 0 {
                    keys.remove(key);
                }
            }
        }

        outcome
    }

    /// Number of keys currently tracked — always equal to the number of
    /// distinct keys with at least one live [`Self::wait_for_change`] call
    /// blocked on them right now (see the module doc's pruning policy).
    /// Ops visibility only (a boot log today) — no route depends on it.
    pub fn key_count(&self) -> usize {
        self.keys.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// A repeat `typing: true` PUT for the same `(room, user)` inside this
/// window is throttled — accepted independently of the IP rate limiter
/// (§3.6/§3.8), so a chatty client cannot force a wake on every keystroke.
const TYPING_THROTTLE_WINDOW: Duration = Duration::from_secs(3);

/// A client-supplied typing timeout above this is clamped down to it.
const TYPING_MAX_TIMEOUT_MS: u64 = 30_000;

/// One `(room, user)`'s typing state: `expires_at` is when a currently-true
/// typing flag auto-clears; `is_active` caches whether this user currently
/// counts as typing (kept in sync by every touch and by the lazy reap, so a
/// membership transition is detected exactly once); `last_true_accepted_at`
/// is `None` until the first accepted `typing: true`, purely for the
/// throttle above — a `typing: false` never touches it.
struct TypingUserState {
    expires_at: Instant,
    is_active: bool,
    last_true_accepted_at: Option<Instant>,
}

/// One room's typing state plus a serial bumped on every EFFECTIVE change
/// (a user starting or stopping counting as typing) — a refreshed-but-still-
/// active `typing: true`, or a throttled repeat, bumps nothing, since
/// nothing about what a peer would see has changed.
#[derive(Default)]
struct RoomTyping {
    users: HashMap<i64, TypingUserState>,
    serial: u64,
}

/// Marks every entry in `room` whose typing flag has timed out as no
/// longer active (bumping `room.serial` once if at least one did), then
/// drops entries that are both inactive and outside the throttle memory
/// window (nothing left worth remembering). Returns whether the serial
/// bumped, so callers can report "this room's typing set just changed"
/// without the caller re-deriving it.
fn reap_room(room: &mut RoomTyping, now: Instant) -> bool {
    let mut bumped = false;
    for state in room.users.values_mut() {
        if state.is_active && state.expires_at <= now {
            state.is_active = false;
            bumped = true;
        }
    }
    if bumped {
        room.serial += 1;
    }
    room.users.retain(|_, state| {
        state.is_active
            || state
                .last_true_accepted_at
                .is_some_and(|last| now.saturating_duration_since(last) <= TYPING_THROTTLE_WINDOW)
    });
    bumped
}

/// In-memory, per-room typing indicator state (§3.6) — deliberately never
/// written to `messenger.db` (see the module doc). Not related to
/// [`LiveRegistry`]'s own keys; a caller that gets `changed == true` back
/// from [`Self::set_typing`] (or a non-empty room list back from
/// [`Self::rooms_with_expired_typing`]) is the one that decides which
/// `LiveRegistry` keys to wake for it.
pub struct TypingRegistry {
    rooms: Mutex<HashMap<String, RoomTyping>>,
}

impl Default for TypingRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TypingRegistry {
    pub fn new() -> Self {
        Self { rooms: Mutex::new(HashMap::new()) }
    }

    /// Apply one `PUT /rooms/{roomId}/typing/{userId}` call. `timeout_ms`
    /// (only meaningful when `typing == true`) is clamped to
    /// [`TYPING_MAX_TIMEOUT_MS`]. Returns whether this call actually
    /// changed who counts as typing in `room_id` — `false` for a throttled
    /// repeat `true` (§3.6), a refresh of an already-active `true`, or a
    /// `false` for a user who was not counted as typing — callers should
    /// skip waking anyone when this returns `false`.
    pub fn set_typing(
        &self,
        room_id: &str,
        user_id: i64,
        typing: bool,
        timeout_ms: u64,
        now: Instant,
    ) -> bool {
        let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
        let room = rooms.entry(room_id.to_string()).or_default();

        let changed = if typing {
            let timeout = Duration::from_millis(timeout_ms.min(TYPING_MAX_TIMEOUT_MS));
            let state = room.users.entry(user_id).or_insert_with(|| TypingUserState {
                expires_at: now,
                is_active: false,
                last_true_accepted_at: None,
            });
            let throttled = state
                .last_true_accepted_at
                .is_some_and(|last| now.saturating_duration_since(last) < TYPING_THROTTLE_WINDOW);
            if throttled {
                false
            } else {
                state.last_true_accepted_at = Some(now);
                state.expires_at = now + timeout;
                let was_active = state.is_active;
                state.is_active = true;
                !was_active
            }
        } else {
            match room.users.get_mut(&user_id) {
                Some(state) if state.is_active => {
                    state.is_active = false;
                    state.expires_at = now;
                    true
                }
                _ => false,
            }
        };

        if changed {
            room.serial += 1;
        }
        changed
    }

    /// Current (non-expired) typers in `room_id`, sorted for a deterministic
    /// response — expired entries are dropped lazily as a side effect.
    /// Empty (including for a room this registry has never heard of) rather
    /// than an error — matches `m.typing`'s own "no event at all if nobody
    /// is typing" convention (§3.6).
    pub fn typing_users(&self, room_id: &str, now: Instant) -> Vec<i64> {
        let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
        let mut users = Vec::new();
        let mut room_now_empty = false;
        if let Some(room) = rooms.get_mut(room_id) {
            reap_room(room, now);
            users.extend(room.users.iter().filter(|(_, state)| state.is_active).map(|(id, _)| *id));
            room_now_empty = room.users.is_empty();
        }
        if room_now_empty {
            rooms.remove(room_id);
        }
        users.sort_unstable();
        users
    }

    /// `room_id`'s current typing serial — bumped on every effective change
    /// (§3.6's "for the sync token's typing part"); `0` for a room this
    /// registry has never heard of. Reaps expired entries first, so this is
    /// never stale relative to `now`.
    pub fn typing_serial(&self, room_id: &str, now: Instant) -> u64 {
        let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
        let mut serial = 0;
        let mut room_now_empty = false;
        if let Some(room) = rooms.get_mut(room_id) {
            reap_room(room, now);
            serial = room.serial;
            room_now_empty = room.users.is_empty();
        }
        if room_now_empty {
            rooms.remove(room_id);
        }
        serial
    }

    /// Sweep every room, reaping any typing flag that has timed out since
    /// it was last touched, and return the `room_id`s whose typing set
    /// changed as a result. A periodic tick (or the `/sync` path itself)
    /// calls this and wakes the returned rooms' members — without it, a
    /// member who stops typing and never sends another `/sync`-triggering
    /// action would never have their typing flag cleared for anyone
    /// currently blocked in a long poll.
    pub fn rooms_with_expired_typing(&self, now: Instant) -> Vec<String> {
        let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
        let mut changed = Vec::new();
        rooms.retain(|room_id, room| {
            if reap_room(room, now) {
                changed.push(room_id.clone());
            }
            !room.users.is_empty()
        });
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- LiveRegistry -------------------------------------------------

    #[tokio::test]
    async fn waking_one_user_key_does_not_wake_a_different_users_waiter() {
        let registry = Arc::new(LiveRegistry::new());

        let r1 = Arc::clone(&registry);
        let user1 = tokio::spawn(async move {
            r1.wait_for_change("user:1", 0, Duration::from_secs(5)).await
        });
        let r2 = Arc::clone(&registry);
        let user2 = tokio::spawn(async move {
            r2.wait_for_change("user:2", 0, Duration::from_millis(50)).await
        });

        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        registry.wake("user:1");

        assert_eq!(user1.await.expect("user1 task"), WaitOutcome::Woken);
        assert_eq!(user2.await.expect("user2 task"), WaitOutcome::TimedOut);
    }

    #[tokio::test]
    async fn two_concurrent_waiters_on_the_same_key_both_wake_on_one_notify_waiters_call() {
        let registry = Arc::new(LiveRegistry::new());

        let r1 = Arc::clone(&registry);
        let waiter1 = tokio::spawn(async move {
            r1.wait_for_change("user:1", 0, Duration::from_secs(5)).await
        });
        let r2 = Arc::clone(&registry);
        let waiter2 = tokio::spawn(async move {
            r2.wait_for_change("user:1", 0, Duration::from_secs(5)).await
        });

        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        registry.wake("user:1");

        assert_eq!(waiter1.await.expect("waiter1 task"), WaitOutcome::Woken);
        assert_eq!(waiter2.await.expect("waiter2 task"), WaitOutcome::Woken);
    }

    #[tokio::test]
    async fn wait_returns_immediately_when_generation_already_moved() {
        let registry = Arc::new(LiveRegistry::new());

        // Keep one long-lived waiter registered so the key's entry (and its
        // generation counter) survives the wake below instead of being
        // pruned immediately.
        let keep_alive = Arc::clone(&registry);
        let keep_alive_task = tokio::spawn(async move {
            keep_alive.wait_for_change("user:1", 0, Duration::from_secs(5)).await
        });
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }

        let seen = registry.generation("user:1");
        registry.wake("user:1");

        let outcome = tokio::time::timeout(
            Duration::from_secs(1),
            registry.wait_for_change("user:1", seen, Duration::from_secs(5)),
        )
        .await
        .expect("must not hit the outer 1s test timeout — the wake already happened");
        assert_eq!(outcome, WaitOutcome::Woken);

        registry.wake("user:1");
        assert_eq!(keep_alive_task.await.expect("keep_alive task"), WaitOutcome::Woken);
    }

    #[tokio::test]
    async fn a_wake_that_races_ahead_of_the_next_registration_is_not_lost_across_loop_iterations() {
        let registry = Arc::new(LiveRegistry::new());

        let keep_alive = Arc::clone(&registry);
        let keep_alive_task = tokio::spawn(async move {
            keep_alive.wait_for_change("user:1", 0, Duration::from_secs(5)).await
        });
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }

        // Simulate one loop iteration observing `seen`, then a write racing
        // ahead and waking the key BEFORE the loop's next iteration ever
        // calls `wait_for_change` again.
        let seen = registry.generation("user:1");
        registry.wake("user:1");

        // The next iteration's registration must still see it — not lost
        // just because nothing was actively `.await`ing `notified()` yet
        // when `wake` ran.
        let outcome = tokio::time::timeout(
            Duration::from_secs(1),
            registry.wait_for_change("user:1", seen, Duration::from_secs(5)),
        )
        .await
        .expect("the raced-ahead wake must not be lost");
        assert_eq!(outcome, WaitOutcome::Woken);

        registry.wake("user:1");
        assert_eq!(keep_alive_task.await.expect("keep_alive task"), WaitOutcome::Woken);
    }

    #[tokio::test]
    async fn wait_times_out_without_a_wake() {
        let registry = LiveRegistry::new();
        let outcome =
            registry.wait_for_change("user:1", 0, Duration::from_millis(20)).await;
        assert_eq!(outcome, WaitOutcome::TimedOut);
    }

    #[tokio::test]
    async fn idle_keys_are_pruned() {
        let registry = LiveRegistry::new();
        assert_eq!(registry.key_count(), 0);

        let outcome =
            registry.wait_for_change("user:1", 0, Duration::from_millis(20)).await;
        assert_eq!(outcome, WaitOutcome::TimedOut);

        // The only waiter left — nothing should still reference the key.
        assert_eq!(registry.key_count(), 0);
        // A wake on the now-pruned key must stay a harmless no-op.
        registry.wake("user:1");
    }

    // ---- TypingRegistry -------------------------------------------------

    #[test]
    fn typing_registry_throttles_a_repeat_put_inside_three_seconds() {
        let registry = TypingRegistry::new();
        let t0 = Instant::now();

        assert!(registry.set_typing("room:1", 42, true, 5_000, t0));
        assert!(!registry.set_typing("room:1", 42, true, 5_000, t0 + Duration::from_secs(1)));
        assert_eq!(registry.typing_users("room:1", t0 + Duration::from_secs(1)), vec![42]);
    }

    #[test]
    fn typing_registry_auto_expires_after_the_clients_own_timeout() {
        let registry = TypingRegistry::new();
        let t0 = Instant::now();

        assert!(registry.set_typing("room:1", 42, true, 1_000, t0));
        assert_eq!(registry.typing_users("room:1", t0 + Duration::from_millis(500)), vec![42]);
        assert!(registry.typing_users("room:1", t0 + Duration::from_millis(1_500)).is_empty());
    }

    #[test]
    fn typing_serial_bumps_only_on_effective_change() {
        let registry = TypingRegistry::new();
        let t0 = Instant::now();

        assert!(registry.set_typing("room:1", 42, true, 5_000, t0));
        assert_eq!(registry.typing_serial("room:1", t0), 1);

        // Throttled repeat true — no bump.
        assert!(!registry.set_typing("room:1", 42, true, 5_000, t0 + Duration::from_millis(500)));
        assert_eq!(registry.typing_serial("room:1", t0 + Duration::from_millis(500)), 1);

        // Non-throttled refresh of an already-active typer — still no
        // visible change, so still no bump.
        let t1 = t0 + Duration::from_secs(4);
        assert!(!registry.set_typing("room:1", 42, true, 5_000, t1));
        assert_eq!(registry.typing_serial("room:1", t1), 1);

        // Stopping typing IS an effective change.
        assert!(registry.set_typing("room:1", 42, false, 0, t1));
        assert_eq!(registry.typing_serial("room:1", t1), 2);

        // Repeat false while already stopped — no bump.
        assert!(!registry.set_typing("room:1", 42, false, 0, t1));
        assert_eq!(registry.typing_serial("room:1", t1), 2);
    }

    #[test]
    fn rooms_with_expired_typing_reports_and_reaps_a_timed_out_flag() {
        let registry = TypingRegistry::new();
        let t0 = Instant::now();

        assert!(registry.set_typing("room:1", 1, true, 1_000, t0));
        assert!(registry.set_typing("room:2", 2, true, 10_000, t0));

        let t1 = t0 + Duration::from_millis(1_500);
        let changed = registry.rooms_with_expired_typing(t1);
        assert_eq!(changed, vec!["room:1".to_string()]);
        assert!(registry.typing_users("room:1", t1).is_empty());
        assert_eq!(registry.typing_users("room:2", t1), vec![2]);
    }
}

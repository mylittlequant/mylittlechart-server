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
//! # `LiveRegistry` — register interest, THEN read the DB, THEN wait
//!
//! Every key (this arc's convention: `"user:{user_id}"`, one `/sync`
//! long-poll loop per signed-in user; a later shared-presets live sync can
//! use its own disjoint key namespace — nothing here is messenger-specific)
//! maps to a `u64` generation counter and a `tokio::sync::Notify`. A write
//! handler calls [`LiveRegistry::wake`]/[`LiveRegistry::wake_many`] once its
//! `messenger.db` commit has returned (never while still holding the
//! connection mutex).
//!
//! A long-poll loop's own three steps must run in exactly this order:
//! [`LiveRegistry::register`] (creates the key's entry if needed, records
//! this caller as interested, and snapshots the current generation) — THEN
//! its own `messenger.db` read — THEN [`Registration::wait`] on the guard
//! `register` returned. This order is load-bearing, not a style choice: a
//! write-then-wake that lands after `register` but before the DB read is
//! still caught, because `wake` can already see this caller's entry (it was
//! created by `register`, before the DB read ever ran) and `wait` re-checks
//! the generation against the snapshot `register` took. Reading the DB
//! first and only registering afterwards (the shape an earlier version of
//! this module used, collapsed into one `wait_for_change` call) leaves
//! exactly that gap open: a wake landing between the DB read and the
//! registration has no entry to bump yet, is silently dropped, and the
//! caller sleeps out its full poll `timeout` for a message that already
//! landed — unacceptable latency for chat. Splitting "register" from "wait"
//! is what lets registration happen before the DB read while the DB read
//! still happens before any actual blocking.
//!
//! The one subtlety `tokio::sync::Notify::notify_waiters` has, and the
//! reason this module carries a generation counter instead of a bare
//! `Notify`: `notify_waiters` has no memory. If it fires while nobody has a
//! `Notified` future registered, that wake is gone — the next `notified()`
//! call has to wait for a *later* `notify_waiters`/`notify_one` call, it
//! never sees the one it missed. [`Registration::wait`] closes that gap the
//! same way `register` closes the DB-read gap: it creates its `Notified`
//! future and calls `enable()` on it (registering it with `Notify`
//! immediately, before doing anything else — the stdlib-recommended way to
//! register interest from synchronous code, see `tokio::sync::Notify`'s own
//! docs on `enable()`), and only *then* compares the current generation
//! against the value `register` snapshotted. If a wake already bumped the
//! generation by that point, the call returns [`WaitOutcome::Woken`]
//! immediately without ever needing the `Notify` to fire.
//!
//! # Pruning — an entry only exists while a [`Registration`] guard is alive
//!
//! [`LiveRegistry::wake`]/[`LiveRegistry::wake_many`] are a no-op for a key
//! nobody currently holds a [`Registration`] for — there is no generation
//! counter to bump and no waiter to notify, and creating one just to
//! immediately have no interested guard would be the unbounded-growth trap
//! this design has to avoid (a room with hundreds of members would
//! otherwise mint one entry per member per write, most of whom are not
//! currently blocked in `/sync` at all). [`LiveRegistry::register`] is the
//! only method that creates an entry; dropping its returned [`Registration`]
//! decrements that entry's interest count and removes the entry once the
//! count reaches zero (re-checked under the lock right before removal, so a
//! fresh `register` call that lands in the meantime keeps the entry alive
//! instead of racing the removal). The result: the map can never hold more
//! entries than there are currently live `Registration` guards, and —
//! critically, unlike the earlier `wait_for_change`-only shape — an entry
//! exists for a caller's *entire* register-then-read-then-wait span, not
//! just while it happens to be inside the `.await`, so there is no gap left
//! in which a wake can be lost for that caller at all.
//!
//! `register`'s lookup-or-create and its interest increment must happen
//! under the very same lock acquisition (not lookup, unlock, *then*
//! increment) — see [`LiveRegistry::register`]'s own doc for the exact
//! orphaned-registration failure that a separated version of those two
//! steps allows a concurrent `drop` to trigger.
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
//!
//! ## The typing generation is GLOBAL, not per-room
//!
//! P10's `/sync` sync-token binds a `typing_gen` component
//! (`routes::matrix::sync_token`) so a long-poll can tell "this room's
//! typing changed since the client's token" apart from "nothing changed at
//! all" without busy-looping. That only works if every room's serial is
//! drawn from ONE shared counter: comparing a per-room-local counter against
//! a token's single `typing_gen` cannot distinguish "room A ticked to 3
//! before this token was issued" from "room A ticked to 3 after" once a
//! DIFFERENT room B has also been ticking its own separate counter — the
//! numbers alias. [`TypingRegistry`] therefore keeps one `next_gen: AtomicU64`
//! and every EFFECTIVE change (a user starting or stopping counting as
//! typing, including an expiry reap — never a throttled repeat or an
//! already-active refresh) takes its room's new [`RoomTyping::serial`] from
//! that same counter via [`TypingRegistry::next_typing_gen`]. A token's
//! `typing_gen` then means exactly "the global tick count observed at token
//! issuance", and `room.serial > token.typing_gen` correctly identifies
//! every room whose typing set changed since — see
//! [`TypingRegistry::current_typing_gen`]'s own doc for the one accepted
//! limitation (an in-memory counter does not survive a process restart).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

/// Capacity (and per-minute steady rate) of [`ClaimRateLimiter`]'s per-caller
/// bucket — plan P9 brief: "Rate-limit claims per caller (OTK exhaustion
/// attack): e.g. ≤ 100 device claims / minute per caller".
const CLAIM_RATE_CAPACITY: f64 = 100.0;
const CLAIM_RATE_REFILL_PER_SEC: f64 = CLAIM_RATE_CAPACITY / 60.0;

/// Per-caller token bucket for `POST /_matrix/client/v3/keys/claim`'s
/// device-claim rate limit — an OTK-exhaustion-attack guard independent of
/// `ratelimit::RateLimiter` (which buckets by client IP and cannot
/// distinguish two callers behind the same NAT/proxy, nor would it be
/// correct to bucket a per-user API limit by IP in the first place). One
/// bucket per `user_id`, keyed and refilled the same way
/// `ratelimit::TokenBucket` is (that type stays private to its own module —
/// this is a fresh, small implementation of the same math rather than a
/// `pub` reach-through, since a per-IP bucket kind and a per-user claim cost
/// are different enough axes that sharing the type would only add
/// cross-module coupling for a few lines of arithmetic).
pub struct ClaimRateLimiter {
    /// `user_id -> (tokens remaining, last refill instant)`.
    buckets: Mutex<HashMap<i64, (f64, Instant)>>,
}

impl Default for ClaimRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl ClaimRateLimiter {
    pub fn new() -> Self {
        Self { buckets: Mutex::new(HashMap::new()) }
    }

    /// Try to spend `cost` tokens (one per device claimed in a single
    /// `/keys/claim` call) from `user_id`'s bucket. `true` means the whole
    /// call is allowed (and the cost is spent); `false` refuses the WHOLE
    /// call — a batch that would exceed the cap is refused outright, never
    /// partially served, so a caller never has to reconcile which of its
    /// claimed keys "actually landed" against a partial rate-limit refusal.
    pub fn try_consume(&self, user_id: i64, cost: f64, now: Instant) -> bool {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let (tokens, last_refill) = buckets.entry(user_id).or_insert((CLAIM_RATE_CAPACITY, now));
        let elapsed = now.saturating_duration_since(*last_refill).as_secs_f64();
        *tokens = (*tokens + elapsed * CLAIM_RATE_REFILL_PER_SEC).min(CLAIM_RATE_CAPACITY);
        *last_refill = now;
        if *tokens >= cost {
            *tokens -= cost;
            true
        } else {
            false
        }
    }
}

/// One key's shared wake state: a generation counter bumped by every
/// [`LiveRegistry::wake`], the `Notify` that wakes any live
/// [`Registration::wait`] call, and an interest count used purely to decide
/// when this entry can be pruned (see the module doc).
struct KeyEntry {
    notify: Notify,
    generation: AtomicU64,
    interest: AtomicUsize,
}

impl KeyEntry {
    fn new() -> Self {
        Self { notify: Notify::new(), generation: AtomicU64::new(0), interest: AtomicUsize::new(0) }
    }
}

/// What a [`Registration::wait`] call resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// The key's generation moved — either observed immediately (it had
    /// already moved before or during registration) or via an actual
    /// `Notify` wake while waiting.
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

    /// Register interest in `key`, creating its entry if this is the first
    /// live registration for it. Call this BEFORE re-deriving state (e.g. a
    /// `messenger.db` read) — see the module doc for why the order matters.
    /// The returned [`Registration`] snapshots the current generation and
    /// must be kept alive across that read; dropping it releases interest
    /// in `key` and may prune the entry (see the module doc).
    pub fn register(&self, key: &str) -> Registration<'_> {
        // The lookup-or-create AND the interest increment happen under the
        // SAME lock acquisition — not lookup-then-unlock-then-increment.
        // Otherwise a concurrent `Registration::drop` for the last other
        // holder can see this entry's interest still at its pre-increment
        // value, conclude (correctly, at that instant) that it is the last
        // one out, and prune the entry from the map before this call ever
        // gets to increment it — leaving this registration holding a clone
        // of an `Arc<KeyEntry>` that `wake` can no longer reach through the
        // map at all. Incrementing inside the lock closes that: by the time
        // this call releases the lock, either the entry it is holding is
        // guaranteed visible-and-correctly-counted in the map, or (if a
        // concurrent drop's own prune already ran and removed the prior
        // entry first) `or_insert_with` here creates a fresh one that goes
        // straight into the map already counted — never a orphaned clone.
        let entry = {
            let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
            let entry = Arc::clone(keys.entry(key.to_string()).or_insert_with(|| Arc::new(KeyEntry::new())));
            entry.interest.fetch_add(1, Ordering::AcqRel);
            entry
        };
        let seen_generation = entry.generation.load(Ordering::Acquire);
        Registration { registry: self, key: key.to_string(), entry, seen_generation }
    }

    /// Bump `key`'s generation and wake every current waiter via
    /// `notify_waiters` (not `notify_one` — every device/tab of the same
    /// user waiting on the same key must all wake). A no-op if nobody
    /// currently holds a [`Registration`] for `key` — see the module doc on
    /// why that is safe and deliberate, not a missed wake.
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

    /// Number of keys currently tracked — always equal to the number of
    /// distinct keys with at least one live [`Registration`] right now (see
    /// the module doc's pruning policy). Ops visibility only (a boot log
    /// today) — no route depends on it.
    pub fn key_count(&self) -> usize {
        self.keys.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// A live interest registration for one key, returned by
/// [`LiveRegistry::register`]. Keeping this alive is what keeps the key's
/// entry alive — see the module doc for why that must span the caller's own
/// DB read, not just its call to [`Self::wait`].
pub struct Registration<'a> {
    registry: &'a LiveRegistry,
    key: String,
    entry: Arc<KeyEntry>,
    seen_generation: u64,
}

impl Registration<'_> {
    /// Wait for the key's generation to move past what [`LiveRegistry::
    /// register`] observed, or for `timeout` to elapse. Registers with the
    /// key's `Notify` and enables it BEFORE re-checking the generation (see
    /// the module doc's "no memory" note on `notify_waiters`), so a wake
    /// racing this call is never lost.
    pub async fn wait(&self, timeout: Duration) -> WaitOutcome {
        let notified = self.entry.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        if self.entry.generation.load(Ordering::Acquire) != self.seen_generation {
            return WaitOutcome::Woken;
        }
        match tokio::time::timeout(timeout, notified).await {
            Ok(()) => WaitOutcome::Woken,
            Err(_) => WaitOutcome::TimedOut,
        }
    }
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        // Last registration leaving prunes the entry — re-checked under the
        // lock so a fresh `register` call that lands in the gap keeps the
        // entry alive instead of racing this removal (see the module doc).
        if self.entry.interest.fetch_sub(1, Ordering::AcqRel) == 1 {
            let mut keys = self.registry.keys.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(current) = keys.get(&self.key) {
                if Arc::ptr_eq(current, &self.entry) && current.interest.load(Ordering::Acquire) == 0 {
                    keys.remove(&self.key);
                }
            }
        }
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

/// One room's typing state plus a serial stamped from [`TypingRegistry`]'s
/// GLOBAL `next_gen` counter on every EFFECTIVE change (a user starting or
/// stopping counting as typing) — a refreshed-but-still-active `typing:
/// true`, or a throttled repeat, bumps nothing, since nothing about what a
/// peer would see has changed. See the module doc's "The typing generation
/// is GLOBAL, not per-room" section for why this is not a local counter.
#[derive(Default)]
struct RoomTyping {
    users: HashMap<i64, TypingUserState>,
    serial: u64,
}

/// Marks every entry in `room` whose typing flag has timed out as no
/// longer active (stamping `room.serial` from `next_gen` once if at least
/// one did), then drops entries that are both inactive and outside the
/// throttle memory window (nothing left worth remembering). Returns whether
/// the serial bumped, so callers can report "this room's typing set just
/// changed" without the caller re-deriving it.
fn reap_room(room: &mut RoomTyping, now: Instant, next_gen: &AtomicU64) -> bool {
    let mut bumped = false;
    for state in room.users.values_mut() {
        if state.is_active && state.expires_at <= now {
            state.is_active = false;
            bumped = true;
        }
    }
    if bumped {
        room.serial = next_gen.fetch_add(1, Ordering::AcqRel) + 1;
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
    /// The one counter every room's [`RoomTyping::serial`] is stamped from —
    /// see the module doc's "The typing generation is GLOBAL, not per-room"
    /// section.
    next_gen: AtomicU64,
}

impl Default for TypingRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TypingRegistry {
    /// A fresh registry whose typing generation starts at `0` — this
    /// codebase's own tests use this (deterministic small values are easy
    /// to assert against); production boot uses [`Self::with_seed`] instead
    /// (see that constructor's own doc for why).
    pub fn new() -> Self {
        Self::with_seed(0)
    }

    /// A fresh registry whose typing generation starts at `seed` (the FIRST
    /// effective change stamps `seed + 1`, matching [`Self::new`]'s own
    /// "first change stamps 1" behavior when `seed == 0`). Production boot
    /// (`main.rs`) seeds this from the current Unix time in milliseconds —
    /// see the module doc's "The typing generation is GLOBAL, not per-room"
    /// section: an in-memory counter starting at `0` on every restart can
    /// under-report a typing change to a client still holding a
    /// higher-`typing_gen` token from before that restart. Seeding from a
    /// wall-clock reading that only ever increases makes a POST-restart
    /// seed reliably higher than anything a PRE-restart process could ever
    /// have reached (an `AtomicU64` counter incrementing once per typing
    /// change, even at an implausible sustained rate, cannot climb into the
    /// same range as milliseconds-since-1970 within any real process
    /// lifetime) — closing the under-reporting gap [`Self::current_typing_gen`]'s
    /// own doc used to accept as a known limitation.
    pub fn with_seed(seed: u64) -> Self {
        Self { rooms: Mutex::new(HashMap::new()), next_gen: AtomicU64::new(seed) }
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
            room.serial = self.next_gen.fetch_add(1, Ordering::AcqRel) + 1;
        }
        changed
    }

    /// The current global typing generation — every effective typing change
    /// across every room takes its own room's [`RoomTyping::serial`] from
    /// this SAME counter (see the module doc), so "room serial > token's
    /// typing_gen" identifies exactly the rooms whose typing changed since
    /// that token was issued. `0` means no typing change has EVER been
    /// accepted by this registry instance — a fresh boot, or simply an idle
    /// server; a token carrying `typing_gen: 0` (the bare `s{stream_id}`
    /// legacy form `routes::matrix::sync_token` still accepts, or a token
    /// issued before this server ever saw a single typing PUT) never
    /// wrongly suppresses a real future change, since every real change
    /// stamps a value `>= 1`.
    ///
    /// In-memory only, like every other fact this registry holds — a plain
    /// `TypingRegistry::new()` restarts this counter at `0` on every
    /// process restart. Production boot avoids the resulting under-report
    /// risk (a token issued before a restart carrying a `typing_gen` LARGER
    /// than anything a freshly-zeroed registry has assigned yet) by
    /// constructing via [`Self::with_seed`] instead, seeded from a
    /// wall-clock reading that is always higher than any pre-restart value
    /// — see that constructor's own doc.
    pub fn current_typing_gen(&self) -> u64 {
        self.next_gen.load(Ordering::Acquire)
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
            reap_room(room, now, &self.next_gen);
            users.extend(room.users.iter().filter(|(_, state)| state.is_active).map(|(id, _)| *id));
            room_now_empty = room.users.is_empty();
        }
        if room_now_empty {
            rooms.remove(room_id);
        }
        users.sort_unstable();
        users
    }

    /// `room_id`'s current typing serial — stamped from the SAME global
    /// counter [`Self::current_typing_gen`] reads (see the module doc) on
    /// every effective change; `0` for a room this registry has never heard
    /// of, or one whose typing set has never actually changed since boot.
    /// Reaps expired entries first, so this is never stale relative to
    /// `now`. `routes::matrix::sync`'s own per-room condition is `is_initial
    /// || typing_serial(room, now) > token.typing_gen`.
    pub fn typing_serial(&self, room_id: &str, now: Instant) -> u64 {
        let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
        let mut serial = 0;
        let mut room_now_empty = false;
        if let Some(room) = rooms.get_mut(room_id) {
            reap_room(room, now, &self.next_gen);
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
            if reap_room(room, now, &self.next_gen) {
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
        let registry = LiveRegistry::new();
        let w1 = registry.register("user:1");
        let w2 = registry.register("user:2");

        registry.wake("user:1");

        assert_eq!(w1.wait(Duration::from_secs(5)).await, WaitOutcome::Woken);
        assert_eq!(w2.wait(Duration::from_millis(20)).await, WaitOutcome::TimedOut);
    }

    #[tokio::test]
    async fn two_concurrent_waiters_on_the_same_key_both_wake_on_one_notify_waiters_call() {
        let registry = LiveRegistry::new();
        let w1 = registry.register("user:1");
        let w2 = registry.register("user:1");

        // Both `wait` calls must actually be pending (registered on
        // `Notify`, not resolved via the immediate generation-check
        // shortcut) when `wake` fires, to exercise `notify_waiters`
        // reaching more than one registered waiter from one call.
        let (o1, o2, ()) = tokio::join!(w1.wait(Duration::from_secs(5)), w2.wait(Duration::from_secs(5)), async {
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
            registry.wake("user:1");
        });

        assert_eq!(o1, WaitOutcome::Woken);
        assert_eq!(o2, WaitOutcome::Woken);
    }

    #[tokio::test]
    async fn wake_between_register_and_wait_is_not_lost() {
        let registry = LiveRegistry::new();
        let w = registry.register("user:1");

        // Simulate a write + wake landing between the handler's own DB read
        // and its call to `wait` — the exact gap `register`-before-the-
        // read must close (this is the correctness fix over the earlier
        // single-call `wait_for_change` shape, which had no entry to bump
        // in this window).
        registry.wake("user:1");

        let outcome = tokio::time::timeout(Duration::from_millis(50), w.wait(Duration::from_secs(5)))
            .await
            .expect("must resolve immediately — the wake must not be lost");
        assert_eq!(outcome, WaitOutcome::Woken);
    }

    #[tokio::test]
    async fn a_wake_that_races_ahead_of_the_next_registration_is_not_lost_across_loop_iterations() {
        let registry = LiveRegistry::new();

        // Iteration 1: a wake races ahead of `wait`, which must still catch
        // it immediately.
        let w1 = registry.register("user:1");
        registry.wake("user:1");
        assert_eq!(w1.wait(Duration::from_secs(5)).await, WaitOutcome::Woken);
        drop(w1);

        // Iteration 2: a fresh registration after the first guard fully
        // dropped (and its entry was pruned) must not spuriously report the
        // PREVIOUS iteration's already-consumed wake as still pending, and
        // must still correctly catch a NEW wake racing ahead of it.
        let w2 = registry.register("user:1");
        registry.wake("user:1");
        assert_eq!(w2.wait(Duration::from_secs(5)).await, WaitOutcome::Woken);
    }

    #[tokio::test]
    async fn wait_times_out_without_a_wake() {
        let registry = LiveRegistry::new();
        let w = registry.register("user:1");
        assert_eq!(w.wait(Duration::from_millis(20)).await, WaitOutcome::TimedOut);
    }

    #[tokio::test]
    async fn idle_keys_are_pruned() {
        let registry = LiveRegistry::new();
        assert_eq!(registry.key_count(), 0);

        let w = registry.register("user:1");
        assert_eq!(registry.key_count(), 1);
        assert_eq!(w.wait(Duration::from_millis(20)).await, WaitOutcome::TimedOut);
        drop(w);

        assert_eq!(registry.key_count(), 0);
        // A wake on the now-pruned key must stay a harmless no-op.
        registry.wake("user:1");
    }

    #[test]
    fn entry_pruned_after_last_guard_drops() {
        let registry = LiveRegistry::new();
        let w1 = registry.register("user:1");
        let w2 = registry.register("user:1");
        assert_eq!(registry.key_count(), 1);

        drop(w1);
        assert_eq!(registry.key_count(), 1, "w2 is still interested");

        drop(w2);
        assert_eq!(registry.key_count(), 0, "the last guard dropped");
    }

    /// Regression guard for the `register`/`Drop` orphaning race: `register`
    /// must increment interest under the SAME lock acquisition as its
    /// lookup-or-create, not after releasing it (see [`LiveRegistry::
    /// register`]'s doc). `register` and `Drop` are both plain synchronous
    /// functions with no `.await` inside them, so the only way to actually
    /// hit the instruction-level window a wrong implementation would open
    /// is genuine OS-thread parallelism, not cooperative task scheduling —
    /// this spawns real `std::thread`s hammering `register`+immediate-drop
    /// on the SAME key in a tight, uninterrupted loop (no `yield_now`, no
    /// delay — maximizing how often that window is actually contended)
    /// while the test's own task repeatedly does `register` then
    /// immediately `wake` (same-thread, so `wake` always runs after
    /// `register` returns — plain sequential execution needs no extra
    /// synchronization to prove that ordering) and asserts the resulting
    /// `wait` is always `Woken`, never `TimedOut`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn wake_after_register_is_never_lost_under_concurrent_churn() {
        let registry = Arc::new(LiveRegistry::new());
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let churn_threads: Vec<_> = (0..8)
            .map(|_| {
                let registry = Arc::clone(&registry);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        drop(registry.register("user:1"));
                    }
                })
            })
            .collect();

        for _ in 0..5_000 {
            let guard = registry.register("user:1");
            registry.wake("user:1");
            let outcome = guard.wait(Duration::from_millis(20)).await;
            assert_eq!(
                outcome,
                WaitOutcome::Woken,
                "a wake sent right after register() must never be lost to concurrent churn",
            );
        }

        stop.store(true, Ordering::Relaxed);
        for handle in churn_threads {
            handle.join().expect("churn thread");
        }
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
    fn typing_gen_is_global_across_rooms_not_per_room() {
        let registry = TypingRegistry::new();
        let t0 = Instant::now();
        assert_eq!(registry.current_typing_gen(), 0);

        assert!(registry.set_typing("room:1", 1, true, 5_000, t0));
        let gen_after_room1 = registry.current_typing_gen();
        assert_eq!(registry.typing_serial("room:1", t0), gen_after_room1);

        assert!(registry.set_typing("room:2", 2, true, 5_000, t0));
        let gen_after_room2 = registry.current_typing_gen();
        assert!(
            gen_after_room2 > gen_after_room1,
            "a second room's own effective change must take a LATER tick from the SAME global counter"
        );
        assert_eq!(registry.typing_serial("room:2", t0), gen_after_room2);
        // room:1's own serial must be untouched by room:2's unrelated change
        // — this is exactly what lets "serial > token.typing_gen" tell two
        // DIFFERENT rooms' changes apart instead of aliasing them.
        assert_eq!(registry.typing_serial("room:1", t0), gen_after_room1);
    }

    #[test]
    fn typing_gen_seed_is_above_any_pre_restart_value() {
        // Simulate a "pre-restart" process that climbed its own zero-based
        // counter some way up through real typing activity.
        let pre_restart = TypingRegistry::new();
        let t0 = Instant::now();
        assert!(pre_restart.set_typing("room:1", 1, true, 5_000, t0));
        let pre_restart_high_water_mark = pre_restart.current_typing_gen();

        // Production boot seeds the fresh, post-restart registry from a
        // wall-clock reading — modeled here as "obviously higher than
        // anything the old process reached" without depending on real time
        // in a unit test.
        let seed = pre_restart_high_water_mark + 1_000_000;
        let post_restart = TypingRegistry::with_seed(seed);
        assert!(
            post_restart.current_typing_gen() > pre_restart_high_water_mark,
            "a post-restart registry must start above any value the pre-restart process could have reached"
        );

        // A stale token minted by the pre-restart process (typing_gen =
        // `pre_restart_high_water_mark`) must compare as strictly BEHIND
        // the fresh registry even before the fresh registry has seen a
        // single real typing change — this is what makes "room serial >
        // token.typing_gen" correctly report a change to a client still
        // holding that stale token.
        assert!(post_restart.current_typing_gen() > pre_restart_high_water_mark);

        // And the seed itself strictly precedes the FIRST real post-restart
        // change, preserving ordinary monotonic behavior from then on.
        assert!(post_restart.set_typing("room:1", 1, true, 5_000, t0));
        assert!(post_restart.current_typing_gen() > seed);
    }

    // ---- ClaimRateLimiter -------------------------------------------------

    #[test]
    fn keys_claim_is_rate_limited() {
        let limiter = ClaimRateLimiter::new();
        let t0 = Instant::now();

        assert!(limiter.try_consume(1, 100.0, t0), "the full capacity is available up front");
        assert!(!limiter.try_consume(1, 1.0, t0), "the bucket is empty immediately after spending it all");
        assert!(limiter.try_consume(2, 100.0, t0), "a different caller has its own, independent bucket");
    }

    #[test]
    fn claim_rate_limiter_refills_over_time() {
        let limiter = ClaimRateLimiter::new();
        let t0 = Instant::now();
        assert!(limiter.try_consume(1, 100.0, t0));
        assert!(!limiter.try_consume(1, 1.0, t0));

        // One second later, at 100/60 tokens/sec: a little under 2 tokens back.
        let t1 = t0 + Duration::from_secs(1);
        assert!(limiter.try_consume(1, 1.0, t1));
        assert!(!limiter.try_consume(1, 1.0, t1));
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

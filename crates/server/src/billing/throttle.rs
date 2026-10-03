//! In-process sliding-window limiter, keyed by client IP for the two
//! unauthenticated anonymous-account routes (and by account id for the staff
//! routes' per-actor write budget, see `staff.rs`):
//!
//! * `POST /api/billing/anon-checkout` — [`SlidingLimiter::try_acquire`]:
//!   at most N creations per IP per window, and at most M across all IPs;
//! * `POST /api/auth/account-key` and `GET /api/billing/anon-invoice/{id}` —
//!   [`SlidingLimiter::is_blocked`] before looking a key up and
//!   [`SlidingLimiter::record`] on every failure: after N failures an IP is
//!   refused until its oldest failure leaves the window. The routes keep two
//!   further limiters of this same type: the SHA-256 of the presented
//!   credential (five failures an hour for that hash only) and, for an onion
//!   `Host`, one shared flood key instead of the clearnet address. An onion
//!   checkout uses its own single key and does not spend the clearnet
//!   per-IP counter or the clearnet global cap.
//!
//! This sits beside the app-wide token bucket in `ratelimit.rs` (which keeps
//! its own short-burst budget per route class); it exists because these
//! budgets are per HOUR and per route, which a token bucket cannot express.
//! State is per process and lost on restart — acceptable for an abuse brake,
//! not an accounting record.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Above this many tracked IPs, expired entries are swept before the next
/// insert, so a flood of distinct addresses cannot grow the map without bound.
const SWEEP_THRESHOLD: usize = 4096;

struct Inner<K> {
    per_ip: HashMap<K, VecDeque<Instant>>,
    global: VecDeque<Instant>,
}

/// A sliding-window limiter over keys `K`. A limit of `0` means "none" for
/// that scope.
pub struct SlidingLimiter<K> {
    window: Duration,
    per_ip_limit: usize,
    global_limit: usize,
    inner: Mutex<Inner<K>>,
}

fn prune(queue: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while queue.front().is_some_and(|t| now.saturating_duration_since(*t) >= window) {
        queue.pop_front();
    }
}

impl<K: Hash + Eq + Copy> SlidingLimiter<K> {
    /// A limiter allowing `per_ip_limit` hits per key and `global_limit` hits
    /// overall within `window`.
    pub fn new(window: Duration, per_ip_limit: usize, global_limit: usize) -> Self {
        Self {
            window,
            per_ip_limit,
            global_limit,
            inner: Mutex::new(Inner { per_ip: HashMap::new(), global: VecDeque::new() }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner<K>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn sweep(&self, inner: &mut Inner<K>, now: Instant) {
        if inner.per_ip.len() >= SWEEP_THRESHOLD {
            let window = self.window;
            inner.per_ip.retain(|_, queue| {
                prune(queue, now, window);
                !queue.is_empty()
            });
        }
    }

    /// Record a hit for `ip` if neither its own budget nor the global one is
    /// spent; `false` (and nothing recorded) otherwise.
    pub fn try_acquire(&self, ip: K, now: Instant) -> bool {
        let mut inner = self.lock();
        self.sweep(&mut inner, now);
        let window = self.window;
        prune(&mut inner.global, now, window);
        if self.global_limit != 0 && inner.global.len() >= self.global_limit {
            return false;
        }
        let queue = inner.per_ip.entry(ip).or_default();
        prune(queue, now, window);
        if self.per_ip_limit != 0 && queue.len() >= self.per_ip_limit {
            return false;
        }
        queue.push_back(now);
        inner.global.push_back(now);
        true
    }

    /// Whether `ip` has used up its own budget (nothing is recorded).
    pub fn is_blocked(&self, ip: K, now: Instant) -> bool {
        let mut inner = self.lock();
        let window = self.window;
        match inner.per_ip.get_mut(&ip) {
            Some(queue) => {
                prune(queue, now, window);
                self.per_ip_limit != 0 && queue.len() >= self.per_ip_limit
            }
            None => false,
        }
    }

    /// Record a hit for `ip` unconditionally (a failed attempt).
    pub fn record(&self, ip: K, now: Instant) {
        let mut inner = self.lock();
        self.sweep(&mut inner, now);
        let window = self.window;
        let queue = inner.per_ip.entry(ip).or_default();
        prune(queue, now, window);
        queue.push_back(now);
    }

    /// The window, for a `Retry-After` header.
    pub fn window(&self) -> Duration {
        self.window
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    const HOUR: Duration = Duration::from_secs(3600);

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([203, 0, 113, last])
    }

    #[test]
    fn five_per_ip_per_window_then_the_window_slides() {
        let limiter: SlidingLimiter<IpAddr> = SlidingLimiter::new(HOUR, 5, 0);
        let t0 = Instant::now();
        for i in 0..5 {
            assert!(limiter.try_acquire(ip(1), t0 + Duration::from_secs(i)), "hit {i}");
        }
        assert!(!limiter.try_acquire(ip(1), t0 + Duration::from_secs(10)), "the sixth is refused");
        assert!(limiter.try_acquire(ip(2), t0 + Duration::from_secs(10)), "another address has its own budget");
        // Once the first hit is an hour old, exactly one slot is free again.
        assert!(limiter.try_acquire(ip(1), t0 + HOUR));
        assert!(!limiter.try_acquire(ip(1), t0 + HOUR), "and only one");
        // The second hit leaves the window a second later, freeing the next slot.
        assert!(limiter.try_acquire(ip(1), t0 + HOUR + Duration::from_secs(1)));
    }

    #[test]
    fn the_global_cap_binds_across_addresses_and_refused_hits_are_not_counted() {
        let limiter: SlidingLimiter<IpAddr> = SlidingLimiter::new(HOUR, 5, 3);
        let t0 = Instant::now();
        assert!(limiter.try_acquire(ip(1), t0));
        assert!(limiter.try_acquire(ip(2), t0));
        assert!(limiter.try_acquire(ip(3), t0));
        assert!(!limiter.try_acquire(ip(4), t0), "the fourth address is turned away by the global cap");
        assert!(!limiter.try_acquire(ip(1), t0));
        // Nothing was recorded for the refusals: after the window, all three slots are free.
        let later = t0 + HOUR;
        assert!(limiter.try_acquire(ip(4), later));
        assert!(limiter.try_acquire(ip(5), later));
        assert!(limiter.try_acquire(ip(6), later));
        assert!(!limiter.try_acquire(ip(7), later));
    }

    #[test]
    fn a_failure_throttle_blocks_only_after_the_limit_and_only_that_address() {
        let limiter: SlidingLimiter<IpAddr> = SlidingLimiter::new(HOUR, 3, 0);
        let t0 = Instant::now();
        assert!(!limiter.is_blocked(ip(1), t0));
        limiter.record(ip(1), t0);
        limiter.record(ip(1), t0);
        assert!(!limiter.is_blocked(ip(1), t0), "two failures of three");
        limiter.record(ip(1), t0);
        assert!(limiter.is_blocked(ip(1), t0));
        assert!(!limiter.is_blocked(ip(2), t0));
        assert!(!limiter.is_blocked(ip(1), t0 + HOUR), "the failures age out");
    }

    #[test]
    fn the_key_can_be_an_account_id() {
        let limiter: SlidingLimiter<i64> = SlidingLimiter::new(Duration::from_secs(60), 2, 0);
        let t0 = Instant::now();
        assert!(limiter.try_acquire(7, t0) && limiter.try_acquire(7, t0));
        assert!(!limiter.try_acquire(7, t0));
        assert!(limiter.try_acquire(8, t0));
        assert!(limiter.try_acquire(7, t0 + Duration::from_secs(60)));
    }

    #[test]
    fn a_zero_limit_means_unlimited() {
        let limiter: SlidingLimiter<IpAddr> = SlidingLimiter::new(HOUR, 0, 0);
        let t0 = Instant::now();
        for _ in 0..100 {
            assert!(limiter.try_acquire(ip(1), t0));
        }
        assert!(!limiter.is_blocked(ip(1), t0));
    }

    #[test]
    fn a_flood_of_distinct_addresses_is_swept_once_it_has_aged_out() {
        let limiter: SlidingLimiter<IpAddr> = SlidingLimiter::new(HOUR, 5, 0);
        let t0 = Instant::now();
        for n in 0..(SWEEP_THRESHOLD as u32 + 10) {
            assert!(limiter.try_acquire(IpAddr::from(n.to_be_bytes()), t0));
        }
        assert!(limiter.try_acquire(ip(1), t0 + HOUR + Duration::from_secs(1)));
        assert!(limiter.lock().per_ip.len() < SWEEP_THRESHOLD, "aged-out entries were dropped");
    }
}

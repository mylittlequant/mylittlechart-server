//! Per-IP token-bucket rate limiting, in-process.
//!
//! `tower_governor 0.4` is incompatible with axum 0.8 (axum-core version
//! mismatch — see the former note this superseded in `routes/mod.rs`), so
//! this is a small, purpose-built `axum::middleware::from_fn_with_state`
//! middleware layered on the `/api` sub-router (see `main.rs`) rather than a
//! pulled-in crate. Four traffic classes (see [`BucketKind`]), each with its
//! own token bucket per client IP:
//!
//! | Class       | Paths                                                          | Rate     | Burst |
//! |-------------|-----------------------------------------------------------------|----------|-------|
//! | `auth_poll` | `/auth/poll`, `/auth/agent-key/poll`, `/auth/link/poll`, `/auth/tg-login/poll` | 30/min | 10 |
//! | `oauth`     | `/oauth/*`, `/auth/*/init`, `/auth/*/start`                     | 20/min   | 20    |
//! | `api_write` | every other POST/PUT/PATCH/DELETE                                | 120/min | 120   |
//! | `api_read`  | every other GET (and anything not matched above)                 | 600/min | 600   |
//!
//! A refusal answers `429` with an EMPTY body and a `retry-after` header —
//! the exact same shape regardless of which bucket or path triggered it, so
//! a probe cannot tell an admin route apart from a forum route by how its
//! 429 looks (same posture as `routes::admin::admin_not_found`'s bare 404).
//!
//! Client IP resolution: nginx sits in front on both topologies this server
//! runs behind (`ops/nginx-mlc-site.conf`) and always sets `X-Forwarded-For`
//! (`$proxy_add_x_forwarded_for`) — trusted ONLY when the immediate TCP peer
//! is nginx's own reachable address: loopback (single-box deploy) or the
//! WireGuard control-box subnet `10.77.0.0/16` that upstream's own comment
//! names (`upstream mlc_backend { server 10.77.0.1:19200; }`). Any other
//! peer's header is ignored outright — an internet-facing caller cannot
//! claim a different IP than the one that actually opened the connection.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Which bucket a request's (method, path) falls into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum BucketKind {
    AuthPoll,
    Oauth,
    ApiWrite,
    ApiRead,
}

impl BucketKind {
    /// `(capacity, tokens refilled per second)` — capacity is the burst
    /// ceiling; steady-state throughput is `capacity` tokens drained no
    /// faster than they refill.
    fn limits(self) -> (f64, f64) {
        match self {
            BucketKind::AuthPoll => (10.0, 30.0 / 60.0),
            BucketKind::Oauth => (20.0, 20.0 / 60.0),
            BucketKind::ApiWrite => (120.0, 120.0 / 60.0),
            BucketKind::ApiRead => (600.0, 600.0 / 60.0),
        }
    }
}

/// `path` is the request path AS SEEN INSIDE `/api` — this middleware is
/// layered on the sub-router before `.nest("/api", …)` in `main.rs`
/// (mirroring `no_store_api_headers`'s own placement there), so `path`
/// never carries the `/api` prefix itself.
fn classify(path: &str, method: &Method) -> BucketKind {
    const AUTH_POLL_PATHS: [&str; 4] = [
        "/auth/poll",
        "/auth/agent-key/poll",
        "/auth/link/poll",
        "/auth/tg-login/poll",
    ];
    if AUTH_POLL_PATHS.contains(&path) {
        return BucketKind::AuthPoll;
    }
    if path.starts_with("/oauth/")
        || (path.starts_with("/auth/") && (path.ends_with("/init") || path.ends_with("/start")))
    {
        return BucketKind::Oauth;
    }
    match *method {
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE => BucketKind::ApiWrite,
        _ => BucketKind::ApiRead,
    }
}

/// `10.77.0.0/16` — the WireGuard subnet nginx's upstream sits on (see this
/// module's doc). Only a peer connecting FROM this subnet (or loopback) may
/// have its `X-Forwarded-For` trusted at all.
fn is_wireguard_control_subnet(v4: Ipv4Addr) -> bool {
    let [a, b, ..] = v4.octets();
    a == 10 && b == 77
}

fn is_trusted_proxy_peer(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || is_wireguard_control_subnet(v4),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// The first (leftmost) address in `X-Forwarded-For` — by convention the
/// original client, with every intermediate proxy appending its own address
/// after it (`$proxy_add_x_forwarded_for` in nginx).
fn first_forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    let raw = headers.get("x-forwarded-for")?.to_str().ok()?;
    raw.split(',').next()?.trim().parse().ok()
}

/// The address this request is billed against: `X-Forwarded-For`'s first
/// value when (and ONLY when) `peer` is a trusted proxy address, else the
/// TCP peer itself.
fn client_ip(headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    if is_trusted_proxy_peer(peer) {
        if let Some(forwarded) = first_forwarded_for(headers) {
            return forwarded;
        }
    }
    peer
}

/// A classic token bucket: `tokens` accumulate at `refill_per_sec`, capped
/// at `capacity`, and one is spent per allowed request.
#[derive(Debug, Clone, Copy)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
        }
    }

    /// Refill by elapsed time (capped at `capacity`), then try to spend one
    /// token. `true` means the request is allowed.
    fn try_consume(&mut self, capacity: f64, refill_per_sec: f64, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * refill_per_sec).min(capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// One client IP's four buckets, plus when it was last seen — the sweep
/// (see [`RateLimiter::sweep`]) drops entries idle past a threshold so a
/// long-running process never accumulates one entry per IP that ever made
/// one request.
struct IpEntry {
    buckets: HashMap<BucketKind, TokenBucket>,
    last_seen: Instant,
}

/// Shared, process-wide rate limiter — one instance lives in an `Arc` handed
/// to [`rate_limit_middleware`] via `axum::middleware::from_fn_with_state`.
pub struct RateLimiter {
    entries: Mutex<HashMap<IpAddr, IpEntry>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// `true` if `ip` still has a token in `kind`'s bucket (and spends it).
    fn check(&self, ip: IpAddr, kind: BucketKind) -> bool {
        let (capacity, refill_per_sec) = kind.limits();
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries.entry(ip).or_insert_with(|| IpEntry {
            buckets: HashMap::new(),
            last_seen: now,
        });
        entry.last_seen = now;
        let bucket = entry
            .buckets
            .entry(kind)
            .or_insert_with(|| TokenBucket::new(capacity));
        bucket.try_consume(capacity, refill_per_sec, now)
    }

    /// Drop every IP entry idle for more than `idle_after`.
    fn sweep(&self, idle_after: Duration) {
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.retain(|_, entry| now.saturating_duration_since(entry.last_seen) < idle_after);
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Spawn the periodic idle-entry sweep: every 5 minutes, drop any IP whose
/// last request was more than 10 minutes ago. Runs for the process
/// lifetime — an in-memory map with nothing older than 10 minutes in it
/// costs nothing to leave running through the graceful-shutdown drain.
pub fn spawn_sweeper(limiter: Arc<RateLimiter>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5 * 60));
        loop {
            interval.tick().await;
            limiter.sweep(Duration::from_secs(10 * 60));
        }
    });
}

/// The one refusal shape every bucket gives — `429`, empty body, a fixed
/// `retry-after: 60` (every window here is one minute; a precisely computed
/// remainder would not tell the caller anything a 429 doesn't already, same
/// reasoning `routes::forum`'s own rate limit uses for its fixed
/// `retry_after_secs`).
fn too_many_requests() -> Response {
    let mut resp = StatusCode::TOO_MANY_REQUESTS.into_response();
    resp.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from_static("60"),
    );
    resp
}

/// `axum::middleware::from_fn_with_state` handler — layered on `api_router`
/// in `main.rs`, before `.nest("/api", …)`, after the `no_store_api_headers`
/// layer so a 429 answer still carries `cache-control: no-store` (see that
/// call site's comment for why the ordering matters).
pub async fn rate_limit_middleware(
    State(limiter): State<Arc<RateLimiter>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let ip = client_ip(req.headers(), peer.ip());
    let kind = classify(req.uri().path(), req.method());
    if !limiter.check(ip, kind) {
        return too_many_requests();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_allows_up_to_capacity_then_refuses() {
        let mut bucket = TokenBucket::new(3.0);
        let now = Instant::now();
        assert!(bucket.try_consume(3.0, 1.0, now));
        assert!(bucket.try_consume(3.0, 1.0, now));
        assert!(bucket.try_consume(3.0, 1.0, now));
        assert!(!bucket.try_consume(3.0, 1.0, now));
    }

    #[test]
    fn token_bucket_refills_at_the_configured_rate() {
        let mut bucket = TokenBucket::new(2.0);
        let t0 = Instant::now();
        assert!(bucket.try_consume(2.0, 1.0, t0));
        assert!(bucket.try_consume(2.0, 1.0, t0));
        assert!(!bucket.try_consume(2.0, 1.0, t0));

        // One second later, at a refill rate of one token/sec: exactly one
        // token back, no more.
        let t1 = t0 + Duration::from_secs(1);
        assert!(bucket.try_consume(2.0, 1.0, t1));
        assert!(!bucket.try_consume(2.0, 1.0, t1));
    }

    #[test]
    fn token_bucket_never_exceeds_capacity_no_matter_how_long_it_is_idle() {
        let mut bucket = TokenBucket::new(2.0);
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(1_000);
        assert!(bucket.try_consume(2.0, 1.0, t1));
        assert!(bucket.try_consume(2.0, 1.0, t1));
        assert!(!bucket.try_consume(2.0, 1.0, t1));
    }

    #[test]
    fn rate_limiter_tracks_buckets_independently_per_ip() {
        let limiter = RateLimiter::new();
        let a: IpAddr = "203.0.113.1".parse().expect("valid ip");
        let b: IpAddr = "203.0.113.2".parse().expect("valid ip");
        // Exhaust `a`'s oauth bucket (capacity 20) without touching `b`'s.
        for _ in 0..20 {
            assert!(limiter.check(a, BucketKind::Oauth));
        }
        assert!(!limiter.check(a, BucketKind::Oauth));
        assert!(limiter.check(b, BucketKind::Oauth));
    }

    #[test]
    fn rate_limiter_sweep_drops_only_idle_entries() {
        let limiter = RateLimiter::new();
        let ip: IpAddr = "203.0.113.9".parse().expect("valid ip");
        assert!(limiter.check(ip, BucketKind::ApiRead));
        {
            let mut entries = limiter.entries.lock().expect("lock");
            entries.get_mut(&ip).expect("entry exists").last_seen =
                Instant::now() - Duration::from_secs(11 * 60);
        }
        limiter.sweep(Duration::from_secs(10 * 60));
        assert!(!limiter.entries.lock().expect("lock").contains_key(&ip));
    }

    #[test]
    fn classify_routes_auth_polls_into_their_own_bucket() {
        assert_eq!(classify("/auth/poll", &Method::GET), BucketKind::AuthPoll);
        assert_eq!(classify("/auth/agent-key/poll", &Method::GET), BucketKind::AuthPoll);
        assert_eq!(classify("/auth/link/poll", &Method::GET), BucketKind::AuthPoll);
        assert_eq!(classify("/auth/tg-login/poll", &Method::GET), BucketKind::AuthPoll);
    }

    #[test]
    fn classify_routes_oauth_and_init_start_paths() {
        assert_eq!(classify("/oauth/github/authorize", &Method::GET), BucketKind::Oauth);
        assert_eq!(classify("/oauth/telegram/callback", &Method::POST), BucketKind::Oauth);
        assert_eq!(classify("/auth/link/init", &Method::POST), BucketKind::Oauth);
        assert_eq!(classify("/auth/device-code", &Method::POST), BucketKind::ApiWrite);
    }

    #[test]
    fn classify_falls_back_to_read_or_write_by_method() {
        assert_eq!(classify("/forum/threads", &Method::GET), BucketKind::ApiRead);
        assert_eq!(classify("/forum/threads", &Method::POST), BucketKind::ApiWrite);
        assert_eq!(classify("/share/live", &Method::POST), BucketKind::ApiWrite);
        assert_eq!(classify("/posts", &Method::GET), BucketKind::ApiRead);
    }

    #[test]
    fn forwarded_header_is_trusted_only_from_the_proxy_peer() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.7, 10.77.0.1".parse().expect("valid header"));

        // Loopback peer (single-box deploy) — trusted.
        let loopback: IpAddr = "127.0.0.1".parse().expect("valid ip");
        assert_eq!(client_ip(&headers, loopback), "203.0.113.7".parse::<IpAddr>().expect("valid ip"));

        // WireGuard control-box subnet peer — trusted.
        let wg_peer: IpAddr = "10.77.0.1".parse().expect("valid ip");
        assert_eq!(client_ip(&headers, wg_peer), "203.0.113.7".parse::<IpAddr>().expect("valid ip"));

        // Any other peer — header ignored, the TCP peer itself is the answer.
        let untrusted: IpAddr = "198.51.100.9".parse().expect("valid ip");
        assert_eq!(client_ip(&headers, untrusted), untrusted);
    }

    #[test]
    fn missing_forwarded_header_falls_back_to_peer_even_when_trusted() {
        let headers = HeaderMap::new();
        let wg_peer: IpAddr = "10.77.0.1".parse().expect("valid ip");
        assert_eq!(client_ip(&headers, wg_peer), wg_peer);
    }

    #[test]
    fn wireguard_subnet_check_matches_only_10_77_0_0_16() {
        assert!(is_wireguard_control_subnet("10.77.0.1".parse().expect("valid ip")));
        assert!(is_wireguard_control_subnet("10.77.255.254".parse().expect("valid ip")));
        assert!(!is_wireguard_control_subnet("10.78.0.1".parse().expect("valid ip")));
        assert!(!is_wireguard_control_subnet("10.76.0.1".parse().expect("valid ip")));
    }
}

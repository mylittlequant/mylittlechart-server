//! Live share hub: the one place every `share-live` room lives.
//!
//! Contract (docs/mlc/plans/live-hub-w1-2026-09-29.md §3):
//!
//! - `GET /api/share/{token}/stream-open` mints a [`ShareHub::mint_ticket`]
//!   ticket: 128-bit random, single use, bound to the share token and to the
//!   caller identity, valid for [`HubLimits::ticket_ttl`].
//! - `GET /api/share-live/{token}?ticket=` is a WebSocket. [`upgrade`] checks
//!   everything BEFORE the 101: missing / expired / used / foreign ticket is
//!   401, no view right is 403, a revoked or unknown share is 404, a full room
//!   is 403. The first server frame is `{"t":"welcome","publish":<bool>}`.
//! - Only sockets with `publish = true` are relayed. A text frame from a
//!   viewer closes that socket with 1008. A relayed frame goes to every other
//!   socket in the room, never back to its sender, byte for byte.
//! - The last frame of each kind (`g`, `v`, `p`, `preview`, `c`) is remembered
//!   PER PUBLISHER SOCKET and replayed to a late joiner. It lives inside the
//!   socket's own entry, so a publisher that leaves takes its frames with it;
//!   the room then receives the stop frames (`preview` cleared when it was
//!   set, `c off`, `v off`, `end`).
//! - A room is freed when its last socket leaves.
//! - Bounds live in one struct, [`HubLimits`]. A frame over
//!   [`HubLimits::max_frame_bytes`] closes 1009, a socket over its rate closes
//!   1008, an outbound queue overflow closes 1013.
//! - Each room has its own lock. The room map is touched only when a socket
//!   joins, or when the last socket of a room leaves; a relayed frame goes
//!   straight through the socket's own `Arc<Room>`.
//! - Revocation: [`ShareHub::members`] lists who is in a room, the caller
//!   evaluates their current access, and [`ShareHub::enforce`] closes the
//!   sockets that lost it with 4003.
//!
//! The hub knows nothing about accounts or the database. Whoever owns those
//! implements [`ShareAuthority`]. It lives in the library target so the real
//! WebSocket behaviour is testable from `tests/` without booting `main`.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use rand::Rng;
use serde::Deserialize;
use tokio::sync::{mpsc, watch};
use tokio::time::MissedTickBehavior;

/// WebSocket close codes this hub sends.
pub mod close_code {
    /// The server is shutting down.
    pub const GOING_AWAY: u16 = 1001;
    /// The socket broke a rule: a viewer sent a frame, or it sent too fast.
    pub const POLICY: u16 = 1008;
    /// A frame was larger than [`super::HubLimits::max_frame_bytes`].
    pub const TOO_BIG: u16 = 1009;
    /// The socket cannot keep up (outbound queue overflow), or the room is full.
    pub const TRY_AGAIN: u16 = 1013;
    /// The socket's right to be here (or to publish) was revoked.
    pub const REVOKED: u16 = 4003;
}

/// Every bound of the hub, in one place. `Default` is the spec's numbers.
#[derive(Debug, Clone)]
pub struct HubLimits {
    /// How long a ticket stays redeemable.
    pub ticket_ttl: Duration,
    /// Tickets that may be pending at once; stream-open answers 503 above it.
    pub max_pending_tickets: usize,
    /// Largest accepted frame, in bytes.
    pub max_frame_bytes: usize,
    /// Sustained frames per second one socket may send.
    pub frames_per_sec: u32,
    /// Frames a socket may send back to back before the rate applies.
    pub burst_frames: u32,
    /// Sockets per room.
    pub max_room_sockets: usize,
    /// Frames queued for one socket before it is closed.
    pub outbound_queue: usize,
    /// How long one write to a socket may take.
    pub write_timeout: Duration,
    /// How often an idle socket is pinged.
    pub ping_interval: Duration,
    /// A socket that sent nothing (not even a pong) for this long is dropped.
    pub idle_timeout: Duration,
    /// How often the owner of the hub re-checks the rights of every room.
    pub recheck_interval: Duration,
}

impl Default for HubLimits {
    fn default() -> Self {
        Self {
            ticket_ttl: Duration::from_secs(30),
            max_pending_tickets: 50_000,
            max_frame_bytes: 64 * 1024,
            frames_per_sec: 60,
            burst_frames: 120,
            max_room_sockets: 256,
            outbound_queue: 256,
            write_timeout: Duration::from_secs(10),
            ping_interval: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(90),
            recheck_interval: Duration::from_secs(60),
        }
    }
}

/// Who a ticket, and a socket, belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Identity {
    /// A signed-out viewer. Every signed-out viewer has the same rights.
    Anonymous,
    /// A signed-in account.
    User(i64),
}

impl Identity {
    /// The account id, or `None` for a signed-out viewer.
    pub fn user_id(self) -> Option<i64> {
        match self {
            Identity::Anonymous => None,
            Identity::User(id) => Some(id),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Identity::Anonymous => "anonymous",
            Identity::User(_) => "user",
        }
    }
}

impl From<Option<i64>> for Identity {
    fn from(user: Option<i64>) -> Self {
        user.map_or(Identity::Anonymous, Identity::User)
    }
}

/// What an identity may do on a share right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// The share is revoked, expired, unknown, or not a live share.
    Gone,
    /// The share exists, but this identity has no view right on it.
    Locked,
    /// The identity may view; `publish` says whether it may also send.
    Granted { publish: bool },
}

/// The authority failed to answer (a database error, a poisoned task). The
/// upgrade answers 500 and nothing is joined.
#[derive(Debug)]
pub struct AuthorityFailure;

/// What the hub asks of whoever owns accounts and share rights.
pub trait ShareAuthority: Send + Sync {
    /// The account the upgrade request itself proves to be (session cookie or
    /// bearer), or `None` when it carries no verifiable credential. A browser
    /// cannot put an `Authorization` header on a WebSocket, so `None` does not
    /// mean anonymous: the ticket still carries the identity it was minted for.
    fn presented_user(
        &self,
        headers: &HeaderMap,
    ) -> impl Future<Output = Result<Option<i64>, AuthorityFailure>> + Send;

    /// The CURRENT access of `identity` on share `token`.
    fn access(
        &self,
        token: &str,
        identity: Identity,
    ) -> impl Future<Output = Result<Access, AuthorityFailure>> + Send;
}

/// A close the hub sends: code plus a short reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Close {
    pub code: u16,
    pub reason: &'static str,
}

const CLOSE_REVOKED: Close = Close { code: close_code::REVOKED, reason: "access revoked" };
const CLOSE_OVERFLOW: Close = Close { code: close_code::TRY_AGAIN, reason: "cannot keep up" };
const CLOSE_ROOM_FULL: Close = Close { code: close_code::TRY_AGAIN, reason: "room full" };
const CLOSE_TOO_BIG: Close = Close { code: close_code::TOO_BIG, reason: "frame too large" };
const CLOSE_VIEWER: Close = Close { code: close_code::POLICY, reason: "viewers cannot send" };
const CLOSE_RATE: Close = Close { code: close_code::POLICY, reason: "rate limit" };
const CLOSE_IDLE: Close = Close { code: close_code::GOING_AWAY, reason: "idle" };

/// Frames that release a viewer, in the order the client itself sends them
/// when Live goes off (`take_live_stop_frames`).
const STOP_FRAMES: [&str; 3] = [
    r#"{"t":"c","off":true}"#,
    r#"{"t":"v","off":true}"#,
    r#"{"t":"end"}"#,
];
/// Clears an in-progress drawing on the viewer.
const PREVIEW_CLEAR_FRAME: &str = r#"{"t":"preview","b":""}"#;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------

/// The five kinds of frame a late joiner is caught up with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Gesture,
    Viewport,
    Point,
    Preview,
    Cursor,
}

const SLOT_COUNT: usize = 5;

/// What one relayed frame does to its sender's remembered state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    Store(Slot),
    Clear(Slot),
    End,
}

#[derive(Deserialize)]
struct FrameHead<'a> {
    #[serde(borrow)]
    t: Cow<'a, str>,
    #[serde(default)]
    off: bool,
}

#[derive(Deserialize)]
struct PreviewBody {
    #[serde(default)]
    b: String,
}

/// What `text` means to the hub, or `None` for anything outside the frame
/// vocabulary (`hello` from an old client, junk): such a frame is not relayed.
fn classify(text: &str) -> Option<Effect> {
    let head: FrameHead<'_> = serde_json::from_str(text).ok()?;
    match head.t.as_ref() {
        "g" => Some(Effect::Store(Slot::Gesture)),
        "p" => Some(Effect::Store(Slot::Point)),
        "v" if head.off => Some(Effect::Clear(Slot::Viewport)),
        "v" => Some(Effect::Store(Slot::Viewport)),
        "c" if head.off => Some(Effect::Clear(Slot::Cursor)),
        "c" => Some(Effect::Store(Slot::Cursor)),
        "preview" => {
            let cleared = serde_json::from_str::<PreviewBody>(text).is_ok_and(|body| body.b.is_empty());
            Some(if cleared { Effect::Clear(Slot::Preview) } else { Effect::Store(Slot::Preview) })
        }
        "end" => Some(Effect::End),
        _ => None,
    }
}

/// The last frame of each kind one publisher sent.
#[derive(Default)]
struct Memory {
    slots: [Option<Arc<str>>; SLOT_COUNT],
}

impl Memory {
    fn apply(&mut self, effect: Effect, frame: &Arc<str>) {
        match effect {
            Effect::Store(slot) => self.slots[slot as usize] = Some(Arc::clone(frame)),
            Effect::Clear(slot) => self.slots[slot as usize] = None,
            Effect::End => self.slots = Default::default(),
        }
    }

    fn has_state(&self) -> bool {
        self.slots.iter().any(Option::is_some)
    }

    fn has(&self, slot: Slot) -> bool {
        self.slots[slot as usize].is_some()
    }

    fn frames(&self) -> impl Iterator<Item = &Arc<str>> {
        self.slots.iter().flatten()
    }
}

// ---------------------------------------------------------------------------
// Rooms
// ---------------------------------------------------------------------------

/// One socket in a room.
struct Sub {
    id: u64,
    identity: Identity,
    publish: bool,
    tx: mpsc::Sender<Arc<str>>,
    close: watch::Sender<Option<Close>>,
    memory: Memory,
}

impl Sub {
    /// Ask this socket's task to close. The first reason wins.
    fn request_close(&self, close: Close) {
        self.close.send_if_modified(|current| {
            if current.is_some() {
                false
            } else {
                *current = Some(close);
                true
            }
        });
    }

    /// Queue a frame for this socket; a full queue closes it (1013).
    fn offer(&self, frame: &Arc<str>) {
        if let Err(mpsc::error::TrySendError::Full(_)) = self.tx.try_send(Arc::clone(frame)) {
            self.request_close(CLOSE_OVERFLOW);
        }
    }
}

struct RoomState {
    subs: Vec<Sub>,
    /// Set when the last socket left; a joiner that finds it retries.
    dead: bool,
}

struct Room {
    token: String,
    state: Mutex<RoomState>,
}

/// What a socket task holds while it is in a room.
struct Member {
    id: u64,
    room: Arc<Room>,
}

/// Everything a socket brings to a room.
struct Seat {
    identity: Identity,
    publish: bool,
    tx: mpsc::Sender<Arc<str>>,
    close: watch::Sender<Option<Close>>,
}

#[derive(Debug, PartialEq, Eq)]
enum JoinRefusal {
    RoomFull,
}

// ---------------------------------------------------------------------------
// Tickets
// ---------------------------------------------------------------------------

struct TicketRow {
    token: String,
    identity: Identity,
    expires: Instant,
}

struct TicketBook {
    rows: HashMap<String, TicketRow>,
    last_purge: Instant,
}

/// Why a ticket was refused. Every reason is a 401 on the wire; the reason is
/// for the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TicketRefusal {
    Unknown,
    Expired,
    OtherShare,
    OtherCaller,
}

impl TicketRefusal {
    fn as_str(self) -> &'static str {
        match self {
            TicketRefusal::Unknown => "unknown or used ticket",
            TicketRefusal::Expired => "expired ticket",
            TicketRefusal::OtherShare => "ticket is for another share",
            TicketRefusal::OtherCaller => "ticket is for another caller",
        }
    }
}

// ---------------------------------------------------------------------------
// The hub
// ---------------------------------------------------------------------------

/// The registry of every live room, and the ticket book that admits sockets.
pub struct ShareHub {
    limits: HubLimits,
    rooms: Mutex<HashMap<String, Arc<Room>>>,
    tickets: Mutex<TicketBook>,
    next_id: AtomicU64,
}

impl ShareHub {
    pub fn new(limits: HubLimits) -> Self {
        Self {
            limits,
            rooms: Mutex::new(HashMap::new()),
            tickets: Mutex::new(TicketBook { rows: HashMap::new(), last_purge: Instant::now() }),
            next_id: AtomicU64::new(1),
        }
    }

    pub fn limits(&self) -> &HubLimits {
        &self.limits
    }

    /// Mint a single-use ticket for `identity` on share `token`. `None` when
    /// [`HubLimits::max_pending_tickets`] tickets are already pending.
    pub fn mint_ticket(&self, token: &str, identity: Identity) -> Option<String> {
        let now = Instant::now();
        let mut book = lock(&self.tickets);
        let full = book.rows.len() >= self.limits.max_pending_tickets;
        if full || now.duration_since(book.last_purge) >= Duration::from_secs(1) {
            book.rows.retain(|_, row| row.expires > now);
            book.last_purge = now;
        }
        if book.rows.len() >= self.limits.max_pending_tickets {
            return None;
        }
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill(&mut bytes);
        let ticket = hex::encode(bytes);
        book.rows.insert(
            ticket.clone(),
            TicketRow { token: token.to_string(), identity, expires: now + self.limits.ticket_ttl },
        );
        Some(ticket)
    }

    /// Consume `ticket` for share `token`. `presented` is the account the
    /// upgrade request itself proved to be, if any: when there is one it must
    /// be the account the ticket was minted for. A refused presentation does
    /// not consume the ticket, so a thief cannot burn the owner's ticket.
    fn redeem_ticket(
        &self,
        ticket: &str,
        token: &str,
        presented: Option<i64>,
    ) -> Result<Identity, TicketRefusal> {
        let now = Instant::now();
        let mut book = lock(&self.tickets);
        let Some(row) = book.rows.get(ticket) else {
            return Err(TicketRefusal::Unknown);
        };
        if row.expires <= now {
            book.rows.remove(ticket);
            return Err(TicketRefusal::Expired);
        }
        if row.token != token {
            return Err(TicketRefusal::OtherShare);
        }
        if let Some(user) = presented {
            if row.identity != Identity::User(user) {
                return Err(TicketRefusal::OtherCaller);
            }
        }
        let identity = row.identity;
        book.rows.remove(ticket);
        Ok(identity)
    }

    /// Sockets currently in the room for `token`.
    pub fn room_len(&self, token: &str) -> usize {
        match self.find_room(token) {
            Some(room) => lock(&room.state).subs.len(),
            None => 0,
        }
    }

    /// Whether the room for `token` already holds its ceiling of sockets:
    /// `stream-open` and the upgrade both answer 403 then.
    pub fn room_is_full(&self, token: &str) -> bool {
        self.room_len(token) >= self.limits.max_room_sockets
    }

    /// Rooms that currently exist.
    pub fn room_count(&self) -> usize {
        lock(&self.rooms).len()
    }

    /// Tokens of every room that currently exists.
    pub fn active_tokens(&self) -> Vec<String> {
        lock(&self.rooms).keys().cloned().collect()
    }

    /// Who is in the room for `token`, each identity once.
    pub fn members(&self, token: &str) -> Vec<Identity> {
        let Some(room) = self.find_room(token) else {
            return Vec::new();
        };
        let state = lock(&room.state);
        let mut seen = HashSet::new();
        state.subs.iter().map(|sub| sub.identity).filter(|identity| seen.insert(*identity)).collect()
    }

    /// Apply current access to a room: a socket whose identity lost its view
    /// right, or a publisher that lost its edit right, is closed with 4003. An
    /// identity without a verdict (it joined after the caller looked) is left
    /// alone.
    pub fn enforce(&self, token: &str, verdicts: &HashMap<Identity, Access>) {
        let Some(room) = self.find_room(token) else {
            return;
        };
        let state = lock(&room.state);
        for sub in &state.subs {
            let Some(access) = verdicts.get(&sub.identity) else {
                continue;
            };
            let keep = match access {
                Access::Granted { publish } => *publish || !sub.publish,
                Access::Gone | Access::Locked => false,
            };
            if !keep {
                sub.request_close(CLOSE_REVOKED);
            }
        }
    }

    /// Close every socket of every room (server shutdown).
    pub fn close_all(&self, close: Close) {
        let rooms: Vec<Arc<Room>> = lock(&self.rooms).values().cloned().collect();
        for room in rooms {
            for sub in &lock(&room.state).subs {
                sub.request_close(close);
            }
        }
    }

    fn find_room(&self, token: &str) -> Option<Arc<Room>> {
        lock(&self.rooms).get(token).cloned()
    }

    fn room_or_create(&self, token: &str) -> Arc<Room> {
        let mut rooms = lock(&self.rooms);
        Arc::clone(rooms.entry(token.to_string()).or_insert_with(|| {
            Arc::new(Room {
                token: token.to_string(),
                state: Mutex::new(RoomState { subs: Vec::new(), dead: false }),
            })
        }))
    }

    /// Drop `room` from the map, unless the map already holds a newer room
    /// under the same token.
    fn remove_room(&self, room: &Arc<Room>) {
        let mut rooms = lock(&self.rooms);
        if rooms.get(&room.token).is_some_and(|held| Arc::ptr_eq(held, room)) {
            rooms.remove(&room.token);
        }
    }

    /// Seat a socket in the room for `token`. The late-joiner replay is queued
    /// on the socket's own channel under the room lock, so no frame can fall
    /// between the replay and the subscription.
    fn join(&self, token: &str, seat: Seat) -> Result<Member, JoinRefusal> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        loop {
            let room = self.room_or_create(token);
            let mut state = lock(&room.state);
            if state.dead {
                drop(state);
                self.remove_room(&room);
                continue;
            }
            if state.subs.len() >= self.limits.max_room_sockets {
                return Err(JoinRefusal::RoomFull);
            }
            'replay: for sub in state.subs.iter().filter(|sub| sub.publish) {
                for frame in sub.memory.frames() {
                    if seat.tx.try_send(Arc::clone(frame)).is_err() {
                        break 'replay;
                    }
                }
            }
            state.subs.push(Sub {
                id,
                identity: seat.identity,
                publish: seat.publish,
                tx: seat.tx,
                close: seat.close,
                memory: Memory::default(),
            });
            drop(state);
            return Ok(Member { id, room });
        }
    }

    /// Relay one frame from `member` to the rest of its room.
    fn relay(&self, member: &Member, frame: Arc<str>) {
        let Some(effect) = classify(&frame) else {
            return;
        };
        let mut state = lock(&member.room.state);
        let Some(sender) = state.subs.iter_mut().find(|sub| sub.id == member.id) else {
            return;
        };
        sender.memory.apply(effect, &frame);
        for sub in state.subs.iter().filter(|sub| sub.id != member.id) {
            sub.offer(&frame);
        }
    }

    /// Take `member` out of its room. A publisher that had state on the
    /// viewers' screens is followed by the stop frames; an empty room is freed.
    fn leave(&self, member: Member) {
        let mut state = lock(&member.room.state);
        let Some(position) = state.subs.iter().position(|sub| sub.id == member.id) else {
            return;
        };
        let leaving = state.subs.remove(position);
        if leaving.publish && leaving.memory.has_state() {
            if leaving.memory.has(Slot::Preview) {
                let frame: Arc<str> = Arc::from(PREVIEW_CLEAR_FRAME);
                state.subs.iter().for_each(|sub| sub.offer(&frame));
            }
            for text in STOP_FRAMES {
                let frame: Arc<str> = Arc::from(text);
                state.subs.iter().for_each(|sub| sub.offer(&frame));
            }
        }
        if state.subs.is_empty() {
            state.dead = true;
            drop(state);
            self.remove_room(&member.room);
        }
    }
}

// ---------------------------------------------------------------------------
// The upgrade
// ---------------------------------------------------------------------------

/// What the route hands to [`upgrade`].
pub struct SocketRequest {
    /// The share token from the path.
    pub token: String,
    /// The `ticket` query parameter.
    pub ticket: Option<String>,
    /// Headers of the upgrade request.
    pub headers: HeaderMap,
    /// The TCP peer (the edge that proxied the socket), for the journal.
    pub peer: Option<IpAddr>,
}

fn refuse(status: StatusCode, why: &str) -> Response {
    tracing::info!(status = status.as_u16(), why, "share-live refused");
    status.into_response()
}

/// A short, non-secret handle on a room for the journal. The token is a
/// capability, so it is never logged whole.
fn room_handle(token: &str) -> String {
    token.chars().take(6).collect()
}

/// Check the ticket and the caller's access, then upgrade the request to a
/// hub socket. Every refusal is a plain status BEFORE the 101.
pub async fn upgrade<A: ShareAuthority>(
    hub: &Arc<ShareHub>,
    authority: &A,
    ws: WebSocketUpgrade,
    request: SocketRequest,
) -> Response {
    let SocketRequest { token, ticket, headers, peer } = request;
    let Some(ticket) = ticket.filter(|ticket| !ticket.is_empty()) else {
        return refuse(StatusCode::UNAUTHORIZED, "no ticket");
    };
    let presented = match authority.presented_user(&headers).await {
        Ok(user) => user,
        Err(AuthorityFailure) => return refuse(StatusCode::INTERNAL_SERVER_ERROR, "authority failed"),
    };
    let identity = match hub.redeem_ticket(&ticket, &token, presented) {
        Ok(identity) => identity,
        Err(why) => return refuse(StatusCode::UNAUTHORIZED, why.as_str()),
    };
    let publish = match authority.access(&token, identity).await {
        Ok(Access::Granted { publish }) => publish,
        Ok(Access::Locked) => return refuse(StatusCode::FORBIDDEN, "no view right"),
        Ok(Access::Gone) => return refuse(StatusCode::NOT_FOUND, "share is gone"),
        Err(AuthorityFailure) => return refuse(StatusCode::INTERNAL_SERVER_ERROR, "authority failed"),
    };
    if hub.room_is_full(&token) {
        return refuse(StatusCode::FORBIDDEN, "room full");
    }
    // The read cap is a memory bound, not the rule: the rule (64 KiB, close
    // 1009) is enforced per frame below, so a frame just over it still gets
    // its close code instead of a transport error.
    let hard_cap = hub.limits.max_frame_bytes.saturating_mul(4);
    let hub = Arc::clone(hub);
    ws.max_message_size(hard_cap)
        .max_frame_size(hard_cap)
        .on_upgrade(move |socket| serve_socket(hub, socket, token, identity, publish, peer))
}

/// A token bucket: `burst` frames at once, then `per_sec` frames a second.
struct RateBucket {
    tokens: f64,
    burst: f64,
    per_sec: f64,
    last: Instant,
}

impl RateBucket {
    fn new(per_sec: u32, burst: u32) -> Self {
        let burst = f64::from(burst.max(1));
        Self { tokens: burst, burst, per_sec: f64::from(per_sec), last: Instant::now() }
    }

    fn allow(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.per_sec).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

enum Inbound {
    Continue,
    Drop,
    Close(Close),
}

fn inbound(hub: &ShareHub, member: &Member, publish: bool, bucket: &mut RateBucket, message: Message) -> Inbound {
    let limit = hub.limits.max_frame_bytes;
    match message {
        Message::Text(text) => {
            if text.len() > limit {
                return Inbound::Close(CLOSE_TOO_BIG);
            }
            if !publish {
                return Inbound::Close(CLOSE_VIEWER);
            }
            if !bucket.allow(Instant::now()) {
                return Inbound::Close(CLOSE_RATE);
            }
            hub.relay(member, Arc::from(text.as_str()));
            Inbound::Continue
        }
        Message::Binary(bytes) if bytes.len() > limit => Inbound::Close(CLOSE_TOO_BIG),
        Message::Binary(_) | Message::Ping(_) | Message::Pong(_) => Inbound::Continue,
        Message::Close(_) => Inbound::Drop,
    }
}

/// One write to the socket, bounded in time. `false` means the socket is gone.
async fn write(socket: &mut WebSocket, message: Message, limit: Duration) -> bool {
    matches!(tokio::time::timeout(limit, socket.send(message)).await, Ok(Ok(())))
}

async fn serve_socket(
    hub: Arc<ShareHub>,
    mut socket: WebSocket,
    token: String,
    identity: Identity,
    publish: bool,
    peer: Option<IpAddr>,
) {
    let limits = hub.limits.clone();
    let (tx, mut queue) = mpsc::channel::<Arc<str>>(limits.outbound_queue.max(2));
    let (close_tx, mut close_rx) = watch::channel::<Option<Close>>(None);
    let welcome: Arc<str> = Arc::from(format!(r#"{{"t":"welcome","publish":{publish}}}"#));
    // The queue is empty and has room, so the welcome is always its first frame.
    let _ = tx.try_send(welcome);

    let member = match hub.join(&token, Seat { identity, publish, tx, close: close_tx }) {
        Ok(member) => member,
        Err(JoinRefusal::RoomFull) => {
            tracing::info!(room = %room_handle(&token), "share-live join refused: room full");
            let _ = write(&mut socket, close_message(CLOSE_ROOM_FULL), limits.write_timeout).await;
            return;
        }
    };
    tracing::info!(
        room = %room_handle(&token),
        identity = identity.label(),
        publish,
        peer = ?peer,
        sockets = hub.room_len(&token),
        "share-live join"
    );

    let mut bucket = RateBucket::new(limits.frames_per_sec, limits.burst_frames);
    let mut ping = tokio::time::interval_at(tokio::time::Instant::now() + limits.ping_interval, limits.ping_interval);
    ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut last_heard = Instant::now();

    let farewell: Option<Close> = loop {
        tokio::select! {
            changed = close_rx.changed() => {
                break match changed {
                    Ok(()) => *close_rx.borrow(),
                    Err(_) => None,
                };
            }
            queued = queue.recv() => {
                let Some(frame) = queued else { break None };
                if !write(&mut socket, Message::Text((&*frame).into()), limits.write_timeout).await {
                    break None;
                }
            }
            incoming = socket.recv() => {
                let Some(Ok(message)) = incoming else { break None };
                last_heard = Instant::now();
                match inbound(&hub, &member, publish, &mut bucket, message) {
                    Inbound::Continue => {}
                    Inbound::Drop => break None,
                    Inbound::Close(close) => break Some(close),
                }
            }
            _ = ping.tick() => {
                if last_heard.elapsed() > limits.idle_timeout {
                    break Some(CLOSE_IDLE);
                }
                if !write(&mut socket, Message::Ping(Bytes::new()), limits.write_timeout).await {
                    break None;
                }
            }
        }
    };

    hub.leave(member);
    match farewell {
        Some(close) => {
            tracing::info!(
                room = %room_handle(&token),
                code = close.code,
                reason = close.reason,
                "share-live close"
            );
            let _ = write(&mut socket, close_message(close), limits.write_timeout.min(Duration::from_secs(2))).await;
        }
        None => tracing::info!(room = %room_handle(&token), "share-live leave"),
    }
}

fn close_message(close: Close) -> Message {
    Message::Close(Some(CloseFrame { code: close.code, reason: close.reason.into() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seat(publish: bool, queue: usize) -> (Seat, mpsc::Receiver<Arc<str>>, watch::Receiver<Option<Close>>) {
        let (tx, rx) = mpsc::channel(queue);
        let (close, close_rx) = watch::channel(None);
        (Seat { identity: Identity::Anonymous, publish, tx, close }, rx, close_rx)
    }

    fn drain(rx: &mut mpsc::Receiver<Arc<str>>) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(frame) = rx.try_recv() {
            out.push(frame.to_string());
        }
        out
    }

    #[test]
    fn classify_knows_the_client_vocabulary_and_nothing_else() {
        assert_eq!(classify(r#"{"t":"g","b":{"phase":"drag"}}"#), Some(Effect::Store(Slot::Gesture)));
        assert_eq!(classify(r#"{"t":"v","b":"{}"}"#), Some(Effect::Store(Slot::Viewport)));
        assert_eq!(classify(r#"{"t":"v","off":true}"#), Some(Effect::Clear(Slot::Viewport)));
        assert_eq!(classify(r#"{"t":"p","id":"a","b":"x"}"#), Some(Effect::Store(Slot::Point)));
        assert_eq!(classify(r#"{"t":"c","b":"{}"}"#), Some(Effect::Store(Slot::Cursor)));
        assert_eq!(classify(r#"{"t":"c","off":true}"#), Some(Effect::Clear(Slot::Cursor)));
        assert_eq!(classify(r#"{"t":"preview","b":"{\"a\":1}"}"#), Some(Effect::Store(Slot::Preview)));
        assert_eq!(classify(r#"{"t":"preview","b":""}"#), Some(Effect::Clear(Slot::Preview)));
        assert_eq!(classify(r#"{"t":"end"}"#), Some(Effect::End));
        assert_eq!(classify(r#"{"t":"hello","k":"abc"}"#), None);
        assert_eq!(classify("not json"), None);
        assert_eq!(classify(r#"{"b":1}"#), None);
    }

    #[test]
    fn a_nested_kind_inside_a_body_does_not_change_the_frame_kind() {
        // The old relay matched substrings and filed this under `g`.
        let frame = r#"{"t":"p","id":"a","b":"{\"t\":\"g\"}"}"#;
        assert_eq!(classify(frame), Some(Effect::Store(Slot::Point)));
    }

    #[test]
    fn rate_bucket_allows_the_burst_then_the_rate() {
        let mut bucket = RateBucket::new(10, 3);
        let start = Instant::now();
        assert!(bucket.allow(start));
        assert!(bucket.allow(start));
        assert!(bucket.allow(start));
        assert!(!bucket.allow(start));
        assert!(bucket.allow(start + Duration::from_millis(150)));
        assert!(!bucket.allow(start + Duration::from_millis(150)));
    }

    #[test]
    fn a_full_outbound_queue_closes_that_socket_with_1013_and_keeps_the_bound() {
        let hub = ShareHub::new(HubLimits::default());
        let (publisher, _publisher_rx, _publisher_close) = seat(true, 8);
        let (slow, mut slow_rx, slow_close) = seat(false, 4);
        let sender = hub.join("room", publisher).expect("join publisher");
        let _slow = hub.join("room", slow).expect("join slow viewer");

        for n in 0..10 {
            hub.relay(&sender, Arc::from(format!(r#"{{"t":"g","b":{n}}}"#)));
        }

        assert_eq!(*slow_close.borrow(), Some(CLOSE_OVERFLOW));
        assert_eq!(CLOSE_OVERFLOW.code, close_code::TRY_AGAIN);
        assert_eq!(drain(&mut slow_rx).len(), 4, "the queue never grows past its bound");
    }

    #[test]
    fn a_room_holds_at_most_the_configured_sockets() {
        let hub = ShareHub::new(HubLimits { max_room_sockets: 2, ..HubLimits::default() });
        let (a, _a_rx, _a_close) = seat(false, 4);
        let (b, _b_rx, _b_close) = seat(false, 4);
        let (c, _c_rx, _c_close) = seat(false, 4);
        let _a = hub.join("room", a).expect("first");
        let _b = hub.join("room", b).expect("second");
        assert_eq!(hub.join("room", c).err(), Some(JoinRefusal::RoomFull));
        assert_eq!(hub.room_len("room"), 2);
    }

    #[test]
    fn the_last_socket_leaving_frees_the_room_and_a_new_join_makes_a_fresh_one() {
        let hub = ShareHub::new(HubLimits::default());
        let (a, _a_rx, _a_close) = seat(true, 4);
        let first = hub.join("room", a).expect("join");
        assert_eq!(hub.room_count(), 1);
        hub.leave(first);
        assert_eq!(hub.room_count(), 0);
        let (b, _b_rx, _b_close) = seat(false, 4);
        let _second = hub.join("room", b).expect("join again");
        assert_eq!(hub.room_count(), 1);
        assert_eq!(hub.room_len("room"), 1);
    }

    #[test]
    fn a_ticket_is_consumed_only_by_a_matching_redeem() {
        let hub = ShareHub::new(HubLimits::default());
        let ticket = hub.mint_ticket("room", Identity::User(7)).expect("mint");
        assert_eq!(hub.redeem_ticket(&ticket, "other", None), Err(TicketRefusal::OtherShare));
        assert_eq!(hub.redeem_ticket(&ticket, "room", Some(8)), Err(TicketRefusal::OtherCaller));
        assert_eq!(hub.redeem_ticket(&ticket, "room", Some(7)), Ok(Identity::User(7)));
        assert_eq!(hub.redeem_ticket(&ticket, "room", Some(7)), Err(TicketRefusal::Unknown));
    }

    #[test]
    fn an_anonymous_ticket_refuses_a_presented_account() {
        let hub = ShareHub::new(HubLimits::default());
        let ticket = hub.mint_ticket("room", Identity::Anonymous).expect("mint");
        assert_eq!(hub.redeem_ticket(&ticket, "room", Some(3)), Err(TicketRefusal::OtherCaller));
        assert_eq!(hub.redeem_ticket(&ticket, "room", None), Ok(Identity::Anonymous));
    }

    #[test]
    fn tickets_are_128_bit_and_distinct() {
        let hub = ShareHub::new(HubLimits::default());
        let a = hub.mint_ticket("room", Identity::Anonymous).expect("mint");
        let b = hub.mint_ticket("room", Identity::Anonymous).expect("mint");
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn the_ticket_book_is_bounded() {
        let hub = ShareHub::new(HubLimits { max_pending_tickets: 3, ..HubLimits::default() });
        for _ in 0..3 {
            assert!(hub.mint_ticket("room", Identity::Anonymous).is_some());
        }
        assert!(hub.mint_ticket("room", Identity::Anonymous).is_none());
    }
}

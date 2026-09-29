//! Real WebSocket clients against the live share hub's own upgrade handler.
//!
//! Each test boots an axum server on a loopback port whose only route is
//! `GET /api/share-live/{token}` -> `share_hub::upgrade`, with a fake
//! authority in place of the database (the database half is covered by the
//! server crate's own tests). Clients are `tokio-tungstenite`, so the
//! handshake, the close codes and the frames on the wire are the real ones.
//! The spec is docs/mlc/plans/live-hub-w1-2026-09-29.md §3 and §5.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use mylittlechart_server::share_hub::{
    self, close_code, Access, AuthorityFailure, Close, HubLimits, Identity, ShareAuthority, ShareHub,
    SocketRequest,
};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

type Client = WebSocketStream<TcpStream>;

const SHARE: &str = "share-under-test";
const WAIT: Duration = Duration::from_secs(3);

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FakeShare {
    gone: bool,
    private: bool,
    viewers: HashSet<i64>,
    editors: HashSet<i64>,
}

/// Rights table standing in for the database. The "credential" of an upgrade
/// is the `x-test-user` header.
#[derive(Default)]
struct FakeAuthority {
    shares: Mutex<HashMap<String, FakeShare>>,
}

impl FakeAuthority {
    fn set(&self, token: &str, share: FakeShare) {
        self.shares.lock().unwrap_or_else(|e| e.into_inner()).insert(token.to_string(), share);
    }
}

impl ShareAuthority for FakeAuthority {
    async fn presented_user(&self, headers: &HeaderMap) -> Result<Option<i64>, AuthorityFailure> {
        Ok(headers
            .get("x-test-user")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok()))
    }

    async fn access(&self, token: &str, identity: Identity) -> Result<Access, AuthorityFailure> {
        let shares = self.shares.lock().unwrap_or_else(|e| e.into_inner());
        let Some(share) = shares.get(token) else {
            return Ok(Access::Gone);
        };
        if share.gone {
            return Ok(Access::Gone);
        }
        let user = identity.user_id();
        let is_editor = user.is_some_and(|id| share.editors.contains(&id));
        let may_view = !share.private || is_editor || user.is_some_and(|id| share.viewers.contains(&id));
        Ok(if may_view { Access::Granted { publish: is_editor } } else { Access::Locked })
    }
}

struct Env {
    addr: SocketAddr,
    hub: Arc<ShareHub>,
    authority: Arc<FakeAuthority>,
}

struct Ctx {
    hub: Arc<ShareHub>,
    authority: Arc<FakeAuthority>,
}

async fn socket(
    State(ctx): State<Arc<Ctx>>,
    ws: WebSocketUpgrade,
    Path(token): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let request = SocketRequest { token, ticket: query.get("ticket").cloned(), headers, peer: None };
    share_hub::upgrade(&ctx.hub, &*ctx.authority, ws, request).await
}

async fn start(limits: HubLimits) -> Env {
    let hub = Arc::new(ShareHub::new(limits));
    let authority = Arc::new(FakeAuthority::default());
    authority.set(
        SHARE,
        FakeShare { editors: HashSet::from([1, 2]), ..FakeShare::default() },
    );
    let ctx = Arc::new(Ctx { hub: Arc::clone(&hub), authority: Arc::clone(&authority) });
    let router = Router::new().route("/api/share-live/{token}", get(socket)).with_state(ctx);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Env { addr, hub, authority }
}

/// Open a socket with an explicit ticket and (optionally) a presented account.
async fn connect(
    env: &Env,
    token: &str,
    ticket: &str,
    presented: Option<i64>,
) -> Result<Client, tokio_tungstenite::tungstenite::Error> {
    let url = format!("ws://{}/api/share-live/{token}?ticket={ticket}", env.addr);
    let mut request = url.into_client_request()?;
    if let Some(user) = presented {
        request.headers_mut().insert("x-test-user", HeaderValue::from(user));
    }
    let stream = TcpStream::connect(env.addr).await.map_err(tokio_tungstenite::tungstenite::Error::Io)?;
    let (ws, _response) = tokio_tungstenite::client_async(request, stream).await?;
    Ok(ws)
}

/// The HTTP status a refused upgrade answered.
async fn refused_with(env: &Env, token: &str, ticket: &str, presented: Option<i64>) -> u16 {
    match connect(env, token, ticket, presented).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => response.status().as_u16(),
        Err(other) => panic!("expected an HTTP refusal, got {other}"),
        Ok(_) => panic!("expected an HTTP refusal, the upgrade succeeded"),
    }
}

/// Mint a ticket for `identity` and join with it, presenting the same account.
async fn join(env: &Env, identity: Identity) -> Client {
    join_room(env, SHARE, identity).await
}

async fn join_room(env: &Env, token: &str, identity: Identity) -> Client {
    let ticket = env.hub.mint_ticket(token, identity).expect("ticket");
    connect(env, token, &ticket, identity.user_id()).await.expect("upgrade")
}

/// The next text frame, skipping pings.
async fn next_text(ws: &mut Client) -> String {
    let deadline = Instant::now() + WAIT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => return text.as_str().to_owned(),
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
            Ok(other) => panic!("expected a text frame, got {other:?}"),
            Err(_) => panic!("timed out waiting for a text frame"),
        }
    }
}

/// Read until the peer closes; returns the close code.
async fn close_code_of(ws: &mut Client) -> u16 {
    let deadline = Instant::now() + WAIT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, ws.next()).await {
            Ok(Some(Ok(Message::Close(Some(frame))))) => return u16::from(frame.code),
            Ok(Some(Ok(Message::Close(None)))) => panic!("closed without a code"),
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(error))) => panic!("transport error before a close frame: {error}"),
            Ok(None) => panic!("stream ended without a close frame"),
            Err(_) => panic!("timed out waiting for a close frame"),
        }
    }
}

/// No text frame arrives within `window`.
async fn silent_for(ws: &mut Client, window: Duration) {
    match tokio::time::timeout(window, async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                other => return other,
            }
        }
    })
    .await
    {
        Err(_) => {}
        Ok(other) => panic!("expected silence, got {other:?}"),
    }
}

async fn send(ws: &mut Client, text: &str) {
    ws.send(Message::text(text)).await.expect("send");
}

async fn expect_welcome(ws: &mut Client, publish: bool) {
    assert_eq!(next_text(ws).await, format!(r#"{{"t":"welcome","publish":{publish}}}"#));
}

/// Wait (bounded) until the room for `SHARE` holds exactly `count` sockets.
async fn wait_for_room_len(env: &Env, count: usize) {
    let deadline = Instant::now() + WAIT;
    while env.hub.room_len(SHARE) != count {
        assert!(Instant::now() < deadline, "room never reached {count} sockets (has {})", env.hub.room_len(SHARE));
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn gesture(n: u32) -> String {
    format!(r#"{{"t":"g","b":{{"n":{n}}}}}"#)
}

// ---------------------------------------------------------------------------
// Tickets and the pre-upgrade checks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_first_frame_is_a_welcome_carrying_the_publish_right() {
    let env = start(HubLimits::default()).await;
    let mut author = join(&env, Identity::User(1)).await;
    let mut viewer = join(&env, Identity::Anonymous).await;
    expect_welcome(&mut author, true).await;
    expect_welcome(&mut viewer, false).await;
}

#[tokio::test]
async fn a_ticket_works_once() {
    let env = start(HubLimits::default()).await;
    let ticket = env.hub.mint_ticket(SHARE, Identity::Anonymous).expect("ticket");
    let mut first = connect(&env, SHARE, &ticket, None).await.expect("first use");
    expect_welcome(&mut first, false).await;
    assert_eq!(refused_with(&env, SHARE, &ticket, None).await, 401);
}

#[tokio::test]
async fn a_ticket_expires() {
    let env = start(HubLimits { ticket_ttl: Duration::from_millis(100), ..HubLimits::default() }).await;
    let ticket = env.hub.mint_ticket(SHARE, Identity::Anonymous).expect("ticket");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(refused_with(&env, SHARE, &ticket, None).await, 401);
}

#[tokio::test]
async fn a_ticket_is_bound_to_its_share_and_its_caller() {
    let env = start(HubLimits::default()).await;
    env.authority.set("other-share", FakeShare::default());

    // Another share.
    let ticket = env.hub.mint_ticket(SHARE, Identity::Anonymous).expect("ticket");
    assert_eq!(refused_with(&env, "other-share", &ticket, None).await, 401);

    // Another account. The refusal does not burn the ticket: its owner still
    // gets in with it.
    let ticket = env.hub.mint_ticket(SHARE, Identity::User(1)).expect("ticket");
    assert_eq!(refused_with(&env, SHARE, &ticket, Some(2)).await, 401);
    let mut owner = connect(&env, SHARE, &ticket, Some(1)).await.expect("the account it was minted for");
    expect_welcome(&mut owner, true).await;

    // A signed-out ticket presented by a signed-in account.
    let ticket = env.hub.mint_ticket(SHARE, Identity::Anonymous).expect("ticket");
    assert_eq!(refused_with(&env, SHARE, &ticket, Some(5)).await, 401);
}

#[tokio::test]
async fn a_missing_or_unknown_ticket_is_401() {
    let env = start(HubLimits::default()).await;
    assert_eq!(refused_with(&env, SHARE, "", None).await, 401);
    assert_eq!(refused_with(&env, SHARE, "00000000000000000000000000000000", None).await, 401);
    assert_eq!(env.hub.room_count(), 0);
}

#[tokio::test]
async fn no_view_right_is_403_and_a_gone_share_is_404_before_the_upgrade() {
    let env = start(HubLimits::default()).await;
    env.authority.set(
        "private-share",
        FakeShare { private: true, viewers: HashSet::from([7]), ..FakeShare::default() },
    );
    env.authority.set("revoked-share", FakeShare { gone: true, ..FakeShare::default() });

    let stranger = env.hub.mint_ticket("private-share", Identity::User(9)).expect("ticket");
    assert_eq!(refused_with(&env, "private-share", &stranger, Some(9)).await, 403);
    let signed_out = env.hub.mint_ticket("private-share", Identity::Anonymous).expect("ticket");
    assert_eq!(refused_with(&env, "private-share", &signed_out, None).await, 403);

    let revoked = env.hub.mint_ticket("revoked-share", Identity::Anonymous).expect("ticket");
    assert_eq!(refused_with(&env, "revoked-share", &revoked, None).await, 404);
    let unknown = env.hub.mint_ticket("no-such-share", Identity::Anonymous).expect("ticket");
    assert_eq!(refused_with(&env, "no-such-share", &unknown, None).await, 404);

    // A granted viewer of the private share does get in.
    let viewer = env.hub.mint_ticket("private-share", Identity::User(7)).expect("ticket");
    let mut viewer = connect(&env, "private-share", &viewer, Some(7)).await.expect("granted viewer");
    expect_welcome(&mut viewer, false).await;
    assert_eq!(env.hub.room_count(), 1, "the refused attempts never created a room");
}

#[tokio::test]
async fn a_room_takes_at_most_its_socket_ceiling() {
    let env = start(HubLimits { max_room_sockets: 2, ..HubLimits::default() }).await;
    let mut first = join(&env, Identity::Anonymous).await;
    let mut second = join(&env, Identity::Anonymous).await;
    expect_welcome(&mut first, false).await;
    expect_welcome(&mut second, false).await;
    assert!(env.hub.room_is_full(SHARE));

    let third = env.hub.mint_ticket(SHARE, Identity::Anonymous).expect("ticket");
    assert_eq!(refused_with(&env, SHARE, &third, None).await, 403);

    drop(first);
    wait_for_room_len(&env, 1).await;
    let fourth = env.hub.mint_ticket(SHARE, Identity::Anonymous).expect("ticket");
    let mut admitted = connect(&env, SHARE, &fourth, None).await.expect("room has space again");
    expect_welcome(&mut admitted, false).await;
}

// ---------------------------------------------------------------------------
// Relay
// ---------------------------------------------------------------------------

#[tokio::test]
async fn publisher_frames_reach_everyone_else_byte_for_byte_and_never_the_sender() {
    let env = start(HubLimits::default()).await;
    let mut author = join(&env, Identity::User(1)).await;
    let mut grantee = join(&env, Identity::User(2)).await;
    let mut viewer_a = join(&env, Identity::Anonymous).await;
    let mut viewer_b = join(&env, Identity::Anonymous).await;
    expect_welcome(&mut author, true).await;
    expect_welcome(&mut grantee, true).await;
    expect_welcome(&mut viewer_a, false).await;
    expect_welcome(&mut viewer_b, false).await;

    let from_author = r#"{"t":"p","id":"line:1","b":"{\"x\":1.5,\"y\":  2}"}"#;
    send(&mut author, from_author).await;
    assert_eq!(next_text(&mut grantee).await, from_author);
    assert_eq!(next_text(&mut viewer_a).await, from_author);
    assert_eq!(next_text(&mut viewer_b).await, from_author);
    silent_for(&mut author, Duration::from_millis(250)).await;

    // Both directions: the grantee publishes too.
    let from_grantee = r#"{"t":"c","b":"{\"bar\":3}"}"#;
    send(&mut grantee, from_grantee).await;
    assert_eq!(next_text(&mut author).await, from_grantee);
    assert_eq!(next_text(&mut viewer_a).await, from_grantee);
    silent_for(&mut grantee, Duration::from_millis(250)).await;
}

#[tokio::test]
async fn a_frame_from_a_viewer_closes_that_socket_with_1008_and_is_not_relayed() {
    let env = start(HubLimits::default()).await;
    let mut author = join(&env, Identity::User(1)).await;
    let mut viewer = join(&env, Identity::Anonymous).await;
    expect_welcome(&mut author, true).await;
    expect_welcome(&mut viewer, false).await;

    send(&mut viewer, &gesture(1)).await;
    assert_eq!(close_code_of(&mut viewer).await, close_code::POLICY);
    silent_for(&mut author, Duration::from_millis(250)).await;
    wait_for_room_len(&env, 1).await;
}

#[tokio::test]
async fn a_frame_over_the_size_bound_closes_with_1009_and_one_at_the_bound_passes() {
    let env = start(HubLimits::default()).await;
    let mut author = join(&env, Identity::User(1)).await;
    let mut viewer = join(&env, Identity::Anonymous).await;
    expect_welcome(&mut author, true).await;
    expect_welcome(&mut viewer, false).await;

    let frame_of = |len: usize| {
        let filler = "x".repeat(len - r#"{"t":"g","b":""}"#.len());
        format!(r#"{{"t":"g","b":"{filler}"}}"#)
    };
    let at_the_bound = frame_of(64 * 1024);
    assert_eq!(at_the_bound.len(), 64 * 1024);
    send(&mut author, &at_the_bound).await;
    assert_eq!(next_text(&mut viewer).await.len(), 64 * 1024);

    send(&mut author, &frame_of(64 * 1024 + 1)).await;
    assert_eq!(close_code_of(&mut author).await, close_code::TOO_BIG);
    // The oversized frame never arrives; what the viewer gets is the stop
    // frames of the publisher that just left with a drawing on the screen.
    for frame in [r#"{"t":"c","off":true}"#, r#"{"t":"v","off":true}"#, r#"{"t":"end"}"#] {
        assert_eq!(next_text(&mut viewer).await, frame);
    }
    silent_for(&mut viewer, Duration::from_millis(250)).await;
}

#[tokio::test]
async fn a_frame_far_over_the_bound_ends_the_socket_without_reaching_anyone() {
    let env = start(HubLimits::default()).await;
    let mut author = join(&env, Identity::User(1)).await;
    let mut viewer = join(&env, Identity::Anonymous).await;
    expect_welcome(&mut author, true).await;
    expect_welcome(&mut viewer, false).await;

    let huge = format!(r#"{{"t":"g","b":"{}"}}"#, "x".repeat(2 * 1024 * 1024));
    let _ = author.send(Message::text(huge)).await;
    let deadline = Instant::now() + WAIT;
    loop {
        match tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), author.next()).await {
            Ok(Some(Ok(Message::Close(_))) | Some(Err(_)) | None) => break,
            Ok(Some(Ok(_))) => {}
            Err(_) => panic!("the socket that sent a 2 MiB frame is still open"),
        }
    }
    silent_for(&mut viewer, Duration::from_millis(250)).await;
    wait_for_room_len(&env, 1).await;
}

#[tokio::test]
async fn a_socket_over_its_rate_closes_with_1008_and_one_within_it_does_not() {
    let env = start(HubLimits { frames_per_sec: 5, burst_frames: 5, ..HubLimits::default() }).await;
    let mut careful = join(&env, Identity::User(1)).await;
    let mut flooder = join(&env, Identity::User(2)).await;
    let mut viewer = join(&env, Identity::Anonymous).await;
    expect_welcome(&mut careful, true).await;
    expect_welcome(&mut flooder, true).await;
    expect_welcome(&mut viewer, false).await;

    for n in 0..5 {
        send(&mut careful, &gesture(n)).await;
    }
    for n in 0..5 {
        assert_eq!(next_text(&mut viewer).await, gesture(n));
    }

    for n in 0..40 {
        // The server may already have closed; a failed send is fine.
        let _ = flooder.send(Message::text(gesture(n))).await;
    }
    assert_eq!(close_code_of(&mut flooder).await, close_code::POLICY);
}

// ---------------------------------------------------------------------------
// Replay, stop frames, room lifetime
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_late_joiner_is_caught_up_only_while_the_publisher_is_connected() {
    let env = start(HubLimits::default()).await;
    let mut author = join(&env, Identity::User(1)).await;
    let mut watcher = join(&env, Identity::Anonymous).await;
    expect_welcome(&mut author, true).await;
    expect_welcome(&mut watcher, false).await;

    let frames = [
        r#"{"t":"g","b":{"phase":"drag"}}"#,
        r#"{"t":"v","b":"{\"view_start\":10}"}"#,
        r#"{"t":"p","id":"line:1","b":"{\"x\":1}"}"#,
        r#"{"t":"preview","b":"{\"kind\":\"trend\"}"}"#,
        r#"{"t":"c","b":"{\"bar\":4}"}"#,
    ];
    for frame in frames {
        send(&mut author, frame).await;
    }
    for frame in frames {
        assert_eq!(next_text(&mut watcher).await, frame);
    }

    // The late joiner gets the welcome and then the five remembered frames.
    let mut late = join(&env, Identity::Anonymous).await;
    expect_welcome(&mut late, false).await;
    for frame in frames {
        assert_eq!(next_text(&mut late).await, frame);
    }

    // The publisher leaves: the room is told to let go of what it showed.
    drop(author);
    let stop = [
        r#"{"t":"preview","b":""}"#,
        r#"{"t":"c","off":true}"#,
        r#"{"t":"v","off":true}"#,
        r#"{"t":"end"}"#,
    ];
    for frame in stop {
        assert_eq!(next_text(&mut watcher).await, frame);
        assert_eq!(next_text(&mut late).await, frame);
    }

    // Nothing of the departed publisher is replayed any more.
    let mut after = join(&env, Identity::Anonymous).await;
    expect_welcome(&mut after, false).await;
    silent_for(&mut after, Duration::from_millis(300)).await;
}

#[tokio::test]
async fn one_publisher_leaving_forgets_only_its_own_frames() {
    let env = start(HubLimits::default()).await;
    let mut author = join(&env, Identity::User(1)).await;
    let mut grantee = join(&env, Identity::User(2)).await;
    let mut watcher = join(&env, Identity::Anonymous).await;
    expect_welcome(&mut author, true).await;
    expect_welcome(&mut grantee, true).await;
    expect_welcome(&mut watcher, false).await;

    let from_author = r#"{"t":"g","b":{"who":"author"}}"#;
    let from_grantee = r#"{"t":"p","id":"line:2","b":"{\"x\":2}"}"#;
    send(&mut author, from_author).await;
    assert_eq!(next_text(&mut watcher).await, from_author);
    send(&mut grantee, from_grantee).await;
    assert_eq!(next_text(&mut watcher).await, from_grantee);

    drop(author);
    for frame in [r#"{"t":"c","off":true}"#, r#"{"t":"v","off":true}"#, r#"{"t":"end"}"#] {
        assert_eq!(next_text(&mut watcher).await, frame);
    }

    let mut late = join(&env, Identity::Anonymous).await;
    expect_welcome(&mut late, false).await;
    assert_eq!(next_text(&mut late).await, from_grantee, "the grantee is still connected");
    silent_for(&mut late, Duration::from_millis(250)).await;
}

#[tokio::test]
async fn a_publisher_that_already_stopped_does_not_stop_the_room_twice() {
    let env = start(HubLimits::default()).await;
    let mut author = join(&env, Identity::User(1)).await;
    let mut watcher = join(&env, Identity::Anonymous).await;
    expect_welcome(&mut author, true).await;
    expect_welcome(&mut watcher, false).await;

    send(&mut author, &gesture(1)).await;
    send(&mut author, r#"{"t":"end"}"#).await;
    assert_eq!(next_text(&mut watcher).await, gesture(1));
    assert_eq!(next_text(&mut watcher).await, r#"{"t":"end"}"#);

    let mut late = join(&env, Identity::Anonymous).await;
    expect_welcome(&mut late, false).await;
    silent_for(&mut late, Duration::from_millis(250)).await;

    drop(author);
    silent_for(&mut watcher, Duration::from_millis(300)).await;
}

#[tokio::test]
async fn a_viewer_or_a_silent_publisher_leaving_sends_no_stop_frames() {
    let env = start(HubLimits::default()).await;
    let mut author = join(&env, Identity::User(1)).await;
    let mut idle_grantee = join(&env, Identity::User(2)).await;
    let mut viewer = join(&env, Identity::Anonymous).await;
    expect_welcome(&mut author, true).await;
    expect_welcome(&mut idle_grantee, true).await;
    expect_welcome(&mut viewer, false).await;

    send(&mut author, &gesture(1)).await;
    assert_eq!(next_text(&mut viewer).await, gesture(1));
    assert_eq!(next_text(&mut idle_grantee).await, gesture(1));

    drop(idle_grantee);
    drop(viewer);
    wait_for_room_len(&env, 1).await;
    silent_for(&mut author, Duration::from_millis(300)).await;
}

#[tokio::test]
async fn frames_outside_the_vocabulary_are_dropped_not_relayed() {
    let env = start(HubLimits::default()).await;
    let mut author = join(&env, Identity::User(1)).await;
    let mut viewer = join(&env, Identity::Anonymous).await;
    expect_welcome(&mut author, true).await;
    expect_welcome(&mut viewer, false).await;

    send(&mut author, r#"{"t":"hello","k":"an-old-clients-ticket"}"#).await;
    send(&mut author, "not json at all").await;
    send(&mut author, &gesture(7)).await;
    assert_eq!(next_text(&mut viewer).await, gesture(7), "only the real frame arrives");
}

#[tokio::test]
async fn the_room_is_freed_when_its_last_socket_leaves() {
    let env = start(HubLimits::default()).await;
    let first = join(&env, Identity::User(1)).await;
    let second = join(&env, Identity::Anonymous).await;
    wait_for_room_len(&env, 2).await;
    assert_eq!(env.hub.room_count(), 1);

    drop(first);
    wait_for_room_len(&env, 1).await;
    assert_eq!(env.hub.room_count(), 1);

    drop(second);
    let deadline = Instant::now() + WAIT;
    while env.hub.room_count() != 0 {
        assert!(Instant::now() < deadline, "the empty room was never freed");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(env.hub.active_tokens().is_empty());
}

// ---------------------------------------------------------------------------
// Revocation, liveness, shutdown
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revocation_closes_the_affected_sockets_with_4003_and_leaves_the_rest() {
    let env = start(HubLimits::default()).await;
    let mut author = join(&env, Identity::User(1)).await;
    let mut grantee = join(&env, Identity::User(2)).await;
    let mut member = join(&env, Identity::User(3)).await;
    let mut viewer = join(&env, Identity::Anonymous).await;
    expect_welcome(&mut author, true).await;
    expect_welcome(&mut grantee, true).await;
    expect_welcome(&mut member, false).await;
    expect_welcome(&mut viewer, false).await;

    let mut members = env.hub.members(SHARE);
    members.sort_by_key(|identity| identity.user_id());
    assert_eq!(
        members,
        vec![Identity::Anonymous, Identity::User(1), Identity::User(2), Identity::User(3)]
    );

    // A viewer's view right is gone: only that identity's sockets close.
    env.hub.enforce(SHARE, &HashMap::from([(Identity::User(3), Access::Locked)]));
    assert_eq!(close_code_of(&mut member).await, close_code::REVOKED);

    // The grantee keeps viewing but loses the edit right: 4003, and the
    // reconnect would be told publish=false.
    env.hub.enforce(SHARE, &HashMap::from([(Identity::User(2), Access::Granted { publish: false })]));
    assert_eq!(close_code_of(&mut grantee).await, close_code::REVOKED);

    // Everyone who is still entitled keeps streaming.
    env.hub.enforce(
        SHARE,
        &HashMap::from([
            (Identity::User(1), Access::Granted { publish: true }),
            (Identity::Anonymous, Access::Granted { publish: false }),
        ]),
    );
    send(&mut author, &gesture(1)).await;
    assert_eq!(next_text(&mut viewer).await, gesture(1));

    // An identity without a verdict (it joined after the caller looked) is left alone.
    env.hub.enforce(SHARE, &HashMap::new());
    send(&mut author, &gesture(2)).await;
    assert_eq!(next_text(&mut viewer).await, gesture(2));
}

#[tokio::test]
async fn a_gone_share_closes_every_socket_with_4003() {
    let env = start(HubLimits::default()).await;
    let mut author = join(&env, Identity::User(1)).await;
    let mut viewer = join(&env, Identity::Anonymous).await;
    expect_welcome(&mut author, true).await;
    expect_welcome(&mut viewer, false).await;

    let verdicts: HashMap<Identity, Access> =
        env.hub.members(SHARE).into_iter().map(|identity| (identity, Access::Gone)).collect();
    env.hub.enforce(SHARE, &verdicts);

    assert_eq!(close_code_of(&mut author).await, close_code::REVOKED);
    assert_eq!(close_code_of(&mut viewer).await, close_code::REVOKED);
    wait_for_room_len(&env, 0).await;
}

#[tokio::test]
async fn the_server_pings_and_drops_a_socket_that_stops_answering() {
    let env = start(HubLimits {
        ping_interval: Duration::from_millis(100),
        idle_timeout: Duration::from_millis(400),
        write_timeout: Duration::from_secs(1),
        ..HubLimits::default()
    })
    .await;
    let mut alive = join(&env, Identity::Anonymous).await;
    let mut silent = join(&env, Identity::Anonymous).await;
    expect_welcome(&mut alive, false).await;
    wait_for_room_len(&env, 2).await;

    // `alive` keeps reading, which is what answers the server's pings; a
    // socket nobody reads from never sends a pong.
    let deadline = Instant::now() + Duration::from_millis(1500);
    let mut pings = 0;
    while Instant::now() < deadline {
        if let Ok(Some(Ok(Message::Ping(_)))) =
            tokio::time::timeout(Duration::from_millis(200), alive.next()).await
        {
            pings += 1;
        }
    }
    assert!(pings >= 3, "the server pinged the idle socket ({pings} pings seen)");
    assert_eq!(env.hub.room_len(SHARE), 1, "the socket that never answered was dropped");
    let _ = silent.close(None).await;
}

#[tokio::test]
async fn shutdown_closes_every_socket_going_away() {
    let env = start(HubLimits::default()).await;
    let mut author = join(&env, Identity::User(1)).await;
    let mut viewer = join(&env, Identity::Anonymous).await;
    expect_welcome(&mut author, true).await;
    expect_welcome(&mut viewer, false).await;

    env.hub.close_all(Close { code: close_code::GOING_AWAY, reason: "server restarting" });

    assert_eq!(close_code_of(&mut author).await, close_code::GOING_AWAY);
    assert_eq!(close_code_of(&mut viewer).await, close_code::GOING_AWAY);
}

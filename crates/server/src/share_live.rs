//! Glue between the live share hub (`mylittlechart_server::share_hub`, the
//! rooms and the wire rules) and this server's accounts and share rights.
//!
//! - [`share_live_socket`] is `GET /api/share-live/{token}?ticket=`.
//! - [`DbAuthority`] answers the hub's two questions from the identity
//!   database: who the upgrade request proves to be, and what an identity may
//!   do on a share right now (`db::share_live_access`, the same rule
//!   `stream-open` uses).
//! - [`reconcile`] re-evaluates one room after a right changed and closes the
//!   sockets that lost it (4003). The routes that revoke a grant, revoke a
//!   share, or change its visibility call it; [`spawn_hub_tasks`] also calls it
//!   for every room on a timer, which covers what no route announces: a grant
//!   that expired, a group member removed.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use mylittlechart_server::share_hub::{
    self, close_code, Access, AuthorityFailure, Close, Identity, ShareAuthority, SocketRequest,
};

use crate::routes::share::resolve_caller_optional;
use crate::state::AppState;

/// The hub's view of accounts and share rights, backed by the identity database.
pub struct DbAuthority {
    state: Arc<AppState>,
}

impl ShareAuthority for DbAuthority {
    async fn presented_user(&self, headers: &HeaderMap) -> Result<Option<i64>, AuthorityFailure> {
        resolve_caller_optional(self.state.clone(), headers)
            .await
            .map_err(|_| AuthorityFailure)
    }

    async fn access(&self, token: &str, identity: Identity) -> Result<Access, AuthorityFailure> {
        access_for(&self.state, token, identity.user_id()).await
    }
}

/// What `caller` (`None` = signed out) may do on share `token` right now.
pub async fn access_for(
    state: &Arc<AppState>,
    token: &str,
    caller: Option<i64>,
) -> Result<Access, AuthorityFailure> {
    let state = Arc::clone(state);
    let token = token.to_string();
    let result = tokio::task::spawn_blocking(move || {
        let conn = state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        crate::db::share_live_access(&conn, &token, caller)
    })
    .await;
    match result {
        Ok(Ok(access)) => Ok(access),
        Ok(Err(e)) => {
            tracing::error!("DB error resolving live share access: {}", e);
            Err(AuthorityFailure)
        }
        Err(e) => {
            tracing::error!("live share access task failed: {}", e);
            Err(AuthorityFailure)
        }
    }
}

/// Query string of the socket route.
#[derive(serde::Deserialize)]
pub struct SocketQuery {
    ticket: Option<String>,
}

/// `GET /api/share-live/{token}?ticket=` — the live socket. Every refusal
/// (401 / 403 / 404) happens before the upgrade; see `share_hub` for the wire
/// contract.
pub async fn share_live_socket(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
    Path(token): Path<String>,
    Query(query): Query<SocketQuery>,
    headers: HeaderMap,
) -> Response {
    let authority = DbAuthority { state: Arc::clone(&state) };
    let request = SocketRequest {
        token,
        ticket: query.ticket,
        headers,
        peer: Some(peer.ip()),
    };
    share_hub::upgrade(&state.share_hub, &authority, ws, request).await
}

/// Re-evaluate the room of `token` against the database and close the sockets
/// that lost their right (a viewer that lost its view right, a publisher that
/// lost its edit right). A room nobody is in costs nothing.
pub async fn reconcile(state: &Arc<AppState>, token: &str) {
    let members = state.share_hub.members(token);
    if members.is_empty() {
        return;
    }
    let db_state = Arc::clone(state);
    let db_token = token.to_string();
    let result = tokio::task::spawn_blocking(move || -> rusqlite::Result<HashMap<Identity, Access>> {
        let conn = db_state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let mut verdicts = HashMap::with_capacity(members.len());
        for identity in members {
            verdicts.insert(identity, crate::db::share_live_access(&conn, &db_token, identity.user_id())?);
        }
        Ok(verdicts)
    })
    .await;
    match result {
        Ok(Ok(verdicts)) => state.share_hub.enforce(token, &verdicts),
        Ok(Err(e)) => tracing::error!("DB error re-checking a live room: {}", e),
        Err(e) => tracing::error!("live room re-check task failed: {}", e),
    }
}

/// Start the hub's background work: close every socket when the server shuts
/// down (a WebSocket would otherwise hold the graceful drain open), and
/// re-check every room's rights on a timer.
pub fn spawn_hub_tasks(state: Arc<AppState>, mut shutdown: tokio::sync::broadcast::Receiver<()>) {
    let closer = Arc::clone(&state);
    tokio::spawn(async move {
        let _ = shutdown.recv().await;
        closer.share_hub.close_all(Close { code: close_code::GOING_AWAY, reason: "server restarting" });
    });

    let period = state.share_hub.limits().recheck_interval;
    tokio::spawn(async move {
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        loop {
            tick.tick().await;
            for token in state.share_hub.active_tokens() {
                reconcile(&state, &token).await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    //! The real route table, the real handlers and a real (in-memory) identity
    //! database, with real WebSocket clients: stream-open -> ticket -> socket,
    //! and every revoke path closing the sockets it should.

    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use axum::body::{to_bytes, Body};
    use axum::http::{HeaderValue, Request, StatusCode};
    use axum::Router;
    use futures_util::{SinkExt, StreamExt};
    use tokio::net::TcpStream;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::WebSocketStream;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::{hash_token, hash_user_agent};
    use crate::state::ControlPlane;

    type Client = WebSocketStream<TcpStream>;

    const AUTHOR: i64 = 1;
    const GRANTEE: i64 = 2;
    const OUTSIDER: i64 = 3;
    const WAIT: Duration = Duration::from_secs(3);

    const SCHEMA: &str = "
        CREATE TABLE share_links (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            preset_json TEXT NOT NULL DEFAULT '',
            blob_path TEXT NOT NULL DEFAULT '',
            blob_bytes INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            clone_allowed INTEGER NOT NULL DEFAULT 0,
            interaction TEXT NOT NULL DEFAULT 'view',
            protected_json TEXT NOT NULL DEFAULT '[]',
            visibility TEXT NOT NULL DEFAULT 'public',
            preview_path TEXT NOT NULL DEFAULT '',
            allow_forward INTEGER,
            pinned INTEGER NOT NULL DEFAULT 0,
            chart_id TEXT NOT NULL DEFAULT '',
            revision INTEGER NOT NULL DEFAULT 1,
            op_seq INTEGER NOT NULL DEFAULT 0,
            live INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE object_grants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            object_kind TEXT NOT NULL,
            object_id TEXT NOT NULL,
            owner_user_id INTEGER NOT NULL,
            grantee_user_id INTEGER,
            grantee_group_id INTEGER,
            right TEXT NOT NULL,
            expires_at TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE grant_group_members (
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL
        );
        CREATE TABLE auth_tokens (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT
        );
        CREATE TABLE web_sessions (
            session_id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            ua_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
    ";

    struct Env {
        state: Arc<AppState>,
        app: Router,
        addr: SocketAddr,
    }

    fn future_ts() -> String {
        (chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339()
    }

    fn bearer(user: i64) -> String {
        format!("token-of-user-{user}")
    }

    fn session(user: i64) -> String {
        format!("session-of-user-{user}")
    }

    async fn start() -> Env {
        let identity = rusqlite::Connection::open_in_memory().expect("identity db");
        identity.execute_batch(SCHEMA).expect("schema");
        let now = chrono::Utc::now().to_rfc3339();
        for user in [AUTHOR, GRANTEE, OUTSIDER] {
            identity
                .execute(
                    "INSERT INTO auth_tokens (token_hash, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, NULL)",
                    rusqlite::params![hash_token(&bearer(user)), user, now],
                )
                .expect("token");
            identity
                .execute(
                    "INSERT INTO web_sessions (session_id, user_id, ua_hash, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![session(user), user, hash_user_agent(""), now, future_ts()],
                )
                .expect("session");
        }
        let scratch = std::env::temp_dir().join("mlc-share-live-tests");
        let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);
        let control_plane = ControlPlane {
            db: Mutex::new(identity),
            ops_db: Mutex::new(rusqlite::Connection::open_in_memory().expect("ops db")),
            social: Mutex::new(rusqlite::Connection::open_in_memory().expect("social db")),
            ops_writer: crate::opswriter::OpsWriter::spawn(
                rusqlite::Connection::open_in_memory().expect("ops writer db"),
                8,
            ),
            sync_store: crate::syncstore::SyncStore::new(scratch.join("sync")),
            share_root: scratch.join("share"),
            data_dir: scratch,
            reserved_nick_cache: std::sync::RwLock::new(Vec::new()),
            live: mylittlechart_server::live::LiveRegistry::new(),
        };
        let state = Arc::new(AppState::new(
            Some(control_plane),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            shutdown_tx,
            Vec::new(),
            false,
            0,
            0,
            None,
        ));
        let app = Router::new().nest("/api", crate::routes::control_api_router(Arc::clone(&state)));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let serving = app.clone();
        tokio::spawn(async move {
            let _ = axum::serve(listener, serving.into_make_service_with_connect_info::<SocketAddr>()).await;
        });
        Env { state, app, addr }
    }

    fn new_share(env: &Env, visibility: &str) -> String {
        let conn = env.state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now().to_rfc3339();
        crate::db::create_share_link(
            &conn, AUTHOR, "live", "chart", "{}", 0, &now, &future_ts(), false, "view", "[]", visibility, None,
        )
        .expect("share")
    }

    fn grant_edit(env: &Env, token: &str, user: i64, expires_at: Option<&str>) -> i64 {
        let conn = env.state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now().to_rfc3339();
        crate::db::upsert_share_edit_grant(&conn, token, AUTHOR, Some(user), None, expires_at, &now)
            .expect("edit grant")
    }

    async fn call(
        env: &Env,
        method: &str,
        path: &str,
        user: Option<i64>,
        json: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(user) = user {
            request = request.header("authorization", format!("Bearer {}", bearer(user)));
        }
        if json.is_some() {
            request = request.header("content-type", "application/json");
        }
        let body = json.map_or_else(Body::empty, |text| Body::from(text.to_string()));
        let response = env.app.clone().oneshot(request.body(body).expect("request")).await.expect("infallible");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.expect("body");
        (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
    }

    async fn stream_open(env: &Env, token: &str, user: Option<i64>) -> (StatusCode, serde_json::Value) {
        call(env, "GET", &format!("/api/share/{token}/stream-open"), user, None).await
    }

    /// The credential an upgrade carries; a browser can only send the cookie.
    enum Upgrade {
        Nothing,
        Cookie(i64),
    }

    async fn connect(
        env: &Env,
        token: &str,
        ticket: &str,
        upgrade: Upgrade,
    ) -> Result<Client, tokio_tungstenite::tungstenite::Error> {
        let mut request = format!("ws://{}/api/share-live/{token}?ticket={ticket}", env.addr).into_client_request()?;
        if let Upgrade::Cookie(user) = upgrade {
            let cookie = format!("session_id={}", session(user));
            request
                .headers_mut()
                .insert("cookie", HeaderValue::from_str(&cookie).expect("cookie header"));
        }
        let stream = TcpStream::connect(env.addr).await.map_err(tokio_tungstenite::tungstenite::Error::Io)?;
        let (ws, _response) = tokio_tungstenite::client_async(request, stream).await?;
        Ok(ws)
    }

    /// stream-open as `user`, then the socket with `upgrade`; returns the socket
    /// and the `publish` stream-open promised.
    async fn open(env: &Env, token: &str, user: Option<i64>, upgrade: Upgrade) -> (Client, bool) {
        let (status, body) = stream_open(env, token, user).await;
        assert_eq!(status, StatusCode::OK, "stream-open for {user:?}: {body}");
        let ticket = body["ticket"].as_str().expect("ticket").to_string();
        let promised = body["publish"].as_bool().expect("publish");
        (connect(env, token, &ticket, upgrade).await.expect("upgrade"), promised)
    }

    async fn next_text(ws: &mut Client) -> String {
        let deadline = Instant::now() + WAIT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, ws.next()).await {
                Ok(Some(Ok(Message::Text(text)))) => return text.as_str().to_owned(),
                Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
                other => panic!("expected a text frame, got {other:?}"),
            }
        }
    }

    async fn close_code_of(ws: &mut Client) -> u16 {
        let deadline = Instant::now() + WAIT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, ws.next()).await {
                Ok(Some(Ok(Message::Close(Some(frame))))) => return u16::from(frame.code),
                Ok(Some(Ok(_))) => {}
                other => panic!("expected a close frame, got {other:?}"),
            }
        }
    }

    async fn expect_welcome(ws: &mut Client, publish: bool) {
        assert_eq!(next_text(ws).await, format!(r#"{{"t":"welcome","publish":{publish}}}"#));
    }

    #[tokio::test]
    async fn stream_open_answers_ticket_publish_and_expiry_and_nothing_about_edges() {
        let env = start().await;
        let token = new_share(&env, "public");
        grant_edit(&env, &token, GRANTEE, None);

        let (status, owner) = stream_open(&env, &token, Some(AUTHOR)).await;
        assert_eq!(status, StatusCode::OK);
        let mut keys: Vec<&str> = owner.as_object().expect("object").keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["expires_in_s", "publish", "ticket"], "no owner / origin / edge fields any more");
        assert_eq!(owner["publish"], true);
        assert_eq!(owner["expires_in_s"], 30);
        let ticket = owner["ticket"].as_str().expect("ticket");
        assert_eq!(ticket.len(), 32);
        assert!(ticket.chars().all(|c| c.is_ascii_hexdigit()));

        let (_, grantee) = stream_open(&env, &token, Some(GRANTEE)).await;
        assert_eq!(grantee["publish"], true);
        let (_, outsider) = stream_open(&env, &token, Some(OUTSIDER)).await;
        assert_eq!(outsider["publish"], false, "a signed-in stranger of a public link only views");
        let (_, signed_out) = stream_open(&env, &token, None).await;
        assert_eq!(signed_out["publish"], false);

        let (_, again) = stream_open(&env, &token, Some(AUTHOR)).await;
        assert_ne!(again["ticket"], owner["ticket"], "every call mints a fresh ticket");
    }

    #[tokio::test]
    async fn stream_open_refuses_with_403_404_and_the_room_ceiling() {
        let env = start().await;
        let private = new_share(&env, "private");
        let (status, _) = stream_open(&env, &private, Some(OUTSIDER)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = stream_open(&env, &private, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = stream_open(&env, "0123456789abcdef0123456789abcdef", Some(AUTHOR)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let revoked = new_share(&env, "public");
        {
            let conn = env.state.control_plane().db.lock().unwrap_or_else(|e| e.into_inner());
            assert!(crate::db::revoke_share(&conn, AUTHOR, &revoked).expect("revoke"));
        }
        let (status, _) = stream_open(&env, &revoked, Some(AUTHOR)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_stream_open_ticket_opens_the_socket_and_frames_flow_both_ways() {
        let env = start().await;
        let token = new_share(&env, "public");
        grant_edit(&env, &token, GRANTEE, None);

        // The author's browser holds a bearer token and no cookie: the upgrade
        // carries no credential, the ticket carries the identity.
        let (mut author, promised) = open(&env, &token, Some(AUTHOR), Upgrade::Nothing).await;
        assert!(promised);
        expect_welcome(&mut author, true).await;
        // The grantee's upgrade carries the grantee's own cookie: it matches the ticket.
        let (mut grantee, _) = open(&env, &token, Some(GRANTEE), Upgrade::Cookie(GRANTEE)).await;
        expect_welcome(&mut grantee, true).await;
        let (mut viewer, promised) = open(&env, &token, None, Upgrade::Nothing).await;
        assert!(!promised);
        expect_welcome(&mut viewer, false).await;

        let drawing = r#"{"t":"p","id":"trend:1","b":"{\"ts\":1700000000000}"}"#;
        author.send(Message::text(drawing)).await.expect("send");
        assert_eq!(next_text(&mut grantee).await, drawing);
        assert_eq!(next_text(&mut viewer).await, drawing);

        let cursor = r#"{"t":"c","b":"{\"ts\":1700000060000}"}"#;
        grantee.send(Message::text(cursor)).await.expect("send");
        assert_eq!(next_text(&mut author).await, cursor);
        assert_eq!(next_text(&mut viewer).await, cursor);
    }

    #[tokio::test]
    async fn a_ticket_is_single_use_and_bound_to_the_account_that_minted_it() {
        let env = start().await;
        let token = new_share(&env, "public");

        let (status, body) = stream_open(&env, &token, Some(AUTHOR)).await;
        assert_eq!(status, StatusCode::OK);
        let ticket = body["ticket"].as_str().expect("ticket").to_string();

        // Another account's cookie on the upgrade: refused, and the ticket survives.
        match connect(&env, &token, &ticket, Upgrade::Cookie(GRANTEE)).await {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                assert_eq!(response.status().as_u16(), 401)
            }
            other => panic!("expected 401, got {:?}", other.map(|_| ())),
        }
        let mut author = connect(&env, &token, &ticket, Upgrade::Cookie(AUTHOR)).await.expect("its own account");
        expect_welcome(&mut author, true).await;

        match connect(&env, &token, &ticket, Upgrade::Cookie(AUTHOR)).await {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                assert_eq!(response.status().as_u16(), 401)
            }
            other => panic!("expected 401 for the used ticket, got {:?}", other.map(|_| ())),
        }
    }

    #[tokio::test]
    async fn revoking_a_grant_closes_only_that_grantees_socket_with_4003() {
        let env = start().await;
        let token = new_share(&env, "public");
        let grant = grant_edit(&env, &token, GRANTEE, None);

        let (mut author, _) = open(&env, &token, Some(AUTHOR), Upgrade::Nothing).await;
        let (mut grantee, _) = open(&env, &token, Some(GRANTEE), Upgrade::Nothing).await;
        let (mut viewer, _) = open(&env, &token, None, Upgrade::Nothing).await;
        expect_welcome(&mut author, true).await;
        expect_welcome(&mut grantee, true).await;
        expect_welcome(&mut viewer, false).await;

        let (status, _) =
            call(&env, "DELETE", &format!("/api/share/{token}/grants/{grant}"), Some(AUTHOR), None).await;
        assert_eq!(status, StatusCode::OK);

        assert_eq!(close_code_of(&mut grantee).await, 4003);
        // The author and the viewer are untouched; the grantee reconnects as a viewer.
        let drawing = r#"{"t":"g","b":{"n":1}}"#;
        author.send(Message::text(drawing)).await.expect("send");
        assert_eq!(next_text(&mut viewer).await, drawing);
        let (mut back, promised) = open(&env, &token, Some(GRANTEE), Upgrade::Nothing).await;
        assert!(!promised, "the reconnect is told publish=false");
        expect_welcome(&mut back, false).await;
    }

    #[tokio::test]
    async fn switching_a_share_to_private_closes_every_socket_that_lost_its_view_right() {
        let env = start().await;
        let token = new_share(&env, "public");
        grant_edit(&env, &token, GRANTEE, None);

        let (mut author, _) = open(&env, &token, Some(AUTHOR), Upgrade::Nothing).await;
        let (mut grantee, _) = open(&env, &token, Some(GRANTEE), Upgrade::Nothing).await;
        let (mut outsider, _) = open(&env, &token, Some(OUTSIDER), Upgrade::Nothing).await;
        let (mut viewer, _) = open(&env, &token, None, Upgrade::Nothing).await;
        for (socket, publish) in [(&mut author, true), (&mut grantee, true), (&mut outsider, false), (&mut viewer, false)] {
            expect_welcome(socket, publish).await;
        }

        let (status, _) =
            call(&env, "PATCH", &format!("/api/share/{token}"), Some(AUTHOR), Some(r#"{"visibility":"private"}"#))
                .await;
        assert_eq!(status, StatusCode::OK);

        assert_eq!(close_code_of(&mut outsider).await, 4003);
        assert_eq!(close_code_of(&mut viewer).await, 4003);
        // The edit grant still opens a private link, so the grantee stays.
        let drawing = r#"{"t":"g","b":{"n":2}}"#;
        author.send(Message::text(drawing)).await.expect("send");
        assert_eq!(next_text(&mut grantee).await, drawing);
    }

    #[tokio::test]
    async fn revoking_the_share_closes_every_socket_with_4003_and_frees_the_room() {
        let env = start().await;
        let token = new_share(&env, "public");

        let (mut author, _) = open(&env, &token, Some(AUTHOR), Upgrade::Nothing).await;
        let (mut viewer, _) = open(&env, &token, None, Upgrade::Nothing).await;
        expect_welcome(&mut author, true).await;
        expect_welcome(&mut viewer, false).await;

        let (status, _) = call(&env, "DELETE", &format!("/api/share/{token}"), Some(AUTHOR), None).await;
        assert_eq!(status, StatusCode::OK);

        assert_eq!(close_code_of(&mut author).await, 4003);
        assert_eq!(close_code_of(&mut viewer).await, 4003);
        let deadline = Instant::now() + WAIT;
        while env.state.share_hub.room_count() != 0 {
            assert!(Instant::now() < deadline, "the room of a revoked share was never freed");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let (status, _) = stream_open(&env, &token, Some(AUTHOR)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn the_timer_recheck_closes_a_socket_whose_edit_grant_expired() {
        let env = start().await;
        let token = new_share(&env, "public");
        let soon = (chrono::Utc::now() + chrono::Duration::milliseconds(1500)).to_rfc3339();
        grant_edit(&env, &token, GRANTEE, Some(&soon));

        let (mut grantee, promised) = open(&env, &token, Some(GRANTEE), Upgrade::Nothing).await;
        assert!(promised);
        expect_welcome(&mut grantee, true).await;

        // No route announces an expiry: only the periodic pass finds it.
        reconcile(&env.state, &token).await;
        let drawing = r#"{"t":"g","b":{"n":3}}"#;
        let (mut author, _) = open(&env, &token, Some(AUTHOR), Upgrade::Nothing).await;
        expect_welcome(&mut author, true).await;
        author.send(Message::text(drawing)).await.expect("send");
        assert_eq!(next_text(&mut grantee).await, drawing, "the grant is still valid");

        tokio::time::sleep(Duration::from_millis(1700)).await;
        reconcile(&env.state, &token).await;
        assert_eq!(close_code_of(&mut grantee).await, 4003);
    }
}

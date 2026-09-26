//! In-memory live channel for one edge. The moving line stays here.
//! The control box is asked once per socket (`stream-open`), then not again.
//!
//! Utah listens on 127.0.0.1:19220 and 10.77.0.11:19220.
//! Amsterdam listens on 127.0.0.1:19220 and 10.77.0.12:19220.
//! A browser that landed on the other edge is bridged over WireGuard.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

#[derive(Clone)]
struct Cfg {
    edge: String,
    peer_ws: String,
    peer_ip: String,
    backend: String,
    wg_bind: String,
}

struct Sub {
    id: u64,
    tx: mpsc::UnboundedSender<String>,
}

struct Room {
    last_g: String,
    last_v: String,
    last_p: String,
    next_id: u64,
    subs: Vec<Sub>,
}

struct App {
    cfg: Cfg,
    rooms: Mutex<HashMap<String, Room>>,
    http: reqwest::Client,
}

#[derive(Deserialize)]
struct BridgeQ {
    #[serde(default)]
    bridge: u8,
    #[serde(default)]
    publish: u8,
}

#[tokio::main]
async fn main() {
    let cfg = Cfg {
        edge: std::env::var("MLC_EDGE").unwrap_or_else(|_| "utah".into()),
        peer_ws: std::env::var("MLC_PEER").unwrap_or_else(|_| "ws://10.77.0.12:19220".into()),
        peer_ip: std::env::var("MLC_PEER_IP").unwrap_or_else(|_| "10.77.0.12".into()),
        backend: std::env::var("MLC_BACKEND").unwrap_or_else(|_| "http://10.77.0.1:19200".into()),
        wg_bind: std::env::var("MLC_WG_BIND").unwrap_or_else(|_| "10.77.0.11:19220".into()),
    };
    let app = Arc::new(App {
        cfg: cfg.clone(),
        rooms: Mutex::new(HashMap::new()),
        http: reqwest::Client::new(),
    });
    let router = Router::new()
        .route("/api/share-live/{token}", get(socket))
        .with_state(app);
    let local = TcpListener::bind("127.0.0.1:19220").await.expect("bind localhost");
    let wg = TcpListener::bind(&cfg.wg_bind).await.expect("bind wg");
    let public = router.clone();
    let tunnel = router;
    tokio::spawn(async move {
        axum::serve(wg, tunnel.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .ok();
    });
    axum::serve(local, public.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .ok();
}

async fn socket(
    State(app): State<Arc<App>>,
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
    Query(q): Query<BridgeQ>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let from_peer = addr.ip().to_string() == app.cfg.peer_ip;
    if q.bridge == 1 {
        if !from_peer {
            return StatusCode::FORBIDDEN.into_response();
        }
        let publish = q.publish == 1;
        return ws.on_upgrade(move |sock| host_room(app, token, sock, publish)).into_response();
    }
    let cookie = header_str(&headers, axum::http::header::COOKIE);
    let auth = header_str(&headers, axum::http::header::AUTHORIZATION);
    let ua = header_str(&headers, axum::http::header::USER_AGENT);
    ws.on_upgrade(move |sock| open_or_bridge(app, token, sock, cookie, auth, ua)).into_response()
}

fn header_str(headers: &HeaderMap, name: axum::http::HeaderName) -> String {
    headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
}

async fn open_or_bridge(app: Arc<App>, token: String, sock: WebSocket, cookie: String, auth: String, ua: String) {
    let mut publish = false;
    let mut owner = String::new();
    for _ in 0..40 {
        let Some((ok, pub_now, owner_now)) = stream_open(&app, &token, &cookie, &auth, &ua).await else {
            return;
        };
        if !ok {
            return;
        }
        publish = pub_now;
        owner = owner_now;
        if publish || !owner.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    eprintln!("share-live {token} publish={publish} owner={owner} edge={}", app.cfg.edge);
    if !publish && owner.is_empty() {
        return;
    }
    if owner.is_empty() || owner == app.cfg.edge {
        host_room(app, token, sock, publish).await;
        return;
    }
    pipe_to_peer(&app, &token, sock, publish).await;
}

async fn stream_open(app: &App, token: &str, cookie: &str, auth: &str, ua: &str) -> Option<(bool, bool, String)> {
    let url = format!("{}/api/share/{token}/stream-open", app.cfg.backend.trim_end_matches('/'));
    let mut req = app.http.get(&url).header("X-Mlc-Edge", &app.cfg.edge);
    if !cookie.is_empty() {
        req = req.header("cookie", cookie);
    }
    if !auth.is_empty() {
        req = req.header("authorization", auth);
    }
    if !ua.is_empty() {
        req = req.header("user-agent", ua);
    }
    let resp = req.send().await.ok()?;
    let ok = resp.status().is_success();
    if !ok {
        eprintln!("share-live stream-open {} {}", token, resp.status());
        return Some((false, false, String::new()));
    }
    let body = resp.json::<serde_json::Value>().await.ok()?;
    let publish = body.get("publish").and_then(|v| v.as_bool()).unwrap_or(false);
    let owner = body.get("owner").and_then(|v| v.as_str()).unwrap_or("").to_string();
    Some((true, publish, owner))
}

async fn host_room(app: Arc<App>, token: String, mut sock: WebSocket, publish: bool) {
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let my_id = {
        let mut rooms = app.rooms.lock().unwrap_or_else(|e| e.into_inner());
        let room = rooms.entry(token.clone()).or_insert_with(|| Room {
            last_g: String::new(),
            last_v: String::new(),
            last_p: String::new(),
            next_id: 1,
            subs: Vec::new(),
        });
        if !room.last_g.is_empty() {
            let _ = tx.send(room.last_g.clone());
        }
        if !room.last_v.is_empty() {
            let _ = tx.send(room.last_v.clone());
        }
        if !room.last_p.is_empty() {
            let _ = tx.send(room.last_p.clone());
        }
        let my_id = room.next_id;
        room.next_id = room.next_id.wrapping_add(1);
        room.subs.push(Sub { id: my_id, tx });
        my_id
    };
    loop {
        tokio::select! {
            incoming = sock.recv() => {
                let Some(Ok(msg)) = incoming else { break };
                let Message::Text(text) = msg else { continue };
                if !publish {
                    continue;
                }
                let text = text.to_string();
                let mut rooms = app.rooms.lock().unwrap_or_else(|e| e.into_inner());
                let Some(room) = rooms.get_mut(&token) else { break };
                if text.contains("\"t\":\"g\"") {
                    room.last_g = text.clone();
                } else if text.contains("\"t\":\"v\"") {
                    room.last_v = text.clone();
                } else if text.contains("\"t\":\"p\"") {
                    room.last_p = text.clone();
                }
                room.subs.retain(|sub| sub.id == my_id || sub.tx.send(text.clone()).is_ok());
            }
            out = rx.recv() => {
                let Some(text) = out else { break };
                if sock.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn pipe_to_peer(app: &App, token: &str, mut browser: WebSocket, publish: bool) {
    let path = format!(
        "/api/share-live/{token}?bridge=1&publish={}",
        if publish { 1 } else { 0 }
    );
    let Some(mut peer) = ws_client(&app.cfg.peer_ws, &path).await else {
        return;
    };
    loop {
        tokio::select! {
            incoming = browser.recv() => {
                let Some(Ok(Message::Text(text))) = incoming else { break };
                if !publish {
                    continue;
                }
                if peer.write_text(&text).await.is_err() {
                    break;
                }
            }
            frame = peer.read_text() => {
                let Some(text) = frame else { break };
                if text.is_empty() {
                    continue;
                }
                if browser.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
        }
    }
}

struct WsClient {
    stream: tokio::net::TcpStream,
}

impl WsClient {
    async fn write_text(&mut self, text: &str) -> std::io::Result<()> {
        let frame = mask_text(text);
        self.stream.write_all(&frame).await
    }

    async fn read_text(&mut self) -> Option<String> {
        read_text_frame(&mut self.stream).await
    }
}

async fn ws_client(peer_ws: &str, path: &str) -> Option<WsClient> {
    let rest = peer_ws.trim_start_matches("ws://");
    let (host, port) = rest.split_once(':').unwrap_or((rest, "19220"));
    let addr = format!("{host}:{port}");
    let mut stream = tokio::net::TcpStream::connect(&addr).await.ok()?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.ok()?;
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await.ok()?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 4096 {
            return None;
        }
    }
    if !buf.windows(3).any(|w| w == b"101") {
        return None;
    }
    Some(WsClient { stream })
}

fn mask_text(text: &str) -> Vec<u8> {
    let payload = text.as_bytes();
    let mask = [0x11u8, 0x22, 0x33, 0x44];
    let mut out = Vec::with_capacity(payload.len() + 8);
    out.push(0x81);
    let len = payload.len();
    if len < 126 {
        out.push(0x80 | len as u8);
    } else if len < 65536 {
        out.push(0x80 | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        out.push(b ^ mask[i % 4]);
    }
    out
}

async fn read_text_frame(stream: &mut tokio::net::TcpStream) -> Option<String> {
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await.ok()?;
    let opcode = hdr[0] & 0x0f;
    let masked = hdr[1] & 0x80 != 0;
    let mut len = (hdr[1] & 0x7f) as usize;
    if len == 126 {
        let mut b = [0u8; 2];
        stream.read_exact(&mut b).await.ok()?;
        len = u16::from_be_bytes(b) as usize;
    } else if len == 127 {
        let mut b = [0u8; 8];
        stream.read_exact(&mut b).await.ok()?;
        len = u64::from_be_bytes(b) as usize;
    }
    if len > 1_000_000 {
        return None;
    }
    let mut mask = [0u8; 4];
    if masked {
        stream.read_exact(&mut mask).await.ok()?;
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload).await.ok()?;
    }
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    if opcode == 0x8 {
        return None;
    }
    if opcode == 0x1 {
        return String::from_utf8(payload).ok();
    }
    Some(String::new())
}

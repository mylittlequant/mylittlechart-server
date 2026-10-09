//! Reverse proxy for `/_matrix` once the messenger runs as its own process.
//!
//! The product server keeps the public listener. When `MESSENGER_UPSTREAM`
//! is set it forwards that prefix byte for byte and does not mount the
//! in-process routes. The chart client does not change.

use axum::body::Body;
use axum::extract::{OriginalUri, Request, State};
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

const BODY_LIMIT: usize = 64 * 1024 * 1024;

#[derive(Clone)]
pub struct Upstream {
    base: String,
    client: reqwest::Client,
}

impl Upstream {
    pub fn new(base: String) -> Self {
        // Loopback only. Do not inherit HTTP_PROXY, and do not follow a
        // redirect — the chart client has to see the messenger's own status.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .expect("messenger upstream client");
        Self { base: base.trim_end_matches('/').to_string(), client }
    }
}

pub fn router(base: String) -> axum::Router {
    axum::Router::new().fallback(forward).with_state(Upstream::new(base))
}

fn hop(name: &header::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
    )
}

fn copy_headers(from: &HeaderMap, to: &mut reqwest::header::HeaderMap) {
    for (name, value) in from {
        if hop(name) {
            continue;
        }
        if let (Ok(n), Ok(v)) = (
            reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            to.append(n, v);
        }
    }
}

async fn forward(State(upstream): State<Upstream>, OriginalUri(uri): OriginalUri, req: Request) -> Response {
    let method = match reqwest::Method::from_bytes(req.method().as_str().as_bytes()) {
        Ok(method) => method,
        Err(_) => return StatusCode::METHOD_NOT_ALLOWED.into_response(),
    };
    let url = match forward_url(&upstream.base, &uri) {
        Ok(url) => url,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let headers_in = req.headers().clone();
    let body = match axum::body::to_bytes(req.into_body(), BODY_LIMIT).await {
        Ok(body) => body,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let mut headers = reqwest::header::HeaderMap::new();
    copy_headers(&headers_in, &mut headers);
    let sent = upstream.client.request(method, url).headers(headers).body(body.to_vec()).send().await;
    let received = match sent {
        Ok(received) => received,
        Err(e) => {
            tracing::warn!("messenger upstream: {e}");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    let status = StatusCode::from_u16(received.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut response = Response::builder().status(status);
    if let Some(out) = response.headers_mut() {
        for (name, value) in received.headers() {
            let name_str = name.as_str();
            if hop_str(name_str) {
                continue;
            }
            if let (Ok(n), Ok(v)) = (
                header::HeaderName::from_bytes(name_str.as_bytes()),
                header::HeaderValue::from_bytes(value.as_bytes()),
            ) {
                out.append(n, v);
            }
        }
    }
    let bytes = match received.bytes().await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!("messenger upstream body: {e}");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    response.body(Body::from(bytes.to_vec())).unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}

fn hop_str(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn forward_url(base: &str, uri: &Uri) -> Result<String, ()> {
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let path_only = path.split('?').next().unwrap_or(path);
    if path_only != "/_matrix" && !path_only.starts_with("/_matrix/") {
        return Err(());
    }
    Ok(format!("{base}{path}"))
}

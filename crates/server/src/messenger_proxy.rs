//! Reverse proxy for `/_matrix` once the messenger runs as its own process.
//!
//! The product server keeps the public listener. When `MESSENGER_UPSTREAM`
//! is set it forwards that prefix and does not mount the in-process
//! routes. A client-supplied `x-account-assertion` is always removed.
//! When `MLC_BRIDGE_SECRET` is set, a resolved chart account gets a
//! signed assertion. The chart client does not change.
//!
//! `M4A_PRODUCT_EDGE_URL`, `M4A_ASSERTION_SECRET` and `M4A_LINK_TOKEN`
//! together replace that upstream. The signature then comes from `m4a-seam`
//! over the path with `/_matrix` removed, and the chart bearer is not
//! forwarded. Any one of the three unset keeps today's proxy.

use axum::body::Body;
use axum::extract::{OriginalUri, Request, State};
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

use crate::state::AppState;

const BODY_LIMIT: usize = 64 * 1024 * 1024;

#[derive(Clone)]
pub struct Upstream {
    base: String,
    client: reqwest::Client,
    app: Arc<AppState>,
    seam: Option<crate::account_bridge::SeamLink>,
}

impl Upstream {
    pub fn new(base: String, app: Arc<AppState>, seam: Option<crate::account_bridge::SeamLink>) -> Self {
        // Loopback only. Do not inherit HTTP_PROXY, and do not follow a
        // redirect — the chart client has to see the messenger's own status.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .expect("messenger upstream client");
        Self { base: base.trim_end_matches('/').to_string(), client, app, seam }
    }
}

pub fn router(
    base: String,
    app: Arc<AppState>,
    seam: Option<crate::account_bridge::SeamLink>,
) -> axum::Router {
    axum::Router::new().fallback(forward).with_state(Upstream::new(base, app, seam))
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
    let path_and_query = uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".to_string());
    let body = match axum::body::to_bytes(req.into_body(), BODY_LIMIT).await {
        Ok(body) => body,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let mut headers = reqwest::header::HeaderMap::new();
    copy_headers(&headers_in, &mut headers);
    headers.remove(crate::account_bridge::ASSERTION_HEADER);
    headers.remove(m4a_seam::DEFAULT_ASSERTION_HEADER);
    headers.remove(m4a_seam::LINK_TOKEN_HEADER);
    headers.remove(m4a_seam::ANON_READ_HEADER);
    let method_name = method.as_str().to_string();
    let app = upstream.app.clone();
    let headers_for_auth = headers_in;
    let seam = upstream.seam.clone();
    let path_for_auth = path_and_query.clone();
    let method_for_auth = method_name.clone();
    let assertion = tokio::task::spawn_blocking(move || {
        assertion_for(&app, &headers_for_auth, &method_for_auth, &path_for_auth, seam.as_ref())
    })
    .await
    .ok()
    .flatten();
    if let Some(link) = &upstream.seam {
        headers.remove(header::AUTHORIZATION);
        if let Ok(value) = reqwest::header::HeaderValue::from_str(&link.token) {
            if let Ok(name) = reqwest::header::HeaderName::from_bytes(m4a_seam::LINK_TOKEN_HEADER.as_bytes()) {
                headers.insert(name, value);
            }
        }
    }
    if let Some(assertion) = assertion {
        let name = if upstream.seam.is_some() {
            m4a_seam::DEFAULT_ASSERTION_HEADER
        } else {
            crate::account_bridge::ASSERTION_HEADER
        };
        if let Ok(value) = reqwest::header::HeaderValue::from_str(&assertion) {
            if let Ok(name) = reqwest::header::HeaderName::from_bytes(name.as_bytes()) {
                headers.insert(name, value);
            }
        }
    } else if upstream.seam.is_some()
        && m4a_seam::anon_read_path_ok(&method_name, crate::account_bridge::core_path(&path_and_query))
    {
        if let Ok(name) = reqwest::header::HeaderName::from_bytes(m4a_seam::ANON_READ_HEADER.as_bytes()) {
            headers.insert(name, reqwest::header::HeaderValue::from_static("1"));
        }
    }
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

fn assertion_for(
    app: &AppState,
    headers: &HeaderMap,
    method: &str,
    path_and_query: &str,
    seam: Option<&crate::account_bridge::SeamLink>,
) -> Option<String> {
    let secret = match seam {
        Some(_) => None,
        None => Some(crate::account_bridge::secret()?),
    };
    let session_id = crate::auth::extract_session_id(headers);
    let bearer = crate::auth::extract_bearer(
        headers.get(header::AUTHORIZATION).and_then(|value| value.to_str().ok()),
    );
    if session_id.is_none() && bearer.is_none() {
        return None;
    }
    let cp = app.control_plane();
    let conn = cp.db.lock().unwrap_or_else(|error| error.into_inner());
    let (user_id, cred_ref) = if let Some(session_id) = session_id {
        let ua_hash = crate::auth::extract_ua_hash(headers);
        let user_id = crate::db::resolve_web_session(&conn, &session_id, &ua_hash).ok().flatten()?;
        (user_id, crate::routes::matrix::auth::web_credential_ref(&session_id))
    } else {
        let raw = bearer?;
        let cred_ref = crate::auth::hash_token(raw);
        let user_id = crate::db::resolve_token_hash_with_expiry(&conn, &cred_ref).ok().flatten()?;
        (user_id, cred_ref)
    };
    let nick = crate::db::nick_for_user(&conn, user_id).ok().flatten()?;
    if nick.is_empty() {
        return None;
    }
    let paid = crate::db::user_is_paid(&conn, user_id).unwrap_or(false);
    if let Some(link) = seam {
        return Some(crate::account_bridge::seam_assertion(
            &link.secret,
            method,
            path_and_query,
            &nick,
            paid,
            &cred_ref,
        ));
    }
    Some(crate::account_bridge::assertion_header(
        secret.as_deref()?,
        method,
        path_and_query,
        &nick,
        paid,
        &cred_ref,
    ))
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

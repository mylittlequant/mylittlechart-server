//! Bearer-token auth middleware for the opsd HTTP API.
//!
//! `/health` is open (d-watchdog liveness). Everything under `/api` requires
//! `Authorization: Bearer <api-key>`; comparison is constant-time (`subtle`)
//! to avoid a timing oracle on the token.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use subtle::ConstantTimeEq;

use crate::state::OpsdState;

pub async fn require_bearer(
    State(state): State<Arc<OpsdState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let provided = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    let ok = match provided {
        Some(token) => token.as_bytes().ct_eq(state.api_key.as_bytes()).into(),
        None => false,
    };
    if ok {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"error": "missing or invalid bearer token"})),
        )
            .into_response()
    }
}

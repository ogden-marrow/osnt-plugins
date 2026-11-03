//! Shared plumbing: JSON errors, blocking helper, request spacing, upstream HTTP helpers and the gateway check.
#![allow(dead_code)]

use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use axum::{
    Json,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

pub fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}
pub fn upstream(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_GATEWAY, msg.into())
}
pub fn not_found(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::NOT_FOUND, msg.into())
}

pub async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, ApiError> + Send + 'static) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f).await.map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

pub fn now_epoch() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Keeps a minimum gap between calls to one upstream (callers hold it only inside blocking tasks).
pub struct Spacer {
    last: Mutex<Option<Instant>>,
    gap: Duration,
}
impl Spacer {
    pub fn new(gap: Duration) -> Self {
        Spacer { last: Mutex::new(None), gap }
    }
    pub fn wait(&self) {
        let Ok(mut g) = self.last.lock() else { return };
        if let Some(t) = *g {
            let el = t.elapsed();
            if el < self.gap {
                std::thread::sleep(self.gap - el);
            }
        }
        *g = Some(Instant::now());
    }
}

/// Percent-encode a query value (everything except unreserved characters).
pub fn enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Map a transport or status failure to a short message that never contains URLs, keys or headers.
pub fn map_ureq(what: &str, e: ureq::Error) -> ApiError {
    match e {
        ureq::Error::StatusCode(429) => upstream(format!("{what} is rate limiting requests (HTTP 429); wait a little and try again")),
        ureq::Error::StatusCode(401) | ureq::Error::StatusCode(403) => upstream(format!("{what} refused the request (HTTP {}); access may need a key or a declared contact", match e { ureq::Error::StatusCode(c) => c, _ => 0 })),
        ureq::Error::StatusCode(c) => upstream(format!("{what} answered HTTP {c}")),
        ureq::Error::Timeout(_) => upstream(format!("{what} timed out")),
        _ => upstream(format!("could not reach {what}")),
    }
}

pub fn read_value(what: &str, mut res: ureq::http::Response<ureq::Body>) -> Result<Value, ApiError> {
    res.body_mut().with_config().limit(32 << 20).read_json::<Value>().map_err(|_| upstream(format!("{what} sent an unreadable response")))
}

/// GET returning JSON; `Ok(None)` for HTTP 404.
pub fn get_json(agent: &ureq::Agent, url: &str, headers: &[(&str, &str)], what: &str) -> Result<Option<Value>, ApiError> {
    let mut req = agent.get(url).header("Accept", "application/json");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    match req.call() {
        Ok(res) => read_value(what, res).map(Some),
        Err(ureq::Error::StatusCode(404)) => Ok(None),
        Err(e) => Err(map_ureq(what, e)),
    }
}

pub fn post_json(agent: &ureq::Agent, url: &str, body: &Value, headers: &[(&str, &str)], what: &str) -> Result<Value, ApiError> {
    let mut req = agent.post(url).header("Accept", "application/json");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    req.send_json(body).map_err(|e| map_ureq(what, e)).and_then(|r| read_value(what, r))
}

/// Gateway check for every /api route: the hub signs requests from the signed-in browser. Set the flag
/// (the plugin's *_INSECURE_LOCAL variable) only for local development.
pub async fn gate(State(open): State<bool>, req: Request, next: Next) -> Response {
    let ok = open
        || osnt_common::gateway_authorized(
            req.method().as_str(),
            req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/"),
            req.headers().get("x-osnt-gateway").and_then(|v| v.to_str().ok()),
        );
    if ok {
        next.run(req).await
    } else {
        ApiError(StatusCode::UNAUTHORIZED, "sign in through the OSNT hub to use this plugin".into()).into_response()
    }
}

//! Shared plumbing: JSON errors, query-parameter parsing with clear messages, a small TTL cache and the hub-signature guard.

use std::{
    collections::HashMap,
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
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError(StatusCode::BAD_GATEWAY, format!("{e:#}"))
    }
}
pub fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

pub async fn blocking<T: Send + 'static>(f: impl FnOnce() -> anyhow::Result<T> + Send + 'static) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f).await.map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?.map_err(Into::into)
}

/// Like `blocking` but the closure already produces an `ApiError`, so its status code is kept.
pub async fn blocking_api<T: Send + 'static>(f: impl FnOnce() -> Result<T, ApiError> + Send + 'static) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f).await.map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

/// Query parameters as strings, with typed getters that produce readable 400 errors.
pub struct Params(pub HashMap<String, String>);

impl Params {
    pub fn str(&self, k: &str) -> Option<&str> {
        self.0.get(k).map(|s| s.trim()).filter(|s| !s.is_empty())
    }
    pub fn req_str(&self, k: &str) -> Result<&str, ApiError> {
        self.str(k).ok_or_else(|| bad(format!("{k} is required")))
    }
    pub fn num(&self, k: &str, lo: f64, hi: f64) -> Result<Option<f64>, ApiError> {
        match self.str(k) {
            None => Ok(None),
            Some(s) => {
                let v: f64 = s.parse().map_err(|_| bad(format!("{k} must be a number")))?;
                if !v.is_finite() || v < lo || v > hi {
                    return Err(bad(format!("{k} must be between {lo} and {hi}")));
                }
                Ok(Some(v))
            }
        }
    }
    pub fn req_num(&self, k: &str, lo: f64, hi: f64) -> Result<f64, ApiError> {
        self.num(k, lo, hi)?.ok_or_else(|| bad(format!("{k} is required")))
    }
    pub fn lat_lon(&self) -> Result<(f64, f64), ApiError> {
        Ok((self.req_num("lat", -90.0, 90.0)?, self.req_num("lon", -180.0, 180.0)?))
    }
}

/// Small TTL cache with a hard entry cap: expired entries go first, then the oldest.
pub struct Cache {
    ttl: Duration,
    cap: usize,
    map: Mutex<HashMap<String, (Instant, Value)>>,
}

impl Cache {
    pub fn new(ttl: Duration, cap: usize) -> Self {
        Cache { ttl, cap, map: Mutex::new(HashMap::new()) }
    }
    pub fn get(&self, key: &str) -> Option<Value> {
        let m = self.map.lock().ok()?;
        m.get(key).filter(|(t, _)| t.elapsed() < self.ttl).map(|(_, v)| v.clone())
    }
    pub fn put(&self, key: String, v: Value) {
        let Ok(mut m) = self.map.lock() else { return };
        if m.len() >= self.cap && !m.contains_key(&key) {
            let ttl = self.ttl;
            m.retain(|_, (t, _)| t.elapsed() < ttl);
            while m.len() >= self.cap {
                let Some(oldest) = m.iter().min_by_key(|(_, (t, _))| *t).map(|(k, _)| k.clone()) else { break };
                m.remove(&oldest);
            }
        }
        m.insert(key, (Instant::now(), v));
    }
    pub fn len(&self) -> usize {
        self.map.lock().map(|m| m.len()).unwrap_or(0)
    }
}

/// Implemented by the app state so the guard knows whether signatures are required.
pub trait Guarded {
    fn require_gateway(&self) -> bool;
}

/// Middleware for /api routes: when the hub's gateway key is configured, only signed requests pass.
pub async fn guard<S: Guarded + Send + Sync + 'static>(State(s): State<std::sync::Arc<S>>, req: Request, next: Next) -> Response {
    if s.require_gateway() {
        let path = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let sig = req.headers().get("x-osnt-gateway").and_then(|v| v.to_str().ok());
        if !osnt_common::gateway_authorized(req.method().as_str(), path, sig) {
            return ApiError(StatusCode::UNAUTHORIZED, "sign in required".into()).into_response();
        }
    }
    next.run(req).await
}

/// True when the hub has handed this plugin a signing key, so /api must verify signatures.
pub fn gateway_configured() -> bool {
    std::env::var("OSNT_GATEWAY_KEY").map(|v| !v.is_empty()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_expires_and_evicts() {
        let c = Cache::new(Duration::from_millis(40), 3);
        for i in 0..5 {
            c.put(format!("k{i}"), json!(i));
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(c.len(), 3);
        assert!(c.get("k0").is_none() && c.get("k1").is_none());
        assert_eq!(c.get("k4"), Some(json!(4)));
        std::thread::sleep(Duration::from_millis(60));
        assert!(c.get("k4").is_none());
        c.put("x".into(), json!(1));
        assert!(c.len() <= 3);
    }

    #[test]
    fn params_validate() {
        let p = Params([("lat".to_string(), "91".to_string()), ("lon".to_string(), "abc".to_string()), ("n".to_string(), " 5 ".to_string())].into());
        assert!(p.req_num("lat", -90.0, 90.0).is_err());
        assert!(p.req_num("lon", -180.0, 180.0).is_err());
        assert_eq!(p.req_num("n", 0.0, 10.0).unwrap(), 5.0);
        assert!(p.req_num("missing", 0.0, 1.0).is_err());
        assert_eq!(p.num("missing", 0.0, 1.0).unwrap(), None);
        let p = Params([("n".to_string(), "NaN".to_string())].into());
        assert!(p.num("n", 0.0, 10.0).is_err());
    }
}

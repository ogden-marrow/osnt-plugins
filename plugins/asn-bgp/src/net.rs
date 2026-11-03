//! Shared plumbing: API errors, gateway authorisation, a polite HTTP client (per-host spacing, size caps, short error
//! messages that never carry secrets), input validation helpers and a tiny bounded parallel map.

use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};
use axum::{
    Json,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

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
pub fn bad(msg: &str) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

/// Every /api route needs the hub's signature (the user is signed in). Local development can set
/// OSNT_INSECURE_DEV=1 to skip the check; the installer never sets it.
pub fn authorized(method: &Method, uri: &Uri, headers: &HeaderMap) -> Result<(), ApiError> {
    if std::env::var("OSNT_INSECURE_DEV").as_deref() == Ok("1") {
        return Ok(());
    }
    let ok = osnt_common::gateway_authorized(
        method.as_str(),
        uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"),
        headers.get("x-osnt-gateway").and_then(|v| v.to_str().ok()),
    );
    if ok { Ok(()) } else { Err(ApiError(StatusCode::UNAUTHORIZED, "sign in through the OSNT hub to use this plugin".into())) }
}

pub async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f).await.map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?.map_err(Into::into)
}

/// Reserves time slots per host so concurrent callers queue up instead of bursting.
#[derive(Default)]
pub struct Throttle(Mutex<HashMap<String, Instant>>);

impl Throttle {
    pub fn wait(&self, host: &str, gap: Duration) {
        if gap.is_zero() {
            return;
        }
        let sleep = {
            let mut m = self.0.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            let next = m.get(host).map(|t| *t + gap).filter(|t| *t > now).unwrap_or(now);
            m.insert(host.to_string(), next);
            next - now
        };
        if !sleep.is_zero() {
            std::thread::sleep(sleep);
        }
    }
}

pub struct Req<'a> {
    pub url: &'a str,
    pub accept: &'a str,
    pub gap: Duration,
    pub headers: Vec<(&'a str, String)>,
    pub max_bytes: u64,
    pub timeout: Duration,
}

impl<'a> Req<'a> {
    pub fn new(url: &'a str) -> Self {
        Req { url, accept: "application/json", gap: Duration::ZERO, headers: Vec::new(), max_bytes: 8 * 1024 * 1024, timeout: Duration::from_secs(15) }
    }
    pub fn accept(mut self, a: &'a str) -> Self {
        self.accept = a;
        self
    }
    pub fn gap(mut self, ms: u64) -> Self {
        self.gap = Duration::from_millis(ms);
        self
    }
    pub fn header(mut self, k: &'a str, v: String) -> Self {
        self.headers.push((k, v));
        self
    }
    pub fn timeout(mut self, secs: u64) -> Self {
        self.timeout = Duration::from_secs(secs);
        self
    }
    pub fn max_bytes(mut self, n: u64) -> Self {
        self.max_bytes = n;
        self
    }
}

/// A non-2xx answer from an upstream. Callers can look at the code (for example to treat 404 as "no data").
#[derive(Debug)]
pub struct HttpStatus {
    pub host: String,
    pub code: u16,
}
impl std::fmt::Display for HttpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.code == 429 { write!(f, "{}: rate limited (HTTP 429), try again later", self.host) } else { write!(f, "{}: HTTP {}", self.host, self.code) }
    }
}
impl std::error::Error for HttpStatus {}
pub fn status_of(e: &anyhow::Error) -> Option<u16> {
    e.downcast_ref::<HttpStatus>().map(|s| s.code)
}

pub fn host_of(url: &str) -> &str {
    url.split("://").nth(1).unwrap_or(url).split(['/', '?']).next().unwrap_or("")
}

pub struct Http {
    pub agent: ureq::Agent,
    pub throttle: Throttle,
}

impl Http {
    pub fn new(user_agent: &str) -> Http {
        Http { agent: osnt_common::http_agent(user_agent), throttle: Throttle::default() }
    }

    pub fn text(&self, r: Req) -> Result<String> {
        let host = host_of(r.url).to_string();
        self.throttle.wait(&host, r.gap);
        let mut b = self.agent.get(r.url).config().timeout_global(Some(r.timeout)).build().header("Accept", r.accept);
        for (k, v) in &r.headers {
            b = b.header(*k, v.as_str());
        }
        match b.call() {
            Ok(mut res) => res.body_mut().with_config().limit(r.max_bytes).read_to_string().map_err(|e| anyhow!("{host}: could not read the response ({e})")),
            Err(ureq::Error::StatusCode(c)) => Err(anyhow::Error::new(HttpStatus { host, code: c })),
            Err(ureq::Error::Timeout(_)) => Err(anyhow!("{host}: timed out")),
            Err(e) => Err(anyhow!("{host}: request failed ({})", short(&e))),
        }
    }

    pub fn json(&self, r: Req) -> Result<Value> {
        let host = host_of(r.url).to_string();
        let t = self.text(r)?;
        serde_json::from_str(&t).map_err(|_| anyhow!("{host}: the response was not valid JSON"))
    }
}

fn short(e: &ureq::Error) -> String {
    let s = e.to_string();
    s.chars().take(120).collect()
}

/// Hostname check for user input: ASCII letters, digits, hyphens, dots; at least one dot; a non-numeric last label.
pub fn valid_domain(s: &str) -> Option<String> {
    domain_checked(s, false)
}

/// Same, but also accepts underscores (names seen in the wild such as `_dmarc.example.com`).
pub fn valid_found_name(s: &str) -> Option<String> {
    domain_checked(s, true)
}

fn domain_checked(s: &str, underscore: bool) -> Option<String> {
    let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
    let ok = !s.is_empty()
        && s.len() <= 253
        && s.contains('.')
        && s.split('.').all(|l| {
            !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || (underscore && c == '_'))
        })
        && !s.rsplit('.').next().unwrap_or("").chars().all(|c| c.is_ascii_digit());
    ok.then_some(s)
}

/// Accept a pasted URL or host: strip scheme, credentials-free path, port and leading `www.` is kept as typed.
pub fn host_from_input(s: &str) -> Option<String> {
    let s = s.trim();
    let s = s.split("://").last().unwrap_or(s);
    let s = s.split(['/', '?', '#']).next().unwrap_or("");
    if s.contains('@') {
        return None;
    }
    let s = s.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map(|(h, _)| h).unwrap_or(s);
    valid_domain(s)
}

/// Run `f` over `items` with at most `n` worker threads, keeping the order of the results.
pub fn par_map<T: Sync, R: Send>(items: &[T], n: usize, f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let next = AtomicUsize::new(0);
    let out: Mutex<Vec<(usize, R)>> = Mutex::new(Vec::with_capacity(items.len()));
    std::thread::scope(|s| {
        for _ in 0..n.max(1).min(items.len().max(1)) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    let Some(item) = items.get(i) else { break };
                    let r = f(item);
                    out.lock().unwrap_or_else(|e| e.into_inner()).push((i, r));
                }
            });
        }
    });
    let mut v = out.into_inner().unwrap_or_else(|e| e.into_inner());
    v.sort_by_key(|(i, _)| *i);
    v.into_iter().map(|(_, r)| r).collect()
}

/// Great-circle distance in kilometres.
pub fn haversine_km(a: (f64, f64), b: (f64, f64)) -> f64 {
    let (la1, lo1, la2, lo2) = (a.0.to_radians(), a.1.to_radians(), b.0.to_radians(), b.1.to_radians());
    let h = ((la2 - la1) / 2.0).sin().powi(2) + la1.cos() * la2.cos() * ((lo2 - lo1) / 2.0).sin().powi(2);
    6371.0 * 2.0 * h.sqrt().asin()
}

/// Tiny fake HTTP server for tests: maps a path-and-query prefix to a (status, body) response.
#[cfg(test)]
pub mod fake {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{Arc, Mutex},
        thread,
    };

    pub type Handler = dyn Fn(&str) -> (u16, String, String) + Send + Sync;

    /// Starts a server; returns (base url, log of requested path+query). Handler returns (status, content-type, body).
    pub fn spawn(handler: Arc<Handler>) -> (String, Arc<Mutex<Vec<String>>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        thread::spawn(move || {
            for stream in l.incoming() {
                let Ok(mut s) = stream else { continue };
                let h = handler.clone();
                let log = log2.clone();
                thread::spawn(move || {
                    let mut buf = [0u8; 8192];
                    let n = s.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                    log.lock().unwrap().push(path.clone());
                    let (status, ct, body) = h(&path);
                    let resp = format!("HTTP/1.1 {status} X\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    let _ = s.write_all(resp.as_bytes());
                });
            }
        });
        (format!("http://127.0.0.1:{port}"), log)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn domain_validation() {
        assert_eq!(valid_domain(" Example.COM. ").as_deref(), Some("example.com"));
        assert_eq!(valid_domain("a-b.co.uk").as_deref(), Some("a-b.co.uk"));
        for bad in ["", "localhost", "exa mple.com", "-a.com", "a-.com", "a..com", "1.2.3.4", "a.com/path", "a_b.com", "münchen.de", "http://a.com", &format!("{}.com", "a".repeat(64))] {
            assert!(valid_domain(bad).is_none(), "{bad} should be rejected");
        }
        assert_eq!(valid_found_name("_dmarc.example.com").as_deref(), Some("_dmarc.example.com"));
        assert!(valid_found_name("user@example.com").is_none());
    }

    #[test]
    fn host_from_pasted_url() {
        assert_eq!(host_from_input("https://www.Example.com:8443/a/b?c=d").as_deref(), Some("www.example.com"));
        assert_eq!(host_from_input("example.org").as_deref(), Some("example.org"));
        assert!(host_from_input("https://user:pw@example.org/").is_none());
        assert!(host_from_input("not a host").is_none());
    }

    #[test]
    fn par_map_keeps_order_and_bounds_workers() {
        let items: Vec<u32> = (0..20).collect();
        let live = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let out = par_map(&items, 3, |i| {
            let n = live.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(n, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(5));
            live.fetch_sub(1, Ordering::SeqCst);
            i * 2
        });
        assert_eq!(out, (0..20).map(|i| i * 2).collect::<Vec<_>>());
        assert!(peak.load(Ordering::SeqCst) <= 3);
        assert!(par_map::<u32, u32>(&[], 4, |i| *i).is_empty());
    }

    #[test]
    fn throttle_spaces_calls() {
        let t = Throttle::default();
        let start = Instant::now();
        for _ in 0..3 {
            t.wait("h", Duration::from_millis(60));
        }
        assert!(start.elapsed() >= Duration::from_millis(115));
        let s2 = Instant::now();
        t.wait("other-host", Duration::from_millis(60));
        assert!(s2.elapsed() < Duration::from_millis(30));
    }

    #[test]
    fn http_errors_are_short_and_classified() {
        let (base, _) = fake::spawn(Arc::new(|p: &str| match p {
            "/ok" => (200, "application/json".into(), r#"{"a":1}"#.into()),
            "/429" => (429, "text/plain".into(), "slow down".into()),
            "/500" => (500, "text/plain".into(), "oops".into()),
            "/html" => (200, "text/html".into(), "<html>".into()),
            _ => (404, "text/plain".into(), "nf".into()),
        }));
        let h = Http::new("osnt-test/0.1");
        assert_eq!(h.json(Req::new(&format!("{base}/ok"))).unwrap()["a"], 1);
        assert!(h.json(Req::new(&format!("{base}/429"))).unwrap_err().to_string().contains("rate limited"));
        let e500 = h.json(Req::new(&format!("{base}/500"))).unwrap_err();
        assert!(e500.to_string().contains("HTTP 500"));
        assert_eq!(status_of(&e500), Some(500));
        assert!(h.json(Req::new(&format!("{base}/html"))).unwrap_err().to_string().contains("not valid JSON"));
        assert!(h.text(Req::new("http://127.0.0.1:1/x").timeout(2)).is_err());
    }

    #[test]
    fn haversine_is_sane() {
        assert!(haversine_km((0.0, 0.0), (0.0, 0.0)) < 0.001);
        let d = haversine_km((51.5, -0.12), (48.85, 2.35));
        assert!((330.0..350.0).contains(&d), "{d}");
    }
}

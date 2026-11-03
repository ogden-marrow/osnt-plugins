//! Shared plumbing: error type, gateway-signature check, TTL cache, input validation and small upstream helpers.
//! (Each plugin is a standalone crate, so this file is kept identical across the threat-intel plugins.)
#![allow(dead_code)]

use std::{
    collections::HashMap,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
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

pub struct ApiError(pub StatusCode, pub String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}
pub fn bad(msg: &str) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}
pub fn upstream(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_GATEWAY, msg.into())
}

pub async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f).await.map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

// ---- gateway authorisation -------------------------------------------------------------------------------------

pub type Authz = fn(&str, &str, Option<&str>) -> bool;

/// The real check: the hub signs every request it proxies for a signed-in user.
pub fn real_authz(method: &str, path_and_query: &str, header: Option<&str>) -> bool {
    osnt_common::gateway_authorized(method, path_and_query, header)
}

/// Middleware for every `/api` route: these calls spend upstream quota (and sometimes the user's API keys), so only
/// requests the hub vouched for are served.
pub async fn require_gateway(State(authz): State<Authz>, req: Request, next: Next) -> Response {
    let pq = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/").to_string();
    let hdr = req.headers().get("x-osnt-gateway").and_then(|v| v.to_str().ok()).map(str::to_owned);
    if !authz(req.method().as_str(), &pq, hdr.as_deref()) {
        return ApiError(StatusCode::UNAUTHORIZED, "sign in through the OSNT hub to use this API".into()).into_response();
    }
    next.run(req).await
}

// ---- cache -----------------------------------------------------------------------------------------------------

/// Small in-memory TTL cache with a hard entry cap (oldest entries are evicted first).
pub struct TtlCache<V: Clone> {
    ttl: Duration,
    cap: usize,
    map: Mutex<HashMap<String, (Instant, V)>>,
}

impl<V: Clone> TtlCache<V> {
    pub fn new(ttl: Duration, cap: usize) -> Self {
        Self { ttl, cap: cap.max(1), map: Mutex::new(HashMap::new()) }
    }
    pub fn get(&self, key: &str) -> Option<V> {
        let mut m = self.map.lock().unwrap_or_else(|e| e.into_inner());
        match m.get(key) {
            Some((t, v)) if t.elapsed() < self.ttl => Some(v.clone()),
            Some(_) => {
                m.remove(key);
                None
            }
            None => None,
        }
    }
    pub fn put(&self, key: &str, v: V) {
        let mut m = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() >= self.cap && !m.contains_key(key) {
            let ttl = self.ttl;
            m.retain(|_, (t, _)| t.elapsed() < ttl);
            while m.len() >= self.cap {
                let Some(oldest) = m.iter().min_by_key(|(_, (t, _))| *t).map(|(k, _)| k.clone()) else { break };
                m.remove(&oldest);
            }
        }
        m.insert(key.to_string(), (Instant::now(), v));
    }
    pub fn len(&self) -> usize {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

// ---- validation ------------------------------------------------------------------------------------------------

/// A hostname: letters, digits, dots and hyphens only, with at least one dot. Returns it lower-cased.
pub fn valid_domain(s: &str) -> Option<String> {
    let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
    let ok = s.len() <= 253
        && s.contains('.')
        && s.split('.').all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        && !s.split('.').next_back().is_some_and(|tld| tld.chars().all(|c| c.is_ascii_digit()));
    ok.then_some(s)
}

fn v4_public(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xC0) == 64)
        || (o[0] == 192 && o[1] == 0 && (o[2] == 0 || o[2] == 2))
        || (o[0] == 198 && (o[1] & 0xFE) == 18)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || o[0] >= 240)
}

fn v6_public(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return v4_public(v4);
    }
    let s = ip.segments();
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    if (s[0] & 0xFE00) == 0xFC00 || (s[0] & 0xFFC0) == 0xFE80 || (s[0] & 0xFFC0) == 0xFEC0 {
        return false;
    }
    if s[..6] == [0; 6] || s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return false;
    }
    !(s[0] == 0x2001 && (s[1] == 0 || s[1] == 0x0db8) || s[0] == 0x2002)
}

/// True only for a globally routable public address.
pub fn ip_is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v4_public(v),
        IpAddr::V6(v) => v6_public(v),
    }
}

/// Parse a public IP literal (private, loopback and reserved addresses are rejected: nothing to report on them).
pub fn parse_public_ip(s: &str) -> Result<IpAddr, ApiError> {
    let ip: IpAddr = s.trim().trim_start_matches('[').trim_end_matches(']').parse().map_err(|_| bad("not a valid IP address"))?;
    if ip_is_public(ip) { Ok(ip) } else { Err(bad("that is a private, loopback or reserved address, which has no public data")) }
}

// ---- upstream fetching -----------------------------------------------------------------------------------------

#[derive(Debug)]
pub enum UpErr {
    NotFound,
    /// Rate limited or access denied by the upstream (429, 401, 403).
    Denied(u16),
    Status(u16),
    Other(String),
}

impl std::fmt::Display for UpErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpErr::NotFound => write!(f, "not found upstream"),
            UpErr::Denied(429) => write!(f, "rate limited by the upstream (HTTP 429)"),
            UpErr::Denied(c) => write!(f, "upstream refused the request (HTTP {c})"),
            UpErr::Status(c) => write!(f, "upstream error (HTTP {c})"),
            UpErr::Other(m) => write!(f, "{m}"),
        }
    }
}

fn map_err(e: ureq::Error) -> UpErr {
    match e {
        ureq::Error::StatusCode(404) => UpErr::NotFound,
        ureq::Error::StatusCode(c @ (401 | 403 | 429)) => UpErr::Denied(c),
        ureq::Error::StatusCode(c) => UpErr::Status(c),
        // Never echo the URL (it can carry an API key path or a user's indicator); the kind is enough.
        ureq::Error::Timeout(_) => UpErr::Other("upstream timed out".into()),
        ureq::Error::HostNotFound => UpErr::Other("upstream host not found".into()),
        ureq::Error::Io(_) | ureq::Error::ConnectionFailed => UpErr::Other("could not connect to the upstream".into()),
        _ => UpErr::Other("upstream request failed".into()),
    }
}

pub fn get_text(agent: &ureq::Agent, url: &str, headers: &[(&str, &str)], max_bytes: u64) -> Result<String, UpErr> {
    let mut req = agent.get(url);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let mut res = req.call().map_err(map_err)?;
    let mut buf = String::new();
    res.body_mut().as_reader().take(max_bytes).read_to_string(&mut buf).map_err(|_| UpErr::Other("could not read the upstream response".into()))?;
    Ok(buf)
}

pub fn get_json(agent: &ureq::Agent, url: &str, headers: &[(&str, &str)]) -> Result<Value, UpErr> {
    let text = get_text(agent, url, headers, 16 * 1024 * 1024)?;
    serde_json::from_str(&text).map_err(|_| UpErr::Other("upstream returned something that is not JSON".into()))
}

/// Current time as an RFC 3339 UTC string without pulling in a date crate.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Civil date (UTC) `YYYY-MM-DD` for a unix timestamp.
pub fn ymd(ts: u64) -> String {
    let days = (ts / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{:02}-{:02}", if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn iso_now() -> String {
    let t = unix_now();
    format!("{}T{:02}:{:02}:{:02}Z", ymd(t), (t % 86_400) / 3600, (t % 3600) / 60, t % 60)
}

/// Percent-encode a query value (unreserved characters pass through).
pub fn enc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains() {
        assert_eq!(valid_domain(" Example.COM. ").as_deref(), Some("example.com"));
        for bad in ["localhost", "a..b", "-a.com", "a-.com", "exa mple.com", "a.com/x", "1.2.3.4", "a.com:80", "", "a_b.com", &"a".repeat(64).to_string()] {
            assert!(valid_domain(bad).is_none(), "{bad}");
        }
        assert!(valid_domain(&format!("{}.com", "a".repeat(64))).is_none());
    }

    #[test]
    fn public_ips() {
        for ok in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(parse_public_ip(ok).is_ok(), "{ok}");
        }
        for no in ["10.0.0.1", "127.0.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fc00::1", "192.0.2.1", "255.255.255.255", "nope", "1.2.3", "1.2.3.4.5", "::ffff:10.0.0.1"] {
            assert!(parse_public_ip(no).is_err(), "{no}");
        }
    }

    #[test]
    fn cache_ttl_and_cap() {
        let c: TtlCache<u32> = TtlCache::new(Duration::from_millis(60), 3);
        c.put("a", 1);
        assert_eq!(c.get("a"), Some(1));
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(c.get("a"), None);
        for (i, k) in ["a", "b", "c", "d", "e"].iter().enumerate() {
            c.put(k, i as u32);
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(c.len() <= 3);
        assert_eq!(c.get("e"), Some(4));
        assert_eq!(c.get("a"), None);
    }

    #[test]
    fn dates() {
        assert_eq!(ymd(0), "1970-01-01");
        assert_eq!(ymd(1_709_164_800), "2024-02-29");
        assert_eq!(ymd(1_793_000_000), "2026-10-26");
        assert_eq!(enc("a b&c=d/é"), "a%20b%26c%3Dd%2F%C3%A9");
    }
}

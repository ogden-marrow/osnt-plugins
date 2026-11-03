//! Small shared helpers: error type, URL encoding, UTC date maths and a cached, size-capped upstream fetcher.

use std::{
    io::Read,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::cache::DiskCache;

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
pub fn upstream_err(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_GATEWAY, msg.into())
}

pub fn enc(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

pub fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Days since 1970-01-01 -> (year, month, day) (proleptic Gregorian).
pub fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `YYYY-MM-DD` for a unix time.
pub fn ymd(secs: i64) -> String {
    let (y, m, d) = civil(secs.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a unix time.
pub fn iso(secs: i64) -> String {
    let r = secs.rem_euclid(86_400);
    format!("{}T{:02}:{:02}:{:02}Z", ymd(secs), r / 3600, r % 3600 / 60, r % 60)
}

/// Parses `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM[:SS[.fff]][Z]` into unix seconds; an offset such as -09:00 is applied, no offset means UTC.
pub fn parse_iso(s: &str) -> Option<i64> {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() < 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let (y, m, d): (i64, i64, i64) = (s.get(0..4)?.parse().ok()?, s.get(5..7)?.parse().ok()?, s.get(8..10)?.parse().ok()?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || !(1900..=2200).contains(&y) {
        return None;
    }
    let mut secs = days_from_civil(y, m, d) * 86_400;
    if b.len() > 10 {
        if b[10] != b'T' && b[10] != b' ' {
            return None;
        }
        let (h, mi): (i64, i64) = (s.get(11..13)?.parse().ok()?, s.get(14..16)?.parse().ok()?);
        let sec: i64 = s.get(17..19).and_then(|x| x.parse().ok()).unwrap_or(0);
        if h > 23 || mi > 59 || sec > 60 {
            return None;
        }
        secs += h * 3600 + mi * 60 + sec;
        // Optional fraction, then Z or a +HH:MM / -HH:MM offset (applied so the result is UTC).
        let mut rest = s.get(19..).unwrap_or("");
        if let Some(r) = rest.strip_prefix('.') {
            rest = r.trim_start_matches(|c: char| c.is_ascii_digit());
        }
        if let Some(sign) = rest.chars().next().filter(|c| *c == '+' || *c == '-') {
            let off = &rest[1..];
            let (oh, om): (i64, i64) = (off.get(0..2)?.parse().ok()?, off.get(3..5).or(off.get(2..4)).and_then(|x| x.parse().ok()).unwrap_or(0));
            secs -= (if sign == '+' { 1 } else { -1 }) * (oh * 3600 + om * 60);
        }
    }
    Some(secs)
}

#[allow(dead_code)]
pub fn valid_date(s: &str) -> bool {
    s.len() == 10 && parse_iso(s).is_some()
}

pub struct Fetched {
    pub body: Vec<u8>,
    /// True when the live upstream failed and an older cached copy was served instead.
    pub stale: bool,
}

/// Cached upstream access. Blocking; call it from `spawn_blocking`.
pub struct Upstream {
    pub agent: ureq::Agent,
    pub cache: DiskCache,
}

pub const MAX_BODY: u64 = 24 * 1024 * 1024;
/// A cached copy older than this is never served, even when the upstream is down.
pub const STALE_LIMIT: Duration = Duration::from_secs(24 * 3600);

impl Upstream {
    pub fn fetch_live(&self, url: &str) -> Result<Vec<u8>, String> {
        let mut res = self.agent.get(url).header("Accept", "application/json, application/xml, text/xml, */*").call().map_err(|e| match e {
            ureq::Error::StatusCode(429) => "the data service is rate limiting this plugin (HTTP 429); try again later".to_string(),
            ureq::Error::StatusCode(c) => format!("the data service answered HTTP {c}"),
            ureq::Error::Timeout(_) => "the data service timed out".to_string(),
            _ => "the data service could not be reached".to_string(),
        })?;
        let mut buf = Vec::new();
        res.body_mut().with_config().limit(MAX_BODY).reader().take(MAX_BODY + 1).read_to_end(&mut buf).map_err(|_| "the data service sent an unreadable response".to_string())?;
        if buf.len() as u64 > MAX_BODY {
            return Err("the data service response was larger than the plugin allows".into());
        }
        Ok(buf)
    }

    /// Fresh cache hit, else a live fetch (stored), else a stale cached copy, else the error.
    pub fn get(&self, url: &str, ttl: Duration) -> Result<Fetched, String> {
        if let Some(body) = self.cache.get(url, ttl) {
            return Ok(Fetched { body, stale: false });
        }
        match self.fetch_live(url) {
            Ok(body) => {
                self.cache.put(url, &body);
                Ok(Fetched { body, stale: false })
            }
            Err(e) => match self.cache.get(url, STALE_LIMIT) {
                Some(body) => Ok(Fetched { body, stale: true }),
                None => Err(e),
            },
        }
    }

    pub fn get_json(&self, url: &str, ttl: Duration) -> Result<(serde_json::Value, bool), String> {
        let f = self.get(url, ttl)?;
        let v = serde_json::from_slice(&f.body).map_err(|_| "the data service sent an unexpected response".to_string())?;
        Ok((v, f.stale))
    }
}

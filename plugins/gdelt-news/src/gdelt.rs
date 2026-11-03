//! GDELT upstream access: request spacing, caches, query validation, parsers and spike detection.
//!
//! GDELT's DOC 2.0 API allows one request per 5 seconds. Every call to it goes through one [`Gate`] so that all
//! browsers, agents and the story checker share a single queue. Responses are cached so repeated views are free.

use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const DOC_BASE: &str = "https://api.gdeltproject.org";
pub const DATA_BASE: &str = "http://data.gdeltproject.org";
pub const SPACING: Duration = Duration::from_secs(5);
pub const MAX_QUEUE: usize = 6;
const MAX_BODY: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
pub enum GdeltError {
    BadInput(String),
    /// Too many requests are already waiting for the 5-second slot.
    Busy,
    /// GDELT answered HTTP 429 even after waiting.
    RateLimited,
    Upstream(String),
}

impl std::fmt::Display for GdeltError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GdeltError::BadInput(m) | GdeltError::Upstream(m) => f.write_str(m),
            GdeltError::Busy => f.write_str("GDELT allows one request per 5 seconds and several are already waiting; try again in a moment"),
            GdeltError::RateLimited => f.write_str("GDELT is rate limiting this host (HTTP 429); wait a few seconds and retry"),
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Rate gate: one upstream call per `spacing`, shared queue.
// ---------------------------------------------------------------------------------------------------------------

pub struct Gate {
    /// Earliest time the next upstream call may start. The lock is held for the whole call, so calls never overlap
    /// and the spacing is measured from when the previous answer arrived (GDELT can take 10 s to answer).
    ready: Mutex<Instant>,
    spacing: Duration,
    waiting: AtomicUsize,
}

/// Held while one upstream call is in flight; dropping it starts the spacing period.
pub struct Permit<'a> {
    guard: std::sync::MutexGuard<'a, Instant>,
    spacing: Duration,
}
impl Permit<'_> {
    /// GDELT said 429: back off for twice the normal spacing.
    pub fn penalize(&mut self) {
        *self.guard = Instant::now() + self.spacing * 2;
    }
}
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        if *self.guard < Instant::now() + self.spacing {
            *self.guard = Instant::now() + self.spacing;
        }
    }
}

impl Gate {
    pub fn new(spacing: Duration) -> Gate {
        Gate { ready: Mutex::new(Instant::now()), spacing, waiting: AtomicUsize::new(0) }
    }
    /// How many callers are queued (waiting for their turn).
    pub fn queued(&self) -> usize {
        self.waiting.load(Ordering::SeqCst)
    }
    /// Blocks until this caller's turn and the spacing has passed. Refuses when more than `max_queue` callers already wait.
    pub fn acquire(&self, max_queue: usize) -> Result<Permit<'_>, GdeltError> {
        if self.waiting.fetch_add(1, Ordering::SeqCst) >= max_queue {
            self.waiting.fetch_sub(1, Ordering::SeqCst);
            return Err(GdeltError::Busy);
        }
        let guard = self.ready.lock().unwrap_or_else(|e| e.into_inner());
        self.waiting.fetch_sub(1, Ordering::SeqCst);
        let wait = guard.saturating_duration_since(Instant::now());
        if wait > Duration::ZERO {
            std::thread::sleep(wait);
        }
        Ok(Permit { guard, spacing: self.spacing })
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Small TTL cache with a size cap.
// ---------------------------------------------------------------------------------------------------------------

pub struct Cache {
    max: usize,
    map: Mutex<HashMap<String, (Instant, Value)>>,
}

impl Cache {
    pub fn new(max: usize) -> Cache {
        Cache { max, map: Mutex::new(HashMap::new()) }
    }
    pub fn get(&self, key: &str, ttl: Duration) -> Option<Value> {
        let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.get(key).filter(|(t, _)| t.elapsed() < ttl).map(|(_, v)| v.clone())
    }
    pub fn put(&self, key: String, v: Value, ttl: Duration) {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, (t, _)| t.elapsed() < ttl.max(Duration::from_secs(1)) * 2);
        while map.len() >= self.max {
            let Some(oldest) = map.iter().min_by_key(|(_, (t, _))| *t).map(|(k, _)| k.clone()) else { break };
            map.remove(&oldest);
        }
        map.insert(key, (Instant::now(), v));
    }
    pub fn len(&self) -> usize {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------------------------------------------

/// The user's query plus optional language and source-country filters, as GDELT query text.
pub fn build_query(q: &str, lang: &str, country: &str) -> Result<String, GdeltError> {
    let q = q.trim();
    if q.chars().count() < 3 {
        return Err(GdeltError::BadInput("enter a query of at least 3 characters".into()));
    }
    if q.chars().count() > 200 {
        return Err(GdeltError::BadInput("query is too long (200 characters at most)".into()));
    }
    if q.chars().any(|c| c.is_control()) {
        return Err(GdeltError::BadInput("query contains control characters".into()));
    }
    let mut out = q.to_string();
    let (lang, country) = (lang.trim(), country.trim());
    if !lang.is_empty() {
        if !(3..=20).contains(&lang.len()) || !lang.bytes().all(|b| b.is_ascii_alphabetic()) {
            return Err(GdeltError::BadInput("language must be letters only, for example english or fra".into()));
        }
        out.push_str(&format!(" sourcelang:{}", lang.to_ascii_lowercase()));
    }
    if !country.is_empty() {
        if !(2..=30).contains(&country.len()) || !country.bytes().all(|b| b.is_ascii_alphabetic()) {
            return Err(GdeltError::BadInput("source country must be letters only: a two-letter code such as US, or a name such as unitedkingdom".into()));
        }
        out.push_str(&format!(" sourcecountry:{}", country.to_ascii_lowercase()));
    }
    Ok(out)
}

/// A GDELT timespan such as 15min, 24h, 7d, 2w, 1m (months). Returns the normalised text, 15 minutes to 3 months.
pub fn parse_timespan(s: &str) -> Result<String, GdeltError> {
    let s = s.trim().to_ascii_lowercase();
    let bad = || GdeltError::BadInput("timespan must look like 15min, 6h, 24h, 7d, 2w or 1m (15 minutes to 3 months)".into());
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    let unit = &s[digits.len()..];
    let n: u64 = digits.parse().map_err(|_| bad())?;
    let minutes = match unit {
        "min" => n,
        "h" => n * 60,
        "d" => n * 60 * 24,
        "w" => n * 60 * 24 * 7,
        "m" => n * 60 * 24 * 30,
        _ => return Err(bad()),
    };
    if !(15..=60 * 24 * 92).contains(&minutes) {
        return Err(bad());
    }
    Ok(format!("{n}{unit}"))
}

pub fn clamp_max(n: Option<u32>) -> u32 {
    n.unwrap_or(50).clamp(1, 250)
}

pub fn valid_sort(s: &str) -> Result<&'static str, GdeltError> {
    match s {
        "" | "datedesc" => Ok("datedesc"),
        "dateasc" => Ok("dateasc"),
        "relevance" | "hybridrel" => Ok("hybridrel"),
        "tonedesc" => Ok("tonedesc"),
        "toneasc" => Ok("toneasc"),
        _ => Err(GdeltError::BadInput("sort must be datedesc, dateasc, relevance, tonedesc or toneasc".into())),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------------------------------------------

/// `20261102T143000Z` -> `2026-11-02T14:30:00Z`
pub fn iso_from_gdelt(s: &str) -> Option<String> {
    let b = s.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' || !b[..8].iter().chain(&b[9..15]).all(u8::is_ascii_digit) {
        return None;
    }
    Some(format!("{}-{}-{}T{}:{}:{}Z", &s[0..4], &s[4..6], &s[6..8], &s[9..11], &s[11..13], &s[13..15]))
}

fn http_url_only(u: &str) -> Option<String> {
    let l = u.trim();
    (l.len() < 2000 && (l.starts_with("https://") || l.starts_with("http://"))).then(|| l.to_string())
}

fn top(counts: HashMap<String, u32>, n: usize) -> Vec<Value> {
    let mut v: Vec<_> = counts.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.into_iter().take(n).map(|(k, c)| json!({ "name": k, "count": c })).collect()
}

/// Normalise an `artlist` body: articles (http/https links only) plus counts of domains, countries and languages.
pub fn parse_artlist(body: &str) -> Result<Value, GdeltError> {
    let t = body.trim();
    let v: Value = if t.is_empty() {
        json!({})
    } else if t.starts_with('{') {
        serde_json::from_str(t).map_err(|_| GdeltError::Upstream("GDELT returned malformed JSON".into()))?
    } else {
        return Err(GdeltError::BadInput(format!("GDELT said: {}", t.chars().take(200).collect::<String>())));
    };
    let (mut dom, mut cty, mut lng) = (HashMap::new(), HashMap::new(), HashMap::new());
    let mut articles = Vec::new();
    for a in v["articles"].as_array().map(Vec::as_slice).unwrap_or_default() {
        let Some(url) = a["url"].as_str().and_then(http_url_only) else { continue };
        let s = |k: &str| a[k].as_str().unwrap_or("").trim().to_string();
        let (domain, country, language) = (s("domain"), s("sourcecountry"), s("language"));
        for (m, k) in [(&mut dom, &domain), (&mut cty, &country), (&mut lng, &language)] {
            if !k.is_empty() {
                *m.entry(k.clone()).or_insert(0u32) += 1;
            }
        }
        articles.push(json!({
            "title": s("title").chars().take(300).collect::<String>(), "url": url, "domain": domain, "language": language, "country": country,
            "seen": a["seendate"].as_str().and_then(iso_from_gdelt),
        }));
    }
    Ok(json!({ "count": articles.len(), "articles": articles, "top_domains": top(dom, 12), "top_countries": top(cty, 8), "top_languages": top(lng, 6) }))
}

/// Normalise a `timelinevol` / `timelinetone` body into one series of `[iso time, value]` points.
pub fn parse_timeline(body: &str) -> Result<Value, GdeltError> {
    let t = body.trim();
    if t.is_empty() {
        return Ok(json!({ "points": [], "resolution": null, "stats": null }));
    }
    if !t.starts_with('{') {
        return Err(GdeltError::BadInput(format!("GDELT said: {}", t.chars().take(200).collect::<String>())));
    }
    let v: Value = serde_json::from_str(t).map_err(|_| GdeltError::Upstream("GDELT returned malformed JSON".into()))?;
    let mut points = Vec::new();
    if let Some(series) = v["timeline"].as_array().and_then(|s| s.first()) {
        for p in series["data"].as_array().map(Vec::as_slice).unwrap_or_default() {
            if let (Some(d), Some(val)) = (p["date"].as_str().and_then(iso_from_gdelt), p["value"].as_f64()) {
                points.push(json!([d, val]));
            }
        }
    }
    let vals: Vec<f64> = points.iter().filter_map(|p| p[1].as_f64()).collect();
    let stats = (!vals.is_empty()).then(|| {
        let sum: f64 = vals.iter().sum();
        json!({ "min": vals.iter().cloned().fold(f64::INFINITY, f64::min), "max": vals.iter().cloned().fold(f64::NEG_INFINITY, f64::max), "mean": sum / vals.len() as f64, "last": vals[vals.len() - 1] })
    });
    Ok(json!({ "points": points, "resolution": v["query_details"]["date_resolution"], "stats": stats }))
}

/// Parse `lastupdate.txt`: three lines of `size md5 url`. Only gdeltproject.org links are returned.
pub fn parse_lastupdate(text: &str) -> Vec<Value> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let (size, md5, url) = (it.next()?, it.next()?, it.next()?);
            let host_ok = url.strip_prefix("http://").or_else(|| url.strip_prefix("https://")).and_then(|r| r.split('/').next()).is_some_and(|h| h == "gdeltproject.org" || h.ends_with(".gdeltproject.org"));
            if !host_ok || md5.len() != 32 {
                return None;
            }
            let file = url.rsplit('/').next().unwrap_or("");
            let stamp = file.split('.').next().unwrap_or("");
            let kind = if file.contains(".export.") {
                "events"
            } else if file.contains(".mentions.") {
                "mentions"
            } else if file.contains(".gkg.") {
                "gkg"
            } else {
                "other"
            };
            let when = (stamp.len() == 14 && stamp.bytes().all(|b| b.is_ascii_digit()))
                .then(|| format!("{}-{}-{}T{}:{}:{}Z", &stamp[0..4], &stamp[4..6], &stamp[6..8], &stamp[8..10], &stamp[10..12], &stamp[12..14]));
            Some(json!({ "kind": kind, "file": file, "url": url, "bytes": size.parse::<u64>().ok(), "md5": md5, "time": when }))
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------------------------
// Spike detection (volume share of coverage, GDELT `timelinevol`)
// ---------------------------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Spike {
    pub spike: bool,
    pub recent_mean: f64,
    pub base_mean: f64,
    pub base_sd: f64,
    pub z: f64,
    pub ratio: f64,
    pub points: usize,
}

/// Compare roughly the last hour with everything before it. The final bucket is still filling, so it is ignored.
/// `resolution` is GDELT's `date_resolution` ("15m", "hour", "day").
pub fn detect_spike(values: &[f64], resolution: &str) -> Option<Spike> {
    let recent_n = match resolution {
        "15m" => 4,
        "hour" => 2,
        _ => 1,
    };
    if values.len() < recent_n + 1 + 12 {
        return None;
    }
    let usable = &values[..values.len() - 1];
    let (base, recent) = usable.split_at(usable.len() - recent_n);
    let mean = |s: &[f64]| s.iter().sum::<f64>() / s.len() as f64;
    let (bm, rm) = (mean(base), mean(recent));
    let sd = (base.iter().map(|v| (v - bm).powi(2)).sum::<f64>() / base.len() as f64).sqrt();
    let floor_sd = sd.max(bm * 0.1).max(1e-9);
    let z = (rm - bm) / floor_sd;
    let ratio = if bm > 0.0 { rm / bm } else { f64::INFINITY };
    let spike = if bm == 0.0 { recent.iter().filter(|v| **v > 0.0).count() >= 2 } else { z >= 3.0 && ratio >= 2.0 };
    Some(Spike { spike, recent_mean: rm, base_mean: bm, base_sd: sd, z: if z.is_finite() { z } else { 0.0 }, ratio: if ratio.is_finite() { ratio } else { 0.0 }, points: values.len() })
}

// ---------------------------------------------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------------------------------------------

pub struct Client {
    pub agent: ureq::Agent,
    pub doc_base: String,
    pub data_base: String,
    pub gate: Gate,
    pub cache: Cache,
}

pub const TTL_ARTICLES: Duration = Duration::from_secs(600);
pub const TTL_TIMELINE: Duration = Duration::from_secs(900);
pub const TTL_LATEST: Duration = Duration::from_secs(120);

impl Client {
    pub fn new(agent: ureq::Agent, doc_base: &str, data_base: &str, spacing: Duration) -> Client {
        Client { agent, doc_base: doc_base.trim_end_matches('/').into(), data_base: data_base.trim_end_matches('/').into(), gate: Gate::new(spacing), cache: Cache::new(64) }
    }

    fn read(&self, url: &str) -> Result<(u16, String), GdeltError> {
        use std::io::Read;
        let mut res = self
            .agent
            .get(url)
            .config()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(25)))
            .build()
            .call()
            .map_err(|e| GdeltError::Upstream(format!("could not reach GDELT: {e}")))?;
        let status = res.status().as_u16();
        let mut buf = Vec::new();
        res.body_mut().as_reader().take(MAX_BODY).read_to_end(&mut buf).map_err(|e| GdeltError::Upstream(format!("reading GDELT response failed: {e}")))?;
        Ok((status, String::from_utf8_lossy(&buf).into_owned()))
    }

    /// One DOC 2.0 call, waiting for the shared slot. Retries once if GDELT still answers 429.
    fn doc(&self, params: &[(&str, &str)]) -> Result<String, GdeltError> {
        let mut ser = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in params {
            ser.append_pair(k, v);
        }
        ser.append_pair("format", "json");
        let url = format!("{}/api/v2/doc/doc?{}", self.doc_base, ser.finish());
        for attempt in 0..2 {
            let mut permit = self.gate.acquire(MAX_QUEUE)?;
            let (status, body) = match self.read(&url) {
                Ok(r) => r,
                Err(e) if attempt == 0 && matches!(&e, GdeltError::Upstream(m) if m.contains("could not reach")) => {
                    permit.penalize();
                    continue;
                }
                Err(e) => return Err(e),
            };
            match status {
                200 => return Ok(body),
                429 => {
                    permit.penalize();
                    if attempt == 0 {
                        continue;
                    }
                    return Err(GdeltError::RateLimited);
                }
                s => return Err(GdeltError::Upstream(format!("GDELT answered HTTP {s}"))),
            }
        }
        Err(GdeltError::RateLimited)
    }

    fn cached(&self, key: String, ttl: Duration, fetch: impl FnOnce() -> Result<Value, GdeltError>) -> Result<Value, GdeltError> {
        if let Some(mut v) = self.cache.get(&key, ttl) {
            v["cached"] = json!(true);
            return Ok(v);
        }
        let mut v = fetch()?;
        self.cache.put(key, v.clone(), ttl);
        v["cached"] = json!(false);
        Ok(v)
    }

    pub fn articles(&self, q: &str, lang: &str, country: &str, timespan: &str, max: u32, sort: &str) -> Result<Value, GdeltError> {
        let query = build_query(q, lang, country)?;
        let ts = parse_timespan(timespan)?;
        let sort = valid_sort(sort)?;
        let key = format!("art|{query}|{ts}|{max}|{sort}");
        self.cached(key, TTL_ARTICLES, || {
            let body = self.doc(&[("query", &query), ("mode", "artlist"), ("maxrecords", &max.to_string()), ("timespan", &ts), ("sort", sort)])?;
            let mut v = parse_artlist(&body)?;
            v["query"] = json!(query);
            v["timespan"] = json!(ts);
            Ok(v)
        })
    }

    /// `mode` is "vol" (share of all coverage) or "tone" (average tone).
    pub fn timeline(&self, q: &str, lang: &str, country: &str, timespan: &str, mode: &str) -> Result<Value, GdeltError> {
        let query = build_query(q, lang, country)?;
        let ts = parse_timespan(timespan)?;
        let up_mode = match mode {
            "vol" | "" => "timelinevol",
            "tone" => "timelinetone",
            _ => return Err(GdeltError::BadInput("mode must be vol or tone".into())),
        };
        let key = format!("tl|{up_mode}|{query}|{ts}");
        self.cached(key, TTL_TIMELINE, || {
            let body = self.doc(&[("query", &query), ("mode", up_mode), ("timespan", &ts)])?;
            let mut v = parse_timeline(&body)?;
            v["query"] = json!(query);
            v["timespan"] = json!(ts);
            v["mode"] = json!(if up_mode == "timelinevol" { "vol" } else { "tone" });
            Ok(v)
        })
    }

    /// The newest 15-minute export files (links only; nothing is downloaded).
    pub fn latest(&self) -> Result<Value, GdeltError> {
        self.cached("latest".into(), TTL_LATEST, || {
            let (status, body) = self.read(&format!("{}/gdeltv2/lastupdate.txt", self.data_base))?;
            if status != 200 {
                return Err(GdeltError::Upstream(format!("GDELT file index answered HTTP {status}")));
            }
            let files = parse_lastupdate(&body);
            if files.is_empty() {
                return Err(GdeltError::Upstream("GDELT file index had no recognisable entries".into()));
            }
            Ok(json!({ "files": files }))
        })
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Story store (redb)
// ---------------------------------------------------------------------------------------------------------------

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
const STORIES: TableDefinition<u64, &[u8]> = TableDefinition::new("stories");
pub const MAX_STORIES: usize = 10;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Story {
    pub id: u64,
    pub name: String,
    pub q: String,
    pub lang: String,
    pub country: String,
    pub created: u64,
    pub checked: Option<u64>,
    pub spike: Option<Spike>,
    pub spark: Vec<f64>,
    pub error: Option<String>,
}

pub struct Store {
    db: Database,
}

impl Store {
    pub fn open(path: &str) -> anyhow::Result<Store> {
        let db = Database::create(path)?;
        let tx = db.begin_write()?;
        tx.open_table(STORIES)?;
        tx.commit()?;
        Ok(Store { db })
    }
    pub fn list(&self) -> anyhow::Result<Vec<Story>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(STORIES)?;
        Ok(t.iter()?.filter_map(|r| r.ok()).filter_map(|(_, v)| serde_json::from_slice(v.value()).ok()).collect())
    }
    pub fn get(&self, id: u64) -> anyhow::Result<Option<Story>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(STORIES)?;
        Ok(t.get(id)?.and_then(|v| serde_json::from_slice(v.value()).ok()))
    }
    pub fn put(&self, s: &Story) -> anyhow::Result<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(STORIES)?.insert(s.id, serde_json::to_vec(s)?.as_slice())?;
        tx.commit()?;
        Ok(())
    }
    pub fn add(&self, name: &str, q: &str, lang: &str, country: &str) -> anyhow::Result<Story> {
        let tx = self.db.begin_write()?;
        let story;
        {
            let mut t = tx.open_table(STORIES)?;
            if t.len()? as usize >= MAX_STORIES {
                anyhow::bail!("at most {MAX_STORIES} saved stories; delete one first");
            }
            let id = t.last()?.map(|(k, _)| k.value() + 1).unwrap_or(1);
            story = Story { id, name: name.into(), q: q.into(), lang: lang.into(), country: country.into(), created: now(), checked: None, spike: None, spark: vec![], error: None };
            t.insert(id, serde_json::to_vec(&story)?.as_slice())?;
        }
        tx.commit()?;
        Ok(story)
    }
    pub fn delete(&self, id: u64) -> anyhow::Result<bool> {
        let tx = self.db.begin_write()?;
        let existed = tx.open_table(STORIES)?.remove(id)?.is_some();
        tx.commit()?;
        Ok(existed)
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Fetch a story's 3-day volume timeline, run spike detection and store the outcome (including failures).
pub fn check_story(client: &Client, store: &Store, id: u64) -> anyhow::Result<Option<Story>> {
    let Some(mut s) = store.get(id)? else { return Ok(None) };
    match client.timeline(&s.q, &s.lang, &s.country, "3d", "vol") {
        Ok(v) => {
            let vals: Vec<f64> = v["points"].as_array().map(|p| p.iter().filter_map(|x| x[1].as_f64()).collect()).unwrap_or_default();
            s.spike = detect_spike(&vals, v["resolution"].as_str().unwrap_or("15m"));
            // About 48 points for the sparkline, taken evenly.
            let step = (vals.len() / 48).max(1);
            s.spark = vals.iter().step_by(step).map(|v| (v * 1e6).round() / 1e6).collect();
            s.error = if vals.is_empty() { Some("GDELT returned no coverage for this query in the last 3 days".into()) } else { None };
        }
        Err(e) => s.error = Some(e.to_string()),
    }
    s.checked = Some(now());
    store.put(&s)?;
    Ok(Some(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_validation() {
        assert_eq!(build_query("  ukraine ceasefire ", "", "").unwrap(), "ukraine ceasefire");
        assert_eq!(build_query("flood", "English", "US").unwrap(), "flood sourcelang:english sourcecountry:us");
        assert!(build_query("ab", "", "").is_err());
        assert!(build_query(&"x".repeat(201), "", "").is_err());
        assert!(build_query("bad\nquery", "", "").is_err());
        assert!(build_query("flood", "eng lish", "").is_err());
        assert!(build_query("flood", "", "U$").is_err());
        assert!(build_query("flood", "", "x").is_err());
    }

    #[test]
    fn timespan_validation() {
        assert_eq!(parse_timespan("24H").unwrap(), "24h");
        assert_eq!(parse_timespan("15min").unwrap(), "15min");
        assert_eq!(parse_timespan("1m").unwrap(), "1m");
        for bad in ["", "h", "5min", "0d", "24", "2y", "99m", "-3d", "3 d", "1e3h"] {
            assert!(parse_timespan(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn sort_and_max() {
        assert_eq!(valid_sort("relevance").unwrap(), "hybridrel");
        assert!(valid_sort("drop table").is_err());
        assert_eq!((clamp_max(None), clamp_max(Some(0)), clamp_max(Some(9999))), (50, 1, 250));
    }

    #[test]
    fn artlist_parsing() {
        let body = r#"{"articles":[
          {"url":"https://a.example/x","title":"One","seendate":"20261102T143000Z","domain":"a.example","language":"English","sourcecountry":"United States"},
          {"url":"javascript:alert(1)","title":"Bad","domain":"evil"},
          {"url":"http://b.example/y","title":"Two","seendate":"junk","domain":"b.example","language":"English","sourcecountry":"France"},
          {"url":"https://a.example/z","title":"Three","domain":"a.example","language":"French","sourcecountry":"United States"}]}"#;
        let v = parse_artlist(body).unwrap();
        assert_eq!(v["count"], 3);
        assert_eq!(v["articles"][0]["seen"], "2026-11-02T14:30:00Z");
        assert!(v["articles"][1]["seen"].is_null());
        assert_eq!(v["top_domains"][0]["name"], "a.example");
        assert_eq!(v["top_domains"][0]["count"], 2);
        assert_eq!(v["top_languages"][0]["name"], "English");
        assert_eq!(parse_artlist("").unwrap()["count"], 0);
        assert_eq!(parse_artlist("{}").unwrap()["count"], 0);
        assert!(matches!(parse_artlist("The specified phrase is too short."), Err(GdeltError::BadInput(_))));
        assert!(matches!(parse_artlist("{broken"), Err(GdeltError::Upstream(_))));
    }

    #[test]
    fn timeline_parsing() {
        let body = r#"{"query_details":{"title":"x","date_resolution":"15m"},"timeline":[{"series":"Volume Intensity","data":[{"date":"20261102T140000Z","value":0.5},{"date":"20261102T141500Z","value":1.5},{"date":"bad","value":9}]}]}"#;
        let v = parse_timeline(body).unwrap();
        assert_eq!(v["points"].as_array().unwrap().len(), 2);
        assert_eq!(v["resolution"], "15m");
        assert_eq!(v["stats"]["max"], 1.5);
        assert_eq!(v["stats"]["mean"], 1.0);
        let empty = parse_timeline(r#"{"timeline": [ ]}"#).unwrap();
        assert!(empty["stats"].is_null());
        assert!(parse_timeline("Please limit requests").is_err());
    }

    #[test]
    fn lastupdate_parsing() {
        let t = "47711 e942270a831268825bcac5361b0f0bb3 http://data.gdeltproject.org/gdeltv2/20261103044500.export.CSV.zip\n\
                 61587 333ee5fe63f879e53352388a99eb4026 http://data.gdeltproject.org/gdeltv2/20261103044500.mentions.CSV.zip\n\
                 1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa http://evil.example/gdeltv2/x.gkg.csv.zip\n\
                 3016952 63475fb1fca95fbe1ff5b604cc874316 http://data.gdeltproject.org/gdeltv2/20261103044500.gkg.csv.zip\ngarbage";
        let f = parse_lastupdate(t);
        assert_eq!(f.len(), 3);
        assert_eq!(f[0]["kind"], "events");
        assert_eq!(f[0]["time"], "2026-11-03T04:45:00Z");
        assert_eq!(f[2]["kind"], "gkg");
        assert_eq!(f[2]["bytes"], 3016952);
    }

    #[test]
    fn spike_detection() {
        let mut calm: Vec<f64> = (0..60).map(|i| 1.0 + if i % 2 == 0 { 0.1 } else { -0.1 }).collect();
        calm.extend([1.0, 1.0, 1.0, 1.0, 1.0]);
        assert!(!detect_spike(&calm, "15m").unwrap().spike);
        let mut hot: Vec<f64> = calm.clone();
        let n = hot.len();
        for v in &mut hot[n - 5..n - 1] {
            *v = 6.0;
        }
        let s = detect_spike(&hot, "15m").unwrap();
        assert!(s.spike && s.ratio > 4.0 && s.z > 3.0, "{s:?}");
        // The still-filling last bucket is ignored.
        let mut partial = calm.clone();
        *partial.last_mut().unwrap() = 50.0;
        assert!(!detect_spike(&partial, "15m").unwrap().spike);
        // Zero baseline, two nonzero recent buckets: flagged. One: not.
        let mut zero = vec![0.0; 40];
        zero[36] = 0.2;
        zero[37] = 0.3;
        assert!(detect_spike(&zero, "15m").unwrap().spike);
        let mut one = vec![0.0; 40];
        one[37] = 0.3;
        assert!(!detect_spike(&one, "15m").unwrap().spike);
        assert!(detect_spike(&[1.0; 5], "15m").is_none());
    }

    #[test]
    fn gate_spaces_calls_from_completion_and_limits_queue() {
        let g = Gate::new(Duration::from_millis(80));
        let t = Instant::now();
        for _ in 0..3 {
            let _p = g.acquire(3).unwrap();
            std::thread::sleep(Duration::from_millis(20)); // the call itself
        }
        // 3 calls of 20 ms with 80 ms measured from each completion: the third call ends after ~220 ms.
        assert!(t.elapsed() >= Duration::from_millis(215), "{:?}", t.elapsed());
        // One caller holds the gate, one waits; with a queue limit of 1 the next is refused instead of waiting.
        let g = std::sync::Arc::new(Gate::new(Duration::from_millis(50)));
        let p = g.acquire(1).unwrap();
        let g2 = g.clone();
        let waiter = std::thread::spawn(move || g2.acquire(1).map(|_| ()));
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(g.queued(), 1);
        assert!(matches!(g.acquire(1), Err(GdeltError::Busy)));
        drop(p);
        waiter.join().unwrap().unwrap();
    }

    #[test]
    fn cache_ttl_and_cap() {
        let c = Cache::new(3);
        for i in 0..6 {
            c.put(format!("k{i}"), json!(i), Duration::from_secs(60));
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(c.len(), 3);
        assert!(c.get("k0", Duration::from_secs(60)).is_none());
        assert_eq!(c.get("k5", Duration::from_secs(60)).unwrap(), json!(5));
        assert!(c.get("k5", Duration::from_nanos(1)).is_none());
    }

    #[test]
    fn store_roundtrip_and_cap() {
        let dir = std::env::temp_dir().join(format!("gdelt-store-{}", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        let st = Store::open(dir.to_str().unwrap()).unwrap();
        let a = st.add("A", "flood", "", "").unwrap();
        assert_eq!(a.id, 1);
        for i in 1..MAX_STORIES {
            st.add("x", &format!("query {i}"), "", "").unwrap();
        }
        assert!(st.add("one too many", "flood2", "", "").is_err());
        assert_eq!(st.list().unwrap().len(), MAX_STORIES);
        assert!(st.delete(1).unwrap());
        assert!(!st.delete(1).unwrap());
        assert_eq!(st.add("again", "flood3", "", "").unwrap().id, MAX_STORIES as u64 + 1);
        let _ = std::fs::remove_file(&dir);
    }
}

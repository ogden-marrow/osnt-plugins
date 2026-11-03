//! Web archives plugin: Internet Archive CDX snapshots, snapshot text diffs, domain URL harvest, Common Crawl index
//! lookups and a user-triggered Save Page Now capture that produces an evidence record (hash, time, archive URL).
//!
//! Upstream hosts are fixed (web.archive.org, index.commoncrawl.org). Every outbound request goes through the SSRF
//! guard in `ssrf.rs`; user-supplied URLs are only ever embedded in requests to the archive, never fetched directly.

mod cdx;
mod diff;
mod ssrf;
#[cfg(test)]
mod tests;

use std::{
    collections::{HashMap, VecDeque},
    env,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use ssrf::{Guard, guarded_agent_timeout, guarded_get};

const PAGE: &str = include_str!("../assets/index.html");
const UA: &str = "osnt-web-archive/0.1 (+https://github.com/ogden-marrow/osnt-hub)";
const CACHE_TTL: Duration = Duration::from_secs(600);
const CACHE_MAX: usize = 200;
const SNAPSHOT_FETCH_MAX: usize = 1_500_000;
const SAVE_MIN_GAP: Duration = Duration::from_secs(15);
const SAVE_PER_HOUR: usize = 10;

pub struct Upstreams {
    pub wayback: String,
    pub cc_index: String,
}

impl Default for Upstreams {
    fn default() -> Self {
        Upstreams { wayback: "https://web.archive.org".into(), cc_index: "https://index.commoncrawl.org".into() }
    }
}

pub struct AppState {
    pub agent: ureq::Agent,
    pub guard: Guard,
    pub up: Upstreams,
    pub keys: Box<dyn Fn() -> Option<(String, String)> + Send + Sync>,
    pub min_gap: Duration,
    cache: Mutex<HashMap<String, (Instant, Value)>>,
    last_call: Mutex<Option<Instant>>,
    saves: Mutex<VecDeque<Instant>>,
}
pub type Shared = Arc<AppState>;

impl AppState {
    pub fn new(guard: Guard, up: Upstreams, keys: Box<dyn Fn() -> Option<(String, String)> + Send + Sync>, min_gap: Duration) -> Shared {
        Arc::new(AppState { agent: guarded_agent_timeout(guard.clone(), UA, 75), guard, up, keys, min_gap, cache: Mutex::default(), last_call: Mutex::new(None), saves: Mutex::default() })
    }

    /// Be polite: at most one upstream request per `min_gap` across the whole plugin. Blocking.
    fn throttle(&self) {
        let wait = {
            let mut last = self.last_call.lock().unwrap();
            let now = Instant::now();
            let at = last.map(|l| (l + self.min_gap).max(now)).unwrap_or(now);
            *last = Some(at);
            at - now
        };
        if !wait.is_zero() {
            std::thread::sleep(wait);
        }
    }

    fn cached(&self, key: &str) -> Option<Value> {
        let c = self.cache.lock().unwrap();
        c.get(key).filter(|(t, _)| t.elapsed() < CACHE_TTL).map(|(_, v)| v.clone())
    }

    fn remember(&self, key: String, v: &Value) {
        let mut c = self.cache.lock().unwrap();
        if c.len() >= CACHE_MAX {
            c.retain(|_, (t, _)| t.elapsed() < CACHE_TTL);
            if c.len() >= CACHE_MAX {
                c.clear();
            }
        }
        c.insert(key, (Instant::now(), v.clone()));
    }

    /// GET a fixed-host upstream URL, mapping rate limits and outages to readable errors.
    fn fetch(&self, url: &str, max: usize) -> Result<ssrf::Fetched, ApiError> {
        self.throttle();
        let f = guarded_get(&self.agent, &self.guard, url, max, "*/*").map_err(|e| ApiError(StatusCode::BAD_GATEWAY, e))?;
        match f.status {
            200..=299 => Ok(f),
            429 => Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "the archive is rate limiting this hub (HTTP 429); wait a minute and try again".into())),
            404 => Err(ApiError(StatusCode::NOT_FOUND, "not found at the archive".into())),
            s => Err(ApiError(StatusCode::BAD_GATEWAY, format!("the archive answered HTTP {s}"))),
        }
    }
}

#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub String);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}
fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, ApiError> + Send + 'static) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f).await.map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

// ---- snapshots ---------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SnapQuery {
    url: String,
    limit: Option<usize>,
    /// "earliest" (default) or "latest"
    order: Option<String>,
    from: Option<String>,
    to: Option<String>,
    /// Only captures with this HTTP status (for example 200).
    status: Option<String>,
    /// "domain" widens the match to the whole domain and its subdomains.
    scope: Option<String>,
}

pub fn snapshots(s: &AppState, q: &SnapQuery) -> Result<Value, ApiError> {
    let target = cdx::clean_target(&q.url).map_err(bad)?;
    let limit = cdx::clean_limit(q.limit, 1000, 5000);
    let latest = q.order.as_deref() == Some("latest");
    let mut u = format!(
        "{}/cdx/search/cdx?url={}&output=json&fl=timestamp,original,statuscode,mimetype,digest,length&limit={}",
        s.up.wayback,
        enc(&target),
        if latest { format!("-{limit}") } else { limit.to_string() }
    );
    if q.scope.as_deref() == Some("domain") {
        u.push_str("&matchType=domain");
    }
    if let Some(f) = q.from.as_deref().filter(|f| !f.is_empty()) {
        u.push_str(&format!("&from={}", cdx::clean_ts(f).map_err(bad)?));
    }
    if let Some(t) = q.to.as_deref().filter(|t| !t.is_empty()) {
        u.push_str(&format!("&to={}", cdx::clean_ts(t).map_err(bad)?));
    }
    if let Some(st) = q.status.as_deref().filter(|t| !t.is_empty()) {
        if st.len() != 3 || !st.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad("status must be a three-digit HTTP code"));
        }
        u.push_str(&format!("&filter=statuscode:{st}"));
    }
    if let Some(v) = s.cached(&u) {
        return Ok(v);
    }
    let f = s.fetch(&u, 8_000_000)?;
    let rows = cdx::parse_cdx(&String::from_utf8_lossy(&f.body)).map_err(|e| ApiError(StatusCode::BAD_GATEWAY, e))?;
    let mut v = cdx::summarise_snapshots(&rows);
    v["query"] = json!({ "url": target, "limit": limit, "order": if latest { "latest" } else { "earliest" } });
    v["capped"] = json!(rows.len() >= limit);
    s.remember(u, &v);
    Ok(v)
}

async fn snapshots_h(State(s): State<Shared>, Query(q): Query<SnapQuery>) -> Result<Json<Value>, ApiError> {
    Ok(Json(blocking(move || snapshots(&s, &q)).await?))
}

// ---- harvest ------------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct UrlsQuery {
    domain: String,
    limit: Option<usize>,
}

pub fn harvest(s: &AppState, q: &UrlsQuery) -> Result<Value, ApiError> {
    let domain = cdx::clean_domain(&q.domain).map_err(bad)?;
    let limit = cdx::clean_limit(q.limit, 1000, 5000);
    let u = format!(
        "{}/cdx/search/cdx?url={}&matchType=domain&collapse=urlkey&output=json&fl=original,timestamp,mimetype,statuscode&filter=statuscode:200&limit={limit}",
        s.up.wayback,
        enc(&domain)
    );
    if let Some(v) = s.cached(&u) {
        return Ok(v);
    }
    let f = s.fetch(&u, 12_000_000)?;
    let rows = cdx::parse_cdx(&String::from_utf8_lossy(&f.body)).map_err(|e| ApiError(StatusCode::BAD_GATEWAY, e))?;
    let mut v = cdx::summarise_urls(&rows);
    v["domain"] = json!(domain);
    v["capped"] = json!(rows.len() >= limit);
    s.remember(u, &v);
    Ok(v)
}

async fn urls_h(State(s): State<Shared>, Query(q): Query<UrlsQuery>) -> Result<Json<Value>, ApiError> {
    Ok(Json(blocking(move || harvest(&s, &q)).await?))
}

// ---- Common Crawl -------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CcQuery {
    url: String,
    limit: Option<usize>,
    /// How many of the newest crawls to ask (1-3).
    crawls: Option<usize>,
    scope: Option<String>,
}

pub fn commoncrawl(s: &AppState, q: &CcQuery) -> Result<Value, ApiError> {
    let target = cdx::clean_target(&q.url).map_err(bad)?;
    let limit = cdx::clean_limit(q.limit, 100, 500);
    let n = q.crawls.unwrap_or(1).clamp(1, 3);
    let info_url = format!("{}/collinfo.json", s.up.cc_index);
    let info = match s.cached(&info_url) {
        Some(v) => v,
        None => {
            let f = s.fetch(&info_url, 2_000_000)?;
            let v: Value = serde_json::from_slice(&f.body).map_err(|_| ApiError(StatusCode::BAD_GATEWAY, "Common Crawl returned an unreadable crawl list".into()))?;
            s.remember(info_url, &v);
            v
        }
    };
    let ids = cdx::newest_collections(&info, n);
    if ids.is_empty() {
        return Err(ApiError(StatusCode::BAD_GATEWAY, "Common Crawl listed no crawls".into()));
    }
    let wildcard = if q.scope.as_deref() == Some("domain") && !target.contains('*') { format!("*.{}", cdx::clean_domain(&target).map_err(bad)?) } else { target.clone() };
    let mut results = Vec::new();
    for id in &ids {
        let u = format!("{}/{id}-index?url={}&output=json&limit={limit}", s.up.cc_index, enc(&wildcard));
        let rows = match s.cached(&u) {
            Some(v) => v,
            None => {
                self_fetch_cc(s, &u).map(|v| {
                    s.remember(u.clone(), &v);
                    v
                })?
            }
        };
        results.push(json!({ "crawl": id, "captures": rows }));
    }
    Ok(json!({ "query": { "url": wildcard, "crawls": ids }, "results": results }))
}

/// Common Crawl answers "no captures" with HTTP 404 and a JSON message; that is an empty result, not an error.
fn self_fetch_cc(s: &AppState, u: &str) -> Result<Value, ApiError> {
    s.throttle();
    let f = guarded_get(&s.agent, &s.guard, u, 4_000_000, "*/*").map_err(|e| ApiError(StatusCode::BAD_GATEWAY, e))?;
    match f.status {
        200..=299 | 404 => Ok(Value::Array(cdx::parse_cc_lines(&String::from_utf8_lossy(&f.body)))),
        429 => Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "Common Crawl is rate limiting this hub; wait a minute and try again".into())),
        502..=504 => Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, format!("Common Crawl's index server is overloaded or down (HTTP {}); it is often slow, try again later", f.status))),
        st => Err(ApiError(StatusCode::BAD_GATEWAY, format!("Common Crawl answered HTTP {st}"))),
    }
}

async fn cc_h(State(s): State<Shared>, Query(q): Query<CcQuery>) -> Result<Json<Value>, ApiError> {
    Ok(Json(blocking(move || commoncrawl(&s, &q)).await?))
}

// ---- diff and evidence --------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct DiffQuery {
    url: String,
    a: String,
    b: String,
}

fn snapshot_raw(s: &AppState, target: &str, ts: &str) -> Result<ssrf::Fetched, ApiError> {
    // `id_` asks the archive for the original bytes without its toolbar or link rewriting.
    let f = s.fetch(&format!("{}/web/{ts}id_/{target}", s.up.wayback), SNAPSHOT_FETCH_MAX)?;
    let ct = f.content_type.to_ascii_lowercase();
    if !(ct.is_empty() || ct.contains("text/") || ct.contains("html") || ct.contains("xml") || ct.contains("json")) {
        return Err(bad(format!("that snapshot is {ct}, not a text page")));
    }
    Ok(f)
}

pub fn diff_snapshots(s: &AppState, q: &DiffQuery) -> Result<Value, ApiError> {
    let target = cdx::clean_target(&q.url).map_err(bad)?;
    let (a, b) = (cdx::clean_ts(&q.a).map_err(bad)?, cdx::clean_ts(&q.b).map_err(bad)?);
    let fa = snapshot_raw(s, &target, &a)?;
    let fb = snapshot_raw(s, &target, &b)?;
    let hex = |d: &[u8]| Sha256::digest(d).iter().map(|x| format!("{x:02x}")).collect::<String>();
    let (ha, hb) = (String::from_utf8_lossy(&fa.body).into_owned(), String::from_utf8_lossy(&fb.body).into_owned());
    let mut v = diff::diff_pages(&ha, &hb);
    v["a"] = json!({ "timestamp": a, "time": cdx::iso(&a), "bytes": fa.body.len(), "sha256": hex(&fa.body), "truncated": fa.truncated, "archive_url": format!("https://web.archive.org/web/{a}/{target}") });
    v["b"] = json!({ "timestamp": b, "time": cdx::iso(&b), "bytes": fb.body.len(), "sha256": hex(&fb.body), "truncated": fb.truncated, "archive_url": format!("https://web.archive.org/web/{b}/{target}") });
    v["identical_bytes"] = json!(fa.body == fb.body);
    v["url"] = json!(target);
    Ok(v)
}

async fn diff_h(State(s): State<Shared>, Query(q): Query<DiffQuery>) -> Result<Json<Value>, ApiError> {
    Ok(Json(blocking(move || diff_snapshots(&s, &q)).await?))
}

#[derive(Deserialize)]
pub struct EvidenceQuery {
    url: String,
    ts: String,
}

/// Evidence record for one archived capture: the SHA-256 of the archived bytes, the capture time and the archive URL.
pub fn evidence(s: &AppState, q: &EvidenceQuery) -> Result<Value, ApiError> {
    let target = cdx::clean_target(&q.url).map_err(bad)?;
    let ts = cdx::clean_ts(&q.ts).map_err(bad)?;
    if ts.len() != 14 {
        return Err(bad("evidence needs a full 14-digit timestamp"));
    }
    let f = s.fetch(&format!("{}/web/{ts}id_/{target}", s.up.wayback), 25_000_000)?;
    let sha: String = Sha256::digest(&f.body).iter().map(|x| format!("{x:02x}")).collect();
    let title = diff::title(&String::from_utf8_lossy(&f.body));
    Ok(json!({
        "kind": "web-capture", "title": title.clone().unwrap_or_else(|| target.clone()), "url": target,
        "captured_at": cdx::iso(&ts), "sha256": sha, "bytes": f.body.len(), "truncated": f.truncated, "content_type": f.content_type,
        "archive_url": format!("https://web.archive.org/web/{ts}/{target}"), "source_plugin": "web-archive",
        "note": "SHA-256 is of the archived bytes as served by web.archive.org (id_ mode), not of the live page.",
    }))
}

async fn evidence_h(State(s): State<Shared>, Query(q): Query<EvidenceQuery>) -> Result<Json<Value>, ApiError> {
    Ok(Json(blocking(move || evidence(&s, &q)).await?))
}

// ---- Save Page Now ------------------------------------------------------------------------------

fn signed_in(method: &Method, uri: &Uri, headers: &HeaderMap) -> bool {
    osnt_common::gateway_authorized(method.as_str(), uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"), headers.get("x-osnt-gateway").and_then(|v| v.to_str().ok()))
}

#[derive(Deserialize)]
pub struct SaveBody {
    url: String,
}

/// The URL the archive will be asked to capture: absolute http(s) on a public host. We never connect to it ourselves.
pub fn save_target(guard: &Guard, raw: &str) -> Result<String, String> {
    let t = cdx::clean_target(raw)?;
    let u = Url::parse(&t).map_err(|_| "enter a full URL starting with http:// or https://".to_string())?;
    guard.check_url(&u, true)?;
    Ok(u.to_string())
}

fn snapshot_from_location(loc: &str) -> Option<(String, String)> {
    let rest = loc.split("/web/").nth(1)?;
    let (ts, orig) = rest.split_once('/')?;
    (ts.len() == 14 && ts.bytes().all(|b| b.is_ascii_digit())).then(|| (ts.to_string(), orig.to_string()))
}

pub fn save(s: &AppState, raw: &str) -> Result<Value, ApiError> {
    let target = save_target(&s.guard, raw).map_err(bad)?;
    {
        let mut log = s.saves.lock().unwrap();
        while log.front().is_some_and(|t| t.elapsed() > Duration::from_secs(3600)) {
            log.pop_front();
        }
        if log.len() >= SAVE_PER_HOUR {
            return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, format!("Save Page Now is limited to {SAVE_PER_HOUR} captures per hour from this hub")));
        }
        if let Some(last) = log.back().filter(|t| t.elapsed() < SAVE_MIN_GAP) {
            return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, format!("wait {} s before the next capture", (SAVE_MIN_GAP - last.elapsed()).as_secs() + 1)));
        }
        log.push_back(Instant::now());
    }
    s.throttle();
    if let Some((access, secret)) = (s.keys)() {
        // Save Page Now 2: authenticated, returns a job to poll.
        let res = s
            .agent
            .post(&format!("{}/save", s.up.wayback))
            .header("Accept", "application/json")
            .header("Authorization", &format!("LOW {access}:{secret}"))
            .send_form([("url", target.as_str())])
            .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, format!("Save Page Now request failed: {e}")))?;
        let status = res.status().as_u16();
        let mut res = res;
        let v: Value = res.body_mut().read_json().unwrap_or(Value::Null);
        if status == 429 {
            return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "Save Page Now is rate limiting this account".into()));
        }
        if !(200..300).contains(&status) || v["job_id"].as_str().is_none() {
            let msg = v["message"].as_str().unwrap_or("no job id returned");
            return Err(ApiError(StatusCode::BAD_GATEWAY, format!("Save Page Now refused the capture (HTTP {status}): {msg}")));
        }
        return Ok(json!({ "mode": "authenticated", "url": target, "job_id": v["job_id"], "status": "pending" }));
    }
    // Anonymous capture: GET /save/<url> redirects to the new snapshot when it worked.
    let res = s.agent.get(&format!("{}/save/{target}", s.up.wayback)).call().map_err(|e| ApiError(StatusCode::BAD_GATEWAY, format!("Save Page Now request failed: {e}")))?;
    let status = res.status().as_u16();
    if status == 429 {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "Save Page Now is rate limiting this hub; try later or add archive.org keys on the Credentials page".into()));
    }
    let loc = res.headers().get("location").and_then(|v| v.to_str().ok()).map(str::to_string);
    if (300..400).contains(&status) {
        if let Some((ts, orig)) = loc.as_deref().and_then(snapshot_from_location) {
            return Ok(json!({ "mode": "anonymous", "url": target, "status": "success", "timestamp": ts, "time": cdx::iso(&ts), "archive_url": format!("https://web.archive.org/web/{ts}/{orig}") }));
        }
    }
    Err(ApiError(StatusCode::BAD_GATEWAY, format!("the archive did not confirm a capture (HTTP {status}); the site may block archiving, or anonymous captures may need archive.org keys")))
}

async fn save_h(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Json(b): Json<SaveBody>) -> Result<Json<Value>, ApiError> {
    if !signed_in(&method, &uri, &headers) {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "sign in required".into()));
    }
    Ok(Json(blocking(move || save(&s, &b.url)).await?))
}

#[derive(Deserialize)]
pub struct JobQuery {
    job: String,
}

pub fn save_status(s: &AppState, job: &str) -> Result<Value, ApiError> {
    if job.is_empty() || job.len() > 80 || !job.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(bad("invalid job id"));
    }
    let Some((access, secret)) = (s.keys)() else { return Err(bad("job status needs archive.org keys")) };
    s.throttle();
    let mut res = s
        .agent
        .get(&format!("{}/save/status/{job}", s.up.wayback))
        .header("Accept", "application/json")
        .header("Authorization", &format!("LOW {access}:{secret}"))
        .call()
        .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, format!("status request failed: {e}")))?;
    let v: Value = res.body_mut().read_json().map_err(|_| ApiError(StatusCode::BAD_GATEWAY, "unreadable status answer".into()))?;
    let st = v["status"].as_str().unwrap_or("pending").to_string();
    let ts = v["timestamp"].as_str().unwrap_or("").to_string();
    let orig = v["original_url"].as_str().unwrap_or("").to_string();
    let mut out = json!({ "status": st, "message": v["message"] });
    if st == "success" && ts.len() == 14 {
        out["timestamp"] = json!(ts);
        out["time"] = json!(cdx::iso(&ts));
        out["archive_url"] = json!(format!("https://web.archive.org/web/{ts}/{orig}"));
    }
    Ok(out)
}

async fn save_status_h(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Query(q): Query<JobQuery>) -> Result<Json<Value>, ApiError> {
    if !signed_in(&method, &uri, &headers) {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "sign in required".into()));
    }
    Ok(Json(blocking(move || save_status(&s, &q.job)).await?))
}

async fn info(State(s): State<Shared>) -> Json<Value> {
    let keyed = tokio::task::spawn_blocking(move || (s.keys)().is_some()).await.unwrap_or(false);
    Json(json!({ "save_mode": if keyed { "authenticated" } else { "anonymous" }, "archive_today": "link-out only" }))
}

// ---- agent tools --------------------------------------------------------------------------------

async fn tools() -> Json<Value> {
    Json(json!([
        { "name": "archive_snapshots", "description": "List Internet Archive snapshots of a URL: first and last seen, content-change count, per-month capture counts and each capture with status, digest and archive link. Read-only.",
          "method": "GET", "path": "api/snapshots", "parameters": { "type": "object", "properties": {
            "url": { "type": "string", "description": "Page URL or domain to look up" },
            "limit": { "type": "integer", "description": "Max captures (1-5000, default 1000)" },
            "order": { "type": "string", "enum": ["earliest", "latest"], "description": "Which end of history to return when capped" } }, "required": ["url"] } },
        { "name": "archive_diff", "description": "Compare the visible text of two Internet Archive captures of the same page: added and removed lines, similarity and changed links.",
          "method": "GET", "path": "api/diff", "parameters": { "type": "object", "properties": {
            "url": { "type": "string" }, "a": { "type": "string", "description": "Earlier capture timestamp YYYYMMDDhhmmss" }, "b": { "type": "string", "description": "Later capture timestamp YYYYMMDDhhmmss" } }, "required": ["url", "a", "b"] } },
        { "name": "archive_urls", "description": "Harvest URLs the Internet Archive knows for a domain and its subdomains (status 200, deduplicated), with per-host counts.",
          "method": "GET", "path": "api/urls", "parameters": { "type": "object", "properties": {
            "domain": { "type": "string", "description": "Domain such as example.com" }, "limit": { "type": "integer", "description": "Max URLs (1-5000, default 1000)" } }, "required": ["domain"] } },
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

pub fn app(state: Shared) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/info", get(info))
        .route("/api/snapshots", get(snapshots_h))
        .route("/api/urls", get(urls_h))
        .route("/api/commoncrawl", get(cc_h))
        .route("/api/diff", get(diff_h))
        .route("/api/evidence", get(evidence_h))
        .route("/api/save", post(save_h))
        .route("/api/save/status", get(save_status_h))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    let keys: Box<dyn Fn() -> Option<(String, String)> + Send + Sync> = Box::new(|| Some((osnt_common::secret("ARCHIVE_ORG_ACCESS")?, osnt_common::secret("ARCHIVE_ORG_SECRET")?)));
    let state = AppState::new(Guard::default(), Upstreams::default(), keys, Duration::from_millis(800));
    let addr: SocketAddr = env::var("OSNT_WEB_ARCHIVE_BIND").unwrap_or_else(|_| "127.0.0.1:8161".into()).parse().expect("bind addr");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("web-archive plugin on http://{addr}");
    axum::serve(listener, app(state)).await.expect("serve");
}

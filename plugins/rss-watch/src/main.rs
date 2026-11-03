//! Feed watcher: polls the investigator's own RSS/Atom feeds (plus Hacker News keyword searches and opt-in public
//! Telegram channel previews), de-duplicates items, applies keyword/regex alert rules and keeps a "new since last
//! visit" inbox. Feeds live in redb under the state directory. Every feed fetch goes through the SSRF guard
//! (ssrf.rs): public addresses only, ports 80/443, redirects re-validated, body capped.

mod feed;
mod ssrf;
mod store;
#[cfg(test)]
mod testutil;

use std::{collections::HashMap, env, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use store::{Feed, Store, StoredItem};
use url::Url;

const PAGE: &str = include_str!("../assets/index.html");
const UA: &str = "osnt-rss-watch/0.1 (+https://github.com/ogden-marrow/osnt-hub)";
const MAX_FEED_BYTES: usize = 2 * 1024 * 1024;
const ACCEPT: &str = "application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.9, */*;q=0.5";

struct App {
    store: Store,
    guard: ssrf::Guard,
    agent: ureq::Agent,
    plain: ureq::Agent,
    hn_base: String,
    tg_base: String,
}
type Shared = Arc<App>;

struct ApiError(StatusCode, String);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))
    }
}
fn bad(m: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, m.into())
}

fn signed(method: &Method, uri: &Uri, headers: &HeaderMap) -> bool {
    osnt_common::gateway_authorized(method.as_str(), uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"), headers.get("x-osnt-gateway").and_then(|v| v.to_str().ok()))
}
fn require_signed(method: &Method, uri: &Uri, headers: &HeaderMap) -> Result<(), ApiError> {
    if signed(method, uri, headers) { Ok(()) } else { Err(ApiError(StatusCode::UNAUTHORIZED, "sign in through the hub to change feeds and alert rules".into())) }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, ApiError> + Send + 'static) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f).await.map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

// ---------------------------------------------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------------------------------------------

/// Seconds until the feed is due again: its interval, doubled after each failure up to 16x.
fn next_due(f: &Feed) -> i64 {
    f.last_fetch + f.interval_min as i64 * 60 * (1i64 << f.fail_count.min(4))
}

fn fetch_one(app: &App, id: u64) -> Result<Value, ApiError> {
    let Some(mut f) = app.store.feed(id)? else { return Err(ApiError(StatusCode::NOT_FOUND, "no such feed".into())) };
    let outcome: Result<(Option<feed::ParsedFeed>, u16), String> = match f.kind.as_str() {
        "rss" => {
            let mut extra = Vec::new();
            if let Some(e) = &f.etag {
                extra.push(("If-None-Match", e.as_str()));
            }
            if let Some(m) = &f.last_modified {
                extra.push(("If-Modified-Since", m.as_str()));
            }
            ssrf::guarded_get_with(&app.agent, &app.guard, &f.target, MAX_FEED_BYTES, ACCEPT, &extra).and_then(|r| {
                if r.status == 304 {
                    return Ok((None, 304));
                }
                if r.status >= 400 {
                    return Err(format!("the server answered HTTP {}", r.status));
                }
                f.etag = r.etag.clone();
                f.last_modified = r.last_modified.clone();
                feed::parse_feed(&r.body).map(|p| (Some(p), r.status))
            })
        }
        "hn" => {
            let url = format!("{}/api/v1/search_by_date?{}", app.hn_base, url::form_urlencoded::Serializer::new(String::new()).append_pair("query", &f.target).append_pair("tags", "story").append_pair("hitsPerPage", "30").finish());
            app.plain
                .get(&url)
                .config()
                .http_status_as_error(false)
                .build()
                .call()
                .map_err(|e| format!("could not reach Hacker News search: {e}"))
                .and_then(|mut r| {
                    let status = r.status().as_u16();
                    if status != 200 {
                        return Err(format!("Hacker News search answered HTTP {status}"));
                    }
                    let mut buf = Vec::new();
                    std::io::Read::read_to_end(&mut std::io::Read::take(r.body_mut().as_reader(), MAX_FEED_BYTES as u64), &mut buf).map_err(|e| e.to_string())?;
                    feed::parse_hn(&buf).map(|p| (Some(p), status))
                })
        }
        "telegram" => ssrf::guarded_get(&app.agent, &app.guard, &format!("{}/s/{}", app.tg_base, f.target), MAX_FEED_BYTES, "text/html").and_then(|r| {
            if r.status >= 400 {
                return Err(format!("t.me answered HTTP {}", r.status));
            }
            feed::parse_telegram(&String::from_utf8_lossy(&r.body), &f.target).map(|p| (Some(p), r.status))
        }),
        _ => Err("unknown feed kind".into()),
    };
    let t = now();
    f.last_fetch = t;
    let mut new = 0;
    let result = match outcome {
        Ok((parsed, status)) => {
            f.last_status = Some(status);
            f.last_ok = t;
            f.fail_count = 0;
            f.last_error = None;
            if let Some(p) = parsed {
                if f.title.is_empty() || f.title == f.target {
                    f.title = if p.title.is_empty() { f.target.clone() } else { p.title.clone() };
                }
                new = app.store.insert_items(f.id, &p.items, t)?;
            }
            Ok(())
        }
        Err(e) => {
            f.fail_count = f.fail_count.saturating_add(1);
            f.last_error = Some(e.chars().take(300).collect());
            Err(e)
        }
    };
    f.item_count = app.store.count_items(f.id)?;
    app.store.put_feed(&f)?;
    Ok(json!({ "id": f.id, "ok": result.is_ok(), "new": new, "error": result.err() }))
}

// ---------------------------------------------------------------------------------------------------------------
// Feeds
// ---------------------------------------------------------------------------------------------------------------

fn feed_json(f: &Feed, full: bool) -> Value {
    let host = Url::parse(&f.target).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
    let label = match f.kind.as_str() {
        "rss" => host.clone(),
        "hn" => format!("Hacker News: {}", f.target),
        _ => format!("Telegram @{}", f.target),
    };
    // Feed URLs can embed private tokens, so only a signed-in user sees them.
    json!({
        "id": f.id, "kind": f.kind, "title": if f.title.is_empty() { &label } else { &f.title }, "label": label, "url": full.then_some(&f.target),
        "interval_min": f.interval_min, "added": f.added, "last_fetch": f.last_fetch, "last_ok": f.last_ok, "fail_count": f.fail_count,
        "last_error": f.last_error, "last_status": f.last_status, "items": f.item_count,
        "health": if f.last_fetch == 0 { "pending" } else if f.fail_count == 0 { "ok" } else if f.last_ok > 0 && f.fail_count < 3 { "warn" } else { "failing" },
        "next_due": next_due(f),
    })
}

async fn list_feeds(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let full = signed(&method, &uri, &headers);
    let mut feeds = s.store.feeds()?;
    feeds.sort_by_key(|f| f.title.to_lowercase());
    Ok(Json(json!({ "feeds": feeds.iter().map(|f| feed_json(f, full)).collect::<Vec<_>>(), "max": store::MAX_FEEDS })))
}

/// Validate a feed URL for storage: http/https, no credentials, public address (re-checked on every fetch).
fn check_feed_url(app: &App, raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if raw.len() > 500 {
        return Err("URL is too long".into());
    }
    let url = Url::parse(raw).map_err(|_| "not a valid URL".to_string())?;
    app.guard.check_url(&url, false)?;
    Ok(url.to_string())
}

#[derive(Deserialize)]
struct NewFeed {
    #[serde(default = "d_kind")]
    kind: String,
    target: String,
    #[serde(default)]
    title: String,
    interval_min: Option<u32>,
}
fn d_kind() -> String {
    "rss".into()
}

fn normalise_target(app: &App, kind: &str, raw: &str) -> Result<String, String> {
    match kind {
        "rss" => check_feed_url(app, raw),
        "hn" => {
            let q = raw.trim();
            if !(2..=80).contains(&q.chars().count()) || q.chars().any(|c| c.is_control()) {
                return Err("Hacker News keywords must be 2 to 80 characters".into());
            }
            Ok(q.to_string())
        }
        "telegram" => {
            let c = raw.trim().trim_start_matches('@');
            let c = c.strip_prefix("https://t.me/s/").or_else(|| c.strip_prefix("https://t.me/")).or_else(|| c.strip_prefix("t.me/")).unwrap_or(c);
            let c = c.split(['/', '?']).next().unwrap_or("");
            if !feed::valid_channel(c) {
                return Err("enter a public channel name (5 to 32 letters, digits or underscores)".into());
            }
            Ok(c.to_string())
        }
        _ => Err("kind must be rss, hn or telegram".into()),
    }
}

async fn add_feed(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, body: String) -> Result<Json<Value>, ApiError> {
    require_signed(&method, &uri, &headers)?;
    let b: NewFeed = serde_json::from_str(&body).map_err(|e| bad(format!("invalid request: {e}")))?;
    blocking(move || {
        let target = normalise_target(&s, &b.kind, &b.target).map_err(bad)?;
        let title = b.title.trim();
        if title.chars().count() > 80 || title.chars().any(|c| c.is_control()) {
            return Err(bad("title must be 80 characters or fewer"));
        }
        let default_iv = if b.kind == "rss" { 30 } else { 60 };
        let iv = b.interval_min.unwrap_or(default_iv).clamp(5, 1440);
        let f = s.store.add_feed(&b.kind, &target, title, iv, now()).map_err(|e| bad(e.to_string()))?;
        let fetched = fetch_one(&s, f.id)?;
        let f = s.store.feed(f.id)?.unwrap_or(f);
        Ok(Json(json!({ "feed": feed_json(&f, true), "fetch": fetched })))
    })
    .await
}

async fn delete_feed(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Path(id): Path<u64>) -> Result<Json<Value>, ApiError> {
    require_signed(&method, &uri, &headers)?;
    if !s.store.delete_feed(id)? {
        return Err(ApiError(StatusCode::NOT_FOUND, "no such feed".into()));
    }
    Ok(Json(json!({ "ok": true })))
}

async fn refresh_one(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Path(id): Path<u64>) -> Result<Json<Value>, ApiError> {
    require_signed(&method, &uri, &headers)?;
    Ok(Json(blocking(move || fetch_one(&s, id)).await?))
}

async fn refresh_all(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    require_signed(&method, &uri, &headers)?;
    blocking(move || {
        let t = now();
        let mut results = Vec::new();
        for f in s.store.feeds()?.into_iter().filter(|f| t - f.last_fetch >= 60).take(20) {
            results.push(fetch_one(&s, f.id)?);
        }
        let new: u64 = results.iter().filter_map(|r| r["new"].as_u64()).sum();
        Ok(Json(json!({ "fetched": results.len(), "new": new, "results": results })))
    })
    .await
}

// ---------------------------------------------------------------------------------------------------------------
// OPML
// ---------------------------------------------------------------------------------------------------------------

async fn opml_export(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap) -> Result<Response, ApiError> {
    require_signed(&method, &uri, &headers)?;
    let rows: Vec<(String, String)> = s.store.feeds()?.into_iter().filter(|f| f.kind == "rss").map(|f| (f.target, f.title)).collect();
    Ok(([(header::CONTENT_TYPE, "text/x-opml; charset=utf-8"), (header::CONTENT_DISPOSITION, "attachment; filename=\"osnt-feeds.opml\"")], feed::build_opml(&rows)).into_response())
}

async fn opml_import(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, body: String) -> Result<Json<Value>, ApiError> {
    require_signed(&method, &uri, &headers)?;
    blocking(move || {
        let list = feed::parse_opml(body.as_bytes()).map_err(bad)?;
        let (mut added, mut skipped) = (0, Vec::new());
        for (url, title) in list.into_iter().take(200) {
            let r = check_feed_url(&s, &url).and_then(|u| s.store.add_feed("rss", &u, &title.chars().take(80).collect::<String>(), 30, now()).map(|_| ()).map_err(|e| e.to_string()));
            match r {
                Ok(()) => added += 1,
                Err(e) => skipped.push(json!({ "url": url.chars().take(100).collect::<String>(), "reason": e })),
            }
        }
        Ok(Json(json!({ "added": added, "skipped": skipped })))
    })
    .await
}

// ---------------------------------------------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------------------------------------------

async fn list_rules(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    require_signed(&method, &uri, &headers)?;
    Ok(Json(json!({ "rules": s.store.rules()?, "max": store::MAX_RULES })))
}

#[derive(Deserialize)]
struct NewRule {
    #[serde(default)]
    name: String,
    kind: String,
    pattern: String,
}

async fn add_rule(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, body: String) -> Result<Json<Value>, ApiError> {
    require_signed(&method, &uri, &headers)?;
    let b: NewRule = serde_json::from_str(&body).map_err(|e| bad(format!("invalid request: {e}")))?;
    feed::validate_rule(&b.kind, &b.pattern).map_err(bad)?;
    let name = if b.name.trim().is_empty() { b.pattern.trim().chars().take(30).collect() } else { b.name.trim().to_string() };
    if name.chars().count() > 60 || name.chars().any(|c| c.is_control()) {
        return Err(bad("name must be 60 characters or fewer"));
    }
    Ok(Json(json!(s.store.add_rule(&name, &b.kind, b.pattern.trim()).map_err(|e| bad(e.to_string()))?)))
}

async fn delete_rule(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Path(id): Path<u64>) -> Result<Json<Value>, ApiError> {
    require_signed(&method, &uri, &headers)?;
    if !s.store.delete_rule(id)? {
        return Err(ApiError(StatusCode::NOT_FOUND, "no such rule".into()));
    }
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------------------------------------------
// Inbox and search
// ---------------------------------------------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct InboxQ {
    feed: Option<u64>,
    rule: Option<u64>,
    #[serde(default)]
    unread: bool,
    #[serde(default)]
    alerts_only: bool,
    #[serde(default)]
    q: String,
    limit: Option<usize>,
}

fn build_inbox(app: &App, q: &InboxQ) -> Result<Value, ApiError> {
    let feeds: HashMap<u64, Feed> = app.store.feeds()?.into_iter().map(|f| (f.id, f)).collect();
    let rules = app.store.rules()?;
    let last_seen = app.store.last_seen()?;
    let needle = q.q.trim().to_lowercase();
    let mut items: Vec<StoredItem> = app.store.all_items()?.into_iter().filter(|i| feeds.contains_key(&i.feed) && q.feed.is_none_or(|f| f == i.feed)).collect();
    items.sort_by(|a, b| b.when().cmp(&a.when()).then(b.fetched.cmp(&a.fetched)));
    let limit = q.limit.unwrap_or(100).clamp(1, 300);
    let (mut out, mut total, mut new_total) = (Vec::new(), 0usize, 0usize);
    for it in items {
        let text = format!("{} {}", it.title, it.summary);
        if !needle.is_empty() && !text.to_lowercase().contains(&needle) {
            continue;
        }
        let is_new = it.fetched > last_seen;
        let matches: Vec<Value> = rules
            .iter()
            .filter_map(|r| {
                let m = feed::rule_matches(r, &text);
                (!m.is_empty()).then(|| json!({ "rule": r.id, "name": r.name, "terms": m }))
            })
            .collect();
        if q.rule.is_some_and(|rid| !matches.iter().any(|m| m["rule"] == rid)) || (q.alerts_only && matches.is_empty()) || (q.unread && !is_new) {
            continue;
        }
        total += 1;
        new_total += is_new as usize;
        if out.len() < limit {
            let fd = &feeds[&it.feed];
            out.push(json!({ "id": it.id, "feed": it.feed, "feed_title": if fd.title.is_empty() { &fd.target } else { &fd.title }, "kind": fd.kind, "title": it.title, "link": it.link, "summary": it.summary,
                "published": it.published, "fetched": it.fetched, "new": is_new, "matches": matches }));
        }
    }
    Ok(json!({ "items": out, "total": total, "new": new_total, "last_seen": last_seen, "now": now() }))
}

async fn inbox(State(s): State<Shared>, Query(q): Query<InboxQ>) -> Result<Json<Value>, ApiError> {
    Ok(Json(blocking(move || build_inbox(&s, &q)).await?))
}

async fn search(State(s): State<Shared>, Query(q): Query<InboxQ>) -> Result<Json<Value>, ApiError> {
    if q.q.trim().chars().count() < 2 {
        return Err(bad("search needs at least 2 characters"));
    }
    Ok(Json(blocking(move || build_inbox(&s, &q)).await?))
}

async fn mark_seen(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    require_signed(&method, &uri, &headers)?;
    s.store.set_last_seen(now())?;
    Ok(Json(json!({ "ok": true })))
}

async fn tools() -> Json<Value> {
    Json(json!([
        { "name": "rss_inbox", "description": "Items from the investigator's watched feeds (RSS/Atom, Hacker News keyword alerts, public Telegram channel previews), newest first, with which alert rules matched and whether each item is new since the last visit. Returns titles, short summaries and links.",
          "method": "GET", "path": "api/inbox", "parameters": { "type": "object", "properties": {
              "unread": { "type": "boolean", "description": "only items new since the last visit" }, "alerts_only": { "type": "boolean", "description": "only items matching an alert rule" },
              "feed": { "type": "integer", "description": "limit to one feed id" }, "limit": { "type": "integer", "description": "1 to 300, default 100" } } } },
        { "name": "rss_search", "description": "Search the stored feed items by text (title and summary).",
          "method": "GET", "path": "api/search", "parameters": { "type": "object", "properties": { "q": { "type": "string", "description": "text to find, 2+ characters" }, "limit": { "type": "integer" } }, "required": ["q"] } }
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

fn router(app: Shared) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/feeds", get(list_feeds).post(add_feed))
        .route("/api/feeds/{id}", delete(delete_feed))
        .route("/api/feeds/{id}/refresh", post(refresh_one))
        .route("/api/refresh", post(refresh_all))
        .route("/api/opml", get(opml_export).post(opml_import))
        .route("/api/rules", get(list_rules).post(add_rule))
        .route("/api/rules/{id}", delete(delete_rule))
        .route("/api/inbox", get(inbox))
        .route("/api/search", get(search))
        .route("/api/seen", post(mark_seen))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .with_state(app)
}

fn scheduler(app: Shared) {
    loop {
        std::thread::sleep(Duration::from_secs(20));
        let t = now();
        let due = app.store.feeds().unwrap_or_default().into_iter().filter(|f| next_due(f) <= t).min_by_key(|f| f.last_fetch);
        if let Some(f) = due {
            let _ = fetch_one(&app, f.id);
        }
    }
}

fn make_app(db: &str, guard: ssrf::Guard, hn_base: &str, tg_base: &str) -> Result<Shared> {
    Ok(Arc::new(App { store: Store::open(db)?, agent: ssrf::guarded_agent(guard.clone(), UA), guard, plain: osnt_common::http_agent(UA), hn_base: hn_base.trim_end_matches('/').into(), tg_base: tg_base.trim_end_matches('/').into() }))
}

#[tokio::main]
async fn main() -> Result<()> {
    let db = env::var("OSNT_RSS_DB").unwrap_or_else(|_| "rss.redb".into());
    let app = make_app(&db, ssrf::Guard::default(), "https://hn.algolia.com", "https://t.me")?;
    match app.store.cleanup(now()) {
        Ok(n) if n > 0 => println!("cleaned up {n} old items"),
        Err(e) => eprintln!("cleanup failed: {e}"),
        _ => {}
    }
    let bg = app.clone();
    std::thread::spawn(move || scheduler(bg));
    let addr: SocketAddr = env::var("OSNT_RSS_BIND").unwrap_or_else(|_| "127.0.0.1:8150".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("rss-watch plugin on http://{addr}");
    axum::serve(listener, router(app)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    fn serve(app: Shared) -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async move {
                axum::serve(tokio::net::TcpListener::from_std(l).unwrap(), router(app)).await.unwrap();
            })
        });
        port
    }

    fn call(port: u16, method: &str, path: &str, sign_it: bool, body: Option<&str>) -> (u16, Value) {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
        let mut b = ureq::http::Request::builder().method(method).uri(format!("http://127.0.0.1:{port}{path}"));
        if sign_it {
            b = b.header("X-OSNT-Gateway", sign(method, path));
        }
        let req = b.header("Content-Type", "application/json").body(body.unwrap_or("").to_string()).unwrap();
        let mut r = agent.run(req).unwrap();
        let st = r.status().as_u16();
        let text = r.body_mut().read_to_string().unwrap_or_default();
        (st, serde_json::from_str(&text).unwrap_or(Value::String(text)))
    }

    const FEED_A: &str = "<rss><channel><title>Wire A</title><item><title>Strong quake hits coast</title><link>https://a.test/1</link><pubDate>Mon, 02 Nov 2026 10:00:00 GMT</pubDate><description>Magnitude M6.4 offshore</description></item><item><title>Markets calm</title><link>https://a.test/2</link><pubDate>Mon, 02 Nov 2026 09:00:00 GMT</pubDate></item></channel></rss>";

    struct Env {
        port: u16,
        fake: u16,
    }

    fn env(tag: &str) -> Env {
        init_env();
        let fake = spawn(Arc::new(move |r| {
            let p = r.path.as_str();
            let has = |n: &str| r.headers.iter().any(|(k, _)| k == n);
            match p {
                "/feed.xml" if has("if-none-match") => Resp::status(304, ""),
                "/feed.xml" => Resp { status: 200, headers: vec![("Content-Type".into(), "application/rss+xml".into()), ("ETag".into(), "\"v1\"".into())], body: FEED_A.as_bytes().to_vec() },
                "/to-private" => Resp { status: 302, headers: vec![("Location".into(), "http://10.0.0.5/feed".into())], body: vec![] },
                "/to-meta" => Resp { status: 302, headers: vec![("Location".into(), "http://169.254.169.254/latest/".into())], body: vec![] },
                "/huge.xml" => Resp::text(&format!("<rss><channel><item><title>first</title></item>{}", "<!-- pad -->".repeat(400_000))),
                "/notfeed" => Resp::text("<html>hello</html>"),
                "/gone" => Resp::status(404, "no"),
                _ if p.starts_with("/api/v1/search_by_date") => Resp::json(json!({ "hits": [{ "objectID": "42", "title": "Quake report", "url": "https://q.test/r", "points": 3, "num_comments": 1, "created_at_i": 1793600000 }] })),
                "/s/chan_news" => Resp::text(r#"<div class="tgme_widget_message_wrap"><div data-post="chan_news/7"><div class="tgme_widget_message_text">Port closed after quake</div><time datetime="2026-11-02T10:00:00+00:00"></time></div></div>"#),
                "/s/emptychan" => Resp::text("<html>no posts</html>"),
                _ => Resp::status(404, "nf"),
            }
        }));
        let db = std::env::temp_dir().join(format!("rss-main-{tag}-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&db);
        let base = format!("http://127.0.0.1:{fake}");
        let app = make_app(db.to_str().unwrap(), ssrf::Guard { exempt_loopback_port: Some(fake) }, &base, &base).unwrap();
        Env { port: serve(app), fake }
    }

    fn add(e: &Env, kind: &str, target: &str) -> (u16, Value) {
        call(e.port, "POST", "/api/feeds", true, Some(&json!({ "kind": kind, "target": target }).to_string()))
    }

    #[test]
    fn mutations_need_the_gateway_signature() {
        let e = env("auth");
        for (m, p) in [("POST", "/api/feeds"), ("DELETE", "/api/feeds/1"), ("POST", "/api/feeds/1/refresh"), ("POST", "/api/refresh"), ("GET", "/api/opml"), ("POST", "/api/opml"), ("GET", "/api/rules"), ("POST", "/api/rules"), ("DELETE", "/api/rules/1"), ("POST", "/api/seen")] {
            assert_eq!(call(e.port, m, p, false, Some("{}")).0, 401, "{m} {p}");
        }
        // open reads
        assert_eq!(call(e.port, "GET", "/api/inbox", false, None).0, 200);
        assert_eq!(call(e.port, "GET", "/api/feeds", false, None).0, 200);
    }

    #[test]
    fn add_validates_and_blocks_internal_addresses() {
        let e = env("add");
        for bad_url in ["not a url", "ftp://example.com/feed", "http://127.0.0.1:8110/internal/secrets/X", "http://10.0.0.1/feed", "http://169.254.169.254/latest/meta-data/", "http://[::1]/feed", "http://localhost/feed", "https://user:pw@93.184.216.34/f", "http://93.184.216.34:8080/feed", "file:///etc/passwd"] {
            let (st, v) = add(&e, "rss", bad_url);
            assert_eq!(st, 400, "{bad_url}: {v}");
        }
        assert_eq!(add(&e, "hn", "x").0, 400);
        assert_eq!(add(&e, "telegram", "a/b").0, 400);
        assert_eq!(add(&e, "telegram", "ab").0, 400);
        assert_eq!(add(&e, "carrier-pigeon", "x").0, 400);
        let (st, v) = call(e.port, "POST", "/api/feeds", true, Some(&json!({ "target": format!("http://127.0.0.1:{}/feed.xml", e.fake), "title": "t".repeat(81) }).to_string()));
        assert_eq!((st, v["error"].as_str().is_some()), (400, true));
    }

    #[test]
    fn fetch_parse_dedupe_conditional_and_inbox() {
        let e = env("fetch");
        let url = format!("http://127.0.0.1:{}/feed.xml", e.fake);
        let (st, v) = add(&e, "rss", &url);
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["fetch"]["new"], 2);
        assert_eq!(v["feed"]["title"], "Wire A");
        assert_eq!(v["feed"]["health"], "ok");
        assert_eq!(add(&e, "rss", &url).0, 400, "duplicate");
        let id = v["feed"]["id"].as_u64().unwrap();
        // second refresh sends If-None-Match and gets 304: no new items, still healthy
        let (st, v) = call(e.port, "POST", &format!("/api/feeds/{id}/refresh"), true, None);
        assert_eq!((st, v["new"].clone(), v["ok"].clone()), (200, json!(0), json!(true)));
        // unsigned list hides the URL, signed shows it
        let (_, l) = call(e.port, "GET", "/api/feeds", false, None);
        assert!(l["feeds"][0]["url"].is_null());
        let (_, l) = call(e.port, "GET", "/api/feeds", true, None);
        assert_eq!(l["feeds"][0]["url"], url);
        // rules and highlighting
        assert_eq!(call(e.port, "POST", "/api/rules", true, Some(r#"{"kind":"regex","pattern":"("}"#)).0, 400);
        let (st, r) = call(e.port, "POST", "/api/rules", true, Some(r#"{"name":"Quakes","kind":"keyword","pattern":"quake, tsunami"}"#));
        assert_eq!(st, 200);
        let rid = r["id"].as_u64().unwrap();
        call(e.port, "POST", "/api/rules", true, Some(r#"{"kind":"regex","pattern":"M\\d\\.\\d"}"#));
        let (_, inbox) = call(e.port, "GET", "/api/inbox", false, None);
        assert_eq!(inbox["total"], 2);
        assert_eq!(inbox["new"], 2, "everything is new before the first visit is recorded");
        assert_eq!(inbox["items"][0]["title"], "Strong quake hits coast", "newest first");
        assert_eq!(inbox["items"][0]["matches"].as_array().unwrap().len(), 2);
        assert_eq!(inbox["items"][0]["matches"][0]["terms"][0], "quake");
        let (_, only) = call(e.port, "GET", &format!("/api/inbox?rule={rid}"), false, None);
        assert_eq!(only["total"], 1);
        let (_, only) = call(e.port, "GET", "/api/inbox?alerts_only=true", false, None);
        assert_eq!(only["total"], 1);
        // new since last visit
        assert_eq!(call(e.port, "POST", "/api/seen", true, None).0, 200);
        let (_, inbox) = call(e.port, "GET", "/api/inbox?unread=true", false, None);
        assert_eq!(inbox["total"], 0);
        // search
        assert_eq!(call(e.port, "GET", "/api/search?q=x", false, None).0, 400);
        let (_, s) = call(e.port, "GET", "/api/search?q=MARKETS", false, None);
        assert_eq!(s["total"], 1);
        // deleting the feed removes its items
        assert_eq!(call(e.port, "DELETE", &format!("/api/feeds/{id}"), true, None).0, 200);
        let (_, inbox) = call(e.port, "GET", "/api/inbox", false, None);
        assert_eq!(inbox["total"], 0);
    }

    #[test]
    fn errors_are_recorded_in_feed_health() {
        let e = env("health");
        let base = format!("http://127.0.0.1:{}", e.fake);
        for (path, expect) in [("/gone", "HTTP 404"), ("/notfeed", "not an RSS"), ("/to-private", "blocked"), ("/to-meta", "blocked")] {
            let (st, v) = add(&e, "rss", &format!("{base}{path}"));
            assert_eq!(st, 200, "{path}: {v}");
            assert_eq!(v["fetch"]["ok"], false, "{path}");
            let err = v["fetch"]["error"].as_str().unwrap();
            assert!(err.contains(expect), "{path}: {err}");
            assert_eq!(v["feed"]["fail_count"], 1);
            assert_eq!(v["feed"]["health"], "failing");
        }
        // none of the redirect targets was ever contacted from the fake server's point of view
    }

    #[test]
    fn oversized_feed_is_truncated_not_buffered() {
        let e = env("huge");
        let (st, v) = add(&e, "rss", &format!("http://127.0.0.1:{}/huge.xml", e.fake));
        assert_eq!(st, 200);
        // 4.8 MB body, cap 2 MB: the parser still gets the first item from the truncated prefix
        assert_eq!(v["fetch"]["new"], 1, "{v}");
    }

    #[test]
    fn hn_and_telegram_sources() {
        let e = env("src");
        let (st, v) = add(&e, "hn", "quake");
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["fetch"]["new"], 1);
        let (st, v) = add(&e, "telegram", "@chan_news");
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["fetch"]["new"], 1);
        assert_eq!(v["feed"]["url"], "chan_news");
        let (st, v) = add(&e, "telegram", "https://t.me/emptychan");
        assert_eq!(st, 200);
        assert_eq!(v["fetch"]["ok"], false);
        assert!(v["fetch"]["error"].as_str().unwrap().contains("public"));
        let (_, inbox) = call(e.port, "GET", "/api/inbox", false, None);
        assert_eq!(inbox["total"], 2);
    }

    #[test]
    fn opml_import_export() {
        let e = env("opml");
        call(e.port, "POST", "/api/feeds", true, Some(&json!({ "target": format!("http://127.0.0.1:{}/feed.xml", e.fake) }).to_string()));
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
        let mut r = agent.get(&format!("http://127.0.0.1:{}/api/opml", e.port)).header("X-OSNT-Gateway", sign("GET", "/api/opml")).call().unwrap();
        let xml = r.body_mut().read_to_string().unwrap();
        assert!(xml.contains("<opml") && xml.contains("/feed.xml"));
        let imp = format!(r#"<opml version="2.0"><body><outline text="Bad" xmlUrl="http://10.1.1.1/f"/><outline text="Dup" xmlUrl="http://127.0.0.1:{}/feed.xml"/><outline text="Gone" xmlUrl="http://127.0.0.1:{}/gone"/></body></opml>"#, e.fake, e.fake);
        let (st, v) = call(e.port, "POST", "/api/opml", true, Some(&imp));
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["added"], 1);
        assert_eq!(v["skipped"].as_array().unwrap().len(), 2);
        assert_eq!(call(e.port, "POST", "/api/opml", true, Some("<rss/>")).0, 400);
    }

    #[test]
    fn backoff_schedule() {
        let mut f = Feed { id: 1, kind: "rss".into(), target: "x".into(), title: String::new(), interval_min: 10, added: 0, last_fetch: 1000, last_ok: 0, fail_count: 0, last_error: None, last_status: None, etag: None, last_modified: None, item_count: 0 };
        assert_eq!(next_due(&f), 1600);
        f.fail_count = 2;
        assert_eq!(next_due(&f), 1000 + 2400);
        f.fail_count = 30;
        assert_eq!(next_due(&f), 1000 + 600 * 16);
    }

    #[test]
    fn tools_shape() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let Json(v) = rt.block_on(tools());
        assert_eq!(v.as_array().unwrap().len(), 2);
        assert!(v[0]["path"].as_str().unwrap().starts_with("api/"));
    }
}

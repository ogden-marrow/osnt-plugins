//! Global news monitor over GDELT: article search, volume and tone timelines, the latest export file list and
//! saved "stories" whose volume is checked in the background for spikes. Events, places, organisations and coverage;
//! nothing here follows individuals. All upstream calls share one 5-second queue (see gdelt.rs).

mod gdelt;
#[cfg(test)]
mod testutil;

use std::{env, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
};
use gdelt::{Client, GdeltError, Store};
use serde::Deserialize;
use serde_json::{Value, json};

const PAGE: &str = include_str!("../assets/index.html");
const UA: &str = "osnt-gdelt-news/0.1 (+https://github.com/ogden-marrow/osnt-hub)";
const CHECK_EVERY_SECS: u64 = 3600;

struct App {
    client: Client,
    store: Store,
}
type Shared = Arc<App>;

struct ApiError(StatusCode, String);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut r = (self.0, Json(json!({ "error": self.1 }))).into_response();
        if self.0 == StatusCode::TOO_MANY_REQUESTS {
            r.headers_mut().insert(header::RETRY_AFTER, "10".parse().unwrap());
        }
        r
    }
}
impl From<GdeltError> for ApiError {
    fn from(e: GdeltError) -> Self {
        let code = match &e {
            GdeltError::BadInput(_) => StatusCode::BAD_REQUEST,
            GdeltError::Busy | GdeltError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            GdeltError::Upstream(_) => StatusCode::BAD_GATEWAY,
        };
        ApiError(code, e.to_string())
    }
}
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))
    }
}
fn bad(m: &str) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, m.into())
}

/// Saved stories are the investigator's watch list: only requests the hub has signed (a signed-in user) may read or change them.
fn require_signed(method: &Method, uri: &Uri, headers: &HeaderMap) -> Result<(), ApiError> {
    let ok = osnt_common::gateway_authorized(method.as_str(), uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"), headers.get("x-osnt-gateway").and_then(|v| v.to_str().ok()));
    if ok { Ok(()) } else { Err(ApiError(StatusCode::UNAUTHORIZED, "sign in through the hub to use saved stories".into())) }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, ApiError> + Send + 'static) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f).await.map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

#[derive(Deserialize)]
struct SearchQ {
    q: String,
    #[serde(default)]
    lang: String,
    #[serde(default)]
    country: String,
    #[serde(default = "d_span")]
    timespan: String,
    max: Option<u32>,
    #[serde(default)]
    sort: String,
    #[serde(default)]
    mode: String,
}
fn d_span() -> String {
    "24h".into()
}

async fn articles(State(s): State<Shared>, Query(q): Query<SearchQ>) -> Result<Json<Value>, ApiError> {
    Ok(Json(blocking(move || Ok(s.client.articles(&q.q, &q.lang, &q.country, &q.timespan, gdelt::clamp_max(q.max), &q.sort)?)).await?))
}

async fn timeline(State(s): State<Shared>, Query(q): Query<SearchQ>) -> Result<Json<Value>, ApiError> {
    Ok(Json(blocking(move || Ok(s.client.timeline(&q.q, &q.lang, &q.country, &q.timespan, &q.mode)?)).await?))
}

async fn latest(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    Ok(Json(blocking(move || Ok(s.client.latest()?)).await?))
}

async fn info(State(s): State<Shared>) -> Json<Value> {
    Json(json!({ "spacing_secs": 5, "queued": s.client.gate.queued(), "check_every_minutes": CHECK_EVERY_SECS / 60, "max_stories": gdelt::MAX_STORIES }))
}

async fn stories(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    require_signed(&method, &uri, &headers)?;
    Ok(Json(json!({ "stories": s.store.list()? })))
}

#[derive(Deserialize)]
struct NewStory {
    #[serde(default)]
    name: String,
    q: String,
    #[serde(default)]
    lang: String,
    #[serde(default)]
    country: String,
}

async fn add_story(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Json(b): Json<NewStory>) -> Result<Json<Value>, ApiError> {
    require_signed(&method, &uri, &headers)?;
    gdelt::build_query(&b.q, &b.lang, &b.country)?; // validate only
    let name = if b.name.trim().is_empty() { b.q.trim().to_string() } else { b.name.trim().to_string() };
    if name.chars().count() > 60 || name.chars().any(|c| c.is_control()) {
        return Err(bad("name must be 60 characters or fewer"));
    }
    let story = s.store.add(&name, b.q.trim(), b.lang.trim(), b.country.trim()).map_err(|e| bad(&e.to_string()))?;
    Ok(Json(json!(story)))
}

async fn delete_story(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Path(id): Path<u64>) -> Result<Json<Value>, ApiError> {
    require_signed(&method, &uri, &headers)?;
    if !s.store.delete(id)? {
        return Err(ApiError(StatusCode::NOT_FOUND, "no such story".into()));
    }
    Ok(Json(json!({ "ok": true })))
}

async fn check_story(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Path(id): Path<u64>) -> Result<Json<Value>, ApiError> {
    require_signed(&method, &uri, &headers)?;
    let story = blocking(move || Ok(gdelt::check_story(&s.client, &s.store, id)?)).await?;
    story.map(|st| Json(json!(st))).ok_or(ApiError(StatusCode::NOT_FOUND, "no such story".into()))
}

async fn tools() -> Json<Value> {
    let s = |d: &str| json!({ "type": "string", "description": d });
    Json(json!([
        { "name": "gdelt_articles", "description": "Search worldwide news coverage through GDELT (last 15 minutes to 3 months). Returns article titles, links, source domains, languages and countries, plus the top domains. Coverage metadata only; GDELT allows one request per 5 seconds so answers can take a few seconds.",
          "method": "GET", "path": "api/articles", "parameters": { "type": "object", "properties": {
              "q": s("search words; use quotes for phrases and (a OR b) for alternatives"), "lang": s("optional source language, for example english"), "country": s("optional source country code or name, for example US"),
              "timespan": s("15min, 6h, 24h (default), 7d, 2w or 1m"), "max": { "type": "integer", "description": "1 to 250, default 50" } }, "required": ["q"] } },
        { "name": "gdelt_timeline", "description": "Coverage volume (share of all monitored news) or average tone over time for a query, from GDELT.",
          "method": "GET", "path": "api/timeline", "parameters": { "type": "object", "properties": {
              "q": s("search words"), "mode": s("vol (default) or tone"), "timespan": s("15min to 1m, default 24h"), "lang": s("optional source language"), "country": s("optional source country") }, "required": ["q"] } },
        { "name": "gdelt_latest_files", "description": "Links to the newest 15-minute GDELT event, mentions and GKG export files (nothing is downloaded).",
          "method": "GET", "path": "api/latest", "parameters": { "type": "object", "properties": {} } }
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

fn router(app: Shared) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/info", get(info))
        .route("/api/articles", get(articles))
        .route("/api/timeline", get(timeline))
        .route("/api/latest", get(latest))
        .route("/api/stories", get(stories).post(add_story))
        .route("/api/stories/{id}", delete(delete_story))
        .route("/api/stories/{id}/check", post(check_story))
        .with_state(app)
}

/// Checks the story that has waited longest (at most one per cycle, only while no user request is queued).
fn checker(app: Shared) {
    loop {
        std::thread::sleep(Duration::from_secs(30));
        if app.client.gate.queued() > 0 {
            continue;
        }
        let due = app.store.list().unwrap_or_default().into_iter().filter(|s| s.checked.is_none_or(|c| gdelt::now().saturating_sub(c) >= CHECK_EVERY_SECS)).min_by_key(|s| s.checked.unwrap_or(0));
        if let Some(st) = due {
            let _ = gdelt::check_story(&app.client, &app.store, st.id);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let doc = env::var("OSNT_GDELT_DOC_BASE").unwrap_or_else(|_| gdelt::DOC_BASE.into());
    let data = env::var("OSNT_GDELT_DATA_BASE").unwrap_or_else(|_| gdelt::DATA_BASE.into());
    let db = env::var("OSNT_GDELT_DB").unwrap_or_else(|_| "gdelt.redb".into());
    let app: Shared = Arc::new(App { client: Client::new(osnt_common::http_agent(UA), &doc, &data, gdelt::SPACING), store: Store::open(&db)? });
    let bg = app.clone();
    std::thread::spawn(move || checker(bg));
    let addr: SocketAddr = env::var("OSNT_GDELT_BIND").unwrap_or_else(|_| "127.0.0.1:8149".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("gdelt-news plugin on http://{addr}");
    axum::serve(listener, router(app)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn serve(app: Shared) -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async move {
                let l = tokio::net::TcpListener::from_std(l).unwrap();
                axum::serve(l, router(app)).await.unwrap();
            })
        });
        port
    }

    fn call(port: u16, method: &str, path: &str, sign_it: bool, body: Option<Value>) -> (u16, Value) {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
        let url = format!("http://127.0.0.1:{port}{path}");
        let mut b = ureq::http::Request::builder().method(method).uri(&url);
        if sign_it {
            b = b.header("X-OSNT-Gateway", sign(method, path));
        }
        let req = b.header("Content-Type", "application/json").body(body.map(|v| v.to_string()).unwrap_or_default()).unwrap();
        let mut r = agent.run(req).unwrap();
        let st = r.status().as_u16();
        (st, r.body_mut().read_json().unwrap_or(Value::Null))
    }

    fn fake(hits: Arc<AtomicUsize>) -> u16 {
        spawn(Arc::new(move |r| {
            hits.fetch_add(1, Ordering::SeqCst);
            if r.path.starts_with("/gdeltv2/lastupdate.txt") {
                return Resp::text("47711 e942270a831268825bcac5361b0f0bb3 http://data.gdeltproject.org/gdeltv2/20261103044500.export.CSV.zip\n");
            }
            if r.path.contains("mode=artlist") {
                if r.path.contains("limitme") {
                    return Resp::status(429, "Please limit requests to one every 5 seconds");
                }
                if r.path.contains("short") {
                    return Resp::text("The specified phrase is too short.");
                }
                return Resp::json(json!({ "articles": [{ "url": "https://n.example/a", "title": "Flood in <b>town</b>", "seendate": "20261102T120000Z", "domain": "n.example", "language": "English", "sourcecountry": "France" }] }));
            }
            if r.path.contains("mode=timelinevol") {
                let data: Vec<Value> = (0..40).map(|i| json!({ "date": format!("20261102T{:02}{:02}00Z", i / 4, (i % 4) * 15), "value": if i >= 35 && i < 39 { 5.0 } else { 1.0 } })).collect();
                return Resp::json(json!({ "query_details": { "date_resolution": "15m" }, "timeline": [{ "series": "v", "data": data }] }));
            }
            Resp::status(500, "boom")
        }))
    }

    fn app_for(fake_port: u16, tag: &str) -> Shared {
        let db = std::env::temp_dir().join(format!("gdelt-{tag}-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&db);
        let base = format!("http://127.0.0.1:{fake_port}");
        Arc::new(App { client: Client::new(osnt_common::http_agent("test"), &base, &base, Duration::from_millis(30)), store: Store::open(db.to_str().unwrap()).unwrap() })
    }

    #[test]
    fn articles_endpoint_validates_caches_and_maps_errors() {
        let hits = Arc::new(AtomicUsize::new(0));
        let fp = fake(hits.clone());
        let port = serve(app_for(fp, "art"));
        let (st, v) = call(port, "GET", "/api/articles?q=flood&timespan=24h", false, None);
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["count"], 1);
        assert_eq!(v["cached"], false);
        assert_eq!(v["articles"][0]["title"], "Flood in <b>town</b>"); // raw text; the page escapes it
        let (_, v2) = call(port, "GET", "/api/articles?q=flood&timespan=24h", false, None);
        assert_eq!(v2["cached"], true);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        // validation happens before any upstream call
        for bad in ["/api/articles?q=ab", "/api/articles?q=flood&timespan=5min", "/api/articles?q=flood&lang=x%20y", "/api/articles?q=flood&sort=zzz", "/api/timeline?q=flood&mode=weird"] {
            assert_eq!(call(port, "GET", bad, false, None).0, 400, "{bad}");
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        // GDELT's plain-text complaint becomes a 400, a persistent 429 stays a 429, a 500 is a bad gateway
        assert_eq!(call(port, "GET", "/api/articles?q=short%20phrase", false, None).0, 400);
        assert_eq!(call(port, "GET", "/api/articles?q=limitme", false, None).0, 429);
        assert_eq!(call(port, "GET", "/api/timeline?q=flood&mode=tone", false, None).0, 502);
    }

    #[test]
    fn timeline_and_latest() {
        let fp = fake(Arc::new(AtomicUsize::new(0)));
        let port = serve(app_for(fp, "tl"));
        let (st, v) = call(port, "GET", "/api/timeline?q=flood&mode=vol", false, None);
        assert_eq!(st, 200);
        assert_eq!(v["points"].as_array().unwrap().len(), 40);
        assert_eq!(v["mode"], "vol");
        let (st, v) = call(port, "GET", "/api/latest", false, None);
        assert_eq!(st, 200);
        assert_eq!(v["files"][0]["kind"], "events");
    }

    #[test]
    fn stories_need_gateway_signature_and_detect_spikes() {
        init_env();
        let fp = fake(Arc::new(AtomicUsize::new(0)));
        let port = serve(app_for(fp, "st"));
        assert_eq!(call(port, "GET", "/api/stories", false, None).0, 401);
        assert_eq!(call(port, "POST", "/api/stories", false, Some(json!({ "q": "flood" }))).0, 401);
        assert_eq!(call(port, "DELETE", "/api/stories/1", false, None).0, 401);
        assert_eq!(call(port, "POST", "/api/stories/1/check", false, None).0, 401);
        // a signature for a different path is refused
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
        let r = agent.get(&format!("http://127.0.0.1:{port}/api/stories")).header("X-OSNT-Gateway", sign("GET", "/api/other")).call().unwrap();
        assert_eq!(r.status().as_u16(), 401);
        // invalid input
        assert_eq!(call(port, "POST", "/api/stories", true, Some(json!({ "q": "x" }))).0, 400);
        assert_eq!(call(port, "POST", "/api/stories", true, Some(json!({ "q": "flood", "name": "n".repeat(61) }))).0, 400);
        let (st, v) = call(port, "POST", "/api/stories", true, Some(json!({ "q": "flood", "name": "Floods" })));
        assert_eq!(st, 200, "{v}");
        let id = v["id"].as_u64().unwrap();
        let (st, v) = call(port, "POST", &format!("/api/stories/{id}/check"), true, None);
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["spike"]["spike"], true);
        assert!(v["checked"].as_u64().unwrap() > 0);
        let (_, list) = call(port, "GET", "/api/stories", true, None);
        assert_eq!(list["stories"].as_array().unwrap().len(), 1);
        assert_eq!(call(port, "POST", "/api/stories/99/check", true, None).0, 404);
        assert_eq!(call(port, "DELETE", &format!("/api/stories/{id}"), true, None).0, 200);
        assert_eq!(call(port, "DELETE", &format!("/api/stories/{id}"), true, None).0, 404);
    }

    #[test]
    fn tools_shape() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let Json(v) = rt.block_on(tools());
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        for t in arr {
            assert!(t["name"].is_string() && t["description"].is_string() && t["path"].as_str().unwrap().starts_with("api/"));
            assert_eq!(t["method"], "GET");
        }
    }
}

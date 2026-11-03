//! Wikipedia and Wikidata event watch: On this day, current events, page-view spike detection and change notices
//! for a watchlist of topics, and Wikidata facts for organisations, places, events, vessels and aircraft types.
//! Pages and entities about people are refused; change notices carry no editor, IP address or edit comment.

mod wiki;
#[cfg(test)]
mod testutil;

use std::{collections::HashSet, env, net::SocketAddr, sync::Arc, sync::atomic::Ordering, time::Duration};

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    routing::{delete, get},
};
use serde::Deserialize;
use serde_json::{Value, json};
use wiki::{Client, Store, Stream, WikiError};

const PAGE: &str = include_str!("../assets/index.html");
const UA: &str = "osnt-wiki-intel/0.1 (+https://github.com/ogden-marrow/osnt-hub)";
const STREAM_URL: &str = "https://stream.wikimedia.org/v2/stream/recentchange";
const STREAM_IDLE_SECS: i64 = 600;

struct App {
    client: Client,
    store: Store,
    stream: Arc<Stream>,
    stream_url: String,
}
type Shared = Arc<App>;

struct ApiError(StatusCode, String, bool);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1, "person": self.2 }))).into_response()
    }
}
impl From<WikiError> for ApiError {
    fn from(e: WikiError) -> Self {
        let code = match &e {
            WikiError::BadInput(_) => StatusCode::BAD_REQUEST,
            WikiError::NotFound(_) => StatusCode::NOT_FOUND,
            WikiError::Person => StatusCode::UNPROCESSABLE_ENTITY,
            WikiError::Upstream(_) => StatusCode::BAD_GATEWAY,
        };
        ApiError(code, e.to_string(), matches!(e, WikiError::Person))
    }
}
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"), false)
    }
}
fn bad(m: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, m.into(), false)
}

fn require_signed(method: &Method, uri: &Uri, headers: &HeaderMap) -> Result<(), ApiError> {
    let ok = osnt_common::gateway_authorized(method.as_str(), uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"), headers.get("x-osnt-gateway").and_then(|v| v.to_str().ok()));
    if ok { Ok(()) } else { Err(ApiError(StatusCode::UNAUTHORIZED, "sign in through the hub to use the watchlist".into(), false)) }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, ApiError> + Send + 'static) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f).await.map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string(), false))?
}

#[derive(Deserialize)]
struct DayQ {
    month: Option<u32>,
    day: Option<u32>,
    #[serde(default)]
    lang: String,
}
async fn onthisday(State(s): State<Shared>, Query(q): Query<DayQ>) -> Result<Json<Value>, ApiError> {
    use chrono::Datelike;
    let today = chrono::Utc::now().date_naive();
    let (m, d) = (q.month.unwrap_or(today.month()), q.day.unwrap_or(today.day()));
    Ok(Json(blocking(move || Ok(s.client.onthisday(&q.lang, m, d)?)).await?))
}

#[derive(Deserialize)]
struct DateQ {
    date: Option<String>,
}
async fn current(State(s): State<Shared>, Query(q): Query<DateQ>) -> Result<Json<Value>, ApiError> {
    let date = match q.date.as_deref().filter(|d| !d.is_empty()) {
        Some(d) => chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").map_err(|_| bad("date must look like 2026-11-02"))?,
        None => chrono::Utc::now().date_naive(),
    };
    let today = chrono::Utc::now().date_naive();
    if date > today || date < today - chrono::Duration::days(365) {
        return Err(bad("date must be within the last year"));
    }
    Ok(Json(blocking(move || {
        let mut v = s.client.current_events(date)?;
        // Today's page is often still empty early in the UTC day: fall back to the previous days (up to 3).
        let mut back = 1;
        while q.date.is_none() && v["items"].as_array().is_none_or(Vec::is_empty) && back <= 3 {
            v = s.client.current_events(date - chrono::Duration::days(back))?;
            back += 1;
        }
        Ok(v)
    }).await?))
}

#[derive(Deserialize)]
struct ViewsQ {
    title: String,
    #[serde(default)]
    lang: String,
    days: Option<u32>,
}
async fn pageviews(State(s): State<Shared>, Query(q): Query<ViewsQ>) -> Result<Json<Value>, ApiError> {
    Ok(Json(blocking(move || Ok(s.client.pageviews(&q.lang, &q.title, q.days.unwrap_or(45))?)).await?))
}

#[derive(Deserialize)]
struct SearchQ {
    q: String,
}
async fn entity_search(State(s): State<Shared>, Query(q): Query<SearchQ>) -> Result<Json<Value>, ApiError> {
    Ok(Json(blocking(move || Ok(s.client.entity_search(&q.q)?)).await?))
}
async fn entity(State(s): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    Ok(Json(blocking(move || Ok(s.client.entity(&id)?)).await?))
}

async fn topics(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    require_signed(&method, &uri, &headers)?;
    Ok(Json(json!({ "topics": s.store.list()?, "max": wiki::MAX_TOPICS })))
}

#[derive(Deserialize)]
struct NewTopic {
    title: String,
    #[serde(default)]
    lang: String,
}
async fn add_topic(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, body: String) -> Result<Json<Value>, ApiError> {
    require_signed(&method, &uri, &headers)?;
    let b: NewTopic = serde_json::from_str(&body).map_err(|e| bad(format!("invalid request: {e}")))?;
    blocking(move || {
        let r = s.client.resolve(&b.lang, &b.title)?;
        let t = s.store.add(r["lang"].as_str().unwrap_or("en"), r["title"].as_str().unwrap_or(""), r["display"].as_str().unwrap_or(r["title"].as_str().unwrap_or("")), r["qid"].as_str(), r["description"].as_str()).map_err(|e| bad(e.to_string()))?;
        Ok(Json(json!(t)))
    })
    .await
}

async fn delete_topic(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Path(id): Path<u64>) -> Result<Json<Value>, ApiError> {
    require_signed(&method, &uri, &headers)?;
    if !s.store.delete(id)? {
        return Err(ApiError(StatusCode::NOT_FOUND, "no such topic".into(), false));
    }
    Ok(Json(json!({ "ok": true })))
}

/// Every watched topic with 45 days of views and spike analysis.
async fn watch(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    require_signed(&method, &uri, &headers)?;
    blocking(move || {
        let mut out = Vec::new();
        for t in s.store.list()? {
            let v = s.client.pageviews(&t.lang, &t.title, 45);
            out.push(match v {
                Ok(v) => json!({ "topic": t, "series": v["series"], "spike": v["spike"], "cached": v["cached"] }),
                Err(e) => json!({ "topic": t, "error": e.to_string() }),
            });
            if s.client.base.is_none() {
                std::thread::sleep(Duration::from_millis(150));
            }
        }
        Ok(Json(json!({ "topics": out })))
    })
    .await
}

fn start_stream(s: &Shared) {
    let a = s.clone();
    s.stream.last_touch.store(wiki::now_secs(), Ordering::SeqCst);
    let watch: Arc<dyn Fn() -> HashSet<(String, String)> + Send + Sync> = Arc::new(move || a.store.list().unwrap_or_default().into_iter().map(|t| (t.lang, t.title)).collect());
    if !watch().is_empty() {
        wiki::spawn_stream(s.client.agent.clone(), s.stream_url.clone(), s.stream.clone(), watch, STREAM_IDLE_SECS);
    }
}

/// Recent change notices for watched topics. Calling this keeps the EventStreams connection open for 10 minutes.
async fn changes(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    require_signed(&method, &uri, &headers)?;
    start_stream(&s);
    let events: Vec<_> = s.stream.events.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect();
    let note = s.stream.note.lock().unwrap_or_else(|e| e.into_inner()).clone();
    Ok(Json(json!({ "events": events, "connected": s.stream.connected.load(Ordering::SeqCst), "running": s.stream.running.load(Ordering::SeqCst), "note": note, "watching": s.store.list()?.len() })))
}

async fn tools() -> Json<Value> {
    let s = |d: &str| json!({ "type": "string", "description": d });
    Json(json!([
        { "name": "wiki_onthisday", "description": "Wikipedia 'On this day' historical events for a date (defaults to today), with links to the articles.",
          "method": "GET", "path": "api/onthisday", "parameters": { "type": "object", "properties": { "month": { "type": "integer" }, "day": { "type": "integer" }, "lang": s("en (default), de, fr, es, ru, uk, ar, it, pt, zh, ja, he or tr") } } },
        { "name": "wiki_current_events", "description": "Wikipedia's Portal:Current events bullet points for a date (defaults to today), grouped by category with source links.",
          "method": "GET", "path": "api/current", "parameters": { "type": "object", "properties": { "date": s("YYYY-MM-DD, within the last year") } } },
        { "name": "wiki_pageviews", "description": "Daily page views for a Wikipedia article about an event, place or organisation, with a spike check against the previous 28 days. Articles about people are refused.",
          "method": "GET", "path": "api/pageviews", "parameters": { "type": "object", "properties": { "title": s("article title"), "lang": s("wiki language, default en"), "days": { "type": "integer", "description": "15 to 90, default 45" } }, "required": ["title"] } },
        { "name": "wikidata_entity", "description": "Wikidata facts (type, country, location, coordinates, dates, operator, identifiers) for an organisation, place, event, vessel or aircraft type by Q-id. Entities that are people are refused.",
          "method": "GET", "path": "api/entity/{id}", "parameters": { "type": "object", "properties": { "id": s("Wikidata id such as Q899") }, "required": ["id"] } },
        { "name": "wikidata_search", "description": "Search Wikidata entities by name; returns ids, labels and descriptions.",
          "method": "GET", "path": "api/entity/search", "parameters": { "type": "object", "properties": { "q": s("name to search") }, "required": ["q"] } }
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

fn router(app: Shared) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/onthisday", get(onthisday))
        .route("/api/current", get(current))
        .route("/api/pageviews", get(pageviews))
        .route("/api/entity/search", get(entity_search))
        .route("/api/entity/{id}", get(entity))
        .route("/api/topics", get(topics).post(add_topic))
        .route("/api/topics/{id}", delete(delete_topic))
        .route("/api/watch", get(watch))
        .route("/api/changes", get(changes))
        .with_state(app)
}

fn make_app(db: &str, base: Option<String>, stream_url: &str) -> Result<Shared> {
    Ok(Arc::new(App { client: Client::new(osnt_common::http_agent(UA), base), store: Store::open(db)?, stream: Arc::new(Stream::new()), stream_url: stream_url.into() }))
}

#[tokio::main]
async fn main() -> Result<()> {
    let db = env::var("OSNT_WIKI_DB").unwrap_or_else(|_| "wiki.redb".into());
    let app = make_app(&db, env::var("OSNT_WIKI_BASE").ok(), &env::var("OSNT_WIKI_STREAM").unwrap_or_else(|_| STREAM_URL.into()))?;
    let addr: SocketAddr = env::var("OSNT_WIKI_BIND").unwrap_or_else(|_| "127.0.0.1:8151".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("wiki-intel plugin on http://{addr}");
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
        let mut r = agent.run(b.body(body.unwrap_or("").to_string()).unwrap()).unwrap();
        let st = r.status().as_u16();
        (st, r.body_mut().read_json().unwrap_or(Value::Null))
    }

    fn views_json() -> Value {
        let today = chrono::Utc::now().date_naive();
        let items: Vec<Value> = (1..=40).rev().map(|d| {
            let day = today - chrono::Duration::days(d);
            json!({ "timestamp": format!("{}00", day.format("%Y%m%d")), "views": if d == 1 { 1500 } else { 100 + (d % 5) * 4 } })
        }).collect();
        json!({ "items": items })
    }

    fn setup(tag: &str) -> (u16, u16, Shared) {
        init_env();
        let fake = spawn(Arc::new(|r| {
            let p = r.path.as_str();
            if p.contains("/page/summary/Suez_Canal") {
                return Resp::json(json!({ "type": "standard", "titles": { "canonical": "Suez_Canal", "normalized": "Suez Canal" }, "wikibase_item": "Q899", "description": "canal in Egypt" }));
            }
            if p.contains("/page/summary/Some_Person") {
                return Resp::json(json!({ "type": "standard", "titles": { "canonical": "Some_Person", "normalized": "Some Person" }, "wikibase_item": "Q100" }));
            }
            if p.contains("/page/summary/Mercury") {
                return Resp::json(json!({ "type": "disambiguation", "titles": { "canonical": "Mercury" } }));
            }
            if p.contains("action=wbgetclaims") {
                let human = p.contains("entity=Q100");
                return Resp::json(json!({ "claims": { "P31": [{ "mainsnak": { "datavalue": { "value": { "id": if human { "Q5" } else { "Q12280" } } } } }] } }));
            }
            if p.contains("/metrics/pageviews/per-article/en.wikipedia/all-access/user/Suez_Canal/daily/") {
                return Resp::json(views_json());
            }
            if p.contains("action=wbgetentities") {
                if p.contains("props=labels&") {
                    return Resp::json(json!({ "entities": { "Q12280": { "labels": { "en": { "value": "canal" } } } } }));
                }
                if p.contains("ids=Q100") {
                    return Resp::json(json!({ "entities": { "Q100": { "claims": { "P31": [{ "mainsnak": { "datavalue": { "value": { "id": "Q5" } } } }] } } } }));
                }
                return Resp::json(json!({ "entities": { "Q899": { "labels": { "en": { "value": "Suez Canal" } }, "claims": { "P31": [{ "mainsnak": { "datavalue": { "type": "wikibase-entityid", "value": { "id": "Q12280" } } } }] } } } }));
            }
            if p.contains("action=wbsearchentities") {
                return Resp::json(json!({ "search": [{ "id": "Q899", "label": "Suez Canal", "description": "canal in Egypt" }] }));
            }
            if p.contains("/feed/onthisday/events/11/02") {
                return Resp::json(json!({ "events": [{ "text": "Something happened.", "year": 1999, "pages": [{ "titles": { "canonical": "Thing", "normalized": "Thing" } }] }] }));
            }
            if p.contains("action=parse") {
                if p.contains("2026_November_2") || p.contains("2026_November_1") {
                    return Resp::json(json!({ "parse": { "text": "<style>.current-events-content{x:y}</style><div class=\"current-events-content\"><p><b>Disasters</b></p><ul><li>A flood. <a class=\"external text\" href=\"https://f.example/x\">(F)</a></li></ul></div>" } }));
                }
                return Resp::json(json!({ "error": { "code": "missingtitle" } }));
            }
            if p.starts_with("/stream") {
                let line = r#"data: {"wiki":"enwiki","namespace":0,"title":"Suez Canal","type":"edit","user":"X","length":{"old":1,"new":9},"timestamp":5}"#;
                return Resp::text(&format!(": hi\n\n{line}\n\n"));
            }
            Resp::status(404, "nf")
        }));
        let db = std::env::temp_dir().join(format!("wiki-main-{tag}-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&db);
        let app = make_app(db.to_str().unwrap(), Some(format!("http://127.0.0.1:{fake}")), &format!("http://127.0.0.1:{fake}/stream")).unwrap();
        (serve(app.clone()), fake, app)
    }

    #[test]
    fn watchlist_routes_need_signature() {
        let (port, _, _) = setup("auth");
        for (m, p) in [("GET", "/api/topics"), ("POST", "/api/topics"), ("DELETE", "/api/topics/1"), ("GET", "/api/watch"), ("GET", "/api/changes")] {
            assert_eq!(call(port, m, p, false, Some("{}")).0, 401, "{m} {p}");
        }
    }

    #[test]
    fn people_and_bad_titles_are_refused() {
        let (port, _, _) = setup("people");
        let (st, v) = call(port, "POST", "/api/topics", true, Some(r#"{"title":"Some Person"}"#));
        assert_eq!((st, v["person"].clone()), (422, json!(true)));
        let (st, v) = call(port, "GET", "/api/pageviews?title=Some_Person", false, None);
        assert_eq!((st, v["person"].clone()), (422, json!(true)));
        assert_eq!(call(port, "GET", "/api/entity/Q100", false, None).0, 422);
        assert_eq!(call(port, "POST", "/api/topics", true, Some(r#"{"title":"a|b"}"#)).0, 400);
        assert_eq!(call(port, "POST", "/api/topics", true, Some(r#"{"title":"Mercury"}"#)).0, 400);
        assert_eq!(call(port, "POST", "/api/topics", true, Some(r#"{"title":"Nope Nothing"}"#)).0, 404);
        assert_eq!(call(port, "POST", "/api/topics", true, Some(r#"{"title":"Suez Canal","lang":"evil.example"}"#)).0, 400);
        assert_eq!(call(port, "POST", "/api/topics", true, Some("not json")).0, 400);
        assert_eq!(call(port, "GET", "/api/entity/Q1;x", false, None).0, 400);
    }

    #[test]
    fn topics_watch_and_spike() {
        let (port, _, _) = setup("watch");
        let (st, t) = call(port, "POST", "/api/topics", true, Some(r#"{"title":"suez Canal"}"#));
        assert_eq!(st, 200, "{t}");
        assert_eq!(t["title"], "Suez_Canal");
        assert_eq!(t["qid"], "Q899");
        assert_eq!(call(port, "POST", "/api/topics", true, Some(r#"{"title":"Suez Canal"}"#)).0, 400, "duplicate");
        let (st, w) = call(port, "GET", "/api/watch", true, None);
        assert_eq!(st, 200);
        assert_eq!(w["topics"][0]["spike"]["spike"], true, "{w}");
        assert!(w["topics"][0]["series"].as_array().unwrap().len() >= 30);
        let (_, pv) = call(port, "GET", "/api/pageviews?title=Suez_Canal&days=30", false, None);
        assert_eq!(pv["title"], "Suez_Canal");
        assert_eq!(call(port, "DELETE", "/api/topics/1", true, None).0, 200);
        assert_eq!(call(port, "DELETE", "/api/topics/1", true, None).0, 404);
    }

    #[test]
    fn day_current_and_entity() {
        let (port, _, _) = setup("misc");
        let (st, v) = call(port, "GET", "/api/onthisday?month=11&day=2", false, None);
        assert_eq!((st, v["events"][0]["pages"][0]["url"].clone()), (200, json!("https://en.wikipedia.org/wiki/Thing")));
        assert_eq!(call(port, "GET", "/api/onthisday?month=2&day=30", false, None).0, 400);
        assert_eq!(call(port, "GET", "/api/onthisday?month=11&day=2&lang=xx", false, None).0, 400);
        let (st, v) = call(port, "GET", "/api/current?date=2026-11-02", false, None);
        assert_eq!(st, 200);
        assert_eq!(v["items"][0]["source"], "F");
        assert_eq!(call(port, "GET", "/api/current?date=garbage", false, None).0, 400);
        assert_eq!(call(port, "GET", "/api/current?date=1999-01-01", false, None).0, 400);
        let (st, v) = call(port, "GET", "/api/entity/Q899", false, None);
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["facts"][0]["values"][0]["label"], "canal");
        let (_, s) = call(port, "GET", "/api/entity/search?q=suez", false, None);
        assert_eq!(s["results"][0]["id"], "Q899");
        assert_eq!(call(port, "GET", "/api/entity/search?q=a", false, None).0, 400);
    }

    #[test]
    fn change_stream_end_to_end() {
        let (port, _, app) = setup("stream");
        call(port, "POST", "/api/topics", true, Some(r#"{"title":"Suez Canal"}"#));
        let (st, v) = call(port, "GET", "/api/changes", true, None);
        assert_eq!(st, 200);
        assert_eq!(v["watching"], 1);
        let mut got = Value::Null;
        for _ in 0..40 {
            std::thread::sleep(Duration::from_millis(100));
            let (_, v) = call(port, "GET", "/api/changes", true, None);
            if v["events"].as_array().is_some_and(|e| !e.is_empty()) {
                got = v;
                break;
            }
        }
        assert_eq!(got["events"][0]["title"], "Suez_Canal", "{got}");
        assert_eq!(got["events"][0]["delta"], 8);
        let text = got.to_string();
        assert!(!text.contains("\"user\"") && !text.contains("\"X\""));
        app.stream.last_touch.store(0, Ordering::SeqCst); // let the background thread end
    }

    #[test]
    fn tools_shape() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let Json(v) = rt.block_on(tools());
        for t in v.as_array().unwrap() {
            assert!(t["name"].is_string() && t["path"].as_str().unwrap().starts_with("api/") && t["method"] == "GET");
        }
    }
}

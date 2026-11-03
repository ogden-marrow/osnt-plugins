//! Disaster imagery: Maxar Open Data (CC BY-NC 4.0), the free very-high-resolution (30-50 cm) imagery that Maxar
//! releases for major disasters and crises, published as a static STAC catalog on AWS. This service reads that catalog
//! (events, then acquisitions, then tile footprints), caches the small JSON files briefly, and hands the browser tile
//! templates for a public titiler to draw the COGs. No imagery is downloaded or stored here.
//! Listens on loopback only; the hub reverse-proxies it at /p/opendata/.

mod cache;

use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::{Value, json};

const PAGE: &str = include_str!("../assets/index.html");
const UA: &str = "osnt-opendata/0.1 (+https://github.com/ogden-marrow/osnt-plugins; self-hosted OSINT hub)";
const CATALOG_TTL: Duration = Duration::from_secs(12 * 3600);
const WORKERS: usize = 8;
const MAX_ACQUISITIONS: usize = 400;
const MAX_ITEMS: usize = 60;

#[derive(Clone)]
pub struct Config {
    /// Root of the events catalog, ending with `/`.
    pub root: String,
    pub titiler: String,
}

impl Config {
    fn from_env() -> Self {
        let get = |k: &str, d: &str| env::var(k).unwrap_or_else(|_| d.to_string());
        Config {
            root: get("OSNT_OPENDATA_ROOT", "https://maxar-opendata.s3.amazonaws.com/events/"),
            titiler: get("OSNT_OPENDATA_TITILER", "https://titiler.xyz"),
        }
    }
}

pub struct App {
    agent: ureq::Agent,
    cfg: Config,
    cache: cache::DiskCache,
    /// Serialises the slow "build the whole event list" step so concurrent page loads share one crawl.
    crawl: Mutex<()>,
}
type Shared = Arc<App>;

struct ApiError(StatusCode, String);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}
fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}
fn upstream(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_GATEWAY, msg.into())
}
fn internal(e: impl ToString) -> ApiError {
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn get_json(agent: &ureq::Agent, url: &str) -> Result<Value, String> {
    let mut res = agent.get(url).call().map_err(|e| match e {
        ureq::Error::StatusCode(c) => format!("the Maxar catalog answered HTTP {c}"),
        _ => "the Maxar catalog could not be reached".to_string(),
    })?;
    res.body_mut().read_json::<Value>().map_err(|_| "the Maxar catalog sent an unreadable document".to_string())
}

/// Cached JSON fetch (blocking).
fn cached_json(app: &App, url: &str) -> Result<Value, String> {
    let key = format!("doc|{url}");
    if let Some(b) = app.cache.get(&key, CATALOG_TTL) {
        if let Ok(v) = serde_json::from_slice(&b) {
            return Ok(v);
        }
    }
    let v = get_json(&app.agent, url)?;
    app.cache.put(&key, v.to_string().as_bytes());
    Ok(v)
}

/// Resolve a STAC relative link (`./x`, `../y/z.json`) against the URL of the document that contained it.
fn resolve(base: &str, rel: &str) -> String {
    if rel.starts_with("http://") || rel.starts_with("https://") {
        return rel.to_string();
    }
    let (origin_len, path) = match base.find("://").and_then(|i| base[i + 3..].find('/').map(|j| i + 3 + j)) {
        Some(i) => (i, &base[i..]),
        None => return rel.to_string(),
    };
    let mut segs: Vec<&str> = path.split('/').collect();
    segs.pop(); // drop the file name
    for part in rel.split('/') {
        match part {
            "." | "" => {}
            ".." => {
                if segs.len() > 1 {
                    segs.pop();
                }
            }
            p => segs.push(p),
        }
    }
    format!("{}{}", &base[..origin_len], segs.join("/"))
}

fn safe_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 120 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) && !s.contains("..")
}

fn enc(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

fn date_of(s: &str) -> Option<String> {
    s.get(..10).filter(|d| d.as_bytes().iter().enumerate().all(|(i, c)| if i == 4 || i == 7 { *c == b'-' } else { c.is_ascii_digit() })).map(str::to_string)
}

fn bbox_of(v: &Value) -> Option<Vec<f64>> {
    let a = v.as_array()?;
    let b: Vec<f64> = a.iter().filter_map(Value::as_f64).collect();
    (b.len() == 4).then_some(b)
}

fn run_parallel<T: Send, F: Fn(String) -> Option<T> + Sync>(inputs: Vec<String>, f: F) -> Vec<T> {
    let queue = Mutex::new(inputs.into_iter());
    let out = Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for _ in 0..WORKERS {
            s.spawn(|| {
                loop {
                    let Some(u) = queue.lock().unwrap().next() else { break };
                    if let Some(r) = f(u) {
                        out.lock().unwrap().push(r);
                    }
                }
            });
        }
    });
    out.into_inner().unwrap()
}

/// All events: one catalog document plus one collection per event. Blocking; the result is cached as a unit.
fn build_events(app: &App) -> Result<Value, String> {
    let key = format!("events|{}", app.cfg.root);
    if let Some(v) = app.cache.get(&key, CATALOG_TTL).and_then(|b| serde_json::from_slice::<Value>(&b).ok()) {
        return Ok(v);
    }
    let _g = app.crawl.lock().unwrap();
    if let Some(v) = app.cache.get(&key, CATALOG_TTL).and_then(|b| serde_json::from_slice::<Value>(&b).ok()) {
        return Ok(v);
    }
    let root_url = format!("{}catalog.json", app.cfg.root);
    let root = cached_json(app, &root_url)?;
    let hrefs: Vec<String> = root["links"].as_array().into_iter().flatten().filter(|l| l["rel"] == "child").filter_map(|l| l["href"].as_str()).map(|h| resolve(&root_url, h)).collect();
    if hrefs.is_empty() {
        return Err("the Maxar catalog listed no events".into());
    }
    let mut events: Vec<Value> = run_parallel(hrefs, |url| {
        let c = cached_json(app, &url).ok()?;
        let id = c.get("id")?.as_str()?.to_string();
        if !safe_id(&id) {
            return None;
        }
        let acq = c["links"].as_array().into_iter().flatten().filter(|l| l["href"].as_str().is_some_and(|h| h.contains("acquisition_collections/"))).count();
        Some(json!({
            "id": id,
            "title": c.get("title").and_then(Value::as_str).unwrap_or(&id),
            "description": c.get("description").and_then(Value::as_str).unwrap_or(""),
            "bbox": c.pointer("/extent/spatial/bbox/0").and_then(bbox_of),
            "start": c.pointer("/extent/temporal/interval/0/0").and_then(Value::as_str).and_then(date_of),
            "end": c.pointer("/extent/temporal/interval/0/1").and_then(Value::as_str).and_then(date_of),
            "acquisitions": acq,
            "license": c.get("license").and_then(Value::as_str).unwrap_or("CC-BY-NC-4.0"),
        }))
    });
    if events.is_empty() {
        return Err("could not read any event from the Maxar catalog".into());
    }
    events.sort_by(|a, b| b["end"].as_str().cmp(&a["end"].as_str()).then(a["id"].as_str().cmp(&b["id"].as_str())));
    let v = json!({ "events": events });
    app.cache.put(&key, v.to_string().as_bytes());
    Ok(v)
}

async fn events(State(app): State<Shared>) -> Result<Json<Value>, ApiError> {
    let a = app.clone();
    let v = tokio::task::spawn_blocking(move || build_events(&a)).await.map_err(internal)?.map_err(upstream)?;
    let list = v["events"].as_array().cloned().unwrap_or_default();
    Ok(Json(json!({
        "count": list.len(), "events": list,
        "licence": "CC BY-NC 4.0: non-commercial use with attribution to Maxar (Vantor). Imagery released for disaster response.",
        "catalog": format!("{}catalog.json", app.cfg.root),
    })))
}

fn event_known(app: &App, id: &str) -> Result<Value, ApiError> {
    if !safe_id(id) {
        return Err(bad("event must be an id from /api/events"));
    }
    let v = build_events(app).map_err(upstream)?;
    v["events"].as_array().into_iter().flatten().find(|e| e["id"] == id).cloned().ok_or_else(|| bad("unknown event; use an id from /api/events"))
}

async fn acquisitions(State(app): State<Shared>, Query(q): Query<HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let ev = q.get("event").cloned().unwrap_or_default();
    let a = app.clone();
    let out = tokio::task::spawn_blocking(move || -> Result<Value, ApiError> {
        let event = event_known(&a, &ev)?;
        let coll_url = format!("{}{ev}/collection.json", a.cfg.root);
        let coll = cached_json(&a, &coll_url).map_err(upstream)?;
        let mut hrefs: Vec<String> = coll["links"].as_array().into_iter().flatten().filter_map(|l| l["href"].as_str()).filter(|h| h.contains("acquisition_collections/")).map(|h| resolve(&coll_url, h)).collect();
        let total = hrefs.len();
        hrefs.truncate(MAX_ACQUISITIONS);
        let mut acq: Vec<Value> = run_parallel(hrefs, |url| {
            let c = cached_json(&a, &url).ok()?;
            let items = c["links"].as_array().into_iter().flatten().filter(|l| l["rel"] == "item").count();
            let start = c.pointer("/extent/temporal/interval/0/0").and_then(Value::as_str)?;
            Some(json!({
                "id": c.get("id").and_then(Value::as_str).filter(|i| safe_id(i)).map(str::to_string).or_else(|| url.rsplit('/').next().and_then(|f| f.strip_suffix("_collection.json")).map(str::to_string))?,
                "date": date_of(start), "datetime": start,
                "bbox": c.pointer("/extent/spatial/bbox/0").and_then(bbox_of),
                "items": items,
            }))
        });
        acq.sort_by(|x, y| x["datetime"].as_str().cmp(&y["datetime"].as_str()).then(x["id"].as_str().cmp(&y["id"].as_str())));
        Ok(json!({ "event": event, "total": total, "count": acq.len(), "acquisitions": acq,
                   "licence": "CC BY-NC 4.0, Maxar Open Data Program" }))
    })
    .await
    .map_err(internal)??;
    Ok(Json(out))
}

/// Tiles of one acquisition: every item's visual COG with its own footprint and a titiler tile template.
async fn acquisition(State(app): State<Shared>, Query(q): Query<HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let ev = q.get("event").cloned().unwrap_or_default();
    let id = q.get("id").cloned().unwrap_or_default();
    if !safe_id(&id) {
        return Err(bad("id must be an acquisition id from /api/acquisitions"));
    }
    let a = app.clone();
    let out = tokio::task::spawn_blocking(move || -> Result<Value, ApiError> {
        event_known(&a, &ev)?;
        let url = format!("{}{ev}/ard/acquisition_collections/{id}_collection.json", a.cfg.root);
        let c = cached_json(&a, &url).map_err(|_| bad("unknown acquisition for this event"))?;
        let mut item_urls: Vec<String> = c["links"].as_array().into_iter().flatten().filter(|l| l["rel"] == "item").filter_map(|l| l["href"].as_str()).map(|h| resolve(&url, h)).collect();
        let total = item_urls.len();
        item_urls.truncate(MAX_ITEMS);
        let root = a.cfg.root.clone();
        let mut items: Vec<Value> = run_parallel(item_urls, |iu| {
            if !iu.starts_with(&root) {
                return None; // never follow a link out of the catalog
            }
            let it = cached_json(&a, &iu).ok()?;
            let bbox = it.get("bbox").and_then(bbox_of)?;
            let cog = resolve(&iu, it.pointer("/assets/visual/href").and_then(Value::as_str)?);
            if !cog.starts_with(&root) {
                return None;
            }
            Some(json!({
                "bbox": bbox, "cog": cog,
                "tiles": format!("{}/cog/tiles/WebMercatorQuad/{{z}}/{{x}}/{{y}}?url={}&tilesize=256", a.cfg.titiler, enc(&cog)),
                "platform": it.pointer("/properties/platform"), "gsd": it.pointer("/properties/gsd"),
                "off_nadir": it.pointer("/properties/view:off_nadir"), "datetime": it.pointer("/properties/datetime"),
            }))
        });
        items.sort_by(|x, y| x["cog"].as_str().cmp(&y["cog"].as_str()));
        let first = items.first().cloned().unwrap_or(Value::Null);
        Ok(json!({
            "event": ev, "id": id, "date": c.pointer("/extent/temporal/interval/0/0").and_then(Value::as_str).and_then(date_of),
            "platform": first["platform"], "gsd": first["gsd"], "off_nadir": first["off_nadir"],
            "bbox": c.pointer("/extent/spatial/bbox/0").and_then(bbox_of),
            "total_items": total, "count": items.len(), "items": items,
            "min_zoom": 12,
        }))
    })
    .await
    .map_err(internal)??;
    Ok(Json(out))
}

async fn tools() -> Json<Value> {
    Json(json!([
        { "name": "opendata_events",
          "description": "List the disaster and crisis events for which Maxar publishes free open imagery (CC BY-NC 4.0): id, title, description, bounding box, date range and number of acquisitions. Metadata only.",
          "method": "GET", "path": "api/events", "parameters": { "type": "object", "properties": {} } },
        { "name": "opendata_acquisitions",
          "description": "List the satellite acquisitions (pass dates, footprints, tile counts) available for one event, oldest first, so before and after images can be picked. Use an event id from opendata_events.",
          "method": "GET", "path": "api/acquisitions",
          "parameters": { "type": "object", "properties": { "event": { "type": "string", "description": "event id such as Cyclone-Chido-Dec15" } }, "required": ["event"] } }
    ]))
}

async fn page() -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], PAGE).into_response()
}

pub fn app(cfg: Config, state_dir: PathBuf) -> Router {
    let st = Arc::new(App { agent: osnt_common::http_agent(UA), cfg, cache: cache::DiskCache::new(state_dir.join("cache"), 12 * 1024 * 1024), crawl: Mutex::new(()) });
    Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/events", get(events))
        .route("/api/acquisitions", get(acquisitions))
        .route("/api/acquisition", get(acquisition))
        .with_state(st)
}

#[tokio::main]
async fn main() {
    let addr: SocketAddr = env::var("OSNT_OPENDATA_BIND").unwrap_or_else(|_| "127.0.0.1:8125".into()).parse().expect("bind addr");
    let state = PathBuf::from(env::var("OSNT_OPENDATA_STATE").unwrap_or_else(|_| env::temp_dir().join("osnt-opendata").to_string_lossy().into()));
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("opendata plugin on http://{addr}");
    axum::serve(listener, app(Config::from_env(), state)).await.expect("serve");
}

#[cfg(test)]
mod tests;

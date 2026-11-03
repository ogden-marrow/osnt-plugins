//! Multi-hazard event aggregator. On demand it reads GDACS, NASA EONET, NWS alerts, the Smithsonian/USGS weekly
//! volcano report, USGS HANS elevated volcanoes, NHC active storms and (with an approved app name) ReliefWeb, and
//! normalises them into one event model for a single map. Nothing is mirrored: responses are cached briefly under
//! the state dir. Listens on loopback only; the hub reverse-proxies it at /p/hazard-events/.

mod cache;
mod sources;
mod util;

use std::{collections::HashMap, env, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{Query, State},
    http::header,
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::{Value, json};

use util::{ApiError, Upstream, bad, enc, upstream_err};

const PAGE: &str = include_str!("../assets/index.html");
const UA: &str = "osnt-hazard-events/0.1 (+https://github.com/ogden-marrow/osnt-hub)";

const ALL_SOURCES: [&str; 7] = ["gdacs", "eonet", "gvp", "hans", "nhc", "nws", "reliefweb"];
/// Sources queried when the caller does not choose: everything that needs no per-user parameter or key.
const DEFAULT_SOURCES: [&str; 5] = ["gdacs", "eonet", "gvp", "hans", "nhc"];
const HAZARDS: [&str; 12] = ["earthquake", "cyclone", "flood", "volcano", "drought", "wildfire", "storm", "ice", "landslide", "dust", "weather-alert", "other"];

#[derive(Clone)]
pub struct Config {
    pub gdacs: String,
    pub eonet: String,
    pub nws: String,
    pub gvp: String,
    pub hans: String,
    pub nhc: String,
    pub reliefweb: String,
    /// Overrides the credential lookup (tests); None reads `RELIEFWEB_APPNAME`.
    pub reliefweb_appname: Option<String>,
}

impl Config {
    fn from_env() -> Self {
        let get = |k: &str, d: &str| env::var(k).unwrap_or_else(|_| d.to_string());
        Config {
            gdacs: get("OSNT_HAZARD_GDACS", "https://www.gdacs.org/gdacsapi/api/events/geteventlist/SEARCH"),
            eonet: get("OSNT_HAZARD_EONET", "https://eonet.gsfc.nasa.gov/api/v3/events"),
            nws: get("OSNT_HAZARD_NWS", "https://api.weather.gov/alerts/active"),
            gvp: get("OSNT_HAZARD_GVP", "https://volcano.si.edu/news/WeeklyVolcanoRSS.xml"),
            hans: get("OSNT_HAZARD_HANS", "https://volcanoes.usgs.gov/hans-public/api/volcano/getCapElevated"),
            nhc: get("OSNT_HAZARD_NHC", "https://www.nhc.noaa.gov/CurrentStorms.json"),
            reliefweb: get("OSNT_HAZARD_RELIEFWEB", "https://api.reliefweb.int/v2/disasters"),
            reliefweb_appname: None,
        }
    }
}

pub struct App {
    up: Upstream,
    cfg: Config,
}
type Shared = Arc<App>;

#[derive(Clone, Debug, Default)]
pub struct Params {
    pub sources: Vec<&'static str>,
    pub min_level: Option<&'static str>,
    pub hazards: Vec<String>,
    pub gdacs_all: bool,
    pub nws_area: Option<String>,
    pub nws_point: Option<(f64, f64)>,
}

fn param<'a>(q: &'a HashMap<String, String>, k: &str) -> Option<&'a str> {
    q.get(k).map(|s| s.trim()).filter(|s| !s.is_empty())
}

fn coord(q: &HashMap<String, String>, k: &str, lo: f64, hi: f64) -> Result<Option<f64>, ApiError> {
    match param(q, k) {
        None => Ok(None),
        Some(s) => s.parse::<f64>().ok().filter(|v| v.is_finite() && (lo..=hi).contains(v)).map(Some).ok_or_else(|| bad(format!("{k} must be a number between {lo} and {hi}"))),
    }
}

fn point_of(q: &HashMap<String, String>) -> Result<Option<(f64, f64)>, ApiError> {
    match (coord(q, "lat", -90.0, 90.0)?, coord(q, "lon", -180.0, 180.0)?) {
        (Some(a), Some(b)) => Ok(Some((a, b))),
        (None, None) => Ok(None),
        _ => Err(bad("give both lat and lon")),
    }
}

pub fn parse_params(q: &HashMap<String, String>) -> Result<Params, ApiError> {
    let mut p = Params::default();
    match param(q, "sources") {
        None => p.sources = DEFAULT_SOURCES.to_vec(),
        Some(list) => {
            for name in list.split(',').map(str::trim).filter(|x| !x.is_empty()) {
                let s = ALL_SOURCES.iter().find(|s| **s == name).ok_or_else(|| bad(format!("unknown source '{name}'; use any of {}", ALL_SOURCES.join(", "))))?;
                if !p.sources.contains(s) {
                    p.sources.push(s);
                }
            }
            if p.sources.is_empty() {
                return Err(bad("sources is empty"));
            }
        }
    }
    p.min_level = match param(q, "level") {
        None => None,
        Some(l) => Some(*sources::LEVELS.iter().find(|x| **x == l).ok_or_else(|| bad("level must be green, yellow, orange or red"))?),
    };
    if let Some(h) = param(q, "hazard") {
        for x in h.split(',').map(str::trim).filter(|x| !x.is_empty()) {
            if !HAZARDS.contains(&x) {
                return Err(bad(format!("unknown hazard '{x}'; use any of {}", HAZARDS.join(", "))));
            }
            p.hazards.push(x.to_string());
        }
    }
    p.gdacs_all = param(q, "gdacs_green") == Some("1");
    if let Some(a) = param(q, "area") {
        if a.len() != 2 || !a.bytes().all(|b| b.is_ascii_alphabetic()) {
            return Err(bad("area must be a two-letter US state, territory or marine area code, for example CA"));
        }
        p.nws_area = Some(a.to_ascii_uppercase());
    }
    p.nws_point = point_of(q)?;
    Ok(p)
}

pub fn haversine_km(a: (f64, f64), b: (f64, f64)) -> f64 {
    let (la1, la2) = (a.0.to_radians(), b.0.to_radians());
    let (dlat, dlon) = ((b.0 - a.0).to_radians(), (b.1 - a.1).to_radians());
    let h = (dlat / 2.0).sin().powi(2) + la1.cos() * la2.cos() * (dlon / 2.0).sin().powi(2);
    2.0 * 6371.0088 * h.sqrt().asin()
}

type Fetch = Result<(Vec<Value>, bool), String>;

/// Blocking: fetch and normalise one source.
fn load_source(app: &App, name: &str, p: &Params) -> Fetch {
    let cfg = &app.cfg;
    let json_of = |url: String, ttl: u64| app.up.get_json(&url, Duration::from_secs(ttl));
    match name {
        "gdacs" => {
            let levels = if p.gdacs_all { "Green;Orange;Red" } else { "Orange;Red" };
            // GDACS expects literal semicolons.
            let (v, st) = json_of(format!("{}?eventlist=EQ;TC;FL;VO;WF;DR&alertlevel={levels}", cfg.gdacs), 600)?;
            Ok((sources::gdacs(&v), st))
        }
        "eonet" => {
            let (v, st) = json_of(format!("{}?status=open&limit=150", cfg.eonet), 600)?;
            Ok((sources::eonet(&v), st))
        }
        "nws" => {
            let (url, fb) = match (&p.nws_point, &p.nws_area) {
                (Some((la, lo)), _) => (format!("{}?point={la:.4},{lo:.4}", cfg.nws), Some((*la, *lo))),
                (None, Some(a)) => (format!("{}?area={a}", cfg.nws), None),
                _ => return Err("NWS alerts need area (for example CA) or lat/lon; the national list is too large to fetch".to_string()),
            };
            let (v, st) = json_of(url, 120)?;
            Ok((sources::nws(&v, fb), st))
        }
        "gvp" => {
            let f = app.up.get(&cfg.gvp, Duration::from_secs(3600))?;
            // The feed is declared ISO-8859-1; the text is effectively ASCII, so lossy UTF-8 is safe.
            Ok((sources::gvp(&String::from_utf8_lossy(&f.body)), f.stale))
        }
        "hans" => {
            let (v, st) = json_of(cfg.hans.clone(), 600)?;
            Ok((sources::hans(&v), st))
        }
        "nhc" => {
            let (v, st) = json_of(cfg.nhc.clone(), 300)?;
            Ok((sources::nhc(&v), st))
        }
        "reliefweb" => {
            let appname = cfg.reliefweb_appname.clone().or_else(|| osnt_common::secret("RELIEFWEB_APPNAME")).ok_or("skipped: set RELIEFWEB_APPNAME on the Credentials page (ReliefWeb only answers approved app names)")?;
            let fields: String = ["name", "status", "country", "type", "date", "url"].iter().map(|f| format!("&fields%5Binclude%5D%5B%5D={f}")).collect();
            let (v, st) = json_of(format!("{}?appname={}&profile=list&preset=latest&limit=30&sort%5B%5D=date.event%3Adesc{fields}", cfg.reliefweb, enc(&appname)), 900)?;
            Ok((sources::reliefweb(&v), st))
        }
        _ => Err("unknown source".into()),
    }
}

pub struct Aggregate {
    pub events: Vec<Value>,
    pub status: Vec<Value>,
}

pub async fn aggregate(app: &Shared, p: &Params) -> Aggregate {
    let mut set = tokio::task::JoinSet::new();
    for (i, name) in p.sources.iter().enumerate() {
        let (app, p, name) = (app.clone(), p.clone(), *name);
        set.spawn_blocking(move || (i, name, load_source(&app, name, &p)));
    }
    let mut results: Vec<(usize, &str, Fetch)> = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(r) = r {
            results.push(r);
        }
    }
    results.sort_by_key(|r| r.0);
    let (mut events, mut status) = (Vec::new(), Vec::new());
    for (_, name, r) in results {
        match r {
            Ok((evs, stale)) => {
                status.push(json!({ "source": name, "ok": true, "count": evs.len(), "stale": stale }));
                events.extend(evs);
            }
            Err(e) => status.push(json!({ "source": name, "ok": false, "error": e })),
        }
    }
    let events = events
        .into_iter()
        .filter(|e| p.hazards.is_empty() || p.hazards.iter().any(|h| e["hazard"] == h.as_str()))
        .filter(|e| match (p.min_level, e["level"].as_str()) {
            (Some(min), Some(l)) => sources::level_rank(Some(l)) >= sources::level_rank(Some(min)),
            _ => true, // events without an alert level are never hidden by the level filter
        })
        .collect();
    Aggregate { events, status }
}

fn sort_events(evs: &mut [Value]) {
    evs.sort_by(|a, b| {
        sources::level_rank(b["level"].as_str()).cmp(&sources::level_rank(a["level"].as_str())).then_with(|| b["time"].as_str().cmp(&a["time"].as_str()))
    });
}

fn limit_of(q: &HashMap<String, String>, d: usize) -> Result<usize, ApiError> {
    match param(q, "limit") {
        None => Ok(d),
        Some(s) => s.parse::<usize>().ok().filter(|n| (1..=1000).contains(n)).ok_or_else(|| bad("limit must be 1-1000")),
    }
}

const ATTRIBUTION: &str = "GDACS (EC JRC / UN OCHA), NASA EONET (public domain), NOAA/NWS (public domain), Smithsonian Global Volcanism Program / USGS Weekly Volcanic Activity Report, USGS Volcano Hazards Program (public domain), NOAA National Hurricane Center (public domain), ReliefWeb (OCHA; terms apply). Informational only; not an official warning channel.";

fn fail_if_all_down(a: &Aggregate) -> Result<(), ApiError> {
    if !a.status.is_empty() && a.status.iter().all(|s| s["ok"] == false) {
        let msg = a.status.iter().filter_map(|s| Some(format!("{}: {}", s["source"].as_str()?, s["error"].as_str()?))).collect::<Vec<_>>().join("; ");
        return Err(upstream_err(msg));
    }
    Ok(())
}

async fn active(State(app): State<Shared>, Query(q): Query<HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let p = parse_params(&q)?;
    let limit = limit_of(&q, 500)?;
    let a = aggregate(&app, &p).await;
    fail_if_all_down(&a)?;
    let mut events = a.events;
    sort_events(&mut events);
    let total = events.len();
    events.truncate(limit);
    let mut counts: HashMap<String, usize> = HashMap::new();
    for e in &events {
        *counts.entry(e["hazard"].as_str().unwrap_or("other").to_string()).or_default() += 1;
    }
    Ok(Json(json!({ "count": events.len(), "total": total, "by_hazard": counts, "sources": a.status, "events": events, "attribution": ATTRIBUTION })))
}

async fn near(State(app): State<Shared>, Query(q): Query<HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let mut p = parse_params(&q)?;
    let c = p.nws_point.ok_or_else(|| bad("lat and lon are required"))?;
    let radius = coord(&q, "radius_km", 1.0, 20_000.0)?.unwrap_or(500.0);
    // Local NWS alerts for the point are part of "what is near here" when the caller asked for them or uses the defaults.
    if param(&q, "sources").is_none() {
        p.sources.push("nws");
    }
    let a = aggregate(&app, &p).await;
    fail_if_all_down(&a)?;
    let mut events: Vec<Value> = a
        .events
        .into_iter()
        .filter_map(|mut e| {
            let d = haversine_km(c, (e["lat"].as_f64()?, e["lon"].as_f64()?));
            (d <= radius).then(|| {
                e["distance_km"] = json!((d * 10.0).round() / 10.0);
                e
            })
        })
        .collect();
    events.sort_by(|a, b| a["distance_km"].as_f64().partial_cmp(&b["distance_km"].as_f64()).unwrap_or(std::cmp::Ordering::Equal));
    events.truncate(limit_of(&q, 200)?);
    Ok(Json(json!({ "center": { "lat": c.0, "lon": c.1 }, "radius_km": radius, "count": events.len(), "sources": a.status, "events": events, "attribution": ATTRIBUTION })))
}

async fn alerts(State(app): State<Shared>, Query(q): Query<HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let mut p = parse_params(&q)?;
    if p.nws_area.is_none() && p.nws_point.is_none() {
        return Err(bad("give area (a two-letter US state code such as CA) or lat and lon"));
    }
    p.sources = vec!["nws"];
    let a = aggregate(&app, &p).await;
    fail_if_all_down(&a)?;
    let mut events = a.events;
    sort_events(&mut events);
    events.truncate(limit_of(&q, 300)?);
    Ok(Json(json!({ "count": events.len(), "sources": a.status, "alerts": events, "attribution": "National Weather Service (NOAA), public domain. US only. Not an official warning channel." })))
}

async fn sources_info(State(app): State<Shared>) -> Json<Value> {
    let rw = app.cfg.reliefweb_appname.is_some() || tokio::task::spawn_blocking(|| osnt_common::secret("RELIEFWEB_APPNAME").is_some()).await.unwrap_or(false);
    Json(json!({
        "sources": [
            { "id": "gdacs", "name": "GDACS", "hazards": ["earthquake", "cyclone", "flood", "volcano", "drought", "wildfire"], "levelled": true, "default": true },
            { "id": "eonet", "name": "NASA EONET", "hazards": ["wildfire", "volcano", "storm", "flood", "ice", "other"], "levelled": false, "default": true },
            { "id": "gvp", "name": "Smithsonian/USGS weekly volcano report", "hazards": ["volcano"], "levelled": false, "default": true },
            { "id": "hans", "name": "USGS HANS elevated volcanoes", "hazards": ["volcano"], "levelled": true, "default": true },
            { "id": "nhc", "name": "NHC active storms", "hazards": ["cyclone"], "levelled": true, "default": true },
            { "id": "nws", "name": "NWS active alerts (US)", "hazards": ["weather-alert"], "levelled": true, "default": false, "needs": "area or lat/lon" },
            { "id": "reliefweb", "name": "ReliefWeb disasters", "hazards": ["other"], "levelled": false, "default": false, "needs": "RELIEFWEB_APPNAME", "configured": rw },
        ],
        "hazards": HAZARDS, "levels": sources::LEVELS,
    }))
}

async fn tools() -> Json<Value> {
    let common = json!({
        "sources": { "type": "string", "description": "comma list of gdacs, eonet, gvp, hans, nhc, nws, reliefweb (default: the first five)" },
        "hazard": { "type": "string", "description": "comma list: earthquake, cyclone, flood, volcano, drought, wildfire, storm, ice, landslide, dust, weather-alert, other" },
        "level": { "type": "string", "enum": ["green", "yellow", "orange", "red"], "description": "minimum alert level for sources that have one" },
    });
    let mut active_props = common.clone();
    active_props["limit"] = json!({ "type": "integer", "description": "1-1000, default 500" });
    let mut near_props = common.clone();
    near_props["lat"] = json!({ "type": "number" });
    near_props["lon"] = json!({ "type": "number" });
    near_props["radius_km"] = json!({ "type": "number", "description": "default 500" });
    Json(json!([
        { "name": "hazards_active", "description": "Active natural-hazard events worldwide in one model (GDACS orange/red alerts, NASA EONET open events, volcano reports, active tropical cyclones), sorted by alert level then time. Each event has hazard type, level, coordinates, time and a source link. Per-source status shows which feeds answered.",
          "method": "GET", "path": "api/active", "parameters": { "type": "object", "properties": active_props } },
        { "name": "hazards_near", "description": "Active hazard events within radius_km of a point, nearest first, including US NWS alerts that cover the point.",
          "method": "GET", "path": "api/near", "parameters": { "type": "object", "properties": near_props, "required": ["lat", "lon"] } },
        { "name": "hazards_alerts", "description": "US National Weather Service active alerts for a state/territory code (area, for example CA) or a point (lat, lon): event, severity, urgency, area, headline and expiry.",
          "method": "GET", "path": "api/alerts", "parameters": { "type": "object", "properties": {
              "area": { "type": "string", "description": "two-letter US state or territory code" }, "lat": { "type": "number" }, "lon": { "type": "number" },
              "level": { "type": "string", "enum": ["green", "yellow", "orange", "red"] }, "limit": { "type": "integer" } } } },
    ]))
}

async fn page() -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], PAGE).into_response()
}

pub fn app(cfg: Config, state_dir: PathBuf) -> Router {
    let st = Arc::new(App { up: Upstream { agent: osnt_common::http_agent(UA), cache: cache::DiskCache::new(state_dir.join("cache"), 8 * 1024 * 1024) }, cfg });
    Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/sources", get(sources_info))
        .route("/api/active", get(active))
        .route("/api/near", get(near))
        .route("/api/alerts", get(alerts))
        .with_state(st)
}

#[tokio::main]
async fn main() {
    let addr: SocketAddr = env::var("OSNT_HAZARD_BIND").unwrap_or_else(|_| "127.0.0.1:8154".into()).parse().expect("bind addr");
    let state = PathBuf::from(env::var("OSNT_HAZARD_STATE").unwrap_or_else(|_| env::temp_dir().join("osnt-hazard-events").to_string_lossy().into()));
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("hazard-events plugin on http://{addr}");
    axum::serve(listener, app(Config::from_env(), state)).await.expect("serve");
}


#[cfg(test)]
mod tests;

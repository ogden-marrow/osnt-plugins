//! Fire watch: statistics, clusters and area watches over NASA FIRMS VIIRS active-fire detections.
//!
//! Complements the `imagery` plugin, which only draws the GIBS thermal-anomaly tile layer for a date; this service
//! reads the detections themselves (free regional CSV files, or the FIRMS area API when a MAP_KEY is configured),
//! groups them into fire events, computes FRP statistics and trends, exports GeoJSON/CSV and flags new clusters in
//! saved boxes. Nothing is mirrored: files are cached for minutes under the state dir with a size cap.

mod cache;
mod firms;
mod util;
mod watch;

use std::{collections::HashMap, env, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{delete, get},
};
use serde_json::{Value, json};

use firms::{Hotspot, Region, REGIONS, SENSORS};
use util::{ApiError, Upstream, bad, enc, now_secs, upstream_err};

const PAGE: &str = include_str!("../assets/index.html");
const FILE_TTL: Duration = Duration::from_secs(20 * 60);
const MAX_POINTS: usize = 400_000;

#[derive(Clone)]
pub struct Config {
    pub files: String,
    pub api: String,
    /// Test override for the key; None reads `FIRMS_MAP_KEY` from the credential store.
    pub map_key: Option<String>,
    pub watch_interval: Duration,
}

impl Config {
    fn from_env() -> Self {
        let get = |k: &str, d: &str| env::var(k).unwrap_or_else(|_| d.to_string());
        Config {
            files: get("OSNT_FIRE_FILES", "https://firms.modaps.eosdis.nasa.gov/data/active_fire"),
            api: get("OSNT_FIRE_API", "https://firms.modaps.eosdis.nasa.gov/api/area/csv"),
            map_key: None,
            watch_interval: Duration::from_secs(30 * 60),
        }
    }
}

pub struct App {
    pub up: Upstream,
    pub cfg: Config,
    pub watches: watch::Store,
}
pub type Shared = Arc<App>;

#[derive(Clone, Debug)]
pub struct Query_ {
    pub bbox: [f64; 4],
    pub sensor: &'static str,
    pub window: &'static str,
    /// FIRMS area API days (1-10); only honoured when a key exists.
    pub days: Option<u32>,
    pub hours: Option<f64>,
    pub min_frp: f64,
    pub min_conf: u8,
    pub eps_km: f64,
}

fn p<'a>(q: &'a HashMap<String, String>, k: &str) -> Option<&'a str> {
    q.get(k).map(|s| s.trim()).filter(|s| !s.is_empty())
}

pub fn parse_bbox(s: &str) -> Result<[f64; 4], ApiError> {
    let v: Vec<f64> = s.split(',').map(|x| x.trim().parse::<f64>()).collect::<Result<_, _>>().map_err(|_| bad("bbox must be west,south,east,north in degrees"))?;
    let [w, so, e, n] = v[..] else { return Err(bad("bbox must be west,south,east,north in degrees")) };
    if ![w, so, e, n].iter().all(|x| x.is_finite()) || !(-180.0..=180.0).contains(&w) || !(-180.0..=180.0).contains(&e) || !(-90.0..=90.0).contains(&so) || !(-90.0..=90.0).contains(&n) {
        return Err(bad("bbox is out of range"));
    }
    if w >= e || so >= n {
        return Err(bad("bbox must have west < east and south < north"));
    }
    Ok([w, so, e, n])
}

pub fn parse_query(q: &HashMap<String, String>) -> Result<Query_, ApiError> {
    let bbox = match p(q, "bbox") {
        Some(b) => parse_bbox(b)?,
        None => [-180.0, -90.0, 180.0, 90.0],
    };
    let sensor = match p(q, "sensor") {
        // All three VIIRS satellites by default: Suomi NPP's feed can lag a day behind while NOAA-20/21 stay current.
        None | Some("all") => "all",
        Some(s) => firms::sensor(s).ok_or_else(|| bad("sensor must be all, snpp, noaa20 or noaa21"))?.id,
    };
    let window = match p(q, "window").unwrap_or("24h") {
        "24h" => "24h",
        "48h" => "48h",
        "7d" => "7d",
        _ => return Err(bad("window must be 24h, 48h or 7d")),
    };
    let days = match p(q, "days") {
        None => None,
        Some(d) => Some(d.parse::<u32>().ok().filter(|d| (1..=10).contains(d)).ok_or_else(|| bad("days must be 1-10 (needs a FIRMS MAP_KEY)"))?),
    };
    let hours = match p(q, "hours") {
        None => None,
        Some(h) => Some(h.parse::<f64>().ok().filter(|h| h.is_finite() && (1.0..=240.0).contains(h)).ok_or_else(|| bad("hours must be 1-240"))?),
    };
    let min_frp = match p(q, "min_frp") {
        None => 0.0,
        Some(f) => f.parse::<f64>().ok().filter(|f| f.is_finite() && (0.0..=100_000.0).contains(f)).ok_or_else(|| bad("min_frp must be a non-negative number (MW)"))?,
    };
    let min_conf = match p(q, "confidence") {
        None => 0,
        Some(c) => firms::conf_rank(c).ok_or_else(|| bad("confidence must be low, nominal or high"))?,
    };
    let eps_km = match p(q, "eps_km") {
        None => 2.0,
        Some(e) => e.parse::<f64>().ok().filter(|e| e.is_finite() && (0.5..=20.0).contains(e)).ok_or_else(|| bad("eps_km must be 0.5-20"))?,
    };
    Ok(Query_ { bbox, sensor, window, days, hours, min_frp, min_conf, eps_km })
}

pub struct Loaded {
    pub points: Vec<Hotspot>,
    pub source: String,
    pub stale: bool,
    pub truncated: bool,
}

fn map_key(app: &App) -> Option<String> {
    app.cfg.map_key.clone().or_else(|| osnt_common::secret("FIRMS_MAP_KEY"))
}

/// Blocking: fetch (cached) and filter detections for a query. `sensor=all` merges the three VIIRS satellites; one
/// failing satellite is tolerated as long as another answers.
pub fn load(app: &App, q: &Query_) -> Result<Loaded, ApiError> {
    let key = if q.days.is_some() { map_key(app) } else { None };
    if q.days.is_some() && key.is_none() {
        return Err(bad("days needs a FIRMS MAP_KEY; add FIRMS_MAP_KEY on the Credentials page, or use window=24h|48h|7d which needs no key"));
    }
    if q.days.is_none() && firms::region_for(&q.bbox) == "Global" && q.window == "7d" {
        return Err(bad("the 7-day file is not offered worldwide: zoom to one region (for example Europe) or add a FIRMS MAP_KEY and use days"));
    }
    let sensors: Vec<&firms::Sensor> = if q.sensor == "all" { SENSORS.iter().collect() } else { vec![firms::sensor(q.sensor).expect("validated")] };
    let (mut points, mut truncated, mut stale) = (Vec::new(), false, false);
    let (mut sources, mut errors) = (Vec::new(), Vec::new());
    for sensor in sensors {
        match load_sensor(app, q, sensor, key.as_deref()) {
            Ok((pts, tr, st, src)) => {
                points.extend(pts);
                truncated |= tr;
                stale |= st;
                sources.push(src);
            }
            Err(e) => errors.push(e),
        }
    }
    if sources.is_empty() {
        return Err(errors.into_iter().next().unwrap_or_else(|| upstream_err("no fire data")));
    }
    let now = now_secs();
    points.retain(|h| h.frp >= q.min_frp && h.conf >= q.min_conf && q.hours.is_none_or(|hrs| (now - h.t) as f64 <= hrs * 3600.0 + 900.0));
    let mut source = sources.join(" + ");
    if !errors.is_empty() {
        source.push_str(&format!(" (partial: {} satellite file(s) unavailable)", errors.len()));
    }
    Ok(Loaded { points, source, stale, truncated })
}

type SensorLoad = (Vec<Hotspot>, bool, bool, String);

fn load_sensor(app: &App, q: &Query_, sensor: &firms::Sensor, key: Option<&str>) -> Result<SensorLoad, ApiError> {
    let (cache_key, url, source) = if let (Some(k), Some(d)) = (key, q.days) {
        let area = q.bbox.iter().map(|x| format!("{x}")).collect::<Vec<_>>().join(",");
        (format!("api|{}|{area}|{d}", sensor.api), format!("{}/{}/{}/{area}/{d}", app.cfg.api, enc(k), sensor.api), format!("FIRMS area API {}, {} days", sensor.id, d))
    } else {
        let region = firms::region_for(&q.bbox);
        let name = format!("{}_{}_{}.csv", sensor.prefix, region, q.window);
        (format!("file|{name}|{}", sensor.dir), format!("{}/{}/csv/{name}", app.cfg.files, sensor.dir), format!("FIRMS {} {} file, {}", sensor.id, region.replace('_', " "), q.window))
    };
    let f = app.up.get_as(&cache_key, &url, FILE_TTL).map_err(upstream_err)?;
    let text = String::from_utf8_lossy(&f.body);
    let (points, truncated) = firms::parse_csv(&text, &q.bbox, MAX_POINTS).map_err(upstream_err)?;
    Ok((points, truncated, f.stale, source))
}

async fn load_async(app: &Shared, q: Query_) -> Result<Loaded, ApiError> {
    let app = app.clone();
    tokio::task::spawn_blocking(move || load(&app, &q)).await.map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

fn limit(q: &HashMap<String, String>, d: usize, max: usize) -> Result<usize, ApiError> {
    match p(q, "limit") {
        None => Ok(d),
        Some(s) => s.parse::<usize>().ok().filter(|n| (1..=max).contains(n)).ok_or_else(|| bad(format!("limit must be 1-{max}"))),
    }
}

fn meta(l: &Loaded, q: &Query_) -> Value {
    let newest = l.points.iter().map(|h| h.t).max();
    json!({ "newest_detection": newest.map(util::iso), "newest_age_hours": newest.map(|t| firms::round((now_secs() - t) as f64 / 3600.0, 1)),
            "source": l.source, "stale": l.stale, "truncated": l.truncated, "sensor": q.sensor, "window": q.window, "bbox": q.bbox, "eps_km": q.eps_km,
            "attribution": "Fire detections: NASA FIRMS (LANCE/FIRMS), VIIRS 375 m active fire, public domain; acknowledge NASA FIRMS. Detections include industrial heat sources such as gas flares and are not confirmed wildfires." })
}

/// Area summary: statistics, trend and clusters (optionally the strongest raw detections).
async fn fires(State(app): State<Shared>, Query(qm): Query<HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let q = parse_query(&qm)?;
    let lim = limit(&qm, 300, 1500)?;
    let l = load_async(&app, q.clone()).await?;
    let cl = firms::cluster(&l.points, q.eps_km);
    let mut out = json!({ "meta": meta(&l, &q), "stats": firms::stats(&l.points, &cl), "clusters": cl.iter().take(lim).map(|c| c.to_json()).collect::<Vec<_>>() });
    if p(&qm, "points") == Some("1") {
        let mut pts: Vec<&Hotspot> = l.points.iter().collect();
        pts.sort_by(|a, b| b.frp.partial_cmp(&a.frp).unwrap_or(std::cmp::Ordering::Equal));
        out["points"] = json!(pts.iter().take(lim.min(3000)).map(|h| point_json(h)).collect::<Vec<_>>());
    }
    Ok(Json(out))
}

fn point_json(h: &Hotspot) -> Value {
    json!({ "lat": h.lat, "lon": h.lon, "frp": firms::round(h.frp, 2), "time": util::iso(h.t), "night": h.night, "confidence": firms::conf_name(h.conf), "satellite": h.sat })
}

async fn clusters(State(app): State<Shared>, Query(qm): Query<HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let q = parse_query(&qm)?;
    let lim = limit(&qm, 100, 1500)?;
    let l = load_async(&app, q.clone()).await?;
    let cl = firms::cluster(&l.points, q.eps_km);
    Ok(Json(json!({ "meta": meta(&l, &q), "count": cl.len(), "clusters": cl.iter().take(lim).map(|c| c.to_json()).collect::<Vec<_>>() })))
}

async fn recent(State(app): State<Shared>, Query(qm): Query<HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let q = parse_query(&qm)?;
    let lim = limit(&qm, 100, 1000)?;
    let l = load_async(&app, q.clone()).await?;
    let mut pts: Vec<&Hotspot> = l.points.iter().collect();
    pts.sort_by(|a, b| b.t.cmp(&a.t).then(b.frp.partial_cmp(&a.frp).unwrap_or(std::cmp::Ordering::Equal)));
    Ok(Json(json!({ "meta": meta(&l, &q), "count": l.points.len(), "detections": pts.iter().take(lim).map(|h| point_json(h)).collect::<Vec<_>>() })))
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.to_string() }
}

/// GeoJSON or CSV of clusters (default) or raw detections.
async fn export(State(app): State<Shared>, Query(qm): Query<HashMap<String, String>>) -> Result<Response, ApiError> {
    let q = parse_query(&qm)?;
    let format = p(&qm, "format").unwrap_or("geojson");
    let what = p(&qm, "what").unwrap_or("clusters");
    if !["geojson", "csv"].contains(&format) || !["clusters", "points"].contains(&what) {
        return Err(bad("format must be geojson or csv and what must be clusters or points"));
    }
    let l = load_async(&app, q.clone()).await?;
    let rows: Vec<Value> = if what == "points" { l.points.iter().take(50_000).map(point_json).collect() } else { firms::cluster(&l.points, q.eps_km).iter().take(5000).map(|c| c.to_json()).collect() };
    let (body, ctype) = if format == "csv" {
        let cols: Vec<&str> = if what == "points" { vec!["lat", "lon", "frp", "time", "night", "confidence", "satellite"] } else { vec!["id", "lat", "lon", "count", "frp_total", "frp_max", "first", "last", "day", "night", "radius_km", "high_confidence"] };
        let mut s = cols.join(",") + "\n";
        for r in &rows {
            s += &cols.iter().map(|c| csv_field(&match &r[*c] { Value::String(x) => x.clone(), Value::Null => String::new(), v => v.to_string() })).collect::<Vec<_>>().join(",");
            s.push('\n');
        }
        (s, "text/csv; charset=utf-8")
    } else {
        let feats: Vec<Value> = rows.iter().map(|r| json!({ "type": "Feature", "geometry": { "type": "Point", "coordinates": [r["lon"], r["lat"]] }, "properties": r })).collect();
        (json!({ "type": "FeatureCollection", "features": feats, "attribution": "NASA FIRMS" }).to_string(), "application/geo+json")
    };
    let name = format!("fires-{what}.{}", if format == "csv" { "csv" } else { "geojson" });
    Ok(([(header::CONTENT_TYPE, ctype.to_string()), (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\""))], body).into_response())
}

// ---- watches (signed-in users only) --------------------------------------------------------------------------------

fn signed_in(method: &Method, uri: &Uri, headers: &HeaderMap) -> Result<(), ApiError> {
    let ok = osnt_common::gateway_authorized(method.as_str(), uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"), headers.get("x-osnt-gateway").and_then(|v| v.to_str().ok()));
    if ok { Ok(()) } else { Err(ApiError(StatusCode::UNAUTHORIZED, "sign in to the hub to manage watches".into())) }
}

async fn watch_list(State(app): State<Shared>, method: Method, uri: Uri, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    signed_in(&method, &uri, &headers)?;
    Ok(Json(json!({ "watches": app.watches.list() })))
}

async fn watch_add(State(app): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Result<Json<Value>, ApiError> {
    signed_in(&method, &uri, &headers)?;
    let v: Value = serde_json::from_slice(&body).map_err(|_| bad("body must be JSON"))?;
    let name = v["name"].as_str().map(str::trim).filter(|n| !n.is_empty() && n.chars().count() <= 60 && !n.chars().any(char::is_control)).ok_or_else(|| bad("name is required (at most 60 characters)"))?;
    let bbox = parse_bbox(v["bbox"].as_str().ok_or_else(|| bad("bbox is required as 'west,south,east,north'"))?)?;
    if bbox[2] - bbox[0] > 30.0 || bbox[3] - bbox[1] > 30.0 {
        return Err(bad("a watch box may be at most 30 degrees on a side"));
    }
    let min_frp = v["min_frp"].as_f64().filter(|f| f.is_finite() && (0.0..=10_000.0).contains(f)).unwrap_or(0.0);
    let id = app.watches.add(name.to_string(), bbox, min_frp).map_err(bad)?;
    // Baseline now so the first check does not report every existing fire as new.
    let a = app.clone();
    let _ = tokio::task::spawn_blocking(move || watch::check_one(&a, &id, true)).await;
    Ok(Json(json!({ "watches": app.watches.list() })))
}

async fn watch_delete(State(app): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    signed_in(&method, &uri, &headers)?;
    if !app.watches.remove(&id) {
        return Err(ApiError(StatusCode::NOT_FOUND, "no such watch".into()));
    }
    Ok(Json(json!({ "watches": app.watches.list() })))
}

async fn watch_check(State(app): State<Shared>, method: Method, uri: Uri, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    signed_in(&method, &uri, &headers)?;
    let a = app.clone();
    tokio::task::spawn_blocking(move || watch::check_all(&a)).await.map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "watches": app.watches.list() })))
}

async fn info(State(app): State<Shared>) -> Json<Value> {
    let a = app.clone();
    let key = tokio::task::spawn_blocking(move || map_key(&a).is_some()).await.unwrap_or(false);
    Json(json!({
        "map_key_configured": key,
        "sensors": SENSORS.iter().map(|s| json!({ "id": s.id, "name": s.name })).collect::<Vec<_>>(),
        "regions": REGIONS.iter().map(|r: &Region| json!({ "key": r.key, "name": r.name, "bbox": r.bbox })).collect::<Vec<_>>(),
        "windows": ["24h", "48h", "7d (regional files only)"],
        "overlap": "The Imagery plugin draws NASA GIBS thermal-anomaly tiles for a chosen date. Fire watch reads the detections themselves for statistics, clusters, trends, exports and watches.",
    }))
}

async fn tools() -> Json<Value> {
    let common = json!({
        "bbox": { "type": "string", "description": "west,south,east,north in degrees (default: whole world, 24h only)" },
        "window": { "type": "string", "enum": ["24h", "48h", "7d"], "description": "7d needs a regional bbox (it must fit inside one FIRMS region such as Europe)" },
        "sensor": { "type": "string", "enum": ["all", "snpp", "noaa20", "noaa21"], "description": "default all (the three VIIRS satellites merged)" },
        "hours": { "type": "number", "description": "only detections from the last N hours" },
        "min_frp": { "type": "number", "description": "minimum fire radiative power in MW" },
        "confidence": { "type": "string", "enum": ["low", "nominal", "high"], "description": "minimum detection confidence" },
        "limit": { "type": "integer" },
    });
    let mut clusters_props = common.clone();
    clusters_props["eps_km"] = json!({ "type": "number", "description": "link detections closer than this (0.5-20 km, default 2)" });
    Json(json!([
        { "name": "fire_recent", "description": "Most recent VIIRS active-fire detections in an area (time, position, FRP in MW, day/night, confidence). Detections include industrial heat sources and are not confirmed wildfires. Data: NASA FIRMS.",
          "method": "GET", "path": "api/recent", "parameters": { "type": "object", "properties": common } },
        { "name": "fire_clusters", "description": "Active-fire detections grouped into fire events with statistics: per-cluster detection count, total and peak FRP, day/night split, first/last detection, plus totals, a per-day timeline and confidence mix for the area.",
          "method": "GET", "path": "api/fires", "parameters": { "type": "object", "properties": clusters_props } },
    ]))
}

async fn page() -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], PAGE).into_response()
}

pub fn app(cfg: Config, state_dir: PathBuf) -> (Router, Shared) {
    let st = Arc::new(App {
        up: Upstream { agent: util::fire_agent(), cache: cache::DiskCache::new(state_dir.join("cache"), 96 * 1024 * 1024) },
        cfg,
        watches: watch::Store::open(state_dir.join("watches.json")),
    });
    let r = Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/info", get(info))
        .route("/api/fires", get(fires))
        .route("/api/clusters", get(clusters))
        .route("/api/recent", get(recent))
        .route("/api/export", get(export))
        .route("/api/watches", get(watch_list).post(watch_add))
        .route("/api/watches/check", axum::routing::post(watch_check))
        .route("/api/watches/{id}", delete(watch_delete))
        .with_state(st.clone());
    (r, st)
}

#[tokio::main]
async fn main() {
    let addr: SocketAddr = env::var("OSNT_FIRE_BIND").unwrap_or_else(|_| "127.0.0.1:8155".into()).parse().expect("bind addr");
    let state = PathBuf::from(env::var("OSNT_FIRE_STATE").unwrap_or_else(|_| env::temp_dir().join("osnt-fire-watch").to_string_lossy().into()));
    let cfg = Config::from_env();
    let (router, shared) = app(cfg.clone(), state);
    watch::spawn_background(shared, cfg.watch_interval);
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("fire-watch plugin on http://{addr}");
    axum::serve(listener, router).await.expect("serve");
}

#[cfg(test)]
mod tests;

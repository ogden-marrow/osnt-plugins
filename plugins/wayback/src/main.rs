//! Imagery history: Esri World Imagery Wayback. The archive of dated basemap releases (2014 onwards) is public; the
//! browser draws tiles straight from Esri's tile servers. This service answers the questions a tile server cannot:
//! which releases exist, which of them actually changed at a given place (via the tilemap index), and when and at what
//! resolution the pixels at a point were captured (via Esri's metadata layers). Only small JSON documents are cached.
//! Listens on loopback only; the hub reverse-proxies it at /p/wayback/.

mod cache;

use std::{
    collections::{BTreeSet, HashMap},
    env,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
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
const UA: &str = "osnt-wayback/0.1 (+https://github.com/ogden-marrow/osnt-plugins; self-hosted OSINT hub)";
const CONFIG_TTL: Duration = Duration::from_secs(6 * 3600);
const CHANGES_TTL: Duration = Duration::from_secs(6 * 3600);
const CAPTURE_TTL: Duration = Duration::from_secs(24 * 3600);
const WORKERS: usize = 8;

#[derive(Clone)]
pub struct Config {
    pub config_url: String,
    /// `{base}/{release}/{z}/{row}/{col}` returns the tilemap JSON.
    pub tilemap_base: String,
    /// Browser tile template with `{id}` for the release number.
    pub tile_template: String,
    /// Metadata layer URLs from the config must start with this prefix before they are queried.
    pub meta_prefix: String,
}

impl Config {
    fn from_env() -> Self {
        let get = |k: &str, d: &str| env::var(k).unwrap_or_else(|_| d.to_string());
        Config {
            config_url: get("OSNT_WAYBACK_CONFIG", "https://s3-us-west-2.amazonaws.com/config.maptiles.arcgis.com/waybackconfig.json"),
            tilemap_base: get("OSNT_WAYBACK_TILEMAP", "https://wayback.maptiles.arcgis.com/arcgis/rest/services/World_Imagery/MapServer/tilemap"),
            tile_template: get("OSNT_WAYBACK_TILES", "https://wayback.maptiles.arcgis.com/arcgis/rest/services/world_imagery/wmts/1.0.0/default028mm/mapserver/tile/{id}/{z}/{y}/{x}"),
            meta_prefix: get("OSNT_WAYBACK_META_PREFIX", "https://metadata.maptiles.arcgis.com/"),
        }
    }
}

pub struct App {
    agent: ureq::Agent,
    cfg: Config,
    cache: cache::DiskCache,
}
type Shared = Arc<App>;

#[derive(Clone, Debug, PartialEq)]
struct Release {
    id: u64,
    date: String,
    meta_url: Option<String>,
}

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

fn get_json(agent: &ureq::Agent, url: &str) -> Result<Value, String> {
    let mut res = agent.get(url).call().map_err(|e| match e {
        ureq::Error::StatusCode(c) => format!("Esri answered HTTP {c}"),
        _ => "Esri could not be reached".to_string(),
    })?;
    res.body_mut().read_json::<Value>().map_err(|_| "Esri sent an unreadable response".to_string())
}

/// Pull `YYYY-MM-DD` out of "World Imagery (Wayback 2026-10-29)".
fn title_date(t: &str) -> Option<String> {
    let b = t.as_bytes();
    (0..b.len().saturating_sub(9)).find_map(|i| {
        let w = &t[i..i + 10];
        let ok = w.is_char_boundary(0) && w.bytes().enumerate().all(|(j, c)| if j == 4 || j == 7 { c == b'-' } else { c.is_ascii_digit() });
        ok.then(|| w.to_string())
    })
}

fn parse_config(v: &Value) -> Vec<Release> {
    let mut out: Vec<Release> = v
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, r)| {
                    Some(Release {
                        id: k.parse().ok()?,
                        date: title_date(r.get("itemTitle")?.as_str()?)?,
                        meta_url: r.get("metadataLayerUrl").and_then(Value::as_str).map(str::to_string),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| a.date.cmp(&b.date).then(a.id.cmp(&b.id)));
    out
}

async fn releases_cached(app: &Shared) -> Result<Vec<Release>, ApiError> {
    let key = format!("config|{}", app.cfg.config_url);
    if let Some(raw) = app.cache.get(&key, CONFIG_TTL) {
        if let Ok(v) = serde_json::from_slice::<Value>(&raw) {
            return Ok(parse_config(&v));
        }
    }
    let a = app.clone();
    let v = tokio::task::spawn_blocking(move || get_json(&a.agent, &a.cfg.config_url))
        .await
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(upstream)?;
    app.cache.put(&key, v.to_string().as_bytes());
    let r = parse_config(&v);
    if r.is_empty() {
        return Err(upstream("the Wayback release list was empty"));
    }
    Ok(r)
}

async fn releases(State(app): State<Shared>) -> Result<Json<Value>, ApiError> {
    let r = releases_cached(&app).await?;
    Ok(Json(json!({
        "count": r.len(),
        "first": r.first().map(|x| &x.date), "latest": r.last().map(|x| &x.date),
        "tile_template": app.cfg.tile_template,
        "releases": r.iter().map(|x| json!({ "id": x.id, "date": x.date })).collect::<Vec<_>>(),
        "attribution": "Esri World Imagery Wayback. Imagery source: Esri, Vantor (formerly Maxar), Earthstar Geographics and the GIS user community.",
    })))
}

fn coord(q: &HashMap<String, String>, k: &str, lim: f64) -> Result<f64, ApiError> {
    q.get(k).and_then(|v| v.trim().parse::<f64>().ok()).filter(|v| v.is_finite() && v.abs() <= lim).ok_or_else(|| bad(format!("{k} is required and must be within +/-{lim}")))
}

/// Web-mercator tile for a point.
fn tile_of(lat: f64, lon: f64, z: u32) -> (u32, u32) {
    let n = (1u64 << z) as f64;
    let lat = lat.clamp(-85.0511, 85.0511).to_radians();
    let x = ((lon + 180.0) / 360.0 * n).floor().clamp(0.0, n - 1.0);
    let y = ((1.0 - (lat.tan() + 1.0 / lat.cos()).ln() / std::f64::consts::PI) / 2.0 * n).floor().clamp(0.0, n - 1.0);
    (x as u32, y as u32)
}

/// Which releases supplied the pixels of one tile? The tilemap for release R names the release (`select`) whose copy of
/// the tile is shown at R; the distinct values over all releases are the versions that actually differ here.
async fn changes(State(app): State<Shared>, Query(q): Query<HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let lat = coord(&q, "lat", 90.0)?;
    let lon = coord(&q, "lon", 180.0)?;
    let z: u32 = q.get("zoom").and_then(|z| z.parse().ok()).unwrap_or(16).clamp(8, 19);
    let (col, row) = tile_of(lat, lon, z);
    let rel = releases_cached(&app).await?;
    let key = format!("changes|{}|{z}/{row}/{col}", app.cfg.tilemap_base);
    let selected: Vec<u64> = match app.cache.get(&key, CHANGES_TTL).and_then(|b| serde_json::from_slice(&b).ok()) {
        Some(v) => v,
        None => {
            let a = app.clone();
            let ids: Vec<u64> = rel.iter().map(|r| r.id).collect();
            let sel = tokio::task::spawn_blocking(move || {
                let queue = std::sync::Mutex::new(ids.into_iter());
                let found = std::sync::Mutex::new(BTreeSet::new());
                let failures = std::sync::atomic::AtomicUsize::new(0);
                std::thread::scope(|s| {
                    for _ in 0..WORKERS {
                        s.spawn(|| {
                            loop {
                                let Some(id) = queue.lock().unwrap().next() else { break };
                                let url = format!("{}/{id}/{z}/{row}/{col}", a.cfg.tilemap_base);
                                match get_json(&a.agent, &url) {
                                    Ok(v) => {
                                        if let Some(s) = v.get("select").and_then(|s| s.get(0)).and_then(Value::as_u64) {
                                            found.lock().unwrap().insert(s);
                                        }
                                    }
                                    Err(_) => {
                                        failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                }
                            }
                        });
                    }
                });
                (found.into_inner().unwrap().into_iter().collect::<Vec<u64>>(), failures.into_inner())
            })
            .await
            .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            if sel.1 > rel.len() / 4 {
                return Err(upstream("Esri's tile index failed too often; try again shortly"));
            }
            if sel.1 == 0 {
                app.cache.put(&key, serde_json::to_string(&sel.0).unwrap().as_bytes());
            }
            sel.0
        }
    };
    let by_id: HashMap<u64, &Release> = rel.iter().map(|r| (r.id, r)).collect();
    let mut versions: Vec<Value> = selected.iter().filter_map(|id| by_id.get(id)).map(|r| json!({ "id": r.id, "date": r.date })).collect();
    versions.sort_by(|a, b| a["date"].as_str().cmp(&b["date"].as_str()));
    Ok(Json(json!({
        "lat": lat, "lon": lon, "tile": { "z": z, "row": row, "col": col },
        "releases_checked": rel.len(), "count": versions.len(), "versions": versions,
        "note": "Each version is a release in which the imagery for this map tile differs from earlier ones. A tile is roughly a few hundred metres at zoom 16.",
    })))
}

fn pick_release<'a>(rel: &'a [Release], q: &HashMap<String, String>) -> Result<&'a Release, ApiError> {
    if let Some(id) = q.get("release").filter(|s| !s.is_empty()) {
        let id: u64 = id.parse().map_err(|_| bad("release must be a number from /api/releases"))?;
        return rel.iter().find(|r| r.id == id).ok_or_else(|| bad("unknown release"));
    }
    match q.get("date").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(d) => {
            title_date(d).filter(|x| x == d).ok_or_else(|| bad("date must be YYYY-MM-DD"))?;
            rel.iter().rfind(|r| r.date.as_str() <= d).ok_or_else(|| bad("date is before the first Wayback release"))
        }
        None => rel.last().ok_or_else(|| bad("no releases")),
    }
}

/// When were the pixels at this point captured, at what resolution, by whom? Esri keeps one metadata layer per
/// resolution band; the finest band that has a footprint at the point is the one on screen.
async fn capture(State(app): State<Shared>, Query(q): Query<HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let lat = coord(&q, "lat", 90.0)?;
    let lon = coord(&q, "lon", 180.0)?;
    let rel = releases_cached(&app).await?;
    let r = pick_release(&rel, &q)?.clone();
    let meta = r.meta_url.clone().filter(|u| u.starts_with(&app.cfg.meta_prefix)).ok_or_else(|| upstream("this release has no capture metadata"))?;
    let key = format!("capture|{}|{lat:.4}|{lon:.4}", r.id);
    let found: Value = match app.cache.get(&key, CAPTURE_TTL).and_then(|b| serde_json::from_slice(&b).ok()) {
        Some(v) => v,
        None => {
            let a = app.clone();
            let v = tokio::task::spawn_blocking(move || {
                let results: std::sync::Mutex<Vec<(u32, Value)>> = Default::default();
                let reachable = std::sync::atomic::AtomicUsize::new(0);
                std::thread::scope(|s| {
                    for layer in 0u32..14 {
                        let (meta, results, reachable, a) = (&meta, &results, &reachable, &a);
                        s.spawn(move || {
                            let url = format!(
                                "{meta}/{layer}/query?f=json&geometry={lon},{lat}&geometryType=esriGeometryPoint&inSR=4326&spatialRel=esriSpatialRelIntersects&outFields=SRC_DATE2,SRC_RES,SRC_ACC,NICE_NAME,NICE_DESC&returnGeometry=false"
                            );
                            if let Ok(v) = get_json(&a.agent, &url) {
                                reachable.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                if let Some(f) = v.pointer("/features/0/attributes") {
                                    results.lock().unwrap().push((layer, f.clone()));
                                }
                            }
                        });
                    }
                });
                if reachable.into_inner() == 0 {
                    return Err("Esri's metadata service could not be reached".to_string());
                }
                let mut v = results.into_inner().unwrap();
                v.sort_by_key(|x| x.0);
                Ok(v.into_iter().next().map(|(_, f)| f).unwrap_or(Value::Null))
            })
            .await
            .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .map_err(upstream)?;
            app.cache.put(&key, v.to_string().as_bytes());
            v
        }
    };
    let date = found.get("SRC_DATE2").and_then(Value::as_i64).map(|ms| {
        let (y, m, d) = civil(ms.div_euclid(86_400_000));
        format!("{y:04}-{m:02}-{d:02}")
    });
    Ok(Json(json!({
        "lat": lat, "lon": lon, "release": r.id, "release_date": r.date,
        "found": !found.is_null(),
        "capture_date": date,
        "resolution_m": found.get("SRC_RES").and_then(Value::as_f64),
        "accuracy_m": found.get("SRC_ACC").and_then(Value::as_f64),
        "source": found.get("NICE_NAME").and_then(Value::as_str),
        "provider": found.get("NICE_DESC").and_then(Value::as_str),
        "note": "Capture date is when the satellite or aircraft image shown at this point was taken, which can be older than the release date.",
    })))
}

fn civil(days: i64) -> (i64, i64, i64) {
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

async fn tools() -> Json<Value> {
    Json(json!([
        { "name": "wayback_releases",
          "description": "List the dated releases of Esri's World Imagery Wayback archive (a historical basemap, 2014 to now). Returns release ids and dates; each is a snapshot of the whole-world imagery basemap, not one satellite pass.",
          "method": "GET", "path": "api/releases", "parameters": { "type": "object", "properties": {} } },
        { "name": "wayback_changes",
          "description": "For a point, list the Wayback releases in which the imagery actually changed there (new capture), i.e. the distinct historical versions available for that location. Returns dates and release ids, and a link-free metadata answer. Use before comparing dates.",
          "method": "GET", "path": "api/changes",
          "parameters": { "type": "object", "properties": {
              "lat": { "type": "number" }, "lon": { "type": "number" },
              "zoom": { "type": "integer", "description": "tile zoom 8-19 that sets the size of the area checked (default 16)" } }, "required": ["lat", "lon"] } },
        { "name": "wayback_capture",
          "description": "When and at what resolution was the imagery at a point captured? Give a Wayback release (by id or by date, the release at or before that date is used; default latest). Returns capture date, resolution in metres, accuracy and provider.",
          "method": "GET", "path": "api/capture",
          "parameters": { "type": "object", "properties": {
              "lat": { "type": "number" }, "lon": { "type": "number" },
              "date": { "type": "string", "description": "YYYY-MM-DD" }, "release": { "type": "integer" } }, "required": ["lat", "lon"] } }
    ]))
}

async fn page() -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], PAGE).into_response()
}

pub fn app(cfg: Config, state_dir: PathBuf) -> Router {
    let st = Arc::new(App { agent: osnt_common::http_agent(UA), cfg, cache: cache::DiskCache::new(state_dir.join("cache"), 4 * 1024 * 1024) });
    Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/releases", get(releases))
        .route("/api/changes", get(changes))
        .route("/api/capture", get(capture))
        .with_state(st)
}

#[tokio::main]
async fn main() {
    let addr: SocketAddr = env::var("OSNT_WAYBACK_BIND").unwrap_or_else(|_| "127.0.0.1:8124".into()).parse().expect("bind addr");
    let state = PathBuf::from(env::var("OSNT_WAYBACK_STATE").unwrap_or_else(|_| env::temp_dir().join("osnt-wayback").to_string_lossy().into()));
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("wayback plugin on http://{addr}");
    axum::serve(listener, app(Config::from_env(), state)).await.expect("serve");
}

#[cfg(test)]
mod tests;

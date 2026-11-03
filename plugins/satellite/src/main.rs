//! Satellite scenes: STAC search over free, open archives (Microsoft Planetary Computer, Element 84 Earth Search),
//! normalised into scenes with footprints, thumbnails and map tile templates. Nothing is mirrored: the service only
//! relays small JSON search results (cached briefly under the state dir); the browser fetches imagery tiles straight
//! from the upstream tilers. Listens on loopback only; the hub reverse-proxies it at /p/satellite/.

mod cache;

use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
const UA: &str = "osnt-satellite/0.1 (+https://github.com/ogden-marrow/osnt-plugins; self-hosted OSINT hub)";
const SEARCH_TTL: Duration = Duration::from_secs(600);
const MAX_SPAN_DEG: f64 = 12.0;

#[derive(Clone)]
pub struct Config {
    pub pc_stac: String,
    pub es_stac: String,
    /// Planetary Computer data API; tile templates must live under this prefix.
    pub pc_data: String,
    /// Public titiler used to render Earth Search COGs (best effort demo service).
    pub titiler: String,
}

impl Config {
    fn from_env() -> Self {
        let get = |k: &str, d: &str| env::var(k).unwrap_or_else(|_| d.to_string());
        Config {
            pc_stac: get("OSNT_SATELLITE_PC_STAC", "https://planetarycomputer.microsoft.com/api/stac/v1"),
            es_stac: get("OSNT_SATELLITE_ES_STAC", "https://earth-search.aws.element84.com/v1"),
            pc_data: get("OSNT_SATELLITE_PC_DATA", "https://planetarycomputer.microsoft.com/api/data/v1/"),
            titiler: get("OSNT_SATELLITE_TITILER", "https://titiler.xyz"),
        }
    }
}

pub struct App {
    agent: ureq::Agent,
    cfg: Config,
    cache: cache::DiskCache,
    pc_key: Mutex<Option<(Instant, Option<String>)>>,
}
type Shared = Arc<App>;

/// What a "kind" means on each source.
struct Kind {
    id: &'static str,
    label: &'static str,
    optical: bool,
    pc: &'static str,
    es: Option<&'static str>,
    note: &'static str,
}

const KINDS: [Kind; 4] = [
    Kind { id: "s2", label: "Sentinel-2 L2A (10 m optical)", optical: true, pc: "sentinel-2-l2a", es: Some("sentinel-2-l2a"),
           note: "Contains modified Copernicus Sentinel data. Revisit about 5 days (2 satellites), clouds block the view." },
    Kind { id: "s1", label: "Sentinel-1 SAR (10 m radar, day and night)", optical: false, pc: "sentinel-1-rtc", es: Some("sentinel-1-grd"),
           note: "Contains modified Copernicus Sentinel data. Radar sees through cloud and at night; bright = rough or metal, dark = smooth or water. Map view needs the Planetary Computer source." },
    Kind { id: "landsat", label: "Landsat 8/9 (30 m optical)", optical: true, pc: "landsat-c2-l2", es: Some("landsat-c2-l2"),
           note: "Landsat Collection 2 Level 2, courtesy of USGS (public domain). Revisit 8 days with two satellites." },
    Kind { id: "naip", label: "NAIP aerial (about 0.6 m, USA only)", optical: false, pc: "naip", es: Some("naip"),
           note: "USDA National Agriculture Imagery Program, public domain. Aerial survey of the US every 2-3 years, summer growing season." },
];

fn kind(id: &str) -> Option<&'static Kind> {
    KINDS.iter().find(|k| k.id == id)
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Days since 1970-01-01 -> (year, month, day) (proleptic Gregorian).
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

fn date_ago(days: i64) -> String {
    let (y, m, d) = civil(now_secs().div_euclid(86_400) - days);
    format!("{y:04}-{m:02}-{d:02}")
}

fn valid_date(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' || !b.iter().enumerate().all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit()) {
        return false;
    }
    let (y, m, d): (i64, i64, i64) = (s[..4].parse().unwrap_or(0), s[5..7].parse().unwrap_or(0), s[8..10].parse().unwrap_or(0));
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=dim).contains(&d) && y >= 1972
}

fn parse_bbox(s: &str) -> Result<[f64; 4], String> {
    let v: Vec<f64> = s.split(',').map(|p| p.trim().parse::<f64>()).collect::<Result<_, _>>().map_err(|_| "bbox must be west,south,east,north in degrees")?;
    let [w, so, e, n] = v[..] else { return Err("bbox must be west,south,east,north in degrees".into()) };
    if ![w, so, e, n].iter().all(|x| x.is_finite()) || !(-180.0..=180.0).contains(&w) || !(-180.0..=180.0).contains(&e) || !(-90.0..=90.0).contains(&so) || !(-90.0..=90.0).contains(&n) {
        return Err("bbox is out of range".into());
    }
    if w >= e || so >= n {
        return Err("bbox must have west < east and south < north".into());
    }
    if e - w > MAX_SPAN_DEG || n - so > MAX_SPAN_DEG {
        return Err(format!("bbox is too large (at most {MAX_SPAN_DEG} degrees on a side); zoom in"));
    }
    Ok([w, so, e, n])
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

fn https_only(v: Option<&str>) -> Option<String> {
    v.filter(|u| u.starts_with("https://")).map(str::to_string)
}

fn enc(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// Turn one STAC feature into the page/agent scene shape.
fn scene_from(f: &Value, source: &str, k: &Kind, cfg: &Config) -> Option<Value> {
    let id = f.get("id")?.as_str()?;
    let p = f.get("properties")?;
    let assets = f.get("assets").cloned().unwrap_or(json!({}));
    let href = |name: &str| assets.get(name).and_then(|a| a.get("href")).and_then(Value::as_str);
    let (collection, item_url, browser) = if source == "pc" {
        (k.pc, format!("{}/collections/{}/items/{}", cfg.pc_stac, k.pc, id),
         format!("https://planetarycomputer.microsoft.com/explore?c={}&i={}", enc(k.pc), enc(id)))
    } else {
        let c = k.es.unwrap_or(k.pc);
        (c, format!("{}/collections/{}/items/{}", cfg.es_stac, c, id),
         format!("https://radiantearth.github.io/stac-browser/#/external/{}/collections/{}/items/{}", cfg.es_stac.trim_start_matches("https://"), c, id))
    };
    let (thumbnail, tiles, cog) = if source == "pc" {
        let tiles = href("tilejson").filter(|h| h.starts_with(&cfg.pc_data) && h.contains("/item/tilejson.json?"))
            .map(|h| h.replacen("/item/tilejson.json?", "/item/tiles/WebMercatorQuad/{z}/{x}/{y}@1x.png?", 1));
        let thumb = https_only(href("thumbnail")).or_else(|| {
            href("rendered_preview").filter(|h| h.starts_with(&cfg.pc_data)).map(|h| format!("{h}&max_size=256"))
        });
        (thumb, tiles, None)
    } else {
        // Earth Search: only HTTPS-readable assets are usable from a browser; the visual COG is drawn by a public titiler.
        let cog = https_only(href("visual")).filter(|_| k.id == "s2" || k.id == "naip");
        let tiles = cog.as_ref().map(|c| format!("{}/cog/tiles/WebMercatorQuad/{{z}}/{{x}}/{{y}}?url={}&tilesize=256", cfg.titiler, enc(c)));
        (https_only(href("thumbnail")), tiles, cog)
    };
    Some(json!({
        "id": id,
        "source": source,
        "collection": collection,
        "kind": k.id,
        "datetime": p.get("datetime").and_then(Value::as_str),
        "platform": p.get("platform").and_then(Value::as_str),
        "cloud_cover": p.get("eo:cloud_cover").and_then(Value::as_f64),
        "gsd": p.get("gsd").and_then(Value::as_f64),
        "sar": if k.id == "s1" { json!({
            "mode": p.get("sar:instrument_mode"), "polarizations": p.get("sar:polarizations"),
            "orbit_state": p.get("sat:orbit_state") }) } else { Value::Null },
        "bbox": f.get("bbox"),
        "geometry": f.get("geometry"),
        "thumbnail": thumbnail,
        "tiles": tiles,
        "cog": cog,
        "stac_item": item_url,
        "browser": browser,
    }))
}

fn stac_post(app: &App, base: &str, body: &Value, key: Option<&str>) -> Result<Value, String> {
    let url = format!("{base}/search");
    let mut req = app.agent.post(&url).header("Accept", "application/geo+json, application/json");
    if let Some(k) = key {
        req = req.header("Ocp-Apim-Subscription-Key", k);
    }
    let mut res = req.send_json(body).map_err(|e| match e {
        ureq::Error::StatusCode(c) => format!("the archive answered HTTP {c}"),
        _ => "the archive could not be reached".to_string(),
    })?;
    res.body_mut().read_json::<Value>().map_err(|_| "the archive sent an unreadable response".to_string())
}

/// Optional Planetary Computer key (raises rate limits); looked up at most every 5 minutes. Never logged or returned.
fn pc_key(app: &App) -> Option<String> {
    let mut g = app.pc_key.lock().unwrap();
    if let Some((at, v)) = g.as_ref() {
        if at.elapsed() < Duration::from_secs(300) {
            return v.clone();
        }
    }
    let v = osnt_common::secret("PC_SDK_SUBSCRIPTION_KEY");
    *g = Some((Instant::now(), v.clone()));
    v
}

async fn search(State(app): State<Shared>, Query(q): Query<HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let get = |k: &str| q.get(k).map(|s| s.trim()).filter(|s| !s.is_empty());
    let kd = kind(get("kind").or(get("collection")).unwrap_or("s2")).ok_or_else(|| bad("kind must be one of s2, s1, landsat, naip"))?;
    let source = match get("source").unwrap_or("pc") {
        "pc" => "pc",
        "es" => "es",
        _ => return Err(bad("source must be pc (Planetary Computer) or es (Earth Search)")),
    };
    let bbox = parse_bbox(get("bbox").ok_or_else(|| bad("bbox is required: west,south,east,north"))?).map_err(bad)?;
    let default_start = if kd.id == "naip" { "2015-01-01".to_string() } else { date_ago(45) };
    let start = get("start").map(str::to_string).unwrap_or(default_start);
    let end = get("end").map(str::to_string).unwrap_or_else(|| date_ago(0));
    if !valid_date(&start) || !valid_date(&end) || start > end {
        return Err(bad("start and end must be YYYY-MM-DD dates with start <= end"));
    }
    let cloud: Option<f64> = match get("cloud") {
        Some(c) => Some(c.parse::<f64>().ok().filter(|v| (0.0..=100.0).contains(v)).ok_or_else(|| bad("cloud must be 0-100"))?),
        None => None,
    };
    let limit: usize = get("limit").and_then(|l| l.parse().ok()).unwrap_or(24usize).clamp(1, 50);
    let collection = if source == "pc" { kd.pc } else { kd.es.ok_or_else(|| bad("not available on this source"))? };
    let mut body = json!({
        "collections": [collection], "bbox": bbox, "limit": limit,
        "datetime": format!("{start}T00:00:00Z/{end}T23:59:59Z"),
        "sortby": [{ "field": if source == "es" { "properties.datetime" } else { "datetime" }, "direction": "desc" }],
    });
    if let (true, Some(c)) = (kd.optical, cloud) {
        body["query"] = json!({ "eo:cloud_cover": { "lt": c } });
    }
    let base = if source == "pc" { app.cfg.pc_stac.clone() } else { app.cfg.es_stac.clone() };
    let cache_key = format!("search|{base}|{body}");
    let raw = if let Some(hit) = app.cache.get(&cache_key, SEARCH_TTL) {
        serde_json::from_slice::<Value>(&hit).ok()
    } else {
        None
    };
    let raw = match raw {
        Some(v) => v,
        None => {
            let app2 = app.clone();
            let b = base.clone();
            let body2 = body.clone();
            let v = tokio::task::spawn_blocking(move || {
                let key = if app2.cfg.pc_stac == b { pc_key(&app2) } else { None };
                stac_post(&app2, &b, &body2, key.as_deref())
            })
            .await
            .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, e))?;
            app.cache.put(&cache_key, v.to_string().as_bytes());
            v
        }
    };
    let feats = raw.get("features").and_then(Value::as_array).cloned().unwrap_or_default();
    let scenes: Vec<Value> = feats.iter().filter_map(|f| scene_from(f, source, kd, &app.cfg)).collect();
    let matched = raw.pointer("/context/matched").or_else(|| raw.get("numberMatched")).cloned();
    Ok(Json(json!({
        "source": source, "kind": kd.id, "collection": collection, "bbox": bbox, "start": start, "end": end,
        "matched": matched, "count": scenes.len(), "scenes": scenes,
        "attribution": kd.note,
        "tiles_available": scenes.iter().any(|s| s["tiles"].is_string()),
    })))
}

async fn sources() -> Json<Value> {
    Json(json!({
        "sources": [
            { "id": "pc", "name": "Microsoft Planetary Computer", "auth": "none (optional free key raises limits)", "map_tiles": true,
              "note": "STAC search plus a hosted tile API: every scene can be drawn on the map, including Sentinel-1 radar." },
            { "id": "es", "name": "Element 84 Earth Search (AWS)", "auth": "none", "map_tiles": "Sentinel-2 and NAIP only (via a public titiler)",
              "note": "Open STAC on AWS. Good as a second opinion on what exists; Sentinel-1 and Landsat assets are requester-pays so only metadata is available." },
        ],
        "kinds": KINDS.iter().map(|k| json!({ "id": k.id, "label": k.label, "cloud_filter": k.optical, "pc": k.pc, "es": k.es, "note": k.note })).collect::<Vec<_>>(),
    }))
}

async fn tools() -> Json<Value> {
    Json(json!([
        { "name": "satellite_search",
          "description": "Search free satellite archives for scenes covering a bounding box and date range. Returns scene metadata (id, UTC acquisition time, platform, cloud cover, footprint, thumbnail and STAC links), no image bytes. kind: s2 = Sentinel-2 optical 10 m, s1 = Sentinel-1 radar (works through cloud and at night), landsat = Landsat 8/9 30 m, naip = US aerial 0.6 m. bbox is west,south,east,north in degrees (at most 12 degrees wide). Dates are YYYY-MM-DD. Newest scenes first.",
          "method": "GET", "path": "api/search",
          "parameters": { "type": "object", "properties": {
              "bbox": { "type": "string", "description": "west,south,east,north, for example 30.4,50.3,30.7,50.5" },
              "start": { "type": "string", "description": "YYYY-MM-DD (default 45 days ago)" },
              "end": { "type": "string", "description": "YYYY-MM-DD (default today)" },
              "kind": { "type": "string", "enum": ["s2", "s1", "landsat", "naip"] },
              "cloud": { "type": "number", "description": "maximum cloud cover percent (optical only)" },
              "source": { "type": "string", "enum": ["pc", "es"], "description": "pc = Planetary Computer (default), es = Earth Search" },
              "limit": { "type": "integer", "description": "1-50, default 24" } }, "required": ["bbox"] } },
        { "name": "satellite_sources",
          "description": "Describe the satellite sources and scene kinds this plugin can search, with resolution, revisit and licence notes.",
          "method": "GET", "path": "api/sources", "parameters": { "type": "object", "properties": {} } }
    ]))
}

async fn page() -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], PAGE).into_response()
}

pub fn app(cfg: Config, state_dir: PathBuf) -> Router {
    let st = Arc::new(App {
        agent: osnt_common::http_agent(UA),
        cfg,
        cache: cache::DiskCache::new(state_dir.join("cache"), 8 * 1024 * 1024),
        pc_key: Mutex::new(None),
    });
    Router::new().route("/", get(page)).route("/tools", get(tools)).route("/api/sources", get(sources)).route("/api/search", get(search)).with_state(st)
}

#[tokio::main]
async fn main() {
    let addr: SocketAddr = env::var("OSNT_SATELLITE_BIND").unwrap_or_else(|_| "127.0.0.1:8123".into()).parse().expect("bind addr");
    let state = PathBuf::from(env::var("OSNT_SATELLITE_STATE").unwrap_or_else(|_| env::temp_dir().join("osnt-satellite").to_string_lossy().into()));
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("satellite plugin on http://{addr}");
    axum::serve(listener, app(Config::from_env(), state)).await.expect("serve");
}

#[cfg(test)]
mod tests;

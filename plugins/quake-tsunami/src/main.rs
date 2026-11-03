//! Earthquakes and tsunami messages. On-demand reads of USGS (feeds and ComCat FDSN), EMSC (FDSN) and the
//! tsunami.gov PTWC/NTWC Atom bulletins, normalised into one event shape. Nothing is mirrored: small responses are
//! cached briefly under the state dir. Listens on loopback only; the hub reverse-proxies it at /p/quake-tsunami/.

mod cache;
mod tsunami;
mod util;

use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Query, State},
    http::header,
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::{Value, json};

use util::{ApiError, Upstream, bad, enc, iso, now_secs, parse_iso, upstream_err, valid_date, ymd};

const PAGE: &str = include_str!("../assets/index.html");
const UA: &str = "osnt-quake-tsunami/0.1 (+https://github.com/ogden-marrow/osnt-hub)";
const FEED_TTL: Duration = Duration::from_secs(120);
const QUERY_TTL: Duration = Duration::from_secs(300);
const BULLETIN_TTL: Duration = Duration::from_secs(180);

#[derive(Clone)]
pub struct Config {
    /// Base of the USGS summary feeds, no trailing slash.
    pub usgs_feed: String,
    pub usgs_fdsn: String,
    pub emsc_fdsn: String,
    /// Tsunami Atom files live at `<base>/<CENTRE>Atom.xml`.
    pub tsunami_base: String,
}

impl Config {
    fn from_env() -> Self {
        let get = |k: &str, d: &str| env::var(k).unwrap_or_else(|_| d.to_string());
        Config {
            usgs_feed: get("OSNT_QUAKE_USGS_FEED", "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary"),
            usgs_fdsn: get("OSNT_QUAKE_USGS_FDSN", "https://earthquake.usgs.gov/fdsnws/event/1/query"),
            emsc_fdsn: get("OSNT_QUAKE_EMSC_FDSN", "https://www.seismicportal.eu/fdsnws/event/1/query"),
            tsunami_base: get("OSNT_QUAKE_TSUNAMI", "https://www.tsunami.gov/events/xml"),
        }
    }
}

pub struct App {
    up: Upstream,
    cfg: Config,
}
type Shared = Arc<App>;

const FEED_LEVELS: [&str; 4] = ["significant", "4.5", "2.5", "1.0"];
const FEED_PERIODS: [&str; 4] = ["hour", "day", "week", "month"];

fn f64_of(v: &Value) -> Option<f64> {
    v.as_f64().filter(|x| x.is_finite())
}

/// One USGS GeoJSON feature into the common event shape.
pub fn usgs_event(f: &Value) -> Option<Value> {
    let p = f.get("properties")?;
    let c = f.pointer("/geometry/coordinates")?.as_array()?;
    let (lon, lat) = (f64_of(c.first()?)?, f64_of(c.get(1)?)?);
    let id = f.get("id").and_then(Value::as_str)?;
    let t = p.get("time").and_then(Value::as_i64)?;
    Some(json!({
        "id": format!("usgs:{id}"), "source": "usgs", "time": iso(t / 1000), "time_ms": t,
        "mag": p.get("mag").and_then(f64_of), "mag_type": p.get("magType").and_then(Value::as_str),
        "place": p.get("place").and_then(Value::as_str), "lat": lat, "lon": lon,
        "depth_km": c.get(2).and_then(f64_of),
        "felt": p.get("felt").and_then(Value::as_i64), "mmi": p.get("mmi").and_then(f64_of), "cdi": p.get("cdi").and_then(f64_of),
        "alert": p.get("alert").and_then(Value::as_str), "tsunami": p.get("tsunami").and_then(Value::as_i64).map(|x| x == 1).unwrap_or(false),
        "sig": p.get("sig").and_then(Value::as_i64), "status": p.get("status").and_then(Value::as_str),
        "url": p.get("url").and_then(Value::as_str).filter(|u| u.starts_with("https://earthquake.usgs.gov/")),
    }))
}

/// One EMSC (SeismicPortal) GeoJSON feature. Its depth sits in properties and as a negative z coordinate.
pub fn emsc_event(f: &Value) -> Option<Value> {
    let p = f.get("properties")?;
    let (lat, lon) = (p.get("lat").and_then(f64_of).or_else(|| f.pointer("/geometry/coordinates/1").and_then(f64_of))?, p.get("lon").and_then(f64_of).or_else(|| f.pointer("/geometry/coordinates/0").and_then(f64_of))?);
    let unid = p.get("unid").and_then(Value::as_str).or_else(|| f.get("id").and_then(Value::as_str))?;
    let t = parse_iso(p.get("time").and_then(Value::as_str)?)?;
    let sid = p.get("source_id").and_then(Value::as_str).unwrap_or("");
    let link = if !sid.is_empty() && sid.bytes().all(|b| b.is_ascii_digit()) {
        Some(format!("https://www.emsc-csem.org/Earthquake_information/earthquake.php?id={sid}"))
    } else {
        None
    };
    Some(json!({
        "id": format!("emsc:{unid}"), "source": "emsc", "time": iso(t), "time_ms": t * 1000,
        "mag": p.get("mag").and_then(f64_of), "mag_type": p.get("magtype").and_then(Value::as_str),
        "place": p.get("flynn_region").and_then(Value::as_str), "lat": lat, "lon": lon,
        "depth_km": p.get("depth").and_then(f64_of), "felt": Value::Null, "mmi": Value::Null, "cdi": Value::Null,
        "alert": Value::Null, "tsunami": false, "sig": Value::Null, "status": p.get("evtype").and_then(Value::as_str).map(emsc_evtype),
        "url": link,
    }))
}

/// EMSC event-type codes (ke = known earthquake, ki = induced, kr = rockburst, ...) as words.
pub fn emsc_evtype(code: &str) -> &str {
    match code {
        "ke" => "earthquake",
        "se" => "suspected earthquake",
        "ki" => "induced event",
        "sm" => "suspected mine blast",
        "km" => "mine blast",
        "kr" => "rockburst",
        "kx" => "explosion",
        other => other,
    }
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct Filter {
    pub minmag: Option<f64>,
    pub maxmag: Option<f64>,
    pub mindepth: Option<f64>,
    pub maxdepth: Option<f64>,
}

fn num(q: &HashMap<String, String>, k: &str, lo: f64, hi: f64) -> Result<Option<f64>, ApiError> {
    match q.get(k).map(|s| s.trim()).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => s.parse::<f64>().ok().filter(|v| v.is_finite() && (lo..=hi).contains(v)).map(Some).ok_or_else(|| bad(format!("{k} must be a number between {lo} and {hi}"))),
    }
}

pub fn parse_filter(q: &HashMap<String, String>) -> Result<Filter, ApiError> {
    let f = Filter { minmag: num(q, "minmag", -2.0, 10.0)?, maxmag: num(q, "maxmag", -2.0, 10.0)?, mindepth: num(q, "mindepth", 0.0, 800.0)?, maxdepth: num(q, "maxdepth", 0.0, 800.0)? };
    if matches!((f.minmag, f.maxmag), (Some(a), Some(b)) if a > b) || matches!((f.mindepth, f.maxdepth), (Some(a), Some(b)) if a > b) {
        return Err(bad("a minimum is larger than its maximum"));
    }
    Ok(f)
}

pub fn passes(e: &Value, f: &Filter) -> bool {
    let mag = e["mag"].as_f64();
    let depth = e["depth_km"].as_f64();
    f.minmag.is_none_or(|m| mag.is_some_and(|x| x >= m))
        && f.maxmag.is_none_or(|m| mag.is_some_and(|x| x <= m))
        && f.mindepth.is_none_or(|m| depth.is_some_and(|x| x >= m))
        && f.maxdepth.is_none_or(|m| depth.is_some_and(|x| x <= m))
}

fn events_of(source: &str, v: &Value) -> Vec<Value> {
    let feats = v.get("features").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut out: Vec<Value> = feats.iter().filter_map(|f| if source == "emsc" { emsc_event(f) } else { usgs_event(f) }).collect();
    out.sort_by(|a, b| b["time_ms"].as_i64().cmp(&a["time_ms"].as_i64()));
    out
}

fn shared_err(e: String) -> ApiError {
    upstream_err(e)
}

async fn blocking_json(app: &Shared, url: String, ttl: Duration) -> Result<(Value, bool), ApiError> {
    let app = app.clone();
    tokio::task::spawn_blocking(move || app.up.get_json(&url, ttl)).await.map_err(|e| ApiError(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?.map_err(shared_err)
}

fn limit_of(q: &HashMap<String, String>, default: usize) -> Result<usize, ApiError> {
    match q.get("limit").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        None => Ok(default),
        Some(s) => s.parse::<usize>().ok().filter(|n| (1..=500).contains(n)).ok_or_else(|| bad("limit must be 1-500")),
    }
}

fn source_of(q: &HashMap<String, String>) -> Result<&'static str, ApiError> {
    match q.get("source").map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("usgs") {
        "usgs" => Ok("usgs"),
        "emsc" => Ok("emsc"),
        _ => Err(bad("source must be usgs or emsc")),
    }
}

/// Recent events: USGS summary feeds (significant, 4.5+, 2.5+, 1.0+ over hour/day/week/month), or EMSC's latest.
async fn recent(State(app): State<Shared>, Query(q): Query<HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let source = source_of(&q)?;
    let filter = parse_filter(&q)?;
    let limit = limit_of(&q, 300)?;
    let (events, stale, feed) = if source == "usgs" {
        let level = q.get("level").map(String::as_str).unwrap_or("2.5");
        let period = q.get("period").map(String::as_str).unwrap_or("day");
        if !FEED_LEVELS.contains(&level) || !FEED_PERIODS.contains(&period) {
            return Err(bad("level must be one of significant, 4.5, 2.5, 1.0 and period one of hour, day, week, month"));
        }
        let name = format!("{level}_{period}");
        let (v, stale) = blocking_json(&app, format!("{}/{name}.geojson", app.cfg.usgs_feed), FEED_TTL).await?;
        (events_of("usgs", &v), stale, name)
    } else {
        let hours: i64 = match q.get("period").map(String::as_str).unwrap_or("day") {
            "hour" => 1,
            "day" => 24,
            "week" => 168,
            _ => return Err(bad("EMSC period must be hour, day or week")),
        };
        let start = iso(now_secs() - hours * 3600);
        let mag = filter.minmag.map(|m| format!("&minmag={m}")).unwrap_or_default();
        // Round the start time to the minute-ish so the cache key is stable within the TTL.
        let start = &start[..16];
        let url = format!("{}?format=json&orderby=time&limit={limit}&start={}{mag}", app.cfg.emsc_fdsn, enc(&format!("{start}:00")));
        let (v, stale) = blocking_json(&app, url, FEED_TTL).await?;
        (events_of("emsc", &v), stale, format!("emsc_{hours}h"))
    };
    let total = events.len();
    let events: Vec<Value> = events.into_iter().filter(|e| passes(e, &filter)).take(limit).collect();
    Ok(Json(json!({ "source": source, "feed": feed, "total_in_feed": total, "count": events.len(), "stale": stale, "events": events,
        "attribution": attribution(source) })))
}

fn attribution(source: &str) -> &'static str {
    if source == "emsc" {
        "Earthquake data: EMSC (European-Mediterranean Seismological Centre), https://www.emsc-csem.org, via its FDSN web service. Contributing agencies own their solutions; see EMSC's data policy."
    } else {
        "Earthquake data: U.S. Geological Survey (public domain), https://earthquake.usgs.gov. Not an official warning source."
    }
}

fn parse_point(q: &HashMap<String, String>) -> Result<Option<(f64, f64, f64)>, ApiError> {
    let (lat, lon, r) = (num(q, "lat", -90.0, 90.0)?, num(q, "lon", -180.0, 180.0)?, num(q, "radius_km", 1.0, 5000.0)?);
    match (lat, lon) {
        (Some(la), Some(lo)) => Ok(Some((la, lo, r.unwrap_or(300.0)))),
        (None, None) => Ok(None),
        _ => Err(bad("give both lat and lon")),
    }
}

fn parse_bbox(q: &HashMap<String, String>) -> Result<Option<[f64; 4]>, ApiError> {
    let Some(s) = q.get("bbox").map(|s| s.trim()).filter(|s| !s.is_empty()) else { return Ok(None) };
    let v: Vec<f64> = s.split(',').map(|p| p.trim().parse::<f64>()).collect::<Result<_, _>>().map_err(|_| bad("bbox must be west,south,east,north in degrees"))?;
    let [w, so, e, n] = v[..] else { return Err(bad("bbox must be west,south,east,north in degrees")) };
    if ![w, so, e, n].iter().all(|x| x.is_finite()) || !(-180.0..=180.0).contains(&w) || !(-180.0..=180.0).contains(&e) || !(-90.0..=90.0).contains(&so) || !(-90.0..=90.0).contains(&n) || w >= e || so >= n {
        return Err(bad("bbox is out of range (west < east, south < north)"));
    }
    Ok(Some([w, so, e, n]))
}

/// Historical query for an area and time window ("what shook here last week").
async fn search(State(app): State<Shared>, Query(q): Query<HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let source = source_of(&q)?;
    let filter = parse_filter(&q)?;
    let limit = limit_of(&q, 200)?;
    let point = parse_point(&q)?;
    let bbox = parse_bbox(&q)?;
    if point.is_some() && bbox.is_some() {
        return Err(bad("use either lat/lon/radius_km or bbox, not both"));
    }
    let now = now_secs();
    let days: Option<f64> = num(&q, "days", 0.01, 3650.0)?;
    let get = |k: &str| q.get(k).map(|s| s.trim()).filter(|s| !s.is_empty());
    let (start, end) = match (get("start"), get("end"), days) {
        (None, None, d) => (ymd(now - (d.unwrap_or(7.0) * 86_400.0) as i64), None),
        (s, e, _) => {
            for d in [s, e].into_iter().flatten() {
                if !valid_date(d) {
                    return Err(bad("start and end must be YYYY-MM-DD dates"));
                }
            }
            (s.map(str::to_string).unwrap_or_else(|| ymd(now - 7 * 86_400)), e.map(str::to_string))
        }
    };
    if end.as_deref().is_some_and(|e| e < start.as_str()) {
        return Err(bad("end is before start"));
    }
    let mut url = if source == "usgs" {
        format!("{}?format=geojson&orderby=time&limit={limit}&starttime={start}", app.cfg.usgs_fdsn)
    } else {
        format!("{}?format=json&orderby=time&limit={limit}&start={start}", app.cfg.emsc_fdsn)
    };
    if let Some(e) = &end {
        // The end date is inclusive for people; the services treat a bare date as 00:00.
        let next = ymd(parse_iso(e).unwrap_or(0) + 86_400);
        url.push_str(&format!("&{}={next}", if source == "usgs" { "endtime" } else { "end" }));
    }
    let (min_k, max_k) = if source == "usgs" { ("minmagnitude", "maxmagnitude") } else { ("minmag", "maxmag") };
    if let Some(m) = filter.minmag {
        url.push_str(&format!("&{min_k}={m}"));
    }
    if let Some(m) = filter.maxmag {
        url.push_str(&format!("&{max_k}={m}"));
    }
    if let Some(m) = filter.mindepth {
        url.push_str(&format!("&mindepth={m}"));
    }
    if let Some(m) = filter.maxdepth {
        url.push_str(&format!("&maxdepth={m}"));
    }
    if let Some((la, lo, r)) = point {
        if source == "usgs" {
            url.push_str(&format!("&latitude={la}&longitude={lo}&maxradiuskm={r}"));
        } else {
            url.push_str(&format!("&lat={la}&lon={lo}&maxradius={:.3}", r / 111.195));
        }
    }
    if let Some([w, s, e, n]) = bbox {
        if source == "usgs" {
            url.push_str(&format!("&minlongitude={w}&minlatitude={s}&maxlongitude={e}&maxlatitude={n}"));
        } else {
            url.push_str(&format!("&minlon={w}&minlat={s}&maxlon={e}&maxlat={n}"));
        }
    }
    let (v, stale) = blocking_json(&app, url, QUERY_TTL).await?;
    let events: Vec<Value> = events_of(source, &v).into_iter().filter(|e| passes(e, &filter)).take(limit).collect();
    let biggest = events.iter().filter_map(|e| e["mag"].as_f64()).fold(None, |a: Option<f64>, m| Some(a.map_or(m, |x| x.max(m))));
    Ok(Json(json!({ "source": source, "start": start, "end": end, "count": events.len(), "largest_mag": biggest, "stale": stale, "events": events,
        "area": point.map(|(la, lo, r)| json!({ "lat": la, "lon": lo, "radius_km": r })).or(bbox.map(|b| json!({ "bbox": b }))),
        "attribution": attribution(source) })))
}

/// Latest bulletins from the two US tsunami warning centres (PTWC Hawaii, NTWC Alaska).
async fn tsunami_bulletins(State(app): State<Shared>) -> Result<Json<Value>, ApiError> {
    let mut bulletins = Vec::new();
    let mut errors = Vec::new();
    let mut stale = false;
    let now = now_secs();
    for centre in ["PHEB", "PAAQ"] {
        let url = format!("{}/{centre}Atom.xml", app.cfg.tsunami_base);
        let a = app.clone();
        let r = tokio::task::spawn_blocking(move || a.up.get(&url, BULLETIN_TTL)).await.map_err(|e| ApiError(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        match r {
            Ok(f) => {
                stale |= f.stale;
                bulletins.extend(tsunami::parse_atom(&String::from_utf8_lossy(&f.body), centre, now));
            }
            Err(e) => errors.push(format!("{centre}: {e}")),
        }
    }
    if bulletins.is_empty() && errors.len() == 2 {
        return Err(upstream_err(errors.join("; ")));
    }
    bulletins.sort_by(|a, b| b["issued_ms"].as_i64().cmp(&a["issued_ms"].as_i64()));
    let current = bulletins.iter().filter(|b| b["current"].as_bool() == Some(true)).count();
    Ok(Json(json!({
        "count": bulletins.len(), "current": current, "stale": stale, "errors": errors, "bulletins": bulletins,
        "attribution": "Tsunami messages: NOAA/NWS Pacific Tsunami Warning Center and National Tsunami Warning Center, https://www.tsunami.gov (public domain). This page is NOT an official warning channel: follow local authorities.",
    })))
}

async fn sources() -> Json<Value> {
    Json(json!({
        "feeds": { "levels": FEED_LEVELS, "periods": FEED_PERIODS },
        "sources": [
            { "id": "usgs", "name": "USGS Earthquake Hazards Program", "licence": "US Government work, public domain", "url": "https://earthquake.usgs.gov" },
            { "id": "emsc", "name": "EMSC (SeismicPortal FDSN)", "licence": "Attribute EMSC; contributing agencies keep rights to their solutions", "url": "https://www.emsc-csem.org" },
            { "id": "tsunami", "name": "NOAA NWS tsunami warning centres", "licence": "US Government work, public domain", "url": "https://www.tsunami.gov" },
        ],
    }))
}

async fn tools() -> Json<Value> {
    let filters = json!({
        "minmag": { "type": "number", "description": "minimum magnitude" }, "maxmag": { "type": "number", "description": "maximum magnitude" },
        "mindepth": { "type": "number", "description": "minimum depth in km" }, "maxdepth": { "type": "number", "description": "maximum depth in km" },
    });
    let mut recent_props = json!({
        "source": { "type": "string", "enum": ["usgs", "emsc"], "description": "default usgs" },
        "level": { "type": "string", "enum": FEED_LEVELS, "description": "USGS feed: significant, 4.5, 2.5 (default) or 1.0 and up" },
        "period": { "type": "string", "enum": FEED_PERIODS, "description": "hour, day (default), week or month (EMSC: hour, day, week)" },
        "limit": { "type": "integer", "description": "1-500, default 300" },
    });
    let mut search_props = json!({
        "lat": { "type": "number" }, "lon": { "type": "number" }, "radius_km": { "type": "number", "description": "1-5000, default 300" },
        "bbox": { "type": "string", "description": "west,south,east,north (instead of lat/lon)" },
        "start": { "type": "string", "description": "YYYY-MM-DD" }, "end": { "type": "string", "description": "YYYY-MM-DD, inclusive" },
        "days": { "type": "number", "description": "look back this many days when start/end are omitted (default 7)" },
        "source": { "type": "string", "enum": ["usgs", "emsc"] }, "limit": { "type": "integer", "description": "1-500, default 200" },
    });
    for (k, v) in filters.as_object().unwrap() {
        recent_props[k] = v.clone();
        search_props[k] = v.clone();
    }
    Json(json!([
        { "name": "quake_recent", "description": "Recent earthquakes from the USGS summary feeds (or EMSC): time, magnitude, depth, place, coordinates, felt-report count, tsunami flag and a link to the event page. No credentials involved.",
          "method": "GET", "path": "api/recent", "parameters": { "type": "object", "properties": recent_props } },
        { "name": "quake_search", "description": "Historical earthquake query for an area and time window (what shook here last week). Give lat/lon with radius_km, or a bbox, plus start/end dates or days.",
          "method": "GET", "path": "api/search", "parameters": { "type": "object", "properties": search_props } },
        { "name": "tsunami_bulletins", "description": "Latest tsunami messages from the Pacific (PTWC) and National (NTWC) tsunami warning centres: category (Information/Advisory/Watch/Warning), region, magnitude, issue time, and links to the bulletin text. Informational only, not an official warning channel.",
          "method": "GET", "path": "api/tsunami", "parameters": { "type": "object", "properties": {} } },
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
        .route("/api/sources", get(sources))
        .route("/api/recent", get(recent))
        .route("/api/search", get(search))
        .route("/api/tsunami", get(tsunami_bulletins))
        .with_state(st)
}

#[tokio::main]
async fn main() {
    let addr: SocketAddr = env::var("OSNT_QUAKE_BIND").unwrap_or_else(|_| "127.0.0.1:8153".into()).parse().expect("bind addr");
    let state = PathBuf::from(env::var("OSNT_QUAKE_STATE").unwrap_or_else(|_| env::temp_dir().join("osnt-quake-tsunami").to_string_lossy().into()));
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("quake-tsunami plugin on http://{addr}");
    axum::serve(listener, app(Config::from_env(), state)).await.expect("serve");
}

#[cfg(test)]
mod tests;

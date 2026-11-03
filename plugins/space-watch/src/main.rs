//! Launches and orbital objects. On demand: Launch Library 2 (The Space Devs) for launches and pads, CelesTrak for
//! GP element sets and SATCAT catalog data. Nothing is mirrored; both services are rate limited, so responses are cached
//! for long periods and a cached copy is served when they are unreachable. Satellite passes are left to the `satellite`
//! and `doppler` plugins. Listens on loopback only; the hub reverse-proxies it at /p/space-watch/.

mod cache;
mod orbit;
mod util;

use std::{collections::HashMap, env, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::{Value, json};

use util::{ApiError, Upstream, bad, enc, now_secs, upstream_err};

const PAGE: &str = include_str!("../assets/index.html");
const UA: &str = "osnt-space-watch/0.1 (+https://github.com/ogden-marrow/osnt-hub)";
/// Launch Library 2 allows 15 anonymous requests an hour: refresh slowly.
const UPCOMING_TTL: Duration = Duration::from_secs(20 * 60);
const PREVIOUS_TTL: Duration = Duration::from_secs(60 * 60);
/// CelesTrak updates element sets about every 2 hours and asks clients not to poll faster.
const GP_TTL: Duration = Duration::from_secs(2 * 3600);
const SATCAT_TTL: Duration = Duration::from_secs(6 * 3600);
const LAUNCH_FETCH: usize = 40;

const GROUPS: [&str; 24] = [
    "stations", "last-30-days", "active", "visual", "weather", "noaa", "goes", "resource", "sarsat", "tdrss", "geo", "gps-ops", "glo-ops", "galileo", "beidou", "science", "geodetic",
    "engineering", "education", "military", "radar", "cubesat", "starlink", "oneweb",
];

#[derive(Clone)]
pub struct Config {
    /// Base like `https://ll.thespacedevs.com/2.2.0`.
    pub ll: String,
    /// `https://celestrak.org/NORAD/elements/gp.php`
    pub gp: String,
    /// `https://celestrak.org/satcat/records.php`
    pub satcat: String,
}

impl Config {
    fn from_env() -> Self {
        let get = |k: &str, d: &str| env::var(k).unwrap_or_else(|_| d.to_string());
        Config {
            ll: get("OSNT_SPACE_LL", "https://ll.thespacedevs.com/2.2.0"),
            gp: get("OSNT_SPACE_GP", "https://celestrak.org/NORAD/elements/gp.php"),
            satcat: get("OSNT_SPACE_SATCAT", "https://celestrak.org/satcat/records.php"),
        }
    }
}

pub struct App {
    up: Upstream,
    cfg: Config,
}
type Shared = Arc<App>;

fn param<'a>(q: &'a HashMap<String, String>, k: &str) -> Option<&'a str> {
    q.get(k).map(|s| s.trim()).filter(|s| !s.is_empty())
}

fn limit(q: &HashMap<String, String>, d: usize, max: usize) -> Result<usize, ApiError> {
    match param(q, "limit") {
        None => Ok(d),
        Some(s) => s.parse::<usize>().ok().filter(|n| (1..=max).contains(n)).ok_or_else(|| bad(format!("limit must be 1-{max}"))),
    }
}

async fn fetch_json(app: &Shared, url: String, ttl: Duration) -> Result<(Value, bool), ApiError> {
    let app = app.clone();
    tokio::task::spawn_blocking(move || app.up.get_json(&url, ttl)).await.map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?.map_err(|e| {
        // Both services answer plain text (not JSON) when they refuse a query.
        if e.contains("unexpected response") { upstream_err("the data service refused or could not parse this query") } else { upstream_err(e) }
    })
}

// ---- launches ----------------------------------------------------------------------------------------------------------

async fn launches(State(app): State<Shared>, Query(q): Query<HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let which = match param(&q, "which").unwrap_or("upcoming") {
        "upcoming" => "upcoming",
        "previous" => "previous",
        _ => return Err(bad("which must be upcoming or previous")),
    };
    let lim = limit(&q, 20, LAUNCH_FETCH)?;
    let needle = match param(&q, "q") {
        None => None,
        Some(s) if s.chars().count() <= 60 && !s.chars().any(char::is_control) => Some(s.to_lowercase()),
        Some(_) => return Err(bad("q must be at most 60 characters")),
    };
    // One canonical upstream request per list so repeated page loads share a single cached call.
    let url = format!("{}/launch/{which}/?limit={LAUNCH_FETCH}&mode=normal", app.cfg.ll);
    let (v, stale) = fetch_json(&app, url, if which == "upcoming" { UPCOMING_TTL } else { PREVIOUS_TTL }).await?;
    if v.get("results").is_none() {
        return Err(upstream_err("Launch Library answered without results (it may be rate limiting this plugin: 15 requests per hour)"));
    }
    let now = now_secs();
    let all: Vec<Value> = v["results"].as_array().cloned().unwrap_or_default().iter().filter_map(|l| orbit::launch(l, now)).collect();
    let status = param(&q, "status").map(str::to_lowercase);
    let mut list: Vec<Value> = all
        .into_iter()
        .filter(|l| needle.as_ref().is_none_or(|n| ["name", "provider", "mission", "pad", "rocket", "location"].iter().any(|k| l[*k].as_str().is_some_and(|s| s.to_lowercase().contains(n)))))
        .filter(|l| status.as_ref().is_none_or(|s| l["status_abbrev"].as_str().is_some_and(|a| a.eq_ignore_ascii_case(s)) || l["status"].as_str().is_some_and(|a| a.eq_ignore_ascii_case(s))))
        .collect();
    if which == "previous" {
        list.sort_by(|a, b| b["net"].as_str().cmp(&a["net"].as_str()));
    } else {
        list.sort_by(|a, b| a["net"].as_str().cmp(&b["net"].as_str()));
    }
    list.truncate(lim);
    Ok(Json(json!({ "which": which, "count": list.len(), "total_upstream": v["count"], "stale": stale, "launches": list, "attribution": LL_ATTR, "links": links() })))
}

const LL_ATTR: &str = "Launch data: Launch Library 2 by The Space Devs (https://thespacedevs.com), free tier, 15 requests per hour; schedules change often, treat times as estimates.";

fn links() -> Value {
    json!({ "passes_and_imagery": "/p/satellite/", "doppler": "/p/doppler/", "note": "Satellite pass prediction and tracking live in the satellite and doppler plugins." })
}

/// Launch sites derived from the upcoming list, with the next launch at each.
async fn pads(State(app): State<Shared>) -> Result<Json<Value>, ApiError> {
    let url = format!("{}/launch/upcoming/?limit={LAUNCH_FETCH}&mode=normal", app.cfg.ll);
    let (v, stale) = fetch_json(&app, url, UPCOMING_TTL).await?;
    let now = now_secs();
    let mut by: Vec<(String, Value)> = Vec::new();
    for l in v["results"].as_array().cloned().unwrap_or_default().iter().filter_map(|l| orbit::launch(l, now)) {
        let (Some(name), Some(_), Some(_)) = (l["pad"].as_str(), l["pad_lat"].as_f64(), l["pad_lon"].as_f64()) else { continue };
        match by.iter_mut().find(|(n, _)| n == name) {
            Some((_, p)) => p["launches"] = json!(p["launches"].as_u64().unwrap_or(0) + 1),
            None => by.push((name.to_string(), json!({ "pad": name, "lat": l["pad_lat"], "lon": l["pad_lon"], "location": l["location"], "country": l["country"], "launches": 1,
                "next": { "name": l["name"], "net": l["net"], "provider": l["provider"], "status": l["status"] } }))),
        }
    }
    Ok(Json(json!({ "stale": stale, "pads": by.into_iter().map(|x| x.1).collect::<Vec<_>>(), "attribution": LL_ATTR })))
}

// ---- orbital objects ---------------------------------------------------------------------------------------------------

fn valid_name(s: &str) -> bool {
    (2..=40).contains(&s.chars().count()) && s.chars().all(|c| c.is_ascii_alphanumeric() || " -_()./+".contains(c))
}

fn valid_intl(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 9 && b.len() <= 11 && b[..4].iter().all(u8::is_ascii_digit) && b[4] == b'-' && b[5..8].iter().all(u8::is_ascii_digit) && b[8..].iter().all(u8::is_ascii_uppercase)
}

pub struct Selector {
    /// CelesTrak query string fragment (already encoded), without FORMAT.
    pub query: String,
    pub single: bool,
}

pub fn selector(q: &HashMap<String, String>) -> Result<Selector, ApiError> {
    let chosen = ["catnr", "name", "group", "intl"].iter().filter(|k| param(q, k).is_some()).count();
    if chosen != 1 {
        return Err(bad("give exactly one of catnr (NORAD ID), name, group or intl (international designator such as 1998-067A)"));
    }
    if let Some(c) = param(q, "catnr") {
        if !(1..=9).contains(&c.len()) || !c.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad("catnr must be a NORAD catalog number (digits only)"));
        }
        return Ok(Selector { query: format!("CATNR={c}"), single: true });
    }
    if let Some(n) = param(q, "name") {
        if !valid_name(n) {
            return Err(bad("name must be 2-40 characters: letters, digits, space and - _ ( ) . / +"));
        }
        return Ok(Selector { query: format!("NAME={}", enc(n)), single: false });
    }
    if let Some(g) = param(q, "group") {
        let g = g.to_ascii_lowercase();
        if !GROUPS.contains(&g.as_str()) {
            return Err(bad(format!("group must be one of {}", GROUPS.join(", "))));
        }
        return Ok(Selector { query: format!("GROUP={g}"), single: false });
    }
    let i = param(q, "intl").unwrap_or("").to_ascii_uppercase();
    if !valid_intl(&i) {
        return Err(bad("intl must look like 1998-067A"));
    }
    Ok(Selector { query: format!("INTDES={i}"), single: true })
}

fn records(v: Value) -> Vec<Value> {
    v.as_array().cloned().unwrap_or_default()
}

/// Element sets plus catalog attributes (owner, launch, decay) for a selection.
async fn object(State(app): State<Shared>, Query(q): Query<HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let sel = selector(&q)?;
    let lim = limit(&q, if sel.single { 10 } else { 50 }, 200)?;
    let gp_url = format!("{}?{}&FORMAT=json", app.cfg.gp, sel.query);
    let sc_url = format!("{}?{}&FORMAT=json", app.cfg.satcat, sel.query);
    let gp = fetch_json(&app, gp_url, GP_TTL).await;
    let sc = fetch_json(&app, sc_url, SATCAT_TTL).await;
    // GP can legitimately be empty for decayed objects while SATCAT still knows them, and vice versa.
    if gp.is_err() && sc.is_err() {
        return Err(gp.err().unwrap());
    }
    let (gp, stale1) = gp.map(|(v, s)| (records(v), s)).unwrap_or((vec![], false));
    let (sc, stale2) = sc.map(|(v, s)| (records(v), s)).unwrap_or((vec![], false));
    let mut cat: HashMap<u64, Value> = sc.iter().filter_map(orbit::satcat_record).map(|r| (r["norad_id"].as_u64().unwrap_or(0), r)).collect();
    let mut out: Vec<Value> = gp.iter().filter_map(orbit::gp_record).map(|mut e| {
        e["catalog"] = cat.remove(&e["norad_id"].as_u64().unwrap_or(0)).unwrap_or(Value::Null);
        e
    }).collect();
    // Catalog-only hits (no current element set, typically decayed objects).
    for (_, c) in cat {
        out.push(json!({ "norad_id": c["norad_id"], "name": c["name"], "intl_designator": c["intl_designator"], "catalog": c, "no_elements": true }));
    }
    out.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    let total = out.len();
    out.truncate(lim);
    Ok(Json(json!({
        "query": sel.query, "total": total, "count": out.len(), "stale": stale1 || stale2, "objects": out,
        "links": links(), "attribution": CT_ATTR,
    })))
}

const CT_ATTR: &str = "Orbital data: CelesTrak (https://celestrak.org, Dr T.S. Kelso), from US Space Force 18th SDS data; element sets update about every 2 hours. Derived apogee/perigee are two-body estimates from mean elements.";

/// Recently launched objects (SATCAT group last-30-days) or the lowest-perigee active objects.
async fn recent(State(app): State<Shared>, Query(q): Query<HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let which = param(&q, "list").unwrap_or("launched");
    let lim = limit(&q, 50, 300)?;
    match which {
        "launched" => {
            let url = format!("{}?GROUP=last-30-days&FORMAT=json", app.cfg.satcat);
            let (v, stale) = fetch_json(&app, url, SATCAT_TTL).await?;
            let mut list: Vec<Value> = records(v).iter().filter_map(orbit::satcat_record).collect();
            list.sort_by(|a, b| b["launch_date"].as_str().cmp(&a["launch_date"].as_str()).then(b["norad_id"].as_u64().cmp(&a["norad_id"].as_u64())));
            let total = list.len();
            list.truncate(lim);
            Ok(Json(json!({ "list": "launched", "total": total, "count": list.len(), "stale": stale, "objects": list, "attribution": CT_ATTR })))
        }
        "decaying" => {
            let max_perigee: f64 = match param(&q, "max_perigee_km") {
                None => 300.0,
                Some(s) => s.parse().ok().filter(|v: &f64| v.is_finite() && (100.0..=2000.0).contains(v)).ok_or_else(|| bad("max_perigee_km must be 100-2000"))?,
            };
            let url = format!("{}?GROUP=active&FORMAT=json", app.cfg.gp);
            let (v, stale) = fetch_json(&app, url, GP_TTL).await?;
            let mut list: Vec<Value> = records(v).iter().filter_map(orbit::gp_record).filter(|e| e["perigee_km"].as_f64().is_some_and(|p| (100.0..=max_perigee).contains(&p))).collect();
            list.sort_by(|a, b| a["perigee_km"].as_f64().partial_cmp(&b["perigee_km"].as_f64()).unwrap_or(std::cmp::Ordering::Equal));
            let total = list.len();
            list.truncate(lim);
            Ok(Json(json!({
                "list": "decaying", "max_perigee_km": max_perigee, "total": total, "count": list.len(), "stale": stale, "objects": list,
                "note": "Lowest-perigee objects in the active catalog, a drag-exposure ranking from mean elements, NOT a reentry prediction. Official reentry predictions come from Space-Track TIP messages and ESA.",
                "attribution": CT_ATTR,
            })))
        }
        _ => Err(bad("list must be launched or decaying")),
    }
}

async fn sources() -> Json<Value> {
    Json(json!({ "groups": GROUPS, "sources": [
        { "id": "ll2", "name": "Launch Library 2 (The Space Devs)", "url": "https://thespacedevs.com", "limit": "15 requests/hour anonymous" },
        { "id": "celestrak", "name": "CelesTrak GP and SATCAT", "url": "https://celestrak.org", "limit": "element sets refresh about every 2 hours" } ],
        "links": links() }))
}

async fn tools() -> Json<Value> {
    Json(json!([
        { "name": "space_launches", "description": "Upcoming or previous orbital launches from Launch Library 2: name, status, NET time and window, provider, rocket, mission and orbit, launch pad with coordinates, webcast flag. Free tier is 15 requests per hour so results are cached for many minutes.",
          "method": "GET", "path": "api/launches", "parameters": { "type": "object", "properties": {
              "which": { "type": "string", "enum": ["upcoming", "previous"] }, "q": { "type": "string", "description": "substring of name, provider, mission, pad or rocket" },
              "status": { "type": "string", "description": "status abbreviation such as Go, TBC, TBD, Success" }, "limit": { "type": "integer", "description": "1-40, default 20" } } } },
        { "name": "space_object", "description": "CelesTrak orbital elements and catalog data (owner, launch date and site, decay date, object type, status) for one object or a group. Give exactly one of catnr (NORAD ID, for example 25544), name (substring, for example ISS), group (for example stations) or intl (for example 1998-067A). Includes derived period, apogee and perigee. Passes are not computed here.",
          "method": "GET", "path": "api/object", "parameters": { "type": "object", "properties": {
              "catnr": { "type": "string" }, "name": { "type": "string" }, "group": { "type": "string", "enum": GROUPS }, "intl": { "type": "string" }, "limit": { "type": "integer" } } } },
        { "name": "space_recent", "description": "list=launched: objects launched in the last 30 days (catalog attributes). list=decaying: active objects with the lowest perigee, a drag-exposure ranking and not a reentry prediction.",
          "method": "GET", "path": "api/recent", "parameters": { "type": "object", "properties": {
              "list": { "type": "string", "enum": ["launched", "decaying"] }, "max_perigee_km": { "type": "number", "description": "decaying only, 100-2000, default 300" }, "limit": { "type": "integer" } } } },
    ]))
}

async fn page() -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], PAGE).into_response()
}

pub fn app(cfg: Config, state_dir: PathBuf) -> Router {
    let st = Arc::new(App { up: Upstream { agent: osnt_common::http_agent(UA), cache: cache::DiskCache::new(state_dir.join("cache"), 24 * 1024 * 1024) }, cfg });
    Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/sources", get(sources))
        .route("/api/launches", get(launches))
        .route("/api/pads", get(pads))
        .route("/api/object", get(object))
        .route("/api/recent", get(recent))
        .with_state(st)
}

#[tokio::main]
async fn main() {
    let addr: SocketAddr = env::var("OSNT_SPACE_BIND").unwrap_or_else(|_| "127.0.0.1:8156".into()).parse().expect("bind addr");
    let state = PathBuf::from(env::var("OSNT_SPACE_STATE").unwrap_or_else(|_| env::temp_dir().join("osnt-space-watch").to_string_lossy().into()));
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("space-watch plugin on http://{addr}");
    axum::serve(listener, app(Config::from_env(), state)).await.expect("serve");
}

#[cfg(test)]
mod tests;

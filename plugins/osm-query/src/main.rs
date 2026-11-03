//! OSM feature finder: friendly Overpass queries (presets, radius/bbox, "A near B"), raw Overpass QL, Nominatim/Photon
//! geocoding and recent changesets and notes for an area. Upstream hosts are fixed or come from the service environment;
//! callers can never choose a host. Editor names are deliberately dropped from changesets and notes.

mod presets;
mod util;

use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use axum::{
    Json, Router,
    extract::{Query, State},
    middleware,
    response::Html,
    routing::get,
};
use presets::{Area, Selectors};
use serde_json::{Value, json};
use util::{ApiError, Cache, Guarded, Params, bad, blocking, blocking_api};

const PAGE: &str = include_str!("../assets/index.html");
const UA: &str = "osnt-osm-query/0.1 (+https://github.com/ogden-marrow/osnt-hub)";
const DOWN_FOR: Duration = Duration::from_secs(300);
const NOMINATIM_GAP: Duration = Duration::from_millis(1100);

pub struct Config {
    pub overpass: Vec<String>,
    pub nominatim: String,
    pub photon: String,
    pub osm_api: String,
}

pub struct App {
    agent: ureq::Agent,
    cfg: Config,
    cache: Cache,
    down: Mutex<HashMap<String, Instant>>,
    last_nominatim: Mutex<Option<Instant>>,
    require_gateway: bool,
}
type Shared = Arc<App>;
impl Guarded for App {
    fn require_gateway(&self) -> bool {
        self.require_gateway
    }
}

type Q = Query<HashMap<String, String>>;

fn round(v: f64, p: i32) -> f64 {
    let k = 10f64.powi(p);
    (v * k).round() / k
}

fn pct(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

fn iso_days_ago(days: u64) -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0).saturating_sub(days * 86400) as i64;
    let z = secs.div_euclid(86400) + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    let r = secs.rem_euclid(86400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", r / 3600, (r % 3600) / 60, r % 60)
}

fn retry_wait() -> Duration {
    Duration::from_millis(if cfg!(test) { 50 } else { 2500 })
}

// ---- Overpass -------------------------------------------------------------------------------------------------------

/// Plain text of an Overpass error page, trimmed.
fn error_text(body: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in body.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    let t: Vec<&str> = out.lines().map(str::trim).filter(|l| l.starts_with("Error") || l.contains("error") || l.contains("Error")).collect();
    let s = if t.is_empty() { out.split_whitespace().collect::<Vec<_>>().join(" ") } else { t.join(" ") };
    s.chars().take(300).collect()
}

fn overpass(app: &App, ql: &str) -> Result<(Value, String), ApiError> {
    let key = format!("op|{ql}");
    if let Some(v) = app.cache.get(&key) {
        return Ok((v["data"].clone(), v["instance"].as_str().unwrap_or("").to_string()));
    }
    let body = format!("data={}", pct(ql));
    let mut tried = vec![];
    for url in &app.cfg.overpass {
        if app.down.lock().map(|d| d.get(url).is_some_and(|t| t.elapsed() < DOWN_FOR)).unwrap_or(false) {
            tried.push(format!("{url} (skipped: recently unreachable)"));
            continue;
        }
        let mut retried = false;
        loop {
            let res = app
                .agent
                .post(url)
                .config()
                .timeout_global(Some(Duration::from_secs(30)))
                .http_status_as_error(false)
                .build()
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .send(body.as_bytes());
            match res {
                Err(e) => {
                    tried.push(format!("{url}: {e}"));
                    if let Ok(mut d) = app.down.lock() {
                        d.insert(url.clone(), Instant::now());
                    }
                    break;
                }
                Ok(mut r) => {
                    let status = r.status().as_u16();
                    let text = r.body_mut().read_to_string().unwrap_or_default();
                    if status == 200 {
                        let v: Value = serde_json::from_str(&text).map_err(|_| ApiError(axum::http::StatusCode::BAD_GATEWAY, "Overpass returned something that is not JSON".into()))?;
                        if let Some(remark) = v["remark"].as_str().filter(|r| r.contains("error") || r.contains("timed out") || r.contains("out of memory")) {
                            return Err(ApiError(axum::http::StatusCode::BAD_GATEWAY, format!("Overpass: {remark}")));
                        }
                        app.cache.put(key, json!({ "data": v, "instance": url }));
                        return Ok((v, url.clone()));
                    }
                    match status {
                        400 => return Err(bad(format!("Overpass rejected the query: {}", error_text(&text)))),
                        429 | 502 | 503 | 504 => {
                            if !retried {
                                // A busy public server often has room a moment later: one short retry before moving on.
                                retried = true;
                                std::thread::sleep(retry_wait());
                                continue;
                            }
                            tried.push(format!("{url}: HTTP {status} (busy)"));
                            if let Ok(mut d) = app.down.lock() {
                                // Skip it for about a minute (checked_sub: an Instant can be younger than DOWN_FOR).
                                d.insert(url.clone(), Instant::now().checked_sub(DOWN_FOR - Duration::from_secs(60)).unwrap_or_else(Instant::now));
                            }
                        }
                        _ => tried.push(format!("{url}: HTTP {status}")),
                    }
                    break;
                }
            }
        }
    }
    Err(ApiError(
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        format!("No Overpass server answered. Set OSNT_OVERPASS_URL to one you can reach. Tried: {}", tried.join("; ")),
    ))
}

fn element_center(e: &Value) -> Option<(f64, f64)> {
    if let (Some(la), Some(lo)) = (e["lat"].as_f64(), e["lon"].as_f64()) {
        return Some((la, lo));
    }
    if let (Some(la), Some(lo)) = (e["center"]["lat"].as_f64(), e["center"]["lon"].as_f64()) {
        return Some((la, lo));
    }
    let b = &e["bounds"];
    Some(((b["minlat"].as_f64()? + b["maxlat"].as_f64()?) / 2.0, (b["minlon"].as_f64()? + b["maxlon"].as_f64()?) / 2.0))
}

/// Overpass elements to GeoJSON features. `class` labels each element "a" or "b" for the near filter.
pub fn to_features(v: &Value, a: Option<&Selectors>, b: Option<&Selectors>) -> Vec<Value> {
    let mut out = vec![];
    for e in v["elements"].as_array().map(Vec::as_slice).unwrap_or_default() {
        let Some((lat, lon)) = element_center(e) else { continue };
        let (t, id) = (e["type"].as_str().unwrap_or("node"), e["id"].as_i64().unwrap_or(0));
        let tags = e["tags"].as_object().cloned().unwrap_or_default();
        let name = tags.get("name").or_else(|| tags.get("ref")).and_then(Value::as_str).unwrap_or("").to_string();
        let class = match (a, b) {
            (Some(a), Some(b)) => if a.matches(&tags) { "a" } else if b.matches(&tags) { "b" } else { "" },
            _ => "",
        };
        // Full geometry only when the query asked for it (raw `out geom`).
        let geometry = match e["geometry"].as_array() {
            Some(g) if g.len() >= 2 => {
                let coords: Vec<Value> = g.iter().filter_map(|p| Some(json!([p["lon"].as_f64()?, p["lat"].as_f64()?]))).collect();
                let linear = ["highway", "railway", "barrier", "waterway"].iter().any(|k| tags.contains_key(*k)) && tags.get("area").and_then(Value::as_str) != Some("yes");
                if coords.len() >= 4 && coords.first() == coords.last() && !linear {
                    json!({ "type": "Polygon", "coordinates": [coords] })
                } else {
                    json!({ "type": "LineString", "coordinates": coords })
                }
            }
            _ => json!({ "type": "Point", "coordinates": [round(lon, 7), round(lat, 7)] }),
        };
        out.push(json!({
            "type": "Feature", "geometry": geometry,
            "properties": { "osm_type": t, "osm_id": id, "name": name, "class": class, "tags": tags, "centre_of_area": e["type"] != "node" && geometry_is_point(&geometry),
                            "url": format!("https://www.openstreetmap.org/{t}/{id}") },
        }));
    }
    out
}

fn geometry_is_point(g: &Value) -> bool {
    g["type"] == "Point"
}

fn finish(app: &App, ql: String, a: Option<Selectors>, b: Option<Selectors>, limit: u32) -> Result<Value, ApiError> {
    let (v, instance) = overpass(app, &ql)?;
    let features = to_features(&v, a.as_ref(), b.as_ref());
    let n = features.len();
    Ok(json!({
        "type": "FeatureCollection", "features": features,
        "meta": { "count": n, "limit": limit, "truncated": n as u32 >= limit, "query": ql, "instance": instance,
                  "data_timestamp": v["osm3s"]["timestamp_osm_base"], "licence": "© OpenStreetMap contributors, ODbL 1.0" },
    }))
}

fn area_from(p: &Params) -> Result<Area, ApiError> {
    if let Some(b) = p.str("bbox") {
        let v: Vec<f64> = b.split(',').map(|x| x.trim().parse::<f64>()).collect::<Result<_, _>>().map_err(|_| bad("bbox must be west,south,east,north"))?;
        if v.len() != 4 || v[1] < -90.0 || v[3] > 90.0 || v[0] < -180.0 || v[2] > 180.0 || v[1] >= v[3] || v[0] >= v[2] {
            return Err(bad("bbox must be west,south,east,north with west < east and south < north"));
        }
        if (v[2] - v[0]) > 0.6 || (v[3] - v[1]) > 0.6 {
            return Err(bad("bbox is limited to 0.6 degrees on a side; use a smaller area"));
        }
        return Ok(Area::Bbox { s: v[1], w: v[0], n: v[3], e: v[2] });
    }
    let (lat, lon) = p.lat_lon()?;
    let radius = p.num("radius", 10.0, 20000.0)?.unwrap_or(1000.0);
    Ok(Area::Around { lat, lon, radius })
}

fn selectors_from(p: &Params, key: &str) -> Result<Selectors, ApiError> {
    let id = p.req_str(key)?;
    if id == "custom" {
        let sfx = if key == "preset" { "" } else { "2" };
        return Selectors::custom(p.req_str(&format!("key{sfx}"))?, p.str(&format!("value{sfx}"))).map_err(bad);
    }
    presets::find(id).map(Selectors::preset).ok_or_else(|| bad(format!("unknown preset '{id}'")))
}

async fn find_handler(State(s): State<Shared>, Query(q): Q) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let a = selectors_from(&p, "preset")?;
    let area = area_from(&p)?;
    let limit = p.num("limit", 1.0, 500.0)?.unwrap_or(200.0) as u32;
    let near = match p.str("near") {
        Some(_) => Some((selectors_from(&p, "near")?, p.num("near_radius", 10.0, 5000.0)?.unwrap_or(200.0))),
        None => None,
    };
    let ql = presets::compile(&a, &area, near.as_ref().map(|(b, d)| (b, *d)), limit);
    let (a2, b2) = (Some(a), near.map(|n| n.0));
    Ok(Json(blocking_api(move || finish(&s, ql, a2, b2, limit)).await?))
}

async fn raw_handler(State(s): State<Shared>, Query(q): Q) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let mut ql = p.req_str("q")?.to_string();
    let has_out = ql.split(';').any(|st| { let t = st.trim(); t == "out" || t.starts_with("out ") });
    if ql.len() > 4000 {
        return Err(bad("query is limited to 4000 characters"));
    }
    if let Some(i) = ql.find("[out:") {
        if !ql[i..].starts_with("[out:json]") {
            return Err(bad("only [out:json] output is supported"));
        }
    } else {
        ql = format!("[out:json][timeout:25];{ql}");
    }
    if !has_out {
        return Err(bad("the query needs an output statement such as: out center tags 100;"));
    }
    Ok(Json(blocking_api(move || finish(&s, ql, None, None, 5000)).await?))
}

// ---- Geocoding ------------------------------------------------------------------------------------------------------

fn get_json(app: &App, url: &str, ttl_key: &str, gate: bool) -> Result<Value> {
    let key = format!("{ttl_key}|{url}");
    if let Some(v) = app.cache.get(&key) {
        return Ok(v);
    }
    if gate {
        // Nominatim usage policy: at most one request per second, whoever asks.
        let mut last = app.last_nominatim.lock().map_err(|_| anyhow!("lock poisoned"))?;
        if let Some(t) = *last {
            if let Some(wait) = NOMINATIM_GAP.checked_sub(t.elapsed()) {
                std::thread::sleep(wait);
            }
        }
        *last = Some(Instant::now());
    }
    let mut res = app.agent.get(url).header("Accept", "application/json").call().map_err(|e| anyhow!("upstream request failed: {e}"))?;
    let v: Value = res.body_mut().read_json().context("decode upstream response")?;
    app.cache.put(key, v.clone());
    Ok(v)
}

fn nominatim_item(r: &Value) -> Value {
    let f = |k: &str| r[k].as_str().and_then(|s| s.parse::<f64>().ok());
    let (t, id) = (r["osm_type"].as_str().unwrap_or(""), r["osm_id"].as_i64().unwrap_or(0));
    let bb = r["boundingbox"].as_array().map(|b| b.iter().filter_map(|x| x.as_str().and_then(|s| s.parse::<f64>().ok())).collect::<Vec<_>>());
    json!({ "name": r["name"], "display_name": r["display_name"], "lat": f("lat"), "lon": f("lon"), "class": r["category"], "type": r["type"],
            "bbox": bb.filter(|b| b.len() == 4).map(|b| json!([b[2], b[0], b[3], b[1]])), "osm_type": t, "osm_id": id, "address": r["address"],
            "url": (!t.is_empty()).then(|| format!("https://www.openstreetmap.org/{t}/{id}")) })
}

fn photon_item(f: &Value) -> Value {
    let p = &f["properties"];
    let c = &f["geometry"]["coordinates"];
    let parts: Vec<&str> = ["name", "street", "district", "city", "state", "country"].iter().filter_map(|k| p[*k].as_str()).collect();
    let t = match p["osm_type"].as_str() { Some("N") => "node", Some("W") => "way", Some("R") => "relation", _ => "" };
    let id = p["osm_id"].as_i64().unwrap_or(0);
    json!({ "name": p["name"], "display_name": parts.join(", "), "lat": c[1], "lon": c[0], "class": p["osm_key"], "type": p["osm_value"],
            "bbox": p["extent"].as_array().filter(|e| e.len() == 4).map(|e| json!([e[0], e[3], e[2], e[1]])), "osm_type": t, "osm_id": id,
            "url": (!t.is_empty()).then(|| format!("https://www.openstreetmap.org/{t}/{id}")) })
}

async fn geocode_handler(State(s): State<Shared>, Query(q): Q) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let text = p.req_str("q")?.to_string();
    if text.chars().count() > 200 {
        return Err(bad("query is limited to 200 characters"));
    }
    let limit = p.num("limit", 1.0, 10.0)?.unwrap_or(5.0) as u32;
    let provider = p.str("provider").unwrap_or("nominatim").to_string();
    if provider != "nominatim" && provider != "photon" {
        return Err(bad("provider must be nominatim or photon"));
    }
    Ok(Json(blocking(move || {
        if provider == "photon" {
            let v = get_json(&s, &format!("{}/api/?q={}&limit={limit}", s.cfg.photon, pct(&text)), "geo", false)?;
            let items: Vec<Value> = v["features"].as_array().map(|a| a.iter().map(photon_item).collect()).unwrap_or_default();
            Ok(json!({ "provider": "photon", "results": items, "licence": "Photon by komoot, data © OpenStreetMap contributors (ODbL)" }))
        } else {
            let v = get_json(&s, &format!("{}/search?q={}&format=jsonv2&limit={limit}&addressdetails=1", s.cfg.nominatim, pct(&text)), "geo", true)?;
            let items: Vec<Value> = v.as_array().map(|a| a.iter().map(nominatim_item).collect()).unwrap_or_default();
            Ok(json!({ "provider": "nominatim", "results": items, "licence": "Nominatim, data © OpenStreetMap contributors (ODbL)" }))
        }
    }).await?))
}

async fn reverse_handler(State(s): State<Shared>, Query(q): Q) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let (lat, lon) = p.lat_lon()?;
    let zoom = p.num("zoom", 3.0, 18.0)?.unwrap_or(18.0) as u32;
    let provider = p.str("provider").unwrap_or("nominatim").to_string();
    if provider != "nominatim" && provider != "photon" {
        return Err(bad("provider must be nominatim or photon"));
    }
    Ok(Json(blocking(move || {
        if provider == "photon" {
            let v = get_json(&s, &format!("{}/reverse?lat={lat:.6}&lon={lon:.6}", s.cfg.photon), "rev", false)?;
            let item = v["features"].as_array().and_then(|a| a.first()).map(photon_item);
            Ok(json!({ "provider": "photon", "result": item }))
        } else {
            let v = get_json(&s, &format!("{}/reverse?lat={lat:.6}&lon={lon:.6}&format=jsonv2&zoom={zoom}&addressdetails=1", s.cfg.nominatim), "rev", true)?;
            let item = (v.get("error").is_none()).then(|| nominatim_item(&v));
            Ok(json!({ "provider": "nominatim", "result": item, "message": v.get("error") }))
        }
    }).await?))
}

// ---- Recent edits ---------------------------------------------------------------------------------------------------

pub fn trim(s: &str, n: usize) -> String {
    let t: String = s.chars().take(n).collect();
    if s.chars().count() > n { format!("{t}…") } else { t }
}

/// Changesets and notes drop the mapper's name and id on purpose: this is "was the place edited", not "who edited".
pub fn changeset_item(c: &Value) -> Value {
    let t = &c["tags"];
    json!({ "id": c["id"], "created_at": c["created_at"], "closed_at": c["closed_at"], "open": c["open"], "changes": c["changes_count"],
            "comment": t["comment"].as_str().map(|s| trim(s, 200)), "editor": t["created_by"], "source": t["source"].as_str().map(|s| trim(s, 80)),
            "bbox": [c["min_lon"], c["min_lat"], c["max_lon"], c["max_lat"]], "regional": is_regional(c), "url": format!("https://www.openstreetmap.org/changeset/{}", c["id"]) })
}

/// A changeset whose box is wider than about 0.1 degrees (roughly 10 km) is a regional or bulk edit, not a change at this spot.
pub fn is_regional(c: &Value) -> bool {
    let d = |a: &str, b: &str| c[a].as_f64().zip(c[b].as_f64()).map(|(x, y)| (x - y).abs());
    d("max_lon", "min_lon").is_some_and(|w| w > 0.1) || d("max_lat", "min_lat").is_some_and(|h| h > 0.1)
}

pub fn note_item(f: &Value) -> Value {
    let p = &f["properties"];
    let c = f["geometry"]["coordinates"].clone();
    let first = p["comments"].as_array().and_then(|a| a.first());
    json!({ "id": p["id"], "lat": c[1], "lon": c[0], "status": p["status"], "created": p["date_created"], "closed": p["closed_at"],
            "text": first.and_then(|c| c["text"].as_str()).map(|s| trim(s, 300)), "comments": p["comments"].as_array().map(|a| a.len()),
            "url": format!("https://www.openstreetmap.org/note/{}", p["id"]) })
}

async fn edits_handler(State(s): State<Shared>, Query(q): Q) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let (lat, lon) = p.lat_lon()?;
    let radius = p.num("radius", 50.0, 5000.0)?.unwrap_or(500.0);
    let days = p.num("days", 1.0, 365.0)?.unwrap_or(30.0) as u64;
    let dlat = radius / 111_320.0;
    let dlon = radius / (111_320.0 * lat.to_radians().cos().max(0.05));
    let bbox = format!("{:.6},{:.6},{:.6},{:.6}", lon - dlon, lat - dlat, lon + dlon, lat + dlat);
    Ok(Json(blocking(move || {
        let since = iso_days_ago(days);
        let cs = get_json(&s, &format!("{}/changesets.json?bbox={bbox}&time={}&limit=40", s.cfg.osm_api, pct(&since)), "edits", false);
        let ns = get_json(&s, &format!("{}/notes.json?bbox={bbox}&limit=40&closed={days}", s.cfg.osm_api), "notes", false);
        let part = |r: Result<Value>, key: &str, f: fn(&Value) -> Value| match r {
            Ok(v) => json!({ "items": v[key].as_array().map(|a| a.iter().map(f).collect::<Vec<_>>()).unwrap_or_default() }),
            Err(e) => json!({ "error": format!("{e:#}"), "items": [] }),
        };
        let changesets = part(cs, "changesets", changeset_item);
        let notes = part(ns, "features", note_item);
        let open_notes = notes["items"].as_array().map(|a| a.iter().filter(|n| n["status"] == "open").count()).unwrap_or(0);
        Ok(json!({ "since": since, "bbox": bbox, "changesets": changesets, "notes": notes, "open_notes": open_notes,
                   "recently_edited": changesets["items"].as_array().map(|a| !a.is_empty()),
                   "local_changesets": changesets["items"].as_array().map(|a| a.iter().filter(|c| c["regional"] == false).count()),
                   "privacy": "Mapper names are not shown. Changesets are public on openstreetmap.org; this view is about the place, not the editor.",
                   "licence": "© OpenStreetMap contributors, ODbL 1.0" }))
    }).await?))
}

async fn status_handler(State(s): State<Shared>, Query(q): Q) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let probe = p.str("probe") == Some("1");
    Ok(Json(blocking(move || {
        let mut out = vec![];
        for url in &s.cfg.overpass {
            let down = s.down.lock().ok().and_then(|d| d.get(url).map(|t| t.elapsed() < DOWN_FOR)).unwrap_or(false);
            let mut reachable = Value::Null;
            if probe {
                let r = s.agent.post(url).config().timeout_global(Some(Duration::from_secs(8))).build().header("Content-Type", "application/x-www-form-urlencoded").send(b"data=%5Bout%3Ajson%5D%5Btimeout%3A5%5D%3Bnode%281%29%3Bout%20ids%3B");
                reachable = json!(r.is_ok());
                if let Ok(mut d) = s.down.lock() {
                    if r.is_ok() { d.remove(url); } else { d.insert(url.clone(), Instant::now()); }
                }
            }
            out.push(json!({ "url": url, "marked_down": down, "reachable": reachable }));
        }
        Ok(json!({ "overpass": out, "hint": "Set OSNT_OVERPASS_URL (service environment) to change the primary server." }))
    }).await?))
}

async fn presets_handler() -> Json<Value> {
    Json(presets::list_json())
}

async fn tools() -> Json<Value> {
    let n = |d: &str| json!({ "type": "number", "description": d });
    let s = |d: &str| json!({ "type": "string", "description": d });
    let preset_ids: Vec<&str> = presets::PRESETS.iter().map(|p| p.id).collect();
    Json(json!([
        { "name": "osm_find", "description": "Find OpenStreetMap features of a preset type within a radius of a point (towers, bridges, fuel, rail_crossings, military, airports, ...), optionally only those within near_radius metres of another preset (the 'bridge near a rail crossing' pattern). Returns GeoJSON.",
          "method": "GET", "path": "api/find", "parameters": { "type": "object", "properties": {
              "preset": json!({ "type": "string", "enum": preset_ids, "description": "feature type" }), "lat": n("latitude"), "lon": n("longitude"), "radius": n("metres, 10..20000, default 1000"),
              "near": s("optional second preset id that must be near each result"), "near_radius": n("metres, 10..5000, default 200"), "limit": n("max results, default 200") },
              "required": ["preset", "lat", "lon"] } },
        { "name": "osm_geocode", "description": "Turn a place name or address into coordinates (Nominatim, or Photon with provider=photon).",
          "method": "GET", "path": "api/geocode", "parameters": { "type": "object", "properties": { "q": s("place name or address"), "provider": s("nominatim (default) or photon"), "limit": n("1..10") }, "required": ["q"] } },
        { "name": "osm_reverse", "description": "Name the place at a coordinate (reverse geocode).",
          "method": "GET", "path": "api/reverse", "parameters": { "type": "object", "properties": { "lat": n("latitude"), "lon": n("longitude"), "zoom": n("3 (country) to 18 (building)"), "provider": s("nominatim or photon") }, "required": ["lat", "lon"] } },
        { "name": "osm_recent_edits", "description": "Recent OSM changesets and open map notes around a point, to check whether a place was edited recently. Mapper names are omitted.",
          "method": "GET", "path": "api/edits", "parameters": { "type": "object", "properties": { "lat": n("latitude"), "lon": n("longitude"), "radius": n("metres, 50..5000"), "days": n("look-back, 1..365") }, "required": ["lat", "lon"] } }
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

pub fn router(app: App) -> Router {
    let state: Shared = Arc::new(app);
    let api = Router::new()
        .route("/api/presets", get(presets_handler))
        .route("/api/find", get(find_handler))
        .route("/api/raw", get(raw_handler))
        .route("/api/geocode", get(geocode_handler))
        .route("/api/reverse", get(reverse_handler))
        .route("/api/edits", get(edits_handler))
        .route("/api/status", get(status_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), util::guard::<App>));
    Router::new().route("/", get(page)).route("/tools", get(tools)).merge(api).with_state(state)
}

pub fn new_app(cfg: Config, require_gateway: bool) -> App {
    App { agent: osnt_common::http_agent(UA), cfg, cache: Cache::new(Duration::from_secs(600), 200), down: Mutex::new(HashMap::new()), last_nominatim: Mutex::new(None), require_gateway }
}

fn clean_url(s: &str) -> Option<String> {
    let s = s.trim().trim_end_matches('/');
    (s.starts_with("https://") || s.starts_with("http://")).then(|| s.to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    let var = |k: &str, d: &str| env::var(k).unwrap_or_else(|_| d.into());
    let mut overpass: Vec<String> = vec![];
    for u in std::iter::once(var("OSNT_OVERPASS_URL", "https://overpass-api.de/api/interpreter")).chain(var("OSNT_OVERPASS_FALLBACKS", "").split(',').map(str::to_string)) {
        if let Some(c) = clean_url(&u) {
            if !overpass.contains(&c) {
                overpass.push(c);
            }
        }
    }
    let cfg = Config { overpass, nominatim: var("OSNT_NOMINATIM_URL", "https://nominatim.openstreetmap.org"), photon: var("OSNT_PHOTON_URL", "https://photon.komoot.io"), osm_api: var("OSNT_OSM_API_URL", "https://api.openstreetmap.org/api/0.6") };
    let app = router(new_app(cfg, util::gateway_configured()));
    let addr: SocketAddr = var("OSNT_OSM_QUERY_BIND", "127.0.0.1:8145").parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("osm-query plugin on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests;

//! Rail plugin: live train positions and station boards from Finland (Digitraffic, CC BY 4.0) and live vehicle
//! positions from Norway (Entur, NLOD). Trains are tracked as objects; nothing about passengers is touched.
//! Short in-memory caches only; nothing is written to disk.

use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use serde_json::{Value, json};

const PAGE: &str = include_str!("../assets/index.html");
const TTL_POS_FI: Duration = Duration::from_secs(10);
const TTL_POS_NO: Duration = Duration::from_secs(15);
const TTL_BOARD: Duration = Duration::from_secs(20);
const TTL_TRAIN: Duration = Duration::from_secs(30);
const TTL_STATIONS: Duration = Duration::from_secs(24 * 3600);
const MAX_CACHE: usize = 300;
const MAX_TRAINS: usize = 1500;

struct AppState {
    agent: ureq::Agent,
    fi: String,
    entur: String,
    cache: Mutex<HashMap<String, (Instant, Duration, Arc<Value>)>>,
}
type Shared = Arc<AppState>;

struct ApiError(StatusCode, String);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}
fn bad(msg: &str) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError(StatusCode::BAD_GATEWAY, format!("{e:#}"))
    }
}

// ---------- upstream ----------

fn fi_get(agent: &ureq::Agent, url: &str) -> Result<Value> {
    let mut res = agent.get(url).header("Digitraffic-User", "osnt-hub").config().http_status_as_error(false).build().call().context("Digitraffic request failed")?;
    let code = res.status().as_u16();
    let text = res.body_mut().read_to_string().context("read Digitraffic response")?;
    if !(200..300).contains(&code) {
        return Err(anyhow!("Digitraffic answered HTTP {code}"));
    }
    serde_json::from_str(&text).context("Digitraffic did not return JSON")
}

const ENTUR_QUERY: &str = "{ vehicles(mode: RAIL) { line { lineRef lineName } vehicleId lastUpdated location { latitude longitude } bearing speed delay mode codespace { codespaceId } } }";

fn entur_post(agent: &ureq::Agent, url: &str) -> Result<Value> {
    let mut res = agent
        .post(url)
        .header("ET-Client-Name", "osnt-hub-osnt-rail-live")
        .config()
        .http_status_as_error(false)
        .build()
        .send_json(json!({ "query": ENTUR_QUERY }))
        .context("Entur request failed")?;
    let code = res.status().as_u16();
    let text = res.body_mut().read_to_string().context("read Entur response")?;
    if !(200..300).contains(&code) {
        return Err(anyhow!("Entur answered HTTP {code}"));
    }
    let v: Value = serde_json::from_str(&text).context("Entur did not return JSON")?;
    if let Some(e) = v["errors"].as_array().and_then(|a| a.first()) {
        return Err(anyhow!("Entur GraphQL error: {}", e["message"].as_str().unwrap_or("unknown")));
    }
    Ok(v)
}

async fn cached<F>(s: &Shared, key: String, ttl: Duration, f: F) -> Result<Arc<Value>>
where
    F: FnOnce(Shared) -> Result<Value> + Send + 'static,
{
    if let Some((at, t, v)) = s.cache.lock().unwrap().get(&key) {
        if at.elapsed() < *t {
            return Ok(v.clone());
        }
    }
    let st = s.clone();
    let v = Arc::new(tokio::task::spawn_blocking(move || f(st)).await.map_err(|e| anyhow!(e))??);
    let mut c = s.cache.lock().unwrap();
    if c.len() >= MAX_CACHE {
        c.retain(|_, (at, t, _)| at.elapsed() < *t);
        if c.len() >= MAX_CACHE {
            if let Some(k) = c.iter().min_by_key(|(_, (at, ..))| *at).map(|(k, _)| k.clone()) {
                c.remove(&k);
            }
        }
    }
    c.insert(key, (Instant::now(), ttl, v.clone()));
    Ok(v)
}

// ---------- parsers ----------

/// Digitraffic `train-locations.geojson` features to flat train objects.
pub fn parse_fi_positions(v: &Value) -> Vec<Value> {
    v["features"]
        .as_array()
        .map(|f| {
            f.iter()
                .filter_map(|x| {
                    let c = x["geometry"]["coordinates"].as_array()?;
                    let (lon, lat) = (c.first()?.as_f64()?, c.get(1)?.as_f64()?);
                    let p = &x["properties"];
                    let n = p["trainNumber"].as_i64()?;
                    Some(json!({ "id": format!("fi-{n}"), "country": "FI", "number": n, "name": format!("Train {n}"), "lat": lat, "lon": lon,
                        "speed_kmh": p["speed"].as_f64(), "bearing": Value::Null, "delay_min": Value::Null, "updated": p["timestamp"], "departure_date": p["departureDate"] }))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Entur GraphQL `vehicles` to flat train objects (rail mode only).
pub fn parse_entur(v: &Value) -> Vec<Value> {
    v["data"]["vehicles"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|x| x["mode"].as_str().is_none_or(|m| m == "RAIL"))
                .filter_map(|x| {
                    let (lat, lon) = (x["location"]["latitude"].as_f64()?, x["location"]["longitude"].as_f64()?);
                    let id = x["vehicleId"].as_str()?;
                    Some(json!({ "id": format!("no-{id}"), "country": "NO", "number": Value::Null, "name": x["line"]["lineName"].as_str().unwrap_or("Train"), "line": x["line"]["lineRef"],
                        "operator": x["codespace"]["codespaceId"], "lat": lat, "lon": lon, "speed_kmh": x["speed"].as_f64().map(|m| m * 3.6), "bearing": x["bearing"].as_f64(),
                        "delay_min": x["delay"].as_f64().map(|s| (s / 60.0).round()), "updated": x["lastUpdated"] }))
                })
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Clone, Debug, PartialEq)]
pub struct Bbox {
    min_lon: f64,
    min_lat: f64,
    max_lon: f64,
    max_lat: f64,
}

pub fn parse_bbox(s: &str) -> Option<Bbox> {
    let p: Vec<f64> = s.split(',').map(|x| x.trim().parse::<f64>().ok()).collect::<Option<_>>()?;
    if p.len() != 4 || p.iter().any(|v| !v.is_finite()) {
        return None;
    }
    let b = Bbox { min_lon: p[0], min_lat: p[1], max_lon: p[2], max_lat: p[3] };
    (b.min_lat >= -90.0 && b.max_lat <= 90.0 && b.min_lat < b.max_lat && b.min_lon < b.max_lon && b.min_lon >= -540.0 && b.max_lon <= 540.0).then_some(b)
}

fn in_bbox(t: &Value, b: &Bbox) -> bool {
    let (lat, lon) = (t["lat"].as_f64().unwrap_or(999.0), t["lon"].as_f64().unwrap_or(999.0));
    lat >= b.min_lat && lat <= b.max_lat && lon >= b.min_lon && lon <= b.max_lon
}

fn station_name_map(stations: &Value) -> HashMap<String, String> {
    stations.as_array().map(|a| a.iter().filter_map(|s| Some((s["stationShortCode"].as_str()?.to_string(), s["stationName"].as_str()?.to_string()))).collect()).unwrap_or_default()
}

/// Departure and arrival boards for one station from Digitraffic `live-trains/station/{code}`.
pub fn build_board(code: &str, trains: &Value, names: &HashMap<String, String>) -> Value {
    let name_of = |c: &str| names.get(c).cloned().unwrap_or_else(|| c.to_string());
    let (mut deps, mut arrs) = (Vec::new(), Vec::new());
    for t in trains.as_array().map(Vec::as_slice).unwrap_or_default() {
        let rows = t["timeTableRows"].as_array().map(Vec::as_slice).unwrap_or_default();
        let (first, last) = (rows.first(), rows.last());
        let label = match t["commuterLineID"].as_str().filter(|s| !s.is_empty()) {
            Some(l) => format!("{l} line"),
            None => format!("{} {}", t["trainType"].as_str().unwrap_or(""), t["trainNumber"]).trim().to_string(),
        };
        for r in rows.iter().filter(|r| r["stationShortCode"] == code && r["commercialStop"].as_bool().unwrap_or(false)) {
            let kind = r["type"].as_str().unwrap_or("");
            let item = json!({
                "train": t["trainNumber"], "label": label, "category": t["trainCategory"], "scheduled": r["scheduledTime"], "estimate": r["liveEstimateTime"], "actual": r["actualTime"],
                "delay_min": r["differenceInMinutes"], "track": r["commercialTrack"], "cancelled": r["cancelled"].as_bool().unwrap_or(false) || t["cancelled"].as_bool().unwrap_or(false),
                "from": first.and_then(|f| f["stationShortCode"].as_str()).map(name_of), "to": last.and_then(|f| f["stationShortCode"].as_str()).map(name_of),
            });
            match kind {
                "DEPARTURE" => deps.push(item),
                "ARRIVAL" => arrs.push(item),
                _ => {}
            }
        }
    }
    let key = |v: &Value| v["scheduled"].as_str().unwrap_or("").to_string();
    deps.sort_by_key(key);
    arrs.sort_by_key(key);
    json!({ "station": { "code": code, "name": name_of(code) }, "departures": deps, "arrivals": arrs })
}

/// Journey summary for one train from `trains/latest/{n}`.
pub fn build_train(t: &Value, names: &HashMap<String, String>) -> Value {
    let name_of = |c: &str| names.get(c).cloned().unwrap_or_else(|| c.to_string());
    let rows = t["timeTableRows"].as_array().map(Vec::as_slice).unwrap_or_default();
    let stops: Vec<Value> = rows
        .iter()
        .filter(|r| r["commercialStop"].as_bool().unwrap_or(false))
        .take(80)
        .map(|r| json!({ "station": r["stationShortCode"].as_str().map(name_of), "type": r["type"], "scheduled": r["scheduledTime"], "estimate": r["liveEstimateTime"], "actual": r["actualTime"], "delay_min": r["differenceInMinutes"], "track": r["commercialTrack"], "cancelled": r["cancelled"] }))
        .collect();
    let delay = rows.iter().rev().find(|r| r["actualTime"].is_string()).and_then(|r| r["differenceInMinutes"].as_i64());
    let next = rows.iter().find(|r| !r["actualTime"].is_string() && r["commercialStop"].as_bool().unwrap_or(false)).and_then(|r| r["stationShortCode"].as_str()).map(name_of);
    json!({
        "number": t["trainNumber"], "date": t["departureDate"], "type": t["trainType"], "category": t["trainCategory"], "line": t["commuterLineID"], "operator": t["operatorShortCode"],
        "running": t["runningCurrently"], "cancelled": t["cancelled"],
        "from": rows.first().and_then(|r| r["stationShortCode"].as_str()).map(name_of), "to": rows.last().and_then(|r| r["stationShortCode"].as_str()).map(name_of),
        "delay_min": delay, "next_stop": next, "stops": stops,
    })
}

// ---------- handlers ----------

async fn stations(s: &Shared) -> Result<Arc<Value>> {
    let base = s.fi.clone();
    cached(s, "stations".into(), TTL_STATIONS, move |st| fi_get(&st.agent, &format!("{base}/api/v1/metadata/stations"))).await
}

#[derive(Deserialize, Default)]
struct TrainsQuery {
    bbox: Option<String>,
}

async fn trains_handler(State(s): State<Shared>, Query(q): Query<TrainsQuery>) -> Result<Json<Value>, ApiError> {
    let bbox = match q.bbox.as_deref().filter(|b| !b.is_empty()) {
        Some(b) => Some(parse_bbox(b).ok_or_else(|| bad("bbox must be minLon,minLat,maxLon,maxLat"))?),
        None => None,
    };
    let (fi_url, no_url) = (format!("{}/api/v1/train-locations.geojson/latest/", s.fi), format!("{}/realtime/v2/vehicles/graphql", s.entur));
    let (fi, no) = tokio::join!(
        cached(&s, "pos-fi".into(), TTL_POS_FI, move |st| fi_get(&st.agent, &fi_url)),
        cached(&s, "pos-no".into(), TTL_POS_NO, move |st| entur_post(&st.agent, &no_url)),
    );
    if fi.is_err() && no.is_err() {
        return Err(anyhow!("both feeds failed: {:#}; {:#}", fi.unwrap_err(), no.unwrap_err()).into());
    }
    let mut trains = Vec::new();
    let mut sources = serde_json::Map::new();
    for (name, r, parse) in [("FI", &fi, parse_fi_positions as fn(&Value) -> Vec<Value>), ("NO", &no, parse_entur)] {
        match r {
            Ok(v) => {
                let list = parse(v);
                sources.insert(name.into(), json!({ "ok": true, "total": list.len() }));
                trains.extend(list);
            }
            Err(e) => {
                sources.insert(name.into(), json!({ "ok": false, "error": format!("{e:#}") }));
            }
        }
    }
    if let Some(b) = &bbox {
        trains.retain(|t| in_bbox(t, b));
    }
    let truncated = trains.len() > MAX_TRAINS;
    trains.truncate(MAX_TRAINS);
    Ok(Json(json!({ "count": trains.len(), "truncated": truncated, "sources": sources, "trains": trains })))
}

fn valid_station(c: &str) -> Option<String> {
    let c = c.trim().to_ascii_uppercase();
    ((1..=8).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_alphanumeric())).then_some(c)
}

#[derive(Deserialize, Default)]
struct StationsQuery {
    q: Option<String>,
}

async fn stations_handler(State(s): State<Shared>, Query(q): Query<StationsQuery>) -> Result<Json<Value>, ApiError> {
    let all = stations(&s).await?;
    let needle = q.q.as_deref().map(|x| x.trim().to_lowercase()).filter(|x| !x.is_empty());
    if needle.as_ref().is_some_and(|n| n.len() > 60) {
        return Err(bad("search text is too long"));
    }
    let list: Vec<Value> = all
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|x| x["passengerTraffic"].as_bool().unwrap_or(false) && x["type"] == "STATION")
                .filter(|x| needle.as_ref().is_none_or(|n| x["stationName"].as_str().unwrap_or("").to_lowercase().contains(n.as_str()) || x["stationShortCode"].as_str().unwrap_or("").eq_ignore_ascii_case(n)))
                .take(if needle.is_some() { 25 } else { 500 })
                .map(|x| json!({ "code": x["stationShortCode"], "name": x["stationName"], "lat": x["latitude"], "lon": x["longitude"] }))
                .collect()
        })
        .unwrap_or_default();
    Ok(Json(json!({ "count": list.len(), "stations": list })))
}

#[derive(Deserialize, Default)]
struct BoardQuery {
    n: Option<u32>,
}

async fn station_handler(State(s): State<Shared>, Path(code): Path<String>, Query(q): Query<BoardQuery>) -> Result<Json<Value>, ApiError> {
    let code = valid_station(&code).ok_or_else(|| bad("station code must be 1-8 letters or digits, e.g. HKI"))?;
    let n = q.n.unwrap_or(15).clamp(1, 40);
    let names = station_name_map(&stations(&s).await.unwrap_or_default());
    if !names.is_empty() && !names.contains_key(&code) {
        return Err(ApiError(StatusCode::NOT_FOUND, format!("unknown station code {code}")));
    }
    let base = s.fi.clone();
    let c2 = code.clone();
    let v = cached(&s, format!("board:{code}:{n}"), TTL_BOARD, move |st| {
        fi_get(&st.agent, &format!("{base}/api/v1/live-trains/station/{c2}?departing_trains={n}&arriving_trains={n}&arrived_trains=0&departed_trains=0&include_nonstopping=false"))
    })
    .await?;
    Ok(Json(build_board(&code, &v, &names)))
}

async fn train_handler(State(s): State<Shared>, Path(number): Path<String>) -> Result<Json<Value>, ApiError> {
    let n: u32 = number.trim().parse().ok().filter(|n| (1..=99999).contains(n)).ok_or_else(|| bad("train number must be 1-99999"))?;
    let names = station_name_map(&stations(&s).await.unwrap_or_default());
    let base = s.fi.clone();
    let v = cached(&s, format!("train:{n}"), TTL_TRAIN, move |st| fi_get(&st.agent, &format!("{base}/api/v1/trains/latest/{n}"))).await?;
    let t = v.as_array().and_then(|a| a.first()).ok_or(ApiError(StatusCode::NOT_FOUND, "no such train today".into()))?;
    Ok(Json(build_train(t, &names)))
}

#[derive(Deserialize)]
struct NearQuery {
    lat: f64,
    lon: f64,
    radius: Option<f64>,
}

/// Trains within `radius` km of a point (for agents): same data as the map, filtered by distance.
async fn near_handler(State(s): State<Shared>, Query(q): Query<NearQuery>) -> Result<Json<Value>, ApiError> {
    if !(-90.0..=90.0).contains(&q.lat) || !(-180.0..=180.0).contains(&q.lon) {
        return Err(bad("lat/lon out of range"));
    }
    let r = q.radius.unwrap_or(50.0).clamp(1.0, 300.0);
    let (dlat, dlon) = (r / 111.0, r / (111.0 * q.lat.to_radians().cos().max(0.05)));
    let bbox = format!("{},{},{},{}", q.lon - dlon, (q.lat - dlat).max(-90.0), q.lon + dlon, (q.lat + dlat).min(90.0));
    let Json(mut v) = trains_handler(State(s), Query(TrainsQuery { bbox: Some(bbox) })).await?;
    let hav = |lat: f64, lon: f64| {
        let (a, b) = (q.lat.to_radians(), lat.to_radians());
        let h = ((b - a) / 2.0).sin().powi(2) + a.cos() * b.cos() * ((lon - q.lon).to_radians() / 2.0).sin().powi(2);
        6371.0 * 2.0 * h.sqrt().asin()
    };
    if let Some(list) = v["trains"].as_array_mut() {
        for t in list.iter_mut() {
            t["distance_km"] = json!((hav(t["lat"].as_f64().unwrap_or(0.0), t["lon"].as_f64().unwrap_or(0.0)) * 10.0).round() / 10.0);
        }
        list.retain(|t| t["distance_km"].as_f64().unwrap_or(1e9) <= r);
        list.sort_by(|a, b| a["distance_km"].as_f64().partial_cmp(&b["distance_km"].as_f64()).unwrap());
        v["count"] = json!(list.len());
    }
    Ok(Json(v))
}

async fn tools() -> Json<Value> {
    Json(json!([
        { "name": "rail_station", "description": "Live departures and arrivals board for a Finnish passenger station (Digitraffic), with delays, tracks and cancellations. Use the 1-8 character station code, e.g. HKI for Helsinki.",
          "method": "GET", "path": "api/station/{code}", "parameters": { "type": "object", "properties": { "code": { "type": "string", "description": "station short code, e.g. HKI" }, "n": { "type": "integer", "description": "rows per direction, max 40" } }, "required": ["code"] } },
        { "name": "rail_near", "description": "Trains currently within a radius (km, max 300) of a point, from Finland (Digitraffic GPS) and Norway (Entur), nearest first. Objects only: position, speed, line, delay.",
          "method": "GET", "path": "api/near", "parameters": { "type": "object", "properties": { "lat": { "type": "number" }, "lon": { "type": "number" }, "radius": { "type": "number", "description": "km" } }, "required": ["lat", "lon"] } },
        { "name": "rail_train", "description": "Journey summary for a Finnish train number today: line, origin, destination, delay, next stop and stop times.",
          "method": "GET", "path": "api/train/{number}", "parameters": { "type": "object", "properties": { "number": { "type": "integer" } }, "required": ["number"] } }
    ]))
}

async fn page() -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], PAGE).into_response()
}

fn app(state: Shared) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/trains", get(trains_handler))
        .route("/api/near", get(near_handler))
        .route("/api/stations", get(stations_handler))
        .route("/api/station/{code}", get(station_handler))
        .route("/api/train/{number}", get(train_handler))
        .with_state(state)
}

fn new_state(fi: String, entur: String) -> Shared {
    Arc::new(AppState { agent: osnt_common::http_agent("osnt-rail-live/0.1 (+https://github.com/ogden-marrow/osnt-hub)"), fi, entur, cache: Mutex::default() })
}

#[tokio::main]
async fn main() -> Result<()> {
    let state = new_state(env::var("OSNT_RAIL_FI").unwrap_or_else(|_| "https://rata.digitraffic.fi".into()), env::var("OSNT_RAIL_ENTUR").unwrap_or_else(|_| "https://api.entur.io".into()));
    let addr: SocketAddr = env::var("OSNT_RAIL_BIND").unwrap_or_else(|_| "127.0.0.1:8158".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("rail-live plugin on http://{addr}");
    axum::serve(listener, app(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    fn fake(routes: Vec<(&'static str, u16, String)>) -> (String, Arc<AtomicUsize>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        std::thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let mut buf = [0u8; 8192];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                h.fetch_add(1, Ordering::SeqCst);
                let (code, body) = routes.iter().find(|(p, ..)| path.starts_with(p)).map(|(_, c, b)| (*c, b.clone())).unwrap_or((404, "{}".into()));
                let _ = write!(s, "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            }
        });
        (base, hits)
    }

    fn fi_pos() -> String {
        json!({"type":"FeatureCollection","features":[
            {"type":"Feature","geometry":{"type":"Point","coordinates":[24.94,60.17]},"properties":{"speed":116,"trainNumber":4,"departureDate":"2026-11-03","timestamp":"2026-11-03T04:35:56.000Z"}},
            {"type":"Feature","geometry":{"type":"Point","coordinates":[22.6,63.4]},"properties":{"speed":0,"trainNumber":30,"departureDate":"2026-11-03"}},
            {"type":"Feature","geometry":null,"properties":{"trainNumber":5}}]}).to_string()
    }
    fn entur_body() -> String {
        json!({"data":{"vehicles":[
            {"line":{"lineRef":"VYG:Line:RE11","lineName":"Eidsvoll-Oslo S-Skien"},"vehicleId":"802","lastUpdated":"2026-11-03T04:35:34Z","location":{"latitude":59.74,"longitude":10.17},"bearing":88.7,"speed":null,"delay":360.0,"mode":"RAIL","codespace":{"codespaceId":"VYG"}},
            {"line":{"lineRef":"VYG:Line:RX11","lineName":"Bus"},"vehicleId":"b1","location":{"latitude":59.3,"longitude":10.3},"mode":"BUS"}]}}).to_string()
    }
    fn stations_body() -> String {
        json!([{"stationName":"Helsinki asema","stationShortCode":"HKI","latitude":60.172,"longitude":24.941,"passengerTraffic":true,"type":"STATION"},
               {"stationName":"Pasila asema","stationShortCode":"PSL","latitude":60.198,"longitude":24.934,"passengerTraffic":true,"type":"STATION"},
               {"stationName":"Ainola","stationShortCode":"AIN","latitude":60.45,"longitude":25.1,"passengerTraffic":true,"type":"STOPPING_POINT"},
               {"stationName":"Ahonpää","stationShortCode":"AHO","latitude":64.5,"longitude":25.0,"passengerTraffic":false,"type":"STATION"}]).to_string()
    }
    fn live_trains() -> String {
        json!([{"trainNumber":8445,"trainType":"HL","trainCategory":"Commuter","commuterLineID":"U","cancelled":false,"timeTableRows":[
            {"type":"DEPARTURE","stationShortCode":"HKI","commercialStop":true,"commercialTrack":"11","scheduledTime":"2026-11-03T04:37:00.000Z","liveEstimateTime":"2026-11-03T04:39:00.000Z","differenceInMinutes":2,"cancelled":false},
            {"type":"ARRIVAL","stationShortCode":"PSL","commercialStop":true,"scheduledTime":"2026-11-03T04:40:54.000Z","cancelled":false},
            {"type":"ARRIVAL","stationShortCode":"PSL","commercialStop":false,"scheduledTime":"2026-11-03T04:41:00.000Z"}]},
            {"trainNumber":1,"trainType":"IC","trainCategory":"Long-distance","cancelled":true,"timeTableRows":[
            {"type":"DEPARTURE","stationShortCode":"PSL","commercialStop":true,"scheduledTime":"2026-11-03T04:10:00.000Z","cancelled":true},
            {"type":"ARRIVAL","stationShortCode":"HKI","commercialStop":true,"scheduledTime":"2026-11-03T04:20:00.000Z","commercialTrack":"3","cancelled":true}]}]).to_string()
    }

    async fn get_json(app: &Router, uri: &str) -> (StatusCode, Value) {
        let res = app.clone().oneshot(Request::get(uri).body(Body::empty()).unwrap()).await.unwrap();
        let st = res.status();
        let b = res.into_body().collect().await.unwrap().to_bytes();
        (st, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    #[test]
    fn parsers() {
        let fi = parse_fi_positions(&serde_json::from_str(&fi_pos()).unwrap());
        assert_eq!(fi.len(), 2, "feature without geometry dropped");
        assert_eq!(fi[0]["id"], "fi-4");
        let no = parse_entur(&serde_json::from_str(&entur_body()).unwrap());
        assert_eq!(no.len(), 1, "bus filtered out");
        assert_eq!(no[0]["delay_min"], 6.0);
        assert_eq!(no[0]["bearing"], 88.7);
    }

    #[test]
    fn bbox_validation() {
        assert!(parse_bbox("10,59,11,60").is_some());
        assert!(parse_bbox("10,59,11").is_none());
        assert!(parse_bbox("11,59,10,60").is_none());
        assert!(parse_bbox("10,59,11,95").is_none());
        assert!(parse_bbox("a,b,c,d").is_none());
        assert!(parse_bbox("NaN,59,11,60").is_none());
    }

    #[test]
    fn board_shapes() {
        let names = station_name_map(&serde_json::from_str(&stations_body()).unwrap());
        let b = build_board("HKI", &serde_json::from_str(&live_trains()).unwrap(), &names);
        assert_eq!(b["station"]["name"], "Helsinki asema");
        assert_eq!(b["departures"].as_array().unwrap().len(), 1);
        assert_eq!(b["departures"][0]["label"], "U line");
        assert_eq!(b["departures"][0]["to"], "Pasila asema");
        assert_eq!(b["departures"][0]["delay_min"], 2);
        assert_eq!(b["arrivals"][0]["cancelled"], true);
        assert_eq!(b["arrivals"][0]["label"], "IC 1");
    }

    #[tokio::test]
    async fn api_trains_bbox_and_partial_failure() {
        let (base, hits) = fake(vec![("/api/v1/train-locations", 200, fi_pos()), ("/realtime/v2/vehicles/graphql", 200, entur_body())]);
        let a = app(new_state(base.clone(), base));
        let (st, v) = get_json(&a, "/api/trains").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["count"], 3);
        let (_, v) = get_json(&a, "/api/trains?bbox=10,59,11,60").await;
        assert_eq!(v["count"], 1);
        assert_eq!(v["trains"][0]["country"], "NO");
        assert_eq!(hits.load(Ordering::SeqCst), 2, "positions cached");
        assert_eq!(get_json(&a, "/api/trains?bbox=oops").await.0, StatusCode::BAD_REQUEST);
        let (st, v) = get_json(&a, "/api/near?lat=59.74&lon=10.17&radius=20").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["count"], 1);
        assert_eq!(get_json(&a, "/api/near?lat=99&lon=10").await.0, StatusCode::BAD_REQUEST);

        let (base, _) = fake(vec![("/api/v1/train-locations", 200, fi_pos()), ("/realtime", 500, "{}".into())]);
        let a = app(new_state(base.clone(), base));
        let (st, v) = get_json(&a, "/api/trains").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["sources"]["NO"]["ok"], false);
        assert_eq!(v["count"], 2);

        let (base, _) = fake(vec![("/api", 503, "{}".into()), ("/realtime", 500, "{}".into())]);
        assert_eq!(get_json(&app(new_state(base.clone(), base)), "/api/trains").await.0, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn entur_graphql_errors_surface() {
        let (base, _) = fake(vec![("/api/v1/train-locations", 200, fi_pos()), ("/realtime", 200, r#"{"errors":[{"message":"bad field"}]}"#.into())]);
        let (_, v) = get_json(&app(new_state(base.clone(), base)), "/api/trains").await;
        assert!(v["sources"]["NO"]["error"].as_str().unwrap().contains("bad field"));
    }

    #[tokio::test]
    async fn stations_board_and_train() {
        let train = json!([{"trainNumber":8445,"departureDate":"2026-11-03","trainType":"HL","commuterLineID":"U","runningCurrently":true,"cancelled":false,"timeTableRows":[
            {"type":"DEPARTURE","stationShortCode":"HKI","commercialStop":true,"scheduledTime":"a","actualTime":"a","differenceInMinutes":1},
            {"type":"ARRIVAL","stationShortCode":"PSL","commercialStop":true,"scheduledTime":"b","differenceInMinutes":0}]}]).to_string();
        let (base, _) = fake(vec![("/api/v1/metadata/stations", 200, stations_body()), ("/api/v1/live-trains/station/HKI", 200, live_trains()), ("/api/v1/trains/latest/8445", 200, train), ("/api/v1/trains/latest/", 200, "[]".into())]);
        let a = app(new_state(base.clone(), base));
        let (_, v) = get_json(&a, "/api/stations").await;
        assert_eq!(v["count"], 2, "only passenger stations");
        let (_, v) = get_json(&a, "/api/stations?q=pas").await;
        assert_eq!(v["stations"][0]["code"], "PSL");
        let (st, v) = get_json(&a, "/api/station/hki?n=5").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["station"]["code"], "HKI");
        assert_eq!(get_json(&a, "/api/station/ZZZ").await.0, StatusCode::NOT_FOUND);
        assert_eq!(get_json(&a, "/api/station/H%20K").await.0, StatusCode::BAD_REQUEST);
        let (st, v) = get_json(&a, "/api/train/8445").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["next_stop"], "Pasila asema");
        assert_eq!(v["delay_min"], 1);
        assert_eq!(get_json(&a, "/api/train/0").await.0, StatusCode::BAD_REQUEST);
        assert_eq!(get_json(&a, "/api/train/abc").await.0, StatusCode::BAD_REQUEST);
        assert_eq!(get_json(&a, "/api/train/77").await.0, StatusCode::NOT_FOUND);
    }

    #[test]
    fn cache_is_bounded() {
        let (base, _) = fake(vec![]);
        let st = new_state(base.clone(), base);
        {
            let mut c = st.cache.lock().unwrap();
            for i in 0..MAX_CACHE {
                c.insert(format!("k{i}"), (Instant::now(), Duration::from_secs(60), Arc::new(json!(1))));
            }
        }
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(cached(&st, "new".into(), Duration::from_secs(5), |_| Ok(json!(2)))).unwrap();
        assert!(st.cache.lock().unwrap().len() <= MAX_CACHE);
    }
}

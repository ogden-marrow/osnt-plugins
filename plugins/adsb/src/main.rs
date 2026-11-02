//! ADS-B plugin: live aircraft from a community aggregator (adsb.lol, ODbL), military and
//! emergency-squawk monitoring, and a local position history for trails.
//! Listens on loopback only; the portal core reverse-proxies it at /p/adsb/.

use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const PAGE: &str = include_str!("../assets/index.html");
/// (hex, unix seconds) -> JSON [lat, lon, alt_ft, gs, track]
const POSITIONS: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("positions");
const EMERGENCY_SQUAWKS: [&str; 3] = ["7700", "7600", "7500"];
const RETENTION_SECS: u64 = 24 * 3600;
const MIN_RECORD_GAP_SECS: u64 = 15;
const MAX_RADIUS_NM: f64 = 250.0;

#[derive(Serialize, Clone)]
struct Aircraft {
    hex: String,
    flight: Option<String>,
    reg: Option<String>,
    #[serde(rename = "type")]
    typ: Option<String>,
    lat: f64,
    lon: f64,
    /// barometric altitude in feet; 0 when on the ground
    alt: Option<i64>,
    on_ground: bool,
    gs: Option<f64>,
    track: Option<f64>,
    squawk: Option<String>,
    mil: bool,
}

struct AppState {
    agent: ureq::Agent,
    api: String,
    db: Database,
    cache: Mutex<HashMap<String, (Instant, Arc<Vec<Aircraft>>)>>,
    last_recorded: Mutex<HashMap<String, u64>>,
}

type Shared = Arc<AppState>;

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn parse_aircraft(v: &Value) -> Option<Aircraft> {
    let lat = v.get("lat")?.as_f64()?;
    let lon = v.get("lon")?.as_f64()?;
    let text = |k: &str| v.get(k).and_then(Value::as_str).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let (alt, on_ground) = match v.get("alt_baro") {
        Some(Value::String(s)) if s == "ground" => (Some(0), true),
        Some(n) => (n.as_f64().map(|f| f.round() as i64), false),
        None => (None, false),
    };
    Some(Aircraft {
        hex: v.get("hex")?.as_str()?.to_lowercase(),
        flight: text("flight"),
        reg: text("r"),
        typ: text("t"),
        lat,
        lon,
        alt,
        on_ground,
        gs: v.get("gs").and_then(Value::as_f64),
        track: v.get("track").and_then(Value::as_f64),
        squawk: text("squawk"),
        mil: v.get("dbFlags").and_then(Value::as_u64).is_some_and(|f| f & 1 == 1),
    })
}

/// Blocking fetch of an aggregator path, returning positioned aircraft.
fn fetch(state: &AppState, path: &str) -> Result<Vec<Aircraft>> {
    let url = format!("{}{path}", state.api);
    let mut res = state.agent.get(&url).call().with_context(|| format!("GET {url}"))?;
    let body: Value = res.body_mut().read_json().context("decode response")?;
    Ok(body.get("ac").and_then(Value::as_array).map(|a| a.iter().filter_map(parse_aircraft).collect()).unwrap_or_default())
}

/// Cached fetch (the aggregator is a free community service, so be polite) that also records history.
async fn cached(state: &Shared, key: String, path: String, ttl: Duration) -> Result<Arc<Vec<Aircraft>>> {
    if let Some((at, v)) = state.cache.lock().unwrap().get(&key) {
        if at.elapsed() < ttl {
            return Ok(v.clone());
        }
    }
    let st = state.clone();
    let list = tokio::task::spawn_blocking(move || fetch(&st, &path)).await??;
    let list = Arc::new(list);
    state.cache.lock().unwrap().insert(key, (Instant::now(), list.clone()));
    if let Err(e) = record(state, &list) {
        tracing::warn!("recording positions failed: {e:#}");
    }
    Ok(list)
}

fn record(state: &AppState, list: &[Aircraft]) -> Result<()> {
    let now = now_secs();
    let due: Vec<&Aircraft> = {
        let mut last = state.last_recorded.lock().unwrap();
        list.iter()
            .filter(|a| {
                let ok = last.get(&a.hex).is_none_or(|t| now.saturating_sub(*t) >= MIN_RECORD_GAP_SECS);
                if ok {
                    last.insert(a.hex.clone(), now);
                }
                ok
            })
            .collect()
    };
    if due.is_empty() {
        return Ok(());
    }
    let txn = state.db.begin_write()?;
    {
        let mut table = txn.open_table(POSITIONS)?;
        for a in due {
            let value = serde_json::to_vec(&json!([a.lat, a.lon, a.alt, a.gs, a.track]))?;
            table.insert((a.hex.as_str(), now), value.as_slice())?;
        }
    }
    txn.commit()?;
    Ok(())
}

fn prune(state: &AppState) -> Result<usize> {
    let cutoff = now_secs().saturating_sub(RETENTION_SECS);
    let txn = state.db.begin_write()?;
    let mut removed = 0;
    {
        let mut table = txn.open_table(POSITIONS)?;
        let stale: Vec<(String, u64)> = table
            .iter()?
            .filter_map(|r| r.ok())
            .map(|(k, _)| {
                let (hex, ts) = k.value();
                (hex.to_string(), ts)
            })
            .filter(|(_, ts)| *ts < cutoff)
            .collect();
        for (hex, ts) in &stale {
            table.remove((hex.as_str(), *ts))?;
            removed += 1;
        }
    }
    txn.commit()?;
    state.last_recorded.lock().unwrap().retain(|_, t| *t >= cutoff);
    Ok(removed)
}

/// Background loop: keep global military and emergency-squawk history even when nobody has the page open.
async fn poll_loop(state: Shared) {
    let every = Duration::from_secs(env::var("OSNT_ADSB_POLL_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(30));
    let mut ticks = 0u32;
    loop {
        if let Err(e) = cached(&state, "mil".into(), "/v2/mil".into(), Duration::ZERO).await {
            tracing::warn!("mil poll failed: {e:#}");
        }
        for sq in EMERGENCY_SQUAWKS {
            if let Err(e) = cached(&state, format!("sqk{sq}"), format!("/v2/sqk/{sq}"), Duration::ZERO).await {
                tracing::warn!("squawk {sq} poll failed: {e:#}");
            }
        }
        ticks += 1;
        if ticks % 20 == 0 {
            let st = state.clone();
            match tokio::task::spawn_blocking(move || prune(&st)).await {
                Ok(Ok(n)) => tracing::info!("pruned {n} old positions"),
                Ok(Err(e)) => tracing::warn!("prune failed: {e:#}"),
                Err(e) => tracing::warn!("prune task: {e}"),
            }
        }
        tokio::time::sleep(every).await;
    }
}

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::warn!("{e:#}");
        ApiError(StatusCode::BAD_GATEWAY, format!("{e:#}"))
    }
}

#[derive(Deserialize)]
struct NearQuery {
    lat: f64,
    lon: f64,
    #[serde(default = "default_radius")]
    radius: f64,
}

fn default_radius() -> f64 {
    100.0
}

async fn near(State(s): State<Shared>, Query(q): Query<NearQuery>) -> Result<Json<Arc<Vec<Aircraft>>>, ApiError> {
    if !(-90.0..=90.0).contains(&q.lat) || !(-180.0..=180.0).contains(&q.lon) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "lat/lon out of range".into()));
    }
    let radius = q.radius.clamp(1.0, MAX_RADIUS_NM).round();
    // Round the centre so nearby map pans share a cache entry.
    let (lat, lon) = ((q.lat * 10.0).round() / 10.0, (q.lon * 10.0).round() / 10.0);
    let key = format!("pt{lat}/{lon}/{radius}");
    Ok(Json(cached(&s, key, format!("/v2/point/{lat}/{lon}/{radius}"), Duration::from_secs(4)).await?))
}

async fn military(State(s): State<Shared>) -> Result<Json<Arc<Vec<Aircraft>>>, ApiError> {
    Ok(Json(cached(&s, "mil".into(), "/v2/mil".into(), Duration::from_secs(10)).await?))
}

async fn emergencies(State(s): State<Shared>) -> Result<Json<Vec<Value>>, ApiError> {
    let mut out = Vec::new();
    for sq in EMERGENCY_SQUAWKS {
        let list = cached(&s, format!("sqk{sq}"), format!("/v2/sqk/{sq}"), Duration::from_secs(15)).await?;
        out.extend(list.iter().map(|a| {
            let mut v = serde_json::to_value(a).unwrap_or_default();
            v["meaning"] = json!(match sq {
                "7700" => "general emergency",
                "7600" => "radio failure",
                _ => "hijack",
            });
            v
        }));
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
}

/// Look up one aircraft by ICAO hex, registration or callsign.
async fn search(State(s): State<Shared>, Query(q): Query<SearchQuery>) -> Result<Json<Arc<Vec<Aircraft>>>, ApiError> {
    let term: String = q.q.trim().chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
    if term.is_empty() || term.len() > 12 {
        return Err(ApiError(StatusCode::BAD_REQUEST, "query must be 1-12 letters, digits or dashes".into()));
    }
    let is_hex = term.len() == 6 && term.chars().all(|c| c.is_ascii_hexdigit());
    let mut paths = Vec::new();
    if is_hex {
        paths.push(format!("/v2/hex/{term}"));
    }
    paths.push(format!("/v2/reg/{term}"));
    paths.push(format!("/v2/callsign/{term}"));
    for path in paths {
        let list = cached(&s, format!("search{path}"), path, Duration::from_secs(5)).await?;
        if !list.is_empty() {
            return Ok(Json(list));
        }
    }
    Ok(Json(Arc::new(vec![])))
}

#[derive(Deserialize)]
struct TrailQuery {
    #[serde(default = "default_minutes")]
    minutes: u64,
}

fn default_minutes() -> u64 {
    120
}

async fn trail(State(s): State<Shared>, Path(hex): Path<String>, Query(q): Query<TrailQuery>) -> Result<Json<Vec<Value>>, ApiError> {
    let hex = hex.to_lowercase();
    let from = now_secs().saturating_sub(q.minutes.min(24 * 60) * 60);
    let rows = tokio::task::spawn_blocking(move || -> Result<Vec<Value>> {
        let txn = s.db.begin_read()?;
        let table = match txn.open_table(POSITIONS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for row in table.range((hex.as_str(), from)..=(hex.as_str(), u64::MAX))? {
            let (k, v) = row?;
            let (_, ts) = k.value();
            let p: Value = serde_json::from_slice(v.value())?;
            out.push(json!({ "t": ts, "lat": p[0], "lon": p[1], "alt": p[2], "gs": p[3], "track": p[4] }));
        }
        Ok(out)
    })
    .await
    .map_err(|e| anyhow::anyhow!(e))??;
    Ok(Json(rows))
}

/// Machine-readable operations, so an agent layer can discover and call this plugin's capabilities.
async fn agent_tools() -> Json<Value> {
    Json(json!([
        { "name": "adsb_search", "description": "Find an aircraft by ICAO hex, registration or callsign and get its live position.",
          "method": "GET", "path": "api/search",
          "parameters": { "type": "object", "properties": { "q": { "type": "string" } }, "required": ["q"] } },
        { "name": "adsb_near", "description": "List aircraft within a radius (max 250 nm) of a point.",
          "method": "GET", "path": "api/aircraft",
          "parameters": { "type": "object", "properties": { "lat": { "type": "number" }, "lon": { "type": "number" }, "radius": { "type": "number", "description": "nautical miles" } }, "required": ["lat", "lon"] } },
        { "name": "adsb_military", "description": "List military-flagged aircraft currently broadcasting worldwide.",
          "method": "GET", "path": "api/military", "parameters": { "type": "object", "properties": {} } },
        { "name": "adsb_emergencies", "description": "Aircraft squawking 7700 (emergency), 7600 (radio failure) or 7500 (hijack).",
          "method": "GET", "path": "api/emergencies", "parameters": { "type": "object", "properties": {} } },
        { "name": "adsb_trail", "description": "Recorded position history for an aircraft (ICAO hex) from this system's own database.",
          "method": "GET", "path": "api/trail/{hex}",
          "parameters": { "type": "object", "properties": { "hex": { "type": "string" }, "minutes": { "type": "integer" } }, "required": ["hex"] } }
    ]))
}

async fn page() -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], PAGE).into_response()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "osnt_adsb=info".into()))
        .init();

    let db_path = env::var("OSNT_ADSB_DB").unwrap_or_else(|_| "adsb.redb".into());
    let state: Shared = Arc::new(AppState {
        agent: osnt_common::http_agent("osnt-adsb/0.1 (personal OSINT dashboard)"),
        api: env::var("OSNT_ADSB_API").unwrap_or_else(|_| "https://api.adsb.lol".into()),
        db: Database::create(&db_path).with_context(|| format!("open {db_path}"))?,
        cache: Mutex::default(),
        last_recorded: Mutex::default(),
    });

    if env::var("OSNT_ADSB_POLL_SECS").as_deref() != Ok("0") {
        tokio::spawn(poll_loop(state.clone()));
    }

    let app = Router::new()
        .route("/", get(page))
        .route("/tools", get(agent_tools))
        .route("/api/aircraft", get(near))
        .route("/api/military", get(military))
        .route("/api/emergencies", get(emergencies))
        .route("/api/search", get(search))
        .route("/api/trail/{hex}", get(trail))
        .with_state(state);

    let addr: SocketAddr = env::var("OSNT_ADSB_BIND").unwrap_or_else(|_| "127.0.0.1:8101".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("adsb plugin on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

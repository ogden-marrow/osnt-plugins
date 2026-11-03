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

#[derive(Serialize, Clone, Debug)]
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
    /// seconds since the position was last updated (None when the aggregator does not say)
    seen_pos: Option<f64>,
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
    /// Set when the aggregator answers HTTP 429: no requests are sent until this instant.
    backoff_until: Mutex<Option<Instant>>,
}

/// How long to stop asking after a 429 (the aggregator sends no usable Retry-After through the SDK client).
const BACKOFF: Duration = Duration::from_secs(30);
/// A failed refresh may be answered from a cached copy this old.
const STALE_OK: Duration = Duration::from_secs(180);
const CACHE_MAX_ENTRIES: usize = 256;

type Shared = Arc<AppState>;

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn parse_aircraft(v: &Value) -> Option<Aircraft> {
    let lat = v.get("lat")?.as_f64()?;
    let lon = v.get("lon")?.as_f64()?;
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }
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
        seen_pos: v.get("seen_pos").and_then(Value::as_f64),
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

/// Marker error text so callers can tell "rate limited" from other failures.
const RATE_LIMITED: &str = "adsb.lol is rate limiting requests";

fn backoff_left(state: &AppState) -> Option<Duration> {
    let mut g = state.backoff_until.lock().unwrap();
    match *g {
        Some(t) if t > Instant::now() => Some(t - Instant::now()),
        Some(_) => {
            *g = None;
            None
        }
        None => None,
    }
}

/// Drop expired cache entries once the map grows (every distinct map position makes a key), keeping memory bounded.
fn trim_cache(cache: &mut HashMap<String, (Instant, Arc<Vec<Aircraft>>)>) {
    if cache.len() <= CACHE_MAX_ENTRIES {
        return;
    }
    cache.retain(|_, (at, _)| at.elapsed() < STALE_OK);
    if cache.len() > CACHE_MAX_ENTRIES {
        // still too many fresh keys: drop the oldest half
        let mut ages: Vec<(String, Instant)> = cache.iter().map(|(k, (at, _))| (k.clone(), *at)).collect();
        ages.sort_by_key(|(_, at)| *at);
        for (k, _) in ages.into_iter().take(cache.len() / 2) {
            cache.remove(&k);
        }
    }
}

/// Cached fetch (the aggregator is a free community service, so be polite) that also records history.
/// A failed or rate-limited refresh falls back to a copy that is at most STALE_OK old.
async fn cached(state: &Shared, key: String, path: String, ttl: Duration) -> Result<Arc<Vec<Aircraft>>> {
    let hit = state.cache.lock().unwrap().get(&key).map(|(at, v)| (at.elapsed(), v.clone()));
    if let Some((age, v)) = &hit {
        if *age < ttl {
            return Ok(v.clone());
        }
    }
    let stale = hit.filter(|(age, _)| *age < STALE_OK).map(|(_, v)| v);
    if let Some(left) = backoff_left(state) {
        return stale.ok_or_else(|| anyhow::anyhow!("{RATE_LIMITED}; try again in {} s", left.as_secs() + 1));
    }
    let st = state.clone();
    let list = match tokio::task::spawn_blocking(move || fetch(&st, &path)).await? {
        Ok(l) => l,
        Err(e) => {
            if format!("{e:#}").contains("429") {
                *state.backoff_until.lock().unwrap() = Some(Instant::now() + BACKOFF);
                tracing::warn!("adsb.lol answered 429; pausing requests for {} s", BACKOFF.as_secs());
                return stale.ok_or_else(|| anyhow::anyhow!("{RATE_LIMITED}; try again in {} s", BACKOFF.as_secs()));
            }
            return stale.ok_or(e);
        }
    };
    let list = Arc::new(list);
    {
        let mut c = state.cache.lock().unwrap();
        c.insert(key, (Instant::now(), list.clone()));
        trim_cache(&mut c);
    }
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
        if let Some(left) = backoff_left(&state) {
            tokio::time::sleep(left + Duration::from_millis(500)).await;
            continue;
        }
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
        let msg = format!("{e:#}");
        if msg.starts_with(RATE_LIMITED) {
            return ApiError(StatusCode::SERVICE_UNAVAILABLE, msg);
        }
        // Do not leak the upstream URL; say what happened.
        ApiError(StatusCode::BAD_GATEWAY, format!("the aircraft feed (adsb.lol) is unavailable right now: {}", msg.rsplit(": ").next().unwrap_or("error")))
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
    if !q.radius.is_finite() {
        return Err(ApiError(StatusCode::BAD_REQUEST, "radius must be a number of nautical miles (1-250)".into()));
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
    let mut failed = None;
    let mut ok = 0;
    for sq in EMERGENCY_SQUAWKS {
        let list = match cached(&s, format!("sqk{sq}"), format!("/v2/sqk/{sq}"), Duration::from_secs(15)).await {
            Ok(l) => {
                ok += 1;
                l
            }
            Err(e) => {
                failed = Some(e);
                continue;
            }
        };
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
    // One squawk code failing should not hide the others; only report an error when none could be read.
    if let (0, Some(e)) = (ok, failed) {
        return Err(e.into());
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
}

/// Look up one aircraft by ICAO hex, registration or callsign.
async fn search(State(s): State<Shared>, Query(q): Query<SearchQuery>) -> Result<Json<Arc<Vec<Aircraft>>>, ApiError> {
    let term: String = q.q.trim().chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect::<String>().to_uppercase();
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
    if hex.is_empty() || hex.len() > 7 || !hex.bytes().all(|b| b.is_ascii_hexdigit() || b == b'~') {
        return Err(ApiError(StatusCode::BAD_REQUEST, "hex must be an ICAO address (6 hex digits, optionally prefixed with ~)".into()));
    }
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
        { "name": "adsb_trail", "description": "Recorded position history for an aircraft (ICAO hex) from this system's own database (positions seen while this hub polled, up to 24 h). Each point: t (unix s), lat, lon, alt (ft), gs (kt), track (deg).",
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
        backoff_until: Mutex::default(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ground_and_flags() {
        let a = parse_aircraft(&json!({"hex":"ABC123","lat":10.0,"lon":20.0,"alt_baro":"ground","dbFlags":1,"flight":"UAL1  ","seen_pos":1.5})).unwrap();
        assert_eq!(a.hex, "abc123");
        assert!(a.on_ground && a.mil);
        assert_eq!(a.alt, Some(0));
        assert_eq!(a.flight.as_deref(), Some("UAL1"));
        assert_eq!(a.seen_pos, Some(1.5));
    }

    #[test]
    fn rejects_bad_positions() {
        assert!(parse_aircraft(&json!({"hex":"abc123","lat":91.0,"lon":0.0})).is_none());
        assert!(parse_aircraft(&json!({"hex":"abc123","lat":0.0,"lon":181.0})).is_none());
        assert!(parse_aircraft(&json!({"hex":"abc123","lat":0.0})).is_none());
    }

    #[test]
    fn cache_stays_bounded() {
        let mut c: HashMap<String, (Instant, Arc<Vec<Aircraft>>)> = HashMap::new();
        for i in 0..(CACHE_MAX_ENTRIES * 2) {
            c.insert(format!("k{i}"), (Instant::now(), Arc::new(vec![])));
        }
        trim_cache(&mut c);
        assert!(c.len() <= CACHE_MAX_ENTRIES);
    }

    fn test_state(api: &str) -> Shared {
        let dir = std::env::temp_dir().join(format!("osnt-adsb-test-{}-{}", std::process::id(), now_secs()));
        std::fs::create_dir_all(&dir).unwrap();
        Arc::new(AppState {
            agent: osnt_common::http_agent("test"),
            api: api.into(),
            db: Database::create(dir.join("t.redb")).unwrap(),
            cache: Mutex::default(),
            last_recorded: Mutex::default(),
            backoff_until: Mutex::default(),
        })
    }

    #[tokio::test]
    async fn rate_limit_backs_off_and_serves_stale() {
        // Nothing listens here, so every fetch fails fast with a transport error (not a 429).
        let st = test_state("http://127.0.0.1:9");
        let err = cached(&st, "k".into(), "/v2/mil".into(), Duration::ZERO).await.unwrap_err();
        assert!(!format!("{err:#}").starts_with(RATE_LIMITED));
        // Seed a cached copy, then simulate an active backoff: the stale copy is served, not an error.
        st.cache.lock().unwrap().insert("k".into(), (Instant::now() - Duration::from_secs(60), Arc::new(vec![])));
        *st.backoff_until.lock().unwrap() = Some(Instant::now() + Duration::from_secs(20));
        assert!(cached(&st, "k".into(), "/v2/mil".into(), Duration::from_secs(4)).await.is_ok());
        // With no cached copy the error says it is a rate limit and maps to HTTP 503.
        let e = cached(&st, "other".into(), "/v2/mil".into(), Duration::from_secs(4)).await.unwrap_err();
        assert!(format!("{e:#}").starts_with(RATE_LIMITED));
        assert_eq!(ApiError::from(e).0, StatusCode::SERVICE_UNAVAILABLE);
        // An expired backoff clears itself.
        *st.backoff_until.lock().unwrap() = Some(Instant::now() - Duration::from_secs(1));
        assert!(backoff_left(&st).is_none());
    }
}

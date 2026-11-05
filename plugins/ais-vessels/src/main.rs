//! Vessels (AIS) plugin. Live ship positions and particulars by MMSI/IMO/name.
//!
//! * Finland's Digitraffic AIS (Baltic and Gulf of Finland, CC BY 4.0, no key) is the default source.
//! * AISStream.io (worldwide, free key `AISSTREAM_API_KEY`) is used only for areas Digitraffic does not cover, over a
//!   WebSocket that exists only while someone is watching such an area.
//! * Global Fishing Watch events (free token `GFW_API_TOKEN`) are fetched on request for one MMSI.
//!
//! Vessels are tracked as objects. No owner or crew data is gathered. Only a bounded recent window for the viewed
//! area is kept, in memory, and it is dropped when nobody has used the plugin for a while.

mod ais;
mod stream;

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
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use serde_json::{Value, json};

use ais::*;

const PAGE: &str = include_str!("../assets/index.html");
const NEAR_TTL: Duration = Duration::from_secs(12);
const INFO_TTL: Duration = Duration::from_secs(30 * 60);
const SECRET_TTL: Duration = Duration::from_secs(60);
const IDLE_CLEAR: Duration = Duration::from_secs(10 * 60);
const MAX_RESULTS: usize = 700;
const MAX_NEAR_CACHE: usize = 40;
/// Area where Digitraffic's receivers give good coverage: Baltic, Gulf of Finland, Gulf of Bothnia, parts of the Danish straits.
const FI_AREA: [f64; 4] = [53.5, 8.0, 71.5, 34.0];

struct AppState {
    agent: ureq::Agent,
    digitraffic: String,
    gfw: String,
    store: Arc<Mutex<Store>>,
    near_cache: Mutex<HashMap<String, (Instant, Arc<Vec<Pos>>)>>,
    secrets: Mutex<HashMap<&'static str, (Instant, Option<String>)>>,
    stream: stream::Stream,
    require_gateway: bool,
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

fn authorized(s: &AppState, method: &Method, uri: &Uri, h: &HeaderMap) -> bool {
    !s.require_gateway
        || osnt_common::gateway_authorized(method.as_str(), uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"), h.get("x-osnt-gateway").and_then(|v| v.to_str().ok()))
}

/// A configured secret, cached for a minute so the credentials plugin is not asked on every request. Never logged.
async fn secret(s: &Shared, name: &'static str) -> Option<String> {
    if let Some((at, v)) = s.secrets.lock().unwrap().get(name) {
        if at.elapsed() < SECRET_TTL {
            return v.clone();
        }
    }
    let v = tokio::task::spawn_blocking(move || osnt_common::secret(name)).await.ok().flatten().filter(|v| !v.trim().is_empty());
    s.secrets.lock().unwrap().insert(name, (Instant::now(), v.clone()));
    v
}

// ---------- Digitraffic ----------

fn dt_get(agent: &ureq::Agent, url: &str) -> Result<Option<Value>> {
    let mut res = agent.get(url).header("Digitraffic-User", "osnt-hub").config().http_status_as_error(false).build().call().context("Digitraffic request failed")?;
    let code = res.status().as_u16();
    if code == 404 {
        return Ok(None);
    }
    let text = res.body_mut().read_to_string().context("read Digitraffic response")?;
    if !(200..300).contains(&code) {
        return Err(anyhow!("Digitraffic answered HTTP {code}"));
    }
    Ok(Some(serde_json::from_str(&text).context("Digitraffic did not return JSON")?))
}

/// Positions around a point from Digitraffic, cached briefly per rounded query, and recorded in the store.
async fn fetch_near(s: &Shared, lat: f64, lon: f64, radius_km: u32, fresh: bool) -> Result<Arc<Vec<Pos>>> {
    let (lat, lon) = ((lat * 20.0).round() / 20.0, (lon * 20.0).round() / 20.0);
    let key = format!("{lat}/{lon}/{radius_km}");
    if let Some((at, v)) = s.near_cache.lock().unwrap().get(&key).filter(|_| !fresh) {
        if at.elapsed() < NEAR_TTL {
            return Ok(v.clone());
        }
    }
    let url = format!("{}/api/ais/v1/locations?latitude={lat}&longitude={lon}&radius={radius_km}", s.digitraffic);
    let agent = s.agent.clone();
    let body = tokio::task::spawn_blocking(move || dt_get(&agent, &url)).await.map_err(|e| anyhow!(e))??;
    let list = Arc::new(body.map(|b| parse_digitraffic_locations(&b)).unwrap_or_default());
    {
        let mut st = s.store.lock().unwrap();
        for p in list.iter() {
            st.update(p.clone());
        }
    }
    let mut c = s.near_cache.lock().unwrap();
    if c.len() >= MAX_NEAR_CACHE {
        c.retain(|_, (at, _)| at.elapsed() < NEAR_TTL);
        if c.len() >= MAX_NEAR_CACHE {
            if let Some(k) = c.iter().min_by_key(|(_, (at, _))| *at).map(|(k, _)| k.clone()) {
                c.remove(&k);
            }
        }
    }
    c.insert(key, (Instant::now(), list.clone()));
    Ok(list)
}

/// The vessel metadata list (about 40 KB gzipped for the whole Finnish feed). Loaded lazily and kept for 30 minutes.
async fn ensure_info(s: &Shared) -> Result<()> {
    if s.store.lock().unwrap().info_loaded.is_some_and(|t| t.elapsed() < INFO_TTL) {
        return Ok(());
    }
    let url = format!("{}/api/ais/v1/vessels", s.digitraffic);
    let agent = s.agent.clone();
    let body = tokio::task::spawn_blocking(move || dt_get(&agent, &url)).await.map_err(|e| anyhow!(e))??;
    let mut st = s.store.lock().unwrap();
    for v in body.as_ref().and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default() {
        if let Some((mmsi, info)) = parse_digitraffic_vessel(v) {
            let merged = match st.info.get(&mmsi) {
                Some(old) => Info { name: info.name.or_else(|| old.name.clone()), ..info },
                None => info,
            };
            st.set_info(mmsi, merged);
        }
    }
    st.info_loaded = Some(Instant::now());
    Ok(())
}

async fn one_info(s: &Shared, mmsi: u32) -> Result<Option<Info>> {
    if let Some(i) = s.store.lock().unwrap().info.get(&mmsi) {
        if i.name.is_some() || i.imo.is_some() {
            return Ok(Some(i.clone()));
        }
    }
    let url = format!("{}/api/ais/v1/vessels/{mmsi}", s.digitraffic);
    let agent = s.agent.clone();
    let body = tokio::task::spawn_blocking(move || dt_get(&agent, &url)).await.map_err(|e| anyhow!(e))??;
    let Some((m, info)) = body.as_ref().and_then(parse_digitraffic_vessel) else { return Ok(None) };
    s.store.lock().unwrap().set_info(m, info.clone());
    Ok(Some(info))
}

async fn one_position(s: &Shared, mmsi: u32) -> Result<Option<Pos>> {
    if let Some(p) = s.store.lock().unwrap().pos.get(&mmsi) {
        if now_ms() - p.ts < 15 * 60_000 {
            return Ok(Some(p.clone()));
        }
    }
    let url = format!("{}/api/ais/v1/locations?mmsi={mmsi}", s.digitraffic);
    let agent = s.agent.clone();
    let body = tokio::task::spawn_blocking(move || dt_get(&agent, &url)).await.map_err(|e| anyhow!(e))??;
    let p = body.map(|b| parse_digitraffic_locations(&b)).and_then(|l| l.into_iter().find(|p| p.mmsi == mmsi));
    if let Some(p) = &p {
        s.store.lock().unwrap().update(p.clone());
    }
    Ok(p)
}

// ---------- views ----------

fn vessel_json(p: &Pos, info: Option<&Info>) -> Value {
    json!({
        "mmsi": format!("{:09}", p.mmsi), "name": info.and_then(|i| i.name.clone()), "lat": p.lat, "lon": p.lon, "sog": p.sog, "cog": p.cog, "heading": p.heading,
        "nav_status": p.nav.map(nav_status_label), "ship_type": info.and_then(|i| i.ship_type), "type_label": info.and_then(|i| i.ship_type).map(ship_type_label),
        "class": ship_class(info.and_then(|i| i.ship_type)), "flag": flag_iso(p.mmsi), "age_s": ((now_ms() - p.ts) / 1000).max(0), "source": p.src,
    })
}

fn particulars(mmsi: u32, info: Option<&Info>) -> Value {
    let i = info.cloned().unwrap_or_default();
    json!({
        "mmsi": format!("{mmsi:09}"), "mmsi_kind": mmsi_kind(mmsi), "flag": flag_iso(mmsi),
        "flag_note": "Flag state as implied by the MMSI prefix (radio registration); it can differ from the flag on the ship's papers.",
        "name": i.name, "imo": i.imo.map(|x| format!("{x:07}")), "call_sign": i.call_sign, "ship_type": i.ship_type, "type_label": i.ship_type.map(ship_type_label),
        "destination": i.destination, "eta": i.eta, "draught_m": i.draught_m, "length_m": i.length_m, "beam_m": i.beam_m,
    })
}

fn links(mmsi: u32, info: Option<&Info>) -> Value {
    let mut l = vec![json!({ "name": "MarineTraffic", "url": format!("https://www.marinetraffic.com/en/ais/details/ships/mmsi:{mmsi:09}") }), json!({ "name": "VesselFinder", "url": format!("https://www.vesselfinder.com/?mmsi={mmsi:09}") })];
    if let Some(imo) = info.and_then(|i| i.imo) {
        l.push(json!({ "name": "VesselFinder (IMO)", "url": format!("https://www.vesselfinder.com/vessels/details/{imo:07}") }));
        l.push(json!({ "name": "IMO GISIS (login required)", "url": "https://gisis.imo.org/Public/SHIPS/Default.aspx" }));
    }
    json!(l)
}

// ---------- handlers ----------

#[derive(Deserialize)]
struct NearQuery {
    lat: f64,
    lon: f64,
    radius: Option<f64>,
    /// `1` skips the short result cache (the page's Refresh buttons).
    fresh: Option<String>,
}

fn bbox_around(lat: f64, lon: f64, km: f64) -> [f64; 4] {
    let dlat = km / 111.0;
    let dlon = km / (111.0 * lat.to_radians().cos().max(0.05));
    [(lat - dlat).max(-90.0), (lon - dlon).max(-180.0), (lat + dlat).min(90.0), (lon + dlon).min(180.0)]
}

fn inside_fi(b: &[f64; 4]) -> bool {
    b[0] >= FI_AREA[0] && b[1] >= FI_AREA[1] && b[2] <= FI_AREA[2] && b[3] <= FI_AREA[3]
}

async fn near_handler(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Query(q): Query<NearQuery>) -> Result<Json<Value>, ApiError> {
    if !(-90.0..=90.0).contains(&q.lat) || !(-180.0..=180.0).contains(&q.lon) || !q.lat.is_finite() || !q.lon.is_finite() {
        return Err(bad("lat/lon out of range"));
    }
    let radius = q.radius.unwrap_or(40.0);
    if !radius.is_finite() {
        return Err(bad("radius must be a number of kilometres"));
    }
    let radius = radius.clamp(1.0, 250.0);
    s.store.lock().unwrap().touch();
    let bbox = bbox_around(q.lat, q.lon, radius);
    let fi_overlap = bbox[0] < FI_AREA[2] && bbox[2] > FI_AREA[0] && bbox[1] < FI_AREA[3] && bbox[3] > FI_AREA[1];
    let mut notes = vec![];
    let mut stream_state = json!("not needed");
    if fi_overlap {
        if let Err(e) = fetch_near(&s, q.lat, q.lon, radius.ceil() as u32, q.fresh.as_deref() == Some("1")).await {
            notes.push(format!("Digitraffic: {e:#}"));
        }
        let _ = ensure_info(&s).await;
    }
    if !(fi_overlap && inside_fi(&bbox)) {
        // Part of the view is outside Digitraffic's area: use the worldwide feed when a key is configured.
        match secret(&s, "AISSTREAM_API_KEY").await {
            None => {
                stream_state = json!("no key");
                if !fi_overlap {
                    notes.push("This area is outside Finland's Digitraffic coverage. Add an AISStream.io key on the Credentials page for worldwide live AIS.".into());
                }
            }
            Some(_) if !authorized(&s, &method, &uri, &headers) => {
                stream_state = json!("sign in required");
                notes.push("Sign in to the hub to start the AISStream worldwide feed.".into());
            }
            Some(key) => {
                // Subscribe to a box 1.5x the view so small pans do not restart the connection.
                let (cy, cx, hy, hx) = ((bbox[0] + bbox[2]) / 2.0, (bbox[1] + bbox[3]) / 2.0, (bbox[2] - bbox[0]) * 0.75, (bbox[3] - bbox[1]) * 0.75);
                s.stream.ensure(s.store.clone(), key, [(cy - hy).max(-90.0), (cx - hx).max(-180.0), (cy + hy).min(90.0), (cx + hx).min(180.0)]);
                stream_state = match s.stream.status() {
                    Some(st) if st.connected => json!({ "connected": true, "messages": st.messages }),
                    Some(st) => json!({ "connected": false, "error": st.error }),
                    None => json!("starting"),
                };
            }
        }
    }
    if fi_overlap && notes.iter().all(|n| !n.starts_with("Digitraffic")) {
        notes.push("Positions come from Digitraffic's land-based receivers; vessels beyond their range are not listed.".into());
    }
    let st = s.store.lock().unwrap();
    let all = st.within(q.lat, q.lon, radius, 30 * 60_000);
    let total = all.len();
    let list: Vec<Value> = all.into_iter().take(MAX_RESULTS).map(|(d, p)| {
        let mut v = vessel_json(p, st.info.get(&p.mmsi));
        v["distance_km"] = json!((d * 10.0).round() / 10.0);
        v
    }).collect();
    Ok(Json(json!({ "count": list.len(), "total": total, "truncated": total > list.len(), "max_age_min": 30, "lat": q.lat, "lon": q.lon, "radius_km": radius, "stream": stream_state, "notes": notes, "vessels": list })))
}

fn parse_id(id: &str) -> Result<u32, ApiError> {
    if let Some(m) = parse_mmsi(id) {
        return Ok(m);
    }
    if parse_imo(id).is_some() {
        return Err(bad("use /api/search?q=<IMO> to resolve an IMO number to an MMSI first"));
    }
    Err(bad("MMSI must be exactly 9 digits (an IMO number is 7 digits with a valid check digit)"))
}

async fn vessel_handler(State(s): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    let id = id.trim().to_string();
    let mmsi = match parse_mmsi(&id) {
        Some(m) => m,
        None => match parse_imo(&id) {
            Some(imo) => {
                ensure_info(&s).await?;
                let found = s.store.lock().unwrap().info.iter().find(|(_, i)| i.imo == Some(imo)).map(|(m, _)| *m);
                found.ok_or(ApiError(StatusCode::NOT_FOUND, format!("IMO {imo:07} is not in the Finnish AIS vessel list; try the MMSI")))?
            }
            None => return Err(parse_id(&id).unwrap_err()),
        },
    };
    s.store.lock().unwrap().touch();
    let (info, pos) = tokio::join!(one_info(&s, mmsi), one_position(&s, mmsi));
    let (info, pos) = (info?, pos?);
    if info.is_none() && pos.is_none() {
        // AISStream data may know it.
        if let Some(i) = s.store.lock().unwrap().info.get(&mmsi) {
            return Ok(Json(json!({ "particulars": particulars(mmsi, Some(i)), "position": Value::Null, "links": links(mmsi, Some(i)) })));
        }
        return Err(ApiError(StatusCode::NOT_FOUND, "no live AIS data for that MMSI in the feeds this plugin can reach".into()));
    }
    let track_n = s.store.lock().unwrap().track(mmsi, 0).len();
    Ok(Json(json!({
        "particulars": particulars(mmsi, info.as_ref()),
        "position": pos.as_ref().map(|p| vessel_json(p, info.as_ref())),
        "track_points": track_n,
        "links": links(mmsi, info.as_ref()),
        "kind": "vessel (object); no owner or crew data is collected",
    })))
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
}

async fn search_handler(State(s): State<Shared>, Query(q): Query<SearchQuery>) -> Result<Json<Value>, ApiError> {
    let text = q.q.trim().to_string();
    if text.len() < 3 || text.len() > 40 || text.chars().any(|c| c.is_control()) {
        return Err(bad("search for 3 to 40 characters: a name, call sign, MMSI or IMO"));
    }
    s.store.lock().unwrap().touch();
    ensure_info(&s).await?;
    let up = text.to_uppercase();
    let (mmsi, imo) = (parse_mmsi(&text), parse_imo(&text));
    let st = s.store.lock().unwrap();
    let mut hits: Vec<(u8, u32, &Info)> = st
        .info
        .iter()
        .filter_map(|(m, i)| {
            let rank = if Some(*m) == mmsi || (imo.is_some() && i.imo == imo) {
                0
            } else if i.call_sign.as_deref().is_some_and(|c| c.eq_ignore_ascii_case(&text)) || i.name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case(&text)) {
                1
            } else if i.name.as_deref().is_some_and(|n| n.to_uppercase().starts_with(&up)) {
                2
            } else if i.name.as_deref().is_some_and(|n| n.to_uppercase().contains(&up)) {
                3
            } else {
                return None;
            };
            Some((rank, *m, i))
        })
        .collect();
    hits.sort_by(|a, b| a.0.cmp(&b.0).then(a.2.name.cmp(&b.2.name)));
    let mut out: Vec<Value> = hits
        .iter()
        .take(25)
        .map(|(_, m, i)| {
            let mut v = particulars(*m, Some(i));
            v["live"] = json!(st.pos.get(m).map(|p| json!({ "lat": p.lat, "lon": p.lon, "age_s": ((now_ms() - p.ts) / 1000).max(0) })));
            v
        })
        .collect();
    if out.is_empty() {
        if let Some(m) = mmsi {
            // A valid MMSI we have no metadata for: still offer it, the detail view will say what is known.
            out.push(particulars(m, None));
        }
    }
    Ok(Json(json!({ "count": out.len(), "results": out })))
}

#[derive(Deserialize)]
struct TrackQuery {
    minutes: Option<i64>,
}

async fn track_handler(State(s): State<Shared>, Path(id): Path<String>, Query(q): Query<TrackQuery>) -> Result<Json<Value>, ApiError> {
    let mmsi = parse_id(&id)?;
    let minutes = q.minutes.unwrap_or(360).clamp(1, 360);
    let mut st = s.store.lock().unwrap();
    st.touch();
    let pts: Vec<Value> = st.track(mmsi, now_ms() - minutes * 60_000).into_iter().map(|(t, la, lo)| json!({ "t": t, "lat": la, "lon": lo })).collect();
    Ok(Json(json!({
        "mmsi": format!("{mmsi:09}"), "count": pts.len(), "points": pts,
        "note": "Points are only those this plugin has received while the area was being watched (at most 6 hours, kept in memory and dropped when nobody is watching). It is not a full voyage history.",
    })))
}

#[derive(Deserialize)]
struct GfwQuery {
    days: Option<i64>,
}

fn gfw_get(agent: &ureq::Agent, url: &str, token: &str) -> Result<Value> {
    let mut res = agent.get(url).header("Authorization", &format!("Bearer {token}")).config().http_status_as_error(false).build().call().context("Global Fishing Watch request failed")?;
    let code = res.status().as_u16();
    let text = res.body_mut().read_to_string().context("read Global Fishing Watch response")?;
    match code {
        200..=299 => serde_json::from_str(&text).context("Global Fishing Watch did not return JSON"),
        401 | 403 => Err(anyhow!("Global Fishing Watch rejected the token (HTTP {code}); check GFW_API_TOKEN on the Credentials page")),
        429 => Err(anyhow!("Global Fishing Watch rate limit reached; try again later")),
        _ => Err(anyhow!("Global Fishing Watch answered HTTP {code}")),
    }
}

pub fn gfw_vessel_ids(v: &Value) -> Vec<String> {
    let mut ids = vec![];
    for e in v["entries"].as_array().map(Vec::as_slice).unwrap_or_default() {
        // combinedSourcesInfo carries the ids GFW itself recommends for event queries; then the self-reported and registry identities.
        for k in ["combinedSourcesInfo", "selfReportedInfo", "registryInfo"] {
            for i in e[k].as_array().map(Vec::as_slice).unwrap_or_default() {
                if let Some(id) = i["vesselId"].as_str().or_else(|| i["id"].as_str()) {
                    if id.len() <= 80 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') && !ids.contains(&id.to_string()) {
                        ids.push(id.to_string());
                    }
                }
            }
        }
    }
    ids.truncate(3);
    ids
}

pub fn gfw_events(v: &Value) -> Vec<Value> {
    v["entries"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|e| json!({ "type": e["type"], "start": e["start"], "end": e["end"], "lat": e["position"]["lat"], "lon": e["position"]["lon"], "distance_km": e["distances"]["startDistanceFromPortKm"], "id": e["id"] }))
                .collect()
        })
        .unwrap_or_default()
}

fn date_string(ms: i64) -> String {
    let (y, m, d) = civil_from_days(ms.div_euclid(86_400_000));
    format!("{y:04}-{m:02}-{d:02}")
}

async fn gfw_handler(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Path(id): Path<String>, Query(q): Query<GfwQuery>) -> Result<Json<Value>, ApiError> {
    if !authorized(&s, &method, &uri, &headers) {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "sign in to the hub to use Global Fishing Watch lookups (they spend your API token's quota)".into()));
    }
    let mmsi = parse_id(&id)?;
    let token = secret(&s, "GFW_API_TOKEN").await.ok_or(ApiError(StatusCode::SERVICE_UNAVAILABLE, "no Global Fishing Watch token: add GFW_API_TOKEN on the Credentials page (free for non-commercial use)".into()))?;
    let days = q.days.unwrap_or(90).clamp(1, 365);
    let (agent, base) = (s.agent.clone(), s.gfw.clone());
    let out = tokio::task::spawn_blocking(move || -> Result<Value> {
        let search = gfw_get(&agent, &format!("{base}/v3/vessels/search?query={mmsi:09}&datasets%5B0%5D=public-global-vessel-identity:latest&limit=3"), &token)?;
        let ids = gfw_vessel_ids(&search);
        if ids.is_empty() {
            return Ok(json!({ "found": false, "events": [] }));
        }
        let (end, start) = (date_string(now_ms()), date_string(now_ms() - days * 86_400_000));
        let mut events = vec![];
        let mut errors = vec![];
        for (label, dataset) in [("fishing", "public-global-fishing-events:latest"), ("port visit", "public-global-port-visits-events:latest"), ("AIS gap", "public-global-gaps-events:latest"), ("loitering", "public-global-loitering-events:latest")] {
            let vessels: String = ids.iter().enumerate().map(|(i, id)| format!("vessels%5B{i}%5D={id}&")).collect();
            let url = format!("{base}/v3/events?{vessels}datasets%5B0%5D={dataset}&start-date={start}&end-date={end}&limit=30&offset=0");
            match gfw_get(&agent, &url, &token) {
                Ok(v) => events.extend(gfw_events(&v).into_iter().map(|mut e| {
                    e["kind"] = json!(label);
                    e
                })),
                Err(e) => errors.push(format!("{label}: {e:#}")),
            }
        }
        events.sort_by(|a, b| b["start"].as_str().cmp(&a["start"].as_str()));
        Ok(json!({ "found": true, "vessel_ids": ids.len(), "events": events, "errors": errors }))
    })
    .await
    .map_err(|e| anyhow!(e))??;
    Ok(Json(json!({ "mmsi": format!("{mmsi:09}"), "days": days, "source": "Global Fishing Watch (CC BY-NC 4.0, non-commercial)", "result": out })))
}

async fn status_handler(State(s): State<Shared>) -> Json<Value> {
    let (ak, gk) = (secret(&s, "AISSTREAM_API_KEY").await.is_some(), secret(&s, "GFW_API_TOKEN").await.is_some());
    let st = s.store.lock().unwrap();
    Json(json!({
        "digitraffic": true, "aisstream": { "configured": ak, "active": s.stream.status().map(|x| x.connected) }, "gfw": { "configured": gk },
        "store": { "vessels": st.pos.len(), "with_tracks": st.tracks.len(), "metadata": st.info.len() },
        "coverage_bbox": FI_AREA,
    }))
}

async fn tools() -> Json<Value> {
    Json(json!([
        { "name": "ais_near", "description": "Vessels around a point (radius km, max 250): MMSI, name, position, speed, course, type and flag. Finland/Baltic from Digitraffic; elsewhere only if an AISStream key is configured. Vessels as objects only.",
          "method": "GET", "path": "api/near", "parameters": { "type": "object", "properties": { "lat": { "type": "number" }, "lon": { "type": "number" }, "radius": { "type": "number", "description": "km" } }, "required": ["lat", "lon"] } },
        { "name": "ais_vessel", "description": "Particulars and last known position of one vessel by MMSI (9 digits) or IMO (7 digits): name, call sign, type, size, destination, ETA, flag from MMSI prefix, and links. No owner data.",
          "method": "GET", "path": "api/vessel/{id}", "parameters": { "type": "object", "properties": { "id": { "type": "string", "description": "MMSI or IMO" } }, "required": ["id"] } },
        { "name": "ais_track", "description": "Recent track points for an MMSI that this plugin has observed while the area was watched (at most 6 hours; not a full history).",
          "method": "GET", "path": "api/track/{mmsi}", "parameters": { "type": "object", "properties": { "mmsi": { "type": "string" }, "minutes": { "type": "integer" } }, "required": ["mmsi"] } },
        { "name": "ais_search", "description": "Find vessels by name, call sign, MMSI or IMO in Finland's AIS vessel list.",
          "method": "GET", "path": "api/search", "parameters": { "type": "object", "properties": { "q": { "type": "string" } }, "required": ["q"] } }
    ]))
}

async fn page() -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], PAGE).into_response()
}

fn app(state: Shared) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/status", get(status_handler))
        .route("/api/near", get(near_handler))
        .route("/api/search", get(search_handler))
        .route("/api/vessel/{id}", get(vessel_handler))
        .route("/api/track/{id}", get(track_handler))
        .route("/api/gfw/{id}", get(gfw_handler))
        .with_state(state)
}

fn new_state(digitraffic: String, gfw: String, stream_url: String, require_gateway: bool) -> Shared {
    Arc::new(AppState {
        agent: osnt_common::http_agent("osnt-ais-vessels/0.1 (+https://github.com/ogden-marrow/osnt-hub)"),
        digitraffic,
        gfw,
        store: Arc::new(Mutex::new(Store::default())),
        near_cache: Mutex::default(),
        secrets: Mutex::default(),
        stream: stream::Stream::new(stream_url),
        require_gateway,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let e = |k: &str, d: &str| env::var(k).unwrap_or_else(|_| d.into());
    let state = new_state(e("OSNT_AIS_DIGITRAFFIC", "https://meri.digitraffic.fi"), e("OSNT_AIS_GFW", "https://gateway.api.globalfishingwatch.org"), e("OSNT_AIS_STREAM_URL", "wss://stream.aisstream.io/v0/stream"), e("OSNT_AIS_REQUIRE_GATEWAY", "1") != "0");
    // Housekeeping: stop the worldwide stream when nobody wants it, and drop everything when nobody has used the plugin.
    let hk = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            hk.stream.stop_if_idle();
            if hk.store.lock().unwrap().clear_if_idle(IDLE_CLEAR) {
                hk.stream.stop();
                hk.near_cache.lock().unwrap().clear();
            }
        }
    });
    let addr: SocketAddr = e("OSNT_AIS_BIND", "127.0.0.1:8157").parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("ais-vessels plugin on http://{addr}");
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

    fn loc(mmsi: u64, lat: f64, lon: f64) -> Value {
        json!({"mmsi":mmsi,"type":"Feature","geometry":{"type":"Point","coordinates":[lon,lat]},"properties":{"mmsi":mmsi,"sog":9.7,"cog":299.5,"navStat":0,"heading":302,"timestampExternal":now_ms()}})
    }
    fn locations() -> String {
        json!({"type":"FeatureCollection","features":[loc(230629000, 60.17, 24.95), loc(230994270, 60.2, 25.0), loc(266471000, 59.9, 24.0)]}).to_string()
    }
    fn vessels() -> String {
        json!([
            {"callSign":"OJPQ","destination":"SESTO","draught":67,"eta":727390,"imo":9606900,"mmsi":230629000,"name":"VIKING GRACE","referencePointA":22,"referencePointB":196,"referencePointC":16,"referencePointD":16,"shipType":60},
            {"callSign":"SBGJ","destination":"SEMMA","draught":71,"imo":9321615,"mmsi":266471000,"name":"TELLUS","shipType":70}
        ])
        .to_string()
    }

    fn st(base: &str) -> Shared {
        new_state(base.into(), base.into(), "ws://127.0.0.1:1/x".into(), false)
    }

    async fn get_json(app: &Router, uri: &str) -> (StatusCode, Value) {
        let res = app.clone().oneshot(Request::get(uri).body(Body::empty()).unwrap()).await.unwrap();
        let code = res.status();
        let b = res.into_body().collect().await.unwrap().to_bytes();
        (code, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    #[tokio::test]
    async fn near_returns_named_vessels_nearest_first_and_caches() {
        let (base, hits) = fake(vec![("/api/ais/v1/locations", 200, locations()), ("/api/ais/v1/vessels", 200, vessels())]);
        let a = app(st(&base));
        let (code, v) = get_json(&a, "/api/near?lat=60.17&lon=24.95&radius=100").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v["count"], 3);
        assert_eq!(v["vessels"][0]["name"], "VIKING GRACE");
        assert_eq!(v["vessels"][0]["flag"], "FI");
        assert_eq!(v["vessels"][0]["type_label"], "Passenger");
        assert_eq!(v["vessels"][0]["mmsi"], "230629000");
        let n = hits.load(Ordering::SeqCst);
        get_json(&a, "/api/near?lat=60.17&lon=24.95&radius=100").await;
        assert_eq!(hits.load(Ordering::SeqCst), n, "repeat view served from cache");
    }

    #[tokio::test]
    async fn near_validates_input_and_reports_uncovered_areas() {
        let (base, _) = fake(vec![]);
        let a = app(st(&base));
        assert_eq!(get_json(&a, "/api/near?lat=100&lon=0").await.0, StatusCode::BAD_REQUEST);
        assert_eq!(get_json(&a, "/api/near?lat=10&lon=200").await.0, StatusCode::BAD_REQUEST);
        assert_eq!(get_json(&a, "/api/near?lat=NaN&lon=0").await.0, StatusCode::BAD_REQUEST);
        assert_eq!(get_json(&a, "/api/near?lat=x&lon=0").await.0, StatusCode::BAD_REQUEST);
        let (code, v) = get_json(&a, "/api/near?lat=-33.9&lon=151.2&radius=5000").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v["radius_km"], 250.0, "radius clamped");
        assert_eq!(v["stream"], "no key");
        assert!(v["notes"][0].as_str().unwrap().contains("AISStream"));
    }

    #[tokio::test]
    async fn near_degrades_when_digitraffic_fails() {
        let (base, _) = fake(vec![("/api", 503, "{}".into())]);
        let a = app(st(&base));
        let (code, v) = get_json(&a, "/api/near?lat=60.17&lon=24.95").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v["count"], 0);
        assert!(v["notes"][0].as_str().unwrap().contains("503"));
    }

    #[tokio::test]
    async fn vessel_by_mmsi_and_imo() {
        let one = json!({"callSign":"OJPQ","destination":"SESTO","draught":67,"eta":727390,"imo":9606900,"mmsi":230629000,"name":"VIKING GRACE","shipType":60,"referencePointA":22,"referencePointB":196,"referencePointC":16,"referencePointD":16}).to_string();
        let one_loc = json!({"type":"FeatureCollection","features":[loc(230629000, 59.36, 18.42)]}).to_string();
        let (base, _) = fake(vec![("/api/ais/v1/vessels/230629000", 200, one), ("/api/ais/v1/locations?mmsi=230629000", 200, one_loc), ("/api/ais/v1/vessels", 200, vessels())]);
        let a = app(st(&base));
        let (code, v) = get_json(&a, "/api/vessel/230629000").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v["particulars"]["imo"], "9606900");
        assert_eq!(v["particulars"]["length_m"], 218);
        assert_eq!(v["position"]["lat"], 59.36);
        assert!(v["links"].as_array().unwrap().iter().any(|l| l["name"] == "VesselFinder (IMO)"));
        assert!(!v.to_string().to_lowercase().contains("owner\":"), "no owner field exists");
        let (code, v) = get_json(&a, "/api/vessel/IMO9606900").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v["particulars"]["mmsi"], "230629000");
        assert_eq!(get_json(&a, "/api/vessel/9606901").await.0, StatusCode::BAD_REQUEST, "bad IMO checksum");
        assert_eq!(get_json(&a, "/api/vessel/12345").await.0, StatusCode::BAD_REQUEST);
        assert_eq!(get_json(&a, "/api/vessel/9074729").await.0, StatusCode::NOT_FOUND, "valid IMO not in the list");
        assert_eq!(get_json(&a, "/api/vessel/999999999").await.0, StatusCode::NOT_FOUND);
    }

    #[test]
    fn ship_type_zero_is_unknown() {
        let (_, i) = parse_digitraffic_vessel(&json!({"mmsi":230998670u64,"name":"ASTRID","shipType":0})).unwrap();
        assert_eq!(i.ship_type, None);
        assert_eq!(ship_class(i.ship_type), "unknown");
    }

    #[tokio::test]
    async fn search_ranks_and_validates() {
        let (base, _) = fake(vec![("/api/ais/v1/vessels", 200, vessels())]);
        let a = app(st(&base));
        let (_, v) = get_json(&a, "/api/search?q=viking").await;
        assert_eq!(v["count"], 1);
        assert_eq!(v["results"][0]["name"], "VIKING GRACE");
        let (_, v) = get_json(&a, "/api/search?q=SBGJ").await;
        assert_eq!(v["results"][0]["name"], "TELLUS");
        let (_, v) = get_json(&a, "/api/search?q=9321615").await;
        assert_eq!(v["results"][0]["mmsi"], "266471000");
        let (_, v) = get_json(&a, "/api/search?q=273123456").await;
        assert_eq!(v["count"], 1, "unknown but valid MMSI is still offered");
        assert_eq!(get_json(&a, "/api/search?q=ab").await.0, StatusCode::BAD_REQUEST);
        assert_eq!(get_json(&a, &format!("/api/search?q={}", "x".repeat(60))).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(get_json(&a, "/api/search?q=%00%00%00%00").await.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn track_accumulates_from_watching() {
        let (base, _) = fake(vec![]);
        let s = st(&base);
        {
            let mut g = s.store.lock().unwrap();
            let t = now_ms();
            for i in 0..5 {
                g.update(Pos { mmsi: 230_629_000, lat: 60.0 + i as f64 * 0.01, lon: 24.0, sog: None, cog: None, heading: None, nav: None, ts: t - 600_000 + i * 60_000, src: "t" });
            }
        }
        let a = app(s);
        let (code, v) = get_json(&a, "/api/track/230629000?minutes=60").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v["count"], 5);
        assert_eq!(get_json(&a, "/api/track/230629000?minutes=1").await.1["count"], 0);
        assert_eq!(get_json(&a, "/api/track/abc").await.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn gfw_requires_gateway_and_token() {
        let (base, _) = fake(vec![]);
        // With the gateway check on and no signature, the route refuses before touching any token.
        let guarded = new_state(base.clone(), base.clone(), "ws://127.0.0.1:1/x".into(), true);
        assert_eq!(get_json(&app(guarded), "/api/gfw/230629000").await.0, StatusCode::UNAUTHORIZED);
        // Without a token the route says how to configure it.
        let a = app(st(&base));
        s_clear_secret(&a);
        let (code, v) = get_json(&a, "/api/gfw/230629000").await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert!(v["error"].as_str().unwrap().contains("GFW_API_TOKEN"));
        assert_eq!(get_json(&a, "/api/gfw/xyz").await.0, StatusCode::BAD_REQUEST);
    }
    fn s_clear_secret(_a: &Router) {
        // osnt_common::secret reads GFW_API_TOKEN from the environment first; tests never set it.
        assert!(std::env::var("GFW_API_TOKEN").is_err());
    }

    #[test]
    fn gfw_parsers() {
        let s = json!({"entries":[{"selfReportedInfo":[{"id":"abc-123","shipname":"X"},{"id":"bad id!"}],"registryInfo":[{"id":"def_456"}]}]});
        assert_eq!(gfw_vessel_ids(&s), vec!["abc-123", "def_456"]);
        let s = json!({"entries":[{"combinedSourcesInfo":[{"vesselId":"comb-1"}],"selfReportedInfo":[{"id":"abc-123"}]}]});
        assert_eq!(gfw_vessel_ids(&s), vec!["comb-1", "abc-123"], "combined-sources id first");
        let e = gfw_events(&json!({"entries":[{"type":"fishing","start":"2026-01-01T00:00:00Z","end":"2026-01-01T05:00:00Z","position":{"lat":1.5,"lon":2.5},"id":"e1"}]}));
        assert_eq!(e[0]["lat"], 1.5);
        assert!(gfw_events(&json!({})).is_empty());
        assert_eq!(date_string(86_400_000 * 20_000), "2024-10-04");
    }

    #[tokio::test]
    async fn idle_data_is_dropped() {
        let (base, _) = fake(vec![("/api/ais/v1/locations", 200, locations()), ("/api/ais/v1/vessels", 200, vessels())]);
        let s = st(&base);
        let a = app(s.clone());
        get_json(&a, "/api/near?lat=60.17&lon=24.95&radius=100").await;
        assert!(!s.store.lock().unwrap().pos.is_empty());
        assert!(s.store.lock().unwrap().clear_if_idle(Duration::ZERO));
        let (_, v) = get_json(&a, "/api/status").await;
        assert_eq!(v["store"]["vessels"], 0);
    }

    #[tokio::test]
    async fn tools_and_status_shapes() {
        let (base, _) = fake(vec![]);
        let a = app(st(&base));
        let (_, t) = get_json(&a, "/tools").await;
        assert!(t.as_array().unwrap().iter().all(|x| x["method"] == "GET" && x["path"].as_str().unwrap().starts_with("api/")));
        let (_, s) = get_json(&a, "/api/status").await;
        assert_eq!(s["aisstream"]["configured"], false);
        assert!(!s.to_string().contains("KEY"), "status never carries secrets");
    }
}

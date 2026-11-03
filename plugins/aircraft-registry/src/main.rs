//! Aircraft registry and routes. Complements the `adsb` plugin (live positions by hex/registration/callsign) with the
//! static side: who the registry says an airframe is, what airline and route a callsign usually flies, airports, type
//! designators, and a position cross-check between two independent open feeds.
//!
//! Privacy rule: registered owners that do not look like organisations are never returned; callers get
//! `{"kind":"private"}` instead of a name. This is about airframes, not people.

mod types;

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
const CACHE_MAX: usize = 1500;
const TTL_REGISTRY: Duration = Duration::from_secs(6 * 3600);
const TTL_ROUTE: Duration = Duration::from_secs(3600);
const TTL_STATIC: Duration = Duration::from_secs(24 * 3600);
const TTL_MISSING: Duration = Duration::from_secs(600);
const TTL_LIVE: Duration = Duration::from_secs(20);

struct Entry {
    at: Instant,
    ttl: Duration,
    val: Value,
}

struct AppState {
    agent: ureq::Agent,
    adsbdb: String,
    hexdb: String,
    adsblol: String,
    opensky: String,
    cache: Mutex<HashMap<String, Entry>>,
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
fn not_found(msg: &str) -> ApiError {
    ApiError(StatusCode::NOT_FOUND, msg.into())
}
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError(StatusCode::BAD_GATEWAY, format!("{e:#}"))
    }
}

// ---------- input validation ----------

pub fn valid_hex(s: &str) -> Option<String> {
    let s = s.trim().trim_start_matches("0x").to_ascii_lowercase();
    (s.len() == 6 && s.bytes().all(|b| b.is_ascii_hexdigit())).then_some(s)
}
/// Tail number / registration: 2-10 letters, digits and dashes, at least one letter, not starting with a dash.
pub fn valid_reg(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_uppercase();
    let ok = (2..=10).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') && !s.starts_with('-') && !s.ends_with('-') && s.bytes().any(|b| b.is_ascii_uppercase());
    ok.then_some(s)
}
pub fn valid_callsign(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_uppercase();
    ((2..=8).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric()) && s.bytes().any(|b| b.is_ascii_uppercase())).then_some(s)
}
pub fn valid_airport(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_uppercase();
    ((3..=4).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric())).then_some(s)
}
pub fn valid_airline(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_uppercase();
    ((2..=3).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric())).then_some(s)
}
pub fn valid_type(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_uppercase();
    ((2..=4).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric())).then_some(s)
}

/// What a free-text query most likely is. A 6-character all-hex string is treated as an ICAO hex first.
pub fn classify(q: &str) -> &'static str {
    let t = q.trim().to_ascii_uppercase();
    if valid_hex(&t).is_some() {
        return "hex";
    }
    let b = t.as_bytes();
    // airline designator + number (+ optional suffix letters), e.g. UAL1, DLH400, BAW12A
    let letters = b.iter().take_while(|c| c.is_ascii_alphabetic()).count();
    let digits = b[letters..].iter().take_while(|c| c.is_ascii_digit()).count();
    if letters == 3 && (1..=4).contains(&digits) && b.len() - letters - digits <= 2 && b[letters + digits..].iter().all(|c| c.is_ascii_alphabetic()) && !t.contains('-') {
        return "callsign";
    }
    if valid_reg(&t).is_some() {
        return "registration";
    }
    "unknown"
}

// ---------- owner privacy ----------

const ORG_WORDS: &[&str] = &[
    "LLC", "INC", "INC.", "CORP", "CORPORATION", "LTD", "LIMITED", "GMBH", "AG", "SA", "SAS", "SARL", "BV", "NV", "AB", "AS", "OY", "OYJ", "PLC", "LP", "LLP", "PTY", "SRL", "SPA", "KG", "CO", "COMPANY", "BANK",
    "AIR", "AIRLINES", "AIRLINE", "AIRWAYS", "AVIATION", "AIRCRAFT", "AEROSPACE", "AERO", "LEASING", "LEASE", "FINANCE", "FINANCIAL", "CAPITAL", "HOLDINGS", "GROUP", "SERVICES", "EXPRESS", "CARGO", "JETS",
    "CHARTER", "FLIGHT", "FLYING", "CLUB", "SCHOOL", "ACADEMY", "UNIVERSITY", "COLLEGE", "GOVERNMENT", "MINISTRY", "DEPARTMENT", "FORCE", "NAVY", "ARMY", "POLICE", "SHERIFF", "COUNTY", "CITY", "STATE", "FEDERAL",
    "AUTHORITY", "INTERNATIONAL", "ENTERPRISES", "INDUSTRIES", "MANAGEMENT", "PARTNERS", "ASSOCIATES", "ASSOCIATION", "FOUNDATION", "TRANSPORT", "LOGISTICS", "SYSTEMS", "TECHNOLOGIES", "HELICOPTERS", "HELICOPTER",
    "SOLUTIONS", "VENTURES", "EQUIPMENT", "INVESTMENTS", "PROPERTIES", "MOTORS", "RENTAL", "AIRLINES.", "TRUSTEE", "TRUSTEES", "ELECTRIC", "ENERGY", "OIL", "GAS", "MEDICAL", "HOSPITAL", "RESCUE", "AMBULANCE", "FIRE",
    "FORESTRY", "AGENCY", "BUREAU", "COMMISSION", "OFFICE", "SERVICE", "NATIONAL", "ROYAL", "REPUBLIC", "MILITARY", "GUARD", "TOURS", "FLUGDIENST", "AEROCLUB", "AERO-CLUB", "WINGS", "AVIATIONS", "JET", "SKY",
];

/// Organisation names are returned as listed; anything else (typically an individual) is withheld.
/// A name with a TRUST token but no other organisation word is withheld too (family trusts are personal).
pub fn owner_view(name: Option<&str>, operator_flag: Option<&str>) -> Value {
    let name = name.map(str::trim).filter(|n| !n.is_empty());
    let Some(name) = name else { return json!({ "kind": "unknown" }) };
    let up = name.to_ascii_uppercase();
    let tokens: Vec<&str> = up.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-')).filter(|t| !t.is_empty()).collect();
    let org = tokens.iter().any(|t| ORG_WORDS.contains(t) || ORG_WORDS.contains(&t.trim_end_matches('.')));
    let has_flag = operator_flag.is_some_and(|f| !f.trim().is_empty());
    if org || has_flag {
        json!({ "kind": "organisation", "name": name })
    } else {
        json!({ "kind": "private", "note": "Name withheld: it does not look like an organisation." })
    }
}

// ---------- upstream access ----------

/// GET JSON. Ok(None) on 404; other non-2xx statuses are errors.
fn fetch(agent: &ureq::Agent, url: &str) -> Result<Option<Value>> {
    let mut res = agent.get(url).config().http_status_as_error(false).build().call().with_context(|| format!("request failed: {}", url.split('?').next().unwrap_or(url)))?;
    let code = res.status().as_u16();
    if code == 404 {
        return Ok(None);
    }
    if !(200..300).contains(&code) {
        return Err(anyhow!("{} answered HTTP {code}", url.split('/').nth(2).unwrap_or("upstream")));
    }
    let text = res.body_mut().read_to_string().context("read response")?;
    Ok(Some(serde_json::from_str(&text).context("upstream did not return JSON")?))
}

/// Cached fetch. `None` (404) is cached briefly too, so repeated misses do not hammer the free services.
async fn cached(s: &Shared, key: String, url: String, ttl: Duration) -> Result<Option<Value>> {
    if let Some(e) = s.cache.lock().unwrap().get(&key) {
        if e.at.elapsed() < e.ttl {
            return Ok(if e.val.is_null() { None } else { Some(e.val.clone()) });
        }
    }
    let st = s.clone();
    let got = tokio::task::spawn_blocking(move || fetch(&st.agent, &url)).await.map_err(|e| anyhow!(e))??;
    let mut c = s.cache.lock().unwrap();
    if c.len() >= CACHE_MAX {
        c.retain(|_, e| e.at.elapsed() < e.ttl);
        if c.len() >= CACHE_MAX {
            let oldest = c.iter().min_by_key(|(_, e)| e.at).map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                c.remove(&k);
            }
        }
    }
    c.insert(key, Entry { at: Instant::now(), ttl: if got.is_some() { ttl } else { TTL_MISSING }, val: got.clone().unwrap_or(Value::Null) });
    Ok(got)
}

fn txt(v: &Value) -> Option<String> {
    v.as_str().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Registry record from adsbdb (primary) and hexdb (fallback/cross-check), owner filtered.
async fn registry(s: &Shared, key: &str) -> Result<Option<Value>> {
    let a = cached(s, format!("adb:{key}"), format!("{}/v0/aircraft/{key}", s.adsbdb), TTL_REGISTRY).await;
    let adb = a.as_ref().ok().cloned().flatten().and_then(|v| v["response"]["aircraft"].as_object().cloned()).map(Value::Object);
    let is_hex = valid_hex(key).is_some();
    // hexdb only answers by hex; for a tail number use the hex adsbdb gave us, if any.
    let hex = if is_hex { Some(key.to_string()) } else { adb.as_ref().and_then(|v| txt(&v["mode_s"])).map(|h| h.to_ascii_lowercase()) };
    let hdb = match &hex {
        Some(h) => cached(s, format!("hdb:{h}"), format!("{}/api/v1/aircraft/{h}", s.hexdb), TTL_REGISTRY).await.ok().flatten(),
        None => None,
    };
    if adb.is_none() && hdb.is_none() {
        if let Err(e) = a {
            return Err(e);
        }
        return Ok(None);
    }
    let pick = |x: Option<String>, y: Option<String>| x.or(y);
    let (ad, hd) = (adb.clone().unwrap_or(Value::Null), hdb.clone().unwrap_or(Value::Null));
    let owner_name = pick(txt(&ad["registered_owner"]), txt(&hd["RegisteredOwners"]));
    let flag = pick(txt(&ad["registered_owner_operator_flag_code"]), txt(&hd["OperatorFlagCode"]));
    let reg = pick(txt(&ad["registration"]), txt(&hd["Registration"]));
    let mut notes = vec![];
    if let (Some(x), Some(y)) = (txt(&ad["registration"]), txt(&hd["Registration"])) {
        if !x.eq_ignore_ascii_case(&y) {
            notes.push(format!("The two databases disagree on the registration ({x} vs {y})."));
        }
    }
    let type_code = pick(txt(&ad["icao_type"]), txt(&hd["ICAOTypeCode"]));
    let photo = txt(&ad["url_photo"]).filter(|u| u.starts_with("https://")).map(|u| json!({ "url": u, "thumb": txt(&ad["url_photo_thumbnail"]).filter(|u| u.starts_with("https://")), "credit": "airport-data.com" }));
    let mut sources = vec![];
    if adb.is_some() {
        sources.push("adsbdb");
    }
    if hdb.is_some() {
        sources.push("hexdb");
    }
    Ok(Some(json!({
        "hex": pick(txt(&ad["mode_s"]), txt(&hd["ModeS"])).map(|h| h.to_ascii_lowercase()).or(hex),
        "registration": reg,
        "type": pick(txt(&ad["type"]), txt(&hd["Type"])),
        "type_code": type_code,
        "type_info": type_code.as_deref().and_then(types::lookup).map(|t| json!({ "name": t.1, "class": t.2 })),
        "manufacturer": pick(txt(&ad["manufacturer"]), txt(&hd["Manufacturer"])),
        "country": { "iso": txt(&ad["registered_owner_country_iso_name"]), "name": txt(&ad["registered_owner_country_name"]) },
        "owner": owner_view(owner_name.as_deref(), flag.as_deref()),
        "operator_flag": flag,
        "photo": photo,
        "sources": sources,
        "notes": notes,
    })))
}

fn haversine_km(a: (f64, f64), b: (f64, f64)) -> f64 {
    let (la1, la2) = (a.0.to_radians(), b.0.to_radians());
    let (dla, dlo) = ((b.0 - a.0).to_radians(), (b.1 - a.1).to_radians());
    let h = (dla / 2.0).sin().powi(2) + la1.cos() * la2.cos() * (dlo / 2.0).sin().powi(2);
    6371.0 * 2.0 * h.sqrt().asin()
}

fn airport_view(v: &Value) -> Value {
    json!({
        "icao": txt(&v["icao_code"]).or_else(|| txt(&v["icao"])), "iata": txt(&v["iata_code"]).or_else(|| txt(&v["iata"])),
        "name": txt(&v["name"]).or_else(|| txt(&v["airport"])), "city": txt(&v["municipality"]), "region": txt(&v["region_name"]),
        "country": txt(&v["country_name"]).or_else(|| txt(&v["country_code"])), "country_iso": txt(&v["country_iso_name"]).or_else(|| txt(&v["country_code"])),
        "lat": v["latitude"].as_f64(), "lon": v["longitude"].as_f64(), "elevation_ft": v["elevation"].as_i64(),
    })
}

async fn airport(s: &Shared, code: &str) -> Result<Option<Value>> {
    let path = if code.len() == 3 { "iata" } else { "icao" };
    Ok(cached(s, format!("apt:{code}"), format!("{}/api/v1/airport/{path}/{code}", s.hexdb), TTL_STATIC).await?.map(|v| airport_view(&v)))
}

/// Route for a callsign: adsbdb first (airline + both airports), hexdb as fallback (airport codes only, completed via airport lookups).
async fn route(s: &Shared, cs: &str) -> Result<Option<Value>> {
    let adb = cached(s, format!("rt:{cs}"), format!("{}/v0/callsign/{cs}", s.adsbdb), TTL_ROUTE).await;
    if let Ok(Some(v)) = &adb {
        let fr = &v["response"]["flightroute"];
        if fr.is_object() {
            let (o, d) = (airport_view(&fr["origin"]), airport_view(&fr["destination"]));
            let dist = match (o["lat"].as_f64().zip(o["lon"].as_f64()), d["lat"].as_f64().zip(d["lon"].as_f64())) {
                (Some(a), Some(b)) => Some((haversine_km(a, b)).round()),
                _ => None,
            };
            let al = &fr["airline"];
            return Ok(Some(json!({
                "callsign": txt(&fr["callsign"]).unwrap_or(cs.into()), "iata_callsign": txt(&fr["callsign_iata"]),
                "airline": if al.is_object() { json!({ "name": txt(&al["name"]), "icao": txt(&al["icao"]), "iata": txt(&al["iata"]), "country": txt(&al["country"]), "radio": txt(&al["callsign"]) }) } else { Value::Null },
                "origin": o, "destination": d, "distance_km": dist, "source": "adsbdb",
                "caveat": "Routes are what this callsign usually flies in a community database, not proof of the current flight.",
            })));
        }
    }
    let hdb = cached(s, format!("hrt:{cs}"), format!("{}/api/v1/route/icao/{cs}", s.hexdb), TTL_ROUTE).await;
    if let Ok(Some(v)) = &hdb {
        if let Some((a, b)) = v["route"].as_str().and_then(|r| r.split_once('-')) {
            let (o, d) = (airport(s, a).await.ok().flatten(), airport(s, b).await.ok().flatten());
            let dist = match (o.as_ref().and_then(|x| x["lat"].as_f64().zip(x["lon"].as_f64())), d.as_ref().and_then(|x| x["lat"].as_f64().zip(x["lon"].as_f64()))) {
                (Some(p), Some(q)) => Some(haversine_km(p, q).round()),
                _ => None,
            };
            return Ok(Some(json!({
                "callsign": cs, "airline": Value::Null, "origin": o.unwrap_or(json!({ "icao": a })), "destination": d.unwrap_or(json!({ "icao": b })),
                "distance_km": dist, "source": "hexdb", "caveat": "Routes are what this callsign usually flies in a community database, not proof of the current flight.",
            })));
        }
    }
    match (adb, hdb) {
        (Err(e), _) => Err(e),
        (_, Err(e)) => Err(e),
        _ => Ok(None),
    }
}

// ---------- handlers ----------

async fn hex_handler(State(s): State<Shared>, Path(hex): Path<String>) -> Result<Json<Value>, ApiError> {
    let h = valid_hex(&hex).ok_or_else(|| bad("ICAO hex must be 6 hexadecimal characters, e.g. a808c5"))?;
    registry(&s, &h).await?.map(Json).ok_or_else(|| not_found("no registry entry for that ICAO hex"))
}

async fn reg_handler(State(s): State<Shared>, Path(reg): Path<String>) -> Result<Json<Value>, ApiError> {
    let r = valid_reg(&reg).ok_or_else(|| bad("registration must be 2-10 letters, digits or dashes, e.g. N617AF or G-EUUU"))?;
    registry(&s, &r).await?.map(Json).ok_or_else(|| not_found("no registry entry for that registration"))
}

async fn callsign_handler(State(s): State<Shared>, Path(cs): Path<String>) -> Result<Json<Value>, ApiError> {
    let c = valid_callsign(&cs).ok_or_else(|| bad("callsign must be 2-8 letters or digits, e.g. UAL1"))?;
    route(&s, &c).await?.map(Json).ok_or_else(|| not_found("no route known for that callsign"))
}

async fn airport_handler(State(s): State<Shared>, Path(code): Path<String>) -> Result<Json<Value>, ApiError> {
    let c = valid_airport(&code).ok_or_else(|| bad("airport code must be 3 (IATA) or 4 (ICAO) characters"))?;
    airport(&s, &c).await?.map(Json).ok_or_else(|| not_found("unknown airport"))
}

async fn airline_handler(State(s): State<Shared>, Path(code): Path<String>) -> Result<Json<Value>, ApiError> {
    let c = valid_airline(&code).ok_or_else(|| bad("airline code must be a 2-letter IATA or 3-letter ICAO designator"))?;
    let v = cached(&s, format!("al:{c}"), format!("{}/v0/airline/{c}", s.adsbdb), TTL_STATIC).await?;
    let first = v.and_then(|v| v["response"].as_array().and_then(|a| a.first().cloned())).ok_or_else(|| not_found("unknown airline"))?;
    Ok(Json(first))
}

async fn type_handler(State(s): State<Shared>, Path(code): Path<String>) -> Result<Json<Value>, ApiError> {
    let t = valid_type(&code).ok_or_else(|| bad("type designator must be 2-4 letters or digits, e.g. B738"))?;
    let known = types::lookup(&t).map(|x| json!({ "designator": x.0, "name": x.1, "class": x.2 }));
    let live = cached(&s, format!("ty:{t}"), format!("{}/v2/type/{t}", s.adsblol), TTL_LIVE).await.ok().flatten();
    let list = live.as_ref().and_then(|v| v["ac"].as_array());
    if known.is_none() && list.is_none_or(|l| l.is_empty()) {
        return Err(not_found("type designator not in the built-in list and none airborne right now"));
    }
    let sample: Vec<Value> = list.map(|l| l.iter().take(10).map(|a| json!({ "hex": a["hex"], "registration": a["r"], "callsign": txt(&a["flight"]) })).collect()).unwrap_or_default();
    Ok(Json(json!({ "type": t, "info": known, "airborne_now": list.map(|l| l.len()), "sample": sample,
        "note": "The built-in list covers common types only. The live count comes from adsb.lol and covers aircraft it currently receives." })))
}

fn opensky_row(r: &Value) -> Option<Value> {
    let a = r.as_array()?;
    let (lon, lat) = (a.get(5)?.as_f64()?, a.get(6)?.as_f64()?);
    Some(json!({ "lat": lat, "lon": lon, "alt_ft": a.get(7).and_then(Value::as_f64).map(|m| (m * 3.28084).round()), "gs_kt": a.get(9).and_then(Value::as_f64).map(|v| (v * 1.94384).round()),
        "track": a.get(10).and_then(Value::as_f64), "on_ground": a.get(8).and_then(Value::as_bool), "callsign": a.get(1).and_then(Value::as_str).map(str::trim), "last_contact": a.get(4) }))
}

async fn position_handler(State(s): State<Shared>, Path(hex): Path<String>) -> Result<Json<Value>, ApiError> {
    let h = valid_hex(&hex).ok_or_else(|| bad("ICAO hex must be 6 hexadecimal characters"))?;
    let (a, b) = tokio::join!(
        cached(&s, format!("pos-lol:{h}"), format!("{}/v2/hex/{h}", s.adsblol), TTL_LIVE),
        cached(&s, format!("pos-osk:{h}"), format!("{}/api/states/all?icao24={h}", s.opensky), TTL_LIVE.max(Duration::from_secs(30)))
    );
    let lol = match &a {
        Ok(Some(v)) => v["ac"].as_array().and_then(|l| l.first()).and_then(|x| {
            Some(json!({ "lat": x["lat"].as_f64()?, "lon": x["lon"].as_f64()?, "alt_ft": x["alt_baro"].as_f64(), "gs_kt": x["gs"].as_f64(), "track": x["track"].as_f64(), "on_ground": x["alt_baro"] == "ground", "callsign": txt(&x["flight"]) }))
        }),
        _ => None,
    };
    let osk = match &b {
        Ok(Some(v)) => v["states"].as_array().and_then(|l| l.first()).and_then(opensky_row),
        _ => None,
    };
    let src = |name: &str, pos: &Option<Value>, err: Option<String>| json!({ "source": name, "seen": pos.is_some(), "position": pos, "error": err });
    let agreement = match (&lol, &osk) {
        (Some(x), Some(y)) => Some(haversine_km((x["lat"].as_f64().unwrap(), x["lon"].as_f64().unwrap()), (y["lat"].as_f64().unwrap(), y["lon"].as_f64().unwrap())) * 10.0).map(|d| d.round() / 10.0),
        _ => None,
    };
    Ok(Json(json!({
        "hex": h,
        "sources": [src("adsb.lol", &lol, a.as_ref().err().map(|e| format!("{e:#}"))), src("OpenSky (anonymous)", &osk, b.as_ref().err().map(|e| format!("{e:#}")))],
        "distance_km": agreement,
        "note": "Neither source seeing the aircraft usually means it is not transmitting or out of coverage.",
    })))
}
#[derive(Deserialize)]
struct LookupQuery {
    q: String,
    kind: Option<String>,
}

/// One box for everything: hex, tail number, callsign. Returns whichever parts exist.
async fn lookup_handler(State(s): State<Shared>, Query(q): Query<LookupQuery>) -> Result<Json<Value>, ApiError> {
    let text = q.q.trim().to_string();
    if text.is_empty() || text.len() > 16 {
        return Err(bad("enter an ICAO hex, tail number or callsign (up to 16 characters)"));
    }
    let kind = match q.kind.as_deref() {
        None | Some("") | Some("auto") => classify(&text),
        Some("hex") => "hex",
        Some("registration") => "registration",
        Some("callsign") => "callsign",
        Some(_) => return Err(bad("kind must be auto, hex, registration or callsign")),
    };
    match kind {
        "hex" => {
            let h = valid_hex(&text).ok_or_else(|| bad("ICAO hex must be 6 hexadecimal characters"))?;
            let reg = registry(&s, &h).await?;
            Ok(Json(json!({ "kind": "hex", "query": h, "aircraft": reg })))
        }
        "registration" => {
            let r = valid_reg(&text).ok_or_else(|| bad("not a valid registration"))?;
            let reg = registry(&s, &r).await?;
            Ok(Json(json!({ "kind": "registration", "query": r, "aircraft": reg })))
        }
        "callsign" => {
            let c = valid_callsign(&text).ok_or_else(|| bad("not a valid callsign"))?;
            let rt = route(&s, &c).await?;
            Ok(Json(json!({ "kind": "callsign", "query": c, "route": rt })))
        }
        _ => Err(bad("could not tell what that is: use a 6-character ICAO hex, a tail number such as N617AF, or a callsign such as UAL1")),
    }
}

async fn tools() -> Json<Value> {
    let p = |k: &str, d: &str| json!({ "type": "object", "properties": { k: { "type": "string", "description": d } }, "required": [k] });
    Json(json!([
        { "name": "aircraft_by_hex", "description": "Registry data for an ICAO 24-bit hex address: registration, type, manufacturer, country and organisation owner (individual owners are returned only as 'private'). Static data, not a live position.",
          "method": "GET", "path": "api/hex/{hex}", "parameters": p("hex", "6 hex characters, e.g. a808c5") },
        { "name": "aircraft_by_registration", "description": "Registry data for a tail number (same fields and owner privacy rule as aircraft_by_hex).",
          "method": "GET", "path": "api/reg/{reg}", "parameters": p("reg", "registration, e.g. N617AF") },
        { "name": "aircraft_route", "description": "Airline and usual route (origin and destination airports with coordinates) for a callsign. A callsign's usual route, not proof of the current flight.",
          "method": "GET", "path": "api/callsign/{callsign}", "parameters": p("callsign", "ICAO callsign, e.g. UAL1") },
        { "name": "aircraft_airport", "description": "Airport details by ICAO (4 letters) or IATA (3 letters) code.",
          "method": "GET", "path": "api/airport/{code}", "parameters": p("code", "KSFO or SFO") },
        { "name": "aircraft_type", "description": "Type designator (for example B738): name and class from the built-in list of common types, plus how many aircraft of that type adsb.lol sees airborne right now with a few example registrations.",
          "method": "GET", "path": "api/type/{code}", "parameters": p("code", "ICAO type designator, e.g. B738") },
        { "name": "aircraft_airline", "description": "Airline by ICAO (3 letters) or IATA (2 letters) designator: name, radio callsign, country.",
          "method": "GET", "path": "api/airline/{code}", "parameters": p("code", "DAL or DL") },
        { "name": "aircraft_position_check", "description": "Where two independent open feeds (adsb.lol, OpenSky) currently see this ICAO hex, and how far apart they are.",
          "method": "GET", "path": "api/position/{hex}", "parameters": p("hex", "ICAO hex") }
    ]))
}

async fn page() -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], PAGE).into_response()
}

fn app(state: Shared) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/lookup", get(lookup_handler))
        .route("/api/hex/{hex}", get(hex_handler))
        .route("/api/reg/{reg}", get(reg_handler))
        .route("/api/callsign/{cs}", get(callsign_handler))
        .route("/api/airport/{code}", get(airport_handler))
        .route("/api/airline/{code}", get(airline_handler))
        .route("/api/type/{code}", get(type_handler))
        .route("/api/position/{hex}", get(position_handler))
        .with_state(state)
}

fn new_state(adsbdb: String, hexdb: String, adsblol: String, opensky: String) -> Shared {
    Arc::new(AppState { agent: osnt_common::http_agent("osnt-aircraft-registry/0.1 (+https://github.com/ogden-marrow/osnt-hub)"), adsbdb, hexdb, adsblol, opensky, cache: Mutex::default() })
}

#[tokio::main]
async fn main() -> Result<()> {
    let e = |k: &str, d: &str| env::var(k).unwrap_or_else(|_| d.into());
    let state = new_state(e("OSNT_ACREG_ADSBDB", "https://api.adsbdb.com"), e("OSNT_ACREG_HEXDB", "https://hexdb.io"), e("OSNT_ACREG_ADSBLOL", "https://api.adsb.lol"), e("OSNT_ACREG_OPENSKY", "https://opensky-network.org"));
    let addr: SocketAddr = e("OSNT_ACREG_BIND", "127.0.0.1:8159").parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("aircraft-registry plugin on http://{addr}");
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

    fn fake(routes: Vec<(&'static str, u16, &'static str)>) -> (String, Arc<AtomicUsize>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        std::thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                h.fetch_add(1, Ordering::SeqCst);
                let (code, body) = routes.iter().find(|(p, ..)| path.starts_with(p)).map(|(_, c, b)| (*c, b.to_string())).unwrap_or((404, "{\"response\":\"unknown\"}".into()));
                let _ = write!(s, "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            }
        });
        (base, hits)
    }

    const ADSBDB_AC: &str = r#"{"response":{"aircraft":{"type":"Honda Jet HA-420","icao_type":"HDJT","manufacturer":"Honda Aircraft Company","mode_s":"A808C5","registration":"N617AF","registered_owner_country_iso_name":"US","registered_owner_country_name":"United States","registered_owner_operator_flag_code":"CTF","registered_owner":"Cutter Flight Management","url_photo":"https://image.airport-data.com/a.jpg","url_photo_thumbnail":"https://airport-data.com/t.jpg"}}}"#;
    const ADSBDB_PRIVATE: &str = r#"{"response":{"aircraft":{"type":"Cessna 172","icao_type":"C172","manufacturer":"Cessna","mode_s":"A12345","registration":"N12345","registered_owner_country_iso_name":"US","registered_owner_country_name":"United States","registered_owner_operator_flag_code":"","registered_owner":"John Q Smith","url_photo":null}}}"#;
    const ROUTE: &str = r#"{"response":{"flightroute":{"callsign":"UAL1","callsign_iata":"UA1","airline":{"name":"United Airlines","icao":"UAL","iata":"UA","country":"United States","country_iso":"US","callsign":"UNITED"},"origin":{"country_iso_name":"US","country_name":"United States","elevation":13,"iata_code":"SFO","icao_code":"KSFO","latitude":37.619,"longitude":-122.375,"municipality":"San Francisco","name":"San Francisco International Airport"},"destination":{"country_iso_name":"SG","country_name":"Singapore","elevation":22,"iata_code":"SIN","icao_code":"WSSS","latitude":1.35019,"longitude":103.994,"municipality":"Singapore","name":"Singapore Changi Airport"}}}}"#;

    async fn get_json(app: &Router, uri: &str) -> (StatusCode, Value) {
        let res = app.clone().oneshot(Request::get(uri).body(Body::empty()).unwrap()).await.unwrap();
        let st = res.status();
        let b = res.into_body().collect().await.unwrap().to_bytes();
        (st, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    #[tokio::test]
    async fn tools_cover_every_agent_safe_route() {
        let a = app(new_state("http://127.0.0.1:1".into(), "http://127.0.0.1:1".into(), "http://127.0.0.1:1".into(), "http://127.0.0.1:1".into()));
        let (_, t) = get_json(&a, "/tools").await;
        let names: Vec<&str> = t.as_array().unwrap().iter().filter_map(|x| x["name"].as_str()).collect();
        for n in ["aircraft_by_hex", "aircraft_by_registration", "aircraft_route", "aircraft_airport", "aircraft_type", "aircraft_airline", "aircraft_position_check"] {
            assert!(names.contains(&n), "{n} missing");
        }
        assert!(t.as_array().unwrap().iter().all(|x| x["method"] == "GET" && x["path"].as_str().unwrap().starts_with("api/")));
    }

    #[test]
    fn validators() {
        assert_eq!(valid_hex(" A808C5 ").as_deref(), Some("a808c5"));
        assert!(valid_hex("a808c").is_none() && valid_hex("g808c5").is_none() && valid_hex("a808c55").is_none() && valid_hex("../etc").is_none());
        assert_eq!(valid_reg("g-euuu").as_deref(), Some("G-EUUU"));
        assert!(valid_reg("-X").is_none() && valid_reg("123456").is_none() && valid_reg("N1; DROP").is_none() && valid_reg("A").is_none() && valid_reg("ABCDEFGHIJK").is_none());
        assert!(valid_callsign("UAL1").is_some() && valid_callsign("U").is_none() && valid_callsign("UAL 1").is_none() && valid_callsign("12345").is_none());
        assert!(valid_airport("KSFO").is_some() && valid_airport("SF").is_none() && valid_airport("KSFO1").is_none());
        assert!(valid_type("B738").is_some() && valid_type("B7388").is_none() && valid_type("B/38").is_none());
    }

    #[test]
    fn classification() {
        assert_eq!(classify("a808c5"), "hex");
        assert_eq!(classify("UAL1"), "callsign");
        assert_eq!(classify("BAW12A"), "callsign");
        assert_eq!(classify("N617AF"), "registration");
        assert_eq!(classify("G-EUUU"), "registration");
        assert_eq!(classify("???"), "unknown");
    }

    #[test]
    fn owner_privacy() {
        assert_eq!(owner_view(Some("Cutter Flight Management"), Some("CTF"))["kind"], "organisation");
        assert_eq!(owner_view(Some("Wells Fargo Trust Co"), None)["kind"], "organisation");
        assert_eq!(owner_view(Some("Delta Air Lines Inc"), None)["name"], "Delta Air Lines Inc");
        let p = owner_view(Some("John Q Smith"), None);
        assert_eq!(p["kind"], "private");
        assert!(p.get("name").is_none());
        let t = owner_view(Some("Smith Family Trust"), None);
        assert_eq!(t["kind"], "private");
        assert!(!t.to_string().contains("Smith"));
        assert_eq!(owner_view(Some("   "), None)["kind"], "unknown");
        assert_eq!(owner_view(None, None)["kind"], "unknown");
    }

    #[test]
    fn haversine_sanity() {
        let d = haversine_km((37.619, -122.375), (1.35, 103.994));
        assert!((d - 13_580.0).abs() < 150.0, "{d}");
    }

    #[tokio::test]
    async fn hex_lookup_filters_owner_and_caches() {
        let (base, hits) = fake(vec![("/v0/aircraft/a808c5", 200, ADSBDB_AC), ("/api/v1/aircraft/a808c5", 200, r#"{"ModeS":"A808C5","Registration":"N617AF","ICAOTypeCode":"HDJT","RegisteredOwners":"Cutter Flight Management","OperatorFlagCode":"CTF"}"#), ("/v0/aircraft/a12345", 200, ADSBDB_PRIVATE)]);
        let a = app(new_state(base.clone(), base.clone(), base.clone(), base));
        let (st, v) = get_json(&a, "/api/hex/A808C5").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["registration"], "N617AF");
        assert_eq!(v["owner"]["name"], "Cutter Flight Management");
        assert_eq!(v["sources"], json!(["adsbdb", "hexdb"]));
        assert_eq!(v["photo"]["credit"], "airport-data.com");
        let first_hits = hits.load(Ordering::SeqCst);
        get_json(&a, "/api/hex/a808c5").await;
        assert_eq!(hits.load(Ordering::SeqCst), first_hits, "second call served from cache");
        let (_, v) = get_json(&a, "/api/hex/a12345").await;
        assert_eq!(v["owner"]["kind"], "private");
        assert!(!v.to_string().contains("Smith"), "personal name must never leave the plugin");
    }

    #[tokio::test]
    async fn errors_and_negative_cache() {
        let (base, hits) = fake(vec![]);
        let a = app(new_state(base.clone(), base.clone(), base.clone(), base));
        assert_eq!(get_json(&a, "/api/hex/zzzzzz").await.0, StatusCode::BAD_REQUEST);
        assert_eq!(get_json(&a, "/api/reg/N1%3Bx").await.0, StatusCode::BAD_REQUEST);
        assert_eq!(get_json(&a, "/api/callsign/U").await.0, StatusCode::BAD_REQUEST);
        assert_eq!(get_json(&a, "/api/lookup?q=%3F%3F%3F").await.0, StatusCode::BAD_REQUEST);
        assert_eq!(get_json(&a, "/api/hex/abcdef").await.0, StatusCode::NOT_FOUND);
        let n = hits.load(Ordering::SeqCst);
        assert_eq!(get_json(&a, "/api/hex/abcdef").await.0, StatusCode::NOT_FOUND);
        assert_eq!(hits.load(Ordering::SeqCst), n, "misses are cached briefly");
    }

    #[tokio::test]
    async fn upstream_failure_is_bad_gateway() {
        let (base, _) = fake(vec![("/v0/aircraft", 500, "oops"), ("/api/v1", 500, "oops")]);
        let a = app(new_state(base.clone(), base.clone(), base.clone(), base));
        let (st, v) = get_json(&a, "/api/hex/aaaaaa").await;
        assert_eq!(st, StatusCode::BAD_GATEWAY);
        assert!(v["error"].as_str().unwrap().contains("500"));
    }

    #[tokio::test]
    async fn route_primary_and_fallback() {
        let (base, _) = fake(vec![("/v0/callsign/UAL1", 200, ROUTE), ("/api/v1/route/icao/DLH9", 200, r#"{"flight":"DLH9","route":"EDDF-KJFK"}"#), ("/api/v1/airport/icao/EDDF", 200, r#"{"icao":"EDDF","iata":"FRA","airport":"Frankfurt","latitude":50.03,"longitude":8.57,"country_code":"DE","region_name":"Hesse"}"#), ("/api/v1/airport/icao/KJFK", 200, r#"{"icao":"KJFK","airport":"JFK","latitude":40.64,"longitude":-73.78,"country_code":"US"}"#)]);
        let a = app(new_state(base.clone(), base.clone(), base.clone(), base));
        let (st, v) = get_json(&a, "/api/callsign/ual1").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["airline"]["name"], "United Airlines");
        assert_eq!(v["origin"]["icao"], "KSFO");
        assert!(v["distance_km"].as_f64().unwrap() > 13_000.0);
        let (_, v) = get_json(&a, "/api/callsign/DLH9").await;
        assert_eq!(v["source"], "hexdb");
        assert_eq!(v["origin"]["iata"], "FRA");
        assert!(v["distance_km"].as_f64().unwrap() > 6000.0);
        let (_, v) = get_json(&a, "/api/lookup?q=UAL1").await;
        assert_eq!(v["kind"], "callsign");
    }

    #[tokio::test]
    async fn position_cross_check() {
        let lol = r#"{"ac":[{"hex":"a808c5","flight":"N617AF  ","lat":37.0,"lon":-122.0,"alt_baro":5000,"gs":200.0,"track":90.0}]}"#;
        let osk = r#"{"time":1,"states":[["a808c5","N617AF  ","United States",1,2,-122.0,37.1,1500.0,false,100.0,91.0,0.0,null,1600.0,"1200",false,0]]}"#;
        let (base, _) = fake(vec![("/v2/hex/a808c5", 200, lol), ("/api/states/all", 200, osk)]);
        let a = app(new_state(base.clone(), base.clone(), base.clone(), base));
        let (st, v) = get_json(&a, "/api/position/a808c5").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["sources"][0]["seen"], true);
        assert_eq!(v["sources"][1]["position"]["alt_ft"], 4921.0);
        let d = v["distance_km"].as_f64().unwrap();
        assert!((d - 11.1).abs() < 0.5, "{d}");
        let (base, _) = fake(vec![("/v2/hex", 200, r#"{"ac":[]}"#), ("/api/states/all", 429, "rate")]);
        let a = app(new_state(base.clone(), base.clone(), base.clone(), base));
        let (st, v) = get_json(&a, "/api/position/a808c5").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["sources"][0]["seen"], false);
        assert!(v["sources"][1]["error"].as_str().unwrap().contains("429"));
        assert!(v["distance_km"].is_null());
    }

    #[tokio::test]
    async fn type_lookup() {
        let (base, _) = fake(vec![("/v2/type/B738", 200, r#"{"ac":[{"hex":"abc123","r":"N1","flight":"X1"},{"hex":"abc124","r":"N2"}]}"#)]);
        let a = app(new_state(base.clone(), base.clone(), base.clone(), base));
        let (st, v) = get_json(&a, "/api/type/b738").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["airborne_now"], 2);
        assert_eq!(v["info"]["designator"], "B738");
        assert_eq!(get_json(&a, "/api/type/ZZZ9").await.0, StatusCode::NOT_FOUND);
        assert_eq!(get_json(&a, "/api/type/toolong").await.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn cache_is_bounded() {
        let (base, _) = fake(vec![]);
        let st = new_state(base.clone(), base.clone(), base.clone(), base);
        {
            let mut c = st.cache.lock().unwrap();
            for i in 0..CACHE_MAX {
                c.insert(format!("k{i}"), Entry { at: Instant::now(), ttl: TTL_STATIC, val: json!(1) });
            }
        }
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _ = rt.block_on(cached(&st, "new".into(), format!("{}/x", st.hexdb), TTL_STATIC));
        assert!(st.cache.lock().unwrap().len() <= CACHE_MAX);
    }
}

//! Sun & shadow plugin: sun position, shadow geometry, time-of-day and candidate-location estimates from a shadow, a yearly
//! sunrise table and an optional weather cross-check. The astronomy is pure Rust (see `sun.rs`); only the cross-check
//! calls the network (Open-Meteo and sunrise-sunset.org, fixed hosts).

mod sun;
mod timeparse;
mod util;

use std::{
    env,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use axum::{
    Json, Router,
    extract::{Query, State},
    middleware,
    response::Html,
    routing::get,
};
use serde_json::{Value, json};
use sun::{Event, day_times, position, shadow_length};
use timeparse::{date_string, iso, parse_date, parse_time};
use util::{ApiError, Cache, Guarded, Params, bad, blocking};

const PAGE: &str = include_str!("../assets/index.html");
const UA: &str = "osnt-sun-shadow/0.1 (+https://github.com/ogden-marrow/osnt-hub)";

pub struct Urls {
    pub archive: String,
    pub forecast: String,
    pub sunrise: String,
}

pub struct App {
    agent: ureq::Agent,
    urls: Urls,
    cache: Cache,
    require_gateway: bool,
}
type Shared = Arc<App>;
impl Guarded for App {
    fn require_gateway(&self) -> bool {
        self.require_gateway
    }
}

fn event_json(e: &Event) -> Value {
    match e {
        Event::At(t) => json!({ "time": iso(*t) }),
        Event::AlwaysUp => json!({ "state": "sun stays up all day" }),
        Event::AlwaysDown => json!({ "state": "sun stays down all day" }),
    }
}

fn compass(az: f64) -> &'static str {
    const N: [&str; 16] = ["N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE", "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW"];
    N[(((az.rem_euclid(360.0)) / 22.5).round() as usize) % 16]
}

fn pos_json(p: &sun::SunPos) -> Value {
    json!({
        "azimuth": round(p.azimuth, 3), "compass": compass(p.azimuth), "altitude": round(p.altitude, 3), "geometric_altitude": round(p.geometric, 3),
        "above_horizon": p.altitude > 0.0, "declination": round(p.declination, 3), "equation_of_time_min": round(p.eq_time, 3),
    })
}

fn round(v: f64, places: i32) -> f64 {
    let k = 10f64.powi(places);
    (v * k).round() / k
}

fn time_param(p: &Params) -> Result<f64, ApiError> {
    parse_time(p.req_str("time")?).map_err(bad)
}

async fn sun_handler(Query(q): Query<std::collections::HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let (lat, lon) = p.lat_lon()?;
    let t = time_param(&p)?;
    let sp = position(lat, lon, t);
    let mut v = pos_json(&sp);
    v["time"] = json!(iso(t));
    v["lat"] = json!(lat);
    v["lon"] = json!(lon);
    v["shadow_bearing"] = json!(round((sp.azimuth + 180.0).rem_euclid(360.0), 3));
    v["method"] = json!("NOAA solar position equations (Meeus); apparent altitude includes standard refraction");
    Ok(Json(v))
}

async fn shadow_handler(Query(q): Query<std::collections::HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let (lat, lon) = p.lat_lon()?;
    let t = time_param(&p)?;
    let height = p.num("height", 0.01, 10000.0)?.unwrap_or(1.0);
    let sp = position(lat, lon, t);
    let len = shadow_length(height, sp.altitude);
    let mut v = pos_json(&sp);
    v["time"] = json!(iso(t));
    v["height_m"] = json!(height);
    v["shadow_bearing"] = json!(round((sp.azimuth + 180.0).rem_euclid(360.0), 3));
    v["shadow_length_m"] = json!(len.map(|l| round(l, 3)));
    v["shadow_to_height_ratio"] = json!(len.map(|l| round(l / height, 4)));
    v["note"] = json!(if len.is_none() { "The sun is below the horizon: no shadow is cast." } else { "Flat ground assumed; a slope changes the length." });
    Ok(Json(v))
}

/// Time at which the shadow length crosses `target` on one side of solar noon. `morning` picks the rising-sun branch.
fn crossing(lat: f64, lon: f64, noon: f64, height: f64, target: f64, morning: bool) -> Option<f64> {
    let len = |t: f64| shadow_length(height, position(lat, lon, t).altitude).unwrap_or(f64::INFINITY);
    let (mut lo, mut hi) = if morning { (noon - 43200.0, noon) } else { (noon, noon + 43200.0) };
    // Shadow length falls through the morning and grows through the afternoon.
    let (l_lo, l_hi) = (len(lo), len(hi));
    if morning && !(l_lo > target && l_hi <= target) || !morning && !(l_lo <= target && l_hi > target) {
        return None;
    }
    for _ in 0..50 {
        let mid = (lo + hi) / 2.0;
        // Morning keeps len(lo) > target >= len(hi); afternoon keeps len(lo) <= target < len(hi).
        if (len(mid) > target) == morning {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Some((lo + hi) / 2.0)
}

fn branch_json(lat: f64, lon: f64, height: f64, t: f64, from: Option<f64>, to: Option<f64>) -> Value {
    let sp = position(lat, lon, t);
    json!({ "time": iso(t), "from": from.map(iso), "to": to.map(iso), "azimuth": round(sp.azimuth, 2), "compass": compass(sp.azimuth), "altitude": round(sp.altitude, 2),
            "shadow_bearing": round((sp.azimuth + 180.0).rem_euclid(360.0), 2), "shadow_length_m": shadow_length(height, sp.altitude).map(|l| round(l, 3)) })
}

async fn solve_handler(Query(q): Query<std::collections::HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let (lat, lon) = p.lat_lon()?;
    let date = parse_date(p.req_str("date")?).map_err(bad)?;
    let height = p.req_num("height", 0.01, 10000.0)?;
    let length = p.req_num("length", 0.001, 100000.0)?;
    let tol = p.num("tolerance", 0.0, 50.0)?.unwrap_or(5.0) / 100.0;
    let dt = day_times(lat, lon, date);
    let noon_len = shadow_length(height, position(lat, lon, dt.noon).altitude);
    let find = |target: f64, morning: bool| crossing(lat, lon, dt.noon, height, target, morning);
    let mut out = json!({
        "date": date_string(date), "solar_noon": iso(dt.noon), "height_m": height, "shadow_length_m": length, "tolerance_pct": tol * 100.0,
        "shortest_shadow_m": noon_len.map(|l| round(l, 3)),
        "note": "Times are UTC. Solar noon is when the shadow is shortest and points due north (northern hemisphere) or south. The same length occurs once before and once after noon.",
    });
    let mut any = false;
    for (name, morning) in [("morning", true), ("afternoon", false)] {
        out[name] = match find(length, morning) {
            Some(t) => {
                any = true;
                // A longer shadow is earlier in the morning and later in the afternoon.
                let (a, b) = (find(length * (1.0 + tol), morning), find(length * (1.0 - tol), morning));
                let (from, to) = if morning { (a, b) } else { (b, a) };
                branch_json(lat, lon, height, t, from, to)
            }
            None => Value::Null,
        };
    }
    if !any {
        out["message"] = json!(match noon_len {
            None => "The sun does not rise on this date at this latitude.".to_string(),
            Some(m) if length < m => format!("A shadow this short does not occur here on this date: the shortest is {:.2} m at solar noon.", m),
            Some(_) => "A shadow this long does not occur here on this date (the sun is too low or below the horizon).".to_string(),
        });
    }
    Ok(Json(out))
}

/// Splits a ring of (lat, lon) at the antimeridian so a map can draw it without a line across the world.
fn split_antimeridian(points: &[(f64, f64)]) -> Vec<Vec<[f64; 2]>> {
    let mut segs: Vec<Vec<[f64; 2]>> = vec![vec![]];
    let mut prev: Option<(f64, f64)> = None;
    for &(lat, lon) in points {
        if let Some((_, plon)) = prev {
            if (lon - plon).abs() > 180.0 {
                segs.push(vec![]);
            }
        }
        segs.last_mut().unwrap().push([round(lat, 4), round(lon, 4)]);
        prev = Some((lat, lon));
    }
    segs.retain(|s| s.len() > 1);
    segs
}

fn ring(when: f64, alt: f64) -> Vec<Vec<[f64; 2]>> {
    let mut pts = sun::equal_altitude_circle(when, alt, 240);
    pts.push(pts[0]);
    split_antimeridian(&pts)
}

async fn candidates_handler(Query(q): Query<std::collections::HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let when = time_param(&p)?;
    let height = p.req_num("height", 0.01, 10000.0)?;
    let length = p.req_num("length", 0.001, 100000.0)?;
    let tol = p.num("tolerance", 0.0, 50.0)?.unwrap_or(5.0) / 100.0;
    let alt_of = |l: f64| (height / l).atan().to_degrees();
    let alt = alt_of(length);
    let (alt_hi, alt_lo) = (alt_of(length * (1.0 - tol)).min(89.9), alt_of(length * (1.0 + tol)));
    let (slat, slon) = sun::subsolar(when);
    let radius = 90.0 - sun::geometric_from_apparent(alt);
    let r_out = 90.0 - sun::geometric_from_apparent(alt_lo);
    // Latitudes touched by the band and, for the centre line, the two longitudes at each 5 degree latitude step.
    let lat_min = (slat - r_out).max(-90.0);
    let lat_max = (slat + r_out).min(90.0);
    let mut table = vec![];
    let mut lat = (lat_min / 5.0).ceil() * 5.0;
    while lat <= lat_max && table.len() < 40 {
        let (latr, slr, c) = (lat.to_radians(), slat.to_radians(), radius.to_radians());
        let cosd = (c.cos() - latr.sin() * slr.sin()) / (latr.cos() * slr.cos());
        if cosd.abs() <= 1.0 {
            let d = cosd.acos().to_degrees();
            let w = |l: f64| round((l + 540.0).rem_euclid(360.0) - 180.0, 2);
            table.push(json!({ "lat": lat, "lon_a": w(slon - d), "lon_b": w(slon + d) }));
        }
        lat += 5.0;
    }
    Ok(Json(json!({
        "time": iso(when), "height_m": height, "shadow_length_m": length, "tolerance_pct": tol * 100.0,
        "sun_altitude": round(alt, 3), "sun_altitude_range": [round(alt_lo, 3), round(alt_hi, 3)],
        "subsolar_point": { "lat": round(slat, 4), "lon": round(slon, 4) },
        "angular_radius": round(radius, 3), "radius_km": round(radius * 111.195, 0),
        "latitude_range": [round(lat_min, 3), round(lat_max, 3)],
        "center": ring(when, alt), "inner": ring(when, alt_hi), "outer": ring(when, alt_lo),
        "longitudes": table,
        "note": "Every point on the centre line has the sun at exactly this altitude at this instant. Time must be UTC. Narrow it with shadow direction, terrain, language and vegetation; this does not name a place by itself.",
    })))
}

async fn year_handler(Query(q): Query<std::collections::HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let (lat, lon) = p.lat_lon()?;
    let year = p.num("year", 1900.0, 2100.0)?.unwrap_or_else(|| {
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64;
        timeparse::civil_from_days(secs.div_euclid(86400)).0 as f64
    }) as i64;
    let start = parse_date(&format!("{year:04}-01-01")).map_err(bad)?;
    let days = if timeparse::is_leap(year) { 366 } else { 365 };
    let mut rows = Vec::with_capacity(days);
    for d in 0..days {
        let ds = start + d as f64 * 86400.0;
        let t = day_times(lat, lon, ds);
        let hm = |e: &Event| match e {
            Event::At(x) => json!(iso(*x)),
            _ => Value::Null,
        };
        let state = match (&t.sunrise, &t.sunset) {
            (Event::AlwaysUp, _) | (_, Event::AlwaysUp) => "up",
            (Event::AlwaysDown, _) | (_, Event::AlwaysDown) => "down",
            _ => "",
        };
        rows.push(json!({ "date": date_string(ds), "sunrise": hm(&t.sunrise), "sunset": hm(&t.sunset), "noon": iso(t.noon), "day_hours": round(t.day_hours, 3), "noon_altitude": round(t.noon_elevation, 2), "polar": state }));
    }
    Ok(Json(json!({ "lat": lat, "lon": lon, "year": year, "note": "Times are UTC for the solar day at this longitude (rise and set may fall on the neighbouring UTC date). Sunrise and sunset use the sun's upper limb with standard refraction.", "days": rows })))
}

async fn path_handler(Query(q): Query<std::collections::HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let (lat, lon) = p.lat_lon()?;
    let date = parse_date(p.req_str("date")?).map_err(bad)?;
    let step = p.num("step", 5.0, 120.0)?.unwrap_or(30.0);
    let dt = day_times(lat, lon, date);
    let mut pts = vec![];
    let mut t = dt.noon - 43200.0;
    while t <= dt.noon + 43200.0 {
        let sp = position(lat, lon, t);
        pts.push(json!({ "time": iso(t), "azimuth": round(sp.azimuth, 2), "altitude": round(sp.altitude, 2) }));
        t += step * 60.0;
    }
    Ok(Json(json!({ "date": date_string(date), "sunrise": event_json(&dt.sunrise), "sunset": event_json(&dt.sunset), "solar_noon": iso(dt.noon), "day_hours": round(dt.day_hours, 3), "points": pts })))
}

fn cached_get(app: &App, url: &str, ttl_key: &str) -> Result<Value> {
    let key = format!("{ttl_key}|{url}");
    if let Some(v) = app.cache.get(&key) {
        return Ok(v);
    }
    let mut res = app.agent.get(url).header("Accept", "application/json").call().map_err(|e| anyhow!("upstream request failed: {e}"))?;
    let v: Value = res.body_mut().read_json().context("decode upstream response")?;
    app.cache.put(key, v.clone());
    Ok(v)
}

fn cloud_text(c: f64) -> &'static str {
    if c < 20.0 {
        "clear or nearly clear: sharp shadows expected"
    } else if c < 60.0 {
        "partly cloudy: shadows present but intermittent"
    } else if c < 85.0 {
        "mostly cloudy: shadows weak or soft"
    } else {
        "overcast: distinct shadows unlikely"
    }
}

fn weather(app: &App, lat: f64, lon: f64, when: f64) -> Result<Value> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
    let date = date_string(when);
    if when > now + 15.0 * 86400.0 {
        return Err(anyhow!("weather data is not available more than 15 days ahead"));
    }
    if when < parse_date("1940-01-01").unwrap_or(0.0) {
        return Err(anyhow!("weather archive starts in 1940"));
    }
    let use_archive = when < now - 7.0 * 86400.0;
    let base = if use_archive { &app.urls.archive } else { &app.urls.forecast };
    let url = format!(
        "{base}?latitude={lat:.4}&longitude={lon:.4}&start_date={date}&end_date={date}&hourly=cloud_cover,cloud_cover_low,temperature_2m,precipitation&timezone=GMT"
    );
    let v = cached_get(app, &url, if use_archive { "wx-archive" } else { "wx" })?;
    let hours = v["hourly"]["time"].as_array().ok_or_else(|| anyhow!("no hourly data in the response"))?;
    let idx = ((when.rem_euclid(86400.0) / 3600.0).round() as usize).min(hours.len().saturating_sub(1));
    let get = |k: &str| v["hourly"][k].get(idx).and_then(Value::as_f64);
    let cloud = get("cloud_cover").ok_or_else(|| anyhow!("no cloud cover for that hour (the archive lags real time by about two days)"))?;
    Ok(json!({
        "source": if use_archive { "Open-Meteo historical weather (ERA5 reanalysis)" } else { "Open-Meteo forecast / recent analysis" },
        "hour_utc": hours.get(idx), "cloud_cover_pct": cloud, "cloud_cover_low_pct": get("cloud_cover_low"), "temperature_c": get("temperature_2m"), "precipitation_mm": get("precipitation"),
        "reading": cloud_text(cloud), "grid_note": "Model values for a grid cell of roughly 10 to 25 km, not a station observation.",
    }))
}

fn sunrise_check(app: &App, lat: f64, lon: f64, when: f64) -> Result<Value> {
    let date = date_string(when);
    let url = format!("{}?lat={lat:.4}&lng={lon:.4}&date={date}&formatted=0", app.urls.sunrise);
    let v = cached_get(app, &url, "ss")?;
    if v["status"] != "OK" {
        return Err(anyhow!("sunrise-sunset.org answered {}", v["status"]));
    }
    let ours = day_times(lat, lon, parse_date(&date).map_err(|e| anyhow!(e))?);
    let parse = |k: &str| v["results"][k].as_str().and_then(|s| parse_time(&s.replace("+00:00", "Z")).ok());
    let (theirs_r, theirs_s) = (parse("sunrise"), parse("sunset"));
    let diff = |a: &Event, b: Option<f64>| match (a, b) {
        (Event::At(x), Some(y)) => Some(round(x - y, 0)),
        _ => None,
    };
    // The service returns the sunrise on the requested UTC date, which can differ from the solar day by one day far from Greenwich.
    let wrap = |d: Option<f64>| d.map(|x| (x + 43200.0).rem_euclid(86400.0) - 43200.0);
    Ok(json!({
        "source": "sunrise-sunset.org (cross-check only)",
        "their_sunrise": theirs_r.map(iso), "their_sunset": theirs_s.map(iso),
        "our_sunrise": event_json(&ours.sunrise), "our_sunset": event_json(&ours.sunset),
        "sunrise_diff_s": wrap(diff(&ours.sunrise, theirs_r)), "sunset_diff_s": wrap(diff(&ours.sunset, theirs_s)),
    }))
}

async fn crosscheck_handler(State(s): State<Shared>, Query(q): Query<std::collections::HashMap<String, String>>) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let (lat, lon) = p.lat_lon()?;
    let when = time_param(&p)?;
    let sp = position(lat, lon, when);
    let (a, b) = (s.clone(), s.clone());
    let (w, r) = tokio::join!(blocking(move || weather(&a, lat, lon, when)), blocking(move || sunrise_check(&b, lat, lon, when)));
    let part = |r: Result<Value, ApiError>| match r {
        Ok(v) => v,
        Err(e) => json!({ "error": e.1 }),
    };
    Ok(Json(json!({ "time": iso(when), "sun": pos_json(&sp), "weather": part(w), "sunrise_check": part(r) })))
}

async fn tools() -> Json<Value> {
    let ll = |extra: Value| {
        let mut props = json!({ "lat": { "type": "number", "description": "latitude, -90..90" }, "lon": { "type": "number", "description": "longitude east-positive, -180..180" } });
        for (k, v) in extra.as_object().unwrap() {
            props[k] = v.clone();
        }
        props
    };
    let time = json!({ "time": { "type": "string", "description": "UTC instant, ISO 8601 (2024-05-02T14:11:00Z; an offset such as +02:00 is honoured)" } });
    let shadow = json!({
        "height": { "type": "number", "description": "object height in metres" }, "length": { "type": "number", "description": "measured shadow length in metres" },
        "tolerance": { "type": "number", "description": "measurement uncertainty in percent (default 5)" } });
    let mut cand_props = time.as_object().unwrap().clone();
    cand_props.extend(shadow.as_object().unwrap().clone());
    let mut solve_props = ll(shadow.clone());
    solve_props["date"] = json!({ "type": "string", "description": "local solar date YYYY-MM-DD" });
    let mut shadow_props = ll(time.clone());
    shadow_props["height"] = json!({ "type": "number", "description": "object height in metres (default 1)" });
    Json(json!([
        { "name": "sun_position", "description": "Sun azimuth and apparent altitude for a latitude, longitude and UTC time (NOAA/Meeus equations).",
          "method": "GET", "path": "api/sun", "parameters": { "type": "object", "properties": ll(time.clone()), "required": ["lat", "lon", "time"] } },
        { "name": "sun_shadow", "description": "Shadow length and bearing cast by an object of a given height at a place and UTC time.",
          "method": "GET", "path": "api/shadow", "parameters": { "type": "object", "properties": shadow_props, "required": ["lat", "lon", "time"] } },
        { "name": "sun_candidates", "description": "ShadowFinder-style: given an object height, its shadow length and the UTC time of a photo, return the circle of places (and latitude range) where the sun had that altitude.",
          "method": "GET", "path": "api/candidates", "parameters": { "type": "object", "properties": cand_props, "required": ["time", "height", "length"] } },
        { "name": "sun_time_from_shadow", "description": "At a known place and date, the times of day (morning and afternoon, UTC) when an object of a given height casts a shadow of a given length.",
          "method": "GET", "path": "api/solve", "parameters": { "type": "object", "properties": solve_props, "required": ["lat", "lon", "date", "height", "length"] } },
        { "name": "sun_weather_check", "description": "Cross-check a claimed time: modelled cloud cover and temperature from Open-Meteo plus a sunrise/sunset comparison.",
          "method": "GET", "path": "api/crosscheck", "parameters": { "type": "object", "properties": ll(time), "required": ["lat", "lon", "time"] } }
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

pub fn router(app: App) -> Router {
    let state: Shared = Arc::new(app);
    let api = Router::new()
        .route("/api/sun", get(sun_handler))
        .route("/api/shadow", get(shadow_handler))
        .route("/api/solve", get(solve_handler))
        .route("/api/candidates", get(candidates_handler))
        .route("/api/year", get(year_handler))
        .route("/api/path", get(path_handler))
        .route("/api/crosscheck", get(crosscheck_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), util::guard::<App>));
    Router::new().route("/", get(page)).route("/tools", get(tools)).merge(api).with_state(state)
}

pub fn new_app(urls: Urls, require_gateway: bool) -> App {
    App { agent: osnt_common::http_agent(UA), urls, cache: Cache::new(Duration::from_secs(3600), 256), require_gateway }
}

#[tokio::main]
async fn main() -> Result<()> {
    let var = |k: &str, d: &str| env::var(k).unwrap_or_else(|_| d.into());
    let urls = Urls {
        archive: var("OSNT_SUN_SHADOW_METEO_ARCHIVE", "https://archive-api.open-meteo.com/v1/archive"),
        forecast: var("OSNT_SUN_SHADOW_METEO_FORECAST", "https://api.open-meteo.com/v1/forecast"),
        sunrise: var("OSNT_SUN_SHADOW_SUNRISE", "https://api.sunrise-sunset.org/json"),
    };
    let app = router(new_app(urls, util::gateway_configured()));
    let addr: SocketAddr = var("OSNT_SUN_SHADOW_BIND", "127.0.0.1:8144").parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("sun-shadow plugin on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests;

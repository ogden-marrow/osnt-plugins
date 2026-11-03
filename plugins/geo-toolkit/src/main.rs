//! Coordinates & geodesy toolkit: conversion between coordinate systems, geodesic distance/bearing/destination,
//! circle/box/grid generators, GeoJSON clean-up with KML/GPX export, and a text scanner for coordinates.
//! Almost everything is offline maths; only the optional timezone lookup calls Open-Meteo.

mod coords;
mod geodesy;
mod geojson;
mod scan;
mod util;

use std::{collections::HashMap, env, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Result, anyhow};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Query, State},
    http::header,
    middleware,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use coords::LL;
use serde_json::{Value, json};
use util::{ApiError, Cache, Guarded, Params, bad, blocking_api};

const PAGE: &str = include_str!("../assets/index.html");
const UA: &str = "osnt-geo-toolkit/0.1 (+https://github.com/ogden-marrow/osnt-hub)";
const BODY_LIMIT: usize = 2 * 1024 * 1024;

pub struct App {
    agent: ureq::Agent,
    meteo: String,
    cache: Cache,
    require_gateway: bool,
}
type Shared = Arc<App>;
impl Guarded for App {
    fn require_gateway(&self) -> bool {
        self.require_gateway
    }
}
type Q = Query<HashMap<String, String>>;

fn r(v: f64, p: i32) -> f64 {
    let k = 10f64.powi(p);
    (v * k).round() / k
}

fn reference(p: &Params) -> Result<Option<LL>, ApiError> {
    match p.str("ref") {
        None => Ok(None),
        Some(s) => coords::parse_pair(s, false).map(Some).map_err(|e| bad(format!("ref: {e}"))),
    }
}

fn point(p: &Params, key: &str) -> Result<LL, ApiError> {
    let s = p.req_str(key)?;
    coords::parse(s, reference(p)?, p.str("order") == Some("lonlat")).map(|x| x.ll).map_err(|e| bad(format!("{key}: {e}")))
}

fn formats(ll: LL) -> Vec<Value> {
    let mut f = vec![];
    let mut add = |id: &str, label: &str, v: String| f.push(json!({ "id": id, "label": label, "value": v }));
    add("dd", "Decimal degrees", format!("{:.6}, {:.6}", ll.lat, ll.lon));
    add("ddm", "Degrees, decimal minutes", format!("{}, {}", coords::fmt_dms(ll.lat, 'N', 'S', false), coords::fmt_dms(ll.lon, 'E', 'W', false)));
    add("dms", "Degrees, minutes, seconds", format!("{}, {}", coords::fmt_dms(ll.lat, 'N', 'S', true), coords::fmt_dms(ll.lon, 'E', 'W', true)));
    match coords::to_utm(ll) {
        Some(u) => {
            add("utm", "UTM (WGS84)", u.text());
            add("utm-detail", "UTM detail", format!("zone {} band {} {} E {:.2} N {:.2}", u.zone, u.band, if u.north { "north" } else { "south" }, u.easting, u.northing));
            if let Some(m) = coords::to_mgrs(ll, 5) {
                add("mgrs", "MGRS (1 m)", format!("{} {} {} {}", &m[..m.len() - 10 - 2], &m[m.len() - 12..m.len() - 10], &m[m.len() - 10..m.len() - 5], &m[m.len() - 5..]));
            }
            if let Some(m) = coords::to_mgrs(ll, 3) {
                add("mgrs100", "MGRS (100 m)", m);
            }
        }
        None => add("utm", "UTM / MGRS", "not defined here (UTM covers 80°S to 84°N; polar areas use UPS)".into()),
    }
    add("geohash", "Geohash (9)", coords::to_geohash(ll, 9));
    add("pluscode", "Plus Code (10)", coords::to_pluscode(ll, 10));
    add("pluscode11", "Plus Code (11)", coords::to_pluscode(ll, 11));
    add("maidenhead", "Maidenhead (6)", coords::to_maidenhead(ll, 3));
    if let Some((x, y)) = coords::web_mercator(ll) {
        add("mercator", "Web Mercator (EPSG:3857)", format!("{x:.2}, {y:.2}"));
    }
    add("geo", "geo: URI", format!("geo:{:.6},{:.6}", ll.lat, ll.lon));
    f
}

async fn convert_handler(Query(q): Q) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let s = p.req_str("q")?;
    let parsed = match coords::parse(s, reference(&p)?, p.str("order") == Some("lonlat")) {
        Ok(x) => x,
        Err(e) => match scan::fallback(s) {
            Some((ll, kind)) => coords::Parsed { ll, kind, bbox: None },
            None => return Err(bad(e)),
        },
    };
    let ll = parsed.ll;
    let mut neighbours = vec![];
    if parsed.kind == "geohash" {
        neighbours = coords::geohash_neighbours(ll, s.trim().len());
    }
    let nominal = (ll.lon / 15.0 * 100.0).round() / 100.0;
    Ok(Json(json!({
        "input": s, "kind": parsed.kind, "lat": r(ll.lat, 8), "lon": r(ll.lon, 8), "bbox": parsed.bbox, "formats": formats(ll), "geohash_neighbours": neighbours,
        "nominal_utc_offset_hours": nominal, "links": { "openstreetmap": format!("https://www.openstreetmap.org/?mlat={:.6}&mlon={:.6}#map=16/{:.6}/{:.6}", ll.lat, ll.lon, ll.lat, ll.lon) },
        "note": "Nominal offset is longitude/15 (solar time), not the legal timezone: use /api/timezone for that.",
    })))
}

async fn distance_handler(Query(q): Q) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let pts: Vec<LL> = if let Some(list) = p.str("points") {
        let parts: Vec<&str> = list.split('|').map(str::trim).filter(|x| !x.is_empty()).collect();
        if parts.len() < 2 || parts.len() > 50 {
            return Err(bad("points needs 2 to 50 coordinates separated by |"));
        }
        let rf = reference(&p)?;
        parts.iter().map(|s| coords::parse(s, rf, p.str("order") == Some("lonlat")).map(|x| x.ll).map_err(|e| bad(format!("{s}: {e}")))).collect::<Result<_, _>>()?
    } else {
        vec![point(&p, "a")?, point(&p, "b")?]
    };
    Ok(Json(geodesy::path(&pts)))
}

async fn destination_handler(Query(q): Q) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let from = point(&p, "from")?;
    let bearing = p.req_num("bearing", -360.0, 720.0)?;
    let km = p.num("km", 0.0, 40_000.0)?;
    let m = p.num("meters", 0.0, 40_000_000.0)?;
    let dist = match (m, km) {
        (Some(m), _) => m,
        (None, Some(k)) => k * 1000.0,
        _ => return Err(bad("give meters or km")),
    };
    let d = geodesy::direct(from, bearing.rem_euclid(360.0), dist);
    Ok(Json(json!({ "lat": r(d.lat, 8), "lon": r(d.lon, 8), "formats": formats(d), "bearing": bearing.rem_euclid(360.0), "meters": dist })))
}

async fn generate_handler(Query(q): Q) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    match p.req_str("kind")? {
        "circle" => {
            let c = point(&p, "center")?;
            let radius = p.req_num("radius", 1.0, 5_000_000.0)?;
            let n = p.num("points", 8.0, 720.0)?.unwrap_or(72.0) as usize;
            let fc = json!({ "type": "FeatureCollection", "features": [geodesy::circle(c, radius, n)] });
            let b = geodesy::bbox_around(c, radius);
            Ok(Json(json!({ "geojson": fc, "bbox": b })))
        }
        "bbox" => {
            let c = point(&p, "center")?;
            let radius = p.req_num("radius", 1.0, 5_000_000.0)?;
            let b = geodesy::bbox_around(c, radius);
            let feat = geodesy::box_feature(b, json!({ "kind": "bbox" }));
            Ok(Json(json!({ "bbox": b.map(|v| r(v, 7)), "bbox_text": format!("{:.6},{:.6},{:.6},{:.6}", b[1], b[0], b[3], b[2]), "geojson": { "type": "FeatureCollection", "features": [feat] } })))
        }
        "grid" => {
            let cell = p.req_num("cell", 1.0, 1_000_000.0)?;
            let b: [f64; 4] = if let Some(bb) = p.str("bbox") {
                let v: Vec<f64> = bb.split(',').map(|x| x.trim().parse::<f64>()).collect::<Result<_, _>>().map_err(|_| bad("bbox must be west,south,east,north"))?;
                if v.len() != 4 || v[1].abs() > 90.0 || v[3].abs() > 90.0 || v[0].abs() > 180.0 || v[2].abs() > 180.0 {
                    return Err(bad("bbox must be west,south,east,north within valid ranges"));
                }
                [v[1], v[0], v[3], v[2]]
            } else {
                geodesy::bbox_around(point(&p, "center")?, p.req_num("radius", 1.0, 5_000_000.0)?)
            };
            Ok(Json(json!({ "geojson": geodesy::grid(b, cell, 2500).map_err(bad)?, "bbox": b })))
        }
        _ => Err(bad("kind must be circle, bbox or grid")),
    }
}

fn parse_body(body: &Bytes) -> Result<Value, ApiError> {
    serde_json::from_slice(body).map_err(|e| bad(format!("body is not valid JSON: {e}")))
}

/// Accepts either the GeoJSON itself or `{ "geojson": <GeoJSON or a string of it>, ...options }`.
fn geojson_input(v: &Value) -> Result<(Value, i32, bool), ApiError> {
    let wrapped = v.get("geojson").is_some() && v.get("type").is_none();
    let gj = if wrapped {
        match &v["geojson"] {
            Value::String(s) => serde_json::from_str(s).map_err(|e| bad(format!("geojson text is not valid JSON: {e}")))?,
            o => o.clone(),
        }
    } else {
        v.clone()
    };
    let decimals = if wrapped { v["decimals"].as_i64().unwrap_or(6) } else { 6 };
    if !(0..=9).contains(&decimals) {
        return Err(bad("decimals must be 0..9"));
    }
    Ok((gj, decimals as i32, if wrapped { v["keep_properties"].as_bool().unwrap_or(true) } else { true }))
}

async fn geojson_handler(body: Bytes) -> Result<Json<Value>, ApiError> {
    let (gj, d, keep) = geojson_input(&parse_body(&body)?)?;
    let c = geojson::clean(&gj, d, keep).map_err(bad)?;
    Ok(Json(json!({ "cleaned": c.collection, "stats": geojson::stats(&c.collection), "warnings": c.warnings })))
}

async fn export_handler(body: Bytes) -> Result<Response, ApiError> {
    let v = parse_body(&body)?;
    let (gj, d, keep) = geojson_input(&v)?;
    let fmt = v["format"].as_str().unwrap_or("kml");
    let title: String = v["name"].as_str().unwrap_or("OSNT export").chars().take(80).collect();
    let c = geojson::clean(&gj, d, keep).map_err(bad)?;
    let (ctype, ext, text) = match fmt {
        "kml" => ("application/vnd.google-earth.kml+xml", "kml", geojson::to_kml(&c.collection, &title)),
        "gpx" => ("application/gpx+xml", "gpx", geojson::to_gpx(&c.collection, &title)),
        "geojson" => ("application/geo+json", "geojson", serde_json::to_string_pretty(&c.collection).unwrap_or_default()),
        _ => return Err(bad("format must be kml, gpx or geojson")),
    };
    Ok(([(header::CONTENT_TYPE, ctype.to_string()), (header::CONTENT_DISPOSITION, format!("attachment; filename=\"osnt-export.{ext}\""))], text).into_response())
}

async fn extract_handler(State(_s): State<Shared>, Query(q): Q, body: Bytes) -> Result<Json<Value>, ApiError> {
    let text = if body.is_empty() { Params(q).req_str("text")?.to_string() } else { String::from_utf8_lossy(&body).into_owned() };
    Ok(Json(scan::scan(&text).map_err(bad)?))
}

fn tz_lookup(app: &App, lat: f64, lon: f64) -> Result<Value> {
    let url = format!("{}/v1/forecast?latitude={lat:.4}&longitude={lon:.4}&current=temperature_2m&timezone=auto&forecast_days=1", app.meteo);
    if let Some(v) = app.cache.get(&url) {
        return Ok(v);
    }
    let mut res = app.agent.get(&url).header("Accept", "application/json").call().map_err(|e| anyhow!("{e}"))?;
    let v: Value = res.body_mut().read_json()?;
    let out = json!({ "timezone": v["timezone"], "abbreviation": v["timezone_abbreviation"], "utc_offset_seconds": v["utc_offset_seconds"] });
    if out["timezone"].is_string() {
        app.cache.put(url, out.clone());
    }
    Ok(out)
}

async fn timezone_handler(State(s): State<Shared>, Query(q): Q) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let (lat, lon) = (p.req_num("lat", -90.0, 90.0)?, p.req_num("lon", -180.0, 180.0)?);
    Ok(Json(blocking_api(move || {
        let nominal = (lon / 15.0 * 100.0).round() / 100.0;
        Ok(match tz_lookup(&s, lat, lon) {
            Ok(t) => json!({ "lat": lat, "lon": lon, "timezone": t["timezone"], "abbreviation": t["abbreviation"], "utc_offset_hours": t["utc_offset_seconds"].as_f64().map(|x| x / 3600.0), "nominal_solar_offset_hours": nominal, "source": "Open-Meteo (current offset, includes daylight saving)" }),
            Err(e) => json!({ "lat": lat, "lon": lon, "timezone": null, "nominal_solar_offset_hours": nominal, "source": "offline estimate only", "warning": format!("timezone lookup unavailable: {e}") }),
        })
    }).await?))
}

async fn tools() -> Json<Value> {
    let s = |d: &str| json!({ "type": "string", "description": d });
    Json(json!([
        { "name": "geo_convert", "description": "Parse a coordinate (decimal, DMS, UTM, MGRS, geohash, Plus Code, Maidenhead) and return it in all formats.",
          "method": "GET", "path": "api/convert", "parameters": { "type": "object", "properties": { "q": s("the coordinate text"), "ref": s("reference 'lat, lon' needed for short Plus Codes") }, "required": ["q"] } },
        { "name": "geo_distance", "description": "Geodesic distance, initial and final bearing and midpoint between two coordinates (WGS84 ellipsoid).",
          "method": "GET", "path": "api/distance", "parameters": { "type": "object", "properties": { "a": s("first coordinate"), "b": s("second coordinate") }, "required": ["a", "b"] } },
        { "name": "geo_extract", "description": "Find coordinates (decimal, DMS, UTM, MGRS, Plus Codes, map-URL fragments) in a piece of text and return them with positions.",
          "method": "GET", "path": "api/extract", "parameters": { "type": "object", "properties": { "text": s("text to scan, up to 4000 characters") }, "required": ["text"] } }
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

pub fn router(app: App) -> Router {
    let state: Shared = Arc::new(app);
    let api = Router::new()
        .route("/api/convert", get(convert_handler))
        .route("/api/distance", get(distance_handler))
        .route("/api/destination", get(destination_handler))
        .route("/api/generate", get(generate_handler))
        .route("/api/timezone", get(timezone_handler))
        .route("/api/extract", get(extract_handler).post(extract_handler))
        .route("/api/geojson", post(geojson_handler))
        .route("/api/export", post(export_handler))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .route_layer(middleware::from_fn_with_state(state.clone(), util::guard::<App>));
    Router::new().route("/", get(page)).route("/tools", get(tools)).merge(api).with_state(state)
}

pub fn new_app(meteo: String, require_gateway: bool) -> App {
    App { agent: osnt_common::http_agent(UA), meteo: meteo.trim_end_matches('/').to_string(), cache: Cache::new(Duration::from_secs(6 * 3600), 200), require_gateway }
}

#[tokio::main]
async fn main() -> Result<()> {
    let var = |k: &str, d: &str| env::var(k).unwrap_or_else(|_| d.into());
    let app = router(new_app(var("OSNT_GEO_TOOLKIT_METEO", "https://api.open-meteo.com"), util::gateway_configured()));
    let addr: SocketAddr = var("OSNT_GEO_TOOLKIT_BIND", "127.0.0.1:8148").parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("geo-toolkit plugin on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests;

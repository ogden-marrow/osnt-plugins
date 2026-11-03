//! Terrain plugin: elevation, profile, line of sight, horizon silhouette and viewshed from decoded Terrarium tiles.
//! Tiles are fetched on demand from one fixed host, cached on disk with a size cap, and never mirrored in bulk.

mod analysis;
mod tiles;
mod util;

use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    middleware,
    response::Html,
    routing::get,
};
use serde_json::{Value, json};
use tiles::Tiles;
use util::{ApiError, Cache, Guarded, Params, bad, blocking, blocking_api};

const PAGE: &str = include_str!("../assets/index.html");
const UA: &str = "osnt-terrain-view/0.1 (+https://github.com/ogden-marrow/osnt-hub)";
const MAX_TILES: usize = 150;

pub struct Config {
    pub tiles: String,
    pub state: PathBuf,
    pub open_meteo: String,
    pub opentopodata: String,
    pub disk_cap: u64,
}

pub struct App {
    agent: ureq::Agent,
    tiles: Tiles,
    cfg: Config,
    cache: Cache,
    heavy: Arc<tokio::sync::Semaphore>,
    require_gateway: bool,
}
type Shared = Arc<App>;
impl Guarded for App {
    fn require_gateway(&self) -> bool {
        self.require_gateway
    }
}
type Q = Query<HashMap<String, String>>;

fn r1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

fn tile_error(failed: &[String], msg: String) -> ApiError {
    if failed.is_empty() {
        ApiError(StatusCode::UNPROCESSABLE_ENTITY, msg)
    } else {
        ApiError(StatusCode::BAD_GATEWAY, format!("{msg} (tile source problem: {})", failed[0]))
    }
}

fn line_params(p: &Params, max_len: f64) -> Result<analysis::Line, ApiError> {
    let l = analysis::Line {
        lat1: p.req_num("lat1", -85.0, 85.0)?,
        lon1: p.req_num("lon1", -180.0, 180.0)?,
        lat2: p.req_num("lat2", -85.0, 85.0)?,
        lon2: p.req_num("lon2", -180.0, 180.0)?,
        n: p.num("n", 10.0, 400.0)?.unwrap_or(200.0) as usize,
    };
    if l.length() < 1.0 {
        return Err(bad("the two points are the same place"));
    }
    if l.length() > max_len {
        return Err(bad(format!("the line is limited to {} km", max_len / 1000.0)));
    }
    Ok(l)
}

async fn permit(s: &App) -> Result<tokio::sync::OwnedSemaphorePermit, ApiError> {
    s.heavy.clone().acquire_owned().await.map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "shutting down".into()))
}

fn external(app: &App, url: &str) -> Result<Value> {
    if let Some(v) = app.cache.get(url) {
        return Ok(v);
    }
    let mut r = app.agent.get(url).header("Accept", "application/json").call().map_err(|e| anyhow!("{e}"))?;
    let v: Value = r.body_mut().read_json().context("decode response")?;
    app.cache.put(url.to_string(), v.clone());
    Ok(v)
}

async fn elevation_handler(State(s): State<Shared>, Query(q): Q) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let lat = p.req_num("lat", -85.0, 85.0)?;
    let lon = p.req_num("lon", -180.0, 180.0)?;
    let z = p.num("zoom", 6.0, tiles::MAX_ZOOM as f64)?.unwrap_or(12.0) as u8;
    let check = p.str("check").unwrap_or("none").to_string();
    if !["none", "openmeteo", "all"].contains(&check.as_str()) {
        return Err(bad("check must be none, openmeteo or all"));
    }
    let _g = permit(&s).await?;
    Ok(Json(blocking_api(move || {
        let set = analysis::needed_set(std::iter::once(analysis::Sample { lat, lon, z }));
        let (field, failed) = s.tiles.field(&set);
        let e = field.elev(lat, lon, z).ok_or_else(|| tile_error(&failed, "no elevation data at this point (open ocean tiles may be absent)".into()))?;
        let mut out = json!({ "lat": lat, "lon": lon, "elevation_m": r1(e), "source": "Terrarium tiles", "tile_zoom": z,
            "resolution_m": r1(156_543.03 * lat.to_radians().cos().max(0.05) / (1u64 << z) as f64), "checks": {} });
        if e < 0.0 {
            out["note"] = json!("Below sea level: over the ocean this is sea-floor depth (the sea surface itself is 0 m, which is what Open-Meteo reports); on land it is a true depression such as a dry lake or the Dead Sea shore.");
        }
        if check != "none" {
            let om = external(&s, &format!("{}/v1/elevation?latitude={lat:.5}&longitude={lon:.5}", s.cfg.open_meteo)).ok().and_then(|v| v["elevation"][0].as_f64());
            out["checks"]["open_meteo_m"] = json!(om);
        }
        if check == "all" {
            let ot = external(&s, &format!("{}/v1/srtm30m?locations={lat:.5},{lon:.5}", s.cfg.opentopodata)).ok().and_then(|v| v["results"][0]["elevation"].as_f64());
            out["checks"]["opentopodata_srtm30m_m"] = json!(ot);
        }
        let diffs: Vec<f64> = out["checks"].as_object().map(|o| o.values().filter_map(Value::as_f64).map(|v| (v - e).abs()).collect()).unwrap_or_default();
        out["max_difference_m"] = json!(diffs.iter().cloned().fold(None, |m: Option<f64>, d| Some(m.map_or(d, |x| x.max(d)))).map(r1));
        Ok(out)
    }).await?))
}

async fn profile_handler(State(s): State<Shared>, Query(q): Q) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let line = line_params(&p, 500_000.0)?;
    let _g = permit(&s).await?;
    Ok(Json(blocking_api(move || {
        let set = analysis::needed_set(line.samples().into_iter().map(|x| x.1));
        let (field, failed) = s.tiles.field(&set);
        analysis::profile(&field, &line).map_err(|m| tile_error(&failed, m))
    }).await?))
}

async fn los_handler(State(s): State<Shared>, Query(q): Q) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let line = line_params(&p, 300_000.0)?;
    let (h1, h2) = (p.num("h1", 0.0, 10000.0)?.unwrap_or(1.7), p.num("h2", 0.0, 10000.0)?.unwrap_or(1.7));
    let k = p.num("k", 0.0, 0.5)?.unwrap_or(0.13);
    let _g = permit(&s).await?;
    Ok(Json(blocking_api(move || {
        let set = analysis::needed_set(line.samples().into_iter().map(|x| x.1));
        let (field, failed) = s.tiles.field(&set);
        analysis::line_of_sight(&field, &line, h1, h2, k).map_err(|m| tile_error(&failed, m))
    }).await?))
}

async fn horizon_handler(State(s): State<Shared>, Query(q): Q) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let h = analysis::Horizon {
        lat: p.req_num("lat", -85.0, 85.0)?,
        lon: p.req_num("lon", -180.0, 180.0)?,
        eye: p.num("eye", 0.0, 1000.0)?.unwrap_or(1.7),
        radius: p.num("radius_km", 1.0, 100.0)?.unwrap_or(30.0) * 1000.0,
        step: p.num("step", 0.25, 5.0)?.unwrap_or(1.0),
        k: p.num("k", 0.0, 0.5)?.unwrap_or(0.13),
    };
    let _g = permit(&s).await?;
    Ok(Json(blocking_api(move || {
        let set = h.plan();
        if set.len() > MAX_TILES {
            return Err(bad(format!("that range needs {} tiles; reduce the radius (limit {MAX_TILES})", set.len())));
        }
        let (field, failed) = s.tiles.field(&set);
        let mut v = analysis::horizon(&field, &h).map_err(|m| tile_error(&failed, m))?;
        v["tiles"] = json!({ "used": field.tile_count(), "missing": field.missing(), "failed": failed.len() });
        Ok(v)
    }).await?))
}

async fn viewshed_handler(State(s): State<Shared>, Query(q): Q) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let v = analysis::Viewshed {
        lat: p.req_num("lat", -85.0, 85.0)?,
        lon: p.req_num("lon", -180.0, 180.0)?,
        eye: p.num("eye", 0.0, 1000.0)?.unwrap_or(1.7),
        target: p.num("target", 0.0, 1000.0)?.unwrap_or(0.0),
        radius: p.num("radius_km", 0.5, 40.0)?.unwrap_or(10.0) * 1000.0,
        from: p.num("from", 0.0, 360.0)?.unwrap_or(0.0),
        span: p.num("span", 5.0, 360.0)?.unwrap_or(360.0),
        step: p.num("step", 0.5, 10.0)?.unwrap_or(2.0),
        k: p.num("k", 0.0, 0.5)?.unwrap_or(0.13),
    };
    let _g = permit(&s).await?;
    Ok(Json(blocking_api(move || {
        let set = v.plan();
        if set.len() > MAX_TILES {
            return Err(bad(format!("that range needs {} tiles; reduce the radius (limit {MAX_TILES})", set.len())));
        }
        let (field, failed) = s.tiles.field(&set);
        analysis::viewshed(&field, &v).map_err(|m| tile_error(&failed, m))
    }).await?))
}

async fn status_handler(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    let v = blocking(move || Ok(json!({ "cache_bytes": s.tiles.disk_bytes(), "cache_cap_bytes": s.cfg.disk_cap, "tiles_downloaded_this_run": s.tiles.fetched.load(Ordering::Relaxed) }))).await?;
    Ok(Json(v))
}

async fn tools() -> Json<Value> {
    let n = |d: &str| json!({ "type": "number", "description": d });
    let pt = json!({ "lat": n("latitude"), "lon": n("longitude") });
    let two = json!({ "lat1": n("start latitude"), "lon1": n("start longitude"), "lat2": n("end latitude"), "lon2": n("end longitude") });
    let mut los = two.as_object().unwrap().clone();
    los.insert("h1".into(), n("observer eye height above ground, m (default 1.7)"));
    los.insert("h2".into(), n("target height above ground, m (default 1.7)"));
    let mut hor = pt.as_object().unwrap().clone();
    hor.insert("radius_km".into(), n("search range, 1..100 (default 30)"));
    hor.insert("eye".into(), n("eye height above ground, m"));
    let mut elev = pt.as_object().unwrap().clone();
    elev.insert("check".into(), json!({ "type": "string", "description": "none (default), openmeteo or all: cross-check with other elevation services" }));
    Json(json!([
        { "name": "terrain_elevation", "description": "Ground elevation in metres at a point (Terrarium tiles), optionally cross-checked.", "method": "GET", "path": "api/elevation",
          "parameters": { "type": "object", "properties": elev, "required": ["lat", "lon"] } },
        { "name": "terrain_profile", "description": "Elevation profile along a line between two points (samples, min, max, gain, loss).", "method": "GET", "path": "api/profile",
          "parameters": { "type": "object", "properties": two, "required": ["lat1", "lon1", "lat2", "lon2"] } },
        { "name": "terrain_los", "description": "Is there an optical line of sight between two points over the terrain, with Earth curvature and refraction? Returns the first obstruction.", "method": "GET", "path": "api/los",
          "parameters": { "type": "object", "properties": los, "required": ["lat1", "lon1", "lat2", "lon2"] } },
        { "name": "terrain_horizon", "description": "Horizon silhouette (elevation angle for each azimuth) seen from a point, with the most prominent peaks, to compare with a photo's skyline.", "method": "GET", "path": "api/horizon",
          "parameters": { "type": "object", "properties": hor, "required": ["lat", "lon"] } }
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

pub fn router(app: App) -> Router {
    let state: Shared = Arc::new(app);
    let api = Router::new()
        .route("/api/elevation", get(elevation_handler))
        .route("/api/profile", get(profile_handler))
        .route("/api/los", get(los_handler))
        .route("/api/horizon", get(horizon_handler))
        .route("/api/viewshed", get(viewshed_handler))
        .route("/api/status", get(status_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), util::guard::<App>));
    Router::new().route("/", get(page)).route("/tools", get(tools)).merge(api).with_state(state)
}

pub fn new_app(cfg: Config, require_gateway: bool) -> App {
    let agent = osnt_common::http_agent(UA);
    let tiles = Tiles::new(agent.clone(), cfg.tiles.clone(), cfg.state.join("tiles"), cfg.disk_cap, 128);
    App { agent, tiles, cfg, cache: Cache::new(Duration::from_secs(86400), 200), heavy: Arc::new(tokio::sync::Semaphore::new(2)), require_gateway }
}

#[tokio::main]
async fn main() -> Result<()> {
    let var = |k: &str, d: &str| env::var(k).unwrap_or_else(|_| d.into());
    let cfg = Config {
        tiles: var("OSNT_TERRAIN_TILES", "https://s3.amazonaws.com/elevation-tiles-prod/terrarium"),
        state: PathBuf::from(var("OSNT_TERRAIN_STATE", &env::temp_dir().join("osnt-terrain-view").to_string_lossy())),
        open_meteo: var("OSNT_TERRAIN_OPENMETEO", "https://api.open-meteo.com"),
        opentopodata: var("OSNT_TERRAIN_OPENTOPODATA", "https://api.opentopodata.org"),
        disk_cap: 150 * 1024 * 1024,
    };
    let app = router(new_app(cfg, util::gateway_configured()));
    let addr: SocketAddr = var("OSNT_TERRAIN_BIND", "127.0.0.1:8146").parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("terrain-view plugin on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests;

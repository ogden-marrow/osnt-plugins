//! Place photos: geotagged Wikimedia Commons photos and Wikipedia articles near a coordinate, plus optional Mapillary
//! street-level coverage (image positions and capture dates only). Places only: there is no text or person search,
//! faces are never analysed, and uploader/creator identities of street imagery are never returned.

mod util;

use std::{collections::HashMap, env, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow};
use axum::{
    Json, Router,
    extract::{Query, State},
    middleware,
    response::Html,
    routing::get,
};
use serde_json::{Value, json};
use util::{ApiError, Cache, Guarded, Params, bad, blocking_api};

const PAGE: &str = include_str!("../assets/index.html");
const UA: &str = "osnt-place-photos/0.1 (+https://github.com/ogden-marrow/osnt-hub)";
const LANGS: &[&str] = &["en", "de", "fr", "es", "it", "pt", "nl", "pl", "sv", "ru", "uk", "tr", "ar", "ja", "zh", "ko", "cs", "fi", "da", "no"];

pub struct Config {
    pub commons: String,
    /// Wikipedia API with a `{lang}` placeholder.
    pub wikipedia: String,
    pub mapillary: String,
    /// Fixed token for tests; in production the token comes from the credentials plugin.
    pub token: Option<String>,
}

pub struct App {
    agent: ureq::Agent,
    cfg: Config,
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

fn pct(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// HTML fragment to plain text: tags dropped, common entities decoded, whitespace collapsed, length capped.
pub fn plain(html: &str, max: usize) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    let out = out.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#39;", "'").replace("&#039;", "'").replace("&nbsp;", " ").replace('\u{a0}', " ");
    let t = out.split_whitespace().collect::<Vec<_>>().join(" ");
    if t.chars().count() > max { format!("{}…", t.chars().take(max).collect::<String>()) } else { t }
}

fn fetch(app: &App, url: &str, auth: Option<&str>) -> Result<Value> {
    let key = format!("{}|{url}", auth.is_some());
    if let Some(v) = app.cache.get(&key) {
        return Ok(v);
    }
    let mut req = app.agent.get(url).header("Accept", "application/json");
    if let Some(a) = auth {
        req = req.header("Authorization", a);
    }
    let mut res = req.call().map_err(|e| match e {
        ureq::Error::StatusCode(c) => anyhow!("upstream answered HTTP {c}"),
        other => anyhow!("upstream request failed: {other}"),
    })?;
    let v: Value = res.body_mut().read_json().context("decode upstream response")?;
    // An answer without results (or an error object) is not worth remembering.
    if v["query"]["pages"].as_array().is_some_and(|a| !a.is_empty()) || v["data"].as_array().is_some_and(|a| !a.is_empty()) {
        app.cache.put(key, v.clone());
    }
    Ok(v)
}

fn round(v: f64, p: i32) -> f64 {
    let k = 10f64.powi(p);
    (v * k).round() / k
}

pub fn photo_item(p: &Value) -> Option<Value> {
    let info = p["imageinfo"].get(0)?;
    let c = p["coordinates"].get(0)?;
    let (lat, lon) = (c["lat"].as_f64()?, c["lon"].as_f64()?);
    let m = &info["extmetadata"];
    let val = |k: &str| m[k]["value"].as_str().unwrap_or("");
    let title = p["title"].as_str().unwrap_or("");
    Some(json!({
        "title": title.trim_start_matches("File:"), "page": info["descriptionurl"], "thumb": info["thumburl"], "thumb_w": info["thumbwidth"], "thumb_h": info["thumbheight"],
        "full_w": info["width"], "full_h": info["height"], "lat": lat, "lon": lon, "distance_m": c["dist"].as_f64().map(|d| round(d, 0)),
        "licence": plain(val("LicenseShortName"), 60), "licence_url": m["LicenseUrl"]["value"], "author": plain(val("Artist"), 120), "credit": plain(val("Credit"), 160),
        "attribution_required": val("AttributionRequired") == "true", "date": plain(val("DateTimeOriginal"), 60), "description": plain(val("ImageDescription"), 240),
    }))
}

async fn photos_handler(State(s): State<Shared>, Query(q): Q) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let (lat, lon) = p.lat_lon()?;
    let radius = p.num("radius", 10.0, 10000.0)?.unwrap_or(500.0) as u32;
    let limit = p.num("limit", 1.0, 100.0)?.unwrap_or(40.0) as u32;
    Ok(Json(blocking_api(move || {
        let url = format!(
            "{}?action=query&format=json&formatversion=2&generator=geosearch&ggscoord={}&ggsradius={radius}&ggslimit={limit}&ggsnamespace=6&prop=imageinfo%7Ccoordinates&iiprop=url%7Cextmetadata%7Csize&iiurlwidth=320&iiextmetadatafilter=Artist%7CLicenseShortName%7CLicenseUrl%7CCredit%7CDateTimeOriginal%7CImageDescription%7CAttributionRequired&colimit={limit}&codistancefrompoint={}",
            s.cfg.commons, pct(&format!("{lat:.6}|{lon:.6}")), pct(&format!("{lat:.6}|{lon:.6}"))
        );
        let v = fetch(&s, &url, None).map_err(|e| ApiError(axum::http::StatusCode::BAD_GATEWAY, format!("Wikimedia Commons: {e:#}")))?;
        let mut items: Vec<Value> = v["query"]["pages"].as_array().map(|a| a.iter().filter_map(photo_item).collect()).unwrap_or_default();
        items.sort_by(|a, b| a["distance_m"].as_f64().partial_cmp(&b["distance_m"].as_f64()).unwrap_or(std::cmp::Ordering::Equal));
        Ok(json!({ "centre": { "lat": lat, "lon": lon }, "radius_m": radius, "count": items.len(), "items": items,
            "source": "Wikimedia Commons (geotagged files)", "note": "Each file keeps its own licence: show the author and licence when you reuse an image. Photos can include people incidentally; nothing here searches for or identifies them." }))
    }).await?))
}

pub fn article_item(p: &Value, lang: &str) -> Option<Value> {
    let c = p["coordinates"].get(0)?;
    let title = p["title"].as_str()?;
    Some(json!({
        "title": title, "extract": p["extract"].as_str().map(|s| plain(s, 320)), "thumb": p["thumbnail"]["source"], "lat": c["lat"], "lon": c["lon"], "distance_m": c["dist"].as_f64().map(|d| round(d, 0)),
        "url": format!("https://{lang}.wikipedia.org/wiki/{}", pct(&title.replace(' ', "_"))),
    }))
}

async fn articles_handler(State(s): State<Shared>, Query(q): Q) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let (lat, lon) = p.lat_lon()?;
    let radius = p.num("radius", 10.0, 10000.0)?.unwrap_or(1000.0) as u32;
    let limit = p.num("limit", 1.0, 50.0)?.unwrap_or(20.0) as u32;
    let lang = p.str("lang").unwrap_or("en").to_ascii_lowercase();
    if !LANGS.contains(&lang.as_str()) {
        return Err(bad(format!("lang must be one of {}", LANGS.join(", "))));
    }
    Ok(Json(blocking_api(move || {
        let api = s.cfg.wikipedia.replace("{lang}", &lang);
        let c = pct(&format!("{lat:.6}|{lon:.6}"));
        let url = format!("{api}?action=query&format=json&formatversion=2&generator=geosearch&ggscoord={c}&ggsradius={radius}&ggslimit={limit}&prop=extracts%7Ccoordinates%7Cpageimages&exintro=1&explaintext=1&exsentences=2&exlimit={limit}&colimit={limit}&codistancefrompoint={c}&piprop=thumbnail&pithumbsize=200");
        let v = fetch(&s, &url, None).map_err(|e| ApiError(axum::http::StatusCode::BAD_GATEWAY, format!("Wikipedia: {e:#}")))?;
        let mut items: Vec<Value> = v["query"]["pages"].as_array().map(|a| a.iter().filter_map(|x| article_item(x, &lang)).collect()).unwrap_or_default();
        items.sort_by(|a, b| a["distance_m"].as_f64().partial_cmp(&b["distance_m"].as_f64()).unwrap_or(std::cmp::Ordering::Equal));
        Ok(json!({ "centre": { "lat": lat, "lon": lon }, "radius_m": radius, "lang": lang, "count": items.len(), "items": items, "source": format!("Wikipedia ({lang}), text under CC BY-SA") }))
    }).await?))
}

pub fn street_item(f: &Value) -> Option<Value> {
    let c = f["computed_geometry"]["coordinates"].as_array()?;
    let id = f["id"].as_str()?;
    let ms = f["captured_at"].as_i64();
    Some(json!({
        "id": id, "lon": c.first()?, "lat": c.get(1)?, "captured": ms.map(|m| crate_time(m / 1000)), "compass": f["compass_angle"], "pano": f["is_pano"], "thumb": f["thumb_256_url"],
        "url": format!("https://www.mapillary.com/app/?pKey={id}"),
    }))
}

fn crate_time(secs: i64) -> String {
    let z = secs.div_euclid(86400) + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}")
}

async fn street_handler(State(s): State<Shared>, Query(q): Q) -> Result<Json<Value>, ApiError> {
    let p = Params(q);
    let (lat, lon) = p.lat_lon()?;
    let radius = p.num("radius", 20.0, 400.0)?.unwrap_or(150.0);
    let limit = p.num("limit", 1.0, 100.0)?.unwrap_or(40.0) as u32;
    Ok(Json(blocking_api(move || {
        let token = s.cfg.token.clone().or_else(|| osnt_common::secret("MAPILLARY_TOKEN"));
        let Some(token) = token else {
            return Ok(json!({ "available": false, "items": [], "count": 0, "message": "Street-level coverage needs a Mapillary access token. Add MAPILLARY_TOKEN on the Credentials page." }));
        };
        let (dlat, dlon) = (radius / 111_320.0, radius / (111_320.0 * lat.to_radians().cos().max(0.05)));
        let url = format!("{}/images?fields=id,captured_at,compass_angle,computed_geometry,is_pano,thumb_256_url&bbox={:.6},{:.6},{:.6},{:.6}&limit={limit}", s.cfg.mapillary, lon - dlon, lat - dlat, lon + dlon, lat + dlat);
        let v = fetch(&s, &url, Some(&format!("OAuth {token}"))).map_err(|e| ApiError(axum::http::StatusCode::BAD_GATEWAY, format!("Mapillary: {e:#}")))?;
        let items: Vec<Value> = v["data"].as_array().map(|a| a.iter().filter_map(street_item).collect()).unwrap_or_default();
        Ok(json!({ "available": true, "centre": { "lat": lat, "lon": lon }, "radius_m": radius, "count": items.len(), "items": items,
            "source": "Mapillary (CC BY-SA)", "note": "Positions and capture dates only; contributor identities are not shown." }))
    }).await?))
}

async fn status_handler(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    Ok(Json(blocking_api(move || Ok(json!({ "street_level": s.cfg.token.is_some() || osnt_common::secret("MAPILLARY_TOKEN").is_some() }))).await?))
}

async fn tools() -> Json<Value> {
    let n = |d: &str| json!({ "type": "number", "description": d });
    let base = |extra: &[(&str, Value)]| {
        let mut p = json!({ "lat": n("latitude"), "lon": n("longitude"), "radius": n("metres") });
        for (k, v) in extra {
            p[*k] = v.clone();
        }
        json!({ "type": "object", "properties": p, "required": ["lat", "lon"] })
    };
    Json(json!([
        { "name": "places_photos_near", "description": "Geotagged Wikimedia Commons photos near a coordinate (thumbnail, distance, author, licence). For comparing a claimed location with what is there.",
          "method": "GET", "path": "api/photos", "parameters": base(&[("limit", n("1..100"))]) },
        { "name": "places_articles_near", "description": "Wikipedia articles about places near a coordinate (title, summary, distance, link).",
          "method": "GET", "path": "api/articles", "parameters": base(&[("lang", json!({ "type": "string", "description": "language code, default en" }))]) },
        { "name": "places_street_near", "description": "Mapillary street-level image positions and capture dates near a coordinate (needs MAPILLARY_TOKEN; says so if missing).",
          "method": "GET", "path": "api/street", "parameters": base(&[]) }
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

pub fn router(app: App) -> Router {
    let state: Shared = Arc::new(app);
    let api = Router::new()
        .route("/api/photos", get(photos_handler))
        .route("/api/articles", get(articles_handler))
        .route("/api/street", get(street_handler))
        .route("/api/status", get(status_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), util::guard::<App>));
    Router::new().route("/", get(page)).route("/tools", get(tools)).merge(api).with_state(state)
}

pub fn new_app(cfg: Config, require_gateway: bool) -> App {
    App { agent: osnt_common::http_agent(UA), cfg, cache: Cache::new(Duration::from_secs(900), 200), require_gateway }
}

#[tokio::main]
async fn main() -> Result<()> {
    let var = |k: &str, d: &str| env::var(k).unwrap_or_else(|_| d.into());
    let cfg = Config {
        commons: var("OSNT_PLACES_COMMONS", "https://commons.wikimedia.org/w/api.php"),
        wikipedia: var("OSNT_PLACES_WIKIPEDIA", "https://{lang}.wikipedia.org/w/api.php"),
        mapillary: var("OSNT_PLACES_MAPILLARY", "https://graph.mapillary.com"),
        token: None,
    };
    let app = router(new_app(cfg, util::gateway_configured()));
    let addr: SocketAddr = var("OSNT_PLACES_BIND", "127.0.0.1:8147").parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("place-photos plugin on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests;

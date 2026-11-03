use super::*;
use axum::{extract::Request, http::StatusCode, response::IntoResponse, routing::{get as aget, post}};
use std::sync::atomic::{AtomicUsize, Ordering};

async fn serve(app: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{a}")
}

async fn get_json(url: String) -> (u16, Value) {
    tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
        let mut r = agent.get(&url).call().unwrap();
        (r.status().as_u16(), r.body_mut().read_json::<Value>().unwrap_or(Value::Null))
    })
    .await
    .unwrap()
}

static OP_HITS: AtomicUsize = AtomicUsize::new(0);
static CACHE_HITS: AtomicUsize = AtomicUsize::new(0);
static NOM_TIMES: Mutex<Vec<Instant>> = Mutex::new(Vec::new());

fn overpass_ok() -> Router {
    Router::new().route("/api/interpreter", post(|body: String| async move {
        OP_HITS.fetch_add(1, Ordering::SeqCst);
        if body.contains("zzcache") { CACHE_HITS.fetch_add(1, Ordering::SeqCst); }
        assert!(body.starts_with("data="), "{body}");
        Json(json!({ "osm3s": { "timestamp_osm_base": "2026-11-03T00:00:00Z" }, "elements": [
            { "type": "node", "id": 1, "lat": 47.0, "lon": 8.0, "tags": { "amenity": "fuel", "name": "Test Fuel" } },
            { "type": "way", "id": 2, "center": { "lat": 47.001, "lon": 8.001 }, "tags": { "railway": "level_crossing" } },
            { "type": "relation", "id": 3, "tags": { "x": "no position" } },
            { "type": "way", "id": 4, "geometry": [ { "lat": 1.0, "lon": 1.0 }, { "lat": 1.0, "lon": 2.0 }, { "lat": 2.0, "lon": 2.0 } ], "bounds": { "minlat": 1.0, "maxlat": 2.0, "minlon": 1.0, "maxlon": 2.0 }, "tags": { "highway": "path" } } ] }))
    }))
}

async fn upstreams() -> Config {
    let op = serve(overpass_ok()).await;
    let nom = serve(Router::new().route("/search", aget(|| async {
        NOM_TIMES.lock().unwrap().push(Instant::now());
        Json(json!([{ "osm_type": "way", "osm_id": 5, "lat": "48.85", "lon": "2.29", "name": "Tour", "display_name": "Tour, Paris", "category": "man_made", "type": "tower", "boundingbox": ["48.8", "48.9", "2.2", "2.3"] }]))
    })).route("/reverse", aget(|| async { NOM_TIMES.lock().unwrap().push(Instant::now()); Json(json!({ "osm_type": "node", "osm_id": 9, "lat": "1", "lon": "2", "display_name": "Somewhere", "address": { "country": "X" } })) }))).await;
    let photon = serve(Router::new().route("/api/", aget(|| async { Json(json!({ "features": [{ "geometry": { "coordinates": [2.29, 48.85] }, "properties": { "name": "Eiffel Tower", "city": "Paris", "country": "France", "osm_type": "W", "osm_id": 7, "osm_key": "man_made", "osm_value": "tower" } }] })) }))).await;
    let api = serve(Router::new()
        .route("/changesets.json", aget(|| async { Json(json!({ "changesets": [{ "id": 11, "created_at": "2026-11-01T00:00:00Z", "closed_at": "2026-11-01T01:00:00Z", "open": false, "changes_count": 3, "uid": 99, "user": "someone", "min_lat": 1.0, "min_lon": 2.0, "max_lat": 1.1, "max_lon": 2.1, "tags": { "comment": "fix", "created_by": "iD 2.30" } }] })) }))
        .route("/notes.json", aget(|| async { Json(json!({ "features": [{ "geometry": { "coordinates": [2.05, 1.05] }, "properties": { "id": 21, "status": "open", "date_created": "2026-10-30 00:00:00 UTC", "comments": [{ "user": "someone", "uid": 99, "text": "gate is gone" }] } }] })) }))).await;
    Config { overpass: vec![format!("{op}/api/interpreter")], nominatim: nom, photon, osm_api: api }
}

async fn plugin(cfg: Config) -> String {
    serve(router(new_app(cfg, false))).await
}

#[tokio::test]
async fn find_returns_geojson_and_caches() {
    let base = plugin(upstreams().await).await;
    let url = format!("{base}/api/find?preset=custom&key=zzcache&lat=47&lon=8&radius=500");
    let (c, v) = get_json(url.clone()).await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["type"], "FeatureCollection");
    let f = v["features"].as_array().unwrap();
    assert_eq!(f.len(), 3, "relation without a position is skipped");
    assert_eq!(f[0]["geometry"]["type"], "Point");
    assert_eq!(f[2]["geometry"]["type"], "LineString");
    assert_eq!(f[0]["properties"]["name"], "Test Fuel");
    assert!(v["meta"]["query"].as_str().unwrap().contains("around:500,47.000000,8.000000"));
    let _ = get_json(url).await;
    assert_eq!(CACHE_HITS.load(Ordering::SeqCst), 1, "repeat must be cached");
}

#[tokio::test]
async fn near_filter_classifies_and_validates() {
    let base = plugin(upstreams().await).await;
    let (c, v) = get_json(format!("{base}/api/find?preset=fuel&near=rail_crossings&near_radius=300&bbox=7.9,46.9,8.1,47.1")).await;
    assert_eq!(c, 200, "{v}");
    let classes: Vec<&str> = v["features"].as_array().unwrap().iter().map(|f| f["properties"]["class"].as_str().unwrap()).collect();
    assert_eq!(&classes[..2], ["a", "b"]);
    assert!(v["meta"]["query"].as_str().unwrap().contains("around.b:300"));
    for bad in ["preset=nope&lat=1&lon=1", "lat=1&lon=1", "preset=fuel&lat=1&lon=1&radius=999999", "preset=fuel&bbox=0,0,5,5", "preset=fuel&bbox=3,0,1,1", "preset=custom&key=a%22%5D&lat=1&lon=1", "preset=fuel&lat=1&lon=1&near=bogus"] {
        let (c, v) = get_json(format!("{base}/api/find?{bad}")).await;
        assert_eq!(c, 400, "{bad}: {v}");
    }
    let (c, _) = get_json(format!("{base}/api/find?preset=custom&key=shop&value=bakery&lat=1&lon=1")).await;
    assert_eq!(c, 200);
}

#[tokio::test]
async fn raw_mode_rules() {
    let base = plugin(upstreams().await).await;
    let (c, v) = get_json(format!("{base}/api/raw?q={}", pct("node[amenity=fuel](1,2,3,4);out;"))).await;
    assert_eq!(c, 200, "{v}");
    assert!(v["meta"]["query"].as_str().unwrap().starts_with("[out:json]"));
    for bad in ["[out:xml];node(1);out;", "node(1);", ""] {
        let (c, _) = get_json(format!("{base}/api/raw?q={}", pct(bad))).await;
        assert_eq!(c, 400, "{bad}");
    }
    let (c, _) = get_json(format!("{base}/api/raw?q={}", "a".repeat(5000))).await;
    assert_eq!(c, 400);
}

#[tokio::test]
async fn overpass_syntax_error_is_a_400_and_busy_falls_back() {
    let bad_srv = serve(Router::new().route("/i", post(|| async { (StatusCode::BAD_REQUEST, "<html><body><p><strong style=\"color:#FF0000\">Error</strong>: line 1: parse error: Unexpected end of input</p></body></html>").into_response() }))).await;
    let busy = serve(Router::new().route("/i", post(|| async { StatusCode::TOO_MANY_REQUESTS }))).await;
    let good = serve(overpass_ok()).await;
    let mut cfg = upstreams().await;
    cfg.overpass = vec![format!("{bad_srv}/i")];
    let base = plugin(cfg).await;
    let (c, v) = get_json(format!("{base}/api/raw?q={}", pct("node(1);out;"))).await;
    assert_eq!(c, 400);
    assert!(v["error"].as_str().unwrap().contains("parse error"), "{v}");
    let mut cfg = upstreams().await;
    cfg.overpass = vec![format!("{busy}/i"), "http://127.0.0.1:9/i".into(), format!("{good}/api/interpreter")];
    let base = plugin(cfg).await;
    let (c, v) = get_json(format!("{base}/api/find?preset=fuel&lat=47&lon=8")).await;
    assert_eq!(c, 200, "{v}");
    assert!(v["meta"]["instance"].as_str().unwrap().contains("/api/interpreter"));
    let (_, s) = get_json(format!("{base}/api/status")).await;
    assert!(s["overpass"][0]["marked_down"].as_bool().unwrap() || s["overpass"][1]["marked_down"].as_bool().unwrap());
}

#[tokio::test]
async fn all_overpass_down_degrades_with_a_clear_message() {
    let mut cfg = upstreams().await;
    cfg.overpass = vec!["http://127.0.0.1:9/api/interpreter".into()];
    let base = plugin(cfg).await;
    let (c, v) = get_json(format!("{base}/api/find?preset=fuel&lat=47&lon=8")).await;
    assert_eq!(c, 503);
    assert!(v["error"].as_str().unwrap().contains("OSNT_OVERPASS_URL"), "{v}");
}

#[tokio::test]
async fn geocode_providers_reverse_and_nominatim_spacing() {
    let base = plugin(upstreams().await).await;
    NOM_TIMES.lock().unwrap().clear();
    let (c, v) = get_json(format!("{base}/api/geocode?q=Eiffel%20Tower")).await;
    assert_eq!(c, 200);
    assert_eq!(v["results"][0]["lat"], 48.85);
    assert_eq!(v["results"][0]["url"], "https://www.openstreetmap.org/way/5");
    let (_, v) = get_json(format!("{base}/api/geocode?q=Eiffel%20Tower&provider=photon")).await;
    assert_eq!(v["results"][0]["display_name"], "Eiffel Tower, Paris, France");
    let (_, v) = get_json(format!("{base}/api/reverse?lat=1&lon=2")).await;
    assert_eq!(v["result"]["display_name"], "Somewhere");
    let t = NOM_TIMES.lock().unwrap().clone();
    assert_eq!(t.len(), 2);
    assert!(t[1].duration_since(t[0]) >= Duration::from_millis(1000), "nominatim requests must be 1 s apart");
    for bad in ["q=", "q=x&provider=evil", "q=x&limit=99"] {
        let (c, _) = get_json(format!("{base}/api/geocode?{bad}")).await;
        assert_eq!(c, 400, "{bad}");
    }
    let (c, _) = get_json(format!("{base}/api/reverse?lat=100&lon=2")).await;
    assert_eq!(c, 400);
}

#[tokio::test]
async fn edits_omit_user_identity() {
    let base = plugin(upstreams().await).await;
    let (c, v) = get_json(format!("{base}/api/edits?lat=1&lon=2&radius=500&days=30")).await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["recently_edited"], true);
    assert_eq!(v["open_notes"], 1);
    let text = v.to_string();
    assert!(!text.contains("someone") && !text.contains("99") || !text.contains("\"uid\""), "{text}");
    assert!(!text.contains("\"user\"") && !text.contains("\"uid\"") && !text.contains("someone"), "{text}");
    assert_eq!(v["changesets"]["items"][0]["editor"], "iD 2.30");
    assert_eq!(v["notes"]["items"][0]["text"], "gate is gone");
    let (c, _) = get_json(format!("{base}/api/edits?lat=1&lon=2&days=9999")).await;
    assert_eq!(c, 400);
}

#[tokio::test]
async fn edits_upstream_failure_is_partial() {
    let mut cfg = upstreams().await;
    cfg.osm_api = "http://127.0.0.1:9".into();
    let base = plugin(cfg).await;
    let (c, v) = get_json(format!("{base}/api/edits?lat=1&lon=2")).await;
    assert_eq!(c, 200);
    assert!(v["changesets"]["error"].is_string());
}

#[tokio::test]
async fn guard_and_tools() {
    let base = serve(router(new_app(upstreams().await, true))).await;
    let (c, _) = get_json(format!("{base}/api/presets")).await;
    assert_eq!(c, 401);
    let (c, v) = get_json(format!("{base}/tools")).await;
    assert_eq!(c, 200);
    assert_eq!(v.as_array().unwrap().len(), 4);
}

#[test]
fn helpers() {
    assert_eq!(pct("a b&c=é"), "a%20b%26c%3D%C3%A9");
    assert_eq!(iso_days_ago(0).len(), 20);
    assert_eq!(trim("abcdef", 3), "abc…");
    assert!(error_text("<p>Error: line 1: parse error</p>").contains("parse error"));
    let _ = Request::new(axum::body::Body::empty());
}

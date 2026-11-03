use super::*;
use axum::routing::get as aget;
use std::sync::atomic::{AtomicUsize, Ordering};

async fn serve(app: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{a}")
}

async fn call(method: &str, url: String, body: Option<String>) -> (u16, String, Value) {
    let method = method.to_string();
    tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
        let mut r = if method == "POST" { agent.post(&url).header("Content-Type", "application/json").send(body.unwrap_or_default().as_bytes()).unwrap() } else { agent.get(&url).call().unwrap() };
        let ct = r.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let text = r.body_mut().read_to_string().unwrap_or_default();
        let v = serde_json::from_str(&text).unwrap_or(Value::Null);
        (r.status().as_u16(), format!("{ct}|{text}"), v)
    })
    .await
    .unwrap()
}

async fn get_json(url: String) -> (u16, Value) {
    let (c, _, v) = call("GET", url, None).await;
    (c, v)
}

static TZ_HITS: AtomicUsize = AtomicUsize::new(0);

async fn plugin(meteo: &str, gateway: bool) -> String {
    serve(router(new_app(meteo.into(), gateway))).await
}

async fn fake_meteo() -> String {
    serve(Router::new().route("/v1/forecast", aget(|| async {
        TZ_HITS.fetch_add(1, Ordering::SeqCst);
        Json(json!({ "timezone": "Europe/Paris", "timezone_abbreviation": "CET", "utc_offset_seconds": 3600 }))
    }))).await
}

fn enc(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

#[tokio::test]
async fn convert_returns_every_format() {
    let base = plugin("http://127.0.0.1:9", false).await;
    let (c, v) = get_json(format!("{base}/api/convert?q={}", enc("48°51'30\"N 2°17'40\"E"))).await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["kind"], "dms");
    let f = v["formats"].as_array().unwrap();
    let get = |id: &str| f.iter().find(|x| x["id"] == id).unwrap()["value"].as_str().unwrap().to_string();
    assert_eq!(get("dd"), "48.858333, 2.294444");
    assert!(get("utm").starts_with("31U 4482"), "{}", get("utm"));
    assert!(get("mgrs").starts_with("31U DQ 482"), "{}", get("mgrs"));
    assert_eq!(get("geohash").len(), 9);
    assert_eq!(get("pluscode").len(), 11);
    assert_eq!(get("maidenhead"), "JN18du");
    assert!(v["links"]["openstreetmap"].as_str().unwrap().starts_with("https://www.openstreetmap.org/"));
    // Polar: UTM is not defined.
    let (_, v) = get_json(format!("{base}/api/convert?q=89.5,10")).await;
    assert!(v["formats"].as_array().unwrap().iter().any(|x| x["id"] == "utm" && x["value"].as_str().unwrap().contains("not defined")));
    // Geohash round trip with neighbours and short Plus Code with a reference.
    let (_, v) = get_json(format!("{base}/api/convert?q=u4pruydqqvj")).await;
    assert_eq!(v["kind"], "geohash");
    assert_eq!(v["geohash_neighbours"].as_array().unwrap().len(), 8);
    let (c, _) = get_json(format!("{base}/api/convert?q={}", enc("V4VQ+JC"))).await;
    assert_eq!(c, 400);
    let (c, v) = get_json(format!("{base}/api/convert?q={}&ref={}", enc("V4VQ+JC"), enc("47.3, 8.5"))).await;
    assert_eq!(c, 200, "{v}");
}

#[tokio::test]
async fn convert_errors_are_clear() {
    let base = plugin("http://127.0.0.1:9", false).await;
    for bad in ["q=", "q=hello", "q=91,10", "q=1,2&ref=nonsense", ""] {
        let (c, v) = get_json(format!("{base}/api/convert?{bad}")).await;
        assert_eq!(c, 400, "{bad}");
        assert!(v["error"].is_string());
    }
}

#[tokio::test]
async fn distance_destination_and_paths() {
    let base = plugin("http://127.0.0.1:9", false).await;
    let (c, v) = get_json(format!("{base}/api/distance?a={}&b={}", enc("-41.32, 174.81"), enc("40.96, -5.50"))).await;
    assert_eq!(c, 200, "{v}");
    assert!((v["total_meters"].as_f64().unwrap() - 19_959_679.267).abs() < 0.01);
    let (_, v) = get_json(format!("{base}/api/distance?points={}", enc("0,0|0,1|1,1"))).await;
    assert_eq!(v["legs"].as_array().unwrap().len(), 2);
    let (c, _) = get_json(format!("{base}/api/distance?points={}", enc("0,0"))).await;
    assert_eq!(c, 400);
    let (c, _) = get_json(format!("{base}/api/distance?a=1,1")).await;
    assert_eq!(c, 400);
    let (_, v) = get_json(format!("{base}/api/destination?from={}&bearing=90&km=100", enc("0,0"))).await;
    assert!((v["lon"].as_f64().unwrap() - 0.898).abs() < 0.01 && v["lat"].as_f64().unwrap().abs() < 1e-6);
    let (c, _) = get_json(format!("{base}/api/destination?from=0,0&bearing=90")).await;
    assert_eq!(c, 400);
}

#[tokio::test]
async fn generators() {
    let base = plugin("http://127.0.0.1:9", false).await;
    let (c, v) = get_json(format!("{base}/api/generate?kind=circle&center={}&radius=1000&points=16", enc("48,2"))).await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["geojson"]["features"][0]["geometry"]["coordinates"][0].as_array().unwrap().len(), 17);
    let (_, v) = get_json(format!("{base}/api/generate?kind=bbox&center={}&radius=500", enc("48,2"))).await;
    assert_eq!(v["bbox_text"].as_str().unwrap().split(',').count(), 4);
    let (_, v) = get_json(format!("{base}/api/generate?kind=grid&bbox={}&cell=5000", enc("2,48,2.2,48.2"))).await;
    assert!(v["geojson"]["features"].as_array().unwrap().len() >= 12);
    for bad in ["kind=nope", "kind=grid&bbox=0,0,50,50&cell=100", "kind=grid&cell=100", "kind=circle&center=1,1&radius=0", "kind=grid&bbox=a,b,c,d&cell=100"] {
        assert_eq!(get_json(format!("{base}/api/generate?{bad}")).await.0, 400, "{bad}");
    }
}

#[tokio::test]
async fn geojson_clean_and_export() {
    let base = plugin("http://127.0.0.1:9", false).await;
    let gj = json!({ "type": "FeatureCollection", "features": [
        { "type": "Feature", "properties": { "name": "A" }, "geometry": { "type": "Point", "coordinates": [2.294444444, 48.85833333, 12] } },
        { "type": "Feature", "properties": {}, "geometry": { "type": "LineString", "coordinates": [[2.0, 48.0], [2.1, 48.1]] } } ] });
    let (c, _, v) = call("POST", format!("{base}/api/geojson"), Some(json!({ "geojson": gj, "decimals": 3 }).to_string())).await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["cleaned"]["features"][0]["geometry"]["coordinates"], json!([2.294, 48.858]));
    assert_eq!(v["stats"]["types"]["Point"], 1);
    // Pasted as a string, and as a bare geometry.
    let (c, ..) = call("POST", format!("{base}/api/geojson"), Some(json!({ "geojson": gj.to_string() }).to_string())).await;
    assert_eq!(c, 200);
    let (c, ..) = call("POST", format!("{base}/api/geojson"), Some(json!({ "type": "Point", "coordinates": [1, 2] }).to_string())).await;
    assert_eq!(c, 200);
    for body in ["not json", "{\"geojson\": {\"x\": 1}}", "{\"geojson\": {\"type\":\"Point\",\"coordinates\":[1,2]}, \"decimals\": 12}"] {
        assert_eq!(call("POST", format!("{base}/api/geojson"), Some(body.into())).await.0, 400, "{body}");
    }
    let (c, raw, _) = call("POST", format!("{base}/api/export"), Some(json!({ "geojson": gj, "format": "kml", "name": "T" }).to_string())).await;
    assert_eq!(c, 200);
    assert!(raw.starts_with("application/vnd.google-earth.kml+xml|") && raw.contains("<Placemark>"));
    let (_, raw, _) = call("POST", format!("{base}/api/export"), Some(json!({ "geojson": gj, "format": "gpx" }).to_string())).await;
    assert!(raw.contains("<gpx") && raw.contains("<trkpt"));
    assert_eq!(call("POST", format!("{base}/api/export"), Some(json!({ "geojson": gj, "format": "zip" }).to_string())).await.0, 400);
}

#[tokio::test]
async fn extract_get_and_post() {
    let base = plugin("http://127.0.0.1:9", false).await;
    let (_, v) = get_json(format!("{base}/api/extract?text={}", enc("meet at 48.858370, 2.294481 then 31UDQ4825011951"))).await;
    assert_eq!(v["count"], 2, "{v}");
    let (c, _, v) = call("POST", format!("{base}/api/extract"), Some("line one\nsecond 51°30'26\"N 0°7'39\"W".into())).await;
    assert_eq!(c, 200);
    assert_eq!(v["matches"][0]["line"], 2);
    assert!(v["matches"][0]["lon"].as_f64().unwrap() < 0.0);
    assert_eq!(get_json(format!("{base}/api/extract")).await.0, 400);
    let big = "x".repeat(scan::MAX_TEXT + 1);
    assert_eq!(call("POST", format!("{base}/api/extract"), Some(big)).await.0, 400);
}

#[tokio::test]
async fn timezone_online_cached_and_offline_fallback() {
    let meteo = fake_meteo().await;
    let base = plugin(&meteo, false).await;
    let (c, v) = get_json(format!("{base}/api/timezone?lat=48.85&lon=2.29")).await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["timezone"], "Europe/Paris");
    assert_eq!(v["utc_offset_hours"], 1.0);
    let before = TZ_HITS.load(Ordering::SeqCst);
    let _ = get_json(format!("{base}/api/timezone?lat=48.85&lon=2.29")).await;
    assert_eq!(TZ_HITS.load(Ordering::SeqCst), before);
    let dead = plugin("http://127.0.0.1:9", false).await;
    let (c, v) = get_json(format!("{dead}/api/timezone?lat=48.85&lon=30")).await;
    assert_eq!(c, 200);
    assert!(v["timezone"].is_null() && v["nominal_solar_offset_hours"] == 2.0 && v["warning"].is_string());
    assert_eq!(get_json(format!("{dead}/api/timezone?lat=1")).await.0, 400);
}

#[tokio::test]
async fn guard_and_tools() {
    let base = plugin("http://127.0.0.1:9", true).await;
    assert_eq!(get_json(format!("{base}/api/convert?q=1,2")).await.0, 401);
    assert_eq!(call("POST", format!("{base}/api/geojson"), Some("{}".into())).await.0, 401);
    let (c, v) = get_json(format!("{base}/tools")).await;
    assert_eq!((c, v.as_array().unwrap().len()), (200, 3));
}

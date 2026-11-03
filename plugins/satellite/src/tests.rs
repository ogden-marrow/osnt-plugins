use super::*;
use axum::{Router, routing::post};
use std::sync::atomic::{AtomicUsize, Ordering};

static HITS: AtomicUsize = AtomicUsize::new(0);

fn s2_feature(id: &str, data: &str) -> Value {
    json!({
        "id": id, "bbox": [30.0, 50.0, 31.0, 51.0],
        "geometry": { "type": "Polygon", "coordinates": [[[30.0, 50.0], [31.0, 50.0], [31.0, 51.0], [30.0, 51.0], [30.0, 50.0]]] },
        "properties": { "datetime": "2026-10-11T09:16:22Z", "platform": "sentinel-2b", "eo:cloud_cover": 12.5 },
        "assets": {
            "tilejson": { "href": format!("{data}item/tilejson.json?collection=sentinel-2-l2a&item={id}&assets=visual&format=png") },
            "rendered_preview": { "href": format!("{data}item/preview.png?collection=sentinel-2-l2a&item={id}&assets=visual") },
            "visual": { "href": "https://example.test/TCI.tif" },
            "thumbnail": { "href": "https://example.test/thumb.jpg" }
        }
    })
}

/// A fake STAC API that records the last request body and answers with one item per call.
async fn fake_upstream() -> (String, Arc<Mutex<Option<Value>>>) {
    let last: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let l2 = last.clone();
    let router = Router::new().route("/search", post(move |Json(b): Json<Value>| {
        let l = l2.clone();
        async move {
            HITS.fetch_add(1, Ordering::SeqCst);
            let coll = b["collections"][0].as_str().unwrap_or("").to_string();
            *l.lock().unwrap() = Some(b);
            if coll == "naip" {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({}))).into_response();
            }
            let data = "https://pc.test/api/data/v1/";
            Json(json!({ "type": "FeatureCollection", "context": { "matched": 7 }, "features": [s2_feature("S2_TEST_1", data)] })).into_response()
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), last)
}

async fn serve(cfg: Config) -> String {
    let dir = env::temp_dir().join(format!("osnt-sat-test-{}-{}", std::process::id(), now_secs()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = app(cfg, dir);
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{addr}")
}

fn get(url: &str) -> (u16, Value) {
    let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
    let mut r = agent.get(url).call().unwrap();
    (r.status().as_u16(), r.body_mut().read_json().unwrap_or(Value::Null))
}

fn cfg(up: &str) -> Config {
    Config { pc_stac: up.to_string(), es_stac: up.to_string(), pc_data: "https://pc.test/api/data/v1/".into(), titiler: "https://titiler.test".into() }
}

#[test]
fn bbox_and_dates_validate() {
    assert!(parse_bbox("30,50,31,51").is_ok());
    assert!(parse_bbox("31,50,30,51").is_err());
    assert!(parse_bbox("0,0,40,5").is_err(), "too wide");
    assert!(parse_bbox("a,b,c,d").is_err());
    assert!(parse_bbox("-200,0,10,5").is_err());
    assert!(valid_date("2026-10-11"));
    // Regression: any day 1-31 used to pass, so 30 February went upstream and came back as an HTTP 400 "archive error".
    assert!(!valid_date("2026-02-30") && !valid_date("2026-02-29") && valid_date("2028-02-29") && !valid_date("2026-04-31") && valid_date("2026-12-31"));
    assert!(!valid_date("2026-13-01") && !valid_date("20261011") && !valid_date("2026-1-011"));
    assert_eq!(civil(0), (1970, 1, 1));
    assert_eq!(civil(20_000), (2024, 10, 4));
}

#[tokio::test(flavor = "multi_thread")]
async fn search_normalises_scenes_and_builds_tiles() {
    let (up, last) = fake_upstream().await;
    let base = serve(cfg(&up)).await;
    let b2 = base.clone();
    let (code, v) = tokio::task::spawn_blocking(move || get(&format!("{b2}/api/search?bbox=30,50,31,51&start=2026-10-01&end=2026-10-20&kind=s2&cloud=30"))).await.unwrap();
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["count"], 1);
    assert_eq!(v["matched"], 7);
    let s = &v["scenes"][0];
    assert_eq!(s["id"], "S2_TEST_1");
    assert_eq!(s["cloud_cover"], 12.5);
    assert_eq!(s["tiles"], "https://pc.test/api/data/v1/item/tiles/WebMercatorQuad/{z}/{x}/{y}@1x.png?collection=sentinel-2-l2a&item=S2_TEST_1&assets=visual&format=png");
    assert_eq!(s["thumbnail"], "https://example.test/thumb.jpg");
    assert!(s["stac_item"].as_str().unwrap().ends_with("/collections/sentinel-2-l2a/items/S2_TEST_1"));
    // The upstream request carried the filters.
    let body = last.lock().unwrap().clone().unwrap();
    assert_eq!(body["collections"][0], "sentinel-2-l2a");
    assert_eq!(body["datetime"], "2026-10-01T00:00:00Z/2026-10-20T23:59:59Z");
    assert_eq!(body["query"]["eo:cloud_cover"]["lt"], 30.0);
    assert_eq!(body["bbox"], json!([30.0, 50.0, 31.0, 51.0]));
}

#[tokio::test(flavor = "multi_thread")]
async fn earth_search_uses_titiler_for_visual_cog_and_second_call_is_cached() {
    let (up, _last) = fake_upstream().await;
    let base = serve(cfg(&up)).await;
    let before = HITS.load(Ordering::SeqCst);
    let url = format!("{base}/api/search?bbox=30,50,31,51&source=es&kind=s2&start=2026-10-01&end=2026-10-20");
    let (u1, u2) = (url.clone(), url);
    let (_, v) = tokio::task::spawn_blocking(move || get(&u1)).await.unwrap();
    let tiles = v["scenes"][0]["tiles"].as_str().unwrap();
    assert!(tiles.starts_with("https://titiler.test/cog/tiles/WebMercatorQuad/{z}/{x}/{y}?url=https%3A%2F%2Fexample.test%2FTCI.tif"), "{tiles}");
    assert!(v["scenes"][0]["browser"].as_str().unwrap().contains("stac-browser"));
    let (_, v2) = tokio::task::spawn_blocking(move || get(&u2)).await.unwrap();
    assert_eq!(v, v2);
    assert!(HITS.load(Ordering::SeqCst) - before <= 1 + 1, "repeat call should be served from the disk cache");
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_input_and_upstream_failure_are_reported() {
    let (up, _l) = fake_upstream().await;
    let base = serve(cfg(&up)).await;
    for (q, want) in [
        ("kind=s2", 400),
        ("bbox=0,0,50,5&kind=s2", 400),
        ("bbox=30,50,31,51&kind=radar", 400),
        ("bbox=30,50,31,51&source=evil", 400),
        ("bbox=30,50,31,51&start=2026-10-20&end=2026-10-01", 400),
        ("bbox=30,50,31,51&cloud=500", 400),
        ("bbox=30,50,31,51&kind=naip", 502),
    ] {
        let u = format!("{base}/api/search?{q}");
        let (code, v) = tokio::task::spawn_blocking(move || get(&u)).await.unwrap();
        assert_eq!(code, want, "{q}: {v}");
        assert!(v["error"].is_string());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tools_and_sources_are_described() {
    let base = serve(cfg("http://127.0.0.1:9")).await;
    let b = base.clone();
    let (_, t) = tokio::task::spawn_blocking(move || get(&format!("{b}/tools"))).await.unwrap();
    let names: Vec<&str> = t.as_array().unwrap().iter().map(|x| x["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["satellite_search", "satellite_sources"]);
    assert!(t[0]["path"].as_str().unwrap().starts_with("api/"));
    let (_, s) = tokio::task::spawn_blocking(move || get(&format!("{base}/api/sources"))).await.unwrap();
    assert_eq!(s["kinds"].as_array().unwrap().len(), 4);
}

#[test]
fn disk_cache_expires_and_evicts() {
    let dir = env::temp_dir().join(format!("osnt-cache-test-{}", std::process::id()));
    let c = cache::DiskCache::new(dir, 100);
    c.put("a", &[1u8; 60]);
    assert_eq!(c.get("a", Duration::from_secs(60)).unwrap().len(), 60);
    std::thread::sleep(Duration::from_millis(20));
    c.put("b", &[2u8; 60]);
    c.evict();
    assert!(c.get("a", Duration::from_secs(60)).is_none(), "oldest entry evicted when over the size cap");
    assert!(c.get("b", Duration::from_secs(60)).is_some());
    assert!(c.get("zz", Duration::from_secs(60)).is_none());
}

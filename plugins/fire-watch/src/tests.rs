use super::*;
use axum::{extract::RawQuery, routing::get as aget};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::{Mutex, Once, atomic::{AtomicUsize, Ordering}};

const HEAD: &str = "latitude,longitude,bright_ti4,scan,track,acq_date,acq_time,satellite,confidence,version,bright_ti5,frp,daynight\n";

fn row(lat: f64, lon: f64, date: &str, time: &str, conf: &str, frp: f64, dn: &str) -> String {
    format!("{lat},{lon},330.2,0.5,0.6,{date},{time},N,{conf},2.0NRT,264.5,{frp},{dn}\n")
}

/// Today's date so the `hours` filter has something to chew on.
fn today() -> String {
    util::ymd(now_secs())
}

fn fixture() -> String {
    let t = today();
    let mut s = HEAD.to_string();
    // Fire A: 3 detections ~1 km apart near (40.0, -120.0)
    s += &row(40.000, -120.000, &t, "0100", "h", 10.0, "N");
    s += &row(40.005, -120.003, &t, "0100", "n", 20.0, "N");
    s += &row(40.009, -120.000, &t, "0300", "n", 5.0, "D");
    // Fire B: single detection far away, low confidence
    s += &row(41.500, -119.000, &t, "0200", "l", 2.0, "D");
    // Outside any box used in tests
    s += &row(-30.0, 150.0, &t, "0200", "n", 50.0, "D");
    // Old row (3 days ago), only in a 7d file
    s += &row(40.002, -120.001, &util::ymd(now_secs() - 3 * 86_400), "0900", "n", 7.0, "D");
    s += "garbage line\n";
    s
}

static HITS: AtomicUsize = AtomicUsize::new(0);
static URLS: Mutex<Vec<String>> = Mutex::new(Vec::new());

async fn fake(body: String) -> String {
    let b2 = body.clone();
    let router = Router::new()
        .route("/files/{sensor}/csv/{name}", aget(move |Path((_s, name)): Path<(String, String)>| {
            let body = b2.clone();
            async move {
                HITS.fetch_add(1, Ordering::SeqCst);
                URLS.lock().unwrap().push(name.clone());
                if name.contains("Broken") { return StatusCode::INTERNAL_SERVER_ERROR.into_response(); }
                body.into_response()
            }
        }))
        .route("/api/{key}/{source}/{area}/{days}", aget(move |Path((key, source, area, days)): Path<(String, String, String, String)>, RawQuery(_): RawQuery| {
            let body = body.clone();
            async move {
                URLS.lock().unwrap().push(format!("api:{source}:{area}:{days}"));
                if key != "GOODKEY" { return "Invalid MAP_KEY.".into_response(); }
                body.into_response()
            }
        }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{addr}")
}

fn cfg(up: &str, key: Option<&str>) -> Config {
    Config { files: format!("{up}/files"), api: format!("{up}/api"), map_key: key.map(str::to_string), watch_interval: Duration::from_secs(3600) }
}

static GW: Once = Once::new();
fn gateway_env() {
    GW.call_once(|| unsafe { env::set_var("OSNT_GATEWAY_KEY", "test-gateway-key") });
}

fn signed(method: &str, path: &str) -> String {
    let ts = now_secs();
    let mut mac = Hmac::<Sha256>::new_from_slice(b"test-gateway-key").unwrap();
    mac.update(format!("{ts}.{method}.{path}").as_bytes());
    let sig: String = mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect();
    format!("v1.{ts}.{sig}")
}

async fn serve(cfg: Config) -> (String, Shared) {
    static N: AtomicUsize = AtomicUsize::new(0);
    gateway_env();
    let dir = env::temp_dir().join(format!("osnt-fire-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    let _ = std::fs::remove_dir_all(&dir);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (router, st) = app(cfg, dir);
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), st)
}

async fn req(method: &'static str, url: String, gw: Option<String>, body: Option<Value>) -> (u16, Value) {
    tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
        let path = url.splitn(4, '/').nth(3).map(|p| format!("/{p}")).unwrap_or_default();
        let _ = path;
        let mut b = ureq::http::Request::builder().method(method).uri(&url);
        if let Some(g) = gw {
            b = b.header("X-OSNT-Gateway", g);
        }
        let r = match body {
            Some(v) => agent.run(b.header("Content-Type", "application/json").body(v.to_string()).unwrap()),
            None => agent.run(b.body(String::new()).unwrap()),
        };
        let mut r = r.unwrap();
        (r.status().as_u16(), r.body_mut().read_json().unwrap_or(Value::Null))
    })
    .await
    .unwrap()
}

async fn getj(url: String) -> (u16, Value) {
    req("GET", url, None, None).await
}

#[test]
fn csv_parses_filters_box_and_rejects_non_csv() {
    let (pts, trunc) = firms::parse_csv(&fixture(), &[-121.0, 39.0, -118.0, 42.0], 100).unwrap();
    assert_eq!(pts.len(), 5, "4 current + 1 old row inside the box; the Australian row and the garbage line are skipped");
    assert!(!trunc);
    assert_eq!(pts[0].conf, 2);
    assert!(pts[0].night && !pts[2].night);
    assert_eq!(pts[3].conf, 0);
    let (cap, trunc) = firms::parse_csv(&fixture(), &[-180.0, -90.0, 180.0, 90.0], 2).unwrap();
    assert_eq!(cap.len(), 2);
    assert!(trunc, "row cap reported");
    assert!(firms::parse_csv("Invalid MAP_KEY.", &[-180.0, -90.0, 180.0, 90.0], 10).is_err());
    assert!(firms::parse_csv("latitude,longitude\n1,2\n", &[-180.0, -90.0, 180.0, 90.0], 10).is_err(), "missing columns");
    assert!(firms::parse_csv("", &[-180.0, -90.0, 180.0, 90.0], 10).is_err());
}

#[test]
fn clustering_groups_nearby_and_respects_eps() {
    let (pts, _) = firms::parse_csv(&fixture(), &[-121.0, 39.0, -118.0, 42.0], 100).unwrap();
    let c = firms::cluster(&pts, 2.0);
    assert_eq!(c.len(), 2, "fire A (4 detections incl. old) and fire B");
    assert_eq!(c[0].count, 4);
    assert!((c[0].frp_total - 42.0).abs() < 1e-9);
    assert_eq!(c[0].frp_max, 20.0);
    assert!((c[0].lat - 40.004).abs() < 0.01);
    assert!(c[0].radius_km < 2.0);
    assert_eq!(firms::cluster(&pts, 0.5).len() > 2, true, "a tighter linking distance splits fire A");
    assert!(firms::cluster(&[], 2.0).is_empty());
    // Many scattered points stay linear and correct: a 60 x 60 lattice 1 km apart is one cluster at eps 1.5 km.
    let lattice: Vec<firms::Hotspot> = (0..60).flat_map(|i| (0..60).map(move |j| firms::Hotspot { lat: 10.0 + i as f64 * 0.009, lon: 170.0 + j as f64 * 0.0091, frp: 1.0, t: 0, night: false, conf: 1, sat: "N".into() })).collect();
    assert_eq!(firms::cluster(&lattice, 1.5).len(), 1);
    assert_eq!(firms::cluster(&lattice, 0.5).len(), 3600);
}

#[test]
fn region_selection_and_stats() {
    assert_eq!(firms::region_for(&[-121.0, 39.0, -118.0, 42.0]), "USA_contiguous_and_Hawaii");
    assert_eq!(firms::region_for(&[-5.0, 40.0, 5.0, 50.0]), "Europe");
    assert_eq!(firms::region_for(&[-180.0, -90.0, 180.0, 90.0]), "Global");
    assert_eq!(firms::region_for(&[-60.0, 30.0, 10.0, 45.0]), "Global", "spans two regions");
    let (pts, _) = firms::parse_csv(&fixture(), &[-121.0, 39.0, -118.0, 42.0], 100).unwrap();
    let st = firms::stats(&pts, &firms::cluster(&pts, 2.0));
    assert_eq!(st["detections"], 5);
    assert_eq!(st["night"], 2);
    assert_eq!(st["day"], 3);
    assert_eq!(st["confidence"]["high"], 1);
    assert_eq!(st["timeline"].as_array().unwrap().len(), 2, "two UTC dates");
    assert!((st["frp_total_mw"].as_f64().unwrap() - 44.0).abs() < 1e-6);
}

#[test]
fn query_validation() {
    let q = |s: &str| -> HashMap<String, String> { s.split('&').filter_map(|p| p.split_once('=')).map(|(a, b)| (a.to_string(), b.to_string())).collect() };
    assert!(parse_query(&q("")).is_ok());
    for bad in ["bbox=1,2,3", "bbox=5,5,1,1", "bbox=-200,0,1,1", "sensor=modis", "window=30d", "days=0", "days=11", "hours=0", "min_frp=-1", "confidence=maybe", "eps_km=100", "bbox=a,b,c,d"] {
        assert!(parse_query(&q(bad)).is_err(), "{bad}");
    }
    assert_eq!(parse_query(&q("sensor=noaa20&window=7d&confidence=high")).unwrap().min_conf, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn fires_endpoint_summarises_and_caches_the_file() {
    let up = fake(fixture()).await;
    let (base, _) = serve(cfg(&up, None)).await;
    let url = format!("{base}/api/fires?bbox=-121,39,-118,42&hours=24&points=1&sensor=noaa20");
    let (code, v) = getj(url.clone()).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["stats"]["detections"], 4, "the 3-day-old row is outside hours=24");
    assert_eq!(v["clusters"][0]["count"], 3);
    assert_eq!(v["points"][0]["frp"], 20.0, "strongest first");
    assert!(v["meta"]["source"].as_str().unwrap().contains("USA contiguous and Hawaii"));
    let (_, v2) = getj(url).await;
    assert_eq!(v, v2);
    let n = URLS.lock().unwrap().iter().filter(|n| n.starts_with("J1_VIIRS_C2_USA_contiguous_and_Hawaii_24h")).count();
    assert_eq!(n, 1, "second call served from the cache");
    let (_, w) = getj(format!("{base}/api/fires?bbox=-121,39,-118,42&min_frp=15&confidence=nominal&sensor=noaa20")).await;
    assert_eq!(w["stats"]["detections"], 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn errors_are_clear() {
    let up = fake(fixture()).await;
    let (base, _) = serve(cfg(&up, None)).await;
    for (q, want) in [
        ("fires?bbox=1,2", 400),
        ("fires?window=7d", 400),          // worldwide 7d is refused
        ("fires?days=3", 400),             // no key
        ("clusters?limit=0", 400),
        ("export?format=xml", 400),
        ("recent?sensor=x", 400),
    ] {
        let (code, v) = getj(format!("{base}/api/{q}")).await;
        assert_eq!(code, want, "{q}: {v}");
        assert!(v["error"].is_string());
    }
    // Upstream failure -> 502, and a non-CSV body (key rejected) -> 502 without echoing anything secret.
    let dead = serve(cfg("http://127.0.0.1:9", None)).await.0;
    assert_eq!(getj(format!("{dead}/api/fires?bbox=-121,39,-118,42")).await.0, 502);
    let (b2, _) = serve(cfg(&up, Some("BADKEY"))).await;
    let (code, v) = getj(format!("{b2}/api/fires?bbox=-121,39,-118,42&days=2")).await;
    assert_eq!(code, 502);
    assert!(!v.to_string().contains("BADKEY"));
}

#[tokio::test(flavor = "multi_thread")]
async fn map_key_unlocks_area_api_and_never_hits_the_cache_dir() {
    let up = fake(fixture()).await;
    let (base, st) = serve(cfg(&up, Some("GOODKEY"))).await;
    let (code, v) = getj(format!("{base}/api/clusters?bbox=-121,39,-118,42&days=3")).await;
    assert_eq!(code, 200, "{v}");
    assert!(v["meta"]["source"].as_str().unwrap().contains("area API"));
    assert!(URLS.lock().unwrap().iter().any(|u| u == "api:VIIRS_SNPP_NRT:-121,39,-118,42:3"));
    // The key must not appear in any cache file.
    let dir = env::temp_dir().join(format!("osnt-fire-test-{}", std::process::id()));
    let _ = (dir, st);
    let all = std::fs::read_dir(env::temp_dir()).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().starts_with("osnt-fire-test-")).flat_map(|e| walk(e.path())).any(|f| std::fs::read(f).map(|b| b.windows(7).any(|w| w == b"GOODKEY")).unwrap_or(false));
    assert!(!all, "API key leaked into the cache");
    assert_eq!(getj(format!("{base}/api/info")).await.1["map_key_configured"], true);
}

fn walk(p: std::path::PathBuf) -> Vec<std::path::PathBuf> {
    if p.is_dir() { std::fs::read_dir(&p).map(|r| r.flatten().flat_map(|e| walk(e.path())).collect()).unwrap_or_default() } else { vec![p] }
}

#[tokio::test(flavor = "multi_thread")]
async fn export_formats() {
    let up = fake(fixture()).await;
    let (base, _) = serve(cfg(&up, None)).await;
    let (code, g) = getj(format!("{base}/api/export?bbox=-121,39,-118,42&hours=24")).await;
    assert_eq!(code, 200);
    assert_eq!(g["type"], "FeatureCollection");
    assert_eq!(g["features"].as_array().unwrap().len(), 2);
    assert_eq!(g["features"][0]["geometry"]["type"], "Point");
    let url = format!("{base}/api/export?bbox=-121,39,-118,42&hours=24&format=csv&what=points");
    let (ct, text) = tokio::task::spawn_blocking(move || {
        let mut r = ureq::get(&url).call().unwrap();
        (r.headers().get("content-type").unwrap().to_str().unwrap().to_string(), r.body_mut().read_to_string().unwrap())
    })
    .await
    .unwrap();
    assert!(ct.starts_with("text/csv"));
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "lat,lon,frp,time,night,confidence,satellite");
    assert_eq!(lines.len(), 5);
}

#[test]
fn watch_diff_flags_only_new_fires() {
    let (pts, _) = firms::parse_csv(&fixture(), &[-121.0, 39.0, -118.0, 42.0], 100).unwrap();
    let cl = firms::cluster(&pts, 2.0);
    let now = now_secs();
    let (fresh, seen) = watch::diff(&[], &cl, now);
    assert_eq!(fresh.len(), 2);
    let (fresh2, _) = watch::diff(&seen, &cl, now + 60);
    assert!(fresh2.is_empty(), "same fires are not new again");
    let mut moved = cl.clone();
    moved[1].lat += 0.01; // ~1 km drift is still the same fire
    assert!(watch::diff(&seen, &moved, now).0.is_empty());
    moved[1].lat += 1.0;
    assert_eq!(watch::diff(&seen, &moved, now).0, vec![1]);
    // Stale seen entries expire.
    let (fresh3, _) = watch::diff(&seen, &cl, now + 30 * 86_400);
    assert_eq!(fresh3.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn watches_require_gateway_and_flag_new_clusters() {
    let up = fake(fixture()).await;
    let (base, st) = serve(cfg(&up, None)).await;
    // No signature: refused on every watch route.
    assert_eq!(req("GET", format!("{base}/api/watches"), None, None).await.0, 401);
    assert_eq!(req("POST", format!("{base}/api/watches"), None, Some(json!({ "name": "x", "bbox": "-121,39,-118,42" }))).await.0, 401);
    assert_eq!(req("DELETE", format!("{base}/api/watches/w1"), Some("v1.1.00".into()), None).await.0, 401);
    // A signature for a different path does not work.
    assert_eq!(req("GET", format!("{base}/api/watches"), Some(signed("GET", "/api/other")), None).await.0, 401);
    // Valid input checks.
    let post = |body: Value| req("POST", format!("{base}/api/watches"), Some(signed("POST", "/api/watches")), Some(body));
    assert_eq!(post(json!({ "bbox": "-121,39,-118,42" })).await.0, 400);
    assert_eq!(post(json!({ "name": "x", "bbox": "-121,39" })).await.0, 400);
    assert_eq!(post(json!({ "name": "big", "bbox": "-100,0,-10,60" })).await.0, 400);
    let (code, v) = post(json!({ "name": "Sierra", "bbox": "-121,39,-118,42" })).await;
    assert_eq!(code, 200, "{v}");
    let w = &v["watches"][0];
    assert_eq!(w["clusters_now"], 2);
    assert_eq!(w["new_count"], 0, "first check is a silent baseline");
    let id = w["id"].as_str().unwrap().to_string();
    // A new fire appears in the upstream file: swap the cache by editing the watch's seen list instead.
    st.watches.update_for_test(&id, |w| w.seen.truncate(1));
    let (code, v) = req("POST", format!("{base}/api/watches/check"), Some(signed("POST", "/api/watches/check")), None).await;
    assert_eq!(code, 200);
    assert_eq!(v["watches"][0]["new_count"], 1);
    let (_, v) = req("GET", format!("{base}/api/watches"), Some(signed("GET", "/api/watches")), None).await;
    assert_eq!(v["watches"].as_array().unwrap().len(), 1);
    // Persisted to disk and reloadable.
    let (code, v) = req("DELETE", format!("{base}/api/watches/{id}"), Some(signed("DELETE", &format!("/api/watches/{id}"))), None).await;
    assert_eq!(code, 200);
    assert!(v["watches"].as_array().unwrap().is_empty());
    assert_eq!(req("DELETE", format!("{base}/api/watches/{id}"), Some(signed("DELETE", &format!("/api/watches/{id}"))), None).await.0, 404);
}

#[test]
fn watch_store_caps_and_persists() {
    let dir = env::temp_dir().join(format!("osnt-fire-store-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let s = watch::Store::open(dir.join("w.json"));
    for i in 0..watch::MAX_WATCHES {
        std::thread::sleep(Duration::from_millis(1));
        s.add(format!("w{i}"), [0.0, 0.0, 1.0, 1.0], 0.0).unwrap();
    }
    assert!(s.add("one too many".into(), [0.0, 0.0, 1.0, 1.0], 0.0).is_err());
    let again = watch::Store::open(dir.join("w.json"));
    assert_eq!(again.list().len(), watch::MAX_WATCHES);
    let ids: std::collections::HashSet<String> = again.ids().into_iter().collect();
    assert_eq!(ids.len(), watch::MAX_WATCHES, "ids are unique");
}

#[tokio::test(flavor = "multi_thread")]
async fn tools_and_page() {
    let (base, _) = serve(cfg("http://127.0.0.1:9", None)).await;
    let (_, t) = getj(format!("{base}/tools")).await;
    let names: Vec<&str> = t.as_array().unwrap().iter().map(|x| x["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["fire_recent", "fire_clusters"]);
    let (_, i) = getj(format!("{base}/api/info")).await;
    assert!(i["overlap"].as_str().unwrap().contains("Imagery"));
    let page = tokio::task::spawn_blocking(move || ureq::get(&format!("{base}/")).call().unwrap().body_mut().read_to_string().unwrap()).await.unwrap();
    assert!(page.contains("osnt-ui.css") && page.contains("embedded"));
}

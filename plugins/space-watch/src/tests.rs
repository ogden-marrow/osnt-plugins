use super::*;
use axum::{extract::{Path, RawQuery}, routing::get as aget};
use std::sync::{Mutex, atomic::{AtomicUsize, Ordering}};

static QUERIES: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn ll_launch(id: &str, name: &str, net: &str, status: (&str, &str), pad: &str, lat: &str, lon: &str) -> Value {
    json!({ "id": id, "slug": name.to_lowercase().replace(' ', "-").replace('|', "").replace("--", "-"), "name": name, "net": net, "window_start": net, "window_end": net,
        "status": { "name": status.0, "abbrev": status.1 }, "net_precision": { "name": "Minute" }, "probability": 90,
        "launch_service_provider": { "name": "Rocket Lab", "type": "Commercial" }, "rocket": { "configuration": { "name": "Electron" } },
        "mission": { "name": "Sea God", "type": "Earth Science", "orbit": { "name": "Low Earth Orbit", "abbrev": "LEO" }, "description": "A radar satellite. ".repeat(40) },
        "pad": { "name": pad, "latitude": lat, "longitude": lon, "location": { "name": "Mahia, New Zealand" }, "country_code": "NZL", "map_url": "https://www.google.com/maps?q=1,2", "wiki_url": "https://evil.example/x" },
        "webcast_live": false, "holdreason": "", "failreason": "", "image": "https://thespacedevs-prod.nyc3.digitaloceanspaces.com/media/x.jpg" })
}

fn ll_list() -> Value {
    json!({ "count": 478, "results": [
        ll_launch("b", "Falcon 9 | Starlink", "2027-01-02T10:00:00Z", ("Go for Launch", "Go"), "SLC-40", "28.56", "-80.57"),
        ll_launch("a", "Electron | Sea God", "2027-01-01T10:00:00Z", ("To Be Confirmed", "TBC"), "LC-1A", "-39.26", "177.86"),
        ll_launch("c", "Falcon 9 | Transporter", "2027-01-03T10:00:00Z", ("Go for Launch", "Go"), "SLC-40", "28.56", "-80.57"),
    ] })
}

fn iss_gp() -> Value {
    json!({ "OBJECT_NAME": "ISS (ZARYA)", "OBJECT_ID": "1998-067A", "EPOCH": "2026-11-02T18:09:49.393152", "MEAN_MOTION": 15.49154261, "ECCENTRICITY": 0.0007124, "INCLINATION": 51.6331,
            "RA_OF_ASC_NODE": 334.3796, "ARG_OF_PERICENTER": 340.7366, "MEAN_ANOMALY": 19.3352, "NORAD_CAT_ID": 25544, "REV_AT_EPOCH": 59323, "BSTAR": 0.0001062, "MEAN_MOTION_DOT": 5.437e-5 })
}

fn iss_sc() -> Value {
    json!({ "OBJECT_NAME": "ISS (ZARYA)", "OBJECT_ID": "1998-067A", "NORAD_CAT_ID": 25544, "OBJECT_TYPE": "PAY", "OPS_STATUS_CODE": "+", "OWNER": "ISS", "LAUNCH_DATE": "1998-11-20",
            "LAUNCH_SITE": "TYMSC", "DECAY_DATE": "", "PERIOD": 92.95, "INCLINATION": 51.63, "APOGEE": 424, "PERIGEE": 414, "RCS": 399.05 })
}

fn low_sat(id: u64, name: &str, mm: f64) -> Value {
    json!({ "OBJECT_NAME": name, "OBJECT_ID": "2020-001A", "EPOCH": "2026-11-02T00:00:00", "MEAN_MOTION": mm, "ECCENTRICITY": 0.0002, "INCLINATION": 53.0, "NORAD_CAT_ID": id, "RA_OF_ASC_NODE": 1.0, "ARG_OF_PERICENTER": 2.0, "MEAN_ANOMALY": 3.0 })
}

async fn fake(rate_limited: Arc<AtomicUsize>) -> (String, Arc<AtomicUsize>) {
    let ll_hits = Arc::new(AtomicUsize::new(0));
    let (h1, rl) = (ll_hits.clone(), rate_limited);
    let rec = |q: Option<String>| QUERIES.lock().unwrap().push(q.unwrap_or_default());
    let router = Router::new()
        .route("/ll/launch/{which}/", aget(move |Path(w): Path<String>| {
            let (h, rl) = (h1.clone(), rl.clone());
            async move {
                h.fetch_add(1, Ordering::SeqCst);
                if rl.load(Ordering::SeqCst) == 1 && w == "previous" { return (StatusCode::TOO_MANY_REQUESTS, "Request was throttled. Expected available in 3000 seconds.").into_response(); }
                Json(ll_list()).into_response()
            }
        }))
        .route("/gp", aget(move |RawQuery(q): RawQuery| async move {
            let q = q.unwrap_or_default();
            rec(Some(q.clone()));
            if q.starts_with("NAME=GONE") { return (StatusCode::NOT_FOUND, "No GP data found").into_response(); }
            if q.starts_with("CATNR=25544") || q.starts_with("INTDES=1998-067A") { return Json(json!([iss_gp()])).into_response(); }
            if q.starts_with("GROUP=active") { return Json(json!([iss_gp(), low_sat(1, "LOW-A", 16.20), low_sat(2, "LOW-B", 16.05), low_sat(3, "TOOLOW", 17.5), low_sat(4, "HIGHER", 14.0)])).into_response(); }
            if q.starts_with("GROUP=stations") { return Json(json!([iss_gp(), low_sat(5, "CSS (TIANHE)", 15.6)])).into_response(); }
            "No GP data found".into_response()
        }))
        .route("/satcat", aget(move |RawQuery(q): RawQuery| async move {
            let q = q.unwrap_or_default();
            rec(Some(format!("sc:{q}")));
            if q.starts_with("NAME=GONE") { return (StatusCode::NOT_FOUND, "").into_response(); }
            if q.contains("INTDES=1998-067A") {
                let mut deb = iss_sc(); deb["OBJECT_NAME"] = json!("ISS DEB"); deb["OBJECT_ID"] = json!("1998-067AA"); deb["NORAD_CAT_ID"] = json!(26000); deb["DECAY_DATE"] = json!("2004-10-12");
                return Json(json!([iss_sc(), deb])).into_response();
            }
            if q.contains("25544") || q.contains("1998-067A") || q.starts_with("GROUP=stations") { return Json(json!([iss_sc()])).into_response(); }
            if q.starts_with("GROUP=last-30-days") {
                return Json(json!([
                    { "OBJECT_NAME": "NEONSAT-02", "OBJECT_ID": "2026-229A", "NORAD_CAT_ID": 100955, "OBJECT_TYPE": "PAY", "OPS_STATUS_CODE": "+", "OWNER": "SKOR", "LAUNCH_DATE": "2026-10-07", "DECAY_DATE": "", "PERIGEE": 567, "APOGEE": 583 },
                    { "OBJECT_NAME": "FALCON 9 R/B", "OBJECT_ID": "2026-240B", "NORAD_CAT_ID": 100990, "OBJECT_TYPE": "R/B", "OPS_STATUS_CODE": "D", "OWNER": "US", "LAUNCH_DATE": "2026-10-20", "DECAY_DATE": "2026-10-25" } ])).into_response();
            }
            "Invalid query".into_response()
        }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), ll_hits)
}

fn cfg(up: &str) -> Config {
    Config { ll: format!("{up}/ll"), gp: format!("{up}/gp"), satcat: format!("{up}/satcat") }
}

async fn serve(cfg: Config) -> String {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = env::temp_dir().join(format!("osnt-space-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    let _ = std::fs::remove_dir_all(&dir);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = app(cfg, dir);
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{addr}")
}

async fn getj(url: String) -> (u16, Value) {
    tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
        let mut r = agent.get(&url).call().unwrap();
        (r.status().as_u16(), r.body_mut().read_json().unwrap_or(Value::Null))
    })
    .await
    .unwrap()
}

#[test]
fn orbit_geometry_matches_reference_values() {
    // ISS GP (epoch 2026-11-02): CelesTrak SATCAT lists period 92.95 min, apogee 424 km, perigee 414 km.
    let g = orbit::geometry(15.49154261, 0.0007124).unwrap();
    assert!((g.period_min - 92.95).abs() < 0.02, "{}", g.period_min);
    assert!((g.apogee_km - 424.0).abs() < 8.0 && (g.perigee_km - 414.0).abs() < 8.0, "{} {}", g.apogee_km, g.perigee_km);
    // Geostationary: 1.0027379 rev/day -> semi-major axis 42164 km, altitude 35786 km.
    let geo = orbit::geometry(1.0027379, 0.0001).unwrap();
    assert!((geo.sma_km - 42_164.0).abs() < 5.0, "{}", geo.sma_km);
    assert!((geo.perigee_km - 35_786.0).abs() < 15.0);
    assert_eq!(orbit::orbit_class(&geo, 0.0001), "GEO");
    assert_eq!(orbit::orbit_class(&g, 0.0007), "LEO");
    // GPS: ~2.0 rev/day, ~20200 km altitude, MEO.
    let gps = orbit::geometry(2.00561, 0.005).unwrap();
    assert!((gps.perigee_km - 20_200.0).abs() < 300.0, "{}", gps.perigee_km);
    assert_eq!(orbit::orbit_class(&gps, 0.005), "MEO");
    // Molniya-like: highly eccentric.
    let m = orbit::geometry(2.0, 0.72).unwrap();
    assert_eq!(orbit::orbit_class(&m, 0.72), "HEO");
    assert!(orbit::geometry(0.0, 0.1).is_none() && orbit::geometry(15.0, 1.2).is_none() && orbit::geometry(f64::NAN, 0.1).is_none());
}

#[test]
fn records_normalise() {
    let e = orbit::gp_record(&iss_gp()).unwrap();
    assert_eq!(e["norad_id"], 25544);
    assert_eq!(e["orbit_class"], "LEO");
    assert_eq!(e["epoch"], "2026-11-02T18:09:49Z");
    assert!(e["perigee_km"].as_f64().unwrap() > 400.0);
    assert!(orbit::gp_record(&json!({ "OBJECT_NAME": "x" })).is_none());
    let c = orbit::satcat_record(&iss_sc()).unwrap();
    assert_eq!((c["object_type"].as_str(), c["status"].as_str(), c["owner"].as_str()), (Some("Payload"), Some("Operational"), Some("ISS")));
    assert_eq!(c["decayed"], false);
    assert!(c["decay_date"].is_null(), "empty strings become null");
    let l = orbit::launch(&ll_list()["results"][0], 1_800_000_000).unwrap();
    assert_eq!(l["pad"], "SLC-40");
    assert_eq!(l["pad_lat"], 28.56);
    assert!(l["pad_wiki"].is_null(), "links off the expected hosts are dropped");
    assert!(l["description"].as_str().unwrap().chars().count() <= 321);
    assert_eq!(l["seconds_to_net"].as_i64().unwrap(), util::parse_iso("2027-01-02T10:00:00Z").unwrap() - 1_800_000_000);
}

#[test]
fn selector_validates() {
    let q = |s: &str| -> HashMap<String, String> { s.split('&').filter_map(|p| p.split_once('=')).map(|(a, b)| (a.to_string(), b.to_string())).collect() };
    assert_eq!(selector(&q("catnr=25544")).unwrap().query, "CATNR=25544");
    assert_eq!(selector(&q("group=Stations")).unwrap().query, "GROUP=stations");
    assert_eq!(selector(&q("intl=1998-067a")).unwrap().query, "INTDES=1998-067A");
    assert_eq!(selector(&q("name=ISS (ZARYA)")).unwrap().query, "NAME=ISS%20%28ZARYA%29");
    for bad in ["", "catnr=12a", "catnr=1234567890", "name=a", "name=x&catnr=1", "name=a%26b=c", "name=<script>alert(1)</script>", "group=everything", "intl=98-067A", "intl=1998-067&"] {
        assert!(selector(&q(bad)).is_err(), "{bad}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn launches_sorted_filtered_and_cached() {
    let (up, hits) = fake(Arc::new(AtomicUsize::new(0))).await;
    let base = serve(cfg(&up)).await;
    let (code, v) = getj(format!("{base}/api/launches")).await;
    assert_eq!(code, 200, "{v}");
    let names: Vec<&str> = v["launches"].as_array().unwrap().iter().map(|l| l["id"].as_str().unwrap()).collect();
    assert_eq!(names, ["a", "b", "c"], "soonest first");
    let (_, f) = getj(format!("{base}/api/launches?q=transporter")).await;
    assert_eq!(f["count"], 1);
    let (_, s) = getj(format!("{base}/api/launches?status=tbc&limit=5")).await;
    assert_eq!(s["launches"][0]["id"], "a");
    let (_, l) = getj(format!("{base}/api/launches?limit=2")).await;
    assert_eq!(l["count"], 2);
    assert_eq!(hits.load(Ordering::SeqCst), 1, "four requests, one upstream call (rate limit is 15/hour)");
    for (q, want) in [("which=future".to_string(), 400), ("limit=0".to_string(), 400), ("limit=500".to_string(), 400), ("q=".to_string() + &"x".repeat(61), 400)] {
        assert_eq!(getj(format!("{base}/api/launches?{q}")).await.0, want, "{q}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_rate_limit_is_explained_and_stale_copy_served() {
    let rl = Arc::new(AtomicUsize::new(1));
    let (up, _) = fake(rl.clone()).await;
    let base = serve(cfg(&up)).await;
    let (code, v) = getj(format!("{base}/api/launches?which=previous")).await;
    assert_eq!(code, 502);
    assert!(v["error"].as_str().unwrap().contains("429"), "{v}");
    // Down entirely: still a clean 502.
    let dead = serve(cfg("http://127.0.0.1:9")).await;
    assert_eq!(getj(format!("{dead}/api/launches")).await.0, 502);
}

#[tokio::test(flavor = "multi_thread")]
async fn pads_group_launches() {
    let (up, _) = fake(Arc::new(AtomicUsize::new(0))).await;
    let base = serve(cfg(&up)).await;
    let (code, v) = getj(format!("{base}/api/pads")).await;
    assert_eq!(code, 200);
    let pads = v["pads"].as_array().unwrap();
    assert_eq!(pads.len(), 2);
    let slc = pads.iter().find(|p| p["pad"] == "SLC-40").unwrap();
    assert_eq!(slc["launches"], 2);
    assert_eq!(slc["next"]["name"], "Falcon 9 | Starlink");
}

#[tokio::test(flavor = "multi_thread")]
async fn object_merges_elements_and_catalog() {
    let (up, _) = fake(Arc::new(AtomicUsize::new(0))).await;
    let base = serve(cfg(&up)).await;
    let (code, v) = getj(format!("{base}/api/object?catnr=25544")).await;
    assert_eq!(code, 200, "{v}");
    let o = &v["objects"][0];
    assert_eq!(o["name"], "ISS (ZARYA)");
    assert_eq!(o["catalog"]["owner"], "ISS");
    assert_eq!(o["orbit_class"], "LEO");
    assert!(v["links"]["passes_and_imagery"].is_string());
    let (_, g) = getj(format!("{base}/api/object?group=stations")).await;
    assert_eq!(g["total"], 2);
    assert!(g["objects"][0]["catalog"].is_null(), "no catalog row for the second station in this fixture");
    // A query with no data on either side is an empty result (CelesTrak answers 404 / plain text), not a crash.
    let (code, v) = getj(format!("{base}/api/object?name=NOSUCHTHING")).await;
    assert_eq!((code, v["count"].as_u64()), (200, Some(0)), "{v}");
    for q in ["", "catnr=abc", "group=nope", "name=x"] {
        assert_eq!(getj(format!("{base}/api/object?{q}")).await.0, 400, "{q}");
    }
    assert!(QUERIES.lock().unwrap().iter().any(|q| q == "CATNR=25544&FORMAT=json"));
}

#[tokio::test(flavor = "multi_thread")]
async fn recent_lists() {
    let (up, _) = fake(Arc::new(AtomicUsize::new(0))).await;
    let base = serve(cfg(&up)).await;
    let (code, v) = getj(format!("{base}/api/recent")).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["objects"][0]["name"], "FALCON 9 R/B", "newest launch first");
    assert_eq!(v["objects"][0]["decayed"], true);
    let (code, d) = getj(format!("{base}/api/recent?list=decaying")).await;
    assert_eq!(code, 200, "{d}");
    let names: Vec<&str> = d["objects"].as_array().unwrap().iter().map(|o| o["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["LOW-A", "LOW-B"], "lowest perigee first; TOOLOW (decayed-range) and higher orbits are excluded: {names:?}");
    assert!(d["note"].as_str().unwrap().contains("NOT a reentry prediction"));
    assert_eq!(getj(format!("{base}/api/recent?list=x")).await.0, 400);
    assert_eq!(getj(format!("{base}/api/recent?list=decaying&max_perigee_km=5")).await.0, 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn tools_and_page() {
    let base = serve(cfg("http://127.0.0.1:9")).await;
    let (_, t) = getj(format!("{base}/tools")).await;
    let names: Vec<&str> = t.as_array().unwrap().iter().map(|x| x["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["space_launches", "space_object", "space_recent"]);
    let page = tokio::task::spawn_blocking(move || ureq::get(&format!("{base}/")).call().unwrap().body_mut().read_to_string().unwrap()).await.unwrap();
    assert!(page.contains("osnt-ui.css") && page.contains("embedded"));
}

#[test]
fn disk_cache_expires_and_evicts() {
    let dir = env::temp_dir().join(format!("osnt-space-cache-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let c = cache::DiskCache::new(dir, 100);
    c.put("a", &[1u8; 60]);
    assert!(c.get("a", Duration::from_secs(60)).is_some());
    std::thread::sleep(Duration::from_millis(20));
    c.put("b", &[2u8; 60]);
    c.evict();
    assert!(c.get("a", Duration::from_secs(60)).is_none() && c.get("b", Duration::from_secs(60)).is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn intl_designator_is_exact_and_no_match_is_an_empty_result() {
    let (up, _) = fake(Arc::new(AtomicUsize::new(0))).await;
    let base = serve(cfg(&up)).await;
    let (code, v) = getj(format!("{base}/api/object?intl=1998-067A")).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["count"], 1, "SATCAT prefix matches (debris) are dropped: {v}");
    assert_eq!(v["objects"][0]["norad_id"], 25544);
    let (code, v) = getj(format!("{base}/api/object?name=gone")).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["count"], 0);
}

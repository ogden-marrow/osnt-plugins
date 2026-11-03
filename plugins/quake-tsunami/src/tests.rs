use super::*;
use axum::{extract::RawQuery, http::StatusCode, routing::get};
use std::sync::{Mutex, atomic::{AtomicUsize, Ordering}};

static HITS: AtomicUsize = AtomicUsize::new(0);
static HOUR_HITS: AtomicUsize = AtomicUsize::new(0);
static QUERIES: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn usgs_fc() -> Value {
    json!({ "type": "FeatureCollection", "features": [
        { "id": "us1", "geometry": { "type": "Point", "coordinates": [159.7, 53.0, 75.5] },
          "properties": { "mag": 4.7, "magType": "mb", "place": "74 km E of Petropavlovsk-Kamchatsky, Russia", "time": 1793675592330i64, "felt": 12, "mmi": null, "alert": null,
                          "tsunami": 1, "sig": 340, "status": "reviewed", "url": "https://earthquake.usgs.gov/earthquakes/eventpage/us1" } },
        { "id": "us2", "geometry": { "type": "Point", "coordinates": [-122.1, 37.5, 8.0] },
          "properties": { "mag": 2.6, "magType": "ml", "place": "5 km N of Somewhere, CA", "time": 1793679000000i64, "felt": null, "tsunami": 0, "url": "https://evil.example/x" } },
        { "id": "bad", "geometry": { "type": "Point", "coordinates": [] }, "properties": {} }
    ] })
}

fn emsc_fc() -> Value {
    json!({ "type": "FeatureCollection", "features": [
        { "type": "Feature", "id": "20261103_0000052", "geometry": { "type": "Point", "coordinates": [-69.92, -17.46, -160.2] },
          "properties": { "source_id": "2084583", "time": "2026-11-03T04:19:24.0Z", "flynn_region": "SOUTHERN PERU", "lat": -17.46, "lon": -69.92, "depth": 160.2, "evtype": "ke", "mag": 2.7, "magtype": "ml", "unid": "20261103_0000052" } }
    ] })
}

const ATOM: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xmlns:geo="http://www.w3.org/2003/01/geo/wgs84_pos#">
<id>urn:uuid:1</id><title>        TSUNAMI INFORMATION STATEMENT NUMBER   1        </title>
<updated>2026-10-25T02:27:01Z</updated>
<author><name>NWS PACIFIC TSUNAMI WARNING CENTER HONOLULU HI</name></author>
<link rel="related" title="Energy Map" href="https://www.tsunami.gov/events/PHEB/map/" type="image/jpeg" />
<entry>
<title>BONIN ISLANDS  JAPAN REGION</title><updated>2026-10-25T02:27:01Z</updated>
<geo:lat>28.</geo:lat>
<geo:long>139.9</geo:long>
<summary type="xhtml"><div xmlns="http://www.w3.org/1999/xhtml">
<strong>Category:</strong> Warning<br/><strong>Bulletin Issue Time: </strong> 2026.10.25 02:27:01 UTC <br/><strong>Preliminary Magnitude: </strong>7.0(Mwp)<br/><strong>Lat/Lon: </strong>28. / 139.9<br/><strong>Affected Region: </strong>BONIN ISLANDS  JAPAN REGION<br/><b>Note:</b>  <br/></div></summary>
<id>urn:uuid:2</id><link rel="related" title="CapXML document" href="https://www.tsunami.gov/events/PHEB/2026/10/24/1/PHEBCAP.xml" type="application/cap+xml" />
<link rel="alternate" title="Bulletin" href="https://www.tsunami.gov/events/PHEB/2026/10/24/1/WEGM42.txt" type="application/xml" />
</entry>
</feed>"#;

const ATOM_EMPTY: &str = r#"<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>No bulletins</title></feed>"#;

async fn fake() -> String {
    let rec = |q: Option<String>| {
        HITS.fetch_add(1, Ordering::SeqCst);
        QUERIES.lock().unwrap().push(q.unwrap_or_default());
    };
    let router = Router::new()
        .route("/feed/{name}", get(move |axum::extract::Path(n): axum::extract::Path<String>| async move {
            HITS.fetch_add(1, Ordering::SeqCst);
            if n == "2.5_hour.geojson" {
                HOUR_HITS.fetch_add(1, Ordering::SeqCst);
            }
            if n == "significant_month.geojson" {
                return (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response();
            }
            Json(usgs_fc()).into_response()
        }))
        .route("/usgs", get(move |RawQuery(q): RawQuery| async move { rec(q); Json(usgs_fc()) }))
        .route("/emsc", get(move |RawQuery(q): RawQuery| async move { rec(q); Json(emsc_fc()) }))
        .route("/ts/{name}", get(|axum::extract::Path(n): axum::extract::Path<String>| async move {
            HITS.fetch_add(1, Ordering::SeqCst);
            if n == "PAAQAtom.xml" { ATOM_EMPTY.to_string() } else { ATOM.to_string() }
        }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{addr}")
}

fn cfg(up: &str) -> Config {
    Config { usgs_feed: format!("{up}/feed"), usgs_fdsn: format!("{up}/usgs"), emsc_fdsn: format!("{up}/emsc"), tsunami_base: format!("{up}/ts") }
}

async fn serve(cfg: Config) -> String {
    let dir = env::temp_dir().join(format!("osnt-quake-test-{}-{}", std::process::id(), HITS.load(Ordering::SeqCst) + now_secs() as usize));
    let _ = std::fs::remove_dir_all(&dir);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = app(cfg, dir);
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{addr}")
}

async fn get_json(url: String) -> (u16, Value) {
    tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
        let mut r = agent.get(&url).call().unwrap();
        (r.status().as_u16(), r.body_mut().read_json().unwrap_or(Value::Null))
    })
    .await
    .unwrap()
}

#[test]
fn date_maths_round_trips() {
    assert_eq!(parse_iso("1970-01-01"), Some(0));
    assert_eq!(parse_iso("2026-10-25T02:27:01Z"), Some(1792895221));
    assert_eq!(iso(1792895221), "2026-10-25T02:27:01Z");
    assert_eq!(parse_iso("2026-13-01"), None);
    assert_eq!(parse_iso("2026-10-25X02:27"), None);
    assert!(valid_date("2026-02-28") && !valid_date("2026-2-28") && !valid_date("nope"));
}

#[test]
fn normalises_usgs_and_emsc_events() {
    let evs = events_of("usgs", &usgs_fc());
    assert_eq!(evs.len(), 2, "the malformed feature is skipped");
    assert_eq!(evs[0]["id"], "usgs:us2", "newest first");
    let e = &evs[1];
    assert_eq!(e["mag"], 4.7);
    assert_eq!(e["depth_km"], 75.5);
    assert_eq!(e["felt"], 12);
    assert_eq!(e["tsunami"], true);
    assert_eq!(e["url"], "https://earthquake.usgs.gov/earthquakes/eventpage/us1");
    assert!(evs[0]["url"].is_null(), "links off the USGS host are dropped");
    let em = events_of("emsc", &emsc_fc());
    assert_eq!(em[0]["depth_km"], 160.2);
    assert_eq!(em[0]["time"], "2026-11-03T04:19:24Z");
    assert_eq!(em[0]["url"], "https://www.emsc-csem.org/Earthquake_information/earthquake.php?id=2084583");
}

#[test]
fn filters_validate_and_apply() {
    let q = |s: &str| -> HashMap<String, String> { s.split('&').filter_map(|p| p.split_once('=')).map(|(a, b)| (a.to_string(), b.to_string())).collect() };
    assert!(parse_filter(&q("minmag=abc")).is_err());
    assert!(parse_filter(&q("minmag=11")).is_err());
    assert!(parse_filter(&q("minmag=5&maxmag=4")).is_err());
    assert!(parse_filter(&q("mindepth=-5")).is_err());
    let f = parse_filter(&q("minmag=3&maxdepth=100")).unwrap();
    let evs = events_of("usgs", &usgs_fc());
    assert_eq!(evs.iter().filter(|e| passes(e, &f)).count(), 1, "only the M4.7 at 75 km passes minmag 3 and maxdepth 100");
}

#[test]
fn tsunami_atom_is_parsed() {
    let now = parse_iso("2026-10-25T10:00:00Z").unwrap();
    let b = tsunami::parse_atom(ATOM, "PHEB", now);
    assert_eq!(b.len(), 1);
    let b = &b[0];
    assert_eq!(b["category"], "Warning");
    assert_eq!(b["region"], "BONIN ISLANDS JAPAN REGION");
    assert_eq!(b["magnitude"], "7.0(Mwp)");
    assert_eq!(b["lat"], 28.0);
    assert_eq!(b["issued"], "2026-10-25T02:27:01Z");
    assert_eq!(b["current"], true);
    assert_eq!(b["statement"], "TSUNAMI INFORMATION STATEMENT NUMBER 1");
    assert_eq!(b["bulletin_url"], "https://www.tsunami.gov/events/PHEB/2026/10/24/1/WEGM42.txt");
    assert_eq!(b["cap_url"], "https://www.tsunami.gov/events/PHEB/2026/10/24/1/PHEBCAP.xml");
    let old = tsunami::parse_atom(ATOM, "PHEB", now + 5 * 86_400);
    assert_eq!(old[0]["current"], false, "old bulletins are not shown as current");
    assert!(tsunami::parse_atom(ATOM_EMPTY, "PAAQ", now).is_empty());
    assert!(tsunami::parse_atom("not xml at all", "PAAQ", now).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn recent_filters_and_caches() {
    let up = fake().await;
    let base = serve(cfg(&up)).await;
    let url = format!("{base}/api/recent?level=2.5&period=hour&minmag=4");
    let (code, v) = get_json(url.clone()).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["total_in_feed"], 2);
    assert_eq!(v["count"], 1);
    assert_eq!(v["events"][0]["mag"], 4.7);
    let (_, v2) = get_json(url).await;
    assert_eq!(v, v2);
    assert_eq!(HOUR_HITS.load(Ordering::SeqCst), 1, "second call is served from the cache");
}

#[tokio::test(flavor = "multi_thread")]
async fn search_builds_upstream_queries() {
    let up = fake().await;
    let base = serve(cfg(&up)).await;
    let (code, v) = get_json(format!("{base}/api/search?lat=37.5&lon=-122.1&radius_km=50&start=2026-10-01&end=2026-10-07&minmag=2")).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["count"], 2);
    assert_eq!(v["largest_mag"], 4.7);
    let (code, _) = get_json(format!("{base}/api/search?source=emsc&bbox=-80,-30,-60,-10&days=3&minmag=2.5&maxdepth=300")).await;
    assert_eq!(code, 200);
    let qs = QUERIES.lock().unwrap().clone();
    let usgs = qs.iter().find(|q| q.contains("maxradiuskm=50")).expect("usgs query");
    assert!(usgs.contains("latitude=37.5") && usgs.contains("longitude=-122.1") && usgs.contains("starttime=2026-10-01") && usgs.contains("endtime=2026-10-08") && usgs.contains("minmagnitude=2"), "{usgs}");
    let emsc = qs.iter().find(|q| q.contains("minlon=-80")).expect("emsc query");
    assert!(emsc.contains("minlat=-30") && emsc.contains("maxlon=-60") && emsc.contains("maxdepth=300") && emsc.contains("minmag=2.5") && emsc.contains("format=json"), "{emsc}");
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_input_is_rejected_and_upstream_errors_reported() {
    let up = fake().await;
    let base = serve(cfg(&up)).await;
    for (q, want) in [
        ("recent?level=9.9", 400),
        ("recent?period=year", 400),
        ("recent?source=evil", 400),
        ("recent?minmag=x", 400),
        ("recent?limit=0", 400),
        ("recent?limit=9999", 400),
        ("recent?level=significant&period=month", 502),
        ("search?lat=95&lon=0", 400),
        ("search?lat=10", 400),
        ("search?lat=1&lon=1&bbox=0,0,1,1", 400),
        ("search?bbox=5,5,1,1", 400),
        ("search?start=2026-13-01", 400),
        ("search?start=2026-10-09&end=2026-10-01", 400),
        ("search?days=0", 400),
    ] {
        let (code, v) = get_json(format!("{base}/api/{q}")).await;
        assert_eq!(code, want, "{q}: {v}");
        assert!(v["error"].is_string());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tsunami_merges_both_centres_and_survives_one_failure() {
    let up = fake().await;
    let base = serve(cfg(&up)).await;
    let (code, v) = get_json(format!("{base}/api/tsunami")).await;
    assert_eq!(code, 200);
    assert_eq!(v["count"], 1);
    assert_eq!(v["bulletins"][0]["centre"], "PHEB");
    // Upstream down entirely: a clear 502, no panic.
    let dead = serve(cfg("http://127.0.0.1:9")).await;
    let (code, v) = get_json(format!("{dead}/api/tsunami")).await;
    assert_eq!(code, 502);
    assert!(v["error"].is_string());
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_cache_is_served_when_upstream_dies() {
    let up = fake().await;
    let dir = env::temp_dir().join(format!("osnt-quake-stale-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let u = Upstream { agent: osnt_common::http_agent("t"), cache: cache::DiskCache::new(dir, 1 << 20) };
    let url = format!("{up}/feed/2.5_day.geojson");
    let fresh = tokio::task::spawn_blocking({ let url = url.clone(); move || { let r = u.get(&url, Duration::from_secs(0)); (u, r.map(|f| f.stale)) } }).await.unwrap();
    assert_eq!(fresh.1, Ok(false));
    let u = fresh.0;
    let dead = url.replace(up.trim_start_matches("http://"), "127.0.0.1:9");
    // Same cache key requires the same URL, so poison the key: store under the dead URL and ask again with ttl 0.
    u.cache.put(&dead, b"{\"features\":[]}");
    let r = tokio::task::spawn_blocking(move || u.get(&dead, Duration::from_secs(0)).map(|f| f.stale)).await.unwrap();
    assert_eq!(r, Ok(true));
}

#[tokio::test(flavor = "multi_thread")]
async fn tools_are_described_and_page_serves() {
    let base = serve(cfg("http://127.0.0.1:9")).await;
    let (_, t) = get_json(format!("{base}/tools")).await;
    let names: Vec<&str> = t.as_array().unwrap().iter().map(|x| x["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["quake_recent", "quake_search", "tsunami_bulletins"]);
    assert!(t[0]["path"].as_str().unwrap().starts_with("api/"));
    let page = tokio::task::spawn_blocking(move || ureq::get(&format!("{base}/")).call().unwrap().body_mut().read_to_string().unwrap()).await.unwrap();
    assert!(page.contains("osnt-ui.css") && page.contains("embedded"));
}

#[test]
fn disk_cache_expires_and_evicts() {
    let dir = env::temp_dir().join(format!("osnt-quake-cache-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let c = cache::DiskCache::new(dir, 100);
    c.put("a", &[1u8; 60]);
    assert_eq!(c.get("a", Duration::from_secs(60)).unwrap().len(), 60);
    std::thread::sleep(Duration::from_millis(20));
    c.put("b", &[2u8; 60]);
    c.evict();
    assert!(c.get("a", Duration::from_secs(60)).is_none(), "oldest entry evicted when over the size cap");
    assert!(c.get("b", Duration::from_secs(60)).is_some());
}

#[test]
fn parse_iso_applies_offsets_and_fractions() {
    assert_eq!(parse_iso("2026-11-02T14:05:13-09:00"), parse_iso("2026-11-02T23:05:13Z"));
    assert_eq!(parse_iso("2026-11-03T04:19:24.0Z"), parse_iso("2026-11-03T04:19:24Z"));
    assert_eq!(parse_iso("2026-11-03T04:19:24.123+01:00"), parse_iso("2026-11-03T03:19:24Z"));
}

#[test]
fn emsc_event_type_codes_are_words() {
    assert_eq!(crate::emsc_evtype("ke"), "earthquake");
    assert_eq!(crate::emsc_evtype("zz"), "zz");
}

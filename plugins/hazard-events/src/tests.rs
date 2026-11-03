use super::*;
use axum::{extract::RawQuery, http::StatusCode, routing::get};
use std::sync::{Mutex, atomic::{AtomicUsize, Ordering}};

static QUERIES: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn gdacs_fc() -> Value {
    json!({ "type": "FeatureCollection", "features": [
        { "geometry": { "type": "Point", "coordinates": [80.3, 15.5] }, "properties": { "eventtype": "TC", "eventid": 1001346, "name": "Tropical Cyclone MURASU-26", "htmldescription": "Red Tropical Cyclone MURASU-26 in India",
          "alertlevel": "Red", "alertscore": 3, "fromdate": "2026-11-01T00:00:00", "datemodified": "2026-11-03T02:02:00", "iscurrent": "true",
          "url": { "report": "https://www.gdacs.org/report.aspx?eventid=1001346&episodeid=9&eventtype=TC" }, "affectedcountries": [{ "countryname": "India" }],
          "severitydata": { "severitytext": "Hurricane/Typhoon > 74 mph" } } },
        { "geometry": { "type": "Point", "coordinates": [100.0, 35.0] }, "properties": { "eventtype": "EQ", "eventid": "1573141", "name": "Earthquake in China", "alertlevel": "Orange", "alertscore": 2, "fromdate": "2026-10-22T14:33:40",
          "url": { "report": "https://evil.example/report" } } },
        { "geometry": { "type": "Point", "coordinates": [999.0, 35.0] }, "properties": { "eventtype": "EQ", "eventid": 3, "alertlevel": "Green" } },
        { "geometry": null, "properties": { "eventtype": "EQ", "eventid": 4 } }
    ] })
}

fn eonet_v() -> Value {
    json!({ "events": [
        { "id": "EONET_1", "title": "Tropical Cyclone Murasu", "description": null, "link": "https://eonet.gsfc.nasa.gov/api/v3/events/EONET_1", "categories": [{ "id": "severeStorms", "title": "Severe Storms" }],
          "sources": [{ "id": "JTWC", "url": "https://www.metoc.navy.mil/jtwc/x.tcw" }],
          "geometry": [{ "magnitudeValue": 35.0, "magnitudeUnit": "kts", "date": "2026-11-01T00:00:00Z", "type": "Point", "coordinates": [86.2, 11.4] },
                       { "magnitudeValue": 60.0, "magnitudeUnit": "kts", "date": "2026-11-01T12:00:00Z", "type": "Point", "coordinates": [83.6, 12.9] }] },
        { "id": "EONET_2", "title": "Wildfire X", "link": "https://eonet.gsfc.nasa.gov/api/v3/events/EONET_2", "categories": [{ "id": "wildfires", "title": "Wildfires" }], "sources": [],
          "geometry": [{ "date": "2026-11-02T00:00:00Z", "type": "Polygon", "coordinates": [[[10.0, 40.0], [12.0, 40.0], [12.0, 42.0], [10.0, 42.0], [10.0, 40.0]]] }] },
        { "id": "EONET_3", "title": "Broken", "categories": [], "geometry": [] }
    ] })
}

const GVP: &str = r#"<?xml version="1.0" encoding="ISO-8859-1"?><rss xmlns:georss="http://www.georss.org/georss"><channel><title>x</title>
<item>
<title>Krakatau (Indonesia) - Report for 8 October-14 October 2026 - New Eruptive Activity</title>
<description>&lt;p&gt;PVMBG reported an increase in low-level eruptive activity.&lt;/p&gt;
&lt;p&gt;Source: PVMBG&lt;/p&gt;</description>
<link>https://volcano.si.edu/reports_weekly.cfm</link>
<guid isPermaLink="true">https://volcano.si.edu/reports_weekly.cfm#vn_262000</guid>
<pubDate>Thu, 15 Oct 2026 03:11:08 -0400</pubDate>
<georss:point>-6.1009 105.4233</georss:point>
</item>
<item><title>No point here</title><guid>x</guid></item>
</channel></rss>"#;

fn hans_v() -> Value {
    json!([{ "volcano_name_appended": "Great Sitkin Volcano", "latitude": 52.0765, "longitude": -176.1109, "vnum": "311120", "elevation_meters": 1740, "obs_fullname": "Alaska Volcano Observatory",
             "alert_level": "WATCH", "color_code": "ORANGE", "synopsis": "Eruption continues.", "sent_date_cap": "2026-11-02T14:05:13-09:00", "notice_url": "https://volcanoes.usgs.gov/hans-public/notice/DOI-1" }])
}

fn nhc_v(active: bool) -> Value {
    if !active {
        return json!({ "activeStorms": [] });
    }
    json!({ "activeStorms": [{ "id": "al092026", "name": "Zeta", "classification": "HU", "intensity": "105", "pressure": "950", "latitude": "26.4N", "longitude": "85.2W",
        "movementDir": 315, "movementSpeed": 12, "lastUpdate": "2026-11-02T15:00:00.000Z", "publicAdvisory": { "url": "https://www.nhc.noaa.gov/text/MIATCPAT4.shtml" } }] })
}

fn nws_v() -> Value {
    json!({ "features": [
        { "id": "https://api.weather.gov/alerts/urn:1", "geometry": null, "properties": { "id": "urn:1", "@id": "https://api.weather.gov/alerts/urn:1", "event": "Frost Advisory", "severity": "Minor", "urgency": "Expected", "certainty": "Likely",
          "headline": "Frost Advisory issued", "areaDesc": "Northern Lake", "effective": "2026-11-02T12:00:00-08:00", "expires": "2026-11-03T09:00:00-08:00", "senderName": "NWS Eureka CA" } },
        { "id": "u2", "geometry": { "type": "Polygon", "coordinates": [[[-120.0, 36.0], [-119.0, 36.0], [-119.0, 37.0], [-120.0, 37.0], [-120.0, 36.0]]] },
          "properties": { "id": "urn:2", "event": "Flood Warning", "severity": "Severe" } }
    ] })
}

async fn fake(storms: bool, down: &'static [&'static str]) -> String {
    fake_counted(storms, down).await.0
}

async fn fake_counted(storms: bool, down: &'static [&'static str]) -> (String, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let h2 = hits.clone();
    let down_set = down;
    let guard = move |name: &'static str| down_set.contains(&name);
    let rec = |q: Option<String>| QUERIES.lock().unwrap().push(q.unwrap_or_default());
    let router = Router::new()
        .route("/gdacs", get(move |RawQuery(q): RawQuery| async move {
            h2.fetch_add(1, Ordering::SeqCst);
            rec(q);
            if guard("gdacs") { return StatusCode::SERVICE_UNAVAILABLE.into_response(); }
            Json(gdacs_fc()).into_response()
        }))
        .route("/eonet", get(move || async move { if guard("eonet") { return StatusCode::INTERNAL_SERVER_ERROR.into_response(); } Json(eonet_v()).into_response() }))
        .route("/gvp", get(move || async move { if guard("gvp") { return StatusCode::INTERNAL_SERVER_ERROR.into_response(); } GVP.into_response() }))
        .route("/hans", get(move || async move { if guard("hans") { return StatusCode::INTERNAL_SERVER_ERROR.into_response(); } Json(hans_v()).into_response() }))
        .route("/nhc", get(move || async move { if guard("nhc") { return StatusCode::INTERNAL_SERVER_ERROR.into_response(); } Json(nhc_v(storms)).into_response() }))
        .route("/nws", get(move |RawQuery(q): RawQuery| async move { rec(q); Json(nws_v()) }))
        .route("/rw", get(move |RawQuery(q): RawQuery| async move { rec(q); Json(json!({ "data": [{ "id": "55", "fields": { "name": "Flood - Nov 2026", "status": "current", "country": [{ "name": "Kenya" }], "type": [{ "name": "Flood" }],
            "date": { "event": "2026-11-01T00:00:00+00:00" }, "url": "https://reliefweb.int/disaster/fl-2026-000001-ken" } }] })) }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), hits)
}

fn cfg(up: &str, appname: Option<&str>) -> Config {
    Config { gdacs: format!("{up}/gdacs"), eonet: format!("{up}/eonet"), nws: format!("{up}/nws"), gvp: format!("{up}/gvp"), hans: format!("{up}/hans"), nhc: format!("{up}/nhc"),
             reliefweb: format!("{up}/rw"), reliefweb_appname: appname.map(str::to_string) }
}

async fn serve(cfg: Config) -> String {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = env::temp_dir().join(format!("osnt-hazard-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
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
fn gdacs_events_normalise_and_foreign_links_drop() {
    let e = sources::gdacs(&gdacs_fc());
    assert_eq!(e.len(), 2, "out-of-range and geometry-less features are skipped");
    assert_eq!(e[0]["id"], "gdacs:TC:1001346");
    assert_eq!(e[0]["hazard"], "cyclone");
    assert_eq!(e[0]["level"], "red");
    assert_eq!(e[0]["countries"][0], "India");
    assert_eq!(e[0]["time"], "2026-11-01T00:00:00Z");
    assert_eq!(e[1]["id"], "gdacs:EQ:1573141");
    assert!(e[1]["url"].is_null());
}

#[test]
fn eonet_takes_latest_position_polygon_centroid_and_track() {
    let e = sources::eonet(&eonet_v());
    assert_eq!(e.len(), 2);
    assert_eq!((e[0]["lat"].as_f64().unwrap(), e[0]["lon"].as_f64().unwrap()), (12.9, 83.6));
    assert_eq!(e[0]["hazard"], "storm");
    assert_eq!(e[0]["magnitude"], "60 kts");
    assert_eq!(e[0]["track"].as_array().unwrap().len(), 2);
    assert_eq!(e[1]["hazard"], "wildfire");
    assert!((e[1]["lat"].as_f64().unwrap() - 40.8).abs() < 0.5, "ring centroid (closing vertex included)");
}

#[test]
fn volcano_sources_parse() {
    let g = sources::gvp(GVP);
    assert_eq!(g.len(), 1);
    assert_eq!(g[0]["title"], "Krakatau (Indonesia)");
    assert_eq!(g[0]["report_type"], "New Eruptive Activity");
    assert_eq!(g[0]["lat"], -6.1009);
    assert_eq!(g[0]["url"], "https://volcano.si.edu/volcano.cfm?vn=262000");
    assert_eq!(g[0]["time"], "2026-10-15T07:11:08Z");
    assert!(g[0]["summary"].as_str().unwrap().starts_with("PVMBG reported"));
    assert!(!g[0]["summary"].as_str().unwrap().contains('<') && !g[0]["summary"].as_str().unwrap().contains("Source:"));
    let h = sources::hans(&hans_v());
    assert_eq!(h[0]["level"], "orange");
    assert_eq!(h[0]["time"], "2026-11-02T23:05:13Z");
    assert_eq!(h[0]["observatory"], "Alaska Volcano Observatory");
}

#[test]
fn nhc_and_nws_parse() {
    assert!(sources::nhc(&nhc_v(false)).is_empty());
    let n = sources::nhc(&nhc_v(true));
    assert_eq!(n[0]["title"], "Hurricane Zeta");
    assert_eq!(n[0]["level"], "red");
    assert_eq!((n[0]["lat"].as_f64().unwrap(), n[0]["lon"].as_f64().unwrap()), (26.4, -85.2), "hemisphere letters become signs");
    let w = sources::nws(&nws_v(), Some((38.0, -121.0)));
    assert_eq!(w[0]["lat"], 38.0, "zone alerts take the queried point");
    assert_eq!(w[0]["level"], "green");
    assert_eq!(w[0]["time"], "2026-11-02T20:00:00Z");
    assert_eq!(w[1]["level"], "orange");
    assert!((w[1]["lon"].as_f64().unwrap() + 119.6).abs() < 0.5);
    assert!(sources::nws(&nws_v(), None)[0]["lat"].is_null());
    assert_eq!(sources::parse_rfc2822("Thu, 15 Oct 2026 03:11:08 -0400"), crate::util::parse_iso("2026-10-15T07:11:08Z"));
    assert_eq!(sources::parse_rfc2822("garbage"), None);
}

#[test]
fn haversine_is_sane() {
    assert!((haversine_km((0.0, 0.0), (0.0, 1.0)) - 111.19).abs() < 0.2);
    assert!((haversine_km((51.5, -0.12), (48.85, 2.35)) - 344.0).abs() < 4.0);
    assert!(haversine_km((10.0, 10.0), (10.0, 10.0)) < 1e-6);
}

#[test]
fn params_validate() {
    let q = |s: &str| -> HashMap<String, String> { s.split('&').filter_map(|p| p.split_once('=')).map(|(a, b)| (a.to_string(), b.to_string())).collect() };
    assert_eq!(parse_params(&q("")).unwrap().sources, DEFAULT_SOURCES.to_vec());
    assert!(parse_params(&q("sources=gdacs,evil")).is_err());
    assert!(parse_params(&q("level=purple")).is_err());
    assert!(parse_params(&q("hazard=zombies")).is_err());
    assert!(parse_params(&q("area=California")).is_err());
    assert!(parse_params(&q("area=C1")).is_err());
    assert_eq!(parse_params(&q("area=ca")).unwrap().nws_area.as_deref(), Some("CA"));
    assert!(parse_params(&q("lat=10")).is_err());
    assert!(parse_params(&q("lat=100&lon=1")).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn active_merges_sources_filters_and_caches() {
    let (up, hits) = fake_counted(true, &[]).await;
    let base = serve(cfg(&up, None)).await;
    let (code, v) = get_json(format!("{base}/api/active")).await;
    assert_eq!(code, 200, "{v}");
    // gdacs 2 + eonet 2 + gvp 1 + hans 1 + nhc 1
    assert_eq!(v["count"], 7);
    assert_eq!(v["sources"].as_array().unwrap().len(), 5);
    assert_eq!(v["events"][0]["level"], "red", "most severe first");
    assert_eq!(v["by_hazard"]["volcano"], 2);
    let (_, v2) = get_json(format!("{base}/api/active?hazard=volcano")).await;
    assert_eq!(v2["count"], 2);
    let (_, v3) = get_json(format!("{base}/api/active?level=red")).await;
    // red GDACS cyclone stays, orange items go, unlevelled events (eonet, gvp) stay
    assert!(v3["events"].as_array().unwrap().iter().all(|e| e["level"].is_null() || e["level"] == "red"), "{v3}");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "three requests, one upstream GDACS call");
    let q = QUERIES.lock().unwrap().iter().find(|q| q.contains("eventlist")).cloned().unwrap();
    assert!(q.contains("alertlevel=Orange;Red") || q.contains("alertlevel=Orange%3BRed"), "{q}");
}

#[tokio::test(flavor = "multi_thread")]
async fn one_source_down_is_reported_not_fatal_and_all_down_is_502() {
    let up = fake(false, &["gdacs", "hans"]).await;
    let base = serve(cfg(&up, None)).await;
    let (code, v) = get_json(format!("{base}/api/active")).await;
    assert_eq!(code, 200);
    let st = v["sources"].as_array().unwrap();
    assert_eq!(st.iter().filter(|s| s["ok"] == false).count(), 2);
    assert!(st.iter().find(|s| s["source"] == "gdacs").unwrap()["error"].as_str().unwrap().contains("503"));
    assert_eq!(v["count"], 3, "eonet 2 + gvp 1 remain");
    let dead = serve(cfg("http://127.0.0.1:9", None)).await;
    let (code, v) = get_json(format!("{dead}/api/active")).await;
    assert_eq!(code, 502);
    assert!(v["error"].as_str().unwrap().contains("gdacs"));
}

#[tokio::test(flavor = "multi_thread")]
async fn near_sorts_by_distance_and_includes_local_alerts() {
    let up = fake(true, &[]).await;
    let base = serve(cfg(&up, None)).await;
    let (code, v) = get_json(format!("{base}/api/near?lat=13&lon=83&radius_km=600")).await;
    assert_eq!(code, 200, "{v}");
    let ids: Vec<&str> = v["events"].as_array().unwrap().iter().map(|e| e["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&"eonet:EONET_1") && ids.contains(&"nws:urn:1"), "{ids:?}");
    assert!(!ids.contains(&"gdacs:EQ:1573141"), "China quake is far away");
    let d: Vec<f64> = v["events"].as_array().unwrap().iter().map(|e| e["distance_km"].as_f64().unwrap()).collect();
    assert!(d.windows(2).all(|w| w[0] <= w[1]));
    assert_eq!(get_json(format!("{base}/api/near?lat=1")).await.0, 400);
    assert_eq!(get_json(format!("{base}/api/near")).await.0, 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn alerts_need_area_or_point() {
    let up = fake(false, &[]).await;
    let base = serve(cfg(&up, None)).await;
    assert_eq!(get_json(format!("{base}/api/alerts")).await.0, 400);
    let (code, v) = get_json(format!("{base}/api/alerts?area=CA&level=orange")).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["count"], 1);
    assert_eq!(v["alerts"][0]["title"], "Flood Warning");
    assert!(QUERIES.lock().unwrap().iter().any(|q| q == "area=CA"));
    let (code, w) = get_json(format!("{base}/api/active?sources=nws")).await;
    assert_eq!(code, 502, "national NWS list is refused: {w}");
    assert!(w["error"].as_str().unwrap().contains("area"));
}

#[tokio::test(flavor = "multi_thread")]
async fn reliefweb_is_optional() {
    let up = fake(false, &[]).await;
    let off = serve(cfg(&up, None)).await;
    // No credential: skipped with a helpful message (the secret lookup finds nothing in tests).
    let (code, v) = get_json(format!("{off}/api/active?sources=reliefweb,eonet")).await;
    assert_eq!(code, 200);
    let rw = v["sources"].as_array().unwrap().iter().find(|s| s["source"] == "reliefweb").unwrap().clone();
    assert!(rw["error"].as_str().unwrap().contains("RELIEFWEB_APPNAME"));
    let on = serve(cfg(&up, Some("my app"))).await;
    let (_, v) = get_json(format!("{on}/api/active?sources=reliefweb")).await;
    assert_eq!(v["events"][0]["title"], "Flood - Nov 2026");
    assert_eq!(v["events"][0]["countries"][0], "Kenya");
    assert!(v["events"][0]["lat"].is_null());
    let q = QUERIES.lock().unwrap().iter().find(|q| q.contains("appname")).cloned().unwrap();
    assert!(q.contains("appname=my%20app"), "{q}");
    // The secret never appears in any response.
    assert!(!v.to_string().contains("my app"));
}

#[tokio::test(flavor = "multi_thread")]
async fn tools_and_page() {
    let base = serve(cfg("http://127.0.0.1:9", None)).await;
    let (_, t) = get_json(format!("{base}/tools")).await;
    let names: Vec<&str> = t.as_array().unwrap().iter().map(|x| x["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["hazards_active", "hazards_near", "hazards_alerts"]);
    let (_, s) = get_json(format!("{base}/api/sources")).await;
    assert_eq!(s["sources"].as_array().unwrap().len(), 7);
    let page = tokio::task::spawn_blocking(move || ureq::get(&format!("{base}/")).call().unwrap().body_mut().read_to_string().unwrap()).await.unwrap();
    assert!(page.contains("osnt-ui.css") && page.contains("embedded"));
}

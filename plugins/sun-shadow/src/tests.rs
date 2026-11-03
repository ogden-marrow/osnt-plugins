use super::*;
use axum::routing::get as aget;
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

async fn plugin(fake: &str, gateway: bool) -> String {
    let urls = Urls { archive: format!("{fake}/archive"), forecast: format!("{fake}/forecast"), sunrise: format!("{fake}/sunrise") };
    serve(router(new_app(urls, gateway))).await
}

static HITS: AtomicUsize = AtomicUsize::new(0);

async fn fake() -> String {
    let wx = |kind: &'static str| {
        aget(move || async move {
            HITS.fetch_add(1, Ordering::SeqCst);
            let times: Vec<String> = (0..24).map(|h| format!("2024-05-02T{h:02}:00")).collect();
            let cloud: Vec<f64> = (0..24).map(|h| if h == 14 { 92.0 } else { 10.0 }).collect();
            Json(json!({ "kind": kind, "hourly": { "time": times, "cloud_cover": cloud, "cloud_cover_low": cloud, "temperature_2m": vec![18.5; 24], "precipitation": vec![0.0; 24] } }))
        })
    };
    let app = Router::new().route("/archive", wx("archive")).route("/forecast", wx("forecast")).route(
        "/sunrise",
        aget(|| async { Json(json!({ "status": "OK", "results": { "sunrise": "2024-05-02T05:03:00+00:00", "sunset": "2024-05-02T19:50:00+00:00" } })) }),
    );
    serve(app).await
}

#[tokio::test]
async fn sun_endpoint_and_validation() {
    let base = plugin(&fake().await, false).await;
    let (c, v) = get_json(format!("{base}/api/sun?lat=51.5074&lon=-0.1278&time=2024-06-20T11:59:00Z")).await;
    assert_eq!(c, 200);
    assert!((v["geometric_altitude"].as_f64().unwrap() - 61.9).abs() < 0.2, "{v}");
    for bad in ["lat=95&lon=0&time=2024-06-20T11:59:00Z", "lat=1&lon=0", "lat=x&lon=0&time=2024-06-20T11:59:00Z", "lat=1&lon=0&time=nope"] {
        let (c, v) = get_json(format!("{base}/api/sun?{bad}")).await;
        assert_eq!(c, 400, "{bad}");
        assert!(v["error"].is_string());
    }
}

#[tokio::test]
async fn shadow_and_night() {
    let base = plugin(&fake().await, false).await;
    let (_, v) = get_json(format!("{base}/api/shadow?lat=0&lon=0&time=2024-03-20T12:07:00Z&height=2")).await;
    assert!(v["shadow_length_m"].as_f64().unwrap() < 0.1, "{v}");
    let (c, v) = get_json(format!("{base}/api/shadow?lat=0&lon=0&time=2024-03-20T00:00:00Z&height=2")).await;
    assert_eq!(c, 200);
    assert!(v["shadow_length_m"].is_null());
    let (c, _) = get_json(format!("{base}/api/shadow?lat=0&lon=0&time=2024-03-20T00:00:00Z&height=-2")).await;
    assert_eq!(c, 400);
}

#[tokio::test]
async fn solve_time_round_trips() {
    let base = plugin(&fake().await, false).await;
    // Shadow of a 10 m pole in London at 08:00 UTC on the solstice, then ask which times give that length.
    let (_, s) = get_json(format!("{base}/api/shadow?lat=51.5074&lon=-0.1278&time=2024-06-20T08:00:00Z&height=10")).await;
    let len = s["shadow_length_m"].as_f64().unwrap();
    let (_, v) = get_json(format!("{base}/api/solve?lat=51.5074&lon=-0.1278&date=2024-06-20&height=10&length={len}&tolerance=5")).await;
    let t = parse_time(v["morning"]["time"].as_str().unwrap()).unwrap();
    assert!((t - parse_time("2024-06-20T08:00:00Z").unwrap()).abs() < 60.0, "{v}");
    assert!(v["afternoon"]["time"].is_string());
    assert!(v["morning"]["from"].as_str().unwrap() < v["morning"]["to"].as_str().unwrap());
    // Impossible: shorter than the noon shadow.
    let (_, v) = get_json(format!("{base}/api/solve?lat=51.5074&lon=-0.1278&date=2024-06-20&height=10&length=0.5")).await;
    assert!(v["morning"].is_null() && v["message"].is_string());
}

#[tokio::test]
async fn candidates_circle_matches_geometry() {
    let base = plugin(&fake().await, false).await;
    let (c, v) = get_json(format!("{base}/api/candidates?time=2024-05-02T14:11:00Z&height=10&length=10&tolerance=5")).await;
    assert_eq!(c, 200);
    assert!((v["sun_altitude"].as_f64().unwrap() - 45.0).abs() < 0.01);
    let when = parse_time("2024-05-02T14:11:00Z").unwrap();
    let mut n = 0;
    for seg in v["center"].as_array().unwrap() {
        for p in seg.as_array().unwrap().iter().step_by(20) {
            let (la, lo) = (p[0].as_f64().unwrap(), p[1].as_f64().unwrap());
            assert!((position(la, lo, when).altitude - 45.0).abs() < 0.05);
            n += 1;
        }
    }
    assert!(n > 5);
    let r = v["latitude_range"].as_array().unwrap();
    assert!(r[0].as_f64().unwrap() < r[1].as_f64().unwrap());
    assert!(v["longitudes"].as_array().unwrap().len() > 3);
    let (c, _) = get_json(format!("{base}/api/candidates?time=2024-05-02T14:11:00Z&height=10")).await;
    assert_eq!(c, 400);
}

#[tokio::test]
async fn year_table_and_path() {
    let base = plugin(&fake().await, false).await;
    let (_, v) = get_json(format!("{base}/api/year?lat=51.5&lon=0&year=2024")).await;
    assert_eq!(v["days"].as_array().unwrap().len(), 366);
    let (_, v) = get_json(format!("{base}/api/year?lat=51.5&lon=0&year=2023")).await;
    assert_eq!(v["days"].as_array().unwrap().len(), 365);
    let (_, v) = get_json(format!("{base}/api/path?lat=51.5&lon=0&date=2024-06-21&step=60")).await;
    assert!(v["points"].as_array().unwrap().len() >= 24);
    let (c, _) = get_json(format!("{base}/api/year?lat=51.5&lon=0&year=1500")).await;
    assert_eq!(c, 400);
}

#[tokio::test]
async fn crosscheck_uses_archive_caches_and_degrades() {
    let before = HITS.load(Ordering::SeqCst);
    let base = plugin(&fake().await, false).await;
    let url = format!("{base}/api/crosscheck?lat=51.5&lon=0&time=2024-05-02T14:20:00Z");
    let (c, v) = get_json(url.clone()).await;
    assert_eq!(c, 200);
    assert_eq!(v["weather"]["cloud_cover_pct"], 92.0, "{v}");
    assert!(v["weather"]["reading"].as_str().unwrap().contains("overcast"));
    assert!(v["weather"]["source"].as_str().unwrap().contains("historical"));
    assert!(v["sunrise_check"]["sunrise_diff_s"].is_number());
    let h1 = HITS.load(Ordering::SeqCst);
    let _ = get_json(url).await;
    assert_eq!(HITS.load(Ordering::SeqCst), h1, "second call must come from the cache");
    assert!(h1 > before);
    // Far future: weather part reports an error but the response still succeeds.
    let (c, v) = get_json(format!("{base}/api/crosscheck?lat=51.5&lon=0&time=2090-05-02T14:20:00Z")).await;
    assert_eq!(c, 200);
    assert!(v["weather"]["error"].is_string());
}

#[tokio::test]
async fn upstream_down_is_reported_not_fatal() {
    let base = plugin("http://127.0.0.1:9", false).await;
    let (c, v) = get_json(format!("{base}/api/crosscheck?lat=51.5&lon=0&time=2024-05-02T14:20:00Z")).await;
    assert_eq!(c, 200);
    assert!(v["weather"]["error"].is_string() && v["sunrise_check"]["error"].is_string());
}

#[tokio::test]
async fn gateway_guard_blocks_unsigned_api_but_not_page_or_tools() {
    let base = plugin("http://127.0.0.1:9", true).await;
    let (c, _) = get_json(format!("{base}/api/sun?lat=1&lon=1&time=2024-05-02T14:20:00Z")).await;
    assert_eq!(c, 401);
    let (c, v) = get_json(format!("{base}/tools")).await;
    assert_eq!(c, 200);
    assert!(v.as_array().unwrap().len() >= 4);
}

#[test]
fn antimeridian_split() {
    let segs = split_antimeridian(&[(0.0, 170.0), (0.0, 179.0), (0.0, -179.0), (0.0, -170.0)]);
    assert_eq!(segs.len(), 2);
}

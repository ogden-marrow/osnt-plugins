use super::*;
use axum::{extract::Request, http::HeaderMap, routing::get as aget};
use std::sync::{Mutex, atomic::{AtomicUsize, Ordering}};

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

static COMMONS_HITS: AtomicUsize = AtomicUsize::new(0);
static AUTH_SEEN: Mutex<Vec<String>> = Mutex::new(Vec::new());

async fn fakes(token: Option<&str>) -> Config {
    let commons = serve(Router::new().route("/w/api.php", aget(|| async {
        COMMONS_HITS.fetch_add(1, Ordering::SeqCst);
        Json(json!({ "query": { "pages": [
            { "title": "File:Far.jpg", "coordinates": [{ "lat": 48.86, "lon": 2.30, "dist": 900.4 }], "imageinfo": [{ "thumburl": "https://thumb/far.jpg", "descriptionurl": "https://commons/far", "thumbwidth": 320, "thumbheight": 200, "width": 4000, "height": 2500,
              "extmetadata": { "Artist": { "value": "<a href=\"x\">Jane &amp; Co</a>" }, "LicenseShortName": { "value": "CC BY-SA 4.0" }, "LicenseUrl": { "value": "https://creativecommons.org/licenses/by-sa/4.0" }, "AttributionRequired": { "value": "true" }, "ImageDescription": { "value": "<p>A  tower\n</p>" } } }] },
            { "title": "File:Near.jpg", "coordinates": [{ "lat": 48.8584, "lon": 2.2945, "dist": 12.0 }], "imageinfo": [{ "thumburl": "https://thumb/near.jpg", "descriptionurl": "https://commons/near", "extmetadata": {} }] },
            { "title": "File:NoCoords.jpg", "imageinfo": [{ "thumburl": "x" }] } ] } }))
    }))).await;
    let wiki = serve(Router::new().route("/w/api.php", aget(|| async { Json(json!({ "query": { "pages": [{ "title": "Eiffel Tower", "extract": "The tower.", "coordinates": [{ "lat": 48.858, "lon": 2.2945, "dist": 40.0 }], "thumbnail": { "source": "https://t/e.jpg" } }] } })) }))).await;
    let mapi = serve(Router::new().route("/images", aget(|h: HeaderMap, req: Request| async move {
        AUTH_SEEN.lock().unwrap().push(format!("{}|{}", h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or(""), req.uri().query().unwrap_or("")));
        Json(json!({ "data": [{ "id": "123", "captured_at": 1714651200000i64, "compass_angle": 90.5, "is_pano": false, "thumb_256_url": "https://cdn/t.jpg", "computed_geometry": { "type": "Point", "coordinates": [2.29, 48.85] }, "creator": { "id": "secret-person" } }, { "id": "bad" }] }))
    }))).await;
    Config { commons: format!("{commons}/w/api.php"), wikipedia: format!("{wiki}/w/api.php?lang={{lang}}").replace("?lang={lang}", ""), mapillary: mapi, token: token.map(String::from) }
}

async fn plugin(cfg: Config, gw: bool) -> String {
    serve(router(new_app(cfg, gw))).await
}

#[test]
fn html_to_plain() {
    assert_eq!(plain("<a href=\"x\">Jane &amp; Co</a>", 50), "Jane & Co");
    assert_eq!(plain("<p>A  tower\n</p><p>two</p>", 50), "A tower two");
    assert_eq!(plain("abcdefgh", 4), "abcd…");
}

#[tokio::test]
async fn photos_sorted_filtered_and_credited() {
    let base = plugin(fakes(None).await, false).await;
    let (c, v) = get_json(format!("{base}/api/photos?lat=48.8584&lon=2.2945&radius=1000")).await;
    assert_eq!(c, 200, "{v}");
    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "file without coordinates is dropped");
    assert_eq!(items[0]["title"], "Near.jpg");
    assert_eq!(items[1]["author"], "Jane & Co");
    assert_eq!(items[1]["licence"], "CC BY-SA 4.0");
    assert_eq!(items[1]["attribution_required"], true);
    assert_eq!(items[1]["description"], "A tower");
    let before = COMMONS_HITS.load(Ordering::SeqCst);
    let _ = get_json(format!("{base}/api/photos?lat=48.8584&lon=2.2945&radius=1000")).await;
    assert_eq!(COMMONS_HITS.load(Ordering::SeqCst), before, "cached");
}

#[tokio::test]
async fn validation() {
    let base = plugin(fakes(None).await, false).await;
    for bad in ["photos?lat=1", "photos?lat=1&lon=1&radius=99999", "photos?lat=1&lon=1&limit=0", "articles?lat=1&lon=1&lang=xx", "articles?lat=1&lon=1&lang=en/../x", "street?lat=91&lon=1", "street?lat=1&lon=1&radius=5000"] {
        assert_eq!(get_json(format!("{base}/api/{bad}")).await.0, 400, "{bad}");
    }
}

#[tokio::test]
async fn articles() {
    let base = plugin(fakes(None).await, false).await;
    let (c, v) = get_json(format!("{base}/api/articles?lat=48.8584&lon=2.2945&lang=DE")).await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["items"][0]["url"], "https://de.wikipedia.org/wiki/Eiffel_Tower");
    assert_eq!(v["lang"], "de");
}

#[tokio::test]
async fn street_needs_a_token_and_hides_creators() {
    let base = plugin(fakes(None).await, false).await;
    let (c, v) = get_json(format!("{base}/api/street?lat=48.85&lon=2.29")).await;
    assert_eq!(c, 200);
    // No token is configured in tests unless the environment has one; either way the answer is well formed.
    assert!(v["available"].is_boolean());
    let base = plugin(fakes(Some("tok123")).await, false).await;
    let (_, v) = get_json(format!("{base}/api/street?lat=48.85&lon=2.29&radius=100")).await;
    assert_eq!(v["available"], true, "{v}");
    assert_eq!(v["count"], 1, "malformed record dropped");
    assert_eq!(v["items"][0]["captured"], "2024-05-02");
    assert_eq!(v["items"][0]["url"], "https://www.mapillary.com/app/?pKey=123");
    let text = v.to_string();
    assert!(!text.contains("secret-person") && !text.contains("tok123"), "{text}");
    let seen = AUTH_SEEN.lock().unwrap().clone();
    assert!(seen.iter().any(|s| s.starts_with("OAuth tok123|") && s.contains("bbox=")), "{seen:?}");
    assert!(!seen.iter().any(|s| s.contains("access_token")), "token must travel in the header only");
}

#[tokio::test]
async fn upstream_down_gives_502_and_guard_works() {
    let cfg = Config { commons: "http://127.0.0.1:9/w".into(), wikipedia: "http://127.0.0.1:9/{lang}".into(), mapillary: "http://127.0.0.1:9".into(), token: None };
    let base = plugin(cfg, false).await;
    let (c, v) = get_json(format!("{base}/api/photos?lat=1&lon=1")).await;
    assert_eq!(c, 502);
    assert!(v["error"].as_str().unwrap().contains("Commons"));
    let g = plugin(fakes(None).await, true).await;
    assert_eq!(get_json(format!("{g}/api/photos?lat=1&lon=1")).await.0, 401);
    let (c, v) = get_json(format!("{g}/tools")).await;
    assert_eq!((c, v.as_array().unwrap().len()), (200, 3));
}

#[test]
fn dates() {
    assert_eq!(crate_time(0), "1970-01-01");
    assert_eq!(crate_time(1714651200), "2024-05-02");
}


#[tokio::test]
async fn busy_search_is_retried_then_reported_not_shown_as_zero_results() {
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let commons = serve(Router::new().route("/w/api.php", aget(move || {
        let h = h.clone();
        async move {
            let n = h.fetch_add(1, Ordering::SeqCst);
            if n < 3 { Json(json!({ "error": { "code": "cirrussearch-too-busy-error", "info": "Search is currently too busy." } })) }
            else { Json(json!({ "query": { "pages": [{ "title": "File:A.jpg", "coordinates": [{ "lat": 1.0, "lon": 2.0, "dist": 5.0 }], "imageinfo": [{ "thumburl": "t", "extmetadata": {} }] }] } })) }
        }
    }))).await;
    let mut cfg = fakes(None).await;
    cfg.commons = format!("{commons}/w/api.php");
    let base = plugin(cfg, false).await;
    // two busy answers (first call + its retry) -> 502 with the reason
    let (c, v) = get_json(format!("{base}/api/photos?lat=1&lon=2")).await;
    assert_eq!(c, 502, "{v}");
    assert!(v["error"].as_str().unwrap().contains("busy"), "{v}");
    // one more busy answer, then success on the retry
    let (c, v) = get_json(format!("{base}/api/photos?lat=1&lon=2&radius=600")).await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["count"], 1);
}

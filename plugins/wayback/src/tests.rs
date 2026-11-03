use super::*;
use axum::extract::Path;

/// Fake Esri: config, tilemap (release 2 reuses release 1's tile), metadata layers (only layers 4 and 9 have a footprint).
async fn fake_esri() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let b2 = base.clone();
    let router = Router::new()
        .route("/config.json", get(move || {
            let b = b2.clone();
            async move {
                Json(json!({
                    "30": { "itemTitle": "World Imagery (Wayback 2024-03-01)", "metadataLayerUrl": format!("{b}/meta/30/MapServer") },
                    "10": { "itemTitle": "World Imagery (Wayback 2020-01-15)", "metadataLayerUrl": format!("{b}/meta/10/MapServer") },
                    "20": { "itemTitle": "World Imagery (Wayback 2022-06-30)", "metadataLayerUrl": "https://evil.test/MapServer" },
                    "bad": { "itemTitle": "not a release" }
                }))
            }
        }))
        .route("/tilemap/{rel}/{z}/{row}/{col}", get(|Path((rel, _z, _r, _c)): Path<(u64, u32, u32, u32)>| async move {
            let sel = if rel == 20 { 10 } else { rel };
            Json(json!({ "data": [1], "select": [sel], "valid": true }))
        }))
        .route("/meta/{rel}/MapServer/{layer}/query", get(|Path((_rel, layer)): Path<(u64, u32)>| async move {
            let f = match layer {
                4 => json!([{ "attributes": { "SRC_DATE2": 1_700_000_000_000i64, "SRC_RES": 0.3, "SRC_ACC": 5.0, "NICE_NAME": "Vivid", "NICE_DESC": "Provider" } }]),
                9 => json!([{ "attributes": { "SRC_DATE2": 1_500_000_000_000i64, "SRC_RES": 9.6, "NICE_NAME": "Other" } }]),
                _ => json!([]),
            };
            Json(json!({ "features": f }))
        }));
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    base
}

async fn serve(up: &str) -> String {
    let cfg = Config {
        config_url: format!("{up}/config.json"),
        tilemap_base: format!("{up}/tilemap"),
        tile_template: "https://tiles.test/{id}/{z}/{y}/{x}".into(),
        meta_prefix: format!("{up}/meta/"),
    };
    let dir = env::temp_dir().join(format!("osnt-wb-test-{}-{}", std::process::id(), up.len() + up.as_bytes()[up.len() - 1] as usize));
    let _ = std::fs::remove_dir_all(&dir);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = app(cfg, dir);
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{addr}")
}

async fn get_(url: String) -> (u16, Value) {
    tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
        let mut r = agent.get(&url).call().unwrap();
        (r.status().as_u16(), r.body_mut().read_json().unwrap_or(Value::Null))
    })
    .await
    .unwrap()
}

#[test]
fn parsing_helpers() {
    assert_eq!(title_date("World Imagery (Wayback 2026-10-29)").as_deref(), Some("2026-10-29"));
    assert_eq!(title_date("nothing"), None);
    // Gainesville, FL at z10 (x = (lon+180)/360*1024 = 277.8).
    assert_eq!(tile_of(29.65, -82.34, 10), (277, 423));
    assert_eq!(civil(19_000), (2022, 1, 8));
}

#[tokio::test(flavor = "multi_thread")]
async fn releases_are_sorted_and_skip_junk() {
    let up = fake_esri().await;
    let base = serve(&up).await;
    let (code, v) = get_(format!("{base}/api/releases")).await;
    assert_eq!(code, 200);
    let dates: Vec<&str> = v["releases"].as_array().unwrap().iter().map(|r| r["date"].as_str().unwrap()).collect();
    assert_eq!(dates, ["2020-01-15", "2022-06-30", "2024-03-01"]);
    assert_eq!(v["tile_template"], "https://tiles.test/{id}/{z}/{y}/{x}");
}

#[tokio::test(flavor = "multi_thread")]
async fn changes_lists_only_distinct_versions() {
    let up = fake_esri().await;
    let base = serve(&up).await;
    let (code, v) = get_(format!("{base}/api/changes?lat=29.65&lon=-82.34&zoom=12")).await;
    assert_eq!(code, 200, "{v}");
    // Release 20 re-uses release 10's tile, so only 10 and 30 are distinct versions.
    let ids: Vec<u64> = v["versions"].as_array().unwrap().iter().map(|x| x["id"].as_u64().unwrap()).collect();
    assert_eq!(ids, [10, 30]);
    assert_eq!(v["releases_checked"], 3);
    let (code, _) = get_(format!("{base}/api/changes?lat=99&lon=0")).await;
    assert_eq!(code, 400);
    let (code, _) = get_(format!("{base}/api/changes?lon=0")).await;
    assert_eq!(code, 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn capture_uses_finest_layer_and_validates_release_hosts() {
    let up = fake_esri().await;
    let base = serve(&up).await;
    let (code, v) = get_(format!("{base}/api/capture?lat=1&lon=2&date=2025-01-01")).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["release"], 30);
    assert_eq!(v["capture_date"], "2023-11-14");
    assert_eq!(v["resolution_m"], 0.3);
    assert_eq!(v["source"], "Vivid");
    let (_, v) = get_(format!("{base}/api/capture?lat=1&lon=2&date=2021-01-01")).await;
    assert_eq!(v["release"], 10);
    // Release 20 points at a host outside the allowed prefix: refused rather than fetched.
    let (code, v) = get_(format!("{base}/api/capture?lat=1&lon=2&release=20")).await;
    assert_eq!(code, 502, "{v}");
    let (code, _) = get_(format!("{base}/api/capture?lat=1&lon=2&date=2001-01-01")).await;
    assert_eq!(code, 400);
    let (code, _) = get_(format!("{base}/api/capture?lat=1&lon=2&date=garbage")).await;
    assert_eq!(code, 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_down_is_a_clean_502_and_tools_listed() {
    let base = serve("http://127.0.0.1:9").await;
    let (code, v) = get_(format!("{base}/api/releases")).await;
    assert_eq!(code, 502);
    assert!(v["error"].is_string());
    let (_, t) = get_(format!("{base}/tools")).await;
    let names: Vec<&str> = t.as_array().unwrap().iter().map(|x| x["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["wayback_releases", "wayback_changes", "wayback_capture"]);
}

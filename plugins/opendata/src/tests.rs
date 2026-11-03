use super::*;
use axum::extract::Path;

/// Static-file style fake of the Maxar catalog.
async fn fake_maxar() -> String {
    let router = Router::new().route("/events/{*path}", get(|Path(p): Path<String>| async move {
        let doc = match p.as_str() {
            "catalog.json" => json!({ "id": "root", "links": [
                { "rel": "child", "href": "./Ev-One/collection.json" }, { "rel": "child", "href": "./Ev-Two/collection.json" }, { "rel": "root", "href": "./catalog.json" }] }),
            "Ev-One/collection.json" => json!({ "id": "Ev-One", "title": "Event One", "description": "A flood.", "license": "CC-BY-NC-4.0",
                "extent": { "spatial": { "bbox": [[10.0, 20.0, 11.0, 21.0], [10.1, 20.1, 10.2, 20.2]] }, "temporal": { "interval": [["2024-05-01 07:00:00Z", "2024-06-02 07:00:00Z"]] } },
                "links": [{ "rel": "root", "href": "../collection.json" },
                          { "rel": "child", "href": "./ard/acquisition_collections/AAA_collection.json" },
                          { "rel": "child", "href": "./ard/acquisition_collections/BBB_collection.json" }] }),
            "Ev-Two/collection.json" => json!({ "id": "Ev-Two", "extent": { "spatial": { "bbox": [[0.0, 0.0, 1.0, 1.0]] }, "temporal": { "interval": [["2023-01-01 00:00:00Z", "2023-01-05 00:00:00Z"]] } }, "links": [] }),
            "Ev-One/ard/acquisition_collections/AAA_collection.json" => json!({ "id": "AAA", "extent": { "spatial": { "bbox": [[10.1, 20.1, 10.2, 20.2]] }, "temporal": { "interval": [["2024-06-02 07:00:00Z", "2024-06-02 07:00:00Z"]] } },
                "links": [{ "rel": "item", "href": "../38/0001/2024-06-02/AAA.json" }, { "rel": "item", "href": "../38/0002/2024-06-02/AAA.json" }, { "rel": "item", "href": "https://evil.test/x.json" }] }),
            "Ev-One/ard/acquisition_collections/BBB_collection.json" => json!({ "id": "BBB", "extent": { "spatial": { "bbox": [[10.1, 20.1, 10.2, 20.2]] }, "temporal": { "interval": [["2024-05-01 07:00:00Z", "2024-05-01 07:00:00Z"]] } }, "links": [] }),
            "Ev-One/ard/38/0001/2024-06-02/AAA.json" => json!({ "bbox": [10.1, 20.1, 10.15, 20.15], "properties": { "platform": "WV02", "gsd": 0.47, "datetime": "2024-06-02 07:00:00Z" },
                "assets": { "visual": { "href": "./AAA-visual.tif" } } }),
            "Ev-One/ard/38/0002/2024-06-02/AAA.json" => json!({ "bbox": [10.15, 20.15, 10.2, 20.2], "properties": { "platform": "WV02", "gsd": 0.47 }, "assets": { "visual": { "href": "https://evil.test/steal.tif" } } }),
            _ => return (StatusCode::NOT_FOUND, Json(json!({}))).into_response(),
        };
        Json(doc).into_response()
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/events/", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    base
}

async fn serve(root: &str) -> String {
    let cfg = Config { root: root.to_string(), titiler: "https://titiler.test".into() };
    let dir = env::temp_dir().join(format!("osnt-od-test-{}-{}", std::process::id(), root.len() + root.as_bytes()[root.len() - 9] as usize));
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
fn relative_links_resolve() {
    let base = "https://h.test/events/Ev/ard/acquisition_collections/A_collection.json";
    assert_eq!(resolve(base, "../38/1/2024-01-01/X.json"), "https://h.test/events/Ev/ard/38/1/2024-01-01/X.json");
    assert_eq!(resolve(base, "./B_collection.json"), "https://h.test/events/Ev/ard/acquisition_collections/B_collection.json");
    assert_eq!(resolve(base, "https://x.test/a.json"), "https://x.test/a.json");
    assert_eq!(resolve("https://h.test/a.json", "../../../b.json"), "https://h.test/b.json");
    assert!(safe_id("Cyclone-Chido-Dec15") && !safe_id("../x") && !safe_id("a/b") && !safe_id(""));
}

#[tokio::test(flavor = "multi_thread")]
async fn events_are_listed_newest_first() {
    let root = fake_maxar().await;
    let base = serve(&root).await;
    let (code, v) = get_(format!("{base}/api/events")).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["count"], 2);
    let e = &v["events"][0];
    assert_eq!(e["id"], "Ev-One");
    assert_eq!(e["title"], "Event One");
    assert_eq!(e["bbox"], json!([10.0, 20.0, 11.0, 21.0]));
    assert_eq!(e["start"], "2024-05-01");
    assert_eq!(e["acquisitions"], 2);
    assert_eq!(v["events"][1]["title"], "Ev-Two", "title falls back to the id");
    assert!(v["licence"].as_str().unwrap().contains("NC"));
}

#[tokio::test(flavor = "multi_thread")]
async fn acquisitions_and_items() {
    let root = fake_maxar().await;
    let base = serve(&root).await;
    let (code, v) = get_(format!("{base}/api/acquisitions?event=Ev-One")).await;
    assert_eq!(code, 200, "{v}");
    let ids: Vec<&str> = v["acquisitions"].as_array().unwrap().iter().map(|a| a["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["BBB", "AAA"], "oldest first");
    assert_eq!(v["acquisitions"][1]["items"], 3);
    assert_eq!(v["acquisitions"][1]["date"], "2024-06-02");

    let (code, v) = get_(format!("{base}/api/acquisition?event=Ev-One&id=AAA")).await;
    assert_eq!(code, 200, "{v}");
    // One item points outside the catalog and one has a COG outside the catalog: both are dropped.
    assert_eq!(v["count"], 1, "{v}");
    assert_eq!(v["total_items"], 3);
    let it = &v["items"][0];
    assert!(it["cog"].as_str().unwrap().ends_with("/events/Ev-One/ard/38/0001/2024-06-02/AAA-visual.tif"));
    assert!(it["tiles"].as_str().unwrap().starts_with("https://titiler.test/cog/tiles/WebMercatorQuad/{z}/{x}/{y}?url=http%3A%2F%2F127.0.0.1"));
    assert_eq!(v["platform"], "WV02");
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_ids_and_upstream_down() {
    let root = fake_maxar().await;
    let base = serve(&root).await;
    for q in ["acquisitions?event=nope", "acquisitions?event=..%2Fx", "acquisitions", "acquisition?event=Ev-One&id=../../x", "acquisition?event=Ev-One&id=ZZZ"] {
        let (code, v) = get_(format!("{base}/api/{q}")).await;
        assert_eq!(code, 400, "{q}: {v}");
    }
    let down = serve("http://127.0.0.1:9/events/").await;
    let (code, v) = get_(format!("{down}/api/events")).await;
    assert_eq!(code, 502);
    assert!(v["error"].is_string());
    let (_, t) = get_(format!("{down}/tools")).await;
    assert_eq!(t.as_array().unwrap().len(), 2);
}

#[test]
fn page_supports_deep_links_and_guards_slow_loads() {
    // ?event=&a=&b= restores a comparison; a slow acquisition load must not overwrite a newer pick.
    for k in ["P.get('event')", "pickToken", "if (S[slot] !== a) return;"] {
        assert!(PAGE.contains(k), "missing {k}");
    }
}

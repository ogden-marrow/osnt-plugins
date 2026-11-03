use super::*;
use axum::{Form, extract::State as AState, routing::{get as aget, post as apost}};
use std::sync::atomic::{AtomicUsize, Ordering};

fn reconcile_fixture() -> Value {
    json!({
        "q0": { "result": [
            { "id": "10211965", "name": "MOSSACK  FOUNDATION", "description": "Entity node extracted from the Panama Papers data.", "score": 38.888, "types": [{ "id": T_ENTITY, "name": "Entity" }] },
            { "id": "12202820", "name": "SOME PERSON", "description": "Officer node extracted from the Panama Papers data.", "score": 90.0, "types": [{ "id": "https://offshoreleaks.icij.org/schema/oldb/officer", "name": "Officer" }] },
            { "id": "bad/id", "name": "X", "description": "", "score": 1.0, "types": [{ "id": T_ENTITY }] }
        ] },
        "q1": { "result": [
            { "id": "11008636", "name": "FIRM  OF  LAWYERS", "description": "Intermediary node extracted from the Pandora Papers data.", "score": 46.6, "types": [{ "id": T_INTERMEDIARY, "name": "Intermediary" }] }
        ] }
    })
}

fn node_page(id: u64, cat: &str) -> String {
    let data = json!([
        { "id": id, "data": { "categories": [cat], "properties": { "sourceID": "Panama Papers", "name": "MOSSACK FONSECA LIMITED", "jurisdiction": "SEY", "jurisdiction_description": "Seychelles", "status": "Defaulted",
            "incorporation_date": "25-SEP-2009", "struck_off_date": "31-DEC-2015", "service_provider": "Mossack Fonseca", "address": "1 PRIVATE HOUSE ROAD", "countries": "Panama", "valid_until": "The Panama Papers data is current through 2015" },
            "statistics": { "digest": [ { "edgeType": "officer_of", "nodeCategories": ["Officer"], "nodes": 2, "edges": 2 }, { "edgeType": "registered_address", "nodeCategories": ["Address"], "nodes": 1, "edges": 1 } ] } } },
        { "id": 99, "data": { "categories": ["Officer"], "properties": { "name": "JANE PRIVATE" } } }
    ]);
    format!("<html><script>document.body.nodeData = {data};\nwindow.i18n = {{}};</script></html>")
}

#[test]
fn reconcile_keeps_only_entities_and_intermediaries() {
    let r = parse_reconcile(&reconcile_fixture(), "q0");
    assert_eq!(r.len(), 1, "officer and malformed ids are dropped");
    assert_eq!(r[0]["name"], "MOSSACK FOUNDATION");
    assert_eq!(r[0]["leak"], "Panama Papers");
    assert_eq!(r[0]["score"], 38.9);
    let i = parse_reconcile(&reconcile_fixture(), "q1");
    assert_eq!((i[0]["kind"].clone(), i[0]["leak"].clone()), (json!("intermediary"), json!("Pandora Papers")));
    assert!(parse_reconcile(&json!({}), "q0").is_empty());
}

#[test]
fn node_data_and_details() {
    let data = extract_node_data(&node_page(10022201, "Entity")).unwrap();
    let d = build_detail(10022201, &data).unwrap();
    assert_eq!(d["jurisdiction"], "Seychelles");
    assert_eq!(d["status"], "Defaulted");
    assert!(d["lat"].as_f64().is_some());
    assert_eq!(d["connected_counts"]["Officer"], 2);
    let txt = d.to_string();
    assert!(!txt.contains("PRIVATE HOUSE") && !txt.contains("JANE PRIVATE"), "no addresses or connected names: {txt}");
    assert!(d["connected_counts"].get("Address").is_none());
    let data = extract_node_data(&node_page(11009214, "Intermediary")).unwrap();
    let d = build_detail(11009214, &data).unwrap();
    assert_eq!(d["kind"], "intermediary");
    assert!(d.get("status").is_none() && d.get("lat").is_none());
    let data = extract_node_data(&node_page(12202820, "Officer")).unwrap();
    assert_eq!(build_detail(12202820, &data).unwrap_err(), "Officer");
    assert!(build_detail(5, &data).is_err());
    assert!(extract_node_data("<html>no data</html>").is_none());
}

#[test]
fn coordinates() {
    assert!(jurisdiction_coords("British Virgin Islands").is_some());
    assert!(jurisdiction_coords("Atlantis").is_none());
}

struct Fake {
    searches: AtomicUsize,
    pages: AtomicUsize,
    last_queries: std::sync::Mutex<String>,
}
async fn start(fake: Arc<Fake>, open: bool) -> String {
    let r = Router::new()
        .route("/api/v1/reconcile", apost(|AState(f): AState<Arc<Fake>>, Form(m): Form<std::collections::HashMap<String, String>>| async move {
            f.searches.fetch_add(1, Ordering::SeqCst);
            *f.last_queries.lock().unwrap() = m.get("queries").cloned().unwrap_or_default();
            Json(reconcile_fixture())
        }))
        .route("/nodes/{id}", aget(|AState(f): AState<Arc<Fake>>, axum::extract::Path(id): axum::extract::Path<u64>| async move {
            f.pages.fetch_add(1, Ordering::SeqCst);
            match id {
                404 => (StatusCode::NOT_FOUND, String::new()),
                12202820 => (StatusCode::OK, node_page(id, "Officer")),
                500 | 501 => (StatusCode::OK, "<html>no embedded data</html>".into()),
                _ => (StatusCode::OK, node_page(id, "Entity")),
            }
        }))
        .route("/api/v1/rest/nodes/{id}", aget(|axum::extract::Path(id): axum::extract::Path<u64>| async move {
            use axum::response::IntoResponse;
            let schema = |s: &str| format!("https://offshoreleaks.icij.org/schema/oldb/{s}");
            match id {
                500 => Json(json!({ "id": id, "schema": schema("intermediary"), "properties": { "name": "BIG FIRM", "country_codes": ["PA"], "data_source": "Panama Papers" } })).into_response(),
                501 => Json(json!({ "id": id, "schema": schema("officer"), "properties": { "name": "A PERSON" } })).into_response(),
                _ => StatusCode::NOT_FOUND.into_response(),
            }
        }))
        .with_state(fake);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, r).await.unwrap() });
    let st = new_state(Config { base, gap: Duration::from_millis(1), open }, None);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app(st)).await.unwrap() });
    url
}
fn fake() -> Arc<Fake> {
    Arc::new(Fake { searches: AtomicUsize::new(0), pages: AtomicUsize::new(0), last_queries: Default::default() })
}
async fn call(url: String) -> (u16, Value) {
    tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
        let mut r = agent.get(&url).call().unwrap();
        (r.status().as_u16(), r.body_mut().read_json::<Value>().unwrap_or(Value::Null))
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn search_sends_only_entity_and_intermediary_types_and_caches() {
    let f = fake();
    let url = start(f.clone(), true).await;
    let (c, v) = call(format!("{url}/api/search?q=mossack&intermediaries=1")).await;
    assert_eq!(c, 200);
    assert_eq!(v["results"].as_array().unwrap().len(), 2);
    let sent = f.last_queries.lock().unwrap().clone();
    assert!(sent.contains(T_ENTITY) && sent.contains(T_INTERMEDIARY) && !sent.to_lowercase().contains("officer"), "{sent}");
    call(format!("{url}/api/search?q=MOSSACK&intermediaries=1")).await;
    assert_eq!(f.searches.load(Ordering::SeqCst), 1, "second search served from cache");
    let (_, v) = call(format!("{url}/api/search?q=mossack")).await;
    assert!(v["results"].as_array().unwrap().iter().all(|r| r["kind"] == "entity"));
    assert!(!f.last_queries.lock().unwrap().contains(T_INTERMEDIARY));
    for q in ["q=", "q=x", &format!("q={}", "a".repeat(101))] {
        assert_eq!(call(format!("{url}/api/search?{q}")).await.0, 400);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn entity_details_officers_refused_enrich_limits() {
    let f = fake();
    let url = start(f.clone(), true).await;
    let (c, v) = call(format!("{url}/api/entity?id=10022201")).await;
    assert_eq!((c, v["status"].clone()), (200, json!("Defaulted")));
    call(format!("{url}/api/entity?id=10022201")).await;
    assert_eq!(f.pages.load(Ordering::SeqCst), 1, "details cached");
    let (c, v) = call(format!("{url}/api/entity?id=12202820")).await;
    assert_eq!(c, 403);
    assert!(v["error"].as_str().unwrap().contains("officer"));
    assert_eq!(call(format!("{url}/api/entity?id=404")).await.0, 404);
    let (c, v) = call(format!("{url}/api/entity?id=500")).await;
    assert_eq!((c, v["name"].clone(), v["partial"].clone()), (200, json!("BIG FIRM"), json!(true)), "pages without embedded data fall back to the REST record");
    assert_eq!(call(format!("{url}/api/entity?id=501")).await.0, 403, "officer found through the fallback is refused too");
    for id in ["abc", "", "../x", "12345678901"] {
        assert_eq!(call(format!("{url}/api/entity?id={id}")).await.0, 400, "{id}");
    }
    let (c, v) = call(format!("{url}/api/enrich?ids=10022201,12202820")).await;
    assert_eq!(c, 200);
    assert_eq!(v["nodes"][0]["jurisdiction"], "Seychelles");
    assert!(v["nodes"][1]["error"].is_string());
    let many = (1..=11).map(|n| n.to_string()).collect::<Vec<_>>().join(",");
    assert_eq!(call(format!("{url}/api/enrich?ids={many}")).await.0, 400);
    assert_eq!(call(format!("{url}/api/enrich?ids=")).await.0, 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn gateway_and_tools() {
    let url = start(fake(), false).await;
    assert_eq!(call(format!("{url}/api/search?q=mossack")).await.0, 401);
    let (_, v) = call(format!("{url}/tools")).await;
    assert_eq!(v.as_array().unwrap().len(), 2);
}

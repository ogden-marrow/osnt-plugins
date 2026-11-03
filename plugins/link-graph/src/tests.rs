use std::sync::Arc;

use axum::{body::Body, http::Request};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use tower::ServiceExt;

use crate::store::*;
use crate::*;

const KEY: &str = "00112233445566778899aabbccddeeff";

fn sign(method: &str, pq: &str) -> String {
    unsafe { std::env::set_var("OSNT_GATEWAY_KEY", KEY) };
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let mut m = Hmac::<Sha256>::new_from_slice(KEY.as_bytes()).unwrap();
    m.update(format!("{ts}.{method}.{pq}").as_bytes());
    format!("v1.{ts}.{}", m.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>())
}

fn new_app() -> (axum::Router, std::path::PathBuf) {
    let d = std::env::temp_dir().join(format!("lg-test-{}", new_id()));
    std::fs::create_dir_all(&d).unwrap();
    (app(Arc::new(App { store: Store::new(&d).unwrap() })), d)
}

async fn call(a: &axum::Router, method: &str, uri: &str, body: Value, signed: bool) -> (StatusCode, Value, String) {
    let mut r = Request::builder().method(method).uri(uri).header("content-type", "application/json");
    if signed {
        r = r.header("x-osnt-gateway", sign(method, uri));
    }
    let res = a.clone().oneshot(r.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let st = res.status();
    let b = axum::body::to_bytes(res.into_body(), 1 << 24).await.unwrap();
    (st, serde_json::from_slice(&b).unwrap_or(Value::Null), String::from_utf8_lossy(&b).to_string())
}

async fn mk(a: &axum::Router) -> String {
    call(a, "POST", "/api/graphs", json!({ "name": "Case A" }), true).await.1["id"].as_str().unwrap().to_string()
}

fn node(id: &str, kind: &str, label: &str) -> Value {
    json!({ "id": id, "type": kind, "label": label })
}

#[test]
fn node_types_exclude_people_by_design() {
    for t in ["person", "username", "email", "phone", "handle", "account", "face", "Domain", ""] {
        let e = check_node(t, "example.com").unwrap_err();
        assert!(e.contains("not allowed"), "{t}: {e}");
    }
    assert!(!NODE_TYPES.iter().any(|t| ["person", "username", "email", "phone"].contains(t)));
}

#[test]
fn labels_are_validated_and_normalised() {
    assert_eq!(check_node("domain", " Example.COM. ").unwrap(), "example.com");
    assert!(check_node("domain", "localhost").is_err() && check_node("domain", "a b.com").is_err());
    assert_eq!(check_node("ip", "2001:0db8:0:0:0:0:0:1").unwrap(), "2001:db8::1");
    assert!(check_node("ip", "999.1.1.1").is_err());
    assert_eq!(check_node("asn", "as15169").unwrap(), "AS15169");
    assert_eq!(check_node("asn", "15169").unwrap(), "AS15169");
    assert!(check_node("asn", "ASX").is_err());
    assert!(check_node("url", "https://user:pw@example.com/").is_err() && check_node("url", "javascript:alert(1)").is_err() && check_node("url", "https://example.com/a b").is_ok());
    assert_eq!(check_node("hash", &"AB".repeat(16)).unwrap(), "ab".repeat(16));
    assert!(check_node("hash", "abc").is_err());
    assert!(check_node("vessel", "MV Example (IMO 1234567)").is_ok());
    assert!(check_node("organisation", "").is_err() && check_node("organisation", &"x".repeat(301)).is_err() && check_node("place", "a\u{7}b").is_err());
}

#[test]
fn free_text_labels_that_look_like_email_or_phone_are_refused() {
    for l in ["jane.doe@example.com", "contact: bob@mail.org", "+1 (352) 555-0147", "352-555-0147", "0049 30 1234 5678"] {
        assert!(check_node("organisation", l).is_err(), "{l}");
        assert!(check_node("place", l).is_err(), "{l}");
    }
    assert!(check_node("organisation", "Acme @ Harbour Ltd").is_ok());
    assert!(check_node("aircraft", "N12345 / hex A1B2C3").is_ok());
    assert!(check_node("ip", "93.184.216.34").is_ok() && check_node("place", "12345678").is_err());
}

#[tokio::test]
async fn every_api_route_needs_the_gateway_signature() {
    let (a, _d) = new_app();
    for (m, p) in [("GET", "/api/graphs"), ("POST", "/api/graphs"), ("GET", "/api/graphs/x"), ("PUT", "/api/graphs/x"), ("DELETE", "/api/graphs/x"), ("POST", "/api/graphs/x/merge"), ("GET", "/api/graphs/x/export"), ("POST", "/api/import")] {
        assert_eq!(call(&a, m, p, json!({}), false).await.0, StatusCode::UNAUTHORIZED, "{m} {p}");
    }
    assert_eq!(call(&a, "GET", "/api/graphs", json!({}), true).await.0, StatusCode::OK);
}

#[tokio::test]
async fn save_validates_and_round_trips() {
    let (a, d) = new_app();
    let id = mk(&a).await;
    let p = format!("/api/graphs/{id}");
    let body = json!({ "name": "Case A", "nodes": [node("n1", "domain", "Example.com"), node("n2", "ip", "93.184.216.34")], "edges": [{ "id": "e1", "from": "n1", "to": "n2", "label": "resolves to" }] });
    let (st, g, _) = call(&a, "PUT", &p, body.clone(), true).await;
    assert_eq!(st, StatusCode::OK, "{g}");
    assert_eq!(g["nodes"][0]["label"], "example.com");
    let mut bad_person = body.clone();
    bad_person["nodes"][0]["type"] = json!("person");
    assert_eq!(call(&a, "PUT", &p, bad_person, true).await.0, StatusCode::BAD_REQUEST);
    for mutate in [
        |b: &mut Value| b["edges"][0]["to"] = json!("ghost"),
        |b: &mut Value| b["edges"][0]["to"] = json!("n1"),
        |b: &mut Value| b["nodes"][1] = json!({ "id": "n1", "type": "ip", "label": "1.1.1.1" }),
        |b: &mut Value| b["nodes"][1] = json!({ "id": "n2", "type": "domain", "label": "example.com" }),
        |b: &mut Value| b["nodes"][1]["id"] = json!("../x"),
        |b: &mut Value| b["name"] = json!(""),
    ] {
        let mut b = body.clone();
        mutate(&mut b);
        assert_eq!(call(&a, "PUT", &p, b, true).await.0, StatusCode::BAD_REQUEST);
    }
    // the stored file is still the last good version and no temp file is left behind
    assert_eq!(call(&a, "GET", &p, json!({}), true).await.1["edges"].as_array().unwrap().len(), 1);
    let names: Vec<String> = std::fs::read_dir(d.join("graphs")).unwrap().flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
    assert_eq!(names, [format!("{id}.json")]);
    assert_eq!(call(&a, "GET", "/api/graphs/NOPE", json!({}), true).await.0, StatusCode::NOT_FOUND);
    assert_eq!(call(&a, "DELETE", &p, json!({}), true).await.0, StatusCode::OK);
    assert_eq!(call(&a, "DELETE", &p, json!({}), true).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn caps_are_enforced() {
    let (a, _d) = new_app();
    let id = mk(&a).await;
    let nodes: Vec<Value> = (0..=MAX_NODES).map(|i| node(&format!("n{i}"), "asn", &format!("AS{i}"))).collect();
    assert_eq!(call(&a, "PUT", &format!("/api/graphs/{id}"), json!({ "name": "x", "nodes": nodes, "edges": [] }), true).await.0, StatusCode::BAD_REQUEST);
    for i in 0..MAX_GRAPHS - 1 {
        assert_eq!(call(&a, "POST", "/api/graphs", json!({ "name": format!("g{i}") }), true).await.0, StatusCode::OK);
    }
    assert_eq!(call(&a, "POST", "/api/graphs", json!({ "name": "one too many" }), true).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn merge_dedupes_remaps_ids_and_is_all_or_nothing() {
    let (a, _d) = new_app();
    let id = mk(&a).await;
    let m = format!("/api/graphs/{id}/merge");
    let add = json!({ "source": "transform:lookup", "nodes": [node("a", "domain", "example.com"), node("b", "ip", "93.184.216.34")], "edges": [{ "id": "x", "from": "a", "to": "b", "label": "A" }] });
    let (_, v, _) = call(&a, "POST", &m, add.clone(), true).await;
    assert_eq!((v["added_nodes"].clone(), v["added_edges"].clone()), (json!(2), json!(1)));
    assert_eq!(v["graph"]["nodes"][0]["source"], "transform:lookup");
    let (_, v, _) = call(&a, "POST", &m, add, true).await;
    assert_eq!((v["added_nodes"].clone(), v["added_edges"].clone()), (json!(0), json!(0)));
    // one bad node (a person-ish type) rejects the whole request
    let (st, _, _) = call(&a, "POST", &m, json!({ "nodes": [node("c", "domain", "other.org"), node("d", "person", "Someone")] }), true).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let g = call(&a, "GET", &format!("/api/graphs/{id}"), json!({}), true).await.1;
    assert_eq!(g["nodes"].as_array().unwrap().len(), 2);
    assert_eq!(call(&a, "POST", &m, json!({ "nodes": [], "edges": [{ "id": "q", "from": "zz", "to": "yy" }] }), true).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn export_formats_and_json_round_trip() {
    let (a, _d) = new_app();
    let id = mk(&a).await;
    call(&a, "PUT", &format!("/api/graphs/{id}"), json!({ "name": "Case A", "nodes": [node("n1", "domain", "a-b.example.com"), node("n2", "organisation", "Acme & \"Ltd\" <x>")], "edges": [{ "id": "e1", "from": "n1", "to": "n2", "label": "operated by" }] }), true).await;
    let ex = |f: &str| format!("/api/graphs/{id}/export?format={f}");
    let (_, _, gm) = call(&a, "GET", &ex("graphml"), json!({}), true).await;
    assert!(gm.contains("<graphml") && gm.contains("a-b.example.com") && gm.contains("Acme &amp; &quot;Ltd&quot; &lt;x&gt;") && gm.contains("source=\"n1\" target=\"n2\""));
    let (_, _, gx) = call(&a, "GET", &ex("gexf"), json!({}), true).await;
    assert!(gx.contains("<gexf") && gx.contains("label=\"operated by\""));
    let (_, _, mmd) = call(&a, "GET", &ex("mermaid"), json!({}), true).await;
    assert!(mmd.starts_with("graph LR") && mmd.contains("n0 -->|\"operated by\"| n1") && !mmd.contains("<x>"));
    let (_, _, md) = call(&a, "GET", &ex("md"), json!({}), true).await;
    assert!(md.contains("# Case A") && md.contains("## domain") && md.contains("```mermaid"));
    assert_eq!(call(&a, "GET", &ex("svg"), json!({}), true).await.0, StatusCode::BAD_REQUEST);
    let (_, _, raw) = call(&a, "GET", &ex("json"), json!({}), true).await;
    let bundle: Value = serde_json::from_str(&raw).unwrap();
    let (st, s, _) = call(&a, "POST", "/api/import", bundle.clone(), true).await;
    assert_eq!((st, s["nodes"].clone(), s["edges"].clone()), (StatusCode::OK, json!(2), json!(1)));
    // imports containing a person-type node, a bad label or the wrong format are rejected
    let mut t = bundle.clone();
    t["graph"]["nodes"][0]["type"] = json!("username");
    assert_eq!(call(&a, "POST", "/api/import", t, true).await.0, StatusCode::BAD_REQUEST);
    let mut t = bundle.clone();
    t["graph"]["nodes"][1]["label"] = json!("jane@example.com");
    assert_eq!(call(&a, "POST", "/api/import", t, true).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(call(&a, "POST", "/api/import", json!({ "format": "gexf" }), true).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn agent_view_is_read_only_and_omits_node_notes() {
    let (a, _d) = new_app();
    let id = mk(&a).await;
    let mut n = node("n1", "domain", "example.com");
    n["note"] = json!("PRIVATE REMARK");
    call(&a, "PUT", &format!("/api/graphs/{id}"), json!({ "name": "Case A", "nodes": [n], "edges": [] }), true).await;
    let (st, v, raw) = call(&a, "GET", &format!("/agent/graphs/{id}?format=json"), json!({}), false).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["nodes"][0]["label"], "example.com");
    assert!(!raw.contains("PRIVATE REMARK"));
    assert_eq!(call(&a, "GET", &format!("/agent/graphs/{id}"), json!({}), false).await.1["format"], "mermaid");
    assert_eq!(call(&a, "GET", &format!("/agent/graphs/{id}?format=xml"), json!({}), false).await.0, StatusCode::BAD_REQUEST);
    let (_, t, _) = call(&a, "GET", "/tools", json!({}), false).await;
    assert!(t.as_array().unwrap().iter().all(|x| x["method"] == "GET"));
    assert_eq!(call(&a, "DELETE", &format!("/agent/graphs/{id}"), json!({}), false).await.0, StatusCode::METHOD_NOT_ALLOWED);
}

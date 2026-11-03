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

fn tmp() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("cn-test-{}", new_id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn new_app() -> (axum::Router, std::path::PathBuf) {
    let d = tmp();
    (app(Arc::new(App { store: Store::new(&d).unwrap() })), d)
}

async fn call(app: &axum::Router, method: &str, uri: &str, body: Value, signed: bool) -> (StatusCode, Value, String) {
    let mut r = Request::builder().method(method).uri(uri).header("content-type", "application/json");
    if signed {
        r = r.header("x-osnt-gateway", sign(method, uri));
    }
    let res = app.clone().oneshot(r.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let st = res.status();
    let b = axum::body::to_bytes(res.into_body(), 1 << 24).await.unwrap();
    let raw = String::from_utf8_lossy(&b).to_string();
    (st, serde_json::from_slice(&b).unwrap_or(Value::Null), raw)
}

async fn make_case(a: &axum::Router) -> String {
    let (st, v, _) = call(a, "POST", "/api/cases", json!({ "title": "Port fire", "description": "d", "tags": ["Fire", "fire", "port"] }), true).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["tags"], json!(["fire", "port"]));
    v["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn every_api_route_needs_the_gateway_signature() {
    let (a, _d) = new_app();
    let id = make_case(&a).await;
    let routes = [
        ("GET", "/api/cases"), ("POST", "/api/cases"), ("GET", "/api/cases/x"), ("PUT", "/api/cases/x"), ("DELETE", "/api/cases/x"),
        ("POST", "/api/cases/x/notes"), ("PUT", "/api/cases/x/notes/y"), ("DELETE", "/api/cases/x/notes/y"), ("POST", "/api/cases/x/timeline"),
        ("DELETE", "/api/cases/x/timeline/y"), ("POST", "/api/cases/x/evidence"), ("GET", "/api/cases/x/verify"), ("GET", "/api/cases/x/export"),
        ("POST", "/api/import"), ("POST", "/api/pin"),
    ];
    for (m, p) in routes {
        let (st, _, _) = call(&a, m, p, json!({}), false).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{m} {p}");
    }
    // a signature for a different path or method does not work
    let r = Request::builder().method("DELETE").uri(format!("/api/cases/{id}")).header("x-osnt-gateway", sign("GET", &format!("/api/cases/{id}"))).body(Body::empty()).unwrap();
    assert_eq!(a.clone().oneshot(r).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    assert_eq!(call(&a, "GET", "/api/cases", json!({}), true).await.0, StatusCode::OK);
}

#[tokio::test]
async fn notes_timeline_and_validation() {
    let (a, _d) = new_app();
    let id = make_case(&a).await;
    let n = format!("/api/cases/{id}/notes");
    assert_eq!(call(&a, "POST", &n, json!({ "title": "", "body": "" }), true).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(call(&a, "POST", &n, json!({ "title": "a\nb" }), true).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(call(&a, "POST", &n, json!({ "body": "x".repeat(100_001) }), true).await.0, StatusCode::BAD_REQUEST);
    let (st, note, _) = call(&a, "POST", &n, json!({ "title": "Idea", "body": "# md\ntext" }), true).await;
    assert_eq!(st, StatusCode::OK);
    let nid = note["id"].as_str().unwrap();
    let (st, upd, _) = call(&a, "PUT", &format!("{n}/{nid}"), json!({ "title": "Idea 2", "body": "new", "share_with_agent": true }), true).await;
    assert_eq!((st, upd["share_with_agent"].clone()), (StatusCode::OK, json!(true)));
    let t = format!("/api/cases/{id}/timeline");
    assert_eq!(call(&a, "POST", &t, json!({ "date": "yesterday", "title": "x" }), true).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(call(&a, "POST", &t, json!({ "date": "2024-13-01", "title": "x" }), true).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(call(&a, "POST", &t, json!({ "date": "2024-05-01", "title": "x", "source_url": "javascript:alert(1)" }), true).await.0, StatusCode::BAD_REQUEST);
    let (st, ev, _) = call(&a, "POST", &t, json!({ "date": "2024-05-01T10:00:00Z", "title": "Smoke seen", "source_url": "https://example.org/a" }), true).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(call(&a, "DELETE", &format!("{t}/{}", ev["id"].as_str().unwrap()), json!({}), true).await.0, StatusCode::OK);
    assert_eq!(call(&a, "DELETE", &format!("{t}/nope"), json!({}), true).await.0, StatusCode::NOT_FOUND);
    assert_eq!(call(&a, "DELETE", &format!("{n}/{nid}"), json!({}), true).await.0, StatusCode::OK);
    assert_eq!(call(&a, "GET", "/api/cases/../../etc/passwd", json!({}), true).await.0, StatusCode::NOT_FOUND);
    assert_eq!(call(&a, "GET", "/api/cases/NOT_VALID", json!({}), true).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn evidence_chain_verifies_and_detects_tampering() {
    let (a, d) = new_app();
    let id = make_case(&a).await;
    let e = format!("/api/cases/{id}/evidence");
    assert_eq!(call(&a, "POST", &e, json!({ "title": "t", "sha256": "xyz" }), true).await.0, StatusCode::BAD_REQUEST);
    for i in 0..3 {
        let (st, v, _) = call(&a, "POST", &e, json!({ "title": format!("item {i}"), "url": "https://example.org/", "sha256": "AB".repeat(32), "note": "n" }), true).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["seq"], i + 1);
        assert_eq!(v["sha256"], "ab".repeat(32));
    }
    let (_, v, _) = call(&a, "GET", &format!("/api/cases/{id}/verify"), json!({}), true).await;
    assert_eq!(v["ok"], true);
    assert_eq!(v["entries"], 3);
    // edit an entry directly on disk: the chain must report where it breaks
    let path = d.join("cases").join(format!("{id}.json"));
    let mut c: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    c["evidence"][1]["title"] = json!("forged");
    std::fs::write(&path, c.to_string()).unwrap();
    let (_, v, _) = call(&a, "GET", &format!("/api/cases/{id}/verify"), json!({}), true).await;
    assert_eq!((v["ok"].clone(), v["broken_at"].clone()), (json!(false), json!(2)));
    // removing an entry is also detected
    let mut c: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    c["evidence"][1]["title"] = json!("item 1");
    c["evidence"].as_array_mut().unwrap().remove(1);
    std::fs::write(&path, c.to_string()).unwrap();
    let (_, v, _) = call(&a, "GET", &format!("/api/cases/{id}/verify"), json!({}), true).await;
    assert_eq!(v["ok"], false);
}

#[tokio::test]
async fn pin_goes_to_inbox_or_chosen_case_and_tags_origin() {
    let (a, _d) = new_app();
    let (st, v, _) = call(&a, "POST", "/api/pin", json!({ "kind": "evidence", "title": "Capture", "url": "https://example.org/", "sha256": "a".repeat(64), "archive_url": "https://web.archive.org/web/2020/https://example.org/", "source_plugin": "web-archive" }), true).await;
    assert_eq!((st, v["case_id"].clone()), (StatusCode::OK, json!("inbox")));
    let (_, v, _) = call(&a, "GET", "/api/cases/inbox", json!({}), true).await;
    assert_eq!(v["case"]["evidence"][0]["origin"], "plugin:web-archive");
    assert_eq!(v["chain"]["ok"], true);
    // a forged origin string is not accepted; it falls back to "user"
    call(&a, "POST", "/api/pin", json!({ "title": "x", "source_plugin": "plugin:evil\nuser" }), true).await;
    let (_, v, _) = call(&a, "GET", "/api/cases/inbox", json!({}), true).await;
    assert_eq!(v["case"]["evidence"][1]["origin"], "user");
    let id = make_case(&a).await;
    let (st, _, _) = call(&a, "POST", "/api/pin", json!({ "case_id": id, "kind": "timeline", "title": "Event", "date": "2024-01-02", "url": "https://example.org/" }), true).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(call(&a, "POST", "/api/pin", json!({ "case_id": "nope", "title": "x" }), true).await.0, StatusCode::NOT_FOUND);
    assert_eq!(call(&a, "POST", "/api/pin", json!({ "kind": "wat", "title": "x" }), true).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(call(&a, "POST", "/api/pin", json!({ "title": "" }), true).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn export_import_round_trip_json_and_markdown() {
    let (a, _d) = new_app();
    let id = make_case(&a).await;
    call(&a, "POST", &format!("/api/cases/{id}/notes"), json!({ "title": "N", "body": "body **md**" }), true).await;
    call(&a, "POST", &format!("/api/cases/{id}/timeline"), json!({ "date": "2024-05-01", "title": "Smoke" }), true).await;
    for i in 0..2 {
        call(&a, "POST", &format!("/api/cases/{id}/evidence"), json!({ "title": format!("e{i}"), "url": "https://example.org/" }), true).await;
    }
    let (_, _, raw) = call(&a, "GET", &format!("/api/cases/{id}/export?format=json"), json!({}), true).await;
    let bundle: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(bundle["format"], "osnt-case/1");
    let (st, imp, _) = call(&a, "POST", "/api/import", bundle.clone(), true).await;
    assert_eq!(st, StatusCode::OK);
    assert_ne!(imp["id"], json!(id));
    assert_eq!((imp["notes"].clone(), imp["timeline"].clone(), imp["evidence"].clone()), (json!(1), json!(1), json!(2)));
    let (_, v, _) = call(&a, "GET", &format!("/api/cases/{}/verify", imp["id"].as_str().unwrap()), json!({}), true).await;
    assert_eq!(v["ok"], true);
    // tampered bundle, wrong format, bad field
    let mut t = bundle.clone();
    t["case"]["evidence"][0]["title"] = json!("changed");
    assert_eq!(call(&a, "POST", "/api/import", t, true).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(call(&a, "POST", "/api/import", json!({ "format": "other" }), true).await.0, StatusCode::BAD_REQUEST);
    let mut t = bundle.clone();
    t["case"]["timeline"][0]["date"] = json!("soon");
    assert_eq!(call(&a, "POST", "/api/import", t, true).await.0, StatusCode::BAD_REQUEST);
    let (st, _, md) = call(&a, "GET", &format!("/api/cases/{id}/export?format=md"), json!({}), true).await;
    assert_eq!(st, StatusCode::OK);
    assert!(md.starts_with("# Port fire") && md.contains("## Timeline") && md.contains("**2024-05-01** Smoke") && md.contains("| 2 |") && md.contains("verified at export") && md.contains("body **md**"));
    assert_eq!(call(&a, "GET", &format!("/api/cases/{id}/export?format=pdf"), json!({}), true).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn agent_view_withholds_private_notes_and_separates_sources() {
    let (a, _d) = new_app();
    let id = make_case(&a).await;
    call(&a, "POST", &format!("/api/cases/{id}/notes"), json!({ "title": "Secret thoughts", "body": "PRIVATE-TEXT" }), true).await;
    call(&a, "POST", &format!("/api/cases/{id}/notes"), json!({ "title": "Shared", "body": "SHARED-TEXT", "share_with_agent": true }), true).await;
    call(&a, "POST", "/api/pin", json!({ "case_id": id, "title": "Fetched page", "url": "https://example.org/", "source_plugin": "web-archive" }), true).await;
    let (st, v, raw) = call(&a, "GET", &format!("/agent/cases/{id}"), json!({}), false).await;
    assert_eq!(st, StatusCode::OK);
    assert!(!raw.contains("PRIVATE-TEXT") && raw.contains("SHARED-TEXT"));
    assert_eq!(v["user_authored"]["notes"][0]["private"], true);
    assert_eq!(v["captured_data"]["evidence"][0]["origin"], "plugin:web-archive");
    assert!(v["user_authored"].get("evidence").is_none());
    assert!(v["reading_guide"].as_str().unwrap().contains("Private notes are withheld"));
    let (_, l, raw) = call(&a, "GET", "/agent/cases", json!({}), false).await;
    assert_eq!(l["cases"][0]["notes"], 2);
    assert!(!raw.contains("SHARED-TEXT"));
    // the agent surface offers no way to write
    let (_, t, _) = call(&a, "GET", "/tools", json!({}), false).await;
    let names: Vec<&str> = t.as_array().unwrap().iter().map(|x| x["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["case_list", "case_get"]);
    assert_eq!(call(&a, "POST", "/agent/cases", json!({}), false).await.0, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(call(&a, "GET", "/agent/cases/missing", json!({}), false).await.0, StatusCode::NOT_FOUND);
}

#[test]
fn atomic_save_leaves_no_temp_files_and_enforces_size_cap() {
    let d = tmp();
    let s = Store::new(&d).unwrap();
    let mut c = Case { id: "abc".into(), title: "t".into(), created: now_iso(), updated: now_iso(), ..Default::default() };
    s.save(&c).unwrap();
    s.save(&c).unwrap();
    let names: Vec<String> = std::fs::read_dir(d.join("cases")).unwrap().flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
    assert_eq!(names, ["abc.json"]);
    // an oversized case is refused and the previous file survives intact
    c.description = "x".repeat(MAX_CASE_BYTES + 10);
    assert!(s.save(&c).is_err());
    assert_eq!(s.load("abc").unwrap().unwrap().description, "");
    assert!(s.load("../abc").unwrap().is_none());
    assert!(!s.delete("missing").unwrap());
    assert!(s.delete("abc").unwrap());
}

#[test]
fn time_and_validators() {
    assert_eq!(iso_from_secs(0), "1970-01-01T00:00:00Z");
    assert_eq!(iso_from_secs(1_709_210_096), "2024-02-29T12:34:56Z");
    assert!(date_field("2024-02-29").is_ok() && date_field("2024-02-29T10:00:00Z").is_ok());
    assert!(date_field("2024-2-29").is_err() && date_field("2024-02-29x").is_err() && date_field("").is_err());
    assert!(url_field("u", "https://a.b/c").is_ok() && url_field("u", "").is_ok());
    assert!(url_field("u", "ftp://a").is_err() && url_field("u", "data:text/html,x").is_err());
    assert!(tags(&(0..21).map(|i| i.to_string()).collect::<Vec<_>>()).is_err());
    assert!(single_line("t", "a\u{7}b", 10, true).is_err());
}

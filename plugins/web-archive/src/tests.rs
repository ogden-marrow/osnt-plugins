use std::{sync::Arc, time::Duration};

use axum::{body::Body, http::Request};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use tower::ServiceExt;

use crate::ssrf::{Guard, testutil::*};
use crate::*;

const KEY: &str = "00112233445566778899aabbccddeeff";

fn set_key() {
    // Tests run in one process; the key is the same for all of them.
    unsafe { std::env::set_var("OSNT_GATEWAY_KEY", KEY) };
}

fn sign(method: &str, pq: &str) -> String {
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let mut m = Hmac::<Sha256>::new_from_slice(KEY.as_bytes()).unwrap();
    m.update(format!("{ts}.{method}.{pq}").as_bytes());
    let sig: String = m.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect();
    format!("v1.{ts}.{sig}")
}

fn state(port: u16, keys: Option<(String, String)>) -> Shared {
    AppState::new(
        Guard { exempt_loopback_port: Some(port) },
        Upstreams { wayback: format!("http://127.0.0.1:{port}"), cc_index: format!("http://127.0.0.1:{port}") },
        Box::new(move || keys.clone()),
        Duration::ZERO,
    )
}

const CDX: &str = r#"[["timestamp","original","statuscode","mimetype","digest","length"],
["20200101000000","http://a.com/","200","text/html","AAA","10"],
["20210101000000","http://a.com/","200","text/html","BBB","12"]]"#;

fn fake() -> u16 {
    spawn(Arc::new(|r| {
        let p = r.path.as_str();
        if p.starts_with("/cdx/search/cdx") {
            if p.contains("url=ratelimited") {
                return Resp { status: 429, headers: vec![], body: b"slow down".to_vec() };
            }
            if p.contains("url=garbage") {
                return Resp::html("<html>oops</html>");
            }
            if p.contains("matchType=domain&collapse=urlkey") {
                return Resp::json(json!([["original", "timestamp", "mimetype", "statuscode"], ["http://a.com/x", "2020", "text/html", "200"], ["http://a.com/x", "2021", "text/html", "200"]]));
            }
            return Resp::json(serde_json::from_str(CDX).unwrap());
        }
        if p == "/collinfo.json" {
            return Resp::json(json!([{ "id": "CC-MAIN-2024-10" }, { "id": "CC-MAIN-2024-33" }, { "id": "../evil" }]));
        }
        if p.starts_with("/CC-MAIN-2024-33-index") {
            return Resp { status: 200, headers: vec![], body: b"{\"url\":\"http://a.com/\",\"timestamp\":\"20240801000000\",\"status\":\"200\",\"mime\":\"text/html\",\"digest\":\"D\",\"filename\":\"f.warc.gz\"}\n".to_vec() };
        }
        if p.starts_with("/CC-MAIN-2024-10-index") {
            return Resp { status: 404, headers: vec![], body: b"{\"message\":\"No Captures found for: a.com\"}".to_vec() };
        }
        if p.starts_with("/web/20200101000000id_/") {
            return Resp::html("<title>One</title><p>keep</p><p>old line</p>");
        }
        if p.starts_with("/web/20210101000000id_/") {
            return Resp::html("<title>Two</title><p>keep</p><p>new line</p>");
        }
        if p.starts_with("/web/20220101000000id_/") {
            return Resp { status: 200, headers: vec![("Content-Type".into(), "image/png".into())], body: vec![0x89, b'P'] };
        }
        if p.starts_with("/save/https://example.org/ok") {
            return Resp::redirect("https://web.archive.org/web/20261103000211/https://example.org/ok");
        }
        if p.starts_with("/save/https://example.org/blocked") {
            return Resp::html("blocked by robots");
        }
        if p.starts_with("/save/https://example.org/limited") {
            return Resp { status: 429, headers: vec![], body: vec![] };
        }
        if r.method == "POST" && p == "/save" {
            return Resp::json(json!({ "url": "https://example.org/", "job_id": "spn2-abc123" }));
        }
        if p == "/save/status/spn2-abc123" {
            return Resp::json(json!({ "status": "success", "timestamp": "20261103000211", "original_url": "https://example.org/" }));
        }
        Resp { status: 404, headers: vec![], body: vec![] }
    }))
}

fn q(url: &str) -> SnapQuery {
    SnapQuery { url: url.into(), limit: None, order: None, from: None, to: None, status: None, scope: None }
}

#[test]
fn snapshots_summarise_the_upstream_rows() {
    let s = state(fake(), None);
    let v = snapshots(&s, &q("a.com")).unwrap();
    assert_eq!(v["count"], 2);
    assert_eq!(v["content_changes"], 1);
    assert_eq!(v["first_seen"], "2020-01-01T00:00:00Z");
    assert_eq!(v["query"]["order"], "earliest");
}

#[test]
fn snapshot_inputs_are_validated() {
    let s = state(fake(), None);
    assert_eq!(snapshots(&s, &q("")).err().unwrap().0, StatusCode::BAD_REQUEST);
    assert_eq!(snapshots(&s, &q("ftp://a.com")).err().unwrap().0, StatusCode::BAD_REQUEST);
    let mut bad_from = q("a.com");
    bad_from.from = Some("20x".into());
    assert_eq!(snapshots(&s, &bad_from).err().unwrap().0, StatusCode::BAD_REQUEST);
    let mut bad_status = q("a.com");
    bad_status.status = Some("2000".into());
    assert_eq!(snapshots(&s, &bad_status).err().unwrap().0, StatusCode::BAD_REQUEST);
}

#[test]
fn upstream_rate_limit_and_garbage_become_readable_errors() {
    let s = state(fake(), None);
    let e = snapshots(&s, &q("ratelimited.com")).err().unwrap();
    assert_eq!(e.0, StatusCode::TOO_MANY_REQUESTS);
    assert!(e.1.contains("rate limiting"));
    let e = snapshots(&s, &q("garbage.com")).err().unwrap();
    assert_eq!(e.0, StatusCode::BAD_GATEWAY);
}

#[test]
fn results_are_cached() {
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let h = hits.clone();
    let port = spawn(Arc::new(move |_| {
        h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Resp::json(serde_json::from_str(CDX).unwrap())
    }));
    let s = state(port, None);
    snapshots(&s, &q("a.com")).unwrap();
    snapshots(&s, &q("a.com")).unwrap();
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn harvest_dedupes_urls() {
    let s = state(fake(), None);
    let v = harvest(&s, &UrlsQuery { domain: "https://A.com/page".into(), limit: Some(10) }).unwrap();
    assert_eq!(v["count"], 1);
    assert_eq!(v["domain"], "a.com");
    assert!(harvest(&s, &UrlsQuery { domain: "localhost".into(), limit: None }).is_err());
}

#[test]
fn common_crawl_uses_newest_crawls_and_treats_404_as_empty() {
    let s = state(fake(), None);
    let v = commoncrawl(&s, &CcQuery { url: "a.com".into(), limit: None, crawls: Some(2), scope: None }).unwrap();
    assert_eq!(v["results"][0]["crawl"], "CC-MAIN-2024-33");
    assert_eq!(v["results"][0]["captures"][0]["time"], "2024-08-01T00:00:00Z");
    assert_eq!(v["results"][1]["crawl"], "CC-MAIN-2024-10");
    assert_eq!(v["results"][1]["captures"].as_array().unwrap().len(), 0);
}

#[test]
fn diff_compares_two_captures_and_rejects_non_text() {
    let s = state(fake(), None);
    let v = diff_snapshots(&s, &DiffQuery { url: "http://a.com/".into(), a: "20200101000000".into(), b: "20210101000000".into() }).unwrap();
    assert_eq!(v["identical_text"], false);
    assert_eq!(v["identical_bytes"], false);
    assert_eq!(v["title_a"], "One");
    assert!(v["hunks"].to_string().contains("new line"));
    assert_eq!(v["a"]["sha256"].as_str().unwrap().len(), 64);
    let e = diff_snapshots(&s, &DiffQuery { url: "http://a.com/".into(), a: "20200101000000".into(), b: "20220101000000".into() }).err().unwrap();
    assert_eq!(e.0, StatusCode::BAD_REQUEST);
    assert!(diff_snapshots(&s, &DiffQuery { url: "http://a.com/".into(), a: "bad".into(), b: "2021".into() }).is_err());
}

#[test]
fn evidence_hashes_the_archived_bytes() {
    let s = state(fake(), None);
    let v = evidence(&s, &EvidenceQuery { url: "http://a.com/".into(), ts: "20200101000000".into() }).unwrap();
    let want: String = Sha256::digest(b"<title>One</title><p>keep</p><p>old line</p>").iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(v["sha256"], want);
    assert_eq!(v["captured_at"], "2020-01-01T00:00:00Z");
    assert_eq!(v["archive_url"], "https://web.archive.org/web/20200101000000/http://a.com/");
    assert!(evidence(&s, &EvidenceQuery { url: "http://a.com/".into(), ts: "2020".into() }).is_err());
}

#[test]
fn save_target_rejects_private_and_odd_urls() {
    let g = Guard::default();
    for u in ["http://127.0.0.1/", "http://10.0.0.1/x", "http://169.254.169.254/", "http://[::1]/", "http://localhost/", "http://example.com:8080/", "http://user:pw@example.com/", "ftp://example.com/", "example.com", "file:///etc/passwd"] {
        assert!(save_target(&g, u).is_err(), "{u}");
    }
    assert!(save_target(&g, "https://this-host-does-not-exist.invalid/x").is_ok()); // only the archive will resolve it
}

#[test]
fn anonymous_save_follows_the_snapshot_redirect() {
    let s = state(fake(), None);
    let v = save(&s, "https://example.org/ok").unwrap();
    assert_eq!(v["mode"], "anonymous");
    assert_eq!(v["timestamp"], "20261103000211");
    assert_eq!(v["archive_url"], "https://web.archive.org/web/20261103000211/https://example.org/ok");
}

#[test]
fn save_failures_and_throttle() {
    let s = state(fake(), None);
    let e = save(&s, "https://example.org/blocked").err().unwrap();
    assert_eq!(e.0, StatusCode::BAD_GATEWAY);
    // The minimum gap between captures applies even after a failure.
    let e = save(&s, "https://example.org/ok").err().unwrap();
    assert_eq!(e.0, StatusCode::TOO_MANY_REQUESTS);
    let s2 = state(fake(), None);
    assert_eq!(save(&s2, "https://example.org/limited").err().unwrap().0, StatusCode::TOO_MANY_REQUESTS);
}

#[test]
fn authenticated_save_returns_a_job_and_status_resolves() {
    let s = state(fake(), Some(("acc".into(), "sec".into())));
    let v = save(&s, "https://example.org/").unwrap();
    assert_eq!(v["mode"], "authenticated");
    assert_eq!(v["job_id"], "spn2-abc123");
    let st = save_status(&s, "spn2-abc123").unwrap();
    assert_eq!(st["status"], "success");
    assert_eq!(st["archive_url"], "https://web.archive.org/web/20261103000211/https://example.org/");
    assert!(save_status(&s, "../x").is_err());
    assert!(save_status(&state(fake(), None), "abc").is_err());
}

async fn call(app: &axum::Router, method: &str, uri: &str, sig: Option<String>, body: &str) -> (StatusCode, Value) {
    let mut r = Request::builder().method(method).uri(uri).header("content-type", "application/json");
    if let Some(s) = sig {
        r = r.header("x-osnt-gateway", s);
    }
    let res = app.clone().oneshot(r.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let st = res.status();
    let b = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
    (st, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

#[tokio::test]
async fn save_route_requires_the_gateway_signature() {
    set_key();
    let app = app(state(fake(), None));
    let body = r#"{"url":"https://example.org/ok"}"#;
    assert_eq!(call(&app, "POST", "/api/save", None, body).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(call(&app, "POST", "/api/save", Some("v1.1.deadbeef".into()), body).await.0, StatusCode::UNAUTHORIZED);
    // A signature for another path is rejected.
    assert_eq!(call(&app, "POST", "/api/save", Some(sign("POST", "/api/other")), body).await.0, StatusCode::UNAUTHORIZED);
    let (st, v) = call(&app, "POST", "/api/save", Some(sign("POST", "/api/save")), body).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "success");
    assert_eq!(call(&app, "GET", "/api/save/status?job=abc", None, "").await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn routes_serve_page_tools_and_errors() {
    let app = app(state(fake(), None));
    let (st, v) = call(&app, "GET", "/tools", None, "").await;
    assert_eq!(st, StatusCode::OK);
    let names: Vec<&str> = v.as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["archive_snapshots", "archive_diff", "archive_urls"]);
    assert!(v.as_array().unwrap().iter().all(|t| t["method"] == "GET"));
    let (st, v) = call(&app, "GET", "/api/snapshots?url=", None, "").await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(v["error"].is_string());
    let (st, v) = call(&app, "GET", "/api/snapshots?url=a.com&limit=5", None, "").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["count"], 2);
    let (st, _) = call(&app, "GET", "/api/info", None, "").await;
    assert_eq!(st, StatusCode::OK);
}

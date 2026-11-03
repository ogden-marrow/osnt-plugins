use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

use axum::{body::Body, http::{Request, StatusCode}};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;
use crate::testutil::*;

fn allow(_: &str, _: &str, _: Option<&str>) -> bool {
    true
}

fn fake(counter: Arc<AtomicUsize>) -> u16 {
    spawn(Arc::new(move |r| {
        counter.fetch_add(1, Ordering::SeqCst);
        let ip = r.path.trim_start_matches('/');
        let last: u32 = ip.rsplit('.').next().and_then(|x| x.parse().ok()).unwrap_or(0);
        match last {
            1 => Resp::json(json!({ "ip": ip, "ports": [443, 80, 80], "hostnames": ["a.example"], "tags": ["cloud"], "vulns": [], "cpes": ["cpe:/a:nginx:nginx:1.18.0"] })),
            2 => Resp::json(json!({ "ip": ip, "ports": [22], "hostnames": [], "tags": ["malware"], "vulns": ["CVE-2021-1", "CVE-2021-1"], "cpes": ["cpe:/a:openbsd:openssh:7.4", "cpe:/a:nginx:nginx:1.18.0"] })),
            3 => Resp::json(json!({ "ip": ip, "ports": [80], "hostnames": ["=cmd|' /C calc'!A0"], "tags": [], "vulns": ["CVE-2022-2"], "cpes": [] })),
            9 => Resp::status(500),
            _ => Resp::json(json!({ "detail": "No information available" })).with_status(404),
        }
    }))
}

trait WithStatus {
    fn with_status(self, c: u16) -> Self;
}
impl WithStatus for Resp {
    fn with_status(mut self, c: u16) -> Self {
        self.status = c;
        self
    }
}

fn state(port: u16, min_prefix: u8) -> Shared {
    let mut s = AppState::new(osnt_common::http_agent("test"), allow, min_prefix);
    s.base = format!("http://127.0.0.1:{port}");
    s.delay = Duration::ZERO;
    Arc::new(s)
}

fn wait_done(s: &Shared, id: &str) -> Value {
    for _ in 0..400 {
        let v = jobs::snapshot(s, id).unwrap();
        if v["state"] != "running" {
            return v;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("scan did not finish");
}

#[test]
fn block_validation() {
    assert_eq!(jobs::parse_block(" 8.8.8.0/24 ", 24).unwrap().to_string(), "8.8.8.0/24");
    assert!(jobs::parse_block("8.8.8.8", 24).is_ok(), "a single address is a /32");
    for (b, p) in [("8.8.0.0/16", 24), ("8.8.8.0/23", 24), ("10.0.0.0/24", 24), ("192.168.1.0/24", 24), ("127.0.0.0/30", 24), ("2001:db8::/48", 24), ("nope", 24), ("8.8.8.0/33", 24), ("0.0.0.0/0", 22), ("", 24), ("8.8.8.0/24/1", 24)] {
        assert!(jobs::parse_block(b, p).is_err(), "{b}");
    }
    assert!(jobs::parse_block("8.8.8.0/22", 22).is_ok());
    assert!(jobs::parse_block("8.8.8.0/22", 24).is_err());
    let s = AppState::new(osnt_common::http_agent("t"), allow, 8);
    assert_eq!(s.min_prefix, 22, "configured limit is clamped to /22");
    assert_eq!(AppState::new(osnt_common::http_agent("t"), allow, 30).min_prefix, 24);
}

#[test]
fn scan_aggregates() {
    let c = Arc::new(AtomicUsize::new(0));
    let s = state(fake(c.clone()), 24);
    let net = jobs::parse_block("198.51.101.0/28", 24).unwrap();
    let id = jobs::start(&s, net).unwrap()["id"].as_str().unwrap().to_string();
    let v = wait_done(&s, &id);
    assert_eq!(v["state"], "done");
    assert_eq!(v["total"], 16);
    assert_eq!(v["done"], 16);
    assert_eq!(v["failed"], 1, "the HTTP 500 address is counted, not fatal");
    let sm = &v["summary"];
    assert_eq!(sm["hosts_with_data"], 3);
    assert_eq!(sm["vulnerable_hosts"], 2);
    assert_eq!(sm["cves"][0], json!({ "name": "CVE-2021-1", "hosts": 1 }), "duplicates within a host count once");
    assert_eq!(sm["ports"][0], json!({ "name": "80", "hosts": 2 }));
    let names: Vec<&str> = sm["products"].as_array().unwrap().iter().map(|p| p["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"nginx 1.18.0") && names.contains(&"openbsd openssh 7.4"));
    assert_eq!(sm["products"][0]["hosts"], 2);
    let cells = v["cells"].as_array().unwrap();
    assert_eq!(cells[0]["risk"], "open");
    assert_eq!(cells[1]["risk"], "high");
    assert_eq!(cells[0]["ports"], json!([80, 443]), "ports sorted and deduped");
    // The same block again is served from cache: no new upstream calls except the failed address
    let before = c.load(Ordering::SeqCst);
    let id2 = jobs::start(&s, net).unwrap()["id"].as_str().unwrap().to_string();
    let v2 = wait_done(&s, &id2);
    assert_eq!(c.load(Ordering::SeqCst) - before, 1, "only the uncached (failed) address is fetched again");
    assert_eq!(v2["from_cache"], 15);
}

#[test]
fn one_scan_at_a_time_and_cancel() {
    let c = Arc::new(AtomicUsize::new(0));
    let mut st = AppState::new(osnt_common::http_agent("test"), allow, 24);
    st.base = format!("http://127.0.0.1:{}", fake(c));
    st.delay = Duration::from_millis(40);
    let s = Arc::new(st);
    let a = jobs::start(&s, jobs::parse_block("198.51.102.0/26", 24).unwrap()).unwrap();
    let again = jobs::start(&s, jobs::parse_block("198.51.102.0/26", 24).unwrap()).unwrap();
    assert_eq!(again["joined"], true);
    assert_eq!(again["id"], a["id"]);
    assert!(jobs::start(&s, jobs::parse_block("198.51.103.0/26", 24).unwrap()).unwrap_err().contains("still running"));
    let id = a["id"].as_str().unwrap();
    assert!(jobs::cancel(&s, id).is_some());
    let v = wait_done(&s, id);
    assert_eq!(v["state"], "cancelled");
    assert!(v["done"].as_u64().unwrap() < 64);
    assert!(jobs::cancel(&s, "nope").is_none());
    assert!(jobs::snapshot(&s, "nope").is_none());
}

#[test]
fn rate_limit_and_repeated_failures_stop_the_scan() {
    let limited = spawn(Arc::new(|_| Resp::status(429)));
    let s = state(limited, 24);
    let id = jobs::start(&s, jobs::parse_block("198.51.104.0/28", 24).unwrap()).unwrap()["id"].as_str().unwrap().to_string();
    let v = wait_done(&s, &id);
    assert_eq!(v["state"], "stopped");
    assert!(v["error"].as_str().unwrap().contains("rate-limited"));
    let broken = spawn(Arc::new(|_| Resp::status(500)));
    let s = state(broken, 24);
    let id = jobs::start(&s, jobs::parse_block("198.51.105.0/28", 24).unwrap()).unwrap()["id"].as_str().unwrap().to_string();
    let v = wait_done(&s, &id);
    assert_eq!(v["state"], "stopped");
    assert!(v["error"].as_str().unwrap().contains("5 errors"));
}

#[test]
fn csv_is_safe_and_complete() {
    let c = Arc::new(AtomicUsize::new(0));
    let s = state(fake(c), 24);
    let id = jobs::start(&s, jobs::parse_block("198.51.106.0/28", 24).unwrap()).unwrap()["id"].as_str().unwrap().to_string();
    wait_done(&s, &id);
    let out = jobs::csv(&s, &id).unwrap();
    assert!(out.starts_with("ip,ports,hostnames,tags,cves,products\n"));
    assert_eq!(out.lines().count(), 4);
    assert!(out.contains("198.51.106.1,80 443,a.example,cloud,,nginx 1.18.0"));
    assert!(out.contains("'=cmd|"), "formula-looking hostnames are neutralised: {out}");
    assert_eq!(jobs::csv_cell_for_test("a,b"), "\"a,b\"");
    assert_eq!(jobs::csv_cell_for_test("x\"y"), "\"x\"\"y\"");
    assert_eq!(jobs::product_for_test("cpe:/a:apache:http_server"), "apache http server");
}

#[test]
fn cache_is_bounded() {
    let s = AppState::new(osnt_common::http_agent("t"), allow, 24);
    for i in 0..5000 {
        s.cache.put(&format!("k{i}"), None);
    }
    assert!(s.cache.len() <= 4096);
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, Value, Vec<u8>) {
    let res = app.clone().oneshot(req).await.unwrap();
    let st = res.status();
    let b = axum::body::to_bytes(res.into_body(), 1 << 22).await.unwrap().to_vec();
    (st, serde_json::from_slice(&b).unwrap_or(Value::Null), b)
}

#[tokio::test]
async fn http_flow() {
    let c = Arc::new(AtomicUsize::new(0));
    let s = state(fake(c), 24);
    let a = app(s.clone());
    let post = |u: &str, b: Value| Request::post(u.to_string()).header("content-type", "application/json").body(Body::from(b.to_string())).unwrap();
    assert_eq!(call(&a, post("/api/scan", json!({ "cidr": "10.0.0.0/24" }))).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(call(&a, post("/api/scan", json!({ "cidr": "8.8.0.0/16" }))).await.0, StatusCode::BAD_REQUEST);
    let (st, v, _) = call(&a, post("/api/scan", json!({ "cidr": "198.51.107.0/29" }))).await;
    assert_eq!(st, StatusCode::OK);
    let id = v["id"].as_str().unwrap().to_string();
    wait_done(&s, &id);
    let (st, v, _) = call(&a, Request::get(format!("/api/scan/{id}")).body(Body::empty()).unwrap()).await;
    assert_eq!((st, v["state"].as_str()), (StatusCode::OK, Some("done")));
    let (st, _, body) = call(&a, Request::get(format!("/api/scan/{id}/csv")).body(Body::empty()).unwrap()).await;
    assert_eq!(st, StatusCode::OK);
    assert!(String::from_utf8(body).unwrap().starts_with("ip,"));
    assert_eq!(call(&a, Request::get("/api/scan/zzz").body(Body::empty()).unwrap()).await.0, StatusCode::NOT_FOUND);
    let (st, v, _) = call(&a, Request::get("/api/summary?cidr=198.51.107.0/29&wait=5").body(Body::empty()).unwrap()).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["complete"], true);
    assert_eq!(call(&a, Request::get("/api/summary?cidr=bogus").body(Body::empty()).unwrap()).await.0, StatusCode::BAD_REQUEST);
    let (_, v, _) = call(&a, Request::get("/api/config").body(Body::empty()).unwrap()).await;
    assert_eq!(v["max_addresses"], 256);
    let (_, v, _) = call(&a, Request::get("/tools").body(Body::empty()).unwrap()).await;
    assert_eq!(v[0]["name"], "cidr_summary");
}

#[tokio::test]
async fn requires_signature() {
    let c = Arc::new(AtomicUsize::new(0));
    let mut st = AppState::new(osnt_common::http_agent("test"), real_authz, 24);
    st.base = format!("http://127.0.0.1:{}", fake(c));
    let a = app(Arc::new(st));
    assert_eq!(call(&a, Request::post("/api/scan").header("content-type", "application/json").body(Body::from("{\"cidr\":\"8.8.8.0/24\"}")).unwrap()).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(call(&a, Request::get("/api/config").body(Body::empty()).unwrap()).await.0, StatusCode::UNAUTHORIZED);
}

#[test]
fn product_name_is_not_doubled() {
    assert_eq!(jobs::product_for_test("cpe:/a:cloudflare:cloudflare"), "cloudflare");
    assert_eq!(jobs::product_for_test("cpe:/a:apache:http_server:2.4.1"), "apache http server 2.4.1");
}

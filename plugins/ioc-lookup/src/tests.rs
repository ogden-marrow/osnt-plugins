use std::sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}};

use axum::{body::Body, http::{Request, StatusCode}};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;
use crate::testutil::*;

fn allow(_: &str, _: &str, _: Option<&str>) -> bool {
    true
}

struct F {
    port: u16,
    hits: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<(String, Vec<(String, String)>)>>>,
}

fn fake() -> F {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(vec![]));
    let (h, sn) = (hits.clone(), seen.clone());
    let port = spawn(Arc::new(move |r| {
        h.fetch_add(1, Ordering::SeqCst);
        sn.lock().unwrap().push((r.path.clone(), r.headers.clone()));
        let p = r.path.as_str();
        if p.starts_with("/idb/") {
            return if p.ends_with("192.0.2.9") || p.ends_with("9.9.9.9") { Resp::status(404) } else { Resp::json(json!({ "ports": [53, 443], "hostnames": ["dns.example"], "tags": ["malware"], "vulns": ["CVE-2021-1"], "cpes": ["cpe:/a:x:y"] })) };
        }
        if p.starts_with("/gn/") {
            return if p.ends_with("9.9.9.9") { Resp::status(404) } else { Resp::json(json!({ "ip": "8.8.8.8", "noise": true, "riot": false, "classification": "malicious", "name": "unknown", "last_seen": "2026-11-01" })) };
        }
        if p.starts_with("/otx/") {
            return if p.contains("nothing") { Resp::status(404) } else { Resp::json(json!({ "pulse_info": { "count": 2, "pulses": [ { "name": "Campaign A" }, { "name": "B" } ] }, "validation": [ { "name": "Whitelisted domain" } ], "country_name": "US" })) };
        }
        if p.starts_with("/us/search") {
            return if p.contains("empty") { Resp::json(json!({ "total": 0, "results": [] })) } else { Resp::json(json!({ "total": 12, "results": [ { "task": { "time": "2026-11-03T04:30:40.628Z" }, "page": { "domain": "e.example", "ip": "1.2.3.4", "country": "US" } } ] })) };
        }
        if p.starts_with("/mn/") {
            return Resp::json(json!({ "count": 997, "data": [ { "rrtype": "a", "answer": "1.2.3.4", "firstSeenTimestamp": 1775811478663u64, "lastSeenTimestamp": 1793644237900u64 }, { "rrtype": "a", "answer": "1.2.3.4", "firstSeenTimestamp": 1775811478663u64, "lastSeenTimestamp": 1793644237900u64 } ] }));
        }
        if p.starts_with("/vt/") {
            return if p.contains("/files/") && p.contains("deadbeef") { Resp::status(404) } else if p.contains("quota") { Resp::status(429) } else { Resp::json(json!({ "data": { "attributes": { "last_analysis_stats": { "malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 10 }, "reputation": -3, "type_description": "Win32 EXE" } } })) };
        }
        if p.starts_with("/ab/check") {
            return Resp::json(json!({ "data": { "abuseConfidenceScore": 100, "totalReports": 42, "usageType": "Data Center", "isp": "X", "countryCode": "NL", "lastReportedAt": "2026-11-02" } }));
        }
        if p == "/scan" {
            return Resp::json(json!({ "uuid": "u-1", "result": "https://urlscan.io/result/u-1/" }));
        }
        Resp::status(404)
    }));
    F { port, hits, seen }
}

fn state(f: &F, keys: &'static [&'static str]) -> AppState {
    let mut s = AppState::new(osnt_common::http_agent("test"), Box::new(move |n| keys.contains(&n).then(|| format!("key-for-{n}"))), allow);
    let b = format!("http://127.0.0.1:{}", f.port);
    s.h = sources::Hosts { urlscan: format!("{b}/us"), otx: format!("{b}/otx"), greynoise: format!("{b}/gn"), mnemonic: format!("{b}/mn"), internetdb: format!("{b}/idb"), vt: format!("{b}/vt"), abuseipdb: format!("{b}/ab") };
    s.urlscan_scan = format!("{b}/scan");
    s
}

fn row(v: &Value, id: &str) -> Value {
    v["rows"].as_array().unwrap().iter().find(|r| r["id"] == id).unwrap().clone()
}

#[test]
fn classify_inputs() {
    assert_eq!(classify("8.8.8.8").unwrap(), Ind::Ip("8.8.8.8".parse().unwrap()));
    assert_eq!(classify("hxxps://Evil[.]example/a?b=1").unwrap(), Ind::Url("https://evil.example/a?b=1".into()));
    assert_eq!(classify("Example.com").unwrap(), Ind::Domain("example.com".into()));
    assert_eq!(classify(&"AB".repeat(16)).unwrap().kind(), "md5");
    assert_eq!(classify(&"ab".repeat(20)).unwrap().kind(), "sha1");
    assert_eq!(classify(&"ab".repeat(32)).unwrap().kind(), "sha256");
    for bad in ["", "   ", "10.1.1.1", "127.0.0.1", "http://192.168.0.1/x", "http://u:p@evil.example/", "http://", "1.2.3.0/24", "a b", "javascript:alert(1)", "ftp://x.example", "localhost", &"x".repeat(2100)] {
        assert!(classify(bad).is_err(), "{bad}");
    }
    assert_eq!(sources::base64url(b"http://a.example/?x=1"), "aHR0cDovL2EuZXhhbXBsZS8_eD0x");
    assert_eq!(sources::base64url(b"a"), "YQ");
}

#[test]
fn ip_fans_out_without_keys() {
    let f = fake();
    let s = state(&f, &[]);
    let v = lookup(&s, "8.8.8.8").unwrap();
    assert_eq!(v["rows"].as_array().unwrap().len(), 7);
    assert_eq!(row(&v, "internetdb")["status"], "hit");
    assert!(row(&v, "internetdb")["summary"].as_str().unwrap().contains("1 known CVE"));
    assert_eq!(row(&v, "greynoise")["status"], "hit");
    assert_eq!(row(&v, "otx")["status"], "hit");
    assert_eq!(row(&v, "urlscan")["status"], "info");
    assert_eq!(row(&v, "mnemonic")["status"], "info");
    assert_eq!(row(&v, "virustotal")["status"], "needs_key");
    assert_eq!(row(&v, "abuseipdb")["status"], "needs_key");
    assert!(v["note"].as_str().unwrap().contains("not combined"), "no combined score claimed");
    assert!(v.get("score").is_none() && v.get("verdict").is_none());
    // the mnemonic details are deduplicated
    let d = row(&v, "mnemonic")["details"].to_string();
    assert_eq!(d.matches("A 1.2.3.4").count(), 1);
    assert!(d.contains("2026-04-10"), "{d}");
}

#[test]
fn unseen_ip_is_clear_not_error() {
    let f = fake();
    let s = state(&f, &[]);
    let v = lookup(&s, "9.9.9.9").unwrap();
    assert_eq!(row(&v, "internetdb")["status"], "clear");
    assert_eq!(row(&v, "greynoise")["status"], "clear");
}

#[test]
fn keys_enable_sources_and_are_sent_but_never_returned() {
    let f = fake();
    let s = state(&f, &["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY", "GREYNOISE_API_KEY", "URLSCAN_API_KEY"]);
    let v = lookup(&s, "8.8.8.8").unwrap();
    assert_eq!(row(&v, "virustotal")["status"], "hit");
    assert!(row(&v, "virustotal")["summary"].as_str().unwrap().contains("5 malicious, 1 suspicious out of 76"));
    assert_eq!(row(&v, "abuseipdb")["status"], "hit");
    assert!(!v.to_string().contains("key-for-"));
    let seen = f.seen.lock().unwrap();
    let hdr = |path: &str, name: &str| seen.iter().find(|(p, _)| p.starts_with(path)).and_then(|(_, h)| h.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone()));
    assert_eq!(hdr("/vt/", "x-apikey").as_deref(), Some("key-for-VIRUSTOTAL_API_KEY"));
    assert_eq!(hdr("/ab/", "key").as_deref(), Some("key-for-ABUSEIPDB_API_KEY"));
    assert_eq!(hdr("/otx/", "x-otx-api-key").as_deref(), Some("key-for-OTX_API_KEY"));
    assert_eq!(hdr("/gn/", "key").as_deref(), Some("key-for-GREYNOISE_API_KEY"));
    assert_eq!(hdr("/us/", "api-key").as_deref(), Some("key-for-URLSCAN_API_KEY"));
}

#[test]
fn domain_url_and_hash_applicability() {
    let f = fake();
    let s = state(&f, &["VIRUSTOTAL_API_KEY"]);
    let v = lookup(&s, "evil.example").unwrap();
    assert_eq!(row(&v, "internetdb")["status"], "n/a");
    assert_eq!(row(&v, "mnemonic")["status"], "info");
    assert_eq!(row(&v, "abuseipdb")["status"], "n/a");
    let v = lookup(&s, "http://evil.example/a").unwrap();
    assert_eq!(row(&v, "mnemonic")["status"], "n/a");
    assert_eq!(row(&v, "urlscan")["status"], "info");
    let seen = f.seen.lock().unwrap();
    assert!(seen.iter().any(|(p, _)| p.starts_with("/vt/urls/aHR0cDovL2V2aWwuZXhhbXBsZS9h")), "VT url id is base64url of the URL");
    drop(seen);
    let v = lookup(&s, &"c".repeat(40)).unwrap();
    assert_eq!(row(&v, "urlscan")["status"], "n/a", "sha1 is not searchable at urlscan");
    assert_eq!(row(&v, "otx")["status"], "hit");
}

#[test]
fn unknown_hash_at_vt_is_clear_and_errors_are_rows() {
    let f = fake();
    let s = state(&f, &["VIRUSTOTAL_API_KEY"]);
    let h = format!("{}{}", "deadbeef".repeat(7), "deadbeef");
    let v = lookup(&s, &h).unwrap();
    assert_eq!(row(&v, "virustotal")["status"], "clear");
    // a failing upstream yields an error row, other rows still answer
    let s2 = {
        let mut s = state(&f, &[]);
        s.h.internetdb = "http://127.0.0.1:1".into();
        s
    };
    let v = lookup(&s2, "8.8.8.8").unwrap();
    assert_eq!(row(&v, "internetdb")["status"], "error");
    assert_eq!(row(&v, "greynoise")["status"], "hit");
}

#[test]
fn rate_limit_is_explained() {
    let f = fake();
    let mut s = state(&f, &["VIRUSTOTAL_API_KEY"]);
    s.h.vt = format!("http://127.0.0.1:{}/vt/quota", f.port);
    let v = lookup(&s, "8.8.8.8").unwrap();
    let r = row(&v, "virustotal");
    assert_eq!(r["status"], "error");
    assert!(r["summary"].as_str().unwrap().contains("429"));
}

#[test]
fn rows_are_cached_and_errors_are_not() {
    let f = fake();
    let s = state(&f, &[]);
    lookup(&s, "8.8.8.8").unwrap();
    let n = f.hits.load(Ordering::SeqCst);
    lookup(&s, "8.8.8.8").unwrap();
    assert_eq!(f.hits.load(Ordering::SeqCst), n, "second lookup is all cache hits");
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let res = app.clone().oneshot(req).await.unwrap();
    let st = res.status();
    let b = axum::body::to_bytes(res.into_body(), 1 << 22).await.unwrap();
    (st, serde_json::from_slice(&b).unwrap_or(Value::Null))
}
fn post(uri: &str, b: Value) -> Request<Body> {
    Request::post(uri).header("content-type", "application/json").body(Body::from(b.to_string())).unwrap()
}

#[tokio::test]
async fn submission_is_opt_in_and_guarded() {
    let f = fake();
    let none = app(Arc::new(state(&f, &[])));
    let (st, _) = call(&none, post("/api/urlscan/submit", json!({ "url": "http://evil.example/", "confirm": true }))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "no key, no submission");
    let keyed = app(Arc::new(state(&f, &["URLSCAN_API_KEY"])));
    assert_eq!(call(&keyed, post("/api/urlscan/submit", json!({ "url": "http://evil.example/" }))).await.0, StatusCode::BAD_REQUEST, "needs confirm");
    assert_eq!(call(&keyed, post("/api/urlscan/submit", json!({ "url": "evil.example", "confirm": true }))).await.0, StatusCode::BAD_REQUEST, "only URLs");
    assert_eq!(call(&keyed, post("/api/urlscan/submit", json!({ "url": "http://10.0.0.1/", "confirm": true }))).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(call(&keyed, post("/api/urlscan/submit", json!({ "url": "http://evil.example/", "confirm": true, "visibility": "weird" }))).await.0, StatusCode::BAD_REQUEST);
    let (st, v) = call(&keyed, post("/api/urlscan/submit", json!({ "url": "http://evil.example/", "confirm": true }))).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["visibility"], "private", "defaults to private");
    assert_eq!(v["uuid"], "u-1");
    // a plain lookup never POSTs to the scan endpoint
    let before = f.seen.lock().unwrap().len();
    call(&keyed, Request::get("/api/lookup?q=http%3A%2F%2Fevil.example%2F").body(Body::empty()).unwrap()).await;
    assert!(f.seen.lock().unwrap()[before..].iter().all(|(p, _)| p != "/scan"));
}

#[tokio::test]
async fn http_surface() {
    use hmac::{Hmac, Mac};
    let f = fake();
    let a = app(Arc::new(state(&f, &["OTX_API_KEY"])));
    assert_eq!(call(&a, Request::get("/api/lookup?q=10.0.0.1").body(Body::empty()).unwrap()).await.0, StatusCode::BAD_REQUEST);
    let (st, v) = call(&a, Request::get("/api/sources").body(Body::empty()).unwrap()).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["urlscan_submit_available"], false);
    assert!(v["sources"].as_array().unwrap().iter().find(|s| s["id"] == "otx").unwrap()["has_key"] == true);
    let (_, t) = call(&a, Request::get("/tools").body(Body::empty()).unwrap()).await;
    assert_eq!(t[0]["name"], "ioc_lookup");
    // signature
    let mut s = state(&f, &[]);
    s.authz = real_authz;
    let a2 = app(Arc::new(s));
    unsafe { std::env::set_var("OSNT_GATEWAY_KEY", "ioc-test-key") };
    assert_eq!(call(&a2, Request::get("/api/lookup?q=8.8.8.8").body(Body::empty()).unwrap()).await.0, StatusCode::UNAUTHORIZED);
    let (path, ts) = ("/api/sources", unix_now().to_string());
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(b"ioc-test-key").unwrap();
    mac.update(format!("{ts}.GET.{path}").as_bytes());
    let sig: String = mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let req = Request::get(path).header("x-osnt-gateway", format!("v1.{ts}.{sig}")).body(Body::empty()).unwrap();
    assert_eq!(call(&a2, req).await.0, StatusCode::OK);
}

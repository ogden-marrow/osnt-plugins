use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};

use axum::{body::Body, http::{Request, StatusCode}};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;
use crate::testutil::*;

fn allow(_: &str, _: &str, _: Option<&str>) -> bool {
    true
}

const FEODO: &str = r#"[{"ip_address":"50.16.16.211","port":443,"status":"online","hostname":"ec2-x.example.com","as_number":14618,"as_name":"AMAZON","country":"US","first_seen":"2024-05-01 10:00:00","last_online":"2026-11-01","malware":"QakBot"},
{"ip_address":"50.16.16.211","port":8080,"status":"offline","hostname":null,"first_seen":"2023-01-01 00:00:00","malware":"Emotet"},
{"ip_address":"162.243.103.246","port":8080,"status":"offline","hostname":null,"first_seen":"2022-06-04 21:24:53","malware":"Emotet"},{"junk":1}]"#;
const DROP4: &str = "{\"cidr\":\"1.10.16.0/20\",\"sblid\":\"SBL256894\",\"rir\":\"apnic\"}\n{\"cidr\":\"203.0.114.0/24\",\"sblid\":\"SBL1\",\"rir\":\"apnic\"}\n{\"type\":\"metadata\",\"timestamp\":1793652242,\"size\":1,\"records\":2}\n";
const DROP6: &str = "{\"cidr\":\"2001:678:254::/48\",\"sblid\":\"SBL697648\",\"rir\":\"ripencc\"}\n";
const IPSUM: &str = "# IPsum\n# Last update: Tue, 03 Nov 2026 03:01:50 +0100\n#\n14.34.249.175\t10\n138.226.239.233\t3\nnot an ip\t4\n8.8.4.4\t1\n";
const TOR: &str = "171.25.193.25\n80.67.167.81\ngarbage\n";
const PHISH: &str = "https://www.roblox.com.et/users/7280036217/profile\nhttps://S4W.in/recwU/\nftp://nope.example/x\nhttps://yukoncloud.cloud/Adobe_Installer.html#frag\n";

struct F {
    port: u16,
    hits: Arc<AtomicUsize>,
    down: Arc<AtomicBool>,
    last_key: Arc<std::sync::Mutex<Option<String>>>,
}
fn fake() -> F {
    let hits = Arc::new(AtomicUsize::new(0));
    let down = Arc::new(AtomicBool::new(false));
    let last_key = Arc::new(std::sync::Mutex::new(None));
    let (h, d, lk) = (hits.clone(), down.clone(), last_key.clone());
    let port = spawn(Arc::new(move |r| {
        let p = r.path.as_str();
        if p.starts_with("/ipsum") || p.starts_with("/feodo") || p.starts_with("/tor") || p.starts_with("/openphish") || p.starts_with("/spamhaus") {
            h.fetch_add(1, Ordering::SeqCst);
            if d.load(Ordering::SeqCst) {
                return Resp::status(503);
            }
        }
        match p {
            "/feodo-0" => Resp::text(FEODO),
            "/spamhaus-drop-0" => Resp::text(DROP4),
            "/spamhaus-drop-1" => Resp::text(DROP6),
            "/ipsum-0" => Resp::text(IPSUM),
            "/tor-exit-0" => Resp::text(TOR),
            "/openphish-0" => Resp::text(PHISH),
            _ if p.starts_with("/details") => Resp::json(json!({ "relays_published": "2026-11-03 03:00:00", "relays_truncated": 0, "relays": [ { "nickname": "DFRI161", "fingerprint": "071B4087358344D5045237655632674124308C2A", "or_addresses": ["171.25.193.25:81"], "flags": ["Exit"], "country": "se", "as": "AS198093", "running": true, "contact": "Jane Doe jane@example.org", "exit_policy_summary": { "accept": ["80", "443"] } } ] })),
            "/uh/host/" => { *lk.lock().unwrap() = r.header("Auth-Key").map(String::from); Resp::json(json!({ "query_status": "ok", "urlcount": "2", "urls": [ { "url": "http://bad.example/x.exe", "url_status": "online", "threat": "malware_download", "date_added": "2026-01-01 00:00:00 UTC" } ] })) }
            "/uh/payload/" => Resp::json(json!({ "query_status": "no_results" })),
            "/tf" => { let b: Value = serde_json::from_slice(&r.body).unwrap(); if b["search_term"] == "50.16.16.211" { Resp::json(json!({ "query_status": "ok", "data": [ { "id": "1", "ioc": "50.16.16.211:443", "malware_printable": "QakBot", "threat_type": "botnet_cc", "confidence_level": 75, "first_seen": "2026-01-01" } ] })) } else { Resp::json(json!({ "query_status": "no_result", "data": "Your search did not yield any results" })) } }
            "/mb" => { let b = String::from_utf8_lossy(&r.body).to_string(); if b.contains("get_recent") { Resp::json(json!({ "query_status": "ok", "data": [ { "sha256_hash": "ab".repeat(32), "signature": "Emotet", "file_type": "exe", "first_seen": "2026-11-01" } ] })) } else { Resp::json(json!({ "query_status": "hash_not_found" })) } }
            _ => Resp::status(404),
        }
    }));
    F { port, hits, down, last_key }
}

fn state(f: &F, dir: &std::path::Path, key: Option<&'static str>) -> AppState {
    let mut s = AppState::new(dir.to_path_buf(), osnt_common::http_agent("test"), Box::new(move |n| if n == "ABUSECH_AUTH_KEY" { key.map(String::from) } else { None }), allow);
    let b = format!("http://127.0.0.1:{}", f.port);
    s.store.base = Some(b.clone());
    s.onionoo = b.clone();
    s.hosts = keyed::Hosts { urlhaus: format!("{b}/uh"), threatfox: format!("{b}/tf"), bazaar: format!("{b}/mb") };
    s
}

fn feed(v: &Value, id: &str) -> Value {
    v["feeds"].as_array().unwrap().iter().find(|f| f["id"] == id).unwrap().clone()
}

#[test]
fn classify_inputs() {
    assert_eq!(classify("8.8.8.8").unwrap(), Indicator::Ip("8.8.8.8".parse().unwrap()));
    assert_eq!(classify(" 8[.]8[.]8[.]8 ").unwrap(), Indicator::Ip("8.8.8.8".parse().unwrap()));
    assert!(matches!(classify("1.10.17.9/20").unwrap(), Indicator::Cidr(n) if n.to_string() == "1.10.16.0/20"));
    assert!(matches!(classify("hxxps://Evil[.]example/Path/").unwrap(), Indicator::Url { host, key, .. } if host == "evil.example" && key == "https://evil.example/Path"));
    assert!(matches!(classify("Example.COM").unwrap(), Indicator::Domain(d) if d == "example.com"));
    assert!(matches!(classify(&"A".repeat(32)).unwrap(), Indicator::Hash(h) if h.len() == 32));
    for bad in ["", "10.0.0.1", "192.168.0.0/16", "8.0.0.0/4", "1.2.3.4/33", "ftp://x.example", "localhost", "not a thing", "999.1.1.1", &"a".repeat(3000), "2001:db8::1"] {
        assert!(classify(bad).is_err(), "{bad}");
    }
    assert!(valid_relay_query("1.2.3.4").is_some() && valid_relay_query("DFRI161").is_some() && valid_relay_query("a b").is_none() && valid_relay_query("x;y").is_none());
}

#[test]
fn parsers() {
    let d = feeds::parse_feodo(FEODO).unwrap();
    assert_eq!(d.total, 3);
    assert_eq!(d.ips[&"50.16.16.211".parse().unwrap()].len(), 2);
    assert_eq!(d.recent[0].indicator, "50.16.16.211", "newest first_seen first");
    assert!(d.hosts.contains_key("ec2-x.example.com"));
    assert!(feeds::parse_feodo("nope").is_err());
    let d = feeds::parse_drop(&format!("{DROP4}{DROP6}")).unwrap();
    assert_eq!((d.total, d.source_updated.as_deref()), (3, Some("2026-11-02")));
    assert!(feeds::parse_drop("junk").is_err());
    let d = feeds::parse_ipsum(IPSUM).unwrap();
    assert_eq!(d.total, 3);
    assert_eq!(d.recent[0].indicator, "14.34.249.175");
    assert!(d.source_updated.unwrap().contains("2026"));
    assert!(feeds::parse_tor("").is_err());
    let d = feeds::parse_openphish(PHISH).unwrap();
    assert_eq!(d.total, 3);
    assert!(d.urls.contains_key("https://s4w.in/recwU"));
    assert!(d.urls.contains_key("https://yukoncloud.cloud/Adobe_Installer.html"));
}

#[test]
fn check_ip_across_feeds() {
    let f = fake();
    let dir = tempfile::tempdir().unwrap();
    let s = state(&f, dir.path(), None);
    let v = check(&s, "50.16.16.211").unwrap();
    assert_eq!(feed(&v, "feodo")["status"], "hit");
    assert_eq!(feed(&v, "feodo")["hits"]["count"], 2);
    assert_eq!(feed(&v, "feodo")["hits"]["items"][0]["since"], "2024-05-01 10:00:00");
    assert_eq!(feed(&v, "ipsum")["status"], "clear");
    assert_eq!(feed(&v, "openphish")["status"], "n/a");
    assert_eq!(feed(&v, "urlhaus")["status"], "needs_key");
    assert_eq!(v["feeds_with_hits"], 1);
    let v = check(&s, "171.25.193.25").unwrap();
    assert_eq!(feed(&v, "tor-exit")["status"], "hit");
    let v = check(&s, "1.10.17.9").unwrap();
    assert_eq!(feed(&v, "spamhaus-drop")["hits"]["items"][0]["link"], "https://www.spamhaus.org/sbl/query/SBL256894");
    let v = check(&s, "2001:678:254::7").unwrap();
    assert_eq!(feed(&v, "spamhaus-drop")["status"], "hit");
}

#[test]
fn check_cidr_domain_url_hash() {
    let f = fake();
    let dir = tempfile::tempdir().unwrap();
    let s = state(&f, dir.path(), None);
    let v = check(&s, "50.16.16.0/24").unwrap();
    assert_eq!(feed(&v, "feodo")["hits"]["count"], 2);
    let v = check(&s, "1.10.0.0/16").unwrap();
    assert_eq!(feed(&v, "spamhaus-drop")["hits"]["count"], 1, "overlapping network counts");
    let v = check(&s, "ec2-x.example.com").unwrap();
    assert_eq!(feed(&v, "feodo")["status"], "hit");
    let v = check(&s, "s4w.in").unwrap();
    assert_eq!(feed(&v, "openphish")["status"], "hit");
    let v = check(&s, "hxxps://s4w[.]in/recwU").unwrap();
    assert_eq!(feed(&v, "openphish")["hits"]["items"][0]["detail"], "reported phishing URL");
    let v = check(&s, "https://s4w.in/other").unwrap();
    assert!(feed(&v, "openphish")["note"].as_str().unwrap().contains("host appears"));
    let v = check(&s, &"a".repeat(64)).unwrap();
    assert_eq!(v["feeds_answered"], 0);
    assert!(v["note"].as_str().unwrap().contains("Auth-Key"));
}

#[test]
fn keyed_feeds_are_queried_live_with_the_key() {
    let f = fake();
    let dir = tempfile::tempdir().unwrap();
    let s = state(&f, dir.path(), Some("secret-key-1"));
    let v = check(&s, "50.16.16.211").unwrap();
    assert_eq!(feed(&v, "urlhaus")["status"], "hit");
    assert_eq!(feed(&v, "urlhaus")["hits"]["count"], 2);
    assert_eq!(feed(&v, "threatfox")["hits"]["items"][0]["detail"], "QakBot / botnet_cc (confidence 75)");
    assert_eq!(feed(&v, "malwarebazaar")["status"], "n/a");
    assert_eq!(f.last_key.lock().unwrap().as_deref(), Some("secret-key-1"));
    assert!(!v.to_string().contains("secret-key-1"));
    let v = check(&s, &"b".repeat(64)).unwrap();
    assert_eq!(feed(&v, "urlhaus")["status"], "clear");
    assert_eq!(feed(&v, "malwarebazaar")["status"], "clear");
    assert_eq!(feed(&v, "threatfox")["status"], "clear");
    let v = check(&s, &"b".repeat(40)).unwrap();
    assert_eq!(feed(&v, "urlhaus")["status"], "n/a", "URLhaus takes MD5 and SHA-256 only");
}

#[test]
fn download_cache_disk_and_stale() {
    let f = fake();
    let dir = tempfile::tempdir().unwrap();
    let s = state(&f, dir.path(), None);
    s.store.ensure(&s.agent, "tor-exit", false).unwrap();
    s.store.ensure(&s.agent, "tor-exit", false).unwrap();
    assert_eq!(f.hits.load(Ordering::SeqCst), 1, "second call is served from memory");
    assert!(dir.path().join("tor-exit.feed").exists());
    // fresh process, fresh disk copy: no download
    let s2 = state(&f, dir.path(), None);
    s2.store.ensure(&s2.agent, "tor-exit", false).unwrap();
    assert_eq!(f.hits.load(Ordering::SeqCst), 1);
    // forced refresh inside the minimum interval is a no-op
    s2.store.ensure(&s2.agent, "tor-exit", true).unwrap();
    assert_eq!(f.hits.load(Ordering::SeqCst), 1);
    // upstream down, nothing cached: error, then cooldown stops hammering
    f.down.store(true, Ordering::SeqCst);
    let s3 = state(&f, tempfile::tempdir().unwrap().path(), None);
    assert!(s3.store.ensure(&s3.agent, "ipsum", false).is_err());
    let n = f.hits.load(Ordering::SeqCst);
    assert!(s3.store.ensure(&s3.agent, "ipsum", false).is_err());
    assert_eq!(f.hits.load(Ordering::SeqCst), n, "retry cooldown");
    let st = s3.store.status();
    assert!(st.iter().find(|x| x["id"] == "ipsum").unwrap()["error"].is_string());
    let v = check(&s3, "8.8.8.8").unwrap();
    assert_eq!(feed(&v, "ipsum")["status"], "error");
    assert!(s3.store.ensure(&s3.agent, "nope", false).is_err());
}

#[test]
fn cleanup_enforces_names_and_removes_temp() {
    let dir = tempfile::tempdir().unwrap();
    for n in ["ipsum.feed", "tor-exit.tmp", "stray.txt", "evil.feed"] {
        std::fs::write(dir.path().join(n), "x").unwrap();
    }
    feeds::cleanup(dir.path());
    let left: Vec<String> = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
    assert_eq!(left, ["ipsum.feed"]);
}

#[test]
fn tor_relay_hides_contact() {
    let f = fake();
    let dir = tempfile::tempdir().unwrap();
    let s = state(&f, dir.path(), None);
    let v = tor_relay(&s, "171.25.193.25").unwrap();
    assert_eq!(v["relays"][0]["nickname"], "DFRI161");
    assert_eq!(v["relays"][0]["exit_ports_accepted"], 2);
    assert!(!v.to_string().contains("jane@example.org") && !v.to_string().contains("contact"));
}

async fn call(app: &Router, method: &str, uri: &str) -> (StatusCode, Value) {
    let res = app.clone().oneshot(Request::builder().method(method).uri(uri).body(Body::empty()).unwrap()).await.unwrap();
    let st = res.status();
    let b = axum::body::to_bytes(res.into_body(), 1 << 22).await.unwrap();
    (st, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

#[tokio::test]
async fn http_routes() {
    let f = fake();
    let dir = tempfile::tempdir().unwrap();
    let app = app(Arc::new(state(&f, dir.path(), None)));
    assert_eq!(call(&app, "GET", "/api/check?q=10.0.0.1").await.0, StatusCode::BAD_REQUEST);
    assert_eq!(call(&app, "GET", "/api/tor?q=a%20b").await.0, StatusCode::BAD_REQUEST);
    assert_eq!(call(&app, "GET", "/api/recent?feed=bogus").await.0, StatusCode::BAD_REQUEST);
    assert_eq!(call(&app, "GET", "/api/recent?feed=ipsum&limit=0").await.0, StatusCode::BAD_REQUEST);
    assert_eq!(call(&app, "GET", "/api/recent?feed=urlhaus").await.0, StatusCode::BAD_REQUEST, "needs a key");
    assert_eq!(call(&app, "POST", "/api/refresh?feed=bogus").await.0, StatusCode::BAD_REQUEST);
    assert_eq!(call(&app, "GET", "/api/refresh").await.0, StatusCode::METHOD_NOT_ALLOWED);
    let (st, v) = call(&app, "GET", "/api/feeds").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["feeds"].as_array().unwrap().len(), 5);
    assert_eq!(v["feeds"][0]["loaded"], false);
    let (_, v) = call(&app, "POST", "/api/refresh?feed=all").await;
    assert_eq!(v["errors"].as_array().unwrap().len(), 0);
    assert_eq!(v["feeds"][2]["entries"], 3);
    let (st, v) = call(&app, "GET", "/api/recent?feed=ipsum&limit=2").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["items"].as_array().unwrap().len(), 2);
    let (_, v) = call(&app, "GET", "/tools").await;
    assert_eq!(v.as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn keyed_recent_and_auth() {
    use hmac::{Hmac, Mac};
    let f = fake();
    let dir = tempfile::tempdir().unwrap();
    let app1 = app(Arc::new(state(&f, dir.path(), Some("k"))));
    let (st, v) = call(&app1, "GET", "/api/recent?feed=malwarebazaar&limit=5").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["items"][0]["detail"], "Emotet exe");
    // signature check
    let mut s = state(&f, dir.path(), None);
    s.authz = real_authz;
    let app2 = app(Arc::new(s));
    unsafe { std::env::set_var("OSNT_GATEWAY_KEY", "tf-test-key") };
    assert_eq!(call(&app2, "GET", "/api/feeds").await.0, StatusCode::UNAUTHORIZED);
    let (path, ts) = ("/api/feeds", unix_now().to_string());
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(b"tf-test-key").unwrap();
    mac.update(format!("{ts}.GET.{path}").as_bytes());
    let sig: String = mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let req = Request::get(path).header("x-osnt-gateway", format!("v1.{ts}.{sig}")).body(Body::empty()).unwrap();
    assert_eq!(app2.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
    // POST refresh with a signature for GET is rejected
    let req = Request::post(path).header("x-osnt-gateway", format!("v1.{ts}.{sig}")).body(Body::empty()).unwrap();
    assert_eq!(app2.oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
}

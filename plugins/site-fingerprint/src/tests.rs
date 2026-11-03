use axum::{body::Body, http::{Request, StatusCode}};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;
use crate::testutil::*;

fn allow(_: &str, _: &str, _: Option<&str>) -> bool {
    true
}

const HOME: &str = r#"<!doctype html><html lang="en"><head><title>Test  Site</title><meta name="description" content="A fixture"><meta name="generator" content="WordPress 6.4.2">
<link rel="icon" href="/static/fav.ico"><link rel="canonical" href="https://example.test/"><script src="/wp-includes/js/jquery/jquery-3.7.1.min.js"></script></head><body>hello</body></html>"#;

fn site() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let port = spawn(Arc::new(move |r| {
        h.fetch_add(1, Ordering::SeqCst);
        match r.path.as_str() {
            "/" => Resp::html(HOME).with("Server", "nginx/1.18.0").with("Strict-Transport-Security", "max-age=63072000").with("X-Content-Type-Options", "nosniff").with("Set-Cookie", "PHPSESSID=SECRETSESSION; Path=/; HttpOnly").with("Alt-Svc", "h3=\":443\"").with("X-Powered-By", "PHP/8.1.2"),
            "/old" => Resp::redirect_to("/"),
            "/robots.txt" => Resp::text("User-agent: *\nDisallow: /private\nSitemap: http://127.0.0.1:PORT/sitemap.xml\n"),
            "/sitemap.xml" => Resp::bytes(b"<urlset><url><loc>http://x/1</loc></url><url><loc>http://x/2</loc></url></urlset>", "application/xml"),
            "/static/fav.ico" => Resp::bytes(b"\x00\x00\x01\x00icondata", "image/x-icon"),
            "/plain" => Resp::text("just text").with("Server", "tiny"),
            "/loop" => Resp::redirect_to("/loop"),
            "/to-internal" => Resp::redirect_to("http://169.254.169.254/latest/meta-data/"),
            _ => Resp::status(404),
        }
    }));
    (port, hits)
}

fn state_for(port: u16) -> Shared {
    let mut s = AppState::new(allow);
    s.guard = Guard { exempt_loopback_port: Some(port) };
    s.agent = guarded_agent(s.guard.clone(), "test");
    Arc::new(s)
}

#[test]
fn input_normalisation() {
    assert_eq!(normalise_input(" Example.com ").unwrap().as_str(), "https://example.com/");
    assert_eq!(normalise_input("http://a.example/x?y=1#frag").unwrap().as_str(), "http://a.example/x?y=1");
    for bad in ["", "   ", "ftp://a.example", "file:///etc/passwd", "javascript:alert(1)", "http://user:pw@a.example/", "a b.example", &format!("http://{}", "a".repeat(2100)), "http://", "gopher://a.example"] {
        assert!(normalise_input(bad).is_err(), "{bad}");
    }
}

#[test]
fn full_fingerprint_of_a_fake_site() {
    let (port, _) = site();
    let s = state_for(port);
    let u = Url::parse(&format!("http://127.0.0.1:{port}/old")).unwrap();
    let v = fingerprint(&s, &u).unwrap();
    assert_eq!(v["status"], 200);
    assert_eq!(v["redirect_count"], 1);
    assert_eq!(v["redirects"][0]["status"], 302);
    assert_eq!(v["page"]["title"], "Test Site");
    assert_eq!(v["page"]["generator"], "WordPress 6.4.2");
    assert_eq!(v["page"]["lang"], "en");
    let tech: Vec<&str> = v["tech"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    for want in ["nginx", "WordPress", "PHP", "jQuery"] {
        assert!(tech.contains(&want), "{tech:?}");
    }
    assert_eq!(v["http"]["http3_advertised"], true);
    assert_eq!(v["tls"]["available"], false, "plain http has no TLS");
    assert!(v["security"]["leaks"].as_array().unwrap().len() >= 2);
    assert_eq!(v["security"]["items"][0]["status"], "na", "HSTS not applicable over http");
    assert_eq!(v["cookies"][0]["name"], "PHPSESSID");
    assert!(!v.to_string().contains("SECRETSESSION"), "cookie values are never returned");
    assert_eq!(v["files"]["robots"]["found"], true);
    assert_eq!(v["files"]["robots"]["disallow_sample"], json!(["/private"]));
    assert_eq!(v["files"]["sitemap"]["entries"], 2);
    assert_eq!(v["favicon"]["bytes"], 12);
    assert!(v["favicon"]["mmh3"].is_i64());
    assert!(v["favicon"]["shodan_query"].as_str().unwrap().starts_with("http.favicon.hash:"));
}

#[test]
fn non_html_and_missing_files() {
    let (port, _) = site();
    let s = state_for(port);
    let v = fingerprint(&s, &Url::parse(&format!("http://127.0.0.1:{port}/plain")).unwrap()).unwrap();
    assert_eq!(v["page"]["is_html"], false);
    assert!(v["page"]["title"].is_null());
    assert_eq!(v["tech"].as_array().unwrap().len(), 0);
}

#[test]
fn ssrf_and_redirect_protection() {
    let (port, _) = site();
    let s = state_for(port);
    for bad in ["http://127.0.0.1:1/", "http://10.0.0.1/", "http://169.254.169.254/", "http://localhost/", "http://[::1]/", "http://93.184.216.34:8080/"] {
        let e = fingerprint(&s, &Url::parse(bad).unwrap()).unwrap_err();
        assert!(e.contains("blocked") || e.contains("resolved") || e.contains("not allowed") || e.contains("failed"), "{bad}: {e}");
    }
    let e = fingerprint(&s, &Url::parse(&format!("http://127.0.0.1:{port}/to-internal")).unwrap()).unwrap_err();
    assert!(e.contains("blocked"), "{e}");
    let e = fingerprint(&s, &Url::parse(&format!("http://127.0.0.1:{port}/loop")).unwrap()).unwrap_err();
    assert!(e.contains("redirects"), "{e}");
}

#[test]
fn unreachable_host_is_a_clean_error() {
    let s = Arc::new(AppState::new(allow));
    let e = fingerprint(&s, &Url::parse("http://this-host-does-not-exist.invalid/").unwrap()).unwrap_err();
    assert!(e.contains("resolved"), "{e}");
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let res = app.clone().oneshot(req).await.unwrap();
    let st = res.status();
    let b = axum::body::to_bytes(res.into_body(), 1 << 22).await.unwrap();
    (st, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

#[tokio::test]
async fn http_api_validation_cache_and_concurrency() {
    let (port, hits) = site();
    let s = state_for(port);
    let a = app(s.clone());
    assert_eq!(call(&a, Request::get("/api/fingerprint?url=ftp%3A%2F%2Fx.example").body(Body::empty()).unwrap()).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(call(&a, Request::get("/api/fingerprint?url=http%3A%2F%2F10.0.0.1%2F").body(Body::empty()).unwrap()).await.0, StatusCode::BAD_GATEWAY);
    let uri = format!("/api/fingerprint?url=http%3A%2F%2F127.0.0.1%3A{port}%2F");
    let (st, v) = call(&a, Request::get(&uri).body(Body::empty()).unwrap()).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["page"]["title"], "Test Site");
    let n = hits.load(Ordering::SeqCst);
    call(&a, Request::get(&uri).body(Body::empty()).unwrap()).await;
    assert_eq!(hits.load(Ordering::SeqCst), n, "second request is cached");
    s.running.store(MAX_CONCURRENT, Ordering::SeqCst);
    let uri2 = format!("/api/fingerprint?url=http%3A%2F%2F127.0.0.1%3A{port}%2Fplain");
    assert_eq!(call(&a, Request::get(&uri2).body(Body::empty()).unwrap()).await.0, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn ssllabs_is_opt_in_and_validated() {
    let fake = spawn(Arc::new(|r| {
        assert!(r.path.contains("host=site.example"), "{}", r.path);
        Resp::json(json!({ "host": "site.example", "status": "READY", "testTime": 1, "endpoints": [ { "ipAddress": "1.2.3.4", "grade": "A+", "statusMessage": "Ready" } ] }))
    }));
    let mut st = AppState::new(allow);
    st.ssllabs = format!("http://127.0.0.1:{fake}");
    let a = app(Arc::new(st));
    let post = |b: Value| Request::post("/api/ssllabs").header("content-type", "application/json").body(Body::from(b.to_string())).unwrap();
    assert_eq!(call(&a, post(json!({ "host": "site.example" }))).await.0, StatusCode::BAD_REQUEST, "needs confirm");
    assert_eq!(call(&a, post(json!({ "host": "1.2.3.4", "confirm": true }))).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(call(&a, post(json!({ "host": "a/b.example", "confirm": true }))).await.0, StatusCode::BAD_REQUEST);
    let (st, v) = call(&a, post(json!({ "host": "Site.Example", "confirm": true }))).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["grades"][0]["grade"], "A+");
    assert_eq!(v["ready"], true);
}

#[tokio::test]
async fn requires_signature_and_has_tools() {
    let a = app(Arc::new(AppState::new(real_authz)));
    assert_eq!(call(&a, Request::get("/api/fingerprint?url=example.com").body(Body::empty()).unwrap()).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(call(&a, Request::post("/api/ssllabs").header("content-type", "application/json").body(Body::from("{}")).unwrap()).await.0, StatusCode::UNAUTHORIZED);
    let (st, v) = call(&a, Request::get("/tools").body(Body::empty()).unwrap()).await;
    assert_eq!((st, v[0]["name"].as_str()), (StatusCode::OK, Some("site_fingerprint")));
}

#[test]
fn certificate_errors_are_recognised_for_the_partial_tls_report() {
    assert!(is_certificate_error("request failed: io: invalid peer certificate: certificate expired: verification time 1"));
    assert!(is_certificate_error("invalid peer certificate: UnknownIssuer"));
    assert!(!is_certificate_error("host could not be resolved"));
    assert!(!is_certificate_error("connection timed out"));
}

//! Site fingerprint: what does one URL say about itself? A handful of ordinary GET requests (the page, robots.txt,
//! sitemap, favicon) plus one TLS handshake, all through the SSRF guard. Nothing is probed, scanned or guessed.

mod common;
mod fetch;
mod files;
mod headers;
mod html;
mod ssrf;
mod tech;
#[cfg(test)]
mod testutil;
mod tls;

use std::{env, net::SocketAddr, sync::{Arc, atomic::{AtomicUsize, Ordering}}, time::Duration};

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    middleware,
    response::Html,
    routing::{get, post},
};
use common::*;
use serde::Deserialize;
use serde_json::{Value, json};
use ssrf::{Guard, guarded_agent, guarded_get};
use url::Url;

const PAGE: &str = include_str!("../assets/index.html");
const UA: &str = "osnt-site-fingerprint/0.1 (+https://github.com/ogden-marrow/osnt-hub)";
const MAX_CONCURRENT: usize = 3;

pub struct AppState {
    pub guard: Guard,
    pub agent: ureq::Agent,
    pub plain: ureq::Agent,
    pub ssllabs: String,
    pub authz: Authz,
    pub cache: TtlCache<Value>,
    pub labs: TtlCache<Value>,
    pub running: AtomicUsize,
    /// Tests: skip TLS inspection (the fake server is plain http).
    pub tls_port: Option<u16>,
}
pub type Shared = Arc<AppState>;

impl AppState {
    pub fn new(authz: Authz) -> Self {
        let guard = Guard::default();
        Self { agent: guarded_agent(guard.clone(), UA), guard, plain: osnt_common::http_agent(UA), ssllabs: "https://api.ssllabs.com/api/v3".into(), authz, cache: TtlCache::new(Duration::from_secs(600), 64), labs: TtlCache::new(Duration::from_secs(1800), 32), running: AtomicUsize::new(0), tls_port: None }
    }
}

/// Turn what the user typed into a fetchable http(s) URL. A bare host gets https://.
pub fn normalise_input(s: &str) -> Result<Url, String> {
    let t = s.trim();
    if t.is_empty() || t.len() > 2000 || t.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("enter a URL or host name".into());
    }
    let with = if t.contains("://") { t.to_string() } else { format!("https://{t}") };
    let mut u = Url::parse(&with).map_err(|_| "that is not a valid URL".to_string())?;
    if !matches!(u.scheme(), "http" | "https") {
        return Err("only http and https URLs can be fingerprinted".into());
    }
    if u.host_str().is_none() {
        return Err("the URL has no host".into());
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err("URLs with embedded credentials are not accepted".into());
    }
    u.set_fragment(None);
    Ok(u)
}

fn origin(u: &Url) -> String {
    let mut o = format!("{}://{}", u.scheme(), u.host_str().unwrap_or(""));
    if let Some(p) = u.port() {
        o.push_str(&format!(":{p}"));
    }
    o
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme() && a.host_str() == b.host_str() && a.port_or_known_default() == b.port_or_known_default()
}

pub fn fingerprint(s: &AppState, start: &Url) -> Result<Value, String> {
    let page = fetch::fetch_chain(&s.agent, &s.guard, start)?;
    let fin = page.final_url.clone();
    let https = fin.scheme() == "https";
    let text = String::from_utf8_lossy(&page.body).to_string();
    let is_html = page.content_type.contains("html") || text.trim_start().to_ascii_lowercase().starts_with("<!doctype html") || text.to_ascii_lowercase().contains("<html");
    let tags = if is_html { html::scan(&text) } else { vec![] };
    let lower = if is_html { text.to_ascii_lowercase() } else { String::new() };
    let cookie_names: Vec<String> = page.set_cookies.iter().map(|c| c.split('=').next().unwrap_or("").trim().to_string()).collect();
    let tech = tech::detect(&page.headers, &cookie_names, &tags, &lower);
    let origin_s = origin(&fin);
    let icon_href = tags.iter().filter(|t| t.name == "link").filter(|t| t.attr("rel").is_some_and(|r| r.to_ascii_lowercase().split_whitespace().any(|w| w == "icon"))).filter_map(|t| t.attr("href")).find(|h| !h.starts_with("data:"));
    let icon_url = icon_href.and_then(|h| fin.join(h).ok()).or_else(|| Url::parse(&format!("{origin_s}/favicon.ico")).ok());

    let host = fin.host_str().unwrap_or("").to_string();
    let (tls_v, robots, favicon) = std::thread::scope(|sc| {
        let tls_h = sc.spawn(|| -> Value {
            if !https {
                return json!({ "available": false, "note": "The final page is served over plain http, so there is no TLS to inspect." });
            }
            match s.guard.check_url(&fin, false) {
                Err(e) => json!({ "available": false, "error": e }),
                Ok(addrs) => match addrs.first().map(|a| SocketAddr::new(a.ip(), s.tls_port.unwrap_or(443))) {
                    None => json!({ "available": false, "error": "no address" }),
                    Some(a) => match tls::inspect(a, &host) {
                        Ok(mut v) => {
                            v["available"] = json!(true);
                            v
                        }
                        Err(e) => json!({ "available": false, "error": e }),
                    },
                },
            }
        });
        let robots_h = sc.spawn(|| robots_and_sitemap(s, &origin_s, &fin));
        let fav_h = sc.spawn(|| icon_url.as_ref().map(|u| favicon(s, u)).unwrap_or(Value::Null));
        (tls_h.join().unwrap_or(json!({ "available": false })), robots_h.join().unwrap_or(Value::Null), fav_h.join().unwrap_or(Value::Null))
    });

    let alt_svc = headers::get(&page.headers, "alt-svc").map(String::from);
    let h3 = alt_svc.as_deref().is_some_and(|a| a.contains("h3"));
    let alpn = tls_v["alpn"].as_str().map(String::from);
    let meta_of = |k: &str| html::meta(&tags, k).map(|v| html::decode(&v.chars().take(300).collect::<String>()));
    let selected: Vec<Value> = ["server", "x-powered-by", "via", "content-type", "content-language", "cache-control", "alt-svc", "x-generator"].iter().filter_map(|k| headers::get(&page.headers, k).map(|v| json!([k, v.chars().take(200).collect::<String>()]))).collect();
    Ok(json!({
        "input": start.to_string(), "final_url": fin.to_string(), "status": page.status, "redirects": page.hops, "redirect_count": page.hops.len() - 1,
        "https": https, "truncated": page.truncated,
        "page": { "title": if is_html { html::title(&text) } else { None }, "description": meta_of("description"), "generator": meta_of("generator"), "robots_meta": meta_of("robots"), "canonical": tags.iter().find(|t| t.name == "link" && t.attr("rel").is_some_and(|r| r.eq_ignore_ascii_case("canonical"))).and_then(|t| t.attr("href")).map(|h| h.chars().take(300).collect::<String>()),
                  "lang": tags.iter().find(|t| t.name == "html").and_then(|t| t.attr("lang")).map(String::from), "bytes": page.body.len(), "is_html": is_html, "scripts": tags.iter().filter(|t| t.name == "script" && t.attr("src").is_some()).count() },
        "headers": selected,
        "http": { "alpn": alpn, "http2": alpn.as_deref() == Some("h2"), "alt_svc": alt_svc.map(|a| a.chars().take(200).collect::<String>()), "http3_advertised": h3,
                  "note": "HTTP/2 is what the server negotiated over TLS; HTTP/3 is only what Alt-Svc advertises. This tool fetches with HTTP/1.1." },
        "tech": tech,
        "security": headers::scorecard(&page.headers, https),
        "cookies": page.set_cookies.iter().take(30).map(|c| headers::parse_cookie(c, https)).collect::<Vec<_>>(),
        "tls": tls_v, "files": robots, "favicon": favicon,
        "requests_made": "page and its redirects, /robots.txt, one sitemap, one favicon, and one TLS handshake",
    }))
}

fn favicon(s: &AppState, u: &Url) -> Value {
    match guarded_get(&s.agent, &s.guard, u.as_str(), 256 * 1024, "image/*,*/*;q=0.5") {
        Ok(f) if f.status == 200 && !f.body.is_empty() && !files::looks_like_html(&f.body, &f.content_type) => files::favicon_json(&f.final_url, &f.body, &f.content_type),
        Ok(f) => json!({ "url": u.to_string(), "error": format!("no usable icon (HTTP {})", f.status) }),
        Err(e) => json!({ "url": u.to_string(), "error": e }),
    }
}

fn robots_and_sitemap(s: &AppState, origin_s: &str, fin: &Url) -> Value {
    let robots_url = format!("{origin_s}/robots.txt");
    let robots = match guarded_get(&s.agent, &s.guard, &robots_url, 256 * 1024, "text/plain,*/*;q=0.5") {
        Ok(f) if f.status == 200 && !files::looks_like_html(&f.body, &f.content_type) => {
            let mut v = files::robots_summary(&String::from_utf8_lossy(&f.body));
            v["found"] = json!(true);
            v["url"] = json!(robots_url);
            v
        }
        Ok(f) => json!({ "found": false, "url": robots_url, "note": format!("HTTP {}", f.status) }),
        Err(e) => json!({ "found": false, "url": robots_url, "note": e }),
    };
    // Sitemap: the first one declared in robots.txt on the same origin, else /sitemap.xml.
    let declared = robots["sitemaps"].as_array().and_then(|a| a.iter().filter_map(|v| v.as_str()).filter_map(|u| Url::parse(u).ok()).find(|u| same_origin(u, fin))).map(|u| u.to_string());
    let sm_url = declared.unwrap_or_else(|| format!("{origin_s}/sitemap.xml"));
    let sitemap = match guarded_get(&s.agent, &s.guard, &sm_url, 1024 * 1024, "application/xml,text/xml,*/*;q=0.5") {
        Ok(f) if f.status == 200 && f.body.starts_with(&[0x1f, 0x8b]) => json!({ "found": true, "url": sm_url, "note": "compressed sitemap not read" }),
        Ok(f) if f.status == 200 && !files::looks_like_html(&f.body, &f.content_type) => {
            let mut v = files::sitemap_summary(&String::from_utf8_lossy(&f.body));
            v["found"] = json!(true);
            v["url"] = json!(sm_url);
            v["truncated"] = json!(f.truncated);
            v
        }
        Ok(f) => json!({ "found": false, "url": sm_url, "note": format!("HTTP {}", f.status) }),
        Err(e) => json!({ "found": false, "url": sm_url, "note": e }),
    };
    json!({ "robots": robots, "sitemap": sitemap })
}

struct Slot<'a>(&'a AtomicUsize);
impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Deserialize)]
struct UrlQ {
    url: String,
}
async fn fingerprint_h(State(s): State<Shared>, Query(q): Query<UrlQ>) -> Result<Json<Value>, ApiError> {
    let u = normalise_input(&q.url).map_err(|e| bad(&e))?;
    let key = u.to_string();
    if let Some(v) = s.cache.get(&key) {
        return Ok(Json(v));
    }
    if s.running.fetch_add(1, Ordering::SeqCst) >= MAX_CONCURRENT {
        s.running.fetch_sub(1, Ordering::SeqCst);
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "several fingerprints are already running; try again in a moment".into()));
    }
    let s2 = s.clone();
    let r = blocking(move || {
        let _slot = Slot(&s2.running);
        fingerprint(&s2, &u)
    })
    .await?;
    match r {
        Ok(v) => {
            s.cache.put(&key, v.clone());
            Ok(Json(v))
        }
        Err(e) => Err(ApiError(StatusCode::BAD_GATEWAY, e)),
    }
}

#[derive(Deserialize)]
struct LabsBody {
    host: String,
    #[serde(default)]
    confirm: bool,
}
/// Opt-in SSL Labs lookup. Honest caveat: the v3 API has no read-only mode, so asking for a host nobody has
/// assessed recently makes SSL Labs begin a public assessment of it. Hence the explicit confirmation.
async fn labs_h(State(s): State<Shared>, Json(b): Json<LabsBody>) -> Result<Json<Value>, ApiError> {
    if !b.confirm {
        return Err(bad("confirm that you accept SSL Labs may start a new assessment of this host"));
    }
    let host = valid_domain(&b.host).ok_or_else(|| bad("SSL Labs takes a host name (not an IP address or URL)"))?;
    if let Some(v) = s.labs.get(&host) {
        return Ok(Json(v));
    }
    let v = blocking(move || {
        let url = format!("{}/analyze?host={}&fromCache=on&maxAge=2160&all=done", s.ssllabs, host);
        let v = get_json(&s.plain, &url, &[("Accept", "application/json")]).map_err(|e| e.to_string())?;
        let status = v["status"].as_str().unwrap_or("").to_string();
        let grades: Vec<Value> = v["endpoints"].as_array().map(|a| a.iter().map(|e| json!({ "ip": e["ipAddress"], "grade": e["grade"], "grade_trust_ignored": e["gradeTrustIgnored"], "status": e["statusMessage"], "has_warnings": e["hasWarnings"] })).collect()).unwrap_or_default();
        let out = json!({ "host": host, "status": status, "message": v["statusMessage"], "grades": grades, "tested": v["testTime"],
                          "ready": status == "READY", "report": format!("https://www.ssllabs.com/ssltest/analyze.html?d={host}&hideResults=on"),
                          "note": "Provided by Qualys SSL Labs under its terms of use (https://www.ssllabs.com/about/terms.html). If no recent assessment existed, one was started; ask again in a few minutes." });
        if status == "READY" {
            s.labs.put(&host, out.clone());
        }
        Ok::<_, String>(out)
    })
    .await?;
    v.map(Json).map_err(|e| upstream(format!("SSL Labs: {e}")))
}

async fn tools() -> Json<Value> {
    Json(json!([
        { "name": "site_fingerprint", "description": "Fingerprint one http(s) URL: redirect chain, server/framework/technology hints, security-header scorecard, cookie flags (names only), robots.txt and sitemap summary, favicon mmh3 hash, TLS version and certificate chain, HTTP/2 and HTTP/3 hints. Makes a few ordinary requests to that site only (SSRF-guarded, ports 80/443).",
          "method": "GET", "path": "api/fingerprint", "parameters": { "type": "object", "properties": { "url": { "type": "string", "description": "URL or host name, e.g. https://example.org" } }, "required": ["url"] } }
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

pub fn app(state: Shared) -> Router {
    let api = Router::new()
        .route("/api/fingerprint", get(fingerprint_h))
        .route("/api/ssllabs", post(labs_h))
        .route_layer(middleware::from_fn_with_state(state.authz, require_gateway));
    Router::new().route("/", get(page)).route("/tools", get(tools)).merge(api).with_state(state)
}

#[tokio::main]
async fn main() -> Result<()> {
    let state: Shared = Arc::new(AppState::new(real_authz));
    let addr: SocketAddr = env::var("OSNT_SITE_FINGERPRINT_BIND").unwrap_or_else(|_| "127.0.0.1:8138".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("site-fingerprint plugin on http://{addr}");
    axum::serve(listener, app(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests;

//! IOC reputation lookup: one indicator, many independent sources, one honest row per source. No combined score.

mod common;
mod sources;
#[cfg(test)]
mod testutil;

use std::{env, net::{IpAddr, SocketAddr}, sync::Arc, time::Duration};

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Query, State},
    middleware,
    response::Html,
    routing::{get, post},
};
use common::*;
use serde::Deserialize;
use serde_json::{Value, json};

const PAGE: &str = include_str!("../assets/index.html");

pub struct AppState {
    pub agent: ureq::Agent,
    pub h: sources::Hosts,
    pub urlscan_scan: String,
    pub keys: Box<dyn Fn(&str) -> Option<String> + Send + Sync>,
    pub authz: Authz,
    key_cache: TtlCache<Option<String>>,
    row_cache: TtlCache<Value>,
}
pub type Shared = Arc<AppState>;

impl AppState {
    pub fn new(agent: ureq::Agent, keys: Box<dyn Fn(&str) -> Option<String> + Send + Sync>, authz: Authz) -> Self {
        Self { agent, h: sources::Hosts::real(), urlscan_scan: "https://urlscan.io/api/v1/scan/".into(), keys, authz, key_cache: TtlCache::new(Duration::from_secs(60), 16), row_cache: TtlCache::new(Duration::from_secs(900), 512) }
    }
    pub fn key(&self, name: &str) -> Option<String> {
        if let Some(v) = self.key_cache.get(name) {
            return v;
        }
        let v = (self.keys)(name);
        self.key_cache.put(name, v.clone());
        v
    }
}

#[derive(Debug, PartialEq)]
pub enum Ind {
    Ip(IpAddr),
    Domain(String),
    Url(String),
    Hash(String),
}

impl Ind {
    pub fn kind(&self) -> &'static str {
        match self {
            Ind::Ip(_) => "ip",
            Ind::Domain(_) => "domain",
            Ind::Url(_) => "url",
            Ind::Hash(h) => match h.len() {
                32 => "md5",
                40 => "sha1",
                _ => "sha256",
            },
        }
    }
    pub fn text(&self) -> String {
        match self {
            Ind::Ip(i) => i.to_string(),
            Ind::Domain(s) | Ind::Url(s) | Ind::Hash(s) => s.clone(),
        }
    }
}

/// Undo common defanging (hxxp, [.]) so pasted indicators work.
pub fn refang(s: &str) -> String {
    let mut t = s.trim().replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[://]", "://");
    for (a, b) in [("hxxps://", "https://"), ("hxxp://", "http://")] {
        if t.to_ascii_lowercase().starts_with(a) {
            t = format!("{b}{}", &t[a.len()..]);
        }
    }
    t
}

pub fn classify(q: &str) -> Result<Ind, String> {
    let t = refang(q);
    if t.is_empty() || t.len() > 2048 {
        return Err("enter an IP address, domain, URL or file hash".into());
    }
    let lower = t.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        let u = url::Url::parse(&t).map_err(|_| "that is not a valid URL".to_string())?;
        if u.host_str().is_none() || !u.username().is_empty() || u.password().is_some() {
            return Err("URLs must have a host and no embedded credentials".into());
        }
        if let Some(url::Host::Ipv4(a)) = u.host().map(|h| h.to_owned()) {
            if !ip_is_public(IpAddr::V4(a)) {
                return Err("that URL points at a private or reserved address".into());
            }
        }
        return Ok(Ind::Url(u.to_string()));
    }
    if t.contains('/') || t.contains(' ') {
        return Err("not recognised: give a bare IP, domain, http(s) URL or hash".into());
    }
    if let Ok(ip) = t.trim_matches(['[', ']']).parse::<IpAddr>() {
        return parse_public_ip(&ip.to_string()).map(Ind::Ip).map_err(|e| e.1);
    }
    if matches!(t.len(), 32 | 40 | 64) && t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(Ind::Hash(lower));
    }
    valid_domain(&t).map(Ind::Domain).ok_or_else(|| "not recognised as an IP, domain, URL or MD5/SHA-1/SHA-256 hash".into())
}

pub fn lookup(s: &AppState, q: &str) -> Result<Value, String> {
    let ind = classify(q)?;
    let text = ind.text();
    let rows: Vec<Value> = std::thread::scope(|sc| {
        let hs: Vec<_> = sources::SOURCES
            .iter()
            .map(|(id, ..)| {
                let (ind, text) = (&ind, &text);
                sc.spawn(move || {
                    // Cache key includes whether a key is set: adding a key must not be hidden by a cached "needs key" row.
                    let ck = format!("{id}|{}|{}", s.key_state(id), text);
                    if let Some(v) = s.row_cache.get(&ck) {
                        return v;
                    }
                    let r = sources::run(s, id, ind);
                    if matches!(r["status"].as_str(), Some("hit" | "clear" | "info")) {
                        s.row_cache.put(&ck, r.clone());
                    }
                    r
                })
            })
            .collect();
        hs.into_iter().filter_map(|h| h.join().ok()).collect()
    });
    Ok(json!({ "query": text, "kind": ind.kind(), "rows": rows,
               "note": "Each row is that source's own answer under its own definition. They are not combined into a score: sources disagree, and absence from a source is not proof of safety." }))
}

impl AppState {
    fn key_state(&self, id: &str) -> bool {
        sources::SOURCES.iter().find(|s| s.0 == id).and_then(|s| s.2).is_some_and(|k| self.key(k).is_some())
    }
}

#[derive(Deserialize)]
struct Q {
    q: String,
}
async fn lookup_h(State(s): State<Shared>, Query(q): Query<Q>) -> Result<Json<Value>, ApiError> {
    blocking(move || lookup(&s, &q.q)).await?.map(Json).map_err(|e| bad(&e))
}

async fn sources_h(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        let list: Vec<Value> = sources::SOURCES.iter().map(|(id, name, key, applies)| json!({ "id": id, "name": name, "key_name": key, "has_key": key.is_some_and(|k| s.key(k).is_some()), "applies_to": applies, "key_required": *id == "virustotal" || *id == "abuseipdb" })).collect();
        json!({ "sources": list, "urlscan_submit_available": s.key("URLSCAN_API_KEY").is_some() })
    })
    .await
    .map(Json)
}

#[derive(Deserialize)]
struct Submit {
    url: String,
    #[serde(default)]
    visibility: Option<String>,
    #[serde(default)]
    confirm: bool,
}
/// Opt-in: sends the URL to urlscan.io to be scanned (a third party fetches it). Needs a key and an explicit confirm.
async fn submit_h(State(s): State<Shared>, Json(b): Json<Submit>) -> Result<Json<Value>, ApiError> {
    if !b.confirm {
        return Err(bad("confirm that you want to send this URL to urlscan.io"));
    }
    let vis = match b.visibility.as_deref().unwrap_or("private") {
        v @ ("private" | "unlisted" | "public") => v.to_string(),
        _ => return Err(bad("visibility must be private, unlisted or public")),
    };
    let Ind::Url(u) = classify(&b.url).map_err(|e| bad(&e))? else { return Err(bad("only http(s) URLs can be scanned")) };
    blocking(move || {
        let key = s.key("URLSCAN_API_KEY").ok_or_else(|| (axum::http::StatusCode::BAD_REQUEST, "set URLSCAN_API_KEY on the Credentials page to enable scan submission".to_string()))?;
        let mut res = s.agent.post(&s.urlscan_scan).header("API-Key", &key).header("Accept", "application/json").send_json(json!({ "url": u, "visibility": vis })).map_err(|e| match e {
            ureq::Error::StatusCode(c) => (axum::http::StatusCode::BAD_GATEWAY, format!("urlscan refused the submission (HTTP {c})")),
            _ => (axum::http::StatusCode::BAD_GATEWAY, "urlscan request failed".to_string()),
        })?;
        let v: Value = res.body_mut().read_json().map_err(|_| (axum::http::StatusCode::BAD_GATEWAY, "urlscan returned something unexpected".to_string()))?;
        Ok::<_, (axum::http::StatusCode, String)>(json!({ "uuid": v["uuid"], "result": v["result"], "visibility": vis, "message": v["message"] }))
    })
    .await?
    .map(Json)
    .map_err(|(c, m)| ApiError(c, m))
}

async fn tools() -> Json<Value> {
    Json(json!([
        { "name": "ioc_lookup", "description": "Reputation of one indicator (IP, domain, URL, MD5/SHA-1/SHA-256) from urlscan, AlienVault OTX, GreyNoise, mnemonic passive DNS, Shodan InternetDB and, if keys are set, VirusTotal and AbuseIPDB. One verdict row per source; no combined score. Never submits anything to be scanned.",
          "method": "GET", "path": "api/lookup", "parameters": { "type": "object", "properties": { "q": { "type": "string", "description": "indicator (defanged input is accepted)" } }, "required": ["q"] } }
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

pub fn app(state: Shared) -> Router {
    let api = Router::new()
        .route("/api/lookup", get(lookup_h))
        .route("/api/sources", get(sources_h))
        .route("/api/urlscan/submit", post(submit_h))
        .route_layer(middleware::from_fn_with_state(state.authz, require_gateway));
    Router::new().route("/", get(page)).route("/tools", get(tools)).merge(api).with_state(state)
}

#[tokio::main]
async fn main() -> Result<()> {
    let agent = osnt_common::http_agent("osnt-ioc-lookup/0.1 (+https://github.com/ogden-marrow/osnt-hub)");
    let keys: Box<dyn Fn(&str) -> Option<String> + Send + Sync> = Box::new(|n| osnt_common::secret(n));
    let state: Shared = Arc::new(AppState::new(agent, keys, real_authz));
    let addr: SocketAddr = env::var("OSNT_IOC_LOOKUP_BIND").unwrap_or_else(|_| "127.0.0.1:8136".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("ioc-lookup plugin on http://{addr}");
    axum::serve(listener, app(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests;

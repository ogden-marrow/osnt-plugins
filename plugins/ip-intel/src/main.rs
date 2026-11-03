//! IP intelligence plugin: one IP (or a hostname) gives ownership, routing, exposure, geolocation cross-check and
//! blocklist membership from open, keyless sources. Upstream hosts are fixed; callers only supply the target.

#[allow(dead_code)]
mod cache;
mod intel;
#[allow(dead_code)]
mod ipx;
#[allow(dead_code)]
mod net;

use std::{env, net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, Method, Uri},
    response::Html,
    routing::get,
};
use serde::Deserialize;
use serde_json::{Value, json};

use intel::{App, Target};
use net::{ApiError, authorized, bad, blocking};

const PAGE: &str = include_str!("../assets/index.html");
const UA: &str = "osnt-ip-intel/0.1 (+https://github.com/ogden-marrow/osnt-hub)";
type Shared = Arc<App>;

#[derive(Deserialize)]
struct Q {
    q: Option<String>,
    ip: Option<String>,
}

async fn overview(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Query(q): Query<Q>) -> Result<Json<Value>, ApiError> {
    authorized(&method, &uri, &headers)?;
    let input = q.q.or(q.ip).unwrap_or_default();
    let target = intel::parse_target(&input).map_err(|e| bad(&e))?;
    Ok(Json(
        blocking(move || {
            let (ip, host) = match target {
                Target::Ip(ip) => (ip, None),
                Target::Host(h) => {
                    let ips = intel::resolve(&s, &h)?;
                    (ips[0], Some((h, ips)))
                }
            };
            let key = match (osnt_common::secret("CENSYS_API_ID"), osnt_common::secret("CENSYS_API_SECRET")) {
                (Some(i), Some(sec)) if !i.is_empty() && !sec.is_empty() => Some((i, sec)),
                _ => None,
            };
            Ok(intel::overview(&s, ip, host, key))
        })
        .await?,
    ))
}

async fn exposure(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Query(q): Query<Q>) -> Result<Json<Value>, ApiError> {
    authorized(&method, &uri, &headers)?;
    let ip = intel::parse_ip(&q.ip.or(q.q).unwrap_or_default()).map_err(|e| bad(&e))?;
    Ok(Json(blocking(move || intel::exposure(&s, &ip.to_string()).map(|v| json!({ "ip": ip.to_string(), "exposure": v, "source": "Shodan InternetDB (internetdb.shodan.io)" }))).await?))
}

async fn lists(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Query(q): Query<Q>) -> Result<Json<Value>, ApiError> {
    authorized(&method, &uri, &headers)?;
    let ip = intel::parse_ip(&q.ip.or(q.q).unwrap_or_default()).map_err(|e| bad(&e))?;
    Ok(Json(blocking(move || intel::lists(&s, ip).map(|v| json!({ "ip": ip.to_string(), "lists": v }))).await?))
}

async fn tools() -> Json<Value> {
    Json(json!([
        { "name": "ip_overview", "description": "Overview of a public IP or hostname: owning organisation and ASN, announced prefix, abuse role contact, exposed ports and CVE ids (Shodan InternetDB), geolocation from three sources with a disagreement distance, Tor exit and Spamhaus DROP membership, Robtex route name. Passive, open sources only.",
          "method": "GET", "path": "api/overview", "parameters": { "type": "object", "properties": { "q": { "type": "string", "description": "public IPv4/IPv6 address or hostname" } }, "required": ["q"] } },
        { "name": "ip_exposure", "description": "Open ports, CPEs, hostnames, tags and CVE ids that Shodan InternetDB has seen for a public IP (no active scanning is done).",
          "method": "GET", "path": "api/exposure", "parameters": { "type": "object", "properties": { "ip": { "type": "string", "description": "public IP address" } }, "required": ["ip"] } },
        { "name": "ip_lists", "description": "Is this public IP a Tor exit node or inside a Spamhaus DROP netblock? Returns list freshness too.",
          "method": "GET", "path": "api/lists", "parameters": { "type": "object", "properties": { "ip": { "type": "string", "description": "public IP address" } }, "required": ["ip"] } }
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

#[tokio::main]
async fn main() -> Result<()> {
    let db = env::var("OSNT_IP_INTEL_DB").ok().filter(|p| !p.starts_with('{') && !p.is_empty()).map(PathBuf::from);
    let app: Shared = Arc::new(App { http: net::Http::new(UA), cache: cache::Cache::open(db.as_deref(), 200, 512 * 1024), up: intel::Up::default() });
    let router = Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/overview", get(overview))
        .route("/api/exposure", get(exposure))
        .route("/api/lists", get(lists))
        .with_state(app);
    let addr: SocketAddr = env::var("OSNT_IP_INTEL_BIND").unwrap_or_else(|_| "127.0.0.1:8130".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("ip-intel plugin on http://{addr}");
    axum::serve(listener, router).await?;
    Ok(())
}

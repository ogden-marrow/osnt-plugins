//! Passive subdomain discovery. Sources are queried one at a time by the page (so each shows its own progress) or all
//! at once for agents. No brute forcing, no zone transfers; upstream hosts are fixed.

#[allow(dead_code)]
mod cache;
#[allow(dead_code)]
mod ipx;
#[allow(dead_code)]
mod net;
mod subs;

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

use net::{ApiError, authorized, bad, blocking};
use subs::{App, Keys, SOURCES};

const PAGE: &str = include_str!("../assets/index.html");
const UA: &str = "osnt-subdomain-enum/0.1 (+https://github.com/ogden-marrow/osnt-hub)";
type Shared = Arc<App>;

#[derive(Deserialize, Default)]
struct Q {
    domain: Option<String>,
    source: Option<String>,
    sources: Option<String>,
    names: Option<String>,
}

fn keys() -> Keys {
    let get = |n: &str| osnt_common::secret(n).filter(|k| !k.is_empty());
    Keys { certspotter: get("CERTSPOTTER_API_KEY"), virustotal: get("VIRUSTOTAL_API_KEY"), otx: get("OTX_API_KEY") }
}

fn domain(q: &Q) -> Result<String, ApiError> {
    net::host_from_input(q.domain.as_deref().unwrap_or("")).ok_or_else(|| bad("enter a domain name such as example.com"))
}

async fn sources(State(_s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    authorized(&method, &uri, &headers)?;
    let k = blocking(|| Ok(keys())).await?;
    let has = |id: &str| match id { "certspotter" => k.certspotter.is_some(), "virustotal" => k.virustotal.is_some(), "otx" => k.otx.is_some(), _ => false };
    Ok(Json(json!(SOURCES.iter().map(|s| json!({
        "id": s.id, "name": s.name, "default": s.default, "note": s.note,
        "needs_key": s.key_required, "key_name": s.key, "key_set": s.key.map(|_| has(s.id)),
        "available": !s.key_required || has(s.id),
    })).collect::<Vec<_>>())))
}

async fn source(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Query(q): Query<Q>) -> Result<Json<Value>, ApiError> {
    authorized(&method, &uri, &headers)?;
    let d = domain(&q)?;
    let id = q.source.unwrap_or_default();
    if !SOURCES.iter().any(|x| x.id == id) {
        return Err(bad("unknown source"));
    }
    Ok(Json(blocking(move || subs::source(&s, &d, &id, &keys())).await?))
}

async fn find(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Query(q): Query<Q>) -> Result<Json<Value>, ApiError> {
    authorized(&method, &uri, &headers)?;
    let d = domain(&q)?;
    let ids: Vec<String> = match q.sources.as_deref().filter(|s| !s.is_empty()) {
        Some(list) => list.split(',').map(str::trim).map(str::to_owned).collect(),
        None => SOURCES.iter().filter(|x| x.default).map(|x| x.id.to_string()).collect(),
    };
    if ids.iter().any(|i| !SOURCES.iter().any(|x| x.id == i)) {
        return Err(bad("unknown source in the list"));
    }
    Ok(Json(blocking(move || subs::find(&s, &d, &ids, &keys())).await?))
}

async fn resolve(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Query(q): Query<Q>) -> Result<Json<Value>, ApiError> {
    authorized(&method, &uri, &headers)?;
    let d = domain(&q)?;
    let names: Vec<String> = q.names.as_deref().unwrap_or("").split(',').map(str::trim).filter(|x| !x.is_empty()).map(str::to_owned).collect();
    if names.is_empty() || names.len() > 40 {
        return Err(bad("give 1 to 40 comma-separated hostnames under the domain"));
    }
    blocking(move || subs::resolve(&s, &d, &names)).await.map(Json).map_err(|e| if e.0 == axum::http::StatusCode::BAD_GATEWAY { bad(&e.1) } else { e })
}

async fn tools() -> Json<Value> {
    Json(json!([
        { "name": "subdomains_find", "description": "Passive subdomain discovery for a domain: merges certificate transparency (Certspotter, crt.sh), passive DNS (mnemonic), urlscan.io and Wayback hosts; each name lists the sources that saw it. Can take up to a minute. Passive only.",
          "method": "GET", "path": "api/find", "parameters": { "type": "object", "properties": { "domain": { "type": "string" }, "sources": { "type": "string", "description": "optional comma list: certspotter,crtsh,mnemonic,urlscan,wayback,hackertarget,otx,virustotal" } }, "required": ["domain"] } },
        { "name": "subdomains_resolve", "description": "Resolve up to 40 hostnames under a domain over DNS-over-HTTPS and mark each live, dead, or a dangling CNAME (with a takeover-provider hint); also reports wildcard DNS.",
          "method": "GET", "path": "api/resolve", "parameters": { "type": "object", "properties": { "domain": { "type": "string" }, "names": { "type": "string", "description": "comma-separated hostnames under the domain" } }, "required": ["domain", "names"] } }
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

#[tokio::main]
async fn main() -> Result<()> {
    let db = env::var("OSNT_SUBDOMAIN_ENUM_DB").ok().filter(|p| !p.starts_with('{') && !p.is_empty()).map(PathBuf::from);
    let app: Shared = Arc::new(App { http: net::Http::new(UA), cache: cache::Cache::open(db.as_deref(), 300, 512 * 1024), up: subs::Up::default() });
    let router = Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/sources", get(sources))
        .route("/api/source", get(source))
        .route("/api/find", get(find))
        .route("/api/resolve", get(resolve))
        .with_state(app);
    let addr: SocketAddr = env::var("OSNT_SUBDOMAIN_ENUM_BIND").unwrap_or_else(|_| "127.0.0.1:8132".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("subdomain-enum plugin on http://{addr}");
    axum::serve(listener, router).await?;
    Ok(())
}

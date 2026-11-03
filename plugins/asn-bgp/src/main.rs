//! ASN and BGP explorer: RIPEstat, PeeringDB and RIPE Atlas on demand. Upstream hosts are fixed; callers supply
//! only an AS number, a public prefix/IP or a country code.

#[allow(dead_code)]
mod bgp;
#[allow(dead_code)]
mod cache;
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

use bgp::App;
use net::{ApiError, authorized, bad, blocking};

const PAGE: &str = include_str!("../assets/index.html");
const UA: &str = "osnt-asn-bgp/0.1 (+https://github.com/ogden-marrow/osnt-hub)";
type Shared = Arc<App>;

#[derive(Deserialize, Default)]
struct Q {
    q: Option<String>,
    asn: Option<String>,
    prefix: Option<String>,
    years: Option<u32>,
    asns: Option<String>,
    country: Option<String>,
}

fn need_asn(q: &Q) -> Result<u32, ApiError> {
    bgp::parse_asn(q.asn.as_deref().or(q.q.as_deref()).unwrap_or("")).ok_or_else(|| bad("enter an AS number such as AS15169"))
}
fn need_prefix(q: &Q) -> Result<String, ApiError> {
    bgp::parse_prefix(q.prefix.as_deref().or(q.q.as_deref()).unwrap_or("")).ok_or_else(|| bad("enter a public IP address or prefix such as 193.0.0.0/21"))
}

macro_rules! route {
    ($name:ident, |$s:ident, $q:ident| $body:expr) => {
        async fn $name(State($s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Query($q): Query<Q>) -> Result<Json<Value>, ApiError> {
            authorized(&method, &uri, &headers)?;
            $body
        }
    };
}

route!(resolve, |s, q| {
    let input = q.q.clone().or(q.asn.clone()).unwrap_or_default();
    if bgp::parse_asn(&input).is_none() && bgp::parse_prefix(&input).is_none() {
        return Err(bad("enter an AS number (AS15169), an IP address or a prefix (193.0.0.0/21)"));
    }
    Ok(Json(blocking(move || bgp::resolve(&s, &input)).await?))
});
route!(overview, |s, q| {
    let input = q.q.clone().or(q.asn.clone()).unwrap_or_default();
    if bgp::parse_asn(&input).is_none() && bgp::parse_prefix(&input).is_none() {
        return Err(bad("enter an AS number (AS15169), an IP address or a prefix (193.0.0.0/21)"));
    }
    Ok(Json(blocking(move || {
        let r = bgp::resolve(&s, &input)?;
        let asn = r["asn"].as_u64().unwrap_or(0) as u32;
        let mut o = bgp::overview(&s, asn)?;
        o["resolved"] = r;
        Ok(o)
    }).await?))
});
route!(prefixes, |s, q| {
    let asn = need_asn(&q)?;
    Ok(Json(blocking(move || bgp::prefixes(&s, asn)).await?))
});
route!(neighbours, |s, q| {
    let asn = need_asn(&q)?;
    Ok(Json(blocking(move || bgp::neighbours(&s, asn)).await?))
});
route!(names, |s, q| {
    let list: Vec<u32> = q.asns.as_deref().unwrap_or("").split(',').filter_map(bgp::parse_asn).take(25).collect();
    if list.is_empty() {
        return Err(bad("asns must be a comma-separated list of AS numbers"));
    }
    Ok(Json(blocking(move || Ok(bgp::names(&s, &list))).await?))
});
route!(history, |s, q| {
    let p = need_prefix(&q)?;
    let years = q.years.unwrap_or(3).clamp(1, 25);
    Ok(Json(blocking(move || bgp::history(&s, &p, years)).await?))
});
route!(state, |s, q| {
    let p = need_prefix(&q)?;
    Ok(Json(blocking(move || bgp::bgp_state(&s, &p)).await?))
});
route!(peeringdb, |s, q| {
    let asn = need_asn(&q)?;
    Ok(Json(blocking(move || {
        let key = osnt_common::secret("PEERINGDB_API_KEY").filter(|k| !k.is_empty());
        bgp::peeringdb(&s, asn, key)
    }).await?))
});
route!(atlas, |s, q| {
    let country = q.country.as_deref().map(|c| bgp::parse_country(c).ok_or_else(|| bad("country must be a two-letter code such as NL"))).transpose()?;
    let asn = if country.is_some() { None } else { Some(need_asn(&q)?) };
    Ok(Json(blocking(move || bgp::atlas(&s, asn, country.as_deref())).await?))
});

async fn tools() -> Json<Value> {
    let p = |k: &str, d: &str| json!({ "type": "object", "properties": { k: { "type": "string", "description": d } }, "required": [k] });
    Json(json!([
        { "name": "asn_overview", "description": "Holder name, announced status and registry block of an AS. Input may be an AS number, an IP or a prefix (resolved to its origin AS).", "method": "GET", "path": "api/overview", "parameters": p("q", "AS number (AS15169), IP address or prefix") },
        { "name": "asn_prefixes", "description": "Prefixes currently announced by an AS (with first and last time seen), IPv4 first.", "method": "GET", "path": "api/prefixes", "parameters": p("asn", "AS number") },
        { "name": "asn_neighbours", "description": "Upstream, downstream and uncertain BGP neighbours of an AS ranked by path power (RIPEstat).", "method": "GET", "path": "api/neighbours", "parameters": p("asn", "AS number") },
        { "name": "prefix_history", "description": "Routing history of a prefix: which origin ASes announced it and when (origin changes are how re-homing and hijack stories show up; a lead, not proof).",
          "method": "GET", "path": "api/history", "parameters": { "type": "object", "properties": { "prefix": { "type": "string", "description": "public prefix or IP" }, "years": { "type": "integer", "description": "years of history, 1-25, default 3" } }, "required": ["prefix"] } },
        { "name": "prefix_bgp_state", "description": "Current BGP view of a prefix across RIPE RIS peers: origins, last hops and sample AS paths.", "method": "GET", "path": "api/state", "parameters": p("prefix", "public prefix or IP") },
        { "name": "asn_peeringdb", "description": "PeeringDB network record for an AS: policy, type, exchange points and facilities. No contact data.", "method": "GET", "path": "api/peeringdb", "parameters": p("asn", "AS number") },
        { "name": "atlas_probes", "description": "Count of connected RIPE Atlas probes and anchors for an AS or a country (counts only).", "method": "GET", "path": "api/atlas",
          "parameters": { "type": "object", "properties": { "asn": { "type": "string" }, "country": { "type": "string", "description": "two-letter country code (use instead of asn)" } } } }
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

#[tokio::main]
async fn main() -> Result<()> {
    let db = env::var("OSNT_ASN_BGP_DB").ok().filter(|p| !p.starts_with('{') && !p.is_empty()).map(PathBuf::from);
    let app: Shared = Arc::new(App { http: net::Http::new(UA), cache: cache::Cache::open(db.as_deref(), 120, 768 * 1024), up: bgp::Up::default() });
    let router = Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/resolve", get(resolve))
        .route("/api/overview", get(overview))
        .route("/api/prefixes", get(prefixes))
        .route("/api/neighbours", get(neighbours))
        .route("/api/names", get(names))
        .route("/api/history", get(history))
        .route("/api/state", get(state))
        .route("/api/peeringdb", get(peeringdb))
        .route("/api/atlas", get(atlas))
        .with_state(app);
    let addr: SocketAddr = env::var("OSNT_ASN_BGP_BIND").unwrap_or_else(|_| "127.0.0.1:8131".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("asn-bgp plugin on http://{addr}");
    axum::serve(listener, router).await?;
    Ok(())
}

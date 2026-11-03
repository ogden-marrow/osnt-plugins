//! Domain hygiene: DNS records, mail policy (SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI), DNSSEC, delegation sanity and
//! web policy files, as a scored checklist. DNS goes to dns.google; the few well-known files on the domain itself are
//! fetched through the SSRF guard. Passive and read-only.

#[allow(dead_code)]
mod cache;
mod hygiene;
#[allow(dead_code)]
mod ipx;
#[allow(dead_code)]
mod net;
#[allow(dead_code)]
mod ssrf;

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

use hygiene::{App, TYPES};
use net::{ApiError, authorized, bad, blocking, valid_found_name};

const PAGE: &str = include_str!("../assets/index.html");
const UA: &str = "osnt-domain-hygiene/0.1 (+https://github.com/ogden-marrow/osnt-hub)";
type Shared = Arc<App>;

#[derive(Deserialize, Default)]
struct Q {
    domain: Option<String>,
    name: Option<String>,
    types: Option<String>,
    section: Option<String>,
}

fn domain(q: &Q) -> Result<String, ApiError> {
    net::host_from_input(q.domain.as_deref().unwrap_or("")).ok_or_else(|| bad("enter a domain name such as example.com"))
}

async fn check(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Query(q): Query<Q>) -> Result<Json<Value>, ApiError> {
    authorized(&method, &uri, &headers)?;
    let d = domain(&q)?;
    Ok(Json(blocking(move || Ok(hygiene::run_all(&s, &d))).await?))
}

/// One group of checks, so the page can show them as each finishes.
async fn section(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Query(q): Query<Q>) -> Result<Json<Value>, ApiError> {
    authorized(&method, &uri, &headers)?;
    let d = domain(&q)?;
    let which = q.section.clone().unwrap_or_default();
    if !["mail", "dnssec", "dns", "web"].contains(&which.as_str()) {
        return Err(bad("section must be mail, dnssec, dns or web"));
    }
    Ok(Json(blocking(move || {
        let checks = match which.as_str() {
            "mail" => hygiene::mail(&s, &d),
            "dnssec" => hygiene::dnssec(&s, &d),
            "dns" => hygiene::dns_health(&s, &d),
            _ => hygiene::web(&s, &d, cache::now_secs() as i64),
        };
        Ok(json!({ "domain": d, "section": which, "checks": checks }))
    }).await?))
}

async fn mail(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Query(q): Query<Q>) -> Result<Json<Value>, ApiError> {
    authorized(&method, &uri, &headers)?;
    let d = domain(&q)?;
    Ok(Json(blocking(move || { let c = hygiene::mail(&s, &d); Ok(json!({ "domain": d, "summary": hygiene::score(&c), "checks": c })) }).await?))
}

async fn dnssec(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Query(q): Query<Q>) -> Result<Json<Value>, ApiError> {
    authorized(&method, &uri, &headers)?;
    let d = domain(&q)?;
    Ok(Json(blocking(move || { let c = hygiene::dnssec(&s, &d); Ok(json!({ "domain": d, "summary": hygiene::score(&c), "checks": c })) }).await?))
}

async fn records(State(s): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, Query(q): Query<Q>) -> Result<Json<Value>, ApiError> {
    authorized(&method, &uri, &headers)?;
    let name = valid_found_name(q.name.as_deref().or(q.domain.as_deref()).unwrap_or("")).ok_or_else(|| bad("enter a valid DNS name such as example.com"))?;
    let types: Vec<String> = match q.types.as_deref().filter(|t| !t.is_empty()) {
        Some(t) => t.split(',').map(|x| x.trim().to_ascii_uppercase()).collect(),
        None => ["A", "AAAA", "NS", "MX", "TXT", "SOA", "CAA", "CNAME"].map(String::from).to_vec(),
    };
    if types.is_empty() || types.len() > 12 || types.iter().any(|t| !TYPES.contains(&t.as_str())) {
        return Err(bad(&format!("types must be a comma list of: {}", TYPES.join(", "))));
    }
    Ok(Json(blocking(move || hygiene::records(&s, &name, &types)).await?))
}

async fn tools() -> Json<Value> {
    let dom = json!({ "type": "object", "properties": { "domain": { "type": "string", "description": "domain name, e.g. example.com" } }, "required": ["domain"] });
    Json(json!([
        { "name": "domain_records", "description": "DNS records of a name over DNS-over-HTTPS (dns.google): A, AAAA, NS, MX, TXT, SOA, CAA, CNAME, DS, DNSKEY, HTTPS, SRV, with the DNSSEC authenticated-data flag.",
          "method": "GET", "path": "api/records", "parameters": { "type": "object", "properties": { "name": { "type": "string" }, "types": { "type": "string", "description": "optional comma list of record types" } }, "required": ["name"] } },
        { "name": "domain_mail_policy", "description": "Mail authentication checklist for a domain: MX, SPF (include tree and lookup count), DMARC, DKIM at common selectors, MTA-STS, TLS-RPT, BIMI, with pass/warn/fail and a score. Mailbox names are masked.",
          "method": "GET", "path": "api/mail", "parameters": dom },
        { "name": "domain_dnssec", "description": "DNSSEC state of a domain: DS and DNSKEY records, algorithms and whether the validating resolver set the AD flag.",
          "method": "GET", "path": "api/dnssec", "parameters": dom },
        { "name": "domain_check", "description": "Full scored hygiene checklist: mail policy, DNSSEC, name-server delegation, wildcard DNS, CAA, security.txt and robots/sitemap files.",
          "method": "GET", "path": "api/check", "parameters": dom }
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

#[tokio::main]
async fn main() -> Result<()> {
    let db = env::var("OSNT_DOMAIN_HYGIENE_DB").ok().filter(|p| !p.starts_with('{') && !p.is_empty()).map(PathBuf::from);
    let guard = ssrf::Guard::default();
    let app: Shared = Arc::new(App { http: net::Http::new(UA), web: ssrf::guarded_agent(guard.clone(), UA), guard, cache: cache::Cache::open(db.as_deref(), 400, 256 * 1024), up: hygiene::Up::default() });
    let router = Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/check", get(check))
        .route("/api/section", get(section))
        .route("/api/mail", get(mail))
        .route("/api/dnssec", get(dnssec))
        .route("/api/records", get(records))
        .with_state(app);
    let addr: SocketAddr = env::var("OSNT_DOMAIN_HYGIENE_BIND").unwrap_or_else(|_| "127.0.0.1:8133".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("domain-hygiene plugin on http://{addr}");
    axum::serve(listener, router).await?;
    Ok(())
}

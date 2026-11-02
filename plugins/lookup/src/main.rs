//! Domain & IP lookup plugin: DNS over HTTPS, RDAP registration data and certificate-transparency names.
//! Inputs are validated strictly and upstream hosts are fixed, so callers cannot steer requests elsewhere.

use std::{
    collections::BTreeSet,
    env,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use serde_json::{Value, json};

const PAGE: &str = include_str!("../assets/index.html");
const RECORD_TYPES: [&str; 8] = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"];

struct AppState {
    agent: ureq::Agent,
}
type Shared = Arc<AppState>;

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError(StatusCode::BAD_GATEWAY, format!("{e:#}"))
    }
}
fn bad(msg: &str) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

/// A hostname: letters, digits, dots and hyphens only, with at least one dot.
fn valid_domain(s: &str) -> Option<String> {
    let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
    let ok = s.len() <= 253
        && s.contains('.')
        && s.split('.').all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    ok.then_some(s)
}

fn get_json(agent: &ureq::Agent, url: &str, accept: &str) -> Result<Value> {
    let mut res = agent.get(url).header("Accept", accept).call().with_context(|| format!("GET {url}"))?;
    res.body_mut().read_json().context("decode response")
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f).await.map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?.map_err(Into::into)
}

#[derive(Deserialize)]
struct DnsQuery {
    name: String,
    #[serde(default = "default_type", rename = "type")]
    rtype: String,
}
fn default_type() -> String {
    "A".into()
}

fn dns(agent: &ureq::Agent, name: &str, rtype: &str) -> Result<Value> {
    let v = get_json(agent, &format!("https://cloudflare-dns.com/dns-query?name={name}&type={rtype}"), "application/dns-json")?;
    let answers: Vec<Value> = v["Answer"]
        .as_array()
        .map(|a| a.iter().map(|r| json!({ "name": r["name"], "type": r["type"], "ttl": r["TTL"], "data": r["data"] })).collect())
        .unwrap_or_default();
    Ok(json!({ "status": v["Status"], "answers": answers }))
}

async fn dns_handler(State(s): State<Shared>, Query(q): Query<DnsQuery>) -> Result<Json<Value>, ApiError> {
    let name = valid_domain(&q.name).ok_or_else(|| bad("invalid domain name"))?;
    let rtype = q.rtype.to_ascii_uppercase();
    if !RECORD_TYPES.contains(&rtype.as_str()) {
        return Err(bad("record type must be one of A, AAAA, MX, NS, TXT, CNAME, SOA, CAA"));
    }
    Ok(Json(blocking(move || dns(&s.agent, &name, &rtype)).await?))
}

fn ptr_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let nibbles: String = v6.octets().iter().flat_map(|b| [b >> 4, b & 0xf]).rev().map(|n| format!("{n:x}.")).collect();
            format!("{nibbles}ip6.arpa")
        }
    }
}

/// RDAP via the IANA-bootstrap redirector; keeps only the fields that matter for triage.
fn rdap(agent: &ureq::Agent, kind: &str, target: &str) -> Result<Value> {
    let v = get_json(agent, &format!("https://rdap.org/{kind}/{target}"), "application/rdap+json, application/json")?;
    let events: Vec<Value> = v["events"].as_array().map(|e| e.iter().map(|x| json!({ "action": x["eventAction"], "date": x["eventDate"] })).collect()).unwrap_or_default();
    let entities: Vec<Value> = v["entities"]
        .as_array()
        .map(|e| e.iter().map(|x| json!({ "handle": x["handle"], "roles": x["roles"], "name": x["vcardArray"][1].as_array().and_then(|f| f.iter().find(|p| p[0] == "fn")).map(|p| p[3].clone()) })).collect())
        .unwrap_or_default();
    Ok(json!({
        "handle": v["handle"], "name": v["name"], "status": v["status"], "events": events, "entities": entities,
        "nameservers": v["nameservers"].as_array().map(|n| n.iter().map(|x| x["ldhName"].clone()).collect::<Vec<_>>()),
        "country": v["country"], "cidr": v["cidr0_cidrs"], "start": v["startAddress"], "end": v["endAddress"], "type": v["type"],
    }))
}

#[derive(Deserialize)]
struct NameQuery {
    name: String,
}
#[derive(Deserialize)]
struct IpQuery {
    ip: String,
}

async fn rdap_domain(State(s): State<Shared>, Query(q): Query<NameQuery>) -> Result<Json<Value>, ApiError> {
    let name = valid_domain(&q.name).ok_or_else(|| bad("invalid domain name"))?;
    Ok(Json(blocking(move || rdap(&s.agent, "domain", &name)).await?))
}

async fn rdap_ip(State(s): State<Shared>, Query(q): Query<IpQuery>) -> Result<Json<Value>, ApiError> {
    let ip: IpAddr = q.ip.trim().parse().map_err(|_| bad("invalid IP address"))?;
    Ok(Json(blocking(move || rdap(&s.agent, "ip", &ip.to_string())).await?))
}

async fn rdns(State(s): State<Shared>, Query(q): Query<IpQuery>) -> Result<Json<Value>, ApiError> {
    let ip: IpAddr = q.ip.trim().parse().map_err(|_| bad("invalid IP address"))?;
    Ok(Json(blocking(move || {
        let v = get_json(&s.agent, &format!("https://cloudflare-dns.com/dns-query?name={}&type=PTR", ptr_name(ip)), "application/dns-json")?;
        let names: Vec<Value> = v["Answer"].as_array().map(|a| a.iter().map(|r| r["data"].clone()).collect()).unwrap_or_default();
        Ok(json!({ "ip": ip.to_string(), "ptr": names }))
    }).await?))
}

/// Names seen in public certificates (crt.sh certificate transparency search). Slow and sometimes flaky.
async fn certs(State(s): State<Shared>, Query(q): Query<NameQuery>) -> Result<Json<Value>, ApiError> {
    let name = valid_domain(&q.name).ok_or_else(|| bad("invalid domain name"))?;
    Ok(Json(blocking(move || {
        let v = get_json(&s.agent, &format!("https://crt.sh/?q=%25.{name}&output=json"), "application/json")?;
        let mut names = BTreeSet::new();
        let mut first = String::new();
        let mut count = 0;
        for row in v.as_array().map(Vec::as_slice).unwrap_or_default() {
            count += 1;
            if let Some(n) = row["name_value"].as_str() {
                names.extend(n.lines().map(|l| l.trim().to_ascii_lowercase()));
            }
            if let Some(d) = row["not_before"].as_str() {
                if first.is_empty() || d < first.as_str() {
                    first = d.to_string();
                }
            }
        }
        Ok(json!({ "domain": name, "certificates": count, "earliest_seen": first, "names": names }))
    }).await?))
}

/// One call for the common case: classify the input as IP or domain and gather the basics.
async fn lookup(State(s): State<Shared>, Query(q): Query<QueryParam>) -> Result<Json<Value>, ApiError> {
    let input = q.q.trim().to_string();
    if let Ok(ip) = input.parse::<IpAddr>() {
        let (a, b) = (s.clone(), s.clone());
        let ip_s = ip.to_string();
        let (r, p) = tokio::join!(
            blocking(move || rdap(&a.agent, "ip", &ip_s)),
            blocking(move || {
                let v = get_json(&b.agent, &format!("https://cloudflare-dns.com/dns-query?name={}&type=PTR", ptr_name(ip)), "application/dns-json")?;
                Ok(v["Answer"].as_array().map(|a| a.iter().map(|r| r["data"].clone()).collect::<Vec<_>>()).unwrap_or_default())
            })
        );
        return Ok(Json(json!({ "kind": "ip", "input": input, "rdap": r.ok(), "ptr": p.ok() })));
    }
    let name = valid_domain(&input).ok_or_else(|| bad("enter a domain (example.com) or an IP address"))?;
    let (a, b) = (s.clone(), s.clone());
    let (n1, n2) = (name.clone(), name.clone());
    let (records, reg) = tokio::join!(
        blocking(move || {
            let mut out = serde_json::Map::new();
            for t in ["A", "AAAA", "MX", "NS", "TXT"] {
                out.insert(t.into(), dns(&a.agent, &n1, t)?["answers"].clone());
            }
            Ok(Value::Object(out))
        }),
        blocking(move || rdap(&b.agent, "domain", &n2))
    );
    Ok(Json(json!({ "kind": "domain", "input": name, "dns": records.ok(), "rdap": reg.ok() })))
}

#[derive(Deserialize)]
struct QueryParam {
    q: String,
}

async fn tools() -> Json<Value> {
    let q = |k: &str, d: &str| json!({ k: { "type": "string", "description": d } });
    Json(json!([
        { "name": "lookup_overview", "description": "Classify a domain or IP and return DNS records, registration (RDAP) and reverse DNS in one call.",
          "method": "GET", "path": "api/lookup", "parameters": { "type": "object", "properties": q("q", "domain or IP"), "required": ["q"] } },
        { "name": "lookup_dns", "description": "DNS records for a domain (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA).",
          "method": "GET", "path": "api/dns", "parameters": { "type": "object", "properties": { "name": { "type": "string" }, "type": { "type": "string" } }, "required": ["name"] } },
        { "name": "lookup_rdap_domain", "description": "Domain registration data: registrar, creation/expiry dates, nameservers.",
          "method": "GET", "path": "api/rdap/domain", "parameters": { "type": "object", "properties": q("name", "domain"), "required": ["name"] } },
        { "name": "lookup_rdap_ip", "description": "IP allocation data: owning organisation, CIDR range, country.",
          "method": "GET", "path": "api/rdap/ip", "parameters": { "type": "object", "properties": q("ip", "IP address"), "required": ["ip"] } },
        { "name": "lookup_certs", "description": "Hostnames seen in public TLS certificates for a domain (certificate transparency).",
          "method": "GET", "path": "api/certs", "parameters": { "type": "object", "properties": q("name", "domain"), "required": ["name"] } }
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

#[tokio::main]
async fn main() -> Result<()> {
    let state: Shared = Arc::new(AppState { agent: osnt_common::http_agent("osnt-lookup/0.1 (personal OSINT dashboard)") });
    let app = Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/lookup", get(lookup))
        .route("/api/dns", get(dns_handler))
        .route("/api/rdap/domain", get(rdap_domain))
        .route("/api/rdap/ip", get(rdap_ip))
        .route("/api/rdns", get(rdns))
        .route("/api/certs", get(certs))
        .with_state(state);
    let addr: SocketAddr = env::var("OSNT_LOOKUP_BIND").unwrap_or_else(|_| "127.0.0.1:8103".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("lookup plugin on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

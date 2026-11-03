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

fn type_name(code: u64) -> String {
    match code {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        257 => "CAA".into(),
        n => n.to_string(),
    }
}

/// Reduce a DNS-over-HTTPS JSON answer to the fields that matter. `status` is the RCODE name (NOERROR, NXDOMAIN, ...).
fn summarize_dns(v: &Value) -> Value {
    let mut answers: Vec<Value> = v["Answer"]
        .as_array()
        .map(|a| a.iter().map(|r| json!({ "name": r["name"], "type": r["type"].as_u64().map(type_name), "ttl": r["TTL"], "data": r["data"] })).collect())
        .unwrap_or_default();
    // MX records are most useful in priority order ("10 mail.example.com").
    answers.sort_by_key(|r| {
        if r["type"] == "MX" { r["data"].as_str().and_then(|d| d.split_whitespace().next()).and_then(|n| n.parse::<u32>().ok()).unwrap_or(u32::MAX) } else { 0 }
    });
    let status = match v["Status"].as_u64() {
        Some(0) => "NOERROR".to_string(),
        Some(2) => "SERVFAIL".to_string(),
        Some(3) => "NXDOMAIN".to_string(),
        Some(5) => "REFUSED".to_string(),
        Some(n) => format!("RCODE {n}"),
        None => "UNKNOWN".to_string(),
    };
    json!({ "status": status, "answers": answers })
}

fn dns(agent: &ureq::Agent, name: &str, rtype: &str) -> Result<Value> {
    let v = get_json(agent, &format!("https://cloudflare-dns.com/dns-query?name={name}&type={rtype}"), "application/dns-json")?;
    Ok(summarize_dns(&v))
}

/// Accept what people paste: a URL, host:port, or a bare name. Returns the host part, trimmed.
fn normalize_input(s: &str) -> String {
    let mut s = s.trim();
    if let Some((_, rest)) = s.split_once("://") {
        s = rest;
    }
    s = s.split(['/', '?', '#']).next().unwrap_or(s);
    if let Some((_, host)) = s.rsplit_once('@') {
        s = host;
    }
    // Strip a :port from a name or IPv4 literal, but leave IPv6 literals (several colons) alone.
    if s.matches(':').count() == 1 {
        s = s.split(':').next().unwrap_or(s);
    }
    s.trim_matches(['[', ']']).trim().to_string()
}

const MAX_CERT_NAMES: usize = 3000;

/// Reduce crt.sh rows to a sorted, de-duplicated name list.
fn summarize_certs(name: &str, v: &Value) -> Value {
    let mut names = BTreeSet::new();
    let (mut first, mut last) = (String::new(), String::new());
    let mut count = 0;
    for row in v.as_array().map(Vec::as_slice).unwrap_or_default() {
        count += 1;
        if let Some(n) = row["name_value"].as_str() {
            names.extend(n.lines().map(|l| l.trim().to_ascii_lowercase()).filter(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '*' | '_'))));
        }
        if let Some(d) = row["not_before"].as_str() {
            if first.is_empty() || d < first.as_str() {
                first = d.to_string();
            }
            if d > last.as_str() {
                last = d.to_string();
            }
        }
    }
    let total = names.len();
    let wildcards = names.iter().filter(|n| n.starts_with("*.")).count();
    let names: Vec<String> = names.into_iter().take(MAX_CERT_NAMES).collect();
    json!({ "domain": name, "certificates": count, "earliest_seen": first, "latest_seen": last, "total_names": total, "wildcards": wildcards, "truncated": total > names.len(), "names": names })
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
        let v = get_json(&s.agent, &format!("https://crt.sh/?q=%25.{name}&output=json"), "application/json")
            .map_err(|_| anyhow::anyhow!("crt.sh did not answer (it is often overloaded); try again in a minute"))?;
        Ok(summarize_certs(&name, &v))
    }).await?))
}

/// One call for the common case: classify the input as IP or domain and gather the basics.
async fn lookup(State(s): State<Shared>, Query(q): Query<QueryParam>) -> Result<Json<Value>, ApiError> {
    let input = normalize_input(&q.q);
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
        let mut errors = serde_json::Map::new();
        if let Err(e) = &r {
            errors.insert("rdap".into(), json!(short_err(e)));
        }
        if let Err(e) = &p {
            errors.insert("ptr".into(), json!(short_err(e)));
        }
        return Ok(Json(json!({ "kind": "ip", "input": ip.to_string(), "rdap": r.ok(), "ptr": p.ok(), "errors": errors })));
    }
    let name = valid_domain(&input).ok_or_else(|| bad("enter a domain (example.com) or an IP address; internationalised names need their xn-- (punycode) form"))?;
    let (a, b) = (s.clone(), s.clone());
    let (n1, n2) = (name.clone(), name.clone());
    let (records, reg) = tokio::join!(
        blocking(move || {
            let mut out = serde_json::Map::new();
            let mut status = "NOERROR".to_string();
            for t in ["A", "AAAA", "CNAME", "MX", "NS", "TXT"] {
                let r = dns(&a.agent, &n1, t)?;
                if r["status"] != "NOERROR" {
                    status = r["status"].as_str().unwrap_or("").to_string();
                }
                out.insert(t.into(), r["answers"].clone());
            }
            Ok(json!({ "status": status, "records": out }))
        }),
        blocking(move || rdap(&b.agent, "domain", &n2))
    );
    let mut errors = serde_json::Map::new();
    if let Err(e) = &records {
        errors.insert("dns".into(), json!(short_err(e)));
    }
    if let Err(e) = &reg {
        errors.insert("rdap".into(), json!(short_err(e)));
    }
    let (dns_status, dns_records) = match records {
        Ok(v) => (v["status"].clone(), Some(v["records"].clone())),
        Err(_) => (Value::Null, None),
    };
    Ok(Json(json!({ "kind": "domain", "input": name, "dns_status": dns_status, "dns": dns_records, "rdap": reg.ok(), "errors": errors })))
}

fn short_err(e: &ApiError) -> String {
    let m = e.1.as_str();
    if m.contains("404") { "no record found".into() } else if m.contains("429") { "rate limited, try again shortly".into() } else { "the upstream service did not answer".into() }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_validation() {
        assert_eq!(valid_domain(" Example.COM. ").as_deref(), Some("example.com"));
        assert!(valid_domain("nodot").is_none());
        assert!(valid_domain("-bad.example.com").is_none());
        assert!(valid_domain("exa mple.com").is_none());
        assert!(valid_domain("a..b.com").is_none());
        assert!(valid_domain("bücher.example").is_none());
    }

    #[test]
    fn pasted_urls_are_reduced_to_a_host() {
        assert_eq!(normalize_input("https://user@Example.com:8443/a/b?x=1#f"), "Example.com");
        assert_eq!(normalize_input("  example.org/path "), "example.org");
        assert_eq!(normalize_input("1.1.1.1:53"), "1.1.1.1");
        assert_eq!(normalize_input("[2606:4700:4700::1111]"), "2606:4700:4700::1111");
        assert_eq!(normalize_input("2606:4700:4700::1111"), "2606:4700:4700::1111");
    }

    #[test]
    fn ptr_names() {
        assert_eq!(ptr_name("1.2.3.4".parse().unwrap()), "4.3.2.1.in-addr.arpa");
        assert!(ptr_name("2001:db8::1".parse().unwrap()).starts_with("1.0.0.0."));
        assert!(ptr_name("2001:db8::1".parse().unwrap()).ends_with("8.b.d.0.1.0.0.2.ip6.arpa"));
    }

    #[test]
    fn dns_summary_names_types_status_and_sorts_mx() {
        let v = json!({ "Status": 0, "Answer": [
            { "name": "x.", "type": 15, "TTL": 60, "data": "20 b.mail." },
            { "name": "x.", "type": 15, "TTL": 60, "data": "10 a.mail." },
        ] });
        let s = summarize_dns(&v);
        assert_eq!(s["status"], "NOERROR");
        assert_eq!(s["answers"][0]["data"], "10 a.mail.");
        assert_eq!(s["answers"][0]["type"], "MX");
        assert_eq!(summarize_dns(&json!({ "Status": 3 }))["status"], "NXDOMAIN");
    }

    #[test]
    fn cert_summary_dedupes_and_counts_wildcards() {
        let v = json!([
            { "name_value": "a.example.com\n*.example.com", "not_before": "2024-02-01T00:00:00" },
            { "name_value": "A.example.com\nsome intermediate - x\nadmin@example.com", "not_before": "2023-01-01T00:00:00" },
        ]);
        let s = summarize_certs("example.com", &v);
        assert_eq!(s["certificates"], 2);
        assert_eq!(s["total_names"], 2);
        assert_eq!(s["wildcards"], 1);
        assert_eq!(s["earliest_seen"], "2023-01-01T00:00:00");
        assert_eq!(s["latest_seen"], "2024-02-01T00:00:00");
    }
}

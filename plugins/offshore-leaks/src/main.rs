//! ICIJ Offshore Leaks lookups, restricted to companies, trusts and foundations (entities) and intermediaries.
//!
//! Officer, beneficiary and nominee records (individuals) are never searched or returned. Intermediaries (which can be
//! individual professionals) are opt-in. Entity details expose
//! only the entity's own facts plus relationship counts, never the names of connected people. Intermediary records
//! (which can be firms or individual professionals) show name, source leak and country only.

mod cache;
mod util;

use std::{
    env,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    middleware,
    response::Html,
    routing::get,
};
use serde::Deserialize;
use serde_json::{Value, json};

use cache::Cache;
use util::{ApiError, Spacer, bad, blocking, get_json, map_ureq, now_epoch, upstream};

const PAGE: &str = include_str!("../assets/index.html");
const T_ENTITY: &str = "https://offshoreleaks.icij.org/schema/oldb/entity";
const T_INTERMEDIARY: &str = "https://offshoreleaks.icij.org/schema/oldb/intermediary";

pub struct Config {
    pub base: String,
    pub gap: Duration,
    pub open: bool,
}
pub struct AppState {
    cfg: Config,
    agent: ureq::Agent,
    cache: Cache,
    spacer: Spacer,
}
type Shared = Arc<AppState>;

/// Approximate centres of jurisdictions that appear in the leaks (ICIJ's own descriptions, lower-case).
pub fn jurisdiction_coords(name: &str) -> Option<(f64, f64)> {
    Some(match name.trim().to_lowercase().as_str() {
        "british virgin islands" => (18.43, -64.62),
        "panama" => (8.54, -80.78),
        "bahamas" => (25.03, -77.40),
        "seychelles" => (-4.68, 55.49),
        "samoa" => (-13.76, -172.10),
        "niue" => (-19.05, -169.87),
        "cook islands" => (-21.24, -159.78),
        "cayman islands" => (19.31, -81.25),
        "bermuda" => (32.30, -64.78),
        "jersey" => (49.21, -2.13),
        "guernsey" => (49.46, -2.58),
        "isle of man" => (54.24, -4.55),
        "hong kong" => (22.32, 114.17),
        "singapore" => (1.35, 103.82),
        "malta" => (35.94, 14.38),
        "cyprus" => (35.13, 33.43),
        "luxembourg" => (49.82, 6.13),
        "switzerland" => (46.82, 8.23),
        "liechtenstein" => (47.16, 9.56),
        "united kingdom" => (54.0, -2.0),
        "ireland" => (53.41, -8.24),
        "mauritius" => (-20.35, 57.55),
        "marshall islands" => (7.13, 171.18),
        "anguilla" => (18.22, -63.07),
        "nevada" => (39.5, -117.0),
        "wyoming" => (43.0, -107.5),
        "delaware" => (39.0, -75.5),
        "united states" => (39.8, -98.6),
        "belize" => (17.19, -88.5),
        "costa rica" => (9.75, -83.75),
        "uruguay" => (-32.5, -55.8),
        "lebanon" => (33.85, 35.86),
        "malaysia" => (4.2, 101.97),
        "labuan" => (5.28, 115.24),
        "barbados" => (13.19, -59.54),
        "bahrain" => (26.07, 50.55),
        "dubai" | "united arab emirates" | "ras al khaimah" => (25.2, 55.27),
        "andorra" => (42.55, 1.6),
        "gibraltar" => (36.14, -5.35),
        "monaco" => (43.74, 7.42),
        "netherlands" => (52.1, 5.3),
        "cyprus, republic of" => (35.13, 33.43),
        "saint kitts and nevis" | "st. kitts and nevis" => (17.36, -62.78),
        "saint vincent and the grenadines" => (13.25, -61.2),
        "turks and caicos islands" => (21.69, -71.8),
        "vanuatu" => (-15.38, 166.96),
        "brunei" => (4.53, 114.73),
        "china" => (35.9, 104.2),
        "taiwan" => (23.7, 121.0),
        "russia" => (61.5, 105.3),
        "india" => (22.0, 79.0),
        "brazil" => (-10.0, -52.0),
        "canada" => (56.1, -106.3),
        "bangladesh" => (23.7, 90.4),
        "jordan" => (31.0, 36.5),
        "south africa" => (-29.0, 24.0),
        "mexico" => (23.6, -102.5),
        "spain" => (40.2, -3.7),
        "germany" => (51.2, 10.4),
        "france" => (46.6, 2.5),
        _ => return None,
    })
}

fn leak_from_description(d: &str) -> Option<String> {
    let a = d.find(" from the ")? + " from the ".len();
    let rest = &d[a..];
    let b = rest.find(" data")?;
    Some(rest[..b].to_string()).filter(|s| !s.is_empty() && s.len() < 60)
}

/// Turn a reconciliation response into rows, keeping only entity and intermediary types.
pub fn parse_reconcile(v: &Value, key: &str) -> Vec<Value> {
    v[key]["result"].as_array().map(|a| a.iter().filter_map(|r| {
        let types: Vec<&str> = r["types"].as_array()?.iter().filter_map(|t| t["id"].as_str()).collect();
        let kind = if types.contains(&T_ENTITY) { "entity" } else if types.contains(&T_INTERMEDIARY) { "intermediary" } else { return None };
        let id = r["id"].as_str()?.to_string();
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(json!({
            "id": id, "kind": kind, "name": r["name"].as_str()?.split_whitespace().collect::<Vec<_>>().join(" "),
            "leak": leak_from_description(r["description"].as_str().unwrap_or("")),
            "score": r["score"].as_f64().map(|s| (s * 10.0).round() / 10.0),
            "url": format!("{}/nodes/{id}", "https://offshoreleaks.icij.org"),
        }))
    }).collect()).unwrap_or_default()
}

/// The `document.body.nodeData = [...]` JSON embedded in an ICIJ node page.
pub fn extract_node_data(html: &str) -> Option<Value> {
    let k = html.find("nodeData = ")? + "nodeData = ".len();
    let rest = &html[k..];
    serde_json::Deserializer::from_str(rest).into_iter::<Value>().next()?.ok()
}

fn sv(v: &Value) -> Option<String> {
    v.as_str().map(str::trim).filter(|x| !x.is_empty()).map(str::to_string)
}

/// Build the detail card for node `id` from page data. Returns Err(category) when the node is not an entity or intermediary.
pub fn build_detail(id: u64, data: &Value) -> Result<Value, String> {
    let node = data.as_array().and_then(|a| a.iter().find(|n| n["id"].as_u64() == Some(id))).ok_or("node not found in page")?;
    let cats: Vec<&str> = node["data"]["categories"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    let kind = if cats.contains(&"Entity") { "entity" } else if cats.contains(&"Intermediary") { "intermediary" } else { return Err(cats.first().unwrap_or(&"unknown").to_string()) };
    let p = &node["data"]["properties"];
    let mut counts = serde_json::Map::new();
    for d in node["data"]["statistics"]["digest"].as_array().map(Vec::as_slice).unwrap_or_default() {
        let cat = d["nodeCategories"][0].as_str().unwrap_or("Other");
        let n = d["nodes"].as_u64().unwrap_or(0);
        if cat == "Address" {
            continue; // addresses can be private homes; not reported
        }
        let e = counts.entry(cat.to_string()).or_insert(json!(0));
        *e = json!(e.as_u64().unwrap_or(0) + n);
    }
    let jur = sv(&p["jurisdiction_description"]);
    let coords = jur.as_deref().and_then(jurisdiction_coords);
    let mut v = json!({
        "id": id.to_string(), "kind": kind, "name": sv(&p["name"]), "source": sv(&p["sourceID"]).or_else(|| sv(&p["data_source"])),
        "countries": sv(&p["countries"]), "valid_until": sv(&p["valid_until"]),
        "url": format!("https://offshoreleaks.icij.org/nodes/{id}"),
        "connected_counts": counts,
    });
    if kind == "entity" {
        for (k, src) in [("original_name", "original_name"), ("former_name", "former_name"), ("status", "status"), ("incorporation_date", "incorporation_date"), ("inactivation_date", "inactivation_date"),
            ("struck_off_date", "struck_off_date"), ("service_provider", "service_provider"), ("note", "note"), ("company_type", "company_type"), ("jurisdiction_code", "jurisdiction")] {
            v[k] = json!(sv(&p[src]));
        }
        v["jurisdiction"] = json!(jur);
        v["lat"] = json!(coords.map(|c| c.0));
        v["lon"] = json!(coords.map(|c| c.1));
    }
    Ok(v)
}

impl AppState {
    fn search(&self, q: &str, kinds: &[&str], limit: usize) -> Result<Value, ApiError> {
        let key = format!("search|{}|{}|{}", q.to_lowercase(), kinds.join(","), limit);
        if let Some(v) = self.cache.get(&key, Duration::from_secs(3600)).and_then(|b| serde_json::from_slice(&b).ok()) {
            return Ok(v);
        }
        let mut queries = serde_json::Map::new();
        for (i, k) in kinds.iter().enumerate() {
            let t = if *k == "entity" { T_ENTITY } else { T_INTERMEDIARY };
            queries.insert(format!("q{i}"), json!({ "query": q, "type": t, "limit": limit }));
        }
        self.spacer.wait();
        let body = Value::Object(queries).to_string();
        let res = self.agent.post(&format!("{}/api/v1/reconcile", self.cfg.base)).header("Accept", "application/json").send_form([("queries", body.as_str())]).map_err(|e| map_ureq("ICIJ Offshore Leaks", e));
        let v: Value = match res {
            Ok(mut r) => r.body_mut().with_config().limit(4 << 20).read_json().map_err(|_| upstream("ICIJ sent an unreadable response"))?,
            Err(e) => return match self.cache.get_stale(&key).and_then(|b| serde_json::from_slice(&b).ok()) { Some(v) => Ok(v), None => Err(e) },
        };
        let mut rows = Vec::new();
        for i in 0..kinds.len() {
            rows.extend(parse_reconcile(&v, &format!("q{i}")));
        }
        rows.sort_by(|a, b| b["score"].as_f64().partial_cmp(&a["score"].as_f64()).unwrap_or(std::cmp::Ordering::Equal));
        let out = json!({ "query": q, "results": rows });
        self.cache.put(&key, out.to_string().as_bytes());
        Ok(out)
    }

    fn rest_detail(&self, id: u64) -> Result<Value, ApiError> {
        self.spacer.wait();
        let v = get_json(&self.agent, &format!("{}/api/v1/rest/nodes/{id}", self.cfg.base), &[], "ICIJ Offshore Leaks")?.ok_or_else(|| util::not_found("no such node"))?;
        let kind = match v["schema"].as_str().and_then(|s| s.rsplit('/').next()) {
            Some("entity") => "entity",
            Some("intermediary") => "intermediary",
            Some(other) => return Err(ApiError(StatusCode::FORBIDDEN, format!("that record is a {other} node; only entities and intermediaries are available here"))),
            None => return Err(upstream("ICIJ sent an unexpected record")),
        };
        let p = &v["properties"];
        let countries = p["country_codes"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).filter(|s| !s.is_empty());
        Ok(json!({ "id": id.to_string(), "kind": kind, "name": sv(&p["name"]), "source": sv(&p["data_source"]), "countries": countries, "valid_until": sv(&p["valid_until"]),
            "url": format!("https://offshoreleaks.icij.org/nodes/{id}"), "connected_counts": {}, "partial": true }))
    }

    fn detail(&self, id: u64) -> Result<Value, ApiError> {
        let key = format!("node|{id}");
        if let Some(v) = self.cache.get(&key, Duration::from_secs(24 * 3600)).and_then(|b| serde_json::from_slice(&b).ok()) {
            return Ok(v);
        }
        self.spacer.wait();
        let page = self.agent.get(&format!("{}/nodes/{id}", self.cfg.base)).header("Accept", "text/html").call();
        let html = match page {
            Ok(mut r) => r.body_mut().with_config().limit(6 << 20).read_to_string().map_err(|_| upstream("ICIJ node page was unreadable"))?,
            Err(ureq::Error::StatusCode(404)) => return Err(util::not_found("no such node")),
            Err(e) => return Err(map_ureq("ICIJ Offshore Leaks", e)),
        };
        let forbidden = |cat: &str| ApiError(StatusCode::FORBIDDEN, format!("that record is a {} node; only entities and intermediaries are available here", cat.to_lowercase()));
        let page = extract_node_data(&html).map(|d| build_detail(id, &d));
        let out = match page {
            Some(Ok(v)) => v,
            Some(Err(cat)) if cat != "node not found in page" => return Err(forbidden(&cat)),
            // Very large nodes (for example big intermediaries) carry no embedded data: use the REST record instead.
            _ => self.rest_detail(id)?,
        };
        self.cache.put(&key, out.to_string().as_bytes());
        Ok(out)
    }
}

fn parse_id(s: &str) -> Result<u64, ApiError> {
    let t = s.trim();
    if t.is_empty() || t.len() > 10 || !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad("id must be a node number"));
    }
    t.parse().map_err(|_| bad("id must be a node number"))
}

#[derive(Deserialize)]
struct SearchQ {
    q: String,
    intermediaries: Option<String>,
    limit: Option<usize>,
}
async fn search(State(st): State<Shared>, Query(q): Query<SearchQ>) -> Result<Json<Value>, ApiError> {
    let text = q.q.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.chars().count() < 2 || text.chars().count() > 100 {
        return Err(bad("enter 2 to 100 characters"));
    }
    let mut kinds = vec!["entity"];
    if q.intermediaries.as_deref() == Some("1") {
        kinds.push("intermediary");
    }
    let limit = q.limit.unwrap_or(15).clamp(1, 25);
    Ok(Json(blocking(move || st.search(&text, &kinds, limit)).await?))
}

#[derive(Deserialize)]
struct IdQ {
    id: String,
}
async fn entity(State(st): State<Shared>, Query(q): Query<IdQ>) -> Result<Json<Value>, ApiError> {
    let id = parse_id(&q.id)?;
    Ok(Json(blocking(move || st.detail(id)).await?))
}

#[derive(Deserialize)]
struct IdsQ {
    ids: String,
}
/// Details for up to ten search results at once (for the jurisdiction map); paced one request per interval.
async fn enrich(State(st): State<Shared>, Query(q): Query<IdsQ>) -> Result<Json<Value>, ApiError> {
    let ids: Vec<u64> = q.ids.split(',').filter(|x| !x.trim().is_empty()).map(parse_id).collect::<Result<_, _>>()?;
    if ids.is_empty() || ids.len() > 10 {
        return Err(bad("give 1 to 10 ids"));
    }
    Ok(Json(blocking(move || {
        let mut rows = Vec::new();
        for id in ids {
            match st.detail(id) {
                Ok(v) => rows.push(v),
                Err(e) => rows.push(json!({ "id": id.to_string(), "error": e.1 })),
            }
        }
        Ok(json!({ "nodes": rows }))
    }).await?))
}

async fn tools() -> Json<Value> {
    Json(json!([
        { "name": "leaks_entity_search", "description": "Search ICIJ Offshore Leaks for companies, trusts and foundations by name (intermediaries only on request). Returns name, source leak (Panama, Paradise, Pandora...), match score and ICIJ link. Individuals (officers) are not searched. Appearing in the database is not evidence of wrongdoing.",
          "method": "GET", "path": "api/search?q={q}&intermediaries={intermediaries}", "parameters": { "type": "object", "properties": { "q": { "type": "string" }, "intermediaries": { "type": "string", "description": "1 to also include intermediaries (off by default; they can be individual professionals)" } }, "required": ["q"] } },
        { "name": "leaks_entity", "description": "Details of one offshore entity by ICIJ node id: jurisdiction, status, incorporation and struck-off dates, service provider, source leak and counts of connected records (no names of connected people).",
          "method": "GET", "path": "api/entity?id={id}", "parameters": { "type": "object", "properties": { "id": { "type": "string", "description": "node id from a search" } }, "required": ["id"] } },
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

pub fn app(st: Shared) -> Router {
    let open = st.cfg.open;
    Router::new()
        .route("/api/search", get(search))
        .route("/api/entity", get(entity))
        .route("/api/enrich", get(enrich))
        .route_layer(middleware::from_fn_with_state(open, util::gate))
        .route("/tools", get(tools))
        .route("/", get(page))
        .with_state(st)
}

pub fn new_state(cfg: Config, dir: Option<PathBuf>) -> Shared {
    let cache = Cache::new(dir, 16 << 20);
    cache.trim(Duration::from_secs(3 * 86400));
    let gap = cfg.gap;
    let _ = now_epoch();
    Arc::new(AppState { cfg, agent: osnt_common::http_agent("osnt-offshore-leaks/0.1 (+https://github.com/ogden-marrow/osnt-hub)"), cache, spacer: Spacer::new(gap) })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let st = new_state(
        Config { base: "https://offshoreleaks.icij.org".into(), gap: Duration::from_millis(1100), open: env::var("OSNT_LEAKS_INSECURE_LOCAL").ok().as_deref() == Some("1") },
        env::var("OSNT_LEAKS_STATE").ok().filter(|s| !s.is_empty()).map(PathBuf::from),
    );
    let addr: SocketAddr = env::var("OSNT_LEAKS_BIND").unwrap_or_else(|_| "127.0.0.1:8141".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("offshore-leaks plugin on http://{addr}");
    axum::serve(listener, app(st)).await?;
    Ok(())
}

#[cfg(test)]
mod tests;

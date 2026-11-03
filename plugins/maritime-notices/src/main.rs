//! Maritime warnings plugin: NGA Maritime Safety Information broadcast warnings (NAVAREA/HYDRO*), with the positions
//! found in each warning's text turned into map shapes, plus ASAM piracy reports where NGA serves them.
//! Fixed upstream host, one cached bulk download (about 40 KB), no key, nothing stored on disk.

mod coords;

use std::{
    collections::BTreeMap,
    env,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use coords::Shape;

const PAGE: &str = include_str!("../assets/index.html");
const TTL: Duration = Duration::from_secs(30 * 60);
/// A failed refresh serves the last good download for this long, flagged as stale.
const STALE_OK: Duration = Duration::from_secs(6 * 3600);
const MAX_TEXT: usize = 20_000;
const MAX_LIMIT: usize = 500;

#[derive(Serialize, Clone, Debug)]
struct Warning {
    id: String,
    nav_area: String,
    area_label: String,
    subregion: String,
    number: i64,
    year: i64,
    issued: String,
    issued_sort: String,
    authority: String,
    text: String,
    cancelled: bool,
    shapes: Vec<Shape>,
    bbox: Option<[f64; 4]>,
}

struct Snapshot {
    at: Instant,
    warnings: Arc<Vec<Warning>>,
}

struct AppState {
    agent: ureq::Agent,
    base: String,
    warnings: Mutex<Option<Snapshot>>,
    asam: Mutex<Option<(Instant, Arc<Vec<Value>>)>>,
}
type Shared = Arc<AppState>;

struct ApiError(StatusCode, String);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}
fn bad(msg: &str) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}
fn upstream(e: anyhow::Error) -> ApiError {
    ApiError(StatusCode::BAD_GATEWAY, format!("{e:#}"))
}

/// NGA's area codes. HYDROARC's code (C) is read from the data, not from NGA documentation.
fn area_label(code: &str) -> String {
    match code {
        "4" => "NAVAREA IV".into(),
        "12" => "NAVAREA XII".into(),
        "A" => "HYDROLANT".into(),
        "P" => "HYDROPAC".into(),
        "C" => "HYDROARC".into(),
        o => format!("Area {o}"),
    }
}

/// "232009Z APR 2024" to "2024-04-23T20:09Z" so the list can be sorted newest first. Unparseable input sorts last.
fn issue_sort_key(s: &str) -> String {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() == 3 && parts[0].len() == 7 && parts[0].ends_with('Z') && parts[0][..6].bytes().all(|b| b.is_ascii_digit()) {
        const M: [&str; 12] = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"];
        if let (Some(mi), true) = (M.iter().position(|m| m.eq_ignore_ascii_case(parts[1])), parts[2].len() == 4 && parts[2].bytes().all(|b| b.is_ascii_digit())) {
            let d = &parts[0];
            return format!("{}-{:02}-{}T{}:{}Z", parts[2], mi + 1, &d[0..2], &d[2..4], &d[4..6]);
        }
    }
    String::new()
}

fn as_i64(v: &Value) -> i64 {
    v.as_i64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())).unwrap_or(0)
}
fn as_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.trim().to_string(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

/// Parses NGA's `{"broadcast-warn":[...]}` body. Rows without a number or area are dropped.
fn parse_warnings(body: &Value) -> Vec<Warning> {
    let rows = body.get("broadcast-warn").and_then(Value::as_array).or_else(|| body.as_array());
    let mut out: Vec<Warning> = rows
        .map(|r| {
            r.iter()
                .filter_map(|w| {
                    let nav = as_str(&w["navArea"]);
                    let number = as_i64(&w["msgNumber"]);
                    if nav.is_empty() || number == 0 {
                        return None;
                    }
                    let year = as_i64(&w["msgYear"]);
                    let mut text = as_str(&w["text"]);
                    if text.len() > MAX_TEXT {
                        let mut cut = MAX_TEXT;
                        while !text.is_char_boundary(cut) {
                            cut -= 1;
                        }
                        text.truncate(cut);
                        text.push_str(" [truncated]");
                    }
                    let shapes = coords::extract(&text);
                    let issued = as_str(&w["issueDate"]);
                    Some(Warning {
                        id: format!("{nav}-{number}-{year}"),
                        area_label: area_label(&nav),
                        subregion: as_str(&w["subregion"]),
                        issued_sort: issue_sort_key(&issued),
                        issued,
                        authority: as_str(&w["authority"]),
                        cancelled: !w["cancelDate"].is_null() || as_str(&w["status"]).eq_ignore_ascii_case("C"),
                        bbox: coords::bbox(&shapes),
                        shapes,
                        text,
                        nav_area: nav,
                        number,
                        year,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| b.issued_sort.cmp(&a.issued_sort).then(b.year.cmp(&a.year)).then(b.number.cmp(&a.number)));
    out
}

fn fetch_json(state: &AppState, path_and_query: &str) -> Result<Value> {
    let url = format!("{}{path_and_query}", state.base);
    let mut res = state.agent.get(&url).header("Accept", "application/json").call().with_context(|| format!("NGA MSI request failed ({path_and_query})"))?;
    let status = res.status().as_u16();
    let text = res.body_mut().read_to_string().context("read NGA response")?;
    // NGA answers unknown paths or parameters with an HTML apology page (and 503); never pass that along as data.
    serde_json::from_str(&text).with_context(|| format!("NGA MSI did not return JSON (HTTP {status})"))
}

/// Cached bulk download; returns (warnings, stale).
async fn warnings(state: &Shared, force: bool) -> Result<(Arc<Vec<Warning>>, bool), ApiError> {
    if !force {
        if let Some(s) = state.warnings.lock().unwrap().as_ref() {
            if s.at.elapsed() < TTL {
                return Ok((s.warnings.clone(), false));
            }
        }
    }
    let st = state.clone();
    let fetched = tokio::task::spawn_blocking(move || fetch_json(&st, "/api/publications/broadcast-warn?output=json&status=active")).await.map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    match fetched {
        Ok(body) => {
            let list = Arc::new(parse_warnings(&body));
            *state.warnings.lock().unwrap() = Some(Snapshot { at: Instant::now(), warnings: list.clone() });
            Ok((list, false))
        }
        Err(e) => {
            if let Some(s) = state.warnings.lock().unwrap().as_ref() {
                if s.at.elapsed() < STALE_OK {
                    return Ok((s.warnings.clone(), true));
                }
            }
            Err(upstream(e))
        }
    }
}

#[derive(Deserialize, Default)]
struct WarnQuery {
    area: Option<String>,
    sub: Option<String>,
    q: Option<String>,
    year: Option<i64>,
    /// only warnings that have at least one position that could be drawn
    mapped: Option<bool>,
    limit: Option<usize>,
}

fn valid_area(s: &str) -> bool {
    !s.is_empty() && s.len() <= 3 && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn filter(list: &[Warning], q: &WarnQuery) -> Result<Vec<Warning>, ApiError> {
    let area = q.area.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if let Some(a) = area {
        if !valid_area(a) {
            return Err(bad("area must be a NAVAREA code such as 4, 12, A, P or C"));
        }
    }
    let sub = q.sub.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if sub.is_some_and(|s| s.len() > 8 || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b',')) {
        return Err(bad("invalid subregion"));
    }
    let needle = q.q.as_deref().map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty());
    if needle.as_ref().is_some_and(|n| n.len() > 80) {
        return Err(bad("search text is too long"));
    }
    let limit = q.limit.unwrap_or(200).clamp(1, MAX_LIMIT);
    Ok(list
        .iter()
        .filter(|w| area.is_none_or(|a| w.nav_area.eq_ignore_ascii_case(a)))
        .filter(|w| sub.is_none_or(|s| w.subregion.eq_ignore_ascii_case(s)))
        .filter(|w| q.year.is_none_or(|y| w.year == y))
        .filter(|w| !q.mapped.unwrap_or(false) || !w.shapes.is_empty())
        .filter(|w| needle.as_ref().is_none_or(|n| w.text.to_ascii_lowercase().contains(n.as_str()) || w.id.to_ascii_lowercase().contains(n.as_str())))
        .take(limit)
        .cloned()
        .collect())
}

async fn warnings_handler(State(s): State<Shared>, Query(q): Query<WarnQuery>) -> Result<Json<Value>, ApiError> {
    let (list, stale) = warnings(&s, false).await?;
    let out = filter(&list, &q)?;
    Ok(Json(json!({ "total": list.len(), "count": out.len(), "stale": stale, "warnings": out })))
}

async fn areas_handler(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    let (list, stale) = warnings(&s, false).await?;
    let mut by: BTreeMap<String, (usize, usize, BTreeMap<String, usize>, i64)> = BTreeMap::new();
    for w in list.iter() {
        let e = by.entry(w.nav_area.clone()).or_default();
        e.0 += 1;
        e.1 += usize::from(!w.shapes.is_empty());
        *e.2.entry(w.subregion.clone()).or_default() += 1;
        e.3 = e.3.max(w.year);
    }
    let areas: Vec<Value> = by.into_iter().map(|(k, (n, mapped, subs, year))| json!({ "code": k, "label": area_label(&k), "count": n, "mapped": mapped, "latest_year": year, "subregions": subs })).collect();
    Ok(Json(json!({ "areas": areas, "stale": stale })))
}

async fn one_handler(State(s): State<Shared>, Path((area, year, number)): Path<(String, i64, i64)>) -> Result<Json<Warning>, ApiError> {
    if !valid_area(&area) {
        return Err(bad("invalid area"));
    }
    let (list, _) = warnings(&s, false).await?;
    list.iter().find(|w| w.nav_area.eq_ignore_ascii_case(&area) && w.year == year && w.number == number).cloned().map(Json).ok_or(ApiError(StatusCode::NOT_FOUND, "no such active warning".into()))
}

#[derive(Deserialize, Default)]
struct AsamQuery {
    q: Option<String>,
    limit: Option<usize>,
}

fn f64_of(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

/// Lenient ASAM row reader: field names vary a little between NGA exports. Rows without a usable position keep lat/lon null.
fn parse_asam(body: &Value) -> Vec<Value> {
    let rows = body.get("asam").and_then(Value::as_array).or_else(|| body.as_array());
    rows.map(|r| {
        r.iter()
            .map(|a| {
                let pick = |keys: &[&str]| keys.iter().map(|k| as_str(&a[*k])).find(|s| !s.is_empty()).unwrap_or_default();
                json!({
                    "reference": pick(&["reference", "ref"]),
                    "date": pick(&["date", "dateOfOccurrence", "occurDate"]),
                    "lat": f64_of(&a["latitude"]).filter(|v| v.abs() <= 90.0),
                    "lon": f64_of(&a["longitude"]).filter(|v| v.abs() <= 180.0),
                    "hostility": pick(&["hostility", "hostilityD"]),
                    "victim": pick(&["victim", "victimD"]),
                    "nav_area": pick(&["navArea"]),
                    "subregion": pick(&["subreg", "subregion"]),
                    "description": pick(&["description", "text"]),
                })
            })
            .collect()
    })
    .unwrap_or_default()
}

async fn asam_handler(State(s): State<Shared>, Query(q): Query<AsamQuery>) -> Result<Json<Value>, ApiError> {
    let cached = s.asam.lock().unwrap().as_ref().filter(|(at, _)| at.elapsed() < TTL).map(|(_, v)| v.clone());
    let rows = match cached {
        Some(r) => r,
        None => {
            let st = s.clone();
            let body = tokio::task::spawn_blocking(move || fetch_json(&st, "/api/publications/asam?output=json")).await.map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let body = body.map_err(|e| ApiError(StatusCode::BAD_GATEWAY, format!("NGA is not serving ASAM piracy reports on the API path this plugin uses right now ({e:#}). Browse them at https://msi.nga.mil/Piracy")))?;
            let rows = Arc::new(parse_asam(&body));
            *s.asam.lock().unwrap() = Some((Instant::now(), rows.clone()));
            rows
        }
    };
    let needle = q.q.as_deref().map(|x| x.trim().to_ascii_lowercase()).filter(|x| !x.is_empty());
    if needle.as_ref().is_some_and(|n| n.len() > 80) {
        return Err(bad("search text is too long"));
    }
    let limit = q.limit.unwrap_or(100).clamp(1, MAX_LIMIT);
    let mut out: Vec<&Value> = rows.iter().filter(|r| needle.as_ref().is_none_or(|n| r.to_string().to_ascii_lowercase().contains(n.as_str()))).collect();
    out.sort_by(|a, b| b["date"].as_str().cmp(&a["date"].as_str()));
    out.truncate(limit);
    Ok(Json(json!({ "count": out.len(), "reports": out })))
}

async fn tools() -> Json<Value> {
    Json(json!([
        { "name": "msi_warnings", "description": "Active NGA navigational/broadcast warnings, filterable by NAVAREA code (4, 12, A=HYDROLANT, P=HYDROPAC, C=HYDROARC), subregion, year and free text. Each warning includes its text, issue time, and any positions extracted from the text as point/line/polygon/circle shapes (a reading aid; the text is authoritative).",
          "method": "GET", "path": "api/warnings",
          "parameters": { "type": "object", "properties": { "area": { "type": "string", "description": "NAVAREA code" }, "sub": { "type": "string" }, "q": { "type": "string", "description": "text to find, for example 'rocket'" }, "year": { "type": "integer" }, "mapped": { "type": "boolean", "description": "only warnings with drawable positions" }, "limit": { "type": "integer" } } } },
        { "name": "msi_asam", "description": "ASAM piracy and hostile-act reports (vessels and positions only), when the NGA API serves them. May return an upstream error.",
          "method": "GET", "path": "api/asam",
          "parameters": { "type": "object", "properties": { "q": { "type": "string" }, "limit": { "type": "integer" } } } }
    ]))
}

async fn page() -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], PAGE).into_response()
}

fn app(state: Shared) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/areas", get(areas_handler))
        .route("/api/warnings", get(warnings_handler))
        .route("/api/warning/{area}/{year}/{number}", get(one_handler))
        .route("/api/asam", get(asam_handler))
        .with_state(state)
}

fn new_state(base: String) -> Shared {
    Arc::new(AppState { agent: osnt_common::http_agent("osnt-maritime-notices/0.1 (+https://github.com/ogden-marrow/osnt-hub)"), base, warnings: Mutex::default(), asam: Mutex::default() })
}

#[tokio::main]
async fn main() -> Result<()> {
    let state = new_state(env::var("OSNT_MSI_BASE").unwrap_or_else(|_| "https://msi.nga.mil".into()));
    let addr: SocketAddr = env::var("OSNT_MSI_BIND").unwrap_or_else(|_| "127.0.0.1:8160".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("maritime-notices plugin on http://{addr}");
    axum::serve(listener, app(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    /// Tiny fake upstream: path prefix -> (status, content type, body). Counts hits.
    fn fake(routes: Vec<(&'static str, u16, &'static str, String)>) -> (String, Arc<AtomicUsize>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let mut s = s;
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                h.fetch_add(1, Ordering::SeqCst);
                let (code, ct, body) = routes.iter().find(|(p, ..)| path.starts_with(p)).map(|(_, c, t, b)| (*c, *t, b.clone())).unwrap_or((404, "text/plain", "nf".into()));
                let _ = write!(s, "HTTP/1.1 {code} X\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            }
        });
        (base, hits)
    }

    fn fixture() -> String {
        json!({"broadcast-warn": [
            {"msgYear": 2024, "msgNumber": 517, "navArea": "4", "subregion": "GEN", "text": "1. MODU POSITIONS:\n   A. AGOSTO 12 19-23.0N 092-03.1W.\n   B. ARGOS 27-10.4N 090-22.1W.", "status": "A", "issueDate": "081630Z MAY 2024", "authority": "NGA", "cancelDate": null},
            {"msgYear": 2024, "msgNumber": 979, "navArea": "A", "subregion": "11", "text": "ROCKET DEBRIS. HAZARDOUS AREA BOUNDED BY\n28-45.0N 080-30.0W, 28-50.0N 080-10.0W, 28-30.0N 079-50.0W.", "status": "A", "issueDate": "091650Z MAY 2024", "authority": "x", "cancelDate": null},
            {"msgYear": 2023, "msgNumber": 12, "navArea": "P", "subregion": "62", "text": "LIGHT UNLIT.", "status": "A", "issueDate": "bogus", "authority": "x", "cancelDate": null},
            {"msgYear": 2024, "navArea": "P", "text": "no number"}
        ]}).to_string()
    }

    async fn get_json(app: &Router, uri: &str) -> (StatusCode, Value) {
        let res = app.clone().oneshot(Request::get(uri).body(Body::empty()).unwrap()).await.unwrap();
        let st = res.status();
        let b = res.into_body().collect().await.unwrap().to_bytes();
        (st, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    #[test]
    fn issue_keys_sort_and_reject() {
        assert_eq!(issue_sort_key("232009Z APR 2024"), "2024-04-23T20:09Z");
        assert_eq!(issue_sort_key("232009Z apr 2024"), "2024-04-23T20:09Z");
        assert_eq!(issue_sort_key("garbage"), "");
        assert_eq!(issue_sort_key("23200Z APR 2024"), "");
    }

    #[test]
    fn parses_and_orders_warnings() {
        let w = parse_warnings(&serde_json::from_str(&fixture()).unwrap());
        assert_eq!(w.len(), 3, "row without a number is dropped");
        assert_eq!(w[0].id, "A-979-2024", "newest first");
        assert!(matches!(w[0].shapes[0], Shape::Polygon { .. }));
        assert_eq!(w[1].shapes.len(), 2);
        assert!(w[2].shapes.is_empty() && w[2].issued_sort.is_empty());
        assert_eq!(w[0].area_label, "HYDROLANT");
    }

    #[tokio::test]
    async fn api_filters_validates_and_caches() {
        let (base, hits) = fake(vec![("/api/publications/broadcast-warn", 200, "application/json", fixture())]);
        let app = app(new_state(base));
        let (st, v) = get_json(&app, "/api/warnings?area=4").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["count"], 1);
        assert_eq!(v["total"], 3);
        let (_, v) = get_json(&app, "/api/warnings?q=rocket&mapped=true").await;
        assert_eq!(v["warnings"][0]["id"], "A-979-2024");
        let (_, v) = get_json(&app, "/api/warnings?year=2023").await;
        assert_eq!(v["count"], 1);
        assert_eq!(hits.load(Ordering::SeqCst), 1, "bulk download is cached");
        assert_eq!(get_json(&app, "/api/warnings?area=%3Cscript%3E").await.0, StatusCode::BAD_REQUEST);
        assert_eq!(get_json(&app, "/api/warnings?sub=a%20b").await.0, StatusCode::BAD_REQUEST);
        let long = "x".repeat(100);
        assert_eq!(get_json(&app, &format!("/api/warnings?q={long}")).await.0, StatusCode::BAD_REQUEST);
        let (st, v) = get_json(&app, "/api/areas").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["areas"].as_array().unwrap().len(), 3);
        let (st, v) = get_json(&app, "/api/warning/4/2024/517").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["number"], 517);
        assert_eq!(get_json(&app, "/api/warning/4/2024/9999").await.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn html_apology_page_is_an_error_not_data() {
        let (base, _) = fake(vec![("/api/publications/broadcast-warn", 503, "text/html", "<!DOCTYPE html><html>sorry</html>".into())]);
        let app = app(new_state(base));
        let (st, v) = get_json(&app, "/api/warnings").await;
        assert_eq!(st, StatusCode::BAD_GATEWAY);
        assert!(v["error"].as_str().unwrap().contains("NGA"));
    }

    #[tokio::test]
    async fn serves_stale_when_refresh_fails() {
        let (base, _) = fake(vec![("/api/publications/broadcast-warn", 503, "text/html", "<html></html>".into())]);
        let st = new_state(base);
        *st.warnings.lock().unwrap() = Some(Snapshot { at: Instant::now() - Duration::from_secs(3600), warnings: Arc::new(parse_warnings(&serde_json::from_str(&fixture()).unwrap())) });
        let app = app(st);
        let (code, v) = get_json(&app, "/api/warnings").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v["stale"], true);
        assert_eq!(v["total"], 3);
    }

    #[tokio::test]
    async fn asam_parses_when_served_and_reports_when_not() {
        let body = json!({"asam": [
            {"reference": "2024-100", "date": "2024-05-01", "latitude": "1.25", "longitude": 103.9, "hostility": "Boarded", "victim": "Bulk carrier", "description": "Robbers boarded", "navArea": "IX", "subreg": "71"},
            {"reference": "2024-101", "date": "2024-05-03", "latitude": 999, "hostility": "Attempted", "victim": "Tanker", "description": "Approached"}
        ]})
        .to_string();
        let (base, _) = fake(vec![("/api/publications/asam", 200, "application/json", body)]);
        let a = app(new_state(base));
        let (st, v) = get_json(&a, "/api/asam").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["reports"][0]["reference"], "2024-101", "newest first");
        assert!(v["reports"][0]["lat"].is_null(), "out-of-range latitude dropped");
        assert_eq!(v["reports"][1]["lat"], 1.25);
        let (_, v) = get_json(&a, "/api/asam?q=tanker").await;
        assert_eq!(v["count"], 1);
        let (base, _) = fake(vec![("/api/publications/asam", 503, "text/html", "<html></html>".into())]);
        let a = app(new_state(base));
        let (st, v) = get_json(&a, "/api/asam").await;
        assert_eq!(st, StatusCode::BAD_GATEWAY);
        assert!(v["error"].as_str().unwrap().contains("msi.nga.mil"));
    }

    #[tokio::test]
    async fn tools_shape() {
        let (base, _) = fake(vec![]);
        let (st, v) = get_json(&app(new_state(base)), "/tools").await;
        assert_eq!(st, StatusCode::OK);
        assert!(v.as_array().unwrap().iter().all(|t| t["method"] == "GET" && t["path"].as_str().unwrap().starts_with("api/")));
    }
}

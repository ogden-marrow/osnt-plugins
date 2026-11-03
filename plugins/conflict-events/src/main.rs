//! Conflict events: UCDP georeferenced events (free access token) and, with an optional account, ACLED events.
//! Both services require attribution and disallow bulk redistribution, so only a short in-memory cache is kept and
//! date ranges are limited. Armed groups and governments appear as actors; narratives that could name individuals
//! are not read (see events.rs).

mod events;
#[cfg(test)]
mod testutil;

use std::{env, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
};
use events::{Cache, Event, Filter};
use serde::Deserialize;
use serde_json::{Value, json};

const PAGE: &str = include_str!("../assets/index.html");
const UA: &str = "osnt-conflict-events/0.1 (+https://github.com/ogden-marrow/osnt-hub)";
const TTL: Duration = Duration::from_secs(1800);
const UCDP_PAGES: u64 = 8;
const ACLED_PAGES: u64 = 4;
const MAX_SPAN_DAYS: i64 = 366;
const DEFAULT_VERSION: &str = "25.1";

type Secrets = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;

struct App {
    agent: ureq::Agent,
    ucdp_base: String,
    acled_base: String,
    version: String,
    secrets: Secrets,
    cache: Cache,
}
type Shared = Arc<App>;

struct ApiError(StatusCode, String, Option<&'static str>);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1, "setup": self.2 }))).into_response()
    }
}
fn bad(m: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, m.into(), None)
}
fn upstream(m: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_GATEWAY, m.into(), None)
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, ApiError> + Send + 'static) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f).await.map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string(), None))?
}

/// Remove secrets from any text before it can reach a response.
fn scrub(app: &App, mut t: String, names: &[&str]) -> String {
    for n in names {
        if let Some(v) = (app.secrets)(n).filter(|v| v.len() >= 4) {
            t = t.replace(&v, "[hidden]");
        }
    }
    t
}

fn get_json(app: &App, url: &str, headers: &[(&str, &str)], names: &[&str]) -> Result<(u16, Value), ApiError> {
    use std::io::Read;
    let mut rb = app.agent.get(url).header("Accept", "application/json");
    for (k, v) in headers {
        rb = rb.header(*k, *v);
    }
    let mut res = rb.config().http_status_as_error(false).timeout_global(Some(Duration::from_secs(40))).build().call().map_err(|e| upstream(scrub(app, format!("could not reach the data service: {e}"), names)))?;
    let status = res.status().as_u16();
    let mut buf = Vec::new();
    res.body_mut().as_reader().take(8 * 1024 * 1024).read_to_end(&mut buf).map_err(|e| upstream(format!("reading the response failed: {e}")))?;
    Ok((status, serde_json::from_slice(&buf).unwrap_or(Value::Null)))
}

fn fetch_ucdp(app: &App, version: &str, start: &str, end: &str, types: &str) -> Result<(Vec<Event>, bool), ApiError> {
    let token = (app.secrets)("UCDP_ACCESS_TOKEN").filter(|t| !t.is_empty()).ok_or(ApiError(StatusCode::SERVICE_UNAVAILABLE, "UCDP needs a free access token. Request one from UCDP (see the link below), then store it as UCDP_ACCESS_TOKEN on the Credentials page.".into(), Some("UCDP_ACCESS_TOKEN")))?;
    let mut all = Vec::new();
    let mut truncated = false;
    for page in 0..UCDP_PAGES {
        let mut q = url::form_urlencoded::Serializer::new(String::new());
        q.append_pair("pagesize", "1000").append_pair("page", &page.to_string()).append_pair("StartDate", start).append_pair("EndDate", end);
        if !types.is_empty() {
            q.append_pair("TypeOfViolence", types);
        }
        let (status, v) = get_json(app, &format!("{}/api/gedevents/{version}?{}", app.ucdp_base, q.finish()), &[("x-ucdp-access-token", &token)], &["UCDP_ACCESS_TOKEN"])?;
        match status {
            200 => {}
            401 | 403 => return Err(ApiError(StatusCode::BAD_GATEWAY, "UCDP rejected the access token. Check UCDP_ACCESS_TOKEN on the Credentials page.".into(), Some("UCDP_ACCESS_TOKEN"))),
            404 => return Err(bad(format!("UCDP has no dataset version {version}"))),
            429 => return Err(upstream("UCDP is rate limiting this host (HTTP 429); try again later")),
            s => return Err(upstream(format!("UCDP answered HTTP {s}"))),
        }
        let (ev, pages) = events::parse_ucdp(&v).map_err(upstream)?;
        all.extend(ev);
        if page + 1 >= pages {
            return Ok((all, truncated));
        }
        if page + 1 == UCDP_PAGES {
            truncated = true;
        }
    }
    Ok((all, truncated))
}

fn fetch_acled(app: &App, start: &str, end: &str) -> Result<(Vec<Event>, bool), ApiError> {
    let (Some(key), Some(email)) = ((app.secrets)("ACLED_API_KEY").filter(|t| !t.is_empty()), (app.secrets)("ACLED_EMAIL").filter(|t| !t.is_empty())) else {
        return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "ACLED is optional and needs a registered account: store ACLED_API_KEY and ACLED_EMAIL on the Credentials page.".into(), Some("ACLED_API_KEY")));
    };
    let mut all = Vec::new();
    for page in 1..=ACLED_PAGES {
        let mut q = url::form_urlencoded::Serializer::new(String::new());
        q.append_pair("_format", "json").append_pair("key", &key).append_pair("email", &email).append_pair("event_date", &format!("{start}|{end}")).append_pair("event_date_where", "BETWEEN").append_pair("limit", "5000").append_pair("page", &page.to_string());
        let (status, v) = get_json(app, &format!("{}?{}", app.acled_base, q.finish()), &[], &["ACLED_API_KEY", "ACLED_EMAIL"])?;
        if status == 401 || status == 403 {
            return Err(upstream("ACLED refused the credentials or the request (the ACLED API changed in 2025 and may now need its newer login; this part is unverified). Check ACLED_API_KEY and ACLED_EMAIL."));
        }
        if status != 200 {
            return Err(upstream(format!("ACLED answered HTTP {status}")));
        }
        let rows = events::parse_acled(&v).map_err(|e| upstream(scrub(app, e, &["ACLED_API_KEY", "ACLED_EMAIL"])))?;
        let n = rows.len();
        all.extend(rows);
        if n < 5000 {
            return Ok((all, false));
        }
    }
    Ok((all, true))
}

#[derive(Deserialize, Default)]
struct EventsQ {
    #[serde(default)]
    source: String,
    start: Option<String>,
    end: Option<String>,
    #[serde(default)]
    country: String,
    #[serde(default, rename = "type")]
    kind: String,
    min_deaths: Option<i64>,
    version: Option<String>,
    limit: Option<usize>,
}

fn run_events(app: &App, q: &EventsQ) -> Result<Value, ApiError> {
    let source = if q.source.is_empty() { "ucdp" } else { q.source.as_str() };
    if source != "ucdp" && source != "acled" {
        return Err(bad("source must be ucdp or acled"));
    }
    let version = events::valid_version(q.version.as_deref().filter(|v| !v.is_empty()).unwrap_or(&app.version)).map_err(bad)?;
    // GED lags real time: without dates, show the last quarter of the dataset's final year.
    let default_end = if source == "ucdp" { events::version_year(&version).map(|y| chrono::NaiveDate::from_ymd_opt(y, 12, 31).unwrap_or_default()) } else { None }.unwrap_or_else(|| chrono::Utc::now().date_naive());
    let end = q.end.as_deref().filter(|d| !d.is_empty()).map(events::parse_date).transpose().map_err(bad)?.unwrap_or(default_end);
    let start = q.start.as_deref().filter(|d| !d.is_empty()).map(events::parse_date).transpose().map_err(bad)?.unwrap_or(end - chrono::Duration::days(91));
    if start > end {
        return Err(bad("the start date is after the end date"));
    }
    if (end - start).num_days() > MAX_SPAN_DAYS {
        return Err(bad("choose a period of at most one year (the services disallow bulk copies)"));
    }
    let (s, e) = (start.format("%Y-%m-%d").to_string(), end.format("%Y-%m-%d").to_string());
    // Only pass the violence type upstream when it is a plain code list, so the cache key stays small; names filter locally.
    let codes: String = q.kind.split(',').map(str::trim).filter(|t| matches!(*t, "1" | "2" | "3")).collect::<Vec<_>>().join(",");
    let local_kind: String = q.kind.split(',').map(str::trim).filter(|t| !matches!(*t, "1" | "2" | "3")).collect::<Vec<_>>().join(",");
    let key = format!("{source}|{version}|{s}|{e}|{codes}");
    let (all, truncated, cached) = match app.cache.get(&key, TTL) {
        Some((v, t)) => (v, t, true),
        None => {
            let (v, t) = if source == "ucdp" { fetch_ucdp(app, &version, &s, &e, &codes)? } else { fetch_acled(app, &s, &e)? };
            let v = Arc::new(v);
            app.cache.put(key, v.clone(), t);
            (v, t, false)
        }
    };
    let filter = Filter::parse(&q.country, &local_kind, q.min_deaths);
    let mut kept: Vec<Event> = all.iter().filter(|ev| filter.keep(ev)).cloned().collect();
    kept.sort_by(|a, b| b.date.cmp(&a.date).then(a.id.cmp(&b.id)));
    let summary = events::summarise(&kept);
    let total = kept.len();
    kept.truncate(q.limit.unwrap_or(2000).clamp(1, 3000));
    let (attribution, codebook) = if source == "ucdp" {
        ("Uppsala Conflict Data Program (UCDP), Georeferenced Event Dataset, version ".to_string() + &version + ". Sundberg & Melander (2013); Davies et al. Used under UCDP's terms (CC BY 4.0 per UCDP).", "https://ucdp.uu.se/downloads/")
    } else {
        ("Armed Conflict Location & Event Data Project (ACLED), acleddata.com. Used under ACLED's terms of use; attribution required, no redistribution.".to_string(), "https://acleddata.com/methodology/acled-codebook")
    };
    Ok(json!({ "source": source, "version": version, "start": s, "end": e, "total": total, "returned": kept.len(), "upstream_truncated": truncated, "cached": cached, "events": kept, "summary": summary, "attribution": attribution, "codebook": codebook }))
}

async fn events_handler(State(s): State<Shared>, Query(q): Query<EventsQ>) -> Result<Json<Value>, ApiError> {
    Ok(Json(blocking(move || run_events(&s, &q)).await?))
}

async fn status(State(s): State<Shared>) -> Json<Value> {
    Json(blocking(move || {
        let has = |n: &str| (s.secrets)(n).is_some_and(|v| !v.is_empty());
        Ok(json!({ "ucdp": { "configured": has("UCDP_ACCESS_TOKEN"), "version": s.version, "token_help": "https://ucdp.uu.se/apidocs/" }, "acled": { "configured": has("ACLED_API_KEY") && has("ACLED_EMAIL") } }))
    }).await.unwrap_or_else(|_| json!({})))
}

async fn tools() -> Json<Value> {
    let st = |d: &str| json!({ "type": "string", "description": d });
    Json(json!([
        { "name": "conflict_events", "description": "Georeferenced armed-conflict events (UCDP GED by default, ACLED if configured) for a period of up to one year, filtered by country and type. Returns event counts, deaths, a type/month/country breakdown and the first events with place, actors (organisations) and source. UCDP is released annually, so recent months may be absent.",
          "method": "GET", "path": "api/events", "parameters": { "type": "object", "properties": {
              "source": st("ucdp (default) or acled"), "start": st("YYYY-MM-DD"), "end": st("YYYY-MM-DD"), "country": st("country name fragment(s), comma separated"),
              "type": st("UCDP: 1 state-based, 2 non-state, 3 one-sided; ACLED: event type text"), "min_deaths": { "type": "integer" }, "limit": { "type": "integer", "description": "events returned, 1 to 3000 (default 2000)" } } } }
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

fn router(app: Shared) -> Router {
    Router::new().route("/", get(page)).route("/tools", get(tools)).route("/api/status", get(status)).route("/api/events", get(events_handler)).with_state(app)
}

fn make_app(ucdp: &str, acled: &str, version: &str, secrets: Secrets) -> Shared {
    Arc::new(App { agent: osnt_common::http_agent(UA), ucdp_base: ucdp.trim_end_matches('/').into(), acled_base: acled.into(), version: version.into(), secrets, cache: Cache::new(4) })
}

#[tokio::main]
async fn main() -> Result<()> {
    let version = env::var("OSNT_UCDP_VERSION").ok().filter(|v| events::valid_version(v).is_ok()).unwrap_or_else(|| DEFAULT_VERSION.into());
    let app = make_app(
        &env::var("OSNT_UCDP_BASE").unwrap_or_else(|_| "https://ucdpapi.pcr.uu.se".into()),
        &env::var("OSNT_ACLED_BASE").unwrap_or_else(|_| "https://acleddata.com/api/acled/read".into()),
        &version,
        Box::new(|n| osnt_common::secret(n)),
    );
    let addr: SocketAddr = env::var("OSNT_CONFLICT_BIND").unwrap_or_else(|_| "127.0.0.1:8152".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("conflict-events plugin on http://{addr}");
    axum::serve(listener, router(app)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn serve(app: Shared) -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async move {
                axum::serve(tokio::net::TcpListener::from_std(l).unwrap(), router(app)).await.unwrap();
            })
        });
        port
    }

    fn call(port: u16, path: &str) -> (u16, Value) {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
        let mut r = agent.get(&format!("http://127.0.0.1:{port}{path}")).call().unwrap();
        let st = r.status().as_u16();
        (st, r.body_mut().read_json().unwrap_or(Value::Null))
    }

    fn rows(page: u64) -> Vec<Value> {
        (0..3).map(|i| json!({ "id": page * 10 + i, "type_of_violence": 1 + (i % 3), "side_a": "Government of A", "side_b": "Group B", "country": if i == 0 { "Aland" } else { "Bland" }, "latitude": 10.0 + i as f64, "longitude": 20.0, "date_start": format!("2024-1{}-0{}", 0 + page, 1 + i), "date_end": "2024-10-05", "best": i * 2, "source_headline": "h" })).collect()
    }

    /// Returns (our port, fake port, hit counter). The fake serves 2 UCDP pages and an ACLED page.
    fn setup(token: Option<&'static str>, acled: bool) -> (u16, u16, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let fake = spawn(Arc::new(move |r| {
            h.fetch_add(1, Ordering::SeqCst);
            let tok = r.headers.iter().find(|(k, _)| k == "x-ucdp-access-token").map(|(_, v)| v.as_str());
            if r.path.starts_with("/api/gedevents/25.1") {
                if tok != Some("good-token") {
                    return Resp::status(401, "API token required");
                }
                let page: u64 = r.path.split("page=").nth(1).and_then(|p| p.split('&').next()).and_then(|p| p.parse().ok()).unwrap_or(0);
                return Resp::json(json!({ "TotalCount": 6, "TotalPages": 2, "Result": rows(page) }));
            }
            if r.path.starts_with("/api/gedevents/") {
                return Resp::status(404, "nf");
            }
            if r.path.starts_with("/acled") {
                if !r.path.contains("key=akey") {
                    return Resp::json(json!({ "status": 401, "success": false, "error": [{ "message": "bad key akey-leak" }] }));
                }
                return Resp::json(json!({ "status": 200, "success": true, "data": [{ "event_id_cnty": "X1", "event_date": "2024-02-02", "event_type": "Battles", "country": "Cland", "latitude": "1", "longitude": "2", "fatalities": "3", "actor1": "Group Z", "notes": "private narrative" }] }));
            }
            Resp::status(404, "nf")
        }));
        let secrets: Secrets = Box::new(move |n| match n {
            "UCDP_ACCESS_TOKEN" => token.map(str::to_string),
            "ACLED_API_KEY" if acled => Some("akey".into()),
            "ACLED_EMAIL" if acled => Some("me@example.org".into()),
            _ => None,
        });
        let base = format!("http://127.0.0.1:{fake}");
        (serve(make_app(&base, &format!("{base}/acled"), "25.1", secrets)), fake, hits)
    }

    #[test]
    fn missing_token_points_at_credentials() {
        let (port, _, hits) = setup(None, false);
        let (st, v) = call(port, "/api/events");
        assert_eq!(st, 503);
        assert_eq!(v["setup"], "UCDP_ACCESS_TOKEN");
        assert_eq!(hits.load(Ordering::SeqCst), 0, "no upstream call without a token");
        assert_eq!(call(port, "/api/events?source=acled").0, 503);
        let (_, s) = call(port, "/api/status");
        assert_eq!((s["ucdp"]["configured"].clone(), s["acled"]["configured"].clone()), (json!(false), json!(false)));
    }

    #[test]
    fn bad_token_and_input_validation() {
        let (port, _, hits) = setup(Some("wrong"), false);
        let (st, v) = call(port, "/api/events");
        assert_eq!(st, 502);
        assert!(v["error"].as_str().unwrap().contains("rejected"));
        assert!(!v.to_string().contains("wrong"));
        let before = hits.load(Ordering::SeqCst);
        for bad in ["/api/events?source=other", "/api/events?start=2024-13-01", "/api/events?start=2024-05-01&end=2024-01-01", "/api/events?start=2020-01-01&end=2024-01-01", "/api/events?version=25.1/../x", "/api/events?version=99.9"] {
            let (st, _) = call(port, bad);
            assert!(st == 400 || st == 502, "{bad} -> {st}");
        }
        assert_eq!(call(port, "/api/events?source=other").0, 400);
        assert_eq!(call(port, "/api/events?version=99.9&start=2024-01-01&end=2024-02-01").0, 400, "unknown dataset version is a 404 upstream");
        let _ = before;
    }

    #[test]
    fn ucdp_events_paging_filters_and_cache() {
        let (port, _, hits) = setup(Some("good-token"), false);
        let (st, v) = call(port, "/api/events?start=2024-10-01&end=2024-12-31");
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["total"], 6, "two pages of three");
        assert_eq!(v["cached"], false);
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(v["summary"]["by_country"].as_array().unwrap().len(), 2);
        assert!(v["attribution"].as_str().unwrap().contains("UCDP"));
        // same range again: served from cache, filters apply locally
        let (_, v2) = call(port, "/api/events?start=2024-10-01&end=2024-12-31&country=aland");
        assert_eq!((v2["cached"].clone(), v2["total"].clone()), (json!(true), json!(2)));
        let (_, v3) = call(port, "/api/events?start=2024-10-01&end=2024-12-31&type=one-sided&min_deaths=1&limit=1");
        assert_eq!(v3["returned"], 1);
        assert!(v3["total"].as_u64().unwrap() >= 1);
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        // default period follows the dataset version (events through 2024 for 25.1)
        let (_, d) = call(port, "/api/events");
        assert_eq!(d["end"], "2024-12-31");
        // type codes are passed upstream (new cache key)
        let (_, t) = call(port, "/api/events?start=2024-10-01&end=2024-12-31&type=1");
        assert_eq!(t["cached"], false);
    }

    #[test]
    fn acled_optional_source_and_secret_scrubbing() {
        let (port, _, _) = setup(Some("good-token"), true);
        let (st, v) = call(port, "/api/events?source=acled&start=2024-01-01&end=2024-03-01");
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["events"][0]["actors"][0], "Group Z");
        assert!(!v.to_string().contains("private narrative"));
        let (_, s) = call(port, "/api/status");
        assert_eq!(s["acled"]["configured"], true);
        // the fake echoes the key in an error: it must be hidden
        let secrets: Secrets = Box::new(|n| (n == "ACLED_API_KEY").then(|| "wrongkey".to_string()).or((n == "ACLED_EMAIL").then(|| "e@x.org".to_string())));
        let fake = spawn(Arc::new(|_| Resp::json(json!({ "status": 400, "success": false, "error": [{ "message": "invalid key wrongkey for e@x.org" }] }))));
        let p2 = serve(make_app("http://127.0.0.1:1", &format!("http://127.0.0.1:{fake}/acled"), "25.1", secrets));
        let (st, v) = call(p2, "/api/events?source=acled&start=2024-01-01&end=2024-03-01");
        assert_eq!(st, 502);
        let text = v.to_string();
        assert!(!text.contains("wrongkey") && !text.contains("e@x.org"), "{text}");
    }

    #[test]
    fn tools_shape() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let Json(v) = rt.block_on(tools());
        assert_eq!(v[0]["name"], "conflict_events");
        assert!(v[0]["path"].as_str().unwrap().starts_with("api/"));
    }
}

//! Public funds and procurement by organisation: USAspending awards, ProPublica Nonprofit Explorer (Form 990 totals),
//! Senate/House LDA lobbying filings by client, and EU TED tender notices by buyer or winner.
//!
//! Organisation level only: recipients are restricted to business, government, higher-education and nonprofit
//! categories; nonprofit pages omit care-of names and street addresses; lobbying rows omit lobbyist, contact and
//! poster names.

mod cache;
mod util;

use std::{env, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{Query, State},
    middleware,
    response::Html,
    routing::get,
};
use serde::Deserialize;
use serde_json::{Value, json};

use cache::Cache;
use util::{ApiError, Spacer, bad, blocking, enc, get_json, not_found, now_epoch, post_json};

const PAGE: &str = include_str!("../assets/index.html");
const TTL: Duration = Duration::from_secs(6 * 3600);

pub struct Bases {
    pub usa: String,
    pub propublica: String,
    pub lda: String,
    pub ted: String,
}
impl Bases {
    pub fn live() -> Bases {
        Bases {
            usa: "https://api.usaspending.gov/api/v2".into(),
            propublica: "https://projects.propublica.org/nonprofits/api/v2".into(),
            lda: "https://lda.gov/api/v1".into(),
            ted: "https://api.ted.europa.eu/v3".into(),
        }
    }
}

pub struct AppState {
    b: Bases,
    open: bool,
    agent: ureq::Agent,
    cache: Cache,
    spacer: Spacer,
}
type Shared = Arc<AppState>;

/// An organisation name: 2 to 100 characters, no control characters, no quotes or backslashes (they would break
/// the search expressions sent upstream).
pub fn valid_org(s: &str) -> Result<String, ApiError> {
    let t = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let n = t.chars().count();
    if !(2..=100).contains(&n) || t.chars().any(|c| c.is_control() || matches!(c, '"' | '\\')) {
        return Err(bad("enter an organisation name of 2 to 100 characters without quotes"));
    }
    Ok(t)
}

pub fn valid_ein(s: &str) -> Option<String> {
    let d: String = s.chars().filter(|c| *c != '-').collect();
    (d.len() == 9 && d.bytes().all(|b| b.is_ascii_digit())).then_some(d)
}

fn current_year() -> i32 {
    (1970 + (now_epoch() / 31_556_952)) as i32
}

fn clip(s: &str, n: usize) -> String {
    let t = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if t.chars().count() > n { format!("{}…", t.chars().take(n).collect::<String>()) } else { t }
}

/// US federal fiscal year (October to September) containing an epoch time.
pub fn fiscal_year_bounds(years_back: i32, now_year: i32, now_month: u32) -> (String, String) {
    let fy_now = if now_month >= 10 { now_year + 1 } else { now_year };
    (format!("{}-10-01", fy_now - years_back - 1), format!("{}-09-30", fy_now))
}

fn month_now() -> u32 {
    let days = (now_epoch() / 86400) as i64;
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    (if mp < 10 { mp + 3 } else { mp - 9 }) as u32
}

impl AppState {
    fn cached(&self, ckey: &str, ttl: Duration, f: impl FnOnce() -> Result<Value, ApiError>) -> Result<Value, ApiError> {
        if let Some(v) = self.cache.get(ckey, ttl).and_then(|b| serde_json::from_slice(&b).ok()) {
            return Ok(v);
        }
        self.spacer.wait();
        match f() {
            Ok(v) => {
                self.cache.put(ckey, v.to_string().as_bytes());
                Ok(v)
            }
            Err(e) => self.cache.get_stale(ckey).and_then(|b| serde_json::from_slice(&b).ok()).ok_or(e),
        }
    }

    // ----- USAspending ----------------------------------------------------------------------------------------

    fn usa_filters(org: &str, kind: &str, start: &str, end: &str) -> Value {
        let codes: Vec<&str> = if kind == "grants" { vec!["02", "03", "04", "05"] } else { vec!["A", "B", "C", "D"] };
        json!({
            "recipient_search_text": [org],
            "recipient_type_names": ["category_business", "category_government", "category_higher_education", "category_nonprofit"],
            "award_type_codes": codes,
            "time_period": [{ "start_date": start, "end_date": end }],
        })
    }

    fn awards(&self, org: &str, kind: &str, years: i32) -> Result<Value, ApiError> {
        let (start, end) = fiscal_year_bounds(years - 1, current_year(), month_now());
        let filters = Self::usa_filters(org, kind, &start, &end);
        let ck = format!("usa|{kind}|{years}|{}", org.to_lowercase());
        self.cached(&ck, TTL, || {
            let over = post_json(&self.agent, &format!("{}/search/spending_over_time/", self.b.usa), &json!({ "group": "fiscal_year", "filters": filters }), &[], "USAspending")?;
            let by_year: Vec<Value> = over["results"].as_array().map(|a| a.iter().map(|r| json!({ "fiscal_year": r["time_period"]["fiscal_year"], "amount": r["aggregated_amount"] })).collect()).unwrap_or_default();
            let total: f64 = by_year.iter().filter_map(|r| r["amount"].as_f64()).sum();
            let ag = post_json(&self.agent, &format!("{}/search/spending_by_category/awarding_agency/", self.b.usa), &json!({ "filters": filters, "limit": 8, "page": 1 }), &[], "USAspending")?;
            let agencies: Vec<Value> = ag["results"].as_array().map(|a| a.iter().map(|r| json!({ "name": r["name"], "amount": r["amount"] })).collect()).unwrap_or_default();
            let top = post_json(&self.agent, &format!("{}/search/spending_by_award/", self.b.usa), &json!({
                "filters": filters, "fields": ["Award ID", "Recipient Name", "Award Amount", "Awarding Agency", "Start Date", "Description"], "limit": 8, "page": 1, "sort": "Award Amount", "order": "desc" }), &[], "USAspending")?;
            let awards: Vec<Value> = top["results"].as_array().map(|a| a.iter().map(|r| json!({
                "award_id": r["Award ID"], "recipient": r["Recipient Name"], "amount": r["Award Amount"], "agency": r["Awarding Agency"], "start": r["Start Date"],
                "description": r["Description"].as_str().map(|d| clip(d, 160)),
                "url": r["generated_internal_id"].as_str().map(|g| format!("https://www.usaspending.gov/award/{}", enc(g))),
            })).collect()).unwrap_or_default();
            let names = post_json(&self.agent, &format!("{}/autocomplete/recipient/", self.b.usa), &json!({ "search_text": org, "limit": 5 }), &[], "USAspending").ok();
            let recipients: Vec<String> = names.and_then(|n| n["results"].as_array().map(|a| a.iter().filter_map(|r| r["recipient_name"].as_str().map(str::to_string)).collect())).unwrap_or_default();
            Ok(json!({ "org": org, "kind": kind, "period": { "start": start, "end": end }, "total": total, "by_fiscal_year": by_year, "agencies": agencies, "top_awards": awards, "matched_recipients": recipients,
                "note": "Prime awards by recipients whose name contains the text; related companies and subsidiaries have their own names. Individuals are excluded by recipient category." }))
        })
    }

    // ----- ProPublica Nonprofit Explorer ---------------------------------------------------------------------

    fn nonprofit_search(&self, q: &str) -> Result<Value, ApiError> {
        self.cached(&format!("pp|s|{}", q.to_lowercase()), TTL, || {
            let v = get_json(&self.agent, &format!("{}/search.json?q={}", self.b.propublica, enc(q)), &[], "ProPublica Nonprofit Explorer")?.ok_or_else(|| not_found("not found"))?;
            let orgs: Vec<Value> = v["organizations"].as_array().map(|a| a.iter().take(15).map(|o| json!({
                "ein": o["ein"].as_u64().map(|e| format!("{e:09}")), "name": o["name"], "city": o["city"], "state": o["state"], "ntee": o["ntee_code"],
            })).collect()).unwrap_or_default();
            Ok(json!({ "query": q, "total": v["total_results"], "organizations": orgs }))
        })
    }

    fn nonprofit(&self, ein: &str) -> Result<Value, ApiError> {
        self.cached(&format!("pp|o|{ein}"), TTL, || {
            let v = get_json(&self.agent, &format!("{}/organizations/{ein}.json", self.b.propublica), &[], "ProPublica Nonprofit Explorer")?.ok_or_else(|| not_found("no nonprofit with that EIN"))?;
            let o = &v["organization"];
            let mut filings: Vec<Value> = v["filings_with_data"].as_array().map(|a| a.iter().map(|f| json!({
                "year": f["tax_prd_yr"], "revenue": f["totrevenue"], "expenses": f["totfuncexpns"], "assets": f["totassetsend"], "liabilities": f["totliabend"],
                "contributions": f["totcntrbgfts"], "pdf_url": f["pdf_url"].as_str().filter(|u| u.starts_with("https://projects.propublica.org/")),
            })).collect()).unwrap_or_default();
            filings.sort_by(|a, b| a["year"].as_i64().cmp(&b["year"].as_i64()));
            Ok(json!({
                "ein": ein, "name": o["name"], "city": o["city"], "state": o["state"], "ntee": o["ntee_code"], "ruling_date": o["ruling_date"], "subsection": o["subsection_code"],
                "tax_period": o["tax_period"], "assets": o["asset_amount"], "income": o["income_amount"], "revenue": o["revenue_amount"], "filings": filings,
                "url": format!("https://projects.propublica.org/nonprofits/organizations/{ein}"),
            }))
        })
    }

    // ----- Lobbying (LDA) ------------------------------------------------------------------------------------

    fn lobbying(&self, client: &str, year: i32) -> Result<Value, ApiError> {
        self.cached(&format!("lda|{year}|{}", client.to_lowercase()), TTL, || {
            let url = format!("{}/filings/?client_name={}&filing_year={year}&page_size=25", self.b.lda, enc(client));
            let v = get_json(&self.agent, &url, &[], "the Lobbying Disclosure database")?.ok_or_else(|| not_found("not found"))?;
            let rows: Vec<Value> = v["results"].as_array().map(|a| a.iter().map(|f| {
                let mut issues: Vec<String> = f["lobbying_activities"].as_array().map(|l| l.iter().filter_map(|x| x["general_issue_code_display"].as_str()).map(str::to_string).collect()).unwrap_or_default();
                issues.sort();
                issues.dedup();
                let money = |k: &str| f[k].as_str().and_then(|s| s.parse::<f64>().ok());
                json!({
                    "type": f["filing_type_display"], "period": f["filing_period_display"], "year": f["filing_year"], "registrant": f["registrant"]["name"], "client": f["client"]["name"],
                    "income": money("income"), "expenses": money("expenses"), "issues": issues.into_iter().take(8).collect::<Vec<_>>(),
                    "posted": f["dt_posted"].as_str().map(|d| d.chars().take(10).collect::<String>()),
                    "url": f["filing_document_url"].as_str().filter(|u| u.starts_with("https://lda.gov/") || u.starts_with("https://lda.senate.gov/")),
                })
            }).collect()).unwrap_or_default();
            let income: f64 = rows.iter().filter_map(|r| r["income"].as_f64()).sum();
            let expenses: f64 = rows.iter().filter_map(|r| r["expenses"].as_f64()).sum();
            let count = v["count"].as_u64().unwrap_or(rows.len() as u64);
            Ok(json!({ "client": client, "year": year, "count": count, "shown": rows.len(), "partial": count as usize > rows.len(), "income_shown": income, "expenses_shown": expenses, "filings": rows }))
        })
    }

    fn lobbying_counts(&self, client: &str, now: i32) -> Result<Value, ApiError> {
        let mut out = Vec::new();
        for y in (now - 4..=now).rev() {
            let c = self.cached(&format!("lda|n|{y}|{}", client.to_lowercase()), TTL, || {
                let v = get_json(&self.agent, &format!("{}/filings/?client_name={}&filing_year={y}&page_size=1", self.b.lda, enc(client)), &[], "the Lobbying Disclosure database")?.ok_or_else(|| not_found("not found"))?;
                Ok(json!(v["count"].as_u64().unwrap_or(0)))
            })?;
            out.push(json!({ "year": y, "filings": c }));
        }
        out.reverse();
        Ok(json!(out))
    }

    // ----- EU TED ---------------------------------------------------------------------------------------------

    fn ted_post(&self, body: Value) -> Result<Value, ApiError> {
        post_json(&self.agent, &format!("{}/notices/search", self.b.ted), &body, &[], "EU TED")
    }

    fn tenders(&self, org: &str, role: &str, page: u32) -> Result<Value, ApiError> {
        let field = if role == "winner" { "winner-name" } else { "buyer-name" };
        self.cached(&format!("ted|{role}|{page}|{}", org.to_lowercase()), TTL, || {
            let v = self.ted_post(json!({ "query": format!("{field}=\"{org}\""), "fields": ["publication-number", "notice-title", "buyer-name", "winner-name", "publication-date", "notice-type"], "limit": 20, "page": page, "sortField": "publication-date", "sortOrder": "desc" }))?;
            let pick = |x: &Value| -> Option<String> {
                let o = x.as_object()?;
                let arr = o.get("eng").or_else(|| o.values().next())?;
                match arr { Value::Array(a) => a.first().and_then(|s| s.as_str()).map(|s| clip(s, 140)), Value::String(s) => Some(clip(s, 200)), _ => None }
            };
            let rows: Vec<Value> = v["notices"].as_array().map(|a| a.iter().map(|n| {
                let id = n["publication-number"].as_str().unwrap_or("");
                json!({ "id": id, "title": pick(&n["notice-title"]), "buyer": pick(&n["buyer-name"]), "winner": pick(&n["winner-name"]), "published": n["publication-date"].as_str().map(|d| d.chars().take(10).collect::<String>()), "type": n["notice-type"],
                    "url": if id.bytes().all(|b| b.is_ascii_digit() || b == b'-') && !id.is_empty() { Some(format!("https://ted.europa.eu/en/notice/-/detail/{id}")) } else { None } })
            }).collect()).unwrap_or_default();
            Ok(json!({ "org": org, "role": role, "page": page, "total": v["totalNoticeCount"], "notices": rows }))
        })
    }

    fn tender_years(&self, org: &str, role: &str, now: i32) -> Result<Value, ApiError> {
        let field = if role == "winner" { "winner-name" } else { "buyer-name" };
        let mut out = Vec::new();
        for y in (now - 5..=now).rev() {
            let c = self.cached(&format!("ted|n|{role}|{y}|{}", org.to_lowercase()), TTL, || {
                let v = self.ted_post(json!({ "query": format!("{field}=\"{org}\" AND publication-date>={y}0101 AND publication-date<={y}1231"), "fields": ["publication-number"], "limit": 1, "page": 1 }))?;
                Ok(json!(v["totalNoticeCount"].as_u64().unwrap_or(0)))
            })?;
            out.push(json!({ "year": y, "notices": c }));
        }
        out.reverse();
        Ok(json!(out))
    }
}

#[derive(Deserialize)]
struct AwardsQ {
    org: String,
    kind: Option<String>,
    years: Option<i32>,
}
async fn awards(State(st): State<Shared>, Query(q): Query<AwardsQ>) -> Result<Json<Value>, ApiError> {
    let org = valid_org(&q.org)?;
    let kind = match q.kind.as_deref() { None | Some("contracts") => "contracts", Some("grants") => "grants", _ => return Err(bad("kind must be contracts or grants")) };
    let years = q.years.unwrap_or(5).clamp(1, 15);
    Ok(Json(blocking(move || st.awards(&org, kind, years)).await?))
}

#[derive(Deserialize)]
struct NpQ {
    q: Option<String>,
    ein: Option<String>,
}
async fn nonprofit(State(st): State<Shared>, Query(q): Query<NpQ>) -> Result<Json<Value>, ApiError> {
    if let Some(e) = &q.ein {
        let ein = valid_ein(e).ok_or_else(|| bad("an EIN is 9 digits"))?;
        return Ok(Json(blocking(move || st.nonprofit(&ein)).await?));
    }
    let text = valid_org(q.q.as_deref().unwrap_or(""))?;
    Ok(Json(blocking(move || st.nonprofit_search(&text)).await?))
}

#[derive(Deserialize)]
struct LobbyQ {
    org: String,
    year: Option<i32>,
}
async fn lobbying(State(st): State<Shared>, Query(q): Query<LobbyQ>) -> Result<Json<Value>, ApiError> {
    let org = valid_org(&q.org)?;
    let now = current_year();
    let year = q.year.unwrap_or(now - 1);
    if !(1999..=now).contains(&year) {
        return Err(bad(format!("year must be between 1999 and {now}")));
    }
    Ok(Json(blocking(move || {
        let mut v = st.lobbying(&org, year)?;
        v["by_year"] = st.lobbying_counts(&org, now)?;
        Ok(v)
    }).await?))
}

#[derive(Deserialize)]
struct TedQ {
    org: String,
    role: Option<String>,
    page: Option<u32>,
}
async fn tenders(State(st): State<Shared>, Query(q): Query<TedQ>) -> Result<Json<Value>, ApiError> {
    let org = valid_org(&q.org)?;
    let role = match q.role.as_deref() { None | Some("buyer") => "buyer", Some("winner") => "winner", _ => return Err(bad("role must be buyer or winner")) };
    let page = q.page.unwrap_or(1).clamp(1, 50);
    Ok(Json(blocking(move || {
        let mut v = st.tenders(&org, role, page)?;
        if page == 1 {
            v["by_year"] = st.tender_years(&org, role, current_year())?;
        }
        Ok(v)
    }).await?))
}

async fn tools() -> Json<Value> {
    let org = json!({ "org": { "type": "string", "description": "organisation name" } });
    Json(json!([
        { "name": "money_awards", "description": "US federal contract or grant awards to an organisation (USAspending): totals by fiscal year, top awarding agencies and largest awards. Organisation recipients only.",
          "method": "GET", "path": "api/awards?org={org}&kind={kind}&years={years}", "parameters": { "type": "object", "properties": { "org": org["org"], "kind": { "type": "string", "description": "contracts (default) or grants" }, "years": { "type": "integer" } }, "required": ["org"] } },
        { "name": "money_nonprofit", "description": "US nonprofit organisations (ProPublica Nonprofit Explorer): search by name, or pass an EIN for Form 990 totals (revenue, expenses, assets) by year.",
          "method": "GET", "path": "api/nonprofit?q={q}&ein={ein}", "parameters": { "type": "object", "properties": { "q": { "type": "string", "description": "name to search" }, "ein": { "type": "string", "description": "9-digit EIN" } } } },
        { "name": "money_lobbying", "description": "US federal lobbying filings (Senate/House LDA) where the named organisation is the client: filings per year, firms hired, amounts and issue areas. No lobbyist names.",
          "method": "GET", "path": "api/lobbying?org={org}&year={year}", "parameters": { "type": "object", "properties": { "org": org["org"], "year": { "type": "integer" } }, "required": ["org"] } },
        { "name": "money_tenders", "description": "EU public procurement notices (TED) where the organisation is the buyer or a winner, with yearly notice counts.",
          "method": "GET", "path": "api/tenders?org={org}&role={role}&page={page}", "parameters": { "type": "object", "properties": { "org": org["org"], "role": { "type": "string", "description": "buyer (default) or winner" }, "page": { "type": "integer" } }, "required": ["org"] } },
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

pub fn app(st: Shared) -> Router {
    let open = st.open;
    Router::new()
        .route("/api/awards", get(awards))
        .route("/api/nonprofit", get(nonprofit))
        .route("/api/lobbying", get(lobbying))
        .route("/api/tenders", get(tenders))
        .route_layer(middleware::from_fn_with_state(open, util::gate))
        .route("/tools", get(tools))
        .route("/", get(page))
        .with_state(st)
}

pub fn new_state(b: Bases, open: bool, dir: Option<PathBuf>, gap: Duration) -> Shared {
    let cache = Cache::new(dir, 24 << 20);
    cache.trim(Duration::from_secs(3 * 86400));
    Arc::new(AppState { b, open, agent: osnt_common::http_agent("osnt-money-trail/0.1 (+https://github.com/ogden-marrow/osnt-hub)"), cache, spacer: Spacer::new(gap) })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let st = new_state(
        Bases::live(),
        env::var("OSNT_MONEY_INSECURE_LOCAL").ok().as_deref() == Some("1"),
        env::var("OSNT_MONEY_STATE").ok().filter(|s| !s.is_empty()).map(PathBuf::from),
        Duration::from_millis(400),
    );
    let addr: SocketAddr = env::var("OSNT_MONEY_BIND").unwrap_or_else(|_| "127.0.0.1:8143".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("money-trail plugin on http://{addr}");
    axum::serve(listener, app(st)).await?;
    Ok(())
}

#[cfg(test)]
mod tests;

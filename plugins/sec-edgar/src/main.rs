//! SEC EDGAR plugin: company lookup, filing timeline, headline XBRL facts and subsidiary-list links.
//!
//! Company-level data only. SEC requires every automated client to identify itself, so the plugin refuses to call SEC
//! until the SEC_CONTACT declaration (an email address or URL) is set. Filers that are individuals (Forms 3/4/5 filers)
//! get no pages here; only the company's own filings are listed, as metadata and links.

mod cache;
mod util;

use std::{
    env,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
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
use util::{ApiError, Spacer, bad, blocking, get_json, not_found, now_epoch};

const PAGE: &str = include_str!("../assets/index.html");

pub struct Config {
    pub data_base: String,
    pub www_base: String,
    pub gap: Duration,
    pub open: bool,
}

pub struct AppState {
    cfg: Config,
    cache: Cache,
    spacer: Spacer,
    agent: Mutex<Option<(String, ureq::Agent)>>,
    contact: Box<dyn Fn() -> Option<String> + Send + Sync>,
}
type Shared = Arc<AppState>;

// ---------------------------------------------------------------------------------------------------------------
// Pure helpers (unit tested)

/// "320193", "CIK0000320193" -> "0000320193". Rejects zero, non-digits and more than ten digits.
pub fn parse_cik(s: &str) -> Option<String> {
    let t = s.trim();
    let t = t.strip_prefix("CIK").or_else(|| t.strip_prefix("cik")).unwrap_or(t);
    if t.is_empty() || t.len() > 10 || !t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = t.parse().ok()?;
    (n > 0).then(|| format!("{n:010}"))
}

/// The contact SEC asks for in the User-Agent: an email address or a URL, printable ASCII, no control characters.
pub fn validate_contact(c: &str) -> Option<String> {
    let c = c.trim();
    let printable = c.bytes().all(|b| (0x20..0x7f).contains(&b));
    let shaped = c.contains('@') || c.starts_with("http://") || c.starts_with("https://");
    ((5..=120).contains(&c.len()) && printable && shaped).then(|| c.to_string())
}

#[derive(Clone, Debug, PartialEq)]
pub struct Match {
    pub cik: u64,
    pub name: String,
    pub tickers: Vec<(String, String)>,
    pub score: u32,
}

/// Rank rows of company_tickers_exchange.json ([cik, name, ticker, exchange]) against a query.
pub fn rank_tickers(rows: &[Value], q: &str, limit: usize) -> Vec<Match> {
    let q = q.trim().to_lowercase();
    if q.is_empty() {
        return vec![];
    }
    let toks: Vec<&str> = q.split(|c: char| !c.is_alphanumeric()).filter(|t| !t.is_empty()).collect();
    let mut by_cik: Vec<Match> = Vec::new();
    for r in rows {
        let (Some(cik), Some(name), Some(tick)) = (r[0].as_u64(), r[1].as_str(), r[2].as_str()) else { continue };
        let exch = r[3].as_str().unwrap_or("");
        let (nl, tl) = (name.to_lowercase(), tick.to_lowercase());
        let words: Vec<&str> = nl.split(|c: char| !c.is_alphanumeric()).filter(|t| !t.is_empty()).collect();
        let score = if tl == q {
            100
        } else if nl == q {
            95
        } else if q.len() >= 2 && tl.starts_with(&q) {
            80
        } else if nl.starts_with(&q) {
            70
        } else if !toks.is_empty() && toks.iter().all(|t| words.iter().any(|w| w.starts_with(t))) {
            50
        } else {
            continue;
        };
        match by_cik.iter_mut().find(|m| m.cik == cik) {
            Some(m) => {
                m.score = m.score.max(score);
                m.tickers.push((tick.to_string(), exch.to_string()));
            }
            None => by_cik.push(Match { cik, name: name.to_string(), tickers: vec![(tick.to_string(), exch.to_string())], score }),
        }
    }
    by_cik.sort_by(|a, b| b.score.cmp(&a.score).then(a.name.len().cmp(&b.name.len())).then(a.name.cmp(&b.name)));
    by_cik.truncate(limit);
    by_cik
}

fn s(v: &Value) -> Option<String> {
    v.as_str().map(str::trim).filter(|x| !x.is_empty()).map(str::to_string)
}

fn address(a: &Value) -> Option<String> {
    if !a.is_object() {
        return None;
    }
    let region = s(&a["stateOrCountryDescription"]).or_else(|| s(&a["stateOrCountry"]));
    let parts: Vec<String> = [s(&a["street1"]), s(&a["street2"]), s(&a["city"]), region, s(&a["zipCode"])].into_iter().flatten().collect();
    (!parts.is_empty()).then(|| parts.join(", "))
}

fn month_day(mmdd: &str) -> Option<String> {
    if mmdd.len() != 4 || !mmdd.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    const M: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let m: usize = mmdd[..2].parse().ok()?;
    let d: u32 = mmdd[2..].parse().ok()?;
    (1..=12).contains(&m).then(|| format!("{} {}", M[m - 1], d))
}

/// A company filer has an operating entity type, a SIC code or a ticker. Individuals that file Forms 3/4/5 have none.
pub fn is_company(sub: &Value) -> bool {
    let et = sub["entityType"].as_str().unwrap_or("");
    let has_tickers = sub["tickers"].as_array().is_some_and(|t| !t.is_empty());
    et == "operating" || has_tickers || s(&sub["sic"]).is_some_and(|x| x != "0")
}

pub fn build_profile(sub: &Value) -> Value {
    let cik = s(&sub["cik"]).unwrap_or_default();
    let cik10 = parse_cik(&cik).unwrap_or(cik);
    let former: Vec<Value> = sub["formerNames"]
        .as_array()
        .map(|a| a.iter().map(|f| json!({ "name": f["name"], "from": s(&f["from"]).map(|d| d[..d.len().min(10)].to_string()), "to": s(&f["to"]).map(|d| d[..d.len().min(10)].to_string()) })).collect())
        .unwrap_or_default();
    let n_recent = sub["filings"]["recent"]["form"].as_array().map(Vec::len).unwrap_or(0);
    let older: u64 = sub["filings"]["files"].as_array().map(|f| f.iter().filter_map(|x| x["filingCount"].as_u64()).sum()).unwrap_or(0);
    json!({
        "cik": cik10,
        "name": sub["name"],
        "entity_type": s(&sub["entityType"]),
        "sic": s(&sub["sic"]),
        "sic_description": s(&sub["sicDescription"]),
        "category": s(&sub["category"]),
        "fiscal_year_end": s(&sub["fiscalYearEnd"]).and_then(|f| month_day(&f)),
        "state_of_incorporation": s(&sub["stateOfIncorporationDescription"]).or_else(|| s(&sub["stateOfIncorporation"])),
        "tickers": sub["tickers"],
        "exchanges": sub["exchanges"],
        "former_names": former,
        "business_address": address(&sub["addresses"]["business"]),
        "mailing_address": address(&sub["addresses"]["mailing"]),
        "phone": s(&sub["phone"]),
        "website": s(&sub["website"]),
        "recent_filings": n_recent,
        "older_filings_not_listed": older,
        "links": {
            "edgar": format!("https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik10}&owner=include&count=40"),
            "sic": s(&sub["sic"]).map(|c| format!("https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&SIC={c}&owner=include&count=40")),
        },
    })
}

fn form_group(token: &str) -> Option<&'static [&'static str]> {
    Some(match token {
        "annual" => &["10-K", "20-F", "40-F", "10-KSB"],
        "quarterly" => &["10-Q", "10-QSB"],
        "current" => &["8-K", "6-K"],
        "registration" => &["S-1", "S-3", "S-4", "S-8", "F-1", "F-3", "F-4", "424B1", "424B2", "424B3", "424B4", "424B5"],
        "ownership" => &["3", "4", "5", "SC 13D", "SC 13G", "SCHEDULE 13D", "SCHEDULE 13G"],
        _ => return None,
    })
}

fn form_matches(form: &str, wanted: &[String]) -> bool {
    if wanted.is_empty() {
        return true;
    }
    let f = form.to_uppercase();
    let base = f.strip_suffix("/A").unwrap_or(&f);
    wanted.iter().any(|w| w == &f || w == base)
}

fn item_label(code: &str) -> Option<&'static str> {
    Some(match code {
        "1.01" => "Entry into a material agreement",
        "1.02" => "Termination of a material agreement",
        "2.01" => "Completion of acquisition or disposition",
        "2.02" => "Results of operations",
        "2.03" => "Creation of a direct financial obligation",
        "2.05" => "Exit or disposal costs",
        "3.02" => "Unregistered sales of equity",
        "4.01" => "Change of certifying accountant",
        "4.02" => "Non-reliance on prior financials",
        "5.02" => "Officer or director change",
        "5.07" => "Shareholder vote results",
        "7.01" => "Regulation FD disclosure",
        "8.01" => "Other events",
        "9.01" => "Financial statements and exhibits",
        _ => return None,
    })
}

/// Rows from the submissions "recent" columns, newest first, filtered by form. Returns (rows, total matching).
pub fn build_filings(sub: &Value, forms: &[String], limit: usize) -> (Vec<Value>, usize) {
    let r = &sub["filings"]["recent"];
    let cik_num = parse_cik(sub["cik"].as_str().unwrap_or("")).and_then(|c| c.parse::<u64>().ok()).unwrap_or(0);
    let col = |k: &str| r[k].as_array().cloned().unwrap_or_default();
    let (form, acc, date, report, doc, desc, items) = (col("form"), col("accessionNumber"), col("filingDate"), col("reportDate"), col("primaryDocument"), col("primaryDocDescription"), col("items"));
    let mut rows = Vec::new();
    let mut total = 0;
    for i in 0..form.len() {
        let f = form[i].as_str().unwrap_or("");
        if !form_matches(f, forms) {
            continue;
        }
        total += 1;
        if rows.len() >= limit {
            continue;
        }
        let a = acc.get(i).and_then(Value::as_str).unwrap_or("");
        let nodash = a.replace('-', "");
        let d = doc.get(i).and_then(Value::as_str).unwrap_or("");
        let item_codes: Vec<String> = items.get(i).and_then(Value::as_str).unwrap_or("").split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
        let item_rows: Vec<Value> = item_codes.iter().map(|c| json!({ "code": c, "label": item_label(c) })).collect();
        rows.push(json!({
            "form": f,
            "filed": date.get(i).and_then(Value::as_str),
            "period": report.get(i).and_then(Value::as_str).filter(|x| !x.is_empty()),
            "accession": a,
            "description": desc.get(i).and_then(Value::as_str).filter(|x| !x.is_empty()),
            "items": item_rows,
            "document_url": (!d.is_empty() && !nodash.is_empty()).then(|| format!("https://www.sec.gov/Archives/edgar/data/{cik_num}/{nodash}/{d}")),
            "index_url": (!nodash.is_empty()).then(|| format!("https://www.sec.gov/Archives/edgar/data/{cik_num}/{nodash}/{a}-index.htm")),
        }));
    }
    (rows, total)
}

struct Metric {
    key: &'static str,
    label: &'static str,
    duration: bool,
    tags: &'static [(&'static str, &'static str)],
}
const METRICS: &[Metric] = &[
    Metric { key: "revenue", label: "Revenue", duration: true, tags: &[("us-gaap", "Revenues"), ("us-gaap", "RevenueFromContractWithCustomerExcludingAssessedTax"), ("us-gaap", "SalesRevenueNet"), ("us-gaap", "RevenueFromContractWithCustomerIncludingAssessedTax")] },
    Metric { key: "net_income", label: "Net income", duration: true, tags: &[("us-gaap", "NetIncomeLoss"), ("us-gaap", "ProfitLoss")] },
    Metric { key: "operating_income", label: "Operating income", duration: true, tags: &[("us-gaap", "OperatingIncomeLoss")] },
    Metric { key: "assets", label: "Total assets", duration: false, tags: &[("us-gaap", "Assets")] },
    Metric { key: "liabilities", label: "Total liabilities", duration: false, tags: &[("us-gaap", "Liabilities")] },
    Metric { key: "equity", label: "Stockholders' equity", duration: false, tags: &[("us-gaap", "StockholdersEquity"), ("us-gaap", "StockholdersEquityIncludingPortionAttributableToNoncontrollingInterest")] },
    Metric { key: "cash", label: "Cash and equivalents", duration: false, tags: &[("us-gaap", "CashAndCashEquivalentsAtCarryingValue")] },
    Metric { key: "shares", label: "Shares outstanding (cover page)", duration: false, tags: &[("dei", "EntityCommonStockSharesOutstanding")] },
];

/// Days since 1970-01-01 for an ISO date (civil-from-days algorithm), or None if malformed.
pub fn iso_days(d: &str) -> Option<i64> {
    let b: Vec<&str> = d.get(..10)?.split('-').collect();
    if b.len() != 3 {
        return None;
    }
    let (y, m, dd): (i64, i64, i64) = (b[0].parse().ok()?, b[1].parse().ok()?, b[2].parse().ok()?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&dd) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + dd - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe - 719468)
}

/// Annual values from a companyconcept response: full-year facts only, one per period end (latest filing wins).
pub fn facts_series(v: &Value, duration: bool) -> (Vec<Value>, Option<String>) {
    let Some(units) = v["units"].as_object() else { return (vec![], None) };
    let Some((unit, arr)) = ["USD", "shares", "USD/shares"].iter().find_map(|u| units.get(*u).map(|a| (u.to_string(), a))).or_else(|| units.iter().next().map(|(k, a)| (k.clone(), a))) else { return (vec![], None) };
    let mut by_end: Vec<Value> = Vec::new();
    for e in arr.as_array().map(Vec::as_slice).unwrap_or_default() {
        if e["fp"].as_str() != Some("FY") {
            continue;
        }
        let (Some(end), Some(val)) = (e["end"].as_str(), e["val"].as_f64()) else { continue };
        if duration {
            let span = e["start"].as_str().and_then(iso_days).zip(iso_days(end)).map(|(a, b)| b - a);
            if !span.is_some_and(|d| (330..=400).contains(&d)) {
                continue;
            }
        }
        let row = json!({ "end": end, "value": val, "fy": e["fy"], "form": e["form"], "filed": e["filed"], "accession": e["accn"] });
        match by_end.iter_mut().find(|r| r["end"] == end) {
            Some(r) => {
                if row["filed"].as_str() > r["filed"].as_str() {
                    *r = row;
                }
            }
            None => by_end.push(row),
        }
    }
    by_end.sort_by(|a, b| a["end"].as_str().cmp(&b["end"].as_str()));
    let n = by_end.len();
    (by_end.split_off(n.saturating_sub(12)), Some(unit))
}

/// The Exhibit 21 (subsidiaries) document in a filing index.json, by file name.
pub fn find_exhibit21(index: &Value) -> Option<String> {
    index["directory"]["item"].as_array()?.iter().filter_map(|i| i["name"].as_str()).find(|n| {
        let l = n.to_lowercase();
        (l.ends_with(".htm") || l.ends_with(".html") || l.ends_with(".txt")) && ["ex21", "ex-21", "exhibit21", "exhibit_21", "exhibit-21"].iter().any(|p| l.contains(p)) && !l.contains("ex210") && !l.contains("exhibit210")
    }).map(str::to_string)
}

// ---------------------------------------------------------------------------------------------------------------
// Upstream access

impl AppState {
    fn agent(&self) -> Result<ureq::Agent, ApiError> {
        let contact = (self.contact)().and_then(|c| validate_contact(&c)).ok_or_else(|| {
            ApiError(StatusCode::SERVICE_UNAVAILABLE, "SEC requires every automated client to identify itself. Set SEC_CONTACT (your email address or a URL) on the Credentials page; nothing is sent to SEC until it is set.".into())
        })?;
        let mut g = self.agent.lock().map_err(|_| util::upstream("internal error"))?;
        if let Some((c, a)) = g.as_ref() {
            if *c == contact {
                return Ok(a.clone());
            }
        }
        let a = osnt_common::http_agent(&format!("osnt-sec-edgar/0.1 {contact}"));
        *g = Some((contact, a.clone()));
        Ok(a)
    }

    /// Cached GET of a JSON document at SEC. `Ok(None)` for 404. Falls back to an older cached copy if SEC fails.
    fn fetch(&self, url: &str, ttl: Duration) -> Result<Option<Value>, ApiError> {
        let agent = self.agent()?;
        if let Some(v) = self.cache.get(url, ttl).and_then(|b| serde_json::from_slice(&b).ok()) {
            return Ok(Some(v));
        }
        self.spacer.wait();
        match get_json(&agent, url, &[], "SEC EDGAR") {
            Ok(Some(v)) => {
                if let Ok(b) = serde_json::to_vec(&v) {
                    self.cache.put(url, &b);
                }
                Ok(Some(v))
            }
            Ok(None) => Ok(None),
            Err(e) => match self.cache.get_stale(url).and_then(|b| serde_json::from_slice(&b).ok()) {
                Some(v) => Ok(Some(v)),
                None => Err(e),
            },
        }
    }

    fn submissions(&self, cik10: &str) -> Result<Value, ApiError> {
        let v = self.fetch(&format!("{}/submissions/CIK{cik10}.json", self.cfg.data_base), Duration::from_secs(3600))?.ok_or_else(|| not_found("no SEC filer with that CIK"))?;
        if !is_company(&v) {
            return Err(ApiError(StatusCode::FORBIDDEN, "that CIK belongs to a filer that is not an operating company, issuer or fund; person pages are not provided".into()));
        }
        Ok(v)
    }

    fn tickers(&self) -> Result<Vec<Value>, ApiError> {
        let v = self.fetch(&format!("{}/files/company_tickers_exchange.json", self.cfg.www_base), Duration::from_secs(12 * 3600))?.ok_or_else(|| util::upstream("SEC ticker list is unavailable"))?;
        Ok(v["data"].as_array().cloned().unwrap_or_default())
    }

    fn facts(&self, cik10: &str, metric: &Metric) -> Result<Value, ApiError> {
        let mut merged: Vec<Value> = Vec::new();
        let mut unit = None;
        let mut used = Vec::new();
        let today = (now_epoch() / 86400) as i64;
        for (tax, tag) in metric.tags {
            let url = format!("{}/api/xbrl/companyconcept/CIK{cik10}/{tax}/{tag}.json", self.cfg.data_base);
            let Some(v) = self.fetch(&url, Duration::from_secs(6 * 3600))? else { continue };
            let (series, u) = facts_series(&v, metric.duration);
            if series.is_empty() {
                continue;
            }
            used.push(format!("{tax}:{tag}"));
            unit = unit.or(u);
            for row in series {
                if !merged.iter().any(|r| r["end"] == row["end"]) {
                    merged.push(row);
                }
            }
            let fresh = merged.last().and_then(|r| r["end"].as_str()).and_then(iso_days).is_some_and(|d| today - d < 550);
            if merged.len() >= 6 && fresh {
                break;
            }
        }
        merged.sort_by(|a, b| a["end"].as_str().cmp(&b["end"].as_str()));
        let n = merged.len();
        let merged = merged.split_off(n.saturating_sub(12));
        Ok(json!({ "metric": metric.key, "label": metric.label, "unit": unit, "tags": used, "series": merged }))
    }
}

// ---------------------------------------------------------------------------------------------------------------
// HTTP handlers

#[derive(Deserialize)]
struct SearchQ {
    q: String,
    limit: Option<usize>,
}
#[derive(Deserialize)]
struct CompanyQ {
    cik: Option<String>,
    q: Option<String>,
}
#[derive(Deserialize)]
struct FilingsQ {
    cik: String,
    form: Option<String>,
    limit: Option<usize>,
}
#[derive(Deserialize)]
struct FactsQ {
    cik: String,
    metric: Option<String>,
}
#[derive(Deserialize)]
struct CikQ {
    cik: String,
}

fn need_cik(s: &str) -> Result<String, ApiError> {
    parse_cik(s).ok_or_else(|| bad("CIK must be 1 to 10 digits"))
}

async fn search(State(st): State<Shared>, Query(q): Query<SearchQ>) -> Result<Json<Value>, ApiError> {
    let text = q.q.trim().to_string();
    if text.is_empty() || text.len() > 100 {
        return Err(bad("enter a company name, ticker or CIK (up to 100 characters)"));
    }
    let limit = q.limit.unwrap_or(15).clamp(1, 50);
    Ok(Json(blocking(move || {
        if let Some(cik10) = parse_cik(&text).filter(|_| text.bytes().all(|b| b.is_ascii_digit()) || text.to_lowercase().starts_with("cik")) {
            let sub = st.submissions(&cik10)?;
            let p = build_profile(&sub);
            return Ok(json!({ "query": text, "matches": [{ "cik": cik10, "name": p["name"], "tickers": sub["tickers"], "exchanges": sub["exchanges"], "score": 100 }], "listed_only": false }));
        }
        let rows = st.tickers()?;
        let m: Vec<Value> = rank_tickers(&rows, &text, limit)
            .into_iter()
            .map(|m| json!({ "cik": format!("{:010}", m.cik), "name": m.name, "tickers": m.tickers.iter().map(|t| t.0.clone()).collect::<Vec<_>>(), "exchanges": m.tickers.iter().map(|t| t.1.clone()).collect::<Vec<_>>(), "score": m.score }))
            .collect();
        Ok(json!({ "query": text, "matches": m, "listed_only": true,
            "note": "Name and ticker search covers companies with a listed ticker. For other filers search by CIK." }))
    }).await?))
}

async fn company(State(st): State<Shared>, Query(q): Query<CompanyQ>) -> Result<Json<Value>, ApiError> {
    Ok(Json(blocking(move || {
        let cik10 = match (&q.cik, &q.q) {
            (Some(c), _) => need_cik(c)?,
            (None, Some(text)) if !text.trim().is_empty() => match parse_cik(text) {
                Some(c) if text.trim().bytes().all(|b| b.is_ascii_digit()) => c,
                _ => {
                    let rows = st.tickers()?;
                    let m = rank_tickers(&rows, text, 5);
                    let top = m.first().ok_or_else(|| not_found("no listed company matches that name or ticker; try a CIK"))?;
                    let alts: Vec<Value> = m.iter().skip(1).map(|x| json!({ "cik": format!("{:010}", x.cik), "name": x.name, "tickers": x.tickers.iter().map(|t| t.0.clone()).collect::<Vec<_>>() })).collect();
                    let sub = st.submissions(&format!("{:010}", top.cik))?;
                    return Ok(json!({ "company": build_profile(&sub), "other_matches": alts }));
                }
            },
            _ => return Err(bad("give cik or q")),
        };
        let sub = st.submissions(&cik10)?;
        Ok(json!({ "company": build_profile(&sub), "other_matches": [] }))
    }).await?))
}

async fn filings(State(st): State<Shared>, Query(q): Query<FilingsQ>) -> Result<Json<Value>, ApiError> {
    let cik10 = need_cik(&q.cik)?;
    let limit = q.limit.unwrap_or(40).clamp(1, 200);
    let mut wanted: Vec<String> = Vec::new();
    for t in q.form.as_deref().unwrap_or("").split(',').map(str::trim).filter(|t| !t.is_empty()) {
        if t.len() > 20 || !t.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b' ' | b'/')) {
            return Err(bad("form must be a form type such as 10-K, or one of annual, quarterly, current, registration, ownership"));
        }
        match form_group(&t.to_lowercase()) {
            Some(g) => wanted.extend(g.iter().map(|x| x.to_string())),
            None => wanted.push(t.to_uppercase()),
        }
    }
    Ok(Json(blocking(move || {
        let sub = st.submissions(&cik10)?;
        let (rows, total) = build_filings(&sub, &wanted, limit);
        Ok(json!({ "cik": cik10, "name": sub["name"], "filter": wanted, "total_matching": total, "shown": rows.len(), "filings": rows,
            "note": "Recent filings only (up to about 1,000). Filings by individuals, such as Forms 3, 4 and 5, are listed as filing metadata only." }))
    }).await?))
}

async fn latest(State(st): State<Shared>, Query(q): Query<CikQ>) -> Result<Json<Value>, ApiError> {
    let cik10 = need_cik(&q.cik)?;
    Ok(Json(blocking(move || {
        let sub = st.submissions(&cik10)?;
        let mut out = serde_json::Map::new();
        for f in ["10-K", "10-Q", "8-K", "20-F", "40-F", "6-K", "S-1"] {
            let (rows, _) = build_filings(&sub, &[f.to_string()], 1);
            if let Some(r) = rows.into_iter().next() {
                out.insert(f.to_string(), r);
            }
        }
        Ok(json!({ "cik": cik10, "name": sub["name"], "latest": out }))
    }).await?))
}

async fn facts(State(st): State<Shared>, Query(q): Query<FactsQ>) -> Result<Json<Value>, ApiError> {
    let cik10 = need_cik(&q.cik)?;
    let key = q.metric.unwrap_or_else(|| "revenue".into());
    let metric = METRICS.iter().find(|m| m.key == key).ok_or_else(|| bad(format!("metric must be one of: {}", METRICS.iter().map(|m| m.key).collect::<Vec<_>>().join(", "))))?;
    Ok(Json(blocking(move || {
        st.submissions(&cik10)?; // also enforces the company-only rule
        st.facts(&cik10, metric)
    }).await?))
}

async fn exhibit21(State(st): State<Shared>, Query(q): Query<CikQ>) -> Result<Json<Value>, ApiError> {
    let cik10 = need_cik(&q.cik)?;
    Ok(Json(blocking(move || {
        let sub = st.submissions(&cik10)?;
        let (rows, _) = build_filings(&sub, &form_group("annual").unwrap().iter().map(|x| x.to_string()).collect::<Vec<_>>(), 1);
        let Some(f) = rows.into_iter().next() else { return Ok(json!({ "cik": cik10, "filing": null, "exhibit21_url": null, "note": "No annual report in the recent filings." })) };
        let nodash = f["accession"].as_str().unwrap_or("").replace('-', "");
        let cik_num: u64 = cik10.parse().unwrap_or(0);
        let idx = st.fetch(&format!("{}/Archives/edgar/data/{cik_num}/{nodash}/index.json", st.cfg.www_base), Duration::from_secs(24 * 3600))?;
        let ex = idx.as_ref().and_then(find_exhibit21).map(|n| format!("https://www.sec.gov/Archives/edgar/data/{cik_num}/{nodash}/{n}"));
        Ok(json!({ "cik": cik10, "filing": { "form": f["form"], "filed": f["filed"], "index_url": f["index_url"] }, "exhibit21_url": ex,
            "note": if ex.is_some() { "Exhibit 21 lists the company's subsidiaries as filed." } else { "No Exhibit 21 file was found in that filing's index; open the filing index to check." } }))
    }).await?))
}

async fn status(State(st): State<Shared>) -> Json<Value> {
    let ok = (st.contact)().and_then(|c| validate_contact(&c)).is_some();
    Json(json!({ "contact_set": ok, "credentials_page": "/p/credentials/" }))
}

async fn tools() -> Json<Value> {
    let p = |props: Value, req: Value| json!({ "type": "object", "properties": props, "required": req });
    Json(json!([
        { "name": "sec_company", "description": "Look up a US-listed company at SEC EDGAR by name, ticker or CIK: profile (SIC code, state of incorporation, former names, company addresses) plus other close matches.",
          "method": "GET", "path": "api/company?q={q}", "parameters": p(json!({ "q": { "type": "string", "description": "company name, ticker or CIK" } }), json!(["q"])) },
        { "name": "sec_filings", "description": "Recent SEC filings of a company (newest first) with links; filter by form type (10-K, 8-K, ...) or group (annual, quarterly, current, registration, ownership).",
          "method": "GET", "path": "api/filings?cik={cik}&form={form}&limit={limit}", "parameters": p(json!({ "cik": { "type": "string" }, "form": { "type": "string", "description": "optional form type or group" }, "limit": { "type": "integer" } }), json!(["cik"])) },
        { "name": "sec_facts", "description": "Annual XBRL values for one headline metric: revenue, net_income, operating_income, assets, liabilities, equity, cash or shares.",
          "method": "GET", "path": "api/facts?cik={cik}&metric={metric}", "parameters": p(json!({ "cik": { "type": "string" }, "metric": { "type": "string" } }), json!(["cik"])) },
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

pub fn app(state: Shared) -> Router {
    let open = state.cfg.open;
    Router::new()
        .route("/api/status", get(status))
        .route("/api/search", get(search))
        .route("/api/company", get(company))
        .route("/api/filings", get(filings))
        .route("/api/latest", get(latest))
        .route("/api/facts", get(facts))
        .route("/api/exhibit21", get(exhibit21))
        .route_layer(middleware::from_fn_with_state(open, util::gate))
        .route("/tools", get(tools))
        .route("/", get(page))
        .with_state(state)
}

pub fn new_state(cfg: Config, state_dir: Option<PathBuf>, contact: Box<dyn Fn() -> Option<String> + Send + Sync>) -> Shared {
    let cache = Cache::new(state_dir, 24 << 20);
    cache.trim(Duration::from_secs(3 * 86400));
    let gap = cfg.gap;
    Arc::new(AppState { cfg, cache, spacer: Spacer::new(gap), agent: Mutex::new(None), contact })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let state_dir = env::var("OSNT_SEC_EDGAR_STATE").ok().filter(|s| !s.is_empty()).map(PathBuf::from);
    let memo: Mutex<Option<(Instant, Option<String>)>> = Mutex::new(None);
    // The declared contact is read from the credentials plugin and remembered for a minute.
    let contact = Box::new(move || {
        let mut m = memo.lock().ok()?;
        if let Some((t, v)) = m.as_ref() {
            if t.elapsed() < Duration::from_secs(60) {
                return v.clone();
            }
        }
        let v = osnt_common::secret("SEC_CONTACT");
        *m = Some((Instant::now(), v.clone()));
        v
    });
    let cfg = Config {
        data_base: "https://data.sec.gov".into(),
        www_base: "https://www.sec.gov".into(),
        gap: Duration::from_millis(150),
        open: env::var("OSNT_SEC_EDGAR_INSECURE_LOCAL").ok().as_deref() == Some("1"),
    };
    let st = new_state(cfg, state_dir, contact);
    let addr: SocketAddr = env::var("OSNT_SEC_EDGAR_BIND").unwrap_or_else(|_| "127.0.0.1:8139".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("sec-edgar plugin on http://{addr}");
    axum::serve(listener, app(st)).await?;
    Ok(())
}

#[cfg(test)]
mod tests;

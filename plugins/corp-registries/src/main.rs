//! Company registries and ownership: GLEIF, Wikidata and national open registries (Norway, Czechia, Finland, Denmark),
//! plus Companies House, OpenCorporates and OCCRP Aleph when a key is configured.
//!
//! Company-level only. Officers, directors, owners and shareholders who are individuals are never requested or shown;
//! sole proprietors and protected records are filtered out of every source.

mod cache;
mod sources;
mod util;

use std::{
    collections::HashMap,
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
use sources::*;
use util::{ApiError, bad, blocking, enc, get_json, post_json};

const PAGE: &str = include_str!("../assets/index.html");

pub struct Bases {
    pub gleif: String,
    pub wd_api: String,
    pub wd_sparql: String,
    pub brreg: String,
    pub ares: String,
    pub prh: String,
    pub cvr: String,
    pub ch: String,
    pub oc: String,
    pub aleph: String,
}
impl Bases {
    pub fn live() -> Bases {
        Bases {
            gleif: "https://api.gleif.org/api/v1".into(),
            wd_api: "https://www.wikidata.org/w/api.php".into(),
            wd_sparql: "https://query.wikidata.org/sparql".into(),
            brreg: "https://data.brreg.no/enhetsregisteret/api".into(),
            ares: "https://ares.gov.cz/ekonomicke-subjekty-v-be/rest/ekonomicke-subjekty".into(),
            prh: "https://avoindata.prh.fi/opendata-ytj-api/v3/companies".into(),
            cvr: "https://cvrapi.dk/api".into(),
            ch: "https://api.company-information.service.gov.uk".into(),
            oc: "https://api.opencorporates.com/v0.4".into(),
            aleph: "https://aleph.occrp.org/api/2".into(),
        }
    }
}

/// GLEIF's full-text order is loose (funds and sub-entities before the parent company). Rank names that contain the whole
/// query first, then names that start with it, then the shortest (the plain "Acme ASA" before "Acme Pension Fund 3").
pub fn rank_gleif(cards: &mut [Card], ql: &str) {
    cards.sort_by_key(|c| { let n = c.name.to_lowercase(); (!n.contains(ql), !n.starts_with(ql), n.chars().count()) });
}

pub struct AppState {
    b: Bases,
    open: bool,
    agent: ureq::Agent,
    cache: Cache,
    secret: Box<dyn Fn(&str) -> Option<String> + Send + Sync>,
    memo: Mutex<HashMap<String, (Instant, Option<String>)>>,
}
type Shared = Arc<AppState>;

pub const SOURCES: &[(&str, &str)] = &[
    ("gleif", "GLEIF (legal entity identifiers)"),
    ("wikidata", "Wikidata"),
    ("brreg", "Norway: Brønnøysund registers"),
    ("ares", "Czechia: ARES"),
    ("prh", "Finland: PRH / YTJ"),
    ("cvr", "Denmark: CVR (via cvrapi.dk)"),
    ("companies-house", "UK: Companies House (key)"),
    ("opencorporates", "OpenCorporates (token)"),
    ("aleph", "OCCRP Aleph (key)"),
];
fn key_name(src: &str) -> Option<&'static str> {
    Some(match src {
        "companies-house" => "COMPANIES_HOUSE_API_KEY",
        "opencorporates" => "OPENCORPORATES_API_TOKEN",
        "aleph" => "ALEPH_API_KEY",
        _ => return None,
    })
}

impl AppState {
    fn key(&self, name: &str) -> Option<String> {
        {
            let m = self.memo.lock().ok()?;
            if let Some((t, v)) = m.get(name) {
                if t.elapsed() < Duration::from_secs(60) {
                    return v.clone();
                }
            }
        }
        let v = (self.secret)(name).filter(|v| !v.trim().is_empty() && v.len() < 300 && v.bytes().all(|b| (0x21..0x7f).contains(&b)));
        self.memo.lock().ok()?.insert(name.to_string(), (Instant::now(), v.clone()));
        v
    }

    /// Cache wrapper: fresh hit, else fetch, else fall back to an old copy. `ckey` never contains secrets.
    fn cached(&self, ckey: &str, ttl: Duration, f: impl FnOnce() -> Result<Option<Value>, ApiError>) -> Result<Option<Value>, ApiError> {
        if let Some(v) = self.cache.get(ckey, ttl).and_then(|b| serde_json::from_slice(&b).ok()) {
            return Ok(Some(v));
        }
        match f() {
            Ok(Some(v)) => {
                self.cache.put(ckey, v.to_string().as_bytes());
                Ok(Some(v))
            }
            Ok(None) => Ok(None),
            Err(e) => match self.cache.get_stale(ckey).and_then(|b| serde_json::from_slice(&b).ok()) {
                Some(v) => Ok(Some(v)),
                None => Err(e),
            },
        }
    }

    fn jget(&self, ckey: &str, url: &str, headers: &[(&str, &str)], what: &str) -> Result<Option<Value>, ApiError> {
        self.cached(ckey, Duration::from_secs(6 * 3600), || get_json(&self.agent, url, headers, what))
    }

    // ----- search sources -------------------------------------------------------------------------------------

    fn gleif_search(&self, q: &str) -> Result<(Vec<Card>, usize), ApiError> {
        let up = q.trim().to_uppercase();
        let v = if valid_lei(&up) {
            self.jget(&format!("gleif|lei|{up}"), &format!("{}/lei-records/{up}", self.b.gleif), &[], "GLEIF")?.map(|d| json!({ "data": [d["data"].clone()] }))
        } else {
            self.jget(&format!("gleif|ft50|{}", q.to_lowercase()), &format!("{}/lei-records?filter%5Bfulltext%5D={}&page%5Bsize%5D=50", self.b.gleif, enc(q)), &[], "GLEIF")?
        };
        let rows = v.as_ref().and_then(|v| v["data"].as_array()).cloned().unwrap_or_default();
        let total = rows.len();
        let mut cards: Vec<Card> = rows.iter().filter_map(gleif_card).collect();
        // GLEIF's full-text order is loose: put names that contain the whole query first.
        let visible = cards.len();
        let ql = q.trim().to_lowercase();
        if !valid_lei(&up) {
            rank_gleif(&mut cards, &ql);
            cards.truncate(15);
        }
        let hidden = total - visible;
        Ok((cards, hidden))
    }

    fn wd_sparql(&self, query: &str) -> Result<Vec<Value>, ApiError> {
        let url = format!("{}?format=json&query={}", self.b.wd_sparql, enc(query));
        // The organisation filter walks the class hierarchy and can take several seconds (and Wikidata answers 429 when
        // busy), so allow a longer timeout and one polite retry instead of failing the whole Wikidata column.
        let v = self.cached(&format!("wdq|{query}"), Duration::from_secs(6 * 3600), || {
            for attempt in 0..2 {
                let r = self.agent.get(&url).header("Accept", "application/sparql-results+json").config().timeout_global(Some(Duration::from_secs(40))).build().call();
                match r {
                    Ok(res) => return util::read_value("Wikidata", res).map(Some),
                    Err(ureq::Error::StatusCode(429)) if attempt == 0 => std::thread::sleep(Duration::from_secs(3)),
                    Err(ureq::Error::StatusCode(404)) => return Ok(None),
                    Err(e) => return Err(util::map_ureq("Wikidata", e)),
                }
            }
            Err(util::upstream("Wikidata is rate limiting requests (HTTP 429); wait a little and try again"))
        })?;
        Ok(v.and_then(|v| v["results"]["bindings"].as_array().cloned()).unwrap_or_default())
    }

    fn wikidata_search(&self, q: &str) -> Result<(Vec<Card>, usize), ApiError> {
        let url = format!("{}?action=wbsearchentities&search={}&language=en&type=item&limit=8&format=json", self.b.wd_api, enc(q));
        let v = self.jget(&format!("wds|{}", q.to_lowercase()), &url, &[], "Wikidata")?;
        let hits: Vec<Value> = v.and_then(|v| v["search"].as_array().cloned()).unwrap_or_default();
        let ids: Vec<&str> = hits.iter().filter_map(|h| h["id"].as_str()).filter(|i| valid_qid(i)).collect();
        if ids.is_empty() {
            return Ok((vec![], 0));
        }
        // Keep only organisations: instance of (a subclass of) organization, and never a human.
        let values = ids.iter().map(|i| format!("wd:{i}")).collect::<Vec<_>>().join(" ");
        let rows = self.wd_sparql(&format!("SELECT DISTINCT ?c WHERE {{ VALUES ?c {{ {values} }} ?c wdt:P31/wdt:P279* wd:Q43229 . FILTER NOT EXISTS {{ ?c wdt:P31 wd:Q5 }} }}"))?;
        let ok: Vec<String> = rows.iter().filter_map(|r| r["c"]["value"].as_str()).map(|u| u.rsplit('/').next().unwrap_or("").to_string()).collect();
        let cards: Vec<Card> = hits.iter().filter(|h| h["id"].as_str().is_some_and(|i| ok.iter().any(|o| o == i))).filter_map(|h| {
            let id = h["id"].as_str()?.to_string();
            Some(Card { source: "wikidata", name: h["label"].as_str()?.to_string(), status: None, form: None, address: None, founded: None, industry: h["description"].as_str().map(str::to_string), country: None, url: format!("https://www.wikidata.org/wiki/{id}"), parent: None, id })
        }).collect();
        let hidden = hits.len() - cards.len();
        Ok((cards, hidden))
    }

    fn brreg_search(&self, q: &str) -> Result<(Vec<Card>, usize), ApiError> {
        let digits: String = q.chars().filter(|c| !c.is_whitespace()).collect();
        let (url, single) = if digits.len() == 9 && digits.bytes().all(|b| b.is_ascii_digit()) { (format!("{}/enheter/{digits}", self.b.brreg), true) } else { (format!("{}/enheter?navn={}&size=10", self.b.brreg, enc(q)), false) };
        let v = self.jget(&format!("brreg|{}", url.split("api/").last().unwrap_or(&url)), &url, &[], "Brønnøysund registers")?;
        let rows: Vec<Value> = match v { Some(v) if single => vec![v], Some(v) => v["_embedded"]["enheter"].as_array().cloned().unwrap_or_default(), None => vec![] };
        let cards: Vec<Card> = rows.iter().filter_map(brreg_card).collect();
        let h = rows.len() - cards.len();
        Ok((cards, h))
    }

    fn ares_search(&self, q: &str) -> Result<(Vec<Card>, usize), ApiError> {
        let t = q.trim();
        let rows: Vec<Value> = if t.len() == 8 && t.bytes().all(|b| b.is_ascii_digit()) {
            self.jget(&format!("ares|ico|{t}"), &format!("{}/{t}", self.b.ares), &[], "ARES")?.into_iter().collect()
        } else {
            let body = json!({ "obchodniJmeno": t, "start": 0, "pocet": 10 });
            let ckey = format!("ares|name|{}", t.to_lowercase());
            self.cached(&ckey, Duration::from_secs(6 * 3600), || post_json(&self.agent, &format!("{}/vyhledat", self.b.ares), &body, &[], "ARES").map(Some))?
                .and_then(|v| v["ekonomickeSubjekty"].as_array().cloned()).unwrap_or_default()
        };
        let cards: Vec<Card> = rows.iter().filter_map(ares_card).collect();
        let h = rows.len() - cards.len();
        Ok((cards, h))
    }

    fn prh_search(&self, q: &str) -> Result<(Vec<Card>, usize), ApiError> {
        let t = q.trim();
        let is_id = t.len() == 9 && t.as_bytes()[7] == b'-' && t.bytes().enumerate().all(|(i, b)| i == 7 || b.is_ascii_digit());
        let url = if is_id { format!("{}?businessId={t}", self.b.prh) } else { format!("{}?name={}&maxResults=10", self.b.prh, enc(t)) };
        let v = self.jget(&format!("prh|{}", t.to_lowercase()), &url, &[], "PRH (Finland)")?;
        let rows = v.and_then(|v| v["companies"].as_array().cloned()).unwrap_or_default();
        let cards: Vec<Card> = rows.iter().filter_map(prh_card).collect();
        let h = rows.len() - cards.len();
        Ok((cards, h))
    }

    fn cvr_search(&self, q: &str) -> Result<(Vec<Card>, usize), ApiError> {
        let url = format!("{}?search={}&country=dk", self.b.cvr, enc(q.trim()));
        let v = self.jget(&format!("cvr|{}", q.trim().to_lowercase()), &url, &[], "cvrapi.dk")?;
        let card = v.as_ref().filter(|v| v["error"].is_null()).and_then(cvr_card);
        let hidden = usize::from(v.as_ref().is_some_and(|v| v["error"].is_null()) && card.is_none());
        Ok((card.into_iter().collect(), hidden))
    }

    fn ch_search(&self, q: &str) -> Result<(Vec<Card>, usize), ApiError> {
        let key = self.key("COMPANIES_HOUSE_API_KEY").ok_or_else(|| bad("key not set"))?;
        let auth = format!("Basic {}", b64(format!("{key}:").as_bytes()));
        let url = format!("{}/search/companies?q={}&items_per_page=10", self.b.ch, enc(q.trim()));
        let v = self.jget(&format!("ch|{}", q.trim().to_lowercase()), &url, &[("Authorization", &auth)], "Companies House")?;
        Ok((v.and_then(|v| v["items"].as_array().cloned()).unwrap_or_default().iter().filter_map(ch_card).collect(), 0))
    }

    fn oc_search(&self, q: &str) -> Result<(Vec<Card>, usize), ApiError> {
        let tok = self.key("OPENCORPORATES_API_TOKEN").ok_or_else(|| bad("key not set"))?;
        let url = format!("{}/companies/search?q={}&per_page=10&api_token={}", self.b.oc, enc(q.trim()), enc(&tok));
        let v = self.jget(&format!("oc|{}", q.trim().to_lowercase()), &url, &[], "OpenCorporates")?;
        Ok((v.and_then(|v| v["results"]["companies"].as_array().cloned()).unwrap_or_default().iter().filter_map(oc_card).collect(), 0))
    }

    fn aleph_search(&self, q: &str) -> Result<(Vec<Card>, usize), ApiError> {
        let k = self.key("ALEPH_API_KEY").ok_or_else(|| bad("key not set"))?;
        let auth = format!("ApiKey {k}");
        let url = format!("{}/entities?q={}&filter%3Aschema=Company&limit=10", self.b.aleph, enc(q.trim()));
        let v = self.jget(&format!("aleph|{}", q.trim().to_lowercase()), &url, &[("Authorization", &auth)], "OCCRP Aleph")?;
        Ok((v.and_then(|v| v["results"].as_array().cloned()).unwrap_or_default().iter().filter_map(aleph_card).collect(), 0))
    }

    fn run_source(&self, src: &str, q: &str) -> Value {
        let label = SOURCES.iter().find(|s| s.0 == src).map(|s| s.1).unwrap_or(src);
        if let Some(k) = key_name(src) {
            if self.key(k).is_none() {
                return json!({ "source": src, "label": label, "ok": false, "skipped": "no key configured", "items": [] });
            }
        }
        let r = match src {
            "gleif" => self.gleif_search(q),
            "wikidata" => self.wikidata_search(q),
            "brreg" => self.brreg_search(q),
            "ares" => self.ares_search(q),
            "prh" => self.prh_search(q),
            "cvr" => self.cvr_search(q),
            "companies-house" => self.ch_search(q),
            "opencorporates" => self.oc_search(q),
            "aleph" => self.aleph_search(q),
            _ => Err(bad("unknown source")),
        };
        match r {
            Ok((cards, hidden)) => json!({ "source": src, "label": label, "ok": true, "hidden_individuals": hidden, "items": cards.into_iter().map(Card::json).collect::<Vec<_>>() }),
            Err(e) => json!({ "source": src, "label": label, "ok": false, "error": e.1, "items": [] }),
        }
    }

    // ----- GLEIF relationships and Wikidata ------------------------------------------------------------------

    fn gleif_rel(&self, lei: &str, rel: &str) -> Result<Option<Value>, ApiError> {
        let r = self.jget(&format!("gleif|{lei}|{rel}"), &format!("{}/lei-records/{lei}/{rel}", self.b.gleif), &[], "GLEIF")?;
        Ok(r.and_then(|v| gleif_card(&v["data"])).map(|c| json!({ "lei": c.id, "name": c.name, "country": c.country, "status": c.status, "url": c.url })))
    }

    fn gleif_exception(&self, lei: &str, rel: &str) -> Option<String> {
        let v = self.jget(&format!("gleif|{lei}|{rel}-ex"), &format!("{}/lei-records/{lei}/{rel}-reporting-exception", self.b.gleif), &[], "GLEIF").ok()??;
        v["data"]["attributes"]["reason"].as_str().map(|s| s.to_lowercase().replace('_', " "))
    }

    fn ownership_gleif(&self, lei: &str) -> Result<Value, ApiError> {
        let rec = self.jget(&format!("gleif|lei|{lei}"), &format!("{}/lei-records/{lei}", self.b.gleif), &[], "GLEIF")?.ok_or_else(|| util::not_found("no such LEI"))?;
        let me = gleif_card(&rec["data"]).ok_or_else(|| ApiError(StatusCode::FORBIDDEN, "that LEI belongs to an individual trading as a sole proprietor; not shown".into()))?;
        let side = |rel: &str| -> Result<Value, ApiError> {
            Ok(match self.gleif_rel(lei, rel)? {
                Some(p) => json!({ "parent": p }),
                None => json!({ "parent": null, "reason": self.gleif_exception(lei, rel) }),
            })
        };
        let direct = side("direct-parent")?;
        let ultimate = side("ultimate-parent")?;
        let ch = self.jget(&format!("gleif|{lei}|children"), &format!("{}/lei-records/{lei}/direct-children?page%5Bsize%5D=25", self.b.gleif), &[], "GLEIF")?;
        let rows = ch.as_ref().and_then(|v| v["data"].as_array()).cloned().unwrap_or_default();
        let kids: Vec<Value> = rows.iter().filter_map(gleif_card).map(|c| json!({ "lei": c.id, "name": c.name, "country": c.country, "status": c.status, "url": c.url })).collect();
        let total = ch.as_ref().and_then(|v| v["meta"]["pagination"]["total"].as_u64()).unwrap_or(kids.len() as u64);
        Ok(json!({ "entity": { "lei": me.id, "name": me.name, "country": me.country, "status": me.status, "url": me.url }, "direct_parent": direct, "ultimate_parent": ultimate, "children": kids, "children_total": total }))
    }

    fn qid_for_lei(&self, lei: &str) -> Result<Option<String>, ApiError> {
        let rows = self.wd_sparql(&format!("SELECT ?c WHERE {{ ?c wdt:P1278 \"{lei}\" }} LIMIT 2"))?;
        Ok(rows.first().and_then(|r| r["c"]["value"].as_str()).map(|u| u.rsplit('/').next().unwrap_or("").to_string()).filter(|q| valid_qid(q)))
    }

    fn ownership_wikidata(&self, qid: &str) -> Result<Value, ApiError> {
        let rel = |p: &str, name: &str| format!("{{ wd:{qid} wdt:{p} ?o . BIND(\"{name}\" AS ?rel) }}");
        let q = format!("SELECT DISTINCT ?rel ?o ?oLabel WHERE {{ {} UNION {} UNION {} FILTER NOT EXISTS {{ ?o wdt:P31 wd:Q5 }} FILTER NOT EXISTS {{ ?o wdt:P31 wd:Q8436 }} SERVICE wikibase:label {{ bd:serviceParam wikibase:language \"en\". }} }} LIMIT 80",
            rel("P749", "parent"), rel("P127", "owned_by"), rel("P355", "subsidiary"));
        let rows = self.wd_sparql(&q)?;
        let mut groups: HashMap<&str, Vec<Value>> = HashMap::new();
        for r in &rows {
            let (Some(rl), Some(u), Some(l)) = (r["rel"]["value"].as_str(), r["o"]["value"].as_str(), r["oLabel"]["value"].as_str()) else { continue };
            let id = u.rsplit('/').next().unwrap_or("");
            if !valid_qid(id) {
                continue;
            }
            let k = match rl { "parent" => "parent_organisations", "owned_by" => "owned_by", _ => "subsidiaries" };
            groups.entry(k).or_default().push(json!({ "qid": id, "name": l, "url": format!("https://www.wikidata.org/wiki/{id}") }));
        }
        let f = self.wd_sparql(&format!("SELECT ?website ?inception ?hqLabel WHERE {{ OPTIONAL {{ wd:{qid} wdt:P856 ?website }} OPTIONAL {{ wd:{qid} wdt:P571 ?inception }} OPTIONAL {{ wd:{qid} wdt:P159 ?hq }} SERVICE wikibase:label {{ bd:serviceParam wikibase:language \"en\". }} }} LIMIT 1"))?;
        let fx = f.first().cloned().unwrap_or(Value::Null);
        let get = |k: &str| fx[k]["value"].as_str().map(str::to_string);
        Ok(json!({ "qid": qid, "url": format!("https://www.wikidata.org/wiki/{qid}"), "website": get("website").filter(|w| w.starts_with("http")), "inception": get("inception").map(|d| d.chars().take(10).collect::<String>()), "headquarters": get("hqLabel"),
            "parent_organisations": groups.get("parent_organisations").cloned().unwrap_or_default(), "owned_by": groups.get("owned_by").cloned().unwrap_or_default(), "subsidiaries": groups.get("subsidiaries").cloned().unwrap_or_default(),
            "note": "Wikidata is community-edited and may be incomplete or dated. Humans and families are filtered out." }))
    }
}

#[derive(Deserialize)]
struct SearchQ {
    q: String,
    sources: Option<String>,
}

async fn search(State(st): State<Shared>, Query(q): Query<SearchQ>) -> Result<Json<Value>, ApiError> {
    let text = q.q.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.chars().count() < 2 || text.chars().count() > 100 || text.chars().any(char::is_control) {
        return Err(bad("enter a company name or registry number (2 to 100 characters)"));
    }
    let mut srcs: Vec<String> = match q.sources.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => {
            let v: Vec<String> = s.split(',').map(|x| x.trim().to_string()).collect();
            if let Some(b) = v.iter().find(|x| !SOURCES.iter().any(|s| s.0 == x.as_str())) {
                return Err(bad(format!("unknown source: {}", b.chars().take(30).collect::<String>())));
            }
            v
        }
        None => SOURCES.iter().map(|s| s.0.to_string()).collect(),
    };
    srcs.dedup();
    Ok(Json(blocking(move || {
        let results: Vec<Value> = std::thread::scope(|sc| {
            let hs: Vec<_> = srcs.iter().map(|s| { let (st, text) = (&st, &text); sc.spawn(move || st.run_source(s, text)) }).collect();
            hs.into_iter().map(|h| h.join().unwrap_or_else(|_| json!({ "ok": false, "error": "internal error", "items": [] }))).collect()
        });
        Ok(json!({ "query": text, "sources": results }))
    }).await?))
}

#[derive(Deserialize)]
struct LeiQ {
    lei: String,
}
async fn lei(State(st): State<Shared>, Query(q): Query<LeiQ>) -> Result<Json<Value>, ApiError> {
    let id = q.lei.trim().to_uppercase();
    if !valid_lei(&id) {
        return Err(bad("an LEI is 20 letters and digits"));
    }
    Ok(Json(blocking(move || {
        let v = st.jget(&format!("gleif|lei|{id}"), &format!("{}/lei-records/{id}", st.b.gleif), &[], "GLEIF")?.ok_or_else(|| util::not_found("no such LEI"))?;
        let d = &v["data"];
        let e = &d["attributes"]["entity"];
        let card = gleif_card(d).ok_or_else(|| ApiError(StatusCode::FORBIDDEN, "that LEI belongs to an individual trading as a sole proprietor; not shown".into()))?;
        let addr = |a: &Value| join_addr(a);
        let reg = &d["attributes"]["registration"];
        Ok(json!({
            "lei": id, "legal_name": card.name, "other_names": e["otherNames"].as_array().map(|a| a.iter().filter_map(|n| n["name"].as_str()).take(8).collect::<Vec<_>>()),
            "status": e["status"], "category": e["category"], "legal_form": e["legalForm"]["id"], "jurisdiction": e["jurisdiction"],
            "registered_as": e["registeredAs"], "registered_at": e["registeredAt"]["id"], "created": e["creationDate"].as_str().map(|s| s.chars().take(10).collect::<String>()),
            "legal_address": addr(&e["legalAddress"]), "headquarters_address": addr(&e["headquartersAddress"]),
            "lei_status": reg["status"], "last_update": reg["lastUpdateDate"], "next_renewal": reg["nextRenewalDate"], "managing_lou": reg["managingLou"],
            "url": card.url, "api_url": format!("https://api.gleif.org/api/v1/lei-records/{id}"),
        }))
    }).await?))
}

fn join_addr(a: &Value) -> Option<String> {
    let lines = a["addressLines"].as_array().map(|l| l.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" "));
    let parts: Vec<String> = [lines, a["postalCode"].as_str().map(str::to_string), a["city"].as_str().map(str::to_string), a["country"].as_str().map(str::to_string)].into_iter().flatten().filter(|s| !s.is_empty()).collect();
    (!parts.is_empty()).then(|| parts.join(", "))
}

#[derive(Deserialize)]
struct OwnQ {
    lei: Option<String>,
    qid: Option<String>,
}
async fn ownership(State(st): State<Shared>, Query(q): Query<OwnQ>) -> Result<Json<Value>, ApiError> {
    let lei = q.lei.as_deref().map(|l| l.trim().to_uppercase()).filter(|l| !l.is_empty());
    let qid = q.qid.as_deref().map(|l| l.trim().to_string()).filter(|l| !l.is_empty());
    if let Some(l) = &lei { if !valid_lei(l) { return Err(bad("an LEI is 20 letters and digits")); } }
    if let Some(i) = &qid { if !valid_qid(i) { return Err(bad("a Wikidata id looks like Q81230")); } }
    if lei.is_none() && qid.is_none() {
        return Err(bad("give lei or qid"));
    }
    Ok(Json(blocking(move || {
        let mut warnings: Vec<String> = Vec::new();
        let gleif = match &lei {
            Some(l) => match st.ownership_gleif(l) { Ok(v) => Some(v), Err(e) if e.0 == StatusCode::BAD_GATEWAY => { warnings.push(format!("GLEIF: {}", e.1)); None } Err(e) => return Err(e) },
            None => None,
        };
        let qid = match (&qid, &lei) {
            (Some(i), _) => Some(i.clone()),
            (None, Some(l)) => st.qid_for_lei(l).unwrap_or_else(|e| { warnings.push(format!("Wikidata: {}", e.1)); None }),
            _ => None,
        };
        let wikidata = qid.as_deref().and_then(|i| st.ownership_wikidata(i).map_err(|e| warnings.push(format!("Wikidata: {}", e.1))).ok());
        if lei.is_some() && qid.is_none() && warnings.is_empty() {
            warnings.push("No Wikidata item carries this LEI.".into());
        }
        Ok(json!({ "lei": lei, "qid": qid, "gleif": gleif, "wikidata": wikidata, "warnings": warnings }))
    }).await?))
}

async fn status(State(st): State<Shared>) -> Json<Value> {
    let st2 = st.clone();
    let keys = tokio::task::spawn_blocking(move || SOURCES.iter().filter_map(|s| key_name(s.0).map(|k| (s.0, st2.key(k).is_some()))).collect::<Vec<_>>()).await.unwrap_or_default();
    Json(json!({ "sources": SOURCES.iter().map(|s| json!({ "id": s.0, "label": s.1, "needs_key": key_name(s.0).is_some(), "key_set": keys.iter().find(|k| k.0 == s.0).map(|k| k.1) })).collect::<Vec<_>>() }))
}

async fn tools() -> Json<Value> {
    Json(json!([
        { "name": "corp_search", "description": "Search company registers by name or registry number: GLEIF, Wikidata, Norway, Czechia, Finland, Denmark (and Companies House, OpenCorporates, Aleph when keys are set). Returns company-level cards (legal name, status, registered address of the company, industry, registry link). Sole proprietors and individuals are filtered out.",
          "method": "GET", "path": "api/search?q={q}&sources={sources}", "parameters": { "type": "object", "properties": { "q": { "type": "string" }, "sources": { "type": "string", "description": "optional comma list: gleif, wikidata, brreg, ares, prh, cvr, companies-house, opencorporates, aleph" } }, "required": ["q"] } },
        { "name": "corp_lei", "description": "GLEIF record for a Legal Entity Identifier: legal name, status, legal form, registration authority and number, legal and headquarters address of the company.",
          "method": "GET", "path": "api/lei?lei={lei}", "parameters": { "type": "object", "properties": { "lei": { "type": "string", "description": "20-character LEI" } }, "required": ["lei"] } },
        { "name": "corp_ownership", "description": "Corporate ownership links from GLEIF (direct and ultimate parent, direct subsidiaries, or the reason none is reported) and Wikidata (parent organisations, owning organisations, subsidiaries). Organisations only.",
          "method": "GET", "path": "api/ownership?lei={lei}&qid={qid}", "parameters": { "type": "object", "properties": { "lei": { "type": "string" }, "qid": { "type": "string", "description": "Wikidata item id such as Q81230" } } } },
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

pub fn app(st: Shared) -> Router {
    let open = st.open;
    Router::new()
        .route("/api/status", get(status))
        .route("/api/search", get(search))
        .route("/api/lei", get(lei))
        .route("/api/ownership", get(ownership))
        .route_layer(middleware::from_fn_with_state(open, util::gate))
        .route("/tools", get(tools))
        .route("/", get(page))
        .with_state(st)
}

pub fn new_state(b: Bases, open: bool, dir: Option<PathBuf>, secret: Box<dyn Fn(&str) -> Option<String> + Send + Sync>) -> Shared {
    let cache = Cache::new(dir, 24 << 20);
    cache.trim(Duration::from_secs(3 * 86400));
    Arc::new(AppState { b, open, agent: osnt_common::http_agent("osnt-corp-registries/0.1 (+https://github.com/ogden-marrow/osnt-hub)"), cache, secret, memo: Mutex::new(HashMap::new()) })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let st = new_state(
        Bases::live(),
        env::var("OSNT_CORP_INSECURE_LOCAL").ok().as_deref() == Some("1"),
        env::var("OSNT_CORP_STATE").ok().filter(|s| !s.is_empty()).map(PathBuf::from),
        Box::new(|n| osnt_common::secret(n)),
    );
    let addr: SocketAddr = env::var("OSNT_CORP_BIND").unwrap_or_else(|_| "127.0.0.1:8142".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("corp-registries plugin on http://{addr}");
    axum::serve(listener, app(st)).await?;
    Ok(())
}

#[cfg(test)]
mod tests;

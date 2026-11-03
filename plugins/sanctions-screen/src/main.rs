//! Sanctions and watchlist screening over official lists, downloaded on demand (OpenSanctions slices) and cached.
//!
//! Safety: companies, organisations, vessels and aircraft are searched by default. Natural persons (and records a list
//! does not classify) are opt-in and are returned as name, list, programme and first-seen date only: no birth dates,
//! addresses, identifiers, phone numbers, emails or aliases. Interpol notices and crypto-wallet rows are not loaded.

mod cache;
mod matching;
mod util;

use std::{
    collections::HashMap,
    env, fs,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    middleware,
    response::Html,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};

use matching::{Name, score};
use util::{ApiError, bad, blocking, map_ureq, not_found, now_epoch, upstream};

const PAGE: &str = include_str!("../assets/index.html");

pub struct ListDef {
    pub id: &'static str,
    pub name: &'static str,
    pub publisher: &'static str,
}
pub const LISTS: &[ListDef] = &[
    ListDef { id: "us_ofac_sdn", name: "US OFAC SDN", publisher: "US Treasury, Office of Foreign Assets Control" },
    ListDef { id: "eu_fsf", name: "EU financial sanctions", publisher: "European Commission (FSF)" },
    ListDef { id: "un_sc_sanctions", name: "UN Security Council", publisher: "United Nations Security Council" },
    ListDef { id: "gb_fcdo_sanctions", name: "UK sanctions list", publisher: "UK Foreign, Commonwealth and Development Office" },
    ListDef { id: "us_trade_csl", name: "US consolidated screening list", publisher: "US International Trade Administration" },
    ListDef { id: "ch_seco_sanctions", name: "Swiss SECO", publisher: "Swiss State Secretariat for Economic Affairs" },
    ListDef { id: "us_bis_denied", name: "US BIS denied persons", publisher: "US Bureau of Industry and Security" },
];

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Entity,
    Vessel,
    Aircraft,
    Person,
    Unclassified,
}
impl Kind {
    fn from_schema(s: &str) -> Option<Kind> {
        Some(match s {
            "Organization" | "Company" | "PublicBody" | "Security" => Kind::Entity,
            "Vessel" => Kind::Vessel,
            "Airplane" => Kind::Aircraft,
            "Person" => Kind::Person,
            "LegalEntity" => Kind::Unclassified,
            _ => return None, // crypto wallets, addresses and anything else are not loaded
        })
    }
    fn minimal(self) -> bool {
        matches!(self, Kind::Person | Kind::Unclassified)
    }
}

pub struct Rec {
    pub id: String,
    pub kind: Kind,
    pub name: String,
    pub aliases: Vec<String>, // empty for persons and unclassified records
    pub countries: String,
    pub programme: String,
    pub program_ids: String,
    pub first_seen: String,
    pub idents: Vec<String>, // vessels and aircraft only
}

pub struct ListData {
    pub recs: Vec<Rec>,
    pub names: Vec<(u32, bool, Name)>, // record index, is_alias, normalised
    pub fetched: u64,
}

fn date_part(s: &str) -> String {
    s.get(..10).unwrap_or(s).to_string()
}

pub fn parse_csv(bytes: &[u8], fetched: u64) -> Result<ListData, String> {
    let mut rd = csv::ReaderBuilder::new().flexible(true).from_reader(bytes);
    let h = rd.headers().map_err(|e| e.to_string())?.clone();
    let col = |n: &str| h.iter().position(|x| x == n);
    let (Some(c_id), Some(c_schema), Some(c_name)) = (col("id"), col("schema"), col("name")) else { return Err("unexpected CSV header".into()) };
    let (c_alias, c_ctry, c_ident, c_sanc, c_prog, c_first) = (col("aliases"), col("countries"), col("identifiers"), col("sanctions"), col("program_ids"), col("first_seen"));
    let mut recs = Vec::new();
    let mut names = Vec::new();
    for row in rd.records() {
        let Ok(r) = row else { continue };
        let get = |c: Option<usize>| c.and_then(|i| r.get(i)).unwrap_or("").trim();
        let Some(kind) = Kind::from_schema(r.get(c_schema).unwrap_or("")) else { continue };
        let name = r.get(c_name).unwrap_or("").trim().to_string();
        if name.is_empty() {
            continue;
        }
        let aliases: Vec<String> = get(c_alias).split(';').map(str::trim).filter(|a| !a.is_empty()).map(str::to_string).collect();
        let idx = recs.len() as u32;
        names.push((idx, false, Name::new(&name)));
        for a in aliases.iter().take(40) {
            names.push((idx, true, Name::new(a)));
        }
        let shown = !kind.minimal();
        recs.push(Rec {
            id: r.get(c_id).unwrap_or("").to_string(),
            kind,
            name,
            aliases: if shown { aliases.into_iter().take(8).collect() } else { vec![] },
            countries: if shown { get(c_ctry).replace(';', ", ") } else { String::new() },
            programme: if shown { get(c_sanc).chars().take(300).collect() } else { String::new() },
            program_ids: get(c_prog).replace(';', ", "),
            first_seen: date_part(get(c_first)),
            idents: if matches!(kind, Kind::Vessel | Kind::Aircraft) { get(c_ident).split(';').map(|x| x.trim().to_uppercase()).filter(|x| !x.is_empty()).collect() } else { vec![] },
        });
    }
    Ok(ListData { recs, names, fetched })
}

pub struct Config {
    pub base: String,
    pub open: bool,
    pub ttl: Duration,
    pub dir: Option<PathBuf>,
}

pub struct AppState {
    cfg: Config,
    agent: ureq::Agent,
    loaded: Mutex<HashMap<&'static str, Arc<ListData>>>,
    locks: HashMap<&'static str, Mutex<()>>,
    forced: Mutex<HashMap<&'static str, u64>>,
}
type Shared = Arc<AppState>;

fn list_def(id: &str) -> Option<&'static ListDef> {
    LISTS.iter().find(|l| l.id == id)
}

impl AppState {
    fn file(&self, id: &str) -> Option<PathBuf> {
        self.cfg.dir.as_ref().map(|d| d.join(format!("{id}.csv")))
    }
    fn file_age(&self, id: &str) -> Option<(u64, Duration)> {
        let m = fs::metadata(self.file(id)?).ok()?;
        let t = m.modified().ok()?;
        Some((t.duration_since(SystemTime::UNIX_EPOCH).ok()?.as_secs(), SystemTime::now().duration_since(t).unwrap_or_default()))
    }

    fn download(&self, id: &str) -> Result<Vec<u8>, ApiError> {
        let url = format!("{}/{id}/targets.simple.csv", self.cfg.base);
        let res = self.agent.get(&url).config().timeout_global(Some(Duration::from_secs(150))).build().call().map_err(|e| map_ureq("OpenSanctions data server", e))?;
        let mut res = res;
        res.body_mut().with_config().limit(48 << 20).read_to_vec().map_err(|_| upstream("the list download was cut off or too large"))
    }

    /// The parsed list: from memory if fresh, else from the cached file, else downloaded. A stale copy is used when
    /// the download fails (second value true).
    fn ensure(&self, id: &str, force: bool) -> Result<(Arc<ListData>, bool), ApiError> {
        let def = list_def(id).ok_or_else(|| bad("unknown list"))?;
        let _g = self.locks[def.id].lock().map_err(|_| upstream("internal error"))?;
        let fresh = |d: &ListData| now_epoch().saturating_sub(d.fetched) < self.cfg.ttl.as_secs();
        let mem = self.loaded.lock().ok().and_then(|m| m.get(def.id).cloned());
        if let Some(d) = &mem {
            if !force && fresh(d) {
                return Ok((d.clone(), false));
            }
        }
        if !force {
            if let (Some(p), Some((ts, age))) = (self.file(def.id), self.file_age(def.id)) {
                if age < self.cfg.ttl {
                    if let Ok(bytes) = fs::read(&p) {
                        if let Ok(d) = parse_csv(&bytes, ts) {
                            let d = Arc::new(d);
                            self.loaded.lock().unwrap().insert(def.id, d.clone());
                            return Ok((d, false));
                        }
                    }
                }
            }
        }
        match self.download(def.id).and_then(|b| parse_csv(&b, now_epoch()).map(|d| (b, d)).map_err(|e| upstream(format!("the list could not be read: {e}")))) {
            Ok((bytes, d)) => {
                if let Some(p) = self.file(def.id) {
                    let tmp = p.with_extension("tmp");
                    if fs::write(&tmp, &bytes).and_then(|_| fs::rename(&tmp, &p)).is_err() {
                        let _ = fs::remove_file(&tmp);
                    }
                }
                let d = Arc::new(d);
                self.loaded.lock().unwrap().insert(def.id, d.clone());
                Ok((d, false))
            }
            Err(e) => {
                if let Some(d) = mem {
                    return Ok((d, true));
                }
                if let Some(bytes) = self.file(def.id).and_then(|p| fs::read(p).ok()) {
                    if let Ok(d) = parse_csv(&bytes, self.file_age(def.id).map(|x| x.0).unwrap_or(0)) {
                        let d = Arc::new(d);
                        self.loaded.lock().unwrap().insert(def.id, d.clone());
                        return Ok((d, true));
                    }
                }
                Err(e)
            }
        }
    }
}

/// Remove stale list files at startup and keep the directory under a size cap.
pub fn cleanup_dir(dir: &std::path::Path, max_age: Duration, max_bytes: u64) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut files = Vec::new();
    for e in rd.flatten() {
        let Ok(md) = e.metadata() else { continue };
        if !md.is_file() {
            continue;
        }
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) == Some("tmp") {
            let _ = fs::remove_file(&p);
            continue;
        }
        files.push((md.modified().unwrap_or(SystemTime::UNIX_EPOCH), md.len(), p));
    }
    files.retain(|(t, _, p)| {
        let old = SystemTime::now().duration_since(*t).map(|a| a > max_age).unwrap_or(false);
        if old {
            let _ = fs::remove_file(p);
        }
        !old
    });
    files.sort_by_key(|f| f.0);
    let mut total: u64 = files.iter().map(|f| f.1).sum();
    for (_, n, p) in files {
        if total <= max_bytes {
            break;
        }
        if fs::remove_file(p).is_ok() {
            total -= n;
        }
    }
}

fn item(list: &ListDef, d: &ListData, idx: u32, via_alias: bool, sc: Option<&matching::Scored>) -> Value {
    let r = &d.recs[idx as usize];
    let minimal = r.kind.minimal();
    let mut v = json!({
        "id": r.id, "list": list.id, "list_name": list.name, "name": r.name, "kind": r.kind,
        "programme": r.programme, "programme_ids": r.program_ids, "first_seen": r.first_seen,
        "url": format!("https://www.opensanctions.org/entities/{}/", r.id),
        "minimal": minimal,
    });
    if !minimal {
        v["aliases"] = json!(r.aliases);
        v["countries"] = json!(r.countries);
        if !r.idents.is_empty() {
            v["identifiers"] = json!(r.idents);
        }
    }
    if let Some(s) = sc {
        v["score"] = json!(s.score);
        v["quality"] = json!(s.quality);
        v["matched_on"] = json!(if via_alias { "alias" } else { "name" });
        v["explanation"] = json!(s.hits);
    }
    v
}

#[derive(Deserialize)]
struct SearchQ {
    q: String,
    lists: Option<String>,
    persons: Option<String>,
    kinds: Option<String>,
    min: Option<f64>,
    limit: Option<usize>,
}

fn selected_lists(s: &Option<String>) -> Result<Vec<&'static ListDef>, ApiError> {
    match s.as_deref().map(str::trim).filter(|x| !x.is_empty()) {
        None => Ok(LISTS.iter().collect()),
        Some(t) => t.split(',').map(|i| list_def(i.trim()).ok_or_else(|| bad(format!("unknown list: {}", i.trim().chars().take(30).collect::<String>())))).collect(),
    }
}

async fn search(State(st): State<Shared>, Query(q): Query<SearchQ>) -> Result<Json<Value>, ApiError> {
    let text = q.q.trim().to_string();
    if text.chars().count() < 2 || text.chars().count() > 120 {
        return Err(bad("enter 2 to 120 characters"));
    }
    let lists = selected_lists(&q.lists)?;
    let persons = matches!(q.persons.as_deref(), Some("1" | "true"));
    let min = q.min.unwrap_or(0.82).clamp(0.5, 1.0);
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let mut kinds = vec![Kind::Entity, Kind::Vessel, Kind::Aircraft];
    if let Some(k) = q.kinds.as_deref().filter(|k| !k.is_empty()) {
        kinds = k.split(',').filter_map(|k| match k.trim() { "entity" => Some(Kind::Entity), "vessel" => Some(Kind::Vessel), "aircraft" => Some(Kind::Aircraft), _ => None }).collect();
        if kinds.is_empty() {
            return Err(bad("kinds must include entity, vessel or aircraft"));
        }
    }
    if persons {
        kinds.push(Kind::Person);
        kinds.push(Kind::Unclassified);
    }
    Ok(Json(blocking(move || {
        let qn = Name::new(&text);
        if qn.toks.is_empty() {
            return Err(bad("the query has no searchable letters or digits"));
        }
        let mut hits: Vec<(f64, Value)> = Vec::new();
        let mut status = Vec::new();
        for def in lists {
            let (d, stale) = st.ensure(def.id, false)?;
            let mut best: HashMap<u32, (matching::Scored, bool)> = HashMap::new();
            for (idx, alias, n) in &d.names {
                if !kinds.contains(&d.recs[*idx as usize].kind) {
                    continue;
                }
                let s = score(&qn, n);
                if s.score >= min && best.get(idx).is_none_or(|(b, _)| s.score > b.score) {
                    best.insert(*idx, (s, *alias));
                }
            }
            status.push(json!({ "list": def.id, "records": d.recs.len(), "fetched": d.fetched, "stale": stale, "matches": best.len() }));
            for (idx, (s, alias)) in best {
                hits.push((s.score, item(def, &d, idx, alias, Some(&s))));
            }
        }
        hits.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal).then_with(|| a.1["name"].as_str().cmp(&b.1["name"].as_str())));
        let total = hits.len();
        hits.truncate(limit);
        Ok(json!({ "query": text, "normalised": qn.flat, "min_score": min, "persons_included": persons, "total_matches": total, "results": hits.into_iter().map(|h| h.1).collect::<Vec<_>>(), "lists": status,
            "how_scoring_works": "Names are lower-cased, accents folded and company-form words (Ltd, LLC, GmbH...) dropped. Each query word is paired with its best remaining word of the listed name by spelling similarity (Jaro-Winkler), prefix, or Soundex when spelling is close. The score is the share of the query covered, scaled down when the listed name has many unmatched words. Scores are aids, not decisions." }))
    }).await?))
}

#[derive(Deserialize)]
struct IdQ {
    imo: Option<String>,
    mmsi: Option<String>,
    reg: Option<String>,
}

pub fn imo_valid(s: &str) -> Option<String> {
    let t = s.trim().to_uppercase();
    let t = t.strip_prefix("IMO").unwrap_or(&t).trim();
    if t.len() != 7 || !t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let d: Vec<u32> = t.bytes().map(|b| (b - b'0') as u32).collect();
    let sum: u32 = (0..6).map(|i| d[i] * (7 - i as u32)).sum();
    (sum % 10 == d[6]).then(|| format!("IMO{t}"))
}
pub fn mmsi_valid(s: &str) -> Option<String> {
    let t = s.trim();
    (t.len() == 9 && t.bytes().all(|b| b.is_ascii_digit()) && !t.starts_with('0')).then(|| t.to_string())
}
pub fn reg_valid(s: &str) -> Option<String> {
    let t: String = s.trim().to_uppercase().chars().filter(|c| *c != '-' && *c != ' ').collect();
    ((2..=9).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_alphanumeric())).then_some(t)
}

async fn identifier(State(st): State<Shared>, Query(q): Query<IdQ>) -> Result<Json<Value>, ApiError> {
    let (kind, needle, label) = match (&q.imo, &q.mmsi, &q.reg) {
        (Some(i), None, None) => (Kind::Vessel, imo_valid(i).ok_or_else(|| bad("not a valid IMO number (7 digits with a correct check digit)"))?, "imo"),
        (None, Some(m), None) => (Kind::Vessel, mmsi_valid(m).ok_or_else(|| bad("MMSI must be 9 digits"))?, "mmsi"),
        (None, None, Some(r)) => (Kind::Aircraft, reg_valid(r).ok_or_else(|| bad("registration must be 2 to 9 letters or digits"))?, "reg"),
        _ => return Err(bad("give exactly one of imo, mmsi or reg")),
    };
    Ok(Json(blocking(move || {
        let mut found = Vec::new();
        let mut checked = Vec::new();
        for def in LISTS {
            let (d, _) = st.ensure(def.id, false)?;
            checked.push(def.id);
            for (i, r) in d.recs.iter().enumerate() {
                if r.kind != kind {
                    continue;
                }
                let hit = r.idents.iter().any(|x| *x == needle) || (kind == Kind::Aircraft && r.name.to_uppercase().replace('-', "") == needle);
                if hit {
                    found.push(item(def, &d, i as u32, false, None));
                }
            }
        }
        Ok(json!({ "checked_by": label, "value": needle, "listed": !found.is_empty(), "matches": found, "lists_checked": checked,
            "note": "Exact identifier match against the loaded lists. No match does not mean the owner or operator is clear; screen those names too." }))
    }).await?))
}

async fn lists(State(st): State<Shared>) -> Json<Value> {
    let mem = st.loaded.lock().unwrap();
    let rows: Vec<Value> = LISTS.iter().map(|l| {
        let d = mem.get(l.id);
        let disk = st.file_age(l.id);
        let count = |k: Kind| d.map(|d| d.recs.iter().filter(|r| r.kind == k).count());
        json!({ "id": l.id, "name": l.name, "publisher": l.publisher, "loaded": d.is_some(),
            "records": d.map(|d| d.recs.len()), "entities": count(Kind::Entity), "vessels": count(Kind::Vessel), "aircraft": count(Kind::Aircraft),
            "fetched": d.map(|d| d.fetched).or(disk.map(|x| x.0)), "age_seconds": d.map(|d| now_epoch().saturating_sub(d.fetched)).or(disk.map(|x| x.1.as_secs())),
            "source": format!("https://data.opensanctions.org/datasets/latest/{}/", l.id) })
    }).collect();
    Json(json!({ "lists": rows, "ttl_seconds": st.cfg.ttl.as_secs(),
        "attribution": "Data from OpenSanctions (opensanctions.org), CC BY-NC 4.0, non-commercial use; each list is published by the authority named." }))
}

#[derive(Deserialize)]
struct RefreshQ {
    list: String,
}
async fn refresh(State(st): State<Shared>, Query(q): Query<RefreshQ>) -> Result<Json<Value>, ApiError> {
    let def = list_def(&q.list).ok_or_else(|| not_found("unknown list"))?;
    {
        let mut f = st.forced.lock().unwrap();
        if now_epoch().saturating_sub(*f.get(def.id).unwrap_or(&0)) < 600 {
            return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "this list was refreshed less than ten minutes ago".into()));
        }
        f.insert(def.id, now_epoch());
    }
    let id = def.id;
    Ok(Json(blocking(move || {
        let (d, stale) = st.ensure(id, true)?;
        Ok(json!({ "list": id, "records": d.recs.len(), "fetched": d.fetched, "stale": stale }))
    }).await?))
}

async fn tools() -> Json<Value> {
    Json(json!([
        { "name": "sanctions_search", "description": "Fuzzy-match a company, organisation, vessel or aircraft name against official sanctions lists (OFAC SDN, EU, UN, UK, US CSL, SECO, BIS). Returns list, programme, first-seen date, aliases and a match explanation. Natural persons are excluded unless include_persons=1, and then only name, list and programme are returned.",
          "method": "GET", "path": "api/search?q={q}&persons={include_persons}&min={min}", "parameters": { "type": "object", "properties": { "q": { "type": "string" }, "include_persons": { "type": "string", "description": "1 to include natural persons (minimal fields)" }, "min": { "type": "number", "description": "minimum score 0.5 to 1, default 0.82" } }, "required": ["q"] } },
        { "name": "sanctions_lists", "description": "Which sanctions lists are available, how fresh each loaded copy is and how many entities, vessels and aircraft each holds.",
          "method": "GET", "path": "api/lists", "parameters": { "type": "object", "properties": {} } },
        { "name": "sanctions_check_vessel", "description": "Exact check of a vessel IMO number, MMSI or an aircraft registration against the loaded lists.",
          "method": "GET", "path": "api/identifier?imo={imo}&mmsi={mmsi}&reg={reg}", "parameters": { "type": "object", "properties": { "imo": { "type": "string" }, "mmsi": { "type": "string" }, "reg": { "type": "string", "description": "aircraft registration" } } } },
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

pub fn app(st: Shared) -> Router {
    let open = st.cfg.open;
    Router::new()
        .route("/api/search", get(search))
        .route("/api/identifier", get(identifier))
        .route("/api/lists", get(lists))
        .route("/api/lists/refresh", post(refresh))
        .route_layer(middleware::from_fn_with_state(open, util::gate))
        .route("/tools", get(tools))
        .route("/", get(page))
        .with_state(st)
}

pub fn new_state(cfg: Config) -> Shared {
    if let Some(d) = &cfg.dir {
        let _ = fs::create_dir_all(d);
        cleanup_dir(d, Duration::from_secs(3 * 86400), 96 << 20);
    }
    Arc::new(AppState {
        cfg,
        agent: osnt_common::http_agent("osnt-sanctions-screen/0.1 (+https://github.com/ogden-marrow/osnt-hub)"),
        loaded: Mutex::new(HashMap::new()),
        locks: LISTS.iter().map(|l| (l.id, Mutex::new(()))).collect(),
        forced: Mutex::new(HashMap::new()),
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let st = new_state(Config {
        base: "https://data.opensanctions.org/datasets/latest".into(),
        open: env::var("OSNT_SANCTIONS_INSECURE_LOCAL").ok().as_deref() == Some("1"),
        ttl: Duration::from_secs(12 * 3600),
        dir: env::var("OSNT_SANCTIONS_STATE").ok().filter(|s| !s.is_empty()).map(PathBuf::from),
    });
    let addr: SocketAddr = env::var("OSNT_SANCTIONS_BIND").unwrap_or_else(|_| "127.0.0.1:8140".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("sanctions-screen plugin on http://{addr}");
    axum::serve(listener, app(st)).await?;
    Ok(())
}

#[cfg(test)]
mod tests;

//! Wikimedia access: On this day, Portal:Current events, page views with spike detection, Wikidata entity facts and
//! the EventStreams change filter. Scope is events, places, organisations, vessels and aircraft types: pages and
//! entities that are about a person (Wikidata "instance of human") are refused everywhere, and change notices never
//! carry an editor name, IP address or edit comment.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::{BufRead, BufReader, Read},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const LANGS: [&str; 13] = ["en", "de", "fr", "es", "ru", "uk", "ar", "it", "pt", "zh", "ja", "he", "tr"];
pub const MAX_TOPICS: usize = 20;
const MAX_BODY: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
pub enum WikiError {
    BadInput(String),
    NotFound(String),
    /// The page or entity is about a person.
    Person,
    Upstream(String),
}
impl std::fmt::Display for WikiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WikiError::BadInput(m) | WikiError::NotFound(m) | WikiError::Upstream(m) => f.write_str(m),
            WikiError::Person => f.write_str("this page is about a person; this tool covers events, places, organisations, vessels and aircraft types, not individuals"),
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------------------------------------------

pub fn valid_lang(l: &str) -> Result<&'static str, WikiError> {
    let l = if l.is_empty() { "en" } else { l };
    LANGS.iter().find(|x| **x == l).copied().ok_or_else(|| WikiError::BadInput(format!("language must be one of {}", LANGS.join(", "))))
}

/// Article title with underscores, 1 to 255 characters, none of the characters MediaWiki forbids in titles.
pub fn norm_title(t: &str) -> Result<String, WikiError> {
    let t = t.trim().replace(' ', "_");
    if t.is_empty() || t.chars().count() > 255 || t.chars().any(|c| c.is_control() || "#<>[]{}|\\".contains(c)) || t.starts_with(':') {
        return Err(WikiError::BadInput("enter an article title (no # < > [ ] { } | characters)".into()));
    }
    // MediaWiki capitalises the first letter of a title.
    let mut c = t.chars();
    Ok(c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default())
}

pub fn pct(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

pub fn valid_qid(q: &str) -> Result<String, WikiError> {
    let q = q.trim().to_ascii_uppercase();
    let ok = q.len() >= 2 && q.len() <= 14 && q.starts_with('Q') && q[1..].bytes().all(|b| b.is_ascii_digit()) && !q[1..].starts_with('0');
    if ok { Ok(q) } else { Err(WikiError::BadInput("entity id must look like Q42".into())) }
}

pub fn page_url(lang: &str, title: &str) -> String {
    format!("https://{lang}.wikipedia.org/wiki/{}", pct(title).replace("%3A", ":").replace("%2F", "/"))
}

// ---------------------------------------------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------------------------------------------

pub struct Cache {
    max: usize,
    map: Mutex<HashMap<String, (Instant, Value)>>,
}
impl Cache {
    pub fn new(max: usize) -> Cache {
        Cache { max, map: Mutex::new(HashMap::new()) }
    }
    pub fn get(&self, key: &str, ttl: Duration) -> Option<Value> {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).get(key).filter(|(t, _)| t.elapsed() < ttl).map(|(_, v)| v.clone())
    }
    pub fn put(&self, key: String, v: Value) {
        let mut m = self.map.lock().unwrap_or_else(|e| e.into_inner());
        while m.len() >= self.max {
            let Some(old) = m.iter().min_by_key(|(_, (t, _))| *t).map(|(k, _)| k.clone()) else { break };
            m.remove(&old);
        }
        m.insert(key, (Instant::now(), v));
    }
    pub fn len(&self) -> usize {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------------------------------------------

fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(end) = rest.find(';').filter(|e| *e <= 10) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let rep = match &rest[1..end] {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" | "#39" => Some('\''),
            "nbsp" => Some(' '),
            e if e.starts_with("#x") || e.starts_with("#X") => u32::from_str_radix(&e[2..], 16).ok().and_then(char::from_u32),
            e if e.starts_with('#') => e[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        };
        match rep {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn attr<'a>(tag: &'a str, name: &str) -> Option<String> {
    let pat = format!("{name}=\"");
    let i = tag.find(&pat)? + pat.len();
    let e = tag[i..].find('"')?;
    Some(decode_entities(&tag[i..i + e]))
}

#[derive(Default)]
struct Frame {
    text: String,
    has_child: bool,
    ext: Option<(String, String)>,
    pages: Vec<String>,
}

/// Portal:Current events rendered HTML -> leaf bullet points with their category and parent topic path.
pub fn parse_current_events(html: &str) -> Vec<Value> {
    let start = html.find("class=\"current-events-content").unwrap_or(0);
    let end = html[start..].find("class=\"current-events-more").map(|e| start + e).unwrap_or(html.len());
    let h = &html[start..end];
    let mut out = Vec::new();
    let (mut category, mut in_b, mut b_text) = (String::new(), false, String::new());
    let mut stack: Vec<Frame> = Vec::new();
    let mut in_ext: Option<(String, String)> = None;
    let mut i = 0;
    while i < h.len() {
        if h.as_bytes()[i] == b'<' {
            let Some(e) = h[i..].find('>') else { break };
            let tag = &h[i + 1..i + e];
            let name = tag.trim_start_matches('/').split(|c: char| c.is_whitespace() || c == '/').next().unwrap_or("").to_ascii_lowercase();
            let closing = tag.starts_with('/');
            match (name.as_str(), closing) {
                ("b", false) if stack.is_empty() => {
                    in_b = true;
                    b_text.clear();
                }
                ("b", true) if in_b => {
                    in_b = false;
                    let c = decode_entities(b_text.trim());
                    if !c.is_empty() {
                        category = c;
                    }
                }
                ("li", false) => stack.push(Frame::default()),
                ("ul", false) => {
                    if let Some(f) = stack.last_mut() {
                        f.has_child = true;
                    }
                }
                ("li", true) => {
                    if let Some(f) = stack.pop() {
                        if !f.has_child {
                            let text = decode_entities(&f.text).split_whitespace().collect::<Vec<_>>().join(" ");
                            if !text.is_empty() {
                                let topic: Vec<String> = stack.iter().map(|p| decode_entities(&p.text).split_whitespace().collect::<Vec<_>>().join(" ")).filter(|t| !t.is_empty()).collect();
                                let (src_url, src_name) = f.ext.unzip();
                                out.push(json!({ "category": category, "topic": topic.join(" › "), "text": text, "source": src_name, "source_url": src_url, "pages": f.pages }));
                            }
                        }
                    }
                }
                ("a", false) => {
                    if tag.contains("external") {
                        // Links that are not http(s) are swallowed (url left empty) rather than shown as text.
                        let href = attr(tag, "href").filter(|u| u.starts_with("https://") || u.starts_with("http://")).unwrap_or_default();
                        in_ext = Some((href, String::new()));
                    } else if let (Some(f), Some(t)) = (stack.last_mut(), attr(tag, "title")) {
                        if f.pages.len() < 5 && !t.contains(':') && !f.pages.contains(&t) {
                            f.pages.push(t);
                        }
                    }
                }
                ("a", true) => {
                    if let (Some((u, t)), Some(f)) = (in_ext.take(), stack.last_mut()) {
                        let name = decode_entities(&t).trim().trim_start_matches('(').trim_end_matches(')').trim().to_string();
                        if f.ext.is_none() && !u.is_empty() {
                            f.ext = Some((u, name));
                        }
                    }
                }
                _ => {}
            }
            i += e + 1;
        } else {
            let next = h[i..].find('<').map(|p| i + p).unwrap_or(h.len());
            let t = &h[i..next];
            if let Some((_, buf)) = in_ext.as_mut() {
                buf.push_str(t);
            } else if in_b {
                b_text.push_str(t);
            } else if let Some(f) = stack.last_mut() {
                f.text.push_str(t);
            }
            i = next;
        }
    }
    out
}

/// REST `onthisday/events` payload -> entries with article links.
pub fn parse_onthisday(v: &Value, lang: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for e in v["events"].as_array().map(Vec::as_slice).unwrap_or_default().iter().take(80) {
        let text = e["text"].as_str().unwrap_or("").trim();
        if text.is_empty() {
            continue;
        }
        let pages: Vec<Value> = e["pages"].as_array().map(Vec::as_slice).unwrap_or_default().iter().take(4).filter_map(|p| {
            let t = p["titles"]["normalized"].as_str().or(p["title"].as_str())?;
            let canon = p["titles"]["canonical"].as_str().unwrap_or(t);
            Some(json!({ "title": t, "url": page_url(lang, canon) }))
        }).collect();
        out.push(json!({ "year": e["year"], "text": text, "pages": pages }));
    }
    out
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Spike {
    pub spike: bool,
    pub latest: f64,
    pub latest_date: String,
    pub median: f64,
    pub ratio: f64,
    pub z: f64,
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = v.len();
    if n == 0 { 0.0 } else if n % 2 == 1 { v[n / 2] } else { (v[n / 2 - 1] + v[n / 2]) / 2.0 }
}

/// Latest complete day against the median of the previous 28 days (robust z-score via MAD).
/// `series` is (YYYY-MM-DD, views) ascending; a still-running `today` is dropped first.
pub fn page_view_spike(series: &[(String, f64)], today: &str) -> Option<Spike> {
    let mut s: Vec<&(String, f64)> = series.iter().filter(|(d, _)| d.as_str() < today).collect();
    if s.len() < 15 {
        return None;
    }
    let (last_d, last_v) = s.pop().map(|(d, v)| (d.clone(), *v))?;
    let base: Vec<f64> = s.iter().rev().take(28).map(|(_, v)| *v).collect();
    let mut b = base.clone();
    let med = median(&mut b);
    let mut dev: Vec<f64> = base.iter().map(|v| (v - med).abs()).collect();
    let mad = median(&mut dev);
    let scale = (1.4826 * mad).max(med * 0.1).max(1.0);
    let z = (last_v - med) / scale;
    let ratio = if med > 0.0 { last_v / med } else { 0.0 };
    Some(Spike { spike: z >= 3.5 && last_v >= 2.0 * med && last_v >= 50.0, latest: last_v, latest_date: last_d, median: med, ratio, z })
}

/// Pageviews `items` -> (YYYY-MM-DD, views) ascending.
pub fn parse_pageviews(v: &Value) -> Vec<(String, f64)> {
    let mut out: Vec<(String, f64)> = v["items"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|i| {
            let ts = i["timestamp"].as_str()?;
            (ts.len() >= 8 && ts.bytes().take(8).all(|b| b.is_ascii_digit())).then(|| (format!("{}-{}-{}", &ts[0..4], &ts[4..6], &ts[6..8]), i["views"].as_f64().unwrap_or(0.0)))
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn has_human(claims: &Value) -> bool {
    claims["claims"]["P31"].as_array().or(claims["P31"].as_array()).map(Vec::as_slice).unwrap_or_default().iter().any(|c| c["mainsnak"]["datavalue"]["value"]["id"] == "Q5")
}

fn snak_text(v: &Value) -> Option<(String, Option<String>)> {
    let dv = &v["mainsnak"]["datavalue"];
    let val = &dv["value"];
    match dv["type"].as_str()? {
        "wikibase-entityid" => val["id"].as_str().map(|id| (id.to_string(), Some(id.to_string()))),
        "string" => val.as_str().map(|s| (s.chars().take(300).collect(), None)),
        "time" => {
            let t = val["time"].as_str()?;
            let p = val["precision"].as_i64().unwrap_or(11);
            let d = t.trim_start_matches('+');
            let d = if p >= 11 { d.get(..10)? } else if p == 10 { d.get(..7)? } else { d.get(..4)? };
            Some((d.to_string(), None))
        }
        "quantity" => {
            let a = val["amount"].as_str()?.trim_start_matches('+');
            let unit = val["unit"].as_str().and_then(|u| u.rsplit('/').next()).filter(|u| u.starts_with('Q')).map(str::to_string);
            Some((a.to_string(), unit.map(|u| format!("unit:{u}"))))
        }
        "globecoordinate" => Some((format!("{:.5}, {:.5}", val["latitude"].as_f64()?, val["longitude"].as_f64()?), Some("coord".into()))),
        _ => None,
    }
}

const PROPS: [(&str, &str); 24] = [
    ("P31", "Instance of"), ("P279", "Subclass of"), ("P17", "Country"), ("P131", "Located in"), ("P625", "Coordinates"), ("P571", "Inception"), ("P576", "Dissolved"),
    ("P580", "Start"), ("P582", "End"), ("P585", "Point in time"), ("P159", "Headquarters"), ("P856", "Official website"), ("P749", "Parent organisation"), ("P127", "Owned by"),
    ("P137", "Operator"), ("P176", "Manufacturer"), ("P606", "First flight"), ("P458", "IMO number"), ("P587", "MMSI"), ("P1278", "LEI"), ("P1082", "Population"),
    ("P2043", "Length"), ("P238", "IATA airport code"), ("P239", "ICAO airport code"),
];

/// Wikidata entity JSON -> card. Returns Err(Person) for humans. Item ids in values are left as ids, to be labelled later.
pub fn entity_card(qid: &str, v: &Value) -> Result<Value, WikiError> {
    let e = &v["entities"][qid];
    if e.is_null() || e["missing"].is_string() {
        return Err(WikiError::NotFound("no such Wikidata entity".into()));
    }
    if has_human(e) {
        return Err(WikiError::Person);
    }
    let mut facts = Vec::new();
    let mut coords = Value::Null;
    for (pid, label) in PROPS {
        let Some(list) = e["claims"][pid].as_array() else { continue };
        let vals: Vec<Value> = list
            .iter()
            .filter(|c| c["rank"] != "deprecated")
            .take(5)
            .filter_map(|c| snak_text(c))
            .map(|(t, k)| {
                if k.as_deref() == Some("coord") {
                    let mut it = t.split(", ");
                    coords = json!({ "lat": it.next().and_then(|x| x.parse::<f64>().ok()), "lon": it.next().and_then(|x| x.parse::<f64>().ok()) });
                }
                match k {
                    Some(k) if k.starts_with('Q') => json!({ "text": t, "qid": k }),
                    Some(k) if k.starts_with("unit:") => json!({ "text": t, "unit": &k[5..] }),
                    _ if pid == "P856" && (t.starts_with("http://") || t.starts_with("https://")) => json!({ "text": t, "url": t }),
                    _ => json!({ "text": t }),
                }
            })
            .collect();
        if !vals.is_empty() {
            facts.push(json!({ "property": pid, "label": label, "values": vals }));
        }
    }
    let aliases: Vec<&str> = e["aliases"]["en"].as_array().map(Vec::as_slice).unwrap_or_default().iter().filter_map(|a| a["value"].as_str()).take(6).collect();
    Ok(json!({
        "id": qid, "label": e["labels"]["en"]["value"], "description": e["descriptions"]["en"]["value"], "aliases": aliases,
        "wikipedia_title": e["sitelinks"]["enwiki"]["title"], "facts": facts, "coordinates": coords, "url": format!("https://www.wikidata.org/wiki/{qid}"),
    }))
}

/// Fill in `label` for every item value from a `wbgetentities&props=labels` response.
pub fn apply_labels(card: &mut Value, labels: &Value) {
    let name = |q: &str| labels["entities"][q]["labels"]["en"]["value"].as_str().map(str::to_string);
    if let Some(facts) = card["facts"].as_array_mut() {
        for f in facts {
            if let Some(vals) = f["values"].as_array_mut() {
                for v in vals {
                    if let Some(q) = v["qid"].as_str().or(v["unit"].as_str()).map(str::to_string) {
                        if let Some(n) = name(&q) {
                            v["label"] = json!(n);
                        }
                    }
                }
            }
        }
    }
}

pub fn referenced_ids(card: &Value) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for f in card["facts"].as_array().map(Vec::as_slice).unwrap_or_default() {
        for v in f["values"].as_array().map(Vec::as_slice).unwrap_or_default() {
            for k in ["qid", "unit"] {
                if let Some(q) = v[k].as_str() {
                    if !ids.iter().any(|x| x == q) && ids.len() < 50 {
                        ids.push(q.to_string());
                    }
                }
            }
        }
    }
    ids
}

// ---------------------------------------------------------------------------------------------------------------
// Change stream
// ---------------------------------------------------------------------------------------------------------------

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Change {
    pub ts: i64,
    pub lang: String,
    pub title: String,
    /// edit, new or log
    pub kind: String,
    pub delta: Option<i64>,
    pub minor: bool,
    pub url: String,
}

/// One SSE line -> a change notice if it concerns a watched (lang, title). Editor, IP and edit comment are never read.
pub fn process_line(line: &str, watch: &HashSet<(String, String)>) -> Option<Change> {
    let data = line.strip_prefix("data:")?.trim_start();
    if !watch.iter().any(|(l, _)| data.contains(&format!("\"wiki\":\"{l}wiki\""))) {
        return None;
    }
    let v: Value = serde_json::from_str(data).ok()?;
    let wiki = v["wiki"].as_str()?;
    let lang = wiki.strip_suffix("wiki")?;
    if v["namespace"].as_i64() != Some(0) {
        return None;
    }
    let title = v["title"].as_str()?.replace(' ', "_");
    if !watch.contains(&(lang.to_string(), title.clone())) {
        return None;
    }
    let kind = match v["type"].as_str()? {
        "edit" => "edit",
        "new" => "new",
        "log" => "log",
        _ => return None,
    };
    let delta = match (v["length"]["old"].as_i64(), v["length"]["new"].as_i64()) {
        (Some(o), Some(n)) => Some(n - o),
        (None, Some(n)) => Some(n),
        _ => None,
    };
    Some(Change { ts: v["timestamp"].as_i64().unwrap_or(0), lang: lang.into(), url: page_url(lang, &title), title, kind: kind.into(), delta, minor: v["minor"].as_bool().unwrap_or(false) })
}

pub struct Stream {
    pub running: AtomicBool,
    pub last_touch: AtomicI64,
    pub connected: AtomicBool,
    pub events: Mutex<VecDeque<Change>>,
    pub note: Mutex<String>,
}
impl Stream {
    pub fn new() -> Stream {
        Stream { running: AtomicBool::new(false), last_touch: AtomicI64::new(0), connected: AtomicBool::new(false), events: Mutex::new(VecDeque::new()), note: Mutex::new(String::new()) }
    }
    pub fn push(&self, c: Change) {
        let mut e = self.events.lock().unwrap_or_else(|e| e.into_inner());
        e.push_front(c);
        e.truncate(200);
    }
}

/// Read one SSE connection until it ends, the idle limit passes, or `stop` says so. Returns the number of matches.
pub fn read_stream(reader: impl Read, stream: &Stream, watch: &dyn Fn() -> HashSet<(String, String)>, idle_secs: i64) -> usize {
    let mut n = 0;
    let mut cur = watch();
    let mut refreshed = Instant::now();
    for line in BufReader::new(reader).lines() {
        let Ok(line) = line else { break };
        if now_secs() - stream.last_touch.load(Ordering::SeqCst) > idle_secs {
            break;
        }
        if refreshed.elapsed() > Duration::from_secs(30) {
            cur = watch();
            refreshed = Instant::now();
        }
        if cur.is_empty() {
            break;
        }
        if let Some(c) = process_line(&line, &cur) {
            stream.push(c);
            n += 1;
        }
    }
    n
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

// ---------------------------------------------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------------------------------------------

pub struct Client {
    pub agent: ureq::Agent,
    /// Tests and development only: send every request here instead of the Wikimedia hosts.
    pub base: Option<String>,
    pub cache: Cache,
}

pub const TTL_DAY: Duration = Duration::from_secs(6 * 3600);
pub const TTL_CURRENT: Duration = Duration::from_secs(1800);
pub const TTL_VIEWS: Duration = Duration::from_secs(3 * 3600);
pub const TTL_ENTITY: Duration = Duration::from_secs(24 * 3600);

impl Client {
    pub fn new(agent: ureq::Agent, base: Option<String>) -> Client {
        Client { agent, base: base.map(|b| b.trim_end_matches('/').to_string()), cache: Cache::new(300) }
    }
    fn host(&self, real: &str) -> String {
        self.base.clone().unwrap_or_else(|| real.to_string())
    }
    fn wiki(&self, lang: &str) -> String {
        self.host(&format!("https://{lang}.wikipedia.org"))
    }

    /// GET JSON. A 404 becomes NotFound(`what`).
    fn get(&self, url: &str, what: &str) -> Result<Value, WikiError> {
        let mut res = self
            .agent
            .get(url)
            .header("Accept", "application/json")
            .config()
            .http_status_as_error(false)
            .build()
            .call()
            .map_err(|e| WikiError::Upstream(format!("could not reach Wikimedia: {e}")))?;
        let status = res.status().as_u16();
        let mut buf = Vec::new();
        res.body_mut().as_reader().take(MAX_BODY).read_to_end(&mut buf).map_err(|e| WikiError::Upstream(format!("reading response failed: {e}")))?;
        match status {
            200 => serde_json::from_slice(&buf).map_err(|_| WikiError::Upstream("Wikimedia returned malformed JSON".into())),
            404 => Err(WikiError::NotFound(what.to_string())),
            429 => Err(WikiError::Upstream("Wikimedia is rate limiting this host (HTTP 429); try again shortly".into())),
            s => Err(WikiError::Upstream(format!("Wikimedia answered HTTP {s}"))),
        }
    }

    fn cached(&self, key: String, ttl: Duration, f: impl FnOnce() -> Result<Value, WikiError>) -> Result<Value, WikiError> {
        if let Some(mut v) = self.cache.get(&key, ttl) {
            v["cached"] = json!(true);
            return Ok(v);
        }
        let mut v = f()?;
        self.cache.put(key, v.clone());
        v["cached"] = json!(false);
        Ok(v)
    }

    pub fn onthisday(&self, lang: &str, month: u32, day: u32) -> Result<Value, WikiError> {
        let lang = valid_lang(lang)?;
        if chrono::NaiveDate::from_ymd_opt(2024, month, day).is_none() {
            return Err(WikiError::BadInput("month and day do not form a date".into()));
        }
        self.cached(format!("otd|{lang}|{month}|{day}"), TTL_DAY, || {
            let v = self.get(&format!("{}/api/rest_v1/feed/onthisday/events/{month:02}/{day:02}", self.wiki(lang)), "no On this day data for that date")?;
            Ok(json!({ "lang": lang, "month": month, "day": day, "events": parse_onthisday(&v, lang) }))
        })
    }

    /// English Wikipedia "Portal:Current events" for one day.
    pub fn current_events(&self, date: chrono::NaiveDate) -> Result<Value, WikiError> {
        let key = date.format("%Y-%m-%d").to_string();
        self.cached(format!("cur|{key}"), TTL_CURRENT, || {
            let page = date.format("Portal:Current_events/%Y_%B_%-d").to_string();
            let url = format!("{}/w/api.php?action=parse&page={}&prop=text&format=json&formatversion=2&disableeditsection=1", self.wiki("en"), pct(&page));
            let v = self.get(&url, "no current events page for that date")?;
            if v["error"].is_object() {
                return Ok(json!({ "date": key, "items": [], "note": "Wikipedia has no current events page for this date yet.", "page_url": page_url("en", &page) }));
            }
            let items = parse_current_events(v["parse"]["text"].as_str().unwrap_or(""));
            Ok(json!({ "date": key, "items": items, "page_url": page_url("en", &page) }))
        })
    }

    /// Resolve a title to its canonical form and Wikidata item; refuses pages about people.
    pub fn resolve(&self, lang: &str, title: &str) -> Result<Value, WikiError> {
        let lang = valid_lang(lang)?;
        let t = norm_title(title)?;
        self.cached(format!("res|{lang}|{}", t.to_lowercase()), TTL_ENTITY, || {
            let s = self.get(&format!("{}/api/rest_v1/page/summary/{}?redirect=true", self.wiki(lang), pct(&t)), "no such article")?;
            if s["type"] == "disambiguation" {
                return Err(WikiError::BadInput("that title is a disambiguation page; pick a specific article".into()));
            }
            let canon = s["titles"]["canonical"].as_str().ok_or_else(|| WikiError::Upstream("summary had no title".into()))?.to_string();
            let qid = s["wikibase_item"].as_str().map(str::to_string);
            if let Some(q) = &qid {
                let c = self.get(&format!("{}/w/api.php?action=wbgetclaims&entity={q}&property=P31&format=json", self.host("https://www.wikidata.org")), "no Wikidata item")?;
                if has_human(&c) {
                    return Err(WikiError::Person);
                }
            }
            Ok(json!({ "lang": lang, "title": canon, "display": s["titles"]["normalized"], "qid": qid, "description": s["description"], "url": page_url(lang, &canon) }))
        })
    }

    /// Daily views for the last `days` days with spike analysis. Resolves the title first (people are refused).
    pub fn pageviews(&self, lang: &str, title: &str, days: u32) -> Result<Value, WikiError> {
        let r = self.resolve(lang, title)?;
        let (lang, canon) = (r["lang"].as_str().unwrap_or("en").to_string(), r["title"].as_str().unwrap_or("").to_string());
        let days = days.clamp(15, 90);
        let today = chrono::Utc::now().date_naive();
        let (start, end) = ((today - chrono::Duration::days(days as i64)).format("%Y%m%d"), today.format("%Y%m%d"));
        let mut v = self.cached(format!("pv|{lang}|{canon}|{days}|{end}"), TTL_VIEWS, || {
            let url = format!("{}/api/rest_v1/metrics/pageviews/per-article/{lang}.wikipedia/all-access/user/{}/daily/{start}/{end}", self.host("https://wikimedia.org"), pct(&canon));
            let raw = match self.get(&url, "no page view data for this period") {
                Ok(v) => v,
                Err(WikiError::NotFound(_)) => json!({ "items": [] }),
                Err(e) => return Err(e),
            };
            let series = parse_pageviews(&raw);
            let spike = page_view_spike(&series, &today.format("%Y-%m-%d").to_string());
            Ok(json!({ "series": series.iter().map(|(d, v)| json!([d, v])).collect::<Vec<_>>(), "spike": spike }))
        })?;
        v["title"] = json!(canon);
        v["lang"] = json!(lang);
        v["url"] = r["url"].clone();
        v["description"] = r["description"].clone();
        Ok(v)
    }

    pub fn entity_search(&self, q: &str) -> Result<Value, WikiError> {
        let q = q.trim();
        if q.chars().count() < 2 || q.chars().count() > 100 || q.chars().any(|c| c.is_control()) {
            return Err(WikiError::BadInput("search needs 2 to 100 characters".into()));
        }
        self.cached(format!("ws|{}", q.to_lowercase()), Duration::from_secs(3600), || {
            let url = format!("{}/w/api.php?action=wbsearchentities&search={}&language=en&uselang=en&limit=8&format=json", self.host("https://www.wikidata.org"), pct(q));
            let v = self.get(&url, "no results")?;
            let results: Vec<Value> = v["search"].as_array().map(Vec::as_slice).unwrap_or_default().iter().filter_map(|r| Some(json!({ "id": r["id"].as_str()?, "label": r["label"], "description": r["description"] }))).collect();
            Ok(json!({ "results": results }))
        })
    }

    pub fn entity(&self, qid: &str) -> Result<Value, WikiError> {
        let qid = valid_qid(qid)?;
        self.cached(format!("ent|{qid}"), TTL_ENTITY, || {
            let base = self.host("https://www.wikidata.org");
            let url = format!("{base}/w/api.php?action=wbgetentities&ids={qid}&props=labels|descriptions|aliases|sitelinks|claims&languages=en&sitefilter=enwiki&format=json");
            let mut card = entity_card(&qid, &self.get(&url, "no such Wikidata entity")?)?;
            let ids = referenced_ids(&card);
            if !ids.is_empty() {
                let lurl = format!("{base}/w/api.php?action=wbgetentities&ids={}&props=labels&languages=en&format=json", ids.join("|"));
                if let Ok(l) = self.get(&lurl, "labels") {
                    apply_labels(&mut card, &l);
                }
            }
            Ok(card)
        })
    }
}

pub fn spawn_stream(client_agent: ureq::Agent, url: String, stream: std::sync::Arc<Stream>, watch: std::sync::Arc<dyn Fn() -> HashSet<(String, String)> + Send + Sync>, idle_secs: i64) {
    if stream.running.swap(true, Ordering::SeqCst) {
        return;
    }
    std::thread::spawn(move || {
        let mut backoff = 3;
        loop {
            if now_secs() - stream.last_touch.load(Ordering::SeqCst) > idle_secs || watch().is_empty() {
                break;
            }
            let res = client_agent.get(&url).header("Accept", "text/event-stream").config().timeout_global(None).timeout_recv_body(Some(Duration::from_secs(120))).http_status_as_error(false).build().call();
            match res {
                Ok(mut r) if r.status().as_u16() == 200 => {
                    stream.connected.store(true, Ordering::SeqCst);
                    *stream.note.lock().unwrap_or_else(|e| e.into_inner()) = String::new();
                    backoff = 3;
                    read_stream(r.body_mut().as_reader(), &stream, &*watch, idle_secs);
                    stream.connected.store(false, Ordering::SeqCst);
                }
                Ok(r) => *stream.note.lock().unwrap_or_else(|e| e.into_inner()) = format!("EventStreams answered HTTP {}", r.status().as_u16()),
                Err(e) => *stream.note.lock().unwrap_or_else(|e| e.into_inner()) = format!("could not reach EventStreams: {e}"),
            }
            std::thread::sleep(Duration::from_secs(backoff));
            backoff = (backoff * 2).min(60);
        }
        stream.connected.store(false, Ordering::SeqCst);
        stream.running.store(false, Ordering::SeqCst);
    });
}

// ---------------------------------------------------------------------------------------------------------------
// Watchlist store
// ---------------------------------------------------------------------------------------------------------------

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
const TOPICS: TableDefinition<u64, &[u8]> = TableDefinition::new("topics");

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Topic {
    pub id: u64,
    pub lang: String,
    pub title: String,
    pub display: String,
    pub qid: Option<String>,
    pub description: Option<String>,
    pub added: i64,
}

pub struct Store {
    db: Database,
}
impl Store {
    pub fn open(path: &str) -> anyhow::Result<Store> {
        let db = Database::create(path)?;
        let tx = db.begin_write()?;
        tx.open_table(TOPICS)?;
        tx.commit()?;
        Ok(Store { db })
    }
    pub fn list(&self) -> anyhow::Result<Vec<Topic>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(TOPICS)?;
        Ok(t.iter()?.filter_map(|r| r.ok()).filter_map(|(_, v)| serde_json::from_slice(v.value()).ok()).collect())
    }
    pub fn add(&self, lang: &str, title: &str, display: &str, qid: Option<&str>, description: Option<&str>) -> anyhow::Result<Topic> {
        let tx = self.db.begin_write()?;
        let topic;
        {
            let mut t = tx.open_table(TOPICS)?;
            if t.len()? as usize >= MAX_TOPICS {
                anyhow::bail!("at most {MAX_TOPICS} topics; remove one first");
            }
            if t.iter()?.filter_map(|r| r.ok()).filter_map(|(_, v)| serde_json::from_slice::<Topic>(v.value()).ok()).any(|e| e.lang == lang && e.title == title) {
                anyhow::bail!("that topic is already watched");
            }
            let id = t.last()?.map(|(k, _)| k.value() + 1).unwrap_or(1);
            topic = Topic { id, lang: lang.into(), title: title.into(), display: display.into(), qid: qid.map(str::to_string), description: description.map(str::to_string), added: now_secs() };
            t.insert(id, serde_json::to_vec(&topic)?.as_slice())?;
        }
        tx.commit()?;
        Ok(topic)
    }
    pub fn delete(&self, id: u64) -> anyhow::Result<bool> {
        let tx = self.db.begin_write()?;
        let existed = tx.open_table(TOPICS)?.remove(id)?.is_some();
        tx.commit()?;
        Ok(existed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_validation() {
        assert_eq!(norm_title(" Suez Canal ").unwrap(), "Suez_Canal");
        for bad in ["", "a|b", "a#b", "<x>", "[[x]]", "a\nb", ":Talk", &"x".repeat(256)] {
            assert!(norm_title(bad).is_err(), "{bad:?}");
        }
        assert_eq!(valid_lang("").unwrap(), "en");
        assert!(valid_lang("evil.com/x").is_err());
        assert_eq!(valid_qid("q42").unwrap(), "Q42");
        for bad in ["", "Q", "Q0", "42", "Q4 2", "Q42;drop", "Q123456789012345"] {
            assert!(valid_qid(bad).is_err(), "{bad}");
        }
        assert_eq!(pct("Café/AC_(x)"), "Caf%C3%A9%2FAC_%28x%29");
        assert_eq!(page_url("en", "Foo:Bar_(x)"), "https://en.wikipedia.org/wiki/Foo:Bar_%28x%29");
    }

    const CE: &str = r#"<div class="current-events-content description">
<p><b>Armed conflicts and attacks</b>
</p>
<ul><li><a href="/wiki/Gaza_war" title="Gaza war">Gaza war</a>
<ul><li>Five <a href="/wiki/Police" title="Police">police officers</a> are killed in an airstrike in <a href="/wiki/Rafah" title="Rafah">Rafah</a>. <a rel="nofollow" class="external text" href="https://www.example.com/news/1">(Example News)</a></li>
<li>Second &amp; third item. <a class="external text" href="javascript:bad()">(Bad)</a></li></ul></li>
<li>Standalone item</li></ul>
<p><b>Disasters and accidents</b></p>
<ul><li>A flood hits <a href="/wiki/Valencia" title="Valencia">Valencia</a>. <a class="external text" href="https://f.example/x">(F)</a></li></ul>
</div><div class="current-events-more">more</div><ul><li>ignored</li></ul>"#;

    #[test]
    fn current_events_parsing() {
        let items = parse_current_events(CE);
        assert_eq!(items.len(), 4, "{items:#?}");
        assert_eq!(items[0]["category"], "Armed conflicts and attacks");
        assert_eq!(items[0]["topic"], "Gaza war");
        assert_eq!(items[0]["source"], "Example News");
        assert_eq!(items[0]["source_url"], "https://www.example.com/news/1");
        assert!(items[0]["text"].as_str().unwrap().starts_with("Five police officers are killed"));
        assert_eq!(items[0]["pages"][0], "Police");
        assert_eq!(items[1]["text"], "Second & third item.");
        assert!(items[1]["source_url"].is_null(), "non-http source links are dropped");
        assert_eq!(items[2]["topic"], "");
        assert_eq!(items[3]["category"], "Disasters and accidents");
        assert!(parse_current_events("<html></html>").is_empty());
    }

    #[test]
    fn onthisday_parsing() {
        let v = json!({ "events": [{ "text": "A treaty is signed.", "year": 1990, "pages": [{ "titles": { "canonical": "Treaty_of_X", "normalized": "Treaty of X" } }] }, { "text": "", "year": 1 }, { "text": "No pages", "year": 5 }] });
        let e = parse_onthisday(&v, "en");
        assert_eq!(e.len(), 2);
        assert_eq!(e[0]["pages"][0]["url"], "https://en.wikipedia.org/wiki/Treaty_of_X");
        assert_eq!(e[1]["pages"].as_array().unwrap().len(), 0);
    }

    fn series(vals: &[f64]) -> Vec<(String, f64)> {
        vals.iter().enumerate().map(|(i, v)| (format!("2026-10-{:02}", i + 1), *v)).collect()
    }

    #[test]
    fn spike_detection() {
        let mut calm = vec![100.0, 110.0, 95.0, 105.0, 98.0, 102.0, 107.0];
        calm = calm.repeat(4);
        let mut s = calm.clone();
        s.push(104.0);
        assert!(!page_view_spike(&series(&s), "2026-11-30").unwrap().spike);
        let mut hot = calm.clone();
        hot.push(900.0);
        let sp = page_view_spike(&series(&hot), "2026-11-30").unwrap();
        assert!(sp.spike && sp.ratio > 8.0 && sp.latest_date == "2026-10-29", "{sp:?}");
        // today's partial day is ignored
        let mut partial = calm.clone();
        partial.push(5.0);
        partial.push(999.0);
        let ser = series(&partial);
        let today = ser.last().unwrap().0.clone();
        assert!(!page_view_spike(&ser, &today).unwrap().spike);
        // tiny absolute numbers never count
        let mut tiny = vec![1.0; 28];
        tiny.push(20.0);
        assert!(!page_view_spike(&series(&tiny), "2026-11-30").unwrap().spike);
        assert!(page_view_spike(&series(&[1.0; 5]), "2026-11-30").is_none());
        let pv = parse_pageviews(&json!({ "items": [{ "timestamp": "2026102000", "views": 5 }, { "timestamp": "2026101900", "views": 3 }, { "timestamp": "x" }] }));
        assert_eq!(pv, vec![("2026-10-19".to_string(), 3.0), ("2026-10-20".to_string(), 5.0)]);
    }

    fn entity(p31: &str) -> Value {
        json!({ "entities": { "Q1": { "labels": { "en": { "value": "Suez Canal" } }, "descriptions": { "en": { "value": "canal in Egypt" } }, "aliases": { "en": [{ "value": "Canal de Suez" }] },
          "sitelinks": { "enwiki": { "title": "Suez Canal" } },
          "claims": {
            "P31": [{ "rank": "normal", "mainsnak": { "datavalue": { "type": "wikibase-entityid", "value": { "id": p31 } } } }, { "rank": "deprecated", "mainsnak": { "datavalue": { "type": "wikibase-entityid", "value": { "id": "Q9" } } } }],
            "P625": [{ "mainsnak": { "datavalue": { "type": "globecoordinate", "value": { "latitude": 30.5, "longitude": 32.3 } } } }],
            "P571": [{ "mainsnak": { "datavalue": { "type": "time", "value": { "time": "+1869-11-17T00:00:00Z", "precision": 11 } } } }],
            "P856": [{ "mainsnak": { "datavalue": { "type": "string", "value": "https://www.suezcanal.gov.eg" } } }, { "mainsnak": { "datavalue": { "type": "string", "value": "javascript:x" } } }],
            "P2043": [{ "mainsnak": { "datavalue": { "type": "quantity", "value": { "amount": "+193.3", "unit": "http://www.wikidata.org/entity/Q828224" } } } }],
            "P999": [{ "mainsnak": { "datavalue": { "type": "string", "value": "ignored property" } } }] } } } })
    }

    #[test]
    fn entity_cards() {
        let mut c = entity_card("Q1", &entity("Q12280")).unwrap();
        assert_eq!(c["label"], "Suez Canal");
        assert_eq!(c["coordinates"]["lat"], 30.5);
        let facts = c["facts"].as_array().unwrap();
        assert_eq!(facts.len(), 5);
        assert_eq!(facts[0]["values"].as_array().unwrap().len(), 1, "deprecated statement skipped");
        let inception = facts.iter().find(|f| f["property"] == "P571").unwrap();
        assert_eq!(inception["values"][0]["text"], "1869-11-17");
        let web = facts.iter().find(|f| f["property"] == "P856").unwrap();
        assert!(web["values"][0]["url"].is_string() && web["values"][1]["url"].is_null());
        let ids = referenced_ids(&c);
        assert_eq!(ids, vec!["Q12280", "Q828224"]);
        apply_labels(&mut c, &json!({ "entities": { "Q12280": { "labels": { "en": { "value": "canal" } } }, "Q828224": { "labels": { "en": { "value": "kilometre" } } } } }));
        assert_eq!(c["facts"][0]["values"][0]["label"], "canal");
        assert!(matches!(entity_card("Q1", &entity("Q5")), Err(WikiError::Person)));
        assert!(matches!(entity_card("Q2", &entity("Q5")), Err(WikiError::NotFound(_))));
        assert!(matches!(entity_card("Q1", &json!({ "entities": { "Q1": { "missing": "" } } })), Err(WikiError::NotFound(_))));
    }

    fn watch(items: &[(&str, &str)]) -> HashSet<(String, String)> {
        items.iter().map(|(l, t)| (l.to_string(), t.to_string())).collect()
    }

    #[test]
    fn stream_lines_carry_no_editor_data() {
        let w = watch(&[("en", "Suez_Canal")]);
        let line = r#"data: {"wiki":"enwiki","namespace":0,"title":"Suez Canal","type":"edit","user":"SecretEditor","comment":"private note","length":{"old":100,"new":160},"minor":true,"timestamp":1793600000,"bot":false}"#;
        let c = process_line(line, &w).unwrap();
        assert_eq!((c.title.as_str(), c.kind.as_str(), c.delta, c.minor, c.ts), ("Suez_Canal", "edit", Some(60), true, 1793600000));
        let json = serde_json::to_string(&c).unwrap();
        assert!(!json.contains("SecretEditor") && !json.contains("private note"));
        assert_eq!(c.url, "https://en.wikipedia.org/wiki/Suez_Canal");
        assert!(process_line(&line.replace("Suez Canal", "Other"), &w).is_none());
        assert!(process_line(&line.replace("enwiki", "dewiki"), &w).is_none());
        assert!(process_line(&line.replace("\"namespace\":0", "\"namespace\":1"), &w).is_none());
        assert!(process_line(&line.replace("\"edit\"", "\"categorize\""), &w).is_none());
        assert!(process_line(": keepalive", &w).is_none());
        assert!(process_line("data: {broken enwiki", &w).is_none());
        assert!(process_line("event: message", &w).is_none());
    }

    #[test]
    fn read_stream_filters_and_stops_when_idle() {
        let st = Stream::new();
        st.last_touch.store(now_secs(), Ordering::SeqCst);
        let body = "event: message\ndata: {\"wiki\":\"enwiki\",\"namespace\":0,\"title\":\"A\",\"type\":\"new\",\"length\":{\"new\":10},\"timestamp\":1}\ndata: {\"wiki\":\"enwiki\",\"namespace\":0,\"title\":\"B\",\"type\":\"edit\"}\n";
        let w = || watch(&[("en", "A")]);
        assert_eq!(read_stream(body.as_bytes(), &st, &w, 600), 1);
        assert_eq!(st.events.lock().unwrap().len(), 1);
        st.last_touch.store(now_secs() - 1000, Ordering::SeqCst);
        assert_eq!(read_stream(body.as_bytes(), &st, &w, 600), 0, "idle stream stops reading");
        st.last_touch.store(now_secs(), Ordering::SeqCst);
        assert_eq!(read_stream(body.as_bytes(), &st, &|| watch(&[]), 600), 0, "empty watchlist");
        for i in 0..250 {
            st.push(Change { ts: i, lang: "en".into(), title: "A".into(), kind: "edit".into(), delta: None, minor: false, url: String::new() });
        }
        assert_eq!(st.events.lock().unwrap().len(), 200);
    }

    #[test]
    fn store_cap_and_dupes() {
        let p = std::env::temp_dir().join(format!("wiki-store-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let s = Store::open(p.to_str().unwrap()).unwrap();
        let t = s.add("en", "Suez_Canal", "Suez Canal", Some("Q1"), None).unwrap();
        assert!(s.add("en", "Suez_Canal", "Suez Canal", None, None).is_err());
        for i in 0..MAX_TOPICS {
            let _ = s.add("en", &format!("T{i}"), "t", None, None);
        }
        assert_eq!(s.list().unwrap().len(), MAX_TOPICS);
        assert!(s.delete(t.id).unwrap() && !s.delete(t.id).unwrap());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn cache_cap() {
        let c = Cache::new(2);
        for i in 0..5 {
            c.put(format!("{i}"), json!(i));
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(c.len(), 2);
        assert!(c.get("4", TTL_DAY).is_some() && c.get("0", TTL_DAY).is_none());
    }
}

//! Keyless open blocklists: definitions, parsers and an on-demand downloader with a disk copy per feed.

use std::{
    collections::HashMap,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use serde_json::{Value, json};

use crate::{common::*, net::Net};

pub const MAX_FEED_BYTES: u64 = 16 * 1024 * 1024;
pub const DIR_CAP_BYTES: u64 = 64 * 1024 * 1024;
const RETRY_COOLDOWN: u64 = 120;
pub const MIN_REFRESH: u64 = 300;

#[derive(Clone, Debug)]
pub struct Entry {
    pub indicator: String,
    pub since: Option<String>,
    pub detail: String,
    pub link: Option<String>,
    pub extra: Value,
}
impl Entry {
    pub fn json(&self) -> Value {
        json!({ "indicator": self.indicator, "since": self.since, "detail": self.detail, "link": self.link, "extra": self.extra })
    }
}

#[derive(Default)]
pub struct FeedData {
    pub ips: HashMap<IpAddr, Vec<Entry>>,
    pub nets: Vec<(Net, Entry)>,
    pub urls: HashMap<String, Entry>,
    pub hosts: HashMap<String, (usize, Entry)>,
    pub recent: Vec<Entry>,
    pub total: usize,
    pub source_updated: Option<String>,
}

pub struct FeedDef {
    pub id: &'static str,
    pub name: &'static str,
    pub kind: &'static str,
    pub urls: &'static [&'static str],
    pub ttl: u64,
    pub info: &'static str,
    pub licence: &'static str,
    pub recent_label: &'static str,
    pub parse: fn(&str) -> Result<FeedData, String>,
}

pub static FEEDS: [FeedDef; 5] = [
    FeedDef { id: "feodo", name: "Feodo Tracker botnet C2", kind: "ip", urls: &["https://feodotracker.abuse.ch/downloads/ipblocklist.json"], ttl: 3600,
        info: "https://feodotracker.abuse.ch/", licence: "abuse.ch, CC0", recent_label: "newest command-and-control servers", parse: parse_feodo },
    FeedDef { id: "spamhaus-drop", name: "Spamhaus DROP", kind: "cidr", urls: &["https://www.spamhaus.org/drop/drop_v4.json", "https://www.spamhaus.org/drop/drop_v6.json"], ttl: 43_200,
        info: "https://www.spamhaus.org/drop/", licence: "The Spamhaus Project; free for use under the DROP terms", recent_label: "listed networks", parse: parse_drop },
    FeedDef { id: "ipsum", name: "IPsum aggregated blocklists", kind: "ip", urls: &["https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"], ttl: 43_200,
        info: "https://github.com/stamparm/ipsum", licence: "stamparm/ipsum, Unlicense", recent_label: "addresses on the most lists", parse: parse_ipsum },
    FeedDef { id: "tor-exit", name: "Tor exit nodes", kind: "ip", urls: &["https://check.torproject.org/torbulkexitlist"], ttl: 3600,
        info: "https://check.torproject.org/torbulkexitlist", licence: "The Tor Project, public data", recent_label: "exit addresses", parse: parse_tor },
    FeedDef { id: "openphish", name: "OpenPhish community feed", kind: "url", urls: &["https://openphish.com/feed.txt"], ttl: 43_200,
        info: "https://openphish.com/", licence: "OpenPhish community feed: free for personal, non-commercial use", recent_label: "latest phishing URLs", parse: parse_openphish },
];

fn cut(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn finish(mut d: FeedData, mut recent: Vec<Entry>) -> FeedData {
    recent.truncate(100);
    d.recent = recent;
    d
}

pub fn parse_feodo(text: &str) -> Result<FeedData, String> {
    let v: Value = serde_json::from_str(text).map_err(|_| "Feodo list is not valid JSON")?;
    let arr = v.as_array().ok_or("Feodo list is not an array")?;
    let mut d = FeedData::default();
    let mut all = vec![];
    for r in arr {
        let Some(ip) = r["ip_address"].as_str().and_then(|s| s.parse::<IpAddr>().ok()) else { continue };
        let mal = r["malware"].as_str().unwrap_or("unknown");
        let e = Entry {
            indicator: ip.to_string(),
            since: r["first_seen"].as_str().map(|s| cut(s, 19)),
            detail: format!("{mal} C2 on port {}, {}", r["port"], r["status"].as_str().unwrap_or("?")),
            link: Some(format!("https://feodotracker.abuse.ch/browse/host/{ip}/")),
            extra: json!({ "malware": mal, "port": r["port"], "status": r["status"], "last_online": r["last_online"], "as_name": r["as_name"], "country": r["country"] }),
        };
        if let Some(h) = r["hostname"].as_str().map(str::to_ascii_lowercase) {
            d.hosts.entry(h).or_insert((0, e.clone())).0 += 1;
        }
        let slot = d.ips.entry(ip).or_default();
        if slot.len() < 5 {
            slot.push(e.clone());
        }
        all.push(e);
        d.total += 1;
    }
    all.sort_by(|a, b| b.since.cmp(&a.since));
    Ok(finish(d, all))
}

pub fn parse_drop(text: &str) -> Result<FeedData, String> {
    let mut d = FeedData::default();
    let mut recent = vec![];
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(v) = serde_json::from_str::<Value>(line) else { continue };
        if v["type"] == "metadata" {
            d.source_updated = v["timestamp"].as_u64().map(ymd);
            continue;
        }
        let (Some(c), Some(net)) = (v["cidr"].as_str(), v["cidr"].as_str().and_then(Net::parse)) else { continue };
        let sbl = v["sblid"].as_str().unwrap_or("");
        let e = Entry { indicator: c.into(), since: None, detail: format!("{sbl} ({})", v["rir"].as_str().unwrap_or("?")), link: (!sbl.is_empty()).then(|| format!("https://www.spamhaus.org/sbl/query/{sbl}")), extra: json!({ "sbl": sbl, "rir": v["rir"] }) };
        recent.push(e.clone());
        d.nets.push((net, e));
        d.total += 1;
    }
    if d.total == 0 {
        return Err("no networks found in the Spamhaus DROP list".into());
    }
    Ok(finish(d, recent))
}

pub fn parse_ipsum(text: &str) -> Result<FeedData, String> {
    let mut d = FeedData::default();
    let mut all = vec![];
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# Last update:") {
            d.source_updated = Some(rest.trim().to_string());
        }
        if line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let (Some(ip), Some(n)) = (it.next().and_then(|s| s.parse::<IpAddr>().ok()), it.next().and_then(|s| s.parse::<u32>().ok())) else { continue };
        let e = Entry { indicator: ip.to_string(), since: None, detail: format!("on {n} blocklist{}", if n == 1 { "" } else { "s" }), link: None, extra: json!({ "lists": n }) };
        d.ips.insert(ip, vec![e.clone()]);
        all.push((n, e));
        d.total += 1;
    }
    if d.total == 0 {
        return Err("no addresses found in the IPsum list".into());
    }
    all.sort_by(|a, b| b.0.cmp(&a.0));
    Ok(finish(d, all.into_iter().map(|x| x.1).take(100).collect()))
}

pub fn parse_tor(text: &str) -> Result<FeedData, String> {
    let mut d = FeedData::default();
    let mut all = vec![];
    for line in text.lines() {
        let Ok(ip) = line.trim().parse::<IpAddr>() else { continue };
        let e = Entry { indicator: ip.to_string(), since: None, detail: "Tor exit relay".into(), link: Some(format!("https://metrics.torproject.org/rs.html#search/{ip}")), extra: Value::Null };
        d.ips.insert(ip, vec![e.clone()]);
        all.push(e);
        d.total += 1;
    }
    if d.total == 0 {
        return Err("no addresses found in the Tor exit list".into());
    }
    Ok(finish(d, all))
}

/// Lower-case scheme and host, drop the fragment and a trailing slash, so a pasted URL matches the feed's copy.
pub fn normalise_url(u: &str) -> Option<(String, String)> {
    let p = url::Url::parse(u.trim()).ok()?;
    if !matches!(p.scheme(), "http" | "https") {
        return None;
    }
    let host = p.host_str()?.to_ascii_lowercase();
    let mut s = format!("{}://{}", p.scheme(), host);
    if let Some(port) = p.port() {
        s.push_str(&format!(":{port}"));
    }
    s.push_str(p.path().trim_end_matches('/'));
    if let Some(q) = p.query() {
        s.push('?');
        s.push_str(q);
    }
    Some((s, host))
}

pub fn parse_openphish(text: &str) -> Result<FeedData, String> {
    let mut d = FeedData::default();
    let mut all = vec![];
    for line in text.lines() {
        let Some((key, host)) = normalise_url(line) else { continue };
        let e = Entry { indicator: cut(line.trim(), 300), since: None, detail: "reported phishing URL".into(), link: None, extra: Value::Null };
        d.hosts.entry(host).or_insert((0, e.clone())).0 += 1;
        d.urls.insert(key, e.clone());
        all.push(e);
        d.total += 1;
    }
    if d.total == 0 {
        return Err("no URLs found in the OpenPhish feed".into());
    }
    Ok(finish(d, all))
}

// ---- store -----------------------------------------------------------------------------------------------------

#[derive(Default)]
struct Slot {
    data: Option<Arc<FeedData>>,
    fetched_at: u64,
    last_attempt: u64,
    error: Option<String>,
}

pub struct Loaded {
    pub data: Arc<FeedData>,
    pub fetched_at: u64,
    pub stale: bool,
}

pub struct Store {
    pub dir: PathBuf,
    /// Tests only: serve every feed from `{base}/{id}-{n}` on a fake server.
    pub base: Option<String>,
    slots: Vec<Mutex<Slot>>,
}

impl Store {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir, base: None, slots: FEEDS.iter().map(|_| Mutex::new(Slot::default())).collect() }
    }

    fn idx(id: &str) -> Option<usize> {
        FEEDS.iter().position(|f| f.id == id)
    }

    fn path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.feed"))
    }

    fn download(&self, agent: &ureq::Agent, def: &FeedDef) -> Result<String, UpErr> {
        let mut out = String::new();
        for (i, u) in def.urls.iter().enumerate() {
            let url = match &self.base {
                Some(b) => format!("{b}/{}-{i}", def.id),
                None => u.to_string(),
            };
            match get_text(agent, &url, &[], MAX_FEED_BYTES) {
                Ok(t) => {
                    out.push_str(&t);
                    if !out.ends_with('\n') {
                        out.push('\n');
                    }
                }
                Err(e) if i == 0 => return Err(e),
                Err(_) => {} // an optional companion file (the IPv6 list) may be missing
            }
        }
        Ok(out)
    }

    /// The feed, refreshed when older than its TTL (or `force` and older than the minimum refresh interval).
    pub fn ensure(&self, agent: &ureq::Agent, id: &str, force: bool) -> Result<Loaded, String> {
        let i = Self::idx(id).ok_or("unknown feed")?;
        let def = &FEEDS[i];
        let mut slot = self.slots[i].lock().unwrap_or_else(|e| e.into_inner());
        let now = unix_now();
        let ttl = if force { MIN_REFRESH.min(def.ttl) } else { def.ttl };
        if let Some(d) = &slot.data {
            if now.saturating_sub(slot.fetched_at) < ttl {
                return Ok(Loaded { data: d.clone(), fetched_at: slot.fetched_at, stale: false });
            }
        } else if let Ok(meta) = fs::metadata(self.path(id)) {
            let mtime = meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
            if now.saturating_sub(mtime) < def.ttl {
                if let Ok(d) = fs::read_to_string(self.path(id)).map_err(|e| e.to_string()).and_then(|t| (def.parse)(&t)) {
                    slot.data = Some(Arc::new(d));
                    slot.fetched_at = mtime;
                    return Ok(Loaded { data: slot.data.clone().unwrap(), fetched_at: mtime, stale: false });
                }
            }
        }
        if slot.error.is_some() && now.saturating_sub(slot.last_attempt) < RETRY_COOLDOWN {
            let err = slot.error.clone().unwrap_or_default();
            return slot.data.clone().map(|d| Loaded { data: d, fetched_at: slot.fetched_at, stale: true }).ok_or(err);
        }
        slot.last_attempt = now;
        let res = self.download(agent, def).map_err(|e| e.to_string()).and_then(|t| (def.parse)(&t).map(|d| (t, d)));
        match res {
            Ok((text, d)) => {
                let _ = fs::create_dir_all(&self.dir);
                let tmp = self.dir.join(format!("{id}.tmp"));
                if fs::write(&tmp, text).is_ok() {
                    let _ = fs::rename(&tmp, self.path(id));
                }
                slot.data = Some(Arc::new(d));
                slot.fetched_at = now;
                slot.error = None;
                Ok(Loaded { data: slot.data.clone().unwrap(), fetched_at: now, stale: false })
            }
            Err(e) => {
                slot.error = Some(e.clone());
                match slot.data.clone() {
                    Some(d) => Ok(Loaded { data: d, fetched_at: slot.fetched_at, stale: true }),
                    None => Err(e),
                }
            }
        }
    }

    /// Current state of every feed without touching the network.
    pub fn status(&self) -> Vec<Value> {
        let now = unix_now();
        FEEDS
            .iter()
            .enumerate()
            .map(|(i, def)| {
                let s = self.slots[i].lock().unwrap_or_else(|e| e.into_inner());
                json!({ "id": def.id, "name": def.name, "kind": def.kind, "info": def.info, "licence": def.licence, "ttl_secs": def.ttl, "recent_label": def.recent_label,
                        "loaded": s.data.is_some(), "entries": s.data.as_ref().map(|d| d.total), "fetched_at": s.data.as_ref().map(|_| s.fetched_at),
                        "age_secs": s.data.as_ref().map(|_| now.saturating_sub(s.fetched_at)), "source_updated": s.data.as_ref().and_then(|d| d.source_updated.clone()),
                        "error": s.error })
            })
            .collect()
    }
}

/// Startup housekeeping: drop temp files and anything that is not one of our feed files, then enforce the size cap.
pub fn cleanup(dir: &Path) {
    let _ = fs::create_dir_all(dir);
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut files = vec![];
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let known = name.strip_suffix(".feed").is_some_and(|id| FEEDS.iter().any(|f| f.id == id));
        let Ok(m) = e.metadata() else { continue };
        if !known || !m.is_file() {
            let _ = fs::remove_file(e.path());
            continue;
        }
        files.push((m.modified().ok(), m.len(), e.path()));
    }
    files.sort_by_key(|f| f.0);
    let mut total: u64 = files.iter().map(|f| f.1).sum();
    for (_, len, p) in &files {
        if total <= DIR_CAP_BYTES {
            break;
        }
        let _ = fs::remove_file(p);
        total -= len;
    }
}

// ---- matching --------------------------------------------------------------------------------------------------

const SHOW: usize = 10;

pub struct Hits {
    pub count: usize,
    pub items: Vec<Entry>,
}

pub fn match_ip(d: &FeedData, ip: IpAddr) -> Hits {
    let mut items: Vec<Entry> = d.ips.get(&ip).cloned().unwrap_or_default();
    items.extend(d.nets.iter().filter(|(n, _)| n.contains_ip(ip)).map(|(_, e)| e.clone()));
    Hits { count: items.len(), items: items.into_iter().take(SHOW).collect() }
}

/// Entries inside the queried block (single addresses) or overlapping it (networks).
pub fn match_net(d: &FeedData, net: &Net) -> Hits {
    let mut items: Vec<Entry> = d.ips.iter().filter(|(ip, _)| net.contains_ip(**ip)).flat_map(|(_, v)| v.iter().cloned()).collect();
    items.sort_by(|a, b| a.indicator.cmp(&b.indicator));
    let mut nets: Vec<Entry> = d.nets.iter().filter(|(n, _)| n.overlaps(net)).map(|(_, e)| e.clone()).collect();
    items.append(&mut nets);
    Hits { count: items.len(), items: items.into_iter().take(SHOW).collect() }
}

pub fn match_host(d: &FeedData, host: &str) -> Hits {
    match d.hosts.get(host) {
        Some((n, e)) => Hits { count: *n, items: vec![e.clone()] },
        None => Hits { count: 0, items: vec![] },
    }
}

pub fn match_url(d: &FeedData, key: &str) -> Hits {
    match d.urls.get(key) {
        Some(e) => Hits { count: 1, items: vec![e.clone()] },
        None => Hits { count: 0, items: vec![] },
    }
}

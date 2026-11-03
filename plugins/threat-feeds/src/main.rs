//! Open blocklists and IOC membership: "is this IP, network, domain, URL or hash in any feed, and since when".
//! Keyless feeds are downloaded on demand and cached; abuse.ch feeds are queried live when a free Auth-Key is set.

mod common;
mod feeds;
mod keyed;
mod net;
#[cfg(test)]
mod testutil;

use std::{env, net::{IpAddr, SocketAddr}, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Query, State},
    middleware,
    response::Html,
    routing::{get, post},
};
use common::*;
use feeds::{Entry, FEEDS, Hits, Store};
use keyed::{Kind, KEYED};
use net::Net;
use serde::Deserialize;
use serde_json::{Value, json};

const PAGE: &str = include_str!("../assets/index.html");

pub struct AppState {
    pub agent: ureq::Agent,
    pub store: Store,
    pub hosts: keyed::Hosts,
    pub onionoo: String,
    pub keys: Box<dyn Fn(&str) -> Option<String> + Send + Sync>,
    pub authz: Authz,
    key_cache: TtlCache<Option<String>>,
    relay_cache: TtlCache<Value>,
    recent_cache: TtlCache<Value>,
}
pub type Shared = Arc<AppState>;

impl AppState {
    pub fn new(dir: PathBuf, agent: ureq::Agent, keys: Box<dyn Fn(&str) -> Option<String> + Send + Sync>, authz: Authz) -> Self {
        Self {
            agent,
            store: Store::new(dir),
            hosts: keyed::Hosts::real(),
            onionoo: "https://onionoo.torproject.org".into(),
            keys,
            authz,
            key_cache: TtlCache::new(Duration::from_secs(60), 4),
            relay_cache: TtlCache::new(Duration::from_secs(600), 128),
            recent_cache: TtlCache::new(Duration::from_secs(600), 8),
        }
    }
    fn auth_key(&self) -> Option<String> {
        if let Some(v) = self.key_cache.get("k") {
            return v;
        }
        let v = (self.keys)("ABUSECH_AUTH_KEY");
        self.key_cache.put("k", v.clone());
        v
    }
}

// ---- classifying the query -------------------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum Indicator {
    Ip(IpAddr),
    Cidr(Net),
    Domain(String),
    Url { key: String, host: String, raw: String },
    Hash(String),
}

/// Undo the usual "defanging" (hxxp, [.]) so pasted indicators work.
pub fn refang(s: &str) -> String {
    let mut t = s.trim().replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[://]", "://");
    for (a, b) in [("hxxps://", "https://"), ("hxxp://", "http://"), ("HXXPS://", "https://"), ("HXXP://", "http://")] {
        if let Some(rest) = t.strip_prefix(a) {
            t = format!("{b}{rest}");
        }
    }
    t
}

pub fn classify(q: &str) -> Result<Indicator, String> {
    let t = refang(q);
    if t.is_empty() || t.len() > 2048 {
        return Err("enter an IP address, network (CIDR), domain, URL or file hash".into());
    }
    let lower = t.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        let (key, host) = feeds::normalise_url(&t).ok_or("that is not a valid http(s) URL")?;
        return Ok(Indicator::Url { key, host, raw: t });
    }
    if t.contains('/') {
        let n = Net::parse(&t).ok_or("that is not a valid CIDR network")?;
        if (!n.v6 && n.prefix < 8) || (n.v6 && n.prefix < 32) {
            return Err("network too large: use /8 or smaller for IPv4, /32 or smaller for IPv6".into());
        }
        if !ip_is_public(n.first()) {
            return Err("that network is private or reserved, which has no public data".into());
        }
        return Ok(Indicator::Cidr(n));
    }
    if let Ok(ip) = t.trim_matches(['[', ']']).parse::<IpAddr>() {
        return parse_public_ip(&ip.to_string()).map(Indicator::Ip).map_err(|e| e.1);
    }
    if matches!(t.len(), 32 | 40 | 64) && t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(Indicator::Hash(lower));
    }
    valid_domain(&t).map(Indicator::Domain).ok_or_else(|| "not recognised as an IP, CIDR, domain, URL or MD5/SHA-1/SHA-256 hash".into())
}

fn hits_json(h: &Hits) -> Value {
    json!({ "count": h.count, "items": h.items.iter().map(Entry::json).collect::<Vec<_>>() })
}

fn row(id: &str, name: &str, kind: &str, status: &str, note: &str, extra: Value) -> Value {
    let mut v = json!({ "id": id, "name": name, "kind": kind, "status": status, "note": note });
    if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) {
        o.extend(e.clone());
    }
    v
}

fn indicator_kind(i: &Indicator) -> (&'static str, Option<Kind>) {
    match i {
        Indicator::Ip(_) => ("ip", Some(Kind::Ip)),
        Indicator::Cidr(_) => ("cidr", None),
        Indicator::Domain(_) => ("domain", Some(Kind::Domain)),
        Indicator::Url { .. } => ("url", Some(Kind::Url)),
        Indicator::Hash(h) => ("hash", Some(Kind::Hash(h.len()))),
    }
}

pub fn check(s: &AppState, q: &str) -> Result<Value, String> {
    let ind = classify(q)?;
    let (kind_name, keyed_kind) = indicator_kind(&ind);
    let query = match &ind {
        Indicator::Ip(i) => i.to_string(),
        Indicator::Cidr(n) => n.to_string(),
        Indicator::Domain(d) => d.clone(),
        Indicator::Url { raw, .. } => raw.clone(),
        Indicator::Hash(h) => h.clone(),
    };
    let key = s.auth_key();
    let mut rows: Vec<Value> = std::thread::scope(|sc| {
        let hs: Vec<_> = FEEDS
            .iter()
            .map(|def| {
                let ind = &ind;
                sc.spawn(move || {
                    let applies = match (def.kind, ind) {
                        (_, Indicator::Ip(_) | Indicator::Cidr(_)) => def.kind != "url",
                        (_, Indicator::Domain(_)) => def.id == "feodo" || def.kind == "url",
                        (_, Indicator::Url { .. }) => def.kind == "url",
                        (_, Indicator::Hash(_)) => false,
                    };
                    if !applies {
                        return row(def.id, def.name, def.kind, "n/a", &format!("This feed holds {} entries, so it cannot answer for a {kind_name}.", match def.kind { "cidr" => "network", "url" => "URL", _ => "IP address" }), json!({}));
                    }
                    match s.store.ensure(&s.agent, def.id, false) {
                        Err(e) => row(def.id, def.name, def.kind, "error", &e, json!({})),
                        Ok(l) => {
                            let d = &*l.data;
                            let mut host_only = false;
                            let hits = match ind {
                                Indicator::Ip(ip) => feeds::match_ip(d, *ip),
                                Indicator::Cidr(n) => feeds::match_net(d, n),
                                Indicator::Domain(h) => feeds::match_host(d, h),
                                Indicator::Url { key, host, .. } => {
                                    let h = feeds::match_url(d, key);
                                    if h.count > 0 { h } else { host_only = true; feeds::match_host(d, host) }
                                }
                                Indicator::Hash(_) => Hits { count: 0, items: vec![] },
                            };
                            let note = if hits.count == 0 { "Not listed.".to_string() } else if host_only { "The URL itself is not listed, but its host appears in this feed.".into() } else { String::new() };
                            let mut r = row(def.id, def.name, def.kind, if hits.count > 0 { "hit" } else { "clear" }, &note, json!({ "fetched_at": l.fetched_at, "stale": l.stale, "entries": d.total, "source_updated": d.source_updated }));
                            r["hits"] = hits_json(&hits);
                            r
                        }
                    }
                })
            })
            .collect();
        hs.into_iter().filter_map(|h| h.join().ok()).collect()
    });
    // abuse.ch feeds: live queries, only with a key.
    let keyed_rows: Vec<Value> = std::thread::scope(|sc| {
        let hs: Vec<_> = KEYED
            .iter()
            .map(|(id, name, _)| {
                let (key, ind_q, kk) = (key.clone(), query.clone(), keyed_kind);
                sc.spawn(move || {
                    let Some(kind) = kk.filter(|k| keyed::applies(id, *k)) else {
                        return row(id, name, "live", "n/a", "This feed does not answer for this kind of indicator.", json!({}));
                    };
                    let Some(k) = key else {
                        return row(id, name, "live", "needs_key", "Set ABUSECH_AUTH_KEY on the Credentials page (free from abuse.ch) to query this feed.", json!({}));
                    };
                    let q = ind_q;
                    match keyed::check(&s.agent, &s.hosts, id, &k, kind, &q) {
                        Ok((n, items)) => {
                            let mut r = row(id, name, "live", if n > 0 { "hit" } else { "clear" }, if n > 0 { "" } else { "Not listed." }, json!({}));
                            r["hits"] = hits_json(&Hits { count: n, items });
                            r
                        }
                        Err(e) => row(id, name, "live", "error", &e.to_string(), json!({})),
                    }
                })
            })
            .collect();
        hs.into_iter().filter_map(|h| h.join().ok()).collect()
    });
    rows.extend(keyed_rows);
    let hits = rows.iter().filter(|r| r["status"] == "hit").count();
    let answered = rows.iter().filter(|r| r["status"] == "hit" || r["status"] == "clear").count();
    let note = if let Indicator::Hash(_) = ind { Some("No keyless feed lists file hashes. Add an abuse.ch Auth-Key to check URLhaus, ThreatFox and MalwareBazaar.") } else { None };
    Ok(json!({ "query": query, "kind": kind_name, "feeds_with_hits": hits, "feeds_answered": answered, "feeds": rows, "note": note }))
}

// ---- Tor relays ------------------------------------------------------------------------------------------------

pub fn valid_relay_query(q: &str) -> Option<String> {
    let t = q.trim();
    let ok = t.parse::<IpAddr>().is_ok() || (t.len() == 40 && t.bytes().all(|b| b.is_ascii_hexdigit())) || ((1..=19).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_alphanumeric()));
    ok.then(|| t.to_string())
}

pub fn tor_relay(s: &AppState, q: &str) -> Result<Value, UpErr> {
    if let Some(v) = s.relay_cache.get(q) {
        return Ok(v);
    }
    let url = format!("{}/details?search={}&limit=5&fields=nickname,fingerprint,or_addresses,exit_addresses,flags,country,as,first_seen,last_seen,running,exit_policy_summary,version", s.onionoo, enc(q));
    let v = get_json(&s.agent, &url, &[("Accept", "application/json")])?;
    // The operator contact line is deliberately dropped: it can hold a person's name or email.
    let relays: Vec<Value> = v["relays"].as_array().map(|a| a.iter().map(|r| {
        let fp = r["fingerprint"].as_str().unwrap_or("");
        json!({ "nickname": r["nickname"], "fingerprint": fp, "addresses": r["or_addresses"], "exit_addresses": r["exit_addresses"], "flags": r["flags"], "country": r["country"], "as": r["as"],
                "first_seen": r["first_seen"], "last_seen": r["last_seen"], "running": r["running"], "version": r["version"],
                "exit_ports_accepted": r["exit_policy_summary"]["accept"].as_array().map(|x| x.len()), "link": format!("https://metrics.torproject.org/rs.html#details/{fp}") })
    }).collect()).unwrap_or_default();
    let out = json!({ "query": q, "published": v["relays_published"], "total_matches": relays.len(), "truncated": v["relays_truncated"], "relays": relays });
    s.relay_cache.put(q, out.clone());
    Ok(out)
}

// ---- routes ----------------------------------------------------------------------------------------------------

#[derive(Deserialize)]
struct Q {
    q: String,
}
async fn check_h(State(s): State<Shared>, Query(q): Query<Q>) -> Result<Json<Value>, ApiError> {
    blocking(move || check(&s, &q.q)).await?.map(Json).map_err(|e| bad(&e))
}

async fn relay_h(State(s): State<Shared>, Query(q): Query<Q>) -> Result<Json<Value>, ApiError> {
    let q = valid_relay_query(&q.q).ok_or_else(|| bad("enter a relay IP address, a 40-character fingerprint or a nickname"))?;
    blocking(move || tor_relay(&s, &q)).await?.map(Json).map_err(|e| upstream(e.to_string()))
}

async fn feeds_h(State(s): State<Shared>) -> Json<Value> {
    let keyed: Vec<Value> = {
        let have = s.auth_key().is_some();
        KEYED.iter().map(|(id, name, info)| json!({ "id": id, "name": name, "info": info, "enabled": have })).collect()
    };
    Json(json!({ "feeds": s.store.status(), "keyed": keyed, "min_refresh_secs": feeds::MIN_REFRESH }))
}

#[derive(Deserialize)]
struct RefreshQ {
    feed: Option<String>,
    #[serde(default)]
    force: bool,
}
/// Download the named feed (or all feeds) if stale. `force` still honours the minimum refresh interval.
async fn refresh_h(State(s): State<Shared>, Query(q): Query<RefreshQ>) -> Result<Json<Value>, ApiError> {
    let which = q.feed.unwrap_or_else(|| "all".into());
    if which != "all" && !FEEDS.iter().any(|f| f.id == which) {
        return Err(bad("unknown feed"));
    }
    let force = q.force;
    let s2 = s.clone();
    let errors: Vec<(String, String)> = blocking(move || {
        std::thread::scope(|sc| {
            let hs: Vec<_> = FEEDS.iter().filter(|f| which == "all" || f.id == which).map(|f| sc.spawn(|| s2.store.ensure(&s2.agent, f.id, force).err().map(|e| (f.id.to_string(), e)))).collect();
            hs.into_iter().filter_map(|h| h.join().ok().flatten()).collect()
        })
    })
    .await?;
    Ok(Json(json!({ "feeds": s.store.status(), "errors": errors.iter().map(|(i, e)| json!({ "feed": i, "error": e })).collect::<Vec<_>>() })))
}

#[derive(Deserialize)]
struct RecentQ {
    feed: String,
    limit: Option<usize>,
}
async fn recent_h(State(s): State<Shared>, Query(q): Query<RecentQ>) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(25);
    if !(1..=100).contains(&limit) {
        return Err(bad("limit must be 1-100"));
    }
    let id = q.feed;
    if FEEDS.iter().any(|f| f.id == id) {
        return blocking(move || {
            let l = s.store.ensure(&s.agent, &id, false)?;
            let def = FEEDS.iter().find(|f| f.id == id).unwrap();
            Ok::<_, String>(json!({ "feed": id, "name": def.name, "label": def.recent_label, "entries": l.data.total, "fetched_at": l.fetched_at, "stale": l.stale, "items": l.data.recent.iter().take(limit).map(Entry::json).collect::<Vec<_>>() }))
        })
        .await?
        .map(Json)
        .map_err(|e| upstream(e));
    }
    let Some((kid, name, _)) = KEYED.iter().find(|k| k.0 == id) else { return Err(bad("unknown feed")) };
    let Some(key) = s.auth_key() else { return Err(bad("this feed needs ABUSECH_AUTH_KEY (free from abuse.ch); set it on the Credentials page")) };
    let ck = format!("{kid}|{limit}");
    if let Some(v) = s.recent_cache.get(&ck) {
        return Ok(Json(v));
    }
    let (kid, name) = (kid.to_string(), name.to_string());
    let v = blocking(move || {
        keyed::recent(&s.agent, &s.hosts, &kid, &key, limit).map(|items| {
            let v = json!({ "feed": kid, "name": name, "label": "most recent submissions", "items": items.iter().map(Entry::json).collect::<Vec<_>>() });
            s.recent_cache.put(&format!("{kid}|{limit}"), v.clone());
            v
        })
    })
    .await?
    .map_err(|e| upstream(e.to_string()))?;
    Ok(Json(v))
}

async fn tools() -> Json<Value> {
    Json(json!([
        { "name": "feeds_check", "description": "Is this IP, CIDR network, domain, URL or file hash on any open blocklist (Feodo Tracker, Spamhaus DROP, IPsum, Tor exit list, OpenPhish; abuse.ch URLhaus/ThreatFox/MalwareBazaar when a key is set)? Returns per-feed hits with first-seen dates and feed freshness.",
          "method": "GET", "path": "api/check", "parameters": { "type": "object", "properties": { "q": { "type": "string", "description": "IP, CIDR, domain, URL or hash (defanged input such as hxxp and [.] is accepted)" } }, "required": ["q"] } },
        { "name": "feeds_recent", "description": "Recent or highest-confidence entries of one feed: feodo, spamhaus-drop, ipsum, tor-exit, openphish (and urlhaus, threatfox, malwarebazaar with a key).",
          "method": "GET", "path": "api/recent", "parameters": { "type": "object", "properties": { "feed": { "type": "string" }, "limit": { "type": "integer", "description": "1-100" } }, "required": ["feed"] } },
        { "name": "tor_relay", "description": "Tor relay details from Onionoo for an IP, fingerprint or nickname: flags, country, AS, first and last seen. Operator contact lines are not returned.",
          "method": "GET", "path": "api/tor", "parameters": { "type": "object", "properties": { "q": { "type": "string" } }, "required": ["q"] } }
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

pub fn app(state: Shared) -> Router {
    let api = Router::new()
        .route("/api/check", get(check_h))
        .route("/api/recent", get(recent_h))
        .route("/api/tor", get(relay_h))
        .route("/api/feeds", get(feeds_h))
        .route("/api/refresh", post(refresh_h))
        .route_layer(middleware::from_fn_with_state(state.authz, require_gateway));
    Router::new().route("/", get(page)).route("/tools", get(tools)).merge(api).with_state(state)
}

#[tokio::main]
async fn main() -> Result<()> {
    let dir = PathBuf::from(env::var("OSNT_THREAT_FEEDS_STATE").unwrap_or_else(|_| env::temp_dir().join("osnt-threat-feeds").to_string_lossy().into()));
    feeds::cleanup(&dir);
    let agent = osnt_common::http_agent("osnt-threat-feeds/0.1 (+https://github.com/ogden-marrow/osnt-hub)");
    let keys: Box<dyn Fn(&str) -> Option<String> + Send + Sync> = Box::new(|n| osnt_common::secret(n));
    let state: Shared = Arc::new(AppState::new(dir, agent, keys, real_authz));
    let addr: SocketAddr = env::var("OSNT_THREAT_FEEDS_BIND").unwrap_or_else(|_| "127.0.0.1:8135".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("threat-feeds plugin on http://{addr}");
    axum::serve(listener, app(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests;

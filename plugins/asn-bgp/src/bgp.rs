//! RIPEstat, PeeringDB and RIPE Atlas calls for the ASN and BGP explorer, plus the parsers that shrink their answers.
//! Upstream hosts are fixed in [`Up`]; callers only supply an ASN, a prefix or a country code.

use std::{collections::BTreeMap, net::IpAddr, time::Duration};

use anyhow::{Result, anyhow};
use serde_json::{Value, json};

use crate::{
    cache::Cache,
    ipx::{ip_public, network_of, parse_cidr},
    net::{Http, Req, status_of},
};

#[derive(Clone)]
pub struct Up {
    pub ripe: String,
    pub peeringdb: String,
    pub atlas: String,
}
impl Default for Up {
    fn default() -> Self {
        Up { ripe: "https://stat.ripe.net".into(), peeringdb: "https://www.peeringdb.com".into(), atlas: "https://atlas.ripe.net".into() }
    }
}

pub struct App {
    pub http: Http,
    pub cache: Cache,
    pub up: Up,
}

const H: u64 = 3600;
const NEG: Duration = Duration::from_secs(90);
const MAX_PREFIXES: usize = 4000;
const MAX_PER_SIDE: usize = 60;

// ---- input validation ------------------------------------------------------------------------------------------

/// `AS15169`, `as15169` or `15169`.
pub fn parse_asn(s: &str) -> Option<u32> {
    let t = s.trim();
    let digits = t.strip_prefix("AS").or_else(|| t.strip_prefix("as")).or_else(|| t.strip_prefix("As")).unwrap_or(t);
    let n: u64 = digits.parse().ok()?;
    (1..=4_294_967_294).contains(&n).then_some(n as u32)
}

/// A public IP address or CIDR prefix, normalised (host bits cleared). IPv4 prefixes /8-/32, IPv6 /16-/128.
pub fn parse_prefix(s: &str) -> Option<String> {
    let t = s.trim();
    if let Ok(ip) = t.parse::<IpAddr>() {
        return ip_public(ip).then(|| ip.to_string());
    }
    let (ip, len) = parse_cidr(t)?;
    let (min, _) = if ip.is_ipv4() { (8, 32) } else { (16, 128) };
    if len < min || !ip_public(ip) {
        return None;
    }
    Some(network_of(ip, len))
}

pub fn parse_country(s: &str) -> Option<String> {
    let t = s.trim().to_ascii_uppercase();
    (t.len() == 2 && t.bytes().all(|b| b.is_ascii_uppercase())).then_some(t)
}

// ---- time helpers (no date crate) ------------------------------------------------------------------------------

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn ymd(unix: i64) -> String {
    let (y, m, d) = civil_from_days(unix.div_euclid(86400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// `2026-11-02T16:00:00` (or a bare date) to unix seconds.
pub fn parse_ts(s: &str) -> Option<i64> {
    let date = s.get(..10)?;
    let mut p = date.split('-');
    let (y, m, d): (i64, i64, i64) = (p.next()?.parse().ok()?, p.next()?.parse().ok()?, p.next()?.parse().ok()?);
    let secs = s.get(11..19).map(|t| {
        let mut q = t.split(':');
        let n = |x: Option<&str>| x.and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
        n(q.next()) * 3600 + n(q.next()) * 60 + n(q.next())
    });
    Some(days_from_civil(y, m, d) * 86400 + secs.unwrap_or(0))
}

// ---- RIPEstat --------------------------------------------------------------------------------------------------

fn ripe(app: &App, call: &str, query: &str, ttl: u64) -> Result<Value> {
    let key = format!("ripe:{call}:{query}");
    app.cache.cached_json_neg(&key, Duration::from_secs(ttl), NEG, || {
        let url = format!("{}/data/{call}/data.json?{query}", app.up.ripe);
        let v = app.http.json(Req::new(&url).gap(200).timeout(40))?;
        if v["status"].as_str() != Some("ok") {
            return Err(anyhow!("stat.ripe.net {call}: {}", v["messages"][0][1].as_str().unwrap_or("not ok")));
        }
        Ok(v["data"].clone())
    })
}

/// Find the ASN for an ASN, IP or prefix input.
pub fn resolve(app: &App, q: &str) -> Result<Value> {
    if let Some(asn) = parse_asn(q) {
        return Ok(json!({ "kind": "asn", "asn": asn }));
    }
    let Some(prefix) = parse_prefix(q) else { return Err(anyhow!("enter an AS number (AS15169), an IP address or a prefix (193.0.0.0/21)")) };
    let d = ripe(app, "prefix-overview", &format!("resource={prefix}"), H)?;
    let first = d["asns"].as_array().and_then(|a| a.first()).ok_or_else(|| anyhow!("{prefix} is not announced in BGP right now, so it has no origin AS"))?;
    Ok(json!({
        "kind": if prefix.contains('/') { "prefix" } else { "ip" }, "input": prefix, "asn": first["asn"], "holder": first["holder"], "prefix": d["resource"],
        "all_asns": d["asns"].as_array().map(|a| a.iter().map(|x| x["asn"].clone()).collect::<Vec<_>>()),
    }))
}

pub fn overview(app: &App, asn: u32) -> Result<Value> {
    let d = ripe(app, "as-overview", &format!("resource=AS{asn}"), 6 * H)?;
    Ok(json!({
        "asn": asn, "holder": d["holder"], "announced": d["announced"],
        "block": { "name": d["block"]["name"], "desc": d["block"]["desc"] },
    }))
}

/// Shrink `announced-prefixes`: prefix with first and last time it was seen announced, v4 first.
pub fn compact_prefixes(d: &Value) -> Value {
    let mut rows: Vec<(bool, String, Value)> = Vec::new();
    for p in d["prefixes"].as_array().into_iter().flatten() {
        let Some(prefix) = p["prefix"].as_str() else { continue };
        let tl = p["timelines"].as_array().cloned().unwrap_or_default();
        let first = tl.iter().filter_map(|t| t["starttime"].as_str()).min().map(str::to_owned);
        let last = tl.iter().filter_map(|t| t["endtime"].as_str()).max().map(str::to_owned);
        let v6 = prefix.contains(':');
        let (a, len) = parse_cidr(prefix).unwrap_or(("0.0.0.0".parse().unwrap(), 0));
        let sort_key = format!("{:039}/{len:03}", match a { IpAddr::V4(v) => u32::from(v) as u128, IpAddr::V6(v) => u128::from(v) });
        rows.push((v6, sort_key, json!({ "prefix": prefix, "first": first, "last": last })));
    }
    rows.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
    let total = rows.len();
    let v4 = rows.iter().filter(|r| !r.0).count();
    let truncated = total > MAX_PREFIXES;
    let list: Vec<Value> = rows.into_iter().take(MAX_PREFIXES).map(|r| r.2).collect();
    json!({ "total": total, "v4": v4, "v6": total - v4, "truncated": truncated, "prefixes": list, "queried": d["query_starttime"], "latest": d["latest_time"] })
}

pub fn prefixes(app: &App, asn: u32) -> Result<Value> {
    let key = format!("prefixes:{asn}");
    app.cache.cached_json_neg(&key, Duration::from_secs(H), NEG, || {
        let url = format!("{}/data/announced-prefixes/data.json?resource=AS{asn}", app.up.ripe);
        let v = app.http.json(Req::new(&url).gap(200).timeout(40).max_bytes(32 * 1024 * 1024))?;
        if v["status"].as_str() != Some("ok") {
            return Err(anyhow!("stat.ripe.net announced-prefixes: {}", v["messages"][0][1].as_str().unwrap_or("not ok")));
        }
        Ok(compact_prefixes(&v["data"]))
    })
}

/// Group neighbours by side (left = upstream, right = downstream, uncertain), strongest first.
pub fn group_neighbours(d: &Value) -> Value {
    let mut sides: BTreeMap<&str, Vec<Value>> = BTreeMap::new();
    for n in d["neighbours"].as_array().into_iter().flatten() {
        let side = match n["type"].as_str() {
            Some("left") => "upstream",
            Some("right") => "downstream",
            _ => "uncertain",
        };
        sides.entry(side).or_default().push(json!({ "asn": n["asn"], "power": n["power"], "v4_peers": n["v4_peers"], "v6_peers": n["v6_peers"] }));
    }
    let mut out = serde_json::Map::new();
    let mut counts = serde_json::Map::new();
    for side in ["upstream", "uncertain", "downstream"] {
        let mut v = sides.remove(side).unwrap_or_default();
        v.sort_by(|a, b| b["power"].as_u64().unwrap_or(0).cmp(&a["power"].as_u64().unwrap_or(0)));
        counts.insert(side.into(), json!(v.len()));
        v.truncate(MAX_PER_SIDE);
        out.insert(side.into(), Value::Array(v));
    }
    json!({ "neighbours": out, "counts": counts, "as_of": d["latest_time"], "limit_per_side": MAX_PER_SIDE })
}

pub fn neighbours(app: &App, asn: u32) -> Result<Value> {
    let d = ripe(app, "asn-neighbours", &format!("resource=AS{asn}"), 6 * H)?;
    Ok(group_neighbours(&d))
}

/// Holder names for a handful of ASNs (the neighbour lists only carry numbers).
pub fn names(app: &App, asns: &[u32]) -> Value {
    let mut out = serde_json::Map::new();
    for a in asns.iter().take(25) {
        if let Ok(d) = ripe(app, "as-overview", &format!("resource=AS{a}"), 24 * H) {
            out.insert(a.to_string(), d["holder"].clone());
        }
    }
    Value::Object(out)
}

// ---- route history ---------------------------------------------------------------------------------------------

/// Turn `routing-history` into one row of merged time segments per origin AS, plus appeared/disappeared events.
pub fn summarize_history(d: &Value, resource: &str) -> Value {
    struct Seg(i64, i64, String, String, f64);
    let mut by_origin: BTreeMap<String, Vec<Seg>> = BTreeMap::new();
    let mut latest_end = 0i64;
    let all: Vec<&Value> = d["by_origin"].as_array().into_iter().flatten().collect();
    let has_exact = all.iter().any(|o| o["prefixes"].as_array().into_iter().flatten().any(|p| p["prefix"].as_str() == Some(resource)));
    for o in &all {
        let origin = o["origin"].as_str().map(str::to_owned).or_else(|| o["origin"].as_u64().map(|n| n.to_string())).unwrap_or_default();
        for p in o["prefixes"].as_array().into_iter().flatten() {
            if has_exact && p["prefix"].as_str() != Some(resource) {
                continue;
            }
            for t in p["timelines"].as_array().into_iter().flatten() {
                let (Some(s), Some(e)) = (t["starttime"].as_str(), t["endtime"].as_str()) else { continue };
                let (Some(si), Some(ei)) = (parse_ts(s), parse_ts(e)) else { continue };
                latest_end = latest_end.max(ei);
                by_origin.entry(origin.clone()).or_default().push(Seg(si, ei, s.to_string(), e.to_string(), t["full_peers_seeing"].as_f64().unwrap_or(0.0)));
            }
        }
    }
    let mut origins = Vec::new();
    let mut events = Vec::new();
    for (origin, mut segs) in by_origin {
        segs.sort_by_key(|s| s.0);
        let mut merged: Vec<Seg> = Vec::new();
        for s in segs {
            match merged.last_mut() {
                Some(m) if s.0 <= m.1 + 2 * 86400 => {
                    if s.1 > m.1 {
                        m.1 = s.1;
                        m.3 = s.3.clone();
                    }
                    m.4 = m.4.max(s.4);
                }
                _ => merged.push(s),
            }
        }
        let first = merged.first().map(|s| s.2.clone()).unwrap_or_default();
        let last = merged.last().map(|s| s.3.clone()).unwrap_or_default();
        let last_i = merged.last().map(|s| s.1).unwrap_or(0);
        let current = latest_end - last_i <= 3 * 86400;
        events.push((merged.first().map(|s| s.0).unwrap_or(0), json!({ "date": first.get(..10), "kind": "appeared", "origin": origin })));
        if !current {
            events.push((last_i, json!({ "date": last.get(..10), "kind": "disappeared", "origin": origin })));
        }
        origins.push((merged.first().map(|s| s.0).unwrap_or(0), json!({
            "origin": origin, "first": first, "last": last, "current": current,
            "segments": merged.iter().map(|s| json!({ "start": s.2, "end": s.3, "peers": s.4 })).collect::<Vec<_>>(),
        })));
    }
    origins.sort_by_key(|o| o.0);
    events.sort_by_key(|e| e.0);
    let current: Vec<&Value> = origins.iter().map(|o| &o.1).filter(|o| o["current"] == true).collect();
    json!({
        "resource": resource, "origins": origins.iter().map(|o| o.1.clone()).collect::<Vec<_>>(), "events": events.into_iter().map(|e| e.1).collect::<Vec<_>>(),
        "current_origins": current.iter().map(|o| o["origin"].clone()).collect::<Vec<_>>(),
        "multiple_origins_now": current.len() > 1,
        "window_start": d["time"].as_str().map(|_| Value::Null).unwrap_or(Value::Null),
    })
}

pub fn history(app: &App, prefix: &str, years: u32) -> Result<Value> {
    let start = ymd(crate::cache::now_secs() as i64 - years as i64 * 365 * 86400);
    let d = ripe(app, "routing-history", &format!("resource={prefix}&starttime={start}"), 3 * H)?;
    let mut v = summarize_history(&d, prefix);
    v["from"] = json!(start);
    v["years"] = json!(years);
    Ok(v)
}

// ---- current BGP state -----------------------------------------------------------------------------------------

fn collapse_path(path: &[u64]) -> Vec<u64> {
    let mut out: Vec<u64> = Vec::with_capacity(path.len());
    for p in path {
        if out.last() != Some(p) {
            out.push(*p);
        }
    }
    out
}

pub fn summarize_state(d: &Value, resource: &str) -> Value {
    let all: Vec<&Value> = d["bgp_state"].as_array().into_iter().flatten().collect();
    let exact: Vec<&&Value> = all.iter().filter(|r| r["target_prefix"].as_str() == Some(resource)).collect();
    let rows: Vec<&Value> = if exact.is_empty() { all.clone() } else { exact.into_iter().copied().collect() };
    let mut origins: BTreeMap<u64, usize> = BTreeMap::new();
    let mut last_hop: BTreeMap<u64, usize> = BTreeMap::new();
    let mut sample = Vec::new();
    let mut prefixes = std::collections::BTreeSet::new();
    for r in &rows {
        let path: Vec<u64> = r["path"].as_array().into_iter().flatten().filter_map(Value::as_u64).collect();
        let path = collapse_path(&path);
        let Some(origin) = path.last().copied() else { continue };
        *origins.entry(origin).or_default() += 1;
        if path.len() >= 2 {
            *last_hop.entry(path[path.len() - 2]).or_default() += 1;
        }
        if let Some(p) = r["target_prefix"].as_str() {
            prefixes.insert(p.to_string());
        }
        if sample.len() < 40 {
            // Collector name only: the peer router address in `source_id` is not needed to read the path.
            let collector = r["source_id"].as_str().and_then(|s| s.split('-').next()).map(|c| format!("rrc{c}"));
            sample.push(json!({ "collector": collector, "path": path }));
        }
    }
    let rank = |m: BTreeMap<u64, usize>| {
        let mut v: Vec<(u64, usize)> = m.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.into_iter().take(20).map(|(a, n)| json!({ "asn": a, "peers": n })).collect::<Vec<_>>()
    };
    json!({
        "resource": resource, "as_of": d["timestamp"], "peers_seeing": rows.len(), "prefixes_seen": prefixes,
        "origins": rank(origins), "last_hops": rank(last_hop), "sample_paths": sample,
    })
}

pub fn bgp_state(app: &App, prefix: &str) -> Result<Value> {
    let d = ripe(app, "bgp-state", &format!("resource={prefix}"), 600)?;
    Ok(summarize_state(&d, prefix))
}

// ---- PeeringDB -------------------------------------------------------------------------------------------------

fn pdb(app: &App, path: &str, key: &Option<String>) -> Result<Value> {
    let url = format!("{}/api/{path}", app.up.peeringdb);
    let mut r = Req::new(&url).gap(1100).timeout(25);
    if let Some(k) = key {
        r = r.header("Authorization", format!("Api-Key {k}"));
    }
    app.http.json(r)
}

/// PeeringDB `net`, `netixlan` and `netfac` rows reduced to organisational facts. Point-of-contact data and free-text
/// notes (which often carry names and e-mail addresses) are never read.
pub fn summarize_peeringdb(net: &Value, ixlan: &Value, fac: &Value) -> Value {
    let n = &net["data"][0];
    if n.is_null() {
        return json!({ "found": false });
    }
    let mut ixs: BTreeMap<u64, (String, u64, u64, bool)> = BTreeMap::new();
    for r in ixlan["data"].as_array().into_iter().flatten() {
        let id = r["ix_id"].as_u64().unwrap_or(0);
        let e = ixs.entry(id).or_insert((r["name"].as_str().unwrap_or("").to_string(), 0, 0, false));
        e.1 += 1;
        e.2 += r["speed"].as_u64().unwrap_or(0);
        e.3 |= r["is_rs_peer"].as_bool().unwrap_or(false);
    }
    let mut ix_list: Vec<Value> = ixs.into_iter().map(|(id, (name, ports, speed, rs))| json!({ "ix_id": id, "name": name, "ports": ports, "speed_mbps": speed, "route_server": rs, "url": format!("https://www.peeringdb.com/ix/{id}") })).collect();
    ix_list.sort_by(|a, b| b["speed_mbps"].as_u64().cmp(&a["speed_mbps"].as_u64()).then(a["name"].as_str().cmp(&b["name"].as_str())));
    ix_list.truncate(150);
    let mut facs: Vec<Value> = fac["data"].as_array().into_iter().flatten().map(|f| json!({ "name": f["name"], "city": f["city"], "country": f["country"], "fac_id": f["fac_id"] })).collect();
    facs.sort_by(|a, b| (a["country"].as_str(), a["city"].as_str(), a["name"].as_str()).cmp(&(b["country"].as_str(), b["city"].as_str(), b["name"].as_str())));
    facs.dedup_by(|a, b| a["fac_id"] == b["fac_id"]);
    facs.truncate(150);
    json!({
        "found": true,
        "net": {
            "id": n["id"], "name": n["name"], "aka": n["aka"], "website": n["website"], "type": n["info_type"], "scope": n["info_scope"], "traffic_ratio": n["info_ratio"],
            "prefixes4": n["info_prefixes4"], "prefixes6": n["info_prefixes6"], "irr_as_set": n["irr_as_set"], "policy": n["policy_general"], "policy_url": n["policy_url"],
            "ix_count": n["ix_count"], "fac_count": n["fac_count"], "status_dashboard": n["status_dashboard"], "looking_glass": n["looking_glass"],
            "link": format!("https://www.peeringdb.com/net/{}", n["id"]),
        },
        "ixs": ix_list, "facilities": facs,
    })
}

pub fn peeringdb(app: &App, asn: u32, key: Option<String>) -> Result<Value> {
    app.cache.cached_json_neg(&format!("pdb:{asn}"), Duration::from_secs(6 * H), NEG, || {
        let net = pdb(app, &format!("net?asn={asn}"), &key)?;
        if net["data"].as_array().map(|a| a.is_empty()).unwrap_or(true) {
            return Ok(json!({ "found": false }));
        }
        let ixlan = pdb(app, &format!("netixlan?asn={asn}&limit=500"), &key)?;
        let net_id = net["data"][0]["id"].as_u64().unwrap_or(0);
        let fac = pdb(app, &format!("netfac?net_id={net_id}&limit=500"), &key)?;
        Ok(summarize_peeringdb(&net, &ixlan, &fac))
    })
}

// ---- RIPE Atlas ------------------------------------------------------------------------------------------------

fn atlas_count(app: &App, filter: &str) -> Result<u64> {
    let url = format!("{}/api/v2/probes/?{filter}&page_size=1&fields=id", app.up.atlas);
    let v = app.http.json(Req::new(&url).gap(400))?;
    v["count"].as_u64().ok_or_else(|| anyhow!("atlas.ripe.net: unexpected answer"))
}

/// Probe counts only: individual probes (often in homes) are deliberately not listed or located.
pub fn atlas(app: &App, asn: Option<u32>, country: Option<&str>) -> Result<Value> {
    let (label, filters): (String, Vec<(&str, String)>) = match (asn, country) {
        (Some(a), _) => (format!("AS{a}"), vec![("connected_v4", format!("asn_v4={a}&status=1")), ("connected_v6", format!("asn_v6={a}&status=1")), ("anchors", format!("asn_v4={a}&is_anchor=true&status=1"))]),
        (None, Some(c)) => (c.to_string(), vec![("connected", format!("country_code={c}&status=1")), ("anchors", format!("country_code={c}&is_anchor=true&status=1"))]),
        _ => return Err(anyhow!("give an ASN or a two-letter country code")),
    };
    app.cache.cached_json_neg(&format!("atlas:{label}"), Duration::from_secs(H), NEG, || {
        let mut out = serde_json::Map::new();
        for (k, f) in &filters {
            out.insert((*k).into(), json!(atlas_count(app, f)?));
        }
        Ok(json!({ "scope": label, "counts": out, "note": "Connected public probes and anchors. Individual probes are not listed." }))
    })
}

pub fn is_not_found(e: &anyhow::Error) -> bool {
    status_of(e) == Some(404)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::fake;
    use std::sync::Arc;

    #[test]
    fn asn_parsing() {
        assert_eq!(parse_asn("AS15169"), Some(15169));
        assert_eq!(parse_asn(" as3333 "), Some(3333));
        assert_eq!(parse_asn("4200000000"), Some(4_200_000_000));
        for bad in ["", "AS", "AS0", "0", "-5", "AS12x", "4294967295", "99999999999", "8.8.8.8", "193.0.0.0/21"] {
            assert_eq!(parse_asn(bad), None, "{bad}");
        }
    }

    #[test]
    fn prefix_parsing_normalises_and_rejects() {
        assert_eq!(parse_prefix("193.0.7.9/21").as_deref(), Some("193.0.0.0/21"));
        assert_eq!(parse_prefix("8.8.8.8").as_deref(), Some("8.8.8.8"));
        assert_eq!(parse_prefix("2a00:1450:4001::1/32").as_deref(), Some("2a00:1450::/32"));
        for bad in ["10.0.0.0/8", "192.168.0.0/16", "1.0.0.0/7", "1.2.3.4/33", "2001:db8::/32", "fe80::/10", "127.0.0.1", "banana", "", "2a00::/8"] {
            assert_eq!(parse_prefix(bad), None, "{bad}");
        }
        assert_eq!(parse_country("nl").as_deref(), Some("NL"));
        assert_eq!(parse_country("NLD"), None);
        assert_eq!(parse_country("1a"), None);
    }

    #[test]
    fn date_helpers_roundtrip() {
        assert_eq!(ymd(0), "1970-01-01");
        assert_eq!(ymd(1_793_681_032), "2026-11-03");
        assert_eq!(parse_ts("2026-11-03T04:34:39"), Some(1_793_680_479));
        assert_eq!(parse_ts("2000-10-26"), Some(972_518_400));
        assert!(parse_ts("garbage").is_none());
        assert_eq!(ymd(parse_ts("2024-02-29T12:00:00").unwrap()), "2024-02-29");
    }

    #[test]
    fn prefixes_are_sorted_v4_first_and_capped() {
        let mut ps: Vec<Value> = vec![
            json!({"prefix":"2a00::/32","timelines":[{"starttime":"2026-01-01T00:00:00","endtime":"2026-02-01T00:00:00"}]}),
            json!({"prefix":"193.0.20.0/23","timelines":[{"starttime":"2026-10-19T16:00:00","endtime":"2026-11-02T16:00:00"},{"starttime":"2026-01-01T00:00:00","endtime":"2026-03-01T00:00:00"}]}),
            json!({"prefix":"9.0.0.0/8","timelines":[]}),
        ];
        let v = compact_prefixes(&json!({ "prefixes": ps.clone() }));
        let order: Vec<&str> = v["prefixes"].as_array().unwrap().iter().map(|p| p["prefix"].as_str().unwrap()).collect();
        assert_eq!(order, ["9.0.0.0/8", "193.0.20.0/23", "2a00::/32"]);
        assert_eq!((v["v4"].as_u64(), v["v6"].as_u64()), (Some(2), Some(1)));
        assert_eq!(v["prefixes"][1]["first"], "2026-01-01T00:00:00");
        assert_eq!(v["prefixes"][1]["last"], "2026-11-02T16:00:00");
        ps = (0..MAX_PREFIXES + 5).map(|i| json!({"prefix": format!("{}.{}.0.0/16", 20 + i / 256, i % 256), "timelines": []})).collect();
        let big = compact_prefixes(&json!({ "prefixes": ps }));
        assert_eq!(big["prefixes"].as_array().unwrap().len(), MAX_PREFIXES);
        assert_eq!(big["truncated"], true);
        assert_eq!(big["total"], MAX_PREFIXES + 5);
    }

    #[test]
    fn neighbours_group_and_rank() {
        let d = json!({"latest_time":"t","neighbours":[
            {"asn":1,"type":"left","power":10},{"asn":2,"type":"left","power":50},{"asn":3,"type":"right","power":5},{"asn":4,"type":"uncertain","power":7},{"asn":5,"type":"weird","power":1}]});
        let g = group_neighbours(&d);
        assert_eq!(g["neighbours"]["upstream"][0]["asn"], 2);
        assert_eq!(g["counts"]["upstream"], 2);
        assert_eq!(g["counts"]["uncertain"], 2, "unknown types fall into uncertain");
        assert_eq!(g["counts"]["downstream"], 1);
        let many: Vec<Value> = (0..200).map(|i| json!({"asn": i, "type": "right", "power": i})).collect();
        let g2 = group_neighbours(&json!({ "neighbours": many }));
        assert_eq!(g2["neighbours"]["downstream"].as_array().unwrap().len(), MAX_PER_SIDE);
        assert_eq!(g2["counts"]["downstream"], 200);
        assert_eq!(g2["neighbours"]["downstream"][0]["asn"], 199);
    }

    #[test]
    fn history_detects_origin_changes_and_merges_gaps() {
        let d = json!({"by_origin":[
          {"origin":"64500","prefixes":[{"prefix":"203.0.0.0/22","timelines":[
             {"starttime":"2024-01-01T00:00:00","endtime":"2024-03-01T23:59:59","full_peers_seeing":20.0},
             {"starttime":"2024-03-02T00:00:00","endtime":"2024-05-01T23:59:59","full_peers_seeing":30.0}]},
             {"prefix":"203.0.0.0/24","timelines":[{"starttime":"2020-01-01T00:00:00","endtime":"2020-02-01T00:00:00"}]}]},
          {"origin":"64501","prefixes":[{"prefix":"203.0.0.0/22","timelines":[{"starttime":"2024-05-10T00:00:00","endtime":"2024-06-01T00:00:00","full_peers_seeing":25.0}]}]}]});
        let s = summarize_history(&d, "203.0.0.0/22");
        let o = s["origins"].as_array().unwrap();
        assert_eq!(o.len(), 2);
        assert_eq!(o[0]["origin"], "64500");
        assert_eq!(o[0]["segments"].as_array().unwrap().len(), 1, "a gap under two days is merged");
        assert_eq!(o[0]["segments"][0]["peers"], 30.0);
        assert_eq!(o[0]["first"], "2024-01-01T00:00:00", "more-specific prefix rows are ignored");
        assert_eq!(s["current_origins"], json!(["64501"]));
        assert_eq!(s["multiple_origins_now"], false);
        let kinds: Vec<String> = s["events"].as_array().unwrap().iter().map(|e| format!("{}:{}", e["kind"].as_str().unwrap(), e["origin"].as_str().unwrap())).collect();
        assert_eq!(kinds, ["appeared:64500", "disappeared:64500", "appeared:64501"]);
    }

    #[test]
    fn history_flags_two_current_origins() {
        let d = json!({"by_origin":[
          {"origin":"1","prefixes":[{"prefix":"203.0.0.0/22","timelines":[{"starttime":"2026-01-01T00:00:00","endtime":"2026-11-02T00:00:00"}]}]},
          {"origin":"2","prefixes":[{"prefix":"203.0.0.0/22","timelines":[{"starttime":"2026-10-01T00:00:00","endtime":"2026-11-02T00:00:00"}]}]}]});
        let s = summarize_history(&d, "203.0.0.0/22");
        assert_eq!(s["multiple_origins_now"], true);
        assert!(summarize_history(&json!({}), "x")["origins"].as_array().unwrap().is_empty());
    }

    #[test]
    fn bgp_state_aggregates_without_peer_addresses() {
        let d = json!({"timestamp":"t","bgp_state":[
          {"target_prefix":"193.0.0.0/21","source_id":"00-102.208.105.2","path":[328840,327727,174,1273,3333]},
          {"target_prefix":"193.0.0.0/21","source_id":"01-1.2.3.4","path":[55720,6939,6939,3333]},
          {"target_prefix":"193.0.0.0/24","source_id":"02-9.9.9.9","path":[1,2,64999]}]});
        let s = summarize_state(&d, "193.0.0.0/21");
        assert_eq!(s["peers_seeing"], 2, "only exact-prefix rows count when present");
        assert_eq!(s["origins"][0]["asn"], 3333);
        assert_eq!(s["origins"][0]["peers"], 2);
        let hops: Vec<u64> = s["last_hops"].as_array().unwrap().iter().map(|h| h["asn"].as_u64().unwrap()).collect();
        assert!(hops.contains(&1273) && hops.contains(&6939));
        assert_eq!(s["sample_paths"][1]["path"], json!([55720, 6939, 3333]), "prepending collapsed");
        assert_eq!(s["sample_paths"][0]["collector"], "rrc00");
        let txt = s.to_string();
        assert!(!txt.contains("102.208.105.2") && !txt.contains("1.2.3.4"));
    }

    #[test]
    fn peeringdb_summary_drops_contacts_and_notes() {
        let net = json!({"data":[{"id":433,"name":"Google LLC","aka":"G","asn":15169,"notes":"Contact noc@google.com Jane","website":"https://g.example","info_type":"Content","ix_count":2,"fac_count":1,"info_prefixes4":15000,"poc_set":[{"name":"Jane Doe","email":"jane@example.com"}]}]});
        let ixlan = json!({"data":[{"ix_id":2,"name":"Equinix Chicago","speed":200000,"is_rs_peer":false},{"ix_id":2,"name":"Equinix Chicago","speed":100000,"is_rs_peer":true},{"ix_id":128,"name":"SOLIX","speed":30000}]});
        let fac = json!({"data":[{"name":"Equinix DC1","city":"Ashburn","country":"US","fac_id":1}]});
        let s = summarize_peeringdb(&net, &ixlan, &fac);
        assert_eq!(s["found"], true);
        assert_eq!(s["ixs"][0]["ix_id"], 2);
        assert_eq!(s["ixs"][0]["ports"], 2);
        assert_eq!(s["ixs"][0]["speed_mbps"], 300000);
        assert_eq!(s["ixs"][0]["route_server"], true);
        assert_eq!(s["facilities"][0]["city"], "Ashburn");
        let txt = s.to_string();
        assert!(!txt.contains("Jane") && !txt.contains("noc@") && !txt.contains("example.com\"") || txt.contains("g.example"));
        assert!(!txt.contains("jane@") && !txt.contains("poc"));
        assert_eq!(summarize_peeringdb(&json!({"data":[]}), &json!({}), &json!({}))["found"], false);
    }

    fn app_for(base: &str) -> App {
        App { http: Http::new("osnt-test/0.1"), cache: Cache::open(None, 100, 1 << 20), up: Up { ripe: base.into(), peeringdb: format!("{base}/pdb"), atlas: format!("{base}/atlas") } }
    }

    fn fake_world() -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
        fake::spawn(Arc::new(|p: &str| {
            let j = |s: &str| (200u16, "application/json".to_string(), s.to_string());
            if p.starts_with("/data/prefix-overview/") {
                return if p.contains("10.") { j(r#"{"status":"ok","data":{"resource":"x","asns":[]}}"#) } else { j(r#"{"status":"ok","data":{"resource":"193.0.0.0/21","announced":true,"asns":[{"asn":3333,"holder":"RIPE-NCC-AS"}]}}"#) };
            }
            if p.starts_with("/data/as-overview/") {
                return j(r#"{"status":"ok","data":{"holder":"RIPE-NCC-AS - Reseaux IP Europeens","announced":true,"block":{"name":"IANA","desc":"Assigned by RIPE"}}}"#);
            }
            if p.starts_with("/data/announced-prefixes/") {
                return j(r#"{"status":"ok","data":{"prefixes":[{"prefix":"193.0.20.0/23","timelines":[{"starttime":"2026-10-19T16:00:00","endtime":"2026-11-02T16:00:00"}]}]}}"#);
            }
            if p.starts_with("/data/asn-neighbours/") {
                return j(r#"{"status":"ok","data":{"neighbours":[{"asn":1103,"type":"left","power":5},{"asn":3,"type":"right","power":2}]}}"#);
            }
            if p.starts_with("/data/routing-history/") {
                return j(r#"{"status":"ok","data":{"by_origin":[{"origin":"3333","prefixes":[{"prefix":"193.0.0.0/21","timelines":[{"starttime":"2024-01-01T00:00:00","endtime":"2026-11-02T00:00:00","full_peers_seeing":28.0}]}]}]}}"#);
            }
            if p.starts_with("/data/bgp-state/") {
                return j(r#"{"status":"ok","data":{"timestamp":"t","bgp_state":[{"target_prefix":"193.0.0.0/21","source_id":"00-1.1.1.1","path":[7018,3333]}]}}"#);
            }
            if p.starts_with("/pdb/api/net?asn=3333") {
                return j(r#"{"data":[{"id":7,"name":"RIPE NCC","asn":3333,"info_type":"Not Disclosed"}]}"#);
            }
            if p.starts_with("/pdb/api/net?asn=") {
                return j(r#"{"data":[]}"#);
            }
            if p.starts_with("/pdb/api/netixlan") {
                return j(r#"{"data":[{"ix_id":1,"name":"AMS-IX","speed":100000}]}"#);
            }
            if p.starts_with("/pdb/api/netfac") {
                return j(r#"{"data":[{"name":"Equinix AM3","city":"Amsterdam","country":"NL","fac_id":9}]}"#);
            }
            if p.starts_with("/atlas/api/v2/probes/") {
                return j(r#"{"count":3,"results":[]}"#);
            }
            (404, "text/plain".into(), "nf".into())
        }))
    }

    #[test]
    fn resolve_handles_asn_ip_prefix_and_unannounced() {
        let (base, _) = fake_world();
        let app = app_for(&base);
        assert_eq!(resolve(&app, "as3333").unwrap()["asn"], 3333);
        let v = resolve(&app, "193.0.0.9").unwrap();
        assert_eq!((v["kind"].as_str(), v["asn"].as_u64()), (Some("ip"), Some(3333)));
        assert_eq!(resolve(&app, "193.0.0.0/21").unwrap()["kind"], "prefix");
        assert!(resolve(&app, "10.0.0.0/8").is_err(), "private space is rejected before any upstream call");
        assert!(resolve(&app, "nonsense").is_err());
        let (base2, _) = fake::spawn(Arc::new(|_: &str| (200, "application/json".into(), r#"{"status":"ok","data":{"resource":"x","asns":[]}}"#.into())));
        assert!(resolve(&app_for(&base2), "8.8.4.0/24").unwrap_err().to_string().contains("not announced"));
    }

    #[test]
    fn end_to_end_calls_and_cache() {
        let (base, log) = fake_world();
        let app = app_for(&base);
        assert_eq!(overview(&app, 3333).unwrap()["holder"], "RIPE-NCC-AS - Reseaux IP Europeens");
        assert_eq!(prefixes(&app, 3333).unwrap()["total"], 1);
        assert_eq!(neighbours(&app, 3333).unwrap()["neighbours"]["upstream"][0]["asn"], 1103);
        assert_eq!(history(&app, "193.0.0.0/21", 3).unwrap()["current_origins"], json!(["3333"]));
        assert_eq!(bgp_state(&app, "193.0.0.0/21").unwrap()["peers_seeing"], 1);
        let pdb = peeringdb(&app, 3333, None).unwrap();
        assert_eq!(pdb["ixs"][0]["name"], "AMS-IX");
        assert_eq!(pdb["facilities"][0]["city"], "Amsterdam");
        assert_eq!(peeringdb(&app, 64496, None).unwrap()["found"], false);
        let a = atlas(&app, Some(3333), None).unwrap();
        assert_eq!(a["counts"]["connected_v4"], 3);
        assert_eq!(atlas(&app, None, Some("NL")).unwrap()["counts"]["anchors"], 3);
        assert!(atlas(&app, None, None).is_err());
        assert_eq!(names(&app, &[3333, 1])["3333"], "RIPE-NCC-AS - Reseaux IP Europeens");
        let n = log.lock().unwrap().len();
        let _ = overview(&app, 3333).unwrap();
        let _ = prefixes(&app, 3333).unwrap();
        let _ = peeringdb(&app, 3333, None).unwrap();
        assert_eq!(log.lock().unwrap().len(), n, "second round is served from the cache");
    }

    #[test]
    fn peeringdb_key_is_sent_as_header_only() {
        let (base, log) = fake_world();
        let app = app_for(&base);
        let _ = peeringdb(&app, 3333, Some("SECRETKEY".into())).unwrap();
        assert!(log.lock().unwrap().iter().all(|p| !p.contains("SECRETKEY")), "never in the URL");
    }

    #[test]
    fn upstream_failure_is_an_error_not_a_panic() {
        let app = app_for("http://127.0.0.1:1");
        assert!(overview(&app, 3333).is_err());
        assert!(neighbours(&app, 3333).is_err());
        assert!(atlas(&app, Some(1), None).is_err());
        assert!(names(&app, &[1, 2]).as_object().unwrap().is_empty());
    }
}

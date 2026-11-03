//! Upstream calls and parsers for the IP overview. Every function takes the fixed upstream base URLs from [`Up`],
//! so tests can point them at a fake server; callers of the HTTP API never choose a host.

use std::{
    collections::BTreeSet,
    net::IpAddr,
    time::Duration,
};

use anyhow::{Result, anyhow};
use serde_json::{Value, json};

use crate::{
    cache::{Cache, now_secs},
    ipx::{cidr_contains, parse_cidr},
    net::{Http, Req, haversine_km, status_of, valid_domain},
};

#[derive(Clone)]
pub struct Up {
    pub ripe: String,
    pub shodan: String,
    pub ipwho: String,
    pub ipapi: String,
    pub robtex: String,
    pub tor: String,
    pub drop4: String,
    pub drop6: String,
    pub censys: String,
    pub dns: String,
}

impl Default for Up {
    fn default() -> Self {
        Up {
            ripe: "https://stat.ripe.net".into(),
            shodan: "https://internetdb.shodan.io".into(),
            ipwho: "https://ipwho.is".into(),
            ipapi: "https://ipapi.co".into(),
            robtex: "https://freeapi.robtex.com".into(),
            tor: "https://check.torproject.org/torbulkexitlist".into(),
            drop4: "https://www.spamhaus.org/drop/drop_v4.json".into(),
            drop6: "https://www.spamhaus.org/drop/drop_v6.json".into(),
            censys: "https://search.censys.io".into(),
            dns: "https://dns.google".into(),
        }
    }
}

pub struct App {
    pub http: Http,
    pub cache: Cache,
    pub up: Up,
}

const H: u64 = 3600;
const NEG: Duration = Duration::from_secs(90);

pub enum Target {
    Ip(IpAddr),
    Host(String),
}

/// A public IP address, or a hostname. Private, loopback and reserved addresses are refused: they have no public data.
pub fn parse_target(q: &str) -> Result<Target, String> {
    let q = q.trim().trim_start_matches('[').trim_end_matches(']');
    if q.is_empty() {
        return Err("enter an IP address or a hostname".into());
    }
    if let Ok(ip) = q.parse::<IpAddr>() {
        if !crate::ipx::ip_public(ip) {
            return Err("that is a private, loopback or reserved address: there is no public data about it".into());
        }
        return Ok(Target::Ip(ip));
    }
    match crate::net::host_from_input(q) {
        Some(h) => Ok(Target::Host(h)),
        None => Err("enter an IP address (8.8.8.8) or a hostname (example.com)".into()),
    }
}

pub fn parse_ip(q: &str) -> Result<IpAddr, String> {
    match parse_target(q)? {
        Target::Ip(ip) => Ok(ip),
        Target::Host(_) => Err("this operation needs an IP address".into()),
    }
}

// ---- RIPEstat ------------------------------------------------------------------------------------------------

fn ripe(app: &App, call: &str, resource: &str, ttl: u64) -> Result<Value> {
    let key = format!("ripe:{call}:{resource}");
    app.cache.cached_json_neg(&key, Duration::from_secs(ttl), NEG, || {
        let url = format!("{}/data/{call}/data.json?resource={resource}", app.up.ripe);
        let v = app.http.json(Req::new(&url).gap(150))?;
        if v["status"].as_str() != Some("ok") {
            return Err(anyhow!("stat.ripe.net {call}: {}", v["messages"][0][1].as_str().unwrap_or("not ok")));
        }
        Ok(v["data"].clone())
    })
}

/// Whois keys that describe a network or an organisation. Person, contact and free-text keys are dropped on purpose.
const WHOIS_KEEP: [&str; 16] =
    ["netrange", "cidr", "inetnum", "inet6num", "netname", "nettype", "orgname", "org-name", "organization", "country", "status", "originas", "regdate", "created", "updated", "last-modified"];

pub fn whois_fields(data: &Value) -> Vec<Value> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for group in ["records", "irr_records"] {
        for rec in data[group].as_array().into_iter().flatten() {
            for f in rec.as_array().into_iter().flatten() {
                let (Some(k), Some(v)) = (f["key"].as_str(), f["value"].as_str()) else { continue };
                if !WHOIS_KEEP.contains(&k.to_ascii_lowercase().as_str()) {
                    continue;
                }
                let v: String = v.trim().chars().take(160).collect();
                if v.is_empty() {
                    continue;
                }
                if seen.insert((k.to_ascii_lowercase(), v.clone())) && out.len() < 24 {
                    out.push(json!({ "key": k, "value": v }));
                }
            }
        }
    }
    out
}

pub fn owner(app: &App, ip: &str) -> Result<Value> {
    let (po, who, abuse) = std::thread::scope(|s| {
        let a = s.spawn(|| ripe(app, "prefix-overview", ip, H));
        let b = s.spawn(|| ripe(app, "whois", ip, 6 * H));
        let c = s.spawn(|| ripe(app, "abuse-contact-finder", ip, 6 * H));
        (a.join().unwrap(), b.join().unwrap(), c.join().unwrap())
    });
    let po = po?;
    let asns: Vec<Value> = po["asns"].as_array().into_iter().flatten().map(|a| json!({ "asn": a["asn"], "holder": a["holder"] })).collect();
    let abuse_list: Vec<Value> = abuse.as_ref().ok().and_then(|a| a["abuse_contacts"].as_array().cloned()).unwrap_or_default();
    Ok(json!({
        "prefix": po["resource"], "announced": po["announced"], "asns": asns,
        "block": po["block"]["name"],
        "whois": who.as_ref().map(|w| whois_fields(w)).unwrap_or_default(),
        "whois_error": who.err().map(|e| e.to_string()),
        "abuse_role_contacts": abuse_list,
        "rir": abuse.ok().and_then(|a| a["authoritative_rir"].as_str().map(str::to_owned)),
    }))
}

// ---- Shodan InternetDB -----------------------------------------------------------------------------------------

pub fn exposure(app: &App, ip: &str) -> Result<Value> {
    app.cache.cached_json_neg(&format!("internetdb:{ip}"), Duration::from_secs(6 * H), NEG, || {
        let url = format!("{}/{ip}", app.up.shodan);
        match app.http.json(Req::new(&url).gap(1000)) {
            Ok(v) => {
                let list = |k: &str, cap: usize| -> Vec<Value> { v[k].as_array().into_iter().flatten().take(cap).cloned().collect() };
                let vulns = v["vulns"].as_array().map(|a| a.len()).unwrap_or(0);
                Ok(json!({ "has_data": true, "ports": list("ports", 200), "cpes": list("cpes", 100), "hostnames": list("hostnames", 100), "tags": list("tags", 50), "vulns": list("vulns", 200), "vuln_count": vulns }))
            }
            // InternetDB answers 404 for an address it has never seen: that is "no data", not a failure.
            Err(e) if status_of(&e) == Some(404) => Ok(json!({ "has_data": false, "ports": [], "cpes": [], "hostnames": [], "tags": [], "vulns": [], "vuln_count": 0 })),
            Err(e) => Err(e),
        }
    })
}

// ---- Geolocation -----------------------------------------------------------------------------------------------

fn geo_entry(source: &str, r: Result<Value>) -> Value {
    match r {
        Ok(v) => v,
        Err(e) => json!({ "source": source, "error": e.to_string() }),
    }
}

fn geo_ripe(app: &App, ip: &str) -> Result<Value> {
    let d = ripe(app, "maxmind-geo-lite", ip, 12 * H)?;
    let loc = d["located_resources"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|r| r["locations"].as_array().into_iter().flatten())
        // (0, 0) is how GeoLite marks "unknown", not a place in the Gulf of Guinea.
        .filter(|l| !(l["latitude"].as_f64() == Some(0.0) && l["longitude"].as_f64() == Some(0.0)))
        .max_by(|a, b| a["covered_percentage"].as_f64().unwrap_or(0.0).total_cmp(&b["covered_percentage"].as_f64().unwrap_or(0.0)))
        .ok_or_else(|| anyhow!("stat.ripe.net: no location for this address"))?;
    let (lat, lon) = (loc["latitude"].as_f64(), loc["longitude"].as_f64());
    if lat.is_none() || lon.is_none() {
        return Err(anyhow!("stat.ripe.net: no coordinates for this address"));
    }
    Ok(json!({ "source": "RIPEstat (MaxMind GeoLite)", "id": "ripe", "lat": lat, "lon": lon, "city": loc["city"], "region": null, "country": loc["country"] }))
}

fn geo_ipwho(app: &App, ip: &str) -> Result<Value> {
    app.cache.cached_json_neg(&format!("ipwho:{ip}"), Duration::from_secs(12 * H), NEG, || {
        let v = app.http.json(Req::new(&format!("{}/{ip}", app.up.ipwho)).gap(500))?;
        if v["success"].as_bool() == Some(false) {
            return Err(anyhow!("ipwho.is: {}", v["message"].as_str().unwrap_or("lookup failed")));
        }
        if v["latitude"].as_f64().is_none() {
            return Err(anyhow!("ipwho.is: no coordinates for this address"));
        }
        Ok(json!({ "source": "ipwho.is", "id": "ipwho", "lat": v["latitude"], "lon": v["longitude"], "city": v["city"], "region": v["region"], "country": v["country_code"] }))
    })
}

fn geo_ipapi(app: &App, ip: &str) -> Result<Value> {
    app.cache.cached_json_neg(&format!("ipapi:{ip}"), Duration::from_secs(12 * H), NEG, || {
        let v = app.http.json(Req::new(&format!("{}/{ip}/json/", app.up.ipapi)).gap(1500))?;
        if v["error"].as_bool() == Some(true) {
            return Err(anyhow!("ipapi.co: {}", v["reason"].as_str().unwrap_or("lookup failed")));
        }
        if v["latitude"].as_f64().is_none() {
            return Err(anyhow!("ipapi.co: no coordinates for this address"));
        }
        Ok(json!({ "source": "ipapi.co", "id": "ipapi", "lat": v["latitude"], "lon": v["longitude"], "city": v["city"], "region": v["region"], "country": v["country_code"] }))
    })
}

/// Largest distance between any two sources that returned coordinates.
pub fn max_disagreement_km(sources: &[Value]) -> Option<f64> {
    let pts: Vec<(f64, f64)> = sources.iter().filter_map(|s| Some((s["lat"].as_f64()?, s["lon"].as_f64()?))).collect();
    if pts.len() < 2 {
        return None;
    }
    let mut best = 0.0f64;
    for (i, a) in pts.iter().enumerate() {
        for b in &pts[i + 1..] {
            best = best.max(haversine_km(*a, *b));
        }
    }
    Some(best)
}

pub fn geo(app: &App, ip: &str) -> Result<Value> {
    let sources: Vec<Value> = std::thread::scope(|s| {
        let a = s.spawn(|| geo_entry("RIPEstat (MaxMind GeoLite)", geo_ripe(app, ip)));
        let b = s.spawn(|| geo_entry("ipwho.is", geo_ipwho(app, ip)));
        let c = s.spawn(|| geo_entry("ipapi.co", geo_ipapi(app, ip)));
        vec![a.join().unwrap(), b.join().unwrap(), c.join().unwrap()]
    });
    let km = max_disagreement_km(&sources);
    Ok(json!({ "sources": sources, "max_disagreement_km": km.map(|k| k.round()), "disagree": km.map(|k| k > 100.0) }))
}

// ---- Membership lists ------------------------------------------------------------------------------------------

fn cached_list(app: &App, key: &str, url: &str, ttl: u64) -> Result<Value> {
    app.cache.cached_json_neg(key, Duration::from_secs(ttl), NEG, || {
        let text = app.http.text(Req::new(url).accept("text/plain, application/json, */*").gap(500))?;
        Ok(json!({ "fetched": now_secs(), "text": text }))
    })
}

fn norm_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) => v6.to_string(),
        IpAddr::V4(v4) => v4.to_string(),
    }
}

/// Tor exit list: one address per line.
pub fn tor_listed(text: &str, ip: IpAddr) -> (bool, usize) {
    let want = norm_ip(ip);
    let mut n = 0;
    let mut hit = false;
    for l in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        n += 1;
        if l.parse::<IpAddr>().map(norm_ip).ok().as_deref() == Some(want.as_str()) {
            hit = true;
        }
    }
    (hit, n)
}

/// Spamhaus DROP JSON lines: `{"cidr":..,"sblid":..,"rir":..}` plus a trailing metadata line.
pub fn drop_match(text: &str, ip: IpAddr) -> (Option<Value>, usize, Option<String>) {
    let mut n = 0;
    let mut hit = None;
    let mut copyright = None;
    for l in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let Ok(v) = serde_json::from_str::<Value>(l) else { continue };
        if v["type"].as_str() == Some("metadata") {
            copyright = v["copyright"].as_str().map(str::to_owned);
            continue;
        }
        let Some(c) = v["cidr"].as_str() else { continue };
        n += 1;
        if hit.is_none() {
            if let Some((net, len)) = parse_cidr(c) {
                if cidr_contains(net, len, ip) {
                    hit = Some(json!({ "cidr": c, "sblid": v["sblid"], "rir": v["rir"], "url": v["sblid"].as_str().map(|s| format!("https://www.spamhaus.org/sbl/query/{s}")) }));
                }
            }
        }
    }
    (hit, n, copyright)
}

pub fn lists(app: &App, ip: IpAddr) -> Result<Value> {
    let (tor, drop4, drop6) = std::thread::scope(|s| {
        let a = s.spawn(|| cached_list(app, "list:tor", &app.up.tor, H));
        let b = s.spawn(|| cached_list(app, "list:drop4", &app.up.drop4, 12 * H));
        let c = s.spawn(|| cached_list(app, "list:drop6", &app.up.drop6, 12 * H));
        (a.join().unwrap(), b.join().unwrap(), c.join().unwrap())
    });
    let tor_v = match tor {
        Ok(v) => {
            let (hit, n) = tor_listed(v["text"].as_str().unwrap_or(""), ip);
            json!({ "listed": hit, "entries": n, "fetched": v["fetched"], "source": "check.torproject.org/torbulkexitlist" })
        }
        Err(e) => json!({ "error": e.to_string() }),
    };
    let which = if ip.is_ipv4() { drop4 } else { drop6 };
    let drop_v = match which {
        Ok(v) => {
            let (hit, n, c) = drop_match(v["text"].as_str().unwrap_or(""), ip);
            json!({ "listed": hit.is_some(), "match": hit, "entries": n, "fetched": v["fetched"], "copyright": c, "source": "spamhaus.org/drop", "terms": "https://www.spamhaus.org/drop/terms/" })
        }
        Err(e) => json!({ "error": e.to_string() }),
    };
    Ok(json!({ "tor_exit": tor_v, "spamhaus_drop": drop_v }))
}

// ---- Robtex ----------------------------------------------------------------------------------------------------

pub fn robtex(app: &App, ip: &str) -> Result<Value> {
    app.cache.cached_json_neg(&format!("robtex:{ip}"), Duration::from_secs(12 * H), NEG, || {
        let v = app.http.json(Req::new(&format!("{}/ipquery/{ip}", app.up.robtex)).gap(1000))?;
        if v["status"].as_str() != Some("ok") {
            return Err(anyhow!("robtex: {}", v["status"].as_str().unwrap_or("no data")));
        }
        // The passive-DNS list ("pas") is deliberately not passed on: this plugin shows routing context only.
        Ok(json!({ "asn": v["as"], "as_name": v["asname"], "as_description": v["asdesc"], "route": v["bgproute"], "route_description": v["routedesc"], "whois_description": v["whoisdesc"], "country": v["country"] }))
    })
}

// ---- Censys (optional, unverified) -----------------------------------------------------------------------------

fn b64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in input.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() { out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char) } else { out.push('=') }
        }
    }
    out
}

pub fn censys(app: &App, ip: &str, id: &str, secret: &str) -> Result<Value> {
    let auth = format!("Basic {}", b64(format!("{id}:{secret}").as_bytes()));
    app.cache.cached_json_neg(&format!("censys:{ip}"), Duration::from_secs(6 * H), NEG, || {
        let url = format!("{}/api/v2/hosts/{ip}", app.up.censys);
        let v = app.http.json(Req::new(&url).header("Authorization", auth.clone()).gap(1000)).map_err(|e| match status_of(&e) {
            Some(401) | Some(403) => anyhow!("censys: the API ID/secret were rejected"),
            Some(404) => anyhow!("censys: no record for this address"),
            _ => e,
        })?;
        let r = &v["result"];
        let services: Vec<Value> =
            r["services"].as_array().into_iter().flatten().take(100).map(|s| json!({ "port": s["port"], "service": s["service_name"], "transport": s["transport_protocol"] })).collect();
        Ok(json!({ "services": services, "labels": r["labels"], "as": r["autonomous_system"]["name"], "last_updated": r["last_updated_at"], "link": format!("https://search.censys.io/hosts/{ip}") }))
    })
}

// ---- DNS (hostname input) --------------------------------------------------------------------------------------

pub fn resolve(app: &App, name: &str) -> Result<Vec<IpAddr>> {
    let name = valid_domain(name).ok_or_else(|| anyhow!("not a valid hostname"))?;
    let mut ips: Vec<IpAddr> = Vec::new();
    let mut any_ok = false;
    for t in ["A", "AAAA"] {
        let v = app.cache.cached_json_neg(&format!("dns:{name}:{t}"), Duration::from_secs(600), NEG, || {
            app.http.json(Req::new(&format!("{}/resolve?name={name}&type={t}", app.up.dns)).accept("application/dns-json").gap(100))
        });
        if let Ok(v) = v {
            any_ok = true;
            for a in v["Answer"].as_array().into_iter().flatten() {
                if a["type"].as_u64() == Some(if t == "A" { 1 } else { 28 }) {
                    if let Some(ip) = a["data"].as_str().and_then(|d| d.parse::<IpAddr>().ok()) {
                        if !ips.contains(&ip) && crate::ipx::ip_public(ip) {
                            ips.push(ip);
                        }
                    }
                }
            }
        }
    }
    if !any_ok {
        return Err(anyhow!("dns.google could not be reached"));
    }
    if ips.is_empty() {
        return Err(anyhow!("{name} has no public A or AAAA record"));
    }
    ips.truncate(12);
    Ok(ips)
}

// ---- Overview --------------------------------------------------------------------------------------------------

fn section(errors: &mut serde_json::Map<String, Value>, name: &str, r: Result<Value>) -> Value {
    match r {
        Ok(v) => v,
        Err(e) => {
            errors.insert(name.into(), json!(e.to_string()));
            Value::Null
        }
    }
}

/// Everything about one IP. Each section fails on its own: the response carries `errors` for the ones that did.
pub fn overview(app: &App, ip: IpAddr, host: Option<(String, Vec<IpAddr>)>, censys_key: Option<(String, String)>) -> Value {
    let ips = ip.to_string();
    let (owner_r, exp_r, geo_r, lists_r, rob_r, cen_r) = std::thread::scope(|s| {
        let o = s.spawn(|| owner(app, &ips));
        let e = s.spawn(|| exposure(app, &ips));
        let g = s.spawn(|| geo(app, &ips));
        let l = s.spawn(|| lists(app, ip));
        let r = s.spawn(|| robtex(app, &ips));
        let c = s.spawn(|| censys_key.as_ref().map(|(id, sec)| censys(app, &ips, id, sec)));
        (o.join().unwrap(), e.join().unwrap(), g.join().unwrap(), l.join().unwrap(), r.join().unwrap(), c.join().unwrap())
    });
    let mut errors = serde_json::Map::new();
    let owner_v = section(&mut errors, "owner", owner_r);
    let exp_v = section(&mut errors, "exposure", exp_r);
    let geo_v = section(&mut errors, "geo", geo_r);
    let lists_v = section(&mut errors, "lists", lists_r);
    let rob_v = section(&mut errors, "robtex", rob_r);
    let cen_v = cen_r.map(|r| section(&mut errors, "censys", r));
    // Cross-check the routing sources: RIPEstat and Robtex should name the same origin AS.
    let ripe_asn = owner_v["asns"][0]["asn"].as_u64();
    let rob_asn = rob_v["asn"].as_u64();
    let asn_agree = match (ripe_asn, rob_asn) {
        (Some(a), Some(b)) => Some(a == b),
        _ => None,
    };
    json!({
        "ip": ips, "version": if ip.is_ipv4() { 4 } else { 6 },
        "host": host.map(|(n, all)| json!({ "name": n, "ips": all.iter().map(|i| i.to_string()).collect::<Vec<_>>() })),
        "owner": owner_v, "exposure": exp_v, "geo": geo_v, "lists": lists_v, "robtex": rob_v, "censys": cen_v,
        "censys_configured": censys_key.is_some(),
        "asn_agree": asn_agree, "errors": errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::fake;
    use std::sync::Arc;

    const DROP: &str = "{\"cidr\":\"1.10.16.0/20\",\"sblid\":\"SBL256894\",\"rir\":\"apnic\"}\n{\"cidr\":\"2a0b:2::/32\",\"sblid\":\"SBL1\",\"rir\":\"ripencc\"}\nnot json\n{\"type\":\"metadata\",\"timestamp\":1,\"size\":2,\"records\":2,\"copyright\":\"(c) Spamhaus\"}\n";

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn target_parsing() {
        assert!(matches!(parse_target(" 8.8.8.8 "), Ok(Target::Ip(_))));
        assert!(matches!(parse_target("[2606:4700::1111]"), Ok(Target::Ip(_))));
        assert!(matches!(parse_target("https://Example.com/x"), Ok(Target::Host(h)) if h == "example.com"));
        for bad in ["", "10.0.0.1", "127.0.0.1", "::1", "not a host", "1.2.3", "999.1.1.1", "fe80::1"] {
            assert!(parse_target(bad).is_err(), "{bad}");
        }
        assert!(parse_ip("example.com").is_err());
    }

    #[test]
    fn whois_keeps_network_fields_and_drops_people() {
        let d = json!({ "records": [[
            {"key":"NetRange","value":"8.8.8.0 - 8.8.8.255"},{"key":"NetName","value":"GOGL"},{"key":"OrgName","value":"Google LLC"},
            {"key":"Address","value":"1600 Amphitheatre"},{"key":"person","value":"Jane Doe"},{"key":"e-mail","value":"jane@example.com"},
            {"key":"phone","value":"+1 555"},{"key":"admin-c","value":"JD1-RIPE"},{"key":"remarks","value":"call me"},{"key":"descr","value":"John's house"}
        ]], "irr_records": [[{"key":"origin","value":"AS15169"},{"key":"NetName","value":"GOGL"}]] });
        let f = whois_fields(&d);
        let keys: Vec<&str> = f.iter().map(|x| x["key"].as_str().unwrap()).collect();
        assert_eq!(keys, ["NetRange", "NetName", "OrgName"], "duplicates collapsed, people and contact keys dropped");
        let s = serde_json::to_string(&f).unwrap();
        assert!(!s.contains("Jane") && !s.contains("@") && !s.contains("house"));
    }

    #[test]
    fn disagreement_between_sources() {
        let s = vec![json!({"lat":51.5,"lon":-0.12}), json!({"lat":48.85,"lon":2.35}), json!({"error":"x"})];
        let km = max_disagreement_km(&s).unwrap();
        assert!((330.0..350.0).contains(&km));
        assert!(max_disagreement_km(&s[..1]).is_none());
        assert!(max_disagreement_km(&[json!({"error":"a"}), json!({"error":"b"})]).is_none());
    }

    #[test]
    fn null_island_is_not_a_location() {
        let (base, _) = fake::spawn(Arc::new(|_: &str| (200, "application/json".into(), r#"{"status":"ok","data":{"located_resources":[{"locations":[{"country":"US","city":"","latitude":0.0,"longitude":0.0,"covered_percentage":100.0}]}]}}"#.into())));
        let app = app_for(&base);
        assert!(geo_ripe(&app, "1.2.3.4").unwrap_err().to_string().contains("no location"));
    }

    #[test]
    fn tor_and_drop_parsers() {
        let tor = "# comment\n171.25.193.25\n2001:db8::1\n\n80.67.167.81\n";
        assert_eq!(tor_listed(tor, ip("171.25.193.25")), (true, 3));
        assert_eq!(tor_listed(tor, ip("171.25.193.26")).0, false);
        let (hit, n, c) = drop_match(DROP, ip("1.10.20.1"));
        assert_eq!(n, 2);
        assert_eq!(hit.unwrap()["sblid"], "SBL256894");
        assert_eq!(c.as_deref(), Some("(c) Spamhaus"));
        assert!(drop_match(DROP, ip("1.10.32.1")).0.is_none());
        assert!(drop_match(DROP, ip("2a0b:2:1::1")).0.is_some());
    }

    #[test]
    fn base64_for_basic_auth() {
        assert_eq!(b64(b"id:secret"), "aWQ6c2VjcmV0");
        assert_eq!(b64(b"ab"), "YWI=");
        assert_eq!(b64(b"a"), "YQ==");
    }

    fn fake_world() -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
        fake::spawn(Arc::new(|p: &str| {
            let j = |s: &str| (200u16, "application/json".to_string(), s.to_string());
            if p.starts_with("/data/prefix-overview/") {
                return j(r#"{"status":"ok","data":{"resource":"8.8.8.0/24","announced":true,"asns":[{"asn":15169,"holder":"GOOGLE"}],"block":{"name":"IANA"}}}"#);
            }
            if p.starts_with("/data/whois/") {
                return j(r#"{"status":"ok","data":{"records":[[{"key":"NetName","value":"GOGL"},{"key":"person","value":"X"}]],"irr_records":[]}}"#);
            }
            if p.starts_with("/data/abuse-contact-finder/") {
                return j(r#"{"status":"ok","data":{"abuse_contacts":["abuse@example.net"],"authoritative_rir":"arin"}}"#);
            }
            if p.starts_with("/data/maxmind-geo-lite/") {
                return j(r#"{"status":"ok","data":{"located_resources":[{"locations":[{"country":"US","city":"","latitude":37.7,"longitude":-97.8,"covered_percentage":100.0}]}]}}"#);
            }
            if p.starts_with("/internetdb/8.8.8.8") {
                return j(r#"{"ports":[53,443],"cpes":[],"hostnames":["dns.google"],"tags":[],"vulns":["CVE-2020-1"]}"#);
            }
            if p.starts_with("/internetdb/") {
                return (404, "application/json".into(), r#"{"detail":"No information available"}"#.into());
            }
            if p.starts_with("/ipwho/") {
                return j(r#"{"success":true,"latitude":37.39,"longitude":-121.89,"city":"San Jose","region":"California","country_code":"US"}"#);
            }
            if p.starts_with("/ipapi/") {
                return j(r#"{"error":true,"reason":"RateLimited"}"#);
            }
            if p.starts_with("/robtex/ipquery/") {
                return j(r#"{"status":"ok","as":15169,"asname":"Google","asdesc":"GOOGLE","bgproute":"8.8.8.0/24","routedesc":"Google LLC","pas":[{"o":"private-person-site.example","t":1}]}"#);
            }
            if p == "/tor" {
                return (200, "text/plain".into(), "8.8.8.8\n1.2.3.4\n".into());
            }
            if p == "/drop4" {
                return (200, "text/json".into(), DROP.into());
            }
            if p == "/drop6" {
                return (200, "text/json".into(), "{\"type\":\"metadata\"}\n".into());
            }
            if p.starts_with("/censys/api/v2/hosts/") {
                return j(r#"{"result":{"services":[{"port":53,"service_name":"DNS","transport_protocol":"UDP"}],"labels":["cdn"],"autonomous_system":{"name":"GOOGLE"}}}"#);
            }
            if p.starts_with("/dns/resolve") {
                return if p.contains("type=A&") || p.ends_with("type=A") {
                    j(r#"{"Status":0,"Answer":[{"name":"x.","type":1,"data":"8.8.4.4"},{"name":"x.","type":1,"data":"10.0.0.1"}]}"#)
                } else {
                    j(r#"{"Status":0}"#)
                };
            }
            (404, "text/plain".into(), "nf".into())
        }))
    }

    fn app_for(base: &str) -> App {
        App {
            http: Http::new("osnt-test/0.1"),
            cache: Cache::open(None, 100, 1 << 20),
            up: Up {
                ripe: base.into(),
                shodan: format!("{base}/internetdb"),
                ipwho: format!("{base}/ipwho"),
                ipapi: format!("{base}/ipapi"),
                robtex: format!("{base}/robtex"),
                tor: format!("{base}/tor"),
                drop4: format!("{base}/drop4"),
                drop6: format!("{base}/drop6"),
                censys: format!("{base}/censys"),
                dns: format!("{base}/dns"),
            },
        }
    }

    #[test]
    fn overview_merges_sections_and_isolates_failures() {
        let (base, log) = fake_world();
        let app = app_for(&base);
        let v = overview(&app, ip("8.8.8.8"), None, None);
        assert_eq!(v["owner"]["asns"][0]["asn"], 15169);
        assert_eq!(v["owner"]["whois"][0]["key"], "NetName");
        assert_eq!(v["owner"]["abuse_role_contacts"][0], "abuse@example.net");
        assert_eq!(v["exposure"]["ports"], json!([53, 443]));
        assert_eq!(v["exposure"]["vuln_count"], 1);
        assert_eq!(v["lists"]["tor_exit"]["listed"], true);
        assert_eq!(v["lists"]["spamhaus_drop"]["listed"], false);
        // ipapi fails (rate limited) but ripe + ipwho still give two sources.
        let srcs = v["geo"]["sources"].as_array().unwrap();
        assert_eq!(srcs.len(), 3);
        assert!(srcs.iter().any(|s| s["error"].as_str().is_some_and(|e| e.contains("RateLimited"))));
        assert!(v["geo"]["max_disagreement_km"].as_f64().unwrap() > 500.0, "37.7,-97.8 vs 37.39,-121.89");
        assert_eq!(v["geo"]["disagree"], true);
        assert_eq!(v["asn_agree"], true);
        assert!(!v["robtex"].to_string().contains("private-person-site"), "passive DNS list must not be passed on");
        assert_eq!(v["censys_configured"], false);
        assert!(v["errors"].as_object().unwrap().is_empty(), "{}", v["errors"]);
        let first = log.lock().unwrap().len();
        // Second call is served from the cache: no new upstream requests.
        let _ = overview(&app, ip("8.8.8.8"), None, None);
        assert_eq!(log.lock().unwrap().len(), first);
    }

    #[test]
    fn exposure_404_is_no_data_not_an_error() {
        let (base, _) = fake_world();
        let app = app_for(&base);
        let v = exposure(&app, "9.9.9.9").unwrap();
        assert_eq!(v["has_data"], false);
        assert_eq!(v["ports"], json!([]));
    }

    #[test]
    fn a_dead_upstream_becomes_a_section_error() {
        let mut app = app_for("http://127.0.0.1:1");
        app.up.ripe = "http://127.0.0.1:1".into();
        let v = overview(&app, ip("8.8.8.8"), None, None);
        let errs = v["errors"].as_object().unwrap();
        assert!(errs.contains_key("owner") && errs.contains_key("exposure") && errs.contains_key("robtex"));
        assert!(v["lists"]["tor_exit"]["error"].is_string(), "list failures are reported inside the section");
        assert!(v["owner"].is_null());
    }

    #[test]
    fn censys_only_runs_with_credentials_and_hides_them() {
        let (base, log) = fake_world();
        let app = app_for(&base);
        let v = overview(&app, ip("8.8.8.8"), None, Some(("ID".into(), "SECRET".into())));
        assert_eq!(v["censys"]["services"][0]["port"], 53);
        assert_eq!(v["censys_configured"], true);
        let s = v.to_string();
        assert!(!s.contains("SECRET") && !s.contains("U0VDUkVU"));
        assert!(log.lock().unwrap().iter().any(|p| p.starts_with("/censys/")));
    }

    #[test]
    fn hostname_resolution_keeps_public_addresses_only() {
        let (base, _) = fake_world();
        let app = app_for(&base);
        let ips = resolve(&app, "example.com").unwrap();
        assert_eq!(ips, vec![ip("8.8.4.4")]);
        assert!(resolve(&app, "bad host").is_err());
    }
}

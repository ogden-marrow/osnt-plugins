//! Passive subdomain sources, merging, and DNS liveness classification. Nothing here brute-forces names or attempts
//! zone transfers; upstream hosts are fixed in [`Up`] and the only caller input is the domain.

use std::{collections::BTreeMap, time::Duration};

use anyhow::{Result, anyhow};
use serde_json::{Value, json};

use crate::{
    cache::Cache,
    net::{Http, Req, par_map, valid_domain, valid_found_name},
};

#[derive(Clone)]
pub struct Up {
    pub certspotter: String,
    pub hackertarget: String,
    pub mnemonic: String,
    pub urlscan: String,
    pub wayback: String,
    pub otx: String,
    pub virustotal: String,
    pub lookup: String,
    pub dns: String,
}
impl Default for Up {
    fn default() -> Self {
        Up {
            certspotter: "https://api.certspotter.com".into(),
            hackertarget: "https://api.hackertarget.com".into(),
            mnemonic: "https://api.mnemonic.no".into(),
            urlscan: "https://urlscan.io".into(),
            wayback: "https://web.archive.org".into(),
            otx: "https://otx.alienvault.com".into(),
            virustotal: "https://www.virustotal.com".into(),
            lookup: format!("http://{}", std::env::var("OSNT_LOOKUP").unwrap_or_else(|_| "127.0.0.1:8103".into())),
            dns: "https://dns.google".into(),
        }
    }
}

#[derive(Default, Clone)]
pub struct Keys {
    pub certspotter: Option<String>,
    pub virustotal: Option<String>,
    pub otx: Option<String>,
}

pub struct App {
    pub http: Http,
    pub cache: Cache,
    pub up: Up,
}

const H: u64 = 3600;
const NEG: Duration = Duration::from_secs(120);
pub const MAX_NAMES: usize = 5000;

pub struct SourceInfo {
    pub id: &'static str,
    pub name: &'static str,
    pub default: bool,
    pub key: Option<&'static str>,
    pub key_required: bool,
    pub note: &'static str,
}

pub const SOURCES: [SourceInfo; 8] = [
    SourceInfo { id: "certspotter", name: "Certspotter (CT logs)", default: true, key: Some("CERTSPOTTER_API_KEY"), key_required: false, note: "Certificate issuances. Anonymous: first pages only, strict rate limit." },
    SourceInfo { id: "crtsh", name: "crt.sh (via Domain & IP lookup)", default: true, key: None, key_required: false, note: "Certificate transparency through the lookup plugin. Slow, sometimes flaky." },
    SourceInfo { id: "mnemonic", name: "mnemonic passive DNS", default: true, key: None, key_required: false, note: "Passive DNS records for the domain; mostly finds the apex and aliases." },
    SourceInfo { id: "urlscan", name: "urlscan.io", default: true, key: None, key_required: false, note: "Hosts seen in public scans." },
    SourceInfo { id: "wayback", name: "Wayback Machine (CDX)", default: true, key: None, key_required: false, note: "Hosts in archived URLs. Can be slow or offline." },
    SourceInfo { id: "hackertarget", name: "HackerTarget host search", default: false, key: None, key_required: false, note: "Last resort: about 50 requests a day for everyone behind this IP, so it is off by default." },
    SourceInfo { id: "otx", name: "AlienVault OTX passive DNS", default: false, key: Some("OTX_API_KEY"), key_required: true, note: "Anonymous access is refused by OTX; needs a free key." },
    SourceInfo { id: "virustotal", name: "VirusTotal", default: false, key: Some("VIRUSTOTAL_API_KEY"), key_required: true, note: "Needs a free key; 4 requests a minute, so it is slow." },
];

// ---- name filtering and parsers --------------------------------------------------------------------------------

/// Keep only valid hostnames that are the domain itself or below it. Wildcards are stripped, anything with an `@`
/// (e-mail addresses sometimes appear in certificate names) is dropped.
pub fn clean_names<'a>(domain: &str, raw: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let suffix = format!(".{domain}");
    let mut set = std::collections::BTreeSet::new();
    for r in raw {
        let n = r.trim().trim_start_matches("*.").trim_end_matches('.').to_ascii_lowercase();
        if n.contains('@') || n.contains(' ') {
            continue;
        }
        let Some(n) = valid_found_name(&n) else { continue };
        if n == domain || n.ends_with(&suffix) {
            set.insert(n);
        }
    }
    set.into_iter().collect()
}

pub fn host_of_url(u: &str) -> Option<&str> {
    let rest = u.split("://").nth(1).unwrap_or(u);
    let auth = rest.split(['/', '?', '#']).next()?;
    let auth = auth.rsplit('@').next()?;
    Some(auth.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map(|(h, _)| h).unwrap_or(auth))
}

pub fn parse_certspotter(v: &Value) -> Vec<&str> {
    v.as_array().into_iter().flatten().flat_map(|c| c["dns_names"].as_array().into_iter().flatten()).filter_map(Value::as_str).collect()
}
pub fn parse_hackertarget(t: &str) -> Result<Vec<&str>> {
    let first = t.trim_start();
    if first.starts_with("error") || first.contains("API count exceeded") {
        return Err(anyhow!("hackertarget.com: {}", first.lines().next().unwrap_or("refused the request").chars().take(100).collect::<String>()));
    }
    Ok(t.lines().filter_map(|l| l.split(',').next()).collect())
}
pub fn parse_mnemonic(v: &Value) -> Vec<&str> {
    v["data"].as_array().into_iter().flatten().flat_map(|r| [r["query"].as_str(), r["answer"].as_str()]).flatten().collect()
}
pub fn parse_urlscan(v: &Value) -> Vec<&str> {
    v["results"].as_array().into_iter().flatten().flat_map(|r| [r["page"]["domain"].as_str(), r["task"]["domain"].as_str()]).flatten().collect()
}
pub fn parse_wayback(v: &Value) -> Vec<&str> {
    v.as_array().into_iter().flatten().filter_map(|row| row.get(0).and_then(Value::as_str)).filter(|s| *s != "original").filter_map(host_of_url).collect()
}
pub fn parse_otx(v: &Value) -> Vec<&str> {
    v["passive_dns"].as_array().into_iter().flatten().flat_map(|r| [r["hostname"].as_str(), r["address"].as_str()]).flatten().collect()
}
pub fn parse_vt(v: &Value) -> Vec<&str> {
    v["data"].as_array().into_iter().flatten().filter_map(|r| r["id"].as_str()).collect()
}

// ---- sources ---------------------------------------------------------------------------------------------------

pub struct Found {
    pub names: Vec<String>,
    pub truncated: bool,
    pub note: Option<String>,
}

fn fetch_source(app: &App, domain: &str, id: &str, keys: &Keys) -> Result<Found> {
    let u = &app.up;
    let mut note = None;
    let mut truncated = false;
    let raw: Vec<String> = match id {
        "certspotter" => {
            let mut out = Vec::new();
            let pages = if keys.certspotter.is_some() { 10 } else { 3 };
            let mut after: Option<String> = None;
            for page in 0..pages {
                let mut url = format!("{}/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names", u.certspotter);
                if let Some(a) = &after {
                    url.push_str(&format!("&after={a}"));
                }
                let mut r = Req::new(&url).gap(1500).timeout(30);
                if let Some(k) = &keys.certspotter {
                    r = r.header("Authorization", format!("Bearer {k}"));
                }
                let v = match app.http.json(r) {
                    Ok(v) => v,
                    Err(e) if page > 0 => {
                        note = Some(format!("stopped after {page} page(s): {e}"));
                        truncated = true;
                        break;
                    }
                    Err(e) => return Err(e),
                };
                out.extend(parse_certspotter(&v).into_iter().map(str::to_owned));
                let last = v.as_array().and_then(|a| a.last()).and_then(|c| c["id"].as_str()).map(str::to_owned);
                if v.as_array().map(|a| a.len()).unwrap_or(0) < 100 || last.is_none() {
                    break;
                }
                after = last;
                if page + 1 == pages {
                    truncated = true;
                    note = Some(format!("read {pages} pages of 100 issuances; more exist{}", if keys.certspotter.is_none() { " (a key reads more)" } else { "" }));
                }
            }
            out
        }
        "crtsh" => {
            let v = app.http.json(Req::new(&format!("{}/api/certs?name={domain}", u.lookup)).timeout(60)).map_err(|e| anyhow!("the Domain & IP lookup plugin is unavailable or crt.sh failed ({e})"))?;
            v["names"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_owned).collect()
        }
        "mnemonic" => {
            let v = app.http.json(Req::new(&format!("{}/pdns/v3/{domain}?limit=1000", u.mnemonic)).gap(500).timeout(30))?;
            parse_mnemonic(&v).into_iter().map(str::to_owned).collect()
        }
        "urlscan" => {
            let v = app.http.json(Req::new(&format!("{}/api/v1/search/?q=domain:{domain}&size=1000", u.urlscan)).gap(1000).timeout(30))?;
            parse_urlscan(&v).into_iter().map(str::to_owned).collect()
        }
        "wayback" => {
            let v = app.http.json(Req::new(&format!("{}/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=20000", u.wayback)).gap(1000).timeout(50).max_bytes(32 << 20))?;
            if v.as_array().map(|a| a.len()).unwrap_or(0) > 20000 {
                truncated = true;
            }
            parse_wayback(&v).into_iter().map(str::to_owned).collect()
        }
        "hackertarget" => {
            let t = app.http.text(Req::new(&format!("{}/hostsearch/?q={domain}", u.hackertarget)).accept("text/plain").gap(1000))?;
            parse_hackertarget(&t)?.into_iter().map(str::to_owned).collect()
        }
        "otx" => {
            let Some(k) = &keys.otx else { return Err(anyhow!("needs an OTX key (add OTX_API_KEY on the Credentials page)")) };
            let v = app.http.json(Req::new(&format!("{}/api/v1/indicators/domain/{domain}/passive_dns", u.otx)).header("X-OTX-API-KEY", k.clone()).gap(500).timeout(30))?;
            parse_otx(&v).into_iter().map(str::to_owned).collect()
        }
        "virustotal" => {
            let Some(k) = &keys.virustotal else { return Err(anyhow!("needs a VirusTotal key (add VIRUSTOTAL_API_KEY on the Credentials page)")) };
            let mut out = Vec::new();
            let mut cursor: Option<String> = None;
            for page in 0..3 {
                let mut url = format!("{}/api/v3/domains/{domain}/subdomains?limit=40", u.virustotal);
                if let Some(c) = &cursor {
                    url.push_str(&format!("&cursor={c}"));
                }
                let v = app.http.json(Req::new(&url).header("x-apikey", k.clone()).gap(15_500).timeout(30))?;
                out.extend(parse_vt(&v).into_iter().map(str::to_owned));
                cursor = v["meta"]["cursor"].as_str().map(str::to_owned);
                if cursor.is_none() {
                    break;
                }
                if page == 2 {
                    truncated = true;
                    note = Some("first 120 results (free key rate limit)".into());
                }
            }
            out
        }
        _ => return Err(anyhow!("unknown source")),
    };
    let mut names = clean_names(domain, raw.iter().map(String::as_str));
    if names.len() > MAX_NAMES {
        names.truncate(MAX_NAMES);
        truncated = true;
    }
    Ok(Found { names, truncated, note })
}

pub fn source(app: &App, domain: &str, id: &str, keys: &Keys) -> Result<Value> {
    let domain = valid_domain(domain).ok_or_else(|| anyhow!("not a valid domain name"))?;
    if !SOURCES.iter().any(|s| s.id == id) {
        return Err(anyhow!("unknown source"));
    }
    match id {
        "otx" if keys.otx.is_none() => return Err(anyhow!("needs an OTX key (add OTX_API_KEY on the Credentials page)")),
        "virustotal" if keys.virustotal.is_none() => return Err(anyhow!("needs a VirusTotal key (add VIRUSTOTAL_API_KEY on the Credentials page)")),
        _ => {}
    }
    let t0 = std::time::Instant::now();
    let v = app.cache.cached_json_neg(&format!("src:{id}:{domain}"), Duration::from_secs(6 * H), NEG, || {
        let f = fetch_source(app, &domain, id, keys)?;
        Ok(json!({ "names": f.names, "truncated": f.truncated, "note": f.note }))
    })?;
    Ok(json!({ "source": id, "domain": domain, "count": v["names"].as_array().map(|a| a.len()), "names": v["names"], "truncated": v["truncated"], "note": v["note"], "ms": t0.elapsed().as_millis() }))
}

/// Run several sources (in parallel) and merge: every name lists the sources that saw it.
pub fn find(app: &App, domain: &str, ids: &[String], keys: &Keys) -> Result<Value> {
    let domain = valid_domain(domain).ok_or_else(|| anyhow!("not a valid domain name"))?;
    let results = par_map(ids, 4, |id| (id.clone(), source(app, &domain, id, keys)));
    let mut merged: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut per = Vec::new();
    for (id, r) in results {
        match r {
            Ok(v) => {
                for n in v["names"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                    merged.entry(n.to_string()).or_default().push(id.clone());
                }
                per.push(json!({ "source": id, "ok": true, "count": v["count"], "truncated": v["truncated"], "note": v["note"] }));
            }
            Err(e) => per.push(json!({ "source": id, "ok": false, "error": e.to_string() })),
        }
    }
    let total = merged.len();
    let names: Vec<Value> = merged.into_iter().take(MAX_NAMES).map(|(n, s)| json!({ "name": n, "sources": s })).collect();
    Ok(json!({ "domain": domain, "total": total, "names": names, "sources": per }))
}

// ---- DNS liveness ----------------------------------------------------------------------------------------------

const TAKEOVER: [(&str, &str); 14] = [
    (".github.io", "GitHub Pages"), (".herokuapp.com", "Heroku"), (".herokudns.com", "Heroku"), (".s3.amazonaws.com", "Amazon S3"), (".azurewebsites.net", "Azure App Service"),
    (".cloudapp.net", "Azure Cloud Services"), (".trafficmanager.net", "Azure Traffic Manager"), (".blob.core.windows.net", "Azure Blob"), (".netlify.app", "Netlify"),
    (".myshopify.com", "Shopify"), (".surge.sh", "Surge"), (".pantheonsite.io", "Pantheon"), (".elasticbeanstalk.com", "Elastic Beanstalk"), (".ghost.io", "Ghost"),
];

pub fn takeover_hint(target: &str) -> Option<&'static str> {
    let t = target.trim_end_matches('.').to_ascii_lowercase();
    TAKEOVER.iter().find(|(suffix, _)| t.ends_with(suffix)).map(|(_, p)| *p)
}

fn doh(app: &App, name: &str, rtype: &str) -> Result<Value> {
    app.cache.cached_json_neg(&format!("doh:{name}:{rtype}"), Duration::from_secs(600), Duration::from_secs(30), || {
        app.http.json(Req::new(&format!("{}/resolve?name={name}&type={rtype}", app.up.dns)).accept("application/dns-json").gap(40))
    })
}

fn answers(v: &Value, ty: u64) -> Vec<String> {
    v["Answer"].as_array().into_iter().flatten().filter(|a| a["type"].as_u64() == Some(ty)).filter_map(|a| a["data"].as_str()).map(|s| s.trim_end_matches('.').to_string()).collect()
}

/// Classify one name from its A and AAAA answers.
pub fn classify(a: &Value, aaaa: &Value) -> Value {
    let mut ips = answers(a, 1);
    ips.extend(answers(aaaa, 28));
    let cname = answers(a, 5).pop().or_else(|| answers(aaaa, 5).pop());
    let (sa, s6) = (a["Status"].as_u64().unwrap_or(2), aaaa["Status"].as_u64().unwrap_or(2));
    let status = if !ips.is_empty() {
        "live"
    } else if sa == 3 && cname.is_some() {
        "dangling"
    } else if sa == 3 || (sa == 0 && s6 == 3) {
        "dead"
    } else if cname.is_some() && sa == 0 {
        "cname-no-address"
    } else if sa == 0 {
        "no-address"
    } else {
        "error"
    };
    let hint = if status == "dangling" || status == "cname-no-address" { cname.as_deref().and_then(takeover_hint) } else { None };
    json!({ "status": status, "ips": ips, "cname": cname, "takeover_hint": hint })
}

pub fn wildcard(app: &App, domain: &str) -> Value {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(7);
    let probe = format!("osnt-wc-{nanos:08x}.{domain}");
    // Fresh random name each time, so this one answer is never served from a cache.
    match app.http.json(Req::new(&format!("{}/resolve?name={probe}&type=A", app.up.dns)).accept("application/dns-json").gap(40)) {
        Ok(v) => {
            let ips = answers(&v, 1);
            json!({ "checked": true, "wildcard": !ips.is_empty(), "ips": ips })
        }
        Err(e) => json!({ "checked": false, "error": e.to_string() }),
    }
}

pub fn resolve(app: &App, domain: &str, names: &[String]) -> Result<Value> {
    let domain = valid_domain(domain).ok_or_else(|| anyhow!("not a valid domain name"))?;
    let suffix = format!(".{domain}");
    let mut clean = Vec::new();
    for n in names.iter().take(40) {
        let n = valid_found_name(n).ok_or_else(|| anyhow!("{n:?} is not a valid hostname"))?;
        if n != domain && !n.ends_with(&suffix) {
            return Err(anyhow!("{n} is not under {domain}"));
        }
        clean.push(n);
    }
    let wc = wildcard(app, &domain);
    let rows = par_map(&clean, 6, |n| {
        let a = doh(app, n, "A");
        let aaaa = doh(app, n, "AAAA");
        match (a, aaaa) {
            (Ok(a), Ok(b)) => {
                let mut c = classify(&a, &b);
                c["name"] = json!(n);
                c
            }
            (Err(e), _) | (_, Err(e)) => json!({ "name": n, "status": "error", "error": e.to_string(), "ips": [] }),
        }
    });
    Ok(json!({ "domain": domain, "wildcard": wc, "results": rows }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::fake;
    use std::sync::Arc;

    #[test]
    fn name_cleaning_scopes_to_domain_and_drops_junk() {
        let raw = ["WWW.Example.com", "*.api.example.com", "example.com.", "user@example.com", "evil-example.com", "example.com.evil.net", "a b.example.com", "bad..example.com", "_dmarc.example.com", "x.example.org", "sub.example.com"];
        assert_eq!(clean_names("example.com", raw), ["_dmarc.example.com", "api.example.com", "example.com", "sub.example.com", "www.example.com"]);
    }

    #[test]
    fn url_host_extraction() {
        assert_eq!(host_of_url("http://a.example.com:80/x?y"), Some("a.example.com"));
        assert_eq!(host_of_url("https://user:pw@b.example.com/"), Some("b.example.com"));
        assert_eq!(host_of_url("c.example.com/path"), Some("c.example.com"));
    }

    #[test]
    fn parsers() {
        assert_eq!(parse_certspotter(&json!([{"dns_names":["a.example.com","b.example.com"]},{"dns_names":["c.example.com"]}])).len(), 3);
        assert_eq!(parse_hackertarget("www.example.com,1.2.3.4\nmail.example.com,5.6.7.8\n").unwrap(), ["www.example.com", "mail.example.com"]);
        assert!(parse_hackertarget("error check your search parameter").is_err());
        assert!(parse_hackertarget("API count exceeded - Increase Quota with Membership").unwrap_err().to_string().contains("exceeded"));
        assert_eq!(parse_mnemonic(&json!({"data":[{"query":"example.com","answer":"1.2.3.4"},{"query":"x.example.com","answer":"example.com"}]})).len(), 4);
        assert_eq!(parse_urlscan(&json!({"results":[{"page":{"domain":"a.example.com"},"task":{"domain":"b.example.com"}}]})), ["a.example.com", "b.example.com"]);
        assert_eq!(parse_wayback(&json!([["original"],["http://old.example.com/x"],["https://new.example.com:443/"]])), ["old.example.com", "new.example.com"]);
        assert_eq!(parse_otx(&json!({"passive_dns":[{"hostname":"h.example.com","address":"1.2.3.4"}]})).len(), 2);
        assert_eq!(parse_vt(&json!({"data":[{"id":"v.example.com"}]})), ["v.example.com"]);
        assert!(parse_certspotter(&json!({"unexpected":1})).is_empty());
    }

    #[test]
    fn classification() {
        let nx = json!({"Status":3});
        let ok = |ip: &str| json!({"Status":0,"Answer":[{"type":1,"data":ip}]});
        assert_eq!(classify(&ok("1.2.3.4"), &json!({"Status":0}))["status"], "live");
        assert_eq!(classify(&nx, &nx)["status"], "dead");
        let dangling = json!({"Status":3,"Answer":[{"type":5,"data":"old-app.herokuapp.com."}]});
        let c = classify(&dangling, &nx);
        assert_eq!(c["status"], "dangling");
        assert_eq!(c["cname"], "old-app.herokuapp.com");
        assert_eq!(c["takeover_hint"], "Heroku");
        let fine = json!({"Status":0,"Answer":[{"type":5,"data":"x.github.io."},{"type":1,"data":"185.199.108.153"}]});
        let c = classify(&fine, &json!({"Status":0}));
        assert_eq!(c["status"], "live");
        assert!(c["takeover_hint"].is_null(), "a CNAME that resolves is not a takeover candidate");
        assert_eq!(classify(&json!({"Status":0}), &json!({"Status":0}))["status"], "no-address");
        assert_eq!(classify(&json!({"Status":2}), &json!({"Status":2}))["status"], "error");
        assert_eq!(takeover_hint("foo.example.net"), None);
    }

    fn world() -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
        fake::spawn(Arc::new(|p: &str| {
            let j = |s: &str| (200u16, "application/json".to_string(), s.to_string());
            if p.starts_with("/cs/v1/issuances") {
                return if p.contains("after=") { j(r#"[{"id":"3","dns_names":["page2.example.com"]}]"#) } else {
                    // 100 rows so the plugin asks for the next page
                    let rows: Vec<String> = (0..100).map(|i| format!(r#"{{"id":"{}","dns_names":["h{i}.example.com","*.wild.example.com","u@example.com"]}}"#, 1000 + i)).collect();
                    j(&format!("[{}]", rows.join(",")))
                };
            }
            if p.starts_with("/ht/hostsearch") { return (200, "text/plain".into(), "ht.example.com,1.1.1.1\n".into()); }
            if p.starts_with("/mn/pdns/v3/") { return j(r#"{"data":[{"query":"mn.example.com","answer":"1.2.3.4"}]}"#); }
            if p.starts_with("/us/api/v1/search") { return (429, "text/plain".into(), "slow".into()); }
            if p.starts_with("/wb/cdx") { return j(r#"[["original"],["http://old.example.com/a"]]"#); }
            if p.starts_with("/lk/api/certs") { return j(r#"{"names":["ct.example.com","*.ct2.example.com"]}"#); }
            if p.starts_with("/otx/") { return j(r#"{"passive_dns":[{"hostname":"otx.example.com"}]}"#); }
            if p.starts_with("/vt/api/v3/domains/") { return j(r#"{"data":[{"id":"vt.example.com"}],"meta":{}}"#); }
            if p.starts_with("/dns/resolve") {
                let q = p.split("name=").nth(1).unwrap_or("").split('&').next().unwrap_or("");
                let aaaa = p.contains("type=AAAA");
                return match q {
                    n if n.starts_with("osnt-wc-") => j(r#"{"Status":3}"#),
                    "live.example.com" if !aaaa => j(r#"{"Status":0,"Answer":[{"type":1,"data":"9.9.9.9"}]}"#),
                    "dangle.example.com" => j(r#"{"Status":3,"Answer":[{"type":5,"data":"gone.github.io."}]}"#),
                    _ => j(r#"{"Status":3}"#),
                };
            }
            (404, "text/plain".into(), "nf".into())
        }))
    }

    fn app(base: &str) -> App {
        App { http: Http::new("osnt-test/0.1"), cache: Cache::open(None, 200, 1 << 20), up: Up {
            certspotter: format!("{base}/cs"), hackertarget: format!("{base}/ht"), mnemonic: format!("{base}/mn"), urlscan: format!("{base}/us"), wayback: format!("{base}/wb"),
            otx: format!("{base}/otx"), virustotal: format!("{base}/vt"), lookup: format!("{base}/lk"), dns: format!("{base}/dns") } }
    }

    #[test]
    fn find_merges_sources_and_reports_failures() {
        let (base, log) = world();
        let a = app(&base);
        let ids: Vec<String> = ["certspotter", "crtsh", "mnemonic", "urlscan", "wayback"].iter().map(|s| s.to_string()).collect();
        let r = find(&a, "example.com", &ids, &Keys::default()).unwrap();
        let names: Vec<&str> = r["names"].as_array().unwrap().iter().map(|n| n["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"h5.example.com") && names.contains(&"page2.example.com"), "second certspotter page was read");
        assert!(names.contains(&"wild.example.com") && !names.iter().any(|n| n.contains('@')));
        assert!(names.contains(&"ct.example.com") && names.contains(&"ct2.example.com") && names.contains(&"old.example.com") && names.contains(&"mn.example.com"));
        let us = r["sources"].as_array().unwrap().iter().find(|s| s["source"] == "urlscan").unwrap();
        assert_eq!(us["ok"], false);
        assert!(us["error"].as_str().unwrap().contains("rate limited"));
        let mn = r["names"].as_array().unwrap().iter().find(|n| n["name"] == "mn.example.com").unwrap();
        assert_eq!(mn["sources"], json!(["mnemonic"]));
        let n = log.lock().unwrap().len();
        let _ = find(&a, "example.com", &ids, &Keys::default()).unwrap();
        assert_eq!(log.lock().unwrap().len(), n, "sources (including the failed one) are cached");
    }

    #[test]
    fn keyed_sources_need_keys_and_keep_them_out_of_urls() {
        let (base, log) = world();
        let a = app(&base);
        assert!(source(&a, "example.com", "otx", &Keys::default()).unwrap_err().to_string().contains("needs an OTX key"));
        assert!(source(&a, "example.com", "virustotal", &Keys::default()).is_err());
        let keys = Keys { otx: Some("OTXSECRET".into()), virustotal: Some("VTSECRET".into()), certspotter: None };
        assert_eq!(source(&a, "example.com", "otx", &keys).unwrap()["names"], json!(["otx.example.com"]));
        assert_eq!(source(&a, "example.com", "virustotal", &keys).unwrap()["names"], json!(["vt.example.com"]));
        assert!(log.lock().unwrap().iter().all(|p| !p.contains("SECRET")));
        assert_eq!(source(&a, "example.com", "hackertarget", &keys).unwrap()["names"], json!(["ht.example.com"]));
    }

    #[test]
    fn input_validation() {
        let (base, _) = world();
        let a = app(&base);
        assert!(source(&a, "not a domain", "mnemonic", &Keys::default()).is_err());
        assert!(source(&a, "example.com", "nope", &Keys::default()).is_err());
        assert!(source(&a, "1.2.3.4", "mnemonic", &Keys::default()).is_err());
        assert!(resolve(&a, "example.com", &["evil.net".into()]).unwrap_err().to_string().contains("not under"));
        assert!(resolve(&a, "example.com", &["a@example.com".into()]).is_err());
        assert!(resolve(&a, "example.com", &["notexample.com".into()]).is_err(), "suffix must match on a label boundary");
    }

    #[test]
    fn resolve_marks_live_dead_dangling_and_checks_wildcard() {
        let (base, _) = world();
        let a = app(&base);
        let r = resolve(&a, "example.com", &["live.example.com".into(), "dead.example.com".into(), "dangle.example.com".into()]).unwrap();
        let st: Vec<&str> = r["results"].as_array().unwrap().iter().map(|x| x["status"].as_str().unwrap()).collect();
        assert_eq!(st, ["live", "dead", "dangling"]);
        assert_eq!(r["results"][2]["cname"], "gone.github.io");
        assert_eq!(r["results"][2]["takeover_hint"], "GitHub Pages");
        assert_eq!(r["wildcard"]["wildcard"], false);
    }

    #[test]
    fn dead_upstream_is_reported_not_fatal() {
        let a = app("http://127.0.0.1:1");
        let r = resolve(&a, "example.com", &["x.example.com".into()]).unwrap();
        assert_eq!(r["results"][0]["status"], "error");
        assert_eq!(r["wildcard"]["checked"], false);
        let f = find(&a, "example.com", &["mnemonic".into()], &Keys::default()).unwrap();
        assert_eq!(f["sources"][0]["ok"], false);
    }
}

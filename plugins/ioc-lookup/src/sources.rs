//! One function per reputation source. Each returns a self-contained row: a verdict word, a one-line summary,
//! a few facts and a link to the source's own page. Nothing is combined into a score.

use serde_json::{Value, json};

use crate::{AppState, Ind, common::*};

pub struct Hosts {
    pub urlscan: String,
    pub otx: String,
    pub greynoise: String,
    pub mnemonic: String,
    pub internetdb: String,
    pub vt: String,
    pub abuseipdb: String,
}
impl Hosts {
    pub fn real() -> Self {
        Self {
            urlscan: "https://urlscan.io/api/v1".into(),
            otx: "https://otx.alienvault.com/api/v1".into(),
            greynoise: "https://api.greynoise.io/v3/community".into(),
            mnemonic: "https://api.mnemonic.no/pdns/v3".into(),
            internetdb: "https://internetdb.shodan.io".into(),
            vt: "https://www.virustotal.com/api/v3".into(),
            abuseipdb: "https://api.abuseipdb.com/api/v2".into(),
        }
    }
}

pub const SOURCES: [(&str, &str, Option<&str>, &str); 7] = [
    ("urlscan", "urlscan.io", Some("URLSCAN_API_KEY"), "IP, domain, URL, SHA-256"),
    ("otx", "AlienVault OTX", Some("OTX_API_KEY"), "IP, domain, URL, hash"),
    ("greynoise", "GreyNoise Community", Some("GREYNOISE_API_KEY"), "IP"),
    ("mnemonic", "mnemonic passive DNS", None, "IP, domain"),
    ("internetdb", "Shodan InternetDB", None, "IP"),
    ("virustotal", "VirusTotal", Some("VIRUSTOTAL_API_KEY"), "IP, domain, URL, hash (needs key)"),
    ("abuseipdb", "AbuseIPDB", Some("ABUSEIPDB_API_KEY"), "IP (needs key)"),
];

fn row(id: &str, status: &str, summary: impl Into<String>, details: Vec<(&str, String)>, link: Option<String>) -> Value {
    let name = SOURCES.iter().find(|s| s.0 == id).map(|s| s.1).unwrap_or(id);
    json!({ "id": id, "name": name, "status": status, "summary": summary.into(), "details": details.into_iter().filter(|(_, v)| !v.is_empty()).map(|(k, v)| json!([k, v])).collect::<Vec<_>>(), "link": link })
}

fn err_row(id: &str, e: UpErr) -> Value {
    let hint = match e {
        UpErr::Denied(429) => " Try again in a minute, or add an API key on the Credentials page.",
        UpErr::Denied(_) => " The key may be missing, wrong or out of quota.",
        _ => "",
    };
    row(id, "error", format!("{e}.{hint}"), vec![], None)
}

pub fn base64url(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        if c.len() > 1 {
            out.push(T[(n >> 6) as usize & 63] as char);
        }
        if c.len() > 2 {
            out.push(T[n as usize & 63] as char);
        }
    }
    out
}

fn short(s: &str, n: usize) -> String {
    if s.chars().count() > n { format!("{}…", s.chars().take(n).collect::<String>()) } else { s.to_string() }
}

fn strs(v: &Value, n: usize) -> String {
    v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from).or_else(|| x.as_u64().map(|u| u.to_string()))).take(n).collect::<Vec<_>>().join(", ")).unwrap_or_default()
}

pub fn run(s: &AppState, id: &str, ind: &Ind) -> Value {
    match id {
        "urlscan" => urlscan(s, ind),
        "otx" => otx(s, ind),
        "greynoise" => greynoise(s, ind),
        "mnemonic" => mnemonic(s, ind),
        "internetdb" => internetdb(s, ind),
        "virustotal" => virustotal(s, ind),
        "abuseipdb" => abuseipdb(s, ind),
        _ => row(id, "error", "unknown source", vec![], None),
    }
}

fn na(id: &str, why: &str) -> Value {
    row(id, "n/a", why, vec![], None)
}

fn internetdb(s: &AppState, ind: &Ind) -> Value {
    let Ind::Ip(ip) = ind else { return na("internetdb", "InternetDB answers for IP addresses only.") };
    let link = Some(format!("https://www.shodan.io/host/{ip}"));
    match get_json(&s.agent, &format!("{}/{ip}", s.h.internetdb), &[("Accept", "application/json")]) {
        Err(UpErr::NotFound) => row("internetdb", "clear", "No data: Shodan has not indexed open services on this address.", vec![], link),
        Err(e) => err_row("internetdb", e),
        Ok(v) => {
            let vulns = strs(&v["vulns"], 12);
            let tags = strs(&v["tags"], 12);
            let bad_tag = v["tags"].as_array().is_some_and(|t| t.iter().any(|x| matches!(x.as_str(), Some("compromised" | "malware" | "doublepulsar"))));
            let status = if !vulns.is_empty() || bad_tag { "hit" } else { "info" };
            let summary = format!("{} open port(s) seen{}{}", v["ports"].as_array().map(|p| p.len()).unwrap_or(0), if vulns.is_empty() { String::new() } else { format!(", {} known CVE(s)", v["vulns"].as_array().map(|x| x.len()).unwrap_or(0)) }, if tags.is_empty() { String::new() } else { format!(", tags: {tags}") });
            row("internetdb", status, summary, vec![("ports", strs(&v["ports"], 40)), ("hostnames", strs(&v["hostnames"], 8)), ("CVEs", vulns), ("products (CPE)", strs(&v["cpes"], 8))], link)
        }
    }
}

fn greynoise(s: &AppState, ind: &Ind) -> Value {
    let Ind::Ip(ip) = ind else { return na("greynoise", "GreyNoise Community answers for IP addresses only.") };
    let key = s.key("GREYNOISE_API_KEY");
    let mut h = vec![("Accept", "application/json")];
    if let Some(k) = key.as_deref() {
        h.push(("key", k));
    }
    let link = Some(format!("https://viz.greynoise.io/ip/{ip}"));
    match get_json(&s.agent, &format!("{}/{ip}", s.h.greynoise), &h) {
        Err(UpErr::NotFound) => row("greynoise", "clear", "Not observed scanning the internet.", vec![], link),
        Err(e) => err_row("greynoise", e),
        Ok(v) => {
            let class = v["classification"].as_str().unwrap_or("");
            let status = if class == "malicious" { "hit" } else { "info" };
            let summary = match (v["riot"].as_bool().unwrap_or(false), v["noise"].as_bool().unwrap_or(false)) {
                (true, _) => format!("Known common business service ({}).", v["name"].as_str().unwrap_or("RIOT")),
                (_, true) => format!("Seen scanning the internet; classified {}.", if class.is_empty() { "unknown" } else { class }),
                _ => v["message"].as_str().unwrap_or("No classification.").to_string(),
            };
            row("greynoise", status, summary, vec![("classification", class.into()), ("name", v["name"].as_str().unwrap_or("").into()), ("last seen", v["last_seen"].as_str().unwrap_or("").into())], link)
        }
    }
}

fn otx(s: &AppState, ind: &Ind) -> Value {
    let (kind, val) = match ind {
        Ind::Ip(ip) => (if ip.is_ipv6() { "IPv6" } else { "IPv4" }, ip.to_string()),
        Ind::Domain(d) => ("domain", d.clone()),
        Ind::Url(u) => ("url", enc(u)),
        Ind::Hash(h) => ("file", h.clone()),
    };
    let key = s.key("OTX_API_KEY");
    let mut hd = vec![("Accept", "application/json")];
    if let Some(k) = key.as_deref() {
        hd.push(("X-OTX-API-KEY", k));
    }
    let page = match ind {
        Ind::Ip(ip) => format!("https://otx.alienvault.com/indicator/ip/{ip}"),
        Ind::Domain(d) => format!("https://otx.alienvault.com/indicator/domain/{d}"),
        Ind::Url(u) => format!("https://otx.alienvault.com/indicator/url/{}", enc(u)),
        Ind::Hash(h) => format!("https://otx.alienvault.com/indicator/file/{h}"),
    };
    match get_json(&s.agent, &format!("{}/indicators/{kind}/{val}/general", s.h.otx), &hd) {
        Err(UpErr::NotFound) => row("otx", "clear", "Unknown to OTX.", vec![], Some(page)),
        Err(e) => err_row("otx", e),
        Ok(v) => {
            let n = v["pulse_info"]["count"].as_u64().unwrap_or(0);
            let names: Vec<String> = v["pulse_info"]["pulses"].as_array().map(|a| a.iter().filter_map(|p| p["name"].as_str().map(|x| short(x, 80))).take(5).collect()).unwrap_or_default();
            let valid = v["validation"].as_array().map(|a| a.iter().filter_map(|x| x["name"].as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
            let status = if n > 0 { "hit" } else { "clear" };
            let summary = if n > 0 { format!("Appears in {n} community pulse(s). Pulses are user-submitted and vary in quality.") } else { "Not in any OTX pulse.".into() };
            row("otx", status, summary, vec![("pulses", names.join(" · ")), ("validation notes", valid), ("reputation", v["reputation"].as_i64().map(|r| r.to_string()).unwrap_or_default()), ("country", v["country_name"].as_str().unwrap_or("").into()), ("ASN", v["asn"].as_str().unwrap_or("").into())], Some(page))
        }
    }
}

fn urlscan(s: &AppState, ind: &Ind) -> Value {
    let q = match ind {
        Ind::Ip(ip) => format!("ip:\"{ip}\""),
        Ind::Domain(d) => format!("domain:{d}"),
        Ind::Url(u) if !u.contains('"') && !u.contains('\\') => format!("page.url:\"{u}\""),
        Ind::Url(_) => return na("urlscan", "This URL contains characters urlscan search cannot take."),
        Ind::Hash(h) if h.len() == 64 => format!("hash:{h}"),
        Ind::Hash(_) => return na("urlscan", "urlscan search takes SHA-256 hashes only."),
    };
    let key = s.key("URLSCAN_API_KEY");
    let mut hd = vec![("Accept", "application/json")];
    if let Some(k) = key.as_deref() {
        hd.push(("API-Key", k));
    }
    let link = Some(format!("https://urlscan.io/search/#{}", enc(&q)));
    match get_json(&s.agent, &format!("{}/search/?q={}&size=5", s.h.urlscan, enc(&q)), &hd) {
        Err(e) => err_row("urlscan", e),
        Ok(v) => {
            let total = v["total"].as_u64().unwrap_or(0);
            if total == 0 {
                return row("urlscan", "clear", "No public scans found.", vec![], link);
            }
            let scans: Vec<String> = v["results"].as_array().map(|a| a.iter().map(|r| format!("{} {} → {} {}", r["task"]["time"].as_str().unwrap_or("").get(..10).unwrap_or(""), short(r["page"]["domain"].as_str().unwrap_or("?"), 40), r["page"]["ip"].as_str().unwrap_or(""), r["page"]["country"].as_str().unwrap_or(""))).collect()).unwrap_or_default();
            row("urlscan", "info", format!("{total} public scan(s) in urlscan's index (the index records what was scanned, not that it is malicious)."), vec![("latest scans", scans.join(" · "))], link)
        }
    }
}

fn mnemonic(s: &AppState, ind: &Ind) -> Value {
    let x = match ind {
        Ind::Ip(ip) => ip.to_string(),
        Ind::Domain(d) => d.clone(),
        _ => return na("mnemonic", "Passive DNS answers for IP addresses and domains only."),
    };
    let link = Some(format!("https://api.mnemonic.no/pdns/v3/{x}"));
    match get_json(&s.agent, &format!("{}/{x}?limit=50", s.h.mnemonic), &[("Accept", "application/json")]) {
        Err(UpErr::NotFound) => row("mnemonic", "clear", "No passive DNS records.", vec![], link),
        Err(e) => err_row("mnemonic", e),
        Ok(v) => {
            let data = v["data"].as_array().cloned().unwrap_or_default();
            let total = v["count"].as_u64().unwrap_or(data.len() as u64);
            if data.is_empty() {
                return row("mnemonic", "clear", "No passive DNS records.", vec![], link);
            }
            let first = data.iter().filter_map(|d| d["firstSeenTimestamp"].as_u64()).filter(|t| *t > 0).min();
            let last = data.iter().filter_map(|d| d["lastSeenTimestamp"].as_u64()).filter(|t| *t > 0).max();
            let mut seen = vec![];
            for d in &data {
                let a = format!("{} {}", d["rrtype"].as_str().unwrap_or("").to_uppercase(), short(d["answer"].as_str().unwrap_or(""), 60));
                if !seen.contains(&a) {
                    seen.push(a);
                }
            }
            row("mnemonic", "info", format!("{total} passive DNS record(s); history, not a verdict."), vec![("first seen", first.map(|m| ymd(m / 1000)).unwrap_or_default()), ("last seen", last.map(|m| ymd(m / 1000)).unwrap_or_default()), ("sample answers", seen.into_iter().take(8).collect::<Vec<_>>().join(" · "))], link)
        }
    }
}

fn virustotal(s: &AppState, ind: &Ind) -> Value {
    let (path, gui) = match ind {
        Ind::Ip(ip) => (format!("ip_addresses/{ip}"), format!("ip-address/{ip}")),
        Ind::Domain(d) => (format!("domains/{d}"), format!("domain/{d}")),
        Ind::Hash(h) => (format!("files/{h}"), format!("file/{h}")),
        Ind::Url(u) => (format!("urls/{}", base64url(u.as_bytes())), format!("url/{}", base64url(u.as_bytes()))),
    };
    let link = Some(format!("https://www.virustotal.com/gui/{gui}"));
    let Some(key) = s.key("VIRUSTOTAL_API_KEY") else { return row("virustotal", "needs_key", "Add VIRUSTOTAL_API_KEY on the Credentials page to include VirusTotal.", vec![], link) };
    match get_json(&s.agent, &format!("{}/{path}", s.h.vt), &[("x-apikey", &key), ("Accept", "application/json")]) {
        Err(UpErr::NotFound) => row("virustotal", "clear", "Not known to VirusTotal.", vec![], link),
        Err(e) => err_row("virustotal", e),
        Ok(v) => {
            let a = &v["data"]["attributes"];
            let st = &a["last_analysis_stats"];
            let g = |k: &str| st[k].as_u64().unwrap_or(0);
            let (mal, sus) = (g("malicious"), g("suspicious"));
            let total = g("malicious") + g("suspicious") + g("harmless") + g("undetected");
            let status = if mal + sus > 0 { "hit" } else { "clear" };
            row("virustotal", status, format!("{mal} malicious, {sus} suspicious out of {total} engines."), vec![
                ("harmless / undetected", format!("{} / {}", g("harmless"), g("undetected"))), ("community reputation", a["reputation"].as_i64().map(|r| r.to_string()).unwrap_or_default()),
                ("threat label", a["popular_threat_classification"]["suggested_threat_label"].as_str().unwrap_or("").into()), ("file type", a["type_description"].as_str().unwrap_or("").into()),
                ("name", short(a["meaningful_name"].as_str().unwrap_or(""), 80)), ("owner", a["as_owner"].as_str().unwrap_or("").into()),
            ], link)
        }
    }
}

fn abuseipdb(s: &AppState, ind: &Ind) -> Value {
    let Ind::Ip(ip) = ind else { return na("abuseipdb", "AbuseIPDB answers for IP addresses only.") };
    let link = Some(format!("https://www.abuseipdb.com/check/{ip}"));
    let Some(key) = s.key("ABUSEIPDB_API_KEY") else { return row("abuseipdb", "needs_key", "Add ABUSEIPDB_API_KEY on the Credentials page to include AbuseIPDB.", vec![], link) };
    match get_json(&s.agent, &format!("{}/check?ipAddress={ip}&maxAgeInDays=90", s.h.abuseipdb), &[("Key", &key), ("Accept", "application/json")]) {
        Err(e) => err_row("abuseipdb", e),
        Ok(v) => {
            let d = &v["data"];
            let score = d["abuseConfidenceScore"].as_u64().unwrap_or(0);
            let reports = d["totalReports"].as_u64().unwrap_or(0);
            let status = if reports > 0 && score > 0 { "hit" } else { "clear" };
            row("abuseipdb", status, format!("Abuse confidence {score}% from {reports} report(s) in the last 90 days (AbuseIPDB's own score)."), vec![
                ("usage type", d["usageType"].as_str().unwrap_or("").into()), ("ISP", d["isp"].as_str().unwrap_or("").into()), ("domain", d["domain"].as_str().unwrap_or("").into()),
                ("country", d["countryCode"].as_str().unwrap_or("").into()), ("last reported", d["lastReportedAt"].as_str().unwrap_or("").into()), ("allow-listed", if d["isWhitelisted"].as_bool() == Some(true) { "yes".into() } else { String::new() }),
            ], link)
        }
    }
}

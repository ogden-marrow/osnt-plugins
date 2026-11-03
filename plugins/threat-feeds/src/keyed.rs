//! abuse.ch URLhaus, ThreatFox and MalwareBazaar. These need a free Auth-Key; they are queried live (never mirrored).
//! The request shapes follow abuse.ch's published API documentation and have not been exercised with a real key here.

use serde_json::{Value, json};

use crate::{common::*, feeds::Entry};

pub struct Hosts {
    pub urlhaus: String,
    pub threatfox: String,
    pub bazaar: String,
}
impl Hosts {
    pub fn real() -> Self {
        Self { urlhaus: "https://urlhaus-api.abuse.ch/v1".into(), threatfox: "https://threatfox-api.abuse.ch/api/v1/".into(), bazaar: "https://mb-api.abuse.ch/api/v1/".into() }
    }
}

pub const KEYED: [(&str, &str, &str); 3] = [
    ("urlhaus", "URLhaus malware URLs", "https://urlhaus.abuse.ch/"),
    ("threatfox", "ThreatFox IOCs", "https://threatfox.abuse.ch/"),
    ("malwarebazaar", "MalwareBazaar samples", "https://bazaar.abuse.ch/"),
];

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Ip,
    Domain,
    Url,
    Hash(usize),
}

fn post(agent: &ureq::Agent, url: &str, key: &str, ctype: &str, body: String) -> Result<Value, UpErr> {
    let mut res = agent.post(url).header("Auth-Key", key).header("Content-Type", ctype).header("Accept", "application/json").send(body).map_err(|e| match e {
        ureq::Error::StatusCode(c @ (401 | 403 | 429)) => UpErr::Denied(c),
        ureq::Error::StatusCode(c) => UpErr::Status(c),
        _ => UpErr::Other("abuse.ch request failed".into()),
    })?;
    res.body_mut().read_json().map_err(|_| UpErr::Other("abuse.ch returned something that is not JSON".into()))
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs.iter().map(|(k, v)| format!("{}={}", enc(k), enc(v))).collect::<Vec<_>>().join("&")
}

const FORM: &str = "application/x-www-form-urlencoded";

pub fn applies(id: &str, kind: Kind) -> bool {
    match (id, kind) {
        ("urlhaus", Kind::Ip | Kind::Domain | Kind::Url) => true,
        ("urlhaus", Kind::Hash(l)) => l == 32 || l == 64,
        ("threatfox", Kind::Hash(l)) => l == 32 || l == 64,
        ("threatfox", _) => true,
        ("malwarebazaar", Kind::Hash(_)) => true,
        _ => false,
    }
}

/// Returns (count, entries). Not-found answers are Ok((0, [])).
pub fn check(agent: &ureq::Agent, h: &Hosts, id: &str, key: &str, kind: Kind, q: &str) -> Result<(usize, Vec<Entry>), UpErr> {
    match id {
        "urlhaus" => {
            let (path, field) = match kind {
                Kind::Url => ("url/", "url"),
                Kind::Hash(32) => ("payload/", "md5_hash"),
                Kind::Hash(_) => ("payload/", "sha256_hash"),
                _ => ("host/", "host"),
            };
            let v = post(agent, &format!("{}/{path}", h.urlhaus), key, FORM, form(&[(field, q)]))?;
            if v["query_status"] != "ok" {
                return Ok((0, vec![]));
            }
            let link = v["urlhaus_reference"].as_str().map(String::from);
            let mut items = vec![];
            if let Some(urls) = v["urls"].as_array() {
                for u in urls.iter().take(10) {
                    items.push(Entry { indicator: u["url"].as_str().unwrap_or("").chars().take(200).collect(), since: u["date_added"].as_str().map(String::from),
                        detail: format!("{} ({})", u["threat"].as_str().unwrap_or("malware_download"), u["url_status"].as_str().unwrap_or("?")), link: u["urlhaus_link"].as_str().map(String::from), extra: json!({ "tags": u["tags"] }) });
                }
            } else {
                items.push(Entry { indicator: q.into(), since: v["date_added"].as_str().or(v["firstseen"].as_str()).map(String::from), detail: format!("{} {}", v["threat"].as_str().or(v["signature"].as_str()).unwrap_or("listed"), v["url_status"].as_str().or(v["file_type"].as_str()).unwrap_or("")).trim().to_string(), link, extra: json!({ "tags": v["tags"] }) });
            }
            let n = v["urlcount"].as_str().and_then(|s| s.parse().ok()).or(v["urlcount"].as_u64().map(|x| x as usize)).unwrap_or(items.len());
            Ok((n.max(items.len()), items))
        }
        "threatfox" => {
            let v = post(agent, &h.threatfox, key, "application/json", json!({ "query": "search_ioc", "search_term": q }).to_string())?;
            let data = v["data"].as_array().cloned().unwrap_or_default();
            if v["query_status"] != "ok" || data.is_empty() {
                return Ok((0, vec![]));
            }
            let items: Vec<Entry> = data.iter().take(10).map(|d| Entry { indicator: d["ioc"].as_str().unwrap_or(q).into(), since: d["first_seen"].as_str().map(String::from),
                detail: format!("{} / {} (confidence {})", d["malware_printable"].as_str().unwrap_or("?"), d["threat_type"].as_str().unwrap_or("?"), d["confidence_level"]), link: d["id"].as_str().map(|i| format!("https://threatfox.abuse.ch/ioc/{i}/")), extra: json!({ "tags": d["tags"] }) }).collect();
            Ok((data.len(), items))
        }
        "malwarebazaar" => {
            let v = post(agent, &h.bazaar, key, FORM, form(&[("query", "get_info"), ("hash", q)]))?;
            let data = v["data"].as_array().cloned().unwrap_or_default();
            if v["query_status"] != "ok" || data.is_empty() {
                return Ok((0, vec![]));
            }
            let items = data.iter().take(5).map(|d| Entry { indicator: d["sha256_hash"].as_str().unwrap_or(q).into(), since: d["first_seen"].as_str().map(String::from),
                detail: format!("{} {}", d["signature"].as_str().unwrap_or("unclassified"), d["file_type"].as_str().unwrap_or("")).trim().to_string(), link: d["sha256_hash"].as_str().map(|s| format!("https://bazaar.abuse.ch/sample/{s}/")), extra: json!({ "tags": d["tags"] }) }).collect();
            Ok((data.len(), items))
        }
        _ => Err(UpErr::Other("unknown feed".into())),
    }
}

pub fn recent(agent: &ureq::Agent, h: &Hosts, id: &str, key: &str, limit: usize) -> Result<Vec<Entry>, UpErr> {
    match id {
        "urlhaus" => {
            let v = get_json(agent, &format!("{}/urls/recent/limit/{limit}/", h.urlhaus), &[("Auth-Key", key), ("Accept", "application/json")])?;
            Ok(v["urls"].as_array().map(|a| a.iter().take(limit).map(|u| Entry { indicator: u["url"].as_str().unwrap_or("").chars().take(200).collect(), since: u["date_added"].as_str().map(String::from),
                detail: format!("{} ({})", u["threat"].as_str().unwrap_or("malware_download"), u["url_status"].as_str().unwrap_or("?")), link: u["urlhaus_link"].as_str().map(String::from), extra: Value::Null }).collect()).unwrap_or_default())
        }
        "threatfox" => {
            let v = post(agent, &h.threatfox, key, "application/json", json!({ "query": "get_iocs", "days": 1 }).to_string())?;
            Ok(v["data"].as_array().map(|a| a.iter().take(limit).map(|d| Entry { indicator: d["ioc"].as_str().unwrap_or("").into(), since: d["first_seen"].as_str().map(String::from),
                detail: format!("{} / {}", d["malware_printable"].as_str().unwrap_or("?"), d["threat_type"].as_str().unwrap_or("?")), link: d["id"].as_str().map(|i| format!("https://threatfox.abuse.ch/ioc/{i}/")), extra: Value::Null }).collect()).unwrap_or_default())
        }
        "malwarebazaar" => {
            let v = post(agent, &h.bazaar, key, FORM, form(&[("query", "get_recent"), ("selector", "time")]))?;
            Ok(v["data"].as_array().map(|a| a.iter().take(limit).map(|d| Entry { indicator: d["sha256_hash"].as_str().unwrap_or("").into(), since: d["first_seen"].as_str().map(String::from),
                detail: format!("{} {}", d["signature"].as_str().unwrap_or("unclassified"), d["file_type"].as_str().unwrap_or("")).trim().to_string(), link: d["sha256_hash"].as_str().map(|s| format!("https://bazaar.abuse.ch/sample/{s}/")), extra: Value::Null }).collect()).unwrap_or_default())
        }
        _ => Err(UpErr::Other("unknown feed".into())),
    }
}

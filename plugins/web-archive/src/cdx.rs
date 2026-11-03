//! Parsers and validators for Internet Archive CDX and Common Crawl index responses.

use std::collections::BTreeMap;

use serde_json::{Value, json};

/// A target for CDX queries: a URL or a bare host/path. It is only ever passed to the Internet Archive as a query
/// value (never fetched by this plugin), so the checks are about sanity, not SSRF.
pub fn clean_target(raw: &str) -> Result<String, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("enter a URL or domain".into());
    }
    if s.len() > 2000 {
        return Err("URL is too long".into());
    }
    if s.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("URL must not contain spaces or control characters".into());
    }
    if let Some((scheme, _)) = s.split_once("://") {
        if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
            return Err("only http and https URLs can be looked up".into());
        }
    }
    let s = s.split('#').next().unwrap_or(s);
    if s.is_empty() {
        return Err("enter a URL or domain".into());
    }
    Ok(s.to_string())
}

/// A registrable-looking domain for the harvest mode: letters, digits, dots and hyphens, at least one dot.
pub fn clean_domain(raw: &str) -> Result<String, String> {
    let s = raw.trim().trim_start_matches("*.").trim_end_matches('.').to_ascii_lowercase();
    let s = s.strip_prefix("http://").or_else(|| s.strip_prefix("https://")).unwrap_or(&s).split(['/', '?', '#']).next().unwrap_or("").to_string();
    let ok = s.len() <= 253
        && s.contains('.')
        && s.split('.').all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    if ok { Ok(s) } else { Err("enter a domain such as example.com".into()) }
}

/// Wayback timestamp: 4 to 14 digits.
pub fn clean_ts(raw: &str) -> Result<String, String> {
    let s = raw.trim();
    if (4..=14).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit()) { Ok(s.to_string()) } else { Err("timestamp must be 4-14 digits (YYYYMMDDhhmmss)".into()) }
}

pub fn clean_limit(v: Option<usize>, default: usize, max: usize) -> usize {
    v.unwrap_or(default).clamp(1, max)
}

/// `20240102030405` -> `2024-01-02T03:04:05Z` (missing trailing parts default to the start of the period).
pub fn iso(ts: &str) -> String {
    let p = |a: usize, b: usize, d: &str| ts.get(a..b).unwrap_or(d).to_string();
    format!("{}-{}-{}T{}:{}:{}Z", p(0, 4, "0000"), p(4, 6, "01"), p(6, 8, "01"), p(8, 10, "00"), p(10, 12, "00"), p(12, 14, "00"))
}

/// Parse `output=json` CDX rows (header row first) into objects keyed by the header names.
pub fn parse_cdx(body: &str) -> Result<Vec<BTreeMap<String, String>>, String> {
    let t = body.trim();
    if t.is_empty() {
        return Ok(vec![]);
    }
    let v: Value = serde_json::from_str(t).map_err(|_| "the archive returned something that is not CDX JSON".to_string())?;
    let rows = v.as_array().ok_or("unexpected CDX shape")?;
    let Some(head) = rows.first().and_then(|h| h.as_array()) else { return Ok(vec![]) };
    let names: Vec<String> = head.iter().map(|h| h.as_str().unwrap_or("").to_string()).collect();
    Ok(rows
        .iter()
        .skip(1)
        .filter_map(|r| r.as_array())
        .map(|r| names.iter().cloned().zip(r.iter().map(|c| c.as_str().unwrap_or("").to_string())).collect())
        .collect())
}

/// Turn raw snapshot rows into the summary the page and agent tools use: rows with a `changed` flag, first and last
/// seen, a month histogram for the calendar and a status-code histogram.
pub fn summarise_snapshots(rows: &[BTreeMap<String, String>]) -> Value {
    let mut sorted: Vec<&BTreeMap<String, String>> = rows.iter().filter(|r| r.get("timestamp").is_some_and(|t| t.len() >= 8)).collect();
    sorted.sort_by(|a, b| a["timestamp"].cmp(&b["timestamp"]));
    let mut months: BTreeMap<String, (u32, u32)> = BTreeMap::new(); // month -> (captures, content changes)
    let mut statuses: BTreeMap<String, u32> = BTreeMap::new();
    let mut digests = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    let mut prev: Option<&str> = None;
    let mut changes = 0u32;
    for r in &sorted {
        let ts = &r["timestamp"];
        let digest = r.get("digest").map(String::as_str).unwrap_or("");
        let changed = prev.is_some_and(|p| p != digest);
        if changed {
            changes += 1;
        }
        prev = Some(digest);
        digests.insert(digest.to_string());
        let m = months.entry(ts[..6].to_string()).or_default();
        m.0 += 1;
        m.1 += changed as u32;
        *statuses.entry(r.get("statuscode").cloned().unwrap_or_default()).or_default() += 1;
        out.push(json!({
            "timestamp": ts, "time": iso(ts), "url": r.get("original"), "status": r.get("statuscode"), "mime": r.get("mimetype"),
            "digest": digest, "length": r.get("length").and_then(|l| l.parse::<u64>().ok()), "changed": changed,
            "archive_url": format!("https://web.archive.org/web/{ts}/{}", r.get("original").map(String::as_str).unwrap_or("")),
        }));
    }
    json!({
        "count": out.len(),
        "first_seen": sorted.first().map(|r| iso(&r["timestamp"])), "last_seen": sorted.last().map(|r| iso(&r["timestamp"])),
        "distinct_versions": digests.len(), "content_changes": changes,
        "months": months.iter().map(|(m, (c, ch))| json!({ "month": m, "captures": c, "changes": ch })).collect::<Vec<_>>(),
        "statuses": statuses, "snapshots": out,
    })
}

/// Reduce wildcard-harvest rows to unique URLs with per-host counts.
pub fn summarise_urls(rows: &[BTreeMap<String, String>]) -> Value {
    let mut seen = std::collections::BTreeSet::new();
    let mut hosts: BTreeMap<String, u32> = BTreeMap::new();
    let mut urls = Vec::new();
    for r in rows {
        let Some(u) = r.get("original").filter(|u| !u.is_empty()) else { continue };
        if !seen.insert(u.clone()) {
            continue;
        }
        let host = url::Url::parse(u).ok().and_then(|p| p.host_str().map(str::to_string)).unwrap_or_default();
        *hosts.entry(host).or_default() += 1;
        urls.push(json!({ "url": u, "first_seen": r.get("timestamp").map(|t| iso(t)), "mime": r.get("mimetype"), "status": r.get("statuscode") }));
    }
    let mut hv: Vec<_> = hosts.into_iter().collect();
    hv.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    json!({ "count": urls.len(), "hosts": hv.into_iter().take(50).map(|(h, c)| json!({ "host": h, "urls": c })).collect::<Vec<_>>(), "urls": urls })
}

/// Common Crawl collection ids look like `CC-MAIN-2024-33`; anything else is ignored.
pub fn valid_cc_id(id: &str) -> bool {
    let p: Vec<&str> = id.split('-').collect();
    p.len() == 4 && p[0] == "CC" && p[1] == "MAIN" && p[2].len() == 4 && p[3].len() == 2 && p[2].bytes().chain(p[3].bytes()).all(|b| b.is_ascii_digit())
}

/// Newest collection ids from `collinfo.json`, at most `n`.
pub fn newest_collections(info: &Value, n: usize) -> Vec<String> {
    let mut ids: Vec<String> = info.as_array().map(|a| a.iter().filter_map(|c| c["id"].as_str()).filter(|i| valid_cc_id(i)).map(str::to_string).collect()).unwrap_or_default();
    ids.sort();
    ids.reverse();
    ids.truncate(n);
    ids
}

/// Common Crawl index output is newline-delimited JSON objects. A "no captures" answer is a JSON object with `message`.
pub fn parse_cc_lines(body: &str) -> Vec<Value> {
    body.lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v.get("message").is_none() && v.get("url").is_some())
        .map(|v| {
            let ts = v["timestamp"].as_str().unwrap_or("");
            json!({ "url": v["url"], "timestamp": ts, "time": iso(ts), "status": v["status"], "mime": v["mime"], "digest": v["digest"], "warc": v["filename"], "offset": v["offset"], "length": v["length"] })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows() -> Vec<BTreeMap<String, String>> {
        parse_cdx(r#"[["timestamp","original","statuscode","mimetype","digest","length"],
          ["20200101000000","http://a.com/","200","text/html","AAA","10"],
          ["20200115000000","http://a.com/","200","text/html","AAA","10"],
          ["20200201000000","http://a.com/","404","text/html","BBB","12"],
          ["20190101000000","http://a.com/","200","text/html","ZZZ","9"]]"#)
        .unwrap()
    }

    #[test]
    fn parses_cdx_and_handles_empty_and_garbage() {
        assert_eq!(rows().len(), 4);
        assert!(parse_cdx("").unwrap().is_empty());
        assert!(parse_cdx("[]").unwrap().is_empty());
        assert!(parse_cdx("<html>rate limited</html>").is_err());
    }

    #[test]
    fn summary_sorts_flags_changes_and_counts_months() {
        let s = summarise_snapshots(&rows());
        assert_eq!(s["count"], 4);
        assert_eq!(s["first_seen"], "2019-01-01T00:00:00Z");
        assert_eq!(s["last_seen"], "2020-02-01T00:00:00Z");
        assert_eq!(s["distinct_versions"], 3);
        assert_eq!(s["content_changes"], 2); // ZZZ->AAA and AAA->BBB
        assert_eq!(s["snapshots"][0]["changed"], false);
        assert_eq!(s["snapshots"][1]["changed"], true);
        assert_eq!(s["snapshots"][2]["changed"], false);
        let jan = s["months"].as_array().unwrap().iter().find(|m| m["month"] == "202001").unwrap();
        assert_eq!(jan["captures"], 2);
        assert_eq!(s["statuses"]["404"], 1);
        assert_eq!(s["snapshots"][1]["archive_url"], "https://web.archive.org/web/20200101000000/http://a.com/");
    }

    #[test]
    fn target_validation() {
        assert_eq!(clean_target(" https://example.com/a?b=1#frag ").unwrap(), "https://example.com/a?b=1");
        assert!(clean_target("").is_err());
        assert!(clean_target("ftp://example.com").is_err());
        assert!(clean_target("javascript:alert(1)").is_ok()); // not a fetch target; only sent to the archive as a query value
        assert!(clean_target("exa mple.com").is_err());
        assert!(clean_target("a\nb").is_err());
        assert!(clean_target(&"a".repeat(2001)).is_err());
    }

    #[test]
    fn domain_and_timestamp_validation() {
        assert_eq!(clean_domain("https://WWW.Example.com/path").unwrap(), "www.example.com");
        assert_eq!(clean_domain("*.example.org").unwrap(), "example.org");
        assert!(clean_domain("localhost").is_err());
        assert!(clean_domain("exa_mple.com").is_err());
        assert!(clean_domain("-a.com").is_err());
        assert!(clean_ts("2020").is_ok() && clean_ts("20200101123456").is_ok());
        assert!(clean_ts("202").is_err() && clean_ts("2020010112345678").is_err() && clean_ts("20a0").is_err());
        assert_eq!(clean_limit(None, 100, 5000), 100);
        assert_eq!(clean_limit(Some(0), 100, 5000), 1);
        assert_eq!(clean_limit(Some(99999), 100, 5000), 5000);
    }

    #[test]
    fn url_harvest_dedupes_and_counts_hosts() {
        let r = parse_cdx(r#"[["original","timestamp","mimetype","statuscode"],["http://a.com/x","2020","text/html","200"],["http://a.com/x","2021","text/html","200"],["http://b.a.com/y.js","2020","text/javascript","200"]]"#).unwrap();
        let s = summarise_urls(&r);
        assert_eq!(s["count"], 2);
        assert_eq!(s["hosts"][0]["host"], "a.com");
    }

    #[test]
    fn common_crawl_helpers() {
        assert!(valid_cc_id("CC-MAIN-2024-33"));
        assert!(!valid_cc_id("CC-MAIN-2024-3x") && !valid_cc_id("../etc") && !valid_cc_id("CC-NEWS-2024-33"));
        let info = json!([{"id":"CC-MAIN-2023-50"},{"id":"CC-MAIN-2024-33"},{"id":"evil/../x"},{"id":"CC-MAIN-2024-10"}]);
        assert_eq!(newest_collections(&info, 2), vec!["CC-MAIN-2024-33", "CC-MAIN-2024-10"]);
        let lines = "{\"url\":\"http://a.com/\",\"timestamp\":\"20240101000000\",\"status\":\"200\",\"mime\":\"text/html\",\"digest\":\"D\",\"filename\":\"crawl-data/x.warc.gz\",\"offset\":\"1\",\"length\":\"2\"}\nnot json\n{\"message\":\"No Captures found\"}";
        let v = parse_cc_lines(lines);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0]["time"], "2024-01-01T00:00:00Z");
    }
}

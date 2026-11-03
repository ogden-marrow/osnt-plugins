//! Finds coordinates in free text (decimal pairs, DMS with hemispheres, UTM, MGRS, Plus Codes, map-URL fragments).
//! Plain integers, versions and prices are not matched: decimal pairs need three or more decimals unless a hemisphere
//! letter is present. Matches are validated by the same parser as the converter.

use regex::Regex;
use serde_json::{Value, json};

use crate::coords::{self, LL};

pub const MAX_TEXT: usize = 200_000;
pub const MAX_MATCHES: usize = 500;

struct Pat {
    kind: &'static str,
    priority: u8,
    re: Regex,
}

fn patterns() -> Vec<Pat> {
    let hem = r"[NSEW]";
    let dms = r#"\d{1,3}[ \t]*[°º˚][ \t]*(?:\d{1,2}(?:\.\d+)?[ \t]*['′’][ \t]*)?(?:\d{1,2}(?:\.\d+)?[ \t]*(?:["″”]|''|′′|’’)[ \t]*)?"#;
    let dec = r"[-+]?\d{1,3}\.\d+";
    vec![
        Pat { kind: "osm-url", priority: 0, re: Regex::new(r"map=\d{1,2}/-?\d{1,3}\.\d+/-?\d{1,3}\.\d+").unwrap() },
        Pat { kind: "dms", priority: 1, re: Regex::new(&format!(r"(?:{hem}[ \t]*)?{dms}(?:{hem}\b)?(?:[ \t]*[,;/][ \t]*|[ \t]+)(?:{hem}[ \t]*)?{dms}(?:{hem}\b)?")).unwrap() },
        Pat { kind: "decimal", priority: 2, re: Regex::new(&format!(r"{dec}[ \t]*°?[ \t]*(?:{hem}\b)?(?:[ \t]*[,;/][ \t]*|[ \t]+){dec}[ \t]*°?(?:[ \t]*{hem}\b)?")).unwrap() },
        Pat { kind: "utm", priority: 3, re: Regex::new(r"\b\d{1,2}\s?[C-HJ-NP-X]\s+\d{5,7}(?:\.\d+)?[ \t]*(?:m[ \t]*)?E?[ \t,;]+\d{6,8}(?:\.\d+)?[ \t]*(?:m\b)?N?\b").unwrap() },
        Pat { kind: "mgrs", priority: 4, re: Regex::new(r"\b\d{1,2}[C-HJ-NP-X][ ]?[A-HJ-NP-Z]{2}(?:[ ]?\d{2,5}){1,2}\b").unwrap() },
        Pat { kind: "pluscode", priority: 5, re: Regex::new(r"\b[23456789CFGHJMPQRVWX]{8}\+[23456789CFGHJMPQRVWX]{2,7}").unwrap() },
    ]
}

fn decimals_ok(text: &str) -> bool {
    // Every number in a decimal match needs 3+ decimals, unless a hemisphere letter is present.
    if Regex::new(r"\d[ \t]*°?[ \t]*[NSEW]\b").unwrap().is_match(text) {
        return true;
    }
    Regex::new(r"\d+\.(\d+)").unwrap().captures_iter(text).all(|c| c[1].len() >= 3)
}

pub fn scan(text: &str) -> Result<Value, String> {
    if text.len() > MAX_TEXT {
        return Err(format!("text is limited to {} characters", MAX_TEXT));
    }
    let mut cands: Vec<(usize, usize, &'static str, u8, LL)> = vec![];
    for p in patterns() {
        for m in p.re.find_iter(text) {
            let t = m.as_str();
            let parsed = match p.kind {
                "osm-url" => {
                    let nums: Vec<f64> = t.trim_start_matches("map=").split('/').skip(1).filter_map(|x| x.parse().ok()).collect();
                    (nums.len() == 2).then(|| coords::check(nums[0], nums[1]).ok()).flatten().map(|ll| coords::Parsed { ll, kind: "osm-url", bbox: None })
                }
                "decimal" if !decimals_ok(t) => None,
                _ => coords::parse(t.trim(), None, false).ok(),
            };
            if let Some(pr) = parsed {
                // Reject versions like 1.2.3.4 and dotted IPs: a digit or dot touching the match is not a coordinate.
                let before = text[..m.start()].chars().next_back();
                let after = text[m.end()..].chars().next();
                if p.kind == "decimal" && (before.is_some_and(|c| c.is_ascii_digit() || c == '.') || after.is_some_and(|c| c.is_ascii_digit() || c == '.')) {
                    continue;
                }
                cands.push((m.start(), m.end(), p.kind, p.priority, pr.ll));
            }
        }
    }
    cands.sort_by_key(|c| (c.3, c.0));
    let mut taken: Vec<(usize, usize, &'static str, u8, LL)> = vec![];
    for c in cands {
        if taken.iter().all(|t| c.1 <= t.0 || c.0 >= t.1) {
            taken.push(c);
        }
    }
    taken.sort_by_key(|c| c.0);
    let truncated = taken.len() > MAX_MATCHES;
    taken.truncate(MAX_MATCHES);
    let items: Vec<Value> = taken
        .iter()
        .map(|(s, e, kind, _, ll)| {
            let line = text[..*s].matches('\n').count() + 1;
            json!({ "text": text[*s..*e].trim(), "kind": kind, "lat": (ll.lat * 1e7).round() / 1e7, "lon": (ll.lon * 1e7).round() / 1e7, "start": text[..*s].chars().count(), "line": line })
        })
        .collect();
    Ok(json!({ "count": items.len(), "truncated": truncated, "matches": items, "note": "Geohashes and short Plus Codes are not searched for in free text: they look like ordinary words." }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(t: &str) -> Vec<(String, String)> {
        scan(t).unwrap()["matches"].as_array().unwrap().iter().map(|m| (m["kind"].as_str().unwrap().into(), m["text"].as_str().unwrap().into())).collect()
    }

    #[test]
    fn finds_many_kinds_in_one_text() {
        let t = "Photo taken at 48.858370, 2.294481 near the tower.\nAlso 48°51'30\"N 2°17'40\"E and UTM 31U 448251 5411951, MGRS 31UDQ4825011951, code 8FW4V75V+8Q.\nSee https://www.openstreetmap.org/#map=17/48.85837/2.29448";
        let k = kinds(t);
        let kinds_only: Vec<&str> = k.iter().map(|x| x.0.as_str()).collect();
        for want in ["decimal", "dms", "utm", "mgrs", "pluscode", "osm-url"] {
            assert!(kinds_only.contains(&want), "{want} missing in {k:?}");
        }
        let r = scan(t).unwrap();
        assert_eq!(r["matches"][0]["line"], 1);
        assert_eq!(r["matches"][0]["lat"], 48.85837);
        assert_eq!(r["matches"][1]["line"], 2);
    }

    #[test]
    fn ignores_look_alikes() {
        for t in ["version 1.2.3.4 released", "price 12.50, 13.40 each", "ip 192.168.100.200", "call 555 1234, 12 2025", "the year 2024, 12 items", "ratio 3.14 2.71", "section 12.5.3"] {
            assert!(kinds(t).is_empty(), "{t}: {:?}", kinds(t));
        }
    }

    #[test]
    fn rejects_out_of_range_and_limits() {
        assert!(kinds("values 123.456789, 234.567890").is_empty());
        assert!(scan(&"x".repeat(MAX_TEXT + 1)).is_err());
        let many = "10.12345, 20.12345\n".repeat(600);
        let r = scan(&many).unwrap();
        assert_eq!(r["count"], 500);
        assert_eq!(r["truncated"], true);
    }

    #[test]
    fn hemisphere_letters_allow_short_decimals() {
        assert_eq!(kinds("at 48.85 N 2.29 E today").len(), 1);
        assert_eq!(kinds("no hemisphere 48.85 2.29 today").len(), 0);
        assert_eq!(kinds("each 48.85 2.29 near").len(), 0, "letters inside words are not hemispheres");
    }
}

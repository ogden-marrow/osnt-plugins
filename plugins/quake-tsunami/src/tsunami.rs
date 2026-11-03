//! Parser for the tsunami.gov Atom bulletins (PHEBAtom.xml = PTWC Hawaii, PAAQAtom.xml = NTWC Alaska).
//! The files are small and regular, so this reads tags directly instead of pulling in an XML crate.

use serde_json::{Value, json};

use crate::util::{iso, parse_iso};

fn squash(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Text between `<tag ...>` and `</tag>` (first occurrence), whitespace squashed.
fn tag<'a>(s: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}");
    let mut from = 0;
    while let Some(i) = s[from..].find(&open) {
        let i = from + i;
        let after = &s[i + open.len()..];
        if after.starts_with('>') || after.starts_with(' ') {
            let start = i + open.len() + after.find('>')? + 1;
            let end = s[start..].find(&format!("</{name}>"))? + start;
            return Some(&s[start..end]);
        }
        from = i + open.len();
    }
    None
}

/// Value after `<strong>Label:</strong>` up to the next tag.
fn labelled(s: &str, label: &str) -> Option<String> {
    let key = format!("<strong>{label}:</strong>");
    let alt = format!("<strong>{label}: </strong>");
    let i = s.find(&key).map(|i| i + key.len()).or_else(|| s.find(&alt).map(|i| i + alt.len()))?;
    let rest = &s[i..];
    let end = rest.find('<').unwrap_or(rest.len());
    let v = squash(&rest[..end]);
    (!v.is_empty()).then_some(v)
}

fn link_href(entry: &str, rel: &str) -> Option<String> {
    let mut from = 0;
    while let Some(i) = entry[from..].find("<link") {
        let i = from + i;
        let end = entry[i..].find('>')? + i;
        let t = &entry[i..end];
        if t.contains(&format!("rel=\"{rel}\"")) {
            let h = t.find("href=\"")? + 6;
            let e = t[h..].find('"')? + h;
            let url = t[h..e].trim();
            return url.starts_with("https://www.tsunami.gov/").then(|| url.to_string());
        }
        from = end;
    }
    None
}

/// `2026.10.25 02:27:01 UTC` -> unix seconds.
fn parse_issue(s: &str) -> Option<i64> {
    let s = s.trim().trim_end_matches("UTC").trim();
    let (d, t) = s.split_once(' ')?;
    parse_iso(&format!("{}T{}", d.replace('.', "-"), t))
}

fn coord(s: Option<&str>) -> Option<f64> {
    s.and_then(|x| x.trim().parse::<f64>().ok()).filter(|v| v.is_finite())
}

pub fn centre_name(code: &str) -> &'static str {
    match code {
        "PHEB" => "Pacific Tsunami Warning Center (Hawaii)",
        "PAAQ" => "National Tsunami Warning Center (Alaska)",
        _ => "Tsunami warning centre",
    }
}

pub fn parse_atom(xml: &str, centre: &str, now: i64) -> Vec<Value> {
    let mut parts = xml.split("<entry>");
    let head = parts.next().unwrap_or("");
    let statement = tag(head, "title").map(squash);
    parts
        .filter_map(|p| {
            let entry = p.split("</entry>").next()?;
            let region = tag(entry, "title").map(squash).unwrap_or_default();
            let summary = tag(entry, "summary").unwrap_or("");
            let category = labelled(summary, "Category");
            let issued = labelled(summary, "Bulletin Issue Time").and_then(|s| parse_issue(&s)).or_else(|| tag(entry, "updated").and_then(|u| parse_iso(u.trim())))?;
            let age_hours = ((now - issued) as f64 / 360.0).round() / 10.0;
            Some(json!({
                "centre": centre, "centre_name": centre_name(centre), "statement": statement,
                "region": region, "category": category, "magnitude": labelled(summary, "Preliminary Magnitude"),
                "lat": coord(tag(entry, "geo:lat")), "lon": coord(tag(entry, "geo:long")),
                "issued": iso(issued), "issued_ms": issued * 1000, "age_hours": age_hours,
                "current": (0.0..48.0).contains(&age_hours),
                "bulletin_url": link_href(entry, "alternate"), "cap_url": link_href(entry, "related"),
                "note": labelled(summary, "Note"),
            }))
        })
        .collect()
}

//! Event model, parsers for UCDP GED and ACLED, filters and summaries. Pure functions plus a small cache.
//! Events are about places, organisations (armed groups, governments) and counts; free-text narratives that can name
//! individuals (ACLED `notes`, UCDP quoted source text) are never read.

use std::{collections::BTreeMap, sync::Mutex, time::{Duration, Instant}};

use serde::Serialize;
use serde_json::{Value, json};

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Event {
    pub source: &'static str,
    pub id: String,
    pub date: String,
    pub end_date: String,
    pub country: String,
    pub region: String,
    pub admin1: String,
    pub location: String,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub kind: String,
    pub subtype: String,
    pub actors: Vec<String>,
    pub deaths: Option<i64>,
    pub deaths_low: Option<i64>,
    pub deaths_high: Option<i64>,
    pub civilians: Option<i64>,
    pub headline: String,
    pub sources: String,
}

fn s(v: &Value, k: &str, max: usize) -> String {
    let t = match &v[k] {
        Value::String(x) => x.trim().to_string(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    };
    t.chars().filter(|c| !c.is_control()).take(max).collect()
}
fn int(v: &Value, k: &str) -> Option<i64> {
    match &v[k] {
        Value::Number(n) => n.as_i64().or(n.as_f64().map(|f| f as i64)),
        Value::String(x) => x.trim().parse().ok(),
        _ => None,
    }
}
fn float(v: &Value, k: &str) -> Option<f64> {
    match &v[k] {
        Value::Number(n) => n.as_f64(),
        Value::String(x) => x.trim().parse().ok(),
        _ => None,
    }
    .filter(|f| f.is_finite())
}
fn day(x: &str) -> String {
    x.get(..10).filter(|d| d.as_bytes().get(4) == Some(&b'-') && d.as_bytes().get(7) == Some(&b'-')).unwrap_or("").to_string()
}
fn coords(v: &Value) -> (Option<f64>, Option<f64>) {
    match (float(v, "latitude"), float(v, "longitude")) {
        (Some(a), Some(o)) if (-90.0..=90.0).contains(&a) && (-180.0..=180.0).contains(&o) => (Some(a), Some(o)),
        _ => (None, None),
    }
}

pub fn ucdp_kind(code: i64) -> &'static str {
    match code {
        1 => "State-based conflict",
        2 => "Non-state conflict",
        3 => "One-sided violence",
        _ => "Other",
    }
}

/// UCDP GED API page -> (events, total pages).
pub fn parse_ucdp(v: &Value) -> Result<(Vec<Event>, u64), String> {
    let rows = v["Result"].as_array().ok_or("UCDP response had no Result list")?;
    let events = rows
        .iter()
        .filter_map(|r| {
            let id = s(r, "id", 30);
            if id.is_empty() {
                return None;
            }
            let (lat, lon) = coords(r);
            Some(Event {
                source: "ucdp",
                id,
                date: day(&s(r, "date_start", 30)),
                end_date: day(&s(r, "date_end", 30)),
                country: s(r, "country", 80),
                region: s(r, "region", 80),
                admin1: s(r, "adm_1", 100),
                location: s(r, "where_description", 160),
                lat,
                lon,
                kind: ucdp_kind(int(r, "type_of_violence").unwrap_or(0)).into(),
                subtype: s(r, "conflict_name", 120),
                actors: [s(r, "side_a", 120), s(r, "side_b", 120)].into_iter().filter(|a| !a.is_empty()).collect(),
                deaths: int(r, "best"),
                deaths_low: int(r, "low"),
                deaths_high: int(r, "high"),
                civilians: int(r, "deaths_civilians"),
                headline: s(r, "source_headline", 200),
                sources: s(r, "source_article", 160),
            })
        })
        .collect();
    Ok((events, v["TotalPages"].as_u64().unwrap_or(1)))
}

/// ACLED read response -> events, or the API's error message.
pub fn parse_acled(v: &Value) -> Result<Vec<Event>, String> {
    if v["success"] == false || v["status"].as_i64().is_some_and(|s| s >= 400) {
        let msg = v["error"].as_array().and_then(|e| e.first()).and_then(|e| e["message"].as_str()).or(v["error"].as_str()).or(v["message"].as_str()).unwrap_or("request refused");
        return Err(format!("ACLED said: {}", msg.chars().take(160).collect::<String>()));
    }
    let rows = v["data"].as_array().ok_or("ACLED response had no data list")?;
    Ok(rows
        .iter()
        .filter_map(|r| {
            let id = s(r, "event_id_cnty", 30);
            if id.is_empty() {
                return None;
            }
            let (lat, lon) = coords(r);
            let d = day(&s(r, "event_date", 30));
            Some(Event {
                source: "acled",
                id,
                end_date: d.clone(),
                date: d,
                country: s(r, "country", 80),
                region: s(r, "region", 80),
                admin1: s(r, "admin1", 100),
                location: s(r, "location", 160),
                lat,
                lon,
                kind: s(r, "event_type", 80),
                subtype: s(r, "sub_event_type", 80),
                actors: [s(r, "actor1", 120), s(r, "actor2", 120)].into_iter().filter(|a| !a.is_empty()).collect(),
                deaths: int(r, "fatalities"),
                deaths_low: None,
                deaths_high: None,
                civilians: None,
                headline: String::new(),
                sources: s(r, "source", 160),
            })
        })
        .collect())
}

#[derive(Default, Debug)]
pub struct Filter {
    /// lower-case country name fragments; an event matches if its country contains any
    pub countries: Vec<String>,
    /// lower-case event-type fragments
    pub kinds: Vec<String>,
    pub min_deaths: i64,
}

impl Filter {
    pub fn parse(country: &str, kind: &str, min_deaths: Option<i64>) -> Filter {
        let list = |x: &str| x.split(',').map(|t| t.trim().to_lowercase()).filter(|t| !t.is_empty()).take(12).collect::<Vec<_>>();
        Filter { countries: list(country), kinds: list(kind), min_deaths: min_deaths.unwrap_or(0).max(0) }
    }
    pub fn keep(&self, e: &Event) -> bool {
        (self.countries.is_empty() || self.countries.iter().any(|c| e.country.to_lowercase().contains(c.as_str())))
            && (self.kinds.is_empty() || self.kinds.iter().any(|k| e.kind.to_lowercase().contains(k.as_str()) || e.subtype.to_lowercase().contains(k.as_str())))
            && e.deaths.unwrap_or(0) >= self.min_deaths
    }
}

/// Counts and deaths by event type, by month and by country.
pub fn summarise(events: &[Event]) -> Value {
    let mut kinds: BTreeMap<&str, (u64, i64)> = BTreeMap::new();
    let mut months: BTreeMap<&str, (u64, i64)> = BTreeMap::new();
    let mut countries: BTreeMap<&str, (u64, i64)> = BTreeMap::new();
    let mut deaths = 0;
    for e in events {
        let d = e.deaths.unwrap_or(0).max(0);
        deaths += d;
        for (m, k) in [(&mut kinds, e.kind.as_str()), (&mut months, e.date.get(..7).unwrap_or("")), (&mut countries, e.country.as_str())] {
            if !k.is_empty() {
                let x = m.entry(k).or_default();
                x.0 += 1;
                x.1 += d;
            }
        }
    }
    let rows = |m: BTreeMap<&str, (u64, i64)>, sort_by_events: bool, n: usize| {
        let mut v: Vec<_> = m.into_iter().collect();
        if sort_by_events {
            v.sort_by(|a, b| b.1.0.cmp(&a.1.0).then(a.0.cmp(b.0)));
        }
        v.into_iter().take(n).map(|(k, (c, d))| json!({ "name": k, "events": c, "deaths": d })).collect::<Vec<_>>()
    };
    json!({ "events": events.len(), "deaths": deaths, "by_type": rows(kinds, true, 20), "by_month": rows(months, false, 400), "by_country": rows(countries, true, 15) })
}

// ---------------------------------------------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------------------------------------------

pub fn parse_date(s: &str) -> Result<chrono::NaiveDate, String> {
    chrono::NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d").map_err(|_| "dates must look like 2024-03-31".to_string())
}

/// UCDP GED version such as 25.1 or 25.0.4.
pub fn valid_version(v: &str) -> Result<String, String> {
    let v = v.trim();
    let parts: Vec<&str> = v.split('.').collect();
    let ok = (2..=3).contains(&parts.len()) && parts.iter().all(|p| !p.is_empty() && p.len() <= 2 && p.bytes().all(|b| b.is_ascii_digit()));
    if ok { Ok(v.to_string()) } else { Err("dataset version must look like 25.1".into()) }
}

/// A GED version `YY.x` covers events through year 2000+YY-1.
pub fn version_year(v: &str) -> Option<i32> {
    v.split('.').next()?.parse::<i32>().ok().map(|y| 2000 + y - 1)
}

// ---------------------------------------------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------------------------------------------

pub struct Cache {
    max: usize,
    map: Mutex<Vec<(String, Instant, std::sync::Arc<Vec<Event>>, bool)>>,
}
impl Cache {
    pub fn new(max: usize) -> Cache {
        Cache { max, map: Mutex::new(Vec::new()) }
    }
    pub fn get(&self, key: &str, ttl: Duration) -> Option<(std::sync::Arc<Vec<Event>>, bool)> {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|(k, t, _, _)| k == key && t.elapsed() < ttl).map(|(_, _, v, tr)| (v.clone(), *tr))
    }
    pub fn put(&self, key: String, v: std::sync::Arc<Vec<Event>>, truncated: bool) {
        let mut m = self.map.lock().unwrap_or_else(|e| e.into_inner());
        m.retain(|(k, ..)| *k != key);
        while m.len() >= self.max {
            let oldest = m.iter().enumerate().min_by_key(|(_, (_, t, ..))| *t).map(|(i, _)| i).unwrap_or(0);
            m.remove(oldest);
        }
        m.push((key, Instant::now(), v, truncated));
    }
    pub fn len(&self) -> usize {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ucdp() -> Value {
        json!({ "TotalCount": 3, "TotalPages": 2, "Result": [
          { "id": 1, "type_of_violence": 1, "conflict_name": "Government of X - Rebel Y", "side_a": "Government of X", "side_b": "Rebel Y", "country": "X-land", "region": "Africa", "adm_1": "North", "where_description": "Near Town",
            "latitude": 12.5, "longitude": "-3.25", "date_start": "2024-03-01 00:00:00.000", "date_end": "2024-03-02 00:00:00.000", "best": 5, "low": 3, "high": 9, "deaths_civilians": 2,
            "source_headline": "Clashes near Town", "source_article": "Reuters;AFP", "source_original": "SECRET QUOTE naming Mr. Someone" },
          { "id": 2, "type_of_violence": 3, "side_a": "Rebel Y", "side_b": "Civilians", "country": "Y-land", "latitude": 95, "longitude": 10, "date_start": "2024-04-01", "date_end": "2024-04-01", "best": 1 },
          { "type_of_violence": 2, "country": "no id" }] })
    }

    #[test]
    fn ucdp_parsing() {
        let (ev, pages) = parse_ucdp(&ucdp()).unwrap();
        assert_eq!((ev.len(), pages), (2, 2));
        assert_eq!(ev[0].date, "2024-03-01");
        assert_eq!(ev[0].lon, Some(-3.25));
        assert_eq!(ev[0].kind, "State-based conflict");
        assert_eq!(ev[0].actors, vec!["Government of X", "Rebel Y"]);
        assert_eq!((ev[0].deaths, ev[0].civilians), (Some(5), Some(2)));
        assert_eq!(ev[1].lat, None, "out-of-range latitude is dropped");
        assert_eq!(ev[1].kind, "One-sided violence");
        let dump = serde_json::to_string(&ev).unwrap();
        assert!(!dump.contains("SECRET QUOTE"), "free-text quotes are never read");
        assert!(parse_ucdp(&json!({})).is_err());
    }

    #[test]
    fn acled_parsing() {
        let ok = json!({ "status": 200, "success": true, "data": [
          { "event_id_cnty": "NGA1", "event_date": "2024-05-05", "event_type": "Battles", "sub_event_type": "Armed clash", "actor1": "Military Forces of Nigeria", "actor2": "", "country": "Nigeria", "admin1": "Borno", "location": "Maiduguri", "latitude": "11.8", "longitude": "13.1", "fatalities": "4", "source": "Local paper", "notes": "A named person was killed" },
          { "event_date": "2024-05-05" }] });
        let ev = parse_acled(&ok).unwrap();
        assert_eq!(ev.len(), 1);
        assert_eq!((ev[0].deaths, ev[0].lat, ev[0].actors.len()), (Some(4), Some(11.8), 1));
        assert!(!serde_json::to_string(&ev).unwrap().contains("named person"));
        let err = parse_acled(&json!({ "status": 401, "success": false, "error": [{ "message": "Invalid key" }] })).unwrap_err();
        assert!(err.contains("Invalid key"));
        assert!(parse_acled(&json!({ "success": true })).is_err());
    }

    #[test]
    fn filters_and_summary() {
        let (ev, _) = parse_ucdp(&ucdp()).unwrap();
        assert_eq!(ev.iter().filter(|e| Filter::parse("x-land", "", None).keep(e)).count(), 1);
        assert_eq!(ev.iter().filter(|e| Filter::parse("x-land, y-land", "", None).keep(e)).count(), 2);
        assert_eq!(ev.iter().filter(|e| Filter::parse("", "one-sided", None).keep(e)).count(), 1);
        assert_eq!(ev.iter().filter(|e| Filter::parse("", "", Some(3)).keep(e)).count(), 1);
        let sm = summarise(&ev);
        assert_eq!((sm["events"].clone(), sm["deaths"].clone()), (json!(2), json!(6)));
        assert_eq!(sm["by_month"][0]["name"], "2024-03");
        assert_eq!(sm["by_type"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn validation() {
        assert!(parse_date("2024-02-30").is_err());
        assert!(parse_date("2024-02-29").is_ok());
        for ok in ["25.1", "24.0.10"] {
            assert!(valid_version(ok).is_ok());
        }
        for bad in ["", "25", "25.", "a.b", "25.1/../x", "1.2.3.4", "250.1"] {
            assert!(valid_version(bad).is_err(), "{bad}");
        }
        assert_eq!(version_year("25.1"), Some(2024));
    }

    #[test]
    fn cache_ttl_and_cap() {
        let c = Cache::new(2);
        for i in 0..4 {
            c.put(format!("k{i}"), std::sync::Arc::new(vec![]), i == 3);
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(c.len(), 2);
        assert!(c.get("k0", Duration::from_secs(60)).is_none());
        assert_eq!(c.get("k3", Duration::from_secs(60)).unwrap().1, true);
        assert!(c.get("k3", Duration::from_nanos(1)).is_none());
    }
}

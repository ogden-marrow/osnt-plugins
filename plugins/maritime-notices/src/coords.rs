//! Pulls positions out of the free text of a navigational warning and groups them into map shapes.
//! Warnings write positions as `19-23.0N 092-03.1W` (degrees-minutes), `19-23-30N 092-03-06W`, `1923.0N 09203.1W`
//! or decimal degrees. Nothing here is authoritative: it is a reading aid, and the original text is always shown.

use regex::Regex;
use serde::Serialize;
use std::sync::OnceLock;

pub const MAX_SHAPES: usize = 60;
pub const MAX_POINTS: usize = 400;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Shape {
    Point { lat: f64, lon: f64 },
    Line { pts: Vec<[f64; 2]> },
    Polygon { pts: Vec<[f64; 2]> },
    Circle { lat: f64, lon: f64, radius_m: f64 },
}

struct Pos {
    start: usize,
    lat: f64,
    lon: f64,
}

fn dms_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?x)
            (?P<la>\d{1,2})(?:-(?P<lam>\d{2}(?:\.\d+)?)(?:-(?P<las>\d{1,2}(?:\.\d+)?))?|\s?(?P<lam2>\d{2}(?:\.\d+)?))\s?(?P<lah>[NS])\b
            [\s,;/]*(?:AND\s+)?
            (?P<lo>\d{1,3})(?:-(?P<lom>\d{2}(?:\.\d+)?)(?:-(?P<los>\d{1,2}(?:\.\d+)?))?|\s?(?P<lom2>\d{2}(?:\.\d+)?))\s?(?P<loh>[EW])\b",
        )
        .unwrap()
    })
}

fn dec_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?P<la>\d{1,2}\.\d{2,})\s?(?P<lah>[NS])\b[\s,;/]*(?P<lo>\d{1,3}\.\d{2,})\s?(?P<loh>[EW])\b").unwrap())
}

fn num(c: &regex::Captures, k: &str) -> f64 {
    c.name(k).and_then(|m| m.as_str().parse().ok()).unwrap_or(0.0)
}

fn positions(block: &str) -> Vec<Pos> {
    let mut out = Vec::new();
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let glued = |st: usize| block[..st].chars().next_back().is_some_and(|c| c.is_ascii_digit() || c == '.');
    for c in dms_re().captures_iter(block) {
        let m = c.get(0).unwrap();
        // A match that starts mid-number (the tail of a decimal such as 12.345N) is not a position.
        if glued(m.start()) {
            continue;
        }
        let (la, lam, las) = (num(&c, "la"), num(&c, "lam") + num(&c, "lam2"), num(&c, "las"));
        let (lo, lom, los) = (num(&c, "lo"), num(&c, "lom") + num(&c, "lom2"), num(&c, "los"));
        if lam >= 60.0 || las >= 60.0 || lom >= 60.0 || los >= 60.0 {
            continue;
        }
        let mut lat = la + lam / 60.0 + las / 3600.0;
        let mut lon = lo + lom / 60.0 + los / 3600.0;
        if lat > 90.0 || lon > 180.0 {
            continue;
        }
        if &c["lah"] == "S" {
            lat = -lat;
        }
        if &c["loh"] == "W" {
            lon = -lon;
        }
        spans.push((m.start(), m.end()));
        out.push(Pos { start: m.start(), lat, lon });
    }
    for c in dec_re().captures_iter(block) {
        let st = c.get(0).unwrap().start();
        if glued(st) || spans.iter().any(|(a, b)| st >= *a && st < *b) {
            continue;
        }
        let (mut lat, mut lon) = (num(&c, "la"), num(&c, "lo"));
        if lat > 90.0 || lon > 180.0 {
            continue;
        }
        if &c["lah"] == "S" {
            lat = -lat;
        }
        if &c["loh"] == "W" {
            lon = -lon;
        }
        out.push(Pos { start: c.get(0).unwrap().start(), lat, lon });
    }
    out.sort_by_key(|p| p.start);
    out
}

fn round5(v: f64) -> f64 {
    (v * 1e5).round() / 1e5
}

fn blocks(text: &str) -> Vec<String> {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = R.get_or_init(|| Regex::new(r"\n\s*\n|\n\s*\d{1,2}\.\s").unwrap());
    r.split(text).map(str::to_owned).collect()
}

fn circle_radius(before: &str) -> Option<f64> {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = R.get_or_init(|| {
        Regex::new(r"(?is)(?:WITHIN|RADIUS OF)\s+(\d+(?:\.\d+)?)\s*(NM|NAUTICAL\s+MILES?|MILES?|KM|KILOMET(?:ER|RE)S?|MET(?:ER|RE)S?|M)\b[^.]{0,40}?\bOF\s*(?:POSITION\s*)?$").unwrap()
    });
    let c = r.captures(before)?;
    let v: f64 = c[1].parse().ok()?;
    let unit = c[2].to_ascii_uppercase();
    let m = if unit.starts_with("NM") || unit.starts_with("NAUT") || unit.starts_with("MILE") {
        v * 1852.0
    } else if unit.starts_with('K') {
        v * 1000.0
    } else {
        v
    };
    (m > 0.0 && m < 2_000_000.0).then_some(m)
}

fn has(text: &str, words: &[&str]) -> bool {
    let up = text.to_ascii_uppercase();
    words.iter().any(|w| up.contains(w))
}

/// Shapes found in `text`. Heuristic: polygon when the text says "bounded by"/"area" and has 3+ points, a line when it says
/// "along"/"cable"/"between" with 2+, circles for "within N NM of <position>", otherwise individual points.
pub fn extract(text: &str) -> Vec<Shape> {
    // NGA text occasionally has a typo such as `143.46.0E` for `143-46.0E`: a number with two dots is never a valid
    // decimal, and dropping that position would silently shorten a line or polygon.
    static TYPO: OnceLock<Regex> = OnceLock::new();
    let typo = TYPO.get_or_init(|| Regex::new(r"(\d)\.(\d{2}\.\d)").unwrap());
    let fixed = typo.replace_all(text, "$1-$2");
    let text: &str = &fixed;
    let mut shapes = Vec::new();
    let mut total = 0usize;
    for block in blocks(text) {
        let mut ps = positions(&block);
        if ps.is_empty() {
            continue;
        }
        if let Some(first) = ps.first() {
            let before: String = {
                let b = block[..first.start].trim_end();
                b.chars().skip(b.chars().count().saturating_sub(90)).collect()
            };
            if let Some(r) = circle_radius(&before) {
                shapes.push(Shape::Circle { lat: round5(first.lat), lon: round5(first.lon), radius_m: r });
                ps.remove(0);
            }
        }
        // De-duplicate a closing point that repeats the first.
        let mut pts: Vec<[f64; 2]> = ps.iter().map(|p| [round5(p.lat), round5(p.lon)]).collect();
        total += pts.len();
        if total > MAX_POINTS {
            break;
        }
        if pts.len() >= 2 && pts.first() == pts.last() && pts.len() >= 4 {
            pts.pop();
        }
        let polygon_words = ["BOUNDED BY", "BOUNDED", "ENCLOSED", "WITHIN THE AREA", "WITHIN AREA", "AREA DEFINED", "IN AREA", "AREAS:", "AREA:", "HAZARDOUS AREA"];
        let line_words = ["ALONG", "TRACKLINE", "TRACK LINE", "CABLE", "PIPELINE", "ROUTE", "BETWEEN", "TOWING"];
        if pts.len() >= 3 && has(&block, &polygon_words) {
            shapes.push(Shape::Polygon { pts });
        } else if pts.len() >= 2 && has(&block, &line_words) {
            shapes.push(Shape::Line { pts });
        } else {
            for p in pts {
                shapes.push(Shape::Point { lat: p[0], lon: p[1] });
            }
        }
        if shapes.len() >= MAX_SHAPES {
            shapes.truncate(MAX_SHAPES);
            break;
        }
    }
    shapes
}

/// [south, west, north, east] of all shapes, or None.
pub fn bbox(shapes: &[Shape]) -> Option<[f64; 4]> {
    let mut b: Option<[f64; 4]> = None;
    let mut add = |lat: f64, lon: f64| {
        b = Some(match b {
            None => [lat, lon, lat, lon],
            Some([s, w, n, e]) => [s.min(lat), w.min(lon), n.max(lat), e.max(lon)],
        })
    };
    for s in shapes {
        match s {
            Shape::Point { lat, lon } | Shape::Circle { lat, lon, .. } => add(*lat, *lon),
            Shape::Line { pts } | Shape::Polygon { pts } => pts.iter().for_each(|p| add(p[0], p[1])),
        }
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn degrees_minutes_points() {
        let s = extract("A. AGOSTO 12 19-23.0N 092-03.1W.\nB. ARGOS 27-10.4N 090-22.1W.");
        assert_eq!(s.len(), 2);
        match &s[0] {
            Shape::Point { lat, lon } => {
                assert!((lat - 19.38333).abs() < 1e-4);
                assert!((lon + 92.05166).abs() < 1e-4);
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn southern_and_eastern_hemispheres_and_seconds() {
        let p = positions("POSN 33-52-30S 151-12-00E.");
        assert_eq!(p.len(), 1);
        assert!((p[0].lat + 33.875).abs() < 1e-6);
        assert!((p[0].lon - 151.2).abs() < 1e-6);
    }

    #[test]
    fn compact_and_decimal_forms() {
        let p = positions("AT 2823.9N 08437.0W AND 12.345N 045.678E");
        assert_eq!(p.len(), 2);
        assert!((p[0].lat - 28.39833).abs() < 1e-4 && p[0].lon < 0.0);
        assert!((p[1].lat - 12.345).abs() < 1e-9 && (p[1].lon - 45.678).abs() < 1e-9);
    }

    #[test]
    fn polygon_for_bounded_area() {
        let t = "ROCKET LAUNCHING 0100Z TO 0500Z DAILY. HAZARDOUS AREA BOUNDED BY\n28-45.0N 080-30.0W, 28-50.0N 080-10.0W, 28-30.0N 079-50.0W, 28-20.0N 080-20.0W.";
        let s = extract(t);
        assert_eq!(s.len(), 1);
        assert!(matches!(&s[0], Shape::Polygon { pts } if pts.len() == 4));
        let b = bbox(&s).unwrap();
        assert!(b[0] < 28.4 && b[2] > 28.8);
    }

    #[test]
    fn dot_typo_in_degrees_minutes_is_repaired() {
        // Real NGA text (HYDROPAC 1519/24): `143.46.0E` stands for 143-46.0E.
        let sh = extract("ALONG TRACKLINE JOINING\n13-47.5N 143.46.0E, 13-34.2N 144-27.3E,\n13-29.9N 144-45.5E.");
        match &sh[0] {
            Shape::Line { pts } => {
                assert_eq!(pts.len(), 3, "{pts:?}");
                assert!((pts[0][1] - 143.76667).abs() < 1e-4);
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn closing_point_is_dropped() {
        let s = extract("AREA BOUNDED BY 10-00N 010-00E, 10-00N 011-00E, 11-00N 011-00E, 10-00N 010-00E.");
        assert!(matches!(&s[0], Shape::Polygon { pts } if pts.len() == 3));
    }

    #[test]
    fn line_for_cable_and_circle_for_radius() {
        let s = extract("CABLE LAYING ALONG 40-00N 070-00W, 40-30N 069-00W.");
        assert!(matches!(&s[0], Shape::Line { pts } if pts.len() == 2));
        let c = extract("FIRING WITHIN 5 MILES OF 34-30.0N 120-40.0W.");
        match &c[0] {
            Shape::Circle { radius_m, .. } => assert!((radius_m - 9260.0).abs() < 1.0),
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn numbered_items_make_separate_shapes() {
        let s = extract("1. AREA BOUNDED BY 10-00N 010-00E, 10-00N 011-00E, 11-00N 011-00E.\n2. DRIFTING OBJECT 20-00N 030-00E.");
        assert_eq!(s.len(), 2);
        assert!(matches!(s[0], Shape::Polygon { .. }));
        assert!(matches!(s[1], Shape::Point { .. }));
    }

    #[test]
    fn rejects_garbage_and_out_of_range() {
        assert!(extract("NO POSITIONS HERE. 081630Z MAY. NAVAREA IV 517/24.").is_empty());
        assert!(extract("99-99N 200-00E").is_empty());
        assert!(extract("95-00N 010-00E").is_empty());
    }

    #[test]
    fn caps_points() {
        let t: String = (0..500).map(|i| format!("{}. P{} 10-{:02}.0N 010-{:02}.0E\n\n", i, i, i % 59, i % 59)).collect();
        let n = extract(&t).len();
        assert!(n <= MAX_SHAPES);
    }
}

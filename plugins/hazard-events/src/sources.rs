//! Parsers that turn each upstream into the common hazard event shape:
//! `{ id, source, hazard, title, level, score, lat, lon, time, updated, url, summary, extra... }`.

use serde_json::{Value, json};

use crate::util::{iso, parse_iso};

pub const LEVELS: [&str; 4] = ["green", "yellow", "orange", "red"];

pub fn level_rank(l: Option<&str>) -> i32 {
    match l {
        Some("red") => 4,
        Some("orange") => 3,
        Some("yellow") => 2,
        Some("green") => 1,
        _ => 0,
    }
}

fn s(v: &Value) -> Option<&str> {
    v.as_str().map(str::trim).filter(|x| !x.is_empty())
}

fn fnum(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str().and_then(|x| x.trim().parse().ok())).filter(|x| x.is_finite())
}

fn trunc(t: &str, n: usize) -> String {
    let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
    if t.chars().count() <= n { t } else { format!("{}…", t.chars().take(n).collect::<String>().trim_end()) }
}

fn only_host(u: Option<&str>, prefix: &str) -> Option<String> {
    u.filter(|x| x.starts_with(prefix)).map(str::to_string)
}

fn valid_pos(lat: f64, lon: f64) -> bool {
    (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon)
}

// ---- GDACS ------------------------------------------------------------------------------------------------------------

pub fn gdacs_hazard(code: &str) -> &'static str {
    match code {
        "EQ" => "earthquake",
        "TC" => "cyclone",
        "FL" => "flood",
        "VO" => "volcano",
        "WF" => "wildfire",
        "DR" => "drought",
        _ => "other",
    }
}

pub fn gdacs(v: &Value) -> Vec<Value> {
    let feats = v.get("features").and_then(Value::as_array).cloned().unwrap_or_default();
    feats
        .iter()
        .filter_map(|f| {
            let p = f.get("properties")?;
            let ty = s(&p["eventtype"])?;
            let id = p.get("eventid").and_then(|x| x.as_i64().or_else(|| x.as_str().and_then(|y| y.parse().ok())))?;
            let c = f.pointer("/geometry/coordinates")?.as_array()?;
            let (lon, lat) = (fnum(c.first()?)?, fnum(c.get(1)?)?);
            if !valid_pos(lat, lon) {
                return None;
            }
            let level = s(&p["alertlevel"]).map(|l| l.to_ascii_lowercase()).filter(|l| LEVELS.contains(&l.as_str()));
            let start = s(&p["fromdate"]).and_then(parse_iso);
            let upd = s(&p["datemodified"]).and_then(parse_iso);
            let countries: Vec<&str> = p["affectedcountries"].as_array().map(|a| a.iter().filter_map(|c| s(&c["countryname"])).collect()).unwrap_or_default();
            Some(json!({
                "id": format!("gdacs:{ty}:{id}"), "source": "gdacs", "hazard": gdacs_hazard(ty),
                "title": s(&p["name"]).or(s(&p["description"])).unwrap_or("GDACS event"), "level": level, "score": p.get("alertscore").and_then(fnum),
                "lat": lat, "lon": lon, "time": start.map(iso), "updated": upd.map(iso), "current": s(&p["iscurrent"]) == Some("true"),
                "url": only_host(s(&p["url"]["report"]), "https://www.gdacs.org/"),
                "summary": s(&p["htmldescription"]).map(|t| trunc(t, 240)),
                "severity": s(&p["severitydata"]["severitytext"]), "countries": countries,
            }))
        })
        .collect()
}

// ---- NASA EONET -------------------------------------------------------------------------------------------------------

pub fn eonet_hazard(cat: &str) -> &'static str {
    match cat {
        "wildfires" => "wildfire",
        "volcanoes" => "volcano",
        "severeStorms" => "storm",
        "floods" => "flood",
        "drought" => "drought",
        "earthquakes" => "earthquake",
        "seaLakeIce" => "ice",
        "landslides" => "landslide",
        "dustHaze" => "dust",
        _ => "other",
    }
}

fn ring_centroid(ring: &[Value]) -> Option<(f64, f64)> {
    let pts: Vec<(f64, f64)> = ring.iter().filter_map(|p| Some((fnum(p.get(1)?)?, fnum(p.get(0)?)?))).collect();
    if pts.is_empty() {
        return None;
    }
    let n = pts.len() as f64;
    Some((pts.iter().map(|p| p.0).sum::<f64>() / n, pts.iter().map(|p| p.1).sum::<f64>() / n))
}

/// Lat/lon of a GeoJSON Point or Polygon (outer ring centroid).
pub fn geom_point(g: &Value) -> Option<(f64, f64)> {
    let c = g.get("coordinates")?;
    match g.get("type")?.as_str()? {
        "Point" => Some((fnum(c.get(1)?)?, fnum(c.get(0)?)?)),
        "Polygon" => ring_centroid(c.get(0)?.as_array()?),
        "MultiPolygon" => ring_centroid(c.get(0)?.get(0)?.as_array()?),
        _ => None,
    }
}

pub fn eonet(v: &Value) -> Vec<Value> {
    let evs = v.get("events").and_then(Value::as_array).cloned().unwrap_or_default();
    evs.iter()
        .filter_map(|e| {
            let id = s(&e["id"])?;
            let geoms = e.get("geometry")?.as_array()?;
            let last = geoms.last()?;
            let (lat, lon) = geom_point(last).filter(|(a, b)| valid_pos(*a, *b))?;
            let cat = e["categories"][0]["id"].as_str().unwrap_or("");
            let track: Vec<Value> = if geoms.len() > 1 {
                geoms.iter().rev().take(60).filter_map(|g| geom_point(g)).map(|(a, b)| json!([a, b])).collect::<Vec<_>>().into_iter().rev().collect()
            } else {
                vec![]
            };
            let mag = last.get("magnitudeValue").and_then(fnum).map(|m| format!("{m} {}", last["magnitudeUnit"].as_str().unwrap_or("")));
            Some(json!({
                "id": format!("eonet:{id}"), "source": "eonet", "hazard": eonet_hazard(cat), "title": s(&e["title"]).unwrap_or("EONET event"),
                "level": Value::Null, "score": Value::Null, "lat": lat, "lon": lon,
                "time": s(&last["date"]).and_then(parse_iso).map(iso), "updated": Value::Null,
                "url": only_host(s(&e["link"]), "https://eonet.gsfc.nasa.gov/"),
                "summary": s(&e["description"]).map(|t| trunc(t, 240)), "category": e["categories"][0]["title"].as_str(),
                "magnitude": mag.map(|m| m.trim().to_string()), "track": track,
                "sources": e["sources"].as_array().map(|a| a.iter().filter_map(|x| s(&x["url"]).filter(|u| u.starts_with("https://")).map(str::to_string)).take(3).collect::<Vec<_>>()),
            }))
        })
        .collect()
}

// ---- NWS alerts -------------------------------------------------------------------------------------------------------

pub fn nws_level(sev: &str) -> Option<&'static str> {
    match sev {
        "Extreme" => Some("red"),
        "Severe" => Some("orange"),
        "Moderate" => Some("yellow"),
        "Minor" => Some("green"),
        _ => None,
    }
}

/// `fallback` is the queried point (for point queries), used when an alert is zone-based and has no geometry.
pub fn nws(v: &Value, fallback: Option<(f64, f64)>) -> Vec<Value> {
    let feats = v.get("features").and_then(Value::as_array).cloned().unwrap_or_default();
    feats
        .iter()
        .filter_map(|f| {
            let p = f.get("properties")?;
            let id = s(&p["id"]).or(s(&f["id"]))?;
            let pos = f.get("geometry").filter(|g| !g.is_null()).and_then(geom_point).or(fallback);
            let level = nws_level(p["severity"].as_str().unwrap_or(""));
            Some(json!({
                "id": format!("nws:{id}"), "source": "nws", "hazard": "weather-alert", "title": s(&p["event"]).unwrap_or("Weather alert"),
                "level": level, "score": Value::Null, "lat": pos.map(|x| x.0), "lon": pos.map(|x| x.1),
                "time": s(&p["effective"]).and_then(parse_iso).map(iso), "updated": Value::Null, "expires": s(&p["expires"]).and_then(parse_iso).map(iso),
                "url": only_host(s(&p["@id"]).or(s(&f["id"])), "https://api.weather.gov/"),
                "summary": s(&p["headline"]).map(|t| trunc(t, 240)), "area": s(&p["areaDesc"]).map(|t| trunc(t, 200)),
                "severity": s(&p["severity"]), "urgency": s(&p["urgency"]), "certainty": s(&p["certainty"]), "sender": s(&p["senderName"]),
                "instruction": s(&p["instruction"]).map(|t| trunc(t, 400)),
            }))
        })
        .collect()
}

// ---- Smithsonian GVP weekly report -----------------------------------------------------------------------------------

fn decode_entities(t: &str) -> String {
    t.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#39;", "'").replace("&apos;", "'").replace("&amp;", "&")
}

fn strip_tags(t: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in t.chars() {
        match c {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

/// `Thu, 15 Oct 2026 03:11:08 -0400` -> unix seconds.
pub fn parse_rfc2822(t: &str) -> Option<i64> {
    let t = t.trim();
    let t = t.split_once(',').map(|x| x.1).unwrap_or(t).trim();
    let mut it = t.split_whitespace();
    let day: i64 = it.next()?.parse().ok()?;
    let mon = it.next()?;
    let year: i64 = it.next()?.parse().ok()?;
    let time = it.next()?;
    let tz = it.next().unwrap_or("+0000");
    let month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].iter().position(|m| mon.starts_with(m))? as i64 + 1;
    let off = if tz.len() == 5 && (tz.starts_with('+') || tz.starts_with('-')) { format!("{}{}:{}", &tz[..1], &tz[1..3], &tz[3..5]) } else { "Z".to_string() };
    parse_iso(&format!("{year:04}-{month:02}-{day:02}T{time}{off}"))
}

fn tag_text<'a>(s: &'a str, name: &str) -> Option<&'a str> {
    let open = s.find(&format!("<{name}>")).map(|i| i + name.len() + 2).or_else(|| {
        let i = s.find(&format!("<{name} "))?;
        Some(i + s[i..].find('>')? + 1)
    })?;
    let start = open;
    let end = s[start..].find(&format!("</{name}>"))? + start;
    Some(&s[start..end])
}

pub fn gvp(xml: &str) -> Vec<Value> {
    xml.split("<item>")
        .skip(1)
        .filter_map(|it| {
            let it = it.split("</item>").next()?;
            let title = decode_entities(tag_text(it, "title")?.trim());
            let (name_part, rest) = title.split_once(" - ").unwrap_or((&title, ""));
            let kind = rest.rsplit_once(" - ").map(|x| x.1.trim().to_string()).filter(|k| !k.is_empty());
            let pt = tag_text(it, "georss:point")?;
            let mut nums = pt.split_whitespace().filter_map(|x| x.parse::<f64>().ok());
            let (lat, lon) = (nums.next()?, nums.next()?);
            if !valid_pos(lat, lon) {
                return None;
            }
            let guid = tag_text(it, "guid").unwrap_or("");
            let vn: String = guid.rsplit_once("#vn_").map(|x| x.1.chars().take_while(|c| c.is_ascii_digit()).collect()).unwrap_or_default();
            let desc = strip_tags(&decode_entities(tag_text(it, "description").unwrap_or("")));
            let summary = desc.split("Source:").next().unwrap_or(&desc);
            let id_part = if vn.is_empty() { name_part.to_string() } else { vn.clone() };
            Some(json!({
                "id": format!("gvp:{id_part}"), "source": "gvp", "hazard": "volcano", "title": name_part.trim(),
                "level": Value::Null, "score": Value::Null, "lat": lat, "lon": lon,
                "time": tag_text(it, "pubDate").and_then(parse_rfc2822).map(iso), "updated": Value::Null,
                "url": if vn.is_empty() { "https://volcano.si.edu/reports_weekly.cfm".to_string() } else { format!("https://volcano.si.edu/volcano.cfm?vn={vn}") },
                "summary": trunc(summary, 600), "report_type": kind, "report_period": rest.split(" - ").next().map(str::trim).filter(|x| !x.is_empty()),
            }))
        })
        .collect()
}

// ---- USGS HANS elevated volcanoes -------------------------------------------------------------------------------------

pub fn hans(v: &Value) -> Vec<Value> {
    v.as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|e| {
            let (lat, lon) = (fnum(&e["latitude"])?, fnum(&e["longitude"])?);
            if !valid_pos(lat, lon) {
                return None;
            }
            let level = s(&e["color_code"]).map(|c| c.to_ascii_lowercase()).filter(|c| LEVELS.contains(&c.as_str()));
            let vnum = s(&e["vnum"]).unwrap_or("");
            let name = s(&e["volcano_name_appended"])?;
            let url = s(&e["notice_url"]).filter(|u| u.starts_with("https://volcanoes.usgs.gov/")).map(str::to_string).unwrap_or_else(|| "https://volcanoes.usgs.gov/hans-public/".to_string());
            Some(json!({
                "id": format!("hans:{}", if vnum.is_empty() { name } else { vnum }), "source": "hans", "hazard": "volcano", "title": name,
                "level": level, "score": Value::Null, "lat": lat, "lon": lon,
                "time": s(&e["sent_date_cap"]).and_then(parse_iso).map(iso), "updated": Value::Null, "url": url,
                "summary": s(&e["synopsis"]).map(|t| trunc(t, 500)), "alert_level": s(&e["alert_level"]), "observatory": s(&e["obs_fullname"]),
                "elevation_m": e.get("elevation_meters").and_then(fnum),
            }))
        })
        .collect()
}

// ---- NHC active storms -----------------------------------------------------------------------------------------------

fn hemi(v: &Value, neg: char) -> Option<f64> {
    if let Some(x) = fnum(v).filter(|_| v.is_number()) {
        return Some(x);
    }
    let t = v.as_str()?.trim();
    let last = t.chars().last()?;
    let n: f64 = t[..t.len() - last.len_utf8()].trim().parse().ok()?;
    Some(if last.to_ascii_uppercase() == neg || last.to_ascii_uppercase() == (if neg == 'S' { 'W' } else { 'S' }) { -n } else { n })
}

pub fn nhc_class(c: &str) -> &'static str {
    match c {
        "TD" => "Tropical depression",
        "TS" => "Tropical storm",
        "HU" => "Hurricane",
        "STD" => "Subtropical depression",
        "STS" => "Subtropical storm",
        "PTC" => "Post-tropical cyclone",
        "PC" => "Post-tropical cyclone",
        "TY" => "Typhoon",
        _ => "Tropical cyclone",
    }
}

pub fn nhc(v: &Value) -> Vec<Value> {
    v.get("activeStorms")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|st| {
            let lat = fnum(&st["latitudeNumeric"]).or_else(|| hemi(&st["latitude"], 'S'))?;
            let lon = fnum(&st["longitudeNumeric"]).or_else(|| hemi(&st["longitude"], 'W'))?;
            if !valid_pos(lat, lon) {
                return None;
            }
            let id = s(&st["id"])?;
            let class = s(&st["classification"]).unwrap_or("");
            let kt = fnum(&st["intensity"]);
            // Saffir-Simpson style colouring of the level: hurricane = orange, major (>= 96 kt) = red.
            let level = match (class, kt) {
                ("HU" | "TY", Some(k)) if k >= 96.0 => Some("red"),
                ("HU" | "TY", _) => Some("orange"),
                ("TS" | "STS", _) => Some("yellow"),
                _ => Some("green"),
            };
            let adv = ["publicAdvisory", "forecastAdvisory", "forecastDiscussion"].iter().find_map(|k| only_host(s(&st[*k]["url"]), "https://www.nhc.noaa.gov/"));
            Some(json!({
                "id": format!("nhc:{id}"), "source": "nhc", "hazard": "cyclone", "title": format!("{} {}", nhc_class(class), s(&st["name"]).unwrap_or(id)),
                "level": level, "score": Value::Null, "lat": lat, "lon": lon,
                "time": s(&st["lastUpdate"]).and_then(parse_iso).map(iso), "updated": Value::Null,
                "url": adv.unwrap_or_else(|| "https://www.nhc.noaa.gov/".to_string()),
                "summary": format!("{} kt winds{}{}", kt.map(|k| k.to_string()).unwrap_or_else(|| "?".into()), fnum(&st["pressure"]).map(|p| format!(", {p} mb")).unwrap_or_default(),
                                   match (fnum(&st["movementDir"]), fnum(&st["movementSpeed"])) { (Some(d), Some(sp)) => format!(", moving {d:.0}° at {sp:.0} mph"), _ => String::new() }),
                "wind_kt": kt, "classification": class,
            }))
        })
        .collect()
}

// ---- ReliefWeb ----------------------------------------------------------------------------------------------------------

pub fn reliefweb(v: &Value) -> Vec<Value> {
    v.get("data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|d| {
            let f = d.get("fields")?;
            let id = d.get("id").and_then(|x| x.as_i64().or_else(|| x.as_str().and_then(|y| y.parse().ok())))?;
            let names = |k: &str| -> Vec<String> { f[k].as_array().map(|a| a.iter().filter_map(|x| s(&x["name"]).map(str::to_string)).collect()).unwrap_or_default() };
            let status = s(&f["status"]).unwrap_or("");
            Some(json!({
                "id": format!("reliefweb:{id}"), "source": "reliefweb", "hazard": "other", "title": s(&f["name"])?,
                "level": Value::Null, "score": Value::Null, "lat": Value::Null, "lon": Value::Null,
                "time": s(&f["date"]["event"]).or(s(&f["date"]["created"])).and_then(parse_iso).map(iso), "updated": Value::Null,
                "url": only_host(s(&f["url"]), "https://reliefweb.int/"), "summary": format!("{status} · {}", names("type").join(", ")),
                "countries": names("country"), "status": status,
            }))
        })
        .collect()
}

//! FIRMS CSV parsing, regional file selection, clustering and statistics. No I/O here.

use std::collections::HashMap;

use serde_json::{Value, json};

use crate::util::{iso, parse_iso};

#[derive(Clone, Debug, PartialEq)]
pub struct Hotspot {
    pub lat: f64,
    pub lon: f64,
    pub frp: f64,
    pub t: i64,
    pub night: bool,
    /// 0 = low, 1 = nominal, 2 = high
    pub conf: u8,
    pub sat: String,
}

pub struct Region {
    pub key: &'static str,
    pub name: &'static str,
    /// west, south, east, north
    pub bbox: [f64; 4],
}

pub const REGIONS: [Region; 12] = [
    Region { key: "Canada", name: "Canada", bbox: [-141.0, 41.0, -52.0, 84.0] },
    Region { key: "Alaska", name: "Alaska", bbox: [-170.0, 51.0, -129.0, 72.0] },
    Region { key: "USA_contiguous_and_Hawaii", name: "USA (contiguous) and Hawaii", bbox: [-125.0, 24.0, -66.0, 50.0] },
    Region { key: "Central_America", name: "Central America and Caribbean", bbox: [-118.0, 7.0, -58.0, 33.0] },
    Region { key: "South_America", name: "South America", bbox: [-93.0, -56.0, -33.0, 13.0] },
    Region { key: "Europe", name: "Europe", bbox: [-25.0, 34.0, 45.0, 72.0] },
    Region { key: "Northern_and_Central_Africa", name: "Northern and Central Africa", bbox: [-20.0, -5.0, 55.0, 38.0] },
    Region { key: "Southern_Africa", name: "Southern Africa", bbox: [8.0, -36.0, 52.0, -5.0] },
    Region { key: "Russia_Asia", name: "Russia and Asia", bbox: [26.0, 35.0, 180.0, 78.0] },
    Region { key: "South_Asia", name: "South Asia", bbox: [60.0, 5.0, 98.0, 38.0] },
    Region { key: "SouthEast_Asia", name: "South-East Asia", bbox: [92.0, -12.0, 141.0, 29.0] },
    Region { key: "Australia_NewZealand", name: "Australia and New Zealand", bbox: [110.0, -48.0, 180.0, -9.0] },
];

/// Smallest regional file that fully contains the box; `Global` when none does.
pub fn region_for(b: &[f64; 4]) -> &'static str {
    REGIONS
        .iter()
        .filter(|r| b[0] >= r.bbox[0] && b[2] <= r.bbox[2] && b[1] >= r.bbox[1] && b[3] <= r.bbox[3])
        .min_by(|a, c| area(&a.bbox).partial_cmp(&area(&c.bbox)).unwrap_or(std::cmp::Ordering::Equal))
        .map(|r| r.key)
        .unwrap_or("Global")
}

fn area(b: &[f64; 4]) -> f64 {
    (b[2] - b[0]) * (b[3] - b[1])
}

pub struct Sensor {
    pub id: &'static str,
    pub name: &'static str,
    pub dir: &'static str,
    pub prefix: &'static str,
    pub api: &'static str,
}

pub const SENSORS: [Sensor; 3] = [
    Sensor { id: "snpp", name: "VIIRS Suomi NPP (375 m)", dir: "suomi-npp-viirs-c2", prefix: "SUOMI_VIIRS_C2", api: "VIIRS_SNPP_NRT" },
    Sensor { id: "noaa20", name: "VIIRS NOAA-20 (375 m)", dir: "noaa-20-viirs-c2", prefix: "J1_VIIRS_C2", api: "VIIRS_NOAA20_NRT" },
    Sensor { id: "noaa21", name: "VIIRS NOAA-21 (375 m)", dir: "noaa-21-viirs-c2", prefix: "J2_VIIRS_C2", api: "VIIRS_NOAA21_NRT" },
];

pub fn sensor(id: &str) -> Option<&'static Sensor> {
    SENSORS.iter().find(|s| s.id == id)
}

pub fn conf_rank(s: &str) -> Option<u8> {
    match s.trim().to_ascii_lowercase().as_str() {
        "l" | "low" => Some(0),
        "n" | "nominal" => Some(1),
        "h" | "high" => Some(2),
        _ => None,
    }
}

pub fn conf_name(c: u8) -> &'static str {
    ["low", "nominal", "high"][c.min(2) as usize]
}

/// Parses a FIRMS VIIRS CSV body. Rows outside `bbox` are skipped while reading. Returns an error for anything that is
/// not a FIRMS CSV (the API answers HTTP 200 with a text message such as an invalid-key notice).
pub fn parse_csv(body: &str, bbox: &[f64; 4], max_rows: usize) -> Result<(Vec<Hotspot>, bool), String> {
    let mut lines = body.lines();
    let head = lines.next().unwrap_or("");
    let head = head.trim_start_matches('\u{feff}');
    // The area API's CSV may carry a leading country_id column; the invalid-key / rate-limit replies are plain text.
    if !(head.contains("latitude,") && head.contains("longitude,") && head.contains("acq_date")) {
        return Err("the fire data service did not return a data file (it may be rejecting the request or the key)".into());
    }
    let cols: HashMap<&str, usize> = head.split(',').enumerate().map(|(i, c)| (c.trim(), i)).collect();
    let need = |n: &str| cols.get(n).copied().ok_or_else(|| format!("the fire data file has no '{n}' column"));
    let (ilat, ilon, idate, itime, ifrp) = (need("latitude")?, need("longitude")?, need("acq_date")?, need("acq_time")?, need("frp")?);
    let (idn, iconf, isat) = (cols.get("daynight").copied(), cols.get("confidence").copied(), cols.get("satellite").copied());
    let mut out = Vec::new();
    let mut truncated = false;
    for line in lines {
        let f: Vec<&str> = line.split(',').collect();
        let get = |i: usize| f.get(i).copied().unwrap_or("");
        let (Ok(lat), Ok(lon)) = (get(ilat).parse::<f64>(), get(ilon).parse::<f64>()) else { continue };
        if lat < bbox[1] || lat > bbox[3] || lon < bbox[0] || lon > bbox[2] {
            continue;
        }
        let time = format!("{:0>4}", get(itime));
        let Some(t) = parse_iso(&format!("{}T{}:{}:00Z", get(idate), &time[..2], &time[2..4])) else { continue };
        if out.len() >= max_rows {
            truncated = true;
            break;
        }
        out.push(Hotspot {
            lat,
            lon,
            frp: get(ifrp).parse::<f64>().ok().filter(|x| x.is_finite() && *x >= 0.0).unwrap_or(0.0),
            t,
            night: idn.map(|i| get(i) == "N").unwrap_or(false),
            conf: iconf.and_then(|i| conf_rank(get(i))).unwrap_or(1),
            sat: isat.map(|i| get(i).to_string()).unwrap_or_default(),
        });
    }
    Ok((out, truncated))
}

pub fn haversine_km(a: (f64, f64), b: (f64, f64)) -> f64 {
    let (la1, la2) = (a.0.to_radians(), b.0.to_radians());
    let h = ((b.0 - a.0).to_radians() / 2.0).sin().powi(2) + la1.cos() * la2.cos() * ((b.1 - a.1).to_radians() / 2.0).sin().powi(2);
    2.0 * 6371.0088 * h.sqrt().asin()
}

#[derive(Clone, Debug)]
pub struct Cluster {
    pub lat: f64,
    pub lon: f64,
    pub count: usize,
    pub frp_total: f64,
    pub frp_max: f64,
    pub first: i64,
    pub last: i64,
    pub night: usize,
    pub radius_km: f64,
    pub conf_high: usize,
}

impl Cluster {
    pub fn id(&self) -> String {
        format!("{:+.2},{:+.2}", self.lat, self.lon)
    }
    pub fn to_json(&self) -> Value {
        json!({ "id": self.id(), "lat": round(self.lat, 4), "lon": round(self.lon, 4), "count": self.count, "frp_total": round(self.frp_total, 1), "frp_max": round(self.frp_max, 1),
                "first": iso(self.first), "last": iso(self.last), "night": self.night, "day": self.count - self.night, "radius_km": round(self.radius_km, 2), "high_confidence": self.conf_high })
    }
}

pub fn round(x: f64, d: i32) -> f64 {
    let m = 10f64.powi(d);
    let r = (x * m).round() / m;
    if r == 0.0 { 0.0 } else { r } // never -0.0
}

fn find(p: &mut [usize], mut x: usize) -> usize {
    while p[x] != x {
        p[x] = p[p[x]];
        x = p[x];
    }
    x
}

/// Single-linkage clustering: detections within `eps_km` of each other join one fire event. A spatial grid keeps it near linear.
pub fn cluster(points: &[Hotspot], eps_km: f64) -> Vec<Cluster> {
    let n = points.len();
    let cell = (eps_km / 111.195).max(1e-4);
    // Rows of constant latitude; within a row the longitude step is widened by 1/cos(lat) so cells stay about eps wide.
    let step = |row: i64| cell / (((row as f64 + 0.5) * cell).to_radians().cos().max(0.05));
    let key = |p: &Hotspot| {
        let row = (p.lat / cell).floor() as i64;
        (row, (p.lon / step(row)).floor() as i64)
    };
    let mut grid: HashMap<(i64, i64), Vec<usize>> = HashMap::new();
    for (i, p) in points.iter().enumerate() {
        grid.entry(key(p)).or_default().push(i);
    }
    let mut parent: Vec<usize> = (0..n).collect();
    for (i, p) in points.iter().enumerate() {
        let (cy, _) = key(p);
        for dy in -1..=1 {
            let row = cy + dy;
            let cx = (p.lon / step(row)).floor() as i64;
            for dx in -2..=2 {
                if let Some(v) = grid.get(&(row, cx + dx)) {
                    for &j in v {
                        if j > i && haversine_km((p.lat, p.lon), (points[j].lat, points[j].lon)) <= eps_km {
                            let (a, b) = (find(&mut parent, i), find(&mut parent, j));
                            if a != b {
                                parent[a] = b;
                            }
                        }
                    }
                }
            }
        }
    }
    let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in 0..n {
        let r = find(&mut parent, i);
        groups.entry(r).or_default().push(i);
    }
    let mut out: Vec<Cluster> = groups
        .values()
        .map(|g| {
            let pts: Vec<&Hotspot> = g.iter().map(|&i| &points[i]).collect();
            let w: f64 = pts.iter().map(|p| p.frp.max(0.1)).sum();
            let lat = pts.iter().map(|p| p.lat * p.frp.max(0.1)).sum::<f64>() / w;
            let lon = pts.iter().map(|p| p.lon * p.frp.max(0.1)).sum::<f64>() / w;
            Cluster {
                lat,
                lon,
                count: pts.len(),
                frp_total: pts.iter().map(|p| p.frp).sum(),
                frp_max: pts.iter().map(|p| p.frp).fold(0.0, f64::max),
                first: pts.iter().map(|p| p.t).min().unwrap_or(0),
                last: pts.iter().map(|p| p.t).max().unwrap_or(0),
                night: pts.iter().filter(|p| p.night).count(),
                radius_km: pts.iter().map(|p| haversine_km((lat, lon), (p.lat, p.lon))).fold(0.0, f64::max),
                conf_high: pts.iter().filter(|p| p.conf == 2).count(),
            }
        })
        .collect();
    out.sort_by(|a, b| b.frp_total.partial_cmp(&a.frp_total).unwrap_or(std::cmp::Ordering::Equal).then(b.count.cmp(&a.count)));
    out
}

/// Totals, day/night split, confidence mix and a per-day timeline (UTC acquisition date).
pub fn stats(points: &[Hotspot], clusters: &[Cluster]) -> Value {
    let mut days: std::collections::BTreeMap<String, (usize, f64)> = Default::default();
    let mut conf = [0usize; 3];
    for p in points {
        let d = days.entry(crate::util::ymd(p.t)).or_default();
        d.0 += 1;
        d.1 += p.frp;
        conf[p.conf.min(2) as usize] += 1;
    }
    let night = points.iter().filter(|p| p.night).count();
    let total_frp: f64 = points.iter().map(|p| p.frp).sum();
    json!({
        "detections": points.len(), "clusters": clusters.len(), "frp_total_mw": round(total_frp, 1),
        "frp_max_mw": round(points.iter().map(|p| p.frp).fold(0.0, f64::max), 1),
        "frp_mean_mw": if points.is_empty() { 0.0 } else { round(total_frp / points.len() as f64, 2) },
        "day": points.len() - night, "night": night,
        "confidence": { "low": conf[0], "nominal": conf[1], "high": conf[2] },
        "timeline": days.into_iter().map(|(d, (c, f))| json!({ "date": d, "detections": c, "frp_mw": round(f, 1) })).collect::<Vec<_>>(),
        "largest_clusters_by_count": clusters.iter().map(|c| c.count).max().unwrap_or(0),
    })
}

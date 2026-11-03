//! AIS data model, identifier validation, decoders for the two feeds, and the bounded in-memory store.
//! Everything here is about vessels as objects. There is no owner or crew data anywhere in this plugin.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use serde_json::Value;

pub const MAX_VESSELS: usize = 8000;
pub const MAX_INFO: usize = 25_000;
pub const TRACK_POINTS: usize = 120;
pub const TRACK_WINDOW_MS: i64 = 6 * 3600 * 1000;
/// Minimum spacing between stored track points for one vessel.
pub const TRACK_GAP_MS: i64 = 20_000;

#[derive(Clone, Debug, PartialEq)]
pub struct Pos {
    pub mmsi: u32,
    pub lat: f64,
    pub lon: f64,
    pub sog: Option<f64>,
    pub cog: Option<f64>,
    pub heading: Option<u16>,
    pub nav: Option<u8>,
    /// position time, unix milliseconds
    pub ts: i64,
    pub src: &'static str,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Info {
    pub name: Option<String>,
    pub call_sign: Option<String>,
    pub imo: Option<u32>,
    pub ship_type: Option<u8>,
    pub destination: Option<String>,
    pub eta: Option<String>,
    pub draught_m: Option<f64>,
    pub length_m: Option<u32>,
    pub beam_m: Option<u32>,
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

// ---------- identifiers ----------

/// MMSI: exactly nine digits (leading zeros allowed for coast stations and groups).
pub fn parse_mmsi(s: &str) -> Option<u32> {
    let t = s.trim();
    (t.len() == 9 && t.bytes().all(|b| b.is_ascii_digit())).then(|| t.parse().ok()).flatten()
}

/// IMO number: seven digits whose weighted checksum matches the last digit. "IMO 9606900" is accepted.
pub fn parse_imo(s: &str) -> Option<u32> {
    let t = s.trim().to_ascii_uppercase();
    let t = t.strip_prefix("IMO").unwrap_or(&t).trim();
    if t.len() != 7 || !t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let d: Vec<u32> = t.bytes().map(|b| (b - b'0') as u32).collect();
    let sum: u32 = d[..6].iter().enumerate().map(|(i, v)| v * (7 - i as u32)).sum();
    (sum % 10 == d[6]).then(|| t.parse().ok()).flatten()
}

/// What kind of station an MMSI belongs to (ITU-R M.585).
pub fn mmsi_kind(mmsi: u32) -> &'static str {
    match mmsi {
        0..=9_999_999 => "coast station",
        10_000_000..=99_999_999 => "group call",
        _ => match mmsi / 1_000_000 {
            111 => "SAR aircraft",
            970 => "AIS-SART",
            972 => "man overboard device",
            974 => "EPIRB-AIS",
            m if (990..=999).contains(&m) => "aid to navigation",
            m if (980..=989).contains(&m) => "craft tied to a parent ship",
            m if (200..=799).contains(&m) => "ship",
            _ => "other",
        },
    }
}

/// Flag state from the MMSI's Maritime Identification Digits. It says where the radio was registered, which can
/// differ from the vessel's owner country or the flag on paper.
pub fn flag_iso(mmsi: u32) -> Option<&'static str> {
    if !(200_000_000..800_000_000).contains(&mmsi) {
        return None;
    }
    let mid = (mmsi / 1_000_000) as u16;
    MID.binary_search_by_key(&mid, |e| e.0).ok().map(|i| MID[i].1)
}

const MID: &[(u16, &str)] = &[
    (201, "AL"), (202, "AD"), (203, "AT"), (204, "PT"), (205, "BE"), (206, "BY"), (207, "BG"), (208, "VA"), (209, "CY"), (210, "CY"), (211, "DE"), (212, "CY"), (213, "GE"),
    (214, "MD"), (215, "MT"), (216, "AM"), (218, "DE"), (219, "DK"), (220, "DK"), (224, "ES"), (225, "ES"), (226, "FR"), (227, "FR"), (228, "FR"), (229, "MT"), (230, "FI"),
    (231, "FO"), (232, "GB"), (233, "GB"), (234, "GB"), (235, "GB"), (236, "GI"), (237, "GR"), (238, "HR"), (239, "GR"), (240, "GR"), (241, "GR"), (242, "MA"), (243, "HU"),
    (244, "NL"), (245, "NL"), (246, "NL"), (247, "IT"), (248, "MT"), (249, "MT"), (250, "IE"), (251, "IS"), (252, "LI"), (253, "LU"), (254, "MC"), (255, "PT"), (256, "MT"),
    (257, "NO"), (258, "NO"), (259, "NO"), (261, "PL"), (262, "ME"), (263, "PT"), (264, "RO"), (265, "SE"), (266, "SE"), (267, "SK"), (268, "SM"), (269, "CH"), (270, "CZ"),
    (271, "TR"), (272, "UA"), (273, "RU"), (274, "MK"), (275, "LV"), (276, "EE"), (277, "LT"), (278, "SI"), (279, "RS"), (301, "AI"), (303, "US"), (304, "AG"), (305, "AG"),
    (306, "CW"), (307, "AW"), (308, "BS"), (309, "BS"), (310, "BM"), (311, "BS"), (312, "BZ"), (314, "BB"), (316, "CA"), (319, "KY"), (321, "CR"), (323, "CU"), (325, "DM"),
    (327, "DO"), (329, "GP"), (330, "GD"), (331, "GL"), (332, "GT"), (334, "HN"), (336, "HT"), (338, "US"), (339, "JM"), (341, "KN"), (343, "LC"), (345, "MX"), (347, "MQ"),
    (348, "MS"), (350, "NI"), (351, "PA"), (352, "PA"), (353, "PA"), (354, "PA"), (355, "PA"), (356, "PA"), (357, "PA"), (358, "PR"), (359, "SV"), (361, "PM"), (362, "TT"),
    (364, "TC"), (366, "US"), (367, "US"), (368, "US"), (369, "US"), (370, "PA"), (371, "PA"), (372, "PA"), (373, "PA"), (374, "PA"), (375, "VC"), (376, "VC"), (377, "VC"),
    (378, "VG"), (379, "VI"), (401, "AF"), (403, "SA"), (405, "BD"), (408, "BH"), (410, "BT"), (412, "CN"), (413, "CN"), (414, "CN"), (416, "TW"), (417, "LK"), (419, "IN"),
    (422, "IR"), (423, "AZ"), (425, "IQ"), (428, "IL"), (431, "JP"), (432, "JP"), (434, "TM"), (436, "KZ"), (437, "UZ"), (438, "JO"), (440, "KR"), (441, "KR"), (443, "PS"),
    (445, "KP"), (447, "KW"), (450, "LB"), (451, "KG"), (453, "MO"), (455, "MV"), (457, "MN"), (459, "NP"), (461, "OM"), (463, "PK"), (466, "QA"), (468, "SY"), (470, "AE"),
    (471, "AE"), (472, "TJ"), (473, "YE"), (475, "YE"), (477, "HK"), (478, "BA"), (501, "TF"), (503, "AU"), (506, "MM"), (508, "BN"), (510, "FM"), (511, "PW"), (512, "NZ"),
    (514, "KH"), (515, "KH"), (516, "CX"), (518, "CK"), (520, "FJ"), (523, "CC"), (525, "ID"), (529, "KI"), (531, "LA"), (533, "MY"), (536, "MP"), (538, "MH"), (540, "NC"),
    (542, "NU"), (544, "NR"), (546, "PF"), (548, "PH"), (553, "PG"), (555, "PN"), (557, "SB"), (559, "AS"), (561, "WS"), (563, "SG"), (564, "SG"), (565, "SG"), (566, "SG"),
    (567, "TH"), (570, "TO"), (572, "TV"), (574, "VN"), (576, "VU"), (577, "VU"), (578, "WF"), (601, "ZA"), (603, "AO"), (605, "DZ"), (607, "TF"), (608, "AC"), (609, "BI"),
    (610, "BJ"), (611, "BW"), (612, "CF"), (613, "CM"), (615, "CG"), (616, "KM"), (617, "CV"), (618, "TF"), (619, "CI"), (620, "KM"), (621, "DJ"), (622, "EG"), (624, "ET"),
    (625, "ER"), (626, "GA"), (627, "GH"), (629, "GM"), (630, "GW"), (631, "GQ"), (632, "GN"), (633, "BF"), (634, "KE"), (635, "TF"), (636, "LR"), (637, "LR"), (638, "SS"),
    (642, "LY"), (644, "LS"), (645, "MU"), (647, "MG"), (649, "ML"), (650, "MZ"), (654, "MR"), (655, "MW"), (656, "NE"), (657, "NG"), (659, "NA"), (660, "RE"), (661, "RW"),
    (662, "SD"), (663, "SN"), (664, "SC"), (665, "SH"), (666, "SO"), (667, "SL"), (668, "ST"), (669, "SZ"), (670, "TD"), (671, "TG"), (672, "TN"), (674, "TZ"), (675, "TZ"),
    (676, "CD"), (677, "TZ"), (678, "ZM"), (679, "ZW"), (701, "AR"), (710, "BR"), (720, "BO"), (725, "CL"), (730, "CO"), (735, "EC"), (740, "FK"), (745, "GF"), (750, "GY"),
    (755, "PY"), (760, "PE"), (765, "SR"), (770, "UY"), (775, "VE"),
];

pub fn ship_type_label(t: u8) -> &'static str {
    match t {
        20..=29 => "Wing in ground",
        30 => "Fishing",
        31 | 32 => "Towing",
        33 => "Dredging or underwater work",
        34 => "Diving operations",
        35 => "Military",
        36 => "Sailing",
        37 => "Pleasure craft",
        40..=49 => "High-speed craft",
        50 => "Pilot vessel",
        51 => "Search and rescue",
        52 => "Tug",
        53 => "Port tender",
        54 => "Anti-pollution",
        55 => "Law enforcement",
        58 => "Medical transport",
        59 => "Special craft",
        60..=69 => "Passenger",
        70..=79 => "Cargo",
        80..=89 => "Tanker",
        90..=99 => "Other",
        _ => "Unknown",
    }
}

/// Coarse class used for map colours.
pub fn ship_class(t: Option<u8>) -> &'static str {
    match t {
        Some(30) => "fishing",
        Some(60..=69) => "passenger",
        Some(70..=79) => "cargo",
        Some(80..=89) => "tanker",
        Some(36) | Some(37) => "pleasure",
        Some(31..=35) | Some(50..=59) => "service",
        Some(_) => "other",
        None => "unknown",
    }
}

pub fn nav_status_label(n: u8) -> &'static str {
    match n {
        0 => "Under way using engine",
        1 => "At anchor",
        2 => "Not under command",
        3 => "Restricted manoeuvrability",
        4 => "Constrained by draught",
        5 => "Moored",
        6 => "Aground",
        7 => "Engaged in fishing",
        8 => "Under way sailing",
        11 => "Towing astern",
        12 => "Pushing or towing alongside",
        14 => "AIS-SART active",
        15 | _ => "Not defined",
    }
}

// ---------- decoders ----------

fn clean_sog(v: Option<f64>) -> Option<f64> {
    v.filter(|s| (0.0..102.3).contains(s))
}
fn clean_cog(v: Option<f64>) -> Option<f64> {
    v.filter(|c| (0.0..360.0).contains(c))
}
fn clean_heading(v: Option<i64>) -> Option<u16> {
    v.filter(|h| (0..360).contains(h)).map(|h| h as u16)
}
fn valid_latlon(lat: f64, lon: f64) -> bool {
    lat.abs() <= 90.0 && lon.abs() <= 180.0 && !(lat == 0.0 && lon == 0.0)
}

/// Digitraffic `locations` GeoJSON (the `?latitude&longitude&radius`, `?mmsi=` and `?from=` forms).
pub fn parse_digitraffic_locations(v: &Value) -> Vec<Pos> {
    v["features"]
        .as_array()
        .map(|f| {
            f.iter()
                .filter_map(|x| {
                    let c = x["geometry"]["coordinates"].as_array()?;
                    let (lon, lat) = (c.first()?.as_f64()?, c.get(1)?.as_f64()?);
                    if !valid_latlon(lat, lon) {
                        return None;
                    }
                    let p = &x["properties"];
                    let mmsi = p["mmsi"].as_u64().or_else(|| x["mmsi"].as_u64())? as u32;
                    Some(Pos {
                        mmsi,
                        lat,
                        lon,
                        sog: clean_sog(p["sog"].as_f64()),
                        cog: clean_cog(p["cog"].as_f64()),
                        heading: clean_heading(p["heading"].as_i64()),
                        nav: p["navStat"].as_u64().map(|n| n as u8),
                        ts: p["timestampExternal"].as_i64().unwrap_or_else(now_ms),
                        src: "digitraffic",
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn nonempty(v: &Value) -> Option<String> {
    v.as_str().map(|s| s.trim().trim_end_matches('@').trim().to_string()).filter(|s| !s.is_empty())
}

/// Digitraffic `/vessels` metadata object (one vessel). `eta` is a packed AIS value (month, day, hour, minute bit fields).
pub fn parse_digitraffic_vessel(v: &Value) -> Option<(u32, Info)> {
    let mmsi = v["mmsi"].as_u64()? as u32;
    let dim = |a: &str, b: &str| {
        let s = v[a].as_u64().unwrap_or(0) + v[b].as_u64().unwrap_or(0);
        (s > 0).then_some(s as u32)
    };
    Some((
        mmsi,
        Info {
            name: nonempty(&v["name"]),
            call_sign: nonempty(&v["callSign"]),
            imo: v["imo"].as_u64().filter(|i| *i > 0).map(|i| i as u32),
            ship_type: v["shipType"].as_u64().map(|t| t as u8),
            destination: nonempty(&v["destination"]),
            eta: v["eta"].as_u64().and_then(|e| unpack_eta(e as u32)),
            draught_m: v["draught"].as_f64().filter(|d| *d > 0.0).map(|d| d / 10.0),
            length_m: dim("referencePointA", "referencePointB"),
            beam_m: dim("referencePointC", "referencePointD"),
        },
    ))
}

/// AIS packs ETA into 20 bits: month(4) day(5) hour(5) minute(6). Digitraffic returns it as that integer.
pub fn unpack_eta(e: u32) -> Option<String> {
    let (month, day, hour, min) = ((e >> 16) & 0xf, (e >> 11) & 0x1f, (e >> 6) & 0x1f, e & 0x3f);
    ((1..=12).contains(&month) && (1..=31).contains(&day) && hour < 24 && min < 60).then(|| format!("{month:02}-{day:02} {hour:02}:{min:02} UTC"))
}

pub enum Decoded {
    Position(Pos, Option<String>),
    Static(u32, Info),
    Error(String),
}

/// "2022-12-29 18:22:32.318353 +0000 UTC" to unix ms. Falls back to now.
pub fn parse_time_utc(s: &str) -> i64 {
    let (date, rest) = s.split_once(' ').unwrap_or((s, ""));
    let time = rest.split_whitespace().next().unwrap_or("");
    let d: Vec<i64> = date.split('-').filter_map(|x| x.parse().ok()).collect();
    let t: Vec<&str> = time.split(':').collect();
    if d.len() != 3 || t.len() != 3 {
        return now_ms();
    }
    let (h, m) = (t[0].parse::<i64>().unwrap_or(0), t[1].parse::<i64>().unwrap_or(0));
    let sec: f64 = t[2].parse().unwrap_or(0.0);
    days_from_civil(d[0], d[1], d[2]) * 86_400_000 + h * 3_600_000 + m * 60_000 + (sec * 1000.0) as i64
}

pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// One AISStream message (text frame). Position reports of class A and B, and static data, are understood; the rest is ignored.
pub fn decode_aisstream(v: &Value) -> Option<Decoded> {
    if let Some(e) = v["error"].as_str() {
        return Some(Decoded::Error(e.to_string()));
    }
    let kind = v["MessageType"].as_str()?;
    let meta = &v["MetaData"];
    let ts = meta["time_utc"].as_str().map(parse_time_utc).unwrap_or_else(now_ms);
    match kind {
        "PositionReport" | "StandardClassBPositionReport" | "ExtendedClassBPositionReport" => {
            let m = &v["Message"][kind];
            let mmsi = m["UserID"].as_u64().or_else(|| meta["MMSI"].as_u64())? as u32;
            let lat = m["Latitude"].as_f64().or_else(|| meta["latitude"].as_f64())?;
            let lon = m["Longitude"].as_f64().or_else(|| meta["longitude"].as_f64())?;
            if !valid_latlon(lat, lon) {
                return None;
            }
            Some(Decoded::Position(
                Pos { mmsi, lat, lon, sog: clean_sog(m["Sog"].as_f64()), cog: clean_cog(m["Cog"].as_f64()), heading: clean_heading(m["TrueHeading"].as_i64()), nav: m["NavigationalStatus"].as_u64().map(|n| n as u8), ts, src: "aisstream" },
                nonempty(&meta["ShipName"]),
            ))
        }
        "ShipStaticData" => {
            let m = &v["Message"]["ShipStaticData"];
            let mmsi = m["UserID"].as_u64().or_else(|| meta["MMSI"].as_u64())? as u32;
            let d = &m["Dimension"];
            let dim = |a: &str, b: &str| {
                let s = d[a].as_u64().unwrap_or(0) + d[b].as_u64().unwrap_or(0);
                (s > 0).then_some(s as u32)
            };
            let eta = &m["Eta"];
            let eta = match (eta["Month"].as_u64(), eta["Day"].as_u64(), eta["Hour"].as_u64(), eta["Minute"].as_u64()) {
                (Some(mo @ 1..=12), Some(d @ 1..=31), Some(h @ 0..=23), Some(mi @ 0..=59)) => Some(format!("{mo:02}-{d:02} {h:02}:{mi:02} UTC")),
                _ => None,
            };
            Some(Decoded::Static(
                mmsi,
                Info {
                    name: nonempty(&m["Name"]).or_else(|| nonempty(&meta["ShipName"])),
                    call_sign: nonempty(&m["CallSign"]),
                    imo: m["ImoNumber"].as_u64().filter(|i| *i > 0).map(|i| i as u32),
                    ship_type: m["Type"].as_u64().map(|t| t as u8),
                    destination: nonempty(&m["Destination"]),
                    eta,
                    draught_m: m["MaximumStaticDraught"].as_f64().filter(|d| *d > 0.0),
                    length_m: dim("A", "B"),
                    beam_m: dim("C", "D"),
                },
            ))
        }
        _ => None,
    }
}

// ---------- store ----------

pub type TrackPt = (i64, f64, f64);

/// Recent positions for the area being watched. Bounded in vessels and per-vessel points, trimmed by age,
/// and cleared completely when nobody has asked for data for a while.
pub struct Store {
    pub pos: HashMap<u32, Pos>,
    pub tracks: HashMap<u32, VecDeque<TrackPt>>,
    pub info: HashMap<u32, Info>,
    pub info_loaded: Option<Instant>,
    pub last_access: Instant,
}

impl Default for Store {
    fn default() -> Self {
        Store { pos: HashMap::new(), tracks: HashMap::new(), info: HashMap::new(), info_loaded: None, last_access: Instant::now() }
    }
}

impl Store {
    pub fn touch(&mut self) {
        self.last_access = Instant::now();
    }

    pub fn update(&mut self, p: Pos) {
        let cutoff = now_ms() - TRACK_WINDOW_MS;
        if p.ts < cutoff {
            return;
        }
        if let Some(old) = self.pos.get(&p.mmsi) {
            if p.ts <= old.ts {
                return; // stale or duplicate report
            }
        } else if self.pos.len() >= MAX_VESSELS {
            // Evict the vessel whose last report is oldest.
            if let Some(k) = self.pos.iter().min_by_key(|(_, v)| v.ts).map(|(k, _)| *k) {
                self.pos.remove(&k);
                self.tracks.remove(&k);
            }
        }
        let tr = self.tracks.entry(p.mmsi).or_default();
        let add = tr.back().is_none_or(|l| p.ts - l.0 >= TRACK_GAP_MS && (l.1 != p.lat || l.2 != p.lon));
        if add {
            tr.push_back((p.ts, p.lat, p.lon));
            while tr.len() > TRACK_POINTS || tr.front().is_some_and(|f| f.0 < cutoff) {
                tr.pop_front();
            }
        }
        self.pos.insert(p.mmsi, p);
    }

    pub fn set_info(&mut self, mmsi: u32, i: Info) {
        if self.info.len() >= MAX_INFO && !self.info.contains_key(&mmsi) {
            return;
        }
        self.info.insert(mmsi, i);
    }

    /// Positions inside a box, nearest to the centre first.
    pub fn within(&self, lat: f64, lon: f64, radius_km: f64, max_age_ms: i64) -> Vec<(f64, &Pos)> {
        let oldest = now_ms() - max_age_ms;
        let mut v: Vec<(f64, &Pos)> = self.pos.values().filter(|p| p.ts >= oldest).map(|p| (haversine_km(lat, lon, p.lat, p.lon), p)).filter(|(d, _)| *d <= radius_km).collect();
        v.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        v
    }

    pub fn track(&self, mmsi: u32, since_ms: i64) -> Vec<TrackPt> {
        self.tracks.get(&mmsi).map(|t| t.iter().filter(|p| p.0 >= since_ms).copied().collect()).unwrap_or_default()
    }

    /// Drops all positions, tracks and metadata if nobody has used the plugin for `idle`. Returns whether it did.
    pub fn clear_if_idle(&mut self, idle: Duration) -> bool {
        if self.last_access.elapsed() >= idle && (!self.pos.is_empty() || !self.info.is_empty() || !self.tracks.is_empty()) {
            *self = Store { last_access: self.last_access, ..Store::default() };
            return true;
        }
        false
    }
}

pub fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let (a, b) = (lat1.to_radians(), lat2.to_radians());
    let h = ((b - a) / 2.0).sin().powi(2) + a.cos() * b.cos() * ((lon2 - lon1).to_radians() / 2.0).sin().powi(2);
    6371.0 * 2.0 * h.sqrt().asin()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn p(mmsi: u32, ts: i64, lat: f64) -> Pos {
        Pos { mmsi, lat, lon: 24.0, sog: Some(5.0), cog: Some(90.0), heading: Some(90), nav: Some(0), ts, src: "t" }
    }

    #[test]
    fn mmsi_validation() {
        assert_eq!(parse_mmsi("230629000"), Some(230_629_000));
        assert_eq!(parse_mmsi(" 002300000 "), Some(2_300_000));
        assert!(parse_mmsi("23062900").is_none() && parse_mmsi("2306290000").is_none() && parse_mmsi("23062900x").is_none() && parse_mmsi("").is_none() && parse_mmsi("-23062900").is_none());
        assert_eq!(mmsi_kind(230_629_000), "ship");
        assert_eq!(mmsi_kind(2_300_000), "coast station");
        assert_eq!(mmsi_kind(992_301_000), "aid to navigation");
        assert_eq!(mmsi_kind(111_230_000), "SAR aircraft");
    }

    #[test]
    fn imo_checksum() {
        assert_eq!(parse_imo("9606900"), Some(9_606_900)); // Viking Grace
        assert_eq!(parse_imo("IMO 9606900"), Some(9_606_900));
        assert_eq!(parse_imo("imo9074729"), Some(9_074_729));
        assert!(parse_imo("9606901").is_none(), "bad checksum");
        assert!(parse_imo("960690").is_none() && parse_imo("96069000").is_none() && parse_imo("abcdefg").is_none());
    }

    #[test]
    fn mid_table_is_sorted_and_resolves() {
        assert!(MID.windows(2).all(|w| w[0].0 < w[1].0), "MID table must be strictly ascending");
        assert_eq!(flag_iso(230_629_000), Some("FI"));
        assert_eq!(flag_iso(366_999_000), Some("US"));
        assert_eq!(flag_iso(636_012_345), Some("LR"));
        assert_eq!(flag_iso(2_300_000), None);
        assert_eq!(flag_iso(999_000_000), None);
    }

    #[test]
    fn labels() {
        assert_eq!(ship_type_label(71), "Cargo");
        assert_eq!(ship_type_label(84), "Tanker");
        assert_eq!(ship_type_label(0), "Unknown");
        assert_eq!(ship_class(Some(60)), "passenger");
        assert_eq!(ship_class(None), "unknown");
        assert_eq!(nav_status_label(5), "Moored");
    }

    #[test]
    fn digitraffic_locations_and_sentinels() {
        let v = json!({"type":"FeatureCollection","features":[
            {"mmsi":230994270,"type":"Feature","geometry":{"type":"Point","coordinates":[24.969178,60.168915]},"properties":{"mmsi":230994270,"sog":0.0,"cog":360.0,"navStat":5,"heading":511,"timestampExternal":1793680419922i64}},
            {"mmsi":1,"type":"Feature","geometry":{"type":"Point","coordinates":[0.0,0.0]},"properties":{"mmsi":1}},
            {"mmsi":2,"type":"Feature","geometry":{"type":"Point","coordinates":[24.0,60.0]},"properties":{"mmsi":2,"sog":102.3,"cog":12.5,"heading":90,"navStat":0}}]});
        let l = parse_digitraffic_locations(&v);
        assert_eq!(l.len(), 2, "null island dropped");
        assert_eq!((l[0].cog, l[0].heading, l[0].sog), (None, None, Some(0.0)));
        assert_eq!((l[1].sog, l[1].cog, l[1].heading), (None, Some(12.5), Some(90)));
        assert_eq!(l[0].ts, 1793680419922);
    }

    #[test]
    fn digitraffic_vessel_metadata() {
        let v = json!({"callSign":"OJPQ","destination":"SESTO-FIMHQ","draught":67,"eta":727390,"imo":9606900,"mmsi":230629000,"name":"VIKING GRACE","referencePointA":22,"referencePointB":196,"referencePointC":16,"referencePointD":16,"shipType":60});
        let (m, i) = parse_digitraffic_vessel(&v).unwrap();
        assert_eq!(m, 230_629_000);
        assert_eq!((i.imo, i.length_m, i.beam_m, i.ship_type), (Some(9_606_900), Some(218), Some(32), Some(60)));
        assert_eq!(i.draught_m, Some(6.7));
        assert_eq!(i.eta.as_deref(), Some("11-03 05:30 UTC"));
        assert!(parse_digitraffic_vessel(&json!({"name":"x"})).is_none());
        let (_, blank) = parse_digitraffic_vessel(&json!({"mmsi":5,"name":"  ","imo":0,"eta":0})).unwrap();
        assert!(blank.name.is_none() && blank.imo.is_none() && blank.eta.is_none());
    }

    #[test]
    fn aisstream_position_static_and_error() {
        let pos = json!({"MessageType":"PositionReport","MetaData":{"MMSI":259000420,"ShipName":"AUGUSTSON  ","latitude":66.02695,"longitude":12.2538,"time_utc":"2022-12-29 18:22:32.318353 +0000 UTC"},
            "Message":{"PositionReport":{"Cog":308,"Latitude":66.02695,"Longitude":12.2538,"NavigationalStatus":0,"Sog":10.5,"TrueHeading":235,"UserID":259000420}}});
        match decode_aisstream(&pos).unwrap() {
            Decoded::Position(p, name) => {
                assert_eq!((p.mmsi, p.heading, p.sog), (259_000_420, Some(235), Some(10.5)));
                assert_eq!(name.as_deref(), Some("AUGUSTSON"));
                assert_eq!(p.ts, 1_672_338_152_318);
            }
            _ => panic!(),
        }
        let st = json!({"MessageType":"ShipStaticData","MetaData":{"MMSI":259000420},"Message":{"ShipStaticData":{"CallSign":"LAAB ","Destination":"BERGEN","Dimension":{"A":100,"B":20,"C":10,"D":8},"Eta":{"Day":3,"Hour":14,"Minute":30,"Month":11},"ImoNumber":9074729,"MaximumStaticDraught":8.5,"Name":"AUGUSTSON ","Type":70,"UserID":259000420}}});
        match decode_aisstream(&st).unwrap() {
            Decoded::Static(m, i) => {
                assert_eq!(m, 259_000_420);
                assert_eq!((i.length_m, i.beam_m, i.imo, i.call_sign.as_deref()), (Some(120), Some(18), Some(9_074_729), Some("LAAB")));
                assert_eq!(i.eta.as_deref(), Some("11-03 14:30 UTC"));
            }
            _ => panic!(),
        }
        assert!(matches!(decode_aisstream(&json!({"error":"Api Key Is Not Valid"})), Some(Decoded::Error(e)) if e.contains("Key")));
        assert!(decode_aisstream(&json!({"MessageType":"BaseStationReport"})).is_none());
        assert!(decode_aisstream(&json!({"MessageType":"PositionReport","Message":{"PositionReport":{"UserID":1,"Latitude":91.0,"Longitude":0.0}}})).is_none());
    }

    #[test]
    fn civil_dates_round_trip() {
        for (y, m, d) in [(1970, 1, 1), (2000, 2, 29), (2024, 12, 31), (2026, 11, 3)] {
            assert_eq!(civil_from_days(days_from_civil(y, m, d)), (y, m, d));
        }
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(parse_time_utc("1970-01-02 00:00:01.5 +0000 UTC"), 86_401_500);
    }

    #[test]
    fn store_dedupes_and_limits_tracks() {
        let mut s = Store::default();
        let base = now_ms() - 3_000_000;
        for i in 0..300 {
            s.update(p(1, base + i * 30_000, 60.0 + i as f64 * 0.001));
        }
        assert!(s.track(1, 0).len() <= TRACK_POINTS);
        let before = s.pos[&1].ts;
        s.update(p(1, before - 1000, 1.0));
        assert_eq!(s.pos[&1].ts, before, "older report ignored");
        s.update(p(2, now_ms() - TRACK_WINDOW_MS - 10_000, 60.0));
        assert!(!s.pos.contains_key(&2), "too old to be useful");
    }

    #[test]
    fn store_evicts_oldest_when_full() {
        let mut s = Store::default();
        let t = now_ms() - 1_000_000;
        for i in 0..MAX_VESSELS as u32 {
            s.update(p(i + 1, t + i as i64, 60.0));
        }
        assert_eq!(s.pos.len(), MAX_VESSELS);
        s.update(p(999_999, now_ms(), 60.0));
        assert_eq!(s.pos.len(), MAX_VESSELS);
        assert!(!s.pos.contains_key(&1) && s.pos.contains_key(&999_999));
    }

    #[test]
    fn store_clears_when_idle_and_selects_by_distance() {
        let mut s = Store::default();
        s.update(p(1, now_ms(), 60.0));
        s.update(Pos { lon: 30.0, ..p(2, now_ms(), 60.0) });
        let near = s.within(60.0, 24.0, 50.0, 60_000);
        assert_eq!(near.len(), 1);
        assert!(!s.clear_if_idle(Duration::from_secs(600)));
        assert!(s.clear_if_idle(Duration::ZERO));
        assert!(s.pos.is_empty() && s.tracks.is_empty() && s.info.is_empty());
        assert!(!s.clear_if_idle(Duration::ZERO), "nothing left to clear");
    }
}

//! Plain two-body orbit geometry from CelesTrak GP mean elements, plus launch and catalog normalisers.
//! No propagation (no SGP4): passes and live positions are left to the `satellite` and `doppler` plugins.

use serde_json::{Value, json};

use crate::util::{iso, parse_iso};

pub const MU_KM3_S2: f64 = 398_600.4418;
pub const EARTH_RADIUS_KM: f64 = 6378.137;

pub struct Geometry {
    pub period_min: f64,
    pub sma_km: f64,
    pub apogee_km: f64,
    pub perigee_km: f64,
}

/// Period, semi-major axis and apsis altitudes from mean motion (rev/day) and eccentricity.
pub fn geometry(mean_motion: f64, ecc: f64) -> Option<Geometry> {
    if !(mean_motion.is_finite() && mean_motion > 0.0 && (0.0..1.0).contains(&ecc)) {
        return None;
    }
    let n = mean_motion * 2.0 * std::f64::consts::PI / 86_400.0;
    let a = (MU_KM3_S2 / (n * n)).cbrt();
    Some(Geometry { period_min: 1440.0 / mean_motion, sma_km: a, apogee_km: a * (1.0 + ecc) - EARTH_RADIUS_KM, perigee_km: a * (1.0 - ecc) - EARTH_RADIUS_KM })
}

pub fn orbit_class(g: &Geometry, ecc: f64) -> &'static str {
    if (g.sma_km - 42_164.0).abs() < 300.0 && ecc < 0.05 {
        "GEO"
    } else if ecc > 0.25 {
        "HEO"
    } else if g.apogee_km < 2000.0 {
        "LEO"
    } else if g.perigee_km < 35_000.0 {
        "MEO"
    } else {
        "Other"
    }
}

fn r1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

fn f(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())).filter(|x| x.is_finite())
}

/// One CelesTrak GP JSON record -> element summary with derived orbit geometry.
pub fn gp_record(r: &Value) -> Option<Value> {
    let catnr = r["NORAD_CAT_ID"].as_u64()?;
    let (mm, ecc) = (f(&r["MEAN_MOTION"])?, f(&r["ECCENTRICITY"])?);
    let g = geometry(mm, ecc)?;
    let epoch = r["EPOCH"].as_str().and_then(parse_iso);
    Some(json!({
        "norad_id": catnr, "name": r["OBJECT_NAME"].as_str().unwrap_or("UNKNOWN"), "intl_designator": r["OBJECT_ID"].as_str(),
        "epoch": epoch.map(iso), "epoch_age_days": epoch.map(|e| r1((crate::util::now_secs() - e) as f64 / 86_400.0)),
        "inclination_deg": f(&r["INCLINATION"]), "raan_deg": f(&r["RA_OF_ASC_NODE"]), "eccentricity": ecc, "arg_perigee_deg": f(&r["ARG_OF_PERICENTER"]),
        "mean_anomaly_deg": f(&r["MEAN_ANOMALY"]), "mean_motion_rev_day": mm, "bstar": f(&r["BSTAR"]), "mean_motion_dot": f(&r["MEAN_MOTION_DOT"]), "rev_at_epoch": r["REV_AT_EPOCH"].as_u64(),
        "period_min": (g.period_min * 100.0).round() / 100.0, "apogee_km": r1(g.apogee_km), "perigee_km": r1(g.perigee_km), "orbit_class": orbit_class(&g, ecc),
    }))
}

/// One CelesTrak SATCAT record.
pub fn satcat_record(r: &Value) -> Option<Value> {
    let catnr = r["NORAD_CAT_ID"].as_u64()?;
    let ty = match r["OBJECT_TYPE"].as_str().unwrap_or("") {
        "PAY" => "Payload",
        "R/B" => "Rocket body",
        "DEB" => "Debris",
        "UNK" => "Unknown",
        _ => "Other",
    };
    let status = match r["OPS_STATUS_CODE"].as_str().unwrap_or("") {
        "+" => "Operational",
        "-" => "Non-operational",
        "P" => "Partially operational",
        "B" => "Backup/standby",
        "S" => "Spare",
        "X" => "Extended mission",
        "D" => "Decayed",
        "?" => "Unknown",
        _ => "",
    };
    let s = |k: &str| r[k].as_str().map(str::trim).filter(|x| !x.is_empty());
    Some(json!({
        "norad_id": catnr, "name": s("OBJECT_NAME"), "intl_designator": s("OBJECT_ID"), "object_type": ty, "status": status,
        "owner": s("OWNER"), "launch_date": s("LAUNCH_DATE"), "launch_site": s("LAUNCH_SITE"), "decay_date": s("DECAY_DATE"), "decayed": s("DECAY_DATE").is_some(),
        "period_min": f(&r["PERIOD"]), "inclination_deg": f(&r["INCLINATION"]), "apogee_km": f(&r["APOGEE"]), "perigee_km": f(&r["PERIGEE"]), "rcs_m2": f(&r["RCS"]),
    }))
}

fn trunc(t: &str, n: usize) -> String {
    let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
    if t.chars().count() <= n { t } else { format!("{}…", t.chars().take(n).collect::<String>().trim_end()) }
}

fn https(u: &Value, host_prefix: &str) -> Option<String> {
    u.as_str().filter(|x| x.starts_with(host_prefix)).map(str::to_string)
}

/// One Launch Library 2 launch (normal mode).
pub fn launch(l: &Value, now: i64) -> Option<Value> {
    let id = l["id"].as_str()?;
    let net = l["net"].as_str().and_then(parse_iso);
    let pad = &l["pad"];
    let (lat, lon) = (f(&pad["latitude"]), f(&pad["longitude"]));
    let slug = l["slug"].as_str().filter(|s| s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    Some(json!({
        "id": id, "name": l["name"].as_str().unwrap_or("Launch"), "slug": slug,
        "status": l["status"]["name"].as_str(), "status_abbrev": l["status"]["abbrev"].as_str(),
        "net": net.map(iso), "net_precision": l["net_precision"]["name"].as_str(),
        "window_start": l["window_start"].as_str().and_then(parse_iso).map(iso), "window_end": l["window_end"].as_str().and_then(parse_iso).map(iso),
        "seconds_to_net": net.map(|n| n - now), "probability": l["probability"].as_i64(),
        "provider": l["launch_service_provider"]["name"].as_str(), "provider_type": l["launch_service_provider"]["type"].as_str(),
        "rocket": l["rocket"]["configuration"]["name"].as_str(),
        "mission": l["mission"]["name"].as_str(), "mission_type": l["mission"]["type"].as_str(), "orbit": l["mission"]["orbit"]["name"].as_str(), "orbit_abbrev": l["mission"]["orbit"]["abbrev"].as_str(),
        "description": l["mission"]["description"].as_str().map(|d| trunc(d, 320)),
        "pad": pad["name"].as_str(), "pad_lat": lat, "pad_lon": lon, "location": pad["location"]["name"].as_str(), "country": pad["country_code"].as_str(),
        "pad_map": https(&pad["map_url"], "https://www.google.com/maps"), "pad_wiki": https(&pad["wiki_url"], "https://en.wikipedia.org/"),
        "webcast_live": l["webcast_live"].as_bool().unwrap_or(false), "hold_reason": l["holdreason"].as_str().filter(|s| !s.is_empty()), "fail_reason": l["failreason"].as_str().filter(|s| !s.is_empty()),
        "image": https(&l["image"], "https://thespacedevs-prod."),
        "link": slug.map(|s| format!("https://spacelaunchnow.me/launch/{s}")),
    }))
}

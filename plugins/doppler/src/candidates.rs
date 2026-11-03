//! Stage 2 (optional): list aircraft from the `adsb-history` plugin whose recorded motion is consistent with a
//! Doppler estimate. These are CANDIDATES for a human to check, never matches: Doppler gives no heading, the speed is
//! relative to the air, and the listener's exact position is unknown.
//!
//! Real adsb-history flow (loopback, see plugins/adsb-history/README.md):
//! 1. `GET api/slices?date=YYYY-MM-DD&from=HH:MM&to=HH:MM&bbox=W,S,E,N&wait=N` starts or reuses a fetch job
//!    (200 + `ready:true` when available, 202 while running, 502 on failure);
//! 2. `GET api/jobs/{id}` reports progress while it is not ready;
//! 3. `GET api/slices/{id}/tracks` returns `{"aircraft":[{hex,callsign,points:[[unix_s,lat,lon,alt_ft|"ground"|null,gs_kt|null],..]}]}`.
//!
//! The data is the archive's 10-second heatmap resolution, so speed and track are DERIVED from successive samples
//! (the reported ground speed is only a fallback), which makes them coarse, especially in turns.

use serde::Serialize;
use serde_json::Value;

const KT: f64 = 0.514444;
const FT: f64 = 0.3048;

#[derive(Clone, Debug, Serialize)]
pub struct Sample {
    pub hex: String,
    pub callsign: Option<String>,
    pub t: f64,
    pub lat: f64,
    pub lon: f64,
    pub gs_ms: Option<f64>,
    pub track: Option<f64>,
    pub alt_m: Option<f64>,
}

pub struct Query {
    pub speed_ms: f64,
    pub speed_sigma: f64,
    pub distance_m: Option<f64>,
    pub distance_sigma: f64,
    /// Event window in unix seconds (source time of closest approach).
    pub t_from: f64,
    pub t_to: f64,
    pub lat: f64,
    pub lon: f64,
    pub radius_km: f64,
}

/// Parse `1700000000`, `1700000000.5` or `2026-11-02T14:03:09Z` (UTC) to unix seconds.
pub fn parse_time(s: &str) -> Option<f64> {
    let s = s.trim();
    if let Ok(v) = s.parse::<f64>() {
        return v.is_finite().then_some(v);
    }
    let s = s.trim_end_matches('Z');
    let (date, time) = s.split_once(['T', ' '])?;
    let mut d = date.split('-').map(|x| x.parse::<i64>().ok());
    let (y, m, dd) = (d.next()??, d.next()??, d.next()??);
    let time = time.split(['+']).next()?;
    let mut tp = time.split(':');
    let h: f64 = tp.next()?.parse().ok()?;
    let mi: f64 = tp.next().unwrap_or("0").parse().ok()?;
    let sec: f64 = tp.next().unwrap_or("0").parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&dd) {
        return None;
    }
    // days from civil (Howard Hinnant)
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + dd - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days as f64 * 86400.0 + h * 3600.0 + mi * 60.0 + sec)
}

pub fn haversine_m(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let a = ((p2 - p1) / 2.0).sin().powi(2) + p1.cos() * p2.cos() * ((lon2 - lon1).to_radians() / 2.0).sin().powi(2);
    6_371_000.0 * 2.0 * a.sqrt().asin()
}

fn bearing_deg(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let (p1, p2, dl) = (lat1.to_radians(), lat2.to_radians(), (lon2 - lon1).to_radians());
    let y = dl.sin() * p2.cos();
    let x = p1.cos() * p2.sin() - p1.sin() * p2.cos() * dl.cos();
    (y.atan2(x).to_degrees() + 360.0) % 360.0
}

/// Parse the `tracks` response. Ground speed and track are derived from neighbouring samples (at most 30 s apart);
/// the reported gs (knots) is used only for an aircraft's isolated samples. Samples on the ground are dropped.
pub fn parse_tracks(body: &Value) -> Vec<Sample> {
    let mut out = Vec::new();
    let Some(list) = body.get("aircraft").and_then(|a| a.as_array()) else { return out };
    for ac in list {
        let Some(hex) = ac.get("hex").and_then(|h| h.as_str()) else { continue };
        let callsign = ac.get("callsign").and_then(|c| c.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let mut pts: Vec<(f64, f64, f64, Option<f64>, Option<f64>, bool)> = Vec::new(); // t, lat, lon, alt_m, gs_ms, ground
        for p in ac.get("points").and_then(|p| p.as_array()).into_iter().flatten() {
            let Some(a) = p.as_array() else { continue };
            let (Some(t), Some(lat), Some(lon)) = (a.first().and_then(|x| x.as_f64()), a.get(1).and_then(|x| x.as_f64()), a.get(2).and_then(|x| x.as_f64())) else { continue };
            let ground = a.get(3).and_then(|x| x.as_str()) == Some("ground");
            let alt = a.get(3).and_then(|x| x.as_f64()).map(|f| f * FT);
            pts.push((t, lat, lon, alt, a.get(4).and_then(|x| x.as_f64()).map(|k| k * KT), ground));
        }
        pts.sort_by(|a, b| a.0.total_cmp(&b.0));
        for i in 0..pts.len() {
            let (t, lat, lon, alt, rep, ground) = pts[i];
            if ground {
                continue;
            }
            let prev = i.checked_sub(1).map(|j| pts[j]).filter(|n| t - n.0 <= 30.0 && !n.5);
            let next = pts.get(i + 1).copied().filter(|n| n.0 - t <= 30.0 && !n.5);
            let (a, b) = match (prev, next) {
                (Some(p), Some(n)) => (p, n),
                (Some(p), None) => (p, pts[i]),
                (None, Some(n)) => (pts[i], n),
                _ => {
                    out.push(Sample { hex: hex.to_lowercase(), callsign: callsign.clone(), t, lat, lon, gs_ms: rep, track: None, alt_m: alt });
                    continue;
                }
            };
            let dt = b.0 - a.0;
            let (gs, trk) = if dt > 0.5 { (Some(haversine_m(a.1, a.2, b.1, b.2) / dt), Some(bearing_deg(a.1, a.2, b.1, b.2))) } else { (rep, None) };
            out.push(Sample { hex: hex.to_lowercase(), callsign: callsign.clone(), t, lat, lon, gs_ms: gs, track: trk, alt_m: alt });
        }
    }
    out
}

#[derive(Serialize)]
pub struct Candidate {
    pub label: &'static str,
    pub hex: String,
    pub callsign: Option<String>,
    pub score: f64,
    pub ground_speed_ms: Option<f64>,
    pub speed_diff_ms: Option<f64>,
    pub track_deg: Option<f64>,
    pub altitude_m: Option<f64>,
    pub sample_time: f64,
    pub distance_to_area_centre_km: f64,
    pub reasons: Vec<String>,
}

/// Rank aircraft by consistency with the estimate. Returns at most `limit` candidates (best first).
pub fn evaluate(samples: &[Sample], q: &Query, limit: usize) -> Vec<Candidate> {
    use std::collections::BTreeMap;
    let mut by: BTreeMap<&str, Vec<&Sample>> = BTreeMap::new();
    for s in samples {
        if s.t >= q.t_from - 60.0 && s.t <= q.t_to + 60.0 {
            by.entry(s.hex.as_str()).or_default().push(s);
        }
    }
    let tol_v = (3.0 * q.speed_sigma).max(0.1 * q.speed_ms).max(10.0); // wind and tracking error are real
    let radius_m = q.radius_km * 1000.0;
    let mut out = Vec::new();
    for (hex, mut v) in by {
        v.sort_by(|a, b| a.t.total_cmp(&b.t));
        let mut best: Option<(f64, Candidate)> = None;
        for (i, s) in v.iter().enumerate() {
            // speed: reported, else derived from the neighbouring position
            let gs = s.gs_ms.or_else(|| {
                let n = v.get(i + 1).or(i.checked_sub(1).and_then(|j| v.get(j)))?;
                let dt = (n.t - s.t).abs();
                (dt > 0.5).then(|| haversine_m(s.lat, s.lon, n.lat, n.lon) / dt)
            });
            let Some(gs) = gs else { continue };
            let dc = haversine_m(q.lat, q.lon, s.lat, s.lon);
            let alt = s.alt_m.unwrap_or(0.0).max(0.0);
            let edge = (dc - radius_m).max(0.0);
            let min_range = (edge * edge + alt * alt).sqrt();
            let max_range = ((dc + radius_m).powi(2) + alt * alt).sqrt();
            let mut reasons = Vec::new();
            let dv = gs - q.speed_ms;
            if dv.abs() > tol_v {
                continue;
            }
            reasons.push(format!("ground speed {:.0} m/s vs estimate {:.0} m/s (tolerance +-{:.0})", gs, q.speed_ms, tol_v));
            let mut dscore = 0.0;
            if let Some(d) = q.distance_m {
                let hi = d + 3.0 * q.distance_sigma.max(0.15 * d);
                let lo = (d - 3.0 * q.distance_sigma.max(0.15 * d)).max(0.0);
                if min_range > hi || max_range < lo {
                    continue;
                }
                reasons.push(format!("could be {:.1}-{:.1} km from somewhere in the area; estimate {:.1} km", min_range / 1000.0, max_range / 1000.0, d / 1000.0));
                let mid = 0.5 * (min_range + max_range);
                dscore = ((mid - d).abs() / hi.max(1.0)).min(2.0);
            } else if edge > 15_000.0 {
                continue;
            }
            if s.alt_m.is_none() {
                reasons.push("no altitude in the record: slant distance not checked against height".into());
            }
            let score = (dv.abs() / tol_v) + dscore + (dc / 1000.0 / (q.radius_km + 20.0)).min(1.0) * 0.5;
            if best.as_ref().is_none_or(|b| score < b.0) {
                best = Some((
                    score,
                    Candidate {
                        label: "candidate",
                        hex: hex.to_string(),
                        callsign: s.callsign.clone(),
                        score,
                        ground_speed_ms: Some(gs),
                        speed_diff_ms: Some(dv),
                        track_deg: s.track,
                        altitude_m: s.alt_m,
                        sample_time: s.t,
                        distance_to_area_centre_km: dc / 1000.0,
                        reasons,
                    },
                ));
            }
        }
        if let Some((_, c)) = best {
            out.push(c);
        }
    }
    out.sort_by(|a, b| a.score.total_cmp(&b.score));
    out.truncate(limit);
    out
}

/// Loopback-only check for the configured adsb-history base URL (a plugin must never be steered to an arbitrary host).
pub fn loopback_base(url: &str) -> Option<String> {
    let rest = url.strip_prefix("http://")?;
    let host_port = rest.split('/').next()?;
    let host = host_port.rsplit_once(':').map(|x| x.0).unwrap_or(host_port);
    matches!(host, "127.0.0.1" | "localhost" | "[::1]").then(|| format!("http://{}", host_port))
}

/// Unix seconds to (YYYY-MM-DD, minutes since midnight), UTC.
pub fn ymd_min(t: f64) -> (String, i64) {
    let secs = t.floor() as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (format!("{y:04}-{m:02}-{d:02}"), rem / 60)
}

fn hhmm(m: i64) -> String {
    format!("{:02}:{:02}", m / 60, m % 60)
}

/// Bounding box `W,S,E,N` around the area, widened by the estimated range (the aircraft may be that far from the listener).
pub fn bbox(q: &Query) -> String {
    let r_km = (q.radius_km + q.distance_m.unwrap_or(0.0) / 1000.0 * 1.5 + 2.0).min(400.0);
    let dlat = r_km / 111.32;
    let dlon = (r_km / (111.32 * q.lat.to_radians().cos().abs().max(0.05))).min(179.0);
    let wrap = |l: f64| if l > 180.0 { l - 360.0 } else if l < -180.0 { l + 360.0 } else { l };
    format!("{:.4},{:.4},{:.4},{:.4}", wrap(q.lon - dlon), (q.lat - dlat).max(-90.0), wrap(q.lon + dlon), (q.lat + dlat).min(90.0))
}

#[derive(Debug)]
pub enum Fetched {
    Samples(Vec<Sample>),
    /// The archive job is still running; calling again with the same parameters reuses it.
    Pending { job_id: String, progress: Value },
}

/// Agent for adsb-history: waits are long and 202/502 are data, not errors.
pub fn history_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(130)))
        .user_agent("osnt-doppler/0.1 (flyby Doppler check)")
        .http_status_as_error(false)
        .build()
        .into()
}

pub fn fetch(agent: &ureq::Agent, base: &str, q: &Query) -> Result<Fetched, String> {
    let (d0, m0) = ymd_min(q.t_from - 60.0);
    let (d1, m1) = ymd_min(q.t_to + 60.0);
    if d0 != d1 {
        return Err("the event window crosses midnight UTC; narrow the clip time window to one UTC day".into());
    }
    let url = format!("{base}/api/slices?date={d0}&from={}&to={}&bbox={}&wait=100", hhmm(m0), hhmm((m1 + 1).min(1439)), bbox(q));
    let mut r = agent.get(&url).call().map_err(|e| format!("adsb-history unavailable: {e}"))?;
    let status = r.status().as_u16();
    let st: Value = r.body_mut().read_json().map_err(|e| format!("adsb-history returned unreadable JSON: {e}"))?;
    match status {
        200 if st["ready"] == true => {}
        202 | 200 => {
            let id = st["id"].as_str().unwrap_or_default().to_string();
            return Ok(Fetched::Pending { job_id: id, progress: st });
        }
        400 => return Err(format!("adsb-history rejected the request: {}", st["error"].as_str().unwrap_or("bad input"))),
        _ => return Err(format!("adsb-history could not fetch the archive: {}", st["error"].as_str().unwrap_or("unknown error"))),
    }
    let id = st["id"].as_str().filter(|i| i.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')).ok_or("adsb-history returned no slice id")?;
    let mut t = agent.get(&format!("{base}/api/slices/{id}/tracks")).call().map_err(|e| format!("adsb-history unavailable: {e}"))?;
    if t.status().as_u16() != 200 {
        return Err("adsb-history slice expired; try again".into());
    }
    let body: Value = t.body_mut().read_json().map_err(|e| format!("adsb-history returned unreadable JSON: {e}"))?;
    Ok(Fetched::Samples(parse_tracks(&body)))
}

/// True when adsb-history answers on loopback.
pub fn available(agent: &ureq::Agent, base: &str) -> bool {
    agent.get(&format!("{base}/api/info")).call().map(|r| r.status().as_u16() == 200).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_times() {
        assert_eq!(parse_time("1700000000"), Some(1_700_000_000.0));
        assert_eq!(parse_time("2023-11-14T22:13:20Z"), Some(1_700_000_000.0));
        assert!(parse_time("nonsense").is_none());
    }

    #[test]
    fn loopback_only() {
        assert!(loopback_base("http://127.0.0.1:8120").is_some());
        assert!(loopback_base("http://evil.example.com:80").is_none());
        assert!(loopback_base("https://127.0.0.1").is_none());
    }

    /// A response shaped exactly like adsb-history's `api/slices/{id}/tracks`.
    fn tracks_body(t: f64) -> Value {
        // FAST1: ~230 m/s due east at 3000 ft. SLOW2: ~45 m/s. FAR3: fast but 400 km north. GND4: on the ground.
        let line = |lat: f64, lon0: f64, dlon_per_10s: f64, alt: Value| -> Vec<Value> {
            (0..13).map(|i| json!([t - 60.0 + 10.0 * i as f64, lat, lon0 + dlon_per_10s * i as f64, alt, null])).collect()
        };
        json!({ "id": "abc", "truncated": false, "aircraft": [
            { "hex": "AAA111", "callsign": "FAST1", "squawk": null, "points": line(51.0, -0.2, 0.033, json!(3000)) },
            { "hex": "BBB222", "callsign": "SLOW2", "squawk": null, "points": line(51.0, -0.2, 0.0065, json!(3000)) },
            { "hex": "CCC333", "callsign": "FAR3", "squawk": null, "points": line(55.0, -0.2, 0.033, json!(3000)) },
            { "hex": "DDD444", "callsign": null, "squawk": null, "points": line(51.0, -0.2, 0.033, json!("ground")) },
        ]})
    }

    fn query(t: f64) -> Query {
        Query { speed_ms: 230.0, speed_sigma: 10.0, distance_m: Some(1500.0), distance_sigma: 300.0, t_from: t - 30.0, t_to: t + 30.0, lat: 51.0, lon: 0.0, radius_km: 3.0 }
    }

    #[test]
    fn derives_speed_from_successive_samples_and_ranks() {
        let t = 1_700_000_000.0;
        let recs = parse_tracks(&tracks_body(t));
        assert!(recs.iter().all(|r| r.hex != "ddd444"), "ground samples are dropped");
        let fast = recs.iter().find(|r| r.hex == "aaa111").unwrap();
        assert!((fast.gs_ms.unwrap() - 230.0).abs() < 8.0, "{:?}", fast.gs_ms);
        assert!((fast.track.unwrap() - 90.0).abs() < 2.0);
        let c = evaluate(&recs, &query(t), 10);
        assert_eq!(c.iter().map(|c| c.hex.as_str()).collect::<Vec<_>>(), vec!["aaa111"]);
        assert_eq!(c[0].label, "candidate");
    }

    #[test]
    fn formats_utc_dates_and_bbox() {
        assert_eq!(ymd_min(1_700_000_000.0), ("2023-11-14".to_string(), 22 * 60 + 13));
        let b = bbox(&query(0.0));
        let v: Vec<f64> = b.split(',').map(|x| x.parse().unwrap()).collect();
        assert!(v[0] < 0.0 && v[2] > 0.0 && v[1] < 51.0 && v[3] > 51.0, "{b}");
    }

    /// Fake adsb-history that mimics the real flow: 202 + job polling is not needed when `wait` succeeds (ready:true).
    async fn fake_history(t: f64, ready: bool) -> String {
        use axum::{Router, extract::Path, http::StatusCode, routing::get};
        let body = tracks_body(t);
        let app = Router::new()
            .route("/api/info", get(|| async { axum::Json(json!({ "name": "adsb-history" })) }))
            .route("/api/slices", get(move |axum::extract::RawQuery(q): axum::extract::RawQuery| async move {
                let q = q.unwrap_or_default();
                assert!(q.contains("date=2023-11-14") && q.contains("from=22:") && q.contains("bbox="), "{q}");
                if ready {
                    (StatusCode::OK, axum::Json(json!({ "id": "abc", "state": "done", "ready": true })))
                } else {
                    (StatusCode::ACCEPTED, axum::Json(json!({ "id": "abc", "state": "running", "ready": false, "phase": "downloading" })))
                }
            }))
            .route("/api/slices/{id}/tracks", get(move |Path(id): Path<String>| async move {
                assert_eq!(id, "abc");
                axum::Json(body)
            }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn full_flow_against_fake_history_server() {
        let t = 1_700_000_000.0;
        let base = fake_history(t, true).await;
        let q = query(t);
        let (agent, b2) = (history_agent(), base.clone());
        assert!(tokio::task::spawn_blocking({ let a = agent.clone(); move || available(&a, &b2) }).await.unwrap());
        let res = tokio::task::spawn_blocking(move || fetch(&agent, &base, &q)).await.unwrap().unwrap();
        let Fetched::Samples(s) = res else { panic!("expected samples") };
        assert_eq!(evaluate(&s, &query(t), 5)[0].hex, "aaa111");
    }

    #[tokio::test]
    async fn pending_job_is_reported_not_failed() {
        let t = 1_700_000_000.0;
        let base = fake_history(t, false).await;
        let q = query(t);
        let res = tokio::task::spawn_blocking(move || fetch(&history_agent(), &base, &q)).await.unwrap().unwrap();
        assert!(matches!(res, Fetched::Pending { ref job_id, .. } if job_id == "abc"));
    }

    #[test]
    fn crossing_midnight_is_refused() {
        let q = Query { t_from: 1_700_000_000.0 - 86_000.0 + 0.0, t_to: 1_700_000_000.0, ..query(1_700_000_000.0) };
        let e = fetch(&history_agent(), "http://127.0.0.1:1", &q).unwrap_err();
        assert!(e.contains("midnight"), "{e}");
    }
}

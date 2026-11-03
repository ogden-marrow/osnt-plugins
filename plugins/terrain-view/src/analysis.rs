//! Terrain analyses on a loaded `Field`: profile, line of sight, horizon silhouette and viewshed rays.
//! Curvature and refraction: a target at distance d appears lowered by d^2 * (1 - k) / (2R), with k = 0.13 for the
//! standard atmosphere (refraction bends light slightly towards the ground) and R the mean Earth radius.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use crate::tiles::{Field, Key, needed};

pub const R: f64 = 6_371_008.8;

#[derive(Clone, Copy, Debug)]
pub struct Sample {
    pub lat: f64,
    pub lon: f64,
    pub z: u8,
}

pub fn zoom_for_distance(d: f64) -> u8 {
    match d {
        d if d < 2_500.0 => 12,
        d if d < 12_000.0 => 11,
        d if d < 40_000.0 => 10,
        d if d < 120_000.0 => 9,
        _ => 8,
    }
}

/// Zoom whose pixels are about as wide as `spacing` metres at this latitude.
pub fn zoom_for_spacing(spacing: f64, lat: f64) -> u8 {
    let z = (156_543.03 * lat.to_radians().cos().max(0.05) / spacing.max(1.0)).log2().round();
    z.clamp(7.0, 13.0) as u8
}

pub fn destination(lat: f64, lon: f64, bearing: f64, dist: f64) -> (f64, f64) {
    let (p1, l1, b, d) = (lat.to_radians(), lon.to_radians(), bearing.to_radians(), dist / R);
    let p2 = (p1.sin() * d.cos() + p1.cos() * d.sin() * b.cos()).clamp(-1.0, 1.0).asin();
    let l2 = l1 + (b.sin() * d.sin() * p1.cos()).atan2(d.cos() - p1.sin() * p2.sin());
    (p2.to_degrees(), (l2.to_degrees() + 540.0).rem_euclid(360.0) - 180.0)
}

pub fn distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let a = ((p2 - p1) / 2.0).sin().powi(2) + p1.cos() * p2.cos() * ((lon2 - lon1).to_radians() / 2.0).sin().powi(2);
    2.0 * R * a.sqrt().asin()
}

pub fn bearing(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let (p1, p2, dl) = (lat1.to_radians(), lat2.to_radians(), (lon2 - lon1).to_radians());
    (dl.sin() * p2.cos()).atan2(p1.cos() * p2.sin() - p1.sin() * p2.cos() * dl.cos()).to_degrees().rem_euclid(360.0)
}

/// Point a fraction `f` of the way along the great circle.
pub fn interpolate(lat1: f64, lon1: f64, lat2: f64, lon2: f64, f: f64) -> (f64, f64) {
    let d = distance(lat1, lon1, lat2, lon2) / R;
    if d < 1e-12 {
        return (lat1, lon1);
    }
    let (p1, l1, p2, l2) = (lat1.to_radians(), lon1.to_radians(), lat2.to_radians(), lon2.to_radians());
    let (a, b) = (((1.0 - f) * d).sin() / d.sin(), (f * d).sin() / d.sin());
    let x = a * p1.cos() * l1.cos() + b * p2.cos() * l2.cos();
    let y = a * p1.cos() * l1.sin() + b * p2.cos() * l2.sin();
    let z = a * p1.sin() + b * p2.sin();
    (z.atan2(x.hypot(y)).to_degrees(), y.atan2(x).to_degrees())
}

/// Sample distances from the observer: fine near, coarser far (1.2 % of the range, at least `min_step`).
pub fn ray_distances(max_m: f64, first: f64, min_step: f64, rel: f64) -> Vec<f64> {
    let mut v = vec![];
    let mut d = first;
    while d <= max_m {
        v.push(d);
        d += min_step.max(d * rel);
    }
    v
}

pub fn needed_set(points: impl Iterator<Item = Sample>) -> BTreeSet<Key> {
    let mut set = BTreeSet::new();
    let mut last: Option<Key> = None;
    for s in points {
        let n = needed(s.lat, s.lon, s.z);
        if last != Some(n[0]) || n[0] != n[3] {
            set.extend(n);
            last = Some(n[0]);
        }
    }
    set
}

fn r1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}
fn r4(v: f64) -> f64 {
    (v * 1e4).round() / 1e4
}
fn r5(v: f64) -> f64 {
    (v * 1e5).round() / 1e5
}

// ---- profile and line of sight ----------------------------------------------------------------------------------------

pub struct Line {
    pub lat1: f64,
    pub lon1: f64,
    pub lat2: f64,
    pub lon2: f64,
    pub n: usize,
}

impl Line {
    pub fn length(&self) -> f64 {
        distance(self.lat1, self.lon1, self.lat2, self.lon2)
    }
    pub fn samples(&self) -> Vec<(f64, Sample)> {
        let len = self.length();
        let z = zoom_for_spacing(len / self.n as f64, (self.lat1 + self.lat2) / 2.0);
        (0..=self.n)
            .map(|i| {
                let f = i as f64 / self.n as f64;
                let (lat, lon) = interpolate(self.lat1, self.lon1, self.lat2, self.lon2, f);
                (len * f, Sample { lat, lon, z })
            })
            .collect()
    }
}

pub fn profile(field: &Field, line: &Line) -> Result<Value, String> {
    let pts = line.samples();
    let elev: Vec<Option<f64>> = pts.iter().map(|(_, s)| field.elev(s.lat, s.lon, s.z)).collect();
    let known: Vec<f64> = elev.iter().flatten().copied().collect();
    if known.len() < 2 || known.len() * 2 < elev.len() {
        return Err("terrain data is not available for most of this line".into());
    }
    let (mut gain, mut loss) = (0.0, 0.0);
    for w in known.windows(2) {
        let d = w[1] - w[0];
        if d > 0.0 { gain += d } else { loss -= d }
    }
    let (min, max) = (known.iter().cloned().fold(f64::MAX, f64::min), known.iter().cloned().fold(f64::MIN, f64::max));
    let rows: Vec<Value> = pts.iter().zip(&elev).map(|((d, s), e)| json!([r1(*d), e.map(r1), r5(s.lat), r5(s.lon)])).collect();
    let len = line.length();
    Ok(json!({
        "distance_m": r1(len), "bearing": r1(bearing(line.lat1, line.lon1, line.lat2, line.lon2)), "samples": rows, "columns": ["distance_m", "elevation_m", "lat", "lon"],
        "min_m": r1(min), "max_m": r1(max), "gain_m": r1(gain), "loss_m": r1(loss), "start_m": elev[0].map(r1), "end_m": elev.last().copied().flatten().map(r1),
        "sample_spacing_m": r1(len / line.n as f64), "tile_zoom": pts[0].1.z,
    }))
}

pub fn line_of_sight(field: &Field, line: &Line, h1: f64, h2: f64, k: f64) -> Result<Value, String> {
    let pts = line.samples();
    let len = line.length();
    if len < 1.0 {
        return Err("the two points are the same place".into());
    }
    let elev: Vec<Option<f64>> = pts.iter().map(|(_, s)| field.elev(s.lat, s.lon, s.z)).collect();
    let (Some(e1), Some(e2)) = (elev[0], elev[elev.len() - 1]) else { return Err("no terrain data at one of the end points".into()) };
    let (a, b) = (e1 + h1, e2 + h2);
    let mut rows = vec![];
    let (mut worst, mut worst_i) = (f64::MAX, None::<usize>);
    let mut first_block: Option<usize> = None;
    let mut missing = 0;
    for (i, ((d, s), e)) in pts.iter().zip(&elev).enumerate() {
        let los = a + (b - a) * d / len;
        let Some(e) = e else {
            missing += 1;
            rows.push(json!([r1(*d), null, null, r1(los), r5(s.lat), r5(s.lon)]));
            continue;
        };
        let bulge = d * (len - d) * (1.0 - k) / (2.0 * R);
        let eff = e + bulge;
        rows.push(json!([r1(*d), r1(*e), r1(eff), r1(los), r5(s.lat), r5(s.lon)]));
        if i > 0 && i + 1 < pts.len() {
            let clear = los - eff;
            if clear < 0.0 && first_block.is_none() {
                first_block = Some(i);
            }
            if clear < worst {
                worst = clear;
                worst_i = Some(i);
            }
        }
    }
    if missing * 2 > pts.len() {
        return Err("terrain data is not available for most of this line".into());
    }
    let visible = first_block.is_none();
    let blocker = worst_i.filter(|_| !visible).map(|i| json!({ "distance_m": r1(pts[i].0), "lat": r5(pts[i].1.lat), "lon": r5(pts[i].1.lon), "ground_m": elev[i].map(r1), "above_line_m": r1(-worst) }));
    Ok(json!({
        "visible": visible, "distance_m": r1(len), "from": { "ground_m": r1(e1), "eye_m": r1(a) }, "to": { "ground_m": r1(e2), "eye_m": r1(b) },
        "min_clearance_m": r1(worst), "first_obstruction": first_block.map(|i| json!({ "distance_m": r1(pts[i].0), "lat": r5(pts[i].1.lat), "lon": r5(pts[i].1.lon) })),
        "worst_obstruction": blocker, "refraction_k": k, "columns": ["distance_m", "ground_m", "ground_with_curvature_m", "line_of_sight_m", "lat", "lon"], "samples": rows,
        "curvature_drop_mid_m": r1(len * len / 4.0 * (1.0 - k) / (2.0 * R)), "tile_zoom": pts[0].1.z,
        "note": "Straight-line optical sight over terrain heights from the tiles (about 30 m resolution; buildings and trees are not included).",
    }))
}

// ---- horizon -----------------------------------------------------------------------------------------------------------

pub struct Horizon {
    pub lat: f64,
    pub lon: f64,
    pub eye: f64,
    pub radius: f64,
    pub step: f64,
    pub k: f64,
}

impl Horizon {
    fn azimuths(&self) -> Vec<f64> {
        let n = (360.0 / self.step).round() as usize;
        (0..n).map(|i| i as f64 * self.step).collect()
    }
    fn dists(&self) -> Vec<f64> {
        ray_distances(self.radius, 30.0, 25.0, 0.012)
    }
    pub fn plan(&self) -> BTreeSet<Key> {
        let dists = self.dists();
        let mut pts = vec![Sample { lat: self.lat, lon: self.lon, z: 12 }];
        for az in self.azimuths() {
            for &d in &dists {
                let (lat, lon) = destination(self.lat, self.lon, az, d);
                pts.push(Sample { lat, lon, z: zoom_for_distance(d) });
            }
        }
        needed_set(pts.into_iter())
    }
}

pub fn horizon(field: &Field, h: &Horizon) -> Result<Value, String> {
    let ground = field.elev(h.lat, h.lon, 12).ok_or("no terrain data at the observer position")?;
    let h0 = ground + h.eye;
    let dists = h.dists();
    let mut rows = vec![];
    let mut points: Vec<(f64, f64, f64, f64, f64, f64)> = vec![]; // az, angle, dist, lat, lon, elev
    for az in h.azimuths() {
        let (mut best, mut bd, mut bpos, mut be) = (f64::MIN, 0.0, (h.lat, h.lon), ground);
        for &d in &dists {
            let (lat, lon) = destination(h.lat, h.lon, az, d);
            let Some(e) = field.elev(lat, lon, zoom_for_distance(d)) else { continue };
            let angle = ((e - h0) / d).atan() - d * (1.0 - h.k) / (2.0 * R);
            if angle > best {
                (best, bd, bpos, be) = (angle, d, (lat, lon), e);
            }
        }
        if best == f64::MIN {
            continue;
        }
        points.push((az, best.to_degrees(), bd, bpos.0, bpos.1, be));
        rows.push(json!([az, r4(best.to_degrees()), r1(bd)]));
    }
    if points.len() * 2 < h.azimuths().len() {
        return Err("terrain data is not available around this point".into());
    }
    // Prominent peaks: local maxima over +/- 8 degrees that stand out from the surrounding horizon.
    let w = (8.0 / h.step).round() as usize;
    let n = points.len();
    let mut peaks: Vec<&(f64, f64, f64, f64, f64, f64)> = vec![];
    for i in 0..n {
        let v = points[i].1;
        let (mut is_peak, mut low) = (true, v);
        for j in 1..=w.min(n / 2) {
            let (a, b) = (points[(i + n - j) % n].1, points[(i + j) % n].1);
            if a > v || b >= v {
                is_peak = false;
                break;
            }
            low = low.min(a).min(b);
        }
        if is_peak && v - low > 0.4 {
            peaks.push(&points[i]);
        }
    }
    peaks.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let mut chosen: Vec<&(f64, f64, f64, f64, f64, f64)> = vec![];
    for p in peaks {
        if chosen.iter().all(|c| (((c.0 - p.0 + 540.0) % 360.0) - 180.0).abs() > 6.0) {
            chosen.push(p);
        }
        if chosen.len() == 8 {
            break;
        }
    }
    let max = points.iter().cloned().fold(points[0], |m, p| if p.1 > m.1 { p } else { m });
    Ok(json!({
        "observer": { "lat": h.lat, "lon": h.lon, "ground_m": r1(ground), "eye_m": h.eye, "eye_elevation_m": r1(h0) },
        "radius_km": h.radius / 1000.0, "step_deg": h.step, "columns": ["azimuth_deg", "elevation_deg", "distance_m"], "horizon": rows,
        "highest": { "azimuth": max.0, "elevation_deg": r4(max.1), "distance_km": r1(max.2 / 1000.0) },
        "peaks": chosen.iter().map(|p| json!({ "azimuth": p.0, "elevation_deg": r4(p.1), "distance_km": r1(p.2 / 1000.0), "lat": r5(p.3), "lon": r5(p.4), "height_m": r1(p.5) })).collect::<Vec<_>>(),
        "refraction_k": h.k,
        "note": "Angles are above the observer's true horizontal. Terrain only: trees, buildings and sub-30 m features are missing, so compare the large shapes.",
    }))
}

// ---- viewshed ----------------------------------------------------------------------------------------------------------

pub struct Viewshed {
    pub lat: f64,
    pub lon: f64,
    pub eye: f64,
    pub target: f64,
    pub radius: f64,
    pub from: f64,
    pub span: f64,
    pub step: f64,
    pub k: f64,
}

impl Viewshed {
    fn azimuths(&self) -> Vec<f64> {
        let n = ((self.span / self.step).round() as usize).max(1) + if self.span >= 360.0 { 0 } else { 1 };
        (0..n).map(|i| (self.from + i as f64 * self.step).rem_euclid(360.0)).collect()
    }
    fn dists(&self) -> Vec<f64> {
        ray_distances(self.radius, 40.0, 40.0, 0.02)
    }
    pub fn plan(&self) -> BTreeSet<Key> {
        let dists = self.dists();
        let mut pts = vec![Sample { lat: self.lat, lon: self.lon, z: 12 }];
        for az in self.azimuths() {
            for &d in &dists {
                let (lat, lon) = destination(self.lat, self.lon, az, d);
                pts.push(Sample { lat, lon, z: zoom_for_distance(d) });
            }
        }
        needed_set(pts.into_iter())
    }
}

pub fn viewshed(field: &Field, v: &Viewshed) -> Result<Value, String> {
    let ground = field.elev(v.lat, v.lon, 12).ok_or("no terrain data at the observer position")?;
    let h0 = ground + v.eye;
    let dists = v.dists();
    let (mut seen, mut total) = (0usize, 0usize);
    let mut rays = vec![];
    for az in v.azimuths() {
        let mut maxang = f64::MIN;
        let mut segs: Vec<[f64; 2]> = vec![];
        let mut prev = 0.0;
        for &d in &dists {
            let (lat, lon) = destination(v.lat, v.lon, az, d);
            let Some(e) = field.elev(lat, lon, zoom_for_distance(d)) else { prev = d; continue };
            let drop = d * (1.0 - v.k) / (2.0 * R);
            let ground_ang = ((e - h0) / d).atan() - drop;
            let target_ang = ((e + v.target - h0) / d).atan() - drop;
            let visible = target_ang >= maxang;
            total += 1;
            if visible {
                seen += 1;
                let (a, b) = ((prev + d) / 2.0, d + (dists.iter().find(|&&x| x > d).copied().unwrap_or(d + 40.0) - d) / 2.0);
                match segs.last_mut() {
                    Some(l) if (l[1] - a).abs() < 1.0 => l[1] = b,
                    _ => segs.push([a, b]),
                }
            }
            maxang = maxang.max(ground_ang);
            prev = d;
        }
        rays.push(json!({ "az": r1(az), "segments": segs.iter().map(|s| [s[0].round(), s[1].round()]).collect::<Vec<_>>() }));
    }
    Ok(json!({
        "observer": { "lat": v.lat, "lon": v.lon, "ground_m": r1(ground), "eye_m": v.eye }, "target_height_m": v.target, "radius_km": v.radius / 1000.0,
        "visible_fraction": if total == 0 { 0.0 } else { (seen as f64 / total as f64 * 1000.0).round() / 1000.0 }, "rays": rays, "refraction_k": v.k,
        "note": "Segments are distance ranges (metres) along each azimuth where a target of the given height would be in sight. Terrain only.",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geodesy_helpers() {
        let (la, lo) = destination(0.0, 0.0, 90.0, 111_195.0);
        assert!(la.abs() < 1e-6 && (lo - 1.0).abs() < 1e-3);
        assert!((distance(0.0, 0.0, 0.0, 1.0) - 111_195.0).abs() < 5.0);
        assert!((bearing(0.0, 0.0, 1.0, 0.0)).abs() < 1e-9);
        let (la, lo) = interpolate(10.0, 10.0, 20.0, 30.0, 0.0);
        assert!((la - 10.0).abs() < 1e-9 && (lo - 10.0).abs() < 1e-9);
        let (la, lo) = interpolate(0.0, 0.0, 0.0, 10.0, 0.5);
        assert!(la.abs() < 1e-9 && (lo - 5.0).abs() < 1e-9);
    }

    #[test]
    fn distances_grow_and_stop() {
        let d = ray_distances(30_000.0, 30.0, 25.0, 0.012);
        assert_eq!(d[0], 30.0);
        assert!(*d.last().unwrap() <= 30_000.0 && *d.last().unwrap() > 29_000.0);
        assert!(d.windows(2).all(|w| w[1] - w[0] >= 25.0));
    }

    #[test]
    fn zoom_choices() {
        assert_eq!(zoom_for_distance(100.0), 12);
        assert_eq!(zoom_for_distance(30_000.0), 10);
        assert_eq!(zoom_for_distance(1.0e6), 8);
        assert!(zoom_for_spacing(30.0, 0.0) >= 12);
        assert!(zoom_for_spacing(5000.0, 60.0) <= 9);
    }
}

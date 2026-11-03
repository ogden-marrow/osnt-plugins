//! Geodesic maths on the WGS84 ellipsoid (Karney's algorithms via geographiclib-rs) and shape generators.

use geographiclib_rs::{DirectGeodesic, Geodesic, InverseGeodesic, PolygonArea, Winding};
use serde_json::{Value, json};

use crate::coords::LL;

pub fn inverse(a: LL, b: LL) -> (f64, f64, f64) {
    let g = Geodesic::wgs84();
    let (s12, azi1, azi2, _a12): (f64, f64, f64, f64) = g.inverse(a.lat, a.lon, b.lat, b.lon);
    (s12, (azi1 + 360.0) % 360.0, (azi2 + 360.0) % 360.0)
}

pub fn direct(a: LL, bearing: f64, dist: f64) -> LL {
    let g = Geodesic::wgs84();
    let (lat, lon, _): (f64, f64, f64) = g.direct(a.lat, a.lon, bearing, dist);
    LL { lat, lon: (lon + 540.0).rem_euclid(360.0) - 180.0 }
}

pub fn compass(az: f64) -> &'static str {
    const N: [&str; 16] = ["N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE", "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW"];
    N[((az.rem_euclid(360.0) / 22.5).round() as usize) % 16]
}

fn r(v: f64, p: i32) -> f64 {
    let k = 10f64.powi(p);
    (v * k).round() / k
}

/// Distance, bearings and midpoint for a path of points.
pub fn path(points: &[LL]) -> Value {
    let mut legs = vec![];
    let mut total = 0.0;
    for w in points.windows(2) {
        let (s, a1, a2) = inverse(w[0], w[1]);
        total += s;
        let mid = direct(w[0], a1, s / 2.0);
        legs.push(json!({ "from": [w[0].lat, w[0].lon], "to": [w[1].lat, w[1].lon], "meters": r(s, 3), "km": r(s / 1000.0, 6), "miles": r(s / 1609.344, 6), "nautical_miles": r(s / 1852.0, 6),
            "initial_bearing": (s > 1e-6).then(|| r(a1, 4)), "initial_compass": (s > 1e-6).then(|| compass(a1)), "final_bearing": (s > 1e-6).then(|| r(a2, 4)), "midpoint": { "lat": r(mid.lat, 7), "lon": r(mid.lon, 7) } }));
    }
    json!({ "legs": legs, "total_meters": r(total, 3), "total_km": r(total / 1000.0, 6), "total_miles": r(total / 1609.344, 6), "total_nautical_miles": r(total / 1852.0, 6),
            "method": "Karney geodesic on the WGS84 ellipsoid (sub-millimetre accuracy)" })
}

/// Walks a ring so that consecutive longitudes never jump by more than 180 degrees (the ring may then leave -180..180).
fn unwrap_ring(ring: &[LL]) -> Vec<(f64, f64)> {
    let mut out: Vec<(f64, f64)> = Vec::with_capacity(ring.len());
    for p in ring {
        let mut lon = p.lon;
        if let Some(prev) = out.last() {
            while lon - prev.0 > 180.0 {
                lon -= 360.0;
            }
            while lon - prev.0 < -180.0 {
                lon += 360.0;
            }
        }
        out.push((lon, p.lat));
    }
    out
}

/// Sutherland-Hodgman clip of a closed (lon, lat) ring to a longitude window.
fn clip_lon(ring: &[(f64, f64)], lo: f64, hi: f64) -> Vec<(f64, f64)> {
    let mut cur = ring.to_vec();
    for (edge, keep_greater) in [(lo, true), (hi, false)] {
        let inside = |p: &(f64, f64)| if keep_greater { p.0 >= edge } else { p.0 <= edge };
        let mut next = vec![];
        for i in 0..cur.len() {
            let (a, b) = (cur[i], cur[(i + 1) % cur.len()]);
            let cut = || {
                let t = (edge - a.0) / (b.0 - a.0);
                (edge, a.1 + t * (b.1 - a.1))
            };
            match (inside(&a), inside(&b)) {
                (true, true) => next.push(b),
                (true, false) => next.push(cut()),
                (false, true) => {
                    next.push(cut());
                    next.push(b);
                }
                _ => {}
            }
        }
        cur = next;
        if cur.is_empty() {
            break;
        }
    }
    cur
}

/// A polygon feature for a ring. A ring that crosses the antimeridian is cut there into a MultiPolygon (RFC 7946 section 3.1.9),
/// so no edge runs the long way round the world.
fn polygon_feature(ring: &[LL], props: Value) -> Value {
    let pts = unwrap_ring(ring);
    let (min, max) = pts.iter().fold((f64::MAX, f64::MIN), |(a, b), p| (a.min(p.0), b.max(p.0)));
    let close = |v: &[(f64, f64)]| -> Vec<Value> {
        let mut c: Vec<Value> = v.iter().map(|p| json!([r(p.0, 7), r(p.1, 7)])).collect();
        if let Some(f) = c.first().cloned() {
            c.push(f);
        }
        c
    };
    if min >= -180.0 && max <= 180.0 {
        return json!({ "type": "Feature", "properties": props, "geometry": { "type": "Polygon", "coordinates": [close(&pts)] } });
    }
    let mut parts = vec![];
    for k in -1..=1 {
        let off = 360.0 * k as f64;
        let clipped = clip_lon(&pts, -180.0 + off, 180.0 + off);
        if clipped.len() >= 3 {
            let shifted: Vec<(f64, f64)> = clipped.iter().map(|p| (p.0 - off, p.1)).collect();
            parts.push(json!([close(&shifted)]));
        }
    }
    let mut props = props;
    props["crosses_antimeridian"] = json!(true);
    json!({ "type": "Feature", "properties": props, "geometry": { "type": "MultiPolygon", "coordinates": parts } })
}

/// A box (south, west, north, east) as a polygon feature; west greater than east means the box crosses the antimeridian.
pub fn box_feature(b: [f64; 4], props: Value) -> Value {
    let e = if b[3] < b[1] { b[3] + 360.0 } else { b[3] };
    let ring = [LL { lat: b[0], lon: b[1] }, LL { lat: b[0], lon: e }, LL { lat: b[2], lon: e }, LL { lat: b[2], lon: b[1] }];
    polygon_feature(&ring, props)
}

/// Circle of `radius` metres around `c` as a polygon with `n` vertices (counter-clockwise).
pub fn circle(c: LL, radius: f64, n: usize) -> Value {
    let ring: Vec<LL> = (0..n).map(|i| direct(c, 360.0 * i as f64 / n as f64, radius)).collect();
    let pole = inverse(c, LL { lat: if c.lat >= 0.0 { 90.0 } else { -90.0 }, lon: 0.0 }).0 < radius;
    let mut f = polygon_feature(&ring, json!({ "kind": "circle", "radius_m": radius, "centre": [c.lat, c.lon] }));
    if pole {
        f["properties"]["encloses_pole"] = json!(true);
        f["properties"]["warning"] = json!("This circle contains a pole, so it cannot be drawn as an ordinary longitude/latitude polygon.");
    }
    f
}

/// Bounding box (south, west, north, east) of a circle of `radius` around `c`.
pub fn bbox_around(c: LL, radius: f64) -> [f64; 4] {
    let n = direct(c, 0.0, radius).lat;
    let s = direct(c, 180.0, radius).lat;
    let e = direct(c, 90.0, radius).lon;
    let w = direct(c, 270.0, radius).lon;
    [s, w, n, e]
}

/// Grid of square-ish cells of about `cell` metres over a box. Cell edges are parallels and meridians.
pub fn grid(b: [f64; 4], cell: f64, max_cells: usize) -> Result<Value, String> {
    let [s, w, n, e0] = b;
    let e = if e0 < w { e0 + 360.0 } else { e0 }; // west greater than east: the box crosses the antimeridian
    if !(s < n && w < e) {
        return Err("box must have south < north and west < east".into());
    }
    let mid = LL { lat: (s + n) / 2.0, lon: ((w + e) / 2.0 + 540.0).rem_euclid(360.0) - 180.0 };
    let dlat = (direct(mid, 0.0, cell).lat - mid.lat).abs();
    let dlon = ((direct(mid, 90.0, cell).lon - mid.lon + 540.0).rem_euclid(360.0) - 180.0).abs(); // wrapped: the box may straddle the date line
    let (rows, cols) = (((n - s) / dlat).ceil() as usize, ((e - w) / dlon).ceil() as usize);
    if rows * cols > max_cells {
        return Err(format!("that is {} cells; the limit is {max_cells}. Use a larger cell size or a smaller box", rows * cols));
    }
    let mut feats = vec![];
    for i in 0..rows {
        for j in 0..cols {
            let (s0, w0) = (s + i as f64 * dlat, w + j as f64 * dlon);
            let (n0, e0) = ((s0 + dlat).min(n), (w0 + dlon).min(e));
            feats.push(box_feature([s0, w0, n0, e0], json!({ "row": i, "col": j, "id": format!("R{}C{}", i + 1, j + 1) })));
        }
    }
    Ok(json!({ "type": "FeatureCollection", "features": feats, "properties": { "rows": rows, "cols": cols, "cell_m": cell } }))
}

pub fn ring_stats(ring: &[(f64, f64)]) -> (f64, f64) {
    let g = Geodesic::wgs84();
    let mut pa = PolygonArea::new(&g, Winding::CounterClockwise);
    for (lat, lon) in ring.iter().take(ring.len().saturating_sub(1)) {
        pa.add_point(*lat, *lon);
    }
    let (perimeter, area, _) = pa.compute(true);
    (perimeter, area.abs())
}

pub fn line_length(pts: &[(f64, f64)]) -> f64 {
    pts.windows(2).map(|w| inverse(LL { lat: w[0].0, lon: w[0].1 }, LL { lat: w[1].0, lon: w[1].1 }).0).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_points_have_no_bearing() {
        let p = LL { lat: 10.0, lon: 20.0 };
        let v = path(&[p, p]);
        assert_eq!(v["legs"][0]["meters"], 0.0);
        assert!(v["legs"][0]["initial_bearing"].is_null());
    }

    fn lons(v: &Value) -> Vec<f64> {
        fn walk(x: &Value, out: &mut Vec<f64>) {
            match x.as_array() {
                Some(a) if a.len() == 2 && a[0].is_f64() => out.push(a[0].as_f64().unwrap()),
                Some(a) => a.iter().for_each(|y| walk(y, out)),
                None => {}
            }
        }
        let mut out = vec![];
        walk(&v["geometry"]["coordinates"], &mut out);
        out
    }

    #[test]
    fn circle_across_the_date_line_is_cut_into_two_polygons() {
        let f = circle(LL { lat: 0.0, lon: 179.9 }, 30_000.0, 72);
        assert_eq!(f["geometry"]["type"], "MultiPolygon", "{f}");
        assert_eq!(f["properties"]["crosses_antimeridian"], true);
        assert_eq!(f["geometry"]["coordinates"].as_array().unwrap().len(), 2);
        assert!(lons(&f).iter().all(|l| (-180.0..=180.0).contains(l)));
        // both halves touch the line, and no edge spans more than a degree
        for poly in f["geometry"]["coordinates"].as_array().unwrap() {
            let l: Vec<f64> = poly[0].as_array().unwrap().iter().map(|p| p[0].as_f64().unwrap()).collect();
            assert!(l.iter().cloned().fold(f64::MIN, f64::max) - l.iter().cloned().fold(f64::MAX, f64::min) < 1.0, "{l:?}");
        }
        let plain = circle(LL { lat: 0.0, lon: 10.0 }, 30_000.0, 72);
        assert_eq!(plain["geometry"]["type"], "Polygon");
    }

    #[test]
    fn grid_and_box_across_the_date_line() {
        let g = grid([0.0, 179.9, 0.2, -179.9], 10_000.0, 1000).unwrap();
        let feats = g["features"].as_array().unwrap();
        assert!(feats.len() >= 4, "{}", feats.len());
        assert!(feats.iter().all(|f| lons(f).iter().all(|l| (-180.0..=180.0).contains(l))));
        assert!(feats.iter().any(|f| f["geometry"]["type"] == "MultiPolygon"));
        let b = box_feature([0.0, 179.0, 1.0, -179.0], json!({}));
        assert_eq!(b["geometry"]["type"], "MultiPolygon");
    }

    #[test]
    fn circle_around_a_pole_is_flagged() {
        let f = circle(LL { lat: 89.99, lon: 0.0 }, 30_000.0, 16);
        assert_eq!(f["properties"]["encloses_pole"], true);
    }

    #[test]
    fn karney_reference_distance() {
        // Karney's published example: Wellington to Salamanca, 19959679.267 m.
        let (s, a1, _) = inverse(LL { lat: -41.32, lon: 174.81 }, LL { lat: 40.96, lon: -5.50 });
        assert!((s - 19_959_679.267).abs() < 0.01, "{s}");
        assert!((a1 - 161.06).abs() < 0.1 || (a1 - 160.0).abs() < 5.0, "{a1}");
        // JFK to LHR is about 5555 km.
        let (s, ..) = inverse(LL { lat: 40.6413, lon: -73.7781 }, LL { lat: 51.4700, lon: -0.4543 });
        assert!((s / 1000.0 - 5554.0).abs() < 8.0, "{s}");
    }

    #[test]
    fn direct_inverse_round_trip() {
        let a = LL { lat: 10.0, lon: 20.0 };
        let b = direct(a, 77.0, 123_456.0);
        let (s, az, _) = inverse(a, b);
        assert!((s - 123_456.0).abs() < 1e-6 && (az - 77.0).abs() < 1e-8);
        let w = direct(LL { lat: 0.0, lon: 179.9 }, 90.0, 50_000.0);
        assert!(w.lon < 0.0 && w.lon > -180.0, "wraps the date line: {w:?}");
    }

    #[test]
    fn path_totals() {
        let p = path(&[LL { lat: 0.0, lon: 0.0 }, LL { lat: 0.0, lon: 1.0 }, LL { lat: 1.0, lon: 1.0 }]);
        assert_eq!(p["legs"].as_array().unwrap().len(), 2);
        assert!((p["total_km"].as_f64().unwrap() - 221.2).abs() < 1.0);
        assert!((p["legs"][0]["initial_bearing"].as_f64().unwrap() - 90.0).abs() < 1e-6);
        assert_eq!(p["legs"][0]["initial_compass"], "E");
    }

    #[test]
    fn circle_vertices_are_on_the_circle() {
        let c = LL { lat: 48.0, lon: 2.0 };
        let f = circle(c, 5000.0, 36);
        let ring = f["geometry"]["coordinates"][0].as_array().unwrap();
        assert_eq!(ring.len(), 37);
        assert_eq!(ring[0], ring[36]);
        for p in ring {
            let (s, ..) = inverse(c, LL { lat: p[1].as_f64().unwrap(), lon: p[0].as_f64().unwrap() });
            assert!((s - 5000.0).abs() < 0.05, "{s}");
        }
    }

    #[test]
    fn bbox_and_grid() {
        let b = bbox_around(LL { lat: 0.0, lon: 0.0 }, 111_319.49);
        assert!((b[2] - 1.0067).abs() < 0.001 && (b[3] - 1.0).abs() < 0.001, "{b:?}");
        let g = grid([0.0, 0.0, 0.1, 0.1], 2000.0, 1000).unwrap();
        assert_eq!(g["properties"]["rows"], 6);
        assert_eq!(g["features"].as_array().unwrap().len(), 36);
        assert!(grid([0.0, 0.0, 10.0, 10.0], 100.0, 1000).is_err());
        assert!(grid([1.0, 0.0, 0.0, 1.0], 100.0, 1000).is_err());
    }

    #[test]
    fn polygon_area_of_a_degree_square() {
        let ring = [(0.0, 0.0), (0.0, 1.0), (1.0, 1.0), (1.0, 0.0), (0.0, 0.0)];
        let (p, a) = ring_stats(&ring);
        assert!((a / 1e6 - 12_308.8).abs() < 5.0, "{a}");
        assert!((p / 1000.0 - 443.8).abs() < 1.0, "{p}");
        let (_, a2) = ring_stats(&[(0.0, 0.0), (1.0, 0.0), (1.0, 1.0), (0.0, 1.0), (0.0, 0.0)]);
        assert!((a - a2).abs() < 1.0, "orientation must not matter");
    }
}

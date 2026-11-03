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
            "initial_bearing": r(a1, 4), "initial_compass": compass(a1), "final_bearing": r(a2, 4), "midpoint": { "lat": r(mid.lat, 7), "lon": r(mid.lon, 7) } }));
    }
    json!({ "legs": legs, "total_meters": r(total, 3), "total_km": r(total / 1000.0, 6), "total_miles": r(total / 1609.344, 6), "total_nautical_miles": r(total / 1852.0, 6),
            "method": "Karney geodesic on the WGS84 ellipsoid (sub-millimetre accuracy)" })
}

fn polygon_feature(ring: &[LL], props: Value) -> Value {
    let mut coords: Vec<Value> = ring.iter().map(|p| json!([r(p.lon, 7), r(p.lat, 7)])).collect();
    if let Some(f) = coords.first().cloned() {
        coords.push(f);
    }
    json!({ "type": "Feature", "properties": props, "geometry": { "type": "Polygon", "coordinates": [coords] } })
}

/// Circle of `radius` metres around `c` as a polygon with `n` vertices (counter-clockwise).
pub fn circle(c: LL, radius: f64, n: usize) -> Value {
    let ring: Vec<LL> = (0..n).map(|i| direct(c, 360.0 * i as f64 / n as f64, radius)).collect();
    polygon_feature(&ring, json!({ "kind": "circle", "radius_m": radius, "centre": [c.lat, c.lon] }))
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
    let [s, w, n, e] = b;
    if !(s < n && w < e) {
        return Err("box must have south < north and west < east".into());
    }
    let mid = LL { lat: (s + n) / 2.0, lon: (w + e) / 2.0 };
    let dlat = (direct(mid, 0.0, cell).lat - mid.lat).abs();
    let dlon = (direct(mid, 90.0, cell).lon - mid.lon).abs();
    let (rows, cols) = (((n - s) / dlat).ceil() as usize, ((e - w) / dlon).ceil() as usize);
    if rows * cols > max_cells {
        return Err(format!("that is {} cells; the limit is {max_cells}. Use a larger cell size or a smaller box", rows * cols));
    }
    let mut feats = vec![];
    for i in 0..rows {
        for j in 0..cols {
            let (s0, w0) = (s + i as f64 * dlat, w + j as f64 * dlon);
            let (n0, e0) = ((s0 + dlat).min(n), (w0 + dlon).min(e));
            let ring = [LL { lat: s0, lon: w0 }, LL { lat: s0, lon: e0 }, LL { lat: n0, lon: e0 }, LL { lat: n0, lon: w0 }];
            feats.push(polygon_feature(&ring, json!({ "row": i, "col": j, "id": format!("R{}C{}", i + 1, j + 1) })));
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

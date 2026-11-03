//! GeoJSON clean-up (normalise, validate, round, drop junk), statistics and KML / GPX export.

use serde_json::{Map, Value, json};

use crate::geodesy::{line_length, ring_stats};

const TYPES: &[&str] = &["Point", "MultiPoint", "LineString", "MultiLineString", "Polygon", "MultiPolygon"];

pub struct Cleaned {
    pub collection: Value,
    pub warnings: Vec<String>,
}

fn rnd(v: f64, d: i32) -> f64 {
    let k = 10f64.powi(d);
    (v * k).round() / k
}

fn pos(v: &Value, d: i32) -> Option<(f64, f64)> {
    let a = v.as_array()?;
    let (lon, lat) = (a.first()?.as_f64()?, a.get(1)?.as_f64()?);
    (lat.abs() <= 90.0 && lon.abs() <= 180.0 && lat.is_finite() && lon.is_finite()).then(|| (rnd(lon, d), rnd(lat, d)))
}

fn line(v: &Value, d: i32, min: usize, w: &mut Vec<String>) -> Option<Vec<(f64, f64)>> {
    let arr = v.as_array()?;
    let mut out: Vec<(f64, f64)> = vec![];
    for p in arr {
        match pos(p, d) {
            Some(x) => {
                if out.last() != Some(&x) {
                    out.push(x);
                }
            }
            None => w.push("a position was out of range or malformed and was dropped".into()),
        }
    }
    (out.len() >= min).then_some(out)
}

fn ring(v: &Value, d: i32, w: &mut Vec<String>) -> Option<Vec<(f64, f64)>> {
    let mut r = line(v, d, 3, w)?;
    if r.first() != r.last() {
        r.push(r[0]);
        w.push("an unclosed polygon ring was closed".into());
    }
    (r.len() >= 4).then_some(r)
}

fn coords(l: &[(f64, f64)]) -> Value {
    Value::Array(l.iter().map(|(x, y)| json!([x, y])).collect())
}

/// Returns a cleaned geometry or None (with warnings) when nothing valid is left.
pub fn clean_geometry(g: &Value, d: i32, w: &mut Vec<String>) -> Option<Value> {
    let t = g["type"].as_str()?;
    if !TYPES.contains(&t) {
        w.push(format!("geometry type {t} is not supported and was dropped"));
        return None;
    }
    let c = &g["coordinates"];
    let out = match t {
        "Point" => pos(c, d).map(|(x, y)| json!([x, y])),
        "MultiPoint" => {
            let v: Vec<Value> = c.as_array()?.iter().filter_map(|p| pos(p, d)).map(|(x, y)| json!([x, y])).collect();
            (!v.is_empty()).then(|| Value::Array(v))
        }
        "LineString" => line(c, d, 2, w).map(|l| coords(&l)),
        "MultiLineString" => {
            let v: Vec<Value> = c.as_array()?.iter().filter_map(|l| line(l, d, 2, w)).map(|l| coords(&l)).collect();
            (!v.is_empty()).then(|| Value::Array(v))
        }
        "Polygon" => {
            let rings: Vec<Value> = c.as_array()?.iter().filter_map(|r| ring(r, d, w)).map(|l| coords(&l)).collect();
            (!rings.is_empty()).then(|| Value::Array(rings))
        }
        _ => {
            let polys: Vec<Value> = c
                .as_array()?
                .iter()
                .filter_map(|p| {
                    let rings: Vec<Value> = p.as_array()?.iter().filter_map(|r| ring(r, d, w)).map(|l| coords(&l)).collect();
                    (!rings.is_empty()).then(|| Value::Array(rings))
                })
                .collect();
            (!polys.is_empty()).then(|| Value::Array(polys))
        }
    };
    match out {
        Some(c) => Some(json!({ "type": t, "coordinates": c })),
        None => {
            w.push(format!("an empty or invalid {t} was dropped"));
            None
        }
    }
}

fn flatten(v: &Value, props: &Value, out: &mut Vec<(Value, Value)>, w: &mut Vec<String>) {
    match v["type"].as_str() {
        Some("FeatureCollection") => v["features"].as_array().into_iter().flatten().for_each(|f| flatten(f, &Value::Null, out, w)),
        Some("Feature") => {
            let p = if v["properties"].is_object() { v["properties"].clone() } else { json!({}) };
            if v["geometry"].is_null() {
                w.push("a feature without geometry was dropped".into());
            } else {
                flatten(&v["geometry"], &p, out, w);
            }
        }
        Some("GeometryCollection") => v["geometries"].as_array().into_iter().flatten().for_each(|g| flatten(g, props, out, w)),
        Some(_) => out.push((v.clone(), if props.is_object() { props.clone() } else { json!({}) })),
        None => w.push("an object without a GeoJSON type was ignored".into()),
    }
}

pub fn clean(input: &Value, decimals: i32, keep_properties: bool) -> Result<Cleaned, String> {
    let mut w = vec![];
    let mut raw = vec![];
    flatten(input, &Value::Null, &mut raw, &mut w);
    if raw.is_empty() && w.is_empty() {
        return Err("no GeoJSON features found".into());
    }
    let mut features = vec![];
    for (g, p) in raw {
        if let Some(cg) = clean_geometry(&g, decimals, &mut w) {
            features.push(json!({ "type": "Feature", "properties": if keep_properties { p } else { json!({}) }, "geometry": cg }));
        }
    }
    if features.is_empty() {
        return Err(format!("nothing valid left after cleaning ({})", w.first().cloned().unwrap_or_default()));
    }
    w.sort();
    w.dedup();
    Ok(Cleaned { collection: json!({ "type": "FeatureCollection", "features": features }), warnings: w })
}

fn tuples(v: &Value) -> Vec<(f64, f64)> {
    v.as_array().map(|a| a.iter().filter_map(|p| Some((p[1].as_f64()?, p[0].as_f64()?))).collect()).unwrap_or_default()
}

fn walk(v: &Value, f: &mut impl FnMut(f64, f64)) {
    match v {
        Value::Array(a) if a.len() >= 2 && a[0].is_number() => f(a[1].as_f64().unwrap_or(0.0), a[0].as_f64().unwrap_or(0.0)),
        Value::Array(a) => a.iter().for_each(|x| walk(x, f)),
        _ => {}
    }
}

pub fn stats(fc: &Value) -> Value {
    let mut counts: Map<String, Value> = Map::new();
    let (mut len, mut area, mut perim) = (0.0, 0.0, 0.0);
    let (mut s, mut w, mut n, mut e) = (91.0f64, 181.0f64, -91.0f64, -181.0f64);
    let mut positions = 0;
    for f in fc["features"].as_array().into_iter().flatten() {
        let g = &f["geometry"];
        let t = g["type"].as_str().unwrap_or("?");
        let c = counts.get(t).and_then(Value::as_u64).unwrap_or(0) + 1;
        counts.insert(t.into(), json!(c));
        walk(&g["coordinates"], &mut |la, lo| {
            positions += 1;
            s = s.min(la);
            n = n.max(la);
            w = w.min(lo);
            e = e.max(lo);
        });
        let add_poly = |rings: &Value, area: &mut f64, perim: &mut f64| {
            for (i, r) in rings.as_array().into_iter().flatten().enumerate() {
                let (p, a) = ring_stats(&tuples(r));
                if i == 0 {
                    *area += a;
                    *perim += p;
                } else {
                    *area -= a;
                }
            }
        };
        match t {
            "LineString" => len += line_length(&tuples(&g["coordinates"])),
            "MultiLineString" => g["coordinates"].as_array().into_iter().flatten().for_each(|l| len += line_length(&tuples(l))),
            "Polygon" => add_poly(&g["coordinates"], &mut area, &mut perim),
            "MultiPolygon" => g["coordinates"].as_array().into_iter().flatten().for_each(|p| add_poly(p, &mut area, &mut perim)),
            _ => {}
        }
    }
    json!({ "features": fc["features"].as_array().map(Vec::len), "positions": positions, "types": counts, "bbox": if positions > 0 { json!([w, s, e, n]) } else { Value::Null },
            "line_length_m": rnd(len, 2), "polygon_area_m2": rnd(area, 1), "polygon_perimeter_m": rnd(perim, 2) })
}

fn esc(s: &str) -> String {
    s.chars().filter(|c| !c.is_control() || *c == '\n').collect::<String>().replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

fn name_of(f: &Value, i: usize) -> String {
    ["name", "title", "label", "id"].iter().find_map(|k| f["properties"][*k].as_str().map(str::to_string).or_else(|| f["properties"][*k].as_i64().map(|n| n.to_string()))).unwrap_or_else(|| format!("Feature {}", i + 1))
}

fn kml_coords(l: &Value) -> String {
    l.as_array().into_iter().flatten().filter_map(|p| Some(format!("{},{}", p[0].as_f64()?, p[1].as_f64()?))).collect::<Vec<_>>().join(" ")
}

fn kml_geom(g: &Value) -> String {
    let c = &g["coordinates"];
    let poly = |rings: &Value| {
        let mut s = String::from("<Polygon>");
        for (i, r) in rings.as_array().into_iter().flatten().enumerate() {
            let tag = if i == 0 { "outerBoundaryIs" } else { "innerBoundaryIs" };
            s += &format!("<{tag}><LinearRing><coordinates>{}</coordinates></LinearRing></{tag}>", kml_coords(r));
        }
        s + "</Polygon>"
    };
    match g["type"].as_str().unwrap_or("") {
        "Point" => format!("<Point><coordinates>{},{}</coordinates></Point>", c[0], c[1]),
        "MultiPoint" => format!("<MultiGeometry>{}</MultiGeometry>", c.as_array().into_iter().flatten().map(|p| format!("<Point><coordinates>{},{}</coordinates></Point>", p[0], p[1])).collect::<String>()),
        "LineString" => format!("<LineString><coordinates>{}</coordinates></LineString>", kml_coords(c)),
        "MultiLineString" => format!("<MultiGeometry>{}</MultiGeometry>", c.as_array().into_iter().flatten().map(|l| format!("<LineString><coordinates>{}</coordinates></LineString>", kml_coords(l))).collect::<String>()),
        "Polygon" => poly(c),
        "MultiPolygon" => format!("<MultiGeometry>{}</MultiGeometry>", c.as_array().into_iter().flatten().map(poly).collect::<String>()),
        _ => String::new(),
    }
}

pub fn to_kml(fc: &Value, title: &str) -> String {
    let mut s = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<kml xmlns=\"http://www.opengis.net/kml/2.2\"><Document><name>{}</name>\n", esc(title));
    for (i, f) in fc["features"].as_array().into_iter().flatten().enumerate() {
        let desc: Vec<String> = f["properties"].as_object().into_iter().flatten().filter(|(k, _)| !["name", "title"].contains(&k.as_str())).filter_map(|(k, v)| Some(format!("{k}: {}", v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())))).take(20).collect();
        s += &format!("<Placemark><name>{}</name>{}{}</Placemark>\n", esc(&name_of(f, i)), if desc.is_empty() { String::new() } else { format!("<description>{}</description>", esc(&desc.join("\n"))) }, kml_geom(&f["geometry"]));
    }
    s + "</Document></kml>\n"
}

pub fn to_gpx(fc: &Value, title: &str) -> String {
    let mut s = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<gpx version=\"1.1\" creator=\"OSNT geo-toolkit\" xmlns=\"http://www.topografix.com/GPX/1/1\"><metadata><name>{}</name></metadata>\n", esc(title));
    let trk = |name: &str, segs: Vec<&Value>| {
        let mut t = format!("<trk><name>{}</name>", esc(name));
        for seg in segs {
            t += "<trkseg>";
            for p in seg.as_array().into_iter().flatten() {
                if let (Some(lon), Some(lat)) = (p[0].as_f64(), p[1].as_f64()) {
                    t += &format!("<trkpt lat=\"{lat}\" lon=\"{lon}\"/>");
                }
            }
            t += "</trkseg>";
        }
        t + "</trk>\n"
    };
    let wpt = |name: &str, p: &Value| format!("<wpt lat=\"{}\" lon=\"{}\"><name>{}</name></wpt>\n", p[1], p[0], esc(name));
    for (i, f) in fc["features"].as_array().into_iter().flatten().enumerate() {
        let (g, name) = (&f["geometry"], name_of(f, i));
        let c = &g["coordinates"];
        match g["type"].as_str().unwrap_or("") {
            "Point" => s += &wpt(&name, c),
            "MultiPoint" => c.as_array().into_iter().flatten().for_each(|p| s += &wpt(&name, p)),
            "LineString" => s += &trk(&name, vec![c]),
            "MultiLineString" => s += &trk(&name, c.as_array().into_iter().flatten().collect()),
            "Polygon" => s += &trk(&name, c.as_array().into_iter().flatten().collect()),
            "MultiPolygon" => s += &trk(&name, c.as_array().into_iter().flatten().flat_map(|p| p.as_array().into_iter().flatten()).collect()),
            _ => {}
        }
    }
    s + "</gpx>\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flattens_cleans_and_rounds() {
        let input = json!({ "type": "FeatureCollection", "features": [
            { "type": "Feature", "properties": { "name": "A & B" }, "geometry": { "type": "Point", "coordinates": [2.29445555, 48.8583701, 35.0] } },
            { "type": "Feature", "properties": null, "geometry": { "type": "LineString", "coordinates": [[0, 0], [0, 0], [1, 1], [200, 5]] } },
            { "type": "Feature", "properties": {}, "geometry": { "type": "Polygon", "coordinates": [[[0, 0], [0, 1], [1, 1], [1, 0]]] } },
            { "type": "Feature", "properties": {}, "geometry": { "type": "LineString", "coordinates": [[5, 5]] } },
            { "type": "Feature", "properties": {}, "geometry": null },
            { "type": "Feature", "properties": {}, "geometry": { "type": "Circle", "coordinates": [1, 1] } } ] });
        let c = clean(&input, 4, true).unwrap();
        let f = c.collection["features"].as_array().unwrap();
        assert_eq!(f.len(), 3);
        assert_eq!(f[0]["geometry"]["coordinates"], json!([2.2945, 48.8584]), "z dropped, rounded");
        assert_eq!(f[1]["geometry"]["coordinates"], json!([[0.0, 0.0], [1.0, 1.0]]), "duplicate and out-of-range dropped");
        assert_eq!(f[2]["geometry"]["coordinates"][0].as_array().unwrap().len(), 5, "ring closed");
        assert_eq!(f[1]["properties"], json!({}));
        assert!(c.warnings.iter().any(|x| x.contains("closed")) && c.warnings.iter().any(|x| x.contains("Circle")));
        let c2 = clean(&input, 4, false).unwrap();
        assert_eq!(c2.collection["features"][0]["properties"], json!({}));
    }

    #[test]
    fn accepts_bare_geometry_feature_and_collection() {
        assert_eq!(clean(&json!({ "type": "Point", "coordinates": [1, 2] }), 6, true).unwrap().collection["features"].as_array().unwrap().len(), 1);
        let gc = json!({ "type": "GeometryCollection", "geometries": [{ "type": "Point", "coordinates": [1, 2] }, { "type": "Point", "coordinates": [3, 4] }] });
        assert_eq!(clean(&gc, 6, true).unwrap().collection["features"].as_array().unwrap().len(), 2);
        assert!(clean(&json!({ "hello": 1 }), 6, true).is_err());
        assert!(clean(&json!({ "type": "Point", "coordinates": [500, 2] }), 6, true).is_err());
        assert!(clean(&json!([]), 6, true).is_err());
    }

    #[test]
    fn statistics() {
        let fc = clean(&json!({ "type": "FeatureCollection", "features": [
            { "type": "Feature", "properties": {}, "geometry": { "type": "Polygon", "coordinates": [[[0, 0], [1, 0], [1, 1], [0, 1], [0, 0]]] } },
            { "type": "Feature", "properties": {}, "geometry": { "type": "LineString", "coordinates": [[0, 0], [1, 0]] } } ] }), 6, true).unwrap().collection;
        let s = stats(&fc);
        assert!((s["polygon_area_m2"].as_f64().unwrap() / 1e6 - 12_308.8).abs() < 5.0);
        assert!((s["line_length_m"].as_f64().unwrap() / 1000.0 - 111.32).abs() < 0.1);
        assert_eq!(s["bbox"], json!([0.0, 0.0, 1.0, 1.0]));
        assert_eq!(s["types"]["Polygon"], 1);
    }

    #[test]
    fn kml_and_gpx_export() {
        let fc = clean(&json!({ "type": "FeatureCollection", "features": [
            { "type": "Feature", "properties": { "name": "Tower <1>", "height": 330 }, "geometry": { "type": "Point", "coordinates": [2.2945, 48.8584] } },
            { "type": "Feature", "properties": {}, "geometry": { "type": "LineString", "coordinates": [[0, 0], [1, 1]] } },
            { "type": "Feature", "properties": {}, "geometry": { "type": "Polygon", "coordinates": [[[0, 0], [1, 0], [1, 1], [0, 0]]] } } ] }), 6, true).unwrap().collection;
        let kml = to_kml(&fc, "T & T");
        assert!(kml.contains("<name>T &amp; T</name>") && kml.contains("<name>Tower &lt;1&gt;</name>"));
        assert!(kml.contains("<Point><coordinates>2.2945,48.8584</coordinates></Point>"));
        assert!(kml.contains("<LineString><coordinates>0,0 1,1</coordinates>") && kml.contains("<outerBoundaryIs><LinearRing>"));
        assert!(kml.contains("height: 330"));
        let gpx = to_gpx(&fc, "x");
        assert!(gpx.contains("<wpt lat=\"48.8584\" lon=\"2.2945\">") && gpx.contains("<trkpt lat=\"1\" lon=\"1\"/>") && gpx.matches("<trk>").count() == 2);
    }
}

//! Feature presets and the Overpass QL they compile to. Everything user-supplied is validated and quoted here.

use serde_json::{Value, json};

pub struct Preset {
    pub id: &'static str,
    pub label: &'static str,
    pub help: &'static str,
    /// (key, accepted values); an empty list means "the key exists".
    pub sel: &'static [(&'static str, &'static [&'static str])],
}

pub const PRESETS: &[Preset] = &[
    Preset { id: "towers", label: "Towers and masts", help: "Communication towers, masts and other towers", sel: &[("man_made", &["tower", "communications_tower", "mast"])] },
    Preset { id: "bridges", label: "Bridges", help: "Bridge ways (roads, rail and paths)", sel: &[("bridge", &["yes", "viaduct", "movable", "suspension", "cantilever", "arch", "cable-stayed", "truss", "beam"]), ("man_made", &["bridge"])] },
    Preset { id: "fuel", label: "Fuel stations", help: "amenity=fuel", sel: &[("amenity", &["fuel"])] },
    Preset { id: "rail_crossings", label: "Rail crossings", help: "Level crossings and pedestrian rail crossings", sel: &[("railway", &["level_crossing", "crossing"])] },
    Preset { id: "military", label: "Military sites", help: "Anything tagged military=*, and military landuse", sel: &[("military", &[]), ("landuse", &["military"])] },
    Preset { id: "airports", label: "Airfields and helipads", help: "Aerodromes and helipads", sel: &[("aeroway", &["aerodrome", "helipad"])] },
    Preset { id: "substations", label: "Power substations and plants", help: "power=substation or plant", sel: &[("power", &["substation", "plant"])] },
    Preset { id: "lighthouses", label: "Lighthouses", help: "man_made=lighthouse", sel: &[("man_made", &["lighthouse"])] },
    Preset { id: "ports", label: "Ports and ferry terminals", help: "Harbours, ferry terminals", sel: &[("landuse", &["harbour"]), ("harbour", &["yes"]), ("amenity", &["ferry_terminal"])] },
    Preset { id: "hospitals", label: "Hospitals", help: "amenity=hospital", sel: &[("amenity", &["hospital"])] },
    Preset { id: "border", label: "Border crossings", help: "barrier=border_control", sel: &[("barrier", &["border_control"])] },
    Preset { id: "water_towers", label: "Water towers and tanks", help: "Water towers, storage tanks, silos", sel: &[("man_made", &["water_tower", "storage_tank", "silo"])] },
    Preset { id: "chimneys", label: "Chimneys", help: "man_made=chimney", sel: &[("man_made", &["chimney"])] },
    Preset { id: "wind", label: "Wind turbines", help: "Wind turbines", sel: &[("generator:source", &["wind"])] },
    Preset { id: "stadiums", label: "Stadiums and arenas", help: "leisure=stadium", sel: &[("leisure", &["stadium"])] },
    Preset { id: "peaks", label: "Peaks", help: "natural=peak (useful against a skyline)", sel: &[("natural", &["peak"])] },
];

pub fn find(id: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.id == id)
}

pub fn list_json() -> Value {
    Value::Array(PRESETS.iter().map(|p| json!({ "id": p.id, "label": p.label, "help": p.help })).collect())
}

/// Characters allowed in a key or value typed by the user.
pub fn safe_token(s: &str, allow_space: bool) -> bool {
    !s.is_empty() && s.len() <= 60 && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | ':' | '.' | '-') || (allow_space && c == ' '))
}

/// The selectors of a feature set: a preset, or one custom key (and optional value).
#[derive(Clone, Debug)]
pub struct Selectors(pub Vec<(String, Vec<String>)>);

impl Selectors {
    pub fn preset(p: &Preset) -> Self {
        Selectors(p.sel.iter().map(|(k, v)| (k.to_string(), v.iter().map(|x| x.to_string()).collect())).collect())
    }
    pub fn custom(key: &str, value: Option<&str>) -> Result<Self, String> {
        if !safe_token(key, false) {
            return Err("tag key may only contain letters, digits and _ : . -".into());
        }
        let vals = match value {
            Some(v) if !v.is_empty() => {
                if !safe_token(v, true) {
                    return Err("tag value may only contain letters, digits, spaces and _ : . -".into());
                }
                vec![v.to_string()]
            }
            _ => vec![],
        };
        Ok(Selectors(vec![(key.to_string(), vals)]))
    }
    /// One Overpass statement per selector, restricted to `area` such as `(around:500,1.0,2.0)` or `(s,w,n,e)`.
    pub fn statements(&self, area: &str) -> String {
        let mut out = String::new();
        for (k, vals) in &self.0 {
            let filter = match vals.len() {
                0 => format!("[\"{k}\"]"),
                1 => format!("[\"{k}\"=\"{}\"]", vals[0]),
                _ => format!("[\"{k}\"~\"^({})$\"]", vals.join("|")),
            };
            out.push_str(&format!("nwr{filter}{area};"));
        }
        out
    }
    pub fn matches(&self, tags: &serde_json::Map<String, Value>) -> bool {
        self.0.iter().any(|(k, vals)| match tags.get(k).and_then(Value::as_str) {
            None => false,
            Some(v) => vals.is_empty() || vals.iter().any(|x| x == v),
        })
    }
}

#[derive(Clone, Debug)]
pub enum Area {
    Around { lat: f64, lon: f64, radius: f64 },
    Bbox { s: f64, w: f64, n: f64, e: f64 },
}

impl Area {
    pub fn clause(&self, extra_m: f64) -> String {
        match *self {
            Area::Around { lat, lon, radius } => format!("(around:{:.0},{lat:.6},{lon:.6})", radius + extra_m),
            Area::Bbox { s, w, n, e } => {
                let dlat = extra_m / 111_320.0;
                let dlon = extra_m / (111_320.0 * ((s + n) / 2.0).to_radians().cos().max(0.05));
                format!("({:.6},{:.6},{:.6},{:.6})", (s - dlat).max(-90.0), w - dlon, (n + dlat).min(90.0), e + dlon)
            }
        }
    }
}

/// Compiles a find request. `near` adds the "feature A within `dist` metres of feature B" filter.
pub fn compile(a: &Selectors, area: &Area, near: Option<(&Selectors, f64)>, limit: u32) -> String {
    let head = "[out:json][timeout:25];";
    match near {
        None => format!("{head}({});out center tags {limit};", a.statements(&area.clause(0.0))),
        Some((b, d)) => format!(
            "{head}({})->.a;({})->.b;nwr.a(around.b:{d:.0})->.ma;nwr.b(around.ma:{d:.0})->.mb;(.ma;.mb;);out center tags {limit};",
            a.statements(&area.clause(0.0)),
            b.statements(&area.clause(d))
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_compiles_to_ql() {
        let s = Selectors::preset(find("fuel").unwrap());
        let q = compile(&s, &Area::Around { lat: 47.0, lon: 8.0, radius: 500.0 }, None, 100);
        assert_eq!(q, "[out:json][timeout:25];(nwr[\"amenity\"=\"fuel\"](around:500,47.000000,8.000000););out center tags 100;");
        let s = Selectors::preset(find("military").unwrap());
        let q = compile(&s, &Area::Bbox { s: 1.0, w: 2.0, n: 3.0, e: 4.0 }, None, 5);
        assert!(q.contains("nwr[\"military\"](1.000000,2.000000,3.000000,4.000000);nwr[\"landuse\"=\"military\"]"), "{q}");
    }

    #[test]
    fn multi_value_uses_regex_and_near_filter() {
        let a = Selectors::preset(find("bridges").unwrap());
        let b = Selectors::preset(find("rail_crossings").unwrap());
        let q = compile(&a, &Area::Around { lat: 1.0, lon: 2.0, radius: 1000.0 }, Some((&b, 200.0)), 50);
        assert!(q.contains("[\"railway\"~\"^(level_crossing|crossing)$\"](around:1200,"), "{q}");
        assert!(q.contains("nwr.a(around.b:200)->.ma;nwr.b(around.ma:200)->.mb;"), "{q}");
    }

    #[test]
    fn custom_tags_are_validated() {
        assert!(Selectors::custom("amenity", Some("fuel")).is_ok());
        assert!(Selectors::custom("name", Some("Café Central")).is_err());
        assert!(Selectors::custom("a\"];out;", None).is_err());
        assert!(Selectors::custom("amenity", Some("x\"]")).is_err());
        assert_eq!(Selectors::custom("shop", None).unwrap().statements("(1,2,3,4)"), "nwr[\"shop\"](1,2,3,4);");
    }

    #[test]
    fn matching() {
        let s = Selectors::preset(find("military").unwrap());
        let tags = json!({ "military": "barracks" });
        assert!(s.matches(tags.as_object().unwrap()));
        let tags = json!({ "landuse": "forest" });
        assert!(!s.matches(tags.as_object().unwrap()));
        let tags = json!({ "landuse": "military" });
        assert!(s.matches(tags.as_object().unwrap()));
    }

    #[test]
    fn bbox_expansion_for_near() {
        let c = Area::Bbox { s: 0.0, w: 0.0, n: 1.0, e: 1.0 }.clause(1113.2);
        assert!(c.starts_with("(-0.010000,-0.010"), "{c}");
    }
}

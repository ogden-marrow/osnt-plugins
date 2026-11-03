use super::*;
use axum::{extract::Path, http::header, response::IntoResponse, routing::get as aget};
use std::sync::atomic::AtomicUsize;

/// Synthetic terrain: 500 m plain with a 3000 m Gaussian peak at 47.0 N 8.0 E (sigma 3 km).
fn terrain(lat: f64, lon: f64) -> f64 {
    let d = crate::analysis::distance(lat, lon, 47.0, 8.0);
    500.0 + 3000.0 * (-(d * d) / (2.0 * 3000.0 * 3000.0)).exp()
}

fn tile_png(z: u32, x: u32, y: u32) -> Vec<u8> {
    let n = (1u64 << z) as f64 * 256.0;
    let mut raw = Vec::with_capacity(256 * 256 * 3);
    for py in 0..256 {
        for px in 0..256 {
            let (gx, gy) = (x as f64 * 256.0 + px as f64 + 0.5, y as f64 * 256.0 + py as f64 + 0.5);
            let lon = gx / n * 360.0 - 180.0;
            let lat = (std::f64::consts::PI * (1.0 - 2.0 * gy / n)).sinh().atan().to_degrees();
            let v = terrain(lat, lon) + 32768.0;
            raw.extend_from_slice(&[(v / 256.0).floor() as u8, (v.floor() % 256.0) as u8, ((v - v.floor()) * 256.0) as u8]);
        }
    }
    let mut out = vec![];
    let mut enc = png::Encoder::new(&mut out, 256, 256);
    enc.set_color(png::ColorType::Rgb);
    enc.set_depth(png::BitDepth::Eight);
    enc.write_header().unwrap().write_image_data(&raw).unwrap();
    out
}

static HITS: AtomicUsize = AtomicUsize::new(0);

async fn serve(app: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{a}")
}

async fn tile_server(counter: Option<Arc<AtomicUsize>>, missing: bool) -> String {
    let app = Router::new().route("/{z}/{x}/{y}", aget(move |Path((z, x, y)): Path<(u32, u32, String)>| {
        let counter = counter.clone();
        async move {
            HITS.fetch_add(1, Ordering::SeqCst);
            if let Some(c) = counter { c.fetch_add(1, Ordering::SeqCst); }
            if missing { return StatusCode::FORBIDDEN.into_response(); }
            let y: u32 = y.trim_end_matches(".png").parse().unwrap();
            ([(header::CONTENT_TYPE, "image/png")], tile_png(z, x, y)).into_response()
        }
    }));
    serve(app).await
}

fn temp(name: &str) -> PathBuf {
    let d = env::temp_dir().join(format!("osnt-terrain-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

async fn plugin(tiles: &str, name: &str, gateway: bool) -> String {
    let cfg = Config { tiles: tiles.into(), state: temp(name), open_meteo: "http://127.0.0.1:9".into(), opentopodata: "http://127.0.0.1:9".into(), disk_cap: 50 * 1024 * 1024 };
    serve(router(new_app(cfg, gateway))).await
}

async fn get_json(url: String) -> (u16, Value) {
    tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(120))).build().into();
        let mut r = agent.get(&url).call().unwrap();
        (r.status().as_u16(), r.body_mut().read_json::<Value>().unwrap_or(Value::Null))
    })
    .await
    .unwrap()
}

#[test]
fn png_round_trip_and_rejects() {
    let png = tile_png(8, 134, 90);
    let t = tiles::decode_png(&png).unwrap();
    assert_eq!(t.len(), 65536);
    assert!(t.iter().all(|v| *v > 400.0 && *v < 3600.0));
    assert!(tiles::decode_png(b"not a png").is_err());
    let mut small = vec![];
    let mut enc = png::Encoder::new(&mut small, 4, 4);
    enc.set_color(png::ColorType::Rgb);
    enc.set_depth(png::BitDepth::Eight);
    enc.write_header().unwrap().write_image_data(&[0u8; 48]).unwrap();
    assert!(tiles::decode_png(&small).unwrap_err().to_string().contains("tile size"));
}

#[test]
fn terrarium_decoding_values() {
    // 1000.5 m -> v = 33768.5 -> R=131, G=232, B=128
    let mut raw = vec![];
    for _ in 0..65536 {
        raw.extend_from_slice(&[131, 232, 128]);
    }
    let mut out = vec![];
    let mut enc = png::Encoder::new(&mut out, 256, 256);
    enc.set_color(png::ColorType::Rgb);
    enc.set_depth(png::BitDepth::Eight);
    enc.write_header().unwrap().write_image_data(&raw).unwrap();
    assert!((tiles::decode_png(&out).unwrap()[100] - 1000.5).abs() < 1e-3);
}

#[test]
fn tile_math() {
    let n = tiles::needed(47.37, 8.54, 10);
    assert_eq!((n[0].1, n[0].2), (536, 358));
    // Equator / date line wrap stays inside the grid.
    for k in tiles::needed(0.0, 179.99999, 5).iter().chain(tiles::needed(85.0, -180.0, 5).iter()) {
        assert!(k.1 < 32 && k.2 < 32);
    }
}

#[tokio::test]
async fn elevation_peak_and_plain_and_caching() {
    let counter = Arc::new(AtomicUsize::new(0));
    let tiles_url = tile_server(Some(counter.clone()), false).await;
    let base = plugin(&tiles_url, "elev", false).await;
    let (c, v) = get_json(format!("{base}/api/elevation?lat=47.0&lon=8.0")).await;
    assert_eq!(c, 200, "{v}");
    assert!((v["elevation_m"].as_f64().unwrap() - 3500.0).abs() < 25.0, "{v}");
    let (_, v) = get_json(format!("{base}/api/elevation?lat=47.2&lon=8.3")).await;
    assert!((v["elevation_m"].as_f64().unwrap() - 500.0).abs() < 3.0, "{v}");
    let before = counter.load(Ordering::SeqCst);
    let _ = get_json(format!("{base}/api/elevation?lat=47.0&lon=8.0")).await;
    assert_eq!(counter.load(Ordering::SeqCst), before, "tiles must come from the cache");
    let (_, s) = get_json(format!("{base}/api/status")).await;
    assert!(s["cache_bytes"].as_u64().unwrap() > 1000);
    // Cross-check failure is reported as null, not an error.
    let (c, v) = get_json(format!("{base}/api/elevation?lat=47.0&lon=8.0&check=all")).await;
    assert_eq!(c, 200);
    assert!(v["checks"]["open_meteo_m"].is_null());
}

#[tokio::test]
async fn profile_over_the_peak() {
    let base = plugin(&tile_server(None, false).await, "prof", false).await;
    let (c, v) = get_json(format!("{base}/api/profile?lat1=47.0&lon1=7.9&lat2=47.0&lon2=8.1&n=100")).await;
    assert_eq!(c, 200, "{v}");
    assert!((v["max_m"].as_f64().unwrap() - 3500.0).abs() < 60.0, "{v}");
    assert!(v["gain_m"].as_f64().unwrap() > 2800.0 && v["loss_m"].as_f64().unwrap() > 2800.0);
    assert_eq!(v["samples"].as_array().unwrap().len(), 101);
    assert!((v["distance_m"].as_f64().unwrap() - 15_170.0).abs() < 100.0);
}

#[tokio::test]
async fn line_of_sight_blocked_then_clear() {
    let base = plugin(&tile_server(None, false).await, "los", false).await;
    let (_, v) = get_json(format!("{base}/api/los?lat1=47.0&lon1=7.9&lat2=47.0&lon2=8.1&h1=2&h2=2")).await;
    assert_eq!(v["visible"], false, "{v}");
    let d = v["worst_obstruction"]["distance_m"].as_f64().unwrap();
    assert!((d - 7600.0).abs() < 900.0, "{v}");
    assert!(v["worst_obstruction"]["above_line_m"].as_f64().unwrap() > 2000.0);
    let (_, v) = get_json(format!("{base}/api/los?lat1=47.0&lon1=7.9&lat2=47.0&lon2=8.1&h1=4500&h2=4500")).await;
    assert_eq!(v["visible"], true, "{v}");
    let (_, v) = get_json(format!("{base}/api/los?lat1=47.2&lon1=7.95&lat2=47.2&lon2=8.05")).await;
    assert_eq!(v["visible"], true);
    // The same flat 15 km line is hidden by Earth curvature alone with 1.7 m eyes.
    let (_, v) = get_json(format!("{base}/api/los?lat1=47.2&lon1=7.9&lat2=47.2&lon2=8.1")).await;
    assert_eq!(v["visible"], false, "{v}");
    let (c, _) = get_json(format!("{base}/api/los?lat1=47.0&lon1=7.9&lat2=47.0&lon2=7.9")).await;
    assert_eq!(c, 400);
    let (c, _) = get_json(format!("{base}/api/los?lat1=47.0&lon1=7.0&lat2=47.0&lon2=20.0")).await;
    assert_eq!(c, 400, "too long");
}

#[tokio::test]
async fn horizon_sees_the_peak() {
    let base = plugin(&tile_server(None, false).await, "hor", false).await;
    let (c, v) = get_json(format!("{base}/api/horizon?lat=47.0&lon=7.9&radius_km=15&step=2")).await;
    assert_eq!(c, 200, "{v}");
    let hi = &v["highest"];
    assert!((hi["azimuth"].as_f64().unwrap() - 90.0).abs() <= 6.0, "{v}");
    let ang = hi["elevation_deg"].as_f64().unwrap();
    assert!((19.0..=25.0).contains(&ang), "{ang}");
    assert!(hi["distance_km"].as_f64().unwrap() < 8.0);
    let peaks = v["peaks"].as_array().unwrap();
    assert!(!peaks.is_empty() && (peaks[0]["azimuth"].as_f64().unwrap() - 90.0).abs() <= 6.0);
    assert_eq!(v["horizon"].as_array().unwrap().len(), 180);
    // Facing away from the peak the horizon is nearly flat (below the peak by far).
    let west = v["horizon"].as_array().unwrap().iter().find(|r| r[0] == 270.0).unwrap();
    assert!(west[1].as_f64().unwrap() < 3.0, "{west}");
}

#[tokio::test]
async fn viewshed_hides_behind_the_peak() {
    let base = plugin(&tile_server(None, false).await, "view", false).await;
    let (c, v) = get_json(format!("{base}/api/viewshed?lat=47.0&lon=7.9&radius_km=14&step=10&from=60&span=60")).await;
    assert_eq!(c, 200, "{v}");
    let ray90 = v["rays"].as_array().unwrap().iter().find(|r| r["az"] == 90.0).unwrap();
    let far = ray90["segments"].as_array().unwrap().iter().map(|s| s[1].as_f64().unwrap()).fold(0.0, f64::max);
    assert!(far < 11_500.0, "terrain behind the peak must be hidden: {ray90}");
    let (_, v2) = get_json(format!("{base}/api/viewshed?lat=47.0&lon=7.9&radius_km=14&step=10&from=240&span=60")).await;
    assert!(v2["visible_fraction"].as_f64().unwrap() > v["visible_fraction"].as_f64().unwrap());
}

#[tokio::test]
async fn missing_tiles_and_dead_source_give_clear_errors() {
    let base = plugin(&tile_server(None, true).await, "miss", false).await;
    let (c, v) = get_json(format!("{base}/api/elevation?lat=47.0&lon=8.0")).await;
    assert_eq!(c, 422, "{v}");
    let base = plugin("http://127.0.0.1:9", "dead", false).await;
    let (c, v) = get_json(format!("{base}/api/elevation?lat=47.0&lon=8.0")).await;
    assert_eq!(c, 502, "{v}");
    assert!(v["error"].as_str().unwrap().contains("tile source problem"));
}

#[tokio::test]
async fn validation_guard_and_tools() {
    let base = plugin("http://127.0.0.1:9", "val", false).await;
    for bad in ["elevation?lat=95&lon=0", "elevation?lat=1", "elevation?lat=1&lon=1&check=evil", "horizon?lat=1&lon=1&radius_km=500", "horizon?lat=1&lon=1&step=0", "profile?lat1=1&lon1=1&lat2=2", "viewshed?lat=1&lon=1&radius_km=99"] {
        let (c, _) = get_json(format!("{base}/api/{bad}")).await;
        assert_eq!(c, 400, "{bad}");
    }
    let g = plugin("http://127.0.0.1:9", "guard", true).await;
    assert_eq!(get_json(format!("{g}/api/status")).await.0, 401);
    let (c, v) = get_json(format!("{g}/tools")).await;
    assert_eq!((c, v.as_array().unwrap().len()), (200, 4));
}

#[test]
fn disk_cache_eviction_by_age_and_size() {
    let dir = temp("evict");
    std::fs::create_dir_all(&dir).unwrap();
    let write = |name: &str, age_days: u64, bytes: usize| {
        let p = dir.join(name);
        std::fs::write(&p, vec![0u8; bytes]).unwrap();
        let f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        f.set_modified(std::time::SystemTime::now() - Duration::from_secs(age_days * 86400)).unwrap();
    };
    write("old.png", 30, 100);
    write("a.png", 5, 600);
    write("b.png", 3, 600);
    write("c.png", 1, 600);
    write("junk.txt", 0, 10);
    let agent = osnt_common::http_agent("t");
    let t = Tiles::new(agent, "http://127.0.0.1:9".into(), dir.clone(), 1300, 4);
    assert!(!dir.join("old.png").exists() && !dir.join("junk.txt").exists());
    assert!(!dir.join("a.png").exists(), "oldest goes first when over the cap");
    assert!(dir.join("b.png").exists() && dir.join("c.png").exists());
    assert_eq!(t.disk_bytes(), 1200);
}

#[test]
fn memory_cache_is_bounded() {
    let _ = HITS.load(Ordering::SeqCst);
    let dir = temp("mem");
    let t = Tiles::new(osnt_common::http_agent("t"), "http://127.0.0.1:9".into(), dir.clone(), 1 << 20, 2);
    for i in 0..5u32 {
        let _ = std::fs::write(dir.join(format!("3_{i}_0.png")), tile_png(3, i, 0));
        assert!(t.get((3, i, 0)).unwrap().is_some());
    }
    assert!(t.mem.lock().unwrap().len() <= 2);
}

//! End-to-end tests against a fake GitHub-release server serving a small fixture tar (split into parts, redirecting to a
//! "blob" host, honouring Range). No live internet.

use std::{collections::HashMap, sync::{Arc, Mutex}, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, Response, StatusCode, header},
    routing::get,
};
use serde_json::Value;

use super::*;
use crate::heat::testutil::{E, heatmap_file};

fn tar_entry(name: &str, data: &[u8], dir: bool) -> Vec<u8> {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..107].copy_from_slice(b"0000644");
    h[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
    h[156] = if dir { b'5' } else { b'0' };
    h[257..263].copy_from_slice(b"ustar\0");
    h[148..156].copy_from_slice(b"        ");
    let sum: u64 = h.iter().map(|b| *b as u64).sum();
    h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    let mut v = h.to_vec();
    v.extend_from_slice(data);
    v.resize(512 + data.len().div_ceil(512) * 512, 0);
    v
}

/// Fixture day: heatmap files 02, 00, 03 (01 missing), preceded by README and followed by traces/.
fn fixture_tar(day_start: i64) -> Vec<u8> {
    let d = day_start;
    let a = 0xAAA111u32;
    let b = 0xBBB222u32;
    let c = 0xCCC333u32;
    let mk = |t0: i64, ents: Vec<Vec<E>>| heatmap_file(&ents.into_iter().enumerate().map(|(i, e)| (t0 + 10 * i as i64, e)).collect::<Vec<_>>());
    let hh0 = mk(d, vec![
        vec![E::Cs(a, 1200, "UAL1"), E::Pos(a, 29.60, -82.30, 400, 2000), E::Pos(b, 50.0, 10.0, 1200, 4000)],
        vec![E::Pos(a, 29.61, -82.31, 410, 2000), E::Pos(b, 50.1, 10.1, 1200, 4000)],
        vec![E::Pos(a, 29.62, -82.32, -123, 0)],
    ]);
    let hh2 = mk(d + 3600, vec![vec![E::Cs(c, 7000, "DAL5"), E::Pos(c, 29.70, -82.40, -124, -1), E::Pos(a, 29.9, -82.5, 800, 3000)]]);
    let hh3 = mk(d + 5400, vec![vec![E::Pos(a, 30.0, -82.0, 800, 3000)]]);
    let mut t = vec![];
    t.extend(tar_entry("./", b"", true));
    t.extend(tar_entry("./README.txt", b"hello", false));
    t.extend(tar_entry("./heatmap/", b"", true));
    t.extend(tar_entry("./heatmap/02.bin.ttf", &hh2, false));
    t.extend(tar_entry("./heatmap/00.bin.ttf", &hh0, false));
    t.extend(tar_entry("./heatmap/03.bin.ttf", &hh3, false));
    t.extend(tar_entry("./traces/", b"", true));
    t.extend(tar_entry("./traces/aa/trace_full_aaa111.json", &vec![7u8; 100_000], false));
    t.extend(vec![0u8; 1024]);
    t
}

/// Layout seen on recent real days: `traces/` (many small members) first, heatmap/ last, then small files.
fn fixture_tar_traces_first(day_start: i64) -> Vec<u8> {
    let mut t = vec![];
    t.extend(tar_entry("./", b"", true));
    t.extend(tar_entry("./traces/", b"", true));
    for i in 0..400 {
        if i % 100 == 0 {
            t.extend(tar_entry(&format!("./traces/{:02x}/", i / 100), b"", true));
        }
        t.extend(tar_entry(&format!("./traces/{:02x}/trace_full_{:06x}.json", i / 100, i), &vec![9u8; 700 + (i % 7) * 300], false));
    }
    let base = fixture_tar(day_start);
    // reuse the heatmap members of the standard fixture (everything between the README and traces/)
    let hm_start = 512 * 3 + 512; // "./", README header+data, "./heatmap/"
    let hm_end = base.len() - 1024 - (512 + 100_000usize.div_ceil(512) * 512) - 512;
    t.extend(tar_entry("./heatmap/", b"", true));
    t.extend_from_slice(&base[hm_start..hm_end]);
    t.extend(tar_entry("./acas/", b"", true));
    t.extend(tar_entry("./acas/acas.json.gz", &[1u8; 300], false));
    t.extend(vec![0u8; 1024]);
    t
}

#[derive(Default)]
struct Fake {
    files: HashMap<String, Vec<u8>>, // asset file name -> bytes
    log: Mutex<Vec<(String, Option<String>)>>, // (path, range)
    port: Mutex<u16>,
}

fn split(t: Vec<u8>, at: usize) -> (Vec<u8>, Vec<u8>) {
    (t[..at].to_vec(), t[at..].to_vec())
}

async fn serve(f: &Fake, name: &str, headers: &HeaderMap) -> Response<Body> {
    f.log.lock().unwrap().push((name.to_string(), headers.get("range").and_then(|v| v.to_str().ok()).map(String::from)));
    let Some(data) = f.files.get(name) else { return Response::builder().status(404).body(Body::empty()).unwrap() };
    let Some(r) = headers.get("range").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("bytes=")) else {
        return Response::builder().status(200).body(Body::from(data.clone())).unwrap();
    };
    let (a, b) = r.split_once('-').unwrap();
    let a: usize = a.parse().unwrap();
    let b: usize = b.parse::<usize>().unwrap().min(data.len() - 1);
    Response::builder().status(206).header(header::CONTENT_RANGE, format!("bytes {a}-{b}/{}", data.len())).body(Body::from(data[a..=b].to_vec())).unwrap()
}

async fn release(State(f): State<Arc<Fake>>, Path((_y, tag, file)): Path<(String, String, String)>, headers: HeaderMap) -> Response<Body> {
    if !f.files.contains_key(&file) || !file.starts_with(&tag) {
        return serve(&f, "404", &headers).await;
    }
    let port = *f.port.lock().unwrap();
    f.log.lock().unwrap().push((format!("redirect {file}"), None));
    Response::builder().status(StatusCode::FOUND).header(header::LOCATION, format!("http://127.0.0.1:{port}/blob/{file}")).body(Body::empty()).unwrap()
}

async fn blob(State(f): State<Arc<Fake>>, Path(file): Path<String>, headers: HeaderMap) -> Response<Body> {
    serve(&f, &file, &headers).await
}

struct Env {
    base: String,
    fake: Arc<Fake>,
    app: Arc<App>,
    dir: PathBuf,
    total: usize,
}

async fn setup(name: &str, tweak: impl FnOnce(&mut Config)) -> Env {
    let day1 = parse_date("2025-03-01").unwrap();
    let day2 = parse_date("2025-03-02").unwrap();
    let tar1 = fixture_tar(day1);
    let total = tar1.len();
    let (p1, p2) = split(tar1, 4096 + 700); // boundary lands inside a heatmap member
    let mut files = HashMap::new();
    files.insert("v2025.03.01-planes-readsb-prod-0.tar.aa".to_string(), p1);
    files.insert("v2025.03.01-planes-readsb-prod-0.tar.ab".to_string(), p2);
    files.insert("v2025.03.02-planes-readsb-staging-0.tar".to_string(), fixture_tar(day2));
    files.insert("v2025.03.03-planes-readsb-prod-0.tar".to_string(), fixture_tar_traces_first(day1 + 2 * 86400));
    let fake = Arc::new(Fake { files, ..Default::default() });
    let fake_router = Router::new().route("/adsblol/{y}/releases/download/{tag}/{file}", get(release)).route("/blob/{file}", get(blob)).with_state(fake.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    *fake.port.lock().unwrap() = port;
    tokio::spawn(async move { axum::serve(l, fake_router).await.unwrap() });

    let dir = std::env::temp_dir().join(format!("adsbh-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut cfg = Config {
        bind: "127.0.0.1:0".into(), state: dir.clone(), upstream: format!("http://127.0.0.1:{port}"), ttl: Duration::from_secs(3600), cache_cap: 50 << 20, download_cap: 50 << 20,
        max_window_s: 6 * 3600, max_points: 1_000_000, probe_window: 16 << 10, hop_delay: Duration::from_millis(1), file_delay: Duration::from_millis(1),
    };
    tweak(&mut cfg);
    // the fixture lives under /adsblol/globe_history_2025/... so the path template above is {y}
    let app = build_app(cfg).unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = l.local_addr().unwrap();
    let r = router(app.clone());
    tokio::spawn(async move { axum::serve(l, r).await.unwrap() });
    Env { base: format!("http://{api}"), fake, app, dir, total }
}

async fn get_json(url: String) -> (u16, Value) {
    tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(60))).build().into();
        let mut r = agent.get(&url).call().unwrap();
        (r.status().as_u16(), r.body_mut().read_json::<Value>().unwrap_or(Value::Null))
    })
    .await
    .unwrap()
}

const BBOX: &str = "-83,29,-82,30";

#[tokio::test]
async fn fetch_filter_cache_and_no_full_download() {
    let e = setup("flow", |_| {}).await;
    let url = format!("{}/api/slices?date=2025-03-01&from=00:00&to=01:45&bbox={BBOX}&wait=30", e.base);
    let (code, st) = get_json(url.clone()).await;
    assert_eq!(code, 200, "{st}");
    assert_eq!(st["ready"], true);
    assert_eq!(st["aircraft"], 2); // UAL1 and DAL5; the aircraft over Europe is excluded by the bbox
    assert_eq!(st["points"], 6); // hh00: 3, hh01 missing, hh02: 2, hh03: 1
    assert_eq!(st["missing_halfhours"], serde_json::json!(["00:30"]));
    let id = st["id"].as_str().unwrap().to_string();

    let (_, tr) = get_json(format!("{}/api/slices/{id}/tracks", e.base)).await;
    let acs = tr["aircraft"].as_array().unwrap();
    let ual = acs.iter().find(|a| a["hex"] == "aaa111").unwrap();
    assert_eq!(ual["callsign"], "UAL1");
    assert_eq!(ual["squawk"], 1200);
    let pts = ual["points"].as_array().unwrap();
    assert_eq!(pts[0][1], 29.6);
    assert_eq!(pts[0][2], -82.3);
    assert_eq!(pts[0][3], 10000); // 400 * 25 ft
    assert_eq!(pts[2][3], "ground");
    assert!(acs.iter().all(|a| a["hex"] != "bbb222"));
    let dal = acs.iter().find(|a| a["hex"] == "ccc333").unwrap();
    assert_eq!(dal["points"][0][3], Value::Null);
    assert_eq!(dal["points"][0][4], Value::Null);

    // narrowing at read time, geojson
    let (_, one) = get_json(format!("{}/api/slices/{id}/tracks?callsign=DAL&format=geojson", e.base)).await;
    assert_eq!(one["features"].as_array().unwrap().len(), 1);

    // never downloaded the tar: far fewer bytes than the archive, only Range requests, traces/ untouched
    let log = e.fake.log.lock().unwrap().clone();
    assert!(log.iter().filter(|(n, _)| !n.starts_with("redirect")).all(|(_, r)| r.is_some()), "every ranged request must carry Range: {log:?}");
    assert!(st["bytes_downloaded"].as_u64().unwrap() < e.total as u64 / 2);

    // second identical request is served from the cache: no new upstream traffic
    let n = e.fake.log.lock().unwrap().len();
    let (code, again) = get_json(url).await;
    assert_eq!((code, again["id"].as_str().unwrap()), (200, id.as_str()));
    assert_eq!(e.fake.log.lock().unwrap().len(), n);
    // the tar index was cached on disk and no temp files remain
    assert!(std::fs::read_dir(e.dir.join("index")).unwrap().count() == 1);
    assert!(std::fs::read_dir(e.dir.join("tmp")).unwrap().next().is_none());
    let (_, list) = get_json(format!("{}/api/slices", e.base)).await;
    assert_eq!(list["slices"].as_array().unwrap().len(), 1);
    let (_, del) = get_json(format!("{}/api/slices/{id}", e.base)).await; // GET on a delete route is not allowed
    assert_eq!(del, Value::Null);
    let _ = std::fs::remove_dir_all(&e.dir);
}

#[tokio::test]
async fn hex_callsign_step_and_staging_fallback() {
    let e = setup("filters", |_| {}).await;
    // staging fallback (day 2 only has a staging release) + hex filter, no bbox
    let (code, st) = get_json(format!("{}/api/slices?date=2025-03-02&from=00:00&to=00:30&hex=BBB222&wait=30", e.base)).await;
    assert_eq!(code, 200, "{st}");
    assert_eq!(st["variant"], "staging");
    assert_eq!(st["aircraft"], 1);
    assert_eq!(st["points"], 2);
    // callsign prefix; step=20 s thins 3 samples to 2
    let (_, st) = get_json(format!("{}/api/slices?date=2025-03-01&from=00:00&to=00:30&callsign=ual&step=20&wait=30", e.base)).await;
    assert_eq!(st["aircraft"], 1);
    assert_eq!(st["points"], 2);
    let _ = std::fs::remove_dir_all(&e.dir);
}

#[tokio::test]
async fn traces_first_layout_is_bisected_not_scanned() {
    let e = setup("traces", |_| {}).await;
    let (code, st) = get_json(format!("{}/api/slices?date=2025-03-03&from=00:00&to=00:30&bbox={BBOX}&wait=30", e.base)).await;
    assert_eq!(code, 200, "{st}");
    assert_eq!(st["points"], 3);
    assert_eq!(st["aircraft"], 1);
    let log = e.fake.log.lock().unwrap().clone();
    let hops = log.iter().filter(|(n, r)| n.starts_with("v2025.03.03") && r.as_deref() == Some("bytes=0-511")).count();
    assert!(hops <= 1, "{hops}");
    // far fewer requests than the 400+ trace members: bisect probes + a short hop chain
    let n = log.iter().filter(|(n, _)| n.starts_with("v2025.03.03")).count();
    assert!(n < 120, "{n} requests");
    let _ = std::fs::remove_dir_all(&e.dir);
}

#[tokio::test]
async fn validation_and_budget() {
    let e = setup("val", |c| c.download_cap = 100).await;
    for bad in [
        "date=2025-13-01&from=00:00&to=01:00",
        "date=2099-01-01&from=00:00&to=01:00",
        "date=2025-03-01&from=02:00&to=01:00",
        "date=2025-03-01&from=00:00&to=23:00",
        "date=2025-03-01&from=00:00&to=01:00&bbox=1,2,3",
        "date=2025-03-01&from=00:00&to=01:00&hex=zzz",
        "date=2025-03-01&from=00:00&to=01:00&callsign=../etc",
    ] {
        let (code, _) = get_json(format!("{}/api/slices?{bad}", e.base)).await;
        assert_eq!(code, 400, "{bad}");
    }
    // a 100-byte budget aborts the download and nothing is stored
    let (code, st) = get_json(format!("{}/api/slices?date=2025-03-01&from=00:00&to=00:30&wait=30", e.base)).await;
    assert_eq!(code, 502, "{st}");
    assert!(st["error"].as_str().unwrap().contains("budget"));
    assert!(e.app.store.list().is_empty());
    assert!(std::fs::read_dir(e.dir.join("tmp")).unwrap().next().is_none());
    let (code, _) = get_json(format!("{}/api/jobs/not-an-id", e.base)).await;
    assert_eq!(code, 400);
    let (code, _) = get_json(format!("{}/api/slices/0123456789abcdef/tracks", e.base)).await;
    assert_eq!(code, 404);
    let (_, tools) = get_json(format!("{}/tools", e.base)).await;
    assert_eq!(tools.as_array().unwrap().len(), 3);
    let _ = std::fs::remove_dir_all(&e.dir);
}

#[test]
fn bbox_antimeridian_and_dates() {
    assert_eq!(parse_date("2025-03-01").unwrap(), 1740787200);
    assert!(parse_date("2025-02-29").is_err());
    let p = Params { date: "2025-03-01".into(), from_s: 0, to_s: 600, bbox: Some([170.0, -10.0, -170.0, 10.0]), hex: vec![], callsign: None, step: 10 };
    let mut acc = Acc { p: &p, t0: 0, t1: i64::MAX, max_points: 10, cur_t: 5, recs: vec![], idx: HashMap::new(), order: vec![], cs: HashMap::new(), last: HashMap::new(), hexset: HashSet::new(), truncated: false, past_end: false };
    acc.feed(heat::Rec::Pos { addr: 1, lat: 0, lon: 175_000_000, alt: 0, gs: 0 });
    acc.feed(heat::Rec::Pos { addr: 2, lat: 0, lon: -175_000_000, alt: 0, gs: 0 });
    acc.feed(heat::Rec::Pos { addr: 3, lat: 0, lon: 0, alt: 0, gs: 0 });
    assert_eq!(acc.recs.len(), 2);
}

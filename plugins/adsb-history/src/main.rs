//! ADS-B history plugin: carve a time/area/aircraft window out of adsb.lol's daily global archive without storing the
//! archive. See README.md in this folder for the archive format and the API.

mod heat;
mod store;
mod upstream;
#[cfg(test)]
mod tests;

use std::{
    collections::{HashMap, HashSet},
    env,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex, atomic::{AtomicBool, AtomicU64, Ordering}},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use store::{AcMeta, Params, Rec, SliceMeta, Store, now_s};
use upstream::{Archive, Index, Metered, R, Upstream};

const PAGE: &str = include_str!("../assets/index.html");

#[derive(Clone)]
pub struct Config {
    pub bind: String,
    pub state: PathBuf,
    pub upstream: String,
    pub ttl: Duration,
    pub cache_cap: u64,
    pub download_cap: u64,
    pub max_window_s: u32,
    pub max_points: usize,
    pub probe_window: u64,
    pub hop_delay: Duration,
    pub file_delay: Duration,
}

impl Config {
    fn from_env() -> Self {
        let num = |k: &str, d: u64| env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
        Self {
            bind: env::var("OSNT_ADSB_HISTORY_BIND").unwrap_or_else(|_| "127.0.0.1:8120".into()),
            state: PathBuf::from(env::var("OSNT_ADSB_HISTORY_STATE").unwrap_or_else(|_| "./adsb-history-state".into())),
            upstream: env::var("OSNT_ADSB_HISTORY_UPSTREAM").unwrap_or_else(|_| "https://github.com".into()),
            ttl: Duration::from_secs(num("OSNT_ADSB_HISTORY_TTL_HOURS", 6) * 3600),
            cache_cap: num("OSNT_ADSB_HISTORY_CACHE_MB", 300) << 20,
            download_cap: num("OSNT_ADSB_HISTORY_MAX_DOWNLOAD_MB", 400) << 20,
            max_window_s: (num("OSNT_ADSB_HISTORY_MAX_WINDOW_HOURS", 6) * 3600) as u32,
            max_points: num("OSNT_ADSB_HISTORY_MAX_POINTS", 1_500_000) as usize,
            probe_window: num("OSNT_ADSB_HISTORY_PROBE_KB", 1024) << 10,
            hop_delay: Duration::from_millis(num("OSNT_ADSB_HISTORY_HOP_DELAY_MS", 150)),
            file_delay: Duration::from_millis(num("OSNT_ADSB_HISTORY_FILE_DELAY_MS", 500)),
        }
    }
}

#[derive(Serialize, Clone, Default)]
pub struct JobStatus {
    pub state: &'static str, // queued | running | done | failed | cancelled
    pub phase: String,
    pub error: Option<String>,
    pub halfhours_total: u32,
    pub halfhours_done: u32,
    pub points: u64,
    pub created: u64,
    pub finished: Option<u64>,
}

pub struct Job {
    pub id: String,
    pub params: Params,
    pub st: Mutex<JobStatus>,
    pub cancel: Arc<AtomicBool>,
    pub bytes: Arc<AtomicU64>,
}

impl Job {
    fn update(&self, f: impl FnOnce(&mut JobStatus)) {
        f(&mut self.st.lock().unwrap());
    }
}

pub struct App {
    pub cfg: Config,
    pub up: Arc<Upstream>,
    pub store: Store,
    pub jobs: Mutex<HashMap<String, Arc<Job>>>,
    /// One download at a time: no parallel hammering of the upstream.
    pub gate: Arc<tokio::sync::Semaphore>,
}

// ---------- dates and parameters ----------

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468
}

fn parse_date(s: &str) -> Result<i64, String> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' || !s.bytes().enumerate().all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit()) {
        return Err("date must be YYYY-MM-DD".into());
    }
    let (y, m, d): (i64, i64, i64) = (s[0..4].parse().unwrap(), s[5..7].parse().unwrap(), s[8..10].parse().unwrap());
    let dim = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        _ => return Err("invalid month".into()),
    };
    if d < 1 || d > dim {
        return Err("invalid day".into());
    }
    if y < 2023 {
        return Err("the adsb.lol archive starts in 2023".into());
    }
    let day_start = days_from_civil(y, m, d) * 86400;
    if day_start > now_s() as i64 {
        return Err("date is in the future".into());
    }
    Ok(day_start)
}

fn parse_hhmm(s: &str) -> Result<u32, String> {
    let (h, m) = s.split_once(':').ok_or("time must be HH:MM (UTC)")?;
    let (h, m): (u32, u32) = (h.parse().map_err(|_| "bad hour")?, m.parse().map_err(|_| "bad minute")?);
    if m > 59 || h > 24 || (h == 24 && m != 0) {
        return Err("time out of range".into());
    }
    Ok(h * 3600 + m * 60)
}

fn parse_params(q: &HashMap<String, String>, cfg: &Config) -> Result<Params, String> {
    let date = q.get("date").ok_or("date is required (YYYY-MM-DD, UTC)")?.trim().to_string();
    parse_date(&date)?;
    let from_s = parse_hhmm(q.get("from").ok_or("from is required (HH:MM UTC)")?.trim())?;
    let to_s = parse_hhmm(q.get("to").ok_or("to is required (HH:MM UTC)")?.trim())?;
    if to_s <= from_s {
        return Err("to must be after from".into());
    }
    if to_s - from_s > cfg.max_window_s {
        return Err(format!("window too long: at most {} hours per slice", cfg.max_window_s / 3600));
    }
    let bbox = match q.get("bbox").filter(|s| !s.trim().is_empty()) {
        None => None,
        Some(s) => {
            let v: Vec<f64> = s.split(',').map(|x| x.trim().parse::<f64>()).collect::<Result<_, _>>().map_err(|_| "bbox must be west,south,east,north in degrees")?;
            if v.len() != 4 || v.iter().any(|x| !x.is_finite()) || v[1] < -90.0 || v[3] > 90.0 || v[1] > v[3] || v[0].abs() > 180.0 || v[2].abs() > 180.0 {
                return Err("bbox must be west,south,east,north (lon -180..180, lat -90..90, south <= north; west > east crosses the antimeridian)".into());
            }
            Some([v[0], v[1], v[2], v[3]])
        }
    };
    let mut hex: Vec<String> = vec![];
    for h in q.get("hex").map(|s| s.as_str()).unwrap_or("").split(',').map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()) {
        let digits = h.strip_prefix('~').unwrap_or(&h);
        if digits.len() != 6 || !digits.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("bad ICAO hex '{h}' (6 hex digits, ~ prefix for non-ICAO)"));
        }
        hex.push(h);
    }
    hex.sort();
    hex.dedup();
    if hex.len() > 100 {
        return Err("at most 100 hex codes".into());
    }
    let callsign = q.get("callsign").map(|s| s.trim().to_uppercase()).filter(|s| !s.is_empty());
    if let Some(c) = &callsign {
        if c.len() > 8 || !c.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err("callsign must be 1-8 letters/digits (matched as a prefix)".into());
        }
    }
    let step = match q.get("step") {
        None => 10,
        Some(s) => s.parse::<u32>().map_err(|_| "step must be seconds (10..3600)")?.clamp(10, 3600),
    };
    Ok(Params { date, from_s, to_s, bbox, hex, callsign, step })
}

pub fn slice_id(p: &Params) -> String {
    let h = Sha256::digest(serde_json::to_vec(p).unwrap());
    h[..8].iter().map(|b| format!("{b:02x}")).collect()
}

// ---------- job execution (blocking thread) ----------

struct Acc<'a> {
    p: &'a Params,
    t0: i64,
    t1: i64,
    max_points: usize,
    cur_t: i64,
    recs: Vec<Rec>,
    idx: HashMap<u32, u32>,
    order: Vec<u32>,
    cs: HashMap<u32, (String, u16)>,
    last: HashMap<u32, u32>,
    hexset: HashSet<String>,
    truncated: bool,
    past_end: bool,
}

impl Acc<'_> {
    fn feed(&mut self, r: heat::Rec) -> bool {
        match r {
            heat::Rec::Slice { ts_ms } => {
                self.cur_t = ts_ms.div_euclid(1000);
                if self.cur_t >= self.t1 {
                    self.past_end = true;
                    return false; // slices are time-ordered: nothing more for this window
                }
            }
            heat::Rec::Callsign { addr, squawk, callsign } => {
                self.cs.insert(addr, (callsign, squawk));
            }
            heat::Rec::Pos { addr, lat, lon, alt, gs } => {
                if self.cur_t < self.t0 {
                    return true;
                }
                if let Some(b) = self.p.bbox {
                    let (la, lo) = (lat as f64 / 1e6, lon as f64 / 1e6);
                    let lon_ok = if b[0] <= b[2] { lo >= b[0] && lo <= b[2] } else { lo >= b[0] || lo <= b[2] };
                    if la < b[1] || la > b[3] || !lon_ok {
                        return true;
                    }
                }
                if !self.hexset.is_empty() && !self.hexset.contains(&heat::hex_string(addr)) {
                    return true;
                }
                if let Some(c) = &self.p.callsign {
                    if !self.cs.get(&addr).is_some_and(|(s, _)| s.to_uppercase().starts_with(c.as_str())) {
                        return true;
                    }
                }
                let t = self.cur_t as u32;
                if self.p.step > 10 {
                    if self.last.get(&addr).is_some_and(|l| t < l + self.p.step) {
                        return true;
                    }
                    self.last.insert(addr, t);
                }
                let order = &mut self.order;
                let ac = *self.idx.entry(addr).or_insert_with(|| {
                    order.push(addr);
                    (order.len() - 1) as u32
                });
                self.recs.push(Rec { ac, t, lat, lon, alt, gs });
                if self.recs.len() >= self.max_points {
                    self.truncated = true;
                    return false;
                }
            }
        }
        true
    }
}

fn load_index(store: &Store, key: &str, a: &Archive) -> Index {
    let idx: Option<Index> = std::fs::read(store.index_path(key)).ok().and_then(|b| serde_json::from_slice(&b).ok());
    match idx {
        Some(i) if i.archive_size == a.total() && i.variant == a.variant => i,
        _ => Index { variant: a.variant.clone(), archive_size: a.total(), ..Default::default() },
    }
}

fn save_index(store: &Store, key: &str, idx: &Index) {
    let tmp = store.tmp_path(&format!("{key}.idx.part"));
    if let Ok(b) = serde_json::to_vec(idx) {
        if std::fs::write(&tmp, b).is_ok() && std::fs::rename(&tmp, store.index_path(key)).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
    }
}

fn run_job(app: &Arc<App>, job: &Arc<Job>) -> R<()> {
    let p = &job.params;
    let day_start = parse_date(&p.date)?;
    let (t0, t1) = (day_start + p.from_s as i64, day_start + p.to_s as i64);
    job.update(|s| s.phase = "locating archive".into());
    let archive = app.up.find_archive(&p.date)?;
    let key = format!("{}-{}", p.date, archive.variant);
    let mut idx = load_index(&app.store, &key, &archive);
    let hhs: Vec<u8> = ((p.from_s / 1800)..p.to_s.div_ceil(1800)).map(|h| h as u8).collect();
    let needed: HashSet<u8> = hhs.iter().copied().collect();
    job.update(|s| {
        s.halfhours_total = hhs.len() as u32;
        s.phase = "locating heatmap files in the archive".into();
    });
    let mut hops = 0;
    let res = upstream::extend_index(&app.up, &archive, &mut idx, &needed, app.cfg.probe_window, app.cfg.hop_delay, &job.cancel, &mut |i| {
        hops += 1;
        if hops % 10 == 0 {
            save_index(&app.store, &key, i);
        }
    });
    save_index(&app.store, &key, &idx);
    res?;

    let mut acc = Acc { p, t0, t1, max_points: app.cfg.max_points, cur_t: 0, recs: vec![], idx: HashMap::new(), order: vec![], cs: HashMap::new(), last: HashMap::new(), hexset: p.hex.iter().cloned().collect(), truncated: false, past_end: false };
    let budget = Arc::new(AtomicU64::new(app.cfg.download_cap));
    let mut missing = vec![];
    for hh in hhs.iter() {
        if job.cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let Some((off, size)) = idx.find(*hh) else {
            missing.push(format!("{:02}:{:02}", hh / 2, (hh % 2) * 30));
            job.update(|s| s.halfhours_done += 1);
            continue;
        };
        job.update(|s| s.phase = format!("streaming {:02}:{:02} UTC ({:.1} MB, filtered while downloading)", hh / 2, (hh % 2) * 30, size as f64 / 1e6));
        let reader = app.up.stream(&archive, off, size)?;
        let mut metered = Metered { inner: reader, count: 0, budget: budget.clone(), cancel: job.cancel.clone(), progress: job.bytes.clone() };
        {
            let gz = flate2::read::GzDecoder::new(&mut metered);
            heat::parse(gz, |r| acc.feed(r)).map_err(|e| format!("reading heatmap {hh:02}: {e}"))?;
            job.update(|s| s.points = acc.recs.len() as u64);
        }
        if !acc.past_end && !acc.truncated && metered.count != size {
            return Err(format!("heatmap {hh:02}: download ended after {} of {size} bytes", metered.count));
        }
        job.update(|s| s.halfhours_done += 1);
        if acc.past_end || acc.truncated {
            break;
        }
        std::thread::sleep(app.cfg.file_delay);
    }
    if missing.len() == hhs.len() {
        return Err("the archive has no heatmap data for that window".into());
    }
    job.update(|s| s.phase = "writing slice".into());
    let mut recs = std::mem::take(&mut acc.recs);
    recs.sort_by_key(|r| (r.ac, r.t));
    let aircraft = acc
        .order
        .iter()
        .map(|a| {
            let c = acc.cs.get(a);
            AcMeta { hex: heat::hex_string(*a), callsign: c.map(|c| c.0.clone()).filter(|s| !s.is_empty()), squawk: c.map(|c| c.1) }
        })
        .collect();
    let meta = SliceMeta { id: job.id.clone(), params: p.clone(), variant: archive.variant.clone(), created: now_s(), points: recs.len() as u64, truncated: acc.truncated, bytes_downloaded: job.bytes.load(Ordering::Relaxed), missing, aircraft };
    app.store.write_slice(&meta, &recs).map_err(|e| format!("writing slice: {e}"))?;
    app.store.evict(app.cfg.ttl, app.cfg.cache_cap, Some(&job.id));
    job.update(|s| s.points = recs.len() as u64);
    Ok(())
}

/// Start a job (or reuse a running/finished one). Returns the slice id.
fn start_job(app: &Arc<App>, p: Params) -> String {
    let id = slice_id(&p);
    if app.store.slice_path(&id).exists() {
        let _ = std::fs::File::open(app.store.slice_path(&id)).and_then(|f| f.set_modified(std::time::SystemTime::now()));
        return id;
    }
    let job = {
        let mut jobs = app.jobs.lock().unwrap();
        if let Some(j) = jobs.get(&id) {
            let st = j.st.lock().unwrap();
            let recent_fail = st.finished.is_some_and(|f| now_s().saturating_sub(f) < 30) && st.state != "done";
            if matches!(st.state, "queued" | "running") || recent_fail {
                return id;
            }
        }
        let job = Arc::new(Job { id: id.clone(), params: p, st: Mutex::new(JobStatus { state: "queued", phase: "waiting for a download slot".into(), created: now_s(), ..Default::default() }), cancel: Arc::new(AtomicBool::new(false)), bytes: Arc::new(AtomicU64::new(0)) });
        jobs.insert(id.clone(), job.clone());
        job
    };
    let app2 = app.clone();
    tokio::spawn(async move {
        let Ok(_permit) = app2.gate.clone().acquire_owned().await else { return };
        if job.cancel.load(Ordering::Relaxed) {
            job.update(|s| { s.state = "cancelled"; s.finished = Some(now_s()); });
            return;
        }
        job.update(|s| s.state = "running");
        let (a, j) = (app2.clone(), job.clone());
        let res = tokio::task::spawn_blocking(move || run_job(&a, &j)).await.unwrap_or_else(|e| Err(format!("job panicked: {e}")));
        job.update(|s| {
            s.finished = Some(now_s());
            match res {
                Ok(()) => { s.state = "done"; s.phase = "done".into(); }
                Err(e) if e == "cancelled" => { s.state = "cancelled"; s.phase = "cancelled".into(); }
                Err(e) => { s.state = "failed"; s.phase = "failed".into(); s.error = Some(e); }
            }
        });
    });
    id
}

// ---------- HTTP ----------

type Resp = Response;

fn err(code: StatusCode, msg: impl Into<String>) -> Resp {
    (code, Json(json!({ "error": msg.into() }))).into_response()
}

fn status_json(app: &App, id: &str) -> Option<Value> {
    let job = app.jobs.lock().unwrap().get(id).cloned();
    let meta = app.store.read_meta(id);
    if let Some(m) = meta {
        let (done, total) = job.as_ref().map(|j| { let s = j.st.lock().unwrap(); (s.halfhours_done, s.halfhours_total) }).unwrap_or((0, 0));
        return Some(json!({
            "id": id, "state": "done", "ready": true, "phase": "done", "params": m.params, "variant": m.variant, "created": m.created,
            "points": m.points, "aircraft": m.aircraft.len(), "truncated": m.truncated, "missing_halfhours": m.missing,
            "bytes_downloaded": m.bytes_downloaded, "halfhours_done": done, "halfhours_total": total,
            "tracks_url": format!("api/slices/{id}/tracks")
        }));
    }
    let job = job?;
    let s = job.st.lock().unwrap().clone();
    if s.state == "done" {
        return None; // finished but evicted since
    }
    Some(json!({
        "id": id, "state": s.state, "ready": false, "phase": s.phase, "error": s.error, "params": job.params,
        "halfhours_done": s.halfhours_done, "halfhours_total": s.halfhours_total, "points": s.points,
        "bytes_downloaded": job.bytes.load(Ordering::Relaxed), "created": s.created, "finished": s.finished
    }))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

/// Starts (or reuses) a fetch job. With no `date`, lists the slices currently on disk.
async fn slices(State(app): State<Arc<App>>, Query(q): Query<HashMap<String, String>>) -> Resp {
    if !q.contains_key("date") {
        let list = tokio::task::spawn_blocking({ let a = app.clone(); move || a.store.list() }).await.unwrap_or_default();
        let items: Vec<Value> = list.iter().map(|(m, bytes, used)| json!({ "id": m.id, "params": m.params, "points": m.points, "aircraft": m.aircraft.len(), "bytes_on_disk": bytes, "last_used": used, "expires_in_s": (app.cfg.ttl.as_secs() as i64) - (now_s() as i64 - *used as i64) })).collect();
        return Json(json!({ "slices": items })).into_response();
    }
    let p = match parse_params(&q, &app.cfg) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    let id = start_job(&app, p);
    let wait = q.get("wait").and_then(|w| w.parse::<u64>().ok()).unwrap_or(0).min(120);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait);
    loop {
        let st = status_json(&app, &id).unwrap_or_else(|| json!({ "id": id, "state": "queued", "ready": false }));
        let state = st["state"].as_str().unwrap_or("");
        if st["ready"] == true {
            return Json(st).into_response();
        }
        if matches!(state, "failed" | "cancelled") {
            return (StatusCode::BAD_GATEWAY, Json(st)).into_response();
        }
        if tokio::time::Instant::now() >= deadline {
            return (StatusCode::ACCEPTED, Json(st)).into_response();
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
}

fn valid_id(id: &str) -> bool {
    id.len() == 16 && id.bytes().all(|c| c.is_ascii_hexdigit())
}

async fn job_status(State(app): State<Arc<App>>, Path(id): Path<String>) -> Resp {
    if !valid_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad id");
    }
    match status_json(&app, &id) {
        Some(v) => Json(v).into_response(),
        None => err(StatusCode::NOT_FOUND, "unknown or expired job; request it again with GET api/slices"),
    }
}

async fn job_cancel(State(app): State<Arc<App>>, Path(id): Path<String>) -> Resp {
    if !valid_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad id");
    }
    match app.jobs.lock().unwrap().get(&id) {
        Some(j) => { j.cancel.store(true, Ordering::Relaxed); Json(json!({ "cancelling": true })).into_response() }
        None => err(StatusCode::NOT_FOUND, "no such running job"),
    }
}

async fn slice_delete(State(app): State<Arc<App>>, Path(id): Path<String>) -> Resp {
    if !valid_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad id");
    }
    let removed = app.store.delete_slice(&id);
    app.jobs.lock().unwrap().remove(&id);
    Json(json!({ "deleted": removed })).into_response()
}

fn r5(v: f64) -> f64 {
    (v * 1e5).round() / 1e5
}

fn alt_json(a: i16) -> Value {
    match a {
        -123 => json!("ground"),
        -124 => Value::Null,
        a => json!(a as i32 * 25),
    }
}

fn gs_json(g: i16) -> Value {
    if g < 0 { Value::Null } else { json!(g as f64 / 10.0) }
}

async fn tracks(State(app): State<Arc<App>>, Path(id): Path<String>, Query(q): Query<HashMap<String, String>>) -> Resp {
    if !valid_id(&id) {
        return err(StatusCode::BAD_REQUEST, "bad id");
    }
    let a = app.clone();
    let loaded = tokio::task::spawn_blocking(move || a.store.read_slice(&id)).await.ok().flatten();
    let Some((meta, recs)) = loaded else {
        return err(StatusCode::NOT_FOUND, "slice not found (never fetched, still running, or expired); start it with GET api/slices");
    };
    let hexes: HashSet<String> = q.get("hex").map(|s| s.split(',').map(|x| x.trim().to_lowercase()).filter(|x| !x.is_empty()).collect()).unwrap_or_default();
    let cs = q.get("callsign").map(|s| s.trim().to_uppercase()).filter(|s| !s.is_empty());
    let geo = q.get("format").is_some_and(|f| f == "geojson");
    let mut groups: Vec<(usize, Vec<&Rec>)> = vec![];
    for r in &recs {
        match groups.last_mut() {
            Some((ac, v)) if *ac == r.ac as usize => v.push(r),
            _ => groups.push((r.ac as usize, vec![r])),
        }
    }
    let mut out = vec![];
    for (ac, pts) in groups {
        let m = &meta.aircraft[ac];
        if !hexes.is_empty() && !hexes.contains(&m.hex) {
            continue;
        }
        if let Some(c) = &cs {
            if !m.callsign.as_ref().is_some_and(|s| s.to_uppercase().starts_with(c.as_str())) {
                continue;
            }
        }
        if geo {
            out.push(json!({ "type": "Feature",
                "geometry": { "type": "LineString", "coordinates": pts.iter().map(|r| json!([r5(r.lon as f64 / 1e6), r5(r.lat as f64 / 1e6)])).collect::<Vec<_>>() },
                "properties": { "hex": m.hex, "callsign": m.callsign, "squawk": m.squawk, "n": pts.len(),
                    "times": pts.iter().map(|r| r.t).collect::<Vec<_>>(), "alt_ft": pts.iter().map(|r| alt_json(r.alt)).collect::<Vec<_>>(), "gs_kt": pts.iter().map(|r| gs_json(r.gs)).collect::<Vec<_>>() } }));
        } else {
            out.push(json!({ "hex": m.hex, "callsign": m.callsign, "squawk": m.squawk,
                "points": pts.iter().map(|r| json!([r.t, r5(r.lat as f64 / 1e6), r5(r.lon as f64 / 1e6), alt_json(r.alt), gs_json(r.gs)])).collect::<Vec<_>>() }));
        }
    }
    if geo {
        return Json(json!({ "type": "FeatureCollection", "features": out, "properties": { "id": meta.id, "params": meta.params, "truncated": meta.truncated } })).into_response();
    }
    Json(json!({
        "id": meta.id, "params": meta.params, "truncated": meta.truncated, "missing_halfhours": meta.missing,
        "point_format": ["unix_time_s", "lat", "lon", "alt_ft (number | \"ground\" | null)", "ground_speed_kt | null"],
        "aircraft": out
    })).into_response()
}

async fn info(State(app): State<Arc<App>>) -> Json<Value> {
    let (slices, other) = app.store.usage();
    Json(json!({
        "provides": "adsb-history", "source": "adsb.lol globe_history (ODbL 1.0) via GitHub releases",
        "limits": { "ttl_hours": app.cfg.ttl.as_secs() / 3600, "cache_cap_mb": app.cfg.cache_cap >> 20, "max_download_mb_per_job": app.cfg.download_cap >> 20,
            "max_window_hours": app.cfg.max_window_s / 3600, "max_points_per_slice": app.cfg.max_points, "resolution_s": 10 },
        "disk": { "slice_bytes": slices, "index_and_tmp_bytes": other },
        "active_jobs": app.jobs.lock().unwrap().values().filter(|j| matches!(j.st.lock().unwrap().state, "queued" | "running")).count()
    }))
}

async fn tools() -> Json<Value> {
    Json(json!([
        {
            "name": "adsb_history_fetch",
            "description": "Fetch historical ADS-B positions (adsb.lol archive, 10 s resolution, UTC) for a time window of one past day, optionally limited to a bounding box, ICAO hex codes or a callsign prefix. Downloads only the needed part of the archive (about 10-20 MB per half hour) and caches it as a short-lived slice. Use wait=60 to block until ready; if the result has ready=false, poll adsb_history_job. When ready, call adsb_history_tracks with the id. Prefer short windows and small bounding boxes.",
            "method": "GET",
            "path": "api/slices?date={date}&from={from}&to={to}&bbox={bbox}&hex={hex}&callsign={callsign}&wait={wait}",
            "parameters": { "type": "object", "properties": {
                "date": { "type": "string", "description": "UTC day, YYYY-MM-DD (a past day; yesterday and older are complete)" },
                "from": { "type": "string", "description": "UTC start, HH:MM" },
                "to": { "type": "string", "description": "UTC end, HH:MM (up to 6 hours after from)" },
                "bbox": { "type": "string", "description": "optional west,south,east,north in degrees" },
                "hex": { "type": "string", "description": "optional comma-separated ICAO hex codes" },
                "callsign": { "type": "string", "description": "optional callsign prefix, e.g. UAL" },
                "wait": { "type": "string", "description": "optional seconds to wait for completion (max 120)" }
            }, "required": ["date", "from", "to"] }
        },
        {
            "name": "adsb_history_job",
            "description": "Progress of an ADS-B history fetch (state queued/running/done/failed, half hours done, bytes downloaded).",
            "method": "GET", "path": "api/jobs/{id}",
            "parameters": { "type": "object", "properties": { "id": { "type": "string", "description": "id returned by adsb_history_fetch" } }, "required": ["id"] }
        },
        {
            "name": "adsb_history_tracks",
            "description": "Positions of a ready ADS-B history slice, grouped per aircraft: [unix_time_s, lat, lon, alt_ft|\"ground\"|null, ground_speed_kt|null]. Optionally narrow by hex or callsign prefix.",
            "method": "GET", "path": "api/slices/{id}/tracks?hex={hex}&callsign={callsign}",
            "parameters": { "type": "object", "properties": {
                "id": { "type": "string", "description": "slice id" },
                "hex": { "type": "string", "description": "optional comma-separated ICAO hex codes" },
                "callsign": { "type": "string", "description": "optional callsign prefix" }
            }, "required": ["id"] }
        }
    ]))
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/info", get(info))
        .route("/api/slices", get(slices))
        .route("/api/slices/{id}", axum::routing::delete(slice_delete))
        .route("/api/slices/{id}/tracks", get(tracks))
        .route("/api/jobs/{id}", get(job_status).delete(job_cancel))
        .with_state(app)
}

pub fn build_app(cfg: Config) -> std::io::Result<Arc<App>> {
    let store = Store::new(cfg.state.clone())?;
    store.startup(cfg.ttl, cfg.cache_cap);
    Ok(Arc::new(App { up: Upstream::new(&cfg.upstream), store, jobs: Mutex::new(HashMap::new()), gate: Arc::new(tokio::sync::Semaphore::new(1)), cfg }))
}

#[tokio::main]
async fn main() {
    let cfg = Config::from_env();
    let addr: SocketAddr = cfg.bind.parse().expect("OSNT_ADSB_HISTORY_BIND");
    let app = build_app(cfg).expect("state dir");
    {
        let app = app.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(300)).await;
                let a = app.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    let n = a.store.evict(a.cfg.ttl, a.cfg.cache_cap, None);
                    if n > 0 { println!("adsb-history: evicted {n} expired/over-cap files"); }
                    // forget finished jobs after an hour
                    a.jobs.lock().unwrap().retain(|_, j| { let s = j.st.lock().unwrap(); s.finished.is_none_or(|f| now_s().saturating_sub(f) < 3600) });
                })
                .await;
            }
        });
    }
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("adsb-history plugin on http://{addr}");
    axum::serve(listener, router(app)).await.expect("serve");
}

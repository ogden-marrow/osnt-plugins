//! YouTube to MP3 plugin. Shells out to `yt-dlp` and `ffmpeg` (argument arrays only, never a shell), keeps all files
//! under OSNT_STATE_DIR, runs at most 1-2 jobs at once and deletes files after a TTL. See `plugin.toml` for settings.

pub mod store;
pub mod tools;
pub mod validate;

use std::{
    collections::{HashMap, HashSet},
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    body::Body,
    extract::{Path as UrlPath, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    sync::Semaphore,
};

const PAGE: &str = include_str!("../assets/index.html");

#[derive(Clone, Debug)]
pub struct Config {
    pub state_dir: PathBuf,
    pub max_minutes: u64,
    pub max_bytes: u64,
    pub max_jobs: usize,
    pub job_timeout: Duration,
    pub ttl: Duration,
    pub ytdlp: Option<String>,
    pub ffmpeg: Option<String>,
    /// Require the hub's gateway signature on /api (fail closed). Disabled only by OSNT_YTMP3_INSECURE_LOCAL=1.
    pub require_gateway: bool,
}

fn env_num(name: &str, default: u64, min: u64, max: u64) -> u64 {
    env::var(name).ok().and_then(|v| v.trim().parse().ok()).map_or(default, |n: u64| n.clamp(min, max))
}

impl Config {
    pub fn from_env() -> Self {
        Config {
            state_dir: PathBuf::from(env::var("OSNT_STATE_DIR").unwrap_or_else(|_| "/var/lib/osnt-yt-mp3".into())),
            max_minutes: env_num("OSNT_YTMP3_MAX_MINUTES", 60, 1, 600),
            max_bytes: env_num("OSNT_YTMP3_MAX_MB", 120, 1, 2000) * 1024 * 1024,
            max_jobs: env_num("OSNT_YTMP3_MAX_JOBS", 1, 1, 2) as usize,
            job_timeout: Duration::from_secs(env_num("OSNT_YTMP3_JOB_TIMEOUT_SECS", 1200, 30, 6 * 3600)),
            ttl: Duration::from_secs(env_num("OSNT_YTMP3_TTL_MINUTES", 120, 5, 7 * 24 * 60) * 60),
            ytdlp: env::var("OSNT_YTMP3_YTDLP").ok(),
            ffmpeg: env::var("OSNT_YTMP3_FFMPEG").ok(),
            require_gateway: env::var("OSNT_YTMP3_INSECURE_LOCAL").ok().as_deref() != Some("1"),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Job {
    pub id: String,
    /// queued | running | done | error
    pub status: String,
    pub stage: String,
    pub progress: f32,
    pub title: String,
    pub filename: String,
    pub size: u64,
    pub error: Option<String>,
    pub created: u64,
    pub expires: u64,
    pub video_id: String,
}

pub struct AppState {
    pub cfg: Config,
    jobs: Mutex<HashMap<String, Job>>,
    sem: Semaphore,
}

type Shared = Arc<AppState>;

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn clean_text(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect::<String>().trim().to_string()
}

// ---------- tools ----------

fn child_path() -> OsString {
    let mut dirs: Vec<PathBuf> = env::var_os("PATH").map(|p| env::split_paths(&p).collect()).unwrap_or_default();
    dirs.extend(tools::EXTRA_DIRS.iter().map(PathBuf::from));
    env::join_paths(dirs).unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".into())
}

/// Detected on every call, so installing a tool takes effect without restarting the plugin.
pub fn detect(cfg: &Config) -> (Option<PathBuf>, Option<PathBuf>) {
    let p = env::var_os("PATH");
    (tools::find_tool("yt-dlp", cfg.ytdlp.as_deref(), p.clone()), tools::find_tool("ffmpeg", cfg.ffmpeg.as_deref(), p))
}

/// A command for an external tool with a clean environment. HOME and every cache/config/temp location point into
/// the state dir, because the systemd sandbox makes the rest of the filesystem read-only.
fn tool_cmd(cfg: &Config, bin: &Path, args: &[String]) -> Command {
    let s = &cfg.state_dir;
    let mut c = Command::new(bin);
    c.args(args)
        .env_clear()
        .env("PATH", child_path())
        .env("HOME", s.join("home"))
        .env("XDG_CACHE_HOME", s.join("cache"))
        .env("XDG_CONFIG_HOME", s.join("home/.config"))
        .env("XDG_DATA_HOME", s.join("home/.local/share"))
        .env("TMPDIR", s.join("tmp"))
        .env("LANG", "C.UTF-8")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .current_dir(s.join("tmp"))
        .stdin(Stdio::null())
        .kill_on_drop(true);
    c
}

async fn version_of(cfg: &Config, bin: &Path, arg: &str) -> Option<String> {
    let out = tokio::time::timeout(Duration::from_secs(10), tool_cmd(cfg, bin, &[arg.to_string()]).stdout(Stdio::piped()).stderr(Stdio::null()).output()).await.ok()?.ok()?;
    let line = String::from_utf8_lossy(&out.stdout).lines().next()?.to_string();
    Some(clean_text(&line, 80))
}

// ---------- job pipeline ----------

fn update(st: &Shared, id: &str, f: impl FnOnce(&mut Job)) {
    if let Some(j) = st.jobs.lock().unwrap().get_mut(id) {
        f(j);
    }
}

fn last_error_line(s: &str) -> String {
    let lines: Vec<&str> = s.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let pick = lines.iter().rev().find(|l| l.starts_with("ERROR")).or(lines.last()).copied().unwrap_or("no details");
    let text = clean_text(pick, 300);
    match friendly_hint(&text) {
        Some(h) => format!("{text} ({h})"),
        None => text,
    }
}

/// Plain-language advice for the failures people actually hit with yt-dlp.
fn friendly_hint(err: &str) -> Option<&'static str> {
    let e = err.to_ascii_lowercase();
    if e.contains("sign in to confirm") || e.contains("not a bot") {
        Some("YouTube is asking this network for a sign-in check; updating yt-dlp or trying again later usually helps")
    } else if e.contains("private video") || e.contains("members-only") || e.contains("sign in") && e.contains("age") {
        Some("this video needs a signed-in account, which this plugin cannot use")
    } else if e.contains("unavailable") {
        Some("the video was removed, is private, or is blocked in this country")
    } else if e.contains("http error 403") || e.contains("unable to extract") || e.contains("nsig") {
        Some("yt-dlp is probably out of date: run sudo yt-dlp -U on the Pi")
    } else {
        None
    }
}

async fn pipeline(st: &Shared, id: &str, video_id: &str, start: Option<u64>, end: Option<u64>) -> Result<(), String> {
    let cfg = &st.cfg;
    let dir = store::job_dir(&cfg.state_dir, id).ok_or("bad id")?;
    let (Some(ytdlp), Some(ffmpeg)) = detect(cfg) else { return Err("yt-dlp or ffmpeg is not installed.".into()) };
    let url = validate::canonical_url(video_id);

    // 1. metadata: duration check before downloading anything.
    update(st, id, |j| {
        j.stage = "Reading video info".into();
        j.progress = 2.0;
    });
    let out = tokio::time::timeout(Duration::from_secs(90), tool_cmd(cfg, &ytdlp, &tools::probe_args(&url)).stdout(Stdio::piped()).stderr(Stdio::piped()).output())
        .await
        .map_err(|_| "Timed out reading video info.")?
        .map_err(|e| format!("Could not run yt-dlp: {e}"))?;
    if !out.status.success() {
        return Err(format!("yt-dlp could not read this video: {}", last_error_line(&String::from_utf8_lossy(&out.stderr))));
    }
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let line = stdout.lines().find(|l| !l.trim().is_empty()).ok_or("yt-dlp returned no video info.")?;
    let (dur_s, title) = line.split_once('\t').unwrap_or((line, ""));
    let duration: f64 = dur_s.trim().parse().map_err(|_| "This looks like a live stream or has no known duration.".to_string())?;
    if !(duration.is_finite() && duration > 0.0) {
        return Err("This video has no usable duration.".into());
    }
    let duration = duration.ceil() as u64;
    if duration > cfg.max_minutes * 60 {
        return Err(format!("This video is {} minutes long; the limit is {}.", duration.div_ceil(60), cfg.max_minutes));
    }
    let title = {
        let t = clean_text(title, 200);
        if t.is_empty() { "audio".to_string() } else { t }
    };
    let s = start.unwrap_or(0);
    if s >= duration {
        return Err(format!("Start time is past the end of the video ({duration} s)."));
    }
    let e = end.map_or(duration, |e| e.min(duration));
    if e <= s {
        return Err("End time must be after the start time.".into());
    }
    let trimmed = s > 0 || e < duration;
    update(st, id, |j| j.title = title.clone());

    // 2. download the audio stream.
    update(st, id, |j| {
        j.stage = "Downloading audio".into();
        j.progress = 5.0;
    });
    let template = dir.join("audio.%(ext)s");
    let mut child = tool_cmd(cfg, &ytdlp, &tools::download_args(&url, &template.to_string_lossy(), cfg.max_bytes))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Could not run yt-dlp: {e}"))?;
    let stderr = child.stderr.take().ok_or("no stderr")?;
    let err_task = tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        let mut tail: Vec<String> = Vec::new();
        while let Ok(Some(l)) = lines.next_line().await {
            tail.push(l);
            if tail.len() > 20 {
                tail.remove(0);
            }
        }
        tail.join("\n")
    });
    let mut lines = BufReader::new(child.stdout.take().ok_or("no stdout")?).lines();
    while let Ok(Some(l)) = lines.next_line().await {
        if let Some(p) = l.strip_prefix("download:").and_then(|p| p.trim().trim_end_matches('%').trim().parse::<f32>().ok()) {
            update(st, id, |j| j.progress = 5.0 + p.clamp(0.0, 100.0) * 0.8);
        }
    }
    let status = child.wait().await.map_err(|e| e.to_string())?;
    let err_text = err_task.await.unwrap_or_default();
    if !status.success() {
        return Err(format!("Download failed: {}", last_error_line(&err_text)));
    }
    let input = fs::read_dir(&dir)
        .map_err(|e| e.to_string())?
        .flatten()
        .map(|e| e.path())
        .find(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("audio.") && !n.ends_with(".part") && !n.ends_with(".ytdl")))
        .ok_or("Download finished but no audio file was found.")?;

    // 3. convert (and trim) to MP3.
    update(st, id, |j| {
        j.stage = if trimmed { "Converting and trimming".into() } else { "Converting to MP3".into() };
        j.progress = 88.0;
    });
    let output = dir.join(store::OUT_NAME);
    let args = tools::ffmpeg_args(&input, &output, start, trimmed.then_some(e - s), cfg.max_bytes);
    let res = tool_cmd(cfg, &ffmpeg, &args).stdout(Stdio::null()).stderr(Stdio::piped()).output().await.map_err(|e| format!("Could not run ffmpeg: {e}"))?;
    let _ = fs::remove_file(&input);
    if !res.status.success() {
        return Err(format!("ffmpeg failed: {}", last_error_line(&String::from_utf8_lossy(&res.stderr))));
    }
    let size = fs::metadata(&output).map_err(|_| "ffmpeg produced no output.")?.len();
    if size == 0 {
        return Err("ffmpeg produced an empty file.".into());
    }
    if size >= cfg.max_bytes {
        return Err(format!("The MP3 would exceed the {} MB size limit.", cfg.max_bytes / 1024 / 1024));
    }

    let now = now_secs();
    let done = {
        let mut jobs = st.jobs.lock().unwrap();
        let j = jobs.get_mut(id).ok_or("job vanished")?;
        j.status = "done".into();
        j.stage = "Ready".into();
        j.progress = 100.0;
        j.size = size;
        j.filename = format!("{}.mp3", validate::sanitize_filename(&title));
        j.created = now;
        j.expires = now + cfg.ttl.as_secs();
        j.clone()
    };
    let _ = fs::write(dir.join(store::META_NAME), serde_json::to_vec(&done).unwrap_or_default());
    Ok(())
}

async fn run_job(st: Shared, id: String, video_id: String, start: Option<u64>, end: Option<u64>) {
    let Ok(_permit) = st.sem.acquire().await else { return };
    update(&st, &id, |j| {
        j.status = "running".into();
        j.stage = "Starting".into();
    });
    let result = match tokio::time::timeout(st.cfg.job_timeout, pipeline(&st, &id, &video_id, start, end)).await {
        Ok(r) => r,
        Err(_) => Err(format!("Timed out after {} minutes.", st.cfg.job_timeout.as_secs() / 60)),
    };
    if let Err(msg) = result {
        if let Some(dir) = store::job_dir(&st.cfg.state_dir, &id) {
            let _ = fs::remove_dir_all(dir);
        }
        let now = now_secs();
        update(&st, &id, |j| {
            j.status = "error".into();
            j.stage = "Failed".into();
            j.error = Some(msg);
            j.created = now;
            j.expires = now + st.cfg.ttl.as_secs();
        });
    }
}

/// Removes expired files and forgets expired jobs. Running and queued jobs are never touched.
pub fn sweep(st: &AppState) -> usize {
    let now = now_secs();
    let mut jobs = st.jobs.lock().unwrap();
    let active: HashSet<String> = jobs.values().filter(|j| j.status == "queued" || j.status == "running").map(|j| j.id.clone()).collect();
    let removed = store::cleanup(&st.cfg.state_dir, st.cfg.ttl, SystemTime::now(), &active);
    jobs.retain(|id, j| active.contains(id) || (j.expires > now && store::job_dir(&st.cfg.state_dir, id).is_some_and(|d| j.status == "error" || d.join(store::OUT_NAME).exists())));
    removed
}

/// Creates the state layout, wipes scratch space, deletes expired files and reloads finished jobs for the history.
pub async fn build(cfg: Config) -> Router {
    build_with_state(cfg).await.0
}

pub async fn build_with_state(cfg: Config) -> (Router, Arc<AppState>) {
    let s = &cfg.state_dir;
    let _ = fs::remove_dir_all(s.join("tmp"));
    for d in ["jobs", "home", "cache", "tmp"] {
        if let Err(e) = fs::create_dir_all(s.join(d)) {
            eprintln!("yt-mp3: cannot create {}: {e}", s.join(d).display());
        }
    }
    store::cleanup(s, cfg.ttl, SystemTime::now(), &HashSet::new());
    let mut jobs = HashMap::new();
    if let Ok(rd) = fs::read_dir(store::jobs_root(s)) {
        for e in rd.flatten() {
            let id = e.file_name().to_string_lossy().into_owned();
            let loaded = fs::read(e.path().join(store::META_NAME)).ok().and_then(|b| serde_json::from_slice::<Job>(&b).ok());
            match loaded {
                Some(j) if j.id == id && store::valid_id(&id) && e.path().join(store::OUT_NAME).is_file() && j.status == "done" => {
                    jobs.insert(id, j);
                }
                _ => {
                    let _ = fs::remove_dir_all(e.path());
                }
            }
        }
    }
    let st = Arc::new(AppState { sem: Semaphore::new(cfg.max_jobs), jobs: Mutex::new(jobs), cfg });
    let bg = st.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(600)).await;
            sweep(&bg);
        }
    });
    let app = Router::new()
        .route("/", get(page))
        .route("/tools", get(agent_tools))
        .route("/api/status", get(status))
        .route("/api/jobs", get(list_jobs).post(create_job))
        .route("/api/jobs/{id}", get(get_job).delete(delete_job))
        .route("/api/jobs/{id}/file", get(download))
        .with_state(st.clone());
    (app, st)
}

// ---------- handlers ----------

fn error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

fn allowed(st: &Shared, method: &Method, uri: &Uri, headers: &HeaderMap) -> bool {
    !st.cfg.require_gateway || osnt_common::gateway_authorized(method.as_str(), uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"), headers.get("x-osnt-gateway").and_then(|v| v.to_str().ok()))
}

macro_rules! guard {
    ($st:expr, $m:expr, $u:expr, $h:expr) => {
        if !allowed(&$st, &$m, &$u, &$h) {
            return error(StatusCode::UNAUTHORIZED, "sign in required");
        }
    };
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

/// Deliberately empty: agents must not be able to download arbitrary media.
async fn agent_tools() -> Json<Value> {
    Json(json!([]))
}

async fn status(State(st): State<Shared>, m: Method, u: Uri, h: HeaderMap) -> Response {
    guard!(st, m, u, h);
    let (y, f) = detect(&st.cfg);
    let yv = match &y {
        Some(p) => version_of(&st.cfg, p, "--version").await,
        None => None,
    };
    let fv = match &f {
        Some(p) => version_of(&st.cfg, p, "-version").await,
        None => None,
    };
    Json(json!({
        "ready": y.is_some() && f.is_some(),
        "ytdlp": { "found": y.is_some(), "path": y, "version": yv },
        "ffmpeg": { "found": f.is_some(), "path": f, "version": fv },
        "install": { "ffmpeg": tools::INSTALL_FFMPEG, "ytdlp": tools::INSTALL_YTDLP, "ytdlp_pipx": tools::INSTALL_YTDLP_PIPX, "update": tools::UPDATE_YTDLP },
        "limits": { "max_minutes": st.cfg.max_minutes, "max_mb": st.cfg.max_bytes / 1024 / 1024, "max_jobs": st.cfg.max_jobs, "ttl_minutes": st.cfg.ttl.as_secs() / 60 },
    }))
    .into_response()
}

#[derive(Deserialize)]
struct NewJob {
    url: String,
    #[serde(default)]
    start: Option<String>,
    #[serde(default)]
    end: Option<String>,
}

async fn create_job(State(st): State<Shared>, m: Method, u: Uri, h: HeaderMap, Json(body): Json<NewJob>) -> Response {
    guard!(st, m, u, h);
    let video_id = match validate::parse_youtube_url(&body.url) {
        Ok(v) => v,
        Err(e) => return error(StatusCode::BAD_REQUEST, &e),
    };
    let start = match validate::parse_time(body.start.as_deref().unwrap_or("")) {
        Ok(v) => v,
        Err(e) => return error(StatusCode::BAD_REQUEST, &format!("Start time: {e}")),
    };
    let end = match validate::parse_time(body.end.as_deref().unwrap_or("")) {
        Ok(v) => v,
        Err(e) => return error(StatusCode::BAD_REQUEST, &format!("End time: {e}")),
    };
    if let (Some(s), Some(e)) = (start, end)
        && e <= s
    {
        return error(StatusCode::BAD_REQUEST, "End time must be after the start time.");
    }
    let (y, f) = detect(&st.cfg);
    if y.is_none() || f.is_none() {
        let missing = [("yt-dlp", y.is_none()), ("ffmpeg", f.is_none())].iter().filter(|(_, m)| *m).map(|(n, _)| *n).collect::<Vec<_>>().join(" and ");
        return error(StatusCode::SERVICE_UNAVAILABLE, &format!("{missing} not installed. See the install commands on the page."));
    }
    let Ok(id) = store::new_id() else { return error(StatusCode::INTERNAL_SERVER_ERROR, "could not create a job id") };
    let dir = store::jobs_root(&st.cfg.state_dir).join(&id);
    {
        let mut jobs = st.jobs.lock().unwrap();
        let active = jobs.values().filter(|j| j.status == "queued" || j.status == "running").count();
        if active >= st.cfg.max_jobs + 3 {
            return error(StatusCode::TOO_MANY_REQUESTS, "Too many conversions in progress. Try again in a minute.");
        }
        if let Err(e) = fs::create_dir_all(&dir) {
            return error(StatusCode::INTERNAL_SERVER_ERROR, &format!("cannot write to the state directory: {e}"));
        }
        let now = now_secs();
        jobs.insert(
            id.clone(),
            Job {
                id: id.clone(),
                status: "queued".into(),
                stage: "Waiting for a free slot".into(),
                progress: 0.0,
                title: String::new(),
                filename: String::new(),
                size: 0,
                error: None,
                created: now,
                expires: now + st.cfg.ttl.as_secs(),
                video_id: video_id.clone(),
            },
        );
    }
    tokio::spawn(run_job(st.clone(), id.clone(), video_id, start, end));
    (StatusCode::ACCEPTED, Json(json!({ "id": id }))).into_response()
}

async fn list_jobs(State(st): State<Shared>, m: Method, u: Uri, h: HeaderMap) -> Response {
    guard!(st, m, u, h);
    let mut v: Vec<Job> = st.jobs.lock().unwrap().values().cloned().collect();
    v.sort_by_key(|j| std::cmp::Reverse(j.created));
    v.truncate(30);
    Json(v).into_response()
}

async fn get_job(State(st): State<Shared>, m: Method, u: Uri, h: HeaderMap, UrlPath(id): UrlPath<String>) -> Response {
    guard!(st, m, u, h);
    match st.jobs.lock().unwrap().get(&id) {
        Some(j) => Json(j.clone()).into_response(),
        None => error(StatusCode::NOT_FOUND, "no such job (it may have expired)"),
    }
}

async fn delete_job(State(st): State<Shared>, m: Method, u: Uri, h: HeaderMap, UrlPath(id): UrlPath<String>) -> Response {
    guard!(st, m, u, h);
    let Some(dir) = store::job_dir(&st.cfg.state_dir, &id) else { return error(StatusCode::NOT_FOUND, "no such job") };
    {
        let mut jobs = st.jobs.lock().unwrap();
        match jobs.get(&id) {
            None => return error(StatusCode::NOT_FOUND, "no such job"),
            Some(j) if j.status == "queued" || j.status == "running" => return error(StatusCode::CONFLICT, "job is still running"),
            Some(_) => {
                jobs.remove(&id);
            }
        }
    }
    let _ = fs::remove_dir_all(dir);
    Json(json!({ "ok": true })).into_response()
}

async fn download(State(st): State<Shared>, m: Method, u: Uri, h: HeaderMap, UrlPath(id): UrlPath<String>) -> Response {
    guard!(st, m, u, h);
    let job = st.jobs.lock().unwrap().get(&id).filter(|j| j.status == "done").cloned();
    // The path is built from a validated 32-hex id and a fixed file name; the title never reaches the filesystem.
    let (Some(job), Some(dir)) = (job, store::job_dir(&st.cfg.state_dir, &id)) else { return error(StatusCode::NOT_FOUND, "no such file (it may have expired)") };
    let Ok(file) = tokio::fs::File::open(dir.join(store::OUT_NAME)).await else { return error(StatusCode::NOT_FOUND, "no such file (it may have expired)") };
    let len = file.metadata().await.map(|m| m.len()).unwrap_or(job.size);
    let mut res = Response::new(Body::from_stream(tokio_util::io::ReaderStream::new(file)));
    let hd = res.headers_mut();
    hd.insert(header::CONTENT_TYPE, HeaderValue::from_static("audio/mpeg"));
    hd.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    hd.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    hd.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    if let Ok(v) = HeaderValue::from_str(&validate::content_disposition(&job.title)) {
        hd.insert(header::CONTENT_DISPOSITION, v);
    }
    res
}

#[cfg(test)]
mod hint_tests {
    use super::*;

    #[test]
    fn errors_get_plain_language_hints() {
        assert!(last_error_line("ERROR: [youtube] x: Sign in to confirm you're not a bot").contains("updating yt-dlp"));
        assert!(last_error_line("WARNING: x\nERROR: [youtube] x: Video unavailable").contains("removed, is private"));
        assert!(last_error_line("ERROR: unable to extract uploader id").contains("yt-dlp -U"));
        assert_eq!(last_error_line("something odd"), "something odd");
    }
}

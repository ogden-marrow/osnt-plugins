//! Media verification helpers that complement `imgmeta` (EXIF, hashes) and `provenance` (reverse-image source finder):
//! YouTube stock thumbnail frames, video metadata and keyframes via ffprobe/ffmpeg (optional), perceptual-hash
//! comparison, error-level analysis and a Content Credentials (C2PA) reader. Nothing here detects, recognises or
//! matches people. URLs fetched server-side go through the SSRF guard in `ssrf.rs`.

mod c2pa;
mod media;
mod phash;
mod ssrf;
#[cfg(test)]
mod tests;

use std::{
    env,
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
};

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Multipart, Query, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{io::AsyncWriteExt, sync::Semaphore};

use ssrf::{Guard, guarded_agent_timeout, guarded_download, guarded_get};

const PAGE: &str = include_str!("../assets/index.html");
const UA: &str = "osnt-media-verify/0.1 (+https://github.com/ogden-marrow/osnt-hub)";
pub const MAX_UPLOAD: u64 = 150 * 1024 * 1024;
pub const MAX_DOWNLOAD: u64 = 100 * 1024 * 1024;
pub const MAX_IMAGE: u64 = 40 * 1024 * 1024;

pub struct AppState {
    pub agent: ureq::Agent,
    pub guard: Guard,
    pub yt_base: String,
    pub busy: Arc<Semaphore>,
}
pub type Shared = Arc<AppState>;

impl AppState {
    pub fn new(guard: Guard, yt_base: String) -> Shared {
        Arc::new(AppState { agent: guarded_agent_timeout(guard.clone(), UA, 120), guard, yt_base, busy: Arc::new(Semaphore::new(1)) })
    }
}

#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub String);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}
fn bad(m: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, m.into())
}
fn upstream(m: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_GATEWAY, m.into())
}
fn internal(m: impl Into<String>) -> ApiError {
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, m.into())
}
type R = Result<Json<Value>, ApiError>;

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, ApiError> + Send + 'static) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f).await.map_err(|e| internal(e.to_string()))?
}

/// A scratch directory that is removed when dropped.
pub struct Scratch(pub PathBuf);
impl Scratch {
    pub fn new() -> Result<Scratch, ApiError> {
        let p = env::temp_dir().join(format!("osnt-mv-{}-{}", std::process::id(), Sha256::digest(format!("{:?}", std::time::Instant::now()).as_bytes())[..4].iter().map(|b| format!("{b:02x}")).collect::<String>()));
        std::fs::create_dir_all(&p).map_err(|e| internal(format!("cannot create a scratch directory: {e}")))?;
        Ok(Scratch(p))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---- YouTube stock frames ------------------------------------------------------------------------

/// The 11-character video id from a YouTube URL (watch, youtu.be, shorts, embed, live) or a bare id.
pub fn youtube_id(input: &str) -> Option<String> {
    let s = input.trim();
    let ok = |id: &str| (id.len() == 11 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')).then(|| id.to_string());
    if let Some(id) = ok(s) {
        return Some(id);
    }
    let u = url::Url::parse(s).or_else(|_| url::Url::parse(&format!("https://{s}"))).ok()?;
    if !matches!(u.scheme(), "http" | "https") {
        return None;
    }
    let host = u.host_str()?.trim_start_matches("www.").trim_start_matches("m.").trim_start_matches("music.");
    match host {
        "youtu.be" => ok(u.path_segments()?.next()?),
        "youtube.com" | "youtube-nocookie.com" => {
            if let Some((_, v)) = u.query_pairs().find(|(k, _)| k == "v") {
                return ok(&v);
            }
            let mut seg = u.path_segments()?;
            match seg.next()? {
                "shorts" | "embed" | "live" | "v" => ok(seg.next()?),
                _ => None,
            }
        }
        _ => None,
    }
}

#[derive(Deserialize)]
pub struct UrlQ {
    url: String,
}

fn youtube_frames(input: &str) -> Result<Value, ApiError> {
    let id = youtube_id(input).ok_or_else(|| bad("that is not a YouTube video link or 11-character video id"))?;
    let frames: Vec<Value> = [("0", "Full frame (default)"), ("1", "Start"), ("2", "Middle"), ("3", "End"), ("hq", "High quality"), ("maxres", "Max resolution (when available)")]
        .iter()
        .map(|(n, label)| {
            let file = match *n { "hq" => "hqdefault.jpg".to_string(), "maxres" => "maxresdefault.jpg".to_string(), k => format!("{k}.jpg") };
            json!({ "n": n, "label": label, "src": format!("api/youtube/frame?id={id}&n={n}"), "public_url": format!("https://i.ytimg.com/vi/{id}/{file}") })
        })
        .collect();
    Ok(json!({
        "id": id, "frames": frames,
        "links": { "watch": format!("https://www.youtube.com/watch?v={id}"), "wayback": format!("https://web.archive.org/web/*/https://www.youtube.com/watch?v={id}") },
        "note": "These are YouTube's own stock frames. Reverse-searching them often finds earlier uploads of the same footage. The upload date is on the YouTube page, not in these images.",
    }))
}

async fn youtube_h(Query(q): Query<UrlQ>) -> R {
    Ok(Json(youtube_frames(&q.url)?))
}

#[derive(Deserialize)]
pub struct FrameQ {
    id: String,
    n: String,
}

async fn youtube_frame_h(State(s): State<Shared>, Query(q): Query<FrameQ>) -> Result<Response, ApiError> {
    let id = youtube_id(&q.id).filter(|i| *i == q.id).ok_or_else(|| bad("invalid video id"))?;
    let file = match q.n.as_str() {
        "0" | "1" | "2" | "3" => format!("{}.jpg", q.n),
        "hq" => "hqdefault.jpg".into(),
        "maxres" => "maxresdefault.jpg".into(),
        _ => return Err(bad("n must be 0-3, hq or maxres")),
    };
    let url = format!("{}/vi/{id}/{file}", s.yt_base);
    let f = blocking(move || guarded_get(&s.agent, &s.guard, &url, 3 * 1024 * 1024, "image/*").map_err(upstream)).await?;
    if f.status == 404 {
        return Err(ApiError(StatusCode::NOT_FOUND, "YouTube has no such frame for this video".into()));
    }
    if f.status != 200 || !f.body.starts_with(&[0xFF, 0xD8]) {
        return Err(upstream(format!("YouTube answered HTTP {} without an image", f.status)));
    }
    Ok(([(header::CONTENT_TYPE, "image/jpeg"), (header::CACHE_CONTROL, "private, max-age=3600")], f.body).into_response())
}

// ---- receiving files -----------------------------------------------------------------------------

pub struct Source {
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
    pub name: Option<String>,
}

/// Stream an upload to disk with a size cap and a running hash.
async fn receive(body: Body, dir: &FsPath, max: u64) -> Result<Source, ApiError> {
    let path = dir.join("upload.bin");
    let mut f = tokio::fs::File::create(&path).await.map_err(|e| internal(e.to_string()))?;
    let mut stream = body.into_data_stream();
    let (mut total, mut h) = (0u64, Sha256::new());
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| bad(format!("upload interrupted: {e}")))?;
        total += chunk.len() as u64;
        if total > max {
            return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, format!("the file is larger than the {} MB limit", max / 1024 / 1024)));
        }
        h.update(&chunk);
        f.write_all(&chunk).await.map_err(|e| internal(e.to_string()))?;
    }
    f.flush().await.map_err(|e| internal(e.to_string()))?;
    if total == 0 {
        return Err(bad("empty body: POST the raw file bytes"));
    }
    Ok(Source { path, bytes: total, sha256: h.finalize().iter().map(|b| format!("{b:02x}")).collect(), name: None })
}

fn fetch_url(s: &AppState, dir: &FsPath, url: &str, max: u64) -> Result<Source, ApiError> {
    let url = url.trim();
    if url.len() > 2000 || !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(bad("enter a full http:// or https:// URL"));
    }
    let path = dir.join("download.bin");
    let d = guarded_download(&s.agent, &s.guard, url, &path, max).map_err(|e| if e.starts_with("blocked") { bad(e) } else { upstream(e) })?;
    Ok(Source { path, bytes: d.bytes, sha256: d.sha256, name: d.final_url.rsplit('/').next().map(|n| n.split('?').next().unwrap_or("").to_string()).filter(|n| !n.is_empty()) })
}

fn kind_of(b: &[u8]) -> &'static str {
    match b {
        [0xFF, 0xD8, 0xFF, ..] => "jpeg",
        [0x89, b'P', b'N', b'G', ..] => "png",
        [b'G', b'I', b'F', b'8', ..] => "gif",
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => "webp",
        _ => "media",
    }
}

fn head(path: &FsPath) -> Vec<u8> {
    use std::io::Read;
    let mut b = vec![0u8; 16];
    let n = std::fs::File::open(path).and_then(|mut f| f.read(&mut b)).unwrap_or(0);
    b.truncate(n);
    b
}

// ---- analysis ------------------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct AnalyzeQ {
    url: Option<String>,
    /// "1" adds an error-level analysis image for pictures.
    ela: Option<String>,
}

pub fn analyze_source(src: &Source, ela: bool) -> Result<Value, ApiError> {
    let kind = kind_of(&head(&src.path));
    let mut out = json!({ "file": { "bytes": src.bytes, "sha256": src.sha256, "name": src.name, "kind": kind } });
    if kind != "media" {
        if src.bytes > MAX_IMAGE {
            return Err(bad(format!("images are limited to {} MB here", MAX_IMAGE / 1024 / 1024)));
        }
        let bytes = std::fs::read(&src.path).map_err(|e| internal(e.to_string()))?;
        let img = phash::decode(&bytes).map_err(bad)?;
        out["image"] = json!({ "width": img.width(), "height": img.height(), "hashes": phash::hashes(&img) });
        out["c2pa"] = c2pa::scan(&bytes);
        if ela {
            out["ela"] = if kind == "jpeg" { phash::ela(&img).map_err(internal)? } else { json!({ "unavailable": "Error-level analysis is meaningful for JPEG photos. This file is not a JPEG." }) };
        }
        return Ok(out);
    }
    let (probe_ok, _) = media::available();
    if !probe_ok {
        return Err(ApiError(StatusCode::NOT_IMPLEMENTED, "ffprobe is not installed on this hub, so audio and video files cannot be inspected. Install ffmpeg (the plugin offers it as an approved system package).".into()));
    }
    out["media"] = media::probe(&src.path).map_err(|e| bad(format!("this does not look like a readable media file: {e}")))?;
    out["c2pa"] = c2pa::scan_file(&src.path);
    Ok(out)
}

fn lock(s: &AppState) -> Result<tokio::sync::OwnedSemaphorePermit, ApiError> {
    s.busy.clone().try_acquire_owned().map_err(|_| ApiError(StatusCode::TOO_MANY_REQUESTS, "another analysis is running on this hub; try again in a moment".into()))
}

async fn analyze_post(State(s): State<Shared>, Query(q): Query<AnalyzeQ>, body: Body) -> R {
    let _p = lock(&s)?;
    let dir = Scratch::new()?;
    let src = receive(body, &dir.0, MAX_UPLOAD).await?;
    let ela = q.ela.as_deref() == Some("1");
    Ok(Json(blocking(move || analyze_source(&src, ela)).await?))
}

async fn analyze_get(State(s): State<Shared>, Query(q): Query<AnalyzeQ>) -> R {
    let url = q.url.clone().ok_or_else(|| bad("url is required"))?;
    let _p = lock(&s)?;
    let ela = q.ela.as_deref() == Some("1");
    Ok(Json(blocking(move || {
        let dir = Scratch::new()?;
        let src = fetch_url(&s, &dir.0, &url, MAX_DOWNLOAD)?;
        let mut v = analyze_source(&src, ela)?;
        v["source_url"] = json!(url);
        Ok(v)
    })
    .await?))
}

// ---- keyframes -----------------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct FramesQ {
    url: Option<String>,
    count: Option<usize>,
    mode: Option<String>,
    /// "0" leaves the picture data out (agent tools only need times and hashes).
    images: Option<String>,
}

pub fn extract_frames(src: &Source, dir: &FsPath, q: &FramesQ) -> Result<Value, ApiError> {
    let (_, ff) = media::available();
    if !ff {
        return Err(ApiError(StatusCode::NOT_IMPLEMENTED, "ffmpeg is not installed on this hub, so keyframes cannot be extracted. YouTube stock frames and image tools still work.".into()));
    }
    if kind_of(&head(&src.path)) != "media" {
        return Err(bad("that is a still image, not a video. Use the image analysis instead."));
    }
    let count = q.count.unwrap_or(12).clamp(2, 24);
    let mode = if q.mode.as_deref() == Some("even") { "even" } else { "keyframes" };
    let info = media::probe(&src.path).map_err(|e| bad(format!("this does not look like a readable video: {e}")))?;
    if !info["streams"].as_array().is_some_and(|s| s.iter().any(|x| x["type"] == "video")) {
        return Err(bad("this file has no video stream"));
    }
    let work = dir.join("frames");
    std::fs::create_dir_all(&work).map_err(|e| internal(e.to_string()))?;
    let (frames, used) = media::frames(&src.path, &work, count, mode, info["duration_s"].as_f64()).map_err(bad)?;
    let hashes: Vec<Option<u64>> = frames.iter().map(|f| image::load_from_memory(&f.jpeg).ok().map(|i| phash::phash(&i))).collect();
    let with_images = q.images.as_deref() != Some("0");
    let out: Vec<Value> = frames
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let dup: Vec<usize> = (0..i).filter(|j| matches!((hashes[i], hashes[*j]), (Some(a), Some(b)) if phash::ham(a, b) <= 6)).collect();
            let mut v = json!({ "index": f.index, "time_s": f.time_s.map(|t| (t * 100.0).round() / 100.0), "phash": hashes[i].map(phash::hex), "similar_to": dup });
            if with_images {
                v["image"] = json!(media::data_uri_jpeg(&f.jpeg));
            }
            v
        })
        .collect();
    let dups = out.iter().filter(|f| !f["similar_to"].as_array().unwrap().is_empty()).count();
    Ok(json!({
        "mode_used": used, "requested_mode": mode, "count": out.len(), "duration_s": info["duration_s"], "frames": out, "near_duplicate_frames": dups,
        "file": { "bytes": src.bytes, "sha256": src.sha256 }, "flags": info["flags"],
        "note": if used == "keyframes" { "Keyframes are the encoder's full pictures, usually at scene changes. Sparse keyframes in a long clip mean the frames shown are far apart." } else { "Frames were taken at evenly spaced times." },
    }))
}

async fn frames_post(State(s): State<Shared>, Query(q): Query<FramesQ>, body: Body) -> R {
    let _p = lock(&s)?;
    let dir = Scratch::new()?;
    let src = receive(body, &dir.0, MAX_UPLOAD).await?;
    Ok(Json(blocking(move || extract_frames(&src, &dir.0, &q)).await?))
}

async fn frames_get(State(s): State<Shared>, Query(q): Query<FramesQ>) -> R {
    let url = q.url.clone().ok_or_else(|| bad("url is required"))?;
    let _p = lock(&s)?;
    Ok(Json(blocking(move || {
        let dir = Scratch::new()?;
        let src = fetch_url(&s, &dir.0, &url, MAX_DOWNLOAD)?;
        let mut v = extract_frames(&src, &dir.0, &q)?;
        v["source_url"] = json!(url);
        Ok(v)
    })
    .await?))
}

// ---- compare two images --------------------------------------------------------------------------

async fn compare_h(State(s): State<Shared>, mut mp: Multipart) -> R {
    let _p = lock(&s)?;
    let (mut a, mut b): (Option<Vec<u8>>, Option<Vec<u8>>) = (None, None);
    while let Some(field) = mp.next_field().await.map_err(|e| bad(format!("bad upload: {e}")))? {
        let name = field.name().unwrap_or("").to_string();
        let data = field.bytes().await.map_err(|e| bad(format!("bad upload: {e}")))?;
        if data.len() as u64 > MAX_IMAGE {
            return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, format!("each image is limited to {} MB", MAX_IMAGE / 1024 / 1024)));
        }
        match name.as_str() {
            "a" => a = Some(data.to_vec()),
            "b" => b = Some(data.to_vec()),
            _ => {}
        }
    }
    let (a, b) = (a.ok_or_else(|| bad("send two files named a and b"))?, b.ok_or_else(|| bad("send two files named a and b"))?);
    Ok(Json(blocking(move || {
        let (ia, ib) = (phash::decode(&a).map_err(|e| bad(format!("image A: {e}")))?, phash::decode(&b).map_err(|e| bad(format!("image B: {e}")))?);
        let mut v = phash::compare(&ia, &ib);
        let sha = |d: &[u8]| Sha256::digest(d).iter().map(|x| format!("{x:02x}")).collect::<String>();
        v["a"]["sha256"] = json!(sha(&a));
        v["b"]["sha256"] = json!(sha(&b));
        v["identical_bytes"] = json!(a == b);
        v["c2pa"] = json!({ "a": c2pa::scan(&a)["present"], "b": c2pa::scan(&b)["present"] });
        Ok(v)
    })
    .await?))
}

// ---- misc ----------------------------------------------------------------------------------------

async fn status_h() -> Json<Value> {
    let (probe, ff) = media::available();
    Json(json!({ "ffprobe": probe, "ffmpeg": ff, "limits": { "upload_mb": MAX_UPLOAD / 1024 / 1024, "download_mb": MAX_DOWNLOAD / 1024 / 1024, "image_mb": MAX_IMAGE / 1024 / 1024 },
                 "note": "Without ffmpeg only video metadata and keyframes are unavailable." }))
}

async fn tools() -> Json<Value> {
    Json(json!([
        { "name": "media_probe", "description": "Download a public image or video URL (size-limited, SSRF-guarded) and report file hash, container metadata (creation time, codecs, encoder, embedded location), flags worth a closer look, perceptual hashes for images and any Content Credentials (C2PA) the file declares (signatures are not validated). Large files may exceed the 40 s tool limit.",
          "method": "GET", "path": "api/analyze", "parameters": { "type": "object", "properties": { "url": { "type": "string", "description": "Direct link to the image or video file" } }, "required": ["url"] } },
        { "name": "media_keyframes", "description": "Download a public video URL and return keyframe times and perceptual hashes with near-duplicate frame markers (no picture data). Needs ffmpeg on the hub.",
          "method": "GET", "path": "api/keyframes", "parameters": { "type": "object", "properties": { "url": { "type": "string" }, "count": { "type": "integer", "description": "Frames to sample (2-24, default 12)" }, "mode": { "type": "string", "enum": ["keyframes", "even"] }, "images": { "type": "string", "enum": ["0"], "description": "Always pass 0 to omit picture data" } }, "required": ["url", "images"] } },
        { "name": "media_youtube_frames", "description": "Given a YouTube link or video id, list the public stock thumbnail frame URLs (i.ytimg.com) that can be reverse-image searched.",
          "method": "GET", "path": "api/youtube", "parameters": { "type": "object", "properties": { "url": { "type": "string", "description": "YouTube video URL or 11-character id" } }, "required": ["url"] } },
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

pub fn app(state: Shared) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/status", get(status_h))
        .route("/api/youtube", get(youtube_h))
        .route("/api/youtube/frame", get(youtube_frame_h))
        .route("/api/analyze", get(analyze_get).post(analyze_post))
        .route("/api/keyframes", get(frames_get).post(frames_post))
        .route("/api/compare", post(compare_h))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD as usize))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    let state = AppState::new(Guard::default(), "https://i.ytimg.com".into());
    let addr: SocketAddr = env::var("OSNT_MEDIA_VERIFY_BIND").unwrap_or_else(|_| "127.0.0.1:8162".into()).parse().expect("bind addr");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("media-verify plugin on http://{addr}");
    axum::serve(listener, app(state)).await.expect("serve");
}

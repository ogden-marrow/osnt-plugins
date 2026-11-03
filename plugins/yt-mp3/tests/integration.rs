//! End-to-end tests with fake `yt-dlp` / `ffmpeg` shell scripts: no network, no real tools.

use std::{fs, os::unix::fs::PermissionsExt, path::Path, time::Duration};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;
use yt_mp3::{Config, Job};

const URL: &str = "https://www.youtube.com/watch?v=dQw4w9WgXcQ";

const FAKE_YTDLP: &str = r#"#!/bin/sh
D=$(dirname "$0")
echo "$@" >> "$D/ytdlp.calls"
echo "HOME=$HOME TMPDIR=$TMPDIR XDG_CACHE_HOME=$XDG_CACHE_HOME PWD=$(pwd)" > "$D/ytdlp.env"
case "$*" in *--version*) echo 2025.01.01; exit 0;; esac
if [ -f "$D/ytdlp.fail" ]; then echo "ERROR: [youtube] Video unavailable" >&2; exit 1; fi
case "$*" in *--print*) cat "$D/probe.txt"; exit 0;; esac
OUT=""
while [ $# -gt 0 ]; do if [ "$1" = "-o" ]; then OUT="$2"; fi; shift; done
OUT=$(echo "$OUT" | sed 's/%(ext)s/webm/')
[ -f "$D/ytdlp.sleep" ] && sleep "$(cat "$D/ytdlp.sleep")"
[ -f "$D/ytdlp.hang" ] && exec sleep 30
echo "download:  10.0%"
echo "download:  50.0%"
echo "download: 100.0%"
printf 'fakeaudio' > "$OUT"
"#;

const FAKE_FFMPEG: &str = r#"#!/bin/sh
D=$(dirname "$0")
case "$*" in *-version*) echo "ffmpeg version fake-1.0"; exit 0;; esac
echo "$@" >> "$D/ffmpeg.calls"
for a; do last=$a; done
head -c 2048 /dev/zero > "$last"
"#;

struct Env {
    tools: TempDir,
    state: TempDir,
    cfg: Config,
}

fn script(dir: &Path, name: &str, body: &str) -> String {
    let p = dir.join(name);
    fs::write(&p, body).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    p.to_string_lossy().into_owned()
}

fn setup() -> Env {
    let tools = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    fs::write(tools.path().join("probe.txt"), "212\tTest: Song / Name\n").unwrap();
    let cfg = Config {
        state_dir: state.path().to_path_buf(),
        max_minutes: 60,
        max_bytes: 10 * 1024 * 1024,
        max_jobs: 1,
        job_timeout: Duration::from_secs(20),
        ttl: Duration::from_secs(7200),
        ytdlp: Some(script(tools.path(), "yt-dlp", FAKE_YTDLP)),
        ffmpeg: Some(script(tools.path(), "ffmpeg", FAKE_FFMPEG)),
        require_gateway: false,
    };
    Env { tools, state, cfg }
}

async fn req(app: &Router, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut b = Request::builder().method(method).uri(uri);
    let body = match body {
        Some(v) => {
            b = b.header(header::CONTENT_TYPE, "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let res = app.clone().oneshot(b.body(body).unwrap()).await.unwrap();
    let (status, headers) = (res.status(), res.headers().clone());
    (status, headers, to_bytes(res.into_body(), usize::MAX).await.unwrap().to_vec())
}

async fn json_of(app: &Router, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    let (s, _, b) = req(app, method, uri, body).await;
    (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

async fn start(app: &Router, body: Value) -> String {
    let (s, v) = json_of(app, "POST", "/api/jobs", Some(body)).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    v["id"].as_str().unwrap().to_string()
}

async fn finish(app: &Router, id: &str) -> Value {
    for _ in 0..200 {
        let (_, v) = json_of(app, "GET", &format!("/api/jobs/{id}"), None).await;
        if v["status"] == "done" || v["status"] == "error" {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("job did not finish");
}

#[tokio::test]
async fn full_flow_download_and_history() {
    let e = setup();
    let app = yt_mp3::build(e.cfg.clone()).await;

    let (s, v) = json_of(&app, "GET", "/api/status", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["ready"], true);
    assert_eq!(v["ytdlp"]["version"], "2025.01.01");
    assert_eq!(v["ffmpeg"]["version"], "ffmpeg version fake-1.0");

    let id = start(&app, json!({ "url": URL, "start": "0:30", "end": "1:30" })).await;
    let job = finish(&app, &id).await;
    assert_eq!(job["status"], "done", "{job}");
    assert_eq!(job["progress"], 100.0);
    assert_eq!(job["title"], "Test: Song / Name");
    assert_eq!(job["filename"], "Test Song Name.mp3");
    assert_eq!(job["size"], 2048);

    // yt-dlp got the canonical URL after `--`; ffmpeg got the trim.
    let calls = fs::read_to_string(e.tools.path().join("ytdlp.calls")).unwrap();
    assert!(calls.lines().filter(|l| *l != "--version").all(|l| l.ends_with(&format!("-- {URL}"))), "{calls}");
    let ff = fs::read_to_string(e.tools.path().join("ffmpeg.calls")).unwrap();
    assert!(ff.contains("-ss 30 ") && ff.contains("-t 60 "), "{ff}");
    // Scratch/cache/HOME all live under the state dir.
    let env = fs::read_to_string(e.tools.path().join("ytdlp.env")).unwrap();
    let sd = e.state.path().to_str().unwrap();
    assert!(env.contains(&format!("HOME={sd}/home")) && env.contains(&format!("TMPDIR={sd}/tmp")) && env.contains(&format!("XDG_CACHE_HOME={sd}/cache")), "{env}");
    assert!(env.contains(&format!("PWD={sd}/tmp")) || env.contains("/tmp"), "{env}");

    let (s, h, body) = req(&app, "GET", &format!("/api/jobs/{id}/file"), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body.len(), 2048);
    assert_eq!(h[header::CONTENT_TYPE], "audio/mpeg");
    assert_eq!(h[header::CONTENT_LENGTH], "2048");
    let cd = h[header::CONTENT_DISPOSITION].to_str().unwrap();
    assert!(cd.starts_with("attachment; filename=\"Test Song Name.mp3\""), "{cd}");
    assert_eq!(h["x-content-type-options"], "nosniff");

    // Only out.mp3 + meta.json remain (the intermediate audio file is gone).
    let mut names: Vec<_> = fs::read_dir(e.state.path().join("jobs").join(&id)).unwrap().map(|f| f.unwrap().file_name().into_string().unwrap()).collect();
    names.sort();
    assert_eq!(names, ["meta.json", "out.mp3"]);

    let (_, list) = json_of(&app, "GET", "/api/jobs", None).await;
    assert_eq!(list.as_array().unwrap().len(), 1);

    let (s, _) = json_of(&app, "DELETE", &format!("/api/jobs/{id}"), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(req(&app, "GET", &format!("/api/jobs/{id}/file"), None).await.0, StatusCode::NOT_FOUND);
    assert!(!e.state.path().join("jobs").join(&id).exists());

    // Untrimmed jobs pass no -ss / -t.
    let id = start(&app, json!({ "url": "https://youtu.be/dQw4w9WgXcQ" })).await;
    assert_eq!(finish(&app, &id).await["status"], "done");
    let ff = fs::read_to_string(e.tools.path().join("ffmpeg.calls")).unwrap();
    let last = ff.lines().last().unwrap();
    assert!(!last.contains("-ss") && !last.contains(" -t "), "{last}");
}

#[tokio::test]
async fn page_tools_and_gateway() {
    let e = setup();
    let app = yt_mp3::build(e.cfg.clone()).await;
    let (s, _, body) = req(&app, "GET", "/", None).await;
    assert_eq!(s, StatusCode::OK);
    let html = String::from_utf8(body).unwrap();
    assert!(html.contains("may violate YouTube's Terms of Service"));
    let (s, v) = json_of(&app, "GET", "/tools", None).await;
    assert_eq!((s, v), (StatusCode::OK, json!([])));

    let mut cfg = e.cfg.clone();
    cfg.require_gateway = true;
    let app = yt_mp3::build(cfg).await;
    for (m, u) in [("GET", "/api/status"), ("GET", "/api/jobs"), ("POST", "/api/jobs"), ("GET", "/api/jobs/x/file")] {
        let (s, _, _) = req(&app, m, u, if m == "POST" { Some(json!({ "url": URL })) } else { None }).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{m} {u}");
    }
    assert_eq!(req(&app, "GET", "/", None).await.0, StatusCode::OK);
}

#[tokio::test]
async fn missing_tools_degrade_gracefully() {
    let mut e = setup();
    e.cfg.ytdlp = Some("/nonexistent/yt-dlp".into());
    let app = yt_mp3::build(e.cfg.clone()).await;
    let (_, v) = json_of(&app, "GET", "/api/status", None).await;
    assert_eq!(v["ready"], false);
    assert_eq!(v["ytdlp"]["found"], false);
    assert_eq!(v["ffmpeg"]["found"], true);
    assert!(v["install"]["ffmpeg"].as_str().unwrap().contains("apt"));
    assert!(v["install"]["ytdlp"].as_str().unwrap().contains("yt-dlp"));
    let (s, v) = json_of(&app, "POST", "/api/jobs", Some(json!({ "url": URL }))).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert!(v["error"].as_str().unwrap().contains("yt-dlp not installed"), "{v}");
    assert_eq!(req(&app, "GET", "/", None).await.0, StatusCode::OK, "rest of the plugin keeps working");
    assert_eq!(json_of(&app, "GET", "/api/jobs", None).await.1, json!([]));
}

#[tokio::test]
async fn bad_input_is_rejected_before_any_tool_runs() {
    let e = setup();
    let app = yt_mp3::build(e.cfg.clone()).await;
    for body in [
        json!({ "url": "http://www.youtube.com/watch?v=dQw4w9WgXcQ" }),
        json!({ "url": "https://evil.example/watch?v=dQw4w9WgXcQ" }),
        json!({ "url": "https://youtu.be/dQw4w9WgXcQ; rm -rf /" }),
        json!({ "url": "--exec" }),
        json!({ "url": URL, "start": "abc" }),
        json!({ "url": URL, "end": "1:99" }),
        json!({ "url": URL, "start": "2:00", "end": "1:00" }),
    ] {
        let (s, v) = json_of(&app, "POST", "/api/jobs", Some(body.clone())).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body} -> {v}");
        assert!(v["error"].is_string());
    }
    assert!(!e.tools.path().join("ytdlp.calls").exists(), "yt-dlp must not have been invoked");
}

#[tokio::test]
async fn duration_limit_and_livestreams() {
    let e = setup();
    let app = yt_mp3::build(e.cfg.clone()).await;
    fs::write(e.tools.path().join("probe.txt"), "7200\tToo long\n").unwrap();
    let id = start(&app, json!({ "url": URL })).await;
    let j = finish(&app, &id).await;
    assert_eq!(j["status"], "error");
    assert!(j["error"].as_str().unwrap().contains("limit is 60"), "{j}");
    assert!(!e.state.path().join("jobs").join(&id).exists(), "failed job leaves no files");
    assert!(!e.tools.path().join("ffmpeg.calls").exists());

    fs::write(e.tools.path().join("probe.txt"), "NA\tLive\n").unwrap();
    let j = finish(&app, &start(&app, json!({ "url": URL })).await).await;
    assert!(j["error"].as_str().unwrap().contains("live stream"), "{j}");

    fs::write(e.tools.path().join("probe.txt"), "100\tShort\n").unwrap();
    let j = finish(&app, &start(&app, json!({ "url": URL, "start": "5:00" })).await).await;
    assert!(j["error"].as_str().unwrap().contains("past the end"), "{j}");
}

#[tokio::test]
async fn size_cap_and_tool_failure() {
    let mut e = setup();
    e.cfg.max_bytes = 1000; // the fake ffmpeg writes 2048 bytes
    let app = yt_mp3::build(e.cfg.clone()).await;
    let j = finish(&app, &start(&app, json!({ "url": URL })).await).await;
    assert_eq!(j["status"], "error");
    assert!(j["error"].as_str().unwrap().contains("size limit"), "{j}");

    let mut e = setup();
    fs::write(e.tools.path().join("ytdlp.fail"), "").unwrap();
    e.cfg.max_bytes = 1 << 20;
    let app = yt_mp3::build(e.cfg.clone()).await;
    let j = finish(&app, &start(&app, json!({ "url": URL })).await).await;
    assert!(j["error"].as_str().unwrap().contains("Video unavailable"), "{j}");
}

#[tokio::test]
async fn per_job_timeout_kills_the_tool() {
    let mut e = setup();
    fs::write(e.tools.path().join("ytdlp.hang"), "").unwrap();
    e.cfg.job_timeout = Duration::from_secs(1);
    let app = yt_mp3::build(e.cfg.clone()).await;
    let j = finish(&app, &start(&app, json!({ "url": URL })).await).await;
    assert_eq!(j["status"], "error");
    assert!(j["error"].as_str().unwrap().contains("Timed out"), "{j}");
}

#[tokio::test]
async fn concurrency_limit_queues_second_job() {
    let e = setup();
    fs::write(e.tools.path().join("ytdlp.sleep"), "1").unwrap();
    let app = yt_mp3::build(e.cfg.clone()).await;
    let a = start(&app, json!({ "url": URL })).await;
    let b = start(&app, json!({ "url": URL })).await;
    let mut saw = false;
    for _ in 0..40 {
        let (_, ja) = json_of(&app, "GET", &format!("/api/jobs/{a}"), None).await;
        let (_, jb) = json_of(&app, "GET", &format!("/api/jobs/{b}"), None).await;
        let running = [&ja, &jb].iter().filter(|j| j["status"] == "running").count();
        assert!(running <= 1, "never more than max_jobs running");
        if ja["status"] == "running" && jb["status"] == "queued" {
            saw = true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(saw, "second job should wait in the queue");
    assert_eq!(finish(&app, &a).await["status"], "done");
    assert_eq!(finish(&app, &b).await["status"], "done");
}

#[tokio::test]
async fn too_many_active_jobs_get_429() {
    let e = setup();
    fs::write(e.tools.path().join("ytdlp.sleep"), "2").unwrap();
    let app = yt_mp3::build(e.cfg.clone()).await;
    for _ in 0..4 {
        start(&app, json!({ "url": URL })).await;
    }
    let (s, _) = json_of(&app, "POST", "/api/jobs", Some(json!({ "url": URL }))).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn no_path_traversal_on_download() {
    let e = setup();
    fs::write(e.state.path().join("secret.txt"), "s").unwrap();
    let app = yt_mp3::build(e.cfg.clone()).await;
    for id in ["..", "..%2f..%2fetc%2fpasswd", "%2e%2e", "../jobs", "not-an-id", "A".repeat(32).as_str(), &"a".repeat(32)] {
        for suffix in ["/file", ""] {
            let (s, _, body) = req(&app, "GET", &format!("/api/jobs/{id}{suffix}"), None).await;
            assert!(s == StatusCode::NOT_FOUND, "{id}{suffix} -> {s}");
            assert!(!String::from_utf8_lossy(&body).contains("root:"));
        }
        assert!(req(&app, "DELETE", &format!("/api/jobs/{id}"), None).await.0 == StatusCode::NOT_FOUND);
    }
    assert!(e.state.path().join("secret.txt").exists() && e.state.path().join("jobs").exists());
}

#[tokio::test]
async fn startup_cleans_expired_and_reloads_history() {
    let e = setup();
    let jobs = e.state.path().join("jobs");
    let (old, fresh, junk) = ("a".repeat(32), "b".repeat(32), "c".repeat(32));
    for id in [&old, &fresh] {
        fs::create_dir_all(jobs.join(id)).unwrap();
        fs::write(jobs.join(id).join("out.mp3"), b"mp3").unwrap();
    }
    fs::create_dir_all(jobs.join(&junk)).unwrap(); // half-finished job without output
    let meta = |id: &str| serde_json::to_vec(&Job { id: id.into(), status: "done".into(), stage: "Ready".into(), progress: 100.0, title: "Old one".into(), filename: "Old one.mp3".into(), size: 3, error: None, created: 1, expires: u64::MAX, video_id: "dQw4w9WgXcQ".into() }).unwrap();
    for id in [&old, &fresh] {
        fs::write(jobs.join(id).join("meta.json"), meta(id)).unwrap();
    }
    let past = std::time::SystemTime::now() - Duration::from_secs(5 * 3600);
    for p in [jobs.join(&old).join("out.mp3"), jobs.join(&old).join("meta.json"), jobs.join(&old)] {
        fs::File::open(p).unwrap().set_modified(past).unwrap();
    }
    fs::create_dir_all(e.state.path().join("tmp")).unwrap();
    fs::write(e.state.path().join("tmp/leftover"), "x").unwrap();

    let app = yt_mp3::build(e.cfg.clone()).await;
    assert!(!jobs.join(&old).exists(), "expired job removed at startup");
    assert!(!jobs.join(&junk).exists(), "incomplete job removed at startup");
    assert!(!e.state.path().join("tmp/leftover").exists(), "scratch wiped at startup");
    let (_, list) = json_of(&app, "GET", "/api/jobs", None).await;
    let ids: Vec<&str> = list.as_array().unwrap().iter().map(|j| j["id"].as_str().unwrap()).collect();
    assert_eq!(ids, [fresh.as_str()]);
    assert_eq!(req(&app, "GET", &format!("/api/jobs/{fresh}/file"), None).await.0, StatusCode::OK);
}

#[tokio::test]
async fn sweep_removes_expired_jobs_while_running() {
    let mut e = setup();
    e.cfg.ttl = Duration::from_secs(1);
    let (app, st) = yt_mp3::build_with_state(e.cfg.clone()).await;
    let id = start(&app, json!({ "url": URL })).await;
    assert_eq!(finish(&app, &id).await["status"], "done");
    assert_eq!(yt_mp3::sweep(&st), 0, "fresh file survives");
    tokio::time::sleep(Duration::from_millis(2200)).await;
    assert_eq!(yt_mp3::sweep(&st), 1);
    assert_eq!(req(&app, "GET", &format!("/api/jobs/{id}/file"), None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(json_of(&app, "GET", "/api/jobs", None).await.1, json!([]));
}

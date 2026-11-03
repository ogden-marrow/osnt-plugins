use std::{io::Cursor, sync::Arc};

use axum::{body::Body, http::Request};
use image::{DynamicImage, ImageFormat, Rgb, RgbImage};
use serde_json::Value;
use tower::ServiceExt;

use crate::ssrf::{Guard, testutil::*};
use crate::*;

fn scene(seed: u32) -> DynamicImage {
    DynamicImage::ImageRgb8(RgbImage::from_fn(200, 150, |x, y| {
        let (fx, fy) = (x as f64 / 200.0, y as f64 / 150.0);
        let v = ((fx * 6.0 + seed as f64).sin() * 60.0 + (fy * 4.0 * (seed as f64 + 1.0)).cos() * 60.0 + 128.0) as u8;
        let blob = if (fx - 0.3 - seed as f64 * 0.1).abs() < 0.15 && (fy - 0.5).abs() < 0.2 { 90 } else { 0 };
        Rgb([v.saturating_add(blob), v / 2 + blob / 2, 255 - v])
    }))
}

fn encode(img: &DynamicImage, f: ImageFormat) -> Vec<u8> {
    let mut b = Cursor::new(Vec::new());
    img.write_to(&mut b, f).unwrap();
    b.into_inner()
}

/// A JPEG that also carries a (synthetic) C2PA manifest store.
fn jpeg_with_credentials() -> Vec<u8> {
    let plain = encode(&scene(1), ImageFormat::Jpeg);
    let carrier = c2pa::tests::jpeg_with(&c2pa::tests::sample_store(true), 100_000);
    let segs = &carrier[2..carrier.len() - 8]; // between SOI and the trailing SOS/EOI stub
    [&plain[..2], segs, &plain[2..]].concat()
}

fn state(port: u16) -> Shared {
    AppState::new(Guard { exempt_loopback_port: Some(port) }, format!("http://127.0.0.1:{port}"))
}

async fn call(a: &axum::Router, method: &str, uri: &str, ct: Option<&str>, body: Vec<u8>) -> (StatusCode, Value, Vec<u8>) {
    let mut r = Request::builder().method(method).uri(uri);
    if let Some(c) = ct {
        r = r.header("content-type", c);
    }
    let res = a.clone().oneshot(r.body(Body::from(body)).unwrap()).await.unwrap();
    let st = res.status();
    let b = axum::body::to_bytes(res.into_body(), 1 << 26).await.unwrap().to_vec();
    (st, serde_json::from_slice(&b).unwrap_or(Value::Null), b)
}

fn multipart(parts: &[(&str, &[u8])]) -> (String, Vec<u8>) {
    let boundary = "XBOUNDARYX";
    let mut body = Vec::new();
    for (name, data) in parts {
        body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{name}.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}

fn fake_server() -> u16 {
    let jpeg = encode(&scene(2), ImageFormat::Jpeg);
    spawn(Arc::new(move |r| {
        let p = r.path.as_str();
        if p == "/vi/dQw4w9WgXcQ/0.jpg" {
            return Resp { status: 200, headers: vec![("Content-Type".into(), "image/jpeg".into())], body: jpeg.clone() };
        }
        if p == "/vi/dQw4w9WgXcQ/hq.jpg" || p == "/vi/dQw4w9WgXcQ/hqdefault.jpg" {
            return Resp::html("<html>not an image</html>");
        }
        if p == "/img.jpg" {
            return Resp { status: 200, headers: vec![("Content-Type".into(), "image/jpeg".into())], body: jpeg.clone() };
        }
        if p == "/redir" {
            return Resp::redirect("http://10.0.0.5/secret.jpg");
        }
        if p == "/big" {
            return Resp { status: 200, headers: vec![], body: vec![7u8; 3 * 1024 * 1024] };
        }
        if p == "/notfound.jpg" {
            return Resp { status: 404, headers: vec![], body: vec![] };
        }
        Resp { status: 404, headers: vec![], body: vec![] }
    }))
}

#[test]
fn youtube_ids() {
    for u in [
        "dQw4w9WgXcQ", "https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=10s", "https://youtu.be/dQw4w9WgXcQ?si=x", "https://m.youtube.com/shorts/dQw4w9WgXcQ",
        "youtube.com/embed/dQw4w9WgXcQ", "https://www.youtube-nocookie.com/embed/dQw4w9WgXcQ", "https://www.youtube.com/live/dQw4w9WgXcQ",
    ] {
        assert_eq!(youtube_id(u).as_deref(), Some("dQw4w9WgXcQ"), "{u}");
    }
    for u in ["", "short", "https://vimeo.com/123456789ab", "https://evil.com/watch?v=dQw4w9WgXcQ", "https://youtube.com.evil.com/watch?v=dQw4w9WgXcQ", "https://www.youtube.com/watch?v=../../etc/pw", "javascript:alert(1)", "ftp://youtu.be/dQw4w9WgXcQ"] {
        assert_eq!(youtube_id(u), None, "{u}");
    }
}

#[tokio::test]
async fn youtube_routes_list_frames_and_proxy_only_real_jpegs() {
    let a = app(state(fake_server()));
    let (st, v, _) = call(&a, "GET", "/api/youtube?url=https%3A%2F%2Fyoutu.be%2FdQw4w9WgXcQ", None, vec![]).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["frames"][0]["public_url"], "https://i.ytimg.com/vi/dQw4w9WgXcQ/0.jpg");
    assert_eq!(v["frames"].as_array().unwrap().len(), 6);
    assert_eq!(call(&a, "GET", "/api/youtube?url=https%3A%2F%2Fexample.com%2Fx", None, vec![]).await.0, StatusCode::BAD_REQUEST);
    let (st, _, body) = call(&a, "GET", "/api/youtube/frame?id=dQw4w9WgXcQ&n=0", None, vec![]).await;
    assert_eq!((st, body.starts_with(&[0xFF, 0xD8])), (StatusCode::OK, true));
    assert_eq!(call(&a, "GET", "/api/youtube/frame?id=dQw4w9WgXcQ&n=hq", None, vec![]).await.0, StatusCode::BAD_GATEWAY);
    assert_eq!(call(&a, "GET", "/api/youtube/frame?id=dQw4w9WgXcQ&n=2", None, vec![]).await.0, StatusCode::NOT_FOUND);
    assert_eq!(call(&a, "GET", "/api/youtube/frame?id=dQw4w9WgXcQ&n=../x", None, vec![]).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(call(&a, "GET", "/api/youtube/frame?id=..%2F..%2Fetc&n=0", None, vec![]).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn image_upload_gives_hashes_c2pa_and_ela() {
    let a = app(state(fake_server()));
    let (st, v, _) = call(&a, "POST", "/api/analyze?ela=1", None, jpeg_with_credentials()).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["file"]["kind"], "jpeg");
    assert_eq!(v["image"]["width"], 200);
    assert_eq!(v["image"]["hashes"]["phash"].as_str().unwrap().len(), 16);
    assert_eq!(v["file"]["sha256"].as_str().unwrap().len(), 64);
    assert_eq!(v["c2pa"]["present"], true);
    assert_eq!(v["c2pa"]["ai_generated_declared"], true);
    assert_eq!(v["c2pa"]["validated"], false);
    assert!(v["ela"]["image"].as_str().unwrap().starts_with("data:image/png"));
    let png = encode(&scene(1), ImageFormat::Png);
    let (_, v, _) = call(&a, "POST", "/api/analyze?ela=1", None, png).await;
    assert_eq!(v["c2pa"]["present"], false);
    assert!(v["ela"]["unavailable"].is_string());
}

#[tokio::test]
async fn upload_errors_and_limits() {
    let a = app(state(fake_server()));
    assert_eq!(call(&a, "POST", "/api/analyze", None, vec![]).await.0, StatusCode::BAD_REQUEST);
    // random bytes are treated as media; without a decodable stream that is a readable 4xx/501, never a crash
    let (st, v, _) = call(&a, "POST", "/api/analyze", None, b"definitely not media".to_vec()).await;
    assert!(st == StatusCode::BAD_REQUEST || st == StatusCode::NOT_IMPLEMENTED, "{st} {v}");
    assert!(v["error"].is_string());
    // a truncated image header is a clean 400
    let mut half = encode(&scene(1), ImageFormat::Png);
    half.truncate(40);
    assert_eq!(call(&a, "POST", "/api/analyze", None, half).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(call(&a, "GET", "/api/analyze", None, vec![]).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn url_fetching_is_ssrf_guarded_and_size_capped() {
    let port = fake_server();
    let a = app(state(port));
    let get = |u: String| {
        let a = a.clone();
        async move { call(&a, "GET", &format!("/api/analyze?url={}", url::form_urlencoded::byte_serialize(u.as_bytes()).collect::<String>()), None, vec![]).await }
    };
    for blocked in ["http://127.0.0.1:8080/x.jpg", "http://127.0.0.1:22/", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.1/a.mp4", "http://[::1]/", "http://localhost/x", "file:///etc/passwd", "ftp://example.com/x", "http://user:pw@93.184.216.34/"] {
        let (st, v, _) = get(blocked.to_string()).await;
        assert!(st == StatusCode::BAD_REQUEST, "{blocked}: {st} {v}");
    }
    // the exempt test port is reachable; a redirect from it into a private address is not followed
    let (st, v, _) = get(format!("http://127.0.0.1:{port}/img.jpg")).await;
    assert_eq!((st, v["image"]["width"].clone()), (StatusCode::OK, serde_json::json!(200)));
    let (st, v, _) = get(format!("http://127.0.0.1:{port}/redir")).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{v}");
    assert!(v["error"].as_str().unwrap().contains("blocked"));
    assert_eq!(get(format!("http://127.0.0.1:{port}/notfound.jpg")).await.0, StatusCode::BAD_GATEWAY);
}

#[test]
fn download_cap_is_enforced() {
    let port = fake_server();
    let s = state(port);
    let dir = Scratch::new().unwrap();
    let r = guarded_download(&s.agent, &s.guard, &format!("http://127.0.0.1:{port}/big"), &dir.0.join("f"), 1024 * 1024);
    assert!(r.unwrap_err().contains("larger than"));
    let ok = guarded_download(&s.agent, &s.guard, &format!("http://127.0.0.1:{port}/big"), &dir.0.join("g"), 5 * 1024 * 1024).unwrap();
    assert_eq!(ok.bytes, 3 * 1024 * 1024);
    assert_eq!(ok.sha256.len(), 64);
}

#[tokio::test]
async fn compare_route() {
    let a = app(state(fake_server()));
    let base = scene(1);
    let small = encode(&base.resize_exact(100, 75, image::imageops::FilterType::Triangle), ImageFormat::Jpeg);
    let (ct, body) = multipart(&[("a", &encode(&base, ImageFormat::Png)), ("b", &small)]);
    let (st, v, _) = call(&a, "POST", "/api/compare", Some(&ct), body).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["verdict"], "near-identical");
    assert_eq!(v["identical_bytes"], false);
    assert!(v["heatmap"].as_str().unwrap().starts_with("data:image/png"));
    let (ct, body) = multipart(&[("a", &encode(&scene(1), ImageFormat::Png)), ("b", &encode(&scene(4), ImageFormat::Png))]);
    assert_eq!(call(&a, "POST", "/api/compare", Some(&ct), body).await.1["verdict"], "different");
    let (ct, body) = multipart(&[("a", &encode(&scene(1), ImageFormat::Png))]);
    assert_eq!(call(&a, "POST", "/api/compare", Some(&ct), body).await.0, StatusCode::BAD_REQUEST);
    let (ct, body) = multipart(&[("a", b"junk"), ("b", b"junk")]);
    assert_eq!(call(&a, "POST", "/api/compare", Some(&ct), body).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn keyframes_reject_stills_and_work_on_real_video() {
    let a = app(state(fake_server()));
    let (_, ff) = media::available();
    let (st, v, _) = call(&a, "POST", "/api/keyframes", None, encode(&scene(1), ImageFormat::Png)).await;
    assert_eq!(st, if ff { StatusCode::BAD_REQUEST } else { StatusCode::NOT_IMPLEMENTED }, "{v}");
    if !ff {
        return;
    }
    let dir = Scratch::new().unwrap();
    let clip = dir.0.join("t.mp4");
    media::run(&media::which("ffmpeg").unwrap(), &["-nostdin", "-v", "error", "-f", "lavfi", "-i", "testsrc=duration=8:size=320x240:rate=10", "-g", "10", "-pix_fmt", "yuv420p", "-metadata", "title=fixture", "-y", clip.to_str().unwrap()], std::time::Duration::from_secs(60)).unwrap();
    let bytes = std::fs::read(&clip).unwrap();
    let (st, v, _) = call(&a, "POST", "/api/keyframes?count=5", None, bytes.clone()).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["mode_used"], "keyframes");
    assert_eq!(v["count"], 5);
    assert!(v["frames"][0]["image"].as_str().unwrap().starts_with("data:image/jpeg"));
    assert_eq!(v["frames"][1]["phash"].as_str().unwrap().len(), 16);
    let (_, v, _) = call(&a, "POST", "/api/keyframes?count=3&images=0&mode=even", None, bytes.clone()).await;
    assert_eq!((v["mode_used"].clone(), v["count"].clone()), (serde_json::json!("even"), serde_json::json!(3)));
    assert!(v["frames"][0].get("image").is_none());
    let (st, v, _) = call(&a, "POST", "/api/analyze", None, bytes).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["media"]["streams"][0]["width"], 320);
    assert_eq!(v["c2pa"]["present"], false);
    assert_eq!(call(&a, "POST", "/api/keyframes", None, b"not a video".to_vec()).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn only_one_heavy_job_at_a_time_and_tools_are_get_only() {
    let s = state(fake_server());
    let held = s.busy.clone().try_acquire_owned().unwrap();
    let a = app(s);
    assert_eq!(call(&a, "POST", "/api/analyze", None, encode(&scene(1), ImageFormat::Png)).await.0, StatusCode::TOO_MANY_REQUESTS);
    drop(held);
    let (_, t, _) = call(&a, "GET", "/tools", None, vec![]).await;
    let names: Vec<&str> = t.as_array().unwrap().iter().map(|x| x["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["media_probe", "media_keyframes", "media_youtube_frames"]);
    assert!(t.as_array().unwrap().iter().all(|x| x["method"] == "GET"));
    let (st, v, _) = call(&a, "GET", "/api/status", None, vec![]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(v["ffmpeg"].is_boolean());
}

#[test]
fn scratch_dirs_are_removed() {
    let p = {
        let d = Scratch::new().unwrap();
        std::fs::write(d.0.join("x"), b"1").unwrap();
        d.0.clone()
    };
    assert!(!p.exists());
}

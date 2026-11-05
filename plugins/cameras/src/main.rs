//! Cameras plugin: a grid of live still-image feeds from a config file, plus map placement.
//! Snapshots are proxied (and cached for a second) so the Pi makes one upstream request per frame no matter how many
//! viewers there are. Only configured URLs are fetched. No analysis of the images happens here.

use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const PAGE: &str = include_str!("../assets/index.html");
const DEFAULT_CAMERAS: &str = include_str!("../cameras.toml");
const MAX_FRAME_BYTES: u64 = 8 * 1024 * 1024;
const FRAME_TTL: Duration = Duration::from_millis(900);
/// After a failed fetch the same error is replayed for this long, so a dead feed is not hit by every viewer every 2 seconds.
const FAIL_TTL: Duration = Duration::from_secs(10);

#[derive(Serialize, Deserialize, Clone)]
struct Camera {
    id: String,
    name: String,
    #[serde(default)]
    group: String,
    #[serde(skip_serializing)]
    url: String,
    #[serde(default)]
    lat: Option<f64>,
    #[serde(default)]
    lon: Option<f64>,
}

#[derive(Deserialize)]
struct Config {
    #[serde(rename = "camera")]
    cameras: Vec<Camera>,
}

struct AppState {
    agent: ureq::Agent,
    frames: Mutex<HashMap<String, (Instant, Bytes, &'static str)>>,
    failures: Mutex<HashMap<String, (Instant, String)>>,
}

/// Identify an image by its first bytes; anything else (an HTML error page, a login wall) is not served as a picture.
fn sniff(b: &[u8]) -> Option<&'static str> {
    match b {
        [0xFF, 0xD8, 0xFF, ..] => Some("image/jpeg"),
        [0x89, b'P', b'N', b'G', ..] => Some("image/png"),
        [b'G', b'I', b'F', b'8', ..] => Some("image/gif"),
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => Some("image/webp"),
        _ => None,
    }
}

/// Short, URL-free description of why a feed failed (the configured URL may contain a key).
fn describe(e: &anyhow::Error) -> String {
    let full = format!("{e:#}");
    let tail = full.rsplit(": ").next().unwrap_or("request failed");
    if full.contains("UnknownIssuer") || full.contains("certificate") {
        "the camera's HTTPS certificate is not trusted (incomplete certificate chain or self-signed)".into()
    } else if let Some(code) = full.split("http status: ").nth(1).and_then(|r| r.split_whitespace().next()) {
        format!("the camera answered HTTP {code}")
    } else if full.contains("timeout") || full.contains("Timeout") {
        "the camera did not answer in time".into()
    } else {
        format!("the camera could not be reached ({tail})")
    }
}
type Shared = Arc<AppState>;

fn load_cameras() -> Result<Vec<Camera>> {
    let text = match env::var("OSNT_CAMERAS") {
        Ok(path) => std::fs::read_to_string(&path).with_context(|| path.clone())?,
        Err(_) => DEFAULT_CAMERAS.to_string(),
    };
    Ok(toml::from_str::<Config>(&text).context("cameras.toml")?.cameras)
}

fn err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({ "error": msg.into() }))).into_response()
}

async fn list() -> Response {
    match load_cameras() {
        Ok(c) => Json(c).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")),
    }
}

async fn snapshot(State(s): State<Shared>, Path(id): Path<String>) -> Response {
    let cams = match load_cameras() {
        Ok(c) => c,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")),
    };
    let Some(cam) = cams.into_iter().find(|c| c.id == id) else { return err(StatusCode::NOT_FOUND, "unknown camera") };

    let fresh = s.frames.lock().unwrap().get(&id).filter(|(at, ..)| at.elapsed() < FRAME_TTL).map(|(_, b, t)| (b.clone(), *t));
    let (bytes, ctype) = match fresh {
        Some(f) => f,
        None => {
            if let Some((_, msg)) = s.failures.lock().unwrap().get(&id).filter(|(at, _)| at.elapsed() < FAIL_TTL) {
                return err(StatusCode::BAD_GATEWAY, msg.clone());
            }
            let st = s.clone();
            let url = cam.url.clone();
            let fetched = tokio::task::spawn_blocking(move || -> Result<(Bytes, &'static str)> {
                let mut res = st.agent.get(&url).call().map_err(|e| anyhow::anyhow!("{}", describe(&e.into())))?;
                let b = Bytes::from(res.body_mut().with_config().limit(MAX_FRAME_BYTES).read_to_vec().map_err(|_| anyhow::anyhow!("the camera sent an unreadable or oversized response"))?);
                let t = sniff(&b).ok_or_else(|| anyhow::anyhow!("the camera did not return an image"))?;
                Ok((b, t))
            })
            .await;
            match fetched {
                Ok(Ok((b, t))) => {
                    s.failures.lock().unwrap().remove(&id);
                    s.frames.lock().unwrap().insert(id, (Instant::now(), b.clone(), t));
                    (b, t)
                }
                Ok(Err(e)) => {
                    let msg = e.to_string();
                    s.failures.lock().unwrap().insert(id, (Instant::now(), msg.clone()));
                    return err(StatusCode::BAD_GATEWAY, msg);
                }
                Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            }
        }
    };
    ([(header::CONTENT_TYPE, ctype), (header::CACHE_CONTROL, "no-store")], bytes).into_response()
}

async fn tools() -> Json<Value> {
    Json(json!([
        { "name": "cameras_list", "description": "List configured camera feeds with names, groups and optional coordinates.",
          "method": "GET", "path": "api/cameras", "parameters": { "type": "object", "properties": {} } }
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

#[tokio::main]
async fn main() -> Result<()> {
    load_cameras().context("invalid camera config")?;
    let state: Shared = Arc::new(AppState { agent: osnt_common::http_agent("osnt-cameras/0.1 (personal OSINT dashboard)"), frames: Mutex::default(), failures: Mutex::default() });
    let app = Router::new().route("/", get(page)).route("/tools", get(tools)).route("/api/cameras", get(list)).route("/snap/{id}", get(snapshot)).with_state(state);
    let addr: SocketAddr = env::var("OSNT_CAMERAS_BIND").unwrap_or_else(|_| "127.0.0.1:8105".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("cameras plugin on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_images_and_rejects_html() {
        assert_eq!(sniff(&[0xFF, 0xD8, 0xFF, 0xE0, 0]), Some("image/jpeg"));
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\n"), Some("image/png"));
        assert_eq!(sniff(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert_eq!(sniff(b"<html>login</html>"), None);
        assert_eq!(sniff(b""), None);
    }

    #[test]
    fn default_config_parses_and_ids_are_unique() {
        let cams = toml::from_str::<Config>(DEFAULT_CAMERAS).unwrap().cameras;
        let mut ids: Vec<_> = cams.iter().map(|c| c.id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), cams.len());
    }

    #[test]
    fn errors_do_not_leak_the_url() {
        let e = anyhow::anyhow!("GET http://cam.example/x?key=SECRET: io: invalid peer certificate: UnknownIssuer");
        let d = describe(&e);
        assert!(!d.contains("SECRET") && d.contains("certificate"));
        let e = anyhow::anyhow!("GET http://cam.example/x?key=SECRET: http status: 404");
        assert!(!describe(&e).contains("SECRET"));
        assert_eq!(describe(&e), "the camera answered HTTP 404");
    }
}

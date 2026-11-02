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
    frames: Mutex<HashMap<String, (Instant, Bytes)>>,
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

    let fresh = s.frames.lock().unwrap().get(&id).filter(|(at, _)| at.elapsed() < FRAME_TTL).map(|(_, b)| b.clone());
    let bytes = match fresh {
        Some(b) => b,
        None => {
            let st = s.clone();
            let url = cam.url.clone();
            let fetched = tokio::task::spawn_blocking(move || -> Result<Bytes> {
                let mut res = st.agent.get(&url).call().with_context(|| format!("GET {url}"))?;
                Ok(Bytes::from(res.body_mut().with_config().limit(MAX_FRAME_BYTES).read_to_vec()?))
            })
            .await;
            match fetched {
                Ok(Ok(b)) => {
                    s.frames.lock().unwrap().insert(id, (Instant::now(), b.clone()));
                    b
                }
                Ok(Err(e)) => return err(StatusCode::BAD_GATEWAY, format!("{e:#}")),
                Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            }
        }
    };
    ([(header::CONTENT_TYPE, "image/jpeg"), (header::CACHE_CONTROL, "no-store")], bytes).into_response()
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
    let state: Shared = Arc::new(AppState { agent: osnt_common::http_agent("osnt-cameras/0.1 (personal OSINT dashboard)"), frames: Mutex::default() });
    let app = Router::new().route("/", get(page)).route("/tools", get(tools)).route("/api/cameras", get(list)).route("/snap/{id}", get(snapshot)).with_state(state);
    let addr: SocketAddr = env::var("OSNT_CAMERAS_BIND").unwrap_or_else(|_| "127.0.0.1:8105".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("cameras plugin on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

//! Image source finder: an agent loop (DeepSeek reasoning + reverse-image-search backends + page fetch + Wayback)
//! that looks for the earliest known appearance of an image. Images are processed in memory and never stored.
//! DeepSeek is text-only: it plans tool calls and writes the report, it never sees the image.

mod agent;
mod analysis;
mod html;
mod ssrf;
mod tools;

use std::{env, net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Semaphore;

const PAGE: &str = include_str!("../assets/index.html");
const MAX_IMAGE_BYTES: usize = 15 * 1024 * 1024;
const UA: &str = "osnt-provenance/0.1 (image source finder; personal OSINT hub)";

struct AppState {
    cfg: tools::Config,
    guard: ssrf::Guard,
    api: ureq::Agent,
    fetch: ureq::Agent,
    /// Each run can cost API credits and takes up to ~90 s: allow only a couple at once.
    slots: Semaphore,
}
type Shared = Arc<AppState>;

struct ApiError(StatusCode, String);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}
fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

fn looks_like_image(b: &[u8]) -> bool {
    analysis::sniff(b) != "unknown" || imagesize::blob_size(b).is_ok()
}

#[derive(Deserialize)]
struct UrlQuery {
    url: Option<String>,
}

async fn run(st: Shared, input: agent::Input) -> Result<Json<Value>, ApiError> {
    let st_permit = st.clone();
    let _permit = st_permit.slots.try_acquire().map_err(|_| ApiError(StatusCode::TOO_MANY_REQUESTS, "another investigation is running; try again in a minute".into()))?;
    let out = tokio::task::spawn_blocking(move || {
        let keys = tools::Keys::load(); // blocking: asks the portal core for credentials
        agent::investigate(&st.cfg, &keys, &st.guard, agent::Agents { api: &st.api, fetch: &st.fetch }, input, agent::MAX_ITERATIONS)
    })
    .await
    .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "investigation crashed".into()))?;
    Ok(Json(out))
}

/// POST raw image bytes (Content-Type: image/*).
async fn investigate_upload(State(st): State<Shared>, headers: HeaderMap, body: Bytes) -> Result<Json<Value>, ApiError> {
    let ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !ct.to_ascii_lowercase().starts_with("image/") {
        return Err(ApiError(StatusCode::UNSUPPORTED_MEDIA_TYPE, "send the raw image bytes with a Content-Type of image/*".into()));
    }
    if body.is_empty() {
        return Err(bad("empty body"));
    }
    if !looks_like_image(&body) {
        return Err(bad("the data does not look like an image"));
    }
    run(st, agent::Input { bytes: body.to_vec(), url: None }).await
}

/// GET ?url=<public image url>. The URL is fetched through the SSRF guard.
async fn investigate_url(State(st): State<Shared>, Query(q): Query<UrlQuery>) -> Result<Json<Value>, ApiError> {
    let url = q.url.map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).ok_or_else(|| bad("missing ?url=<public image URL>"))?;
    let st2 = st.clone();
    let u2 = url.clone();
    let fetched = tokio::task::spawn_blocking(move || ssrf::guarded_get(&st2.fetch, &st2.guard, &u2, MAX_IMAGE_BYTES, "image/*,*/*;q=0.5"))
        .await
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "fetch crashed".into()))?
        .map_err(|e| bad(format!("could not fetch image URL: {e}")))?;
    if fetched.status != 200 {
        return Err(bad(format!("image URL returned HTTP {}", fetched.status)));
    }
    if fetched.truncated {
        return Err(bad("image is larger than 15 MB"));
    }
    if !looks_like_image(&fetched.body) {
        return Err(bad("the URL did not return an image"));
    }
    run(st, agent::Input { bytes: fetched.body, url: Some(url) }).await
}

async fn tools_list() -> Json<Value> {
    Json(json!([{
        "name": "provenance_investigate_url",
        "description": "Agentic search for the likely ORIGINAL SOURCE of a public image URL: reverse-image search, page dates and Internet Archive, ranked candidates with confidence and caveats. Slow: can take up to about 90 seconds. Sends the image to third-party services (Google/SerpAPI/DeepSeek). Never identifies people. 'Earliest found' is not proof of the original.",
        "method": "GET",
        "path": "api/investigate",
        "parameters": { "type": "object", "properties": { "url": { "type": "string", "description": "Public http(s) URL of the image" } }, "required": ["url"] }
    }]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

#[tokio::main]
async fn main() {
    let guard = ssrf::Guard::default();
    let state = Arc::new(AppState {
        cfg: tools::Config::from_env(),
        fetch: ssrf::guarded_agent(guard.clone(), UA),
        guard,
        api: osnt_common::http_agent(UA),
        slots: Semaphore::new(2),
    });
    let app = Router::new()
        .route("/", get(page))
        .route("/tools", get(tools_list))
        .route("/api/investigate", get(investigate_url).post(investigate_upload))
        .layer(DefaultBodyLimit::max(MAX_IMAGE_BYTES))
        .with_state(state);
    let addr: SocketAddr = env::var("OSNT_PROVENANCE_BIND").unwrap_or_else(|_| "127.0.0.1:8106".into()).parse().expect("bind addr");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("provenance plugin on http://{addr}");
    axum::serve(listener, app).await.expect("serve");
}

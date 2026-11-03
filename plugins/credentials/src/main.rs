//! Credentials plugin: the secret store for the whole hub.
//!
//! The browser side (/api/credentials, via the portal proxy at /p/credentials/) needs the portal's gateway signature,
//! which it only adds for a signed-in user, and never receives values back. Other plugins read secrets at /internal/secrets/<name> directly on this service's loopback port, using
//! their own per-plugin token; a plugin only gets names its manifest declares. The portal refuses to proxy
//! `internal/*`, so that endpoint is not reachable from the network.

use std::{collections::BTreeMap, env, fs, io::Write, net::SocketAddr, os::unix::fs::OpenOptionsExt, path::{Path as FsPath, PathBuf}, sync::Mutex};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Path},
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PAGE: &str = include_str!("../assets/index.html");
static WRITE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Deserialize)]
struct SecretSpec {
    name: String,
    label: String,
    #[serde(default)]
    help_url: Option<String>,
    #[serde(default)]
    required: bool,
}

/// The parts of a plugin manifest (in /etc/osnt/plugins.d) that matter here.
#[derive(Deserialize)]
struct Manifest {
    id: String,
    #[serde(default)]
    token_sha256: Option<String>,
    #[serde(default, rename = "secret")]
    secrets: Vec<SecretSpec>,
}

fn manifests() -> Vec<Manifest> {
    let dir = PathBuf::from(env::var("OSNT_PLUGINS_DIR").unwrap_or_else(|_| "/etc/osnt/plugins.d".into()));
    let Ok(entries) = fs::read_dir(dir) else { return vec![] };
    entries
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "toml"))
        .filter_map(|e| toml::from_str(&fs::read_to_string(e.path()).ok()?).ok())
        .collect()
}

fn state_dir() -> PathBuf {
    PathBuf::from(env::var("OSNT_STATE_DIR").unwrap_or_else(|_| "/var/lib/osnt-credentials".into()))
}

fn write_private(path: &FsPath, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(tmp, path)
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ")
}

/// Was this request vouched for by the portal (a signed-in user)? See `osnt_common::gateway_authorized`.
fn signed_in(method: &Method, uri: &Uri, headers: &HeaderMap) -> bool {
    osnt_common::gateway_authorized(method.as_str(), uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"), headers.get("x-osnt-gateway").and_then(|v| v.to_str().ok()))
}

fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

fn load() -> BTreeMap<String, String> {
    fs::read_to_string(state_dir().join("secrets.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

fn save(map: &BTreeMap<String, String>) -> std::io::Result<()> {
    fs::create_dir_all(state_dir())?;
    write_private(&state_dir().join("secrets.json"), serde_json::to_string(map)?.as_bytes())
}

fn error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

fn unauthorized() -> Response {
    error(StatusCode::UNAUTHORIZED, "sign in required")
}

/// Declared credentials (from plugin manifests) plus any stored by hand. Never includes values.
async fn list(method: Method, uri: Uri, headers: HeaderMap) -> Response {
    if !signed_in(&method, &uri, &headers) {
        return unauthorized();
    }
    let stored = load();
    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    for m in manifests() {
        for s in &m.secrets {
            let e = out.entry(s.name.clone()).or_insert_with(|| json!({ "name": s.name, "label": s.label, "help_url": s.help_url, "required": false, "plugins": [], "custom": false }));
            e["required"] = json!(e["required"].as_bool().unwrap_or(false) || s.required);
            e["plugins"].as_array_mut().unwrap().push(json!(m.id));
        }
    }
    for name in stored.keys() {
        out.entry(name.clone()).or_insert_with(|| json!({ "name": name, "label": name, "help_url": null, "required": false, "plugins": [], "custom": true }));
    }
    let list: Vec<Value> = out.into_values().map(|mut v| { v["set"] = json!(stored.contains_key(v["name"].as_str().unwrap_or_default())); v }).collect();
    Json(list).into_response()
}

#[derive(Deserialize)]
struct PutBody {
    value: String,
}

async fn put(method: Method, uri: Uri, headers: HeaderMap, Path(name): Path<String>, Json(body): Json<PutBody>) -> Response {
    if !signed_in(&method, &uri, &headers) {
        return unauthorized();
    }
    let value = body.value.trim().to_string();
    if !valid_name(&name) {
        return error(StatusCode::BAD_REQUEST, "the name must be capital letters, digits and underscores (at most 64 characters)");
    }
    if value.is_empty() {
        return error(StatusCode::BAD_REQUEST, "the value is empty");
    }
    if value.len() > 4096 {
        return error(StatusCode::BAD_REQUEST, "the value is too long (limit 4096 characters)");
    }
    if value.chars().any(char::is_control) {
        return error(StatusCode::BAD_REQUEST, "the value contains line breaks or control characters; paste it as a single line (JSON key files are compacted automatically with From file)");
    }
    let _guard = WRITE_LOCK.lock().unwrap();
    let mut map = load();
    map.insert(name, value);
    match save(&map) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &format!("could not save: {e}")),
    }
}

async fn delete(method: Method, uri: Uri, headers: HeaderMap, Path(name): Path<String>) -> Response {
    if !signed_in(&method, &uri, &headers) {
        return unauthorized();
    }
    let _guard = WRITE_LOCK.lock().unwrap();
    let mut map = load();
    map.remove(&name);
    match save(&map) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &format!("could not save: {e}")),
    }
}

/// Plugin-facing read. Needs a loopback peer, the X-OSNT-Internal header (so a bare GET smuggled through an SSRF bug
/// fails), and the caller's token, which must match a plugin whose manifest declares this secret.
async fn internal(ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, Path(name): Path<String>) -> Response {
    let deny = || error(StatusCode::FORBIDDEN, "forbidden");
    if !peer.ip().is_loopback() || headers.get("x-osnt-internal").and_then(|v| v.to_str().ok()) != Some("1") || !valid_name(&name) {
        return deny();
    }
    let Some(token) = bearer(&headers) else { return deny() };
    let hash: String = Sha256::digest(token.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    let allowed = manifests().iter().any(|m| m.token_sha256.as_deref().is_some_and(|h| ct_eq(h, &hash)) && m.secrets.iter().any(|s| s.name == name));
    if !allowed {
        return deny();
    }
    match load().get(&name) {
        Some(v) => Json(json!({ "value": v })).into_response(),
        None => error(StatusCode::NOT_FOUND, "not set"),
    }
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

async fn tools() -> Json<Value> {
    // Deliberately empty: agents must never be able to read or write credentials.
    Json(json!([]))
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/credentials", get(list))
        .route("/api/credentials/{name}", axum::routing::put(put).delete(delete))
        .route("/internal/secrets/{name}", get(internal));
    let addr: SocketAddr = env::var("OSNT_CREDENTIALS_BIND").unwrap_or_else(|_| "127.0.0.1:8110".into()).parse().expect("bind addr");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("credentials plugin on http://{addr}");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.expect("serve");
}

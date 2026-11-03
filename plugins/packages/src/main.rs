//! Packages plugin: the list of package repositories, and what each offers versus what is installed.
//!
//! It reads each repository's `index.toml` from raw.githubusercontent.com and the installed manifests in
//! /etc/osnt/plugins.d. The optional GitHub connection (device flow, token kept in this plugin's state directory, mode 0600, never sent to the browser)
//! lets it read private repositories. Installing and removing still happens with `cargo deploy plugin add|remove` on your
//! computer; this page shows the exact command. Every route needs the portal's gateway signature (a signed-in user).

use std::{env, fs, io::Write, net::SocketAddr, os::unix::fs::OpenOptionsExt, path::PathBuf, sync::Mutex, time::{SystemTime, UNIX_EPOCH}};

use axum::{
    Json, Router,
    extract::Query,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use serde_json::{Value, json};

const PAGE: &str = include_str!("../assets/index.html");
static WRITE_LOCK: Mutex<()> = Mutex::new(());
const MAX_REPOS: usize = 50;
/// The OSNT GitHub App's client ID (public, not a secret). Device flow needs no client secret.
const DEFAULT_CLIENT_ID: &str = "Iv23liDg2ML1wL4BKjT5";
/// The device code of a sign-in in progress; it stays on the server and is never sent to the browser.
static PENDING: Mutex<Option<String>> = Mutex::new(None);
const MAX_INDEX_BYTES: u64 = 512 * 1024;

#[derive(Deserialize)]
struct Installed {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
}

#[derive(Deserialize, Default)]
struct Index {
    #[serde(default, rename = "plugin")]
    plugins: Vec<Entry>,
}

#[derive(Deserialize, Clone)]
struct Entry {
    id: String,
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    requires: Vec<String>,
}

fn installed() -> Vec<Installed> {
    let dir = PathBuf::from(env::var("OSNT_PLUGINS_DIR").unwrap_or_else(|_| "/etc/osnt/plugins.d".into()));
    let Ok(entries) = fs::read_dir(dir) else { return vec![] };
    let mut out: Vec<Installed> = entries
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "toml"))
        .filter_map(|e| toml::from_str(&fs::read_to_string(e.path()).ok()?).ok())
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

fn repos_file() -> PathBuf {
    PathBuf::from(env::var("OSNT_STATE_DIR").unwrap_or_else(|_| "/var/lib/osnt-packages".into())).join("repos.json")
}

fn load_repos() -> Vec<String> {
    fs::read_to_string(repos_file()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

fn save_repos(repos: &[String]) -> std::io::Result<()> {
    let path = repos_file();
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, serde_json::to_string(repos)?)?;
    fs::rename(tmp, path)
}

fn safe_segment(s: &str) -> bool {
    (1..=100).contains(&s.len()) && s != "." && s != ".." && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// "https://github.com/owner/repo[.git][/tree/...]" -> ("owner", "repo"). Only github.com is accepted, which also
/// keeps the fetch below pinned to raw.githubusercontent.com.
fn parse_repo(url: &str) -> Option<(String, String)> {
    let rest = url.trim().strip_prefix("https://github.com/")?;
    let mut parts = rest.split('/');
    let (owner, repo) = (parts.next()?, parts.next()?);
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    (safe_segment(owner) && safe_segment(repo)).then(|| (owner.to_string(), repo.to_string()))
}

fn canonical(owner: &str, repo: &str) -> String {
    format!("https://github.com/{owner}/{repo}")
}

fn fetch_index(owner: &str, repo: &str, token: Option<&str>) -> Result<Vec<Entry>, String> {
    let agent = osnt_common::http_agent("osnt-packages");
    // With a GitHub token the API serves private repositories; without one only public raw files are reachable.
    let mut req = match token {
        Some(_) => agent.get(&format!("https://api.github.com/repos/{owner}/{repo}/contents/index.toml")).header("Accept", "application/vnd.github.raw+json"),
        None => agent.get(&format!("https://raw.githubusercontent.com/{owner}/{repo}/HEAD/index.toml")),
    };
    if let Some(t) = token {
        req = req.header("Authorization", &format!("Bearer {t}"));
    }
    let mut resp = req.config().http_status_as_error(false).build().call().map_err(|e| format!("could not reach GitHub: {e}"))?;
    match resp.status().as_u16() {
        200 => {}
        401 => return Err("GitHub sign-in expired. Use Connect GitHub again".into()),
        404 if token.is_some() => return Err("not found. Check the link, and that the OSNT GitHub App is installed on this repository".into()),
        404 => return Err("not found. If the repository is private, use Connect GitHub first".into()),
        s => return Err(format!("GitHub answered {s}")),
    }
    let text = resp.body_mut().with_config().limit(MAX_INDEX_BYTES).read_to_string().map_err(|e| format!("could not read index.toml: {e}"))?;
    let idx: Index = toml::from_str(&text).map_err(|e| format!("index.toml is not valid: {e}"))?;
    Ok(idx.plugins.into_iter().filter(|e| e.path.is_empty() || e.path.split('/').all(safe_segment)).collect())
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn client_id() -> String {
    env::var("OSNT_GITHUB_CLIENT_ID").unwrap_or_else(|_| DEFAULT_CLIENT_ID.into())
}

fn token_file() -> PathBuf {
    repos_file().with_file_name("github.json")
}

/// The stored GitHub token, unless it has expired.
fn load_token() -> Option<String> {
    let v: Value = serde_json::from_str(&fs::read_to_string(token_file()).ok()?).ok()?;
    if v["expires_at"].as_u64().is_some_and(|t| t <= now()) {
        return None;
    }
    v["access_token"].as_str().map(str::to_string)
}

fn save_token(token: &str, expires_in: Option<u64>) -> std::io::Result<()> {
    let path = token_file();
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let body = json!({ "access_token": token, "expires_at": expires_in.map(|s| now() + s) });
    let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(body.to_string().as_bytes())?;
    f.sync_all()?;
    fs::rename(tmp, path)
}

/// POST a form to github.com and parse the JSON reply (GitHub answers 200 even for "authorization_pending").
fn github_form(url: &str, fields: &[(&str, &str)]) -> Result<Value, String> {
    let enc = |s: &str| s.bytes().map(|b| if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' { (b as char).to_string() } else { format!("%{b:02X}") }).collect::<String>();
    let body = fields.iter().map(|(k, v)| format!("{k}={}", enc(v))).collect::<Vec<_>>().join("&");
    let agent = osnt_common::http_agent("osnt-packages");
    let mut resp = agent
        .post(url)
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .config()
        .http_status_as_error(false)
        .build()
        .send(body.as_str())
        .map_err(|e| format!("could not reach GitHub: {e}"))?;
    let text = resp.body_mut().with_config().limit(64 * 1024).read_to_string().map_err(|e| format!("bad reply from GitHub: {e}"))?;
    serde_json::from_str(&text).map_err(|_| "bad reply from GitHub".to_string())
}

fn signed_in(method: &Method, uri: &Uri, headers: &HeaderMap) -> bool {
    osnt_common::gateway_authorized(method.as_str(), uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"), headers.get("x-osnt-gateway").and_then(|v| v.to_str().ok()))
}

fn error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

async fn list_repos(method: Method, uri: Uri, headers: HeaderMap) -> Response {
    if !signed_in(&method, &uri, &headers) {
        return error(StatusCode::UNAUTHORIZED, "sign in required");
    }
    Json(load_repos()).into_response()
}

#[derive(Deserialize)]
struct RepoBody {
    url: String,
}

async fn add_repo(method: Method, uri: Uri, headers: HeaderMap, Json(body): Json<RepoBody>) -> Response {
    if !signed_in(&method, &uri, &headers) {
        return error(StatusCode::UNAUTHORIZED, "sign in required");
    }
    let Some((owner, repo)) = parse_repo(&body.url) else {
        return error(StatusCode::BAD_REQUEST, "expected a link like https://github.com/<owner>/<repo>");
    };
    let url = canonical(&owner, &repo);
    let _guard = WRITE_LOCK.lock().unwrap();
    let mut repos = load_repos();
    if repos.len() >= MAX_REPOS {
        return error(StatusCode::BAD_REQUEST, "too many repositories");
    }
    if !repos.contains(&url) {
        repos.push(url);
    }
    match save_repos(&repos) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &format!("could not save: {e}")),
    }
}

async fn remove_repo(method: Method, uri: Uri, headers: HeaderMap, Query(q): Query<RepoBody>) -> Response {
    if !signed_in(&method, &uri, &headers) {
        return error(StatusCode::UNAUTHORIZED, "sign in required");
    }
    let _guard = WRITE_LOCK.lock().unwrap();
    let mut repos = load_repos();
    repos.retain(|r| *r != q.url);
    match save_repos(&repos) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &format!("could not save: {e}")),
    }
}

/// Every repository's offerings merged with what is installed.
async fn packages(method: Method, uri: Uri, headers: HeaderMap) -> Response {
    if !signed_in(&method, &uri, &headers) {
        return error(StatusCode::UNAUTHORIZED, "sign in required");
    }
    let repos = load_repos();
    let token = load_token();
    let results = tokio::task::spawn_blocking(move || {
        std::thread::scope(|s| {
            let handles: Vec<_> = repos
                .iter()
                .map(|url| {
                    let parsed = parse_repo(url);
                    let token = token.as_deref();
                    s.spawn(move || match parsed {
                        Some((o, r)) => fetch_index(&o, &r, token),
                        None => Err("not a GitHub repository link".into()),
                    })
                })
                .collect();
            repos.iter().cloned().zip(handles.into_iter().map(|h| h.join().unwrap_or_else(|_| Err("fetch crashed".into())))).collect::<Vec<_>>()
        })
    })
    .await
    .unwrap_or_default();

    let have = installed();
    let mut seen = std::collections::BTreeSet::new();
    let mut repo_status = vec![];
    let mut out: Vec<Value> = vec![];
    for (url, res) in results {
        match res {
            Err(e) => repo_status.push(json!({ "url": url, "ok": false, "error": e })),
            Ok(entries) => {
                repo_status.push(json!({ "url": url, "ok": true, "count": entries.len() }));
                for e in entries {
                    let inst = have.iter().find(|i| i.id == e.id);
                    let status = match inst {
                        None => "available",
                        Some(i) if !e.version.is_empty() && i.version != e.version => "update",
                        Some(_) => "installed",
                    };
                    let missing: Vec<&String> = e.requires.iter().filter(|r| !have.iter().any(|i| &i.id == *r)).collect();
                    seen.insert(e.id.clone());
                    out.push(json!({
                        "id": e.id, "name": e.name, "description": e.description, "version": e.version,
                        "installed_version": inst.map(|i| i.version.clone()), "status": status,
                        "requires": e.requires, "missing_requires": missing, "repo": url,
                        "install": format!("cargo deploy plugin add {}/tree/HEAD/{}", url, e.path),
                        "remove": format!("cargo deploy plugin remove {}", e.id),
                    }));
                }
            }
        }
    }
    // Installed but offered by none of the repositories (local folder installs, or a repo that failed to load).
    let others: Vec<Value> = have
        .iter()
        .filter(|i| !seen.contains(&i.id))
        .map(|i| json!({ "id": i.id, "name": if i.name.is_empty() { &i.id } else { &i.name }, "version": i.version, "remove": format!("cargo deploy plugin remove {}", i.id) }))
        .collect();
    Json(json!({ "repos": repo_status, "packages": out, "other_installed": others })).into_response()
}

async fn github_status(method: Method, uri: Uri, headers: HeaderMap) -> Response {
    if !signed_in(&method, &uri, &headers) {
        return error(StatusCode::UNAUTHORIZED, "sign in required");
    }
    let Some(token) = load_token() else {
        return Json(json!({ "connected": false, "stored": token_file().exists() })).into_response();
    };
    let login = tokio::task::spawn_blocking(move || {
        let agent = osnt_common::http_agent("osnt-packages");
        let mut r = agent.get("https://api.github.com/user").header("Authorization", &format!("Bearer {token}")).config().http_status_as_error(false).build().call().ok()?;
        (r.status().as_u16() == 200).then_some(())?;
        let v: Value = serde_json::from_str(&r.body_mut().with_config().limit(256 * 1024).read_to_string().ok()?).ok()?;
        v["login"].as_str().map(str::to_string)
    })
    .await
    .ok()
    .flatten();
    Json(json!({ "connected": login.is_some(), "login": login, "stored": true })).into_response()
}

/// Step 1 of device flow: ask GitHub for a code the user types at github.com/login/device.
async fn github_start(method: Method, uri: Uri, headers: HeaderMap) -> Response {
    if !signed_in(&method, &uri, &headers) {
        return error(StatusCode::UNAUTHORIZED, "sign in required");
    }
    let r = tokio::task::spawn_blocking(|| github_form("https://github.com/login/device/code", &[("client_id", &client_id())])).await;
    match r {
        Ok(Ok(v)) if v["device_code"].is_string() => {
            *PENDING.lock().unwrap() = v["device_code"].as_str().map(str::to_string);
            Json(json!({ "user_code": v["user_code"], "verification_uri": v["verification_uri"], "interval": v["interval"], "expires_in": v["expires_in"] })).into_response()
        }
        Ok(Ok(v)) => error(StatusCode::BAD_GATEWAY, v["error_description"].as_str().unwrap_or("GitHub refused the request. Is Device Flow enabled on the app?")),
        Ok(Err(e)) => error(StatusCode::BAD_GATEWAY, &e),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

/// Step 2: the page polls this until the user has approved the code.
async fn github_poll(method: Method, uri: Uri, headers: HeaderMap) -> Response {
    if !signed_in(&method, &uri, &headers) {
        return error(StatusCode::UNAUTHORIZED, "sign in required");
    }
    let Some(device) = PENDING.lock().unwrap().clone() else {
        return error(StatusCode::BAD_REQUEST, "no sign-in in progress");
    };
    let r = tokio::task::spawn_blocking(move || {
        github_form("https://github.com/login/oauth/access_token", &[("client_id", &client_id()), ("device_code", &device), ("grant_type", "urn:ietf:params:oauth:grant-type:device_code")])
    })
    .await;
    let v = match r {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return error(StatusCode::BAD_GATEWAY, &e),
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    if let Some(token) = v["access_token"].as_str() {
        *PENDING.lock().unwrap() = None;
        return match save_token(token, v["expires_in"].as_u64()) {
            Ok(()) => Json(json!({ "status": "connected" })).into_response(),
            Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &format!("could not save: {e}")),
        };
    }
    match v["error"].as_str().unwrap_or("error") {
        "authorization_pending" => Json(json!({ "status": "pending" })).into_response(),
        "slow_down" => Json(json!({ "status": "pending", "slow_down": true })).into_response(),
        "expired_token" | "access_denied" => {
            *PENDING.lock().unwrap() = None;
            Json(json!({ "status": "failed", "error": "The code expired or was denied. Start again." })).into_response()
        }
        other => error(StatusCode::BAD_GATEWAY, &format!("GitHub said: {other}")),
    }
}

async fn github_disconnect(method: Method, uri: Uri, headers: HeaderMap) -> Response {
    if !signed_in(&method, &uri, &headers) {
        return error(StatusCode::UNAUTHORIZED, "sign in required");
    }
    let _ = fs::remove_file(token_file());
    *PENDING.lock().unwrap() = None;
    Json(json!({ "ok": true })).into_response()
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

async fn tools() -> Json<Value> {
    // Deliberately empty: agents must not manage packages.
    Json(json!([]))
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/repos", get(list_repos).post(add_repo).delete(remove_repo))
        .route("/api/packages", get(packages))
        .route("/api/github", get(github_status).delete(github_disconnect))
        .route("/api/github/start", axum::routing::post(github_start))
        .route("/api/github/poll", axum::routing::post(github_poll));
    let addr: SocketAddr = env::var("OSNT_PACKAGES_BIND").unwrap_or_else(|_| "127.0.0.1:8111".into()).parse().expect("bind addr");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("packages plugin on http://{addr}");
    axum::serve(listener, app).await.expect("serve");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_links() {
        assert_eq!(parse_repo("https://github.com/a/b"), Some(("a".into(), "b".into())));
        assert_eq!(parse_repo(" https://github.com/a/b.git/tree/main/x "), Some(("a".into(), "b".into())));
        assert_eq!(parse_repo("http://github.com/a/b"), None);
        assert_eq!(parse_repo("https://github.com.evil.com/a/b"), None);
        assert_eq!(parse_repo("https://github.com/a/../b"), None);
        assert_eq!(parse_repo("https://github.com/a"), None);
        assert_eq!(parse_repo("https://github.com/a/b?x=1"), None);
    }
}

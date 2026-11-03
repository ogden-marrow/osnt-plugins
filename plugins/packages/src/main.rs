//! Packages plugin: the list of package repositories, and what each offers versus what is installed.
//!
//! It reads each repository's `index.toml` from raw.githubusercontent.com and the installed manifests in
//! /etc/osnt/plugins.d. The optional GitHub connection (device flow, token kept in this plugin's state directory, mode 0600, never sent to the browser)
//! lets it read private repositories. Installing and removing still happens with `cargo deploy plugin add|remove` on your
//! computer; this page shows the exact command. Every route needs the portal's gateway signature (a signed-in user).

use std::{collections::{BTreeMap, HashMap}, env, fs, io::{Read, Write}, net::SocketAddr, os::unix::fs::OpenOptionsExt, path::PathBuf, sync::Mutex, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};

use axum::{
    Json, Router,
    extract::{Path, Query},
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
    #[serde(default)]
    requires: Vec<String>,
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

/// A file from a repository: through the API with a token (private repositories), else from raw.githubusercontent.com.
fn fetch_text(owner: &str, repo: &str, path: &str, token: Option<&str>) -> Result<String, String> {
    let agent = osnt_common::http_agent("osnt-packages");
    let mut req = match token {
        Some(_) => agent.get(&format!("https://api.github.com/repos/{owner}/{repo}/contents/{path}")).header("Accept", "application/vnd.github.raw+json"),
        None => agent.get(&format!("https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{path}")),
    };
    if let Some(t) = token {
        req = req.header("Authorization", &format!("Bearer {t}"));
    }
    let mut resp = req.config().http_status_as_error(false).build().call().map_err(|e| format!("could not reach GitHub: {e}"))?;
    match resp.status().as_u16() {
        200 => {}
        401 => return Err("GitHub sign-in expired. Connect GitHub again".into()),
        404 if token.is_some() => return Err("not found. Check the link, and that the OSNT GitHub App is installed on this repository".into()),
        404 => return Err("not found. If the repository is private, connect GitHub first".into()),
        s => return Err(format!("GitHub answered {s}")),
    }
    resp.body_mut().with_config().limit(MAX_INDEX_BYTES).read_to_string().map_err(|e| format!("could not read {path}: {e}"))
}

fn fetch_index(owner: &str, repo: &str, token: Option<&str>) -> Result<Vec<Entry>, String> {
    let text = fetch_text(owner, repo, "index.toml", token)?;
    let idx: Index = toml::from_str(&text).map_err(|e| format!("index.toml is not valid: {e}"))?;
    Ok(idx.plugins.into_iter().filter(|e| e.path.is_empty() || e.path.split('/').all(safe_segment)).collect())
}

/// The `latest` release's manifest.json: which plugins have a published build, and of which version.
/// None when the repository has not published one (its release workflow has not run yet).
fn fetch_builds(owner: &str, repo: &str, token: Option<&str>) -> Option<BTreeMap<String, String>> {
    let agent = osnt_common::http_agent("osnt-packages");
    let call = |url: &str, accept: &str| {
        let mut req = agent.get(url).header("Accept", accept);
        if let Some(t) = token {
            req = req.header("Authorization", &format!("Bearer {t}"));
        }
        let mut r = req.config().http_status_as_error(false).build().call().ok()?;
        (r.status().as_u16() == 200).then_some(())?;
        r.body_mut().with_config().limit(MAX_INDEX_BYTES).read_to_string().ok()
    };
    let release: Value = serde_json::from_str(&call(&format!("https://api.github.com/repos/{owner}/{repo}/releases/tags/latest"), "application/vnd.github+json")?).ok()?;
    let asset = release["assets"].as_array()?.iter().find(|a| a["name"] == "manifest.json")?["id"].as_u64()?;
    let manifest: Value = serde_json::from_str(&call(&format!("https://api.github.com/repos/{owner}/{repo}/releases/assets/{asset}"), "application/octet-stream")?).ok()?;
    Some(manifest["plugins"].as_array()?.iter().filter_map(|p| Some((p["id"].as_str()?.to_string(), p["version"].as_str()?.to_string()))).collect())
}

#[derive(Clone)]
struct RepoData {
    entries: Vec<Entry>,
    builds: Option<BTreeMap<String, String>>,
}

static CACHE: Mutex<Option<HashMap<String, (Instant, Result<RepoData, String>)>>> = Mutex::new(None);
const CACHE_TTL: Duration = Duration::from_secs(60);

fn forget_cache() {
    *CACHE.lock().unwrap() = None;
}

/// One repository's index and published builds, cached briefly so the page does not hammer GitHub.
fn repo_data(url: &str, token: Option<&str>, fresh: bool) -> Result<RepoData, String> {
    if !fresh {
        if let Some((at, data)) = CACHE.lock().unwrap().as_ref().and_then(|c| c.get(url)) {
            if at.elapsed() < CACHE_TTL {
                return data.clone();
            }
        }
    }
    let (owner, repo) = parse_repo(url).ok_or("not a GitHub repository link")?;
    let data = fetch_index(&owner, &repo, token).map(|entries| RepoData { entries, builds: fetch_builds(&owner, &repo, token) });
    CACHE.lock().unwrap().get_or_insert_with(HashMap::new).insert(url.to_string(), (Instant::now(), data.clone()));
    data
}

/// installed / update / available, given what is installed and the newest known version.
fn status_of(installed: Option<&str>, latest: &str) -> &'static str {
    match installed {
        None => "available",
        // An empty version means it was installed before versions were recorded: reinstalling brings it current.
        Some("") => "update",
        Some(v) if !latest.is_empty() && v != latest => "update",
        Some(_) => "installed",
    }
}

const CORE: [&str; 2] = ["packages", "credentials"];

fn valid_id(s: &str) -> bool {
    (1..=32).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') && !s.starts_with('-')
}

fn valid_job(s: &str) -> bool {
    (8..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
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
    forget_cache();
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
    forget_cache();
    match save_repos(&repos) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &format!("could not save: {e}")),
    }
}

#[derive(Deserialize, Default)]
struct PackagesQuery {
    #[serde(default)]
    fresh: bool,
}

/// Every repository's offerings merged with what is installed.
async fn packages(method: Method, uri: Uri, headers: HeaderMap, Query(q): Query<PackagesQuery>) -> Response {
    if !signed_in(&method, &uri, &headers) {
        return error(StatusCode::UNAUTHORIZED, "sign in required");
    }
    let repos = load_repos();
    let token = load_token();
    let fresh = q.fresh;
    let results = tokio::task::spawn_blocking(move || {
        std::thread::scope(|s| {
            let handles: Vec<_> = repos.iter().map(|url| { let token = token.as_deref(); s.spawn(move || repo_data(url, token, fresh)) }).collect();
            repos.iter().cloned().zip(handles.into_iter().map(|h| h.join().unwrap_or_else(|_| Err("fetch crashed".into())))).collect::<Vec<_>>()
        })
    })
    .await
    .unwrap_or_default();

    let have = installed();
    let dependents = |id: &str| have.iter().filter(|i| i.requires.iter().any(|r| r == id)).map(|i| i.id.clone()).collect::<Vec<_>>();
    let mut seen = std::collections::BTreeSet::new();
    let mut repo_status = vec![];
    let mut out: Vec<Value> = vec![];
    for (url, res) in results {
        match res {
            Err(e) => repo_status.push(json!({ "url": url, "ok": false, "error": e })),
            Ok(data) => {
                repo_status.push(json!({ "url": url, "ok": true, "count": data.entries.len(), "published": data.builds.is_some() }));
                for e in data.entries {
                    if !seen.insert(e.id.clone()) {
                        continue; // the same id in two repositories: the first one listed wins
                    }
                    let inst = have.iter().find(|i| i.id == e.id);
                    let build = data.builds.as_ref().and_then(|b| b.get(&e.id)).cloned();
                    let latest = build.clone().unwrap_or_else(|| e.version.clone());
                    let missing: Vec<&String> = e.requires.iter().filter(|r| !have.iter().any(|i| &i.id == *r)).collect();
                    out.push(json!({
                        "id": e.id, "name": e.name, "description": e.description, "version": latest,
                        "installed_version": inst.map(|i| i.version.clone()), "status": status_of(inst.map(|i| i.version.as_str()), &latest),
                        "requires": e.requires, "missing_requires": missing, "dependents": dependents(&e.id), "repo": url,
                        "installable": build.is_some(), "core": CORE.contains(&e.id.as_str()),
                    }));
                }
            }
        }
    }
    // Installed but offered by none of the repositories (installed from a local folder, or a repository that failed to load).
    let others: Vec<Value> = have
        .iter()
        .filter(|i| !seen.contains(&i.id))
        .map(|i| json!({ "id": i.id, "name": if i.name.is_empty() { &i.id } else { &i.name }, "version": i.version, "dependents": dependents(&i.id), "core": CORE.contains(&i.id.as_str()) }))
        .collect();
    Json(json!({ "repos": repo_status, "packages": out, "other_installed": others, "github": load_token().is_some() })).into_response()
}

#[derive(Deserialize)]
struct DetailsQuery {
    repo: String,
    id: String,
}

/// What installing a package will do: its manifest, read from the repository, for the confirmation dialog.
async fn details(method: Method, uri: Uri, headers: HeaderMap, Query(q): Query<DetailsQuery>) -> Response {
    if !signed_in(&method, &uri, &headers) {
        return error(StatusCode::UNAUTHORIZED, "sign in required");
    }
    if !valid_id(&q.id) || !load_repos().contains(&q.repo) {
        return error(StatusCode::BAD_REQUEST, "unknown package");
    }
    let token = load_token();
    let r = tokio::task::spawn_blocking(move || {
        let data = repo_data(&q.repo, token.as_deref(), false)?;
        let entry = data.entries.iter().find(|e| e.id == q.id).ok_or("not in that repository")?;
        let (owner, repo) = parse_repo(&q.repo).ok_or("bad repository")?;
        let path = if entry.path.is_empty() { "plugin.toml".to_string() } else { format!("{}/plugin.toml", entry.path) };
        let text = fetch_text(&owner, &repo, &path, token.as_deref())?;
        let m: toml::Value = toml::from_str(&text).map_err(|e| format!("plugin.toml: {e}"))?;
        let s = |k: &str| m.get(k).and_then(|v| v.as_str()).map(str::to_string);
        let list = |k: &str| m.get(k).and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect::<Vec<_>>()).unwrap_or_default();
        let secrets: Vec<Value> = m.get("secret").and_then(|v| v.as_array()).into_iter().flatten().map(|x| json!({ "name": x.get("name").and_then(|v| v.as_str()), "label": x.get("label").and_then(|v| v.as_str()), "required": x.get("required").and_then(|v| v.as_bool()).unwrap_or(false) })).collect();
        Ok::<Value, String>(json!({
            "id": q.id, "name": s("name"), "description": s("description"), "version": s("version"), "grid": s("grid"),
            "requires": list("requires"), "provides": list("provides"), "secrets": secrets,
            "stores_data": m.get("service").and_then(|v| v.get("state_dir")).and_then(|v| v.as_bool()).unwrap_or(false),
        }))
    })
    .await;
    match r {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err(e)) => error(StatusCode::BAD_GATEWAY, &e),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

fn state_dir() -> PathBuf {
    repos_file().parent().map(PathBuf::from).unwrap_or_default()
}

fn random_job() -> Option<String> {
    let mut b = [0u8; 12];
    fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).ok()?;
    Some(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Queue a request for the root helper (a systemd path unit starts it when the file appears) and a job record to poll.
fn queue(action: &str, id: &str, repo: &str, purge: bool) -> Result<String, String> {
    let job = random_job().ok_or("no randomness available")?;
    let dir = state_dir();
    let (requests, jobs) = (dir.join("requests"), dir.join("jobs"));
    fs::create_dir_all(&requests).and_then(|_| fs::create_dir_all(&jobs)).map_err(|e| format!("could not queue: {e}"))?;
    let record = json!({ "job": job, "action": action, "id": id, "state": "queued", "message": "Waiting for the installer to start", "log": [] });
    fs::write(jobs.join(format!("{job}.json")), record.to_string()).map_err(|e| format!("could not queue: {e}"))?;
    let tmp = requests.join(format!("{job}.tmp"));
    fs::write(&tmp, json!({ "job": job, "action": action, "id": id, "repo": repo, "purge": purge }).to_string()).map_err(|e| format!("could not queue: {e}"))?;
    fs::rename(&tmp, requests.join(format!("{job}.json"))).map_err(|e| format!("could not queue: {e}"))?;
    forget_cache();
    Ok(job)
}

#[derive(Deserialize)]
struct InstallBody {
    repo: String,
    id: String,
}

async fn install(method: Method, uri: Uri, headers: HeaderMap, Json(b): Json<InstallBody>) -> Response {
    if !signed_in(&method, &uri, &headers) {
        return error(StatusCode::UNAUTHORIZED, "sign in required");
    }
    if !valid_id(&b.id) || !load_repos().contains(&b.repo) {
        return error(StatusCode::BAD_REQUEST, "unknown package");
    }
    match queue("install", &b.id, &b.repo, false) {
        Ok(job) => Json(json!({ "job": job })).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

#[derive(Deserialize)]
struct RemoveBody {
    id: String,
    #[serde(default)]
    purge: bool,
}

async fn uninstall(method: Method, uri: Uri, headers: HeaderMap, Json(b): Json<RemoveBody>) -> Response {
    if !signed_in(&method, &uri, &headers) {
        return error(StatusCode::UNAUTHORIZED, "sign in required");
    }
    if !valid_id(&b.id) || CORE.contains(&b.id.as_str()) {
        return error(StatusCode::BAD_REQUEST, "this package cannot be removed from here");
    }
    match queue("remove", &b.id, "", b.purge) {
        Ok(job) => Json(json!({ "job": job })).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn job(method: Method, uri: Uri, headers: HeaderMap, Path(job): Path<String>) -> Response {
    if !signed_in(&method, &uri, &headers) {
        return error(StatusCode::UNAUTHORIZED, "sign in required");
    }
    if !valid_job(&job) {
        return error(StatusCode::BAD_REQUEST, "bad job id");
    }
    match fs::read_to_string(state_dir().join("jobs").join(format!("{job}.json"))) {
        Ok(t) => ([(axum::http::header::CONTENT_TYPE, "application/json")], t).into_response(),
        Err(_) => error(StatusCode::NOT_FOUND, "no such job"),
    }
}

/// Drop job records and stray request files older than a day.
fn tidy() {
    let dir = state_dir();
    let _ = fs::create_dir_all(dir.join("requests"));
    let _ = fs::create_dir_all(dir.join("jobs"));
    for sub in ["jobs", "requests"] {
        for e in fs::read_dir(dir.join(sub)).into_iter().flatten().flatten() {
            if e.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age > Duration::from_secs(86_400)) {
                let _ = fs::remove_file(e.path());
            }
        }
    }
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
        forget_cache();
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
    forget_cache();
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
    tidy();
    let app = Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/repos", get(list_repos).post(add_repo).delete(remove_repo))
        .route("/api/packages", get(packages))
        .route("/api/details", get(details))
        .route("/api/install", axum::routing::post(install))
        .route("/api/remove", axum::routing::post(uninstall))
        .route("/api/jobs/{job}", get(job))
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

    #[test]
    fn status_logic() {
        assert_eq!(status_of(None, "1.0.0"), "available");
        assert_eq!(status_of(Some("1.0.0"), "1.0.0"), "installed");
        assert_eq!(status_of(Some("0.9.0"), "1.0.0"), "update");
        assert_eq!(status_of(Some(""), "1.0.0"), "update");
        assert_eq!(status_of(Some("1.0.0"), ""), "installed");
    }

    #[test]
    fn ids_and_jobs_are_validated() {
        assert!(valid_id("adsb-history") && !valid_id("../x") && !valid_id("-x") && !valid_id(""));
        assert!(valid_job("0123456789abcdef") && !valid_job("../../etc") && !valid_job("short"));
    }
}

//! Packages plugin: the list of package repositories, and what each offers versus what is installed.
//!
//! It reads each repository's `index.toml` from raw.githubusercontent.com and the installed manifests in
//! /etc/osnt/plugins.d. Installing and removing still happens with `cargo deploy plugin add|remove` on your
//! computer; this page shows the exact command. Every route needs the portal's gateway signature (a signed-in user).

use std::{env, fs, net::SocketAddr, path::PathBuf, sync::Mutex};

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

fn fetch_index(owner: &str, repo: &str) -> Result<Vec<Entry>, String> {
    let agent = osnt_common::http_agent("osnt-packages");
    let url = format!("https://raw.githubusercontent.com/{owner}/{repo}/HEAD/index.toml");
    let mut resp = agent.get(&url).config().http_status_as_error(false).build().call().map_err(|e| format!("could not reach GitHub: {e}"))?;
    match resp.status().as_u16() {
        200 => {}
        404 => return Err("not found. If the repository is private, the hub cannot read it until GitHub sign-in is set up".into()),
        s => return Err(format!("GitHub answered {s}")),
    }
    let text = resp.body_mut().with_config().limit(MAX_INDEX_BYTES).read_to_string().map_err(|e| format!("could not read index.toml: {e}"))?;
    let idx: Index = toml::from_str(&text).map_err(|e| format!("index.toml is not valid: {e}"))?;
    Ok(idx.plugins.into_iter().filter(|e| e.path.is_empty() || e.path.split('/').all(safe_segment)).collect())
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
    let results = tokio::task::spawn_blocking(move || {
        std::thread::scope(|s| {
            let handles: Vec<_> = repos
                .iter()
                .map(|url| {
                    let parsed = parse_repo(url);
                    s.spawn(move || match parsed {
                        Some((o, r)) => fetch_index(&o, &r),
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
        .route("/api/packages", get(packages));
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

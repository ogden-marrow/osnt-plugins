//! Link graph: a Maltego-style entity graph. Nodes are things (domains, IPs, ASNs, organisations, vessels, aircraft,
//! places, events, documents, hashes, URLs); there is no person, username, email or phone node type, and imports
//! that contain one are rejected. All /api routes need the hub's gateway signature. Transforms ("expand") run in the
//! browser against sibling plugins, so each call carries the signed-in user's own authority.

mod store;
#[cfg(test)]
mod tests;

use std::{env, net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use serde_json::{Value, json};

use store::*;

const PAGE: &str = include_str!("../assets/index.html");

pub struct App {
    pub store: Store,
}
pub type Shared = Arc<App>;

#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub String);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}
fn bad(e: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, e.into())
}
fn missing() -> ApiError {
    ApiError(StatusCode::NOT_FOUND, "no such graph".into())
}
fn internal(e: String) -> ApiError {
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, e)
}
type R = Result<Json<Value>, ApiError>;

fn auth(method: &Method, uri: &Uri, headers: &HeaderMap) -> Result<(), ApiError> {
    if osnt_common::gateway_authorized(method.as_str(), uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"), headers.get("x-osnt-gateway").and_then(|v| v.to_str().ok())) {
        Ok(())
    } else {
        Err(ApiError(StatusCode::UNAUTHORIZED, "sign in required".into()))
    }
}

/// Every /api request is checked before its body is parsed.
async fn gate(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    if req.uri().path().starts_with("/api/") {
        if let Err(e) = auth(req.method(), req.uri(), req.headers()) {
            return e.into_response();
        }
    }
    next.run(req).await
}

fn load(s: &App, id: &str) -> Result<Graph, ApiError> {
    s.store.load(id).map_err(internal)?.ok_or_else(missing)
}

async fn list(State(s): State<Shared>) -> R {
    Ok(Json(json!({ "graphs": s.store.list().iter().map(summary).collect::<Vec<_>>(), "node_types": NODE_TYPES })))
}

#[derive(Deserialize)]
pub struct CreateBody {
    name: String,
}

async fn create(State(s): State<Shared>, Json(b): Json<CreateBody>) -> R {
    let _g = LOCK.lock().unwrap();
    if s.store.list().len() >= MAX_GRAPHS {
        return Err(bad(format!("at most {MAX_GRAPHS} graphs; export and delete old ones")));
    }
    let now = now_iso();
    let mut g = Graph { id: new_id(), name: b.name, created: now.clone(), updated: now, ..Default::default() };
    validate(&mut g).map_err(bad)?;
    s.store.save(&g).map_err(internal)?;
    Ok(Json(json!(g)))
}

async fn get_graph(State(s): State<Shared>, Path(id): Path<String>) -> R {
    Ok(Json(json!(load(&s, &id)?)))
}

#[derive(Deserialize)]
pub struct SaveBody {
    name: String,
    nodes: Vec<Node>,
    edges: Vec<Edge>,
}

/// Replace a graph's contents (the page autosaves with this). Everything is re-validated.
async fn save_graph(State(s): State<Shared>, Path(id): Path<String>, Json(b): Json<SaveBody>) -> R {
    let _g = LOCK.lock().unwrap();
    let old = load(&s, &id)?;
    let mut g = Graph { id: old.id, name: b.name, created: old.created, updated: now_iso(), nodes: b.nodes, edges: b.edges };
    validate(&mut g).map_err(bad)?;
    s.store.save(&g).map_err(internal)?;
    Ok(Json(json!(g)))
}

async fn delete_graph(State(s): State<Shared>, Path(id): Path<String>) -> R {
    let _g = LOCK.lock().unwrap();
    if s.store.delete(&id).map_err(internal)? { Ok(Json(json!({ "ok": true }))) } else { Err(missing()) }
}

#[derive(Deserialize)]
pub struct MergeBody {
    #[serde(default)]
    nodes: Vec<Node>,
    #[serde(default)]
    edges: Vec<Edge>,
    /// Where the additions came from, e.g. "transform:lookup" or "case-notebook".
    #[serde(default)]
    source: String,
}

/// Add nodes and edges produced by a transform or an import. Existing nodes are reused; the request is all or nothing.
async fn merge_into(State(s): State<Shared>, Path(id): Path<String>, Json(b): Json<MergeBody>) -> R {
    let src: String = b.source.chars().filter(|c| c.is_ascii_alphanumeric() || ":-_".contains(*c)).take(60).collect();
    let _g = LOCK.lock().unwrap();
    let mut g = load(&s, &id)?;
    let (an, ae) = merge(&mut g, b.nodes, b.edges, if src.is_empty() { "import" } else { &src }).map_err(bad)?;
    s.store.save(&g).map_err(internal)?;
    Ok(Json(json!({ "added_nodes": an, "added_edges": ae, "graph": g })))
}

#[derive(Deserialize)]
pub struct ExportQuery {
    format: Option<String>,
}

fn render(g: &Graph, format: &str) -> Result<(String, String, &'static str), String> {
    let slug: String = g.name.to_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect::<String>().trim_matches('-').chars().take(40).collect();
    Ok(match format {
        "json" => (serde_json::to_string_pretty(&export_json(g)).unwrap(), format!("graph-{slug}.json"), "application/json"),
        "graphml" => (graphml(g), format!("graph-{slug}.graphml"), "application/xml"),
        "gexf" => (gexf(g), format!("graph-{slug}.gexf"), "application/xml"),
        "mermaid" => (mermaid(g), format!("graph-{slug}.mmd"), "text/plain; charset=utf-8"),
        "md" | "markdown" => (markdown(g), format!("graph-{slug}.md"), "text/markdown; charset=utf-8"),
        _ => return Err("format must be json, graphml, gexf, mermaid or md".into()),
    })
}

async fn export(State(s): State<Shared>, Path(id): Path<String>, Query(q): Query<ExportQuery>) -> Result<Response, ApiError> {
    let g = load(&s, &id)?;
    let (body, name, ct) = render(&g, q.format.as_deref().unwrap_or("json")).map_err(bad)?;
    Ok(([(header::CONTENT_TYPE, ct.to_string()), (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\""))], body).into_response())
}

async fn import(State(s): State<Shared>, Json(v): Json<Value>) -> R {
    let g = import_bundle(&v).map_err(bad)?;
    let _g = LOCK.lock().unwrap();
    if s.store.list().len() >= MAX_GRAPHS {
        return Err(bad(format!("at most {MAX_GRAPHS} graphs")));
    }
    s.store.save(&g).map_err(internal)?;
    Ok(Json(summary(&g)))
}

// ---- agent views (read-only; the investigator's per-node remarks are left out) --------------------

async fn agent_list(State(s): State<Shared>) -> Json<Value> {
    Json(json!({ "graphs": s.store.list().iter().map(summary).collect::<Vec<_>>() }))
}

async fn agent_export(State(s): State<Shared>, Path(id): Path<String>, Query(q): Query<ExportQuery>) -> R {
    let mut g = load(&s, &id)?;
    for n in &mut g.nodes {
        n.note.clear();
    }
    match q.format.as_deref().unwrap_or("mermaid") {
        "mermaid" => Ok(Json(json!({ "graph": g.name, "format": "mermaid", "content": mermaid(&g) }))),
        "json" => Ok(Json(json!({ "graph": g.name, "format": "json", "nodes": g.nodes.iter().map(|n| json!({ "id": n.id, "type": n.kind, "label": n.label, "group": n.group, "source": n.source })).collect::<Vec<_>>(), "edges": g.edges.iter().map(|e| json!({ "from": e.from, "to": e.to, "label": e.label })).collect::<Vec<_>>() }))),
        _ => Err(bad("format must be mermaid or json")),
    }
}

async fn tools() -> Json<Value> {
    Json(json!([
        { "name": "graph_list", "description": "List the investigator's entity graphs (name, node and edge counts). Read-only.", "method": "GET", "path": "agent/graphs", "parameters": { "type": "object", "properties": {} } },
        { "name": "graph_export", "description": "Export one entity graph as Mermaid text or JSON (nodes: domain, ip, asn, certificate, organisation, url, hash, vessel, aircraft, place, event, document). The investigator's private per-node remarks are omitted. Relationships are the investigator's hypotheses, not verified facts.",
          "method": "GET", "path": "agent/graphs/{id}", "parameters": { "type": "object", "properties": { "id": { "type": "string", "description": "Graph id from graph_list" }, "format": { "type": "string", "enum": ["mermaid", "json"] } }, "required": ["id"] } },
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

pub fn app(state: Shared) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/agent/graphs", get(agent_list))
        .route("/agent/graphs/{id}", get(agent_export))
        .route("/api/graphs", get(list).post(create))
        .route("/api/graphs/{id}", get(get_graph).put(save_graph).delete(delete_graph))
        .route("/api/graphs/{id}/merge", axum::routing::post(merge_into))
        .route("/api/graphs/{id}/export", get(export))
        .route("/api/import", axum::routing::post(import))
        .layer(DefaultBodyLimit::max(MAX_GRAPH_BYTES))
        .layer(axum::middleware::from_fn(gate))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    let dir = PathBuf::from(env::var("OSNT_STATE_DIR").unwrap_or_else(|_| "/var/lib/osnt-link-graph".into()));
    let store = Store::new(dir).expect("state dir");
    let addr: SocketAddr = env::var("OSNT_LINK_GRAPH_BIND").unwrap_or_else(|_| "127.0.0.1:8164".into()).parse().expect("bind addr");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("link-graph plugin on http://{addr}");
    axum::serve(listener, app(Arc::new(App { store }))).await.expect("serve");
}

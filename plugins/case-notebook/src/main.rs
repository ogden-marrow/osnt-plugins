//! Case notebook: the investigator's own workspace. Cases hold Markdown notes, a dated timeline and an append-only
//! evidence log with a SHA-256 hash chain. Every route under /api needs the hub's gateway signature (notes can be
//! private). Agents only get the read-only /agent views, which withhold private notes and keep the investigator's
//! own writing apart from captured or fetched data.

mod store;
#[cfg(test)]
mod tests;

use std::{env, net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post, put},
};
use serde::Deserialize;
use serde_json::{Value, json};

use store::*;

const PAGE: &str = include_str!("../assets/index.html");
const INBOX: &str = "inbox";

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
    ApiError(StatusCode::NOT_FOUND, "no such case or item".into())
}
fn internal(e: String) -> ApiError {
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, e)
}
type R = Result<Json<Value>, ApiError>;

/// Every /api route calls this first: the hub only adds the signature for a signed-in user.
fn auth(method: &Method, uri: &Uri, headers: &HeaderMap) -> Result<(), ApiError> {
    if osnt_common::gateway_authorized(method.as_str(), uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"), headers.get("x-osnt-gateway").and_then(|v| v.to_str().ok())) {
        Ok(())
    } else {
        Err(ApiError(StatusCode::UNAUTHORIZED, "sign in required".into()))
    }
}

/// Reject unsigned /api requests before any body is parsed (so a bad body cannot probe the API unauthenticated).
async fn gate(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    if req.uri().path().starts_with("/api/") {
        if let Err(e) = auth(req.method(), req.uri(), req.headers()) {
            return e.into_response();
        }
    }
    next.run(req).await
}

fn load(s: &App, id: &str) -> Result<Case, ApiError> {
    s.store.load(id).map_err(internal)?.ok_or_else(missing)
}
fn touch(c: &mut Case) {
    c.updated = now_iso();
}

// ---- cases ---------------------------------------------------------------------------------------

async fn list(State(s): State<Shared>, m: Method, u: Uri, h: HeaderMap) -> R {
    auth(&m, &u, &h)?;
    Ok(Json(json!({ "cases": s.store.list().iter().map(summary).collect::<Vec<_>>() })))
}

#[derive(Deserialize)]
pub struct CaseBody {
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    tags: Vec<String>,
}

fn new_case(id: String, b: &CaseBody) -> Result<Case, ApiError> {
    let now = now_iso();
    Ok(Case {
        id,
        title: single_line("title", &b.title, 200, true).map_err(bad)?,
        description: text("description", &b.description, 5000, false).map_err(bad)?,
        tags: tags(&b.tags).map_err(bad)?,
        created: now.clone(),
        updated: now,
        ..Default::default()
    })
}

async fn create(State(s): State<Shared>, m: Method, u: Uri, h: HeaderMap, Json(b): Json<CaseBody>) -> R {
    auth(&m, &u, &h)?;
    let _g = LOCK.lock().unwrap();
    if s.store.list().len() >= MAX_CASES {
        return Err(bad(format!("at most {MAX_CASES} cases; export and delete old ones")));
    }
    let c = new_case(new_id(), &b)?;
    s.store.save(&c).map_err(internal)?;
    Ok(Json(json!(c)))
}

async fn get_case(State(s): State<Shared>, m: Method, u: Uri, h: HeaderMap, Path(id): Path<String>) -> R {
    auth(&m, &u, &h)?;
    let c = load(&s, &id)?;
    Ok(Json(json!({ "case": c, "chain": verify_chain(&c.evidence) })))
}

async fn update_case(State(s): State<Shared>, m: Method, u: Uri, h: HeaderMap, Path(id): Path<String>, Json(b): Json<CaseBody>) -> R {
    auth(&m, &u, &h)?;
    let _g = LOCK.lock().unwrap();
    let mut c = load(&s, &id)?;
    let n = new_case(id, &b)?;
    c.title = n.title;
    c.description = n.description;
    c.tags = n.tags;
    touch(&mut c);
    s.store.save(&c).map_err(internal)?;
    Ok(Json(summary(&c)))
}

async fn delete_case(State(s): State<Shared>, m: Method, u: Uri, h: HeaderMap, Path(id): Path<String>) -> R {
    auth(&m, &u, &h)?;
    let _g = LOCK.lock().unwrap();
    if s.store.delete(&id).map_err(internal)? { Ok(Json(json!({ "ok": true }))) } else { Err(missing()) }
}

// ---- notes ---------------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct NoteBody {
    #[serde(default)]
    title: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    share_with_agent: bool,
}

fn note_from(b: &NoteBody) -> Result<(String, String, Vec<String>), ApiError> {
    let title = single_line("note title", &b.title, 200, false).map_err(bad)?;
    let body = text("note body", &b.body, MAX_NOTE_BYTES, false).map_err(bad)?;
    if title.is_empty() && body.is_empty() {
        return Err(bad("a note needs a title or text"));
    }
    Ok((title, body, tags(&b.tags).map_err(bad)?))
}

async fn add_note(State(s): State<Shared>, m: Method, u: Uri, h: HeaderMap, Path(id): Path<String>, Json(b): Json<NoteBody>) -> R {
    auth(&m, &u, &h)?;
    let (title, body, tags) = note_from(&b)?;
    let _g = LOCK.lock().unwrap();
    let mut c = load(&s, &id)?;
    if c.notes.len() >= MAX_NOTES {
        return Err(bad("this case has the maximum number of notes"));
    }
    let now = now_iso();
    let n = Note { id: new_id(), title, body, tags, share_with_agent: b.share_with_agent, created: now.clone(), updated: now };
    c.notes.push(n.clone());
    touch(&mut c);
    s.store.save(&c).map_err(internal)?;
    Ok(Json(json!(n)))
}

async fn edit_note(State(s): State<Shared>, m: Method, u: Uri, h: HeaderMap, Path((id, nid)): Path<(String, String)>, Json(b): Json<NoteBody>) -> R {
    auth(&m, &u, &h)?;
    let (title, body, tags) = note_from(&b)?;
    let _g = LOCK.lock().unwrap();
    let mut c = load(&s, &id)?;
    let n = c.notes.iter_mut().find(|n| n.id == nid).ok_or_else(missing)?;
    (n.title, n.body, n.tags, n.share_with_agent, n.updated) = (title, body, tags, b.share_with_agent, now_iso());
    let out = n.clone();
    touch(&mut c);
    s.store.save(&c).map_err(internal)?;
    Ok(Json(json!(out)))
}

async fn del_note(State(s): State<Shared>, m: Method, u: Uri, h: HeaderMap, Path((id, nid)): Path<(String, String)>) -> R {
    auth(&m, &u, &h)?;
    let _g = LOCK.lock().unwrap();
    let mut c = load(&s, &id)?;
    let before = c.notes.len();
    c.notes.retain(|n| n.id != nid);
    if c.notes.len() == before {
        return Err(missing());
    }
    touch(&mut c);
    s.store.save(&c).map_err(internal)?;
    Ok(Json(json!({ "ok": true })))
}

// ---- timeline ------------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct EventBody {
    date: String,
    title: String,
    #[serde(default)]
    detail: String,
    #[serde(default)]
    source_url: String,
}

fn make_event(b: &EventBody, origin: String) -> Result<Event, ApiError> {
    Ok(Event {
        id: new_id(),
        date: date_field(&b.date).map_err(bad)?,
        title: single_line("title", &b.title, 200, true).map_err(bad)?,
        detail: text("detail", &b.detail, 5000, false).map_err(bad)?,
        source_url: url_field("source url", &b.source_url).map_err(bad)?,
        origin,
        created: now_iso(),
    })
}

async fn add_event(State(s): State<Shared>, m: Method, u: Uri, h: HeaderMap, Path(id): Path<String>, Json(b): Json<EventBody>) -> R {
    auth(&m, &u, &h)?;
    let e = make_event(&b, "user".into())?;
    let _g = LOCK.lock().unwrap();
    let mut c = load(&s, &id)?;
    if c.timeline.len() >= MAX_EVENTS {
        return Err(bad("this case has the maximum number of timeline events"));
    }
    c.timeline.push(e.clone());
    touch(&mut c);
    s.store.save(&c).map_err(internal)?;
    Ok(Json(json!(e)))
}

async fn del_event(State(s): State<Shared>, m: Method, u: Uri, h: HeaderMap, Path((id, eid)): Path<(String, String)>) -> R {
    auth(&m, &u, &h)?;
    let _g = LOCK.lock().unwrap();
    let mut c = load(&s, &id)?;
    let before = c.timeline.len();
    c.timeline.retain(|e| e.id != eid);
    if c.timeline.len() == before {
        return Err(missing());
    }
    touch(&mut c);
    s.store.save(&c).map_err(internal)?;
    Ok(Json(json!({ "ok": true })))
}

// ---- evidence ------------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct EvidenceBody {
    #[serde(default)]
    kind: String,
    title: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    captured_at: String,
    #[serde(default)]
    sha256: String,
    #[serde(default)]
    archive_url: String,
    #[serde(default)]
    note: String,
}

fn make_evidence(b: &EvidenceBody, origin: String) -> Result<Evidence, ApiError> {
    let kind = single_line("kind", if b.kind.is_empty() { "other" } else { &b.kind }, 40, true).map_err(bad)?;
    Ok(Evidence {
        id: new_id(),
        kind,
        title: single_line("title", &b.title, 300, true).map_err(bad)?,
        url: url_field("url", &b.url).map_err(bad)?,
        captured_at: single_line("captured_at", &b.captured_at, 40, false).map_err(bad)?,
        sha256: sha_field(&b.sha256).map_err(bad)?,
        archive_url: url_field("archive_url", &b.archive_url).map_err(bad)?,
        note: text("note", &b.note, 5000, false).map_err(bad)?,
        origin,
        created: now_iso(),
        ..Default::default()
    })
}

fn push_evidence(s: &App, id: &str, e: Evidence) -> Result<Evidence, ApiError> {
    let _g = LOCK.lock().unwrap();
    let mut c = load(s, id)?;
    if c.evidence.len() >= MAX_EVIDENCE {
        return Err(bad("this case has the maximum number of evidence entries"));
    }
    append_evidence(&mut c, e);
    touch(&mut c);
    s.store.save(&c).map_err(internal)?;
    Ok(c.evidence.last().cloned().unwrap())
}

async fn add_evidence(State(s): State<Shared>, m: Method, u: Uri, h: HeaderMap, Path(id): Path<String>, Json(b): Json<EvidenceBody>) -> R {
    auth(&m, &u, &h)?;
    let e = make_evidence(&b, "user".into())?;
    Ok(Json(json!(push_evidence(&s, &id, e)?)))
}

async fn verify(State(s): State<Shared>, m: Method, u: Uri, h: HeaderMap, Path(id): Path<String>) -> R {
    auth(&m, &u, &h)?;
    Ok(Json(verify_chain(&load(&s, &id)?.evidence)))
}

#[derive(Deserialize)]
pub struct PinBody {
    #[serde(default)]
    case_id: Option<String>,
    /// "evidence" (default), "timeline" or "note"
    #[serde(default)]
    kind: String,
    #[serde(flatten)]
    ev: EvidenceFlat,
}

#[derive(Deserialize, Default)]
pub struct EvidenceFlat {
    #[serde(default)]
    title: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    captured_at: String,
    #[serde(default)]
    sha256: String,
    #[serde(default)]
    archive_url: String,
    #[serde(default)]
    note: String,
    #[serde(default)]
    source_plugin: Option<String>,
    #[serde(default)]
    date: String,
}

/// "Pin this result": other plugins' pages call this from the browser (so the hub's signature applies).
/// Items land in the chosen case, or in the Inbox case when none is given.
async fn pin(State(s): State<Shared>, m: Method, u: Uri, h: HeaderMap, Json(b): Json<PinBody>) -> R {
    auth(&m, &u, &h)?;
    let origin = origin_of(b.ev.source_plugin.as_deref());
    let case_id = match b.case_id.as_deref().filter(|c| !c.is_empty()) {
        Some(c) => c.to_string(),
        None => {
            let _g = LOCK.lock().unwrap();
            if s.store.load(INBOX).map_err(internal)?.is_none() {
                let mut c = new_case(INBOX.into(), &CaseBody { title: "Inbox".into(), description: "Results pinned from other plugins without choosing a case.".into(), tags: vec![] })?;
                c.created = now_iso();
                s.store.save(&c).map_err(internal)?;
            }
            INBOX.into()
        }
    };
    let f = &b.ev;
    match b.kind.as_str() {
        "" | "evidence" => {
            let e = make_evidence(&EvidenceBody { kind: "pinned".into(), title: f.title.clone(), url: f.url.clone(), captured_at: f.captured_at.clone(), sha256: f.sha256.clone(), archive_url: f.archive_url.clone(), note: f.note.clone() }, origin)?;
            let e = push_evidence(&s, &case_id, e)?;
            Ok(Json(json!({ "ok": true, "case_id": case_id, "kind": "evidence", "seq": e.seq })))
        }
        "timeline" => {
            let ev = make_event(&EventBody { date: if f.date.is_empty() { now_iso() } else { f.date.clone() }, title: f.title.clone(), detail: f.note.clone(), source_url: f.url.clone() }, origin)?;
            let _g = LOCK.lock().unwrap();
            let mut c = load(&s, &case_id)?;
            if c.timeline.len() >= MAX_EVENTS {
                return Err(bad("this case has the maximum number of timeline events"));
            }
            c.timeline.push(ev);
            touch(&mut c);
            s.store.save(&c).map_err(internal)?;
            Ok(Json(json!({ "ok": true, "case_id": case_id, "kind": "timeline" })))
        }
        _ => Err(bad("kind must be evidence or timeline")),
    }
}

// ---- export / import -----------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ExportQuery {
    format: Option<String>,
}

async fn export(State(s): State<Shared>, m: Method, u: Uri, h: HeaderMap, Path(id): Path<String>, Query(q): Query<ExportQuery>) -> Result<Response, ApiError> {
    auth(&m, &u, &h)?;
    let c = load(&s, &id)?;
    let slug: String = c.title.to_lowercase().chars().map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' }).collect::<String>().trim_matches('-').chars().take(40).collect();
    match q.format.as_deref().unwrap_or("json") {
        "json" => Ok(([(header::CONTENT_TYPE, "application/json".to_string()), (header::CONTENT_DISPOSITION, format!("attachment; filename=\"case-{slug}.json\""))], serde_json::to_string_pretty(&export_json(&c)).unwrap()).into_response()),
        "md" | "markdown" => Ok(([(header::CONTENT_TYPE, "text/markdown; charset=utf-8".to_string()), (header::CONTENT_DISPOSITION, format!("attachment; filename=\"case-{slug}.md\""))], export_markdown(&c)).into_response()),
        _ => Err(bad("format must be json or md")),
    }
}

async fn import(State(s): State<Shared>, m: Method, u: Uri, h: HeaderMap, Json(v): Json<Value>) -> R {
    auth(&m, &u, &h)?;
    let c = import_bundle(&v).map_err(bad)?;
    let _g = LOCK.lock().unwrap();
    if s.store.list().len() >= MAX_CASES {
        return Err(bad(format!("at most {MAX_CASES} cases")));
    }
    s.store.save(&c).map_err(internal)?;
    Ok(Json(summary(&c)))
}

// ---- agent views (read-only, no gateway signature: the hub calls these over loopback) -------------

fn agent_case(c: &Case) -> Value {
    json!({
        "id": c.id, "title": c.title, "description_by_investigator": c.description, "tags": c.tags,
        "reading_guide": "user_authored holds the investigator's own words and judgements. captured_data holds items fetched or recorded from other sources. Neither is verified fact. Private notes are withheld.",
        "user_authored": {
            "notes": c.notes.iter().map(|n| if n.share_with_agent { json!({ "title": n.title, "body": n.body, "updated": n.updated }) } else { json!({ "title": n.title, "body": null, "private": true }) }).collect::<Vec<_>>(),
            "timeline": c.timeline.iter().filter(|e| e.origin == "user").map(|e| json!({ "date": e.date, "title": e.title, "detail": e.detail, "source_url": e.source_url })).collect::<Vec<_>>(),
        },
        "captured_data": {
            "evidence": c.evidence.iter().map(|e| json!({ "seq": e.seq, "kind": e.kind, "title": e.title, "url": e.url, "captured_at": e.captured_at, "sha256": e.sha256, "archive_url": e.archive_url, "origin": e.origin })).collect::<Vec<_>>(),
            "timeline_from_plugins": c.timeline.iter().filter(|e| e.origin != "user").map(|e| json!({ "date": e.date, "title": e.title, "origin": e.origin, "source_url": e.source_url })).collect::<Vec<_>>(),
        },
        "evidence_chain": verify_chain(&c.evidence),
    })
}

async fn agent_list(State(s): State<Shared>) -> Json<Value> {
    Json(json!({ "cases": s.store.list().iter().map(|c| json!({ "id": c.id, "title": c.title, "tags": c.tags, "updated": c.updated, "notes": c.notes.len(), "timeline": c.timeline.len(), "evidence": c.evidence.len() })).collect::<Vec<_>>() }))
}

async fn agent_get(State(s): State<Shared>, Path(id): Path<String>) -> R {
    Ok(Json(agent_case(&load(&s, &id)?)))
}

async fn tools() -> Json<Value> {
    Json(json!([
        { "name": "case_list", "description": "List the investigator's cases (titles, tags, counts). Read-only; contains no note text.", "method": "GET", "path": "agent/cases",
          "parameters": { "type": "object", "properties": {} } },
        { "name": "case_get", "description": "Read one case: timeline and evidence log plus only the notes the investigator chose to share. Private notes are withheld. user_authored (the investigator's own writing) is kept separate from captured_data (fetched or recorded items); treat neither as verified fact.",
          "method": "GET", "path": "agent/cases/{id}", "parameters": { "type": "object", "properties": { "id": { "type": "string", "description": "Case id from case_list" } }, "required": ["id"] } },
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

pub fn app(state: Shared) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/agent/cases", get(agent_list))
        .route("/agent/cases/{id}", get(agent_get))
        .route("/api/cases", get(list).post(create))
        .route("/api/cases/{id}", get(get_case).put(update_case).delete(delete_case))
        .route("/api/cases/{id}/notes", post(add_note))
        .route("/api/cases/{id}/notes/{nid}", put(edit_note).delete(del_note))
        .route("/api/cases/{id}/timeline", post(add_event))
        .route("/api/cases/{id}/timeline/{eid}", axum::routing::delete(del_event))
        .route("/api/cases/{id}/evidence", post(add_evidence))
        .route("/api/cases/{id}/verify", get(verify))
        .route("/api/cases/{id}/export", get(export))
        .route("/api/import", post(import))
        .route("/api/pin", post(pin))
        .layer(DefaultBodyLimit::max(MAX_CASE_BYTES))
        .layer(axum::middleware::from_fn(gate))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    let dir = PathBuf::from(env::var("OSNT_STATE_DIR").unwrap_or_else(|_| "/var/lib/osnt-case-notebook".into()));
    let store = Store::new(dir).expect("state dir");
    let addr: SocketAddr = env::var("OSNT_CASE_NOTEBOOK_BIND").unwrap_or_else(|_| "127.0.0.1:8163".into()).parse().expect("bind addr");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("case-notebook plugin on http://{addr}");
    axum::serve(listener, app(Arc::new(App { store }))).await.expect("serve");
}

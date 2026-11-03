//! Netblock exposure: expand a small IPv4 block and summarise what Shodan InternetDB already knows about each
//! address. Entirely passive: this plugin sends no packets to the addresses themselves.

mod common;
mod jobs;
mod net;
#[cfg(test)]
mod testutil;

use std::{env, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    middleware,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use common::*;
use serde::Deserialize;
use serde_json::{Value, json};

const PAGE: &str = include_str!("../assets/index.html");

pub struct AppState {
    pub agent: ureq::Agent,
    pub base: String,
    pub authz: Authz,
    pub min_prefix: u8,
    pub delay: Duration,
    pub cache: TtlCache<Option<jobs::Cell>>,
    pub jobs: jobs::Jobs,
}
pub type Shared = Arc<AppState>;

impl AppState {
    pub fn new(agent: ureq::Agent, authz: Authz, min_prefix: u8) -> Self {
        Self { agent, base: "https://internetdb.shodan.io".into(), authz, min_prefix: min_prefix.clamp(22, 24), delay: Duration::from_millis(250), cache: TtlCache::new(Duration::from_secs(6 * 3600), 4096), jobs: jobs::Jobs::default() }
    }
}

#[derive(Deserialize)]
struct ScanBody {
    cidr: String,
}
async fn start(State(s): State<Shared>, Json(b): Json<ScanBody>) -> Result<Json<Value>, ApiError> {
    let net = jobs::parse_block(&b.cidr, s.min_prefix).map_err(|e| bad(&e))?;
    jobs::start(&s, net).map(Json).map_err(|e| ApiError(StatusCode::CONFLICT, e))
}
async fn status(State(s): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    jobs::snapshot(&s, &id).map(Json).ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such scan (it may have expired)".into()))
}
async fn cancel(State(s): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    jobs::cancel(&s, &id).map(Json).ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such scan".into()))
}
async fn csv(State(s): State<Shared>, Path(id): Path<String>) -> Result<Response, ApiError> {
    let body = jobs::csv(&s, &id).ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such scan".into()))?;
    Ok(([(header::CONTENT_TYPE, "text/csv; charset=utf-8"), (header::CONTENT_DISPOSITION, "attachment; filename=\"exposure.csv\"")], body).into_response())
}

#[derive(Deserialize)]
struct SumQ {
    cidr: String,
    wait: Option<u64>,
}
/// Agent-friendly: start (or join) a scan and wait up to `wait` seconds for the summary.
async fn summary(State(s): State<Shared>, Query(q): Query<SumQ>) -> Result<Json<Value>, ApiError> {
    let net = jobs::parse_block(&q.cidr, s.min_prefix).map_err(|e| bad(&e))?;
    let wait = q.wait.unwrap_or(40).min(90);
    let s2 = s.clone();
    let id = blocking(move || jobs::start(&s2, net).map_err(|e| e)).await?.map_err(|e| ApiError(StatusCode::CONFLICT, e))?["id"].as_str().unwrap_or("").to_string();
    let end = std::time::Instant::now() + Duration::from_secs(wait);
    loop {
        let snap = jobs::snapshot(&s, &id).ok_or_else(|| upstream("scan vanished"))?;
        if snap["state"] != "running" || std::time::Instant::now() >= end {
            let mut out = snap;
            // The agent gets the aggregates and the hosts with something to report, without the per-cell geometry.
            out["complete"] = json!(out["state"] == "done");
            return Ok(Json(out));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn config(State(s): State<Shared>) -> Json<Value> {
    Json(json!({ "min_prefix": s.min_prefix, "max_addresses": 1u64 << (32 - s.min_prefix), "delay_ms": s.delay.as_millis() as u64 }))
}

async fn tools() -> Json<Value> {
    Json(json!([
        { "name": "cidr_summary", "description": "Passive exposure summary of an IPv4 block (up to /24 by default) from Shodan InternetDB: hosts with data, open-port histogram, products, hosts with known CVEs, hostnames. Sends nothing to the targets. Large blocks take about a quarter second per uncached address; if it is not finished within the wait time, `complete` is false and the partial summary is returned.",
          "method": "GET", "path": "api/summary", "parameters": { "type": "object", "properties": { "cidr": { "type": "string", "description": "IPv4 CIDR such as 203.0.113.0/24" }, "wait": { "type": "integer", "description": "seconds to wait for completion (default 40, max 90)" } }, "required": ["cidr"] } }
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

pub fn app(state: Shared) -> Router {
    let api = Router::new()
        .route("/api/config", get(config))
        .route("/api/scan", post(start))
        .route("/api/scan/{id}", get(status))
        .route("/api/scan/{id}/cancel", post(cancel))
        .route("/api/scan/{id}/csv", get(csv))
        .route("/api/summary", get(summary))
        .route_layer(middleware::from_fn_with_state(state.authz, require_gateway));
    Router::new().route("/", get(page)).route("/tools", get(tools)).merge(api).with_state(state)
}

#[tokio::main]
async fn main() -> Result<()> {
    let agent = osnt_common::http_agent("osnt-cidr-exposure/0.1 (+https://github.com/ogden-marrow/osnt-hub)");
    let min_prefix = env::var("OSNT_CIDR_EXPOSURE_MIN_PREFIX").ok().and_then(|v| v.parse().ok()).unwrap_or(24);
    let state: Shared = Arc::new(AppState::new(agent, real_authz, min_prefix));
    let addr: SocketAddr = env::var("OSNT_CIDR_EXPOSURE_BIND").unwrap_or_else(|_| "127.0.0.1:8137".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("cidr-exposure plugin on http://{addr}");
    axum::serve(listener, app(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests;

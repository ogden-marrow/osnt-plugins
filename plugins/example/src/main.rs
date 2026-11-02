//! Minimal OSNT plugin. Copy this crate, rename it, and see docs/PLUGINS.md.
//! The portal core proxies /p/<id>/ to this service, which must listen on loopback only.

use std::{env, net::SocketAddr};

use axum::{Json, Router, response::Html, routing::get};
use serde_json::{Value, json};

const PAGE: &str = include_str!("../assets/index.html");

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

async fn hello() -> Json<Value> {
    Json(json!({ "message": "hello from the example plugin" }))
}

/// Operations an agent can discover and call; paths are relative to /p/<id>/.
async fn tools() -> Json<Value> {
    Json(json!([{
        "name": "example_hello",
        "description": "Returns a greeting. Replace with your plugin's real operations.",
        "method": "GET",
        "path": "api/hello",
        "parameters": { "type": "object", "properties": {} }
    }]))
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(page))
        .route("/api/hello", get(hello))
        .route("/tools", get(tools));
    let addr: SocketAddr = env::var("OSNT_EXAMPLE_BIND").unwrap_or_else(|_| "127.0.0.1:8190".into()).parse().expect("bind addr");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("example plugin on http://{addr}");
    axum::serve(listener, app).await.expect("serve");
}

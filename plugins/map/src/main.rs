//! Map plugin: the world map with the layer catalog. Tiles stream from public services straight to the browser;
//! the page uses the portal's shared map kit (/static/osnt-map.js, layers from the portal's layers.toml).

use std::{env, net::SocketAddr};

use axum::{Json, Router, response::Html, routing::get};
use serde_json::{Value, json};

const PAGE: &str = include_str!("../assets/index.html");

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

async fn tools() -> Json<Value> {
    Json(json!([]))
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", get(page)).route("/tools", get(tools));
    let addr: SocketAddr = env::var("OSNT_MAP_BIND").unwrap_or_else(|_| "127.0.0.1:8107".into()).parse().expect("bind addr");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("map plugin on http://{addr}");
    axum::serve(listener, app).await.expect("serve");
}

#[cfg(test)]
mod tests {
    use super::PAGE;

    #[test]
    fn page_has_deep_links_and_health_failure_does_not_hide_the_map() {
        assert!(PAGE.contains("P.has('lat')") && PAGE.contains("P.get('q')"));
        // /api/health is best effort: it must not sit in the same try block as createMap.
        assert!(PAGE.contains("fetch('/api/health')") && PAGE.contains(".catch(() => {})"));
    }
}

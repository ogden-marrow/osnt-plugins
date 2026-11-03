//! Imagery timeline plugin. Frontend-only: tiles stream from NASA GIBS straight to the browser;
//! this service just serves the page and describes itself to the agent layer.

use std::{env, net::SocketAddr};

use axum::{Json, Router, response::Html, routing::get};
use serde_json::{Value, json};

const PAGE: &str = include_str!("../assets/index.html");

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

async fn tools() -> Json<Value> {
    // The imagery itself is browser-side tiles, so there is nothing for an agent to call yet.
    Json(json!([]))
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", get(page)).route("/tools", get(tools));
    let addr: SocketAddr = env::var("OSNT_IMAGERY_BIND").unwrap_or_else(|_| "127.0.0.1:8102".into()).parse().expect("bind addr");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("imagery plugin on http://{addr}");
    axum::serve(listener, app).await.expect("serve");
}

#[cfg(test)]
mod tests {
    use super::PAGE;

    #[test]
    fn fire_layer_uses_wms_because_gibs_only_has_vector_tiles_for_it() {
        // Regression: the 375 m thermal-anomaly layer has no PNG WMTS tiles (HTTP 400), so it must go through WMS.
        assert!(PAGE.contains("wms/epsg3857/best/wms.cgi"));
        assert!(!PAGE.contains("Thermal_Anomalies_375m_All', level"));
    }

    #[test]
    fn page_supports_deep_links() {
        for k in ["P.has('lat')", "dateOr('a'", "P.get('product')"] {
            assert!(PAGE.contains(k), "missing {k}");
        }
    }
}

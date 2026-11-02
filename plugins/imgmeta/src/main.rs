//! Image forensics plugin: hashes, format and size, EXIF (camera, timestamps, editing software, GPS)
//! and flags worth a closer look. Images are analysed in memory and never stored.

use std::{env, io::Cursor, net::SocketAddr};

use axum::{
    Json, Router,
    body::Bytes,
    extract::DefaultBodyLimit,
    http::StatusCode,
    response::Html,
    routing::{get, post},
};
use exif::{In, Tag, Value as ExifValue};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PAGE: &str = include_str!("../assets/index.html");
const MAX_BYTES: usize = 25 * 1024 * 1024;
const EDITORS: [&str; 8] = ["photoshop", "lightroom", "gimp", "affinity", "snapseed", "picsart", "canva", "pixelmator"];

fn sniff(b: &[u8]) -> &'static str {
    match b {
        [0xFF, 0xD8, 0xFF, ..] => "jpeg",
        [0x89, b'P', b'N', b'G', ..] => "png",
        [b'G', b'I', b'F', b'8', ..] => "gif",
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => "webp",
        [b'I', b'I', 0x2A, 0, ..] | [b'M', b'M', 0, 0x2A, ..] => "tiff",
        _ if b.len() > 12 && &b[4..8] == b"ftyp" => "heif/mp4-family",
        _ => "unknown",
    }
}

/// Degrees/minutes/seconds rationals plus N/S/E/W reference -> signed decimal degrees.
fn gps_coord(e: &exif::Exif, value: Tag, reference: Tag) -> Option<f64> {
    let ExifValue::Rational(r) = &e.get_field(value, In::PRIMARY)?.value else { return None };
    if r.len() < 3 {
        return None;
    }
    let deg = r[0].to_f64() + r[1].to_f64() / 60.0 + r[2].to_f64() / 3600.0;
    let sign = e.get_field(reference, In::PRIMARY).map(|f| f.display_value().to_string()).unwrap_or_default();
    Some(if sign.contains('S') || sign.contains('W') { -deg } else { deg })
}

fn analyze_bytes(data: &[u8]) -> Value {
    let sha256: String = Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect();
    let size = imagesize::blob_size(data).ok().map(|s| json!({ "width": s.width, "height": s.height }));
    let mut out = json!({ "bytes": data.len(), "sha256": sha256, "format": sniff(data), "dimensions": size });
    let mut flags: Vec<String> = Vec::new();

    match exif::Reader::new().read_from_container(&mut Cursor::new(data)) {
        Ok(e) => {
            let get = |t: Tag| e.get_field(t, In::PRIMARY).map(|f| f.display_value().with_unit(&e).to_string().trim_matches('"').to_string());
            let software = get(Tag::Software);
            let taken = get(Tag::DateTimeOriginal);
            let modified = get(Tag::DateTime);
            let (lat, lon) = (gps_coord(&e, Tag::GPSLatitude, Tag::GPSLatitudeRef), gps_coord(&e, Tag::GPSLongitude, Tag::GPSLongitudeRef));
            let gps = lat.zip(lon).map(|(la, lo)| json!({ "lat": la, "lon": lo, "altitude": get(Tag::GPSAltitude) }));

            if let Some(s) = &software {
                if EDITORS.iter().any(|ed| s.to_lowercase().contains(ed)) {
                    flags.push(format!("Processed by editing software: {s}"));
                }
            }
            if let (Some(t), Some(m)) = (&taken, &modified) {
                if t != m {
                    flags.push(format!("Capture time ({t}) differs from last-modified time ({m})"));
                }
            }
            if taken.is_none() {
                flags.push("No original capture timestamp".into());
            }
            if get(Tag::Make).is_none() && get(Tag::Model).is_none() {
                flags.push("No camera make/model recorded".into());
            }
            let fields: Vec<Value> = e.fields().map(|f| json!({ "tag": f.tag.to_string(), "value": f.display_value().with_unit(&e).to_string() })).collect();
            out["exif"] = json!({
                "make": get(Tag::Make), "model": get(Tag::Model), "software": software, "captured": taken, "modified": modified,
                "lens": get(Tag::LensModel), "gps": gps, "field_count": fields.len(), "fields": fields,
            });
        }
        Err(_) => {
            out["exif"] = Value::Null;
            flags.push("No EXIF metadata. Common after social-media upload or screenshots; it does not prove tampering.".into());
        }
    }
    out["flags"] = json!(flags);
    out
}

async fn analyze(body: Bytes) -> Result<Json<Value>, (StatusCode, String)> {
    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "empty body: POST the raw image bytes".into()));
    }
    let result = tokio::task::spawn_blocking(move || analyze_bytes(&body)).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(result))
}

async fn tools() -> Json<Value> {
    // Analysis takes raw image bytes, which does not fit the simple GET tool contract yet.
    Json(json!([]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/analyze", post(analyze))
        .layer(DefaultBodyLimit::max(MAX_BYTES));
    let addr: SocketAddr = env::var("OSNT_IMGMETA_BIND").unwrap_or_else(|_| "127.0.0.1:8104".into()).parse().expect("bind addr");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("imgmeta plugin on http://{addr}");
    axum::serve(listener, app).await.expect("serve");
}

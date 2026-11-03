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
    if sniff(data) == "unknown" {
        flags.push("This does not look like an image file (unrecognised header). Results below may be empty or meaningless.".into());
    }
    out["markers"] = json!(scan_markers(data, &mut flags));

    match exif::Reader::new().read_from_container(&mut Cursor::new(data)) {
        Ok(e) => {
            let get = |t: Tag| e.get_field(t, In::PRIMARY).map(|f| f.display_value().with_unit(&e).to_string().trim_matches('"').to_string());
            let software = get(Tag::Software);
            let taken = get(Tag::DateTimeOriginal);
            let modified = get(Tag::DateTime);
            let (lat, lon) = (gps_coord(&e, Tag::GPSLatitude, Tag::GPSLatitudeRef), gps_coord(&e, Tag::GPSLongitude, Tag::GPSLongitudeRef));
            let gps = lat.zip(lon).map(|(la, lo)| json!({ "lat": la, "lon": lo, "altitude": get(Tag::GPSAltitude) }));

            // EXIF records the original pixel size; a different actual size means the image was resized or cropped after capture.
            let exif_dim = |t: Tag| e.get_field(t, In::PRIMARY).and_then(|f| f.value.get_uint(0));
            if let (Some(ew), Some(eh), Some(sz)) = (exif_dim(Tag::PixelXDimension), exif_dim(Tag::PixelYDimension), imagesize::blob_size(data).ok()) {
                if (ew as usize, eh as usize) != (sz.width, sz.height) && (eh as usize, ew as usize) != (sz.width, sz.height) {
                    flags.push(format!("EXIF says the image is {ew} × {eh} but the file is {} × {}: it was resized or cropped after capture", sz.width, sz.height));
                }
            }
            if let Some(g) = &gps {
                let (la, lo) = (g["lat"].as_f64().unwrap_or(0.0), g["lon"].as_f64().unwrap_or(0.0));
                if la.abs() > 90.0 || lo.abs() > 180.0 {
                    flags.push("GPS coordinates are out of range: the location data is corrupt or was edited".into());
                } else {
                    flags.push("Contains a GPS location (check before sharing the file)".into());
                }
            }
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

/// Byte-level hints that survive even when EXIF is gone: Content Credentials, XMP edit history, data appended after a JPEG.
fn scan_markers(data: &[u8], flags: &mut Vec<String>) -> Vec<&'static str> {
    let has = |needle: &[u8]| data.windows(needle.len()).any(|w| w == needle);
    let mut found = Vec::new();
    if has(b"c2pa") || has(b"jumb") {
        found.push("C2PA / Content Credentials manifest");
        flags.push("Contains a C2PA (Content Credentials) manifest: validate it with a C2PA verifier; this tool only detects it".into());
    }
    if has(b"<x:xmpmeta") {
        found.push("XMP packet");
        if has(b"xmpMM:History") || has(b"stEvt:action") {
            found.push("XMP edit history");
            flags.push("XMP edit history is present: the file was saved by editing software".into());
        }
    }
    if has(b"ICC_PROFILE") {
        found.push("ICC colour profile");
    }
    if data.starts_with(&[0xFF, 0xD8]) {
        if let Some(end) = data.windows(2).rposition(|w| w == [0xFF, 0xD9]) {
            let tail = data.len() - (end + 2);
            if tail > 16 {
                found.push("data after JPEG end");
                flags.push(format!("{tail} bytes follow the end of the JPEG image data (an appended thumbnail, a trailer or hidden content)"));
            }
        }
    }
    found
}

fn err(code: StatusCode, msg: &str) -> (StatusCode, Json<Value>) {
    (code, Json(json!({ "error": msg })))
}

async fn analyze(body: Bytes) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if body.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "empty body: POST the raw image bytes"));
    }
    let result = tokio::task::spawn_blocking(move || analyze_bytes(&body)).await.map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    Ok(Json(result))
}

async fn too_large(req: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response {
    use axum::response::IntoResponse;
    let res = next.run(req).await;
    if res.status() == StatusCode::PAYLOAD_TOO_LARGE {
        return err(StatusCode::PAYLOAD_TOO_LARGE, "that file is larger than 25 MB").into_response();
    }
    res
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
        .layer(DefaultBodyLimit::max(MAX_BYTES))
        .layer(axum::middleware::from_fn(too_large));
    let addr: SocketAddr = env::var("OSNT_IMGMETA_BIND").unwrap_or_else(|_| "127.0.0.1:8104".into()).parse().expect("bind addr");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("imgmeta plugin on http://{addr}");
    axum::serve(listener, app).await.expect("serve");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny JPEG with an EXIF APP1 segment: little-endian TIFF, IFD0 with Make, Software and DateTime.
    fn jpeg_with_exif(software: &str, datetime: &str) -> Vec<u8> {
        fn ascii(tag: u16, text: &str, data_off: u32, blob: &mut Vec<u8>) -> Vec<u8> {
            let mut t = text.as_bytes().to_vec();
            t.push(0);
            let mut e = Vec::new();
            e.extend(tag.to_le_bytes());
            e.extend(2u16.to_le_bytes());
            e.extend((t.len() as u32).to_le_bytes());
            e.extend((data_off + blob.len() as u32).to_le_bytes());
            blob.extend(t);
            e
        }
        let n = 3u32;
        let data_off = 8 + 2 + n * 12 + 4;
        let mut blob = Vec::new();
        let mut entries = Vec::new();
        entries.extend(ascii(0x010F, "TestCam", data_off, &mut blob));
        entries.extend(ascii(0x0131, software, data_off, &mut blob));
        entries.extend(ascii(0x0132, datetime, data_off, &mut blob));
        let mut tiff = b"II*\0\x08\0\0\0".to_vec();
        tiff.extend((n as u16).to_le_bytes());
        tiff.extend(entries);
        tiff.extend(0u32.to_le_bytes());
        tiff.extend(blob);
        let mut app1 = b"Exif\0\0".to_vec();
        app1.extend(tiff);
        let mut j = vec![0xFF, 0xD8, 0xFF, 0xE1];
        j.extend(((app1.len() + 2) as u16).to_be_bytes());
        j.extend(app1);
        j.extend([0xFF, 0xD9]);
        j
    }

    #[test]
    fn exif_is_parsed_and_editor_flagged() {
        let v = analyze_bytes(&jpeg_with_exif("Adobe Photoshop 25", "2024:01:02 03:04:05"));
        assert_eq!(v["format"], "jpeg");
        assert_eq!(v["exif"]["make"], "TestCam");
        assert_eq!(v["exif"]["software"], "Adobe Photoshop 25");
        let flags = v["flags"].to_string();
        assert!(flags.contains("editing software"), "{flags}");
        assert!(flags.contains("No original capture timestamp"), "{flags}");
        assert_eq!(v["sha256"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn non_images_are_flagged_not_crashed() {
        let v = analyze_bytes(b"hello world, this is plain text");
        assert_eq!(v["format"], "unknown");
        assert!(v["flags"].to_string().contains("does not look like an image"));
        assert!(v["exif"].is_null());
    }

    #[test]
    fn markers_and_trailing_data() {
        let mut j = vec![0xFF, 0xD8, 0xFF, 0xD9];
        j.extend(b"c2pa manifest and then some more trailing bytes here");
        let mut flags = Vec::new();
        let found = scan_markers(&j, &mut flags);
        assert!(found.contains(&"C2PA / Content Credentials manifest"));
        assert!(found.contains(&"data after JPEG end"));
        assert_eq!(flags.len(), 2);
    }

    #[test]
    fn truncated_input_does_not_panic() {
        for n in 0..40 {
            let j = jpeg_with_exif("x", "2024:01:02 03:04:05");
            let _ = analyze_bytes(&j[..n.min(j.len())]);
        }
    }
}

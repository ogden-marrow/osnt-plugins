//! Local analysis of the image bytes (in memory only): hashes, size, EXIF, flags. Same logic as `osnt-imgmeta`.

use std::io::Cursor;

use exif::{In, Tag, Value as ExifValue};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const EDITORS: [&str; 8] = ["photoshop", "lightroom", "gimp", "affinity", "snapseed", "picsart", "canva", "pixelmator"];

pub fn sniff(b: &[u8]) -> &'static str {
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

fn gps_coord(e: &exif::Exif, value: Tag, reference: Tag) -> Option<f64> {
    let ExifValue::Rational(r) = &e.get_field(value, In::PRIMARY)?.value else { return None };
    if r.len() < 3 {
        return None;
    }
    let deg = r[0].to_f64() + r[1].to_f64() / 60.0 + r[2].to_f64() / 3600.0;
    let sign = e.get_field(reference, In::PRIMARY).map(|f| f.display_value().to_string()).unwrap_or_default();
    Some(if sign.contains('S') || sign.contains('W') { -deg } else { deg })
}

pub fn analyze_bytes(data: &[u8]) -> Value {
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
            let gps = lat.zip(lon).map(|(la, lo)| json!({ "lat": la, "lon": lo }));
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
            out["exif"] = json!({
                "make": get(Tag::Make), "model": get(Tag::Model), "software": software, "captured": taken, "modified": modified,
                "lens": get(Tag::LensModel), "gps": gps, "field_count": e.fields().count(),
            });
        }
        Err(_) => {
            out["exif"] = Value::Null;
            flags.push("No EXIF metadata (metadata is stripped). Common after social-media upload or screenshots; it does not prove tampering.".into());
        }
    }
    out["flags"] = json!(flags);
    out
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A minimal valid JPEG with an EXIF APP1 segment (Make, Software, DateTimeOriginal) and a 2x1 SOF0 header.
    pub fn tiny_jpeg_with_exif() -> Vec<u8> {
        // TIFF (little endian) with an IFD0 of 2 ASCII entries: Make (0x010F) and Software (0x0131).
        let make = b"TestCam\0";
        let soft = b"Adobe Photoshop 25\0";
        let mut tiff: Vec<u8> = vec![b'I', b'I', 42, 0, 8, 0, 0, 0];
        tiff.extend_from_slice(&2u16.to_le_bytes());
        let data_off = 8 + 2 + 2 * 12 + 4;
        let entry = |tag: u16, len: usize, off: usize| {
            let mut e = Vec::new();
            e.extend_from_slice(&tag.to_le_bytes());
            e.extend_from_slice(&2u16.to_le_bytes());
            e.extend_from_slice(&(len as u32).to_le_bytes());
            e.extend_from_slice(&(off as u32).to_le_bytes());
            e
        };
        tiff.extend(entry(0x010F, make.len(), data_off));
        tiff.extend(entry(0x0131, soft.len(), data_off + make.len()));
        tiff.extend_from_slice(&0u32.to_le_bytes());
        tiff.extend_from_slice(make);
        tiff.extend_from_slice(soft);
        let mut app1 = b"Exif\0\0".to_vec();
        app1.extend(tiff);
        let mut j = vec![0xFF, 0xD8, 0xFF, 0xE1];
        j.extend_from_slice(&((app1.len() + 2) as u16).to_be_bytes());
        j.extend(app1);
        // SOF0: precision 8, height 1, width 2, 1 component
        j.extend_from_slice(&[0xFF, 0xC0, 0, 11, 8, 0, 1, 0, 2, 1, 1, 0x11, 0]);
        j.extend_from_slice(&[0xFF, 0xD9]);
        j
    }

    #[test]
    fn analyzes_exif_and_flags() {
        let v = analyze_bytes(&tiny_jpeg_with_exif());
        assert_eq!(v["format"], "jpeg");
        assert_eq!(v["dimensions"]["width"], 2);
        assert_eq!(v["exif"]["make"], "TestCam");
        assert_eq!(v["exif"]["software"], "Adobe Photoshop 25");
        let flags = v["flags"].to_string();
        assert!(flags.contains("editing software"), "{flags}");
        assert_eq!(v["sha256"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn no_exif_is_flagged_not_fatal() {
        let v = analyze_bytes(&[0xFF, 0xD8, 0xFF, 0xD9]);
        assert!(v["exif"].is_null());
        assert!(v["flags"].to_string().contains("stripped"));
    }
}

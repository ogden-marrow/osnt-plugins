//! Perceptual hashes (average, difference, DCT), near-duplicate comparison, a difference heatmap and error-level
//! analysis. These compare whole images; nothing here detects, recognises or matches people.

use std::io::Cursor;

use base64::Engine;
use image::{DynamicImage, GenericImageView, ImageFormat, imageops::FilterType};
use serde_json::{Value, json};

pub const MAX_DIM: u32 = 12_000;

pub fn decode(bytes: &[u8]) -> Result<DynamicImage, String> {
    let mut r = image::ImageReader::new(Cursor::new(bytes)).with_guessed_format().map_err(|e| e.to_string())?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_DIM);
    limits.max_image_height = Some(MAX_DIM);
    limits.max_alloc = Some(300 * 1024 * 1024);
    r.limits(limits);
    r.decode().map_err(|e| format!("could not decode the image ({e}). Supported: JPEG, PNG, WebP, GIF"))
}

fn gray(img: &DynamicImage, w: u32, h: u32) -> Vec<f64> {
    img.resize_exact(w, h, FilterType::Triangle).to_luma8().pixels().map(|p| p.0[0] as f64).collect()
}

pub fn ahash(img: &DynamicImage) -> u64 {
    let g = gray(img, 8, 8);
    let mean = g.iter().sum::<f64>() / 64.0;
    g.iter().enumerate().fold(0u64, |h, (i, v)| if *v > mean { h | 1 << i } else { h })
}

pub fn dhash(img: &DynamicImage) -> u64 {
    let g = gray(img, 9, 8);
    let mut h = 0u64;
    for y in 0..8 {
        for x in 0..8 {
            if g[y * 9 + x] > g[y * 9 + x + 1] {
                h |= 1 << (y * 8 + x);
            }
        }
    }
    h
}

pub fn phash(img: &DynamicImage) -> u64 {
    const N: usize = 32;
    let g = gray(img, N as u32, N as u32);
    let cos: Vec<f64> = (0..8).flat_map(|u| (0..N).map(move |x| ((2 * x + 1) as f64 * u as f64 * std::f64::consts::PI / (2.0 * N as f64)).cos())).collect();
    // rows then columns, keeping only the 8x8 low frequencies
    let mut tmp = [[0f64; 8]; N];
    for y in 0..N {
        for u in 0..8 {
            tmp[y][u] = (0..N).map(|x| g[y * N + x] * cos[u * N + x]).sum();
        }
    }
    let mut d = [0f64; 64];
    for v in 0..8 {
        for u in 0..8 {
            d[v * 8 + u] = (0..N).map(|y| tmp[y][u] * cos[v * N + y]).sum();
        }
    }
    let mut rest: Vec<f64> = d[1..].to_vec();
    rest.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = (rest[31] + rest[32]) / 2.0;
    d.iter().enumerate().fold(0u64, |h, (i, v)| if *v > median { h | 1 << i } else { h })
}

pub fn hex(h: u64) -> String {
    format!("{h:016x}")
}

pub fn ham(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

pub fn hashes(img: &DynamicImage) -> Value {
    json!({ "phash": hex(phash(img)), "dhash": hex(dhash(img)), "ahash": hex(ahash(img)) })
}

pub fn verdict(phash_distance: u32) -> &'static str {
    match phash_distance {
        0..=4 => "near-identical",
        5..=10 => "similar",
        _ => "different",
    }
}

fn png_data_uri(img: &DynamicImage) -> String {
    let mut buf = Cursor::new(Vec::new());
    img.write_to(&mut buf, ImageFormat::Png).expect("png encode");
    format!("data:image/png;base64,{}", base64::engine::general_purpose::STANDARD.encode(buf.into_inner()))
}

/// Compare two images: hash distances, a verdict, whether the second looks like a mirrored copy of the first,
/// a mean pixel difference after normalising size, and a heatmap of where they differ.
pub fn compare(a: &DynamicImage, b: &DynamicImage) -> Value {
    let (pa, pb) = (phash(a), phash(b));
    let d = ham(pa, pb);
    let flipped = ham(pa, phash(&b.fliph()));
    let (da, db) = (ham(dhash(a), dhash(b)), ham(ahash(a), ahash(b)));
    let (ga, gb) = (gray(a, 128, 128), gray(b, 128, 128));
    let diffs: Vec<f64> = ga.iter().zip(&gb).map(|(x, y)| (x - y).abs()).collect();
    let mean = diffs.iter().sum::<f64>() / diffs.len() as f64;
    let heat = DynamicImage::ImageLuma8(image::GrayImage::from_fn(128, 128, |x, y| image::Luma([(diffs[(y * 128 + x) as usize] * 3.0).min(255.0) as u8])));
    let (aw, ah) = a.dimensions();
    let (bw, bh) = b.dimensions();
    let ratio_a = aw as f64 / ah as f64;
    let ratio_b = bw as f64 / bh as f64;
    let mut notes = Vec::new();
    if (ratio_a - ratio_b).abs() > 0.03 {
        notes.push("The aspect ratios differ, so one image may be a crop or have been re-framed. Hash comparison assumes similar framing.");
    }
    if flipped + 4 < d && flipped <= 10 {
        notes.push("The second image matches the first when mirrored horizontally.");
    }
    notes.push("Perceptual hashes find copies and re-encodes of the same picture. They cannot prove which came first, and a heavy crop or overlay can defeat them.");
    json!({
        "a": { "width": aw, "height": ah, "hashes": hashes(a) }, "b": { "width": bw, "height": bh, "hashes": hashes(b) },
        "distance": { "phash": d, "dhash": da, "ahash": db, "phash_mirrored": flipped, "max": 64 },
        "verdict": verdict(d.min(flipped)), "mirrored_match": flipped + 4 < d && flipped <= 10,
        "mean_pixel_difference_percent": (mean / 255.0 * 1000.0).round() / 10.0,
        "heatmap": png_data_uri(&heat), "notes": notes,
    })
}

/// Error level analysis: recompress as JPEG at quality 90 and amplify the per-pixel difference. Regions that were
/// edited or pasted from another source often recompress differently from their surroundings. It is a heuristic with
/// many false positives (sharp edges, text, previously recompressed images), never proof of manipulation.
pub fn ela(img: &DynamicImage) -> Result<Value, String> {
    let img = if img.width() > 1600 || img.height() > 1600 { img.resize(1600, 1600, FilterType::Triangle) } else { img.clone() };
    let rgb = DynamicImage::ImageRgb8(img.to_rgb8());
    let mut buf = Cursor::new(Vec::new());
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut buf, 90).encode_image(&rgb).map_err(|e| e.to_string())?;
    let re = image::load_from_memory_with_format(buf.get_ref(), ImageFormat::Jpeg).map_err(|e| e.to_string())?.to_rgb8();
    let orig = rgb.to_rgb8();
    let mut max = 0u8;
    let mut sum = 0u64;
    let out = image::RgbImage::from_fn(orig.width(), orig.height(), |x, y| {
        let (p, q) = (orig.get_pixel(x, y).0, re.get_pixel(x, y).0);
        let mut o = [0u8; 3];
        for i in 0..3 {
            let d = p[i].abs_diff(q[i]);
            max = max.max(d);
            sum += d as u64;
            o[i] = (d as u32 * 20).min(255) as u8;
        }
        image::Rgb(o)
    });
    let mean = sum as f64 / (orig.width() as f64 * orig.height() as f64 * 3.0);
    Ok(json!({
        "image": png_data_uri(&DynamicImage::ImageRgb8(out)), "max_error": max, "mean_error": (mean * 100.0).round() / 100.0, "quality": 90, "scale": 20,
        "caveat": "Bright areas recompress differently from the rest of the picture. That can come from edits, but also from sharp edges, text, noise or earlier recompression. Treat it as a pointer for closer inspection, not as proof.",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{Rgb, RgbImage};

    fn scene(w: u32, h: u32, seed: u32) -> DynamicImage {
        DynamicImage::ImageRgb8(RgbImage::from_fn(w, h, |x, y| {
            let fx = x as f64 / w as f64;
            let fy = y as f64 / h as f64;
            let v = ((fx * 6.0 + seed as f64).sin() * 60.0 + (fy * 4.0 * (seed as f64 + 1.0)).cos() * 60.0 + 128.0) as u8;
            let blob = if (fx - 0.3 - seed as f64 * 0.1).abs() < 0.15 && (fy - 0.5).abs() < 0.2 { 90 } else { 0 };
            Rgb([v.saturating_add(blob), v / 2 + blob / 2, 255 - v])
        }))
    }

    #[test]
    fn identical_resized_and_recompressed_copies_are_near_identical() {
        let a = scene(400, 300, 1);
        let small = a.resize_exact(160, 120, FilterType::Triangle);
        assert!(ham(phash(&a), phash(&small)) <= 4, "{}", ham(phash(&a), phash(&small)));
        let mut buf = Cursor::new(Vec::new());
        a.write_to(&mut buf, ImageFormat::Jpeg).unwrap();
        let re = decode(buf.get_ref()).unwrap();
        let c = compare(&a, &re);
        assert_eq!(c["verdict"], "near-identical");
        assert!(c["mean_pixel_difference_percent"].as_f64().unwrap() < 3.0);
        assert!(c["heatmap"].as_str().unwrap().starts_with("data:image/png;base64,"));
    }

    #[test]
    fn different_scenes_are_different_and_mirrors_are_noticed() {
        let a = scene(300, 300, 1);
        let b = scene(300, 300, 4);
        assert_eq!(compare(&a, &b)["verdict"], "different");
        let m = compare(&a, &a.fliph());
        assert_eq!(m["verdict"], "near-identical");
        assert!(ham(phash(&a), phash(&a.fliph())) > 4, "scene must be asymmetric for this test");
        assert_eq!(m["mirrored_match"], true);
    }

    #[test]
    fn hash_basics() {
        let a = scene(64, 64, 2);
        assert_eq!(phash(&a), phash(&a.clone()));
        assert_eq!(ham(0, u64::MAX), 64);
        assert_eq!(hex(255), "00000000000000ff");
        assert_eq!(verdict(0), "near-identical");
        assert_eq!(verdict(7), "similar");
        assert_eq!(verdict(30), "different");
        // flat images do not panic
        let flat = DynamicImage::ImageRgb8(RgbImage::from_pixel(10, 10, Rgb([5, 5, 5])));
        let _ = hashes(&flat);
    }

    #[test]
    fn ela_runs_and_reports() {
        let r = ela(&scene(120, 90, 3)).unwrap();
        assert!(r["image"].as_str().unwrap().starts_with("data:image/png"));
        assert!(r["max_error"].as_u64().is_some());
        assert!(r["caveat"].as_str().unwrap().contains("not as proof"));
    }

    #[test]
    fn decode_rejects_garbage_and_huge_dimensions() {
        assert!(decode(b"not an image").is_err());
        assert!(decode(&[]).is_err());
        // PNG header declaring 20000x20000
        let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, b'I', b'H', b'D', b'R'];
        png.extend_from_slice(&20000u32.to_be_bytes());
        png.extend_from_slice(&20000u32.to_be_bytes());
        png.extend_from_slice(&[8, 2, 0, 0, 0, 0, 0, 0, 0]);
        assert!(decode(&png).is_err());
    }
}

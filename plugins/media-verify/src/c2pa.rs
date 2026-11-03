//! A small pure-Rust reader for C2PA / Content Credentials manifests. It locates the JUMBF manifest store in JPEG,
//! PNG and ISO-BMFF files (MP4, MOV, HEIC, AVIF), walks the boxes and reports who claims to have made or edited the
//! file. It does NOT verify signatures, certificate trust or hard bindings (the official c2pa crate needs C code and
//! does not build for this hub). Treat the output as "what the file says about itself", never as proof.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MAX_DEPTH: usize = 8;
const MAX_BOXES: usize = 4000;

#[derive(Debug, Clone, Default)]
pub struct JBox {
    pub kind: String,
    pub label: String,
    pub children: Vec<JBox>,
    /// Payload of leaf boxes (cbor / json / binary), capped.
    pub data: Vec<u8>,
}

// ---- locating the manifest store ----------------------------------------------------------------

fn be32(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(i..i + 4)?.try_into().ok()?))
}

/// JPEG: APP11 (0xFFEB) segments with the "JP" common identifier carry JUMBF, split across numbered segments.
pub fn from_jpeg(b: &[u8]) -> Option<Vec<u8>> {
    if b.get(0..2)? != [0xFF, 0xD8] {
        return None;
    }
    let mut i = 2;
    let mut store: Vec<u8> = Vec::new();
    let mut first = true;
    while i + 4 <= b.len() {
        if b[i] != 0xFF {
            break;
        }
        let marker = b[i + 1];
        if marker == 0xD8 || marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            i += 2;
            continue;
        }
        if marker == 0xDA || marker == 0xD9 {
            break;
        }
        let len = u16::from_be_bytes([b[i + 2], b[i + 3]]) as usize;
        if len < 2 || i + 2 + len > b.len() {
            break;
        }
        let seg = &b[i + 4..i + 2 + len];
        if marker == 0xEB && seg.len() >= 8 && &seg[0..2] == b"JP" {
            let body = &seg[8..]; // "JP", En (2), Z (4)
            if first {
                store.extend_from_slice(body);
                first = false;
            } else if body.len() >= 8 {
                store.extend_from_slice(&body[8..]); // continuation segments repeat the box header
            }
            if store.len() > 32 * 1024 * 1024 {
                return None;
            }
        }
        i += 2 + len;
    }
    (!store.is_empty()).then_some(store)
}

/// PNG: the `caBX` chunk holds the store.
pub fn from_png(b: &[u8]) -> Option<Vec<u8>> {
    if b.get(0..8)? != [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A] {
        return None;
    }
    let mut i = 8;
    while i + 12 <= b.len() {
        let len = be32(b, i)? as usize;
        let kind = &b[i + 4..i + 8];
        if kind == b"caBX" {
            return b.get(i + 8..i + 8 + len).map(<[u8]>::to_vec);
        }
        i += 12 + len;
    }
    None
}

/// C2PA UUID in ISO-BMFF `uuid` boxes.
pub const C2PA_UUID: [u8; 16] = [0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c, 0x92, 0x97, 0x58, 0x28, 0x87, 0x7e, 0xc4, 0x81];

/// Payload of a top-level C2PA `uuid` box, given its content (after the 16-byte UUID).
pub fn bmff_payload(content: &[u8]) -> Option<Vec<u8>> {
    // version/flags (4), purpose string "manifest\0", then (v1) a merkle offset and the JUMBF; find the superbox itself.
    let pos = content.windows(4).position(|w| w == b"jumb").filter(|p| *p >= 4)?;
    Some(content[pos - 4..].to_vec())
}

pub fn from_bmff(b: &[u8]) -> Option<Vec<u8>> {
    if b.len() < 12 || &b[4..8] != b"ftyp" {
        return None;
    }
    let mut i = 0usize;
    while i + 8 <= b.len() {
        let mut size = be32(b, i)? as usize;
        let kind = &b[i + 4..i + 8];
        let mut head = 8;
        if size == 1 {
            size = u64::from_be_bytes(b.get(i + 8..i + 16)?.try_into().ok()?) as usize;
            head = 16;
        } else if size == 0 {
            size = b.len() - i;
        }
        if size < head || i + size > b.len() {
            break;
        }
        if kind == b"uuid" && b.get(i + head..i + head + 16)? == C2PA_UUID {
            return bmff_payload(&b[i + head + 16..i + size]);
        }
        i += size;
    }
    None
}

pub fn extract(b: &[u8]) -> Option<Vec<u8>> {
    from_jpeg(b).or_else(|| from_png(b)).or_else(|| from_bmff(b))
}

/// For large video files: read only the top-level boxes of a file and return the C2PA uuid payload if present.
pub fn from_bmff_file(path: &std::path::Path) -> Option<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let mut head = [0u8; 16];
    f.read_exact(&mut head[..12]).ok()?;
    if &head[4..8] != b"ftyp" {
        return None;
    }
    let mut pos = 0u64;
    for _ in 0..2000 {
        if pos + 8 > len {
            break;
        }
        f.seek(SeekFrom::Start(pos)).ok()?;
        f.read_exact(&mut head[..8]).ok()?;
        let mut size = u32::from_be_bytes(head[0..4].try_into().ok()?) as u64;
        let kind: [u8; 4] = head[4..8].try_into().ok()?;
        let mut hl = 8;
        if size == 1 {
            f.read_exact(&mut head[..8]).ok()?;
            size = u64::from_be_bytes(head[..8].try_into().ok()?);
            hl = 16;
        } else if size == 0 {
            size = len - pos;
        }
        if size < hl || pos + size > len {
            break;
        }
        if &kind == b"uuid" && size <= 32 * 1024 * 1024 {
            let mut buf = vec![0u8; (size - hl) as usize];
            f.seek(SeekFrom::Start(pos + hl)).ok()?;
            f.read_exact(&mut buf).ok()?;
            if buf.len() > 16 && buf[..16] == C2PA_UUID {
                return bmff_payload(&buf[16..]);
            }
        }
        pos += size;
    }
    None
}

// ---- JUMBF boxes ---------------------------------------------------------------------------------

fn parse_boxes(b: &[u8], depth: usize, count: &mut usize) -> Vec<JBox> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 8 <= b.len() && *count < MAX_BOXES {
        *count += 1;
        let mut size = be32(b, i).unwrap_or(0) as usize;
        let kind = String::from_utf8_lossy(&b[i + 4..i + 8]).to_string();
        let mut head = 8;
        if size == 1 {
            let Some(x) = b.get(i + 8..i + 16) else { break };
            size = u64::from_be_bytes(x.try_into().unwrap()) as usize;
            head = 16;
        } else if size == 0 {
            size = b.len() - i;
        }
        if size < head || i + size > b.len() {
            break;
        }
        let payload = &b[i + head..i + size];
        let mut node = JBox { kind: kind.clone(), ..Default::default() };
        if kind == "jumb" && depth < MAX_DEPTH {
            let mut kids = parse_boxes(payload, depth + 1, count);
            if let Some(pos) = kids.iter().position(|k| k.kind == "jumd") {
                node.label = std::mem::take(&mut kids[pos].label);
                kids.remove(pos);
            }
            node.children = kids;
        } else if kind == "jumd" {
            // 16-byte content type, 1 byte toggles, then a null-terminated label when bit 1 is set
            if payload.len() > 17 && payload[16] & 0x02 != 0 {
                let l = &payload[17..];
                node.label = String::from_utf8_lossy(&l[..l.iter().position(|c| *c == 0).unwrap_or(l.len())]).to_string();
            }
        } else {
            node.data = payload.iter().take(1024 * 1024).copied().collect();
        }
        out.push(node);
        i += size;
    }
    out
}

pub fn parse_jumbf(b: &[u8]) -> Vec<JBox> {
    let mut count = 0;
    parse_boxes(b, 0, &mut count)
}

// ---- CBOR helpers --------------------------------------------------------------------------------

fn cbor(data: &[u8]) -> Option<ciborium::Value> {
    ciborium::de::from_reader(data).ok()
}

fn key<'a>(v: &'a ciborium::Value, name: &str) -> Option<&'a ciborium::Value> {
    v.as_map()?.iter().find(|(k, _)| k.as_text() == Some(name)).map(|(_, v)| v)
}

fn text(v: Option<&ciborium::Value>) -> Option<String> {
    v?.as_text().map(|s| s.chars().take(300).collect())
}

fn content_of(b: &JBox) -> Option<ciborium::Value> {
    b.children.iter().find(|c| c.kind == "cbor").and_then(|c| cbor(&c.data)).or_else(|| b.children.iter().find(|c| c.kind == "json").and_then(|c| serde_json::from_slice::<serde_json::Value>(&c.data).ok()).and_then(|j| ciborium::Value::serialized(&j).ok()))
}

// ---- minimal DER (just enough to name the signing certificate) ------------------------------------

fn der(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let l0 = *b.get(1)? as usize;
    let (len, off) = if l0 < 0x80 {
        (l0, 2)
    } else {
        let n = l0 & 0x7f;
        if n == 0 || n > 3 {
            return None;
        }
        (b.get(2..2 + n)?.iter().fold(0usize, |a, x| a << 8 | *x as usize), 2 + n)
    };
    Some((tag, b.get(off..off + len)?, b.get(off + len..)?))
}

fn name_of(mut rdns: &[u8]) -> String {
    let mut parts = Vec::new();
    while let Some((_, set, rest)) = der(rdns) {
        if let Some((_, atv, _)) = der(set) {
            if let Some((_, oid, after)) = der(atv) {
                if let Some((_, val, _)) = der(after) {
                    let label = match oid {
                        [0x55, 0x04, 0x03] => Some("CN"),
                        [0x55, 0x04, 0x0a] => Some("O"),
                        [0x55, 0x04, 0x06] => Some("C"),
                        _ => None,
                    };
                    if let (Some(l), Ok(s)) = (label, std::str::from_utf8(val)) {
                        parts.push(format!("{l}={}", s.chars().take(100).collect::<String>()));
                    }
                }
            }
        }
        rdns = rest;
    }
    parts.join(", ")
}

/// Issuer and subject names (CN, O, C only) of a DER certificate.
pub fn cert_names(cert: &[u8]) -> Option<(String, String)> {
    let (_, cert_body, _) = der(cert)?;
    let (_, mut tbs, _) = der(cert_body)?;
    let mut fields = Vec::new();
    while let Some((tag, body, rest)) = der(tbs) {
        fields.push((tag, body));
        tbs = rest;
    }
    // [0] version (optional), serial, sigalg, issuer, validity, subject
    let off = if fields.first().is_some_and(|f| f.0 == 0xa0) { 1 } else { 0 };
    let issuer = fields.get(off + 2)?.1;
    let subject = fields.get(off + 4)?.1;
    Some((name_of(issuer), name_of(subject)))
}

fn cose_alg(n: i64) -> String {
    match n {
        -7 => "ES256".into(),
        -35 => "ES384".into(),
        -36 => "ES512".into(),
        -37 => "PS256".into(),
        -38 => "PS384".into(),
        -39 => "PS512".into(),
        -8 => "EdDSA".into(),
        o => format!("COSE {o}"),
    }
}

// ---- analysis ------------------------------------------------------------------------------------

fn ai_source(s: &str) -> bool {
    let t = s.to_ascii_lowercase();
    t.contains("trainedalgorithmicmedia") || t.ends_with("/algorithmicmedia") || t.contains("compositewithtrainedalgorithmicmedia")
}

fn analyse_manifest(m: &JBox, active: bool) -> Value {
    let mut assertion_labels = Vec::new();
    let mut actions = Vec::new();
    let mut ai = false;
    let mut ingredients = 0;
    if let Some(store) = m.children.iter().find(|c| c.label == "c2pa.assertions") {
        for a in &store.children {
            assertion_labels.push(a.label.clone());
            if a.label.starts_with("c2pa.ingredient") {
                ingredients += 1;
            }
            if a.label.starts_with("c2pa.actions") {
                if let Some(c) = content_of(a) {
                    for act in key(&c, "actions").and_then(|x| x.as_array()).into_iter().flatten() {
                        let dst = text(key(act, "digitalSourceType")).or_else(|| text(key(key(act, "parameters").unwrap_or(&ciborium::Value::Null), "digitalSourceType")));
                        if dst.as_deref().is_some_and(ai_source) {
                            ai = true;
                        }
                        let agent = text(key(act, "softwareAgent")).or_else(|| key(act, "softwareAgent").and_then(|s| text(key(s, "name"))));
                        actions.push(json!({ "action": text(key(act, "action")), "software_agent": agent, "digital_source_type": dst, "when": text(key(act, "when")) }));
                    }
                }
            }
        }
    }
    let claim = m.children.iter().find(|c| c.label.starts_with("c2pa.claim")).and_then(content_of);
    let generator = claim.as_ref().and_then(|c| text(key(c, "claim_generator")).or_else(|| key(c, "claim_generator_info").and_then(|g| g.as_array().and_then(|a| a.first()).or(Some(g)).and_then(|g| text(key(g, "name"))))));
    let mut sig = json!(null);
    if let Some(s) = m.children.iter().find(|c| c.label == "c2pa.signature") {
        if let Some(cose) = s.children.iter().find(|c| c.kind == "cbor").and_then(|c| cbor(&c.data)) {
            // COSE_Sign1 may be wrapped in tag 18
            let arr = match &cose {
                ciborium::Value::Tag(_, inner) => inner.as_array().cloned(),
                v => v.as_array().cloned(),
            };
            if let Some(arr) = arr {
                let alg = arr.first().and_then(|p| p.as_bytes()).and_then(|p| cbor(p)).and_then(|m| m.as_map().and_then(|m| m.iter().find(|(k, _)| k.as_integer().map(i128::from) == Some(1)).and_then(|(_, v)| v.as_integer().map(i128::from)))).map(|n| cose_alg(n as i64));
                let chain: Vec<Vec<u8>> = arr.get(1).and_then(|u| u.as_map()).and_then(|m| m.iter().find(|(k, _)| k.as_integer().map(i128::from) == Some(33)).map(|(_, v)| v)).map(|v| match v {
                    ciborium::Value::Array(a) => a.iter().filter_map(|x| x.as_bytes().cloned()).collect(),
                    ciborium::Value::Bytes(b) => vec![b.clone()],
                    _ => vec![],
                }).unwrap_or_default();
                let (issuer, subject) = chain.first().and_then(|c| cert_names(c)).unwrap_or_default();
                sig = json!({
                    "algorithm": alg, "certificates": chain.len(),
                    "signer_subject": (!subject.is_empty()).then_some(subject), "signer_issuer": (!issuer.is_empty()).then_some(issuer),
                    "leaf_sha256": chain.first().map(|c| Sha256::digest(c).iter().map(|b| format!("{b:02x}")).collect::<String>()),
                });
            }
        }
    }
    json!({
        "label": m.label, "active": active, "claim_generator": generator, "title": claim.as_ref().and_then(|c| text(key(c, "dc:title"))),
        "format": claim.as_ref().and_then(|c| text(key(c, "dc:format"))), "assertions": assertion_labels, "actions": actions, "ingredients": ingredients,
        "ai_generated_declared": ai, "signature": sig,
    })
}

/// Analyse a raw JUMBF manifest store.
pub fn analyse(jumbf: &[u8]) -> Value {
    let roots = parse_jumbf(jumbf);
    let Some(store) = roots.iter().find(|r| r.kind == "jumb" && r.label == "c2pa").or_else(|| roots.iter().find(|r| r.kind == "jumb")) else {
        return json!({ "present": true, "readable": false, "note": "A manifest container was found but could not be parsed." });
    };
    let manifests: Vec<&JBox> = store.children.iter().filter(|c| c.kind == "jumb").collect();
    let n = manifests.len();
    let out: Vec<Value> = manifests.iter().enumerate().map(|(i, m)| analyse_manifest(m, i + 1 == n)).collect();
    let ai = out.iter().any(|m| m["ai_generated_declared"] == true);
    json!({
        "present": true, "readable": true, "manifest_count": n, "manifests": out, "ai_generated_declared": ai,
        "validated": false,
        "note": "Signatures, certificate trust and the binding to the pixels were NOT checked. This shows what the file claims about itself. Use the official Content Credentials verifier for validation.",
    })
}

/// Look for Content Credentials in an in-memory file.
pub fn scan(bytes: &[u8]) -> Value {
    match extract(bytes) {
        Some(j) => analyse(&j),
        None => json!({ "present": false, "note": "No Content Credentials found. Most files carry none, and social platforms usually strip them, so this says nothing about authenticity." }),
    }
}

/// Look for Content Credentials in a video/ISO-BMFF file on disk without loading it.
pub fn scan_file(path: &std::path::Path) -> Value {
    match from_bmff_file(path) {
        Some(j) => analyse(&j),
        None => json!({ "present": false, "note": "No Content Credentials found in the top-level boxes. Most files carry none, and platforms usually strip them." }),
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn jbox(kind: &str, payload: &[u8]) -> Vec<u8> {
        let mut v = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
        v.extend_from_slice(kind.as_bytes());
        v.extend_from_slice(payload);
        v
    }
    pub fn jumb(label: &str, children: &[Vec<u8>]) -> Vec<u8> {
        let mut d = vec![0u8; 16];
        d.push(0x03);
        d.extend_from_slice(label.as_bytes());
        d.push(0);
        let mut body = jbox("jumd", &d);
        for c in children {
            body.extend_from_slice(c);
        }
        jbox("jumb", &body)
    }
    pub fn cbor_box(v: &ciborium::Value) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(v, &mut out).unwrap();
        jbox("cbor", &out)
    }
    fn t(s: &str) -> ciborium::Value {
        ciborium::Value::Text(s.into())
    }
    fn map(kv: Vec<(&str, ciborium::Value)>) -> ciborium::Value {
        ciborium::Value::Map(kv.into_iter().map(|(k, v)| (t(k), v)).collect())
    }
    /// A synthetic manifest store: one manifest created by a generative tool, with a fake signature block.
    pub fn sample_store(ai: bool) -> Vec<u8> {
        let actions = map(vec![("actions", ciborium::Value::Array(vec![map(vec![
            ("action", t("c2pa.created")),
            ("softwareAgent", t("ExampleGen 2.1")),
            ("digitalSourceType", t(if ai { "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia" } else { "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture" })),
            ("when", t("2024-05-01T10:00:00Z")),
        ])]))]);
        let claim = map(vec![("claim_generator", t("ExampleGen/2.1")), ("dc:title", t("sunset.jpg")), ("dc:format", t("image/jpeg"))]);
        // minimal certificate: SEQ { SEQ { [0] ver, serial, sigalg, issuer, validity, subject } }
        let name = |o: &[u8], v: &str| -> Vec<u8> {
            let atv = [vec![0x06, o.len() as u8], o.to_vec(), vec![0x0c, v.len() as u8], v.as_bytes().to_vec()].concat();
            let atv = [vec![0x30, atv.len() as u8], atv].concat();
            let set = [vec![0x31, atv.len() as u8], atv].concat();
            [vec![0x30, set.len() as u8], set].concat()
        };
        let issuer = name(&[0x55, 0x04, 0x0a], "Example CA");
        let subject = name(&[0x55, 0x04, 0x0a], "Example Studio");
        let tbs_body = [vec![0xa0, 3, 0x02, 1, 2], vec![0x02, 1, 7], vec![0x30, 0], issuer, vec![0x30, 0], subject].concat();
        let tbs = [vec![0x30, tbs_body.len() as u8], tbs_body].concat();
        let cert = [vec![0x30, tbs.len() as u8], tbs].concat();
        let mut prot = Vec::new();
        ciborium::ser::into_writer(&ciborium::Value::Map(vec![(ciborium::Value::Integer(1.into()), ciborium::Value::Integer((-7).into()))]), &mut prot).unwrap();
        let cose = ciborium::Value::Tag(18, Box::new(ciborium::Value::Array(vec![
            ciborium::Value::Bytes(prot),
            ciborium::Value::Map(vec![(ciborium::Value::Integer(33.into()), ciborium::Value::Array(vec![ciborium::Value::Bytes(cert)]))]),
            ciborium::Value::Null,
            ciborium::Value::Bytes(vec![0; 64]),
        ])));
        let manifest = jumb("urn:uuid:1234", &[
            jumb("c2pa.assertions", &[jumb("c2pa.actions.v2", &[cbor_box(&actions)]), jumb("c2pa.hash.data", &[cbor_box(&map(vec![("alg", t("sha256"))]))])]),
            jumb("c2pa.claim.v2", &[cbor_box(&claim)]),
            jumb("c2pa.signature", &[cbor_box(&cose)]),
        ]);
        jumb("c2pa", &[manifest])
    }

    pub fn jpeg_with(store: &[u8], split: usize) -> Vec<u8> {
        let mut out = vec![0xFF, 0xD8];
        let header = &store[..8];
        for (z, chunk) in store.chunks(split).enumerate() {
            let mut seg = b"JP".to_vec();
            seg.extend_from_slice(&[0, 1]);
            seg.extend_from_slice(&((z + 1) as u32).to_be_bytes());
            if z > 0 {
                seg.extend_from_slice(header);
            }
            seg.extend_from_slice(chunk);
            out.extend_from_slice(&[0xFF, 0xEB]);
            out.extend_from_slice(&((seg.len() + 2) as u16).to_be_bytes());
            out.extend_from_slice(&seg);
        }
        out.extend_from_slice(&[0xFF, 0xDA, 0, 2, 0, 0, 0xFF, 0xD9]);
        out
    }

    #[test]
    fn reads_a_manifest_from_a_single_and_a_split_jpeg() {
        for split in [100_000, 120] {
            let r = scan(&jpeg_with(&sample_store(true), split));
            assert_eq!(r["present"], true, "split {split}");
            assert_eq!(r["manifest_count"], 1);
            let m = &r["manifests"][0];
            assert_eq!(m["claim_generator"], "ExampleGen/2.1");
            assert_eq!(m["title"], "sunset.jpg");
            assert_eq!(m["actions"][0]["action"], "c2pa.created");
            assert_eq!(m["actions"][0]["software_agent"], "ExampleGen 2.1");
            assert_eq!(m["ai_generated_declared"], true);
            assert_eq!(m["assertions"], json!(["c2pa.actions.v2", "c2pa.hash.data"]));
            assert_eq!(m["signature"]["algorithm"], "ES256");
            assert_eq!(m["signature"]["signer_subject"], "O=Example Studio");
            assert_eq!(m["signature"]["signer_issuer"], "O=Example CA");
            assert_eq!(r["validated"], false);
        }
    }

    #[test]
    fn camera_capture_is_not_flagged_as_ai() {
        let r = scan(&jpeg_with(&sample_store(false), 100_000));
        assert_eq!(r["ai_generated_declared"], false);
    }

    #[test]
    fn reads_png_and_bmff_and_reports_absence() {
        let store = sample_store(false);
        let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        png.extend_from_slice(&(store.len() as u32).to_be_bytes());
        png.extend_from_slice(b"caBX");
        png.extend_from_slice(&store);
        png.extend_from_slice(&[0; 4]);
        assert_eq!(scan(&png)["present"], true);
        let mut payload = C2PA_UUID.to_vec();
        payload.extend_from_slice(&[0, 0, 0, 0]);
        payload.extend_from_slice(b"manifest\0");
        payload.extend_from_slice(&0u64.to_be_bytes());
        payload.extend_from_slice(&store);
        let mut mp4 = jbox("ftyp", b"isom\0\0\0\0isom");
        mp4.extend_from_slice(&jbox("uuid", &payload));
        mp4.extend_from_slice(&jbox("mdat", b"xxxx"));
        assert_eq!(scan(&mp4)["manifests"][0]["claim_generator"], "ExampleGen/2.1");
        let dir = std::env::temp_dir().join(format!("c2pa-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("v.mp4");
        std::fs::write(&p, &mp4).unwrap();
        assert_eq!(scan_file(&p)["present"], true);
        std::fs::write(&p, jbox("ftyp", b"isom\0\0\0\0isom")).unwrap();
        assert_eq!(scan_file(&p)["present"], false);
        assert_eq!(scan(b"just some bytes")["present"], false);
        assert_eq!(scan(&[0xFF, 0xD8, 0xFF, 0xD9])["present"], false);
    }

    #[test]
    fn malformed_input_never_panics() {
        let store = sample_store(true);
        for cut in [0, 5, 9, 30, 100, store.len() - 3] {
            let _ = analyse(&store[..cut]);
        }
        let mut bad = store.clone();
        bad[0] = 0xff;
        let _ = analyse(&bad);
        assert_eq!(analyse(b"")["readable"], false);
        let _ = scan(&jpeg_with(&store[..60], 20));
        assert!(cert_names(&[0x30, 0x80]).is_none());
        assert!(cert_names(&[]).is_none());
    }
}

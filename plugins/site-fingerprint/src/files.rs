//! robots.txt, sitemap and favicon helpers, including the Shodan-style favicon hash (MurmurHash3 x86 32 of the
//! base64 text with a newline every 76 characters), which is a pivot value for other tools.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub fn murmur3_32(data: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e2d51;
    const C2: u32 = 0x1b873593;
    let mut h = seed;
    let mut chunks = data.chunks_exact(4);
    for c in &mut chunks {
        let mut k = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h ^= k;
        h = h.rotate_left(13).wrapping_mul(5).wrapping_add(0xe6546b64);
    }
    let tail = chunks.remainder();
    let mut k = 0u32;
    if tail.len() >= 3 {
        k ^= (tail[2] as u32) << 16;
    }
    if tail.len() >= 2 {
        k ^= (tail[1] as u32) << 8;
    }
    if !tail.is_empty() {
        k ^= tail[0] as u32;
        k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h ^= k;
    }
    h ^= data.len() as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85ebca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2ae35);
    h ^ (h >> 16)
}

pub fn base64_lines(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut flat = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        flat.push(T[(n >> 18) as usize & 63] as char);
        flat.push(T[(n >> 12) as usize & 63] as char);
        flat.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        flat.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    let mut out = String::new();
    for chunk in flat.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out
}

pub fn favicon_hash(data: &[u8]) -> i32 {
    murmur3_32(base64_lines(data).as_bytes(), 0) as i32
}

pub fn favicon_json(url: &str, data: &[u8], ctype: &str) -> Value {
    let h = favicon_hash(data);
    json!({ "url": url, "bytes": data.len(), "content_type": ctype, "mmh3": h, "sha256": Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "shodan_query": format!("http.favicon.hash:{h}"), "note": "Pivot value only: search for it yourself in Shodan, Censys or FOFA. This plugin does not query them." })
}

pub fn looks_like_html(body: &[u8], ctype: &str) -> bool {
    let head = String::from_utf8_lossy(&body[..body.len().min(512)]).to_ascii_lowercase();
    ctype.contains("html") || head.contains("<html") || head.contains("<!doctype html")
}

pub fn robots_summary(text: &str) -> Value {
    let (mut agents, mut dis, mut allow, mut delay) = (vec![], vec![], 0usize, None::<String>);
    let mut sitemaps = vec![];
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some((k, v)) = line.split_once(':') else { continue };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        match k.as_str() {
            "user-agent" => {
                if !agents.contains(&v.to_string()) {
                    agents.push(v.to_string());
                }
            }
            "disallow" if !v.is_empty() => dis.push(v.chars().take(120).collect::<String>()),
            "allow" => allow += 1,
            "crawl-delay" => delay = Some(v.to_string()),
            "sitemap" => sitemaps.push(v.chars().take(300).collect::<String>()),
            _ => {}
        }
    }
    let total = dis.len();
    let mut uniq = vec![];
    for d in dis {
        if !uniq.contains(&d) {
            uniq.push(d);
        }
    }
    uniq.truncate(25);
    json!({ "user_agents": agents.len(), "agents": agents.into_iter().take(10).collect::<Vec<_>>(), "disallow_rules": total, "allow_rules": allow, "crawl_delay": delay, "sitemaps": sitemaps.into_iter().take(10).collect::<Vec<_>>(), "disallow_sample": uniq })
}

pub fn sitemap_summary(xml: &str) -> Value {
    let lower = xml.to_ascii_lowercase();
    let index = lower.contains("<sitemapindex");
    let mut locs = vec![];
    let mut count = 0usize;
    let mut pos = 0usize;
    // ASCII lower-casing keeps byte offsets, so `lower` can be searched while slicing `xml`.
    while let Some(s) = lower[pos..].find("<loc>") {
        let start = pos + s + 5;
        let Some(e) = lower[start..].find("</loc>") else { break };
        count += 1;
        if locs.len() < 10 {
            locs.push(xml[start..start + e].trim().chars().take(200).collect::<String>());
        }
        pos = start + e + 6;
        if count >= 50_000 {
            break;
        }
    }
    let newest = lower.match_indices("<lastmod>").filter_map(|(i, _)| xml.get(i + 9..i + 19)).filter(|d| d.len() == 10 && d.as_bytes()[4] == b'-').max().map(String::from);
    json!({ "kind": if index { "index" } else { "urlset" }, "entries": count, "sample": locs, "newest_lastmod": newest })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn murmur_vectors() {
        assert_eq!(murmur3_32(b"", 0), 0);
        assert_eq!(murmur3_32(b"hello", 0), 0x248bfa47);
        assert_eq!(murmur3_32(b"foo", 0) as i32, -156908512);
        assert_eq!(murmur3_32(b"The quick brown fox jumps over the lazy dog", 0), 0x2e4ff723);
        assert_eq!(murmur3_32(b"", 1), 0x514e28b7);
    }

    #[test]
    fn base64_matches_python_encodebytes() {
        assert_eq!(base64_lines(b"hello"), "aGVsbG8=\n");
        let long = base64_lines(&[0u8; 100]);
        let lines: Vec<&str> = long.lines().collect();
        assert_eq!(lines[0].len(), 76);
        assert!(long.ends_with('\n') && lines.len() == 2);
        assert_eq!(favicon_hash(b""), 0, "empty input hashes to zero");
    }

    #[test]
    fn robots_and_sitemaps() {
        let r = robots_summary("User-agent: *\nDisallow: /admin # secret\nDisallow: /admin\nDisallow:\nAllow: /\nCrawl-delay: 5\nSitemap: https://a.example/sitemap.xml\nUser-agent: Googlebot\n");
        assert_eq!((r["user_agents"].as_u64(), r["disallow_rules"].as_u64(), r["allow_rules"].as_u64()), (Some(2), Some(2), Some(1)));
        assert_eq!(r["disallow_sample"], json!(["/admin"]));
        assert_eq!(r["sitemaps"][0], "https://a.example/sitemap.xml");
        let s = sitemap_summary("<urlset><url><loc>https://a.example/1</loc><lastmod>2026-01-02</lastmod></url><URL><LOC> https://a.example/2 </LOC><lastmod>2026-03-04T10:00:00Z</lastmod></URL></urlset>");
        assert_eq!((s["entries"].as_u64(), s["newest_lastmod"].as_str()), (Some(2), Some("2026-03-04")));
        assert_eq!(s["sample"][1], "https://a.example/2");
        assert_eq!(sitemap_summary("<sitemapindex><sitemap><loc>x</loc></sitemap></sitemapindex>")["kind"], "index");
        assert!(looks_like_html(b"<!DOCTYPE html><html>", "text/plain"));
        assert!(!looks_like_html(b"User-agent: *", "text/plain"));
    }
}

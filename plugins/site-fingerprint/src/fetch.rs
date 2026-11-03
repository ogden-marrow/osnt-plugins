//! Fetch the page the user named: follow redirects by hand (each hop SSRF-checked) and keep headers and cookies.

use std::{io::Read, time::Instant};

use serde_json::{Value, json};
use ureq::Agent;
use url::Url;

use crate::{headers::Headers, ssrf::Guard};

pub const MAX_HOPS: usize = 6;
pub const PAGE_MAX: usize = 1024 * 1024;

pub struct Page {
    pub hops: Vec<Value>,
    pub final_url: Url,
    pub status: u16,
    pub headers: Headers,
    pub set_cookies: Vec<String>,
    pub body: Vec<u8>,
    pub truncated: bool,
    pub content_type: String,
}

pub fn fetch_chain(agent: &Agent, guard: &Guard, start: &Url) -> Result<Page, String> {
    let mut url = start.clone();
    let mut hops = vec![];
    let mut cookies = vec![];
    for hop in 0..=MAX_HOPS {
        guard.check_url(&url, false)?;
        let t = Instant::now();
        let mut res = agent.get(url.as_str()).header("Accept", "text/html,application/xhtml+xml,*/*;q=0.8").call().map_err(|e| format!("request failed: {}", crate::ssrf::short_err_pub(&e)))?;
        let status = res.status().as_u16();
        let headers: Headers = res.headers().iter().map(|(k, v)| (k.as_str().to_ascii_lowercase(), String::from_utf8_lossy(v.as_bytes()).to_string())).collect();
        for (k, v) in &headers {
            if k == "set-cookie" {
                cookies.push(v.clone());
            }
        }
        let location = headers.iter().find(|(k, _)| k == "location").map(|(_, v)| v.clone());
        hops.push(json!({ "url": url.to_string(), "status": status, "location": location, "server": crate::headers::get(&headers, "server"), "ms": t.elapsed().as_millis() as u64 }));
        if (300..400).contains(&status) {
            let loc = location.ok_or("redirect without a Location header")?;
            if hop == MAX_HOPS {
                return Err(format!("more than {MAX_HOPS} redirects"));
            }
            url = url.join(&loc).map_err(|_| "invalid redirect target".to_string())?;
            continue;
        }
        let content_type = crate::headers::get(&headers, "content-type").unwrap_or("").to_string();
        let mut body = Vec::new();
        res.body_mut().as_reader().take(PAGE_MAX as u64 + 1).read_to_end(&mut body).map_err(|_| "reading the page failed".to_string())?;
        let truncated = body.len() > PAGE_MAX;
        body.truncate(PAGE_MAX);
        return Ok(Page { hops, final_url: url, status, headers, set_cookies: cookies, body, truncated, content_type });
    }
    Err("too many redirects".into())
}

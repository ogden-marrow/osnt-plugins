//! Test helpers: a tiny fake HTTP server on 127.0.0.1 (random port) and request signing for gateway-gated routes.

use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::Arc,
    thread,
};

#[allow(dead_code)]
pub struct Req {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
#[allow(dead_code)]
impl Resp {
    pub fn json(v: serde_json::Value) -> Resp {
        Resp { status: 200, headers: vec![("Content-Type".into(), "application/json".into())], body: v.to_string().into_bytes() }
    }
    pub fn text(s: &str) -> Resp {
        Resp { status: 200, headers: vec![("Content-Type".into(), "text/plain".into())], body: s.as_bytes().to_vec() }
    }
    pub fn status(code: u16, s: &str) -> Resp {
        Resp { status: code, headers: vec![], body: s.as_bytes().to_vec() }
    }
}

/// Fake server. Returns the port. Every connection serves one request.
pub fn spawn(handler: Arc<dyn Fn(&Req) -> Resp + Send + Sync>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in l.incoming() {
            let Ok(mut s) = stream else { continue };
            let h = handler.clone();
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let head_end = loop {
                    let n = s.read(&mut tmp).unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break p + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let mut lines = head.lines();
                let mut first = lines.next().unwrap_or("").split(' ');
                let (method, path) = (first.next().unwrap_or("").to_string(), first.next().unwrap_or("").to_string());
                let headers: Vec<(String, String)> = lines.filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))).collect();
                let len: usize = headers.iter().find(|(k, _)| k == "content-length").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
                while buf.len() < head_end + len {
                    let n = s.read(&mut tmp).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                let r = h(&Req { method, path, headers, body: buf[head_end..].to_vec() });
                let mut out = format!("HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n", r.status, r.body.len());
                for (k, v) in &r.headers {
                    out.push_str(&format!("{k}: {v}\r\n"));
                }
                out.push_str("\r\n");
                let _ = s.write_all(out.as_bytes());
                let _ = s.write_all(&r.body);
            });
        }
    });
    port
}

pub const TEST_KEY: &str = "test-gateway-key";

/// Header value the hub would send for this request (needs OSNT_GATEWAY_KEY=TEST_KEY, set by `init_env`).
pub fn sign(method: &str, path_and_query: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let mut mac = Hmac::<Sha256>::new_from_slice(TEST_KEY.as_bytes()).unwrap();
    mac.update(format!("{ts}.{method}.{path_and_query}").as_bytes());
    let sig: String = mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect();
    format!("v1.{ts}.{sig}")
}

pub fn init_env() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| unsafe { std::env::set_var("OSNT_GATEWAY_KEY", TEST_KEY) });
}

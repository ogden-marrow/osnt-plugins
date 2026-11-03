//! Tiny fake HTTP server on 127.0.0.1 (random port) for tests, so no test touches the live internet.
#![allow(dead_code)]
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::Arc,
    thread,
};

pub struct Req {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
impl Resp {
    pub fn json(v: serde_json::Value) -> Resp {
        Resp { status: 200, headers: vec![("Content-Type".into(), "application/json".into())], body: v.to_string().into_bytes() }
    }
    pub fn text(s: &str) -> Resp {
        Resp { status: 200, headers: vec![("Content-Type".into(), "text/plain".into())], body: s.as_bytes().to_vec() }
    }
    pub fn status(code: u16) -> Resp {
        Resp { status: code, headers: vec![], body: b"{}".to_vec() }
    }
    pub fn redirect_to(to: &str) -> Resp {
        Resp { status: 302, headers: vec![("Location".into(), to.into())], body: vec![] }
    }
    pub fn html(s: &str) -> Resp {
        Resp { status: 200, headers: vec![("Content-Type".into(), "text/html; charset=utf-8".into())], body: s.as_bytes().to_vec() }
    }
    pub fn bytes(b: &[u8], ctype: &str) -> Resp {
        Resp { status: 200, headers: vec![("Content-Type".into(), ctype.into())], body: b.to_vec() }
    }
    pub fn with(mut self, k: &str, v: &str) -> Resp {
        self.headers.push((k.into(), v.into()));
        self
    }
}

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
                let headers: Vec<(String, String)> = lines.filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))).collect();
                let len: usize = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
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

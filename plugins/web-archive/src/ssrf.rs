#![allow(dead_code)]
//! SSRF guard and guarded HTTP fetching.
//!
//! Every URL that a user or the model supplies goes through [`Guard`]. The guard only allows http/https on ports
//! 80/443, rejects credentials in the URL, and rejects any hostname that resolves to a non-public address.
//! The ureq agent built by [`guarded_agent`] uses a resolver that applies the same check and hands ureq *only*
//! the vetted addresses, so the connection goes to the address that was checked (no second lookup that DNS
//! rebinding could swap). Redirects are followed by hand so every hop is re-validated (max 3).

use std::{
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

use ureq::{
    Agent,
    unversioned::{
        resolver::{ResolvedSocketAddrs, Resolver},
        transport::DefaultConnector,
    },
};
use url::{Host, Url};

pub const MAX_REDIRECTS: usize = 3;
pub const PAGE_MAX_BYTES: usize = 2 * 1024 * 1024;

fn v4_allowed(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || o[0] == 0 // 0.0.0.0/8 "this network"
        || (o[0] == 100 && (o[1] & 0xC0) == 64) // 100.64.0.0/10 CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF protocol assignments
        || (o[0] == 192 && o[1] == 0 && o[2] == 2) // TEST-NET-1
        || (o[0] == 198 && (o[1] & 0xFE) == 18) // 198.18.0.0/15 benchmarking
        || (o[0] == 198 && o[1] == 51 && o[2] == 100) // TEST-NET-2
        || (o[0] == 203 && o[1] == 0 && o[2] == 113) // TEST-NET-3
        || o[0] >= 240) // reserved
}

fn v6_allowed(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return v4_allowed(v4);
    }
    let s = ip.segments();
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    if (s[0] & 0xFE00) == 0xFC00 || (s[0] & 0xFFC0) == 0xFE80 || (s[0] & 0xFFC0) == 0xFEC0 {
        return false; // unique-local, link-local, site-local
    }
    // ::a.b.c.d (IPv4-compatible, deprecated) and 64:ff9b::/96 (NAT64) embed an IPv4 address.
    if s[..6] == [0; 6] || s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return v4_allowed(Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8));
    }
    if s[0] == 0x2002 {
        // 6to4 embeds an IPv4 address in bits 16..48.
        return v4_allowed(Ipv4Addr::new((s[1] >> 8) as u8, s[1] as u8, (s[2] >> 8) as u8, s[2] as u8));
    }
    if s[0] == 0x2001 && s[1] == 0 {
        return false; // Teredo
    }
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return false; // documentation
    }
    true
}

/// True only for a globally routable public address.
pub fn ip_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v4_allowed(v),
        IpAddr::V6(v) => v6_allowed(v),
    }
}

#[derive(Clone, Debug, Default)]
pub struct Guard {
    /// Tests only: allow loopback addresses on exactly this port, so a local fake server can be reached while
    /// every other loopback port, private range and metadata address stays blocked. Never set in production.
    pub exempt_loopback_port: Option<u16>,
}

impl Guard {
    /// Validate scheme, port, credentials and address(es). Returns the vetted socket addresses.
    /// `allow_unresolvable`: a hostname with no DNS answer is accepted (returns no addresses); used for URLs we
    /// only pass to a third party (Wayback), never connect to ourselves.
    pub fn check_url(&self, url: &Url, allow_unresolvable: bool) -> Result<Vec<SocketAddr>, String> {
        if !matches!(url.scheme(), "http" | "https") {
            return Err("blocked: only http and https URLs are allowed".into());
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err("blocked: credentials in URLs are not allowed".into());
        }
        let port = url.port_or_known_default().ok_or("blocked: no port")?;
        let host = url.host().ok_or("blocked: URL has no host")?;
        let exempt = self.exempt_loopback_port == Some(port);
        if !(port == 80 || port == 443 || exempt) {
            return Err(format!("blocked: port {port} is not allowed (only 80 and 443)"));
        }
        let ips: Vec<IpAddr> = match host {
            Host::Ipv4(a) => vec![IpAddr::V4(a)],
            Host::Ipv6(a) => vec![IpAddr::V6(a)],
            Host::Domain(d) => match (d, port).to_socket_addrs() {
                Ok(it) => it.map(|s| s.ip()).collect(),
                Err(_) if allow_unresolvable => return Ok(Vec::new()),
                Err(_) => return Err("host could not be resolved".into()),
            },
        };
        if ips.is_empty() {
            return if allow_unresolvable { Ok(Vec::new()) } else { Err("host could not be resolved".into()) };
        }
        // Every answer must be public: a mixed answer set is how some rebinding tricks work.
        for ip in &ips {
            if !(ip_allowed(*ip) || (exempt && ip.is_loopback())) {
                return Err("blocked: address is not a public internet address".into());
            }
        }
        Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect())
    }
}

/// ureq resolver that returns only vetted addresses. ureq connects to what this returns, nothing else.
#[derive(Debug)]
struct GuardResolver(Guard);

impl Resolver for GuardResolver {
    fn resolve(&self, uri: &ureq::http::Uri, _config: &ureq::config::Config, _timeout: ureq::unversioned::transport::NextTimeout) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let url = Url::parse(&uri.to_string()).map_err(|_| ureq::Error::HostNotFound)?;
        let addrs = self.0.check_url(&url, false).map_err(|_| ureq::Error::HostNotFound)?;
        let mut out = self.empty();
        for a in addrs.into_iter().take(8) {
            out.push(a);
        }
        if out.is_empty() { Err(ureq::Error::HostNotFound) } else { Ok(out) }
    }
}

/// An agent for fetching untrusted URLs: pure-Rust TLS, vetted-address resolver, no proxy (an env proxy would
/// bypass the resolver), no cookies, no automatic redirects, 3xx and 4xx/5xx returned as ordinary responses.
pub fn guarded_agent(guard: Guard, user_agent: &str) -> Agent {
    guarded_agent_timeout(guard, user_agent, 15)
}

/// Same, with a longer overall timeout (slow archive queries, large downloads).
pub fn guarded_agent_timeout(guard: Guard, user_agent: &str, secs: u64) -> Agent {
    let provider = Arc::new(rustls_rustcrypto::provider());
    let tls = ureq::tls::TlsConfig::builder().provider(ureq::tls::TlsProvider::Rustls).unversioned_rustls_crypto_provider(provider).build();
    let config = Agent::config_builder()
        .tls_config(tls)
        .timeout_global(Some(Duration::from_secs(secs)))
        .user_agent(user_agent)
        .proxy(None)
        .max_redirects(0)
        .max_redirects_will_error(false)
        .http_status_as_error(false)
        .build();
    Agent::with_parts(config, DefaultConnector::new(), GuardResolver(guard))
}

pub struct Fetched {
    pub final_url: String,
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
    pub truncated: bool,
}

/// GET with SSRF protection: every hop is validated, at most [`MAX_REDIRECTS`] redirects, body capped at `max_bytes`.
pub fn guarded_get(agent: &Agent, guard: &Guard, start: &str, max_bytes: usize, accept: &str) -> Result<Fetched, String> {
    let mut url = Url::parse(start).map_err(|_| "not a valid URL".to_string())?;
    for hop in 0..=MAX_REDIRECTS {
        guard.check_url(&url, false)?;
        let mut res = agent.get(url.as_str()).header("Accept", accept).call().map_err(|e| format!("request failed: {}", short_err(&e)))?;
        let status = res.status().as_u16();
        if (300..400).contains(&status) {
            let loc = res.headers().get("location").and_then(|v| v.to_str().ok()).ok_or("redirect without Location")?.to_string();
            if hop == MAX_REDIRECTS {
                return Err("too many redirects".into());
            }
            url = url.join(&loc).map_err(|_| "invalid redirect target".to_string())?;
            continue;
        }
        let content_type = res.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let mut body = Vec::new();
        res.body_mut().as_reader().take(max_bytes as u64 + 1).read_to_end(&mut body).map_err(|e| format!("reading body failed: {e}"))?;
        let truncated = body.len() > max_bytes;
        body.truncate(max_bytes);
        return Ok(Fetched { final_url: url.to_string(), status, content_type, body, truncated });
    }
    Err("too many redirects".into())
}

fn short_err(e: &ureq::Error) -> String {
    match e {
        ureq::Error::HostNotFound => "host not found or not allowed".into(),
        other => other.to_string(),
    }
}

#[cfg(test)]
pub mod testutil {
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
        pub fn html(s: &str) -> Resp {
            Resp { status: 200, headers: vec![("Content-Type".into(), "text/html".into())], body: s.as_bytes().to_vec() }
        }
        pub fn redirect(to: &str) -> Resp {
            Resp { status: 302, headers: vec![("Location".into(), to.into())], body: vec![] }
        }
    }

    /// Tiny fake HTTP server on 127.0.0.1 (random port). Returns the port.
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
                    let len: usize = lines.filter_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0))).next().unwrap_or(0);
                    while buf.len() < head_end + len {
                        let n = s.read(&mut tmp).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let r = h(&Req { method, path, body: buf[head_end..].to_vec() });
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
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    fn blocked(u: &str) -> bool {
        let g = Guard::default();
        g.check_url(&Url::parse(u).unwrap(), false).is_err()
    }

    #[test]
    fn rejects_non_public_literals() {
        for u in [
            "http://127.0.0.1/",
            "http://127.0.0.1:8080/internal/secrets/X",
            "http://10.1.2.3/",
            "http://172.16.0.1/",
            "http://192.168.1.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.64.0.1/",
            "http://0.0.0.0/",
            "http://224.0.0.1/",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:10.0.0.1]/",
            "http://[fc00::1]/",
            "http://[fe80::1]/",
            "http://[::]/",
            "http://[ff02::1]/",
            "http://[64:ff9b::7f00:1]/",
            "http://[2002:7f00:1::]/",
            "http://2130706433/", // decimal form of 127.0.0.1, normalised by the URL parser
            "http://0x7f.1/",
        ] {
            assert!(blocked(u), "{u} should be blocked");
        }
    }

    #[test]
    fn rejects_bad_scheme_port_credentials() {
        assert!(blocked("file:///etc/passwd"));
        assert!(blocked("ftp://93.184.216.34/"));
        assert!(blocked("http://93.184.216.34:8080/"));
        assert!(blocked("http://93.184.216.34:22/"));
        assert!(blocked("http://user:pw@93.184.216.34/"));
        assert!(!blocked("http://93.184.216.34/"));
        assert!(!blocked("https://93.184.216.34:443/"));
        assert!(!blocked("http://[2606:2800:220:1:248:1893:25c8:1946]/"));
    }

    #[test]
    fn hostname_resolving_to_localhost_is_blocked() {
        // "localhost" resolves to loopback via the system resolver.
        assert!(blocked("http://localhost/"));
        assert!(blocked("https://localhost:443/"));
        let e = Guard::default().check_url(&Url::parse("http://localhost/").unwrap(), false).unwrap_err();
        assert!(e.contains("blocked"), "{e}");
    }

    #[test]
    fn unresolvable_host_only_ok_when_allowed() {
        let u = Url::parse("http://this-host-does-not-exist.invalid/").unwrap();
        assert!(Guard::default().check_url(&u, false).is_err());
        assert!(Guard::default().check_url(&u, true).is_ok());
        // ...but a literal private address is never ok.
        assert!(Guard::default().check_url(&Url::parse("http://10.0.0.1/").unwrap(), true).is_err());
    }

    #[test]
    fn agent_cannot_reach_loopback_even_directly() {
        // Real server on loopback; guard has no exemption, so the guarded agent must refuse to connect.
        let port = spawn(Arc::new(|_| Resp::html("secret")));
        let agent = guarded_agent(Guard::default(), "test");
        let r = guarded_get(&agent, &Guard::default(), &format!("http://127.0.0.1:{port}/"), 1000, "*/*");
        assert!(r.is_err());
        let r = guarded_get(&agent, &Guard::default(), &format!("http://localhost:{port}/"), 1000, "*/*");
        assert!(r.is_err());
    }

    #[test]
    fn redirects_are_revalidated() {
        let port = spawn(Arc::new(|r| match r.path.as_str() {
            "/ok" => Resp::html("hello"),
            "/to-private" => Resp::redirect("http://10.0.0.5/admin"),
            "/to-meta" => Resp::redirect("http://169.254.169.254/latest/meta-data/"),
            "/to-loopback-other-port" => Resp::redirect("http://127.0.0.1:8080/internal/secrets/DEEPSEEK_API_KEY"),
            "/to-localhost" => Resp::redirect("http://localhost:80/"),
            "/loop" => Resp::redirect("/loop"),
            _ => Resp { status: 404, headers: vec![], body: vec![] },
        }));
        let guard = Guard { exempt_loopback_port: Some(port) };
        let agent = guarded_agent(guard.clone(), "test");
        let get = |p: &str| guarded_get(&agent, &guard, &format!("http://127.0.0.1:{port}{p}"), 1000, "*/*");
        let ok = get("/ok").unwrap();
        assert_eq!(ok.body, b"hello");
        for p in ["/to-private", "/to-meta", "/to-loopback-other-port", "/to-localhost"] {
            let e = get(p).err().unwrap_or_else(|| panic!("{p} must fail"));
            assert!(e.contains("blocked"), "{p}: {e}");
        }
        let e = get("/loop").err().unwrap();
        assert!(e.contains("too many redirects"), "{e}");
    }

    #[test]
    fn response_size_is_capped() {
        let port = spawn(Arc::new(|_| Resp::html(&"a".repeat(5000))));
        let guard = Guard { exempt_loopback_port: Some(port) };
        let agent = guarded_agent(guard.clone(), "test");
        let r = guarded_get(&agent, &guard, &format!("http://127.0.0.1:{port}/"), 1000, "*/*").unwrap();
        assert_eq!(r.body.len(), 1000);
        assert!(r.truncated);
    }
}

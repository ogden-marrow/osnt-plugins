//! Polite, range-based access to the adsb.lol globe_history release assets.
//!
//! A day is one tar (GNU tar, uncompressed) published as GitHub release assets, split into 2 GB parts `.tar.aa`, `.tar.ab`
//! (older and small days: a single `.tar`). The tar has no index, but a tar member can be located by hopping from header
//! to header with 512-byte Range requests, and a member can then be fetched with one Range request. We only ever read
//! heatmap members and never store tar bytes.
//!
//! Only fixed hosts are contacted: the configured base (github.com) and the `*.githubusercontent.com` host it redirects
//! to. Callers cannot influence the URL beyond a validated date.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::{self, Read},
    sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

pub const USER_AGENT: &str = "osnt-adsb-history/0.1 (+https://github.com/ogden-marrow/osnt-plugins; polite range requests, one at a time)";
const SIGNED_URL_TTL: Duration = Duration::from_secs(40 * 60);

/// Like `osnt_common::http_agent` (pure-Rust TLS, same provider) but for long streaming downloads: no 15 s global cap,
/// no redirect following (we vet the redirect target ourselves) and 4xx/5xx are returned as responses.
fn agent() -> ureq::Agent {
    let provider = Arc::new(rustls_rustcrypto::provider());
    let tls = ureq::tls::TlsConfig::builder().provider(ureq::tls::TlsProvider::Rustls).unversioned_rustls_crypto_provider(provider).build();
    ureq::Agent::config_builder()
        .tls_config(tls)
        .user_agent(USER_AGENT)
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(None)
        .timeout_resolve(Some(Duration::from_secs(10)))
        .timeout_connect(Some(Duration::from_secs(10)))
        .timeout_recv_response(Some(Duration::from_secs(30)))
        .timeout_recv_body(Some(Duration::from_secs(20 * 60)))
        .build()
        .into()
}

fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map(|x| x.1).unwrap_or(url);
    rest.split(['/', '?']).next().unwrap_or("")
}

#[derive(Clone, Debug)]
pub struct Part {
    pub orig: String,
    pub size: u64,
}

#[derive(Clone, Debug)]
pub struct Archive {
    pub variant: String,
    pub parts: Vec<Part>,
}

impl Archive {
    pub fn total(&self) -> u64 {
        self.parts.iter().map(|p| p.size).sum()
    }
}

pub struct Upstream {
    agent: ureq::Agent,
    base: String,
    signed: Mutex<HashMap<String, (String, Instant)>>,
}

pub type R<T> = Result<T, String>;

impl Upstream {
    pub fn new(base: &str) -> Arc<Self> {
        Arc::new(Self { agent: agent(), base: base.trim_end_matches('/').to_string(), signed: Mutex::new(HashMap::new()) })
    }

    fn redirect_ok(&self, loc: &str) -> bool {
        let h = host_of(loc);
        let secure = loc.starts_with("https://") || self.base.starts_with("http://");
        secure && (h == host_of(&self.base) || h == "githubusercontent.com" || h.ends_with(".githubusercontent.com"))
    }

    /// One ranged GET with no redirect following. Returns the response (any status).
    fn get_range(&self, url: &str, start: u64, end_incl: u64) -> R<ureq::http::Response<ureq::Body>> {
        self.agent
            .get(url)
            .header("Range", &format!("bytes={start}-{end_incl}"))
            .header("Accept-Encoding", "identity")
            .call()
            .map_err(|e| format!("request failed: {e}"))
    }

    /// Resolve a release asset URL to the (signed) download URL and its size. Ok(None) = not found.
    fn probe(&self, orig: &str) -> R<Option<(String, u64)>> {
        let resp = self.get_range(orig, 0, 0)?;
        let status = resp.status().as_u16();
        let (final_url, resp) = match status {
            301 | 302 | 303 | 307 | 308 => {
                let loc = resp.headers().get("location").and_then(|v| v.to_str().ok()).ok_or("redirect without location")?.to_string();
                let loc = if loc.starts_with('/') {
                    let scheme = orig.split("://").next().unwrap_or("https");
                    format!("{scheme}://{}{loc}", host_of(orig))
                } else {
                    loc
                };
                if !self.redirect_ok(&loc) {
                    return Err(format!("refusing redirect to unexpected host {}", host_of(&loc)));
                }
                let r2 = self.get_range(&loc, 0, 0)?;
                (loc, r2)
            }
            _ => (orig.to_string(), resp),
        };
        match resp.status().as_u16() {
            404 => return Ok(None),
            206 => {}
            200 => return Err("upstream ignores Range requests; refusing to download a whole archive".into()),
            s => return Err(format!("unexpected upstream status {s}")),
        }
        let total = resp
            .headers()
            .get("content-range")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit('/').next())
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or("missing Content-Range")?;
        self.signed.lock().unwrap().insert(orig.to_string(), (final_url.clone(), Instant::now()));
        Ok(Some((final_url, total)))
    }

    fn final_url(&self, orig: &str) -> R<String> {
        if let Some((u, t)) = self.signed.lock().unwrap().get(orig) {
            if t.elapsed() < SIGNED_URL_TTL {
                return Ok(u.clone());
            }
        }
        self.probe(orig)?.map(|x| x.0).ok_or_else(|| "archive part not found".to_string())
    }

    /// Open `[start, end_incl]` of one part as a stream.
    fn open_part(&self, orig: &str, start: u64, end_incl: u64) -> R<Box<dyn Read + Send>> {
        for attempt in 0..2 {
            let url = self.final_url(orig)?;
            let resp = self.get_range(&url, start, end_incl)?;
            match resp.status().as_u16() {
                206 => return Ok(Box::new(resp.into_body().into_reader())),
                401 | 403 | 410 if attempt == 0 => {
                    self.signed.lock().unwrap().remove(orig); // signed URL expired; re-resolve once
                }
                200 => return Err("upstream ignored the Range header".into()),
                s => return Err(format!("upstream returned {s} for a range request")),
            }
        }
        Err("could not open range".into())
    }

    /// Find the archive for a day (`YYYY-MM-DD`): the "prod" release, or "staging" if prod is not out yet (today).
    pub fn find_archive(&self, date: &str) -> R<Archive> {
        let (y, m, d) = (&date[0..4], &date[5..7], &date[8..10]);
        for variant in ["prod", "staging"] {
            let tag = format!("v{y}.{m}.{d}-planes-readsb-{variant}-0");
            let stem = format!("{}/adsblol/globe_history_{y}/releases/download/{tag}/{tag}.tar", self.base);
            let mut parts = vec![];
            if let Some((_, size)) = self.probe(&format!("{stem}.aa"))? {
                parts.push(Part { orig: format!("{stem}.aa"), size });
                for suffix in ["ab", "ac", "ad", "ae", "af", "ag", "ah"] {
                    let u = format!("{stem}.{suffix}");
                    match self.probe(&u)? {
                        Some((_, size)) => parts.push(Part { orig: u, size }),
                        None => break,
                    }
                }
            } else if let Some((_, size)) = self.probe(&stem)? {
                parts.push(Part { orig: stem, size });
            }
            if !parts.is_empty() {
                return Ok(Archive { variant: variant.into(), parts });
            }
        }
        Err(format!("no archive published for {date} (adsb.lol globe_history releases start in late 2023; today's day appears only as a partial staging release)"))
    }

    /// Stream `len` bytes at logical offset `start` of the (concatenated) archive.
    pub fn stream(self: &Arc<Self>, a: &Archive, start: u64, len: u64) -> R<ChainReader> {
        if len == 0 || start + len > a.total() {
            return Err("range outside archive".into());
        }
        let mut segs = VecDeque::new();
        let (mut base, mut pos, mut left) = (0u64, start, len);
        for p in &a.parts {
            if pos < base + p.size && left > 0 {
                let local = pos - base;
                let n = left.min(p.size - local);
                segs.push_back((p.orig.clone(), local, local + n - 1));
                pos += n;
                left -= n;
            }
            base += p.size;
        }
        Ok(ChainReader { up: self.clone(), segs, cur: None })
    }

    pub fn read_bytes(self: &Arc<Self>, a: &Archive, start: u64, len: u64) -> R<Vec<u8>> {
        let mut v = Vec::with_capacity(len as usize);
        self.stream(a, start, len)?.read_to_end(&mut v).map_err(|e| e.to_string())?;
        Ok(v)
    }
}

pub struct ChainReader {
    up: Arc<Upstream>,
    segs: VecDeque<(String, u64, u64)>,
    cur: Option<Box<dyn Read + Send>>,
}

impl Read for ChainReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.cur.is_none() {
                let Some((orig, a, b)) = self.segs.pop_front() else { return Ok(0) };
                self.cur = Some(self.up.open_part(&orig, a, b).map_err(io::Error::other)?);
            }
            let n = self.cur.as_mut().unwrap().read(buf)?;
            if n == 0 {
                self.cur = None;
                continue;
            }
            return Ok(n);
        }
    }
}

/// Counts bytes and aborts when cancelled or when the per-job download budget is exceeded.
pub struct Metered<R> {
    pub inner: R,
    pub count: u64,
    pub budget: Arc<std::sync::atomic::AtomicU64>,
    pub cancel: Arc<AtomicBool>,
    pub progress: Arc<std::sync::atomic::AtomicU64>,
}

impl<R: Read> Read for Metered<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(io::Error::other("cancelled"));
        }
        let n = self.inner.read(buf)?;
        self.count += n as u64;
        self.progress.fetch_add(n as u64, Ordering::Relaxed);
        let used = self.progress.load(Ordering::Relaxed);
        if used > self.budget.load(Ordering::Relaxed) {
            return Err(io::Error::other("download budget exceeded (OSNT_ADSB_HISTORY_MAX_DOWNLOAD_MB); narrow the window"));
        }
        Ok(n)
    }
}

// ---- tar member index ----

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Index {
    pub variant: String,
    pub archive_size: u64,
    /// (half hour 0..47, data offset, data size)
    pub entries: Vec<(u8, u64, u64)>,
    pub next: u64,
    pub done: bool,
    pub seen_heatmap: bool,
    /// Already bisected past a leading traces/ directory.
    #[serde(default)]
    pub jumped: bool,
}

impl Index {
    pub fn find(&self, hh: u8) -> Option<(u64, u64)> {
        self.entries.iter().find(|e| e.0 == hh).map(|e| (e.1, e.2))
    }
}

fn octal(b: &[u8]) -> Option<u64> {
    if b.first().is_some_and(|c| c & 0x80 != 0) {
        return Some(b.iter().enumerate().fold(0u64, |a, (i, c)| (a << 8) | (if i == 0 { c & 0x7f } else { *c }) as u64));
    }
    let s: String = b.iter().take_while(|c| **c != 0).map(|c| *c as char).collect();
    u64::from_str_radix(s.trim(), 8).ok()
}

/// "heatmap/07.bin.ttf" -> Some(7)
fn heatmap_slot(name: &str) -> Option<u8> {
    let n = name.trim_start_matches("./").strip_prefix("heatmap/")?.strip_suffix(".bin.ttf")?;
    n.parse::<u8>().ok().filter(|v| *v < 48 && n.len() == 2)
}

pub struct Hdr {
    pub name: String,
    pub size: u64,
    pub typeflag: u8,
}

/// A 512-byte block is a tar header only if the ustar magic, a sane name and the header checksum all agree (the checksum
/// makes false positives inside compressed member data practically impossible).
pub fn parse_header(h: &[u8]) -> Option<Hdr> {
    if h.len() < 512 || &h[257..262] != b"ustar" {
        return None;
    }
    let stored = octal(&h[148..156])?;
    let sum: u64 = h.iter().enumerate().map(|(i, b)| if (148..156).contains(&i) { 32 } else { *b as u64 }).sum();
    if stored != sum {
        return None;
    }
    let mut name = String::from_utf8_lossy(&h[0..100]).trim_end_matches('\0').to_string();
    let prefix = String::from_utf8_lossy(&h[345..500]).trim_end_matches('\0').to_string();
    if !prefix.is_empty() {
        name = format!("{prefix}/{name}");
    }
    if name.is_empty() || !name.bytes().all(|c| (0x20..0x7f).contains(&c)) {
        return None;
    }
    Some(Hdr { name, size: octal(&h[124..136])?, typeflag: h[156] })
}

fn is_trace(name: &str) -> bool {
    name.trim_start_matches("./").starts_with("traces/")
}

/// Days whose tar lists `traces/` (thousands of tiny files, ~2.5 GB) before `heatmap/` cannot be hopped through. The
/// heatmap directory then sits after all of them, so bisect (reading `window` bytes per probe) for the end of the traces
/// region, using "this window contains a traces/ header" as a monotone test, and resume hopping from the last trace
/// header of the last positive window. Returns the offset of a trace member header.
fn jump_past_traces(up: &Arc<Upstream>, a: &Archive, from: u64, window: u64, cancel: &AtomicBool) -> R<u64> {
    let total = a.total();
    let scan = |at: u64| -> R<Option<u64>> {
        // last traces/ header at a block boundary inside [at, at+window)
        let len = window.min(total - at);
        let buf = up.read_bytes(a, at, len)?;
        Ok(buf.chunks_exact(512).enumerate().rev().find(|(_, b)| parse_header(b).is_some_and(|h| is_trace(&h.name) && h.typeflag != b'5')).map(|(i, _)| at + i as u64 * 512))
    };
    let (mut lo, mut hi) = (from, total);
    let mut best = from;
    for _ in 0..40 {
        if hi.saturating_sub(lo) <= window || cancel.load(Ordering::Relaxed) {
            break;
        }
        let mid = (lo + (hi - lo) / 2) / 512 * 512;
        match scan(mid)? {
            Some(h) => { lo = mid; best = h; }
            None => hi = mid,
        }
    }
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    if let Some(h) = scan(lo)? {
        best = h;
    }
    Ok(best)
}

/// Hop over tar headers (one 512-byte Range request each, one at a time) until every needed half hour is located or the
/// heatmap directory has ended. Resumes from `idx.next`, so a later job continues where an earlier one stopped.
pub fn extend_index(up: &Arc<Upstream>, a: &Archive, idx: &mut Index, needed: &HashSet<u8>, window: u64, delay: Duration, cancel: &AtomicBool, on_hop: &mut dyn FnMut(&Index)) -> R<()> {
    let total = a.total();
    let mut hops = 0;
    while !idx.done && !needed.iter().all(|h| idx.find(*h).is_some()) {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        hops += 1;
        if hops > 1500 {
            return Err("tar index scan exceeded 1500 headers; archive layout unexpected".into());
        }
        if idx.next + 512 > total {
            idx.done = true;
            break;
        }
        let blk = up.read_bytes(a, idx.next, 512)?;
        if blk.iter().all(|b| *b == 0) {
            idx.done = true;
            break;
        }
        let h = parse_header(&blk).ok_or_else(|| format!("no tar header at offset {} (archive layout unexpected)", idx.next))?;
        let data = idx.next + 512;
        if h.typeflag == b'0' || h.typeflag == 0 {
            if let Some(hh) = heatmap_slot(&h.name) {
                idx.seen_heatmap = true;
                if idx.find(hh).is_none() {
                    idx.entries.push((hh, data, h.size));
                }
            } else if is_trace(&h.name) && !idx.seen_heatmap && !idx.jumped {
                idx.jumped = true;
                let to = jump_past_traces(up, a, idx.next, window, cancel)?;
                if to > idx.next {
                    idx.next = to;
                    on_hop(idx);
                    continue;
                }
            } else if idx.seen_heatmap && !h.name.trim_start_matches("./").starts_with("heatmap") && !is_trace(&h.name) {
                idx.done = true;
                on_hop(idx);
                break;
            } else if idx.seen_heatmap && is_trace(&h.name) {
                idx.done = true; // heatmap/ is followed by traces/: nothing more to find
                on_hop(idx);
                break;
            }
        }
        idx.next = data + h.size.div_ceil(512) * 512;
        on_hop(idx);
        std::thread::sleep(delay);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names_and_sizes() {
        assert_eq!(heatmap_slot("./heatmap/07.bin.ttf"), Some(7));
        assert_eq!(heatmap_slot("heatmap/47.bin.ttf"), Some(47));
        assert_eq!(heatmap_slot("./heatmap/48.bin.ttf"), None);
        assert_eq!(heatmap_slot("./traces/00/x"), None);
        assert_eq!(octal(b"00000000040\0"), Some(32));
        assert_eq!(host_of("https://a.b/c?d"), "a.b");
    }
}

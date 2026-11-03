//! Tiny on-disk TTL cache with size-bounded eviction. Entries are small documents (upstream feed responses,
//! never mirrored datasets. Each file stores its key on the first line so hash collisions are harmless.

use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime},
};

pub struct DiskCache {
    dir: PathBuf,
    max_bytes: u64,
    writes: AtomicU64,
}

fn fnv(key: &str) -> u64 {
    key.bytes().fold(0xcbf29ce484222325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100000001b3))
}

impl DiskCache {
    pub fn new(dir: PathBuf, max_bytes: u64) -> Self {
        let _ = fs::create_dir_all(&dir);
        let c = DiskCache { dir, max_bytes, writes: AtomicU64::new(0) };
        c.evict(); // startup cleanup: drop stale files and enforce the size cap
        c
    }

    fn path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{:016x}.cache", fnv(key)))
    }

    /// Returns the cached body when it is younger than `ttl`.
    pub fn get(&self, key: &str, ttl: Duration) -> Option<Vec<u8>> {
        let p = self.path(key);
        let age = SystemTime::now().duration_since(fs::metadata(&p).ok()?.modified().ok()?).unwrap_or_default();
        if age > ttl {
            return None;
        }
        let raw = fs::read(&p).ok()?;
        let nl = raw.iter().position(|&b| b == b'\n')?;
        (&raw[..nl] == key.as_bytes()).then(|| raw[nl + 1..].to_vec())
    }

    pub fn put(&self, key: &str, body: &[u8]) {
        let mut raw = Vec::with_capacity(key.len() + 1 + body.len());
        raw.extend_from_slice(key.as_bytes());
        raw.push(b'\n');
        raw.extend_from_slice(body);
        let p = self.path(key);
        let tmp = p.with_extension("tmp");
        if fs::write(&tmp, raw).is_ok() {
            let _ = fs::rename(&tmp, &p);
        }
        if self.writes.fetch_add(1, Ordering::Relaxed) % 16 == 15 {
            self.evict();
        }
    }

    /// Drops anything older than a day, then the oldest files until the directory fits `max_bytes`.
    pub fn evict(&self) {
        let Ok(rd) = fs::read_dir(&self.dir) else { return };
        let now = SystemTime::now();
        let mut files: Vec<(SystemTime, u64, PathBuf)> = Vec::new();
        for e in rd.flatten() {
            let Ok(m) = e.metadata() else { continue };
            let t = m.modified().unwrap_or(now);
            if now.duration_since(t).unwrap_or_default() > Duration::from_secs(86_400) {
                let _ = fs::remove_file(e.path());
            } else {
                files.push((t, m.len(), e.path()));
            }
        }
        let mut total: u64 = files.iter().map(|f| f.1).sum();
        files.sort_by_key(|f| f.0);
        for (_, len, path) in files {
            if total <= self.max_bytes {
                break;
            }
            if fs::remove_file(path).is_ok() {
                total -= len;
            }
        }
    }
}

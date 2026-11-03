//! Small TTL cache for upstream responses. Values are bytes keyed by a string. With a state directory they live on disk
//! (one file per key, size-capped, trimmed at startup); without one they live in memory with an entry cap.

use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant, SystemTime},
};

pub struct Cache {
    dir: Option<PathBuf>,
    mem: Mutex<HashMap<String, (Instant, Vec<u8>)>>,
    max_bytes: u64,
    max_entries: usize,
    puts: Mutex<u32>,
}

fn fnv(key: &str) -> u64 {
    key.bytes().fold(0xcbf29ce484222325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100000001b3))
}

impl Cache {
    pub fn new(dir: Option<PathBuf>, max_bytes: u64) -> Self {
        if let Some(d) = &dir {
            let _ = fs::create_dir_all(d);
        }
        Cache { dir, mem: Mutex::new(HashMap::new()), max_bytes, max_entries: 256, puts: Mutex::new(0) }
    }

    fn path(&self, key: &str) -> Option<PathBuf> {
        self.dir.as_ref().map(|d| d.join(format!("{:016x}.c", fnv(key))))
    }

    fn read(&self, key: &str) -> Option<(Duration, Vec<u8>)> {
        if let Some(p) = self.path(key) {
            let bytes = fs::read(&p).ok()?;
            let nl = bytes.iter().position(|b| *b == b'\n')?;
            if &bytes[..nl] != key.as_bytes() {
                return None; // hash collision: treat as a miss
            }
            let age = fs::metadata(&p).and_then(|m| m.modified()).ok().and_then(|t| SystemTime::now().duration_since(t).ok()).unwrap_or_default();
            return Some((age, bytes[nl + 1..].to_vec()));
        }
        let m = self.mem.lock().ok()?;
        m.get(key).map(|(t, v)| (t.elapsed(), v.clone()))
    }

    /// A value younger than `ttl`.
    pub fn get(&self, key: &str, ttl: Duration) -> Option<Vec<u8>> {
        self.read(key).filter(|(age, _)| *age <= ttl).map(|(_, v)| v)
    }

    /// Any stored value however old; used to keep serving something when the upstream is down.
    pub fn get_stale(&self, key: &str) -> Option<Vec<u8>> {
        self.read(key).map(|(_, v)| v)
    }

    pub fn put(&self, key: &str, val: &[u8]) {
        if let Some(p) = self.path(key) {
            let mut data = Vec::with_capacity(key.len() + 1 + val.len());
            data.extend_from_slice(key.as_bytes());
            data.push(b'\n');
            data.extend_from_slice(val);
            let tmp = p.with_extension("tmp");
            if fs::write(&tmp, &data).and_then(|_| fs::rename(&tmp, &p)).is_err() {
                let _ = fs::remove_file(&tmp);
            }
            let trim = self.puts.lock().map(|mut n| { *n += 1; *n % 32 == 0 }).unwrap_or(false);
            if trim {
                self.trim(Duration::from_secs(7 * 86400));
            }
        } else if let Ok(mut m) = self.mem.lock() {
            m.insert(key.to_string(), (Instant::now(), val.to_vec()));
            while m.len() > self.max_entries {
                let oldest = m.iter().min_by_key(|(_, (t, _))| *t).map(|(k, _)| k.clone());
                match oldest {
                    Some(k) => { m.remove(&k); }
                    None => break,
                }
            }
        }
    }

    /// Delete files older than `max_age`, then the oldest files until the directory is under the size cap.
    pub fn trim(&self, max_age: Duration) {
        let Some(dir) = &self.dir else { return };
        let Ok(rd) = fs::read_dir(dir) else { return };
        let mut files: Vec<(SystemTime, u64, PathBuf)> = Vec::new();
        for e in rd.flatten() {
            let p = e.path();
            let Ok(md) = e.metadata() else { continue };
            if !md.is_file() {
                continue;
            }
            let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
            if ext != "c" {
                if ext == "tmp" {
                    let _ = fs::remove_file(&p);
                }
                continue;
            }
            files.push((md.modified().unwrap_or(SystemTime::UNIX_EPOCH), md.len(), p));
        }
        let now = SystemTime::now();
        files.retain(|(t, _, p)| {
            let old = now.duration_since(*t).map(|a| a > max_age).unwrap_or(false);
            if old {
                let _ = fs::remove_file(p);
            }
            !old
        });
        files.sort_by_key(|(t, _, _)| *t);
        let mut total: u64 = files.iter().map(|(_, n, _)| *n).sum();
        for (_, n, p) in &files {
            if total <= self.max_bytes {
                break;
            }
            if fs::remove_file(p).is_ok() {
                total -= n;
            }
        }
    }

    /// Bytes currently stored on disk (0 for the in-memory cache); used by tests and diagnostics.
    #[allow(dead_code)]
    pub fn disk_bytes(&self) -> u64 {
        let Some(dir) = &self.dir else { return 0 };
        fs::read_dir(dir).map(|rd| rd.flatten().filter_map(|e| e.metadata().ok()).filter(|m| m.is_file()).map(|m| m.len()).sum()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("osnt-cache-test-{}-{}-{}", name, std::process::id(), fnv(name)));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn memory_roundtrip_and_ttl() {
        let c = Cache::new(None, 1000);
        assert!(c.get("a", Duration::from_secs(60)).is_none());
        c.put("a", b"hello");
        assert_eq!(c.get("a", Duration::from_secs(60)).unwrap(), b"hello");
        std::thread::sleep(Duration::from_millis(30));
        assert!(c.get("a", Duration::from_millis(5)).is_none(), "expired for a short ttl");
        assert_eq!(c.get_stale("a").unwrap(), b"hello", "stale read ignores ttl");
    }

    #[test]
    fn memory_evicts_oldest_over_cap() {
        let c = Cache::new(None, 1000);
        for i in 0..300 {
            c.put(&format!("k{i}"), b"x");
        }
        assert!(c.mem.lock().unwrap().len() <= 256);
        assert!(c.get("k299", Duration::from_secs(60)).is_some());
        assert!(c.get("k0", Duration::from_secs(60)).is_none());
    }

    #[test]
    fn disk_roundtrip_survives_new_instance() {
        let d = tmp("rt");
        Cache::new(Some(d.clone()), 1 << 20).put("key one", b"{\"a\":1}\nwith newline");
        let c2 = Cache::new(Some(d.clone()), 1 << 20);
        assert_eq!(c2.get("key one", Duration::from_secs(60)).unwrap(), b"{\"a\":1}\nwith newline");
        assert!(c2.get("key two", Duration::from_secs(60)).is_none());
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn disk_trim_enforces_size_cap_and_age() {
        let d = tmp("trim");
        let c = Cache::new(Some(d.clone()), 2500);
        for i in 0..10 {
            c.put(&format!("k{i}"), &vec![b'z'; 1000]);
            std::thread::sleep(Duration::from_millis(15));
        }
        c.trim(Duration::from_secs(3600));
        assert!(c.disk_bytes() <= 2500, "size cap respected, got {}", c.disk_bytes());
        assert!(c.get("k9", Duration::from_secs(60)).is_some(), "newest entry kept");
        assert!(c.get("k0", Duration::from_secs(60)).is_none(), "oldest entry evicted");
        std::thread::sleep(Duration::from_millis(30));
        c.trim(Duration::from_millis(1));
        assert_eq!(c.disk_bytes(), 0, "everything is older than max_age");
        let _ = fs::remove_dir_all(d);
    }
}

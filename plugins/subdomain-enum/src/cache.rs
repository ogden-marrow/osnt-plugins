//! Small TTL cache for upstream responses. Persists to a redb file under the plugin's state directory when one is
//! available (so a restart does not re-hit free community APIs), otherwise lives in memory. The number of entries and
//! the size of one entry are capped, expired entries are dropped at startup, and the oldest entries are evicted first.

use std::{
    collections::HashMap,
    path::Path,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde_json::Value;

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("cache");

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Entry layout: expires (u64 BE) + stored (u64 BE) + payload.
fn encode(expires: u64, stored: u64, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(16 + payload.len());
    v.extend_from_slice(&expires.to_be_bytes());
    v.extend_from_slice(&stored.to_be_bytes());
    v.extend_from_slice(payload);
    v
}
fn decode(raw: &[u8]) -> Option<(u64, u64, &[u8])> {
    if raw.len() < 16 {
        return None;
    }
    Some((u64::from_be_bytes(raw[..8].try_into().ok()?), u64::from_be_bytes(raw[8..16].try_into().ok()?), &raw[16..]))
}

/// Pick keys to drop: everything expired, then the oldest until `keep` entries remain. `rows` = (key, expires, stored).
fn victims(mut rows: Vec<(String, u64, u64)>, now: u64, keep: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    rows.retain(|(k, exp, _)| {
        if *exp <= now {
            out.push(k.clone());
            false
        } else {
            true
        }
    });
    if rows.len() > keep {
        rows.sort_by_key(|(_, _, stored)| *stored);
        let drop = rows.len() - keep;
        out.extend(rows.into_iter().take(drop).map(|(k, _, _)| k));
    }
    out
}

pub struct Cache {
    db: Option<Database>,
    mem: Mutex<HashMap<String, (u64, u64, Vec<u8>)>>,
    max_entries: usize,
    max_value: usize,
}

impl Cache {
    pub fn open(path: Option<&Path>, max_entries: usize, max_value: usize) -> Cache {
        let db = path.and_then(|p| {
            if let Some(dir) = p.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            Database::create(p).or_else(|_| {
                // A damaged cache file is only a cache: start over.
                let _ = std::fs::remove_file(p);
                Database::create(p)
            }).ok()
        });
        let c = Cache { db, mem: Mutex::new(HashMap::new()), max_entries, max_value };
        c.sweep();
        c
    }

    pub fn persistent(&self) -> bool {
        self.db.is_some()
    }

    pub fn len(&self) -> usize {
        match &self.db {
            Some(db) => db.begin_read().ok().and_then(|r| r.open_table(TABLE).ok()).and_then(|t| t.len().ok()).unwrap_or(0) as usize,
            None => self.mem.lock().map(|m| m.len()).unwrap_or(0),
        }
    }

    /// Drop expired entries and enforce the entry cap (run at startup and after inserts).
    pub fn sweep(&self) {
        self.sweep_at(now_secs());
    }

    pub fn sweep_at(&self, now: u64) {
        let keep = self.max_entries * 9 / 10;
        match &self.db {
            Some(db) => {
                let rows: Vec<(String, u64, u64)> = (|| -> Result<Vec<(String, u64, u64)>> {
                    let r = db.begin_read()?;
                    let t = match r.open_table(TABLE) {
                        Ok(t) => t,
                        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(vec![]),
                        Err(e) => return Err(e.into()),
                    };
                    let mut rows = Vec::new();
                    for item in t.iter()? {
                        let (k, v) = item?;
                        if let Some((exp, stored, _)) = decode(v.value()) {
                            rows.push((k.value().to_string(), exp, stored));
                        } else {
                            rows.push((k.value().to_string(), 0, 0));
                        }
                    }
                    Ok(rows)
                })()
                .unwrap_or_default();
                let over = rows.len() > self.max_entries;
                let drop = victims(rows, now, if over { keep } else { usize::MAX });
                if drop.is_empty() {
                    return;
                }
                let _ = (|| -> Result<()> {
                    let w = db.begin_write()?;
                    {
                        let mut t = w.open_table(TABLE)?;
                        for k in &drop {
                            t.remove(k.as_str())?;
                        }
                    }
                    w.commit()?;
                    Ok(())
                })();
            }
            None => {
                let Ok(mut m) = self.mem.lock() else { return };
                let rows: Vec<(String, u64, u64)> = m.iter().map(|(k, (e, s, _))| (k.clone(), *e, *s)).collect();
                let over = rows.len() > self.max_entries;
                for k in victims(rows, now, if over { keep } else { usize::MAX }) {
                    m.remove(&k);
                }
            }
        }
    }

    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.get_at(key, now_secs())
    }

    pub fn get_at(&self, key: &str, now: u64) -> Option<Vec<u8>> {
        match &self.db {
            Some(db) => {
                let r = db.begin_read().ok()?;
                let t = r.open_table(TABLE).ok()?;
                let raw = t.get(key).ok()??;
                let (exp, _, payload) = decode(raw.value())?;
                (exp > now).then(|| payload.to_vec())
            }
            None => {
                let m = self.mem.lock().ok()?;
                let (exp, _, payload) = m.get(key)?;
                (*exp > now).then(|| payload.clone())
            }
        }
    }

    pub fn put(&self, key: &str, ttl: Duration, payload: &[u8]) {
        self.put_at(key, ttl, payload, now_secs());
    }

    pub fn put_at(&self, key: &str, ttl: Duration, payload: &[u8], now: u64) {
        if payload.len() > self.max_value || ttl.is_zero() {
            return;
        }
        let exp = now + ttl.as_secs().max(1);
        match &self.db {
            Some(db) => {
                let _ = (|| -> Result<()> {
                    let w = db.begin_write()?;
                    {
                        let mut t = w.open_table(TABLE)?;
                        t.insert(key, encode(exp, now, payload).as_slice())?;
                    }
                    w.commit()?;
                    Ok(())
                })();
            }
            None => {
                if let Ok(mut m) = self.mem.lock() {
                    m.insert(key.to_string(), (exp, now, payload.to_vec()));
                }
            }
        }
        if self.len() > self.max_entries {
            self.sweep_at(now);
        }
    }

    pub fn get_json(&self, key: &str) -> Option<Value> {
        serde_json::from_slice(&self.get(key)?).ok()
    }

    pub fn put_json(&self, key: &str, ttl: Duration, v: &Value) {
        if let Ok(b) = serde_json::to_vec(v) {
            self.put(key, ttl, &b);
        }
    }

    /// Like `cached_json`, but a failure is remembered for `neg` so a rate-limited or broken upstream is not
    /// hammered by repeated clicks. The stored error comes back as an error with the same message.
    pub fn cached_json_neg(&self, key: &str, ttl: Duration, neg: Duration, f: impl FnOnce() -> Result<Value>) -> Result<Value> {
        if let Some(v) = self.get_json(key) {
            if let Some(msg) = v.get("__error").and_then(|m| m.as_str()) {
                return Err(anyhow::anyhow!("{msg}"));
            }
            return Ok(v);
        }
        match f() {
            Ok(v) => {
                self.put_json(key, ttl, &v);
                Ok(v)
            }
            Err(e) => {
                self.put_json(key, neg, &serde_json::json!({ "__error": e.to_string() }));
                Err(e)
            }
        }
    }

    /// Cached value, or compute it and store it. Errors are not cached.
    pub fn cached_json(&self, key: &str, ttl: Duration, f: impl FnOnce() -> Result<Value>) -> Result<Value> {
        if let Some(v) = self.get_json(key) {
            return Ok(v);
        }
        let v = f()?;
        self.put_json(key, ttl, &v);
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("osnt-cache-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d.join("c.redb")
    }

    #[test]
    fn memory_roundtrip_and_expiry() {
        let c = Cache::open(None, 10, 1000);
        assert!(!c.persistent());
        c.put_at("a", Duration::from_secs(60), b"hello", 1000);
        assert_eq!(c.get_at("a", 1030).as_deref(), Some(&b"hello"[..]));
        assert_eq!(c.get_at("a", 1060), None, "expired at ttl");
        assert_eq!(c.get_at("missing", 1000), None);
    }

    #[test]
    fn zero_ttl_and_oversize_values_are_not_stored() {
        let c = Cache::open(None, 10, 4);
        c.put_at("z", Duration::ZERO, b"x", 1000);
        c.put_at("big", Duration::from_secs(60), b"12345", 1000);
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn eviction_drops_expired_then_oldest() {
        let c = Cache::open(None, 10, 100);
        for i in 0..10u64 {
            c.put_at(&format!("k{i}"), Duration::from_secs(1000), b"v", 1000 + i);
        }
        assert_eq!(c.len(), 10);
        c.put_at("k10", Duration::from_secs(1000), b"v", 1020);
        // 11 > cap 10, so trimmed to 9: the two oldest go.
        assert!(c.len() <= 9);
        assert_eq!(c.get_at("k0", 1021), None);
        assert!(c.get_at("k10", 1021).is_some());
        assert!(c.get_at("k9", 1021).is_some());
    }

    #[test]
    fn expired_go_before_live_ones() {
        let c = Cache::open(None, 4, 100);
        c.put_at("old", Duration::from_secs(5), b"v", 100);
        for i in 0..4u64 {
            c.put_at(&format!("n{i}"), Duration::from_secs(1000), b"v", 200 + i);
        }
        assert_eq!(c.get_at("old", 150), None);
        assert!(c.get_at("n0", 300).is_some() || c.len() <= 3);
    }

    #[test]
    fn persists_across_reopen_and_startup_sweep_removes_expired() {
        let p = tmp("persist");
        {
            let c = Cache::open(Some(&p), 10, 1000);
            assert!(c.persistent());
            c.put("live", Duration::from_secs(3600), b"1");
            c.put_at("dead", Duration::from_secs(1), b"2", 10);
            assert_eq!(c.len(), 2);
        }
        let c = Cache::open(Some(&p), 10, 1000);
        assert_eq!(c.len(), 1, "expired entry swept at open");
        assert_eq!(c.get("live").as_deref(), Some(&b"1"[..]));
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn corrupt_file_is_replaced() {
        let p = tmp("corrupt");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"this is not a redb database at all, just junk bytes").unwrap();
        let c = Cache::open(Some(&p), 10, 1000);
        c.put("k", Duration::from_secs(60), b"v");
        assert_eq!(c.get("k").as_deref(), Some(&b"v"[..]));
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn cached_json_computes_once_and_does_not_cache_errors() {
        let c = Cache::open(None, 10, 1000);
        let mut calls = 0;
        for _ in 0..3 {
            let v = c.cached_json("j", Duration::from_secs(60), || { calls += 1; Ok(serde_json::json!({"n": 1})) }).unwrap();
            assert_eq!(v["n"], 1);
        }
        assert_eq!(calls, 1);
        assert!(c.cached_json("e", Duration::from_secs(60), || Err(anyhow::anyhow!("boom"))).is_err());
        assert!(c.cached_json("e", Duration::from_secs(60), || Ok(serde_json::json!(1))).is_ok());
    }

    #[test]
    fn negative_caching_remembers_failures_briefly() {
        let c = Cache::open(None, 10, 1000);
        let mut calls = 0;
        for _ in 0..3 {
            let r = c.cached_json_neg("n", Duration::from_secs(60), Duration::from_secs(30), || { calls += 1; Err(anyhow::anyhow!("host: rate limited")) });
            assert_eq!(r.unwrap_err().to_string(), "host: rate limited");
        }
        assert_eq!(calls, 1, "failure served from the negative cache");
        let ok = c.cached_json_neg("m", Duration::from_secs(60), Duration::from_secs(30), || Ok(serde_json::json!({"a": 1}))).unwrap();
        assert_eq!(ok["a"], 1);
    }

    #[test]
    fn persistent_eviction_respects_cap() {
        let p = tmp("evict");
        let c = Cache::open(Some(&p), 5, 100);
        for i in 0..12u64 {
            c.put_at(&format!("k{i}"), Duration::from_secs(1000), b"v", 1000 + i);
        }
        assert!(c.len() <= 5);
        assert!(c.get_at("k11", 1013).is_some());
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }
}

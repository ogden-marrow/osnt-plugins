//! On-disk slices (compact binary, short-lived) and the cleanup that keeps the state dir small.
//!
//! state/slices/<id>.bin   magic, u32 meta length, meta JSON, then 20-byte records
//! state/index/<day>.json  tar member offsets for a day (a few KB; saves ~50 header hops)
//! state/tmp/              half-written files; emptied at startup, files removed on error
//! Eviction: anything not used for `ttl` goes (reads refresh the mtime); then oldest-first until under the size cap.

use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use serde::{Deserialize, Serialize};

const MAGIC: &[u8; 8] = b"OSNTADH1";
pub const REC_LEN: usize = 20;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Params {
    pub date: String,
    pub from_s: u32,
    pub to_s: u32,
    pub bbox: Option<[f64; 4]>, // west, south, east, north
    pub hex: Vec<String>,
    pub callsign: Option<String>,
    pub step: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AcMeta {
    pub hex: String,
    pub callsign: Option<String>,
    pub squawk: Option<u16>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SliceMeta {
    pub id: String,
    pub params: Params,
    pub variant: String,
    pub created: u64,
    pub points: u64,
    pub truncated: bool,
    pub bytes_downloaded: u64,
    /// Half hours (HH:MM UTC) the archive did not contain.
    pub missing: Vec<String>,
    pub aircraft: Vec<AcMeta>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rec {
    pub ac: u32,
    pub t: u32,
    pub lat: i32,
    pub lon: i32,
    pub alt: i16,
    pub gs: i16,
}

#[derive(Clone)]
pub struct Store {
    pub root: PathBuf,
}

pub fn now_s() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Store {
    pub fn new(root: PathBuf) -> std::io::Result<Self> {
        for d in ["slices", "index", "tmp"] {
            fs::create_dir_all(root.join(d))?;
        }
        Ok(Self { root })
    }
    pub fn slice_path(&self, id: &str) -> PathBuf {
        self.root.join("slices").join(format!("{id}.bin"))
    }
    pub fn index_path(&self, key: &str) -> PathBuf {
        self.root.join("index").join(format!("{key}.json"))
    }
    pub fn tmp_path(&self, name: &str) -> PathBuf {
        self.root.join("tmp").join(name)
    }

    /// Startup cleanup: drop every temp file, then apply TTL and size cap.
    pub fn startup(&self, ttl: Duration, cap: u64) {
        if let Ok(rd) = fs::read_dir(self.root.join("tmp")) {
            for e in rd.flatten() {
                let _ = fs::remove_file(e.path());
            }
        }
        // anything else unexpected in slices/ (e.g. a stray .part) goes too
        if let Ok(rd) = fs::read_dir(self.root.join("slices")) {
            for e in rd.flatten() {
                if e.path().extension().is_none_or(|x| x != "bin") {
                    let _ = fs::remove_file(e.path());
                }
            }
        }
        self.evict(ttl, cap, None);
    }

    pub fn write_slice(&self, meta: &SliceMeta, recs: &[Rec]) -> std::io::Result<u64> {
        let tmp = self.tmp_path(&format!("{}.part", meta.id));
        let guard = TmpGuard(tmp.clone());
        let mut f = std::io::BufWriter::new(fs::File::create(&tmp)?);
        let m = serde_json::to_vec(meta)?;
        f.write_all(MAGIC)?;
        f.write_all(&(m.len() as u32).to_le_bytes())?;
        f.write_all(&m)?;
        for r in recs {
            f.write_all(&r.ac.to_le_bytes())?;
            f.write_all(&r.t.to_le_bytes())?;
            f.write_all(&r.lat.to_le_bytes())?;
            f.write_all(&r.lon.to_le_bytes())?;
            f.write_all(&r.alt.to_le_bytes())?;
            f.write_all(&r.gs.to_le_bytes())?;
        }
        f.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        fs::rename(&tmp, self.slice_path(&meta.id))?;
        std::mem::forget(guard);
        Ok(fs::metadata(self.slice_path(&meta.id))?.len())
    }

    pub fn read_meta(&self, id: &str) -> Option<SliceMeta> {
        let mut f = fs::File::open(self.slice_path(id)).ok()?;
        read_header(&mut f)
    }

    /// Whole slice. Touches the file so active slices do not expire.
    pub fn read_slice(&self, id: &str) -> Option<(SliceMeta, Vec<Rec>)> {
        let p = self.slice_path(id);
        let mut f = fs::File::open(&p).ok()?;
        let meta = read_header(&mut f)?;
        let mut body = Vec::new();
        f.read_to_end(&mut body).ok()?;
        let _ = f.set_modified(SystemTime::now());
        let recs = body
            .chunks_exact(REC_LEN)
            .map(|c| Rec {
                ac: u32::from_le_bytes(c[0..4].try_into().unwrap()),
                t: u32::from_le_bytes(c[4..8].try_into().unwrap()),
                lat: i32::from_le_bytes(c[8..12].try_into().unwrap()),
                lon: i32::from_le_bytes(c[12..16].try_into().unwrap()),
                alt: i16::from_le_bytes(c[16..18].try_into().unwrap()),
                gs: i16::from_le_bytes(c[18..20].try_into().unwrap()),
            })
            .collect();
        Some((meta, recs))
    }

    pub fn delete_slice(&self, id: &str) -> bool {
        fs::remove_file(self.slice_path(id)).is_ok()
    }

    pub fn list(&self) -> Vec<(SliceMeta, u64, u64)> {
        let mut out = vec![];
        if let Ok(rd) = fs::read_dir(self.root.join("slices")) {
            for e in rd.flatten() {
                let Some(id) = e.path().file_stem().map(|s| s.to_string_lossy().to_string()) else { continue };
                if let (Some(m), Ok(md)) = (self.read_meta(&id), e.metadata()) {
                    let mt = md.modified().ok().and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
                    out.push((m, md.len(), mt));
                }
            }
        }
        out.sort_by(|a, b| b.2.cmp(&a.2));
        out
    }

    /// (slice bytes, index bytes)
    pub fn usage(&self) -> (u64, u64) {
        (dir_size(&self.root.join("slices")), dir_size(&self.root.join("index")) + dir_size(&self.root.join("tmp")))
    }

    /// TTL eviction (slices after `ttl` unused, index files after max(ttl, 24 h)), then the size cap, oldest first.
    /// `keep` is never removed (the slice that was just written). Returns the number of files removed.
    pub fn evict(&self, ttl: Duration, cap: u64, keep: Option<&str>) -> usize {
        let now = SystemTime::now();
        let mut removed = 0;
        let mut files: Vec<(PathBuf, SystemTime, u64)> = vec![];
        for (dir, life) in [("slices", ttl), ("index", ttl.max(Duration::from_secs(86400)))] {
            let Ok(rd) = fs::read_dir(self.root.join(dir)) else { continue };
            for e in rd.flatten() {
                let Ok(md) = e.metadata() else { continue };
                let mt = md.modified().unwrap_or(now);
                let is_keep = keep.is_some_and(|k| e.path().file_stem().is_some_and(|s| s == k));
                if !is_keep && now.duration_since(mt).unwrap_or_default() > life {
                    if fs::remove_file(e.path()).is_ok() {
                        removed += 1;
                    }
                } else if dir == "slices" {
                    files.push((e.path(), mt, md.len()));
                }
            }
        }
        let mut total: u64 = files.iter().map(|f| f.2).sum();
        files.sort_by_key(|f| f.1);
        for (p, _, len) in files {
            if total <= cap {
                break;
            }
            if keep.is_some_and(|k| p.file_stem().is_some_and(|s| s == k)) {
                continue;
            }
            if fs::remove_file(&p).is_ok() {
                total -= len;
                removed += 1;
            }
        }
        removed
    }
}

struct TmpGuard(PathBuf);
impl Drop for TmpGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn read_header(f: &mut fs::File) -> Option<SliceMeta> {
    let mut h = [0u8; 12];
    f.read_exact(&mut h).ok()?;
    if &h[0..8] != MAGIC {
        return None;
    }
    let n = u32::from_le_bytes(h[8..12].try_into().unwrap()) as usize;
    if n > 64 << 20 {
        return None;
    }
    let mut m = vec![0u8; n];
    f.read_exact(&mut m).ok()?;
    serde_json::from_slice(&m).ok()
}

fn dir_size(p: &Path) -> u64 {
    fs::read_dir(p).map(|rd| rd.flatten().filter_map(|e| e.metadata().ok()).map(|m| m.len()).sum()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(n: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("adsbh-{n}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        p
    }
    fn meta(id: &str) -> SliceMeta {
        SliceMeta { id: id.into(), params: Params { date: "2025-01-01".into(), from_s: 0, to_s: 60, bbox: None, hex: vec![], callsign: None, step: 10 }, variant: "prod".into(), created: 1, points: 1, truncated: false, bytes_downloaded: 0, missing: vec![], aircraft: vec![AcMeta { hex: "abc123".into(), callsign: None, squawk: None }] }
    }

    #[test]
    fn roundtrip_and_cleanup() {
        let d = tmpdir("rt");
        let s = Store::new(d.clone()).unwrap();
        let r = Rec { ac: 0, t: 5, lat: -1, lon: 2, alt: -123, gs: 7 };
        s.write_slice(&meta("aaaa"), &[r]).unwrap();
        let (m, recs) = s.read_slice("aaaa").unwrap();
        assert_eq!(m.id, "aaaa");
        assert_eq!(recs, vec![r]);
        assert!(fs::read_dir(d.join("tmp")).unwrap().next().is_none(), "no temp file left behind");

        // startup removes stray temp files
        fs::write(d.join("tmp/x.part"), b"junk").unwrap();
        fs::write(d.join("slices/y.part"), b"junk").unwrap();
        s.startup(Duration::from_secs(3600), u64::MAX);
        assert!(!d.join("tmp/x.part").exists() && !d.join("slices/y.part").exists());
        assert!(s.slice_path("aaaa").exists());

        // TTL
        let f = fs::File::open(s.slice_path("aaaa")).unwrap();
        f.set_modified(SystemTime::now() - Duration::from_secs(7200)).unwrap();
        assert_eq!(s.evict(Duration::from_secs(3600), u64::MAX, None), 1);
        assert!(!s.slice_path("aaaa").exists());

        // size cap: oldest goes first, `keep` survives
        for (i, id) in ["b1", "b2", "b3"].iter().enumerate() {
            s.write_slice(&meta(id), &vec![r; 100]).unwrap();
            fs::File::open(s.slice_path(id)).unwrap().set_modified(SystemTime::now() - Duration::from_secs(100 - i as u64 * 10)).unwrap();
        }
        let one = fs::metadata(s.slice_path("b1")).unwrap().len();
        s.evict(Duration::from_secs(3600), one * 2, Some("b3"));
        assert!(!s.slice_path("b1").exists() && s.slice_path("b2").exists() && s.slice_path("b3").exists());
        let _ = fs::remove_dir_all(d);
    }
}

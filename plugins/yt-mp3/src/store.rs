//! On-disk job storage under the state dir: `jobs/<random id>/{out.mp3,meta.json}`, ids, cleanup.

use std::{
    collections::HashSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

pub const OUT_NAME: &str = "out.mp3";
pub const META_NAME: &str = "meta.json";

/// 128 random bits as 32 lowercase hex characters, from the kernel.
pub fn new_id() -> std::io::Result<String> {
    let mut b = [0u8; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Only ids we could have generated are ever turned into paths, so a download cannot traverse directories.
pub fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn jobs_root(state: &Path) -> PathBuf {
    state.join("jobs")
}

pub fn job_dir(state: &Path, id: &str) -> Option<PathBuf> {
    valid_id(id).then(|| jobs_root(state).join(id))
}

fn newest_mtime(dir: &Path) -> Option<SystemTime> {
    let mut newest = dir.metadata().ok()?.modified().ok()?;
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            if let Some(m) = e.metadata().ok().and_then(|m| m.modified().ok()) {
                newest = newest.max(m);
            }
        }
    }
    Some(newest)
}

/// Deletes job directories not modified for `ttl` (and anything in `jobs/` that is not a job directory), except ids
/// in `keep` (running jobs). Returns how many entries were removed.
pub fn cleanup(state: &Path, ttl: Duration, now: SystemTime, keep: &HashSet<String>) -> usize {
    let Ok(rd) = fs::read_dir(jobs_root(state)) else { return 0 };
    let mut removed = 0;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if keep.contains(&name) {
            continue;
        }
        let path = e.path();
        let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
        let stale_junk = !(is_dir && valid_id(&name));
        let expired = newest_mtime(&path).is_none_or(|m| now.duration_since(m).unwrap_or_default() >= ttl);
        if stale_junk || expired {
            let ok = if is_dir { fs::remove_dir_all(&path) } else { fs::remove_file(&path) };
            if ok.is_ok() {
                removed += 1;
            }
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_random_hex_and_validated() {
        let a = new_id().unwrap();
        assert!(valid_id(&a));
        assert_ne!(a, new_id().unwrap());
        for bad in ["", "..", "../etc/passwd", &"A".repeat(32), &"g".repeat(32), &"a".repeat(31), &format!("{}/", "a".repeat(31))] {
            assert!(!valid_id(bad), "{bad}");
            assert!(job_dir(Path::new("/s"), bad).is_none());
        }
        assert_eq!(job_dir(Path::new("/s"), &a).unwrap(), Path::new("/s/jobs").join(&a));
    }

    #[test]
    fn cleanup_removes_only_expired_and_junk() {
        let d = tempfile::tempdir().unwrap();
        let root = jobs_root(d.path());
        let (old, fresh, running) = ("a".repeat(32), "b".repeat(32), "c".repeat(32));
        for id in [&old, &fresh, &running] {
            fs::create_dir_all(root.join(id)).unwrap();
            fs::write(root.join(id).join(OUT_NAME), b"x").unwrap();
        }
        fs::write(root.join("stray.txt"), b"x").unwrap();
        let past = SystemTime::now() - Duration::from_secs(3 * 3600);
        for id in [&old, &running] {
            let f = fs::File::open(root.join(id).join(OUT_NAME)).unwrap();
            f.set_modified(past).unwrap();
            fs::File::open(root.join(id)).unwrap().set_modified(past).unwrap();
        }
        let keep: HashSet<String> = [running.clone()].into();
        let n = cleanup(d.path(), Duration::from_secs(7200), SystemTime::now(), &keep);
        assert_eq!(n, 2);
        assert!(!root.join(&old).exists());
        assert!(root.join(&fresh).exists());
        assert!(root.join(&running).exists(), "running jobs are kept");
        assert!(!root.join("stray.txt").exists());
        // Missing root is fine.
        assert_eq!(cleanup(&d.path().join("nope"), Duration::ZERO, SystemTime::now(), &keep), 0);
    }
}

//! Area watches: saved boxes that flag fire clusters not seen before. Stored as a small JSON file in the state dir.

use std::{path::PathBuf, sync::Mutex, time::Duration};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    Shared,
    firms::{self, haversine_km},
    util::{iso, now_secs},
};

pub const MAX_WATCHES: usize = 20;
const MAX_SEEN: usize = 600;
const SEEN_TTL: i64 = 14 * 86_400;
/// A cluster within this distance of one already seen is the same fire.
const SAME_FIRE_KM: f64 = 4.0;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Watch {
    pub id: String,
    pub name: String,
    pub bbox: [f64; 4],
    pub min_frp: f64,
    pub created: i64,
    /// (lat, lon, last seen unix time)
    pub seen: Vec<(f64, f64, i64)>,
    pub last_check: Option<i64>,
    pub last_error: Option<String>,
    pub last_total: usize,
    pub last_new: Vec<Value>,
    pub new_total: usize,
}

pub struct Store {
    path: PathBuf,
    items: Mutex<Vec<Watch>>,
}

impl Store {
    pub fn open(path: PathBuf) -> Self {
        if let Some(d) = path.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let items = std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        Store { path, items: Mutex::new(items) }
    }

    fn save(&self, items: &[Watch]) {
        let tmp = self.path.with_extension("tmp");
        if std::fs::write(&tmp, serde_json::to_vec(items).unwrap_or_default()).is_ok() {
            let _ = std::fs::rename(&tmp, &self.path);
        }
    }

    pub fn list(&self) -> Vec<Value> {
        self.items.lock().unwrap().iter().map(public).collect()
    }

    pub fn ids(&self) -> Vec<String> {
        self.items.lock().unwrap().iter().map(|w| w.id.clone()).collect()
    }

    pub fn get(&self, id: &str) -> Option<Watch> {
        self.items.lock().unwrap().iter().find(|w| w.id == id).cloned()
    }

    pub fn add(&self, name: String, bbox: [f64; 4], min_frp: f64) -> Result<String, String> {
        let mut g = self.items.lock().unwrap();
        if g.len() >= MAX_WATCHES {
            return Err(format!("at most {MAX_WATCHES} watches; delete one first"));
        }
        let now = now_secs();
        let id = format!("w{:x}{:x}", now, g.len() as u32 ^ (now as u32).rotate_left(7) & 0xffff);
        g.push(Watch { id: id.clone(), name, bbox, min_frp, created: now, seen: vec![], last_check: None, last_error: None, last_total: 0, last_new: vec![], new_total: 0 });
        self.save(&g);
        Ok(id)
    }

    pub fn remove(&self, id: &str) -> bool {
        let mut g = self.items.lock().unwrap();
        let n = g.len();
        g.retain(|w| w.id != id);
        let changed = g.len() != n;
        if changed {
            self.save(&g);
        }
        changed
    }

    #[cfg(test)]
    pub fn update_for_test(&self, id: &str, f: impl FnOnce(&mut Watch)) {
        self.update(id, f)
    }

    fn update(&self, id: &str, f: impl FnOnce(&mut Watch)) {
        let mut g = self.items.lock().unwrap();
        if let Some(w) = g.iter_mut().find(|w| w.id == id) {
            f(w);
            self.save(&g);
        }
    }
}

fn public(w: &Watch) -> Value {
    json!({ "id": w.id, "name": w.name, "bbox": w.bbox, "min_frp": w.min_frp, "created": iso(w.created),
            "last_check": w.last_check.map(iso), "last_error": w.last_error, "clusters_now": w.last_total, "new_clusters": w.last_new, "new_count": w.last_new.len(), "new_total": w.new_total })
}

/// Splits clusters into (new, all) against the seen list and returns the updated seen list.
pub fn diff(seen: &[(f64, f64, i64)], clusters: &[firms::Cluster], now: i64) -> (Vec<usize>, Vec<(f64, f64, i64)>) {
    let mut fresh = Vec::new();
    let mut next: Vec<(f64, f64, i64)> = seen.iter().copied().filter(|s| now - s.2 < SEEN_TTL).collect();
    for (i, c) in clusters.iter().enumerate() {
        let hit = next.iter_mut().find(|s| haversine_km((s.0, s.1), (c.lat, c.lon)) <= SAME_FIRE_KM);
        match hit {
            Some(s) => s.2 = now,
            None => {
                fresh.push(i);
                next.push((c.lat, c.lon, now));
            }
        }
    }
    if next.len() > MAX_SEEN {
        next.sort_by_key(|s| std::cmp::Reverse(s.2));
        next.truncate(MAX_SEEN);
    }
    (fresh, next)
}

/// Blocking. `baseline` records what exists without reporting it as new.
pub fn check_one(app: &Shared, id: &str, baseline: bool) {
    let Some(w) = app.watches.get(id) else { return };
    let q = crate::Query_ { bbox: w.bbox, sensor: "snpp", window: "24h", days: None, hours: None, min_frp: w.min_frp, min_conf: 0, eps_km: 2.0 };
    // A box inside one region still uses the (smaller) regional file automatically.
    match crate::load(app, &q) {
        Ok(l) => {
            let cl = firms::cluster(&l.points, 2.0);
            let now = now_secs();
            let (fresh, seen) = diff(&w.seen, &cl, now);
            let new: Vec<Value> = if baseline { vec![] } else { fresh.iter().map(|&i| cl[i].to_json()).take(50).collect() };
            let n = new.len();
            app.watches.update(id, |w| {
                w.seen = seen;
                w.last_check = Some(now);
                w.last_error = None;
                w.last_total = cl.len();
                w.last_new = new;
                w.new_total += n;
            });
        }
        Err(e) => app.watches.update(id, |w| {
            w.last_check = Some(now_secs());
            w.last_error = Some(e.1.clone());
        }),
    }
}

pub fn check_all(app: &Shared) {
    for id in app.watches.ids() {
        check_one(app, &id, false);
    }
}

pub fn spawn_background(app: Shared, every: Duration) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.tick().await;
        loop {
            tick.tick().await;
            if app.watches.ids().is_empty() {
                continue;
            }
            let a = app.clone();
            let _ = tokio::task::spawn_blocking(move || check_all(&a)).await;
        }
    });
}

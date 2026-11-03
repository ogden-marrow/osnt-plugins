//! Terrarium elevation tiles: fetch, decode (pure-Rust PNG), cache on disk with a size cap and in memory, and sample
//! heights with bilinear interpolation in global pixel space so samples across tile borders are seamless.
//! Elevation in metres = R * 256 + G + B / 256 - 32768.

use std::{
    collections::{BTreeSet, HashMap},
    fs,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, anyhow, bail};

pub const TILE: usize = 256;
pub const MAX_ZOOM: u8 = 14;
const MAX_PNG_BYTES: usize = 1_500_000;
const DISK_TTL: Duration = Duration::from_secs(14 * 86400);

pub type Tile = Arc<Vec<f32>>;
pub type Key = (u8, u32, u32);

pub struct Tiles {
    agent: ureq::Agent,
    base: String,
    dir: PathBuf,
    max_bytes: u64,
    pub(crate) mem: Mutex<HashMap<Key, (u64, Option<Tile>)>>,
    mem_cap: usize,
    tick: AtomicU64,
    writes: AtomicU64,
    pub fetched: AtomicU64,
}

/// Decoded tiles for one request, readable without locks.
pub struct Field {
    tiles: HashMap<Key, Option<Tile>>,
}

pub fn decode_png(bytes: &[u8]) -> Result<Vec<f32>> {
    let mut dec = png::Decoder::new(bytes);
    dec.set_transformations(png::Transformations::EXPAND);
    let mut reader = dec.read_info().context("not a PNG")?;
    let (w, h, ct, bd) = {
        let i = reader.info();
        (i.width as usize, i.height as usize, i.color_type, i.bit_depth)
    };
    if w != TILE || h != TILE {
        bail!("unexpected tile size {w}x{h}");
    }
    if bd != png::BitDepth::Eight {
        bail!("unexpected bit depth");
    }
    let ch = match ct {
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 4,
        _ => bail!("unexpected PNG colour type"),
    };
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let frame = reader.next_frame(&mut buf).context("decode PNG")?;
    if frame.buffer_size() < TILE * TILE * ch {
        bail!("short PNG data");
    }
    Ok((0..TILE * TILE).map(|i| buf[i * ch] as f32 * 256.0 + buf[i * ch + 1] as f32 + buf[i * ch + 2] as f32 / 256.0 - 32768.0).collect())
}

/// Global pixel coordinates (fractional, pixel centres at .5 removed) of a point at zoom `z`.
pub fn pixel(lat: f64, lon: f64, z: u8) -> (f64, f64) {
    let n = (1u64 << z) as f64 * TILE as f64;
    let lat = lat.clamp(-85.0511, 85.0511).to_radians();
    let x = (lon + 180.0) / 360.0 * n - 0.5;
    let y = (1.0 - (lat.tan() + 1.0 / lat.cos()).ln() / std::f64::consts::PI) / 2.0 * n - 0.5;
    (x, y)
}

/// Tiles needed to interpolate a height at this point.
pub fn needed(lat: f64, lon: f64, z: u8) -> [Key; 4] {
    let (gx, gy) = pixel(lat, lon, z);
    let n = 1i64 << z;
    let total = n * TILE as i64;
    let (x0, y0) = (gx.floor() as i64, gy.floor() as i64);
    let mut out = [(z, 0, 0); 4];
    for (i, (dx, dy)) in [(0, 0), (1, 0), (0, 1), (1, 1)].iter().enumerate() {
        let px = (x0 + dx).rem_euclid(total);
        let py = (y0 + dy).clamp(0, total - 1);
        out[i] = (z, (px / TILE as i64) as u32, (py / TILE as i64) as u32);
    }
    out
}

impl Field {
    /// Bilinear height in metres, or None where no tile data exists.
    pub fn elev(&self, lat: f64, lon: f64, z: u8) -> Option<f64> {
        let (gx, gy) = pixel(lat, lon, z);
        let total = (1i64 << z) * TILE as i64;
        let (x0, y0) = (gx.floor() as i64, gy.floor() as i64);
        let (fx, fy) = (gx - x0 as f64, gy - y0 as f64);
        let (mut sum, mut wsum) = (0.0, 0.0);
        for (dx, dy, w) in [(0, 0, (1.0 - fx) * (1.0 - fy)), (1, 0, fx * (1.0 - fy)), (0, 1, (1.0 - fx) * fy), (1, 1, fx * fy)] {
            let px = (x0 + dx).rem_euclid(total);
            let py = (y0 + dy).clamp(0, total - 1);
            let key = (z, (px / TILE as i64) as u32, (py / TILE as i64) as u32);
            if let Some(Some(t)) = self.tiles.get(&key) {
                sum += w * t[(py as usize % TILE) * TILE + (px as usize % TILE)] as f64;
                wsum += w;
            }
        }
        (wsum > 1e-9).then(|| sum / wsum)
    }
    /// Height of the optical surface for line of sight, horizon and viewshed. The tiles hold sea-floor depth under the ocean, so
    /// anything below zero is raised to sea level: a ship or a beach must not "stand" kilometres underwater. (Land below sea
    /// level such as the Dead Sea shore is raised to zero too; the responses say so.)
    pub fn surface(&self, lat: f64, lon: f64, z: u8) -> Option<f64> {
        self.elev(lat, lon, z).map(|e| e.max(0.0))
    }
    pub fn tile_count(&self) -> usize {
        self.tiles.len()
    }
    pub fn missing(&self) -> usize {
        self.tiles.values().filter(|t| t.is_none()).count()
    }
}

impl Tiles {
    pub fn new(agent: ureq::Agent, base: String, dir: PathBuf, max_bytes: u64, mem_cap: usize) -> Self {
        let _ = fs::create_dir_all(&dir);
        let t = Tiles { agent, base: base.trim_end_matches('/').to_string(), dir, max_bytes, mem: Mutex::new(HashMap::new()), mem_cap, tick: AtomicU64::new(0), writes: AtomicU64::new(0), fetched: AtomicU64::new(0) };
        t.evict();
        t
    }

    fn path(&self, k: Key) -> PathBuf {
        self.dir.join(format!("{}_{}_{}.png", k.0, k.1, k.2))
    }

    /// Removes expired files, then the oldest ones until the folder fits the size cap. Also runs at startup.
    pub fn evict(&self) {
        let Ok(rd) = fs::read_dir(&self.dir) else { return };
        let now = SystemTime::now();
        let mut files = vec![];
        for e in rd.flatten() {
            let Ok(m) = e.metadata() else { continue };
            let t = m.modified().unwrap_or(now);
            if e.path().extension().is_none_or(|x| x != "png") || now.duration_since(t).unwrap_or_default() > DISK_TTL {
                let _ = fs::remove_file(e.path());
            } else {
                files.push((t, m.len(), e.path()));
            }
        }
        let mut total: u64 = files.iter().map(|f| f.1).sum();
        files.sort_by_key(|f| f.0);
        for (_, len, p) in files {
            if total <= self.max_bytes {
                break;
            }
            if fs::remove_file(p).is_ok() {
                total -= len;
            }
        }
    }

    pub fn disk_bytes(&self) -> u64 {
        fs::read_dir(&self.dir).map(|rd| rd.flatten().filter_map(|e| e.metadata().ok()).map(|m| m.len()).sum()).unwrap_or(0)
    }

    fn load(&self, k: Key) -> Result<Option<Tile>> {
        let p = self.path(k);
        if let Ok(m) = fs::metadata(&p) {
            if SystemTime::now().duration_since(m.modified().unwrap_or(SystemTime::now())).unwrap_or_default() < DISK_TTL {
                if let Ok(bytes) = fs::read(&p) {
                    if let Ok(t) = decode_png(&bytes) {
                        return Ok(Some(Arc::new(t)));
                    }
                }
                let _ = fs::remove_file(&p);
            }
        }
        let url = format!("{}/{}/{}/{}.png", self.base, k.0, k.1, k.2);
        let res = self.agent.get(&url).config().http_status_as_error(false).build().call().map_err(|e| anyhow!("tile request failed: {e}"))?;
        let status = res.status().as_u16();
        if status == 403 || status == 404 {
            return Ok(None);
        }
        if status != 200 {
            bail!("tile server answered HTTP {status}");
        }
        let bytes = res.into_body().into_with_config().limit(MAX_PNG_BYTES as u64).read_to_vec().context("read tile")?;
        let tile = decode_png(&bytes)?;
        self.fetched.fetch_add(1, Ordering::Relaxed);
        let tmp = p.with_extension("tmp");
        if fs::write(&tmp, &bytes).is_ok() {
            let _ = fs::rename(&tmp, &p);
        }
        if self.writes.fetch_add(1, Ordering::Relaxed) % 32 == 31 {
            self.evict();
        }
        Ok(Some(Arc::new(tile)))
    }

    pub fn get(&self, k: Key) -> Result<Option<Tile>> {
        let tick = self.tick.fetch_add(1, Ordering::Relaxed);
        if let Some(e) = self.mem.lock().map_err(|_| anyhow!("lock"))?.get_mut(&k) {
            e.0 = tick;
            return Ok(e.1.clone());
        }
        let t = self.load(k)?;
        let mut m = self.mem.lock().map_err(|_| anyhow!("lock"))?;
        while m.len() >= self.mem_cap {
            let Some(old) = m.iter().min_by_key(|(_, v)| v.0).map(|(k, _)| *k) else { break };
            m.remove(&old);
        }
        m.insert(k, (tick, t.clone()));
        Ok(t)
    }

    /// Loads every tile in `set` (up to 8 in parallel). Tiles that cannot be fetched are reported as `failed`.
    pub fn field(&self, set: &BTreeSet<Key>) -> (Field, Vec<String>) {
        let keys: Vec<Key> = set.iter().copied().collect();
        let results: Mutex<Vec<(Key, Result<Option<Tile>>)>> = Mutex::new(vec![]);
        let next = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..8.min(keys.len().max(1)) {
                s.spawn(|| {
                    loop {
                        let i = next.fetch_add(1, Ordering::SeqCst);
                        let Some(&k) = keys.get(i) else { break };
                        let r = self.get(k);
                        if let Ok(mut v) = results.lock() {
                            v.push((k, r));
                        }
                    }
                });
            }
        });
        let mut tiles = HashMap::new();
        let mut failed = vec![];
        for (k, r) in results.into_inner().unwrap_or_default() {
            match r {
                Ok(t) => {
                    tiles.insert(k, t);
                }
                Err(e) => {
                    failed.push(format!("{}/{}/{}: {e:#}", k.0, k.1, k.2));
                    tiles.insert(k, None);
                }
            }
        }
        (Field { tiles }, failed)
    }
}

#[cfg(test)]
mod surface_tests {
    use super::*;

    #[test]
    fn sea_floor_is_raised_to_sea_level_for_sight_lines_only() {
        let mut tiles = HashMap::new();
        tiles.insert((0u8, 0u32, 0u32), Some(Arc::new(vec![-4000.0f32; TILE * TILE])));
        let f = Field { tiles };
        assert!(f.elev(0.0, 0.0, 0).unwrap() < -3999.0);
        assert_eq!(f.surface(0.0, 0.0, 0), Some(0.0));
    }
}

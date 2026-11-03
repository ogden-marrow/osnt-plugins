//! Spectrogram and tonal-line tracking.

use rustfft::{FftPlanner, num_complex::Complex};

pub struct Spectrogram {
    /// dB magnitude, `frames x bins`, bins covering `fmin..fmax` Hz.
    pub db: Vec<Vec<f32>>,
    /// Contrast version: local-frequency mean and stationary per-bin median removed (dB above background).
    pub contrast: Vec<Vec<f32>>,
    pub times: Vec<f64>,
    pub bin_hz: f64,
    pub k0: usize,
    pub hop_s: f64,
}

impl Spectrogram {
    pub fn freq_of_bin(&self, k: f64) -> f64 {
        (self.k0 as f64 + k) * self.bin_hz
    }
}

fn median(v: &mut [f32]) -> f32 {
    v.sort_by(f32::total_cmp);
    v[v.len() / 2]
}

pub fn spectrogram(x: &[f32], fs: f64, fmin: f64, fmax: f64) -> Spectrogram {
    let win = ((fs * 0.04).max(256.0) as usize).next_power_of_two().min(8192);
    let nfft = win * 2; // zero padded for finer peak interpolation
    let dur = x.len() as f64 / fs;
    let hop_min = win / 4;
    let hop_cap = (dur * fs / 3000.0).ceil() as usize; // at most ~3000 frames
    let hop = hop_min.max(hop_cap).min(win);
    let hann: Vec<f32> = (0..win).map(|i| 0.5 - 0.5 * (2.0 * std::f32::consts::PI * i as f32 / win as f32).cos()).collect();
    let bin_hz = fs / nfft as f64;
    let k0 = (fmin / bin_hz).floor().max(1.0) as usize;
    let k1 = ((fmax.min(fs / 2.0 * 0.98)) / bin_hz).ceil() as usize;
    let fft = FftPlanner::<f32>::new().plan_fft_forward(nfft);
    let mut db: Vec<Vec<f32>> = Vec::new();
    let mut times = Vec::new();
    let mut buf = vec![Complex::new(0.0f32, 0.0); nfft];
    let mut start = 0usize;
    while start + win <= x.len() {
        for i in 0..nfft {
            buf[i] = if i < win { Complex::new(x[start + i] * hann[i], 0.0) } else { Complex::new(0.0, 0.0) };
        }
        fft.process(&mut buf);
        db.push((k0..=k1).map(|k| 10.0 * (buf[k].norm_sqr() + 1e-12).log10()).collect());
        times.push((start as f64 + win as f64 / 2.0) / fs);
        start += hop;
    }
    let nb = k1 - k0 + 1;
    // Contrast: subtract the local mean over +-20 bins (whitens the broadband hump), then each bin's median over time
    // (kills hum and other stationary tones).
    let half = 20usize;
    let mut contrast: Vec<Vec<f32>> = db
        .iter()
        .map(|row| {
            let mut pre = vec![0.0f64; nb + 1];
            for i in 0..nb {
                pre[i + 1] = pre[i] + row[i] as f64;
            }
            (0..nb)
                .map(|i| {
                    let (a, b) = (i.saturating_sub(half), (i + half + 1).min(nb));
                    row[i] - ((pre[b] - pre[a]) / (b - a) as f64) as f32
                })
                .collect()
        })
        .collect();
    if contrast.len() > 4 {
        for i in 0..nb {
            let mut col: Vec<f32> = contrast.iter().map(|r| r[i]).collect();
            let m = median(&mut col);
            for r in contrast.iter_mut() {
                r[i] -= m;
            }
        }
    }
    Spectrogram { db, contrast, times, bin_hz, k0, hop_s: hop as f64 / fs }
}

pub struct Track {
    /// (time, frequency Hz, snr dB) for frames where the line is credible.
    pub points: Vec<(f64, f64, f64)>,
    pub bins: Vec<usize>,
    pub median_snr: f64,
}

/// Viterbi path through the contrast spectrogram: maximises summed SNR with a smoothness penalty on bin jumps.
/// Bins marked in `mask` (per frame) are excluded, so repeated calls find successive lines.
fn viterbi(sp: &Spectrogram, mask: &[Vec<bool>]) -> Vec<usize> {
    let nf = sp.contrast.len();
    let nb = sp.contrast[0].len();
    // A pass can glide at most ~1500 Hz/s.
    let jmax = ((1500.0 * sp.hop_s / sp.bin_hz).ceil() as usize + 1).clamp(3, 24);
    let reward = |t: usize, k: usize| if mask[t][k] { 0.0 } else { sp.contrast[t][k].clamp(0.0, 40.0) };
    let mut score = vec![0.0f32; nb];
    let mut back = vec![vec![0u8; nb]; nf];
    for k in 0..nb {
        score[k] = reward(0, k);
    }
    let lam = 0.6f32;
    for t in 1..nf {
        let mut ns = vec![0.0f32; nb];
        for k in 0..nb {
            let (mut best, mut bj) = (f32::MIN, 0i32);
            for j in -(jmax as i32)..=(jmax as i32) {
                let kp = k as i32 + j;
                if kp < 0 || kp >= nb as i32 {
                    continue;
                }
                let s = score[kp as usize] - lam * (j * j) as f32;
                if s > best {
                    best = s;
                    bj = j;
                }
            }
            ns[k] = best + reward(t, k);
            back[t][k] = (bj + jmax as i32) as u8;
        }
        score = ns;
    }
    let mut k = (0..nb).max_by(|&a, &b| score[a].total_cmp(&score[b])).unwrap_or(0);
    let mut path = vec![0usize; nf];
    for t in (0..nf).rev() {
        path[t] = k;
        if t > 0 {
            k = (k as i32 + back[t][k] as i32 - jmax as i32) as usize;
        }
    }
    path
}

fn parabolic(row: &[f32], k: usize) -> f64 {
    if k == 0 || k + 1 >= row.len() {
        return k as f64;
    }
    let (a, b, c) = (row[k - 1] as f64, row[k] as f64, row[k + 1] as f64);
    let den = a - 2.0 * b + c;
    if den.abs() < 1e-9 { k as f64 } else { k as f64 + (0.5 * (a - c) / den).clamp(-0.5, 0.5) }
}

/// Track up to `max_lines` dominant tonal lines, strongest first.
pub fn track_lines(sp: &Spectrogram, max_lines: usize) -> Vec<Track> {
    let nf = sp.contrast.len();
    if nf < 12 || sp.contrast[0].len() < 16 {
        return vec![];
    }
    let nb = sp.contrast[0].len();
    let mut mask = vec![vec![false; nb]; nf];
    let mut lines = Vec::new();
    for _ in 0..max_lines {
        let path = viterbi(sp, &mask);
        let mut snrs: Vec<f64> = path.iter().enumerate().map(|(t, &k)| sp.contrast[t][k] as f64).collect();
        let mut sorted = snrs.clone();
        sorted.sort_by(f64::total_cmp);
        let p90 = sorted[(sorted.len() as f64 * 0.9) as usize];
        let thr = (0.4 * p90).max(6.0);
        let mut pts = Vec::new();
        for (t, &k) in path.iter().enumerate() {
            if snrs[t] >= thr {
                // snap to the local spectral maximum (the DP reward plateaus on a strong tone's main lobe)
                let (a, b) = (k.saturating_sub(3), (k + 4).min(nb));
                let ks = (a..b).max_by(|&x, &y| sp.db[t][x].total_cmp(&sp.db[t][y])).unwrap_or(k);
                let kf = parabolic(&sp.db[t], ks);
                pts.push((sp.times[t], sp.freq_of_bin(kf), snrs[t]));
            }
        }
        // mask this line (and a margin) for the next pass
        for (t, &k) in path.iter().enumerate() {
            for kk in k.saturating_sub(6)..(k + 7).min(nb) {
                mask[t][kk] = true;
            }
        }
        snrs.retain(|s| *s >= thr);
        let ms = if snrs.is_empty() { 0.0 } else { snrs.sort_by(f64::total_cmp); snrs[snrs.len() / 2] };
        if pts.len() >= 12 {
            lines.push(Track { points: pts, bins: path, median_snr: ms });
        } else {
            break;
        }
    }
    lines
}

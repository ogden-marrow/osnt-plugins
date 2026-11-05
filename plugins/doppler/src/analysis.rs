//! End-to-end analysis: decode -> spectrogram -> track -> fit -> JSON.

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

use crate::{
    decode, dsp,
    model::{self, FitResult, Point, freq_at},
};

/// Longest recording accepted (decoded and decimated in memory; passes are searched for in clips above SCAN_ABOVE_S).
pub const MAX_SECONDS: f64 = 7200.0;
/// Clips longer than this are scanned in windows for passes instead of fitted as a single pass.
pub const SCAN_ABOVE_S: f64 = 150.0;
const WIN_S: f64 = 60.0;
const HOP_S: f64 = 30.0;

pub const CAVEAT: &str = "This is an ESTIMATE from one microphone, assuming a constant-speed straight-line pass, a still atmosphere and a \
steady tone. Speed is relative to the air (wind changes it), distance is slant range to the track (height and sideways offset cannot be \
separated), and no direction or location is derived. Use it to test whether a clip's claim (aircraft type, speed, place, time) is plausible, \
not as proof of anything.";

#[derive(Clone)]
pub struct Options {
    pub temp_c: f64,
    pub fmin: f64,
    pub fmax: f64,
    pub max_lines: usize,
    /// Unix time of the first sample, if the user knows it (used only to label absolute times).
    pub clip_start: Option<f64>,
}

impl Default for Options {
    fn default() -> Self {
        Options { temp_c: 15.0, fmin: 60.0, fmax: 5000.0, max_lines: 2, clip_start: None }
    }
}

fn confidence(fit: &FitResult, c: f64, median_snr: f64, bin_hz: f64) -> (&'static str, Vec<String>) {
    let mut warn = Vec::new();
    let p = &fit.params;
    let rel_v = fit.sigma.v.map(|s| s / p.v).unwrap_or(1.0);
    if fit.coverage < 0.7 {
        warn.push(format!(
            "The clip covers only {:.0}% of the pitch change a full pass would show (the far approach and/or far recede is missing), so speed, source frequency and distance trade off against each other and their uncertainty is large.",
            fit.coverage * 100.0
        ));
    }
    if p.v > 0.9 * c.min(model::MAX_SPEED) {
        warn.push("Fitted speed is at or near the supersonic/model limit: not credible for an ordinary flyby.".into());
    }
    if p.d < 5.0 {
        warn.push("Fitted closest distance is tiny; the pitch change is very abrupt. Check the clip is a single pass of one source.".into());
    }
    if fit.n_used < 40 {
        warn.push(format!("Only {} tracked points agree with the curve.", fit.n_used));
    }
    if median_snr < 10.0 {
        warn.push("The tonal line is weak against the background; the track may follow noise.".into());
    }
    if fit.n_used * 10 < fit.n_total * 6 {
        warn.push("Many tracked points disagree with the fitted curve; the line may be a mix of sources or reflections.".into());
    }
    let mut poor = false;
    if fit.rms_hz > 1.5 * bin_hz {
        warn.push(format!("The curve fits poorly (rms {:.0} Hz, spectrogram bins are {:.0} Hz): the line does not follow a clean flyby shape.", fit.rms_hz, bin_hz));
        poor = true;
    }
    if fit.coverage > 1.3 {
        warn.push("The tracked frequencies span more than the fitted pass allows: the fit is not credible.".into());
        poor = true;
    }
    let level = if poor {
        "low"
    } else if fit.coverage >= 0.85 && fit.n_used >= 40 && rel_v < 0.05 && median_snr >= 12.0 && fit.rms_hz <= 0.75 * bin_hz {
        "high"
    } else if fit.coverage >= 0.6 && rel_v < 0.15 && fit.n_used >= 20 && fit.rms_hz <= 1.2 * bin_hz {
        "medium"
    } else {
        "low"
    };
    (level, warn)
}

fn spectrogram_image(sp: &dsp::Spectrogram) -> Value {
    let nf = sp.contrast.len();
    let nb = sp.contrast[0].len();
    let cols = nf.min(700);
    let rows = nb.min(280);
    let mut px = vec![0u8; cols * rows]; // row 0 = lowest frequency; the page flips it
    for ci in 0..cols {
        let (t0, t1) = (ci * nf / cols, ((ci + 1) * nf / cols).max(ci * nf / cols + 1));
        for ri in 0..rows {
            let (b0, b1) = (ri * nb / rows, ((ri + 1) * nb / rows).max(ri * nb / rows + 1));
            let mut m = f32::MIN;
            for t in t0..t1.min(nf) {
                for b in b0..b1.min(nb) {
                    m = m.max(sp.contrast[t][b]);
                }
            }
            px[ri * cols + ci] = (m.clamp(0.0, 30.0) / 30.0 * 255.0) as u8;
        }
    }
    json!({
        "width": cols, "height": rows, "data_b64": STANDARD.encode(&px),
        "t0": sp.times.first(), "t1": sp.times.last(),
        "f0": sp.freq_of_bin(0.0), "f1": sp.freq_of_bin(nb as f64),
        "note": "contrast spectrogram: dB above the local and stationary background, 0-30 dB",
    })
}

/// Decode and analyse. A clip up to SCAN_ABOVE_S is fitted as one pass; a longer one is scanned for passes.
pub fn analyze(data: Vec<u8>, bytes: usize, o: &Options) -> Result<Value, String> {
    analyze_auto(data, bytes, o).map(|r| r.0)
}

pub fn analyze_auto(data: Vec<u8>, bytes: usize, o: &Options) -> Result<(Value, Option<decode::Audio>), String> {
    let audio = decode::decode(data, MAX_SECONDS, o.fmax)?;
    let dur = audio.samples.len() as f64 / audio.sample_rate as f64;
    if dur <= SCAN_ABOVE_S {
        let v = analyze_samples(&audio.samples, audio.sample_rate, audio.channels, bytes, o)?;
        return Ok((v, None));
    }
    let v = scan(&audio, bytes, o)?;
    Ok((v, Some(audio)))
}

/// Analyse part of an already decoded recording (seconds from the start).
pub fn analyze_segment(audio: &decode::Audio, from: f64, to: f64, o: &Options) -> Result<Value, String> {
    let fs = audio.sample_rate as f64;
    let a = ((from.max(0.0)) * fs) as usize;
    let b = ((to * fs) as usize).min(audio.samples.len());
    if b <= a + (fs as usize) {
        return Err("segment is empty or shorter than a second".into());
    }
    let mut o2 = o.clone();
    o2.clip_start = o.clip_start.map(|s| s + from.max(0.0));
    let mut v = analyze_samples(&audio.samples[a..b], audio.sample_rate, audio.channels, 0, &o2)?;
    v["window"] = json!({ "start_s": round(from.max(0.0), 1), "end_s": round(b as f64 / fs, 1) });
    Ok(v)
}

fn level_rank(c: &str) -> u8 {
    match c { "high" => 3, "medium" => 2, _ => 1 }
}

/// Slide a window over a long recording, fit each, keep the credible passes (best first, one per pass).
fn scan(audio: &decode::Audio, bytes: usize, o: &Options) -> Result<Value, String> {
    let fs = audio.sample_rate as f64;
    let total = audio.samples.len() as f64 / fs;
    let mut wins = Vec::new();
    let mut t = 0.0;
    while t + 10.0 < total {
        wins.push((t, (t + WIN_S).min(total)));
        t += HOP_S;
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let found = std::sync::Mutex::new(Vec::<(f64, f64, Value)>::new());
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2).clamp(1, 3);
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(&(a, b)) = wins.get(i) else { break };
                if let Ok(v) = analyze_segment(audio, a, b, o) {
                    found.lock().unwrap().push((a, b, v));
                }
            });
        }
    });
    let c: Vec<(f64, f64, Value)> = found.into_inner().unwrap();
    let (env, events) = loudness_events(audio);
    let score = |v: &Value| {
        let bi = v["best_line"].as_u64().unwrap_or(0) as usize;
        let l = &v["lines"][bi];
        (level_rank(v["summary"]["confidence"].as_str().unwrap_or("low")), l["median_snr_db"].as_f64().unwrap_or(0.0) * l["points_used"].as_f64().unwrap_or(0.0))
    };
    let tca = |a: f64, v: &Value| a + v["summary"]["fit"]["closest_approach_heard_s"]["value"].as_f64().unwrap_or(0.0);
    // One entry per pass: (heard closest approach or loudness peak, loudness excess dB, window start, optional fit)
    struct Item { t: f64, loud: Option<f64>, from: f64, fit: Option<Value>, rank: (u8, f64) }
    let mut items: Vec<Item> = Vec::new();
    // credible tonal fits from the blind windows (best first, one per ~25 s)
    let mut cr: Vec<&(f64, f64, Value)> = c.iter().collect();
    cr.sort_by(|x, y| { let (sx, sy) = (score(&x.2), score(&y.2)); sy.0.cmp(&sx.0).then(sy.1.total_cmp(&sx.1)) });
    for (a, _, v) in cr {
        let tc = tca(*a, v);
        if items.iter().any(|i| (i.t - tc).abs() < 25.0) {
            continue;
        }
        if score(v).0 < 2 && items.iter().filter(|i| i.rank.0 < 2).count() >= 3 {
            continue;
        }
        items.push(Item { t: tc, loud: None, from: *a, fit: Some(v.clone()), rank: score(v) });
    }
    // loud events: fit a window around each one (the pass is where the sound swells, tonal or not)
    for &(pt, excess) in events.iter().take(8) {
        if let Some(it) = items.iter_mut().find(|i| (i.t - pt).abs() < 25.0) {
            it.loud = Some(excess);
            continue;
        }
        let (from, to) = ((pt - 40.0).max(0.0), (pt + 40.0).min(total));
        let fit = analyze_segment(audio, from, to, o).ok();
        let rank = fit.as_ref().map(&score).unwrap_or((0, 0.0));
        let t = fit.as_ref().map(|v| tca(from, v)).unwrap_or(pt);
        items.push(Item { t, loud: Some(excess), from, fit, rank: (rank.0.max(if rank.0 > 0 { 1 } else { 0 }), rank.1) });
    }
    // credible fits first; then by how loud the event is (a low-confidence fit never outranks a louder event)
    items.sort_by(|x, y| (y.rank.0 >= 2).cmp(&(x.rank.0 >= 2)).then(y.loud.unwrap_or(-1.0).total_cmp(&x.loud.unwrap_or(-1.0))).then(y.rank.1.total_cmp(&x.rank.1)));
    items.truncate(10);
    if items.is_empty() {
        return Err(format!("scanned {:.0} minutes and found no loud event and no clear flyby. Try a wider Hz range, or trim to where you know a pass happens.", total / 60.0));
    }
    let list: Vec<Value> = items.iter().map(|i| {
        let f = i.fit.as_ref().map(|v| &v["summary"]["fit"]);
        let conf = i.fit.as_ref().map(|v| v["summary"]["confidence"].clone()).unwrap_or(json!("none"));
        json!({
            "closest_approach_s": round(i.t, 1), "from_s": round((i.t - 30.0).max(0.0), 1), "to_s": round((i.t + 30.0).min(total), 1),
            "loudness_above_background_db": i.loud.map(|x| round(x, 1)),
            "confidence": conf,
            "speed_ms": f.map(|f| f["speed_ms"]["value"].clone()), "speed_kmh": f.map(|f| f["speed_kmh"].clone()),
            "closest_distance_m": f.map(|f| f["closest_distance_m"]["value"].clone()), "source_frequency_hz": f.map(|f| f["source_frequency_hz"]["value"].clone()),
        })
    }).collect();
    let scan_info = json!({ "duration_s": round(total, 1), "windows": wins.len(), "passes": list, "envelope_db": env,
        "note": "Passes are ranked by how well a Doppler curve fits, then by how far above the background the sound rises. A pass of broadband noise (jet or road noise) can be loud without a tonal line to fit; those are listed with confidence none." });
    let first = items.into_iter().find(|i| i.fit.is_some());
    let mut best = match first {
        Some(i) => {
            let mut v = i.fit.unwrap();
            let a = i.from;
            v["window"] = json!({ "start_s": round(a, 1), "end_s": round(a + WIN_S.max(80.0), 1).min(round(total, 1)) });
            v
        }
        None => json!({ "ok": true, "caveat": CAVEAT, "clip": { "clip_start_unix": o.clip_start }, "no_fit": true }),
    };
    best["clip"]["bytes"] = json!(bytes);
    best["clip"]["duration_s"] = json!(round(total, 1));
    best["scan"] = scan_info;
    Ok(best)
}

/// Loudness per second (dB, 100 Hz-fmax signal as decoded) above a rolling-median background, and its peaks.
/// Returns (envelope downsampled to <= 720 points of excess dB, [(peak time s, excess dB)] strongest first).
fn loudness_events(audio: &decode::Audio) -> (Vec<f64>, Vec<(f64, f64)>) {
    let fs = audio.sample_rate as usize;
    let n = audio.samples.len() / fs;
    let db: Vec<f64> = (0..n).map(|i| {
        let w = &audio.samples[i * fs..(i + 1) * fs];
        let ms = w.iter().map(|&x| (x as f64) * (x as f64)).sum::<f64>() / fs as f64;
        10.0 * (ms + 1e-12).log10()
    }).collect();
    let half = 90usize;
    let ex: Vec<f64> = (0..n).map(|i| {
        let (a, b) = (i.saturating_sub(half), (i + half + 1).min(n));
        let mut w: Vec<f64> = db[a..b].to_vec();
        w.sort_by(f64::total_cmp);
        db[i] - w[w.len() / 2]
    }).collect();
    let mut peaks: Vec<(f64, f64)> = Vec::new();
    for i in 0..n {
        let (a, b) = (i.saturating_sub(15), (i + 16).min(n));
        if ex[i] >= 5.0 && ex[a..b].iter().all(|&e| e <= ex[i]) {
            peaks.push((i as f64 + 0.5, ex[i]));
        }
    }
    peaks.sort_by(|x, y| y.1.total_cmp(&x.1));
    let step = n.div_ceil(720).max(1);
    let env: Vec<f64> = ex.chunks(step).map(|c| round(c.iter().cloned().fold(f64::MIN, f64::max), 1)).collect();
    (env, peaks)
}

pub fn analyze_samples(samples: &[f32], sample_rate: u32, channels: usize, bytes: usize, o: &Options) -> Result<Value, String> {
    let fs = sample_rate as f64;
    let duration = samples.len() as f64 / fs;
    let c = model::sound_speed(o.temp_c);
    let sp = dsp::spectrogram(samples, fs, o.fmin, o.fmax);
    if sp.contrast.len() < 12 {
        return Err("clip too short for a spectrogram".into());
    }
    let tracks = dsp::track_lines(&sp, o.max_lines.clamp(1, 3));
    let mut lines = Vec::new();
    let mut best: Option<(f64, usize)> = None;
    let mut fail_reasons = Vec::new();
    for (i, tr) in tracks.iter().enumerate() {
        let pts: Vec<Point> = tr.points.iter().map(|&(t, f, snr)| Point { t, f, w: (snr / 10.0).clamp(0.3, 3.0) }).collect();
        let raw: Vec<Value> = tr.points.iter().map(|&(t, f, s)| json!([round(t, 3), round(f, 2), round(s, 1)])).collect();
        match model::fit(&pts, c, sp.bin_hz) {
            Ok(fit) => {
                let (conf, warns) = confidence(&fit, c, tr.median_snr, sp.bin_hz);
                let p = fit.params;
                let (t0, t1) = (sp.times[0], *sp.times.last().unwrap());
                let curve: Vec<Value> = (0..=300).map(|k| {
                    let t = t0 + (t1 - t0) * k as f64 / 300.0;
                    json!([round(t, 3), round(freq_at(t, &p, c), 2)])
                }).collect();
                let src_ca = p.tca - p.d / c;
                let abs = |t: f64| o.clip_start.map(|s| round(s + t, 1));
                // Statistical sigma from the fit, plus a systematic floor in quadrature for what the model ignores
                // (temperature/wind -> speed of sound, tracker bias, non-constant velocity).
                let floor = |s: Option<f64>, f: f64| s.map(|x| (x * x + f * f).sqrt());
                let sg = model::Sigma {
                    f0: floor(fit.sigma.f0, 0.005 * p.f0),
                    v: floor(fit.sigma.v, 0.03 * p.v),
                    d: floor(fit.sigma.d, 0.08 * p.d),
                    tca: floor(fit.sigma.tca, sp.hop_s.max(0.05)),
                };
                // sorted-by-time index of the points flagged as used
                let mut sorted: Vec<&(f64, f64, f64)> = tr.points.iter().collect();
                sorted.sort_by(|a, b| a.0.total_cmp(&b.0));
                let flags: Vec<bool> = fit.used.clone();
                let used_pts: Vec<Value> = sorted.iter().zip(&flags).map(|(p, u)| json!([round(p.0, 3), round(p.1, 2), *u])).collect();
                let weight = tr.median_snr * fit.n_used as f64;
                if best.is_none_or(|b| weight > b.0) {
                    best = Some((weight, lines.len()));
                }
                lines.push(json!({
                    "index": i,
                    "median_snr_db": round(tr.median_snr, 1),
                    "points_tracked": tr.points.len(),
                    "points_used": fit.n_used,
                    "points": raw,
                    "points_flagged": used_pts,
                    "fit": {
                        "source_frequency_hz": { "value": round(p.f0, 1), "sigma": sg.f0.map(|x| round(x, 1)) },
                        "speed_ms": { "value": round(p.v, 1), "sigma": sg.v.map(|x| round(x, 1)) },
                        "speed_kmh": round(p.v * 3.6, 0),
                        "speed_knots": round(p.v / 0.514444, 0),
                        "closest_distance_m": { "value": round(p.d, 0), "sigma": sg.d.map(|x| round(x, 0)), "range_16_84": fit.d_range_m.map(|(a, b)| [round(a, 0), round(b, 0)]) },
                        "closest_approach_heard_s": { "value": round(p.tca, 2), "sigma": sg.tca.map(|x| round(x, 2)), "clip_absolute_unix": abs(p.tca) },
                        "closest_approach_at_source_s": { "value": round(src_ca, 2), "clip_absolute_unix": abs(src_ca), "note": "when the aircraft was nearest, i.e. the heard time minus d/c sound delay" },
                        "rms_residual_hz": round(fit.rms_hz, 2),
                        "pitch_change_coverage": round(fit.coverage, 2),
                        "model": "f(t) = f0 / (1 + v cos(theta(t)) / c), constant-velocity straight pass, retarded time",
                    },
                    "confidence": conf,
                    "warnings": warns,
                    "curve": curve,
                }));
            }
            Err(e) => fail_reasons.push(format!("line {}: {e}", i + 1)),
        }
    }
    if lines.is_empty() {
        let why = if tracks.is_empty() {
            "no clear moving tonal line was found (steady tones such as hum are removed on purpose). Try a tighter frequency range or a cleaner clip.".to_string()
        } else {
            format!("a tonal line was found but it does not look like a flyby: {}", fail_reasons.join("; "))
        };
        return Err(why);
    }
    let bi = best.map(|b| b.1).unwrap_or(0);
    let mut consistency = Value::Null;
    if lines.len() > 1 {
        let g = |l: &Value, k: &str| l["fit"][k]["value"].as_f64().unwrap_or(0.0);
        let (a, b) = (&lines[bi], &lines[if bi == 0 { 1 } else { 0 }]);
        let dv = (g(a, "speed_ms") - g(b, "speed_ms")).abs();
        let dt = (g(a, "closest_approach_heard_s") - g(b, "closest_approach_heard_s")).abs();
        consistency = json!({
            "speed_difference_ms": round(dv, 1), "closest_approach_difference_s": round(dt, 2),
            "ratio_f0": round(g(b, "source_frequency_hz") / g(a, "source_frequency_hz").max(1e-9), 3),
            "note": "A second line that gives the same speed and timing (often f0 at an integer ratio: a harmonic) supports the estimate; disagreement means treat it with extra caution.",
        });
    }
    let bl = lines[bi].clone();
    Ok(json!({
        "ok": true,
        "caveat": CAVEAT,
        "clip": { "bytes": bytes, "duration_s": round(duration, 2), "sample_rate_hz": sample_rate, "channels": channels, "clip_start_unix": o.clip_start },
        "settings": { "speed_of_sound_ms": round(c, 1), "temperature_c": o.temp_c, "freq_range_hz": [o.fmin, o.fmax], "bin_hz": round(sp.bin_hz, 2) },
        "best_line": bi,
        "summary": { "fit": bl["fit"].clone(), "confidence": bl["confidence"].clone(), "warnings": bl["warnings"].clone() },
        "line_consistency": consistency,
        "spectrogram": spectrogram_image(&sp),
        "lines": lines,
    }))
}

fn round(x: f64, dp: i32) -> f64 {
    let m = 10f64.powi(dp);
    (x * m).round() / m
}

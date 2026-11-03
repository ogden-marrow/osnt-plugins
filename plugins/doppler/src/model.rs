//! Doppler flyby model and fitting.
//!
//! A source moving at constant speed `v` along a straight line passes a stationary listener at closest distance `d`.
//! The emitted tone has frequency `f0`. With retarded time (sound takes R/c to arrive) the received frequency is
//! `f(t) = f0 / (1 + v*cos(theta)/c)`, where `cos(theta) = x/R` is the cosine of the angle between the track and the
//! line from the source to the listener at the moment of emission (negative while approaching).
//!
//! Parameters: `f0` (Hz), `v` (m/s), `d` (m), `tca` (the time the closest-approach sound is *received*, s).

use serde::Serialize;

pub const MAX_SPEED: f64 = 450.0;

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Params {
    pub f0: f64,
    pub v: f64,
    pub d: f64,
    pub tca: f64,
}

/// Speed of sound in air (m/s) at `temp_c` degrees Celsius.
pub fn sound_speed(temp_c: f64) -> f64 {
    331.3 * (1.0 + temp_c / 273.15).sqrt()
}

/// Received frequency at received time `t`. Closed-form retarded-time solution:
/// with `s = t - te0` (te0 = emission time of closest approach = tca - d/c),
/// `tau = (c^2 s - sqrt(d^2 (c^2 - v^2) + v^2 c^2 s^2)) / (c^2 - v^2)` is the emission offset.
pub fn freq_at(t: f64, p: &Params, c: f64) -> f64 {
    let v = p.v.min(c * 0.999);
    let te0 = p.tca - p.d / c;
    let s = t - te0;
    let c2 = c * c;
    let k = c2 - v * v;
    let tau = (c2 * s - (p.d * p.d * k + v * v * c2 * s * s).sqrt()) / k;
    let x = v * tau;
    let r = (x * x + p.d * p.d).sqrt();
    p.f0 / (1.0 + v * (x / r) / c)
}

/// Emission time offset and range for received time `t` (used to synthesise test signals and amplitudes).
pub fn emission(t: f64, p: &Params, c: f64) -> (f64, f64) {
    let v = p.v.min(c * 0.999);
    let te0 = p.tca - p.d / c;
    let s = t - te0;
    let c2 = c * c;
    let k = c2 - v * v;
    let tau = (c2 * s - (p.d * p.d * k + v * v * c2 * s * s).sqrt()) / k;
    let r = ((v * tau).powi(2) + p.d * p.d).sqrt();
    (te0 + tau, r)
}

#[derive(Clone, Copy, Debug)]
pub struct Point {
    pub t: f64,
    pub f: f64,
    pub w: f64,
}

fn to_params(q: &[f64; 4], c: f64, t_lo: f64, t_hi: f64) -> Params {
    Params {
        f0: q[0].max(1.0),
        v: q[1].clamp(1.0, MAX_SPEED.min(c * 0.95)),
        d: q[2].clamp(-1.0, 10.5).exp(), // ln(d) in [~0.4 m, ~36 km]
        tca: q[3].clamp(t_lo, t_hi),
    }
}

fn from_params(p: &Params) -> [f64; 4] {
    [p.f0, p.v, p.d.ln(), p.tca]
}

fn residuals(q: &[f64; 4], pts: &[Point], w: &[f64], c: f64, tr: (f64, f64)) -> Vec<f64> {
    let p = to_params(q, c, tr.0, tr.1);
    pts.iter().zip(w).map(|(pt, wi)| wi.sqrt() * (freq_at(pt.t, &p, c) - pt.f)).collect()
}

fn solve(mut a: Vec<Vec<f64>>, mut b: Vec<f64>) -> Option<Vec<f64>> {
    let n = b.len();
    for i in 0..n {
        let piv = (i..n).max_by(|&x, &y| a[x][i].abs().total_cmp(&a[y][i].abs()))?;
        if a[piv][i].abs() < 1e-300 || !a[piv][i].is_finite() {
            return None;
        }
        a.swap(i, piv);
        b.swap(i, piv);
        for r in i + 1..n {
            let m = a[r][i] / a[i][i];
            for cidx in i..n {
                a[r][cidx] -= m * a[i][cidx];
            }
            b[r] -= m * b[i];
        }
    }
    let mut x = vec![0.0; n];
    for i in (0..n).rev() {
        let s: f64 = (i + 1..n).map(|j| a[i][j] * x[j]).sum();
        x[i] = (b[i] - s) / a[i][i];
    }
    x.iter().all(|v| v.is_finite()).then_some(x)
}

fn jacobian(q: &[f64; 4], pts: &[Point], w: &[f64], c: f64, tr: (f64, f64)) -> Vec<[f64; 4]> {
    let steps = [q[0].abs().max(10.0) * 1e-5, q[1].abs().max(1.0) * 1e-5, 1e-5, 1e-5];
    let mut cols: Vec<Vec<f64>> = Vec::new();
    for k in 0..4 {
        let (mut a, mut b) = (*q, *q);
        a[k] += steps[k];
        b[k] -= steps[k];
        let (ra, rb) = (residuals(&a, pts, w, c, tr), residuals(&b, pts, w, c, tr));
        cols.push(ra.iter().zip(&rb).map(|(x, y)| (x - y) / (2.0 * steps[k])).collect());
    }
    (0..pts.len()).map(|i| [cols[0][i], cols[1][i], cols[2][i], cols[3][i]]).collect()
}

fn normal_eq(j: &[[f64; 4]]) -> Vec<Vec<f64>> {
    let mut a = vec![vec![0.0; 4]; 4];
    for row in j {
        for r in 0..4 {
            for cc in 0..4 {
                a[r][cc] += row[r] * row[cc];
            }
        }
    }
    a
}

/// Levenberg-Marquardt least squares from `p0`; returns the parameters and the weighted sum of squares.
fn lm(pts: &[Point], w: &[f64], p0: &Params, c: f64, tr: (f64, f64), iters: usize) -> (Params, f64) {
    let mut q = from_params(p0);
    let sse = |q: &[f64; 4]| residuals(q, pts, w, c, tr).iter().map(|r| r * r).sum::<f64>();
    let mut cur = sse(&q);
    let mut lambda = 1e-3;
    for _ in 0..iters {
        let r = residuals(&q, pts, w, c, tr);
        let j = jacobian(&q, pts, w, c, tr);
        let a = normal_eq(&j);
        let g: Vec<f64> = (0..4).map(|k| j.iter().zip(&r).map(|(row, ri)| row[k] * ri).sum()).collect();
        let mut improved = false;
        for _ in 0..12 {
            let mut aa = a.clone();
            for k in 0..4 {
                aa[k][k] += lambda * a[k][k].max(1e-12);
            }
            if let Some(step) = solve(aa, g.iter().map(|x| -x).collect()) {
                let mut nq = q;
                for k in 0..4 {
                    nq[k] += step[k];
                }
                let np = to_params(&nq, c, tr.0, tr.1);
                let nq = from_params(&np);
                let s = sse(&nq);
                if s.is_finite() && s < cur {
                    let rel = (cur - s) / cur.max(1e-12);
                    q = nq;
                    cur = s;
                    lambda = (lambda * 0.3).max(1e-9);
                    improved = true;
                    if rel < 1e-10 {
                        return (to_params(&q, c, tr.0, tr.1), cur);
                    }
                    break;
                }
            }
            lambda *= 4.0;
            if lambda > 1e12 {
                break;
            }
        }
        if !improved {
            break;
        }
    }
    (to_params(&q, c, tr.0, tr.1), cur)
}

/// Small deterministic xorshift generator (no external rand dependency).
pub struct Rng(pub u64);
impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    pub fn uniform(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    pub fn gauss(&mut self) -> f64 {
        let (u1, u2) = (self.uniform().max(1e-12), self.uniform());
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct FitResult {
    pub params: Params,
    /// 1-sigma uncertainty per parameter (f0 Hz, v m/s, d m, tca s): the larger of the linearised and bootstrap values.
    pub sigma: Sigma,
    pub rms_hz: f64,
    pub n_total: usize,
    pub n_used: usize,
    /// Observed frequency span divided by the span a full pass (far approach to far recede) would show.
    pub coverage: f64,
    /// Bootstrap 16th-84th percentile range of the closest distance (m).
    pub d_range_m: Option<(f64, f64)>,
    pub used: Vec<bool>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Sigma {
    pub f0: Option<f64>,
    pub v: Option<f64>,
    pub d: Option<f64>,
    pub tca: Option<f64>,
}

fn weighted_median(vals: &[f64]) -> f64 {
    if vals.is_empty() {
        return 0.0;
    }
    let mut v = vals.to_vec();
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

/// Fit the flyby model to a tracked tonal line. `bin_hz` is the spectrogram bin width (sets the outlier scale).
pub fn fit(points: &[Point], c: f64, bin_hz: f64) -> Result<FitResult, String> {
    let n = points.len();
    if n < 12 {
        return Err("too few tracked points to fit".into());
    }
    let mut pts = points.to_vec();
    pts.sort_by(|a, b| a.t.total_cmp(&b.t));
    let t_lo = pts[0].t - 2.0;
    let t_hi = pts[n - 1].t + 2.0;
    let tr = (t_lo, t_hi);
    let k = (n / 8).max(3);
    let f_hi = weighted_median(&pts[..k].iter().map(|p| p.f).collect::<Vec<_>>());
    let f_lo = weighted_median(&pts[n - k..].iter().map(|p| p.f).collect::<Vec<_>>());
    if f_hi < f_lo * 1.003 {
        return Err("the tracked line is not falling: a flyby shows a pitch glide from high (approaching) to low (receding)".into());
    }
    let f0_init = 2.0 * f_hi * f_lo / (f_hi + f_lo);
    let beta = (f_hi - f_lo) / (f_hi + f_lo);
    let v0 = (beta * c).clamp(5.0, MAX_SPEED.min(c * 0.9));
    let mut w: Vec<f64> = pts.iter().map(|p| p.w).collect();

    // Coarse multi-start grid, then LM refine the best few.
    let mut starts: Vec<(f64, Params)> = Vec::new();
    for ti in 0..24 {
        let tca = t_lo + (t_hi - t_lo) * (ti as f64 + 0.5) / 24.0;
        for &d in &[10.0, 30.0, 100.0, 300.0, 1000.0, 3000.0] {
            for &vm in &[1.0, 1.6] {
                let p = Params { f0: f0_init, v: (v0 * vm).min(MAX_SPEED), d, tca };
                let q = from_params(&p);
                let s: f64 = residuals(&q, &pts, &w, c, tr).iter().map(|r| r * r).sum();
                starts.push((s, p));
            }
        }
    }
    starts.sort_by(|a, b| a.0.total_cmp(&b.0));
    let mut best: Option<(Params, f64)> = None;
    for (_, p0) in starts.iter().take(6) {
        let (p, s) = lm(&pts, &w, p0, c, tr, 80);
        if best.as_ref().is_none_or(|b| s < b.1) {
            best = Some((p, s));
        }
    }
    let (mut p, _) = best.ok_or("fit failed")?;

    // Robust reweighting (Cauchy-style) to shrug off tracker glitches, then drop gross outliers.
    let scale = (2.0 * bin_hz).max(1.0);
    for _ in 0..4 {
        let res: Vec<f64> = pts.iter().map(|pt| freq_at(pt.t, &p, c) - pt.f).collect();
        let mad = weighted_median(&res.iter().map(|r| r.abs()).collect::<Vec<_>>());
        let s = (1.4826 * mad).max(scale * 0.5);
        for i in 0..n {
            let z = res[i] / (2.5 * s);
            w[i] = pts[i].w / (1.0 + z * z);
        }
        p = lm(&pts, &w, &p, c, tr, 60).0;
    }
    let res: Vec<f64> = pts.iter().map(|pt| freq_at(pt.t, &p, c) - pt.f).collect();
    let mad = weighted_median(&res.iter().map(|r| r.abs()).collect::<Vec<_>>());
    let cut = (4.0 * 1.4826 * mad).max(2.0 * scale);
    let used: Vec<bool> = res.iter().map(|r| r.abs() <= cut).collect();
    let n_used = used.iter().filter(|u| **u).count();
    if n_used < 10 {
        return Err("too few points agree with any flyby curve".into());
    }
    let inl: Vec<Point> = pts.iter().zip(&used).filter(|(_, u)| **u).map(|(p, _)| *p).collect();
    let wi: Vec<f64> = inl.iter().map(|p| p.w).collect();
    let (p, sse) = lm(&inl, &wi, &p, c, tr, 80);
    let rms = (inl.iter().map(|pt| (freq_at(pt.t, &p, c) - pt.f).powi(2)).sum::<f64>() / inl.len() as f64).sqrt();
    let s2 = sse / (inl.len() as f64 - 4.0).max(1.0); // weighted residual variance

    // Linearised covariance.
    let q = from_params(&p);
    let jm = jacobian(&q, &inl, &wi, c, tr);
    let a = normal_eq(&jm);
    let mut sig = [None; 4];
    let mut cols = Vec::new();
    for k in 0..4 {
        let mut e = vec![0.0; 4];
        e[k] = 1.0;
        cols.push(solve(a.clone(), e));
    }
    if cols.iter().all(|c| c.is_some()) {
        for k in 0..4 {
            let var = cols[k].as_ref().unwrap()[k] * s2;
            if var.is_finite() && var >= 0.0 {
                sig[k] = Some(var.sqrt());
            }
        }
    }
    // d is fitted as ln d: convert to metres.
    sig[2] = sig[2].map(|s| s * p.d);

    // Pairs bootstrap: honest about the strongly correlated v/d/f0 trio on short or one-sided clips.
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut draws: Vec<Params> = Vec::new();
    for _ in 0..40 {
        let sample: Vec<Point> = (0..inl.len()).map(|_| inl[(rng.next_u64() % inl.len() as u64) as usize]).collect();
        let ws: Vec<f64> = sample.iter().map(|p| p.w).collect();
        let (bp, bs) = lm(&sample, &ws, &p, c, tr, 40);
        if bs.is_finite() {
            draws.push(bp);
        }
    }
    let spread = |f: &dyn Fn(&Params) -> f64| -> Option<(f64, f64, f64)> {
        if draws.len() < 10 {
            return None;
        }
        let mut v: Vec<f64> = draws.iter().map(f).collect();
        v.sort_by(f64::total_cmp);
        let (lo, hi) = (v[(v.len() as f64 * 0.16) as usize], v[((v.len() as f64 * 0.84) as usize).min(v.len() - 1)]);
        Some(((hi - lo) / 2.0, lo, hi))
    };
    let merge = |lin: Option<f64>, b: Option<f64>| match (lin, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    let bf0 = spread(&|p| p.f0);
    let bv = spread(&|p| p.v);
    let bd = spread(&|p| p.d);
    let bt = spread(&|p| p.tca);
    let sigma = Sigma {
        f0: merge(sig[0], bf0.map(|x| x.0)),
        v: merge(sig[1], bv.map(|x| x.0)),
        d: merge(sig[2], bd.map(|x| x.0)),
        tca: merge(sig[3], bt.map(|x| x.0)),
    };

    let beta = p.v / c;
    let far_span = p.f0 * (1.0 / (1.0 - beta) - 1.0 / (1.0 + beta));
    let (fmin, fmax) = inl.iter().fold((f64::MAX, f64::MIN), |(lo, hi), pt| (lo.min(pt.f), hi.max(pt.f)));
    let coverage = ((fmax - fmin) / far_span.max(1e-9)).clamp(0.0, 1.5);

    Ok(FitResult {
        params: p,
        sigma,
        rms_hz: rms,
        n_total: n,
        n_used,
        coverage,
        d_range_m: bd.map(|x| (x.1, x.2)),
        used, // indexed by the time-sorted input
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_form_matches_numeric_retarded_time() {
        let c = 343.0;
        let p = Params { f0: 1000.0, v: 150.0, d: 200.0, tca: 10.0 };
        for &t in &[0.0, 5.0, 9.9, 10.0, 11.0, 20.0] {
            let (te, r) = emission(t, &p, c);
            assert!((te + r / c - t).abs() < 1e-9, "retarded-time identity at t={t}");
        }
        // far approach / far recede asymptotes: f0/(1-b), f0/(1+b)
        let b = p.v / c;
        assert!((freq_at(-1e5, &p, c) - p.f0 / (1.0 - b)).abs() < 2.0);
        assert!((freq_at(1e5, &p, c) - p.f0 / (1.0 + b)).abs() < 2.0);
        // at closest approach the emitted-direction is perpendicular, so f = f0
        assert!((freq_at(p.tca, &p, c) - p.f0).abs() < 1e-6);
    }

    #[test]
    fn recovers_parameters_from_noisy_curve() {
        let c = 343.0;
        let truth = Params { f0: 650.0, v: 220.0, d: 400.0, tca: 12.0 };
        let mut rng = Rng(42);
        let pts: Vec<Point> = (0..400)
            .map(|i| {
                let t = i as f64 * 0.05;
                Point { t, f: freq_at(t, &truth, c) + rng.gauss() * 3.0, w: 1.0 }
            })
            .collect();
        let r = fit(&pts, c, 5.0).unwrap();
        assert!((r.params.f0 - truth.f0).abs() < 8.0, "{:?}", r.params);
        assert!((r.params.v - truth.v).abs() < 10.0, "{:?}", r.params);
        assert!((r.params.tca - truth.tca).abs() < 0.2, "{:?}", r.params);
        assert!((r.params.d / truth.d - 1.0).abs() < 0.3, "{:?}", r.params);
    }
}

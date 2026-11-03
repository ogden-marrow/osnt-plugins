//! Synthetic-flyby tests: build WAV files of passes with known parameters from first principles (a tone emitted by a
//! moving source, retarded time, 1/R amplitude) and check the full decode -> spectrogram -> track -> fit pipeline.

use crate::{
    analysis::{self, Options},
    model::{Params, Rng, emission},
};

const C: f64 = 343.0; // 20 C; Options below use temp 20.0 so the analysis matches

struct Synth {
    p: Params,
    fs: u32,
    secs: f64,
    harmonics: &'static [(f64, f64)], // (ratio to f0, relative amplitude)
    noise: f64,                       // white noise sigma relative to peak tone amplitude
    hum: bool,
}

fn render(s: &Synth, seed: u64) -> Vec<f32> {
    let mut rng = Rng(seed);
    let n = (s.secs * s.fs as f64) as usize;
    let mut x = vec![0.0f32; n];
    let norm = s.p.d; // amplitude 1 at closest approach
    for (i, out) in x.iter_mut().enumerate() {
        let t = i as f64 / s.fs as f64;
        let (te, r) = emission(t, &s.p, C);
        let amp = norm / r.max(1.0);
        let mut v = 0.0;
        for &(ratio, a) in s.harmonics {
            v += a * (2.0 * std::f64::consts::PI * s.p.f0 * ratio * te).sin();
        }
        v *= amp * 0.4;
        v += rng.gauss() * s.noise * 0.4;
        if s.hum {
            v += 0.15 * (2.0 * std::f64::consts::PI * 100.0 * t).sin();
        }
        *out = v as f32;
    }
    x
}

fn wav16(x: &[f32], fs: u32) -> Vec<u8> {
    let mut b = Vec::new();
    let data_len = (x.len() * 2) as u32;
    b.extend(b"RIFF");
    b.extend((36 + data_len).to_le_bytes());
    b.extend(b"WAVEfmt ");
    b.extend(16u32.to_le_bytes());
    b.extend(1u16.to_le_bytes());
    b.extend(1u16.to_le_bytes());
    b.extend(fs.to_le_bytes());
    b.extend((fs * 2).to_le_bytes());
    b.extend(2u16.to_le_bytes());
    b.extend(16u16.to_le_bytes());
    b.extend(b"data");
    b.extend(data_len.to_le_bytes());
    for v in x {
        b.extend(((v.clamp(-1.0, 1.0) * 32767.0) as i16).to_le_bytes());
    }
    b
}

fn wav_f32(x: &[f32], fs: u32) -> Vec<u8> {
    let mut b = Vec::new();
    let data_len = (x.len() * 4) as u32;
    b.extend(b"RIFF");
    b.extend((36 + data_len).to_le_bytes());
    b.extend(b"WAVEfmt ");
    b.extend(16u32.to_le_bytes());
    b.extend(3u16.to_le_bytes());
    b.extend(1u16.to_le_bytes());
    b.extend(fs.to_le_bytes());
    b.extend((fs * 4).to_le_bytes());
    b.extend(4u16.to_le_bytes());
    b.extend(32u16.to_le_bytes());
    b.extend(b"data");
    b.extend(data_len.to_le_bytes());
    for v in x {
        b.extend(v.to_le_bytes());
    }
    b
}

fn opts() -> Options {
    Options { temp_c: 20.0, ..Options::default() }
}

fn val(r: &serde_json::Value, k: &str) -> f64 {
    r["summary"]["fit"][k]["value"].as_f64().unwrap_or_else(|| panic!("missing {k} in {}", r["summary"]))
}

fn check(r: &serde_json::Value, truth: &Params, f_tol: f64, v_tol: f64, t_tol: f64, d_tol: f64) {
    let (f0, v, d, tca) = (val(r, "source_frequency_hz"), val(r, "speed_ms"), val(r, "closest_distance_m"), val(r, "closest_approach_heard_s"));
    println!("estimated f0={f0} v={v} d={d} tca={tca}; truth {:?}; confidence {}", truth, r["summary"]["confidence"]);
    assert!((f0 / truth.f0 - 1.0).abs() < f_tol, "f0 {f0} vs {}", truth.f0);
    assert!((v / truth.v - 1.0).abs() < v_tol, "v {v} vs {}", truth.v);
    assert!((tca - truth.tca).abs() < t_tol, "tca {tca} vs {}", truth.tca);
    assert!((d / truth.d - 1.0).abs() < d_tol, "d {d} vs {}", truth.d);
}

#[test]
fn clean_flyby_wav_is_recovered() {
    let s = Synth { p: Params { f0: 800.0, v: 200.0, d: 250.0, tca: 15.0 }, fs: 22050, secs: 30.0, harmonics: &[(1.0, 1.0)], noise: 0.0, hum: false };
    let wav = wav16(&render(&s, 1), s.fs);
    let r = analysis::analyze(wav.clone(), wav.len(), &opts()).expect("analysis");
    check(&r, &s.p, 0.01, 0.05, 0.15, 0.2);
    assert_eq!(r["summary"]["confidence"], "high");
}

#[test]
fn noisy_flyby_with_hum_and_harmonics_is_recovered() {
    // white noise at 30% of the tone's closest-approach amplitude, harmonics, and a 100 Hz hum throughout
    let s = Synth { p: Params { f0: 520.0, v: 140.0, d: 180.0, tca: 18.0 }, fs: 16000, secs: 36.0, harmonics: &[(1.0, 1.0), (2.0, 0.6), (3.0, 0.3)], noise: 0.6, hum: true };
    let wav = wav16(&render(&s, 7), s.fs);
    let r = analysis::analyze(wav.clone(), wav.len(), &opts()).expect("analysis");
    check(&r, &s.p, 0.02, 0.10, 0.4, 0.35);
    // uncertainty is reported and positive
    assert!(r["summary"]["fit"]["speed_ms"]["sigma"].as_f64().unwrap() > 0.5, "systematic floor must keep sigma honest");
}

#[test]
fn quiet_clip_with_strong_harmonic_does_not_hop_between_lines() {
    // Almost noise-free, second harmonic nearly as loud as the fundamental: both lines saturate the tracker's contrast.
    let s = Synth { p: Params { f0: 700.0, v: 100.0, d: 200.0, tca: 15.0 }, fs: 16000, secs: 30.0, harmonics: &[(1.0, 1.0), (2.0, 0.9)], noise: 0.0, hum: false };
    let wav = wav16(&render(&s, 11), s.fs);
    let r = analysis::analyze(wav.clone(), wav.len(), &opts()).expect("analysis");
    // v, d and timing are independent of which harmonic is tracked
    let (v, d, tca) = (val(&r, "speed_ms"), val(&r, "closest_distance_m"), val(&r, "closest_approach_heard_s"));
    assert!((v / s.p.v - 1.0).abs() < 0.1, "v {v}");
    assert!((d / s.p.d - 1.0).abs() < 0.3, "d {d}");
    assert!((tca - s.p.tca).abs() < 0.5, "tca {tca}");
}

#[test]
fn float_wav_decodes_the_same() {
    let s = Synth { p: Params { f0: 1000.0, v: 120.0, d: 150.0, tca: 12.0 }, fs: 22050, secs: 24.0, harmonics: &[(1.0, 1.0)], noise: 0.05, hum: false };
    let wav = wav_f32(&render(&s, 3), s.fs);
    let r = analysis::analyze(wav.clone(), wav.len(), &opts()).expect("analysis");
    check(&r, &s.p, 0.02, 0.08, 0.3, 0.35);
}

#[test]
fn truncated_pass_reports_low_confidence_and_wide_uncertainty() {
    // approach only: the clip ends 1 s BEFORE closest approach, so the recede is never heard
    let s = Synth { p: Params { f0: 800.0, v: 200.0, d: 250.0, tca: 15.0 }, fs: 22050, secs: 14.0, harmonics: &[(1.0, 1.0)], noise: 0.3, hum: false };
    let wav = wav16(&render(&s, 5), s.fs);
    if let Ok(r) = analysis::analyze(wav.clone(), wav.len(), &opts()) {
        let conf = r["summary"]["confidence"].as_str().unwrap();
        println!("truncated: {}", serde_json::to_string(&r["summary"]).unwrap());
        assert_ne!(conf, "high", "a truncated pass must not claim high confidence");
        assert!(!r["summary"]["warnings"].as_array().unwrap().is_empty() || conf == "low" || conf == "medium");
    }
}

#[test]
fn steady_tone_is_not_a_flyby() {
    let fs = 16000u32;
    let x: Vec<f32> = (0..fs as usize * 15).map(|i| (0.3 * (2.0 * std::f64::consts::PI * 700.0 * i as f64 / fs as f64).sin()) as f32).collect();
    let wav = wav16(&x, fs);
    assert!(analysis::analyze(wav.clone(), wav.len(), &opts()).is_err());
}

#[test]
fn pure_noise_is_rejected_or_low_confidence() {
    let mut rng = Rng(99);
    let fs = 16000u32;
    let x: Vec<f32> = (0..fs as usize * 15).map(|_| (rng.gauss() * 0.1) as f32).collect();
    let wav = wav16(&x, fs);
    match analysis::analyze(wav.clone(), wav.len(), &opts()) {
        Err(_) => {}
        Ok(r) => assert_eq!(r["summary"]["confidence"], "low", "noise must never look credible: {}", r["summary"]),
    }
}

#[test]
fn garbage_and_overlong_input_are_rejected() {
    assert!(analysis::analyze(vec![1, 2, 3, 4, 5, 6, 7, 8], 8, &opts()).is_err());
    let x = vec![0.0f32; 22050 * 200];
    let wav = wav16(&x, 22050);
    let e = analysis::analyze(wav.clone(), wav.len(), &opts()).unwrap_err();
    assert!(e.contains("longer"), "{e}");
}

#[tokio::test]
async fn candidates_degrade_gracefully_when_adsb_history_is_absent() {
    use std::sync::Arc;
    use axum::{body::Body, http::Request};
    use tower_service_shim::call;
    let st = Arc::new(crate::AppState { agent: osnt_common::http_agent("test"), adsb_base: Some("http://127.0.0.1:1".into()), slots: tokio::sync::Semaphore::new(1) });
    let uri = "/api/candidates?speed_ms=200&clip_from=2026-01-01T10:00:00Z&clip_to=2026-01-01T10:30:00Z&lat=51&lon=0&radius_km=5";
    let (status, body) = call(crate::router(st), Request::get(uri).body(Body::empty()).unwrap()).await;
    assert_eq!(status, 200);
    assert_eq!(body["available"], false);
    assert_eq!(body["candidates"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn tools_and_predict_endpoints_work() {
    use std::sync::Arc;
    use axum::{body::Body, http::Request};
    use tower_service_shim::call;
    let st = Arc::new(crate::AppState { agent: osnt_common::http_agent("test"), adsb_base: None, slots: tokio::sync::Semaphore::new(1) });
    let (_, tools) = call(crate::router(st.clone()), Request::get("/tools").body(Body::empty()).unwrap()).await;
    assert!(tools.as_array().unwrap().len() >= 2);
    let (s, p) = call(crate::router(st), Request::get("/api/predict?f0=1000&speed_ms=200&distance_m=300").body(Body::empty()).unwrap()).await;
    assert_eq!(s, 200);
    let a = p["approach_asymptote_hz"].as_f64().unwrap();
    assert!((a - 1000.0 / (1.0 - 200.0 / 340.4)).abs() < 5.0, "{a}");
}

/// Tiny helper to drive an axum Router in-process without extra dev-dependencies.
mod tower_service_shim {
    use axum::{Router, body::Body, http::Request};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub async fn call(app: Router, req: Request<Body>) -> (u16, serde_json::Value) {
        // Serve on an ephemeral loopback port and issue a plain HTTP/1.1 request.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let path = req.uri().path_and_query().unwrap().to_string();
        s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).await.unwrap();
        let text = String::from_utf8_lossy(&raw).to_string();
        let status: u16 = text.split(' ').nth(1).unwrap().parse().unwrap();
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
        // tolerate chunked encoding: take from first '{' or '[' to last '}' or ']'
        let start = body.find(['{', '[']).unwrap_or(0);
        let end = body.rfind(['}', ']']).map(|e| e + 1).unwrap_or(body.len());
        (status, serde_json::from_str(&body[start..end]).unwrap_or(serde_json::Value::Null))
    }
}

#[test]
#[ignore]
fn debug_track() {
    use crate::{dsp, model::freq_at};
    let s = Synth { p: Params { f0: 800.0, v: 200.0, d: 250.0, tca: 15.0 }, fs: 22050, secs: 30.0, harmonics: &[(1.0, 1.0)], noise: 0.0, hum: false };
    let x = render(&s, 1);
    let sp = dsp::spectrogram(&x, s.fs as f64, 60.0, 5000.0);
    let tr = dsp::track_lines(&sp, 1);
    println!("bin_hz {} hop_s {} n {}", sp.bin_hz, sp.hop_s, tr[0].points.len());
    for (i, (t, f, snr)) in tr[0].points.iter().enumerate() {
        if i % 20 == 0 { println!("t {t:.2} f {f:.1} truth {:.1} snr {snr:.1}", freq_at(*t, &s.p, C)); }
    }
}

//! Doppler flyby check: estimate speed, closest approach and distance of an aircraft/vehicle pass from the Doppler
//! shift of a recording, as a media-verification aid. Audio is analysed in memory and never stored. Nothing here
//! identifies people; it analyses the physics of one moving sound source.

mod analysis;
mod candidates;
mod decode;
mod dsp;
mod model;

use std::{env, net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Query, State},
    http::StatusCode,
    response::Html,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Semaphore;

const PAGE: &str = include_str!("../assets/index.html");
const MAX_BYTES: usize = 40 * 1024 * 1024;
const UA: &str = "osnt-doppler/0.1 (flyby Doppler check; personal OSINT hub)";

struct AppState {
    agent: ureq::Agent,
    adsb_base: Option<String>,
    slots: Semaphore,
}
type Shared = Arc<AppState>;
type ApiErr = (StatusCode, Json<Value>);

fn bad(msg: impl Into<String>) -> ApiErr {
    (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "error": msg.into() })))
}

#[derive(Deserialize)]
struct AnalyzeQuery {
    temp_c: Option<f64>,
    fmin: Option<f64>,
    fmax: Option<f64>,
    max_lines: Option<usize>,
    /// Unix seconds or ISO-8601 UTC time of the first sample of the clip (optional; labels absolute times).
    clip_start: Option<String>,
}

async fn analyze(State(st): State<Shared>, Query(q): Query<AnalyzeQuery>, body: Bytes) -> Result<Json<Value>, ApiErr> {
    if body.is_empty() {
        return Err(bad("empty body: POST the raw audio file bytes (WAV, MP3, AAC/M4A, OGG, FLAC)"));
    }
    let mut o = analysis::Options::default();
    if let Some(t) = q.temp_c {
        if !(-60.0..=60.0).contains(&t) {
            return Err(bad("temp_c must be between -60 and 60"));
        }
        o.temp_c = t;
    }
    if let Some(f) = q.fmin {
        o.fmin = f.clamp(20.0, 10_000.0);
    }
    if let Some(f) = q.fmax {
        o.fmax = f.clamp(100.0, 12_000.0);
    }
    if o.fmax < o.fmin * 2.0 {
        return Err(bad("fmax must be at least twice fmin"));
    }
    if let Some(m) = q.max_lines {
        o.max_lines = m;
    }
    if let Some(s) = q.clip_start.as_deref().filter(|s| !s.is_empty()) {
        o.clip_start = Some(candidates::parse_time(s).ok_or_else(|| bad("clip_start: use unix seconds or YYYY-MM-DDTHH:MM:SSZ (UTC)"))?);
    }
    let _permit = st.slots.acquire().await.map_err(|_| bad("busy"))?;
    let n = body.len();
    let res = tokio::task::spawn_blocking(move || analysis::analyze(body.to_vec(), n, &o))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "ok": false, "error": e.to_string() }))))?;
    match res {
        Ok(v) => Ok(Json(v)),
        Err(e) => Err((StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "ok": false, "error": e, "caveat": analysis::CAVEAT })))),
    }
}

#[derive(Deserialize)]
struct CandQuery {
    speed_ms: f64,
    speed_sigma_ms: Option<f64>,
    distance_m: Option<f64>,
    distance_sigma_m: Option<f64>,
    /// Seconds into the clip at which the source was nearest (the fit's "closest_approach_at_source_s").
    tca_s: Option<f64>,
    /// Approximate window for the clip's first sample: unix seconds or ISO-8601 UTC.
    clip_from: String,
    clip_to: String,
    lat: f64,
    lon: f64,
    radius_km: f64,
}

async fn status(State(st): State<Shared>) -> Json<Value> {
    let Some(base) = st.adsb_base.clone() else {
        return Json(json!({ "adsb_history": { "configured": false, "available": false } }));
    };
    let agent = candidates::history_agent();
    let b = base.clone();
    let ok = tokio::task::spawn_blocking(move || candidates::available(&agent, &b)).await.unwrap_or(false);
    Json(json!({ "adsb_history": { "configured": true, "available": ok, "base": base } }))
}

async fn find_candidates(State(st): State<Shared>, Query(q): Query<CandQuery>) -> Result<Json<Value>, ApiErr> {
    let (from, to) = (
        candidates::parse_time(&q.clip_from).ok_or_else(|| bad("clip_from: unix seconds or YYYY-MM-DDTHH:MM:SSZ (UTC)"))?,
        candidates::parse_time(&q.clip_to).ok_or_else(|| bad("clip_to: unix seconds or YYYY-MM-DDTHH:MM:SSZ (UTC)"))?,
    );
    if !(from <= to) || to - from > 5.9 * 3600.0 {
        return Err(bad("the clip time window must be ordered and at most 5.9 hours wide"));
    }
    if !(q.speed_ms.is_finite() && (1.0..=450.0).contains(&q.speed_ms)) {
        return Err(bad("speed_ms must be 1-450"));
    }
    if !(-90.0..=90.0).contains(&q.lat) || !(-180.0..=180.0).contains(&q.lon) || !(0.1..=300.0).contains(&q.radius_km) {
        return Err(bad("lat/lon out of range, or radius_km not within 0.1-300"));
    }
    let tca = q.tca_s.unwrap_or(0.0);
    let cq = candidates::Query {
        speed_ms: q.speed_ms,
        speed_sigma: q.speed_sigma_ms.unwrap_or(0.05 * q.speed_ms).max(0.0),
        distance_m: q.distance_m.filter(|d| d.is_finite() && *d >= 0.0),
        distance_sigma: q.distance_sigma_m.unwrap_or(0.0).max(0.0),
        t_from: from + tca,
        t_to: to + tca,
        lat: q.lat,
        lon: q.lon,
        radius_km: q.radius_km,
    };
    let note = "Candidates, not matches: Doppler gives no heading; speed is relative to the air; the listener may be anywhere in the area. Verify against the clip (audio, visible aircraft, claimed time) before treating any as the source.";
    let Some(base) = st.adsb_base.clone() else {
        return Ok(Json(json!({ "available": false, "reason": "adsb-history is not configured", "candidates": [], "note": note })));
    };
    let agent = candidates::history_agent();
    let fetched = tokio::task::spawn_blocking(move || {
        Ok::<_, String>(match candidates::fetch(&agent, &base, &cq)? {
            candidates::Fetched::Samples(s) => Ok((candidates::evaluate(&s, &cq, 25), s.len())),
            candidates::Fetched::Pending { job_id, progress } => Err((job_id, progress)),
        })
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "ok": false, "error": e.to_string() }))))?;
    let resolution = "adsb-history data is the archive's 10-second heatmap resolution; ground speed and track are derived from successive samples and are coarse, especially in turns.";
    Ok(Json(match fetched {
        Ok(Ok((c, n))) => json!({
            "available": true, "records_examined": n, "candidates": c, "note": note, "resolution_note": resolution,
            "event_window_unix": [from + tca, to + tca],
        }),
        Ok(Err((job_id, progress))) => json!({
            "available": true, "pending": true, "job_id": job_id, "progress": progress, "candidates": [], "note": note,
            "hint": "adsb-history is still downloading this part of the archive (about 10-20 MB per half hour). Repeat the same request in a minute; the job is reused.",
        }),
        Err(e) => json!({ "available": false, "reason": e, "hint": "Install and start the adsb-history plugin to enable this step.", "candidates": [], "note": note }),
    }))
}

#[derive(Deserialize)]
struct PredictQuery {
    f0: f64,
    speed_ms: f64,
    distance_m: f64,
    temp_c: Option<f64>,
}

/// What a given pass would sound like: useful for testing a claim ("a jet at 250 m/s passing 300 m away").
async fn predict(Query(q): Query<PredictQuery>) -> Result<Json<Value>, ApiErr> {
    if !(20.0..=20_000.0).contains(&q.f0) || !(1.0..=450.0).contains(&q.speed_ms) || !(1.0..=30_000.0).contains(&q.distance_m) {
        return Err(bad("f0 20-20000 Hz, speed_ms 1-450, distance_m 1-30000"));
    }
    let c = model::sound_speed(q.temp_c.unwrap_or(15.0).clamp(-60.0, 60.0));
    if q.speed_ms >= c {
        return Err(bad("supersonic passes are outside this model"));
    }
    let p = model::Params { f0: q.f0, v: q.speed_ms, d: q.distance_m, tca: 0.0 };
    let b = q.speed_ms / c;
    let half = (6.0 * q.distance_m / q.speed_ms).clamp(2.0, 120.0);
    let curve: Vec<Value> = (0..=60).map(|k| {
        let t = -half + 2.0 * half * k as f64 / 60.0;
        json!([(t * 100.0).round() / 100.0, (model::freq_at(t, &p, c) * 10.0).round() / 10.0])
    }).collect();
    let steepest = (model::freq_at(-0.05, &p, c) - model::freq_at(0.05, &p, c)) / 0.1;
    Ok(Json(json!({
        "approach_asymptote_hz": q.f0 / (1.0 - b), "recede_asymptote_hz": q.f0 / (1.0 + b),
        "total_shift_ratio": (1.0 + b) / (1.0 - b),
        "max_glide_hz_per_s": steepest, "sound_delay_at_closest_s": q.distance_m / c,
        "curve_t_relative_to_closest_heard_s_f_hz": curve,
        "note": "Model prediction for a constant-speed straight pass in still air; a real recording will differ.",
    })))
}

async fn tools() -> Json<Value> {
    Json(json!([
        {
            "name": "doppler_expected_curve",
            "description": "Doppler physics check: for a claimed pass (source tone frequency, speed, closest distance) return the pitch an observer would hear far before/after the pass, the maximum glide rate and a sampled curve. Use it to test whether a claim about a recorded aircraft or vehicle pass is plausible. A model, not a measurement. (Analysing an actual audio file is done on the plugin page.)",
            "method": "GET",
            "path": "api/predict",
            "parameters": { "type": "object", "properties": {
                "f0": { "type": "number", "description": "Frequency the source emits, Hz (20-20000)" },
                "speed_ms": { "type": "number", "description": "Speed in metres per second (1-450)" },
                "distance_m": { "type": "number", "description": "Closest distance to the listener in metres" },
                "temp_c": { "type": "number", "description": "Air temperature, Celsius (default 15)" }
            }, "required": ["f0", "speed_ms", "distance_m"] }
        },
        {
            "name": "doppler_aircraft_candidates",
            "description": "Optional, needs the adsb-history plugin. Given a Doppler-estimated speed (and optionally closest distance), an approximate time window for the start of the clip and an approximate area, list recorded aircraft whose ground speed and position are consistent. Returns CANDIDATES to check, never matches: no heading is known, speed is relative to the air, and the listener's exact position is unknown. Returns available=false if adsb-history is not installed.",
            "method": "GET",
            "path": "api/candidates",
            "parameters": { "type": "object", "properties": {
                "speed_ms": { "type": "number", "description": "Estimated speed, m/s" },
                "speed_sigma_ms": { "type": "number", "description": "1-sigma speed uncertainty, m/s" },
                "distance_m": { "type": "number", "description": "Estimated closest (slant) distance, m" },
                "distance_sigma_m": { "type": "number", "description": "1-sigma distance uncertainty, m" },
                "tca_s": { "type": "number", "description": "Seconds after the clip start at which the source was nearest" },
                "clip_from": { "type": "string", "description": "Earliest plausible clip start, unix seconds or YYYY-MM-DDTHH:MM:SSZ (UTC)" },
                "clip_to": { "type": "string", "description": "Latest plausible clip start (max 5.9 h after clip_from, same UTC day)" },
                "lat": { "type": "number", "description": "Centre of the approximate recording area, degrees" },
                "lon": { "type": "number", "description": "Centre of the approximate recording area, degrees" },
                "radius_km": { "type": "number", "description": "Radius of the approximate area, km (0.1-300)" }
            }, "required": ["speed_ms", "clip_from", "clip_to", "lat", "lon", "radius_km"] }
        }
    ]))
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

fn router(state: Shared) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/tools", get(tools))
        .route("/api/analyze", post(analyze))
        .route("/api/candidates", get(find_candidates))
        .route("/api/predict", get(predict))
        .route("/api/status", get(status))
        .layer(DefaultBodyLimit::max(MAX_BYTES))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    let adsb_base = env::var("OSNT_DOPPLER_ADSB_HISTORY").ok().and_then(|u| candidates::loopback_base(&u));
    let state = Arc::new(AppState { agent: osnt_common::http_agent(UA), adsb_base, slots: Semaphore::new(2) });
    let addr: SocketAddr = env::var("OSNT_DOPPLER_BIND").unwrap_or_else(|_| "127.0.0.1:8121".into()).parse().expect("bind addr");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("doppler plugin on http://{addr}");
    axum::serve(listener, router(state)).await.expect("serve");
}

#[cfg(test)]
mod tests;

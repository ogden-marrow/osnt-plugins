//! ffprobe / ffmpeg wrappers: container metadata with plain-language flags, and keyframe extraction.
//! The plugin works without ffmpeg installed; callers check [`available`] and say so.

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use base64::Engine;
use serde_json::{Value, json};

pub fn which(bin: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|p| std::env::split_paths(&p).map(|d| d.join(bin)).find(|f| f.is_file())).or_else(|| ["/usr/bin", "/usr/local/bin", "/bin"].iter().map(|d| Path::new(d).join(bin)).find(|f| f.is_file()))
}

pub fn available() -> (bool, bool) {
    (which("ffprobe").is_some(), which("ffmpeg").is_some())
}

/// Run a command with a time limit, capturing capped stdout and stderr. Arguments are passed as a vector (no shell).
pub fn run(cmd: &Path, args: &[&str], limit: Duration) -> Result<(Vec<u8>, String), String> {
    let mut child = Command::new(cmd).args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| format!("could not start {}: {e}", cmd.display()))?;
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let t_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = (&mut out).take(16 * 1024 * 1024).read_to_end(&mut b);
        b
    });
    let t_err = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = (&mut err).take(4 * 1024 * 1024).read_to_end(&mut b);
        String::from_utf8_lossy(&b).to_string()
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if start.elapsed() > limit => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("timed out after {} s", limit.as_secs()));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(40)),
            Err(e) => return Err(e.to_string()),
        }
    };
    let (o, e) = (t_out.join().unwrap_or_default(), t_err.join().unwrap_or_default());
    if status.success() { Ok((o, e)) } else { Err(e.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("ffmpeg failed").chars().take(300).collect()) }
}

// ---- metadata -----------------------------------------------------------------------------------

/// ISO 6709 location such as `+27.5916+086.5640+8850.000/` -> (lat, lon).
pub fn parse_iso6709(s: &str) -> Option<(f64, f64)> {
    let s = s.trim().trim_end_matches('/');
    let mut parts = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        if (c == '+' || c == '-') && !cur.is_empty() {
            parts.push(std::mem::take(&mut cur));
        }
        cur.push(c);
    }
    parts.push(cur);
    let lat: f64 = parts.first()?.parse().ok()?;
    let lon: f64 = parts.get(1)?.parse().ok()?;
    ((-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon)).then_some((lat, lon))
}

fn tag<'a>(tags: &'a Value, name: &str) -> Option<&'a str> {
    tags.as_object()?.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).and_then(|(_, v)| v.as_str())
}

fn fps(r: &str) -> Option<f64> {
    let (a, b) = r.split_once('/')?;
    let (a, b): (f64, f64) = (a.parse().ok()?, b.parse().ok()?);
    (b > 0.0 && a > 0.0).then_some(a / b)
}

/// Turn ffprobe's JSON into a compact summary with flags worth a second look.
pub fn summarise_probe(p: &Value) -> Value {
    let fmt = &p["format"];
    let ftags = &fmt["tags"];
    let mut flags: Vec<String> = Vec::new();
    let mut gps: Option<(f64, f64)> = None;
    for (k, v) in ftags.as_object().into_iter().flatten() {
        if k.to_ascii_lowercase().contains("location") {
            if let Some(g) = v.as_str().and_then(parse_iso6709) {
                gps = Some(g);
            }
        }
    }
    let mut streams = Vec::new();
    let mut creation: Option<String> = tag(ftags, "creation_time").map(str::to_string);
    let mut encoders: Vec<String> = Vec::new();
    for s in p["streams"].as_array().into_iter().flatten() {
        let st = &s["tags"];
        creation = creation.or_else(|| tag(st, "creation_time").map(str::to_string));
        if let Some(e) = tag(st, "encoder") {
            encoders.push(e.to_string());
        }
        let r = s["r_frame_rate"].as_str().and_then(fps);
        let avg = s["avg_frame_rate"].as_str().and_then(fps);
        if s["codec_type"] == "video" {
            if let (Some(r), Some(a)) = (r, avg) {
                if (r - a).abs() / r > 0.05 {
                    flags.push(format!("Variable frame rate (nominal {r:.2} fps, average {a:.2} fps). Common for phone and screen recordings and for edited video."));
                }
            }
        }
        streams.push(json!({
            "index": s["index"], "type": s["codec_type"], "codec": s["codec_name"], "profile": s["profile"], "width": s["width"], "height": s["height"],
            "fps": r.map(|x| (x * 100.0).round() / 100.0), "bit_rate": s["bit_rate"], "duration": s["duration"], "sample_rate": s["sample_rate"], "channels": s["channels"],
            "created": tag(st, "creation_time"), "handler": tag(st, "handler_name"), "encoder": tag(st, "encoder"), "rotation": s["side_data_list"].as_array().and_then(|a| a.iter().find_map(|d| d["rotation"].as_i64())),
        }));
    }
    if let Some(e) = tag(ftags, "encoder") {
        encoders.push(e.to_string());
    }
    if creation.is_none() {
        flags.push("No container creation time. Platforms usually strip it, so this alone is not suspicious.".into());
    }
    if encoders.iter().any(|e| e.to_ascii_lowercase().contains("lavf") || e.to_ascii_lowercase().contains("lavc") || e.to_ascii_lowercase().contains("ffmpeg") || e.to_ascii_lowercase().contains("handbrake")) {
        flags.push("Written by a general-purpose re-encoding tool (ffmpeg/Lavf, HandBrake). The file was exported or converted at least once after capture; that is ordinary for shared video.".into());
    }
    if let Some((la, lo)) = gps {
        flags.push(format!("Embedded location tag {la:.5}, {lo:.5}. Check it against what the video shows; tags can be edited or copied."));
    }
    if ftags.as_object().is_none_or(|t| t.is_empty()) && streams.iter().all(|s| s["created"].is_null()) {
        flags.push("No metadata tags at all, typical after upload to a social platform.".into());
    }
    let dur = fmt["duration"].as_str().and_then(|d| d.parse::<f64>().ok());
    json!({
        "container": fmt["format_long_name"], "container_short": fmt["format_name"], "duration_s": dur, "size_bytes": fmt["size"].as_str().and_then(|s| s.parse::<u64>().ok()), "bit_rate": fmt["bit_rate"],
        "created": creation, "brand": tag(ftags, "major_brand"), "encoders": encoders, "gps": gps.map(|(la, lo)| json!({ "lat": la, "lon": lo })),
        "tags": ftags, "streams": streams, "flags": flags,
    })
}

pub fn probe(path: &Path) -> Result<Value, String> {
    let bin = which("ffprobe").ok_or("ffprobe is not installed on this hub")?;
    let p = path.to_str().ok_or("bad path")?;
    let (out, _) = run(&bin, &["-v", "error", "-print_format", "json", "-show_format", "-show_streams", "-i", p], Duration::from_secs(30))?;
    let v: Value = serde_json::from_slice(&out).map_err(|_| "ffprobe returned unreadable output".to_string())?;
    if v["streams"].as_array().is_none_or(|s| s.is_empty()) {
        return Err("no audio or video streams found in this file".into());
    }
    Ok(summarise_probe(&v))
}

// ---- frames -------------------------------------------------------------------------------------

pub struct Frame {
    pub index: usize,
    pub time_s: Option<f64>,
    pub jpeg: Vec<u8>,
}

/// `pts_time:12.34` values from ffmpeg's showinfo filter, in output order.
pub fn parse_showinfo(stderr: &str) -> Vec<f64> {
    stderr.lines().filter(|l| l.contains("Parsed_showinfo")).filter_map(|l| l.split("pts_time:").nth(1)?.split_whitespace().next()?.parse().ok()).collect()
}

/// Evenly pick `n` of `len` indices (always including the first, spreading to the last).
pub fn spread(len: usize, n: usize) -> Vec<usize> {
    if len == 0 || n == 0 {
        return vec![];
    }
    if len <= n {
        return (0..len).collect();
    }
    (0..n).map(|i| i * (len - 1) / (n - 1).max(1)).collect()
}

/// Extract frames. `keyframes` decodes only intra frames (fast, and shows real scene changes); `even` seeks to evenly
/// spaced times. Falls back to `even` when a file has too few keyframes.
pub fn frames(path: &Path, workdir: &Path, count: usize, mode: &str, duration: Option<f64>) -> Result<(Vec<Frame>, &'static str), String> {
    let ff = which("ffmpeg").ok_or("ffmpeg is not installed on this hub")?;
    let input = path.to_str().ok_or("bad path")?;
    if mode != "even" {
        let pattern = workdir.join("k%04d.jpg");
        let pat = pattern.to_str().unwrap();
        let (_, err) = run(&ff, &["-nostdin", "-hide_banner", "-skip_frame", "nokey", "-i", input, "-vf", "showinfo,scale=480:-2", "-fps_mode", "vfr", "-frames:v", "240", "-q:v", "4", "-y", pat], Duration::from_secs(90))?;
        let times = parse_showinfo(&err);
        let mut files: Vec<PathBuf> = std::fs::read_dir(workdir).map_err(|e| e.to_string())?.flatten().map(|e| e.path()).filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with('k'))).collect();
        files.sort();
        if files.len() >= 3.min(count) {
            let pick = spread(files.len(), count);
            let out = pick.iter().enumerate().filter_map(|(i, &k)| Some(Frame { index: i, time_s: times.get(k).copied(), jpeg: std::fs::read(&files[k]).ok()? })).collect();
            return Ok((out, "keyframes"));
        }
    }
    let dur = duration.filter(|d| *d > 0.0).ok_or("the file has no known duration, so evenly spaced frames cannot be chosen")?;
    let mut out = Vec::new();
    for i in 0..count {
        let t = dur * (i as f64 + 0.5) / count as f64;
        let file = workdir.join(format!("e{i:04}.jpg"));
        let ts = format!("{t:.3}");
        if run(&ff, &["-nostdin", "-hide_banner", "-ss", &ts, "-i", input, "-frames:v", "1", "-vf", "scale=480:-2", "-q:v", "4", "-y", file.to_str().unwrap()], Duration::from_secs(30)).is_ok() {
            if let Ok(jpeg) = std::fs::read(&file) {
                out.push(Frame { index: out.len(), time_s: Some(t), jpeg });
            }
        }
    }
    if out.is_empty() {
        return Err("no frames could be decoded from this file".into());
    }
    Ok((out, "even"))
}

pub fn data_uri_jpeg(b: &[u8]) -> String {
    format!("data:image/jpeg;base64,{}", base64::engine::general_purpose::STANDARD.encode(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso6709_parsing() {
        assert_eq!(parse_iso6709("+27.5916+086.5640+8850.000/"), Some((27.5916, 86.564)));
        assert_eq!(parse_iso6709("-33.8688+151.2093/"), Some((-33.8688, 151.2093)));
        assert_eq!(parse_iso6709("+95.0+010.0/"), None);
        assert_eq!(parse_iso6709("garbage"), None);
        assert_eq!(parse_iso6709(""), None);
    }

    #[test]
    fn showinfo_and_spread() {
        let err = "[Parsed_showinfo_0 @ 0x1] n:   0 pts:      0 pts_time:0       duration: 1\n[Parsed_showinfo_0 @ 0x1] n:   1 pts:  90000 pts_time:1.5 pos: 3\nother pts_time:9 line\n";
        assert_eq!(parse_showinfo(err), vec![0.0, 1.5]);
        assert_eq!(spread(10, 4), vec![0, 3, 6, 9]);
        assert_eq!(spread(3, 8), vec![0, 1, 2]);
        assert_eq!(spread(0, 3), Vec::<usize>::new());
        assert_eq!(spread(5, 1), vec![0]);
    }

    #[test]
    fn probe_summary_flags() {
        let p = json!({ "format": { "format_name": "mov,mp4", "format_long_name": "QuickTime / MOV", "duration": "12.5", "size": "1000", "tags": { "creation_time": "2024-05-01T10:00:00.000000Z", "encoder": "Lavf60.3.100", "com.apple.quicktime.location.ISO6709": "+29.6516-082.3248+031.0/" } },
          "streams": [{ "index": 0, "codec_type": "video", "codec_name": "h264", "width": 1920, "height": 1080, "r_frame_rate": "30/1", "avg_frame_rate": "20/1", "tags": { "handler_name": "VideoHandler" } }] });
        let s = summarise_probe(&p);
        assert_eq!(s["duration_s"], 12.5);
        assert_eq!(s["gps"]["lat"], 29.6516);
        let flags = s["flags"].to_string();
        assert!(flags.contains("Variable frame rate") && flags.contains("re-encoding tool") && flags.contains("location tag"));
        assert!(!flags.contains("No container creation time"));
        let bare = summarise_probe(&json!({ "format": {}, "streams": [{ "codec_type": "audio", "codec_name": "aac" }] }));
        assert!(bare["flags"].to_string().contains("No container creation time") && bare["flags"].to_string().contains("No metadata tags"));
    }

    #[test]
    fn run_enforces_timeout_and_reports_failures() {
        let sleep = which("sleep").expect("sleep exists");
        assert!(run(&sleep, &["5"], Duration::from_millis(200)).unwrap_err().contains("timed out"));
        let f = which("false").expect("false exists");
        assert!(run(&f, &[], Duration::from_secs(5)).is_err());
        assert!(run(Path::new("/nonexistent/bin"), &[], Duration::from_secs(1)).is_err());
    }

    #[test]
    fn real_ffmpeg_end_to_end_when_installed() {
        let (probe_ok, ff_ok) = available();
        if !(probe_ok && ff_ok) {
            eprintln!("ffmpeg not installed: skipping");
            return;
        }
        let dir = std::env::temp_dir().join(format!("mv-ff-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let clip = dir.join("t.mp4");
        // 6 s test pattern with a keyframe every second
        run(&which("ffmpeg").unwrap(), &["-nostdin", "-v", "error", "-f", "lavfi", "-i", "testsrc=duration=6:size=320x240:rate=10", "-g", "10", "-pix_fmt", "yuv420p", "-y", clip.to_str().unwrap()], Duration::from_secs(60)).unwrap();
        let p = probe(&clip).unwrap();
        assert_eq!(p["streams"][0]["width"], 320);
        assert!(p["duration_s"].as_f64().unwrap() > 5.0);
        let work = dir.join("w");
        std::fs::create_dir_all(&work).unwrap();
        let (fr, mode) = frames(&clip, &work, 4, "keyframes", p["duration_s"].as_f64()).unwrap();
        assert_eq!(mode, "keyframes");
        assert_eq!(fr.len(), 4);
        assert!(fr[0].jpeg.starts_with(&[0xFF, 0xD8]));
        assert!(fr[3].time_s.unwrap() > fr[0].time_s.unwrap());
        let work2 = dir.join("w2");
        std::fs::create_dir_all(&work2).unwrap();
        let (fr, mode) = frames(&clip, &work2, 3, "even", p["duration_s"].as_f64()).unwrap();
        assert_eq!((mode, fr.len()), ("even", 3));
        std::fs::write(dir.join("junk.mp4"), b"not a video at all").unwrap();
        assert!(probe(&dir.join("junk.mp4")).is_err());
    }
}

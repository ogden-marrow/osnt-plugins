//! Locating the external tools and building their command lines (argument arrays only, never a shell).

use std::{
    ffi::OsString,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

/// Directories searched after PATH (a systemd unit may run with a very small PATH).
pub const EXTRA_DIRS: [&str; 3] = ["/usr/local/bin", "/usr/bin", "/bin"];

fn is_exec(p: &Path) -> bool {
    p.metadata().is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Finds `name`. A non-empty `override_path` (from OSNT_YTMP3_YTDLP / OSNT_YTMP3_FFMPEG) is used exclusively:
/// if it is wrong the tool counts as missing rather than silently falling back.
pub fn find_tool(name: &str, override_path: Option<&str>, path_env: Option<OsString>) -> Option<PathBuf> {
    if let Some(o) = override_path.filter(|o| !o.is_empty()) {
        let p = PathBuf::from(o);
        return (p.is_absolute() && is_exec(&p)).then_some(p);
    }
    let mut dirs: Vec<PathBuf> = path_env.map(|p| std::env::split_paths(&p).collect()).unwrap_or_default();
    dirs.extend(EXTRA_DIRS.iter().map(PathBuf::from));
    dirs.into_iter().filter(|d| d.is_absolute()).map(|d| d.join(name)).find(|p| is_exec(p))
}

/// First call: metadata only. Output is one line `<duration seconds or NA>\t<title>`.
pub fn probe_args(url: &str) -> Vec<String> {
    ["--ignore-config", "--no-playlist", "--no-warnings", "--skip-download", "--print", "%(duration)s\t%(title)s", "--", url].map(String::from).to_vec()
}

/// Second call: fetch the best audio stream into `out_template` (which contains `%(ext)s`). ffmpeg does the MP3 step.
pub fn download_args(url: &str, out_template: &str, max_bytes: u64) -> Vec<String> {
    let mut v: Vec<String> = [
        "--ignore-config",
        "--no-playlist",
        "--no-warnings",
        "--no-part",
        "--quiet",
        "--progress",
        "--newline",
        "--progress-template",
        "download:%(progress._percent_str)s",
        "-f",
        "bestaudio/best",
        "--max-filesize",
    ]
    .map(String::from)
    .to_vec();
    v.push(max_bytes.to_string());
    v.extend(["-o", out_template, "--", url].map(String::from));
    v
}

/// Third call: transcode to 192 kbit/s MP3, optionally trimmed, stripping tags/metadata, capped at `max_bytes`.
pub fn ffmpeg_args(input: &Path, output: &Path, start: Option<u64>, length: Option<u64>, max_bytes: u64) -> Vec<String> {
    let mut v: Vec<String> = ["-nostdin", "-hide_banner", "-loglevel", "error", "-y"].map(String::from).to_vec();
    if let Some(s) = start.filter(|s| *s > 0) {
        v.extend(["-ss".into(), s.to_string()]);
    }
    v.extend(["-i".into(), input.to_string_lossy().into_owned()]);
    if let Some(l) = length {
        v.extend(["-t".into(), l.to_string()]);
    }
    v.extend(["-vn", "-map_metadata", "-1", "-codec:a", "libmp3lame", "-b:a", "192k", "-fs"].map(String::from));
    v.push(max_bytes.to_string());
    v.extend(["-f", "mp3"].map(String::from));
    v.push(output.to_string_lossy().into_owned());
    v
}

pub const INSTALL_FFMPEG: &str = "sudo apt update && sudo apt install -y ffmpeg";
pub const INSTALL_YTDLP: &str = "sudo curl -L https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp_linux_aarch64 -o /usr/local/bin/yt-dlp && sudo chmod a+rx /usr/local/bin/yt-dlp";
pub const INSTALL_YTDLP_PIPX: &str = "sudo apt install -y pipx && sudo PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install yt-dlp";
pub const UPDATE_YTDLP: &str = "sudo yt-dlp -U";

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn url_comes_after_double_dash_and_is_last() {
        let url = "https://www.youtube.com/watch?v=dQw4w9WgXcQ";
        for args in [probe_args(url), download_args(url, "/s/audio.%(ext)s", 1000)] {
            assert_eq!(args.last().unwrap(), url);
            assert_eq!(args[args.len() - 2], "--");
            assert_eq!(args.iter().filter(|a| *a == url).count(), 1);
        }
    }

    #[test]
    fn download_args_shape() {
        let a = download_args("U", "/s/audio.%(ext)s", 123);
        let i = a.iter().position(|x| x == "--max-filesize").unwrap();
        assert_eq!(a[i + 1], "123");
        assert!(a.contains(&"--no-playlist".to_string()) && a.contains(&"--ignore-config".to_string()));
        assert!(!a.iter().any(|x| x == "--exec" || x == "-x" || x == "--update"));
    }

    #[test]
    fn ffmpeg_args_trim_and_cap() {
        let a = ffmpeg_args(Path::new("/s/in.webm"), Path::new("/s/out.mp3"), Some(30), Some(60), 999);
        let pos = |k: &str| a.iter().position(|x| x == k).unwrap();
        assert!(pos("-ss") < pos("-i"), "seek before input");
        assert_eq!(a[pos("-ss") + 1], "30");
        assert_eq!(a[pos("-t") + 1], "60");
        assert_eq!(a[pos("-fs") + 1], "999");
        assert_eq!(a.last().unwrap(), "/s/out.mp3");
        let b = ffmpeg_args(Path::new("/s/in"), Path::new("/s/o"), Some(0), None, 1);
        assert!(!b.contains(&"-ss".to_string()) && !b.contains(&"-t".to_string()));
    }

    #[test]
    fn find_tool_rules() {
        let d = tempfile::tempdir().unwrap();
        let exe = d.path().join("osnt-fake-tool");
        fs::write(&exe, "#!/bin/sh\n").unwrap();
        assert_eq!(find_tool("osnt-fake-tool", None, Some(d.path().into())), None, "not executable yet");
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(find_tool("osnt-fake-tool", None, Some(d.path().into())), Some(exe.clone()));
        assert_eq!(find_tool("osnt-fake-tool", Some(exe.to_str().unwrap()), None), Some(exe.clone()));
        // A bad override does not fall back to PATH.
        assert_eq!(find_tool("osnt-fake-tool", Some("/nonexistent/tool"), Some(d.path().into())), None);
        assert_eq!(find_tool("osnt-fake-tool", Some("relative/tool"), Some(d.path().into())), None);
        assert_eq!(find_tool("definitely-not-a-real-tool-xyz", None, None), None);
    }
}

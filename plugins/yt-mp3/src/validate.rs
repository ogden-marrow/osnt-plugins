//! Input validation: YouTube URLs, trim times, filenames. Pure functions, no I/O.

const HOSTS: [&str; 5] = ["youtube.com", "www.youtube.com", "m.youtube.com", "music.youtube.com", "youtu.be"];

fn valid_id(id: &str) -> bool {
    id.len() == 11 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Accepts only `https://` links on the allowed YouTube hosts and returns the 11-character video id.
/// Nothing the user typed is passed on except this id; the plugin rebuilds the URL itself.
pub fn parse_youtube_url(input: &str) -> Result<String, String> {
    let bad = |m: &str| Err(m.to_string());
    let s = input.trim();
    if s.is_empty() || s.len() > 300 || s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return bad("Enter a single YouTube link.");
    }
    if s.len() < 8 || !s[..8].eq_ignore_ascii_case("https://") {
        return bad("Only https:// YouTube links are accepted.");
    }
    let rest = &s[8..];
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host = rest[..auth_end].to_ascii_lowercase();
    if !HOSTS.contains(&host.as_str()) {
        return bad("Only youtube.com, music.youtube.com and youtu.be links are accepted.");
    }
    let tail = rest[auth_end..].split('#').next().unwrap_or("");
    let (path, query) = tail.split_once('?').unwrap_or((tail, ""));
    let segs: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    let id = if host == "youtu.be" {
        match segs.as_slice() {
            [id] => Some(*id),
            _ => None,
        }
    } else {
        match segs.as_slice() {
            ["watch"] => query.split('&').find_map(|kv| kv.strip_prefix("v=")),
            ["shorts" | "live" | "embed" | "v", id] if host != "music.youtube.com" => Some(*id),
            _ => None,
        }
    };
    match id {
        Some(id) if valid_id(id) => Ok(id.to_string()),
        _ => bad("That does not look like a link to a single YouTube video."),
    }
}

/// The URL actually handed to yt-dlp.
pub fn canonical_url(video_id: &str) -> String {
    format!("https://www.youtube.com/watch?v={video_id}")
}

/// Parses `90`, `1:30` or `1:02:03` into seconds. Empty input means "not set".
pub fn parse_time(input: &str) -> Result<Option<u64>, String> {
    let s = input.trim();
    if s.is_empty() {
        return Ok(None);
    }
    let err = || Err("Times look like 90, 1:30 or 1:02:03.".to_string());
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() > 3 || parts.iter().any(|p| p.is_empty() || p.len() > 6 || !p.bytes().all(|b| b.is_ascii_digit())) {
        return err();
    }
    let nums: Vec<u64> = parts.iter().map(|p| p.parse().unwrap()).collect();
    if nums.iter().skip(1).any(|n| *n >= 60) {
        return err();
    }
    Ok(Some(nums.iter().fold(0, |acc, n| acc * 60 + n)))
}

/// A safe file name stem (no extension) from a video title: no path separators, control or bidi characters.
pub fn sanitize_filename(title: &str) -> String {
    let cleaned: String = title
        .chars()
        .filter(|c| !c.is_control() && !matches!(*c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'))
        .map(|c| if "/\\:*?\"<>|%;'`$&".contains(c) { ' ' } else { c })
        .collect();
    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    let trimmed: String = collapsed.chars().take(100).collect();
    let trimmed = trimmed.trim_matches(|c: char| c == '.' || c.is_whitespace()).to_string();
    if trimmed.is_empty() { "audio".to_string() } else { trimmed }
}

/// `Content-Disposition` for a download: ASCII fallback plus an RFC 5987 UTF-8 name.
pub fn content_disposition(stem: &str) -> String {
    let stem = sanitize_filename(stem);
    let ascii: String = stem.chars().map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '_' }).collect();
    let mut enc = String::new();
    for b in format!("{stem}.mp3").bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            enc.push(b as char);
        } else {
            enc.push_str(&format!("%{b:02X}"));
        }
    }
    format!("attachment; filename=\"{ascii}.mp3\"; filename*=UTF-8''{enc}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_common_forms() {
        let id = "dQw4w9WgXcQ";
        for u in [
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://youtube.com/watch?v=dQw4w9WgXcQ&t=42s",
            "https://youtube.com/watch?list=PL1&v=dQw4w9WgXcQ",
            "HTTPS://M.YOUTUBE.COM/watch?v=dQw4w9WgXcQ",
            "https://music.youtube.com/watch?v=dQw4w9WgXcQ&si=x",
            "https://youtu.be/dQw4w9WgXcQ",
            "https://youtu.be/dQw4w9WgXcQ?si=abc#frag",
            "https://www.youtube.com/shorts/dQw4w9WgXcQ",
            "https://www.youtube.com/embed/dQw4w9WgXcQ/",
            "  https://www.youtube.com/live/dQw4w9WgXcQ  ",
        ] {
            assert_eq!(parse_youtube_url(u).as_deref(), Ok(id), "{u}");
        }
    }

    #[test]
    fn rejects_bad_urls() {
        for u in [
            "",
            "http://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "ftp://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://evil.com/watch?v=dQw4w9WgXcQ",
            "https://youtube.com.evil.com/watch?v=dQw4w9WgXcQ",
            "https://www.youtube.com@evil.com/watch?v=dQw4w9WgXcQ",
            "https://evil.com/?x=https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://www.youtube.com:8443/watch?v=dQw4w9WgXcQ",
            "https://notyoutube.com/watch?v=dQw4w9WgXcQ",
            "https://www.youtube.com/watch?v=short",
            "https://www.youtube.com/watch?v=dQw4w9WgXcQextra",
            "https://www.youtube.com/watch?v=dQw4w9WgX;Q",
            "https://www.youtube.com/watch?v=$(reboot)",
            "https://www.youtube.com/playlist?list=PLabc",
            "https://www.youtube.com/@channel",
            "https://youtu.be/",
            "https://youtu.be/dQw4w9WgXcQ/extra",
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ https://x.com",
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ\n--exec",
            "https://music.youtube.com/shorts/dQw4w9WgXcQ",
            "https://www.youtube.com/../watch?v=dQw4w9WgXcQ",
        ] {
            assert!(parse_youtube_url(u).is_err(), "should reject {u:?}");
        }
        assert!(parse_youtube_url(&format!("https://youtu.be/{}", "a".repeat(400))).is_err());
    }

    #[test]
    fn canonical_is_fixed_shape() {
        assert_eq!(canonical_url("dQw4w9WgXcQ"), "https://www.youtube.com/watch?v=dQw4w9WgXcQ");
    }

    #[test]
    fn times() {
        assert_eq!(parse_time(""), Ok(None));
        assert_eq!(parse_time(" 90 "), Ok(Some(90)));
        assert_eq!(parse_time("1:30"), Ok(Some(90)));
        assert_eq!(parse_time("1:02:03"), Ok(Some(3723)));
        assert_eq!(parse_time("0:00"), Ok(Some(0)));
        for bad in ["-1", "1:60", "1:2:3:4", "abc", "1:", ":5", "1.5", "99999999", "1:00:60"] {
            assert!(parse_time(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn filenames() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "etc passwd");
        assert_eq!(sanitize_filename("A/B\\C:D*E?F\"G<H>I|J"), "A B C D E F G H I J");
        assert_eq!(sanitize_filename("  ..hidden.. "), "hidden");
        assert_eq!(sanitize_filename(""), "audio");
        assert_eq!(sanitize_filename("///"), "audio");
        assert_eq!(sanitize_filename("a\u{0}b\nc\u{202E}d"), "abcd");
        assert_eq!(sanitize_filename(&"x".repeat(500)).len(), 100);
        assert_eq!(sanitize_filename("Café – 日本語"), "Café – 日本語");
    }

    #[test]
    fn disposition_is_safe() {
        let d = content_disposition("Café \"x\"\r\nSet-Cookie: a=b");
        assert!(!d.contains('\r') && !d.contains('\n'));
        assert_eq!(d.matches('"').count(), 2, "{d}");
        assert!(d.starts_with("attachment; filename=\"Caf_ x Set-Cookie a=b.mp3\""), "{d}");
        assert!(d.contains("filename*=UTF-8''Caf%C3%A9%20x%20Set-Cookie%20a%3Db.mp3"), "{d}");
        assert!(content_disposition("../x").contains("filename=\"x.mp3\""));
    }
}

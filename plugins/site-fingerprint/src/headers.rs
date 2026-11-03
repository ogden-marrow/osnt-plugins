//! Security-header scorecard and cookie review. The grade is a plain heuristic, labelled as such in the UI.

use serde_json::{Value, json};

pub type Headers = Vec<(String, String)>;

pub fn get<'a>(h: &'a Headers, name: &str) -> Option<&'a str> {
    h.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

fn short(s: &str) -> String {
    if s.chars().count() > 240 { format!("{}…", s.chars().take(240).collect::<String>()) } else { s.to_string() }
}

fn item(name: &str, header: &str, status: &str, points: u32, max: u32, value: Option<&str>, note: &str) -> Value {
    json!({ "name": name, "header": header, "status": status, "points": points, "max": max, "value": value.map(short), "note": note })
}

/// Judge only the directive that governs scripts (script-src, else default-src): unsafe-inline in style-src is common
/// and much less serious, and a nonce or 'strict-dynamic' makes browsers ignore unsafe-inline.
fn script_policy_weak(csp: &str) -> bool {
    let l = csp.to_ascii_lowercase();
    let dirs: Vec<&str> = l.split(';').map(str::trim).collect();
    let pick = |name: &str| dirs.iter().find(|d| d.split_whitespace().next() == Some(name)).copied();
    let Some(d) = pick("script-src").or_else(|| pick("default-src")) else { return false };
    let modern = d.contains("'strict-dynamic'") || d.contains("'nonce-");
    let toks: Vec<&str> = d.split_whitespace().skip(1).collect();
    (!modern && d.contains("'unsafe-inline'")) || d.contains("'unsafe-eval'") || toks.contains(&"*")
}

pub fn scorecard(h: &Headers, https: bool) -> Value {
    let mut items = vec![];
    match (get(h, "strict-transport-security"), https) {
        (_, false) => items.push(item("HTTP Strict Transport Security", "Strict-Transport-Security", "na", 0, 0, None, "Not applicable: the final page was served over plain http.")),
        (Some(v), _) => {
            let age: u64 = v.split(';').find_map(|p| p.trim().to_ascii_lowercase().strip_prefix("max-age=").and_then(|n| n.trim_matches('"').parse().ok())).unwrap_or(0);
            if age >= 15_552_000 {
                items.push(item("HTTP Strict Transport Security", "Strict-Transport-Security", "pass", 20, 20, Some(v), if v.to_ascii_lowercase().contains("includesubdomains") { "Long max-age, covers subdomains." } else { "Long max-age (consider includeSubDomains)." }));
            } else {
                items.push(item("HTTP Strict Transport Security", "Strict-Transport-Security", "warn", 10, 20, Some(v), "max-age is shorter than six months."));
            }
        }
        (None, _) => items.push(item("HTTP Strict Transport Security", "Strict-Transport-Security", "fail", 0, 20, None, "Missing: browsers may be downgraded to http on first visit.")),
    }
    match get(h, "content-security-policy") {
        Some(v) => {
            if script_policy_weak(v) {
                items.push(item("Content-Security-Policy", "Content-Security-Policy", "warn", 15, 25, Some(v), "Present, but allows unsafe-inline, unsafe-eval or wildcards for scripts."));
            } else {
                items.push(item("Content-Security-Policy", "Content-Security-Policy", "pass", 25, 25, Some(v), "Present without unsafe-inline or unsafe-eval."));
            }
        }
        None if get(h, "content-security-policy-report-only").is_some() => items.push(item("Content-Security-Policy", "Content-Security-Policy", "warn", 5, 25, get(h, "content-security-policy-report-only"), "Only report-only mode: nothing is enforced.")),
        None => items.push(item("Content-Security-Policy", "Content-Security-Policy", "fail", 0, 25, None, "Missing.")),
    }
    match get(h, "x-content-type-options") {
        Some(v) if v.eq_ignore_ascii_case("nosniff") => items.push(item("MIME sniffing protection", "X-Content-Type-Options", "pass", 10, 10, Some(v), "nosniff.")),
        Some(v) => items.push(item("MIME sniffing protection", "X-Content-Type-Options", "warn", 3, 10, Some(v), "Unexpected value; should be nosniff.")),
        None => items.push(item("MIME sniffing protection", "X-Content-Type-Options", "fail", 0, 10, None, "Missing.")),
    }
    let csp_fa = get(h, "content-security-policy").is_some_and(|c| c.to_ascii_lowercase().contains("frame-ancestors"));
    match (get(h, "x-frame-options"), csp_fa) {
        (_, true) => items.push(item("Clickjacking protection", "CSP frame-ancestors", "pass", 15, 15, None, "frame-ancestors is set in the CSP.")),
        (Some(v), _) if matches!(v.trim().to_ascii_lowercase().as_str(), "deny" | "sameorigin") => items.push(item("Clickjacking protection", "X-Frame-Options", "pass", 15, 15, Some(v), "")),
        (Some(v), _) => items.push(item("Clickjacking protection", "X-Frame-Options", "warn", 5, 15, Some(v), "Unusual value (ALLOW-FROM is obsolete).")),
        (None, _) => items.push(item("Clickjacking protection", "X-Frame-Options", "fail", 0, 15, None, "Neither X-Frame-Options nor CSP frame-ancestors.")),
    }
    match get(h, "referrer-policy") {
        Some(v) if !v.to_ascii_lowercase().contains("unsafe-url") => items.push(item("Referrer policy", "Referrer-Policy", "pass", 10, 10, Some(v), "")),
        Some(v) => items.push(item("Referrer policy", "Referrer-Policy", "warn", 3, 10, Some(v), "unsafe-url leaks full URLs.")),
        None => items.push(item("Referrer policy", "Referrer-Policy", "fail", 0, 10, None, "Missing: the browser default applies.")),
    }
    match get(h, "permissions-policy").or_else(|| get(h, "feature-policy")) {
        Some(v) => items.push(item("Permissions policy", "Permissions-Policy", "pass", 10, 10, Some(v), "")),
        None => items.push(item("Permissions policy", "Permissions-Policy", "fail", 0, 10, None, "Missing.")),
    }
    match get(h, "cross-origin-opener-policy") {
        Some(v) => items.push(item("Cross-origin opener policy", "Cross-Origin-Opener-Policy", "pass", 5, 5, Some(v), "")),
        None => items.push(item("Cross-origin opener policy", "Cross-Origin-Opener-Policy", "fail", 0, 5, None, "Missing (optional hardening).")),
    }
    match get(h, "cross-origin-resource-policy") {
        Some(v) => items.push(item("Cross-origin resource policy", "Cross-Origin-Resource-Policy", "pass", 5, 5, Some(v), "")),
        None => items.push(item("Cross-origin resource policy", "Cross-Origin-Resource-Policy", "fail", 0, 5, None, "Missing (optional hardening).")),
    }
    let (got, max): (u32, u32) = items.iter().fold((0, 0), |a, i| (a.0 + i["points"].as_u64().unwrap_or(0) as u32, a.1 + i["max"].as_u64().unwrap_or(0) as u32));
    let pct = if max == 0 { 0 } else { got * 100 / max };
    let grade = match pct {
        90..=100 => "A",
        75..=89 => "B",
        60..=74 => "C",
        40..=59 => "D",
        _ => "F",
    };
    let mut leaks = vec![];
    if let Some(s) = get(h, "server") {
        if s.chars().any(|c| c.is_ascii_digit()) {
            leaks.push(format!("Server header discloses a version: {}", short(s)));
        }
    }
    for k in ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"] {
        if let Some(v) = get(h, k) {
            leaks.push(format!("{k} discloses technology: {}", short(v)));
        }
    }
    json!({ "grade": grade, "score": pct, "points": got, "max": max, "items": items, "leaks": leaks,
            "note": "A simple heuristic over common response headers, not a substitute for a full audit and not comparable to other sites' grades." })
}

pub fn parse_cookie(s: &str, https: bool) -> Value {
    let mut parts = s.split(';');
    let name = parts.next().unwrap_or("").split('=').next().unwrap_or("").trim().chars().take(80).collect::<String>();
    let (mut secure, mut httponly, mut persistent) = (false, false, false);
    let (mut samesite, mut path, mut domain) = (None::<String>, None::<String>, None::<String>);
    for p in parts {
        let p = p.trim();
        let (k, v) = p.split_once('=').unwrap_or((p, ""));
        match k.to_ascii_lowercase().as_str() {
            "secure" => secure = true,
            "httponly" => httponly = true,
            "samesite" => samesite = Some(v.trim().to_ascii_lowercase()),
            "path" => path = Some(v.trim().chars().take(100).collect()),
            "domain" => domain = Some(v.trim().chars().take(100).collect()),
            "max-age" | "expires" => persistent = true,
            _ => {}
        }
    }
    let mut issues = vec![];
    if https && !secure {
        issues.push("missing Secure");
    }
    if !httponly {
        issues.push("missing HttpOnly");
    }
    match samesite.as_deref() {
        None => issues.push("no SameSite"),
        Some("none") if !secure => issues.push("SameSite=None without Secure"),
        _ => {}
    }
    if name.starts_with("__Host-") && (domain.is_some() || path.as_deref() != Some("/") || !secure) {
        issues.push("__Host- prefix rules broken");
    }
    // Only names and attributes are returned, never the value: it may be a live session token.
    json!({ "name": name, "secure": secure, "httponly": httponly, "samesite": samesite, "path": path, "domain": domain, "persistent": persistent, "issues": issues })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdrs(v: &[(&str, &str)]) -> Headers {
        v.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn grades() {
        let none = scorecard(&hdrs(&[]), true);
        assert_eq!(none["grade"], "F");
        assert_eq!(none["score"], 0);
        let good = scorecard(&hdrs(&[("strict-transport-security", "max-age=63072000; includeSubDomains"), ("content-security-policy", "default-src 'self'; frame-ancestors 'none'"), ("x-content-type-options", "nosniff"), ("referrer-policy", "no-referrer"), ("permissions-policy", "camera=()"), ("cross-origin-opener-policy", "same-origin"), ("cross-origin-resource-policy", "same-site")]), true);
        assert_eq!((good["grade"].as_str(), good["score"].as_u64()), (Some("A"), Some(100)));
        assert!(!script_policy_weak("default-src 'none'; style-src 'unsafe-inline'; script-src a.example"));
        assert!(script_policy_weak("default-src 'self'; script-src 'unsafe-inline'"));
        assert!(script_policy_weak("default-src *"));
        assert!(!script_policy_weak("script-src 'nonce-abc' 'unsafe-inline' 'strict-dynamic'"));
        let weak = scorecard(&hdrs(&[("strict-transport-security", "max-age=300"), ("content-security-policy", "script-src 'unsafe-inline'"), ("x-frame-options", "SAMEORIGIN")]), true);
        assert!(weak["items"].as_array().unwrap().iter().any(|i| i["status"] == "warn"));
        let http = scorecard(&hdrs(&[]), false);
        assert_eq!(http["items"][0]["status"], "na");
        assert_eq!(http["max"], 80, "HSTS does not count against plain-http pages");
    }

    #[test]
    fn leaks_reported() {
        let r = scorecard(&hdrs(&[("server", "Apache/2.4.41 (Ubuntu)"), ("x-powered-by", "PHP/7.4")]), true);
        assert_eq!(r["leaks"].as_array().unwrap().len(), 2);
        assert!(scorecard(&hdrs(&[("server", "cloudflare")]), true)["leaks"].as_array().unwrap().is_empty());
    }

    #[test]
    fn cookies_never_return_values() {
        let c = parse_cookie("sid=SECRETVALUE123; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600", true);
        assert!(!c.to_string().contains("SECRETVALUE"));
        assert_eq!(c["issues"].as_array().unwrap().len(), 0);
        assert_eq!(c["persistent"], true);
        let b = parse_cookie("t=1; SameSite=None", true);
        let issues: Vec<&str> = b["issues"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
        assert_eq!(issues, ["missing Secure", "missing HttpOnly", "SameSite=None without Secure"]);
        assert!(parse_cookie("__Host-x=1; Secure; Path=/; Domain=a.com; HttpOnly; SameSite=Strict", true)["issues"][0].as_str().unwrap().contains("__Host-"));
    }
}

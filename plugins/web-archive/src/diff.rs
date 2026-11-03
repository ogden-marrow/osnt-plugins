//! HTML to readable text, and a line diff between two archived versions of a page.

use std::collections::BTreeSet;

use serde_json::{Value, json};
use similar::{ChangeTag, TextDiff};

const BLOCK_TAGS: [&str; 24] = [
    "p", "div", "br", "li", "ul", "ol", "tr", "td", "th", "table", "h1", "h2", "h3", "h4", "h5", "h6", "section", "article", "header", "footer", "nav", "blockquote", "pre", "form",
];
const MAX_DIFF_LINES: usize = 1500;

fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(end) = rest.find(';').filter(|&e| e <= 10) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let ent = &rest[1..end];
        let rep = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some(' '),
            _ => ent.strip_prefix('#').and_then(|n| if let Some(h) = n.strip_prefix(['x', 'X']) { u32::from_str_radix(h, 16).ok() } else { n.parse().ok() }).and_then(char::from_u32),
        };
        match rep {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Case-insensitive search of ASCII `needle` in `hay` from `from` (byte offsets stay valid because only ASCII is matched).
fn find_ci(hay: &str, needle: &str, from: usize) -> Option<usize> {
    let h = hay.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    (from..=h.len() - n.len()).find(|&i| h[i..i + n.len()].eq_ignore_ascii_case(n))
}

/// Extract the visible text of an HTML document, one block per line. Not a full parser: it drops comments,
/// scripts, styles and tags, turns block boundaries into line breaks and decodes common entities.
pub fn html_to_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len() / 3);
    let mut i = 0;
    let b = html.as_bytes();
    while i < b.len() {
        if b[i] != b'<' {
            let next = html[i..].find('<').map(|n| i + n).unwrap_or(b.len());
            out.push_str(&html[i..next]);
            i = next;
            continue;
        }
        if html[i..].starts_with("<!--") {
            i = html[i..].find("-->").map(|n| i + n + 3).unwrap_or(b.len());
            continue;
        }
        let Some(close) = html[i..].find('>').map(|n| i + n) else { break };
        let tag = &html[i + 1..close];
        let name: String = tag.trim_start_matches('/').chars().take_while(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_lowercase();
        i = close + 1;
        if !tag.starts_with('/') && matches!(name.as_str(), "script" | "style" | "noscript" | "template" | "svg" | "title") {
            i = find_ci(html, &format!("</{name}"), i).and_then(|p| html[p..].find('>').map(|n| p + n + 1)).unwrap_or(b.len());
            continue;
        }
        if BLOCK_TAGS.contains(&name.as_str()) {
            out.push('\n');
        }
    }
    let text = decode_entities(&out);
    text.lines().map(|l| l.split_whitespace().collect::<Vec<_>>().join(" ")).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("\n")
}

pub fn title(html: &str) -> Option<String> {
    let s = find_ci(html, "<title", 0)?;
    let gt = html[s..].find('>')? + s + 1;
    let e = find_ci(html, "</title", gt)?;
    let t = decode_entities(html[gt..e].trim()).split_whitespace().collect::<Vec<_>>().join(" ");
    (!t.is_empty()).then_some(t.chars().take(300).collect())
}

/// `href` and `src` attribute values (quoted), deduplicated, in document order, capped.
pub fn links(html: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for attr in ["href=", "src="] {
        let mut from = 0;
        while let Some(p) = find_ci(html, attr, from) {
            from = p + attr.len();
            let Some(q) = html[from..].chars().next().filter(|c| *c == '"' || *c == '\'') else { continue };
            let start = from + 1;
            let Some(len) = html[start..].find(q) else { continue };
            let v = decode_entities(html[start..start + len].trim());
            if !v.is_empty() && v.len() < 500 && !v.starts_with('#') && !v.starts_with("javascript:") && seen.insert(v.clone()) {
                out.push(v);
            }
            if out.len() >= 2000 {
                return out;
            }
        }
    }
    out
}

/// Strip the archive's own rewriting so the same link in two captures compares equal.
fn normalise_link(l: &str) -> String {
    match l.strip_prefix("/web/").and_then(|r| r.split_once('/')) {
        Some((ts, rest)) if ts.trim_end_matches(|c: char| c.is_ascii_alphabetic() || c == '_').bytes().all(|b| b.is_ascii_digit()) => rest.to_string(),
        _ => l.to_string(),
    }
}

/// Line diff of the visible text of two documents with a few lines of context.
pub fn diff_pages(a_html: &str, b_html: &str) -> Value {
    let (ta, tb) = (html_to_text(a_html), html_to_text(b_html));
    let d = TextDiff::from_lines(&ta, &tb);
    let (mut added, mut removed, mut same) = (0usize, 0usize, 0usize);
    let mut hunks = Vec::new();
    let mut shown = 0usize;
    let mut truncated = false;
    for c in d.iter_all_changes() {
        match c.tag() {
            ChangeTag::Insert => added += 1,
            ChangeTag::Delete => removed += 1,
            ChangeTag::Equal => same += 1,
        }
    }
    'outer: for group in d.grouped_ops(2) {
        let mut lines = Vec::new();
        for op in &group {
            for c in d.iter_changes(op) {
                if shown >= MAX_DIFF_LINES {
                    truncated = true;
                    break 'outer;
                }
                shown += 1;
                let kind = match c.tag() {
                    ChangeTag::Insert => "add",
                    ChangeTag::Delete => "del",
                    ChangeTag::Equal => "ctx",
                };
                lines.push(json!({ "kind": kind, "text": c.value().trim_end_matches('\n') }));
            }
        }
        hunks.push(json!({ "lines": lines }));
    }
    let la: BTreeSet<String> = links(a_html).iter().map(|l| normalise_link(l)).collect();
    let lb: BTreeSet<String> = links(b_html).iter().map(|l| normalise_link(l)).collect();
    let cap = |s: BTreeSet<&String>| s.into_iter().take(100).cloned().collect::<Vec<_>>();
    json!({
        "identical_text": added == 0 && removed == 0,
        "stats": { "added": added, "removed": removed, "unchanged": same, "similarity": (d.ratio() * 1000.0).round() / 1000.0 },
        "title_a": title(a_html), "title_b": title(b_html),
        "hunks": hunks, "truncated": truncated,
        "links_added": cap(lb.difference(&la).collect()), "links_removed": cap(la.difference(&lb).collect()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "<html><head><title>Old &amp; Gold</title><style>p{color:red}</style><script>var x='<b>nope</b>';</script></head>\
<body><h1>Hello</h1><p>First   paragraph &lt;ok&gt; &#169; &unknown;</p><!-- hidden --><p>Second</p><a href=\"/web/2020/http://x.com/a\">a</a><a href='/b'>b</a></body></html>";
    const B: &str = "<html><head><title>New</title></head><body><h1>Hello</h1><p>First paragraph &lt;ok&gt; &#169; &unknown;</p><p>Third</p><a href=\"http://x.com/a\">a</a><img src=\"/c.png\"></body></html>";

    #[test]
    fn text_extraction_drops_scripts_comments_and_decodes() {
        let t = html_to_text(A);
        assert_eq!(t, "Hello\nFirst paragraph <ok> \u{a9} &unknown;\nSecond\nab");
        assert!(!t.contains("nope") && !t.contains("hidden") && !t.contains("color"));
        assert_eq!(title(A).as_deref(), Some("Old & Gold"));
    }

    #[test]
    fn handles_unterminated_markup_without_panicking() {
        let _ = html_to_text("<p>text <b");
        let _ = html_to_text("<script>never closed");
        let _ = html_to_text("&#xFFFFFFFF; &#99999999999; &");
        assert_eq!(html_to_text("a &amp b"), "a &amp b");
        assert_eq!(html_to_text("é<p>ü</p>"), "é\nü");
    }

    #[test]
    fn diff_reports_added_removed_and_links() {
        let d = diff_pages(A, B);
        assert_eq!(d["identical_text"], false);
        assert_eq!(d["stats"]["added"], 2); // Third and the shorter link text
        assert!(d["stats"]["removed"].as_u64().unwrap() >= 1); // Second
        let flat = d["hunks"].to_string();
        assert!(flat.contains("Third") && flat.contains("Second"));
        // /web/2020/http://x.com/a normalises to the same link as http://x.com/a
        assert!(!d["links_removed"].to_string().contains("x.com/a"));
        assert!(d["links_added"].to_string().contains("/c.png"));
        assert!(d["links_removed"].to_string().contains("/b"));
        assert_eq!(diff_pages(A, A)["identical_text"], true);
        assert_eq!(diff_pages("", "")["identical_text"], true);
    }

    #[test]
    fn diff_output_is_capped() {
        let big_a: String = (0..3000).map(|i| format!("<p>a{i}</p>")).collect();
        let big_b: String = (0..3000).map(|i| format!("<p>b{i}</p>")).collect();
        let d = diff_pages(&big_a, &big_b);
        assert_eq!(d["truncated"], true);
        let n: usize = d["hunks"].as_array().unwrap().iter().map(|h| h["lines"].as_array().unwrap().len()).sum();
        assert!(n <= MAX_DIFF_LINES);
    }
}

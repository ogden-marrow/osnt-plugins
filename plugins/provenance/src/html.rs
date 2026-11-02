//! Minimal pure-Rust HTML reading for `fetch_page`: title, site name, dates found in common places, visible text.
//! This is a forgiving scanner, not a full HTML parser; it never executes anything.

use serde_json::{Value, json};

pub struct Page {
    pub title: Option<String>,
    pub site_name: Option<String>,
    /// (where it was found, raw value)
    pub dates: Vec<(String, String)>,
    pub text: String,
}

const DATE_META: [&str; 20] = [
    "article:published_time", "og:article:published_time", "article:modified_time", "og:updated_time", "datepublished", "datemodified",
    "datecreated", "date", "pubdate", "publishdate", "publish-date", "dc.date", "dc.date.issued", "dc.date.created", "dcterms.created",
    "dcterms.issued", "sailthru.date", "parsely-pub-date", "last-modified", "article.published",
];

struct Tag {
    name: String,
    attrs: Vec<(String, String)>,
    closing: bool,
    end: usize,
}

impl Tag {
    fn attr(&self, k: &str) -> Option<&str> {
        self.attrs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }
}

/// Parse a tag starting at `s[start] == '<'`. Returns None if it does not look like a tag.
fn parse_tag(s: &str, start: usize) -> Option<Tag> {
    let b = s.as_bytes();
    let mut i = start + 1;
    let closing = b.get(i) == Some(&b'/');
    if closing {
        i += 1;
    }
    let name_start = i;
    while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'-' || b[i] == b':') {
        i += 1;
    }
    if i == name_start {
        return None;
    }
    let name = s[name_start..i].to_ascii_lowercase();
    let mut attrs = Vec::new();
    loop {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        if i >= b.len() {
            return None;
        }
        if b[i] == b'>' {
            return Some(Tag { name, attrs, closing, end: i + 1 });
        }
        let ks = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && !matches!(b[i], b'=' | b'>' | b'/') {
            i += 1;
        }
        if i == ks {
            i += 1; // stray character
            continue;
        }
        let key = s[ks..i].to_ascii_lowercase();
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut val = String::new();
        if b.get(i) == Some(&b'=') {
            i += 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
                let q = b[i];
                let vs = i + 1;
                i = vs;
                while i < b.len() && b[i] != q {
                    i += 1;
                }
                val = s[vs..i.min(b.len())].to_string();
                i += 1;
            } else {
                let vs = i;
                while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'>' {
                    i += 1;
                }
                val = s[vs..i].to_string();
            }
        }
        attrs.push((key, decode_entities(&val)));
    }
}

pub fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(p) = rest.find('&') {
        out.push_str(&rest[..p]);
        rest = &rest[p..];
        let Some(semi) = rest.find(';').filter(|&e| e <= 10) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let ent = &rest[1..semi];
        let rep = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some(' '),
            e if e.starts_with("#x") || e.starts_with("#X") => u32::from_str_radix(&e[2..], 16).ok().and_then(char::from_u32),
            e if e.starts_with('#') => e[1..].parse::<u32>().ok().and_then(char::from_u32),
            _ => None,
        };
        match rep {
            Some(c) => {
                out.push(c);
                rest = &rest[semi + 1..];
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

fn collapse(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn cut_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Walk JSON-LD for date keys, handling arrays and @graph.
fn jsonld_dates(v: &Value, out: &mut Vec<(String, String)>, depth: usize) {
    if depth > 8 {
        return;
    }
    match v {
        Value::Object(m) => {
            for (k, val) in m {
                if matches!(k.as_str(), "datePublished" | "dateCreated" | "dateModified" | "uploadDate") {
                    if let Some(s) = val.as_str() {
                        out.push((format!("json-ld:{k}"), s.to_string()));
                    }
                } else {
                    jsonld_dates(val, out, depth + 1);
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|x| jsonld_dates(x, out, depth + 1)),
        _ => {}
    }
}

pub fn extract(html: &str, max_text: usize) -> Page {
    let mut title = None;
    let mut site_name = None;
    let mut dates: Vec<(String, String)> = Vec::new();
    let mut text = String::new();
    let mut time_tags = 0;
    let mut i = 0;
    let mut skip_depth: Option<String> = None; // inside script/style/etc: ignore text until the closing tag
    let bytes = html.as_bytes();
    while i < bytes.len() {
        let Some(rel) = html[i..].find('<') else {
            if skip_depth.is_none() && text.len() < max_text * 4 {
                text.push_str(&html[i..]);
            }
            break;
        };
        if skip_depth.is_none() && text.len() < max_text * 4 {
            text.push_str(&html[i..i + rel]);
        }
        i += rel;
        if html[i..].starts_with("<!--") {
            i = html[i..].find("-->").map_or(bytes.len(), |e| i + e + 3);
            continue;
        }
        if matches!(bytes.get(i + 1), Some(b'!' | b'?')) {
            i = html[i..].find('>').map_or(bytes.len(), |e| i + e + 1); // doctype / processing instruction
            continue;
        }
        let Some(tag) = parse_tag(html, i) else {
            if skip_depth.is_none() {
                text.push('<');
            }
            i += 1;
            continue;
        };
        i = tag.end;
        if let Some(sk) = &skip_depth {
            if tag.closing && &tag.name == sk {
                skip_depth = None;
            }
            continue;
        }
        if tag.closing {
            text.push(' ');
            continue;
        }
        match tag.name.as_str() {
            "script" | "style" | "noscript" | "svg" | "template" => {
                // Capture the body (needed for JSON-LD) up to the matching close tag.
                let close = format!("</{}", tag.name);
                let lower_rest = html[i..].to_ascii_lowercase();
                let body_end = lower_rest.find(&close).unwrap_or(lower_rest.len());
                if tag.name == "script" && tag.attr("type").is_some_and(|t| t.to_ascii_lowercase().contains("ld+json")) {
                    if let Ok(v) = serde_json::from_str::<Value>(&html[i..i + body_end]) {
                        jsonld_dates(&v, &mut dates, 0);
                    }
                }
                i += body_end;
                let after = html[i..].find('>').map_or(bytes.len(), |e| i + e + 1);
                i = after;
            }
            "title" => {
                let end = html[i..].to_ascii_lowercase().find("</title").map_or(bytes.len(), |e| i + e);
                if title.is_none() {
                    title = Some(collapse(&decode_entities(&html[i..end]))).filter(|t| !t.is_empty());
                }
                i = html[end..].find('>').map_or(bytes.len(), |e| end + e + 1);
            }
            "meta" => {
                let key = tag.attr("property").or_else(|| tag.attr("name")).or_else(|| tag.attr("itemprop")).or_else(|| tag.attr("http-equiv")).map(str::to_ascii_lowercase);
                if let (Some(k), Some(c)) = (key, tag.attr("content")) {
                    let c = c.trim();
                    if !c.is_empty() {
                        if k == "og:site_name" || (k == "application-name" && site_name.is_none()) {
                            site_name = Some(cut_chars(c, 120));
                        }
                        if DATE_META.contains(&k.as_str()) {
                            dates.push((format!("meta:{k}"), cut_chars(c, 60)));
                        }
                    }
                }
            }
            "time" => {
                if let Some(d) = tag.attr("datetime") {
                    if time_tags < 5 {
                        time_tags += 1;
                        dates.push(("time[datetime]".into(), cut_chars(d.trim(), 60)));
                    }
                }
                text.push(' ');
            }
            "br" | "p" | "div" | "li" | "tr" | "h1" | "h2" | "h3" | "h4" | "section" | "article" => text.push(' '),
            _ => {}
        }
    }
    dates.dedup();
    dates.truncate(12);
    let text = cut_chars(&collapse(&decode_entities(&text)), max_text);
    Page { title, site_name, dates, text }
}

impl Page {
    pub fn to_json(&self, url: &str) -> Value {
        json!({
            "url": url, "title": self.title, "site_name": self.site_name,
            "dates_found": self.dates.iter().map(|(s, v)| json!({ "source": s, "value": v })).collect::<Vec<_>>(),
            "text": self.text,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<!doctype html><html><head>
<title> Big &amp; Famous Photo </title>
<meta property="og:site_name" content="Example News">
<meta property="article:published_time" content="2021-03-04T10:00:00Z">
<meta name="DC.date.issued" content='2021-03-05'>
<meta property="article:modified_time" content="2022-01-01T00:00:00Z">
<script type="application/ld+json">{"@context":"https://schema.org","@graph":[{"@type":"NewsArticle","datePublished":"2021-03-04T09:00:00+00:00","image":{"dateCreated":"2020-12-31"}}]}</script>
<script>var x = "<p>not text</p>";</script><style>p{color:red}</style>
</head><body><!-- hidden comment -->
<h1>Headline</h1><p>Photo by <b>someone</b> &mdash; taken &#38; shared.</p>
<time datetime="2021-03-03">March 3</time>
<noscript>enable js</noscript>
</body></html>"#;

    #[test]
    fn extracts_title_site_and_dates() {
        let p = extract(SAMPLE, 2000);
        assert_eq!(p.title.as_deref(), Some("Big & Famous Photo"));
        assert_eq!(p.site_name.as_deref(), Some("Example News"));
        let has = |s: &str, v: &str| p.dates.iter().any(|(src, val)| src == s && val == v);
        assert!(has("meta:article:published_time", "2021-03-04T10:00:00Z"), "{:?}", p.dates);
        assert!(has("meta:dc.date.issued", "2021-03-05"));
        assert!(has("meta:article:modified_time", "2022-01-01T00:00:00Z"));
        assert!(has("json-ld:datePublished", "2021-03-04T09:00:00+00:00"));
        assert!(has("json-ld:dateCreated", "2020-12-31"));
        assert!(has("time[datetime]", "2021-03-03"));
    }

    #[test]
    fn text_is_visible_text_only() {
        let p = extract(SAMPLE, 2000);
        assert!(p.text.contains("Headline"));
        assert!(p.text.contains("Photo by someone"));
        assert!(p.text.contains("taken & shared"));
        assert!(!p.text.contains("doctype"));
        assert!(!p.text.contains("not text"));
        assert!(!p.text.contains("color:red"));
        assert!(!p.text.contains("hidden comment"));
        assert!(!p.text.contains("enable js"));
    }

    #[test]
    fn text_is_capped_and_survives_garbage() {
        let big = format!("<p>{}</p>", "word ".repeat(10_000));
        assert_eq!(extract(&big, 2000).text.chars().count(), 2000);
        let _ = extract("<<<>>> <a href=\"x <b <meta", 100);
        let _ = extract("<script>unterminated", 100);
        let _ = extract("<p>héllo wörld ✓</p><meta content='ü'", 100);
    }
}

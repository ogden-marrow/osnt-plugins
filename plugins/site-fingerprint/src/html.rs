//! A forgiving tag scanner: enough to read title, meta, link and script attributes without a full HTML parser.

#[derive(Debug, Clone)]
pub struct Tag {
    pub name: String,
    pub attrs: Vec<(String, String)>,
}

impl Tag {
    pub fn attr(&self, k: &str) -> Option<&str> {
        self.attrs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }
}

const MAX_TAGS: usize = 6000;

/// All start tags (lower-cased names and attribute names). Comments and the bodies of script/style are skipped.
pub fn scan(html: &str) -> Vec<Tag> {
    let b = html.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() && out.len() < MAX_TAGS {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        if html[i..].starts_with("<!--") {
            i = html[i..].find("-->").map(|p| i + p + 3).unwrap_or(b.len());
            continue;
        }
        let mut j = i + 1;
        if j >= b.len() || !b[j].is_ascii_alphabetic() {
            i += 1;
            continue;
        }
        while j < b.len() && !b[j].is_ascii_whitespace() && b[j] != b'>' && b[j] != b'/' {
            j += 1;
        }
        let name = html[i + 1..j].to_ascii_lowercase();
        let mut attrs = vec![];
        loop {
            while j < b.len() && (b[j].is_ascii_whitespace() || b[j] == b'/') {
                j += 1;
            }
            if j >= b.len() || b[j] == b'>' {
                j += 1;
                break;
            }
            let ns = j;
            while j < b.len() && !b[j].is_ascii_whitespace() && b[j] != b'=' && b[j] != b'>' && b[j] != b'/' {
                j += 1;
            }
            let an = html[ns..j].to_ascii_lowercase();
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            let mut val = String::new();
            if j < b.len() && b[j] == b'=' {
                j += 1;
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < b.len() && (b[j] == b'"' || b[j] == b'\'') {
                    let q = b[j];
                    let vs = j + 1;
                    j = vs;
                    while j < b.len() && b[j] != q {
                        j += 1;
                    }
                    val = html.get(vs..j).unwrap_or("").to_string();
                    j += 1;
                } else {
                    let vs = j;
                    while j < b.len() && !b[j].is_ascii_whitespace() && b[j] != b'>' {
                        j += 1;
                    }
                    val = html.get(vs..j).unwrap_or("").to_string();
                }
            }
            if !an.is_empty() && attrs.len() < 40 {
                attrs.push((an, val));
            }
        }
        let raw = name == "script" || name == "style";
        out.push(Tag { name: name.clone(), attrs });
        i = j.min(b.len());
        if raw {
            let close = format!("</{name}");
            let lower_rest = html.get(i..).unwrap_or("").to_ascii_lowercase();
            i = lower_rest.find(&close).map(|p| i + p).unwrap_or(b.len());
        }
    }
    out
}

pub fn title(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let s = lower.find("<title")?;
    let gt = lower[s..].find('>')? + s + 1;
    let e = lower[gt..].find("</title")? + gt;
    let t = html.get(gt..e)?.split_whitespace().collect::<Vec<_>>().join(" ");
    let t = decode(&t);
    (!t.is_empty()).then(|| t.chars().take(200).collect())
}

/// Decode the handful of entities that turn up in titles and meta text.
pub fn decode(s: &str) -> String {
    s.replace("&#39;", "'").replace("&#x27;", "'").replace("&quot;", "\"").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
}

pub fn meta<'a>(tags: &'a [Tag], key: &str) -> Option<&'a str> {
    tags.iter().filter(|t| t.name == "meta").find(|t| t.attr("name").or(t.attr("property")).or(t.attr("http-equiv")).is_some_and(|n| n.eq_ignore_ascii_case(key))).and_then(|t| t.attr("content"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_tags_and_skips_scripts() {
        let h = r#"<!doctype html><html lang=en><head><TITLE> My  &amp; Site </TITLE><meta name="Generator" content='WordPress 6.4.2'><!-- <meta name="generator" content="fake"> -->
        <link rel="icon" href=/fav.png><script src="/a.js">var s = "<meta name='x' content='y'>";</script><script>if (a<b) {}</script><img src=x alt="a > b"></head></html>"#;
        let tags = scan(h);
        let names: Vec<&str> = tags.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["html", "head", "title", "meta", "link", "script", "script", "img"]);
        assert_eq!(meta(&tags, "generator"), Some("WordPress 6.4.2"));
        assert_eq!(tags.iter().find(|t| t.name == "link").unwrap().attr("href"), Some("/fav.png"));
        assert_eq!(tags.iter().find(|t| t.name == "img").unwrap().attr("alt"), Some("a > b"));
        assert_eq!(title(h).as_deref(), Some("My & Site"));
    }

    #[test]
    fn survives_garbage() {
        assert!(scan("<<<<<").is_empty());
        assert_eq!(scan("<a href='unterminated").len(), 1);
        assert_eq!(title("no title here"), None);
        let big = "<a ".repeat(100_000);
        assert!(scan(&big).len() <= MAX_TAGS);
        assert_eq!(title("<title></title>"), None);
    }
}

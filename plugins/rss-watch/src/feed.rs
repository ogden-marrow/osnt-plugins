//! Parsers: RSS 2.0, RSS 1.0 (RDF), Atom, OPML, Hacker News Algolia JSON and Telegram public-channel preview HTML,
//! plus alert-rule matching. Everything here is pure functions over bytes/strings.

use quick_xml::{Reader, events::Event};
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const MAX_ITEMS_PER_FETCH: usize = 100;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Parsed {
    pub title: String,
    pub link: String,
    pub summary: String,
    /// Unix seconds, 0 when the feed gave no usable date.
    pub published: i64,
    pub guid: String,
}

#[derive(Debug, Default)]
pub struct ParsedFeed {
    pub title: String,
    pub items: Vec<Parsed>,
}

pub fn item_id(feed: u64, p: &Parsed) -> String {
    let basis = if !p.guid.is_empty() { &p.guid } else if !p.link.is_empty() { &p.link } else { &p.title };
    let h = Sha256::digest(format!("{feed}|{basis}").as_bytes());
    h.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(end) = rest.find(';').filter(|e| *e <= 10) else {
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
            "apos" | "#39" => Some('\''),
            "nbsp" => Some(' '),
            e if e.starts_with("#x") || e.starts_with("#X") => u32::from_str_radix(&e[2..], 16).ok().and_then(char::from_u32),
            e if e.starts_with('#') => e[1..].parse().ok().and_then(char::from_u32),
            _ => None,
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

/// Remove tags, decode entities, collapse whitespace, cut to `max` characters.
pub fn plain_text(html: &str, max: usize) -> String {
    let mut out = String::with_capacity(html.len().min(4096));
    let lower = html.to_ascii_lowercase();
    let bytes = html.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            let close = if lower[i..].starts_with("<script") {
                Some("</script>")
            } else if lower[i..].starts_with("<style") {
                Some("</style>")
            } else {
                None
            };
            out.push(' ');
            match close {
                Some(c) => match lower[i..].find(c) {
                    Some(p) => i += p + c.len(),
                    None => break,
                },
                None => match html[i..].find('>') {
                    Some(p) => i += p + 1,
                    None => break,
                },
            }
        } else {
            let ch_len = html[i..].chars().next().map(char::len_utf8).unwrap_or(1);
            out.push_str(&html[i..i + ch_len]);
            i += ch_len;
        }
    }
    let decoded = decode_entities(&out);
    let collapsed = decoded.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() > max { collapsed.chars().take(max).collect::<String>() + "…" } else { collapsed }
}

fn parse_date(s: &str) -> i64 {
    let s = s.trim();
    if s.is_empty() {
        return 0;
    }
    chrono::DateTime::parse_from_rfc3339(s)
        .or_else(|_| chrono::DateTime::parse_from_rfc2822(s))
        .map(|d| d.timestamp())
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").map(|d| d.and_utc().timestamp()))
        .unwrap_or(0)
}

fn http_link(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with("https://") || s.starts_with("http://")) && s.len() < 2000 { s.to_string() } else { String::new() }
}

fn local(name: &[u8]) -> String {
    let n = String::from_utf8_lossy(name).to_ascii_lowercase();
    n.rsplit(':').next().unwrap_or("").to_string()
}

/// Parse an RSS/RDF/Atom document. Items without a title and link are dropped; at most 100 items are returned.
pub fn parse_feed(bytes: &[u8]) -> Result<ParsedFeed, String> {
    let mut r = Reader::from_reader(bytes);
    r.config_mut().check_end_names = false;
    let mut feed = ParsedFeed::default();
    let mut stack: Vec<String> = Vec::new();
    let mut cur: Option<Parsed> = None;
    let mut text = String::new();
    let mut saw_root = false;
    let mut buf = Vec::new();
    let mut atom_alt_set = false;
    loop {
        let ev = r.read_event_into(&mut buf);
        match ev {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let is_empty = matches!(ev, Ok(Event::Empty(_)));
                let name = local(e.name().as_ref());
                if stack.is_empty() {
                    saw_root = matches!(name.as_str(), "rss" | "feed" | "rdf");
                    if !saw_root {
                        return Err("not an RSS, RDF or Atom feed".into());
                    }
                }
                if matches!(name.as_str(), "item" | "entry") {
                    cur = Some(Parsed::default());
                    atom_alt_set = false;
                }
                if name == "link" {
                    if let Some(p) = cur.as_mut() {
                        let mut href = None;
                        let mut rel = String::from("alternate");
                        for a in e.attributes().flatten() {
                            let k = local(a.key.as_ref());
                            let v = a.unescape_value().map(|c| c.into_owned()).unwrap_or_default();
                            if k == "href" {
                                href = Some(v);
                            } else if k == "rel" {
                                rel = v;
                            }
                        }
                        if let (Some(h), "alternate") = (href, rel.as_str()) {
                            if !atom_alt_set {
                                let l = http_link(&h);
                                if !l.is_empty() {
                                    p.link = l;
                                    atom_alt_set = true;
                                }
                            }
                        }
                    }
                }
                if !is_empty {
                    stack.push(name);
                    text.clear();
                }
            }
            Ok(Event::Text(t)) => {
                if text.len() < 200_000 {
                    match t.unescape() {
                        Ok(s) => text.push_str(&s),
                        Err(_) => text.push_str(&decode_entities(&String::from_utf8_lossy(&t))),
                    }
                }
            }
            Ok(Event::CData(c)) => {
                if text.len() < 200_000 {
                    text.push_str(&String::from_utf8_lossy(&c));
                }
            }
            Ok(Event::End(_)) => {
                let Some(name) = stack.pop() else { continue };
                let t = std::mem::take(&mut text);
                match (&mut cur, name.as_str()) {
                    (Some(p), "title") => p.title = plain_text(&t, 300),
                    (Some(p), "link") if p.link.is_empty() => p.link = http_link(&t),
                    (Some(p), "guid" | "id") => p.guid = t.trim().chars().take(500).collect(),
                    (Some(p), "pubdate" | "published" | "date" | "issued") => {
                        let d = parse_date(&t);
                        if d != 0 {
                            p.published = d;
                        }
                    }
                    (Some(p), "updated") if p.published == 0 => p.published = parse_date(&t),
                    (Some(p), "description" | "summary" | "content" | "encoded") if p.summary.is_empty() => p.summary = plain_text(&t, 500),
                    (Some(_), "item" | "entry") => {
                        let p = cur.take().unwrap();
                        if (!p.title.is_empty() || !p.link.is_empty()) && feed.items.len() < MAX_ITEMS_PER_FETCH {
                            feed.items.push(Parsed { title: if p.title.is_empty() { p.link.clone() } else { p.title.clone() }, ..p });
                        }
                    }
                    (None, "title") if feed.title.is_empty() && stack.len() <= 2 => feed.title = plain_text(&t, 120),
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                if feed.items.is_empty() {
                    return Err(format!("could not parse feed: {e}"));
                }
                break;
            }
        }
        buf.clear();
    }
    if !saw_root {
        return Err("empty document".into());
    }
    Ok(feed)
}

/// Feed URLs listed in an OPML file: (url, title).
pub fn parse_opml(bytes: &[u8]) -> Result<Vec<(String, String)>, String> {
    let mut r = Reader::from_reader(bytes);
    r.config_mut().check_end_names = false;
    let mut out = Vec::new();
    let mut buf = Vec::new();
    let mut root_seen = false;
    loop {
        match r.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let name = local(e.name().as_ref());
                if name == "opml" {
                    root_seen = true;
                }
                if name == "outline" {
                    let (mut url, mut title) = (String::new(), String::new());
                    for a in e.attributes().flatten() {
                        let k = String::from_utf8_lossy(a.key.as_ref()).to_ascii_lowercase();
                        let v = a.unescape_value().map(|c| c.into_owned()).unwrap_or_default();
                        match k.as_str() {
                            "xmlurl" => url = v,
                            "title" => title = v,
                            "text" if title.is_empty() => title = v,
                            _ => {}
                        }
                    }
                    if !url.is_empty() {
                        out.push((url, title));
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("could not parse OPML: {e}")),
            _ => {}
        }
        buf.clear();
    }
    if !root_seen {
        return Err("not an OPML file".into());
    }
    Ok(out)
}

fn xml_esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

pub fn build_opml(feeds: &[(String, String)]) -> String {
    let mut s = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<opml version=\"2.0\"><head><title>OSNT feed watcher</title></head><body>\n");
    for (url, title) in feeds {
        s.push_str(&format!("<outline type=\"rss\" text=\"{0}\" title=\"{0}\" xmlUrl=\"{1}\"/>\n", xml_esc(title), xml_esc(url)));
    }
    s.push_str("</body></opml>\n");
    s
}

/// Hacker News Algolia `search_by_date` response.
pub fn parse_hn(body: &[u8]) -> Result<ParsedFeed, String> {
    let v: Value = serde_json::from_slice(body).map_err(|_| "Hacker News search returned malformed JSON".to_string())?;
    let hits = v["hits"].as_array().ok_or("Hacker News search returned no hits list")?;
    let mut feed = ParsedFeed::default();
    for h in hits.iter().take(MAX_ITEMS_PER_FETCH) {
        let id = h["objectID"].as_str().unwrap_or("");
        let title = h["title"].as_str().or(h["story_title"].as_str()).unwrap_or("").trim();
        if title.is_empty() || id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let thread = format!("https://news.ycombinator.com/item?id={id}");
        let link = h["url"].as_str().map(http_link).filter(|l| !l.is_empty()).unwrap_or_else(|| thread.clone());
        let points = h["points"].as_i64().unwrap_or(0);
        let comments = h["num_comments"].as_i64().unwrap_or(0);
        feed.items.push(Parsed { title: plain_text(title, 300), link, summary: format!("{points} points, {comments} comments · discussion: {thread}"), published: h["created_at_i"].as_i64().unwrap_or(0), guid: format!("hn:{id}") });
    }
    Ok(feed)
}

pub fn valid_channel(c: &str) -> bool {
    (5..=32).contains(&c.len()) && c.as_bytes()[0].is_ascii_alphabetic() && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Telegram `t.me/s/<channel>` preview page: message text, time and permalink only. No author or viewer data is read.
pub fn parse_telegram(html: &str, channel: &str) -> Result<ParsedFeed, String> {
    let marker = "data-post=\"";
    let mut feed = ParsedFeed { title: String::new(), items: vec![] };
    if let Some(i) = html.find("og:title\" content=\"") {
        let rest = &html[i + 19..];
        if let Some(e) = rest.find('"') {
            feed.title = plain_text(&rest[..e], 100);
        }
    }
    let mut parts = html.split(marker);
    parts.next();
    for chunk in parts {
        let Some(end) = chunk.find('"') else { continue };
        let post = &chunk[..end];
        let Some((chan, num)) = post.split_once('/') else { continue };
        if !chan.eq_ignore_ascii_case(channel) || num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let body = &chunk[end..];
        // Stop at the next message wrapper so one message's fields never come from another.
        let body = body.split("tgme_widget_message_wrap").next().unwrap_or(body);
        let text = body.find("tgme_widget_message_text").and_then(|i| {
            let from = body[i..].find('>')? + i + 1;
            let to = body[from..].find("</div>").map(|e| from + e).unwrap_or(body.len());
            Some(plain_text(&body[from..to], 600))
        });
        let published = body.find("<time").and_then(|i| body[i..].find("datetime=\"").map(|j| i + j + 10)).and_then(|s| body[s..].find('"').map(|e| parse_date(&body[s..s + e]))).unwrap_or(0);
        let Some(text) = text.filter(|t| !t.is_empty()) else { continue };
        let title: String = if text.chars().count() > 140 { text.chars().take(140).collect::<String>() + "…" } else { text.clone() };
        feed.items.push(Parsed { title, link: format!("https://t.me/{chan}/{num}"), summary: text, published, guid: format!("tg:{chan}/{num}") });
        if feed.items.len() >= MAX_ITEMS_PER_FETCH {
            break;
        }
    }
    if feed.items.is_empty() {
        return Err("no public posts found: the name may be wrong, or it is not a public channel with a web preview (groups and users are not supported)".into());
    }
    feed.items.reverse(); // preview pages list oldest first
    Ok(feed)
}

// ---------------------------------------------------------------------------------------------------------------
// Alert rules
// ---------------------------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Rule {
    pub id: u64,
    pub name: String,
    /// "keyword" (comma or newline separated terms, any match) or "regex"
    pub kind: String,
    pub pattern: String,
}

pub fn validate_rule(kind: &str, pattern: &str) -> Result<(), String> {
    let p = pattern.trim();
    if p.is_empty() || p.chars().count() > 200 {
        return Err("pattern must be 1 to 200 characters".into());
    }
    match kind {
        "keyword" => {
            if terms(p).is_empty() {
                return Err("give at least one keyword of 2 or more characters".into());
            }
            Ok(())
        }
        "regex" => build_regex(p).map(|_| ()),
        _ => Err("kind must be keyword or regex".into()),
    }
}

fn terms(p: &str) -> Vec<String> {
    p.split([',', '\n']).map(|t| t.trim().to_lowercase()).filter(|t| t.chars().count() >= 2).collect()
}

fn build_regex(p: &str) -> Result<regex::Regex, String> {
    RegexBuilder::new(p).case_insensitive(true).size_limit(1 << 20).dfa_size_limit(1 << 20).build().map_err(|e| format!("invalid regex: {}", e.to_string().lines().last().unwrap_or("")))
}

/// Distinct matched snippets (at most 5) for highlighting; empty when the rule does not match.
pub fn rule_matches(rule: &Rule, text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    match rule.kind.as_str() {
        "keyword" => {
            let lower = text.to_lowercase();
            for t in terms(&rule.pattern) {
                if lower.contains(&t) && !out.contains(&t) {
                    out.push(t);
                }
            }
        }
        "regex" => {
            if let Ok(re) = build_regex(&rule.pattern) {
                for m in re.find_iter(text).take(20) {
                    let s = m.as_str().to_string();
                    if !s.is_empty() && !out.contains(&s) {
                        out.push(s.chars().take(60).collect());
                    }
                }
            }
        }
        _ => {}
    }
    out.truncate(5);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const RSS: &str = r#"<?xml version="1.0"?><rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel><title>Example &amp; News</title>
      <item><title><![CDATA[Quake <b>hits</b> coast]]></title><link>https://ex.test/a</link><guid isPermaLink="false">g1</guid><pubDate>Mon, 02 Nov 2026 10:00:00 GMT</pubDate><description>&lt;p&gt;Strong &amp;amp; shallow&lt;/p&gt;</description></item>
      <item><title>Second</title><link>javascript:alert(1)</link><dc:date>2026-11-01T08:00:00Z</dc:date><content:encoded><![CDATA[<p>Body <script>x()</script>text</p>]]></content:encoded></item>
      <item><link>https://ex.test/c</link></item><item></item></channel></rss>"#;

    #[test]
    fn rss_parsing() {
        let f = parse_feed(RSS.as_bytes()).unwrap();
        assert_eq!(f.title, "Example & News");
        assert_eq!(f.items.len(), 3);
        assert_eq!(f.items[0].title, "Quake hits coast");
        assert_eq!(f.items[0].link, "https://ex.test/a");
        assert_eq!(f.items[0].summary, "Strong & shallow");
        assert_eq!(f.items[0].published, 1793613600);
        assert_eq!(f.items[1].link, "", "non-http links are dropped");
        assert_eq!(f.items[1].summary, "Body text");
        assert_eq!(f.items[1].published, 1793520000);
        assert_eq!(f.items[2].title, "https://ex.test/c");
    }

    #[test]
    fn atom_parsing() {
        let a = r#"<feed xmlns="http://www.w3.org/2005/Atom"><title>Atom Feed</title><link href="https://ex.test/"/>
          <entry><title type="html">Entry &amp;lt;1&amp;gt;</title><link rel="self" href="https://ex.test/self"/><link rel="alternate" href="https://ex.test/e1"/><id>urn:1</id><updated>2026-11-02T10:00:00+02:00</updated><summary>Sum</summary></entry>
          <entry><title>E2</title><link href="https://ex.test/e2"/><published>2026-11-02T09:00:00Z</published><updated>2026-11-03T09:00:00Z</updated><content type="html">&lt;b&gt;Hi&lt;/b&gt;</content></entry></feed>"#;
        let f = parse_feed(a.as_bytes()).unwrap();
        assert_eq!(f.title, "Atom Feed");
        assert_eq!(f.items.len(), 2);
        assert_eq!(f.items[0].link, "https://ex.test/e1");
        assert_eq!(f.items[0].guid, "urn:1");
        assert_eq!(f.items[0].published, 1793606400);
        assert_eq!(f.items[1].published, 1793610000, "published wins over updated");
        assert_eq!(f.items[1].summary, "Hi");
    }

    #[test]
    fn rdf_and_garbage() {
        let r = r#"<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/"><channel><title>RDF</title></channel><item><title>One</title><link>http://ex.test/1</link></item></rdf:RDF>"#;
        assert_eq!(parse_feed(r.as_bytes()).unwrap().items.len(), 1);
        assert!(parse_feed(b"<html><body>hi</body></html>").is_err());
        assert!(parse_feed(b"").is_err());
        assert!(parse_feed(b"\x00\x01\x02 not xml").is_err());
        // truncated feed keeps what parsed
        let cut = &RSS[..RSS.find("<item><link>").unwrap()];
        assert_eq!(parse_feed(cut.as_bytes()).unwrap().items.len(), 2);
    }

    #[test]
    fn entity_bomb_is_inert_and_item_cap() {
        let bomb = r#"<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><rss><channel><item><title>&b;</title><link>https://x.test/</link></item></channel></rss>"#;
        let f = parse_feed(bomb.as_bytes()).unwrap();
        assert!(f.items[0].title.len() < 100);
        let mut big = String::from("<rss><channel>");
        for i in 0..300 {
            big.push_str(&format!("<item><title>t{i}</title></item>"));
        }
        assert_eq!(parse_feed(big.as_bytes()).unwrap().items.len(), MAX_ITEMS_PER_FETCH);
    }

    #[test]
    fn plain_text_cases() {
        assert_eq!(plain_text("<p>a&nbsp;b &#65; &#x42; &bogus; &amp;lt;</p>\n\n  c", 100), "a b A B &bogus; &lt; c");
        assert_eq!(plain_text("x<style>p{}</style>y<script>1</script>z", 100), "x y z");
        assert_eq!(plain_text(&"é".repeat(50), 10).chars().count(), 11);
        assert_eq!(plain_text("<unclosed", 10), "");
    }

    #[test]
    fn opml_roundtrip() {
        let o = build_opml(&[("https://a.test/feed?x=1&y=2".into(), "A & B".into())]);
        let back = parse_opml(o.as_bytes()).unwrap();
        assert_eq!(back, vec![("https://a.test/feed?x=1&y=2".to_string(), "A & B".to_string())]);
        assert!(parse_opml(b"<rss/>").is_err());
        let nested = r#"<opml><body><outline text="Group"><outline text="F" xmlUrl="http://f.test/rss"/><outline text="no url"/></outline></body></opml>"#;
        assert_eq!(parse_opml(nested.as_bytes()).unwrap().len(), 1);
    }

    #[test]
    fn hn_parsing() {
        let b = br#"{"hits":[{"objectID":"123","title":"Quake <i>report</i>","url":"https://q.test/r","points":10,"num_comments":2,"created_at_i":1793600000},
          {"objectID":"124","title":"Ask HN","url":null,"created_at_i":5},{"objectID":"x","title":"bad id"},{"objectID":"5","title":""}]}"#;
        let f = parse_hn(b).unwrap();
        assert_eq!(f.items.len(), 2);
        assert_eq!(f.items[0].link, "https://q.test/r");
        assert_eq!(f.items[1].link, "https://news.ycombinator.com/item?id=124");
        assert!(parse_hn(b"{}").is_err());
    }

    #[test]
    fn telegram_parsing() {
        let h = r#"<meta property="og:title" content="Chan News"><div class="tgme_widget_message_wrap"><div class="tgme_widget_message" data-post="chan_news/10"><div class="tgme_widget_message_from_author">SHOULD NOT APPEAR</div><div class="tgme_widget_message_text js-message_text">First <b>post</b> &amp; more</div><time datetime="2026-11-02T10:00:00+00:00">x</time></div></div>
          <div class="tgme_widget_message_wrap"><div class="tgme_widget_message" data-post="chan_news/11"><div class="tgme_widget_message_text">Second</div><time datetime="2026-11-02T11:00:00+00:00"></time></div></div>
          <div class="tgme_widget_message_wrap"><div class="tgme_widget_message" data-post="other/12"><div class="tgme_widget_message_text">other channel</div></div></div>
          <div class="tgme_widget_message_wrap"><div data-post="chan_news/13">photo only</div></div>"#;
        let f = parse_telegram(h, "chan_news").unwrap();
        assert_eq!(f.title, "Chan News");
        assert_eq!(f.items.len(), 2);
        assert_eq!(f.items[0].link, "https://t.me/chan_news/11", "newest first");
        assert_eq!(f.items[1].summary, "First post & more");
        assert!(!f.items.iter().any(|i| i.summary.contains("SHOULD NOT")));
        assert!(parse_telegram("<html>nothing</html>", "chan_news").is_err());
        assert!(valid_channel("chan_news") && !valid_channel("ab") && !valid_channel("a/b") && !valid_channel("1abcde") && !valid_channel("a b c d e"));
    }

    #[test]
    fn rules() {
        let k = Rule { id: 1, name: "k".into(), kind: "keyword".into(), pattern: "Quake, tsunami\nx".into() };
        assert_eq!(rule_matches(&k, "A QUAKE and a tsunami warning"), vec!["quake", "tsunami"]);
        assert!(rule_matches(&k, "nothing here").is_empty());
        let r = Rule { id: 2, name: "r".into(), kind: "regex".into(), pattern: r"M\s?\d\.\d".into() };
        assert_eq!(rule_matches(&r, "m 6.1 and M7.2 and M7.2"), vec!["m 6.1", "M7.2"]);
        assert!(validate_rule("regex", "(").is_err());
        assert!(validate_rule("regex", &"a".repeat(201)).is_err());
        assert!(validate_rule("regex", "(a+)+$").is_ok(), "linear-time engine, so catastrophic patterns are harmless");
        let t = std::time::Instant::now();
        let evil = Rule { id: 3, name: "e".into(), kind: "regex".into(), pattern: "(a+)+$".into() };
        rule_matches(&evil, &format!("{}b", "a".repeat(5000)));
        assert!(t.elapsed().as_secs() < 2);
        assert!(validate_rule("keyword", "a").is_err());
        assert!(validate_rule("nope", "abc").is_err());
        assert!(validate_rule("regex", "(?:a{1000}){1000}").is_err(), "size limit");
    }

    #[test]
    fn ids_are_stable_and_per_feed() {
        let p = Parsed { guid: "g".into(), ..Default::default() };
        assert_eq!(item_id(1, &p), item_id(1, &p));
        assert_ne!(item_id(1, &p), item_id(2, &p));
    }
}

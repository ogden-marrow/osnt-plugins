//! Case data model, validation, hash chain, atomic file storage and exports.

use std::{fs, io::Write, path::PathBuf, sync::Mutex};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const MAX_CASES: usize = 200;
pub const MAX_NOTES: usize = 500;
pub const MAX_EVENTS: usize = 2000;
pub const MAX_EVIDENCE: usize = 5000;
pub const MAX_NOTE_BYTES: usize = 100_000;
pub const MAX_CASE_BYTES: usize = 8 * 1024 * 1024;
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Serialises every read-modify-write so two requests cannot lose each other's changes.
pub static LOCK: Mutex<()> = Mutex::new(());

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Note {
    pub id: String,
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Private notes are never shown to agents. Only notes the investigator explicitly shares are.
    #[serde(default)]
    pub share_with_agent: bool,
    pub created: String,
    pub updated: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Event {
    pub id: String,
    pub date: String,
    pub title: String,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub source_url: String,
    /// "user" or "plugin:<id>"
    pub origin: String,
    pub created: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Evidence {
    pub seq: u64,
    pub id: String,
    pub kind: String,
    pub title: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub captured_at: String,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub archive_url: String,
    #[serde(default)]
    pub note: String,
    pub origin: String,
    pub created: String,
    pub prev: String,
    pub hash: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Case {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub created: String,
    pub updated: String,
    #[serde(default)]
    pub notes: Vec<Note>,
    #[serde(default)]
    pub timeline: Vec<Event>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
}

// ---- time and ids --------------------------------------------------------------------------------

pub fn now_iso() -> String {
    iso_from_secs(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0))
}

pub fn iso_from_secs(s: u64) -> String {
    let (days, rem) = ((s / 86400) as i64, s % 86400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as i64;
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

pub fn new_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let h = Sha256::digest(format!("{nanos}-{}-{}", N.fetch_add(1, Ordering::SeqCst), std::process::id()));
    h[..6].iter().map(|b| format!("{b:02x}")).collect()
}

pub fn valid_id(s: &str) -> bool {
    (1..=32).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

// ---- validation ----------------------------------------------------------------------------------

pub fn text(label: &str, s: &str, max: usize, required: bool) -> Result<String, String> {
    let t = s.trim();
    if required && t.is_empty() {
        return Err(format!("{label} is required"));
    }
    if t.chars().count() > max {
        return Err(format!("{label} is too long (max {max} characters)"));
    }
    if t.chars().any(|c| c.is_control() && c != '\n' && c != '\t' && c != '\r') {
        return Err(format!("{label} contains control characters"));
    }
    Ok(t.to_string())
}

pub fn single_line(label: &str, s: &str, max: usize, required: bool) -> Result<String, String> {
    let t = text(label, s, max, required)?;
    if t.contains('\n') || t.contains('\r') {
        return Err(format!("{label} must be a single line"));
    }
    Ok(t)
}

pub fn tags(list: &[String]) -> Result<Vec<String>, String> {
    if list.len() > 20 {
        return Err("at most 20 tags".into());
    }
    let mut out: Vec<String> = Vec::new();
    for t in list {
        let t = single_line("tag", t, 40, false)?.to_lowercase();
        if !t.is_empty() && !out.contains(&t) {
            out.push(t);
        }
    }
    Ok(out)
}

pub fn url_field(label: &str, s: &str) -> Result<String, String> {
    let t = single_line(label, s, 2000, false)?;
    if !t.is_empty() && !(t.starts_with("http://") || t.starts_with("https://")) {
        return Err(format!("{label} must start with http:// or https://"));
    }
    Ok(t)
}

pub fn sha_field(s: &str) -> Result<String, String> {
    let t = s.trim().to_ascii_lowercase();
    if t.is_empty() || (t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())) { Ok(t) } else { Err("sha256 must be 64 hex characters".into()) }
}

/// `YYYY-MM-DD`, optionally followed by `T` and a time. Only the shape is checked.
pub fn date_field(s: &str) -> Result<String, String> {
    let t = single_line("date", s, 40, true)?;
    let b = t.as_bytes();
    let ok = b.len() >= 10 && b[..4].iter().all(u8::is_ascii_digit) && b[4] == b'-' && b[5..7].iter().all(u8::is_ascii_digit) && b[7] == b'-' && b[8..10].iter().all(u8::is_ascii_digit)
        && (b.len() == 10 || b[10] == b'T' || b[10] == b' ');
    if !ok {
        return Err("date must look like 2024-05-31 or 2024-05-31T14:30:00Z".into());
    }
    let (m, d) = (t[5..7].parse::<u32>().unwrap_or(0), t[8..10].parse::<u32>().unwrap_or(0));
    if (1..=12).contains(&m) && (1..=31).contains(&d) { Ok(t) } else { Err("date must look like 2024-05-31 or 2024-05-31T14:30:00Z".into()) }
}

/// Plugin ids (for "who pinned this") are restricted so a caller cannot forge another origin format.
pub fn origin_of(source_plugin: Option<&str>) -> String {
    match source_plugin {
        Some(p) if (1..=40).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') => format!("plugin:{p}"),
        _ => "user".into(),
    }
}

// ---- evidence hash chain -------------------------------------------------------------------------

pub fn entry_hash(e: &Evidence) -> String {
    let canon = json!([e.prev, e.seq, e.id, e.kind, e.title, e.url, e.captured_at, e.sha256, e.archive_url, e.note, e.origin, e.created]).to_string();
    Sha256::digest(canon.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// Append a new evidence entry linked to the previous one.
pub fn append_evidence(c: &mut Case, mut e: Evidence) {
    e.seq = c.evidence.last().map(|l| l.seq + 1).unwrap_or(1);
    e.prev = c.evidence.last().map(|l| l.hash.clone()).unwrap_or_else(|| GENESIS.into());
    e.hash = entry_hash(&e);
    c.evidence.push(e);
}

/// Recompute the chain. Reports the first entry that does not match.
pub fn verify_chain(list: &[Evidence]) -> Value {
    let mut prev = GENESIS.to_string();
    for (i, e) in list.iter().enumerate() {
        if e.seq != i as u64 + 1 {
            return json!({ "ok": false, "entries": list.len(), "broken_at": e.seq, "reason": "sequence number gap or reorder (an entry was removed or inserted)" });
        }
        if e.prev != prev {
            return json!({ "ok": false, "entries": list.len(), "broken_at": e.seq, "reason": "link to the previous entry does not match" });
        }
        if entry_hash(e) != e.hash {
            return json!({ "ok": false, "entries": list.len(), "broken_at": e.seq, "reason": "entry content does not match its hash (edited after it was recorded)" });
        }
        prev = e.hash.clone();
    }
    json!({ "ok": true, "entries": list.len(), "head": prev })
}

// ---- storage -------------------------------------------------------------------------------------

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> std::io::Result<Store> {
        let dir = dir.into().join("cases");
        fs::create_dir_all(&dir)?;
        Ok(Store { dir })
    }

    fn path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    pub fn load(&self, id: &str) -> Result<Option<Case>, String> {
        if !valid_id(id) {
            return Ok(None);
        }
        match fs::read_to_string(self.path(id)) {
            Ok(t) => serde_json::from_str(&t).map(Some).map_err(|e| format!("case file is unreadable: {e}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Write via a temp file in the same directory, fsync, then rename, so a crash never leaves a half-written case.
    pub fn save(&self, c: &Case) -> Result<(), String> {
        let data = serde_json::to_vec_pretty(c).map_err(|e| e.to_string())?;
        if data.len() > MAX_CASE_BYTES {
            return Err(format!("this case would exceed {} MB; export it and start a new case", MAX_CASE_BYTES / 1024 / 1024));
        }
        let tmp = self.dir.join(format!(".{}.tmp", c.id));
        let write = || -> std::io::Result<()> {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&data)?;
            f.sync_all()?;
            fs::rename(&tmp, self.path(&c.id))?;
            if let Ok(d) = fs::File::open(&self.dir) {
                let _ = d.sync_all();
            }
            Ok(())
        };
        write().map_err(|e| {
            let _ = fs::remove_file(&tmp);
            format!("could not save: {e}")
        })
    }

    pub fn delete(&self, id: &str) -> Result<bool, String> {
        if !valid_id(id) {
            return Ok(false);
        }
        match fs::remove_file(self.path(id)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn list(&self) -> Vec<Case> {
        let Ok(rd) = fs::read_dir(&self.dir) else { return vec![] };
        let mut v: Vec<Case> = rd
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .filter_map(|e| serde_json::from_str(&fs::read_to_string(e.path()).ok()?).ok())
            .collect();
        v.sort_by(|a, b| b.updated.cmp(&a.updated));
        v
    }
}

pub fn summary(c: &Case) -> Value {
    json!({ "id": c.id, "title": c.title, "description": c.description, "tags": c.tags, "created": c.created, "updated": c.updated,
            "notes": c.notes.len(), "timeline": c.timeline.len(), "evidence": c.evidence.len() })
}

// ---- export / import -----------------------------------------------------------------------------

pub fn export_json(c: &Case) -> Value {
    json!({ "format": "osnt-case/1", "exported": now_iso(), "case": c, "chain": verify_chain(&c.evidence) })
}

/// Parse a bundle made by [`export_json`]. Every field is re-validated and the evidence chain must verify.
pub fn import_bundle(v: &Value) -> Result<Case, String> {
    if v["format"] != "osnt-case/1" {
        return Err("not an OSNT case bundle (format osnt-case/1 expected)".into());
    }
    let mut c: Case = serde_json::from_value(v["case"].clone()).map_err(|e| format!("bundle is malformed: {e}"))?;
    c.title = single_line("title", &c.title, 200, true)?;
    c.description = text("description", &c.description, 5000, false)?;
    c.tags = tags(&c.tags)?;
    if c.notes.len() > MAX_NOTES || c.timeline.len() > MAX_EVENTS || c.evidence.len() > MAX_EVIDENCE {
        return Err("bundle has more items than a case can hold".into());
    }
    for n in &mut c.notes {
        n.title = single_line("note title", &n.title, 200, false)?;
        n.body = text("note body", &n.body, MAX_NOTE_BYTES, false)?;
        n.tags = tags(&n.tags)?;
        if !valid_id(&n.id) {
            n.id = new_id();
        }
    }
    for e in &mut c.timeline {
        e.date = date_field(&e.date)?;
        e.title = single_line("event title", &e.title, 200, true)?;
        e.detail = text("event detail", &e.detail, 5000, false)?;
        e.source_url = url_field("source url", &e.source_url)?;
        if !valid_id(&e.id) {
            e.id = new_id();
        }
    }
    for e in &c.evidence {
        single_line("evidence title", &e.title, 300, true)?;
        url_field("url", &e.url)?;
        url_field("archive url", &e.archive_url)?;
        sha_field(&e.sha256)?;
        text("evidence note", &e.note, 5000, false)?;
    }
    let chain = verify_chain(&c.evidence);
    if chain["ok"] != true {
        return Err(format!("the evidence chain in this bundle does not verify (entry {}: {})", chain["broken_at"], chain["reason"].as_str().unwrap_or("")));
    }
    c.id = new_id();
    c.updated = now_iso();
    Ok(c)
}

fn md_line(s: &str) -> String {
    s.replace('\n', " ").replace('|', "\\|")
}

pub fn export_markdown(c: &Case) -> String {
    let mut m = format!("# {}\n\n", c.title);
    if !c.description.is_empty() {
        m.push_str(&format!("{}\n\n", c.description));
    }
    m.push_str(&format!("Created {}, last updated {}.", c.created, c.updated));
    if !c.tags.is_empty() {
        m.push_str(&format!(" Tags: {}.", c.tags.join(", ")));
    }
    m.push_str("\n\n## Timeline\n\n");
    if c.timeline.is_empty() {
        m.push_str("_No events._\n\n");
    }
    let mut ev: Vec<&Event> = c.timeline.iter().collect();
    ev.sort_by(|a, b| a.date.cmp(&b.date));
    for e in ev {
        m.push_str(&format!("- **{}** {}{}{}\n", e.date, e.title, if e.detail.is_empty() { String::new() } else { format!(": {}", md_line(&e.detail)) }, if e.source_url.is_empty() { String::new() } else { format!(" ([source]({}))", e.source_url) }));
    }
    m.push_str("\n## Evidence log\n\n");
    if c.evidence.is_empty() {
        m.push_str("_No evidence recorded._\n\n");
    } else {
        m.push_str("| # | Captured | Title | URL | SHA-256 | Archive | Origin | Entry hash |\n|---|---|---|---|---|---|---|---|\n");
        for e in &c.evidence {
            m.push_str(&format!("| {} | {} | {} | {} | `{}` | {} | {} | `{}` |\n", e.seq, md_line(&e.captured_at), md_line(&e.title), md_line(&e.url), e.sha256, md_line(&e.archive_url), md_line(&e.origin), &e.hash[..16]));
        }
        let v = verify_chain(&c.evidence);
        m.push_str(&format!("\nHash chain: {} (head `{}`).\n\n", if v["ok"] == true { "verified at export" } else { "BROKEN" }, v["head"].as_str().unwrap_or("")));
    }
    m.push_str("## Notes\n\n");
    if c.notes.is_empty() {
        m.push_str("_No notes._\n");
    }
    for n in &c.notes {
        m.push_str(&format!("### {}\n\n{}\n\n", if n.title.is_empty() { "Untitled" } else { &n.title }, n.body));
    }
    m
}

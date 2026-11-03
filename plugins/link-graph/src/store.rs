//! Graph model, node validation (no person-type nodes), atomic storage and exports.

use std::{collections::{BTreeMap, BTreeSet}, fs, io::Write, net::IpAddr, path::PathBuf, sync::Mutex};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const MAX_GRAPHS: usize = 50;
pub const MAX_NODES: usize = 2000;
pub const MAX_EDGES: usize = 6000;
pub const MAX_GRAPH_BYTES: usize = 5 * 1024 * 1024;
pub static LOCK: Mutex<()> = Mutex::new(());

/// The complete list of node types. There is deliberately no person, username, email, phone or social-account type.
pub const NODE_TYPES: [&str; 12] = ["domain", "ip", "asn", "certificate", "organisation", "url", "hash", "vessel", "aircraft", "place", "event", "document"];

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Node {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub label: String,
    #[serde(default)]
    pub x: f64,
    #[serde(default)]
    pub y: f64,
    #[serde(default)]
    pub pinned: bool,
    #[serde(default)]
    pub group: String,
    /// The investigator's own remark about this node.
    #[serde(default)]
    pub note: String,
    /// "user", "import" or "transform:<plugin>": where the node came from.
    #[serde(default)]
    pub source: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Edge {
    pub id: String,
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub source: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Graph {
    pub id: String,
    pub name: String,
    pub created: String,
    pub updated: String,
    #[serde(default)]
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub edges: Vec<Edge>,
}

pub fn now_iso() -> String {
    let s = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
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
    Sha256::digest(format!("{nanos}-{}-{}", N.fetch_add(1, Ordering::SeqCst), std::process::id()))[..6].iter().map(|b| format!("{b:02x}")).collect()
}

pub fn valid_id(s: &str) -> bool {
    (1..=32).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_domain(s: &str) -> Option<String> {
    let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
    let ok = s.len() <= 253 && s.contains('.') && s.split('.').all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    ok.then_some(s)
}

fn looks_like_email(s: &str) -> bool {
    s.split_whitespace().any(|w| match w.split_once('@') {
        Some((l, r)) => !l.is_empty() && r.contains('.') && !r.starts_with('.') && !r.ends_with('.'),
        None => false,
    })
}

fn looks_like_phone(s: &str) -> bool {
    let digits = s.chars().filter(char::is_ascii_digit).count();
    let other = s.chars().filter(|c| !c.is_ascii_digit() && !" +-().".contains(*c)).count();
    digits >= 8 && other == 0
}

/// Validate and normalise one node's type and label. Returns the canonical label.
pub fn check_node(kind: &str, label: &str) -> Result<String, String> {
    if !NODE_TYPES.contains(&kind) {
        return Err(format!("node type \"{kind}\" is not allowed. Allowed: {}. People-related types (person, username, email, phone) are excluded by design.", NODE_TYPES.join(", ")));
    }
    let l = label.trim();
    if l.is_empty() || l.chars().count() > 300 || l.chars().any(char::is_control) {
        return Err("label must be 1-300 printable characters".into());
    }
    let out = match kind {
        "domain" => valid_domain(l).ok_or("not a valid domain name")?,
        "ip" => l.parse::<IpAddr>().map_err(|_| "not a valid IP address")?.to_string(),
        "asn" => {
            let n = l.trim_start_matches(['A', 'a', 'S', 's']);
            if n.is_empty() || n.len() > 10 || !n.bytes().all(|b| b.is_ascii_digit()) {
                return Err("ASN must look like AS15169".into());
            }
            format!("AS{n}")
        }
        "url" => {
            let u = url::Url::parse(l).map_err(|_| "not a valid URL")?;
            if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none() {
                return Err("URL must be http or https".into());
            }
            if !u.username().is_empty() || u.password().is_some() {
                return Err("URL must not contain credentials".into());
            }
            u.to_string()
        }
        "hash" => {
            let h = l.to_ascii_lowercase();
            if ![32, 40, 64, 128].contains(&h.len()) || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("hash must be 32, 40, 64 or 128 hex characters (MD5, SHA-1, SHA-256, SHA-512)".into());
            }
            h
        }
        _ => l.to_string(),
    };
    if !matches!(kind, "url" | "hash" | "ip" | "asn" | "domain") && (looks_like_email(&out) || looks_like_phone(&out)) {
        return Err("labels that look like an email address or phone number are not accepted".into());
    }
    Ok(out)
}

fn short(label: &str, s: &str, max: usize) -> Result<String, String> {
    let t = s.trim();
    if t.chars().count() > max || t.chars().any(char::is_control) {
        return Err(format!("{label} must be at most {max} printable characters"));
    }
    Ok(t.to_string())
}

/// Validate a whole graph body (nodes and edges), normalising labels, dropping nothing silently.
pub fn validate(g: &mut Graph) -> Result<(), String> {
    g.name = short("name", &g.name, 120)?;
    if g.name.is_empty() {
        return Err("a graph needs a name".into());
    }
    if g.nodes.len() > MAX_NODES || g.edges.len() > MAX_EDGES {
        return Err(format!("at most {MAX_NODES} nodes and {MAX_EDGES} edges per graph"));
    }
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for n in &mut g.nodes {
        if !valid_id(&n.id) || !ids.insert(n.id.clone()) {
            return Err(format!("node id \"{}\" is invalid or repeated", n.id));
        }
        n.label = check_node(&n.kind, &n.label)?;
        if !keys.insert((n.kind.clone(), n.label.clone())) {
            return Err(format!("duplicate node {} {}", n.kind, n.label));
        }
        n.group = short("group", &n.group, 40)?;
        n.note = short("note", &n.note, 1000)?;
        n.source = short("source", &n.source, 60)?;
        if !n.x.is_finite() || !n.y.is_finite() {
            n.x = 0.0;
            n.y = 0.0;
        }
        n.x = n.x.clamp(-1e6, 1e6);
        n.y = n.y.clamp(-1e6, 1e6);
    }
    let mut eids = BTreeSet::new();
    let mut ekeys = BTreeSet::new();
    for e in &mut g.edges {
        if !valid_id(&e.id) || !eids.insert(e.id.clone()) {
            return Err(format!("edge id \"{}\" is invalid or repeated", e.id));
        }
        if !ids.contains(&e.from) || !ids.contains(&e.to) || e.from == e.to {
            return Err("every edge must join two different existing nodes".into());
        }
        e.label = short("edge label", &e.label, 80)?;
        e.source = short("source", &e.source, 60)?;
        if !ekeys.insert((e.from.clone(), e.to.clone(), e.label.clone())) {
            return Err("duplicate edge".into());
        }
    }
    Ok(())
}

/// Merge validated additions into a graph (used by transforms and imports): nodes are matched by type and label,
/// edges by endpoints and label. Client ids are remapped.
/// Add nodes and edges to a graph, reusing existing nodes. With `skip_invalid` a node whose type or label fails validation (and any edge touching it) is
/// dropped and counted instead of failing the whole request. Transforms use it: upstream data is messy.
/// Returns (added nodes, added edges, skipped nodes and edges).
pub fn merge_opt(g: &mut Graph, nodes: Vec<Node>, edges: Vec<Edge>, source: &str, skip_invalid: bool) -> Result<(usize, usize, usize), String> {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    let (mut an, mut ae, mut skipped) = (0, 0, 0);
    for mut n in nodes {
        n.label = match check_node(&n.kind, &n.label) {
            Ok(l) => l,
            Err(_) if skip_invalid => {
                skipped += 1;
                continue;
            }
            Err(e) => return Err(e),
        };
        let existing = g.nodes.iter().find(|x| x.kind == n.kind && x.label == n.label).map(|x| x.id.clone());
        let id = match existing {
            Some(id) => id,
            None => {
                if g.nodes.len() >= MAX_NODES {
                    return Err(format!("graph is full ({MAX_NODES} nodes)"));
                }
                let id = new_id();
                g.nodes.push(Node { id: id.clone(), kind: n.kind, label: n.label, x: n.x, y: n.y, pinned: false, group: short("group", &n.group, 40)?, note: String::new(), source: source.into() });
                an += 1;
                id
            }
        };
        map.insert(n.id, id);
    }
    for e in edges {
        let (Some(f), Some(t)) = (map.get(&e.from).cloned().or_else(|| g.nodes.iter().find(|n| n.id == e.from).map(|n| n.id.clone())), map.get(&e.to).cloned().or_else(|| g.nodes.iter().find(|n| n.id == e.to).map(|n| n.id.clone()))) else {
            if skip_invalid {
                skipped += 1;
                continue;
            }
            return Err("an edge refers to a node that is not in the request".into());
        };
        let label = short("edge label", &e.label, 80)?;
        if f == t || g.edges.iter().any(|x| x.from == f && x.to == t && x.label == label) {
            continue;
        }
        if g.edges.len() >= MAX_EDGES {
            return Err(format!("graph is full ({MAX_EDGES} edges)"));
        }
        g.edges.push(Edge { id: new_id(), from: f, to: t, label, source: source.into() });
        ae += 1;
    }
    g.updated = now_iso();
    Ok((an, ae, skipped))
}

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> std::io::Result<Store> {
        let dir = dir.into().join("graphs");
        fs::create_dir_all(&dir)?;
        Ok(Store { dir })
    }
    fn path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }
    pub fn load(&self, id: &str) -> Result<Option<Graph>, String> {
        if !valid_id(id) {
            return Ok(None);
        }
        match fs::read_to_string(self.path(id)) {
            Ok(t) => serde_json::from_str(&t).map(Some).map_err(|e| format!("graph file is unreadable: {e}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
    /// Temp file, fsync, rename: a crash never leaves a half-written graph.
    pub fn save(&self, g: &Graph) -> Result<(), String> {
        let data = serde_json::to_vec(g).map_err(|e| e.to_string())?;
        if data.len() > MAX_GRAPH_BYTES {
            return Err(format!("graph would exceed {} MB", MAX_GRAPH_BYTES / 1024 / 1024));
        }
        let tmp = self.dir.join(format!(".{}.tmp", g.id));
        let w = || -> std::io::Result<()> {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&data)?;
            f.sync_all()?;
            fs::rename(&tmp, self.path(&g.id))
        };
        w().map_err(|e| {
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
    pub fn list(&self) -> Vec<Graph> {
        let Ok(rd) = fs::read_dir(&self.dir) else { return vec![] };
        let mut v: Vec<Graph> = rd.flatten().filter(|e| e.path().extension().is_some_and(|x| x == "json")).filter_map(|e| serde_json::from_str(&fs::read_to_string(e.path()).ok()?).ok()).collect();
        v.sort_by(|a, b| b.updated.cmp(&a.updated));
        v
    }
}

pub fn summary(g: &Graph) -> Value {
    json!({ "id": g.id, "name": g.name, "created": g.created, "updated": g.updated, "nodes": g.nodes.len(), "edges": g.edges.len() })
}

// ---- exports -------------------------------------------------------------------------------------

pub fn export_json(g: &Graph) -> Value {
    json!({ "format": "osnt-graph/1", "exported": now_iso(), "graph": g })
}

pub fn import_bundle(v: &Value) -> Result<Graph, String> {
    if v["format"] != "osnt-graph/1" {
        return Err("not an OSNT graph bundle (format osnt-graph/1 expected)".into());
    }
    let mut g: Graph = serde_json::from_value(v["graph"].clone()).map_err(|e| format!("bundle is malformed: {e}"))?;
    validate(&mut g)?;
    g.id = new_id();
    g.updated = now_iso();
    for n in &mut g.nodes {
        if n.source.is_empty() {
            n.source = "import".into();
        }
    }
    Ok(g)
}

fn xml(s: &str) -> String {
    s.chars().map(|c| match c { '&' => "&amp;".to_string(), '<' => "&lt;".into(), '>' => "&gt;".into(), '"' => "&quot;".into(), '\'' => "&apos;".into(), c => c.to_string() }).collect()
}

pub fn graphml(g: &Graph) -> String {
    let mut s = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n  <key id=\"type\" for=\"node\" attr.name=\"type\" attr.type=\"string\"/>\n  <key id=\"label\" for=\"node\" attr.name=\"label\" attr.type=\"string\"/>\n  <key id=\"group\" for=\"node\" attr.name=\"group\" attr.type=\"string\"/>\n  <key id=\"elabel\" for=\"edge\" attr.name=\"label\" attr.type=\"string\"/>\n");
    s.push_str(&format!("  <graph id=\"{}\" edgedefault=\"directed\">\n", xml(&g.id)));
    for n in &g.nodes {
        s.push_str(&format!("    <node id=\"{}\"><data key=\"type\">{}</data><data key=\"label\">{}</data><data key=\"group\">{}</data></node>\n", xml(&n.id), xml(&n.kind), xml(&n.label), xml(&n.group)));
    }
    for e in &g.edges {
        s.push_str(&format!("    <edge id=\"{}\" source=\"{}\" target=\"{}\"><data key=\"elabel\">{}</data></edge>\n", xml(&e.id), xml(&e.from), xml(&e.to), xml(&e.label)));
    }
    s.push_str("  </graph>\n</graphml>\n");
    s
}

pub fn gexf(g: &Graph) -> String {
    let mut s = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<gexf xmlns=\"http://gexf.net/1.3\" version=\"1.3\">\n");
    s.push_str(&format!("  <graph defaultedgetype=\"directed\">\n    <attributes class=\"node\"><attribute id=\"0\" title=\"type\" type=\"string\"/><attribute id=\"1\" title=\"group\" type=\"string\"/></attributes>\n    <nodes>\n"));
    for n in &g.nodes {
        s.push_str(&format!("      <node id=\"{}\" label=\"{}\"><attvalues><attvalue for=\"0\" value=\"{}\"/><attvalue for=\"1\" value=\"{}\"/></attvalues></node>\n", xml(&n.id), xml(&n.label), xml(&n.kind), xml(&n.group)));
    }
    s.push_str("    </nodes>\n    <edges>\n");
    for e in &g.edges {
        s.push_str(&format!("      <edge id=\"{}\" source=\"{}\" target=\"{}\" label=\"{}\"/>\n", xml(&e.id), xml(&e.from), xml(&e.to), xml(&e.label)));
    }
    s.push_str("    </edges>\n  </graph>\n</gexf>\n");
    s
}

fn mm(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).map(|c| match c { '"' => '\'', '[' | ']' | '(' | ')' | '{' | '}' | '|' | '<' | '>' | '`' => ' ', c => c }).collect()
}

pub fn mermaid(g: &Graph) -> String {
    let idx: BTreeMap<&str, usize> = g.nodes.iter().enumerate().map(|(i, n)| (n.id.as_str(), i)).collect();
    let mut s = String::from("graph LR\n");
    for (i, n) in g.nodes.iter().enumerate() {
        s.push_str(&format!("  n{i}[\"{}: {}\"]\n", mm(&n.kind), mm(&n.label)));
    }
    for e in &g.edges {
        if let (Some(a), Some(b)) = (idx.get(e.from.as_str()), idx.get(e.to.as_str())) {
            if e.label.is_empty() { s.push_str(&format!("  n{a} --> n{b}\n")) } else { s.push_str(&format!("  n{a} -->|\"{}\"| n{b}\n", mm(&e.label))) }
        }
    }
    s
}

pub fn markdown(g: &Graph) -> String {
    let mut m = format!("# {}\n\n{} nodes, {} edges. Updated {}.\n\n", g.name, g.nodes.len(), g.edges.len(), g.updated);
    for t in NODE_TYPES {
        let of: Vec<&Node> = g.nodes.iter().filter(|n| n.kind == t).collect();
        if of.is_empty() {
            continue;
        }
        m.push_str(&format!("## {t}\n\n"));
        for n in of {
            m.push_str(&format!("- `{}`{}{}\n", n.label, if n.group.is_empty() { String::new() } else { format!(" (group {})", n.group) }, if n.note.is_empty() { String::new() } else { format!(": {}", n.note.replace('\n', " ")) }));
        }
        m.push('\n');
    }
    let name: BTreeMap<&str, &str> = g.nodes.iter().map(|n| (n.id.as_str(), n.label.as_str())).collect();
    m.push_str("## Relationships\n\n");
    for e in &g.edges {
        m.push_str(&format!("- `{}` -> `{}`{}\n", name.get(e.from.as_str()).unwrap_or(&"?"), name.get(e.to.as_str()).unwrap_or(&"?"), if e.label.is_empty() { String::new() } else { format!(" ({})", e.label) }));
    }
    m.push_str(&format!("\n## Diagram\n\n```mermaid\n{}```\n", mermaid(g)));
    m
}

//! DNS, mail-policy and web-policy checks for one domain. DNS goes through DNS-over-HTTPS (dns.google); the few
//! well-known files on the domain itself are fetched through the SSRF guard. Everything is passive and read-only, and
//! mailbox names found in records (rua, SOA rname, security.txt Contact) are masked: only organisational domains show.

use std::{
    collections::{BTreeSet, HashSet},
    time::Duration,
};

use anyhow::{Result, anyhow};
use serde_json::{Value, json};

use crate::{
    cache::Cache,
    net::{Http, Req, par_map, valid_found_name},
    ssrf::{Guard, guarded_get},
};

#[derive(Clone)]
pub struct Up {
    pub dns: String,
    /// Tests only: fetch web files from `{base}/{host}{path}` instead of `https://{host}{path}`.
    pub web_base: Option<String>,
}
impl Default for Up {
    fn default() -> Self {
        Up { dns: "https://dns.google".into(), web_base: None }
    }
}

pub struct App {
    pub http: Http,
    pub web: ureq::Agent,
    pub guard: Guard,
    pub cache: Cache,
    pub up: Up,
}

const NEG: Duration = Duration::from_secs(30);
const WEB_MAX: usize = 256 * 1024;

pub const TYPES: [&str; 12] = ["A", "AAAA", "NS", "MX", "TXT", "SOA", "CAA", "CNAME", "DS", "DNSKEY", "HTTPS", "SRV"];
const SELECTORS: [&str; 24] = [
    "default", "google", "selector1", "selector2", "k1", "k2", "k3", "mail", "dkim", "s1", "s2", "smtp", "mandrill", "mxvault", "everlytickey1", "zendesk1", "zendesk2", "pm", "cm", "fm1", "fm2", "fm3",
    "protonmail", "scph1118",
];

// ---- DoH -------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Rec {
    pub name: String,
    pub ty: u64,
    pub ttl: u64,
    pub data: String,
}

pub struct Dns {
    pub status: u64,
    pub ad: bool,
    pub recs: Vec<Rec>,
}

/// TXT answers may come back as quoted chunks (`"abc" "def"`); join them as the DNS RFCs say.
pub fn txt_value(data: &str) -> String {
    let d = data.trim();
    if !d.starts_with('"') {
        return d.to_string();
    }
    let mut out = String::new();
    let mut in_q = false;
    let mut esc = false;
    for c in d.chars() {
        match (in_q, esc, c) {
            (true, true, c) => { out.push(c); esc = false; }
            (true, false, '\\') => esc = true,
            (true, false, '"') => in_q = false,
            (true, false, c) => out.push(c),
            (false, _, '"') => in_q = true,
            _ => {}
        }
    }
    out
}

pub fn parse_dns(v: &Value) -> Dns {
    let recs = v["Answer"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|a| Some(Rec { name: a["name"].as_str()?.trim_end_matches('.').to_string(), ty: a["type"].as_u64()?, ttl: a["TTL"].as_u64().unwrap_or(0), data: a["data"].as_str()?.to_string() }))
        .collect();
    Dns { status: v["Status"].as_u64().unwrap_or(2), ad: v["AD"].as_bool().unwrap_or(false), recs }
}

pub fn type_code(t: &str) -> u64 {
    match t { "A" => 1, "NS" => 2, "CNAME" => 5, "SOA" => 6, "MX" => 15, "TXT" => 16, "AAAA" => 28, "SRV" => 33, "DS" => 43, "DNSKEY" => 48, "HTTPS" => 65, "CAA" => 257, _ => 0 }
}

pub fn doh(app: &App, name: &str, rtype: &str, dnssec: bool) -> Result<Dns> {
    let key = format!("doh:{name}:{rtype}:{}", dnssec as u8);
    let v = app.cache.cached_json_neg(&key, Duration::from_secs(300), NEG, || {
        let url = format!("{}/resolve?name={name}&type={rtype}{}", app.up.dns, if dnssec { "&do=1" } else { "" });
        app.http.json(Req::new(&url).accept("application/dns-json").gap(40))
    })?;
    Ok(parse_dns(&v))
}

fn of_type(d: &Dns, t: &str) -> Vec<Rec> {
    d.recs.iter().filter(|r| r.ty == type_code(t)).cloned().collect()
}

fn txt(app: &App, name: &str) -> Result<Vec<String>> {
    Ok(of_type(&doh(app, name, "TXT", false)?, "TXT").into_iter().map(|r| txt_value(&r.data)).collect())
}

// ---- masking ---------------------------------------------------------------------------------------------------

/// Hide mailbox names (`mailto:a@b` becomes `mailto:(mailbox)@b`); URLs and plain text pass through.
pub fn mask_contact(s: &str) -> String {
    let s = s.trim();
    let (scheme, rest) = match s.split_once(':') {
        Some((sc, r)) if sc.eq_ignore_ascii_case("mailto") => (format!("{sc}:"), r),
        Some((sc, _)) if sc.eq_ignore_ascii_case("tel") || sc.eq_ignore_ascii_case("sms") => return format!("{sc}:(number hidden)"),
        _ => (String::new(), s),
    };
    match rest.split('?').next().unwrap_or(rest).rsplit_once('@') {
        Some((_, host)) if !rest.contains("://") => format!("{scheme}(mailbox)@{host}"),
        _ => s.to_string(),
    }
}

fn mask_list(s: &str) -> Vec<String> {
    s.split(',').map(mask_contact).filter(|x| !x.is_empty()).collect()
}

// ---- check plumbing --------------------------------------------------------------------------------------------

pub fn check(id: &str, title: &str, status: &str, weight: u32, summary: impl Into<String>, data: Value) -> Value {
    json!({ "id": id, "title": title, "status": status, "weight": weight, "summary": summary.into(), "data": data })
}

fn unknown(id: &str, title: &str, e: &anyhow::Error) -> Value {
    check(id, title, "unknown", 0, format!("Lookup failed: {e}"), Value::Null)
}

/// Score 0-100 from pass (1), warn (0.5), fail (0), weighted. Info and unknown rows do not count.
pub fn score(checks: &[Value]) -> Value {
    let (mut earned, mut total) = (0.0f64, 0.0f64);
    let (mut p, mut w, mut f) = (0, 0, 0);
    for c in checks {
        let wt = c["weight"].as_f64().unwrap_or(1.0);
        match c["status"].as_str() {
            Some("pass") => { earned += wt; total += wt; p += 1; }
            Some("warn") => { earned += wt * 0.5; total += wt; w += 1; }
            Some("fail") => { total += wt; f += 1; }
            _ => {}
        }
    }
    json!({ "score": if total > 0.0 { Some((100.0 * earned / total).round() as u32) } else { None }, "pass": p, "warn": w, "fail": f })
}

fn tags(rec: &str) -> Vec<(String, String)> {
    rec.split(';').filter_map(|p| p.split_once('=')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect()
}
fn tag<'a>(t: &'a [(String, String)], k: &str) -> Option<&'a str> {
    t.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str())
}

// ---- SPF -------------------------------------------------------------------------------------------------------

struct SpfCtx<'a> {
    app: &'a App,
    fetched: usize,
    lookups: usize,
    visited: HashSet<String>,
    limited: bool,
}

fn spf_node(ctx: &mut SpfCtx, domain: &str, depth: usize) -> Value {
    let recs = if ctx.fetched >= 14 { ctx.limited = true; Err(anyhow!("not expanded (query budget reached)")) } else { ctx.fetched += 1; txt(ctx.app, domain) };
    let spf: Vec<String> = match recs {
        Ok(r) => r.into_iter().filter(|t| t.to_ascii_lowercase().starts_with("v=spf1")).collect(),
        Err(e) => return json!({ "domain": domain, "error": e.to_string() }),
    };
    let Some(record) = spf.first() else { return json!({ "domain": domain, "error": "no SPF record found (the include or redirect target has none)" }) };
    let mut mechs = Vec::new();
    let mut children = Vec::new();
    for tok in record.split_whitespace().skip(1) {
        if let Some(t) = tok.strip_prefix("redirect=") {
            ctx.lookups += 1;
            mechs.push(json!({ "q": "", "kind": "redirect", "arg": t }));
            children.push(spf_child(ctx, t, depth));
            continue;
        }
        if tok.contains('=') {
            mechs.push(json!({ "q": "", "kind": tok.split('=').next(), "arg": tok.split_once('=').map(|x| x.1) }));
            continue;
        }
        let (q, rest) = match tok.chars().next() { Some(c @ ('+' | '-' | '~' | '?')) => (c.to_string(), &tok[1..]), _ => ("+".to_string(), tok) };
        let (kind, arg) = match rest.split_once([':', '/']) { Some((k, a)) => (k.to_ascii_lowercase(), Some(a.to_string())), None => (rest.to_ascii_lowercase(), None) };
        if matches!(kind.as_str(), "include" | "a" | "mx" | "ptr" | "exists") {
            ctx.lookups += 1;
        }
        if kind == "include" {
            if let Some(a) = &arg {
                children.push(spf_child(ctx, a, depth));
            }
        }
        mechs.push(json!({ "q": q, "kind": kind, "arg": arg }));
    }
    json!({ "domain": domain, "record": record, "mechanisms": mechs, "children": children, "duplicate_records": spf.len() > 1 })
}

fn spf_child(ctx: &mut SpfCtx, target: &str, depth: usize) -> Value {
    let t = target.trim_end_matches('.').to_ascii_lowercase();
    if depth >= 8 || !ctx.visited.insert(t.clone()) {
        return json!({ "domain": t, "error": if depth >= 8 { "too deep: not expanded" } else { "already seen (loop or repeat)" } });
    }
    if valid_found_name(&t).is_none() {
        return json!({ "domain": t, "error": "macro or invalid domain: not expanded" });
    }
    spf_node(ctx, &t, depth + 1)
}

/// The final `all` qualifier, following a `redirect=`.
pub fn spf_all(node: &Value) -> Option<String> {
    for m in node["mechanisms"].as_array().into_iter().flatten() {
        if m["kind"] == "all" {
            return m["q"].as_str().map(str::to_owned);
        }
    }
    node["children"].as_array().and_then(|c| {
        let has_redirect = node["mechanisms"].as_array().is_some_and(|m| m.iter().any(|x| x["kind"] == "redirect"));
        if has_redirect { c.last().and_then(spf_all) } else { None }
    })
}

fn count_kind(node: &Value, kind: &str) -> usize {
    node["mechanisms"].as_array().into_iter().flatten().filter(|m| m["kind"] == kind).count() + node["children"].as_array().into_iter().flatten().map(|c| count_kind(c, kind)).sum::<usize>()
}

fn spf_checks(app: &App, domain: &str) -> Vec<Value> {
    let recs = match txt(app, domain) {
        Ok(r) => r,
        Err(e) => return vec![unknown("spf", "SPF record", &e)],
    };
    let spf: Vec<&String> = recs.iter().filter(|t| t.to_ascii_lowercase().starts_with("v=spf1")).collect();
    match spf.len() {
        0 => return vec![check("spf", "SPF record", "fail", 2, "No SPF record. Receivers cannot tell which servers may send mail for this domain.", Value::Null)],
        1 => {}
        n => return vec![check("spf", "SPF record", "fail", 2, format!("{n} SPF records published. RFC 7208 allows exactly one; receivers return a permanent error."), json!({ "records": spf }))],
    }
    let mut ctx = SpfCtx { app, fetched: 0, lookups: 0, visited: HashSet::from([domain.to_string()]), limited: false };
    let tree = spf_node(&mut ctx, domain, 0);
    let mut out = vec![check("spf", "SPF record", "pass", 2, "One SPF record is published.", json!({ "record": spf[0], "tree": tree }))];
    let n = ctx.lookups;
    let ptr = count_kind(&tree, "ptr");
    let (st, msg) = match n {
        0..=7 => ("pass", format!("{n} of 10 DNS lookups used.")),
        8..=10 => ("warn", format!("{n} of 10 DNS lookups used: close to the limit.")),
        _ => ("fail", format!("{n} DNS lookups: over the limit of 10, so SPF evaluation fails with a permanent error.")),
    };
    out.push(check("spf_lookups", "SPF lookup count", st, 1, if ctx.limited { format!("{msg} (tree not fully expanded, so this is a lower bound)") } else { msg }, json!({ "lookups": n })));
    let (st, msg) = match spf_all(&tree).as_deref() {
        Some("-") => ("pass", "Ends in -all: mail from other servers is rejected.".to_string()),
        Some("~") => ("warn", "Ends in ~all (softfail): unauthorised mail is marked, not rejected.".to_string()),
        Some("?") => ("fail", "Ends in ?all (neutral): the record gives receivers no guidance.".to_string()),
        Some(_) => ("fail", "Ends in +all: anyone may send as this domain.".to_string()),
        None => ("warn", "No terminating all mechanism or redirect.".to_string()),
    };
    out.push(check("spf_all", "SPF default policy", st, 1, msg, Value::Null));
    if ptr > 0 {
        out.push(check("spf_ptr", "SPF uses ptr", "warn", 1, "The ptr mechanism is deprecated (RFC 7208): slow and unreliable.", Value::Null));
    }
    out
}

// ---- DMARC / DKIM / MTA-STS / TLS-RPT / BIMI -------------------------------------------------------------------

fn dmarc_checks(app: &App, domain: &str) -> Vec<Value> {
    let recs = match txt(app, &format!("_dmarc.{domain}")) {
        Ok(r) => r,
        Err(e) => return vec![unknown("dmarc", "DMARC policy", &e)],
    };
    let d: Vec<&String> = recs.iter().filter(|t| t.to_ascii_lowercase().starts_with("v=dmarc1")).collect();
    if d.is_empty() {
        return vec![check("dmarc", "DMARC policy", "fail", 2, "No DMARC record at _dmarc. Spoofed mail is not covered by any published policy.", Value::Null)];
    }
    if d.len() > 1 {
        return vec![check("dmarc", "DMARC policy", "fail", 2, "More than one DMARC record: receivers ignore the policy.", Value::Null)];
    }
    let t = tags(d[0]);
    let p = tag(&t, "p").unwrap_or("").to_ascii_lowercase();
    let pct: u32 = tag(&t, "pct").and_then(|v| v.parse().ok()).unwrap_or(100);
    let rua = tag(&t, "rua").map(mask_list).unwrap_or_default();
    let ruf = tag(&t, "ruf").map(mask_list).unwrap_or_default();
    let data = json!({ "record": mask_record(d[0]), "p": p, "sp": tag(&t, "sp"), "pct": pct, "adkim": tag(&t, "adkim"), "aspf": tag(&t, "aspf"), "rua": rua, "ruf": ruf });
    let mut out = Vec::new();
    let (st, msg) = match p.as_str() {
        "reject" => ("pass", "p=reject: unauthenticated mail is rejected."),
        "quarantine" => ("pass", "p=quarantine: unauthenticated mail goes to spam."),
        "none" => ("warn", "p=none: monitoring only, nothing is enforced."),
        _ => ("fail", "The p= tag is missing or invalid, so the record is ignored."),
    };
    out.push(check("dmarc", "DMARC policy", st, 2, msg, data));
    if p == "reject" || p == "quarantine" {
        if pct < 100 {
            out.push(check("dmarc_pct", "DMARC coverage", "warn", 1, format!("pct={pct}: the policy applies to only {pct}% of failing mail."), Value::Null));
        }
    }
    out.push(if rua.is_empty() {
        check("dmarc_rua", "DMARC reporting", "warn", 1, "No rua= address: the owner receives no aggregate reports about spoofing attempts.", Value::Null)
    } else {
        check("dmarc_rua", "DMARC reporting", "pass", 1, "Aggregate reports are requested.", json!({ "rua": rua }))
    });
    out
}

/// A copy of the record text with the mailbox names removed from rua/ruf.
pub fn mask_record(rec: &str) -> String {
    rec.split(';')
        .map(|part| match part.split_once('=') {
            Some((k, v)) if matches!(k.trim().to_ascii_lowercase().as_str(), "rua" | "ruf") => format!("{}={}", k.trim(), mask_list(v).join(",")),
            _ => part.trim().to_string(),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn rsa_bits(p_b64: &str) -> Option<u32> {
    let clean: String = p_b64.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = clean.trim_end_matches('=').len() * 6 / 8;
    Some(match bytes { 0 => return None, 1..=100 => 512, 101..=220 => 1024, 221..=400 => 2048, _ => 4096 })
}

fn dkim_check(app: &App, domain: &str) -> Value {
    let probes = par_map(&SELECTORS, 6, |sel| (*sel, txt(app, &format!("{sel}._domainkey.{domain}"))));
    let mut found = Vec::new();
    let mut errors = 0;
    for (sel, r) in probes {
        match r {
            Ok(v) => {
                if let Some(rec) = v.iter().find(|t| { let l = t.to_ascii_lowercase(); l.contains("p=") && (l.contains("v=dkim1") || l.contains("k=")) }) {
                    let t = tags(rec);
                    let p = tag(&t, "p").unwrap_or("");
                    let k = tag(&t, "k").unwrap_or("rsa").to_string();
                    found.push(json!({ "selector": sel, "key_type": k, "key_bits": if k == "rsa" { rsa_bits(p).map(Value::from).unwrap_or(Value::Null) } else { Value::from(256) }, "revoked": p.is_empty(), "testing": tag(&t, "t").is_some_and(|x| x.contains('y')) }));
                }
            }
            Err(_) => errors += 1,
        }
    }
    if errors == SELECTORS.len() {
        return check("dkim", "DKIM keys", "unknown", 0, "DNS lookups failed.", Value::Null);
    }
    let live: Vec<&Value> = found.iter().filter(|f| f["revoked"] == false).collect();
    let note = format!("Probed {} common selectors only; a domain can use any selector name.", SELECTORS.len());
    if live.is_empty() {
        return check("dkim", "DKIM keys", "warn", 1, format!("No DKIM key found at the common selectors. {note}"), json!({ "found": found }));
    }
    let weak = live.iter().any(|f| f["key_bits"].as_u64().is_some_and(|b| b <= 1024) && f["key_type"] == "rsa");
    check("dkim", "DKIM keys", if weak { "warn" } else { "pass" }, 1, if weak { format!("{} key(s) found, at least one RSA key of 1024 bits or less. {note}", live.len()) } else { format!("{} key(s) found. {note}", live.len()) }, json!({ "found": found }))
}

fn web_fetch(app: &App, host: &str, path: &str) -> Result<crate::ssrf::Fetched, String> {
    let url = match &app.up.web_base {
        Some(b) => format!("{b}/{host}{path}"),
        None => format!("https://{host}{path}"),
    };
    guarded_get(&app.web, &app.guard, &url, WEB_MAX, "text/plain, */*")
}

fn mta_sts_checks(app: &App, domain: &str) -> Vec<Value> {
    let rec = match txt(app, &format!("_mta-sts.{domain}")) {
        Ok(r) => r.into_iter().find(|t| t.to_ascii_lowercase().starts_with("v=stsv1")),
        Err(e) => return vec![unknown("mta_sts", "MTA-STS", &e)],
    };
    let Some(rec) = rec else { return vec![check("mta_sts", "MTA-STS", "info", 0, "Not configured. MTA-STS makes sending servers require TLS to your mail servers; optional hardening.", Value::Null)] };
    let host = format!("mta-sts.{domain}");
    match web_fetch(app, &host, "/.well-known/mta-sts.txt") {
        Ok(f) if f.status == 200 => {
            let body = String::from_utf8_lossy(&f.body).to_string();
            let mut mode = String::new();
            let mut max_age = 0u64;
            let mut mx = Vec::new();
            for l in body.lines() {
                if let Some((k, v)) = l.split_once(':') {
                    match k.trim().to_ascii_lowercase().as_str() {
                        "mode" => mode = v.trim().to_ascii_lowercase(),
                        "max_age" => max_age = v.trim().parse().unwrap_or(0),
                        "mx" => mx.push(v.trim().to_string()),
                        _ => {}
                    }
                }
            }
            let data = json!({ "record": rec, "mode": mode, "max_age": max_age, "mx": mx });
            let (st, msg) = match mode.as_str() {
                "enforce" if max_age >= 86400 => ("pass", "Policy published with mode=enforce.".to_string()),
                "enforce" => ("warn", format!("mode=enforce but max_age={max_age}s is under a day.")),
                "testing" => ("warn", "mode=testing: failures are reported but not enforced.".into()),
                "none" => ("warn", "mode=none: MTA-STS is switched off.".into()),
                _ => ("fail", "The policy file has no valid mode.".into()),
            };
            vec![check("mta_sts", "MTA-STS", st, 1, msg, data)]
        }
        Ok(f) => vec![check("mta_sts", "MTA-STS", "fail", 1, format!("The TXT record exists but the policy file at https://{host}/.well-known/mta-sts.txt returned HTTP {}.", f.status), json!({ "record": rec }))],
        Err(e) => vec![check("mta_sts", "MTA-STS", "fail", 1, format!("The TXT record exists but the policy file could not be fetched: {e}"), json!({ "record": rec }))],
    }
}

fn simple_txt(app: &App, id: &str, title: &str, name: String, prefix: &str, absent: &str) -> Value {
    match txt(app, &name) {
        Err(e) => unknown(id, title, &e),
        Ok(r) => match r.into_iter().find(|t| t.to_ascii_lowercase().starts_with(prefix)) {
            None => check(id, title, "info", 0, absent, Value::Null),
            Some(rec) => {
                let t = tags(&rec);
                let mut data = json!({ "record": mask_record(&rec) });
                if let Some(rua) = tag(&t, "rua") { data["rua"] = json!(mask_list(rua)); }
                if let Some(l) = tag(&t, "l") { data["logo"] = json!(l); }
                if let Some(a) = tag(&t, "a") { data["vmc"] = json!(a); }
                check(id, title, "pass", 0, "Published.", data)
            }
        },
    }
}

pub fn mail(app: &App, domain: &str) -> Vec<Value> {
    let (spf, dmarc, dkim, sts, others, mx) = std::thread::scope(|s| {
        let a = s.spawn(|| spf_checks(app, domain));
        let b = s.spawn(|| dmarc_checks(app, domain));
        let c = s.spawn(|| dkim_check(app, domain));
        let d = s.spawn(|| mta_sts_checks(app, domain));
        let e = s.spawn(|| vec![
            simple_txt(app, "tls_rpt", "TLS-RPT", format!("_smtp._tls.{domain}"), "v=tlsrptv1", "Not configured. TLS-RPT sends reports about failed TLS connections to your mail servers; optional."),
            simple_txt(app, "bimi", "BIMI", format!("default._bimi.{domain}"), "v=bimi1", "Not configured. BIMI shows a brand logo in some mail clients; optional and needs a strict DMARC policy."),
        ]);
        let f = s.spawn(|| mx_check(app, domain));
        (a.join().unwrap(), b.join().unwrap(), c.join().unwrap(), d.join().unwrap(), e.join().unwrap(), f.join().unwrap())
    });
    let mut out = vec![mx];
    out.extend(spf);
    out.extend(dmarc);
    out.push(dkim);
    out.extend(sts);
    out.extend(others);
    out
}

fn mx_check(app: &App, domain: &str) -> Value {
    match doh(app, domain, "MX", false) {
        Err(e) => unknown("mx", "Mail exchangers", &e),
        Ok(d) => {
            let mx: Vec<String> = of_type(&d, "MX").into_iter().map(|r| r.data).collect();
            let null = mx.len() == 1 && mx[0].split_whitespace().nth(1).is_some_and(|h| h == ".");
            if mx.is_empty() {
                check("mx", "Mail exchangers", "info", 0, "No MX records: the domain does not receive mail (or relies on an A record fallback).", json!({ "mx": mx }))
            } else if null {
                check("mx", "Mail exchangers", "info", 0, "Null MX (RFC 7505): the domain states that it accepts no mail.", json!({ "mx": mx }))
            } else {
                check("mx", "Mail exchangers", "pass", 1, format!("{} MX record(s).", mx.len()), json!({ "mx": mx }))
            }
        }
    }
}

// ---- DNSSEC ----------------------------------------------------------------------------------------------------

fn alg_name(n: u64) -> (&'static str, bool) {
    match n {
        1 => ("RSAMD5", true), 3 => ("DSA", true), 5 => ("RSASHA1", true), 6 => ("DSA-NSEC3-SHA1", true), 7 => ("RSASHA1-NSEC3-SHA1", true), 8 => ("RSASHA256", false), 10 => ("RSASHA512", false),
        13 => ("ECDSAP256SHA256", false), 14 => ("ECDSAP384SHA384", false), 15 => ("ED25519", false), 16 => ("ED448", false), _ => ("unknown", false),
    }
}

pub fn dnssec(app: &App, domain: &str) -> Vec<Value> {
    let (ds, key, a) = std::thread::scope(|s| {
        let x = s.spawn(|| doh(app, domain, "DS", true));
        let y = s.spawn(|| doh(app, domain, "DNSKEY", true));
        let z = s.spawn(|| doh(app, domain, "SOA", true));
        (x.join().unwrap(), y.join().unwrap(), z.join().unwrap())
    });
    let (ds, key, soa) = match (ds, key, a) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => return vec![unknown("dnssec", "DNSSEC", &e)],
    };
    let ds_recs = of_type(&ds, "DS");
    let key_recs = of_type(&key, "DNSKEY");
    let ds_info: Vec<Value> = ds_recs.iter().map(|r| { let p: Vec<&str> = r.data.split_whitespace().collect(); json!({ "key_tag": p.first(), "algorithm": p.get(1).and_then(|a| a.parse::<u64>().ok()).map(|a| alg_name(a).0), "digest_type": p.get(2) }) }).collect();
    let key_info: Vec<Value> = key_recs.iter().map(|r| {
        let p: Vec<&str> = r.data.split_whitespace().collect();
        let flags = p.first().and_then(|f| f.parse::<u64>().ok()).unwrap_or(0);
        let alg = p.get(2).and_then(|a| a.parse::<u64>().ok()).unwrap_or(0);
        json!({ "role": if flags & 1 == 1 { "KSK" } else { "ZSK" }, "flags": flags, "algorithm": alg_name(alg).0, "deprecated": alg_name(alg).1 })
    }).collect();
    let data = json!({ "ds": ds_info, "dnskey": key_info, "ad": soa.ad || ds.ad });
    let weak = key_info.iter().any(|k| k["deprecated"] == true);
    let mut out = Vec::new();
    out.push(if ds_recs.is_empty() && key_recs.is_empty() {
        check("dnssec", "DNSSEC", "warn", 1, "The domain is not signed: answers cannot be verified as authentic.", data)
    } else if ds_recs.is_empty() {
        check("dnssec", "DNSSEC", "warn", 1, "DNSKEY records exist but there is no DS record at the parent: the chain of trust is not established.", data)
    } else if !(soa.ad || ds.ad || key.ad) {
        check("dnssec", "DNSSEC", "fail", 2, "A DS record exists but the validating resolver did not return the authenticated-data flag: the signatures may be broken or expired.", data)
    } else {
        check("dnssec", "DNSSEC", "pass", 2, "Signed, and the validating resolver confirms the chain (AD flag set).", data)
    });
    if weak {
        out.push(check("dnssec_alg", "DNSSEC algorithms", "warn", 1, "A deprecated signing algorithm (RSASHA1 family or older) is in use.", Value::Null));
    }
    out
}

// ---- DNS health ------------------------------------------------------------------------------------------------

fn v4_24(ip: &str) -> Option<String> {
    let o: Vec<&str> = ip.split('.').collect();
    (o.len() == 4).then(|| format!("{}.{}.{}", o[0], o[1], o[2]))
}

pub fn dns_health(app: &App, domain: &str) -> Vec<Value> {
    let mut out = Vec::new();
    match doh(app, domain, "NS", false) {
        Err(e) => out.push(unknown("ns", "Name servers", &e)),
        Ok(d) => {
            let ns: Vec<String> = of_type(&d, "NS").into_iter().map(|r| r.data.trim_end_matches('.').to_ascii_lowercase()).collect();
            if ns.is_empty() {
                out.push(check("ns", "Name servers", "fail", 2, "No NS records were returned for this name. Check that it is a registered domain (not a subdomain).", Value::Null));
            } else {
                let probes = par_map(&ns, 4, |n| (n.clone(), doh(app, n, "A", false), doh(app, n, "AAAA", false)));
                let mut rows = Vec::new();
                let (mut unresolved, mut cname_ns) = (Vec::new(), Vec::new());
                let mut nets = BTreeSet::new();
                let mut v6 = false;
                let mut ips_seen = BTreeSet::new();
                for (n, a, aaaa) in probes {
                    let (Ok(a), Ok(aaaa)) = (a, aaaa) else { rows.push(json!({ "ns": n, "error": "lookup failed" })); continue };
                    let v4: Vec<String> = of_type(&a, "A").into_iter().map(|r| r.data).collect();
                    let v6s: Vec<String> = of_type(&aaaa, "AAAA").into_iter().map(|r| r.data).collect();
                    if a.recs.iter().chain(aaaa.recs.iter()).any(|r| r.ty == 5) { cname_ns.push(n.clone()); }
                    if v4.is_empty() && v6s.is_empty() { unresolved.push(n.clone()); }
                    v6 |= !v6s.is_empty();
                    for ip in &v4 { if let Some(net) = v4_24(ip) { nets.insert(net); } ips_seen.insert(ip.clone()); }
                    rows.push(json!({ "ns": n, "a": v4, "aaaa": v6s }));
                }
                let data = json!({ "servers": rows });
                out.push(if !cname_ns.is_empty() {
                    check("ns", "Name servers", "fail", 2, format!("NS target(s) are CNAMEs, which the DNS specification forbids: {}.", cname_ns.join(", ")), data)
                } else if !unresolved.is_empty() {
                    check("ns", "Name servers", "fail", 2, format!("Name server(s) with no address: {}.", unresolved.join(", ")), data)
                } else if ns.len() < 2 {
                    check("ns", "Name servers", "warn", 2, "Only one name server: RFC 2182 recommends at least two.", data)
                } else {
                    check("ns", "Name servers", "pass", 2, format!("{} name servers, all with addresses.", ns.len()), data)
                });
                if ns.len() >= 2 && ips_seen.len() >= 1 {
                    out.push(if nets.len() >= 2 { check("ns_diversity", "Name server diversity", "pass", 1, format!("IPv4 name servers span {} different /24 networks.", nets.len()), Value::Null) }
                        else { check("ns_diversity", "Name server diversity", "warn", 1, "All IPv4 name servers sit in one /24 network: one outage can take them all down.", Value::Null) });
                }
                out.push(check("ns_ipv6", "Name servers over IPv6", if v6 { "pass" } else { "info" }, 0, if v6 { "At least one name server has an AAAA record." } else { "No name server has an AAAA record." }, Value::Null));
            }
        }
    }
    match doh(app, domain, "SOA", false) {
        Err(e) => out.push(unknown("soa", "SOA record", &e)),
        Ok(d) => match of_type(&d, "SOA").first() {
            None => out.push(check("soa", "SOA record", "warn", 1, "No SOA record at this name (it may be a subdomain inside a parent zone).", Value::Null)),
            Some(r) => {
                let p: Vec<&str> = r.data.split_whitespace().collect();
                let n = |i: usize| p.get(i).and_then(|x| x.parse::<u64>().ok());
                out.push(check("soa", "SOA record", "pass", 1, "Present.", json!({ "primary": p.first(), "admin_mailbox": p.get(1).map(|m| format!("(mailbox)@{}", m.split_once('.').map(|x| x.1).unwrap_or("").trim_end_matches('.'))), "serial": n(2), "refresh": n(3), "retry": n(4), "expire": n(5), "minimum_ttl": n(6) })));
            }
        },
    }
    out.push(wildcard_check(app, domain));
    out.push(caa_check(app, domain));
    out
}

fn wildcard_check(app: &App, domain: &str) -> Value {
    let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(1);
    let mut hits = Vec::new();
    for i in 0..2u32 {
        let probe = format!("osnt-wc-{:08x}.{domain}", seed.wrapping_mul(2654435761).wrapping_add(i * 7919));
        // A fresh name every time: query the resolver directly so the answer cannot come from the cache.
        let url = format!("{}/resolve?name={probe}&type=A", app.up.dns);
        match app.http.json(Req::new(&url).accept("application/dns-json").gap(40)) {
            Ok(v) => hits.extend(of_type(&parse_dns(&v), "A").into_iter().map(|r| r.data)),
            Err(e) => return unknown("wildcard", "Wildcard DNS", &e),
        }
    }
    if hits.is_empty() {
        check("wildcard", "Wildcard DNS", "info", 0, "No wildcard: random names under the domain do not resolve.", Value::Null)
    } else {
        hits.sort();
        hits.dedup();
        check("wildcard", "Wildcard DNS", "info", 0, "Wildcard record: random, non-existent names resolve, so \"this name exists\" tells you nothing.", json!({ "answers": hits }))
    }
}

fn caa_check(app: &App, domain: &str) -> Value {
    match doh(app, domain, "CAA", false) {
        Err(e) => unknown("caa", "CAA records", &e),
        Ok(d) => {
            let caa = of_type(&d, "CAA");
            if caa.is_empty() {
                return check("caa", "CAA records", "warn", 1, "No CAA record at the apex: any certificate authority may issue for this domain (a parent zone's CAA may still apply).", Value::Null);
            }
            let mut issuers = Vec::new();
            let mut iodef = Vec::new();
            for r in &caa {
                let p: Vec<&str> = r.data.splitn(3, ' ').collect();
                let val = p.get(2).map(|v| v.trim_matches('"').to_string()).unwrap_or_default();
                match p.get(1).map(|t| t.to_ascii_lowercase()).as_deref() {
                    Some("issue") | Some("issuewild") => issuers.push(format!("{}: {}", p[1], if val.is_empty() || val == ";" { "(none allowed)".to_string() } else { val })),
                    Some("iodef") => iodef.push(mask_contact(&val)),
                    _ => {}
                }
            }
            check("caa", "CAA records", "pass", 1, format!("{} CAA record(s) restrict which CAs may issue.", caa.len()), json!({ "issuers": issuers, "iodef": iodef }))
        }
    }
}

// ---- security.txt, robots, sitemap -----------------------------------------------------------------------------

pub fn parse_security_txt(body: &str) -> Value {
    let signed = body.trim_start().starts_with("-----BEGIN PGP SIGNED MESSAGE-----");
    let mut contacts = Vec::new();
    let mut f = serde_json::Map::new();
    for l in body.lines().map(str::trim).filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let Some((k, v)) = l.split_once(':') else { continue };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_string());
        match k.as_str() {
            "contact" => if contacts.len() < 10 { contacts.push(mask_contact(&v)); },
            "expires" | "preferred-languages" | "canary" => { f.insert(k, json!(v)); }
            "policy" | "encryption" | "acknowledgments" | "hiring" | "csaf" => { f.entry(k).or_insert_with(|| json!([])).as_array_mut().map(|a| if a.len() < 5 { a.push(json!(v)) }); }
            _ => {}
        }
    }
    f.insert("contacts".into(), json!(contacts));
    f.insert("signed".into(), json!(signed));
    Value::Object(f)
}

fn expired(expires: &str, now: i64) -> Option<bool> {
    parse_rfc3339(expires).map(|t| t < now)
}

fn parse_rfc3339(s: &str) -> Option<i64> {
    let date = s.get(..10)?;
    let mut p = date.split('-');
    let (y, m, d): (i64, i64, i64) = (p.next()?.parse().ok()?, p.next()?.parse().ok()?, p.next()?.parse().ok()?);
    let (y2, m2) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * m2 + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let secs = s.get(11..19).and_then(|t| { let mut q = t.split(':'); Some(q.next()?.parse::<i64>().ok()? * 3600 + q.next()?.parse::<i64>().ok()? * 60 + q.next()?.parse::<i64>().ok()?) }).unwrap_or(0);
    Some(days * 86400 + secs)
}

pub fn web(app: &App, domain: &str, now: i64) -> Vec<Value> {
    let mut out = Vec::new();
    let mut sec = None;
    for path in ["/.well-known/security.txt", "/security.txt"] {
        match web_fetch(app, domain, path) {
            Ok(f) if f.status == 200 && !f.body.is_empty() && !f.content_type.to_ascii_lowercase().contains("html") => { sec = Some((path, f)); break; }
            _ => {}
        }
    }
    out.push(match sec {
        None => check("security_txt", "security.txt", "warn", 1, "No security.txt found at /.well-known/security.txt: researchers have no published way to report a vulnerability (RFC 9116).", Value::Null),
        Some((path, f)) => {
            let body = String::from_utf8_lossy(&f.body).to_string();
            let mut d = parse_security_txt(&body);
            d["path"] = json!(path);
            let has_contact = d["contacts"].as_array().is_some_and(|c| !c.is_empty());
            let exp = d["expires"].as_str().map(|e| expired(e, now));
            if !has_contact {
                check("security_txt", "security.txt", "fail", 1, "The file has no Contact field, which RFC 9116 requires.", d)
            } else if exp.is_none() || exp == Some(None) {
                check("security_txt", "security.txt", "warn", 1, "Found, but the Expires field is missing or unreadable (RFC 9116 requires it).", d)
            } else if exp == Some(Some(true)) {
                check("security_txt", "security.txt", "warn", 1, "Found, but it has expired: the contact details may be stale.", d)
            } else if path == "/security.txt" {
                check("security_txt", "security.txt", "warn", 1, "Valid, but served only at the legacy /security.txt path; /.well-known/security.txt is preferred.", d)
            } else {
                check("security_txt", "security.txt", "pass", 1, "Valid security.txt with a contact and a future expiry.", d)
            }
        }
    });
    match web_fetch(app, domain, "/robots.txt") {
        Ok(f) if f.status == 200 && !f.content_type.to_ascii_lowercase().contains("html") => {
            let body = String::from_utf8_lossy(&f.body);
            let mut sitemaps = Vec::new();
            let (mut dis, mut allow) = (0, 0);
            for l in body.lines().map(str::trim) {
                let low = l.to_ascii_lowercase();
                if let Some(v) = low.strip_prefix("sitemap:") { let _ = v; if let Some((_, u)) = l.split_once(':') { if sitemaps.len() < 10 { sitemaps.push(u.trim().to_string()); } } }
                else if low.starts_with("disallow:") && !low.trim_end().ends_with(':') { dis += 1; }
                else if low.starts_with("allow:") { allow += 1; }
            }
            out.push(check("robots", "robots.txt and sitemaps", "info", 0, format!("robots.txt found with {dis} Disallow and {allow} Allow rules, {} sitemap URL(s).", sitemaps.len()), json!({ "disallow_rules": dis, "allow_rules": allow, "sitemaps": sitemaps, "truncated": f.truncated })));
        }
        Ok(f) => out.push(check("robots", "robots.txt and sitemaps", "info", 0, format!("No robots.txt (HTTP {}).", f.status), Value::Null)),
        Err(e) => out.push(check("robots", "robots.txt and sitemaps", "unknown", 0, format!("Could not fetch robots.txt: {e}"), Value::Null)),
    }
    out
}

pub fn run_all(app: &App, domain: &str) -> Value {
    let now = crate::cache::now_secs() as i64;
    let (m, d, h, w) = std::thread::scope(|s| {
        let a = s.spawn(|| mail(app, domain));
        let b = s.spawn(|| dnssec(app, domain));
        let c = s.spawn(|| dns_health(app, domain));
        let e = s.spawn(|| web(app, domain, now));
        (a.join().unwrap(), b.join().unwrap(), c.join().unwrap(), e.join().unwrap())
    });
    let groups = [("mail", "Mail policy", m), ("dnssec", "DNSSEC", d), ("dns", "DNS health", h), ("web", "Web policy files", w)];
    let all: Vec<Value> = groups.iter().flat_map(|g| g.2.clone()).collect();
    json!({ "domain": domain, "summary": score(&all), "groups": groups.iter().map(|g| json!({ "id": g.0, "title": g.1, "checks": g.2 })).collect::<Vec<_>>() })
}

pub fn records(app: &App, name: &str, types: &[String]) -> Result<Value> {
    let mut out = serde_json::Map::new();
    let mut ad = false;
    for t in types {
        let d = doh(app, name, t, matches!(t.as_str(), "DS" | "DNSKEY"))?;
        ad |= d.ad;
        out.insert(
            t.clone(),
            json!({ "status": match d.status { 0 => "NOERROR", 2 => "SERVFAIL", 3 => "NXDOMAIN", 5 => "REFUSED", _ => "OTHER" },
                "answers": d.recs.iter().filter(|r| r.ty == type_code(t) || r.ty == 5).map(|r| json!({ "name": r.name, "type": r.ty, "ttl": r.ttl, "data": if t == "TXT" { txt_value(&r.data) } else { r.data.clone() } })).collect::<Vec<_>>() }),
        );
    }
    Ok(json!({ "name": name, "ad": ad, "records": out }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{net::fake, ssrf::testutil};
    use std::{collections::HashMap, sync::Arc};

    #[test]
    fn txt_chunks_and_masking() {
        assert_eq!(txt_value("\"v=spf1 \" \"-all\""), "v=spf1 -all");
        assert_eq!(txt_value("v=DMARC1; p=none"), "v=DMARC1; p=none");
        assert_eq!(txt_value(r#""a\"b""#), "a\"b");
        assert_eq!(mask_contact("mailto:jane.doe@example.com"), "mailto:(mailbox)@example.com");
        assert_eq!(mask_contact("jane@example.com"), "(mailbox)@example.com");
        assert_eq!(mask_contact("https://example.com/report"), "https://example.com/report");
        assert_eq!(mask_contact("https://example.com/r?u=a@b.c"), "https://example.com/r?u=a@b.c");
        assert_eq!(mask_contact("tel:+15551234"), "tel:(number hidden)");
        assert_eq!(mask_record("v=DMARC1; p=reject; rua=mailto:a@x.com,mailto:b@y.org; fo=1"), "v=DMARC1; p=reject; rua=mailto:(mailbox)@x.com,mailto:(mailbox)@y.org; fo=1");
    }

    #[test]
    fn scoring() {
        let c = |s: &str, w: u32| check("x", "x", s, w, "", Value::Null);
        let s = score(&[c("pass", 2), c("warn", 2), c("fail", 1), c("info", 5), c("unknown", 3)]);
        assert_eq!(s["score"], 60);
        assert_eq!((s["pass"].as_u64(), s["warn"].as_u64(), s["fail"].as_u64()), (Some(1), Some(1), Some(1)));
        assert!(score(&[c("info", 0)])["score"].is_null());
    }

    #[test]
    fn security_txt_parsing_masks_contacts() {
        let d = parse_security_txt("# c\nContact: mailto:sec@example.com\nContact: https://example.com/report\nExpires: 2030-01-01T00:00:00Z\nPolicy: https://example.com/p\nEncryption: https://example.com/k.asc\n");
        assert_eq!(d["contacts"], json!(["mailto:(mailbox)@example.com", "https://example.com/report"]));
        assert_eq!(d["policy"][0], "https://example.com/p");
        assert_eq!(d["signed"], false);
        assert_eq!(parse_security_txt("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nContact: x\n")["signed"], true);
        assert_eq!(parse_rfc3339("2026-11-03T00:00:00Z"), Some(1_793_664_000));
        assert_eq!(expired("2020-01-01T00:00:00Z", 1_793_664_000), Some(true));
        assert_eq!(expired("nonsense", 0), None);
    }

    #[test]
    fn key_size_estimates() {
        assert_eq!(rsa_bits(&"A".repeat(216)), Some(1024));
        assert_eq!(rsa_bits(&"A".repeat(392)), Some(2048));
        assert_eq!(rsa_bits(""), None);
    }

    type Table = HashMap<(String, String), String>;

    fn dns_world(table: Table) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
        fake::spawn(Arc::new(move |p: &str| {
            let name = p.split("name=").nth(1).unwrap_or("").split('&').next().unwrap_or("").to_string();
            let ty = p.split("type=").nth(1).unwrap_or("").split('&').next().unwrap_or("").to_string();
            let body = if name.starts_with("osnt-wc-") { table.get(&("*".into(), ty.clone())).cloned() } else { table.get(&(name, ty)).cloned() };
            (200, "application/json".into(), body.unwrap_or_else(|| r#"{"Status":3}"#.into()))
        }))
    }
    fn ans(ty: u64, data: &[&str], ad: bool) -> String {
        json!({ "Status": 0, "AD": ad, "Answer": data.iter().map(|d| json!({ "name": "x.", "type": ty, "TTL": 60, "data": d })).collect::<Vec<_>>() }).to_string()
    }
    fn t(name: &str, ty: &str, body: String) -> ((String, String), String) {
        ((name.to_string(), ty.to_string()), body)
    }

    fn app(dns: &str, web_base: Option<String>) -> App {
        App {
            http: Http::new("osnt-test/0.1"),
            web: crate::ssrf::guarded_agent(Guard { exempt_loopback_port: web_base.as_deref().and_then(|b| b.rsplit(':').next()).and_then(|p| p.parse().ok()) }, "osnt-test/0.1"),
            guard: Guard { exempt_loopback_port: web_base.as_deref().and_then(|b| b.rsplit(':').next()).and_then(|p| p.parse().ok()) },
            cache: Cache::open(None, 500, 1 << 20),
            up: Up { dns: dns.to_string(), web_base },
        }
    }

    #[test]
    fn spf_tree_counts_lookups_and_finds_all() {
        let mut m = Table::new();
        m.extend([
            t("e.com", "TXT", ans(16, &["v=spf1 include:_spf.a.com include:b.com a mx ip4:1.2.3.4 ~all"], false)),
            t("_spf.a.com", "TXT", ans(16, &["v=spf1 include:c.com ip4:5.6.7.8 -all"], false)),
            t("c.com", "TXT", ans(16, &["v=spf1 ptr -all"], false)),
            t("b.com", "TXT", ans(16, &["v=spf1 redirect=e.com"], false)),
        ]);
        let (base, _) = dns_world(m);
        let a = app(&base, None);
        let c = spf_checks(&a, "e.com");
        let by = |id: &str| c.iter().find(|x| x["id"] == id).unwrap();
        assert_eq!(by("spf")["status"], "pass");
        // include a, include b, a, mx = 4 at top; _spf.a.com: include c = 1; c.com: ptr = 1; b.com: redirect = 1 (loop back to e.com is not re-expanded)
        assert_eq!(by("spf_lookups")["data"]["lookups"], 7);
        assert_eq!(by("spf_all")["status"], "warn", "top-level ~all");
        assert_eq!(by("spf_ptr")["status"], "warn");
        let loop_found = by("spf")["data"]["tree"].to_string().contains("already seen");
        assert!(loop_found);
    }

    #[test]
    fn spf_failures() {
        let mut m = Table::new();
        let includes: String = (0..11).map(|i| format!("include:i{i}.com ")).collect();
        m.extend([
            t("many.com", "TXT", ans(16, &[&format!("v=spf1 {includes}-all")], false)),
            t("two.com", "TXT", ans(16, &["v=spf1 -all", "v=spf1 +all"], false)),
            t("open.com", "TXT", ans(16, &["v=spf1 +all"], false)),
            t("none.com", "TXT", ans(16, &["hello"], false)),
        ]);
        let (base, _) = dns_world(m);
        let a = app(&base, None);
        assert_eq!(spf_checks(&a, "many.com").iter().find(|x| x["id"] == "spf_lookups").unwrap()["status"], "fail");
        assert_eq!(spf_checks(&a, "two.com")[0]["status"], "fail");
        assert_eq!(spf_checks(&a, "open.com").iter().find(|x| x["id"] == "spf_all").unwrap()["status"], "fail");
        assert_eq!(spf_checks(&a, "none.com")[0]["summary"].as_str().unwrap().contains("No SPF"), true);
    }

    #[test]
    fn dmarc_levels_and_masking() {
        let mut m = Table::new();
        m.extend([
            t("_dmarc.good.com", "TXT", ans(16, &["v=DMARC1; p=reject; rua=mailto:jane@good.com; pct=50"], false)),
            t("_dmarc.weak.com", "TXT", ans(16, &["v=DMARC1; p=none"], false)),
            t("_dmarc.bad.com", "TXT", ans(16, &["v=DMARC1; rua=mailto:x@bad.com"], false)),
        ]);
        let (base, _) = dns_world(m);
        let a = app(&base, None);
        let g = dmarc_checks(&a, "good.com");
        assert_eq!(g[0]["status"], "pass");
        assert!(g.iter().any(|c| c["id"] == "dmarc_pct" && c["status"] == "warn"));
        assert!(!serde_json::to_string(&g).unwrap().contains("jane"), "mailbox names are masked");
        assert_eq!(dmarc_checks(&a, "weak.com")[0]["status"], "warn");
        assert_eq!(dmarc_checks(&a, "bad.com")[0]["status"], "fail");
        assert_eq!(dmarc_checks(&a, "missing.com")[0]["status"], "fail");
    }

    #[test]
    fn dkim_probe_reads_key_strength() {
        let mut m = Table::new();
        m.insert(("google._domainkey.k.com".into(), "TXT".into()), ans(16, &[&format!("v=DKIM1; k=rsa; p={}", "A".repeat(216))], false));
        m.insert(("selector1._domainkey.k.com".into(), "TXT".into()), ans(16, &[&format!("v=DKIM1; k=rsa; p={}", "A".repeat(392))], false));
        m.insert(("s1._domainkey.r.com".into(), "TXT".into()), ans(16, &["v=DKIM1; p="], false));
        let (base, log) = dns_world(m);
        let a = app(&base, None);
        let c = dkim_check(&a, "k.com");
        assert_eq!(c["status"], "warn", "1024-bit key flagged");
        assert_eq!(c["data"]["found"].as_array().unwrap().len(), 2);
        assert_eq!(log.lock().unwrap().iter().filter(|p| p.contains("_domainkey")).count(), SELECTORS.len(), "only the fixed selector list is probed");
        assert_eq!(dkim_check(&a, "r.com")["data"]["found"][0]["revoked"], true);
        assert_eq!(dkim_check(&a, "none.com")["status"], "warn");
    }

    #[test]
    fn dnssec_states() {
        let mut m = Table::new();
        m.extend([
            t("ok.com", "DS", ans(43, &["2371 13 2 ABCD"], true)),
            t("ok.com", "DNSKEY", ans(48, &["257 3 13 AAAA", "256 3 13 BBBB"], true)),
            t("ok.com", "SOA", ans(6, &["ns. h. 1 2 3 4 5"], true)),
            t("half.com", "DNSKEY", ans(48, &["257 3 8 AAAA"], false)),
            t("broken.com", "DS", ans(43, &["1 5 2 AB"], false)),
            t("broken.com", "DNSKEY", ans(48, &["257 3 5 AAAA"], false)),
        ]);
        let (base, _) = dns_world(m);
        let a = app(&base, None);
        let ok = dnssec(&a, "ok.com");
        assert_eq!(ok[0]["status"], "pass");
        assert_eq!(ok[0]["data"]["dnskey"][0]["role"], "KSK");
        assert_eq!(dnssec(&a, "half.com")[0]["status"], "warn");
        let b = dnssec(&a, "broken.com");
        assert_eq!(b[0]["status"], "fail");
        assert!(b.iter().any(|c| c["id"] == "dnssec_alg"));
        assert_eq!(dnssec(&a, "unsigned.com")[0]["status"], "warn");
    }

    #[test]
    fn dns_health_flags_cname_ns_wildcard_and_caa() {
        let mut m = Table::new();
        m.extend([
            t("h.com", "NS", ans(2, &["ns1.h.com.", "ns2.h.com."], false)),
            t("ns1.h.com", "A", ans(1, &["198.51.100.1"], false)),
            t("ns2.h.com", "A", ans(1, &["198.51.100.2"], false)),
            t("h.com", "SOA", ans(6, &["ns1.h.com. hostmaster.h.com. 5 10 20 30 40"], false)),
            t("h.com", "CAA", ans(257, &["0 issue \"letsencrypt.org\"", "0 iodef \"mailto:sec@h.com\""], false)),
            (("*".into(), "A".into()), ans(1, &["203.0.113.9"], false)),
            t("c.com", "NS", ans(2, &["ns.c.com.", "ns2.other.net."], false)),
            t("ns.c.com", "A", json!({"Status":0,"Answer":[{"name":"ns.c.com.","type":5,"TTL":1,"data":"x.y."}]}).to_string()),
        ]);
        let (base, _) = dns_world(m);
        let a = app(&base, None);
        let h = dns_health(&a, "h.com");
        let by = |id: &str| h.iter().find(|x| x["id"] == id).unwrap_or_else(|| panic!("{id}")).clone();
        assert_eq!(by("ns")["status"], "pass");
        assert_eq!(by("ns_diversity")["status"], "warn", "same /24");
        assert_eq!(by("soa")["data"]["admin_mailbox"], "(mailbox)@h.com");
        assert!(!by("soa").to_string().contains("hostmaster@"));
        assert_eq!(by("caa")["status"], "pass");
        assert_eq!(by("caa")["data"]["iodef"][0], "mailto:(mailbox)@h.com");
        assert!(by("wildcard")["summary"].as_str().unwrap().starts_with("Wildcard record"));
        let c = dns_health(&a, "c.com");
        assert_eq!(c.iter().find(|x| x["id"] == "ns").unwrap()["status"], "fail");
        let none = dns_health(&a, "nothing.com");
        assert_eq!(none.iter().find(|x| x["id"] == "ns").unwrap()["status"], "fail");
        assert_eq!(none.iter().find(|x| x["id"] == "caa").unwrap()["status"], "warn");
    }

    #[test]
    fn web_files_through_guarded_fetch() {
        let port = testutil::spawn(Arc::new(|r: &testutil::Req| match r.path.as_str() {
            "/good.com/.well-known/security.txt" => testutil::Resp { status: 200, headers: vec![("Content-Type".into(), "text/plain".into())], body: b"Contact: mailto:psirt@good.com\nExpires: 2099-01-01T00:00:00Z\n".to_vec() },
            "/old.com/.well-known/security.txt" => testutil::Resp { status: 200, headers: vec![("Content-Type".into(), "text/plain".into())], body: b"Contact: https://old.com/r\nExpires: 2001-01-01T00:00:00Z\n".to_vec() },
            "/nocontact.com/.well-known/security.txt" => testutil::Resp { status: 200, headers: vec![("Content-Type".into(), "text/plain".into())], body: b"Expires: 2099-01-01T00:00:00Z\n".to_vec() },
            "/html.com/.well-known/security.txt" => testutil::Resp::html("<html>soft 404</html>"),
            "/good.com/robots.txt" => testutil::Resp { status: 200, headers: vec![("Content-Type".into(), "text/plain".into())], body: b"User-agent: *\nDisallow: /a\nDisallow:\nAllow: /b\nSitemap: https://good.com/sitemap.xml\n".to_vec() },
            _ => testutil::Resp { status: 404, headers: vec![], body: b"nf".to_vec() },
        }));
        let (dns, _) = dns_world(Table::new());
        let a = app(&dns, Some(format!("http://127.0.0.1:{port}")));
        let now = 1_793_664_000;
        let g = web(&a, "good.com", now);
        assert_eq!(g[0]["status"], "pass");
        assert!(!g[0].to_string().contains("psirt@"));
        assert_eq!(g[1]["data"]["sitemaps"][0], "https://good.com/sitemap.xml");
        assert_eq!(g[1]["data"]["disallow_rules"], 1);
        assert_eq!(web(&a, "old.com", now)[0]["status"], "warn");
        assert_eq!(web(&a, "nocontact.com", now)[0]["status"], "fail");
        assert_eq!(web(&a, "html.com", now)[0]["summary"].as_str().unwrap().starts_with("No security.txt"), true, "HTML soft-404 is not a security.txt");
    }

    #[test]
    fn web_fetch_refuses_private_targets() {
        let (dns, _) = dns_world(Table::new());
        let a = app(&dns, None);
        // localhost resolves to a loopback address, which the guard must refuse before any request is made.
        let r = web_fetch(&a, "localhost", "/.well-known/security.txt");
        assert!(r.is_err(), "{:?}", r.map(|f| f.status));
    }

    #[test]
    fn mta_sts_policy_modes() {
        let port = testutil::spawn(Arc::new(|r: &testutil::Req| match r.path.as_str() {
            "/mta-sts.s.com/.well-known/mta-sts.txt" => testutil::Resp { status: 200, headers: vec![("Content-Type".into(), "text/plain".into())], body: b"version: STSv1\nmode: enforce\nmx: mail.s.com\nmax_age: 604800\n".to_vec() },
            _ => testutil::Resp { status: 404, headers: vec![], body: vec![] },
        }));
        let mut m = Table::new();
        m.extend([t("_mta-sts.s.com", "TXT", ans(16, &["v=STSv1; id=1"], false)), t("_mta-sts.t.com", "TXT", ans(16, &["v=STSv1; id=1"], false))]);
        let (dns, _) = dns_world(m);
        let a = app(&dns, Some(format!("http://127.0.0.1:{port}")));
        assert_eq!(mta_sts_checks(&a, "s.com")[0]["status"], "pass");
        assert_eq!(mta_sts_checks(&a, "t.com")[0]["status"], "fail", "record without a policy file");
        assert_eq!(mta_sts_checks(&a, "u.com")[0]["status"], "info");
    }

    #[test]
    fn records_endpoint_and_dead_upstream() {
        let mut m = Table::new();
        m.insert(("r.com".into(), "TXT".into()), ans(16, &["\"hello\" \"world\""], false));
        let (base, _) = dns_world(m);
        let a = app(&base, None);
        let r = records(&a, "r.com", &["TXT".into(), "A".into()]).unwrap();
        assert_eq!(r["records"]["TXT"]["answers"][0]["data"], "helloworld");
        assert_eq!(r["records"]["A"]["status"], "NXDOMAIN");
        let dead = app("http://127.0.0.1:1", None);
        assert!(records(&dead, "r.com", &["A".into()]).is_err());
        let all = run_all(&dead, "r.com");
        assert!(all["groups"].as_array().unwrap().iter().all(|g| !g["checks"].as_array().unwrap().is_empty()));
        assert!(all["summary"]["score"].is_null() || all["summary"]["score"].is_number());
    }
}

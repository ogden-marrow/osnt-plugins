//! Scan jobs: one background worker per job, polite spacing between InternetDB requests, per-address cache.

use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}},
    time::{Duration, Instant},
};

use serde::Serialize;
use serde_json::{Value, json};

use crate::{AppState, common::*, net::{Net, bits_ip}};

#[derive(Clone, Serialize, Debug, PartialEq)]
pub struct Cell {
    pub ip: String,
    pub ports: Vec<u64>,
    pub vulns: Vec<String>,
    pub tags: Vec<String>,
    pub hostnames: Vec<String>,
    pub cpes: Vec<String>,
}

#[derive(Clone, PartialEq, Debug)]
enum Slot {
    Pending,
    None,
    Data(Cell),
    Failed,
}

struct Job {
    id: String,
    cidr: String,
    net: Net,
    slots: Vec<Slot>,
    state: &'static str,
    error: Option<String>,
    cached: usize,
    cancel: Arc<AtomicBool>,
    created: Instant,
}

#[derive(Default)]
pub struct Jobs {
    list: Mutex<Vec<Job>>,
    counter: Mutex<u64>,
}

const MAX_JOBS: usize = 8;

/// Parse and vet the block: IPv4, public, and no larger than the configured limit.
pub fn parse_block(s: &str, min_prefix: u8) -> Result<Net, String> {
    let t = s.trim();
    if t.contains(':') {
        return Err("only IPv4 blocks are supported".into());
    }
    let n = Net::parse(t).ok_or("enter a block such as 203.0.113.0/24")?;
    if n.prefix < min_prefix {
        return Err(format!("that block is too large: the limit is /{min_prefix} ({} addresses)", 1u64 << (32 - min_prefix)));
    }
    if !ip_is_public(n.first()) || !ip_is_public(n.last()) {
        return Err("that block includes private or reserved addresses, which have no public data".into());
    }
    Ok(n)
}

fn tidy<T: Ord>(mut v: Vec<T>) -> Vec<T> {
    v.sort();
    v.dedup();
    v
}

fn strings(v: &Value, key: &str, cap: usize) -> Vec<String> {
    tidy(v[key].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.chars().take(100).collect())).take(cap).collect()).unwrap_or_default())
}

fn fetch_cell(s: &AppState, ip: IpAddr) -> Result<Option<Cell>, UpErr> {
    match get_json(&s.agent, &format!("{}/{ip}", s.base), &[("Accept", "application/json")]) {
        Err(UpErr::NotFound) => Ok(None),
        Err(e) => Err(e),
        Ok(v) => Ok(Some(Cell {
            ip: ip.to_string(),
            ports: tidy(v["ports"].as_array().map(|a| a.iter().filter_map(Value::as_u64).take(200).collect()).unwrap_or_default()),
            vulns: strings(&v, "vulns", 100),
            tags: strings(&v, "tags", 20),
            hostnames: strings(&v, "hostnames", 20),
            cpes: strings(&v, "cpes", 50),
        })),
    }
}

/// Start a scan, or join an unfinished scan of the same block. Only one scan runs at a time.
pub fn start(s: &Arc<AppState>, net: Net) -> Result<Value, String> {
    let cidr = net.to_string();
    let mut list = s.jobs.list.lock().unwrap_or_else(|e| e.into_inner());
    list.retain(|j| j.state == "running" || j.created.elapsed() < Duration::from_secs(3600));
    if let Some(j) = list.iter().find(|j| j.state == "running") {
        if j.cidr == cidr {
            return Ok(json!({ "id": j.id, "cidr": cidr, "joined": true }));
        }
        return Err(format!("another scan ({}) is still running; wait for it or cancel it", j.cidr));
    }
    while list.len() >= MAX_JOBS {
        list.remove(0);
    }
    let id = {
        let mut c = s.jobs.counter.lock().unwrap_or_else(|e| e.into_inner());
        *c += 1;
        format!("{:x}{:04x}", unix_now(), *c)
    };
    let total = net.size() as usize;
    let cancel = Arc::new(AtomicBool::new(false));
    list.push(Job { id: id.clone(), cidr: cidr.clone(), net, slots: vec![Slot::Pending; total], state: "running", error: None, cached: 0, cancel: cancel.clone(), created: Instant::now() });
    drop(list);
    let (s2, id2) = (s.clone(), id.clone());
    std::thread::spawn(move || worker(&s2, &id2, net, &cancel));
    Ok(json!({ "id": id, "cidr": cidr, "joined": false, "total": total }))
}

fn with_job<R>(s: &AppState, id: &str, f: impl FnOnce(&mut Job) -> R) -> Option<R> {
    let mut list = s.jobs.list.lock().unwrap_or_else(|e| e.into_inner());
    list.iter_mut().find(|j| j.id == id).map(f)
}

fn worker(s: &AppState, id: &str, net: Net, cancel: &AtomicBool) {
    let total = net.size() as usize;
    let mut consecutive_errors = 0;
    let mut finish = "done";
    let mut error = None;
    for i in 0..total {
        if cancel.load(Ordering::SeqCst) {
            finish = "cancelled";
            break;
        }
        let ip = bits_ip(false, net.base + i as u128);
        let key = ip.to_string();
        let (slot, was_cached) = if let Some(c) = s.cache.get(&key) {
            (c.map_or(Slot::None, Slot::Data), true)
        } else {
            let r = fetch_cell(s, ip);
            std::thread::sleep(s.delay);
            match r {
                Ok(c) => {
                    consecutive_errors = 0;
                    s.cache.put(&key, c.clone());
                    (c.map_or(Slot::None, Slot::Data), false)
                }
                Err(UpErr::Denied(429)) => {
                    finish = "stopped";
                    error = Some("InternetDB rate-limited this scan. The addresses already checked are cached; run it again later to continue.".to_string());
                    break;
                }
                Err(e) => {
                    consecutive_errors += 1;
                    if consecutive_errors >= 5 {
                        finish = "stopped";
                        error = Some(format!("InternetDB keeps failing ({e}); stopped after 5 errors in a row"));
                        break;
                    }
                    (Slot::Failed, false)
                }
            }
        };
        with_job(s, id, |j| {
            j.slots[i] = slot;
            if was_cached {
                j.cached += 1;
            }
        });
    }
    with_job(s, id, |j| {
        j.state = finish;
        j.error = error;
    });
}

pub fn cancel(s: &AppState, id: &str) -> Option<Value> {
    with_job(s, id, |j| {
        j.cancel.store(true, Ordering::SeqCst);
        json!({ "id": j.id, "cancelling": j.state == "running" })
    })
}

fn product(cpe: &str) -> String {
    // InternetDB uses the 2.2 form: cpe:/a:vendor:product:version
    let parts: Vec<&str> = cpe.trim_start_matches("cpe:/").trim_start_matches("cpe:2.3:").split(':').collect();
    if parts.len() >= 3 {
        let ver = parts.get(3).filter(|v| !v.is_empty() && **v != "*").map(|v| format!(" {v}")).unwrap_or_default();
        let (vendor, prod) = (parts[1].replace('_', " "), parts[2].replace('_', " "));
        // "cloudflare cloudflare" reads like a bug: when vendor and product are the same, say it once.
        if vendor == prod { format!("{vendor}{ver}") } else { format!("{vendor} {prod}{ver}") }
    } else {
        cpe.to_string()
    }
}

fn top(map: BTreeMap<String, usize>, n: usize) -> Vec<Value> {
    let mut v: Vec<_> = map.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.into_iter().take(n).map(|(k, c)| json!({ "name": k, "hosts": c })).collect()
}

pub fn snapshot(s: &AppState, id: &str) -> Option<Value> {
    with_job(s, id, |j| {
        let total = j.slots.len();
        let done = j.slots.iter().filter(|x| **x != Slot::Pending).count();
        let failed = j.slots.iter().filter(|x| **x == Slot::Failed).count();
        let (mut ports, mut products, mut cves, mut tags) = (BTreeMap::new(), BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
        let (mut hosts, mut vulnerable, mut named) = (0, 0, 0);
        let mut cells = vec![];
        for (i, sl) in j.slots.iter().enumerate() {
            let Slot::Data(c) = sl else { continue };
            hosts += 1;
            if !c.vulns.is_empty() {
                vulnerable += 1;
            }
            if !c.hostnames.is_empty() {
                named += 1;
            }
            for p in &c.ports {
                *ports.entry(p.to_string()).or_insert(0) += 1;
            }
            for p in tidy(c.cpes.iter().map(|x| product(x)).collect()) {
                *products.entry(p).or_insert(0) += 1;
            }
            for v in &c.vulns {
                *cves.entry(v.clone()).or_insert(0) += 1;
            }
            for t in &c.tags {
                *tags.entry(t.clone()).or_insert(0) += 1;
            }
            let risk = if !c.vulns.is_empty() || c.tags.iter().any(|t| matches!(t.as_str(), "compromised" | "malware" | "doublepulsar")) { "high" } else if !c.ports.is_empty() { "open" } else { "seen" };
            cells.push(json!({ "i": i, "ip": c.ip, "ports": c.ports, "vulns": c.vulns, "tags": c.tags, "hostnames": c.hostnames, "cpes": c.cpes, "products": tidy(c.cpes.iter().map(|x| product(x)).collect()), "risk": risk }));
        }
        let uncached = total - done;
        json!({ "id": j.id, "cidr": j.cidr, "state": j.state, "error": j.error, "total": total, "done": done, "failed": failed, "from_cache": j.cached,
                "remaining_estimate_secs": ((uncached as f64) * (s.delay.as_secs_f64() + 0.1)).round() as u64,
                "first": j.net.first().to_string(),
                "summary": { "hosts_with_data": hosts, "vulnerable_hosts": vulnerable, "hosts_with_hostnames": named,
                             "ports": top(ports, 30), "products": top(products, 25), "cves": top(cves, 40), "tags": top(tags, 15) },
                "cells": cells,
                "source": "Shodan InternetDB (https://internetdb.shodan.io/), free for non-commercial use. No packets are sent to the addresses." })
    })
}

fn csv_cell(s: &str) -> String {
    let mut t = s.to_string();
    if t.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        t.insert(0, '\'');
    }
    if t.contains([',', '"', '\n', '\r']) {
        t = format!("\"{}\"", t.replace('"', "\"\""));
    }
    t
}

pub fn csv(s: &AppState, id: &str) -> Option<String> {
    with_job(s, id, |j| {
        let mut out = String::from("ip,ports,hostnames,tags,cves,products\n");
        for sl in &j.slots {
            if let Slot::Data(c) = sl {
                let row = [c.ip.clone(), c.ports.iter().map(u64::to_string).collect::<Vec<_>>().join(" "), c.hostnames.join(" "), c.tags.join(" "), c.vulns.join(" "), tidy(c.cpes.iter().map(|x| product(x)).collect()).join("; ")];
                out.push_str(&row.iter().map(|x| csv_cell(x)).collect::<Vec<_>>().join(","));
                out.push('\n');
            }
        }
        out
    })
}

#[cfg(test)]
pub fn product_for_test(c: &str) -> String {
    product(c)
}
#[cfg(test)]
pub fn csv_cell_for_test(c: &str) -> String {
    csv_cell(c)
}

//! redb storage: feeds, items, alert rules and the "last visit" marker.

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::feed::{Parsed, Rule, item_id};

const FEEDS: TableDefinition<u64, &[u8]> = TableDefinition::new("feeds");
const ITEMS: TableDefinition<&str, &[u8]> = TableDefinition::new("items");
const RULES: TableDefinition<u64, &[u8]> = TableDefinition::new("rules");
const KV: TableDefinition<&str, u64> = TableDefinition::new("kv");

pub const MAX_FEEDS: usize = 50;
pub const MAX_RULES: usize = 30;
pub const KEEP_PER_FEED: usize = 150;
pub const KEEP_SECS: i64 = 30 * 86400;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Feed {
    pub id: u64,
    /// "rss", "hn" (Hacker News keyword search) or "telegram" (public channel preview)
    pub kind: String,
    /// feed URL, HN query or channel name
    pub target: String,
    pub title: String,
    pub interval_min: u32,
    pub added: i64,
    pub last_fetch: i64,
    pub last_ok: i64,
    pub fail_count: u32,
    pub last_error: Option<String>,
    pub last_status: Option<u16>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub item_count: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StoredItem {
    pub id: String,
    pub feed: u64,
    pub title: String,
    pub link: String,
    pub summary: String,
    pub published: i64,
    pub fetched: i64,
}

impl StoredItem {
    pub fn when(&self) -> i64 {
        if self.published > 0 { self.published.min(self.fetched.max(1) + 86400) } else { self.fetched }
    }
}

pub struct Store {
    db: Database,
}

type R<T> = anyhow::Result<T>;

fn key(feed: u64, id: &str) -> String {
    format!("{feed:010}|{id}")
}

impl Store {
    pub fn open(path: &str) -> R<Store> {
        let db = Database::create(path)?;
        let tx = db.begin_write()?;
        tx.open_table(FEEDS)?;
        tx.open_table(ITEMS)?;
        tx.open_table(RULES)?;
        tx.open_table(KV)?;
        tx.commit()?;
        Ok(Store { db })
    }

    pub fn feeds(&self) -> R<Vec<Feed>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(FEEDS)?;
        Ok(t.iter()?.filter_map(|r| r.ok()).filter_map(|(_, v)| serde_json::from_slice(v.value()).ok()).collect())
    }
    pub fn feed(&self, id: u64) -> R<Option<Feed>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(FEEDS)?;
        Ok(t.get(id)?.and_then(|v| serde_json::from_slice(v.value()).ok()))
    }
    pub fn put_feed(&self, f: &Feed) -> R<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(FEEDS)?.insert(f.id, serde_json::to_vec(f)?.as_slice())?;
        tx.commit()?;
        Ok(())
    }
    pub fn add_feed(&self, kind: &str, target: &str, title: &str, interval_min: u32, now: i64) -> R<Feed> {
        let tx = self.db.begin_write()?;
        let f;
        {
            let mut t = tx.open_table(FEEDS)?;
            if t.len()? as usize >= MAX_FEEDS {
                anyhow::bail!("at most {MAX_FEEDS} feeds; remove one first");
            }
            if t.iter()?.filter_map(|r| r.ok()).filter_map(|(_, v)| serde_json::from_slice::<Feed>(v.value()).ok()).any(|e| e.kind == kind && e.target.eq_ignore_ascii_case(target)) {
                anyhow::bail!("that feed is already in the list");
            }
            let id = t.last()?.map(|(k, _)| k.value() + 1).unwrap_or(1);
            f = Feed { id, kind: kind.into(), target: target.into(), title: title.into(), interval_min, added: now, last_fetch: 0, last_ok: 0, fail_count: 0, last_error: None, last_status: None, etag: None, last_modified: None, item_count: 0 };
            t.insert(id, serde_json::to_vec(&f)?.as_slice())?;
        }
        tx.commit()?;
        Ok(f)
    }
    pub fn delete_feed(&self, id: u64) -> R<bool> {
        let tx = self.db.begin_write()?;
        let existed = tx.open_table(FEEDS)?.remove(id)?.is_some();
        {
            let mut items = tx.open_table(ITEMS)?;
            let prefix = format!("{id:010}|");
            let keys: Vec<String> = items.range(prefix.as_str()..)?.filter_map(|r| r.ok()).map(|(k, _)| k.value().to_string()).take_while(|k| k.starts_with(&prefix)).collect();
            for k in keys {
                items.remove(k.as_str())?;
            }
        }
        tx.commit()?;
        Ok(existed)
    }

    /// Store items not seen before; returns how many were new. Enforces the per-feed cap afterwards.
    pub fn insert_items(&self, feed: u64, items: &[Parsed], now: i64) -> R<u32> {
        let tx = self.db.begin_write()?;
        let mut new = 0;
        {
            let mut t = tx.open_table(ITEMS)?;
            for p in items {
                let id = item_id(feed, p);
                let k = key(feed, &id);
                if t.get(k.as_str())?.is_some() {
                    continue;
                }
                let it = StoredItem { id, feed, title: p.title.clone(), link: p.link.clone(), summary: p.summary.clone(), published: p.published, fetched: now };
                t.insert(k.as_str(), serde_json::to_vec(&it)?.as_slice())?;
                new += 1;
            }
        }
        tx.commit()?;
        if new > 0 {
            self.prune_feed(feed)?;
        }
        Ok(new)
    }

    fn feed_items(&self, feed: u64) -> R<Vec<StoredItem>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(ITEMS)?;
        let prefix = format!("{feed:010}|");
        Ok(t.range(prefix.as_str()..)?.filter_map(|r| r.ok()).take_while(|(k, _)| k.value().starts_with(&prefix)).filter_map(|(_, v)| serde_json::from_slice(v.value()).ok()).collect())
    }

    fn prune_feed(&self, feed: u64) -> R<()> {
        let mut items = self.feed_items(feed)?;
        if items.len() <= KEEP_PER_FEED {
            return Ok(());
        }
        items.sort_by_key(|i| std::cmp::Reverse(i.when()));
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(ITEMS)?;
            for it in &items[KEEP_PER_FEED..] {
                t.remove(key(feed, &it.id).as_str())?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Startup cleanup: drop items older than 30 days, items of deleted feeds, and over-cap leftovers.
    pub fn cleanup(&self, now: i64) -> R<usize> {
        let feeds: Vec<u64> = self.feeds()?.iter().map(|f| f.id).collect();
        let all = self.all_items()?;
        let tx = self.db.begin_write()?;
        let mut removed = 0;
        {
            let mut t = tx.open_table(ITEMS)?;
            for it in &all {
                if !feeds.contains(&it.feed) || it.when() < now - KEEP_SECS {
                    t.remove(key(it.feed, &it.id).as_str())?;
                    removed += 1;
                }
            }
        }
        tx.commit()?;
        for f in feeds {
            self.prune_feed(f)?;
        }
        Ok(removed)
    }

    pub fn all_items(&self) -> R<Vec<StoredItem>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(ITEMS)?;
        Ok(t.iter()?.filter_map(|r| r.ok()).filter_map(|(_, v)| serde_json::from_slice(v.value()).ok()).collect())
    }
    pub fn count_items(&self, feed: u64) -> R<u32> {
        Ok(self.feed_items(feed)?.len() as u32)
    }

    pub fn rules(&self) -> R<Vec<Rule>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(RULES)?;
        Ok(t.iter()?.filter_map(|r| r.ok()).filter_map(|(_, v)| serde_json::from_slice(v.value()).ok()).collect())
    }
    pub fn add_rule(&self, name: &str, kind: &str, pattern: &str) -> R<Rule> {
        let tx = self.db.begin_write()?;
        let r;
        {
            let mut t = tx.open_table(RULES)?;
            if t.len()? as usize >= MAX_RULES {
                anyhow::bail!("at most {MAX_RULES} alert rules");
            }
            let id = t.last()?.map(|(k, _)| k.value() + 1).unwrap_or(1);
            r = Rule { id, name: name.into(), kind: kind.into(), pattern: pattern.into() };
            t.insert(id, serde_json::to_vec(&r)?.as_slice())?;
        }
        tx.commit()?;
        Ok(r)
    }
    pub fn delete_rule(&self, id: u64) -> R<bool> {
        let tx = self.db.begin_write()?;
        let existed = tx.open_table(RULES)?.remove(id)?.is_some();
        tx.commit()?;
        Ok(existed)
    }

    pub fn last_seen(&self) -> R<i64> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(KV)?;
        Ok(t.get("last_seen")?.map(|v| v.value() as i64).unwrap_or(0))
    }
    pub fn set_last_seen(&self, now: i64) -> R<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(KV)?.insert("last_seen", now as u64)?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> Store {
        let p = std::env::temp_dir().join(format!("rss-{tag}-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&p);
        Store::open(p.to_str().unwrap()).unwrap()
    }
    fn p(n: u32, published: i64) -> Parsed {
        Parsed { title: format!("t{n}"), link: format!("https://x.test/{n}"), summary: String::new(), published, guid: format!("g{n}") }
    }

    #[test]
    fn feeds_dedupe_and_cap() {
        let s = tmp("feeds");
        let f = s.add_feed("rss", "https://a.test/feed", "A", 30, 1).unwrap();
        assert!(s.add_feed("rss", "HTTPS://A.TEST/feed", "A", 30, 1).is_err());
        assert!(s.add_feed("hn", "https://a.test/feed", "A", 30, 1).is_ok(), "same text, different kind");
        for i in 0..MAX_FEEDS {
            let _ = s.add_feed("rss", &format!("https://b.test/{i}"), "B", 30, 1);
        }
        assert_eq!(s.feeds().unwrap().len(), MAX_FEEDS);
        assert!(s.add_feed("rss", "https://zzz.test/", "Z", 30, 1).is_err());
        assert!(s.delete_feed(f.id).unwrap());
        assert!(!s.delete_feed(f.id).unwrap());
    }

    #[test]
    fn items_dedupe_prune_and_cleanup() {
        let s = tmp("items");
        let f = s.add_feed("rss", "https://a.test/feed", "A", 30, 1).unwrap();
        let g = s.add_feed("rss", "https://c.test/feed", "C", 30, 1).unwrap();
        let now = 2_000_000_000;
        let batch: Vec<Parsed> = (0..10).map(|n| p(n, now - n as i64 * 60)).collect();
        assert_eq!(s.insert_items(f.id, &batch, now).unwrap(), 10);
        assert_eq!(s.insert_items(f.id, &batch, now).unwrap(), 0, "same items are not new again");
        assert_eq!(s.insert_items(g.id, &batch[..2], now).unwrap(), 2, "ids are per feed");
        // cap: insert more than KEEP_PER_FEED, newest survive
        let many: Vec<Parsed> = (100..100 + KEEP_PER_FEED as u32 + 20).map(|n| p(n, now + n as i64)).collect();
        s.insert_items(f.id, &many, now).unwrap();
        assert_eq!(s.count_items(f.id).unwrap() as usize, KEEP_PER_FEED);
        assert!(s.all_items().unwrap().iter().filter(|i| i.feed == f.id).all(|i| i.published >= now - 600 || i.published > now), "old items evicted first");
        // cleanup: old items and orphans go
        s.insert_items(g.id, &[p(900, now - KEEP_SECS - 100)], now).unwrap();
        s.delete_feed(f.id).unwrap();
        s.insert_items(f.id, &[p(1, now)], now).unwrap(); // orphan
        let removed = s.cleanup(now).unwrap();
        assert_eq!(removed, 2);
        assert_eq!(s.count_items(g.id).unwrap(), 2);
    }

    #[test]
    fn rules_and_last_seen() {
        let s = tmp("rules");
        let r = s.add_rule("quakes", "keyword", "quake").unwrap();
        assert_eq!(s.rules().unwrap().len(), 1);
        assert!(s.delete_rule(r.id).unwrap());
        for i in 0..MAX_RULES {
            s.add_rule("r", "keyword", &format!("kw{i}")).unwrap();
        }
        assert!(s.add_rule("r", "keyword", "more").is_err());
        assert_eq!(s.last_seen().unwrap(), 0);
        s.set_last_seen(12345).unwrap();
        assert_eq!(s.last_seen().unwrap(), 12345);
    }
}

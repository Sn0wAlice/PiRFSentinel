//! SQLite history: every emitted event (except status/device snapshots) and a
//! summary row per address ever seen. WAL mode, so the HTTP API can read while
//! the scanner writes.

use crate::registry::Track;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde_json::Value;

pub struct Store {
    conn: Connection,
    /// Devices heard after this were not yet written to `devices`.
    flushed_until: i64,
}

impl Store {
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS events (
                 id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, event TEXT NOT NULL,
                 device_id TEXT, mac TEXT, category TEXT, confidence INTEGER, json TEXT NOT NULL);
             CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
             CREATE INDEX IF NOT EXISTS events_device ON events(device_id);
             CREATE TABLE IF NOT EXISTS devices (
                 mac TEXT PRIMARY KEY, device_id TEXT NOT NULL, radio TEXT NOT NULL,
                 first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
                 name TEXT, vendor TEXT, max_confidence INTEGER, top_label TEXT);
             CREATE INDEX IF NOT EXISTS devices_last_seen ON devices(last_seen);",
        )?;
        Ok(Store { conn, flushed_until: 0 })
    }

    pub fn add_event(&self, ev: &Value) -> rusqlite::Result<()> {
        let d = &ev["device"];
        self.conn.execute(
            "INSERT INTO events (ts, event, device_id, mac, category, confidence, json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![ev["ts"].as_i64(), ev["event"].as_str(), d["device_id"].as_str().or(ev["device_id"].as_str()),
                d["mac"].as_str().or(ev["mac"].as_str()), ev["hit"]["category"].as_str(), ev["hit"]["confidence"].as_i64(), ev.to_string()],
        )?;
        Ok(())
    }

    /// When this address was first seen in any earlier run.
    pub fn first_seen(&self, mac: &str) -> Option<i64> {
        self.conn.query_row("SELECT first_seen FROM devices WHERE mac = ?1", [mac], |r| r.get(0)).optional().ok().flatten()
    }

    /// Merges recently heard devices into `devices`.
    pub fn flush_devices<'a>(&mut self, tracks: impl Iterator<Item = &'a Track>, now: i64) -> rusqlite::Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut st = tx.prepare(
                "INSERT INTO devices (mac, device_id, radio, first_seen, last_seen, name, vendor, max_confidence, top_label)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(mac) DO UPDATE SET
                   last_seen = MAX(last_seen, excluded.last_seen),
                   name = COALESCE(excluded.name, name),
                   vendor = COALESCE(excluded.vendor, vendor),
                   top_label = CASE WHEN COALESCE(excluded.max_confidence, -1) > COALESCE(max_confidence, -1) THEN excluded.top_label ELSE top_label END,
                   max_confidence = MAX(COALESCE(max_confidence, -1), COALESCE(excluded.max_confidence, -1))",
            )?;
            for t in tracks.filter(|t| t.last_seen >= self.flushed_until) {
                let best = t.hits.first();
                st.execute(params![t.mac, t.device_id, if t.advert.is_ble() { "ble" } else { "wifi" }, t.first_seen, t.last_seen,
                    t.name, t.vendor, best.map(|h| h.confidence), best.map(|h| &h.label)])?;
            }
        }
        tx.commit()?;
        self.flushed_until = now;
        Ok(())
    }

    pub fn prune(&self, before: i64) -> rusqlite::Result<()> {
        self.conn.execute("DELETE FROM events WHERE ts < ?1", [before])?;
        self.conn.execute("DELETE FROM devices WHERE last_seen < ?1", [before])?;
        Ok(())
    }
}

/// Events from a separate read-only connection (for the HTTP API), newest first.
pub fn query_events(path: &str, since: i64, event: Option<&str>, limit: i64) -> rusqlite::Result<Vec<Value>> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut st = conn.prepare(
        "SELECT json FROM events WHERE ts >= ?1 AND (?2 IS NULL OR event = ?2) ORDER BY ts DESC LIMIT ?3",
    )?;
    let rows = st.query_map(params![since, event, limit], |r| r.get::<_, String>(0))?;
    Ok(rows.filter_map(|r| r.ok()).filter_map(|j| serde_json::from_str(&j).ok()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{Advert, Category, Hit, Source};
    use crate::registry::Registry;
    use serde_json::json;

    #[test]
    fn events_devices_and_retention() {
        let path = std::env::temp_dir().join(format!("pirf-{}.db", std::process::id()));
        let path = path.to_str().unwrap();
        let _ = std::fs::remove_file(path);
        let mut s = Store::open(path).unwrap();
        s.add_event(&json!({"ts": 10, "event": "alert", "device": {"device_id": "A", "mac": "A"}, "hit": {"category": "ALPR", "confidence": 88}})).unwrap();
        s.add_event(&json!({"ts": 20, "event": "error", "component": "wifi"})).unwrap();
        assert_eq!(query_events(path, 0, None, 10).unwrap().len(), 2);
        assert_eq!(query_events(path, 0, Some("alert"), 10).unwrap()[0]["hit"]["confidence"], 88);
        assert_eq!(query_events(path, 15, None, 10).unwrap().len(), 1);

        let mut r = Registry::default();
        let a = Advert::new("00:25:DF:00:00:01", Source::Ble, -50);
        r.report(&a, &[Hit::new(Category::BodyCam, "cam", 75, "", "")], Some("Axon"), None, false, 100);
        s.flush_devices(r.tracks(), 100).unwrap();
        s.flush_devices(r.tracks(), 200).unwrap(); // idempotent
        assert_eq!(s.first_seen("00:25:DF:00:00:01"), Some(100));
        assert_eq!(s.first_seen("FF:FF:FF:FF:FF:FF"), None);

        s.prune(150).unwrap();
        assert!(query_events(path, 0, None, 10).unwrap().is_empty());
        assert_eq!(s.first_seen("00:25:DF:00:00:01"), None);
        let _ = std::fs::remove_file(path);
    }
}

//! Push notifications: one thread per configured target, so a slow or dead
//! webhook never blocks scanning. "text" suits ntfy.sh (Title/Priority/Tags
//! headers + readable body); "json" posts the event as is.

use crate::config::Notify;
use crate::events;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

pub fn spawn(n: Notify, mut rx: broadcast::Receiver<Arc<Value>>) {
    std::thread::spawn(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(10))).build().into();
        loop {
            let ev = match rx.blocking_recv() {
                Ok(ev) => ev,
                Err(broadcast::error::RecvError::Lagged(k)) => {
                    crate::ui::note(&format!("notify {}: skipped {k} events (target too slow)", n.url));
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => return,
            };
            if !n.events.iter().any(|e| ev["event"] == e.as_str()) {
                continue;
            }
            let req = agent.post(&n.url);
            let res = if n.format == "json" {
                req.header("Content-Type", "application/json").send(ev.to_string())
            } else {
                let (title, body, prio) = events::text(&ev);
                req.header("Title", ascii(&title)).header("Priority", prio.to_string()).header("Tags", "satellite_antenna").send(body)
            };
            if let Err(e) = res {
                crate::ui::note(&format!("notify {}: {e}", n.url));
            }
        }
    });
}

/// HTTP header values must be visible ASCII.
fn ascii(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' }).collect()
}

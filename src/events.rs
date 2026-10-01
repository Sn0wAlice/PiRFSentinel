//! The JSON event contract (v1), shared by stdout (--json), the SSE stream, the
//! database and webhooks. Documented in SCHEMA.md; bump SCHEMA_VERSION on any
//! breaking change.

use crate::detect::{Advert, Hit};
use crate::registry::Track;
use serde_json::{json, Map, Value};

pub const SCHEMA_VERSION: u32 = 1;

/// Wraps an event body in the common envelope.
pub fn envelope(sensor: &str, ts: i64, event: &str, body: Value) -> Value {
    let mut m = Map::new();
    m.insert("v".into(), SCHEMA_VERSION.into());
    m.insert("event".into(), event.into());
    m.insert("sensor".into(), sensor.into());
    m.insert("ts".into(), ts.into());
    m.insert("time".into(), iso(ts).into());
    if let Value::Object(b) = body {
        m.extend(b);
    }
    Value::Object(m)
}

pub fn hit(h: &Hit) -> Value {
    json!({
        "category": h.category.id(), "tier": h.tier().label(), "confidence": h.confidence,
        "label": h.label, "evidence": h.evidence, "source": h.source,
    })
}

/// Full device state, including every current hit and the latest raw radio data.
pub fn device(t: &Track) -> Value {
    let a = &t.advert;
    json!({
        "device_id": t.device_id, "mac": t.mac, "radio": if a.is_ble() { "ble" } else { "wifi" },
        "address_type": format!("{:?}", a.address_type), "rssi": a.rssi, "name": t.name, "vendor": t.vendor,
        "first_seen": t.first_seen, "last_seen": t.last_seen, "sightings": t.sightings,
        "first_seen_ever": t.first_seen_ever, "linked_from": t.linked_from, "whitelisted": t.whitelisted,
        "hits": t.hits.iter().map(hit).collect::<Vec<_>>(), "remote_id": t.remote_id, "raw": raw(a),
    })
}

fn raw(a: &Advert) -> Value {
    let mut mfg: Vec<_> = a.manufacturer_data.iter().collect();
    mfg.sort_by_key(|(k, _)| **k);
    let mut sd: Vec<_> = a.service_data.iter().collect();
    sd.sort_by_key(|(k, _)| **k);
    let mut v = json!({
        "manufacturer_data": mfg.into_iter().map(|(k, d)| (format!("{k:04X}"), Value::from(hex(d)))).collect::<Map<_, _>>(),
        "service_uuids": a.service_uuids.iter().map(|u| u.to_string()).collect::<Vec<_>>(),
        "service_data": sd.into_iter().map(|(k, d)| (k.to_string(), Value::from(hex(d)))).collect::<Map<_, _>>(),
        "tx_power": a.tx_power,
    });
    if let Some(w) = &a.wifi {
        v["wifi"] = json!({
            "freq_mhz": w.freq_mhz, "channel": channel(w.freq_mhz), "wps": w.wps,
            "ies": w.ies.iter().map(|(id, d)| json!([id, hex(d)])).collect::<Vec<_>>(),
        });
    }
    v
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// WiFi channel number from the centre frequency.
pub fn channel(mhz: u32) -> Option<u32> {
    match mhz {
        2484 => Some(14),
        2412..=2472 => Some((mhz - 2407) / 5),
        5160..=5885 => Some((mhz - 5000) / 5),
        5955..=7115 => Some((mhz - 5950) / 5),
        _ => None,
    }
}

/// "2026-10-01T10:12:29.123Z" from epoch milliseconds (proleptic Gregorian, UTC).
pub fn iso(ms: i64) -> String {
    let (days, rem) = (ms.div_euclid(86_400_000), ms.rem_euclid(86_400_000));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    let s = rem / 1000;
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z", s / 3600, s / 60 % 60, s % 60, rem % 1000)
}

/// (title, body, ntfy priority 1-5) for human-readable notifications.
pub fn text(ev: &Value) -> (String, String, u8) {
    let s = |v: &Value| v.as_str().unwrap_or("").to_string();
    let kind = s(&ev["event"]);
    let sensor = s(&ev["sensor"]);
    let d = &ev["device"];
    let who = format!("{} {} {} dBm{}{}", s(&d["mac"]), s(&d["radio"]).to_uppercase(), d["rssi"],
        d["name"].as_str().map(|n| format!(" \"{n}\"")).unwrap_or_default(),
        d["vendor"].as_str().map(|v| format!(" ({v})")).unwrap_or_default());
    match kind.as_str() {
        "alert" | "match" => {
            let h = &ev["hit"];
            let prio = match h["tier"].as_str() { Some("strong") => 5, Some("probable") => 4, _ => 3 };
            (format!("{sensor}: {} {}%", s(&h["category"]), h["confidence"]),
             format!("{}\n{who}\n{}", s(&h["label"]), s(&h["evidence"])), prio)
        }
        "error" => (format!("{sensor}: {} error", s(&ev["component"])), s(&ev["message"]), 4),
        _ => (format!("{sensor}: {kind}"), if d.is_null() { ev.to_string() } else { who }, 2),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_dates() {
        assert_eq!(iso(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso(951_782_400_000), "2000-02-29T00:00:00.000Z"); // leap day
        assert_eq!(iso(1_790_849_549_123), "2026-10-01T10:12:29.123Z");
        assert_eq!(iso(-1), "1969-12-31T23:59:59.999Z");
    }

    #[test]
    fn channels() {
        assert_eq!(channel(2412), Some(1));
        assert_eq!(channel(2484), Some(14));
        assert_eq!(channel(5180), Some(36));
        assert_eq!(channel(5975), Some(5));
        assert_eq!(channel(900), None);
    }

    #[test]
    fn envelope_and_text() {
        let ev = envelope("pi", 0, "alert", json!({
            "device": {"mac": "AA", "radio": "ble", "rssi": -60, "name": null, "vendor": "Axon"},
            "hit": {"category": "BODY_CAM", "tier": "strong", "confidence": 90, "label": "cam", "evidence": "tag"},
        }));
        assert_eq!((ev["v"].as_u64(), ev["event"].as_str(), ev["sensor"].as_str()), (Some(1), Some("alert"), Some("pi")));
        let (title, body, prio) = text(&ev);
        assert_eq!((title.as_str(), prio), ("pi: BODY_CAM 90%", 5));
        assert_eq!(body, "cam\nAA BLE -60 dBm (Axon)\ntag");
    }
}

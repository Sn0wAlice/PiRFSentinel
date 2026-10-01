//! WiFi access points via `iw dev <iface> scan -u` (needs root; uses `sudo -n`
//! when not root). The built-in Pi radio has no monitor mode, so this sees
//! beacons only, like Android does.

use crate::detect::{now_ms, AddressType, Advert, Source, WifiInfo};
use crate::Input;
use std::os::unix::fs::MetadataExt;
use std::time::Duration;
use tokio::{process::Command, sync::mpsc};

pub async fn run(iface: String, interval: Duration, tx: mpsc::Sender<Input>) {
    let root = std::fs::metadata("/proc/self").map(|m| m.uid() == 0).unwrap_or(false);
    let mut tick = tokio::time::interval(interval);
    loop {
        tick.tick().await;
        let mut cmd = if root { Command::new("iw") } else { let mut c = Command::new("sudo"); c.args(["-n", "iw"]); c };
        let out = match cmd.args(["dev", &iface, "scan", "-u"]).output().await {
            Ok(o) if o.status.success() => o,
            // EBUSY: another scan (ours or another program's) is running; retry next tick.
            Ok(o) if String::from_utf8_lossy(&o.stderr).contains("(-16)") => continue,
            Ok(o) => {
                let msg = format!("iw failed: {}", String::from_utf8_lossy(&o.stderr).trim());
                if tx.send(Input::Error("wifi", msg)).await.is_err() { return }
                continue;
            }
            Err(e) => { let _ = tx.send(Input::Error("wifi", format!("cannot run iw: {e}"))).await; return }
        };
        for a in parse_iw(&String::from_utf8_lossy(&out.stdout), now_ms()) {
            if tx.send(Input::Advert(a)).await.is_err() {
                return;
            }
        }
    }
}

/// Parses `iw ... scan -u` output into one Advert per BSS.
pub fn parse_iw(text: &str, now: i64) -> Vec<Advert> {
    let mut out: Vec<Advert> = Vec::new();
    let (mut manufacturer, mut model) = (None::<String>, None::<String>);
    let flush_wps = |a: Option<&mut Advert>, m: &mut Option<String>, mo: &mut Option<String>| {
        if let Some(a) = a {
            let wps = [m.take(), mo.take()].into_iter().flatten().collect::<Vec<_>>().join(" ");
            if !wps.is_empty() {
                a.wifi.as_mut().unwrap().wps = Some(wps);
            }
        }
    };
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("BSS ") {
            flush_wps(out.last_mut(), &mut manufacturer, &mut model);
            let mac = rest.split('(').next().unwrap_or("").trim().to_uppercase();
            let mut a = Advert::new(&mac, Source::Wifi, -100);
            a.address_type = AddressType::of_wifi(&mac);
            a.wifi = Some(WifiInfo::default());
            a.timestamp = now;
            out.push(a);
            continue;
        }
        let Some(a) = out.last_mut() else { continue };
        let t = line.trim();
        if let Some(v) = t.strip_prefix("freq: ") {
            a.wifi.as_mut().unwrap().freq_mhz = v.parse::<f64>().unwrap_or(0.0) as u32;
        } else if let Some(v) = t.strip_prefix("signal: ") {
            a.rssi = v.split_whitespace().next().and_then(|s| s.parse::<f64>().ok()).unwrap_or(-100.0) as i16;
        } else if let Some(v) = t.strip_prefix("SSID:") {
            let ssid = unescape(v.trim());
            a.name = (!ssid.is_empty() && !ssid.chars().all(|c| c == '\0')).then_some(ssid);
        } else if let Some(v) = t.strip_prefix("Vendor specific: OUI ") {
            // "fa:0b:bc, data: 0d 01 ..." -> IE 221 payload = OUI + data
            if let Some((oui, data)) = v.split_once(", data:") {
                let bytes: Vec<u8> = oui.split(':').chain(data.split_whitespace()).filter_map(|h| u8::from_str_radix(h, 16).ok()).collect();
                a.wifi.as_mut().unwrap().ies.push((221, bytes));
            }
        } else if let Some(v) = t.strip_prefix("Unknown IE (") {
            if let Some((id, data)) = v.split_once("):") {
                if let Ok(id) = id.parse::<u8>() {
                    let bytes = data.split_whitespace().filter_map(|h| u8::from_str_radix(h, 16).ok()).collect();
                    a.wifi.as_mut().unwrap().ies.push((id, bytes));
                }
            }
        } else if let Some(v) = t.strip_prefix("* Manufacturer: ") {
            manufacturer = Some(v.trim().to_string());
        } else if let Some(v) = t.strip_prefix("* Model: ") {
            model = Some(v.trim().to_string());
        }
    }
    flush_wps(out.last_mut(), &mut manufacturer, &mut model);
    out
}

/// iw prints non-printable SSID bytes as `\xNN`.
fn unescape(s: &str) -> String {
    let mut bytes = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && b.get(i + 1) == Some(&b'x') {
            if let Some(v) = s.get(i + 2..i + 4).and_then(|h| u8::from_str_radix(h, 16).ok()) {
                bytes.push(v);
                i += 4;
                continue;
            }
        }
        bytes.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "BSS f8:08:4f:2d:99:70(on wlan0)
\tlast seen: 425.566s [boottime]
\tfreq: 2412.0
\tcapability: ESS Privacy ShortSlotTime (0x0411)
\tsignal: -54.00 dBm
\tSSID: Flock-3F2A1B
\tWPS:\t * Version: 1.0
\t\t * Manufacturer: Broadcom
\t\t * Model: BroadcomAP
\tVendor specific: OUI 00:10:18, data: 02 01 00 1c 00 00
BSS 12:0b:8b:e0:bc:6c(on wlan0) -- associated
\tfreq: 5180.0
\tsignal: -67.00 dBm
\tSSID: \\x00\\x00\\x00
\tUnknown IE (201): 20 0d
\tVendor specific: OUI fa:0b:bc, data: 0d 01
";

    #[test]
    fn parses_bss_blocks() {
        let v = parse_iw(SAMPLE, 1);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].mac, "F8:08:4F:2D:99:70");
        assert_eq!(v[0].rssi, -54);
        assert_eq!(v[0].name.as_deref(), Some("Flock-3F2A1B"));
        let w = v[0].wifi.as_ref().unwrap();
        assert_eq!((w.freq_mhz, w.wps.as_deref()), (2412, Some("Broadcom BroadcomAP")));
        assert_eq!(w.ies, vec![(221, vec![0x00, 0x10, 0x18, 0x02, 0x01, 0x00, 0x1c, 0x00, 0x00])]);
        assert_eq!(v[1].name, None); // hidden network
        assert_eq!(v[1].address_type, AddressType::WifiLocal);
        let w = v[1].wifi.as_ref().unwrap();
        assert_eq!(w.ies, vec![(201, vec![0x20, 0x0d]), (221, vec![0xfa, 0x0b, 0xbc, 0x0d, 0x01])]);
        assert_eq!(w.wps, None);
    }

    #[test]
    fn unescapes_ssid() {
        assert_eq!(unescape(r"caf\xc3\xa9"), "café");
        assert_eq!(unescape(r"a\x"), r"a\x");
    }
}

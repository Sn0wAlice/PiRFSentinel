//! PiRFSentinel: passive BLE/WiFi surveillance-equipment scanner for Raspberry Pi.
//! Rust port of RF Sentinel (github.com/CIS-C0/RFSentinel, GPL-3.0). Receive-only.

#[cfg(target_os = "linux")]
mod ble;
mod detect;
mod registry;
mod wifi;

use detect::{fusion, remote_id, signatures, uuid16, vendor, Advert, Category, Hit};
use registry::Registry;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;

const USAGE: &str = "usage: pirfsentinel [--no-ble] [--no-wifi] [--iface wlan0] [--wifi-interval 10] \
[--threshold 50] [--presets global,canada,us] [--all-categories] [--list]";

/// Re-run signatures per device at most this often; RSSI still updates every advert.
const CLASSIFY_INTERVAL_MS: i64 = 2_000;
/// At most one printed match per device per this interval (BLE repeats many times a second).
const LOG_THROTTLE_MS: i64 = 30_000;
/// Same device alerts again only after this long.
const ALERT_DEDUPE_MS: i64 = 5 * 60_000;

struct Args {
    ble: bool,
    wifi: bool,
    iface: String,
    wifi_interval: u64,
    threshold: i32,
    presets: Vec<String>,
    all_categories: bool,
    /// Print every device heard, not just matches, with each status line.
    list: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args { ble: true, wifi: true, iface: "wlan0".into(), wifi_interval: 10, threshold: 50, presets: vec!["global".into()], all_categories: false, list: false };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut val = || it.next().ok_or(format!("{k} needs a value"));
        match k.as_str() {
            "--no-ble" => a.ble = false,
            "--no-wifi" => a.wifi = false,
            "--all-categories" => a.all_categories = true,
            "--list" => a.list = true,
            "--iface" => a.iface = val()?,
            "--wifi-interval" => a.wifi_interval = val()?.parse().map_err(|_| "bad --wifi-interval")?,
            "--threshold" => a.threshold = val()?.parse().map_err(|_| "bad --threshold")?,
            "--presets" => a.presets = val()?.split(',').map(str::to_string).collect(),
            _ => return Err(format!("unknown argument {k}")),
        }
    }
    Ok(a)
}

#[tokio::main]
async fn main() {
    let args = parse_args().unwrap_or_else(|e| {
        eprintln!("{e}\n{USAGE}");
        std::process::exit(2)
    });
    let presets: Vec<&str> = args.presets.iter().map(String::as_str).collect();
    let watchlist = vendor::Watchlist::load(&presets).unwrap_or_else(|e| {
        eprintln!("watchlist: {e}");
        std::process::exit(2)
    });
    eprintln!("watchlist: {} entries from {:?}; alert threshold {}", watchlist.len(), presets, args.threshold);

    let (tx, mut rx) = mpsc::channel::<Advert>(4096);
    if args.ble {
        #[cfg(target_os = "linux")]
        {
            let tx = tx.clone();
            tokio::spawn(async move {
                if let Err(e) = ble::run(tx).await {
                    eprintln!("ble: {e}");
                }
            });
        }
        #[cfg(not(target_os = "linux"))]
        eprintln!("ble: only supported on Linux (BlueZ)");
    }
    if args.wifi {
        tokio::spawn(wifi::run(args.iface.clone(), Duration::from_secs(args.wifi_interval), tx.clone()));
    }
    drop(tx);

    let mut s = Scanner { args, watchlist, reg: Registry::default(), classified: HashMap::new(), last_logged: HashMap::new(), last_alerted: HashMap::new() };
    let mut status = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            a = rx.recv() => match a {
                Some(a) => s.process(a),
                None => { eprintln!("all scanners stopped"); break }
            },
            _ = status.tick() => s.status(),
        }
    }
}

struct Classified {
    time: i64,
    hits: Vec<Hit>,
    vendor: Option<String>,
}

struct Scanner {
    args: Args,
    watchlist: vendor::Watchlist,
    reg: Registry,
    classified: HashMap<String, Classified>,
    last_logged: HashMap<String, i64>,
    last_alerted: HashMap<String, i64>,
}

impl Scanner {
    fn process(&mut self, a: Advert) {
        let now = a.timestamp;
        // Remote ID messages arrive one type at a time; merge every packet.
        let prev = self.reg.remote_id_of(&a.mac);
        let rid = if a.is_ble() {
            a.service_data.get(&uuid16(signatures::UUID_REMOTE_ID)).and_then(|d| remote_id::decode_ble(d, prev))
        } else {
            a.wifi.as_ref().and_then(|w| w.ies.iter().find(|(id, ie)| *id == 221 && remote_id::is_wifi_ie(ie)))
                .and_then(|(_, ie)| remote_id::decode_wifi_ie(ie, prev))
        };
        if self.classified.get(&a.mac).is_none_or(|c| now - c.time >= CLASSIFY_INTERVAL_MS) {
            let c = self.classify(&a, now);
            self.classified.insert(a.mac.clone(), c);
        }
        let c = &self.classified[&a.mac];
        self.reg.report(&a, &c.hits, c.vendor.as_deref(), rid, now);
        let Some(best) = c.hits.first() else { return };

        // Someone else's tracker nearby is normal: trackers never alert here (no GPS follower check yet).
        let alert = best.category != Category::Tracker && best.confidence >= self.args.threshold
            && self.last_alerted.get(&a.mac).is_none_or(|t| now - t > ALERT_DEDUPE_MS);
        if !alert && self.last_logged.get(&a.mac).is_some_and(|t| now - t < LOG_THROTTLE_MS) {
            return;
        }
        self.last_logged.insert(a.mac.clone(), now);
        if alert {
            self.last_alerted.insert(a.mac.clone(), now);
        }
        let line = self.describe(&a, best, c.vendor.as_deref());
        println!("{} {} {line}", clock(now), if alert { "ALERT" } else { "match" });
    }

    fn classify(&mut self, a: &Advert, now: i64) -> Classified {
        let mac_vendor = vendor::mac_vendor(&a.mac);
        let companies: Vec<&str> = a.manufacturer_data.keys().filter_map(|&k| vendor::company(k)).collect();
        let wps = a.wifi.as_ref().and_then(|w| w.wps.clone());
        let vendor = mac_vendor.map(str::to_string).or(wps).or(companies.first().map(|s| s.to_string()));
        let vendors: Vec<&str> = mac_vendor.into_iter().chain(companies.iter().copied()).collect();
        // Per-packet rules, the watchlist, matches carried over from a rotated address and the
        // patrol-vehicle cluster, then fused into one calibrated score.
        let mut raw = signatures::classify(a);
        raw.extend(self.watchlist.hits(&a.mac, a.name.as_deref(), &vendors));
        raw.extend(self.reg.inherited_hits(&a.mac));
        raw.extend(self.reg.cluster_hit(&a.mac, now));
        raw.retain(|h| self.args.all_categories || h.category.default_enabled());
        Classified { time: now, hits: fusion::fuse(raw), vendor }
    }

    fn describe(&self, a: &Advert, best: &Hit, vendor: Option<&str>) -> String {
        let radio = if a.is_ble() { "BLE" } else { "WiFi" };
        let mut s = format!("[{} {}] {} - {} | {} {radio} {} dBm", best.tier().label(), best.confidence, best.category.tag(), best.label, a.mac, a.rssi);
        if let Some(n) = &a.name {
            s += &format!(" \"{n}\"");
        }
        if let Some(v) = vendor {
            s += &format!(" ({v})");
        }
        s += &format!(" | {}", best.evidence);
        if let Some(r) = self.reg.get(&a.mac).and_then(|t| t.remote_id.as_ref()) {
            s += &format!(" | RID id={} {} lat={:?} lon={:?} alt={:?}m speed={:?}m/s op=({:?},{:?})",
                r.uas_id.as_deref().unwrap_or("?"), r.status.unwrap_or(""), r.latitude, r.longitude,
                r.altitude_geo_m, r.speed_ms, r.operator_latitude, r.operator_longitude);
        }
        s
    }

    fn status(&mut self) {
        let now = detect::now_ms();
        self.reg.prune(now);
        self.classified.retain(|_, c| now - c.time <= registry::PRUNE_AFTER_MS);
        self.last_logged.retain(|_, t| now - *t <= LOG_THROTTLE_MS);
        self.last_alerted.retain(|_, t| now - *t <= ALERT_DEDUPE_MS);
        let flagged = self.reg.tracks().filter(|t| !t.hits.is_empty()).count();
        eprintln!("{} status: {} devices, {} flagged", clock(now), self.reg.len(), flagged);
        if self.args.list {
            let mut all: Vec<_> = self.reg.tracks().collect();
            all.sort_by_key(|t| std::cmp::Reverse(t.rssi));
            for t in all {
                let tag = t.hits.first().map_or(String::new(), |h| format!("  [{} {}] {}", h.category.tag(), h.confidence, h.label));
                println!("  {:<4} {} {:>4} dBm  {:<28.28} {:<30.30}{tag}", if t.ble { "BLE" } else { "WiFi" }, t.mac, t.rssi,
                    t.name.as_deref().unwrap_or("-"), t.vendor.as_deref().unwrap_or("-"));
            }
        }
    }
}

/// "HH:MM:SSZ" (UTC; journald adds local timestamps anyway).
fn clock(ms: i64) -> String {
    let s = ms / 1000 % 86_400;
    format!("{:02}:{:02}:{:02}Z", s / 3600, s / 60 % 60, s % 60)
}

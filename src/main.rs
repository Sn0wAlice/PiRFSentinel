//! PiRFSentinel: passive BLE/WiFi surveillance-equipment scanner for Raspberry Pi.
//! Rust port of RF Sentinel (github.com/CIS-C0/RFSentinel, GPL-3.0). Receive-only.

#[cfg(target_os = "linux")]
mod ble;
mod detect;
mod registry;
mod ui;
mod wifi;

use detect::{fusion, remote_id, signatures, uuid16, vendor, Advert, Category, Hit, Tier};
use registry::{Registry, Track};
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;

const USAGE: &str = "usage: pirfsentinel [--no-ble] [--no-wifi] [--iface wlan0] [--wifi-interval 10] \
[--threshold 50] [--presets global,canada,us] [--all-categories] [--list] [--json]";

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
    /// Print every device heard, not just matches, every 30 s.
    list: bool,
    /// One JSON object per line on stdout (matches, and devices with --list).
    json: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        ble: true, wifi: true, iface: "wlan0".into(), wifi_interval: 10, threshold: 50,
        presets: vec!["global".into()], all_categories: false, list: false, json: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut val = || it.next().ok_or(format!("{k} needs a value"));
        match k.as_str() {
            "--no-ble" => a.ble = false,
            "--no-wifi" => a.wifi = false,
            "--all-categories" => a.all_categories = true,
            "--list" => a.list = true,
            "--json" => a.json = true,
            "--iface" => a.iface = val()?,
            "--wifi-interval" => a.wifi_interval = val()?.parse().map_err(|_| "bad --wifi-interval")?,
            "--threshold" => a.threshold = val()?.parse().map_err(|_| "bad --threshold")?,
            "--presets" => a.presets = val()?.split(',').map(str::to_string).collect(),
            "-h" | "--help" => return Err("PiRFSentinel - passive BLE/WiFi surveillance-equipment scanner".into()),
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
    ui::init(!args.json);
    banner(&args, watchlist.len());

    let (tx, mut rx) = mpsc::channel::<Advert>(4096);
    if args.ble {
        #[cfg(target_os = "linux")]
        {
            let tx = tx.clone();
            tokio::spawn(async move {
                if let Err(e) = ble::run(tx).await {
                    ui::note(&format!("{} ble: {e}", ui::red("✗")));
                }
            });
        }
        #[cfg(not(target_os = "linux"))]
        ui::note("ble: only supported on Linux (BlueZ)");
    }
    if args.wifi {
        tokio::spawn(wifi::run(args.iface.clone(), Duration::from_secs(args.wifi_interval), tx.clone()));
    }
    drop(tx);

    let mut s = Scanner {
        args, watchlist, reg: Registry::default(), classified: HashMap::new(), last_logged: HashMap::new(),
        last_alerted: HashMap::new(), adverts: 0, alerts: 0, start: detect::now_ms(),
    };
    let mut live = tokio::time::interval(Duration::from_secs(1));
    let mut housekeeping = tokio::time::interval(Duration::from_secs(30));
    housekeeping.tick().await; // skip the immediate first tick: nothing heard yet
    loop {
        tokio::select! {
            a = rx.recv() => match a {
                Some(a) => s.process(a),
                None => { ui::note("all scanners stopped"); break }
            },
            _ = live.tick() => s.live(),
            _ = housekeeping.tick() => s.housekeeping(),
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    ui::finish();
    s.summary();
}

fn banner(a: &Args, entries: usize) {
    if a.json {
        return;
    }
    let radios = [
        a.ble.then(|| "BLE".to_string()),
        a.wifi.then(|| format!("WiFi {} every {}s", a.iface, a.wifi_interval)),
    ].into_iter().flatten().collect::<Vec<_>>().join(" · ");
    ui::note(&format!("\n  {}  {}", ui::purple(&ui::bold("pirfsentinel")), ui::dim(&format!("v{} · passive BLE/WiFi surveillance scanner", env!("CARGO_PKG_VERSION")))));
    ui::note(&ui::dim("  ──────────────────────────────────────────────────────"));
    ui::note(&format!("  {}  {radios}", ui::dim("radios   ")));
    ui::note(&format!("  {}  {entries} entries ({}) · alert ≥ {}{}", ui::dim("watchlist"), a.presets.join(", "), a.threshold,
        if a.all_categories { " · all categories" } else { "" }));
    ui::note("");
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
    /// Adverts received since the last live tick.
    adverts: u32,
    alerts: u32,
    start: i64,
}

impl Scanner {
    fn process(&mut self, a: Advert) {
        self.adverts += 1;
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
            self.alerts += 1;
        }
        let track = self.reg.get(&a.mac).unwrap();
        ui::out(&if self.args.json { match_json(&a, best, track, alert) } else { match_block(&a, best, track, alert) });
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

    /// Refreshes the spinner line once a second.
    fn live(&mut self) {
        let ble = self.reg.tracks().filter(|t| t.ble).count();
        let flagged = self.reg.tracks().filter(|t| !t.hits.is_empty()).count();
        let flag = if flagged > 0 { ui::orange(&format!("{flagged} flagged")) } else { ui::green("all clear") };
        ui::status(format!("scanning  {}  {} BLE · {} WiFi  {}  {}",
            ui::dim("│"), ui::bold(&ble.to_string()), ui::bold(&(self.reg.len() - ble).to_string()),
            ui::dim(&format!("│  {:>3} adv/s  │", self.adverts)), flag));
        self.adverts = 0;
    }

    fn housekeeping(&mut self) {
        let now = detect::now_ms();
        self.reg.prune(now);
        self.classified.retain(|_, c| now - c.time <= registry::PRUNE_AFTER_MS);
        self.last_logged.retain(|_, t| now - *t <= LOG_THROTTLE_MS);
        self.last_alerted.retain(|_, t| now - *t <= ALERT_DEDUPE_MS);
        if !ui::animated() && !self.args.json {
            let flagged = self.reg.tracks().filter(|t| !t.hits.is_empty()).count();
            eprintln!("{} status: {} devices, {} flagged", clock(now), self.reg.len(), flagged);
        }
        if self.args.list {
            self.list(now);
        }
    }

    fn list(&self, now: i64) {
        let mut all: Vec<&Track> = self.reg.tracks().collect();
        all.sort_by_key(|t| (t.hits.is_empty(), std::cmp::Reverse(t.rssi)));
        if self.args.json {
            for t in all {
                ui::out(&json!({"ts": now, "event": "device", "mac": t.mac, "radio": radio(t.ble), "rssi": t.rssi,
                    "name": t.name, "vendor": t.vendor, "match": t.hits.first().map(|h| h.label.clone())}).to_string());
            }
            return;
        }
        let mut s = format!("\n  {}  {}\n  {}\n", ui::bold(&format!("{} devices", all.len())), ui::dim(&clock(now)),
            ui::dim(&format!("{:<5} {:<17} {:<9}  {:<26} {:<26} MATCH", "RADIO", "ADDRESS", "SIGNAL", "NAME", "VENDOR")));
        for t in all {
            let m = t.hits.first().map_or(String::new(), |h| tier_color(h.tier(), &format!("{} {}", h.category.tag(), h.confidence)));
            s += &format!("  {:<5} {} {}  {:<26} {}  {m}\n", radio(t.ble), ui::dim(&format!("{:<17}", t.mac)), bars(t.rssi),
                trunc(t.name.as_deref().unwrap_or("·"), 26), ui::dim(&format!("{:<26}", trunc(t.vendor.as_deref().unwrap_or("·"), 26))));
        }
        ui::out(&s);
    }

    fn summary(&self) {
        if self.args.json {
            return;
        }
        let mins = (detect::now_ms() - self.start) / 60_000;
        ui::note(&format!("\n  {} {} min · {} devices in view · {} alerts\n", ui::green("✓"), mins, self.reg.len(), self.alerts));
    }
}

/// Human match block: one headline, one identity line, the evidence.
fn match_block(a: &Advert, best: &Hit, t: &Track, alert: bool) -> String {
    let badge = tier_color(best.tier(), &format!("▌{} {}", best.tier().label().to_uppercase(), best.confidence));
    let kind = if alert { ui::red("ALERT") } else { ui::dim("match") };
    let mut who = format!("{} {} {} dBm", ui::dim(&a.mac), radio(a.is_ble()), a.rssi);
    if let Some(n) = &t.name { who += &format!("  \"{n}\""); }
    if let Some(v) = &t.vendor { who += &format!("  {}", ui::dim(v)); }
    if let Some(prev) = &t.linked_from { who += &ui::dim(&format!("  (was {prev})")); }
    let mut s = format!("{} {kind}  {badge}  {}  {}\n           {who}\n           {}",
        ui::dim(&clock(a.timestamp)), ui::purple(best.category.tag()), ui::bold(&best.label), ui::dim(&format!("↳ {}", best.evidence)));
    if let Some(r) = &t.remote_id {
        let f = |v: Option<f64>| v.map_or("?".into(), |v| format!("{v:.5}"));
        s += &format!("\n           {} {} {}  drone {},{}  alt {} m  {} m/s  operator {},{}", ui::purple("✈"),
            r.uas_id.as_deref().unwrap_or("?"), r.status.unwrap_or(""), f(r.latitude), f(r.longitude),
            r.altitude_geo_m.map_or("?".into(), |v| format!("{v:.0}")), r.speed_ms.map_or("?".into(), |v| format!("{v:.1}")),
            f(r.operator_latitude), f(r.operator_longitude));
    }
    s
}

fn match_json(a: &Advert, best: &Hit, t: &Track, alert: bool) -> String {
    json!({
        "ts": a.timestamp, "event": if alert { "alert" } else { "match" },
        "mac": a.mac, "radio": radio(a.is_ble()), "rssi": a.rssi, "name": t.name, "vendor": t.vendor,
        "category": best.category.tag(), "tier": best.tier().label(), "confidence": best.confidence,
        "label": best.label, "evidence": best.evidence, "source": best.source, "linked_from": t.linked_from,
        "remote_id": t.remote_id,
    }).to_string()
}

fn tier_color(tier: Tier, s: &str) -> String {
    match tier {
        Tier::Strong => ui::red(s),
        Tier::Probable => ui::orange(s),
        Tier::Weak => ui::dim(s),
    }
}

fn radio(ble: bool) -> &'static str {
    if ble { "BLE" } else { "WiFi" }
}

/// "▂▄▆█ -52" style signal gauge, padded to a fixed width.
fn bars(rssi: i16) -> String {
    let n = match rssi { -55.. => 4, -67..=-56 => 3, -80..=-68 => 2, _ => 1 };
    let g: String = "▂▄▆█".chars().enumerate().map(|(i, c)| if i < n { c } else { ' ' }).collect();
    format!("{} {:>4}", ui::green(&g), rssi)
}

fn trunc(s: &str, n: usize) -> String {
    let t: String = s.chars().take(n).collect();
    format!("{t:<n$}")
}

/// "HH:MM:SS" UTC (journald adds local timestamps anyway).
fn clock(ms: i64) -> String {
    let s = ms / 1000 % 86_400;
    format!("{:02}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
}

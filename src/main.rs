//! PiRFSentinel: passive BLE/WiFi surveillance-equipment scanner for Raspberry Pi.
//! Rust port of RF Sentinel (github.com/CIS-C0/RFSentinel, GPL-3.0). Receive-only.

mod api;
#[cfg(target_os = "linux")]
mod ble;
mod config;
mod detect;
mod events;
mod notify;
mod registry;
mod store;
mod ui;
mod wifi;

use config::Config;
use detect::{fusion, remote_id, signatures, uuid16, vendor, Advert, Category, Hit, Tier};
use registry::{Registry, Track};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};

/// Re-run signatures per device at most this often; RSSI still updates every advert.
const CLASSIFY_INTERVAL_MS: i64 = 2_000;
/// Human mode: at most one printed match per device per this interval.
const LOG_THROTTLE_MS: i64 = 30_000;
/// Same device alerts again only after this long.
const ALERT_DEDUPE_MS: i64 = 5 * 60_000;
/// A drone's Remote ID event is re-sent at most this often.
const REMOTE_ID_EVERY_MS: i64 = 1_000;
const STATUS_EVERY: Duration = Duration::from_secs(30);

/// What the radio tasks send to the main loop.
pub enum Input {
    Advert(Advert),
    Error(&'static str, String),
}

#[tokio::main]
async fn main() {
    let cfg = Config::from_args(std::env::args().skip(1)).unwrap_or_else(|e| fail(&format!("{e}\n{}", config::USAGE)));
    let presets: Vec<&str> = cfg.presets.iter().map(String::as_str).collect();
    let watchlist = vendor::Watchlist::load(&presets, &cfg.watch).unwrap_or_else(|e| fail(&e));
    let whitelist = vendor::Watchlist::whitelist(&cfg.whitelist).unwrap_or_else(|e| fail(&e));
    let store = cfg.db.as_deref().map(|p| store::Store::open(p).unwrap_or_else(|e| fail(&format!("db {p}: {e}"))));

    ui::init(!cfg.json);
    banner(&cfg, watchlist.len(), whitelist.len());

    let (events_tx, _) = broadcast::channel::<Arc<Value>>(1024);
    for n in &cfg.notify {
        notify::spawn(n.clone(), events_tx.subscribe());
    }
    let start = detect::now_ms();
    let shared = cfg.listen.clone().map(|addr| {
        let shared = Arc::new(api::Shared {
            devices: RwLock::new(json!([])), status: RwLock::new(json!({})), events: events_tx.clone(), db: cfg.db.clone(), started: start,
        });
        let s = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = api::serve(addr.clone(), s).await {
                fail(&format!("api {addr}: {e}"));
            }
        });
        shared
    });

    let (tx, mut rx) = mpsc::channel::<Input>(4096);
    if cfg.ble {
        #[cfg(target_os = "linux")]
        {
            let tx = tx.clone();
            tokio::spawn(async move {
                if let Err(e) = ble::run(tx.clone()).await {
                    let _ = tx.send(Input::Error("ble", e.to_string())).await;
                }
            });
        }
        #[cfg(not(target_os = "linux"))]
        ui::note("ble: only supported on Linux (BlueZ)");
    }
    if cfg.wifi {
        tokio::spawn(wifi::run(cfg.iface.clone(), Duration::from_secs(cfg.wifi_interval), tx.clone()));
    }
    drop(tx);

    let radios = HashMap::from([
        ("ble", if cfg.ble { "starting" } else { "off" }.to_string()),
        ("wifi", if cfg.wifi { "starting" } else { "off" }.to_string()),
    ]);
    let mut s = Scanner {
        cfg, watchlist, whitelist, store, shared, events: events_tx, reg: Registry::default(),
        classified: HashMap::new(), last_logged: HashMap::new(), last_alerted: HashMap::new(),
        match_state: HashMap::new(), rid_sent: HashMap::new(), radios,
        adverts_sec: 0, adverts_window: 0, alerts: 0, start,
    };
    s.emit("start", json!({"version": env!("CARGO_PKG_VERSION"), "config": {
        "ble": s.cfg.ble, "wifi": s.cfg.wifi, "threshold": s.cfg.threshold, "presets": s.cfg.presets,
        "all_categories": s.cfg.all_categories, "watchlist": s.watchlist.len(), "whitelist": s.whitelist.len(),
        "db": s.cfg.db.is_some(), "api": s.cfg.listen.is_some(), "notify": s.cfg.notify.len(),
    }}));

    let mut live = tokio::time::interval(Duration::from_secs(1));
    let mut housekeeping = tokio::time::interval(STATUS_EVERY);
    housekeeping.tick().await; // skip the immediate first tick: nothing heard yet
    loop {
        tokio::select! {
            input = rx.recv() => match input {
                Some(Input::Advert(a)) => s.process(a),
                Some(Input::Error(component, message)) => s.radio_error(component, message),
                None => { ui::note("all scanners stopped"); break }
            },
            _ = live.tick() => s.live(),
            _ = housekeeping.tick() => s.housekeeping(),
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    ui::finish();
    s.housekeeping_store(detect::now_ms());
    s.summary();
}

fn fail(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(2)
}

fn banner(c: &Config, entries: usize, whitelisted: usize) {
    if c.json {
        return;
    }
    let radios = [c.ble.then(|| "BLE".to_string()), c.wifi.then(|| format!("WiFi {} every {}s", c.iface, c.wifi_interval))]
        .into_iter().flatten().collect::<Vec<_>>().join(" · ");
    let outputs = [
        c.listen.as_ref().map(|l| format!("api http://{l}")),
        c.db.as_ref().map(|d| format!("db {d}")),
        (!c.notify.is_empty()).then(|| format!("{} notify target(s)", c.notify.len())),
    ].into_iter().flatten().collect::<Vec<_>>().join(" · ");
    ui::note(&format!("\n  {}  {}", ui::purple(&ui::bold("pirfsentinel")),
        ui::dim(&format!("v{} · {} · passive BLE/WiFi surveillance scanner", env!("CARGO_PKG_VERSION"), c.sensor))));
    ui::note(&ui::dim("  ──────────────────────────────────────────────────────"));
    ui::note(&format!("  {}  {radios}", ui::dim("radios   ")));
    ui::note(&format!("  {}  {entries} entries ({}) · {whitelisted} whitelisted · alert ≥ {}{}", ui::dim("watchlist"),
        c.presets.join(", "), c.threshold, if c.all_categories { " · all categories" } else { "" }));
    if !outputs.is_empty() {
        ui::note(&format!("  {}  {outputs}", ui::dim("outputs  ")));
    }
    ui::note("");
}

struct Classified {
    time: i64,
    hits: Vec<Hit>,
    vendor: Option<String>,
    whitelisted: bool,
}

struct Scanner {
    cfg: Config,
    watchlist: vendor::Watchlist,
    whitelist: vendor::Watchlist,
    store: Option<store::Store>,
    shared: Option<Arc<api::Shared>>,
    events: broadcast::Sender<Arc<Value>>,
    reg: Registry,
    classified: HashMap<String, Classified>,
    last_logged: HashMap<String, i64>,
    last_alerted: HashMap<String, i64>,
    /// Last best (label, tier) announced per address, to emit `match` only on change.
    match_state: HashMap<String, Option<(String, Tier)>>,
    /// Last Remote ID sent per address.
    rid_sent: HashMap<String, (i64, remote_id::Info)>,
    radios: HashMap<&'static str, String>,
    adverts_sec: u32,
    adverts_window: u64,
    alerts: u32,
    start: i64,
}

impl Scanner {
    /// Sends one event to every output: stdout (--json), SSE, webhooks, database.
    fn emit(&mut self, kind: &str, body: Value) {
        let ev = events::envelope(&self.cfg.sensor, detect::now_ms(), kind, body);
        if self.cfg.json {
            ui::out(&ev.to_string());
        }
        if let Some(st) = &self.store {
            if matches!(kind, "alert" | "match" | "remote_id" | "error") {
                if let Err(e) = st.add_event(&ev) {
                    ui::note(&format!("db: {e}"));
                }
            }
        }
        let _ = self.events.send(Arc::new(ev)); // no subscribers is fine
    }

    fn process(&mut self, a: Advert) {
        self.adverts_sec += 1;
        self.adverts_window += 1;
        let radio = if a.is_ble() { "ble" } else { "wifi" };
        if self.radios[radio] != "ok" {
            self.radios.insert(radio, "ok".into());
        }
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
        let (hits, whitelisted) = (c.hits.clone(), c.whitelisted);
        let first = self.reg.report(&a, &hits, c.vendor.as_deref(), rid.clone(), whitelisted, now);

        if first {
            let ever = self.store.as_ref().and_then(|s| s.first_seen(&a.mac));
            if let Some(t) = self.reg.get_mut(&a.mac) {
                t.first_seen_ever = ever;
            }
            let d = events::device(self.reg.get(&a.mac).unwrap());
            self.emit("device_new", json!({"device": d}));
        }
        self.maybe_match_event(&a.mac);
        if let Some(info) = rid {
            if self.rid_sent.get(&a.mac).is_none_or(|(t, last)| *last != info && now - t >= REMOTE_ID_EVERY_MS) {
                self.rid_sent.insert(a.mac.clone(), (now, info.clone()));
                let t = self.reg.get(&a.mac).unwrap();
                self.emit("remote_id", json!({"device_id": t.device_id, "mac": a.mac, "remote_id": info}));
            }
        }

        let Some(best) = hits.first() else { return };
        // Someone else's tracker nearby is normal: trackers never alert here (no GPS follower check yet).
        let alert = best.category != Category::Tracker && best.confidence >= self.cfg.threshold
            && self.last_alerted.get(&a.mac).is_none_or(|t| now - t > ALERT_DEDUPE_MS);
        if alert {
            self.last_alerted.insert(a.mac.clone(), now);
            self.alerts += 1;
            let d = events::device(self.reg.get(&a.mac).unwrap());
            self.emit("alert", json!({"device": d, "hit": events::hit(best)}));
        }
        if !self.cfg.json && (alert || self.last_logged.get(&a.mac).is_none_or(|t| now - t >= LOG_THROTTLE_MS)) {
            self.last_logged.insert(a.mac.clone(), now);
            ui::out(&match_block(&a, best, self.reg.get(&a.mac).unwrap(), alert));
        }
    }

    /// Emits `match` when a device's best (held) hit changes label or tier, `hit: null` when it clears.
    fn maybe_match_event(&mut self, mac: &str) {
        let t = self.reg.get(mac).unwrap();
        let now_state = t.hits.first().map(|h| (h.label.clone(), h.tier()));
        let before = self.match_state.get(mac).cloned().flatten();
        if now_state == before {
            return;
        }
        let body = json!({"device": events::device(t), "hit": t.hits.first().map(events::hit)});
        self.match_state.insert(mac.to_string(), now_state);
        self.emit("match", body);
    }

    fn classify(&mut self, a: &Advert, now: i64) -> Classified {
        let mac_vendor = vendor::mac_vendor(&a.mac);
        let companies: Vec<&str> = a.manufacturer_data.keys().filter_map(|&k| vendor::company(k)).collect();
        let wps = a.wifi.as_ref().and_then(|w| w.wps.clone());
        let vendor = mac_vendor.map(str::to_string).or(wps).or(companies.first().map(|s| s.to_string()));
        let vendors: Vec<&str> = mac_vendor.into_iter().chain(companies.iter().copied()).collect();
        if !self.whitelist.hits(&a.mac, a.name.as_deref(), &vendors).is_empty() {
            return Classified { time: now, hits: Vec::new(), vendor, whitelisted: true };
        }
        // Per-packet rules, the watchlist, matches carried over from a rotated address and the
        // patrol-vehicle cluster, then fused into one calibrated score.
        let mut raw = signatures::classify(a);
        raw.extend(self.watchlist.hits(&a.mac, a.name.as_deref(), &vendors));
        raw.extend(self.reg.inherited_hits(&a.mac));
        raw.extend(self.reg.cluster_hit(&a.mac, now));
        raw.retain(|h| self.cfg.all_categories || h.category.default_enabled());
        Classified { time: now, hits: fusion::fuse(raw), vendor, whitelisted: false }
    }

    /// A radio task failed: report once per distinct message, keep running on the other radio.
    fn radio_error(&mut self, component: &'static str, message: String) {
        if self.radios.get(component).is_some_and(|s| *s == format!("error: {message}")) {
            return;
        }
        self.radios.insert(component, format!("error: {message}"));
        if !self.cfg.json {
            ui::note(&format!("{} {component}: {message}", ui::red("✗")));
        }
        self.emit("error", json!({"component": component, "message": message}));
    }

    /// Refreshes the spinner line and the API's device snapshot once a second.
    fn live(&mut self) {
        let ble = self.reg.tracks().filter(|t| t.advert.is_ble()).count();
        let flagged = self.reg.tracks().filter(|t| !t.hits.is_empty()).count();
        let flag = if flagged > 0 { ui::orange(&format!("{flagged} flagged")) } else { ui::green("all clear") };
        ui::status(format!("scanning  {}  {} BLE · {} WiFi  {}  {}",
            ui::dim("│"), ui::bold(&ble.to_string()), ui::bold(&(self.reg.len() - ble).to_string()),
            ui::dim(&format!("│  {:>3} adv/s  │", self.adverts_sec)), flag));
        self.adverts_sec = 0;
        if let Some(sh) = &self.shared {
            let mut all: Vec<&Track> = self.reg.tracks().collect();
            all.sort_by_key(|t| (t.hits.is_empty(), std::cmp::Reverse(t.advert.rssi)));
            *sh.devices.write().unwrap() = Value::Array(all.into_iter().map(events::device).collect());
        }
    }

    fn housekeeping(&mut self) {
        let now = detect::now_ms();
        self.housekeeping_store(now);
        for t in self.reg.prune(now) {
            self.match_state.remove(&t.mac);
            self.rid_sent.remove(&t.mac);
            self.emit("device_lost", json!({"device_id": t.device_id, "mac": t.mac, "name": t.name, "vendor": t.vendor,
                "first_seen": t.first_seen, "last_seen": t.last_seen}));
        }
        self.classified.retain(|_, c| now - c.time <= registry::PRUNE_AFTER_MS);
        self.last_logged.retain(|_, t| now - *t <= LOG_THROTTLE_MS);
        self.last_alerted.retain(|_, t| now - *t <= ALERT_DEDUPE_MS);

        let ble = self.reg.tracks().filter(|t| t.advert.is_ble()).count();
        let flagged = self.reg.tracks().filter(|t| !t.hits.is_empty()).count();
        let status = json!({
            "devices": self.reg.len(), "ble": ble, "wifi": self.reg.len() - ble, "flagged": flagged,
            "adverts_per_s": self.adverts_window as f64 / STATUS_EVERY.as_secs_f64(), "alerts": self.alerts,
            "uptime_s": (now - self.start) / 1000, "radios": self.radios,
        });
        self.adverts_window = 0;
        if let Some(sh) = &self.shared {
            *sh.status.write().unwrap() = events::envelope(&self.cfg.sensor, now, "status", status.clone());
        }
        self.emit("status", status);
        if !ui::animated() && !self.cfg.json {
            eprintln!("{} status: {} devices, {} flagged", clock(now), self.reg.len(), flagged);
        }
        if self.cfg.list {
            self.list(now);
        }
    }

    /// Flushes devices to the database and applies retention.
    fn housekeeping_store(&mut self, now: i64) {
        let Some(st) = &mut self.store else { return };
        let res = st.flush_devices(self.reg.tracks(), now)
            .and_then(|_| st.prune(now - self.cfg.retention_days * 86_400_000));
        if let Err(e) = res {
            ui::note(&format!("db: {e}"));
        }
    }

    fn list(&mut self, now: i64) {
        let mut all: Vec<&Track> = self.reg.tracks().collect();
        all.sort_by_key(|t| (t.hits.is_empty(), std::cmp::Reverse(t.advert.rssi)));
        if self.cfg.json {
            let devices: Vec<Value> = all.into_iter().map(events::device).collect();
            for d in devices {
                self.emit("device", json!({"device": d}));
            }
            return;
        }
        let mut s = format!("\n  {}  {}\n  {}\n", ui::bold(&format!("{} devices", all.len())), ui::dim(&clock(now)),
            ui::dim(&format!("{:<5} {:<17} {:<9}  {:<26} {:<26} MATCH", "RADIO", "ADDRESS", "SIGNAL", "NAME", "VENDOR")));
        for t in all {
            let m = if t.whitelisted { ui::dim("whitelisted") } else {
                t.hits.first().map_or(String::new(), |h| tier_color(h.tier(), &format!("{} {}", h.category.tag(), h.confidence)))
            };
            let new = if t.first_seen_ever.is_none() && self.store.is_some() { ui::purple(" new") } else { String::new() };
            s += &format!("  {:<5} {} {}  {:<26} {}  {m}{new}\n", radio(t.advert.is_ble()), ui::dim(&format!("{:<17}", t.mac)), bars(t.advert.rssi),
                trunc(t.name.as_deref().unwrap_or("·"), 26), ui::dim(&format!("{:<26}", trunc(t.vendor.as_deref().unwrap_or("·"), 26))));
        }
        ui::out(&s);
    }

    fn summary(&self) {
        if self.cfg.json {
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

/// "▂▄▆█  -52" style signal gauge, fixed width.
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

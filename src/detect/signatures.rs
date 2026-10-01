//! Built-in payload / name / UUID / SSID signatures (RF Sentinel's `SignatureEngine`).
//! MAC-prefix signatures for law-enforcement vendors live in the watchlist presets.
//! Every row cites its source; see docs/SIGNATURES.md upstream for provenance.

use super::{contains_ascii, is_locally_administered, remote_id, short_of, uuid16, Advert, Category, Hit};
use super::vendor::PrefixTable;
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;
use uuid::Uuid;

const ACAB: &str = "all-cameras-are-beacons signature reference (Apache-2.0)";
const SIG: &str = "Bluetooth SIG assigned numbers";
const IEEE: &str = "IEEE registry";
const ASTM: &str = "ASTM F3411 Remote ID (opendroneid-core-c, Apache-2.0)";

// Bluetooth SIG company IDs (manufacturer data, AD 0xFF).
const CID_APPLE: u16 = 0x004C;
const CID_TASER: u16 = 0x034D;
const CID_MOTOROLA: u16 = 0x04EC;
const CID_XUNTONG: u16 = 0x09C8; // BT module in Flock hardware
const CID_LUXOTTICA: u16 = 0x0D53;
const CID_SNAPCHAT: u16 = 0x03C2;
const CID_VUZIX: u16 = 0x060C;
const CID_META: u16 = 0x01AB;
const CID_META_TECH: u16 = 0x058E; // shared with Quest

// 16-bit service UUIDs.
const AXON_UUIDS: [(u16, &str); 3] = [(0xFC81, "Axon Enterprise"), (0xFE6B, "TASER International"), (0xFE6C, "TASER International")];
const MOTOROLA_UUIDS: [u16; 2] = [0xFD8E, 0xFE04];
const RAVEN_SHORTS: [(u16, &str); 5] = [(0x3100, "GPS"), (0x3200, "power"), (0x3300, "network"), (0x3400, "upload"), (0x3500, "error")];
pub const UUID_REMOTE_ID: u16 = 0xFFFA;
const UUID_SMARTTAG: u16 = 0xFD5A;
const UUID_TILE: u16 = 0xFEED;
const UUID_GOOGLE_FMDN: u16 = 0xFEAA;
const UUID_SPECTACLES: u16 = 0xFE45;
const META_UUIDS: [u16; 2] = [0xFEB7, 0xFEB8];
const ZEBRA_UUIDS: [u16; 2] = [0xFE79, 0xFD66];

/// HeyCyan glasses SDK service; must match all 16 bytes (Apple ANCS differs by 2).
const HEYCYAN: Uuid = Uuid::from_u128(0x7905fff0_b5ce_4e99_a40f_4b1e122d00d0);
static HEYCYAN_REVERSED: LazyLock<Uuid> = LazyLock::new(|| {
    let mut b = *HEYCYAN.as_bytes();
    b.reverse();
    Uuid::from_bytes(b)
});

static DRONE_PREFIXES: LazyLock<PrefixTable> = LazyLock::new(|| {
    let mut v: Vec<(&str, &'static str)> = Vec::new();
    for p in ["60601F", "34D262", "481CB9", "E47A2C", "58B858", "04A85A", "8C5823", "0C9AE6", "882985", "4C43F6"] { v.push((p, "DJI")); }
    for p in ["9C5A8A", "EC72F7", "3491F0"] { v.push((p, "DJI Baiwang (DJI subsidiary)")); }
    for p in ["00121C", "00267E", "9003B7", "903AE6", "A0143D"] { v.push((p, "Parrot")); }
    v.extend([
        ("381D14", "Skydio"), ("EC5BCDE", "Autel Robotics"), ("E0B6F58", "Yuneec"),
        ("EC715E", "Freefly Systems"), ("B030C8", "Teal Drones"), ("001AF9", "AeroVironment"),
        ("8C1F64B07", "AeroVironment"), ("34B5F32", "Inspired Flight"), ("AC86D17", "Quantum Systems"),
        ("8C1F640F1", "ideaForge"), ("8C1F64A2D", "ACSL"), ("74B80F", "Zipline"),
        ("24A10D7", "Cyon Drones"), ("B44D43A", "UAV Navigation"), ("14DD48", "Shield AI"),
        ("E8B470C", "Anduril Industries"),
    ]);
    PrefixTable::new(&v)
});

static CAMERA_PREFIXES: LazyLock<PrefixTable> = LazyLock::new(|| {
    let mut v: Vec<(&str, &'static str)> = Vec::new();
    for p in ["A41162", "FC9C98", "486264"] { v.push((p, "Arlo")); }
    for p in ["3CA070", "70AD43", "741348", "74AB93", "C819D8", "F074C1"] { v.push((p, "Blink (Amazon)")); }
    v.extend([
        ("38F25D", "Ezviz"), ("14BA88", "Uniview"), ("3446632", "Amcrest"), ("A4DA222", "Wyze"),
        ("0C0EC14", "Swann"), ("542B57", "Night Owl"), ("D0C193", "SkyBell"), ("B0B3537", "WUUK"),
    ]);
    PrefixTable::new(&v)
});

static PENGUIN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^Penguin-[0-9]+$").unwrap());
static FS_HEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^FS-[0-9A-Fa-f]+$").unwrap());
/// Zebra's default name is the serial: 2-char plant, 3-letter model code, YYWW + 5 digits.
static ZEBRA_SERIAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Z0-9]{2}[A-Z]{3}[0-9]{9}$").unwrap());

/// All matching signatures, strongest first.
pub fn classify(a: &Advert) -> Vec<Hit> {
    let mut hits = if a.is_ble() { classify_ble(a) } else { classify_wifi(a) };
    hits.sort_by(|x, y| y.confidence.cmp(&x.confidence));
    hits
}

fn classify_ble(a: &Advert) -> Vec<Hit> {
    let mut hits = Vec::new();
    let name = a.name.as_deref().unwrap_or("").trim();
    let lname = name.to_lowercase();
    let shorts: HashSet<u16> = a.service_uuids.iter().filter_map(short_of).collect();
    let all_shorts: HashSet<u16> = shorts.iter().copied().chain(a.service_data.keys().filter_map(short_of)).collect();
    let mfg = |cid: u16| a.manufacturer_data.get(&cid);

    // ---- Body cams ----
    if a.service_data.values().chain(a.manufacturer_data.values()).any(|p| contains_ascii(p, "BWCDEVICE")) {
        hits.push(Hit::new(Category::BodyCam, "Axon body camera", 90,
            "Advert payload carries Axon's \"BWCDEVICE\" tag (works even with a randomized address)",
            format!("{ACAB} - field-validated against visually confirmed cameras")));
    }
    if mfg(CID_TASER).is_some() {
        hits.push(Hit::new(Category::BodyCam, "Axon / TASER equipment (type unknown)", 60,
            "Manufacturer data from company ID 0x034D (TASER International)",
            format!("{SIG}; ID spans body cams, holster sensors, TASER handles and batteries")));
    }
    if let Some((u, who)) = AXON_UUIDS.iter().find(|(u, _)| all_shorts.contains(u)) {
        hits.push(Hit::new(Category::BodyCam, "Axon / TASER equipment (type unknown)", 60,
            format!("Service UUID 0x{u:04X} ({who})"), SIG));
    }
    if lname.contains("bodyworn remote") {
        hits.push(Hit::new(Category::BodyCam, "Utility BodyWorn camera remote", 80,
            "Advertised name contains \"BodyWorn Remote\"", format!("{ACAB} (nite-oui-collection capture)")));
    }

    // ---- Motorola Solutions ----
    if mfg(CID_MOTOROLA).is_some() || MOTOROLA_UUIDS.iter().any(|u| all_shorts.contains(u)) {
        hits.push(Hit::new(Category::PublicSafety, "Motorola Solutions equipment (radio, camera or accessory)", 45,
            "Motorola Solutions company ID 0x04EC or service UUID 0xFD8E/0xFE04",
            format!("{SIG}; the same IDs are used by retail, school and venue two-way radios")));
    }

    // ---- Mobile ticket printers ----
    if let Some(u) = ZEBRA_UUIDS.iter().find(|u| all_shorts.contains(u)) {
        hits.push(if ZEBRA_SERIAL.is_match(name) {
            Hit::new(Category::PublicSafety, "Zebra mobile printer (e-ticket printer in patrol cars)", 50,
                format!("Service UUID 0x{u:04X} (Zebra) and a factory serial-number name \"{name}\" - an unrenamed \
                    fleet printer. Also used by parking officers, couriers and field technicians"),
                format!("{SIG}; Zebra Link-OS BLE app note (default friendly name = serial); field capture"))
        } else {
            Hit::new(Category::PublicSafety, "Zebra printer", 30,
                format!("Service UUID 0x{u:04X} (Zebra Technologies) - common in warehouses, stores and deliveries"), SIG)
        });
    }

    // ---- Flock Safety ALPR + Raven ----
    let xuntong = mfg(CID_XUNTONG).is_some();
    let with_x = |s: &str| if xuntong { format!("{s} plus XUNTONG module ID 0x09C8") } else { s.to_string() };
    if lname.contains("fs ext battery") {
        hits.push(Hit::new(Category::Alpr, "Flock Safety camera battery", 80, "Advertised name \"FS Ext Battery\"", format!("{ACAB} (ryanohoro research)")));
    } else if PENGUIN.is_match(name) {
        hits.push(Hit::new(Category::Alpr, "Flock Safety device", if xuntong { 80 } else { 70 },
            with_x("Name pattern \"Penguin-<digits>\""), format!("{ACAB} (ryanohoro research)")));
    } else if FS_HEX.is_match(name) {
        let ev = if xuntong { with_x("Name pattern \"FS-<hex>\"") } else { "Name pattern \"FS-<hex>\" (generic white-label prefix - verify)".into() };
        hits.push(Hit::new(Category::Alpr, "Flock Safety device", if xuntong { 80 } else { 70 }, ev, format!("{ACAB} (field capture 2026-06)")));
    } else if lname.starts_with("flock") {
        hits.push(Hit::new(Category::Alpr, "Possible Flock Safety device", 55, "Advertised name starts with \"Flock\" (brand string - verify)", ACAB));
    } else if xuntong {
        hits.push(Hit::new(Category::Alpr, "XUNTONG Bluetooth module (used in Flock hardware)", 45,
            "Company ID 0x09C8 - shared silicon, also in other products", format!("{SIG}; {ACAB}")));
    }
    let raven: Vec<String> = RAVEN_SHORTS.iter().filter(|(u, _)| shorts.contains(u)).map(|(u, w)| format!("0x{u:04X} ({w})")).collect();
    if !raven.is_empty() {
        hits.push(Hit::new(Category::AudioSensor, "Flock Raven audio / gunshot sensor", 80,
            format!("Raven service UUIDs: {}", raven.join(", ")), format!("{ACAB} (field capture)")));
    }

    // ---- Drones ----
    if a.service_data.get(&uuid16(UUID_REMOTE_ID)).is_some_and(|d| remote_id::is_ble_remote_id(d)) {
        hits.push(Hit::new(Category::Drone, "Drone broadcasting Remote ID", 95, "ASTM F3411 Remote ID message on service UUID 0xFFFA", ASTM));
    }
    hits.extend(drone_by_prefix(a));

    // ---- Trackers separated from their owner ----
    if mfg(CID_APPLE).is_some_and(|d| d.len() >= 2 && d[0] == 0x12 && d[1] == 0x19) {
        hits.push(Hit::new(Category::Tracker, "Apple Find My tracker away from its owner (AirTag or compatible)", 70,
            "Apple Find My offline-finding frame (type 0x12, length 0x19 = separated state)", format!("{ACAB}; arXiv 2501.17452")));
    }
    if a.service_data.get(&uuid16(UUID_GOOGLE_FMDN)).is_some_and(|d| d.first() == Some(&0x41)) {
        hits.push(Hit::new(Category::Tracker, "Google Find Hub tracker away from its owner", 70,
            "Find Hub Network frame 0x41 (separated state) on UUID 0xFEAA", format!("Google Find Hub Network Accessory Spec; {ACAB}")));
    }
    if a.service_data.get(&uuid16(UUID_SMARTTAG)).is_some_and(|d| !d.is_empty()) {
        hits.push(Hit::new(Category::Tracker, "Samsung SmartTag", 55, "Service data on UUID 0xFD5A (Samsung)", format!("{SIG}; arXiv 2501.17452")));
    }
    if a.service_data.get(&uuid16(UUID_TILE)).is_some_and(|d| !d.is_empty()) {
        hits.push(Hit::new(Category::Tracker, "Tile tracker", 55, "Service data on UUID 0xFEED (Tile, Inc.)", SIG));
    }

    // ---- Smart / recording glasses ----
    let is_heycyan = |u: &Uuid| *u == HEYCYAN || *u == *HEYCYAN_REVERSED;
    if a.service_uuids.iter().any(is_heycyan) || a.service_data.keys().any(is_heycyan) {
        hits.push(Hit::new(Category::Glasses, "Camera smart glasses (HeyCyan SDK)", 68, "HeyCyan glasses SDK service UUID (full 128-bit match)", format!("{ACAB} (yj_nearbyglasses)")));
    }
    if mfg(CID_LUXOTTICA).is_some() {
        hits.push(Hit::new(Category::Glasses, "Ray-Ban Meta smart glasses", 70, "Company ID 0x0D53 (Luxottica)", SIG));
    }
    if mfg(CID_SNAPCHAT).is_some() || all_shorts.contains(&UUID_SPECTACLES) {
        hits.push(Hit::new(Category::Glasses, "Snap Spectacles camera glasses", 70, "Snapchat company ID 0x03C2 or service UUID 0xFE45", SIG));
    }
    if mfg(CID_VUZIX).is_some() {
        hits.push(Hit::new(Category::Glasses, "Vuzix camera AR glasses", 70, "Company ID 0x060C (Vuzix)", SIG));
    }
    if mfg(CID_META_TECH).is_some_and(|d| contains_ascii(d, "META_RB_GLASS")) {
        hits.push(Hit::new(Category::Glasses, "Ray-Ban / Oakley Meta smart glasses", 72, "Meta manufacturer data carries the META_RB_GLASS token", ACAB));
    }
    if mfg(CID_META).is_some() || META_UUIDS.iter().any(|u| all_shorts.contains(u)) {
        hits.push(Hit::new(Category::Glasses, "Meta hardware - possibly Ray-Ban Meta glasses", 45,
            "Meta Platforms company ID 0x01AB or UUID 0xFEB7/0xFEB8 (also used by Quest headsets)", format!("{SIG}; {ACAB} field capture 2026-07-31")));
    }
    hits
}

fn classify_wifi(a: &Advert) -> Vec<Hit> {
    let mut hits = Vec::new();
    let ssid = a.name.as_deref().unwrap_or("").trim();
    if ssid.to_lowercase().starts_with("flock-") {
        hits.push(Hit::new(Category::Alpr, "Flock Safety camera", 88,
            format!("WiFi network \"{ssid}\" (Flock- prefix: the vendor names its own AP)"), format!("{ACAB} (ryanohoro, GainSec research)")));
    }
    if ssid.starts_with("ARLO_VMB_") || ssid.starts_with("NTGR_VMB_") {
        hits.push(Hit::new(Category::NetworkCamera, "Arlo camera base station", 88,
            format!("WiFi network \"{ssid}\" (Arlo base-station SSID)"), format!("{ACAB} (field capture)")));
    }
    if a.wifi.as_ref().is_some_and(|w| w.ies.iter().any(|(id, ie)| *id == 221 && remote_id::is_wifi_ie(ie))) {
        hits.push(Hit::new(Category::Drone, "Drone broadcasting Remote ID (WiFi)", 95,
            "ASTM F3411 vendor information element (OUI FA:0B:BC) in the WiFi beacon", ASTM));
    }
    if !is_locally_administered(&a.mac) {
        if let Some((prefix, vendor)) = CAMERA_PREFIXES.find(&a.mac) {
            hits.push(Hit::new(Category::NetworkCamera, format!("{vendor} camera, hub or recorder"), 65,
                format!("WiFi address in {vendor}'s registered block {}", fmt_prefix(&prefix)), format!("{IEEE}; {ACAB}")));
        }
    }
    hits.extend(drone_by_prefix(a));
    hits
}

fn drone_by_prefix(a: &Advert) -> Option<Hit> {
    if is_locally_administered(&a.mac) {
        return None;
    }
    let (prefix, vendor) = DRONE_PREFIXES.find(&a.mac)?;
    Some(Hit::new(Category::Drone, format!("{vendor} equipment (drone or controller)"), 60,
        format!("Address in {vendor}'s registered block {}; no Remote ID decoded", fmt_prefix(&prefix)), format!("{IEEE}; {ACAB}")))
}

fn fmt_prefix(hex: &str) -> String {
    hex.as_bytes().chunks(2).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(":")
}

#[cfg(test)]
mod tests {
    //! Ported from upstream DetectionTest.kt.
    use super::*;
    use crate::detect::{Source, Tier, WifiInfo};
    use std::collections::HashMap;

    fn ble() -> Advert {
        Advert::new("C0:11:22:33:44:55", Source::Ble, -60)
    }
    fn named(n: &str) -> Advert {
        Advert { name: Some(n.into()), ..ble() }
    }
    fn mfg(cid: u16, d: &[u8]) -> Advert {
        Advert { manufacturer_data: HashMap::from([(cid, d.to_vec())]), ..ble() }
    }
    fn uuids(u: &[u16]) -> Advert {
        Advert { service_uuids: u.iter().map(|&s| uuid16(s)).collect(), ..ble() }
    }
    fn sdata(u: u16, d: &[u8]) -> Advert {
        Advert { service_data: HashMap::from([(uuid16(u), d.to_vec())]), ..ble() }
    }
    fn wifi(mac: &str, ssid: &str) -> Advert {
        Advert { name: Some(ssid.into()), wifi: Some(WifiInfo { freq_mhz: 2437, ..Default::default() }), ..Advert::new(mac, Source::Wifi, -60) }
    }
    fn best(a: &Advert) -> Option<Hit> {
        classify(a).into_iter().next()
    }

    #[test]
    fn axon_tag_matches_in_either_byte_order() {
        let reversed: Vec<u8> = "AXJANUSBWCDEVICE".bytes().rev().collect();
        let hit = best(&sdata(0xFE6B, &reversed)).unwrap();
        assert_eq!((hit.category, hit.confidence), (Category::BodyCam, 90));
        assert_eq!(best(&sdata(0x1234, b"BWC DEVICE")), None);
    }

    #[test]
    fn axon_sig_identifiers() {
        assert_eq!(best(&mfg(0x034D, &[1, 2])).unwrap().category, Category::BodyCam);
        assert_eq!(best(&uuids(&[0xFC81])).unwrap().category, Category::BodyCam);
    }

    #[test]
    fn motorola_is_weak() {
        let hit = best(&mfg(0x04EC, &[0])).unwrap();
        assert_eq!((hit.category, hit.tier()), (Category::PublicSafety, Tier::Weak));
    }

    #[test]
    fn zebra_printer_needs_serial_name_to_be_probable() {
        let fleet = best(&Advert { name: Some("XXRBJ000000001".into()), ..uuids(&[0xFE79]) }).unwrap();
        assert_eq!((fleet.category, fleet.tier()), (Category::PublicSafety, Tier::Probable));
        let renamed = best(&Advert { name: Some("Warehouse 3".into()), ..uuids(&[0xFE79]) }).unwrap();
        assert_eq!(renamed.tier(), Tier::Weak);
        assert_eq!(best(&named("XXRBJ000000001")), None);
    }

    #[test]
    fn flock_signatures() {
        assert_eq!(best(&wifi("B4:1E:52:00:00:01", "Flock-3F2A1B")).unwrap().confidence, 88);
        assert_eq!(best(&named("FS Ext Battery")).unwrap().confidence, 80);
        assert_eq!(best(&named("Penguin-1234567890")).unwrap().confidence, 70);
        let x = Advert { name: Some("Penguin-1234567890".into()), ..mfg(0x09C8, &[0]) };
        assert_eq!(best(&x).unwrap().confidence, 80);
        assert_eq!(best(&named("FS-BEC46A")).unwrap().confidence, 70);
        assert_eq!(best(&named("Penguin-abc")), None);
        assert_eq!(best(&named("My penguin speaker")), None);
        assert_eq!(best(&wifi("12:00:00:00:00:01", "Atlanta-Falcons")), None);
    }

    #[test]
    fn raven_service_uuid() {
        let hit = best(&uuids(&[0x3100, 0x3400])).unwrap();
        assert_eq!(hit.category, Category::AudioSensor);
        assert!(hit.evidence.contains("0x3100"));
    }

    #[test]
    fn apple_find_my_only_when_separated() {
        let mut separated = vec![0u8; 27];
        separated[0] = 0x12;
        separated[1] = 0x19;
        assert_eq!(best(&mfg(0x004C, &separated)).unwrap().category, Category::Tracker);
        assert_eq!(best(&mfg(0x004C, &[0x12, 0x02, 0, 0])), None);
    }

    #[test]
    fn find_hub_only_frame_0x41() {
        assert_eq!(best(&sdata(0xFEAA, &[0x41, 1, 2])).unwrap().category, Category::Tracker);
        assert_eq!(best(&sdata(0xFEAA, &[0x40, 1, 2])), None);
        assert_eq!(best(&sdata(0xFEAA, &[0x10, 1, 2])), None); // Eddystone-URL
    }

    #[test]
    fn heycyan_needs_full_128_bit_match() {
        let ancs = Uuid::parse_str("7905F431-B5CE-4E99-A40F-4B1E122D00D0").unwrap();
        assert_eq!(best(&Advert { service_uuids: vec![HEYCYAN], ..ble() }).unwrap().category, Category::Glasses);
        assert_eq!(best(&Advert { service_uuids: vec![*HEYCYAN_REVERSED], ..ble() }).unwrap().category, Category::Glasses);
        assert_eq!(best(&Advert { service_uuids: vec![ancs], ..ble() }), None);
    }

    #[test]
    fn glasses_company_ids() {
        assert_eq!(best(&mfg(0x0D53, &[0])).unwrap().confidence, 70);
        assert_eq!(best(&mfg(0x01AB, &[0])).unwrap().tier(), Tier::Weak);
        assert_eq!(best(&mfg(0x058E, &[1, 2, 3])), None);
        assert_eq!(best(&mfg(0x058E, b"xxMETA_RB_GLASSxx")).unwrap().confidence, 72);
    }

    #[test]
    fn drone_maker_prefixes_respect_block_size() {
        let at = |mac: &str| best(&Advert::new(mac, Source::Ble, -60));
        assert_eq!(at("60:60:1F:12:34:56").unwrap().category, Category::Drone); // DJI MA-L
        assert_eq!(at("EC:5B:CD:E1:23:45").unwrap().category, Category::Drone); // Autel MA-M
        assert_eq!(at("EC:5B:CD:01:23:45"), None); // same 24 bits, other /28 block
        assert_eq!(at("62:60:1F:12:34:56"), None); // locally administered
    }

    #[test]
    fn wifi_remote_id_ie() {
        let mut a = wifi("12:00:00:00:00:02", "");
        a.wifi.as_mut().unwrap().ies.push((221, vec![0xFA, 0x0B, 0xBC, 0x0D, 0x01]));
        assert_eq!(best(&a).unwrap().confidence, 95);
    }
}

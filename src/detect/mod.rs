//! Detection core, ported from RF Sentinel's `detect/` package. Pure Rust, no
//! radio or OS types, so it is unit-tested on any machine.

pub mod fusion;
pub mod patrol;
pub mod remote_id;
pub mod signatures;
pub mod vendor;

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    Ble,
    Wifi,
}

/// How trackable an address is (Bluetooth Core Spec Vol 6, Part B, 1.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // Public is only built by the BlueZ scanner
pub enum AddressType {
    Public,
    RandomStatic,
    ResolvablePrivate,
    NonResolvable,
    WifiGlobal,
    WifiLocal,
    Unknown,
}

fn msb(mac: &str) -> Option<u8> {
    mac.get(0..2).and_then(|s| u8::from_str_radix(s, 16).ok())
}

impl AddressType {
    /// Sub-type of a BLE random address from the top two bits of its first byte.
    pub fn of_random(mac: &str) -> Self {
        match msb(mac).map(|b| b >> 6) {
            Some(0b11) => Self::RandomStatic,
            Some(0b01) => Self::ResolvablePrivate,
            Some(0b00) => Self::NonResolvable,
            _ => Self::Unknown, // 0b10 is reserved
        }
    }

    pub fn of_wifi(mac: &str) -> Self {
        match msb(mac) {
            Some(b) if b & 0x02 != 0 => Self::WifiLocal,
            Some(_) => Self::WifiGlobal,
            None => Self::Unknown,
        }
    }
}

/// Locally administered bit set: a randomized address, not a vendor block.
pub fn is_locally_administered(mac: &str) -> bool {
    msb(mac).is_some_and(|b| b & 0x02 != 0)
}

#[derive(Clone, Debug, Default)]
pub struct WifiInfo {
    pub freq_mhz: u32,
    /// Beacon information elements (id, payload).
    pub ies: Vec<(u8, Vec<u8>)>,
    /// WPS manufacturer / model as reported by the AP.
    pub wps: Option<String>,
}

/// One radio observation, normalized from a BLE advertisement or a WiFi scan result.
#[derive(Clone, Debug)]
pub struct Advert {
    /// Normalized "AA:BB:CC:DD:EE:FF".
    pub mac: String,
    pub source: Source,
    pub rssi: i16,
    /// BLE local name, or WiFi SSID.
    pub name: Option<String>,
    pub manufacturer_data: HashMap<u16, Vec<u8>>,
    pub service_uuids: Vec<Uuid>,
    pub service_data: HashMap<Uuid, Vec<u8>>,
    pub tx_power: Option<i16>,
    pub address_type: AddressType,
    pub wifi: Option<WifiInfo>,
    pub timestamp: i64,
}

impl Advert {
    pub fn new(mac: &str, source: Source, rssi: i16) -> Self {
        Advert {
            mac: mac.to_uppercase(),
            source,
            rssi,
            name: None,
            manufacturer_data: HashMap::new(),
            service_uuids: Vec::new(),
            service_data: HashMap::new(),
            tx_power: None,
            address_type: AddressType::Unknown,
            wifi: None,
            timestamp: now_ms(),
        }
    }

    pub fn is_ble(&self) -> bool {
        self.source == Source::Ble
    }
}

const BASE_UUID: u128 = 0x0000_0000_0000_1000_8000_0080_5F9B_34FB;

/// Expands a SIG 16-bit UUID onto the Bluetooth base UUID.
pub fn uuid16(short: u16) -> Uuid {
    Uuid::from_u128(BASE_UUID | ((short as u128) << 96))
}

/// The 16-bit short of a base-UUID-derived UUID, or None for a vendor 128-bit UUID.
pub fn short_of(u: &Uuid) -> Option<u16> {
    let v = u.as_u128();
    (v & !(0xFFFF_FFFFu128 << 96) == BASE_UUID && v >> 112 == 0).then_some((v >> 96) as u16)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Category {
    BodyCam,
    Alpr,
    AudioSensor,
    PublicSafety,
    Drone,
    Tracker,
    Glasses,
    NetworkCamera,
    Custom,
}

impl Category {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_uppercase().as_str() {
            "BODY_CAM" => Self::BodyCam,
            "ALPR" => Self::Alpr,
            "AUDIO_SENSOR" => Self::AudioSensor,
            "PUBLIC_SAFETY" => Self::PublicSafety,
            "DRONE" => Self::Drone,
            "TRACKER" => Self::Tracker,
            "GLASSES" => Self::Glasses,
            "NETWORK_CAMERA" => Self::NetworkCamera,
            "CUSTOM" => Self::Custom,
            _ => return None,
        })
    }

    pub fn tag(self) -> &'static str {
        match self {
            Self::BodyCam => "BODY CAM",
            Self::Alpr => "ALPR",
            Self::AudioSensor => "AUDIO",
            Self::PublicSafety => "PUBLIC SAFETY",
            Self::Drone => "DRONE",
            Self::Tracker => "TRACKER",
            Self::Glasses => "GLASSES",
            Self::NetworkCamera => "CAMERA",
            Self::Custom => "WATCHLIST",
        }
    }

    /// Network cameras are off by default: home cameras are everywhere.
    pub fn default_enabled(self) -> bool {
        self != Self::NetworkCamera
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    Weak,
    Probable,
    Strong,
}

impl Tier {
    pub fn of(confidence: i32) -> Self {
        match confidence {
            80.. => Self::Strong,
            50.. => Self::Probable,
            _ => Self::Weak,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Weak => "weak",
            Self::Probable => "probable",
            Self::Strong => "strong",
        }
    }
}

/// One signature that matched an observation.
#[derive(Clone, Debug, PartialEq)]
pub struct Hit {
    pub category: Category,
    pub label: String,
    pub confidence: i32,
    /// What in the radio data matched, in plain words.
    pub evidence: String,
    /// Where the signature comes from (registry / research citation).
    pub source: String,
}

impl Hit {
    pub fn new(category: Category, label: impl Into<String>, confidence: i32, evidence: impl Into<String>, source: impl Into<String>) -> Self {
        Hit { category, label: label.into(), confidence, evidence: evidence.into(), source: source.into() }
    }

    pub fn tier(&self) -> Tier {
        Tier::of(self.confidence)
    }
}

// ---- byte helpers ----------------------------------------------------------

/// True when `hay` contains the ASCII `needle` in either byte order.
pub fn contains_ascii(hay: &[u8], needle: &str) -> bool {
    let fwd = needle.as_bytes();
    if fwd.is_empty() || hay.len() < fwd.len() {
        return false;
    }
    let rev: Vec<u8> = fwd.iter().rev().copied().collect();
    hay.windows(fwd.len()).any(|w| w == fwd || w == rev.as_slice())
}

/// Printable ASCII, trimmed of NUL padding; None if nothing printable.
pub fn ascii(b: &[u8], from: usize, len: usize) -> Option<String> {
    let s: String = b.get(from..b.len().min(from + len))?
        .iter()
        .filter(|c| (0x20..=0x7E).contains(*c))
        .map(|&c| c as char)
        .collect();
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

pub fn i32le(b: &[u8], i: usize) -> i32 {
    i32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

pub fn u16le(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_types() {
        assert_eq!(AddressType::of_random("C3:11:22:33:44:55"), AddressType::RandomStatic);
        assert_eq!(AddressType::of_random("5A:11:22:33:44:55"), AddressType::ResolvablePrivate);
        assert_eq!(AddressType::of_random("1A:11:22:33:44:55"), AddressType::NonResolvable);
        assert_eq!(AddressType::of_wifi("DA:A1:19:00:00:01"), AddressType::WifiLocal);
        assert_eq!(AddressType::of_wifi("00:25:DF:00:00:01"), AddressType::WifiGlobal);
    }

    #[test]
    fn uuid16_roundtrip() {
        let u = uuid16(0xFFFA);
        assert_eq!(u.to_string(), "0000fffa-0000-1000-8000-00805f9b34fb");
        assert_eq!(short_of(&u), Some(0xFFFA));
        assert_eq!(short_of(&Uuid::parse_str("7905fff0-b5ce-4e99-a40f-4b1e122d00d0").unwrap()), None);
        // 32-bit SIG UUIDs are not 16-bit shorts.
        assert_eq!(short_of(&Uuid::parse_str("1234fffa-0000-1000-8000-00805f9b34fb").unwrap()), None);
    }

    #[test]
    fn ascii_helpers() {
        assert!(contains_ascii(b"xxBWCDEVICExx", "BWCDEVICE"));
        assert!(contains_ascii(b"ECIVEDCWB", "BWCDEVICE"));
        assert!(!contains_ascii(b"BWC DEVICE", "BWCDEVICE"));
        assert_eq!(ascii(b"\0AB C\0\0", 0, 7).as_deref(), Some("AB C"));
        assert_eq!(ascii(b"\0\0", 0, 2), None);
        assert_eq!(ascii(b"ab", 5, 2), None);
    }
}

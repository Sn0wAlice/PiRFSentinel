//! ASTM F3411 drone Remote ID decoder, from the opendroneid-core-c message
//! layout (Apache-2.0). Remote ID is a legally required public broadcast.
//!
//! - BLE: service data UUID 0xFFFA, `[0x0D app code][counter][25-byte message or pack]`
//! - WiFi beacon: vendor IE 221, OUI FA:0B:BC, type 0x0D, then `[counter][message pack]`

use super::{ascii, i32le, u16le};

pub const MESSAGE_SIZE: usize = 25;
const APP_CODE: u8 = 0x0D;

/// Everything decoded so far for one aircraft; messages arrive one type at a time.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Info {
    pub uas_id: Option<String>,
    pub id_type: Option<&'static str>,
    pub ua_type: Option<&'static str>,
    pub status: Option<&'static str>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub altitude_geo_m: Option<f64>,
    pub height_m: Option<f64>,
    pub speed_ms: Option<f64>,
    pub vertical_speed_ms: Option<f64>,
    pub direction_deg: Option<i32>,
    pub operator_latitude: Option<f64>,
    pub operator_longitude: Option<f64>,
    pub self_id: Option<String>,
    pub operator_id: Option<String>,
}

const UA_TYPES: [&str; 16] = [
    "Not declared", "Aeroplane", "Helicopter / multirotor", "Gyroplane", "Hybrid lift (VTOL)",
    "Ornithopter", "Glider", "Kite", "Free balloon", "Captive balloon", "Airship",
    "Parachute", "Rocket", "Tethered powered aircraft", "Ground obstacle", "Other",
];
const ID_TYPES: [&str; 5] = ["None", "Serial number (ANSI/CTA-2063-A)", "CAA registration", "UTM UUID", "Specific session ID"];
const STATUS: [&str; 5] = ["Undeclared", "Ground", "Airborne", "Emergency", "Remote ID system failure"];

pub fn is_ble_remote_id(sd: &[u8]) -> bool {
    sd.len() >= 2 + MESSAGE_SIZE && sd[0] == APP_CODE
}

pub fn is_wifi_ie(ie: &[u8]) -> bool {
    ie.len() >= 4 && ie[..4] == [0xFA, 0x0B, 0xBC, APP_CODE]
}

/// Decodes BLE service data for UUID 0xFFFA, merging into `prev`. None if not Remote ID.
pub fn decode_ble(sd: &[u8], prev: Option<&Info>) -> Option<Info> {
    is_ble_remote_id(sd).then(|| decode_message(sd, 2, prev.cloned().unwrap_or_default()))
}

/// Decodes a WiFi vendor IE payload (starting at the OUI), merging into `prev`.
pub fn decode_wifi_ie(ie: &[u8], prev: Option<&Info>) -> Option<Info> {
    (is_wifi_ie(ie) && ie.len() >= 8).then(|| decode_message(ie, 5, prev.cloned().unwrap_or_default()))
}

fn decode_message(b: &[u8], off: usize, info: Info) -> Info {
    if off >= b.len() {
        return info;
    }
    let kind = b[off] >> 4;
    if kind == 0xF {
        return decode_pack(b, off, info);
    }
    if off + MESSAGE_SIZE > b.len() {
        return info;
    }
    match kind {
        0 => decode_basic_id(b, off, info),
        1 => decode_location(b, off, info),
        3 => Info { self_id: ascii(b, off + 2, 23).or(info.self_id.clone()), ..info },
        4 => decode_system(b, off, info),
        5 => Info { operator_id: ascii(b, off + 2, 20).or(info.operator_id.clone()), ..info },
        _ => info, // 2 = authentication: nothing user-facing
    }
}

fn decode_pack(b: &[u8], off: usize, mut info: Info) -> Info {
    if off + 3 > b.len() {
        return info;
    }
    let (size, count) = (b[off + 1] as usize, b[off + 2] as usize);
    if size != MESSAGE_SIZE || count == 0 || count > 9 {
        return info;
    }
    for i in 0..count {
        let m = off + 3 + i * MESSAGE_SIZE;
        if m + MESSAGE_SIZE > b.len() {
            break;
        }
        if b[m] >> 4 != 0xF {
            info = decode_message(b, m, info); // no nested packs
        }
    }
    info
}

fn decode_basic_id(b: &[u8], off: usize, info: Info) -> Info {
    Info {
        uas_id: ascii(b, off + 2, 20).or(info.uas_id.clone()),
        id_type: ID_TYPES.get((b[off + 1] >> 4) as usize).copied().or(info.id_type),
        ua_type: UA_TYPES.get((b[off + 1] & 0x0F) as usize).copied().or(info.ua_type),
        ..info
    }
}

fn decode_location(b: &[u8], off: usize, info: Info) -> Info {
    let flags = b[off + 1];
    let speed_enc = b[off + 3] as f64;
    let v_speed_enc = b[off + 4] as i8;
    let (lat, lon) = (i32le(b, off + 5), i32le(b, off + 9));
    let direction = b[off + 2] as i32 + if (flags >> 1) & 1 == 1 { 180 } else { 0 };
    let speed = match (b[off + 3], flags & 1) {
        (255, _) => None,
        (_, 1) => Some(speed_enc * 0.75 + 255.0 * 0.25),
        _ => Some(speed_enc * 0.25),
    };
    Info {
        status: STATUS.get((flags >> 4) as usize).copied().or(info.status),
        latitude: if lat != 0 { Some(lat as f64 * 1e-7) } else { info.latitude },
        longitude: if lon != 0 { Some(lon as f64 * 1e-7) } else { info.longitude },
        altitude_geo_m: altitude(u16le(b, off + 15)).or(info.altitude_geo_m),
        height_m: altitude(u16le(b, off + 17)).or(info.height_m),
        speed_ms: speed.or(info.speed_ms),
        vertical_speed_ms: if v_speed_enc == 63 { info.vertical_speed_ms } else { Some(v_speed_enc as f64 * 0.5) },
        direction_deg: if (0..=359).contains(&direction) { Some(direction) } else { info.direction_deg },
        ..info
    }
}

fn decode_system(b: &[u8], off: usize, info: Info) -> Info {
    let (lat, lon) = (i32le(b, off + 2), i32le(b, off + 6));
    Info {
        operator_latitude: if lat != 0 { Some(lat as f64 * 1e-7) } else { info.operator_latitude },
        operator_longitude: if lon != 0 { Some(lon as f64 * 1e-7) } else { info.operator_longitude },
        ..info
    }
}

/// Encoded 0 means "unknown" (-1000 m).
fn altitude(enc: u16) -> Option<f64> {
    (enc != 0).then(|| enc as f64 * 0.5 - 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_id_then_location_merge() {
        let mut basic = vec![0u8; 27];
        basic[0] = 0x0D;
        basic[1] = 7;
        basic[2] = 0x02; // Basic ID, version 2
        basic[3] = (1 << 4) | 2; // serial number, multirotor
        basic[4..22].copy_from_slice(b"1581F5FJD123456789");
        let info = decode_ble(&basic, None).unwrap();
        assert_eq!(info.uas_id.as_deref(), Some("1581F5FJD123456789"));
        assert_eq!(info.ua_type, Some("Helicopter / multirotor"));

        let mut loc = vec![0u8; 27];
        loc[0] = 0x0D;
        loc[1] = 8;
        let m = 2;
        loc[m] = 0x12; // Location, version 2
        loc[m + 1] = 2 << 4; // airborne
        loc[m + 2] = 90;
        loc[m + 3] = 40; // 10 m/s
        loc[m + 5..m + 9].copy_from_slice(&105_000_000i32.to_le_bytes());
        loc[m + 9..m + 13].copy_from_slice(&(-205_000_000i32).to_le_bytes());
        let alt = ((120.0 + 1000.0) / 0.5) as u16;
        loc[m + 15..m + 17].copy_from_slice(&alt.to_le_bytes());
        let info = decode_ble(&loc, Some(&info)).unwrap();
        assert_eq!(info.uas_id.as_deref(), Some("1581F5FJD123456789")); // merged, not replaced
        assert!((info.latitude.unwrap() - 10.5).abs() < 1e-6);
        assert!((info.longitude.unwrap() + 20.5).abs() < 1e-6);
        assert_eq!(info.speed_ms, Some(10.0));
        assert_eq!(info.direction_deg, Some(90));
        assert_eq!(info.altitude_geo_m, Some(120.0));
        assert_eq!(info.status, Some("Airborne"));
    }

    #[test]
    fn wifi_pack_and_garbage() {
        // IE: OUI + type, counter, then a pack of one Basic ID message.
        let mut ie = vec![0xFA, 0x0B, 0xBC, 0x0D, 0x01, 0xF0, 25, 1];
        let mut msg = vec![0u8; 25];
        msg[1] = 1 << 4;
        msg[2..6].copy_from_slice(b"ABCD");
        ie.extend(msg);
        assert_eq!(decode_wifi_ie(&ie, None).unwrap().uas_id.as_deref(), Some("ABCD"));
        // Truncated / wrong inputs never panic.
        assert_eq!(decode_wifi_ie(&ie[..6], None), None);
        assert_eq!(decode_wifi_ie(&ie[..12], None), Some(Info::default()));
        assert_eq!(decode_ble(&[0x0D, 0, 0xF0], None), None);
    }
}

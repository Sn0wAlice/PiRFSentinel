//! Evidence fusion and the rotation-surviving advert fingerprint
//! (RF Sentinel's `EvidenceFusion` and `AdvertFingerprint`).

use super::{patrol, Advert, AddressType, Hit};

const MIN_SUPPORT: i32 = 30;
const FUSED_CAP: i32 = 90;
const SUPPORT_WEIGHT: f64 = 0.5;

/// Noisy-OR of agreeing rules of the same category, each supporting hit
/// discounted by half (rules often share evidence). Hits under 30 never
/// corroborate; fusion alone never passes 90. The patrol hit is derived from the
/// device's own matches, so it is never fused (that would count them twice).
pub fn fuse(hits: Vec<Hit>) -> Vec<Hit> {
    if hits.len() < 2 {
        return hits;
    }
    let mut sorted = hits;
    sorted.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    let Some(ti) = sorted.iter().position(|h| h.source != patrol::SOURCE) else { return sorted };
    let top = &sorted[ti];
    let mut support: Vec<&Hit> = Vec::new();
    for (i, h) in sorted.iter().enumerate() {
        if i != ti && h.source != patrol::SOURCE && h.category == top.category && h.confidence >= MIN_SUPPORT
            && h.label != top.label && !support.iter().any(|s| s.label == h.label)
        {
            support.push(h);
        }
    }
    if support.is_empty() || top.confidence >= FUSED_CAP {
        return sorted;
    }
    let mut miss = 1.0 - top.confidence as f64 / 100.0;
    for s in &support {
        miss *= 1.0 - SUPPORT_WEIGHT * s.confidence as f64 / 100.0;
    }
    let fused = (((1.0 - miss) * 100.0).round() as i32).clamp(top.confidence, FUSED_CAP);
    if fused == top.confidence {
        return sorted;
    }
    let evidence = format!(
        "{}. Corroborated by: {} - combined {}% -> {fused}%",
        top.evidence,
        support.iter().map(|s| format!("{} ({}%)", s.label, s.confidence)).collect::<Vec<_>>().join("; "),
        top.confidence
    );
    sorted[ti] = Hit { confidence: fused, evidence, ..sorted[ti].clone() };
    sorted.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    sorted
}

const CID_APPLE: u16 = 0x004C;

/// Structural fingerprint of a BLE advert that survives address rotation.
/// None for adverts too bare to tell devices apart (Apple-Continuity-only or
/// empty: every iPhone looks alike), so phones never get linked.
pub fn fingerprint(a: &Advert) -> Option<String> {
    if !a.is_ble() {
        return None;
    }
    let name = a.name.as_deref().map(str::trim).filter(|n| !n.is_empty());
    let non_apple = a.manufacturer_data.keys().any(|&k| k != CID_APPLE);
    if name.is_none() && !non_apple && a.service_data.is_empty() && a.service_uuids.is_empty() {
        return None;
    }
    let sorted = |mut v: Vec<String>| { v.sort(); v.join(",") };
    Some(format!(
        "n={}|u={}|d={}|m={}|t={}",
        name.unwrap_or(""),
        sorted(a.service_uuids.iter().map(|u| u.to_string()).collect()),
        sorted(a.service_data.iter().map(|(k, v)| format!("{k}:{}", v.len())).collect()),
        sorted(a.manufacturer_data.iter().map(|(k, v)| format!("{k}:{}", v.len())).collect()),
        a.tx_power.map(|t| t.to_string()).unwrap_or_default(),
    ))
}

/// True when the address is expected to rotate.
pub fn may_rotate(a: &Advert) -> bool {
    a.is_ble() && !matches!(a.address_type, AddressType::Public | AddressType::RandomStatic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{uuid16, Category, Source};
    use std::collections::HashMap;

    fn hit(cat: Category, label: &str, c: i32) -> Hit {
        Hit::new(cat, label, c, "e", "s")
    }

    #[test]
    fn fuses_agreeing_rules() {
        // Watchlisted address 70 + Zebra serial name 50: 1 - 0.30 * 0.75 = 77.5 % (float lands on 77, as upstream).
        let out = fuse(vec![hit(Category::PublicSafety, "zebra", 50), hit(Category::PublicSafety, "watch", 70)]);
        assert!((77..=78).contains(&out[0].confidence));
        assert!(out[0].evidence.contains("Corroborated by: zebra (50%)"));
    }

    #[test]
    fn fusion_guards() {
        // Other category, weak support, same label, patrol hit: no fusion.
        let base = || hit(Category::BodyCam, "a", 60);
        assert_eq!(fuse(vec![base(), hit(Category::Alpr, "b", 70)])[0].confidence, 70);
        assert_eq!(fuse(vec![base(), hit(Category::BodyCam, "b", 29)])[0].confidence, 60);
        assert_eq!(fuse(vec![base(), hit(Category::BodyCam, "a", 55)])[0].confidence, 60);
        let p = Hit::new(Category::BodyCam, "p", 50, "e", patrol::SOURCE);
        assert_eq!(fuse(vec![base(), p])[0].confidence, 60);
        // Cap at 90.
        let many: Vec<Hit> = (0..6).map(|i| hit(Category::BodyCam, &i.to_string(), 85)).collect();
        assert_eq!(fuse(many)[0].confidence, 90);
    }

    #[test]
    fn fingerprint_ignores_apple_only_adverts() {
        let mut a = Advert::new("5A:00:00:00:00:01", Source::Ble, -50);
        a.manufacturer_data = HashMap::from([(CID_APPLE, vec![1, 2, 3])]);
        assert_eq!(fingerprint(&a), None);
        a.service_data = HashMap::from([(uuid16(0xFE6B), vec![0; 8])]);
        let fp = fingerprint(&a).unwrap();
        let mut b = a.clone();
        b.mac = "4B:00:00:00:00:02".into();
        assert_eq!(fingerprint(&b).unwrap(), fp);
    }
}

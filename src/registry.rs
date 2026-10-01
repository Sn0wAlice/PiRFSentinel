//! In-memory state for every device heard recently (RF Sentinel's `DeviceRegistry`):
//! hit holding, address-rotation linking and the patrol-vehicle cluster.
//! Single-threaded: only the main loop touches it.

use crate::detect::{fusion, patrol, remote_id, Advert, Hit};
use std::collections::{HashMap, VecDeque};

/// Devices not heard from for this long are dropped.
pub const PRUNE_AFTER_MS: i64 = 3 * 60_000;
/// How long a device keeps a match after the evidence was last observed.
const HIT_HOLD_MS: i64 = 120_000;
const HISTORY_MAX: usize = 600;
const HISTORY_MIN_SPACING_MS: i64 = 1_000;
const ROTATION_SILENCE_MS: i64 = 1_500;
const ROTATION_WINDOW_MS: i64 = 30_000;
const CLUSTER_EVERY_MS: i64 = 2_000;

pub struct Track {
    pub mac: String,
    pub name: Option<String>,
    pub vendor: Option<String>,
    pub rssi: i16,
    pub ble: bool,
    pub first_seen: i64,
    pub last_seen: i64,
    pub hits: Vec<Hit>,
    pub remote_id: Option<remote_id::Info>,
    history: VecDeque<(i64, i16)>,
    fingerprint: Option<String>,
    /// Patrol-kit role, sticky once known.
    role: Option<String>,
    /// The address this device most likely used before it rotated.
    pub linked_from: Option<String>,
    inherited: Vec<Hit>,
    held: Option<(Hit, i64)>,
}

#[derive(Default)]
pub struct Registry {
    tracks: HashMap<String, Track>,
    groups: (i64, Vec<patrol::Group>),
}

impl Registry {
    pub fn get(&self, mac: &str) -> Option<&Track> {
        self.tracks.get(mac)
    }

    pub fn len(&self) -> usize {
        self.tracks.len()
    }

    pub fn tracks(&self) -> impl Iterator<Item = &Track> {
        self.tracks.values()
    }

    /// Records one observation. Returns true the first time the device is seen.
    pub fn report(&mut self, a: &Advert, hits: &[Hit], vendor: Option<&str>, remote_id: Option<remote_id::Info>, now: i64) -> bool {
        let first = !self.tracks.contains_key(&a.mac);
        if first {
            let t = self.new_track(a, now);
            self.tracks.insert(a.mac.clone(), t);
        }
        let t = self.tracks.get_mut(&a.mac).unwrap();
        if let Some(r) = patrol::role_of(hits, vendor, a.name.as_deref()) {
            t.role = Some(r);
        }
        if let Some(n) = a.name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
            t.name = Some(n.to_string());
        }
        if let Some(v) = vendor {
            t.vendor = Some(v.to_string());
        }
        t.rssi = a.rssi;
        t.ble = a.is_ble();
        t.hits = merge_hits(t, hits, now);
        if remote_id.is_some() {
            t.remote_id = remote_id;
        }
        t.last_seen = now;
        if t.history.back().is_none_or(|&(time, _)| now - time >= HISTORY_MIN_SPACING_MS) {
            t.history.push_back((now, a.rssi));
            if t.history.len() > HISTORY_MAX {
                t.history.pop_front();
            }
        }
        first
    }

    /// New track, linked to a rotated address when exactly one device with the
    /// same advert fingerprint went silent shortly before (two candidates = no link).
    fn new_track(&self, a: &Advert, now: i64) -> Track {
        let fp = fusion::fingerprint(a);
        let mut t = Track {
            mac: a.mac.clone(), name: None, vendor: None, rssi: a.rssi, ble: a.is_ble(), first_seen: now, last_seen: now, hits: Vec::new(), remote_id: None,
            history: VecDeque::new(), fingerprint: fp.clone(), role: None, linked_from: None, inherited: Vec::new(), held: None,
        };
        if fp.is_none() || !fusion::may_rotate(a) {
            return t;
        }
        let mut cands = self.tracks.values().filter(|o| {
            o.fingerprint == fp && o.last_seen <= now - ROTATION_SILENCE_MS && now - o.last_seen <= ROTATION_WINDOW_MS
        });
        let (Some(prev), None) = (cands.next(), cands.next()) else { return t };
        let src = if prev.hits.is_empty() { &prev.inherited } else { &prev.hits };
        t.inherited = src.iter().map(|h| Hit {
            confidence: (h.confidence - 5).max(0),
            evidence: format!("Same device as {} before its address rotated (identical advert fingerprint, {} s gap). Original evidence: {}",
                prev.mac, (now - prev.last_seen) / 1000, h.evidence),
            ..h.clone()
        }).collect();
        t.linked_from = Some(prev.mac.clone());
        t.name = prev.name.clone();
        t.role = prev.role.clone();
        t
    }

    /// Matches carried over from this device's previous (rotated) address.
    pub fn inherited_hits(&self, mac: &str) -> Vec<Hit> {
        self.tracks.get(mac).map(|t| t.inherited.clone()).unwrap_or_default()
    }

    pub fn remote_id_of(&self, mac: &str) -> Option<&remote_id::Info> {
        self.tracks.get(mac)?.remote_id.as_ref()
    }

    /// Patrol-vehicle cluster hit for `mac` (groups recomputed every 2 s).
    pub fn cluster_hit(&mut self, mac: &str, now: i64) -> Option<Hit> {
        if now - self.groups.0 >= CLUSTER_EVERY_MS {
            let members: Vec<patrol::Member> = self.tracks.values().filter_map(|t| {
                Some(patrol::Member {
                    mac: t.mac.clone(), role: t.role.clone()?, first_seen: t.first_seen, last_seen: t.last_seen,
                    samples: t.history.iter().copied().collect(),
                })
            }).collect();
            self.groups = (now, patrol::groups(&members, now));
        }
        patrol::hit_for(mac, &self.groups.1)
    }

    pub fn prune(&mut self, now: i64) {
        self.tracks.retain(|_, t| now - t.last_seen <= PRUNE_AFTER_MS);
    }
}

/// Current matches plus the device's own strongest recent one, held for
/// HIT_HOLD_MS (payload tags are intermittent). The patrol hit is never held.
fn merge_hits(t: &mut Track, hits: &[Hit], now: i64) -> Vec<Hit> {
    if let Some(own) = hits.iter().find(|h| h.source != patrol::SOURCE) {
        let replace = match &t.held {
            None => true,
            Some((h, until)) => now > *until || own.confidence >= h.confidence,
        };
        if replace {
            t.held = Some((own.clone(), 0));
        }
        if let Some((h, until)) = &mut t.held {
            if h.label == own.label {
                *until = now + HIT_HOLD_MS;
            }
        }
    }
    let mut merged = hits.to_vec();
    if let Some((h, until)) = &t.held {
        if now <= *until && !hits.iter().any(|x| x.label == h.label) {
            merged.push(h.clone());
        }
    }
    merged.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{uuid16, AddressType, Category, Source};
    use std::collections::HashMap;

    fn axon(mac: &str) -> Advert {
        let mut a = Advert::new(mac, Source::Ble, -60);
        a.address_type = AddressType::of_random(mac);
        a.service_data = HashMap::from([(uuid16(0xFE6B), vec![0; 6])]);
        a
    }

    #[test]
    fn holds_hit_then_fades() {
        let mut r = Registry::default();
        let a = axon("5A:00:00:00:00:01");
        let h = Hit::new(Category::BodyCam, "cam", 90, "", "");
        r.report(&a, &[h], None, None, 0);
        r.report(&a, &[], None, None, 60_000);
        assert_eq!(r.get(&a.mac).unwrap().hits.len(), 1);
        r.report(&a, &[], None, None, 121_000);
        assert!(r.get(&a.mac).unwrap().hits.is_empty());
    }

    #[test]
    fn links_rotated_address_once() {
        let mut r = Registry::default();
        let h = Hit::new(Category::BodyCam, "cam", 60, "uuid", "");
        r.report(&axon("5A:00:00:00:00:01"), &[h], None, None, 0);
        r.report(&axon("4B:00:00:00:00:02"), &[], None, None, 5_000);
        let t = r.get("4B:00:00:00:00:02").unwrap();
        assert_eq!(t.linked_from.as_deref(), Some("5A:00:00:00:00:01"));
        assert_eq!(r.inherited_hits("4B:00:00:00:00:02")[0].confidence, 55);
        // Two identical silent candidates: no link.
        let mut r2 = Registry::default();
        r2.report(&axon("5A:00:00:00:00:01"), &[], None, None, 0);
        r2.report(&axon("5A:00:00:00:00:03"), &[], None, None, 0);
        r2.report(&axon("4B:00:00:00:00:02"), &[], None, None, 5_000);
        assert!(r2.get("4B:00:00:00:00:02").unwrap().linked_from.is_none());
    }
}

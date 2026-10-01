//! Spots a likely police vehicle from the combination of equipment around it
//! (RF Sentinel's `PatrolCluster`). One Motorola radio or Zebra printer is weak
//! evidence; several different kinds of police-type gear whose signals rise and
//! fall together are most likely installed in the same vehicle.

use super::{Category, Hit};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

pub const SOURCE: &str = "RF Sentinel co-location analysis; each device alone is only weak evidence";

const RECENT_MS: i64 = 60_000;
const ARRIVAL_WINDOW_MS: i64 = 30_000;
const WINDOW_MS: i64 = 120_000;
const MIN_OVERLAP: usize = 8;
const MIN_CORRELATION: f64 = 0.6;
const MIN_SPREAD_DB: f64 = 2.0;

/// One device that can be part of a patrol-vehicle kit.
#[derive(Clone, Debug)]
pub struct Member {
    pub mac: String,
    pub role: String,
    pub first_seen: i64,
    pub last_seen: i64,
    /// RSSI samples (time ms, dBm), roughly one per second.
    pub samples: Vec<(i64, i16)>,
}

#[derive(Debug)]
pub struct Group {
    pub members: Vec<Member>,
    pub roles: HashSet<String>,
    pub correlated: bool,
}

impl Group {
    pub fn confidence(&self) -> i32 {
        (24 + 12 * self.roles.len() as i32 + if self.correlated { 10 } else { 0 }).min(88)
    }
}

fn rules(rows: &[(&str, &'static str)]) -> Vec<(Regex, &'static str)> {
    rows.iter().map(|(r, role)| (Regex::new(&format!("(?i){r}")).unwrap(), *role)).collect()
}

static ROLE_BY_VENDOR: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| rules(&[
    ("axon|taser", "Axon / TASER gear"),
    ("motorola solutions|harris corp|l3harris", "two-way radio"),
    ("cradlepoint|sierra wireless", "vehicle cellular router"),
    ("zebra|ruggedjet|pocketjet", "mobile printer"),
    ("cyberkar", "in-car computer / console"),
    ("getac", "rugged laptop / body cam"),
    ("genetec", "plate reader"),
    ("stalker|decatur|police speed radar", "police radar"),
    ("lightbar|siren controller|patrol products|police vehicle upfit", "emergency-vehicle equipment"),
    ("utility,? inc|digital ally|watchguard|i-pro|zepcam", "police camera"),
]));

static ROLE_BY_NAME: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| rules(&[
    ("^(RJ-4|PJ-[78])", "mobile printer"),
    ("^(BC-0[0-9]|HS-01)", "rugged laptop / body cam"),
]));

/// The patrol-kit role of a device, or None if it's ordinary.
pub fn role_of(all_hits: &[Hit], vendor: Option<&str>, name: Option<&str>) -> Option<String> {
    let hits: Vec<&Hit> = all_hits.iter().filter(|h| h.source != SOURCE).collect();
    if hits.iter().any(|h| h.category == Category::BodyCam) {
        return Some("body camera".into());
    }
    if hits.iter().any(|h| h.category == Category::Alpr) {
        return Some("plate reader".into());
    }
    let texts = vendor.into_iter().chain(hits.iter().filter(|h| h.category == Category::PublicSafety).map(|h| h.label.as_str()));
    for t in texts {
        if let Some((_, role)) = ROLE_BY_VENDOR.iter().find(|(r, _)| r.is_match(t)) {
            return Some(role.to_string());
        }
    }
    let name = name?;
    ROLE_BY_NAME.iter().find(|(r, _)| r.is_match(name)).map(|(_, role)| role.to_string())
}

/// Groups of at least two different roles travelling or parked together.
pub fn groups(members: &[Member], now: i64) -> Vec<Group> {
    let live: Vec<&Member> = members.iter().filter(|m| now - m.last_seen <= RECENT_MS).collect();
    if live.len() < 2 {
        return Vec::new();
    }
    let mut parent: Vec<usize> = (0..live.len()).collect();
    fn find(p: &[usize], mut x: usize) -> usize {
        while p[x] != x {
            x = p[x];
        }
        x
    }
    let mut correlated = HashSet::new();
    for i in 0..live.len() {
        for j in i + 1..live.len() {
            let (a, b) = (live[i], live[j]);
            if a.role == b.role {
                continue;
            }
            let m = motion(&a.samples, &b.samples, now);
            let together = match m {
                Motion::Moving(r) => r >= MIN_CORRELATION,
                // Both parked: signals can't correlate, so arriving together is the only clue.
                Motion::BothFlat => (a.first_seen - b.first_seen).abs() <= ARRIVAL_WINDOW_MS,
                Motion::OneFlat | Motion::TooShort => false,
            };
            if together {
                let (ri, rj) = (find(&parent, i), find(&parent, j));
                parent[ri] = rj;
                if matches!(m, Motion::Moving(_)) {
                    correlated.insert(i);
                    correlated.insert(j);
                }
            }
        }
    }
    let mut by_root: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in 0..live.len() {
        by_root.entry(find(&parent, i)).or_default().push(i);
    }
    by_root
        .into_values()
        .map(|idx| Group {
            roles: idx.iter().map(|&i| live[i].role.clone()).collect(),
            correlated: idx.iter().any(|i| correlated.contains(i)),
            members: idx.iter().map(|&i| live[i].clone()).collect(),
        })
        .filter(|g| g.roles.len() >= 2)
        .collect()
}

/// The cluster hit for `mac`, if it belongs to a group.
pub fn hit_for(mac: &str, groups: &[Group]) -> Option<Hit> {
    let g = groups.iter().find(|g| g.members.iter().any(|m| m.mac == mac))?;
    let me = g.members.iter().find(|m| m.mac == mac)?;
    let others: Vec<String> = g.members.iter().filter(|m| m.mac != mac).map(|m| format!("{} {}", m.role, m.mac)).collect();
    let mut role = me.role.clone();
    if let Some(c) = role.get_mut(0..1) {
        c.make_ascii_uppercase();
    }
    Some(Hit::new(
        Category::PublicSafety,
        format!("{role} in a possible police vehicle ({} kinds of gear together)", g.roles.len()),
        g.confidence(),
        format!("Heard together with {}{}", others.join(", "),
            if g.correlated { " - their signals rise and fall together (same vehicle)" } else { " - they arrived within 30 s of each other" }),
        SOURCE,
    ))
}

#[derive(Debug, PartialEq)]
pub enum Motion {
    /// Both signals vary: Pearson correlation.
    Moving(f64),
    /// Both flat: both parked relative to you.
    BothFlat,
    /// One varies while the other is flat: not moving together.
    OneFlat,
    /// Fewer than MIN_OVERLAP shared seconds.
    TooShort,
}

/// Compares two RSSI series over the last WINDOW_MS, aligned by second.
pub fn motion(a: &[(i64, i16)], b: &[(i64, i16)], now: i64) -> Motion {
    let bucket = |s: &[(i64, i16)]| -> HashMap<i64, f64> {
        s.iter().filter(|(t, _)| now - t <= WINDOW_MS).map(|&(t, r)| (t / 1000, r as f64)).collect()
    };
    let (ba, bb) = (bucket(a), bucket(b));
    let keys: Vec<i64> = ba.keys().filter(|k| bb.contains_key(k)).copied().collect();
    if keys.len() < MIN_OVERLAP {
        return Motion::TooShort;
    }
    let xs: Vec<f64> = keys.iter().map(|k| ba[k]).collect();
    let ys: Vec<f64> = keys.iter().map(|k| bb[k]).collect();
    let n = xs.len() as f64;
    let (mx, my) = (xs.iter().sum::<f64>() / n, ys.iter().sum::<f64>() / n);
    let sx = (xs.iter().map(|x| (x - mx).powi(2)).sum::<f64>() / n).sqrt();
    let sy = (ys.iter().map(|y| (y - my).powi(2)).sum::<f64>() / n).sqrt();
    match (sx < MIN_SPREAD_DB, sy < MIN_SPREAD_DB) {
        (true, true) => Motion::BothFlat,
        (true, false) | (false, true) => Motion::OneFlat,
        _ => {
            let cov = xs.iter().zip(&ys).map(|(x, y)| (x - mx) * (y - my)).sum::<f64>() / n;
            Motion::Moving(cov / (sx * sy))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(mac: &str, role: &str, first: i64, f: impl Fn(i64) -> i16) -> Member {
        let samples = (0..20).map(|s| (s * 1000, f(s))).collect();
        Member { mac: mac.into(), role: role.into(), first_seen: first, last_seen: 19_000, samples }
    }

    #[test]
    fn moving_together_groups_with_bonus() {
        let wave = |s: i64| (-70 + ((s % 10) * 3)) as i16;
        let ms = [member("A", "two-way radio", 0, wave), member("B", "mobile printer", 0, move |s| wave(s) - 5)];
        let g = groups(&ms, 20_000);
        assert_eq!(g.len(), 1);
        assert!(g[0].correlated);
        assert_eq!(g[0].confidence(), 24 + 24 + 10);
        assert!(hit_for("A", &g).unwrap().label.starts_with("Two-way radio in a possible police vehicle"));
    }

    #[test]
    fn parked_needs_close_arrival_and_one_moving_never_groups() {
        let flat = |_| -60i16;
        let parked = [member("A", "two-way radio", 0, flat), member("B", "mobile printer", 10_000, flat)];
        assert_eq!(groups(&parked, 20_000).len(), 1);
        let late = [member("A", "two-way radio", 0, flat), member("B", "mobile printer", 40_000, flat)];
        assert!(groups(&late, 20_000).is_empty());
        let mixed = [member("A", "two-way radio", 0, flat), member("B", "mobile printer", 0, |s| (-80 + s) as i16)];
        assert!(groups(&mixed, 20_000).is_empty());
        let same_role = [member("A", "two-way radio", 0, flat), member("B", "two-way radio", 0, flat)];
        assert!(groups(&same_role, 20_000).is_empty());
    }

    #[test]
    fn roles() {
        let bc = Hit::new(Category::BodyCam, "x", 60, "", "");
        assert_eq!(role_of(&[bc], None, None).as_deref(), Some("body camera"));
        assert_eq!(role_of(&[], Some("Cradlepoint, Inc"), None).as_deref(), Some("vehicle cellular router"));
        assert_eq!(role_of(&[], None, Some("RJ-4230B")).as_deref(), Some("mobile printer"));
        assert_eq!(role_of(&[], Some("Apple, Inc."), Some("iPhone")), None);
    }
}

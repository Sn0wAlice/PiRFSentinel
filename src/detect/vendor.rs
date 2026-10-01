//! Offline IEEE / Bluetooth SIG tables and the editable MAC-prefix watchlist
//! (RF Sentinel's `VendorDb`, `PrefixTable` and `OuiWatchlist`).

use super::{is_locally_administered, Category, Hit};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::LazyLock;

static OUI: LazyLock<HashMap<&'static str, &'static str>> =
    LazyLock::new(|| read_tsv(include_str!("../../assets/vendors/oui.tsv")));
static COMPANIES: LazyLock<HashMap<u16, &'static str>> = LazyLock::new(|| {
    read_tsv(include_str!("../../assets/vendors/bt_company.tsv"))
        .into_iter()
        .filter_map(|(k, v)| Some((u16::from_str_radix(k, 16).ok()?, v)))
        .collect()
});

fn read_tsv(text: &'static str) -> HashMap<&'static str, &'static str> {
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('\t'))
        .collect()
}

/// "8C:1F:64:DF:0" -> "8C1F64DF0".
pub fn hex(mac_or_prefix: &str) -> String {
    mac_or_prefix.trim().to_uppercase().replace(['-', ':'], "")
}

/// IEEE registrant of a MAC, most specific block first (36, 28, then 24 bits).
/// None for randomized addresses, whose leading bytes aren't a vendor block.
pub fn mac_vendor(mac: &str) -> Option<&'static str> {
    if is_locally_administered(mac) {
        return None;
    }
    let h = hex(mac);
    [9, 7, 6].iter().filter(|&&n| h.len() >= n).find_map(|&n| OUI.get(&h[..n]).copied())
}

pub fn company(id: u16) -> Option<&'static str> {
    COMPANIES.get(&id).copied()
}

/// Hex-prefix table with 24/28/36-bit keys.
pub struct PrefixTable(HashMap<String, &'static str>);

impl PrefixTable {
    pub fn new(entries: &[(&str, &'static str)]) -> Self {
        PrefixTable(entries.iter().map(|(k, v)| (hex(k), *v)).collect())
    }

    /// (matched hex prefix, value) for the most specific block containing `mac`.
    pub fn find(&self, mac: &str) -> Option<(String, &'static str)> {
        let h = hex(mac);
        [9, 7, 6].iter().filter(|&&n| h.len() >= n).find_map(|&n| self.0.get(&h[..n]).map(|v| (h[..n].to_string(), *v)))
    }
}

// ---- watchlist ---------------------------------------------------------------

/// One watchlist row. `prefix` is an IEEE block ("AA:BB:CC", "AA:BB:CC:D",
/// "AA:BB:CC:DD:E"), an exact MAC, "name:<text>" or "vendor:<text>".
#[derive(Clone, Debug, Deserialize)]
pub struct OuiEntry {
    pub prefix: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub source: String,
    /// "confirmed", "candidate" or "custom".
    #[serde(default = "confirmed")]
    pub confidence: String,
    pub score: Option<i32>,
    pub category: Option<String>,
}

fn confirmed() -> String {
    "confirmed".into()
}

impl OuiEntry {
    fn is_custom(&self) -> bool {
        self.confidence == "custom"
    }

    fn rule_text(&self) -> &str {
        self.prefix.split_once(':').map_or("", |(_, t)| t.trim())
    }

    fn effective_score(&self) -> i32 {
        self.score.unwrap_or(match self.confidence.as_str() {
            "custom" => 100,
            "candidate" => 50,
            _ => 75,
        })
    }

    fn to_hit(&self, evidence: String) -> Hit {
        let category = self.category.as_deref().and_then(Category::parse)
            .unwrap_or(if self.is_custom() { Category::Custom } else { Category::PublicSafety });
        let source = if self.is_custom() { "Your watchlist".to_string() }
            else if self.source.is_empty() { "Watchlist preset".to_string() }
            else { self.source.clone() };
        Hit::new(category, self.label.clone(), self.effective_score(), evidence, source)
    }
}

static BLOCK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9A-F]{2}(:[0-9A-F]{2}){2}(:[0-9A-F]|:[0-9A-F]{2}:[0-9A-F])?$").unwrap());
static FULL_MAC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$").unwrap());

/// Normalizes a key; None if it is neither a valid block/MAC nor a non-empty name:/vendor: rule.
fn normalize_key(key: &str) -> Option<String> {
    let k = key.trim();
    for rule in ["name:", "vendor:"] {
        if k.len() >= rule.len() && k[..rule.len()].eq_ignore_ascii_case(rule) {
            let text = k[rule.len()..].trim();
            return (!text.is_empty()).then(|| format!("{rule}{text}"));
        }
    }
    let m = k.to_uppercase().replace('-', ":");
    (BLOCK.is_match(&m) || FULL_MAC.is_match(&m)).then_some(m)
}

pub const PRESETS: [(&str, &str); 3] = [
    ("global", include_str!("../../assets/oui_presets/global.json")),
    ("canada", include_str!("../../assets/oui_presets/canada.json")),
    ("us", include_str!("../../assets/oui_presets/us.json")),
];

#[derive(Default)]
pub struct Watchlist {
    /// Address entries keyed by hex digits: 12 = one device, 9/7/6 = IEEE block.
    by_hex: HashMap<String, OuiEntry>,
    name_rules: Vec<OuiEntry>,
    vendor_rules: Vec<OuiEntry>,
}

impl Watchlist {
    /// Loads the named bundled presets plus the user's own entries (which win on
    /// the same key). User entries must be valid: a typo is an error, not a silent skip.
    pub fn load(presets: &[&str], custom: &[OuiEntry]) -> Result<Self, String> {
        let mut entries: Vec<OuiEntry> = Vec::new();
        for name in presets {
            let json = PRESETS.iter().find(|(n, _)| n == name).ok_or(format!("unknown preset {name}"))?.1;
            let list: Vec<OuiEntry> = serde_json::from_str(json).map_err(|e| format!("{name}: {e}"))?;
            entries.extend(list.into_iter().filter_map(|mut e| {
                e.prefix = normalize_key(&e.prefix)?;
                Some(e)
            }));
        }
        for e in custom {
            let prefix = normalize_key(&e.prefix).ok_or(format!("watch: invalid key \"{}\"", e.prefix))?;
            let label = if e.label.is_empty() { prefix.clone() } else { e.label.clone() };
            entries.push(OuiEntry { prefix, label, confidence: "custom".into(), ..e.clone() });
        }
        Ok(Self::build(entries))
    }

    /// A whitelist: same keys as the watchlist, no scores.
    pub fn whitelist(keys: &[String]) -> Result<Self, String> {
        let entries = keys.iter().map(|k| {
            let prefix = normalize_key(k).ok_or(format!("whitelist: invalid key \"{k}\""))?;
            Ok(OuiEntry { prefix, label: "whitelisted".into(), source: String::new(), confidence: "custom".into(), score: None, category: None })
        }).collect::<Result<Vec<_>, String>>()?;
        Ok(Self::build(entries))
    }

    fn build(entries: Vec<OuiEntry>) -> Self {
        let mut w = Watchlist::default();
        for e in entries {
            if e.prefix.starts_with("name:") {
                w.name_rules.retain(|o| o.prefix != e.prefix);
                w.name_rules.push(e);
            } else if e.prefix.starts_with("vendor:") {
                w.vendor_rules.retain(|o| o.prefix != e.prefix);
                w.vendor_rules.push(e);
            } else {
                w.by_hex.insert(hex(&e.prefix), e);
            }
        }
        w
    }

    pub fn len(&self) -> usize {
        self.by_hex.len() + self.name_rules.len() + self.vendor_rules.len()
    }

    /// The address entry for a MAC: exact device, then 36-, 28-, 24-bit block.
    fn find(&self, mac: &str) -> Option<&OuiEntry> {
        let h = hex(mac);
        [12, 9, 7, 6].iter().filter(|&&n| h.len() >= n).find_map(|&n| self.by_hex.get(&h[..n]))
    }

    /// Every watchlist entry that matches, as hits.
    pub fn hits(&self, mac: &str, name: Option<&str>, vendors: &[&str]) -> Vec<Hit> {
        let mut out = Vec::new();
        if let Some(e) = self.find(mac) {
            out.push(e.to_hit(if hex(&e.prefix).len() == 12 {
                format!("Exact address {mac} is on the watchlist")
            } else {
                format!("Address is in the watchlisted block {}", e.prefix)
            }));
        }
        if let Some(name) = name {
            let lower = name.to_lowercase();
            for r in self.name_rules.iter().filter(|r| lower.contains(&r.rule_text().to_lowercase())) {
                out.push(r.to_hit(format!("Name \"{name}\" contains \"{}\"", r.rule_text())));
            }
        }
        for r in &self.vendor_rules {
            let t = r.rule_text().to_lowercase();
            if let Some(v) = vendors.iter().find(|v| v.to_lowercase().contains(&t)) {
                out.push(r.to_hit(format!("Manufacturer \"{v}\" contains \"{}\"", r.rule_text())));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_lookups() {
        assert!(mac_vendor("00:25:DF:11:22:33").unwrap().contains("Axon"));
        assert!(mac_vendor("B4:1E:52:11:22:33").unwrap().contains("Flock"));
        assert!(mac_vendor("EC:5B:CD:E1:22:33").unwrap().to_lowercase().contains("autel"));
        assert_eq!(mac_vendor("DA:A1:19:00:00:01"), None); // randomized
        assert_eq!(company(0x004C), Some("Apple, Inc."));
    }

    #[test]
    fn all_presets_parse_and_keys_are_valid() {
        for (name, json) in PRESETS {
            let raw: Vec<OuiEntry> = serde_json::from_str(json).unwrap();
            for e in &raw {
                assert!(normalize_key(&e.prefix).is_some(), "{name}: bad key {}", e.prefix);
            }
        }
        assert!(Watchlist::load(&["global", "canada", "us"], &[]).unwrap().len() > 50);
        assert!(Watchlist::load(&["nope"], &[]).is_err());
    }

    #[test]
    fn watchlist_matches_most_specific_block() {
        let w = Watchlist::load(&["global", "canada"], &[]).unwrap();
        let axon = w.hits("00:25:DF:12:34:56", None, &[]);
        assert_eq!(axon[0].category, Category::BodyCam);
        assert_eq!(axon[0].confidence, 75);
        // Cyberkar is a 36-bit MA-S block: neighbours in the same /24 must not match.
        assert!(!w.hits("8C:1F:64:DF:01:23", None, &[]).is_empty());
        assert!(w.hits("8C:1F:64:DE:01:23", None, &[]).iter().all(|h| !h.label.to_lowercase().contains("cyberkar")));
        // Name rules are case-insensitive substrings.
        assert!(!w.hits("12:00:00:00:00:00", Some("getac bc-02 cam"), &[]).is_empty());
    }

    #[test]
    fn custom_entries_and_whitelist() {
        let mine: OuiEntry = serde_json::from_str(r#"{"prefix": "aa-bb-cc", "label": "mine"}"#).unwrap();
        let w = Watchlist::load(&["global"], &[mine]).unwrap();
        let h = &w.hits("AA:BB:CC:00:00:01", None, &[])[0];
        assert_eq!((h.confidence, h.category, h.source.as_str()), (100, Category::Custom, "Your watchlist"));
        let bad: OuiEntry = serde_json::from_str(r#"{"prefix": "AA:BB"}"#).unwrap();
        assert!(Watchlist::load(&[], &[bad]).is_err());

        let wl = Watchlist::whitelist(&["name:my airpods".into(), "11:22:33:44:55:66".into()]).unwrap();
        assert!(!wl.hits("00:00:00:00:00:00", Some("Alice's My AirPods"), &[]).is_empty());
        assert!(!wl.hits("11:22:33:44:55:66", None, &[]).is_empty());
        assert!(Watchlist::whitelist(&["name:".into()]).is_err());
    }
}

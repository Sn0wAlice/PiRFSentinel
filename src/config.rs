//! Settings: an optional TOML file (`--config FILE`), then command-line flags on
//! top. Never loaded implicitly, so a manual run can't collide with the service's
//! database or port. See pirfsentinel.example.toml.

use crate::detect::vendor::OuiEntry;
use serde::Deserialize;

pub const USAGE: &str = "usage: pirfsentinel [--config FILE] [--no-ble] [--no-wifi] [--iface wlan0] \
[--wifi-interval 10] [--threshold 50] [--presets global,canada,us] [--all-categories] [--list] [--json] \
[--listen 127.0.0.1:8787] [--db FILE] [--sensor NAME]";

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Name of this sensor in every event (defaults to the hostname).
    pub sensor: String,
    pub ble: bool,
    pub wifi: bool,
    pub iface: String,
    pub wifi_interval: u64,
    /// Confidence at which a match becomes an alert.
    pub threshold: i32,
    pub presets: Vec<String>,
    pub all_categories: bool,
    /// Human mode: print the device table every 30 s. JSON mode: `device` events.
    pub list: bool,
    /// One JSON event per line on stdout instead of the terminal UI.
    pub json: bool,
    /// HTTP API address (e.g. "0.0.0.0:8787"); off when unset. No auth: LAN only.
    pub listen: Option<String>,
    /// SQLite history file; off when unset.
    pub db: Option<String>,
    /// Days of events and devices kept in the database.
    pub retention_days: i64,
    /// Never flagged, never alerted: exact MACs, blocks, "name:<text>", "vendor:<text>".
    pub whitelist: Vec<String>,
    /// Your own watchlist entries, on top of the presets.
    pub watch: Vec<OuiEntry>,
    pub notify: Vec<Notify>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notify {
    pub url: String,
    /// "text" (ntfy-style: title/priority headers + readable body) or "json" (the event as is).
    #[serde(default = "text")]
    pub format: String,
    /// Event types to send.
    #[serde(default = "alert_only")]
    pub events: Vec<String>,
}

fn text() -> String {
    "text".into()
}

fn alert_only() -> Vec<String> {
    vec!["alert".into()]
}

impl Default for Config {
    fn default() -> Self {
        Config {
            sensor: std::fs::read_to_string("/etc/hostname").map(|h| h.trim().to_string()).unwrap_or_default(),
            ble: true, wifi: true, iface: "wlan0".into(), wifi_interval: 10, threshold: 50,
            presets: vec!["global".into()], all_categories: false, list: false, json: false,
            listen: None, db: None, retention_days: 30, whitelist: Vec::new(), watch: Vec::new(), notify: Vec::new(),
        }
    }
}

impl Config {
    /// Loads the config file, then applies command-line flags.
    pub fn from_args(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let args: Vec<String> = args.into_iter().collect();
        let explicit = args.iter().position(|a| a == "--config").map(|i| args.get(i + 1).cloned().ok_or("--config needs a value"));
        let mut c = match explicit.transpose()? {
            Some(path) => Self::load(&path)?,
            None => Config::default(),
        };
        let mut it = args.into_iter();
        while let Some(k) = it.next() {
            let mut val = || it.next().ok_or(format!("{k} needs a value"));
            match k.as_str() {
                "--config" => { val()?; }
                "--no-ble" => c.ble = false,
                "--no-wifi" => c.wifi = false,
                "--all-categories" => c.all_categories = true,
                "--list" => c.list = true,
                "--json" => c.json = true,
                "--iface" => c.iface = val()?,
                "--wifi-interval" => c.wifi_interval = val()?.parse().map_err(|_| "bad --wifi-interval")?,
                "--threshold" => c.threshold = val()?.parse().map_err(|_| "bad --threshold")?,
                "--presets" => c.presets = val()?.split(',').map(str::to_string).collect(),
                "--listen" => c.listen = Some(val()?),
                "--db" => c.db = Some(val()?),
                "--sensor" => c.sensor = val()?,
                "-h" | "--help" => return Err("PiRFSentinel - passive BLE/WiFi surveillance-equipment scanner".into()),
                _ => return Err(format!("unknown argument {k}")),
            }
        }
        if c.wifi_interval == 0 {
            return Err("wifi_interval must be at least 1 s".into());
        }
        if let Some(n) = c.notify.iter().find(|n| n.format != "text" && n.format != "json") {
            return Err(format!("notify {}: format must be \"text\" or \"json\"", n.url));
        }
        Ok(c)
    }

    fn load(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        toml::from_str(&text).map_err(|e| format!("{path}: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn example_config_parses_and_flags_override() {
        let c: Config = toml::from_str(include_str!("../pirfsentinel.example.toml")).unwrap();
        assert!(!c.whitelist.is_empty() && !c.watch.is_empty() && !c.notify.is_empty());
        let path = std::env::temp_dir().join("pirf-test.toml");
        std::fs::write(&path, "threshold = 70\nsensor = \"car\"\n").unwrap();
        let c = Config::from_args(args(&format!("--config {} --threshold 40", path.display()))).unwrap();
        assert_eq!((c.threshold, c.sensor.as_str()), (40, "car"));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(toml::from_str::<Config>("thresold = 3").is_err()); // typo: unknown field
        assert!(Config::from_args(args("--threshold")).is_err());
        assert!(Config::from_args(args("--wifi-interval 0")).is_err());
        assert!(Config::from_args(args("--bogus")).is_err());
    }
}

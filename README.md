# PiRFSentinel

Passive BLE + WiFi surveillance-equipment scanner for Raspberry Pi, in Rust.
Port of [RF Sentinel](https://github.com/CIS-C0/RFSentinel) (GPL-3.0): same
signatures, watchlist presets, evidence fusion, address-rotation linking,
patrol-vehicle clustering and Remote ID decoding. Receive-only.

## Build & run (on the Pi)

```bash
sudo apt install libdbus-1-dev iw
cargo build --release
./target/release/pirfsentinel --presets global,canada --threshold 50
```

BLE goes through BlueZ (D-Bus); WiFi runs `iw dev wlan0 scan -u` (as root, or via `sudo -n`).

| Option | Default | |
|---|---|---|
| `--no-ble` / `--no-wifi` | both on | |
| `--iface` | `wlan0` | WiFi interface |
| `--wifi-interval` | `10` | seconds between WiFi scans |
| `--threshold` | `50` | confidence at which a match prints `ALERT` |
| `--presets` | `global` | `global`, `canada`, `us` |
| `--all-categories` | off | also network/home cameras |
| `--list` | off | print every device heard (strongest first) with each 30 s status |

Matches go to stdout (`ALERT` above threshold, once per device per 5 min; `match`
otherwise, once per 30 s), status to stderr.

```bash
cargo test
```

## Not ported yet

GPS (followers, known ALPR map, traces), device identification of ordinary
devices, storage/export, web UI, IMSI-catcher heuristics (needs a modem).

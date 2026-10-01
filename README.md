# PiRFSentinel

Passive BLE + WiFi surveillance-equipment scanner for Raspberry Pi, in Rust.
Port of [RF Sentinel](https://github.com/CIS-C0/RFSentinel) (GPL-3.0): same
signatures, watchlist presets, evidence fusion, address-rotation linking,
patrol-vehicle clustering and Remote ID decoding. Receive-only.

## Build & run (on the Pi)

```bash
sudo apt install libdbus-1-dev iw
cargo build --release
sudo install -m 755 target/release/pirfsentinel /usr/local/bin/rfs
rfs --list
```

BLE goes through BlueZ (D-Bus); WiFi runs `iw dev wlan0 scan -u` (as root, or via `sudo -n`).

## Options

Everything can live in a TOML file (`--config FILE`, see
[pirfsentinel.example.toml](pirfsentinel.example.toml)); flags override it.

| Flag | Config key | Default | |
|---|---|---|---|
| `--config FILE` | | | TOML config |
| `--no-ble` / `--no-wifi` | `ble` / `wifi` | on | |
| `--iface` | `iface` | `wlan0` | WiFi interface |
| `--wifi-interval` | `wifi_interval` | `10` | seconds between WiFi scans |
| `--threshold` | `threshold` | `50` | confidence at which a match becomes an alert |
| `--presets` | `presets` | `global` | `global`, `canada`, `us` |
| `--all-categories` | `all_categories` | off | also network/home cameras |
| `--list` | `list` | off | device table every 30 s (`device` events in JSON mode) |
| `--json` | `json` | off | one JSON event per line on stdout, no UI |
| `--listen ADDR` | `listen` | off | HTTP API + SSE stream, e.g. `0.0.0.0:8787` (no auth) |
| `--db FILE` | `db` | off | SQLite history |
| `--sensor NAME` | `sensor` | hostname | name in every event |
| | `retention_days` | `30` | database retention |
| | `whitelist` | | MACs / blocks / `name:` / `vendor:` never flagged |
| | `[[watch]]` | | your own watchlist entries |
| | `[[notify]]` | | push to ntfy (`format = "text"`) or any webhook (`"json"`) |

## Outputs

- **Terminal:** banner, live status line, colored match blocks, `--list` table, summary on Ctrl-C.
  Pipes, journald and `NO_COLOR` get plain lines.
- **JSON events** (`--json`, `/stream`, `/events`, webhooks): one stable contract,
  documented in [SCHEMA.md](SCHEMA.md). Real (anonymized) samples of every
  output: [docs/EXAMPLES.md](docs/EXAMPLES.md).
- **HTTP API:** `/health`, `/status`, `/devices`, `/events`, `/stream`.
- **SQLite:** events and every device ever seen (`first_seen_ever`, "new" badge in `--list`).
- **Notifications:** ntfy / webhooks, per event type.

```bash
curl -s localhost:8787/devices | jq '.[] | select(.hits | length > 0)'
curl -N 'localhost:8787/stream?events=alert'
```

## Run as a service

```bash
sudo cp pirfsentinel.example.toml /etc/pirfsentinel.toml   # then edit it
sudo cp deploy/pirfsentinel.service /etc/systemd/system/
sudo systemctl enable --now pirfsentinel
journalctl -u pirfsentinel -f
```

```bash
cargo test
```

## Not ported yet

GPS (followers, known ALPR map, traces), identification of ordinary devices,
MQTT, IMSI-catcher heuristics (needs a modem).

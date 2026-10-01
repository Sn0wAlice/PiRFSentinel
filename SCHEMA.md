# Event schema v1

Every output carries the same JSON events: stdout with `--json` (one per line),
`GET /stream` (Server-Sent Events, the SSE `event:` name is the event type),
`GET /events` (history, from the database) and `format = "json"` webhooks.

Real (anonymized) samples: [docs/EXAMPLES.md](docs/EXAMPLES.md).

Breaking changes bump `v`. New fields may appear at any time; ignore unknown fields.

## Envelope

| Field | Type | |
|---|---|---|
| `v` | int | schema version, `1` |
| `event` | string | event type, below |
| `sensor` | string | sensor name (config `sensor`, default hostname) |
| `ts` | int | Unix time, milliseconds |
| `time` | string | same instant, ISO 8601 UTC (`2026-10-01T10:12:29.123Z`) |

## Events

| `event` | When | Body | Stored in db |
|---|---|---|---|
| `start` | once at startup | `version`, `config` (radios, threshold, presets, sizes of lists, enabled outputs) | no |
| `status` | every 30 s | `devices`, `ble`, `wifi`, `flagged`, `adverts_per_s`, `alerts`, `uptime_s`, `radios` (`{"ble": "ok" \| "starting" \| "off" \| "error: …"}`) | no |
| `device_new` | first time an address is heard this run | `device` | no |
| `device_lost` | address silent for 3 min | `device_id`, `mac`, `name`, `vendor`, `first_seen`, `last_seen` | no |
| `match` | a device's best match changes (label or tier), including the first match; `hit: null` when it clears | `device`, `hit` | yes |
| `alert` | best match ≥ threshold, at most once per address per 5 min; never for trackers | `device`, `hit` | yes |
| `remote_id` | a drone's decoded Remote ID changed (at most 1/s per drone) | `device_id`, `mac`, `remote_id` | yes |
| `error` | a radio failed (once per distinct message) | `component` (`ble` / `wifi`), `message` | yes |
| `device` | every 30 s per device, only with `--list --json` | `device` | no |

`match` follows state (it is not throttled by time); `alert` is the
notification-grade signal.

## Objects

**device**

| Field | Type | |
|---|---|---|
| `device_id` | string | stable across BLE address rotation: the first address of a linked chain |
| `mac` | string | current address, `AA:BB:CC:DD:EE:FF` |
| `radio` | string | `ble` / `wifi` |
| `address_type` | string | `Public`, `RandomStatic`, `ResolvablePrivate`, `NonResolvable`, `WifiGlobal`, `WifiLocal`, `Unknown` |
| `rssi` | int | dBm, latest |
| `name` | string? | BLE name or SSID (null = none / hidden) |
| `vendor` | string? | IEEE registrant, WPS manufacturer/model or Bluetooth company |
| `first_seen`, `last_seen` | int | ms, this run |
| `first_seen_ever` | int? | ms, from the database (null = never seen before, or no db) |
| `sightings` | int | observations this run |
| `linked_from` | string? | previous address before a rotation |
| `whitelisted` | bool | whitelisted devices never have hits |
| `hits` | hit[] | all current matches, strongest first (fused, plus held/inherited ones) |
| `remote_id` | object? | decoded drone Remote ID (below) |
| `raw` | object | `manufacturer_data` (`{"004C": "hex"}`), `service_uuids`, `service_data` (`{uuid: "hex"}`), `tx_power`, and for WiFi `wifi`: `freq_mhz`, `channel`, `wps`, `ies` (`[[id, "hex"], …]`) |

**hit**

| Field | Type | |
|---|---|---|
| `category` | string | `BODY_CAM`, `ALPR`, `AUDIO_SENSOR`, `PUBLIC_SAFETY`, `DRONE`, `TRACKER`, `GLASSES`, `NETWORK_CAMERA`, `CUSTOM` |
| `tier` | string | `weak` (< 50), `probable` (50-79), `strong` (≥ 80) |
| `confidence` | int | 0-100 |
| `label` | string | what it probably is |
| `evidence` | string | what in the radio data matched |
| `source` | string | where the signature comes from |

**remote_id** (all optional): `uas_id`, `id_type`, `ua_type`, `status`,
`latitude`, `longitude`, `altitude_geo_m`, `height_m`, `speed_ms`,
`vertical_speed_ms`, `direction_deg`, `operator_latitude`,
`operator_longitude`, `self_id`, `operator_id`.

## HTTP API

Enabled with `listen`. Read-only, no authentication: bind to `127.0.0.1` or a trusted LAN.

| Endpoint | |
|---|---|
| `GET /health` | `{"ok": true, "version", "schema", "uptime_s"}` |
| `GET /status` | latest `status` event |
| `GET /devices` | array of `device`, flagged first, refreshed every second |
| `GET /events?since=<ms>&event=<type>&limit=<n>` | stored events, newest first (limit ≤ 1000, default 100); needs `db` |
| `GET /stream?events=alert,match` | live SSE; omit `events` for everything |

## Database

SQLite (`db = ...`), WAL mode, safe to read while running:
`events(ts, event, device_id, mac, category, confidence, json)` and
`devices(mac, device_id, radio, first_seen, last_seen, name, vendor, max_confidence, top_label)`.
Rows older than `retention_days` are deleted.

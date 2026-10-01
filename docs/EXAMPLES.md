# Output examples

Real captures from a Raspberry Pi 4 (2026-10-01), **anonymized**: MAC addresses
are consistent fakes (vendor prefix kept for public addresses), SSIDs and personal
device names are replaced, and raw payload bytes are scrambled.

The `Test: …` matches come from a demo config that adds two `[[watch]]` entries
(`vendor:Sony` at 85, `vendor:Apple` at 40) and whitelists `vendor:Microsoft`,
so the capture shows an alert, weak matches and whitelisted devices.

## Terminal

`rfs --config demo.toml --list` (colors and the spinner are not shown here):

```
  pirfsentinel  v0.1.0 · lab · passive BLE/WiFi surveillance scanner
  ──────────────────────────────────────────────────────
  radios     BLE · WiFi wlan0 every 10s
  watchlist  163 entries (global) · 1 whitelisted · alert ≥ 50
  outputs    api http://127.0.0.1:8788 · db /tmp/pirf-test.db · 2 notify target(s)
  ble: scanning on hci0

10:35:38 ALERT  ▌STRONG 85  WATCHLIST  Test: Sony headphones
           EA:9F:A1:7B:3E:C5 BLE -60 dBm  "LE_WH-1000XM4"  Sony Corporation
           ↳ Manufacturer "Sony Corporation" contains "Sony"
10:35:37 match  ▌WEAK 40  WATCHLIST  Test: Apple device
           F6:2C:ED:01:D3:94 BLE -55 dBm  Apple, Inc.
           ↳ Manufacturer "Apple, Inc." contains "Apple"
…

  44 devices  10:36:07
  RADIO ADDRESS           SIGNAL     NAME                       VENDOR                     MATCH
  BLE   60:65:A3:A8:7C:70 ▂▄▆█  -42  ·                          Apple, Inc.                 WATCHLIST 40 new
  BLE   F5:13:F1:BD:B2:37 ▂▄▆█  -43  ·                          Apple, Inc.                 WATCHLIST 40 new
  BLE   4B:74:14:F3:D5:FC ▂▄▆█  -44  ·                          Apple, Inc.                 WATCHLIST 40 new
  BLE   EA:9F:A1:7B:3E:C5 ▂▄▆█  -54  LE_WH-1000XM4              Sony Corporation            WATCHLIST 85 new
  WiFi  1C:0B:8B:07:5A:53 ▂▄▆█  -46  HomeNet                    Ubiquiti Inc                 new
  WiFi  8E:DA:69:12:D9:18 ▂▄▆█  -52  Freebox-A1B2C3             ·                            new
  WiFi  F8:08:4F:16:3C:CA ▂▄▆█  -52  Bbox-1A2B3C4D              Sagemcom Broadband SAS       new
  WiFi  02:09:31:1F:03:39 ▂▄▆█  -53  ·                          ·                            new
  WiFi  1C:0B:8B:75:D0:DD ▂▄▆█  -53  HomeNet                    Ubiquiti Inc                 new
  BLE   3A:37:E4:2A:DA:98 ▂▄▆   -67  ·                          Microsoft                   whitelisted new
  BLE   28:6B:B4:E2:B5:8A ▂▄    -70  Washer                     SJIT Co., Ltd.               new
  …

⠦ scanning  │  26 BLE · 19 WiFi  │  154 adv/s  │  20 flagged
  ✓ 0 min · 45 devices in view · 1 alerts
```

## Plain lines (journald, pipes, `NO_COLOR`)

`journalctl -u pirfsentinel`:

```
2026-10-01T12:38:58+02:00 lab systemd[1]: Starting pirfsentinel.service - PiRFSentinel passive BLE/WiFi surveillance scanner...
2026-10-01T12:38:58+02:00 lab rfkill[8310]: unblock set for type bluetooth
2026-10-01T12:38:58+02:00 lab systemd[1]: Started pirfsentinel.service - PiRFSentinel passive BLE/WiFi surveillance scanner.
2026-10-01T12:38:58+02:00 lab rfs[8316]:   pirfsentinel  v0.1.0 · lab · passive BLE/WiFi surveillance scanner
2026-10-01T12:38:58+02:00 lab rfs[8316]:   ──────────────────────────────────────────────────────
2026-10-01T12:38:58+02:00 lab rfs[8316]:   radios     BLE · WiFi wlan0 every 10s
2026-10-01T12:38:58+02:00 lab rfs[8316]:   watchlist  161 entries (global) · 0 whitelisted · alert ≥ 50
2026-10-01T12:38:58+02:00 lab rfs[8316]:   outputs    api http://0.0.0.0:8787 · db /var/lib/pirfsentinel/pirf.db
2026-10-01T12:38:58+02:00 lab rfs[8316]:   ble: scanning on hci0
2026-10-01T12:39:28+02:00 lab rfs[8316]: 10:39:28 status: 42 devices, 0 flagged
2026-10-01T12:43:58+02:00 lab rfs[8316]: 10:43:58 status: 54 devices, 0 flagged
```

## JSON events

Every event shares the envelope (`v`, `event`, `sensor`, `ts`, `time`); see
[SCHEMA.md](../SCHEMA.md). `rfs --json` prints one per line; pretty-printed here.

### `start`

```json
{
  "config": {
    "all_categories": false,
    "api": true,
    "ble": true,
    "db": true,
    "notify": 2,
    "presets": [
      "global"
    ],
    "threshold": 50,
    "watchlist": 163,
    "whitelist": 1,
    "wifi": true
  },
  "event": "start",
  "sensor": "lab",
  "time": "2026-10-01T10:31:46.169Z",
  "ts": 1790850706169,
  "v": 1,
  "version": "0.1.0"
}
```

### `device_new` (WiFi access point)

```json
{
  "device": {
    "address_type": "WifiGlobal",
    "device_id": "F8:08:4F:16:3C:CA",
    "first_seen": 1790850708725,
    "first_seen_ever": null,
    "hits": [],
    "last_seen": 1790850708725,
    "linked_from": null,
    "mac": "F8:08:4F:16:3C:CA",
    "name": "Bbox-1A2B3C4D",
    "radio": "wifi",
    "raw": {
      "manufacturer_data": {},
      "service_data": {},
      "service_uuids": [],
      "tx_power": null,
      "wifi": {
        "channel": 1,
        "freq_mhz": 2412,
        "ies": [
          [
            221,
            "0010612a2e00e154af"
          ]
        ],
        "wps": "Broadcom Broadcom"
      }
    },
    "remote_id": null,
    "rssi": -52,
    "sightings": 1,
    "vendor": "Sagemcom Broadband SAS",
    "whitelisted": false
  },
  "event": "device_new",
  "sensor": "lab",
  "time": "2026-10-01T10:31:48.726Z",
  "ts": 1790850708726,
  "v": 1
}
```

### `match` (weak, below the alert threshold)

```json
{
  "device": {
    "address_type": "ResolvablePrivate",
    "device_id": "74:88:3E:34:49:74",
    "first_seen": 1790850706273,
    "first_seen_ever": null,
    "hits": [
      {
        "category": "CUSTOM",
        "confidence": 40,
        "evidence": "Manufacturer \"Apple, Inc.\" contains \"Apple\"",
        "label": "Test: Apple device",
        "source": "Your watchlist",
        "tier": "weak"
      }
    ],
    "last_seen": 1790850706273,
    "linked_from": null,
    "mac": "74:88:3E:34:49:74",
    "name": null,
    "radio": "ble",
    "raw": {
      "manufacturer_data": {
        "004C": "0f059137478a38cdaeb878"
      },
      "service_data": {},
      "service_uuids": [],
      "tx_power": 0
    },
    "remote_id": null,
    "rssi": -34,
    "sightings": 1,
    "vendor": "Apple, Inc.",
    "whitelisted": false
  },
  "event": "match",
  "hit": {
    "category": "CUSTOM",
    "confidence": 40,
    "evidence": "Manufacturer \"Apple, Inc.\" contains \"Apple\"",
    "label": "Test: Apple device",
    "source": "Your watchlist",
    "tier": "weak"
  },
  "sensor": "lab",
  "time": "2026-10-01T10:31:46.350Z",
  "ts": 1790850706350,
  "v": 1
}
```

### `alert`

```json
{
  "device": {
    "address_type": "RandomStatic",
    "device_id": "EA:9F:A1:7B:3E:C5",
    "first_seen": 1790850706358,
    "first_seen_ever": null,
    "hits": [
      {
        "category": "CUSTOM",
        "confidence": 85,
        "evidence": "Manufacturer \"Sony Corporation\" contains \"Sony\"",
        "label": "Test: Sony headphones",
        "source": "Your watchlist",
        "tier": "strong"
      }
    ],
    "last_seen": 1790850706358,
    "linked_from": null,
    "mac": "EA:9F:A1:7B:3E:C5",
    "name": "LE_WH-1000XM4",
    "radio": "ble",
    "raw": {
      "manufacturer_data": {
        "012D": "0400c889884b28b4e001d58e5575c32991dcd2"
      },
      "service_data": {
        "0000fe2c-0000-1000-8000-00805f9b34fb": "0030d06e901d17"
      },
      "service_uuids": [
        "0000fe03-0000-1000-8000-00805f9b34fb",
        "0000fe26-0000-1000-8000-00805f9b34fb",
        "0000fe2c-0000-1000-8000-00805f9b34fb"
      ],
      "tx_power": null
    },
    "remote_id": null,
    "rssi": -42,
    "sightings": 1,
    "vendor": "Sony Corporation",
    "whitelisted": false
  },
  "event": "alert",
  "hit": {
    "category": "CUSTOM",
    "confidence": 85,
    "evidence": "Manufacturer \"Sony Corporation\" contains \"Sony\"",
    "label": "Test: Sony headphones",
    "source": "Your watchlist",
    "tier": "strong"
  },
  "sensor": "lab",
  "time": "2026-10-01T10:31:46.360Z",
  "ts": 1790850706360,
  "v": 1
}
```

### `status`

```json
{
  "adverts_per_s": 168.63333333333333,
  "alerts": 0,
  "ble": 24,
  "devices": 42,
  "event": "status",
  "flagged": 0,
  "radios": {
    "ble": "ok",
    "wifi": "ok"
  },
  "sensor": "lab",
  "time": "2026-10-01T10:39:28.557Z",
  "ts": 1790851168557,
  "uptime_s": 30,
  "v": 1,
  "wifi": 18
}
```

### `device_lost`

```json
{
  "device_id": "F6:2C:ED:01:D3:94",
  "event": "device_lost",
  "first_seen": 1790851402361,
  "last_seen": 1790851497375,
  "mac": "F6:2C:ED:01:D3:94",
  "name": null,
  "sensor": "lab",
  "time": "2026-10-01T10:48:22.046Z",
  "ts": 1790851702046,
  "v": 1,
  "vendor": "Apple, Inc."
}
```

## HTTP API

`curl -s localhost:8787/health`

```json
{"ok":true,"schema":1,"uptime_s":313,"version":"0.1.0"}
```

`curl -s localhost:8787/devices | jq '.[0]'` (first of 54 devices)

```json
{
  "address_type": "ResolvablePrivate",
  "device_id": "7E:91:CC:46:56:8B",
  "first_seen": 1790851318850,
  "first_seen_ever": null,
  "hits": [],
  "last_seen": 1790851451340,
  "linked_from": null,
  "mac": "7E:91:CC:46:56:8B",
  "name": null,
  "radio": "ble",
  "raw": {
    "manufacturer_data": {
      "004C": "1006bb14dd73657f"
    },
    "service_data": {},
    "service_uuids": [],
    "tx_power": 12
  },
  "remote_id": null,
  "rssi": -41,
  "sightings": 729,
  "vendor": "Apple, Inc.",
  "whitelisted": false
}
```

`curl -N localhost:8787/stream` (Server-Sent Events, one JSON event per `data:` line)

```
event: device_new
data: {"device":{"address_type":"RandomStatic","device_id":"F5:13:F1:BD:B2:37","first_seen":1790851141766,"first_seen_ever":1790850879091,"hits":[],"last_seen":1790851141766,"linked_from":null,"mac":"F5:13:F1:BD:B2:37","name":null,"radio":"ble","raw":{"manufacturer_data":{"004C":"120240a3"},"service_data":{},"service_uuids":[],"tx_power":null},"remote_id":null,"rssi":-43,"sightings":1,"vendor":"Apple, Inc.","whitelisted":false},"event":"device_new","sensor":"lab","time":"2026-10-01T10:39:01.777Z","ts":1790851141777,"v":1}

event: status
data: {"adverts_per_s":168.63333333333333,"alerts":0,"ble":24,"devices":42,"event":"status","flagged":0,"radios":{"ble":"ok","wifi":"ok"},"sensor":"lab","time":"2026-10-01T10:39:28.557Z","ts":1790851168557,"uptime_s":30,"v":1,"wifi":18}
```

## ntfy notification (`format = "text"`)

What the ntfy server receives for the alert above:

```
POST /your-topic
Title: lab: CUSTOM 85%
Priority: 5
Tags: satellite_antenna

Test: Sony headphones
EA:9F:A1:7B:3E:C5 BLE -42 dBm "LE_WH-1000XM4" (Sony Corporation)
Manufacturer "Sony Corporation" contains "Sony"
```

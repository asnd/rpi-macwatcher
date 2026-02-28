# rpi-macwatcher

A lightweight WiFi network device monitor for **Raspberry Pi 3 / 4 / 5** and **Raspberry Pi Zero 2 W**.

Periodically scans the local network for devices, resolves vendor names from the MAC OUI database, and logs **JOIN** and **LEAVE** events to:
- **syslog** (`/var/log/syslog` / `journalctl`)
- **TinyFlux** time-series CSV database

## Features

- Two mutually exclusive scan modes:
  - **`arp-scan`** (active) — sends ARP requests to every host; reliable, sees all devices
  - **`arpwatch`** (passive/promiscuous) — silently listens for ARP traffic; zero injected packets
- MAC vendor resolution via offline IEEE OUI database (`mac-vendor-lookup`)
- Optional friendly-name mapping (your own `known-macs.conf`)
- Runs as a `systemd` service with automatic restart
- All events stored in a queryable TinyFlux CSV (append-only, O(1) writes)

## Requirements

| Component | Version |
|-----------|---------|
| Raspberry Pi OS (Debian bookworm) | 64-bit recommended |
| Python | 3.10+ |
| arp-scan | ≥ 1.9 |
| arpwatch | ≥ 2.1 (only needed for passive mode) |

## Quick Install

```bash
git clone https://github.com/asnd/rpi-macwatcher.git
cd rpi-macwatcher
sudo bash install.sh
```

The script will:
1. Install system packages (`arp-scan`, `arpwatch`)
2. Create a Python venv and install Python deps
3. Download the IEEE OUI vendor database (once, then offline)
4. Write config to `/etc/macwatcher/config.ini`
5. Enable and start the `macwatcher` systemd service

## Configuration

Edit `/etc/macwatcher/config.ini` then restart the service:

```bash
sudo systemctl restart macwatcher
```

### Key options

```ini
[scanner]
interface     = wlan0          # WiFi interface
scan_mode     = arp-scan       # "arp-scan" OR "arpwatch" (mutually exclusive)
scan_interval = 60             # seconds between scans
miss_threshold = 3             # arp-scan mode: missed polls before LEAVE

[arpwatch]
leave_timeout = 300            # arpwatch mode: seconds of silence before LEAVE

[database]
db_path = /var/lib/macwatcher/events.csv
```

### Friendly device names (optional)

Copy the example and add your devices:

```bash
sudo cp /etc/macwatcher/known-macs.conf.example /etc/macwatcher/known-macs.conf
```

```
# known-macs.conf
aa:bb:cc:dd:ee:ff   Alice's iPhone
11:22:33:44:55:66   Living Room TV
```

Then set `known_macs_file = /etc/macwatcher/known-macs.conf` in `config.ini`.

## Monitoring

```bash
# Live service log (stdout + stderr)
sudo journalctl -u macwatcher -f

# Syslog entries only
sudo grep macwatcher /var/log/syslog

# Service status
sudo systemctl status macwatcher
```

### Sample log output

```
2026-02-28T14:01:00 macwatcher INFO JOIN  mac=aa:bb:cc:dd:ee:ff ip=192.168.1.42  vendor=Apple, Inc.       "Alice's iPhone"
2026-02-28T14:05:00 macwatcher INFO LEAVE mac=aa:bb:cc:dd:ee:ff last_ip=192.168.1.42 vendor=Apple, Inc. "Alice's iPhone"
```

## Scan modes compared

| | `arp-scan` (active) | `arpwatch` (passive) |
|---|---|---|
| Network traffic | Yes (ARP probes) | None |
| Detects idle devices | Yes | Only if they ARP |
| Leave detection | After N missed scans | After N seconds of silence |
| Requires | `arp-scan` binary | `arpwatch` binary |

## Database

Events are stored in a TinyFlux CSV at `/var/lib/macwatcher/events.csv`.

Each row: `timestamp, event (JOIN/LEAVE), mac, vendor, name, ip`

Query example (Python):

```python
from tinyflux import TinyFlux, TagQuery
db = TinyFlux("/var/lib/macwatcher/events.csv")
Tag = TagQuery()
joins = db.search(Tag.event == "JOIN")
```

## Project structure

```
rpi-macwatcher/
├── macwatcher.py              # Main daemon
├── config.ini                 # Default configuration
├── requirements.txt           # Python dependencies
├── macwatcher.service         # systemd unit file
├── install.sh                 # One-command installer
├── known-macs.conf.example    # Friendly name mapping template
├── AGENTS.md                  # AI agent conventions
└── .github/
    └── workflows/
        └── ci.yml             # GitHub Actions CI
```

## License

MIT

"""Unit tests for macwatcher — no hardware required."""

import configparser
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_config(**overrides) -> configparser.ConfigParser:
    """Return a minimal ConfigParser suitable for MacWatcher instantiation."""
    cfg = configparser.ConfigParser()
    cfg.read_dict({
        "scanner": {
            "interface":       "eth0",
            "scan_mode":       "arp-scan",
            "scan_interval":   "30",
            "miss_threshold":  "2",
            "arp_scan_args":   "--localnet",
            "known_macs_file": "",
        },
        "arpwatch": {
            "arpwatch_bin":   "/usr/sbin/arpwatch",
            "arpwatch_dat":   "/tmp/test_arp.dat",
            "arpwatch_extra": "",
            "leave_timeout":  "120",
        },
        "database": {"db_path": ""},  # filled per test
        "logging":  {"log_level": "DEBUG"},
    })
    for section, key, value in (o.split(".", 1) + [v]
                                 for o, v in overrides.items()
                                 for o, v in [(o, v)]):
        cfg.set(section, key, value)
    return cfg


# ── MAC normalisation (arpwatch dat) ─────────────────────────────────────────

def test_normalise_mac_padded():
    """arpwatch compressed MACs are zero-padded to standard form."""
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from macwatcher import _normalise_mac
    assert _normalise_mac("0:1:2:3:4:5")       == "00:01:02:03:04:05"
    assert _normalise_mac("aa:bb:cc:dd:ee:ff")  == "aa:bb:cc:dd:ee:ff"
    assert _normalise_mac("A:B:C:D:E:F")        == "0a:0b:0c:0d:0e:0f"


# ── ARP scan line parsing ─────────────────────────────────────────────────────

def test_arp_line_regex_matches_standard_output():
    from macwatcher import _ARP_LINE
    sample = "192.168.1.10\taa:bb:cc:dd:ee:ff\tApple, Inc."
    m = _ARP_LINE.match(sample)
    assert m is not None
    assert m.group(1) == "192.168.1.10"
    assert m.group(2).lower() == "aa:bb:cc:dd:ee:ff"
    assert "Apple" in m.group(3)


def test_arp_line_regex_rejects_header_lines():
    from macwatcher import _ARP_LINE
    for line in (
        "Interface: wlan0, datalink type: EN10MB",
        "Starting arp-scan 1.9.8",
        "3 hosts scanned. 1 responded",
        "",
    ):
        assert _ARP_LINE.match(line) is None, f"Should not match: {line!r}"


# ── insert_event DB write ─────────────────────────────────────────────────────

def test_insert_event_writes_to_db():
    from macwatcher import insert_event
    from tinyflux import TinyFlux, TagQuery

    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
        db_path = f.name

    db = TinyFlux(db_path)
    insert_event(db, "JOIN", "aa:bb:cc:dd:ee:ff",
                 "192.168.1.5", "Apple, Inc.", "My iPhone")

    Tag = TagQuery()
    results = db.search(Tag.event == "JOIN")
    assert len(results) == 1
    p = results[0]
    assert p.tags["mac"]    == "aa:bb:cc:dd:ee:ff"
    assert p.tags["vendor"] == "Apple, Inc."
    assert p.fields["ip"]   == "192.168.1.5"
    Path(db_path).unlink(missing_ok=True)


def test_insert_event_unknown_vendor_fallback():
    from macwatcher import insert_event
    from tinyflux import TinyFlux, TagQuery

    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
        db_path = f.name

    db = TinyFlux(db_path)
    insert_event(db, "LEAVE", "11:22:33:44:55:66",
                 "10.0.0.1", "", "")   # empty vendor

    Tag = TagQuery()
    results = db.search(Tag.event == "LEAVE")
    assert results[0].tags["vendor"] == "unknown"
    Path(db_path).unlink(missing_ok=True)


# ── load_known_macs ───────────────────────────────────────────────────────────

def test_load_known_macs_parses_file():
    from macwatcher import load_known_macs

    content = (
        "# comment\n"
        "aa:bb:cc:dd:ee:ff  My TV\n"
        "11:22:33:44:55:66  Alice's Phone\n"
        "\n"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
        f.write(content)
        path = f.name

    known = load_known_macs(path)
    assert known["aa:bb:cc:dd:ee:ff"] == "My TV"
    assert known["11:22:33:44:55:66"] == "Alice's Phone"
    assert len(known) == 2
    Path(path).unlink(missing_ok=True)


def test_load_known_macs_returns_empty_for_missing_file():
    from macwatcher import load_known_macs
    assert load_known_macs("/nonexistent/path.conf") == {}


def test_load_known_macs_returns_empty_when_path_blank():
    from macwatcher import load_known_macs
    assert load_known_macs("") == {}


# ── scan_mode validation ──────────────────────────────────────────────────────

def test_invalid_scan_mode_raises():
    import logging
    from macwatcher import MacWatcher

    logger = logging.getLogger("test")
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
        db_path = f.name

    cfg = _make_config()
    cfg.set("scanner", "scan_mode", "nmap")   # invalid
    cfg.set("database", "db_path", db_path)

    with pytest.raises(ValueError, match="scan_mode"):
        MacWatcher(cfg, logger)

    Path(db_path).unlink(missing_ok=True)


# ── ArpWatchMonitor dat-file reader ──────────────────────────────────────────

def test_arpwatch_read_devices_parses_dat():
    from macwatcher import ArpWatchMonitor

    dat_content = (
        "aa:bb:cc:dd:ee:ff\t192.168.1.1\t1700000000\trouter\n"
        "0:1:2:3:4:5\t192.168.1.42\t1700000100\t\n"
        "\n"
        "# bad line\n"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".dat", delete=False) as f:
        f.write(dat_content)
        dat_path = f.name

    cfg = _make_config()
    cfg.set("arpwatch", "arpwatch_dat", dat_path)

    logger = MagicMock()
    monitor = ArpWatchMonitor(cfg, logger)
    devices = monitor.read_devices()

    assert "aa:bb:cc:dd:ee:ff" in devices
    assert devices["aa:bb:cc:dd:ee:ff"] == ("192.168.1.1", 1700000000.0)
    # compressed MAC should be normalised
    assert "00:01:02:03:04:05" in devices

    Path(dat_path).unlink(missing_ok=True)

"""Unit tests for macwatcher — no hardware required."""

import configparser
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_config(**overrides) -> configparser.ConfigParser:
    """Return a minimal ConfigParser suitable for MacWatcher instantiation.

    Keyword arguments are dotted ``section.key=value`` pairs, e.g.::

        _make_config(**{"scanner.scan_mode": "arpwatch"})
    """
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
    for dotted_key, value in overrides.items():
        section, key = dotted_key.split(".", 1)
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
    assert p.tags["ip"]     == "192.168.1.5"
    assert p.fields["count"] == 1
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
    r = results[0]
    assert r.tags["vendor"] == "unknown"
    assert r.fields["count"] == 1
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


# ── Bug #5: load_known_macs must not silently drop MAC-only lines ─────────────

def test_load_known_macs_mac_only_line_stored_with_empty_label():
    """A line with only a MAC (no friendly name) must be kept with label ''
    and a warning must be emitted instead of silently dropping the entry."""
    from macwatcher import load_known_macs

    content = (
        "aa:bb:cc:dd:ee:ff  My TV\n"
        "11:22:33:44:55:66\n"           # MAC only — no name
    )
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
        f.write(content)
        path = f.name

    with patch("logging.Logger.warning") as mock_warn:
        known = load_known_macs(path)

    assert "11:22:33:44:55:66" in known, "MAC-only entry must not be dropped"
    assert known["11:22:33:44:55:66"] == ""
    assert mock_warn.called, "A warning must be emitted for the incomplete line"
    Path(path).unlink(missing_ok=True)


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
    # comment lines and blank lines must not produce entries
    assert len(devices) == 2

    Path(dat_path).unlink(missing_ok=True)


# ── _make_config override helper ─────────────────────────────────────────────

def test_make_config_override_applies_value():
    """_make_config keyword overrides must update the correct section/key."""
    cfg = _make_config(**{"scanner.scan_mode": "arpwatch",
                          "arpwatch.leave_timeout": "600"})
    assert cfg.get("scanner", "scan_mode") == "arpwatch"
    assert cfg.get("arpwatch", "leave_timeout") == "600"


# ── MacWatcher db_path validation ─────────────────────────────────────────────

def test_macwatcher_empty_db_path_raises():
    """MacWatcher must raise ValueError when db_path is empty."""
    import logging
    from macwatcher import MacWatcher

    logger = logging.getLogger("test")
    cfg = _make_config()
    # db_path is "" in the default _make_config
    with pytest.raises(ValueError, match="db_path"):
        MacWatcher(cfg, logger)


# ── Bug #4: load_config must not bleed keys across sections ──────────────────

def test_load_config_no_cross_section_bleed():
    """Keys defined only in [scanner] must not be readable from [database]
    or any other section — ConfigParser defaults= bleed must be absent."""
    from macwatcher import load_config

    cfg = load_config()
    # 'interface' belongs to [scanner]; it must NOT exist in [database]
    assert not cfg.has_option("database", "interface"), (
        "cross-section bleed: 'interface' must not be visible in [database]"
    )
    # 'db_path' belongs to [database]; it must NOT exist in [scanner]
    assert not cfg.has_option("scanner", "db_path"), (
        "cross-section bleed: 'db_path' must not be visible in [scanner]"
    )


# ── Bug #1: arpwatch LEAVE events must fire based on last_seen age ────────────

def test_arpwatch_leave_fires_when_last_seen_is_stale():
    """LEAVE must be emitted for a device whose last_seen timestamp is older
    than leave_timeout, even if the entry is still present in the dat file.
    This verifies the fix for the arpwatch dat-file retention bug."""
    import logging
    import tempfile
    from macwatcher import MacWatcher

    logger = logging.getLogger("test_aw_leave")
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
        db_path = f.name

    cfg = _make_config(
        **{
            "scanner.scan_mode": "arpwatch",
            "arpwatch.leave_timeout": "60",   # 60 s timeout
            "database.db_path": db_path,
        }
    )
    watcher = MacWatcher(cfg, logger)

    stale_ts = time.time() - 120   # 120 s ago → older than 60 s threshold
    watcher.active["aa:bb:cc:dd:ee:ff"] = {
        "ip": "192.168.1.1",
        "vendor": "Apple, Inc.",
        "name": "Test Device",
        "last_seen": stale_ts,
    }

    # Simulate a dat snapshot that still contains the device (arpwatch keeps
    # old entries in the file — the root cause of Bug #1).
    mock_monitor = MagicMock()
    mock_monitor.is_running.return_value = True
    mock_monitor.read_devices.return_value = {
        "aa:bb:cc:dd:ee:ff": ("192.168.1.1", stale_ts),
    }
    watcher._arpwatch = mock_monitor

    watcher._cycle_arpwatch({})

    assert "aa:bb:cc:dd:ee:ff" not in watcher.active, (
        "stale device must have been evicted and a LEAVE event emitted"
    )
    Path(db_path).unlink(missing_ok=True)


# ── Bug #2: interruptible sleep — _running=False exits promptly ───────────────

def test_run_exits_promptly_after_signal():
    """After _running is set to False the main loop must not block for the
    full scan_interval (previously a solid time.sleep(interval) call)."""
    import logging
    import tempfile
    import threading
    from macwatcher import MacWatcher

    logger = logging.getLogger("test_sleep")
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
        db_path = f.name

    # Use a long interval (300 s) to make the old bug obvious: if the sleep
    # is not interruptible the test would hang for 5 minutes.
    cfg = _make_config(
        **{
            "scanner.scan_mode": "arp-scan",
            "scanner.scan_interval": "300",
            "database.db_path": db_path,
        }
    )
    watcher = MacWatcher(cfg, logger)

    # Stub out the scan so it returns immediately with no devices.
    with patch("macwatcher.run_arp_scan", return_value={}):
        def _stop_after_first_cycle():
            # Give the cycle time to complete, then signal shutdown.
            time.sleep(0.3)
            watcher._running = False

        stopper = threading.Thread(target=_stop_after_first_cycle, daemon=True)
        stopper.start()

        start = time.monotonic()
        watcher.run()
        elapsed = time.monotonic() - start

    # Should exit well within 5 seconds, not after 300 s.
    assert elapsed < 5, (
        f"run() took {elapsed:.1f}s — sleep is not interruptible (Bug #2)"
    )
    Path(db_path).unlink(missing_ok=True)


# ── Bug #3: 'macwatcher stopped' must always be logged ───────────────────────

def test_stopped_log_emitted_on_clean_exit():
    """'macwatcher stopped' must appear in the log even on a clean shutdown
    (previously the log call was outside the finally block)."""
    import logging
    import tempfile
    import threading
    from macwatcher import MacWatcher

    logger = logging.getLogger("test_stopped_log")
    logger.setLevel(logging.DEBUG)
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
        db_path = f.name

    cfg = _make_config(
        **{
            "scanner.scan_mode": "arp-scan",
            "scanner.scan_interval": "300",
            "database.db_path": db_path,
        }
    )
    watcher = MacWatcher(cfg, logger)

    logged_messages: list[str] = []

    class _CapHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            logged_messages.append(record.getMessage())

    cap = _CapHandler()
    cap.setLevel(logging.DEBUG)
    logger.addHandler(cap)

    with patch("macwatcher.run_arp_scan", return_value={}):
        def _stop():
            time.sleep(0.3)
            watcher._running = False

        threading.Thread(target=_stop, daemon=True).start()
        watcher.run()

    logger.removeHandler(cap)
    assert any("stopped" in m for m in logged_messages), (
        "'macwatcher stopped' was never logged (Bug #3)"
    )
    Path(db_path).unlink(missing_ok=True)

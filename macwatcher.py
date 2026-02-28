#!/usr/bin/env python3
"""
macwatcher - WiFi network device monitor for Raspberry Pi

Two mutually exclusive scan modes:
  arp-scan  — active scanning: sends ARP requests to every host on the subnet
  arpwatch  — passive / promiscuous: listens for ARP traffic on the wire

Both modes detect device JOIN and LEAVE events and log them to syslog
and a TinyFlux time-series CSV database.  Vendor is resolved from the
MAC OUI via the mac-vendor-lookup package.
"""

import configparser
import logging
import logging.handlers
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from tinyflux import TinyFlux, Point

# ── Default config values (overridden by config.ini) ─────────────────────────
DEFAULTS = {
    # [scanner]
    "scan_mode":         "arp-scan",       # "arp-scan" or "arpwatch"
    "interface":         "wlan0",
    "scan_interval":     "60",
    "miss_threshold":    "3",
    "arp_scan_args":     "--localnet --retry=2",
    "known_macs_file":   "",
    # [arpwatch]
    "arpwatch_bin":      "/usr/sbin/arpwatch",
    "arpwatch_dat":      "/var/lib/macwatcher/arp.dat",
    "arpwatch_extra":    "",               # extra flags for arpwatch
    "leave_timeout":     "300",            # seconds of inactivity → LEAVE
    # [database]
    "db_path":           "/var/lib/macwatcher/events.csv",
    # [logging]
    "log_level":         "INFO",
}

VALID_SCAN_MODES = {"arp-scan", "arpwatch"}

CONFIG_PATHS = [
    "/etc/macwatcher/config.ini",
    os.path.join(os.path.dirname(__file__), "config.ini"),
]


# ── Config & logger ──────────────────────────────────────────────────────────

def load_config() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser(defaults=DEFAULTS)
    cfg.read(CONFIG_PATHS)
    for section in ("scanner", "arpwatch", "database", "logging"):
        if not cfg.has_section(section):
            cfg.add_section(section)
    return cfg


def setup_logger(level_name: str) -> logging.Logger:
    logger = logging.getLogger("macwatcher")
    level = getattr(logging, level_name.upper(), logging.INFO)
    logger.setLevel(level)

    syslog_address = "/dev/log" if Path("/dev/log").exists() else "/var/run/syslog"
    try:
        sh = logging.handlers.SysLogHandler(address=syslog_address)
        sh.setFormatter(logging.Formatter(
            "macwatcher[%(process)d]: %(levelname)s %(message)s"))
        logger.addHandler(sh)
    except OSError:
        pass

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter(
        "%(asctime)s macwatcher %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"))
    logger.addHandler(ch)
    return logger


# ── MAC vendor lookup (OUI) ──────────────────────────────────────────────────

class VendorLookup:
    """Resolve vendor from MAC address using the IEEE OUI database.

    Uses the ``mac-vendor-lookup`` package.  The OUI database is
    downloaded once at install time and cached locally, so subsequent
    look-ups are fully offline.
    """

    def __init__(self, logger: logging.Logger):
        self._logger = logger
        self._mac_lookup = None
        try:
            from mac_vendor_lookup import MacLookup
            ml = MacLookup()
            # Use the cached vendor list; update_vendors() is called once
            # at install time by install.sh.  If no cache exists yet, the
            # bundled fallback in the package is used automatically.
            self._mac_lookup = ml
            self._logger.debug("vendor OUI database loaded")
        except ImportError:
            self._logger.warning(
                "mac-vendor-lookup not installed — vendor resolution disabled"
            )
        except Exception as exc:
            self._logger.warning("vendor DB init failed: %s", exc)

    def lookup(self, mac: str) -> str:
        """Return vendor string for *mac*, or ``""`` on failure."""
        if self._mac_lookup is None:
            return ""
        try:
            return self._mac_lookup.lookup(mac)
        except Exception:
            return ""


# ── Known MACs (optional friendly names) ─────────────────────────────────────

def load_known_macs(path: str) -> dict:
    known: dict[str, str] = {}
    if not path:
        return known
    try:
        with open(path) as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    known[parts[0].lower()] = parts[1]
    except FileNotFoundError:
        pass
    return known


# ── DB helpers ────────────────────────────────────────────────────────────────

def insert_event(db: TinyFlux, event: str, mac: str, ip: str,
                 vendor: str, name: str) -> None:
    # TinyFlux tags = strings, fields = numeric only.
    # IP address is metadata → tag; count=1 satisfies the numeric field req.
    db.insert(Point(
        time=datetime.now(timezone.utc),
        tags={
            "event":  event,
            "mac":    mac,
            "vendor": vendor or "unknown",
            "name":   name or "",
            "ip":     ip,
        },
        fields={"count": 1},
    ))


# ── Active mode: arp-scan ────────────────────────────────────────────────────

_ARP_LINE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s*(.*)"
)


def run_arp_scan(interface: str, extra_args: str,
                 logger: logging.Logger) -> dict | None:
    """Return ``{mac_lower: (ip, arp_scan_vendor)}`` or *None* on failure."""
    cmd = ["arp-scan", f"--interface={interface}"] + extra_args.split()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        logger.error("arp-scan not found — install with: sudo apt install arp-scan")
        return None
    except subprocess.TimeoutExpired:
        logger.warning("arp-scan timed out after 60 s")
        return None
    except PermissionError:
        logger.error("arp-scan permission denied — run as root or set capabilities")
        return None

    if result.returncode not in (0, 1):
        logger.warning("arp-scan exited %d: %s",
                       result.returncode, result.stderr.strip())
        return None

    found: dict[str, tuple[str, str]] = {}
    for line in result.stdout.splitlines():
        m = _ARP_LINE.match(line.strip())
        if m:
            found[m.group(2).lower()] = (m.group(1), m.group(3).strip())
    return found


# ── Passive mode: arpwatch ───────────────────────────────────────────────────

def _normalise_mac(raw: str) -> str:
    """Normalise arpwatch's compressed MAC (``0:1:2:3:4:5``) to
    zero-padded lower-case ``00:01:02:03:04:05``."""
    return ":".join(part.zfill(2) for part in raw.lower().split(":"))


class ArpWatchMonitor:
    """Manage an ``arpwatch`` child process running in promiscuous mode.

    ``arpwatch -d`` keeps it in the foreground so we can manage its
    lifecycle directly.  The dat-file is read periodically by the main
    loop to derive the current device table.
    """

    def __init__(self, cfg: configparser.ConfigParser,
                 logger: logging.Logger):
        self._logger = logger
        self._interface = cfg.get("scanner", "interface")
        self._bin       = cfg.get("arpwatch", "arpwatch_bin")
        self._dat       = cfg.get("arpwatch", "arpwatch_dat")
        self._extra     = cfg.get("arpwatch", "arpwatch_extra")
        self._process: subprocess.Popen | None = None

    # ── lifecycle ─────────────────────────────────────────────────────

    def start(self) -> None:
        """Launch arpwatch as a foreground child process."""
        dat_path = Path(self._dat)
        dat_path.parent.mkdir(parents=True, exist_ok=True)
        # create the dat file if it does not exist; arpwatch requires it
        dat_path.touch(exist_ok=True)

        cmd = [
            self._bin,
            "-i", self._interface,
            "-f", self._dat,
            "-d",                      # foreground / debug – don't fork
            "-N",                      # don't report bogons
        ]
        if self._extra:
            cmd.extend(self._extra.split())

        self._logger.info("starting arpwatch: %s", " ".join(cmd))
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            self._logger.error(
                "arpwatch not found at %s — install with: "
                "sudo apt install arpwatch", self._bin)
            raise
        except PermissionError:
            self._logger.error(
                "arpwatch permission denied — run as root")
            raise

    def stop(self) -> None:
        if self._process is None:
            return
        self._logger.info("stopping arpwatch (pid %d)", self._process.pid)
        self._process.terminate()
        try:
            self._process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=5)
        self._process = None

    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    # ── dat-file reader ───────────────────────────────────────────────

    def read_devices(self) -> dict[str, tuple[str, float]]:
        """Parse the arpwatch dat file.

        Returns ``{normalised_mac: (ip, epoch_timestamp)}``.
        The dat format is tab-separated:
        ``<mac>\\t<ip>\\t<epoch>\\t<hostname>``
        """
        devices: dict[str, tuple[str, float]] = {}
        try:
            with open(self._dat) as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line:
                        continue
                    parts = line.split("\t")
                    if len(parts) < 3:
                        continue
                    try:
                        mac = _normalise_mac(parts[0])
                        ip  = parts[1]
                        ts  = float(parts[2])
                        devices[mac] = (ip, ts)
                    except (ValueError, IndexError):
                        continue
        except FileNotFoundError:
            self._logger.debug("dat file %s not found yet", self._dat)
        return devices


# ── Main watcher ─────────────────────────────────────────────────────────────

class MacWatcher:
    def __init__(self, cfg: configparser.ConfigParser,
                 logger: logging.Logger):
        self.mode          = cfg.get("scanner", "scan_mode").strip().lower()
        self.interface     = cfg.get("scanner", "interface")
        self.interval      = cfg.getint("scanner", "scan_interval")
        self.miss_thresh   = cfg.getint("scanner", "miss_threshold")
        self.arp_args      = cfg.get("scanner", "arp_scan_args")
        self.known_macs_f  = cfg.get("scanner", "known_macs_file")
        self.db_path       = cfg.get("database", "db_path")
        self.logger        = logger

        if self.mode not in VALID_SCAN_MODES:
            raise ValueError(
                f"scan_mode must be one of {VALID_SCAN_MODES}, got '{self.mode}'"
            )

        # arpwatch-specific
        self.leave_timeout = cfg.getint("arpwatch", "leave_timeout")
        self._arpwatch: ArpWatchMonitor | None = None

        # vendor resolver
        self.vendor = VendorLookup(logger)

        # {mac: {"ip", "vendor", "name", "missed"}}    (arp-scan mode)
        # {mac: {"ip", "vendor", "name", "last_seen"}}  (arpwatch mode)
        self.active: dict = {}

        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.db = TinyFlux(self.db_path)

        self._running = True
        self._cfg = cfg
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT,  self._handle_signal)

    # ── helpers ───────────────────────────────────────────────────────

    def _handle_signal(self, signum, _frame):
        self.logger.info("received signal %d — shutting down", signum)
        self._running = False

    def _resolve_vendor(self, mac: str, hint: str = "") -> str:
        """Return best-effort vendor string.  Prefers OUI DB, falls
        back to *hint* (e.g. arp-scan's own vendor column)."""
        oui = self.vendor.lookup(mac)
        return oui or hint or "unknown"

    def _log_join(self, mac: str, ip: str, vendor: str,
                  name: str) -> None:
        label = f'"{name}" ' if name else ""
        self.logger.info(
            "JOIN  mac=%s ip=%-15s vendor=%s %s",
            mac, ip, vendor, label,
        )
        insert_event(self.db, "JOIN", mac, ip, vendor, name)

    def _log_leave(self, mac: str, ip: str, vendor: str,
                   name: str) -> None:
        label = f'"{name}" ' if name else ""
        self.logger.info(
            "LEAVE mac=%s last_ip=%-15s vendor=%s %s",
            mac, ip, vendor, label,
        )
        insert_event(self.db, "LEAVE", mac, ip, vendor, name)

    # ── arp-scan mode ─────────────────────────────────────────────────

    def _cycle_arpscan(self, known_macs: dict) -> None:
        scan = run_arp_scan(self.interface, self.arp_args, self.logger)
        if scan is None:
            self.logger.debug("scan failed, skipping this cycle")
            return

        self.logger.debug("arp-scan found %d device(s)", len(scan))

        for mac, (ip, arpscan_vendor) in scan.items():
            name   = known_macs.get(mac, "")
            vendor = self._resolve_vendor(mac, arpscan_vendor)
            if mac not in self.active:
                self._log_join(mac, ip, vendor, name)
                self.active[mac] = {
                    "ip": ip, "vendor": vendor,
                    "name": name, "missed": 0,
                }
            else:
                dev = self.active[mac]
                dev["missed"] = 0
                dev["ip"]     = ip
                dev["vendor"] = vendor

        for mac in list(self.active):
            if mac not in scan:
                self.active[mac]["missed"] += 1
                missed = self.active[mac]["missed"]
                self.logger.debug("mac=%s miss %d/%d",
                                  mac, missed, self.miss_thresh)
                if missed >= self.miss_thresh:
                    dev = self.active.pop(mac)
                    self._log_leave(mac, dev["ip"],
                                    dev["vendor"], dev["name"])

    # ── arpwatch mode ─────────────────────────────────────────────────

    def _cycle_arpwatch(self, known_macs: dict) -> None:
        if self._arpwatch is None:
            return

        if not self._arpwatch.is_running():
            self.logger.error(
                "arpwatch process died — attempting restart")
            try:
                self._arpwatch.start()
            except Exception:
                return

        devices = self._arpwatch.read_devices()
        now = time.time()
        self.logger.debug("arpwatch dat has %d device(s)", len(devices))

        # ── Detect JOINs ──────────────────────────────────────────────
        for mac, (ip, ts) in devices.items():
            name   = known_macs.get(mac, "")
            vendor = self._resolve_vendor(mac)

            if mac not in self.active:
                self._log_join(mac, ip, vendor, name)
                self.active[mac] = {
                    "ip": ip, "vendor": vendor,
                    "name": name, "last_seen": ts,
                }
            else:
                dev = self.active[mac]
                dev["last_seen"] = ts
                dev["ip"]        = ip
                dev["vendor"]    = vendor

        # ── Detect LEAVEs (stale entries) ─────────────────────────────
        for mac in list(self.active):
            dev = self.active[mac]
            age = now - dev["last_seen"]
            if age >= self.leave_timeout:
                self.logger.debug(
                    "mac=%s last_seen %.0fs ago (threshold %ds)",
                    mac, age, self.leave_timeout,
                )
                dev = self.active.pop(mac)
                self._log_leave(mac, dev["ip"],
                                dev["vendor"], dev["name"])

    # ── main loop ─────────────────────────────────────────────────────

    def run(self) -> None:
        self.logger.info(
            "macwatcher started — mode=%s interface=%s interval=%ds db=%s",
            self.mode, self.interface, self.interval, self.db_path,
        )

        if self.mode == "arpwatch":
            self._arpwatch = ArpWatchMonitor(self._cfg, self.logger)
            self._arpwatch.start()
            self.logger.info(
                "arpwatch passive mode — leave_timeout=%ds",
                self.leave_timeout,
            )
        else:
            self.logger.info(
                "arp-scan active mode — miss_threshold=%d",
                self.miss_thresh,
            )

        try:
            while self._running:
                known_macs = load_known_macs(self.known_macs_f)

                if self.mode == "arp-scan":
                    self._cycle_arpscan(known_macs)
                else:
                    self._cycle_arpwatch(known_macs)

                time.sleep(self.interval)
        finally:
            if self._arpwatch is not None:
                self._arpwatch.stop()

        self.logger.info("macwatcher stopped")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    cfg    = load_config()
    level  = cfg.get("logging", "log_level")
    logger = setup_logger(level)

    try:
        watcher = MacWatcher(cfg, logger)
        watcher.run()
    except Exception as exc:
        logger.exception("fatal error: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()

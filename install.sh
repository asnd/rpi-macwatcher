#!/usr/bin/env bash
# install.sh — Deploy macwatcher on Raspberry Pi OS (Debian/bookworm based)
# Run as root:  sudo bash install.sh

set -euo pipefail

INSTALL_DIR="/opt/macwatcher"
CONFIG_DIR="/etc/macwatcher"
DATA_DIR="/var/lib/macwatcher"
SERVICE_NAME="macwatcher"

# ── Colour helpers ────────────────────────────────────────────────────────────
info()  { echo -e "\e[32m[INFO]\e[0m  $*"; }
warn()  { echo -e "\e[33m[WARN]\e[0m  $*"; }
error() { echo -e "\e[31m[ERROR]\e[0m $*" >&2; exit 1; }

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || error "Please run as root: sudo bash install.sh"

# ── Detect active WiFi interface ──────────────────────────────────────────────
WIFI_IF=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | head -n1)
if [[ -z "$WIFI_IF" ]]; then
    WIFI_IF="wlan0"
    warn "Could not detect WiFi interface automatically — defaulting to wlan0"
else
    info "Detected WiFi interface: $WIFI_IF"
fi

# ── System packages ───────────────────────────────────────────────────────────
info "Updating package lists..."
apt-get update -qq

info "Installing arp-scan, arpwatch, and Python dependencies..."
apt-get install -y -qq arp-scan arpwatch python3-pip python3-venv

# Disable the system arpwatch service — macwatcher manages its own arpwatch
# process when running in arpwatch mode.
if systemctl is-enabled arpwatch.service &>/dev/null; then
    info "Disabling system arpwatch service (macwatcher manages its own)..."
    systemctl stop arpwatch.service || true
    systemctl disable arpwatch.service || true
fi

# ── Python virtual environment ────────────────────────────────────────────────
info "Creating Python venv at $INSTALL_DIR/venv ..."
mkdir -p "$INSTALL_DIR"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet tinyflux mac-vendor-lookup

PYTHON_BIN="$INSTALL_DIR/venv/bin/python3"

# ── Download MAC vendor OUI database (offline after this) ─────────────────────
info "Downloading IEEE OUI vendor database (one-time)..."
"$PYTHON_BIN" -c "
from mac_vendor_lookup import MacLookup
MacLookup().update_vendors()
print('  vendor database cached successfully')
" || warn "Vendor DB download failed — will use bundled fallback"

# ── Application files ─────────────────────────────────────────────────────────
info "Copying application files to $INSTALL_DIR ..."
cp macwatcher.py "$INSTALL_DIR/"
chmod 755 "$INSTALL_DIR/macwatcher.py"

# ── Config ────────────────────────────────────────────────────────────────────
mkdir -p "$CONFIG_DIR"
if [[ -f "$CONFIG_DIR/config.ini" ]]; then
    warn "$CONFIG_DIR/config.ini already exists — skipping (not overwriting your config)"
else
    cp config.ini "$CONFIG_DIR/"
    sed -i "s/^interface = .*/interface = $WIFI_IF/" "$CONFIG_DIR/config.ini"
    info "Config written to $CONFIG_DIR/config.ini (interface=$WIFI_IF)"
fi

if [[ ! -f "$CONFIG_DIR/known-macs.conf" ]]; then
    cp known-macs.conf.example "$CONFIG_DIR/known-macs.conf"
fi

# ── Data directory ────────────────────────────────────────────────────────────
mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"

# ── systemd service ───────────────────────────────────────────────────────────
info "Installing systemd service..."
sed "s|/usr/bin/python3|$PYTHON_BIN|g" macwatcher.service \
    > /etc/systemd/system/"$SERVICE_NAME".service

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
info "macwatcher installed and started successfully."
echo ""
echo "  Status  : sudo systemctl status $SERVICE_NAME"
echo "  Logs    : sudo journalctl -u $SERVICE_NAME -f"
echo "  Syslog  : sudo grep macwatcher /var/log/syslog"
echo "  DB file : $DATA_DIR/events.csv"
echo "  Config  : $CONFIG_DIR/config.ini"
echo ""
echo "  To switch modes, edit scan_mode in $CONFIG_DIR/config.ini"
echo "  and run:  sudo systemctl restart $SERVICE_NAME"
echo ""

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[riggs]${NC} $*"; }
warn()  { echo -e "${YELLOW}[riggs]${NC} $*"; }
error() { echo -e "${RED}[riggs]${NC} $*" >&2; }

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (use sudo)."
    exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~$REAL_USER")

info "Building release binaries..."
cd "$PROJECT_ROOT"
sudo -u "$REAL_USER" cargo build --release

info "Creating directories..."
mkdir -p /usr/local/bin
mkdir -p /var/lib/riggs
mkdir -p /var/log/riggs
mkdir -p /etc/riggs
mkdir -p "$REAL_HOME/Library/Logs/riggs"
chown "$REAL_USER" "$REAL_HOME/Library/Logs/riggs"

info "Installing binaries to /usr/local/bin/..."
cp "$PROJECT_ROOT/target/release/riggs" /usr/local/bin/riggs
cp "$PROJECT_ROOT/target/release/riggs-daemon" /usr/local/bin/riggs-daemon
# riggs-menubar may not exist yet; install it if built
if [[ -f "$PROJECT_ROOT/target/release/riggs-menubar" ]]; then
    cp "$PROJECT_ROOT/target/release/riggs-menubar" /usr/local/bin/riggs-menubar
else
    warn "riggs-menubar binary not found, skipping (build it when ready)."
fi
chmod 755 /usr/local/bin/riggs /usr/local/bin/riggs-daemon
[[ -f /usr/local/bin/riggs-menubar ]] && chmod 755 /usr/local/bin/riggs-menubar

info "Installing configuration..."
if [[ ! -f /etc/riggs/riggs.toml ]]; then
    cp "$PROJECT_ROOT/config/riggs.toml" /etc/riggs/riggs.toml
    info "Installed default config to /etc/riggs/riggs.toml"
else
    warn "/etc/riggs/riggs.toml already exists, not overwriting."
fi

info "Installing rules..."
cp -R "$PROJECT_ROOT/rules/" /etc/riggs/rules/

info "Installing launchd daemon plist..."
cp "$SCRIPT_DIR/launchd/com.riggs.daemon.plist" /Library/LaunchDaemons/com.riggs.daemon.plist
chown root:wheel /Library/LaunchDaemons/com.riggs.daemon.plist
chmod 644 /Library/LaunchDaemons/com.riggs.daemon.plist

info "Installing launchd menubar agent plist..."
AGENT_DIR="$REAL_HOME/Library/LaunchAgents"
mkdir -p "$AGENT_DIR"
cp "$SCRIPT_DIR/launchd/com.riggs.menubar.plist" "$AGENT_DIR/com.riggs.menubar.plist"
chown "$REAL_USER" "$AGENT_DIR/com.riggs.menubar.plist"
chmod 644 "$AGENT_DIR/com.riggs.menubar.plist"

info "Loading launchd daemon..."
launchctl unload /Library/LaunchDaemons/com.riggs.daemon.plist 2>/dev/null || true
launchctl load /Library/LaunchDaemons/com.riggs.daemon.plist || warn "Failed to load daemon plist."

info "Loading launchd menubar agent..."
sudo -u "$REAL_USER" launchctl unload "$AGENT_DIR/com.riggs.menubar.plist" 2>/dev/null || true
sudo -u "$REAL_USER" launchctl load "$AGENT_DIR/com.riggs.menubar.plist" || warn "Failed to load menubar plist."

echo ""
info "Riggs endpoint protection installed successfully."
echo ""
echo "  Daemon:   launchctl list com.riggs.daemon"
echo "  Menubar:  launchctl list com.riggs.menubar"
echo "  CLI:      riggs status"
echo "  Config:   /etc/riggs/riggs.toml"
echo "  Logs:     /var/log/riggs/"
echo ""
echo "  To uninstall: sudo $SCRIPT_DIR/uninstall.sh"

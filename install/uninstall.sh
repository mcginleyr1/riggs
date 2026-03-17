#!/usr/bin/env bash
set -euo pipefail

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

info "Unloading launchd daemon..."
if launchctl list com.riggs.daemon &>/dev/null; then
    launchctl unload /Library/LaunchDaemons/com.riggs.daemon.plist 2>/dev/null || true
    info "Daemon unloaded."
else
    warn "Daemon was not loaded."
fi

info "Unloading launchd menubar agent..."
AGENT_PLIST="$REAL_HOME/Library/LaunchAgents/com.riggs.menubar.plist"
if sudo -u "$REAL_USER" launchctl list com.riggs.menubar &>/dev/null; then
    sudo -u "$REAL_USER" launchctl unload "$AGENT_PLIST" 2>/dev/null || true
    info "Menubar agent unloaded."
else
    warn "Menubar agent was not loaded."
fi

info "Removing launchd plist files..."
rm -f /Library/LaunchDaemons/com.riggs.daemon.plist
rm -f "$AGENT_PLIST"

info "Removing binaries..."
rm -f /usr/local/bin/riggs
rm -f /usr/local/bin/riggs-daemon
rm -f /usr/local/bin/riggs-menubar

info "Removing log files..."
rm -rf /var/log/riggs
rm -rf "$REAL_HOME/Library/Logs/riggs"

echo ""
read -rp "Remove /var/lib/riggs (database and runtime data)? [y/N] " remove_data
if [[ "$remove_data" =~ ^[Yy]$ ]]; then
    rm -rf /var/lib/riggs
    info "Removed /var/lib/riggs"
else
    warn "Kept /var/lib/riggs"
fi

read -rp "Remove /etc/riggs (configuration and rules)? [y/N] " remove_config
if [[ "$remove_config" =~ ^[Yy]$ ]]; then
    rm -rf /etc/riggs
    info "Removed /etc/riggs"
else
    warn "Kept /etc/riggs"
fi

rm -f /var/run/riggs.sock

echo ""
info "Riggs endpoint protection uninstalled."
echo ""
echo "  Summary:"
echo "    - Launchd plists:  removed"
echo "    - Binaries:        removed"
echo "    - Logs:            removed"
if [[ "$remove_data" =~ ^[Yy]$ ]]; then
    echo "    - Data:            removed"
else
    echo "    - Data:            kept (/var/lib/riggs)"
fi
if [[ "$remove_config" =~ ^[Yy]$ ]]; then
    echo "    - Config:          removed"
else
    echo "    - Config:          kept (/etc/riggs)"
fi

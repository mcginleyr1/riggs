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

# Deactivate while the app is still in /Applications: its binary owns the extension.
FILTER_APP="/Applications/Riggs Filter.app"
if [[ -d "$FILTER_APP" ]]; then
    info "Deactivating the network filter (approve the removal if prompted)..."
    sudo -u "$REAL_USER" "$FILTER_APP/Contents/MacOS/riggs-filter" --deactivate ||
        warn "Filter deactivation failed; remove it in System Settings > Network Extensions."
    rm -rf "$FILTER_APP"
fi

info "Unloading launchd daemon..."
if launchctl list com.riggs.daemon &>/dev/null; then
    launchctl unload /Library/LaunchDaemons/com.riggs.daemon.plist 2>/dev/null || true
    info "Daemon unloaded."
else
    warn "Daemon was not loaded."
fi

# The Outlook for Mac sensor goes whether or not install.sh was given --outlook. The CA's hash is
# read before the state directory goes: it names the certificate in the keychain commands printed
# at the end, which this script never runs.
MAILBRIDGE_STATE="$REAL_HOME/Library/Application Support/Riggs/mailbridge"
CA_NAME="Riggs mail bridge local CA"
CA_HASH=""
if [[ -f "$MAILBRIDGE_STATE/ca.pem" ]]; then
    CA_HASH=$(openssl x509 -in "$MAILBRIDGE_STATE/ca.pem" -noout -fingerprint -sha256 2>/dev/null |
        sed 's/.*=//; s/://g') || CA_HASH=""
fi
MAILBRIDGE_PLIST="$REAL_HOME/Library/LaunchAgents/com.riggs.mailbridge.plist"
info "Unloading launchd mailbridge agent..."
if sudo -u "$REAL_USER" launchctl list com.riggs.mailbridge &>/dev/null; then
    sudo -u "$REAL_USER" launchctl unload "$MAILBRIDGE_PLIST" 2>/dev/null || true
    info "Mailbridge agent unloaded."
else
    warn "Mailbridge agent was not loaded."
fi
info "Removing the Outlook for Mac sensor's files..."
rm -f "$MAILBRIDGE_PLIST"
rm -f /usr/local/bin/riggs-mailbridge
rm -rf /usr/local/share/riggs/outlook-addin
rm -rf "$MAILBRIDGE_STATE"
rmdir "$REAL_HOME/Library/Application Support/Riggs" 2>/dev/null || true

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
rm -f /usr/local/bin/riggs-browser-host

info "Removing the browser extension and native-messaging manifests..."
rm -rf /usr/local/share/riggs
rm -f "/Library/Google/Chrome/NativeMessagingHosts/com.riggs.browser.json"
rm -f "/Library/Application Support/Chromium/NativeMessagingHosts/com.riggs.browser.json"
rm -f "/Library/Microsoft/Edge/NativeMessagingHosts/com.riggs.browser.json"
rm -f "$REAL_HOME/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/com.riggs.browser.json"

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
rm -rf "/private/var/root/Library/Group Containers/"*.com.riggs  # filter IPC socket's app group

echo ""
info "Riggs endpoint protection uninstalled."
echo ""
echo "  Summary:"
echo "    - Network filter:  deactivated and removed (if it was installed)"
echo "    - Launchd plists:  removed"
echo "    - Binaries:        removed"
echo "    - Browser:         extension files and native-messaging manifests removed"
echo "    - Outlook sensor:  bridge, agent, add-in files and its state removed (if it was installed)"
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
echo ""
echo "  A browser keeps its entry for the Riggs extension until you remove it there:"
echo "  open chrome://extensions in each profile it was loaded into."
echo ""
echo "  If you ever set up the Outlook for Mac sensor, two things are left that only you can"
echo "  remove. This script does not run either."
echo ""
echo "  1. The bridge's certificate authority and its trust setting, in your login keychain"
echo "     (macOS asks for your password). -t deletes the trust setting with the certificate:"
echo ""
if [[ -n "$CA_HASH" ]]; then
    echo "     security delete-certificate -t -Z $CA_HASH \"\$HOME/Library/Keychains/login.keychain-db\""
else
    echo "     security delete-certificate -t -c \"$CA_NAME\" \"\$HOME/Library/Keychains/login.keychain-db\""
fi
echo ""
echo "     Every 'setup --renew' made a new authority with the same name, so the command above"
echo "     can name more than one. List what is left, and delete each by the SHA-256 hash this"
echo "     prints (-Z <hash> in place of -c <name>) until nothing is listed:"
echo ""
echo "     security find-certificate -a -c \"$CA_NAME\" -Z \"\$HOME/Library/Keychains/login.keychain-db\""
echo ""
echo "  2. The add-in in your mailbox. It lives there, not on this Mac. In a browser signed in to"
echo "     the mailbox, open https://aka.ms/olksideload, choose My add-ins, find \"Riggs\" under"
echo "     Custom Addins, choose its ellipsis (...), then Remove. Do it for each mailbox you added"
echo "     it to; restart Outlook if its button lingers."

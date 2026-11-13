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
# The native-messaging host the browser extension talks to the daemon through.
cp "$PROJECT_ROOT/target/release/riggs-browser-host" /usr/local/bin/riggs-browser-host
# riggs-menubar may not exist yet; install it if built
if [[ -f "$PROJECT_ROOT/target/release/riggs-menubar" ]]; then
    cp "$PROJECT_ROOT/target/release/riggs-menubar" /usr/local/bin/riggs-menubar
else
    warn "riggs-menubar binary not found, skipping (build it when ready)."
fi
chmod 755 /usr/local/bin/riggs /usr/local/bin/riggs-daemon /usr/local/bin/riggs-browser-host
[[ -f /usr/local/bin/riggs-menubar ]] && chmod 755 /usr/local/bin/riggs-menubar

info "Installing configuration..."
if [[ ! -f /etc/riggs/riggs.toml ]]; then
    cp "$PROJECT_ROOT/config/riggs.toml" /etc/riggs/riggs.toml
    info "Installed default config to /etc/riggs/riggs.toml"
else
    warn "/etc/riggs/riggs.toml already exists, not overwriting."
fi
# The phishing policy is the only switch for phishing protection. The daemon
# looks for it only at startup, so it has to be in place before the daemon loads.
if [[ ! -f /etc/riggs/phishing-policy.toml ]]; then
    cp "$PROJECT_ROOT/config/phishing-policy.toml" /etc/riggs/phishing-policy.toml
    info "Installed phishing policy to /etc/riggs/phishing-policy.toml"
else
    warn "/etc/riggs/phishing-policy.toml already exists, not overwriting."
fi

info "Installing rules..."
cp -R "$PROJECT_ROOT/rules/" /etc/riggs/rules/

# Browsers read the extension and the native-messaging manifests as the
# logged-in user, so both are world-readable whatever root's umask is. Root
# owns them, so a process running as the user cannot rewrite either.
BROWSER_EXT_DIR=/usr/local/share/riggs/browser-extension
NM_MANIFEST="$SCRIPT_DIR/native-messaging/com.riggs.browser.json"
NM_DIRS=(
    "/Library/Google/Chrome/NativeMessagingHosts"
    "/Library/Application Support/Chromium/NativeMessagingHosts"
    "/Library/Microsoft/Edge/NativeMessagingHosts"
)

info "Installing the browser extension to $BROWSER_EXT_DIR..."
(umask 022 && mkdir -p /usr/local/share/riggs)
rm -rf "$BROWSER_EXT_DIR"
ditto "$PROJECT_ROOT/extensions/riggs-browser/ext" "$BROWSER_EXT_DIR"
chown -R root:wheel "$BROWSER_EXT_DIR"
chmod -R u=rwX,go=rX "$BROWSER_EXT_DIR"

info "Installing native-messaging manifests (Chrome, Chromium, Edge)..."
for dir in "${NM_DIRS[@]}"; do
    (umask 022 && mkdir -p "$dir")
    cp "$NM_MANIFEST" "$dir/com.riggs.browser.json"
    chown root:wheel "$dir/com.riggs.browser.json"
    chmod 644 "$dir/com.riggs.browser.json"
done
# Brave documents no system-wide directory, so its manifest goes into the
# user's own Brave directory, and only when Brave has been run by that user.
BRAVE_DIR="$REAL_HOME/Library/Application Support/BraveSoftware/Brave-Browser"
if [[ -d "$BRAVE_DIR" ]]; then
    info "Installing the native-messaging manifest for Brave ($REAL_USER)..."
    sudo -u "$REAL_USER" mkdir -p "$BRAVE_DIR/NativeMessagingHosts"
    sudo -u "$REAL_USER" cp "$NM_MANIFEST" "$BRAVE_DIR/NativeMessagingHosts/com.riggs.browser.json"
fi

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

# The network filter enforces egress/DLP verdicts. It needs signing with
# provisioning profiles, so it is built separately (extensions/riggs-filter/build.sh).
FILTER_APP="$PROJECT_ROOT/extensions/riggs-filter/.build/bundle/Riggs Filter.app"
if [[ -f "$FILTER_APP/Contents/embedded.provisionprofile" ]]; then
    info "Installing Riggs Filter.app (macOS activates system extensions only from /Applications)..."
    rm -rf "/Applications/Riggs Filter.app"
    ditto "$FILTER_APP" "/Applications/Riggs Filter.app"
    info "Activating the network filter: approve it in System Settings when prompted..."
    sudo -u "$REAL_USER" "/Applications/Riggs Filter.app/Contents/MacOS/riggs-filter" --activate ||
        warn "Filter activation failed; fix the error above and rerun it."
else
    warn "Riggs Filter.app not built with provisioning profiles: egress/DLP verdicts are not enforced."
    warn "See \"macOS network filter\" in docs/STANDALONE.md."
fi

echo ""
info "Riggs endpoint protection installed successfully."
echo ""
echo "  Daemon:   launchctl list com.riggs.daemon"
echo "  Menubar:  launchctl list com.riggs.menubar"
echo "  Filter:   \"/Applications/Riggs Filter.app/Contents/MacOS/riggs-filter\" --status"
echo "  CLI:      riggs status"
echo "  Phishing: riggs phishing status"
echo "  Config:   /etc/riggs/riggs.toml"
echo "  Logs:     /var/log/riggs/"
echo ""
echo "  Phishing protection needs the browser extension, and a browser only takes"
echo "  it by hand. Once in each browser profile:"
echo "    1. Open chrome://extensions and turn on \"Developer mode\"."
echo "    2. Click \"Load unpacked\" and choose $BROWSER_EXT_DIR"
echo "  The extension's popup shows its state; docs/PHISHING.md explains each one."
echo ""
echo "  To uninstall: sudo $SCRIPT_DIR/uninstall.sh"

#!/bin/bash
# Removes what install/pkg/build-pkg.sh's packages installed. Runs as root from an MDM: no prompts,
# no $SUDO_USER, no tty. Configuration (/etc/riggs) and data (/var/lib/riggs) stay unless --purge.
set -euo pipefail

PURGE=0
case "${1:-}" in
    "") ;;
    --purge) PURGE=1 ;;
    *) echo "usage: uninstall-pkg.sh [--purge]" >&2; exit 1 ;;
esac
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }

FILTER_APP="/Applications/Riggs Filter.app"

# Root never acts on a path under a home directory: a user owns those and can replace any
# component with a link. Per-user steps run as that user, by uid, so a planted link can only
# reach what the user could already reach. Accounts come from the directory service, not from
# directory names, so /Users/Shared and /Users/Guest never appear.
local_users() {
    dscl . -list /Users UniqueID | while read -r name uid; do
        [[ "$uid" -ge 501 ]] || continue
        printf '%s\t%s\n' "$uid" "$(dscl . -read "/Users/$name" NFSHomeDirectory | tail -n 1 | sed 's/^NFSHomeDirectory: //; s/^ //')"
    done
}
as_user() { local uid="$1"; shift; sudo -u "#$uid" "$@" </dev/null; }

console_uid=$(stat -f %u /dev/console)
status=0
AGENTS=(com.riggs.menubar com.riggs.mailbridge com.riggs.filter-activate)

# Stop the agents first: with the app still present, the activation agent would put the
# filter back at the next login. Every account is tried: other logged-in sessions would
# otherwise keep running binaries that are about to be deleted.
while IFS=$'\t' read -r uid _; do
    for label in "${AGENTS[@]}"; do
        launchctl bootout "gui/$uid/$label" 2>/dev/null || true
    done
done < <(local_users)

# Deactivate while the app is still in /Applications: its binary owns the extension, and
# nothing else here can remove it. If that was not done, keep the app so it can be done later.
if [[ -d "$FILTER_APP" ]]; then
    if [[ "$console_uid" -eq 0 ]]; then
        deactivated=0
        echo "riggs: no user logged in, so the network filter could not be deactivated."
    elif launchctl asuser "$console_uid" sudo -u "#$console_uid" "$FILTER_APP/Contents/MacOS/riggs-filter" --deactivate; then
        deactivated=1
    else
        deactivated=0
        echo "riggs: filter deactivation failed."
    fi
    if [[ $deactivated -eq 1 ]]; then
        rm -rf "$FILTER_APP"
    else
        echo "riggs: KEPT $FILTER_APP, because without it nothing can remove the active system extension."
        echo "riggs: Log in as a user and run this script again, or remove the extension by hand in"
        echo "riggs: System Settings > Network Extensions and then delete the app."
        status=1
    fi
fi

launchctl bootout system/com.riggs.daemon 2>/dev/null || true

rm -f /Library/LaunchDaemons/com.riggs.daemon.plist
rm -f /Library/LaunchAgents/com.riggs.menubar.plist /Library/LaunchAgents/com.riggs.mailbridge.plist \
    /Library/LaunchAgents/com.riggs.filter-activate.plist
rm -f /usr/local/bin/riggs /usr/local/bin/riggs-daemon /usr/local/bin/riggs-menubar \
    /usr/local/bin/riggs-browser-host /usr/local/bin/riggs-mailbridge
rm -rf /usr/local/share/riggs
rm -f "/Library/Google/Chrome/NativeMessagingHosts/com.riggs.browser.json" \
    "/Library/Application Support/Chromium/NativeMessagingHosts/com.riggs.browser.json" \
    "/Library/Microsoft/Edge/NativeMessagingHosts/com.riggs.browser.json"
rm -rf /var/log/riggs
rm -f /var/run/riggs.sock
rm -rf "/private/var/root/Library/Group Containers/"*.com.riggs  # the filter IPC socket's app group

while IFS=$'\t' read -r uid home; do
    # One odd account must not stop the uninstall halfway.
    as_user "$uid" rm -f "$home/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/com.riggs.browser.json" ||
        echo "riggs: could not remove the Brave manifest for uid $uid; skipped."
    as_user "$uid" rm -rf "$home/Library/Application Support/Riggs/mailbridge" "$home/Library/Logs/riggs" ||
        echo "riggs: could not remove Riggs state for uid $uid; skipped."
    as_user "$uid" rmdir "$home/Library/Application Support/Riggs" 2>/dev/null || true
done < <(local_users)

if [[ $PURGE -eq 1 ]]; then
    rm -rf /var/lib/riggs /etc/riggs
else
    echo "riggs: kept /var/lib/riggs and /etc/riggs (use --purge to remove them)."
fi

pkgutil --forget com.riggs.pkg.core || true
pkgutil --forget com.riggs.pkg.outlook || true

echo "riggs: removed. Left for you: the mail bridge's CA in each user's login keychain and the"
echo "riggs: add-in in each mailbox (docs/DEPLOYMENT.md, \"Remove everything\")."
exit "$status"

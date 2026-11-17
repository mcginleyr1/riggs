#!/usr/bin/env bash
# Builds the installer packages an MDM deploys, from already built release binaries.
# Nothing here installs anything. See docs/DEPLOYMENT.md.
set -euo pipefail

PKG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$(cd "$PKG_DIR/.." && pwd)"
PROJECT_ROOT="$(cd "$INSTALL_DIR/.." && pwd)"

usage() {
    cat <<'EOF'
Usage: install/pkg/build-pkg.sh --out DIR [options]

  --out DIR                   Where the packages and the staging tree go (required).
  --version V                 Package version (default: the workspace version in Cargo.toml).
  --bin-dir DIR               Built binaries (default: target/release). Must hold riggs,
                              riggs-daemon, riggs-browser-host, riggs-menubar and, for the
                              Outlook package, riggs-mailbridge.
  --cargo                     Run `cargo build --release --locked` first.
  --installer-identity NAME   Sign the packages with this "Developer ID Installer" identity.
                              Without it the packages are unsigned and the script says so.
  --app-identity NAME         Sign the binaries with this "Developer ID Application" identity
                              (hardened runtime, secure timestamp). "-" signs ad hoc, for tests.
  --filter-app PATH           Add an already signed "Riggs Filter.app" to the core package.

Writes Riggs-VERSION.pkg (core) and Riggs-Outlook-VERSION.pkg (optional Outlook component).
EOF
}

OUT=""
VERSION=""
BIN_DIR="$PROJECT_ROOT/target/release"
RUN_CARGO=0
INSTALLER_IDENTITY=""
APP_IDENTITY=""
FILTER_APP=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --bin-dir) BIN_DIR="$2"; shift 2 ;;
        --cargo) RUN_CARGO=1; shift ;;
        --installer-identity) INSTALLER_IDENTITY="$2"; shift 2 ;;
        --app-identity) APP_IDENTITY="$2"; shift 2 ;;
        --filter-app) FILTER_APP="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 1 ;;
    esac
done
[[ -n "$OUT" ]] || { usage >&2; exit 1; }
[[ -n "$VERSION" ]] || VERSION=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' "$PROJECT_ROOT/Cargo.toml")
[[ -n "$VERSION" ]] || { echo "no version found in Cargo.toml; pass --version" >&2; exit 1; }

if [[ $RUN_CARGO -eq 1 ]]; then
    cargo build --release --locked --manifest-path "$PROJECT_ROOT/Cargo.toml"
fi

CORE_BINS=(riggs riggs-daemon riggs-browser-host riggs-menubar)
for bin in "${CORE_BINS[@]}" riggs-mailbridge; do
    [[ -x "$BIN_DIR/$bin" ]] || { echo "missing $BIN_DIR/$bin (build it, or pass --cargo)" >&2; exit 1; }
done
[[ -z "$FILTER_APP" || -d "$FILTER_APP" ]] || { echo "not a directory: $FILTER_APP" >&2; exit 1; }

CORE="$OUT/stage/core"
OUTLOOK="$OUT/stage/outlook"
rm -rf "$OUT/stage"
mkdir -p "$CORE" "$OUTLOOK" "$OUT/scripts"

# dir MODE PATH...: a payload directory with an explicit mode. The Installer applies the
# recommended owner, root:wheel, to every payload entry (pkgbuild --ownership recommended).
dir() { local mode="$1"; shift; install -d -m "$mode" "$@"; }
# tree SRC DEST: copy a directory tree, directories 755 and files 644 (the executable bit is
# set per file by the caller, never inherited from a source checkout).
tree() {
    ditto "$1" "$2"
    chmod -R u=rwX,go=rX "$2"
}
# sign_bin PATH: Developer ID signing of a payload binary, which notarization requires.
sign_bin() {
    [[ -n "$APP_IDENTITY" ]] || return 0
    local stamp=--timestamp
    [[ "$APP_IDENTITY" != "-" ]] || stamp=--timestamp=none
    # A fixed identifier: without --identifier codesign appends a hash of the binary, and the
    # designated requirement in the Full Disk Access profile would break on every build.
    codesign --force --options runtime "$stamp" --identifier "com.riggs.$(basename "$1")" \
        --sign "$APP_IDENTITY" "$1"
}

dir 755 "$CORE/usr/local/bin" "$CORE/usr/local/share/riggs" "$CORE/usr/local/share/riggs/defaults"
for bin in "${CORE_BINS[@]}"; do
    install -m 755 "$BIN_DIR/$bin" "$CORE/usr/local/bin/$bin"
    sign_bin "$CORE/usr/local/bin/$bin"
done

# Defaults live in the payload and postinstall copies them only when /etc/riggs lacks them.
install -m 644 "$PROJECT_ROOT/config/riggs.toml" "$CORE/usr/local/share/riggs/defaults/riggs.toml"
install -m 644 "$PROJECT_ROOT/config/phishing-policy.toml" "$CORE/usr/local/share/riggs/defaults/phishing-policy.toml"
tree "$PROJECT_ROOT/rules" "$CORE/usr/local/share/riggs/defaults/rules"

tree "$PROJECT_ROOT/extensions/riggs-browser/ext" "$CORE/usr/local/share/riggs/browser-extension"

for nm_dir in "Library/Google/Chrome/NativeMessagingHosts" \
    "Library/Application Support/Chromium/NativeMessagingHosts" \
    "Library/Microsoft/Edge/NativeMessagingHosts"; do
    dir 755 "$CORE/$nm_dir"
    install -m 644 "$INSTALL_DIR/native-messaging/com.riggs.browser.json" "$CORE/$nm_dir/com.riggs.browser.json"
done

dir 755 "$CORE/Library/LaunchDaemons" "$CORE/Library/LaunchAgents"
install -m 644 "$INSTALL_DIR/launchd/com.riggs.daemon.plist" "$CORE/Library/LaunchDaemons/com.riggs.daemon.plist"
# The shared menubar plist logs to /tmp/riggs-menubar.log, which every user's agent would
# fight over; the packaged copy discards its output instead.
sed 's#/tmp/riggs-menubar.log#/dev/null#' "$INSTALL_DIR/launchd/com.riggs.menubar.plist" \
    > "$CORE/Library/LaunchAgents/com.riggs.menubar.plist"
chmod 644 "$CORE/Library/LaunchAgents/com.riggs.menubar.plist"
if grep -q '/tmp/' "$CORE/Library/LaunchAgents/com.riggs.menubar.plist"; then
    echo "the menubar plist still names /tmp" >&2; exit 1
fi

if [[ -n "$FILTER_APP" ]]; then
    dir 755 "$CORE/Applications"
    ditto "$FILTER_APP" "$CORE/Applications/Riggs Filter.app"
    install -m 644 "$PKG_DIR/launchd/com.riggs.filter-activate.plist" "$CORE/Library/LaunchAgents/com.riggs.filter-activate.plist"
fi

dir 755 "$OUTLOOK/usr/local/bin" "$OUTLOOK/usr/local/share/riggs" "$OUTLOOK/Library/LaunchAgents"
install -m 755 "$BIN_DIR/riggs-mailbridge" "$OUTLOOK/usr/local/bin/riggs-mailbridge"
sign_bin "$OUTLOOK/usr/local/bin/riggs-mailbridge"
tree "$PROJECT_ROOT/extensions/riggs-outlook/addin" "$OUTLOOK/usr/local/share/riggs/outlook-addin"
install -m 644 "$PKG_DIR/launchd/com.riggs.mailbridge.plist" "$OUTLOOK/Library/LaunchAgents/com.riggs.mailbridge.plist"

# Extended attributes are archived as ._ AppleDouble entries in the payload. The Installer
# restores them as attributes, so they are harmless, but clear what can be cleared.
xattr -cr "$OUT/stage"
if [[ -n "$(xattr -r "$OUT/stage")" ]]; then
    echo "note: some staged files carry kernel-managed attributes (com.apple.provenance); the payload will hold ._ entries for them." >&2
fi

for plist in "$CORE"/Library/LaunchDaemons/*.plist "$CORE"/Library/LaunchAgents/*.plist "$OUTLOOK"/Library/LaunchAgents/*.plist; do
    plutil -lint "$plist" >/dev/null
done

cp "$PKG_DIR/scripts/core/preinstall" "$PKG_DIR/scripts/core/postinstall" "$OUT/scripts/"
chmod 755 "$OUT/scripts/preinstall" "$OUT/scripts/postinstall"

pkgbuild --quiet --root "$CORE" --identifier com.riggs.pkg.core --version "$VERSION" \
    --install-location / --ownership recommended --component-plist "$PKG_DIR/no-bundles.plist" \
    --scripts "$OUT/scripts" "$OUT/Riggs-core-component.pkg"
pkgbuild --quiet --root "$OUTLOOK" --identifier com.riggs.pkg.outlook --version "$VERSION" \
    --install-location / --ownership recommended --component-plist "$PKG_DIR/no-bundles.plist" \
    "$OUT/Riggs-Outlook-component.pkg"

SIGN_ARGS=()
[[ -z "$INSTALLER_IDENTITY" ]] || SIGN_ARGS=(--sign "$INSTALLER_IDENTITY")
productbuild --package "$OUT/Riggs-core-component.pkg" ${SIGN_ARGS[@]+"${SIGN_ARGS[@]}"} "$OUT/Riggs-$VERSION.pkg"
productbuild --package "$OUT/Riggs-Outlook-component.pkg" ${SIGN_ARGS[@]+"${SIGN_ARGS[@]}"} "$OUT/Riggs-Outlook-$VERSION.pkg"
rm -f "$OUT/Riggs-core-component.pkg" "$OUT/Riggs-Outlook-component.pkg"

echo "built $OUT/Riggs-$VERSION.pkg and $OUT/Riggs-Outlook-$VERSION.pkg"
if [[ -z "$INSTALLER_IDENTITY" ]]; then
    echo "UNSIGNED: no --installer-identity given. An MDM or Gatekeeper will not accept these for distribution." >&2
    exit 0
fi
[[ -n "$APP_IDENTITY" ]] || echo "warning: binaries not signed (--app-identity); notarization will reject the package." >&2
cat <<EOF

Next, notarize and staple each package. These commands are printed, not run.
Store credentials once (see docs/DEPLOYMENT.md, "Notarization"), then for each package:

  xcrun notarytool submit "$OUT/Riggs-$VERSION.pkg" --keychain-profile NOTARY_PROFILE --wait
  xcrun notarytool log SUBMISSION_ID --keychain-profile NOTARY_PROFILE notary-log.json
  xcrun stapler staple "$OUT/Riggs-$VERSION.pkg"

  xcrun notarytool submit "$OUT/Riggs-Outlook-$VERSION.pkg" --keychain-profile NOTARY_PROFILE --wait
  xcrun stapler staple "$OUT/Riggs-Outlook-$VERSION.pkg"
EOF

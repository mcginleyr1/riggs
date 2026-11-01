#!/usr/bin/env bash
# Build and sign "Riggs Filter.app" with the riggs-filter system extension
# embedded at Contents/Library/SystemExtensions/.
#
#   extensions/riggs-filter/build.sh [--app-profile FILE --extension-profile FILE]
#
# Environment overrides: IDENTITY, TEAM_ID, VERSION, BUILD_NUMBER, OUT_DIR.
#
# The network-extension and system-extension entitlements are restricted:
# without provisioning profiles that grant them the bundle still signs, but
# macOS refuses to launch it. Create the profiles as described in
# docs/STANDALONE.md ("macOS network filter") and pass both.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IDENTITY="${IDENTITY:-Apple Development: Robert McGinley (Y85FH6KD69)}"
TEAM_ID="${TEAM_ID:-3KSC5YWCZ6}"
VERSION="${VERSION:-$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' "$HERE/../../Cargo.toml")}"
BUILD_NUMBER="${BUILD_NUMBER:-$(date +%Y%m%d.%H%M)}"  # sysextd only replaces an extension whose version changed
OUT_DIR="${OUT_DIR:-$HERE/.build/bundle}"
APP_PROFILE=""
EXT_PROFILE=""

die() { echo "build.sh: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --app-profile) APP_PROFILE="$2"; shift 2 ;;
        --extension-profile) EXT_PROFILE="$2"; shift 2 ;;
        *) die "usage: build.sh [--app-profile FILE --extension-profile FILE]" ;;
    esac
done
if [[ -n "$APP_PROFILE" && -z "$EXT_PROFILE" || -z "$APP_PROFILE" && -n "$EXT_PROFILE" ]]; then
    die "pass both profiles or neither"
fi

APP="$OUT_DIR/Riggs Filter.app"
EXT="$APP/Contents/Library/SystemExtensions/com.riggs.filter.extension.systemextension"

swift build -c release --package-path "$HERE"
BIN="$(swift build -c release --package-path "$HERE" --show-bin-path)"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$EXT/Contents/MacOS"
cp "$BIN/RiggsFilterHost" "$APP/Contents/MacOS/riggs-filter"
cp "$BIN/RiggsFilterExtension" "$EXT/Contents/MacOS/com.riggs.filter.extension"

decode() { security cms -D -i "$1" > "$OUT_DIR/$2.profile.plist"; }
grants() {  # decoded-profile entitlement value
    /usr/libexec/PlistBuddy -c "Print :Entitlements:$2" "$OUT_DIR/$1.profile.plist" | grep -qxE "[[:space:]]*$3"
}

# Developer ID profiles grant content-filter-provider-systemextension; Apple
# Development profiles may grant only the plain value. Sign with what they grant.
NE_VALUE=content-filter-provider-systemextension
if [[ -n "$APP_PROFILE" ]]; then
    decode "$EXT_PROFILE" com.riggs.filter.extension
    decode "$APP_PROFILE" com.riggs.filter
    grants com.riggs.filter.extension com.apple.developer.networking.networkextension "$NE_VALUE" ||
        NE_VALUE=content-filter-provider
fi

render() {
    sed -e "s/@TEAM_ID@/$TEAM_ID/g" -e "s/@VERSION@/$VERSION/g" -e "s/@BUILD_NUMBER@/$BUILD_NUMBER/g" \
        -e "s/@NE_VALUE@/$NE_VALUE/g" "$HERE/Bundle/$1" > "$2"
}
render Host-Info.plist "$APP/Contents/Info.plist"
render Extension-Info.plist "$EXT/Contents/Info.plist"
render Host.entitlements "$OUT_DIR/host.entitlements"
render Extension.entitlements "$OUT_DIR/extension.entitlements"

# Fail here, not at launch, when a profile can't back the entitlements we sign.
embed_profile() {  # profile bundle bundle-id
    grants "$3" com.apple.application-identifier "$TEAM_ID\.$3" || die "$1 is not for App ID $TEAM_ID.$3"
    grants "$3" com.apple.developer.networking.networkextension "$NE_VALUE" || die "$1 does not grant $NE_VALUE"
    cp "$1" "$2/Contents/embedded.provisionprofile"
}
if [[ -n "$APP_PROFILE" ]]; then
    embed_profile "$EXT_PROFILE" "$EXT" com.riggs.filter.extension
    embed_profile "$APP_PROFILE" "$APP" com.riggs.filter
    grants com.riggs.filter com.apple.developer.system-extension.install true ||
        die "$APP_PROFILE does not grant the System Extension capability"
fi

# Inside out: the extension is sealed into the app's signature.
codesign --force --options runtime --sign "$IDENTITY" --entitlements "$OUT_DIR/extension.entitlements" "$EXT"
codesign --force --options runtime --sign "$IDENTITY" --entitlements "$OUT_DIR/host.entitlements" "$APP"
codesign --verify --deep --strict "$APP"

echo "built $APP ($VERSION, build $BUILD_NUMBER, team $TEAM_ID)"
[[ -n "$APP_PROFILE" ]] ||
    echo "warning: no provisioning profiles; macOS will refuse to launch this build" >&2

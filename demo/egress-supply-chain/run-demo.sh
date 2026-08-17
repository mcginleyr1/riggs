#!/usr/bin/env bash
# Riggs egress supply-chain demo (MVP acceptance row #5).
#
# Proves: default-deny per-process egress stops a poisoned npm/pip install script
# from beaconing to a C&C host, while the package registry stays reachable — and
# keeps blocking the beacon even after the C&C is added to the GLOBAL allowlist
# (per-process confinement a network-layer ACL cannot do).
#
# Tier 1 (runs today, no Xcode): probes the daemon's decision engine over its
#         Unix socket. Proves the brain.
# Tier 2 (needs the riggs-filter Network Extension loaded): runs the fake
#         poisoned postinstall and shows the beacon actually dropped on the wire.
#
# Usage:  ./run-demo.sh
# Env:    RIGGS_DEMO_CANDC   C&C stand-in host (default: example.com)
#         RIGGS               path to the riggs CLI (default: riggs on PATH)
set -uo pipefail

CANDC="${RIGGS_DEMO_CANDC:-example.com}"
RIGGS="${RIGGS:-riggs}"
SOCK="/var/run/riggs.sock"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
POLICY_DEST="${RIGGS_POLICY_DEST:-$REPO_ROOT/config/egress-policy.toml}"

bold=$(printf '\033[1m'); dim=$(printf '\033[2m'); grn=$(printf '\033[32m')
red=$(printf '\033[31m'); ylw=$(printf '\033[33m'); rst=$(printf '\033[0m')
pass=0; fail=0
ok()   { echo "${grn}  PASS${rst} $*"; pass=$((pass+1)); }
bad()  { echo "${red}  FAIL${rst} $*"; fail=$((fail+1)); }
info() { echo "${dim}  $*${rst}"; }
hdr()  { echo; echo "${bold}== $* ==${rst}"; }

# expect <allow|deny> <process_path> <host> <why>
expect() {
  local want=$1 proc=$2 host=$3 why=$4 rc
  python3 "$HERE/probe.py" "$proc" "$host" >/tmp/riggs_probe.$$ 2>&1; rc=$?
  local got; case $rc in 0) got=allow;; 3) got=deny;; *) got=error;; esac
  local line; line=$(cat /tmp/riggs_probe.$$); rm -f /tmp/riggs_probe.$$
  if [ "$got" = "$want" ]; then ok "$why  ${dim}[$line]${rst}"
  else bad "$why — expected $want, got $got  ${dim}[$line]${rst}"; fi
}

hdr "Preconditions"
[ -S "$SOCK" ] || { echo "${red}daemon socket $SOCK not found — start the riggs daemon first.${rst}"; exit 1; }
command -v python3 >/dev/null || { echo "${red}python3 required${rst}"; exit 1; }
command -v "$RIGGS" >/dev/null || info "riggs CLI not on PATH ('$RIGGS'); policy mutation steps will be skipped."
info "daemon socket: $SOCK"
info "C&C stand-in:  $CANDC"

hdr "Load demo policy (enforce; node/npm confined to the registry)"
mkdir -p "$(dirname "$POLICY_DEST")"
cp "$HERE/egress-policy.demo.toml" "$POLICY_DEST"
info "wrote $POLICY_DEST — waiting for hot-reload..."
sleep 1
if command -v "$RIGGS" >/dev/null; then "$RIGGS" egress status || true; fi

hdr "Tier 1 — decision engine (no extension needed)"
expect allow /usr/local/bin/node registry.npmjs.org "npm reaches its registry"
expect deny  /usr/local/bin/node "$CANDC"           "npm's postinstall beacon to C&C is denied"
expect deny  /usr/bin/curl       "$CANDC"           "unrelated process to C&C is denied (default-deny)"

if command -v "$RIGGS" >/dev/null; then
  hdr "Tier 1 — per-process confinement (the money shot)"
  info "Adding $CANDC to the GLOBAL allowlist..."
  "$RIGGS" egress allow "$CANDC" >/dev/null && sleep 1
  expect allow /usr/bin/curl       "$CANDC" "unrelated process CAN now reach $CANDC (global allow)"
  expect deny  /usr/local/bin/node "$CANDC" "but node/npm STILL cannot — confined to its rule"
  info "Reverting global allowlist..."
  "$RIGGS" egress deny "$CANDC" >/dev/null && sleep 1
fi

hdr "Tier 2 — live packet drop (needs the Network Extension)"
EXT_LOADED=""
if command -v systemextensionsctl >/dev/null; then
  systemextensionsctl list 2>/dev/null | grep -qi "riggs" && EXT_LOADED=1
fi
if [ -n "$EXT_LOADED" ]; then
  info "riggs-filter extension detected — running the fake poisoned postinstall."
  info "(watch blocks in another terminal: log stream --predicate 'subsystem == \"com.riggs.filter\"')"
  ( cd "$HERE/poisoned-package" && RIGGS_DEMO_CANDC="$CANDC" node beacon.js )
  rc=$?
  case $rc in
    0) ok "live: registry reachable, beacon dropped on the wire";;
    1) bad "live: beacon reached the C&C — enforcement not effective";;
    *) info "live: inconclusive (connectivity). rc=$rc";;
  esac
else
  info "${ylw}riggs-filter Network Extension not loaded — skipping the live packet-drop step.${rst}"
  info "Tier 1 above already proved the decision engine end-to-end through the real daemon IPC."
  info "To run Tier 2: build + sign the extension in extensions/riggs-filter, enable"
  info "  developer mode ( sudo systemextensionsctl developer on ), load it, then re-run."
fi

hdr "Result"
echo "  ${grn}$pass passed${rst}, ${red}$fail failed${rst}"
[ "$fail" -eq 0 ]

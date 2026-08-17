# Demo: default-deny egress stops a supply-chain beacon

This is the runnable proof for **MVP acceptance row #5** — Riggs' differentiator.
It demonstrates that a poisoned `npm`/`pip` pre/post-install script cannot beacon
stolen credentials to a C&C host, while the package registry stays reachable —
and that the block holds *per process* even when the C&C is globally allowed.

Why this matters: network-layer tools (Zscaler, firewall ACLs) allow or deny a
destination for the whole host. Riggs scopes egress to the **originating
process**, so `npm` can reach `registry.npmjs.org` and *nothing else*, even
though your browser on the same box can reach the whole internet.

## Two tiers

| Tier | Proves | Needs |
|------|--------|-------|
| **1 — decision engine** | the per-process allow/deny/confine logic, through the real daemon IPC | a running daemon (no Xcode) |
| **2 — live packet drop** | the beacon is actually dropped on the wire | the `riggs-filter` Network Extension built + loaded |

Tier 1 runs **today**. Tier 2 is the full visual demo once you're on a machine
with Xcode and can load the system extension.

## Files

- `egress-policy.demo.toml` — demo policy: `enforce`, `node`/`npm` confined to the registry, C&C stand-in deliberately absent.
- `probe.py` — sends `EgressCheckFlow` to the daemon and prints the verdict. `probe.py suite [candc]` runs the canonical matrix.
- `run-demo.sh` — orchestrates both tiers with PASS/FAIL output.
- `poisoned-package/` — a benign stand-in for a poisoned dependency; its `postinstall` runs `beacon.js`, which fetches the registry (legit) then tries to exfiltrate a **fake** credential to the C&C stand-in.

Nothing harmful leaves the box: the "secret" is the literal
`FAKE-CREDENTIAL-demo-do-not-use`, and the C&C stand-in defaults to `example.com`
(override with `RIGGS_DEMO_CANDC`). Only run this against your own host.

## Quick start (Tier 1, today)

```bash
# 1. Build + start the daemon (standalone, no console). From the repo root:
cargo run -p riggs-daemon        # or your built binary; needs the Unix socket up

# 2. Load the demo policy where the daemon looks (it hot-reloads):
cp demo/egress-supply-chain/egress-policy.demo.toml config/egress-policy.toml
#    (or /etc/riggs/egress-policy.toml if that's your configured path)

# 3. Prove the engine:
./demo/egress-supply-chain/run-demo.sh
#    …or eyeball the matrix directly:
python3 demo/egress-supply-chain/probe.py suite example.com
```

Expected Tier-1 result:

```
[ALLOW]   node -> registry.npmjs.org     npm reaches its registry
[DENY ]   node -> example.com            postinstall beacon to C&C denied
[DENY ]   curl -> example.com            default-deny for unrelated process
# after `riggs egress allow example.com`:
[ALLOW]   curl -> example.com            unrelated process may now reach it
[DENY ]   node -> example.com            npm STILL cannot — confined to its rule
```

That last pair is the whole pitch: a globally-allowed host is still unreachable
from the confined toolchain.

## Full demo (Tier 2, needs Xcode)

1. Build and sign `extensions/riggs-filter` (needs an Apple Developer account and
   the Network Extension entitlement).
2. Enable local system-extension development and load it:
   ```bash
   sudo systemextensionsctl developer on
   # install the containing app / load the extension, approve it in
   # System Settings > General > Login Items & Extensions > Network Extensions
   systemextensionsctl list | grep -i riggs   # confirm it's [activated enabled]
   ```
3. In one terminal, watch blocks:
   ```bash
   log stream --predicate 'subsystem == "com.riggs.filter"'
   ```
4. Re-run `./run-demo.sh`. With the extension loaded it also runs the fake
   poisoned postinstall and you'll see:
   - `registry fetch (legit): connected` (allowed),
   - `beacon to C&C: connection ... timed out (egress drop)` (blocked),
   - an `EGRESS BLOCK [enforce]: pid … (…/node) -> example.com` line in the log,
   - `RESULT: PASS — registry reachable, beacon blocked.`

To contrast enforce vs. monitor:

```bash
riggs egress mode monitor     # beacon now succeeds but is logged as would-block
riggs egress mode enforce     # beacon dropped again
```

## Cleanup

```bash
riggs egress mode enforce           # restore your intended mode
git checkout config/egress-policy.toml 2>/dev/null || rm -f config/egress-policy.toml
```

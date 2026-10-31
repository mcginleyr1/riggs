# Running Riggs standalone (no console)

Riggs runs fully on-device with no cloud dependency. The Murtaugh console is
optional; when `cloud_enabled = false` (the default) the daemon never connects
out, and all detection, response, storage, and retention run locally.

## Minimal config

`config/riggs.toml` already defaults to standalone. The only line that matters
for "no console" is:

```toml
[comms]
cloud_enabled = false          # default — no console connection is attempted
```

Everything else works locally out of the box with secure defaults.

## What runs locally

- Sensors → detection pipeline (static AI, behavioral, rules/YARA, threat intel)
- Response engine (kill / quarantine / network containment)
- Local event/verdict/response store (redb) with automatic retention
- Threat-intel feed refresh (MalwareBazaar / URLhaus / OSV) straight from the agent.
  MalwareBazaar and URLhaus need a free abuse.ch Auth-Key (https://auth.abuse.ch/)
  in `[intel.feeds] abusech_auth_key`; edit riggs.toml directly (a secret on the
  `riggs config` command line would land in shell history)

## Local control (Unix socket, no network)

```
riggs status              # daemon + counters
riggs config              # effective config (secrets redacted)
riggs events -n 50        # recent events
riggs threats             # detections
```

State-changing commands require running as the daemon owner; read-only status
queries are open to the local user.

## Tuning it for your box

All operator policy is config, not code (see `config/riggs.toml` for the full
list). The knobs you're most likely to touch standalone:

```toml
[engine]
merge_malicious_threshold = 0.7      # detection sensitivity
merge_suspicious_threshold = 0.3
static_ai_max_scan_mib = 64          # lower on tiny hosts
stage_timeout_ms = 5000              # per-stage budget; overruns on files report Suspicious
behavioral_max_storylines = 4096     # memory bound

[detection]
exfil_outbound_threshold = 50
threat_score_threshold = 0.5
persistence_paths = [ "/etc/cron.d", "..." ]   # add your own

[store]
retention_days = 90                  # how long telemetry is kept

[response]
auto_respond = true                  # set false to alert-only
quarantine_path = "/var/lib/riggs/quarantine"
```

## Egress allowlist (default-deny, standalone)

Stops supply-chain install-script exfil: a poisoned `npm`/`pip`/etc. pre/post-
install script that tries to beacon credentials to a C&C host is denied, because
egress rules are scoped to the originating process — the registry is allowed,
the beacon is not. Runs entirely on-device; no console, no Zscaler.

Policy lives in `/etc/riggs/egress-policy.toml` (or `config/egress-policy.toml`
in a dev checkout). It is loaded at startup, and the daemon refuses to start if
the file doesn't parse; unknown keys count as errors, so a typo can't silently
disable a rule. Changes, including creating the file, are picked up without a
restart. A change that doesn't parse keeps the current policy and logs an
error, and the daemon won't start again until it is fixed. A starter file with
a dev-tooling profile ships in the repo as `config/egress-policy.toml`; copy it
to `/etc/riggs/` to use it. Manage it locally:

```
riggs egress status                    # mode + allow-domain / process-rule counts
riggs egress allow github.com          # add to the global allowlist
riggs egress deny  old-vendor.com
riggs egress mode monitor              # off | monitor | enforce
```

**Roll out with monitor first:** `mode = "monitor"` never drops a flow but logs
every would-block, so you can see what `enforce` would break before flipping it
on. `mode = "off"` disables it entirely on demand.

### Platform enforcement

**macOS** — enforcement runs inline in the `riggs-filter` Network Extension,
which queries the daemon per flow and gets a per-process verdict from the
originating PID's audit token. This is the full feature, including process-scoped
rules. Without the extension installed ("macOS network filter" below) nothing
is enforced.

How it sees destinations and what it does on failure:

- **Hostnames.** macOS only fills in a flow's hostname for apps on
  Network.framework/NSURLSession. CLI tools (npm/node, pip, cargo, git, curl)
  use BSD sockets, so for outbound TCP the filter holds the first bytes, reads
  the SNI from the TLS ClientHello and decides on that name. The TCP handshake
  completes first; a dropped flow sends no payload. Non-TLS flows
  (ssh, plain HTTP) and UDP (DNS, QUIC) are decided on the remote IP, so
  allow those with `allow_cidrs`/`allow_ports`, not `allow_domains`.
- **SNI is client-chosen.** It names where an honest client is going; a
  targeted attacker can send an allowlisted name to a C&C IP. Domain rules
  stop an install script beaconing to its own domain, not one that forges SNI.
- **Fail-open.** If the daemon doesn't answer (stopped, crashed, wedged past
  the 500 ms timeout) every flow is allowed, even in `enforce` mode, so Riggs
  can never take the network down. The filter logs once when the daemon goes
  unreachable and once when it is back (`log stream --predicate
  'subsystem == "com.riggs.filter"'`).

**Linux** — the policy engine and the nftables ruleset generator
(`riggs_egress::nftables::render_ruleset`) are implemented and unit-tested: they
turn the CIDR/port/baseline allowlist plus resolved allow-domain IPs into a
default-deny `inet` table. The remaining runtime, which needs a Linux host with
`CAP_NET_ADMIN`, is a milestone:

1. **Domain → IP resolution.** nftables matches addresses, not SNI, so
   `allow_domains` must be resolved and kept fresh (DNS-snoop or periodic
   resolve) and fed into `render_ruleset`.
2. **Apply / teardown.** Pipe the rendered script to `nft -f -`; on daemon exit
   or a switch to `off`/`monitor`, `nft delete table inet riggs_egress` so the
   host fails open.
3. **Per-process attribution.** The process-scoped rules (npm → registry only)
   need eBPF/cgroup socket attribution, which nftables alone cannot express.
   Until then Linux enforces the host-level default-deny allowlist, which already
   blocks a beacon to an un-allowlisted C&C host.

## macOS network filter

The filter is a system extension inside `Riggs Filter.app`. Network
Extensions are sandboxed, so the daemon also listens on a root-only (0600,
uid 0) socket in the app group the extension shares with it,
`comms.filter_socket_path` in `riggs.toml`. The extension falls back to
`/var/run/riggs.sock`.

Content-filter and system-extension entitlements are restricted: macOS kills
the app at launch unless a provisioning profile grants them. One-time setup in
the Apple Developer portal (Certificates, Identifiers & Profiles), using the
Team ID the filter is signed with (default `3KSC5YWCZ6`; change `TEAM_ID` for
`build.sh` and `filter_socket_path` together):

1. **Devices**: register this Mac's Provisioning UDID
   (`system_profiler SPHardwareDataType | grep "Provisioning UDID"`).
2. **Identifiers → App IDs** (explicit, macOS):
   - `com.riggs.filter` with *System Extension* and *Network Extensions*
   - `com.riggs.filter.extension` with *Network Extensions*.
   The app group `<TEAM_ID>.com.riggs` needs no registration; macOS accepts
   Team-ID-prefixed groups.
3. **Profiles**: a *macOS App Development* profile for each App ID, with your
   Apple Development certificate and this Mac. Download both.

Then build, install and activate:

```
extensions/riggs-filter/build.sh \
    --app-profile ~/Downloads/Riggs_Filter.provisionprofile \
    --extension-profile ~/Downloads/Riggs_Filter_Extension.provisionprofile
sudo install/install.sh
```

`build.sh` refuses a profile for the wrong App ID or without the content
filter entitlement; it signs with `content-filter-provider-systemextension`, or
`content-filter-provider` when a development profile grants only that. A
Developer ID build for other Macs also needs notarization. `install.sh`
copies the app to `/Applications` (macOS only activates system extensions from
there) and runs its `--activate`; approve the extension in System Settings →
General → Login Items & Extensions → Network Extensions, then allow the
content filter when asked. Check it any time with:

```
"/Applications/Riggs Filter.app/Contents/MacOS/riggs-filter" --status
```

`--deactivate` turns the filter off and removes the extension;
`install/uninstall.sh` runs it. Each build gets a new `CFBundleVersion`
(`BUILD_NUMBER`) because macOS only replaces an active extension whose
version changed.


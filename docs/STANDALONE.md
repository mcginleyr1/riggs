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

- Sensors (process, file, outbound connections) → detection pipeline (static AI,
  behavioral, rules/YARA/IOC, threat intel)
- Response engine (kill / quarantine / network containment)
- Local event/verdict/response store (redb) with automatic retention
- Threat-intel feed refresh (MalwareBazaar / URLhaus / OSV) straight from the agent.
  MalwareBazaar and URLhaus need a free abuse.ch Auth-Key (https://auth.abuse.ch/)
  in `[intel.feeds] abusech_auth_key`; edit riggs.toml directly (a secret on the
  `riggs config` command line would land in shell history)

## Linux file attribution

On Linux the daemon uses fanotify (root, `CAP_SYS_ADMIN`) to tie file events to
the process behind them. Under the watched paths (`/tmp`, `/home`, `/etc`,
`/usr/bin`, `/var/spool/cron`) each write session is reported once, when the
file is closed, with the writer's pid, name, executable, command line and uid;
opens under `/home` and `/tmp` are reported too, for DLP. Creates, renames and
attribute changes still come from inotify and take the pid fanotify saw on the
same file within 2 s, which covers write-then-rename saves such as `crontab -`.
Deletes and directory events (`mkdir`, `touch`/`chmod` on a directory) carry
pid 0: nothing fanotify reports ties them to a process. The daemon's own file
reads are ignored.

Without `CAP_SYS_ADMIN` (not root, an unprivileged container) the daemon logs one
warning, `fanotify unavailable; file events fall back to inotify without process
attribution`, and every file event carries pid 0, so kill and suspend responses
have no process to target.

fanotify marks whole mounts and filters paths in the daemon, so every open on
those mounts reaches it. It marks the mounts holding the watched directories and
every mount below them at startup (a separately mounted `/home/alice`); one it
cannot mark is still reported by inotify, without a pid. A mount added after
startup (a home mounted at login) is watched by neither until the daemon
restarts: inotify watches the directory the mount covers. Idle that costs nothing measurable; in a 20 s
shell-loop stress test (about 3,500 execs/s, 22k fanotify events/s) daemon CPU
rose by 40-90% over inotify alone, with no events lost.

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

On both platforms the daemon also checks every outbound connection the network
sensor observes (it polls the socket tables once a second) and logs
`egress would-block (observed connection)` at warn, once per process and
destination, with the pid, process and reason. These are log lines, not
detections, and they never block. The sensor sees the peer address but not the
hostname, so only `allow_cidrs` can allow these flows: a domain-allowlisted
service still shows up, and a process rule that lists only domains reports
every connection its process makes. The `reason` names the process rule when
one applied. Connections that open and close between two polls are not seen.

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

**Linux** — in `enforce` mode the daemon (as root, or with `CAP_NET_ADMIN`, and
the `nft` binary installed) applies the allowlist as a default-deny
`table inet riggs_egress` on the output hook, so it covers traffic that
originates on the host (including host-network containers, not routed or
bridged container traffic). Check it with `sudo nft list table inet riggs_egress`.

- **Domains are resolved to addresses.** nftables matches addresses, not
  hostnames, so the daemon resolves every allowed domain (and the console host)
  and re-resolves every `resolve_interval_secs` (policy file, default 60). DNS
  answers rotate, so an address stays allowed for an hour after a lookup last
  returned it. A client can still be handed an address the daemon has not seen
  yet and be refused: a host whose DNS gives one rotating address per query
  (github.com does) fails now and then until the daemon has seen its whole
  pool, and so does a client using another resolver (DNS over HTTPS). Allow
  such a service's published ranges as `allow_cidrs` instead (GitHub lists its
  own at `https://api.github.com/meta`).
- **Wildcards are not enforceable.** `*.example.com` cannot be resolved ahead
  of time, so on Linux its hosts are denied; the daemon logs which patterns are
  affected. List the exact hostnames you need (`raw.githubusercontent.com`).
  Matching wildcards needs DNS snooping, which is not built.
- **Process rules are not enforced per process.** nftables cannot tell which
  process opened a socket, so every process rule's destinations join the global
  allowlist for the whole host: npm still reaches its registry, but so can any
  other process, and npm can reach the global allowlist. The default deny still
  refuses a beacon to any host that is in no list. `allow_ports`, when set,
  narrows the process-rule destinations too.
- **The host is never stranded.** Loopback, DNS, DHCP/DHCPv6/NTP (per the
  `[baseline]` toggles), IPv6 neighbor discovery, replies on connections the
  remote side opened (an inbound SSH session), and the console endpoint
  (`[comms] cloud_endpoint`, when `cloud_enabled`) on any port stay allowed.
- **Existing connections are cut.** Packets of connections the host opened are
  checked one by one, so switching to `enforce`, or removing a destination,
  also ends connections already open to hosts not in the allowlist, such as an
  attacker's `ssh -R` tunnel. A denied TCP connection is reset ("Connection
  refused"); other protocols get an ICMP administratively-prohibited error.
- **Changes apply at once and atomically.** Every policy reload, `riggs egress`
  edit, and mode change replaces the table in one `nft` transaction, so there
  is never a moment with no rules or half of them. Switching to `off` or
  `monitor` removes the table.
- **Failures keep the last good rules.** If `nft` is missing or an apply fails,
  the daemon logs an error and the kernel keeps the previous ruleset (or none,
  if nothing was ever applied); it retries on the next change or interval.
- **Clean stop opens, crash stays closed.** On SIGTERM/SIGINT the daemon removes
  the table, since nothing would keep its addresses fresh. A crash leaves it in
  force until the restarted daemon replaces it; to lift it by hand, run
  `sudo nft delete table inet riggs_egress`.
- **The daemon's own traffic is filtered too.** Apart from the console, its
  threat-intel and vulnerability fetches need their hosts allowed
  (`mb-api.abuse.ch`, `urlhaus-api.abuse.ch`, `api.osv.dev`, and
  `www.virustotal.com` / `api.abuseipdb.com` when configured).
- Network containment (`flush ruleset`) also removes the egress table; the next
  refresh restores it.

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


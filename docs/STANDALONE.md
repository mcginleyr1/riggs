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
- Threat-intel feed refresh (MalwareBazaar / URLhaus / OSV) straight from the agent

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

Policy lives in `config/egress-policy.toml` (or `/etc/riggs/egress-policy.toml`),
hot-reloaded on change. A starter file with a dev-tooling profile ships in the
repo. Manage it locally:

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
rules.

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


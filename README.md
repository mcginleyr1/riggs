This is just an experiment to see how models do with the idea.

# Riggs

Local-first endpoint protection for macOS and Linux. All detection runs on-device
with no cloud dependency. Built in Rust.

```
Platform Sensors → Normalization → Detection Pipeline → Response / Store
                                        │
                     ┌──────────────────┼──────────────────┐
                     │                  │                  │
                 Static AI         Behavioral AI       Rules/YARA
                 (ONNX)            (ONNX)              IOC Matching
                     │                  │                  │
                     └──────────────────┼──────────────────┘
                                        │
                              Verdict Merger (weighted)
                                        │
                          ┌─────────────┼─────────────┐
                          │             │             │
                      Response       Store         DLP
                      Engine         (redb)        Correlator
```

## Features

- **Process monitoring** — tracks exec, fork, exit with full process context
- **File monitoring** — watches creates, modifies, deletes, opens across sensitive paths
- **Static AI** — ONNX-based file classification for malware detection
- **Behavioral AI** — sequence-based anomaly detection across event windows
- **YARA rules** — YARA-X engine with hot-reload from rules directories
- **IOC matching** — Aho-Corasick and bloom filter matching against threat feeds
- **Threat intelligence** — VirusTotal, AbuseIPDB, MalwareBazaar, URLhaus, OSV feeds
- **Data loss prevention** — blocks sensitive file uploads to AI assistants and cloud services
- **Storyline correlation** — links events into process-tree storylines
- **Response engine** — kill, suspend, quarantine, network containment
- **Vulnerability scanning** — CVE matching against installed packages via OSV
- **Device control** — USB and Bluetooth policy enforcement
- **Network discovery** — passive and active local network mapping
- **Remote shell** — authenticated, encrypted investigation terminal
- **Menubar app** — macOS status bar with live threat status

## Quick Start

### Prerequisites

The `riggs-cloud` crate compiles gRPC protobufs at build time and requires
`protoc` (the Protocol Buffers compiler) to be installed. Without it, the build
fails in `riggs-cloud/build.rs`.

```
# macOS
brew install protobuf

# Debian / Ubuntu
sudo apt-get install -y protobuf-compiler
```

### Build

```
cargo build --release
```

### Install (macOS)

```
sudo install/install.sh
```

This installs the daemon, CLI, config, and launchd plists. The daemon starts
automatically on boot.

### Verify

```
riggs status
```

### Uninstall

```
sudo install/uninstall.sh
```

## Project Structure

```
crates/
  riggs-types/            Shared types, event model, errors
  riggs-platform/         Platform sensor trait
  riggs-platform-macos/   macOS sensor (Endpoint Security, FSEvents, sysinfo)
  riggs-platform-linux/   Linux sensor (eBPF, inotify, sysinfo)
  riggs-sensor/           Event collection and normalization
  riggs-engine/           Detection pipeline, stage routing, verdict merging
  riggs-static-ai/        Static file analysis via ONNX
  riggs-behavioral-ai/    Behavioral sequence analysis via ONNX
  riggs-rules/            YARA-X, IOC matching, custom TOML rules, hot-reload
  riggs-dlp/              Data loss prevention correlator and policy engine
  riggs-intel/            Threat feeds, bloom filters, verdict caching
  riggs-storyline/        Process-tree correlation
  riggs-response/         Kill, quarantine, network containment
  riggs-store/            redb persistence with compression and retention
  riggs-comms/            Unix socket IPC, DLP query protocol
  riggs-discovery/        ARP scanning and passive traffic analysis
  riggs-device-control/   USB/Bluetooth policy enforcement
  riggs-vuln/             CVE scanning via OSV feeds
  riggs-shell/            Authenticated remote investigation terminal
  riggs-cli/              `riggs` command-line tool
  riggs-daemon/           `riggs-daemon` binary, supervisor, lifecycle
  riggs-menubar/          macOS menu bar status app
extensions/
  riggs-filter/           macOS Network Extension for DLP flow blocking (Swift)
config/
  riggs.toml              Main daemon configuration
  dlp-policy.toml         Default DLP policy (hot-reloadable)
  policies/               Example DLP policies for common scenarios
install/
  install.sh              macOS installer
  uninstall.sh            macOS uninstaller
  launchd/                launchd plist files
docs/                     Architecture and design documents
```

## Configuration

Main config lives at `/etc/riggs/riggs.toml` (or `config/riggs.toml` for
development). See `config/riggs.toml` for all options.

### DLP Policy

DLP is configured via a standalone policy file that hot-reloads on change:

```
/etc/riggs/dlp-policy.toml      # production
config/dlp-policy.toml           # development
```

The policy controls which domains are monitored for sensitive file uploads,
which file types are blocked or flagged, and which processes are excluded.

Example: block Office document uploads to AI assistants:

```toml
action = "block"
correlation_window_secs = 30

[[watched_domains]]
pattern = "claude.ai"
category = "ai-assistant"

[[watched_domains]]
pattern = "*.openai.com"
category = "ai-assistant"

[file_types]
block = ["pptx", "xlsx", "docx", "pdf"]
alert = ["csv", "json"]

[excluded_processes]
names = ["softwareupdated"]
```

Pre-built policies for common scenarios are in `config/policies/`:

| Policy | Use Case |
|---|---|
| `ai-lockdown.toml` | Block uploads to all major AI services |
| `cloud-storage.toml` | Block uploads to cloud storage and file sharing |
| `source-code-protect.toml` | Block source code and secrets from leaving the machine |
| `alert-only.toml` | Monitor everything, block nothing (audit mode) |

Install one with:

```
sudo cp config/policies/ai-lockdown.toml /etc/riggs/dlp-policy.toml
```

Changes take effect immediately.

## CLI

```
riggs status             Daemon status and active threat count
riggs threats            List detected threats with severity
riggs events             Query event log (--storyline, --limit)
riggs config [<key> <value>]  View config, or save a change to riggs.toml (applies on restart)
riggs scan <path>        Scan files through the detection pipeline (static AI, YARA, hash intel)
riggs quarantine [restore <id>]  List quarantined files, or restore one
riggs intel [status|update]   Threat intelligence feeds (update = refresh now)
riggs dlp [status|policy]     DLP module status and active policy
riggs vuln update             Scan installed packages against OSV.dev, report to console
```

## Detection Pipeline

Events flow through a multi-stage detection pipeline:

1. **Threat intel** — bloom filter + API lookups against known-bad indicators
2. **Static AI** — ONNX model scores files on structural features
3. **Rules** — YARA-X pattern matching + IOC matching + custom TOML rules
4. **Behavioral AI** — ONNX model scores event sequences for anomalous behavior
5. **DLP** — correlates file accesses with network flows to watched domains

Each stage returns a verdict with a confidence score. The verdict merger
computes a weighted average to produce a final threat level (Clean, Suspicious,
Malicious). Stages run in parallel where possible.

## How DLP Works

DLP does not inspect encrypted traffic. Instead it correlates two signals:

1. The file sensor sees a process open a sensitive file (e.g., `.pptx`)
2. The network filter sees that same process connect to a watched domain

Same PID + sensitive file + watched domain within the correlation window = block.

On macOS, the network filter is a System Extension using `NEFilterDataProvider`
(in `extensions/riggs-filter/`). It queries the daemon over a Unix socket for
allow/block verdicts. The daemon's DLP correlator responds in under 1ms.

Magic byte detection prevents evasion by file renaming (e.g., renaming `.pptx`
to `.txt` — the OOXML `PK` header is still detected).

## Design Principles

- **Local-first** — all detection on-device, no cloud required
- **Fail-fast** — bad state crashes and restarts, no limping
- **Unidirectional data flow** — sensors → engine → response, never upstream
- **Bounded channels** — natural backpressure, no unbounded memory growth
- **Simple over clever** — TOML config, flat crate structure, typed errors

## Development

```
make fmt                 # cargo fmt --check
make clippy              # clippy, warnings are errors
make test                # run all tests
cargo test -p riggs-dlp  # test a specific crate
```

CI runs the same checks on Linux, plus `mix format --check-formatted`,
`mix credo` and `mix test` for Murtaugh (see `DEVELOPMENT.md`).

The workspace has 25 crates. Each crate is independently testable. See
`docs/DEVELOPMENT_PHASES.md` for the implementation roadmap.

## Documentation

| Document | Contents |
|---|---|
| `docs/ARCHITECTURE.md` | System design, supervisor tree, channel map |
| `docs/DETECTION_PIPELINE.md` | Stage orchestration, verdict merging |
| `docs/EVENT_MODEL.md` | Event types and field definitions |
| `docs/PLATFORM_ABSTRACTION.md` | Platform sensor implementations |
| `docs/RESPONSE_ENGINE.md` | Response actions and policies |
| `docs/RULE_SYSTEM.md` | YARA-X, IOC matching, custom rules |
| `docs/ML_PIPELINE.md` | ONNX inference pipelines |
| `docs/DATA_LAYER.md` | redb schema and query patterns |
| `docs/COMMUNICATION.md` | IPC and cloud protocols |
| `docs/FEATURES.md` | Network discovery, device control, vuln scanning, shell |
| `docs/DLP_IMPLEMENTATION_PLAN.md` | DLP module architecture and phased plan |
| `docs/DEVELOPMENT_PHASES.md` | Five-phase development roadmap |

## License

MIT

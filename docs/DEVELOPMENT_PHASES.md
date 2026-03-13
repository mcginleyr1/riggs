# Riggs: Development Phases

## Overview

Development is organized into five sequential phases. Each phase builds on the
previous one and has clear verification criteria that must pass before moving
to the next phase. This phasing ensures the foundation is solid before adding
complexity.

Each phase produces a working, testable system at its boundary. There are no
"big bang" integrations.

## Phase 1: Foundation

**Goal**: Establish shared types, platform sensor, event normalization, and
local storage. At the end of this phase, the system can capture events from
the OS and persist them.

### Crates Built

| Crate                  | Purpose                                    |
|------------------------|--------------------------------------------|
| riggs-types            | All shared types, event model, error types |
| riggs-platform         | PlatformSensor trait, abstractions          |
| riggs-platform-macos   | Endpoint Security Framework sensor         |
| riggs-platform-linux   | eBPF sensor (Aya)                          |
| riggs-platform-windows | Stub implementation                        |
| riggs-sensor           | Event normalization, OCSF emission         |
| riggs-store            | redb database, tables, read/write paths    |

### Work Items

#### riggs-types

- [ ] Define `EventEnvelope` with all OCSF fields.
- [ ] Define all event payload types: `ProcessEvent`, `FileEvent`,
  `NetworkEvent`, `RegistryEvent`, `DNSEvent`, `AuthEvent`, `KernelEvent`.
- [ ] Define `ProcessContext`, `FileHash`, `Severity`, `EventMetadata`.
- [ ] Define `Verdict`, `Disposition`, `StageResult`.
- [ ] Define `Storyline`, `StorylineEdge`, `EdgeRelation`.
- [ ] Define `ResponseAction` and all action variants.
- [ ] Define `QuarantineRecord`, `ResponseAuditEntry`.
- [ ] Implement `serde::Serialize` + `serde::Deserialize` for all types.
- [ ] Unit tests for serialization round-trip of every type.

#### riggs-platform

- [ ] Define `PlatformSensor` trait with all methods.
- [ ] Define `RawPlatformEvent` enum with platform-specific variants.
- [ ] Define `PlatformError` error type.
- [ ] Implement `MockSensor` for testing (replays events from JSON).
- [ ] Unit tests for `MockSensor` event replay.

#### riggs-platform-macos

- [ ] Initialize Endpoint Security client.
- [ ] Subscribe to process, file, network, auth, and kernel event types.
- [ ] Convert ES events to `MacOSRawEvent`.
- [ ] Apply default mute rules (self, spotlight, mds).
- [ ] Handle ES client lifecycle (create, destroy, error recovery).
- [ ] Integration tests (require root + entitlement).

#### riggs-platform-linux

- [ ] Write eBPF programs for process, file, and network tracepoints.
- [ ] Compile eBPF programs with aya-bpf.
- [ ] Load eBPF programs from user-space via Aya.
- [ ] Read events from perf ring buffers.
- [ ] Supplement eBPF events with procfs data.
- [ ] Convert to `LinuxRawEvent`.
- [ ] Integration tests (require root + CAP_SYS_ADMIN).

#### riggs-sensor

- [ ] Implement `SensorNormalizer` for macOS raw events.
- [ ] Implement `SensorNormalizer` for Linux raw events.
- [ ] Timestamp normalization (platform-specific → UTC).
- [ ] Process context table (pid → ProcessContext mapping).
- [ ] Sequence number tracking and gap detection.
- [ ] Unit tests with mock events, verify OCSF output.

#### riggs-store

- [ ] Create database and all tables on first run.
- [ ] Implement write path for events, verdicts, quarantine, audit, config.
- [ ] Implement read path with query filters (time range, storyline, type).
- [ ] Implement index table maintenance.
- [ ] Implement zstd compression for event payloads.
- [ ] Implement retention policy compaction.
- [ ] Implement schema version tracking and migration framework.
- [ ] Implement corruption detection and recovery.
- [ ] Unit tests for all CRUD operations.
- [ ] Property-based tests for serialization/compression round-trip.

### Verification Criteria

- [ ] `cargo check` passes for all Phase 1 crates.
- [ ] `cargo clippy` passes with no warnings.
- [ ] `cargo test` passes for all Phase 1 crates.
- [ ] On macOS (with entitlement): sensor captures process exec, file create,
  and network connect events correctly.
- [ ] Events are normalized to OCSF format with correct timestamps and
  process context.
- [ ] Events are persisted to redb and queryable by time range and storyline.
- [ ] Zstd compression reduces event storage by ~3x.
- [ ] Retention compaction deletes expired events without data loss.
- [ ] Database survives simulated crash (kill -9 during writes) without
  corruption.

## Phase 2: Detection Core

**Goal**: Add the detection pipeline with static AI and rules matching. At the
end of this phase, the system can detect malicious files via ML and rules.

### Crates Built

| Crate              | Purpose                                       |
|--------------------|-----------------------------------------------|
| riggs-engine       | Detection pipeline orchestrator               |
| riggs-static-ai    | File feature extraction, ONNX inference       |
| riggs-rules        | YARA-X, IOC matching, rule loading/hot-reload |

### Work Items

#### riggs-static-ai

- [ ] Mach-O feature extraction via goblin (256-float vector).
- [ ] ELF feature extraction via goblin.
- [ ] Shannon entropy calculation per section.
- [ ] String statistics extraction.
- [ ] Feature normalization using features.json schema.
- [ ] ONNX model loading via `ort`.
- [ ] Fallback to `tract-onnx` when ort is unavailable.
- [ ] Static prediction with malicious probability and confidence.
- [ ] Model hot-reload on active.toml change.
- [ ] Unit tests with known benign and malicious sample features.
- [ ] Benchmark: feature extraction + inference < 50ms per file.

#### riggs-rules

- [ ] YARA-X rule loading from default/ and custom/ directories.
- [ ] YARA-X rule compilation into Rules object.
- [ ] YARA-X scanning of files with match extraction.
- [ ] IOC file parsing (sha256, md5, ip, cidr, domain, url).
- [ ] IOC compilation into HashSet (hashes, IPs) and Aho-Corasick (domains).
- [ ] IOC matching against event fields.
- [ ] Rule hot-reload via notify file watcher.
- [ ] Debounced reload (500ms window).
- [ ] Partial failure isolation (bad rule file does not block others).
- [ ] Publish compiled rules to watch channel.
- [ ] Unit tests for each rule type matching.
- [ ] Unit tests for hot-reload behavior.

#### riggs-engine

- [ ] File gate: intercept new/modified executables.
- [ ] Allowlist fast path (platform binaries, known-safe hashes, path patterns).
- [ ] Route files through static AI → rules → verdict merger.
- [ ] Verdict merger: weighted score aggregation.
- [ ] Verdict caching by SHA-256.
- [ ] Cache invalidation on rule/model reload.
- [ ] Concurrent file analysis (up to num_cpus).
- [ ] Metrics collection per pipeline stage.
- [ ] Unit tests with mock events and mock models.
- [ ] Integration test: known malicious file detected, verdict persisted.

### Verification Criteria

- [ ] `cargo check` and `cargo clippy` pass for all Phase 1 + 2 crates.
- [ ] `cargo test` passes for all Phase 1 + 2 crates.
- [ ] Static AI produces correct predictions for a test corpus of
  benign/malicious Mach-O files (AUC-ROC > 0.95 on test set).
- [ ] YARA rules match known test samples.
- [ ] IOC hash matching correctly identifies known-bad hashes.
- [ ] Verdict merger produces correct weighted scores.
- [ ] Verdict cache returns cached results without re-running pipeline.
- [ ] Rule hot-reload picks up new/modified rules within 2 seconds.
- [ ] File analysis pipeline latency < 70ms for a typical Mach-O binary.
- [ ] Engine handles 100 concurrent file analysis tasks without deadlock.

## Phase 3: Advanced Detection

**Goal**: Add behavioral AI, storyline correlation, and STAR rules. At the
end of this phase, the system can detect behavioral threats and correlate
events into storylines.

### Crates Built

| Crate                | Purpose                                     |
|----------------------|---------------------------------------------|
| riggs-behavioral-ai  | Behavioral feature extraction, ONNX model   |
| riggs-storyline      | Process tree correlation, storyline graph    |

### Work Items

#### riggs-behavioral-ai

- [ ] Event window management per storyline (100 events or 60s).
- [ ] Behavioral feature extraction (process, file, network, temporal).
- [ ] Temporal feature extraction (inter-event times, burst rates, buckets).
- [ ] Sequence embedding computation.
- [ ] ONNX model loading and inference.
- [ ] Evaluation scheduling (timer, threshold, trigger).
- [ ] Attack stage classification.
- [ ] MITRE technique scoring.
- [ ] Unit tests with synthetic event sequences.
- [ ] Benchmark: behavioral inference < 200ms.

#### riggs-storyline

- [ ] Process tree construction from ProcessEvent::Exec/Fork/Exit.
- [ ] Storyline ID assignment and inheritance.
- [ ] Storyline graph with edges (Spawned, Created, Executed, etc.).
- [ ] Event-to-storyline linking by pid, file causation, DNS causation.
- [ ] Storyline scoring (max severity + accumulated indicators).
- [ ] Threshold evaluation and response dispatch trigger.
- [ ] Storyline persistence to redb.
- [ ] Storyline status management (Active, Completed, Mitigated).
- [ ] Unit tests for process tree construction.
- [ ] Unit tests for cross-event correlation (file→exec, DNS→connect).
- [ ] Unit tests for scoring and threshold evaluation.

#### riggs-engine (updates)

- [ ] Integrate behavioral AI into the pipeline.
- [ ] Route all events to behavioral AI event windows.
- [ ] Integrate storyline correlation after verdict merger.
- [ ] Update verdict merger to include behavioral AI scores.

#### riggs-rules (updates)

- [ ] STAR rule parsing from TOML format.
- [ ] STAR state machine compilation (conditions → closures).
- [ ] STAR state machine execution (event matching, transitions).
- [ ] STAR TTL expiration and garbage collection.
- [ ] STAR state persistence to redb (rule_state table).
- [ ] STAR state restoration on daemon restart.
- [ ] Unit tests for STAR rule matching with event sequences.
- [ ] Unit tests for TTL expiration.

### Verification Criteria

- [ ] `cargo check` and `cargo clippy` pass for all Phase 1-3 crates.
- [ ] `cargo test` passes for all Phase 1-3 crates.
- [ ] Behavioral AI detects simulated shell-download-execute attack sequence.
- [ ] Storyline correctly links: process exec → DNS query → network connect →
  file download → child process exec.
- [ ] Storyline scoring crosses threshold on accumulated suspicious events.
- [ ] STAR rules detect "shell download and execute" pattern in replay test.
- [ ] STAR state machines are garbage-collected after TTL expiry.
- [ ] STAR state survives simulated daemon restart.
- [ ] Full pipeline (static + behavioral + rules + storyline) processes
  5000 events/second without backpressure.
- [ ] Memory usage during behavioral evaluation stays below 100 MB for
  100 active storylines.

## Phase 4: Operational

**Goal**: Add response engine, CLI, and daemon supervisor. At the end of this
phase, the system is a fully operational endpoint protection agent.

### Crates Built

| Crate            | Purpose                                        |
|------------------|------------------------------------------------|
| riggs-response   | Response action execution, policy engine       |
| riggs-cli        | Command-line interface binary                  |
| riggs-daemon     | Daemon binary, supervisor, lifecycle           |

### Work Items

#### riggs-response

- [ ] ProcessKill implementation (SIGTERM → SIGKILL with pid verification).
- [ ] ProcessSuspend implementation (SIGSTOP, optional auto-resume timer).
- [ ] FileQuarantine implementation (copy, encrypt, overwrite, delete).
- [ ] FileDelete implementation (optional secure overwrite).
- [ ] NetworkContain implementation (pf/iptables rule management).
- [ ] Rollback implementation (snapshot store, file restoration).
- [ ] Policy engine (TOML parsing, severity→action mapping).
- [ ] Policy hot-reload.
- [ ] Allowlist checking.
- [ ] Dry-run mode.
- [ ] Manual approval queue.
- [ ] Audit trail recording for every action.
- [ ] Per-storyline action sequencing.
- [ ] Action deduplication.
- [ ] Unit tests for each response action (with mock filesystem/process).
- [ ] Unit tests for policy evaluation.

#### riggs-cli

- [ ] Unix socket client connecting to daemon.
- [ ] All CLI commands: status, events, verdicts, storyline, quarantine,
  contain, rules, audit, config, metrics.
- [ ] Output formatting (table, json, jsonl).
- [ ] Error handling and user-friendly error messages.
- [ ] Shell completion generation (bash, zsh, fish).
- [ ] Integration tests against running daemon.

#### riggs-daemon

- [ ] Tokio runtime initialization.
- [ ] Configuration loading (file, env, CLI args).
- [ ] Channel creation (all mpsc, broadcast, watch channels).
- [ ] Supervised task spawning (JoinSet).
- [ ] Task failure detection and restart with backoff.
- [ ] Degraded mode on repeated task failures.
- [ ] Signal handling (SIGTERM, SIGINT → graceful shutdown).
- [ ] Graceful shutdown sequence (drain, flush, close).
- [ ] IPC socket listener.
- [ ] Startup sequence (config → db → rules → models → sensors → engine).
- [ ] PID file management.
- [ ] Logging initialization (tracing-subscriber with env-filter).
- [ ] Integration test: daemon starts, captures events, detects threat,
  executes response, shuts down cleanly.

### Verification Criteria

- [ ] `cargo check` and `cargo clippy` pass for all Phase 1-4 crates.
- [ ] `cargo test` passes for all Phase 1-4 crates.
- [ ] Daemon starts, runs, and shuts down cleanly on SIGTERM.
- [ ] Daemon restarts failed tasks automatically.
- [ ] CLI connects to daemon and all commands return data.
- [ ] `riggs status` shows healthy sensor, engine, and store.
- [ ] ProcessKill terminates a test process.
- [ ] FileQuarantine moves a file to the vault and it is no longer executable.
- [ ] FileQuarantine restore puts the file back with correct permissions.
- [ ] NetworkContain blocks outbound traffic except allowed endpoints.
- [ ] NetworkContain release restores normal networking.
- [ ] Policy dry-run mode logs actions without executing them.
- [ ] Audit trail records all response actions.
- [ ] End-to-end test: malicious file dropped → detected → quarantined →
  audit entry created → queryable via CLI.
- [ ] Daemon survives kill -9 and restarts cleanly (no database corruption,
  no orphaned socket files).

## Phase 5: Full Feature Set

**Goal**: Add all remaining features: cloud communication, network discovery,
device control, vulnerability scanning, and remote investigation shell.

### Crates Built

| Crate                | Purpose                                     |
|----------------------|---------------------------------------------|
| riggs-comms          | Cloud gRPC client (feature-gated), IPC      |
| riggs-discovery      | Network discovery (ARP + passive)           |
| riggs-device-control | USB/Bluetooth policy enforcement            |
| riggs-vuln           | Vulnerability scanning                      |
| riggs-shell          | Remote investigation shell                  |

### Work Items

#### riggs-comms

- [ ] Move IPC logic from daemon to comms crate.
- [ ] gRPC client implementation via tonic (behind `cloud` feature flag).
- [ ] TelemetryReport streaming with batching.
- [ ] ThreatAlert immediate reporting.
- [ ] Heartbeat with agent health.
- [ ] PolicyUpdate streaming and application.
- [ ] mTLS configuration (CA cert, client cert, client key).
- [ ] Agent enrollment flow (keygen, CSR, enrollment token).
- [ ] Retry with exponential backoff.
- [ ] Offline mode with local queue.
- [ ] Backpressure handling on telemetry channel.
- [ ] Bandwidth optimization (summaries only, no full payloads).
- [ ] Unit tests with mock gRPC server.
- [ ] Integration test: agent → cloud → policy update round-trip.

#### riggs-discovery

- [ ] ARP scanner for local subnet.
- [ ] Passive traffic analyzer via pnet (ARP, DNS, mDNS, TCP SYN).
- [ ] Network map construction and persistence.
- [ ] Host table with first_seen/last_seen tracking.
- [ ] OUI vendor lookup for MAC addresses.
- [ ] Reverse DNS for discovered IPs.
- [ ] Network event enrichment (is_internal flag, hostname).
- [ ] Configurable scan interval and enable/disable.
- [ ] CLI commands: network map, network scan, network watch.
- [ ] Unit tests for ARP packet construction/parsing.
- [ ] Integration tests (require network interface).

#### riggs-device-control

- [ ] macOS USB monitoring via IOKit.
- [ ] macOS Bluetooth monitoring via IOBluetooth.
- [ ] Linux USB monitoring via udev.
- [ ] Device policy parsing from TOML.
- [ ] USB device allowlist/blocklist evaluation.
- [ ] Device blocking (IOKit deauthorize / sysfs unauthorized).
- [ ] Device connection event emission.
- [ ] CLI commands: devices list, devices policy, devices block/allow.
- [ ] Unit tests for policy evaluation.
- [ ] Integration tests (require USB devices).

#### riggs-vuln

- [ ] CVE database storage in separate redb file.
- [ ] CVE database update from NVD JSON feeds.
- [ ] macOS package enumeration (Homebrew, system, apps, pip, npm, gem).
- [ ] Linux package enumeration (dpkg, rpm, pip, npm, gem).
- [ ] Semantic version comparison for CVE matching.
- [ ] Vulnerability scan execution with results.
- [ ] Remediation suggestions (fixed version, upgrade command).
- [ ] Scan scheduling (startup, daily, on package install).
- [ ] Integration with behavioral AI (risk factor for running vulnService).
- [ ] CLI commands: vuln scan, vuln report, vuln cve, vuln update.
- [ ] Unit tests for version matching.
- [ ] Integration tests with real package databases.

#### riggs-shell

- [ ] Ed25519 key management (generation, authorized_keys loading).
- [ ] Challenge-response authentication.
- [ ] AES-256-GCM session encryption (key derived from ed25519 exchange).
- [ ] PTY allocation via portable-pty.
- [ ] Shell session spawning with environment setup.
- [ ] Session logging (command and output capture).
- [ ] Session timeout (idle 30 minutes).
- [ ] Concurrent session limit.
- [ ] Session kill command.
- [ ] Binary transport protocol (TCP port 4722).
- [ ] CLI commands: shell connect, shell sessions, shell kill, shell history.
- [ ] Unit tests for auth protocol.
- [ ] Integration tests for session lifecycle.

### Verification Criteria

- [ ] `cargo check` and `cargo clippy` pass for all crates.
- [ ] `cargo test` passes for all crates.
- [ ] Cloud enrollment succeeds with a test server.
- [ ] Telemetry reports arrive at the cloud server.
- [ ] Threat alerts arrive at the cloud server within 5 seconds.
- [ ] Policy updates from cloud are applied and rules hot-reload.
- [ ] Agent operates normally when cloud is unreachable (offline mode).
- [ ] Agent reconnects and drains queued data when cloud becomes available.
- [ ] Network discovery finds hosts on the local subnet.
- [ ] Network map is queryable via CLI.
- [ ] USB device connection is detected and logged.
- [ ] USB device is blocked when policy is set to restrict mode.
- [ ] Remote shell session authenticates with ed25519 key.
- [ ] Remote shell session provides working terminal.
- [ ] Remote shell session is logged in audit trail.
- [ ] Vulnerability scan identifies known CVEs in installed packages.
- [ ] Vulnerability report is queryable via CLI.
- [ ] Full system runs stable for 24 hours under simulated workload
  without memory leaks or crashes.
- [ ] Full system memory usage stays below 200 MB under active load.
- [ ] Full system CPU usage stays below 5% under normal workload.

## Cross-Phase Concerns

### Testing Strategy

Every phase maintains:

1. **Unit tests**: Per-function tests in each crate. Run with `cargo test`.
2. **Integration tests**: Cross-crate tests in `tests/` directories. May
   require elevated privileges.
3. **Property-based tests**: For serialization, compression, and data
   structures. Using `proptest` or `quickcheck`.
4. **Benchmark tests**: For performance-critical paths (feature extraction,
   inference, rule matching). Using `criterion`.
5. **End-to-end tests**: Full daemon + CLI tests. Scripted in shell or
   Rust integration tests.

### CI Pipeline

Each phase adds to the CI pipeline:

- Phase 1: `cargo check`, `cargo clippy`, `cargo test` (unit only)
- Phase 2: + benchmark tests for static AI and rules
- Phase 3: + benchmark tests for behavioral AI and storyline
- Phase 4: + integration tests for daemon lifecycle
- Phase 5: + full end-to-end tests, 24-hour stability test

### Documentation

Each phase includes updating:
- This document (marking items complete)
- Crate-level doc comments (`//!` module docs)
- Public API documentation (`///` function docs)
- Relevant architecture docs if design changes during implementation

### Dependency Audit

At the end of each phase, run `cargo audit` to check for known
vulnerabilities in dependencies. All advisories must be addressed before
proceeding to the next phase.

### Binary Size

Track binary size at each phase boundary:

| Phase   | Expected Size | Notes                              |
|---------|---------------|------------------------------------|
| Phase 1 | ~5 MB         | Types + sensor + store             |
| Phase 2 | ~10 MB        | + YARA-X + ONNX runtime            |
| Phase 3 | ~12 MB        | + behavioral AI                    |
| Phase 4 | ~15 MB        | + response + CLI + daemon          |
| Phase 5 | ~20 MB        | + gRPC + pnet + pty + crypto       |

These are estimates for release builds with `strip = true` and `lto = true`.

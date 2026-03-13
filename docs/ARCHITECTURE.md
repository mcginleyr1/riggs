# Riggs: System Architecture

## Overview

Riggs is a local-first endpoint protection system built in Rust. It runs as a
single daemon process that supervises a tree of tokio tasks. All detection,
response, and storage happen on-device. Cloud connectivity is optional and
hidden behind a feature flag.

The system follows Joe Armstrong's fail-fast philosophy: every subsystem is
isolated, every channel is bounded, and any component that enters a bad state
crashes and gets restarted by its supervisor rather than limping along with
corrupted data.

## Workspace Layout

The project is organized as a Cargo workspace with ~20 crates:

```
protect/
  Cargo.toml              # workspace root
  crates/
    riggs-types/          # shared types, event model, error types
    riggs-platform/       # PlatformSensor trait, platform-agnostic abstractions
    riggs-platform-macos/ # Endpoint Security Framework bindings
    riggs-platform-linux/ # eBPF (Aya) + procfs implementation
    riggs-platform-windows/ # ETW stub (future)
    riggs-sensor/         # sensor normalization, OCSF event emission
    riggs-engine/         # detection pipeline orchestrator
    riggs-static-ai/      # static file analysis, ONNX inference
    riggs-behavioral-ai/  # behavioral pattern detection, ONNX inference
    riggs-rules/          # YARA-X, IOC matching, STAR behavioral rules
    riggs-storyline/      # process-tree correlation, storyline graph
    riggs-response/       # response actions (kill, quarantine, contain)
    riggs-store/          # redb local database, retention, queries
    riggs-comms/          # IPC (Unix sockets), optional gRPC cloud
    riggs-discovery/      # network/device discovery
    riggs-device-control/ # USB/Bluetooth policy enforcement
    riggs-vuln/           # vulnerability scanning against CVE database
    riggs-shell/          # remote investigation shell (authenticated PTY)
    riggs-cli/            # command-line interface binary
    riggs-daemon/         # daemon binary, supervisor, lifecycle
  config/
    policies/             # response policy TOML files
  rules/
    default/              # shipped detection rules
    custom/               # user-added rules
  models/                 # ONNX model files (versioned)
  ebpf/                   # eBPF programs for Linux sensor
```

## Design Principles

### Local-First

Every capability works without network connectivity. Detection models run
on-device via ONNX Runtime. Rules are stored locally. Verdicts are persisted
to a local redb database. The optional cloud channel transmits telemetry and
receives policy updates, but the agent never depends on it for protection.

### No Shared Mutable State

Components communicate exclusively through channels. There are no `Arc<Mutex<T>>`
patterns outside of the store layer. The store itself is the single writer to
redb, serializing access internally. Everything else passes owned data through
mpsc or broadcast channels.

### Fail-Fast

If a sensor encounters an unrecoverable error, it panics. The daemon supervisor
detects the task failure and restarts it. If the store becomes corrupted, the
daemon wipes and rebuilds it from scratch rather than attempting repair. There
are no retry loops inside components; retry logic lives only at the supervisor
level and in the comms layer for network operations.

### Unidirectional Data Flow

Data flows in one direction through the system:

```
Platform Sensors → Sensor Normalization → Engine (Detection Pipeline)
                                              ↓
                              ┌────────────────┼────────────────┐
                              ↓                ↓                ↓
                          Response          Store           Comms
                          Engine            (redb)          (optional)
```

No component sends data "upstream." The engine never tells a sensor what to
look for. The store never pushes data to the engine. This makes the system
trivially debuggable: you can tap any channel and see exactly what flows through.

## Daemon Architecture

The daemon (`riggs-daemon`) is the root process. It owns the tokio runtime and
spawns all subsystems as supervised tasks.

### Supervisor Tree

```
riggs-daemon (main)
  ├── platform-sensor-task       # platform-specific event collection
  ├── sensor-normalization-task  # raw → OCSF normalization
  ├── engine-task                # detection pipeline orchestrator
  │     ├── static-ai-worker     # file analysis (spawned per-file)
  │     ├── rules-worker         # YARA-X + IOC matching
  │     ├── behavioral-ai-worker # behavioral sequence analysis
  │     ├── verdict-merger       # confidence score aggregation
  │     └── storyline-worker     # process-tree correlation
  ├── response-task              # executes response actions
  ├── store-task                 # single writer to redb
  ├── comms-ipc-task             # Unix domain socket listener
  ├── comms-cloud-task           # gRPC client (feature-gated)
  ├── rule-reload-task           # watches rules/ for changes
  ├── discovery-task             # periodic network scanning
  ├── device-control-task        # USB/Bluetooth policy monitor
  └── shell-listener-task        # authenticated PTY server
```

Each task is spawned with `tokio::spawn` and tracked via a `JoinSet`. If any
task panics or returns an error, the supervisor logs the failure, applies a
backoff delay, and restarts it. If a task fails more than 5 times within 60
seconds, the supervisor escalates: it logs a critical alert and enters a
degraded mode where only the sensor and store remain active.

### Startup Sequence

1. Parse CLI arguments and load config from `/etc/riggs/riggs.toml` (or
   `~/.config/riggs/riggs.toml` for user-mode).
2. Initialize tracing subscriber with configurable log levels.
3. Open or create the redb database.
4. Load detection rules from `rules/default/` and `rules/custom/`.
5. Load ONNX models from `models/`.
6. Create all channels (bounded mpsc and broadcast).
7. Spawn platform sensor task (requires root/elevated privileges on macOS).
8. Spawn remaining tasks in dependency order.
9. Begin accepting CLI connections on the IPC socket.
10. If cloud feature is enabled, begin gRPC connection with backoff.

### Shutdown Sequence

Shutdown is coordinated via a `tokio::sync::watch` channel. When the daemon
receives SIGTERM or SIGINT:

1. Set the shutdown watch to `true`.
2. All tasks observe the watch and begin draining their input channels.
3. The response task completes any in-flight response actions.
4. The store task flushes all pending writes.
5. The comms task sends a final heartbeat (if cloud is connected).
6. The daemon awaits all tasks in the JoinSet with a 10-second timeout.
7. Any tasks still running after the timeout are aborted.
8. The redb database is closed cleanly.
9. Process exits with code 0.

## Channel Architecture

All inter-component communication uses tokio channels. Channel buffer sizes
are configurable but have sensible defaults.

### Channel Map

| From                | To              | Type           | Buffer | Content                    |
|---------------------|-----------------|----------------|--------|----------------------------|
| platform-sensor     | sensor-norm     | mpsc           | 4096   | RawPlatformEvent           |
| sensor-norm         | engine          | mpsc           | 4096   | NormalizedEvent (OCSF)     |
| engine              | response        | mpsc           | 256    | ResponseAction             |
| engine              | store           | mpsc           | 4096   | StorableEvent              |
| engine              | comms           | mpsc           | 1024   | TelemetryPayload           |
| engine              | storyline       | mpsc           | 2048   | StorylineUpdate            |
| rule-reload         | engine          | watch          | 1      | RuleSet (latest compiled)  |
| daemon (shutdown)   | all tasks       | watch          | 1      | bool                       |
| engine (verdicts)   | broadcast       | broadcast      | 1024   | Verdict                    |

### Backpressure

All mpsc channels are bounded. When a channel fills up, the sender blocks
(async). This provides natural backpressure: if the engine cannot keep up
with sensor events, the sensor normalization task slows down, which in turn
slows down the platform sensor. Under extreme load, the platform sensor drops
events and increments a counter rather than consuming unbounded memory.

The store channel has the largest buffer because writes to redb can be bursty.
If the store falls behind, the engine will eventually block, which is the
correct behavior: detection must be durable.

## Crate Dependency Graph

Dependencies flow strictly downward. No circular dependencies exist.

```
riggs-types (leaf — no internal dependencies)
  ↑
riggs-platform (depends on: types)
  ↑
riggs-platform-{macos,linux,windows} (depends on: platform, types)
  ↑
riggs-sensor (depends on: platform, types)
  ↑
riggs-engine (depends on: sensor, static-ai, behavioral-ai, rules, storyline, types)
  ↑       ↑           ↑              ↑           ↑
  │  riggs-static-ai  │   riggs-behavioral-ai    │
  │  (types, goblin,  │   (types, ort)            │
  │   ort)             │                           │
  │                    │                           │
  │              riggs-rules                 riggs-storyline
  │              (types, yara-x,             (types)
  │               aho-corasick)
  │
riggs-response (depends on: types, store)
riggs-store (depends on: types, redb, zstd)
riggs-comms (depends on: types, tonic [optional])
riggs-discovery (depends on: types, pnet)
riggs-device-control (depends on: types)
riggs-vuln (depends on: types, store)
riggs-shell (depends on: types, ed25519-dalek, portable-pty)
riggs-cli (depends on: types, comms)
riggs-daemon (depends on: everything)
```

## Security Model

### Privilege Separation

On macOS, the daemon runs as root to access the Endpoint Security Framework.
The CLI runs as the user and communicates over a Unix domain socket with
permission checks (SO_PEERCRED or equivalent).

### Least Privilege

Each subsystem only has access to the channels it needs. The static AI worker
receives file paths and returns verdicts; it has no access to the response
channel and cannot kill processes.

### Tamper Resistance

The daemon monitors its own binary, config files, and rule directories for
unauthorized modification. If tampering is detected, an alert is raised through
the store and comms channels. The redb database uses checksums to detect
corruption.

## Configuration

Configuration is layered:

1. Compiled defaults (in each crate).
2. System config: `/etc/riggs/riggs.toml`.
3. User config: `~/.config/riggs/riggs.toml`.
4. Environment variables: `RIGGS_*` prefix.
5. CLI flags override everything.

The config is parsed once at startup and distributed to tasks as owned copies.
There is no shared config object. If a config change is needed at runtime, the
daemon must be restarted (except for rules and policies, which hot-reload).

## Performance Targets

| Metric                      | Target        | Notes                           |
|-----------------------------|---------------|---------------------------------|
| Event throughput            | 50k events/s  | Sustained, single core engine   |
| Detection latency (static)  | < 50ms        | Per-file static AI verdict      |
| Detection latency (behavioral) | < 200ms   | Per-event behavioral scoring    |
| Memory usage (idle)         | < 50 MB       | No active threats               |
| Memory usage (active)       | < 200 MB      | Under sustained event load      |
| Disk usage (database)       | < 500 MB      | With default 7-day retention    |
| CPU usage (idle)            | < 1%          | Between event bursts            |
| Startup time                | < 2 seconds   | Cold start, models loaded       |

## Error Handling Strategy

Every crate defines its own error enum using `thiserror`. Errors are specific
and actionable:

```rust
#[derive(Debug, thiserror::Error)]
pub enum SensorError {
    #[error("endpoint security client authorization denied")]
    AuthorizationDenied,
    #[error("event subscription failed for type {event_type}: {source}")]
    SubscriptionFailed { event_type: String, source: std::io::Error },
    #[error("sensor channel closed unexpectedly")]
    ChannelClosed,
}
```

Errors are never silently swallowed. Every error either causes the task to
restart (via panic or returning Err from the task body) or is logged at
`tracing::error!` level and counted in metrics.

The `anyhow` crate is used only at the binary level (`riggs-daemon` and
`riggs-cli`) for top-level error aggregation. Library crates use typed errors
exclusively.

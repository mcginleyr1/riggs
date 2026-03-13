# Riggs: Platform Abstraction

## Overview

Riggs runs on macOS, Linux, and (eventually) Windows. Each platform has
radically different APIs for monitoring processes, files, and network activity.
The platform abstraction layer isolates these differences behind a single
`PlatformSensor` trait so the rest of the system never touches platform-specific
code.

All platform-specific code lives in three crates:
- `riggs-platform-macos`
- `riggs-platform-linux`
- `riggs-platform-windows`

The abstract trait definitions live in `riggs-platform`. The normalization to
OCSF event types happens in `riggs-sensor`, which consumes raw platform events
and emits `NormalizedEvent` structs.

## PlatformSensor Trait

```rust
#[async_trait]
pub trait PlatformSensor: Send + Sync + 'static {
    /// Initialize the sensor. This may require elevated privileges.
    /// Fails fast if the required platform APIs are unavailable.
    async fn initialize(&mut self) -> Result<(), PlatformError>;

    /// Start emitting events to the provided channel. This method
    /// runs until the shutdown signal is received or an unrecoverable
    /// error occurs.
    async fn run(
        &mut self,
        event_tx: mpsc::Sender<RawPlatformEvent>,
        shutdown: watch::Receiver<bool>,
    ) -> Result<(), PlatformError>;

    /// Subscribe to specific event categories. By default, all categories
    /// are subscribed. Call this before `run()` to filter.
    fn subscribe(&mut self, categories: &[EventCategory]) -> Result<(), PlatformError>;

    /// Unsubscribe from event categories at runtime.
    fn unsubscribe(&mut self, categories: &[EventCategory]) -> Result<(), PlatformError>;

    /// Return platform information for metadata.
    fn platform_info(&self) -> PlatformInfo;

    /// Health check. Returns true if the sensor is operating normally.
    fn is_healthy(&self) -> bool;
}

pub enum EventCategory {
    Process,
    File,
    Network,
    Auth,
    DNS,
    Kernel,
    Registry, // Windows only
}

pub struct PlatformInfo {
    pub os_type: OsType,
    pub os_version: String,
    pub kernel_version: String,
    pub hostname: String,
    pub architecture: String,
    pub sensor_capabilities: Vec<EventCategory>,
}
```

## Raw Platform Events

Each platform emits raw events in its own format, wrapped in a common enum:

```rust
pub enum RawPlatformEvent {
    MacOS(MacOSRawEvent),
    Linux(LinuxRawEvent),
    Windows(WindowsRawEvent),
}

pub struct MacOSRawEvent {
    pub event_type: u32,        // ES_EVENT_TYPE_*
    pub process: MacOSProcess,
    pub timestamp: u64,         // mach_absolute_time
    pub payload: MacOSEventPayload,
}

pub struct LinuxRawEvent {
    pub event_type: LinuxEventType,
    pub pid: u32,
    pub tgid: u32,
    pub timestamp_ns: u64,      // ktime_get_ns
    pub payload: LinuxEventPayload,
}
```

These raw events are intentionally un-normalized. The sensor normalization
layer in `riggs-sensor` converts them to the OCSF `EventEnvelope` type.

## macOS Implementation

### Endpoint Security Framework

macOS uses the Endpoint Security (ES) framework, available since macOS 10.15.
ES provides kernel-level visibility into process, file, network, and
authentication events.

We use the `endpoint-sec` Rust crate, which provides safe bindings to the
ES C API.

### Initialization

```rust
pub struct MacOSSensor {
    client: Option<es::Client>,
    subscribed_events: Vec<es_event_type_t>,
}

impl MacOSSensor {
    pub fn new() -> Self {
        Self {
            client: None,
            subscribed_events: Vec::new(),
        }
    }
}
```

ES client creation requires the `com.apple.developer.endpoint-security.client`
entitlement, which in turn requires a provisioning profile from Apple. During
development, the daemon must run as root with SIP partially disabled, or use
a development entitlement.

If the entitlement is missing, `initialize()` returns
`PlatformError::AuthorizationDenied` and the daemon logs a clear error message
explaining the requirement.

### Subscribed Event Types

macOS ES provides granular event types. Riggs subscribes to:

**Process events:**
- `ES_EVENT_TYPE_NOTIFY_EXEC` — process execution
- `ES_EVENT_TYPE_NOTIFY_FORK` — process fork
- `ES_EVENT_TYPE_NOTIFY_EXIT` — process exit
- `ES_EVENT_TYPE_NOTIFY_SIGNAL` — signal delivery
- `ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED` — code signature invalidation

**File events:**
- `ES_EVENT_TYPE_NOTIFY_CREATE` — file creation
- `ES_EVENT_TYPE_NOTIFY_WRITE` — file write
- `ES_EVENT_TYPE_NOTIFY_RENAME` — file rename
- `ES_EVENT_TYPE_NOTIFY_UNLINK` — file deletion
- `ES_EVENT_TYPE_NOTIFY_CLOSE` — file close (with modified flag)
- `ES_EVENT_TYPE_NOTIFY_OPEN` — file open
- `ES_EVENT_TYPE_NOTIFY_LINK` — hard link creation
- `ES_EVENT_TYPE_NOTIFY_MMAP` — memory map of file
- `ES_EVENT_TYPE_NOTIFY_TRUNCATE` — file truncation
- `ES_EVENT_TYPE_NOTIFY_CHOWN` — ownership change
- `ES_EVENT_TYPE_NOTIFY_CHMOD` — permission change

**Network events:**
- `ES_EVENT_TYPE_NOTIFY_CONNECT` — outbound connection (macOS 13+)
- These are supplemented by `pnet` for passive traffic capture where ES
  coverage is limited.

**Auth events:**
- `ES_EVENT_TYPE_NOTIFY_AUTHENTICATION` — login events (macOS 13+)
- `ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN` — SSH authentication
- `ES_EVENT_TYPE_NOTIFY_SUDO` — sudo invocation (macOS 14+)

**Kernel events:**
- `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` — kernel extension load
- `ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD` — kernel extension unload
- `ES_EVENT_TYPE_NOTIFY_MOUNT` — filesystem mount
- `ES_EVENT_TYPE_NOTIFY_UNMOUNT` — filesystem unmount

### AUTH vs NOTIFY

ES offers two event delivery modes:

- **NOTIFY**: Asynchronous notification after the event occurs. No blocking.
- **AUTH**: Synchronous authorization before the event completes. The daemon
  must respond with ALLOW or DENY within a deadline (default varies by event).

Riggs uses NOTIFY for all events in the initial implementation. AUTH events
are planned for Phase 5 to enable proactive blocking (e.g., preventing a
malicious binary from executing before it starts).

Using AUTH events requires extreme care: if the daemon is slow to respond,
the kernel deadlines the decision and the operation proceeds. Worse, if the
daemon crashes while holding an AUTH decision, the kernel may block the
operation indefinitely. The fail-fast architecture helps here: a crashed
daemon restarts quickly and clears any pending AUTH decisions.

### Event Processing Loop

```rust
async fn run(
    &mut self,
    event_tx: mpsc::Sender<RawPlatformEvent>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), PlatformError> {
    let client = self.client.as_ref().ok_or(PlatformError::NotInitialized)?;

    loop {
        tokio::select! {
            event = client.next_event() => {
                let raw = convert_es_event(event?);
                if event_tx.send(RawPlatformEvent::MacOS(raw)).await.is_err() {
                    return Err(PlatformError::ChannelClosed);
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return Ok(());
                }
            }
        }
    }
}
```

### Mute Rules

ES supports muting events from specific processes or paths. Riggs mutes
its own process and the processes of known system daemons that generate
excessive noise (e.g., `mds`, `mdworker`, `spotlight`). Mute rules are
applied at the ES client level for zero-overhead filtering.

```rust
fn apply_default_mutes(client: &es::Client) {
    // Mute ourselves
    client.mute_process(std::process::id());

    // Mute high-volume system daemons
    let muted_paths = [
        "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mds",
        "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mdworker",
    ];
    for path in &muted_paths {
        client.mute_path(path, ES_MUTE_PATH_TYPE_PREFIX);
    }
}
```

## Linux Implementation

### eBPF via Aya

Linux uses eBPF programs loaded via the Aya framework. eBPF provides
kernel-level event tracing without kernel modules, with strong safety
guarantees enforced by the kernel's eBPF verifier.

### Architecture

```
Kernel Space:
  eBPF programs (tracepoints, kprobes, LSM hooks)
      │
      ▼
  perf ring buffer (per-CPU)
      │
User Space: │
      ▼
  riggs-platform-linux (Aya user-space)
      │
      ▼
  RawPlatformEvent::Linux
```

### eBPF Programs

eBPF programs are compiled from Rust source in the `ebpf/` directory using
`aya-bpf`. Each program attaches to a specific kernel hook.

**Process monitoring:**
- `tracepoint/sched/sched_process_exec` — process execution
- `tracepoint/sched/sched_process_fork` — process fork
- `tracepoint/sched/sched_process_exit` — process exit
- `kprobe/security_ptrace_access_check` — ptrace detection
- `kprobe/__x64_sys_setuid` — uid changes

**File monitoring:**
- `lsm/file_open` — file open (via LSM BPF hooks, kernel 5.7+)
- `tracepoint/syscalls/sys_enter_openat` — file open fallback
- `tracepoint/syscalls/sys_enter_unlinkat` — file deletion
- `tracepoint/syscalls/sys_enter_renameat2` — file rename
- `kprobe/vfs_write` — file write (sampled)

**Network monitoring:**
- `tracepoint/syscalls/sys_enter_connect` — outbound connections
- `tracepoint/syscalls/sys_enter_bind` — port binding
- `tracepoint/syscalls/sys_enter_accept4` — inbound connections
- `kprobe/tcp_sendmsg` — TCP data sent (size only, no content)

### procfs Supplement

eBPF events provide real-time notifications but limited process metadata. The
Linux sensor supplements eBPF events with data from `/proc`:

- `/proc/[pid]/exe` — executable path (readlink)
- `/proc/[pid]/cmdline` — command line arguments
- `/proc/[pid]/status` — uid, gid, ppid
- `/proc/[pid]/cwd` — working directory
- `/proc/[pid]/environ` — environment variables (if readable)

This supplemental data is read synchronously when the eBPF event arrives.
If the process has already exited by the time we read `/proc`, the sensor
uses whatever data was captured by the eBPF program itself (which includes
pid, ppid, uid, and comm name at minimum).

### eBPF Map Design

```rust
// Shared between eBPF programs and user-space
#[repr(C)]
pub struct ProcessExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
    pub timestamp_ns: u64,
}
```

Events are pushed from eBPF programs to user-space via a perf ring buffer
(one per CPU). The Aya user-space code polls these buffers using
`AsyncPerfEventArray`.

If the ring buffer overflows (user-space is too slow), events are dropped
and a counter in a BPF map is incremented. The sensor periodically checks
this counter and logs warnings when drops occur.

### Privilege Requirements

The Linux sensor requires `CAP_SYS_ADMIN` (or root) to load eBPF programs
and `CAP_PERFMON` to attach to perf events. The daemon drops all other
capabilities after initialization.

## Windows Implementation (Stub)

The Windows sensor is a stub for future implementation. It returns
`PlatformError::NotImplemented` for all operations.

### Planned: ETW (Event Tracing for Windows)

The Windows implementation will use ETW providers:

- `Microsoft-Windows-Kernel-Process` — process lifecycle
- `Microsoft-Windows-Kernel-File` — file operations
- `Microsoft-Windows-Kernel-Network` — network events
- `Microsoft-Windows-Security-Auditing` — auth events

### Planned: Minifilter Driver

For proactive file blocking (AUTH-mode equivalent), a minifilter driver will
be needed. This is a significant engineering effort and is not planned until
after the macOS and Linux implementations are stable.

## Sensor Normalization

The `riggs-sensor` crate converts raw platform events into OCSF
`EventEnvelope` structs. This is a pure transformation with no I/O.

### Normalization Pipeline

```rust
pub struct SensorNormalizer {
    platform_info: PlatformInfo,
    agent_id: Uuid,
    sequence_counter: AtomicU64,
}

impl SensorNormalizer {
    pub fn normalize(&self, raw: RawPlatformEvent) -> Option<EventEnvelope> {
        match raw {
            RawPlatformEvent::MacOS(event) => self.normalize_macos(event),
            RawPlatformEvent::Linux(event) => self.normalize_linux(event),
            RawPlatformEvent::Windows(event) => self.normalize_windows(event),
        }
    }
}
```

The normalizer returns `Option<EventEnvelope>` rather than `Result` because
some raw events may not map to any OCSF event type (e.g., internal kernel
housekeeping events). These are silently dropped.

### Timestamp Normalization

Each platform uses different timestamp sources:

- **macOS**: `mach_absolute_time()` converted to UTC via
  `mach_timebase_info`.
- **Linux**: `ktime_get_ns()` from eBPF, converted to UTC by adding
  `clock_gettime(CLOCK_REALTIME) - clock_gettime(CLOCK_MONOTONIC)`.
- **Windows**: ETW timestamps are already in 100ns intervals since
  1601-01-01 (FILETIME).

The normalizer converts all timestamps to `chrono::DateTime<Utc>`.

### Process Context Enrichment

For non-process events, the normalizer must attach process context. It
maintains an internal process table (a `HashMap<u32, ProcessContext>`) that
is updated on every ProcessEvent::Exec and ProcessEvent::Exit. When a file
or network event arrives, the normalizer looks up the responsible pid in this
table.

If the pid is not found (race condition: process exited between the kernel
event and our lookup), the normalizer constructs a minimal ProcessContext
with just the pid and marks it as `incomplete`.

## Compile-Time Platform Selection

The workspace uses conditional compilation to select the active platform:

```toml
# In riggs-sensor/Cargo.toml
[target.'cfg(target_os = "macos")'.dependencies]
riggs-platform-macos = { workspace = true }

[target.'cfg(target_os = "linux")'.dependencies]
riggs-platform-linux = { workspace = true }

[target.'cfg(target_os = "windows")'.dependencies]
riggs-platform-windows = { workspace = true }
```

At runtime, the sensor factory creates the correct platform implementation:

```rust
pub fn create_sensor() -> Box<dyn PlatformSensor> {
    #[cfg(target_os = "macos")]
    { Box::new(riggs_platform_macos::MacOSSensor::new()) }

    #[cfg(target_os = "linux")]
    { Box::new(riggs_platform_linux::LinuxSensor::new()) }

    #[cfg(target_os = "windows")]
    { Box::new(riggs_platform_windows::WindowsSensor::new()) }
}
```

## Testing Strategy

### Mock Sensor

A `MockSensor` implementation of `PlatformSensor` is provided in
`riggs-platform` behind a `#[cfg(test)]` gate. It replays canned events from
JSON files, enabling deterministic testing of the entire pipeline without
platform APIs.

### Integration Testing

macOS integration tests require:
1. Running as root
2. A valid endpoint security entitlement
3. The test spawns short-lived processes and verifies the sensor captures them

Linux integration tests require:
1. Running as root (or `CAP_SYS_ADMIN` + `CAP_PERFMON`)
2. Kernel 5.7+ for LSM BPF hooks
3. Tests load eBPF programs and verify event capture

### Event Replay

Captured events can be serialized to JSON and replayed through the normalizer
and engine for regression testing. This allows reproducing detection failures
without access to the original platform.

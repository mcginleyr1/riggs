# Riggs: Event Model

## Overview

Riggs uses an event model based on the Open Cybersecurity Schema Framework
(OCSF). Every observable system activity is captured as a typed, immutable
event. Events are the universal currency of the system: sensors produce them,
the engine consumes them, the store persists them, and the comms layer
transmits them.

All event types live in `riggs-types`. Platform-specific sensors produce raw
events that are immediately normalized to this schema at the sensor boundary.
No platform-specific data leaks past `riggs-sensor`.

## Core Event Structure

Every event shares a common envelope:

```rust
pub struct EventEnvelope {
    pub event_id: Uuid,           // UUIDv7 — time-ordered, globally unique
    pub timestamp: DateTime<Utc>, // when the event was observed
    pub event_type: EventType,    // discriminant for the inner payload
    pub storyline_id: Uuid,       // links event to a process storyline
    pub process_context: ProcessContext, // always present
    pub severity: Severity,       // None, Info, Low, Medium, High, Critical
    pub metadata: EventMetadata,  // source sensor, agent version, host info
}
```

### UUIDv7 Event IDs

Event IDs use UUIDv7, which encodes a millisecond timestamp in the high bits.
This gives us three properties for free:

1. Globally unique without coordination (no central ID server).
2. Time-ordered: sorting by event_id sorts by time.
3. Indexable: redb range queries on event_id correspond to time ranges.

### Timestamps

The `timestamp` field records when the event was observed by the sensor, not
when the kernel generated it. The kernel timestamp (if available) is stored
in `metadata.kernel_timestamp`. The difference between these two values is
the sensor latency, which is tracked as a metric.

All timestamps are UTC. No local time zones appear anywhere in the event model.

## Event Types

```rust
pub enum EventType {
    Process(ProcessEvent),
    File(FileEvent),
    Network(NetworkEvent),
    Registry(RegistryEvent),
    DNS(DNSEvent),
    Auth(AuthEvent),
    Kernel(KernelEvent),
}
```

### ProcessEvent

Captures process lifecycle and execution events.

```rust
pub struct ProcessEvent {
    pub action: ProcessAction,
    pub executable_path: PathBuf,
    pub command_line: Vec<String>,
    pub working_directory: PathBuf,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub user_name: Option<String>,
    pub signing_info: Option<SigningInfo>,
    pub file_hash: Option<FileHash>,
    pub environment: Option<Vec<(String, String)>>, // captured on exec only
}

pub enum ProcessAction {
    Exec,
    Fork,
    Exit { exit_code: i32 },
    SetUid { old_uid: u32, new_uid: u32 },
    SetGid { old_gid: u32, new_gid: u32 },
    PTrace { target_pid: u32 },
    Signal { target_pid: u32, signal: i32 },
}

pub struct SigningInfo {
    pub is_signed: bool,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub cdhash: Option<Vec<u8>>,
    pub is_platform_binary: bool,
    pub is_notarized: bool,
}
```

ProcessEvent is the most critical event type. Every process exec generates one.
The engine uses these to build process trees and initialize storylines.

### FileEvent

Captures file system operations.

```rust
pub struct FileEvent {
    pub action: FileAction,
    pub path: PathBuf,
    pub target_path: Option<PathBuf>, // for rename/link operations
    pub file_hash: Option<FileHash>,
    pub file_size: Option<u64>,
    pub file_type: Option<FileType>,
    pub owner_uid: Option<u32>,
    pub permissions: Option<u32>,
}

pub enum FileAction {
    Create,
    Modify,
    Delete,
    Rename,
    Link,
    Unlink,
    Open { flags: u32 },
    Close { was_modified: bool },
    Chmod { old_mode: u32, new_mode: u32 },
    Chown { old_uid: u32, new_uid: u32 },
    Truncate,
    MMap { protection: u32 },
}

pub enum FileType {
    Regular,
    Directory,
    Symlink,
    Executable,
    SharedLibrary,
    Script,
    Archive,
    Unknown,
}
```

FileEvent drives the static analysis pipeline. When a file is created or
modified and its type is Executable, SharedLibrary, or Script, the engine
routes it to the static AI and YARA-X stages.

### NetworkEvent

Captures network connections and traffic metadata.

```rust
pub struct NetworkEvent {
    pub action: NetworkAction,
    pub direction: Direction,
    pub protocol: Protocol,
    pub local_addr: SocketAddr,
    pub remote_addr: Option<SocketAddr>,
    pub bytes_sent: Option<u64>,
    pub bytes_received: Option<u64>,
    pub domain: Option<String>,      // from DNS correlation
    pub ja3_hash: Option<String>,    // TLS fingerprint
    pub ja3s_hash: Option<String>,   // TLS server fingerprint
}

pub enum NetworkAction {
    Connect,
    Listen,
    Accept,
    Close,
    Send,
    Receive,
    Bind,
}

pub enum Direction {
    Inbound,
    Outbound,
    Lateral, // internal network traffic
}

pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Raw,
    Unknown(u8),
}
```

### RegistryEvent

Registry events apply to Windows only. On macOS and Linux, this variant is
never emitted but exists in the model for cross-platform schema completeness.

```rust
pub struct RegistryEvent {
    pub action: RegistryAction,
    pub key_path: String,
    pub value_name: Option<String>,
    pub value_data: Option<Vec<u8>>,
    pub value_type: Option<RegistryValueType>,
}

pub enum RegistryAction {
    CreateKey,
    DeleteKey,
    SetValue,
    DeleteValue,
    RenameKey,
}
```

### DNSEvent

Captures DNS resolution, correlated with network events.

```rust
pub struct DNSEvent {
    pub action: DNSAction,
    pub query_name: String,
    pub query_type: DNSQueryType,
    pub response_code: Option<u16>,
    pub answers: Vec<DNSAnswer>,
    pub server_addr: Option<SocketAddr>,
    pub latency_ms: Option<u32>,
}

pub enum DNSAction {
    Query,
    Response,
}

pub enum DNSQueryType {
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    TXT,
    SRV,
    PTR,
    SOA,
    Other(u16),
}

pub struct DNSAnswer {
    pub name: String,
    pub answer_type: DNSQueryType,
    pub data: String,     // IP address, CNAME target, etc.
    pub ttl: u32,
}
```

DNS events are correlated with NetworkEvents by matching the resolved IP to
the remote_addr of subsequent connections. This correlation happens in the
storyline engine.

### AuthEvent

Captures authentication and authorization decisions.

```rust
pub struct AuthEvent {
    pub action: AuthAction,
    pub mechanism: AuthMechanism,
    pub success: bool,
    pub user_name: String,
    pub source_addr: Option<SocketAddr>,
    pub failure_reason: Option<String>,
}

pub enum AuthAction {
    Login,
    Logout,
    PrivilegeEscalation,
    SudoInvocation,
    KeychainAccess,
    TokenRefresh,
}

pub enum AuthMechanism {
    Password,
    PublicKey,
    Kerberos,
    TouchId,
    SmartCard,
    PAM,
    Other(String),
}
```

### KernelEvent

Captures kernel-level operations that do not fit into other categories.

```rust
pub struct KernelEvent {
    pub action: KernelAction,
    pub details: serde_json::Value, // flexible payload for kernel-specific data
}

pub enum KernelAction {
    KextLoad { bundle_id: String, path: PathBuf },
    KextUnload { bundle_id: String },
    SystemExtensionActivate { bundle_id: String },
    IoctlCall { device: PathBuf, request: u64 },
    MountFilesystem { source: String, target: PathBuf, fs_type: String },
    UnmountFilesystem { target: PathBuf },
    ModuleLoad { name: String, path: PathBuf },   // Linux
    ModuleUnload { name: String },                 // Linux
}
```

## Process Context

Every event carries a `ProcessContext`, which identifies the process that
generated or caused the event. This is the universal join key for storyline
correlation.

```rust
pub struct ProcessContext {
    pub pid: u32,
    pub ppid: u32,
    pub executable_path: PathBuf,
    pub executable_hash: Option<FileHash>,
    pub command_line: Vec<String>,
    pub uid: u32,
    pub user_name: Option<String>,
    pub start_time: DateTime<Utc>,
    pub storyline_id: Uuid,       // inherited from parent or assigned on exec
}
```

The process context is populated by the sensor normalization layer. When a
non-process event (e.g., FileEvent) is observed, the sensor looks up the
responsible process and attaches its context. On macOS, the Endpoint Security
Framework provides this natively via the `audit_token`. On Linux, the eBPF
program captures the task_struct fields.

## File Hashes

```rust
pub struct FileHash {
    pub sha256: [u8; 32],
    pub md5: Option<[u8; 16]>,   // for legacy IOC compatibility
    pub ssdeep: Option<String>,  // fuzzy hash for similarity matching
}
```

SHA-256 is always computed. MD5 is computed only when legacy IOC matching is
enabled. ssdeep is computed for files sent to the static AI pipeline for
similarity clustering.

## Severity Levels

```rust
pub enum Severity {
    None,      // informational, no security relevance
    Info,      // normal activity worth recording
    Low,       // unusual but probably benign
    Medium,    // suspicious, warrants investigation
    High,      // likely malicious, automated response may trigger
    Critical,  // confirmed malicious, immediate response required
}
```

Severity is initially set by the sensor (usually None or Info) and then
elevated by the detection pipeline as evidence accumulates. The storyline
engine can further elevate severity based on correlated events.

## Event Metadata

```rust
pub struct EventMetadata {
    pub agent_id: Uuid,
    pub agent_version: String,
    pub hostname: String,
    pub os_type: OsType,
    pub os_version: String,
    pub sensor_name: String,         // which sensor produced this event
    pub kernel_timestamp: Option<DateTime<Utc>>, // kernel-reported time
    pub sequence_number: u64,        // per-sensor monotonic counter
    pub tags: Vec<String>,           // engine-applied tags (e.g., "mitre:T1059")
}

pub enum OsType {
    MacOS,
    Linux,
    Windows,
}
```

The `sequence_number` is a per-sensor monotonic counter. If events arrive
out of order or with gaps, the storyline engine detects this and logs a
warning. Gaps may indicate dropped events under load.

## Storyline Correlation Model

A storyline is a directed acyclic graph of events linked by causal
relationships. The root of every storyline is a ProcessEvent::Exec.

### Storyline Identity

Every process gets a `storyline_id` when it execs. Child processes inherit
the parent's `storyline_id` unless the engine decides the child represents
a distinct activity (e.g., a shell spawning an unrelated tool). In that case,
a new storyline is created and the old one gets a cross-reference.

### Correlation Rules

Events are linked to storylines by:

1. **Process tree**: Same pid or descendant pid inherits the storyline.
2. **File causation**: A FileEvent::Create followed by a ProcessEvent::Exec
   of that file creates a causal edge.
3. **Network causation**: A DNSEvent followed by a NetworkEvent::Connect to
   the resolved IP creates a causal edge.
4. **Temporal proximity**: Events from the same process within a configurable
   window (default 5 seconds) are grouped.

### Storyline Scoring

Each storyline accumulates a threat score. The score is the maximum severity
of any event in the storyline, modified by the number of suspicious indicators:

```
storyline_score = max(event_severities) + (0.1 * count(medium_or_higher_events))
```

When a storyline's score crosses a threshold (configurable, default 0.8 on a
0.0-1.0 scale), the entire storyline is flagged for response.

### Storyline Persistence

Storylines are persisted to the store as a graph structure:

```rust
pub struct Storyline {
    pub storyline_id: Uuid,
    pub root_event_id: Uuid,         // the initial exec event
    pub root_process: ProcessContext,
    pub score: f32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub event_count: u64,
    pub status: StorylineStatus,
    pub edges: Vec<StorylineEdge>,
}

pub struct StorylineEdge {
    pub from_event_id: Uuid,
    pub to_event_id: Uuid,
    pub relation: EdgeRelation,
}

pub enum EdgeRelation {
    Spawned,       // parent → child process
    Created,       // process → file created
    Executed,      // file → process executed
    Connected,     // process → network connection
    Resolved,      // DNS query → network connection
    Loaded,        // process → library/module loaded
    Modified,      // process → file modified
    Authenticated, // auth event → subsequent activity
}

pub enum StorylineStatus {
    Active,        // process tree still alive
    Completed,     // all processes exited normally
    Mitigated,     // response actions taken
    FalsePositive, // analyst marked as benign
}
```

## Event Serialization

Events are serialized to two formats:

1. **In-memory / channel**: Events are passed as owned Rust structs. No
   serialization overhead between components.
2. **Storage (redb)**: Events are serialized with `serde_json` then compressed
   with zstd before writing. The event_id and timestamp are stored as separate
   keys for indexing; the full event payload is the value.
3. **Wire (gRPC)**: Events are serialized with protobuf via prost. The proto
   definitions map 1:1 to the Rust structs.

## Event Volume Estimates

Typical macOS workstation:

| Event Type    | Events/sec (idle) | Events/sec (active) | Events/sec (build) |
|---------------|-------------------|---------------------|---------------------|
| Process       | 1-5               | 10-50               | 100-500             |
| File          | 10-50             | 100-500             | 1000-5000           |
| Network       | 5-20              | 20-100              | 50-200              |
| DNS           | 1-5               | 5-20                | 10-50               |
| Auth          | < 1               | < 1                 | < 1                 |
| Kernel        | < 1               | < 1                 | < 1                 |
| **Total**     | **~20-80**        | **~150-670**        | **~1200-5750**      |

The engine must handle sustained peaks of ~6000 events/sec on a developer
workstation without dropping events. During a large build (e.g., compiling
Chromium), file events dominate and the engine should apply fast-path filtering
to skip known-safe patterns (e.g., build artifacts matching a configured
allowlist).

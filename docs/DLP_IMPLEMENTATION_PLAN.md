# DLP Module Implementation Plan

## Overview

Add a Data Loss Prevention (DLP) subsystem to Riggs that detects and blocks
sensitive file uploads to monitored services (e.g., claude.ai, ChatGPT, Slack
file uploads). The approach combines macOS NEFilterDataProvider for network flow
interception with file-access correlation from the existing sensor layer —
avoiding TLS inspection entirely.

### Why Correlation Instead of Deep Packet Inspection

HTTPS traffic to services like Anthropic is TLS-encrypted.
NEFilterDataProvider sees transport-layer bytes, not HTTP payloads. We cannot
inspect multipart form data or file content inside the encrypted stream.

Instead, we correlate two signals the system already has access to:
1. **File reads** — the existing file sensor sees when a process opens a `.pptx`
2. **Network flows** — NEFilterDataProvider sees when that same process
   connects to `claude.ai`

Same PID + sensitive file read + monitored destination within a time window =
block the flow. This is how production endpoint DLP works (CrowdStrike,
SentinelOne, Microsoft Defender).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        macOS System Extension                       │
│                                                                     │
│  ┌───────────────────────────────────┐                              │
│  │   NEFilterDataProvider            │                              │
│  │                                   │                              │
│  │  handleNewFlow():                 │                              │
│  │    extract PID from audit token   │                              │
│  │    extract SNI / remote hostname  │──── unix socket ────┐       │
│  │    if monitored domain:           │                      │       │
│  │      query daemon for verdict     │◄─── verdict ────────┤       │
│  │      allow / drop                 │                      │       │
│  └───────────────────────────────────┘                      │       │
└─────────────────────────────────────────────────────────────│───────┘
                                                              │
┌─────────────────────────────────────────────────────────────│───────┐
│                        Riggs Daemon                         │       │
│                                                              │       │
│  ┌──────────────┐    ┌──────────────────┐    ┌──────────────▼──┐   │
│  │ File Sensor   │───▶│ DLP Correlator   │◄───│ DLP IPC Handler │   │
│  │ (existing)    │    │ (new)            │    │ (new)           │   │
│  │               │    │                  │    └─────────────────┘   │
│  │ FileEvent with│    │ Per-PID ring buf │                          │
│  │ ProcessContext│    │ of sensitive file │    ┌─────────────────┐   │
│  └──────────────┘    │ accesses (30s)    │───▶│ DLP Stage       │   │
│                      │                  │    │ (DetectionStage) │   │
│                      │ Policy:          │    │                  │   │
│                      │  - watched domains│    │ Emits verdicts   │   │
│                      │  - blocked types  │    │ for pipeline     │   │
│                      │  - action (block/ │    └─────────────────┘   │
│                      │    alert)         │                          │
│                      └──────────────────┘                          │
└────────────────────────────────────────────────────────────────────┘
```

---

## Components

### 1. `riggs-dlp` crate (Rust)

New workspace crate. Contains the correlator, policy engine, and DLP detection stage.

**Files:**
```
crates/riggs-dlp/
├── Cargo.toml
└── src/
    ├── lib.rs           # Public API, re-exports
    ├── correlator.rs    # Per-PID file access tracking + flow correlation
    ├── policy.rs        # DLP policy definitions and matching
    ├── stage.rs         # DetectionStage impl for the pipeline
    └── ipc.rs           # Handler for filter extension queries
```

#### correlator.rs

Core data structure that tracks sensitive file accesses per process.

```rust
use dashmap::DashMap;
use std::collections::VecDeque;
use std::path::PathBuf;
use chrono::{DateTime, Utc, Duration};

pub struct DlpCorrelator {
    // PID -> recent sensitive file accesses
    file_access_log: DashMap<u32, VecDeque<SensitiveAccess>>,
    policy: Arc<DlpPolicy>,
    window: Duration,  // default 30s
}

pub struct SensitiveAccess {
    pub path: PathBuf,
    pub file_type: SensitiveFileType,
    pub timestamp: DateTime<Utc>,
    pub process_name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SensitiveFileType {
    Pptx,
    Xlsx,
    Docx,
    Pdf,
    Csv,
    SourceCode,
    PrivateKey,
    DatabaseDump,
    Custom(String),
}

impl DlpCorrelator {
    pub fn new(policy: Arc<DlpPolicy>, window: Duration) -> Self;

    // Called by the pipeline when a FileEvent::Open arrives.
    // Checks extension AND magic bytes (first 8 bytes from the event hash
    // or a quick fs read) to prevent rename evasion.
    pub fn record_file_access(&self, pid: u32, path: &Path,
                               process_name: &str, timestamp: DateTime<Utc>);

    // Called by the DLP IPC handler when NEFilterDataProvider asks
    // "should I block PID X connecting to domain Y?"
    pub fn check_flow(&self, pid: u32, domain: &str) -> FlowVerdict;

    // Background task: evict entries older than self.window
    pub async fn reaper_loop(&self);
}

pub enum FlowVerdict {
    Allow,
    Block { reason: String, file_path: PathBuf, file_type: SensitiveFileType },
    Alert { reason: String, file_path: PathBuf, file_type: SensitiveFileType },
}
```

**File type detection strategy:**

Extension-based matching is fast but trivially defeated by renaming.
For robustness, check magic bytes on `FileEvent::Open`:

| Type | Magic Bytes | Notes |
|------|-------------|-------|
| PPTX/XLSX/DOCX | `PK\x03\x04` | ZIP-based OOXML, check `[Content_Types].xml` inside for subtype |
| Legacy PPT/XLS/DOC | `\xD0\xCF\x11\xE0` | OLE2 compound document |
| PDF | `%PDF` | |
| CSV | heuristic | Check if first N bytes are printable + commas/tabs |
| Private keys | `-----BEGIN` | RSA/EC/SSH private keys |
| SQLite | `SQLite format 3\0` | Database dumps |

When a `FileEvent::Open` arrives, the normalizer already has the path.
The correlator does a quick 16-byte head read (async, non-blocking) to
confirm the actual file type. This adds negligible latency since we only
do it for files matching a candidate extension OR living in watched directories.

#### policy.rs

```rust
pub struct DlpPolicy {
    pub watched_domains: Vec<DomainPattern>,
    pub blocked_file_types: Vec<SensitiveFileType>,
    pub alert_only_file_types: Vec<SensitiveFileType>,
    pub excluded_processes: Vec<String>,  // e.g., "Finder", system processes
    pub excluded_paths: Vec<PathBuf>,     // e.g., /tmp/scratch
    pub action: DlpAction,
}

pub enum DlpAction {
    Block,      // Drop the network flow
    AlertOnly,  // Allow but emit a Malicious/Suspicious verdict
}

pub struct DomainPattern {
    pub pattern: String,       // e.g., "claude.ai", "*.openai.com"
    pub category: String,      // e.g., "ai-assistant", "file-sharing"
}
```

The policy is loaded from the Riggs config file (`riggs.toml`) and supports
hot-reload via the existing config watcher.

#### stage.rs

```rust
pub struct DlpStage {
    correlator: Arc<DlpCorrelator>,
}

#[async_trait]
impl DetectionStage for DlpStage {
    fn name(&self) -> &str { "dlp" }

    async fn analyze(&self, event: &RiggsEvent) -> Result<StageVerdict, RiggsError> {
        match event {
            // When a file is opened, record it in the correlator.
            // No verdict yet — the verdict comes when the network flow happens.
            RiggsEvent::File(fe) if fe.action == FileAction::Open => {
                self.correlator.record_file_access(
                    fe.process_context.pid,
                    Path::new(&fe.path),
                    &fe.process_context.name,
                    fe.timestamp,
                );
                Ok(StageVerdict::Clean)
            }

            // When a network event arrives (from the filter extension via IPC),
            // check if the originating process recently accessed sensitive files.
            RiggsEvent::Network(ne) if ne.direction == NetworkDirection::Outbound => {
                match self.correlator.check_flow(ne.process_context.pid, &ne.dst_addr) {
                    FlowVerdict::Block { reason, file_path, file_type } => {
                        Ok(StageVerdict::Malicious(Verdict {
                            event_id: ne.event_id.clone(),
                            threat_level: ThreatLevel::Malicious,
                            confidence: 0.95,
                            source: DetectionSource::CustomRule,
                            description: format!(
                                "DLP: {} ({:?}) upload blocked to {}. File: {}",
                                reason, file_type, ne.dst_addr,
                                file_path.display()
                            ),
                            timestamp: Utc::now(),
                        }))
                    }
                    FlowVerdict::Alert { reason, .. } => {
                        Ok(StageVerdict::Suspicious(Verdict {
                            event_id: ne.event_id.clone(),
                            threat_level: ThreatLevel::Suspicious,
                            confidence: 0.8,
                            source: DetectionSource::CustomRule,
                            description: format!("DLP alert: {}", reason),
                            timestamp: Utc::now(),
                        }))
                    }
                    FlowVerdict::Allow => Ok(StageVerdict::Clean),
                }
            }

            _ => Ok(StageVerdict::Clean),
        }
    }
}
```

#### ipc.rs — DLP query handler

Extends the existing `riggs-comms` IPC protocol with a new message pair
for the filter extension to query the daemon synchronously.

```rust
// New messages added to riggs-comms/src/messages.rs:

// From the filter extension to the daemon
pub enum ClientMessage {
    // ... existing variants ...
    DlpCheckFlow {
        pid: u32,
        remote_hostname: String,
        remote_ip: String,
        remote_port: u16,
    },
}

// From the daemon back to the filter extension
pub enum DaemonMessage {
    // ... existing variants ...
    DlpVerdict {
        allow: bool,
        reason: Option<String>,
    },
}
```

The DLP IPC handler lives in `riggs-dlp` but is registered with the
existing `IpcServer` in the daemon startup path. When a `DlpCheckFlow`
message arrives, it calls `correlator.check_flow()` and returns the verdict.

**Latency requirement:** The NEFilterDataProvider blocks on this response.
The correlator lookup is a DashMap read — sub-microsecond. The unix socket
round-trip adds ~50-100µs. Total < 1ms, well within acceptable limits.

---

### 2. `riggs-filter-extension` (Swift)

A standalone macOS System Extension containing the NEFilterDataProvider.
This is a separate Xcode target (not a Cargo crate) because System Extensions
must be Swift/ObjC and bundled as `.systemextension` inside an `.app`.

**Directory structure:**
```
extensions/
├── riggs-filter/
│   ├── Package.swift or Xcode project
│   ├── Info.plist
│   ├── entitlements/
│   │   └── riggs-filter.entitlements
│   └── Sources/
│       ├── FilterDataProvider.swift
│       ├── DaemonConnection.swift
│       └── main.swift
└── riggs-filter-host/
    ├── Sources/
    │   └── main.swift          # Minimal app that activates the extension
    └── Info.plist
```

#### FilterDataProvider.swift

```swift
import NetworkExtension
import os.log

class FilterDataProvider: NEFilterDataProvider {
    private let logger = Logger(subsystem: "com.riggs.filter", category: "dlp")
    private var daemonConnection: DaemonConnection?
    private var watchedDomains: Set<String> = []

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        // Connect to riggs daemon via unix socket
        daemonConnection = DaemonConnection(socketPath: "/var/run/riggs.sock")

        // Load initial domain watchlist from daemon
        // (or from a shared config file for faster startup)
        loadWatchedDomains()

        completionHandler(nil)
    }

    override func stopFilter(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        daemonConnection?.disconnect()
        completionHandler()
    }

    override func handleNewFlow(
        _ flow: NEFilterFlow
    ) -> NEFilterNewFlowVerdict {
        // Extract remote hostname from the flow
        guard let socketFlow = flow as? NEFilterSocketFlow,
              let hostname = socketFlow.remoteHostname ?? resolveHostname(socketFlow)
        else {
            return .allow()
        }

        // Fast path: not a watched domain, allow immediately
        if !isWatchedDomain(hostname) {
            return .allow()
        }

        // Extract the source PID from the audit token
        let pid = extractPid(from: socketFlow)

        // Query the daemon: has this PID recently read sensitive files?
        guard let connection = daemonConnection else {
            logger.warning("No daemon connection, allowing flow")
            return .allow()
        }

        let verdict = connection.checkFlow(
            pid: pid,
            hostname: hostname,
            remoteIP: socketFlow.remoteEndpoint?.hostname ?? "",
            remotePort: UInt16(socketFlow.remoteEndpoint?.port ?? 0)
        )

        if verdict.allow {
            return .allow()
        } else {
            logger.warning(
                "DLP BLOCK: PID \(pid) -> \(hostname): \(verdict.reason ?? "policy")"
            )
            return .drop()
        }
    }

    private func isWatchedDomain(_ hostname: String) -> Bool {
        // Check exact match and wildcard patterns
        // e.g., "claude.ai" matches, "*.anthropic.com" matches
        //        "api.anthropic.com"
        for domain in watchedDomains {
            if domain.hasPrefix("*.") {
                let suffix = String(domain.dropFirst(1)) // ".anthropic.com"
                if hostname.hasSuffix(suffix) || hostname == String(domain.dropFirst(2)) {
                    return true
                }
            } else if hostname == domain {
                return true
            }
        }
        return false
    }

    private func extractPid(from flow: NEFilterSocketFlow) -> UInt32 {
        // audit_token_to_pid from the sourceAppAuditToken
        guard let token = flow.sourceAppAuditToken else { return 0 }
        return token.withUnsafeBytes { ptr in
            // audit_token_t field layout: pid is at index 5
            let tokenArray = ptr.bindMemory(to: UInt32.self)
            return tokenArray[5]
        }
    }
}
```

#### DaemonConnection.swift

Handles the unix socket communication with the Riggs daemon. Uses the same
simple length-prefixed JSON protocol that `riggs-comms` already speaks.

```swift
class DaemonConnection {
    private var socket: Int32 = -1
    private let socketPath: String
    private let queue = DispatchQueue(label: "com.riggs.filter.daemon")

    init(socketPath: String) {
        self.socketPath = socketPath
        connect()
    }

    func checkFlow(pid: UInt32, hostname: String,
                   remoteIP: String, remotePort: UInt16) -> DlpVerdict {
        let request = """
        {"DlpCheckFlow":{"pid":\(pid),"remote_hostname":"\(hostname)",\
        "remote_ip":"\(remoteIP)","remote_port":\(remotePort)}}
        """

        guard let response = sendAndReceive(request) else {
            // Fail open — if daemon is unreachable, allow
            return DlpVerdict(allow: true, reason: nil)
        }

        return parseDlpVerdict(response)
    }

    // ... socket connect, sendAndReceive, reconnect logic ...
}

struct DlpVerdict {
    let allow: Bool
    let reason: String?
}
```

#### Signing and Distribution (Open Source)

Since this is open source for self-install, users have two paths:

**Option A: Self-sign with a Developer ID (recommended)**
- User has an Apple Developer account ($99/year or free for personal use)
- Build the extension locally: `make build-filter-extension`
- macOS will prompt "allow system extension from <developer>"
- User approves in System Preferences > Privacy & Security

**Option B: Disable SIP (development only)**
- `csrutil disable` in Recovery Mode
- Extensions load without signing
- Not recommended for production use

The Makefile/build script handles building the Swift extension and
embedding it in a minimal host `.app` bundle. See Build Sequence below.

---

### 3. Config Changes

Add DLP section to `riggs-types/src/config.rs` and `config/riggs.toml`:

```toml
[dlp]
enabled = true
action = "block"            # "block" or "alert"
correlation_window_secs = 30

# Domains to monitor for sensitive file uploads
[[dlp.watched_domains]]
pattern = "claude.ai"
category = "ai-assistant"

[[dlp.watched_domains]]
pattern = "*.anthropic.com"
category = "ai-assistant"

[[dlp.watched_domains]]
pattern = "chatgpt.com"
category = "ai-assistant"

[[dlp.watched_domains]]
pattern = "*.openai.com"
category = "ai-assistant"

# File types to block/alert on
[dlp.file_types]
block = ["pptx", "xlsx", "docx", "pdf", "csv", "ppt", "xls", "doc"]
alert = ["txt", "json", "source_code"]

# Processes excluded from DLP (system processes that legitimately upload)
[dlp.excluded_processes]
names = ["softwareupdated", "nsurlsessiond"]
```

Corresponding Rust struct:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct DlpConfig {
    pub enabled: bool,
    pub action: String,                    // "block" or "alert"
    pub correlation_window_secs: u64,
    pub watched_domains: Vec<WatchedDomain>,
    pub file_types: DlpFileTypes,
    pub excluded_processes: DlpExclusions,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WatchedDomain {
    pub pattern: String,
    pub category: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DlpFileTypes {
    pub block: Vec<String>,
    pub alert: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DlpExclusions {
    pub names: Vec<String>,
}
```

---

### 4. Router Changes

Update `EventRouter::stages_for_event` to include the DLP stage:

```rust
RiggsEvent::File(_) => vec!["threat-intel", "static-ai", "rules", "behavioral-ai", "dlp"],
RiggsEvent::Network(_) => vec!["threat-intel", "behavioral-ai", "dlp"],
```

---

### 5. Daemon Integration

In `riggs-daemon/src/daemon.rs`, the startup sequence adds:

```rust
// After pipeline creation, before starting the event loop:

if config.dlp.enabled {
    let dlp_policy = Arc::new(DlpPolicy::from_config(&config.dlp));
    let correlator = Arc::new(DlpCorrelator::new(
        dlp_policy,
        Duration::seconds(config.dlp.correlation_window_secs as i64),
    ));

    // Register the DLP detection stage with the pipeline
    pipeline.add_stage(Box::new(DlpStage::new(correlator.clone())));

    // Register the DLP IPC handler so the filter extension can query
    ipc_server.register_dlp_handler(correlator.clone());

    // Spawn the correlator reaper (evicts stale entries)
    tokio::spawn(correlator.clone().reaper_loop());

    info!("DLP module enabled: watching {} domains, blocking {:?}",
        config.dlp.watched_domains.len(),
        config.dlp.file_types.block);
}
```

---

### 6. File Sensor Enhancement

The existing file sensor in `riggs-platform-macos/src/sensor.rs` uses the
`notify` crate which gives us Create, Modify, Delete, and Rename events.
It does NOT currently report Open events — this is needed for DLP.

**Required change:** Add file-open monitoring. Two approaches:

**Approach A: Endpoint Security framework (preferred)**

Use Apple's Endpoint Security framework (`es_subscribe` with
`ES_EVENT_TYPE_NOTIFY_OPEN`) to get file-open events with full process context
(PID, audit token, executable path). This is the same framework used by
production EDR tools.

- Requires the `com.apple.developer.endpoint-security.client` entitlement
- Gives us PID and process path for free (no need to guess from filesystem events)
- Can be selective: only subscribe to opens of files with extensions we care about

This is a significant enhancement to the macOS sensor but aligns with
the project's long-term direction. The Endpoint Security framework also
gives process exec, file write, and other events that would replace the
current `sysinfo` polling approach.

**Approach B: FSEvents with heuristic (quick and dirty)**

Stay with the `notify` crate. When we see a file access event for a file
with a sensitive extension, record it attributed to the frontmost application
(query via NSWorkspace). Less accurate but zero new entitlements.

**Recommendation:** Approach A for correctness. The Endpoint Security
entitlement is self-signable for open source distribution, and it gives
accurate PID→file attribution that the DLP correlator depends on.

---

## Build Sequence

The build has two parts: the Rust daemon (Cargo) and the Swift extension (Xcode/SPM).

### Makefile targets

```makefile
# Build everything
build-all: build-daemon build-filter-extension

# Rust daemon (existing, add riggs-dlp to workspace)
build-daemon:
    cargo build --release

# Swift filter extension
build-filter-extension:
    cd extensions/riggs-filter && swift build -c release
    # Bundle into .app structure for system extension loading
    ./scripts/bundle-filter-extension.sh

# Install (requires sudo)
install: build-all
    sudo cp target/release/riggs-daemon /usr/local/bin/
    sudo cp -r extensions/riggs-filter/.build/release/RiggsFilter.app \
        /Applications/
    # Activate the system extension
    /Applications/RiggsFilter.app/Contents/MacOS/riggs-filter-host --activate

# Development: run without signing (requires SIP disabled)
dev-unsigned:
    systemextensionsctl developer on
    $(MAKE) build-all
    $(MAKE) install
```

---

## Implementation Phases

### Phase 1: Correlator and DLP Stage (Rust only, no network interception)

**Goal:** Get the DLP logic working end-to-end using synthetic/test events.

**Tasks:**
- [ ] Create `crates/riggs-dlp/` with correlator, policy, and stage
- [ ] Add `DlpConfig` to `riggs-types/src/config.rs`
- [ ] Add `dlp` section to `config/riggs.toml`
- [ ] Register `DlpStage` in the pipeline (daemon.rs)
- [ ] Update `EventRouter` to route File and Network events to `dlp`
- [ ] Add `DlpCheckFlow` / `DlpVerdict` to `riggs-comms` messages
- [ ] Wire up the DLP IPC handler in `IpcServer`
- [ ] Unit tests: correlator logic, policy matching, stage verdicts
- [ ] Integration test: synthetic FileEvent::Open + NetworkEvent → block verdict
- [ ] `cargo check && cargo clippy` pass

**Estimated scope:** ~800 LOC Rust across 4-5 files.

**Verification:**
```
cargo test -p riggs-dlp
cargo test -p riggs-engine  # pipeline integration
```

### Phase 2: Endpoint Security File-Open Sensor

**Goal:** Get real file-open events with accurate PID attribution flowing
into the pipeline.

**Tasks:**
- [ ] Add Endpoint Security framework integration to `riggs-platform-macos`
  - Subscribe to `ES_EVENT_TYPE_NOTIFY_OPEN`
  - Filter to sensitive extensions at the subscription level to limit volume
  - Extract PID, process path, file path from `es_message_t`
  - Emit `RiggsEvent::File` with `FileAction::Open` and correct `ProcessContext`
- [ ] Add `FileAction::Open` variant if not already present in `riggs-types`
- [ ] Handle entitlement provisioning in the build scripts
- [ ] Test: open a `.pptx` file in Finder → verify FileEvent appears in daemon logs
- [ ] `cargo check && cargo clippy` pass

**Estimated scope:** ~300 LOC Rust (ES framework FFI or via `endpoint-security` crate).

**Key dependency:** The `endpoint-security` crate
(https://crates.io/crates/endpoint-security) provides safe Rust bindings.
If it doesn't cover `es_subscribe` for OPEN events, a thin `unsafe` FFI
layer is straightforward (~50 LOC).

**Verification:**
```
# As root (ES requires root):
sudo cargo test -p riggs-platform-macos -- --ignored es_open
# Manual: open a pptx, check riggs-cli events output
```

### Phase 3: NEFilterDataProvider System Extension (Swift)

**Goal:** Intercept network flows to monitored domains and query the daemon.

**Tasks:**
- [ ] Create `extensions/riggs-filter/` Swift package
- [ ] Implement `FilterDataProvider` (NEFilterDataProvider subclass)
  - `handleNewFlow`: extract PID + hostname, query daemon
  - `startFilter` / `stopFilter`: connect/disconnect from daemon socket
- [ ] Implement `DaemonConnection` (unix socket client, JSON protocol)
- [ ] Create minimal host app (`riggs-filter-host`) for extension activation
- [ ] Set up entitlements:
  - `com.apple.developer.networking.networkextension` with `content-filter-provider`
  - `com.apple.developer.system-extension.install`
- [ ] Create `Info.plist` with `NEProviderClasses` and `NetworkExtension` keys
- [ ] Build script: compile Swift, bundle as `.systemextension` inside `.app`
- [ ] Test: block a curl to claude.ai after touching a .pptx
- [ ] Test: allow normal browsing to claude.ai without prior file access
- [ ] Test: verify fail-open behavior when daemon is unreachable

**Estimated scope:** ~400 LOC Swift, ~100 LOC build scripting.

**Verification:**
```
# Install and activate
make install
# Terminal 1: riggs daemon running
# Terminal 2:
touch /tmp/test.pptx && open /tmp/test.pptx  # triggers file-open event
curl https://claude.ai                         # should be blocked
curl https://example.com                       # should be allowed
```

### Phase 4: CLI and Menubar Integration

**Goal:** Give users visibility and control over DLP events.

**Tasks:**
- [ ] Add `riggs dlp status` — show active policy, recent blocks, correlator stats
- [ ] Add `riggs dlp policy` — display current watched domains and file types
- [ ] Add `riggs dlp test <file> <domain>` — dry-run: would this be blocked?
- [ ] Menubar: show DLP block count, recent block notifications
- [ ] IPC: add `GetDlpStatus` and `GetDlpPolicy` message types

**Estimated scope:** ~200 LOC Rust.

### Phase 5: Hardening

**Goal:** Production-quality DLP with evasion resistance.

**Tasks:**
- [ ] Magic-byte file type detection (not just extension) in the correlator
  - OOXML: `PK\x03\x04` header → peek inside ZIP for `[Content_Types].xml`
  - OLE2: `\xD0\xCF\x11\xE0` → legacy Office formats
  - PDF: `%PDF-`
  - Implement as a small utility in `riggs-dlp/src/magic.rs`
- [ ] Process tree correlation: if Chrome spawns a helper process that does
  the actual upload, trace the PID tree using `ProcessContext.ppid` to
  attribute the file access from the parent
- [ ] Subdomain matching: `uploads.claude.ai`, `api.anthropic.com`, etc.
- [ ] Rate limiting: if a process opens 100 files/sec, don't flood the correlator
- [ ] Allowlisting: per-app overrides (e.g., "allow Slack to upload PDFs")
- [ ] Audit log: all DLP decisions (allow/block) written to a dedicated log
  for compliance review
- [ ] Config hot-reload: policy changes take effect without daemon restart

**Estimated scope:** ~500 LOC Rust.

---

## Known Limitations and Future Work

### Things This Design Cannot Catch

| Scenario | Why | Mitigation |
|----------|-----|------------|
| Copy-paste sensitive content into chat | No file read event | Clipboard monitor (future: NSPasteboard watcher) |
| Screenshot of sensitive document uploaded | Image file, not flagged by default | Add image types to watched list, but high false-positive rate |
| User types sensitive data manually | No file involvement | Out of scope for file-based DLP |
| Upload via VPN/tunnel that bypasses NEFilterDataProvider | Extension bypassed | Network-level enforcement at firewall |
| Browser reads file into memory, uploads later (>30s) | Falls outside correlation window | Increase window, but higher false-positive rate |
| Drag-and-drop without an explicit file-open syscall | Some apps use memory-mapped I/O | ES framework covers mmap; verify per-app behavior |

### Linux Equivalent

This plan focuses on macOS. The Linux equivalent would replace:
- NEFilterDataProvider → NFQUEUE via nftables (already partially built)
- Endpoint Security → eBPF (fanotify for file-open, or `bpf_probe_read` on `do_sys_open`)
- System Extension packaging → systemd unit (much simpler)

The `riggs-dlp` crate is platform-agnostic. Only the sensor and network
interception layers differ.

### Future: Content-Aware DLP

For organizations that need to inspect actual content (not just file types),
the path forward is a local transparent proxy:
- NETransparentProxyProvider (macOS) or mitmproxy (Linux)
- Terminates TLS locally with a user-installed CA certificate
- Inspects HTTP multipart form data for sensitive content
- Significantly more invasive — requires user trust and CA installation
- Deferred to a future phase if there's demand

---

## Dependencies

### New Rust crate dependencies for `riggs-dlp`:

| Crate | Purpose |
|-------|---------|
| `dashmap` | Concurrent hash map for correlator (already in workspace) |
| `chrono` | Timestamps (already in workspace) |

### New/updated for Endpoint Security:

| Crate | Purpose |
|-------|---------|
| `endpoint-security` | Safe Rust bindings for Apple Endpoint Security framework |

### Swift dependencies:

| Framework | Purpose |
|-----------|---------|
| `NetworkExtension` | NEFilterDataProvider |
| `SystemExtensions` | Extension activation from host app |

No third-party Swift packages required.

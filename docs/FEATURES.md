# Riggs: Additional Features

## Overview

Beyond core detection and response, Riggs includes four supplementary
capabilities that round out the endpoint protection platform:

1. **Network Discovery** — passive and active network asset discovery
2. **Device Control** — USB and Bluetooth policy enforcement
3. **Remote Investigation Shell** — authenticated remote terminal for
   forensic investigation
4. **Vulnerability Scanning** — CVE matching against installed packages

Each feature is implemented in its own crate and runs as an independent
supervised task in the daemon.

## Network Discovery

**Crate**: `riggs-discovery`

### Purpose

Network discovery maps the local network to identify other endpoints,
services, and potential lateral movement paths. This data feeds into
storyline enrichment (knowing the network context of a connection) and
provides operators with network visibility.

### Capabilities

#### ARP Scanning (Active)

Sends ARP requests to all addresses in the local subnet to discover active
hosts.

```rust
pub struct ArpScanner {
    interface: NetworkInterface,
    scan_interval: Duration,    // default: 5 minutes
    timeout_per_host: Duration, // default: 2 seconds
}

pub struct DiscoveredHost {
    pub ip_addr: IpAddr,
    pub mac_addr: MacAddr,
    pub hostname: Option<String>,   // from reverse DNS
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub vendor: Option<String>,     // from OUI database
    pub open_ports: Vec<u16>,       // from passive observation
}
```

ARP scanning is:
- Limited to the local subnet (no off-network scanning).
- Rate-limited to avoid triggering IDS/IPS systems on the network.
- Configurable interval (can be disabled entirely).

#### Passive Traffic Analysis

Captures network traffic passively using `pnet` to build a network map
without generating any traffic.

```rust
pub struct PassiveAnalyzer {
    interface: NetworkInterface,
    host_table: Arc<DashMap<IpAddr, DiscoveredHost>>,
}
```

Passive analysis observes:

- **ARP replies**: Maps IP to MAC addresses without sending requests.
- **DNS responses**: Captures hostname-to-IP mappings from DNS traffic
  visible on the local segment.
- **TCP SYN/SYN-ACK**: Identifies services by observing connection handshakes.
- **mDNS/Bonjour**: Discovers services advertised via multicast DNS (common
  on macOS networks).
- **DHCP**: Observes DHCP traffic to identify the DHCP server and lease
  assignments.
- **LLMNR/NetBIOS**: Captures name resolution on Windows networks.

Passive analysis runs continuously with minimal CPU overhead (it uses BPF
filters to capture only relevant traffic).

#### Network Map

The combined active and passive discovery data is stored in the network map:

```rust
pub struct NetworkMap {
    pub hosts: HashMap<IpAddr, DiscoveredHost>,
    pub local_interfaces: Vec<NetworkInterface>,
    pub default_gateway: Option<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
    pub dhcp_server: Option<IpAddr>,
    pub subnet: IpNet,
    pub last_active_scan: Option<DateTime<Utc>>,
    pub last_updated: DateTime<Utc>,
}
```

The network map is persisted to redb and queryable via the CLI:

```
riggs network map                # show discovered hosts
riggs network scan               # trigger active scan
riggs network watch              # live view of network changes
```

### Event Enrichment

When the engine processes a NetworkEvent, it looks up the remote IP in the
network map. If the host is known (internal network), the event is enriched
with the host's metadata. This helps distinguish lateral movement (internal
host → internal host) from external communication (internal host → internet).

```rust
pub fn enrich_network_event(
    event: &mut NetworkEvent,
    network_map: &NetworkMap,
) {
    if let Some(host) = network_map.hosts.get(&event.remote_addr.ip()) {
        event.remote_hostname = host.hostname.clone();
        event.remote_mac = Some(host.mac_addr);
        event.is_internal = true;
    }
}
```

## Device Control

**Crate**: `riggs-device-control`

### Purpose

Device control enforces policies on removable storage devices (USB) and
wireless interfaces (Bluetooth). This prevents data exfiltration via
physical devices and blocks unauthorized peripheral connections.

### USB Policy Enforcement

#### macOS Implementation

macOS device control uses the IOKit framework to monitor USB device
connections:

```rust
pub struct UsbMonitor {
    policy: DevicePolicy,
    notification_port: IONotificationPort,
}

pub struct DevicePolicy {
    pub usb_mode: UsbMode,
    pub allowed_vendor_ids: Vec<u16>,
    pub allowed_product_ids: Vec<(u16, u16)>, // (vendor_id, product_id)
    pub allowed_serial_numbers: Vec<String>,
    pub block_storage_devices: bool,
    pub block_hid_devices: bool,
    pub log_all_connections: bool,
}

pub enum UsbMode {
    Allow,     // all devices allowed (default)
    Audit,     // all devices allowed, but connections are logged
    Restrict,  // only allowed devices, block others
    Block,     // no USB devices allowed
}
```

When a USB device is connected:

1. The IOKit notification fires.
2. The device control task reads the device descriptor (vendor ID, product
   ID, serial number, device class).
3. The device is checked against the policy.
4. If blocked, an event is emitted and the device is disabled via IOKit.
5. If allowed or audit-only, the connection is logged.

```rust
pub struct UsbDeviceEvent {
    pub action: UsbAction,
    pub vendor_id: u16,
    pub product_id: u16,
    pub serial_number: Option<String>,
    pub device_class: UsbDeviceClass,
    pub manufacturer: Option<String>,
    pub product_name: Option<String>,
    pub policy_decision: PolicyDecision,
}

pub enum UsbAction {
    Connected,
    Disconnected,
    Blocked,
}

pub enum UsbDeviceClass {
    MassStorage,
    HumanInterface,
    Printer,
    Audio,
    Video,
    Wireless,
    Hub,
    Other(u8),
}

pub enum PolicyDecision {
    Allowed,
    Blocked { reason: String },
    Audited,
}
```

#### Linux Implementation

Linux device control uses udev rules and sysfs:

1. Monitor `/dev` via udev for USB device events.
2. Read device attributes from `/sys/bus/usb/devices/`.
3. Use `usb_deauthorize` to block devices by writing to
   `/sys/bus/usb/devices/<device>/authorized`.

### Bluetooth Policy Enforcement

#### macOS Implementation

Bluetooth monitoring uses the IOBluetooth framework:

```rust
pub struct BluetoothPolicy {
    pub bluetooth_mode: BluetoothMode,
    pub allowed_device_addresses: Vec<String>,
    pub block_file_transfer: bool,
    pub block_audio: bool,
    pub log_all_connections: bool,
}

pub enum BluetoothMode {
    Allow,
    Audit,
    Restrict,  // only paired/allowed devices
    Block,     // disable Bluetooth entirely
}
```

When `Block` mode is active, Bluetooth is disabled via the `blueutil`
system utility or IOBluetooth API.

### Policy Configuration

```toml
[device_control]
enabled = true

[device_control.usb]
mode = "restrict"
block_storage_devices = true
block_hid_devices = false
allowed_vendor_ids = [0x05AC]  # Apple devices
allowed_serial_numbers = ["ABC123"]
log_all_connections = true

[device_control.bluetooth]
mode = "audit"
block_file_transfer = true
log_all_connections = true
```

### CLI Interface

```
riggs devices list              # list connected USB/Bluetooth devices
riggs devices policy show       # show current device policy
riggs devices block usb         # switch USB to block mode
riggs devices allow usb         # switch USB to allow mode
riggs devices history           # show device connection history
```

## Remote Investigation Shell

**Crate**: `riggs-shell`

### Purpose

The remote investigation shell provides an authenticated, encrypted terminal
session on the endpoint for forensic investigation. It is a controlled
alternative to SSH: the session is logged, audited, and can be terminated
by policy.

### Architecture

```
Investigator (remote)
    │
    │ encrypted channel (ed25519 + AES-256-GCM)
    │
    ▼
riggs-daemon (shell-listener-task)
    │
    ▼
portable-pty (pseudo-terminal)
    │
    ▼
/bin/zsh (or configured shell)
```

### Authentication

Shell access uses ed25519 public key authentication:

1. **Authorized keys**: Public keys of authorized investigators are stored in
   `/etc/riggs/authorized_keys`. Each key has an associated identity and
   permission level.

```
# /etc/riggs/authorized_keys
# Format: <base64-ed25519-pubkey> <identity> <permissions>
AAAAC3NzaC1lZDI1NTE5AAAAIGh... analyst@soc read,shell
AAAAC3NzaC1lZDI1NTE5AAAAIBx... admin@soc read,shell,response
```

2. **Challenge-response**: When a client connects, the daemon sends a
   random 32-byte challenge. The client signs it with their ed25519 private
   key. The daemon verifies the signature against authorized keys.

```rust
pub struct ShellAuth {
    pub authorized_keys: Vec<AuthorizedKey>,
}

pub struct AuthorizedKey {
    pub public_key: ed25519_dalek::VerifyingKey,
    pub identity: String,
    pub permissions: Vec<Permission>,
}

pub enum Permission {
    Read,       // can view events, verdicts, storylines
    Shell,      // can open interactive shell
    Response,   // can execute response actions
}
```

### Session Management

```rust
pub struct ShellSession {
    pub session_id: Uuid,
    pub identity: String,
    pub connected_at: DateTime<Utc>,
    pub source_addr: SocketAddr,
    pub pty: Box<dyn portable_pty::MasterPty>,
    pub child: Box<dyn portable_pty::Child>,
    pub permissions: Vec<Permission>,
}
```

Sessions are:

- **Logged**: Every command entered and output produced is recorded in the
  audit trail.
- **Timeout**: Sessions idle for more than 30 minutes are terminated.
- **Concurrent limit**: Maximum 3 concurrent shell sessions (configurable).
- **Kill switch**: The daemon can terminate any session via CLI command or
  cloud policy.

### PTY Implementation

The `portable-pty` crate provides cross-platform pseudo-terminal allocation:

```rust
pub fn spawn_shell(config: &ShellConfig) -> Result<ShellSession, ShellError> {
    let pty_system = portable_pty::native_pty_system();

    let pair = pty_system.openpty(PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    })?;

    let mut cmd = CommandBuilder::new(&config.shell_path); // /bin/zsh
    cmd.env("TERM", "xterm-256color");
    cmd.env("RIGGS_SHELL", "1"); // marker for shell awareness
    cmd.cwd(&config.working_directory);

    let child = pair.slave.spawn_command(cmd)?;

    Ok(ShellSession {
        session_id: Uuid::now_v7(),
        pty: pair.master,
        child,
        // ...
    })
}
```

### Transport

Shell sessions use a custom binary protocol over TCP (port 4722, configurable):

```
┌──────────┬──────┬──────────┬──────────────────┐
│ 4 bytes  │ 1 B  │ 4 bytes  │ N bytes          │
│ (seq no) │(type)│ (length) │ (encrypted data) │
└──────────┴──────┴──────────┴──────────────────┘

Types:
  0x01 = terminal data (stdin/stdout)
  0x02 = resize event
  0x03 = signal
  0x04 = keepalive
  0x05 = session metadata
```

All data is encrypted with AES-256-GCM using a session key derived from the
ed25519 key exchange.

### CLI Access

```
riggs shell connect <host>:<port>     # connect to remote agent
riggs shell sessions                   # list active sessions (local)
riggs shell kill <session_id>          # terminate a session
riggs shell history <session_id>       # view session transcript
```

## Vulnerability Scanning

**Crate**: `riggs-vuln`

### Purpose

Vulnerability scanning identifies known CVEs in software installed on the
endpoint. It compares installed package versions against a local CVE database
and reports vulnerabilities with severity scores.

### CVE Database

The CVE database is stored locally at `/var/lib/riggs/cve.db` (a redb file,
separate from the main database). It is populated from the NVD (National
Vulnerability Database) JSON feeds, downloaded and processed offline.

```rust
pub struct CveEntry {
    pub cve_id: String,           // "CVE-2026-12345"
    pub description: String,
    pub cvss_score: f32,          // 0.0 - 10.0
    pub cvss_vector: String,
    pub severity: CveSeverity,
    pub affected_products: Vec<AffectedProduct>,
    pub published_date: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub references: Vec<String>,
}

pub struct AffectedProduct {
    pub vendor: String,
    pub product: String,
    pub version_start: Option<String>,
    pub version_end: Option<String>,
    pub version_exact: Option<String>,
}

pub enum CveSeverity {
    None,
    Low,
    Medium,
    High,
    Critical,
}
```

### Package Enumeration

The vulnerability scanner enumerates installed software:

#### macOS

1. **Homebrew packages**: Parse `$(brew --prefix)/Cellar/` directory structure.
2. **System packages**: Parse `/Library/Receipts/InstallHistory.plist`.
3. **Applications**: Scan `/Applications/` and `~/Applications/` for app
   bundles, extract version from `Info.plist`.
4. **Python packages**: Parse `pip list --format=json` output.
5. **Node.js packages**: Parse global `node_modules` and project
   `package-lock.json` files.
6. **Ruby gems**: Parse `gem list --local` output.

#### Linux

1. **dpkg**: Parse `/var/lib/dpkg/status` for Debian-based.
2. **rpm**: Query RPM database for Red Hat-based.
3. **Installed binaries**: Enumerate `/usr/bin/`, `/usr/sbin/` with version
   detection heuristics (`--version` flag).
4. **Python/Node/Ruby**: Same as macOS.

```rust
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub source: PackageSource,
    pub install_path: Option<PathBuf>,
}

pub enum PackageSource {
    Homebrew,
    System,
    Application,
    Pip,
    Npm,
    Gem,
    Dpkg,
    Rpm,
    Binary,
}
```

### Matching Engine

```rust
pub fn scan_vulnerabilities(
    packages: &[InstalledPackage],
    cve_db: &CveDatabase,
) -> Vec<VulnerabilityMatch> {
    let mut matches = Vec::new();

    for package in packages {
        let cves = cve_db.lookup(&package.name, &package.version);
        for cve in cves {
            matches.push(VulnerabilityMatch {
                package: package.clone(),
                cve: cve.clone(),
                remediation: suggest_remediation(package, &cve),
            });
        }
    }

    matches.sort_by(|a, b| b.cve.cvss_score.partial_cmp(&a.cve.cvss_score).unwrap());
    matches
}

pub struct VulnerabilityMatch {
    pub package: InstalledPackage,
    pub cve: CveEntry,
    pub remediation: Option<Remediation>,
}

pub struct Remediation {
    pub fixed_version: Option<String>,
    pub upgrade_command: Option<String>,
    pub workaround: Option<String>,
}
```

Version matching uses semantic version comparison with range support:
`version_start <= installed_version < version_end`.

### Scan Schedule

- **Full scan**: On daemon startup and every 24 hours.
- **Incremental scan**: When a new package install is detected (via file
  system events in package manager directories).
- **On-demand**: Via CLI command.

### Output

```
riggs vuln scan                       # run scan now
riggs vuln report                     # show latest scan results
riggs vuln report --severity critical # filter by severity
riggs vuln report --format json       # machine-readable output
riggs vuln cve <CVE-ID>              # show details for a specific CVE
riggs vuln update                     # update local CVE database
```

### Integration with Detection

High-severity vulnerabilities in running services feed into the behavioral
model as risk factors. A process running a version of OpenSSL with a known
RCE vulnerability gets a higher baseline risk score, making the behavioral
model more sensitive to anomalous behavior from that process.

## Metrics

- `riggs_discovery_hosts_total` — gauge
- `riggs_discovery_scan_duration_ms` — histogram
- `riggs_device_events_total` — counter per action per device class
- `riggs_device_blocked_total` — counter
- `riggs_shell_sessions_active` — gauge
- `riggs_shell_sessions_total` — counter
- `riggs_vuln_total` — gauge per severity
- `riggs_vuln_scan_duration_ms` — histogram
- `riggs_vuln_packages_scanned` — gauge

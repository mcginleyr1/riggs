# Murtaugh — gRPC Protocol

## Overview

Agents connect to the console via gRPC over mTLS. The protocol uses
bidirectional streaming for telemetry and server-push for commands.
Proto definitions will live in a shared `proto/` directory used by both
the Rust agent (`tonic`) and the Elixir console (`grpc` + `protobuf`).

## Service Definitions

```protobuf
syntax = "proto3";

package riggs.v1;

import "google/protobuf/timestamp.proto";

// ═══════════════════════════════════════════════════════════════════
// Agent → Console
// ═══════════════════════════════════════════════════════════════════

service AgentService {
    // Enrollment: agent registers itself with the console
    rpc Enroll(EnrollRequest) returns (EnrollResponse);

    // Heartbeat stream: agent sends health, console sends ack or commands
    rpc Heartbeat(stream HeartbeatRequest) returns (stream HeartbeatResponse);

    // Telemetry stream: agent pushes batched events
    rpc StreamEvents(stream EventBatch) returns (stream EventAck);

    // Immediate threat report (not batched)
    rpc ReportThreat(ThreatReport) returns (ThreatAck);

    // DLP event report
    rpc ReportDlpEvent(DlpEventReport) returns (DlpEventAck);

    // Vulnerability scan results
    rpc ReportVulnScan(VulnScanReport) returns (VulnScanAck);

    // Device event report
    rpc ReportDeviceEvent(DeviceEventReport) returns (DeviceEventAck);

    // Network map update
    rpc UpdateNetworkMap(NetworkMapUpdate) returns (NetworkMapAck);

    // Storyline update
    rpc UpdateStoryline(StorylineUpdate) returns (StorylineAck);
}

// ═══════════════════════════════════════════════════════════════════
// Console → Agent (via heartbeat response or command stream)
// ═══════════════════════════════════════════════════════════════════

service CommandService {
    // Long-lived command stream: console pushes commands, agent acks
    rpc CommandStream(stream CommandAck) returns (stream AgentCommand);
}

// ═══════════════════════════════════════════════════════════════════
// Messages: Enrollment
// ═══════════════════════════════════════════════════════════════════

message EnrollRequest {
    string hostname = 1;
    string os = 2;
    string os_version = 3;
    string arch = 4;
    string agent_version = 5;
    string ip_address = 6;
    string mac_address = 7;
    string enrollment_token = 8;  // pre-shared token for auth
}

message EnrollResponse {
    string agent_id = 1;          // assigned UUID
    bytes  client_cert = 2;       // mTLS client certificate
    bytes  client_key = 3;        // mTLS client private key
    bytes  ca_cert = 4;           // CA certificate for verification
    int32  heartbeat_interval_secs = 5;
    int32  event_batch_size = 6;
    int32  event_flush_interval_ms = 7;
}

// ═══════════════════════════════════════════════════════════════════
// Messages: Heartbeat
// ═══════════════════════════════════════════════════════════════════

message HeartbeatRequest {
    string agent_id = 1;
    google.protobuf.Timestamp timestamp = 2;
    AgentHealth health = 3;
}

message AgentHealth {
    uint64 events_processed = 1;
    uint64 threats_detected = 2;
    uint64 dlp_blocks = 3;
    bool   sensor_healthy = 4;
    uint64 pipeline_latency_us = 5;
    uint64 store_size_bytes = 6;
    uint64 uptime_secs = 7;
    string agent_version = 8;
    int32  config_version = 9;
}

message HeartbeatResponse {
    bool accepted = 1;
    // Piggyback lightweight commands on heartbeat responses
    repeated AgentCommand commands = 2;
}

// ═══════════════════════════════════════════════════════════════════
// Messages: Events
// ═══════════════════════════════════════════════════════════════════

message EventBatch {
    string agent_id = 1;
    repeated Event events = 2;
    int32  batch_seq = 3;         // for ordering / gap detection
}

message Event {
    string event_id = 1;          // UUID v7
    string storyline_id = 2;
    string event_type = 3;        // process, file, network, dns, auth, kernel
    string severity = 4;
    google.protobuf.Timestamp timestamp = 5;
    ProcessContext process_context = 6;
    bytes  payload_json = 7;      // event-specific fields as JSON
}

message ProcessContext {
    uint32 pid = 1;
    uint32 ppid = 2;
    string name = 3;
    string path = 4;
    string cmdline = 5;
    string user = 6;
    string storyline_id = 7;
}

message EventAck {
    int32 batch_seq = 1;
    bool  accepted = 2;
}

// ═══════════════════════════════════════════════════════════════════
// Messages: Threats
// ═══════════════════════════════════════════════════════════════════

message ThreatReport {
    string agent_id = 1;
    string event_id = 2;
    string storyline_id = 3;
    string threat_level = 4;      // suspicious, malicious
    float  final_score = 5;
    google.protobuf.Timestamp timestamp = 6;
    repeated VerdictDetail verdicts = 7;
    string process_name = 8;
    string process_path = 9;
    string summary = 10;
}

message VerdictDetail {
    string source = 1;            // StaticAI, BehavioralAI, YaraRule, etc.
    string threat_level = 2;
    float  confidence = 3;
    string description = 4;
}

message ThreatAck {
    bool accepted = 1;
    string threat_id = 2;         // console-assigned ID
}

// ═══════════════════════════════════════════════════════════════════
// Messages: DLP
// ═══════════════════════════════════════════════════════════════════

message DlpEventReport {
    string agent_id = 1;
    google.protobuf.Timestamp timestamp = 2;
    string action = 3;            // block, alert
    uint32 pid = 4;
    string process_name = 5;
    string file_path = 6;
    string file_type = 7;
    string domain = 8;
    string domain_category = 9;
    string username = 10;
}

message DlpEventAck {
    bool accepted = 1;
}

// ═══════════════════════════════════════════════════════════════════
// Messages: Vulnerability
// ═══════════════════════════════════════════════════════════════════

message VulnScanReport {
    string agent_id = 1;
    google.protobuf.Timestamp scan_timestamp = 2;
    repeated VulnFinding findings = 3;
}

message VulnFinding {
    string cve_id = 1;
    string package_name = 2;
    string package_version = 3;
    string package_source = 4;
    float  cvss_score = 5;
    string severity = 6;
    string fixed_version = 7;
}

message VulnScanAck {
    bool accepted = 1;
    int32 findings_stored = 2;
}

// ═══════════════════════════════════════════════════════════════════
// Messages: Device Control
// ═══════════════════════════════════════════════════════════════════

message DeviceEventReport {
    string agent_id = 1;
    google.protobuf.Timestamp timestamp = 2;
    string device_type = 3;       // usb, bluetooth
    string action = 4;            // connected, disconnected, blocked
    uint32 vendor_id = 5;
    uint32 product_id = 6;
    string serial_number = 7;
    string device_class = 8;
    string manufacturer = 9;
    string product_name = 10;
    string policy_decision = 11;
}

message DeviceEventAck {
    bool accepted = 1;
}

// ═══════════════════════════════════════════════════════════════════
// Messages: Network Discovery
// ═══════════════════════════════════════════════════════════════════

message NetworkMapUpdate {
    string agent_id = 1;
    repeated DiscoveredHost hosts = 2;
}

message DiscoveredHost {
    string ip_address = 1;
    string mac_address = 2;
    string hostname = 3;
    string vendor = 4;
    google.protobuf.Timestamp first_seen = 5;
    google.protobuf.Timestamp last_seen = 6;
    repeated uint32 open_ports = 7;
}

message NetworkMapAck {
    bool accepted = 1;
}

// ═══════════════════════════════════════════════════════════════════
// Messages: Storylines
// ═══════════════════════════════════════════════════════════════════

message StorylineUpdate {
    string agent_id = 1;
    string storyline_id = 2;
    string status = 3;            // active, completed, mitigated
    string max_severity = 4;
    int32  threat_count = 5;
    int32  event_count = 6;
    google.protobuf.Timestamp first_seen = 7;
    google.protobuf.Timestamp last_seen = 8;
    uint32 root_pid = 9;
    string root_process = 10;
    string root_path = 11;
    bytes  process_tree_json = 12;
}

message StorylineAck {
    bool accepted = 1;
}

// ═══════════════════════════════════════════════════════════════════
// Messages: Commands (Console → Agent)
// ═══════════════════════════════════════════════════════════════════

message AgentCommand {
    string command_id = 1;        // for ack correlation
    oneof command {
        KillProcess kill_process = 10;
        SuspendProcess suspend_process = 11;
        QuarantineFile quarantine_file = 12;
        ContainNetwork contain_network = 13;
        ReleaseNetwork release_network = 14;
        UpdatePolicy update_policy = 15;
        UpdateConfig update_config = 16;
        TriggerScan trigger_scan = 17;
        RefreshFeeds refresh_feeds = 18;
        OpenShell open_shell = 19;
    }
}

message KillProcess {
    uint32 pid = 1;
    string reason = 2;
}

message SuspendProcess {
    uint32 pid = 1;
    string reason = 2;
}

message QuarantineFile {
    string path = 1;
    string reason = 2;
}

message ContainNetwork {
    repeated string allowed_ips = 1;  // only these IPs allowed during containment
    string reason = 2;
}

message ReleaseNetwork {
    string reason = 1;
}

message UpdatePolicy {
    string policy_type = 1;       // dlp, response, detection, device
    string policy_name = 2;
    bytes  content = 3;           // TOML body
    int32  version = 4;
}

message UpdateConfig {
    string key = 1;
    string value = 2;
}

message TriggerScan {
    string path = 1;
}

message RefreshFeeds {}

message OpenShell {
    string session_id = 1;
    uint32 port = 2;              // agent opens listener on this port
}

message CommandAck {
    string command_id = 1;
    bool   success = 2;
    string detail = 3;
}
```

## Connection Lifecycle

```
Agent                                Console
  │                                    │
  │──── Enroll(token, host info) ─────▶│  Store agent, issue mTLS certs
  │◀─── EnrollResponse(id, certs) ────│
  │                                    │
  │════ mTLS connection established ══│
  │                                    │
  │──── Heartbeat stream opens ───────▶│
  │     (every 60s)                    │
  │◀─── HeartbeatResponse ────────────│  May include piggybacked commands
  │                                    │
  │──── StreamEvents stream opens ────▶│  Batched, every 5s or 100 events
  │◀─── EventAck ────────────────────│
  │                                    │
  │──── ReportThreat (immediate) ─────▶│  Bypasses batching
  │◀─── ThreatAck ───────────────────│
  │                                    │
  │◀═══ CommandStream opens ══════════│  Console pushes commands
  │──── CommandAck ───────────────────▶│
  │                                    │
```

## Batching Strategy

Events are batched on the agent side to reduce gRPC overhead:

- **Batch size**: 100 events max
- **Flush interval**: 5 seconds (whichever comes first)
- **Priority bypass**: ThreatReport and DlpEventReport are sent immediately
  (not batched) because they require fast console visibility
- **Backpressure**: if the console is slow to ack, the agent buffers up to
  10,000 events in memory. Beyond that, oldest events are dropped and a
  gap counter is incremented (reported in next heartbeat)

## Authentication

1. **Enrollment**: agent presents a pre-shared enrollment token. Console
   validates it and issues mTLS client certificate + key.
2. **Ongoing**: all gRPC calls use mTLS. The console extracts agent_id from
   the client certificate's CN field.
3. **Token rotation**: console can push a new client cert via UpdateConfig
   command before the current one expires.

## Elixir Side

The console uses `grpc` and `protobuf` hex packages:

```elixir
# mix.exs
{:grpc, "~> 0.9"},
{:protobuf, "~> 0.13"},
```

Each service maps to a GenServer or set of GenServers:

| gRPC Service | Elixir Module | Notes |
|---|---|---|
| AgentService.Enroll | `Riggs.Grpc.EnrollHandler` | Creates agent record |
| AgentService.Heartbeat | `Riggs.Grpc.HeartbeatHandler` | Updates agent health, broadcasts via PubSub |
| AgentService.StreamEvents | `Riggs.Grpc.EventIngester` | Batch insert to events table |
| AgentService.ReportThreat | `Riggs.Grpc.ThreatHandler` | Insert + broadcast to LiveView |
| AgentService.ReportDlpEvent | `Riggs.Grpc.DlpHandler` | Insert + broadcast |
| CommandService.CommandStream | `Riggs.Grpc.CommandDispatcher` | Holds open streams per agent |

Events are broadcast via Phoenix PubSub to LiveView processes:

```elixir
Phoenix.PubSub.broadcast(Riggs.PubSub, "threats", {:new_threat, threat})
Phoenix.PubSub.broadcast(Riggs.PubSub, "agent:#{agent_id}", {:heartbeat, health})
Phoenix.PubSub.broadcast(Riggs.PubSub, "dlp", {:dlp_event, event})
```

LiveView pages subscribe to the topics they care about and update in real-time.

# Riggs: Communication Layer

## Overview

The communication layer handles two distinct concerns:

1. **Local IPC**: Communication between the CLI and the daemon via Unix domain
   sockets. Always available.
2. **Cloud reporting**: Optional gRPC connection to a management server for
   telemetry, alerts, and policy updates. Feature-gated behind
   `--features cloud`.

All communication code lives in `riggs-comms`.

## Local IPC

### Unix Domain Socket

The daemon listens on a Unix domain socket for CLI connections:

- **System mode**: `/var/run/riggs/riggs.sock`
- **User mode**: `$XDG_RUNTIME_DIR/riggs/riggs.sock` (typically
  `/tmp/riggs-<uid>/riggs.sock`)

The socket is created with permissions `0660`, owned by `root:riggs-admin`.
Only members of the `riggs-admin` group can connect.

### Protocol

IPC uses a simple length-prefixed JSON protocol over the Unix socket:

```
┌──────────┬──────────────────┐
│ 4 bytes  │ N bytes          │
│ (u32 LE) │ (JSON payload)   │
│ length   │                  │
└──────────┴──────────────────┘
```

Each message is a JSON object with a `type` field and a `payload` field:

```json
{
    "type": "request",
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "method": "list_events",
    "params": {
        "since": "2026-03-13T10:00:00Z",
        "event_type": "process",
        "limit": 100
    }
}
```

Responses:

```json
{
    "type": "response",
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "ok",
    "data": [ ... ]
}
```

Errors:

```json
{
    "type": "response",
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "error",
    "error": {
        "code": "NOT_FOUND",
        "message": "No events matching filter"
    }
}
```

### IPC Methods

| Method              | Description                                   | Params                      |
|---------------------|-----------------------------------------------|-----------------------------|
| status              | Agent status and health                       | none                        |
| list_events         | Query events with filters                     | since, until, type, limit   |
| get_event           | Get single event by ID                        | event_id                    |
| list_verdicts       | Query verdicts with filters                   | since, disposition, limit   |
| get_storyline       | Get storyline with events                     | storyline_id                |
| list_quarantine     | List quarantined files                        | since, limit                |
| restore_quarantine  | Restore a quarantined file                    | quarantine_id               |
| list_audit          | Query response audit trail                    | since, action, limit        |
| contain             | Activate network containment                  | mode, allowed_endpoints     |
| release_containment | Remove network containment                    | none                        |
| reload_rules        | Force rule reload                             | none                        |
| get_config          | Read config value                             | key                         |
| set_config          | Write config value                            | key, value                  |
| get_metrics         | Get internal metrics snapshot                 | none                        |
| list_rules          | List loaded rules                             | type (yara/ioc/star)        |
| test_rule           | Test a rule against a sample                  | rule_path, sample_path      |
| approve_response    | Approve a pending response action             | audit_id                    |
| deny_response       | Deny a pending response action                | audit_id                    |

### IPC Authentication

The IPC socket uses OS-level authentication:

1. **macOS**: `getpeereid()` system call to get the connecting process's uid
   and gid.
2. **Linux**: `SO_PEERCRED` socket option to get pid, uid, and gid.

The daemon checks that the connecting uid is either root or a member of the
`riggs-admin` group. Unauthorized connections are rejected with a clear error
message.

Some methods require elevated permissions:

| Permission Level | Methods                                         |
|------------------|-------------------------------------------------|
| read             | status, list_*, get_*, get_metrics               |
| write            | reload_rules, set_config, approve/deny_response  |
| admin            | contain, release_containment, restore_quarantine |

### IPC Connection Handling

The daemon spawns a new tokio task per CLI connection. Each connection is
independent and stateless (no sessions). The connection task reads a request,
dispatches it to the appropriate handler, and writes the response.

```rust
async fn handle_connection(
    stream: UnixStream,
    store: StoreReader,
    response_tx: mpsc::Sender<StoreCommand>,
) {
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);

    loop {
        match read_message(&mut reader).await {
            Ok(request) => {
                let response = dispatch(request, &store, &response_tx).await;
                write_message(&mut writer, &response).await.ok();
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                tracing::warn!("IPC read error: {e}");
                break;
            }
        }
    }
}
```

Maximum concurrent IPC connections: 16 (configurable). Connections exceeding
the limit are queued, not rejected.

## Cloud Reporting (Feature-Gated)

Cloud connectivity is compiled only with `--features cloud`. Without this
feature flag, no gRPC dependencies are included and no cloud code exists in
the binary.

### gRPC Service Definition

```protobuf
syntax = "proto3";
package riggs.v1;

service RiggsCloud {
    // Agent → Cloud: push telemetry
    rpc ReportTelemetry(stream TelemetryReport) returns (TelemetryAck);

    // Agent → Cloud: push threat alerts
    rpc ReportThreat(ThreatAlert) returns (ThreatAck);

    // Agent → Cloud: heartbeat
    rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);

    // Cloud → Agent: stream policy updates
    rpc StreamPolicies(PolicyRequest) returns (stream PolicyUpdate);

    // Cloud → Agent: on-demand investigation request
    rpc RequestInvestigation(InvestigationRequest) returns (InvestigationResponse);
}
```

### Message Types

#### TelemetryReport

```protobuf
message TelemetryReport {
    string agent_id = 1;
    int64 timestamp = 2;
    repeated EventSummary events = 3;
    AgentMetrics metrics = 4;
}

message EventSummary {
    string event_id = 1;
    string event_type = 2;
    int64 timestamp = 3;
    string storyline_id = 4;
    Severity severity = 5;
    // Full event payload is NOT sent — only metadata summaries
    // to minimize bandwidth and protect sensitive data
}
```

Telemetry reports are batched. The agent accumulates event summaries and
sends a batch every 60 seconds (configurable). Under quiet conditions,
the batch may contain only a metrics snapshot.

#### ThreatAlert

```protobuf
message ThreatAlert {
    string agent_id = 1;
    string alert_id = 2;
    int64 timestamp = 3;
    string storyline_id = 4;
    Severity severity = 5;
    Disposition disposition = 6;
    float confidence = 7;
    string description = 8;
    repeated string mitre_techniques = 9;
    repeated ResponseActionSummary actions_taken = 10;
    // Full storyline events can be requested via RequestInvestigation
}
```

Threat alerts are sent immediately (not batched). They are the highest
priority messages.

#### HeartBeat

```protobuf
message HeartbeatRequest {
    string agent_id = 1;
    int64 timestamp = 2;
    string agent_version = 3;
    string os_type = 4;
    string os_version = 5;
    string hostname = 6;
    AgentHealth health = 7;
}

message HeartbeatResponse {
    bool acknowledged = 1;
    int64 server_timestamp = 2;
    repeated string pending_commands = 3; // commands for the agent to execute
}

message AgentHealth {
    bool sensor_healthy = 1;
    bool engine_healthy = 2;
    bool store_healthy = 3;
    uint64 events_per_second = 4;
    uint64 active_storylines = 5;
    float cpu_usage_percent = 6;
    uint64 memory_usage_bytes = 7;
    uint64 db_size_bytes = 8;
}
```

Heartbeats are sent every 30 seconds (configurable). The server responds
with an acknowledgment and optionally a list of pending commands (e.g.,
"update rules", "start investigation", "change policy").

#### PolicyUpdate

```protobuf
message PolicyUpdate {
    string policy_id = 1;
    int64 timestamp = 2;
    PolicyType policy_type = 3;
    bytes policy_content = 4; // TOML or JSON payload
    string checksum = 5;
}

enum PolicyType {
    RESPONSE_POLICY = 0;
    RULE_UPDATE = 1;
    IOC_UPDATE = 2;
    MODEL_UPDATE = 3;
    CONFIG_UPDATE = 4;
}
```

The agent streams policy updates from the cloud. When a new policy arrives:

1. Verify the checksum.
2. Write the policy to the appropriate file (e.g., `config/policies/cloud.toml`).
3. Trigger a hot-reload.
4. Acknowledge receipt to the cloud.

### mTLS Authentication

All cloud connections use mutual TLS (mTLS):

- **Server certificate**: The management server presents a certificate signed
  by the organization's CA. The agent verifies it against a pinned CA
  certificate stored at `/etc/riggs/ca.pem`.
- **Client certificate**: The agent presents its own certificate (generated
  at enrollment time) to authenticate itself to the server. The certificate
  and private key are stored at `/etc/riggs/agent.pem` and
  `/etc/riggs/agent.key`.

```rust
pub fn create_tls_config(config: &CloudConfig) -> Result<ClientTlsConfig, CommsError> {
    let server_ca = std::fs::read(&config.ca_cert_path)?;
    let client_cert = std::fs::read(&config.agent_cert_path)?;
    let client_key = std::fs::read(&config.agent_key_path)?;

    let identity = Identity::from_pem(client_cert, client_key);
    let ca = Certificate::from_pem(server_ca);

    Ok(ClientTlsConfig::new()
        .domain_name(&config.server_domain)
        .ca_certificate(ca)
        .identity(identity))
}
```

### Enrollment

Before cloud connectivity works, the agent must be enrolled:

```
riggs enroll --server cloud.example.com:443 --token <enrollment_token>
```

Enrollment flow:

1. Agent generates an ed25519 keypair.
2. Agent creates a CSR (Certificate Signing Request).
3. Agent sends CSR + enrollment token to the server's enrollment endpoint.
4. Server validates the token, signs the CSR, and returns a client certificate.
5. Agent stores the certificate and key.
6. Agent stores the server CA certificate.
7. Cloud connection is now possible.

### Backpressure Handling

Cloud connections may be slow or unreliable. The comms layer handles this:

1. **Bounded buffer**: Telemetry reports queue in a bounded channel (1024
   entries). If the channel fills, the oldest reports are dropped (the most
   recent data is more valuable).
2. **Priority queue**: Threat alerts bypass the telemetry queue and are sent
   immediately on a dedicated channel.
3. **Write coalescing**: Multiple telemetry reports are merged into larger
   batches when the channel is draining slowly, reducing per-message overhead.

### Retry with Exponential Backoff

Failed cloud operations are retried with exponential backoff:

```rust
pub struct RetryPolicy {
    pub initial_delay: Duration,    // 1 second
    pub max_delay: Duration,        // 5 minutes
    pub multiplier: f64,            // 2.0
    pub jitter: f64,                // 0.1 (10% random jitter)
    pub max_retries: Option<u32>,   // None = infinite
}
```

Backoff sequence: 1s, 2s, 4s, 8s, 16s, 32s, 64s, 128s, 256s, 300s (cap).

Connection loss is detected via heartbeat timeout. If 3 consecutive heartbeats
fail, the agent enters offline mode. In offline mode:

1. Telemetry is queued locally (in redb) up to the retention limit.
2. Threat alerts are queued locally.
3. The agent continues reconnection attempts with exponential backoff.
4. When the connection is restored, queued data is sent in chronological order.

### Bandwidth Estimates

| Message Type     | Frequency    | Size (avg) | Bandwidth      |
|------------------|-------------|------------|----------------|
| Heartbeat        | every 30s   | 500 bytes  | ~1 KB/min      |
| Telemetry batch  | every 60s   | 10 KB      | ~10 KB/min     |
| Threat alert     | on event    | 2 KB       | varies         |
| Policy update    | on change   | 5 KB       | rare           |
| **Typical total**|             |            | **~15 KB/min** |

Cloud bandwidth usage is minimal by design. Full event payloads are never
sent in telemetry — only summaries. The full data can be requested
on-demand via `RequestInvestigation`.

## CLI Client

The `riggs-cli` crate implements the CLI binary, which connects to the
daemon via the Unix socket.

### Connection

```rust
pub struct DaemonClient {
    stream: UnixStream,
}

impl DaemonClient {
    pub async fn connect() -> Result<Self, CliError> {
        let socket_path = determine_socket_path()?;
        let stream = UnixStream::connect(&socket_path).await
            .map_err(|_| CliError::DaemonNotRunning)?;
        Ok(Self { stream })
    }

    pub async fn call(&mut self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, CliError> {
        let request = json!({
            "type": "request",
            "id": Uuid::new_v4().to_string(),
            "method": method,
            "params": params,
        });

        write_message(&mut self.stream, &request).await?;
        let response = read_message(&mut self.stream).await?;

        match response["status"].as_str() {
            Some("ok") => Ok(response["data"].clone()),
            Some("error") => Err(CliError::ServerError(
                response["error"]["message"].as_str().unwrap_or("unknown").to_string()
            )),
            _ => Err(CliError::InvalidResponse),
        }
    }
}
```

### CLI Commands

```
riggs status                          # agent health and summary
riggs events list [--since] [--type]  # query events
riggs events show <id>                # show single event
riggs verdicts list [--disposition]    # query verdicts
riggs storyline show <id>             # show storyline graph
riggs quarantine list                 # list quarantined files
riggs quarantine restore <id>         # restore quarantined file
riggs contain [full|partial|dns-only] # activate containment
riggs contain release                 # remove containment
riggs rules list [--type]             # list loaded rules
riggs rules reload                    # force rule reload
riggs rules test <path> [--sample]    # test a rule
riggs audit list [--since] [--action] # query audit trail
riggs config get <key>                # read config
riggs config set <key> <value>        # write config
riggs metrics                         # internal metrics
riggs enroll --server <url> --token <token>  # cloud enrollment
```

### Output Formatting

The CLI supports multiple output formats:

- **table** (default): Human-readable table output
- **json**: Machine-readable JSON
- **jsonl**: JSON Lines (one JSON object per line)

```
riggs events list --since "1h ago" --format json | jq '.[] | .event_type'
```

## Metrics

- `riggs_ipc_connections_active` — gauge
- `riggs_ipc_requests_total` — counter per method
- `riggs_ipc_request_latency_us` — histogram per method
- `riggs_ipc_errors_total` — counter per error code
- `riggs_cloud_connected` — boolean gauge
- `riggs_cloud_messages_sent_total` — counter per message type
- `riggs_cloud_messages_failed_total` — counter per message type
- `riggs_cloud_retry_count_total` — counter
- `riggs_cloud_queue_depth` — gauge
- `riggs_cloud_bandwidth_bytes_total` — counter (sent/received)

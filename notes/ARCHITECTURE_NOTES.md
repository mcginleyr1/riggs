# Murtaugh — Architecture Notes

## Tech Stack

- **Elixir 1.19** / **OTP 28**
- **Phoenix 1.8** with **LiveView** (no SPA, no REST API for UI)
- **PostgreSQL 16** — two-tier: meta DB + database-per-tenant (partitioned by month)
- **gRPC** for agent communication (`grpc` + `protobuf` hex packages)
- **Tailwind CSS** (ships with Phoenix 1.8)
- **Oban** for background jobs (partition maintenance, stale agent detection, alert dispatch)

## Multi-Tenancy

See `MULTI_TENANCY.md` for the full spec. Key points:

- **Meta DB** (`murtaugh_meta`): org tree (nested set), users, permissions,
  shard routing, enrollment tokens, audit log
- **Tenant DBs** (`murtaugh_tenant_<slug>`): one per account node. Contains
  agents, events, threats, DLP events — physically separated per tenant
- **Shard routing**: walk org tree to nearest account ancestor → lookup
  tenant_shards → dynamic Ecto repo
- **Org-scoped everything**: every URL is under `/orgs/:slug/...`, every
  query filters by org_node_id descendants via nested set

## Why These Choices

**LiveView over SPA**: the entire value of this console is real-time
visibility. LiveView gives us server-push for free via PubSub. No REST
API to build, no client state to sync, no WebSocket protocol to design.
Every threat, DLP block, and heartbeat pushes to the browser the moment
it arrives.

**PostgreSQL over ClickHouse/TimescaleDB**: for a self-hosted open source
tool, Postgres is the right default. Partitioning + indexes handle the
event volume for single-team deployments (hundreds of agents, millions of
events/day). If someone needs more scale, TimescaleDB is a drop-in
extension on the same Postgres.

**gRPC over HTTP/REST**: the agent already has `tonic` in its dependency
tree. gRPC gives us streaming (critical for event ingestion), protobuf
(compact wire format), and mTLS (built-in). The Elixir side uses the
`grpc` package which handles HTTP/2 framing.

**Oban for background jobs**: partition creation, stale agent marking,
alert webhook dispatch, and retention cleanup are all background jobs.
Oban gives us reliable execution with retry, uniqueness, and scheduling
without needing Redis.

## Process Architecture

```
                          ┌─────────────────────────────────┐
                          │        Phoenix Endpoint          │
                          │    (HTTP + LiveView WebSocket)   │
                          └────────────┬────────────────────┘
                                       │
                          ┌────────────┴────────────────────┐
                          │         Phoenix PubSub           │
                          │     (in-memory, single node)     │
                          └──┬─────────┬──────────┬─────────┘
                             │         │          │
                    ┌────────┴──┐  ┌───┴────┐  ┌──┴────────┐
                    │ LiveView  │  │LiveView│  │ LiveView   │
                    │ Dashboard │  │Threats │  │ DLP       │
                    └───────────┘  └────────┘  └───────────┘
                                       ▲
                                       │ broadcast
                                       │
┌──────────────────────────────────────┴──────────────────────┐
│                      gRPC Server                            │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ EventIngester│  │ThreatHandler │  │  DlpHandler      │  │
│  │ (batched)    │  │ (immediate)  │  │  (immediate)     │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘  │
│         │                 │                    │             │
│         ▼                 ▼                    ▼             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              PostgreSQL (Ecto)                        │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐                         │
│  │HeartbeatLoop │  │CommandStream │                         │
│  │ (per-agent)  │  │ (per-agent)  │                         │
│  └──────────────┘  └──────────────┘                         │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│                      Oban Workers                            │
│                                                              │
│  PartitionManager  StaleAgentChecker  AlertDispatcher       │
│  RetentionCleaner  VulnAggregator                           │
└──────────────────────────────────────────────────────────────┘
```

## Contexts (Elixir Modules)

| Context | Responsibility |
|---|---|
| `Riggs.Fleet` | Agent CRUD, health tracking, enrollment |
| `Riggs.Telemetry` | Event ingestion, queries, throughput stats |
| `Riggs.Detection` | Threats, storylines, triage workflow |
| `Riggs.Dlp` | DLP events, policy management, stats |
| `Riggs.Response` | Response action audit trail, command dispatch |
| `Riggs.Vuln` | Vulnerability findings, scan tracking |
| `Riggs.DeviceControl` | Device events, USB/BT policy |
| `Riggs.Discovery` | Network hosts, network maps |
| `Riggs.Policy` | Policy CRUD, versioning, agent-policy mapping |
| `Riggs.Accounts` | Users, authentication, roles |
| `Riggs.Audit` | Audit log |
| `Riggs.Grpc` | gRPC server, handlers, stream management |
| `Riggs.Alerts` | Webhook dispatch (Slack, PagerDuty, email) |

## Event Ingestion Flow

```
Agent gRPC StreamEvents
    │
    ▼
Riggs.Grpc.EventIngester
    │
    │  1. Decode protobuf batch
    │  2. Validate agent_id (from mTLS cert)
    │  3. Batch insert into events table (Ecto.insert_all)
    │  4. Update agent.events_processed counter
    │  5. Broadcast high-severity events to PubSub
    │
    ▼
PostgreSQL events table
    │
    ▼ (for severity > info)
Phoenix.PubSub.broadcast("agent:#{id}", {:event, event})
```

Only events above `info` severity are broadcast to avoid flooding LiveView
processes. The event explorer page queries the DB directly (not PubSub).

## Command Dispatch Flow

```
Admin clicks "Kill Process" on threat detail page
    │
    ▼
LiveView handle_event("kill_process", %{"pid" => pid})
    │
    │  1. Insert response_action record (audit trail)
    │  2. Lookup agent's command stream
    │  3. Push KillProcess command to stream
    │  4. Broadcast to PubSub for UI update
    │
    ▼
Riggs.Grpc.CommandDispatcher
    │
    │  Sends AgentCommand over the agent's CommandStream
    │
    ▼
Agent receives command, executes, sends CommandAck
    │
    ▼
Riggs.Grpc.CommandDispatcher
    │
    │  1. Update response_action record (success/failure)
    │  2. Broadcast ack to PubSub
    │
    ▼
LiveView receives {:command_ack, ack} and updates UI
```

## Deployment

Single binary release via `mix release`. Ships with:
- Phoenix endpoint (HTTP on port 4000)
- gRPC server (HTTP/2 on port 4001)
- Oban job runner
- Migrations

```
# Production
MIX_ENV=prod mix release
_build/prod/rel/riggs_console/bin/riggs_console start

# Requires:
# - PostgreSQL 16+
# - DATABASE_URL env var
# - SECRET_KEY_BASE env var
# - GRPC_PORT env var (default 4001)
```

## Scale Considerations

For a self-hosted open source tool, the target is:
- 1-500 agents
- 1M-50M events/day
- Single Phoenix node, single Postgres instance

If someone needs more:
- Events table partitioning already handles time-range queries efficiently
- Event ingestion can be parallelized across multiple EventIngester processes
- PubSub can be swapped to Phoenix.PubSub.PG2 for multi-node
- Read replicas for event queries vs write primary for ingestion

# Riggs: Data Layer

## Overview

Riggs stores all persistent data locally using redb, an embedded key-value
store written in Rust. There is no external database dependency. The store
runs as a single-writer task in the daemon, receiving writes via an mpsc
channel and serving reads via synchronous methods called by the CLI and
shell interfaces.

All store logic lives in `riggs-store`.

## Why redb

redb was chosen over alternatives for specific reasons:

- **Pure Rust**: No C dependencies, no FFI, reproducible builds.
- **ACID transactions**: Crash-safe writes with automatic recovery.
- **Zero-copy reads**: Memory-mapped values avoid deserialization for lookups.
- **Single-writer, multi-reader**: Matches our architecture (one store task
  writes, CLI and shell read).
- **Embedded**: No server process. The database is a single file.
- **Small footprint**: ~200 KB of compiled code.

Alternatives considered:
- SQLite (via rusqlite): Good but adds C dependency, more overhead for our
  simple access patterns.
- sled: Abandoned/unmaintained, known data loss bugs.
- RocksDB: C++ dependency, complex configuration, overkill for our needs.

## Database File

The database lives at `/var/lib/riggs/riggs.db` (system mode) or
`~/.local/share/riggs/riggs.db` (user mode). The file is created on first
run.

Typical sizes:
- Fresh install: ~100 KB
- After 1 day of normal use: ~10-50 MB
- After 7 days (default retention): ~100-500 MB
- Maximum (with aggressive retention): configurable, default cap at 2 GB

## Table Definitions

### events

Primary event storage. Every normalized event that passes through the engine
is persisted here.

```rust
const EVENTS_TABLE: TableDefinition<&[u8; 16], &[u8]> =
    TableDefinition::new("events");
```

- **Key**: UUIDv7 bytes (16 bytes). Since UUIDv7 is time-ordered, keys are
  naturally sorted chronologically.
- **Value**: Zstd-compressed JSON of `EventEnvelope`.

#### Index Tables

redb does not support secondary indexes natively. We maintain manual index
tables for common query patterns:

```rust
// Index: storyline_id → list of event_ids
const EVENTS_BY_STORYLINE: TableDefinition<&[u8; 16], &[u8]> =
    TableDefinition::new("events_by_storyline");

// Index: event_type + timestamp → event_id (for type-filtered time queries)
const EVENTS_BY_TYPE: TableDefinition<&[u8], &[u8; 16]> =
    TableDefinition::new("events_by_type");

// Index: process pid + timestamp → event_id
const EVENTS_BY_PID: TableDefinition<&[u8], &[u8; 16]> =
    TableDefinition::new("events_by_pid");
```

The `events_by_storyline` value is a serialized `Vec<Uuid>` (list of event
IDs belonging to the storyline). This is updated append-only: when a new
event joins a storyline, we read the existing list, append, and write back.
This is efficient because storylines rarely exceed 10,000 events.

The `events_by_type` key is a composite of `event_type_id (u8) + timestamp
(i64 millis)`, giving us efficient time-range queries filtered by type.

### verdicts

Stores detection verdicts for files and storylines.

```rust
const VERDICTS_TABLE: TableDefinition<&[u8; 16], &[u8]> =
    TableDefinition::new("verdicts");
```

- **Key**: Verdict UUID (16 bytes).
- **Value**: Zstd-compressed JSON of `Verdict`.

#### Verdict Index

```rust
// Index: file SHA-256 hash → verdict_id (for verdict cache lookups)
const VERDICTS_BY_HASH: TableDefinition<&[u8; 32], &[u8; 16]> =
    TableDefinition::new("verdicts_by_hash");

// Index: storyline_id → list of verdict_ids
const VERDICTS_BY_STORYLINE: TableDefinition<&[u8; 16], &[u8]> =
    TableDefinition::new("verdicts_by_storyline");

// Index: disposition (u8) + timestamp → verdict_id
const VERDICTS_BY_DISPOSITION: TableDefinition<&[u8], &[u8; 16]> =
    TableDefinition::new("verdicts_by_disposition");
```

The `verdicts_by_hash` table serves as the verdict cache. When a file is
encountered, the engine first checks this table. If a verdict exists and has
not expired, the cached verdict is returned without re-running the pipeline.

### quarantine_metadata

Tracks quarantined files and their vault locations.

```rust
const QUARANTINE_TABLE: TableDefinition<&[u8; 16], &[u8]> =
    TableDefinition::new("quarantine_metadata");
```

- **Key**: Quarantine UUID (16 bytes).
- **Value**: JSON of `QuarantineRecord`.

Not compressed because records are small (~500 bytes each) and need fast
random access for restore operations.

#### Quarantine Indexes

```rust
// Index: original file path (UTF-8 bytes) → quarantine_id
const QUARANTINE_BY_PATH: TableDefinition<&str, &[u8; 16]> =
    TableDefinition::new("quarantine_by_path");

// Index: file hash → quarantine_id
const QUARANTINE_BY_HASH: TableDefinition<&[u8; 32], &[u8; 16]> =
    TableDefinition::new("quarantine_by_hash");
```

### config

Stores runtime configuration and agent state.

```rust
const CONFIG_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("config");
```

- **Key**: Config key string (e.g., `"agent_id"`, `"encryption_key"`,
  `"last_cloud_sync"`).
- **Value**: JSON-serialized config value.

Well-known config keys:

| Key                    | Type      | Description                          |
|------------------------|-----------|--------------------------------------|
| agent_id               | Uuid      | Persistent agent identifier          |
| encryption_key         | [u8; 32]  | AES-256 key for quarantine vault     |
| agent_version          | String    | Current agent version                |
| last_cloud_sync        | DateTime  | Last successful cloud sync timestamp |
| install_timestamp      | DateTime  | When the agent was first installed   |
| schema_version         | u32       | Database schema version for migrations|

### rule_state

Persists state for STAR behavioral rules (active state machines that survive
daemon restarts).

```rust
const RULE_STATE_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("rule_state");
```

- **Key**: Composite of `rule_id + storyline_id` (variable length).
- **Value**: Serialized `StarMachine` state.

State machines are checkpointed every 10 seconds. On daemon restart, active
machines are restored from this table and continue matching from their last
state.

### response_audit

Audit trail for all response actions.

```rust
const RESPONSE_AUDIT_TABLE: TableDefinition<&[u8; 16], &[u8]> =
    TableDefinition::new("response_audit");
```

- **Key**: Audit entry UUID (16 bytes).
- **Value**: JSON of `ResponseAuditEntry`.

#### Audit Indexes

```rust
// Index: storyline_id → list of audit_ids
const AUDIT_BY_STORYLINE: TableDefinition<&[u8; 16], &[u8]> =
    TableDefinition::new("audit_by_storyline");

// Index: action_type (u8) + timestamp → audit_id
const AUDIT_BY_ACTION: TableDefinition<&[u8], &[u8; 16]> =
    TableDefinition::new("audit_by_action");
```

### storylines

Persists storyline metadata and graph structure.

```rust
const STORYLINES_TABLE: TableDefinition<&[u8; 16], &[u8]> =
    TableDefinition::new("storylines");
```

- **Key**: Storyline UUID (16 bytes).
- **Value**: Zstd-compressed JSON of `Storyline`.

## Compression

Event payloads are compressed with zstd before storage. Compression settings:

```rust
const ZSTD_COMPRESSION_LEVEL: i32 = 3; // fast compression, ~3:1 ratio
const COMPRESSION_THRESHOLD: usize = 256; // don't compress payloads smaller than 256 bytes
```

Level 3 provides a good balance: ~3:1 compression ratio with negligible CPU
overhead (~50 MB/s compression speed on a single core). Higher levels provide
marginally better ratios but significantly slower compression.

### Compression Performance

| Content Type | Avg Size (raw) | Avg Size (zstd) | Ratio | Compress Time |
|--------------|---------------|-----------------|-------|---------------|
| ProcessEvent | 800 bytes     | 280 bytes       | 2.9:1 | 5 us          |
| FileEvent    | 500 bytes     | 180 bytes       | 2.8:1 | 3 us          |
| NetworkEvent | 400 bytes     | 150 bytes       | 2.7:1 | 3 us          |
| Verdict      | 1200 bytes    | 350 bytes       | 3.4:1 | 8 us          |
| Storyline    | 5000 bytes    | 1100 bytes      | 4.5:1 | 15 us         |

## Retention Policies

Events and verdicts are subject to configurable retention policies. Expired
data is deleted by a background compaction task.

### Configuration

```toml
[store.retention]
events_days = 7           # delete events older than 7 days
verdicts_days = 30        # keep verdicts longer for cache
quarantine_days = 30      # quarantine vault retention
audit_days = 90           # keep audit trail for compliance
storylines_days = 14      # completed storylines
rule_state_days = 1       # expired state machines
max_db_size_mb = 2048     # hard cap on database file size
```

### Compaction

The compaction task runs every hour (configurable). It:

1. Scans each table for entries older than the configured retention.
2. Deletes expired entries in batches of 1000 per transaction to avoid
   long-running transactions.
3. Deletes corresponding index entries.
4. If `max_db_size_mb` is exceeded even after retention deletion, it
   aggressively deletes the oldest entries regardless of retention policy.
5. Calls `redb::Database::compact()` to reclaim freed pages.

### Size Monitoring

The store task periodically reports database size metrics:

```rust
pub struct StoreMetrics {
    pub db_file_size_bytes: u64,
    pub event_count: u64,
    pub verdict_count: u64,
    pub quarantine_count: u64,
    pub storyline_count: u64,
    pub oldest_event: Option<DateTime<Utc>>,
    pub newest_event: Option<DateTime<Utc>>,
}
```

## Write Path

All writes go through the store task via an mpsc channel:

```rust
pub enum StoreCommand {
    WriteEvent(EventEnvelope),
    WriteVerdict(Verdict),
    WriteQuarantineRecord(QuarantineRecord),
    WriteResponseAudit(ResponseAuditEntry),
    WriteStoryline(Storyline),
    WriteConfig(String, serde_json::Value),
    WriteRuleState(String, Uuid, StarMachine),
    DeleteQuarantine(Uuid),
    Compact,
}
```

The store task processes commands sequentially from the channel:

```rust
async fn store_task(
    db: Database,
    mut rx: mpsc::Receiver<StoreCommand>,
    shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            cmd = rx.recv() => {
                match cmd {
                    Some(StoreCommand::WriteEvent(event)) => {
                        let txn = db.begin_write().unwrap();
                        write_event(&txn, &event);
                        update_event_indexes(&txn, &event);
                        txn.commit().unwrap();
                    }
                    // ... other commands
                    None => break,
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    // Drain remaining commands
                    while let Ok(cmd) = rx.try_recv() {
                        process_command(&db, cmd);
                    }
                    break;
                }
            }
        }
    }
}
```

### Write Batching

Under high event volume, individual transactions per event are inefficient.
The store task batches writes when the channel has multiple pending commands:

```rust
fn drain_batch(rx: &mut mpsc::Receiver<StoreCommand>, max_batch: usize) -> Vec<StoreCommand> {
    let mut batch = Vec::with_capacity(max_batch);
    while batch.len() < max_batch {
        match rx.try_recv() {
            Ok(cmd) => batch.push(cmd),
            Err(_) => break,
        }
    }
    batch
}
```

A batch of up to 256 events is written in a single transaction, reducing
fsync overhead from O(n) to O(1).

## Read Path

Reads are served synchronously by acquiring a read transaction. redb supports
concurrent readers without blocking the writer.

```rust
pub struct StoreReader {
    db: Arc<Database>,
}

impl StoreReader {
    pub fn get_event(&self, event_id: Uuid) -> Result<Option<EventEnvelope>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(EVENTS_TABLE)?;
        match table.get(event_id.as_bytes())? {
            Some(value) => {
                let decompressed = zstd::decode_all(value.value())?;
                let event: EventEnvelope = serde_json::from_slice(&decompressed)?;
                Ok(Some(event))
            }
            None => Ok(None),
        }
    }

    pub fn query_events(
        &self,
        filter: EventFilter,
    ) -> Result<Vec<EventEnvelope>, StoreError> {
        let txn = self.db.begin_read()?;

        match filter {
            EventFilter::TimeRange { start, end } => {
                let table = txn.open_table(EVENTS_TABLE)?;
                let start_key = uuid_from_timestamp(start);
                let end_key = uuid_from_timestamp(end);
                let range = table.range(start_key.as_bytes()..end_key.as_bytes())?;
                collect_events(range)
            }
            EventFilter::Storyline { storyline_id } => {
                let index = txn.open_table(EVENTS_BY_STORYLINE)?;
                let event_ids = get_event_ids(&index, storyline_id)?;
                let table = txn.open_table(EVENTS_TABLE)?;
                lookup_events(&table, &event_ids)
            }
            EventFilter::Type { event_type, start, end } => {
                let index = txn.open_table(EVENTS_BY_TYPE)?;
                let prefix = make_type_prefix(event_type, start, end);
                let range = index.range(prefix.clone()..)?;
                collect_from_index(range, &txn)
            }
        }
    }
}
```

### Query Interface

The CLI and remote shell query events through a structured filter API:

```rust
pub enum EventFilter {
    TimeRange { start: DateTime<Utc>, end: DateTime<Utc> },
    Storyline { storyline_id: Uuid },
    Type { event_type: EventType, start: DateTime<Utc>, end: DateTime<Utc> },
    Pid { pid: u32, start: DateTime<Utc>, end: DateTime<Utc> },
    Combined(Vec<EventFilter>), // AND of multiple filters
}
```

CLI usage examples:

```
riggs events list --since "1h ago" --type process
riggs events show <event_id>
riggs storyline show <storyline_id> --with-events
riggs verdicts list --disposition malicious --since "24h ago"
riggs audit list --action quarantine --since "7d ago"
```

## Schema Migrations

The `schema_version` config key tracks the current database schema. On daemon
startup, if the schema version is less than the code's expected version, a
migration runs.

```rust
pub fn migrate(db: &Database, from_version: u32, to_version: u32) -> Result<(), StoreError> {
    for version in from_version..to_version {
        match version {
            0 => migrate_v0_to_v1(db)?,
            1 => migrate_v1_to_v2(db)?,
            _ => return Err(StoreError::UnknownSchemaVersion(version)),
        }
    }
    set_schema_version(db, to_version)?;
    Ok(())
}
```

Migrations are forward-only. There is no downgrade path. If a migration fails,
the daemon logs the error and refuses to start (fail-fast).

## Corruption Recovery

If redb detects corruption on open (checksum mismatch, invalid page), the
store enters recovery mode:

1. Rename the corrupted database to `riggs.db.corrupt.<timestamp>`.
2. Create a fresh database.
3. Log a CRITICAL alert.
4. Continue operating with an empty database.

Quarantine vault files on disk are not affected by database corruption. A
recovery tool (`riggs store recover`) can scan the vault directory and rebuild
quarantine metadata from vault file headers.

## Metrics

- `riggs_store_writes_total` — counter per table
- `riggs_store_reads_total` — counter per table
- `riggs_store_write_batch_size` — histogram
- `riggs_store_write_latency_us` — histogram per table
- `riggs_store_read_latency_us` — histogram per table
- `riggs_store_db_size_bytes` — gauge
- `riggs_store_compaction_duration_ms` — histogram
- `riggs_store_compaction_deleted_total` — counter per table

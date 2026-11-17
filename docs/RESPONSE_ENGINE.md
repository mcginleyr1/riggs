# Riggs: Response Engine

## Overview

The response engine executes protective actions when the detection pipeline
identifies a threat. It receives `ResponseAction` messages from the engine
via an mpsc channel and executes them on the local system. Every action is
policy-driven, auditable, and reversible where possible.

The response engine lives in `riggs-response` and runs as a supervised task
in the daemon.

## Response Actions

### ProcessKill

Terminates a process immediately via `SIGKILL` (Unix) or `TerminateProcess`
(Windows).

```rust
pub struct ProcessKill {
    pub pid: u32,
    pub signal: KillSignal,
    pub storyline_id: Uuid,
    pub reason: String,
}

pub enum KillSignal {
    SigKill, // immediate, non-catchable
    SigTerm, // graceful, catchable (used as first attempt if policy allows)
}
```

**Execution flow:**

1. Verify the target pid still exists and matches the expected executable
   path (prevent TOCTOU race where the pid has been reused).
2. If policy allows graceful termination, send SIGTERM and wait up to 5
   seconds.
3. If the process is still alive (or policy requires immediate kill), send
   SIGKILL.
4. Verify the process is gone via `waitpid` or `/proc` check.
5. Also kill all child processes in the process group if
   `kill_children: true` in policy.
6. Log the action to the audit trail.

**Failure modes:**

- Process already exited: Success (idempotent).
- Permission denied: Escalate to CRITICAL alert. The daemon runs as root, so
  this should not happen in normal operation.
- Pid reuse race: If the executable path does not match, abort and log an error.

### ProcessSuspend

Suspends a process via `SIGSTOP` (Unix), preserving its state for
investigation.

```rust
pub struct ProcessSuspend {
    pub pid: u32,
    pub storyline_id: Uuid,
    pub reason: String,
    pub duration: Option<Duration>, // auto-resume after duration, or None for manual
}
```

**Execution flow:**

1. Verify pid and executable path match.
2. Send `SIGSTOP` to the process and all members of its process group.
3. If `duration` is set, spawn a timer task that will send `SIGCONT` after
   the duration expires.
4. The suspended process remains in memory, allowing forensic examination of
   `/proc/[pid]/maps`, file descriptors, and network connections.
5. Log the action.

### FileQuarantine

Moves a malicious file to an encrypted quarantine vault, preventing execution
while preserving evidence.

```rust
pub struct FileQuarantine {
    pub source_path: PathBuf,
    pub file_hash: FileHash,
    pub storyline_id: Uuid,
    pub reason: String,
}
```

**Quarantine vault design:**

The vault is a directory at `/var/lib/riggs/quarantine/` (configurable). Each
quarantined file is:

1. Copied to the vault with a UUID filename (no original name preserved in
   the filesystem to prevent accidental execution).
2. Encrypted with AES-256-GCM using a key derived from the agent's local
   secret (stored in the redb config table, generated at first run).
3. The original file is overwritten with zeros, then deleted (`unlink`).
4. Metadata is stored in the quarantine_metadata redb table:

```rust
pub struct QuarantineRecord {
    pub quarantine_id: Uuid,
    pub original_path: PathBuf,
    pub original_permissions: u32,
    pub original_owner: (u32, u32), // uid, gid
    pub file_hash: FileHash,
    pub file_size: u64,
    pub quarantined_at: DateTime<Utc>,
    pub reason: String,
    pub storyline_id: Uuid,
    pub vault_path: PathBuf,
    pub can_restore: bool,
}
```

**Restore procedure:**

An administrator can restore a quarantined file via the CLI:

```
riggs quarantine restore <quarantine_id>
```

This decrypts the file from the vault, places it back at the original path
with original permissions and ownership, and deletes the vault copy. A restore
event is logged.

**Vault maintenance:**

Quarantined files are retained for a configurable period (default 30 days).
After expiration, the vault file is securely deleted (overwrite + unlink) and
the metadata record is marked as `expired`.

### FileDelete

Permanently deletes a malicious file without quarantine. Used for files that
are clearly malicious and have no forensic value (e.g., known commodity
malware).

```rust
pub struct FileDelete {
    pub path: PathBuf,
    pub file_hash: FileHash,
    pub storyline_id: Uuid,
    pub secure: bool, // if true, overwrite before unlink
}
```

When `secure` is true, the file content is overwritten with random bytes
before unlinking. This prevents recovery from filesystem journaling or
disk forensics. When false, a simple `unlink` is performed.

### NetworkContain

Isolates the host from the network, allowing only connections to the
management server.

```rust
pub struct NetworkContain {
    pub mode: ContainmentMode,
    pub storyline_id: Uuid,
    pub reason: String,
    pub allowed_endpoints: Vec<SocketAddr>, // management server(s)
}

pub enum ContainmentMode {
    Full,       // drop all traffic except allowed_endpoints
    Partial,    // drop outbound to non-RFC1918, allow local network
    DnsOnly,    // block all except DNS (for investigation)
}
```

**Implementation:**

- **macOS**: Uses `pfctl` to install packet filter rules. A dedicated anchor
  `com.riggs.containment` is created so rules can be cleanly removed.
- **Linux**: Uses `iptables` (or `nftables` where available) to install
  DROP rules with exceptions for allowed endpoints.
- **Windows**: Uses Windows Filtering Platform (WFP) API.

**Containment rules example (macOS pf):**

```
anchor "com.riggs.containment" {
    block drop all
    pass quick proto tcp from any to 10.0.0.1 port 443  # management server
    pass quick proto tcp from 10.0.0.1 port 443 to any
    pass quick on lo0 all  # allow loopback
}
```

**Removal:**

Containment is removed via CLI command or by a policy update from the
management server:

```
riggs contain release
```

This flushes the `com.riggs.containment` anchor.

### Rollback

Reverts filesystem changes made by a malicious process using filesystem
snapshots.

```rust
pub struct Rollback {
    pub storyline_id: Uuid,
    pub target_paths: Vec<PathBuf>,
    pub snapshot_id: Option<Uuid>,
    pub reason: String,
}
```

**Snapshot mechanism:**

Riggs maintains lightweight filesystem snapshots using a copy-on-write
approach for monitored directories:

1. When a process under a suspicious storyline modifies a file, the
   response engine (if preemptive rollback is enabled) copies the original
   file content to a snapshot store before the modification completes.
2. Snapshots are stored in `/var/lib/riggs/snapshots/` with zstd compression.
3. Each snapshot records the file path, original content hash, and the
   storyline that triggered the snapshot.

On macOS, APFS snapshots can also be leveraged as a heavier-weight
alternative via `tmutil localsnapshot`.

**Current implementation:** `riggs_response::SnapshotStore` takes a snapshot
when a process in a storyline already scored as a threat *opens* a file
(`[response] preemptive_snapshots`, `snapshot_path`, `snapshot_max_file_mib`,
`snapshot_retention_hours`). Policy `Rollback` actions without a
`storyline_id` target the detection's storyline; the default Malicious rules
end with one. This needs a sensor that reports process-attributed `Open`
events. The current macOS and Linux file sensors are `notify`-based and emit
unattributed Create/Modify/Delete only, so no snapshots are taken until such a
sensor (Endpoint Security, fanotify) lands.

**Rollback execution:**

1. For each target path, look up the most recent pre-modification snapshot.
2. Verify the current file content differs from the snapshot (the malware
   actually changed something).
3. Replace the current file with the snapshot content.
4. Restore original permissions and ownership.
5. Delete the snapshot.
6. Log the rollback action.

## Policy Engine

The policy is built into the daemon (`ResponsePolicy` in
`crates/riggs-response/src/policy.rs`). There are no policy files and no
approval queue: an action either runs, is recorded as not run, or is refused.
The `[response]` table of `riggs.toml` shapes the policy.

### Rules

The first rule whose threat level and conditions match the verdict selects
the actions; the rest are not consulted.

| Verdict | Condition | Actions |
|---|---|---|
| Malicious | a verdict with confidence 0.95 or more | kill the acting process, quarantine the file, roll back the storyline |
| Malicious | none | quarantine the file, roll back the storyline |
| Suspicious | none | none |

An action whose target cannot be resolved is dropped: no kill without a pid
above 1 (and never the daemon's own), no quarantine without a file path.

### Configuration

```toml
[response]
mode = "record"                # "off", "record" or "act"
kill_on_critical = true        # false removes the kill action from the rules
quarantine_on_malicious = true # false removes the quarantine action from the rules
# protected_processes = [...]  # unset: the built-in list for this platform
```

`mode` has three values:

- `off`: detections are not evaluated and nothing is recorded.
- `record`: the rules are evaluated and each action they select is stored
  with the outcome `recorded only`. Nothing runs. This is the shipped value,
  for judging what the rules would do before letting them act.
- `act`: the actions run, and each is stored with its result.

`auto_respond` no longer exists. A file that still contains it fails to load,
and so does any other unknown key in `[response]`.

`kill_on_critical` and `quarantine_on_malicious` each remove one action from
the rules. They do not change the other action or the verdict.

### Protected processes

`protected_processes` lists executable paths that kill and suspend never
target. An entry starting with `/` must equal the acting process's path. An
entry without one matches any process with that name or executable file
name, which a malicious process can claim for itself, so prefer full paths.

Left unset, the list is the built-in one for the platform: on macOS launchd,
WindowServer and loginwindow; on Linux systemd, systemd-logind, sshd,
dbus-daemon, dpkg and rpm (both `/usr/lib` and `/lib` paths for systemd). Each
is a process whose death ends the session or the machine, or that leaves the
system half-installed; the comments in `crates/riggs-types/src/config.rs` say
why. Setting the key replaces the whole list.

Kill and suspend are also refused, whatever the list says, when:

- the process's path is empty or `unknown` (the sensor could not identify it,
  so no path list can match it), and
- the event is a process exit (the process is gone and its pid may belong to
  something else by now).

Each refusal is stored with the outcome `refused` and the reason in `detail`.
Protection concerns the acting process only. A file in a protected
executable's path is still quarantined.

### Snapshots

Preemptive snapshots (`preemptive_snapshots`) exist only so Rollback can
restore files, and Rollback only runs in `act` mode, so files are copied only
in `act` mode. The time-based prune of old snapshots runs in every mode.

## Response records

Every action the rules select is stored in the `response_log` table in redb
(`RiggsStore::store_response_record`), pruned with the rest of the telemetry:

| Field | Meaning |
|---|---|
| `executed_at` | when the action was decided |
| `event_id` | the detection the action answers (the id `riggs threats` shows) |
| `action_description` | the action and its target, e.g. `Kill process (PID 42)` |
| `outcome` | `executed`, `recorded only`, `refused` or `failed` |
| `detail` | `ok`, the reason for a refusal, or the error of a failure |

`riggs threats` prints the records under the threat they answer, so after a
trial in `record` mode it shows what the daemon would have done to each
detection. A threat with no record had no action selected, or was detected in
`off` mode.

## Concurrency and Ordering

Response actions execute sequentially within a storyline (a process kill must
complete before file quarantine for the same storyline) but concurrently across
different storylines. This is implemented with a per-storyline queue inside the
response task.

If multiple response actions arrive for the same storyline simultaneously, they
are deduplicated:

- Only one ProcessKill per pid.
- Only one FileQuarantine per file path.
- NetworkContain is singleton (only one containment at a time).

## Error Handling

The response engine follows fail-fast principles:

- If a ProcessKill fails for a non-transient reason (e.g., pid reuse detected),
  it does not retry. It logs the failure and moves on.
- If FileQuarantine fails due to disk space, it falls back to FileDelete.
- If NetworkContain fails (e.g., pf not available), it logs a CRITICAL alert
  and attempts a fallback of killing all suspicious processes instead.
- Every failure is recorded in the audit trail.

The response engine never panics on action failure. It returns errors to the
supervisor, which may trigger escalation policies.

## Metrics

- `riggs_response_actions_total` — counter per action type per outcome
- `riggs_response_latency_ms` — histogram per action type
- `riggs_quarantine_vault_size_bytes` — gauge
- `riggs_quarantine_file_count` — gauge
- `riggs_containment_active` — boolean gauge

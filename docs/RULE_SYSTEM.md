# Riggs: Rule System

## Overview

The rule system provides deterministic, human-authored threat detection that
complements the probabilistic ML models. Rules are transparent, auditable,
and instantly deployable — an operator can write a new rule and have it active
within seconds via hot-reload.

Three rule types are supported:

1. **YARA-X rules** — content-based pattern matching on file bytes
2. **IOC rules** — indicator matching against hashes, IPs, and domains
3. **STAR rules** — behavioral pattern matching as state machines

All rule logic lives in `riggs-rules`. Rules are loaded from disk, compiled
into efficient matching structures, and published to the engine via a
`tokio::sync::watch` channel.

## Directory Layout

```
rules/
  default/           # shipped with Riggs, updated by vendor
    yara/
      malware_generic.yar
      ransomware.yar
      persistence.yar
      credential_access.yar
      ...
    ioc/
      hashes.ioc
      ips.ioc
      domains.ioc
    star/
      shell_download_exec.star
      reverse_shell.star
      crypto_miner.star
      ...
  custom/            # operator-created rules
    yara/
    ioc/
    star/
```

Default rules are read-only in production (owned by root, mode 0644). Custom
rules are writable by the riggs admin group.

## YARA-X Rules

### Format

Standard YARA rule syntax, compiled by the `yara-x` crate:

```yara
rule Suspicious_Packed_Binary {
    meta:
        id = "RIGGS-YARA-001"
        description = "Detects packed or encrypted binaries with high entropy"
        severity = "medium"
        mitre = "T1027"
        author = "riggs-team"
        created = "2026-01-15"

    strings:
        $upx = "UPX!" ascii
        $mpress = ".MPRESS" ascii
        $packed_section = ".packed" ascii

    condition:
        uint32(0) == 0xfeedface or  // Mach-O magic
        uint32(0) == 0xfeedfacf or  // Mach-O 64 magic
        uint32(0) == 0xcafebabe     // Mach-O fat magic
        and (
            $upx or $mpress or $packed_section or
            math.entropy(0, filesize) > 7.2
        )
}

rule Malicious_Dylib_Hijack {
    meta:
        id = "RIGGS-YARA-002"
        description = "Detects dylib files in unusual locations"
        severity = "high"
        mitre = "T1574.004"

    strings:
        $lc_id_dylib = { 0C 00 00 00 }  // LC_ID_DYLIB
        $suspicious_rpath = "/tmp/" ascii
        $suspicious_rpath2 = "/var/tmp/" ascii
        $suspicious_rpath3 = "/Users/Shared/" ascii

    condition:
        $lc_id_dylib and any of ($suspicious_rpath*)
}
```

### Required Metadata Fields

Every YARA rule must include these meta fields:

| Field       | Type     | Required | Description                           |
|-------------|----------|----------|---------------------------------------|
| id          | string   | yes      | Unique rule identifier (RIGGS-YARA-*) |
| description | string   | yes      | Human-readable description            |
| severity    | string   | yes      | none, low, medium, high, critical     |
| mitre       | string   | no       | MITRE ATT&CK technique ID            |
| author      | string   | no       | Rule author                           |
| created     | string   | no       | ISO date of creation                  |
| enabled     | boolean  | no       | Default true. Set false to disable.   |

### Compilation

YARA rules are compiled into a single `yara_x::Rules` object at startup:

```rust
pub struct CompiledYaraRules {
    pub rules: yara_x::Rules,
    pub metadata: HashMap<String, YaraRuleMeta>,
    pub compiled_at: DateTime<Utc>,
    pub rule_count: usize,
    pub source_hash: [u8; 32], // SHA-256 of all source files concatenated
}
```

Compilation takes all `.yar` files from both `default/yara/` and `custom/yara/`,
concatenates them (with error tracking per file), and compiles once. If any
single file has a syntax error, that file is skipped and the error is logged;
the remaining rules still compile.

### Matching

When a file enters the detection pipeline, YARA matching runs against the
file's content:

```rust
pub fn scan_file(
    rules: &yara_x::Rules,
    file_path: &Path,
) -> Result<Vec<YaraMatch>, RuleError> {
    let scanner = yara_x::Scanner::new(rules);
    let results = scanner.scan_file(file_path)?;

    results
        .matching_rules()
        .map(|rule| YaraMatch {
            rule_id: rule.identifier().to_string(),
            meta: extract_meta(rule),
            matched_strings: extract_strings(rule),
        })
        .collect()
}
```

YARA scanning is CPU-bound. Files larger than a configurable maximum (default
100 MB) are skipped. Scanning is time-bounded to 30 seconds per file.

## IOC Rules

### Format

IOC files are newline-delimited text with a type prefix:

```
# Hashes - known malicious file hashes
sha256:a1b2c3d4e5f6...
sha256:dead0000beef...
md5:d41d8cd98f00b204e9800998ecf8427e

# IP addresses - C2 infrastructure
ip:198.51.100.1
ip:203.0.113.42
cidr:192.0.2.0/24

# Domains - malicious domains
domain:evil-c2.example.com
domain:*.malware-domain.example.net

# URLs - specific malicious URLs
url:http://example.com/malware/payload.bin
```

Lines starting with `#` are comments. Empty lines are ignored.

### Compilation

IOC indicators are compiled into an Aho-Corasick automaton for O(n) matching
regardless of the number of patterns:

```rust
pub struct CompiledIOCRules {
    pub hash_set: HashSet<String>,          // exact hash lookups
    pub ip_set: HashSet<IpAddr>,            // exact IP lookups
    pub cidr_set: Vec<IpNet>,               // CIDR range checks
    pub domain_automaton: AhoCorasick,      // multi-pattern string matching
    pub url_automaton: AhoCorasick,         // multi-pattern string matching
    pub indicator_count: usize,
    pub compiled_at: DateTime<Utc>,
}
```

Hashes and IPs use `HashSet` for O(1) exact lookup. Domains and URLs use
Aho-Corasick for substring/pattern matching in event fields.

### Matching Pipeline

IOC matching runs against different event fields depending on the indicator
type:

| IOC Type | Matched Against                                    |
|----------|----------------------------------------------------|
| sha256   | FileEvent file_hash, ProcessEvent executable hash  |
| md5      | FileEvent file_hash (if MD5 computed)              |
| ip       | NetworkEvent remote_addr                           |
| cidr     | NetworkEvent remote_addr                           |
| domain   | DNSEvent query_name, NetworkEvent correlated domain|
| url      | ProcessEvent command_line, FileEvent path (scripts)|

### IOC Severity

An IOC match is always treated as `High` severity by default. An optional
severity field can be appended to any indicator:

```
sha256:abc123...:critical
ip:198.51.100.1:high
domain:suspicious.example.com:medium
```

### IOC Sources

Riggs supports multiple IOC sources:

1. **Shipped lists**: Bundled in `rules/default/ioc/`, updated with releases.
2. **Custom lists**: Added by operators to `rules/custom/ioc/`.
3. **STIX/TAXII feed** (future): Automated IOC ingestion from threat intel
   feeds, written to `rules/custom/ioc/feeds/`.

## STAR Rules (Stateful Temporal Analysis Rules)

STAR rules detect behavioral patterns that unfold over time. Unlike YARA (which
matches file content) or IOCs (which match atomic indicators), STAR rules
match sequences of events with temporal and causal relationships.

### Concept

A STAR rule is a state machine. Each state represents an observed condition.
Transitions between states are triggered by events that match specified
criteria. When the state machine reaches its final (accepting) state, the
rule fires.

### Rule Format

STAR rules use a TOML-based format:

```toml
[rule]
id = "RIGGS-STAR-001"
name = "Shell Download and Execute"
description = "Detects a shell process downloading a file and executing it"
severity = "high"
mitre = "T1059.004"
ttl_secs = 60  # state machine expires after 60 seconds of inactivity

[[states]]
name = "shell_started"
initial = true
match_event = "Process"
conditions = [
    { field = "executable_path", op = "ends_with", value = "/bin/sh" },
    { field = "executable_path", op = "ends_with", value = "/bin/bash" },
    { field = "executable_path", op = "ends_with", value = "/bin/zsh" },
]
condition_logic = "any"

[[states]]
name = "download_observed"
match_event = "Network"
conditions = [
    { field = "action", op = "eq", value = "Connect" },
    { field = "direction", op = "eq", value = "Outbound" },
    { field = "remote_addr.port", op = "in", value = [80, 443, 8080] },
]
condition_logic = "all"

[[states]]
name = "file_written"
match_event = "File"
conditions = [
    { field = "action", op = "eq", value = "Create" },
    { field = "path", op = "matches", value = "/tmp/*" },
]
condition_logic = "all"

[[states]]
name = "file_executed"
final = true
match_event = "Process"
conditions = [
    { field = "action", op = "eq", value = "Exec" },
    { field = "executable_path", op = "starts_with", value = "/tmp/" },
]
condition_logic = "all"

[[transitions]]
from = "shell_started"
to = "download_observed"
within_secs = 30
same_storyline = true

[[transitions]]
from = "download_observed"
to = "file_written"
within_secs = 15
same_storyline = true

[[transitions]]
from = "file_written"
to = "file_executed"
within_secs = 15
same_storyline = true
```

### Condition Operators

| Operator    | Description                                |
|-------------|--------------------------------------------|
| eq          | Exact equality                             |
| neq         | Not equal                                  |
| contains    | String contains substring                  |
| starts_with | String starts with prefix                  |
| ends_with   | String ends with suffix                    |
| matches     | Glob pattern match                         |
| regex       | Regular expression match                   |
| in          | Value is in a list                         |
| not_in      | Value is not in a list                     |
| gt / lt     | Numeric greater/less than                  |
| gte / lte   | Numeric greater/less than or equal         |
| exists      | Field is present and non-null              |

### State Machine Execution

```rust
pub struct StarMachine {
    pub rule_id: String,
    pub states: Vec<StarState>,
    pub transitions: Vec<StarTransition>,
    pub current_state: usize,
    pub started_at: DateTime<Utc>,
    pub last_transition: DateTime<Utc>,
    pub ttl: Duration,
    pub storyline_id: Uuid,
    pub matched_events: Vec<Uuid>, // event_ids that triggered transitions
}
```

Active state machines are stored in a `HashMap<(Uuid, String), StarMachine>`
keyed by `(storyline_id, rule_id)`. When an event arrives:

1. For each active machine whose current state expects this event type:
   a. Evaluate the state conditions against the event fields.
   b. Check transition constraints (within_secs, same_storyline).
   c. If conditions match, advance the machine to the next state.
   d. If the new state is `final`, the rule fires: emit a verdict.
2. For each rule whose initial state matches this event type:
   a. Create a new machine instance if no machine exists for this
      (storyline_id, rule_id).

### TTL and Garbage Collection

State machines that have not transitioned within their TTL are expired and
removed. This prevents unbounded memory growth from partially-matched rules.
A background task sweeps expired machines every 10 seconds.

### Compilation

STAR rules are parsed from TOML at load time. The conditions are compiled
into closures (or a small bytecode VM for complex rules) to avoid repeated
string matching during evaluation.

```rust
pub struct CompiledStarRule {
    pub rule_id: String,
    pub metadata: StarRuleMeta,
    pub states: Vec<CompiledState>,
    pub transitions: Vec<CompiledTransition>,
}

pub struct CompiledState {
    pub name: String,
    pub is_initial: bool,
    pub is_final: bool,
    pub event_type: EventType,
    pub matcher: Box<dyn Fn(&EventEnvelope) -> bool + Send + Sync>,
}
```

## Hot-Reload

All rule types support hot-reload via the `notify` file watcher crate.

### Reload Flow

```
File change detected (notify)
    │
    ▼
Rule Reload Task
    │
    ├── Read all rule files from default/ and custom/
    ├── Compile YARA rules → CompiledYaraRules
    ├── Compile IOC lists → CompiledIOCRules
    ├── Parse STAR rules → Vec<CompiledStarRule>
    │
    ▼
Validation
    │
    ├── All YARA rules parse successfully? (per-file, skip bad ones)
    ├── All IOC entries are well-formed? (per-line, skip bad ones)
    ├── All STAR rules have valid state machines? (per-file, skip bad ones)
    │
    ▼
Publish to watch channel
    │
    ▼
Engine reads new rules on next event
```

### Reload Guarantees

1. **Atomic swap**: The engine sees either the old rules or the new rules,
   never a mix. The `watch` channel provides this atomicity.
2. **No downtime**: Rules are compiled in the background. The engine continues
   using old rules until new ones are ready.
3. **Partial failure isolation**: A bad rule in one file does not prevent
   other files from loading. Errors are logged per-file/per-line.
4. **Debouncing**: File changes within 500ms of each other are batched into
   a single reload to avoid thrashing during bulk edits.

## Rule Testing

### riggs rule test

The CLI provides a rule testing command:

```
riggs rule test rules/custom/yara/my_rule.yar --sample /path/to/test/file
riggs rule test rules/custom/star/my_rule.star --replay events.json
riggs rule validate rules/custom/  # validate all rules, report errors
```

### Test Event Replay

STAR rules can be tested by replaying a JSON file of events:

```json
[
    {
        "event_type": "Process",
        "timestamp": "2026-01-15T10:00:00Z",
        "process_context": { "pid": 1234, "executable_path": "/bin/bash" },
        "payload": { "action": "Exec" }
    },
    {
        "event_type": "Network",
        "timestamp": "2026-01-15T10:00:05Z",
        "process_context": { "pid": 1234, "executable_path": "/bin/bash" },
        "payload": { "action": "Connect", "remote_addr": "198.51.100.1:443" }
    }
]
```

The test runner feeds these events into the STAR engine and reports which
rules fired.

## Metrics

- `riggs_rules_loaded_total` — gauge per rule type
- `riggs_rules_matched_total` — counter per rule_id
- `riggs_rules_compile_duration_ms` — histogram per rule type
- `riggs_rules_reload_total` — counter (success/failure)
- `riggs_star_active_machines` — gauge
- `riggs_star_expired_machines_total` — counter

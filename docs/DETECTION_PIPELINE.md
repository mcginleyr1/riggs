# Riggs: Detection Pipeline

## Overview

The detection pipeline is a staged, multi-engine system that processes every
event through a series of analysis stages. Each stage can pass, fail, or flag
an event as suspicious. The pipeline is orchestrated by `riggs-engine`, which
routes events to the appropriate stages based on event type and accumulates
confidence scores into a final verdict.

The pipeline is designed so that cheap checks run first and expensive checks
run only when earlier stages produce ambiguous results. This keeps the common
case fast: most events are benign and exit the pipeline early.

## Pipeline Stages

```
Event Ingress
    │
    ▼
┌──────────┐
│ File Gate │──── (non-file events bypass) ─────────────────────────┐
└────┬─────┘                                                        │
     │ (new/modified executables)                                   │
     ▼                                                              │
┌───────────┐                                                       │
│ Static AI │ PE/ELF/Mach-O feature extraction → ONNX inference     │
└────┬──────┘                                                       │
     │                                                              │
     ▼                                                              │
┌──────────────┐                                                    │
│ Rules Engine │ YARA-X content matching + IOC hash/IP matching     │
└────┬─────────┘                                                    │
     │                                                              │
     ▼                                                              ▼
┌────────────────┐                                    ┌────────────────┐
│ Behavioral AI  │◄─── (all events feed here) ────────│ Event Router   │
└────┬───────────┘                                    └────────────────┘
     │
     ▼
┌────────────────┐
│ Verdict Merger │ combine all confidence scores
└────┬───────────┘
     │
     ▼
┌──────────────────────┐
│ Storyline Correlation│ link verdict to process tree
└────┬─────────────────┘
     │
     ▼
┌───────────────────┐
│ Response Dispatch  │ trigger actions if threshold exceeded
└───────────────────┘
```

## Stage 1: File Gate

The file gate is the entry point for static analysis. It intercepts file
creation and modification events and decides which files warrant deeper
inspection.

### Trigger Conditions

A file enters the gate when any of these conditions hold:

- `FileEvent::Create` where `file_type` is `Executable`, `SharedLibrary`, or
  `Script`
- `FileEvent::Modify` where the file was previously classified as executable
- `FileEvent::Close { was_modified: true }` for files in monitored directories
- `ProcessEvent::Exec` where the executable has no cached verdict or has been
  modified since the last verdict

### Allowlist Fast Path

Before any analysis, the file gate checks an allowlist:

1. **Platform binaries**: Files signed by Apple (macOS) or in /usr paths
   (Linux) with valid signatures skip all analysis.
2. **Known-safe hashes**: SHA-256 matches against a local safe-hash database
   (populated from vendor-supplied lists and local learning).
3. **Path patterns**: Configurable glob patterns (e.g., `/usr/local/Cellar/**`)
   that skip analysis.

If the allowlist matches, the file gate emits a verdict of `Clean` with
confidence 1.0 and the file does not proceed to static AI.

### Rate Limiting

During high-volume file creation (e.g., package installs, builds), the file
gate applies per-directory rate limiting. If more than 100 files/second are
created in a single directory tree, the gate switches to sampling mode: it
analyzes every Nth file and queues the rest for deferred analysis.

## Stage 2: Static AI

Static AI analyzes file content without execution. This is the primary
defense against known malware variants and obfuscated threats.

### Feature Extraction

The `riggs-static-ai` crate uses `goblin` to parse binary formats:

**Mach-O (macOS primary target)**:
- Number of load commands and their types
- Segment names, sizes, and permissions
- Import table: imported dylibs and function counts
- Export table: exported symbol count and names
- Entitlements (parsed from embedded XML)
- Code signature presence and validity
- Section entropy values (high entropy suggests packing/encryption)
- String density and suspicious string patterns
- Fat binary architecture list

**ELF (Linux)**:
- Section headers, count, and permissions
- Dynamic symbol table imports
- Interpreter path (e.g., `/lib64/ld-linux-x86-64.so.2`)
- GNU build ID presence
- Section entropy values
- Packed/UPX detection via section name heuristics

**PE (Windows, future)**:
- Import table analysis (suspicious DLL imports)
- Resource section entropy
- Authenticode signature parsing
- Section characteristics

### Feature Vector

Extracted features are normalized into a fixed-size float vector:

```rust
pub struct StaticFeatureVector {
    pub features: [f32; 256], // fixed-size for ONNX model input
}
```

The feature vector layout is documented in `models/static_features.json`,
which maps vector indices to feature names. This mapping is versioned
alongside the model.

### ONNX Inference

The feature vector is passed to an ONNX model via the `ort` crate:

```rust
pub struct StaticModelOutput {
    pub malicious_probability: f32, // 0.0 = benign, 1.0 = malicious
    pub family_scores: Vec<(String, f32)>, // malware family classification
    pub confidence: f32,            // model's self-assessed confidence
}
```

The model is loaded once at startup and shared (read-only) across analysis
tasks. Inference is CPU-only (no GPU dependency) and targets < 50ms per file.

If `ort` fails to load (e.g., missing ONNX Runtime shared library), the system
falls back to `tract-onnx`, which is a pure-Rust ONNX runtime. Tract is slower
but has zero native dependencies.

## Stage 3: Rules Engine

The rules engine applies deterministic pattern matching. Unlike AI, rules
produce exact matches with no probabilistic uncertainty.

### YARA-X Rules

YARA-X rules match against file content. Rules are compiled at startup and
recompiled on hot-reload.

```
rule Suspicious_Shell_Download {
    meta:
        description = "Detects shell scripts that download and execute"
        severity = "high"
        mitre = "T1059.004"
    strings:
        $curl = "curl" ascii
        $wget = "wget" ascii
        $pipe = "| sh" ascii
        $pipe2 = "| bash" ascii
        $chmod = "chmod +x" ascii
    condition:
        ($curl or $wget) and ($pipe or $pipe2 or $chmod)
}
```

Rules are organized in directories:

- `rules/default/yara/` — Shipped with Riggs, vendor-maintained
- `rules/custom/yara/` — User-created rules

### IOC Matching

Indicators of Compromise are matched using Aho-Corasick for high-throughput
multi-pattern matching:

- **File hashes**: SHA-256 and MD5 checked against IOC database
- **IP addresses**: Remote addresses checked against threat intel lists
- **Domains**: DNS query names checked against domain blocklists
- **URLs**: Full URLs extracted from process command lines and file content

The Aho-Corasick automaton is built once from all IOC patterns and applied
to every relevant event field. Pattern matching is O(n) in the length of
the input regardless of the number of patterns.

IOC lists are stored in `rules/default/ioc/` and `rules/custom/ioc/` as
newline-delimited text files, one indicator per line, with a type prefix:

```
sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
ip:198.51.100.1
domain:evil-command-and-control.example.com
```

### Rule Compilation and Caching

YARA-X rules are compiled into an in-memory automaton at startup. The compiled
rules are stored in a `tokio::sync::watch` channel so the engine always sees
the latest version without locking.

When rules change on disk (detected by `notify` file watcher), the rule-reload
task:

1. Reads all rule files from both directories.
2. Compiles them in a background task.
3. If compilation succeeds, publishes the new compiled rules to the watch channel.
4. If compilation fails, logs the error and keeps the old rules active.

This ensures a syntax error in a custom rule never breaks the running engine.

## Stage 4: Behavioral AI

Behavioral AI analyzes sequences of events over time, not individual files.
It detects threats that are invisible to static analysis: living-off-the-land
attacks, fileless malware, and slow-and-low exfiltration.

### Event Sequence Window

The behavioral AI maintains a sliding window of events per process, grouped
by `storyline_id`. The window size is configurable (default: last 100 events
or 60 seconds, whichever is larger).

### Behavioral Feature Extraction

From the event window, the behavioral AI extracts temporal and relational
features:

```rust
pub struct BehavioralFeatureVector {
    pub process_event_count: u32,
    pub file_event_count: u32,
    pub network_event_count: u32,
    pub unique_child_processes: u32,
    pub unique_file_paths_written: u32,
    pub unique_remote_ips: u32,
    pub dns_query_count: u32,
    pub max_event_burst_rate: f32,      // events/sec peak
    pub privilege_escalation_count: u32,
    pub suspicious_path_access_count: u32,
    pub entropy_of_written_data: f32,
    pub network_bytes_ratio: f32,       // sent/received ratio
    pub temporal_features: [f32; 32],   // time-series patterns
    pub sequence_embedding: [f32; 64],  // learned event sequence embedding
}
```

### ONNX Inference

The behavioral feature vector feeds into a separate ONNX model:

```rust
pub struct BehavioralModelOutput {
    pub threat_score: f32,             // 0.0 = benign, 1.0 = threat
    pub attack_stage: Option<AttackStage>,
    pub technique_scores: Vec<(MitreTechnique, f32)>,
}

pub enum AttackStage {
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    Exfiltration,
    CommandAndControl,
    Impact,
}
```

The behavioral model is evaluated periodically (every 5 seconds per active
storyline) rather than on every event. This keeps CPU usage bounded.

### After-the-click rules (alert-only)

Phishing that gets past the mail view ends in a few acts on the machine: the
person runs something they just downloaded, a lure page talks them into pasting
a command that fetches and runs a script, or a stealer reads the browser's and
keyring's stores. Five rules in `crates/riggs-behavioral-ai/src/lure.rs` look
for these. Each looks at the current event only, so one act gives one verdict;
the storyline patterns in `tracker.rs` re-fire on every later event of their
storyline.

| Rule | Fires on one event when | Platform |
|---|---|---|
| D1 executed download | An exec carries a download mark younger than `download_recent_hours`, and the marked file is the executable, or the process is an interpreter and the marked file its first non-flag argument (the script it runs). Once per mark value | macOS |
| D2a lure child | The parent's executable basename is in `lure_parents`, and the child is a downloader, or an interpreter given inline code: `-c` for the shells and python3 (alone or in a cluster such as `-lc`), `-e` for perl, ruby and osascript | macOS, Linux |
| D2b lure pipeline | An interpreter's command line names a downloader or `base64`, and the word after a pipe is an interpreter. A pipe is a `\|` outside single and double quotes that is not half of `\|\|` | macOS, Linux |
| D2c temp exec | The executable sits directly in one of `temp_exec_dirs` | macOS, Linux |
| D3 credential store | A file `Open` matches `credential_paths`, by an executable that starts with none of `credential_readers`. Off by default | Linux |

D1 raises `DownloadExecuted`, D2a to D2c `LureCommand`, D3
`CredentialStoreAccess`. The verdict's description says what matched: the
file, the app that downloaded it and the process (D1); the parent app and the
child (D2a); what is piped into what (D2b); the directory (D2c); the store that
was opened and by whom (D3). `riggs threats` prints it under each threat.

**Alert-only, and why.** All three patterns are `Severity::Low`: a Suspicious
verdict at confidence 0.40, for which the default response policy has no
action. Anything higher has side effects. A High pattern is Malicious and starts
the response engine (quarantine, rollback). One Medium verdict makes the
storyline a threat (its score, 0.62, crosses the 0.5 threshold), and on Linux the
files a threat storyline opens are copied to the snapshot store: for D3 that is
the credential file itself. Low verdicts add up too: the storyline score
(`recalculate_threat_score` in `crates/riggs-storyline/src/correlator.rs`) is
`0.4 × mean confidence + 0.6 × max confidence + ln(1 + n) / 30` over the
storyline's `n` verdicts, and a storyline is a threat when that is above
`threat_score_threshold` (0.5). With every verdict at 0.40 that is 0.423 for
one verdict, 0.460 at 5, 0.4999 at 19 and 0.5015 at 20: the 20th Low verdict
makes the storyline a threat. So these rules give at most **5 patterns per
storyline**, all five rules together (D1 also fires only once per download
mark); a stealer reading a hundred stores raises five alerts.

That keeps these rules under the threat threshold only at the default
`threat_score_threshold`: below 0.46 five Low verdicts make a threat, below
0.423 one does. The per-storyline counts and the reported download marks are
both kept in sets of 4096 that are cleared when full, so the cap bounds memory
and ordinary noise. It is not a guarantee against a process that deliberately
raises alerts in thousands of other storylines to reset its own count. Other
things also break alert-only: `merge_malicious_threshold` at or below 0.5
makes every Suspicious verdict Malicious, and another rule in the same
storyline can (any `sudo` exec is a High `PrivilegeEscalation`, and one Medium
verdict alone crosses 0.5).

**What they miss.**

- The process sensors poll once a second, so a process that starts and exits
  between two polls is never seen: a `curl` fetching a small script, `xattr -c`,
  `chmod +x`. A pipeline typed into a terminal (`curl ... | bash`) runs as
  separate processes and none of them carries the pipeline, so its shape is
  invisible; only its payload can be caught (D2c, D1). The
  `bash -c "$(curl ...)"` shape is the Homebrew installer's and has no rule of
  its own; D2b fires on it only when the fetched script itself pipes a download
  into an interpreter.
- D2b reads the first word after each pipe: `| sudo bash` and `| env bash` do
  not fire. A command line nested in quotes (`sh -c "bash -c \"curl … | sh\""`)
  hides its pipe from the outer shell; only the inner process, if a poll catches
  it, fires.
- D1 looks at the executable and the first non-flag argument only, because an
  interpreter runs its first operand and treats the rest as data
  (`python3 convert.py data.csv` runs no `data.csv`). A flag that takes a value
  hides the script: `python3 -W ignore payload.py` is missed. That miss is
  accepted: an alert that is wrong teaches people to ignore the rule.
- D1 needs the `com.apple.quarantine` attribute. Setting it is up to the
  downloading app: Safari, Chromium, Firefox and AirDrop set it;
  `curl`, USB drives and network shares do not. Any process with write access
  can strip it, and the cited lure scripts do (`xattr -c`). Whether a root
  daemon may read it under a user's Downloads folder without Full Disk Access is
  unverified: on a permission error the sensor logs one warning and D1 stays
  blind to such files. Linux has no such mark (Chromium stopped writing
  `user.xdg.*` attributes in 2019, Firefox never did), so D1 never fires there.
- D2a rarely fires on macOS, where an opened download is started by launchd,
  not by the browser or the mail app.
- D2c matches the directory itself: a payload one level down
  (`/tmp/x/payload`, anything under `mktemp -d`) does not fire. macOS reports
  `/tmp` as `/private/tmp`; the per-user temporary directory under
  `/var/folders` is not listed.
- D3 needs `Open` events with the opening process, which only the Linux
  fanotify sensor produces, and only under `/home` and `/tmp`. A stealer that
  drives the browser through its remote-debugging port looks like the browser.
  Readers are matched by executable path, so keep them in root-owned
  directories; a path can probably be spoofed from a private mount namespace
  (not tested).

**Expected noise** (not measured yet): D1, one alert per downloaded app or
script that is run; D2a, quiet; D2b, a few alerts a week on a developer host
(installers such as rustup's `curl ... | sh` run inside `sh -c` by a Dockerfile
or Makefile), constant on a build host; D2c, every ad-hoc binary run from
`/tmp`; D3 (when enabled), backup tools, indexers and recursive greps over a
home directory until they are listed as readers, and every start of a browser
whose install directory is not in `credential_readers`. That last one is why D3
ships off.

**Config** (`[detection]` in `riggs.toml`; a missing key takes its default, a
misspelled key stops startup):

| Key | Default | Rules |
|---|---|---|
| `download_recent_hours` | `24` (0 turns D1 off) | D1 |
| `interpreters` | `sh`, `bash`, `zsh`, `dash`, `ksh`, `csh`, `tcsh`, `python3`, `Python`, `perl`, `ruby`, `osascript` | D1, D2a, D2b |
| `downloaders` | `curl`, `wget` | D2a, D2b |
| `lure_parents` | `Safari`, `Google Chrome`, `chromium`, `firefox`, `firefox-esr`, `Mail`, `Microsoft Outlook`, `thunderbird`, `Slack`, `Discord`, `Signal`, `Telegram` | D2a |
| `temp_exec_dirs` | `/tmp`, `/private/tmp`, `/var/tmp`, `/private/var/tmp` | D2c |
| `credential_paths` | empty (D3 off) | D3 |
| `credential_readers` | empty | D3 |

Names in `interpreters`, `downloaders` and `lure_parents` are executable
basenames; a name also matches its versioned build (`python3` matches
`python3.12`), and macOS runs `/usr/bin/python3` as `Python`. An empty
`lure_parents`, `temp_exec_dirs` or `credential_paths` turns its rule off, as
does an empty `interpreters` for D2b.

**Enabling D3.** First list as readers the install directory of every browser
and keyring on the host, or each of them alerts on every open of its own store.
Use root-owned directories only. Then list the stores. In `credential_paths`,
`*` stands for any run of characters, so `/.config/chromium/*/Cookies` covers
both `Default/Cookies` and `Default/Network/Cookies`. These lists are sourced
for Debian's packages and the Firefox snap; `config/riggs.toml` carries them
commented out:

```toml
credential_paths = [
  "/.config/chromium/*/Cookies", "/.config/chromium/*/Login Data",
  "/.mozilla/firefox/*/cookies.sqlite", "/.mozilla/firefox/*/logins.json", "/.mozilla/firefox/*/key4.db",
  "/.local/share/keyrings/", "/.local/share/kwalletd/",
  "/.ssh/id_",
]
credential_readers = [
  "/usr/lib/chromium/", "/usr/lib/firefox-esr/", "/snap/firefox/",
  "/usr/bin/ssh", "/usr/lib/openssh/",
  "/usr/bin/gnome-keyring", "/usr/bin/kwalletd", "/usr/bin/ksecretd",
]
```

They do not cover Firefox or Chromium installed any other way (Fedora's
`/usr/lib64/…`, Arch, Mozilla's own repository), nor Google Chrome, Brave or
Edge: no vendor source for their Linux install directories was found. Add a
browser's profile files and its install directory together. Cloud credential
files (`~/.aws`, `~/.config/gcloud`, `~/.azure`, `~/.kube/config`) are left out
on purpose: any SDK program reads them.

## Stage 5: Verdict Merger

The verdict merger combines outputs from all upstream stages into a single
verdict per event or storyline.

### Confidence Score Aggregation

Each stage produces a confidence score in [0.0, 1.0]:

| Stage          | Weight | Notes                                    |
|----------------|--------|------------------------------------------|
| Static AI      | 0.35   | Strong signal for known malware patterns |
| YARA-X Rules   | 0.25   | Exact match, high precision              |
| IOC Match      | 0.20   | Depends on IOC quality                   |
| Behavioral AI  | 0.20   | Catches what static misses               |

The merged score is a weighted average, capped at 1.0:

```
merged_score = min(1.0,
    static_ai_score * 0.35
  + yara_score * 0.25
  + ioc_score * 0.20
  + behavioral_score * 0.20
)
```

However, any single stage can force a verdict:

- **IOC exact hash match**: Overrides to `Malicious(1.0)` regardless of other
  scores. Known-bad is known-bad.
- **YARA critical rule match**: Rules tagged `severity = "critical"` override
  to `Malicious(1.0)`.
- **Allowlist match**: Overrides to `Clean(1.0)` regardless of other scores.

### Verdict Structure

```rust
pub struct Verdict {
    pub verdict_id: Uuid,
    pub target: VerdictTarget,
    pub disposition: Disposition,
    pub merged_score: f32,
    pub stage_results: Vec<StageResult>,
    pub timestamp: DateTime<Utc>,
    pub auto_mitigated: bool,
}

pub enum VerdictTarget {
    File { path: PathBuf, hash: FileHash },
    Process { pid: u32, storyline_id: Uuid },
    Storyline { storyline_id: Uuid },
}

pub enum Disposition {
    Clean,
    Suspicious,
    Malicious,
}

pub struct StageResult {
    pub stage: PipelineStage,
    pub score: f32,
    pub details: serde_json::Value,
    pub duration_us: u64,
}
```

### Verdict Caching

File verdicts are cached by SHA-256 hash. If the same file is seen again
(e.g., executed multiple times), the cached verdict is returned immediately
without re-running the pipeline. Cache entries are invalidated when:

- The file content changes (hash mismatch).
- Rules are updated (cache is flushed on rule reload).
- Models are updated (cache is flushed on model reload).
- TTL expires (configurable, default 24 hours).

## Stage 6: Storyline Correlation

After a verdict is produced, it feeds into the storyline engine. The storyline
engine maintains the graph of related events (see EVENT_MODEL.md) and
determines whether the verdict, combined with prior events in the storyline,
crosses the response threshold.

A single suspicious file might not trigger a response. But if the same
storyline shows: DNS resolution of a known-sketchy domain, followed by a
download, followed by execution of an unsigned binary, followed by privilege
escalation attempts, the accumulated storyline score will cross the threshold.

### Threshold Evaluation

```
if storyline.score >= config.response_threshold {
    dispatch_response(storyline, verdict)
}
```

The default threshold is 0.7. Operators can tune this per-policy.

## Stage 7: Response Dispatch

If the storyline score exceeds the threshold, the engine sends a
`ResponseAction` to the response task via the response channel. The response
engine executes the action and reports success/failure back to the store.

Response dispatch is detailed in RESPONSE_ENGINE.md.

## Pipeline Performance

### Latency Budget

| Stage              | Target Latency | Notes                              |
|--------------------|----------------|------------------------------------|
| File Gate          | < 1ms          | Hash lookup + allowlist check      |
| Static AI          | < 50ms         | Feature extraction + inference     |
| Rules Engine       | < 10ms         | Compiled YARA + Aho-Corasick       |
| Behavioral AI      | < 200ms        | Per evaluation cycle (not per event)|
| Verdict Merger     | < 1ms          | Arithmetic only                    |
| Storyline Update   | < 5ms          | Graph update + score recalculation |
| **Total (file)**   | **< 70ms**     | From file gate to verdict          |
| **Total (event)**  | **< 10ms**     | Non-file event through behavioral  |

### Concurrency Model

The engine runs file analysis concurrently: up to `num_cpus` files can be
analyzed in parallel. Each file gets its own spawned task for static AI and
rules. The behavioral AI runs on a timer, not per-event, so its cost is
amortized.

The rules engine is lock-free: the compiled rule set is read from a `watch`
channel receiver, which returns a clone of the current `Arc<CompiledRules>`.
Multiple tasks can run YARA matches concurrently against the same compiled
rules without contention.

### Metrics

The engine exposes internal metrics for each stage:

- `riggs_pipeline_events_total` — counter per stage per disposition
- `riggs_pipeline_latency_us` — histogram per stage
- `riggs_pipeline_errors_total` — counter per stage per error type
- `riggs_verdict_cache_hit_ratio` — gauge
- `riggs_active_storylines` — gauge

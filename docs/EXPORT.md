# Riggs: JSON-lines export

The daemon can append what it decides to a local file, one JSON object per
line, for a log collector (Splunk, Elastic, the Datadog agent and the like)
to tail. A collector's file input is the supported path: there is no network
sink and no syslog output.

## Turning it on

```toml
[export]
jsonl_path = "/var/log/riggs/events.jsonl"   # unset (the shipped state): nothing is written or queued
max_bytes = 67108864                         # default 64 MiB
heartbeat_secs = 60                          # default 60
```

The parent directory must exist. A path the daemon cannot open stops
startup. A new file is created with mode 0640 (owner and group read, minus
the daemon's umask); an existing file keeps its mode.

## Line format

Every line carries `schema` (1), `ts` (RFC 3339 UTC, milliseconds), `host`
(the output of `hostname` at start), `kind`, and the fields of that kind. A
line also carries `dropped` (a count) when lines were lost since the previous
line was written, see Back-pressure.

Examples with constructed values:

```json
{"schema":1,"ts":"2026-01-02T03:04:05.678Z","host":"mac-01","kind":"threat","level":"MALICIOUS","confidence":0.97,"event_id":"0190a1b2-0000-7000-8000-000000000001","storyline_id":"0190a1b2-0000-7000-8000-000000000002","detections":[{"source":"StaticAI","confidence":0.97,"description":"packed sample"}],"process":{"pid":4321,"ppid":1,"name":"dropper","path":"/tmp/dropper","user":"501","cmdline":"dropper --flag","cmdline_truncated":false},"file":"/tmp/payload.bin"}
{"schema":1,"ts":"2026-01-02T03:04:05.690Z","host":"mac-01","kind":"response","event_id":"0190a1b2-0000-7000-8000-000000000001","action":"Kill process (PID 4321)","outcome":"recorded","detail":"mode is record"}
{"schema":1,"ts":"2026-01-02T03:04:00.000Z","host":"mac-01","kind":"daemon","state":"started","version":"0.1.0","modes":{"response":"record","egress":"monitor","dlp":false,"phishing":"off"}}
{"schema":1,"ts":"2026-01-02T03:05:00.000Z","host":"mac-01","kind":"daemon","state":"heartbeat","uptime_secs":60,"events_processed":1234,"threats_detected":1}
{"schema":1,"ts":"2026-01-02T03:06:00.000Z","host":"mac-01","kind":"daemon","state":"stopping","reason":"signal"}
{"schema":1,"ts":"2026-01-02T03:07:00.000Z","host":"mac-01","kind":"policy","policy":"egress","change":"rejected","error":"failed to parse egress policy /etc/riggs/egress-policy.toml: TOML parse error at line 3, column 1"}
{"schema":1,"ts":"2026-01-02T03:08:00.000Z","host":"mac-01","kind":"policy","policy":"dlp","change":"deleted","file":"/etc/riggs/dlp-policy.toml"}
```

### `threat`

One line for each merged verdict above Clean, when it is produced.

| Field | Meaning |
|---|---|
| `level` | `SUSPICIOUS` or `MALICIOUS` |
| `confidence` | the highest confidence among the detections |
| `event_id`, `storyline_id` | ids, the same as `riggs threats` shows |
| `detections` | one entry per detection stage: `source`, `confidence`, `description` (cut at 500 characters) |
| `process` | `pid`, `ppid`, `name`, `path`, `user`, `cmdline` |
| `file` | the file path, only for file events |

There is no `mitre` field and no parent process name: verdicts carry no
technique, and a process context carries only the parent's pid. Both can be
added when the detectors record them.

### `response`

One line for each response record: `event_id` (the threat it answers),
`action` (action and target), `outcome` (`executed`, `recorded`, `refused` or
`failed`) and `detail`. See `docs/RESPONSE_ENGINE.md`. In `off` mode there are
none.

### `daemon`

- `state: "started"`: `version` and `modes` for response (`off`, `record`,
  `act`), egress (its policy mode), `dlp` (enabled or not) and phishing
  (`off`, `monitor` or `warn`).
- `state: "heartbeat"`: every `heartbeat_secs`, with `uptime_secs`,
  `events_processed` and `threats_detected`.
- `state: "stopping"`, `reason: "signal"`: on SIGINT or SIGTERM. The daemon
  waits up to five seconds for the file write before exiting.

### `policy`

`policy` is `egress`, `dlp`, `phishing` or `rules` (the rules directory), and
`change` is one of:

- `reloaded`: the file was read and is now in force.
- `rejected`: the file no longer loads and the old copy stays in force.
  `error` is the first line of the load error, which names the file and the
  line (and column for TOML syntax errors). Content of the file is never
  exported: only the first line of the error is kept, because the lines after
  it quote the file.
- `deleted`: the file is gone and the daemon still holds its old copy, so
  protection continues until the next restart, which will not find the file:
  egress and DLP then fall back to `riggs.toml`, and phishing protection is
  off (`file` is its path). For `rules`, a deleted rule file is followed by a
  `reloaded` line: the set is rebuilt without it.

## What is never exported

- File contents.
- Command lines longer than 256 characters: they are cut at 256 and
  `cmdline_truncated` is `true`, because command lines can hold secrets.
  Shorter ones are exported as they are, so a secret in a short command line
  is in the file: treat the file as sensitive and restrict who can read it.
- Phishing checks (verdicts, logins, hosts) and mail content of any kind.
  Only the phishing policy file's reload, rejection and deletion are exported.
- Telemetry that is not a threat: ordinary events, Clean verdicts, DLP and
  egress would-block warnings.

## Back-pressure

Writes never slow detection. Lines go through a queue of 10,000 to one writer
thread. When the queue is full, or a write fails, the line is dropped and
counted; the next line written carries `dropped: <count>`. A write error is
logged once when it starts and once when writing recovers, not per line.

## Rotation

When a line would take the file past `max_bytes`, the daemon renames it to
`<jsonl_path>.1` (replacing any previous `.1`) and starts a new file at
`jsonl_path`. This is rename rotation, as logrotate does by default, chosen
over copy-and-truncate because truncating can lose lines written between the
copy and the truncation, and a collector can lose its offset.

For a collector this means:

- Follow the file by identity (inode or content fingerprint), not only by name.
  Filebeat, the Splunk universal forwarder and the Datadog agent do this by
  default: they finish the renamed file, then read the new one.
- Read `.1` before the next rotation replaces it. At the default 64 MiB that
  takes a long time at normal rates, but a collector that is down for longer
  than one fill of the file loses the older lines.
- Do not also rotate the file with logrotate; the daemon owns rotation.

## Collecting and alerting

Point the collector's file input at `jsonl_path`, parse each line as JSON,
and index on `kind`.

The heartbeat is the only signal of a daemon that was killed with `kill -9`
or unloaded: it simply stops. Alert when no line with `kind = "daemon"` and
`state = "heartbeat"` has arrived from a `host` for longer than a few
`heartbeat_secs` (for example 3 minutes at the default 60 s). A `stopping`
line followed by silence is a clean stop; silence with no `stopping` line is
not. Also alert on `policy` lines with `change` `rejected` or `deleted`, and on
any `dropped` field.

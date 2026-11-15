//! JSON-lines export of what the daemon decides (docs/EXPORT.md). Producers
//! never block: lines go through a bounded queue to one writer thread, and a
//! full queue drops the line and counts it.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc as std_mpsc, Arc};
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use riggs_response::ResponseRecord;
use riggs_types::config::{ExportConfig, PolicyChange, PolicyReport};
use riggs_types::events::RiggsEvent;
use riggs_types::verdict::MergedVerdict;
use serde_json::{json, Map, Value};
use tokio::sync::mpsc;
use tracing::{error, info};

const SCHEMA_VERSION: u32 = 1;
const QUEUE_CAPACITY: usize = 10_000;
/// Command lines can hold secrets: a line carries at most this many characters of one.
pub const CMDLINE_MAX_CHARS: usize = 256;
/// A detection's description is built by the detectors; this bounds a runaway one.
const DESCRIPTION_MAX_CHARS: usize = 500;

enum Message {
    Line(Map<String, Value>),
    Flush(std_mpsc::SyncSender<()>),
}

pub struct Export {
    host: String,
    queue: mpsc::Sender<Message>,
    dropped: Arc<AtomicU64>,
}

impl Export {
    /// `None` when `jsonl_path` is unset: nothing is written or queued. A path that
    /// cannot be opened is an error, so a misconfigured export stops startup.
    pub fn start(config: &ExportConfig) -> std::io::Result<Option<Arc<Self>>> {
        let Some(path) = &config.jsonl_path else {
            return Ok(None);
        };
        let sink = Sink::open(PathBuf::from(path), config.max_bytes)?;
        let (export, queue) = Self::new(hostname(), QUEUE_CAPACITY);
        let dropped = Arc::clone(&export.dropped);
        std::thread::Builder::new()
            .name("riggs-export".into())
            .spawn(move || write_lines(sink, queue, dropped))?;
        Ok(Some(Arc::new(export)))
    }

    fn new(host: String, capacity: usize) -> (Self, mpsc::Receiver<Message>) {
        let (queue, receiver) = mpsc::channel(capacity);
        let export = Self {
            host,
            queue,
            dropped: Arc::new(AtomicU64::new(0)),
        };
        (export, receiver)
    }

    /// Queue one line of `kind` with the object `fields` merged in.
    pub fn emit(&self, kind: &str, fields: Value) {
        let mut line = Map::new();
        line.insert("schema".into(), SCHEMA_VERSION.into());
        line.insert(
            "ts".into(),
            Utc::now()
                .to_rfc3339_opts(SecondsFormat::Millis, true)
                .into(),
        );
        line.insert("host".into(), self.host.clone().into());
        line.insert("kind".into(), kind.into());
        if let Value::Object(fields) = fields {
            line.extend(fields);
        }
        if self.queue.try_send(Message::Line(line)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn threat(&self, merged: &MergedVerdict, event: &RiggsEvent) {
        let process = event.process_context();
        let (cmdline, cmdline_truncated) = cap(&process.cmdline, CMDLINE_MAX_CHARS);
        let confidence = merged
            .verdicts
            .iter()
            .map(|v| v.confidence)
            .fold(0.0, f32::max);
        let detections: Vec<_> = merged
            .verdicts
            .iter()
            .map(|v| {
                json!({
                    "source": v.source.to_string(),
                    "confidence": v.confidence,
                    "description": cap(&v.description, DESCRIPTION_MAX_CHARS).0,
                })
            })
            .collect();
        let mut fields = json!({
            "level": merged.final_threat_level.to_string(),
            "confidence": confidence,
            "event_id": merged.event_id.to_string(),
            "storyline_id": merged.storyline_id.to_string(),
            "detections": detections,
            "process": {
                "pid": process.pid,
                "ppid": process.ppid,
                "name": process.name,
                "path": process.path,
                "user": process.user,
                "cmdline": cmdline,
                "cmdline_truncated": cmdline_truncated,
            },
        });
        if let RiggsEvent::File(file) = event {
            fields["file"] = file.path.clone().into();
        }
        self.emit("threat", fields);
    }

    pub fn response(&self, record: &ResponseRecord) {
        self.emit(
            "response",
            json!({
                "event_id": record.event_id.to_string(),
                "action": record.action.to_string(),
                "outcome": record.outcome,
                "detail": record.detail,
            }),
        );
    }

    /// Wait (bounded) until every line queued so far has been written.
    pub async fn flush(&self) {
        let (ack, done) = std_mpsc::sync_channel(1);
        let wait = async {
            if self.queue.send(Message::Flush(ack)).await.is_ok() {
                let _ = tokio::task::spawn_blocking(move || done.recv()).await;
            }
        };
        let _ = tokio::time::timeout(Duration::from_secs(5), wait).await;
    }
}

/// What to hand a reload watcher: its changes become `policy` lines about `subject`.
pub fn policy_reporter(export: &Option<Arc<Export>>, subject: &'static str) -> PolicyReport {
    match export {
        None => Arc::new(|_| {}),
        Some(export) => {
            let export = Arc::clone(export);
            Arc::new(move |change| {
                let (change, detail) = match change {
                    PolicyChange::Reloaded => ("reloaded", None),
                    PolicyChange::Rejected(error) => ("rejected", Some(("error", error))),
                    PolicyChange::Deleted(file) => ("deleted", Some(("file", file))),
                };
                let mut fields = json!({ "policy": subject, "change": change });
                if let Some((key, value)) = detail {
                    fields[key] = value.into();
                }
                export.emit("policy", fields);
            })
        }
    }
}

/// `text` cut to `max` characters, and whether it was cut.
fn cap(text: &str, max: usize) -> (String, bool) {
    match text.char_indices().nth(max) {
        Some((end, _)) => (text[..end].to_string(), true),
        None => (text.to_string(), false),
    }
}

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn write_lines(mut sink: Sink, mut queue: mpsc::Receiver<Message>, dropped: Arc<AtomicU64>) {
    let mut failing = false;
    while let Some(message) = queue.blocking_recv() {
        let mut line = match message {
            Message::Line(line) => line,
            Message::Flush(ack) => {
                let _ = ack.send(());
                continue;
            }
        };
        let missed = dropped.swap(0, Ordering::Relaxed);
        if missed > 0 {
            line.insert("dropped".into(), missed.into());
        }
        let result = serde_json::to_vec(&line)
            .map_err(std::io::Error::other)
            .and_then(|bytes| sink.write_line(&bytes));
        match &result {
            Err(e) if !failing => {
                error!(error = %e, path = %sink.path.display(), "export write failed; lines are dropped until it recovers");
            }
            Ok(()) if failing => info!(path = %sink.path.display(), "export writes recovered"),
            _ => {}
        }
        failing = result.is_err();
        if failing {
            dropped.fetch_add(missed + 1, Ordering::Relaxed);
        }
    }
}

struct Sink {
    path: PathBuf,
    max_bytes: u64,
    file: Option<(File, u64)>,
}

impl Sink {
    fn open(path: PathBuf, max_bytes: u64) -> std::io::Result<Self> {
        let mut sink = Self {
            path,
            max_bytes,
            file: None,
        };
        sink.file = Some(sink.open_file()?);
        Ok(sink)
    }

    fn open_file(&self) -> std::io::Result<(File, u64)> {
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o640);
        let file = options.open(&self.path)?;
        let size = file.metadata()?.len();
        Ok((file, size))
    }

    /// Append `line` and a newline, first renaming the file to `<path>.1` when
    /// the line would take it past `max_bytes`. A collector that follows the file
    /// by inode finishes the renamed file and then reads the new one.
    fn write_line(&mut self, line: &[u8]) -> std::io::Result<()> {
        let (mut file, mut size) = match self.file.take() {
            Some(open) => open,
            None => self.open_file()?,
        };
        let len = line.len() as u64 + 1;
        if size > 0 && size + len > self.max_bytes {
            let mut rotated = self.path.clone().into_os_string();
            rotated.push(".1");
            std::fs::rename(&self.path, rotated)?;
            (file, size) = self.open_file()?;
        }
        let mut bytes = Vec::with_capacity(line.len() + 1);
        bytes.extend_from_slice(line);
        bytes.push(b'\n');
        file.write_all(&bytes)?;
        self.file = Some((file, size + len));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use riggs_response::ResponseAction;
    use riggs_types::config::ResponseOutcome;
    use riggs_types::events::{FileAction, ProcessContext, StorylineId};
    use riggs_types::verdict::{DetectionSource, ThreatLevel, Verdict};

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("riggs-export-{name}-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn lines(path: &std::path::Path) -> Vec<Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn started(dir: &std::path::Path) -> (Arc<Export>, PathBuf) {
        let path = dir.join("riggs.jsonl");
        let config = ExportConfig {
            jsonl_path: Some(path.display().to_string()),
            ..ExportConfig::default()
        };
        (Export::start(&config).unwrap().unwrap(), path)
    }

    fn detection(cmdline: &str) -> (MergedVerdict, RiggsEvent) {
        let process = ProcessContext::new(
            4321,
            1,
            "dropper",
            "/tmp/dropper",
            cmdline,
            "501",
            StorylineId::new(),
        );
        let event = RiggsEvent::new_file(FileAction::Create, process, "/tmp/payload.bin", None);
        let verdict = Verdict::new(
            event.event_id().clone(),
            ThreatLevel::Malicious,
            0.97,
            DetectionSource::StaticAI,
            "packed sample",
        );
        let merged = MergedVerdict::from_verdicts(
            event.event_id().clone(),
            event.process_context().storyline_id.clone(),
            vec![verdict],
        );
        (merged, event)
    }

    #[tokio::test]
    async fn a_verdict_and_its_response_record_are_one_line_each() {
        let dir = scratch("lines");
        let (export, path) = started(&dir);
        let (merged, event) = detection("dropper --flag");
        export.threat(&merged, &event);
        export.response(&ResponseRecord {
            id: uuid::Uuid::now_v7(),
            action: ResponseAction::KillProcess { pid: 4321 },
            event_id: merged.event_id.clone(),
            storyline_id: None,
            executed_at: Utc::now(),
            outcome: ResponseOutcome::Recorded,
            detail: "mode is record".into(),
        });
        export.flush().await;
        let written = lines(&path);
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(written.len(), 2);
        let (threat, response) = (&written[0], &written[1]);
        assert_eq!(threat["schema"], 1);
        assert_eq!(threat["kind"], "threat");
        assert!(chrono::DateTime::parse_from_rfc3339(threat["ts"].as_str().unwrap()).is_ok());
        assert!(!threat["host"].as_str().unwrap().is_empty());
        assert_eq!(threat["level"], "MALICIOUS");
        assert_eq!(threat["event_id"], merged.event_id.to_string());
        assert_eq!(threat["detections"][0]["source"], "StaticAI");
        assert_eq!(threat["detections"][0]["description"], "packed sample");
        assert_eq!(threat["process"]["pid"], 4321);
        assert_eq!(threat["process"]["path"], "/tmp/dropper");
        assert_eq!(threat["process"]["user"], "501");
        assert_eq!(threat["file"], "/tmp/payload.bin");
        assert_eq!(response["kind"], "response");
        assert_eq!(response["event_id"], threat["event_id"]);
        assert_eq!(response["outcome"], "recorded");
        assert_eq!(response["action"], "Kill process (PID 4321)");
        assert_eq!(response["detail"], "mode is record");
    }

    #[tokio::test]
    async fn a_long_command_line_is_cut_and_marked() {
        let dir = scratch("cmdline");
        let (export, path) = started(&dir);
        let (merged, event) = detection(&"x".repeat(10_000));
        export.threat(&merged, &event);
        export.flush().await;
        let written = lines(&path);
        std::fs::remove_dir_all(&dir).unwrap();

        let process = &written[0]["process"];
        assert_eq!(
            process["cmdline"].as_str().unwrap().len(),
            CMDLINE_MAX_CHARS
        );
        assert_eq!(process["cmdline_truncated"], true);
    }

    #[tokio::test]
    async fn a_full_queue_drops_instead_of_blocking_and_the_next_line_says_how_many() {
        let dir = scratch("drop");
        let path = dir.join("riggs.jsonl");
        // No writer yet: the queue holds two lines and the rest are dropped.
        let (export, queue) = Export::new("test-host".into(), 2);
        for n in 0..5 {
            export.emit("daemon", json!({ "n": n }));
        }
        let dropped = Arc::clone(&export.dropped);
        let sink = Sink::open(path.clone(), 1 << 20).unwrap();
        std::thread::spawn(move || write_lines(sink, queue, dropped));
        export.flush().await;
        export.emit("daemon", json!({ "n": 5 }));
        export.flush().await;
        let written = lines(&path);
        std::fs::remove_dir_all(&dir).unwrap();

        let ns: Vec<_> = written.iter().map(|l| l["n"].as_u64().unwrap()).collect();
        assert_eq!(ns, [0, 1, 5]);
        assert_eq!(written[0]["dropped"], 3);
        assert!(written[1..].iter().all(|l| l.get("dropped").is_none()));
    }

    #[test]
    fn rotation_happens_at_the_size_and_loses_no_line() {
        let dir = scratch("rotate");
        let path = dir.join("riggs.jsonl");
        let mut sink = Sink::open(path.clone(), 1000).unwrap();
        let sent: Vec<String> = (0..15).map(|n| format!("{{\"n\":{n:0>80}}}")).collect();
        for line in &sent {
            sink.write_line(line.as_bytes()).unwrap();
        }
        let size = |p: &std::path::Path| std::fs::metadata(p).unwrap().len();
        let rotated = dir.join("riggs.jsonl.1");
        let both = [&rotated, &path];
        let sizes: Vec<_> = both.iter().map(|p| size(p)).collect();
        let found: Vec<String> = both
            .iter()
            .flat_map(|p| {
                std::fs::read_to_string(p)
                    .unwrap()
                    .lines()
                    .map(String::from)
                    .collect::<Vec<_>>()
            })
            .collect();
        std::fs::remove_dir_all(&dir).unwrap();

        assert!(sizes.iter().all(|s| *s > 0 && *s <= 1000), "{sizes:?}");
        assert_eq!(found, sent);
    }

    #[cfg(unix)]
    #[test]
    fn a_new_file_is_created_owner_and_group_readable_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("mode");
        let path = dir.join("riggs.jsonl");
        Sink::open(path.clone(), 1000).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        std::fs::remove_dir_all(&dir).unwrap();

        // Requested as 0640; the process umask can only remove bits.
        assert_eq!(mode & !0o640, 0);
    }

    #[test]
    fn with_no_path_nothing_starts_and_policy_changes_go_nowhere() {
        assert!(Export::start(&ExportConfig::default()).unwrap().is_none());
        policy_reporter(&None, "egress")(PolicyChange::Reloaded);
    }

    #[tokio::test]
    async fn policy_changes_become_policy_lines_without_content() {
        let dir = scratch("policy");
        let (export, path) = started(&dir);
        let export = Some(export);
        let report = policy_reporter(&export, "dlp");
        report(PolicyChange::Reloaded);
        report(PolicyChange::rejected(
            &"failed to parse DLP policy /etc/riggs/dlp-policy.toml: TOML parse error at line 3, column 1\n  |\n3 | secret = oops\n  | ^",
        ));
        report(PolicyChange::Deleted("/etc/riggs/dlp-policy.toml".into()));
        if let Some(export) = &export {
            export.flush().await;
        }
        let written = lines(&path);
        std::fs::remove_dir_all(&dir).unwrap();

        let changes: Vec<_> = written
            .iter()
            .map(|l| l["change"].as_str().unwrap())
            .collect();
        assert_eq!(changes, ["reloaded", "rejected", "deleted"]);
        assert!(written
            .iter()
            .all(|l| l["kind"] == "policy" && l["policy"] == "dlp"));
        assert_eq!(
            written[1]["error"],
            "failed to parse DLP policy /etc/riggs/dlp-policy.toml: TOML parse error at line 3, column 1"
        );
        assert_eq!(written[2]["file"], "/etc/riggs/dlp-policy.toml");
        assert!(!written[1].to_string().contains("oops"));
    }
}

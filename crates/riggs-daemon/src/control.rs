//! Privileged CLI operations (`riggs config/scan/feeds refresh/vuln update`).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use riggs_cloud::ConsoleClient;
use riggs_intel::FeedManager;
use riggs_types::config::RiggsConfig;
use riggs_types::events::{FileAction, ProcessContext, RiggsEvent, StorylineId};
use riggs_vuln::{CveSeverity, VulnReport, VulnScanner};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// Upper bound on files queued by one `riggs scan`.
const MAX_SCAN_FILES: usize = 100_000;
/// Files larger than this are scanned without a hash (no reputation lookup).
const MAX_HASH_BYTES: u64 = 256 * 1024 * 1024;

/// Console client and enrolled agent id, set once enrollment succeeds.
pub type ConsoleSlot = Arc<RwLock<Option<(ConsoleClient, String)>>>;

pub struct ControlAdapter {
    pub config_path: Option<PathBuf>,
    pub events: mpsc::Sender<RiggsEvent>,
    pub feeds: Option<Arc<FeedManager>>,
    pub console: ConsoleSlot,
    pub vuln_running: Arc<AtomicBool>,
    pub vault: riggs_response::QuarantineVault,
}

impl riggs_comms::ControlOps for ControlAdapter {
    fn update_config(&self, key: &str, value: &str) -> Result<String, String> {
        let path = self
            .config_path
            .as_deref()
            .ok_or("no config file was loaded; create /etc/riggs/riggs.toml first")?;
        let updated = set_config_value(
            &std::fs::read_to_string(path)
                .map_err(|e| format!("reading {}: {e}", path.display()))?,
            key,
            value,
        )?;

        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, updated)
            .and_then(|_| std::fs::rename(&tmp, path))
            .map_err(|e| format!("writing {}: {e}", path.display()))?;
        info!(key, path = %path.display(), "configuration updated");
        Ok(format!(
            "{key} saved to {}; restart the daemon to apply",
            path.display()
        ))
    }

    fn trigger_scan(&self, path: &str) -> Result<String, String> {
        let root = PathBuf::from(path);
        if !root.is_absolute() {
            return Err(format!("scan path must be absolute: {path}"));
        }
        if !root.exists() {
            return Err(format!("{path} does not exist"));
        }

        let events = self.events.clone();
        tokio::task::spawn_blocking(move || {
            let storyline = StorylineId::new();
            let ctx = ProcessContext::new(
                std::process::id(),
                0,
                "riggs-scan",
                "riggs-scan",
                root.to_string_lossy(),
                "root",
                storyline,
            );
            let mut queued = 0usize;
            for file in walk_files(&root).take(MAX_SCAN_FILES) {
                let hash = sha256_file(&file);
                let event = RiggsEvent::new_file(
                    FileAction::Scan,
                    ctx.clone(),
                    file.to_string_lossy(),
                    hash,
                );
                if events.blocking_send(event).is_err() {
                    warn!("event pipeline closed; stopping scan");
                    break;
                }
                queued += 1;
            }
            info!(root = %root.display(), files = queued, "on-demand scan queued");
        });

        Ok(format!(
            "scanning {path}; detections appear in `riggs threats`"
        ))
    }

    fn refresh_feeds(&self) -> Result<String, String> {
        match &self.feeds {
            Some(feeds) if feeds.request_refresh() => Ok("threat feed refresh started".into()),
            Some(_) => Err("no threat feeds are enabled in [intel.feeds]".into()),
            None => Err("threat intel is disabled ([intel] enabled = false)".into()),
        }
    }

    fn vuln_update(&self) -> Result<String, String> {
        if self.vuln_running.swap(true, Ordering::SeqCst) {
            return Err("a vulnerability scan is already running".into());
        }

        let running = Arc::clone(&self.vuln_running);
        let console = Arc::clone(&self.console);
        tokio::spawn(async move {
            match VulnScanner::new().update_from_osv_and_scan().await {
                Ok(report) => {
                    info!("{}", report.summary());
                    report_to_console(&console, &report).await;
                }
                Err(e) => error!(error = %e, "vulnerability scan failed"),
            }
            running.store(false, Ordering::SeqCst);
        });

        Ok("vulnerability database refresh and scan started; results are logged and sent to the console".into())
    }

    fn quarantine_list(&self) -> Result<Vec<riggs_comms::QuarantinedFile>, String> {
        let entries = self.vault.list().map_err(|e| e.to_string())?;
        Ok(entries
            .into_iter()
            .map(|e| riggs_comms::QuarantinedFile {
                id: e.id.to_string(),
                original_path: e.original_path.display().to_string(),
                quarantined_at: e.quarantined_at.to_rfc3339(),
                file_size: e.file_size,
                sha256: e.sha256_hash,
            })
            .collect())
    }

    fn quarantine_restore(&self, id: &str) -> Result<String, String> {
        let entry_id =
            uuid::Uuid::parse_str(id).map_err(|_| format!("not a quarantine id: {id}"))?;
        let original = self
            .vault
            .list()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|e| e.id == entry_id)
            .ok_or_else(|| format!("no quarantined file with id {id}"))?
            .original_path;
        self.vault.restore(entry_id).map_err(|e| e.to_string())?;
        info!(id, path = %original.display(), "restored file from quarantine");
        Ok(format!("restored {}", original.display()))
    }
}

/// Set `key` (dotted, e.g. `engine.rules_enabled`) to `value` in a riggs.toml
/// document, preserving its comments and layout. The key must be a known
/// config field and the result must still parse as a `RiggsConfig`.
fn set_config_value(text: &str, key: &str, value: &str) -> Result<String, String> {
    let pointer = format!("/{}", key.replace('.', "/"));
    let known = serde_json::to_value(RiggsConfig::default())
        .is_ok_and(|config| config.pointer(&pointer).is_some());
    if !known {
        return Err(format!("unknown config key: {key}"));
    }

    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|e| format!("config file is not valid TOML: {e}"))?;
    let mut segments: Vec<&str> = key.split('.').collect();
    let leaf = segments.pop().ok_or("empty config key")?;
    let mut table = doc.as_table_mut();
    for segment in segments {
        table = table
            .entry(segment)
            .or_insert(toml_edit::table())
            .as_table_mut()
            .ok_or_else(|| format!("`{segment}` is not a table in the config file"))?;
    }
    table[leaf] = toml_edit::Item::Value(parse_toml_value(value));

    let updated = doc.to_string();
    toml::from_str::<RiggsConfig>(&updated).map_err(|e| format!("invalid value for {key}: {e}"))?;
    Ok(updated)
}

/// A TOML literal (`true`, `42`, `["a"]`, `"quoted"`) or, failing that, a bare string.
fn parse_toml_value(raw: &str) -> toml_edit::Value {
    format!("v = {raw}")
        .parse::<toml_edit::DocumentMut>()
        .ok()
        .and_then(|doc| doc.get("v").and_then(|item| item.as_value()).cloned())
        .unwrap_or_else(|| raw.into())
}

/// Regular files under `root` (or `root` itself), without following symlinked dirs.
fn walk_files(root: &Path) -> impl Iterator<Item = PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    std::iter::from_fn(move || {
        while let Some(path) = stack.pop() {
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&path) {
                    stack.extend(entries.flatten().map(|e| e.path()));
                }
            } else if meta.is_file() {
                return Some(path);
            }
        }
        None
    })
}

fn sha256_file(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    if file.metadata().ok()?.len() > MAX_HASH_BYTES {
        return None;
    }
    let mut hasher = Sha256::new();
    let mut reader = std::io::BufReader::new(file);
    let mut buf = [0u8; 64 * 1024];
    loop {
        match reader.read(&mut buf).ok()? {
            0 => break,
            n => hasher.update(&buf[..n]),
        }
    }
    Some(format!("{:x}", hasher.finalize()))
}

async fn report_to_console(console: &ConsoleSlot, report: &VulnReport) {
    let Some((client, agent_id)) = console.read().ok().and_then(|slot| slot.clone()) else {
        return;
    };
    let Some(mut grpc) = client.grpc_client() else {
        warn!("no console channel; vulnerability findings not reported");
        return;
    };

    let findings = report
        .vulnerabilities
        .iter()
        .map(|m| riggs_cloud::proto::VulnFinding {
            cve_id: m.cve.id.clone(),
            package_name: m.package_name.clone(),
            package_version: m.installed_version.clone(),
            package_source: String::new(),
            cvss_score: m.cve.cvss_score,
            severity: match m.cve.severity {
                CveSeverity::Critical => "critical",
                CveSeverity::High => "high",
                CveSeverity::Medium => "medium",
                CveSeverity::Low | CveSeverity::None => "low",
            }
            .into(),
            fixed_version: m.cve.fixed_version.clone().unwrap_or_default(),
        })
        .collect();

    let request = riggs_cloud::proto::VulnScanReport {
        agent_id,
        scan_timestamp: None,
        findings,
    };
    match grpc.report_vuln_scan(request).await {
        Ok(ack) => info!(
            stored = ack.into_inner().findings_stored,
            "vulnerability findings reported to console"
        ),
        Err(e) => warn!(error = %e, "vulnerability report to console failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = include_str!("../../../config/riggs.toml");

    #[test]
    fn set_config_value_preserves_comments_and_applies_value() {
        let updated = set_config_value(CONFIG, "engine.rules_enabled", "false").unwrap();
        let parsed: RiggsConfig = toml::from_str(&updated).unwrap();

        assert!(!parsed.engine.rules_enabled);
        assert_eq!(
            updated
                .lines()
                .filter(|l| l.trim_start().starts_with('#'))
                .count(),
            CONFIG
                .lines()
                .filter(|l| l.trim_start().starts_with('#'))
                .count()
        );
    }

    #[test]
    fn set_config_value_sets_strings_and_arrays() {
        let updated = set_config_value(CONFIG, "rules.rules_dir", "/opt/rules").unwrap();
        let updated = set_config_value(&updated, "egress.allow_domains", r#"["a.test"]"#).unwrap();
        let parsed: RiggsConfig = toml::from_str(&updated).unwrap();

        assert_eq!(parsed.rules.rules_dir, "/opt/rules");
        assert_eq!(parsed.egress.allow_domains, vec!["a.test".to_string()]);
    }

    #[test]
    fn set_config_value_rejects_unknown_keys_and_bad_types() {
        assert!(set_config_value(CONFIG, "engine.rules_enabled", "true").is_ok());
        assert!(set_config_value(CONFIG, "engine.no_such_key", "1").is_err());
        assert!(set_config_value(CONFIG, "engine.rules_enabled", "sometimes").is_err());
    }

    #[test]
    fn walk_files_finds_nested_files() {
        let dir = std::env::temp_dir().join(format!("riggs-walk-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("a/b")).unwrap();
        std::fs::write(dir.join("top.bin"), b"x").unwrap();
        std::fs::write(dir.join("a/b/deep.bin"), b"y").unwrap();
        let mut found: Vec<_> = walk_files(&dir).collect();
        found.sort();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(found, vec![dir.join("a/b/deep.bin"), dir.join("top.bin")]);
    }

    #[test]
    fn sha256_matches_known_digest() {
        let file = std::env::temp_dir().join(format!("riggs-hash-{}", std::process::id()));
        std::fs::write(&file, b"abc").unwrap();
        let hash = sha256_file(&file);
        std::fs::remove_file(&file).unwrap();
        assert_eq!(
            hash.as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }
}

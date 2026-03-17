use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use tracing::{debug, trace};

use crate::magic::{self, SensitiveFileType};
use crate::policy::{DlpAction, DlpPolicy};

#[derive(Debug, Clone)]
pub struct SensitiveAccess {
    pub path: PathBuf,
    pub file_type: SensitiveFileType,
    pub timestamp: DateTime<Utc>,
    pub process_name: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FlowVerdict {
    pub allow: bool,
    pub action: FlowAction,
    pub reason: Option<String>,
    pub file_path: Option<String>,
    pub file_type: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FlowAction {
    Allow,
    Block,
    Alert,
}

impl FlowVerdict {
    pub fn allow() -> Self {
        Self {
            allow: true,
            action: FlowAction::Allow,
            reason: None,
            file_path: None,
            file_type: None,
        }
    }

    pub fn block(reason: String, file_path: PathBuf, file_type: SensitiveFileType) -> Self {
        Self {
            allow: false,
            action: FlowAction::Block,
            reason: Some(reason),
            file_path: Some(file_path.display().to_string()),
            file_type: Some(file_type.to_string()),
        }
    }

    pub fn alert(reason: String, file_path: PathBuf, file_type: SensitiveFileType) -> Self {
        Self {
            allow: true,
            action: FlowAction::Alert,
            reason: Some(reason),
            file_path: Some(file_path.display().to_string()),
            file_type: Some(file_type.to_string()),
        }
    }
}

pub struct DlpCorrelator {
    file_access_log: DashMap<u32, VecDeque<SensitiveAccess>>,
    policy: RwLock<Arc<DlpPolicy>>,
    window: Duration,
}

impl DlpCorrelator {
    pub fn new(policy: Arc<DlpPolicy>, window_secs: i64) -> Self {
        Self {
            file_access_log: DashMap::new(),
            policy: RwLock::new(policy),
            window: Duration::seconds(window_secs),
        }
    }

    pub fn replace_policy(&self, new_policy: Arc<DlpPolicy>) {
        if let Ok(mut guard) = self.policy.write() {
            *guard = new_policy;
        }
    }

    fn policy(&self) -> Arc<DlpPolicy> {
        self.policy.read().expect("DLP policy lock poisoned").clone()
    }

    pub fn record_file_access(
        &self,
        pid: u32,
        path: &Path,
        process_name: &str,
        timestamp: DateTime<Utc>,
        header: Option<&[u8]>,
    ) {
        let policy = self.policy();

        if policy.is_excluded_process(process_name) {
            return;
        }

        let file_type = match magic::detect_file_type(path, header) {
            Some(ft) => ft,
            None => return, // Not a sensitive file type
        };

        // Only track file types we care about
        if policy.file_type_action(&file_type).is_none() {
            return;
        }

        let access = SensitiveAccess {
            path: path.to_path_buf(),
            file_type: file_type.clone(),
            timestamp,
            process_name: process_name.to_string(),
        };

        debug!(
            pid = pid,
            path = %path.display(),
            file_type = %file_type,
            "recorded sensitive file access"
        );

        self.file_access_log
            .entry(pid)
            .or_default()
            .push_back(access);
    }

    pub fn check_flow(&self, pid: u32, hostname: &str) -> FlowVerdict {
        let policy = self.policy();

        if !policy.is_watched_domain(hostname) {
            return FlowVerdict::allow();
        }

        let now = Utc::now();
        let cutoff = now - self.window;

        // Check this PID's recent file accesses
        if let Some(verdict) = self.check_pid_accesses(pid, hostname, cutoff, &policy) {
            return verdict;
        }

        // Also check parent/child relationships: walk the PID's recent accesses
        // and nearby PIDs that share the same process name (heuristic for
        // browser helper processes).
        // For now, just check the exact PID. Phase 5 adds process tree walking.

        FlowVerdict::allow()
    }

    fn check_pid_accesses(
        &self,
        pid: u32,
        hostname: &str,
        cutoff: DateTime<Utc>,
        policy: &DlpPolicy,
    ) -> Option<FlowVerdict> {
        let accesses = self.file_access_log.get(&pid)?;

        // Find the most recent sensitive file access within the window
        let recent = accesses
            .iter()
            .rev()
            .find(|a| a.timestamp >= cutoff)?;

        let action = policy.file_type_action(&recent.file_type)?;

        let reason = format!(
            "{} ({}) accessed by PID {} before connection to {}",
            recent.path.display(),
            recent.file_type,
            pid,
            hostname,
        );

        match action {
            DlpAction::Block => Some(FlowVerdict::block(
                reason,
                recent.path.clone(),
                recent.file_type.clone(),
            )),
            DlpAction::AlertOnly => Some(FlowVerdict::alert(
                reason,
                recent.path.clone(),
                recent.file_type.clone(),
            )),
        }
    }

    pub async fn reaper_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            interval.tick().await;
            self.evict_stale();
        }
    }

    fn evict_stale(&self) {
        let cutoff = Utc::now() - self.window;
        let mut empty_pids = Vec::new();

        for mut entry in self.file_access_log.iter_mut() {
            let queue = entry.value_mut();
            while queue.front().is_some_and(|a| a.timestamp < cutoff) {
                queue.pop_front();
            }
            if queue.is_empty() {
                empty_pids.push(*entry.key());
            }
        }

        for pid in empty_pids {
            self.file_access_log.remove(&pid);
        }

        trace!(
            active_pids = self.file_access_log.len(),
            "correlator reaper sweep"
        );
    }

    pub fn active_pid_count(&self) -> usize {
        self.file_access_log.len()
    }

    pub fn total_tracked_accesses(&self) -> usize {
        self.file_access_log
            .iter()
            .map(|entry| entry.value().len())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> Arc<DlpPolicy> {
        Arc::new(DlpPolicy {
            watched_domains: vec![
                crate::policy::DomainPattern {
                    pattern: "claude.ai".into(),
                    category: "ai-assistant".into(),
                },
                crate::policy::DomainPattern {
                    pattern: "*.anthropic.com".into(),
                    category: "ai-assistant".into(),
                },
            ],
            blocked_file_types: vec![
                SensitiveFileType::Pptx,
                SensitiveFileType::Xlsx,
                SensitiveFileType::Docx,
                SensitiveFileType::Pdf,
            ],
            alert_file_types: vec![SensitiveFileType::Csv],
            excluded_processes: vec!["softwareupdated".into()],
            action: DlpAction::Block,
        })
    }

    #[test]
    fn records_and_blocks_sensitive_upload() {
        let correlator = DlpCorrelator::new(test_policy(), 30);

        correlator.record_file_access(
            1234,
            Path::new("/Users/test/Documents/earnings.pptx"),
            "Google Chrome",
            Utc::now(),
            None,
        );

        let verdict = correlator.check_flow(1234, "claude.ai");
        assert!(!verdict.allow);
        assert_eq!(verdict.action, FlowAction::Block);
        assert!(verdict.reason.unwrap().contains("earnings.pptx"));
    }

    #[test]
    fn allows_flow_without_prior_file_access() {
        let correlator = DlpCorrelator::new(test_policy(), 30);
        let verdict = correlator.check_flow(1234, "claude.ai");
        assert!(verdict.allow);
    }

    #[test]
    fn allows_flow_to_non_watched_domain() {
        let correlator = DlpCorrelator::new(test_policy(), 30);

        correlator.record_file_access(
            1234,
            Path::new("/Users/test/report.pptx"),
            "Chrome",
            Utc::now(),
            None,
        );

        let verdict = correlator.check_flow(1234, "example.com");
        assert!(verdict.allow);
    }

    #[test]
    fn excludes_system_processes() {
        let correlator = DlpCorrelator::new(test_policy(), 30);

        correlator.record_file_access(
            999,
            Path::new("/tmp/update.pptx"),
            "softwareupdated",
            Utc::now(),
            None,
        );

        // The access should not have been recorded
        let verdict = correlator.check_flow(999, "claude.ai");
        assert!(verdict.allow);
    }

    #[test]
    fn stale_entries_evicted() {
        let correlator = DlpCorrelator::new(test_policy(), 30);

        // Record an access from 60 seconds ago
        let old_time = Utc::now() - Duration::seconds(60);
        correlator.record_file_access(
            1234,
            Path::new("/tmp/old.pptx"),
            "Chrome",
            old_time,
            None,
        );

        correlator.evict_stale();
        assert_eq!(correlator.active_pid_count(), 0);

        let verdict = correlator.check_flow(1234, "claude.ai");
        assert!(verdict.allow);
    }

    #[test]
    fn csv_gets_alert_not_block() {
        let correlator = DlpCorrelator::new(test_policy(), 30);

        correlator.record_file_access(
            1234,
            Path::new("/tmp/data.csv"),
            "Chrome",
            Utc::now(),
            None,
        );

        let verdict = correlator.check_flow(1234, "claude.ai");
        assert!(verdict.allow); // Alert = allow but flag
        assert_eq!(verdict.action, FlowAction::Alert);
    }

    #[test]
    fn different_pid_not_correlated() {
        let correlator = DlpCorrelator::new(test_policy(), 30);

        correlator.record_file_access(
            1234,
            Path::new("/tmp/secret.pptx"),
            "Chrome",
            Utc::now(),
            None,
        );

        let verdict = correlator.check_flow(5678, "claude.ai");
        assert!(verdict.allow);
    }

    #[test]
    fn wildcard_domain_matching_via_correlator() {
        let correlator = DlpCorrelator::new(test_policy(), 30);

        correlator.record_file_access(
            1234,
            Path::new("/tmp/report.pdf"),
            "curl",
            Utc::now(),
            None,
        );

        let verdict = correlator.check_flow(1234, "api.anthropic.com");
        assert!(!verdict.allow);
        assert_eq!(verdict.action, FlowAction::Block);
    }
}

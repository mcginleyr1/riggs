use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use tracing::{debug, trace};

use crate::magic::{self, SensitiveFileType};
use crate::policy::{DlpAction, DlpPolicy};

/// A sensitive file access recorded by the correlator.
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

/// Correlates file opens/closes with network flows for DLP enforcement.
///
/// ## Two-tier tracking
///
/// **Primary (fd-aware):** When the sensor provides a file descriptor, we track
/// `(pid, fd) → SensitiveAccess` in `open_fds`. The entry lives exactly as long
/// as the fd is open. On `Close`, it is moved to the fallback tier.
///
/// **Fallback (time-window):** Covers two cases:
/// 1. Sensors without fd visibility (Linux `notify`-based): entries are recorded
///    here with `fallback_window` expiry (default 10 s).
/// 2. The close→connect race: after `Close` the entry lingers in `pid_accesses`
///    for `fallback_window`, allowing an upload that starts immediately after
///    closing the file to still be caught.
///
/// **Reaper:** Runs every 10 s. Evicts stale `pid_accesses` entries and also
/// evicts `open_fds` entries older than 1 h (handles missed Close events).
pub struct DlpCorrelator {
    /// Primary: (pid, fd) → access. Precise, zero false-negatives for fd-aware sensors.
    open_fds: DashMap<(u32, u32), SensitiveAccess>,
    /// Fallback: pid → ring of recent accesses with timestamps.
    pid_accesses: DashMap<u32, VecDeque<SensitiveAccess>>,
    policy: RwLock<Arc<DlpPolicy>>,
    /// Short window used for the fallback tier (close→connect races, no-fd sensors).
    fallback_window: Duration,
    /// How long open_fds entries can survive without a matching Close (missed event guard).
    max_fd_age: Duration,
}

impl DlpCorrelator {
    pub fn new(policy: Arc<DlpPolicy>, fallback_window_secs: i64) -> Self {
        Self {
            open_fds: DashMap::new(),
            pid_accesses: DashMap::new(),
            policy: RwLock::new(policy),
            fallback_window: Duration::seconds(fallback_window_secs),
            max_fd_age: Duration::hours(1),
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

    /// Record that `pid` opened a sensitive file.
    ///
    /// `fd` — the file descriptor if known (macOS ES / eBPF sensors).
    pub fn record_file_access(
        &self,
        pid: u32,
        fd: Option<u32>,
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
            None => return,
        };

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
            pid,
            fd,
            path = %path.display(),
            %file_type,
            "recorded sensitive file access"
        );

        // Primary: fd-aware tracking
        if let Some(fd) = fd {
            self.open_fds.insert((pid, fd), access.clone());
        }

        // Fallback: always push to per-pid ring (for no-fd sensors and close→connect races)
        self.pid_accesses
            .entry(pid)
            .or_default()
            .push_back(access);
    }

    /// Record that `pid` closed `fd`. Removes the precise fd tracking entry.
    /// The fallback `pid_accesses` entry remains and expires via the reaper.
    pub fn record_file_close(&self, pid: u32, fd: u32) {
        if self.open_fds.remove(&(pid, fd)).is_some() {
            trace!(pid, fd, "fd closed, removed from open_fds");
        }
    }

    /// Check whether `pid` connecting to `hostname` should be blocked.
    pub fn check_flow(&self, pid: u32, hostname: &str) -> FlowVerdict {
        let policy = self.policy();

        if !policy.is_watched_domain(hostname) {
            return FlowVerdict::allow();
        }

        // 1. Primary check: any currently-open sensitive fd for this pid?
        if let Some(verdict) = self.check_open_fds(pid, hostname, &policy) {
            return verdict;
        }

        // 2. Fallback: recently accessed (closed or no-fd sensors) within window
        if let Some(verdict) = self.check_pid_accesses(pid, hostname, &policy) {
            return verdict;
        }

        FlowVerdict::allow()
    }

    fn check_open_fds(&self, pid: u32, hostname: &str, policy: &DlpPolicy) -> Option<FlowVerdict> {
        // Find any open fd for this pid that we care about
        let entry = self
            .open_fds
            .iter()
            .find(|e| e.key().0 == pid && policy.file_type_action(&e.value().file_type).is_some())?;

        let access = entry.value();
        let action = policy.file_type_action(&access.file_type)?;

        let reason = format!(
            "{} (fd open, {}) by PID {} → {}",
            access.path.display(),
            access.file_type,
            pid,
            hostname,
        );

        Some(match action {
            DlpAction::Block => FlowVerdict::block(reason, access.path.clone(), access.file_type.clone()),
            DlpAction::AlertOnly => FlowVerdict::alert(reason, access.path.clone(), access.file_type.clone()),
        })
    }

    fn check_pid_accesses(&self, pid: u32, hostname: &str, policy: &DlpPolicy) -> Option<FlowVerdict> {
        let cutoff = Utc::now() - self.fallback_window;
        let accesses = self.pid_accesses.get(&pid)?;

        let recent = accesses
            .iter()
            .rev()
            .find(|a| a.timestamp >= cutoff && policy.file_type_action(&a.file_type).is_some())?;

        let action = policy.file_type_action(&recent.file_type)?;

        let reason = format!(
            "{} (recently closed, {}) by PID {} → {}",
            recent.path.display(),
            recent.file_type,
            pid,
            hostname,
        );

        Some(match action {
            DlpAction::Block => FlowVerdict::block(reason, recent.path.clone(), recent.file_type.clone()),
            DlpAction::AlertOnly => FlowVerdict::alert(reason, recent.path.clone(), recent.file_type.clone()),
        })
    }

    pub async fn reaper_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            interval.tick().await;
            self.evict_stale();
        }
    }

    fn evict_stale(&self) {
        let now = Utc::now();
        let fallback_cutoff = now - self.fallback_window;
        let fd_cutoff = now - self.max_fd_age;

        // Evict stale pid_accesses entries
        let mut empty_pids = Vec::new();
        for mut entry in self.pid_accesses.iter_mut() {
            let queue = entry.value_mut();
            while queue.front().is_some_and(|a| a.timestamp < fallback_cutoff) {
                queue.pop_front();
            }
            if queue.is_empty() {
                empty_pids.push(*entry.key());
            }
        }
        for pid in empty_pids {
            self.pid_accesses.remove(&pid);
        }

        // Evict open_fds entries older than max_fd_age (missed Close guard)
        self.open_fds.retain(|key, access| {
            let keep = access.timestamp >= fd_cutoff;
            if !keep {
                trace!(pid = key.0, fd = key.1, "evicting stale open_fd entry (missed close)");
            }
            keep
        });

        trace!(
            open_fds = self.open_fds.len(),
            tracked_pids = self.pid_accesses.len(),
            "correlator reaper sweep"
        );
    }

    pub fn active_pid_count(&self) -> usize {
        self.pid_accesses.len()
    }

    pub fn open_fd_count(&self) -> usize {
        self.open_fds.len()
    }

    pub fn total_tracked_accesses(&self) -> usize {
        self.pid_accesses.iter().map(|e| e.value().len()).sum()
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

    fn record(correlator: &DlpCorrelator, pid: u32, fd: Option<u32>, path: &str) {
        correlator.record_file_access(pid, fd, Path::new(path), "Google Chrome", Utc::now(), None);
    }

    #[test]
    fn fd_tracking_blocks_while_open() {
        let c = DlpCorrelator::new(test_policy(), 10);
        record(&c, 1234, Some(5), "/docs/earnings.pptx");

        let v = c.check_flow(1234, "claude.ai");
        assert!(!v.allow);
        assert_eq!(v.action, FlowAction::Block);
        assert!(v.reason.as_deref().unwrap_or("").contains("fd open"));
    }

    #[test]
    fn fd_tracking_allows_after_close() {
        let c = DlpCorrelator::new(test_policy(), 0); // zero fallback window
        record(&c, 1234, Some(5), "/docs/earnings.pptx");
        c.record_file_close(1234, 5);

        // open_fds cleared; fallback window is 0s so pid_accesses also expired
        let v = c.check_flow(1234, "claude.ai");
        assert!(v.allow, "should allow after close with zero fallback window");
    }

    #[test]
    fn fallback_catches_close_to_connect_race() {
        let c = DlpCorrelator::new(test_policy(), 10); // 10s fallback
        record(&c, 1234, Some(5), "/docs/earnings.pptx");
        c.record_file_close(1234, 5);

        // fd is gone but fallback window still active
        let v = c.check_flow(1234, "claude.ai");
        assert!(!v.allow, "fallback should catch close→connect race");
        assert!(v.reason.as_deref().unwrap_or("").contains("recently closed"));
    }

    #[test]
    fn no_fd_sensor_uses_fallback() {
        let c = DlpCorrelator::new(test_policy(), 10);
        record(&c, 1234, None, "/docs/report.pdf"); // no fd

        let v = c.check_flow(1234, "claude.ai");
        assert!(!v.allow);
        assert_eq!(v.action, FlowAction::Block);
    }

    #[test]
    fn allows_flow_without_prior_file_access() {
        let c = DlpCorrelator::new(test_policy(), 10);
        let v = c.check_flow(1234, "claude.ai");
        assert!(v.allow);
    }

    #[test]
    fn allows_flow_to_non_watched_domain() {
        let c = DlpCorrelator::new(test_policy(), 10);
        record(&c, 1234, Some(3), "/tmp/report.pptx");
        let v = c.check_flow(1234, "example.com");
        assert!(v.allow);
    }

    #[test]
    fn excludes_system_processes() {
        let c = DlpCorrelator::new(test_policy(), 10);
        c.record_file_access(999, Some(3), Path::new("/tmp/update.pptx"), "softwareupdated", Utc::now(), None);
        let v = c.check_flow(999, "claude.ai");
        assert!(v.allow);
    }

    #[test]
    fn csv_gets_alert_not_block() {
        let c = DlpCorrelator::new(test_policy(), 10);
        record(&c, 1234, Some(4), "/tmp/data.csv");
        let v = c.check_flow(1234, "claude.ai");
        assert!(v.allow); // alert = allow but flagged
        assert_eq!(v.action, FlowAction::Alert);
    }

    #[test]
    fn different_pid_not_correlated() {
        let c = DlpCorrelator::new(test_policy(), 10);
        record(&c, 1234, Some(3), "/tmp/secret.pptx");
        let v = c.check_flow(5678, "claude.ai");
        assert!(v.allow);
    }

    #[test]
    fn wildcard_domain_matching() {
        let c = DlpCorrelator::new(test_policy(), 10);
        record(&c, 1234, Some(3), "/tmp/report.pdf");
        let v = c.check_flow(1234, "api.anthropic.com");
        assert!(!v.allow);
        assert_eq!(v.action, FlowAction::Block);
    }

    #[test]
    fn stale_fallback_entries_evicted() {
        let c = DlpCorrelator::new(test_policy(), 10);

        // Inject an old access directly
        let old_time = Utc::now() - Duration::seconds(60);
        c.pid_accesses.entry(1234).or_default().push_back(SensitiveAccess {
            path: PathBuf::from("/old/file.pptx"),
            file_type: SensitiveFileType::Pptx,
            timestamp: old_time,
            process_name: "Chrome".into(),
        });

        c.evict_stale();
        assert_eq!(c.active_pid_count(), 0);
        assert!(c.check_flow(1234, "claude.ai").allow);
    }

    #[test]
    fn open_fd_count_tracks_correctly() {
        let c = DlpCorrelator::new(test_policy(), 10);
        record(&c, 1000, Some(3), "/docs/a.pptx");
        record(&c, 1000, Some(4), "/docs/b.pdf");
        record(&c, 2000, Some(3), "/docs/c.xlsx");
        assert_eq!(c.open_fd_count(), 3);

        c.record_file_close(1000, 3);
        assert_eq!(c.open_fd_count(), 2);
    }
}

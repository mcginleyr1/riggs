use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use riggs_platform::{NetworkContainment, ProcessControl};
use riggs_types::config::{ResponseMode, ResponseOutcome};
use riggs_types::errors::RiggsError;
use riggs_types::events::ProcessContext;
use riggs_types::verdict::MergedVerdict;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{error, info};
use uuid::Uuid;

use crate::actions::{ResponseAction, ResponseRecord};
use crate::policy::ResponsePolicy;
use crate::snapshots::SnapshotStore;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: Uuid,
    pub original_path: PathBuf,
    pub quarantined_at: DateTime<Utc>,
    pub file_size: u64,
    pub sha256_hash: Option<String>,
}

pub struct QuarantineVault {
    vault_dir: PathBuf,
    manifest_path: PathBuf,
}

impl QuarantineVault {
    pub fn new(vault_dir: PathBuf) -> Self {
        let manifest_path = vault_dir.join("manifest.json");
        Self {
            vault_dir,
            manifest_path,
        }
    }

    fn ensure_vault_dir(&self) -> Result<(), RiggsError> {
        std::fs::create_dir_all(&self.vault_dir)
            .map_err(|e| RiggsError::Io(format!("failed to create vault dir: {e}")))
    }

    fn load_manifest(&self) -> Result<Vec<QuarantineEntry>, RiggsError> {
        if !self.manifest_path.exists() {
            return Ok(Vec::new());
        }
        let data = std::fs::read_to_string(&self.manifest_path)
            .map_err(|e| RiggsError::Io(format!("failed to read manifest: {e}")))?;
        serde_json::from_str(&data)
            .map_err(|e| RiggsError::Io(format!("failed to parse manifest: {e}")))
    }

    fn save_manifest(&self, entries: &[QuarantineEntry]) -> Result<(), RiggsError> {
        let data = serde_json::to_string_pretty(entries)
            .map_err(|e| RiggsError::Io(format!("failed to serialize manifest: {e}")))?;
        std::fs::write(&self.manifest_path, data)
            .map_err(|e| RiggsError::Io(format!("failed to write manifest: {e}")))
    }

    /// Hashes of files an operator restored. Restoring means "this file is
    /// fine", so auto-response must not quarantine the same bytes again.
    fn released_path(&self) -> PathBuf {
        self.vault_dir.join("released.json")
    }

    fn load_released(&self) -> Result<Vec<String>, RiggsError> {
        match std::fs::read_to_string(self.released_path()) {
            Ok(data) => serde_json::from_str(&data)
                .map_err(|e| RiggsError::Io(format!("failed to parse released list: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(RiggsError::Io(format!("failed to read released list: {e}"))),
        }
    }

    fn release(&self, hash: &str) -> Result<(), RiggsError> {
        let mut released = self.load_released()?;
        if !released.iter().any(|h| h == hash) {
            released.push(hash.to_string());
            let data = serde_json::to_string_pretty(&released)
                .map_err(|e| RiggsError::Io(format!("failed to serialize released list: {e}")))?;
            std::fs::write(self.released_path(), data)
                .map_err(|e| RiggsError::Io(format!("failed to write released list: {e}")))?;
        }
        Ok(())
    }

    fn compute_sha256(path: &Path) -> Result<String, RiggsError> {
        let data = std::fs::read(path)
            .map_err(|e| RiggsError::Io(format!("failed to read file for hashing: {e}")))?;
        let hash = Sha256::digest(&data);
        Ok(format!("{hash:x}"))
    }

    pub fn quarantine(&self, path: &Path) -> Result<QuarantineEntry, RiggsError> {
        self.ensure_vault_dir()?;

        if !path.exists() {
            return Err(RiggsError::Io(format!(
                "file does not exist: {}",
                path.display()
            )));
        }

        let metadata = std::fs::metadata(path)
            .map_err(|e| RiggsError::Io(format!("failed to read metadata: {e}")))?;
        let file_size = metadata.len();

        let sha256_hash = Self::compute_sha256(path).ok();
        if let Some(hash) = &sha256_hash {
            if self.load_released()?.contains(hash) {
                return Err(RiggsError::Response(format!(
                    "not re-quarantining {}: an operator restored this file (sha256 {hash})",
                    path.display()
                )));
            }
        }

        let id = Uuid::now_v7();
        let vault_path = self.vault_dir.join(id.to_string());

        std::fs::rename(path, &vault_path).or_else(|_| {
            // rename fails across filesystems; fall back to copy + remove
            std::fs::copy(path, &vault_path)
                .and_then(|_| std::fs::remove_file(path))
                .map_err(|e| RiggsError::Io(format!("failed to quarantine file: {e}")))
        })?;

        let entry = QuarantineEntry {
            id,
            original_path: path.to_path_buf(),
            quarantined_at: Utc::now(),
            file_size,
            sha256_hash,
        };

        let mut manifest = self.load_manifest()?;
        manifest.push(entry.clone());
        self.save_manifest(&manifest)?;

        info!(
            id = %entry.id,
            original = %entry.original_path.display(),
            "file quarantined"
        );

        Ok(entry)
    }

    pub fn restore(&self, entry_id: Uuid) -> Result<(), RiggsError> {
        let mut manifest = self.load_manifest()?;
        let pos = manifest
            .iter()
            .position(|e| e.id == entry_id)
            .ok_or_else(|| {
                RiggsError::Response(format!("quarantine entry not found: {entry_id}"))
            })?;

        let entry = &manifest[pos];
        let vault_path = self.vault_dir.join(entry_id.to_string());

        if !vault_path.exists() {
            return Err(RiggsError::Io(format!(
                "quarantined file missing from vault: {entry_id}"
            )));
        }

        // Record the release before the file reappears, so the sensor event it
        // triggers can't race a re-quarantine.
        if let Some(hash) = &entry.sha256_hash {
            self.release(hash)?;
        }

        if let Some(parent) = entry.original_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| RiggsError::Io(format!("failed to recreate parent dir: {e}")))?;
        }

        std::fs::rename(&vault_path, &entry.original_path).or_else(|_| {
            std::fs::copy(&vault_path, &entry.original_path)
                .and_then(|_| std::fs::remove_file(&vault_path))
                .map_err(|e| RiggsError::Io(format!("failed to restore file: {e}")))
        })?;

        info!(
            id = %entry_id,
            path = %entry.original_path.display(),
            "file restored from quarantine"
        );

        manifest.remove(pos);
        self.save_manifest(&manifest)?;

        Ok(())
    }

    pub fn list(&self) -> Result<Vec<QuarantineEntry>, RiggsError> {
        self.load_manifest()
    }
}

pub struct ResponseExecutor {
    process_ctl: Box<dyn ProcessControl>,
    network_ctl: Box<dyn NetworkContainment>,
    quarantine_vault: QuarantineVault,
    snapshots: Option<Arc<SnapshotStore>>,
}

impl ResponseExecutor {
    pub fn new(
        process_ctl: Box<dyn ProcessControl>,
        network_ctl: Box<dyn NetworkContainment>,
        quarantine_vault: QuarantineVault,
    ) -> Self {
        Self {
            process_ctl,
            network_ctl,
            quarantine_vault,
            snapshots: None,
        }
    }

    /// Enable Rollback, restoring from the snapshots in `store`.
    pub fn with_snapshots(mut self, store: Arc<SnapshotStore>) -> Self {
        self.snapshots = Some(store);
        self
    }

    /// Apply the policy's actions for a detection as `mode` allows, returning
    /// one record per action. `Off` evaluates nothing.
    pub async fn respond(
        &self,
        policy: &ResponsePolicy,
        mode: ResponseMode,
        verdict: &MergedVerdict,
        process: &ProcessContext,
        process_exited: bool,
        target_path: Option<&Path>,
    ) -> Vec<ResponseRecord> {
        if mode == ResponseMode::Off {
            return Vec::new();
        }
        let refusal = policy.signal_refusal(process, process_exited);
        let actions = policy.evaluate(verdict, process.pid, target_path, &verdict.storyline_id);
        let mut records = Vec::with_capacity(actions.len());
        for action in actions {
            let (outcome, detail) = match (&action, refusal) {
                (
                    ResponseAction::KillProcess { .. } | ResponseAction::SuspendProcess { .. },
                    Some(reason),
                ) => (ResponseOutcome::Refused, reason.to_string()),
                _ if mode == ResponseMode::Record => {
                    (ResponseOutcome::Recorded, "mode is record".to_string())
                }
                _ => match self.run(&action).await {
                    Ok(()) => (ResponseOutcome::Executed, "ok".to_string()),
                    Err(e) => {
                        error!(%e, "response action failed");
                        (ResponseOutcome::Failed, e.to_string())
                    }
                },
            };
            records.push(ResponseRecord {
                id: Uuid::now_v7(),
                action,
                event_id: verdict.event_id.clone(),
                storyline_id: Some(verdict.storyline_id.clone()),
                executed_at: Utc::now(),
                outcome,
                detail,
            });
        }
        records
    }

    async fn run(&self, action: &ResponseAction) -> Result<(), RiggsError> {
        match action {
            ResponseAction::KillProcess { pid } => {
                info!(pid, "killing process");
                self.process_ctl.kill_process(*pid).await
            }
            ResponseAction::SuspendProcess { pid } => {
                info!(pid, "suspending process");
                self.process_ctl.suspend_process(*pid).await
            }
            ResponseAction::QuarantineFile { path } => {
                info!(?path, "quarantining file");
                self.quarantine_vault.quarantine(path).map(|entry| {
                    info!(entry_id = %entry.id, "quarantine succeeded");
                })
            }
            ResponseAction::DeleteFile { path } => {
                info!(?path, "deleting file");
                std::fs::remove_file(path)
                    .map_err(|e| RiggsError::Io(format!("failed to delete file: {e}")))
            }
            ResponseAction::NetworkContain { allowed_ips } => {
                info!(?allowed_ips, "applying network containment");
                self.network_ctl.contain(allowed_ips).await
            }
            ResponseAction::NetworkRelease => {
                info!("releasing network containment");
                self.network_ctl.release().await
            }
            ResponseAction::Rollback { storyline_id } => match &self.snapshots {
                Some(store) => {
                    info!(storyline = %storyline_id, "rolling back storyline");
                    let (store, storyline) = (Arc::clone(store), storyline_id.clone());
                    tokio::task::spawn_blocking(move || store.rollback(&storyline))
                        .await
                        .map_err(|e| RiggsError::Response(format!("rollback task failed: {e}")))
                        .and_then(|restored| restored.map(|_| ()))
                }
                None => Err(RiggsError::Response(
                    "rollback needs [response] preemptive_snapshots = true".into(),
                )),
            },
        }
    }

    pub fn vault(&self) -> &QuarantineVault {
        &self.quarantine_vault
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use riggs_types::config::ResponseConfig;
    use riggs_types::events::StorylineId;

    struct Inert;

    #[async_trait]
    impl ProcessControl for Inert {
        async fn kill_process(&self, _pid: u32) -> Result<(), RiggsError> {
            Ok(())
        }
        async fn suspend_process(&self, _pid: u32) -> Result<(), RiggsError> {
            Ok(())
        }
        async fn resume_process(&self, _pid: u32) -> Result<(), RiggsError> {
            Ok(())
        }
    }

    #[async_trait]
    impl NetworkContainment for Inert {
        async fn contain(&self, _allowed: &[std::net::IpAddr]) -> Result<(), RiggsError> {
            Ok(())
        }
        async fn release(&self) -> Result<(), RiggsError> {
            Ok(())
        }
        async fn is_contained(&self) -> Result<bool, RiggsError> {
            Ok(false)
        }
    }

    fn executor(dir: &Path, snapshots: Option<Arc<SnapshotStore>>) -> ResponseExecutor {
        let exec = ResponseExecutor::new(
            Box::new(Inert),
            Box::new(Inert),
            QuarantineVault::new(dir.join("vault")),
        );
        match snapshots {
            Some(store) => exec.with_snapshots(store),
            None => exec,
        }
    }

    #[test]
    fn restored_files_are_not_requarantined_but_changed_ones_are() {
        let dir = std::env::temp_dir().join(format!("riggs-vault-release-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let vault = QuarantineVault::new(dir.join("vault"));
        let file = dir.join("tool.bin");
        std::fs::write(&file, b"flagged but fine").unwrap();

        let entry = vault.quarantine(&file).unwrap();
        vault.restore(entry.id).unwrap();
        let again = vault.quarantine(&file);
        std::fs::write(&file, b"now actually malicious").unwrap();
        let changed = vault.quarantine(&file);
        std::fs::remove_dir_all(&dir).unwrap();

        assert!(
            again.is_err(),
            "operator-restored bytes must not be re-quarantined"
        );
        assert!(changed.is_ok(), "a modified file is quarantined again");
    }

    #[tokio::test]
    async fn rollback_action_restores_snapshotted_files() {
        let dir = std::env::temp_dir().join(format!("riggs-exec-rollback-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("report.docx");
        std::fs::write(&file, b"original").unwrap();
        let store = Arc::new(SnapshotStore::new(dir.join("snapshots"), 1 << 20));
        let storyline = StorylineId::new();
        store.snapshot(&file, &storyline).unwrap();
        std::fs::write(&file, b"ENCRYPTED").unwrap();

        let with = executor(&dir, Some(store));
        let without = executor(&dir, None);
        let restored = with
            .run(&ResponseAction::Rollback {
                storyline_id: storyline.clone(),
            })
            .await;
        let disabled = without
            .run(&ResponseAction::Rollback {
                storyline_id: storyline,
            })
            .await;
        let content = std::fs::read(&file).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert!(restored.is_ok());
        assert_eq!(content, b"original");
        assert!(disabled.is_err());
    }

    /// Records every pid it is asked to kill.
    struct Killer(Arc<std::sync::Mutex<Vec<u32>>>);

    #[async_trait]
    impl ProcessControl for Killer {
        async fn kill_process(&self, pid: u32) -> Result<(), RiggsError> {
            self.0.lock().unwrap().push(pid);
            Ok(())
        }
        async fn suspend_process(&self, _pid: u32) -> Result<(), RiggsError> {
            Ok(())
        }
        async fn resume_process(&self, _pid: u32) -> Result<(), RiggsError> {
            Ok(())
        }
    }

    fn malicious_critical() -> MergedVerdict {
        use riggs_types::events::{EventId, StorylineId};
        use riggs_types::verdict::{DetectionSource, ThreatLevel, Verdict};
        let event_id = EventId::new();
        let verdict = Verdict::new(
            event_id.clone(),
            ThreatLevel::Malicious,
            0.99,
            DetectionSource::StaticAI,
            "sample",
        );
        MergedVerdict::from_verdicts(event_id, StorylineId::new(), vec![verdict])
    }

    fn process(path: &str) -> ProcessContext {
        ProcessContext {
            pid: 4321,
            ppid: 1,
            name: path.rsplit('/').next().unwrap().into(),
            path: path.into(),
            cmdline: path.into(),
            user: "501".into(),
            storyline_id: riggs_types::events::StorylineId::new(),
        }
    }

    /// What `respond` records and which pids it kills, for a critical verdict on
    /// `process_path` with a real file to quarantine.
    async fn respond_to_critical(
        mode: ResponseMode,
        process_path: &str,
        config: &ResponseConfig,
    ) -> (Vec<(String, ResponseOutcome)>, Vec<u32>, bool) {
        respond_to_process(mode, process_path, false, config).await
    }

    async fn respond_to_process(
        mode: ResponseMode,
        process_path: &str,
        exited: bool,
        config: &ResponseConfig,
    ) -> (Vec<(String, ResponseOutcome)>, Vec<u32>, bool) {
        let dir = std::env::temp_dir().join(format!("riggs-respond-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("dropper");
        std::fs::write(&file, b"x").unwrap();
        let killed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let exec = ResponseExecutor::new(
            Box::new(Killer(Arc::clone(&killed))),
            Box::new(Inert),
            QuarantineVault::new(dir.join("vault")),
        );
        let records = exec
            .respond(
                &ResponsePolicy::from_config(config),
                mode,
                &malicious_critical(),
                &process(process_path),
                exited,
                Some(&file),
            )
            .await;
        let still_there = file.exists();
        std::fs::remove_dir_all(&dir).unwrap();
        let outcomes = records
            .into_iter()
            .map(|r| (r.action.to_string(), r.outcome))
            .collect();
        let killed = killed.lock().unwrap().clone();
        (outcomes, killed, still_there)
    }

    fn kinds(outcomes: &[(String, ResponseOutcome)]) -> Vec<(&str, ResponseOutcome)> {
        outcomes
            .iter()
            .map(|(action, outcome)| (action.split(' ').next().unwrap(), *outcome))
            .collect()
    }

    #[tokio::test]
    async fn record_mode_runs_nothing_and_reports_every_action() {
        let (outcomes, killed, file_kept) = respond_to_critical(
            ResponseMode::Record,
            "/tmp/evil",
            &ResponseConfig::default(),
        )
        .await;

        assert_eq!(
            kinds(&outcomes),
            vec![
                ("Kill", ResponseOutcome::Recorded),
                ("Quarantine", ResponseOutcome::Recorded),
                ("Rollback", ResponseOutcome::Recorded),
            ]
        );
        assert!(killed.is_empty());
        assert!(file_kept);
    }

    #[tokio::test]
    async fn act_mode_runs_the_actions() {
        let (outcomes, killed, file_kept) =
            respond_to_critical(ResponseMode::Act, "/tmp/evil", &ResponseConfig::default()).await;

        assert_eq!(
            kinds(&outcomes),
            vec![
                ("Kill", ResponseOutcome::Executed),
                ("Quarantine", ResponseOutcome::Executed),
                // No snapshot store in this executor.
                ("Rollback", ResponseOutcome::Failed),
            ]
        );
        assert_eq!(killed, vec![4321]);
        assert!(!file_kept);
    }

    #[tokio::test]
    async fn off_mode_records_nothing() {
        let (outcomes, killed, file_kept) =
            respond_to_critical(ResponseMode::Off, "/tmp/evil", &ResponseConfig::default()).await;

        assert!(outcomes.is_empty());
        assert!(killed.is_empty());
        assert!(file_kept);
    }

    #[tokio::test]
    async fn a_protected_process_is_not_killed() {
        let config = ResponseConfig::default();
        let launchd = config.protected_processes[0].clone();
        let (outcomes, killed, _) = respond_to_critical(ResponseMode::Act, &launchd, &config).await;

        assert_eq!(kinds(&outcomes)[0], ("Kill", ResponseOutcome::Refused));
        assert!(killed.is_empty());
    }

    #[tokio::test]
    async fn a_process_only_named_like_a_protected_path_is_killed() {
        let config = ResponseConfig::default();
        let (_, killed, _) = respond_to_critical(ResponseMode::Act, "/tmp/launchd", &config).await;

        assert_eq!(killed, vec![4321]);
    }

    #[tokio::test]
    async fn an_unidentified_or_exited_process_is_never_killed() {
        let config = ResponseConfig::default();
        for (path, exited) in [("", false), ("unknown", false), ("/tmp/evil", true)] {
            let (outcomes, killed, file_kept) =
                respond_to_process(ResponseMode::Act, path, exited, &config).await;

            assert_eq!(
                kinds(&outcomes)[0],
                ("Kill", ResponseOutcome::Refused),
                "{path:?}"
            );
            assert_eq!(
                kinds(&outcomes)[1],
                ("Quarantine", ResponseOutcome::Executed)
            );
            assert!(killed.is_empty(), "{path:?}");
            assert!(!file_kept);
        }
    }
}

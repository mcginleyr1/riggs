use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use riggs_platform::{NetworkContainment, ProcessControl};
use riggs_types::errors::RiggsError;
use riggs_types::events::EventId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{error, info};
use uuid::Uuid;

use crate::actions::{ResponseAction, ResponseRecord};

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
        }
    }

    pub async fn execute(&self, action: ResponseAction) -> Result<ResponseRecord, RiggsError> {
        let id = Uuid::now_v7();
        let event_id = EventId::new();

        let result = match &action {
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
            ResponseAction::Rollback { .. } => Err(RiggsError::Response(
                "storyline rollback is not implemented".into(),
            )),
        };

        let (success, detail) = match result {
            Ok(()) => (true, "ok".to_string()),
            Err(e) => {
                error!(%e, "response action failed");
                (false, e.to_string())
            }
        };

        Ok(ResponseRecord {
            id,
            action,
            event_id,
            storyline_id: None,
            executed_at: Utc::now(),
            success,
            detail,
        })
    }

    pub async fn execute_all(&self, actions: Vec<ResponseAction>) -> Vec<ResponseRecord> {
        let mut records = Vec::with_capacity(actions.len());
        for action in actions {
            match self.execute(action).await {
                Ok(record) => records.push(record),
                Err(e) => {
                    error!(%e, "failed to build response record");
                }
            }
        }
        records
    }

    pub fn vault(&self) -> &QuarantineVault {
        &self.quarantine_vault
    }
}

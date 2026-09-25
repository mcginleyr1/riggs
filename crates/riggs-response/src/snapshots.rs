//! Pre-modification file snapshots backing storyline rollback.
//!
//! When a process in a storyline already scored as a threat opens a file, the
//! daemon snapshots the file's current content. Rollback restores every
//! snapshotted file the storyline changed. See docs/RESPONSE_ENGINE.md.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use riggs_types::errors::RiggsError;
use riggs_types::events::StorylineId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    pub id: Uuid,
    pub storyline_id: StorylineId,
    pub original_path: PathBuf,
    pub sha256: String,
    /// Unix permission bits of the original file (0 where unsupported).
    pub mode: u32,
    pub taken_at: DateTime<Utc>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RollbackSummary {
    pub restored: usize,
    pub unchanged: usize,
}

pub struct SnapshotStore {
    dir: PathBuf,
    max_file_bytes: u64,
    /// Serializes manifest read-modify-write cycles.
    manifest_lock: Mutex<()>,
}

fn io(context: &str, path: &Path, e: impl std::fmt::Display) -> RiggsError {
    RiggsError::Io(format!("{context} {}: {e}", path.display()))
}

fn sha256(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

impl SnapshotStore {
    pub fn new(dir: PathBuf, max_file_bytes: u64) -> Self {
        Self {
            dir,
            max_file_bytes,
            manifest_lock: Mutex::new(()),
        }
    }

    fn manifest_path(&self) -> PathBuf {
        self.dir.join("manifest.json")
    }

    fn blob_path(&self, id: Uuid) -> PathBuf {
        self.dir.join(format!("{id}.zst"))
    }

    fn load(&self) -> Result<Vec<SnapshotEntry>, RiggsError> {
        let path = self.manifest_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let data = std::fs::read_to_string(&path).map_err(|e| io("reading", &path, e))?;
        serde_json::from_str(&data).map_err(|e| io("parsing", &path, e))
    }

    fn save(&self, entries: &[SnapshotEntry]) -> Result<(), RiggsError> {
        std::fs::create_dir_all(&self.dir).map_err(|e| io("creating", &self.dir, e))?;
        let path = self.manifest_path();
        let data = serde_json::to_vec_pretty(entries).map_err(|e| io("encoding", &path, e))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, data)
            .and_then(|_| std::fs::rename(&tmp, &path))
            .map_err(|e| io("writing", &path, e))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.manifest_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Copy `path`'s current content before `storyline` can change it. Only the
    /// first snapshot per (storyline, path) is kept: that is the pre-attack state.
    /// Returns `None` when the file is skipped (not a regular file, too large, or
    /// already snapshotted for this storyline).
    pub fn snapshot(
        &self,
        path: &Path,
        storyline: &StorylineId,
    ) -> Result<Option<SnapshotEntry>, RiggsError> {
        let _guard = self.lock();
        let Ok(meta) = std::fs::metadata(path) else {
            return Ok(None);
        };
        if !meta.is_file() || meta.len() > self.max_file_bytes {
            return Ok(None);
        }

        let mut entries = self.load()?;
        if entries
            .iter()
            .any(|e| &e.storyline_id == storyline && e.original_path == path)
        {
            return Ok(None);
        }

        let data = std::fs::read(path).map_err(|e| io("reading", path, e))?;
        let compressed = zstd::encode_all(&data[..], 3).map_err(|e| io("compressing", path, e))?;
        std::fs::create_dir_all(&self.dir).map_err(|e| io("creating", &self.dir, e))?;

        let entry = SnapshotEntry {
            id: Uuid::now_v7(),
            storyline_id: storyline.clone(),
            original_path: path.to_path_buf(),
            sha256: sha256(&data),
            mode: file_mode(&meta),
            taken_at: Utc::now(),
        };
        let blob = self.blob_path(entry.id);
        write_private(&blob, &compressed).map_err(|e| io("writing", &blob, e))?;

        entries.push(entry.clone());
        self.save(&entries)?;
        Ok(Some(entry))
    }

    /// Restore every file `storyline` changed since it was snapshotted, then
    /// discard those snapshots. A file that fails to restore keeps its snapshot
    /// (so a retry can succeed) and the call returns an error naming it.
    pub fn rollback(&self, storyline: &StorylineId) -> Result<RollbackSummary, RiggsError> {
        let _guard = self.lock();
        let (mine, mut keep): (Vec<_>, Vec<_>) = self
            .load()?
            .into_iter()
            .partition(|e| &e.storyline_id == storyline);

        let mut summary = RollbackSummary::default();
        let mut failures = Vec::new();
        for entry in mine {
            match self.restore(&entry) {
                Ok(true) => summary.restored += 1,
                Ok(false) => summary.unchanged += 1,
                Err(e) => {
                    warn!(path = %entry.original_path.display(), error = %e, "rollback failed for file");
                    failures.push(entry.original_path.display().to_string());
                    keep.push(entry);
                    continue;
                }
            }
            let _ = std::fs::remove_file(self.blob_path(entry.id));
        }
        self.save(&keep)?;

        info!(
            storyline = %storyline,
            restored = summary.restored,
            unchanged = summary.unchanged,
            failed = failures.len(),
            "storyline rollback finished"
        );
        if failures.is_empty() {
            Ok(summary)
        } else {
            Err(RiggsError::Response(format!(
                "rollback could not restore: {}",
                failures.join(", ")
            )))
        }
    }

    /// Returns true when the file was restored, false when it was unchanged.
    fn restore(&self, entry: &SnapshotEntry) -> Result<bool, RiggsError> {
        let blob = self.blob_path(entry.id);
        let file = std::fs::File::open(&blob).map_err(|e| io("opening", &blob, e))?;
        let original = zstd::decode_all(file).map_err(|e| io("decompressing", &blob, e))?;

        let path = &entry.original_path;
        let current = std::fs::read(path).ok();
        if current.as_deref().map(sha256).as_deref() == Some(entry.sha256.as_str()) {
            return Ok(false);
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io("creating", parent, e))?;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();
        let tmp = path.with_file_name(format!(".{name}.riggs-restore"));
        std::fs::write(&tmp, &original)
            .and_then(|_| set_file_mode(&tmp, entry.mode))
            .and_then(|_| std::fs::rename(&tmp, path))
            .map_err(|e| io("restoring", path, e))?;
        Ok(true)
    }

    /// Drop snapshots older than `max_age`. Returns how many were removed.
    pub fn prune(&self, max_age: Duration) -> Result<usize, RiggsError> {
        let _guard = self.lock();
        let cutoff = Utc::now() - max_age;
        let (expired, keep): (Vec<_>, Vec<_>) =
            self.load()?.into_iter().partition(|e| e.taken_at < cutoff);
        for entry in &expired {
            let _ = std::fs::remove_file(self.blob_path(entry.id));
        }
        if !expired.is_empty() {
            self.save(&keep)?;
        }
        Ok(expired.len())
    }
}

#[cfg(unix)]
fn file_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode()
}

#[cfg(not(unix))]
fn file_mode(_meta: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn set_file_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_file_mode(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

/// Snapshots hold user file contents, so only the daemon's user may read them.
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, data)?;
    set_file_mode(path, 0o600)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("riggs-snap-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn rollback_restores_changed_and_deleted_files() {
        let dir = temp_dir("restore");
        let store = SnapshotStore::new(dir.join("store"), 1024 * 1024);
        let storyline = StorylineId::new();
        let (doc, notes, kept) = (
            dir.join("doc.txt"),
            dir.join("notes.txt"),
            dir.join("kept.txt"),
        );
        std::fs::write(&doc, b"quarterly numbers").unwrap();
        std::fs::write(&notes, b"meeting notes").unwrap();
        std::fs::write(&kept, b"untouched").unwrap();
        for path in [&doc, &notes, &kept] {
            assert!(store.snapshot(path, &storyline).unwrap().is_some());
        }
        // A second open by the same storyline must not replace the pre-attack copy.
        std::fs::write(&doc, b"ENCRYPTED").unwrap();
        assert!(store.snapshot(&doc, &storyline).unwrap().is_none());
        std::fs::remove_file(&notes).unwrap();

        let summary = store.rollback(&storyline).unwrap();

        assert_eq!(
            summary,
            RollbackSummary {
                restored: 2,
                unchanged: 1
            }
        );
        assert_eq!(std::fs::read(&doc).unwrap(), b"quarterly numbers");
        assert_eq!(std::fs::read(&notes).unwrap(), b"meeting notes");
        assert!(store.load().unwrap().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rollback_with_no_snapshots_is_a_no_op() {
        let dir = temp_dir("empty");
        let store = SnapshotStore::new(dir.join("never-created"), 1024);
        assert_eq!(
            store.rollback(&StorylineId::new()).unwrap(),
            RollbackSummary::default()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rollback_only_touches_its_own_storyline() {
        let dir = temp_dir("isolation");
        let store = SnapshotStore::new(dir.join("store"), 1024 * 1024);
        let (attacker, other) = (StorylineId::new(), StorylineId::new());
        let file = dir.join("f.txt");
        std::fs::write(&file, b"v1").unwrap();
        store.snapshot(&file, &other).unwrap();
        std::fs::write(&file, b"v2").unwrap();

        assert_eq!(
            store.rollback(&attacker).unwrap(),
            RollbackSummary::default()
        );
        assert_eq!(std::fs::read(&file).unwrap(), b"v2");
        assert_eq!(store.load().unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn oversized_files_are_skipped_and_old_snapshots_pruned() {
        let dir = temp_dir("limits");
        let store = SnapshotStore::new(dir.join("store"), 4);
        let storyline = StorylineId::new();
        let (big, small) = (dir.join("big"), dir.join("small"));
        std::fs::write(&big, b"too large").unwrap();
        std::fs::write(&small, b"ok").unwrap();

        assert!(store.snapshot(&big, &storyline).unwrap().is_none());
        assert!(store.snapshot(&small, &storyline).unwrap().is_some());
        assert_eq!(store.prune(Duration::hours(1)).unwrap(), 0);
        assert_eq!(
            store
                .prune(Duration::zero() - Duration::seconds(1))
                .unwrap(),
            1
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

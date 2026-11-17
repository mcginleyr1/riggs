use std::path::{Path, PathBuf};
use std::sync::Arc;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use riggs_types::config::{PolicyChange, PolicyReport};
use riggs_types::errors::RiggsError;
use tokio::sync::{mpsc, watch};
use tracing::{error, info, warn};

use crate::policy::Policy;

const PHISHING_POLICY_PATHS: &[&str] = &[
    "/etc/riggs/phishing-policy.toml",
    "config/phishing-policy.toml",
];

pub fn find_policy_file() -> Option<PathBuf> {
    PHISHING_POLICY_PATHS
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

/// Errors name the file and the line or key, never the file's content.
pub fn load_policy_file(path: &Path) -> Result<Policy, RiggsError> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        RiggsError::Config(format!(
            "failed to read phishing policy {}: {e}",
            path.display()
        ))
    })?;
    Policy::from_toml(&contents).map_err(|e| {
        RiggsError::Config(format!(
            "failed to load phishing policy {}: {e}",
            path.display()
        ))
    })
}

/// Watch the phishing policy file and swap the live policy on change. A file that no longer
/// loads keeps the current policy.
pub async fn watch_policy(
    policy_path: PathBuf,
    policy: Arc<watch::Sender<Arc<Policy>>>,
    report: PolicyReport,
) -> Result<(), RiggsError> {
    let (tx, mut rx) = mpsc::channel::<notify::Result<Event>>(32);

    let mut watcher = RecommendedWatcher::new(
        move |result: notify::Result<Event>| {
            let _ = tx.blocking_send(result);
        },
        notify::Config::default(),
    )
    .map_err(|e| RiggsError::Io(format!("failed to create phishing policy watcher: {e}")))?;

    let watch_dir = policy_path.parent().unwrap_or_else(|| Path::new("."));
    watcher
        .watch(watch_dir, RecursiveMode::NonRecursive)
        .map_err(|e| {
            RiggsError::Io(format!(
                "failed to watch phishing policy dir {}: {e}",
                watch_dir.display()
            ))
        })?;

    info!(path = %policy_path.display(), "watching phishing policy file for changes");
    let _watcher = watcher;
    let mut deleted = false;

    while let Some(result) = rx.recv().await {
        let event = match result {
            Ok(event) => event,
            Err(e) => {
                warn!(error = %e, "phishing policy watcher error");
                continue;
            }
        };

        let is_our_file = event
            .paths
            .iter()
            .any(|p| p.file_name() == policy_path.file_name());
        if !is_our_file {
            continue;
        }

        // A deletion can arrive as a Remove or as a Modify; either way the old
        // policy stays in force and the operator is told.
        if !policy_path.exists() {
            if !std::mem::replace(&mut deleted, true) {
                warn!("phishing policy file deleted; keeping the current policy");
                report(PolicyChange::Deleted(policy_path.display().to_string()));
            }
            continue;
        }
        deleted = false;

        if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
            match load_policy_file(&policy_path) {
                Ok(new) => {
                    info!(mode = ?new.mode(), "phishing policy reloaded");
                    policy.send_replace(Arc::new(new));
                    report(PolicyChange::Reloaded);
                }
                Err(e) => {
                    error!(
                        error = %e,
                        "phishing policy no longer loads; keeping the current policy, but the daemon will refuse to start until the file is fixed"
                    );
                    report(PolicyChange::rejected(&e));
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use riggs_types::phishing::Mode;
    use std::time::Duration;

    async fn wait_for_mode(policy: &watch::Sender<Arc<Policy>>, mode: Mode) -> bool {
        for _ in 0..200 {
            if policy.borrow().mode() == mode {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    #[tokio::test]
    async fn a_valid_edit_swaps_the_policy_and_an_invalid_edit_keeps_it() {
        let shipped =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/phishing-policy.toml");
        let text = std::fs::read_to_string(shipped).unwrap();
        let dir =
            std::env::temp_dir().join(format!("riggs-phishing-reload-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("phishing-policy.toml");
        std::fs::write(&path, &text).unwrap();

        let policy = Arc::new(watch::Sender::new(Arc::new(
            load_policy_file(&path).unwrap(),
        )));
        let task = tokio::spawn(watch_policy(path.clone(), policy.clone(), Arc::new(|_| {})));
        // Let the watcher register before the first edit.
        tokio::time::sleep(Duration::from_millis(500)).await;

        let warn = text.replacen("mode = \"monitor\"", "mode = \"warn\"", 1);
        std::fs::write(&path, &warn).unwrap();
        let swapped = wait_for_mode(&policy, Mode::Warn).await;

        std::fs::write(&path, format!("{warn}\nnot toml at all [")).unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let kept = policy.borrow().mode();

        let off = text.replacen("mode = \"monitor\"", "mode = \"off\"", 1);
        std::fs::write(&path, &off).unwrap();
        let alive = wait_for_mode(&policy, Mode::Off).await;

        task.abort();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(swapped, "a valid edit was not picked up");
        assert_eq!(kept, Mode::Warn, "an invalid edit replaced the policy");
        assert!(alive, "the watcher stopped after an invalid edit");
    }

    #[test]
    fn a_missing_file_is_a_config_error() {
        let error = load_policy_file(Path::new("/nonexistent/phishing-policy.toml")).unwrap_err();
        assert!(matches!(error, RiggsError::Config(_)));
    }
}

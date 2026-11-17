use std::path::{Path, PathBuf};
use std::sync::Arc;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use riggs_types::config::{EgressConfig, PolicyChange, PolicyReport};
use riggs_types::errors::RiggsError;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::engine::EgressEngine;
use crate::policy::EgressPolicy;

const EGRESS_POLICY_PATHS: &[&str] =
    &["/etc/riggs/egress-policy.toml", "config/egress-policy.toml"];

pub fn find_policy_file() -> Option<PathBuf> {
    EGRESS_POLICY_PATHS
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

/// Where local `riggs egress` edits are written when no policy file exists yet.
pub fn default_policy_path() -> PathBuf {
    PathBuf::from(EGRESS_POLICY_PATHS[0])
}

pub fn load_policy_file(path: &Path) -> Result<EgressConfig, RiggsError> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        RiggsError::Config(format!(
            "failed to read egress policy {}: {e}",
            path.display()
        ))
    })?;
    let config: EgressConfig = toml::from_str(&contents).map_err(|e| {
        RiggsError::Config(format!(
            "failed to parse egress policy {}: {e}",
            path.display()
        ))
    })?;
    Ok(config)
}

/// Watch the egress policy file and swap the engine's policy on change.
pub async fn watch_policy(
    policy_path: PathBuf,
    engine: Arc<EgressEngine>,
    report: PolicyReport,
) -> Result<(), RiggsError> {
    let (tx, mut rx) = mpsc::channel::<notify::Result<Event>>(32);

    let mut watcher = RecommendedWatcher::new(
        move |result: notify::Result<Event>| {
            let _ = tx.blocking_send(result);
        },
        notify::Config::default(),
    )
    .map_err(|e| RiggsError::Io(format!("failed to create egress policy watcher: {e}")))?;

    let watch_dir = policy_path.parent().unwrap_or_else(|| Path::new("."));
    watcher
        .watch(watch_dir, RecursiveMode::NonRecursive)
        .map_err(|e| {
            RiggsError::Io(format!(
                "failed to watch egress policy dir {}: {e}",
                watch_dir.display()
            ))
        })?;

    info!(path = %policy_path.display(), "watching egress policy file for changes");
    let _watcher = watcher;
    let mut deleted = false;

    while let Some(result) = rx.recv().await {
        let event = match result {
            Ok(event) => event,
            Err(e) => {
                warn!(error = %e, "egress policy watcher error");
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
                warn!("egress policy file deleted; keeping the current policy");
                report(PolicyChange::Deleted(policy_path.display().to_string()));
            }
            continue;
        }
        deleted = false;

        if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
            match load_policy_file(&policy_path) {
                Ok(config) => {
                    engine.replace_policy(EgressPolicy::from_config(&config));
                    info!(mode = %config.mode, "egress policy reloaded");
                    report(PolicyChange::Reloaded);
                }
                Err(e) => {
                    error!(
                        error = %e,
                        "egress policy no longer parses; keeping the current policy, but the daemon will refuse to start until the file is fixed"
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

    #[test]
    fn shipped_policies_load_with_their_process_rules() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for file in [
            "config/egress-policy.toml",
            "demo/egress-supply-chain/egress-policy.demo.toml",
        ] {
            let config = load_policy_file(&root.join(file)).unwrap();
            assert!(config.enabled, "{file}");
            assert!(!config.process_rules.is_empty(), "{file}");
        }
    }

    #[tokio::test]
    async fn a_deleted_policy_file_is_reported_and_the_old_policy_stays_in_force() {
        let dir = std::env::temp_dir().join(format!("riggs-egress-delete-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("egress-policy.toml");
        std::fs::write(&path, "enabled = true\nmode = \"enforce\"\n").unwrap();
        let engine = Arc::new(EgressEngine::new(EgressPolicy::from_config(
            &load_policy_file(&path).unwrap(),
        )));
        let (changes, mut seen) = mpsc::unbounded_channel();
        let report: PolicyReport = Arc::new(move |change| {
            let _ = changes.send(change);
        });
        let task = tokio::spawn(watch_policy(path.clone(), Arc::clone(&engine), report));
        // Let the watcher register before the deletion.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        std::fs::remove_file(&path).unwrap();
        let change = tokio::time::timeout(std::time::Duration::from_secs(10), seen.recv()).await;
        task.abort();
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(
            change.unwrap(),
            Some(PolicyChange::Deleted(path.display().to_string()))
        );
        assert_eq!(engine.mode().as_str(), "enforce");
    }

    #[test]
    fn wrapped_or_misspelled_policies_are_rejected() {
        let path =
            std::env::temp_dir().join(format!("riggs-egress-strict-{}.toml", std::process::id()));
        let results: Vec<_> = [
            "[egress]\nenabled = true\nmode = \"enforce\"\n",
            "enable = true\n",
            "[[process_rules]]\nprocess = \"npm\"\nallow_domain = [\"registry.npmjs.org\"]\n",
            "resolve_interval_secs = 0\n",
        ]
        .iter()
        .map(|policy| {
            std::fs::write(&path, policy).unwrap();
            load_policy_file(&path)
        })
        .collect();
        std::fs::remove_file(&path).unwrap();

        assert!(results.iter().all(Result::is_err));
    }
}

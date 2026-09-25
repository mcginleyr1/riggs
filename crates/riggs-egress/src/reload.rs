use std::path::{Path, PathBuf};
use std::sync::Arc;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use riggs_types::config::EgressConfig;
use riggs_types::errors::RiggsError;
use tokio::sync::mpsc;
use tracing::{info, warn};

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
    // The file may be a bare [egress] table or the field contents directly.
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

        if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
            match load_policy_file(&policy_path) {
                Ok(config) => {
                    engine.replace_policy(EgressPolicy::from_config(&config));
                    info!(mode = %config.mode, "egress policy reloaded");
                }
                Err(e) => {
                    warn!(error = %e, "failed to reload egress policy, keeping current");
                }
            }
        }
    }

    Ok(())
}

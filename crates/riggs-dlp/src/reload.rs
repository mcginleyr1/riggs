use std::path::{Path, PathBuf};
use std::sync::Arc;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tracing::{info, warn};

use riggs_types::config::DlpConfig;
use riggs_types::errors::RiggsError;

use crate::correlator::DlpCorrelator;
use crate::policy::DlpPolicy;

const DLP_POLICY_PATHS: &[&str] = &[
    "/etc/riggs/dlp-policy.toml",
    "config/dlp-policy.toml",
];

pub fn find_policy_file() -> Option<PathBuf> {
    DLP_POLICY_PATHS
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

pub fn load_policy_file(path: &Path) -> Result<DlpConfig, RiggsError> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        RiggsError::Config(format!(
            "failed to read DLP policy {}: {}",
            path.display(),
            e
        ))
    })?;
    let config: DlpConfig = toml::from_str(&contents).map_err(|e| {
        RiggsError::Config(format!(
            "failed to parse DLP policy {}: {}",
            path.display(),
            e
        ))
    })?;
    Ok(config)
}

pub async fn watch_policy(
    policy_path: PathBuf,
    correlator: Arc<DlpCorrelator>,
) -> Result<(), RiggsError> {
    let (tx, mut rx) = mpsc::channel::<notify::Result<Event>>(32);

    let mut watcher = RecommendedWatcher::new(
        move |result: notify::Result<Event>| {
            let _ = tx.blocking_send(result);
        },
        notify::Config::default(),
    )
    .map_err(|e| RiggsError::Io(format!("failed to create DLP policy watcher: {e}")))?;

    // Watch the parent directory (in case the file is replaced atomically)
    let watch_dir = policy_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    watcher
        .watch(watch_dir, RecursiveMode::NonRecursive)
        .map_err(|e| {
            RiggsError::Io(format!(
                "failed to watch DLP policy directory {}: {e}",
                watch_dir.display()
            ))
        })?;

    info!(
        path = %policy_path.display(),
        "watching DLP policy file for changes"
    );

    let _watcher = watcher;

    while let Some(result) = rx.recv().await {
        match result {
            Ok(event) => {
                let is_our_file = event
                    .paths
                    .iter()
                    .any(|p| p.file_name() == policy_path.file_name());

                if !is_our_file {
                    continue;
                }

                match event.kind {
                    EventKind::Create(_) | EventKind::Modify(_) => {
                        info!("DLP policy file changed, reloading");
                        match load_policy_file(&policy_path) {
                            Ok(config) => {
                                let new_policy = Arc::new(DlpPolicy::from_config(&config));
                                correlator.replace_policy(new_policy);
                                info!(
                                    domains = config.watched_domains.len(),
                                    blocked_types = config.file_types.block.len(),
                                    "DLP policy reloaded"
                                );
                            }
                            Err(e) => {
                                warn!(error = %e, "failed to reload DLP policy, keeping current policy");
                            }
                        }
                    }
                    _ => {}
                }
            }
            Err(e) => {
                warn!(error = %e, "DLP policy watcher error");
            }
        }
    }

    Ok(())
}

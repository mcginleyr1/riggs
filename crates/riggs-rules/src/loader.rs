use std::path::PathBuf;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use riggs_types::errors::RiggsError;
use tokio::sync::mpsc;
use tracing::{info, warn};

pub struct RuleLoader {
    rules_dir: PathBuf,
}

impl RuleLoader {
    pub fn new(rules_dir: PathBuf) -> Self {
        Self { rules_dir }
    }

    pub async fn watch(&self) -> Result<(), RiggsError> {
        let (tx, mut rx) = mpsc::channel::<notify::Result<Event>>(100);

        let mut watcher = RecommendedWatcher::new(
            move |result: notify::Result<Event>| {
                let _ = tx.blocking_send(result);
            },
            notify::Config::default(),
        )
        .map_err(|e| RiggsError::Io(format!("failed to create file watcher: {}", e)))?;

        watcher
            .watch(&self.rules_dir, RecursiveMode::Recursive)
            .map_err(|e| {
                RiggsError::Io(format!(
                    "failed to watch rules directory {}: {}",
                    self.rules_dir.display(),
                    e
                ))
            })?;

        info!(dir = %self.rules_dir.display(), "watching rules directory for changes");

        // Keep the watcher alive by holding it in scope while we process events.
        // When this future is cancelled (e.g. via tokio::select!), the watcher drops and stops.
        let _watcher = watcher;

        while let Some(result) = rx.recv().await {
            match result {
                Ok(event) => match event.kind {
                    EventKind::Create(_) => {
                        info!(paths = ?event.paths, "rule file created");
                        // TODO: reload affected rules
                    }
                    EventKind::Modify(_) => {
                        info!(paths = ?event.paths, "rule file modified");
                        // TODO: reload affected rules
                    }
                    EventKind::Remove(_) => {
                        info!(paths = ?event.paths, "rule file removed");
                        // TODO: unload affected rules
                    }
                    _ => {}
                },
                Err(e) => {
                    warn!(error = %e, "file watcher error");
                }
            }
        }

        Ok(())
    }
}

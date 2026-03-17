use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use riggs_types::errors::RiggsError;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::custom::CustomRuleEngine;
use crate::yara::YaraEngine;

pub struct RuleLoader {
    rules_dir: PathBuf,
    yara: Option<Arc<RwLock<YaraEngine>>>,
    custom: Option<Arc<RwLock<CustomRuleEngine>>>,
}

impl RuleLoader {
    pub fn new(
        rules_dir: PathBuf,
        yara: Option<Arc<RwLock<YaraEngine>>>,
        custom: Option<Arc<RwLock<CustomRuleEngine>>>,
    ) -> Self {
        Self {
            rules_dir,
            yara,
            custom,
        }
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
                    EventKind::Create(_) | EventKind::Modify(_) => {
                        info!(paths = ?event.paths, "rule file created or modified");
                        self.reload_affected(&event.paths);
                    }
                    EventKind::Remove(_) => {
                        info!(paths = ?event.paths, "rule file removed");
                        self.reload_affected(&event.paths);
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

    fn reload_affected(&self, paths: &[PathBuf]) {
        let has_yara_change = paths.iter().any(|p| {
            p.extension()
                .is_some_and(|ext| ext == "yar" || ext == "yara")
        });

        let has_toml_change = paths
            .iter()
            .any(|p| p.extension().is_some_and(|ext| ext == "toml"));

        if has_yara_change {
            self.reload_yara_rules();
        }
        if has_toml_change {
            self.rebuild_custom_rules();
        }
    }

    fn reload_yara_rules(&self) {
        if let Some(ref yara) = self.yara {
            match yara.write() {
                Ok(mut engine) => match engine.load_rules() {
                    Ok(()) => info!("yara rules reloaded"),
                    Err(e) => warn!(error = %e, "failed to reload yara rules"),
                },
                Err(e) => warn!(error = %e, "failed to acquire yara engine write lock"),
            }
        }
    }

    fn rebuild_custom_rules(&self) {
        if let Some(ref custom) = self.custom {
            let mut engine = CustomRuleEngine::new();

            if let Ok(entries) = std::fs::read_dir(&self.rules_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|ext| ext == "toml") {
                        match CustomRuleEngine::load_from_file(&path) {
                            Ok(rules) => {
                                for rule in rules {
                                    engine.add_rule(rule);
                                }
                            }
                            Err(e) => {
                                warn!(
                                    path = %path.display(),
                                    error = %e,
                                    "failed to load custom rules"
                                );
                            }
                        }
                    }
                }
            }

            match custom.write() {
                Ok(mut guard) => {
                    *guard = engine;
                    info!("custom rules reloaded");
                }
                Err(e) => warn!(error = %e, "failed to acquire custom engine write lock"),
            }
        }
    }
}

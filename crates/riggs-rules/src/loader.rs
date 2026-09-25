use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

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
                Ok(event)
                    if matches!(
                        event.kind,
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                    ) =>
                {
                    info!(paths = ?event.paths, "rule files changed");
                    // Reading and compiling rules is blocking work; keep it off
                    // the async runtime.
                    let dir = self.rules_dir.clone();
                    let yara = self.yara.clone();
                    let custom = self.custom.clone();
                    let reload = tokio::task::spawn_blocking(move || {
                        reload_affected(&dir, yara, custom, &event.paths)
                    });
                    if let Err(e) = reload.await {
                        warn!(error = %e, "rule reload task failed");
                    }
                }
                Ok(_) => {}
                Err(e) => warn!(error = %e, "file watcher error"),
            }
        }

        Ok(())
    }
}

/// Recompile whichever rule sets the changed paths belong to. New engines are
/// built without holding a lock, then swapped in, so scans never wait on a compile.
fn reload_affected(
    dir: &Path,
    yara: Option<Arc<RwLock<YaraEngine>>>,
    custom: Option<Arc<RwLock<CustomRuleEngine>>>,
    paths: &[PathBuf],
) {
    let touches = |exts: &[&str]| paths.iter().any(|p| crate::has_extension(p, exts));

    if let Some(yara) = yara.filter(|_| touches(crate::YARA_EXTENSIONS)) {
        match YaraEngine::new(dir.to_path_buf()) {
            Ok(fresh) => {
                *yara.write().unwrap_or_else(PoisonError::into_inner) = fresh;
                info!("yara rules reloaded");
            }
            Err(e) => warn!(error = %e, "failed to reload yara rules; keeping previous set"),
        }
    }

    if let Some(custom) = custom.filter(|_| touches(crate::CUSTOM_RULE_EXTENSIONS)) {
        let fresh = CustomRuleEngine::load_dir(dir);
        *custom.write().unwrap_or_else(PoisonError::into_inner) = fresh;
        info!("custom rules reloaded");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reload_swaps_in_newly_added_yara_rules() {
        let dir = std::env::temp_dir().join(format!("riggs-loader-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sample = dir.join("sample.bin");
        std::fs::write(&sample, b"xxNEW_MARKERxx").unwrap();
        let yara = Arc::new(RwLock::new(YaraEngine::new(dir.clone()).unwrap()));
        assert!(yara.read().unwrap().scan_file(&sample).unwrap().is_empty());

        let rule = dir.join("new.yar");
        std::fs::write(
            &rule,
            r#"rule fresh { strings: $a = "NEW_MARKER" condition: $a }"#,
        )
        .unwrap();
        reload_affected(&dir, Some(Arc::clone(&yara)), None, &[rule]);
        let matches = yara.read().unwrap().scan_file(&sample).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(matches[0].rule_name, "fresh");
    }
}

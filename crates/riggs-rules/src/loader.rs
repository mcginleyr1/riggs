use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use riggs_types::config::{PolicyChange, PolicyReport};
use riggs_types::errors::RiggsError;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::custom::CustomRuleEngine;
use crate::ioc::IocMatcher;
use crate::yara::YaraEngine;

pub struct RuleLoader {
    rules_dir: PathBuf,
    yara: Option<Arc<RwLock<YaraEngine>>>,
    local_ioc: Option<Arc<RwLock<IocMatcher>>>,
    custom: Option<Arc<RwLock<CustomRuleEngine>>>,
    report: PolicyReport,
}

impl RuleLoader {
    pub fn new(
        rules_dir: PathBuf,
        yara: Option<Arc<RwLock<YaraEngine>>>,
        local_ioc: Option<Arc<RwLock<IocMatcher>>>,
        custom: Option<Arc<RwLock<CustomRuleEngine>>>,
    ) -> Self {
        Self {
            rules_dir,
            yara,
            local_ioc,
            custom,
            report: Arc::new(|_| {}),
        }
    }

    pub fn with_report(mut self, report: PolicyReport) -> Self {
        self.report = report;
        self
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
                    if matches!(event.kind, EventKind::Remove(_)) {
                        for path in removed_rule_files(&event.paths) {
                            (self.report)(PolicyChange::Deleted(path.display().to_string()));
                        }
                    }
                    let report = Arc::clone(&self.report);
                    // Reading and compiling rules is blocking work; keep it off
                    // the async runtime.
                    let dir = self.rules_dir.clone();
                    let yara = self.yara.clone();
                    let local_ioc = self.local_ioc.clone();
                    let custom = self.custom.clone();
                    let reload = tokio::task::spawn_blocking(move || {
                        reload_affected(&dir, yara, local_ioc, custom, &event.paths, &*report)
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

/// The paths that are gone and that the loader would have loaded: an editor's
/// probe, swap, backup and lock files are not rules.
fn removed_rule_files(paths: &[PathBuf]) -> impl Iterator<Item = &PathBuf> {
    paths.iter().filter(|p| {
        !p.exists()
            && [
                crate::YARA_EXTENSIONS,
                crate::IOC_EXTENSIONS,
                crate::CUSTOM_RULE_EXTENSIONS,
            ]
            .iter()
            .any(|exts| crate::has_extension(p, exts))
    })
}

/// Recompile whichever rule sets the changed paths belong to. New engines are
/// built without holding a lock, then swapped in, so scans never wait on a compile.
/// Reports once: `Rejected` if the yara set failed, else `Reloaded`.
fn reload_affected(
    dir: &Path,
    yara: Option<Arc<RwLock<YaraEngine>>>,
    local_ioc: Option<Arc<RwLock<IocMatcher>>>,
    custom: Option<Arc<RwLock<CustomRuleEngine>>>,
    paths: &[PathBuf],
    report: &(dyn Fn(PolicyChange) + Send + Sync),
) {
    let touches = |exts: &[&str]| paths.iter().any(|p| crate::has_extension(p, exts));
    let mut outcome = None;

    if let Some(yara) = yara.filter(|_| touches(crate::YARA_EXTENSIONS)) {
        match YaraEngine::new(dir.to_path_buf()) {
            Ok(fresh) => {
                *yara.write().unwrap_or_else(PoisonError::into_inner) = fresh;
                info!("yara rules reloaded");
                outcome = Some(PolicyChange::Reloaded);
            }
            Err(e) => {
                warn!(error = %e, "failed to reload yara rules; keeping previous set");
                outcome = Some(PolicyChange::rejected(&e));
            }
        }
    }

    if let Some(local_ioc) = local_ioc.filter(|_| touches(crate::IOC_EXTENSIONS)) {
        let fresh = IocMatcher::load_dir(dir);
        info!(count = fresh.len(), "local IOC lists reloaded");
        *local_ioc.write().unwrap_or_else(PoisonError::into_inner) = fresh;
        outcome.get_or_insert(PolicyChange::Reloaded);
    }

    if let Some(custom) = custom.filter(|_| touches(crate::CUSTOM_RULE_EXTENSIONS)) {
        let fresh = CustomRuleEngine::load_dir(dir);
        *custom.write().unwrap_or_else(PoisonError::into_inner) = fresh;
        info!("custom rules reloaded");
        outcome.get_or_insert(PolicyChange::Reloaded);
    }

    if let Some(outcome) = outcome {
        report(outcome);
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
        reload_affected(&dir, Some(Arc::clone(&yara)), None, None, &[rule], &|_| {});
        let matches = yara.read().unwrap().scan_file(&sample).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(matches[0].rule_name, "fresh");
    }

    #[test]
    fn reload_swaps_in_edited_ioc_lists() {
        let dir = std::env::temp_dir().join(format!("riggs-loader-ioc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let local_ioc = Arc::new(RwLock::new(IocMatcher::load_dir(&dir)));
        assert!(local_ioc.read().unwrap().is_empty());

        let list = dir.join("c2.ioc");
        std::fs::write(&list, "# c2\nip:203.0.113[.]7\ndomain:c2.example\n").unwrap();
        reload_affected(
            &dir,
            None,
            Some(Arc::clone(&local_ioc)),
            None,
            &[list],
            &|_| {},
        );
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(local_ioc.read().unwrap().len(), 2);
    }

    #[test]
    fn one_change_to_all_three_rule_kinds_is_one_report() {
        let dir = std::env::temp_dir().join(format!("riggs-loader-report-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let yara = Arc::new(RwLock::new(YaraEngine::new(dir.clone()).unwrap()));
        let local_ioc = Arc::new(RwLock::new(IocMatcher::load_dir(&dir)));
        let custom = Arc::new(RwLock::new(CustomRuleEngine::load_dir(&dir)));
        let reports = std::sync::Mutex::new(Vec::new());

        reload_affected(
            &dir,
            Some(yara),
            Some(local_ioc),
            Some(custom),
            &[dir.join("a.yar"), dir.join("b.ioc"), dir.join("c.toml")],
            &|change| reports.lock().unwrap().push(change),
        );
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(*reports.lock().unwrap(), vec![PolicyChange::Reloaded]);
    }

    #[test]
    fn only_removed_rule_files_are_reported_deleted() {
        let dir = std::env::temp_dir().join(format!("riggs-loader-gone-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("still-here.yar"), "").unwrap();
        let paths: Vec<PathBuf> = [
            "gone.yar",
            "gone.ioc",
            "gone.toml",
            "still-here.yar",
            ".gone.yar.swp",
            "gone.yar~",
            "4913",
            "gone.txt",
        ]
        .iter()
        .map(|name| dir.join(name))
        .collect();

        let reported: Vec<_> = removed_rule_files(&paths)
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(reported, ["gone.yar", "gone.ioc", "gone.toml"]);
    }
}

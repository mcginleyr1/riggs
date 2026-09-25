pub mod custom;
pub mod ioc;
pub mod loader;
pub mod stage;
pub mod yara;

pub use custom::*;
pub use ioc::*;
pub use loader::*;
pub use stage::*;
pub use yara::*;

use std::path::{Path, PathBuf};

pub(crate) const YARA_EXTENSIONS: &[&str] = &["yar", "yara"];
pub(crate) const CUSTOM_RULE_EXTENSIONS: &[&str] = &["toml"];

/// Rule files under `dir` (recursively, so `default/yara` and `custom/yara`
/// both load). Symlinked directories are not followed, so a loop can't hang it.
pub(crate) fn rule_files(dir: &Path, extensions: &[&str]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            files.extend(rule_files(&path, extensions));
        } else if has_extension(&path, extensions) {
            files.push(path);
        }
    }
    files.sort();
    files
}

pub(crate) fn has_extension(path: &Path, extensions: &[&str]) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| extensions.contains(&e))
}

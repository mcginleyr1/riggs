use std::io::Read;
use std::path::{Path, PathBuf};

use riggs_types::RiggsError;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Only the file prefix is scanned so a huge file can't exhaust agent memory
/// (same bound as static-ai's default).
const MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub tags: Vec<String>,
    pub matched_strings: Vec<String>,
}

pub struct YaraEngine {
    rules_dir: PathBuf,
    compiled_rules: Option<yara_x::Rules>,
}

impl YaraEngine {
    pub fn new(rules_dir: PathBuf) -> Result<Self, RiggsError> {
        if !rules_dir.is_dir() {
            return Err(RiggsError::Config(format!(
                "YARA rules directory does not exist: {}",
                rules_dir.display()
            )));
        }
        let mut engine = Self {
            rules_dir,
            compiled_rules: None,
        };
        engine.load_rules()?;
        Ok(engine)
    }

    pub fn load_rules(&mut self) -> Result<(), RiggsError> {
        let mut compiler = yara_x::Compiler::new();
        let mut count = 0;

        let entries = std::fs::read_dir(&self.rules_dir)
            .map_err(|e| RiggsError::Io(format!("failed to read rules dir: {e}")))?;

        for entry in entries {
            let entry = entry.map_err(|e| RiggsError::Io(format!("dir entry error: {e}")))?;
            let path = entry.path();

            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "yar" || ext == "yara" {
                        let source = std::fs::read_to_string(&path).map_err(|e| {
                            RiggsError::Io(format!("failed to read {}: {e}", path.display()))
                        })?;

                        match compiler.add_source(source.as_str()) {
                            Ok(_) => {
                                count += 1;
                            }
                            Err(e) => {
                                warn!(
                                    path = %path.display(),
                                    error = %e,
                                    "failed to compile YARA rule, skipping"
                                );
                            }
                        }
                    }
                }
            }
        }

        let rules = compiler.build();
        self.compiled_rules = Some(rules);
        info!(count, dir = %self.rules_dir.display(), "YARA rules compiled");
        Ok(())
    }

    pub fn scan_file(&self, path: &Path) -> Result<Vec<YaraMatch>, RiggsError> {
        let rules = self
            .compiled_rules
            .as_ref()
            .ok_or_else(|| RiggsError::Engine("YARA rules not compiled yet".to_string()))?;

        let mut data = Vec::new();
        std::fs::File::open(path)
            .and_then(|f| f.take(MAX_SCAN_BYTES).read_to_end(&mut data))
            .map_err(|e| RiggsError::Io(format!("failed to read {}: {e}", path.display())))?;

        let mut scanner = yara_x::Scanner::new(rules);
        let results = scanner
            .scan(&data)
            .map_err(|e| RiggsError::Engine(format!("YARA scan error: {e}")))?;

        let matches: Vec<YaraMatch> = results
            .matching_rules()
            .map(|rule| {
                let patterns: Vec<String> = rule
                    .patterns()
                    .flat_map(|p| {
                        let ident = p.identifier().to_string();
                        p.matches()
                            .map(move |m| format!("0x{:x}:{}", m.range().start, ident))
                    })
                    .collect();

                YaraMatch {
                    rule_name: rule.identifier().to_string(),
                    tags: rule.tags().map(|t| t.identifier().to_string()).collect(),
                    matched_strings: patterns,
                }
            })
            .collect();

        Ok(matches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_file_matches_rule() {
        let dir = std::env::temp_dir().join(format!("riggs-yara-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("t.yar"),
            r#"rule evil { strings: $a = "EVIL_MARKER" condition: $a }"#,
        )
        .unwrap();
        let sample = dir.join("sample.bin");
        std::fs::write(&sample, b"xxEVIL_MARKERxx").unwrap();

        let matches = YaraEngine::new(dir.clone())
            .unwrap()
            .scan_file(&sample)
            .unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "evil");
    }
}

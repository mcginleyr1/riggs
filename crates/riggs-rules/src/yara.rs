use std::path::{Path, PathBuf};

use riggs_types::RiggsError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub tags: Vec<String>,
    pub matched_strings: Vec<String>,
}

pub struct YaraEngine {
    rules_dir: PathBuf,
    // Will hold compiled yara-x rules once loaded
    // compiled_rules: Option<yara_x::Rules>,
}

impl YaraEngine {
    /// Create a new YaraEngine pointing at the given rules directory.
    pub fn new(rules_dir: PathBuf) -> Result<Self, RiggsError> {
        // TODO: use yara_x::Compiler to initialize
        todo!("initialize YaraEngine with yara-x crate; compile rules from {rules_dir:?}")
    }

    /// Load (or reload) all .yar files from the rules directory into a compiled ruleset.
    pub fn load_rules(&mut self) -> Result<(), RiggsError> {
        // TODO: walk rules_dir for *.yar files, feed each into yara_x::Compiler,
        // then call compiler.build() to produce compiled Rules
        todo!("load .yar files from {:?} using yara-x compiler", self.rules_dir)
    }

    /// Scan a single file against the compiled YARA rules.
    pub fn scan_file(&self, path: &Path) -> Result<Vec<YaraMatch>, RiggsError> {
        // TODO: read file bytes, create yara_x::Scanner from compiled rules,
        // call scanner.scan(&bytes), convert matching rules into Vec<YaraMatch>
        todo!("scan {path:?} with yara-x scanner and return matches")
    }
}

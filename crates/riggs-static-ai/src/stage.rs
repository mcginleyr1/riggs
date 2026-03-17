use std::path::{Path, PathBuf};

use async_trait::async_trait;
use chrono::Utc;
use tracing::{debug, warn};

use riggs_engine::{DetectionStage, StageVerdict};
use riggs_types::errors::RiggsError;
use riggs_types::events::RiggsEvent;
use riggs_types::verdict::{DetectionSource, Verdict};

use crate::analyzer::StaticAnalyzer;

pub struct StaticAiStage {
    analyzer: StaticAnalyzer,
    malicious_threshold: f32,
    suspicious_threshold: f32,
}

impl StaticAiStage {
    pub fn new(model_path: PathBuf) -> Self {
        Self {
            analyzer: StaticAnalyzer::new(model_path),
            malicious_threshold: 0.85,
            suspicious_threshold: 0.5,
        }
    }

    pub fn new_heuristic_only() -> Self {
        Self {
            analyzer: StaticAnalyzer::new_without_model(),
            malicious_threshold: 0.85,
            suspicious_threshold: 0.5,
        }
    }

    pub fn with_thresholds(
        model_path: PathBuf,
        suspicious_threshold: f32,
        malicious_threshold: f32,
    ) -> Self {
        Self {
            analyzer: StaticAnalyzer::new(model_path),
            malicious_threshold,
            suspicious_threshold,
        }
    }
}

#[async_trait]
impl DetectionStage for StaticAiStage {
    fn name(&self) -> &str {
        "static-ai"
    }

    async fn analyze(&self, event: &RiggsEvent) -> Result<StageVerdict, RiggsError> {
        let file_event = match event {
            RiggsEvent::File(fe) => fe,
            _ => {
                debug!("static-ai stage skipping non-file event");
                return Ok(StageVerdict::Clean);
            }
        };

        // Only scan newly created files — modifications/deletes don't introduce new binaries
        if file_event.action != riggs_types::events::FileAction::Create {
            return Ok(StageVerdict::Clean);
        }

        let path = Path::new(&file_event.path);
        if !path.exists() {
            debug!(path = %file_event.path, "file does not exist, skipping");
            return Ok(StageVerdict::Clean);
        }

        // Skip non-regular files (sockets, pipes, directories, symlinks)
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return Ok(StageVerdict::Clean),
        };
        if !metadata.is_file() || metadata.len() < 64 {
            return Ok(StageVerdict::Clean);
        }

        // Skip files that are clearly not executables
        let skip_extensions = ["txt", "log", "json", "toml", "yaml", "yml", "xml",
            "csv", "md", "rst", "html", "css", "js", "ts", "py", "rb", "sh",
            "conf", "cfg", "ini", "lock", "pid", "sock", "tmp"];
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if skip_extensions.iter().any(|&s| s.eq_ignore_ascii_case(ext)) {
                return Ok(StageVerdict::Clean);
            }
        }

        let confidence = match self.analyzer.analyze_file(path) {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, path = %file_event.path, "static analysis failed");
                return Ok(StageVerdict::Error(e.to_string()));
            }
        };

        let verdict = Verdict {
            event_id: file_event.event_id.clone(),
            threat_level: if confidence >= self.malicious_threshold {
                riggs_types::verdict::ThreatLevel::Malicious
            } else if confidence >= self.suspicious_threshold {
                riggs_types::verdict::ThreatLevel::Suspicious
            } else {
                riggs_types::verdict::ThreatLevel::Clean
            },
            confidence,
            source: DetectionSource::StaticAI,
            description: format!(
                "Static AI analysis of {} (confidence: {:.2})",
                file_event.path, confidence
            ),
            timestamp: Utc::now(),
        };

        if confidence >= self.malicious_threshold {
            Ok(StageVerdict::Malicious(verdict))
        } else if confidence >= self.suspicious_threshold {
            Ok(StageVerdict::Suspicious(verdict))
        } else {
            Ok(StageVerdict::Clean)
        }
    }
}

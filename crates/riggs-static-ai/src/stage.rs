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

    /// Override the max bytes read per file for analysis (operator-configurable).
    pub fn with_max_scan_bytes(mut self, max_scan_bytes: u64) -> Self {
        self.analyzer = self.analyzer.with_max_scan_bytes(max_scan_bytes);
        self
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

        // Skip files that are clearly not executables -- but only when the
        // content agrees. A binary renamed to invoice.txt still has executable
        // magic bytes and must be scanned, so the extension is trusted only for
        // files that do NOT begin with a known executable signature.
        let skip_extensions = [
            "txt", "log", "json", "toml", "yaml", "yml", "xml", "csv", "md", "rst", "html", "css",
            "js", "ts", "py", "rb", "sh", "conf", "cfg", "ini", "lock", "pid", "sock", "tmp",
        ];
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if skip_extensions.iter().any(|&s| s.eq_ignore_ascii_case(ext))
                && !has_executable_magic(path)
            {
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

/// True when the file begins with a known executable signature (ELF, Mach-O,
/// PE/DOS), regardless of its extension.
fn has_executable_magic(path: &Path) -> bool {
    use std::io::Read;
    let mut buf = [0u8; 4];
    match std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut buf)) {
        Ok(()) => {
            matches!(
                buf,
                [0x7f, b'E', b'L', b'F']        // ELF
                    | [0xFE, 0xED, 0xFA, 0xCE]  // Mach-O 32-bit
                    | [0xFE, 0xED, 0xFA, 0xCF]  // Mach-O 64-bit
                    | [0xCE, 0xFA, 0xED, 0xFE]  // Mach-O 32-bit (byte-swapped)
                    | [0xCF, 0xFA, 0xED, 0xFE]  // Mach-O 64-bit (byte-swapped)
                    | [0xCA, 0xFE, 0xBA, 0xBE] // Mach-O universal
            ) || buf[..2] == *b"MZ" // PE / DOS
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(name: &str, bytes: &[u8]) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "riggs-static-ai-test-{}-{name}",
            std::process::id()
        ));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(bytes).unwrap();
        path
    }

    #[test]
    fn detects_elf_magic_despite_extension() {
        let path = write_temp("fake.txt", b"\x7fELF and some more bytes here");
        assert!(has_executable_magic(&path));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn plain_text_has_no_executable_magic() {
        let path = write_temp("real.txt", b"just some plain text content here");
        assert!(!has_executable_magic(&path));
        let _ = std::fs::remove_file(&path);
    }
}

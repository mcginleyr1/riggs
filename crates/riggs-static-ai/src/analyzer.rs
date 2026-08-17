use std::path::{Path, PathBuf};

use thiserror::Error;
use tracing::debug;

use crate::features::{FeatureError, FileFeatures};

#[derive(Debug, Error)]
pub enum AnalyzerError {
    #[error("feature extraction failed: {0}")]
    FeatureExtraction(#[from] FeatureError),

    #[error("model inference failed: {0}")]
    Inference(String),
}

pub struct StaticAnalyzer {
    model_path: Option<PathBuf>,
    max_scan_bytes: u64,
}

impl StaticAnalyzer {
    pub fn new(model_path: PathBuf) -> Self {
        Self {
            model_path: Some(model_path),
            max_scan_bytes: crate::features::DEFAULT_MAX_SCAN_BYTES,
        }
    }

    pub fn new_without_model() -> Self {
        Self {
            model_path: None,
            max_scan_bytes: crate::features::DEFAULT_MAX_SCAN_BYTES,
        }
    }

    /// Override the max bytes read per file for analysis.
    pub fn with_max_scan_bytes(mut self, max_scan_bytes: u64) -> Self {
        self.max_scan_bytes = max_scan_bytes;
        self
    }

    pub fn has_model(&self) -> bool {
        self.model_path.is_some()
    }

    pub fn analyze_file(&self, path: &Path) -> Result<f32, AnalyzerError> {
        let features = FileFeatures::extract_with_limit(path, self.max_scan_bytes)?;

        debug!(
            file = %path.display(),
            size = features.file_size,
            entropy = features.entropy,
            sections = features.section_count,
            imports = features.import_count,
            packed = features.is_packed,
            suspicious_imports = features.suspicious_imports.len(),
            suspicious_strings = features.suspicious_strings.len(),
            "extracted file features"
        );

        let confidence = match &self.model_path {
            Some(_path) => {
                // TODO: Load ONNX model from path and run inference via ort crate.
                // Until that is wired up, fall back to heuristics.
                debug!("ONNX model not yet integrated, falling back to heuristic score");
                features.heuristic_score()
            }
            None => features.heuristic_score(),
        };

        Ok(confidence)
    }
}

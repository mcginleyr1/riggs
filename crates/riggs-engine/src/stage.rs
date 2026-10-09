use async_trait::async_trait;
use riggs_types::errors::RiggsError;
use riggs_types::events::RiggsEvent;
use riggs_types::verdict::{DetectionSource, Verdict};

#[derive(Debug, Clone)]
pub enum StageVerdict {
    Clean,
    Suspicious(Verdict),
    Malicious(Verdict),
    Error(String),
}

#[async_trait]
pub trait DetectionStage: Send + Sync + 'static {
    fn name(&self) -> &str;
    /// Credited on verdicts the pipeline issues for the stage, e.g. when its
    /// analysis runs out of time.
    fn source(&self) -> DetectionSource;
    async fn analyze(&self, event: &RiggsEvent) -> Result<StageVerdict, RiggsError>;
}

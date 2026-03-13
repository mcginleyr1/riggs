use async_trait::async_trait;
use riggs_types::events::RiggsEvent;
use riggs_types::verdict::Verdict;
use riggs_types::errors::RiggsError;

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
    async fn analyze(&self, event: &RiggsEvent) -> Result<StageVerdict, RiggsError>;
}

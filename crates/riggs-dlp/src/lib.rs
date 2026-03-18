pub mod correlator;
pub mod magic;
pub mod policy;
pub mod reload;
pub mod stage;

pub use correlator::{DlpCorrelator, FlowAction, FlowVerdict};
pub use magic::SensitiveFileType;
pub use policy::{DlpAction, DlpPolicy};
pub use reload::{find_policy_file, load_policy_file, watch_policy};
pub use stage::{DlpDetection, DlpStage};

/// Action taken on the flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DlpEventAction {
    Block,
    Alert,
}

use serde::{Serialize, Deserialize};
use riggs_types::events::RiggsEvent;
use riggs_types::verdict::MergedVerdict;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientMessage {
    GetStatus,
    QueryEvents { storyline_id: Option<String>, limit: usize },
    QueryThreats { min_severity: String },
    GetConfig,
    UpdateConfig { key: String, value: String },
    TriggerScan { path: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonMessage {
    Status { running: bool, events_processed: u64, active_threats: u32 },
    Events(Vec<RiggsEvent>),
    Threats(Vec<MergedVerdict>),
    Config(String),
    Ok,
    Error(String),
}

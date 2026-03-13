use std::fmt;

use chrono::{DateTime, Utc};
use riggs_types::events::{EventId, StorylineId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseAction {
    KillProcess { pid: u32 },
    SuspendProcess { pid: u32 },
    QuarantineFile { path: std::path::PathBuf },
    DeleteFile { path: std::path::PathBuf },
    NetworkContain { allowed_ips: Vec<std::net::IpAddr> },
    NetworkRelease,
    Rollback { storyline_id: StorylineId },
}

impl fmt::Display for ResponseAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResponseAction::KillProcess { pid } => {
                write!(f, "Kill process (PID {})", pid)
            }
            ResponseAction::SuspendProcess { pid } => {
                write!(f, "Suspend process (PID {})", pid)
            }
            ResponseAction::QuarantineFile { path } => {
                write!(f, "Quarantine file {}", path.display())
            }
            ResponseAction::DeleteFile { path } => {
                write!(f, "Delete file {}", path.display())
            }
            ResponseAction::NetworkContain { allowed_ips } => {
                let ips: Vec<String> = allowed_ips.iter().map(|ip| ip.to_string()).collect();
                write!(f, "Network containment (allow: {})", ips.join(", "))
            }
            ResponseAction::NetworkRelease => {
                write!(f, "Release network containment")
            }
            ResponseAction::Rollback { storyline_id } => {
                write!(f, "Rollback storyline {}", storyline_id.0)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseRecord {
    pub id: Uuid,
    pub action: ResponseAction,
    pub event_id: EventId,
    pub storyline_id: Option<StorylineId>,
    pub executed_at: DateTime<Utc>,
    pub success: bool,
    pub detail: String,
}

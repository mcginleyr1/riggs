use serde::{Deserialize, Serialize};

use riggs_types::events::RiggsEvent;
use riggs_types::verdict::MergedVerdict;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientMessage {
    GetStatus,
    QueryEvents {
        storyline_id: Option<String>,
        limit: usize,
    },
    QueryThreats {
        min_severity: String,
    },
    GetConfig,
    UpdateConfig {
        key: String,
        value: String,
    },
    TriggerScan {
        path: String,
    },
    RefreshFeeds,
    VulnUpdate,
    IntelStatus,
    DlpCheckFlow {
        pid: u32,
        remote_hostname: String,
        remote_ip: String,
        remote_port: u16,
    },
    DlpStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonMessage {
    Status {
        running: bool,
        events_processed: u64,
        active_threats: u32,
    },
    Events(Vec<RiggsEvent>),
    Threats(Vec<MergedVerdict>),
    Config(String),
    IntelStatus {
        bloom_size: usize,
        cache_entries: u64,
        feeds_last_updated: Option<String>,
    },
    Ok,
    Error(String),
    DlpVerdict {
        allow: bool,
        reason: Option<String>,
    },
    DlpStatus {
        enabled: bool,
        tracked_pids: usize,
        tracked_accesses: usize,
        watched_domains: usize,
    },
}

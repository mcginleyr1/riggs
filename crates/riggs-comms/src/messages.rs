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
    QuarantineList,
    QuarantineRestore {
        id: String,
    },
    VulnUpdate,
    IntelStatus,
    DlpCheckFlow {
        pid: u32,
        remote_hostname: String,
        remote_ip: String,
        remote_port: u16,
    },
    DlpStatus,
    EgressCheckFlow {
        pid: u32,
        process_path: String,
        remote_hostname: String,
        remote_ip: String,
        remote_port: u16,
    },
    EgressStatus,
    EgressAllow {
        domain: String,
    },
    EgressDeny {
        domain: String,
    },
    EgressSetMode {
        mode: String,
    },
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
    Quarantine(Vec<QuarantinedFile>),
    Config(String),
    IntelStatus {
        bloom_size: usize,
        cache_entries: u64,
        feeds_last_updated: Option<String>,
    },
    Ok,
    /// A privileged command succeeded; the text describes what happened.
    Done(String),
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
    EgressVerdict {
        allow: bool,
        would_block: bool,
        reason: Option<String>,
        mode: String,
    },
    EgressStatus {
        mode: String,
        allow_domains: usize,
        process_rules: usize,
    },
}

/// A file held in the daemon's quarantine vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinedFile {
    pub id: String,
    pub original_path: String,
    pub quarantined_at: String,
    pub file_size: u64,
    pub sha256: Option<String>,
}

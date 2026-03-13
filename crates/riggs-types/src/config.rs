use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiggsConfig {
    pub sensor: SensorConfig,
    pub engine: EngineConfig,
    pub store: StoreConfig,
    pub comms: CommsConfig,
    pub response: ResponseConfig,
}

impl Default for RiggsConfig {
    fn default() -> Self {
        Self {
            sensor: SensorConfig::default(),
            engine: EngineConfig::default(),
            store: StoreConfig::default(),
            comms: CommsConfig::default(),
            response: ResponseConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorConfig {
    pub enabled_sources: Vec<String>,
    pub poll_interval_ms: u64,
}

impl Default for SensorConfig {
    fn default() -> Self {
        Self {
            enabled_sources: vec![
                "process".into(),
                "file".into(),
                "network".into(),
                "dns".into(),
                "auth".into(),
            ],
            poll_interval_ms: 100,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    pub static_ai_enabled: bool,
    pub behavioral_ai_enabled: bool,
    pub rules_enabled: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            static_ai_enabled: true,
            behavioral_ai_enabled: true,
            rules_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreConfig {
    pub db_path: String,
    pub retention_days: u32,
    pub compression_enabled: bool,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            db_path: "/var/lib/riggs/riggs.db".into(),
            retention_days: 90,
            compression_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommsConfig {
    pub cloud_enabled: bool,
    pub cloud_endpoint: Option<String>,
    pub heartbeat_interval_secs: u64,
}

impl Default for CommsConfig {
    fn default() -> Self {
        Self {
            cloud_enabled: false,
            cloud_endpoint: None,
            heartbeat_interval_secs: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseConfig {
    pub auto_respond: bool,
    pub kill_on_critical: bool,
    pub quarantine_on_malicious: bool,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            auto_respond: true,
            kill_on_critical: true,
            quarantine_on_malicious: true,
        }
    }
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RiggsConfig {
    pub sensor: SensorConfig,
    pub engine: EngineConfig,
    pub store: StoreConfig,
    pub comms: CommsConfig,
    pub response: ResponseConfig,
    #[serde(default)]
    pub intel: IntelConfig,
    #[serde(default)]
    pub dlp: DlpConfig,
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
    #[serde(default = "default_socket_path")]
    pub socket_path: String,
    pub cloud_enabled: bool,
    pub cloud_endpoint: Option<String>,
    pub enrollment_token: Option<String>,
    pub heartbeat_interval_secs: u64,
}

fn default_socket_path() -> String {
    "/var/run/riggs.sock".into()
}

impl Default for CommsConfig {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
            cloud_enabled: false,
            cloud_endpoint: None,
            enrollment_token: None,
            heartbeat_interval_secs: 30,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelConfig {
    pub enabled: bool,
    pub cache_path: String,
    pub cache_ttl_clean_hours: u32,
    pub cache_ttl_malicious_hours: u32,
    pub virustotal: VtConfig,
    pub abuseipdb: AbuseIpdbConfig,
    pub feeds: FeedsConfig,
}

impl Default for IntelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_path: "/var/lib/riggs/intel_cache.db".into(),
            cache_ttl_clean_hours: 24,
            cache_ttl_malicious_hours: 168,
            virustotal: VtConfig::default(),
            abuseipdb: AbuseIpdbConfig::default(),
            feeds: FeedsConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VtConfig {
    pub enabled: bool,
    pub api_key: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AbuseIpdbConfig {
    pub enabled: bool,
    pub api_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedsConfig {
    pub malwarebazaar_enabled: bool,
    pub malwarebazaar_interval_hours: u32,
    pub urlhaus_enabled: bool,
    pub urlhaus_interval_hours: u32,
    pub osv_enabled: bool,
    pub osv_interval_hours: u32,
}

impl Default for FeedsConfig {
    fn default() -> Self {
        Self {
            malwarebazaar_enabled: true,
            malwarebazaar_interval_hours: 24,
            urlhaus_enabled: true,
            urlhaus_interval_hours: 1,
            osv_enabled: true,
            osv_interval_hours: 24,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpConfig {
    pub enabled: bool,
    pub action: String,
    pub correlation_window_secs: u64,
    #[serde(default)]
    pub watched_domains: Vec<WatchedDomain>,
    #[serde(default)]
    pub file_types: DlpFileTypes,
    #[serde(default)]
    pub excluded_processes: DlpExclusions,
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            action: "block".into(),
            correlation_window_secs: 30,
            watched_domains: vec![
                WatchedDomain {
                    pattern: "claude.ai".into(),
                    category: "ai-assistant".into(),
                },
                WatchedDomain {
                    pattern: "*.anthropic.com".into(),
                    category: "ai-assistant".into(),
                },
                WatchedDomain {
                    pattern: "chatgpt.com".into(),
                    category: "ai-assistant".into(),
                },
                WatchedDomain {
                    pattern: "*.openai.com".into(),
                    category: "ai-assistant".into(),
                },
            ],
            file_types: DlpFileTypes::default(),
            excluded_processes: DlpExclusions::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchedDomain {
    pub pattern: String,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpFileTypes {
    pub block: Vec<String>,
    pub alert: Vec<String>,
}

impl Default for DlpFileTypes {
    fn default() -> Self {
        Self {
            block: vec![
                "pptx".into(),
                "xlsx".into(),
                "docx".into(),
                "pdf".into(),
                "ppt".into(),
                "xls".into(),
                "doc".into(),
            ],
            alert: vec!["csv".into(), "json".into()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpExclusions {
    pub names: Vec<String>,
}

impl Default for DlpExclusions {
    fn default() -> Self {
        Self {
            names: vec!["softwareupdated".into(), "nsurlsessiond".into()],
        }
    }
}

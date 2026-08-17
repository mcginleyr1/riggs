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
    #[serde(default)]
    pub detection: DetectionConfig,
    #[serde(default)]
    pub egress: EgressConfig,
}

/// Default-deny egress allowlist: an endpoint may only reach the hosts an
/// operator has allowed (plus a system baseline). Rules can be scoped to a
/// process so package managers/build tools are locked to their registries while
/// other traffic follows the global policy. Hot-reloaded from a TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressConfig {
    /// Feature master switch. When false the evaluator always allows.
    #[serde(default)]
    pub enabled: bool,
    /// "off" (allow all), "monitor" (log would-block), or "enforce" (drop).
    #[serde(default = "default_egress_mode")]
    pub mode: String,
    /// Globally allowed destination domain patterns (exact or `*.` wildcard).
    #[serde(default)]
    pub allow_domains: Vec<String>,
    /// Globally allowed destination CIDRs (for IP-literal / no-SNI flows).
    #[serde(default)]
    pub allow_cidrs: Vec<String>,
    /// Optional destination-port allowlist; empty means any port.
    #[serde(default)]
    pub allow_ports: Vec<u16>,
    /// System baseline always permitted so the host can't strand itself.
    #[serde(default)]
    pub baseline: EgressBaseline,
    /// Per-process rules. A flow from a matching process is restricted to that
    /// rule's destinations (not the global allowlist).
    #[serde(default)]
    pub process_rules: Vec<EgressProcessRule>,
}

fn default_egress_mode() -> String {
    "monitor".into()
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: default_egress_mode(),
            allow_domains: Vec::new(),
            allow_cidrs: Vec::new(),
            allow_ports: Vec::new(),
            baseline: EgressBaseline::default(),
            process_rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressBaseline {
    #[serde(default = "default_true")]
    pub dns: bool,
    #[serde(default = "default_true")]
    pub dhcp_ntp: bool,
    #[serde(default = "default_true")]
    pub loopback: bool,
}

impl Default for EgressBaseline {
    fn default() -> Self {
        Self {
            dns: true,
            dhcp_ntp: true,
            loopback: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressProcessRule {
    /// Process name to match (basename; case-insensitive substring).
    pub process: String,
    #[serde(default)]
    pub allow_domains: Vec<String>,
    #[serde(default)]
    pub allow_cidrs: Vec<String>,
}

/// Behavioral/heuristic detection thresholds and signatures. These are tuning
/// for detection logic (kept separate from [engine] plumbing) so operators can
/// adjust sensitivity and add environment-specific persistence locations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Outbound connections in a storyline before flagging data exfiltration.
    pub exfil_outbound_threshold: usize,
    /// Distinct files modified within the window before flagging rapid encryption.
    pub rapid_encryption_file_threshold: usize,
    /// Sliding window (seconds) for the rapid-encryption check.
    pub rapid_encryption_window_secs: i64,
    /// Storyline threat score above which a storyline is considered a threat.
    pub threat_score_threshold: f32,
    /// Filesystem locations treated as persistence mechanisms when written.
    pub persistence_paths: Vec<String>,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            exfil_outbound_threshold: 50,
            rapid_encryption_file_threshold: 10,
            rapid_encryption_window_secs: 5,
            threat_score_threshold: 0.5,
            persistence_paths: vec![
                "/Library/LaunchDaemons".into(),
                "/Library/LaunchAgents".into(),
                "~/Library/LaunchAgents".into(),
                ".config/autostart".into(),
                "/etc/cron.d".into(),
                "/etc/crontab".into(),
                "/var/spool/cron".into(),
                "/etc/systemd/system".into(),
                "/usr/lib/systemd/system".into(),
                "/etc/init.d".into(),
                "/etc/rc.local".into(),
            ],
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
    /// Weighted-merge threshold at/above which the final verdict is Malicious.
    #[serde(default = "default_malicious_threshold")]
    pub merge_malicious_threshold: f32,
    /// Weighted-merge threshold at/above which the final verdict is Suspicious.
    #[serde(default = "default_suspicious_threshold")]
    pub merge_suspicious_threshold: f32,
    /// Max MiB of a file read for static analysis (headers/strings live early).
    #[serde(default = "default_static_ai_max_scan_mib")]
    pub static_ai_max_scan_mib: u64,
    /// Behavioral tracker: max events retained per storyline.
    #[serde(default = "default_behavioral_max_events")]
    pub behavioral_max_events_per_storyline: usize,
    /// Behavioral tracker: max storylines tracked before evicting the idlest.
    #[serde(default = "default_behavioral_max_storylines")]
    pub behavioral_max_storylines: usize,
    /// Storyline correlator: max event ids retained per storyline.
    #[serde(default = "default_storyline_max_events")]
    pub storyline_max_events: usize,
    /// Storyline correlator: prune storylines idle longer than this (seconds).
    #[serde(default = "default_storyline_idle_secs")]
    pub storyline_idle_secs: u64,
    /// Path to the static-AI ONNX model.
    #[serde(default = "default_static_ai_model_path")]
    pub static_ai_model_path: String,
    /// How often (seconds) idle storylines are pruned.
    #[serde(default = "default_storyline_prune_interval_secs")]
    pub storyline_prune_interval_secs: u64,
    /// Health-check log/task cadence in seconds.
    #[serde(default = "default_health_check_secs")]
    pub health_check_secs: u64,
    /// How often (seconds) retention cleanup runs.
    #[serde(default = "default_retention_sweep_secs")]
    pub retention_sweep_secs: u64,
}

fn default_static_ai_model_path() -> String {
    "/var/lib/riggs/models/static.onnx".into()
}

fn default_storyline_prune_interval_secs() -> u64 {
    60
}

fn default_health_check_secs() -> u64 {
    30
}

fn default_retention_sweep_secs() -> u64 {
    6 * 60 * 60
}

fn default_malicious_threshold() -> f32 {
    0.7
}

fn default_suspicious_threshold() -> f32 {
    0.3
}

fn default_static_ai_max_scan_mib() -> u64 {
    64
}

fn default_behavioral_max_events() -> usize {
    512
}

fn default_behavioral_max_storylines() -> usize {
    4096
}

fn default_storyline_max_events() -> usize {
    1024
}

fn default_storyline_idle_secs() -> u64 {
    3600
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            static_ai_enabled: true,
            behavioral_ai_enabled: true,
            rules_enabled: true,
            merge_malicious_threshold: default_malicious_threshold(),
            merge_suspicious_threshold: default_suspicious_threshold(),
            static_ai_max_scan_mib: default_static_ai_max_scan_mib(),
            behavioral_max_events_per_storyline: default_behavioral_max_events(),
            behavioral_max_storylines: default_behavioral_max_storylines(),
            storyline_max_events: default_storyline_max_events(),
            storyline_idle_secs: default_storyline_idle_secs(),
            static_ai_model_path: default_static_ai_model_path(),
            storyline_prune_interval_secs: default_storyline_prune_interval_secs(),
            health_check_secs: default_health_check_secs(),
            retention_sweep_secs: default_retention_sweep_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreConfig {
    pub db_path: String,
    pub retention_days: u32,
    pub compression_enabled: bool,
    /// Max (event, verdict) pairs coalesced into one write transaction. Higher
    /// = fewer fsyncs under load, at the cost of more events lost on a crash.
    #[serde(default = "default_store_batch_max")]
    pub batch_max: usize,
    /// Flush a partial batch after this many milliseconds even if `batch_max`
    /// hasn't been reached, bounding write latency when traffic is light.
    #[serde(default = "default_store_batch_flush_ms")]
    pub batch_flush_ms: u64,
}

fn default_store_batch_max() -> usize {
    64
}

fn default_store_batch_flush_ms() -> u64 {
    250
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            db_path: "/var/lib/riggs/riggs.db".into(),
            retention_days: 90,
            compression_enabled: true,
            batch_max: default_store_batch_max(),
            batch_flush_ms: default_store_batch_flush_ms(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommsConfig {
    #[serde(default = "default_socket_path")]
    pub socket_path: String,
    pub cloud_enabled: bool,
    pub cloud_endpoint: Option<String>,
    // Secret: never expose over IPC (GetConfig serializes this struct).
    #[serde(skip_serializing)]
    pub enrollment_token: Option<String>,
    pub heartbeat_interval_secs: u64,
    #[serde(default)]
    pub tls: CloudTlsConfig,
    /// Require TLS for the console connection. When true (default), the agent
    /// refuses to send its enrollment token over a non-https endpoint. Set false
    /// for deployments that terminate TLS elsewhere or accept cleartext.
    #[serde(default = "default_true")]
    pub require_tls: bool,
    /// Max bytes accepted for a single IPC request frame (DoS guard).
    #[serde(default = "default_ipc_max_message_bytes")]
    pub ipc_max_message_bytes: usize,
    /// Max concurrent IPC client handlers.
    #[serde(default = "default_ipc_max_connections")]
    pub ipc_max_connections: usize,
}

fn default_true() -> bool {
    true
}

fn default_ipc_max_message_bytes() -> usize {
    8 * 1024 * 1024
}

fn default_ipc_max_connections() -> usize {
    32
}

/// mTLS material for the agent's connection to the Murtaugh console.
///
/// Bring-your-own-PKI: your organization's CA signs both the console's server
/// certificate and each agent's client certificate. The agent verifies the
/// console against `ca_cert_path` and presents `client_cert_path` /
/// `client_key_path` for mutual authentication. Paths point to PEM files.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CloudTlsConfig {
    /// CA (PEM) that signed the console's server certificate. Required for https.
    pub ca_cert_path: Option<String>,
    /// This agent's client certificate (PEM), signed by your CA.
    pub client_cert_path: Option<String>,
    /// This agent's client private key (PEM). Secret.
    #[serde(skip_serializing)]
    pub client_key_path: Option<String>,
    /// Server name to verify in the console's certificate (defaults to the host
    /// in `cloud_endpoint`). Set when the cert CN/SAN differs from the dial host.
    pub domain_name: Option<String>,
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
            tls: CloudTlsConfig::default(),
            require_tls: true,
            ipc_max_message_bytes: default_ipc_max_message_bytes(),
            ipc_max_connections: default_ipc_max_connections(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseConfig {
    pub auto_respond: bool,
    pub kill_on_critical: bool,
    pub quarantine_on_malicious: bool,
    /// Directory where quarantined files are stored.
    #[serde(default = "default_quarantine_path")]
    pub quarantine_path: String,
    /// Path the macOS network-containment pf ruleset is written to (off /tmp).
    #[serde(default = "default_pf_conf_path")]
    pub pf_conf_path: String,
}

fn default_quarantine_path() -> String {
    "/var/lib/riggs/quarantine".into()
}

fn default_pf_conf_path() -> String {
    "/var/lib/riggs/pf-containment.conf".into()
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            auto_respond: true,
            kill_on_critical: true,
            quarantine_on_malicious: true,
            quarantine_path: default_quarantine_path(),
            pf_conf_path: default_pf_conf_path(),
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
    /// Initial capacity of the in-memory malware-hash bloom filter.
    #[serde(default = "default_bloom_capacity")]
    pub bloom_capacity: usize,
    /// Target false-positive rate for the bloom filter.
    #[serde(default = "default_bloom_fp_rate")]
    pub bloom_false_positive_rate: f64,
}

fn default_bloom_capacity() -> usize {
    1_000_000
}

fn default_bloom_fp_rate() -> f64 {
    0.001
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
            bloom_capacity: default_bloom_capacity(),
            bloom_false_positive_rate: default_bloom_fp_rate(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VtConfig {
    pub enabled: bool,
    // Secret: never expose over IPC (GetConfig serializes this struct).
    #[serde(skip_serializing)]
    pub api_key: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AbuseIpdbConfig {
    pub enabled: bool,
    // Secret: never expose over IPC (GetConfig serializes this struct).
    #[serde(skip_serializing)]
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

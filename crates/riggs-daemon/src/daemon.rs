use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;

use riggs_behavioral_ai::BehavioralAiStage;
use riggs_dlp::stage::DlpDetection;
use riggs_dlp::{DlpCorrelator, DlpPolicy, DlpStage};
use riggs_engine::DetectionPipeline;
use riggs_intel::clients::abuseipdb::AbuseIpdbClient;
use riggs_intel::clients::virustotal::VtClient;
use riggs_intel::{BloomFilter, FeedManager, FeedUpdate, HashVerdictCache, ThreatIntelStage};
use riggs_rules::{Ioc, IocMatcher, IocType, RulesStage};
use riggs_static_ai::StaticAiStage;
use riggs_store::RiggsStore;
use riggs_storyline::StorylineCorrelator;
use riggs_types::config::RiggsConfig;
use riggs_types::errors::RiggsError;
use riggs_types::events::RiggsEvent;
use riggs_types::verdict::{MergedVerdict, ThreatLevel};
use riggs_types::Severity;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::supervisor::Supervisor;

struct StoreAdapter(Arc<RiggsStore>);

impl riggs_comms::StoreQuery for StoreAdapter {
    fn recent_events(&self, limit: usize) -> Vec<RiggsEvent> {
        self.0.get_recent_events(limit).unwrap_or_default()
    }

    fn threats_above_clean(&self, limit: usize) -> Vec<MergedVerdict> {
        self.0.get_verdicts_above_clean(limit).unwrap_or_default()
    }
}

struct DlpAdapter {
    correlator: Arc<DlpCorrelator>,
    policy: Arc<DlpPolicy>,
}

impl riggs_comms::DlpQuery for DlpAdapter {
    fn check_flow(
        &self,
        pid: u32,
        hostname: &str,
        _remote_ip: &str,
        _remote_port: u16,
    ) -> riggs_comms::DlpFlowVerdict {
        let verdict = self.correlator.check_flow(pid, hostname);
        riggs_comms::DlpFlowVerdict {
            allow: verdict.allow,
            reason: verdict.reason,
        }
    }

    fn status(&self) -> riggs_comms::DlpQueryStatus {
        riggs_comms::DlpQueryStatus {
            enabled: true,
            tracked_pids: self.correlator.active_pid_count(),
            tracked_accesses: self.correlator.total_tracked_accesses(),
            watched_domains: self.policy.watched_domains.len(),
        }
    }
}

struct EgressAdapter {
    engine: Arc<riggs_egress::EgressEngine>,
    policy_path: PathBuf,
    config: std::sync::Mutex<riggs_types::config::EgressConfig>,
}

impl EgressAdapter {
    /// Mutate the egress config, persist it to the policy file, and hot-reload
    /// the live policy so a local `riggs egress` edit takes effect immediately.
    fn mutate(&self, f: impl FnOnce(&mut riggs_types::config::EgressConfig)) -> Result<(), String> {
        let mut guard = self
            .config
            .lock()
            .map_err(|_| "egress config lock poisoned".to_string())?;
        f(&mut guard);

        let toml_str =
            toml::to_string_pretty(&*guard).map_err(|e| format!("serialize egress policy: {e}"))?;
        if let Some(parent) = self.policy_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&self.policy_path, toml_str)
            .map_err(|e| format!("write {}: {e}", self.policy_path.display()))?;

        self.engine
            .replace_policy(riggs_egress::EgressPolicy::from_config(&guard));
        Ok(())
    }
}

impl riggs_comms::EgressQuery for EgressAdapter {
    fn check(
        &self,
        pid: u32,
        process_path: &str,
        hostname: &str,
        remote_ip: &str,
        remote_port: u16,
    ) -> riggs_comms::EgressFlowVerdict {
        let process = egress_process_name(process_path);
        let host = (!hostname.is_empty()).then_some(hostname);
        let ip = remote_ip.parse::<std::net::IpAddr>().ok();

        let decision = self
            .engine
            .evaluate(process.as_deref(), host, ip, remote_port);

        if decision.would_block {
            warn!(
                pid,
                process = %process.as_deref().unwrap_or("?"),
                dest = %hostname,
                mode = %decision.mode.as_str(),
                dropped = !decision.allow,
                reason = %decision.reason,
                "egress would-block"
            );
        }

        riggs_comms::EgressFlowVerdict {
            allow: decision.allow,
            would_block: decision.would_block,
            reason: Some(decision.reason),
            mode: decision.mode.as_str().to_string(),
        }
    }

    fn status(&self) -> riggs_comms::EgressQueryStatus {
        let (mode, allow_domains, process_rules) = self.engine.status();
        riggs_comms::EgressQueryStatus {
            mode: mode.as_str().to_string(),
            allow_domains,
            process_rules,
        }
    }

    fn allow_domain(&self, domain: &str) -> Result<(), String> {
        let domain = domain.trim().to_string();
        if domain.is_empty() {
            return Err("empty domain".into());
        }
        self.mutate(|c| {
            if !c.allow_domains.iter().any(|d| d == &domain) {
                c.allow_domains.push(domain.clone());
            }
        })
    }

    fn deny_domain(&self, domain: &str) -> Result<(), String> {
        let domain = domain.trim().to_string();
        self.mutate(|c| c.allow_domains.retain(|d| d != &domain))
    }

    fn set_mode(&self, mode: &str) -> Result<(), String> {
        let m = mode.trim().to_ascii_lowercase();
        let enabled = match m.as_str() {
            "off" => false,
            "monitor" | "enforce" => true,
            _ => {
                return Err(format!(
                    "invalid mode '{mode}' (use off | monitor | enforce)"
                ))
            }
        };
        self.mutate(move |c| {
            c.enabled = enabled;
            c.mode = m;
        })
    }
}

fn egress_process_name(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    Some(
        std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(path)
            .to_string(),
    )
}

const CONFIG_PATHS: &[&str] = &["/etc/riggs/riggs.toml", "config/riggs.toml"];
/// Resolve when the daemon should shut down: SIGINT (Ctrl-C) or SIGTERM.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sigterm.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

pub struct RiggsDaemon {
    config: RiggsConfig,
    supervisor: Supervisor,
}

impl RiggsDaemon {
    pub async fn new() -> Result<Self, RiggsError> {
        let config = Self::load_config()?;
        let supervisor = Supervisor::new();

        Ok(Self { config, supervisor })
    }

    fn load_config() -> Result<RiggsConfig, RiggsError> {
        let mut config = 'file: {
            for config_path in CONFIG_PATHS {
                let path = std::path::Path::new(config_path);
                if path.exists() {
                    let contents = std::fs::read_to_string(path).map_err(|e| {
                        RiggsError::Config(format!("failed to read {config_path}: {e}"))
                    })?;
                    let cfg: RiggsConfig = toml::from_str(&contents).map_err(|e| {
                        RiggsError::Config(format!("failed to parse {config_path}: {e}"))
                    })?;
                    info!(path = config_path, "loaded configuration");
                    break 'file cfg;
                }
            }
            info!("no config file found, using defaults");
            RiggsConfig::default()
        };

        // Environment variable overrides (useful for Docker/container deployments)
        if let Ok(url) = std::env::var("RIGGS_CONSOLE_URL") {
            config.comms.cloud_enabled = true;
            config.comms.cloud_endpoint = Some(url);
        }
        if let Ok(token) = std::env::var("RIGGS_ENROLL_TOKEN") {
            config.comms.enrollment_token = Some(token);
        }

        Ok(config)
    }

    pub async fn run(&mut self) -> Result<(), RiggsError> {
        info!("initializing components...");

        let (event_tx, mut event_rx) = mpsc::channel::<RiggsEvent>(10_000);
        let (verdict_tx, verdict_rx) = mpsc::channel::<MergedVerdict>(10_000);
        let (dlp_tx, dlp_rx) = mpsc::channel::<DlpDetection>(1_000);

        // -- Shared daemon state (used by IPC server + feed dispatcher) --
        let daemon_state = Arc::new(riggs_comms::DaemonState::new());

        // Serialize config into state for IPC queries
        if let Ok(config_json) = serde_json::to_string_pretty(&self.config) {
            if let Ok(mut guard) = daemon_state.config_json.write() {
                *guard = config_json;
            }
        }

        // -- Detection pipeline --
        let mut pipeline = DetectionPipeline::new(verdict_tx).with_merge_thresholds(
            self.config.engine.merge_malicious_threshold,
            self.config.engine.merge_suspicious_threshold,
        );

        if self.config.engine.static_ai_enabled {
            let model_path = PathBuf::from(&self.config.engine.static_ai_model_path);
            let max_scan_bytes = self.config.engine.static_ai_max_scan_mib * 1024 * 1024;
            pipeline.add_stage(Box::new(
                StaticAiStage::new(model_path).with_max_scan_bytes(max_scan_bytes),
            ));
        }

        let ioc_handle: Arc<StdRwLock<Option<IocMatcher>>> = Arc::new(StdRwLock::new(None));

        if self.config.engine.rules_enabled {
            let rules_stage = RulesStage::new_with_shared_ioc(None, Arc::clone(&ioc_handle), None);
            pipeline.add_stage(Box::new(rules_stage));
        }

        if self.config.engine.behavioral_ai_enabled {
            pipeline.add_stage(Box::new(BehavioralAiStage::configured(
                self.config.engine.behavioral_max_events_per_storyline,
                self.config.engine.behavioral_max_storylines,
                &self.config.detection,
            )));
        }

        // -- Threat intelligence stage --
        let bloom: Arc<StdRwLock<BloomFilter>> = Arc::new(StdRwLock::new(BloomFilter::new(
            self.config.intel.bloom_capacity,
            self.config.intel.bloom_false_positive_rate,
        )));

        if self.config.intel.enabled {
            let cache_path = PathBuf::from(&self.config.intel.cache_path);
            match HashVerdictCache::new(
                &cache_path,
                self.config.intel.cache_ttl_clean_hours,
                self.config.intel.cache_ttl_malicious_hours,
            ) {
                Ok(cache) => {
                    let cache = Arc::new(cache);

                    let vt_client = if self.config.intel.virustotal.enabled
                        && !self.config.intel.virustotal.api_key.is_empty()
                    {
                        info!("VirusTotal client enabled");
                        Some(VtClient::new(self.config.intel.virustotal.api_key.clone()))
                    } else {
                        None
                    };

                    let abuseipdb_client = if self.config.intel.abuseipdb.enabled
                        && !self.config.intel.abuseipdb.api_key.is_empty()
                    {
                        info!("AbuseIPDB client enabled");
                        Some(AbuseIpdbClient::new(
                            self.config.intel.abuseipdb.api_key.clone(),
                        ))
                    } else {
                        None
                    };

                    let intel_stage = ThreatIntelStage::new(
                        Arc::clone(&bloom),
                        cache,
                        vt_client,
                        abuseipdb_client,
                    );
                    pipeline.add_stage(Box::new(intel_stage));
                    info!("threat intelligence stage added to pipeline");
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "failed to create intel cache, continuing without threat intel stage"
                    );
                }
            }
        }

        // -- DLP stage --
        if self.config.dlp.enabled {
            // Load DLP policy: standalone file takes priority, fall back to riggs.toml
            let (dlp_config, policy_file) = match riggs_dlp::find_policy_file() {
                Some(path) => match riggs_dlp::load_policy_file(&path) {
                    Ok(cfg) => {
                        info!(path = %path.display(), "loaded DLP policy from standalone file");
                        (cfg, Some(path))
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to load DLP policy file, using config");
                        (self.config.dlp.clone(), None)
                    }
                },
                None => (self.config.dlp.clone(), None),
            };

            let dlp_policy = Arc::new(DlpPolicy::from_config(&dlp_config));
            let dlp_correlator = Arc::new(DlpCorrelator::new(
                Arc::clone(&dlp_policy),
                dlp_config.correlation_window_secs as i64,
            ));

            pipeline.add_stage(Box::new(
                DlpStage::new(Arc::clone(&dlp_correlator)).with_detection_channel(dlp_tx.clone()),
            ));

            // Register DLP query handler for filter extension IPC
            if let Ok(mut guard) = daemon_state.dlp.write() {
                *guard = Some(Arc::new(DlpAdapter {
                    correlator: Arc::clone(&dlp_correlator),
                    policy: Arc::clone(&dlp_policy),
                }));
            }

            // Supervised correlator reaper to evict stale file access entries
            // (restarted by the supervisor if it ever exits).
            let reaper_correlator = Arc::clone(&dlp_correlator);
            self.supervisor.spawn("dlp-reaper", move || {
                let correlator = Arc::clone(&reaper_correlator);
                Box::pin(async move {
                    correlator.reaper_loop().await;
                })
            });

            // Hot-reload: watch the policy file for changes
            if let Some(policy_path) = policy_file {
                let watch_correlator = Arc::clone(&dlp_correlator);
                self.supervisor.spawn("dlp-policy-watcher", move || {
                    let correlator = Arc::clone(&watch_correlator);
                    let path = policy_path.clone();
                    Box::pin(async move {
                        if let Err(e) = riggs_dlp::watch_policy(path, correlator).await {
                            tracing::error!(error = %e, "DLP policy watcher error");
                        }
                    })
                });
                info!("DLP policy hot-reload watcher started");
            }

            info!(
                domains = dlp_config.watched_domains.len(),
                blocked_types = dlp_config.file_types.block.len(),
                window_secs = dlp_config.correlation_window_secs,
                "DLP module enabled"
            );
        }

        // -- Egress allowlist (default-deny, opt-in; local-first) --
        {
            let egress_config = self.config.egress.clone();
            let engine = Arc::new(riggs_egress::EgressEngine::new(
                riggs_egress::EgressPolicy::from_config(&egress_config),
            ));
            let egress_policy_path = riggs_egress::reload::find_policy_file()
                .unwrap_or_else(riggs_egress::reload::default_policy_path);
            if let Ok(mut guard) = daemon_state.egress.write() {
                *guard = Some(Arc::new(EgressAdapter {
                    engine: Arc::clone(&engine),
                    policy_path: egress_policy_path,
                    config: std::sync::Mutex::new(egress_config.clone()),
                }));
            }
            info!(
                enabled = egress_config.enabled,
                mode = %egress_config.mode,
                domains = egress_config.allow_domains.len(),
                process_rules = egress_config.process_rules.len(),
                "egress allowlist initialized"
            );

            // Hot-reload the egress policy file if present.
            if let Some(path) = riggs_egress::reload::find_policy_file() {
                let watch_engine = Arc::clone(&engine);
                self.supervisor.spawn("egress-policy-watcher", move || {
                    let engine = Arc::clone(&watch_engine);
                    let path = path.clone();
                    Box::pin(async move {
                        if let Err(e) = riggs_egress::reload::watch_policy(path, engine).await {
                            tracing::error!(error = %e, "egress policy watcher error");
                        }
                    })
                });
                info!("egress policy hot-reload watcher started");
            }
        }

        let pipeline = Arc::new(pipeline);

        // -- Feed manager & dispatcher --
        if self.config.intel.enabled {
            let (feed_tx, feed_rx) = mpsc::channel::<FeedUpdate>(256);

            let feed_manager = Arc::new(FeedManager::new(
                self.config.intel.feeds.clone(),
                feed_tx,
                (self.config.intel.bloom_capacity / 100).max(1),
                self.config.intel.bloom_false_positive_rate,
            ));

            let fm = Arc::clone(&feed_manager);
            self.supervisor.spawn("feed-manager", move || {
                let fm = Arc::clone(&fm);
                Box::pin(async move {
                    fm.run().await;
                })
            });

            let dispatch_bloom = Arc::clone(&bloom);
            let dispatch_ioc = Arc::clone(&ioc_handle);
            let dispatch_state = Arc::clone(&daemon_state);
            let feed_rx = Arc::new(tokio::sync::Mutex::new(feed_rx));
            self.supervisor.spawn("feed-dispatcher", move || {
                let bloom = Arc::clone(&dispatch_bloom);
                let ioc_handle = Arc::clone(&dispatch_ioc);
                let feed_rx = Arc::clone(&feed_rx);
                let state = Arc::clone(&dispatch_state);
                Box::pin(async move {
                    let mut rx = feed_rx.lock().await;
                    while let Some(update) = rx.recv().await {
                        match update {
                            FeedUpdate::BloomFilterReady(new_bloom) => {
                                let count = new_bloom.len();
                                match bloom.write() {
                                    Ok(mut guard) => {
                                        info!(
                                            entries = count,
                                            "replacing bloom filter with fresh feed data"
                                        );
                                        *guard = new_bloom;
                                        state.bloom_size.store(count as u64, Ordering::Relaxed);
                                    }
                                    Err(e) => {
                                        error!("bloom filter lock poisoned: {e}");
                                    }
                                }
                            }
                            FeedUpdate::IocBatch(entries) => {
                                let iocs: Vec<Ioc> = entries
                                    .into_iter()
                                    .map(|entry| {
                                        let ioc_type = match entry.ioc_type.as_str() {
                                            "sha256" => IocType::Sha256,
                                            "md5" => IocType::Md5,
                                            "domain" => IocType::Domain,
                                            "ip" | "ip_address" => IocType::IpAddress,
                                            "url" => IocType::Url,
                                            "file_path" | "filepath" => IocType::FilePath,
                                            other => {
                                                warn!(
                                                    ioc_type = other,
                                                    "unknown IOC type, defaulting to Url"
                                                );
                                                IocType::Url
                                            }
                                        };
                                        let severity = match entry.severity.as_str() {
                                            "info" => Severity::Info,
                                            "low" => Severity::Low,
                                            "medium" => Severity::Medium,
                                            "high" => Severity::High,
                                            "critical" => Severity::Critical,
                                            _ => Severity::Medium,
                                        };
                                        Ioc {
                                            ioc_type,
                                            value: entry.value,
                                            description: entry.description,
                                            severity,
                                        }
                                    })
                                    .collect();

                                let count = iocs.len();
                                let matcher = IocMatcher::new(iocs);
                                match ioc_handle.write() {
                                    Ok(mut guard) => {
                                        *guard = Some(matcher);
                                        info!(
                                            ioc_count = count,
                                            "IOC matcher rebuilt from feed data"
                                        );
                                    }
                                    Err(e) => {
                                        error!("IOC handle lock poisoned: {e}");
                                    }
                                }
                            }
                            FeedUpdate::CveBatch(cves) => {
                                info!(
                                    count = cves.len(),
                                    "received CVE feed update (vuln scanner integration pending)"
                                );
                            }
                        }
                    }
                    warn!("feed update channel closed, dispatcher exiting");
                })
            });

            info!("feed manager and dispatcher started");
        }

        // -- Storyline correlator --
        let mut correlator = StorylineCorrelator::new()
            .with_limits(
                self.config.engine.storyline_max_events,
                self.config.engine.storyline_idle_secs,
                self.config.engine.storyline_prune_interval_secs,
            )
            .with_threat_threshold(self.config.detection.threat_score_threshold);

        // -- Sensor + collector --
        #[cfg(target_os = "macos")]
        let sensor = Box::new(riggs_platform_macos::MacOsSensor::new());
        #[cfg(not(target_os = "macos"))]
        let sensor = Box::new(riggs_platform_linux::LinuxSensor::new());
        let mut collector = riggs_sensor::EventCollector::new(sensor, event_tx);
        collector.start().await?;
        info!("sensor and event collector started");

        // -- Store --
        let store_path = PathBuf::from(&self.config.store.db_path);
        if let Some(parent) = store_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                RiggsError::Store(format!(
                    "failed to create store directory {}: {e}",
                    parent.display()
                ))
            })?;
        }
        let store = Arc::new(RiggsStore::with_compression(
            &store_path,
            self.config.store.compression_enabled,
        )?);
        if let Ok(mut guard) = daemon_state.store.write() {
            *guard = Some(Arc::new(StoreAdapter(Arc::clone(&store))));
        }

        // -- Retention (prunes events/verdicts/response_log past retention_days) --
        let retention_days = self.config.store.retention_days;
        let retention_sweep = Duration::from_secs(self.config.engine.retention_sweep_secs.max(1));
        let retention_store = Arc::clone(&store);
        self.supervisor.spawn("retention", move || {
            let store = Arc::clone(&retention_store);
            Box::pin(async move {
                let policy = riggs_store::RetentionPolicy::new(retention_days);
                let mut interval = tokio::time::interval(retention_sweep);
                loop {
                    interval.tick().await;
                    if let Err(e) = policy.run_cleanup(&store).await {
                        tracing::error!(error = %e, "retention cleanup failed");
                    }
                }
            })
        });

        // -- Response executor --
        let policy = riggs_response::ResponsePolicy::default();
        let vault = riggs_response::QuarantineVault::new(PathBuf::from(
            &self.config.response.quarantine_path,
        ));
        #[cfg(target_os = "macos")]
        let response_sensor_pc = Box::new(riggs_platform_macos::MacOsSensor::new());
        #[cfg(target_os = "macos")]
        let response_sensor_nc = Box::new(
            riggs_platform_macos::MacOsSensor::new()
                .with_pf_conf_path(self.config.response.pf_conf_path.clone()),
        );
        #[cfg(not(target_os = "macos"))]
        let response_sensor_pc = Box::new(riggs_platform_linux::LinuxSensor::new());
        #[cfg(not(target_os = "macos"))]
        let response_sensor_nc = Box::new(riggs_platform_linux::LinuxSensor::new());
        let executor = Arc::new(riggs_response::ResponseExecutor::new(
            response_sensor_pc,
            response_sensor_nc,
            vault,
        ));

        // -- Counters (shared with IPC state) --
        let events_processed = Arc::clone(&daemon_state.events_processed);
        let threats_detected = Arc::clone(&daemon_state.threats_detected);

        // -- Health check loop --
        let health_interval = Duration::from_secs(self.config.engine.health_check_secs.max(1));
        let health_events = Arc::clone(&events_processed);
        let health_threats = Arc::clone(&threats_detected);
        self.supervisor.spawn("health-check", move || {
            let events = Arc::clone(&health_events);
            let threats = Arc::clone(&health_threats);
            Box::pin(async move {
                let mut interval = tokio::time::interval(health_interval);
                loop {
                    interval.tick().await;
                    let ev = events.load(Ordering::Relaxed);
                    let th = threats.load(Ordering::Relaxed);
                    info!(
                        events_processed = ev,
                        threats_detected = th,
                        "health check ok"
                    );
                }
            })
        });

        // -- IPC server (wired to shared daemon state) --
        let ipc_state = Arc::clone(&daemon_state);
        let ipc_socket_path = self.config.comms.socket_path.clone();
        let ipc_max_msg = self.config.comms.ipc_max_message_bytes;
        let ipc_max_conn = self.config.comms.ipc_max_connections;
        self.supervisor.spawn("ipc-server", move || {
            let state = Arc::clone(&ipc_state);
            let socket = ipc_socket_path.clone();
            Box::pin(async move {
                let server = riggs_comms::IpcServer::with_state(PathBuf::from(&socket), state)
                    .with_limits(ipc_max_msg, ipc_max_conn);
                if let Err(e) = server.start().await {
                    tracing::error!(error = %e, "IPC server error");
                }
            })
        });
        info!(socket = %self.config.comms.socket_path, "IPC server started");

        // -- Rule hot-reload watcher --
        let rules_dir = PathBuf::from("rules/default");
        if rules_dir.is_dir() {
            self.supervisor.spawn("rule-watcher", move || {
                let dir = rules_dir.clone();
                Box::pin(async move {
                    let loader = riggs_rules::RuleLoader::new(dir, None, None);
                    if let Err(e) = loader.watch().await {
                        tracing::error!(error = %e, "rule watcher error");
                    }
                })
            });
            info!("rule hot-reload watcher started");
        }

        // -- Cloud client (connects to Murtaugh console if configured) --
        if self.config.comms.cloud_enabled {
            match (
                self.config.comms.cloud_endpoint.clone(),
                self.config.comms.enrollment_token.clone(),
            ) {
                (Some(endpoint), Some(token)) => {
                    let cloud_config = riggs_cloud::ConsoleConfig {
                        endpoint,
                        enrollment_token: token,
                        heartbeat_interval_secs: self.config.comms.heartbeat_interval_secs,
                        tls: self.config.comms.tls.clone(),
                        require_tls: self.config.comms.require_tls,
                    };
                    let mut cc = riggs_cloud::ConsoleClient::new(cloud_config.clone());
                    match cc.connect().await {
                        Ok(()) => {
                            match riggs_cloud::enroll(&mut cc).await {
                                Ok(agent_id) => {
                                    cc.agent_id = Some(agent_id.clone());
                                    info!(agent_id = %agent_id, "enrolled with console");

                                    // Heartbeat loop
                                    let hb_client = cc.clone();
                                    let hb_agent_id = agent_id.clone();
                                    let hb_events = Arc::clone(&daemon_state.events_processed);
                                    let hb_threats = Arc::clone(&daemon_state.threats_detected);
                                    let hb_secs = self.config.comms.heartbeat_interval_secs;
                                    self.supervisor.spawn("cloud-heartbeat", move || {
                                        let client = hb_client.clone();
                                        let id = hb_agent_id.clone();
                                        let ev = Arc::clone(&hb_events);
                                        let th = Arc::clone(&hb_threats);
                                        Box::pin(async move {
                                            riggs_cloud::run_heartbeat_loop(
                                                client, id, hb_secs, ev, th,
                                            )
                                            .await;
                                        })
                                    });

                                    // Threat reporter (supervised). The receiver
                                    // lives in a shared mutex and is only borrowed
                                    // per run, so a restart after a panic resumes
                                    // draining the same channel.
                                    let rep_client = cc.clone();
                                    let rep_agent_id = agent_id.clone();
                                    let rep_rx = Arc::new(tokio::sync::Mutex::new(verdict_rx));
                                    self.supervisor.spawn("cloud-threat-reporter", move || {
                                        let client = rep_client.clone();
                                        let id = rep_agent_id.clone();
                                        let rx = Arc::clone(&rep_rx);
                                        Box::pin(async move {
                                            let mut rx = rx.lock().await;
                                            riggs_cloud::run_threat_reporter(client, id, &mut rx)
                                                .await
                                        })
                                    });

                                    // DLP event reporter (supervised, same pattern)
                                    let dlp_client = cc.clone();
                                    let dlp_agent_id = agent_id.clone();
                                    let dlp_rx = Arc::new(tokio::sync::Mutex::new(dlp_rx));
                                    self.supervisor.spawn("cloud-dlp-reporter", move || {
                                        let client = dlp_client.clone();
                                        let id = dlp_agent_id.clone();
                                        let rx = Arc::clone(&dlp_rx);
                                        Box::pin(async move {
                                            let mut rx = rx.lock().await;
                                            riggs_cloud::run_dlp_reporter(client, id, &mut rx).await
                                        })
                                    });

                                    info!("cloud heartbeat, threat reporter, and DLP reporter started");
                                }
                                Err(e) => {
                                    warn!(error = %e, "enrollment failed, running without console");
                                }
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "cannot connect to console, running without it");
                        }
                    }
                }
                _ => {
                    warn!("cloud_enabled=true but cloud_endpoint or enrollment_token not set");
                }
            }
        } else {
            // Drop receivers so channels close cleanly
            drop(verdict_rx);
            drop(dlp_rx);
        }

        // -- Config for auto-respond, captured before entering the loop --
        let auto_respond = self.config.response.auto_respond;
        let supervisor_check_interval =
            Duration::from_secs(self.config.engine.health_check_secs.max(1));

        // -- Batched store writer (H16) --
        // Coalesce (event, verdict) writes into one transaction so the hot path
        // pays a single fsync per batch instead of two per event. The writer
        // flushes when the buffer hits `batch_max` or `batch_flush_ms` elapses.
        let batch_max = self.config.store.batch_max.max(1);
        let batch_flush = Duration::from_millis(self.config.store.batch_flush_ms.max(1));
        let (store_tx, mut store_rx) =
            mpsc::channel::<(RiggsEvent, MergedVerdict)>(batch_max.saturating_mul(4).max(1));
        let writer_store = Arc::clone(&store);
        let writer_handle = tokio::spawn(async move {
            let mut buf: Vec<(RiggsEvent, MergedVerdict)> = Vec::with_capacity(batch_max);
            let mut ticker = tokio::time::interval(batch_flush);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    item = store_rx.recv() => {
                        match item {
                            Some(pair) => {
                                buf.push(pair);
                                if buf.len() >= batch_max {
                                    if let Err(e) = writer_store.store_batch(&buf) {
                                        error!(error = %e, "failed to store batch");
                                    }
                                    buf.clear();
                                }
                            }
                            None => break, // channel closed: flush below and exit
                        }
                    }
                    _ = ticker.tick() => {
                        if !buf.is_empty() {
                            if let Err(e) = writer_store.store_batch(&buf) {
                                error!(error = %e, "failed to flush batch");
                            }
                            buf.clear();
                        }
                    }
                }
            }
            if !buf.is_empty() {
                if let Err(e) = writer_store.store_batch(&buf) {
                    error!(error = %e, "failed to flush final batch");
                }
            }
        });

        info!("riggs daemon running");

        // -- Main event processing loop --
        tokio::select! {
            _ = async {
                while let Some(event) = event_rx.recv().await {
                    events_processed.fetch_add(1, Ordering::Relaxed);

                    // Isolate detection in its own task: a panic in any stage
                    // (e.g. on a crafted event) becomes a JoinError here instead
                    // of unwinding and killing the daemon's event loop.
                    let merged = {
                        let pipeline = Arc::clone(&pipeline);
                        let ev = event.clone();
                        match tokio::spawn(async move { pipeline.run(ev).await }).await {
                            Ok(merged) => merged,
                            Err(e) => {
                                error!(
                                    error = %e,
                                    event_id = %event.event_id(),
                                    "detection pipeline panicked; dropping event"
                                );
                                continue;
                            }
                        }
                    };
                    let storyline_id = correlator.correlate(&event);

                    for v in &merged.verdicts {
                        correlator.add_verdict(&storyline_id, v.clone());
                    }

                    if merged.final_threat_level > ThreatLevel::Clean {
                        threats_detected.fetch_add(1, Ordering::Relaxed);
                        warn!(
                            event_id = %event.event_id(),
                            storyline = %storyline_id,
                            threat = %merged.final_threat_level,
                            "threat detected"
                        );

                        if auto_respond {
                            let target_pid = event.process_context().pid;
                            let target_path = match &event {
                                RiggsEvent::File(fe) => Some(std::path::Path::new(fe.path.as_str())),
                                _ => None,
                            };
                            let actions = policy.evaluate(&merged, target_pid, target_path);
                            if !actions.is_empty() {
                                let exec = Arc::clone(&executor);
                                tokio::spawn(async move {
                                    let records = exec.execute_all(actions).await;
                                    for record in &records {
                                        if record.success {
                                            info!(action = %record.action, "response action executed");
                                        } else {
                                            warn!(
                                                action = %record.action,
                                                detail = %record.detail,
                                                "response action failed"
                                            );
                                        }
                                    }
                                });
                            }
                        }
                    }

                    // Hand off to the batched writer. If the queue is full the
                    // writer is behind; drop from persistence rather than stall
                    // the detection loop (telemetry fails open, sensing never
                    // blocks on disk). If the writer is gone, stop so the
                    // service manager restarts us with persistence intact.
                    match store_tx.try_send((event, merged)) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            warn!("store queue full; event not persisted");
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            error!("store writer exited; stopping daemon");
                            break;
                        }
                    }
                }
            } => {}
            _ = shutdown_signal() => {
                info!("shutdown signal received");
            }
            _ = async {
                // Restart any supervised task that has died.
                let mut interval = tokio::time::interval(supervisor_check_interval);
                loop {
                    interval.tick().await;
                    self.supervisor.check_health().await;
                }
            } => {}
        }

        // -- Shutdown --
        info!("shutting down...");

        if let Err(e) = collector.stop().await {
            warn!(error = %e, "failed to stop event collector");
        }

        self.supervisor.shutdown_all();

        // Close the store channel so the writer flushes its final batch, then
        // wait briefly for it to drain before we exit.
        drop(store_tx);
        if let Err(e) = tokio::time::timeout(Duration::from_secs(5), writer_handle).await {
            warn!(error = %e, "store writer did not flush within timeout");
        }

        let stats = pipeline.stats();
        info!(
            events = stats.events_processed,
            verdicts = stats.verdicts_issued,
            "pipeline stats at shutdown"
        );
        for st in &stats.stage_timings {
            info!(
                stage = %st.stage_name,
                invocations = st.invocations,
                total_us = st.total_duration_us,
                "stage timing"
            );
        }

        drop(store);
        info!("riggs daemon stopped");
        Ok(())
    }
}

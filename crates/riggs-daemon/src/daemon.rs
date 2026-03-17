use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;

use riggs_behavioral_ai::BehavioralAiStage;
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

const CONFIG_PATHS: &[&str] = &[
    "/etc/riggs/riggs.toml",
    "config/riggs.toml",
];
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);

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
        for config_path in CONFIG_PATHS {
            let path = std::path::Path::new(config_path);
            if path.exists() {
                let contents = std::fs::read_to_string(path).map_err(|e| {
                    RiggsError::Config(format!("failed to read {config_path}: {e}"))
                })?;

                let config: RiggsConfig = toml::from_str(&contents).map_err(|e| {
                    RiggsError::Config(format!("failed to parse {config_path}: {e}"))
                })?;

                info!(path = config_path, "loaded configuration");
                return Ok(config);
            }
        }

        info!("no config file found, using defaults");
        Ok(RiggsConfig::default())
    }

    pub async fn run(&mut self) -> Result<(), RiggsError> {
        info!("initializing components...");

        let (event_tx, mut event_rx) = mpsc::channel::<RiggsEvent>(10_000);
        let (verdict_tx, _verdict_rx) = mpsc::channel::<MergedVerdict>(10_000);

        // -- Shared daemon state (used by IPC server + feed dispatcher) --
        let daemon_state = Arc::new(riggs_comms::DaemonState::new());

        // Serialize config into state for IPC queries
        if let Ok(config_json) = serde_json::to_string_pretty(&self.config) {
            if let Ok(mut guard) = daemon_state.config_json.write() {
                *guard = config_json;
            }
        }

        // -- Detection pipeline --
        let mut pipeline = DetectionPipeline::new(verdict_tx);

        if self.config.engine.static_ai_enabled {
            let model_path = PathBuf::from("/var/lib/riggs/models/static.onnx");
            pipeline.add_stage(Box::new(StaticAiStage::new(model_path)));
        }

        let ioc_handle: Arc<StdRwLock<Option<IocMatcher>>> =
            Arc::new(StdRwLock::new(None));

        if self.config.engine.rules_enabled {
            let rules_stage =
                RulesStage::new_with_shared_ioc(None, Arc::clone(&ioc_handle), None);
            pipeline.add_stage(Box::new(rules_stage));
        }

        if self.config.engine.behavioral_ai_enabled {
            pipeline.add_stage(Box::new(BehavioralAiStage::new()));
        }

        // -- Threat intelligence stage --
        let bloom: Arc<StdRwLock<BloomFilter>> =
            Arc::new(StdRwLock::new(BloomFilter::new(1_000_000, 0.001)));

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
                        Some(VtClient::new(
                            self.config.intel.virustotal.api_key.clone(),
                        ))
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

            pipeline.add_stage(Box::new(DlpStage::new(Arc::clone(&dlp_correlator))));

            // Register DLP query handler for filter extension IPC
            if let Ok(mut guard) = daemon_state.dlp.write() {
                *guard = Some(Arc::new(DlpAdapter {
                    correlator: Arc::clone(&dlp_correlator),
                    policy: Arc::clone(&dlp_policy),
                }));
            }

            // Spawn correlator reaper to evict stale file access entries
            let reaper_correlator = Arc::clone(&dlp_correlator);
            tokio::spawn(async move {
                reaper_correlator.reaper_loop().await;
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

        let pipeline = Arc::new(pipeline);

        // -- Feed manager & dispatcher --
        if self.config.intel.enabled {
            let (feed_tx, feed_rx) = mpsc::channel::<FeedUpdate>(256);

            let feed_manager =
                Arc::new(FeedManager::new(self.config.intel.feeds.clone(), feed_tx));

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
        let mut correlator = StorylineCorrelator::new();

        // -- Sensor + collector --
        let sensor = Box::new(riggs_platform_macos::MacOsSensor::new());
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
        let store = Arc::new(RiggsStore::new(&store_path)?);
        if let Ok(mut guard) = daemon_state.store.write() {
            *guard = Some(Arc::new(StoreAdapter(Arc::clone(&store))));
        }

        // -- Response executor --
        let policy = riggs_response::ResponsePolicy::default();
        let vault = riggs_response::QuarantineVault::new(PathBuf::from(
            "/var/lib/riggs/quarantine",
        ));
        let response_sensor_pc = Box::new(riggs_platform_macos::MacOsSensor::new());
        let response_sensor_nc = Box::new(riggs_platform_macos::MacOsSensor::new());
        let executor = Arc::new(riggs_response::ResponseExecutor::new(
            response_sensor_pc,
            response_sensor_nc,
            vault,
        ));

        // -- Counters (shared with IPC state) --
        let events_processed = Arc::clone(&daemon_state.events_processed);
        let threats_detected = Arc::clone(&daemon_state.threats_detected);

        // -- Health check loop --
        let health_events = Arc::clone(&events_processed);
        let health_threats = Arc::clone(&threats_detected);
        self.supervisor.spawn("health-check", move || {
            let events = Arc::clone(&health_events);
            let threats = Arc::clone(&health_threats);
            Box::pin(async move {
                let mut interval = tokio::time::interval(HEALTH_CHECK_INTERVAL);
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
        self.supervisor.spawn("ipc-server", move || {
            let state = Arc::clone(&ipc_state);
            let socket = ipc_socket_path.clone();
            Box::pin(async move {
                let server = riggs_comms::IpcServer::with_state(PathBuf::from(&socket), state);
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

        // -- Config for auto-respond, captured before entering the loop --
        let auto_respond = self.config.response.auto_respond;

        info!("riggs daemon running");

        // -- Main event processing loop --
        tokio::select! {
            _ = async {
                while let Some(event) = event_rx.recv().await {
                    events_processed.fetch_add(1, Ordering::Relaxed);

                    let merged = pipeline.run(event.clone()).await;
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
                            let actions = policy.evaluate(&merged);
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

                    if let Err(e) = store.store_event(&event) {
                        error!(error = %e, "failed to store event");
                    }
                    if let Err(e) = store.store_verdict(&merged) {
                        error!(error = %e, "failed to store verdict");
                    }
                }
            } => {}
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown signal received");
            }
        }

        // -- Shutdown --
        info!("shutting down...");

        if let Err(e) = collector.stop().await {
            warn!(error = %e, "failed to stop event collector");
        }

        self.supervisor.shutdown_all();

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

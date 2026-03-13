use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use riggs_behavioral_ai::BehavioralAiStage;
use riggs_engine::DetectionPipeline;
use riggs_rules::RulesStage;
use riggs_static_ai::StaticAiStage;
use riggs_store::RiggsStore;
use riggs_storyline::StorylineCorrelator;
use riggs_types::config::RiggsConfig;
use riggs_types::errors::RiggsError;
use riggs_types::events::RiggsEvent;
use riggs_types::verdict::{MergedVerdict, ThreatLevel};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::supervisor::Supervisor;

const CONFIG_PATH: &str = "config/riggs.toml";
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
        let path = Path::new(CONFIG_PATH);
        if !path.exists() {
            info!(
                path = CONFIG_PATH,
                "config file not found, using defaults"
            );
            return Ok(RiggsConfig::default());
        }

        let contents = std::fs::read_to_string(path)
            .map_err(|e| RiggsError::Config(format!("failed to read {CONFIG_PATH}: {e}")))?;

        let config: RiggsConfig = toml::from_str(&contents)
            .map_err(|e| RiggsError::Config(format!("failed to parse {CONFIG_PATH}: {e}")))?;

        info!(path = CONFIG_PATH, "loaded configuration");
        Ok(config)
    }

    pub async fn run(&mut self) -> Result<(), RiggsError> {
        info!("initializing components...");

        let (_event_tx, mut event_rx) = mpsc::channel::<RiggsEvent>(10_000);
        let (verdict_tx, _verdict_rx) = mpsc::channel::<MergedVerdict>(10_000);

        // -- Detection pipeline --
        let mut pipeline = DetectionPipeline::new(verdict_tx);

        if self.config.engine.static_ai_enabled {
            let model_path = PathBuf::from("/var/lib/riggs/models/static.onnx");
            pipeline.add_stage(Box::new(StaticAiStage::new(model_path)));
        }

        if self.config.engine.rules_enabled {
            pipeline.add_stage(Box::new(RulesStage::new(None, None, None)));
        }

        if self.config.engine.behavioral_ai_enabled {
            pipeline.add_stage(Box::new(BehavioralAiStage::new()));
        }

        let pipeline = Arc::new(pipeline);

        // -- Storyline correlator --
        let mut correlator = StorylineCorrelator::new();

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
        let store = RiggsStore::new(&store_path)?;

        // -- Counters --
        let events_processed = Arc::new(AtomicU64::new(0));
        let threats_detected = Arc::new(AtomicU64::new(0));

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

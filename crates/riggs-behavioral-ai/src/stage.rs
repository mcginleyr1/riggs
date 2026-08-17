use std::sync::Mutex;

use async_trait::async_trait;
use chrono::Utc;
use tracing::{debug, info};

use riggs_engine::{DetectionStage, StageVerdict};
use riggs_types::errors::RiggsError;
use riggs_types::events::{RiggsEvent, Severity, StorylineId};
use riggs_types::verdict::{DetectionSource, ThreatLevel, Verdict};

use crate::tracker::BehaviorTracker;

pub struct BehavioralAiStage {
    tracker: Mutex<BehaviorTracker>,
}

impl BehavioralAiStage {
    pub fn new() -> Self {
        Self {
            tracker: Mutex::new(BehaviorTracker::new()),
        }
    }

    /// Construct with operator-configured memory caps.
    pub fn with_limits(max_events_per_storyline: usize, max_storylines: usize) -> Self {
        Self {
            tracker: Mutex::new(
                BehaviorTracker::new().with_limits(max_events_per_storyline, max_storylines),
            ),
        }
    }

    /// Construct with operator-configured memory caps and detection thresholds.
    pub fn configured(
        max_events_per_storyline: usize,
        max_storylines: usize,
        detection: &riggs_types::config::DetectionConfig,
    ) -> Self {
        Self {
            tracker: Mutex::new(
                BehaviorTracker::new()
                    .with_limits(max_events_per_storyline, max_storylines)
                    .with_detection(detection),
            ),
        }
    }
}

impl Default for BehavioralAiStage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DetectionStage for BehavioralAiStage {
    fn name(&self) -> &str {
        "behavioral-ai"
    }

    async fn analyze(&self, event: &RiggsEvent) -> Result<StageVerdict, RiggsError> {
        let storyline_id = extract_storyline_id(event);

        let patterns = {
            // Recover from a poisoned lock instead of erroring out; a single
            // panic under the lock must not disable behavioral detection forever.
            let mut tracker = self
                .tracker
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());

            tracker.track(event.clone());
            tracker.check_patterns(&storyline_id)
        };

        if patterns.is_empty() {
            debug!(storyline = ?storyline_id, "no behavioral patterns detected");
            return Ok(StageVerdict::Clean);
        }

        let worst_severity = patterns
            .iter()
            .map(|p| p.severity())
            .max()
            .unwrap_or(Severity::Info);

        let descriptions: Vec<&str> = patterns.iter().map(|p| p.description()).collect();
        let description = descriptions.join("; ");

        info!(
            storyline = ?storyline_id,
            pattern_count = patterns.len(),
            severity = ?worst_severity,
            "behavioral patterns detected"
        );

        let event_id = extract_event_id(event);
        let (threat_level, confidence) = match worst_severity {
            Severity::Critical => (ThreatLevel::Malicious, 0.95),
            Severity::High => (ThreatLevel::Malicious, 0.80),
            Severity::Medium => (ThreatLevel::Suspicious, 0.60),
            Severity::Low => (ThreatLevel::Suspicious, 0.40),
            Severity::Info => return Ok(StageVerdict::Clean),
        };

        let verdict = Verdict {
            event_id,
            threat_level,
            confidence,
            source: DetectionSource::BehavioralAI,
            description,
            timestamp: Utc::now(),
        };

        match threat_level {
            ThreatLevel::Malicious => Ok(StageVerdict::Malicious(verdict)),
            ThreatLevel::Suspicious => Ok(StageVerdict::Suspicious(verdict)),
            ThreatLevel::Clean => Ok(StageVerdict::Clean),
        }
    }
}

fn extract_storyline_id(event: &RiggsEvent) -> StorylineId {
    match event {
        RiggsEvent::Process(e) => e.process_context.storyline_id.clone(),
        RiggsEvent::File(e) => e.process_context.storyline_id.clone(),
        RiggsEvent::Network(e) => e.process_context.storyline_id.clone(),
        RiggsEvent::Dns(e) => e.process_context.storyline_id.clone(),
        RiggsEvent::Auth(e) => e.process_context.storyline_id.clone(),
        RiggsEvent::Kernel(e) => e.process_context.storyline_id.clone(),
    }
}

fn extract_event_id(event: &RiggsEvent) -> riggs_types::events::EventId {
    match event {
        RiggsEvent::Process(e) => e.event_id.clone(),
        RiggsEvent::File(e) => e.event_id.clone(),
        RiggsEvent::Network(e) => e.event_id.clone(),
        RiggsEvent::Dns(e) => e.event_id.clone(),
        RiggsEvent::Auth(e) => e.event_id.clone(),
        RiggsEvent::Kernel(e) => e.event_id.clone(),
    }
}

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use riggs_types::events::RiggsEvent;
use riggs_types::verdict::{MergedVerdict, ThreatLevel, Verdict};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::router::EventRouter;
use crate::stage::{DetectionStage, StageVerdict};

#[derive(Debug)]
pub struct PipelineStats {
    pub events_processed: u64,
    pub verdicts_issued: u64,
    pub stage_timings: Vec<StageTiming>,
}

#[derive(Debug, Clone)]
pub struct StageTiming {
    pub stage_name: String,
    pub total_duration_us: u64,
    pub invocations: u64,
}

struct TrackedStage {
    stage: Box<dyn DetectionStage>,
    total_duration_us: AtomicU64,
    invocations: AtomicU64,
}

pub struct DetectionPipeline {
    stages: Vec<Arc<TrackedStage>>,
    #[allow(dead_code)]
    verdict_tx: mpsc::Sender<MergedVerdict>,
    events_processed: AtomicU64,
    verdicts_issued: AtomicU64,
    malicious_threshold: f32,
    suspicious_threshold: f32,
}

impl DetectionPipeline {
    pub fn new(verdict_tx: mpsc::Sender<MergedVerdict>) -> Self {
        Self {
            stages: Vec::new(),
            verdict_tx,
            events_processed: AtomicU64::new(0),
            verdicts_issued: AtomicU64::new(0),
            malicious_threshold: 0.7,
            suspicious_threshold: 0.3,
        }
    }

    /// Override the weighted-merge thresholds (operator-configurable detection
    /// sensitivity). Defaults are 0.7 (malicious) and 0.3 (suspicious).
    pub fn with_merge_thresholds(mut self, malicious: f32, suspicious: f32) -> Self {
        self.malicious_threshold = malicious;
        self.suspicious_threshold = suspicious;
        self
    }

    pub fn add_stage(&mut self, stage: Box<dyn DetectionStage>) {
        info!(stage = stage.name(), "added detection stage");
        self.stages.push(Arc::new(TrackedStage {
            stage,
            total_duration_us: AtomicU64::new(0),
            invocations: AtomicU64::new(0),
        }));
    }

    pub async fn run(&self, event: RiggsEvent) -> MergedVerdict {
        let allowed_stages = EventRouter::stages_for_event(&event);
        let storyline_id = extract_storyline_id(&event);
        let event_id = extract_event_id(&event);

        let mut verdicts: Vec<Verdict> = Vec::new();

        for tracked in &self.stages {
            if !allowed_stages.contains(&tracked.stage.name()) {
                continue;
            }

            let start = Instant::now();
            let result = tracked.stage.analyze(&event).await;
            let elapsed_us = start.elapsed().as_micros() as u64;

            tracked.total_duration_us.fetch_add(elapsed_us, Ordering::Relaxed);
            tracked.invocations.fetch_add(1, Ordering::Relaxed);

            collect_verdict(&*tracked.stage, result, &mut verdicts);
        }

        self.events_processed.fetch_add(1, Ordering::Relaxed);

        let final_threat_level = merge_verdicts_weighted(&verdicts, self.malicious_threshold, self.suspicious_threshold);

        if final_threat_level > ThreatLevel::Clean {
            self.verdicts_issued.fetch_add(1, Ordering::Relaxed);
        }

        MergedVerdict {
            event_id,
            final_threat_level,
            verdicts,
            storyline_id,
        }
    }

    pub async fn run_with_timeout(
        &self,
        event: RiggsEvent,
        timeout_per_stage: Duration,
    ) -> MergedVerdict {
        let allowed_stages = EventRouter::stages_for_event(&event);
        let storyline_id = extract_storyline_id(&event);
        let event_id = extract_event_id(&event);

        let mut verdicts: Vec<Verdict> = Vec::new();

        for tracked in &self.stages {
            if !allowed_stages.contains(&tracked.stage.name()) {
                continue;
            }

            let start = Instant::now();
            let result =
                tokio::time::timeout(timeout_per_stage, tracked.stage.analyze(&event)).await;
            let elapsed_us = start.elapsed().as_micros() as u64;

            tracked.total_duration_us.fetch_add(elapsed_us, Ordering::Relaxed);
            tracked.invocations.fetch_add(1, Ordering::Relaxed);

            match result {
                Ok(stage_result) => {
                    collect_verdict(&*tracked.stage, stage_result, &mut verdicts);
                }
                Err(_) => {
                    warn!(
                        stage = tracked.stage.name(),
                        timeout_ms = timeout_per_stage.as_millis() as u64,
                        "stage timed out"
                    );
                }
            }
        }

        self.events_processed.fetch_add(1, Ordering::Relaxed);

        let final_threat_level = merge_verdicts_weighted(&verdicts, self.malicious_threshold, self.suspicious_threshold);

        if final_threat_level > ThreatLevel::Clean {
            self.verdicts_issued.fetch_add(1, Ordering::Relaxed);
        }

        MergedVerdict {
            event_id,
            final_threat_level,
            verdicts,
            storyline_id,
        }
    }

    pub fn stats(&self) -> PipelineStats {
        let stage_timings = self
            .stages
            .iter()
            .map(|tracked| StageTiming {
                stage_name: tracked.stage.name().to_string(),
                total_duration_us: tracked.total_duration_us.load(Ordering::Relaxed),
                invocations: tracked.invocations.load(Ordering::Relaxed),
            })
            .collect();

        PipelineStats {
            events_processed: self.events_processed.load(Ordering::Relaxed),
            verdicts_issued: self.verdicts_issued.load(Ordering::Relaxed),
            stage_timings,
        }
    }
}

fn collect_verdict(
    stage: &dyn DetectionStage,
    result: Result<StageVerdict, riggs_types::errors::RiggsError>,
    verdicts: &mut Vec<Verdict>,
) {
    match result {
        Ok(StageVerdict::Clean) => {}
        Ok(StageVerdict::Suspicious(verdict)) | Ok(StageVerdict::Malicious(verdict)) => {
            verdicts.push(verdict);
        }
        Ok(StageVerdict::Error(msg)) => {
            warn!(stage = stage.name(), error = %msg, "stage returned error");
        }
        Err(e) => {
            warn!(stage = stage.name(), error = %e, "stage execution failed");
        }
    }
}

fn merge_verdicts_weighted(
    verdicts: &[Verdict],
    malicious_threshold: f32,
    suspicious_threshold: f32,
) -> ThreatLevel {
    // Drop non-finite/non-positive confidences. A single NaN would otherwise
    // poison the sum and make every comparison below false, silently returning
    // Clean even alongside a confident Malicious verdict.
    let usable: Vec<&Verdict> = verdicts
        .iter()
        .filter(|v| v.confidence.is_finite() && v.confidence > 0.0)
        .collect();

    if usable.is_empty() {
        return ThreatLevel::Clean;
    }

    let total_confidence: f32 = usable.iter().map(|v| v.confidence).sum();

    let weighted_score: f32 = usable
        .iter()
        .map(|v| {
            let threat_weight = match v.threat_level {
                ThreatLevel::Clean => 0.0,
                ThreatLevel::Suspicious => 0.5,
                ThreatLevel::Malicious => 1.0,
            };
            threat_weight * v.confidence
        })
        .sum();

    let average = weighted_score / total_confidence;

    let weighted_level = if average >= malicious_threshold {
        ThreatLevel::Malicious
    } else if average >= suspicious_threshold {
        ThreatLevel::Suspicious
    } else {
        ThreatLevel::Clean
    };

    // Escalate, never dilute: a stage only emits Malicious once it has crossed
    // its own confidence bar, so corroborating weaker signals must not drag the
    // merged verdict below the strongest individual finding.
    let max_individual = usable
        .iter()
        .map(|v| v.threat_level)
        .max()
        .unwrap_or(ThreatLevel::Clean);

    weighted_level.max(max_individual)
}

fn extract_storyline_id(event: &RiggsEvent) -> riggs_types::events::StorylineId {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weighted_merge_empty_is_clean() {
        assert_eq!(merge_verdicts_weighted(&[], 0.7, 0.3), ThreatLevel::Clean);
    }

    #[test]
    fn weighted_merge_high_confidence_malicious() {
        use chrono::Utc;
        use riggs_types::events::EventId;
        use riggs_types::verdict::DetectionSource;

        let verdicts = vec![
            Verdict {
                event_id: EventId::new(),
                threat_level: ThreatLevel::Malicious,
                confidence: 0.95,
                source: DetectionSource::StaticAI,
                description: "malware detected".into(),
                timestamp: Utc::now(),
            },
            Verdict {
                event_id: EventId::new(),
                threat_level: ThreatLevel::Suspicious,
                confidence: 0.6,
                source: DetectionSource::YaraRule,
                description: "yara match".into(),
                timestamp: Utc::now(),
            },
        ];

        // weighted = (1.0 * 0.95 + 0.5 * 0.6) / (0.95 + 0.6)
        //          = (0.95 + 0.3) / 1.55
        //          = 1.25 / 1.55 ~= 0.806
        assert_eq!(merge_verdicts_weighted(&verdicts, 0.7, 0.3), ThreatLevel::Malicious);
    }

    #[test]
    fn weighted_merge_low_confidence_stays_suspicious() {
        use chrono::Utc;
        use riggs_types::events::EventId;
        use riggs_types::verdict::DetectionSource;

        let verdicts = vec![Verdict {
            event_id: EventId::new(),
            threat_level: ThreatLevel::Suspicious,
            confidence: 0.4,
            source: DetectionSource::CustomRule,
            description: "heuristic match".into(),
            timestamp: Utc::now(),
        }];

        // weighted = 0.5 * 0.4 / 0.4 = 0.5 -> Suspicious
        assert_eq!(merge_verdicts_weighted(&verdicts, 0.7, 0.3), ThreatLevel::Suspicious);
    }

    fn verdict(level: ThreatLevel, confidence: f32) -> Verdict {
        use chrono::Utc;
        use riggs_types::events::EventId;
        use riggs_types::verdict::DetectionSource;
        Verdict {
            event_id: EventId::new(),
            threat_level: level,
            confidence,
            source: DetectionSource::StaticAI,
            description: "test".into(),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn corroborating_suspicious_does_not_dilute_malicious() {
        // A confirmed-malicious verdict plus two weaker corroborating signals.
        // The weighted average alone is (0.85 + 0.35 + 0.4) / 2.35 ~= 0.68,
        // which would wrongly downgrade to Suspicious. Escalation keeps it
        // Malicious because a stage already crossed its malicious threshold.
        let verdicts = vec![
            verdict(ThreatLevel::Malicious, 0.85),
            verdict(ThreatLevel::Suspicious, 0.7),
            verdict(ThreatLevel::Suspicious, 0.8),
        ];
        assert_eq!(merge_verdicts_weighted(&verdicts, 0.7, 0.3), ThreatLevel::Malicious);
    }

    #[test]
    fn nan_confidence_does_not_collapse_to_clean() {
        // A poisoned NaN confidence must not hide a co-occurring Malicious verdict.
        let verdicts = vec![
            verdict(ThreatLevel::Malicious, f32::NAN),
            verdict(ThreatLevel::Malicious, 0.9),
        ];
        assert_eq!(merge_verdicts_weighted(&verdicts, 0.7, 0.3), ThreatLevel::Malicious);
    }

    #[test]
    fn all_nan_confidence_is_clean() {
        let verdicts = vec![verdict(ThreatLevel::Malicious, f32::NAN)];
        assert_eq!(merge_verdicts_weighted(&verdicts, 0.7, 0.3), ThreatLevel::Clean);
    }
}

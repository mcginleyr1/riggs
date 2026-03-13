use async_trait::async_trait;
use chrono::Utc;

use riggs_engine::{DetectionStage, StageVerdict};
use riggs_types::errors::RiggsError;
use riggs_types::events::{EventId, RiggsEvent};
use riggs_types::verdict::{DetectionSource, ThreatLevel, Verdict};
use riggs_types::Severity;

use crate::custom::CustomRuleEngine;
use crate::ioc::IocMatcher;
use crate::yara::YaraEngine;

pub struct RulesStage {
    _yara: Option<YaraEngine>,
    ioc: Option<IocMatcher>,
    custom: Option<CustomRuleEngine>,
}

impl RulesStage {
    pub fn new(
        yara: Option<YaraEngine>,
        ioc: Option<IocMatcher>,
        custom: Option<CustomRuleEngine>,
    ) -> Self {
        Self {
            _yara: yara,
            ioc,
            custom,
        }
    }
}

fn event_id(event: &RiggsEvent) -> EventId {
    match event {
        RiggsEvent::Process(e) => e.event_id.clone(),
        RiggsEvent::File(e) => e.event_id.clone(),
        RiggsEvent::Network(e) => e.event_id.clone(),
        RiggsEvent::Dns(e) => e.event_id.clone(),
        RiggsEvent::Auth(e) => e.event_id.clone(),
        RiggsEvent::Kernel(e) => e.event_id.clone(),
    }
}

fn severity_to_threat_level(severity: Severity) -> ThreatLevel {
    match severity {
        Severity::Info | Severity::Low => ThreatLevel::Suspicious,
        Severity::Medium | Severity::High => ThreatLevel::Suspicious,
        Severity::Critical => ThreatLevel::Malicious,
    }
}

fn severity_to_confidence(severity: Severity) -> f32 {
    match severity {
        Severity::Info => 0.3,
        Severity::Low => 0.4,
        Severity::Medium => 0.6,
        Severity::High => 0.8,
        Severity::Critical => 0.95,
    }
}

#[async_trait]
impl DetectionStage for RulesStage {
    fn name(&self) -> &str {
        "rules"
    }

    async fn analyze(&self, event: &RiggsEvent) -> Result<StageVerdict, RiggsError> {
        let eid = event_id(event);

        // Run IOC matching
        if let Some(ioc_matcher) = &self.ioc {
            let ioc_hits = ioc_matcher.check_event(event);
            if !ioc_hits.is_empty() {
                let worst_severity = ioc_hits
                    .iter()
                    .map(|ioc| ioc.severity)
                    .max()
                    .unwrap_or(Severity::Low);

                let descriptions: Vec<String> = ioc_hits
                    .iter()
                    .map(|ioc| format!("{}: {}", ioc.value, ioc.description))
                    .collect();

                let threat_level = severity_to_threat_level(worst_severity);
                let confidence = severity_to_confidence(worst_severity);

                let verdict = Verdict {
                    event_id: eid.clone(),
                    threat_level,
                    confidence,
                    source: DetectionSource::IocMatch,
                    description: format!("IOC matches: {}", descriptions.join("; ")),
                    timestamp: Utc::now(),
                };

                return match threat_level {
                    ThreatLevel::Malicious => Ok(StageVerdict::Malicious(verdict)),
                    _ => Ok(StageVerdict::Suspicious(verdict)),
                };
            }
        }

        // Run custom rule evaluation
        if let Some(custom_engine) = &self.custom {
            let matched_rules = custom_engine.evaluate(event);
            if !matched_rules.is_empty() {
                let verdict = Verdict {
                    event_id: eid,
                    threat_level: ThreatLevel::Suspicious,
                    confidence: 0.7,
                    source: DetectionSource::CustomRule,
                    description: format!("Custom rules matched: {}", matched_rules.join(", ")),
                    timestamp: Utc::now(),
                };
                return Ok(StageVerdict::Suspicious(verdict));
            }
        }

        // YARA scanning is not yet wired (YaraEngine::new still uses todo!())
        // Once implemented, it would scan file events here.

        Ok(StageVerdict::Clean)
    }
}

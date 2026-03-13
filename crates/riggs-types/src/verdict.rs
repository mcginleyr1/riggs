use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::events::{EventId, StorylineId};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatLevel {
    Clean,
    Suspicious,
    Malicious,
}

impl fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatLevel::Clean => write!(f, "CLEAN"),
            ThreatLevel::Suspicious => write!(f, "SUSPICIOUS"),
            ThreatLevel::Malicious => write!(f, "MALICIOUS"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DetectionSource {
    StaticAI,
    BehavioralAI,
    YaraRule,
    IocMatch,
    CustomRule,
}

impl fmt::Display for DetectionSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DetectionSource::StaticAI => write!(f, "StaticAI"),
            DetectionSource::BehavioralAI => write!(f, "BehavioralAI"),
            DetectionSource::YaraRule => write!(f, "YaraRule"),
            DetectionSource::IocMatch => write!(f, "IocMatch"),
            DetectionSource::CustomRule => write!(f, "CustomRule"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub event_id: EventId,
    pub threat_level: ThreatLevel,
    pub confidence: f32,
    pub source: DetectionSource,
    pub description: String,
    pub timestamp: DateTime<Utc>,
}

impl Verdict {
    pub fn new(
        event_id: EventId,
        threat_level: ThreatLevel,
        confidence: f32,
        source: DetectionSource,
        description: impl Into<String>,
    ) -> Self {
        Self {
            event_id,
            threat_level,
            confidence,
            source,
            description: description.into(),
            timestamp: Utc::now(),
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} (confidence={:.0}%, source={})",
            self.event_id,
            self.threat_level,
            self.confidence * 100.0,
            self.source,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergedVerdict {
    pub event_id: EventId,
    pub final_threat_level: ThreatLevel,
    pub verdicts: Vec<Verdict>,
    pub storyline_id: StorylineId,
}

impl MergedVerdict {
    pub fn from_verdicts(
        event_id: EventId,
        storyline_id: StorylineId,
        verdicts: Vec<Verdict>,
    ) -> Self {
        let final_threat_level = verdicts
            .iter()
            .map(|v| v.threat_level)
            .max()
            .unwrap_or(ThreatLevel::Clean);
        Self {
            event_id,
            final_threat_level,
            verdicts,
            storyline_id,
        }
    }
}

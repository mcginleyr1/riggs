use std::path::PathBuf;
use std::sync::{Arc, PoisonError, RwLock};

use async_trait::async_trait;
use chrono::Utc;

use riggs_engine::{DetectionStage, StageVerdict};
use riggs_types::errors::RiggsError;
use riggs_types::events::{EventId, FileAction, RiggsEvent};
use riggs_types::verdict::{DetectionSource, ThreatLevel, Verdict};
use riggs_types::Severity;

use crate::custom::CustomRuleEngine;
use crate::ioc::IocMatcher;
use crate::yara::YaraEngine;

pub type SharedYara = Arc<RwLock<YaraEngine>>;
pub type SharedCustomRules = Arc<RwLock<CustomRuleEngine>>;

pub struct RulesStage {
    yara: Option<SharedYara>,
    ioc: Arc<RwLock<Option<IocMatcher>>>,
    custom: Option<SharedCustomRules>,
}

impl RulesStage {
    pub fn new(
        yara: Option<YaraEngine>,
        ioc: Option<IocMatcher>,
        custom: Option<CustomRuleEngine>,
    ) -> Self {
        Self {
            yara: yara.map(|y| Arc::new(RwLock::new(y))),
            ioc: Arc::new(RwLock::new(ioc)),
            custom: custom.map(|c| Arc::new(RwLock::new(c))),
        }
    }

    /// Build from handles shared with the feed dispatcher (IOC) and the rule
    /// hot-reload watcher (YARA, custom rules).
    pub fn new_shared(
        yara: Option<SharedYara>,
        ioc: Arc<RwLock<Option<IocMatcher>>>,
        custom: Option<SharedCustomRules>,
    ) -> Self {
        Self { yara, ioc, custom }
    }

    pub fn ioc_handle(&self) -> Arc<RwLock<Option<IocMatcher>>> {
        Arc::clone(&self.ioc)
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
        Severity::Info | Severity::Low | Severity::Medium => ThreatLevel::Suspicious,
        // A high-severity IOC (e.g. a live-malware URLhaus hit) is a confirmed
        // match against known-bad infrastructure, so it warrants Malicious.
        Severity::High | Severity::Critical => ThreatLevel::Malicious,
    }
}

/// Convert a verdict to a stage verdict by its threat level.
fn stage_verdict(verdict: Verdict) -> StageVerdict {
    match verdict.threat_level {
        ThreatLevel::Malicious => StageVerdict::Malicious(verdict),
        ThreatLevel::Suspicious => StageVerdict::Suspicious(verdict),
        ThreatLevel::Clean => StageVerdict::Clean,
    }
}

/// Pick the strongest verdict (highest threat level, then highest confidence).
fn strongest(candidates: Vec<Verdict>) -> Option<Verdict> {
    candidates.into_iter().max_by(|a, b| {
        a.threat_level
            .cmp(&b.threat_level)
            .then(a.confidence.total_cmp(&b.confidence))
    })
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

        // Run every matcher and keep the strongest verdict; a weak IOC/custom
        // hit must not short-circuit a stronger YARA match on the same event.
        let mut candidates: Vec<Verdict> = Vec::new();

        // IOC matching
        if let Ok(guard) = self.ioc.read() {
            if let Some(ioc_matcher) = guard.as_ref() {
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

                    candidates.push(Verdict {
                        event_id: eid.clone(),
                        threat_level: severity_to_threat_level(worst_severity),
                        confidence: severity_to_confidence(worst_severity),
                        source: DetectionSource::IocMatch,
                        description: format!("IOC matches: {}", descriptions.join("; ")),
                        timestamp: Utc::now(),
                    });
                }
            }
        }

        // Custom rule evaluation
        if let Some(custom_engine) = &self.custom {
            let matched_rules = custom_engine
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .evaluate(event);
            if !matched_rules.is_empty() {
                candidates.push(Verdict {
                    event_id: eid.clone(),
                    threat_level: ThreatLevel::Suspicious,
                    confidence: 0.7,
                    source: DetectionSource::CustomRule,
                    description: format!("Custom rules matched: {}", matched_rules.join(", ")),
                    timestamp: Utc::now(),
                });
            }
        }

        // YARA scanning — only when a file's content may have changed (not on
        // every Open/Close), and on the blocking pool since it reads the file.
        if let (Some(yara), RiggsEvent::File(fe)) = (&self.yara, event) {
            if matches!(
                fe.action,
                FileAction::Create | FileAction::Modify | FileAction::Rename | FileAction::Scan
            ) {
                let yara = Arc::clone(yara);
                let path = PathBuf::from(&fe.path);
                let scan = tokio::task::spawn_blocking(move || {
                    if !path.is_file() {
                        return Ok(Vec::new());
                    }
                    yara.read()
                        .unwrap_or_else(PoisonError::into_inner)
                        .scan_file(&path)
                })
                .await
                .map_err(|e| RiggsError::Engine(format!("YARA scan task failed: {e}")))?;

                match scan {
                    Ok(matches) if !matches.is_empty() => {
                        let rule_names: Vec<&str> =
                            matches.iter().map(|m| m.rule_name.as_str()).collect();
                        candidates.push(Verdict {
                            event_id: eid.clone(),
                            threat_level: ThreatLevel::Malicious,
                            confidence: 0.9,
                            source: DetectionSource::YaraRule,
                            description: format!("YARA rules matched: {}", rule_names.join(", ")),
                            timestamp: Utc::now(),
                        });
                    }
                    Err(e) => tracing::debug!(error = %e, path = %fe.path, "YARA scan failed"),
                    _ => {}
                }
            }
        }

        Ok(strongest(candidates)
            .map(stage_verdict)
            .unwrap_or(StageVerdict::Clean))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(level: ThreatLevel, confidence: f32, source: DetectionSource) -> Verdict {
        Verdict {
            event_id: EventId::new(),
            threat_level: level,
            confidence,
            source,
            description: String::new(),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn high_severity_ioc_maps_to_malicious() {
        assert_eq!(
            severity_to_threat_level(Severity::High),
            ThreatLevel::Malicious
        );
        assert_eq!(
            severity_to_threat_level(Severity::Medium),
            ThreatLevel::Suspicious
        );
    }

    #[test]
    fn strongest_yara_wins_over_weaker_ioc() {
        // A suspicious IOC must not suppress a malicious YARA match.
        let ioc = verdict(ThreatLevel::Suspicious, 0.8, DetectionSource::IocMatch);
        let yara = verdict(ThreatLevel::Malicious, 0.9, DetectionSource::YaraRule);
        let best = strongest(vec![ioc, yara]).unwrap();
        assert_eq!(best.threat_level, ThreatLevel::Malicious);
        assert_eq!(best.source, DetectionSource::YaraRule);
    }

    #[test]
    fn strongest_is_none_for_no_matches() {
        assert!(strongest(vec![]).is_none());
    }

    #[tokio::test]
    async fn yara_rules_in_nested_dirs_detect_created_files_only() {
        use riggs_types::events::{ProcessContext, StorylineId};

        let dir = std::env::temp_dir().join(format!("riggs-stage-yara-{}", std::process::id()));
        let yara_dir = dir.join("custom").join("yara");
        std::fs::create_dir_all(&yara_dir).unwrap();
        std::fs::write(
            yara_dir.join("t.yar"),
            r#"rule evil { strings: $a = "EVIL_MARKER" condition: $a }"#,
        )
        .unwrap();
        let sample = dir.join("dropped.bin");
        std::fs::write(&sample, b"xxEVIL_MARKERxx").unwrap();

        let stage = RulesStage::new(Some(YaraEngine::new(dir.clone()).unwrap()), None, None);
        let ctx = ProcessContext::new(1, 0, "curl", "/usr/bin/curl", "", "u", StorylineId::new());
        let path = sample.to_string_lossy().to_string();

        let created = RiggsEvent::new_file(FileAction::Create, ctx.clone(), path.clone(), None);
        let opened = RiggsEvent::new_file(FileAction::Open, ctx, path, None);
        let on_create = stage.analyze(&created).await.unwrap();
        let on_open = stage.analyze(&opened).await.unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert!(
            matches!(on_create, StageVerdict::Malicious(v) if v.source == DetectionSource::YaraRule)
        );
        assert!(matches!(on_open, StageVerdict::Clean));
    }
}

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use chrono::{DateTime, TimeDelta, Utc};
use riggs_types::errors::RiggsError;
use riggs_types::events::{RiggsEvent, StorylineId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCondition {
    ProcessName(String),
    FilePath(String),
    NetworkDest(String),
    Sequence(Vec<RuleCondition>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    pub name: String,
    pub description: String,
    pub conditions: Vec<RuleCondition>,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CustomRulesFile {
    #[serde(default)]
    rule: Vec<CustomRule>,
}

struct SequenceState {
    current_step: usize,
    started_at: DateTime<Utc>,
}

pub struct CustomRuleEngine {
    rules: Vec<CustomRule>,
    // Keyed by (rule name, storyline) so a sequence only advances within a
    // single process tree -- steps from unrelated processes must not combine.
    sequence_state: Mutex<HashMap<(String, StorylineId), SequenceState>>,
    sequence_timeout: TimeDelta,
}

impl CustomRuleEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            sequence_state: Mutex::new(HashMap::new()),
            sequence_timeout: TimeDelta::seconds(60),
        }
    }

    pub fn add_rule(&mut self, rule: CustomRule) {
        self.rules.push(rule);
    }

    pub fn load_from_file(path: &Path) -> Result<Vec<CustomRule>, RiggsError> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            RiggsError::Io(format!(
                "failed to read rules file {}: {}",
                path.display(),
                e
            ))
        })?;
        let file: CustomRulesFile = toml::from_str(&contents).map_err(|e| {
            RiggsError::Config(format!(
                "failed to parse TOML rules from {}: {}",
                path.display(),
                e
            ))
        })?;
        Ok(file.rule)
    }

    pub fn evaluate(&self, event: &RiggsEvent) -> Vec<String> {
        let mut matched_rules = Vec::new();
        let now = Utc::now();
        let storyline_id = event.storyline_id().clone();
        // Recover the guard on poison rather than panicking every subsequent call.
        let mut states = self
            .sequence_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        for rule in &self.rules {
            let has_sequence = rule
                .conditions
                .iter()
                .any(|c| matches!(c, RuleCondition::Sequence(_)));

            if has_sequence {
                for condition in &rule.conditions {
                    if let RuleCondition::Sequence(steps) = condition {
                        let state = states
                            .entry((rule.name.clone(), storyline_id.clone()))
                            .or_insert_with(|| SequenceState {
                                current_step: 0,
                                started_at: now,
                            });

                        // Reset on timeout
                        if (now - state.started_at) > self.sequence_timeout {
                            state.current_step = 0;
                            state.started_at = now;
                        }

                        if state.current_step < steps.len()
                            && condition_matches(&steps[state.current_step], event)
                        {
                            if state.current_step == 0 {
                                state.started_at = now;
                            }
                            state.current_step += 1;

                            if state.current_step >= steps.len() {
                                matched_rules.push(rule.name.clone());
                                state.current_step = 0;
                            }
                        }
                    }
                }
            } else {
                let all_match = rule
                    .conditions
                    .iter()
                    .all(|cond| condition_matches(cond, event));
                if all_match {
                    matched_rules.push(rule.name.clone());
                }
            }
        }

        // Prune stale sequence states
        let prune_limit = self.sequence_timeout * 2;
        states.retain(|_, state| (now - state.started_at) <= prune_limit);

        matched_rules
    }
}

fn condition_matches(condition: &RuleCondition, event: &RiggsEvent) -> bool {
    match condition {
        RuleCondition::ProcessName(name) => {
            let process_name = match event {
                RiggsEvent::Process(e) => &e.process_context.name,
                RiggsEvent::File(e) => &e.process_context.name,
                RiggsEvent::Network(e) => &e.process_context.name,
                RiggsEvent::Dns(e) => &e.process_context.name,
                RiggsEvent::Auth(e) => &e.process_context.name,
                RiggsEvent::Kernel(e) => &e.process_context.name,
            };
            process_name == name
        }
        RuleCondition::FilePath(path) => {
            if let RiggsEvent::File(e) = event {
                e.path == *path
            } else {
                false
            }
        }
        RuleCondition::NetworkDest(addr) => {
            if let RiggsEvent::Network(e) = event {
                e.dst_addr == *addr
            } else {
                false
            }
        }
        RuleCondition::Sequence(_) => {
            // Sequence matching is handled at the rule level in evaluate(),
            // not at the individual condition level. This arm should not be
            // reached directly during normal evaluation.
            false
        }
    }
}

impl Default for CustomRuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use riggs_types::events::*;

    fn dummy_process_context(name: &str, storyline: &StorylineId) -> ProcessContext {
        ProcessContext {
            pid: 1,
            ppid: 0,
            name: name.into(),
            path: "/usr/bin/test".into(),
            cmdline: "test".into(),
            user: "root".into(),
            storyline_id: storyline.clone(),
        }
    }

    fn process_event(name: &str, storyline: &StorylineId) -> RiggsEvent {
        RiggsEvent::Process(ProcessEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context: dummy_process_context(name, storyline),
            action: ProcessAction::Exec,
            parent_context: None,
        })
    }

    fn file_event(name: &str, path: &str, storyline: &StorylineId) -> RiggsEvent {
        RiggsEvent::File(FileEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context: dummy_process_context(name, storyline),
            action: FileAction::Create,
            path: path.into(),
            hash: None,
            fd: None,
        })
    }

    fn network_event(name: &str, dst: &str, storyline: &StorylineId) -> RiggsEvent {
        RiggsEvent::Network(NetworkEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context: dummy_process_context(name, storyline),
            direction: NetworkDirection::Outbound,
            src_addr: "127.0.0.1".into(),
            dst_addr: dst.into(),
            src_port: 12345,
            dst_port: 443,
            protocol: "tcp".into(),
        })
    }

    #[test]
    fn simple_condition_matches() {
        let mut engine = CustomRuleEngine::new();
        engine.add_rule(CustomRule {
            name: "detect-curl".into(),
            description: "detect curl process".into(),
            conditions: vec![RuleCondition::ProcessName("curl".into())],
            action: "alert".into(),
        });

        let sid = StorylineId::new();
        let matched = engine.evaluate(&process_event("curl", &sid));
        assert_eq!(matched, vec!["detect-curl"]);

        let matched = engine.evaluate(&process_event("wget", &sid));
        assert!(matched.is_empty());
    }

    #[test]
    fn sequence_condition_progresses_across_events() {
        let mut engine = CustomRuleEngine::new();
        engine.add_rule(CustomRule {
            name: "exfil-sequence".into(),
            description: "detect data exfiltration pattern".into(),
            conditions: vec![RuleCondition::Sequence(vec![
                RuleCondition::FilePath("/etc/passwd".into()),
                RuleCondition::NetworkDest("evil.example.com".into()),
            ])],
            action: "block".into(),
        });

        let sid = StorylineId::new();
        // First event: file access -- should not match yet
        let matched = engine.evaluate(&file_event("cat", "/etc/passwd", &sid));
        assert!(matched.is_empty());

        // Second event (same storyline): network connection completes the sequence
        let matched = engine.evaluate(&network_event("curl", "evil.example.com", &sid));
        assert_eq!(matched, vec!["exfil-sequence"]);
    }

    #[test]
    fn sequence_does_not_combine_across_storylines() {
        let mut engine = CustomRuleEngine::new();
        engine.add_rule(CustomRule {
            name: "exfil-sequence".into(),
            description: "test".into(),
            conditions: vec![RuleCondition::Sequence(vec![
                RuleCondition::FilePath("/etc/passwd".into()),
                RuleCondition::NetworkDest("evil.example.com".into()),
            ])],
            action: "block".into(),
        });

        // Step 1 in one process tree, step 2 in an unrelated one: must NOT match.
        let matched = engine.evaluate(&file_event("cat", "/etc/passwd", &StorylineId::new()));
        assert!(matched.is_empty());
        let matched =
            engine.evaluate(&network_event("curl", "evil.example.com", &StorylineId::new()));
        assert!(matched.is_empty());
    }

    #[test]
    fn sequence_resets_after_completion() {
        let mut engine = CustomRuleEngine::new();
        engine.add_rule(CustomRule {
            name: "seq-rule".into(),
            description: "test".into(),
            conditions: vec![RuleCondition::Sequence(vec![
                RuleCondition::ProcessName("step1".into()),
                RuleCondition::ProcessName("step2".into()),
            ])],
            action: "alert".into(),
        });

        let sid = StorylineId::new();
        let _ = engine.evaluate(&process_event("step1", &sid));
        let matched = engine.evaluate(&process_event("step2", &sid));
        assert_eq!(matched, vec!["seq-rule"]);

        // After completion, sequence should reset -- step2 alone should not match
        let matched = engine.evaluate(&process_event("step2", &sid));
        assert!(matched.is_empty());

        // But a fresh sequence should work again
        let _ = engine.evaluate(&process_event("step1", &sid));
        let matched = engine.evaluate(&process_event("step2", &sid));
        assert_eq!(matched, vec!["seq-rule"]);
    }

    #[test]
    fn sequence_wrong_order_does_not_match() {
        let mut engine = CustomRuleEngine::new();
        engine.add_rule(CustomRule {
            name: "ordered".into(),
            description: "test".into(),
            conditions: vec![RuleCondition::Sequence(vec![
                RuleCondition::ProcessName("first".into()),
                RuleCondition::ProcessName("second".into()),
            ])],
            action: "alert".into(),
        });

        let sid = StorylineId::new();
        // Send them in reverse order
        let matched = engine.evaluate(&process_event("second", &sid));
        assert!(matched.is_empty());
        let matched = engine.evaluate(&process_event("first", &sid));
        assert!(matched.is_empty());
        // Now step 1 matched, so step 2 should complete it
        let matched = engine.evaluate(&process_event("second", &sid));
        assert_eq!(matched, vec!["ordered"]);
    }

    #[test]
    fn sequence_timeout_resets_progress() {
        let mut engine = CustomRuleEngine::new();
        engine.sequence_timeout = TimeDelta::zero(); // immediate timeout for testing
        engine.add_rule(CustomRule {
            name: "timeout-rule".into(),
            description: "test".into(),
            conditions: vec![RuleCondition::Sequence(vec![
                RuleCondition::ProcessName("a".into()),
                RuleCondition::ProcessName("b".into()),
            ])],
            action: "alert".into(),
        });

        let sid = StorylineId::new();
        let _ = engine.evaluate(&process_event("a", &sid));

        // With timeout=0, the next evaluate sees the state as expired and resets.
        std::thread::sleep(std::time::Duration::from_millis(10));

        // "b" should not match because the sequence timed out and was reset
        let matched = engine.evaluate(&process_event("b", &sid));
        assert!(matched.is_empty());
    }
}

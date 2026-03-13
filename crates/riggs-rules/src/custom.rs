use std::path::Path;

use riggs_types::errors::RiggsError;
use riggs_types::events::RiggsEvent;
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

pub struct CustomRuleEngine {
    rules: Vec<CustomRule>,
}

impl CustomRuleEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: CustomRule) {
        self.rules.push(rule);
    }

    pub fn load_from_file(path: &Path) -> Result<Vec<CustomRule>, RiggsError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| RiggsError::Io(format!("failed to read rules file {}: {}", path.display(), e)))?;
        let file: CustomRulesFile = toml::from_str(&contents)
            .map_err(|e| RiggsError::Config(format!("failed to parse TOML rules from {}: {}", path.display(), e)))?;
        Ok(file.rule)
    }

    pub fn evaluate(&self, event: &RiggsEvent) -> Vec<String> {
        let mut matched_rules = Vec::new();

        for rule in &self.rules {
            let all_conditions_match = rule.conditions.iter().all(|cond| condition_matches(cond, event));
            if all_conditions_match {
                matched_rules.push(rule.name.clone());
            }
        }

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
            // Sequence conditions require cross-event state tracking.
            // This needs a state machine that persists across multiple evaluate() calls,
            // which is a significant design decision. Leaving as unimplemented for now.
            todo!("Sequence condition requires stateful cross-event tracking")
        }
    }
}

impl Default for CustomRuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

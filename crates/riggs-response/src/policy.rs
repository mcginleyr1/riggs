use std::path::Path;

use riggs_types::errors::RiggsError;
use riggs_types::verdict::{MergedVerdict, ThreatLevel};
use serde::{Deserialize, Serialize};

use crate::actions::ResponseAction;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub min_threat_level: ThreatLevel,
    pub conditions: Vec<String>,
    pub actions: Vec<ResponseAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePolicy {
    pub rules: Vec<PolicyRule>,
}

impl Default for ResponsePolicy {
    fn default() -> Self {
        Self {
            rules: vec![
                PolicyRule {
                    min_threat_level: ThreatLevel::Malicious,
                    conditions: vec!["critical_confidence".into()],
                    actions: vec![
                        ResponseAction::KillProcess { pid: 0 },
                        ResponseAction::QuarantineFile {
                            path: std::path::PathBuf::new(),
                        },
                    ],
                },
                PolicyRule {
                    min_threat_level: ThreatLevel::Malicious,
                    conditions: vec![],
                    actions: vec![ResponseAction::QuarantineFile {
                        path: std::path::PathBuf::new(),
                    }],
                },
                PolicyRule {
                    min_threat_level: ThreatLevel::Suspicious,
                    conditions: vec![],
                    actions: vec![],
                },
            ],
        }
    }
}

/// TOML representation for deserialization.
/// The TOML file uses string keys that map to our internal types.
///
/// Example TOML:
/// ```toml
/// [[rules]]
/// min_threat_level = "Malicious"
/// conditions = ["critical_confidence"]
///
/// [[rules.actions]]
/// type = "KillProcess"
/// pid = 0
///
/// [[rules.actions]]
/// type = "QuarantineFile"
/// path = ""
/// ```
#[derive(Debug, Deserialize)]
struct TomlPolicy {
    rules: Vec<TomlPolicyRule>,
}

#[derive(Debug, Deserialize)]
struct TomlPolicyRule {
    min_threat_level: String,
    #[serde(default)]
    conditions: Vec<String>,
    #[serde(default)]
    actions: Vec<TomlAction>,
}

#[derive(Debug, Deserialize)]
struct TomlAction {
    #[serde(rename = "type")]
    action_type: String,
    pid: Option<u32>,
    path: Option<String>,
    allowed_ips: Option<Vec<String>>,
    storyline_id: Option<String>,
}

fn parse_threat_level(s: &str) -> Result<ThreatLevel, RiggsError> {
    match s {
        "Clean" | "clean" => Ok(ThreatLevel::Clean),
        "Suspicious" | "suspicious" => Ok(ThreatLevel::Suspicious),
        "Malicious" | "malicious" => Ok(ThreatLevel::Malicious),
        other => Err(RiggsError::Config(format!(
            "unknown threat level: {other}"
        ))),
    }
}

fn parse_action(toml_action: &TomlAction) -> Result<ResponseAction, RiggsError> {
    match toml_action.action_type.as_str() {
        "KillProcess" => {
            let pid = toml_action.pid.unwrap_or(0);
            Ok(ResponseAction::KillProcess { pid })
        }
        "SuspendProcess" => {
            let pid = toml_action.pid.unwrap_or(0);
            Ok(ResponseAction::SuspendProcess { pid })
        }
        "QuarantineFile" => {
            let path = toml_action
                .path
                .as_deref()
                .unwrap_or("")
                .into();
            Ok(ResponseAction::QuarantineFile { path })
        }
        "DeleteFile" => {
            let path = toml_action
                .path
                .as_deref()
                .unwrap_or("")
                .into();
            Ok(ResponseAction::DeleteFile { path })
        }
        "NetworkContain" => {
            let allowed_ips = toml_action
                .allowed_ips
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|ip| {
                    ip.parse()
                        .map_err(|e| RiggsError::Config(format!("invalid IP {ip}: {e}")))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ResponseAction::NetworkContain { allowed_ips })
        }
        "NetworkRelease" => Ok(ResponseAction::NetworkRelease),
        "Rollback" => {
            let raw = toml_action
                .storyline_id
                .as_deref()
                .ok_or_else(|| RiggsError::Config("Rollback requires storyline_id".into()))?;
            let uuid = uuid::Uuid::parse_str(raw)
                .map_err(|e| RiggsError::Config(format!("invalid storyline_id UUID: {e}")))?;
            Ok(ResponseAction::Rollback {
                storyline_id: riggs_types::events::StorylineId(uuid),
            })
        }
        other => Err(RiggsError::Config(format!(
            "unknown action type: {other}"
        ))),
    }
}

impl ResponsePolicy {
    pub fn load_from_toml(path: &Path) -> Result<Self, RiggsError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| RiggsError::Config(format!("failed to read policy file: {e}")))?;

        let toml_policy: TomlPolicy = toml::from_str(&content)
            .map_err(|e| RiggsError::Config(format!("failed to parse policy TOML: {e}")))?;

        let mut rules = Vec::with_capacity(toml_policy.rules.len());
        for toml_rule in &toml_policy.rules {
            let min_threat_level = parse_threat_level(&toml_rule.min_threat_level)?;
            let actions = toml_rule
                .actions
                .iter()
                .map(parse_action)
                .collect::<Result<Vec<_>, _>>()?;

            rules.push(PolicyRule {
                min_threat_level,
                conditions: toml_rule.conditions.clone(),
                actions,
            });
        }

        Ok(Self { rules })
    }

    pub fn evaluate(&self, verdict: &MergedVerdict) -> Vec<ResponseAction> {
        let mut selected = Vec::new();

        for rule in &self.rules {
            if verdict.final_threat_level >= rule.min_threat_level
                && self.conditions_met(&rule.conditions, verdict)
            {
                selected.extend(rule.actions.clone());
                break;
            }
        }

        selected
    }

    fn conditions_met(&self, conditions: &[String], verdict: &MergedVerdict) -> bool {
        for condition in conditions {
            match condition.as_str() {
                "critical_confidence" => {
                    let has_high_confidence =
                        verdict.verdicts.iter().any(|v| v.confidence >= 0.95);
                    if !has_high_confidence {
                        return false;
                    }
                }
                "multi_source" => {
                    let sources: Vec<_> =
                        verdict.verdicts.iter().map(|v| v.source).collect();
                    let distinct = sources
                        .iter()
                        .enumerate()
                        .filter(|(i, s)| !sources[..*i].contains(s))
                        .count();
                    if distinct < 2 {
                        return false;
                    }
                }
                "behavioral_match" => {
                    let has_behavioral = verdict.verdicts.iter().any(|v| {
                        v.source == riggs_types::verdict::DetectionSource::BehavioralAI
                    });
                    if !has_behavioral {
                        return false;
                    }
                }
                "static_match" => {
                    let has_static = verdict.verdicts.iter().any(|v| {
                        v.source == riggs_types::verdict::DetectionSource::StaticAI
                    });
                    if !has_static {
                        return false;
                    }
                }
                _ => {
                    // Unknown conditions fail open -- treat as not met to
                    // avoid accidentally triggering drastic actions.
                    return false;
                }
            }
        }
        true
    }
}

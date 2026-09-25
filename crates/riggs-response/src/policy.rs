use std::path::{Path, PathBuf};

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
        other => Err(RiggsError::Config(format!("unknown threat level: {other}"))),
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
            let path = toml_action.path.as_deref().unwrap_or("").into();
            Ok(ResponseAction::QuarantineFile { path })
        }
        "DeleteFile" => {
            let path = toml_action.path.as_deref().unwrap_or("").into();
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
        other => Err(RiggsError::Config(format!("unknown action type: {other}"))),
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

    /// Select response actions for a verdict, filling placeholder targets
    /// (pid 0 / empty path) with the concrete pid/path of the triggering event.
    ///
    /// `target_pid` is the offending process; `target_path` is the offending
    /// file when the event is a file event. Actions whose placeholder cannot be
    /// resolved are dropped so a broken action (e.g. `kill(0)`) never runs.
    pub fn evaluate(
        &self,
        verdict: &MergedVerdict,
        target_pid: u32,
        target_path: Option<&Path>,
    ) -> Vec<ResponseAction> {
        let mut selected = Vec::new();

        for rule in &self.rules {
            if verdict.final_threat_level >= rule.min_threat_level
                && self.conditions_met(&rule.conditions, verdict)
            {
                for action in &rule.actions {
                    if let Some(concrete) = concretize_action(action, target_pid, target_path) {
                        selected.push(concrete);
                    }
                }
                break;
            }
        }

        selected
    }

    fn conditions_met(&self, conditions: &[String], verdict: &MergedVerdict) -> bool {
        for condition in conditions {
            match condition.as_str() {
                "critical_confidence" => {
                    let has_high_confidence = verdict.verdicts.iter().any(|v| v.confidence >= 0.95);
                    if !has_high_confidence {
                        return false;
                    }
                }
                "multi_source" => {
                    let sources: Vec<_> = verdict.verdicts.iter().map(|v| v.source).collect();
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
                    let has_behavioral = verdict
                        .verdicts
                        .iter()
                        .any(|v| v.source == riggs_types::verdict::DetectionSource::BehavioralAI);
                    if !has_behavioral {
                        return false;
                    }
                }
                "static_match" => {
                    let has_static = verdict
                        .verdicts
                        .iter()
                        .any(|v| v.source == riggs_types::verdict::DetectionSource::StaticAI);
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

/// Resolve a policy action's placeholder target against the triggering event.
///
/// A pid of 0 or an empty path are placeholders in the policy (the concrete
/// target is only known at runtime). Returns `None` when a placeholder cannot
/// be resolved, or when a process target resolves to pid <= 1 (which would
/// signal the daemon's own process group or init).
fn concretize_action(
    action: &ResponseAction,
    target_pid: u32,
    target_path: Option<&Path>,
) -> Option<ResponseAction> {
    match action {
        ResponseAction::KillProcess { pid } => {
            let pid = if *pid == 0 { target_pid } else { *pid };
            (pid > 1).then_some(ResponseAction::KillProcess { pid })
        }
        ResponseAction::SuspendProcess { pid } => {
            let pid = if *pid == 0 { target_pid } else { *pid };
            (pid > 1).then_some(ResponseAction::SuspendProcess { pid })
        }
        ResponseAction::QuarantineFile { path } => {
            resolve_path(path, target_path).map(|path| ResponseAction::QuarantineFile { path })
        }
        ResponseAction::DeleteFile { path } => {
            resolve_path(path, target_path).map(|path| ResponseAction::DeleteFile { path })
        }
        other => Some(other.clone()),
    }
}

fn resolve_path(configured: &Path, target: Option<&Path>) -> Option<PathBuf> {
    if configured.as_os_str().is_empty() {
        target.map(Path::to_path_buf)
    } else {
        Some(configured.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use riggs_types::events::{EventId, StorylineId};
    use riggs_types::verdict::MergedVerdict;

    fn malicious_verdict() -> MergedVerdict {
        MergedVerdict {
            event_id: EventId::new(),
            final_threat_level: ThreatLevel::Malicious,
            verdicts: vec![],
            storyline_id: StorylineId::new(),
        }
    }

    #[test]
    fn default_policy_substitutes_real_pid_and_path() {
        // The default policy's second rule (Malicious, no conditions) quarantines.
        let policy = ResponsePolicy::default();
        let actions = policy.evaluate(&malicious_verdict(), 4321, Some(Path::new("/tmp/evil")));

        assert!(actions.iter().any(|a| matches!(
            a,
            ResponseAction::QuarantineFile { path } if path == Path::new("/tmp/evil")
        )));
    }

    #[test]
    fn placeholder_kill_is_dropped_without_a_real_pid() {
        // pid 0 placeholder + unknown target (0) must not produce a kill(0).
        let action = ResponseAction::KillProcess { pid: 0 };
        assert!(concretize_action(&action, 0, None).is_none());
        assert!(concretize_action(&action, 1, None).is_none());
        assert!(matches!(
            concretize_action(&action, 42, None),
            Some(ResponseAction::KillProcess { pid: 42 })
        ));
    }

    #[test]
    fn placeholder_quarantine_dropped_without_a_path() {
        let action = ResponseAction::QuarantineFile {
            path: PathBuf::new(),
        };
        assert!(concretize_action(&action, 42, None).is_none());
    }

    #[test]
    fn explicit_targets_pass_through() {
        let action = ResponseAction::KillProcess { pid: 99 };
        assert!(matches!(
            concretize_action(&action, 42, None),
            Some(ResponseAction::KillProcess { pid: 99 })
        ));
    }
}

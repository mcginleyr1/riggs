use std::path::{Path, PathBuf};

use riggs_types::config::ResponseConfig;
use riggs_types::errors::RiggsError;
use riggs_types::events::{ProcessContext, StorylineId};
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
    /// Executable paths or names kill and suspend never target.
    #[serde(default)]
    pub protected: Vec<String>,
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
                        ResponseAction::Rollback {
                            storyline_id: DETECTED_STORYLINE,
                        },
                    ],
                },
                PolicyRule {
                    min_threat_level: ThreatLevel::Malicious,
                    conditions: vec![],
                    actions: vec![
                        ResponseAction::QuarantineFile {
                            path: std::path::PathBuf::new(),
                        },
                        ResponseAction::Rollback {
                            storyline_id: DETECTED_STORYLINE,
                        },
                    ],
                },
                PolicyRule {
                    min_threat_level: ThreatLevel::Suspicious,
                    conditions: vec![],
                    actions: vec![],
                },
            ],
            protected: Vec::new(),
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
        // Without storyline_id, Rollback targets the detection's storyline.
        "Rollback" => {
            let storyline_id =
                match toml_action.storyline_id.as_deref() {
                    None => DETECTED_STORYLINE,
                    Some(raw) => StorylineId(uuid::Uuid::parse_str(raw).map_err(|e| {
                        RiggsError::Config(format!("invalid storyline_id UUID: {e}"))
                    })?),
                };
            Ok(ResponseAction::Rollback { storyline_id })
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

        Ok(Self {
            rules,
            protected: Vec::new(),
        })
    }

    /// The default rules without the actions `[response]` switches off.
    pub fn from_config(config: &ResponseConfig) -> Self {
        let mut policy = Self::default();
        for rule in &mut policy.rules {
            rule.actions.retain(|action| match action {
                ResponseAction::KillProcess { .. } => config.kill_on_critical,
                ResponseAction::QuarantineFile { .. } => config.quarantine_on_malicious,
                _ => true,
            });
        }
        policy.protected = config.protected_processes.clone();
        policy
    }

    pub fn protects(&self, process: &ProcessContext) -> bool {
        self.protected.iter().any(|entry| {
            if entry.starts_with('/') {
                *entry == process.path
            } else {
                *entry == process.name
                    || Path::new(&process.path)
                        .file_name()
                        .is_some_and(|n| n == entry.as_str())
            }
        })
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
        storyline: &StorylineId,
    ) -> Vec<ResponseAction> {
        let mut selected = Vec::new();

        for rule in &self.rules {
            if verdict.final_threat_level >= rule.min_threat_level
                && self.conditions_met(&rule.conditions, verdict)
            {
                for action in &rule.actions {
                    if let Some(concrete) =
                        concretize_action(action, target_pid, target_path, storyline)
                    {
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
/// signal the daemon's own process group or init) or to the daemon itself.
/// A Rollback with this storyline id targets the detection's own storyline.
pub const DETECTED_STORYLINE: StorylineId = StorylineId(uuid::Uuid::nil());

fn concretize_action(
    action: &ResponseAction,
    target_pid: u32,
    target_path: Option<&Path>,
    storyline: &StorylineId,
) -> Option<ResponseAction> {
    match action {
        ResponseAction::Rollback { storyline_id } if *storyline_id == DETECTED_STORYLINE => {
            Some(ResponseAction::Rollback {
                storyline_id: storyline.clone(),
            })
        }
        ResponseAction::KillProcess { pid } => {
            let pid = if *pid == 0 { target_pid } else { *pid };
            (pid > 1 && pid != std::process::id()).then_some(ResponseAction::KillProcess { pid })
        }
        ResponseAction::SuspendProcess { pid } => {
            let pid = if *pid == 0 { target_pid } else { *pid };
            (pid > 1 && pid != std::process::id()).then_some(ResponseAction::SuspendProcess { pid })
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
    use riggs_types::verdict::{MergedVerdict, Verdict};

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
        let storyline = StorylineId::new();
        let actions = policy.evaluate(
            &malicious_verdict(),
            4321,
            Some(Path::new("/tmp/evil")),
            &storyline,
        );

        assert!(actions.iter().any(|a| matches!(
            a,
            ResponseAction::QuarantineFile { path } if path == Path::new("/tmp/evil")
        )));
        assert!(actions.iter().any(|a| matches!(
            a,
            ResponseAction::Rollback { storyline_id } if *storyline_id == storyline
        )));
    }

    fn critical_actions(config: &ResponseConfig) -> Vec<String> {
        let mut verdict = malicious_verdict();
        verdict.verdicts.push(Verdict::new(
            verdict.event_id.clone(),
            ThreatLevel::Malicious,
            0.99,
            riggs_types::verdict::DetectionSource::StaticAI,
            "sample",
        ));
        ResponsePolicy::from_config(config)
            .evaluate(
                &verdict,
                4321,
                Some(Path::new("/tmp/evil")),
                &StorylineId(uuid::Uuid::from_u128(1)),
            )
            .iter()
            .map(|a| a.to_string())
            .collect()
    }

    #[test]
    fn each_switch_removes_exactly_its_action() {
        let all = critical_actions(&ResponseConfig::default());
        let no_kill = critical_actions(&ResponseConfig {
            kill_on_critical: false,
            ..ResponseConfig::default()
        });
        let no_quarantine = critical_actions(&ResponseConfig {
            quarantine_on_malicious: false,
            ..ResponseConfig::default()
        });

        assert_eq!(all.len(), 3);
        assert_eq!(
            no_kill,
            all.iter()
                .filter(|a| !a.starts_with("Kill"))
                .cloned()
                .collect::<Vec<_>>()
        );
        assert_eq!(
            no_quarantine,
            all.iter()
                .filter(|a| !a.starts_with("Quarantine"))
                .cloned()
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn protected_entries_match_a_full_path_exactly_and_a_bare_name_by_basename() {
        let policy = ResponsePolicy {
            protected: vec!["/sbin/launchd".into(), "WindowServer".into()],
            ..ResponsePolicy::default()
        };
        let process = |name: &str, path: &str| ProcessContext {
            pid: 9,
            ppid: 1,
            name: name.into(),
            path: path.into(),
            cmdline: path.into(),
            user: "0".into(),
            storyline_id: StorylineId::new(),
        };

        assert!(policy.protects(&process("launchd", "/sbin/launchd")));
        assert!(!policy.protects(&process("launchd", "/tmp/launchd")));
        assert!(policy.protects(&process("x", "/tmp/WindowServer")));
    }

    #[test]
    fn toml_rollback_without_storyline_targets_the_detection() {
        let action = TomlAction {
            action_type: "Rollback".into(),
            pid: None,
            path: None,
            allowed_ips: None,
            storyline_id: None,
        };
        let parsed = parse_action(&action).unwrap();
        let storyline = StorylineId::new();

        assert!(matches!(
            concretize_action(&parsed, 0, None, &storyline),
            Some(ResponseAction::Rollback { storyline_id }) if storyline_id == storyline
        ));
    }

    #[test]
    fn placeholder_kill_is_dropped_without_a_real_pid() {
        // pid 0 placeholder + unknown target (0) must not produce a kill(0).
        let action = ResponseAction::KillProcess { pid: 0 };
        let storyline = StorylineId::new();
        assert!(concretize_action(&action, 0, None, &storyline).is_none());
        assert!(concretize_action(&action, 1, None, &storyline).is_none());
        assert!(matches!(
            concretize_action(&action, 42, None, &storyline),
            Some(ResponseAction::KillProcess { pid: 42 })
        ));
    }

    #[test]
    fn critical_hit_on_an_unattributed_file_quarantines_without_killing() {
        // What an on-demand scan produces: no acting process (pid 0), a file path.
        let mut verdict = malicious_verdict();
        verdict.verdicts.push(Verdict::new(
            verdict.event_id.clone(),
            ThreatLevel::Malicious,
            0.99,
            riggs_types::verdict::DetectionSource::StaticAI,
            "packed sample",
        ));
        let actions = ResponsePolicy::default().evaluate(
            &verdict,
            0,
            Some(Path::new("/tmp/evil")),
            &StorylineId::new(),
        );

        assert!(actions
            .iter()
            .any(|a| matches!(a, ResponseAction::QuarantineFile { .. })));
        assert!(!actions
            .iter()
            .any(|a| matches!(a, ResponseAction::KillProcess { .. })));
    }

    #[test]
    fn kill_and_suspend_never_target_the_daemon_itself() {
        let own_pid = std::process::id();
        let storyline = StorylineId::new();
        for action in [
            ResponseAction::KillProcess { pid: 0 },
            ResponseAction::SuspendProcess { pid: 0 },
            ResponseAction::KillProcess { pid: own_pid },
        ] {
            assert!(concretize_action(&action, own_pid, None, &storyline).is_none());
        }
    }

    #[test]
    fn placeholder_quarantine_dropped_without_a_path() {
        let action = ResponseAction::QuarantineFile {
            path: PathBuf::new(),
        };
        assert!(concretize_action(&action, 42, None, &StorylineId::new()).is_none());
    }

    #[test]
    fn explicit_targets_pass_through() {
        let action = ResponseAction::KillProcess { pid: 99 };
        assert!(matches!(
            concretize_action(&action, 42, None, &StorylineId::new()),
            Some(ResponseAction::KillProcess { pid: 99 })
        ));
    }
}

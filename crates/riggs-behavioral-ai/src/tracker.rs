use std::collections::{HashMap, HashSet};

use chrono::Duration;
use riggs_types::events::{
    FileAction, NetworkDirection, ProcessAction, RiggsEvent, StorylineId,
};

use crate::patterns::BehaviorPattern;

pub struct BehaviorTracker {
    storylines: HashMap<StorylineId, Vec<RiggsEvent>>,
}

impl BehaviorTracker {
    pub fn new() -> Self {
        Self {
            storylines: HashMap::new(),
        }
    }

    pub fn track(&mut self, event: RiggsEvent) {
        let storyline_id = extract_storyline_id(&event);
        self.storylines
            .entry(storyline_id)
            .or_default()
            .push(event);
    }

    pub fn check_patterns(&self, storyline_id: &StorylineId) -> Vec<BehaviorPattern> {
        let events = match self.storylines.get(storyline_id) {
            Some(events) => events,
            None => return Vec::new(),
        };

        let mut patterns = Vec::new();

        if let Some(p) = self.check_rapid_file_encryption(events) {
            patterns.push(p);
        }
        if let Some(p) = self.check_process_injection(events) {
            patterns.push(p);
        }
        if let Some(p) = self.check_privilege_escalation(events) {
            patterns.push(p);
        }
        if let Some(p) = self.check_lateral_movement(events) {
            patterns.push(p);
        }
        if let Some(p) = self.check_data_exfiltration(events) {
            patterns.push(p);
        }
        if let Some(p) = self.check_persistence_mechanism(events) {
            patterns.push(p);
        }
        if let Some(p) = self.check_suspicious_child_process(events) {
            patterns.push(p);
        }
        if let Some(p) = self.check_crypto_mining(events) {
            patterns.push(p);
        }

        patterns
    }

    pub fn storyline_event_count(&self, storyline_id: &StorylineId) -> usize {
        self.storylines
            .get(storyline_id)
            .map(|events| events.len())
            .unwrap_or(0)
    }

    fn check_rapid_file_encryption(&self, events: &[RiggsEvent]) -> Option<BehaviorPattern> {
        let file_modify_timestamps: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                RiggsEvent::File(fe) if fe.action == FileAction::Modify => Some((fe.timestamp, fe.path.as_str())),
                _ => None,
            })
            .collect();

        if file_modify_timestamps.len() < 10 {
            return None;
        }

        let window = Duration::seconds(5);
        // Sliding window: for each event, count unique file paths within 5 seconds
        for (i, (ts, _)) in file_modify_timestamps.iter().enumerate() {
            let mut unique_paths: HashSet<&str> = HashSet::new();
            for (other_ts, path) in &file_modify_timestamps[i..] {
                if *other_ts - *ts > window {
                    break;
                }
                unique_paths.insert(path);
            }
            if unique_paths.len() > 10 {
                return Some(BehaviorPattern::RapidFileEncryption);
            }
        }
        None
    }

    fn check_process_injection(&self, _events: &[RiggsEvent]) -> Option<BehaviorPattern> {
        // TODO: detect WriteProcessMemory + CreateRemoteThread patterns
        // or ptrace attach + mmap + mprotect sequences
        None
    }

    fn check_privilege_escalation(&self, _events: &[RiggsEvent]) -> Option<BehaviorPattern> {
        // TODO: detect uid changes, sudo invocations, setuid calls
        None
    }

    fn check_lateral_movement(&self, _events: &[RiggsEvent]) -> Option<BehaviorPattern> {
        // TODO: detect SSH/RDP/SMB connections to internal hosts
        // combined with credential access
        None
    }

    fn check_data_exfiltration(&self, events: &[RiggsEvent]) -> Option<BehaviorPattern> {
        const OUTBOUND_THRESHOLD: usize = 50;
        let outbound_count = events
            .iter()
            .filter(|e| matches!(e, RiggsEvent::Network(ne) if ne.direction == NetworkDirection::Outbound))
            .count();

        if outbound_count >= OUTBOUND_THRESHOLD {
            return Some(BehaviorPattern::DataExfiltration);
        }
        None
    }

    fn check_persistence_mechanism(&self, events: &[RiggsEvent]) -> Option<BehaviorPattern> {
        const PERSISTENCE_PATHS: &[&str] = &[
            "/Library/LaunchDaemons",
            "/Library/LaunchAgents",
            "~/Library/LaunchAgents",
            ".config/autostart",
            "/etc/cron.d",
            "/etc/crontab",
            "/var/spool/cron",
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/etc/init.d",
            "/etc/rc.local",
        ];

        for event in events {
            if let RiggsEvent::File(fe) = event {
                if matches!(fe.action, FileAction::Create | FileAction::Modify) {
                    let path_lower = fe.path.to_lowercase();
                    for persistence_path in PERSISTENCE_PATHS {
                        if path_lower.contains(&persistence_path.to_lowercase()) {
                            return Some(BehaviorPattern::PersistenceMechanism);
                        }
                    }
                }
            }
        }
        None
    }

    fn check_suspicious_child_process(&self, events: &[RiggsEvent]) -> Option<BehaviorPattern> {
        const SUSPICIOUS_PARENTS: &[&str] = &[
            "office", "word", "excel", "powerpoint", "outlook",
            "pdf", "acrobat", "preview", "evince",
            "libreoffice", "pages", "numbers", "keynote",
        ];
        const SHELL_BINARIES: &[&str] = &[
            "/bin/sh", "/bin/bash", "/bin/zsh", "/usr/bin/sh",
            "/usr/bin/bash", "/usr/bin/zsh", "/bin/dash",
            "python", "python3", "perl", "ruby",
            "powershell", "pwsh", "cmd.exe",
        ];

        for event in events {
            if let RiggsEvent::Process(pe) = event {
                if pe.action != ProcessAction::Exec {
                    continue;
                }
                if let Some(parent) = &pe.parent_context {
                    let parent_name_lower = parent.name.to_lowercase();
                    let is_suspicious_parent = SUSPICIOUS_PARENTS
                        .iter()
                        .any(|s| parent_name_lower.contains(s));

                    if !is_suspicious_parent {
                        continue;
                    }

                    let child_path_lower = pe.process_context.path.to_lowercase();
                    let child_name_lower = pe.process_context.name.to_lowercase();
                    let is_shell_child = SHELL_BINARIES.iter().any(|s| {
                        child_path_lower.contains(s) || child_name_lower.contains(s)
                    });

                    if is_shell_child {
                        return Some(BehaviorPattern::SuspiciousChildProcess);
                    }
                }
            }
        }
        None
    }

    fn check_crypto_mining(&self, _events: &[RiggsEvent]) -> Option<BehaviorPattern> {
        // TODO: detect connections to known mining pools
        // combined with high CPU process events
        None
    }
}

impl Default for BehaviorTracker {
    fn default() -> Self {
        Self::new()
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

use std::collections::{HashMap, HashSet};

use chrono::Duration;
use riggs_types::events::{
    AuthAction, FileAction, KernelAction, NetworkDirection, ProcessAction, RiggsEvent, StorylineId,
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

    fn check_process_injection(&self, events: &[RiggsEvent]) -> Option<BehaviorPattern> {
        // Signal 1: KernelEvent::MemoryExec — shellcode execution in memory
        // This is the kernel telling us a process executed code that wasn't
        // mapped from a file (i.e., dynamically generated shellcode).
        // Immediate critical signal — no threshold needed.
        for event in events {
            if let RiggsEvent::Kernel(k) = event {
                if k.action == KernelAction::MemoryExec {
                    return Some(BehaviorPattern::ProcessInjection);
                }
            }
        }
        None
    }

    fn check_privilege_escalation(&self, events: &[RiggsEvent]) -> Option<BehaviorPattern> {
        // Signal 1: AuthEvent::Escalation — direct privilege escalation attempt
        // The OS auth subsystem reported an escalation (sudo, su, pkexec, etc.)
        for event in events {
            if let RiggsEvent::Auth(ae) = event {
                if ae.action == AuthAction::Escalation {
                    return Some(BehaviorPattern::PrivilegeEscalation);
                }
            }
        }

        // Signal 2: AuthEvent::Failed followed by AuthEvent::Login from same process
        // Brute-force pattern: failed auth attempt succeeded shortly after
        let auth_events: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                RiggsEvent::Auth(ae) => Some((ae.timestamp, &ae.action, &ae.user)),
                _ => None,
            })
            .collect();

        if auth_events.len() >= 2 {
            for i in 0..auth_events.len() {
                if auth_events[i].1 == &AuthAction::Failed {
                    // Look for a successful login from the same user within 60 seconds
                    for j in (i + 1)..auth_events.len() {
                        if auth_events[j].1 == &AuthAction::Login
                            && auth_events[i].2 == &auth_events[j].2 // same user
                            && (auth_events[j].0 - auth_events[i].0) <= Duration::seconds(60)
                        {
                            return Some(BehaviorPattern::PrivilegeEscalation);
                        }
                    }
                }
            }
        }

        // Signal 3: Process cmdline contains privilege escalation tools
        // Tools like sudo, su, pkexec, doas, runuser are used to gain elevated privileges
        const ESCALATION_COMMANDS: &[&str] = &["sudo ", "sudo\t", " pkexec", " doas", " runuser"];

        for event in events {
            if let RiggsEvent::Process(pe) = event {
                if pe.action == ProcessAction::Exec {
                    let cmdline_lower = pe.process_context.cmdline.to_lowercase();
                    if ESCALATION_COMMANDS
                        .iter()
                        .any(|cmd| cmdline_lower.contains(cmd))
                    {
                        return Some(BehaviorPattern::PrivilegeEscalation);
                    }
                }
            }
        }

        // Signal 4: Process running as root with non-root parent
        // A process spawned as root when its parent is not root is suspicious
        for event in events {
            if let RiggsEvent::Process(pe) = event {
                if pe.action == ProcessAction::Exec {
                    let is_root = pe.process_context.user == "root"
                        || pe.process_context.user == "0";
                    if let Some(parent) = &pe.parent_context {
                        let parent_is_root = parent.user == "root" || parent.user == "0";
                        if is_root && !parent_is_root {
                            return Some(BehaviorPattern::PrivilegeEscalation);
                        }
                    }
                }
            }
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx(pid: u32, name: &str) -> ProcessContext {
        ProcessContext::new(
            pid, 0, name, format!("/usr/bin/{}", name), "",
            "user",
            StorylineId::new(),
        )
    }

    #[test]
    fn test_memory_exec_detected() {
        let ctx = make_ctx(1234, "suspicious");
        let kernel_event = RiggsEvent::new_kernel(
            KernelAction::MemoryExec,
            ctx.clone(),
            "shellcode executed in anonymous memory mapping",
        );
        let events = vec![kernel_event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::ProcessInjection));
    }

    #[test]
    fn test_no_memory_exec_returns_none() {
        let ctx = make_ctx(1234, "bash");
        let process_event = RiggsEvent::new_process(
            ProcessAction::Exec,
            ctx.clone(),
            None,
        );
        let events = vec![process_event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_memory_exec_mixed_with_other_events() {
        let ctx = make_ctx(5678, "python3");
        let normal_event = RiggsEvent::new_process(
            ProcessAction::Exec,
            ctx.clone(),
            None,
        );
        let kernel_event = RiggsEvent::new_kernel(
            KernelAction::MemoryExec,
            ctx,
            "mmap+exec memory region",
        );
        let events = vec![normal_event, kernel_event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[1].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::ProcessInjection));
    }

    #[test]
    fn test_other_kernel_actions_not_flagged() {
        let ctx = make_ctx(9999, "kernel_task");
        let module_load = RiggsEvent::new_kernel(
            KernelAction::ModuleLoad,
            ctx,
            "loaded /System/Library/Extensions/foo.kext",
        );
        let events = vec![module_load];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        // ModuleLoad alone should not trigger process injection
        assert!(!patterns.contains(&BehaviorPattern::ProcessInjection));
    }

    // --- Privilege Escalation Tests ---

    fn make_auth_event(
        action: AuthAction,
        pid: u32,
        user: &str,
        method: &str,
    ) -> RiggsEvent {
        let ctx = ProcessContext::new(
            pid, 0, "auth_service", "/usr/sbin/authserv", "",
            user,
            StorylineId::new(),
        );
        RiggsEvent::new_auth(action, ctx, user, method)
    }

    #[test]
    fn test_auth_escalation_detected() {
        let auth_event = make_auth_event(
            AuthAction::Escalation,
            1001,
            "user",
            "sudo",
        );
        let events = vec![auth_event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::PrivilegeEscalation));
    }

    #[test]
    fn test_brute_force_success_detected() {
        let failed = make_auth_event(
            AuthAction::Failed,
            2001,
            "user",
            "password",
        );
        let success = make_auth_event(
            AuthAction::Login,
            2001,
            "user",
            "password",
        );
        let events = vec![failed, success];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[1].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::PrivilegeEscalation));
    }

    #[test]
    fn test_brute_force_different_users_not_flagged() {
        let failed = make_auth_event(
            AuthAction::Failed,
            3001,
            "user",
            "password",
        );
        let success = make_auth_event(
            AuthAction::Login,
            3001,
            "admin",
            "password",
        );
        let events = vec![failed, success];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[1].storyline_id());

        // Different users — not a brute force pattern
        assert!(!patterns.contains(&BehaviorPattern::PrivilegeEscalation));
    }

    #[test]
    fn test_sudo_in_cmdline_detected() {
        let ctx = ProcessContext::new(
            4001, 0, "bash", "/bin/bash",
            "sudo apt update",
            "user",
            StorylineId::new(),
        );
        let exec_event = RiggsEvent::new_process(
            ProcessAction::Exec,
            ctx,
            None,
        );
        let events = vec![exec_event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::PrivilegeEscalation));
    }

    #[test]
    fn test_pkexec_in_cmdline_detected() {
        let ctx = ProcessContext::new(
            5001, 0, "pkexec", "/usr/bin/pkexec",
            "pkexec /usr/bin/systemctl restart nginx",
            "user",
            StorylineId::new(),
        );
        let exec_event = RiggsEvent::new_process(
            ProcessAction::Exec,
            ctx,
            None,
        );
        let events = vec![exec_event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::PrivilegeEscalation));
    }

    #[test]
    fn test_root_process_from_nonroot_parent_detected() {
        let parent_ctx = ProcessContext::new(
            6001, 0, "firefox", "/usr/bin/firefox",
            "",
            "user",
            StorylineId::new(),
        );
        let child_ctx = ProcessContext::new(
            6002, 6001, "suid_exploit", "/tmp/exploit",
            "",
            "root",
            StorylineId::new(),
        );
        let exec_event = RiggsEvent::new_process(
            ProcessAction::Exec,
            child_ctx,
            Some(parent_ctx),
        );
        let events = vec![exec_event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::PrivilegeEscalation));
    }

    #[test]
    fn test_root_from_root_parent_not_flagged() {
        let parent_ctx = ProcessContext::new(
            7001, 0, "sshd", "/usr/sbin/sshd",
            "",
            "root",
            StorylineId::new(),
        );
        let child_ctx = ProcessContext::new(
            7002, 7001, "bash", "/bin/bash",
            "",
            "root",
            StorylineId::new(),
        );
        let exec_event = RiggsEvent::new_process(
            ProcessAction::Exec,
            child_ctx,
            Some(parent_ctx),
        );
        let events = vec![exec_event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        // Normal: root spawning root (e.g., ssh session)
        assert!(!patterns.contains(&BehaviorPattern::PrivilegeEscalation));
    }

    #[test]
    fn test_no_privilege_escalation_in_normal_events() {
        let ctx = make_ctx(8001, "normal_app");
        let exec_event = RiggsEvent::new_process(
            ProcessAction::Exec,
            ctx,
            None,
        );
        let events = vec![exec_event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }
}

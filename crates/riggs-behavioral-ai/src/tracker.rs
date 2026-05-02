use std::collections::{HashMap, HashSet};

use chrono::{Duration, Utc};
use riggs_types::events::{
    AuthAction, EventId, FileAction, FileEvent, KernelAction, NetworkDirection, ProcessAction, RiggsEvent, StorylineId,
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

    fn check_lateral_movement(&self, events: &[RiggsEvent]) -> Option<BehaviorPattern> {
        // Signal 1: Outbound connections to internal IPs on lateral movement ports
        // Internal ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        // Ports: 22 (SSH), 135 (DCOM), 445 (SMB), 3389 (RDP), 5985 (WinRM), 5986 (WinRM-SSL)
        const LATERAL_PORTS: &[u16] = &[22, 135, 445, 3389, 5985, 5986];

        for event in events {
            if let RiggsEvent::Network(ne) = event {
                if ne.direction != NetworkDirection::Outbound {
                    continue;
                }
                if !LATERAL_PORTS.contains(&ne.dst_port) {
                    continue;
                }
                if Self::is_internal_ip(&ne.dst_addr) {
                    return Some(BehaviorPattern::LateralMovement);
                }
            }
        }

        // Signal 2: DNS query for internal hostname followed by network connection
        // Detects DNS reconnaissance → exploitation pattern
        let dns_queries: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                RiggsEvent::Dns(de) => Some((de.timestamp, &de.query)),
                _ => None,
            })
            .collect();

        let network_events: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                RiggsEvent::Network(ne) if ne.direction == NetworkDirection::Outbound => {
                    Some((ne.timestamp, &ne.dst_addr))
                }
                _ => None,
            })
            .collect();

        for (dns_ts, dns_query) in &dns_queries {
            for (net_ts, net_dst) in &network_events {
                // DNS query happened before the network connection
                if *net_ts < *dns_ts {
                    continue;
                }
                // Within 30-second window
                if *net_ts - *dns_ts > Duration::seconds(30) {
                    continue;
                }
                // DNS query resolved to the destination IP
                if dns_query == net_dst || dns_query.trim_end_matches('.') == net_dst {
                    return Some(BehaviorPattern::LateralMovement);
                }
            }
        }

        // Signal 3: AuthEvent (Failed/Login) combined with outbound network to internal host
        // Credential access + lateral movement from same process
        let auth_events: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                RiggsEvent::Auth(ae) => Some((ae.timestamp, &ae.action, ae.process_context.pid)),
                _ => None,
            })
            .collect();

        let outbound_internal: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                RiggsEvent::Network(ne)
                    if ne.direction == NetworkDirection::Outbound
                        && Self::is_internal_ip(&ne.dst_addr) =>
                {
                    Some((ne.timestamp, ne.process_context.pid))
                }
                _ => None,
            })
            .collect();

        for (auth_ts, auth_action, pid) in &auth_events {
            if !matches!(auth_action, AuthAction::Failed | AuthAction::Login) {
                continue;
            }
            for (net_ts, net_pid) in &outbound_internal {
                if pid != net_pid {
                    continue;
                }
                // Auth event within 60 seconds of network connection
                let time_diff = if *net_ts > *auth_ts {
                    *net_ts - *auth_ts
                } else {
                    *auth_ts - *net_ts
                };
                if time_diff <= Duration::seconds(60) {
                    return Some(BehaviorPattern::LateralMovement);
                }
            }
        }

        None
    }

    fn is_internal_ip(addr: &str) -> bool {
        // Check if address is in private/internal IP ranges
        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
        let parts: Vec<&str> = addr.split('.').collect();
        if parts.len() != 4 {
            return false;
        }

        let octets: Result<Vec<u8>, _> = parts.iter().map(|p| p.parse::<u8>()).collect();
        let Ok(octets) = octets else {
            return false;
        };

        // 10.0.0.0/8
        if octets[0] == 10 {
            return true;
        }
        // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
        if octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31 {
            return true;
        }
        // 192.168.0.0/16
        if octets[0] == 192 && octets[1] == 168 {
            return true;
        }
        // 127.0.0.0/8 (loopback)
        if octets[0] == 127 {
            return true;
        }

        false
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

    fn check_crypto_mining(&self, events: &[RiggsEvent]) -> Option<BehaviorPattern> {
        // Crypto mining detection (MITRE T1496 — Resource Hijacking)
        // Uses multi-signal scoring to reduce false positives.
        // No single signal is definitive — we look for combinations.

        let mut score = 0;
        let mut signals = Vec::new();

        // === Signal 1: Outbound connections to mining pool ports ===
        // Ports used by Stratum protocol and mining pool proxies
        const MINING_PORTS: &[u16] = &[
            3333, 443, 4433, 4444, 5555, 6666, 7777, 8333,
            8888, 9999, 14444, 14445, 45700, 55555,
        ];

        let mining_port_connections: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                RiggsEvent::Network(ne)
                    if ne.direction == NetworkDirection::Outbound
                        && MINING_PORTS.contains(&ne.dst_port) =>
                {
                    Some((ne.timestamp, &ne.dst_addr, ne.dst_port))
                }
                _ => None,
            })
            .collect();

        if !mining_port_connections.is_empty() {
            score += 1;
            signals.push("mining_port".to_string());
        }

        // === Signal 2: DNS queries to mining pool domains ===
        // Curated list of known mining pool domains
        const MINING_DOMAINS: &[&str] = &[
            "f2pool.com",
            "nicehash.com",
            "pool.ethermine.org",
            "solo.ethermine.org",
            "ethermine.org",
            "2miners.com",
            "herominers.com",
            "miningpoolhub.com",
            "coinhive.com",
            "minexmr.com",
            "coinpot.co",
            "miningrigrentals.com",
            "poolin.com",
            "antpool.com",
            "pool.btc.com",
            "btc.com",
            "slushpool.com",
            "wafflepool.com",
            "hashvault.pro",
            "hashflare.io",
            "genuinevesta.com",
            "pool.bitcoin.com",
            "navpool.com",
        ];

        let mining_domain_queries: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                RiggsEvent::Dns(de) => {
                    let query_lower = de.query.to_lowercase();
                    let response_lower = de.response.to_lowercase();
                    if MINING_DOMAINS
                        .iter()
                        .any(|domain| query_lower.contains(domain) || response_lower.contains(domain))
                    {
                        Some((de.timestamp, &de.query))
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .collect();

        if !mining_domain_queries.is_empty() {
            score += 1;
            signals.push("mining_domain".to_string());
        }

        // === Signal 3: Known miner binary/process name ===
        // Detect execution of known mining software by name or path
        const MINER_NAMES: &[&str] = &[
            "xmrig", "cpuminer", "minerd", "ethminer", "ethdcrminer",
            "ccminer", "bfgminer", "cgminer", "lolminers", "t-rex",
            "minergate", "cryptonight", "randomx",
        ];

        let miner_process_detected = events.iter().any(|e| {
            if let RiggsEvent::Process(pe) = e {
                let name_lower = pe.process_context.name.to_lowercase();
                let path_lower = pe.process_context.path.to_lowercase();
                let cmdline_lower = pe.process_context.cmdline.to_lowercase();

                MINER_NAMES.iter().any(|miner| {
                    name_lower.contains(miner)
                        || path_lower.contains(miner)
                        || cmdline_lower.contains(miner)
                })
            } else {
                false
            }
        });

        if miner_process_detected {
            score += 1;
            signals.push("miner_binary".to_string());
        }

        // === Signal 4: High CPU heuristic (fork/exec storm) ===
        // Mining processes often spawn child processes rapidly to distribute work.
        // We detect this via rapid exec events in the storyline.
        const CHILD_EXEC_THRESHOLD: usize = 10;
        const EXEC_WINDOW_SECS: i64 = 60;

        let exec_timestamps: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                RiggsEvent::Process(pe) if pe.action == ProcessAction::Exec => {
                    Some(pe.timestamp)
                }
                _ => None,
            })
            .collect();

        let mut fork_exec_storm = false;
        if exec_timestamps.len() >= CHILD_EXEC_THRESHOLD {
            for i in 0..exec_timestamps.len() {
                let mut count = 0;
                for j in i..exec_timestamps.len() {
                    if (exec_timestamps[j] - exec_timestamps[i]).num_seconds() <= EXEC_WINDOW_SECS {
                        count += 1;
                    } else {
                        break;
                    }
                }
                if count >= CHILD_EXEC_THRESHOLD {
                    fork_exec_storm = true;
                    break;
                }
            }
        }

        if fork_exec_storm {
            score += 1;
            signals.push("fork_exec_storm".to_string());
        }

        // === Decision: multi-signal scoring ===
        // 1 signal alone = Suspicious (conflict with legitimate uses)
        // 2+ signals = Malicious (strong indicator of mining)
        // Miner binary + mining port = Malicious (very strong indicator)
        match score {
            0 => None,
            1 => {
                // Single signal — suspicious but not conclusive
                // Port-only without domain correlation is weak (443 is common)
                if signals == vec!["mining_port"] {
                    None // Too weak alone — port 443 is too noisy
                } else {
                    Some(BehaviorPattern::CryptoMining)
                }
            }
            2.. => Some(BehaviorPattern::CryptoMining),
        }
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

    // --- Lateral Movement Tests ---

    fn make_network_event(
        direction: NetworkDirection,
        pid: u32,
        dst_addr: &str,
        dst_port: u16,
    ) -> RiggsEvent {
        let ctx = ProcessContext::new(
            pid, 0, "ssh", "/usr/bin/ssh", "",
            "user",
            StorylineId::new(),
        );
        RiggsEvent::new_network(
            direction,
            ctx,
            "192.168.1.100",
            dst_addr,
            52000,
            dst_port,
            "tcp",
        )
    }

    fn make_dns_event(pid: u32, query: &str, response: &str) -> RiggsEvent {
        let ctx = ProcessContext::new(
            pid, 0, "curl", "/usr/bin/curl", "",
            "user",
            StorylineId::new(),
        );
        RiggsEvent::new_dns(ctx, query, response, "A")
    }

    #[test]
    fn test_ssh_to_internal_ip_detected() {
        let event = make_network_event(
            NetworkDirection::Outbound,
            9001,
            "192.168.1.50",
            22, // SSH
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::LateralMovement));
    }

    #[test]
    fn test_rdp_to_internal_ip_detected() {
        let event = make_network_event(
            NetworkDirection::Outbound,
            9002,
            "10.0.0.50",
            3389, // RDP
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::LateralMovement));
    }

    #[test]
    fn test_smb_to_internal_ip_detected() {
        let event = make_network_event(
            NetworkDirection::Outbound,
            9003,
            "172.16.5.10",
            445, // SMB
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::LateralMovement));
    }

    #[test]
    fn test_winrm_to_internal_ip_detected() {
        let event = make_network_event(
            NetworkDirection::Outbound,
            9004,
            "10.10.0.20",
            5985, // WinRM
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::LateralMovement));
    }

    #[test]
    fn test_outbound_to_public_ip_not_flagged() {
        let event = make_network_event(
            NetworkDirection::Outbound,
            9005,
            "8.8.8.8",
            443,
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(!patterns.contains(&BehaviorPattern::LateralMovement));
    }

    #[test]
    fn test_inbound_to_internal_ip_not_flagged() {
        let event = make_network_event(
            NetworkDirection::Inbound,
            9006,
            "192.168.1.50",
            22,
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        // Inbound connections are not lateral movement
        assert!(!patterns.contains(&BehaviorPattern::LateralMovement));
    }

    #[test]
    fn test_outbound_to_internal_on_web_port_not_flagged() {
        let event = make_network_event(
            NetworkDirection::Outbound,
            9007,
            "192.168.1.50",
            443, // HTTPS, not a lateral movement port
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(!patterns.contains(&BehaviorPattern::LateralMovement));
    }

    #[test]
    fn test_dns_recon_to_connection_detected() {
        // DNS query for internal host, then network connection to that host
        let dns_event = make_dns_event(10001, "192.168.1.50", "192.168.1.50");
        let net_event = make_network_event(
            NetworkDirection::Outbound,
            10001,
            "192.168.1.50",
            22,
        );
        let events = vec![dns_event, net_event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[1].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::LateralMovement));
    }

    #[test]
    fn test_auth_failed_with_internal_network_detected() {
        let auth_event = make_auth_event(
            AuthAction::Failed,
            11001,
            "admin",
            "password",
        );
        let net_event = make_network_event(
            NetworkDirection::Outbound,
            11001,
            "10.0.0.100",
            445,
        );
        let events = vec![auth_event, net_event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[1].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::LateralMovement));
    }

    #[test]
    fn test_auth_login_with_internal_network_detected() {
        let auth_event = make_auth_event(
            AuthAction::Login,
            12001,
            "admin",
            "ssh",
        );
        let net_event = make_network_event(
            NetworkDirection::Outbound,
            12001,
            "172.16.0.5",
            3389,
        );
        let events = vec![auth_event, net_event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[1].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::LateralMovement));
    }

    #[test]
    fn test_auth_with_different_pid_not_flagged() {
        let auth_event = make_auth_event(
            AuthAction::Failed,
            13001,
            "admin",
            "password",
        );
        let net_event = make_network_event(
            NetworkDirection::Outbound,
            13002, // Different PID
            "10.0.0.100",
            445,
        );
        let events = vec![auth_event, net_event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[1].storyline_id());

        // Different PIDs — not from the same process
        assert!(!patterns.contains(&BehaviorPattern::LateralMovement));
    }

    #[test]
    fn test_internal_ip_detection() {
        // 10.x.x.x
        assert!(BehaviorTracker::is_internal_ip("10.0.0.1"));
        assert!(BehaviorTracker::is_internal_ip("10.255.255.255"));
        // 172.16-31.x.x
        assert!(BehaviorTracker::is_internal_ip("172.16.0.1"));
        assert!(BehaviorTracker::is_internal_ip("172.31.255.255"));
        assert!(!BehaviorTracker::is_internal_ip("172.15.0.1"));
        assert!(!BehaviorTracker::is_internal_ip("172.32.0.1"));
        // 192.168.x.x
        assert!(BehaviorTracker::is_internal_ip("192.168.0.1"));
        assert!(BehaviorTracker::is_internal_ip("192.168.255.255"));
        assert!(!BehaviorTracker::is_internal_ip("192.169.0.1"));
        // 127.x.x.x
        assert!(BehaviorTracker::is_internal_ip("127.0.0.1"));
        assert!(BehaviorTracker::is_internal_ip("127.255.255.255"));
        // Public IPs
        assert!(!BehaviorTracker::is_internal_ip("8.8.8.8"));
        assert!(!BehaviorTracker::is_internal_ip("1.1.1.1"));
        assert!(!BehaviorTracker::is_internal_ip("203.0.113.50"));
        // Invalid
        assert!(!BehaviorTracker::is_internal_ip("not-an-ip"));
        assert!(!BehaviorTracker::is_internal_ip("192.168.1"));
    }

    #[test]
    fn test_no_lateral_movement_in_normal_events() {
        let ctx = make_ctx(14001, "web_browser");
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

    // --- Crypto Mining Tests ---

    fn make_mining_network_event(pid: u32, dst_addr: &str, dst_port: u16) -> RiggsEvent {
        let ctx = ProcessContext::new(
            pid, 0, "miner", "/tmp/xmrig", "",
            "user",
            StorylineId::new(),
        );
        RiggsEvent::new_network(
            NetworkDirection::Outbound,
            ctx,
            "192.168.1.100",
            dst_addr,
            52000,
            dst_port,
            "tcp",
        )
    }

    fn make_mining_dns_event(pid: u32, query: &str, response: &str) -> RiggsEvent {
        let ctx = ProcessContext::new(
            pid, 0, "miner", "/tmp/xmrig", "",
            "user",
            StorylineId::new(),
        );
        RiggsEvent::new_dns(ctx, query, response, "A")
    }

    fn make_mining_process_event(pid: u32, name: &str, path: &str, cmdline: &str) -> RiggsEvent {
        let ctx = ProcessContext::new(
            pid, 0, name, path, cmdline,
            "user",
            StorylineId::new(),
        );
        RiggsEvent::new_process(ProcessAction::Exec, ctx, None)
    }

    #[test]
    fn test_mining_port_connection_detected() {
        let event = make_mining_network_event(20001, "pool.example.com", 3333);
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        // Mining port alone is suspicious but not conclusive (443 is noisy)
        // Port 3333 should trigger detection
        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_mining_port_4444_detected() {
        let event = make_mining_network_event(20002, "f2pool.com", 4444);
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_mining_port_14444_detected() {
        let event = make_mining_network_event(20003, "ethermine.org", 14444);
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_mining_port_45700_detected() {
        let event = make_mining_network_event(20004, "nicehash.com", 45700);
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_port_443_alone_not_flagged() {
        // Port 443 is common for HTTPS — too noisy alone
        let event = make_mining_network_event(20005, "example.com", 443);
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        // Port 443 alone is intentionally not flagged (too many legitimate uses)
        assert!(patterns.is_empty());
    }

    #[test]
    fn test_outbound_not_flagged_on_non_mining_port() {
        let event = make_mining_network_event(20006, "example.com", 8080);
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_inbound_to_mining_port_not_flagged() {
        let event = make_mining_network_event(20007, "192.168.1.50");
        // Note: this helper uses Outbound direction, so we need to create manually
        let ctx = ProcessContext::new(
            20007, 0, "server", "/usr/bin/server", "",
            "user",
            StorylineId::new(),
        );
        let inbound_event = RiggsEvent::new_network(
            NetworkDirection::Inbound,
            ctx,
            "192.168.1.50",
            "192.168.1.50",
            52000,
            3333,
            "tcp",
        );
        let events = vec![inbound_event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        // Inbound connections are not mining
        assert!(patterns.is_empty());
    }

    #[test]
    fn test_mining_domain_dns_detected() {
        let event = make_mining_dns_event(21001, "pool.ethermine.org", "146.190.28.145");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_mining_domain_nicehash_detected() {
        let event = make_mining_dns_event(21002, "www.nicehash.com", "185.177.150.207");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_mining_domain_in_response_detected() {
        let event = make_mining_dns_event(21003, "random-lookup.com", "f2pool.com");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        // Domain in response also triggers detection
        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_normal_dns_not_flagged() {
        let event = make_mining_dns_event(21004, "www.google.com", "142.250.80.46");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_mining_binary_name_detected() {
        let event = make_mining_process_event(22001, "xmrig", "/tmp/xmrig", "./xmrig -o pool.example.com");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_cpuminer_binary_detected() {
        let event = make_mining_process_event(22002, "cpuminer", "/usr/local/bin/cpuminer", "./cpuminer -a sha256d");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_ethminer_binary_detected() {
        let event = make_mining_process_event(22003, "ethminer", "/usr/bin/ethminer", "ethminer -G");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_mining_name_in_cmdline_detected() {
        let event = make_mining_process_event(22004, "bash", "/bin/bash", "./start_mining.sh");
        // "xmrig" not in name/path, but mining script implies it
        // Actually, let's test with xmrig in cmdline
        let event = make_mining_process_event(22004, "bash", "/bin/bash", "./xmrig -o pool.example.com");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_normal_process_not_flagged() {
        let event = make_mining_process_event(22005, "firefox", "/usr/bin/firefox", "firefox");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_mining_port_plus_domain_detected() {
        // Two signals: mining port + mining domain = strong indicator
        let net_event = make_mining_network_event(23001, "pool.ethermine.org", 3333);
        let dns_event = make_mining_dns_event(23001, "pool.ethermine.org", "146.190.28.145");
        let events = vec![net_event, dns_event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[1].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_mining_binary_plus_port_detected() {
        // Two signals: miner binary + mining port = strong indicator
        let proc_event = make_mining_process_event(23002, "xmrig", "/tmp/xmrig", "./xmrig");
        let net_event = make_mining_network_event(23002, "pool.example.com", 3333);
        let events = vec![proc_event, net_event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[1].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_mining_binary_plus_domain_detected() {
        // Two signals: miner binary + mining domain = strong indicator
        let proc_event = make_mining_process_event(23003, "xmrig", "/tmp/xmrig", "./xmrig");
        let dns_event = make_mining_dns_event(23003, "pool.ethermine.org", "146.190.28.145");
        let events = vec![proc_event, dns_event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[1].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_no_crypto_mining_in_normal_events() {
        let ctx = make_ctx(24001, "web_browser");
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

    #[test]
    fn test_all_events_normal_no_mining() {
        let ctx = make_ctx(24002, "chrome");
        let exec_event = RiggsEvent::new_process(
            ProcessAction::Exec,
            ctx.clone(),
            None,
        );
        let dns_event = make_mining_dns_event(24002, "www.google.com", "142.250.80.46");
        let net_event = make_mining_network_event(24002, "142.250.80.46", 443);
        let events = vec![exec_event, dns_event, net_event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[2].storyline_id());

        // Normal browsing — no mining signals
        assert!(patterns.is_empty());
    }

   // --- Persistence Mechanism Tests (T1543) ---

    fn make_file_event(pid: u32, name: &str, action: FileAction, path: &str) -> RiggsEvent {
        let ctx = ProcessContext::new(
            pid, 0, name, format!("/usr/bin/{}", name), "",
            "user",
            StorylineId::new(),
        );

// HEAD (main): Crypto mining / Ransomware tests
        RiggsEvent::new_file(FileAction::Modify, ctx, path, None)
    }

    #[test]
    fn test_rapid_file_encryption_detected() {
        // Simulate ransomware: 15 unique files modified in rapid succession
        // All timestamps will be nearly identical (Utc::now()), well within 5s window
        let ctx = ProcessContext::new(
            30001, 0, "ransomware", "/tmp/ransomware", "./ransomware",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..15)
            .map(|i| {
                RiggsEvent::File(FileEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx.clone(),
                    action: FileAction::Modify,
                    path: format!("/home/user/documents/file_{}.docx", i),
                    hash: None,
                    fd: None,
                })
            })
            .collect();

// Branch: Persistence mechanism / Suspicious child process tests
        RiggsEvent::new_file(action, ctx, path, None)
    }

    #[test]
    fn test_launchdaemon_create_detected() {
        let event = make_file_event(32001, "installer", FileAction::Create, "/Library/LaunchDaemons/com.evil.backdoor.plist");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);

// HEAD (main): Crypto mining / Ransomware tests
        assert!(matches!(patterns[0], BehaviorPattern::RapidFileEncryption));
    }

    #[test]
    fn test_rapid_file_encryption_boundary_11_files() {
        // Exactly 11 unique files (threshold is >10, so 11 should trigger)
        let ctx = ProcessContext::new(
            30002, 0, "crypto_locker", "/tmp/crypto_locker", "",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..11)
            .map(|i| {
                RiggsEvent::File(FileEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx.clone(),
                    action: FileAction::Modify,
                    path: format!("/data/file_{}.txt", i),
                    hash: None,
                    fd: None,
                })
            })
            .collect();

// Branch: Persistence mechanism / Suspicious child process tests
        assert!(matches!(patterns[0], BehaviorPattern::PersistenceMechanism));
    }

    #[test]
    fn test_launchdaemon_modify_detected() {
        let event = make_file_event(32002, "installer", FileAction::Modify, "/Library/LaunchDaemons/com.evil.backdoor.plist");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);

// HEAD (main): Crypto mining / Ransomware tests
        assert!(matches!(patterns[0], BehaviorPattern::RapidFileEncryption));
    }

    #[test]
    fn test_no_false_positive_9_files() {
        // 9 unique files — below threshold (< 10 total count check)
        let ctx = ProcessContext::new(
            30003, 0, "backup", "/usr/bin/rsync", "",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..9)
            .map(|i| {
                RiggsEvent::File(FileEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx.clone(),
                    action: FileAction::Modify,
                    path: format!("/data/file_{}.txt", i),
                    hash: None,
                    fd: None,
                })
            })
            .collect();

// Branch: Persistence mechanism / Suspicious child process tests
        assert!(matches!(patterns[0], BehaviorPattern::PersistenceMechanism));
    }

    #[test]
    fn test_launchagent_create_detected() {
        let event = make_file_event(32003, "installer", FileAction::Create, "/Library/LaunchAgents/com.evil.backdoor.plist");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::PersistenceMechanism));
    }

    #[test]
    fn test_home_launchagent_detected() {
        let event = make_file_event(32004, "installer", FileAction::Create, "~/Library/LaunchAgents/com.evil.backdoor.plist");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::PersistenceMechanism));
    }

    #[test]
    fn test_config_autostart_detected() {
        let event = make_file_event(32005, "installer", FileAction::Create, "/home/user/.config/autostart/backdoor.desktop");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::PersistenceMechanism));
    }

    #[test]
    fn test_cron_d_create_detected() {
        let event = make_file_event(32006, "installer", FileAction::Create, "/etc/cron.d/backdoor");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::PersistenceMechanism));
    }

    #[test]
    fn test_crontab_modify_detected() {
        let event = make_file_event(32007, "installer", FileAction::Modify, "/etc/crontab");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::PersistenceMechanism));
    }

    #[test]
    fn test_spool_cron_detected() {
        let event = make_file_event(32008, "installer", FileAction::Create, "/var/spool/cron/crontabs/root");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::PersistenceMechanism));
    }

    #[test]
    fn test_systemd_system_create_detected() {
        let event = make_file_event(32009, "installer", FileAction::Create, "/etc/systemd/system/backdoor.service");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::PersistenceMechanism));
    }

    #[test]
    fn test_usr_lib_systemd_create_detected() {
        let event = make_file_event(32010, "installer", FileAction::Create, "/usr/lib/systemd/system/backdoor.service");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::PersistenceMechanism));
    }

    #[test]
    fn test_init_d_modify_detected() {
        let event = make_file_event(32011, "installer", FileAction::Modify, "/etc/init.d/backdoor");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::PersistenceMechanism));
    }

    #[test]
    fn test_rc_local_modify_detected() {
        let event = make_file_event(32012, "installer", FileAction::Modify, "/etc/rc.local");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::PersistenceMechanism));
    }

    #[test]
    fn test_normal_file_create_not_flagged() {
        let event = make_file_event(32013, "editor", FileAction::Create, "/home/user/documents/report.docx");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]

// HEAD (main): Crypto mining / Ransomware tests
    fn test_no_false_positive_10_files() {
        // Exactly 10 unique files — threshold is >10, so 10 should NOT trigger
        let ctx = ProcessContext::new(
            30004, 0, "sync_tool", "/usr/bin/sync", "",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..10)
            .map(|i| {
                RiggsEvent::File(FileEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx.clone(),
                    action: FileAction::Modify,
                    path: format!("/data/file_{}.txt", i),
                    hash: None,
                    fd: None,
                })
            })
            .collect();

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_file_create_not_flagged() {
        // File creation (not modification) should not trigger
        let ctx = ProcessContext::new(
            30005, 0, "editor", "/usr/bin/vim", "",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..15)
            .map(|i| {
                RiggsEvent::File(FileEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx.clone(),
                    action: FileAction::Create,
                    path: format!("/tmp/new_file_{}.txt", i),
                    hash: None,
                    fd: None,
                })
            })
            .collect();

// Branch: Persistence mechanism / Suspicious child process tests
    fn test_normal_file_modify_not_flagged() {
        let event = make_file_event(32014, "editor", FileAction::Modify, "/home/user/documents/report.docx");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_file_delete_not_flagged() {

// HEAD (main): Crypto mining / Ransomware tests
        // File deletion should not trigger
        let ctx = ProcessContext::new(
            30006, 0, "cleanup", "/usr/bin/rm", "",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..15)
            .map(|i| {
                RiggsEvent::File(FileEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx.clone(),
                    action: FileAction::Delete,
                    path: format!("/tmp/old_file_{}.txt", i),
                    hash: None,
                    fd: None,
                })
            })
            .collect();

// Branch: Persistence mechanism / Suspicious child process tests
        let event = make_file_event(32015, "rm", FileAction::Delete, "/Library/LaunchDaemons/com.evil.backdoor.plist");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

// HEAD (main): Crypto mining / Ransomware tests

// Branch: Persistence mechanism / Suspicious child process tests
        // Delete action should not trigger persistence detection

        assert!(patterns.is_empty());
    }

    #[test]

// HEAD (main): Crypto mining / Ransomware tests
    fn test_same_file_modified_multiple_times_not_flagged() {
        // 15 modifications to the SAME file — no unique paths
        let ctx = ProcessContext::new(
            30007, 0, "logger", "/usr/bin/logger", "",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..15)
            .map(|_| {
                RiggsEvent::File(FileEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx.clone(),
                    action: FileAction::Modify,
                    path: "/var/log/app.log".to_string(),
                    hash: None,
                    fd: None,
                })
            })
            .collect();

// Branch: Persistence mechanism / Suspicious child process tests
    fn test_file_open_not_flagged() {
        let event = make_file_event(32016, "editor", FileAction::Open, "/Library/LaunchDaemons/com.evil.backdoor.plist");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

// HEAD (main): Crypto mining / Ransomware tests
        // Same file modified many times — not ransomware behavior

// Branch: Persistence mechanism / Suspicious child process tests
        // Open action should not trigger persistence detection

        assert!(patterns.is_empty());
    }

    #[test]

// HEAD (main): Crypto mining / Ransomware tests
    fn test_normal_bulk_modify_no_encryption() {
        // 15 file modifications but spread across different storylines
        // (each event has a unique storyline_id)
        let ctx = ProcessContext::new(
            30008, 0, "editor", "/usr/bin/vim", "",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..15)
            .map(|i| {
                let mut ctx = ctx.clone();
                ctx.storyline_id = StorylineId::new(); // Different storyline
                RiggsEvent::File(FileEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx,
                    action: FileAction::Modify,
                    path: format!("/home/user/notes/{}.txt", i),
                    hash: None,
                    fd: None,
                })
            })
            .collect();

        let tracker = BehaviorTracker::new();
        // Check only the last event's storyline
        let patterns = tracker.check_patterns(events[14].storyline_id());

        // Each storyline has only 1 event — no rapid encryption
        assert!(patterns.is_empty());
    }

    #[test]
    fn test_rapid_encryption_with_mixed_events() {
        // 15 file modifies mixed with other event types
        let ctx = ProcessContext::new(
            30009, 0, "ransomware", "/tmp/lock", "./lock",
            "user",
            StorylineId::new(),
        );
        let mut events: Vec<RiggsEvent> = Vec::new();
        for i in 0..15 {
            events.push(RiggsEvent::File(FileEvent {
                event_id: EventId::new(),
                timestamp: Utc::now(),
                process_context: ctx.clone(),
                action: FileAction::Modify,
                path: format!("/data/encrypted_{}.dat", i),
                hash: None,
                fd: None,
            }));
        }
        // Add some non-file events
        events.push(RiggsEvent::new_process(
            ProcessAction::Exec,
            ctx.clone(),
            None,
        ));
        events.push(make_mining_dns_event(30009, "www.google.com", "142.250.80.46"));

// Branch: Persistence mechanism / Suspicious child process tests
    fn test_case_insensitive_path_matching() {
        // Test that path matching is case-insensitive
        let event = make_file_event(32017, "installer", FileAction::Create, "/library/launchdaemons/com.evil.backdoor.plist");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);

// HEAD (main): Crypto mining / Ransomware tests
        assert!(matches!(patterns[0], BehaviorPattern::RapidFileEncryption));
    }

    #[test]
    fn test_rapid_encryption_no_other_signals() {
        // Ensure rapid file encryption detection is independent of
        // other signals (no network, no DNS, no process injection)
        let ctx = ProcessContext::new(
            30010, 0, "encryptor", "/tmp/encrypt", "",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..15)
            .map(|i| {
                RiggsEvent::File(FileEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx.clone(),
                    action: FileAction::Modify,
                    path: format!("/backup/file_{}.bak", i),
                    hash: None,
                    fd: None,
                })
            })
            .collect();

// Branch: Persistence mechanism / Suspicious child process tests
        assert!(matches!(patterns[0], BehaviorPattern::PersistenceMechanism));
    }

    #[test]
    fn test_multiple_persistence_mechanisms() {
        // Multiple persistence mechanisms in same storyline
        let events = vec![
            make_file_event(32018, "installer", FileAction::Create, "/Library/LaunchDaemons/com.evil.backdoor.plist"),
            make_file_event(32018, "installer", FileAction::Create, "/etc/cron.d/backdoor"),
        ];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[1].storyline_id());

        // First persistence mechanism triggers detection
        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::PersistenceMechanism));
    }

    #[test]
    fn test_persistence_mechanism_with_mixed_events() {
        // Persistence mechanism mixed with other event types
        let events = vec![
            make_file_event(32019, "installer", FileAction::Create, "/Library/LaunchDaemons/com.evil.backdoor.plist"),
            make_mining_dns_event(32019, "www.google.com", "142.250.80.46"),
            make_outbound_network_event(32019, "142.250.80.46", 443),
        ];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);

// HEAD (main): Crypto mining / Ransomware tests
        assert!(matches!(patterns[0], BehaviorPattern::RapidFileEncryption));

        // Verify it's ONLY RapidFileEncryption, not crypto mining or anything else
        assert!(!patterns.contains(&BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_rapid_file_encryption_large_scale() {
        // Simulate large-scale ransomware: 100 files in rapid succession
        let ctx = ProcessContext::new(
            30011, 0, "ransomware", "/tmp/ransomware", "./ransomware --encrypt",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..100)
            .map(|i| {
                RiggsEvent::File(FileEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx.clone(),
                    action: FileAction::Modify,
                    path: format!("/home/user/documents/important_file_{}.docx", i),
                    hash: None,
                    fd: None,
                })
            })
            .collect();

// Branch: Persistence mechanism / Suspicious child process tests
        assert!(matches!(patterns[0], BehaviorPattern::PersistenceMechanism));

        // Verify it's ONLY PersistenceMechanism
        assert!(!patterns.contains(&BehaviorPattern::CryptoMining));
        assert!(!patterns.contains(&BehaviorPattern::DataExfiltration));
    }

    #[test]
    fn test_persistence_mechanism_no_other_signals() {
        // Ensure persistence detection is independent of other signals
        let event = make_file_event(32020, "installer", FileAction::Create, "/Library/LaunchDaemons/com.evil.backdoor.plist");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);

// HEAD (main): Crypto mining / Ransomware tests
        assert!(matches!(patterns[0], BehaviorPattern::RapidFileEncryption));

// Branch: Persistence mechanism / Suspicious child process tests
        assert!(matches!(patterns[0], BehaviorPattern::PersistenceMechanism));

        assert!(!patterns.contains(&BehaviorPattern::ProcessInjection));
        assert!(!patterns.contains(&BehaviorPattern::PrivilegeEscalation));
    }

    #[test]
    fn test_normal_launchagent_not_flagged() {
        // Legitimate LaunchAgent in a different location should not trigger
        let event = make_file_event(32021, "app", FileAction::Create, "/Applications/MyApp.app/Contents/Resources/agent.plist");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_normal_cron_job_not_flagged() {
        // Normal cron job in user directory should not trigger
        let event = make_file_event(32022, "user", FileAction::Create, "/home/user/scripts/backup.sh");
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    // --- Suspicious Child Process Tests (T1059) ---

    fn make_process_event_with_parent(
        pid: u32,
        name: &str,
        path: &str,
        cmdline: &str,
        parent_name: &str,
        parent_path: &str,
    ) -> RiggsEvent {
        let child_ctx = ProcessContext::new(
            pid, 0, name, path, cmdline,
            "user",
            StorylineId::new(),
        );
        let parent_ctx = ProcessContext::new(
            pid - 1, 0, parent_name, parent_path, "",
            "user",
            StorylineId::new(),
        );
        RiggsEvent::new_process(
            ProcessAction::Exec,
            child_ctx,
            Some(parent_ctx),
        )
    }

    #[test]
    fn test_word_spawning_cmd_detected() {
        let event = make_process_event_with_parent(
            33001, "cmd.exe", "C:\\Windows\\System32\\cmd.exe", "cmd.exe",
            "winword", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::SuspiciousChildProcess));
    }

    #[test]
    fn test_excel_spawning_powershell_detected() {
        let event = make_process_event_with_parent(
            33002, "pwsh", "C:\\Program Files\\PowerShell\\7\\pwsh.exe", "pwsh",
            "excel", "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::SuspiciousChildProcess));
    }

    #[test]
    fn test_pdf_acrobat_spawning_bash_detected() {
        let event = make_process_event_with_parent(
            33003, "bash", "/bin/bash", "bash",
            "acrobat", "/Applications/Adobe Acrobat Acrobat DC/Adobe Acrobat.app/Contents/MacOS/Acrobat",
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::SuspiciousChildProcess));
    }

    #[test]
    fn test_powerpoint_spawning_python_detected() {
        let event = make_process_event_with_parent(
            33004, "python3", "/usr/bin/python3", "python3",
            "powerpoint", "/Applications/Microsoft PowerPoint.app/Contents/MacOS/Microsoft PowerPoint",
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::SuspiciousChildProcess));
    }

    #[test]
    fn test_outlook_spawning_sh_detected() {
        let event = make_process_event_with_parent(
            33005, "sh", "/bin/sh", "sh",
            "outlook", "/Applications/Microsoft Outlook.app/Contents/MacOS/Microsoft Outlook",
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::SuspiciousChildProcess));
    }

    #[test]
    fn test_pages_spawning_zsh_detected() {
        let event = make_process_event_with_parent(
            33006, "zsh", "/bin/zsh", "zsh",
            "pages", "/Applications/Pages.app/Contents/MacOS/Pages",
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::SuspiciousChildProcess));
    }

    #[test]
    fn test_numbers_spawning_ruby_detected() {
        let event = make_process_event_with_parent(
            33007, "ruby", "/usr/bin/ruby", "ruby",
            "numbers", "/Applications/Numbers.app/Contents/MacOS/Numbers",
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::SuspiciousChildProcess));
    }

    #[test]
    fn test_keynote_spawning_perl_detected() {
        let event = make_process_event_with_parent(
            33008, "perl", "/usr/bin/perl", "perl",
            "keynote", "/Applications/Keynote.app/Contents/MacOS/Keynote",
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::SuspiciousChildProcess));
    }

    #[test]
    fn test_chrome_spawning_cmd_not_flagged() {
        // Chrome spawning cmd.exe should not be flagged (not a suspicious parent)
        let event = make_process_event_with_parent(
            33009, "cmd.exe", "C:\\Windows\\System32\\cmd.exe", "cmd.exe",
            "chrome", "/usr/bin/chrome",
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_word_spawning_ls_not_flagged() {
        // Word spawning ls should not be flagged (not a shell binary)
        let event = make_process_event_with_parent(
            33010, "ls", "/bin/ls", "ls",
            "word", "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word",
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_word_spawning_word_not_flagged() {
        // Word spawning Word should not be flagged (not a shell binary)
        let event = make_process_event_with_parent(
            33011, "winword", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "winword",
            "word", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_no_parent_context_not_flagged() {
        // Process with no parent context should not be flagged
        let ctx = ProcessContext::new(
            33012, 0, "bash", "/bin/bash", "bash",
            "user",
            StorylineId::new(),
        );
        let event = RiggsEvent::new_process(
            ProcessAction::Exec,
            ctx,
            None, // No parent
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_non_exec_action_not_flagged() {
        // Non-Exec process actions should not be flagged
        let child_ctx = ProcessContext::new(
            33013, 0, "bash", "/bin/bash", "bash",
            "user",
            StorylineId::new(),
        );
        let parent_ctx = ProcessContext::new(
            33012, 0, "word", "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word", "",
            "user",
            StorylineId::new(),
        );
        let event = RiggsEvent::new_process(
            ProcessAction::Exit, // Not Exec
            child_ctx,
            Some(parent_ctx),
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_suspicious_child_process_with_mixed_events() {
        // Suspicious child process mixed with other event types
        let events = vec![
            make_process_event_with_parent(
                33014, "cmd.exe", "C:\\Windows\\System32\\cmd.exe", "cmd.exe",
                "word", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            ),
            make_mining_dns_event(33014, "www.google.com", "142.250.80.46"),
            make_outbound_network_event(33014, "142.250.80.46", 443),
        ];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::SuspiciousChildProcess));

        // Verify it's ONLY SuspiciousChildProcess
        assert!(!patterns.contains(&BehaviorPattern::CryptoMining));
        assert!(!patterns.contains(&BehaviorPattern::DataExfiltration));
    }

    #[test]
    fn test_suspicious_child_process_no_other_signals() {
        // Ensure suspicious child process detection is independent of other signals
        let event = make_process_event_with_parent(
            33015, "bash", "/bin/bash", "bash",
            "acrobat", "/Applications/Adobe Acrobat.app/Contents/MacOS/Acrobat",
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::SuspiciousChildProcess));

        assert!(!patterns.contains(&BehaviorPattern::PersistenceMechanism));
        assert!(!patterns.contains(&BehaviorPattern::PrivilegeEscalation));
    }

    #[test]
    fn test_libreoffice_spawning_bash_detected() {
        let event = make_process_event_with_parent(
            33016, "bash", "/bin/bash", "bash",
            "libreoffice", "/usr/lib/libreoffice/program/soffice.bin",
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::SuspiciousChildProcess));
    }

    #[test]
    fn test_preview_spawning_python_detected() {
        let event = make_process_event_with_parent(
            33017, "python", "/usr/bin/python", "python",
            "preview", "/Applications/Preview.app/Contents/MacOS/Preview",
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::SuspiciousChildProcess));
    }

    #[test]
    fn test_evince_spawning_pwsh_detected() {
        let event = make_process_event_with_parent(
            33018, "pwsh", "/usr/bin/pwsh", "pwsh",
            "evince", "/usr/bin/evince",
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::SuspiciousChildProcess));
    }

    #[test]
    fn test_child_path_contains_shell_binary() {
        // Shell binary in path should trigger detection
        let event = make_process_event_with_parent(
            33019, "my_script", "/tmp/bin/bash", "/tmp/bin/bash",
            "word", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::SuspiciousChildProcess));
    }

    #[test]
    fn test_child_name_contains_shell_binary() {
        // Shell binary in name should trigger detection
        let event = make_process_event_with_parent(
            33020, "bash_helper", "/usr/local/bin/bash_helper", "bash_helper",
            "excel", "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
        );
        let events = vec![event];

        let tracker = BehaviorTracker::new();
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::SuspiciousChildProcess));

    }
}

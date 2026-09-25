use std::collections::{HashMap, HashSet};

use chrono::Duration;
use riggs_types::events::{
    AuthAction, FileAction, KernelAction, NetworkDirection, ProcessAction, RiggsEvent, StorylineId,
};

use crate::patterns::BehaviorPattern;

/// Default cap on events retained per storyline. Detection windows only look at
/// recent events, so keeping the most recent N bounds memory and O(n^2) rescans.
const DEFAULT_MAX_EVENTS_PER_STORYLINE: usize = 512;
/// Default cap on tracked storylines. Short-lived processes each open a
/// storyline, so without this a busy host grows the map without bound.
const DEFAULT_MAX_STORYLINES: usize = 4096;

pub struct BehaviorTracker {
    storylines: HashMap<StorylineId, Vec<RiggsEvent>>,
    max_events_per_storyline: usize,
    max_storylines: usize,
    exfil_threshold: usize,
    rapid_file_threshold: usize,
    rapid_window_secs: i64,
    persistence_paths: Vec<String>,
}

impl BehaviorTracker {
    pub fn new() -> Self {
        let d = riggs_types::config::DetectionConfig::default();
        Self {
            storylines: HashMap::new(),
            max_events_per_storyline: DEFAULT_MAX_EVENTS_PER_STORYLINE,
            max_storylines: DEFAULT_MAX_STORYLINES,
            exfil_threshold: d.exfil_outbound_threshold,
            rapid_file_threshold: d.rapid_encryption_file_threshold,
            rapid_window_secs: d.rapid_encryption_window_secs,
            persistence_paths: d.persistence_paths,
        }
    }

    /// Override the memory caps (operator-configurable).
    pub fn with_limits(mut self, max_events_per_storyline: usize, max_storylines: usize) -> Self {
        self.max_events_per_storyline = max_events_per_storyline.max(1);
        self.max_storylines = max_storylines.max(1);
        self
    }

    /// Apply operator-configured detection thresholds and signatures.
    pub fn with_detection(mut self, cfg: &riggs_types::config::DetectionConfig) -> Self {
        self.exfil_threshold = cfg.exfil_outbound_threshold;
        self.rapid_file_threshold = cfg.rapid_encryption_file_threshold;
        self.rapid_window_secs = cfg.rapid_encryption_window_secs;
        self.persistence_paths = cfg.persistence_paths.clone();
        self
    }

    pub fn track(&mut self, event: RiggsEvent) {
        let storyline_id = extract_storyline_id(&event);

        // Bound the number of storylines: when a new one would exceed the cap,
        // evict the least-recently-active storyline first.
        if !self.storylines.contains_key(&storyline_id)
            && self.storylines.len() >= self.max_storylines
        {
            if let Some(oldest) = self.least_recently_active() {
                self.storylines.remove(&oldest);
            }
        }

        let events = self.storylines.entry(storyline_id).or_default();
        events.push(event);

        // Bound per-storyline history to the most recent events.
        if events.len() > self.max_events_per_storyline {
            let overflow = events.len() - self.max_events_per_storyline;
            events.drain(0..overflow);
        }
    }

    /// The storyline whose most recent event is oldest (idle eviction target).
    fn least_recently_active(&self) -> Option<StorylineId> {
        self.storylines
            .iter()
            .filter_map(|(id, events)| events.last().map(|e| (id.clone(), e.timestamp())))
            .min_by_key(|(_, ts)| *ts)
            .map(|(id, _)| id)
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
                RiggsEvent::File(fe) if fe.action == FileAction::Modify => {
                    Some((fe.timestamp, fe.path.as_str()))
                }
                _ => None,
            })
            .collect();

        if file_modify_timestamps.len() < self.rapid_file_threshold {
            return None;
        }

        let window = Duration::seconds(self.rapid_window_secs);
        // Sliding window: for each event, count unique file paths within the window
        for (i, (ts, _)) in file_modify_timestamps.iter().enumerate() {
            let mut unique_paths: HashSet<&str> = HashSet::new();
            for (other_ts, path) in &file_modify_timestamps[i..] {
                if *other_ts - *ts > window {
                    break;
                }
                unique_paths.insert(path);
            }
            if unique_paths.len() >= self.rapid_file_threshold {
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
                            && auth_events[i].2 == auth_events[j].2 // same user
                            && (auth_events[j].0 - auth_events[i].0) <= Duration::seconds(60)
                        {
                            return Some(BehaviorPattern::PrivilegeEscalation);
                        }
                    }
                }
            }
        }

        // Signal 3: Process cmdline invokes a privilege-escalation tool.
        // Match on the first token (basename) so an invocation at the very start
        // of the cmdline is caught, whether bare (`pkexec ...`) or absolute
        // (`/usr/bin/pkexec ...`), without matching unrelated substrings.
        const ESCALATION_COMMANDS: &[&str] = &["sudo", "su", "pkexec", "doas", "runuser"];

        for event in events {
            if let RiggsEvent::Process(pe) = event {
                if pe.action == ProcessAction::Exec {
                    let cmdline_lower = pe.process_context.cmdline.to_lowercase();
                    let first_token = cmdline_lower.split_whitespace().next().unwrap_or("");
                    let basename = first_token.rsplit('/').next().unwrap_or(first_token);
                    if ESCALATION_COMMANDS.contains(&basename) {
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
                    let is_root =
                        pe.process_context.user == "root" || pe.process_context.user == "0";
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
                if dns_query == net_dst || dns_query.trim_end_matches('.') == net_dst.as_str() {
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
        // Data exfiltration detection (MITRE T1041)
        // Uses multi-signal scoring to reduce false positives.
        // No single signal is definitive — we look for combinations.

        let mut score = 0;
        let mut signals = Vec::new();

        // === Signal 1: High volume outbound connections ===
        // Large number of EXTERNAL outbound connections in the storyline. Internal
        // traffic (backups, replication) is excluded so it doesn't read as exfil.
        // (threshold is operator-configurable via [detection].exfil_outbound_threshold)
        let outbound_count = events
            .iter()
            .filter(|e| {
                matches!(e, RiggsEvent::Network(ne)
                if ne.direction == NetworkDirection::Outbound
                    && !Self::is_internal_ip(&ne.dst_addr))
            })
            .count();

        if outbound_count >= self.exfil_threshold {
            score += 1;
            signals.push("high_outbound_volume".to_string());
        }

        // === Signal 2: External destination concentration ===
        // Many outbound connections to external (non-private) IPs
        let external_outbound_count = events
            .iter()
            .filter(|e| {
                matches!(e, RiggsEvent::Network(ne)
                    if ne.direction == NetworkDirection::Outbound
                        && !Self::is_internal_ip(&ne.dst_addr))
            })
            .count();

        const EXTERNAL_THRESHOLD: usize = 20;
        if external_outbound_count >= EXTERNAL_THRESHOLD {
            score += 1;
            signals.push("external_destination_concentration".to_string());
        }

        // === Signal 3: Connection to unusual/suspicious ports ===
        // Non-standard ports for outbound connections (not 80, 443, 53, 25)
        const STANDARD_PORTS: &[u16] = &[80, 443, 53, 25, 587, 993, 995, 5222];
        let unusual_port_connections: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                RiggsEvent::Network(ne)
                    if ne.direction == NetworkDirection::Outbound
                        && !Self::is_internal_ip(&ne.dst_addr)
                        && !STANDARD_PORTS.contains(&ne.dst_port) =>
                {
                    Some((ne.timestamp, &ne.dst_addr, ne.dst_port))
                }
                _ => None,
            })
            .collect();

        if unusual_port_connections.len() >= 5 {
            score += 1;
            signals.push("unusual_port_connections".to_string());
        }

        // === Signal 4: Data staging + exfiltration pattern ===
        // File operations followed by outbound network transfers
        let mut has_outbound_after_staging = false;

        // Find the most recent file operation (Create/Modify), then look for an
        // external outbound transfer at or after it.
        let max_file_timestamp = events
            .iter()
            .filter_map(|event| match event {
                RiggsEvent::File(fe)
                    if matches!(fe.action, FileAction::Create | FileAction::Modify) =>
                {
                    Some(fe.timestamp)
                }
                _ => None,
            })
            .max();

        if let Some(max_ts) = max_file_timestamp {
            for event in events {
                if let RiggsEvent::Network(ne) = event {
                    if ne.direction == NetworkDirection::Outbound
                        && ne.timestamp >= max_ts
                        && !Self::is_internal_ip(&ne.dst_addr)
                    {
                        has_outbound_after_staging = true;
                        break;
                    }
                }
            }
        }

        // Check if there were file operations at all
        let file_ops_count = events.iter().filter(|e| {
            matches!(e, RiggsEvent::File(fe) if matches!(fe.action, FileAction::Create | FileAction::Modify))
        }).count();

        if file_ops_count >= 3 && has_outbound_after_staging {
            score += 1;
            signals.push("staging_then_exfiltration".to_string());
        }

        // === Decision: multi-signal scoring ===
        // 1 signal alone: Suspicious (could be legitimate large transfer)
        // 2+ signals: Malicious (strong indicator of exfiltration)
        match score {
            0 => None,
            _ => Some(BehaviorPattern::DataExfiltration),
        }
    }

    fn check_persistence_mechanism(&self, events: &[RiggsEvent]) -> Option<BehaviorPattern> {
        // Persistence paths are operator-configurable via [detection].persistence_paths.
        for event in events {
            if let RiggsEvent::File(fe) = event {
                if matches!(fe.action, FileAction::Create | FileAction::Modify) {
                    let path_lower = fe.path.to_lowercase();
                    for persistence_path in &self.persistence_paths {
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
            "office",
            "word",
            "excel",
            "powerpoint",
            "outlook",
            "pdf",
            "acrobat",
            "preview",
            "evince",
            "libreoffice",
            "pages",
            "numbers",
            "keynote",
        ];
        const SHELL_BINARIES: &[&str] = &[
            "/bin/sh",
            "/bin/bash",
            "/bin/zsh",
            "/usr/bin/sh",
            "/usr/bin/bash",
            "/usr/bin/zsh",
            "/bin/dash",
            "python",
            "python3",
            "perl",
            "ruby",
            "powershell",
            "pwsh",
            "cmd.exe",
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
                    let is_shell_child = SHELL_BINARIES
                        .iter()
                        .any(|s| child_path_lower.contains(s) || child_name_lower.contains(s));

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
        // 443 is deliberately excluded: it is HTTPS and far too common to treat
        // as a mining signal on its own.
        const MINING_PORTS: &[u16] = &[
            3333, 4433, 4444, 5555, 6666, 7777, 8333, 8888, 9999, 14444, 14445, 45700, 55555,
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
                    if MINING_DOMAINS.iter().any(|domain| {
                        query_lower.contains(domain) || response_lower.contains(domain)
                    }) {
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
            "xmrig",
            "cpuminer",
            "minerd",
            "ethminer",
            "ethdcrminer",
            "ccminer",
            "bfgminer",
            "cgminer",
            "lolminers",
            "t-rex",
            "minergate",
            "cryptonight",
            "randomx",
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
                RiggsEvent::Process(pe) if pe.action == ProcessAction::Exec => Some(pe.timestamp),
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
        // Any distinctive mining signal (miner binary, mining-pool domain, or a
        // dedicated Stratum port) is enough; combinations only reinforce it.
        // 443 was already excluded from the port list above.
        match score {
            0 => None,
            _ => Some(BehaviorPattern::CryptoMining),
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
    use chrono::Utc;
    use riggs_types::events::{EventId, FileEvent, NetworkEvent, ProcessContext};

    fn make_ctx(pid: u32, name: &str) -> ProcessContext {
        ProcessContext::new(
            pid,
            0,
            name,
            format!("/usr/bin/{}", name),
            "",
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

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::ProcessInjection));
    }

    #[test]
    fn test_no_memory_exec_returns_none() {
        let ctx = make_ctx(1234, "bash");
        let process_event = RiggsEvent::new_process(ProcessAction::Exec, ctx.clone(), None);
        let events = vec![process_event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_memory_exec_mixed_with_other_events() {
        let ctx = make_ctx(5678, "python3");
        let normal_event = RiggsEvent::new_process(ProcessAction::Exec, ctx.clone(), None);
        let kernel_event =
            RiggsEvent::new_kernel(KernelAction::MemoryExec, ctx, "mmap+exec memory region");
        let events = vec![normal_event, kernel_event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
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

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        // ModuleLoad alone should not trigger process injection
        assert!(!patterns.contains(&BehaviorPattern::ProcessInjection));
    }

    // --- Rapid File Encryption Tests ---

    fn modify_distinct_files(count: usize) -> Vec<BehaviorPattern> {
        let ctx = make_ctx(4242, "locker");
        let mut tracker = BehaviorTracker::new();
        for i in 0..count {
            let path = format!("/home/user/doc{i}.txt");
            tracker.track(RiggsEvent::new_file(
                FileAction::Modify,
                ctx.clone(),
                path,
                None,
            ));
        }
        tracker.check_patterns(&ctx.storyline_id)
    }

    #[test]
    fn test_rapid_encryption_fires_at_threshold() {
        let threshold =
            riggs_types::config::DetectionConfig::default().rapid_encryption_file_threshold;
        assert!(modify_distinct_files(threshold).contains(&BehaviorPattern::RapidFileEncryption));
    }

    #[test]
    fn test_rapid_encryption_quiet_below_threshold() {
        let threshold =
            riggs_types::config::DetectionConfig::default().rapid_encryption_file_threshold;
        assert!(
            !modify_distinct_files(threshold - 1).contains(&BehaviorPattern::RapidFileEncryption)
        );
    }

    // --- Privilege Escalation Tests ---

    fn make_auth_event(action: AuthAction, pid: u32, user: &str, method: &str) -> RiggsEvent {
        let ctx = ProcessContext::new(
            pid,
            0,
            "auth_service",
            "/usr/sbin/authserv",
            "",
            user,
            StorylineId::new(),
        );
        RiggsEvent::new_auth(action, ctx, user, method)
    }

    #[test]
    fn test_auth_escalation_detected() {
        let auth_event = make_auth_event(AuthAction::Escalation, 1001, "user", "sudo");
        let events = vec![auth_event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::PrivilegeEscalation));
    }

    #[test]
    fn test_brute_force_success_detected() {
        // Failed then successful auth for the same user must share a storyline
        // to correlate, so both events are built from one context.
        let ctx = ProcessContext::new(
            2001,
            0,
            "auth_service",
            "/usr/sbin/authserv",
            "",
            "user",
            StorylineId::new(),
        );
        let failed = RiggsEvent::new_auth(AuthAction::Failed, ctx.clone(), "user", "password");
        let success = RiggsEvent::new_auth(AuthAction::Login, ctx.clone(), "user", "password");
        let events = vec![failed, success];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[1].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::PrivilegeEscalation));
    }

    #[test]
    fn test_brute_force_different_users_not_flagged() {
        let failed = make_auth_event(AuthAction::Failed, 3001, "user", "password");
        let success = make_auth_event(AuthAction::Login, 3001, "admin", "password");
        let events = vec![failed, success];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[1].storyline_id());

        // Different users — not a brute force pattern
        assert!(!patterns.contains(&BehaviorPattern::PrivilegeEscalation));
    }

    #[test]
    fn test_sudo_in_cmdline_detected() {
        let ctx = ProcessContext::new(
            4001,
            0,
            "bash",
            "/bin/bash",
            "sudo apt update",
            "user",
            StorylineId::new(),
        );
        let exec_event = RiggsEvent::new_process(ProcessAction::Exec, ctx, None);
        let events = vec![exec_event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::PrivilegeEscalation));
    }

    #[test]
    fn test_pkexec_in_cmdline_detected() {
        let ctx = ProcessContext::new(
            5001,
            0,
            "pkexec",
            "/usr/bin/pkexec",
            "pkexec /usr/bin/systemctl restart nginx",
            "user",
            StorylineId::new(),
        );
        let exec_event = RiggsEvent::new_process(ProcessAction::Exec, ctx, None);
        let events = vec![exec_event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::PrivilegeEscalation));
    }

    #[test]
    fn test_root_process_from_nonroot_parent_detected() {
        let parent_ctx = ProcessContext::new(
            6001,
            0,
            "firefox",
            "/usr/bin/firefox",
            "",
            "user",
            StorylineId::new(),
        );
        let child_ctx = ProcessContext::new(
            6002,
            6001,
            "suid_exploit",
            "/tmp/exploit",
            "",
            "root",
            StorylineId::new(),
        );
        let exec_event = RiggsEvent::new_process(ProcessAction::Exec, child_ctx, Some(parent_ctx));
        let events = vec![exec_event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::PrivilegeEscalation));
    }

    #[test]
    fn test_root_from_root_parent_not_flagged() {
        let parent_ctx = ProcessContext::new(
            7001,
            0,
            "sshd",
            "/usr/sbin/sshd",
            "",
            "root",
            StorylineId::new(),
        );
        let child_ctx = ProcessContext::new(
            7002,
            7001,
            "bash",
            "/bin/bash",
            "",
            "root",
            StorylineId::new(),
        );
        let exec_event = RiggsEvent::new_process(ProcessAction::Exec, child_ctx, Some(parent_ctx));
        let events = vec![exec_event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        // Normal: root spawning root (e.g., ssh session)
        assert!(!patterns.contains(&BehaviorPattern::PrivilegeEscalation));
    }

    #[test]
    fn test_no_privilege_escalation_in_normal_events() {
        let ctx = make_ctx(8001, "normal_app");
        let exec_event = RiggsEvent::new_process(ProcessAction::Exec, ctx, None);
        let events = vec![exec_event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
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
            pid,
            0,
            "ssh",
            "/usr/bin/ssh",
            "",
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
            pid,
            0,
            "curl",
            "/usr/bin/curl",
            "",
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

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
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

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
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

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
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

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::LateralMovement));
    }

    #[test]
    fn test_outbound_to_public_ip_not_flagged() {
        let event = make_network_event(NetworkDirection::Outbound, 9005, "8.8.8.8", 443);
        let events = vec![event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(!patterns.contains(&BehaviorPattern::LateralMovement));
    }

    #[test]
    fn test_inbound_to_internal_ip_not_flagged() {
        let event = make_network_event(NetworkDirection::Inbound, 9006, "192.168.1.50", 22);
        let events = vec![event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
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

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(!patterns.contains(&BehaviorPattern::LateralMovement));
    }

    #[test]
    fn test_dns_recon_to_connection_detected() {
        // DNS query for internal host, then network connection to that host
        let dns_event = make_dns_event(10001, "192.168.1.50", "192.168.1.50");
        let net_event = make_network_event(NetworkDirection::Outbound, 10001, "192.168.1.50", 22);
        let events = vec![dns_event, net_event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[1].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::LateralMovement));
    }

    #[test]
    fn test_auth_failed_with_internal_network_detected() {
        let auth_event = make_auth_event(AuthAction::Failed, 11001, "admin", "password");
        let net_event = make_network_event(NetworkDirection::Outbound, 11001, "10.0.0.100", 445);
        let events = vec![auth_event, net_event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[1].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::LateralMovement));
    }

    #[test]
    fn test_auth_login_with_internal_network_detected() {
        let auth_event = make_auth_event(AuthAction::Login, 12001, "admin", "ssh");
        let net_event = make_network_event(NetworkDirection::Outbound, 12001, "172.16.0.5", 3389);
        let events = vec![auth_event, net_event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[1].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::LateralMovement));
    }

    #[test]
    fn test_auth_with_different_pid_not_flagged() {
        let auth_event = make_auth_event(AuthAction::Failed, 13001, "admin", "password");
        let net_event = make_network_event(
            NetworkDirection::Outbound,
            13002,        // Different PID
            "10.0.0.100", // internal, but on a non-lateral port
            8080,
        );
        let events = vec![auth_event, net_event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[1].storyline_id());

        // Different PIDs (and thus storylines) — the auth and the connection do
        // not correlate, and the connection alone is on a benign port.
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
        let exec_event = RiggsEvent::new_process(ProcessAction::Exec, ctx, None);
        let events = vec![exec_event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    // --- Crypto Mining Tests ---

    fn make_mining_network_event(pid: u32, dst_addr: &str, dst_port: u16) -> RiggsEvent {
        let ctx = ProcessContext::new(
            pid,
            0,
            "miner",
            "/tmp/xmrig",
            "",
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
            pid,
            0,
            "miner",
            "/tmp/xmrig",
            "",
            "user",
            StorylineId::new(),
        );
        RiggsEvent::new_dns(ctx, query, response, "A")
    }

    fn make_mining_process_event(pid: u32, name: &str, path: &str, cmdline: &str) -> RiggsEvent {
        let ctx = ProcessContext::new(pid, 0, name, path, cmdline, "user", StorylineId::new());
        RiggsEvent::new_process(ProcessAction::Exec, ctx, None)
    }

    #[test]
    fn test_mining_port_connection_detected() {
        let event = make_mining_network_event(20001, "pool.example.com", 3333);
        let events = vec![event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
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

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_mining_port_14444_detected() {
        let event = make_mining_network_event(20003, "ethermine.org", 14444);
        let events = vec![event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_mining_port_45700_detected() {
        let event = make_mining_network_event(20004, "nicehash.com", 45700);
        let events = vec![event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_port_443_alone_not_flagged() {
        // Port 443 is common for HTTPS — too noisy alone
        let event = make_mining_network_event(20005, "example.com", 443);
        let events = vec![event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        // Port 443 alone is intentionally not flagged (too many legitimate uses)
        assert!(patterns.is_empty());
    }

    #[test]
    fn test_outbound_not_flagged_on_non_mining_port() {
        let event = make_mining_network_event(20006, "example.com", 8080);
        let events = vec![event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_inbound_to_mining_port_not_flagged() {
        // This helper uses Outbound direction, so we build the inbound flow manually.
        let ctx = ProcessContext::new(
            20007,
            0,
            "server",
            "/usr/bin/server",
            "",
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

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        // Inbound connections are not mining
        assert!(patterns.is_empty());
    }

    #[test]
    fn test_mining_domain_dns_detected() {
        let event = make_mining_dns_event(21001, "pool.ethermine.org", "146.190.28.145");
        let events = vec![event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_mining_domain_nicehash_detected() {
        let event = make_mining_dns_event(21002, "www.nicehash.com", "185.177.150.207");
        let events = vec![event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_mining_domain_in_response_detected() {
        let event = make_mining_dns_event(21003, "random-lookup.com", "f2pool.com");
        let events = vec![event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        // Domain in response also triggers detection
        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_normal_dns_not_flagged() {
        let event = make_mining_dns_event(21004, "www.google.com", "142.250.80.46");
        let events = vec![event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_mining_binary_name_detected() {
        let event =
            make_mining_process_event(22001, "xmrig", "/tmp/xmrig", "./xmrig -o pool.example.com");
        let events = vec![event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_cpuminer_binary_detected() {
        let event = make_mining_process_event(
            22002,
            "cpuminer",
            "/usr/local/bin/cpuminer",
            "./cpuminer -a sha256d",
        );
        let events = vec![event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_ethminer_binary_detected() {
        let event =
            make_mining_process_event(22003, "ethminer", "/usr/bin/ethminer", "ethminer -G");
        let events = vec![event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_mining_name_in_cmdline_detected() {
        // Miner name only in the cmdline (not the process name/path).
        let event =
            make_mining_process_event(22004, "bash", "/bin/bash", "./xmrig -o pool.example.com");
        let events = vec![event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_normal_process_not_flagged() {
        let event = make_mining_process_event(22005, "firefox", "/usr/bin/firefox", "firefox");
        let events = vec![event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_mining_port_plus_domain_detected() {
        // Two signals: mining port + mining domain = strong indicator
        let net_event = make_mining_network_event(23001, "pool.ethermine.org", 3333);
        let dns_event = make_mining_dns_event(23001, "pool.ethermine.org", "146.190.28.145");
        let events = vec![net_event, dns_event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
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

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
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

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[1].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::CryptoMining));
    }

    #[test]
    fn test_no_crypto_mining_in_normal_events() {
        let ctx = make_ctx(24001, "web_browser");
        let exec_event = RiggsEvent::new_process(ProcessAction::Exec, ctx, None);
        let events = vec![exec_event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_all_events_normal_no_mining() {
        let ctx = make_ctx(24002, "chrome");
        let exec_event = RiggsEvent::new_process(ProcessAction::Exec, ctx.clone(), None);
        let dns_event = make_mining_dns_event(24002, "www.google.com", "142.250.80.46");
        let net_event = make_mining_network_event(24002, "142.250.80.46", 443);
        let events = vec![exec_event, dns_event, net_event];

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[2].storyline_id());

        // Normal browsing — no mining signals
        assert!(patterns.is_empty());
    }

    // --- Data Exfiltration Tests (T1041) ---

    #[test]
    fn test_high_outbound_volume_detected() {
        // 50 outbound connections to external IPs should trigger detection
        let ctx = ProcessContext::new(
            31001,
            0,
            "exfiltrator",
            "/tmp/exfil",
            "./exfil",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..50)
            .map(|i| {
                RiggsEvent::Network(NetworkEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx.clone(),
                    direction: NetworkDirection::Outbound,
                    src_addr: "192.168.1.100".to_string(),
                    dst_addr: format!("{}.{}.{}.{}", 10 + (i % 200), i / 256, i % 256, 1),
                    src_port: 52000,
                    dst_port: 443,
                    protocol: "tcp".to_string(),
                })
            })
            .collect();

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::DataExfiltration));
    }

    #[test]
    fn test_below_outbound_threshold_not_flagged() {
        // 19 external connections — below both the volume (50) and the external
        // concentration (20) thresholds, so nothing should fire.
        let ctx = ProcessContext::new(
            31002,
            0,
            "browser",
            "/usr/bin/chrome",
            "",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..19)
            .map(|i| {
                RiggsEvent::Network(NetworkEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx.clone(),
                    direction: NetworkDirection::Outbound,
                    src_addr: "192.168.1.100".to_string(),
                    dst_addr: format!("203.0.{}.{}", i / 256, i % 256),
                    src_port: 52000,
                    dst_port: 443,
                    protocol: "tcp".to_string(),
                })
            })
            .collect();

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_external_destination_concentration_detected() {
        // 20+ outbound connections to external IPs triggers this signal
        let ctx = ProcessContext::new(
            31003,
            0,
            "scanner",
            "/usr/bin/nmap",
            "",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..20)
            .map(|i| {
                RiggsEvent::Network(NetworkEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx.clone(),
                    direction: NetworkDirection::Outbound,
                    src_addr: "192.168.1.100".to_string(),
                    dst_addr: format!("203.0.{}.{}", i / 256, i % 256),
                    src_port: 52000,
                    dst_port: 80,
                    protocol: "tcp".to_string(),
                })
            })
            .collect();

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::DataExfiltration));
    }

    #[test]
    fn test_internal_connections_not_flagged() {
        // Outbound connections to internal IPs should not trigger
        let ctx = ProcessContext::new(
            31004,
            0,
            "sync",
            "/usr/bin/rsync",
            "",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..50)
            .map(|_i| {
                RiggsEvent::Network(NetworkEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx.clone(),
                    direction: NetworkDirection::Outbound,
                    src_addr: "192.168.1.100".to_string(),
                    dst_addr: "192.168.1.50".to_string(),
                    src_port: 52000,
                    dst_port: 873,
                    protocol: "tcp".to_string(),
                })
            })
            .collect();

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        // Internal connections — not exfiltration
        assert!(patterns.is_empty());
    }

    #[test]
    fn test_unusual_port_connections_detected() {
        // 5+ connections to unusual ports on external IPs
        let ctx = ProcessContext::new(
            31005,
            0,
            "exfiltrator",
            "/tmp/exfil",
            "./exfil",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..5)
            .map(|i| {
                RiggsEvent::Network(NetworkEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx.clone(),
                    direction: NetworkDirection::Outbound,
                    src_addr: "192.168.1.100".to_string(),
                    dst_addr: format!("203.0.0.{}", i),
                    src_port: 52000,
                    dst_port: 41000 + i, // Unusual, non-mining ports
                    protocol: "tcp".to_string(),
                })
            })
            .collect();

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::DataExfiltration));
    }

    #[test]
    fn test_standard_ports_not_flagged() {
        // Connections to standard ports (80, 443, 53, 25) should not trigger
        let ctx = ProcessContext::new(
            31006,
            0,
            "browser",
            "/usr/bin/chrome",
            "",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..10)
            .map(|i| {
                RiggsEvent::Network(NetworkEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx.clone(),
                    direction: NetworkDirection::Outbound,
                    src_addr: "192.168.1.100".to_string(),
                    dst_addr: format!("{}.{}.{}.{}", 10 + i, 0, 0, 1),
                    src_port: 52000,
                    dst_port: 443, // Standard HTTPS port
                    protocol: "tcp".to_string(),
                })
            })
            .collect();

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_data_staging_then_exfiltration_detected() {
        // File operations followed by outbound network transfers
        let ctx = ProcessContext::new(
            31007,
            0,
            "exfiltrator",
            "/tmp/exfil",
            "./exfil",
            "user",
            StorylineId::new(),
        );
        let mut events: Vec<RiggsEvent> = Vec::new();

        // File staging operations
        for i in 0..5 {
            events.push(RiggsEvent::File(FileEvent {
                event_id: EventId::new(),
                timestamp: Utc::now(),
                process_context: ctx.clone(),
                action: FileAction::Create,
                path: format!("/tmp/staged_data_{}.tar", i),
                hash: None,
                fd: None,
            }));
        }

        // Outbound network transfers after staging
        for i in 0..5 {
            events.push(RiggsEvent::Network(NetworkEvent {
                event_id: EventId::new(),
                timestamp: Utc::now(),
                process_context: ctx.clone(),
                direction: NetworkDirection::Outbound,
                src_addr: "192.168.1.100".to_string(),
                dst_addr: format!("{}.{}.{}.{}", 10 + i, 0, 0, 1),
                src_port: 52000,
                dst_port: 443,
                protocol: "tcp".to_string(),
            }));
        }

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[events.len() - 1].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::DataExfiltration));
    }

    #[test]
    fn test_no_staging_pattern_without_file_ops() {
        // Outbound connections without prior file operations
        let ctx = ProcessContext::new(
            31008,
            0,
            "browser",
            "/usr/bin/chrome",
            "",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..5)
            .map(|i| {
                RiggsEvent::Network(NetworkEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx.clone(),
                    direction: NetworkDirection::Outbound,
                    src_addr: "192.168.1.100".to_string(),
                    dst_addr: format!("{}.{}.{}.{}", 10 + i, 0, 0, 1),
                    src_port: 52000,
                    dst_port: 443,
                    protocol: "tcp".to_string(),
                })
            })
            .collect();

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        // No file staging — should not trigger staging signal
        assert!(patterns.is_empty());
    }

    #[test]
    fn test_normal_outbound_traffic_not_flagged() {
        // Normal web browsing traffic
        let ctx = ProcessContext::new(
            31009,
            0,
            "chrome",
            "/usr/bin/chrome",
            "",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..10)
            .map(|_i| {
                RiggsEvent::Network(NetworkEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx.clone(),
                    direction: NetworkDirection::Outbound,
                    src_addr: "192.168.1.100".to_string(),
                    dst_addr: "142.250.80.46".to_string(), // Google
                    src_port: 52000,
                    dst_port: 443,
                    protocol: "tcp".to_string(),
                })
            })
            .collect();

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_data_exfiltration_with_mixed_events() {
        // Exfiltration pattern mixed with other event types
        let ctx = ProcessContext::new(
            31010,
            0,
            "exfiltrator",
            "/tmp/exfil",
            "./exfil",
            "user",
            StorylineId::new(),
        );
        let mut events: Vec<RiggsEvent> = Vec::new();

        // File staging
        for i in 0..5 {
            events.push(RiggsEvent::File(FileEvent {
                event_id: EventId::new(),
                timestamp: Utc::now(),
                process_context: ctx.clone(),
                action: FileAction::Create,
                path: format!("/tmp/staged_{}.tar", i),
                hash: None,
                fd: None,
            }));
        }

        // Outbound transfers
        for i in 0..5 {
            events.push(RiggsEvent::Network(NetworkEvent {
                event_id: EventId::new(),
                timestamp: Utc::now(),
                process_context: ctx.clone(),
                direction: NetworkDirection::Outbound,
                src_addr: "192.168.1.100".to_string(),
                dst_addr: format!("{}.{}.{}.{}", 10 + i, 0, 0, 1),
                src_port: 52000,
                dst_port: 443,
                protocol: "tcp".to_string(),
            }));
        }

        // Add a benign process event on the same storyline. (A DNS event would
        // carry its own storyline via the helper, so it is intentionally omitted.)
        events.push(RiggsEvent::new_process(
            ProcessAction::Exec,
            ctx.clone(),
            None,
        ));

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        // Inspect the exfiltration storyline (the shared ctx), not a later event
        // that may belong to a different storyline.
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::DataExfiltration));
    }

    #[test]
    fn test_data_exfiltration_boundary_20_external() {
        // Exactly 20 external connections — at threshold
        let ctx = ProcessContext::new(
            31011,
            0,
            "scanner",
            "/usr/bin/nmap",
            "",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..20)
            .map(|i| {
                RiggsEvent::Network(NetworkEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx.clone(),
                    direction: NetworkDirection::Outbound,
                    src_addr: "192.168.1.100".to_string(),
                    dst_addr: format!("203.0.{}.{}", i / 256, i % 256),
                    src_port: 52000,
                    dst_port: 80,
                    protocol: "tcp".to_string(),
                })
            })
            .collect();

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::DataExfiltration));
    }

    #[test]
    fn test_data_exfiltration_below_external_threshold() {
        // 19 external connections — below threshold
        let ctx = ProcessContext::new(
            31012,
            0,
            "browser",
            "/usr/bin/chrome",
            "",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..19)
            .map(|i| {
                RiggsEvent::Network(NetworkEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx.clone(),
                    direction: NetworkDirection::Outbound,
                    src_addr: "192.168.1.100".to_string(),
                    dst_addr: format!("{}.{}.{}.{}", 10 + (i % 200), i / 256, i % 256, 1),
                    src_port: 52000,
                    dst_port: 80,
                    protocol: "tcp".to_string(),
                })
            })
            .collect();

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_data_exfiltration_unusual_port_boundary_4() {
        // 4 unusual port connections — below threshold
        let ctx = ProcessContext::new(
            31013,
            0,
            "browser",
            "/usr/bin/chrome",
            "",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..4)
            .map(|i| {
                RiggsEvent::Network(NetworkEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx.clone(),
                    direction: NetworkDirection::Outbound,
                    src_addr: "192.168.1.100".to_string(),
                    dst_addr: format!("203.0.0.{}", i),
                    src_port: 52000,
                    dst_port: 41000 + i, // Unusual, non-mining ports
                    protocol: "tcp".to_string(),
                })
            })
            .collect();

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_data_exfiltration_unusual_port_boundary_5() {
        // 5 unusual port connections — at threshold
        let ctx = ProcessContext::new(
            31014,
            0,
            "exfiltrator",
            "/tmp/exfil",
            "./exfil",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..5)
            .map(|i| {
                RiggsEvent::Network(NetworkEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx.clone(),
                    direction: NetworkDirection::Outbound,
                    src_addr: "192.168.1.100".to_string(),
                    dst_addr: format!("203.0.0.{}", i),
                    src_port: 52000,
                    dst_port: 41000 + i, // Unusual, non-mining ports
                    protocol: "tcp".to_string(),
                })
            })
            .collect();

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::DataExfiltration));
    }

    #[test]
    fn test_data_exfiltration_no_other_signals() {
        // Ensure data exfiltration detection is independent of
        // other signals (no mining, no injection, no privilege escalation)
        let ctx = ProcessContext::new(
            31015,
            0,
            "exfiltrator",
            "/tmp/exfil",
            "./exfil",
            "user",
            StorylineId::new(),
        );
        let events: Vec<_> = (0..50)
            .map(|i| {
                RiggsEvent::Network(NetworkEvent {
                    event_id: EventId::new(),
                    timestamp: Utc::now(),
                    process_context: ctx.clone(),
                    direction: NetworkDirection::Outbound,
                    src_addr: "192.168.1.100".to_string(),
                    dst_addr: format!("{}.{}.{}.{}", 10 + (i % 200), i / 256, i % 256, 1),
                    src_port: 52000,
                    dst_port: 443,
                    protocol: "tcp".to_string(),
                })
            })
            .collect();

        let mut tracker = BehaviorTracker::new();
        for e in &events {
            tracker.track(e.clone());
        }
        let patterns = tracker.check_patterns(events[0].storyline_id());

        assert_eq!(patterns.len(), 1);
        assert!(matches!(patterns[0], BehaviorPattern::DataExfiltration));

        // Verify it's ONLY DataExfiltration, not crypto mining or anything else
        assert!(!patterns.contains(&BehaviorPattern::CryptoMining));
    }

    // --- Resource-cap tests (hardening) ---

    fn cap_event_for(storyline: &StorylineId) -> RiggsEvent {
        let ctx = ProcessContext::new(1, 0, "t", "/t", "t", "root", storyline.clone());
        RiggsEvent::new_process(ProcessAction::Exec, ctx, None)
    }

    #[test]
    fn caps_events_per_storyline() {
        let mut tracker = BehaviorTracker::new();
        let sid = StorylineId::new();
        for _ in 0..(DEFAULT_MAX_EVENTS_PER_STORYLINE + 50) {
            tracker.track(cap_event_for(&sid));
        }
        assert_eq!(
            tracker.storyline_event_count(&sid),
            DEFAULT_MAX_EVENTS_PER_STORYLINE
        );
    }

    #[test]
    fn caps_total_storylines() {
        let mut tracker = BehaviorTracker::new();
        for _ in 0..(DEFAULT_MAX_STORYLINES + 20) {
            tracker.track(cap_event_for(&StorylineId::new()));
        }
        assert!(tracker.storylines.len() <= DEFAULT_MAX_STORYLINES);
    }
}

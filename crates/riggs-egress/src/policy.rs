use std::net::IpAddr;

use ipnetwork::IpNetwork;
use riggs_types::config::{EgressConfig, EgressProcessRule};

/// Enforcement mode for the egress allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressMode {
    /// Feature off: everything is allowed, no evaluation.
    Off,
    /// Evaluate and record would-block decisions, but never drop a flow.
    Monitor,
    /// Drop flows that are not allowed.
    Enforce,
}

impl EgressMode {
    fn parse(s: &str, enabled: bool) -> Self {
        if !enabled {
            return EgressMode::Off;
        }
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => EgressMode::Off,
            "enforce" => EgressMode::Enforce,
            _ => EgressMode::Monitor,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            EgressMode::Off => "off",
            EgressMode::Monitor => "monitor",
            EgressMode::Enforce => "enforce",
        }
    }
}

/// The result of evaluating a flow against the egress policy.
#[derive(Debug, Clone)]
pub struct EgressDecision {
    /// Whether the flow should be permitted (accounts for the mode).
    pub allow: bool,
    /// Whether the policy would block this flow (true even in monitor mode).
    pub would_block: bool,
    pub reason: String,
    pub mode: EgressMode,
}

struct ProcessRule {
    process: String, // lowercased
    domains: Vec<String>,
    cidrs: Vec<IpNetwork>,
}

/// Snapshot of the global allowlist for an out-of-band enforcer. See
/// [`EgressPolicy::snapshot`].
#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    pub mode: EgressMode,
    pub allow_cidrs: Vec<IpNetwork>,
    pub allow_ports: Vec<u16>,
    pub allow_domains: Vec<String>,
    pub baseline_dns: bool,
    pub baseline_dhcp_ntp: bool,
    pub baseline_loopback: bool,
}

pub struct EgressPolicy {
    mode: EgressMode,
    allow_domains: Vec<String>,
    allow_cidrs: Vec<IpNetwork>,
    allow_ports: Vec<u16>,
    baseline_dns: bool,
    baseline_dhcp_ntp: bool,
    baseline_loopback: bool,
    process_rules: Vec<ProcessRule>,
}

impl EgressPolicy {
    pub fn from_config(config: &EgressConfig) -> Self {
        Self {
            mode: EgressMode::parse(&config.mode, config.enabled),
            allow_domains: config
                .allow_domains
                .iter()
                .map(|d| d.to_ascii_lowercase())
                .collect(),
            allow_cidrs: parse_cidrs(&config.allow_cidrs),
            allow_ports: config.allow_ports.clone(),
            baseline_dns: config.baseline.dns,
            baseline_dhcp_ntp: config.baseline.dhcp_ntp,
            baseline_loopback: config.baseline.loopback,
            process_rules: config.process_rules.iter().map(compile_rule).collect(),
        }
    }

    pub fn mode(&self) -> EgressMode {
        self.mode
    }

    pub fn domain_count(&self) -> usize {
        self.allow_domains.len()
    }

    pub fn process_rule_count(&self) -> usize {
        self.process_rules.len()
    }

    /// Read-only view of the allowlist fields an out-of-band enforcer (the Linux
    /// nftables backend) needs to materialize a ruleset. `allow_domains` are
    /// included so the caller knows what to resolve; they must be turned into
    /// IPs before rendering (nftables matches addresses, not SNI).
    pub fn snapshot(&self) -> PolicySnapshot {
        PolicySnapshot {
            mode: self.mode,
            allow_cidrs: self.allow_cidrs.clone(),
            allow_ports: self.allow_ports.clone(),
            allow_domains: self.allow_domains.clone(),
            baseline_dns: self.baseline_dns,
            baseline_dhcp_ntp: self.baseline_dhcp_ntp,
            baseline_loopback: self.baseline_loopback,
        }
    }

    /// Evaluate a flow. `process` is the originating process name (if known).
    pub fn evaluate(
        &self,
        process: Option<&str>,
        hostname: Option<&str>,
        ip: Option<IpAddr>,
        port: u16,
    ) -> EgressDecision {
        if self.mode == EgressMode::Off {
            return EgressDecision {
                allow: true,
                would_block: false,
                reason: "egress control off".into(),
                mode: self.mode,
            };
        }

        let (policy_allow, reason) = self.decide(process, hostname, ip, port);
        // Monitor never drops; enforce honors the decision.
        let allow = self.mode != EgressMode::Enforce || policy_allow;

        EgressDecision {
            allow,
            would_block: !policy_allow,
            reason,
            mode: self.mode,
        }
    }

    fn decide(
        &self,
        process: Option<&str>,
        hostname: Option<&str>,
        ip: Option<IpAddr>,
        port: u16,
    ) -> (bool, String) {
        // Baseline: keep the host functional regardless of the allowlist.
        if self.baseline_loopback && ip.map(|ip| ip.is_loopback()).unwrap_or(false) {
            return (true, "baseline: loopback".into());
        }
        if self.baseline_dns && port == 53 {
            return (true, "baseline: dns".into());
        }
        if self.baseline_dhcp_ntp && matches!(port, 67 | 68 | 123) {
            return (true, "baseline: dhcp/ntp".into());
        }

        let dest = describe_dest(hostname, ip, port);

        // Process-scoped rule: a matching process is restricted to its own list.
        if let Some(proc) = process {
            let proc_lower = proc.to_ascii_lowercase();
            if let Some(rule) = self
                .process_rules
                .iter()
                .find(|r| proc_lower.contains(&r.process))
            {
                if dest_matches(&rule.domains, &rule.cidrs, hostname, ip) {
                    return (true, format!("process rule '{}' allows {dest}", rule.process));
                }
                return (
                    false,
                    format!("process '{proc}' restricted; {dest} not in its allowlist"),
                );
            }
        }

        // Global allowlist.
        if !self.allow_ports.is_empty() && !self.allow_ports.contains(&port) {
            return (false, format!("port {port} not in allow_ports"));
        }
        if dest_matches(&self.allow_domains, &self.allow_cidrs, hostname, ip) {
            return (true, format!("allowlisted: {dest}"));
        }

        (false, format!("{dest} not in egress allowlist"))
    }
}

fn compile_rule(rule: &EgressProcessRule) -> ProcessRule {
    ProcessRule {
        process: rule.process.to_ascii_lowercase(),
        domains: rule
            .allow_domains
            .iter()
            .map(|d| d.to_ascii_lowercase())
            .collect(),
        cidrs: parse_cidrs(&rule.allow_cidrs),
    }
}

fn parse_cidrs(raw: &[String]) -> Vec<IpNetwork> {
    raw.iter()
        .filter_map(|c| match c.parse::<IpNetwork>() {
            Ok(net) => Some(net),
            Err(e) => {
                tracing::warn!(cidr = %c, error = %e, "ignoring invalid egress CIDR");
                None
            }
        })
        .collect()
}

fn dest_matches(
    domains: &[String],
    cidrs: &[IpNetwork],
    hostname: Option<&str>,
    ip: Option<IpAddr>,
) -> bool {
    if let Some(host) = hostname {
        let host = host.to_ascii_lowercase();
        if domains.iter().any(|p| domain_matches(p, &host)) {
            return true;
        }
    }
    if let Some(ip) = ip {
        if cidrs.iter().any(|net| net.contains(ip)) {
            return true;
        }
    }
    false
}

/// Exact or `*.`-wildcard domain match (both sides already lowercased).
fn domain_matches(pattern: &str, host: &str) -> bool {
    if let Some(bare) = pattern.strip_prefix("*.") {
        host == bare || host.ends_with(&format!(".{bare}"))
    } else {
        host == pattern
    }
}

fn describe_dest(hostname: Option<&str>, ip: Option<IpAddr>, port: u16) -> String {
    match (hostname, ip) {
        (Some(h), _) => format!("{h}:{port}"),
        (None, Some(ip)) => format!("{ip}:{port}"),
        (None, None) => format!("<unknown>:{port}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> EgressConfig {
        EgressConfig {
            enabled: true,
            mode: "enforce".into(),
            allow_domains: vec!["github.com".into(), "*.githubusercontent.com".into()],
            allow_cidrs: vec!["10.0.0.0/8".into()],
            allow_ports: vec![],
            baseline: Default::default(),
            process_rules: vec![EgressProcessRule {
                process: "npm".into(),
                allow_domains: vec!["registry.npmjs.org".into(), "*.npmjs.org".into()],
                allow_cidrs: vec![],
            }],
        }
    }

    fn policy() -> EgressPolicy {
        EgressPolicy::from_config(&cfg())
    }

    #[test]
    fn off_allows_everything() {
        let mut c = cfg();
        c.enabled = false;
        let p = EgressPolicy::from_config(&c);
        let d = p.evaluate(Some("npm"), Some("evil.example.com"), None, 443);
        assert!(d.allow);
        assert!(!d.would_block);
    }

    #[test]
    fn enforce_denies_unlisted_and_allows_listed() {
        let p = policy();
        assert!(!p.evaluate(None, Some("evil.example.com"), None, 443).allow);
        assert!(p.evaluate(None, Some("github.com"), None, 443).allow);
        assert!(p.evaluate(None, Some("raw.githubusercontent.com"), None, 443).allow);
    }

    #[test]
    fn monitor_records_but_never_blocks() {
        let mut c = cfg();
        c.mode = "monitor".into();
        let p = EgressPolicy::from_config(&c);
        let d = p.evaluate(None, Some("evil.example.com"), None, 443);
        assert!(d.allow, "monitor must not drop");
        assert!(d.would_block, "but records the would-block");
    }

    #[test]
    fn process_rule_locks_npm_to_registry() {
        let p = policy();
        // npm may reach the registry...
        assert!(p.evaluate(Some("npm"), Some("registry.npmjs.org"), None, 443).allow);
        // ...but a poisoned install script's beacon is denied, even though the
        // domain would be fine for other processes' global policy.
        let d = p.evaluate(Some("npm"), Some("github.com"), None, 443);
        assert!(!d.allow);
        assert!(d.reason.contains("restricted"));
    }

    #[test]
    fn process_without_rule_uses_global_allowlist() {
        let p = policy();
        // A browser (no process rule) may reach the global allowlist.
        assert!(p.evaluate(Some("Google Chrome"), Some("github.com"), None, 443).allow);
        assert!(!p.evaluate(Some("Google Chrome"), Some("evil.example.com"), None, 443).allow);
    }

    #[test]
    fn baseline_allows_dns_and_loopback() {
        let p = policy();
        assert!(p.evaluate(Some("anything"), Some("evil.example.com"), None, 53).allow);
        assert!(p
            .evaluate(None, None, Some("127.0.0.1".parse().unwrap()), 8080)
            .allow);
    }

    #[test]
    fn cidr_allowlist_matches_ip_literals() {
        let p = policy();
        assert!(p.evaluate(None, None, Some("10.1.2.3".parse().unwrap()), 443).allow);
        assert!(!p.evaluate(None, None, Some("8.8.8.8".parse().unwrap()), 443).allow);
    }

    #[test]
    fn port_narrowing_denies_other_ports() {
        let mut c = cfg();
        c.allow_ports = vec![443];
        let p = EgressPolicy::from_config(&c);
        assert!(p.evaluate(None, Some("github.com"), None, 443).allow);
        assert!(!p.evaluate(None, Some("github.com"), None, 8443).allow);
    }
}

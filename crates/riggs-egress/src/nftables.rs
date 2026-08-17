//! Translate an egress [`PolicySnapshot`] into an `nft` ruleset that implements
//! default-deny egress on Linux.
//!
//! This module only RENDERS the ruleset — it is pure and unit-tested. The
//! runtime pieces of the Linux enforcer are deliberately out of scope here and
//! require a Linux host with `CAP_NET_ADMIN`:
//!
//!   1. resolving `allow_domains` to IPs and keeping them fresh (DNS snoop /
//!      periodic resolve) — feed the results in as `resolved`,
//!   2. applying the rendered script via `nft -f -`,
//!   3. per-process attribution (eBPF / cgroup) for the process-scoped rules,
//!      which nftables alone cannot express.
//!
//! See `docs/STANDALONE.md` for the Linux enforcement milestone.

use std::fmt::Write;
use std::net::IpAddr;

use ipnetwork::IpNetwork;

use crate::policy::{EgressMode, PolicySnapshot};

/// nftables table name Riggs owns. Applying a fresh ruleset replaces it;
/// teardown is `nft delete table inet <TABLE>`.
pub const TABLE: &str = "riggs_egress";

/// Render an `nft -f` script for the snapshot. `resolved` are the addresses the
/// `allow_domains` currently resolve to (supplied by the resolver/DNS-snoop).
///
/// Returns `None` when the mode is not [`EgressMode::Enforce`] — in `Off` and
/// `Monitor` there is nothing to install, and the caller should tear the table
/// down instead (fail open).
pub fn render_ruleset(snap: &PolicySnapshot, resolved: &[IpAddr]) -> Option<String> {
    if snap.mode != EgressMode::Enforce {
        return None;
    }

    // Partition allow entries (CIDRs + resolved host IPs) by address family.
    let mut v4: Vec<String> = Vec::new();
    let mut v6: Vec<String> = Vec::new();
    for net in &snap.allow_cidrs {
        match net {
            IpNetwork::V4(_) => v4.push(net.to_string()),
            IpNetwork::V6(_) => v6.push(net.to_string()),
        }
    }
    for ip in resolved {
        match ip {
            IpAddr::V4(a) => v4.push(a.to_string()),
            IpAddr::V6(a) => v6.push(a.to_string()),
        }
    }

    let mut s = String::new();
    let _ = writeln!(s, "table inet {TABLE} {{");

    if !v4.is_empty() {
        let _ = writeln!(
            s,
            "  set allow4 {{ type ipv4_addr; flags interval; elements = {{ {} }} }}",
            v4.join(", ")
        );
    }
    if !v6.is_empty() {
        let _ = writeln!(
            s,
            "  set allow6 {{ type ipv6_addr; flags interval; elements = {{ {} }} }}",
            v6.join(", ")
        );
    }

    let ports_set = !snap.allow_ports.is_empty();
    if ports_set {
        let ports = snap
            .allow_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            s,
            "  set allowports {{ type inet_service; elements = {{ {ports} }} }}"
        );
    }

    let _ = writeln!(s, "  chain output {{");
    let _ = writeln!(s, "    type filter hook output priority 0; policy drop;");
    // Let replies to already-accepted flows through.
    let _ = writeln!(s, "    ct state established,related accept");

    if snap.baseline_loopback {
        let _ = writeln!(s, "    oif \"lo\" accept");
    }
    if snap.baseline_dns {
        let _ = writeln!(s, "    udp dport 53 accept");
        let _ = writeln!(s, "    tcp dport 53 accept");
    }
    if snap.baseline_dhcp_ntp {
        let _ = writeln!(s, "    udp dport {{ 67, 68, 123 }} accept");
    }

    // Allow set matches, optionally constrained to allow_ports (per protocol so
    // the port set applies to both tcp and udp destinations).
    let daddr_rule = |fam: &str, set: &str| -> Vec<String> {
        if ports_set {
            vec![
                format!("    {fam} daddr @{set} tcp dport @allowports accept"),
                format!("    {fam} daddr @{set} udp dport @allowports accept"),
            ]
        } else {
            vec![format!("    {fam} daddr @{set} accept")]
        }
    };
    if !v4.is_empty() {
        for line in daddr_rule("ip", "allow4") {
            let _ = writeln!(s, "{line}");
        }
    }
    if !v6.is_empty() {
        for line in daddr_rule("ip6", "allow6") {
            let _ = writeln!(s, "{line}");
        }
    }

    let _ = writeln!(s, "  }}");
    let _ = writeln!(s, "}}");
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::EgressMode;

    fn snap(mode: EgressMode) -> PolicySnapshot {
        PolicySnapshot {
            mode,
            allow_cidrs: vec!["10.0.0.0/8".parse().unwrap()],
            allow_ports: vec![],
            allow_domains: vec!["github.com".into()],
            baseline_dns: true,
            baseline_dhcp_ntp: true,
            baseline_loopback: true,
        }
    }

    #[test]
    fn off_and_monitor_render_nothing() {
        assert!(render_ruleset(&snap(EgressMode::Off), &[]).is_none());
        assert!(render_ruleset(&snap(EgressMode::Monitor), &[]).is_none());
    }

    #[test]
    fn enforce_is_default_deny_with_baseline() {
        let ip: IpAddr = "140.82.112.3".parse().unwrap();
        let out = render_ruleset(&snap(EgressMode::Enforce), &[ip]).unwrap();
        assert!(out.contains("table inet riggs_egress"));
        assert!(out.contains("policy drop;"));
        assert!(out.contains("oif \"lo\" accept"));
        assert!(out.contains("udp dport 53 accept"));
        assert!(out.contains("udp dport { 67, 68, 123 } accept"));
        // CIDR and the resolved host IP both land in the v4 allow set.
        assert!(out.contains("10.0.0.0/8"));
        assert!(out.contains("140.82.112.3"));
        assert!(out.contains("ip daddr @allow4 accept"));
    }

    #[test]
    fn allow_ports_constrains_the_daddr_rule() {
        let mut s = snap(EgressMode::Enforce);
        s.allow_ports = vec![443];
        let out = render_ruleset(&s, &[]).unwrap();
        assert!(out.contains("set allowports"));
        assert!(out.contains("ip daddr @allow4 tcp dport @allowports accept"));
        assert!(out.contains("ip daddr @allow4 udp dport @allowports accept"));
    }

    #[test]
    fn no_baseline_omits_those_rules() {
        let mut s = snap(EgressMode::Enforce);
        s.baseline_dns = false;
        s.baseline_dhcp_ntp = false;
        s.baseline_loopback = false;
        let out = render_ruleset(&s, &[]).unwrap();
        assert!(!out.contains("dport 53"));
        assert!(!out.contains("oif \"lo\""));
        assert!(!out.contains("67, 68, 123"));
    }
}

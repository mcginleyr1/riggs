//! Linux egress enforcement with nftables.
//!
//! [`render_ruleset`] turns an egress [`PolicySnapshot`] plus resolved
//! addresses into a default-deny `inet` table; it is pure and unit-tested. The
//! Linux runtime (`enforce`, `shutdown`) resolves the allowed domains, applies
//! the ruleset with `nft -f -`, and keeps it in step with the live policy.
//!
//! nftables matches addresses, not processes or hostnames, so this is a
//! host-wide allowlist: process rules only widen it (see
//! [`EgressPolicy::snapshot`](crate::EgressPolicy::snapshot)), and `*.`
//! wildcard domains cannot be resolved ahead of time, so their hosts stay
//! denied. See `docs/STANDALONE.md`.

use std::fmt::Write;
use std::net::IpAddr;

use ipnetwork::IpNetwork;

use crate::policy::{EgressMode, PolicySnapshot};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{enforce, shutdown};

/// nftables table name Riggs owns. Applying a fresh ruleset replaces it;
/// teardown is `nft delete table inet <TABLE>`.
pub const TABLE: &str = "riggs_egress";

/// Render an `nft -f` script for the snapshot. `resolved` are the addresses the
/// `allow_domains` currently resolve to; `console` are the management
/// console's, which stay reachable on any port, like the baseline.
///
/// Returns `None` when the mode is not [`EgressMode::Enforce`] — in `Off` and
/// `Monitor` there is nothing to install, and the caller should tear the table
/// down instead (fail open).
pub fn render_ruleset(
    snap: &PolicySnapshot,
    resolved: &[IpAddr],
    console: &[IpAddr],
) -> Option<String> {
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

    // A resolved address can repeat or fall inside an allowed CIDR; without
    // auto-merge nft rejects the whole set as "conflicting intervals".
    if !v4.is_empty() {
        let _ = writeln!(
            s,
            "  set allow4 {{ type ipv4_addr; flags interval; auto-merge; elements = {{ {} }} }}",
            v4.join(", ")
        );
    }
    if !v6.is_empty() {
        let _ = writeln!(
            s,
            "  set allow6 {{ type ipv6_addr; flags interval; auto-merge; elements = {{ {} }} }}",
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
    // Replies on connections the remote side opened (an inbound SSH session)
    // and ICMP errors about tracked flows. Flows this host opens are checked
    // packet by packet, so turning enforce on, or dropping a destination, also
    // cuts connections that already exist, such as an attacker's `ssh -R`.
    let _ = writeln!(s, "    ct direction reply accept");
    let _ = writeln!(s, "    ct state related accept");
    // Neighbor discovery is IPv6's ARP: without it no IPv6 route works at all.
    let _ = writeln!(
        s,
        "    icmpv6 type {{ nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, mld2-listener-report }} accept"
    );

    if snap.baseline_loopback {
        let _ = writeln!(s, "    oif \"lo\" accept");
    }
    if snap.baseline_dns {
        let _ = writeln!(s, "    udp dport 53 accept");
        let _ = writeln!(s, "    tcp dport 53 accept");
    }
    if snap.baseline_dhcp_ntp {
        let _ = writeln!(s, "    udp dport {{ 67, 68, 123 }} accept");
        let _ = writeln!(s, "    udp dport {{ 546, 547 }} accept");
    }
    for ip in console {
        let family = if ip.is_ipv4() { "ip" } else { "ip6" };
        let _ = writeln!(s, "    {family} daddr {ip} accept");
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

    // Refuse instead of dropping: a denied connect fails at once rather than
    // hanging until its timeout, and a cut connection is reset.
    let _ = writeln!(s, "    meta l4proto tcp reject with tcp reset");
    let _ = writeln!(s, "    reject with icmpx type admin-prohibited");

    let _ = writeln!(s, "  }}");
    let _ = writeln!(s, "}}");
    Some(s)
}

/// Host of a console URL (`https://console.example.com:443/path`), without the
/// brackets of an IPv6 literal.
pub fn console_host(endpoint: &str) -> Option<&str> {
    let authority = endpoint
        .split_once("://")
        .map_or(endpoint, |(_, rest)| rest);
    let authority = authority.split(['/', '?', '#']).next()?;
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next()?,
        None => authority.split(':').next()?,
    };
    (!host.is_empty()).then_some(host)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

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
            resolve_interval: Duration::from_secs(120),
        }
    }

    #[test]
    fn off_and_monitor_render_nothing() {
        assert!(render_ruleset(&snap(EgressMode::Off), &[], &[]).is_none());
        assert!(render_ruleset(&snap(EgressMode::Monitor), &[], &[]).is_none());
    }

    #[test]
    fn enforce_is_default_deny_with_baseline() {
        let ip: IpAddr = "140.82.112.3".parse().unwrap();
        let out = render_ruleset(&snap(EgressMode::Enforce), &[ip], &[]).unwrap();
        assert!(out.contains("table inet riggs_egress"));
        assert!(out.contains("policy drop;"));
        assert!(out.contains("oif \"lo\" accept"));
        assert!(out.contains("udp dport 53 accept"));
        assert!(out.contains("udp dport { 67, 68, 123 } accept"));
        assert!(out.contains("udp dport { 546, 547 } accept"));
        assert!(out.contains("nd-neighbor-solicit"));
        // CIDR and the resolved host IP both land in the v4 allow set.
        assert!(out.contains("10.0.0.0/8"));
        assert!(out.contains("140.82.112.3"));
        assert!(out.contains("ip daddr @allow4 accept"));
    }

    #[test]
    fn allow_ports_constrains_the_daddr_rule() {
        let mut s = snap(EgressMode::Enforce);
        s.allow_ports = vec![443];
        let out = render_ruleset(&s, &[], &[]).unwrap();
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
        let out = render_ruleset(&s, &[], &[]).unwrap();
        assert!(!out.contains("dport 53"));
        assert!(!out.contains("oif \"lo\""));
        assert!(!out.contains("67, 68, 123"));
        assert!(!out.contains("546, 547"));
    }

    #[test]
    fn resolved_addresses_inside_a_cidr_or_repeated_merge() {
        let mut s = snap(EgressMode::Enforce);
        s.allow_cidrs.push("2001:db8::/32".parse().unwrap());
        let resolved: Vec<IpAddr> = ["10.1.2.3", "10.1.2.3", "2001:db8::1"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        let out = render_ruleset(&s, &resolved, &[]).unwrap();
        assert!(out.contains(
            "set allow4 { type ipv4_addr; flags interval; auto-merge; elements = { 10.0.0.0/8, 10.1.2.3, 10.1.2.3 } }"
        ));
        assert!(out.contains(
            "set allow6 { type ipv6_addr; flags interval; auto-merge; elements = { 2001:db8::/32, 2001:db8::1 } }"
        ));
        assert!(out.contains("ip6 daddr @allow6 accept"));
    }

    #[test]
    fn console_is_reachable_on_any_port() {
        let mut s = snap(EgressMode::Enforce);
        s.allow_ports = vec![443];
        let console: Vec<IpAddr> = ["203.0.113.10", "2001:db8::10"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        let out = render_ruleset(&s, &[], &console).unwrap();
        assert!(out.contains("    ip daddr 203.0.113.10 accept\n"));
        assert!(out.contains("    ip6 daddr 2001:db8::10 accept\n"));
    }

    #[test]
    fn only_replies_skip_the_allowlist_and_the_rest_is_refused() {
        let out = render_ruleset(&snap(EgressMode::Enforce), &[], &[]).unwrap();
        assert!(out.contains("ct direction reply accept"));
        assert!(!out.contains("established"));
        let allow = out.find("ip daddr @allow4 accept").unwrap();
        let tcp_reset = out.find("meta l4proto tcp reject with tcp reset").unwrap();
        let reject = out.find("reject with icmpx type admin-prohibited").unwrap();
        assert!(allow < tcp_reset && tcp_reset < reject);
    }

    #[test]
    fn console_host_strips_scheme_port_path_and_brackets() {
        assert_eq!(
            console_host("https://console.example.com:50051/v1"),
            Some("console.example.com")
        );
        assert_eq!(console_host("http://10.0.0.5:8080"), Some("10.0.0.5"));
        assert_eq!(
            console_host("https://[2001:db8::1]:443"),
            Some("2001:db8::1")
        );
        assert_eq!(
            console_host("console.example.com"),
            Some("console.example.com")
        );
        assert_eq!(console_host("https://"), None);
    }
}

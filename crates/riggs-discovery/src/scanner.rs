use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use chrono::Utc;
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use thiserror::Error;
use tracing::info;

use crate::device::DiscoveredDevice;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid CIDR: {0}")]
    InvalidCidr(String),

    #[error("Scan error: {0}")]
    Other(String),
}

type Result<T> = std::result::Result<T, ScanError>;

/// Poll granularity for datalink reads. Without a read timeout, `receiver.next()`
/// blocks forever on a silent network and the deadline loop never re-checks the
/// clock — so we bound each read and re-check the deadline between polls.
const DATALINK_READ_TIMEOUT: Duration = Duration::from_millis(200);

/// How long to wait for ARP replies after blasting an active scan.
const ARP_REPLY_WAIT: Duration = Duration::from_secs(3);

fn datalink_config() -> datalink::Config {
    datalink::Config {
        read_timeout: Some(DATALINK_READ_TIMEOUT),
        ..Default::default()
    }
}

/// True when a datalink read error is just the poll timeout expiring (no packet
/// arrived in the window) rather than a real channel failure.
fn is_read_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(ScanError::InvalidCidr(format!(
            "expected IP/prefix: {cidr}"
        )));
    }
    let ip: Ipv4Addr = parts[0]
        .parse()
        .map_err(|_| ScanError::InvalidCidr(format!("invalid IP: {}", parts[0])))?;
    let prefix: u8 = parts[1]
        .parse()
        .map_err(|_| ScanError::InvalidCidr(format!("invalid prefix: {}", parts[1])))?;
    if prefix > 32 {
        return Err(ScanError::InvalidCidr(format!(
            "prefix too large: {prefix}"
        )));
    }
    Ok((ip, prefix))
}

fn enumerate_hosts(base: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    // /0 would enumerate the entire IPv4 space -- nonsensical for a local scan.
    if prefix == 0 {
        return Vec::new();
    }
    if prefix >= 31 {
        return vec![base];
    }
    let mask = !((1u32 << (32 - prefix)) - 1);
    let network = u32::from(base) & mask;
    let broadcast = network | !mask;
    ((network + 1)..broadcast).map(Ipv4Addr::from).collect()
}

fn find_interface_for_subnet(target: Ipv4Addr, prefix: u8) -> Option<NetworkInterface> {
    let mask = if prefix == 0 {
        0
    } else if prefix >= 32 {
        u32::MAX
    } else {
        !((1u32 << (32 - prefix)) - 1)
    };
    let target_network = u32::from(target) & mask;

    datalink::interfaces().into_iter().find(|iface| {
        !iface.is_loopback()
            && iface.ips.iter().any(|ip| {
                if let IpAddr::V4(v4) = ip.ip() {
                    (u32::from(v4) & mask) == target_network
                } else {
                    false
                }
            })
    })
}

fn build_arp_request(
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    buf: &mut [u8; 42],
) -> std::result::Result<(), ScanError> {
    let mut eth_packet = MutableEthernetPacket::new(buf.as_mut_slice())
        .ok_or_else(|| ScanError::Other("failed to create ethernet packet".into()))?;

    eth_packet.set_destination(MacAddr::broadcast());
    eth_packet.set_source(source_mac);
    eth_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buf = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buf)
        .ok_or_else(|| ScanError::Other("failed to create ARP packet".into()))?;

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    eth_packet.set_payload(arp_packet.packet());
    Ok(())
}

pub struct NetworkScanner;

impl NetworkScanner {
    pub fn new() -> Self {
        Self
    }

    pub async fn scan_subnet(&self, cidr: &str) -> Result<Vec<DiscoveredDevice>> {
        let (base_ip, prefix_len) = parse_cidr(cidr)?;
        let hosts = enumerate_hosts(base_ip, prefix_len);

        info!(cidr, host_count = hosts.len(), "starting ARP scan");

        let interface = find_interface_for_subnet(base_ip, prefix_len)
            .ok_or_else(|| ScanError::Other("no suitable network interface found".into()))?;

        let source_ip = interface
            .ips
            .iter()
            .find_map(|ip| match ip.ip() {
                IpAddr::V4(v4) => Some(v4),
                _ => None,
            })
            .ok_or_else(|| ScanError::Other("interface has no IPv4 address".into()))?;

        let source_mac = interface
            .mac
            .ok_or_else(|| ScanError::Other("interface has no MAC address".into()))?;

        let (mut sender, receiver) = match datalink::channel(&interface, datalink_config()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(ScanError::Other("unsupported channel type".into())),
            Err(e) => {
                return Err(ScanError::Other(format!(
                    "failed to open datalink channel (may need root): {e}"
                )))
            }
        };

        for &target_ip in &hosts {
            let mut buf = [0u8; 42];
            build_arp_request(source_mac, source_ip, target_ip, &mut buf)?;

            sender
                .send_to(&buf, None)
                .ok_or_else(|| ScanError::Other("send returned None".into()))?
                .map_err(|e| ScanError::Other(format!("send failed: {e}")))?;
        }

        let discovered = tokio::task::spawn_blocking(move || collect_arp_replies(receiver))
            .await
            .map_err(|e| ScanError::Other(format!("blocking task failed: {e}")))?;

        let now = Utc::now();
        let devices: Vec<DiscoveredDevice> = discovered
            .into_iter()
            .map(|(ip, mac)| DiscoveredDevice {
                ip: IpAddr::V4(ip),
                mac: Some(mac.to_string()),
                hostname: None,
                os_fingerprint: None,
                open_ports: Vec::new(),
                first_seen: now,
                last_seen: now,
            })
            .collect();

        info!(found = devices.len(), "ARP scan complete");
        Ok(devices)
    }

    pub async fn passive_discover(&self, duration_secs: u64) -> Result<Vec<DiscoveredDevice>> {
        let interface = datalink::interfaces()
            .into_iter()
            .find(|i| !i.is_loopback() && i.is_up() && !i.ips.is_empty())
            .ok_or_else(|| ScanError::Other("no suitable network interface".into()))?;

        info!(
            iface = %interface.name,
            duration_secs,
            "starting passive discovery"
        );

        let (_, receiver) = match datalink::channel(&interface, datalink_config()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(ScanError::Other("unsupported channel type".into())),
            Err(e) => {
                return Err(ScanError::Other(format!(
                    "failed to open datalink channel (may need root): {e}"
                )))
            }
        };

        let duration = Duration::from_secs(duration_secs);

        let seen = tokio::task::spawn_blocking(move || sniff_arp_traffic(receiver, duration))
            .await
            .map_err(|e| ScanError::Other(format!("blocking task failed: {e}")))?;

        let now = Utc::now();
        let result: Vec<DiscoveredDevice> = seen
            .into_iter()
            .map(|(ip, mac)| DiscoveredDevice {
                ip,
                mac,
                hostname: None,
                os_fingerprint: None,
                open_ports: Vec::new(),
                first_seen: now,
                last_seen: now,
            })
            .collect();

        info!(found = result.len(), "passive discovery complete");
        Ok(result)
    }
}

impl Default for NetworkScanner {
    fn default() -> Self {
        Self::new()
    }
}

fn collect_arp_replies(
    mut receiver: Box<dyn pnet::datalink::DataLinkReceiver>,
) -> HashMap<Ipv4Addr, MacAddr> {
    let mut found: HashMap<Ipv4Addr, MacAddr> = HashMap::new();
    let deadline = std::time::Instant::now() + ARP_REPLY_WAIT;

    while std::time::Instant::now() < deadline {
        match receiver.next() {
            Ok(packet) => {
                if let Some(eth) = EthernetPacket::new(packet) {
                    if eth.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp) = ArpPacket::new(eth.payload()) {
                            if arp.get_operation() == ArpOperations::Reply {
                                let sender_ip = arp.get_sender_proto_addr();
                                let sender_mac = arp.get_sender_hw_addr();
                                found.insert(sender_ip, sender_mac);
                            }
                        }
                    }
                }
            }
            // Poll timeout: no packet this window -> re-check the deadline.
            Err(ref e) if is_read_timeout(e) => continue,
            Err(_) => break,
        }
    }
    found
}

fn sniff_arp_traffic(
    mut receiver: Box<dyn pnet::datalink::DataLinkReceiver>,
    duration: Duration,
) -> HashMap<IpAddr, Option<String>> {
    let mut seen: HashMap<IpAddr, Option<String>> = HashMap::new();
    let deadline = std::time::Instant::now() + duration;

    while std::time::Instant::now() < deadline {
        match receiver.next() {
            Ok(packet) => {
                if let Some(eth) = EthernetPacket::new(packet) {
                    if eth.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp) = ArpPacket::new(eth.payload()) {
                            let ip = IpAddr::V4(arp.get_sender_proto_addr());
                            let mac = arp.get_sender_hw_addr().to_string();
                            seen.entry(ip).or_insert(Some(mac));
                        }
                    }
                }
            }
            // Poll timeout: no packet this window -> re-check the deadline.
            Err(ref e) if is_read_timeout(e) => continue,
            Err(_) => break,
        }
    }
    seen
}

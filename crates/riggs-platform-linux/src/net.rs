//! Outbound connections from the kernel socket tables in /proc/net, attributed
//! to processes through their /proc/<pid>/fd socket links.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use riggs_platform::PlatformSensor;
use riggs_types::events::{NetworkDirection, RiggsEvent};
use tokio::sync::mpsc;

use crate::LinuxSensor;

#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) struct Connection {
    pid: u32,
    proto: &'static str,
    local: SocketAddr,
    remote: SocketAddr,
}

struct Socket {
    local: SocketAddr,
    remote: SocketAddr,
    state: u8,
    inode: u64,
}

const TCP_LISTEN: u8 = 0x0A;
const TABLES: [(&str, &str); 4] = [
    ("tcp", "/proc/net/tcp"),
    ("tcp", "/proc/net/tcp6"),
    ("udp", "/proc/net/udp"),
    ("udp", "/proc/net/udp6"),
];

/// Emit one Outbound event per connection the first time a poll sees it.
pub(crate) fn spawn(tx: mpsc::Sender<RiggsEvent>) {
    tokio::spawn(async move {
        let sensor = LinuxSensor::new();
        let mut known = HashSet::new();
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let current: HashSet<Connection> = connections()
                .into_iter()
                .filter(|c| c.pid != std::process::id())
                .collect();
            for conn in current.difference(&known) {
                let Ok(Some(ctx)) = sensor.process_context(conn.pid).await else {
                    continue;
                };
                let event = RiggsEvent::new_network(
                    NetworkDirection::Outbound,
                    ctx,
                    conn.local.ip().to_string(),
                    conn.remote.ip().to_string(),
                    conn.local.port(),
                    conn.remote.port(),
                    conn.proto,
                );
                if tx.send(event).await.is_err() {
                    return;
                }
            }
            known = current;
        }
    });
}

pub(crate) fn connections() -> Vec<Connection> {
    let tables = TABLES.map(|(proto, path)| {
        (
            proto,
            parse_table(&std::fs::read_to_string(path).unwrap_or_default()),
        )
    });
    let outbound = outbound(&tables);
    let owners = socket_owners(outbound.iter().map(|(_, s)| s.inode).collect());
    outbound
        .into_iter()
        .filter_map(|(proto, s)| {
            Some(Connection {
                pid: *owners.get(&s.inode)?,
                proto,
                local: s.local,
                remote: s.remote,
            })
        })
        .collect()
}

/// Connected sockets to a non-loopback peer, minus the server side of TCP
/// connections accepted on a listening port and sockets no process holds
/// (inode 0, e.g. TIME_WAIT).
fn outbound<'a>(tables: &'a [(&'static str, Vec<Socket>)]) -> Vec<(&'static str, &'a Socket)> {
    let listening: HashSet<u16> = tables
        .iter()
        .filter(|(proto, _)| *proto == "tcp")
        .flat_map(|(_, sockets)| sockets)
        .filter(|s| s.state == TCP_LISTEN)
        .map(|s| s.local.port())
        .collect();
    tables
        .iter()
        .flat_map(|(proto, sockets)| sockets.iter().map(move |s| (*proto, s)))
        .filter(|(_, s)| {
            s.remote.port() != 0 && !s.remote.ip().is_unspecified() && !s.remote.ip().is_loopback()
        })
        .filter(|(proto, s)| !(*proto == "tcp" && listening.contains(&s.local.port())))
        .filter(|(_, s)| s.inode != 0)
        .collect()
}

fn parse_table(table: &str) -> Vec<Socket> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            Some(Socket {
                local: parse_addr(fields.get(1)?)?,
                remote: parse_addr(fields.get(2)?)?,
                state: u8::from_str_radix(fields.get(3)?, 16).ok()?,
                inode: fields.get(9)?.parse().ok()?,
            })
        })
        .collect()
}

fn parse_addr(field: &str) -> Option<SocketAddr> {
    let (hex, port) = field.split_once(':')?;
    // The kernel prints each 32-bit word of the address in host byte order.
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(8)
        .map(|i| u32::from_str_radix(hex.get(i..i + 8)?, 16).ok())
        .collect::<Option<Vec<u32>>>()?
        .into_iter()
        .flat_map(u32::to_ne_bytes)
        .collect();
    let ip = match bytes.len() {
        4 => IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?),
        16 => IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?),
        _ => return None,
    };
    // A dual-stack socket talking IPv4 shows ::ffff:a.b.c.d.
    Some(SocketAddr::new(
        ip.to_canonical(),
        u16::from_str_radix(port, 16).ok()?,
    ))
}

fn socket_owners(inodes: HashSet<u64>) -> HashMap<u64, u32> {
    let mut owners = HashMap::new();
    if inodes.is_empty() {
        return owners;
    }
    let pids = std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok());
    for pid in pids {
        let fds = std::fs::read_dir(format!("/proc/{pid}/fd"))
            .into_iter()
            .flatten()
            .flatten();
        for fd in fds {
            let inode = std::fs::read_link(fd.path()).ok().and_then(|link| {
                link.to_str()?
                    .strip_prefix("socket:[")?
                    .strip_suffix(']')?
                    .parse()
                    .ok()
            });
            if let Some(inode) = inode.filter(|i| inodes.contains(i)) {
                owners.entry(inode).or_insert(pid);
            }
        }
        if owners.len() == inodes.len() {
            break;
        }
    }
    owners
}

#[cfg(test)]
mod tests {
    use super::*;

    // Captured from /proc/net in a rust:1.99 container (192.168.215.3) with: a
    // blackholed `nc 203.0.113.7 22` (SYN_SENT), `nc -6 ::ffff:203.0.113.8 443`,
    // a connected `nc -u 198.51.100.9 5353`, listeners on 4444 and [::]:4446,
    // clients connected to them over 192.168.215.3 and ::1, and the orphaned
    // FIN_WAIT1 row an exited `curl http://example.com` left behind.
    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:115C 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 6555059 1 000000004f1ee2cb 100 0 0 10 0
   1: 03D7A8C0:DCB8 077100CB:0016 02 00000001:00000000 01:0000062B 00000008     0        0 6552352 2 000000007dc46290 1600 0 0 1 7
   2: 03D7A8C0:9B94 03D7A8C0:115C 01 00000000:00000000 00:00000000 00000000     0        0 6563920 1 0000000063bc5c18 20 0 0 10 -1
   3: 03D7A8C0:115C 03D7A8C0:9B94 01 00000000:00000000 00:00000000 00000000     0        0 6555060 1 00000000ec2e857a 20 0 0 10 -1
  15: 03D7A8C0:946C 9A171468:0050 04 00000001:00000000 01:00000015 00000000     0        0 0 3 00000000ca05110d 21 4 30 10 -1
";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:115E 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 6559993 1 000000009c6951e0 100 0 0 10 0
   1: 0000000000000000FFFF000003D7A8C0:AC38 0000000000000000FFFF0000087100CB:01BB 02 00000001:00000000 01:000000CE 00000006     0        0 6564966 2 0000000027c734ee 400 0 0 1 7
   2: 00000000000000000000000001000000:115E 00000000000000000000000001000000:B228 01 00000000:00000000 00:00000000 00000000     0        0 6559994 1 00000000fcbdaae8 20 0 0 10 -1
   3: 00000000000000000000000001000000:B228 00000000000000000000000001000000:115E 01 00000000:00000000 00:00000000 00000000     0        0 6546268 1 00000000608cf90f 20 0 0 10 -1
";
    const UDP: &str = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
 1276: 03D7A8C0:C1F5 096433C6:14E9 01 00000000:00000000 00:00000000 00000000     0        0 6555077 2 000000008ed7c836 0
";

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_ipv4_rows_including_a_connect_in_progress() {
        let sockets = parse_table(TCP);
        let syn_sent = &sockets[1];
        assert_eq!(syn_sent.local, addr("192.168.215.3:56504"));
        assert_eq!(syn_sent.remote, addr("203.0.113.7:22"));
        assert_eq!(syn_sent.state, 0x02);
        assert_eq!(syn_sent.inode, 6552352);
        assert_eq!(sockets[4].remote, addr("104.20.23.154:80"));
        assert_eq!(sockets[4].inode, 0);
    }

    #[test]
    fn parses_ipv6_rows_and_unmaps_ipv4_peers() {
        let sockets = parse_table(TCP6);
        assert_eq!(sockets.len(), 4);
        assert_eq!(sockets[0].local, addr("[::]:4446"));
        assert_eq!(sockets[1].remote, addr("203.0.113.8:443"));
        assert_eq!(sockets[3].local, addr("[::1]:45608"));
    }

    #[test]
    fn keeps_outbound_connections_and_drops_listeners_accepted_loopback_and_orphans() {
        let tables = [
            ("tcp", parse_table(TCP)),
            ("tcp", parse_table(TCP6)),
            ("udp", parse_table(UDP)),
        ];
        let found: Vec<_> = outbound(&tables)
            .into_iter()
            .map(|(proto, s)| (proto, s.remote, s.inode))
            .collect();
        assert_eq!(
            found,
            [
                ("tcp", addr("203.0.113.7:22"), 6552352),
                ("tcp", addr("192.168.215.3:4444"), 6563920),
                ("tcp", addr("203.0.113.8:443"), 6564966),
                ("udp", addr("198.51.100.9:5353"), 6555077),
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attributes_a_live_connection_to_this_process() {
        use std::net::{TcpListener, TcpStream, UdpSocket};

        // The address of the default-route interface (a UDP connect sends nothing).
        let probe = UdpSocket::bind("0.0.0.0:0").unwrap();
        probe.connect("192.0.2.1:9").unwrap();
        let listener = TcpListener::bind((probe.local_addr().unwrap().ip(), 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _accepted = listener.accept().unwrap();

        let found = connections();

        assert!(found.contains(&Connection {
            pid: std::process::id(),
            proto: "tcp",
            local: client.local_addr().unwrap(),
            remote: listener.local_addr().unwrap(),
        }));
        assert!(!found
            .iter()
            .any(|c| c.local == listener.local_addr().unwrap()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "prints this host's outbound connections and what one poll costs"]
    fn print_connections_and_poll_cost() {
        let cpu_us = || {
            let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
            unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
            let us = |t: libc::timeval| t.tv_sec * 1_000_000 + t.tv_usec;
            us(usage.ru_utime) + us(usage.ru_stime)
        };
        let polls = 20;
        let (wall, cpu) = (std::time::Instant::now(), cpu_us());
        for _ in 0..polls {
            connections();
        }
        let (wall, cpu) = (wall.elapsed() / polls, (cpu_us() - cpu) / polls as i64);
        let found = connections();
        for conn in &found {
            println!("{conn:?}");
        }
        let sockets: usize = TABLES
            .iter()
            .map(|(_, path)| parse_table(&std::fs::read_to_string(path).unwrap()).len())
            .sum();
        let pids = std::fs::read_dir("/proc")
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.parse::<u32>().is_ok())
            })
            .count();
        println!(
            "{pids} pids, {sockets} sockets, {} outbound; one poll: {wall:?} wall, {cpu} us cpu",
            found.len()
        );
    }
}

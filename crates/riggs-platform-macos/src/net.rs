//! Outbound connections from every process's socket descriptors, via libproc.
//! As root this sees all processes; otherwise only the caller's own.

use std::collections::HashSet;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use riggs_platform::PlatformSensor;
use riggs_types::events::{NetworkDirection, RiggsEvent};
use tokio::sync::mpsc;

use crate::MacOsSensor;

#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) struct Connection {
    pid: u32,
    proto: &'static str,
    local: SocketAddr,
    remote: SocketAddr,
}

// <sys/proc_info.h> values libc does not export.
const PROC_PIDFDSOCKETINFO: i32 = 3;
const SOCKINFO_IN: i32 = 1;
const SOCKINFO_TCP: i32 = 2;
const TSI_S_CLOSED: i32 = 0;
const TSI_S_LISTEN: i32 = 1;
const INI_IPV4: u8 = 0x1;

/// `struct socket_fdinfo` with the in_sockinfo/tcp_sockinfo arm of the
/// `soi_proto` union; the fields riggs does not read are padding.
#[repr(C)]
struct SocketFdInfo {
    _fileinfo_to_soi_type: [u8; 180],
    soi_protocol: i32,
    _soi_family_to_soi_snd: [u8; 72],
    soi_kind: i32,
    _rfu_1: u32,
    insi_fport: i32,
    insi_lport: i32,
    _insi_gencnt_to_flow: [u8; 16],
    insi_vflag: u8,
    _insi_ip_ttl_to_rfu_1: [u8; 7],
    insi_faddr: [u8; 16],
    insi_laddr: [u8; 16],
    _insi_v4_v6: [u8; 16],
    tcpsi_state: i32,
    _rest_of_soi_proto: [u8; 444],
}

// Size and offsets as clang reports them for the macOS SDK header.
const _: () = {
    assert!(size_of::<SocketFdInfo>() == 792);
    assert!(std::mem::offset_of!(SocketFdInfo, soi_kind) == 256);
    assert!(std::mem::offset_of!(SocketFdInfo, insi_fport) == 264);
    assert!(std::mem::offset_of!(SocketFdInfo, insi_vflag) == 288);
    assert!(std::mem::offset_of!(SocketFdInfo, insi_faddr) == 296);
    assert!(std::mem::offset_of!(SocketFdInfo, tcpsi_state) == 344);
};

/// Emit one Outbound event per connection the first time a poll sees it.
pub(crate) fn spawn(tx: mpsc::Sender<RiggsEvent>) {
    tokio::spawn(async move {
        let sensor = MacOsSensor::new();
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

/// Connected sockets to a non-loopback peer, minus the server side of TCP
/// connections accepted on a listening port.
pub(crate) fn connections() -> Vec<Connection> {
    let sockets: Vec<(Connection, bool)> = pids()
        .into_iter()
        .flat_map(|pid| {
            socket_fds(pid)
                .into_iter()
                .filter_map(move |fd| socket(pid, fd))
        })
        .collect();
    let listening: HashSet<u16> = sockets
        .iter()
        .filter(|(_, listen)| *listen)
        .map(|(c, _)| c.local.port())
        .collect();
    sockets
        .into_iter()
        .map(|(c, _)| c)
        .filter(|c| {
            c.remote.port() != 0 && !c.remote.ip().is_unspecified() && !c.remote.ip().is_loopback()
        })
        .filter(|c| !(c.proto == "tcp" && listening.contains(&c.local.port())))
        .collect()
}

fn pids() -> Vec<i32> {
    let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    // Room for processes started between the two calls.
    let mut pids = vec![0i32; count.max(0) as usize + 64];
    let count = unsafe {
        libc::proc_listallpids(
            pids.as_mut_ptr().cast(),
            (pids.len() * size_of::<i32>()) as i32,
        )
    };
    pids.truncate(count.max(0) as usize);
    pids
}

fn socket_fds(pid: i32) -> Vec<i32> {
    let bytes =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    let empty = libc::proc_fdinfo {
        proc_fd: 0,
        proc_fdtype: 0,
    };
    let mut fds = vec![empty; bytes.max(0) as usize / size_of::<libc::proc_fdinfo>()];
    let bytes = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            fds.as_mut_ptr().cast(),
            (fds.len() * size_of::<libc::proc_fdinfo>()) as i32,
        )
    };
    fds.truncate(bytes.max(0) as usize / size_of::<libc::proc_fdinfo>());
    fds.into_iter()
        .filter(|fd| fd.proc_fdtype == libc::PROX_FDTYPE_SOCKET as u32)
        .map(|fd| fd.proc_fd)
        .collect()
}

/// A TCP or UDP socket and whether it is listening.
fn socket(pid: i32, fd: i32) -> Option<(Connection, bool)> {
    // SAFETY: SocketFdInfo is plain integers, for which all-zero is valid.
    let mut info: SocketFdInfo = unsafe { std::mem::zeroed() };
    let size = size_of::<SocketFdInfo>() as i32;
    let filled = unsafe {
        libc::proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDSOCKETINFO,
            (&mut info as *mut SocketFdInfo).cast(),
            size,
        )
    };
    if filled != size {
        return None;
    }
    let proto = match (info.soi_kind, info.soi_protocol) {
        // A closed TCP socket is no flow, and the kernel has cleared the
        // flags that say which address family it held.
        (SOCKINFO_TCP, _) if info.tcpsi_state != TSI_S_CLOSED => "tcp",
        (SOCKINFO_IN, libc::IPPROTO_UDP) => "udp",
        _ => return None,
    };
    let ip = |mut addr: [u8; 16]| -> IpAddr {
        if info.insi_vflag & INI_IPV4 != 0 {
            return Ipv4Addr::new(addr[12], addr[13], addr[14], addr[15]).into();
        }
        // The kernel embeds a link-local address's interface index in bytes 2-3.
        if Ipv6Addr::from(addr).is_unicast_link_local() {
            addr[2..4].fill(0);
        }
        Ipv6Addr::from(addr).to_canonical()
    };
    // Ports are stored in network byte order.
    let port = |raw: i32| u16::from_be(raw as u16);
    let conn = Connection {
        pid: pid as u32,
        proto,
        local: SocketAddr::new(ip(info.insi_laddr), port(info.insi_lport)),
        remote: SocketAddr::new(ip(info.insi_faddr), port(info.insi_fport)),
    };
    Some((conn, proto == "tcp" && info.tcpsi_state == TSI_S_LISTEN))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream, UdpSocket};

    #[test]
    fn attributes_a_live_connection_to_this_process() {
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
        assert!(found.contains(&Connection {
            pid: std::process::id(),
            proto: "udp",
            local: probe.local_addr().unwrap(),
            remote: "192.0.2.1:9".parse().unwrap(),
        }));
        assert!(!found
            .iter()
            .any(|c| c.local == listener.local_addr().unwrap()));
    }

    #[tokio::test]
    #[ignore = "prints the events this user's connections produce and what one poll costs"]
    async fn print_events_and_poll_cost() {
        let cpu_us = || {
            let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
            unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
            let us = |t: libc::timeval| t.tv_sec * 1_000_000 + i64::from(t.tv_usec);
            us(usage.ru_utime) + us(usage.ru_stime)
        };
        let pids = pids();
        let socket_fds: usize = pids.iter().map(|pid| socket_fds(*pid).len()).sum();
        let polls = 20;
        let (wall, cpu) = (std::time::Instant::now(), cpu_us());
        for _ in 0..polls {
            connections();
        }
        let (wall, cpu) = (wall.elapsed() / polls, (cpu_us() - cpu) / polls as i64);
        let (tx, mut rx) = mpsc::channel(4096);
        spawn(tx);
        tokio::time::sleep(Duration::from_millis(1500)).await;
        while let Ok(RiggsEvent::Network(e)) = rx.try_recv() {
            let ctx = &e.process_context;
            println!(
                "{} {}:{} -> {}:{} pid={} ppid={} user={} path={} cmdline={:.60}",
                e.protocol,
                e.src_addr,
                e.src_port,
                e.dst_addr,
                e.dst_port,
                ctx.pid,
                ctx.ppid,
                ctx.user,
                ctx.path,
                ctx.cmdline
            );
        }
        println!(
            "{} pids, {socket_fds} visible socket fds; one poll: {wall:?} wall, {cpu} us cpu",
            pids.len()
        );
    }
}

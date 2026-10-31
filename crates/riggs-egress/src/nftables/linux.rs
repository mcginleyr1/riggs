use std::collections::BTreeMap;
use std::io::{self, ErrorKind, Write};
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use super::{console_host, render_ruleset};
use crate::policy::{EgressMode, EgressPolicy};

/// Drops the table in one transaction whether or not it exists (a bare
/// `delete` fails when it is absent). In front of a ruleset it makes the
/// replacement atomic: there is never a moment with no rules or half of them.
const CLEAR: &str = "table inet riggs_egress {}\ndelete table inet riggs_egress\n";

/// DNS answers rotate (round-robin, geo, CDN), so an address stays allowed for
/// this long after a lookup last returned it: a client that resolved a little
/// earlier or later than the enforcer still connects.
const ANSWER_RETENTION: Duration = Duration::from_secs(3600);

/// Serializes `nft` runs. Set once the daemon has removed the table on a clean
/// stop, so an apply still in flight cannot put it back.
static STOPPED: Mutex<bool> = Mutex::new(false);

/// Keep the kernel ruleset in step with the live policy: in enforce mode
/// resolve the allowed domains and the console host and replace the table, on
/// every policy change and every `resolve_interval`; in off/monitor remove it.
///
/// A failed apply leaves the previous ruleset in force: `nft -f` is one
/// transaction, so the kernel holds a complete earlier ruleset, or none, never
/// part of one. It is retried on the next change or interval.
pub async fn enforce(
    mut policy: watch::Receiver<Arc<EgressPolicy>>,
    console_endpoint: Option<String>,
) {
    let console = console_endpoint
        .as_deref()
        .and_then(console_host)
        .map(str::to_owned);
    let mut answers: BTreeMap<(String, IpAddr), Instant> = BTreeMap::new();
    let mut unenforceable: Vec<String> = Vec::new();
    let mut applied = String::new();
    loop {
        let snap = policy.borrow_and_update().snapshot();
        let enforcing = snap.mode == EgressMode::Enforce;
        let (script, addresses) = if enforcing {
            let (wildcards, mut hosts): (Vec<String>, Vec<String>) = snap
                .allow_domains
                .iter()
                .cloned()
                .partition(|d| d.starts_with("*."));
            if wildcards != unenforceable && !wildcards.is_empty() {
                warn!(
                    patterns = ?wildcards,
                    "wildcard egress domains cannot be resolved ahead of time, so nftables denies their hosts; list exact hostnames to allow them"
                );
            }
            unenforceable = wildcards;
            hosts.extend(console.clone());

            let now = Instant::now();
            answers.retain(|(host, _), seen| {
                hosts.contains(host) && now.duration_since(*seen) < ANSWER_RETENTION
            });
            let mut lookups = JoinSet::new();
            for host in hosts {
                lookups.spawn(async move {
                    let found = tokio::net::lookup_host((host.as_str(), 0))
                        .await
                        .map(|addrs| addrs.map(|a| a.ip()).collect::<Vec<_>>());
                    (host, found)
                });
            }
            while let Some(joined) = lookups.join_next().await {
                match joined.expect("lookup task panicked") {
                    (host, Ok(ips)) => {
                        for ip in ips {
                            answers.insert((host.clone(), ip), now);
                        }
                    }
                    (host, Err(e)) => warn!(
                        host,
                        error = %e,
                        "egress allow domain did not resolve; keeping its recent addresses"
                    ),
                }
            }

            let mut resolved = Vec::new();
            let mut pinned = Vec::new();
            for (host, ip) in answers.keys() {
                if Some(host) == console.as_ref() {
                    pinned.push(*ip);
                } else {
                    resolved.push(*ip);
                }
            }
            let ruleset =
                render_ruleset(&snap, &resolved, &pinned).expect("enforce mode renders a ruleset");
            (format!("{CLEAR}{ruleset}"), resolved.len())
        } else {
            (CLEAR.to_owned(), 0)
        };

        let failed = match tokio::task::block_in_place(|| nft(&script, false)) {
            Ok(()) if script != applied => {
                if enforcing {
                    info!(
                        addresses,
                        cidrs = snap.allow_cidrs.len(),
                        console = ?console,
                        "egress allowlist enforced with nftables; host-wide, so process rules widen it but do not restrict a process"
                    );
                } else {
                    info!(mode = snap.mode.as_str(), "egress nftables table removed");
                }
                applied = script;
                false
            }
            Ok(()) => false,
            // Without nft there is no table of ours to remove.
            Err(e) if !enforcing && e.kind() == ErrorKind::NotFound => false,
            Err(e) => {
                error!(
                    error = %e,
                    mode = snap.mode.as_str(),
                    "nft failed; the kernel keeps its previous egress ruleset"
                );
                true
            }
        };

        // Enforce re-resolves on the interval. A failed run is retried on it in
        // every mode: a removal that failed must not leave default-deny in force
        // until the next policy edit.
        tokio::select! {
            changed = policy.changed() => if changed.is_err() { return },
            _ = tokio::time::sleep(snap.resolve_interval), if enforcing || failed => {}
        }
    }
}

/// Clean daemon stop: remove the table so the host fails open (nothing would
/// keep its resolved addresses fresh) and keep a still-running enforcer from
/// re-applying it. A crash skips this and leaves the table in force (fail
/// closed) until the restarted daemon replaces it.
pub fn shutdown() {
    match nft(CLEAR, true) {
        Ok(()) => info!("egress nftables table removed for shutdown"),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => error!(error = %e, "failed to remove the egress nftables table at shutdown"),
    }
}

/// Run `script` through `nft -f -`. `last` marks the shutdown removal, after
/// which no run may touch the table again.
fn nft(script: &str, last: bool) -> io::Result<()> {
    let mut stopped = STOPPED.lock().unwrap_or_else(PoisonError::into_inner);
    if *stopped {
        return Ok(());
    }
    *stopped = last;
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(script.as_bytes())?;
    let out = child.wait_with_output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(
            String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        ))
    }
}

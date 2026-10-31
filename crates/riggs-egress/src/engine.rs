use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::watch;

use crate::policy::{EgressDecision, EgressMode, EgressPolicy};

/// Holds the live egress policy in a watch channel: flow checks read it, the
/// hot-reload watcher swaps it, and every swap wakes the subscribers (the
/// Linux nftables enforcer).
pub struct EgressEngine {
    policy: watch::Sender<Arc<EgressPolicy>>,
}

impl EgressEngine {
    pub fn new(policy: EgressPolicy) -> Self {
        Self {
            policy: watch::Sender::new(Arc::new(policy)),
        }
    }

    pub fn replace_policy(&self, policy: EgressPolicy) {
        self.policy.send_replace(Arc::new(policy));
    }

    pub fn subscribe(&self) -> watch::Receiver<Arc<EgressPolicy>> {
        self.policy.subscribe()
    }

    fn current(&self) -> Arc<EgressPolicy> {
        self.policy.borrow().clone()
    }

    pub fn mode(&self) -> EgressMode {
        self.current().mode()
    }

    /// (mode, global allow-domain count, process-rule count) for status queries.
    pub fn status(&self) -> (EgressMode, usize, usize) {
        let p = self.current();
        (p.mode(), p.domain_count(), p.process_rule_count())
    }

    pub fn evaluate(
        &self,
        process: Option<&str>,
        hostname: Option<&str>,
        ip: Option<IpAddr>,
        port: u16,
    ) -> EgressDecision {
        self.current().evaluate(process, hostname, ip, port)
    }
}

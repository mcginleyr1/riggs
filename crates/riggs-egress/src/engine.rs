use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use crate::policy::{EgressDecision, EgressMode, EgressPolicy};

/// Holds the live egress policy behind an RwLock so the hot-reload watcher can
/// swap it while flow checks read it concurrently.
pub struct EgressEngine {
    policy: RwLock<Arc<EgressPolicy>>,
}

impl EgressEngine {
    pub fn new(policy: EgressPolicy) -> Self {
        Self {
            policy: RwLock::new(Arc::new(policy)),
        }
    }

    pub fn replace_policy(&self, policy: EgressPolicy) {
        let mut guard = self.policy.write().unwrap_or_else(|e| e.into_inner());
        *guard = Arc::new(policy);
    }

    fn current(&self) -> Arc<EgressPolicy> {
        self.policy
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
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

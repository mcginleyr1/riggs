use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Clone, Default)]
pub struct DaemonStatus {
    pub connected: bool,
    pub running: bool,
    pub events_processed: u64,
    pub active_threats: u32,
    pub bloom_size: usize,
    pub cache_entries: u64,
    pub feeds_last_updated: Option<String>,
    pub last_update: Option<Instant>,
}

impl DaemonStatus {
    pub fn events_per_sec(&self) -> Option<f64> {
        let elapsed = self.last_update?.elapsed().as_secs_f64();
        if elapsed > 0.0 && self.events_processed > 0 {
            Some(self.events_processed as f64 / elapsed.max(1.0))
        } else {
            None
        }
    }
}

pub type SharedStatus = Arc<Mutex<DaemonStatus>>;

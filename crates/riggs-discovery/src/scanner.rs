use thiserror::Error;

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

pub struct NetworkScanner;

impl NetworkScanner {
    pub fn new() -> Self {
        Self
    }

    pub async fn scan_subnet(&self, _cidr: &str) -> Result<Vec<DiscoveredDevice>> {
        todo!("ARP scan implementation")
    }

    pub async fn passive_discover(&self, _duration_secs: u64) -> Result<Vec<DiscoveredDevice>> {
        todo!("Passive traffic analysis implementation")
    }
}

impl Default for NetworkScanner {
    fn default() -> Self {
        Self::new()
    }
}

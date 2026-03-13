use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredDevice {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub os_fingerprint: Option<String>,
    pub open_ports: Vec<u16>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

use async_trait::async_trait;
use riggs_types::errors::RiggsError;
use riggs_types::events::{ProcessContext, RiggsEvent};
use tokio::sync::mpsc;

/// Capability flags indicating what a platform sensor supports
#[derive(Debug, Clone)]
pub struct PlatformCapabilities {
    pub process_monitoring: bool,
    pub file_monitoring: bool,
    pub network_monitoring: bool,
    pub dns_monitoring: bool,
    pub auth_monitoring: bool,
    pub kernel_monitoring: bool,
}

/// Core trait that every platform sensor must implement
#[async_trait]
pub trait PlatformSensor: Send + Sync + 'static {
    /// Returns what this platform supports
    fn capabilities(&self) -> PlatformCapabilities;

    /// Start the sensor, sending events to the provided channel
    async fn start(&mut self, tx: mpsc::Sender<RiggsEvent>) -> Result<(), RiggsError>;

    /// Stop the sensor gracefully
    async fn stop(&mut self) -> Result<(), RiggsError>;

    /// Get current process context for a PID
    async fn process_context(&self, pid: u32) -> Result<Option<ProcessContext>, RiggsError>;

    /// Check if sensor is healthy
    async fn health_check(&self) -> Result<bool, RiggsError>;
}

/// Trait for file system interception (blocking a file open until verdict)
#[async_trait]
pub trait FileGate: Send + Sync + 'static {
    /// Register a handler that is called before a file is opened/executed
    /// Returns true to allow, false to block
    async fn register_gate<F>(&mut self, handler: F) -> Result<(), RiggsError>
    where
        F: Fn(&std::path::Path, &ProcessContext) -> bool + Send + Sync + 'static;
}

/// Trait for network containment actions
#[async_trait]
pub trait NetworkContainment: Send + Sync + 'static {
    /// Block all network traffic except to specified allowed IPs
    async fn contain(&self, allowed_ips: &[std::net::IpAddr]) -> Result<(), RiggsError>;

    /// Remove containment, restore normal networking
    async fn release(&self) -> Result<(), RiggsError>;

    /// Check if containment is currently active
    async fn is_contained(&self) -> Result<bool, RiggsError>;
}

/// Trait for process control actions
#[async_trait]
pub trait ProcessControl: Send + Sync + 'static {
    /// Kill a process by PID
    async fn kill_process(&self, pid: u32) -> Result<(), RiggsError>;

    /// Suspend a process by PID
    async fn suspend_process(&self, pid: u32) -> Result<(), RiggsError>;

    /// Resume a suspended process
    async fn resume_process(&self, pid: u32) -> Result<(), RiggsError>;
}

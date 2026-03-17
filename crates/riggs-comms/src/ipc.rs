use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info};

use riggs_types::events::RiggsEvent;
use riggs_types::verdict::MergedVerdict;

use crate::messages::{ClientMessage, DaemonMessage};

pub trait StoreQuery: Send + Sync {
    fn recent_events(&self, limit: usize) -> Vec<RiggsEvent>;
    fn threats_above_clean(&self, limit: usize) -> Vec<MergedVerdict>;
}

pub struct DlpFlowVerdict {
    pub allow: bool,
    pub reason: Option<String>,
}

pub trait DlpQuery: Send + Sync {
    fn check_flow(
        &self,
        pid: u32,
        hostname: &str,
        remote_ip: &str,
        remote_port: u16,
    ) -> DlpFlowVerdict;

    fn status(&self) -> DlpQueryStatus;
}

pub struct DlpQueryStatus {
    pub enabled: bool,
    pub tracked_pids: usize,
    pub tracked_accesses: usize,
    pub watched_domains: usize,
}

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("IPC error: {0}")]
    Other(String),
}

type Result<T> = std::result::Result<T, IpcError>;

pub struct DaemonState {
    pub events_processed: Arc<AtomicU64>,
    pub threats_detected: Arc<AtomicU64>,
    pub config_json: Arc<std::sync::RwLock<String>>,
    pub bloom_size: Arc<AtomicU64>,
    pub cache_entries: Arc<AtomicU64>,
    pub store: std::sync::RwLock<Option<Arc<dyn StoreQuery>>>,
    pub dlp: std::sync::RwLock<Option<Arc<dyn DlpQuery>>>,
}

impl DaemonState {
    pub fn new() -> Self {
        Self {
            events_processed: Arc::new(AtomicU64::new(0)),
            threats_detected: Arc::new(AtomicU64::new(0)),
            config_json: Arc::new(std::sync::RwLock::new("{}".to_string())),
            bloom_size: Arc::new(AtomicU64::new(0)),
            cache_entries: Arc::new(AtomicU64::new(0)),
            store: std::sync::RwLock::new(None),
            dlp: std::sync::RwLock::new(None),
        }
    }
}

impl Default for DaemonState {
    fn default() -> Self {
        Self::new()
    }
}

async fn read_length_prefixed(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_length_prefixed(stream: &mut UnixStream, data: &[u8]) -> Result<()> {
    let len = (data.len() as u32).to_le_bytes();
    stream.write_all(&len).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

pub struct IpcServer {
    socket_path: PathBuf,
    state: Arc<DaemonState>,
}

impl IpcServer {
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            state: Arc::new(DaemonState::new()),
        }
    }

    pub fn with_state(socket_path: PathBuf, state: Arc<DaemonState>) -> Self {
        Self {
            socket_path,
            state,
        }
    }

    pub fn state(&self) -> &Arc<DaemonState> {
        &self.state
    }

    pub async fn start(&self) -> Result<()> {
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;

        // Allow non-root users (CLI, menubar) to connect
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o666);
            std::fs::set_permissions(&self.socket_path, perms)?;
        }

        info!("IPC server listening on {:?}", self.socket_path);

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let state = Arc::clone(&self.state);
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_client(stream, &state).await {
                            error!("Client handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                }
            }
        }
    }

    async fn handle_client(mut stream: UnixStream, state: &DaemonState) -> Result<()> {
        let raw = read_length_prefixed(&mut stream).await?;
        let msg: ClientMessage = serde_json::from_slice(&raw)?;

        let response = match msg {
            ClientMessage::GetStatus => DaemonMessage::Status {
                running: true,
                events_processed: state.events_processed.load(Ordering::Relaxed),
                active_threats: state.threats_detected.load(Ordering::Relaxed) as u32,
            },
            ClientMessage::QueryEvents { limit, .. } => {
                let events = state
                    .store
                    .read()
                    .ok()
                    .and_then(|guard| guard.as_ref().map(|s| s.recent_events(limit)))
                    .unwrap_or_default();
                DaemonMessage::Events(events)
            }
            ClientMessage::QueryThreats { .. } => {
                let threats = state
                    .store
                    .read()
                    .ok()
                    .and_then(|guard| guard.as_ref().map(|s| s.threats_above_clean(100)))
                    .unwrap_or_default();
                DaemonMessage::Threats(threats)
            }
            ClientMessage::GetConfig => {
                let config = state
                    .config_json
                    .read()
                    .map(|guard| guard.clone())
                    .unwrap_or_else(|_| "{}".to_string());
                DaemonMessage::Config(config)
            }
            ClientMessage::UpdateConfig { .. } => DaemonMessage::Ok,
            ClientMessage::TriggerScan { path } => {
                info!("Scan requested for: {}", path);
                DaemonMessage::Ok
            }
            ClientMessage::RefreshFeeds => {
                info!("Feed refresh requested");
                DaemonMessage::Ok
            }
            ClientMessage::VulnUpdate => {
                info!("Vulnerability database update requested");
                DaemonMessage::Ok
            }
            ClientMessage::IntelStatus => DaemonMessage::IntelStatus {
                bloom_size: state.bloom_size.load(Ordering::Relaxed) as usize,
                cache_entries: state.cache_entries.load(Ordering::Relaxed),
                feeds_last_updated: None,
            },
            ClientMessage::DlpCheckFlow {
                pid,
                remote_hostname,
                remote_ip,
                remote_port,
            } => {
                let verdict = state
                    .dlp
                    .read()
                    .ok()
                    .and_then(|guard| {
                        guard.as_ref().map(|dlp| {
                            dlp.check_flow(pid, &remote_hostname, &remote_ip, remote_port)
                        })
                    })
                    .unwrap_or(DlpFlowVerdict {
                        allow: true,
                        reason: None,
                    });
                DaemonMessage::DlpVerdict {
                    allow: verdict.allow,
                    reason: verdict.reason,
                }
            }
            ClientMessage::DlpStatus => {
                let status = state
                    .dlp
                    .read()
                    .ok()
                    .and_then(|guard| guard.as_ref().map(|dlp| dlp.status()));
                match status {
                    Some(s) => DaemonMessage::DlpStatus {
                        enabled: s.enabled,
                        tracked_pids: s.tracked_pids,
                        tracked_accesses: s.tracked_accesses,
                        watched_domains: s.watched_domains,
                    },
                    None => DaemonMessage::DlpStatus {
                        enabled: false,
                        tracked_pids: 0,
                        tracked_accesses: 0,
                        watched_domains: 0,
                    },
                }
            }
        };

        let response_bytes = serde_json::to_vec(&response)?;
        write_length_prefixed(&mut stream, &response_bytes).await?;
        Ok(())
    }
}

pub struct IpcClient {
    stream: UnixStream,
}

impl IpcClient {
    pub async fn connect(socket_path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(socket_path).await?;
        Ok(Self { stream })
    }

    pub async fn send(&mut self, msg: &ClientMessage) -> Result<DaemonMessage> {
        let request_bytes = serde_json::to_vec(msg)?;
        write_length_prefixed(&mut self.stream, &request_bytes).await?;
        let response_bytes = read_length_prefixed(&mut self.stream).await?;
        let response: DaemonMessage = serde_json::from_slice(&response_bytes)?;
        Ok(response)
    }
}

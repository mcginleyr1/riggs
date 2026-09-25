use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

/// Default max IPC frame size before allocating (untrusted length prefix).
const DEFAULT_MAX_MSG_LEN: usize = 8 * 1024 * 1024;

/// Default cap on concurrent client handlers so a flood can't exhaust the daemon.
/// Applied separately to owner and non-owner peers.
const DEFAULT_MAX_CONCURRENT_CLIENTS: usize = 32;

/// Deadline for reading a request and writing its response. A peer that
/// connects and stalls would otherwise pin a handler slot forever.
const CLIENT_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

use riggs_types::events::RiggsEvent;
use riggs_types::verdict::MergedVerdict;

use crate::messages::{ClientMessage, DaemonMessage, QuarantinedFile};

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

pub struct EgressFlowVerdict {
    pub allow: bool,
    pub would_block: bool,
    pub reason: Option<String>,
    pub mode: String,
}

pub struct EgressQueryStatus {
    pub mode: String,
    pub allow_domains: usize,
    pub process_rules: usize,
}

pub trait EgressQuery: Send + Sync {
    fn check(
        &self,
        pid: u32,
        process_path: &str,
        hostname: &str,
        remote_ip: &str,
        remote_port: u16,
    ) -> EgressFlowVerdict;

    fn status(&self) -> EgressQueryStatus;

    /// Local management: add/remove a global allow domain, or set the mode.
    /// Persist the change and reload the live policy. Returns an error string.
    fn allow_domain(&self, domain: &str) -> std::result::Result<(), String>;
    fn deny_domain(&self, domain: &str) -> std::result::Result<(), String>;
    fn set_mode(&self, mode: &str) -> std::result::Result<(), String>;
}

/// Privileged daemon operations requested from the CLI. Each returns a
/// human-readable outcome. Long-running work must be spawned, not awaited:
/// the IPC request has a short deadline.
pub trait ControlOps: Send + Sync {
    fn update_config(&self, key: &str, value: &str) -> std::result::Result<String, String>;
    fn trigger_scan(&self, path: &str) -> std::result::Result<String, String>;
    fn refresh_feeds(&self) -> std::result::Result<String, String>;
    fn vuln_update(&self) -> std::result::Result<String, String>;
    fn quarantine_list(&self) -> std::result::Result<Vec<QuarantinedFile>, String>;
    fn quarantine_restore(&self, id: &str) -> std::result::Result<String, String>;
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
    pub egress: std::sync::RwLock<Option<Arc<dyn EgressQuery>>>,
    pub control: std::sync::RwLock<Option<Arc<dyn ControlOps>>>,
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
            egress: std::sync::RwLock::new(None),
            control: std::sync::RwLock::new(None),
        }
    }
}

impl Default for DaemonState {
    fn default() -> Self {
        Self::new()
    }
}

async fn read_length_prefixed(stream: &mut UnixStream, max_len: usize) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > max_len {
        return Err(IpcError::Other(format!(
            "message length {len} exceeds maximum {max_len}"
        )));
    }
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

/// Apply a local egress management op and map the result to a DaemonMessage.
fn egress_mutate(
    state: &DaemonState,
    op: impl FnOnce(&dyn EgressQuery) -> std::result::Result<(), String>,
) -> DaemonMessage {
    let guard = match state.egress.read() {
        Ok(guard) => guard,
        Err(_) => return DaemonMessage::Error("egress state unavailable".into()),
    };
    match guard.as_ref() {
        Some(egress) => match op(egress.as_ref()) {
            Ok(()) => DaemonMessage::Ok,
            Err(e) => DaemonMessage::Error(e),
        },
        None => DaemonMessage::Error("egress control not initialized".into()),
    }
}

fn control(
    state: &DaemonState,
    op: impl FnOnce(&dyn ControlOps) -> std::result::Result<String, String>,
) -> DaemonMessage {
    let guard = match state.control.read() {
        Ok(guard) => guard,
        Err(_) => return DaemonMessage::Error("daemon control unavailable".into()),
    };
    match guard.as_ref() {
        Some(control) => match op(control.as_ref()) {
            Ok(outcome) => DaemonMessage::Done(outcome),
            Err(e) => DaemonMessage::Error(e),
        },
        None => DaemonMessage::Error("daemon control not initialized".into()),
    }
}

/// True when the connecting peer runs as the same user as the daemon.
fn peer_is_owner(stream: &UnixStream) -> bool {
    stream
        .peer_cred()
        .is_ok_and(|cred| cred.uid() == unsafe { libc::geteuid() })
}

pub struct IpcServer {
    socket_path: PathBuf,
    state: Arc<DaemonState>,
    max_message_bytes: usize,
    max_connections: usize,
}

impl IpcServer {
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            state: Arc::new(DaemonState::new()),
            max_message_bytes: DEFAULT_MAX_MSG_LEN,
            max_connections: DEFAULT_MAX_CONCURRENT_CLIENTS,
        }
    }

    pub fn with_state(socket_path: PathBuf, state: Arc<DaemonState>) -> Self {
        Self {
            socket_path,
            state,
            max_message_bytes: DEFAULT_MAX_MSG_LEN,
            max_connections: DEFAULT_MAX_CONCURRENT_CLIENTS,
        }
    }

    /// Override the IPC frame-size and concurrency caps (operator-configurable).
    pub fn with_limits(mut self, max_message_bytes: usize, max_connections: usize) -> Self {
        self.max_message_bytes = max_message_bytes.max(1024);
        self.max_connections = max_connections.max(1);
        self
    }

    pub fn state(&self) -> &Arc<DaemonState> {
        &self.state
    }

    pub async fn start(&self) -> Result<()> {
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;

        // Non-root users (CLI, menubar) may connect for read-only status/query
        // commands; state-changing commands are gated per-connection by peer uid
        // in handle_client, and secrets are stripped from GetConfig responses.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o666);
            std::fs::set_permissions(&self.socket_path, perms)?;
        }

        info!("IPC server listening on {:?}", self.socket_path);

        // Separate pools so unprivileged peers (the socket is 0666) can never
        // starve the root NEFilter extension, which fails open on timeout.
        let owner_limiter = Arc::new(Semaphore::new(self.max_connections));
        let other_limiter = Arc::new(Semaphore::new(self.max_connections));
        let max_message_bytes = self.max_message_bytes;

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let is_owner = peer_is_owner(&stream);
                    let limiter = if is_owner {
                        &owner_limiter
                    } else {
                        &other_limiter
                    };
                    let permit = match Arc::clone(limiter).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            warn!(
                                is_owner,
                                "IPC connection limit reached, dropping connection"
                            );
                            continue;
                        }
                    };
                    let state = Arc::clone(&self.state);
                    tokio::spawn(async move {
                        let _permit = permit; // released when the handler finishes
                        let handled = tokio::time::timeout(
                            CLIENT_IO_TIMEOUT,
                            Self::handle_client(stream, &state, max_message_bytes, is_owner),
                        )
                        .await;
                        match handled {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => error!("Client handler error: {}", e),
                            Err(_) => warn!(is_owner, "IPC client timed out"),
                        }
                    });
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                }
            }
        }
    }

    async fn handle_client(
        mut stream: UnixStream,
        state: &DaemonState,
        max_message_bytes: usize,
        is_owner: bool,
    ) -> Result<()> {
        let raw = read_length_prefixed(&mut stream, max_message_bytes).await?;
        let msg: ClientMessage = serde_json::from_slice(&raw)?;

        // State-changing commands require the peer to run as the daemon owner.
        // Read-only status/query/DLP commands stay open to the CLI and menubar.
        let needs_privilege = matches!(
            msg,
            ClientMessage::UpdateConfig { .. }
                | ClientMessage::TriggerScan { .. }
                | ClientMessage::RefreshFeeds
                | ClientMessage::VulnUpdate
                | ClientMessage::QuarantineRestore { .. }
                | ClientMessage::EgressAllow { .. }
                | ClientMessage::EgressDeny { .. }
                | ClientMessage::EgressSetMode { .. }
        );
        if needs_privilege && !is_owner {
            let denied = DaemonMessage::Error(
                "permission denied: command requires daemon-owner privilege".into(),
            );
            let bytes = serde_json::to_vec(&denied)?;
            write_length_prefixed(&mut stream, &bytes).await?;
            return Ok(());
        }

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
            ClientMessage::UpdateConfig { key, value } => {
                control(state, |c| c.update_config(&key, &value))
            }
            ClientMessage::TriggerScan { path } => control(state, |c| c.trigger_scan(&path)),
            ClientMessage::RefreshFeeds => control(state, |c| c.refresh_feeds()),
            ClientMessage::VulnUpdate => control(state, |c| c.vuln_update()),
            ClientMessage::QuarantineList => match state.control.read() {
                Ok(guard) => match guard.as_ref().map(|c| c.quarantine_list()) {
                    Some(Ok(files)) => DaemonMessage::Quarantine(files),
                    Some(Err(e)) => DaemonMessage::Error(e),
                    None => DaemonMessage::Error("daemon control not initialized".into()),
                },
                Err(_) => DaemonMessage::Error("daemon control unavailable".into()),
            },
            ClientMessage::QuarantineRestore { id } => {
                control(state, |c| c.quarantine_restore(&id))
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
            ClientMessage::EgressCheckFlow {
                pid,
                process_path,
                remote_hostname,
                remote_ip,
                remote_port,
            } => {
                let verdict = state
                    .egress
                    .read()
                    .ok()
                    .and_then(|guard| {
                        guard.as_ref().map(|eg| {
                            eg.check(
                                pid,
                                &process_path,
                                &remote_hostname,
                                &remote_ip,
                                remote_port,
                            )
                        })
                    })
                    // No policy loaded -> allow (fail-open until egress is enabled).
                    .unwrap_or(EgressFlowVerdict {
                        allow: true,
                        would_block: false,
                        reason: None,
                        mode: "off".into(),
                    });
                DaemonMessage::EgressVerdict {
                    allow: verdict.allow,
                    would_block: verdict.would_block,
                    reason: verdict.reason,
                    mode: verdict.mode,
                }
            }
            ClientMessage::EgressStatus => {
                let status = state
                    .egress
                    .read()
                    .ok()
                    .and_then(|guard| guard.as_ref().map(|eg| eg.status()));
                match status {
                    Some(s) => DaemonMessage::EgressStatus {
                        mode: s.mode,
                        allow_domains: s.allow_domains,
                        process_rules: s.process_rules,
                    },
                    None => DaemonMessage::EgressStatus {
                        mode: "off".into(),
                        allow_domains: 0,
                        process_rules: 0,
                    },
                }
            }
            ClientMessage::EgressAllow { domain } => {
                egress_mutate(state, |eg| eg.allow_domain(&domain))
            }
            ClientMessage::EgressDeny { domain } => {
                egress_mutate(state, |eg| eg.deny_domain(&domain))
            }
            ClientMessage::EgressSetMode { mode } => egress_mutate(state, |eg| eg.set_mode(&mode)),
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
        let response_bytes = read_length_prefixed(&mut self.stream, DEFAULT_MAX_MSG_LEN).await?;
        let response: DaemonMessage = serde_json::from_slice(&response_bytes)?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn start_server(name: &str, max_connections: usize) -> PathBuf {
        start_server_with(Arc::new(DaemonState::new()), name, max_connections).await
    }

    async fn start_server_with(
        state: Arc<DaemonState>,
        name: &str,
        max_connections: usize,
    ) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("riggs-ipc-{name}-{}.sock", std::process::id()));
        let server = IpcServer::with_state(path.clone(), state)
            .with_limits(DEFAULT_MAX_MSG_LEN, max_connections);
        tokio::spawn(async move { server.start().await });
        while !path.exists() {
            tokio::task::yield_now().await;
        }
        path
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_client_releases_its_slot() {
        let path = start_server("stall", 1).await;
        let _stalled = UnixStream::connect(&path).await.unwrap();
        tokio::time::sleep(CLIENT_IO_TIMEOUT * 2).await;

        let mut client = IpcClient::connect(&path).await.unwrap();
        let response = client.send(&ClientMessage::GetStatus).await.unwrap();
        assert!(matches!(response, DaemonMessage::Status { .. }));
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn control_commands_route_to_control_ops() {
        struct StubControl;
        impl ControlOps for StubControl {
            fn update_config(&self, key: &str, value: &str) -> std::result::Result<String, String> {
                Ok(format!("{key}={value}"))
            }
            fn trigger_scan(&self, path: &str) -> std::result::Result<String, String> {
                Err(format!("{path} missing"))
            }
            fn refresh_feeds(&self) -> std::result::Result<String, String> {
                Ok("refreshing".into())
            }
            fn vuln_update(&self) -> std::result::Result<String, String> {
                Ok("scanning".into())
            }
            fn quarantine_list(&self) -> std::result::Result<Vec<QuarantinedFile>, String> {
                Ok(vec![QuarantinedFile {
                    id: "q1".into(),
                    original_path: "/tmp/evil".into(),
                    quarantined_at: "now".into(),
                    file_size: 3,
                    sha256: None,
                }])
            }
            fn quarantine_restore(&self, id: &str) -> std::result::Result<String, String> {
                Ok(format!("restored {id}"))
            }
        }

        let state = Arc::new(DaemonState::new());
        let path = start_server_with(Arc::clone(&state), "control", 4).await;
        let send = |msg: ClientMessage| {
            let path = path.clone();
            async move {
                let mut client = IpcClient::connect(&path).await.unwrap();
                client.send(&msg).await.unwrap()
            }
        };

        let before_init = send(ClientMessage::RefreshFeeds).await;
        *state.control.write().unwrap() = Some(Arc::new(StubControl));
        let config = send(ClientMessage::UpdateConfig {
            key: "engine.rules_enabled".into(),
            value: "false".into(),
        })
        .await;
        let scan = send(ClientMessage::TriggerScan {
            path: "/nope".into(),
        })
        .await;
        let listed = send(ClientMessage::QuarantineList).await;
        std::fs::remove_file(&path).unwrap();

        assert!(matches!(listed, DaemonMessage::Quarantine(files) if files[0].id == "q1"));

        assert!(matches!(before_init, DaemonMessage::Error(_)));
        assert!(matches!(config, DaemonMessage::Done(s) if s == "engine.rules_enabled=false"));
        assert!(matches!(scan, DaemonMessage::Error(e) if e == "/nope missing"));
    }
}

use std::path::{Path, PathBuf};

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, error};

use crate::messages::{ClientMessage, DaemonMessage};

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
}

impl IpcServer {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    pub async fn start(&self) -> Result<()> {
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        info!("IPC server listening on {:?}", self.socket_path);

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_client(stream).await {
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

    async fn handle_client(mut stream: UnixStream) -> Result<()> {
        let raw = read_length_prefixed(&mut stream).await?;
        let msg: ClientMessage = serde_json::from_slice(&raw)?;

        let response = match msg {
            ClientMessage::GetStatus => DaemonMessage::Status {
                running: true,
                events_processed: 0,
                active_threats: 0,
            },
            ClientMessage::QueryEvents { .. } => DaemonMessage::Events(Vec::new()),
            ClientMessage::QueryThreats { .. } => DaemonMessage::Threats(Vec::new()),
            ClientMessage::GetConfig => DaemonMessage::Config(String::from("{}")),
            ClientMessage::UpdateConfig { .. } => DaemonMessage::Ok,
            ClientMessage::TriggerScan { path } => {
                info!("Scan requested for: {}", path);
                DaemonMessage::Ok
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

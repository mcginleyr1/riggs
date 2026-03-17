use tonic::transport::Channel;
use tracing::info;

use crate::proto::agent_service_client::AgentServiceClient;

#[derive(Clone, Debug)]
pub struct ConsoleConfig {
    /// gRPC endpoint, e.g. "http://murtaugh:4001"
    pub endpoint: String,
    pub enrollment_token: String,
    pub heartbeat_interval_secs: u64,
}

#[derive(Clone)]
pub struct ConsoleClient {
    pub config: ConsoleConfig,
    pub agent_id: Option<String>,
    channel: Option<Channel>,
}

impl ConsoleClient {
    pub fn new(config: ConsoleConfig) -> Self {
        Self {
            config,
            agent_id: None,
            channel: None,
        }
    }

    pub async fn connect(&mut self) -> Result<(), tonic::transport::Error> {
        let channel = tonic::transport::Channel::from_shared(self.config.endpoint.clone())
            .expect("invalid console endpoint URI")
            .connect()
            .await?;
        self.channel = Some(channel);
        info!(endpoint = %self.config.endpoint, "connected to Murtaugh console");
        Ok(())
    }

    pub fn grpc_client(&self) -> Option<AgentServiceClient<Channel>> {
        self.channel
            .as_ref()
            .map(|ch| AgentServiceClient::new(ch.clone()))
    }
}

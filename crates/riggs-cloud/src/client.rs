use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tracing::info;

use riggs_types::config::CloudTlsConfig;

use crate::proto::agent_service_client::AgentServiceClient;

#[derive(Debug, thiserror::Error)]
pub enum ConsoleError {
    #[error("invalid console endpoint: {0}")]
    Config(String),

    #[error("refusing to send credentials over an insecure channel: {0}")]
    Insecure(String),

    #[error("failed to read TLS material: {0}")]
    Tls(String),

    #[error("transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
}

#[derive(Clone, Debug)]
pub struct ConsoleConfig {
    /// gRPC endpoint, e.g. "https://murtaugh:4001"
    pub endpoint: String,
    pub enrollment_token: String,
    pub heartbeat_interval_secs: u64,
    pub tls: CloudTlsConfig,
    /// When true, refuse to send credentials over a non-https endpoint.
    pub require_tls: bool,
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

    pub async fn connect(&mut self) -> Result<(), ConsoleError> {
        let endpoint = &self.config.endpoint;
        let mut builder = Channel::from_shared(endpoint.clone())
            .map_err(|e| ConsoleError::Config(format!("{endpoint}: {e}")))?;

        if endpoint.starts_with("https://") {
            builder = builder.tls_config(self.build_tls_config()?)?;
        } else if self.config.require_tls && !self.config.enrollment_token.is_empty() {
            // With require_tls (the default), the enrollment token is a bearer
            // credential that must not travel in the clear.
            return Err(ConsoleError::Insecure(format!(
                "console endpoint {endpoint} is not https and comms.require_tls is set; use an https:// endpoint with [comms.tls] certificates, or set comms.require_tls = false to allow cleartext"
            )));
        } else if !endpoint.starts_with("https://") {
            tracing::warn!(
                endpoint = %endpoint,
                "connecting to console over cleartext (comms.require_tls = false); credentials and telemetry are unencrypted"
            );
        }

        let channel = builder.connect().await?;
        self.channel = Some(channel);
        info!(endpoint = %self.config.endpoint, "connected to Murtaugh console");
        Ok(())
    }

    /// Build the mTLS config from the configured PEM paths (bring-your-own-PKI).
    fn build_tls_config(&self) -> Result<ClientTlsConfig, ConsoleError> {
        let tls = &self.config.tls;

        let ca_path = tls.ca_cert_path.as_ref().ok_or_else(|| {
            ConsoleError::Tls(
                "comms.tls.ca_cert_path is required for an https console endpoint".into(),
            )
        })?;
        let ca_pem = std::fs::read(ca_path)
            .map_err(|e| ConsoleError::Tls(format!("reading ca_cert_path {ca_path}: {e}")))?;

        let mut config = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca_pem));

        // Present a client certificate for mutual TLS when both cert and key are set.
        match (&tls.client_cert_path, &tls.client_key_path) {
            (Some(cert_path), Some(key_path)) => {
                let cert = std::fs::read(cert_path).map_err(|e| {
                    ConsoleError::Tls(format!("reading client_cert_path {cert_path}: {e}"))
                })?;
                let key = std::fs::read(key_path).map_err(|e| {
                    ConsoleError::Tls(format!("reading client_key_path {key_path}: {e}"))
                })?;
                config = config.identity(Identity::from_pem(cert, key));
            }
            (None, None) => {}
            _ => {
                return Err(ConsoleError::Tls(
                    "comms.tls.client_cert_path and client_key_path must be set together".into(),
                ));
            }
        }

        if let Some(domain) = &tls.domain_name {
            config = config.domain_name(domain.clone());
        }

        Ok(config)
    }

    pub fn grpc_client(&self) -> Option<AgentServiceClient<Channel>> {
        self.channel
            .as_ref()
            .map(|ch| AgentServiceClient::new(ch.clone()))
    }
}

use sysinfo::System;
use tracing::info;

use crate::client::ConsoleClient;
use crate::proto::EnrollRequest;

pub async fn enroll(
    client: &mut ConsoleClient,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let hostname = System::host_name().unwrap_or_else(|| "unknown".into());
    let os_name = System::name().unwrap_or_else(|| "Linux".into());
    let os_version = System::os_version().unwrap_or_else(|| "unknown".into());

    let request = EnrollRequest {
        hostname: hostname.clone(),
        os: os_name,
        os_version,
        arch: std::env::consts::ARCH.to_string(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        ip_address: local_ip(),
        mac_address: String::new(),
        enrollment_token: client.config.enrollment_token.clone(),
    };

    let mut grpc = client.grpc_client().ok_or("not connected to console")?;

    let response = grpc.enroll(request).await?.into_inner();
    info!(
        agent_id = %response.agent_id,
        hostname = %hostname,
        "enrolled with Murtaugh console"
    );
    Ok(response.agent_id)
}

fn local_ip() -> String {
    use std::net::UdpSocket;
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| "0.0.0.0".into())
}

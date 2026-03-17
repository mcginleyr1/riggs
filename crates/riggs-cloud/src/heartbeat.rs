use sysinfo::System;
use tokio::time::{interval, Duration};
use tokio_stream::iter as stream_iter;
use tracing::{debug, warn};

use crate::client::ConsoleClient;
use crate::proto::{AgentHealth, HeartbeatRequest};

pub async fn run_heartbeat_loop(
    client: ConsoleClient,
    agent_id: String,
    interval_secs: u64,
    events_processed: std::sync::Arc<std::sync::atomic::AtomicU64>,
    threats_detected: std::sync::Arc<std::sync::atomic::AtomicU64>,
) {
    let mut tick = interval(Duration::from_secs(interval_secs));

    loop {
        tick.tick().await;

        let Some(mut grpc) = client.grpc_client() else {
            warn!("no gRPC channel for heartbeat, skipping");
            continue;
        };

        let health = build_health(&events_processed, &threats_detected);
        let request = HeartbeatRequest {
            agent_id: agent_id.clone(),
            timestamp: None,
            health: Some(health),
        };

        let stream = stream_iter(vec![request]);
        match grpc.heartbeat(stream).await {
            Ok(_) => debug!("heartbeat sent to console"),
            Err(e) => warn!(error = %e, "heartbeat failed"),
        }
    }
}

fn build_health(
    events: &std::sync::Arc<std::sync::atomic::AtomicU64>,
    threats: &std::sync::Arc<std::sync::atomic::AtomicU64>,
) -> AgentHealth {
    use std::sync::atomic::Ordering;

    AgentHealth {
        events_processed: events.load(Ordering::Relaxed),
        threats_detected: threats.load(Ordering::Relaxed),
        dlp_blocks: 0,
        sensor_healthy: true,
        pipeline_latency_us: 0,
        store_size_bytes: 0,
        uptime_secs: System::uptime(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        config_version: 1,
    }
}

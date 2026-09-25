use std::path::Path;
use std::time::Instant;

use riggs_comms::{ClientMessage, DaemonMessage, IpcClient};
use tracing::{info, warn};

use crate::status::SharedStatus;

fn socket_path() -> String {
    std::env::var("RIGGS_SOCKET").unwrap_or_else(|_| "/var/run/riggs.sock".to_string())
}
const DEFAULT_POLL_INTERVAL_SECS: u64 = 3;

/// Status poll cadence, overridable via RIGGS_MENUBAR_POLL_SECS.
fn poll_interval_secs() -> u64 {
    std::env::var("RIGGS_MENUBAR_POLL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&s| s > 0)
        .unwrap_or(DEFAULT_POLL_INTERVAL_SECS)
}

pub fn spawn_poller(status: SharedStatus) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime for poller");

        rt.block_on(async move {
            poll_loop(status).await;
        });
    });
}

async fn poll_loop(status: SharedStatus) {
    loop {
        match poll_once(&status).await {
            Ok(()) => {}
            Err(e) => {
                warn!("poller error: {e}");
                if let Ok(mut s) = status.lock() {
                    s.connected = false;
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(poll_interval_secs())).await;
    }
}

async fn poll_once(status: &SharedStatus) -> Result<(), Box<dyn std::error::Error>> {
    let sock = socket_path();
    let socket_path = Path::new(&sock);
    let mut client = IpcClient::connect(socket_path).await?;

    // Query daemon status
    let response = client.send(&ClientMessage::GetStatus).await?;
    match response {
        DaemonMessage::Status {
            running,
            events_processed,
            active_threats,
        } => {
            let mut s = status.lock().map_err(|e| format!("lock poisoned: {e}"))?;
            s.connected = true;
            s.running = running;
            s.events_processed = events_processed;
            s.active_threats = active_threats;
            s.last_update = Some(Instant::now());
        }
        DaemonMessage::Error(e) => {
            warn!("daemon returned error: {e}");
        }
        _ => {}
    }

    // Query intel status (separate connection since IPC is one-shot)
    if let Ok(mut client2) = IpcClient::connect(socket_path).await {
        if let Ok(DaemonMessage::IntelStatus {
            bloom_size,
            cache_entries,
            feeds_last_updated,
        }) = client2.send(&ClientMessage::IntelStatus).await
        {
            let mut s = status.lock().map_err(|e| format!("lock poisoned: {e}"))?;
            s.bloom_size = bloom_size;
            s.cache_entries = cache_entries;
            s.feeds_last_updated = feeds_last_updated;
        }
    }

    Ok(())
}

pub fn trigger_scan_background(path: String) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime for scan");

        rt.block_on(async move {
            let sock = socket_path();
            let socket_path = Path::new(&sock);
            match IpcClient::connect(socket_path).await {
                Ok(mut client) => match client.send(&ClientMessage::TriggerScan { path }).await {
                    Ok(DaemonMessage::Ok) => info!("scan triggered successfully"),
                    Ok(DaemonMessage::Error(e)) => warn!("scan error: {e}"),
                    Ok(_) => warn!("unexpected scan response"),
                    Err(e) => warn!("failed to send scan request: {e}"),
                },
                Err(e) => warn!("failed to connect for scan: {e}"),
            }
        });
    });
}

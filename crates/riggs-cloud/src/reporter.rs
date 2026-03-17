use tokio::sync::mpsc;
use tracing::{info, warn};

use riggs_types::verdict::{MergedVerdict, ThreatLevel};

use crate::client::ConsoleClient;
use crate::proto::{ThreatReport, VerdictDetail};

pub async fn run_threat_reporter(
    client: ConsoleClient,
    agent_id: String,
    mut verdict_rx: mpsc::Receiver<MergedVerdict>,
) {
    while let Some(verdict) = verdict_rx.recv().await {
        if verdict.final_threat_level == ThreatLevel::Clean {
            continue;
        }

        let Some(mut grpc) = client.grpc_client() else {
            warn!("no gRPC channel, dropping threat report");
            continue;
        };

        let threat_level = match verdict.final_threat_level {
            ThreatLevel::Suspicious => "suspicious",
            ThreatLevel::Malicious => "malicious",
            ThreatLevel::Clean => continue,
        };

        let verdicts: Vec<VerdictDetail> = verdict
            .verdicts
            .iter()
            .map(|v| VerdictDetail {
                source: v.source.to_string(),
                threat_level: format!("{}", v.threat_level).to_lowercase(),
                confidence: v.confidence,
                description: v.description.clone(),
            })
            .collect();

        let report = ThreatReport {
            agent_id: agent_id.clone(),
            event_id: verdict.event_id.to_string(),
            storyline_id: verdict.storyline_id.to_string(),
            threat_level: threat_level.into(),
            final_score: verdict
                .verdicts
                .iter()
                .map(|v| v.confidence)
                .fold(0.0f32, f32::max),
            timestamp: None,
            verdicts,
            process_name: String::new(),
            process_path: String::new(),
            summary: format!(
                "{} detected by {} engines",
                threat_level,
                verdict.verdicts.len()
            ),
        };

        match grpc.report_threat(report).await {
            Ok(resp) => {
                let ack = resp.into_inner();
                if ack.accepted {
                    info!(threat_id = %ack.threat_id, level = %threat_level, "threat reported to console");
                }
            }
            Err(e) => warn!(error = %e, "threat report failed"),
        }
    }
}

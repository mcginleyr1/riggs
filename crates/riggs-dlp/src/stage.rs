use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use tracing::debug;

use riggs_engine::{DetectionStage, StageVerdict};
use riggs_types::errors::RiggsError;
use riggs_types::events::{FileAction, NetworkDirection, RiggsEvent};
use riggs_types::verdict::{DetectionSource, ThreatLevel, Verdict};

use crate::correlator::{DlpCorrelator, FlowAction};
use crate::magic;

pub struct DlpStage {
    correlator: Arc<DlpCorrelator>,
}

impl DlpStage {
    pub fn new(correlator: Arc<DlpCorrelator>) -> Self {
        Self { correlator }
    }
}

#[async_trait]
impl DetectionStage for DlpStage {
    fn name(&self) -> &str {
        "dlp"
    }

    async fn analyze(&self, event: &RiggsEvent) -> Result<StageVerdict, RiggsError> {
        match event {
            RiggsEvent::File(fe) if fe.action == FileAction::Open => {
                let path = Path::new(&fe.path);

                // Try to read file header for magic byte detection.
                // Non-blocking, fail gracefully if file is gone or unreadable.
                let header = magic::read_file_header(path, 16).await;

                self.correlator.record_file_access(
                    fe.process_context.pid,
                    path,
                    &fe.process_context.name,
                    fe.timestamp,
                    header.as_deref(),
                );

                Ok(StageVerdict::Clean)
            }

            RiggsEvent::Network(ne) if ne.direction == NetworkDirection::Outbound => {
                let verdict =
                    self.correlator
                        .check_flow(ne.process_context.pid, &ne.dst_addr);

                match verdict.action {
                    FlowAction::Block => {
                        let description = format!(
                            "DLP block: {} upload to {} by {} (PID {})",
                            verdict.file_type.as_deref().unwrap_or("unknown"),
                            ne.dst_addr,
                            ne.process_context.name,
                            ne.process_context.pid,
                        );

                        debug!("{}", description);

                        Ok(StageVerdict::Malicious(Verdict {
                            event_id: ne.event_id.clone(),
                            threat_level: ThreatLevel::Malicious,
                            confidence: 0.95,
                            source: DetectionSource::Dlp,
                            description,
                            timestamp: Utc::now(),
                        }))
                    }
                    FlowAction::Alert => {
                        let description = format!(
                            "DLP alert: {} upload to {} by {} (PID {})",
                            verdict.file_type.as_deref().unwrap_or("unknown"),
                            ne.dst_addr,
                            ne.process_context.name,
                            ne.process_context.pid,
                        );

                        debug!("{}", description);

                        Ok(StageVerdict::Suspicious(Verdict {
                            event_id: ne.event_id.clone(),
                            threat_level: ThreatLevel::Suspicious,
                            confidence: 0.8,
                            source: DetectionSource::Dlp,
                            description,
                            timestamp: Utc::now(),
                        }))
                    }
                    FlowAction::Allow => Ok(StageVerdict::Clean),
                }
            }

            _ => Ok(StageVerdict::Clean),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{DlpAction, DlpPolicy, DomainPattern};
    use riggs_types::events::*;

    fn test_correlator() -> Arc<DlpCorrelator> {
        let policy = Arc::new(DlpPolicy {
            watched_domains: vec![DomainPattern {
                pattern: "claude.ai".into(),
                category: "ai-assistant".into(),
            }],
            blocked_file_types: vec![
                magic::SensitiveFileType::Pptx,
                magic::SensitiveFileType::Pdf,
            ],
            alert_file_types: vec![magic::SensitiveFileType::Csv],
            excluded_processes: vec![],
            action: DlpAction::Block,
        });
        Arc::new(DlpCorrelator::new(policy, 30))
    }

    fn test_process_context() -> ProcessContext {
        ProcessContext {
            pid: 1234,
            ppid: 1,
            name: "Google Chrome".into(),
            path: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into(),
            cmdline: "Google Chrome".into(),
            user: "testuser".into(),
            storyline_id: StorylineId::new(),
        }
    }

    #[tokio::test]
    async fn file_open_records_access() {
        let correlator = test_correlator();
        let stage = DlpStage::new(correlator.clone());

        let event = RiggsEvent::File(FileEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context: test_process_context(),
            action: FileAction::Open,
            path: "/Users/test/earnings.pptx".into(),
            hash: None,
        });

        let result = stage.analyze(&event).await.unwrap();
        assert!(matches!(result, StageVerdict::Clean));
        assert_eq!(correlator.total_tracked_accesses(), 1);
    }

    #[tokio::test]
    async fn network_after_file_open_blocks() {
        let correlator = test_correlator();
        let stage = DlpStage::new(correlator.clone());

        // Step 1: file open
        let file_event = RiggsEvent::File(FileEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context: test_process_context(),
            action: FileAction::Open,
            path: "/Users/test/earnings.pptx".into(),
            hash: None,
        });
        stage.analyze(&file_event).await.unwrap();

        // Step 2: network connection to watched domain
        let net_event = RiggsEvent::Network(NetworkEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context: test_process_context(),
            direction: NetworkDirection::Outbound,
            src_addr: "192.168.1.100".into(),
            dst_addr: "claude.ai".into(),
            src_port: 54321,
            dst_port: 443,
            protocol: "tcp".into(),
        });

        let result = stage.analyze(&net_event).await.unwrap();
        assert!(matches!(result, StageVerdict::Malicious(_)));
    }

    #[tokio::test]
    async fn network_without_file_open_allows() {
        let correlator = test_correlator();
        let stage = DlpStage::new(correlator);

        let net_event = RiggsEvent::Network(NetworkEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context: test_process_context(),
            direction: NetworkDirection::Outbound,
            src_addr: "192.168.1.100".into(),
            dst_addr: "claude.ai".into(),
            src_port: 54321,
            dst_port: 443,
            protocol: "tcp".into(),
        });

        let result = stage.analyze(&net_event).await.unwrap();
        assert!(matches!(result, StageVerdict::Clean));
    }

    #[tokio::test]
    async fn inbound_traffic_ignored() {
        let correlator = test_correlator();
        let stage = DlpStage::new(correlator);

        let net_event = RiggsEvent::Network(NetworkEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context: test_process_context(),
            direction: NetworkDirection::Inbound,
            src_addr: "claude.ai".into(),
            dst_addr: "192.168.1.100".into(),
            src_port: 443,
            dst_port: 54321,
            protocol: "tcp".into(),
        });

        let result = stage.analyze(&net_event).await.unwrap();
        assert!(matches!(result, StageVerdict::Clean));
    }
}

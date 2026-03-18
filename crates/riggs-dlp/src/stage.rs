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

                let header = magic::read_file_header(path, 16).await;

                self.correlator.record_file_access(
                    fe.process_context.pid,
                    fe.fd,
                    path,
                    &fe.process_context.name,
                    fe.timestamp,
                    header.as_deref(),
                );

                Ok(StageVerdict::Clean)
            }

            RiggsEvent::File(fe) if fe.action == FileAction::Close => {
                if let Some(fd) = fe.fd {
                    self.correlator.record_file_close(fe.process_context.pid, fd);
                }
                Ok(StageVerdict::Clean)
            }

            RiggsEvent::Network(ne) if ne.direction == NetworkDirection::Outbound => {
                let verdict = self.correlator.check_flow(ne.process_context.pid, &ne.dst_addr);

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
        Arc::new(DlpCorrelator::new(policy, 10))
    }

    fn process(pid: u32) -> ProcessContext {
        ProcessContext {
            pid,
            ppid: 1,
            name: "Google Chrome".into(),
            path: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into(),
            cmdline: "Google Chrome".into(),
            user: "testuser".into(),
            storyline_id: StorylineId::new(),
        }
    }

    fn file_open(pid: u32, path: &str, fd: Option<u32>) -> RiggsEvent {
        RiggsEvent::File(FileEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context: process(pid),
            action: FileAction::Open,
            path: path.into(),
            hash: None,
            fd,
        })
    }

    fn file_close(pid: u32, fd: u32) -> RiggsEvent {
        RiggsEvent::File(FileEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context: process(pid),
            action: FileAction::Close,
            path: String::new(),
            hash: None,
            fd: Some(fd),
        })
    }

    fn net_out(pid: u32, dst: &str) -> RiggsEvent {
        RiggsEvent::Network(NetworkEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context: process(pid),
            direction: NetworkDirection::Outbound,
            src_addr: "192.168.1.100".into(),
            dst_addr: dst.into(),
            src_port: 54321,
            dst_port: 443,
            protocol: "tcp".into(),
        })
    }

    #[tokio::test]
    async fn open_with_fd_blocks() {
        let c = test_correlator();
        let s = DlpStage::new(c);
        s.analyze(&file_open(1234, "/docs/earnings.pptx", Some(5))).await.unwrap();
        let r = s.analyze(&net_out(1234, "claude.ai")).await.unwrap();
        assert!(matches!(r, StageVerdict::Malicious(_)));
    }

    #[tokio::test]
    async fn close_removes_fd_but_fallback_catches() {
        let c = test_correlator();
        let s = DlpStage::new(c);
        s.analyze(&file_open(1234, "/docs/earnings.pptx", Some(5))).await.unwrap();
        s.analyze(&file_close(1234, 5)).await.unwrap();

        // Fallback window (10s) still active — should still block
        let r = s.analyze(&net_out(1234, "claude.ai")).await.unwrap();
        assert!(matches!(r, StageVerdict::Malicious(_)));
    }

    #[tokio::test]
    async fn no_fd_sensor_still_blocks() {
        let c = test_correlator();
        let s = DlpStage::new(c);
        s.analyze(&file_open(1234, "/docs/earnings.pptx", None)).await.unwrap();
        let r = s.analyze(&net_out(1234, "claude.ai")).await.unwrap();
        assert!(matches!(r, StageVerdict::Malicious(_)));
    }

    #[tokio::test]
    async fn network_without_file_open_allows() {
        let c = test_correlator();
        let s = DlpStage::new(c);
        let r = s.analyze(&net_out(1234, "claude.ai")).await.unwrap();
        assert!(matches!(r, StageVerdict::Clean));
    }

    #[tokio::test]
    async fn inbound_traffic_ignored() {
        let c = test_correlator();
        let s = DlpStage::new(c);
        s.analyze(&file_open(1234, "/docs/earnings.pptx", Some(3))).await.unwrap();

        let r = s.analyze(&RiggsEvent::Network(NetworkEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context: process(1234),
            direction: NetworkDirection::Inbound,
            src_addr: "claude.ai".into(),
            dst_addr: "192.168.1.100".into(),
            src_port: 443,
            dst_port: 54321,
            protocol: "tcp".into(),
        })).await.unwrap();

        assert!(matches!(r, StageVerdict::Clean));
    }
}

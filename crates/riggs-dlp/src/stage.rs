use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::mpsc;
use tracing::debug;

use riggs_engine::{DetectionStage, StageVerdict};
use riggs_types::errors::RiggsError;
use riggs_types::events::{FileAction, NetworkDirection, RiggsEvent};
use riggs_types::verdict::{DetectionSource, ThreatLevel, Verdict};

use crate::correlator::{DlpCorrelator, FlowAction};
use crate::magic;

/// Structured DLP detection event emitted when a block or alert fires.
/// Sent over a dedicated channel so the cloud reporter can forward it as
/// a `DlpEventReport` gRPC call with all fields intact.
#[derive(Debug, Clone)]
pub struct DlpDetection {
    pub action: FlowAction,
    pub pid: u32,
    pub process_name: String,
    pub file_path: String,
    pub file_type: String,
    pub domain: String,
    pub username: String,
}

pub struct DlpStage {
    correlator: Arc<DlpCorrelator>,
    /// When set, structured DLP detections are sent here for cloud reporting.
    detection_tx: Option<mpsc::Sender<DlpDetection>>,
}

impl DlpStage {
    pub fn new(correlator: Arc<DlpCorrelator>) -> Self {
        Self {
            correlator,
            detection_tx: None,
        }
    }

    /// Attach a channel to receive structured DLP detection events.
    pub fn with_detection_channel(mut self, tx: mpsc::Sender<DlpDetection>) -> Self {
        self.detection_tx = Some(tx);
        self
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
                    self.correlator
                        .record_file_close(fe.process_context.pid, fd);
                }
                Ok(StageVerdict::Clean)
            }

            RiggsEvent::Network(ne) if ne.direction == NetworkDirection::Outbound => {
                let verdict = self
                    .correlator
                    .check_flow(ne.process_context.pid, &ne.dst_addr);

                match verdict.action {
                    FlowAction::Block => {
                        let file_type = verdict.file_type.as_deref().unwrap_or("unknown");
                        let description = format!(
                            "DLP block: {} upload to {} by {} (PID {})",
                            file_type, ne.dst_addr, ne.process_context.name, ne.process_context.pid,
                        );
                        debug!("{}", description);

                        self.emit_detection(DlpDetection {
                            action: FlowAction::Block,
                            pid: ne.process_context.pid,
                            process_name: ne.process_context.name.clone(),
                            file_path: verdict.file_path.clone().unwrap_or_default(),
                            file_type: file_type.to_string(),
                            domain: ne.dst_addr.clone(),
                            username: ne.process_context.user.clone(),
                        });

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
                        let file_type = verdict.file_type.as_deref().unwrap_or("unknown");
                        let description = format!(
                            "DLP alert: {} upload to {} by {} (PID {})",
                            file_type, ne.dst_addr, ne.process_context.name, ne.process_context.pid,
                        );
                        debug!("{}", description);

                        self.emit_detection(DlpDetection {
                            action: FlowAction::Alert,
                            pid: ne.process_context.pid,
                            process_name: ne.process_context.name.clone(),
                            file_path: verdict.file_path.clone().unwrap_or_default(),
                            file_type: file_type.to_string(),
                            domain: ne.dst_addr.clone(),
                            username: ne.process_context.user.clone(),
                        });

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

impl DlpStage {
    fn emit_detection(&self, detection: DlpDetection) {
        if let Some(tx) = &self.detection_tx {
            // Non-blocking — drop if consumer is behind. DLP reporting is
            // best-effort; the verdict is already enforced at the network layer.
            let _ = tx.try_send(detection);
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
        let s = DlpStage::new(test_correlator());
        s.analyze(&file_open(1234, "/docs/earnings.pptx", Some(5)))
            .await
            .unwrap();
        let r = s.analyze(&net_out(1234, "claude.ai")).await.unwrap();
        assert!(matches!(r, StageVerdict::Malicious(_)));
    }

    #[tokio::test]
    async fn close_removes_fd_but_fallback_catches() {
        let s = DlpStage::new(test_correlator());
        s.analyze(&file_open(1234, "/docs/earnings.pptx", Some(5)))
            .await
            .unwrap();
        s.analyze(&file_close(1234, 5)).await.unwrap();
        let r = s.analyze(&net_out(1234, "claude.ai")).await.unwrap();
        assert!(matches!(r, StageVerdict::Malicious(_)));
    }

    #[tokio::test]
    async fn no_fd_sensor_still_blocks() {
        let s = DlpStage::new(test_correlator());
        s.analyze(&file_open(1234, "/docs/earnings.pptx", None))
            .await
            .unwrap();
        let r = s.analyze(&net_out(1234, "claude.ai")).await.unwrap();
        assert!(matches!(r, StageVerdict::Malicious(_)));
    }

    #[tokio::test]
    async fn detection_emitted_on_block() {
        let (tx, mut rx) = mpsc::channel(8);
        let s = DlpStage::new(test_correlator()).with_detection_channel(tx);

        s.analyze(&file_open(1234, "/docs/earnings.pptx", Some(5)))
            .await
            .unwrap();
        s.analyze(&net_out(1234, "claude.ai")).await.unwrap();

        let det = rx.try_recv().expect("detection should have been emitted");
        assert_eq!(det.action, FlowAction::Block);
        assert_eq!(det.domain, "claude.ai");
        assert_eq!(det.pid, 1234);
    }

    #[tokio::test]
    async fn no_detection_emitted_on_allow() {
        let (tx, mut rx) = mpsc::channel(8);
        let s = DlpStage::new(test_correlator()).with_detection_channel(tx);
        s.analyze(&net_out(1234, "claude.ai")).await.unwrap();
        assert!(rx.try_recv().is_err(), "no detection for clean flow");
    }

    #[tokio::test]
    async fn network_without_file_open_allows() {
        let s = DlpStage::new(test_correlator());
        let r = s.analyze(&net_out(1234, "claude.ai")).await.unwrap();
        assert!(matches!(r, StageVerdict::Clean));
    }

    #[tokio::test]
    async fn inbound_traffic_ignored() {
        let s = DlpStage::new(test_correlator());
        s.analyze(&file_open(1234, "/docs/earnings.pptx", Some(3)))
            .await
            .unwrap();

        let r = s
            .analyze(&RiggsEvent::Network(NetworkEvent {
                event_id: EventId::new(),
                timestamp: Utc::now(),
                process_context: process(1234),
                direction: NetworkDirection::Inbound,
                src_addr: "claude.ai".into(),
                dst_addr: "192.168.1.100".into(),
                src_port: 443,
                dst_port: 54321,
                protocol: "tcp".into(),
            }))
            .await
            .unwrap();

        assert!(matches!(r, StageVerdict::Clean));
    }
}

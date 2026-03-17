use riggs_types::events::RiggsEvent;

const THREAT_INTEL: &str = "threat-intel";
const STATIC_AI: &str = "static-ai";
const RULES: &str = "rules";
const BEHAVIORAL_AI: &str = "behavioral-ai";
const DLP: &str = "dlp";

pub struct EventRouter;

impl EventRouter {
    pub fn stages_for_event(event: &RiggsEvent) -> Vec<&'static str> {
        match event {
            RiggsEvent::File(_) => vec![THREAT_INTEL, STATIC_AI, RULES, BEHAVIORAL_AI, DLP],
            RiggsEvent::Process(_) => vec![RULES, BEHAVIORAL_AI],
            RiggsEvent::Network(_) => vec![THREAT_INTEL, BEHAVIORAL_AI, DLP],
            RiggsEvent::Dns(_) => vec![THREAT_INTEL, RULES, BEHAVIORAL_AI],
            RiggsEvent::Auth(_) => vec![RULES, BEHAVIORAL_AI],
            RiggsEvent::Kernel(_) => vec![RULES, BEHAVIORAL_AI],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use riggs_types::events::*;

    fn dummy_process_context() -> ProcessContext {
        ProcessContext {
            pid: 1,
            ppid: 0,
            name: "test".into(),
            path: "/usr/bin/test".into(),
            cmdline: "test".into(),
            user: "root".into(),
            storyline_id: StorylineId::new(),
        }
    }

    #[test]
    fn file_events_run_all_stages() {
        let event = RiggsEvent::File(FileEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context: dummy_process_context(),
            action: FileAction::Create,
            path: "/tmp/test".into(),
            hash: None,
        });
        assert_eq!(
            EventRouter::stages_for_event(&event),
            vec!["threat-intel", "static-ai", "rules", "behavioral-ai", "dlp"]
        );
    }

    #[test]
    fn process_events_skip_static_ai() {
        let event = RiggsEvent::Process(ProcessEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context: dummy_process_context(),
            action: ProcessAction::Exec,
            parent_context: None,
        });
        assert_eq!(
            EventRouter::stages_for_event(&event),
            vec!["rules", "behavioral-ai"]
        );
    }

    #[test]
    fn network_events_include_threat_intel() {
        let event = RiggsEvent::Network(NetworkEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context: dummy_process_context(),
            direction: NetworkDirection::Outbound,
            src_addr: "127.0.0.1".into(),
            dst_addr: "8.8.8.8".into(),
            src_port: 12345,
            dst_port: 443,
            protocol: "tcp".into(),
        });
        assert_eq!(
            EventRouter::stages_for_event(&event),
            vec!["threat-intel", "behavioral-ai", "dlp"]
        );
    }

    #[test]
    fn dns_events_include_threat_intel() {
        let event = RiggsEvent::Dns(DnsEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context: dummy_process_context(),
            query: "example.com".into(),
            response: "93.184.216.34".into(),
            query_type: "A".into(),
        });
        assert_eq!(
            EventRouter::stages_for_event(&event),
            vec!["threat-intel", "rules", "behavioral-ai"]
        );
    }
}

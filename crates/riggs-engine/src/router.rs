use riggs_types::events::RiggsEvent;

const STATIC_AI: &str = "static-ai";
const RULES: &str = "rules";
const BEHAVIORAL_AI: &str = "behavioral-ai";

pub struct EventRouter;

impl EventRouter {
    pub fn stages_for_event(event: &RiggsEvent) -> Vec<&'static str> {
        match event {
            RiggsEvent::File(_) => vec![STATIC_AI, RULES, BEHAVIORAL_AI],
            RiggsEvent::Process(_) => vec![RULES, BEHAVIORAL_AI],
            RiggsEvent::Network(_) => vec![BEHAVIORAL_AI],
            RiggsEvent::Dns(_) => vec![RULES, BEHAVIORAL_AI],
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
            vec!["static-ai", "rules", "behavioral-ai"]
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
    fn network_events_only_behavioral() {
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
            vec!["behavioral-ai"]
        );
    }

    #[test]
    fn dns_events_skip_static_ai() {
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
            vec!["rules", "behavioral-ai"]
        );
    }
}

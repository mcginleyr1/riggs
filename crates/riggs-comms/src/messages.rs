use serde::{Deserialize, Serialize};

use riggs_types::events::RiggsEvent;
use riggs_types::phishing::{PhishingRequest, PhishingResponse};
use riggs_types::verdict::MergedVerdict;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientMessage {
    GetStatus,
    QueryEvents {
        storyline_id: Option<String>,
        limit: usize,
    },
    QueryThreats {
        min_severity: String,
    },
    GetConfig,
    UpdateConfig {
        key: String,
        value: String,
    },
    TriggerScan {
        path: String,
    },
    RefreshFeeds,
    QuarantineList,
    QuarantineRestore {
        id: String,
    },
    VulnUpdate,
    IntelStatus,
    DlpCheckFlow {
        pid: u32,
        remote_hostname: String,
        remote_ip: String,
        remote_port: u16,
    },
    DlpStatus,
    EgressCheckFlow {
        pid: u32,
        process_path: String,
        remote_hostname: String,
        remote_ip: String,
        remote_port: u16,
    },
    EgressStatus,
    EgressAllow {
        domain: String,
    },
    EgressDeny {
        domain: String,
    },
    EgressSetMode {
        mode: String,
    },
    Phishing(PhishingRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonMessage {
    Status {
        running: bool,
        events_processed: u64,
        active_threats: u32,
    },
    Events(Vec<RiggsEvent>),
    Threats(Vec<MergedVerdict>),
    Quarantine(Vec<QuarantinedFile>),
    Config(String),
    IntelStatus {
        bloom_size: usize,
        cache_entries: u64,
        feeds_last_updated: Option<String>,
    },
    Ok,
    /// A privileged command succeeded; the text describes what happened.
    Done(String),
    Error(String),
    DlpVerdict {
        allow: bool,
        reason: Option<String>,
    },
    DlpStatus {
        enabled: bool,
        tracked_pids: usize,
        tracked_accesses: usize,
        watched_domains: usize,
    },
    EgressVerdict {
        allow: bool,
        would_block: bool,
        reason: Option<String>,
        mode: String,
    },
    EgressStatus {
        mode: String,
        allow_domains: usize,
        process_rules: usize,
    },
    Phishing(PhishingResponse),
}

/// A file held in the daemon's quarantine vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinedFile {
    pub id: String,
    pub original_path: String,
    pub quarantined_at: String,
    pub file_size: u64,
    pub sha256: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use riggs_types::phishing::{Evidence, Level, LoginObservation, PhishingVerdict, Reason};

    // The browser extension is written against these exact strings.

    #[test]
    fn phishing_requests_have_the_json_the_extension_sends() {
        let login_seen = PhishingRequest::LoginSeen(LoginObservation {
            host: "example.com".into(),
            evidence: Evidence::Typed,
        });
        let pinned = [
            (r#"{"Phishing":"Status"}"#, PhishingRequest::Status),
            (
                r#"{"Phishing":{"LoginSeen":{"host":"example.com","evidence":"typed"}}}"#,
                login_seen,
            ),
        ];
        for (json, request) in pinned {
            let message = ClientMessage::Phishing(request.clone());
            assert_eq!(serde_json::to_string(&message).unwrap(), json);
            let parsed: ClientMessage = serde_json::from_str(json).unwrap();
            assert!(matches!(parsed, ClientMessage::Phishing(r) if r == request));
        }
    }

    // Chrome's sendNativeMessage accepts only an object, so the extension cannot send "Status".
    #[test]
    fn phishing_status_also_parses_in_object_form() {
        let parsed: ClientMessage =
            serde_json::from_str(r#"{"Phishing":{"Status":null}}"#).unwrap();
        assert!(matches!(
            parsed,
            ClientMessage::Phishing(PhishingRequest::Status)
        ));
    }

    #[test]
    fn phishing_verdict_has_the_json_the_extension_reads() {
        let json = r#"{"Phishing":{"Verdict":{"level":"danger","reasons":[{"cue":"example_cue","text":"example reason"}],"show":true}}}"#;
        let verdict = PhishingResponse::Verdict(PhishingVerdict {
            level: Level::Danger,
            reasons: vec![Reason {
                cue: "example_cue".into(),
                text: "example reason".into(),
            }],
            show: true,
        });
        let message = DaemonMessage::Phishing(verdict.clone());
        assert_eq!(serde_json::to_string(&message).unwrap(), json);
        let parsed: DaemonMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(parsed, DaemonMessage::Phishing(r) if r == verdict));
    }
}

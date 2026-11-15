use riggs_types::events::Severity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BehaviorPattern {
    RapidFileEncryption,
    ProcessInjection,
    /// `signals`: root gained (an exec or the OS's report of it, counted once),
    /// a reason to distrust the process that asked, and an independent failed
    /// then successful login (2 = Suspicious, 3 = Malicious).
    PrivilegeEscalation {
        signals: u8,
    },
    /// `signals`: internal-host sweep, DNS then connect, auth then connect
    /// (1 = Suspicious, 2+ = Malicious).
    LateralMovement {
        signals: u8,
    },
    /// `signals`: independent corroborating signals (1 = Suspicious, 2+ = Malicious).
    DataExfiltration {
        signals: u8,
    },
    PersistenceMechanism,
    SuspiciousChildProcess,
    CryptoMining {
        signals: u8,
    },
    // After-the-click rules (lure.rs). Low on purpose: they alert only. A
    // Medium verdict makes the storyline a threat, whose opened files are
    // snapshotted; a High one is Malicious and starts the response engine.
    DownloadExecuted {
        detail: String,
    },
    LureCommand {
        detail: String,
    },
    CredentialStoreAccess {
        detail: String,
    },
}

impl BehaviorPattern {
    pub fn severity(&self) -> Severity {
        match self {
            Self::DownloadExecuted { .. }
            | Self::LureCommand { .. }
            | Self::CredentialStoreAccess { .. } => Severity::Low,
            Self::RapidFileEncryption => Severity::Critical,
            Self::ProcessInjection => Severity::Critical,
            Self::PrivilegeEscalation { signals } => {
                if *signals >= 3 {
                    Severity::High
                } else {
                    Severity::Medium
                }
            }
            Self::LateralMovement { signals }
            | Self::DataExfiltration { signals }
            | Self::CryptoMining { signals } => {
                if *signals >= 2 {
                    Severity::High
                } else {
                    Severity::Medium
                }
            }
            Self::PersistenceMechanism => Severity::Medium,
            Self::SuspiciousChildProcess => Severity::Medium,
        }
    }

    pub fn description(&self) -> &str {
        match self {
            Self::RapidFileEncryption => "Rapid sequential file encryption detected, consistent with ransomware behavior",
            Self::ProcessInjection => "Process memory injection detected, code injected into remote process",
            Self::PrivilegeEscalation { .. } => "Unexpected privilege escalation detected",
            Self::LateralMovement { .. } => "Network-based lateral movement pattern detected across hosts",
            Self::DataExfiltration { .. } => "Archive staged then sent out of the host, possible data exfiltration",
            Self::PersistenceMechanism => "Persistence mechanism installed (LaunchDaemon, crontab, systemd, SSH authorized_keys, or registry)",
            Self::SuspiciousChildProcess => "Suspicious child process spawned from unexpected parent (e.g., shell from Office app)",
            Self::CryptoMining { .. } => "Cryptocurrency miner: miner program, mining pool domain or mining pool port",
            Self::DownloadExecuted { detail }
            | Self::LureCommand { detail }
            | Self::CredentialStoreAccess { detail } => detail,
        }
    }

    pub fn mitre_technique(&self) -> &str {
        match self {
            Self::RapidFileEncryption => "T1486",
            Self::ProcessInjection => "T1055",
            Self::PrivilegeEscalation { .. } => "T1548",
            Self::LateralMovement { .. } => "T1021",
            Self::DataExfiltration { .. } => "T1041",
            Self::PersistenceMechanism => "T1543",
            Self::SuspiciousChildProcess => "T1059",
            Self::CryptoMining { .. } => "T1496",
            Self::DownloadExecuted { .. } => "T1204.002",
            Self::LureCommand { .. } => "T1059",
            Self::CredentialStoreAccess { .. } => "T1555",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_signal_is_medium_corroborated_is_high() {
        for pattern in [
            |signals| BehaviorPattern::DataExfiltration { signals },
            |signals| BehaviorPattern::CryptoMining { signals },
            |signals| BehaviorPattern::LateralMovement { signals },
        ] {
            assert_eq!(pattern(1).severity(), Severity::Medium);
            assert_eq!(pattern(2).severity(), Severity::High);
            assert_eq!(pattern(4).severity(), Severity::High);
        }
    }

    #[test]
    fn privilege_escalation_needs_three_signals_for_high() {
        let pattern = |signals| BehaviorPattern::PrivilegeEscalation { signals };
        assert_eq!(pattern(2).severity(), Severity::Medium);
        assert_eq!(pattern(3).severity(), Severity::High);
    }

    #[test]
    fn after_the_click_patterns_are_low_and_describe_what_matched() {
        for pattern in [
            |detail| BehaviorPattern::DownloadExecuted { detail },
            |detail| BehaviorPattern::LureCommand { detail },
            |detail| BehaviorPattern::CredentialStoreAccess { detail },
        ] {
            let matched = pattern("what matched".to_string());
            assert_eq!(matched.severity(), Severity::Low);
            assert_eq!(matched.description(), "what matched");
        }
    }
}

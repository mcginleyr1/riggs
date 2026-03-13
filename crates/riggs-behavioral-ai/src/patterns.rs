use riggs_types::events::Severity;

#[derive(Debug, Clone)]
pub enum BehaviorPattern {
    RapidFileEncryption,
    ProcessInjection,
    PrivilegeEscalation,
    LateralMovement,
    DataExfiltration,
    PersistenceMechanism,
    SuspiciousChildProcess,
    CryptoMining,
}

impl BehaviorPattern {
    pub fn severity(&self) -> Severity {
        match self {
            Self::RapidFileEncryption => Severity::Critical,
            Self::ProcessInjection => Severity::Critical,
            Self::PrivilegeEscalation => Severity::High,
            Self::LateralMovement => Severity::High,
            Self::DataExfiltration => Severity::High,
            Self::PersistenceMechanism => Severity::Medium,
            Self::SuspiciousChildProcess => Severity::Medium,
            Self::CryptoMining => Severity::Medium,
        }
    }

    pub fn description(&self) -> &str {
        match self {
            Self::RapidFileEncryption => "Rapid sequential file encryption detected, consistent with ransomware behavior",
            Self::ProcessInjection => "Process memory injection detected, code injected into remote process",
            Self::PrivilegeEscalation => "Unexpected privilege escalation detected",
            Self::LateralMovement => "Network-based lateral movement pattern detected across hosts",
            Self::DataExfiltration => "Large outbound data transfer detected, possible data exfiltration",
            Self::PersistenceMechanism => "Persistence mechanism installed (LaunchDaemon, crontab, systemd, or registry)",
            Self::SuspiciousChildProcess => "Suspicious child process spawned from unexpected parent (e.g., shell from Office app)",
            Self::CryptoMining => "High CPU usage combined with mining pool network connections",
        }
    }

    pub fn mitre_technique(&self) -> &str {
        match self {
            Self::RapidFileEncryption => "T1486",
            Self::ProcessInjection => "T1055",
            Self::PrivilegeEscalation => "T1548",
            Self::LateralMovement => "T1021",
            Self::DataExfiltration => "T1041",
            Self::PersistenceMechanism => "T1543",
            Self::SuspiciousChildProcess => "T1059",
            Self::CryptoMining => "T1496",
        }
    }
}

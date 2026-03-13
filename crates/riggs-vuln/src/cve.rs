use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CveSeverity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cve {
    pub id: String,           // e.g., "CVE-2024-1234"
    pub severity: CveSeverity,
    pub description: String,
    pub affected_package: String,
    pub affected_versions: String,
    pub fixed_version: Option<String>,
    pub published: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnReport {
    pub scanned_at: DateTime<Utc>,
    pub total_packages: usize,
    pub vulnerabilities: Vec<VulnMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnMatch {
    pub cve: Cve,
    pub installed_version: String,
    pub package_name: String,
    pub path: std::path::PathBuf,
}

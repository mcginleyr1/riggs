use std::fmt;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::packages::InstalledPackage;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CveSeverity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for CveSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "NONE"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl CveSeverity {
    pub fn from_cvss(score: f32) -> Self {
        match score {
            s if s >= 9.0 => Self::Critical,
            s if s >= 7.0 => Self::High,
            s if s >= 4.0 => Self::Medium,
            s if s > 0.0 => Self::Low,
            _ => Self::None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cve {
    pub id: String,
    pub severity: CveSeverity,
    pub cvss_score: f32,
    pub description: String,
    pub affected_package: String,
    pub affected_versions: String,
    pub fixed_version: Option<String>,
    pub published: DateTime<Utc>,
    pub references: Vec<String>,
}

impl fmt::Display for Cve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}, CVSS {:.1}): {}",
            self.id, self.severity, self.cvss_score, self.description
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnMatch {
    pub cve: Cve,
    pub installed_version: String,
    pub package_name: String,
    pub path: PathBuf,
    pub remediation: Option<Remediation>,
}

impl fmt::Display for VulnMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} affects {} {} (installed at {})",
            self.cve.id,
            self.package_name,
            self.installed_version,
            self.path.display()
        )?;
        if let Some(ref rem) = self.remediation {
            if let Some(ref fix) = rem.fixed_version {
                write!(f, " — fix: upgrade to {fix}")?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remediation {
    pub fixed_version: Option<String>,
    pub upgrade_command: Option<String>,
    pub workaround: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnReport {
    pub scanned_at: DateTime<Utc>,
    pub total_packages: usize,
    pub vulnerabilities: Vec<VulnMatch>,
}

impl VulnReport {
    pub fn summary(&self) -> String {
        let critical = self.count_by_severity(CveSeverity::Critical);
        let high = self.count_by_severity(CveSeverity::High);
        let medium = self.count_by_severity(CveSeverity::Medium);
        let low = self.count_by_severity(CveSeverity::Low);
        format!(
            "{} packages scanned, {} vulnerabilities found (critical: {}, high: {}, medium: {}, low: {})",
            self.total_packages,
            self.vulnerabilities.len(),
            critical,
            high,
            medium,
            low,
        )
    }

    pub fn count_by_severity(&self, severity: CveSeverity) -> usize {
        self.vulnerabilities
            .iter()
            .filter(|v| v.cve.severity == severity)
            .count()
    }

    pub fn has_critical(&self) -> bool {
        self.vulnerabilities
            .iter()
            .any(|v| v.cve.severity == CveSeverity::Critical)
    }

    pub fn filter_by_min_severity(&self, min: &CveSeverity) -> Vec<&VulnMatch> {
        self.vulnerabilities
            .iter()
            .filter(|v| &v.cve.severity >= min)
            .collect()
    }

    pub fn suggest_remediation(package: &InstalledPackage, cve: &Cve) -> Option<Remediation> {
        let upgrade_command = match package.source {
            crate::packages::PackageSource::Homebrew => {
                Some(format!("brew upgrade {}", package.name))
            }
            crate::packages::PackageSource::Pip => {
                cve.fixed_version.as_ref().map(|v| {
                    format!("pip install --upgrade {}=={}", package.name, v)
                })
            }
            crate::packages::PackageSource::Npm => {
                Some(format!("npm update -g {}", package.name))
            }
            crate::packages::PackageSource::Gem => {
                Some(format!("gem update {}", package.name))
            }
            crate::packages::PackageSource::Dpkg => {
                Some(format!("apt-get install --only-upgrade {}", package.name))
            }
            crate::packages::PackageSource::Rpm => {
                Some(format!("yum update {}", package.name))
            }
            _ => None,
        };

        Some(Remediation {
            fixed_version: cve.fixed_version.clone(),
            upgrade_command,
            workaround: None,
        })
    }
}

use std::collections::HashMap;
use std::path::Path;

use tracing::{debug, info, warn};

use crate::cve::{Cve, CveSeverity};
use crate::version::Version;

/// In-memory CVE database indexed by package name for fast lookup.
pub struct CveDatabase {
    /// Map from lowercase package name to list of CVEs affecting that package.
    entries: HashMap<String, Vec<Cve>>,
    total_cves: usize,
}

impl CveDatabase {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            total_cves: 0,
        }
    }

    /// Load CVE database from a JSON file.
    /// Expected format: array of Cve objects.
    pub fn load_from_file(path: &Path) -> Result<Self, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        let cves: Vec<Cve> = serde_json::from_str(&content).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
        })?;

        let mut db = Self::new();
        for cve in cves {
            db.add(cve);
        }

        info!("Loaded {} CVEs from {}", db.total_cves, path.display());
        Ok(db)
    }

    /// Add a single CVE entry.
    pub fn add(&mut self, cve: Cve) {
        let key = cve.affected_package.to_lowercase();
        self.entries.entry(key).or_default().push(cve);
        self.total_cves += 1;
    }

    /// Look up CVEs that affect a given package at a given version.
    pub fn lookup(&self, package_name: &str, installed_version: &str) -> Vec<&Cve> {
        let key = package_name.to_lowercase();
        let cves = match self.entries.get(&key) {
            Some(c) => c,
            None => return Vec::new(),
        };

        let installed = match Version::parse(installed_version) {
            Some(v) => v,
            None => {
                debug!(
                    "Could not parse version '{installed_version}' for {package_name}, skipping"
                );
                return Vec::new();
            }
        };

        cves.iter()
            .filter(|cve| version_is_affected(&installed, &cve.affected_versions, &cve.fixed_version))
            .collect()
    }

    /// Look up all CVEs for a package regardless of version.
    pub fn lookup_all(&self, package_name: &str) -> Vec<&Cve> {
        let key = package_name.to_lowercase();
        match self.entries.get(&key) {
            Some(cves) => cves.iter().collect(),
            None => Vec::new(),
        }
    }

    pub fn total_cves(&self) -> usize {
        self.total_cves
    }

    pub fn replace_all(&mut self, cves: Vec<Cve>) {
        self.entries.clear();
        self.total_cves = 0;
        for cve in cves {
            self.add(cve);
        }
        info!("CVE database replaced: {} CVEs across {} packages", self.total_cves, self.entries.len());
    }

    pub fn package_count(&self) -> usize {
        self.entries.len()
    }

    /// Get CVEs by minimum severity.
    pub fn by_severity(&self, min_severity: &CveSeverity) -> Vec<&Cve> {
        self.entries
            .values()
            .flatten()
            .filter(|cve| &cve.severity >= min_severity)
            .collect()
    }

    /// Look up a specific CVE by ID.
    pub fn get_by_id(&self, cve_id: &str) -> Option<&Cve> {
        self.entries
            .values()
            .flatten()
            .find(|cve| cve.id == cve_id)
    }
}

impl Default for CveDatabase {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if an installed version is affected by a CVE.
///
/// `affected_versions` is a string like:
///   - "< 1.2.3" — all versions before 1.2.3
///   - ">= 1.0.0, < 2.0.0" — range
///   - "= 1.5.0" — exact version
///   - "*" — all versions
///
/// `fixed_version` is the version that fixes the CVE. If the installed
/// version is >= fixed_version, the CVE doesn't apply.
fn version_is_affected(
    installed: &Version,
    affected_versions: &str,
    fixed_version: &Option<String>,
) -> bool {
    // If there's a fixed version and we're at or past it, not affected
    if let Some(fixed) = fixed_version {
        if let Some(fixed_ver) = Version::parse(fixed) {
            if installed >= &fixed_ver {
                return false;
            }
        }
    }

    // Parse the affected version constraints
    let constraints: Vec<&str> = affected_versions.split(',').map(|s| s.trim()).collect();

    for constraint in &constraints {
        let constraint = constraint.trim();

        if constraint == "*" {
            return true;
        }

        if let Some(rest) = constraint.strip_prefix(">=") {
            if let Some(v) = Version::parse(rest.trim()) {
                if installed < &v {
                    return false;
                }
            }
        } else if let Some(rest) = constraint.strip_prefix('>') {
            if let Some(v) = Version::parse(rest.trim()) {
                if installed <= &v {
                    return false;
                }
            }
        } else if let Some(rest) = constraint.strip_prefix("<=") {
            if let Some(v) = Version::parse(rest.trim()) {
                if installed > &v {
                    return false;
                }
            }
        } else if let Some(rest) = constraint.strip_prefix('<') {
            if let Some(v) = Version::parse(rest.trim()) {
                if installed >= &v {
                    return false;
                }
            }
        } else if let Some(rest) = constraint.strip_prefix('=') {
            if let Some(v) = Version::parse(rest.trim()) {
                if installed != &v {
                    return false;
                }
            }
        } else {
            // Unparseable constraint — be conservative, assume affected
            warn!("Unparseable version constraint: '{constraint}'");
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_cve(package: &str, affected: &str, fixed: Option<&str>) -> Cve {
        Cve {
            id: "CVE-2024-0001".into(),
            severity: CveSeverity::High,
            cvss_score: 7.5,
            description: "Test CVE".into(),
            affected_package: package.into(),
            affected_versions: affected.into(),
            fixed_version: fixed.map(|s| s.into()),
            published: Utc::now(),
            references: Vec::new(),
        }
    }

    #[test]
    fn lookup_finds_affected() {
        let mut db = CveDatabase::new();
        db.add(make_cve("openssl", ">= 1.0.0, < 1.1.1", Some("1.1.1")));

        let hits = db.lookup("openssl", "1.0.5");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn lookup_skips_fixed() {
        let mut db = CveDatabase::new();
        db.add(make_cve("openssl", ">= 1.0.0, < 1.1.1", Some("1.1.1")));

        let hits = db.lookup("openssl", "1.1.1");
        assert_eq!(hits.len(), 0);
    }

    #[test]
    fn lookup_wildcard() {
        let mut db = CveDatabase::new();
        db.add(make_cve("badlib", "*", None));

        let hits = db.lookup("badlib", "99.99.99");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn lookup_case_insensitive() {
        let mut db = CveDatabase::new();
        db.add(make_cve("OpenSSL", ">= 1.0.0", Some("2.0.0")));

        let hits = db.lookup("openssl", "1.5.0");
        assert_eq!(hits.len(), 1);
    }
}

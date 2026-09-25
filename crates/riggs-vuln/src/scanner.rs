use std::path::Path;

use chrono::Utc;
use tracing::{info, warn};

use riggs_types::errors::RiggsError;

use crate::cve::{Cve, VulnMatch, VulnReport};
use crate::database::CveDatabase;
use crate::osv::OsvClient;
use crate::packages::{self, InstalledPackage};

pub struct VulnScanner {
    db: CveDatabase,
}

impl VulnScanner {
    pub fn new() -> Self {
        Self {
            db: CveDatabase::new(),
        }
    }

    pub fn with_database(db: CveDatabase) -> Self {
        Self { db }
    }

    /// Load CVE database from a JSON file.
    pub fn load_cve_database(&mut self, path: &Path) -> Result<(), RiggsError> {
        self.db = CveDatabase::load_from_file(path)
            .map_err(|e| RiggsError::Other(format!("Failed to load CVE database: {e}")))?;
        info!(
            "CVE database loaded: {} CVEs across {} packages",
            self.db.total_cves(),
            self.db.package_count()
        );
        Ok(())
    }

    /// Scan all installed packages on the system against the CVE database.
    pub async fn scan_system(&self) -> Result<VulnReport, RiggsError> {
        let packages = packages::enumerate_packages();
        info!(
            "Scanning {} installed packages for vulnerabilities",
            packages.len()
        );
        self.scan_packages(&packages)
    }

    /// Refresh the CVE database from OSV.dev for every installed package OSV
    /// tracks, then scan those packages against it.
    pub async fn update_from_osv_and_scan(&mut self) -> Result<VulnReport, RiggsError> {
        let packages = tokio::task::spawn_blocking(packages::enumerate_packages)
            .await
            .map_err(|e| RiggsError::Other(format!("package enumeration failed: {e}")))?;
        let debian = tokio::fs::read_to_string("/etc/os-release")
            .await
            .ok()
            .and_then(|text| packages::debian_ecosystem(&text));

        // OSV matches each installed version itself, with the ecosystem's own
        // ordering, so only advisories that affect this exact build come back.
        let osv = OsvClient::new();
        let mut vulnerabilities = Vec::new();
        let mut cves = Vec::new();
        for package in &packages {
            let Some(ecosystem) = package.source.osv_ecosystem(debian.as_deref()) else {
                continue;
            };
            match osv
                .query_installed(&ecosystem, &package.name, &package.version)
                .await
            {
                Ok(affecting) => {
                    vulnerabilities.extend(affecting.iter().map(|cve| vuln_match(package, cve)));
                    cves.extend(affecting);
                }
                Err(e) => warn!(package = %package, error = %e, "OSV query failed, skipping"),
            }
        }

        self.db.replace_all(cves);
        info!(
            "CVE database refreshed from OSV: {} CVEs across {} packages",
            self.db.total_cves(),
            self.db.package_count()
        );
        Ok(build_report(packages.len(), vulnerabilities))
    }

    /// Scan packages at a specific path (e.g., a project's node_modules).
    pub async fn scan_path(&self, path: &Path) -> Result<VulnReport, RiggsError> {
        let packages = enumerate_path_packages(path);
        info!(
            "Scanning {} packages at {} for vulnerabilities",
            packages.len(),
            path.display()
        );
        self.scan_packages(&packages)
    }

    fn scan_packages(&self, packages: &[InstalledPackage]) -> Result<VulnReport, RiggsError> {
        let vulnerabilities = packages
            .iter()
            .flat_map(|package| {
                self.db
                    .lookup(&package.name, &package.version)
                    .into_iter()
                    .map(move |cve| vuln_match(package, cve))
            })
            .collect();
        Ok(build_report(packages.len(), vulnerabilities))
    }

    pub fn database(&self) -> &CveDatabase {
        &self.db
    }

    pub fn database_mut(&mut self) -> &mut CveDatabase {
        &mut self.db
    }
}

fn vuln_match(package: &InstalledPackage, cve: &Cve) -> VulnMatch {
    VulnMatch {
        remediation: VulnReport::suggest_remediation(package, cve),
        cve: cve.clone(),
        installed_version: package.version.clone(),
        package_name: package.name.clone(),
        path: package.install_path.clone().unwrap_or_default(),
    }
}

/// Report with the most severe (highest CVSS) findings first.
fn build_report(total_packages: usize, mut vulnerabilities: Vec<VulnMatch>) -> VulnReport {
    vulnerabilities.sort_by(|a, b| b.cve.cvss_score.total_cmp(&a.cve.cvss_score));
    let report = VulnReport {
        scanned_at: Utc::now(),
        total_packages,
        vulnerabilities,
    };
    info!("{}", report.summary());
    report
}

impl Default for VulnScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Enumerate packages found under a specific path.
/// Looks for package.json (npm), requirements.txt / dist-info (pip), Gemfile.lock (ruby).
fn enumerate_path_packages(path: &Path) -> Vec<InstalledPackage> {
    let mut packages = Vec::new();

    if !path.is_dir() {
        warn!("Scan path does not exist: {}", path.display());
        return packages;
    }

    // Check for node_modules
    let node_modules = path.join("node_modules");
    if node_modules.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&node_modules) {
            for entry in entries.flatten() {
                let pkg_path = entry.path();
                let package_json = pkg_path.join("package.json");
                if !package_json.exists() {
                    continue;
                }
                if let Ok(content) = std::fs::read_to_string(&package_json) {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                        let name = json["name"].as_str().unwrap_or_default().to_string();
                        let version = json["version"].as_str().unwrap_or("0.0.0").to_string();
                        if !name.is_empty() {
                            packages.push(InstalledPackage {
                                name,
                                version,
                                source: packages::PackageSource::Npm,
                                install_path: Some(pkg_path),
                            });
                        }
                    }
                }
            }
        }
    }

    // Check for Python venv or dist-info dirs
    let venv_lib = path.join("lib");
    if venv_lib.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&venv_lib) {
            for entry in entries.flatten() {
                let dir = entry.path();
                let site_packages = dir.join("site-packages");
                if site_packages.is_dir() {
                    if let Ok(sp_entries) = std::fs::read_dir(&site_packages) {
                        for sp_entry in sp_entries.flatten() {
                            let name = sp_entry.file_name().to_string_lossy().to_string();
                            if let Some(stripped) = name.strip_suffix(".dist-info") {
                                if let Some((pkg_name, version)) = stripped.rsplit_once('-') {
                                    packages.push(InstalledPackage {
                                        name: pkg_name.replace('_', "-"),
                                        version: version.to_string(),
                                        source: packages::PackageSource::Pip,
                                        install_path: Some(sp_entry.path()),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    packages
}

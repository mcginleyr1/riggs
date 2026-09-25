use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackageSource {
    Homebrew,
    System,
    Application,
    Pip,
    Npm,
    Gem,
    Dpkg,
    Rpm,
    Binary,
}

impl PackageSource {
    /// The OSV.dev ecosystem for this source, when OSV tracks it. dpkg packages
    /// need the Debian release (`Debian:12`, see [`debian_ecosystem`]).
    pub fn osv_ecosystem(&self, debian_ecosystem: Option<&str>) -> Option<String> {
        match self {
            Self::Npm => Some("npm".into()),
            Self::Pip => Some("PyPI".into()),
            Self::Gem => Some("RubyGems".into()),
            Self::Dpkg => debian_ecosystem.map(String::from),
            Self::Homebrew | Self::System | Self::Application | Self::Rpm | Self::Binary => None,
        }
    }
}

/// OSV's release-specific Debian ecosystem (`Debian:12`) from /etc/os-release
/// text, or `None` on other distributions.
pub fn debian_ecosystem(os_release: &str) -> Option<String> {
    let field = |name: &str| {
        os_release
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(|v| v.trim().trim_matches('"'))
    };
    match (field("ID="), field("VERSION_ID=")) {
        (Some("debian"), Some(version)) if !version.is_empty() => Some(format!("Debian:{version}")),
        _ => None,
    }
}

impl fmt::Display for PackageSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Homebrew => write!(f, "homebrew"),
            Self::System => write!(f, "system"),
            Self::Application => write!(f, "application"),
            Self::Pip => write!(f, "pip"),
            Self::Npm => write!(f, "npm"),
            Self::Gem => write!(f, "gem"),
            Self::Dpkg => write!(f, "dpkg"),
            Self::Rpm => write!(f, "rpm"),
            Self::Binary => write!(f, "binary"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub source: PackageSource,
    pub install_path: Option<PathBuf>,
}

impl fmt::Display for InstalledPackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} ({})", self.name, self.version, self.source)
    }
}

/// Enumerate all installed packages on the system.
pub fn enumerate_packages() -> Vec<InstalledPackage> {
    let mut packages = Vec::new();

    #[cfg(target_os = "macos")]
    {
        packages.extend(enumerate_homebrew());
        packages.extend(enumerate_macos_apps());
    }

    #[cfg(target_os = "linux")]
    {
        packages.extend(enumerate_dpkg());
    }

    // Cross-platform package managers
    packages.extend(enumerate_pip());
    packages.extend(enumerate_npm_global());

    debug!("Enumerated {} installed packages", packages.len());
    packages
}

/// Parse Homebrew Cellar directory to find installed packages.
#[cfg(target_os = "macos")]
fn enumerate_homebrew() -> Vec<InstalledPackage> {
    let mut packages = Vec::new();

    // Try common Homebrew prefixes
    let prefixes = ["/opt/homebrew/Cellar", "/usr/local/Cellar"];

    for prefix in &prefixes {
        let cellar = Path::new(prefix);
        if !cellar.is_dir() {
            continue;
        }

        let entries = match std::fs::read_dir(cellar) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let pkg_dir = entry.path();

            // Each subdirectory of the package dir is a version
            if let Ok(versions) = std::fs::read_dir(&pkg_dir) {
                for ver_entry in versions.flatten() {
                    if ver_entry.path().is_dir() {
                        let version = ver_entry.file_name().to_string_lossy().to_string();
                        packages.push(InstalledPackage {
                            name: name.clone(),
                            version,
                            source: PackageSource::Homebrew,
                            install_path: Some(ver_entry.path()),
                        });
                    }
                }
            }
        }
    }

    debug!("Found {} Homebrew packages", packages.len());
    packages
}

/// Scan /Applications for macOS app bundles and extract versions from Info.plist.
#[cfg(target_os = "macos")]
fn enumerate_macos_apps() -> Vec<InstalledPackage> {
    let mut packages = Vec::new();
    let app_dirs = ["/Applications"];

    for dir in &app_dirs {
        let path = Path::new(dir);
        if !path.is_dir() {
            continue;
        }

        let entries = match std::fs::read_dir(path) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let app_path = entry.path();
            if app_path.extension().is_none_or(|e| e != "app") {
                continue;
            }

            let plist_path = app_path.join("Contents/Info.plist");
            if !plist_path.exists() {
                continue;
            }

            // Extract app name from directory name
            let name = app_path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            // Try to read version from Info.plist (plain text grep — plist can be XML or binary)
            let version = read_plist_version(&plist_path).unwrap_or_else(|| "unknown".into());

            packages.push(InstalledPackage {
                name,
                version,
                source: PackageSource::Application,
                install_path: Some(app_path),
            });
        }
    }

    debug!("Found {} macOS applications", packages.len());
    packages
}

/// Read CFBundleShortVersionString from an XML plist file.
#[cfg(target_os = "macos")]
fn read_plist_version(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;

    // Simple XML parsing — find <key>CFBundleShortVersionString</key> then the next <string>
    let key = "CFBundleShortVersionString";
    let key_pos = content.find(key)?;
    let after_key = &content[key_pos + key.len()..];

    let string_start = after_key.find("<string>")? + "<string>".len();
    let remaining = &after_key[string_start..];
    let string_end = remaining.find("</string>")?;

    Some(remaining[..string_end].trim().to_string())
}

/// Parse /var/lib/dpkg/status for Debian/Ubuntu packages.
#[cfg(target_os = "linux")]
fn enumerate_dpkg() -> Vec<InstalledPackage> {
    let mut packages = Vec::new();
    let status_path = Path::new("/var/lib/dpkg/status");

    if !status_path.exists() {
        return packages;
    }

    match std::fs::read_to_string(status_path) {
        Ok(content) => packages = parse_dpkg_status(&content),
        Err(e) => tracing::warn!("Failed to read dpkg status: {e}"),
    }

    debug!("Found {} dpkg source packages", packages.len());
    packages
}

/// Installed Debian *source* packages from dpkg status text. Debian security
/// advisories (and OSV's Debian ecosystem) are keyed by source package and
/// source version, so binaries built from one source (libssl3, openssl) collapse
/// into a single entry.
#[cfg(any(target_os = "linux", test))]
fn parse_dpkg_status(content: &str) -> Vec<InstalledPackage> {
    let mut sources = std::collections::BTreeSet::new();

    for block in content.split("\n\n") {
        let field = |name: &str| {
            block
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .map(str::trim)
        };

        // "Status: install ok installed" -- the last word is the state, so
        // "not-installed" and "config-files" don't count.
        let installed =
            field("Status:").is_some_and(|s| s.split_whitespace().last() == Some("installed"));
        let (Some(binary), Some(version)) = (field("Package:"), field("Version:")) else {
            continue;
        };
        if !installed {
            continue;
        }

        // "Source: openssl" or "Source: openssl (3.0.11-1)" when versions differ.
        let (name, version) = match field("Source:") {
            Some(source) => match source.split_once(' ') {
                Some((name, v)) => (name, v.trim_matches(|c| c == '(' || c == ')')),
                None => (source, version),
            },
            None => (binary, version),
        };
        sources.insert((name.to_string(), version.to_string()));
    }

    sources
        .into_iter()
        .map(|(name, version)| InstalledPackage {
            name,
            version,
            source: PackageSource::Dpkg,
            install_path: None,
        })
        .collect()
}

/// Parse pip packages from pip's metadata directories.
fn enumerate_pip() -> Vec<InstalledPackage> {
    let mut packages = Vec::new();

    // Check common site-packages locations
    let home = std::env::var("HOME").unwrap_or_default();
    let candidates = [
        format!("{home}/.local/lib/python3/dist-packages"),
        "/usr/lib/python3/dist-packages".into(),
        "/usr/local/lib/python3/dist-packages".into(),
    ];

    for base in &candidates {
        let base_path = Path::new(base);
        if !base_path.is_dir() {
            continue;
        }

        let entries = match std::fs::read_dir(base_path) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // pip metadata dirs look like "package_name-1.2.3.dist-info"
            if let Some(stripped) = name.strip_suffix(".dist-info") {
                if let Some((pkg_name, version)) = stripped.rsplit_once('-') {
                    packages.push(InstalledPackage {
                        name: pkg_name.replace('_', "-"),
                        version: version.to_string(),
                        source: PackageSource::Pip,
                        install_path: Some(entry.path()),
                    });
                }
            }
        }
    }

    debug!("Found {} pip packages", packages.len());
    packages
}

/// Parse globally installed npm packages.
fn enumerate_npm_global() -> Vec<InstalledPackage> {
    let mut packages = Vec::new();

    let home = std::env::var("HOME").unwrap_or_default();
    let candidates = [
        format!("{home}/.npm-global/lib/node_modules"),
        "/usr/local/lib/node_modules".into(),
        "/usr/lib/node_modules".into(),
    ];

    for base in &candidates {
        let base_path = Path::new(base);
        if !base_path.is_dir() {
            continue;
        }

        let entries = match std::fs::read_dir(base_path) {
            Ok(e) => e,
            Err(_) => continue,
        };

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
                            source: PackageSource::Npm,
                            install_path: Some(pkg_path),
                        });
                    }
                }
            }
        }
    }

    debug!("Found {} npm packages", packages.len());
    packages
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &str = "Package: libssl3\nStatus: install ok installed\nSource: openssl\nVersion: 3.0.15-1~deb12u1\n\nPackage: openssl\nStatus: install ok installed\nVersion: 3.0.15-1~deb12u1\n\nPackage: bash\nStatus: install ok installed\nVersion: 5.2.15-2+b7\nSource: bash (5.2.15-2)\n\nPackage: telnet\nStatus: deinstall ok config-files\nVersion: 0.17-44\n\nPackage: old\nStatus: unknown ok not-installed\nVersion: 1.0\n";

    #[test]
    fn dpkg_status_reports_installed_source_packages() {
        let found: Vec<(String, String)> = parse_dpkg_status(STATUS)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect();

        assert_eq!(
            found,
            vec![
                ("bash".to_string(), "5.2.15-2".to_string()),
                ("openssl".to_string(), "3.0.15-1~deb12u1".to_string()),
            ]
        );
    }

    #[test]
    fn debian_ecosystem_is_release_specific() {
        let debian =
            "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n";
        let ubuntu = "ID=ubuntu\nVERSION_ID=\"22.04\"\n";
        assert_eq!(debian_ecosystem(debian).as_deref(), Some("Debian:12"));
        assert_eq!(debian_ecosystem(ubuntu), None);
        assert_eq!(PackageSource::Dpkg.osv_ecosystem(None), None);
    }
}

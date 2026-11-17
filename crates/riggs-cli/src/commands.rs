use std::path::Path;

use riggs_comms::{ClientMessage, DaemonMessage, IpcClient};
use riggs_types::errors::RiggsError;
use riggs_types::phishing::{Level, Mode, ObservationKind, PhishingRequest, PhishingResponse};

const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

async fn connect(socket_path: &Path) -> Result<IpcClient, RiggsError> {
    IpcClient::connect(socket_path).await.map_err(|_| {
        RiggsError::Comms(format!(
            "Could not connect to daemon at {}\nIs the riggs daemon running?",
            socket_path.display()
        ))
    })
}

async fn send(client: &mut IpcClient, msg: &ClientMessage) -> Result<DaemonMessage, RiggsError> {
    client
        .send(msg)
        .await
        .map_err(|e| RiggsError::Comms(format!("Communication error: {e}")))
}

pub async fn status(socket_path: &Path) -> Result<(), RiggsError> {
    let mut client = connect(socket_path).await?;
    let response = send(&mut client, &ClientMessage::GetStatus).await?;

    println!("{BOLD}riggs - Endpoint Protection{RESET}");
    println!("{DIM}────────────────────────────────────{RESET}");

    match response {
        DaemonMessage::Status {
            running,
            events_processed,
            active_threats,
        } => {
            let status_color = if running { GREEN } else { RED };
            let status_text = if running { "active" } else { "stopped" };
            let threat_color = if active_threats > 0 { RED } else { GREEN };

            println!("  {BOLD}Status:{RESET}           {status_color}{status_text}{RESET}");
            println!("  {BOLD}Events processed:{RESET} {events_processed}");
            println!("  {BOLD}Active threats:{RESET}   {threat_color}{active_threats}{RESET}");
        }
        DaemonMessage::Error(e) => {
            println!("  {RED}Error:{RESET} {e}");
        }
        _ => {
            println!("  {RED}Unexpected response from daemon{RESET}");
        }
    }

    Ok(())
}

pub async fn threats(socket_path: &Path) -> Result<(), RiggsError> {
    let mut client = connect(socket_path).await?;
    let msg = ClientMessage::QueryThreats {
        min_severity: "Low".into(),
    };
    let response = send(&mut client, &msg).await?;
    let mut client = connect(socket_path).await?;
    let responses = match send(&mut client, &ClientMessage::QueryResponses).await? {
        DaemonMessage::Responses(responses) => responses,
        _ => Vec::new(),
    };

    match response {
        DaemonMessage::Threats(threats) => {
            if threats.is_empty() {
                println!("{GREEN}No active threats detected.{RESET}");
                return Ok(());
            }

            println!("{BOLD}Active Threats{RESET}");
            println!("{DIM}─────────────────────────────────────────────────────────────────────────────{RESET}");
            println!(
                "  {BOLD}{:<38} {:<12} {:<10} {:<14}{RESET}",
                "EVENT ID", "LEVEL", "SOURCES", "STORYLINE"
            );
            println!("{DIM}─────────────────────────────────────────────────────────────────────────────{RESET}");

            for threat in &threats {
                let level_color = match threat.final_threat_level {
                    riggs_types::verdict::ThreatLevel::Malicious => RED,
                    riggs_types::verdict::ThreatLevel::Suspicious => YELLOW,
                    riggs_types::verdict::ThreatLevel::Clean => GREEN,
                };

                let sources: Vec<String> = threat
                    .verdicts
                    .iter()
                    .map(|v| v.source.to_string())
                    .collect();
                let sources_str = sources.join(", ");

                println!(
                    "  {:<38} {level_color}{:<12}{RESET} {:<10} {DIM}{:<14}{RESET}",
                    threat.event_id, threat.final_threat_level, sources_str, threat.storyline_id,
                );
                for verdict in &threat.verdicts {
                    println!(
                        "    {DIM}{}:{RESET} {}",
                        verdict.source, verdict.description
                    );
                }
                for r in responses
                    .iter()
                    .filter(|r| r.event_id == threat.event_id.to_string())
                {
                    println!(
                        "    {DIM}response:{RESET} {} ({}) {DIM}{}{RESET}",
                        r.action, r.outcome, r.detail
                    );
                }
            }

            println!();
            println!("  {BOLD}Total:{RESET} {} threat(s)", threats.len());
        }
        DaemonMessage::Error(e) => {
            eprintln!("{RED}Error:{RESET} {e}");
        }
        _ => {
            eprintln!("{RED}Unexpected response from daemon{RESET}");
        }
    }

    Ok(())
}

pub async fn events(socket_path: &Path, args: &[String]) -> Result<(), RiggsError> {
    let mut storyline_id = None;
    let mut limit: usize = 50;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--storyline" | "-s" if i + 1 < args.len() => {
                storyline_id = Some(args[i + 1].clone());
                i += 2;
                continue;
            }
            "--limit" | "-n" if i + 1 < args.len() => {
                limit = args[i + 1]
                    .parse()
                    .map_err(|_| RiggsError::Other("Invalid limit value".into()))?;
                i += 2;
                continue;
            }
            _ => {}
        }
        i += 1;
    }

    let mut client = connect(socket_path).await?;
    let msg = ClientMessage::QueryEvents {
        storyline_id,
        limit,
    };
    let response = send(&mut client, &msg).await?;

    match response {
        DaemonMessage::Events(events) => {
            if events.is_empty() {
                println!("{DIM}No events to display.{RESET}");
                return Ok(());
            }

            println!("{BOLD}Recent Events{RESET}");
            println!("{DIM}─────────────────────────────────────────────────────────────────────────────{RESET}");
            println!(
                "  {BOLD}{:<24} {:<10} {:<8} {:<6} DETAIL{RESET}",
                "TIMESTAMP", "TYPE", "SEVERITY", "PID"
            );
            println!("{DIM}─────────────────────────────────────────────────────────────────────────────{RESET}");

            for event in &events {
                let severity = event.severity();
                let sev_color = match severity {
                    riggs_types::events::Severity::Critical => RED,
                    riggs_types::events::Severity::High => RED,
                    riggs_types::events::Severity::Medium => YELLOW,
                    riggs_types::events::Severity::Low => CYAN,
                    riggs_types::events::Severity::Info => DIM,
                };

                let ts = event.timestamp().format("%Y-%m-%d %H:%M:%S");
                let pid = event.process_context().pid;

                let (etype, detail) = event_summary(event);

                println!(
                    "  {:<24} {:<10} {sev_color}{:<8}{RESET} {:<6} {}",
                    ts, etype, severity, pid, detail,
                );
            }

            println!();
            println!("  {BOLD}Showing:{RESET} {} event(s)", events.len());
        }
        DaemonMessage::Error(e) => {
            eprintln!("{RED}Error:{RESET} {e}");
        }
        _ => {
            eprintln!("{RED}Unexpected response from daemon{RESET}");
        }
    }

    Ok(())
}

fn event_summary(event: &riggs_types::events::RiggsEvent) -> (&'static str, String) {
    use riggs_types::events::RiggsEvent;
    match event {
        RiggsEvent::Process(e) => {
            let action = match e.action {
                riggs_types::events::ProcessAction::Exec => "exec",
                riggs_types::events::ProcessAction::Fork => "fork",
                riggs_types::events::ProcessAction::Exit => "exit",
            };
            ("PROCESS", format!("{} {}", action, e.process_context.path))
        }
        RiggsEvent::File(e) => {
            let action = match e.action {
                riggs_types::events::FileAction::Create => "create",
                riggs_types::events::FileAction::Modify => "modify",
                riggs_types::events::FileAction::Delete => "delete",
                riggs_types::events::FileAction::Rename => "rename",
                riggs_types::events::FileAction::Open => "open",
                riggs_types::events::FileAction::Close => "close",
                riggs_types::events::FileAction::Scan => "scan",
            };
            ("FILE", format!("{} {}", action, e.path))
        }
        RiggsEvent::Network(e) => {
            let dir = match e.direction {
                riggs_types::events::NetworkDirection::Inbound => "in",
                riggs_types::events::NetworkDirection::Outbound => "out",
            };
            (
                "NETWORK",
                format!(
                    "{} {}:{} -> {}:{}",
                    dir, e.src_addr, e.src_port, e.dst_addr, e.dst_port
                ),
            )
        }
        RiggsEvent::Dns(e) => ("DNS", format!("{} -> {}", e.query, e.response)),
        RiggsEvent::Auth(e) => {
            let action = match e.action {
                riggs_types::events::AuthAction::Login => "login",
                riggs_types::events::AuthAction::Logout => "logout",
                riggs_types::events::AuthAction::Escalation => "escalation",
                riggs_types::events::AuthAction::Failed => "failed",
            };
            ("AUTH", format!("{} user={}", action, e.user))
        }
        RiggsEvent::Kernel(e) => {
            let action = match e.action {
                riggs_types::events::KernelAction::ModuleLoad => "module_load",
                riggs_types::events::KernelAction::SyscallFilter => "syscall_filter",
                riggs_types::events::KernelAction::MemoryExec => "memory_exec",
            };
            ("KERNEL", format!("{} {}", action, e.detail))
        }
    }
}

pub async fn config(socket_path: &Path, args: &[String]) -> Result<(), RiggsError> {
    let mut client = connect(socket_path).await?;

    if args.len() >= 2 {
        let msg = ClientMessage::UpdateConfig {
            key: args[0].clone(),
            value: args[1].clone(),
        };
        let response = send(&mut client, &msg).await?;
        match response {
            DaemonMessage::Done(outcome) => println!("{GREEN}{outcome}{RESET}"),
            DaemonMessage::Error(e) => eprintln!("{RED}Error:{RESET} {e}"),
            _ => eprintln!("{RED}Unexpected response from daemon{RESET}"),
        }
    } else {
        let response = send(&mut client, &ClientMessage::GetConfig).await?;
        match response {
            DaemonMessage::Config(cfg) => {
                println!("{BOLD}Current Configuration{RESET}");
                println!("{DIM}────────────────────────────────────{RESET}");
                println!("{cfg}");
            }
            DaemonMessage::Error(e) => eprintln!("{RED}Error:{RESET} {e}"),
            _ => eprintln!("{RED}Unexpected response from daemon{RESET}"),
        }
    }

    Ok(())
}

pub async fn scan(socket_path: &Path, args: &[String]) -> Result<(), RiggsError> {
    // The daemon has its own working directory, so send an absolute path.
    let requested = args.first().map(|s| s.as_str()).unwrap_or(".");
    let path = std::fs::canonicalize(requested)
        .map_err(|e| RiggsError::Io(format!("cannot scan {requested}: {e}")))?;
    let path = path.to_string_lossy().to_string();

    let mut client = connect(socket_path).await?;
    println!("{BOLD}Requesting scan:{RESET} {path}");

    let response = send(&mut client, &ClientMessage::TriggerScan { path }).await?;
    match response {
        DaemonMessage::Done(outcome) => {
            println!("{GREEN}{outcome}{RESET}");
        }
        DaemonMessage::Error(e) => {
            eprintln!("{RED}Scan failed:{RESET} {e}");
        }
        _ => {
            eprintln!("{RED}Unexpected response from daemon{RESET}");
        }
    }

    Ok(())
}

pub async fn quarantine(socket_path: &Path, args: &[String]) -> Result<(), RiggsError> {
    let mut client = connect(socket_path).await?;

    if args.first().map(String::as_str) == Some("restore") {
        let Some(id) = args.get(1) else {
            eprintln!("Usage: riggs quarantine restore <id>");
            return Ok(());
        };
        let msg = ClientMessage::QuarantineRestore { id: id.clone() };
        match send(&mut client, &msg).await? {
            DaemonMessage::Done(outcome) => println!("{GREEN}{outcome}{RESET}"),
            DaemonMessage::Error(e) => eprintln!("{RED}Error:{RESET} {e}"),
            _ => eprintln!("{RED}Unexpected response from daemon{RESET}"),
        }
        return Ok(());
    }

    match send(&mut client, &ClientMessage::QuarantineList).await? {
        DaemonMessage::Quarantine(files) => {
            println!("{BOLD}Quarantine{RESET}");
            println!("{DIM}────────────────────────────────────{RESET}");
            if files.is_empty() {
                println!("  {DIM}No quarantined files.{RESET}");
            }
            for f in &files {
                println!(
                    "  {}  {}  {} bytes  {DIM}{}{RESET}",
                    f.id, f.original_path, f.file_size, f.quarantined_at
                );
            }
            if !files.is_empty() {
                println!("\n  {DIM}Restore with: riggs quarantine restore <id>{RESET}");
            }
        }
        DaemonMessage::Error(e) => eprintln!("{RED}Error:{RESET} {e}"),
        _ => eprintln!("{RED}Unexpected response from daemon{RESET}"),
    }

    Ok(())
}

pub async fn intel(socket_path: &Path, args: &[String]) -> Result<(), RiggsError> {
    let subcmd = args.first().map(|s| s.as_str()).unwrap_or("status");

    let mut client = connect(socket_path).await?;

    match subcmd {
        "update" => {
            println!("{BOLD}Refreshing threat intelligence feeds...{RESET}");
            let response = send(&mut client, &ClientMessage::RefreshFeeds).await?;
            match response {
                DaemonMessage::Done(outcome) => println!("{GREEN}{outcome}{RESET}"),
                DaemonMessage::Error(e) => eprintln!("{RED}Error:{RESET} {e}"),
                _ => eprintln!("{RED}Unexpected response from daemon{RESET}"),
            }
        }
        "status" => {
            let response = send(&mut client, &ClientMessage::IntelStatus).await?;
            match response {
                DaemonMessage::IntelStatus {
                    bloom_size,
                    cache_entries,
                    feeds_last_updated,
                } => {
                    println!("{BOLD}Threat Intelligence{RESET}");
                    println!("{DIM}────────────────────────────────────{RESET}");
                    println!("  {BOLD}Bloom filter:{RESET}   {bloom_size} hashes");
                    println!("  {BOLD}Cache entries:{RESET}  {cache_entries}");
                    if let Some(last) = feeds_last_updated {
                        println!("  {BOLD}Last updated:{RESET}   {last}");
                    } else {
                        println!("  {BOLD}Last updated:{RESET}   {DIM}never{RESET}");
                    }
                }
                DaemonMessage::Error(e) => eprintln!("{RED}Error:{RESET} {e}"),
                _ => eprintln!("{RED}Unexpected response from daemon{RESET}"),
            }
        }
        cmd => {
            eprintln!("Unknown intel subcommand: {cmd}");
            println!("Usage: riggs intel [update|status]");
        }
    }

    Ok(())
}

pub async fn dlp(socket_path: &Path, args: &[String]) -> Result<(), RiggsError> {
    let subcmd = args.first().map(|s| s.as_str()).unwrap_or("status");

    match subcmd {
        "status" => {
            let mut client = connect(socket_path).await?;
            let response = send(&mut client, &ClientMessage::DlpStatus).await?;
            match response {
                DaemonMessage::DlpStatus {
                    enabled,
                    tracked_pids,
                    tracked_accesses,
                    watched_domains,
                } => {
                    let status_color = if enabled { GREEN } else { DIM };
                    let status_text = if enabled { "active" } else { "disabled" };

                    println!("{BOLD}DLP Module{RESET}");
                    println!("{DIM}────────────────────────────────────{RESET}");
                    println!("  {BOLD}Status:{RESET}           {status_color}{status_text}{RESET}");
                    println!("  {BOLD}Watched domains:{RESET}  {watched_domains}");
                    println!("  {BOLD}Tracked PIDs:{RESET}     {tracked_pids}");
                    println!("  {BOLD}File accesses:{RESET}    {tracked_accesses}");
                }
                DaemonMessage::Error(e) => eprintln!("{RED}Error:{RESET} {e}"),
                _ => eprintln!("{RED}Unexpected response from daemon{RESET}"),
            }
        }
        "policy" => {
            // Read and display the DLP policy file directly
            let policy_paths = ["/etc/riggs/dlp-policy.toml", "config/dlp-policy.toml"];
            let policy_path = policy_paths.iter().find(|p| Path::new(p).exists());

            match policy_path {
                Some(path) => {
                    let contents = std::fs::read_to_string(path)
                        .map_err(|e| RiggsError::Io(format!("failed to read {path}: {e}")))?;
                    let config: serde_json::Value = toml::from_str(&contents)
                        .map_err(|e| RiggsError::Config(format!("failed to parse {path}: {e}")))?;

                    println!("{BOLD}DLP Policy{RESET} {DIM}({path}){RESET}");
                    println!("{DIM}────────────────────────────────────{RESET}");

                    if let Some(action) = config.get("action").and_then(|v| v.as_str()) {
                        let action_color = if action == "block" { RED } else { YELLOW };
                        println!("  {BOLD}Action:{RESET}           {action_color}{action}{RESET}");
                    }
                    if let Some(window) = config
                        .get("correlation_window_secs")
                        .and_then(|v| v.as_i64())
                    {
                        println!("  {BOLD}Window:{RESET}           {window}s");
                    }

                    println!();
                    println!("  {BOLD}Watched Domains:{RESET}");
                    if let Some(domains) = config.get("watched_domains").and_then(|v| v.as_array())
                    {
                        for d in domains {
                            let pattern = d.get("pattern").and_then(|v| v.as_str()).unwrap_or("?");
                            let category = d.get("category").and_then(|v| v.as_str()).unwrap_or("");
                            println!("    {CYAN}{pattern:<30}{RESET} {DIM}{category}{RESET}");
                        }
                    }

                    println!();
                    if let Some(ft) = config.get("file_types") {
                        if let Some(block) = ft.get("block").and_then(|v| v.as_array()) {
                            let types: Vec<&str> =
                                block.iter().filter_map(|v| v.as_str()).collect();
                            println!(
                                "  {BOLD}Blocked types:{RESET}    {RED}{}{RESET}",
                                types.join(", ")
                            );
                        }
                        if let Some(alert) = ft.get("alert").and_then(|v| v.as_array()) {
                            let types: Vec<&str> =
                                alert.iter().filter_map(|v| v.as_str()).collect();
                            println!(
                                "  {BOLD}Alert types:{RESET}      {YELLOW}{}{RESET}",
                                types.join(", ")
                            );
                        }
                    }

                    println!();
                    if let Some(excluded) = config.get("excluded_processes") {
                        if let Some(names) = excluded.get("names").and_then(|v| v.as_array()) {
                            let procs: Vec<&str> =
                                names.iter().filter_map(|v| v.as_str()).collect();
                            println!(
                                "  {BOLD}Excluded:{RESET}         {DIM}{}{RESET}",
                                procs.join(", ")
                            );
                        }
                    }
                }
                None => {
                    println!("{DIM}No DLP policy file found.{RESET}");
                    println!();
                    println!("Create one at /etc/riggs/dlp-policy.toml or config/dlp-policy.toml");
                    println!("See config/dlp-policy.toml in the repository for a template.");
                }
            }
        }
        cmd => {
            eprintln!("Unknown dlp subcommand: {cmd}");
            println!("Usage: riggs dlp [status|policy]");
        }
    }

    Ok(())
}

pub async fn egress(socket_path: &Path, args: &[String]) -> Result<(), RiggsError> {
    let subcmd = args.first().map(|s| s.as_str()).unwrap_or("status");

    match subcmd {
        "status" | "list" => {
            let mut client = connect(socket_path).await?;
            match send(&mut client, &ClientMessage::EgressStatus).await? {
                DaemonMessage::EgressStatus {
                    mode,
                    allow_domains,
                    process_rules,
                } => {
                    let (color, text) = match mode.as_str() {
                        "enforce" => (RED, "enforce"),
                        "monitor" => (YELLOW, "monitor"),
                        _ => (DIM, "off"),
                    };
                    println!("{BOLD}Egress Allowlist{RESET}");
                    println!("{DIM}────────────────────────────────────{RESET}");
                    println!("  {BOLD}Mode:{RESET}            {color}{text}{RESET}");
                    println!("  {BOLD}Allow domains:{RESET}   {allow_domains}");
                    println!("  {BOLD}Process rules:{RESET}   {process_rules}");
                }
                DaemonMessage::Error(e) => eprintln!("{RED}Error:{RESET} {e}"),
                _ => eprintln!("{RED}Unexpected response from daemon{RESET}"),
            }
        }
        "allow" | "deny" | "mode" => {
            let value = match args.get(1) {
                Some(v) => v.clone(),
                None => {
                    eprintln!("Usage: riggs egress {subcmd} <value>");
                    return Ok(());
                }
            };
            let msg = match subcmd {
                "allow" => ClientMessage::EgressAllow { domain: value },
                "deny" => ClientMessage::EgressDeny { domain: value },
                _ => ClientMessage::EgressSetMode { mode: value },
            };
            let mut client = connect(socket_path).await?;
            match send(&mut client, &msg).await? {
                DaemonMessage::Ok => println!("{GREEN}ok{RESET}"),
                DaemonMessage::Error(e) => eprintln!("{RED}Error:{RESET} {e}"),
                _ => eprintln!("{RED}Unexpected response from daemon{RESET}"),
            }
        }
        cmd => {
            eprintln!("Unknown egress subcommand: {cmd}");
            println!(
                "Usage: riggs egress [status | allow <domain> | deny <domain> | mode off|monitor|enforce]"
            );
        }
    }

    Ok(())
}

pub async fn vuln(socket_path: &Path, args: &[String]) -> Result<(), RiggsError> {
    let subcmd = args.first().map(|s| s.as_str()).unwrap_or("status");

    let mut client = connect(socket_path).await?;

    match subcmd {
        "update" => {
            println!("{BOLD}Refreshing vulnerability database from OSV.dev...{RESET}");
            let response = send(&mut client, &ClientMessage::VulnUpdate).await?;
            match response {
                DaemonMessage::Done(outcome) => println!("{GREEN}{outcome}{RESET}"),
                DaemonMessage::Error(e) => eprintln!("{RED}Error:{RESET} {e}"),
                _ => eprintln!("{RED}Unexpected response from daemon{RESET}"),
            }
        }
        cmd => {
            eprintln!("Unknown vuln subcommand: {cmd}");
            println!("Usage: riggs vuln update");
        }
    }

    Ok(())
}

pub async fn phishing(socket_path: &Path, args: &[String]) -> Result<(), RiggsError> {
    let sudo_uid = std::env::var("SUDO_UID").ok();
    let request = phishing_request(args, sudo_uid.as_deref(), unsafe { libc::getuid() })?;

    let mut client = connect(socket_path).await?;
    let unexpected = || RiggsError::Comms("Unexpected response from daemon".into());
    let response = match send(&mut client, &ClientMessage::Phishing(request)).await? {
        DaemonMessage::Phishing(PhishingResponse::Error(e)) | DaemonMessage::Error(e) => {
            return Err(RiggsError::Other(e));
        }
        DaemonMessage::Phishing(response) => response,
        _ => return Err(unexpected()),
    };

    match response {
        PhishingResponse::Status(status) => {
            let (color, mode) = match status.mode {
                Mode::Warn => (GREEN, "warn"),
                Mode::Monitor => (YELLOW, "monitor"),
                Mode::Off => (DIM, "off"),
            };
            println!("{BOLD}Phishing Protection{RESET}");
            println!("{DIM}────────────────────────────────────{RESET}");
            println!("  {BOLD}Mode:{RESET}     {color}{mode}{RESET}");
            println!("  {BOLD}Logins:{RESET}   {}", status.logins);
        }
        PhishingResponse::Recent(entries) => {
            if entries.is_empty() {
                println!("{DIM}No phishing checks recorded.{RESET}");
                return Ok(());
            }
            println!("{BOLD}Recent Phishing Checks{RESET}");
            println!("{DIM}─────────────────────────────────────────────────────────────────────────────{RESET}");
            println!(
                "  {BOLD}{:<20} {:<5} {:<30} {:<8} {:<6} CUES{RESET}",
                "TIME (UTC)", "KIND", "DOMAIN", "LEVEL", "SHOWN"
            );
            for entry in &entries {
                let kind = match entry.kind {
                    ObservationKind::Mail => "mail",
                    ObservationKind::Page => "page",
                };
                let (color, level) = match entry.level {
                    Level::Danger => (RED, "danger"),
                    Level::Caution => (YELLOW, "caution"),
                    Level::None => (DIM, "none"),
                };
                let shown = if entry.shown { "yes" } else { "no" };
                println!(
                    "  {:<20} {:<5} {:<30} {color}{:<8}{RESET} {:<6} {}",
                    utc_time(entry.time_ms),
                    kind,
                    entry.domain,
                    level,
                    shown,
                    entry.cues.join(", "),
                );
            }
        }
        PhishingResponse::Stats(mut stats) => {
            stats
                .cues
                .sort_by(|a, b| b.hits.cmp(&a.hits).then_with(|| a.cue.cmp(&b.cue)));
            println!("{BOLD}Phishing Statistics{RESET}");
            println!("{DIM}────────────────────────────────────{RESET}");
            println!("  {BOLD}Total:{RESET}     {}", stats.total);
            println!("  {BOLD}Caution:{RESET}   {YELLOW}{}{RESET}", stats.caution);
            println!("  {BOLD}Danger:{RESET}    {RED}{}{RESET}", stats.danger);
            if !stats.cues.is_empty() {
                println!();
                println!("  {BOLD}{:<40} HITS{RESET}", "CUE");
                for cue in &stats.cues {
                    println!("  {:<40} {}", cue.cue, cue.hits);
                }
            }
        }
        PhishingResponse::Logins(logins) => {
            if logins.is_empty() {
                println!("{DIM}No logins recorded.{RESET}");
                return Ok(());
            }
            println!("{BOLD}Known Logins{RESET}");
            println!("{DIM}─────────────────────────────────────────────────────────────────────────────{RESET}");
            println!(
                "  {BOLD}{:<30} {:<20} {:<20} COUNT{RESET}",
                "DOMAIN", "FIRST (UTC)", "LAST (UTC)"
            );
            for login in &logins {
                println!(
                    "  {:<30} {:<20} {:<20} {}",
                    login.domain,
                    utc_time(login.first_ms),
                    utc_time(login.last_ms),
                    login.count,
                );
            }
        }
        PhishingResponse::Ok => println!("{GREEN}ok{RESET}"),
        PhishingResponse::Verdict(_) | PhishingResponse::Error(_) => return Err(unexpected()),
    }

    Ok(())
}

fn phishing_request(
    args: &[String],
    sudo_uid: Option<&str>,
    own_uid: u32,
) -> Result<PhishingRequest, RiggsError> {
    let usage = || {
        RiggsError::Other(
            "Usage: riggs phishing [status | recent [--limit N] [--user UID] | stats [--user UID] \
             | logins [--user UID] | trust <domain> [--user UID] | forget <domain> [--user UID] \
             | mode off|monitor|warn]"
                .into(),
        )
    };

    let mut words = Vec::new();
    let mut user = None;
    let mut limit = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--user" => user = Some(rest.next().ok_or_else(usage)?.as_str()),
            "--limit" => {
                let value = rest.next().ok_or_else(usage)?;
                limit =
                    Some(value.parse::<u32>().map_err(|_| {
                        RiggsError::Other(format!("invalid --limit value: {value}"))
                    })?);
            }
            word => words.push(word),
        }
    }

    let uid = || target_uid(user, sudo_uid, own_uid);
    match (words.as_slice(), limit) {
        ([] | ["status"], None) if user.is_none() => Ok(PhishingRequest::Status),
        (["recent"], limit) => Ok(PhishingRequest::Recent {
            uid: uid()?,
            limit: limit.unwrap_or(50),
        }),
        (["stats"], None) => Ok(PhishingRequest::Stats { uid: uid()? }),
        (["logins"], None) => Ok(PhishingRequest::Logins { uid: uid()? }),
        (["trust", domain], None) => Ok(PhishingRequest::Trust {
            uid: uid()?,
            domain: domain.to_string(),
        }),
        (["forget", domain], None) => Ok(PhishingRequest::Forget {
            uid: uid()?,
            domain: domain.to_string(),
        }),
        (["mode", mode], None) if user.is_none() => Ok(PhishingRequest::SetMode {
            mode: serde_json::from_value(serde_json::Value::from(*mode)).map_err(|_| usage())?,
        }),
        _ => Err(usage()),
    }
}

/// The local user whose phishing state an admin request targets. The daemon runs
/// as root on an installed host, so under `sudo` this is the invoking user.
fn target_uid(user: Option<&str>, sudo_uid: Option<&str>, own_uid: u32) -> Result<u32, RiggsError> {
    match user {
        Some(user) => user.parse().map_err(|_| {
            RiggsError::Other(format!("invalid --user value: {user} (expected a uid)"))
        }),
        None => Ok(sudo_uid.and_then(|uid| uid.parse().ok()).unwrap_or(own_uid)),
    }
}

/// Milliseconds since the Unix epoch in UTC, formatted like `events`; the raw
/// number when chrono cannot represent it.
fn utc_time(ms: u64) -> String {
    i64::try_from(ms)
        .ok()
        .and_then(chrono::DateTime::from_timestamp_millis)
        .map_or_else(
            || ms.to_string(),
            |time| time.format("%Y-%m-%d %H:%M:%S").to_string(),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(line: &str) -> Vec<String> {
        line.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn target_uid_is_the_user_flag_then_sudo_uid_then_own_uid() {
        assert_eq!(target_uid(Some("1000"), Some("501"), 0).unwrap(), 1000);
        assert_eq!(target_uid(None, Some("501"), 0).unwrap(), 501);
        assert_eq!(target_uid(None, None, 502).unwrap(), 502);
        assert_eq!(target_uid(None, Some("not-a-uid"), 502).unwrap(), 502);
        assert!(target_uid(Some("alice"), Some("501"), 0).is_err());
        assert!(target_uid(Some("-1"), None, 502).is_err());
    }

    #[test]
    fn each_phishing_subcommand_builds_its_request() {
        let trust = |uid| PhishingRequest::Trust {
            uid,
            domain: "example.com".into(),
        };
        let cases = [
            ("", PhishingRequest::Status),
            ("status", PhishingRequest::Status),
            (
                "recent",
                PhishingRequest::Recent {
                    uid: 501,
                    limit: 50,
                },
            ),
            (
                "recent --limit 5 --user 1000",
                PhishingRequest::Recent {
                    uid: 1000,
                    limit: 5,
                },
            ),
            ("stats", PhishingRequest::Stats { uid: 501 }),
            ("stats --user 1000", PhishingRequest::Stats { uid: 1000 }),
            ("logins", PhishingRequest::Logins { uid: 501 }),
            ("logins --user 1000", PhishingRequest::Logins { uid: 1000 }),
            ("trust example.com", trust(501)),
            ("trust --user 1000 example.com", trust(1000)),
            (
                "forget example.com",
                PhishingRequest::Forget {
                    uid: 501,
                    domain: "example.com".into(),
                },
            ),
            ("mode off", PhishingRequest::SetMode { mode: Mode::Off }),
            (
                "mode monitor",
                PhishingRequest::SetMode {
                    mode: Mode::Monitor,
                },
            ),
            ("mode warn", PhishingRequest::SetMode { mode: Mode::Warn }),
        ];
        for (line, expected) in cases {
            let request = phishing_request(&args(line), Some("501"), 0).unwrap();
            assert_eq!(request, expected, "{line}");
        }
    }

    #[test]
    fn malformed_phishing_arguments_are_refused() {
        for line in [
            "bogus",
            "trust",
            "trust example.com example.org",
            "mode",
            "mode loud",
            "mode warn --user 1000",
            "status --user 1000",
            "stats --limit 5",
            "recent --limit many",
            "logins --user",
            "logins --user alice",
        ] {
            assert!(phishing_request(&args(line), None, 501).is_err(), "{line}");
        }
    }

    #[test]
    fn utc_time_formats_epoch_milliseconds() {
        assert_eq!(utc_time(0), "1970-01-01 00:00:00");
        assert_eq!(utc_time(951_782_400_000), "2000-02-29 00:00:00");
        assert_eq!(utc_time(1_700_000_000_999), "2023-11-14 22:13:20");
        assert_eq!(utc_time(i64::MAX as u64), i64::MAX.to_string());
        assert_eq!(utc_time(u64::MAX), u64::MAX.to_string());
    }
}

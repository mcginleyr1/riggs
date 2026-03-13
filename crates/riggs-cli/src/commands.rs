use std::path::Path;

use riggs_comms::{ClientMessage, DaemonMessage, IpcClient};
use riggs_types::errors::RiggsError;

const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

async fn connect(socket_path: &Path) -> Result<IpcClient, RiggsError> {
    IpcClient::connect(socket_path)
        .await
        .map_err(|_| RiggsError::Comms(format!(
            "Could not connect to daemon at {}\nIs the riggs daemon running?",
            socket_path.display()
        )))
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
        DaemonMessage::Status { running, events_processed, active_threats } => {
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
                    threat.event_id,
                    threat.final_threat_level,
                    sources_str,
                    threat.storyline_id,
                );
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
            "--storyline" | "-s" => {
                if i + 1 < args.len() {
                    storyline_id = Some(args[i + 1].clone());
                    i += 2;
                    continue;
                }
            }
            "--limit" | "-n" => {
                if i + 1 < args.len() {
                    limit = args[i + 1]
                        .parse()
                        .map_err(|_| RiggsError::Other("Invalid limit value".into()))?;
                    i += 2;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }

    let mut client = connect(socket_path).await?;
    let msg = ClientMessage::QueryEvents { storyline_id, limit };
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
            };
            ("FILE", format!("{} {}", action, e.path))
        }
        RiggsEvent::Network(e) => {
            let dir = match e.direction {
                riggs_types::events::NetworkDirection::Inbound => "in",
                riggs_types::events::NetworkDirection::Outbound => "out",
            };
            ("NETWORK", format!("{} {}:{} -> {}:{}", dir, e.src_addr, e.src_port, e.dst_addr, e.dst_port))
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
            DaemonMessage::Ok => println!("{GREEN}Configuration updated.{RESET}"),
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
    let path = args.first().map(|s| s.as_str()).unwrap_or(".");

    let mut client = connect(socket_path).await?;
    let msg = ClientMessage::TriggerScan {
        path: path.to_string(),
    };

    println!("{BOLD}Requesting scan:{RESET} {path}");

    let response = send(&mut client, &msg).await?;
    match response {
        DaemonMessage::Ok => {
            println!("{GREEN}Scan initiated successfully.{RESET}");
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
    let _ = args;
    let mut client = connect(socket_path).await?;
    let response = send(&mut client, &ClientMessage::GetStatus).await?;

    match response {
        DaemonMessage::Status { .. } => {
            println!("{BOLD}Quarantine{RESET}");
            println!("{DIM}────────────────────────────────────{RESET}");
            println!("  {DIM}No quarantined files.{RESET}");
        }
        DaemonMessage::Error(e) => eprintln!("{RED}Error:{RESET} {e}"),
        _ => eprintln!("{RED}Unexpected response from daemon{RESET}"),
    }

    Ok(())
}

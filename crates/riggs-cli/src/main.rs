use std::env;
use std::path::PathBuf;

mod commands;

const DEFAULT_SOCKET_PATH: &str = "/var/run/riggs.sock";

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    let mut socket_path = PathBuf::from(
        env::var("RIGGS_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string()),
    );
    let mut cmd_args: Vec<String> = Vec::new();
    let mut found_command = false;

    let mut i = 1;
    while i < args.len() {
        if !found_command && args[i] == "--socket" {
            if i + 1 < args.len() {
                socket_path = PathBuf::from(&args[i + 1]);
                i += 2;
                continue;
            } else {
                eprintln!("Error: --socket requires a path argument");
                std::process::exit(1);
            }
        }
        if !found_command {
            found_command = true;
            cmd_args.push(args[i].clone());
        } else {
            cmd_args.push(args[i].clone());
        }
        i += 1;
    }

    if cmd_args.is_empty() {
        print_usage();
        return;
    }

    let result = match cmd_args[0].as_str() {
        "status" => commands::status(&socket_path).await,
        "threats" => commands::threats(&socket_path).await,
        "events" => commands::events(&socket_path, &cmd_args[1..]).await,
        "config" => commands::config(&socket_path, &cmd_args[1..]).await,
        "scan" => commands::scan(&socket_path, &cmd_args[1..]).await,
        "quarantine" => commands::quarantine(&socket_path, &cmd_args[1..]).await,
        "intel" => commands::intel(&socket_path, &cmd_args[1..]).await,
        "dlp" => commands::dlp(&socket_path, &cmd_args[1..]).await,
        "egress" => commands::egress(&socket_path, &cmd_args[1..]).await,
        "vuln" => commands::vuln(&socket_path, &cmd_args[1..]).await,
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        cmd => {
            eprintln!("Unknown command: {cmd}");
            print_usage();
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn print_usage() {
    println!("riggs - Endpoint Protection System");
    println!();
    println!("Usage: riggs [--socket <path>] <command> [options]");
    println!();
    println!("Options:");
    println!("  --socket <path>  Override daemon socket path (default: {})", DEFAULT_SOCKET_PATH);
    println!();
    println!("Commands:");
    println!("  status       Show daemon status and active threats");
    println!("  threats      List detected threats");
    println!("  events       Query event log");
    println!("  config       View/update configuration");
    println!("  scan <path>  Trigger on-demand scan");
    println!("  quarantine   Manage quarantined files");
    println!("  intel        Threat intelligence management");
    println!("  dlp          Data loss prevention status and policy");
    println!("  egress       Default-deny egress allowlist (status/allow/deny/mode)");
    println!("  vuln         Vulnerability feed management");
    println!("  help         Show this help message");
}

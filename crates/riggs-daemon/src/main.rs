use tracing::{error, info};
use tracing_subscriber::EnvFilter;

mod daemon;
mod supervisor;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_banner() {
    let banner = format!(
        r#"
  ____  _
 |  _ \(_) __ _  __ _ ___
 | |_) | |/ _` |/ _` / __|
 |  _ <| | (_| | (_| \__ \
 |_| \_\_|\__, |\__, |___/
          |___/ |___/
  Endpoint Protection Daemon v{VERSION}
"#
    );
    eprintln!("{banner}");
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("riggs=info".parse().unwrap()),
        )
        .init();

    print_banner();
    info!(version = VERSION, "riggs daemon starting");

    // SIGTERM and SIGINT are both handled inside RiggsDaemon::run so that either
    // signal runs the same graceful shutdown path.
    if let Err(e) = run_daemon().await {
        error!("daemon fatal error: {e}");
        std::process::exit(1);
    }
}

async fn run_daemon() -> Result<(), riggs_types::errors::RiggsError> {
    let mut daemon = daemon::RiggsDaemon::new().await?;
    daemon.run().await
}

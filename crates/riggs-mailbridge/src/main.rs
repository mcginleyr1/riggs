//! Per-user loopback HTTPS endpoint for the Outlook add-in: serves the task pane's files and
//! forwards its mail observations to the Riggs daemon's Unix socket as the user it runs as.

use std::num::NonZeroU16;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{bail, Context};

mod server;
mod setup;

const DEFAULT_SOCKET: &str = "/var/run/riggs.sock";
const USAGE: &str = "usage:
  riggs-mailbridge setup --dir <state dir> --assets <assets dir> [--port <n>] [--renew]
  riggs-mailbridge run --dir <state dir> --assets <assets dir>";

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .init();
    match command(std::env::args().skip(1).collect()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("riggs-mailbridge: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn command(args: Vec<String>) -> anyhow::Result<()> {
    let (command, options) = args.split_first().context(USAGE)?;
    let (mut dir, mut assets, mut port, mut renew) = (None, None, None, false);
    let mut options = options.iter();
    while let Some(option) = options.next() {
        match option.as_str() {
            "--dir" => dir = options.next().map(PathBuf::from),
            "--assets" => assets = options.next().map(PathBuf::from),
            "--port" if command == "setup" => {
                let value = options.next().and_then(|n| n.parse::<NonZeroU16>().ok());
                port = Some(
                    value
                        .context("--port takes a number from 1 to 65535")?
                        .get(),
                );
            }
            "--renew" if command == "setup" => renew = true,
            _ => bail!("unexpected argument {option:?}\n{USAGE}"),
        }
    }
    let (Some(dir), Some(assets)) = (dir, assets) else {
        bail!(USAGE)
    };
    match command.as_str() {
        "setup" => print!("{}", setup::setup(&dir, &assets, port, renew)?),
        "run" => {
            let socket = std::env::var_os("RIGGS_SOCKET")
                .map_or_else(|| PathBuf::from(DEFAULT_SOCKET), PathBuf::from);
            let (bridge, tls) = server::load(&dir, &assets, socket)?;
            let listener = server::bind(bridge.port).await?;
            server::serve(listener, tls, Arc::new(bridge)).await?;
        }
        _ => bail!(USAGE),
    }
    Ok(())
}

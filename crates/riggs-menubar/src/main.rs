#[cfg(target_os = "macos")]
mod app;
#[cfg(target_os = "macos")]
mod poller;
#[cfg(target_os = "macos")]
mod status;

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("Menu bar app is macOS only");
}

#[cfg(target_os = "macos")]
fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let shared_status = std::sync::Arc::new(std::sync::Mutex::new(status::DaemonStatus::default()));

    poller::spawn_poller(shared_status.clone());

    app::run_app(shared_status);
}

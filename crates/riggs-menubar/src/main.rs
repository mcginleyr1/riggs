#[cfg(target_os = "macos")]
mod app;
mod poller;
mod status;

fn main() {
    #[cfg(not(target_os = "macos"))]
    {
        println!("Menu bar app is macOS only");
        return;
    }

    #[cfg(target_os = "macos")]
    {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .init();

        let shared_status = std::sync::Arc::new(std::sync::Mutex::new(
            status::DaemonStatus::default(),
        ));

        poller::spawn_poller(shared_status.clone());

        app::run_app(shared_status);
    }
}

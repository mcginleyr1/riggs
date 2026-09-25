use std::collections::HashSet;

use async_trait::async_trait;
use notify::Watcher;
use riggs_platform::{NetworkContainment, PlatformCapabilities, PlatformSensor, ProcessControl};
use riggs_types::errors::RiggsError;
use riggs_types::events::{FileAction, ProcessAction, ProcessContext, RiggsEvent, StorylineId};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::sync::mpsc;
use tracing::info;

pub struct MacOsSensor {
    running: bool,
    pf_conf_path: String,
}

impl MacOsSensor {
    pub fn new() -> Self {
        Self {
            running: false,
            pf_conf_path: DEFAULT_PF_CONF_PATH.to_string(),
        }
    }

    /// Override the path the network-containment pf ruleset is written to.
    pub fn with_pf_conf_path(mut self, path: String) -> Self {
        if !path.is_empty() {
            self.pf_conf_path = path;
        }
        self
    }
}

impl Default for MacOsSensor {
    fn default() -> Self {
        Self::new()
    }
}

fn send_signal(pid: u32, signal: libc::c_int, signal_name: &str) -> Result<(), RiggsError> {
    // Never signal pid 0 (the caller's entire process group -- would kill the
    // daemon itself) or pid 1 (init). Response actions must carry a real target.
    if pid <= 1 {
        return Err(RiggsError::Platform(format!(
            "refusing to send {signal_name} to pid {pid}: pid 0 signals the daemon's own process group, pid 1 is init"
        )));
    }
    let ret = unsafe { libc::kill(pid as i32, signal) };
    if ret == -1 {
        let err = std::io::Error::last_os_error();
        Err(RiggsError::Platform(format!(
            "failed to send {} to pid {}: {}",
            signal_name, pid, err
        )))
    } else {
        Ok(())
    }
}

fn build_process_context(process: &sysinfo::Process, pid: u32) -> ProcessContext {
    ProcessContext::new(
        pid,
        process.parent().map(|p| p.as_u32()).unwrap_or(0),
        process.name().to_string_lossy().to_string(),
        process
            .exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default(),
        process
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" "),
        process
            .user_id()
            .map(|u| u.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        StorylineId::new(),
    )
}

#[async_trait]
impl PlatformSensor for MacOsSensor {
    fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities {
            process_monitoring: true,
            file_monitoring: true,
            network_monitoring: true,
            dns_monitoring: true,
            auth_monitoring: true,
            kernel_monitoring: false,
        }
    }

    async fn start(&mut self, tx: mpsc::Sender<RiggsEvent>) -> Result<(), RiggsError> {
        info!("Starting macOS sensor (MVP: notify + sysinfo polling)");
        self.running = true;

        // -- File monitoring via notify (FSEvents on macOS) --
        let file_tx = tx.clone();
        let (notify_tx, mut notify_rx) =
            tokio::sync::mpsc::channel::<notify::Result<notify::Event>>(1024);

        let mut watcher = notify::RecommendedWatcher::new(
            move |result: notify::Result<notify::Event>| {
                let _ = notify_tx.blocking_send(result);
            },
            notify::Config::default(),
        )
        .map_err(|e| RiggsError::Platform(format!("failed to create file watcher: {e}")))?;

        for dir in ["/tmp", "/Users", "/Applications"] {
            let path = std::path::Path::new(dir);
            if path.exists() {
                let _ = watcher.watch(path, notify::RecursiveMode::Recursive);
            }
        }

        tokio::spawn(async move {
            let _watcher = watcher; // prevent drop while task runs
            while let Some(result) = notify_rx.recv().await {
                let Ok(event) = result else { continue };
                let action = match event.kind {
                    notify::EventKind::Create(_) => Some(FileAction::Create),
                    notify::EventKind::Modify(_) => Some(FileAction::Modify),
                    notify::EventKind::Remove(_) => Some(FileAction::Delete),
                    _ => None,
                };
                if let Some(action) = action {
                    for path in &event.paths {
                        let ctx = ProcessContext::new(
                            0,
                            0,
                            "unknown",
                            "unknown",
                            "",
                            "unknown",
                            StorylineId::new(),
                        );
                        let riggs_event = RiggsEvent::new_file(
                            action,
                            ctx,
                            path.to_string_lossy().to_string(),
                            None,
                        );
                        if file_tx.send(riggs_event).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });

        // -- Process monitoring via sysinfo polling --
        let proc_tx = tx;
        tokio::spawn(async move {
            let mut sys = System::new();
            let mut known_pids: HashSet<u32> = HashSet::new();

            // Capture the initial set of running PIDs
            sys.refresh_processes_specifics(
                ProcessesToUpdate::All,
                true,
                ProcessRefreshKind::everything(),
            );
            for pid in sys.processes().keys() {
                known_pids.insert(pid.as_u32());
            }

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                interval.tick().await;
                sys.refresh_processes_specifics(
                    ProcessesToUpdate::All,
                    true,
                    ProcessRefreshKind::everything(),
                );

                let current_pids: HashSet<u32> =
                    sys.processes().keys().map(|p| p.as_u32()).collect();

                // Detect newly spawned processes
                for &pid in current_pids.difference(&known_pids) {
                    if let Some(process) = sys.process(Pid::from_u32(pid)) {
                        let ctx = build_process_context(process, pid);
                        let event = RiggsEvent::new_process(ProcessAction::Exec, ctx, None);
                        if proc_tx.send(event).await.is_err() {
                            return;
                        }
                    }
                }

                // Detect exited processes
                for &pid in known_pids.difference(&current_pids) {
                    let ctx = ProcessContext::new(
                        pid,
                        0,
                        "exited",
                        "",
                        "",
                        "unknown",
                        StorylineId::new(),
                    );
                    let event = RiggsEvent::new_process(ProcessAction::Exit, ctx, None);
                    if proc_tx.send(event).await.is_err() {
                        return;
                    }
                }

                known_pids = current_pids;
            }
        });

        Ok(())
    }

    async fn stop(&mut self) -> Result<(), RiggsError> {
        info!("Stopping macOS sensor");
        self.running = false;
        Ok(())
    }

    async fn process_context(&self, pid: u32) -> Result<Option<ProcessContext>, RiggsError> {
        let mut sys = System::new();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[Pid::from_u32(pid)]),
            true,
            ProcessRefreshKind::everything(),
        );
        let Some(process) = sys.process(Pid::from_u32(pid)) else {
            return Ok(None);
        };
        Ok(Some(build_process_context(process, pid)))
    }

    async fn health_check(&self) -> Result<bool, RiggsError> {
        Ok(self.running)
    }
}

#[async_trait]
impl ProcessControl for MacOsSensor {
    async fn kill_process(&self, pid: u32) -> Result<(), RiggsError> {
        send_signal(pid, libc::SIGKILL, "SIGKILL")
    }

    async fn suspend_process(&self, pid: u32) -> Result<(), RiggsError> {
        send_signal(pid, libc::SIGSTOP, "SIGSTOP")
    }

    async fn resume_process(&self, pid: u32) -> Result<(), RiggsError> {
        send_signal(pid, libc::SIGCONT, "SIGCONT")
    }
}

const PF_ANCHOR: &str = "riggs-containment";
// Default off the world-writable /tmp (a symlink/pre-create there let a local
// user influence the ruleset). Overridable via response.pf_conf_path.
const DEFAULT_PF_CONF_PATH: &str = "/var/lib/riggs/pf-containment.conf";

#[async_trait]
impl NetworkContainment for MacOsSensor {
    async fn contain(&self, allowed_ips: &[std::net::IpAddr]) -> Result<(), RiggsError> {
        let mut rules = String::from("# riggs containment rules\nblock all\n");
        for ip in allowed_ips {
            rules.push_str(&format!("pass out quick to {ip}\n"));
        }
        rules.push_str("pass quick on lo0 all\n");

        std::fs::write(&self.pf_conf_path, &rules)
            .map_err(|e| RiggsError::Platform(format!("failed to write pf rules: {e}")))?;

        let output = std::process::Command::new("pfctl")
            .args(["-a", PF_ANCHOR, "-f", self.pf_conf_path.as_str()])
            .output()
            .map_err(|e| RiggsError::Platform(format!("failed to run pfctl: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(RiggsError::Platform(format!("pfctl load failed: {stderr}")));
        }

        // Ensure pf is enabled (idempotent; ignore errors if already on)
        let _ = std::process::Command::new("pfctl").arg("-e").output();

        info!("network containment activated");
        Ok(())
    }

    async fn release(&self) -> Result<(), RiggsError> {
        let output = std::process::Command::new("pfctl")
            .args(["-a", PF_ANCHOR, "-F", "all"])
            .output()
            .map_err(|e| RiggsError::Platform(format!("failed to run pfctl: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(RiggsError::Platform(format!(
                "pfctl flush failed: {stderr}"
            )));
        }

        // Clean up the rules file
        let _ = std::fs::remove_file(&self.pf_conf_path);

        info!("network containment released");
        Ok(())
    }

    async fn is_contained(&self) -> Result<bool, RiggsError> {
        let output = std::process::Command::new("pfctl")
            .args(["-a", PF_ANCHOR, "-sr"])
            .output()
            .map_err(|e| RiggsError::Platform(format!("failed to query pfctl: {e}")))?;

        let rules = String::from_utf8_lossy(&output.stdout);
        Ok(!rules.trim().is_empty())
    }
}

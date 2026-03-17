use std::collections::HashSet;

use async_trait::async_trait;
use notify::Watcher;
use riggs_platform::{NetworkContainment, PlatformCapabilities, PlatformSensor, ProcessControl};
use riggs_types::errors::RiggsError;
use riggs_types::events::{FileAction, ProcessAction, ProcessContext, RiggsEvent, StorylineId};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::sync::mpsc;
use tracing::info;

pub struct LinuxSensor {
    running: bool,
}

impl LinuxSensor {
    pub fn new() -> Self {
        Self { running: false }
    }

    fn send_signal(&self, pid: u32, signal: libc::c_int) -> Result<(), RiggsError> {
        let ret = unsafe { libc::kill(pid as libc::pid_t, signal) };
        if ret == 0 {
            Ok(())
        } else {
            Err(RiggsError::Platform(format!(
                "kill({pid}, {signal}) failed: {}",
                std::io::Error::last_os_error()
            )))
        }
    }
}

impl Default for LinuxSensor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PlatformSensor for LinuxSensor {
    fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities {
            process_monitoring: true,
            file_monitoring: true,
            network_monitoring: true,
            dns_monitoring: true,
            auth_monitoring: true,
            kernel_monitoring: true,
        }
    }

    async fn start(&mut self, tx: mpsc::Sender<RiggsEvent>) -> Result<(), RiggsError> {
        info!("Starting Linux sensor (MVP: notify + sysinfo polling)");
        self.running = true;

        // -- File monitoring via notify (inotify on Linux) --
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

        for dir in ["/tmp", "/home", "/etc", "/usr/bin"] {
            let path = std::path::Path::new(dir);
            if path.exists() {
                let _ = watcher.watch(path, notify::RecursiveMode::Recursive);
            }
        }

        tokio::spawn(async move {
            let _watcher = watcher; // keep watcher alive for the lifetime of this task
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

                // New processes
                for &pid in current_pids.difference(&known_pids) {
                    if let Some(process) = sys.process(Pid::from_u32(pid)) {
                        let ctx = ProcessContext::new(
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
                        );
                        let event =
                            RiggsEvent::new_process(ProcessAction::Exec, ctx, None);
                        if proc_tx.send(event).await.is_err() {
                            return;
                        }
                    }
                }

                // Exited processes
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
                    let event =
                        RiggsEvent::new_process(ProcessAction::Exit, ctx, None);
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
        info!("Stopping Linux sensor");
        self.running = false;
        Ok(())
    }

    async fn process_context(&self, pid: u32) -> Result<Option<ProcessContext>, RiggsError> {
        let proc_path = std::path::PathBuf::from(format!("/proc/{pid}"));
        if !proc_path.exists() {
            return Ok(None);
        }

        let name = std::fs::read_to_string(proc_path.join("comm"))
            .unwrap_or_default()
            .trim()
            .to_string();

        let exe = std::fs::read_link(proc_path.join("exe"))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let cmdline = std::fs::read_to_string(proc_path.join("cmdline"))
            .unwrap_or_default()
            .replace('\0', " ")
            .trim()
            .to_string();

        let status = std::fs::read_to_string(proc_path.join("status")).unwrap_or_default();
        let mut ppid: u32 = 0;
        let mut uid_str = String::from("unknown");
        for line in status.lines() {
            if let Some(val) = line.strip_prefix("PPid:\t") {
                ppid = val.trim().parse().unwrap_or(0);
            } else if let Some(val) = line.strip_prefix("Uid:\t") {
                uid_str = val.split_whitespace().next().unwrap_or("unknown").to_string();
            }
        }

        Ok(Some(ProcessContext::new(
            pid,
            ppid,
            name,
            exe,
            cmdline,
            uid_str,
            StorylineId::new(),
        )))
    }

    async fn health_check(&self) -> Result<bool, RiggsError> {
        Ok(self.running)
    }
}

#[async_trait]
impl ProcessControl for LinuxSensor {
    async fn kill_process(&self, pid: u32) -> Result<(), RiggsError> {
        info!(pid, "Sending SIGKILL");
        self.send_signal(pid, libc::SIGKILL)
    }

    async fn suspend_process(&self, pid: u32) -> Result<(), RiggsError> {
        info!(pid, "Sending SIGSTOP");
        self.send_signal(pid, libc::SIGSTOP)
    }

    async fn resume_process(&self, pid: u32) -> Result<(), RiggsError> {
        info!(pid, "Sending SIGCONT");
        self.send_signal(pid, libc::SIGCONT)
    }
}

#[async_trait]
impl NetworkContainment for LinuxSensor {
    async fn contain(&self, allowed_ips: &[std::net::IpAddr]) -> Result<(), RiggsError> {
        let mut rules = String::from("flush ruleset\ntable inet riggs_containment {\n  chain input {\n    type filter hook input priority 0; policy drop;\n    ct state established,related accept\n    iif lo accept\n");
        for ip in allowed_ips {
            rules.push_str(&format!("    ip saddr {ip} accept\n    ip daddr {ip} accept\n"));
        }
        rules.push_str("  }\n  chain output {\n    type filter hook output priority 0; policy drop;\n    ct state established,related accept\n    oif lo accept\n");
        for ip in allowed_ips {
            rules.push_str(&format!("    ip daddr {ip} accept\n    ip saddr {ip} accept\n"));
        }
        rules.push_str("  }\n}\n");

        let output = std::process::Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(rules.as_bytes())?;
                }
                child.wait_with_output()
            })
            .map_err(|e| RiggsError::Platform(format!("nft command failed: {e}")))?;

        if output.status.success() {
            info!("Network containment enabled via nftables");
            Ok(())
        } else {
            Err(RiggsError::Platform(format!(
                "nft failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    async fn release(&self) -> Result<(), RiggsError> {
        let output = std::process::Command::new("nft")
            .args(["delete", "table", "inet", "riggs_containment"])
            .output()
            .map_err(|e| RiggsError::Platform(format!("nft command failed: {e}")))?;

        if output.status.success() {
            info!("Network containment released");
            Ok(())
        } else {
            Err(RiggsError::Platform(format!(
                "nft failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    async fn is_contained(&self) -> Result<bool, RiggsError> {
        let output = std::process::Command::new("nft")
            .args(["list", "tables"])
            .output()
            .map_err(|e| RiggsError::Platform(format!("nft command failed: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.contains("riggs_containment"))
    }
}

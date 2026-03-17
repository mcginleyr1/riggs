use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::task::JoinHandle;
use tracing::{error, info, warn};

type TaskFactory = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

#[allow(dead_code)]
struct TaskEntry {
    handle: JoinHandle<()>,
    factory: TaskFactory,
    restart_count: u32,
    max_restarts: u32,
}

pub struct Supervisor {
    tasks: HashMap<String, TaskEntry>,
}

impl Supervisor {
    pub fn new() -> Self {
        Self {
            tasks: HashMap::new(),
        }
    }

    pub fn spawn<F>(&mut self, name: impl Into<String>, factory: F)
    where
        F: Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync + 'static,
    {
        let name = name.into();
        info!(task = %name, "supervisor: spawning task");
        let factory = Arc::new(factory) as TaskFactory;
        let handle = tokio::spawn((factory)());
        self.tasks.insert(
            name,
            TaskEntry {
                handle,
                factory,
                restart_count: 0,
                max_restarts: 5,
            },
        );
    }

    #[allow(dead_code)]
    pub async fn check_health(&mut self) {
        let mut to_restart = Vec::new();

        for (name, entry) in &self.tasks {
            if entry.handle.is_finished() {
                if entry.restart_count < entry.max_restarts {
                    to_restart.push(name.clone());
                } else {
                    error!(task = %name, "task exceeded max restarts, not restarting");
                }
            }
        }

        for name in to_restart {
            if let Some(entry) = self.tasks.get_mut(&name) {
                entry.restart_count += 1;
                warn!(
                    task = %name,
                    restart = entry.restart_count,
                    max = entry.max_restarts,
                    "task died, restarting"
                );
                let new_handle = tokio::spawn((entry.factory)());
                entry.handle = new_handle;
            }
        }
    }

    pub fn shutdown_all(&mut self) {
        info!(count = self.tasks.len(), "supervisor: shutting down all tasks");
        for (name, entry) in self.tasks.drain() {
            info!(task = %name, "aborting task");
            entry.handle.abort();
        }
    }
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

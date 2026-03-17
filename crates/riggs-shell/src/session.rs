use chrono::{DateTime, Utc};
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use riggs_types::errors::RiggsError;
use tracing::info;
use uuid::Uuid;

use crate::auth::ShellAuth;

pub struct ShellSession {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub user: String,
    _auth: ShellAuth,
    master: Option<Box<dyn MasterPty + Send>>,
    child: Option<Box<dyn Child + Send + Sync>>,
}

impl ShellSession {
    pub fn new(auth: ShellAuth) -> Result<Self, RiggsError> {
        Ok(Self {
            id: Uuid::now_v7(),
            created_at: Utc::now(),
            user: String::from("unknown"),
            _auth: auth,
            master: None,
            child: None,
        })
    }

    pub async fn start(&mut self) -> Result<(), RiggsError> {
        let pty_system = native_pty_system();

        let pair = pty_system
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| RiggsError::Platform(format!("failed to open PTY: {e}")))?;

        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".to_string());
        let cmd = CommandBuilder::new(&shell);

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| RiggsError::Platform(format!("failed to spawn shell: {e}")))?;

        info!(
            session_id = %self.id,
            shell = %shell,
            "shell session started"
        );

        self.master = Some(pair.master);
        self.child = Some(child);

        Ok(())
    }

    pub async fn stop(&mut self) -> Result<(), RiggsError> {
        if let Some(mut child) = self.child.take() {
            child
                .kill()
                .map_err(|e| RiggsError::Platform(format!("failed to kill shell process: {e}")))?;
            let _ = child.wait();
        }

        self.master.take();

        info!(session_id = %self.id, "shell session stopped");
        Ok(())
    }
}

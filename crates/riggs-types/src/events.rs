use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EventId(pub Uuid);

impl EventId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for EventId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct StorylineId(pub Uuid);

impl StorylineId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for StorylineId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for StorylineId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessContext {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: String,
    pub cmdline: String,
    pub user: String,
    pub storyline_id: StorylineId,
}

impl ProcessContext {
    pub fn new(
        pid: u32,
        ppid: u32,
        name: impl Into<String>,
        path: impl Into<String>,
        cmdline: impl Into<String>,
        user: impl Into<String>,
        storyline_id: StorylineId,
    ) -> Self {
        Self {
            pid,
            ppid,
            name: name.into(),
            path: path.into(),
            cmdline: cmdline.into(),
            user: user.into(),
            storyline_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiggsEvent {
    Process(ProcessEvent),
    File(FileEvent),
    Network(NetworkEvent),
    Dns(DnsEvent),
    Auth(AuthEvent),
    Kernel(KernelEvent),
}

impl RiggsEvent {
    pub fn event_id(&self) -> &EventId {
        match self {
            RiggsEvent::Process(e) => &e.event_id,
            RiggsEvent::File(e) => &e.event_id,
            RiggsEvent::Network(e) => &e.event_id,
            RiggsEvent::Dns(e) => &e.event_id,
            RiggsEvent::Auth(e) => &e.event_id,
            RiggsEvent::Kernel(e) => &e.event_id,
        }
    }

    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            RiggsEvent::Process(e) => e.timestamp,
            RiggsEvent::File(e) => e.timestamp,
            RiggsEvent::Network(e) => e.timestamp,
            RiggsEvent::Dns(e) => e.timestamp,
            RiggsEvent::Auth(e) => e.timestamp,
            RiggsEvent::Kernel(e) => e.timestamp,
        }
    }

    pub fn process_context(&self) -> &ProcessContext {
        match self {
            RiggsEvent::Process(e) => &e.process_context,
            RiggsEvent::File(e) => &e.process_context,
            RiggsEvent::Network(e) => &e.process_context,
            RiggsEvent::Dns(e) => &e.process_context,
            RiggsEvent::Auth(e) => &e.process_context,
            RiggsEvent::Kernel(e) => &e.process_context,
        }
    }

    pub fn storyline_id(&self) -> &StorylineId {
        &self.process_context().storyline_id
    }

    pub fn severity(&self) -> Severity {
        match self {
            RiggsEvent::Process(e) => match e.action {
                ProcessAction::Exec => Severity::Info,
                ProcessAction::Fork => Severity::Info,
                ProcessAction::Exit => Severity::Info,
            },
            RiggsEvent::File(e) => match e.action {
                FileAction::Open | FileAction::Close => Severity::Info,
                FileAction::Create | FileAction::Modify | FileAction::Rename => Severity::Low,
                FileAction::Delete => Severity::Medium,
            },
            RiggsEvent::Network(e) => match e.direction {
                NetworkDirection::Outbound => Severity::Low,
                NetworkDirection::Inbound => Severity::Medium,
            },
            RiggsEvent::Dns(_) => Severity::Info,
            RiggsEvent::Auth(e) => match e.action {
                AuthAction::Login | AuthAction::Logout => Severity::Info,
                AuthAction::Failed => Severity::Medium,
                AuthAction::Escalation => Severity::High,
            },
            RiggsEvent::Kernel(e) => match e.action {
                KernelAction::ModuleLoad => Severity::High,
                KernelAction::SyscallFilter => Severity::Medium,
                KernelAction::MemoryExec => Severity::Critical,
            },
        }
    }

    pub fn new_process(
        action: ProcessAction,
        process_context: ProcessContext,
        parent_context: Option<ProcessContext>,
    ) -> Self {
        RiggsEvent::Process(ProcessEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context,
            action,
            parent_context,
        })
    }

    pub fn new_file(
        action: FileAction,
        process_context: ProcessContext,
        path: impl Into<String>,
        hash: Option<String>,
    ) -> Self {
        RiggsEvent::File(FileEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context,
            action,
            path: path.into(),
            hash,
            fd: None,
        })
    }

    pub fn new_file_with_fd(
        action: FileAction,
        process_context: ProcessContext,
        path: impl Into<String>,
        hash: Option<String>,
        fd: u32,
    ) -> Self {
        RiggsEvent::File(FileEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context,
            action,
            path: path.into(),
            hash,
            fd: Some(fd),
        })
    }

    pub fn new_network(
        direction: NetworkDirection,
        process_context: ProcessContext,
        src_addr: impl Into<String>,
        dst_addr: impl Into<String>,
        src_port: u16,
        dst_port: u16,
        protocol: impl Into<String>,
    ) -> Self {
        RiggsEvent::Network(NetworkEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context,
            direction,
            src_addr: src_addr.into(),
            dst_addr: dst_addr.into(),
            src_port,
            dst_port,
            protocol: protocol.into(),
        })
    }

    pub fn new_dns(
        process_context: ProcessContext,
        query: impl Into<String>,
        response: impl Into<String>,
        query_type: impl Into<String>,
    ) -> Self {
        RiggsEvent::Dns(DnsEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context,
            query: query.into(),
            response: response.into(),
            query_type: query_type.into(),
        })
    }

    pub fn new_auth(
        action: AuthAction,
        process_context: ProcessContext,
        user: impl Into<String>,
        method: impl Into<String>,
    ) -> Self {
        RiggsEvent::Auth(AuthEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context,
            action,
            user: user.into(),
            method: method.into(),
        })
    }

    pub fn new_kernel(
        action: KernelAction,
        process_context: ProcessContext,
        detail: impl Into<String>,
    ) -> Self {
        RiggsEvent::Kernel(KernelEvent {
            event_id: EventId::new(),
            timestamp: Utc::now(),
            process_context,
            action,
            detail: detail.into(),
        })
    }
}

impl fmt::Display for RiggsEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiggsEvent::Process(e) => {
                let action = match e.action {
                    ProcessAction::Exec => "exec",
                    ProcessAction::Fork => "fork",
                    ProcessAction::Exit => "exit",
                };
                write!(
                    f,
                    "[PROCESS] pid={} {} {}",
                    e.process_context.pid, action, e.process_context.path
                )
            }
            RiggsEvent::File(e) => {
                let action = match e.action {
                    FileAction::Create => "create",
                    FileAction::Modify => "modify",
                    FileAction::Delete => "delete",
                    FileAction::Rename => "rename",
                    FileAction::Open => "open",
                    FileAction::Close => "close",
                };
                write!(
                    f,
                    "[FILE] pid={} {} {}",
                    e.process_context.pid, action, e.path
                )
            }
            RiggsEvent::Network(e) => {
                let dir = match e.direction {
                    NetworkDirection::Inbound => "inbound",
                    NetworkDirection::Outbound => "outbound",
                };
                write!(
                    f,
                    "[NETWORK] pid={} {} {}:{} -> {}:{}",
                    e.process_context.pid, dir, e.src_addr, e.src_port, e.dst_addr, e.dst_port
                )
            }
            RiggsEvent::Dns(e) => {
                write!(
                    f,
                    "[DNS] pid={} {} -> {}",
                    e.process_context.pid, e.query, e.response
                )
            }
            RiggsEvent::Auth(e) => {
                let action = match e.action {
                    AuthAction::Login => "login",
                    AuthAction::Logout => "logout",
                    AuthAction::Escalation => "escalation",
                    AuthAction::Failed => "failed",
                };
                write!(
                    f,
                    "[AUTH] pid={} {} user={}",
                    e.process_context.pid, action, e.user
                )
            }
            RiggsEvent::Kernel(e) => {
                let action = match e.action {
                    KernelAction::ModuleLoad => "module_load",
                    KernelAction::SyscallFilter => "syscall_filter",
                    KernelAction::MemoryExec => "memory_exec",
                };
                write!(
                    f,
                    "[KERNEL] pid={} {} {}",
                    e.process_context.pid, action, e.detail
                )
            }
        }
    }
}

// --- Process ---

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProcessAction {
    Exec,
    Fork,
    Exit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub event_id: EventId,
    pub timestamp: DateTime<Utc>,
    pub process_context: ProcessContext,
    pub action: ProcessAction,
    pub parent_context: Option<ProcessContext>,
}

// --- File ---

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileAction {
    Create,
    Modify,
    Delete,
    Rename,
    Open,
    /// File descriptor closed by the process.
    /// Only emitted by sensors that have fd-level visibility (macOS ES, eBPF).
    Close,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub event_id: EventId,
    pub timestamp: DateTime<Utc>,
    pub process_context: ProcessContext,
    pub action: FileAction,
    pub path: String,
    pub hash: Option<String>,
    /// File descriptor number, when available from the sensor.
    /// Present on Open and Close events from sensors with fd visibility.
    /// None on Linux notify-based sensors and synthetic events.
    pub fd: Option<u32>,
}

// --- Network ---

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub event_id: EventId,
    pub timestamp: DateTime<Utc>,
    pub process_context: ProcessContext,
    pub direction: NetworkDirection,
    pub src_addr: String,
    pub dst_addr: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
}

// --- DNS ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEvent {
    pub event_id: EventId,
    pub timestamp: DateTime<Utc>,
    pub process_context: ProcessContext,
    pub query: String,
    pub response: String,
    pub query_type: String,
}

// --- Auth ---

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthAction {
    Login,
    Logout,
    Escalation,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthEvent {
    pub event_id: EventId,
    pub timestamp: DateTime<Utc>,
    pub process_context: ProcessContext,
    pub action: AuthAction,
    pub user: String,
    pub method: String,
}

// --- Kernel ---

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum KernelAction {
    ModuleLoad,
    SyscallFilter,
    MemoryExec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelEvent {
    pub event_id: EventId,
    pub timestamp: DateTime<Utc>,
    pub process_context: ProcessContext,
    pub action: KernelAction,
    pub detail: String,
}

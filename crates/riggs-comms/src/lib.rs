mod ipc;
mod messages;

pub use ipc::{IpcClient, IpcError, IpcServer};
pub use messages::{ClientMessage, DaemonMessage};

// Cloud module would use tonic - deferred to later phase
// #[cfg(feature = "cloud")]
// mod cloud;

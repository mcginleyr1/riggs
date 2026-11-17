mod ipc;
mod messages;

pub use ipc::{
    ControlOps, DaemonState, DlpFlowVerdict, DlpQuery, DlpQueryStatus, EgressFlowVerdict,
    EgressQuery, EgressQueryStatus, IpcClient, IpcError, IpcServer, PhishingQuery, StoreQuery,
};
pub use messages::{ClientMessage, DaemonMessage, QuarantinedFile, ResponseEntry};

// Cloud module would use tonic - deferred to later phase
// #[cfg(feature = "cloud")]
// mod cloud;

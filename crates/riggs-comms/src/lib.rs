mod ipc;
mod messages;

pub use ipc::{
    ControlOps, DaemonState, DlpFlowVerdict, DlpQuery, DlpQueryStatus, EgressFlowVerdict,
    EgressQuery, EgressQueryStatus, IpcClient, IpcError, IpcServer, StoreQuery,
};
pub use messages::{ClientMessage, DaemonMessage};

// Cloud module would use tonic - deferred to later phase
// #[cfg(feature = "cloud")]
// mod cloud;

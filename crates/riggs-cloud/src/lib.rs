pub mod proto {
    tonic::include_proto!("riggs.v1");
}

mod client;
mod enroll;
mod heartbeat;
mod reporter;

pub use client::{ConsoleClient, ConsoleConfig};
pub use enroll::enroll;
pub use heartbeat::run_heartbeat_loop;
pub use reporter::run_threat_reporter;

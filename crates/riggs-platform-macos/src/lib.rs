#[cfg(target_os = "macos")]
mod net;
#[cfg(target_os = "macos")]
mod quarantine;
mod sensor;
pub use sensor::MacOsSensor;

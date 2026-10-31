#[cfg(target_os = "macos")]
mod net;
mod sensor;
pub use sensor::MacOsSensor;

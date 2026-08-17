use std::collections::HashSet;

use serde_json::Value;
use thiserror::Error;
use tracing::{error, info, warn};

use crate::policy::{DeviceAction, DeviceClass, DevicePolicy};

#[derive(Debug, Error)]
pub enum MonitorError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Monitor error: {0}")]
    Other(String),
}

type Result<T> = std::result::Result<T, MonitorError>;

pub struct DeviceMonitor {
    policies: Vec<DevicePolicy>,
    running: bool,
    known_devices: HashSet<String>,
}

impl DeviceMonitor {
    pub fn new(policies: Vec<DevicePolicy>) -> Self {
        Self {
            policies,
            running: false,
            known_devices: HashSet::new(),
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        self.running = true;
        info!(
            "Device monitor started with {} policies",
            self.policies.len()
        );

        #[cfg(target_os = "macos")]
        {
            self.run_macos_monitor().await
        }

        #[cfg(target_os = "linux")]
        {
            Err(MonitorError::Other(
                "Linux udev device monitoring not yet implemented".into(),
            ))
        }

        #[cfg(target_os = "windows")]
        {
            Err(MonitorError::Other(
                "Windows WMI device monitoring not yet implemented".into(),
            ))
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            Err(MonitorError::Other("Unsupported platform".into()))
        }
    }

    pub async fn stop(&mut self) -> Result<()> {
        self.running = false;
        info!("Device monitor stopped");
        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn run_macos_monitor(&mut self) -> Result<()> {
        let policies = self.policies.clone();

        // Initial scan to populate known devices
        match scan_usb_devices() {
            Ok(devices) => {
                for dev in &devices {
                    self.known_devices.insert(dev.id.clone());
                }
                info!(count = self.known_devices.len(), "initial USB device scan");
            }
            Err(e) => {
                error!(error = %e, "initial USB scan failed");
            }
        }

        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));

        loop {
            interval.tick().await;
            if !self.running {
                break;
            }

            let current_devices = match scan_usb_devices() {
                Ok(devs) => devs,
                Err(e) => {
                    warn!(error = %e, "USB scan failed");
                    continue;
                }
            };

            let current_ids: HashSet<String> =
                current_devices.iter().map(|d| d.id.clone()).collect();

            // Detect new devices
            for dev in &current_devices {
                if !self.known_devices.contains(&dev.id) {
                    info!(
                        device = %dev.id,
                        name = %dev.name,
                        vendor_id = dev.vendor_id,
                        product_id = dev.product_id,
                        "USB device connected"
                    );

                    for policy in &policies {
                        if matches_policy(dev, policy) {
                            match policy.action {
                                DeviceAction::Block => {
                                    warn!(device = %dev.name, "blocking USB device per policy");
                                    if let Some(ref vol) = dev.volume_path {
                                        let _ = std::process::Command::new("diskutil")
                                            .args(["unmount", vol])
                                            .output();
                                    }
                                }
                                DeviceAction::Notify => {
                                    info!(
                                        device = %dev.name,
                                        policy = %policy.description,
                                        "device policy notification"
                                    );
                                }
                                DeviceAction::ReadOnly => {
                                    info!(
                                        device = %dev.name,
                                        "read-only policy (enforcement not yet implemented)"
                                    );
                                }
                                DeviceAction::Allow => {}
                            }
                        }
                    }
                }
            }

            // Detect removed devices
            for id in self.known_devices.difference(&current_ids) {
                info!(device = %id, "USB device disconnected");
            }

            self.known_devices = current_ids;
        }

        Ok(())
    }
}

// -- macOS-specific helpers --------------------------------------------------

#[cfg(target_os = "macos")]
struct UsbDevice {
    id: String,
    name: String,
    vendor_id: u16,
    product_id: u16,
    volume_path: Option<String>,
}

#[cfg(target_os = "macos")]
fn scan_usb_devices() -> Result<Vec<UsbDevice>> {
    let output = std::process::Command::new("system_profiler")
        .args(["SPUSBDataType", "-json"])
        .output()?;

    if !output.status.success() {
        return Err(MonitorError::Other("system_profiler failed".into()));
    }

    let json: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| MonitorError::Other(format!("JSON parse error: {e}")))?;

    let mut devices = Vec::new();
    extract_usb_devices(&json, &mut devices);
    Ok(devices)
}

#[cfg(target_os = "macos")]
fn extract_usb_devices(value: &Value, devices: &mut Vec<UsbDevice>) {
    match value {
        Value::Object(map) => {
            // A USB device entry has both `_name` and `vendor_id` keys.
            if let (Some(name), Some(vid_str)) = (
                map.get("_name").and_then(|v| v.as_str()),
                map.get("vendor_id").and_then(|v| v.as_str()),
            ) {
                let vendor_id = parse_hex_id(vid_str);
                let product_id = map
                    .get("product_id")
                    .and_then(|v| v.as_str())
                    .map(parse_hex_id)
                    .unwrap_or(0);

                let serial = map
                    .get("serial_num")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                let id = format!("{vendor_id:04x}:{product_id:04x}:{serial}");

                let volume_path = map
                    .get("volumes")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|v| v.get("mount_point"))
                    .and_then(|v| v.as_str())
                    .map(String::from);

                devices.push(UsbDevice {
                    id,
                    name: name.to_string(),
                    vendor_id,
                    product_id,
                    volume_path,
                });
            }

            // Recurse into child items
            for (key, val) in map {
                if key == "_items" || key == "SPUSBDataType" {
                    extract_usb_devices(val, devices);
                }
            }
        }
        Value::Array(arr) => {
            for item in arr {
                extract_usb_devices(item, devices);
            }
        }
        _ => {}
    }
}

/// Parse a hex identifier like "0x1234" or "1234" into a u16.
#[cfg(target_os = "macos")]
fn parse_hex_id(s: &str) -> u16 {
    let s = s.trim().trim_start_matches("0x");
    u16::from_str_radix(s, 16).unwrap_or(0)
}

#[cfg(target_os = "macos")]
fn matches_policy(device: &UsbDevice, policy: &DevicePolicy) -> bool {
    let class_matches = matches!(
        policy.device_class,
        DeviceClass::UsbStorage | DeviceClass::UsbHid | DeviceClass::UsbOther
    );

    if !class_matches {
        return false;
    }

    if let Some(vid) = policy.vendor_id {
        if vid != device.vendor_id {
            return false;
        }
    }

    if let Some(pid) = policy.product_id {
        if pid != device.product_id {
            return false;
        }
    }

    true
}

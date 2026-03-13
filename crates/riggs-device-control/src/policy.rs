use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceClass {
    UsbStorage,
    UsbHid,
    UsbOther,
    Bluetooth,
    Thunderbolt,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceAction {
    Allow,
    Block,
    ReadOnly,
    Notify,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePolicy {
    pub device_class: DeviceClass,
    pub vendor_id: Option<u16>,
    pub product_id: Option<u16>,
    pub action: DeviceAction,
    pub description: String,
}

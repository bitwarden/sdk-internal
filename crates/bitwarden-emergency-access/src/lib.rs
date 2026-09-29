#![doc = include_str!("../README.md")]

mod emergency_access;
mod emergency_access_client;
mod view_ciphers;

pub use emergency_access::EmergencyAccessId;
pub use emergency_access_client::{EmergencyAccessClient, EmergencyAccessClientExt};
pub use view_ciphers::EmergencyAccessViewError;

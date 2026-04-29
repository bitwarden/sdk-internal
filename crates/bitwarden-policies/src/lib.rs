#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

pub mod filter;
mod master_password_policy_response;
mod policy_client;
mod registry;

pub use filter::{Policy, PolicyType, PolicyView};
pub use master_password_policy_response::MasterPasswordPolicyResponse;
pub use policy_client::{PoliciesClientExt, PolicyClient};

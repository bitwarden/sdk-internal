#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

mod master_password_policy_response;
mod policy;

pub use master_password_policy_response::MasterPasswordPolicyResponse;
pub use policy::Policy;

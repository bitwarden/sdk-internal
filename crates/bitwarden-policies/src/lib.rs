#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

mod master_password_policy_response;
mod models;
mod policies;
pub mod policy;
mod policy_client;
mod policy_type;

pub use master_password_policy_response::MasterPasswordPolicyResponse;
pub use models::{EnforcedPolicyErased, OrganizationUserPolicyContext, PolicyView};
// Policies will be referenced by other crates once this starts being used
#[allow(unused)]
pub(crate) use policies::*;
pub(crate) use policy::Policy;
pub use policy_client::{PoliciesClientExt, PolicyClient};
pub use policy_type::{PolicyDataType, PolicyType};

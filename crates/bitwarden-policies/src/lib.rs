#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

pub mod enforcement;
mod master_password_policy_response;
mod models;
mod policy_client;
pub mod policy_overrides;
mod policy_type;
mod registry;

pub use enforcement::{
    EnforcedAggregatePolicy, EnforcedPolicy, NoData, Policy, PolicyAggregate, PolicyData,
};
pub use master_password_policy_response::MasterPasswordPolicyResponse;
pub use models::{OrganizationUserPolicyContext, PolicyView};
pub use policy_client::{PoliciesClientExt, PolicyClient};
pub use policy_overrides::*;
pub use policy_type::PolicyType;

#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

mod enriched_policy_type;
pub mod filter;
pub mod policy_definitions;
mod models;
mod policy_client;
mod policy_type;
mod registry;

pub use enriched_policy_type::EnrichedPolicyType;
pub use filter::Policy;
pub use models::{OrganizationUserPolicyContext, PolicyView};
pub use policy_client::{PoliciesClientExt, PolicyClient};
pub use policy_definitions::*;
pub use policy_type::PolicyType;

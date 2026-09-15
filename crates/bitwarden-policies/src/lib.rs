#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

mod models;
mod policies;
mod policy;
mod policy_client;
mod policy_definition;
mod policy_sync_handler;
mod policy_type;

pub use models::{OrganizationUserPolicyContext, PolicyDecisionErased};
// Policy structs will be referenced by other crates once this starts being used
#[allow(unused)]
pub(crate) use policies::*;
pub use policies::{
    AutomaticAppLogInPolicyData, FillAssistPolicyData, MasterPasswordPolicyData,
    MaximumVaultTimeoutPolicyData, OrganizationDataOwnershipPolicyData,
    OrganizationUserNotificationPolicyData, PasswordGeneratorPolicyData, PasswordGeneratorType,
    ResetPasswordPolicyData, SendOptionsPolicyData, VaultTimeoutAction, VaultTimeoutType,
};
pub use policy::{Policy, PolicyId, PolicyParseError};
pub use policy_client::{PoliciesClientExt, PolicyClient};
pub(crate) use policy_definition::PolicyDefinition;
pub use policy_sync_handler::PolicySyncHandler;
pub use policy_type::{PolicyDataType, PolicyType};

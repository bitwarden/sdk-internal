#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

mod models;
mod policies;
pub mod policy;
mod policy_client;
mod policy_sync_handler;
mod policy_type;

pub use models::{
    EnforcedPolicyErased, OrganizationUserPolicyContext, PolicyId, PolicyParseError, PolicyView,
};
// Policy structs will be referenced by other crates once this starts being used
#[allow(unused)]
pub(crate) use policies::*;
pub use policies::{
    AutomaticAppLogInPolicyData, FillAssistPolicyData, MasterPasswordPolicyData,
    MaximumVaultTimeoutPolicyData, OrganizationDataOwnershipPolicyData,
    OrganizationUserNotificationPolicyData, PasswordGeneratorPolicyData, PasswordGeneratorType,
    ResetPasswordPolicyData, SendOptionsPolicyData, VaultTimeoutAction, VaultTimeoutType,
};
pub(crate) use policy::Policy;
pub use policy_client::{PoliciesClientExt, PolicyClient};
pub use policy_sync_handler::PolicySyncHandler;
pub use policy_type::{PolicyDataType, PolicyType};

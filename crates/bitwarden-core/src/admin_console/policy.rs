use std::collections::HashMap;

use bitwarden_api_api::models::PolicyResponseModel;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use uuid::Uuid;

use crate::{MissingFieldError, require};

/// Represents a policy that can be applied to an organization.
#[derive(Serialize, Deserialize, Debug)]
pub struct Policy {
    id: Uuid,
    organization_id: Uuid,
    r#type: PolicyType,
    data: Option<HashMap<String, serde_json::Value>>,
    enabled: bool,
}

#[derive(Serialize_repr, Deserialize_repr, Debug)]
#[repr(u8)]
pub enum PolicyType {
    /// Requires users to have 2fa enabled
    TwoFactorAuthentication = 0,
    /// Sets minimum requirements for master password complexity
    MasterPassword = 1,
    /// Sets minimum requirements/default type for generated passwords/passphrases
    PasswordGenerator = 2,
    /// Allows users to only be apart of one organization
    SingleOrg = 3,
    /// Requires users to authenticate with SSO
    RequireSso = 4,
    /// Disables personal vault ownership for adding/cloning items
    PersonalOwnership = 5,
    /// Disables the ability to create and edit Bitwarden Sends
    DisableSend = 6,
    /// Sets restrictions or defaults for Bitwarden Sends
    SendOptions = 7,
    /// Allows orgs to use reset password : also can enable auto-enrollment during invite flow
    ResetPassword = 8,
    /// Sets the maximum allowed vault timeout
    MaximumVaultTimeout = 9,
    /// Disable personal vault export
    DisablePersonalVaultExport = 10,
    /// Activates autofill with page load on the browser extension
    ActivateAutofill = 11,
    AutomaticAppLogIn = 12,
    FreeFamiliesSponsorshipPolicy = 13,
    RemoveUnlockWithPin = 14,
    RestrictedItemTypesPolicy = 15,
    UriMatchDefaults = 16,
}

impl TryFrom<PolicyResponseModel> for Policy {
    type Error = MissingFieldError;

    fn try_from(policy: PolicyResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            id: require!(policy.id),
            organization_id: require!(policy.organization_id),
            r#type: require!(policy.r#type).into(),
            data: policy.data,
            enabled: require!(policy.enabled),
        })
    }
}

impl From<bitwarden_api_api::models::PolicyType> for PolicyType {
    fn from(policy_type: bitwarden_api_api::models::PolicyType) -> Self {
        match policy_type {
            bitwarden_api_api::models::PolicyType::TwoFactorAuthentication => {
                PolicyType::TwoFactorAuthentication
            }
            bitwarden_api_api::models::PolicyType::MasterPassword => PolicyType::MasterPassword,
            bitwarden_api_api::models::PolicyType::PasswordGenerator => {
                PolicyType::PasswordGenerator
            }
            bitwarden_api_api::models::PolicyType::SingleOrg => PolicyType::SingleOrg,
            bitwarden_api_api::models::PolicyType::RequireSso => PolicyType::RequireSso,
            bitwarden_api_api::models::PolicyType::OrganizationDataOwnership => {
                PolicyType::PersonalOwnership
            }
            bitwarden_api_api::models::PolicyType::DisableSend => PolicyType::DisableSend,
            bitwarden_api_api::models::PolicyType::SendOptions => PolicyType::SendOptions,
            bitwarden_api_api::models::PolicyType::ResetPassword => PolicyType::ResetPassword,
            bitwarden_api_api::models::PolicyType::MaximumVaultTimeout => {
                PolicyType::MaximumVaultTimeout
            }
            bitwarden_api_api::models::PolicyType::DisablePersonalVaultExport => {
                PolicyType::DisablePersonalVaultExport
            }
            bitwarden_api_api::models::PolicyType::ActivateAutofill => PolicyType::ActivateAutofill,
            bitwarden_api_api::models::PolicyType::AutomaticAppLogIn => {
                PolicyType::AutomaticAppLogIn
            }
            bitwarden_api_api::models::PolicyType::FreeFamiliesSponsorshipPolicy => {
                PolicyType::FreeFamiliesSponsorshipPolicy
            }
            bitwarden_api_api::models::PolicyType::RemoveUnlockWithPin => {
                PolicyType::RemoveUnlockWithPin
            }
            bitwarden_api_api::models::PolicyType::RestrictedItemTypesPolicy => {
                PolicyType::RestrictedItemTypesPolicy
            }
            bitwarden_api_api::models::PolicyType::UriMatchDefaults => PolicyType::UriMatchDefaults,
        }
    }
}

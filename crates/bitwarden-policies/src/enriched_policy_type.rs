//! The [`EnrichedPolicyType`] enum.
//!
//! [`PolicyType`](crate::PolicyType) is a bare discriminant that matches the
//! server's numeric wire format. `EnrichedPolicyType` mirrors every variant of
//! that enum but additionally carries the strongly-typed `policy.data` payload
//! (see [`policy_definitions`](crate::policy_definitions)) for the policies that have one.
//! Toggle-only policies (whose `data` is always `null`) are unit variants.

use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::{
    PolicyType,
    policy_definition::PolicyDefinition,
    policy_definitions::{
        AutomaticAppLoginPolicy, AutomaticUserConfirmationPolicy, FreeFamiliesSponsorshipPolicy,
        MasterPasswordPolicy, MaximumSessionTimeoutPolicy, OrganizationDataOwnershipPolicy,
        OrganizationUserNotificationPolicy, PasswordGeneratorPolicy, RemoveUnlockWithPinPolicy,
        ResetPasswordPolicy, RestrictedItemTypesPolicy, SendControlsPolicy, SendOptionsPolicy,
        UriMatchDefaultPolicy,
    },
};

/// A [`PolicyType`](crate::PolicyType) paired with its strongly-typed
/// `policy.data` payload.
///
/// Variants mirror [`PolicyType`](crate::PolicyType) one-to-one. Policies that
/// carry configuration wrap their payload struct; toggle-only policies (whose
/// `data` is always `null`) are unit variants.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum EnrichedPolicyType {
    /// Requires members to have two-step login enabled on their account.
    TwoFactorAuthentication,
    /// Sets minimum requirements for members' master passwords.
    MasterPassword(MasterPasswordPolicy),
    /// Sets minimum requirements for the password generator.
    PasswordGenerator(PasswordGeneratorPolicy),
    /// Restricts members to being part of a single organization.
    SingleOrg,
    /// Requires members to authenticate with single sign-on.
    RequireSso,
    /// Forces newly added or cloned items to be owned by the organization.
    OrganizationDataOwnership(OrganizationDataOwnershipPolicy),
    /// Disables the ability to create and edit Bitwarden Sends.
    DisableSend,
    /// Sets restrictions or defaults for Bitwarden Sends.
    SendOptions(SendOptionsPolicy),
    /// Allows administrators to recover member accounts.
    ResetPassword(ResetPasswordPolicy),
    /// Sets the maximum allowed vault timeout for members.
    MaximumVaultTimeout(MaximumSessionTimeoutPolicy),
    /// Disables members' ability to export their personal vault.
    DisablePersonalVaultExport,
    /// Activates autofill on page load in the browser extension.
    ActivateAutofill,
    /// Automatically logs members into apps using single sign-on.
    AutomaticAppLogIn(AutomaticAppLoginPolicy),
    /// Removes members' access to the free Bitwarden Families sponsorship benefit.
    FreeFamiliesSponsorship,
    /// Prevents members from unlocking the app with a PIN.
    RemoveUnlockWithPin,
    /// Restricts the item types that members can create.
    RestrictedItemTypes,
    /// Sets the default URI match detection strategy for autofill.
    UriMatchDefaults(UriMatchDefaultPolicy),
    /// Sets the default behavior for the autotype feature.
    AutotypeDefaultSetting,
    /// Automatically confirms invited users into the organization.
    AutomaticUserConfirmation,
    /// Blocks account creation for users with email addresses on claimed domains.
    BlockClaimedDomainAccountCreation,
    /// Displays an organization-configured banner message to members.
    OrganizationUserNotification(OrganizationUserNotificationPolicy),
    /// Configures Send-related behavior (disabling Sends, email visibility,
    /// access controls, Send types, and deletion).
    SendControls(SendControlsPolicy),
}

impl EnrichedPolicyType {
    /// Returns the [`PolicyDefinition`](crate::filter::PolicyDefinition) trait implementer for this
    /// policy type, if one exists.
    ///
    /// Only policies with custom rules return `Some`. Policies without custom rules return `None`.
    pub fn to_policy_definition(&self) -> Option<Box<dyn PolicyDefinition>> {
        match self {
            EnrichedPolicyType::MasterPassword(p) => Some(Box::new(p.clone())),
            EnrichedPolicyType::PasswordGenerator(p) => Some(Box::new(p.clone())),
            EnrichedPolicyType::MaximumVaultTimeout(p) => Some(Box::new(p.clone())),
            EnrichedPolicyType::FreeFamiliesSponsorship => {
                Some(Box::new(FreeFamiliesSponsorshipPolicy))
            }
            EnrichedPolicyType::RemoveUnlockWithPin => Some(Box::new(RemoveUnlockWithPinPolicy)),
            EnrichedPolicyType::RestrictedItemTypes => Some(Box::new(RestrictedItemTypesPolicy)),
            EnrichedPolicyType::AutomaticUserConfirmation => {
                Some(Box::new(AutomaticUserConfirmationPolicy))
            }
            EnrichedPolicyType::OrganizationUserNotification(p) => Some(Box::new(p.clone())),
            // Policies without custom rules return None
            _ => None,
        }
    }

    /// Constructs an `EnrichedPolicyType` from a `PolicyType` and optional JSON data.
    ///
    /// For policies with configuration data, the JSON string is deserialized into the
    /// appropriate data structure. If deserialization fails or data is missing, the
    /// policy defaults are used.
    pub fn from_policy_type(policy_type: PolicyType, data: Option<String>) -> Self {
        match policy_type {
            PolicyType::TwoFactorAuthentication => Self::TwoFactorAuthentication,
            PolicyType::MasterPassword => Self::MasterPassword(
                serde_json::from_str(data.as_deref().unwrap_or("")).unwrap_or_default(),
            ),
            PolicyType::PasswordGenerator => Self::PasswordGenerator(
                serde_json::from_str(data.as_deref().unwrap_or("")).unwrap_or_default(),
            ),
            PolicyType::SingleOrg => Self::SingleOrg,
            PolicyType::RequireSso => Self::RequireSso,
            PolicyType::OrganizationDataOwnership => Self::OrganizationDataOwnership(
                serde_json::from_str(data.as_deref().unwrap_or("")).unwrap_or_default(),
            ),
            PolicyType::DisableSend => Self::DisableSend,
            PolicyType::SendOptions => Self::SendOptions(
                serde_json::from_str(data.as_deref().unwrap_or("")).unwrap_or_default(),
            ),
            PolicyType::ResetPassword => Self::ResetPassword(
                serde_json::from_str(data.as_deref().unwrap_or("")).unwrap_or_default(),
            ),
            PolicyType::MaximumVaultTimeout => Self::MaximumVaultTimeout(
                serde_json::from_str(data.as_deref().unwrap_or("")).unwrap_or_default(),
            ),
            PolicyType::DisablePersonalVaultExport => Self::DisablePersonalVaultExport,
            PolicyType::ActivateAutofill => Self::ActivateAutofill,
            PolicyType::AutomaticAppLogIn => Self::AutomaticAppLogIn(
                serde_json::from_str(data.as_deref().unwrap_or("")).unwrap_or_default(),
            ),
            PolicyType::FreeFamiliesSponsorship => Self::FreeFamiliesSponsorship,
            PolicyType::RemoveUnlockWithPin => Self::RemoveUnlockWithPin,
            PolicyType::RestrictedItemTypes => Self::RestrictedItemTypes,
            PolicyType::UriMatchDefaults => Self::UriMatchDefaults(
                serde_json::from_str(data.as_deref().unwrap_or("")).unwrap_or_default(),
            ),
            PolicyType::AutotypeDefaultSetting => Self::AutotypeDefaultSetting,
            PolicyType::AutomaticUserConfirmation => Self::AutomaticUserConfirmation,
            PolicyType::BlockClaimedDomainAccountCreation => {
                Self::BlockClaimedDomainAccountCreation
            }
            PolicyType::OrganizationUserNotification => Self::OrganizationUserNotification(
                serde_json::from_str(data.as_deref().unwrap_or("")).unwrap_or_default(),
            ),
            PolicyType::SendControls => Self::SendControls(
                serde_json::from_str(data.as_deref().unwrap_or("")).unwrap_or_default(),
            ),
        }
    }
}

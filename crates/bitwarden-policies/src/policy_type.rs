//! The [`PolicyType`] enum.

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{policies::*, policy::ErasedPolicy};

/// The type of an organization policy.
///
/// The integer value matches the server's wire format.
#[derive(PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr, Debug, Copy, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[repr(u8)]
pub enum PolicyType {
    /// Requires members to have two-step login enabled on their account.
    TwoFactorAuthentication = 0,
    /// Sets minimum requirements for members' master passwords.
    MasterPassword = 1,
    /// Sets minimum requirements for the password generator.
    PasswordGenerator = 2,
    /// Restricts members to being part of a single organization.
    SingleOrg = 3,
    /// Requires members to authenticate with single sign-on.
    RequireSso = 4,
    /// Forces newly added or cloned items to be owned by the organization rather than the
    /// member's personal vault. Also enables My Items functionality.
    OrganizationDataOwnership = 5,
    /// Disables the ability to create and edit Bitwarden Sends.
    ///
    /// Superseded by [`SendControls`](Self::SendControls) when the
    /// `pm-31885-send-controls` feature flag is active.
    DisableSend = 6,
    /// Sets restrictions or defaults for Bitwarden Sends.
    ///
    /// Superseded by [`SendControls`](Self::SendControls) when the
    /// `pm-31885-send-controls` feature flag is active.
    SendOptions = 7,
    /// Allows administrators to recover member accounts.
    ResetPassword = 8,
    /// Sets the maximum allowed vault timeout for members.
    MaximumVaultTimeout = 9,
    /// Disables members' ability to export their personal vault.
    DisablePersonalVaultExport = 10,
    /// Activates autofill on page load in the browser extension.
    ActivateAutofill = 11,
    /// Automatically logs members into apps using single sign-on.
    AutomaticAppLogIn = 12,
    /// Removes members' access to the free Bitwarden Families sponsorship benefit.
    FreeFamiliesSponsorship = 13,
    /// Prevents members from unlocking the app with a PIN.
    RemoveUnlockWithPin = 14,
    /// Restricts the item types that members can create.
    RestrictedItemTypes = 15,
    /// Sets the default URI match detection strategy for autofill.
    UriMatchDefaults = 16,
    /// Sets the default behavior for the autotype feature.
    AutotypeDefaultSetting = 17,
    /// Automatically confirms invited users into the organization.
    AutomaticUserConfirmation = 18,
    /// Blocks account creation for users with email addresses on claimed domains.
    BlockClaimedDomainAccountCreation = 19,
    /// Displays an organization-configured banner message to members in their vault.
    OrganizationUserNotification = 20,
    /// Configures Send-related behavior: disabling Sends, email visibility, access controls,
    /// Send types, and deletion.
    ///
    /// Supersedes [`DisableSend`](Self::DisableSend) and [`SendOptions`](Self::SendOptions) when
    /// the `pm-31885-send-controls` feature flag is active on the server.
    SendControls = 21,
    /// Enables the Fill Assist targeting-rules autofill engine as the default for members who
    /// have not explicitly set their Fill Assist preference, and optionally overrides the default
    /// rules feed URL.
    FillAssist = 22,
}

impl PolicyType {
    /// Dispatches this runtime policy type to its concrete (zero-sized)
    /// [`crate::Policy`] implementation, erased behind [`ErasedPolicy`] so the
    /// differing associated `Data` types can be handled uniformly.
    pub(crate) fn resolve_policy(self) -> Box<dyn ErasedPolicy> {
        match self {
            PolicyType::TwoFactorAuthentication => Box::new(TwoFactorAuthenticationPolicy),
            PolicyType::MasterPassword => Box::new(MasterPasswordPolicy),
            PolicyType::PasswordGenerator => Box::new(PasswordGeneratorPolicy),
            PolicyType::SingleOrg => Box::new(SingleOrgPolicy),
            PolicyType::RequireSso => Box::new(RequireSsoPolicy),
            PolicyType::OrganizationDataOwnership => Box::new(OrganizationDataOwnershipPolicy),
            PolicyType::DisableSend => Box::new(DisableSendPolicy),
            PolicyType::SendOptions => Box::new(SendOptionsPolicy),
            PolicyType::ResetPassword => Box::new(ResetPasswordPolicy),
            PolicyType::MaximumVaultTimeout => Box::new(MaximumVaultTimeoutPolicy),
            PolicyType::DisablePersonalVaultExport => Box::new(DisablePersonalVaultExportPolicy),
            PolicyType::ActivateAutofill => Box::new(ActivateAutofillPolicy),
            PolicyType::AutomaticAppLogIn => Box::new(AutomaticAppLogInPolicy),
            PolicyType::FreeFamiliesSponsorship => Box::new(FreeFamiliesSponsorshipPolicy),
            PolicyType::RemoveUnlockWithPin => Box::new(RemoveUnlockWithPinPolicy),
            PolicyType::RestrictedItemTypes => Box::new(RestrictedItemTypesPolicy),
            PolicyType::UriMatchDefaults => Box::new(UriMatchDefaultsPolicy),
            PolicyType::AutotypeDefaultSetting => Box::new(AutotypeDefaultSettingPolicy),
            PolicyType::AutomaticUserConfirmation => Box::new(AutomaticUserConfirmationPolicy),
            PolicyType::BlockClaimedDomainAccountCreation => {
                Box::new(BlockClaimedDomainAccountCreationPolicy)
            }
            PolicyType::OrganizationUserNotification => {
                Box::new(OrganizationUserNotificationPolicy)
            }
            PolicyType::SendControls => Box::new(SendControlsPolicy),
            PolicyType::FillAssist => Box::new(FillAssistPolicy),
        }
    }
}

/// Type-erased policy type + data for crossing the FFI boundary.
///
/// Each variant carries the strongly-typed data for one policy, mirroring the
/// generic `Policy::Data` used on the native side. Variants are
/// named identically to (and documented by) the matching [`PolicyType`] variant.
///
/// The discriminator is serialized under `_policyType` rather than `type` so it
/// cannot collide with a policy data field named `type` (e.g.
/// [`MaximumVaultTimeoutPolicyData`]), which the internally-tagged
/// representation flattens alongside the discriminator.
// Variants mirror the already-documented `PolicyType`, so per-variant docs would
// be redundant boilerplate.
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase", tag = "_policyType")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum PolicyDataType {
    TwoFactorAuthentication,
    MasterPassword(MasterPasswordPolicyData),
    PasswordGenerator(PasswordGeneratorPolicyData),
    SingleOrg,
    RequireSso,
    OrganizationDataOwnership(OrganizationDataOwnershipPolicyData),
    DisableSend,
    SendOptions(SendOptionsPolicyData),
    ResetPassword(ResetPasswordPolicyData),
    MaximumVaultTimeout(MaximumVaultTimeoutPolicyData),
    DisablePersonalVaultExport,
    ActivateAutofill,
    AutomaticAppLogIn(AutomaticAppLogInPolicyData),
    FreeFamiliesSponsorship,
    RemoveUnlockWithPin,
    RestrictedItemTypes,
    UriMatchDefaults,
    AutotypeDefaultSetting,
    AutomaticUserConfirmation,
    BlockClaimedDomainAccountCreation,
    OrganizationUserNotification(OrganizationUserNotificationPolicyData),
    SendControls,
    FillAssist,
}

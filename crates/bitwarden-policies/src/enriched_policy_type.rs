//! The [`EnrichedPolicyType`] enum.
//!
//! [`PolicyType`](crate::PolicyType) is a bare discriminant that matches the
//! server's numeric wire format. `EnrichedPolicyType` mirrors every variant of
//! that enum but additionally carries the strongly-typed `policy.data` payload
//! (see [`policy_data`](crate::policy_data)) for the policies that have one.
//! Toggle-only policies (whose `data` is always `null`) are unit variants.
//!
// TODO: There is no conversion yet from [`PolicyView`](crate::PolicyView) (whose
// `data` is an `Option<String>` of JSON) into an [`EnrichedPolicyType`]. Add a
// fallible `TryFrom<&PolicyView>` (or similar) that parses `data` per policy
// type, along with round-trip tests, when this is wired into a client.

use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::{
    MasterPasswordPolicyResponse,
    policy_data::{
        AutomaticAppLoginPolicyData, MaximumSessionTimeoutPolicyData,
        OrganizationDataOwnershipPolicyData, OrganizationUserNotificationPolicyData,
        PasswordGeneratorPolicyData, ResetPasswordPolicyData, SendControlsPolicyData,
        SendOptionsPolicyData, UriMatchDefaultPolicyData,
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
    MasterPassword(MasterPasswordPolicyResponse),
    /// Sets minimum requirements for the password generator.
    PasswordGenerator(PasswordGeneratorPolicyData),
    /// Restricts members to being part of a single organization.
    SingleOrg,
    /// Requires members to authenticate with single sign-on.
    RequireSso,
    /// Forces newly added or cloned items to be owned by the organization.
    OrganizationDataOwnership(OrganizationDataOwnershipPolicyData),
    /// Disables the ability to create and edit Bitwarden Sends.
    DisableSend,
    /// Sets restrictions or defaults for Bitwarden Sends.
    SendOptions(SendOptionsPolicyData),
    /// Allows administrators to recover member accounts.
    ResetPassword(ResetPasswordPolicyData),
    /// Sets the maximum allowed vault timeout for members.
    MaximumVaultTimeout(MaximumSessionTimeoutPolicyData),
    /// Disables members' ability to export their personal vault.
    DisablePersonalVaultExport,
    /// Activates autofill on page load in the browser extension.
    ActivateAutofill,
    /// Automatically logs members into apps using single sign-on.
    AutomaticAppLogIn(AutomaticAppLoginPolicyData),
    /// Removes members' access to the free Bitwarden Families sponsorship benefit.
    FreeFamiliesSponsorship,
    /// Prevents members from unlocking the app with a PIN.
    RemoveUnlockWithPin,
    /// Restricts the item types that members can create.
    RestrictedItemTypes,
    /// Sets the default URI match detection strategy for autofill.
    UriMatchDefaults(UriMatchDefaultPolicyData),
    /// Sets the default behavior for the autotype feature.
    AutotypeDefaultSetting,
    /// Automatically confirms invited users into the organization.
    AutomaticUserConfirmation,
    /// Blocks account creation for users with email addresses on claimed domains.
    BlockClaimedDomainAccountCreation,
    /// Displays an organization-configured banner message to members.
    OrganizationUserNotification(OrganizationUserNotificationPolicyData),
    /// Configures Send-related behavior (disabling Sends, email visibility,
    /// access controls, Send types, and deletion).
    SendControls(SendControlsPolicyData),
}

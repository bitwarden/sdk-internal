//! The [`PolicyType`] enum.

use serde_repr::{Deserialize_repr, Serialize_repr};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

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
    FreeFamiliesSponsorshipPolicy = 13,
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
}

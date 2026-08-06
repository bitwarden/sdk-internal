//! Policy definitions with strongly-typed payloads and trait implementations.
//!
//! Each policy type is defined here with its associated data structure (if any)
//! and its [`PolicyDefinition`] trait implementation.
//! Organized by policy type numeric value.

use std::str::FromStr;

use bitwarden_api_api::models::MasterPasswordPolicyResponseModel;
use bitwarden_organizations::OrganizationUserType;
use bitwarden_send::SendType;
use bitwarden_vault::UriMatchType;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::policy_definition::PolicyDefinition;

impl FromStr for MasterPasswordPolicy {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

// =============================================================================
// Supporting enums
// =============================================================================

// =============================================================================
// Policy type 0: TwoFactorAuthentication (no data)
// =============================================================================

// (Unit variant in EnrichedPolicyType, no data structure needed)

// =============================================================================
// Policy type 1: MasterPassword
// =============================================================================

/// SDK domain model for master password policy requirements.
/// Defines the complexity requirements for a user's master password
/// when enforced by an organization policy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct MasterPasswordPolicy {
    /// The minimum complexity score required for the master password.
    /// Complexity is calculated based on password strength metrics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_complexity: Option<i32>,

    /// The minimum length required for the master password.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_length: Option<i32>,

    /// Whether the master password must contain at least one lowercase letter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_lower: Option<bool>,

    /// Whether the master password must contain at least one uppercase letter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_upper: Option<bool>,

    /// Whether the master password must contain at least one numeric digit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_numbers: Option<bool>,

    /// Whether the master password must contain at least one special character.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_special: Option<bool>,

    /// Whether this policy should be enforced when the user logs in.
    /// If true, the user will be required to update their master password
    /// if it doesn't meet the policy requirements.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforce_on_login: Option<bool>,
}

impl From<MasterPasswordPolicyResponseModel> for MasterPasswordPolicy {
    fn from(api: MasterPasswordPolicyResponseModel) -> Self {
        Self {
            min_complexity: api.min_complexity,
            min_length: api.min_length,
            require_lower: api.require_lower,
            require_upper: api.require_upper,
            require_numbers: api.require_numbers,
            require_special: api.require_special,
            enforce_on_login: api.enforce_on_login,
        }
    }
}

impl PolicyDefinition for MasterPasswordPolicy {
    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

// =============================================================================
// Policy type 2: PasswordGenerator
// =============================================================================

/// `policy.data` for the password generator policy.
///
/// Sets restrictions and defaults for the password/passphrase generator.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct PasswordGeneratorPolicy {
    /// Forces the generator to a specific type (e.g. `"password"` or `"passphrase"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_password_type: Option<String>,
    /// The minimum generated password length.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_length: Option<i32>,
    /// Requires uppercase characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_upper: Option<bool>,
    /// Requires lowercase characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_lower: Option<bool>,
    /// Requires numeric characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_numbers: Option<bool>,
    /// Requires special characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_special: Option<bool>,
    /// The minimum number of numeric characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_numbers: Option<i32>,
    /// The minimum number of special characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_special: Option<i32>,
    /// The minimum number of words in a generated passphrase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_number_words: Option<i32>,
    /// Whether generated passphrase words are capitalized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capitalize: Option<bool>,
    /// Whether a number is included in a generated passphrase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_number: Option<bool>,
}

impl PolicyDefinition for PasswordGeneratorPolicy {
    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

// =============================================================================
// Policy type 3: SingleOrg (no data)
// =============================================================================

// (Unit variant in EnrichedPolicyType, no data structure needed)

// =============================================================================
// Policy type 4: RequireSso (no data)
// =============================================================================

// (Unit variant in EnrichedPolicyType, no data structure needed)

// =============================================================================
// Policy type 5: OrganizationDataOwnership
// =============================================================================

/// `policy.data` for the organization data ownership policy.
///
/// Note: this policy also sends an encrypted `metadata.defaultUserCollectionName`
/// separately from `policy.data`; that value is not part of this struct.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct OrganizationDataOwnershipPolicy {
    /// Whether members may transfer individual items into their personal vault.
    pub enable_individual_items_transfer: bool,
}

// =============================================================================
// Policy type 6: DisableSend (no data)
// =============================================================================

// (Unit variant in EnrichedPolicyType, no data structure needed)

// =============================================================================
// Policy type 7: SendOptions
// =============================================================================

/// `policy.data` for the Send options policy.
///
/// Superseded by [`SendControlsPolicy`] when the `pm-31885-send-controls`
/// feature flag is active on the server.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendOptionsPolicy {
    /// Disables the "hide my email" option when creating a Send.
    pub disable_hide_email: bool,
}

// =============================================================================
// Policy type 8: ResetPassword
// =============================================================================

/// `policy.data` for the reset password (account recovery) policy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct ResetPasswordPolicy {
    /// Whether new members are automatically enrolled in account recovery.
    pub auto_enroll_enabled: bool,
}

// =============================================================================
// Policy type 9: MaximumVaultTimeout
// =============================================================================

/// The action to take when the maximum session timeout elapses, used by
/// [`MaximumSessionTimeoutPolicy`].
///
/// Serialized as a camelCase string to match the server's wire format.
// TODO: The variant set (`Lock`/`LogOut`) and their camelCase serialization are
// assumed to mirror the client `VaultTimeoutAction`. Verify against the server's
// wire format before relying on it.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Copy, Clone, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum SessionTimeoutAction {
    /// Lock the vault, requiring the user to unlock again.
    #[default]
    Lock,
    /// Log the user out entirely.
    LogOut,
}

/// `policy.data` for the maximum session timeout policy.
///
/// Backs both the v1 and v2 maximum session timeout policies (both use
/// [`PolicyType::MaximumVaultTimeout`](crate::PolicyType::MaximumVaultTimeout)).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct MaximumSessionTimeoutPolicy {
    /// The kind of timeout being enforced.
    // TODO: This is the `SessionTimeoutType` discriminant, modeled as a raw
    // string until the server's enum domain is confirmed. Tighten to a dedicated
    // enum once the allowed values are known.
    pub r#type: String,
    /// The maximum allowed session timeout, in minutes.
    pub minutes: i32,
    /// The action taken when the timeout elapses.
    pub action: SessionTimeoutAction,
}

impl PolicyDefinition for MaximumSessionTimeoutPolicy {
    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[OrganizationUserType::Owner]
    }
}

// =============================================================================
// Policy type 10: DisablePersonalVaultExport (no data)
// =============================================================================

// (Unit variant in EnrichedPolicyType, no data structure needed)

// =============================================================================
// Policy type 11: ActivateAutofill (no data)
// =============================================================================

// (Unit variant in EnrichedPolicyType, no data structure needed)

// =============================================================================
// Policy type 12: AutomaticAppLogIn
// =============================================================================

/// `policy.data` for the automatic app login policy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct AutomaticAppLoginPolicy {
    /// The identity provider host used to automatically log members into apps.
    pub idp_host: String,
}

// =============================================================================
// Policy type 13: FreeFamiliesSponsorship
// =============================================================================

/// Free Families Sponsorship policy.
///
/// Applies to **everyone**, including Owners and Admins.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct FreeFamiliesSponsorshipPolicy;

impl PolicyDefinition for FreeFamiliesSponsorshipPolicy {
    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

// =============================================================================
// Policy type 14: RemoveUnlockWithPin
// =============================================================================

/// Remove Unlock with PIN policy.
///
/// Applies to **everyone**, including Owners and Admins.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RemoveUnlockWithPinPolicy;

impl PolicyDefinition for RemoveUnlockWithPinPolicy {
    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

// =============================================================================
// Policy type 15: RestrictedItemTypes
// =============================================================================

/// Restricted Item Types policy.
///
/// Applies to **everyone**, including Owners and Admins.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RestrictedItemTypesPolicy;

impl PolicyDefinition for RestrictedItemTypesPolicy {
    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

// =============================================================================
// Policy type 16: UriMatchDefaults
// =============================================================================

/// `policy.data` for the URI match defaults policy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct UriMatchDefaultPolicy {
    /// The default URI match detection strategy for autofill.
    pub uri_match_detection: UriMatchType,
}

// =============================================================================
// Policy type 17: AutotypeDefaultSetting (no data)
// =============================================================================

// (Unit variant in EnrichedPolicyType, no data structure needed)

// =============================================================================
// Policy type 18: AutomaticUserConfirmation
// =============================================================================

/// Automatic User Confirmation policy.
///
/// Applies to **everyone**, including Owners and Admins.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AutomaticUserConfirmationPolicy;

impl PolicyDefinition for AutomaticUserConfirmationPolicy {
    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

// =============================================================================
// Policy type 19: BlockClaimedDomainAccountCreation (no data)
// =============================================================================

// (Unit variant in EnrichedPolicyType, no data structure needed)

// =============================================================================
// Policy type 20: OrganizationUserNotification
// =============================================================================

/// `policy.data` for the organization user notification policy.
///
/// The server returns `null` (i.e. no data) when the policy is disabled.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct OrganizationUserNotificationPolicy {
    /// The banner header text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// The banner body text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The banner call-to-action button label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub button_text: Option<String>,
    /// Whether the banner is shown after every login rather than once.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub show_after_every_login: Option<bool>,
}

impl PolicyDefinition for OrganizationUserNotificationPolicy {
    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

// =============================================================================
// Policy type 21: SendControls
// =============================================================================

/// `policy.data` for the Send controls policy.
///
/// Configures Send-related behavior. Supersedes [`SendOptionsPolicy`] (and the
/// toggle-only `DisableSend` policy) when the `pm-31885-send-controls` feature flag
/// is active on the server.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendControlsPolicy {
    /// Disables the ability to create and edit Sends.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_send: Option<bool>,
    /// Restricts who can access created Sends.
    // TODO: Modeled as a raw string until the server's enum domain is confirmed.
    // Tighten to a dedicated enum once the allowed values are known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub who_can_access: Option<String>,
    /// The domains a Send may be shared with, when access is restricted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_domains: Option<Vec<String>>,
    /// Disables the "hide my email" option when creating a Send.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_hide_email: Option<bool>,
    /// The Send types members are allowed to create.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_send_types: Option<Vec<SendType>>,
    /// The maximum number of hours before a Send is automatically deleted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletion_hours: Option<i32>,
}

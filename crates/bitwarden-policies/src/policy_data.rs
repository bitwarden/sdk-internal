//! Strongly-typed `policy.data` payloads and their supporting enums.
//!
//! [`PolicyView::data`](crate::PolicyView::data) is stored as a JSON string. Each
//! struct here models the JSON object for a policy that carries configuration.
//! These payloads are wrapped by
//! [`EnrichedPolicyType`](crate::EnrichedPolicyType).
//!
//! Fields are optional because the server only persists the values an
//! administrator has configured.

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
#[cfg(feature = "wasm")]
use tsify::Tsify;

// -----------------------------------------------------------------------------
// Supporting enums
// -----------------------------------------------------------------------------

/// The type of a Bitwarden Send, used by [`SendControlsPolicyData`].
///
/// The integer value matches the server's wire format.
///
// TODO: This duplicates `bitwarden_send::SendType` (values confirmed from that
// crate). Kept local to avoid making this foundation crate depend on a feature
// crate; revisit if these types should be shared instead.
#[derive(Serialize_repr, Deserialize_repr, PartialEq, Eq, Debug, Copy, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[repr(u8)]
pub enum SendType {
    /// A text-based Send.
    Text = 0,
    /// A file-based Send.
    File = 1,
}

/// The URI match detection strategy, used by [`UriMatchDefaultPolicyData`].
///
/// The integer value matches the server's wire format (mirrors the vault's
/// `UriMatchType`).
///
// TODO: This duplicates `bitwarden_vault::UriMatchType` (values confirmed from
// that crate). Kept local to avoid making this foundation crate depend on a
// feature crate; revisit if these types should be shared instead.
#[derive(Serialize_repr, Deserialize_repr, PartialEq, Eq, Debug, Copy, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[repr(u8)]
pub enum UriMatchStrategySetting {
    /// Match by base domain.
    Domain = 0,
    /// Match by host (including port).
    Host = 1,
    /// Match when the resource URI starts with the configured URI.
    StartsWith = 2,
    /// Match only on an exact URI.
    Exact = 3,
    /// Match using a regular expression.
    RegularExpression = 4,
    /// Never match automatically.
    Never = 5,
}

/// The action to take when the maximum session timeout elapses, used by
/// [`MaximumSessionTimeoutPolicyData`].
///
/// Serialized as a camelCase string to match the server's wire format.
///
// TODO: The variant set (`Lock`/`LogOut`) and their camelCase serialization are
// assumed to mirror the client `VaultTimeoutAction`. Verify against the server's
// wire format before relying on it.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Copy, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum SessionTimeoutAction {
    /// Lock the vault, requiring the user to unlock again.
    Lock,
    /// Log the user out entirely.
    LogOut,
}

// -----------------------------------------------------------------------------
// Per-policy data payloads
// -----------------------------------------------------------------------------

/// `policy.data` for the password generator policy.
///
/// Sets restrictions and defaults for the password/passphrase generator.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct PasswordGeneratorPolicyData {
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

/// `policy.data` for the organization data ownership policy.
///
/// Note: this policy also sends an encrypted `metadata.defaultUserCollectionName`
/// separately from `policy.data`; that value is not part of this struct.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct OrganizationDataOwnershipPolicyData {
    /// Whether members may transfer individual items into their personal vault.
    pub enable_individual_items_transfer: bool,
}

/// `policy.data` for the Send options policy.
///
/// Superseded by [`SendControlsPolicyData`] when the `pm-31885-send-controls`
/// feature flag is active on the server.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendOptionsPolicyData {
    /// Disables the "hide my email" option when creating a Send.
    pub disable_hide_email: bool,
}

/// `policy.data` for the Send controls policy.
///
/// Configures Send-related behavior. Supersedes [`SendOptionsPolicyData`] (and the
/// toggle-only `DisableSend` policy) when the `pm-31885-send-controls` feature flag
/// is active on the server.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendControlsPolicyData {
    /// Disables the ability to create and edit Sends.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_send: Option<bool>,
    /// Restricts who can access created Sends.
    ///
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

/// `policy.data` for the reset password (account recovery) policy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct ResetPasswordPolicyData {
    /// Whether new members are automatically enrolled in account recovery.
    pub auto_enroll_enabled: bool,
}

/// `policy.data` for the maximum session timeout policy.
///
/// Backs both the v1 and v2 maximum session timeout policies (both use
/// [`PolicyType::MaximumVaultTimeout`](crate::PolicyType::MaximumVaultTimeout)).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct MaximumSessionTimeoutPolicyData {
    /// The kind of timeout being enforced.
    ///
    // TODO: This is the `SessionTimeoutType` discriminant, modeled as a raw
    // string until the server's enum domain is confirmed. Tighten to a dedicated
    // enum once the allowed values are known.
    pub r#type: String,
    /// The maximum allowed session timeout, in minutes.
    pub minutes: i32,
    /// The action taken when the timeout elapses.
    pub action: SessionTimeoutAction,
}

/// `policy.data` for the automatic app login policy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct AutomaticAppLoginPolicyData {
    /// The identity provider host used to automatically log members into apps.
    pub idp_host: String,
}

/// `policy.data` for the URI match defaults policy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct UriMatchDefaultPolicyData {
    /// The default URI match detection strategy for autofill.
    pub uri_match_detection: UriMatchStrategySetting,
}

/// `policy.data` for the organization user notification policy.
///
/// The server returns `null` (i.e. no data) when the policy is disabled.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct OrganizationUserNotificationPolicyData {
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

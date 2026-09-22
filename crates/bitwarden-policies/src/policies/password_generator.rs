use bitwarden_organizations::OrganizationUserType;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// Password Generator policy.
pub struct PasswordGeneratorPolicy;

impl Policy for PasswordGeneratorPolicy {
    type Data = PasswordGeneratorPolicyData;

    fn policy_type(&self) -> PolicyType {
        PolicyType::PasswordGenerator
    }

    fn to_erased(&self, data: Self::Data) -> PolicyDataType {
        PolicyDataType::PasswordGenerator(data)
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }
}

/// The generator type the policy forces members to use, overriding their own
/// preference.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum PasswordGeneratorType {
    /// Force the password generator.
    Password,
    /// Force the passphrase generator.
    Passphrase,
}

/// Configuration data for the Password Generator policy. Each field, when set,
/// enforces a minimum or a required option on the member's generator.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct PasswordGeneratorPolicyData {
    /// Forces the generator type; `None` leaves the choice to the member.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_password_type: Option<PasswordGeneratorType>,

    /// Minimum password length.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_length: Option<i32>,

    /// Require uppercase letters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_upper: Option<bool>,

    /// Require lowercase letters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_lower: Option<bool>,

    /// Require numbers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_numbers: Option<bool>,

    /// Require special characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_special: Option<bool>,

    /// Minimum number of numeric digits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_numbers: Option<i32>,

    /// Minimum number of special characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_special: Option<i32>,

    /// Minimum number of words (passphrase).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_number_words: Option<i32>,

    /// Require the passphrase to capitalize each word.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capitalize: Option<bool>,

    /// Require the passphrase to include a number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_number: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_full() {
        let data = PasswordGeneratorPolicyData {
            override_password_type: Some(PasswordGeneratorType::Passphrase),
            min_length: Some(14),
            use_upper: Some(true),
            use_lower: Some(true),
            use_numbers: Some(true),
            use_special: Some(false),
            min_numbers: Some(1),
            min_special: Some(0),
            min_number_words: Some(4),
            capitalize: Some(true),
            include_number: Some(true),
        };
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains(r#""overridePasswordType":"passphrase""#));
        assert!(json.contains("minNumberWords"));
        assert_eq!(
            serde_json::from_str::<PasswordGeneratorPolicyData>(&json).unwrap(),
            data
        );
    }

    #[test]
    fn override_password_type_serializes_as_camel_case_string() {
        let json = serde_json::to_string(&PasswordGeneratorPolicyData {
            override_password_type: Some(PasswordGeneratorType::Password),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(json, r#"{"overridePasswordType":"password"}"#);
    }

    #[test]
    fn empty_serializes_to_empty_object() {
        assert_eq!(
            serde_json::to_string(&PasswordGeneratorPolicyData::default()).unwrap(),
            "{}"
        );
    }
}

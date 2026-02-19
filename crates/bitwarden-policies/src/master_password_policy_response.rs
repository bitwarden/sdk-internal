use bitwarden_api_api::models::MasterPasswordPolicyResponseModel;
use serde::{Deserialize, Serialize};

/// SDK domain model for master password policy requirements.
/// Defines the complexity requirements for a user's master password
/// when enforced by an organization policy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct MasterPasswordPolicyResponse {
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

impl From<MasterPasswordPolicyResponseModel> for MasterPasswordPolicyResponse {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_password_policy_conversion_full() {
        let api = MasterPasswordPolicyResponseModel {
            object: Some("masterPasswordPolicy".to_string()),
            min_complexity: Some(4),
            min_length: Some(12),
            require_lower: Some(true),
            require_upper: Some(true),
            require_numbers: Some(true),
            require_special: Some(true),
            enforce_on_login: Some(true),
        };

        let domain: MasterPasswordPolicyResponse = api.into();

        assert_eq!(domain.min_complexity, Some(4));
        assert_eq!(domain.min_length, Some(12));
        assert_eq!(domain.require_lower, Some(true));
        assert_eq!(domain.require_upper, Some(true));
        assert_eq!(domain.require_numbers, Some(true));
        assert_eq!(domain.require_special, Some(true));
        assert_eq!(domain.enforce_on_login, Some(true));
    }

    #[test]
    fn test_master_password_policy_conversion_minimal() {
        let api = MasterPasswordPolicyResponseModel {
            object: Some("masterPasswordPolicy".to_string()),
            min_complexity: None,
            min_length: Some(8),
            require_lower: None,
            require_upper: None,
            require_numbers: None,
            require_special: None,
            enforce_on_login: Some(false),
        };

        let domain: MasterPasswordPolicyResponse = api.into();

        assert_eq!(domain.min_complexity, None);
        assert_eq!(domain.min_length, Some(8));
        assert_eq!(domain.require_lower, None);
        assert_eq!(domain.require_upper, None);
        assert_eq!(domain.require_numbers, None);
        assert_eq!(domain.require_special, None);
        assert_eq!(domain.enforce_on_login, Some(false));
    }

    #[test]
    fn test_master_password_policy_conversion_empty() {
        let api = MasterPasswordPolicyResponseModel {
            object: Some("masterPasswordPolicy".to_string()),
            min_complexity: None,
            min_length: None,
            require_lower: None,
            require_upper: None,
            require_numbers: None,
            require_special: None,
            enforce_on_login: None,
        };

        let domain: MasterPasswordPolicyResponse = api.into();

        assert_eq!(domain.min_complexity, None);
        assert_eq!(domain.min_length, None);
        assert_eq!(domain.require_lower, None);
        assert_eq!(domain.require_upper, None);
        assert_eq!(domain.require_numbers, None);
        assert_eq!(domain.require_special, None);
        assert_eq!(domain.enforce_on_login, None);
    }
}

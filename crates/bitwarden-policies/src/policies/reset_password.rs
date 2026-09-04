use serde::{Deserialize, Serialize};

use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// Account Recovery Administration policy.
pub struct ResetPasswordPolicy;

impl Policy for ResetPasswordPolicy {
    type Data = ResetPasswordPolicyData;

    fn policy_type(&self) -> PolicyType {
        PolicyType::ResetPassword
    }

    fn to_erased(&self, data: Self::Data) -> PolicyDataType {
        PolicyDataType::ResetPassword(data)
    }
}

/// Configuration data for the Account Recovery Administration policy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct ResetPasswordPolicyData {
    /// Whether members are automatically enrolled in account recovery when
    /// they join the organization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_enroll_enabled: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let data = ResetPasswordPolicyData {
            auto_enroll_enabled: Some(true),
        };
        let json = serde_json::to_string(&data).unwrap();
        assert_eq!(json, r#"{"autoEnrollEnabled":true}"#);
        assert_eq!(
            serde_json::from_str::<ResetPasswordPolicyData>(&json).unwrap(),
            data
        );
    }

    #[test]
    fn empty_serializes_to_empty_object() {
        assert_eq!(
            serde_json::to_string(&ResetPasswordPolicyData::default()).unwrap(),
            "{}"
        );
    }

    #[test]
    fn ignores_unknown_fields() {
        let data: ResetPasswordPolicyData =
            serde_json::from_str(r#"{"autoEnrollEnabled":false,"unknown":1}"#).unwrap();
        assert_eq!(data.auto_enroll_enabled, Some(false));
    }
}

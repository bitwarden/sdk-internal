use bitwarden_organizations::OrganizationUserType;
use serde::{Deserialize, Serialize};

use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// Fill Assist policy.
pub struct FillAssistPolicy;

impl Policy for FillAssistPolicy {
    type Data = FillAssistPolicyData;

    fn policy_type(&self) -> PolicyType {
        PolicyType::FillAssist
    }

    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[]
    }

    fn to_erased(&self, data: Self::Data) -> PolicyDataType {
        PolicyDataType::FillAssist(data)
    }
}

/// Configuration data for the Fill Assist policy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct FillAssistPolicyData {
    /// Overrides the default Fill Assist rules feed URL. Absent when the organization has
    /// not configured a custom URL, in which case clients fall back to their server
    /// configuration or the built-in default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules_url: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let data = FillAssistPolicyData {
            rules_url: Some("https://example.com/rules".to_string()),
        };
        let json = serde_json::to_string(&data).unwrap();
        assert_eq!(json, r#"{"rulesUrl":"https://example.com/rules"}"#);
        assert_eq!(
            serde_json::from_str::<FillAssistPolicyData>(&json).unwrap(),
            data
        );
    }

    #[test]
    fn empty_serializes_to_empty_object() {
        assert_eq!(
            serde_json::to_string(&FillAssistPolicyData::default()).unwrap(),
            "{}"
        );
    }
}

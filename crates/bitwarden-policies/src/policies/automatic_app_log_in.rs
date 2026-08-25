use serde::{Deserialize, Serialize};

use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// Automatic App Log-in policy.
pub struct AutomaticAppLogInPolicy;

impl Policy for AutomaticAppLogInPolicy {
    type Data = AutomaticAppLogInPolicyData;

    fn policy_type(&self) -> PolicyType {
        PolicyType::AutomaticAppLogIn
    }

    fn to_erased(&self, data: Self::Data) -> PolicyDataType {
        PolicyDataType::AutomaticAppLogIn(data)
    }
}

/// Configuration data for the Automatic App Log-in policy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct AutomaticAppLogInPolicyData {
    /// The identity provider host used for automatic single sign-on into apps.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idp_host: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let data = AutomaticAppLogInPolicyData {
            idp_host: Some("https://idp.example.com".to_string()),
        };
        let json = serde_json::to_string(&data).unwrap();
        assert_eq!(json, r#"{"idpHost":"https://idp.example.com"}"#);
        assert_eq!(
            serde_json::from_str::<AutomaticAppLogInPolicyData>(&json).unwrap(),
            data
        );
    }

    #[test]
    fn empty_serializes_to_empty_object() {
        assert_eq!(
            serde_json::to_string(&AutomaticAppLogInPolicyData::default()).unwrap(),
            "{}"
        );
    }
}

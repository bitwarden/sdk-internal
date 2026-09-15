use serde::{Deserialize, Serialize};

use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// Send Options policy.
pub struct SendOptionsPolicy;

impl Policy for SendOptionsPolicy {
    type Data = SendOptionsPolicyData;

    fn policy_type(&self) -> PolicyType {
        PolicyType::SendOptions
    }

    fn to_erased(&self, data: Self::Data) -> PolicyDataType {
        PolicyDataType::SendOptions(data)
    }
}

/// Configuration data for the Send Options policy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct SendOptionsPolicyData {
    /// Whether members are prevented from hiding their email address from
    /// Send recipients.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_hide_email: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let data = SendOptionsPolicyData {
            disable_hide_email: Some(true),
        };
        let json = serde_json::to_string(&data).unwrap();
        assert_eq!(json, r#"{"disableHideEmail":true}"#);
        assert_eq!(
            serde_json::from_str::<SendOptionsPolicyData>(&json).unwrap(),
            data
        );
    }

    #[test]
    fn empty_serializes_to_empty_object() {
        assert_eq!(
            serde_json::to_string(&SendOptionsPolicyData::default()).unwrap(),
            "{}"
        );
    }
}

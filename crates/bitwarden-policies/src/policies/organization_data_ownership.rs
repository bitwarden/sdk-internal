use serde::{Deserialize, Serialize};

use crate::{Policy, PolicyType, policy_type::PolicyDataType};

/// Organization Data Ownership policy.
pub struct OrganizationDataOwnershipPolicy;

impl Policy for OrganizationDataOwnershipPolicy {
    type Data = OrganizationDataOwnershipPolicyData;

    fn policy_type(&self) -> PolicyType {
        PolicyType::OrganizationDataOwnership
    }

    fn to_erased(&self, data: Self::Data) -> PolicyDataType {
        PolicyDataType::OrganizationDataOwnership(data)
    }
}

/// Configuration data for the Organization Data Ownership policy.
///
/// Note: the client also sends a `defaultUserCollectionName` in the request
/// metadata (not in the policy `data` blob), so it is intentionally not
/// modeled here.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct OrganizationDataOwnershipPolicyData {
    /// Whether members may transfer individual items into their personal vault.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_individual_items_transfer: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let data = OrganizationDataOwnershipPolicyData {
            enable_individual_items_transfer: Some(true),
        };
        let json = serde_json::to_string(&data).unwrap();
        assert_eq!(json, r#"{"enableIndividualItemsTransfer":true}"#);
        assert_eq!(
            serde_json::from_str::<OrganizationDataOwnershipPolicyData>(&json).unwrap(),
            data
        );
    }

    #[test]
    fn empty_serializes_to_empty_object() {
        assert_eq!(
            serde_json::to_string(&OrganizationDataOwnershipPolicyData::default()).unwrap(),
            "{}"
        );
    }
}

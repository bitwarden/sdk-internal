//! The [`Policy`] record: the raw, persisted representation of an organization policy.

use bitwarden_api_api::models::PolicyResponseModel;
use bitwarden_core::{MissingFieldError, OrganizationId, require};
use bitwarden_uuid::uuid_newtype;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::policy_type::PolicyType;

uuid_newtype!(pub PolicyId);

/// An organization policy in the raw data format that is sent over the FFI.
///
/// This is the storage-layer record. It is resolved into a strongly-typed,
/// per-policy projection at the enforcement boundary.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct Policy {
    /// The policy's unique ID.
    pub id: PolicyId,
    /// The organization this policy belongs to.
    pub organization_id: OrganizationId,
    /// The type of policy.
    pub r#type: PolicyType,
    /// The policy's additional configuration data as a JSON string, if any.
    pub data: Option<String>,
    /// Whether the policy is enabled.
    pub enabled: bool,
    /// When the policy was last modified.
    pub revision_date: Option<DateTime<Utc>>,
}

impl TryFrom<PolicyResponseModel> for Policy {
    type Error = MissingFieldError;

    fn try_from(response: PolicyResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            id: PolicyId::new(require!(response.id)),
            organization_id: OrganizationId::new(require!(response.organization_id)),
            r#type: require!(response.r#type).try_into()?,
            data: response.data.map(|data| data.to_string()),
            enabled: require!(response.enabled),
            revision_date: response
                .revision_date
                .map(|date| date.parse())
                .transpose()
                .map_err(|_| MissingFieldError("revision_date"))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::PolicyType as ApiPolicyType;

    use super::*;

    const TEST_POLICY_ID: &str = "0ae2ad8e-2f1c-4d1b-9d7c-7a4c3f4b8a11";
    const TEST_ORGANIZATION_ID: &str = "5b9e0a0c-7f3e-4b8a-9c1d-2e6f4a8b0c22";

    fn response() -> PolicyResponseModel {
        PolicyResponseModel {
            object: None,
            id: Some(TEST_POLICY_ID.parse().unwrap()),
            organization_id: Some(TEST_ORGANIZATION_ID.parse().unwrap()),
            r#type: Some(ApiPolicyType::MasterPassword),
            data: Some(serde_json::json!({ "minLength": 12 })),
            enabled: Some(true),
            revision_date: Some("2024-01-01T00:00:00Z".to_owned()),
        }
    }

    #[test]
    fn converts_policy_response() {
        let policy = Policy::try_from(response()).unwrap();

        assert_eq!(policy.id.to_string(), TEST_POLICY_ID);
        assert_eq!(policy.organization_id.to_string(), TEST_ORGANIZATION_ID);
        assert_eq!(policy.r#type, PolicyType::MasterPassword);
        assert_eq!(policy.data.as_deref(), Some(r#"{"minLength":12}"#));
        assert!(policy.enabled);
        assert_eq!(
            policy.revision_date.unwrap().to_rfc3339(),
            "2024-01-01T00:00:00+00:00"
        );
    }

    #[test]
    fn rejects_unknown_policy_type() {
        let response = PolicyResponseModel {
            r#type: Some(ApiPolicyType::__Unknown(999)),
            ..response()
        };

        assert!(Policy::try_from(response).is_err());
    }

    #[test]
    fn rejects_malformed_revision_date() {
        let response = PolicyResponseModel {
            revision_date: Some("yesterday".to_owned()),
            ..response()
        };

        assert!(Policy::try_from(response).is_err());
    }
}

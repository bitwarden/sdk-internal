//! The [`Policy`] record: the raw, persisted representation of an organization policy.

use bitwarden_core::{MissingFieldError, OrganizationId, require};
use bitwarden_uuid::uuid_newtype;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::policy_type::PolicyType;

uuid_newtype!(pub PolicyId);

/// An organization policy in the raw data format that is sent over the FFI.
///
/// This is the storage-layer record. It is resolved into a strongly-typed,
/// per-policy projection at the enforcement boundary.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
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

bitwarden_state::register_repository_item!(PolicyId => Policy, "Policy");

/// Errors that can occur when parsing a [`Policy`] from its raw API representation.
#[derive(Debug, thiserror::Error)]
pub enum PolicyParseError {
    /// A required field was missing from the API response.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    /// The server returned a policy type this SDK version does not recognize.
    #[error("Unknown policy type: {0}")]
    UnknownPolicyType(i64),
    /// The revision date could not be parsed.
    #[error(transparent)]
    InvalidRevisionDate(#[from] chrono::ParseError),
}

impl TryFrom<bitwarden_api_api::models::PolicyResponseModel> for Policy {
    type Error = PolicyParseError;

    fn try_from(
        policy: bitwarden_api_api::models::PolicyResponseModel,
    ) -> Result<Self, Self::Error> {
        Ok(Policy {
            id: PolicyId::new(require!(policy.id)),
            organization_id: OrganizationId::new(require!(policy.organization_id)),
            r#type: require!(policy.r#type).try_into()?,
            data: policy.data.map(|d| d.to_string()),
            enabled: require!(policy.enabled),
            revision_date: policy.revision_date.map(|d| d.parse()).transpose()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::{PolicyResponseModel, PolicyType as ApiPolicyType};

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

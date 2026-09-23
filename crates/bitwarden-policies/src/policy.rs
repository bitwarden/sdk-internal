//! The [`Policy`] record: the raw, persisted representation of an organization policy.

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

//! The [`PolicyView`] record: the raw, persisted representation of an organization policy.

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
/// TODO: this is misnamed, but changing it is a breaking change.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct PolicyView {
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

bitwarden_state::register_repository_item!(PolicyId => PolicyView, "Policy");

/// Errors that can occur when converting a server [`PolicyResponseModel`] into a [`PolicyView`].
#[derive(Debug, thiserror::Error)]
pub enum PolicyParseError {
    /// A required field was missing from the server response.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    /// The server sent a policy type this SDK version does not recognise.
    #[error("Unknown policy type: {0}")]
    UnknownPolicyType(i64),
    /// The revision date could not be parsed.
    #[error(transparent)]
    InvalidRevisionDate(#[from] chrono::ParseError),
}

impl TryFrom<PolicyResponseModel> for PolicyView {
    type Error = PolicyParseError;

    fn try_from(model: PolicyResponseModel) -> Result<Self, Self::Error> {
        Ok(PolicyView {
            id: PolicyId::new(require!(model.id)),
            organization_id: OrganizationId::new(require!(model.organization_id)),
            r#type: require!(model.r#type).try_into()?,
            // The raw JSON blob is stored verbatim and parsed per-policy at enforcement time.
            data: model.data.map(|d| d.to_string()),
            enabled: require!(model.enabled),
            revision_date: model.revision_date.map(|d| d.parse()).transpose()?,
        })
    }
}

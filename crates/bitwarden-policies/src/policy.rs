//! The [`Policy`] record: the raw, persisted representation of an organization policy.

use bitwarden_core::OrganizationId;
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

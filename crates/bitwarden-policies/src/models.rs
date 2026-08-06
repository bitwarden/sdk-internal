//! Data models for the policy domain.
//!
//! These are the inputs to the policy filtering API and are exposed across the
//! FFI boundary.

use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;
use uuid::Uuid;

use crate::policy_type::PolicyType;

/// An organization policy.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct PolicyView {
    /// The policy's unique ID.
    pub id: Uuid,
    /// The organization this policy belongs to.
    pub organization_id: Uuid,
    /// The type of policy.
    pub r#type: PolicyType,
    /// The policy's additional configuration data as a JSON string, if any.
    pub data: Option<String>,
    /// Whether the policy is enabled.
    pub enabled: bool,
    /// When the policy was last modified.
    pub revision_date: Option<DateTime<Utc>>,
}

/// A minimal set of data for a user in an organization. This provides
/// the context needed to evaluate the policies that are applied to the
/// user by the organization.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct OrganizationUserPolicyContext {
    /// The organization's unique ID.
    pub id: Uuid,
    /// The user's membership status in the organization.
    pub status: OrganizationUserStatusType,
    /// The user's role within the organization.
    pub role: OrganizationUserType,
    /// Whether the organization is enabled.
    pub enabled: bool,
    /// Whether the organization's plan supports policies.
    pub use_policies: bool,
    /// Whether the user is acting on behalf of a provider
    /// that manages the organization.
    pub is_provider_user: bool,
}

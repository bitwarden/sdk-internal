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
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct PolicyView {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub r#type: PolicyType,
    /// The policy's raw configuration data as a JSON string, if any.
    pub data: Option<String>,
    pub enabled: bool,
    pub revision_date: Option<DateTime<Utc>>,
}

/// Minimal organization data needed to evaluate organization policies for a
/// user.
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct PolicyOrganizationContext {
    pub id: Uuid,
    pub status: OrganizationUserStatusType,
    pub role: OrganizationUserType,
    pub enabled: bool,
    pub use_policies: bool,
    pub is_provider_user: bool,
}

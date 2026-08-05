//! Data models for the policy domain.
//!
//! These are the inputs to the policy filtering API and are exposed across the
//! FFI boundary.

use std::collections::HashMap;

use bitwarden_core::OrganizationId;
use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;
use uuid::Uuid;

use crate::{
    Policy,
    policy_type::{PolicyDataType, PolicyType},
};

/// An organization policy.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct PolicyView {
    /// The policy's unique ID.
    pub id: Uuid,
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

/// A minimal set of data for a user in an organization. This provides
/// the context needed to evaluate the policies that are applied to the
/// user by the organization.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct OrganizationUserPolicyContext {
    /// The organization's unique ID.
    pub id: OrganizationId,
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

/// A per-organization enforcement decision for a single policy type.
///
/// Unlike [`PolicyView`] (the server-side record), this carries only the
/// fields relevant to an enforcement decision: `enforced` reflects the
/// user-specific evaluation rather than the policy's raw `enabled` flag, and
/// `data` is strongly typed via [`PolicyData::Data`].
///
/// `data` is always populated. When no matching policy is found, or when the
/// policy record's data could not be parsed, `data` is [`Default::default()`].
#[derive(Debug, Clone, PartialEq)]
pub struct EnforcedPolicy<P: Policy> {
    /// The organization this enforcement decision is for.
    pub organization_id: OrganizationId,
    /// The policy type.
    pub data: P::Data,
    /// Whether the policy is being enforced against the current user for this
    /// organization.
    pub enforced: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct EnforcedPolicyErased {
    /// The organization this enforcement decision is for.
    pub organization_id: OrganizationId,
    /// The policy type.
    pub data: PolicyDataType,
    /// Whether the policy is being enforced against the current user for this
    /// organization.
    pub enforced: bool,
}

impl<P: Policy> EnforcedPolicy<P> {
    /// Constructs a new EnforcedPolicy, evaluating whether the policy should be
    /// enforced against the user or not.
    /// If the organization context is missing for the corresponding organization,
    /// it will be enforced by default (err on the side of enforcement).
    pub fn new(
        organization_id: OrganizationId,
        policy: &P,
        policy_views: &[PolicyView],
        organization_user_policy_contexts: &HashMap<OrganizationId, &OrganizationUserPolicyContext>,
    ) -> EnforcedPolicy<P> {
        // Resolve policy_view here so that a mismatch between the Policy.policy_type and
        // policy_view.type is not possible
        let view = policy_views
            .iter()
            .find(|v| v.organization_id == organization_id && v.r#type == policy.policy_type());
        let context = organization_user_policy_contexts.get(&organization_id);

        let data = match view.and_then(|v| v.data.as_deref()) {
            Some(raw) => serde_json::from_str(raw).unwrap_or_else(|e| {
                tracing::warn!(
                    policy_type = ?policy.policy_type(),
                    %organization_id,
                    "Failed to parse policy data, falling back to default: {e}"
                );
                Default::default()
            }),
            None => Default::default(),
        };

        let enforced = match view {
            None => false,
            Some(v) => context.map_or(true, |ctx| {
                v.enabled
                    && ctx.enabled
                    && ctx.use_policies
                    && policy.applicable_statuses().contains(&ctx.status)
                    && !policy.exempt_roles().contains(&ctx.role)
                    && !(ctx.is_provider_user && policy.exempt_providers())
            }),
        };

        EnforcedPolicy {
            organization_id,
            data,
            enforced,
        }
    }

    /// Consumes this decision and erases its strongly-typed `data` into the
    /// FFI-friendly [`PolicyDataType`] via [`Policy::to_erased`].
    fn erase(self, policy: &P) -> EnforcedPolicyErased {
        EnforcedPolicyErased {
            organization_id: self.organization_id,
            data: policy.to_erased(self.data),
            enforced: self.enforced,
        }
    }
}

/// Object-safe erasure of [`Policy`].
///
/// [`Policy`] cannot be used as a trait object because it has an associated
/// [`Data`](Policy::Data) type. This trait hides that type behind the
/// serializable [`PolicyDataType`], letting a runtime
/// [`PolicyType`](crate::PolicyType) be dispatched to its concrete (zero-sized)
/// implementation for the FFI boundary.
pub(crate) trait ErasedPolicy {
    /// Evaluates enforcement for a single organization and erases the result.
    fn get_enforced_erased(
        &self,
        organization_id: OrganizationId,
        policy_views: &[PolicyView],
        organization_user_policy_contexts: &HashMap<OrganizationId, &OrganizationUserPolicyContext>,
    ) -> EnforcedPolicyErased;

    /// Evaluates enforcement for every organization in `policy_views` and erases
    /// each result.
    fn get_many_enforced_erased(
        &self,
        policy_views: &[PolicyView],
        organization_user_policy_contexts: &HashMap<OrganizationId, &OrganizationUserPolicyContext>,
    ) -> Vec<EnforcedPolicyErased>;
}

impl<P: Policy> ErasedPolicy for P {
    fn get_enforced_erased(
        &self,
        organization_id: OrganizationId,
        policy_views: &[PolicyView],
        organization_user_policy_contexts: &HashMap<OrganizationId, &OrganizationUserPolicyContext>,
    ) -> EnforcedPolicyErased {
        EnforcedPolicy::new(
            organization_id,
            self,
            policy_views,
            organization_user_policy_contexts,
        )
        .erase(self)
    }

    fn get_many_enforced_erased(
        &self,
        policy_views: &[PolicyView],
        organization_user_policy_contexts: &HashMap<OrganizationId, &OrganizationUserPolicyContext>,
    ) -> Vec<EnforcedPolicyErased> {
        policy_views
            .iter()
            .map(|v| {
                EnforcedPolicy::new(
                    v.organization_id,
                    self,
                    policy_views,
                    organization_user_policy_contexts,
                )
                .erase(self)
            })
            .collect()
    }
}

//! Data models for the policy domain.

use std::{any::TypeId, collections::HashMap};

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

/// An organization policy in the raw data format that is sent over the FFI.
///
/// TODO: this is misnamed, but changing it is a breaking change.
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
/// user.
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
/// `data` is strongly typed via [`Policy::Data`].
///
/// `data` is always populated. It is [`Default::default()`] whenever the policy
/// is not enforced against the user, when no matching policy is found, or when
/// the policy record's data could not be parsed.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EnforcedPolicy<P: Policy> {
    /// The organization this enforcement decision is for.
    pub organization_id: OrganizationId,
    /// The policy data, if any.
    pub data: P::Data,
    /// Whether the policy should be enforced against the current user for this
    /// organization.
    pub enforced: bool,
}

impl<P: Policy> EnforcedPolicy<P> {
    /// The decision for an organization that has no matching policy: not
    /// enforced, with [`Default`] data.
    pub(crate) fn not_enforced(organization_id: OrganizationId) -> Self {
        Self {
            organization_id,
            data: Default::default(),
            enforced: false,
        }
    }

    /// Consumes this decision into its FFI-friendly form, erasing the
    /// strongly-typed `data` into a [`PolicyDataType`] via [`Policy::to_erased`].
    pub(crate) fn into_erased(self, policy: &P) -> EnforcedPolicyErased {
        EnforcedPolicyErased {
            organization_id: self.organization_id,
            data: policy.to_erased(self.data),
            enforced: self.enforced,
        }
    }
}

/// The FFI-facing counterpart of the native `EnforcedPolicy`, with its
/// strongly-typed `data` erased to [`PolicyDataType`] so it can cross the
/// binding boundary.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct EnforcedPolicyErased {
    /// The organization this enforcement decision is for.
    pub organization_id: OrganizationId,
    /// The policy data, if any.
    pub data: PolicyDataType,
    /// Whether the policy is being enforced against the current user for this
    /// organization.
    pub enforced: bool,
}

/// A [`PolicyView`] resolved against the concrete [`Policy`] that handles it.
///
/// This is the typed domain value the untyped wire [`PolicyView`] transforms into
/// at the boundary: the `r#type` discriminant has been matched and the untyped
/// `data` blob parsed into [`Policy::Data`], so a policy can only ever be paired
/// with its own data type.
pub(crate) struct ResolvedPolicyView<P: Policy> {
    organization_id: OrganizationId,
    enabled: bool,
    data: P::Data,
}

impl<P: Policy> ResolvedPolicyView<P> {
    /// Resolves `view` against `policy`, returning `Some` only when the view is
    /// the type handled by `policy`.
    ///
    /// Deserializes the untyped `data` blob into `P::Data`, falling back to
    /// [`Default`] (with a warning) when it is absent or fails to parse.
    ///
    /// By default, a single unrecognised value within `P::Data` will fail
    /// parsing of the entire struct. Individual policies should provide their
    /// own handling at the field level if this is unacceptable.
    pub(crate) fn resolve(policy: &P, view: &PolicyView) -> Option<Self> {
        if view.r#type != policy.policy_type() {
            return None;
        }

        let data = match view.data.as_deref() {
            Some(raw) => serde_json::from_str(raw).unwrap_or_else(|e| {
                if TypeId::of::<P::Data>() == TypeId::of::<()>() {
                    // Any non-null value will fail to deserialize to ().
                    // This is a separate case to receiving malformed data - log it separately.
                    tracing::debug!(
                        policy_type = ?policy.policy_type(),
                        organization_id = %view.organization_id,
                        "Ignoring unexpected data for a policy type that models none"
                    );
                } else {
                    tracing::warn!(
                        policy_type = ?policy.policy_type(),
                        organization_id = %view.organization_id,
                        "Failed to parse policy data, falling back to default: {e}"
                    );
                }
                Default::default()
            }),
            None => Default::default(),
        };

        Some(Self {
            organization_id: view.organization_id,
            enabled: view.enabled,
            data,
        })
    }

    /// Consumes the resolved view into an [`EnforcedPolicy`], evaluating whether
    /// `policy` is enforced against the user.
    ///
    /// Pass in all organization contexts for this user; the specific context is looked
    /// up by this method so that a mismatch between policy and organization is not possible.
    /// If no context is present for the organization, the policy is enforced by default
    /// (err on the side of enforcement).
    pub(crate) fn into_enforced(
        self,
        policy: &P,
        organization_user_policy_contexts: &HashMap<OrganizationId, &OrganizationUserPolicyContext>,
    ) -> EnforcedPolicy<P> {
        let context = organization_user_policy_contexts.get(&self.organization_id);

        let enforced = self.enabled
            && context.is_none_or(|ctx| {
                ctx.enabled
                    && ctx.use_policies
                    && policy.enforced_statuses().contains(&ctx.status)
                    && !policy.exempt_roles().contains(&ctx.role)
                    && !(ctx.is_provider_user && policy.exempt_providers())
            });

        if enforced {
            EnforcedPolicy {
                organization_id: self.organization_id,
                data: self.data,
                enforced,
            }
        } else {
            EnforcedPolicy::not_enforced(self.organization_id)
        }
    }
}

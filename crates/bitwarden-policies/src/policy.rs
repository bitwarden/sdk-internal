use std::collections::HashMap;

use bitwarden_core::OrganizationId;
use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
use serde::de::DeserializeOwned;

use crate::{
    OrganizationUserPolicyContext, PolicyView,
    models::{EnforcedPolicy, EnforcedPolicyErased},
    policy_type::{PolicyDataType, PolicyType},
};

/// Declares which organization members a specific policy type applies to.
///
/// An implementor identifies the [`PolicyType`] it handles and specifies the
/// role exemptions, applicable membership statuses, and provider exemption.
/// The defaults match the most common Bitwarden policy: exempt Owners and
/// Admins, exempt provider users, apply to Accepted and Confirmed members.
///
/// Ready-made implementations for the built-in policy types live in
/// [`policy_overrides`](crate::policy_overrides).
pub trait Policy: Send + Sync + 'static {
    /// Returns the policy type this definition handles.
    fn policy_type(&self) -> PolicyType;

    fn to_erased(&self, data: Self::Data) -> PolicyDataType;

    /// The strongly-typed data for this policy. The [`Default`] value is
    /// the fall-back whenever the policy is not enforced or the raw data could
    /// not be parsed.
    type Data: Default + DeserializeOwned;

    /// Returns the organization roles that are exempt from this policy.
    ///
    /// Defaults to [`Owner`](OrganizationUserType::Owner) and
    /// [`Admin`](OrganizationUserType::Admin).
    fn exempt_roles(&self) -> &[OrganizationUserType] {
        &[OrganizationUserType::Owner, OrganizationUserType::Admin]
    }

    /// Returns whether provider users are exempt from this policy.
    ///
    /// Defaults to `true`.
    fn exempt_providers(&self) -> bool {
        true
    }

    /// Returns the organization membership statuses for which this policy applies.
    ///
    /// Defaults to [`Accepted`](OrganizationUserStatusType::Accepted) and
    /// [`Confirmed`](OrganizationUserStatusType::Confirmed).
    fn applicable_statuses(&self) -> &[OrganizationUserStatusType] {
        &[
            OrganizationUserStatusType::Accepted,
            OrganizationUserStatusType::Confirmed,
        ]
    }
}

/// Evaluates whether a [`Policy`] is enforced against the current user for a
/// given organization.
///
/// Implemented for every [`Policy`] via a blanket implementation, mirroring the
/// object-safe [`ErasedPolicy`](crate::models::ErasedPolicy).
pub(crate) trait EnforceablePolicy: Policy {
    /// Constructs a new [`EnforcedPolicy`], evaluating whether the policy should
    /// be enforced against the user or not.
    ///
    /// If the organization context is missing for the corresponding
    /// organization, it will be enforced by default (err on the side of
    /// enforcement).
    fn get_enforced(
        &self,
        organization_id: OrganizationId,
        policy_views: &[PolicyView],
        organization_user_policy_contexts: &HashMap<OrganizationId, &OrganizationUserPolicyContext>,
    ) -> EnforcedPolicy<Self>
    where
        Self: Sized;
}

impl<P: Policy> EnforceablePolicy for P {
    fn get_enforced(
        &self,
        organization_id: OrganizationId,
        policy_views: &[PolicyView],
        organization_user_policy_contexts: &HashMap<OrganizationId, &OrganizationUserPolicyContext>,
    ) -> EnforcedPolicy<P> {
        // Resolve policy_view here so that a mismatch between the Policy.policy_type and
        // policy_view.type is not possible
        let view = policy_views
            .iter()
            .find(|v| v.organization_id == organization_id && v.r#type == self.policy_type());
        let context = organization_user_policy_contexts.get(&organization_id);

        let data = match view.and_then(|v| v.data.as_deref()) {
            Some(raw) => serde_json::from_str(raw).unwrap_or_else(|e| {
                tracing::warn!(
                    policy_type = ?self.policy_type(),
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
                    && self.applicable_statuses().contains(&ctx.status)
                    && !self.exempt_roles().contains(&ctx.role)
                    && !(ctx.is_provider_user && self.exempt_providers())
            }),
        };

        EnforcedPolicy {
            organization_id,
            data,
            enforced,
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
        let decision = self.get_enforced(
            organization_id,
            policy_views,
            organization_user_policy_contexts,
        );
        EnforcedPolicyErased {
            organization_id: decision.organization_id,
            data: self.to_erased(decision.data),
            enforced: decision.enforced,
        }
    }

    fn get_many_enforced_erased(
        &self,
        policy_views: &[PolicyView],
        organization_user_policy_contexts: &HashMap<OrganizationId, &OrganizationUserPolicyContext>,
    ) -> Vec<EnforcedPolicyErased> {
        policy_views
            .iter()
            .map(|v| {
                let decision = self.get_enforced(
                    v.organization_id,
                    policy_views,
                    organization_user_policy_contexts,
                );
                EnforcedPolicyErased {
                    organization_id: decision.organization_id,
                    data: self.to_erased(decision.data),
                    enforced: decision.enforced,
                }
            })
            .collect()
    }
}

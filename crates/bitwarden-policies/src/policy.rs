use std::collections::HashMap;

use bitwarden_core::OrganizationId;
use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
use serde::de::DeserializeOwned;

use crate::{
    OrganizationUserPolicyContext, PolicyView,
    models::{EnforcedPolicy, EnforcedPolicyErased, ResolvedPolicyView},
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

/// Evaluates whether a [`Policy`] is enforced against the current user.
///
/// Implemented for every [`Policy`] via a blanket implementation, mirroring the
/// object-safe [`ErasedPolicy`].
pub(crate) trait EnforceablePolicy: Policy {
    /// Constructs a new [`EnforcedPolicy`] for a single organization, evaluating
    /// whether the policy should be enforced against the user or not.
    ///
    /// If the organization context is missing for the corresponding
    /// organization, it will be enforced by default (err on the side of
    /// enforcement).
    fn get_enforced(
        &self,
        organization_id: OrganizationId,
        policy_views: &[PolicyView],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> EnforcedPolicy<Self>
    where
        Self: Sized;

    /// Constructs an [`EnforcedPolicy`] for every view matching this policy's
    /// type, in a single pass over `policy_views`.
    fn get_all_enforced(
        &self,
        policy_views: &[PolicyView],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> Vec<EnforcedPolicy<Self>>
    where
        Self: Sized;
}

impl<P: Policy> EnforceablePolicy for P {
    fn get_enforced(
        &self,
        organization_id: OrganizationId,
        policy_views: &[PolicyView],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> EnforcedPolicy<P> {
        let contexts: HashMap<OrganizationId, &OrganizationUserPolicyContext> =
            organization_user_policy_contexts
                .iter()
                .map(|ctx| (ctx.id, ctx))
                .collect();

        // Resolve the untyped views into a typed ResolvedPolicyView so a mismatch between
        // Policy.policy_type and policy_view.type cannot be represented downstream.
        let resolved = policy_views
            .iter()
            .filter(|v| v.organization_id == organization_id)
            .find_map(|v| ResolvedPolicyView::resolve(self, v));

        match resolved {
            Some(resolved) => resolved.into_enforced(self, &contexts),
            None => EnforcedPolicy::not_enforced(organization_id),
        }
    }

    fn get_all_enforced(
        &self,
        policy_views: &[PolicyView],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> Vec<EnforcedPolicy<P>> {
        let contexts: HashMap<OrganizationId, &OrganizationUserPolicyContext> =
            organization_user_policy_contexts
                .iter()
                .map(|ctx| (ctx.id, ctx))
                .collect();

        // Resolve each view this policy handles once (a mismatch is unrepresentable via
        // ResolvedPolicyView) and pair it with an O(1) context lookup, keeping this linear.
        policy_views
            .iter()
            .filter_map(|v| ResolvedPolicyView::resolve(self, v))
            .map(|resolved| resolved.into_enforced(self, &contexts))
            .collect()
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
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> EnforcedPolicyErased;

    /// Evaluates enforcement for every organization in `policy_views` and erases
    /// each result.
    fn get_many_enforced_erased(
        &self,
        policy_views: &[PolicyView],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> Vec<EnforcedPolicyErased>;
}

impl<P: Policy> ErasedPolicy for P {
    fn get_enforced_erased(
        &self,
        organization_id: OrganizationId,
        policy_views: &[PolicyView],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> EnforcedPolicyErased {
        self.get_enforced(
            organization_id,
            policy_views,
            organization_user_policy_contexts,
        )
        .into_erased(self)
    }

    fn get_many_enforced_erased(
        &self,
        policy_views: &[PolicyView],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> Vec<EnforcedPolicyErased> {
        self.get_all_enforced(policy_views, organization_user_policy_contexts)
            .into_iter()
            .map(|decision| decision.into_erased(self))
            .collect()
    }
}

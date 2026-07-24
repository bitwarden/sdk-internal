use std::collections::HashMap;

use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
use uuid::Uuid;

use crate::{
    models::{OrganizationUserPolicyContext, PolicyView},
    policy_type::PolicyType,
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

/// Adds the [`enforced`](PolicyFilter::enforced) (single decision) and
/// [`filter`](PolicyFilter::filter) (bulk filter) enforcement methods to every
/// [`Policy`].
///
/// For typed-data decisions, prefer
/// [`EnforcedPolicyFilter`](super::EnforcedPolicyFilter) /
/// [`PolicyAggregateFilter`](super::PolicyAggregateFilter) which return a
/// structured [`EnforcedPolicy`](super::EnforcedPolicy) /
/// [`EnforcedAggregatePolicy`](super::EnforcedAggregatePolicy). Use
/// [`PolicyFilter::filter`] only when you need the raw [`PolicyView`]s back.
///
/// Blanket-implemented for all `T: Policy`.
pub trait PolicyFilter: Policy {
    /// Returns whether `view` is enforced against the user described by
    /// `context`. When `context` is `None`, the policy is enforced — unknown
    /// organizations are treated as in-scope by default so policies are not
    /// silently bypassed.
    ///
    /// # Inputs
    ///
    /// `view.r#type` must equal [`self.policy_type()`](Policy::policy_type),
    /// and when `context` is `Some`, `context.id` must equal
    /// `view.organization_id`. Both invariants should be guaranteed by
    /// upstream filtering and lookup.
    ///
    /// # Panics
    ///
    /// Panics if either invariant above is violated.
    fn enforced(&self, view: &PolicyView, context: Option<&OrganizationUserPolicyContext>) -> bool {
        // Sanity checks: if inputs are invalid, refuse to make an enforcement decision
        // TODO: should this panic or return a result?
        if view.r#type != self.policy_type() {
            panic!(
                "Policy type mismatch: filter for type {:?} called with actual policy type {:?}",
                self.policy_type(),
                view.r#type
            );
        }

        if let Some(c) = context
            && c.id != view.organization_id
        {
            panic!(
                "Policy organization mismatch: policy for organization {:?} called with context for organization {:?}",
                view.organization_id, c.id
            );
        }

        if !view.enabled {
            return false;
        }

        match context {
            Some(org) => {
                org.enabled
                    && org.use_policies
                    && self.applicable_statuses().contains(&org.status)
                    && !self.exempt_roles().contains(&org.role)
                    && !(org.is_provider_user && self.exempt_providers())
            }
            None => true, // Unknown org: enforce by default
        }
    }

    /// Filters `policies` to those that should be enforced against the user.
    /// This evaluates common business rules (e.g. the policy is enabled),
    /// as well as policy-specific rules according to its [`Policy`].
    ///
    /// `policies` may include other policy types; entries whose `type` field
    /// does not match [`Policy::policy_type`] are dropped.
    ///
    /// If a policy's organization is not present in
    /// `organization_user_policy_contexts`, the policy is enforced — unknown
    /// organizations are treated as in-scope by default so policies are not
    /// silently bypassed.
    fn filter<'a>(
        &self,
        policies: &'a [PolicyView],
        organization_user_policy_contexts: &[OrganizationUserPolicyContext],
    ) -> Vec<&'a PolicyView> {
        let org_map: HashMap<&Uuid, &OrganizationUserPolicyContext> =
            organization_user_policy_contexts
                .iter()
                .map(|o| (&o.id, o))
                .collect();

        policies
            .iter()
            .filter(|p| p.r#type == self.policy_type())
            .filter(|p| self.enforced(p, org_map.get(&p.organization_id).copied()))
            .collect()
    }
}

impl<T: Policy> PolicyFilter for T {}

#[cfg(test)]
mod tests {
    use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
    use uuid::Uuid;

    use super::*;
    use crate::enforcement::test_helpers::*;

    #[test]
    #[should_panic(expected = "Policy type mismatch")]
    fn enforced_panics_if_policy_type_mismatch() {
        let org_id = Uuid::new_v4();
        let view = policy_view(org_id, PolicyType::PasswordGenerator, true);
        let ctx = organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Confirmed,
            false,
        );

        let _ = TestMasterPasswordPolicy.enforced(&view, Some(&ctx));
    }

    #[test]
    #[should_panic(expected = "Policy organization mismatch")]
    fn enforced_panics_if_organization_mismatch() {
        let view = policy_view(Uuid::new_v4(), PolicyType::MasterPassword, true);
        let ctx = organization(
            Uuid::new_v4(),
            OrganizationUserType::User,
            OrganizationUserStatusType::Confirmed,
            false,
        );

        let _ = TestMasterPasswordPolicy.enforced(&view, Some(&ctx));
    }

    #[test]
    fn filter_matching_policy_is_returned() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MasterPassword, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Confirmed,
            false,
        )];

        let result = TestMasterPasswordPolicy.filter(&policies, &orgs);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn filter_disabled_organization_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let orgs = [OrganizationUserPolicyContext {
            enabled: false,
            id: org_id,
            role: OrganizationUserType::User,
            status: OrganizationUserStatusType::Confirmed,
            use_policies: true,
            is_provider_user: false,
        }];
        let policies = [policy_view(org_id, PolicyType::MasterPassword, true)];

        let result = TestMasterPasswordPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_disabled_policy_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MasterPassword, false)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Confirmed,
            false,
        )];

        let result = TestMasterPasswordPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_wrong_policy_type_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::PasswordGenerator, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Confirmed,
            false,
        )];

        let result = TestMasterPasswordPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_use_policies_false_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let orgs = [OrganizationUserPolicyContext {
            id: org_id,
            role: OrganizationUserType::User,
            status: OrganizationUserStatusType::Confirmed,
            enabled: true,
            use_policies: false,
            is_provider_user: false,
        }];
        let policies = [policy_view(org_id, PolicyType::MasterPassword, true)];

        let result = TestMasterPasswordPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_exempt_role_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MasterPassword, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::Owner,
            OrganizationUserStatusType::Confirmed,
            false,
        )];

        let result = TestMasterPasswordPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_non_applicable_status_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MasterPassword, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Revoked,
            false,
        )];

        let result = TestMasterPasswordPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_provider_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MasterPassword, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Confirmed,
            true,
        )];

        let result = TestMasterPasswordPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_missing_org_enforces_by_default() {
        let policies = [policy_view(
            Uuid::new_v4(),
            PolicyType::MasterPassword,
            true,
        )];

        let result = TestMasterPasswordPolicy.filter(&policies, &[]);
        assert_eq!(result.len(), 1);
    }
}

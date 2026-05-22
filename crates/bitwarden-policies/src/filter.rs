#![allow(dead_code)]

//! Policy filtering logic.
//!
//! Provides the [`Policy`] trait for determining which policies
//! should be enforced against the current user based on business rules.

use std::collections::HashMap;

use bitwarden_organizations::{OrganizationUserStatusType, OrganizationUserType};
use uuid::Uuid;

use crate::{
    models::{PolicyOrganizationContext, PolicyView},
    policy_type::PolicyType,
};

/// Defines the filtering behavior for a specific policy type.
///
/// Implement this trait to control how a policy is enforced.
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

/// Extension trait that adds a [`filter`](PolicyFilter::filter) method to every [`Policy`].
///
/// Implemented automatically for all `T: Policy`.
pub trait PolicyFilter: Policy {
    /// Filters `policies` to those that should be enforced against the user.
    /// This evaluates common business rules (e.g. the policy is enabled),
    /// as well as policy-specific rules according to its [`Policy`].
    ///
    /// If a policy's organization is not present in `organization_user_policy_contexts`, the policy
    /// is enforced by default.
    fn filter<'a>(
        &self,
        policies: &'a [PolicyView],
        organization_user_policy_contexts: &[PolicyOrganizationContext],
    ) -> Vec<&'a PolicyView> {
        let org_map: HashMap<&Uuid, &PolicyOrganizationContext> = organization_user_policy_contexts
            .iter()
            .map(|o| (&o.id, o))
            .collect();

        policies
            .iter()
            .filter(|p| p.r#type == self.policy_type())
            .filter(|p| p.enabled)
            .filter(|p| {
                match org_map.get(&p.organization_id) {
                    Some(org) => {
                        org.enabled
                            && org.use_policies
                            && self.applicable_statuses().contains(&org.status)
                            && !self.exempt_roles().contains(&org.role)
                            && !(org.is_provider_user && self.exempt_providers())
                    }
                    None => true, // Unknown org: enforce by default
                }
            })
            .collect()
    }
}

impl<T: Policy> PolicyFilter for T {}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_view(organization_id: Uuid, policy_type: PolicyType, enabled: bool) -> PolicyView {
        PolicyView {
            id: Uuid::new_v4(),
            organization_id,
            r#type: policy_type,
            data: None,
            enabled,
            revision_date: Default::default(),
        }
    }

    fn organization(
        id: Uuid,
        user_type: OrganizationUserType,
        status: OrganizationUserStatusType,
        provider: bool,
    ) -> PolicyOrganizationContext {
        PolicyOrganizationContext {
            id,
            role: user_type,
            status,
            enabled: true,
            use_policies: true,
            is_provider_user: provider,
        }
    }

    struct TestPolicy;
    impl Policy for TestPolicy {
        fn policy_type(&self) -> PolicyType {
            PolicyType::MasterPassword
        }

        // These happen to match the default impl, but repeating here
        // to decouple the filter tests from the default impl
        fn exempt_roles(&self) -> &[OrganizationUserType] {
            &[OrganizationUserType::Owner, OrganizationUserType::Admin]
        }

        fn exempt_providers(&self) -> bool {
            true
        }

        fn applicable_statuses(&self) -> &[OrganizationUserStatusType] {
            &[
                OrganizationUserStatusType::Accepted,
                OrganizationUserStatusType::Confirmed,
            ]
        }
    }

    #[test]
    fn matching_policy_is_returned() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MasterPassword, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Confirmed,
            false,
        )];

        let result = TestPolicy.filter(&policies, &orgs);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn disabled_organization_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let orgs = [PolicyOrganizationContext {
            enabled: false,
            id: org_id,
            role: OrganizationUserType::User,
            status: OrganizationUserStatusType::Confirmed,
            use_policies: true,
            is_provider_user: false,
        }];
        let policies = [policy_view(org_id, PolicyType::MasterPassword, true)];

        let result = TestPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn disabled_policy_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MasterPassword, false)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Confirmed,
            false,
        )];

        let result = TestPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn wrong_policy_type_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::PasswordGenerator, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Confirmed,
            false,
        )];

        let result = TestPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn use_policies_false_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let orgs = [PolicyOrganizationContext {
            id: org_id,
            role: OrganizationUserType::User,
            status: OrganizationUserStatusType::Confirmed,
            enabled: true,
            use_policies: false,
            is_provider_user: false,
        }];
        let policies = [policy_view(org_id, PolicyType::MasterPassword, true)];

        let result = TestPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn exempt_role_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MasterPassword, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::Owner,
            OrganizationUserStatusType::Confirmed,
            false,
        )];

        let result = TestPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn non_applicable_status_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MasterPassword, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Revoked,
            false,
        )];

        let result = TestPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn provider_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, PolicyType::MasterPassword, true)];
        let orgs = [organization(
            org_id,
            OrganizationUserType::User,
            OrganizationUserStatusType::Confirmed,
            true,
        )];

        let result = TestPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn missing_org_enforces_by_default() {
        let policies = [policy_view(
            Uuid::new_v4(),
            PolicyType::MasterPassword,
            true,
        )];

        let result = TestPolicy.filter(&policies, &[]);
        assert_eq!(result.len(), 1);
    }
}

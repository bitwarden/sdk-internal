#![allow(dead_code)]

//! Policy filtering logic.
//!
//! Provides the [`Policy`] trait for determining which policies
//! should be enforced against the current user based on business rules.

use std::collections::HashMap;

use bitwarden_organizations::{
    OrganizationUserStatusType, OrganizationUserType, ProfileOrganization,
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;
use uuid::Uuid;

/// A newtype representing the policy type.
#[derive(PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Copy, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct PolicyType(
    /// The raw integer value as defined by the server.
    pub u8,
);

/// An organization policy.
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct PolicyView {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) r#type: PolicyType,
    #[cfg_attr(feature = "wasm", tsify(type = "Record<string, unknown>"))]
    pub(crate) data: Option<HashMap<String, serde_json::Value>>,
    pub(crate) enabled: bool,
}

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
    /// If a policy's organization is not present in `organizations`, the policy is enforced by
    /// default.
    fn filter<'a>(
        &self,
        policies: &'a [PolicyView],
        organizations: &[ProfileOrganization],
    ) -> Vec<&'a PolicyView> {
        let org_map: HashMap<&Uuid, &ProfileOrganization> =
            organizations.iter().map(|o| (&o.id, o)).collect();

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
                            && !self.exempt_roles().contains(&org.r#type)
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

    fn policy_view(organization_id: Uuid, policy_type: u8, enabled: bool) -> PolicyView {
        PolicyView {
            id: Uuid::new_v4(),
            organization_id,
            r#type: PolicyType(policy_type),
            data: None,
            enabled,
        }
    }

    fn organization(
        id: Uuid,
        user_type: OrganizationUserType,
        status: OrganizationUserStatusType,
        provider: bool,
    ) -> ProfileOrganization {
        ProfileOrganization {
            id,
            r#type: user_type,
            status,
            use_policies: true,
            is_provider_user: provider,
            ..Default::default()
        }
    }

    struct TestPolicy;
    impl Policy for TestPolicy {
        fn policy_type(&self) -> PolicyType {
            PolicyType(1)
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
        let policies = [policy_view(org_id, 1, true)];
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
        let orgs = [ProfileOrganization {
            enabled: false,
            id: org_id,
            r#type: OrganizationUserType::User,
            status: OrganizationUserStatusType::Confirmed,
            use_policies: true,
            is_provider_user: false,
            ..Default::default()
        }];
        let policies = [policy_view(org_id, 1, true)];

        let result = TestPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn disabled_policy_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, 1, false)];
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
        let policies = [policy_view(org_id, 2, true)];
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
        let orgs = [ProfileOrganization {
            id: org_id,
            r#type: OrganizationUserType::User,
            status: OrganizationUserStatusType::Confirmed,
            use_policies: false,
            is_provider_user: false,
            ..Default::default()
        }];
        let policies = [policy_view(org_id, 1, true)];

        let result = TestPolicy.filter(&policies, &orgs);
        assert!(result.is_empty());
    }

    #[test]
    fn exempt_role_is_filtered_out() {
        let org_id = Uuid::new_v4();
        let policies = [policy_view(org_id, 1, true)];
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
        let policies = [policy_view(org_id, 1, true)];
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
        let policies = [policy_view(org_id, 1, true)];
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
        let policies = [policy_view(Uuid::new_v4(), 1, true)];

        let result = TestPolicy.filter(&policies, &[]);
        assert_eq!(result.len(), 1);
    }
}
